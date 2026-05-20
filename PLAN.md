# PLAN — terraform-review-agent

Reusable GitHub Actions workflow that runs a LangGraph multi-agent review on Terraform PRs and posts a single severity-ranked sticky comment.

---

## Architecture

```
GitHub PR event
  └─► reusable workflow (.github/workflows/terraform-review.yml)
        └─► uv run python -m terraform_review_agent.entrypoint
              └─► LangGraph:
                     start ──► [security ∥ cost ∥ style] ──► aggregator ──► post_comment
```

- **start** — fetch PR metadata + diff via GitHub API, filter to `*.tf` / `*.tfvars`, early-exit if none changed.
- **security** — `tfsec` + `checkov` as `@tool`s; LLM normalizes to `Finding[]`.
- **cost** — `infracost diff` against the base ref; LLM annotates significant deltas.
- **style** — `terraform fmt -check` + `tflint`; LLM produces concise style findings.
- **aggregator** — merges, dedupes (`file+rule+line`), ranks by severity, renders markdown.
- **post_comment** — upserts via hidden marker `<!-- terraform-review-agent:v1 -->`.

---

## Decisions locked

| Question | Choice |
|---|---|
| Topology | Parallel fan-out + aggregator |
| Scanners | LLM + OSS scanners as tools (tfsec, checkov, tflint, terraform fmt) |
| Cost agent | Infracost (paid third-party, approved) |
| Comment mode | Single sticky comment, edited each run |
| Checkpointer | Off for MVP (one-shot CI run) |
| Distribution | Prebuilt container on GHCR — reusable workflow runs the job inside `ghcr.io/spanosg131/terraform-review-agent`, no per-run installs |

---

## State (Pydantic v2 sketch)

```python
Severity = Literal["critical", "high", "medium", "low", "info"]

class Finding(BaseModel):
    agent: Literal["security", "cost", "style"]
    severity: Severity
    file: str
    line: int | None
    rule: str           # e.g. "tfsec:AWS017", "infracost:cost-increase"
    message: str
    suggestion: str | None

class ReviewState(BaseModel):
    pr: PRContext
    security: list[Finding] = []
    cost:     list[Finding] = []
    style:    list[Finding] = []
    comment_markdown: str | None = None
```

Parallel branches write to disjoint fields — no reducer needed.

---

## Reusable workflow contract

- **Inputs:** `llm-provider` (default `openai`), `llm-model`, `paths` (default `**/*.tf,**/*.tfvars`), `fail-on-severity` (default `none`).
- **Secrets:** one of `anthropic-api-key` / `openai-api-key` / `google-api-key`; `infracost-api-key`; `github-token` (defaults to `${{ github.token }}`).
- **Concurrency:** group by PR, `cancel-in-progress: true`.

---

## Build phases

### Phase 1 — Scaffolding
- [x] `pyproject.toml` (python 3.13, uv, deps: langgraph, langchain-{openai,anthropic,google-genai}, pydantic, pydantic-settings, structlog, httpx, pytest, ruff, mypy)
- [x] `.python-version`, `.env.example`, `.gitignore`
- [x] `Makefile` (venv, install, fmt, lint, type, test, run, docker-build, docker-up, clean)
- [x] `Dockerfile` + `docker-compose.yml`
- [x] `langgraph.json` pointing at `src/terraform_review_agent/agent.py:agent`
- [x] `agent.py` with no-op nodes wired in the target topology — `make fmt lint type test` green

### Phase 2 — Core
- [x] `config.py` (pydantic-settings reading env)
- [x] `llm.py` (provider factory: openai / anthropic / google)
- [x] `utils/state.py` (`PRContext`, `ChangedFile`, `Finding`, `ReviewState`)
- [x] `github_client.py` (fetch PR + diff; sticky comment upsert via marker)
- [x] `entrypoint.py` (CLI invoked by the GH Action)
- [x] Unit tests for state models and the sticky-comment upsert logic

### Phase 3 — Tools (one scanner per agent first)
- [x] `utils/tools.py` — `tfsec` wrapper (JSON output → structured)
- [x] `utils/tools.py` — `infracost diff` wrapper
- [x] `utils/tools.py` — `tflint` wrapper
- [x] Add `checkov` (security)
- [x] Add `terraform fmt -check` (style)
- [x] Token/size caps: per-file content cap, fallback to diff-only above threshold

### Phase 4 — Specialist nodes
- [x] `nodes.security_node` — calls tfsec + checkov, LLM → `Finding[]`
- [x] `nodes.cost_node` — calls infracost, LLM → `Finding[]`
- [x] `nodes.style_node` — calls tflint + fmt, LLM → `Finding[]`
- [x] `utils/prompts.py` for each specialist (no inlined prompts in nodes)
- [x] Unit test per node with mocked LLM + subprocess

### Phase 5 — Aggregator + renderer
- [x] `nodes.aggregator_node` — merge, dedupe by `(file, rule, line)`, severity-rank
- [x] Markdown renderer — severity sections, per-agent `<details>` blocks, file:line links
- [x] Low-severity collapse behavior (always post; collapse `info`/`low` into `<details>`)
- [x] Unit tests for dedupe + renderer snapshots

### Phase 6 — Prebuilt container image
- [x] Extend `Dockerfile` to bundle pinned `terraform`, `tfsec`, `tflint`, `infracost` binaries + `checkov` (in the `.venv`)
- [x] Single image used for both local `docker compose` dev and CI — entrypoint runs `terraform_review_agent.entrypoint`
- [x] `.github/workflows/build-image.yml` — buildx + layer cache, pushes to GHCR on version tags (`v*.*.*`) and manual dispatch only
- [x] Tagging: `vX.Y.Z` per release, `v1` major float, `sha-<short>` per build commit, `latest` for stable release tags
- [x] Smoke test inside the image that every binary resolves on `PATH`

### Phase 7 — Reusable workflow
- [x] `.github/workflows/terraform-review.yml` (`workflow_call`, inputs/secrets above)
- [x] Job uses `container: ghcr.io/spanosg131/terraform-review-agent:v1` — no per-run scanner installs
- [x] `actions/checkout@v4` with `fetch-depth: 0` so the base ref is available for `infracost diff`
- [x] Concurrency group + `cancel-in-progress`
- [x] `examples/example-caller.yml` (docs-only sample — kept out of `.github/workflows/` so it doesn't run in this repo)
- [ ] End-to-end run on a throwaway test PR _(requires a live repo + published `:v1` image; run manually)_

> **Phase 7 notes:**
> - `fail-on-severity` is now functional: `config.fail_on_severity` + an exit-code
>   gate in `entrypoint.main` (exit 2 when a finding meets/exceeds the floor;
>   `none` never gates). Covered by `tests/unit/test_entrypoint.py`.
> - `paths` is realized as the caller's `on.pull_request.paths` trigger (see
>   `examples/example-caller.yml`), not a reusable-workflow input — the entrypoint
>   already filters to `*.tf`/`*.tfvars` and early-exits when none changed.
> - `workflow_dispatch` runs carry no PR context, so the reusable workflow takes
>   a `pr-number` input (fallback to the pull_request event) and the caller's
>   dispatch supplies it; without it the CLI exits on `--pr-number ''`.
> - Checkout is keyed off the resolved PR number (`refs/pull/<n>/merge`), not the
>   triggering ref, and the infracost base SHA is derived from the merge commit's
>   first parent (`HEAD^1`). Otherwise a dispatch rerun would scan the selected
>   branch (e.g. `main`) instead of the PR head, since scanners read `workspace="."`.
> - Reusable-workflow `llm-provider` defaults to `openai`/`gpt-4o` (a coherent
>   pair); other providers must set `llm-model` to match (example uses anthropic).
> - The container runs as root (`options: --user root`) because GitHub-hosted
>   container jobs mount the workspace as uid 1001, which the image's non-root
>   `app` user cannot write.

### Phase 8 — Tests + polish
- [x] Integration test: compiled graph end-to-end with mocked LLM + recorded scanner output
- [x] `README.md` (consumer-facing: how to call the reusable workflow, required secrets, sample comment)
- [x] `make fmt lint type test` green on a clean checkout

---

## Open considerations

- **Token control** — large PRs will blow budgets. Per-file content cap, diff-only fallback above N KB, hard cap on changed-file count with a "review truncated" notice.
- **Scanner versions** — pinned in the `Dockerfile` (single source of truth). Bumping a scanner is a rebuild-image PR, not a workflow-file edit.
- **Image size vs. pull time** — keep the image at `python:3.13-slim` base; ~400-600 MB target so warm pulls stay sub-10s on GitHub runners.
- **Severity floor** — default: always post, collapse `info`/`low`. Revisit if comment spam becomes an issue.
- **`fail-on-severity`** — default `none`; consumers opt in to gating CI.
- **Checkpointer** — off for MVP; reconsider if we want to debug stuck runs.
