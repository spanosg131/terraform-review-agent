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
- [ ] `config.py` (pydantic-settings reading env)
- [ ] `llm.py` (provider factory: openai / anthropic / google)
- [ ] `utils/state.py` (`PRContext`, `ChangedFile`, `Finding`, `ReviewState`)
- [ ] `github_client.py` (fetch PR + diff; sticky comment upsert via marker)
- [ ] `entrypoint.py` (CLI invoked by the GH Action)
- [ ] Unit tests for state models and the sticky-comment upsert logic

### Phase 3 — Tools (one scanner per agent first)
- [ ] `utils/tools.py` — `tfsec` wrapper (JSON output → structured)
- [ ] `utils/tools.py` — `infracost diff` wrapper
- [ ] `utils/tools.py` — `tflint` wrapper
- [ ] Add `checkov` (security)
- [ ] Add `terraform fmt -check` (style)
- [ ] Token/size caps: per-file content cap, fallback to diff-only above threshold

### Phase 4 — Specialist nodes
- [ ] `nodes.security_node` — calls tfsec + checkov, LLM → `Finding[]`
- [ ] `nodes.cost_node` — calls infracost, LLM → `Finding[]`
- [ ] `nodes.style_node` — calls tflint + fmt, LLM → `Finding[]`
- [ ] `utils/prompts.py` for each specialist (no inlined prompts in nodes)
- [ ] Unit test per node with mocked LLM + subprocess

### Phase 5 — Aggregator + renderer
- [ ] `nodes.aggregator_node` — merge, dedupe by `(file, rule, line)`, severity-rank
- [ ] Markdown renderer — severity sections, per-agent `<details>` blocks, file:line links
- [ ] Low-severity collapse behavior (always post; collapse `info`/`low` into `<details>`)
- [ ] Unit tests for dedupe + renderer snapshots

### Phase 6 — Reusable workflow
- [ ] `.github/workflows/terraform-review.yml` (`workflow_call`, inputs/secrets above)
- [ ] Install steps: uv + python 3.13, `aquasecurity/tfsec-action`, `terraform-linters/setup-tflint`, `infracost/actions/setup`, `hashicorp/setup-terraform`
- [ ] Concurrency group + `cancel-in-progress`
- [ ] `.github/workflows/example-caller.yml` (docs-only sample)
- [ ] End-to-end run on a throwaway test PR

### Phase 7 — Tests + polish
- [ ] Integration test: compiled graph end-to-end with mocked LLM + recorded scanner output
- [ ] `README.md` (consumer-facing: how to call the reusable workflow, required secrets, sample comment)
- [ ] `make fmt lint type test` green on a clean checkout

---

## Open considerations

- **Token control** — large PRs will blow budgets. Per-file content cap, diff-only fallback above N KB, hard cap on changed-file count with a "review truncated" notice.
- **Scanner install** — pinned action versions in the workflow keep the Python image lean.
- **Severity floor** — default: always post, collapse `info`/`low`. Revisit if comment spam becomes an issue.
- **`fail-on-severity`** — default `none`; consumers opt in to gating CI.
- **Checkpointer** — off for MVP; reconsider if we want to debug stuck runs.
