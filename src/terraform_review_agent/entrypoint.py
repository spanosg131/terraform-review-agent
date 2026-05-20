"""CLI entrypoint invoked by the reusable GitHub Actions workflow.

Reads PR coordinates from the environment (``GITHUB_REPOSITORY``,
``GITHUB_PR_NUMBER``, ``GITHUB_TOKEN``), fetches PR context, runs the compiled
LangGraph agent, and — when the graph produced markdown — upserts a sticky
review comment.

Phase 2 wires the plumbing end-to-end; specialist nodes still produce empty
findings, so the comment body will be empty until Phases 4-5 land.
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import structlog

from terraform_review_agent.agent import agent
from terraform_review_agent.config import FailOnSeverity, Settings, settings
from terraform_review_agent.github_client import GitHubClient
from terraform_review_agent.utils.state import SEVERITY_ORDER, Finding, PRContext, ReviewState

log = structlog.get_logger(__name__)

# Exit code returned when findings trip the configured `fail_on_severity` floor,
# so consumers can gate CI on it. Distinct from 1 (unexpected error).
GATING_EXIT_CODE = 2


def _max_severity_finding(findings: list[Finding], threshold: FailOnSeverity) -> Finding | None:
    """Return the highest-severity finding at or above ``threshold``, else ``None``.

    ``"none"`` disables gating. Severity ranks ascend by leniency (critical=0),
    so a finding trips the gate when its rank is ``<=`` the threshold's rank.
    """

    if threshold == "none":
        return None
    floor = SEVERITY_ORDER[threshold]
    gating = [f for f in findings if f.severity_rank <= floor]
    if not gating:
        return None
    return min(gating, key=lambda f: f.severity_rank)


@dataclass(frozen=True)
class CLIArgs:
    repository: str
    pr_number: int


def _parse_args(argv: list[str] | None = None) -> CLIArgs:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        help="`owner/repo` slug (defaults to $GITHUB_REPOSITORY).",
        default=None,
    )
    parser.add_argument(
        "--pr-number",
        type=int,
        help="PR number to review (defaults to $GITHUB_PR_NUMBER).",
        default=None,
    )
    parsed = parser.parse_args(argv)

    repository = parsed.repository or settings.github_repository
    pr_number = parsed.pr_number or settings.github_pr_number
    if not repository:
        raise SystemExit("repository is required (pass --repository or set GITHUB_REPOSITORY)")
    if not pr_number:
        raise SystemExit("pr-number is required (pass --pr-number or set GITHUB_PR_NUMBER)")
    return CLIArgs(repository=repository, pr_number=pr_number)


def _configure_logging(cfg: Settings) -> None:
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
    )


def _git(args: list[str], *, cwd: str | None = None) -> int:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    ).returncode


def _clone_pr_workspace(pr: PRContext) -> str:
    """Clone ``pr``'s repo and check out its merge ref into a temp dir.

    Used for non-CI runs (e.g. ``make run``) where the workspace doesn't already
    contain the PR. Authenticates with ``GITHUB_TOKEN`` and prefers the merge ref
    (PR merged into base, so the cost agent can derive the base from ``HEAD^1``),
    falling back to the head ref for unmergeable PRs.
    """

    if settings.github_token is None:
        raise SystemExit("GITHUB_TOKEN is required to fetch the PR workspace")
    token = settings.github_token.get_secret_value()
    dest = tempfile.mkdtemp(prefix="tfr-pr-")
    auth_url = f"https://x-access-token:{token}@github.com/{pr.repository}.git"

    log.info("cloning pr workspace", repo=pr.repository, pr=pr.pr_number, dest=dest)
    if _git(["clone", "--quiet", auth_url, dest]) != 0:
        raise SystemExit(f"failed to clone {pr.repository}")
    # Prefer the merge ref; fall back to the head ref for unmergeable PRs.
    if (
        _git(["fetch", "--quiet", "origin", f"pull/{pr.pr_number}/merge"], cwd=dest) != 0
        and _git(["fetch", "--quiet", "origin", f"pull/{pr.pr_number}/head"], cwd=dest) != 0
    ):
        raise SystemExit(f"failed to fetch refs for PR #{pr.pr_number}")
    if _git(["checkout", "--quiet", "FETCH_HEAD"], cwd=dest) != 0:
        raise SystemExit("failed to check out the PR ref")
    return dest


def _ensure_workspace(pr: PRContext, base_dir: str) -> str:
    """Return a workspace containing the PR's files.

    If ``base_dir`` is already a git checkout (the CI case, where the job checked
    out the merge ref) use it as-is; otherwise clone the PR so the scanners and
    the cost baseline have real files to work with.
    """

    if (Path(base_dir) / ".git").is_dir():
        return base_dir
    return _clone_pr_workspace(pr)


def run(
    repository: str,
    pr_number: int,
    *,
    client: GitHubClient | None = None,
) -> ReviewState:
    """Run one review pass and (when markdown was produced) post the comment.

    Returns the final :class:`ReviewState` for caller-side assertions / tests.
    """

    gh = client or GitHubClient.from_settings()
    pr_context: PRContext = gh.fetch_pr_context(repository, pr_number)
    log.info(
        "fetched pr context",
        repo=repository,
        pr=pr_number,
        files=len(pr_context.changed_files),
    )

    workspace = _ensure_workspace(pr_context, settings.workspace_dir)

    raw_final = agent.invoke(
        ReviewState(
            pr=pr_context,
            workspace=workspace,
            cost_baseline_path=settings.infracost_baseline_path,
        )
    )
    final = ReviewState.model_validate(raw_final)

    if final.skipped:
        log.info("skipping review", reason=final.skip_reason)
        return final

    if final.comment_markdown:
        comment_id = gh.upsert_sticky_comment(repository, pr_number, final.comment_markdown)
        return final.model_copy(update={"posted_comment_id": comment_id})

    log.info("no comment markdown produced; skipping upsert")
    return final


def main(argv: list[str] | None = None) -> int:
    _configure_logging(settings)
    args = _parse_args(argv)
    final = run(args.repository, args.pr_number)

    if final.skipped:
        return 0

    gating = _max_severity_finding(final.all_findings(), settings.fail_on_severity)
    if gating is not None:
        log.warning(
            "failing run: finding meets fail_on_severity floor",
            threshold=settings.fail_on_severity,
            severity=gating.severity,
            rule=gating.rule,
            file=gating.file,
        )
        return GATING_EXIT_CODE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
