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
import sys
from dataclasses import dataclass

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

    raw_final = agent.invoke(
        ReviewState(
            pr=pr_context,
            workspace=settings.workspace_dir,
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
