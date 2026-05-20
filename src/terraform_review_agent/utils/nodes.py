"""Specialist review nodes for the LangGraph fan-out.

Each node:

1. Builds per-file LLM payloads from the PR's changed Terraform files (size
   capped, with a diff-only fallback) via
   :func:`~terraform_review_agent.utils.tools.prepare_file_payloads`.
2. Runs its OSS scanners against the workspace, tolerating a missing scanner
   binary by logging and continuing.
3. Hands the scanner findings + file contents to the configured LLM, which
   returns a normalized, de-duplicated :class:`SpecialistReview`.
4. Stamps the owning agent name onto each finding and writes its disjoint state
   field (``security`` / ``cost`` / ``style``).

A node short-circuits before touching scanners or the LLM when there is nothing
to review (no Terraform payloads; for cost, no configured infracost baseline or
no cost delta), which keeps token usage and CI runtime down on trivial PRs.
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from terraform_review_agent.llm import get_llm
from terraform_review_agent.utils import prompts
from terraform_review_agent.utils.state import (
    AgentName,
    Finding,
    ReviewState,
    SpecialistReview,
)
from terraform_review_agent.utils.tools import (
    FilePayload,
    ScannerError,
    prepare_file_payloads,
    run_checkov,
    run_infracost_diff,
    run_terraform_fmt,
    run_tflint,
    run_tfsec,
)

log = structlog.get_logger(__name__)


def _collect(scanners: list[tuple[str, Any]], working_dir: str) -> list[Finding]:
    """Run each ``(name, tool)`` against ``working_dir``, skipping missing binaries."""

    findings: list[Finding] = []
    for name, scanner in scanners:
        try:
            findings.extend(scanner.invoke({"working_dir": working_dir}))
        except ScannerError as exc:
            log.warning("scanner.skipped", scanner=name, error=str(exc))
    return findings


def _filter_to_changed(findings: list[Finding], changed_paths: set[str]) -> list[Finding]:
    """Keep only findings attributable to a Terraform file this PR changed.

    Scanners run over the whole workspace, so findings in unchanged files (and
    findings with no resolvable path) would otherwise leak into the review. This
    scopes them deterministically instead of relying on the LLM to drop them.
    """

    return [f for f in findings if f.file in changed_paths]


def _review_with_llm(
    agent: AgentName,
    system_prompt: str,
    raw_findings: list[Finding],
    payloads: list[FilePayload],
) -> list[Finding]:
    """Refine scanner output with the LLM and stamp the owning ``agent`` name."""

    human = prompts.build_specialist_input(raw_findings, payloads)
    structured = get_llm().with_structured_output(SpecialistReview)
    result = structured.invoke([SystemMessage(content=system_prompt), HumanMessage(content=human)])
    review = (
        result if isinstance(result, SpecialistReview) else SpecialistReview.model_validate(result)
    )
    return [
        Finding(
            agent=agent,
            severity=item.severity,
            file=item.file,
            line=item.line,
            rule=item.rule,
            message=item.message,
            suggestion=item.suggestion,
        )
        for item in review.findings
    ]


def security_node(state: ReviewState) -> dict[str, list[Finding]]:
    """tfsec + checkov, then LLM normalization into security findings."""

    payloads = prepare_file_payloads(state.pr, state.workspace)
    if not payloads:
        return {"security": []}
    changed = state.pr.changed_terraform_paths
    raw = _filter_to_changed(
        _collect([("tfsec", run_tfsec), ("checkov", run_checkov)], state.workspace),
        changed,
    )
    findings = _review_with_llm("security", prompts.SECURITY_SYSTEM_PROMPT, raw, payloads)
    return {"security": _filter_to_changed(findings, changed)}


def cost_node(state: ReviewState) -> dict[str, list[Finding]]:
    """infracost diff against the configured baseline, then LLM annotation."""

    if not state.cost_baseline_path:
        log.info("cost.skipped", reason="no infracost baseline configured")
        return {"cost": []}
    payloads = prepare_file_payloads(state.pr, state.workspace)
    if not payloads:
        return {"cost": []}
    try:
        raw: list[Finding] = run_infracost_diff.invoke(
            {"working_dir": state.workspace, "baseline_path": state.cost_baseline_path}
        )
    except ScannerError as exc:
        log.warning("scanner.skipped", scanner="infracost", error=str(exc))
        return {"cost": []}
    if not raw:
        return {"cost": []}
    return {"cost": _review_with_llm("cost", prompts.COST_SYSTEM_PROMPT, raw, payloads)}


def style_node(state: ReviewState) -> dict[str, list[Finding]]:
    """tflint + terraform fmt, then LLM into concise style findings."""

    payloads = prepare_file_payloads(state.pr, state.workspace)
    if not payloads:
        return {"style": []}
    changed = state.pr.changed_terraform_paths
    raw = _filter_to_changed(
        _collect(
            [("tflint", run_tflint), ("terraform-fmt", run_terraform_fmt)],
            state.workspace,
        ),
        changed,
    )
    findings = _review_with_llm("style", prompts.STYLE_SYSTEM_PROMPT, raw, payloads)
    return {"style": _filter_to_changed(findings, changed)}
