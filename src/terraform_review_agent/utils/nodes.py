"""Specialist review nodes for the LangGraph fan-out.

Each node:

1. Builds per-file LLM payloads from the PR's changed Terraform files (size
   capped, with a diff-only fallback) via
   :func:`~terraform_review_agent.utils.tools.prepare_file_payloads`.
2. Runs its OSS scanners against the workspace, tolerating a missing scanner
   binary by logging and continuing.
3. Hands the scanner findings (the canonical, deterministic set) + file contents
   to the configured LLM, which may only *reword* them via
   :class:`SpecialistAnnotations` — severity/file/line/rule and the finding set
   itself are owned by the scanners, so they stay identical across runs.
4. Stamps the owning agent name onto each finding and writes its disjoint state
   field (``security`` / ``cost`` / ``style``).

Speculative LLM-discovered findings (no scanner reported them) are opt-in via
``settings.enable_llm_findings`` and never emitted for cost.

A node short-circuits before touching scanners or the LLM when the PR changed no
Terraform files (for cost, also when the infracost key is unset), which keeps
token usage and CI runtime down on trivial PRs. Scanner coverage does not depend
on LLM payloads being buildable: a large PR whose patches GitHub omitted yields
empty payloads but is still scanned from the workspace on disk.
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from terraform_review_agent.config import settings
from terraform_review_agent.llm import get_llm
from terraform_review_agent.utils import prompts
from terraform_review_agent.utils.render import render_comment
from terraform_review_agent.utils.state import (
    AgentName,
    CostReport,
    Finding,
    ReviewState,
    SpecialistAnnotations,
)
from terraform_review_agent.utils.tools import (
    FilePayload,
    ScannerError,
    build_infracost_baseline,
    build_synced_usage_file,
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


def _prefer_refined(refined: str | None, original: str | None) -> str | None:
    """Use the LLM's text only when it's non-blank; otherwise keep the scanner's.

    The annotation step is wording-only: a blank/whitespace ``message`` or
    ``suggestion`` from the model means "nothing to add", not "erase the
    scanner's remediation". Only a real, non-empty string overrides the
    deterministic scanner text.
    """

    if refined is not None and refined.strip():
        return refined
    return original


def _namespaced_llm_rule(agent: AgentName, rule: str) -> str:
    """Force a discovered finding's rule into the ``{agent}:llm-`` namespace.

    The prompt asks for this prefix, but the model isn't bound to it. Enforcing
    it in code stops a hallucinated finding from masquerading as scanner output
    (e.g. ``tfsec:...``) or colliding with a real scanner finding's
    ``(file, rule, line)`` dedupe key.
    """

    prefix = f"{agent}:llm-"
    if rule.startswith(prefix):
        return rule
    slug = rule.split(":")[-1].removeprefix("llm-").strip() or "finding"
    return f"{prefix}{slug}"


def _annotate_with_llm(
    agent: AgentName,
    raw_findings: list[Finding],
    payloads: list[FilePayload],
) -> list[Finding]:
    """Reword scanner findings with the LLM, keeping the finding set deterministic.

    The scanner findings are canonical: their severity/file/line/rule are
    preserved verbatim and every one is returned. The LLM may only rewrite
    ``message``/``suggestion`` (matched back by the ``id`` we assign here), so
    the *set* of findings is identical run-to-run — only the wording varies.
    Speculative LLM-discovered findings are appended only when
    ``settings.enable_llm_findings`` is set (and never for cost).
    """

    canonical = [f.model_copy(update={"agent": agent}) for f in raw_findings]
    allow_discovery = settings.enable_llm_findings and agent != "cost"
    # Nothing for the LLM to do: no findings to reword and discovery is off (or
    # on but with no file content to discover from).
    if not canonical and (not allow_discovery or not payloads):
        return canonical

    system = prompts.specialist_system_prompt(agent, allow_discovery)
    human = prompts.build_specialist_input(canonical, payloads)
    structured = get_llm().with_structured_output(SpecialistAnnotations)
    result = structured.invoke([SystemMessage(content=system), HumanMessage(content=human)])
    review = (
        result
        if isinstance(result, SpecialistAnnotations)
        else SpecialistAnnotations.model_validate(result)
    )

    by_id = {a.id: a for a in review.annotations}
    findings: list[Finding] = []
    for idx, finding in enumerate(canonical):
        annotation = by_id.get(idx)
        if annotation is None:
            findings.append(finding)
            continue
        findings.append(
            finding.model_copy(
                update={
                    "message": _prefer_refined(annotation.message, finding.message),
                    "suggestion": _prefer_refined(annotation.suggestion, finding.suggestion),
                }
            )
        )

    if allow_discovery:
        findings.extend(
            Finding(
                agent=agent,
                severity=item.severity,
                file=item.file,
                line=item.line,
                rule=_namespaced_llm_rule(agent, item.rule),
                message=item.message,
                suggestion=item.suggestion,
            )
            for item in review.discovered
        )
    return findings


def security_node(state: ReviewState) -> dict[str, list[Finding]]:
    """tfsec + checkov, then LLM normalization into security findings."""

    changed = state.pr.changed_terraform_paths
    if not changed:
        return {"security": []}
    # Scanners read the workspace from disk, so they run whether or not we could
    # build LLM payloads — a large PR with omitted patches yields empty payloads
    # but must still be scanned.
    payloads = prepare_file_payloads(state.pr, state.workspace)
    raw = _filter_to_changed(
        _collect([("tfsec", run_tfsec), ("checkov", run_checkov)], state.workspace),
        changed,
    )
    if not (raw or payloads):
        return {"security": []}
    findings = _annotate_with_llm("security", raw, payloads)
    return {"security": _filter_to_changed(findings, changed)}


def cost_node(state: ReviewState) -> dict[str, object]:
    """infracost diff against the base ref, then LLM annotation.

    Gated on the infracost API key — when it's unset the agent skips. The base
    breakdown comes from ``cost_baseline_path`` when one was supplied (CI may
    inject it), otherwise it's generated on the fly from the workspace's git
    history. A usage file is auto-synced from the PR's Terraform (no per-repo
    setup) so usage-based resources are priced from infracost's defaults on both
    the base and head; if the sync fails the totals fall back to fixed costs.
    Returns both the per-resource findings and a ``cost_summary`` (the head's
    absolute monthly total + the change), so the report can show both.
    """

    if settings.infracost_api_key is None:
        log.info("cost.skipped", reason="no infracost api key")
        return {"cost": []}
    if not state.pr.has_terraform_changes:
        return {"cost": []}
    # Empty payloads (large PR, omitted patches) must not skip infracost — it
    # prices the workspace on disk and doesn't need the LLM payloads.
    payloads = prepare_file_payloads(state.pr, state.workspace)
    usage_file = build_synced_usage_file(state.workspace)
    try:
        baseline = state.cost_baseline_path or build_infracost_baseline(
            state.workspace, state.pr.repository, usage_file_path=usage_file
        )
        result = run_infracost_diff.invoke(
            {
                "working_dir": state.workspace,
                "baseline_path": baseline,
                "usage_file_path": usage_file,
            }
        )
    except ScannerError as exc:
        log.warning("scanner.skipped", scanner="infracost", error=str(exc))
        return {"cost": []}

    report = result if isinstance(result, CostReport) else CostReport.model_validate(result)
    summary = report.summary
    log.info(
        "cost.ran",
        total_monthly=summary.total_monthly if summary else None,
        delta_monthly=summary.delta_monthly if summary else None,
        usage_file_synced=usage_file is not None,
    )
    findings = _annotate_with_llm("cost", report.findings, payloads) if report.findings else []
    return {"cost": findings, "cost_summary": summary}


def style_node(state: ReviewState) -> dict[str, list[Finding]]:
    """tflint + terraform fmt, then LLM into concise style findings."""

    changed = state.pr.changed_terraform_paths
    if not changed:
        return {"style": []}
    # Scanners read the workspace from disk; run them even when payloads are
    # empty (large PR with omitted patches) so coverage isn't silently dropped.
    payloads = prepare_file_payloads(state.pr, state.workspace)
    raw = _filter_to_changed(
        _collect(
            [("tflint", run_tflint), ("terraform-fmt", run_terraform_fmt)],
            state.workspace,
        ),
        changed,
    )
    if not (raw or payloads):
        return {"style": []}
    findings = _annotate_with_llm("style", raw, payloads)
    return {"style": _filter_to_changed(findings, changed)}


def aggregator_node(state: ReviewState) -> dict[str, str]:
    """Merge the specialist branches into the rendered sticky-comment markdown.

    Dedupe/severity-rank/render all live in :mod:`utils.render`; this node just
    feeds it the joined findings and the PR context for file:line links.
    """

    markdown = render_comment(state.all_findings(), state.pr, state.cost_summary)
    return {"comment_markdown": markdown}
