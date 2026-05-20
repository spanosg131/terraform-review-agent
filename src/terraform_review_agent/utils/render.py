"""Aggregation + markdown rendering for the sticky review comment.

The aggregator collapses the three specialist branches into a single comment:

1. :func:`dedupe_findings` merges findings that share a ``(file, rule, line)``
   identity, keeping the most severe instance.
2. :func:`sort_findings` orders them by severity, then file/line, for a stable
   render (and stable test snapshots).
3. :func:`render_comment` emits GitHub-flavored markdown: a headline 💰 cost
   callout (absolute monthly total + the PR's delta), then findings as severity
   tables (badge · agent | issue | location); critical/high/medium show inline,
   ``low``/``info`` collapse into a ``<details>`` block.

The hidden sticky marker is intentionally *not* embedded here — the GitHub
client owns it (see :meth:`GitHubClient.upsert_sticky_comment`), so the rendered
body stays a pure function of the findings.
"""

from __future__ import annotations

import html
from collections import Counter
from urllib.parse import quote

from terraform_review_agent.utils.state import (
    SEVERITY_ORDER,
    AgentName,
    CostSummary,
    Finding,
    PRContext,
    Severity,
)

# Severities shown inline, in display order. ``low``/``info`` are collapsed.
VISIBLE_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium")
COLLAPSED_SEVERITIES: tuple[Severity, ...] = ("low", "info")

_SEVERITY_LABELS: dict[Severity, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

# Colored badges for quick visual triage (descending severity = red→white).
_SEVERITY_EMOJI: dict[Severity, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_AGENT_LABELS: dict[AgentName, str] = {
    "security": "Security",
    "cost": "Cost",
    "style": "Style",
}
_AGENT_EMOJI: dict[AgentName, str] = {
    "security": "🔒",
    "cost": "💰",
    "style": "🎨",
}
_AGENT_ORDER: tuple[AgentName, ...] = ("security", "cost", "style")

_NO_FINDINGS = "No issues found in the changed Terraform files."

# Sort sentinel so findings without a line number sort after located ones.
_NO_LINE = 1 << 31


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a ``(file, rule, line)`` key, keeping the worst.

    Scanners and the LLM can surface the same issue from more than one branch;
    we keep the most severe instance and preserve first-seen order so the render
    is deterministic.
    """

    best: dict[tuple[str, str, int | None], Finding] = {}
    order: list[tuple[str, str, int | None]] = []
    for finding in findings:
        key = finding.dedupe_key()
        current = best.get(key)
        if current is None:
            best[key] = finding
            order.append(key)
        elif finding.severity_rank < current.severity_rank:
            best[key] = finding
    return [best[key] for key in order]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order by severity, then file, line, agent, rule — stable for snapshots."""

    return sorted(
        findings,
        key=lambda f: (
            f.severity_rank,
            f.file,
            f.line if f.line is not None else _NO_LINE,
            f.agent,
            f.rule,
        ),
    )


def _flatten(value: str) -> str:
    """Collapse all whitespace (incl. newlines/tabs) into single spaces.

    Findings are rendered as single markdown bullets; an embedded newline would
    break the bullet and let scanner/LLM text inject headings or list items.
    """

    return " ".join(value.split())


def _inline(value: str) -> str:
    """Sanitize untrusted free text for a markdown line.

    Flattened so it stays on one bullet, then HTML-escaped so content like
    ``</details>`` can't close the surrounding tags or otherwise smuggle live
    HTML into the comment. (GitHub strips scripts, but unescaped tags still
    corrupt the comment structure.)
    """

    return html.escape(_flatten(value), quote=False)


def _code(value: str) -> str:
    """Sanitize untrusted text rendered inside an inline code span.

    Backticks terminate a code span, so neutralize them; HTML/markdown inside a
    code span is otherwise inert.
    """

    return _flatten(value).replace("`", "'")


def _file_ref(pr: PRContext, finding: Finding) -> str:
    """A ``[file:line](blob-url)`` link pinned to the PR head sha."""

    path = quote(finding.file, safe="/")
    url = f"https://github.com/{pr.repository}/blob/{pr.head_sha}/{path}"
    label = finding.file
    if finding.line is not None:
        url = f"{url}#L{finding.line}"
        label = f"{finding.file}:{finding.line}"
    return f"[`{_code(label)}`]({url})"


def _cell(value: str) -> str:
    """Inline-sanitize free text and escape pipes so it can't break a table cell."""

    return _inline(value).replace("|", "\\|")


def _finding_table(pr: PRContext, findings: list[Finding]) -> list[str]:
    """Render findings as a markdown table: severity badge · agent | issue | location.

    The issue cell stacks the message, an optional suggestion, and the rule (as
    small text) with ``<br>`` so the table stays three columns wide and scannable.
    """

    rows = ["| Severity | Issue | Location |", "|:--|:--|:--|"]
    for f in findings:
        badge = f"{_SEVERITY_EMOJI[f.severity]} {_AGENT_EMOJI[f.agent]}"
        issue = f"**{_cell(f.message)}**"
        if f.suggestion:
            issue += f" <br> 💡 {_cell(f.suggestion)}"
        issue += f" <br> <sub>`{_cell(_code(f.rule))}`</sub>"
        location = _file_ref(pr, f).replace("|", "\\|")
        rows.append(f"| {badge} | {issue} | {location} |")
    return rows


def _cost_callout(summary: CostSummary | None) -> list[str]:
    """A headline cost line: absolute monthly total + the change from this PR."""

    if summary is None:
        return []
    total = f"**${summary.total_monthly:,.2f}/mo** total"
    delta = summary.delta_monthly
    if abs(delta) < 0.005:
        change = "**no change** from this PR"
    else:
        sign = "-" if delta < 0 else "+"
        change = f"**{sign}${abs(delta):,.2f}/mo** from this PR"
    return [f"> 💰 **Infracost estimate:** {total} · {change}", ""]


def _summary_lines(findings: list[Finding]) -> list[str]:
    """Headline counts: total + distinct files + per-severity, then per-agent."""

    sev_counts = Counter(f.severity for f in findings)
    sev_parts = [
        f"{sev_counts[sev]} {_SEVERITY_LABELS[sev].lower()}"
        for sev in SEVERITY_ORDER
        if sev_counts[sev]
    ]
    total = len(findings)
    noun = "finding" if total == 1 else "findings"
    n_files = len({f.file for f in findings})
    file_noun = "file" if n_files == 1 else "files"
    lines = [f"**{total} {noun}** in {n_files} {file_noun} — {', '.join(sev_parts)}"]

    agent_counts = Counter(f.agent for f in findings)
    agent_parts = [
        f"{_AGENT_EMOJI[agent]} {_AGENT_LABELS[agent]} {agent_counts[agent]}"
        for agent in _AGENT_ORDER
        if agent_counts[agent]
    ]
    if agent_parts:
        lines.append("")
        lines.append(f"_By agent:_ {' · '.join(agent_parts)}")
    return lines


def _severity_sections(pr: PRContext, findings: list[Finding]) -> list[str]:
    parts: list[str] = []
    for sev in VISIBLE_SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        parts.append(f"### {_SEVERITY_EMOJI[sev]} {_SEVERITY_LABELS[sev]} ({len(group)})")
        parts.append("")
        parts.extend(_finding_table(pr, group))
        parts.append("")
    return parts


def _collapsed_section(pr: PRContext, findings: list[Finding]) -> list[str]:
    group = [f for f in findings if f.severity in COLLAPSED_SEVERITIES]
    if not group:
        return []
    parts = ["<details>", f"<summary>Low &amp; info ({len(group)})</summary>", ""]
    for sev in COLLAPSED_SEVERITIES:
        sub = [f for f in group if f.severity == sev]
        if not sub:
            continue
        parts.append(f"#### {_SEVERITY_EMOJI[sev]} {_SEVERITY_LABELS[sev]} ({len(sub)})")
        parts.append("")
        parts.extend(_finding_table(pr, sub))
        parts.append("")
    parts.append("</details>")
    parts.append("")
    return parts


def render_comment(
    findings: list[Finding],
    pr: PRContext,
    cost_summary: CostSummary | None = None,
) -> str:
    """Render the full sticky-comment body for ``pr`` (marker added by caller)."""

    ordered = sort_findings(dedupe_findings(findings))
    parts: list[str] = ["## Terraform Review Agent", ""]

    if not ordered:
        parts.extend(_cost_callout(cost_summary))
        parts.append(_NO_FINDINGS)
        return "\n".join(parts).rstrip() + "\n"

    parts.extend(_summary_lines(ordered))
    parts.append("")
    parts.extend(_cost_callout(cost_summary))
    parts.extend(_severity_sections(pr, ordered))
    parts.extend(_collapsed_section(pr, ordered))

    return "\n".join(parts).rstrip() + "\n"
