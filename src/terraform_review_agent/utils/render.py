"""Aggregation + markdown rendering for the sticky review comment.

The aggregator collapses the three specialist branches into a single comment:

1. :func:`dedupe_findings` merges findings that share a ``(file, rule, line)``
   identity, keeping the most severe instance.
2. :func:`sort_findings` orders them by severity, then file/line, for a stable
   render (and stable test snapshots).
3. :func:`render_comment` emits GitHub-flavored markdown: critical/high/medium
   are shown inline as severity sections; ``low``/``info`` collapse into a
   ``<details>`` block; a per-agent ``<details>`` breakdown follows.

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

_AGENT_LABELS: dict[AgentName, str] = {
    "security": "Security",
    "cost": "Cost",
    "style": "Style",
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


def _render_finding(pr: PRContext, finding: Finding) -> list[str]:
    """One bullet per finding, with an optional suggestion sub-bullet.

    The line carries severity + rule + agent so it reads correctly in any
    section (severity-grouped or agent-grouped). Untrusted fields (``rule``,
    ``message``, ``suggestion``, ``file``) are sanitized; ``severity``/``agent``
    are constrained literals.
    """

    lines = [
        f"- `{finding.severity}` · `{_code(finding.rule)}` · {finding.agent} — "
        f"{_inline(finding.message)} ({_file_ref(pr, finding)})"
    ]
    if finding.suggestion:
        lines.append(f"  - _Suggestion:_ {_inline(finding.suggestion)}")
    return lines


def _summary_line(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    parts = [
        f"{counts[sev]} {_SEVERITY_LABELS[sev].lower()}" for sev in SEVERITY_ORDER if counts[sev]
    ]
    total = len(findings)
    noun = "finding" if total == 1 else "findings"
    return f"**{total} {noun}** — {', '.join(parts)}"


def _severity_sections(pr: PRContext, findings: list[Finding]) -> list[str]:
    parts: list[str] = []
    for sev in VISIBLE_SEVERITIES:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        parts.append(f"### {_SEVERITY_LABELS[sev]} ({len(group)})")
        for finding in group:
            parts.extend(_render_finding(pr, finding))
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
        parts.append(f"#### {_SEVERITY_LABELS[sev]} ({len(sub)})")
        for finding in sub:
            parts.extend(_render_finding(pr, finding))
        parts.append("")
    parts.append("</details>")
    parts.append("")
    return parts


def _agent_sections(pr: PRContext, findings: list[Finding]) -> list[str]:
    parts: list[str] = []
    for agent in _AGENT_ORDER:
        group = [f for f in findings if f.agent == agent]
        if not group:
            continue
        parts.append("<details>")
        parts.append(f"<summary>{_AGENT_LABELS[agent]} ({len(group)})</summary>")
        parts.append("")
        for finding in group:
            parts.extend(_render_finding(pr, finding))
        parts.append("")
        parts.append("</details>")
        parts.append("")
    return parts


def render_comment(findings: list[Finding], pr: PRContext) -> str:
    """Render the full sticky-comment body for ``pr`` (marker added by caller)."""

    ordered = sort_findings(dedupe_findings(findings))
    parts: list[str] = ["## Terraform Review", ""]

    if not ordered:
        parts.append(_NO_FINDINGS)
        return "\n".join(parts) + "\n"

    parts.append(_summary_line(ordered))
    parts.append("")
    parts.extend(_severity_sections(pr, ordered))
    parts.extend(_collapsed_section(pr, ordered))

    agent_blocks = _agent_sections(pr, ordered)
    if agent_blocks:
        parts.append("### Findings by agent")
        parts.append("")
        parts.extend(agent_blocks)

    return "\n".join(parts).rstrip() + "\n"
