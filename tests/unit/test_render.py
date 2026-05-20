"""Unit tests for the aggregation + markdown renderer in :mod:`utils.render`.

Covers dedupe identity/severity-precedence, severity ordering, the low/info
collapse behavior, file:line link shape, and full-comment snapshots.
"""

from __future__ import annotations

from terraform_review_agent.utils.render import (
    dedupe_findings,
    render_comment,
    sort_findings,
)
from terraform_review_agent.utils.state import (
    AgentName,
    CostSummary,
    Finding,
    PRContext,
    Severity,
)


def _pr() -> PRContext:
    return PRContext(
        repository="acme/example",
        pr_number=7,
        base_sha="a" * 7,
        head_sha="deadbeef",
        base_ref="main",
        head_ref="feature/x",
    )


def _f(
    *,
    agent: AgentName = "security",
    severity: Severity = "high",
    file: str = "main.tf",
    line: int | None = 1,
    rule: str = "tfsec:x",
    message: str = "msg",
    suggestion: str | None = None,
) -> Finding:
    return Finding(
        agent=agent,
        severity=severity,
        file=file,
        line=line,
        rule=rule,
        message=message,
        suggestion=suggestion,
    )


# ---------------------------------------------------------------------------
# dedupe
# ---------------------------------------------------------------------------


def test_dedupe_collapses_same_file_rule_line_keeping_most_severe() -> None:
    findings = [
        _f(severity="low", rule="tfsec:x", file="main.tf", line=10, message="low one"),
        _f(severity="critical", rule="tfsec:x", file="main.tf", line=10, message="crit one"),
    ]

    out = dedupe_findings(findings)

    assert len(out) == 1
    assert out[0].severity == "critical"
    assert out[0].message == "crit one"


def test_dedupe_distinguishes_by_line_and_rule() -> None:
    findings = [
        _f(rule="tfsec:x", line=10),
        _f(rule="tfsec:x", line=11),  # different line
        _f(rule="tfsec:y", line=10),  # different rule
    ]

    assert len(dedupe_findings(findings)) == 3


def test_dedupe_preserves_first_seen_order() -> None:
    a = _f(rule="a", line=1)
    b = _f(rule="b", line=2)
    a_dup = _f(rule="a", line=1, severity="critical")  # replaces a's content, keeps slot

    out = dedupe_findings([a, b, a_dup])

    assert [x.rule for x in out] == ["a", "b"]
    assert out[0].severity == "critical"


def test_dedupe_keeps_existing_when_duplicate_is_less_severe() -> None:
    findings = [
        _f(severity="high", rule="tfsec:x", line=1, message="first"),
        _f(severity="low", rule="tfsec:x", line=1, message="second"),
    ]

    out = dedupe_findings(findings)

    assert len(out) == 1
    assert out[0].message == "first"


# ---------------------------------------------------------------------------
# sort
# ---------------------------------------------------------------------------


def test_sort_orders_by_severity_then_file_then_line() -> None:
    findings = [
        _f(severity="info", file="z.tf", line=1, rule="r1"),
        _f(severity="critical", file="b.tf", line=5, rule="r2"),
        _f(severity="medium", file="a.tf", line=2, rule="r3"),
        _f(severity="critical", file="a.tf", line=9, rule="r4"),
    ]

    out = sort_findings(findings)

    assert [f.severity for f in out] == ["critical", "critical", "medium", "info"]
    # Within critical, file "a.tf" sorts before "b.tf".
    assert [f.file for f in out[:2]] == ["a.tf", "b.tf"]


def test_sort_places_lineless_findings_after_located_ones_in_same_file() -> None:
    findings = [
        _f(severity="high", file="main.tf", line=None, rule="r-none"),
        _f(severity="high", file="main.tf", line=3, rule="r-line"),
    ]

    out = sort_findings(findings)

    assert [f.rule for f in out] == ["r-line", "r-none"]


# ---------------------------------------------------------------------------
# render — structure & collapse
# ---------------------------------------------------------------------------


def test_render_no_findings_message() -> None:
    assert render_comment([], _pr()) == (
        "## Terraform Review Agent\n\nNo issues found in the changed Terraform files.\n"
    )


def test_render_visible_severities_are_top_level_sections() -> None:
    md = render_comment(
        [
            _f(severity="critical", rule="c"),
            _f(severity="high", rule="h"),
            _f(severity="medium", rule="m"),
        ],
        _pr(),
    )

    assert "### 🔴 Critical (1)" in md
    assert "### 🟠 High (1)" in md
    assert "### 🟡 Medium (1)" in md
    # Visible severities are not buried in a collapsed block.
    assert "<summary>Low &amp; info" not in md


def test_render_collapses_low_and_info_into_details() -> None:
    md = render_comment(
        [
            _f(severity="low", rule="lo", message="low item"),
            _f(severity="info", rule="inf", message="info item"),
        ],
        _pr(),
    )

    assert "<details>" in md
    assert "<summary>Low &amp; info (2)</summary>" in md
    assert "#### 🔵 Low (1)" in md
    assert "#### ⚪ Info (1)" in md
    # Collapsed severities never appear as top-level (`### `) sections — they
    # only show up as `#### ` sub-headers inside the details block.
    lines = md.splitlines()
    assert "### 🔵 Low (1)" not in lines
    assert "### ⚪ Info (1)" not in lines


def test_render_summarizes_counts_by_agent_without_duplicating_findings() -> None:
    md = render_comment(
        [
            _f(agent="security", severity="high", rule="s"),
            _f(agent="cost", severity="medium", rule="infracost:resource-delta"),
            _f(agent="style", severity="low", rule="tflint:z"),
        ],
        _pr(),
    )

    assert "_By agent:_ 🔒 Security 1 · 💰 Cost 1 · 🎨 Style 1" in md
    # The old per-agent <details> dump (which re-printed every finding) is gone.
    assert "### Findings by agent" not in md
    assert "<summary>Security" not in md


def test_render_summary_counts_files_and_findings() -> None:
    md = render_comment(
        [
            _f(severity="high", file="a.tf", line=1, rule="r1"),
            _f(severity="high", file="a.tf", line=2, rule="r2"),
            _f(severity="medium", file="b.tf", line=1, rule="r3"),
        ],
        _pr(),
    )

    assert "**3 findings** in 2 files — 2 high, 1 medium" in md


def test_render_finding_leads_with_message_not_severity() -> None:
    md = render_comment([_f(severity="high", message="Public bucket", rule="tfsec:x")], _pr())

    # Findings render as a table; the row carries a severity+agent badge, the
    # bolded message, and the rule as small text.
    assert "| Severity | Issue | Location |" in md
    assert "🟠 🔒" in md
    assert "**Public bucket**" in md
    assert "`tfsec:x`" in md


def test_render_file_line_link_pinned_to_head_sha() -> None:
    md = render_comment([_f(file="modules/net/main.tf", line=42, rule="r")], _pr())

    assert (
        "[`modules/net/main.tf:42`]"
        "(https://github.com/acme/example/blob/deadbeef/modules/net/main.tf#L42)"
    ) in md


def test_render_lineless_finding_link_has_no_anchor() -> None:
    md = render_comment([_f(file="ec2.tf", line=None, rule="r")], _pr())

    assert "[`ec2.tf`](https://github.com/acme/example/blob/deadbeef/ec2.tf)" in md
    assert "#L" not in md


def test_render_includes_suggestion_in_issue_cell() -> None:
    md = render_comment([_f(suggestion="Set acl=private")], _pr())

    assert "💡 Set acl=private" in md


def test_render_cost_callout_shows_total_and_delta() -> None:
    md = render_comment([_f()], _pr(), CostSummary(total_monthly=26.5, delta_monthly=5.0))

    assert "> 💰 **Infracost estimate:** **$26.50/mo** total · **+$5.00/mo** from this PR" in md


def test_render_cost_callout_reports_no_change_for_zero_delta() -> None:
    md = render_comment([_f()], _pr(), CostSummary(total_monthly=21.9, delta_monthly=0.0))

    assert "> 💰 **Infracost estimate:** **$21.90/mo** total · **no change** from this PR" in md


def test_render_cost_callout_shown_even_with_no_findings() -> None:
    md = render_comment([], _pr(), CostSummary(total_monthly=21.9, delta_monthly=0.0))

    assert "> 💰 **Infracost estimate:**" in md
    assert "No issues found in the changed Terraform files." in md


# ---------------------------------------------------------------------------
# render — sanitization of untrusted scanner/LLM text
# ---------------------------------------------------------------------------


def test_render_escapes_html_in_message_so_tags_cannot_close_details() -> None:
    md = render_comment([_f(severity="low", message="oops </details> escape")], _pr())

    assert "&lt;/details&gt;" in md
    # Exactly the details blocks the renderer itself opens are closed — no extra
    # closing tag smuggled in via the message.
    assert md.count("</details>") == md.count("<details>")


def test_render_flattens_newlines_in_message_and_suggestion() -> None:
    md = render_comment(
        [_f(message="line one\nline two", suggestion="do a\nthen b")],
        _pr(),
    )

    assert "line one line two" in md
    assert "do a then b" in md
    # A newline-injected markdown heading must not become a real heading.
    assert "\n## " not in md.replace("\n## Terraform Review Agent", "", 1)


def test_render_neutralizes_backticks_in_rule_code_span() -> None:
    md = render_comment([_f(rule="tflint:`break`out")], _pr())

    assert "`tflint:'break'out`" in md


def test_render_url_encodes_file_path_in_link_target() -> None:
    md = render_comment([_f(file="weird name).tf", line=3)], _pr())

    assert "/blob/deadbeef/weird%20name%29.tf#L3" in md


def test_render_url_encodes_hash_and_backtick_but_keeps_slashes() -> None:
    # A literal `#` must be encoded so it can't collide with the `#L` line
    # anchor; backticks/spaces/parens encoded too; path separators preserved.
    md = render_comment([_f(file="mod/a b/main#1`x`.tf", line=7)], _pr())

    assert "/blob/deadbeef/mod/a%20b/main%231%60x%60.tf#L7" in md


# ---------------------------------------------------------------------------
# render — full snapshot
# ---------------------------------------------------------------------------


def test_render_full_comment_snapshot() -> None:
    findings = [
        _f(
            agent="security",
            severity="critical",
            file="main.tf",
            line=10,
            rule="tfsec:aws-s3-no-public",
            message="Public S3 bucket",
            suggestion="Set acl=private",
        ),
        _f(
            agent="security",
            severity="info",
            file="variables.tf",
            line=None,
            rule="security:llm-note",
            message="Consider tagging",
            suggestion=None,
        ),
    ]

    expected = (
        "\n".join(
            [
                "## Terraform Review Agent",
                "",
                "**2 findings** in 2 files — 1 critical, 1 info",
                "",
                "_By agent:_ 🔒 Security 2",
                "",
                "### 🔴 Critical (1)",
                "",
                "| Severity | Issue | Location |",
                "|:--|:--|:--|",
                "| 🔴 🔒 | **Public S3 bucket** <br> 💡 Set acl=private <br> "
                "<sub>`tfsec:aws-s3-no-public`</sub> | "
                "[`main.tf:10`](https://github.com/acme/example/blob/deadbeef/main.tf#L10) |",
                "",
                "<details>",
                "<summary>Low &amp; info (1)</summary>",
                "",
                "#### ⚪ Info (1)",
                "",
                "| Severity | Issue | Location |",
                "|:--|:--|:--|",
                "| ⚪ 🔒 | **Consider tagging** <br> <sub>`security:llm-note`</sub> | "
                "[`variables.tf`](https://github.com/acme/example/blob/deadbeef/variables.tf) |",
                "",
                "</details>",
            ]
        )
        + "\n"
    )

    assert render_comment(findings, _pr()) == expected
