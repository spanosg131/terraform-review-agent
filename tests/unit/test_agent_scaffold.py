"""Smoke tests — exercise the compiled graph end-to-end with a real PRContext."""

from __future__ import annotations

from terraform_review_agent.agent import agent
from terraform_review_agent.utils.state import (
    ChangedFile,
    PRContext,
    ReviewState,
)


def _pr_context(files: list[ChangedFile]) -> PRContext:
    return PRContext(
        repository="acme/example",
        pr_number=1,
        base_sha="aaaaaaa",
        head_sha="bbbbbbb",
        base_ref="main",
        head_ref="feature/x",
        changed_files=files,
    )


def test_graph_runs_with_terraform_changes() -> None:
    pr = _pr_context([ChangedFile(path="main.tf", status="modified")])

    final = agent.invoke(ReviewState(pr=pr))

    assert final["skipped"] is False
    assert final["security"] == []
    assert final["cost"] == []
    assert final["style"] == []
    # With no findings the aggregator still renders a clean "all clear" comment.
    assert final["comment_markdown"] == (
        "## Terraform Review Agent\n\nNo issues found in the changed Terraform files.\n"
    )


def test_graph_skips_when_no_terraform_files_changed() -> None:
    pr = _pr_context([ChangedFile(path="README.md", status="modified")])

    final = agent.invoke(ReviewState(pr=pr))

    assert final["skipped"] is True
    assert "no terraform files changed" in (final["skip_reason"] or "")


def test_graph_topology_contains_expected_nodes() -> None:
    nodes = set(agent.get_graph().nodes)

    assert {"start", "security", "cost", "style", "aggregator", "post_comment"} <= nodes
