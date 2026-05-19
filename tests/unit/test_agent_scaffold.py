"""Phase 1 scaffold tests — exercise the no-op graph end-to-end."""

from __future__ import annotations

from terraform_review_agent.agent import ReviewState, agent


def test_graph_runs_all_nodes() -> None:
    final = agent.invoke(ReviewState())

    assert final["started"] is True
    assert final["security_done"] is True
    assert final["cost_done"] is True
    assert final["style_done"] is True
    assert final["aggregated"] is True
    assert final["posted"] is True


def test_graph_topology_contains_expected_nodes() -> None:
    nodes = set(agent.get_graph().nodes)

    assert {"start", "security", "cost", "style", "aggregator", "post_comment"} <= nodes
