"""LangGraph wiring for the Terraform review agent.

Topology — specialist branches fan out in parallel, then aggregate:

    start ──► [security ∥ cost ∥ style] ──► aggregator ──► post_comment

The specialist branches write to disjoint state fields, so no reducers are
required. The specialist + aggregator nodes live in :mod:`utils.nodes`;
``post_comment`` is still a no-op stub pending Phase 6.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from terraform_review_agent.utils.nodes import (
    aggregator_node,
    cost_node,
    security_node,
    style_node,
)
from terraform_review_agent.utils.state import ReviewState


def start_node(state: ReviewState) -> dict[str, object]:
    """Branch on whether the PR touches terraform files at all."""

    if not state.pr.has_terraform_changes:
        return {"skipped": True, "skip_reason": "no terraform files changed"}
    return {"skipped": False}


def post_comment_node(state: ReviewState) -> dict[str, object]:
    """Placeholder — Phase 6 wires the GitHub sticky-comment upsert."""

    return {"posted_comment_id": None}


def build_graph() -> StateGraph[ReviewState]:
    graph: StateGraph[ReviewState] = StateGraph(ReviewState)

    graph.add_node("start", start_node)
    graph.add_node("security", security_node)
    graph.add_node("cost", cost_node)
    graph.add_node("style", style_node)
    graph.add_node("aggregator", aggregator_node)
    graph.add_node("post_comment", post_comment_node)

    graph.add_edge(START, "start")
    graph.add_edge("start", "security")
    graph.add_edge("start", "cost")
    graph.add_edge("start", "style")
    graph.add_edge("security", "aggregator")
    graph.add_edge("cost", "aggregator")
    graph.add_edge("style", "aggregator")
    graph.add_edge("aggregator", "post_comment")
    graph.add_edge("post_comment", END)

    return graph


agent = build_graph().compile()
