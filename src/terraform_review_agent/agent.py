"""LangGraph wiring for the Terraform review agent.

Topology — specialist branches fan out in parallel, then aggregate:

    start ──► [security ∥ cost ∥ style] ──► aggregator ──► post_comment

The specialist branches write to disjoint state fields, so no reducers are
required. Real node implementations land in Phases 3-5; for now they are
no-op stubs that preserve the topology and let ``make test`` exercise the
compiled graph end-to-end.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from terraform_review_agent.utils.state import ReviewState


def start_node(state: ReviewState) -> dict[str, object]:
    """Branch on whether the PR touches terraform files at all."""

    if not state.pr.has_terraform_changes:
        return {"skipped": True, "skip_reason": "no terraform files changed"}
    return {"skipped": False}


def security_node(state: ReviewState) -> dict[str, object]:
    """Placeholder — Phase 4 wires tfsec + checkov + LLM normalization."""

    return {"security": []}


def cost_node(state: ReviewState) -> dict[str, object]:
    """Placeholder — Phase 4 wires infracost + LLM annotation."""

    return {"cost": []}


def style_node(state: ReviewState) -> dict[str, object]:
    """Placeholder — Phase 4 wires terraform fmt + tflint + LLM."""

    return {"style": []}


def aggregator_node(state: ReviewState) -> dict[str, object]:
    """Placeholder — Phase 5 renders the severity-ranked markdown comment."""

    return {"comment_markdown": ""}


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
