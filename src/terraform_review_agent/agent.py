"""LangGraph scaffold for the Terraform review agent.

Topology (no-op nodes for Phase 1 — real logic lands in later phases):

    start ──► [security ∥ cost ∥ style] ──► aggregator ──► post_comment

Specialist branches write to disjoint state fields so no reducer is required.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field


class ReviewState(BaseModel):
    """Placeholder state — replaced with the full schema in Phase 2."""

    started: bool = False
    security_done: bool = False
    cost_done: bool = False
    style_done: bool = False
    aggregated: bool = False
    posted: bool = False
    comment_markdown: str | None = Field(default=None)


def start_node(state: ReviewState) -> dict[str, bool]:
    return {"started": True}


def security_node(state: ReviewState) -> dict[str, bool]:
    return {"security_done": True}


def cost_node(state: ReviewState) -> dict[str, bool]:
    return {"cost_done": True}


def style_node(state: ReviewState) -> dict[str, bool]:
    return {"style_done": True}


def aggregator_node(state: ReviewState) -> dict[str, object]:
    return {"aggregated": True, "comment_markdown": ""}


def post_comment_node(state: ReviewState) -> dict[str, bool]:
    return {"posted": True}


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
