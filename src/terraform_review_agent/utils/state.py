"""Pydantic state schemas for the review graph.

Specialist branches (security / cost / style) write to disjoint fields, so the
graph needs no custom reducers — each agent owns its own list.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
AgentName = Literal["security", "cost", "style"]

TERRAFORM_SUFFIXES = (".tf", ".tfvars", ".tf.json", ".tfvars.json")

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ChangedFile(BaseModel):
    """One file touched by the PR — restricted to terraform-relevant paths."""

    model_config = ConfigDict(frozen=True)

    path: str
    status: Literal["added", "modified", "removed", "renamed"] = "modified"
    additions: int = 0
    deletions: int = 0
    patch: str | None = None
    previous_path: str | None = None

    @property
    def is_terraform(self) -> bool:
        """True if the new or pre-rename path is a Terraform file.

        Renaming a ``.tf`` to a non-Terraform suffix drops its resources from
        Terraform's view, so the old path must count as a Terraform change.
        """

        return self.path.endswith(TERRAFORM_SUFFIXES) or bool(
            self.previous_path and self.previous_path.endswith(TERRAFORM_SUFFIXES)
        )


class PRContext(BaseModel):
    """Metadata + changed-file payload describing the PR under review."""

    repository: str = Field(description="`owner/repo` slug")
    pr_number: int
    base_sha: str
    head_sha: str
    base_ref: str
    head_ref: str
    title: str = ""
    author: str = ""
    changed_files: list[ChangedFile] = Field(default_factory=list)

    @property
    def has_terraform_changes(self) -> bool:
        return any(f.is_terraform for f in self.changed_files)

    @property
    def changed_terraform_paths(self) -> set[str]:
        """Repo-relative paths of changed Terraform files (incl. pre-rename names).

        Used to scope repo-wide scanner findings down to the files this PR
        actually touched.
        """

        paths: set[str] = set()
        for f in self.changed_files:
            if not f.is_terraform:
                continue
            paths.add(f.path)
            if f.previous_path:
                paths.add(f.previous_path)
        return paths


class Finding(BaseModel):
    """A single normalized review finding produced by a specialist agent."""

    agent: AgentName
    severity: Severity
    file: str
    line: int | None = None
    rule: str
    message: str
    suggestion: str | None = None

    def dedupe_key(self) -> tuple[str, str, int | None]:
        """Identity for cross-agent deduplication."""

        return (self.file, self.rule, self.line)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]


class LLMFinding(BaseModel):
    """A finding the LLM discovered that no scanner reported (no ``agent`` field).

    Only used when ``settings.enable_llm_findings`` is true. The owning node
    stamps the agent label when mapping these to :class:`Finding`, so the model
    can't mislabel the source. Scanner-reported findings never flow through this
    model — those keep their deterministic severity/file/line/rule.
    """

    severity: Severity
    file: str
    line: int | None = None
    rule: str
    message: str
    suggestion: str | None = None


class FindingAnnotation(BaseModel):
    """A wording-only refinement the LLM applies to one scanner finding.

    Keyed by the ``id`` the node assigned when listing the scanner findings.
    The LLM may rewrite ``message``/``suggestion`` for clarity but cannot change
    a finding's severity, file, line, or rule — those stay as the scanner
    reported them, which keeps the finding *set* identical across runs.
    """

    id: int
    message: str
    suggestion: str | None = None


class SpecialistAnnotations(BaseModel):
    """Structured-output container for a specialist LLM call.

    ``annotations`` reword the scanner findings (deterministic set); ``discovered``
    holds extra LLM-only findings and is ignored unless
    ``settings.enable_llm_findings`` is set.
    """

    annotations: list[FindingAnnotation] = Field(default_factory=list)
    discovered: list[LLMFinding] = Field(default_factory=list)


class CostSummary(BaseModel):
    """Absolute monthly cost of the PR head plus the change vs. the base ref."""

    total_monthly: float
    delta_monthly: float


class CostReport(BaseModel):
    """infracost diff output: per-resource delta findings + the cost summary."""

    findings: list[Finding] = Field(default_factory=list)
    summary: CostSummary | None = None


class ReviewState(BaseModel):
    """Top-level graph state.

    Specialist nodes populate ``security`` / ``cost`` / ``style`` independently.
    The aggregator emits ``comment_markdown``; ``post_comment`` records the
    resulting comment id (if any).
    """

    pr: PRContext
    workspace: str = Field(
        default=".",
        description="Path to the checked-out PR head where scanners run.",
    )
    cost_baseline_path: str | None = Field(
        default=None,
        description="infracost baseline JSON (base-ref breakdown); cost agent skips when unset.",
    )
    security: list[Finding] = Field(default_factory=list)
    cost: list[Finding] = Field(default_factory=list)
    cost_summary: CostSummary | None = None
    style: list[Finding] = Field(default_factory=list)
    comment_markdown: str | None = None
    posted_comment_id: int | None = None
    skipped: bool = False
    skip_reason: str | None = None

    def all_findings(self) -> list[Finding]:
        return [*self.security, *self.cost, *self.style]
