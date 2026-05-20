"""System prompts and input rendering for the specialist review nodes.

Prompt text never lives in node code (see CLAUDE.md §6/§10). Nodes import
:func:`specialist_system_prompt` and :func:`build_specialist_input`.

The contract is deliberately narrow: scanners own *detection* and *severity*,
so the LLM is handed the scanner findings (each with a stable ``id``) and asked
only to reword them for clarity. It cannot change a finding's severity, file,
line, or rule, and it cannot add or drop findings — which keeps the finding
*set* identical across runs. Speculative LLM-discovered findings are opt-in
(``settings.enable_llm_findings``); when enabled the system prompt gains a
discovery clause.
"""

from __future__ import annotations

import json

from terraform_review_agent.utils.state import AgentName, Finding
from terraform_review_agent.utils.tools import FilePayload

_SEVERITY_VOCAB = "critical, high, medium, low, info"

_PERSONA: dict[AgentName, str] = {
    "security": "You are a senior cloud-security engineer reviewing a Terraform pull request.",
    "cost": "You are a FinOps engineer reviewing the cost impact of a Terraform pull request.",
    "style": "You are a Terraform style reviewer.",
}

_SCANNERS: dict[AgentName, str] = {
    "security": "the tfsec and checkov scanners",
    "cost": "the infracost diff",
    "style": "tflint and `terraform fmt -check`",
}

# Per-agent guidance for *how to phrase* the rewritten message/suggestion.
_MESSAGE_GUIDANCE: dict[AgentName, str] = {
    "security": (
        "Calibrate wording to real-world exploitability and blast radius; do not "
        "dramatize. `suggestion` is a concrete remediation, or null."
    ),
    "cost": (
        "Name the resource/project and state the monthly delta exactly as it "
        "appears in the finding — never invent or alter dollar amounts. "
        "`suggestion` is a concrete cost-reduction idea when one is obvious "
        "(smaller instance type, retention/lifecycle policy, autoscaling), else null."
    ),
    "style": (
        "Keep it objective and brief — these are maintainability nits. "
        "`suggestion` is a concrete fix, or null."
    ),
}

# Discovery guidance, appended only when settings.enable_llm_findings is set.
# Cost has no source of truth for invented dollar amounts, so it never discovers.
_DISCOVERY: dict[AgentName, str] = {
    "security": (
        "You may additionally report a real risk no scanner caught: add it to "
        "`discovered` with a rule id prefixed `security:llm-`, a severity from "
        f"[{_SEVERITY_VOCAB}], and a file/line in the changed code. Do this only "
        "when you are confident; otherwise leave `discovered` empty."
    ),
    "style": (
        "You may additionally report a clear style/maintainability issue the "
        "linters missed (naming, missing variable description/type, hardcoded "
        "values that belong in variables): add it to `discovered` with a rule id "
        "prefixed `style:llm-` and a file/line in the changed code. Otherwise "
        "leave `discovered` empty."
    ),
}

_ANNOTATION_TASK = """\
Each scanner finding below is listed with a stable integer `id`. For every \
finding you can make clearer, return one entry in `annotations` echoing that \
`id`, with `message` rewritten to a single concise sentence on the real impact \
and `suggestion` set to a concrete fix (or null). Omit findings you have \
nothing to add to — they keep the scanner's wording.

You MUST NOT change any finding's severity, file, line, or rule: those are \
fixed by the scanner. You cannot drop, merge, reorder, or split findings — the \
set of findings is owned by the scanners, not you."""

_NO_DISCOVERY = "Leave `discovered` empty: do not invent findings the scanners did not report."


def specialist_system_prompt(agent: AgentName, allow_discovery: bool) -> str:
    """Assemble the system prompt for ``agent``.

    ``allow_discovery`` toggles the speculative-findings clause (driven by
    ``settings.enable_llm_findings`` at the call site). Cost never discovers, so
    passing ``True`` for it still yields the no-discovery clause.
    """

    discovery = _DISCOVERY.get(agent) if allow_discovery else None
    return "\n\n".join(
        [
            f"{_PERSONA[agent]} You are given (1) findings from {_SCANNERS[agent]} "
            "and (2) the contents of the changed Terraform files.",
            _ANNOTATION_TASK,
            _MESSAGE_GUIDANCE[agent],
            discovery or _NO_DISCOVERY,
        ]
    )


def build_specialist_input(
    findings: list[Finding],
    payloads: list[FilePayload],
) -> str:
    """Render the human turn: id-tagged scanner findings (JSON) + file contents.

    Each finding is given its list index as ``id`` so the LLM's annotations can
    be matched back deterministically. The ``agent`` field is dropped — the node
    owns it and the LLM should not reason about it.
    """

    findings_json = json.dumps(
        [{"id": i, **f.model_dump(exclude={"agent"})} for i, f in enumerate(findings)],
        indent=2,
    )
    parts: list[str] = [
        "## Scanner findings",
        "```json",
        findings_json,
        "```",
        "",
        "## Changed Terraform files",
    ]
    if not payloads:
        parts.append("_(no file contents available)_")
    for payload in payloads:
        parts.append(f"### {payload.path} ({payload.mode})")
        parts.append("```hcl")
        parts.append(payload.content)
        parts.append("```")
    return "\n".join(parts)
