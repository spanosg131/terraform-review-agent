"""Unit tests for the specialist nodes in :mod:`utils.nodes`.

Both sides of each node are stubbed: scanner ``@tool`` objects are replaced with
fakes returning canned ``Finding``/raising ``ScannerError``, and ``get_llm`` is
replaced with a fake chat model whose structured-output runnable returns a
canned :class:`SpecialistAnnotations`. No subprocesses or network calls run.

The contract under test: scanner findings are canonical — their severity, file,
line, and rule survive verbatim and the finding *set* is fixed by the scanners.
The LLM may only reword ``message``/``suggestion`` (matched back by ``id``).
Speculative LLM-discovered findings are gated on ``settings.enable_llm_findings``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from terraform_review_agent.utils import nodes
from terraform_review_agent.utils.state import (
    ChangedFile,
    CostReport,
    CostSummary,
    Finding,
    FindingAnnotation,
    LLMFinding,
    PRContext,
    ReviewState,
    SpecialistAnnotations,
)
from terraform_review_agent.utils.tools import ScannerError

# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class _FakeTool:
    """Stand-in for a scanner ``@tool``: returns a canned result or raises on invoke."""

    def __init__(self, result: Any) -> None:
        self._result = result
        self.calls: list[dict[str, Any]] = []

    def invoke(self, payload: dict[str, Any]) -> Any:
        self.calls.append(payload)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _FakeStructured:
    def __init__(self, result: SpecialistAnnotations) -> None:
        self._result = result
        self.messages: list[Any] = []

    def invoke(self, messages: Any) -> SpecialistAnnotations:
        self.messages = messages
        return self._result


class _FakeLLM:
    def __init__(self, result: SpecialistAnnotations) -> None:
        self.structured = _FakeStructured(result)
        self.schema: Any = None

    def with_structured_output(self, schema: Any) -> _FakeStructured:
        self.schema = schema
        return self.structured


def _patch_llm(monkeypatch: pytest.MonkeyPatch, result: SpecialistAnnotations) -> _FakeLLM:
    llm = _FakeLLM(result)
    monkeypatch.setattr(nodes, "get_llm", lambda *a, **k: llm)
    return llm


def _forbid_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("LLM must not be invoked for this state")

    monkeypatch.setattr(nodes, "get_llm", _boom)


def _pr(files: list[ChangedFile]) -> PRContext:
    return PRContext(
        repository="acme/example",
        pr_number=7,
        base_sha="a" * 7,
        head_sha="b" * 7,
        base_ref="main",
        head_ref="feature/x",
        changed_files=files,
    )


def _state(
    workspace: Path, *, files: list[ChangedFile], baseline: str | None = None
) -> ReviewState:
    return ReviewState(
        pr=_pr(files),
        workspace=str(workspace),
        cost_baseline_path=baseline,
    )


@pytest.fixture(autouse=True)
def _no_usage_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    # cost_node auto-syncs an infracost usage file, which shells out to
    # infracost. Default it off so unit tests don't; the cost tests that care
    # about usage-file threading override this.
    monkeypatch.setattr(nodes, "build_synced_usage_file", lambda _wd: None)


# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------


def test_security_node_runs_scanners_then_llm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    tfsec = _FakeTool(
        [Finding(agent="security", severity="high", file="main.tf", rule="tfsec:x", message="raw")]
    )
    checkov = _FakeTool([])
    monkeypatch.setattr(nodes, "run_tfsec", tfsec)
    monkeypatch.setattr(nodes, "run_checkov", checkov)
    llm = _patch_llm(
        monkeypatch,
        SpecialistAnnotations(
            annotations=[
                FindingAnnotation(
                    id=0, message="Public S3 bucket", suggestion="Add a bucket policy"
                )
            ]
        ),
    )

    out = nodes.security_node(state)

    assert tfsec.calls == [{"working_dir": str(tmp_path)}]
    assert checkov.calls == [{"working_dir": str(tmp_path)}]
    findings = out["security"]
    assert len(findings) == 1
    f = findings[0]
    assert f.agent == "security"
    # Scanner owns severity/rule; LLM only reworded the message/suggestion.
    assert f.severity == "high"
    assert f.rule == "tfsec:x"
    assert f.message == "Public S3 bucket"
    assert f.suggestion == "Add a bucket policy"
    assert llm.schema is SpecialistAnnotations
    # The raw scanner finding and the file content are both handed to the LLM.
    human = llm.structured.messages[1].content
    assert "tfsec:x" in human
    assert "aws_s3_bucket" in human


def test_security_node_keeps_scanner_text_when_unannotated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A finding the LLM returns no annotation for keeps the scanner's own
    # message/suggestion verbatim — it is never dropped.
    (tmp_path / "main.tf").write_text("resource {}\n")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(
        nodes,
        "run_tfsec",
        _FakeTool(
            [
                Finding(
                    agent="security",
                    severity="high",
                    file="main.tf",
                    rule="tfsec:x",
                    message="scanner message",
                    suggestion="scanner fix",
                )
            ]
        ),
    )
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    _patch_llm(monkeypatch, SpecialistAnnotations(annotations=[]))

    out = nodes.security_node(state)

    f = out["security"][0]
    assert f.message == "scanner message"
    assert f.suggestion == "scanner fix"
    assert f.severity == "high"


def test_security_node_blank_annotation_preserves_scanner_text(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A blank/whitespace message or suggestion from the LLM means "nothing to
    # add" — it must not erase the scanner's own message/remediation.
    (tmp_path / "main.tf").write_text("resource {}\n")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(
        nodes,
        "run_tfsec",
        _FakeTool(
            [
                Finding(
                    agent="security",
                    severity="high",
                    file="main.tf",
                    rule="tfsec:x",
                    message="scanner message",
                    suggestion="scanner remediation",
                )
            ]
        ),
    )
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="   ", suggestion="")]),
    )

    out = nodes.security_node(state)

    f = out["security"][0]
    assert f.message == "scanner message"
    assert f.suggestion == "scanner remediation"


def test_security_node_filters_unchanged_file_findings_from_llm_input(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Scanners run repo-wide; a finding in an unchanged file must not be fed to
    # the LLM (deterministic pre-filter), only the changed-file finding.
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    tfsec = _FakeTool(
        [
            Finding(
                agent="security", severity="high", file="main.tf", rule="tfsec:changed", message="r"
            ),
            Finding(
                agent="security",
                severity="high",
                file="legacy/old.tf",
                rule="tfsec:unchanged",
                message="r",
            ),
        ]
    )
    monkeypatch.setattr(nodes, "run_tfsec", tfsec)
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    llm = _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="ok")]),
    )

    out = nodes.security_node(state)

    human = llm.structured.messages[1].content
    assert "tfsec:changed" in human
    assert "tfsec:unchanged" not in human
    assert "legacy/old.tf" not in human
    assert [f.rule for f in out["security"]] == ["tfsec:changed"]


def test_security_node_discovery_off_ignores_llm_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # With discovery disabled (default) the scanners reported nothing, so the
    # LLM is never consulted and no speculative findings leak through.
    (tmp_path / "main.tf").write_text("resource {}\n")
    monkeypatch.setattr(nodes.settings, "enable_llm_findings", False)
    _forbid_llm(monkeypatch)
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(nodes, "run_tfsec", _FakeTool([]))
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))

    assert nodes.security_node(state) == {"security": []}


def test_security_node_discovery_on_post_filters_to_changed_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # With discovery enabled the LLM may add `discovered` findings; any that
    # land outside the changed files are stripped by the post-filter.
    (tmp_path / "main.tf").write_text("resource {}\n")
    monkeypatch.setattr(nodes.settings, "enable_llm_findings", True)
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(nodes, "run_tfsec", _FakeTool([]))
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(
            discovered=[
                LLMFinding(severity="high", file="main.tf", rule="security:llm-1", message="real"),
                LLMFinding(
                    severity="high", file="other/untouched.tf", rule="security:llm-2", message="x"
                ),
            ]
        ),
    )

    out = nodes.security_node(state)

    assert [f.file for f in out["security"]] == ["main.tf"]
    assert [f.rule for f in out["security"]] == ["security:llm-1"]


def test_security_node_discovery_namespaces_rule_ids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A discovered finding cannot masquerade as scanner output: its rule is
    # coerced into the `security:llm-` namespace regardless of what the LLM
    # returned (here a scanner-looking id and a bare slug).
    (tmp_path / "main.tf").write_text("resource {}\n")
    monkeypatch.setattr(nodes.settings, "enable_llm_findings", True)
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(nodes, "run_tfsec", _FakeTool([]))
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(
            discovered=[
                LLMFinding(severity="high", file="main.tf", rule="tfsec:fake", message="spoof"),
                LLMFinding(severity="low", file="main.tf", rule="public-bucket", message="bare"),
                LLMFinding(
                    severity="low", file="main.tf", rule="security:llm-ok", message="already ok"
                ),
            ]
        ),
    )

    out = nodes.security_node(state)

    rules = [f.rule for f in out["security"]]
    assert rules == ["security:llm-fake", "security:llm-public-bucket", "security:llm-ok"]
    # Nothing leaked through with a scanner namespace.
    assert not any(r.startswith(("tfsec:", "checkov:")) for r in rules)


def test_security_node_skips_when_no_terraform_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _forbid_llm(monkeypatch)
    tfsec, checkov = _FakeTool([]), _FakeTool([])
    monkeypatch.setattr(nodes, "run_tfsec", tfsec)
    monkeypatch.setattr(nodes, "run_checkov", checkov)
    # No Terraform file changed -> nothing to scan or review.
    state = _state(tmp_path, files=[ChangedFile(path="README.md")])

    assert nodes.security_node(state) == {"security": []}
    assert tfsec.calls == [] and checkov.calls == []


def test_security_node_runs_scanners_when_payloads_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: a large PR whose patches GitHub omitted yields empty payloads,
    but the Terraform files still need scanning. The node must run scanners and
    surface their findings rather than skipping the whole review."""

    # Terraform file changed but absent on disk with no patch -> payloads empty.
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    tfsec = _FakeTool(
        [Finding(agent="security", severity="high", file="main.tf", rule="tfsec:x", message="raw")]
    )
    monkeypatch.setattr(nodes, "run_tfsec", tfsec)
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="ok")]),
    )

    out = nodes.security_node(state)

    assert tfsec.calls == [{"working_dir": str(tmp_path)}]
    assert [f.rule for f in out["security"]] == ["tfsec:x"]


def test_security_node_tolerates_missing_scanner_binary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "main.tf").write_text("resource {}\n")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(nodes, "run_tfsec", _FakeTool(ScannerError("tfsec missing")))
    checkov = _FakeTool(
        [Finding(agent="security", severity="low", file="main.tf", rule="checkov:y", message="raw")]
    )
    monkeypatch.setattr(nodes, "run_checkov", checkov)
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="ok")]),
    )

    out = nodes.security_node(state)

    # tfsec blew up but the node still produced checkov-derived findings.
    assert [f.rule for f in out["security"]] == ["checkov:y"]


# ---------------------------------------------------------------------------
# cost
# ---------------------------------------------------------------------------


def test_cost_node_skips_without_api_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Gate is the infracost key: even with a baseline present, no key => skip.
    monkeypatch.setattr(nodes.settings, "infracost_api_key", None)
    _forbid_llm(monkeypatch)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(tmp_path / "b.json"))

    assert nodes.cost_node(state) == {"cost": []}


def test_cost_node_runs_infracost_when_payloads_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: empty payloads (large PR, omitted patches) must not suppress
    infracost, which prices the workspace on disk without LLM payloads."""

    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    # Terraform file changed but absent on disk with no patch -> payloads empty.
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    infracost = _FakeTool(
        CostReport(
            findings=[
                Finding(
                    agent="cost",
                    severity="medium",
                    file="main.tf",
                    rule="infracost:resource-delta",
                    message="raw delta",
                )
            ],
            summary=CostSummary(total_monthly=26.0, delta_monthly=25.0),
        )
    )
    monkeypatch.setattr(nodes, "run_infracost_diff", infracost)
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="+$25/mo")]),
    )

    out = nodes.cost_node(state)

    assert infracost.calls and infracost.calls[0]["working_dir"] == str(tmp_path)
    assert [f.rule for f in out["cost"]] == ["infracost:resource-delta"]


def test_cost_node_runs_infracost_then_llm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    infracost = _FakeTool(
        CostReport(
            findings=[
                Finding(
                    agent="cost",
                    severity="medium",
                    file="main.tf",
                    rule="infracost:resource-delta",
                    message="raw delta",
                )
            ],
            summary=CostSummary(total_monthly=26.0, delta_monthly=25.0),
        )
    )
    monkeypatch.setattr(nodes, "run_infracost_diff", infracost)
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(
            annotations=[
                FindingAnnotation(
                    id=0,
                    message="+$25/mo for aws_instance.w",
                    suggestion="Use a smaller instance type",
                )
            ]
        ),
    )

    out = nodes.cost_node(state)

    assert infracost.calls == [
        {
            "working_dir": str(tmp_path),
            "baseline_path": str(baseline),
            "usage_file_path": None,
        }
    ]
    assert [f.agent for f in out["cost"]] == ["cost"]
    # Scanner owns the severity; the LLM only reworded the message.
    assert out["cost"][0].severity == "medium"
    assert out["cost"][0].message.startswith("+$25")
    # The absolute total + delta are surfaced via cost_summary.
    assert out["cost_summary"] == CostSummary(total_monthly=26.0, delta_monthly=25.0)


def test_cost_node_auto_generates_baseline_when_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # No pre-built baseline => the node builds one from the workspace git history.
    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=None)

    monkeypatch.setattr(
        nodes,
        "build_infracost_baseline",
        lambda wd, name, usage_file_path=None: "/tmp/generated.json",
    )
    infracost = _FakeTool(
        CostReport(
            findings=[
                Finding(
                    agent="cost",
                    severity="medium",
                    file="main.tf",
                    rule="infracost:resource-delta",
                    message="raw",
                )
            ],
            summary=CostSummary(total_monthly=10.0, delta_monthly=5.0),
        )
    )
    monkeypatch.setattr(nodes, "run_infracost_diff", infracost)
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="+$5/mo")]),
    )

    out = nodes.cost_node(state)

    assert infracost.calls == [
        {
            "working_dir": str(tmp_path),
            "baseline_path": "/tmp/generated.json",
            "usage_file_path": None,
        }
    ]
    assert [f.agent for f in out["cost"]] == ["cost"]


def test_cost_node_applies_synced_usage_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The auto-synced usage file is applied to BOTH the base breakdown and the
    # head diff, so usage-based resources are priced and the delta stays
    # apples-to-apples.
    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    _forbid_llm(monkeypatch)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    monkeypatch.setattr(nodes, "build_synced_usage_file", lambda _wd: "/tmp/usage.yml")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=None)

    baseline_calls: list[dict[str, Any]] = []

    def _fake_baseline(wd: str, name: str, usage_file_path: str | None = None) -> str:
        baseline_calls.append({"working_dir": wd, "usage_file_path": usage_file_path})
        return "/tmp/generated.json"

    monkeypatch.setattr(nodes, "build_infracost_baseline", _fake_baseline)
    infracost = _FakeTool(
        CostReport(findings=[], summary=CostSummary(total_monthly=42.0, delta_monthly=0.0))
    )
    monkeypatch.setattr(nodes, "run_infracost_diff", infracost)

    nodes.cost_node(state)

    assert baseline_calls == [{"working_dir": str(tmp_path), "usage_file_path": "/tmp/usage.yml"}]
    assert infracost.calls == [
        {
            "working_dir": str(tmp_path),
            "baseline_path": "/tmp/generated.json",
            "usage_file_path": "/tmp/usage.yml",
        }
    ]


def test_cost_node_reports_summary_with_no_resource_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Cost-neutral PR: no per-resource findings (so no LLM call), but the
    # absolute total is still surfaced via cost_summary.
    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    _forbid_llm(monkeypatch)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    summary = CostSummary(total_monthly=21.90, delta_monthly=0.0)
    monkeypatch.setattr(
        nodes, "run_infracost_diff", _FakeTool(CostReport(findings=[], summary=summary))
    )

    out = nodes.cost_node(state)

    assert out["cost"] == []
    assert out["cost_summary"] == summary


def test_cost_node_discovery_flag_never_invents_cost_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Even with enable_llm_findings on, cost has no source of truth for invented
    # dollar amounts, so `discovered` is ignored for the cost agent.
    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    monkeypatch.setattr(nodes.settings, "enable_llm_findings", True)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    infracost = _FakeTool(
        CostReport(
            findings=[
                Finding(
                    agent="cost",
                    severity="medium",
                    file="main.tf",
                    rule="infracost:resource-delta",
                    message="raw",
                )
            ],
            summary=CostSummary(total_monthly=26.0, delta_monthly=25.0),
        )
    )
    monkeypatch.setattr(nodes, "run_infracost_diff", infracost)
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(
            annotations=[FindingAnnotation(id=0, message="+$25/mo")],
            discovered=[
                LLMFinding(severity="high", file="main.tf", rule="cost:llm-1", message="invented")
            ],
        ),
    )

    out = nodes.cost_node(state)

    assert [f.rule for f in out["cost"]] == ["infracost:resource-delta"]


def test_cost_node_tolerates_infracost_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(nodes.settings, "infracost_api_key", SecretStr("k"))
    _forbid_llm(monkeypatch)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    monkeypatch.setattr(nodes, "run_infracost_diff", _FakeTool(ScannerError("infracost boom")))

    assert nodes.cost_node(state) == {"cost": []}


# ---------------------------------------------------------------------------
# style
# ---------------------------------------------------------------------------


def test_style_node_runs_scanners_then_llm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("variable x {}\n")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    tflint = _FakeTool(
        [Finding(agent="style", severity="medium", file="main.tf", rule="tflint:z", message="raw")]
    )
    fmt = _FakeTool([])
    monkeypatch.setattr(nodes, "run_tflint", tflint)
    monkeypatch.setattr(nodes, "run_terraform_fmt", fmt)
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="Add type")]),
    )

    out = nodes.style_node(state)

    assert tflint.calls and fmt.calls
    assert [f.agent for f in out["style"]] == ["style"]
    # Scanner owns the severity; the LLM cannot downgrade it.
    assert out["style"][0].severity == "medium"
    assert out["style"][0].message == "Add type"


def test_style_node_skips_when_no_terraform_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _forbid_llm(monkeypatch)
    tflint, fmt = _FakeTool([]), _FakeTool([])
    monkeypatch.setattr(nodes, "run_tflint", tflint)
    monkeypatch.setattr(nodes, "run_terraform_fmt", fmt)
    state = _state(tmp_path, files=[ChangedFile(path="README.md")])

    assert nodes.style_node(state) == {"style": []}
    assert tflint.calls == [] and fmt.calls == []


def test_style_node_runs_scanners_when_payloads_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: empty payloads (large PR, omitted patches) must not suppress
    the style scanners, which read the workspace from disk."""

    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    tflint = _FakeTool(
        [Finding(agent="style", severity="low", file="main.tf", rule="tflint:z", message="raw")]
    )
    monkeypatch.setattr(nodes, "run_tflint", tflint)
    monkeypatch.setattr(nodes, "run_terraform_fmt", _FakeTool([]))
    _patch_llm(
        monkeypatch,
        SpecialistAnnotations(annotations=[FindingAnnotation(id=0, message="ok")]),
    )

    out = nodes.style_node(state)

    assert tflint.calls == [{"working_dir": str(tmp_path)}]
    assert [f.rule for f in out["style"]] == ["tflint:z"]


def test_style_node_pre_filters_unchanged_and_post_filters_discovered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Pre-filter: an unchanged-file scanner finding never reaches the LLM.
    # Post-filter (discovery on): a discovered finding outside the changed files
    # is stripped from the output.
    (tmp_path / "main.tf").write_text("variable x {}\n")
    monkeypatch.setattr(nodes.settings, "enable_llm_findings", True)
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(
        nodes,
        "run_tflint",
        _FakeTool(
            [
                Finding(
                    agent="style", severity="low", file="main.tf", rule="tflint:z", message="r"
                ),
                Finding(
                    agent="style",
                    severity="low",
                    file="legacy/old.tf",
                    rule="tflint:unchanged",
                    message="r",
                ),
            ]
        ),
    )
    monkeypatch.setattr(nodes, "run_terraform_fmt", _FakeTool([]))
    llm = _patch_llm(
        monkeypatch,
        SpecialistAnnotations(
            annotations=[FindingAnnotation(id=0, message="ok")],
            discovered=[
                LLMFinding(
                    severity="low", file="legacy/old.tf", rule="style:llm-leak", message="leak"
                ),
                LLMFinding(severity="low", file="main.tf", rule="style:llm-1", message="real"),
            ],
        ),
    )

    out = nodes.style_node(state)

    human = llm.structured.messages[1].content
    assert "tflint:unchanged" not in human
    assert "legacy/old.tf" not in human
    assert sorted(f.file for f in out["style"]) == ["main.tf", "main.tf"]
    assert "style:llm-leak" not in [f.rule for f in out["style"]]


# ---------------------------------------------------------------------------
# structured-output coercion
# ---------------------------------------------------------------------------


def test_annotate_with_llm_coerces_dict_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Some providers return a dict rather than the pydantic model instance.
    class _DictStructured:
        def invoke(self, _messages: Any) -> dict[str, Any]:
            return {"annotations": [{"id": 0, "message": "m", "suggestion": None}]}

    class _DictLLM:
        def with_structured_output(self, _schema: Any) -> _DictStructured:
            return _DictStructured()

    monkeypatch.setattr(nodes, "get_llm", lambda *a, **k: _DictLLM())

    raw = [Finding(agent="security", severity="info", file="a.tf", rule="r", message="raw")]
    findings = nodes._annotate_with_llm("security", raw, [])

    assert len(findings) == 1
    assert findings[0].agent == "security"
    assert findings[0].rule == "r"
    assert findings[0].message == "m"
