"""Unit tests for the specialist nodes in :mod:`utils.nodes`.

Both sides of each node are stubbed: scanner ``@tool`` objects are replaced with
fakes returning canned ``Finding``/raising ``ScannerError``, and ``get_llm`` is
replaced with a fake chat model whose structured-output runnable returns a
canned :class:`SpecialistReview`. No subprocesses or network calls run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from terraform_review_agent.utils import nodes
from terraform_review_agent.utils.state import (
    ChangedFile,
    Finding,
    LLMFinding,
    PRContext,
    ReviewState,
    SpecialistReview,
)
from terraform_review_agent.utils.tools import ScannerError

# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


class _FakeTool:
    """Stand-in for a scanner ``@tool``: returns findings or raises on invoke."""

    def __init__(self, result: list[Finding] | Exception) -> None:
        self._result = result
        self.calls: list[dict[str, Any]] = []

    def invoke(self, payload: dict[str, Any]) -> list[Finding]:
        self.calls.append(payload)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _FakeStructured:
    def __init__(self, review: SpecialistReview) -> None:
        self._review = review
        self.messages: list[Any] = []

    def invoke(self, messages: Any) -> SpecialistReview:
        self.messages = messages
        return self._review


class _FakeLLM:
    def __init__(self, review: SpecialistReview) -> None:
        self.structured = _FakeStructured(review)
        self.schema: Any = None

    def with_structured_output(self, schema: Any) -> _FakeStructured:
        self.schema = schema
        return self.structured


def _patch_llm(monkeypatch: pytest.MonkeyPatch, review: SpecialistReview) -> _FakeLLM:
    llm = _FakeLLM(review)
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
        SpecialistReview(
            findings=[
                LLMFinding(
                    severity="high",
                    file="main.tf",
                    line=1,
                    rule="tfsec:x",
                    message="Public S3 bucket",
                    suggestion="Add a bucket policy",
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
    assert f.rule == "tfsec:x"
    assert f.message == "Public S3 bucket"
    assert llm.schema is SpecialistReview
    # The raw scanner finding and the file content are both handed to the LLM.
    human = llm.structured.messages[1].content
    assert "tfsec:x" in human
    assert "aws_s3_bucket" in human


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
        SpecialistReview(
            findings=[
                LLMFinding(severity="high", file="main.tf", rule="tfsec:changed", message="ok")
            ]
        ),
    )

    out = nodes.security_node(state)

    human = llm.structured.messages[1].content
    assert "tfsec:changed" in human
    assert "tfsec:unchanged" not in human
    assert "legacy/old.tf" not in human
    assert [f.rule for f in out["security"]] == ["tfsec:changed"]


def test_security_node_drops_llm_findings_outside_changed_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Even if the LLM emits a finding for a file the PR did not touch, the
    # post-filter removes it from the output.
    (tmp_path / "main.tf").write_text("resource {}\n")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(nodes, "run_tfsec", _FakeTool([]))
    monkeypatch.setattr(nodes, "run_checkov", _FakeTool([]))
    _patch_llm(
        monkeypatch,
        SpecialistReview(
            findings=[
                LLMFinding(severity="high", file="main.tf", rule="security:llm-1", message="real"),
                LLMFinding(
                    severity="high", file="other/untouched.tf", rule="security:llm-2", message="x"
                ),
            ]
        ),
    )

    out = nodes.security_node(state)

    assert [f.file for f in out["security"]] == ["main.tf"]


def test_security_node_skips_when_no_terraform_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _forbid_llm(monkeypatch)
    # File is declared changed but absent on disk with no patch -> no payload.
    state = _state(tmp_path, files=[ChangedFile(path="missing.tf")])

    assert nodes.security_node(state) == {"security": []}


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
        SpecialistReview(
            findings=[LLMFinding(severity="low", file="main.tf", rule="checkov:y", message="ok")]
        ),
    )

    out = nodes.security_node(state)

    # tfsec blew up but the node still produced checkov-derived findings.
    assert [f.rule for f in out["security"]] == ["checkov:y"]


# ---------------------------------------------------------------------------
# cost
# ---------------------------------------------------------------------------


def test_cost_node_skips_without_baseline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _forbid_llm(monkeypatch)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=None)

    assert nodes.cost_node(state) == {"cost": []}


def test_cost_node_runs_infracost_then_llm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    infracost = _FakeTool(
        [
            Finding(
                agent="cost",
                severity="medium",
                file="main.tf",
                rule="infracost:resource-delta",
                message="raw delta",
            )
        ]
    )
    monkeypatch.setattr(nodes, "run_infracost_diff", infracost)
    _patch_llm(
        monkeypatch,
        SpecialistReview(
            findings=[
                LLMFinding(
                    severity="medium",
                    file="main.tf",
                    rule="infracost:resource-delta",
                    message="+$25/mo for aws_instance.w",
                    suggestion="Use a smaller instance type",
                )
            ]
        ),
    )

    out = nodes.cost_node(state)

    assert infracost.calls == [{"working_dir": str(tmp_path), "baseline_path": str(baseline)}]
    assert [f.agent for f in out["cost"]] == ["cost"]
    assert out["cost"][0].message.startswith("+$25")


def test_cost_node_skips_when_infracost_finds_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _forbid_llm(monkeypatch)
    (tmp_path / "main.tf").write_text('resource "aws_instance" "w" {}\n')
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")], baseline=str(baseline))

    monkeypatch.setattr(nodes, "run_infracost_diff", _FakeTool([]))

    assert nodes.cost_node(state) == {"cost": []}


def test_cost_node_tolerates_infracost_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
        SpecialistReview(
            findings=[
                LLMFinding(
                    severity="low", file="main.tf", line=1, rule="tflint:z", message="Add type"
                )
            ]
        ),
    )

    out = nodes.style_node(state)

    assert tflint.calls and fmt.calls
    assert [f.agent for f in out["style"]] == ["style"]
    assert out["style"][0].severity == "low"


def test_style_node_skips_when_no_terraform_payloads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _forbid_llm(monkeypatch)
    state = _state(tmp_path, files=[ChangedFile(path="README.md")])

    assert nodes.style_node(state) == {"style": []}


def test_style_node_filters_unchanged_files_pre_and_post(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "main.tf").write_text("variable x {}\n")
    state = _state(tmp_path, files=[ChangedFile(path="main.tf")])

    monkeypatch.setattr(
        nodes,
        "run_tflint",
        _FakeTool(
            [
                Finding(
                    agent="style",
                    severity="low",
                    file="legacy/old.tf",
                    rule="tflint:unchanged",
                    message="r",
                )
            ]
        ),
    )
    monkeypatch.setattr(nodes, "run_terraform_fmt", _FakeTool([]))
    llm = _patch_llm(
        monkeypatch,
        SpecialistReview(
            findings=[
                LLMFinding(
                    severity="low", file="legacy/old.tf", rule="tflint:unchanged", message="leak"
                ),
                LLMFinding(severity="low", file="main.tf", rule="style:llm-1", message="ok"),
            ]
        ),
    )

    out = nodes.style_node(state)

    # Unchanged-file scanner finding never reaches the LLM (pre-filter), and the
    # LLM's unchanged-file finding is stripped from the output (post-filter).
    human = llm.structured.messages[1].content
    assert "tflint:unchanged" not in human
    assert [f.file for f in out["style"]] == ["main.tf"]


# ---------------------------------------------------------------------------
# structured-output coercion
# ---------------------------------------------------------------------------


def test_review_with_llm_coerces_dict_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Some providers return a dict rather than the pydantic model instance.
    class _DictStructured:
        def invoke(self, _messages: Any) -> dict[str, Any]:
            return {"findings": [{"severity": "info", "file": "a.tf", "rule": "r", "message": "m"}]}

    class _DictLLM:
        def with_structured_output(self, _schema: Any) -> _DictStructured:
            return _DictStructured()

    monkeypatch.setattr(nodes, "get_llm", lambda *a, **k: _DictLLM())

    findings = nodes._review_with_llm("security", "sys", [], [])

    assert len(findings) == 1
    assert findings[0].agent == "security"
    assert findings[0].rule == "r"
