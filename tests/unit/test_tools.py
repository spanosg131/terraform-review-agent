"""Unit tests for the scanner wrappers in :mod:`utils.tools`.

The wrappers shell out to real binaries (tfsec, checkov, tflint, terraform,
infracost), so every test stubs ``shutil.which`` + ``subprocess.run`` via
``monkeypatch``. Parsers are exercised directly with canned scanner payloads.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from terraform_review_agent.utils import tools
from terraform_review_agent.utils.state import ChangedFile, PRContext
from terraform_review_agent.utils.tools import (
    PER_FILE_CONTENT_CAP_BYTES,
    ScannerError,
    _parse_checkov,
    _parse_infracost_diff,
    _parse_tflint,
    _parse_tfsec,
    _severity_for_cost_delta,
    prepare_file_payloads,
    run_checkov,
    run_infracost_diff,
    run_terraform_fmt,
    run_tflint,
    run_tfsec,
)


def _completed(
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    args: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=args or ["scanner"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _stub_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    *,
    binary_path: str,
    completed: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    """Patch shutil.which + subprocess.run, returning a dict that captures the call."""

    captured: dict[str, Any] = {}

    def fake_which(name: str) -> str:
        return binary_path

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return completed

    monkeypatch.setattr(tools.shutil, "which", fake_which)
    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    return captured


# ---------------------------------------------------------------------------
# tfsec
# ---------------------------------------------------------------------------


def test_parse_tfsec_normalizes_severity_and_paths(tmp_path: Path) -> None:
    payload = {
        "results": [
            {
                "rule_id": "AWS017",
                "long_id": "aws-s3-encryption-customer-key",
                "rule_description": "S3 bucket not encrypted with CMK",
                "severity": "HIGH",
                "location": {
                    "filename": str(tmp_path / "main.tf"),
                    "start_line": 12,
                    "end_line": 15,
                },
                "description": "Public bucket",
                "resolution": "Use SSE-KMS",
            }
        ]
    }

    findings = _parse_tfsec(payload, tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.agent == "security"
    assert f.severity == "high"
    assert f.file == "main.tf"
    assert f.line == 12
    assert f.rule == "tfsec:aws-s3-encryption-customer-key"
    assert f.message == "Public bucket"
    assert f.suggestion == "Use SSE-KMS"


def test_parse_tfsec_handles_unknown_severity_and_missing_location() -> None:
    payload = {"results": [{"severity": "weird", "location": {}}]}

    findings = _parse_tfsec(payload, Path("/tmp"))

    assert findings[0].severity == "info"
    assert findings[0].rule == "tfsec:unknown"
    assert findings[0].file == ""
    assert findings[0].line is None


def test_parse_tfsec_empty_payload() -> None:
    assert _parse_tfsec({}, Path("/tmp")) == []


def test_run_tfsec_invokes_binary_and_returns_parsed_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/tfsec",
        completed=_completed(stdout=json.dumps({"results": []})),
    )

    findings = run_tfsec.invoke({"working_dir": str(tmp_path)})

    assert findings == []
    cmd = captured["cmd"]
    assert cmd[0] == "/usr/bin/tfsec"
    assert "--format" in cmd and "json" in cmd
    assert "--soft-fail" in cmd


def test_run_tfsec_raises_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda _name: None)

    with pytest.raises(ScannerError, match="tfsec"):
        run_tfsec.invoke({"working_dir": str(tmp_path)})


def test_run_tfsec_raises_on_invalid_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/tfsec",
        completed=_completed(stdout="not json"),
    )

    with pytest.raises(ScannerError, match="invalid JSON"):
        run_tfsec.invoke({"working_dir": str(tmp_path)})


def test_run_tfsec_raises_on_unexpected_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/tfsec",
        completed=_completed(stderr="boom", returncode=2),
    )

    with pytest.raises(ScannerError, match="exited with code 2"):
        run_tfsec.invoke({"working_dir": str(tmp_path)})


# ---------------------------------------------------------------------------
# checkov
# ---------------------------------------------------------------------------


def test_parse_checkov_dict_form(tmp_path: Path) -> None:
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_19",
                    "check_name": "Ensure S3 bucket is encrypted",
                    "severity": "MEDIUM",
                    "file_path": "/main.tf",
                    "file_line_range": [4, 9],
                    "guideline": "https://docs.example/ckv_aws_19",
                }
            ]
        }
    }

    findings = _parse_checkov(payload, tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.file == "main.tf"
    assert f.line == 4
    assert f.rule == "checkov:CKV_AWS_19"
    assert f.suggestion == "https://docs.example/ckv_aws_19"


def test_parse_checkov_list_form_aggregates_blocks(tmp_path: Path) -> None:
    payload: list[dict[str, Any]] = [
        {"results": {"failed_checks": []}},
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV2_AWS_1",
                        "check_name": "Ensure encryption",
                        "severity": "HIGH",
                        "file_path": "infra/main.tf",
                        "file_line_range": [1, 2],
                    }
                ]
            }
        },
    ]

    findings = _parse_checkov(payload, tmp_path)

    assert [f.rule for f in findings] == ["checkov:CKV2_AWS_1"]
    assert findings[0].severity == "high"


def test_parse_checkov_collapses_zero_line_to_none(tmp_path: Path) -> None:
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_GEN_1",
                    "check_name": "x",
                    "file_path": "main.tf",
                    "file_line_range": [0, 0],
                }
            ]
        }
    }

    findings = _parse_checkov(payload, tmp_path)

    assert findings[0].line is None


def test_run_checkov_returns_empty_when_stdout_blank(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/checkov",
        completed=_completed(stdout=""),
    )

    assert run_checkov.invoke({"working_dir": str(tmp_path)}) == []


def test_run_checkov_invokes_with_soft_fail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/checkov",
        completed=_completed(stdout=json.dumps({"results": {"failed_checks": []}})),
    )

    findings = run_checkov.invoke({"working_dir": str(tmp_path)})

    assert findings == []
    assert "--soft-fail" in captured["cmd"]
    assert "-o" in captured["cmd"] and "json" in captured["cmd"]


# ---------------------------------------------------------------------------
# tflint
# ---------------------------------------------------------------------------


def test_parse_tflint_maps_severities_and_paths(tmp_path: Path) -> None:
    payload = {
        "issues": [
            {
                "rule": {
                    "name": "terraform_unused_declarations",
                    "severity": "warning",
                    "link": "https://example/tflint-rule",
                },
                "message": "Unused variable",
                "range": {"filename": "main.tf", "start": {"line": 5}},
            },
            {
                "rule": {"name": "terraform_typed_variables", "severity": "error"},
                "message": "Variable missing type",
                "range": {"filename": "main.tf", "start": {"line": 9}},
            },
        ]
    }

    findings = _parse_tflint(payload, tmp_path)

    assert [f.severity for f in findings] == ["medium", "high"]
    assert findings[0].rule == "tflint:terraform_unused_declarations"
    assert findings[0].suggestion == "https://example/tflint-rule"
    assert findings[1].line == 9


def test_run_tflint_tolerates_nonzero_exit_with_issues(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/tflint",
        completed=_completed(stdout=json.dumps({"issues": []}), returncode=2),
    )

    assert run_tflint.invoke({"working_dir": str(tmp_path)}) == []


# ---------------------------------------------------------------------------
# terraform fmt
# ---------------------------------------------------------------------------


def test_run_terraform_fmt_emits_finding_per_unformatted_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/terraform",
        completed=_completed(stdout="main.tf\ninfra/network.tf\n\n", returncode=3),
    )

    findings = run_terraform_fmt.invoke({"working_dir": str(tmp_path)})

    assert [f.file for f in findings] == ["main.tf", "infra/network.tf"]
    assert all(f.agent == "style" for f in findings)
    assert all(f.rule == "terraform-fmt:unformatted" for f in findings)
    assert all(f.severity == "low" for f in findings)


def test_run_terraform_fmt_empty_when_already_formatted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/terraform",
        completed=_completed(stdout="", returncode=0),
    )

    assert run_terraform_fmt.invoke({"working_dir": str(tmp_path)}) == []


# ---------------------------------------------------------------------------
# infracost
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "delta,expected",
    [
        (250.0, "high"),
        (-150.0, "high"),
        (45.0, "medium"),
        (5.0, "low"),
        (0.5, "info"),
        (0.0, "info"),
    ],
)
def test_severity_for_cost_delta(delta: float, expected: str) -> None:
    assert _severity_for_cost_delta(delta) == expected


def test_parse_infracost_emits_resource_and_total_findings(tmp_path: Path) -> None:
    payload = {
        "projects": [
            {
                "name": "infra",
                "diff": {
                    "totalMonthlyCost": "120.00",
                    "resources": [
                        {"name": "aws_instance.web", "monthlyCost": "25.0"},
                        {"name": "aws_instance.cache", "monthlyCost": "0"},
                    ],
                },
            }
        ]
    }

    findings = _parse_infracost_diff(payload, tmp_path)

    rules = [f.rule for f in findings]
    assert "infracost:resource-delta" in rules
    assert "infracost:total-delta" in rules
    total = next(f for f in findings if f.rule == "infracost:total-delta")
    assert total.severity == "high"
    resource = next(f for f in findings if f.rule == "infracost:resource-delta")
    assert resource.severity == "medium"
    assert "aws_instance.web" in resource.message


def test_parse_infracost_skips_zero_and_unparseable(tmp_path: Path) -> None:
    payload = {
        "projects": [
            {
                "name": "infra",
                "diff": {
                    "totalMonthlyCost": "0",
                    "resources": [
                        {"name": "r1", "monthlyCost": None},
                        {"name": "r2", "monthlyCost": "n/a"},
                    ],
                },
            }
        ]
    }

    assert _parse_infracost_diff(payload, tmp_path) == []


def test_run_infracost_diff_invokes_with_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/infracost",
        completed=_completed(stdout=json.dumps({"projects": []})),
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")

    findings = run_infracost_diff.invoke(
        {"working_dir": str(tmp_path), "baseline_path": str(baseline)}
    )

    assert findings == []
    cmd = captured["cmd"]
    assert "diff" in cmd
    assert "--compare-to" in cmd
    assert str(baseline) in cmd


# ---------------------------------------------------------------------------
# per-file content cap + diff-only fallback
# ---------------------------------------------------------------------------


def _pr(files: list[ChangedFile]) -> PRContext:
    return PRContext(
        repository="acme/example",
        pr_number=42,
        base_sha="a" * 7,
        head_sha="b" * 7,
        base_ref="main",
        head_ref="feature/x",
        changed_files=files,
    )


def test_prepare_file_payloads_returns_full_content_for_small_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.tf").write_text('resource "x" "y" {}\n')
    pr = _pr([ChangedFile(path="main.tf")])

    payloads = prepare_file_payloads(pr, tmp_path)

    assert len(payloads) == 1
    assert payloads[0].mode == "full"
    assert payloads[0].content.startswith('resource "x" "y"')


def test_prepare_file_payloads_truncates_oversized_files(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("a" * (PER_FILE_CONTENT_CAP_BYTES + 4096))
    pr = _pr([ChangedFile(path="main.tf")])

    payloads = prepare_file_payloads(pr, tmp_path)

    assert payloads[0].mode == "truncated"
    assert "[content truncated" in payloads[0].content


def test_prepare_file_payloads_falls_back_to_diff_only_above_threshold(
    tmp_path: Path,
) -> None:
    files: list[ChangedFile] = []
    for i in range(20):
        path = f"f{i}.tf"
        (tmp_path / path).write_text("x" * 20_000)
        files.append(ChangedFile(path=path, patch=f"--- {path}\n+++ {path}\n"))
    pr = _pr(files)

    payloads = prepare_file_payloads(pr, tmp_path)

    assert len(payloads) == 20
    assert all(p.mode == "diff_only" for p in payloads)


def test_prepare_file_payloads_skips_removed_and_non_terraform(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text("resource {}")
    (tmp_path / "README.md").write_text("hi")
    pr = _pr(
        [
            ChangedFile(path="main.tf"),
            ChangedFile(path="README.md"),
            ChangedFile(path="deleted.tf", status="removed"),
        ]
    )

    payloads = prepare_file_payloads(pr, tmp_path)

    assert [p.path for p in payloads] == ["main.tf"]
    assert payloads[0].mode == "full"


def test_prepare_file_payloads_falls_back_to_patch_when_file_missing(
    tmp_path: Path,
) -> None:
    # File not present on disk but PR includes a patch — emit diff-only payload.
    pr = _pr([ChangedFile(path="missing.tf", patch="@@ -1 +1 @@\n+x")])

    payloads = prepare_file_payloads(pr, tmp_path)

    assert len(payloads) == 1
    assert payloads[0].mode == "diff_only"
    assert payloads[0].content.startswith("@@")
