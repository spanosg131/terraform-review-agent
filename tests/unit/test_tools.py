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
    build_synced_usage_file,
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
# _relpath
# ---------------------------------------------------------------------------


def test_relpath_normalizes_absolute_path_under_relative_working_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: CI passes ``working_dir="."`` but tfsec/tflint report
    filesystem-absolute paths. ``_relpath`` must resolve ``"."`` to the cwd so
    the path becomes repo-relative; otherwise ``_filter_to_changed`` drops the
    finding as "unchanged"."""

    monkeypatch.chdir(tmp_path)
    abs_path = (tmp_path / "modules" / "db" / "main.tf").resolve()

    assert tools._relpath(str(abs_path), Path(".")) == "modules/db/main.tf"


def test_relpath_treats_checkov_leading_slash_as_workspace_relative(
    tmp_path: Path,
) -> None:
    """checkov reports ``/main.tf`` to mean workspace-relative, not absolute;
    such paths fall back to a stripped relative path."""

    assert tools._relpath("/main.tf", tmp_path) == "main.tf"


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


def test_run_converts_timeout_to_scanner_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: a hung scanner raises subprocess.TimeoutExpired, which is a
    SubprocessError (not a ScannerError). _run must convert it so the node-level
    ScannerError handlers skip the one scanner instead of failing the review."""

    monkeypatch.setattr(tools.shutil, "which", lambda _name: "/usr/bin/tfsec")

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    with pytest.raises(ScannerError, match="timed out"):
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


def _record_subprocess(monkeypatch: pytest.MonkeyPatch, *, binary_path: str) -> list[list[str]]:
    """Patch which + subprocess.run, recording every command (not just the last)."""

    calls: list[list[str]] = []
    monkeypatch.setattr(tools.shutil, "which", lambda _name: binary_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return _completed(stdout=json.dumps({"issues": []}))

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    return calls


def test_run_tflint_initializes_plugins_when_config_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Regression: a repo with .tflint.hcl declares plugins that need
    `tflint --init`. Without it, tflint errors on the plugin block and the
    repo silently loses plugin-rule style coverage."""

    (tmp_path / ".tflint.hcl").write_text('plugin "aws" {\n  enabled = true\n}\n')
    calls = _record_subprocess(monkeypatch, binary_path="/usr/bin/tflint")

    run_tflint.invoke({"working_dir": str(tmp_path)})

    assert ["/usr/bin/tflint", "--init"] in calls
    init_idx = calls.index(["/usr/bin/tflint", "--init"])
    scan_idx = next(i for i, c in enumerate(calls) if "--recursive" in c)
    assert init_idx < scan_idx, "tflint --init must run before the scan"


def test_run_tflint_skips_init_without_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No .tflint.hcl means no plugins to install; skip the init round-trip."""

    calls = _record_subprocess(monkeypatch, binary_path="/usr/bin/tflint")

    run_tflint.invoke({"working_dir": str(tmp_path)})

    assert not any("--init" in c for c in calls)


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


def test_parse_infracost_emits_resource_findings_and_summary(tmp_path: Path) -> None:
    payload = {
        # Top-level totals drive the summary (head absolute + delta vs base).
        "totalMonthlyCost": "120.00",
        "diffTotalMonthlyCost": "25.00",
        "projects": [
            {
                "name": "infra",
                "diff": {
                    "resources": [
                        {"name": "aws_instance.web", "monthlyCost": "25.0"},
                        {"name": "aws_instance.cache", "monthlyCost": "0"},
                    ],
                },
            }
        ],
    }

    report = _parse_infracost_diff(payload, tmp_path)

    # Per-resource deltas only (zero ones skipped); no standalone total finding.
    assert [f.rule for f in report.findings] == ["infracost:resource-delta"]
    resource = report.findings[0]
    assert resource.severity == "medium"
    assert "aws_instance.web" in resource.message
    assert "+$25.00" in resource.message
    # The summary carries the absolute monthly total + the change.
    assert report.summary is not None
    assert report.summary.total_monthly == 120.0
    assert report.summary.delta_monthly == 25.0


def test_parse_infracost_skips_zero_resources_but_keeps_summary(tmp_path: Path) -> None:
    payload = {
        "totalMonthlyCost": "21.90",
        "diffTotalMonthlyCost": "0",
        "projects": [
            {
                "name": "infra",
                "diff": {
                    "resources": [
                        {"name": "r1", "monthlyCost": None},
                        {"name": "r2", "monthlyCost": "n/a"},
                    ],
                },
            }
        ],
    }

    report = _parse_infracost_diff(payload, tmp_path)

    # No resource deltas, but a cost-neutral PR still reports its absolute total.
    assert report.findings == []
    assert report.summary is not None
    assert report.summary.total_monthly == 21.90
    assert report.summary.delta_monthly == 0.0


def test_parse_infracost_uses_metadata_path_not_repo_name(tmp_path: Path) -> None:
    """Regression: the head project is named after its git remote (owner/repo),
    which is not a repo file path. The finding file must come from metadata.path
    so rendered blob links point at a real path, not /blob/sha/owner/repo."""

    payload = {
        "totalMonthlyCost": "50.00",
        "diffTotalMonthlyCost": "10.00",
        "projects": [
            {
                "name": "acme/infra-repo",
                "metadata": {"path": "modules/db"},
                "diff": {"resources": [{"name": "aws_db_instance.main", "monthlyCost": "10.0"}]},
            }
        ],
    }

    report = _parse_infracost_diff(payload, tmp_path)

    assert [f.file for f in report.findings] == ["modules/db"]
    assert all(f.file != "acme/infra-repo" for f in report.findings)


def test_parse_infracost_falls_back_to_dot_when_no_metadata_path(tmp_path: Path) -> None:
    """Without metadata.path, fall back to "." (repo root), never the repo name."""

    payload = {
        "totalMonthlyCost": "10.00",
        "diffTotalMonthlyCost": "10.00",
        "projects": [
            {
                "name": "acme/infra-repo",
                "diff": {"resources": [{"name": "aws_s3_bucket.logs", "monthlyCost": "10.0"}]},
            }
        ],
    }

    report = _parse_infracost_diff(payload, tmp_path)

    assert [f.file for f in report.findings] == ["."]


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

    report = run_infracost_diff.invoke(
        {"working_dir": str(tmp_path), "baseline_path": str(baseline)}
    )

    assert report.findings == []
    assert report.summary is None
    cmd = captured["cmd"]
    assert "diff" in cmd
    assert "--compare-to" in cmd
    assert str(baseline) in cmd
    # No usage file given => no --usage-file flag.
    assert "--usage-file" not in cmd


def test_run_infracost_diff_passes_usage_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured = _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/infracost",
        completed=_completed(stdout=json.dumps({"totalMonthlyCost": "50.00"})),
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    usage = tmp_path / "infracost-usage.yml"
    usage.write_text("version: 0.1\nresource_usage: {}\n")

    report = run_infracost_diff.invoke(
        {
            "working_dir": str(tmp_path),
            "baseline_path": str(baseline),
            "usage_file_path": str(usage),
        }
    )

    cmd = captured["cmd"]
    assert "--usage-file" in cmd
    assert str(usage) in cmd
    assert report.summary is not None
    assert report.summary.total_monthly == 50.0


def test_build_synced_usage_file_syncs_and_returns_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def fake_which(_name: str) -> str:
        return "/usr/bin/infracost"

    def fake_run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        # Emulate infracost writing the synced usage file to the --usage-file path.
        target = cmd[cmd.index("--usage-file") + 1]
        Path(target).write_text("version: 0.1\nresource_usage: {}\n")
        return _completed(stdout="{}")

    monkeypatch.setattr(tools.shutil, "which", fake_which)
    monkeypatch.setattr(tools.subprocess, "run", fake_run)

    result = build_synced_usage_file(str(tmp_path))

    cmd = captured["cmd"]
    assert "breakdown" in cmd
    assert "--sync-usage-file" in cmd
    assert "--usage-file" in cmd
    assert result is not None
    assert Path(result).is_file()


def test_build_synced_usage_file_returns_none_when_infracost_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools.shutil, "which", lambda _name: None)

    assert build_synced_usage_file(str(tmp_path)) is None


def test_build_synced_usage_file_returns_none_when_sync_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # infracost present but the breakdown exits non-zero => best-effort None.
    _stub_subprocess(
        monkeypatch,
        binary_path="/usr/bin/infracost",
        completed=_completed(stderr="boom", returncode=1),
    )

    assert build_synced_usage_file(str(tmp_path)) is None


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


def test_prepare_file_payloads_skips_non_terraform_and_patchless_removed(
    tmp_path: Path,
) -> None:
    # Non-terraform files are excluded; a removed file with no patch has nothing
    # to read on disk and no diff to fall back to, so it is skipped too.
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


def test_prepare_file_payloads_emits_diff_only_for_removed_file_with_patch(
    tmp_path: Path,
) -> None:
    # A deleted .tf file is gone from disk but its patch carries the removed
    # lines — surface it as a diff_only payload so deletions stay reviewable.
    pr = _pr(
        [
            ChangedFile(
                path="deleted.tf",
                status="removed",
                patch='@@ -1,2 +0,0 @@\n-resource "aws_kms_key" "k" {}\n',
            )
        ]
    )

    payloads = prepare_file_payloads(pr, tmp_path)

    assert len(payloads) == 1
    assert payloads[0].path == "deleted.tf"
    assert payloads[0].mode == "diff_only"
    assert payloads[0].content.startswith("@@")


def test_prepare_file_payloads_falls_back_to_patch_when_file_missing(
    tmp_path: Path,
) -> None:
    # File not present on disk but PR includes a patch — emit diff-only payload.
    pr = _pr([ChangedFile(path="missing.tf", patch="@@ -1 +1 @@\n+x")])

    payloads = prepare_file_payloads(pr, tmp_path)

    assert len(payloads) == 1
    assert payloads[0].mode == "diff_only"
    assert payloads[0].content.startswith("@@")


def test_prepare_file_payloads_includes_terraform_renamed_to_non_terraform(
    tmp_path: Path,
) -> None:
    # main.tf renamed to main.txt: the HCL content lives on disk under the new
    # (non-.tf) path, so the previous_path must qualify it as a candidate.
    (tmp_path / "main.txt").write_text('resource "aws_s3_bucket" "b" {}\n')
    pr = _pr([ChangedFile(path="main.txt", status="renamed", previous_path="main.tf")])

    payloads = prepare_file_payloads(pr, tmp_path)

    assert len(payloads) == 1
    assert payloads[0].path == "main.txt"
    assert payloads[0].mode == "full"
    assert payloads[0].content.startswith('resource "aws_s3_bucket"')


# ---------------------------------------------------------------------------
# build_infracost_baseline
# ---------------------------------------------------------------------------


def test_build_infracost_baseline_breaks_down_base_parent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_which_or_raise", lambda b: b)
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], *, cwd: Any, **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        if "breakdown" in cmd:
            # infracost writes the JSON; emit a project named after its path so
            # the rename-to-head-name step has something to overwrite.
            out_file = cmd[cmd.index("--out-file") + 1]
            Path(out_file).write_text(json.dumps({"projects": [{"name": "/tmp/base"}]}))
        stdout = "basesha123\n" if "rev-parse" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(tools, "_run", fake_run)
    # worktree cleanup goes through subprocess.run directly.
    monkeypatch.setattr(
        tools.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""),
    )

    path = tools.build_infracost_baseline("/ws", "acme/example")

    assert path.endswith("infracost-base.json")
    breakdown = next(c for c in calls if c and c[0] == "infracost")
    assert "breakdown" in breakdown
    assert breakdown[breakdown.index("--out-file") + 1] == path
    worktree_add = next(c for c in calls if "worktree" in c and "add" in c)
    assert worktree_add[-1] == "basesha123"
    # The baseline's project name is pinned to the PR head's name so
    # `infracost diff` pairs them into a single delta.
    data = json.loads(Path(path).read_text())
    assert [p["name"] for p in data["projects"]] == ["acme/example"]


def test_build_infracost_baseline_raises_when_base_unresolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tools, "_which_or_raise", lambda b: b)
    monkeypatch.setattr(
        tools,
        "_run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="", stderr=""),
    )

    with pytest.raises(ScannerError):
        tools.build_infracost_baseline("/ws", "acme/example")
