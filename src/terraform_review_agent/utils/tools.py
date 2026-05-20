"""Subprocess wrappers around the OSS Terraform scanners.

Each wrapper:

* Locates the scanner binary on ``PATH`` (raising :class:`ScannerError` if
  missing).
* Runs the scanner against a checkout of the PR's head commit.
* Parses the scanner's structured output.
* Returns a list of :class:`~terraform_review_agent.utils.state.Finding`
  records in the agent's normalized severity vocabulary.

Wrappers are ``@tool``-decorated so they can be bound to an LLM if we ever
want one; for now Phase 4 specialist nodes call them directly via
``.invoke({"working_dir": ...})``.

This module also exposes :func:`prepare_file_payloads`, the per-file content
cap + diff-only fallback used to keep specialist LLM prompts inside token
budgets on very large PRs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Literal

import structlog
from langchain_core.tools import tool
from pydantic import BaseModel

from terraform_review_agent.utils.state import (
    ChangedFile,
    CostReport,
    CostSummary,
    Finding,
    PRContext,
    Severity,
)

log = structlog.get_logger(__name__)


DEFAULT_SCANNER_TIMEOUT_SECONDS = 300


class ScannerError(RuntimeError):
    """Raised when a scanner binary is missing or fails unrecoverably."""


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _which_or_raise(binary: str) -> str:
    found = shutil.which(binary)
    if found is None:
        raise ScannerError(f"required scanner binary not found on PATH: {binary!r}")
    return found


def _run(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int = DEFAULT_SCANNER_TIMEOUT_SECONDS,
    ok_exit_codes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    log.debug("scanner.run", cmd=cmd, cwd=str(cwd))
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # TimeoutExpired is a SubprocessError, not a ScannerError, so without
        # this it escapes the node-level ScannerError handlers and fails the
        # whole review instead of skipping the one hung scanner.
        raise ScannerError(f"{Path(cmd[0]).name!r} timed out after {timeout}s") from exc
    if completed.returncode not in ok_exit_codes:
        tail = (completed.stderr or completed.stdout or "").strip()[:400]
        raise ScannerError(f"{Path(cmd[0]).name!r} exited with code {completed.returncode}: {tail}")
    return completed


def _relpath(raw_path: str, working_dir: Path) -> str:
    """Normalize a scanner-reported path to a workspace-relative POSIX path.

    Some scanners (notably checkov) report a leading ``/`` to mean "relative to
    the scanned directory" rather than a filesystem-absolute path. We treat
    that as relative when the path doesn't sit inside ``working_dir``.
    """

    if not raw_path:
        return ""
    p = Path(raw_path)
    if p.is_absolute():
        try:
            # Resolve working_dir: scanners report absolute paths, but the
            # workspace is often a relative "." (CI), which never matches.
            return p.relative_to(working_dir.resolve()).as_posix()
        except ValueError:
            return p.as_posix().lstrip("/")
    return p.as_posix()


# ---------------------------------------------------------------------------
# severity normalization tables
# ---------------------------------------------------------------------------


_TFSEC_SEVERITY: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}

_CHECKOV_SEVERITY: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}

_TFLINT_SEVERITY: dict[str, Severity] = {
    "error": "high",
    "warning": "medium",
    "notice": "info",
    "info": "info",
}


# ---------------------------------------------------------------------------
# tfsec
# ---------------------------------------------------------------------------


def _parse_tfsec(payload: dict[str, Any], working_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in payload.get("results") or []:
        severity = _TFSEC_SEVERITY.get(
            str(item.get("severity") or "").upper(),
            "info",
        )
        location = item.get("location") or {}
        rule_id = item.get("long_id") or item.get("rule_id") or "unknown"
        if not rule_id.startswith("tfsec:"):
            rule_id = f"tfsec:{rule_id}"
        findings.append(
            Finding(
                agent="security",
                severity=severity,
                file=_relpath(location.get("filename") or "", working_dir),
                line=location.get("start_line"),
                rule=rule_id,
                message=(
                    item.get("description") or item.get("rule_description") or "tfsec finding"
                ),
                suggestion=item.get("resolution") or None,
            )
        )
    return findings


@tool
def run_tfsec(working_dir: str) -> list[Finding]:
    """Run tfsec under ``working_dir`` and return normalized security findings.

    The scanner is invoked with ``--soft-fail`` so a non-zero exit caused by
    findings does not raise; only invocation failures (missing binary, invalid
    JSON, other non-zero exits) do.
    """

    binary = _which_or_raise("tfsec")
    cwd = Path(working_dir)
    completed = _run(
        [binary, "--format", "json", "--soft-fail", "--no-colour", str(cwd)],
        cwd=cwd,
        ok_exit_codes=(0,),
    )
    try:
        payload: dict[str, Any] = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"tfsec produced invalid JSON: {exc}") from exc
    return _parse_tfsec(payload, cwd)


# ---------------------------------------------------------------------------
# checkov
# ---------------------------------------------------------------------------


def _parse_checkov(
    payload: dict[str, Any] | list[dict[str, Any]],
    working_dir: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    blocks = payload if isinstance(payload, list) else [payload]
    for block in blocks:
        results = (block.get("results") or {}).get("failed_checks") or []
        for item in results:
            severity = _CHECKOV_SEVERITY.get(
                str(item.get("severity") or "").upper(),
                "medium",
            )
            line_range = item.get("file_line_range") or []
            start_line = line_range[0] if line_range else None
            if start_line == 0:
                start_line = None
            check_id = item.get("check_id") or "unknown"
            rule_id = check_id if check_id.lower().startswith("checkov") else f"checkov:{check_id}"
            findings.append(
                Finding(
                    agent="security",
                    severity=severity,
                    file=_relpath(item.get("file_path") or "", working_dir),
                    line=start_line,
                    rule=rule_id,
                    message=item.get("check_name") or "checkov finding",
                    suggestion=item.get("guideline") or None,
                )
            )
    return findings


@tool
def run_checkov(working_dir: str) -> list[Finding]:
    """Run checkov under ``working_dir`` and return normalized security findings."""

    binary = _which_or_raise("checkov")
    cwd = Path(working_dir)
    completed = _run(
        [binary, "-d", str(cwd), "-o", "json", "--quiet", "--soft-fail"],
        cwd=cwd,
        ok_exit_codes=(0,),
    )
    if not completed.stdout.strip():
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"checkov produced invalid JSON: {exc}") from exc
    return _parse_checkov(payload, cwd)


# ---------------------------------------------------------------------------
# tflint
# ---------------------------------------------------------------------------


def _parse_tflint(payload: dict[str, Any], working_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for issue in payload.get("issues") or []:
        rule = issue.get("rule") or {}
        rng = issue.get("range") or {}
        start = rng.get("start") or {}
        severity = _TFLINT_SEVERITY.get(
            str(rule.get("severity") or "").lower(),
            "info",
        )
        rule_name = rule.get("name") or "unknown"
        findings.append(
            Finding(
                agent="style",
                severity=severity,
                file=_relpath(rng.get("filename") or "", working_dir),
                line=start.get("line"),
                rule=f"tflint:{rule_name}",
                message=issue.get("message") or rule.get("name") or "tflint finding",
                suggestion=rule.get("link") or None,
            )
        )
    return findings


@tool
def run_tflint(working_dir: str) -> list[Finding]:
    """Run tflint under ``working_dir`` and return normalized style findings.

    When the workspace ships a ``.tflint.hcl``, ``tflint --init`` is run first so
    any plugins it declares (e.g. the aws/google/azurerm rulesets) are installed;
    without it tflint errors on the plugin block and the repo loses plugin-rule
    coverage. ``GITHUB_TOKEN`` (set in CI) raises the plugin download rate limit.
    tflint exits non-zero (1/2) when issues are found, treated as a successful run.
    """

    binary = _which_or_raise("tflint")
    cwd = Path(working_dir)
    if (cwd / ".tflint.hcl").is_file():
        _run([binary, "--init"], cwd=cwd)
    completed = _run(
        [binary, "--format=json", "--recursive"],
        cwd=cwd,
        ok_exit_codes=(0, 1, 2),
    )
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"tflint produced invalid JSON: {exc}") from exc
    return _parse_tflint(payload, cwd)


# ---------------------------------------------------------------------------
# terraform fmt
# ---------------------------------------------------------------------------


@tool
def run_terraform_fmt(working_dir: str) -> list[Finding]:
    """Run ``terraform fmt -check`` and emit one finding per unformatted file.

    ``terraform fmt -check`` exits 0 when everything is formatted and 3 when
    one or more files differ from canonical style; both are expected outcomes
    here. Each path on stdout becomes a single low-severity style finding.
    """

    binary = _which_or_raise("terraform")
    cwd = Path(working_dir)
    completed = _run(
        [binary, "fmt", "-check", "-recursive", "-list=true", "-no-color"],
        cwd=cwd,
        ok_exit_codes=(0, 3),
    )
    findings: list[Finding] = []
    for raw_line in (completed.stdout or "").splitlines():
        path = raw_line.strip()
        if not path:
            continue
        findings.append(
            Finding(
                agent="style",
                severity="low",
                file=_relpath(path, cwd),
                line=None,
                rule="terraform-fmt:unformatted",
                message="File does not match `terraform fmt` canonical style.",
                suggestion="Run `terraform fmt` locally and commit the result.",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# infracost
# ---------------------------------------------------------------------------


_INFRACOST_THRESHOLDS: list[tuple[float, Severity]] = [
    (100.0, "high"),
    (10.0, "medium"),
    (1.0, "low"),
]


def _severity_for_cost_delta(delta_monthly: float) -> Severity:
    abs_delta = abs(delta_monthly)
    for threshold, severity in _INFRACOST_THRESHOLDS:
        if abs_delta >= threshold:
            return severity
    return "info"


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _format_delta(value: float) -> str:
    """Render a signed monthly cost like ``+$25.00`` / ``-$25.00`` (sign before $)."""

    return f"{'-' if value < 0 else '+'}${abs(value):,.2f}"


def _parse_infracost_diff(payload: dict[str, Any], working_dir: Path) -> CostReport:
    """Parse ``infracost diff`` JSON into per-resource findings + a cost summary.

    The summary carries the head's absolute monthly total and the change vs. the
    base (the top-level ``totalMonthlyCost`` / ``diffTotalMonthlyCost``). The
    per-project total is intentionally not emitted as a finding — the summary
    represents it, rendered as a headline callout rather than a severity row.
    """

    findings: list[Finding] = []
    for project in payload.get("projects") or []:
        # Use metadata.path (the project dir), not name: the head project is
        # named after its git remote (`owner/repo`), which is not a repo file
        # path and renders as a broken blob link.
        project_path = (project.get("metadata") or {}).get("path") or "."
        diff = project.get("diff") or {}

        for resource in diff.get("resources") or []:
            monthly_delta = _coerce_float(resource.get("monthlyCost"))
            if not monthly_delta:
                continue
            resource_name = resource.get("name") or "(unnamed resource)"
            findings.append(
                Finding(
                    agent="cost",
                    severity=_severity_for_cost_delta(monthly_delta),
                    file=_relpath(project_path, working_dir),
                    line=None,
                    rule="infracost:resource-delta",
                    message=(
                        f"Estimated monthly cost change for `{resource_name}`: "
                        f"{_format_delta(monthly_delta)}"
                    ),
                    suggestion=None,
                )
            )

    total_monthly = _coerce_float(payload.get("totalMonthlyCost"))
    summary = (
        CostSummary(
            total_monthly=total_monthly,
            delta_monthly=_coerce_float(payload.get("diffTotalMonthlyCost")) or 0.0,
        )
        if total_monthly is not None
        else None
    )
    return CostReport(findings=findings, summary=summary)


def build_synced_usage_file(working_dir: str) -> str | None:
    """Auto-generate an infracost usage file from the workspace's Terraform.

    Runs ``infracost breakdown --sync-usage-file`` so usage-based resources
    (requests, data processed, egress, ...) are priced from infracost's default
    estimates instead of $0 — no usage file authored by the reviewed repo. The
    file is written to a scratch dir (never inside the checkout) and applied to
    both the base and head breakdowns so the delta stays consistent.

    Best-effort: returns ``None`` if infracost is missing or the sync fails, in
    which case cost review falls back to fixed-cost pricing.
    """

    cwd = Path(working_dir)
    usage_file = Path(tempfile.mkdtemp(prefix="tfr-usage-")) / "infracost-usage.yml"
    try:
        infracost = _which_or_raise("infracost")
        _run(
            [
                infracost,
                "breakdown",
                "--path",
                str(cwd),
                "--sync-usage-file",
                "--usage-file",
                str(usage_file),
                "--format",
                "json",
            ],
            cwd=cwd,
        )
    except ScannerError as exc:
        log.warning("infracost.usage_sync_failed", error=str(exc))
        return None
    return str(usage_file) if usage_file.is_file() else None


@tool
def run_infracost_diff(
    working_dir: str, baseline_path: str, usage_file_path: str | None = None
) -> CostReport:
    """Run ``infracost diff`` and return cost findings + a total/delta summary.

    ``baseline_path`` must point at a JSON file produced by
    ``infracost breakdown --path <dir> --format json --out-file ...`` against
    the PR's base ref (see :func:`build_infracost_baseline`).

    ``usage_file_path``, when given, prices usage-based resources (Cloud Run
    compute, load-balancer data, egress, logging, ...) from the monthly
    assumptions in that file. Without it the totals cover only fixed-cost
    resources. The same file should price the baseline so the delta stays
    apples-to-apples.
    """

    binary = _which_or_raise("infracost")
    cwd = Path(working_dir)
    cmd = [
        binary,
        "diff",
        "--path",
        str(cwd),
        "--compare-to",
        baseline_path,
        "--format",
        "json",
    ]
    if usage_file_path:
        cmd += ["--usage-file", usage_file_path]
    completed = _run(cmd, cwd=cwd, ok_exit_codes=(0,))
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"infracost produced invalid JSON: {exc}") from exc
    return _parse_infracost_diff(payload, cwd)


def build_infracost_baseline(
    working_dir: str, project_name: str, usage_file_path: str | None = None
) -> str:
    """Generate the base-ref breakdown JSON consumed by ``infracost diff``.

    The workspace HEAD is the PR's merge commit, so its first parent (``HEAD^1``)
    is the base branch tip. We materialize that base tree in a throwaway git
    worktree, run ``infracost breakdown`` over it, and return the JSON path.

    ``infracost diff`` pairs the baseline and the PR head *by project name*. The
    head is named after its git remote (``owner/repo``), but the base worktree
    has no remote and would be named after its temp path — so the two wouldn't
    match and infracost would report the head as fully added and the base as
    fully removed instead of a real delta. We therefore pin the baseline's
    project name to ``project_name`` (the head's ``owner/repo``) so they pair up.

    Raises :class:`ScannerError` on any failure so the cost node skips cleanly.
    """

    git = _which_or_raise("git")
    infracost = _which_or_raise("infracost")
    repo = Path(working_dir)
    # `-c safe.directory=*`: in CI the checkout is owned by a different uid than
    # the (root) container user, which git otherwise refuses to operate on.
    safe = ["-c", "safe.directory=*"]

    base_sha = _run([git, *safe, "rev-parse", "HEAD^1"], cwd=repo).stdout.strip()
    if not base_sha:
        raise ScannerError("could not resolve base ref (HEAD^1) for the infracost baseline")

    scratch = Path(tempfile.mkdtemp(prefix="tfr-cost-"))
    worktree = scratch / "base"
    out_file = scratch / "infracost-base.json"
    try:
        _run([git, *safe, "worktree", "add", "--detach", str(worktree), base_sha], cwd=repo)
        breakdown_cmd = [
            infracost,
            "breakdown",
            "--path",
            str(worktree),
            "--format",
            "json",
            "--out-file",
            str(out_file),
        ]
        if usage_file_path:
            breakdown_cmd += ["--usage-file", usage_file_path]
        _run(breakdown_cmd, cwd=worktree)
    finally:
        subprocess.run(
            [git, *safe, "worktree", "remove", "--force", str(worktree)],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
        )

    data = json.loads(out_file.read_text())
    for project in data.get("projects") or []:
        project["name"] = project_name
    out_file.write_text(json.dumps(data))
    return str(out_file)


# ---------------------------------------------------------------------------
# per-file content cap + diff-only fallback
# ---------------------------------------------------------------------------


PER_FILE_CONTENT_CAP_BYTES = 32 * 1024
TOTAL_CONTENT_THRESHOLD_BYTES = 256 * 1024
TRUNCATION_MARKER = "\n... [content truncated by terraform-review-agent]"

PayloadMode = Literal["full", "truncated", "diff_only"]


class FilePayload(BaseModel):
    """A per-file content blob to be embedded in a specialist LLM prompt."""

    path: str
    mode: PayloadMode
    content: str


def _truncate_to_bytes(text: str, cap_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= cap_bytes:
        return text, False
    cut = encoded[:cap_bytes].decode("utf-8", errors="ignore")
    return cut + TRUNCATION_MARKER, True


def prepare_file_payloads(
    pr: PRContext,
    working_dir: Path | str,
    *,
    per_file_cap_bytes: int = PER_FILE_CONTENT_CAP_BYTES,
    total_threshold_bytes: int = TOTAL_CONTENT_THRESHOLD_BYTES,
) -> list[FilePayload]:
    """Return per-file LLM payloads with size caps + diff-only fallback applied.

    For each terraform-relevant changed file we:

    * Read the file content from ``working_dir`` and cap it at
      ``per_file_cap_bytes`` (replacing the overflow with a truncation
      marker).
    * For files not present on disk (e.g. removed by the PR), fall back to the
      file's PR patch as a ``diff_only`` payload so deletions are still
      reviewable from the diff.
    * If the combined post-cap content exceeds ``total_threshold_bytes``, fall
      back to sending only each file's PR patch (diff) instead of the full
      content, so the LLM still gets context without blowing the token budget.
    """

    base = Path(working_dir)
    candidates: list[ChangedFile] = [f for f in pr.changed_files if f.is_terraform]

    full_payloads: list[FilePayload] = []
    total_bytes = 0
    for f in candidates:
        target = base / f.path
        if not target.is_file():
            if f.patch:
                full_payloads.append(FilePayload(path=f.path, mode="diff_only", content=f.patch))
            continue
        raw = target.read_text(encoding="utf-8", errors="replace")
        content, truncated = _truncate_to_bytes(raw, per_file_cap_bytes)
        mode: PayloadMode = "truncated" if truncated else "full"
        full_payloads.append(FilePayload(path=f.path, mode=mode, content=content))
        total_bytes += len(content.encode("utf-8"))

    if total_bytes <= total_threshold_bytes:
        return full_payloads

    log.info(
        "diff_only_fallback",
        total_bytes=total_bytes,
        threshold=total_threshold_bytes,
        files=len(candidates),
    )
    diff_payloads: list[FilePayload] = []
    for f in candidates:
        if f.patch:
            diff_payloads.append(FilePayload(path=f.path, mode="diff_only", content=f.patch))
    return diff_payloads
