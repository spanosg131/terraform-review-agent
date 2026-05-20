"""Unit tests for the ``fail-on-severity`` CI gate in :mod:`entrypoint`.

The graph and GitHub client are never exercised here: ``run`` is replaced with
a stub returning a hand-built :class:`ReviewState`, and ``settings.fail_on_severity``
is monkeypatched per case. We assert on the helper directly and on the exit code
``main`` returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from terraform_review_agent import entrypoint
from terraform_review_agent.entrypoint import (
    GATING_EXIT_CODE,
    _ensure_workspace,
    _max_severity_finding,
)
from terraform_review_agent.utils.state import Finding, PRContext, ReviewState


def _pr() -> PRContext:
    return PRContext(
        repository="acme/example",
        pr_number=7,
        base_sha="a" * 7,
        head_sha="b" * 7,
        base_ref="main",
        head_ref="feature/x",
    )


_ARGV = ["--repository", "acme/example", "--pr-number", "7"]


def _finding(severity: str, rule: str = "r") -> Finding:
    return Finding(agent="security", severity=severity, file="main.tf", rule=rule, message="m")


def _state(*, findings: list[Finding], skipped: bool = False) -> ReviewState:
    return ReviewState(pr=_pr(), security=findings, skipped=skipped)


# ---------------------------------------------------------------------------
# _max_severity_finding
# ---------------------------------------------------------------------------


def test_none_threshold_never_gates() -> None:
    assert _max_severity_finding([_finding("critical")], "none") is None


def test_below_threshold_returns_none() -> None:
    # floor "high" → only critical/high trip; a medium finding must not.
    assert _max_severity_finding([_finding("medium")], "high") is None


def test_at_threshold_trips() -> None:
    hit = _max_severity_finding([_finding("high")], "high")
    assert hit is not None and hit.severity == "high"


def test_returns_highest_severity_among_gating() -> None:
    findings = [_finding("high", "a"), _finding("critical", "b"), _finding("medium", "c")]
    hit = _max_severity_finding(findings, "medium")
    assert hit is not None and hit.severity == "critical"


def test_no_findings_returns_none() -> None:
    assert _max_severity_finding([], "info") is None


# ---------------------------------------------------------------------------
# main() exit code
# ---------------------------------------------------------------------------


def test_main_exits_zero_when_threshold_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entrypoint, "run", lambda *a, **k: _state(findings=[_finding("critical")]))
    monkeypatch.setattr(entrypoint.settings, "fail_on_severity", "none")
    assert entrypoint.main(_ARGV) == 0


def test_main_gates_when_finding_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entrypoint, "run", lambda *a, **k: _state(findings=[_finding("high")]))
    monkeypatch.setattr(entrypoint.settings, "fail_on_severity", "high")
    assert entrypoint.main(_ARGV) == GATING_EXIT_CODE


def test_main_exits_zero_when_below_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(entrypoint, "run", lambda *a, **k: _state(findings=[_finding("low")]))
    monkeypatch.setattr(entrypoint.settings, "fail_on_severity", "high")
    assert entrypoint.main(_ARGV) == 0


def test_main_skipped_run_never_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        entrypoint, "run", lambda *a, **k: _state(findings=[_finding("critical")], skipped=True)
    )
    monkeypatch.setattr(entrypoint.settings, "fail_on_severity", "critical")
    assert entrypoint.main(_ARGV) == 0


# ---------------------------------------------------------------------------
# _ensure_workspace
# ---------------------------------------------------------------------------


def test_ensure_workspace_uses_existing_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".git").mkdir()

    def _no_clone(_pr_arg: PRContext) -> str:
        raise AssertionError("must not clone when the workspace is already a checkout")

    monkeypatch.setattr(entrypoint, "_clone_pr_workspace", _no_clone)

    assert _ensure_workspace(_pr(), str(tmp_path)) == str(tmp_path)


def test_ensure_workspace_clones_when_not_a_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # No .git in base_dir => the PR must be cloned into a fresh workspace.
    monkeypatch.setattr(entrypoint, "_clone_pr_workspace", lambda _pr_arg: "/tmp/cloned-ws")

    assert _ensure_workspace(_pr(), str(tmp_path)) == "/tmp/cloned-ws"
