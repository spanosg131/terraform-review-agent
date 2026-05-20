"""Unit tests for the Pydantic state models in ``utils/state``."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from terraform_review_agent.utils.state import (
    SEVERITY_ORDER,
    ChangedFile,
    Finding,
    PRContext,
    ReviewState,
)


def _pr(files: list[ChangedFile] | None = None) -> PRContext:
    return PRContext(
        repository="acme/example",
        pr_number=42,
        base_sha="a" * 7,
        head_sha="b" * 7,
        base_ref="main",
        head_ref="feature/x",
        changed_files=files or [],
    )


def test_pr_context_detects_terraform_changes() -> None:
    pr = _pr(
        [
            ChangedFile(path="infra/main.tf"),
            ChangedFile(path="README.md"),
        ]
    )

    assert pr.has_terraform_changes is True


def test_pr_context_ignores_non_terraform_changes() -> None:
    pr = _pr([ChangedFile(path="README.md"), ChangedFile(path="src/app.py")])

    assert pr.has_terraform_changes is False


@pytest.mark.parametrize(
    "path",
    ["main.tf", "vars.tfvars", "infra/cluster.tf.json", "envs/prod.tfvars.json"],
)
def test_pr_context_recognises_terraform_file_variants(path: str) -> None:
    pr = _pr([ChangedFile(path=path)])

    assert pr.has_terraform_changes is True


def test_pr_context_detects_terraform_renamed_to_non_terraform() -> None:
    # Renaming main.tf -> main.txt drops resources from Terraform's view; the
    # pre-rename path must still register as a Terraform change.
    pr = _pr(
        [
            ChangedFile(path="main.txt", status="renamed", previous_path="main.tf"),
        ]
    )

    assert pr.has_terraform_changes is True


def test_changed_file_is_terraform_uses_previous_path() -> None:
    renamed_away = ChangedFile(path="main.txt", status="renamed", previous_path="main.tf")
    renamed_into = ChangedFile(path="main.tf", status="renamed", previous_path="main.txt")
    non_tf = ChangedFile(path="docs/readme.txt", status="renamed", previous_path="docs/notes.txt")

    assert renamed_away.is_terraform is True
    assert renamed_into.is_terraform is True
    assert non_tf.is_terraform is False


def test_changed_terraform_paths_collects_tf_paths_and_previous_names() -> None:
    pr = _pr(
        [
            ChangedFile(path="infra/main.tf"),
            ChangedFile(path="README.md"),
            ChangedFile(path="renamed.txt", status="renamed", previous_path="old.tf"),
        ]
    )

    # Non-terraform files are excluded; renamed-away files contribute both names.
    assert pr.changed_terraform_paths == {"infra/main.tf", "renamed.txt", "old.tf"}


def test_finding_severity_rank_matches_order() -> None:
    critical = Finding(
        agent="security",
        severity="critical",
        file="main.tf",
        line=10,
        rule="tfsec:AWS017",
        message="public bucket",
    )
    info = Finding(
        agent="style",
        severity="info",
        file="main.tf",
        line=1,
        rule="style:nit",
        message="trailing whitespace",
    )

    assert critical.severity_rank < info.severity_rank
    assert SEVERITY_ORDER["critical"] == 0
    assert SEVERITY_ORDER["info"] == 4


def test_finding_dedupe_key_uses_file_rule_line() -> None:
    f = Finding(
        agent="security",
        severity="high",
        file="main.tf",
        line=5,
        rule="tfsec:AWS017",
        message="x",
    )

    assert f.dedupe_key() == ("main.tf", "tfsec:AWS017", 5)


def test_review_state_collects_all_findings_in_order() -> None:
    sec = Finding(agent="security", severity="high", file="a.tf", rule="s", message="m")
    cost = Finding(agent="cost", severity="medium", file="b.tf", rule="c", message="m")
    style = Finding(agent="style", severity="low", file="c.tf", rule="y", message="m")
    state = ReviewState(pr=_pr(), security=[sec], cost=[cost], style=[style])

    assert state.all_findings() == [sec, cost, style]


def test_finding_rejects_unknown_severity() -> None:
    with pytest.raises(ValidationError):
        Finding(
            agent="security",
            severity="catastrophic",  # type: ignore[arg-type]
            file="main.tf",
            rule="x",
            message="m",
        )
