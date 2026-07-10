from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
from pathlib import Path
import shutil

import pytest

from hermes_feishu_card.install.detect import detect_hermes
from hermes_feishu_card.install.patcher import (
    CRON_PATCH_END,
    apply_patch,
)
from hermes_feishu_card.install.recovery import (
    RecoveryFinding,
    _classify_evidence,
    _read_evidence,
    plan_recovery,
    sanitize_recovery_plan,
)


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "hermes_v2026_4_23"


@pytest.fixture
def installed_state(tmp_path):
    root = tmp_path / "hermes"
    shutil.copytree(FIXTURE, root)
    detection = detect_hermes(root)
    original = detection.run_py.read_text(encoding="utf-8")
    patched = apply_patch(original, strategy=detection.hook_strategy)
    backup = detection.run_py.with_name("run.py.hermes_feishu_card.bak")
    backup.write_text(original, encoding="utf-8")
    detection.run_py.write_text(patched, encoding="utf-8")
    manifest_path = root / ".hermes_feishu_card_manifest"
    manifest_path.write_text(
        json.dumps(
            {
                "run_py": "gateway/run.py",
                "patched_sha256": sha256(patched.encode("utf-8")).hexdigest(),
                "backup": "gateway/run.py.hermes_feishu_card.bak",
                "backup_sha256": sha256(original.encode("utf-8")).hexdigest(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return detection, original, patched, manifest_path


def test_plan_recovery_allows_manifest_owned_corrupt_completion_markers(
    installed_state,
):
    detection, _original, patched, manifest_path = installed_state
    corrupt = patched.replace("# HERMES_FEISHU_CARD_COMPLETE_PATCH_END\n", "")
    detection.run_py.write_text(corrupt, encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["patched_sha256"] = sha256(corrupt.encode("utf-8")).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
    )

    plan = plan_recovery(detection)

    assert plan.state == "corrupt_owned"
    assert plan.executable is True
    assert plan.actions == ("restore_verified_backup", "reapply_current_hook")


def test_plan_recovery_refuses_corrupt_markers_after_user_edit(installed_state):
    detection, _original, patched, _manifest_path = installed_state
    detection.run_py.write_text(
        patched.replace("import asyncio", "import asyncio\nUSER_EDIT = True").replace(
            "# HERMES_FEISHU_CARD_COMPLETE_PATCH_END\n", ""
        ),
        encoding="utf-8",
    )

    plan = plan_recovery(detection)

    assert plan.executable is False
    assert any(item.code == "current_hash_mismatch" for item in plan.findings)


def test_plan_recovery_reports_healthy_installed_state(installed_state):
    detection, _original, _patched, _manifest_path = installed_state

    plan = plan_recovery(detection)

    assert plan.state == "installed"
    assert plan.executable is False
    assert plan.actions == ()
    assert not any(item.severity == "error" for item in plan.findings)


def test_plan_recovery_reports_healthy_clean_state(tmp_path):
    root = tmp_path / "hermes"
    shutil.copytree(FIXTURE, root)
    detection = detect_hermes(root)

    plan = plan_recovery(detection)

    assert plan.state == "clean"
    assert plan.executable is False
    assert plan.actions == ()
    assert not any(item.severity == "error" for item in plan.findings)


def test_classify_evidence_treats_any_marker_validation_error_as_corrupt(
    installed_state,
):
    detection, _original, _patched, _manifest_path = installed_state
    evidence = replace(
        _read_evidence(detection),
        marker_error="corrupt completion patch markers",
    )

    classification = _classify_evidence(detection, evidence)

    assert classification.state == "corrupt_owned"
    assert classification.executable is True


def test_plan_recovery_allows_verified_stale_unpatched_state(installed_state):
    detection, original, _patched, _manifest_path = installed_state
    detection.run_py.write_text(original, encoding="utf-8")

    plan = plan_recovery(detection)

    assert plan.state == "stale_unpatched"
    assert plan.executable is True
    assert plan.actions == ("clear_stale_install_state",)


def test_plan_recovery_allows_rebuilding_a_missing_backup(installed_state):
    detection, _original, _patched, _manifest_path = installed_state
    detection.run_py.with_name("run.py.hermes_feishu_card.bak").unlink()

    plan = plan_recovery(detection)

    assert plan.state == "owned_incomplete"
    assert plan.executable is True
    assert "rebuild_backup" in plan.actions
    assert any(item.code == "backup_missing" for item in plan.findings)


def test_plan_recovery_refuses_a_backup_hash_mismatch(installed_state):
    detection, _original, _patched, _manifest_path = installed_state
    backup = detection.run_py.with_name("run.py.hermes_feishu_card.bak")
    backup.write_text(
        backup.read_text(encoding="utf-8") + "USER_EDIT = True\n",
        encoding="utf-8",
    )

    plan = plan_recovery(detection)

    assert plan.state == "owned_incomplete"
    assert plan.executable is False
    assert any(item.code == "backup_hash_mismatch" for item in plan.findings)


def test_plan_recovery_allows_manifest_rebuild_for_removable_owned_patch(
    installed_state,
):
    detection, _original, _patched, manifest_path = installed_state
    manifest_path.unlink()

    plan = plan_recovery(detection)

    assert plan.state == "owned_incomplete"
    assert plan.executable is True
    assert plan.actions == ("rebuild_manifest",)
    assert any(item.code == "manifest_missing" for item in plan.findings)


def test_plan_recovery_refuses_when_verified_backup_has_unsupported_anchors(
    installed_state,
):
    detection, _original, patched, manifest_path = installed_state
    corrupt = patched.replace("# HERMES_FEISHU_CARD_COMPLETE_PATCH_END\n", "")
    unsupported = "VALUE = 1\n"
    detection.run_py.write_text(corrupt, encoding="utf-8")
    backup = detection.run_py.with_name("run.py.hermes_feishu_card.bak")
    backup.write_text(unsupported, encoding="utf-8")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["patched_sha256"] = sha256(corrupt.encode("utf-8")).hexdigest()
    manifest["backup_sha256"] = sha256(unsupported.encode("utf-8")).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
    )

    plan = plan_recovery(detection)

    assert plan.state == "corrupt_owned"
    assert plan.executable is False
    assert any(item.code == "unsupported_anchors" for item in plan.findings)


def test_plan_recovery_allows_manifest_owned_cron_marker_damage(tmp_path):
    root = tmp_path / "hermes"
    shutil.copytree(FIXTURE, root)
    (root / "VERSION").write_text("v0.13.0\n", encoding="utf-8")
    run_py = root / "gateway" / "run.py"
    original = run_py.read_text(encoding="utf-8") + (
        "\ndef _deliver_result(job: dict, content: str, adapters=None, loop=None):\n"
        "    return None\n"
    )
    run_py.write_text(original, encoding="utf-8")
    detection = detect_hermes(root)
    patched = apply_patch(original, strategy=detection.hook_strategy)
    assert CRON_PATCH_END in patched
    corrupt = patched.replace(f"{CRON_PATCH_END}\n", "")
    backup = run_py.with_name("run.py.hermes_feishu_card.bak")
    backup.write_text(original, encoding="utf-8")
    run_py.write_text(corrupt, encoding="utf-8")
    (root / ".hermes_feishu_card_manifest").write_text(
        json.dumps(
            {
                "run_py": "gateway/run.py",
                "patched_sha256": sha256(corrupt.encode("utf-8")).hexdigest(),
                "backup": "gateway/run.py.hermes_feishu_card.bak",
                "backup_sha256": sha256(original.encode("utf-8")).hexdigest(),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    plan = plan_recovery(detection)

    assert plan.state == "corrupt_owned"
    assert plan.executable is True
    assert plan.actions == ("restore_verified_backup", "reapply_current_hook")


def test_plan_recovery_refuses_gateway_symlink(tmp_path):
    root = tmp_path / "hermes"
    (root / "gateway").mkdir(parents=True)
    (root / "VERSION").write_text("v2026.4.23\n", encoding="utf-8")
    (root / "gateway" / "run.py").symlink_to(FIXTURE / "gateway" / "run.py")
    detection = detect_hermes(root)

    plan = plan_recovery(detection)

    assert plan.executable is False
    assert any(item.code == "symlink_refused" for item in plan.findings)


def test_sanitize_recovery_plan_excludes_sensitive_evidence(installed_state):
    detection, original, patched, _manifest_path = installed_state
    detection.run_py.write_text(
        patched.replace("import asyncio", "import asyncio\nUSER_EDIT = True").replace(
            "# HERMES_FEISHU_CARD_COMPLETE_PATCH_END\n", ""
        ),
        encoding="utf-8",
    )
    plan = plan_recovery(detection)

    safe = sanitize_recovery_plan(plan)
    serialized = json.dumps(safe, sort_keys=True)

    assert safe == {
        "state": plan.state,
        "executable": plan.executable,
        "fingerprint": plan.fingerprint[:12],
        "actions": list(plan.actions),
        "findings": [
            {
                "code": finding.code,
                "severity": finding.severity,
                "message": finding.message,
            }
            for finding in plan.findings
        ],
    }
    assert str(detection.root) not in serialized
    assert original not in serialized
    assert patched not in serialized
    assert plan.fingerprint not in serialized
    assert all(len(part) != 64 for part in _all_strings(safe))


def test_recovery_findings_are_immutable():
    finding = RecoveryFinding("safe", "info", "No recovery is required.")

    with pytest.raises(FrozenInstanceError):
        finding.code = "changed"


def _all_strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_strings(item)
    elif isinstance(value, str):
        yield value
