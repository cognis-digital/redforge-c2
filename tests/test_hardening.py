"""Tests for hardened error paths and edge cases in redforge-c2."""
import json

import pytest

from cognis_mil import AuditLog
from redforge_c2.core import (
    ROEValidationError,
    RulesOfEngagement,
    authorize_command,
    check_technique,
    is_in_scope,
    load_roe,
    requires_tpi,
    scan,
)

# ---------------------------------------------------------------------------
# load_roe — validation
# ---------------------------------------------------------------------------

def test_load_roe_missing_file(tmp_path):
    """load_roe raises FileNotFoundError for a non-existent path."""
    with pytest.raises(FileNotFoundError, match="ROE file not found"):
        load_roe(tmp_path / "no_such_file.json")


def test_load_roe_malformed_json(tmp_path):
    """load_roe raises ROEValidationError when the file is not valid JSON."""
    bad = tmp_path / "roe_bad.json"
    bad.write_text("{this is: not json}", encoding="utf-8")
    with pytest.raises(ROEValidationError, match="not valid JSON"):
        load_roe(bad)


def test_load_roe_missing_required_fields(tmp_path):
    """load_roe raises ROEValidationError when required fields are absent."""
    incomplete = tmp_path / "roe_incomplete.json"
    # Missing start_ts and end_ts
    incomplete.write_text(
        json.dumps({"engagement_id": "X", "authorized_by": "Y"}),
        encoding="utf-8",
    )
    with pytest.raises(ROEValidationError, match="missing required fields"):
        load_roe(incomplete)


def test_load_roe_end_before_start(tmp_path):
    """load_roe raises ROEValidationError when end_ts <= start_ts."""
    bad_window = tmp_path / "roe_badwindow.json"
    bad_window.write_text(
        json.dumps({
            "engagement_id": "RT-TEST",
            "authorized_by": "Tester",
            "start_ts": 9_000_000.0,
            "end_ts": 1_000_000.0,  # before start
        }),
        encoding="utf-8",
    )
    with pytest.raises(ROEValidationError, match="end_ts.*must be after start_ts"):
        load_roe(bad_window)


def test_load_roe_unknown_fields_ignored(tmp_path):
    """load_roe silently drops unknown fields rather than crashing."""
    roe_with_extra = tmp_path / "roe_extra.json"
    roe_with_extra.write_text(
        json.dumps({
            "engagement_id": "RT-EXTRA",
            "authorized_by": "Tester",
            "start_ts": 1_000_000.0,
            "end_ts": 9_999_999.0,
            "unknown_future_field": "should_be_ignored",
        }),
        encoding="utf-8",
    )
    roe = load_roe(roe_with_extra)
    assert roe.engagement_id == "RT-EXTRA"


# ---------------------------------------------------------------------------
# is_in_scope / check_technique — edge cases
# ---------------------------------------------------------------------------

def test_is_in_scope_empty_target():
    """is_in_scope returns False for an empty target string."""
    roe = RulesOfEngagement(
        engagement_id="T", authorized_by="T",
        start_ts=1.0, end_ts=9_999_999.0,
        in_scope_targets=["*"],
    )
    ok, reason = is_in_scope("", roe)
    assert not ok
    assert "non-empty" in reason.lower()


def test_check_technique_empty_id():
    """check_technique returns False for an empty ATT&CK ID."""
    roe = RulesOfEngagement(
        engagement_id="T", authorized_by="T",
        start_ts=1.0, end_ts=9_999_999.0,
    )
    ok, reason = check_technique("", roe)
    assert not ok
    assert "non-empty" in reason.lower()


def test_requires_tpi_empty_command():
    """requires_tpi returns False for empty / None-like inputs."""
    assert not requires_tpi("")
    assert not requires_tpi("  ")


# ---------------------------------------------------------------------------
# authorize_command — bad actor / target guards
# ---------------------------------------------------------------------------

def test_authorize_command_empty_operator(tmp_path):
    """authorize_command rejects a blank operator string immediately."""
    roe = RulesOfEngagement(
        engagement_id="T", authorized_by="T",
        start_ts=1.0, end_ts=9_999_999.0,
        in_scope_targets=["host.lab"],
    )
    audit = AuditLog(tmp_path / "audit.jsonl")
    ok, msg = authorize_command("", "host.lab", "T1078", "whoami", roe, audit)
    assert not ok
    assert "operator" in msg.lower()


# ---------------------------------------------------------------------------
# scan — path / I/O edge cases
# ---------------------------------------------------------------------------

def test_scan_nonexistent_path():
    """scan on a missing path returns RF-NOTFOUND finding, not an exception."""
    r = scan("/no/such/path/at/all")
    ids = {f.id for f in r.findings}
    assert "RF-NOTFOUND" in ids


def test_scan_empty_directory(tmp_path):
    """scan on an empty directory returns RF-NOLOG, not an exception."""
    r = scan(str(tmp_path))
    ids = {f.id for f in r.findings}
    assert "RF-NOLOG" in ids


def test_scan_malformed_roe(tmp_path):
    """scan with a malformed roe*.json emits RF-ROE-INVALID and still scans logs."""
    # Write a bad ROE file
    (tmp_path / "roe-bad.json").write_text("{broken", encoding="utf-8")
    # Write a minimal valid audit log so we get scan results too
    (tmp_path / "audit-test.jsonl").write_text(
        json.dumps({
            "ts": 1.0, "prev": "GENESIS",
            "event": {"actor": "x", "target": "t", "attack": "T1078",
                      "cmd": "whoami", "decision": "ALLOW"},
            "hash": "abc",
        }) + "\n",
        encoding="utf-8",
    )
    r = scan(str(tmp_path))
    ids = {f.id for f in r.findings}
    assert "RF-ROE-INVALID" in ids


def test_scan_empty_log_file(tmp_path):
    """scan on an all-blank audit log produces no findings (not a crash)."""
    (tmp_path / "audit-empty.jsonl").write_text("\n\n\n", encoding="utf-8")
    r = scan(str(tmp_path))
    # No crash; no crash-related finding IDs
    assert "RF-NOTFOUND" not in {f.id for f in r.findings}
    assert "RF-NOLOG" not in {f.id for f in r.findings}


# ---------------------------------------------------------------------------
# AuditLog — hardened verify
# ---------------------------------------------------------------------------

def test_audit_verify_empty_file(tmp_path):
    """verify returns True for a log file that exists but is entirely blank."""
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text("", encoding="utf-8")
    audit = AuditLog(log_path)
    ok, msg = audit.verify()
    assert ok
    assert "Empty" in msg


def test_audit_append_non_dict_raises(tmp_path):
    """AuditLog.append rejects non-dict events with a clear TypeError."""
    audit = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(TypeError, match="dict"):
        audit.append("not a dict")  # type: ignore[arg-type]
