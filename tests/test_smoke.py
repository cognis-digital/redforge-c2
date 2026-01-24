import time, json
from pathlib import Path
from redforge_c2.core import (load_roe, is_in_scope, check_technique, check_window,
                               requires_tpi, authorize_command, scan)
from cognis_mil import AuditLog
D = Path(__file__).parent.parent / "demos"
def test_in_scope():
    roe = load_roe(D / "roe.json")
    assert is_in_scope("demo.lab.internal", roe)[0]
    assert not is_in_scope("prod.crm", roe)[0]
def test_technique_check():
    roe = load_roe(D / "roe.json")
    assert check_technique("T1078", roe)[0]
    assert not check_technique("T1485", roe)[0]   # forbidden
def test_tpi_required():
    assert requires_tpi("rm -rf /tmp/x")
    assert not requires_tpi("whoami")
def test_authorize_flow(tmp_path):
    roe = load_roe(D / "roe.json")
    audit = AuditLog(tmp_path / "audit.jsonl")
    # OK
    ok, _ = authorize_command("alice","demo.lab.internal","T1078","whoami", roe, audit)
    assert ok
    # Denied: out of scope
    ok, _ = authorize_command("alice","prod.crm","T1078","whoami", roe, audit)
    assert not ok
    # Denied: destructive w/o TPI
    ok, _ = authorize_command("alice","demo.lab.internal","T1059","rm -rf /tmp/x", roe, audit)
    assert not ok
    # Approved: destructive w/ TPI
    ok, _ = authorize_command("alice","demo.lab.internal","T1059","rm -rf /tmp/x", roe, audit, second_operator="bob")
    assert ok
def test_post_scan():
    r = scan(str(D))
    ids = {f.id for f in r.findings}
    assert "RF-TPI-MISS" in ids  # demo log has a violation
