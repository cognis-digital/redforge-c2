"""redforge-c2 — engagement governance overlay for authorized red-team C2.

This module is a *governance* layer. It does NOT implement implant
capabilities. It wraps an upstream C2 (Sliver / Mythic / Empire) with:
  - Scope-of-Engagement (SoE) enforcement (target list, allowed actions)
  - Two-Person Integrity (TPI) approval for destructive actions
  - Hash-chained audit log of every operator command
  - Authorization expiration (engagement window)

Designed for use by authorized red teams on systems they have written
authorization to test (Rules of Engagement / Authorization to Operate).
"""
from __future__ import annotations
import json, time, hashlib, fnmatch
from pathlib import Path
from dataclasses import dataclass, field
from cognis_mil import ScanResult, Finding, Severity, AuditLog

@dataclass
class RulesOfEngagement:
    """Loaded from a signed JSON file before any operations begin."""
    engagement_id: str
    authorized_by: str
    start_ts: float
    end_ts: float
    in_scope_targets: list[str] = field(default_factory=list)   # CIDR / FQDN / glob
    out_of_scope_targets: list[str] = field(default_factory=list)
    allowed_techniques: list[str] = field(default_factory=list)  # ATT&CK IDs
    forbidden_techniques: list[str] = field(default_factory=list)
    destructive_actions_require_tpi: bool = True
    sla_first_response_minutes: int = 15

def load_roe(path: Path) -> RulesOfEngagement:
    d = json.loads(path.read_text())
    return RulesOfEngagement(**d)

def is_in_scope(target: str, roe: RulesOfEngagement) -> tuple[bool, str]:
    for pat in roe.out_of_scope_targets:
        if fnmatch.fnmatch(target, pat) or target == pat:
            return False, f"Explicitly out of scope: {pat}"
    for pat in roe.in_scope_targets:
        if fnmatch.fnmatch(target, pat) or target == pat:
            return True, f"In scope: {pat}"
    return False, "Target not listed in in_scope_targets"

def check_window(roe: RulesOfEngagement) -> tuple[bool, str]:
    now = time.time()
    if now < roe.start_ts: return False, f"Engagement starts at {roe.start_ts}"
    if now > roe.end_ts:   return False, f"Engagement ended at {roe.end_ts}"
    return True, "Within authorization window"

def check_technique(attack_id: str, roe: RulesOfEngagement) -> tuple[bool, str]:
    if attack_id in roe.forbidden_techniques: return False, f"{attack_id} forbidden by ROE"
    if roe.allowed_techniques and attack_id not in roe.allowed_techniques:
        return False, f"{attack_id} not in allowed_techniques list"
    return True, "Technique approved"

DESTRUCTIVE_ACTIONS = {"rm","delete","destroy","wipe","format","drop","disable","shutdown"}

def requires_tpi(command: str) -> bool:
    cmd_lower = command.lower()
    return any(d in cmd_lower for d in DESTRUCTIVE_ACTIONS)

def authorize_command(operator: str, target: str, attack_id: str, command: str,
                      roe: RulesOfEngagement, audit: AuditLog,
                      second_operator: str = None) -> tuple[bool, str]:
    """Run full pre-flight authorization. Logs every decision."""
    event = {"actor": operator, "target": target, "attack": attack_id, "cmd": command[:200]}
    # Window
    ok, msg = check_window(roe)
    if not ok: audit.append({**event, "decision":"DENY", "reason": msg}); return False, msg
    # Scope
    ok, msg = is_in_scope(target, roe)
    if not ok: audit.append({**event, "decision":"DENY", "reason": msg}); return False, msg
    # Technique
    ok, msg = check_technique(attack_id, roe)
    if not ok: audit.append({**event, "decision":"DENY", "reason": msg}); return False, msg
    # TPI
    if roe.destructive_actions_require_tpi and requires_tpi(command):
        if not second_operator:
            audit.append({**event, "decision":"DENY", "reason":"TPI required: no second operator"})
            return False, "Destructive command — TPI required"
        if second_operator == operator:
            audit.append({**event, "decision":"DENY", "reason":"TPI second operator must differ"})
            return False, "TPI second operator must be different person"
        event["second_actor"] = second_operator
    audit.append({**event, "decision":"ALLOW"})
    return True, "Approved"

def scan(target=".", **opts):
    """Scan a session log for ROE violations."""
    r = ScanResult(tool_name="redforge-c2", tool_version="0.1.0")
    p = Path(target)
    log_files = list(p.glob("audit*.jsonl")) if p.is_dir() else [p]
    roe_files = list(p.glob("roe*.json")) if p.is_dir() else []
    if not log_files:
        r.add(Finding("RF-NOLOG", Severity.MODERATE, "No audit log found",
                      remediation="Pass a directory containing audit-*.jsonl"))
        r.finalize(); return r
    roe = load_roe(roe_files[0]) if roe_files else None
    for lf in log_files:
        lines = lf.read_text().splitlines()
        r.items_scanned += len(lines)
        for line in lines:
            try: e = json.loads(line)
            except: continue
            ev = e.get("event", {})
            if ev.get("decision") == "DENY":
                r.add(Finding("RF-DENY", Severity.LOW,
                              f"Denied: {ev.get('cmd','?')[:50]} on {ev.get('target','?')}",
                              description=ev.get("reason",""),
                              location=str(lf),
                              remediation="Review with team lead; update ROE if appropriate."))
            elif requires_tpi(ev.get("cmd","")) and not ev.get("second_actor"):
                r.add(Finding("RF-TPI-MISS", Severity.VERY_HIGH,
                              "Destructive command logged without TPI second-actor",
                              location=str(lf),
                              mitre_attack="T1485",
                              remediation="Halt engagement; investigate."))
    r.finalize(); return r
