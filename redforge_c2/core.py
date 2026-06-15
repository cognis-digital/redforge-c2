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

import fnmatch
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from cognis_mil import AuditLog, Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# ROE data model
# ---------------------------------------------------------------------------

_REQUIRED_ROE_FIELDS = {
    "engagement_id",
    "authorized_by",
    "start_ts",
    "end_ts",
}


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


class ROEValidationError(ValueError):
    """Raised when a ROE file fails structural validation."""


def load_roe(path: Path) -> RulesOfEngagement:
    """Load and validate a Rules-of-Engagement JSON file.

    Raises:
        FileNotFoundError: if *path* does not exist.
        ROEValidationError: if the file is not valid JSON, is missing required
            fields, or contains logically invalid values (e.g. end before start).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"ROE file not found: {path}")
    if not path.is_file():
        raise ROEValidationError(f"ROE path is not a file: {path}")

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ROEValidationError(f"Cannot read ROE file {path}: {exc}") from exc

    try:
        d = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ROEValidationError(
            f"ROE file is not valid JSON ({path}): {exc}"
        ) from exc

    if not isinstance(d, dict):
        raise ROEValidationError(
            f"ROE file must be a JSON object, got {type(d).__name__}: {path}"
        )

    missing = _REQUIRED_ROE_FIELDS - d.keys()
    if missing:
        raise ROEValidationError(
            f"ROE file missing required fields {sorted(missing)}: {path}"
        )

    # Type-coerce timestamps and validate range.
    try:
        start_ts = float(d["start_ts"])
        end_ts = float(d["end_ts"])
    except (TypeError, ValueError) as exc:
        raise ROEValidationError(
            f"ROE start_ts/end_ts must be numeric timestamps: {exc}"
        ) from exc

    if end_ts <= start_ts:
        raise ROEValidationError(
            f"ROE end_ts ({end_ts}) must be after start_ts ({start_ts})"
        )

    for field_name in ("engagement_id", "authorized_by"):
        val = d.get(field_name, "")
        if not isinstance(val, str) or not val.strip():
            raise ROEValidationError(
                f"ROE field '{field_name}' must be a non-empty string"
            )

    # Only pass known fields to avoid unexpected-keyword-argument errors.
    known_fields = {
        "engagement_id",
        "authorized_by",
        "start_ts",
        "end_ts",
        "in_scope_targets",
        "out_of_scope_targets",
        "allowed_techniques",
        "forbidden_techniques",
        "destructive_actions_require_tpi",
        "sla_first_response_minutes",
    }
    filtered = {k: v for k, v in d.items() if k in known_fields}
    return RulesOfEngagement(**filtered)


# ---------------------------------------------------------------------------
# Authorization logic
# ---------------------------------------------------------------------------

def is_in_scope(target: str, roe: RulesOfEngagement) -> tuple[bool, str]:
    if not target:
        return False, "Target must be a non-empty string"
    for pat in roe.out_of_scope_targets:
        if fnmatch.fnmatch(target, pat) or target == pat:
            return False, f"Explicitly out of scope: {pat}"
    for pat in roe.in_scope_targets:
        if fnmatch.fnmatch(target, pat) or target == pat:
            return True, f"In scope: {pat}"
    return False, "Target not listed in in_scope_targets"


def check_window(roe: RulesOfEngagement) -> tuple[bool, str]:
    now = time.time()
    if now < roe.start_ts:
        return False, f"Engagement starts at {roe.start_ts}"
    if now > roe.end_ts:
        return False, f"Engagement ended at {roe.end_ts}"
    return True, "Within authorization window"


def check_technique(attack_id: str, roe: RulesOfEngagement) -> tuple[bool, str]:
    if not attack_id:
        return False, "ATT&CK technique ID must be a non-empty string"
    if attack_id in roe.forbidden_techniques:
        return False, f"{attack_id} forbidden by ROE"
    if roe.allowed_techniques and attack_id not in roe.allowed_techniques:
        return False, f"{attack_id} not in allowed_techniques list"
    return True, "Technique approved"


DESTRUCTIVE_ACTIONS = {
    "rm", "delete", "destroy", "wipe", "format", "drop", "disable", "shutdown",
}


def requires_tpi(command: str) -> bool:
    if not command:
        return False
    cmd_lower = command.lower()
    return any(d in cmd_lower for d in DESTRUCTIVE_ACTIONS)


def authorize_command(
    operator: str,
    target: str,
    attack_id: str,
    command: str,
    roe: RulesOfEngagement,
    audit: AuditLog,
    second_operator: str | None = None,
) -> tuple[bool, str]:
    """Run full pre-flight authorization. Logs every decision."""
    if not operator or not isinstance(operator, str):
        return False, "operator must be a non-empty string"
    if not target or not isinstance(target, str):
        return False, "target must be a non-empty string"
    if not isinstance(command, str):
        command = ""

    event = {
        "actor": operator,
        "target": target,
        "attack": attack_id,
        "cmd": command[:200],
    }

    # Window
    ok, msg = check_window(roe)
    if not ok:
        audit.append({**event, "decision": "DENY", "reason": msg})
        return False, msg

    # Scope
    ok, msg = is_in_scope(target, roe)
    if not ok:
        audit.append({**event, "decision": "DENY", "reason": msg})
        return False, msg

    # Technique
    ok, msg = check_technique(attack_id, roe)
    if not ok:
        audit.append({**event, "decision": "DENY", "reason": msg})
        return False, msg

    # TPI
    if roe.destructive_actions_require_tpi and requires_tpi(command):
        if not second_operator:
            audit.append(
                {**event, "decision": "DENY",
                 "reason": "TPI required: no second operator"}
            )
            return False, "Destructive command — TPI required"
        if second_operator == operator:
            audit.append(
                {**event, "decision": "DENY",
                 "reason": "TPI second operator must differ"}
            )
            return False, "TPI second operator must be different person"
        event["second_actor"] = second_operator

    audit.append({**event, "decision": "ALLOW"})
    return True, "Approved"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan(target: str = ".", **opts) -> ScanResult:
    """Scan a session log for ROE violations."""
    r = ScanResult(tool_name="redforge-c2", tool_version="0.1.0")

    p = Path(target)
    if not p.exists():
        r.add(Finding(
            "RF-NOTFOUND", Severity.MODERATE,
            f"Target path does not exist: {target}",
            remediation="Pass an existing directory or audit log file.",
        ))
        r.finalize()
        return r

    log_files = list(p.glob("audit*.jsonl")) if p.is_dir() else [p]
    roe_files = list(p.glob("roe*.json")) if p.is_dir() else []

    if not log_files:
        r.add(Finding(
            "RF-NOLOG", Severity.MODERATE,
            "No audit log found",
            remediation="Pass a directory containing audit-*.jsonl",
        ))
        r.finalize()
        return r

    # Load ROE if present; emit a finding on parse failure but continue.
    # The loaded ROE is stored in meta for downstream consumers.
    if roe_files:
        try:
            loaded_roe = load_roe(roe_files[0])
            r.meta["engagement_id"] = loaded_roe.engagement_id
        except (ROEValidationError, FileNotFoundError, OSError) as exc:
            r.add(Finding(
                "RF-ROE-INVALID", Severity.HIGH,
                f"ROE file could not be loaded: {exc}",
                location=str(roe_files[0]),
                remediation=(
                    "Ensure roe*.json is valid and contains all required fields."
                ),
            ))

    for lf in log_files:
        try:
            text = lf.read_text(encoding="utf-8")
        except OSError as exc:
            r.add(Finding(
                "RF-IOERR", Severity.MODERATE,
                f"Cannot read log file: {exc}",
                location=str(lf),
                remediation="Check file permissions.",
            ))
            continue

        lines = text.splitlines()
        r.items_scanned += len(lines)

        for line in lines:
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(e, dict):
                continue

            ev = e.get("event")
            if not isinstance(ev, dict):
                continue

            if ev.get("decision") == "DENY":
                cmd_str = str(ev.get("cmd", "?"))[:50]
                tgt_str = ev.get("target", "?")
                r.add(Finding(
                    "RF-DENY", Severity.LOW,
                    f"Denied: {cmd_str} on {tgt_str}",
                    description=ev.get("reason", ""),
                    location=str(lf),
                    remediation="Review with team lead; update ROE if appropriate.",
                ))
            elif requires_tpi(ev.get("cmd") or "") and not ev.get("second_actor"):
                r.add(Finding(
                    "RF-TPI-MISS", Severity.VERY_HIGH,
                    "Destructive command logged without TPI second-actor",
                    location=str(lf),
                    mitre_attack="T1485",
                    remediation="Halt engagement; investigate.",
                ))

    r.finalize()
    return r
