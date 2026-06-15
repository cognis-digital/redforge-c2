"""Tamper-evident audit log. Hash-chained, append-only, local file."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        try:
            last = self.path.read_text(encoding="utf-8").rstrip().split("\n")[-1]
            return json.loads(last)["hash"]
        except Exception:
            return "GENESIS"

    def append(self, event: dict) -> dict:
        if not isinstance(event, dict):
            raise TypeError(f"audit event must be a dict, got {type(event).__name__}")
        prev = self._last_hash()
        entry = {
            "ts": time.time(),
            "prev": prev,
            "event": event,
        }
        body = json.dumps(entry, sort_keys=True, default=str)
        entry["hash"] = hashlib.sha256((body + prev).encode()).hexdigest()
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            raise OSError(f"Failed to write audit log {self.path}: {exc}") from exc
        return entry

    def verify(self) -> tuple[bool, str]:
        if not self.path.exists():
            return True, "Empty log"
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"Cannot read log file: {exc}"

        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return True, "Empty log"

        prev = "GENESIS"
        for i, line in enumerate(lines, 1):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return False, f"Line {i}: not valid JSON"
            if not isinstance(e, dict):
                return False, f"Line {i}: entry is not a JSON object"
            for required in ("ts", "prev", "event", "hash"):
                if required not in e:
                    return False, f"Line {i}: missing field '{required}'"
            recomputed_body = json.dumps(
                {k: e[k] for k in ("ts", "prev", "event")},
                sort_keys=True,
                default=str,
            )
            recomputed = hashlib.sha256((recomputed_body + prev).encode()).hexdigest()
            if recomputed != e["hash"]:
                return False, f"Hash mismatch at line {i}"
            if e["prev"] != prev:
                return False, f"Prev mismatch at line {i}"
            prev = e["hash"]
        return True, f"Chain OK ({i} entries)"
