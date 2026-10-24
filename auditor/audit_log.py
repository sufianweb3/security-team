"""Append-only, hash-chained JSONL audit log (tamper-evident, redacted)."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redact import redact_obj

_LOCK = threading.Lock()
GENESIS = "0" * 64


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - 65536))
        tail = fh.read().decode("utf-8", "replace").strip().splitlines()
    for line in reversed(tail):
        try:
            return json.loads(line)["hash"]
        except Exception:
            continue
    return GENESIS


def append(path: Path, event: str, actor: str, data: dict[str, Any] | None = None,
           decision: str | None = None) -> dict[str, Any]:
    """event: e.g. scope.validated, net.request, tool.run, policy.deny"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        prev = _last_hash(path)
        rec: dict[str, Any] = {
            "ts": utcnow(),
            "event": event,
            "actor": actor,
            "decision": decision,
            "data": redact_obj(data or {}),
            "prev_hash": prev,
        }
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        rec["hash"] = hashlib.sha256((prev + body).encode()).hexdigest()
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def verify(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    if not path.exists():
        return False, "log missing"
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, f"line {i}: invalid JSON"
        h = rec.pop("hash", None)
        if rec.get("prev_hash") != prev:
            return False, f"line {i}: chain broken"
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        if hashlib.sha256((prev + body).encode()).hexdigest() != h:
            return False, f"line {i}: hash mismatch"
        prev = h
    return True, "ok"
