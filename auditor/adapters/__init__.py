"""Deterministic analysis adapters. Each returns (findings, coverage) where findings
are dicts in the finding schema (without id; the ledger assigns ids)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..redact import redact


def read_lines(target_dir: Path, rel: str, start: int, end: int | None = None, context: int = 0) -> str:
    p = target_dir / rel
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    end = end or start
    s, e = max(1, start - context), min(len(lines), end + context)
    return redact("\n".join(lines[s - 1:e]))[:1500]


def base_finding(*, title: str, category: str, cwe: str | None, target_id: str, file: str | None,
                 start: int | None, end: int | None, excerpt: str, tool: str, rule_id: str,
                 description: str, severity: str, impact: str, remediation: str,
                 references: list[str] | None = None, url: str | None = None,
                 evidence_kind: str = "code_excerpt", status: str = "potential",
                 limitations: list[str] | None = None, cvss: dict | None = None,
                 preconditions: list[str] | None = None, scenario: str | None = None,
                 expected: str | None = None, observed: str | None = None) -> dict[str, Any]:
    loc: dict[str, Any] = {"role": "location"}
    ev: dict[str, Any] = {"kind": evidence_kind, "content": excerpt or "(no excerpt)"}
    if file:
        loc.update({"file": file, "start_line": start or 1, "end_line": end or start or 1})
        ev.update({"file": file, "start_line": start or 1, "end_line": end or start or 1})
    if url:
        loc.update({"url": url, "role": "observation"})
        ev["url"] = url
    return {
        "title": title[:160],
        "category": category,
        "cwe": cwe,
        "component": file.split("/")[0] if file and "/" in file else (file or url or target_id),
        "target_id": target_id,
        "locations": [loc],
        "evidence": [ev],
        "description": description,
        "preconditions": preconditions or ["Code path is reachable in the deployed configuration (not verified by the tool)."],
        "attack_scenario": scenario or "Not established by the tool; requires analyst review of reachability and attacker control.",
        "expected_boundary": expected or "Untrusted input should not reach this operation without validation/authorization.",
        "observed_behavior": observed or f"Pattern matched by {tool} rule {rule_id}.",
        "technical_impact": impact,
        "severity": severity,
        "severity_basis": "tool_default",
        "cvss": cvss,
        "confidence": "medium",
        "verification": {"status": status, "basis": [f"tool:{tool}"]},
        "safe_validation": "Review the cited code and its callers statically; confirm attacker control of inputs "
                           "using local tests against a disposable copy only. Do not test the live target.",
        "remediation": remediation,
        "references": references or [],
        "limitations": limitations or [f"Detected by pattern-based tool ({tool}); reachability and exploitability not established."],
        "source": {"kind": "tool", "name": tool, "rule_id": rule_id},
    }
