"""Severity, confidence and Red/Yellow/Green zone logic. All deterministic.

Dimensions are kept independent:
  zone (RED/YELLOW/GREEN) | severity | confidence | verification status | financial exposure
See docs/RISK_METHODOLOGY.md for the rationale and edge cases."""
from __future__ import annotations

import math
from typing import Any

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
CONF_ORDER = ["low", "medium", "high"]
STRONG_STATUSES = {"confirmed_static", "strongly_supported"}
EXCLUDED_STATUSES = {"false_positive", "not_applicable"}

# ---------------------------------------------------------------- CVSS v3.1
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_REQ = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


class CvssError(ValueError):
    pass


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def parse_cvss31(vector: str) -> dict[str, str]:
    if not vector.startswith("CVSS:3.1/"):
        raise CvssError("vector must start with CVSS:3.1/")
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    for k in _REQ:
        if k not in parts:
            raise CvssError(f"missing metric {k}")
    if parts["S"] not in ("U", "C"):
        raise CvssError("S must be U or C")
    for k in ("AV", "AC", "UI", "C", "I", "A"):
        if parts[k] not in _W[k]:
            raise CvssError(f"bad value for {k}")
    if parts["PR"] not in ("N", "L", "H"):
        raise CvssError("bad value for PR")
    return parts


def cvss31_base(vector: str) -> float:
    m = parse_cvss31(vector)
    iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[m["S"]][m["PR"]] * _W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def severity_from_score(score: float) -> str:
    if score == 0:
        return "informational"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# ------------------------------------------------------------- severity rules
def normalize_severity(f: dict[str, Any], policy: dict | None = None) -> list[str]:
    """Make severity defensible. Returns notes on any adjustment (logged in history)."""
    notes: list[str] = []
    cvss = f.get("cvss") or None
    if cvss and cvss.get("vector"):
        if cvss.get("version", "3.1") == "3.1":
            try:
                score = cvss31_base(cvss["vector"])
            except CvssError as exc:
                notes.append(f"invalid CVSS vector removed ({exc})")
                f["cvss"] = None
                cvss = None
            else:
                cvss["score"] = score
                derived = severity_from_score(score)
                if f["severity"] != derived:
                    notes.append(f"severity {f['severity']} -> {derived} to match CVSS {score}")
                    f["severity"] = derived
                f["severity_basis"] = "cvss"
        else:
            cvss["score"] = None  # CVSS 4.0 stored, not computed (documented limitation)
            notes.append("CVSS 4.0 vector stored without computed score")
    if not (f.get("cvss") or {}).get("vector"):
        if f["severity"] == "critical":
            f["severity"] = "high"
            notes.append("critical requires a defensible CVSS vector: capped at high")
        f.setdefault("severity_basis", "qualitative")
    # A missing security header alone is never more than low.
    if f.get("category") in ("missing-security-header", "security-header") and SEV_ORDER.index(f["severity"]) > 1:
        f["severity"] = "low"
        f["severity_basis"] = "policy_cap"
        notes.append("missing security header alone capped at low")
    # Weak evidence cannot carry high/critical severity claims from a model.
    status = f["verification"]["status"]
    if status == "unverified_hypothesis" and SEV_ORDER.index(f["severity"]) > 2:
        notes.append("unverified hypothesis: severity retained but zone limited to YELLOW")
    return notes


def derive_confidence(f: dict[str, Any]) -> str:
    """Confidence reflects evidence quality, independent of severity."""
    status = f["verification"]["status"]
    verified_ev = sum(1 for e in f["evidence"] if e.get("verified"))
    if status == "confirmed_static" and verified_ev >= 1:
        return "high"
    if status in ("strongly_supported", "confirmed_static"):
        return "medium" if verified_ev else "low"
    if status == "potential":
        return "medium" if verified_ev and f["source"]["kind"] in ("tool", "merged") else "low"
    return "low"


def zone(f: dict[str, Any]) -> str | None:
    """None => excluded from the findings list (false positive / not applicable)."""
    status = f["verification"]["status"]
    if status in EXCLUDED_STATUSES:
        return None
    sev = f["severity"]
    if sev == "informational":
        return "GREEN"
    verified_ev = any(e.get("verified") for e in f["evidence"])
    if (sev in ("critical", "high") and status in STRONG_STATUSES
            and f["confidence"] in ("high", "medium") and verified_ev):
        return "RED"
    return "YELLOW"


def component_zone(findings: list[dict[str, Any]], covered: bool) -> str:
    if not covered:
        return "NOT_ASSESSED"
    zones = [f.get("risk_zone") for f in findings]
    if "RED" in zones:
        return "RED"
    if "YELLOW" in zones:
        return "YELLOW"
    return "GREEN"
