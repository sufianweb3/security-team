"""Finding ledger: schema validation, evidence verification against the immutable
snapshot, deduplication, verification-status rules and scoring."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from . import business, risk
from .audit_log import utcnow
from .policy import PROJECT_ROOT, PolicyError, load_policy
from .redact import redact, redact_obj

SCHEMA = json.loads((PROJECT_ROOT / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
DATAFLOW_CATEGORIES = {"sql-injection", "command-injection", "path-traversal", "ssrf", "xss",
                       "deserialization", "code-injection", "open-redirect", "xxe", "template-injection"}


# ------------------------------------------------------------------ helpers
def fingerprint(f: dict[str, Any]) -> str:
    loc = f["locations"][0]
    key = "|".join([
        (f.get("cwe") or f["category"]).lower(),
        f.get("target_id", ""),
        (loc.get("file") or loc.get("url") or "").lower(),
        str((loc.get("start_line") or 0) // 10),
        f["category"],
        f.get("source", {}).get("rule_id", "") if f.get("source", {}).get("kind") == "tool" else "",
    ])
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def make_id(f: dict[str, Any]) -> str:
    prefix = re.sub(r"[^A-Z0-9]", "", (f.get("cwe") or f["category"]).upper().replace("CWE-", "CWE"))[:10] or "GEN"
    if len(prefix) < 2:
        prefix = (prefix + "XX")[:2]
    return f"SA-{prefix}-{fingerprint(f)}"


def schema_errors(f: dict[str, Any]) -> list[str]:
    if jsonschema is None:
        return []
    v = jsonschema.Draft202012Validator(SCHEMA)
    return [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in v.iter_errors(f)]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def verify_excerpt(target_dir: Path, ev: dict[str, Any]) -> tuple[bool, str]:
    """True only if every substantive line of the excerpt exists in the cited
    line range (±2 lines tolerance) of the snapshot file."""
    rel = ev.get("file")
    if not rel:
        return False, "no file reference"
    path = (target_dir / rel).resolve()
    if target_dir.resolve() not in path.parents:
        return False, "file reference escapes target snapshot"
    if not path.is_file():
        return False, "cited file does not exist in snapshot"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    s = max(1, int(ev.get("start_line", 1)) - 2)
    e = min(len(lines), int(ev.get("end_line", ev.get("start_line", 1))) + 2)
    if s > len(lines):
        return False, f"cited lines beyond end of file ({len(lines)} lines)"
    window = [_norm(redact(x)) for x in lines[s - 1:e]]
    window_raw = [_norm(x) for x in lines[s - 1:e]]
    wanted = [_norm(x) for x in ev["content"].splitlines()
              if _norm(x) and _norm(x) not in ("...", "…") and not _norm(x).startswith("# ...")]
    if not wanted:
        return False, "empty excerpt"
    for w in wanted:
        if not any(w in line for line in window) and not any(w in line for line in window_raw):
            return False, f"excerpt line not found at cited location: {w[:80]!r}"
    return True, f"matched lines {s}-{e}"


def verify_evidence(f: dict[str, Any], targets_base: Path, http_dir: Path | None = None) -> None:
    tdir = targets_base / f.get("target_id", "")
    for ev in f["evidence"]:
        if ev["kind"] in ("code_excerpt", "config_excerpt", "spec_excerpt", "doc_excerpt", "tool_output") and ev.get("file"):
            ok, note = verify_excerpt(tdir, ev)
        elif ev["kind"] == "http_observation" and http_dir is not None:
            ok, note = _verify_http(ev, http_dir)
        else:
            ok, note = False, "evidence kind cannot be machine-verified"
        ev["verified"] = ok
        ev["verification_note"] = note
        ev["content"] = redact(ev["content"])


def _verify_http(ev: dict[str, Any], http_dir: Path) -> tuple[bool, str]:
    for p in sorted(http_dir.glob("*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        if rec.get("url") == ev.get("url") or rec.get("final_url") == ev.get("url"):
            headers = {k.lower(): str(v) for k, v in (rec.get("headers") or {}).items()}
            ok = True
            for line in (_norm(x) for x in ev["content"].splitlines() if _norm(x)):
                name, _, value = line.partition(":")
                name, value = name.strip().lower(), value.strip()
                if value.lower() == "(absent)":
                    ok &= name not in headers            # absence must really be absent
                else:
                    ok &= name in headers and (not value or value.split("…")[0][:40].lower() in headers[name].lower()
                                               or "[redacted]" in value.lower())
            if ok:
                return True, f"matches recorded observation {p.name}"
    return False, "no recorded observation for this URL"


def locations_exist(f: dict[str, Any], targets_base: Path) -> tuple[bool, str]:
    tdir = targets_base / f.get("target_id", "")
    for loc in f["locations"]:
        if loc.get("file"):
            p = (tdir / loc["file"]).resolve()
            if tdir.resolve() not in p.parents or not p.is_file():
                return False, f"location file not found in snapshot: {loc['file']}"
            n = len(p.read_text(encoding="utf-8", errors="replace").splitlines())
            if loc.get("start_line", 1) > n:
                return False, f"line {loc.get('start_line')} beyond end of {loc['file']} ({n} lines)"
        elif not loc.get("url"):
            return False, "location needs file or url"
    return True, "ok"


# ------------------------------------------------------------------ ledger
class Ledger:
    def __init__(self, path: Path):
        self.path = path
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            data = {"findings": [], "rejected": []}
        self.findings: list[dict[str, Any]] = data["findings"]
        self.rejected: list[dict[str, Any]] = data["rejected"]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"findings": self.findings, "rejected": self.rejected}, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def get(self, fid: str) -> dict[str, Any]:
        for f in self.findings:
            if f["id"] == fid:
                return f
        raise PolicyError(f"unknown finding {fid}")

    # -- intake -----------------------------------------------------------
    def add(self, f: dict[str, Any], targets_base: Path, http_dir: Path | None = None,
            actor: str = "unknown") -> tuple[bool, str]:
        f = redact_obj(copy.deepcopy(f))
        # Business impact is only ever set through `auditor business set` by an independent
        # reviewer against the scope's business_context; never accepted from a candidate.
        for k in ("business_impact", "business_review", "business_reviewer"):
            f.pop(k, None)
        f.setdefault("references", [])
        f.setdefault("limitations", [])
        f.setdefault("preconditions", [])
        f.setdefault("verification", {"status": "unverified_hypothesis"})
        f.setdefault("confidence", "low")
        f["fingerprint"] = fingerprint(f) if f.get("locations") else ""
        if not f.get("id"):
            try:
                f["id"] = make_id(f)
            except Exception:
                f["id"] = "SA-GEN-" + hashlib.sha256(json.dumps(f, sort_keys=True).encode()).hexdigest()[:10]
        errs = schema_errors(f)
        if errs:
            self.rejected.append({"actor": actor, "title": f.get("title"), "reasons": errs[:10], "at": utcnow()})
            return False, "schema: " + "; ".join(errs[:5])
        ok, why = locations_exist(f, targets_base)
        if not ok:
            self.rejected.append({"actor": actor, "id": f["id"], "title": f["title"], "reasons": [why], "at": utcnow()})
            return False, why
        verify_evidence(f, targets_base, http_dir)
        if not any(e.get("verified") for e in f["evidence"]):
            if f["verification"]["status"] in ("confirmed_static", "strongly_supported", "potential"):
                f.setdefault("history", []).append({"at": utcnow(), "note": "no machine-verifiable evidence: status set to unverified_hypothesis"})
                f["verification"]["status"] = "unverified_hypothesis"
        if f["verification"]["status"] == "confirmed_static" and f["source"]["kind"] == "agent":
            # Discovery agents cannot self-confirm; the verifier must review.
            f["verification"]["status"] = "strongly_supported" if any(e.get("verified") for e in f["evidence"]) else "unverified_hypothesis"
            f.setdefault("history", []).append({"at": utcnow(), "note": "self-confirmation not allowed: pending independent verification"})
        f.setdefault("history", []).append({"at": utcnow(), "event": "added", "actor": actor})
        for existing in self.findings:
            if _same_issue(existing, f):
                merge(existing, f)
                return True, f"merged into {existing['id']}"
        ids = {x["id"] for x in self.findings}
        base_id, n = f["id"], 2
        while f["id"] in ids:
            f["id"] = f"{base_id[:-2]}{n:02d}"
            n += 1
        if len(self.findings) > 5000:
            raise PolicyError("finding ledger limit reached")
        self.findings.append(f)
        return True, f["id"]

    # -- verification -------------------------------------------------------
    def set_status(self, fid: str, status: str, rationale: str, reviewer: str,
                   basis: list[str] | None = None, missing: list[str] | None = None,
                   alternatives: list[str] | None = None) -> dict[str, Any]:
        policy = load_policy()
        f = self.get(fid)
        basis = basis or []
        forbidden = set(policy["findings"]["forbidden_verification_bases"])
        if forbidden & {b.lower() for b in basis}:
            raise PolicyError("agreement between models is not evidence")
        if not rationale or len(rationale) < 20:
            raise PolicyError("a substantive rationale (>=20 chars) is required")
        contributors = set(f["source"].get("contributors") or [f["source"]["name"]])
        if status in ("confirmed_static", "strongly_supported") and reviewer in contributors:
            raise PolicyError("verification must be performed by an independent reviewer")
        verified_code = [e for e in f["evidence"] if e.get("verified") and e["kind"] in ("code_excerpt", "config_excerpt", "spec_excerpt", "tool_output", "http_observation")]
        if status == "confirmed_static":
            if not verified_code:
                raise PolicyError("confirmed_static requires machine-verified evidence")
            if f["category"] in DATAFLOW_CATEGORIES:
                roles = {l.get("role") for l in f["locations"]}
                if not ({"source", "sink"} <= roles) and "dataflow" not in basis:
                    raise PolicyError("data-flow findings need source and sink locations (or a recorded dataflow trace)")
        if status == "strongly_supported" and not verified_code:
            raise PolicyError("strongly_supported requires machine-verified evidence")
        f["verification"].update({"status": status, "rationale": rationale, "reviewed_by": reviewer,
                                  "basis": basis, "missing_prerequisites": missing or [],
                                  "alternative_explanations": alternatives or []})
        f.setdefault("history", []).append({"at": utcnow(), "event": "status", "status": status, "by": reviewer})
        return f

    # -- scoring ------------------------------------------------------------
    def score_all(self, scope=None) -> None:
        for f in self.findings:
            notes = risk.normalize_severity(f)
            derived = risk.derive_confidence(f)
            claimed = f.setdefault("claimed_confidence", f.get("confidence", "high"))
            # a model may lower confidence but never raise it above the evidence-derived level
            f["confidence"] = min(claimed, derived, key=risk.CONF_ORDER.index)
            f["risk_zone"] = risk.zone(f)
            if scope is not None and scope.category_excluded(f["category"]):
                f.setdefault("bounty", {})
                f["bounty"] = {**(f.get("bounty") or {}), "program_status": "excluded_category"}
            for n in notes:
                f.setdefault("history", []).append({"at": utcnow(), "event": "score", "note": n})
            f["business_impact"] = business.assess(f, scope)

    def accepted(self) -> list[dict[str, Any]]:
        return [f for f in self.findings if f.get("risk_zone") is not None and
                f["verification"]["status"] not in risk.EXCLUDED_STATUSES]


def _ranges_overlap(a: dict, b: dict, slack: int = 3) -> bool:
    if a.get("file") != b.get("file"):
        return False
    if a.get("file") is None:
        return a.get("url") == b.get("url")
    a1, a2 = a.get("start_line", 0), a.get("end_line", a.get("start_line", 0))
    b1, b2 = b.get("start_line", 0), b.get("end_line", b.get("start_line", 0))
    return a1 - slack <= b2 and b1 - slack <= a2


def _family(f: dict) -> str:
    return (f.get("cwe") or f["category"]).lower()


def _same_issue(a: dict, b: dict) -> bool:
    """Same target + same category + overlapping location; or same CWE at the same exact line.
    Dependency findings are only ever merged when they name the same package@version."""
    if a.get("target_id") != b.get("target_id"):
        return False
    if "vulnerable-dependency" in (a["category"], b["category"]):
        return a["category"] == b["category"] and a["source"].get("rule_id") == b["source"].get("rule_id")
    if a["category"] == b["category"]:
        url_based = all(not l.get("file") for l in a["locations"] + b["locations"])
        if url_based and a["source"].get("rule_id") != b["source"].get("rule_id"):
            return False   # distinct observations (e.g. different missing headers) on one URL
        return any(_ranges_overlap(x, y) for x in a["locations"] for y in b["locations"])
    if a.get("cwe") and a.get("cwe") == b.get("cwe"):
        return any(x.get("file") == y.get("file") and x.get("start_line") == y.get("start_line")
                   for x in a["locations"] for y in b["locations"])
    return False


STATUS_RANK = ["unverified_hypothesis", "potential", "strongly_supported", "confirmed_static"]


def merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    seen = {(e["kind"], e.get("file"), e.get("start_line"), e["content"]) for e in dst["evidence"]}
    for e in src["evidence"]:
        k = (e["kind"], e.get("file"), e.get("start_line"), e["content"])
        if k not in seen:
            dst["evidence"].append(e)
            seen.add(k)
    for loc in src["locations"]:
        if loc not in dst["locations"]:
            dst["locations"].append(loc)
    contrib = set(dst["source"].get("contributors") or [dst["source"]["name"]])
    contrib |= set(src["source"].get("contributors") or [src["source"]["name"]])
    dst["source"]["contributors"] = sorted(contrib)
    if dst["source"]["kind"] != src["source"]["kind"]:
        dst["source"]["kind"] = "merged"
    for key in ("references", "limitations", "preconditions"):
        for x in src.get(key) or []:
            if x not in dst.get(key, []):
                dst.setdefault(key, []).append(x)
    s_a, s_b = dst["verification"]["status"], src["verification"]["status"]
    if s_a in STATUS_RANK and s_b in STATUS_RANK and STATUS_RANK.index(s_b) > STATUS_RANK.index(s_a):
        # only adopt the stronger status if it is backed by verified evidence
        if any(e.get("verified") for e in src["evidence"]):
            dst["verification"] = src["verification"]
    if risk.SEV_ORDER.index(src["severity"]) > risk.SEV_ORDER.index(dst["severity"]):
        # keep the higher claim; normalize_severity() later re-derives it from CVSS / policy caps
        dst["severity"] = src["severity"]
        if src.get("cvss"):
            dst["cvss"] = src["cvss"]
    dst.setdefault("history", []).append({"at": utcnow(), "event": "merged", "from": src.get("source", {}).get("name")})
