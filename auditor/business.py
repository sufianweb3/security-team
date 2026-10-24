"""Business-impact assessment: "how much does this finding matter to THIS organization?"

Kept separate from technical severity, CVSS, confidence, verification and risk zone. The
technical dimensions are never changed here; this module only adds a `business_impact`
block with a business priority (P1..P5), the program's expected rating where the program
publishes one, and a submission recommendation.

Context comes ONLY from the scope file's `business_context` block (asset tiers, data
classes, environment, exposure, the program's severity table). The scope file lives under
config/ which agents cannot write, so an agent cannot inflate an asset's importance.

Rules (deterministic, see docs/BUSINESS_IMPACT.md):
  * No business_context in scope              -> not_assessed (never guessed).
  * No asset matches the finding              -> asset_unknown, priority = technical.
  * Automatic modifiers may only LOWER priority: low-tier asset, non-production
    environment, not internet-exposed.
  * An asset's max_severity (program asset tier cap) always clamps the priority.
  * A reviewer (sentinel-business-impact) may lower freely with a rationale, but may RAISE
    by at most one step and only when ALL hold: verification is confirmed_static or
    strongly_supported, technical severity >= medium, the asset is high/critical tier, the
    context source is not "unknown", and the affected data classes are declared for that
    asset and include at least one high-value class. Raising to P1 also needs a CVSS vector.
  * The reviewer must not have contributed to the finding.
  * Program out-of-scope impacts / excluded categories -> do_not_submit.
"""
from __future__ import annotations

from typing import Any

from .policy import PolicyError
from .redact import redact
from . import risk

SEV = risk.SEV_ORDER                       # informational, low, medium, high, critical
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "informational": "P5"}
TIERS = ["low", "medium", "high", "critical"]
NON_PROD = {"test", "staging", "development", "dev", "sandbox", "demo"}
HIGH_VALUE_DATA = {"pii", "payment", "credentials", "health", "funds", "secrets",
                   "authentication", "financial", "customer_content"}
DATA_CLASSES = HIGH_VALUE_DATA | {"internal", "public", "none", "telemetry"}
MIN_RATIONALE = 40


def _clamp(i: int, lo: int = 1, hi: int = 4) -> int:
    return max(lo, min(hi, i))


def match_asset(f: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Most specific match wins: path/host match beats target-only; first listed breaks ties."""
    files = [l.get("file") for l in f.get("locations", []) if l.get("file")]
    hosts = []
    for l in f.get("locations", []):
        u = l.get("url") or ""
        if "://" in u:
            hosts.append(u.split("/")[2].split(":")[0].lower())
    if (f.get("target_id") or "").startswith("web:"):
        hosts.append(f["target_id"][4:].lower())
    specific, generic = [], []
    for a in ctx.get("assets") or []:
        m = a.get("match") or {}
        tids = m.get("target_ids") or []
        if tids and f.get("target_id") not in tids:
            continue
        prefixes, hs = m.get("path_prefixes") or [], [h.lower() for h in m.get("hosts") or []]
        if prefixes or hs:
            if any(fp.startswith(p) for fp in files for p in prefixes) or any(h in hs for h in hosts):
                specific.append(a)
        elif tids:
            generic.append(a)
    return (specific or generic or [None])[0]


def validate_review(review: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(review, dict):
        raise PolicyError("business review must be a JSON object")
    allowed = {"adjustment", "rationale", "affected_data_classes", "program_rating_ref",
               "business_scenario", "assumptions"}
    extra = set(review) - allowed
    if extra:
        raise PolicyError(f"unknown business review fields: {sorted(extra)}")
    adj = review.get("adjustment", 0)
    if not isinstance(adj, int) or isinstance(adj, bool) or not -2 <= adj <= 1:
        raise PolicyError("adjustment must be an integer from -2 (lower) to +1 (raise one step)")
    rat = str(review.get("rationale") or "")
    if len(rat) < MIN_RATIONALE:
        raise PolicyError(f"a substantive business rationale (>= {MIN_RATIONALE} chars) is required")
    dcs = review.get("affected_data_classes") or []
    if not isinstance(dcs, list) or not all(isinstance(x, str) for x in dcs):
        raise PolicyError("affected_data_classes must be a list of strings")
    bad = set(dcs) - DATA_CLASSES
    if bad:
        raise PolicyError(f"unknown data classes {sorted(bad)}; allowed: {sorted(DATA_CLASSES)}")
    return {"adjustment": adj, "rationale": redact(rat), "affected_data_classes": dcs,
            "program_rating_ref": str(review.get("program_rating_ref") or ""),
            "business_scenario": redact(str(review.get("business_scenario") or "")),
            "assumptions": [redact(str(x)) for x in review.get("assumptions") or []]}


def check_raise(f: dict[str, Any], ctx: dict[str, Any], asset: dict[str, Any] | None,
                review: dict[str, Any]) -> None:
    """Raise PolicyError explaining why an upward adjustment is not permitted."""
    why = []
    if f["verification"]["status"] not in risk.STRONG_STATUSES:
        why.append("finding is not independently verified (confirmed_static/strongly_supported)")
    if SEV.index(f["severity"]) < SEV.index("medium"):
        why.append("technical severity below medium")
    if asset is None:
        why.append("no asset in business_context matches this finding")
    elif asset.get("criticality") not in ("high", "critical"):
        why.append(f"asset tier is {asset.get('criticality')!r}, raising needs high or critical")
    if (ctx.get("source") or "unknown") == "unknown":
        why.append("business_context.source is 'unknown' (owner or program must supply it)")
    dcs = set(review.get("affected_data_classes") or [])
    declared = set((asset or {}).get("data_classes") or [])
    if not dcs:
        why.append("no affected_data_classes given")
    elif not dcs <= declared:
        why.append(f"data classes {sorted(dcs - declared)} are not declared for asset {(asset or {}).get('id')!r}")
    elif not dcs & HIGH_VALUE_DATA:
        why.append("none of the affected data classes is high-value")
    if why:
        raise PolicyError("business priority raise refused: " + "; ".join(why))


def assess(f: dict[str, Any], scope) -> dict[str, Any]:
    ctx = getattr(scope, "business_context", None) if scope is not None else None
    tech = f["severity"]
    out: dict[str, Any] = {"technical_severity": tech, "technical_priority": PRIORITY[tech]}
    if not ctx:
        return {**out, "status": "not_assessed", "business_priority": None,
                "reason": "scope has no business_context; business impact is not guessed",
                "submission_recommendation": _submission(f, scope, None, None)}
    asset = match_asset(f, ctx)
    review = f.get("business_review")
    notes: list[str] = []
    if tech == "informational":
        level = 0
    else:
        level = SEV.index(tech)
        auto = 0
        if asset is None:
            notes.append("no asset mapping: business priority equals technical priority")
        else:
            if asset.get("criticality") == "low":
                auto -= 1
                notes.append("low-tier asset (-1)")
            if (asset.get("environment") or "unknown") in NON_PROD:
                auto -= 1
                notes.append(f"non-production environment '{asset.get('environment')}' (-1)")
            if asset.get("internet_exposed") is False:
                auto -= 1
                notes.append("not internet-exposed (-1)")
        level = _clamp(level + max(auto, -2))
        if review:
            adj = review["adjustment"]
            if adj > 0:
                try:
                    check_raise(f, ctx, asset, review)
                    new = _clamp(level + 1)
                    if new == SEV.index("critical") and not (f.get("cvss") or {}).get("vector"):
                        notes.append("raise to P1 refused: no CVSS vector")
                    else:
                        level = new
                        notes.append(f"reviewer raised one step: {review['rationale'][:160]}")
                except PolicyError as exc:  # verification may have changed since the review
                    notes.append(str(exc))
            elif adj < 0:
                level = _clamp(level + adj)
                notes.append(f"reviewer lowered {abs(adj)} step(s): {review['rationale'][:160]}")
        if asset and asset.get("max_severity") in SEV:
            cap = SEV.index(asset["max_severity"])
            if level > cap:
                level = cap
                notes.append(f"asset tier caps severity at {asset['max_severity']} (program rule)")
    bp_sev = SEV[level]
    program_rating = _program_rating(f, ctx)
    out.update({
        "status": "assessed" if asset else "asset_unknown",
        "asset_id": (asset or {}).get("id"),
        "asset_criticality": (asset or {}).get("criticality"),
        "asset_environment": (asset or {}).get("environment", "unknown") if asset else None,
        "data_classes_at_risk": (review or {}).get("affected_data_classes")
                                or ((asset or {}).get("data_classes") if asset else []),
        "business_priority": PRIORITY[bp_sev],
        "business_severity": bp_sev,
        "program_expected_rating": program_rating,
        "context_source": ctx.get("source", "unknown"),
        "context_ref": ctx.get("source_ref"),
        "reviewed_by": f.get("business_reviewer"),
        "notes": notes,
        "submission_recommendation": _submission(f, scope, ctx, bp_sev),
    })
    if review:
        out["business_scenario"] = review.get("business_scenario")
        out["assumptions"] = review.get("assumptions")
    return out


def _program_rating(f: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any] | None:
    ps = ctx.get("program_severity") or {}
    table = ps.get("category_ratings") or {}
    key = f["category"] if f["category"] in table else (f.get("cwe") if f.get("cwe") in table else None)
    if key is None:
        return None
    return {"rating": table[key], "matched_on": key, "scale": ps.get("scale", "custom"),
            "source": ps.get("source_ref") or ctx.get("source_ref")}


def _submission(f: dict[str, Any], scope, ctx: dict[str, Any] | None, bp_sev: str | None) -> dict[str, str]:
    oos = set(((ctx or {}).get("program_severity") or {}).get("out_of_scope_impacts") or [])
    if f["category"] in oos or (scope is not None and scope.category_excluded(f["category"])):
        return {"decision": "do_not_submit", "why": "the program lists this category/impact as out of scope or excluded"}
    status = f["verification"]["status"]
    if status in risk.EXCLUDED_STATUSES:
        return {"decision": "do_not_submit", "why": f"finding marked {status}"}
    if status not in risk.STRONG_STATUSES:
        return {"decision": "needs_more_evidence", "why": "not independently verified; do not submit as-is"}
    if bp_sev is None:
        return {"decision": "manual_review", "why": "verified, but business impact not assessed (no business_context)"}
    if bp_sev in ("low", "informational"):
        return {"decision": "low_value", "why": "verified but low business priority; check the program accepts low-impact reports"}
    return {"decision": "candidate_for_manual_submission",
            "why": "verified with meaningful business priority; a human must review, check duplicates and program rules"}


def assess_all(findings: list[dict[str, Any]], scope) -> None:
    for f in findings:
        f["business_impact"] = assess(f, scope)


def set_review(f: dict[str, Any], review_raw: dict[str, Any], reviewer: str, scope) -> dict[str, Any]:
    review = validate_review(review_raw)
    contributors = set(f["source"].get("contributors") or [f["source"]["name"]])
    if reviewer in contributors:
        raise PolicyError("business impact must be assessed by an agent that did not author the finding")
    ctx = getattr(scope, "business_context", None)
    if not ctx:
        raise PolicyError("scope has no business_context: business impact cannot be assessed (ask the user to add it)")
    if review["adjustment"] > 0:
        check_raise(f, ctx, match_asset(f, ctx), review)
    f["business_review"] = review
    f["business_reviewer"] = reviewer
    f["business_impact"] = assess(f, scope)
    return f["business_impact"]
