"""Evidence-based financial exposure estimation (separate from severity & bounty).

Hierarchy: disclosure > cited_scale > scenario > unknown.
Never assumes full exposure of TVL, volume, valuation or customer balances."""
from __future__ import annotations

from typing import Any

UNKNOWN_TEXT = "Financial exposure cannot be reliably quantified from the available evidence."
METHODS = ("disclosure", "cited_scale", "scenario", "unknown")
LOSS_TYPES = ("direct_loss", "indirect_cost", "total_potential_exposure")
CATEGORIES = ("direct_theft", "unauthorized_withdrawal", "fraudulent_credit", "business_interruption",
              "incident_response", "breach_response", "customer_compensation")
AGGREGATE_METRICS = {"tvl", "total_value_locked", "trading_volume", "valuation", "market_cap",
                     "total_customer_balances", "revenue", "aum"}


class FinancialError(ValueError):
    pass


def unknown(reason: str = "") -> dict[str, Any]:
    return {"method": "unknown", "statement": UNKNOWN_TEXT, "reason": reason,
            "is_actual_loss": False, "is_bounty_estimate": False}


def validate(est: dict[str, Any]) -> dict[str, Any]:
    """Raise FinancialError for unsupported estimates; return normalized estimate."""
    if not est or est.get("method") == "unknown":
        return unknown((est or {}).get("reason", ""))
    m = est.get("method")
    if m not in METHODS:
        raise FinancialError(f"method must be one of {METHODS}")
    for key in ("currency", "loss_type", "time_horizon", "category", "inputs", "assumptions",
                "calculation", "confidence", "limitations"):
        if not est.get(key):
            raise FinancialError(f"missing required field: {key}")
    if est["loss_type"] not in LOSS_TYPES:
        raise FinancialError("loss_type invalid")
    if est["category"] not in CATEGORIES:
        raise FinancialError("category invalid")
    if est["confidence"] not in ("low", "medium", "high"):
        raise FinancialError("confidence invalid")
    if m == "scenario" and est["confidence"] == "high":
        raise FinancialError("scenario-based estimates cannot have high confidence")
    names = set()
    for inp in est["inputs"]:
        for key in ("name", "value", "source", "source_date"):
            if inp.get(key) in (None, ""):
                raise FinancialError(f"input {inp.get('name')!r} missing {key} (every material input needs a source and date)")
        if m in ("disclosure", "cited_scale") and str(inp["source"]).lower().startswith("assum"):
            raise FinancialError(f"{m} estimates require cited sources, not assumptions")
        names.add(str(inp["name"]).lower())
    # Aggregate business metrics may only be used with an evidenced exposure fraction.
    if names & AGGREGATE_METRICS:
        frac = [i for i in est["inputs"] if str(i["name"]).lower() in ("exposure_fraction", "exposed_fraction")]
        if not frac:
            raise FinancialError("aggregate metrics (TVL/volume/valuation/balances) require an evidenced exposure_fraction input")
        for fi in frac:
            v = fi["value"]
            vals = v.values() if isinstance(v, dict) else [v]
            if any(not (0 <= float(x) < 1) for x in vals):
                raise FinancialError("exposure_fraction must be in [0, 1): full exposure is never assumed")
    rng = est.get("range") or {}
    lo, likely, hi = rng.get("min"), rng.get("most_plausible"), rng.get("max")
    if None in (lo, likely, hi):
        raise FinancialError("range.min, range.most_plausible and range.max are required")
    if not (0 <= float(lo) <= float(likely) <= float(hi)):
        raise FinancialError("range must satisfy 0 <= min <= most_plausible <= max")
    est["is_actual_loss"] = False
    est["is_bounty_estimate"] = False
    est["statement"] = (f"Potential exposure (not an actual loss, not a bounty estimate): "
                        f"{est['currency']} {float(lo):,.0f} – {float(hi):,.0f} "
                        f"(most plausible {float(likely):,.0f}) over {est['time_horizon']}; "
                        f"method={m}; confidence={est['confidence']}.")
    return est


def scenario_from_components(components: list[dict[str, Any]], **meta: Any) -> dict[str, Any]:
    """Helper: exposure = sum(base_value * fraction) with min/likely/max fractions.
    Each component: {name, base_value, source, source_date, fraction:{min,likely,max}, fraction_source}"""
    lo = likely = hi = 0.0
    inputs = []
    for c in components:
        f = c["fraction"]
        lo += c["base_value"] * f["min"]
        likely += c["base_value"] * f["likely"]
        hi += c["base_value"] * f["max"]
        inputs.append({"name": c["name"], "value": c["base_value"], "source": c["source"], "source_date": c["source_date"]})
        inputs.append({"name": "exposure_fraction", "value": f, "source": c["fraction_source"], "source_date": c["source_date"]})
    est = {"method": "scenario", "inputs": inputs, "range": {"min": lo, "most_plausible": likely, "max": hi},
           "calculation": "sum(base_value_i * exposure_fraction_i) for min/likely/max", **meta}
    return validate(est)
