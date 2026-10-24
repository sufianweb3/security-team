"""Severity/CVSS/zone and financial-estimate validation (deterministic)."""
import pytest

from auditor import financial, risk


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
])
def test_cvss31(vector, score):
    assert risk.cvss31_base(vector) == pytest.approx(score, abs=0.05)


def test_cvss_invalid():
    with pytest.raises(risk.CvssError):
        risk.cvss31_base("CVSS:3.1/AV:N")


def _f(**kw):
    base = {"severity": "high", "category": "sql-injection", "cvss": None, "evidence": [{"verified": True}],
            "verification": {"status": "confirmed_static"}, "source": {"kind": "tool", "name": "semgrep"},
            "confidence": "high"}
    base.update(kw)
    return base


def test_critical_requires_cvss():
    f = _f(severity="critical", cvss=None)
    notes = risk.normalize_severity(f)
    assert f["severity"] == "high" and any("critical" in n for n in notes)


def test_cvss_overrides_severity():
    f = _f(severity="low", cvss={"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    risk.normalize_severity(f)
    assert f["severity"] == "critical" and f["cvss"]["score"] == pytest.approx(9.8, abs=0.05)


def test_header_only_capped_low():
    f = _f(severity="high", category="missing-security-header")
    risk.normalize_severity(f)
    assert f["severity"] == "low"


def test_zone_red_needs_strong_evidence():
    f = _f(risk_zone=None)
    risk.normalize_severity(f); f["confidence"] = risk.derive_confidence(f)
    assert risk.zone(f) == "RED"
    f2 = _f(verification={"status": "unverified_hypothesis"}, evidence=[{"verified": False}])
    risk.normalize_severity(f2); f2["confidence"] = risk.derive_confidence(f2)
    assert risk.zone(f2) == "YELLOW"


def test_zone_excludes_false_positive():
    f = _f(verification={"status": "false_positive"})
    assert risk.zone(f) is None


def test_confidence_independent_of_severity():
    f = _f(severity="critical", verification={"status": "potential"}, evidence=[{"verified": False}],
           source={"kind": "agent", "name": "x"})
    assert risk.derive_confidence(f) == "low"


# ---- financial ----
def _est(**kw):
    e = {"method": "scenario", "currency": "USD", "loss_type": "direct_loss", "time_horizon": "per incident",
         "category": "direct_theft", "confidence": "low", "calculation": "x", "limitations": ["demo"],
         "assumptions": ["a"], "inputs": [{"name": "balance", "value": 1000, "source": "docs", "source_date": "2026-01-01"}],
         "range": {"min": 100, "most_plausible": 500, "max": 1000}}
    e.update(kw)
    return e


def test_valid_estimate():
    out = financial.validate(_est())
    assert "Potential exposure" in out["statement"] and out["is_actual_loss"] is False


def test_unsourced_input_rejected():
    with pytest.raises(financial.FinancialError):
        financial.validate(_est(inputs=[{"name": "x", "value": 1, "source": "", "source_date": ""}]))


def test_full_tvl_exposure_rejected():
    with pytest.raises(financial.FinancialError, match="exposure_fraction"):
        financial.validate(_est(inputs=[{"name": "tvl", "value": 1e9, "source": "chain", "source_date": "2026"}]))


def test_fraction_must_be_below_one():
    bad = _est(inputs=[{"name": "tvl", "value": 1e9, "source": "chain", "source_date": "2026"},
                       {"name": "exposure_fraction", "value": 1.0, "source": "analysis", "source_date": "2026"}])
    with pytest.raises(financial.FinancialError):
        financial.validate(bad)


def test_scenario_cannot_be_high_confidence():
    with pytest.raises(financial.FinancialError):
        financial.validate(_est(confidence="high"))


def test_bad_range_rejected():
    with pytest.raises(financial.FinancialError):
        financial.validate(_est(range={"min": 500, "most_plausible": 100, "max": 1000}))


def test_unknown_passthrough():
    out = financial.validate({})
    assert out["method"] == "unknown" and "cannot be reliably quantified" in out["statement"]
