"""Business-impact layer: priority only goes up under strict, code-enforced conditions,
never touches technical severity/zone, and context comes only from the scope file."""
import copy
from pathlib import Path

import pytest
import yaml

from auditor import business, risk
from auditor.findings import Ledger
from auditor.policy import PolicyError
from auditor.scope import Scope, validate

ROOT = Path(__file__).resolve().parent.parent

CTX = {
    "source": "owner_provided",
    "program_severity": {"scale": "custom", "category_ratings": {"idor": "high"},
                         "out_of_scope_impacts": ["missing-security-header"]},
    "assets": [
        {"id": "api", "match": {"target_ids": ["t"], "path_prefixes": ["app/"]}, "criticality": "critical",
         "data_classes": ["pii", "payment"], "environment": "production", "internet_exposed": True},
        {"id": "tests", "match": {"target_ids": ["t"], "path_prefixes": ["tests/"]}, "criticality": "low",
         "data_classes": ["none"], "environment": "test", "internet_exposed": False},
        {"id": "tier3", "match": {"target_ids": ["t"], "path_prefixes": ["marketing/"]}, "criticality": "high",
         "max_severity": "medium", "data_classes": ["pii"], "environment": "production", "internet_exposed": True},
        {"id": "rest", "match": {"target_ids": ["t"]}, "criticality": "medium", "data_classes": ["internal"]},
    ],
}


def _scope(ctx=CTX, excluded=None):
    raw = {"scope_version": 1, "assessment": {"id": "biz-test", "name": "biz test", "type": ["source_code"]},
           "authorization": {"status": "authorized", "basis": "own_code"},
           "targets": {"local_paths": [{"id": "t", "path": "."}]},
           "exclusions": {"vuln_categories": excluded or []}}
    if ctx is not None:
        raw["business_context"] = copy.deepcopy(ctx)
    return validate(Scope(raw=raw))


def _f(file="app/x.py", sev="medium", status="confirmed_static", cat="idor", cvss=None, author="sentinel-authz"):
    return {"id": "SA-X-00000001", "title": "t" * 10, "category": cat, "target_id": "t", "severity": sev,
            "cvss": cvss, "locations": [{"file": file, "start_line": 1}], "evidence": [{"verified": True}],
            "verification": {"status": status}, "source": {"kind": "agent", "name": author}}


REVIEW_UP = {"adjustment": 1, "affected_data_classes": ["pii"],
             "rationale": "Customer PII on the critical production billing API is exposed to other customers."}


def test_no_context_is_not_assessed():
    bi = business.assess(_f(), _scope(ctx=None))
    assert bi["status"] == "not_assessed" and bi["business_priority"] is None


def test_scope_validation_rejects_unknown_target_and_bad_values():
    bad = copy.deepcopy(CTX)
    bad["assets"][0]["match"]["target_ids"] = ["nope"]
    assert any("unknown target id" in e for e in _scope(bad).errors)
    bad2 = copy.deepcopy(CTX)
    bad2["assets"][0]["criticality"] = "ultra"
    assert _scope(bad2).errors


def test_example_scopes_still_valid():
    from auditor.scope import load_scope
    for name in ("vulnapp-local.yaml", "example-bugbounty-web.yaml"):
        s = load_scope(ROOT / "config" / "scopes" / name)
        assert not s.errors, s.errors
        assert s.business_context


def test_asset_matching_specific_beats_generic():
    assert business.match_asset(_f(file="app/a.py"), CTX)["id"] == "api"
    assert business.match_asset(_f(file="lib/z.py"), CTX)["id"] == "rest"
    other = _f()
    other["target_id"] = "other"
    assert business.match_asset(other, CTX) is None


def test_automatic_modifiers_only_lower():
    s = _scope()
    assert business.assess(_f(file="app/a.py", sev="high"), s)["business_priority"] == "P2"
    bi = business.assess(_f(file="tests/a.py", sev="high"), s)
    assert bi["business_priority"] == "P4"          # low tier -1, test env -1 (not-exposed would exceed -2 cap)
    assert business.assess(_f(file="lib/z.py", sev="high"), s)["business_priority"] == "P2"


def test_max_severity_cap():
    f = _f(file="marketing/p.py", sev="critical",
           cvss={"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    bi = business.assess(f, _scope())
    assert bi["business_priority"] == "P3" and any("caps" in n for n in bi["notes"])


def test_raise_one_step_when_all_conditions_hold():
    s = _scope()
    f = _f(file="app/a.py", sev="medium")
    bi = business.set_review(f, REVIEW_UP, "sentinel-business-impact", s)
    assert bi["business_priority"] == "P2"
    assert f["severity"] == "medium"                # technical severity untouched
    assert bi["program_expected_rating"]["rating"] == "high"


@pytest.mark.parametrize("change,msg", [
    ({"status": "potential"}, "not independently verified"),
    ({"sev": "low"}, "below medium"),
    ({"file": "lib/z.py"}, "asset tier"),
])
def test_raise_refused(change, msg):
    kw = {"file": "app/a.py", "sev": "medium", "status": "confirmed_static"}
    kw.update(change)
    with pytest.raises(PolicyError, match=msg):
        business.set_review(_f(**kw), REVIEW_UP, "sentinel-business-impact", _scope())


def test_raise_refused_for_undeclared_or_low_value_data():
    s = _scope()
    with pytest.raises(PolicyError, match="not declared"):
        business.set_review(_f(), {**REVIEW_UP, "affected_data_classes": ["health"]}, "sentinel-business-impact", s)
    with pytest.raises(PolicyError, match="no affected_data_classes"):
        business.set_review(_f(), {**REVIEW_UP, "affected_data_classes": []}, "sentinel-business-impact", s)


def test_raise_refused_when_source_unknown():
    ctx = copy.deepcopy(CTX)
    ctx["source"] = "unknown"
    with pytest.raises(PolicyError, match="unknown"):
        business.set_review(_f(), REVIEW_UP, "sentinel-business-impact", _scope(ctx))


def test_raise_bounds_and_p1_needs_vector():
    s = _scope()
    with pytest.raises(PolicyError, match="adjustment"):
        business.set_review(_f(), {**REVIEW_UP, "adjustment": 2}, "sentinel-business-impact", s)
    f = _f(sev="high", cvss=None)
    bi = business.set_review(f, REVIEW_UP, "sentinel-business-impact", s)
    assert bi["business_priority"] == "P2" and any("no CVSS vector" in n for n in bi["notes"])


def test_author_cannot_assess_own_finding():
    with pytest.raises(PolicyError, match="did not author"):
        business.set_review(_f(author="sentinel-business-impact"), REVIEW_UP, "sentinel-business-impact", _scope())


def test_rationale_required_and_fields_whitelisted():
    s = _scope()
    with pytest.raises(PolicyError, match="rationale"):
        business.set_review(_f(), {"adjustment": 0, "rationale": "short"}, "sentinel-business-impact", s)
    with pytest.raises(PolicyError, match="unknown business review fields"):
        business.set_review(_f(), {**REVIEW_UP, "severity": "critical"}, "sentinel-business-impact", s)


def test_lowering_allowed_and_floor_is_low():
    s = _scope()
    bi = business.set_review(_f(sev="medium"), {"adjustment": -2, "rationale": "Data returned is already public marketing content; no customer impact."},
                             "sentinel-business-impact", s)
    assert bi["business_priority"] == "P4"


def test_submission_recommendations():
    s = _scope(excluded=["missing-security-header"])
    assert business.assess(_f(cat="missing-security-header", sev="low"), s)["submission_recommendation"]["decision"] == "do_not_submit"
    assert business.assess(_f(status="potential"), s)["submission_recommendation"]["decision"] == "needs_more_evidence"
    assert business.assess(_f(file="app/a.py", sev="high"), s)["submission_recommendation"]["decision"] == "candidate_for_manual_submission"
    assert business.assess(_f(file="tests/a.py", sev="medium"), s)["submission_recommendation"]["decision"] == "low_value"


def test_zone_independent_of_business_priority():
    f = _f(file="tests/a.py", sev="high")
    f["confidence"] = "high"
    before = risk.zone(f)
    business.assess(f, _scope())
    assert risk.zone(f) == before == "RED"


def test_candidates_cannot_smuggle_business_fields(tmp_path):
    led = Ledger(tmp_path / "findings.json")
    tdir = tmp_path / "t"
    (tdir / "app").mkdir(parents=True)
    (tdir / "app" / "x.py").write_text("print('hello world')\n")
    cand = {"title": "Example finding title", "category": "idor", "component": "app", "target_id": "t",
            "locations": [{"file": "app/x.py", "start_line": 1, "end_line": 1}],
            "evidence": [{"kind": "code_excerpt", "file": "app/x.py", "start_line": 1, "end_line": 1,
                          "content": "print('hello world')"}],
            "description": "d" * 30, "preconditions": [], "attack_scenario": "a" * 20, "expected_boundary": "e" * 10,
            "observed_behavior": "o" * 10, "technical_impact": "i" * 10, "severity": "medium", "confidence": "low",
            "verification": {"status": "potential"}, "safe_validation": "review the cited code path",
            "remediation": "add an ownership check", "references": [], "limitations": [],
            "source": {"kind": "agent", "name": "x"},
            "business_review": {"adjustment": 1, "rationale": "x" * 50}, "business_reviewer": "x"}
    ok, _ = led.add(cand, tmp_path, actor="x")
    assert ok
    f = led.findings[0]
    assert "business_review" not in f and "business_reviewer" not in f


def test_business_subcommand_only_for_orchestrator_and_business_agent():
    agents = yaml.safe_load((ROOT / "harness" / "agents.yaml").read_text())["agents"]
    holders = {a["name"] for a in agents if "business" in a["subcommands"]}
    assert holders == {"sentinel-orchestrator", "sentinel-business-impact"}
