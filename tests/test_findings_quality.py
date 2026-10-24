"""Agent-candidate intake: evidence must match the snapshot; no self-confirmation;
no confirmation on consensus; independent reviewer; false positives excluded."""
import json
from pathlib import Path

import pytest

from auditor.findings import Ledger, verify_excerpt
from auditor.pipeline import Run
from auditor.policy import PROJECT_ROOT, PolicyError
from auditor.scope import load_scope

SCOPE = PROJECT_ROOT / "config" / "scopes" / "vulnapp-local.yaml"


@pytest.fixture(scope="module")
def run():
    r = Run(load_scope(SCOPE))
    r.ingest()
    r.inventory_target("vulnapp")
    return r


def candidate(**kw):
    c = {
        "title": "Invoice endpoint lacks ownership check (IDOR)",
        "category": "idor", "cwe": "CWE-639", "component": "app", "target_id": "vulnapp",
        "locations": [{"file": "app/app.py", "start_line": 21, "end_line": 29, "function": "get_invoice", "role": "sink"}],
        "evidence": [{"kind": "code_excerpt", "file": "app/app.py", "start_line": 24, "end_line": 25,
                      "content": 'row = db().execute("SELECT id, owner_id, total FROM invoices WHERE id = ?", (invoice_id,)).fetchone()'}],
        "description": "The handler loads any invoice by id without comparing owner_id to the session user.",
        "preconditions": ["Attacker has any valid account"],
        "attack_scenario": "A logged-in user requests /invoices/<other id> and receives another customer's invoice.",
        "expected_boundary": "Users can only read their own invoices.",
        "observed_behavior": "Query filters only by id; owner_id is returned but never checked.",
        "technical_impact": "Disclosure of other customers' invoice data.",
        "severity": "high", "confidence": "high",
        "verification": {"status": "confirmed_static"},
        "safe_validation": "Read get_invoice and confirm no owner check exists on any path.",
        "remediation": "Add WHERE owner_id = current_user().id or an explicit ownership check.",
        "references": ["https://cwe.mitre.org/data/definitions/639.html"], "limitations": [],
        "source": {"kind": "agent", "name": "sentinel-authz"},
    }
    c.update(kw)
    return c


def test_real_excerpt_verifies(run):
    ok, note = verify_excerpt(run.targets_base / "vulnapp", candidate()["evidence"][0])
    assert ok, note


def test_fabricated_excerpt_rejected(run):
    ev = dict(candidate()["evidence"][0], content="if user.is_admin: return secret_data")
    ok, _ = verify_excerpt(run.targets_base / "vulnapp", ev)
    assert not ok


def test_fabricated_file_rejected(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    c = candidate(locations=[{"file": "app/does_not_exist.py", "start_line": 1, "end_line": 2}])
    ok, why = L.add(c, run.targets_base, actor="sentinel-authz")
    assert not ok and "not found" in why
    assert L.rejected


def test_self_confirmation_downgraded(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    ok, fid = L.add(candidate(), run.targets_base, actor="sentinel-authz")
    assert ok
    f = L.get(fid)
    assert f["verification"]["status"] == "strongly_supported"   # not confirmed by its own author


def test_unverifiable_evidence_becomes_hypothesis(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    c = candidate(evidence=[{"kind": "code_excerpt", "file": "app/app.py", "start_line": 24, "end_line": 25,
                             "content": "totally invented line"}])
    ok, fid = L.add(c, run.targets_base, actor="sentinel-authz")
    assert ok
    assert L.get(fid)["verification"]["status"] == "unverified_hypothesis"
    L.score_all()
    assert L.get(fid)["risk_zone"] != "RED" and L.get(fid)["confidence"] == "low"


def test_consensus_is_not_evidence(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    _, fid = L.add(candidate(), run.targets_base, actor="sentinel-authz")
    with pytest.raises(PolicyError, match="not evidence"):
        L.set_status(fid, "confirmed_static", "three agents agree on this one strongly", "sentinel-verifier",
                     basis=["consensus"])


def test_author_cannot_verify_own_finding(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    _, fid = L.add(candidate(), run.targets_base, actor="sentinel-authz")
    with pytest.raises(PolicyError, match="independent"):
        L.set_status(fid, "confirmed_static", "I re-read it and it is definitely real.", "sentinel-authz")


def test_independent_confirmation_makes_red(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    _, fid = L.add(candidate(), run.targets_base, actor="sentinel-authz")
    L.set_status(fid, "confirmed_static", "get_invoice selects by id only; no owner check on any path; "
                 "sibling handlers use current_user().", "sentinel-verifier")
    L.score_all()
    f = L.get(fid)
    assert f["risk_zone"] == "RED" and f["confidence"] == "high"


def test_false_positive_excluded_from_report_list(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    _, fid = L.add(candidate(), run.targets_base, actor="sentinel-authz")
    L.set_status(fid, "false_positive", "Ownership enforced by a DB row-level policy (documented).", "sentinel-verifier")
    L.score_all()
    assert fid not in [f["id"] for f in L.accepted()]


def test_schema_violation_rejected(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    c = candidate(); del c["remediation"]
    ok, why = L.add(c, run.targets_base, actor="x")
    assert not ok and "schema" in why


def test_severity_and_confidence_are_separate_fields(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    c = candidate(severity="high", confidence="low")
    _, fid = L.add(c, run.targets_base, actor="sentinel-authz")
    L.score_all()
    f = L.get(fid)
    assert f["severity"] == "high" and f["confidence"] == "low"


def test_secret_in_candidate_redacted(run, tmp_path):
    L = Ledger(tmp_path / "f.json")
    c = candidate(description="Key AKIAZ7QF3XK2LMNB4TQP found hardcoded in config used by the app.")
    _, fid = L.add(c, run.targets_base, actor="sentinel-secrets")
    assert "AKIAZ7QF3XK2LMNB4TQP" not in json.dumps(L.get(fid))


def test_http_observation_absence_verified_and_not_merged(tmp_path):
    from auditor.adapters.builtin import web_headers
    obs = {"url": "https://app.example.com/", "final_url": "https://app.example.com/", "status": 200,
           "headers": {"server": "nginx", "x-frame-options": "DENY"}, "observed_at": "2026-10-24T00:00:00Z"}
    http = tmp_path / "obs"; http.mkdir()
    (http / "o.json").write_text(json.dumps(obs))
    L = Ledger(tmp_path / "f.json")
    for f in web_headers(obs, "web:app.example.com"):
        L.add(f, tmp_path, http, actor="builtin-web")
    L.score_all()
    rules = {f["source"]["rule_id"] for f in L.findings}
    assert {"hdr-strict-transport-security", "hdr-content-security-policy", "hdr-x-content-type-options"} <= rules
    assert "hdr-framing" not in rules                       # header present -> no finding
    assert all(f["severity"] == "low" and f["risk_zone"] == "YELLOW" for f in L.findings)
    assert all(e["verified"] for f in L.findings for e in f["evidence"])


def test_http_claim_of_absent_header_that_exists_is_unverified(tmp_path):
    obs = {"url": "https://app.example.com/", "final_url": "https://app.example.com/", "headers": {"content-security-policy": "default-src 'self'"}}
    http = tmp_path / "obs"; http.mkdir(); (http / "o.json").write_text(json.dumps(obs))
    from auditor.findings import _verify_http
    ok, _ = _verify_http({"url": "https://app.example.com/", "content": "content-security-policy: (absent)"}, http)
    assert not ok
