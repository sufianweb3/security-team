"""End-to-end on the intentionally vulnerable fixture: ingest is read-only, nothing in
the target is executed, findings are evidence-linked and deduplicated, reports are
valid, missing tools degrade gracefully, and repeated runs are structurally stable."""
import json
import os
import re
import stat
from pathlib import Path

import pytest
import yaml

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from auditor import audit_log
from auditor.findings import Ledger
from auditor.pipeline import Run, run_all
from auditor.policy import PROJECT_ROOT
from auditor.scope import load_scope

SCOPE = PROJECT_ROOT / "config" / "scopes" / "vulnapp-local.yaml"
EXPECTED = yaml.safe_load((PROJECT_ROOT / "fixtures" / "vulnapp.expected.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def result():
    return run_all(str(SCOPE))


@pytest.fixture(scope="module")
def report(result):
    return json.loads(Path(result["reports"]["json"]).read_text(encoding="utf-8"))


def test_report_valid_json_schema(report):
    if jsonschema is None:
        pytest.skip("jsonschema missing")
    schema_dir = PROJECT_ROOT / "schemas"
    rschema = json.loads((schema_dir / "report.schema.json").read_text(encoding="utf-8"))
    fschema = json.loads((schema_dir / "finding.schema.json").read_text(encoding="utf-8"))
    resolver = jsonschema.RefResolver(base_uri=schema_dir.as_uri() + "/", referrer=rschema,
                                      store={fschema["$id"]: fschema, "finding.schema.json": fschema})
    jsonschema.validate(report, rschema, resolver=resolver)


def test_markdown_has_disclaimer_and_green_caveat(result):
    md = Path(result["reports"]["md"]).read_text(encoding="utf-8")
    assert "does NOT mean the system is secure" in md
    assert "Read-only assessment" in md


def test_every_finding_has_verified_traceable_evidence(report):
    for f in report["findings"]:
        assert f["evidence"], f["id"]
        assert any(e.get("verified") for e in f["evidence"]), (f["id"], f["evidence"])
        for loc in f["locations"]:
            assert loc.get("file") or loc.get("url")


def test_target_snapshot_is_read_only():
    tdir = PROJECT_ROOT / "targets" / "vulnapp-local" / "vulnapp"
    p = tdir / "app" / "app.py"
    assert p.exists()
    mode = p.stat().st_mode
    assert not (mode & stat.S_IWUSR), "snapshot file should not be writable"
    if hasattr(os, "geteuid") and os.geteuid() == 0:   # root ignores permission bits
        pytest.skip("running as root: permission bits are not enforced")
    with pytest.raises(PermissionError):
        p.open("a").write("x")


def test_lifecycle_scripts_never_executed(result):
    # fixture's postinstall would pipe a remote script to sh; nothing should have run
    run_dir = Path(result["run_dir"])
    log = (run_dir / "audit-log.jsonl").read_text(encoding="utf-8")
    assert "npm" not in [json.loads(l)["data"].get("tool") for l in log.splitlines() if l]
    tools_run = {json.loads(l)["data"].get("tool") for l in log.splitlines() if '"tool.run"' in l}
    assert tools_run <= {"semgrep", "bandit", "gitleaks", "osv-scanner", "git"}


def test_deterministic_ground_truth_detected(report):
    """Every deterministic seeded issue is found when the corresponding tool is installed."""
    cov = report["coverage"]["tools"]
    have = {t for t, c in cov.items() if c.get("available")}
    found = {(f["locations"][0].get("file"), f["category"]) for f in report["findings"]}
    cats_by_file = {}
    for f in report["findings"]:
        for loc in f["locations"]:
            cats_by_file.setdefault(loc.get("file"), set()).add(f["category"])
    needs = {"sql-injection": "semgrep", "path-traversal": "semgrep", "deserialization": "semgrep",
             "command-injection": "semgrep", "code-injection": "semgrep", "tls-verification-disabled": "semgrep",
             "hardcoded-secret": "semgrep", "vulnerable-dependency": "osv-scanner"}
    missing = []
    for issue in EXPECTED["issues"]:
        if not issue["deterministic"]:
            continue
        tool = needs.get(issue["category"])
        if tool and tool not in have:
            continue
        if issue["category"] not in cats_by_file.get(issue["file"], set()):
            missing.append(issue["id"])
    assert not missing, f"missed deterministic issues: {missing}"


def test_deduplication_merges_tools(report):
    multi = [f for f in report["findings"] if len(f["source"].get("contributors") or []) > 1]
    keys = [(f["category"], f["locations"][0].get("file"), f["locations"][0].get("start_line")) for f in report["findings"]]
    assert len(keys) == len(set(keys)), "duplicate findings at the same location"
    if {"semgrep", "bandit"} <= {t for t, c in report["coverage"]["tools"].items() if c.get("available")}:
        assert multi, "expected semgrep+bandit overlaps to be merged"


def test_tool_only_findings_are_not_red(report):
    # deterministic pattern matches are 'potential' at most → never RED without verification
    for f in report["findings"]:
        if f["source"]["kind"] == "tool" and f["verification"]["status"] == "potential":
            assert f["risk_zone"] != "RED"


def test_fixture_false_positives_triaged(report):
    for f in report["findings"]:
        if f["locations"][0].get("file") in ("docs/SETUP.md", "tests/test_login.py") and f["category"] == "hardcoded-secret":
            assert f["severity"] == "low"


def test_secrets_redacted_everywhere(result):
    # Read the fixture's fake credentials instead of embedding them here: the values are
    # intentionally scanner-detectable, and literals in tests trip host secret scanning.
    fixture_src = (PROJECT_ROOT / "fixtures" / "vulnapp" / "app" / "config.py").read_text(encoding="utf-8")
    fake_values = re.findall(r'^[A-Z_]+ = "([^"]+)"$', fixture_src, re.M)
    assert len(fake_values) == 3
    run_dir = Path(result["run_dir"])
    for name in ("report.json", "report.md", "report.html", "findings.json", "audit-log.jsonl"):
        text = (run_dir / name).read_text(encoding="utf-8")
        for value in fake_values:
            assert value not in text


def test_outputs_only_in_output_dir(result):
    run_dir = Path(result["run_dir"]).resolve()
    assert (PROJECT_ROOT / "audit-output").resolve() in run_dir.parents


def test_audit_log_chain_and_tamper_detection(result, tmp_path):
    log = Path(result["log"])
    ok, _ = audit_log.verify(log)
    assert ok
    lines = log.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0]); rec["actor"] = "attacker"
    t = tmp_path / "t.jsonl"; t.write_text("\n".join([json.dumps(rec)] + lines[1:]) + "\n")
    assert not audit_log.verify(t)[0]


def test_missing_tools_do_not_corrupt_report(monkeypatch):
    import auditor.sandbox as sb
    monkeypatch.setattr(sb, "find_tool", lambda name: None)
    import auditor.adapters.external as ext
    monkeypatch.setattr(ext, "run_tool", lambda name, args, **k: sb.ToolResult(name, args, 127, "", "missing", 0, available=False))
    res = run_all(str(SCOPE))
    rep = json.loads(Path(res["reports"]["json"]).read_text(encoding="utf-8"))
    assert rep["findings"], "builtin analyzers should still produce findings"
    assert any("NOT covered" in l for l in rep["limitations"])
    assert rep["coverage"]["tools"]["semgrep"]["available"] is False
    assert "builtin-secrets" in rep["coverage"]["tools"]   # fallback engaged


def test_repeated_runs_structurally_consistent():
    a = json.loads(Path(run_all(str(SCOPE))["reports"]["json"]).read_text(encoding="utf-8"))
    b = json.loads(Path(run_all(str(SCOPE))["reports"]["json"]).read_text(encoding="utf-8"))
    ids_a = sorted(f["id"] for f in a["findings"])
    ids_b = sorted(f["id"] for f in b["findings"])
    assert ids_a == ids_b
    assert set(a) == set(b)


def test_adversarial_ignore_files_do_not_hide_findings(report):
    """The fixture ships a .semgrepignore (hides app/), a .gitleaks.toml (allowlists app/config.py)
    and a .gitignore (hides app/config.py, web/). None of them may suppress analysis."""
    have = {t for t, c in report["coverage"]["tools"].items() if c.get("available")}
    by_tool = {}
    for f in report["findings"]:
        for c in f["source"].get("contributors") or [f["source"]["name"]]:
            by_tool.setdefault(c, set()).add(f["locations"][0].get("file"))
    if "semgrep" in have:
        assert "app/app.py" in by_tool.get("semgrep", set())
        assert "web/index.js" in by_tool.get("semgrep", set())
    if "gitleaks" in have:
        assert "app/config.py" in by_tool.get("gitleaks", set())
    if "osv-scanner" in have:
        assert "requirements.txt" in by_tool.get("osv-scanner", set())
