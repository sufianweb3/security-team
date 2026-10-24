#!/usr/bin/env python3
"""Reproduce the bundled example audit of the vulnerable training fixture, including the
agent layer (pre-recorded agent candidates in examples/agent-candidates/), independent
verification, CVSS scoring, a financial estimate, a rejected financial estimate, and the
final report. Every step goes through the same CLI the agents use. No model calls.

  python scripts/example_audit.py
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANDS = ROOT / "examples" / "agent-candidates"


def cli(*args, ok=(0,)):
    p = subprocess.run([sys.executable, "-m", "auditor", *args], capture_output=True, text=True, cwd=str(ROOT))
    out = json.loads(p.stdout) if p.stdout.strip().startswith("{") else {"raw": p.stdout}
    print(f"$ python -m auditor {' '.join(a if len(a) < 60 else a[:57] + '...' for a in args)}  -> rc={p.returncode}")
    if p.returncode not in ok:
        print(p.stdout, p.stderr)
        sys.exit(1)
    return out


def main():
    scope = "config/scopes/vulnapp-local.yaml"
    cli("scope", "validate", scope)
    run = cli("ingest", scope)["run"]
    run_dir = ROOT / "audit-output" / run
    cli("tools", "run", run)
    (run_dir / "candidates").mkdir(exist_ok=True)
    for f in CANDS.glob("*.json"):
        shutil.copy(f, run_dir / "candidates" / f.name)
    for agent, fname in (("sentinel-authz", "sentinel-authz.json"),
                         ("sentinel-business-logic", "sentinel-business-logic.json"),
                         ("sentinel-static-code", "sentinel-static-code-hallucination-demo.json")):
        cli("findings", "add", run, "--agent", agent, "--file", str(run_dir / "candidates" / fname))

    fl = cli("findings", "list", run)["findings"]
    def fid(cat, contains=""):
        return next(f["id"] for f in fl if f["category"] == cat and contains in f["title"])
    led = json.loads((run_dir / "findings.json").read_text())
    test_fp = next(f["id"] for f in led["findings"] if f["locations"][0].get("file") == "tests/test_login.py")
    idor, role, cpn, sqli = fid("idor"), fid("missing-authorization"), fid("business-logic"), fid("sql-injection")
    hall = fid("hardcoded-secret", "invented")

    print("\n# guardrail demonstrations (expected to be refused):")
    cli("findings", "set-status", run, idor, "--status", "confirmed_static", "--reviewer", "sentinel-verifier",
        "--basis", "consensus", "--rationale", "authz and static-code agents both agree this is real", ok=(3,))
    cli("findings", "set-status", run, idor, "--status", "confirmed_static", "--reviewer", "sentinel-authz",
        "--rationale", "I re-checked my own finding and it is real", ok=(3,))

    print("\n# independent verification (sentinel-verifier):")
    V = lambda i, *a: cli("findings", "set-status", run, i, "--reviewer", "sentinel-verifier", *a)
    V(idor, "--status", "confirmed_static", "--rationale",
      "get_invoice is reachable by any session (login_required only), selects by id alone and never compares owner_id; "
      "no before_request hook, middleware or DB policy in the snapshot adds an ownership check.")
    V(role, "--status", "confirmed_static", "--rationale",
      "delete_user carries only @login_required while promote_user adds @require_role('admin'); no global role check exists.")
    V(cpn, "--status", "strongly_supported", "--missing", "Database schema/triggers for coupons are not in the snapshot",
      "--rationale", "single_use is selected but never read; the total is re-discounted on every call. "
                     "Unproven: whether a DB trigger elsewhere limits redemptions.")
    V(sqli, "--status", "confirmed_static", "--basis", "dataflow", "--rationale",
      "Source request.args.get('q') (unauthenticated /search) flows into an f-string passed to db().execute with no binding.")
    V(hall, "--status", "false_positive", "--rationale",
      "Cited excerpt does not exist in app/auth.py; evidence failed snapshot verification (hallucinated candidate).")
    V(test_fp, "--status", "false_positive", "--rationale",
      "tests/test_login.py value is an explicit test-only dummy used by a placeholder assertion; not a deployed credential.")

    print("\n# severity (sentinel-severity):")
    C = lambda i, v, r: cli("findings", "set-cvss", run, i, "--vector", v, "--rationale", r)
    C(idor, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "Any account reads other users' invoices; no write impact.")
    C(role, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H", "Any account deletes arbitrary users.")
    C(sqli, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Unauthenticated read via SQLi; sqlite3 blocks stacked statements, so I/A not claimed.")
    C(cpn, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N", "Any account manipulates cart totals.")
    cli("financial", "set", run, cpn, "--file", str(run_dir / "candidates" / "fin-coupon.json"))
    cli("financial", "set", run, role, "--file", str(run_dir / "candidates" / "fin-rejected-tvl.json"), ok=(2,))

    print("\n# business impact (sentinel-business-impact):")
    cli("business", "context", run)
    B = lambda i, f, rev="sentinel-business-impact", ok=(0,): cli(
        "business", "set", run, i, "--reviewer", rev, "--file", str(run_dir / "candidates" / f), ok=ok)
    B(sqli, "business-sqli.json")
    B(idor, "business-idor.json")
    B(cpn, "business-keep-coupon.json")
    print("# business guardrails (expected to be refused):")
    B(role, "business-refused-undeclared.json", ok=(3,))          # undeclared data classes
    B(idor, "business-idor.json", rev="sentinel-authz", ok=(3,))   # author may not assess own finding
    unverified = next(f["id"] for f in cli("findings", "list", run)["findings"]
                      if f["status"] == "potential" and f["severity"] in ("high", "medium"))
    B(unverified, "business-idor.json", ok=(3,))                   # not independently verified

    print("\n# report (sentinel-report):")
    paths = cli("report", run)
    cli("log", "verify", run)
    print(json.dumps(paths, indent=2))
    return run_dir


if __name__ == "__main__":
    main()
