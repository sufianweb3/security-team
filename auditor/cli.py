"""`python -m auditor ...` — the only shell surface agents are allowed to use.

Every sub-command is read-only with respect to targets and writes only inside
audit-output/<assessment>/<run>/ (ingest writes immutable snapshots to targets/).
Output is JSON on stdout so agents can parse it reliably."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, audit_log, business, financial, risk
from .adapters import builtin
from .findings import Ledger
from .netguard import NetGuard
from .pipeline import Run, find_run_dir, run_all
from .policy import PolicyError, check_write_path, load_policy, require
from .redact import redact_obj
from .scope import load_scope


def _out(obj, code: int = 0):
    print(json.dumps(redact_obj(obj), indent=2, default=str))
    return code


def _read_json_in_run(run: Run, path: str) -> object:
    """Agents may only hand the CLI files they wrote inside the run directory."""
    p = Path(path)
    if not p.is_absolute():
        p = Path.cwd() / p
    p = p.resolve()
    if run.dir.resolve() not in p.parents:
        raise PolicyError("input file must live inside the run directory (e.g. <run>/candidates/<agent>.json)")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_scope(a):
    s = load_scope(a.scope)
    return _out({"valid": not s.errors, **s.summary()}, 0 if not s.errors else 2)


def cmd_ingest(a):
    s = load_scope(a.scope)
    run = Run(s)
    info = run.ingest()
    for tid in info:
        run.inventory_target(tid)
    run.save_state()
    return _out({"run": f"{s.assessment_id}/{run.rid}", "run_dir": str(run.dir), "targets": info,
                 "next": "dispatch agents with this run id"})


def cmd_run(a):
    return _out(run_all(a.scope))


def cmd_inventory(a):
    run = Run.load(a.run)
    tids = [a.target] if a.target else list(run._inventory) or [p.name for p in run.targets_base.iterdir() if p.is_dir()]
    res = {t: run.inventory_target(t) for t in tids}
    run.save_state()
    return _out(res)


def cmd_tools(a):
    run = Run.load(a.run)
    if a.action == "list":
        from .sandbox import find_tool
        return _out({t: bool(find_tool(t)) for t in load_policy()["tools"]["allowlist"]})
    tids = [a.target] if a.target else list(run._inventory)
    for t in tids:
        run.analyze_target(t)
    run.score()
    run.save_state()
    return _out({"coverage": run.coverage, "accepted": len(run.ledger.accepted())})


def cmd_fetch(a):
    run = Run.load(a.run)
    guard = NetGuard(run.scope, run.log_path)
    res = guard.get(a.url, method=a.method)
    run.http_dir.mkdir(exist_ok=True)
    obs = {"url": res.url, "final_url": res.final_url, "status": res.status, "headers": res.headers,
           "tls": res.tls, "observed_at": res.observed_at}
    name = f"obs-{abs(hash(a.url)) % 10**9}.json"
    (run.http_dir / name).write_text(json.dumps(obs, indent=2), encoding="utf-8")
    tid = f"web:{res.final_url.split('/')[2]}"
    for f in builtin.web_headers(obs, tid):
        run.ledger.add(f, run.targets_base, run.http_dir, actor="builtin-web")
    run.coverage["targets"].setdefault(tid, {"analyzed": True, "analyzers": []})
    if "builtin-web" not in run.coverage["targets"][tid]["analyzers"]:
        run.coverage["targets"][tid]["analyzers"].append("builtin-web")
    run.coverage["tools"]["builtin-web"] = {"tool": "builtin-web", "available": True}
    run.save_state()
    body_preview = res.body[:2000].decode("utf-8", "replace") if a.show_body else None
    return _out({"observation": obs, "file": name, "body_preview": body_preview})


def cmd_openapi(a):
    run = Run.load(a.run)
    findings, cov = builtin.openapi(run.targets_base / a.target, a.target, a.spec)
    for f in findings:
        run.ledger.add(f, run.targets_base, actor="builtin-openapi")
    run.coverage["tools"]["builtin-openapi"] = cov
    run.save_state()
    return _out({"added": len(findings), "coverage": cov})


def cmd_supplychain(a):
    run = Run.load(a.run)
    findings, cov = builtin.supply_chain(run.targets_base / a.target, a.target)
    for f in findings:
        run.ledger.add(f, run.targets_base, actor="builtin-supplychain")
    run.coverage["tools"]["builtin-supplychain"] = cov
    run.save_state()
    return _out({"added": len(findings)})


def cmd_findings(a):
    run = Run.load(a.run)
    L: Ledger = run.ledger
    if a.action == "add":
        data = _read_json_in_run(run, a.file)
        items = data if isinstance(data, list) else data.get("findings", [])
        cap = load_policy()["budgets"]["max_candidate_findings_per_agent"]
        results = []
        for f in items[:cap]:
            f.setdefault("source", {"kind": "agent", "name": a.agent})
            f["source"].update({"kind": "agent", "name": a.agent})
            if a.model:
                f["source"]["model"] = a.model
            ok, msg = L.add(f, run.targets_base, run.http_dir if run.http_dir.exists() else None, actor=a.agent)
            results.append({"title": f.get("title"), "accepted": ok, "result": msg})
        L.score_all(run.scope)
        run.save_state()
        audit_log.append(run.log_path, "findings.add", a.agent, {"count": len(items), "accepted": sum(r["accepted"] for r in results)})
        return _out({"results": results, "truncated": max(0, len(items) - cap)})
    if a.action == "list":
        rows = [{"id": f["id"], "zone": f.get("risk_zone"), "severity": f["severity"], "confidence": f["confidence"],
                 "status": f["verification"]["status"], "category": f["category"], "title": f["title"],
                 "source": f["source"].get("contributors") or [f["source"]["name"]]}
                for f in L.findings
                if (not a.status or f["verification"]["status"] == a.status) and (not a.zone or f.get("risk_zone") == a.zone)]
        return _out({"count": len(rows), "findings": rows, "rejected": len(L.rejected)})
    if a.action == "show":
        return _out(L.get(a.id))
    if a.action == "set-status":
        f = L.set_status(a.id, a.status, a.rationale, a.reviewer, basis=a.basis or [], missing=a.missing or [],
                         alternatives=a.alternative or [])
        L.score_all(run.scope)
        run.save_state()
        audit_log.append(run.log_path, "findings.status", a.reviewer, {"id": a.id, "status": a.status})
        return _out({"id": f["id"], "status": f["verification"]["status"], "zone": f.get("risk_zone"), "confidence": f["confidence"]})
    if a.action == "set-cvss":
        f = L.get(a.id)
        risk.parse_cvss31(a.vector)
        f["cvss"] = {"version": "3.1", "vector": a.vector, "rationale": a.rationale}
        L.score_all(run.scope)
        run.save_state()
        return _out({"id": f["id"], "severity": f["severity"], "cvss": f["cvss"], "zone": f.get("risk_zone")})
    raise PolicyError("unknown findings action")


def cmd_score(a):
    if a.cvss:
        s = risk.cvss31_base(a.cvss)
        return _out({"vector": a.cvss, "score": s, "severity": risk.severity_from_score(s)})
    run = Run.load(a.run)
    run.score()
    run.save_state()
    return _out({"accepted": len(run.ledger.accepted())})


def cmd_financial(a):
    if a.action == "check":
        est = json.loads(Path(a.file).read_text(encoding="utf-8"))
        try:
            return _out({"valid": True, "estimate": financial.validate(est)})
        except financial.FinancialError as exc:
            return _out({"valid": False, "error": str(exc), "fallback": financial.unknown(str(exc))}, 2)
    run = Run.load(a.run)
    est = _read_json_in_run(run, a.file)
    f = run.ledger.get(a.id)
    try:
        f["financial_exposure"] = financial.validate(est)
    except financial.FinancialError as exc:
        f["financial_exposure"] = financial.unknown(f"rejected estimate: {exc}")
        run.save_state()
        return _out({"accepted": False, "error": str(exc)}, 2)
    run.save_state()
    return _out({"accepted": True, "statement": f["financial_exposure"]["statement"]})


def cmd_business(a):
    run = Run.load(a.run)
    L: Ledger = run.ledger
    if a.action == "context":
        ctx = run.scope.business_context
        return _out({"business_context": ctx, "assessed": bool(ctx),
                     "note": None if ctx else "no business_context in scope; ask the user/program owner to add one"})
    if a.action == "show":
        items = [L.get(a.id)] if a.id else L.accepted()
        return _out({"items": [{"id": f["id"], "title": f["title"], "severity": f["severity"],
                                "status": f["verification"]["status"],
                                "business_impact": f.get("business_impact")} for f in items]})
    if a.action == "set":
        if not a.id or not a.reviewer or not a.file:
            raise PolicyError("business set needs <id> --reviewer <agent> --file <json in run dir>")
        f = L.get(a.id)
        review = _read_json_in_run(run, a.file)
        try:
            bi = business.set_review(f, review, a.reviewer, run.scope)
        except PolicyError as exc:
            audit_log.append(run.log_path, "business.set", a.reviewer, {"id": a.id, "error": str(exc)}, "deny")
            raise
        L.score_all(run.scope)
        run.save_state()
        audit_log.append(run.log_path, "business.set", a.reviewer,
                         {"id": a.id, "priority": bi.get("business_priority"), "adjustment": review.get("adjustment")})
        return _out({"id": a.id, "business_impact": f["business_impact"]})
    raise PolicyError("unknown business action")


def cmd_report(a):
    run = Run.load(a.run)
    run.score()
    run.save_state()
    return _out(run.report())


def cmd_status(a):
    run = Run.load(a.run)
    acc = run.ledger.accepted()
    return _out({"run": run.rid, "network_mode": run.scope.network_mode, "coverage": run.coverage,
                 "targets": list(run._inventory), "findings_total": len(run.ledger.findings),
                 "accepted": len(acc), "rejected": len(run.ledger.rejected),
                 "pending_verification": [f["id"] for f in acc if f["verification"]["status"] in ("potential", "unverified_hypothesis")
                                          and f["severity"] in ("critical", "high", "medium")]})


def cmd_log(a):
    d = find_run_dir(a.run)
    ok, msg = audit_log.verify(d / "audit-log.jsonl")
    return _out({"ok": ok, "message": msg}, 0 if ok else 2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m auditor", description="Sentinel read-only security auditor")
    p.add_argument("--version", action="version", version=__version__)
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("scope"); s.add_argument("action", choices=["validate"]); s.add_argument("scope"); s.set_defaults(fn=cmd_scope)
    s = sp.add_parser("ingest"); s.add_argument("scope"); s.set_defaults(fn=cmd_ingest)
    s = sp.add_parser("run"); s.add_argument("scope"); s.set_defaults(fn=cmd_run)
    s = sp.add_parser("inventory"); s.add_argument("run"); s.add_argument("--target"); s.set_defaults(fn=cmd_inventory)
    s = sp.add_parser("tools"); s.add_argument("action", choices=["run", "list"]); s.add_argument("run"); s.add_argument("--target"); s.set_defaults(fn=cmd_tools)
    s = sp.add_parser("fetch"); s.add_argument("run"); s.add_argument("url"); s.add_argument("--method", default="GET", choices=["GET", "HEAD"])
    s.add_argument("--show-body", action="store_true"); s.set_defaults(fn=cmd_fetch)
    s = sp.add_parser("openapi"); s.add_argument("run"); s.add_argument("--target", required=True); s.add_argument("--spec", required=True); s.set_defaults(fn=cmd_openapi)
    s = sp.add_parser("supplychain"); s.add_argument("run"); s.add_argument("--target", required=True); s.set_defaults(fn=cmd_supplychain)

    s = sp.add_parser("findings"); s.add_argument("action", choices=["add", "list", "show", "set-status", "set-cvss"]); s.add_argument("run")
    s.add_argument("id", nargs="?"); s.add_argument("--file"); s.add_argument("--agent", default="unknown-agent"); s.add_argument("--model")
    s.add_argument("--status"); s.add_argument("--zone"); s.add_argument("--reviewer"); s.add_argument("--rationale", default="")
    s.add_argument("--basis", action="append"); s.add_argument("--missing", action="append"); s.add_argument("--alternative", action="append")
    s.add_argument("--vector"); s.set_defaults(fn=cmd_findings)

    s = sp.add_parser("score"); s.add_argument("run", nargs="?"); s.add_argument("--cvss"); s.set_defaults(fn=cmd_score)
    s = sp.add_parser("financial"); s.add_argument("action", choices=["set", "check"]); s.add_argument("run", nargs="?")
    s.add_argument("id", nargs="?"); s.add_argument("--file", required=True); s.set_defaults(fn=cmd_financial)
    s = sp.add_parser("business"); s.add_argument("action", choices=["context", "show", "set"]); s.add_argument("run")
    s.add_argument("id", nargs="?"); s.add_argument("--reviewer"); s.add_argument("--file"); s.set_defaults(fn=cmd_business)
    s = sp.add_parser("report"); s.add_argument("run"); s.set_defaults(fn=cmd_report)
    s = sp.add_parser("bounty"); s.add_argument("run"); s.set_defaults(fn=cmd_report)
    s = sp.add_parser("status"); s.add_argument("run"); s.set_defaults(fn=cmd_status)
    s = sp.add_parser("log"); s.add_argument("action", choices=["verify"]); s.add_argument("run"); s.set_defaults(fn=cmd_log)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except PolicyError as exc:
        return _out({"error": "policy_denied", "reason": str(exc)}, 3)
    except (FileNotFoundError, json.JSONDecodeError, risk.CvssError) as exc:
        return _out({"error": type(exc).__name__, "reason": str(exc)}, 2)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
