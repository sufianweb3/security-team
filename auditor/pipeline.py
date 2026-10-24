"""Deterministic (LLM-free) end-to-end pipeline. Also the set of building blocks
the agents call one step at a time. Running `python -m auditor run <scope>`
produces a complete report with zero model calls, which is the baseline the
agent-driven runs must not regress below."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import audit_log
from .adapters import builtin, external
from .findings import Ledger
from .ingest import ingest_all
from .inventory import inventory, write_inventory
from .netguard import NetGuard
from .policy import PolicyError, load_policy, output_root, safe_output_path, targets_root
from .report import build as build_report
from .report import write_all
from .scope import Scope, load_scope, require_valid


def run_id(scope: Scope) -> str:
    import secrets
    return f"{scope.assessment_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(2)}"


def run_dir_for(scope: Scope, rid: str | None = None) -> Path:
    rid = rid or run_id(scope)
    d = safe_output_path(scope.assessment_id, rid)
    d.mkdir(parents=True, exist_ok=True)
    return d


class Run:
    """A single assessment run. Holds the scope, the run directory, the audit log,
    the finding ledger and coverage. Agents operate through this object's methods."""

    def __init__(self, scope: Scope, rid: str | None = None):
        self.scope = require_valid(scope)
        self.policy = load_policy()
        self.rid = rid or run_id(scope)
        self.dir = run_dir_for(scope, self.rid)
        self.work = self.dir / "work"
        self.work.mkdir(exist_ok=True)
        self.log_path = self.dir / "audit-log.jsonl"
        self.http_dir = self.dir / "observations"
        self.ledger = Ledger(self.dir / "findings.json")
        self.targets_base = targets_root() / scope.assessment_id
        self.coverage: dict[str, Any] = {"tools": {}, "targets": {}}
        self._inventory: dict[str, dict] = {}
        state = self.dir / "state.json"
        if state.exists():
            st = json.loads(state.read_text(encoding="utf-8"))
            self.coverage = st.get("coverage", self.coverage)
            self._inventory = st.get("inventory", {})
        else:
            audit_log.append(self.log_path, "run.start", "orchestrator",
                             {"run_id": self.rid, "scope": scope.summary()}, "allow")
            self.save_state()

    def save_state(self) -> None:
        st = {"run_id": self.rid, "scope_path": str(self.scope.path) if self.scope.path else None,
              "coverage": self.coverage, "inventory": self._inventory}
        (self.dir / "state.json").write_text(json.dumps(st, indent=2), encoding="utf-8")
        self.ledger.save()

    @classmethod
    def load(cls, ref: str) -> "Run":
        d = find_run_dir(ref)
        st = json.loads((d / "state.json").read_text(encoding="utf-8"))
        if not st.get("scope_path"):
            raise PolicyError("run has no scope path recorded")
        return cls(load_scope(st["scope_path"]), rid=st["run_id"])

    # -- steps -------------------------------------------------------------
    def ingest(self) -> dict[str, Any]:
        info = ingest_all(self.scope, self.log_path)
        (self.dir / "ingest.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
        return info

    def inventory_target(self, target_id: str) -> dict[str, Any]:
        tdir = self.targets_base / target_id
        inv = inventory(tdir, target_id)
        write_inventory(inv, self.dir / "inventory" / f"{target_id}.json")
        self._inventory[target_id] = inv
        return inv

    def _mark(self, target_id: str, analyzer: str) -> None:
        t = self.coverage["targets"].setdefault(target_id, {"analyzed": True, "analyzers": []})
        if analyzer not in t["analyzers"]:
            t["analyzers"].append(analyzer)

    def analyze_target(self, target_id: str) -> None:
        """Run every applicable deterministic analyzer over one ingested target."""
        tdir = self.targets_base / target_id
        if not tdir.is_dir():
            raise PolicyError(f"target {target_id} not ingested")
        inv = self._inventory.get(target_id) or self.inventory_target(target_id)
        analyzers = [
            ("semgrep", lambda: external.semgrep(tdir, target_id, self.work, self.log_path), bool(inv["languages"])),
            ("bandit", lambda: external.bandit(tdir, target_id, self.work, self.log_path), "python" in inv["languages"]),
            ("gitleaks", lambda: external.gitleaks(tdir, target_id, self.work, self.log_path), True),
            ("osv-scanner", lambda: external.osv(tdir, target_id, self.work, self.log_path), bool(inv["manifests"])),
            ("builtin-supplychain", lambda: builtin.supply_chain(tdir, target_id), True),
        ]
        gitleaks_ok = True
        for name, fn, applies in analyzers:
            if not applies:
                continue
            findings, cov = fn()
            self.coverage["tools"][name] = {**self.coverage["tools"].get(name, {}), **cov}
            if name == "gitleaks" and not cov.get("available"):
                gitleaks_ok = False
            if cov.get("available"):
                self._mark(target_id, name)
            self._ingest_findings(findings, actor=name)
        if not gitleaks_ok:  # fallback secret scan only if gitleaks is missing
            findings, cov = builtin.secrets_builtin(tdir, target_id)
            self.coverage["tools"]["builtin-secrets"] = cov
            self._mark(target_id, "builtin-secrets")
            self._ingest_findings(findings, actor="builtin-secrets")
        for spec in inv["api_specs"]:
            findings, cov = builtin.openapi(tdir, target_id, spec)
            self.coverage["tools"]["builtin-openapi"] = cov
            self._mark(target_id, "builtin-openapi")
            self._ingest_findings(findings, actor="builtin-openapi")

    def analyze_web(self) -> None:
        if self.scope.network_mode != "passive_web":
            return
        guard = NetGuard(self.scope, self.log_path)
        self.http_dir.mkdir(exist_ok=True)
        self.coverage["tools"]["builtin-web"] = {"tool": "builtin-web", "available": True}
        seen = set()
        urls = list(self.scope.web.get("seed_urls") or [])
        for host in self.scope.web.get("allowed_hosts") or []:
            if not host.startswith("*"):
                urls.append(f"https://{host}/")
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            try:
                res = guard.get(url)
            except PolicyError as exc:
                audit_log.append(self.log_path, "web.skip", "orchestrator", {"url": url, "reason": str(exc)}, "deny")
                continue
            obs = {"url": res.url, "final_url": res.final_url, "status": res.status,
                   "headers": res.headers, "tls": res.tls, "observed_at": res.observed_at}
            (self.http_dir / f"obs-{abs(hash(url)) % 10**9}.json").write_text(json.dumps(obs, indent=2), encoding="utf-8")
            tid = f"web:{res.final_url.split('/')[2]}"
            self._mark(tid, "builtin-web")
            self._ingest_findings(builtin.web_headers(obs, tid), actor="builtin-web")

    def _ingest_findings(self, findings: list[dict], actor: str) -> None:
        cap = self.policy["budgets"]["max_candidate_findings_per_agent"]
        # Tool output order can vary (gitleaks reports overlapping secrets in arbitrary
        # order). Sort before ingestion so merging picks the same canonical finding on
        # every run and finding ids stay stable.
        def _sort_key(f: dict) -> tuple:
            loc = (f.get("locations") or [{}])[0]
            return (loc.get("file") or "", loc.get("start_line") or 0,
                    loc.get("end_line") or 0, f.get("source", {}).get("rule_id") or "",
                    f.get("title") or "")
        for f in sorted(findings, key=_sort_key)[:cap]:
            if self.scope.category_excluded(f.get("category", "")):
                continue
            self.ledger.add(f, self.targets_base, self.http_dir if self.http_dir.exists() else None, actor=actor)

    def score(self) -> None:
        self.ledger.score_all(self.scope)
        self.ledger.save()

    def report(self) -> dict[str, str]:
        merged_inv: dict[str, Any] = {"languages": {}, "frameworks": [], "manifests": [], "api_specs": []}
        for inv in self._inventory.values():
            for k in ("frameworks", "manifests", "api_specs"):
                merged_inv[k] = sorted(set(merged_inv[k]) | set(inv.get(k, [])))
            for lang, n in inv.get("languages", {}).items():
                merged_inv["languages"][lang] = merged_inv["languages"].get(lang, 0) + n
        report = build_report(self.scope, self.ledger, self.coverage, merged_inv)
        paths = write_all(self.dir, report)
        audit_log.append(self.log_path, "run.report", "orchestrator",
                         {"overall": report["summary"]["overall_zone"], "findings": len(report["findings"])}, "allow")
        ok, msg = audit_log.verify(self.log_path)
        (self.dir / "audit-log.verify.txt").write_text(f"{ok}: {msg}\n", encoding="utf-8")
        return paths


def find_run_dir(ref: str) -> Path:
    base = output_root()
    ref = ref.strip().replace("\\", "/")
    if ".." in ref.split("/"):
        raise PolicyError("illegal run reference")
    cands = [base / ref] if "/" in ref else list(base.glob(f"*/{ref}"))
    cands = [c for c in cands if (c / "state.json").exists()]
    if len(cands) != 1:
        raise PolicyError(f"run {ref!r} not found (or ambiguous)")
    return cands[0]


def run_all(scope_path: str) -> dict[str, Any]:
    """Full deterministic pipeline: ingest -> inventory -> analyze -> score -> report."""
    scope = load_scope(scope_path)
    run = Run(scope)
    info = run.ingest()
    for tid in info:
        run.inventory_target(tid)
        run.analyze_target(tid)
    run.analyze_web()
    run.score()
    run.save_state()
    paths = run.report()
    return {"run_id": run.rid, "run_dir": str(run.dir), "reports": paths,
            "findings": len(run.ledger.accepted()), "log": str(run.log_path)}
