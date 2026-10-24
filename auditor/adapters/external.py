"""Adapters for the allowlisted external tools: semgrep, bandit, gitleaks, osv-scanner."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ..policy import project_root
from ..sandbox import run_tool
from . import base_finding, read_lines

SEV_MAP_SEMGREP = {"ERROR": "medium", "WARNING": "low", "INFO": "informational"}
SEV_MAP_BANDIT = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
TESTISH = re.compile(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?|samples?|docs?|mock|testdata)(/|$)|_test\.|\.test\.|\.spec\.", re.I)
PLACEHOLDER = re.compile(r"(?i)(example|dummy|placeholder|changeme|xxxx|your[_-]?(api|secret)|<[^>]+>|redacted|test)")


def is_likely_placeholder(target_dir: Path, rel: str, start: int, end: int) -> bool:
    """Context triage on the RAW (unredacted) lines; the raw value never leaves this function."""
    if TESTISH.search(rel):
        return True
    try:
        lines = (target_dir / rel).read_text(encoding="utf-8", errors="ignore").splitlines()[start - 1:end]
    except OSError:
        return False
    return any(PLACEHOLDER.search(l) for l in lines)


def _coverage(tool: str, res, extra: dict | None = None) -> dict[str, Any]:
    return {"tool": tool, "available": res.available, "returncode": res.returncode,
            "seconds": res.seconds, **(extra or {}),
            "error": None if res.available and res.returncode in (0, 1) else (res.stderr[-400:] or None)}


# ---------------------------------------------------------------- semgrep
def semgrep(target_dir: Path, target_id: str, work: Path, log_path: Path) -> tuple[list, dict]:
    configs = [project_root() / "rules" / "semgrep"]
    extra_rules = os.environ.get("SEMGREP_RULES_DIR") or str(project_root() / "tools" / "semgrep-rules")
    if Path(extra_rules).is_dir():
        configs.append(Path(extra_rules))
    out = work / f"semgrep-{target_id}.json"
    args = ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
            "--timeout", "30", "--max-target-bytes", "2000000", "--no-git-ignore",
            "--x-ignore-semgrepignore-files",   # a target's .semgrepignore must not hide code (pinned semgrep 1.182.1)
            "--output", str(out)]
    for c in configs:
        args += ["--config", str(c)]
    args.append(".")
    res = run_tool("semgrep", args, cwd=target_dir, log_path=log_path)
    findings: list[dict] = []
    if res.available and out.exists():
        data = json.loads(out.read_text(encoding="utf-8") or "{}")
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {}) or {}
            cwe = meta.get("cwe")
            if isinstance(cwe, list):
                cwe = cwe[0] if cwe else None
            m = re.search(r"CWE-\d+", str(cwe or ""))
            rel = r["path"].lstrip("./")
            s, e = r["start"]["line"], r["end"]["line"]
            findings.append(base_finding(
                title=meta.get("title") or r["extra"].get("message", r["check_id"])[:120],
                category=meta.get("sentinel_category") or meta.get("category", "code-weakness"),
                cwe=m.group(0) if m else None, target_id=target_id, file=rel, start=s, end=e,
                excerpt=read_lines(target_dir, rel, s, e), tool="semgrep", rule_id=r["check_id"],
                description=r["extra"].get("message", ""),
                severity=meta.get("sentinel_severity") or SEV_MAP_SEMGREP.get(r["extra"].get("severity", "INFO"), "low"),
                impact=meta.get("impact", "Depends on reachability and attacker control of the input."),
                remediation=meta.get("fix", "See rule references."),
                references=[x for x in (meta.get("references") or []) if isinstance(x, str)]))
    return findings, _coverage("semgrep", res, {"rulesets": [str(c) for c in configs]})


# ---------------------------------------------------------------- bandit
def bandit(target_dir: Path, target_id: str, work: Path, log_path: Path) -> tuple[list, dict]:
    out = work / f"bandit-{target_id}.json"
    res = run_tool("bandit", ["-r", ".", "-f", "json", "-o", str(out), "-q",
                              "-s", "B101,B403,B404",  # assert / import-only noise
                              "-x", "./node_modules,./.venv,./venv"], cwd=target_dir, log_path=log_path)
    findings: list[dict] = []
    if res.available and out.exists():
        data = json.loads(out.read_text(encoding="utf-8") or "{}")
        for r in data.get("results", []):
            rel = r["filename"].lstrip("./")
            rng = r.get("line_range") or [r["line_number"]]
            cwe = r.get("issue_cwe", {}).get("id")
            category = _bandit_category(r["test_id"])
            sev = SEV_MAP_BANDIT.get(r["issue_severity"], "low")
            lims = None
            if category == "hardcoded-secret" and is_likely_placeholder(target_dir, rel, rng[0], rng[-1]):
                sev, lims = "low", ["Path/value looks like a test fixture, example or placeholder: likely false positive."]
            findings.append(base_finding(limitations=lims,
                title=f"{r['test_name'].replace('_', ' ')}: {r['issue_text'][:90]}",
                category=category, cwe=f"CWE-{cwe}" if cwe else None,
                target_id=target_id, file=rel, start=rng[0], end=rng[-1],
                excerpt=read_lines(target_dir, rel, rng[0], rng[-1]), tool="bandit", rule_id=r["test_id"],
                description=r["issue_text"], severity=sev,
                impact="See CWE; impact depends on reachability.",
                remediation=f"See {r.get('more_info', 'bandit documentation')}",
                references=[r.get("more_info")] if r.get("more_info") else []))
    return findings, _coverage("bandit", res)


def _bandit_category(test_id: str) -> str:
    return {"B608": "sql-injection", "B602": "command-injection", "B605": "command-injection",
            "B301": "deserialization", "B506": "deserialization", "B105": "hardcoded-secret",
            "B106": "hardcoded-secret", "B201": "debug-enabled", "B501": "tls-verification-disabled",
            "B324": "weak-crypto", "B104": "insecure-binding"}.get(test_id, "code-weakness")


# ---------------------------------------------------------------- gitleaks
def gitleaks(target_dir: Path, target_id: str, work: Path, log_path: Path) -> tuple[list, dict]:
    out = work / f"gitleaks-{target_id}.json"
    empty_ignore = work / "empty-gitleaksignore"
    empty_ignore.mkdir(exist_ok=True)
    res = run_tool("gitleaks", ["dir", ".", "--report-format", "json", "--report-path", str(out),
                                "--config", str(project_root() / "config" / "gitleaks.toml"),
                                "--gitleaks-ignore-path", str(empty_ignore),   # ignore target's .gitleaksignore
                                "--ignore-gitleaks-allow",                     # ignore inline gitleaks:allow
                                "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error"],
                   cwd=target_dir, log_path=log_path)
    findings: list[dict] = []
    if res.available and out.exists():
        for r in json.loads(out.read_text(encoding="utf-8") or "[]"):
            rel = r["File"].lstrip("./")
            excerpt = read_lines(target_dir, rel, r["StartLine"], r["EndLine"])
            likely_fp = is_likely_placeholder(target_dir, rel, r["StartLine"], r["EndLine"])
            findings.append(base_finding(
                title=f"Potential hardcoded credential ({r['RuleID']}) in {rel}",
                category="hardcoded-secret", cwe="CWE-798", target_id=target_id, file=rel,
                start=r["StartLine"], end=r["EndLine"], excerpt=excerpt, tool="gitleaks", rule_id=r["RuleID"],
                description=f"{r.get('Description', 'Secret pattern')} matched. The value was redacted and was NOT "
                            "validated, used or sent anywhere.",
                severity="low" if likely_fp else "high",
                impact="If the credential is real and active, an attacker with repository access could use it "
                       "to access the associated service.",
                remediation="Revoke/rotate the credential with its owner, remove it from source and history, "
                            "and load secrets from a secret manager or environment at runtime.",
                status="potential",
                limitations=["Liveness of the credential was deliberately NOT tested (policy).",
                             *(["Path/value looks like a test fixture, example or placeholder: likely false positive."] if likely_fp else [])],
                references=["https://cwe.mitre.org/data/definitions/798.html"]))
    return findings, _coverage("gitleaks", res)


# ---------------------------------------------------------------- osv-scanner
def osv(target_dir: Path, target_id: str, work: Path, log_path: Path, offline: bool = False) -> tuple[list, dict]:
    out = work / f"osv-{target_id}.json"
    args = ["scan", "source", "-r", ".", "--format", "json", "--output-file", str(out),
            "--no-resolve",                       # no transitive resolution via external registries
            "--no-call-analysis", "go", "--no-call-analysis", "rust",  # rust call analysis runs build scripts
            "--allow-no-lockfiles",
            "--no-ignore"]                        # a target's (or our) .gitignore must not hide manifests
    if offline:
        args.append("--offline-vulnerabilities")
    res = run_tool("osv-scanner", args, cwd=target_dir, log_path=log_path)
    findings: list[dict] = []
    if res.available and out.exists():
        data = json.loads(out.read_text(encoding="utf-8") or "{}")
        for result in data.get("results", []):
            src = (result.get("source") or {}).get("path", "")
            rel = os.path.relpath(src, str(target_dir)).replace("\\", "/") if os.path.isabs(src) else src.lstrip("./")
            for pkg in result.get("packages", []):
                info = pkg.get("package", {})
                vulns = pkg.get("vulnerabilities", [])
                if not vulns:
                    continue
                groups = pkg.get("groups") or [{"ids": [v["id"]]} for v in vulns]
                ids_all = sorted({i for g in groups for i in g.get("ids", [])} | {a for v in vulns for a in v.get("aliases", [])})
                cves = [i for i in ids_all if i.startswith("CVE-")] or ids_all
                best_vec, best_score = None, -1.0
                for v in vulns:
                    for sv in v.get("severity", []):
                        vec = str(sv.get("score", ""))
                        if sv.get("type") == "CVSS_V3" and vec.startswith("CVSS:3.1/"):
                            try:
                                from ..risk import cvss31_base
                                sc = cvss31_base(vec)
                            except Exception:
                                continue
                            if sc > best_score:
                                best_vec, best_score = vec, sc
                line = _find_line(target_dir / rel, info.get("name", ""))
                name, ver = info.get("name"), info.get("version")
                findings.append(base_finding(
                    title=f"{name} {ver} has {len(groups)} known vulnerabilit{'y' if len(groups) == 1 else 'ies'} ({', '.join(cves[:3])}{'…' if len(cves) > 3 else ''})",
                    category="vulnerable-dependency", cwe="CWE-1395", target_id=target_id, file=rel,
                    start=line, end=line, excerpt=read_lines(target_dir, rel, line, line) or f"{name}=={ver}",
                    evidence_kind="config_excerpt", tool="osv-scanner", rule_id=f"{info.get('ecosystem', '')}:{name}@{ver}",
                    description="; ".join((v.get("summary") or v["id"]) for v in vulns[:5])[:900],
                    severity="medium",
                    cvss={"version": "3.1", "vector": best_vec, "rationale": "Highest upstream advisory base vector "
                          "among the package's advisories; application reachability not assessed."} if best_vec else None,
                    impact="Depends on whether the application uses the vulnerable functionality.",
                    remediation=f"Upgrade {name} to a version that fixes all listed advisories; verify compatibility.",
                    references=[f"https://osv.dev/vulnerability/{i}" for i in cves[:5]],
                    limitations=["Version match only; reachability of vulnerable code not established.",
                                 "Upstream CVSS describes the library, not this application."]))
    return findings, _coverage("osv-scanner", res, {"offline": offline})


def _find_line(path: Path, name: str) -> int:
    try:
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if name and name.lower() in line.lower():
                return i
    except OSError:
        pass
    return 1
