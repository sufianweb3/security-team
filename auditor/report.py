"""Report generation: JSON (machine), Markdown (human), HTML (trusted local
template, fully escaped, no external assets), and bug-bounty drafts.
Writes ONLY under the run directory inside output_dir."""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__, business, financial, risk
from .audit_log import utcnow
from .policy import check_write_path, require
from .redact import redact, redact_obj

DISCLAIMER = (
    "This assessment is limited to the inputs, scope, tools and analysis methods listed in this report. "
    "It was performed in read-only mode: nothing was exploited, no payloads were sent, and no target state "
    "was changed. A GREEN result means no material issue was identified in the assessed component within "
    "that coverage; it does NOT mean the system is secure. Findings marked potential or unverified require "
    "safe manual verification. Financial figures, where present, are potential exposure estimates, not "
    "actual losses and not bounty predictions."
)

ZONE_ICON = {"RED": "🔴 RED", "YELLOW": "🟡 YELLOW", "GREEN": "🟢 GREEN", "NOT_ASSESSED": "⚪ NOT ASSESSED"}


def _bp_rank(f: dict[str, Any]) -> int:
    bp = (f.get("business_impact") or {}).get("business_priority")
    return int(bp[1]) if bp else 9


def build(scope, ledger, coverage: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    accepted = ledger.accepted()
    for f in accepted:
        fe = f.get("financial_exposure")
        f["financial_exposure"] = financial.validate(fe) if fe else financial.unknown("no estimate supplied")
        f["business_impact"] = business.assess(f, scope)
    accepted.sort(key=lambda f: (["RED", "YELLOW", "GREEN"].index(f["risk_zone"]),
                                 _bp_rank(f), -risk.SEV_ORDER.index(f["severity"]), f["id"]))
    excluded = [{"id": f["id"], "title": f["title"], "status": f["verification"]["status"],
                 "rationale": f["verification"].get("rationale", "")}
                for f in ledger.findings if f["verification"]["status"] in risk.EXCLUDED_STATUSES]
    components = []
    covered_targets = {t for t, c in coverage.get("targets", {}).items() if c.get("analyzed")}
    for tid in sorted(set(coverage.get("targets", {})) | {f.get("target_id") for f in accepted if f.get("target_id")}):
        fs = [f for f in accepted if f.get("target_id") == tid]
        components.append({
            "name": tid,
            "zone": risk.component_zone(fs, tid in covered_targets),
            "covered_by": coverage.get("targets", {}).get(tid, {}).get("analyzers", []),
            "finding_ids": [f["id"] for f in fs],
        })
    zones = [c["zone"] for c in components]
    overall = "RED" if "RED" in zones else "YELLOW" if "YELLOW" in zones else \
        "GREEN" if zones and all(z == "GREEN" for z in zones) else "NOT_ASSESSED"
    limitations = [
        "Static and passive analysis only; no dynamic testing or exploitation was performed.",
        "Reachability of vulnerable dependencies was not established unless stated per finding.",
        "LLM-assisted findings were only accepted when their evidence matched the immutable snapshot.",
    ]
    for tool, cov in coverage.get("tools", {}).items():
        if not cov.get("available"):
            limitations.append(f"{tool} was not available: its analysis class is NOT covered in this run.")
        elif cov.get("error"):
            limitations.append(f"{tool} reported an error; its coverage may be partial: {str(cov['error'])[:160]}")
    if scope.network_mode == "offline":
        limitations.append("Run was offline: no live web/API observations were made.")
    ctx = scope.business_context
    if not ctx:
        limitations.append("No business_context in scope: business priority was NOT assessed; findings are ranked by technical severity only.")
    elif ctx.get("source", "unknown") == "unknown":
        limitations.append("business_context.source is 'unknown': business priorities could only be lowered, never raised.")
    report = {
        "report_version": "1.0",
        "generated_at": utcnow(),
        "tool_version": __version__,
        "assessment": {"id": scope.assessment_id, "name": scope.raw["assessment"]["name"],
                       "types": scope.raw["assessment"]["type"]},
        "scope_summary": scope.summary(),
        "disclaimer": DISCLAIMER,
        "summary": {
            "overall_zone": overall,
            "counts_by_zone": dict(Counter(f["risk_zone"] for f in accepted)),
            "counts_by_severity": dict(Counter(f["severity"] for f in accepted)),
            "counts_by_verification": dict(Counter(f["verification"]["status"] for f in accepted)),
            "counts_by_business_priority": dict(Counter((f.get("business_impact") or {}).get("business_priority") or "not_assessed"
                                                        for f in accepted)),
            "business_context_source": (ctx or {}).get("source") if ctx else "none",
        },
        "components": components,
        "findings": accepted,
        "excluded_findings": excluded,
        "rejected_candidates": ledger.rejected,
        "coverage": coverage,
        "inventory_summary": {k: inventory.get(k) for k in ("languages", "frameworks", "manifests", "api_specs")} if inventory else {},
        "limitations": limitations,
        "bug_bounty": bounty_section(scope, accepted),
    }
    return redact_obj(report)


def bounty_section(scope, findings: list[dict]) -> dict[str, Any] | None:
    auth = scope.raw.get("authorization", {})
    if auth.get("basis") != "bug_bounty_program":
        return None
    prog = auth.get("program") or {}
    items = []
    for f in findings:
        if f["risk_zone"] == "GREEN":
            continue
        excluded = scope.category_excluded(f["category"])
        missing = []
        if f["verification"]["status"] not in risk.STRONG_STATUSES:
            missing.append("Independent evidence that the issue is real (currently potential/unverified).")
        if not f.get("cvss"):
            missing.append("A defensible CVSS vector.")
        if "reachab" in " ".join(f.get("limitations", [])).lower():
            missing.append("Evidence the vulnerable path is reachable in production.")
        missing.append("Program reviewers usually require reproduction on the in-scope asset; obtain it only "
                       "through methods the program explicitly permits, manually, outside this tool.")
        bi = f.get("business_impact") or {}
        items.append({
            "finding_id": f["id"],
            "business_priority": bi.get("business_priority"),
            "program_expected_rating": (bi.get("program_expected_rating") or {}).get("rating"),
            "recommendation": (bi.get("submission_recommendation") or {}).get("decision"),
            "program_status": "excluded_category" if excluded else "in_scope_category_unconfirmed",
            "technical_validity": f["verification"]["status"],
            "why_it_might_qualify": f"{f['severity']} {f['category']} with {f['confidence']} confidence evidence."
                                    if not excluded else "Category is listed as excluded by the program.",
            "missing_evidence": missing,
            "duplicate_check": "Not performed: no reliable disclosed-issues dataset supplied."
                               if not prog.get("known_issues_file") else "See known_issues_file comparison.",
            "eligibility_claim": "none — eligibility and uniqueness are decided by the program, not this tool",
            "reward_estimate": "none — rewards are never predicted",
        })
    return {"program": prog.get("name"), "policy": prog.get("policy_url") or prog.get("policy_file"),
            "submission_mode": "manual only (no automatic submission)", "items": items}


# ---------------------------------------------------------------- writers
def _write(path: Path, text: str) -> None:
    require(check_write_path(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def to_markdown(r: dict[str, Any]) -> str:
    L = []
    a = r["assessment"]
    L += [f"# Security Assessment Report — {a['name']}", "",
          f"*Assessment ID:* `{a['id']}` · *Generated:* {r['generated_at']} · *Tool:* sentinel-auditor {r.get('tool_version','')}",
          "", f"> **Read-only assessment.** {r['disclaimer']}", "",
          "## Executive summary", "",
          f"**Overall zone: {ZONE_ICON[r['summary']['overall_zone']]}**", "",
          "| Zone | Count |", "|---|---|"]
    for z in ("RED", "YELLOW", "GREEN"):
        L.append(f"| {ZONE_ICON[z]} | {r['summary']['counts_by_zone'].get(z, 0)} |")
    L += ["", "| Severity | Count |", "|---|---|"]
    for s in reversed(risk.SEV_ORDER):
        L.append(f"| {s} | {r['summary']['counts_by_severity'].get(s, 0)} |")
    L += ["", "| Business priority | Count |", "|---|---|"]
    for bp in ("P1", "P2", "P3", "P4", "P5", "not_assessed"):
        n = r['summary'].get('counts_by_business_priority', {}).get(bp, 0)
        if n:
            L.append(f"| {bp} | {n} |")
    L += ["", "Zone, severity, confidence, verification status, business priority and financial exposure are independent dimensions. "
          "Business priority (P1 highest) says how much a finding matters to this organization given the asset and data "
          f"context in scope (source: {r['summary'].get('business_context_source')}); it never changes technical severity or zone.", "",
          "## Scope", "", f"- Authorized: **{r['scope_summary']['authorized']}**",
          f"- Network mode: **{r['scope_summary']['network_mode']}**",
          f"- Assessment types: {', '.join(a.get('types') or [])}", "",
          "## Components", "", "| Component | Zone | Analyzers | Findings |", "|---|---|---|---|"]
    for c in r["components"]:
        L.append(f"| {c['name']} | {ZONE_ICON[c['zone']]} | {', '.join(c['covered_by']) or '—'} | {len(c.get('finding_ids', []))} |")
    L += ["", "## Findings", ""]
    if not r["findings"]:
        L.append("No material issues were identified within the stated coverage. This is not a statement that the system is secure.")
    for f in r["findings"]:
        L += [f"### {f['id']} — {f['title']}", "",
              f"| Zone | Severity | Confidence | Verification | Business priority | CWE |", "|---|---|---|---|---|---|",
              f"| {ZONE_ICON[f['risk_zone']]} | {f['severity']}" + (f" (CVSS {f['cvss']['score']})" if f.get('cvss') and f['cvss'].get('score') is not None else "")
              + f" | {f['confidence']} | {f['verification']['status']} | {(f.get('business_impact') or {}).get('business_priority') or 'not assessed'} | {f.get('cwe') or '—'} |", "",
              f"**Component:** `{f['component']}` · **Category:** {f['category']} · **Source:** {f['source']['kind']}:{', '.join(f['source'].get('contributors') or [f['source']['name']])}", ""]
        locs = []
        for loc in f["locations"]:
            if loc.get("file"):
                locs.append(f"`{loc['file']}:{loc.get('start_line')}-{loc.get('end_line', loc.get('start_line'))}`" + (f" ({loc['role']})" if loc.get("role") else ""))
            elif loc.get("url"):
                locs.append(f"`{loc['url']}` observed {loc.get('observed_at', '')}")
        L += ["**Location(s):** " + ", ".join(locs), "", f"**Description.** {f['description']}", ""]
        for ev in f["evidence"][:3]:
            mark = "✅ verified against snapshot" if ev.get("verified") else "⚠️ not machine-verified"
            L += [f"Evidence ({ev['kind']}, {mark}):", "", "```", ev["content"][:1200], "```", ""]
        L += [f"**Preconditions.** " + ("; ".join(f["preconditions"]) or "—"),
              f"**Plausible scenario (not executed).** {f['attack_scenario']}",
              f"**Expected boundary vs observed.** {f['expected_boundary']} — *Observed:* {f['observed_behavior']}",
              f"**Technical impact.** {f['technical_impact']}",
              f"**Safe validation.** {f['safe_validation']}",
              f"**Remediation.** {f['remediation']}",
              f"**Financial exposure.** {f['financial_exposure'].get('statement')}", ""]
        L += _business_md(f.get("business_impact") or {})
        if f["verification"].get("rationale"):
            L.append(f"**Verifier rationale.** {f['verification']['rationale']}")
        if f.get("limitations"):
            L.append("**Limitations.** " + " ".join(f["limitations"]))
        if f.get("references"):
            L.append("**References.** " + ", ".join(f["references"][:6]))
        L.append("")
    L += ["## Coverage", "", "| Tool / analyzer | Available | Notes |", "|---|---|---|"]
    for tool, cov in r["coverage"].get("tools", {}).items():
        L.append(f"| {tool} | {'yes' if cov.get('available') else 'NO'} | {redact(str(cov.get('error') or ''))[:120]} |")
    L += ["", "## Limitations", ""] + [f"- {x}" for x in r["limitations"]]
    if r["excluded_findings"]:
        L += ["", "## Excluded (false positive / not applicable)", ""]
        L += [f"- {x['id']} {x['title']} — {x['status']}: {x['rationale']}" for x in r["excluded_findings"]]
    if r.get("rejected_candidates"):
        L += ["", f"## Rejected candidates ({len(r['rejected_candidates'])})", "",
              "Candidates whose evidence could not be matched to the snapshot or that failed the schema:", ""]
        L += [f"- {x.get('title')}: {'; '.join(x.get('reasons', []))[:200]}" for x in r["rejected_candidates"][:50]]
    if r.get("bug_bounty"):
        b = r["bug_bounty"]
        L += ["", "## Bug bounty notes", "", f"Program: {b.get('program')} · Policy: {b.get('policy')} · Submission: {b['submission_mode']}", ""]
        for it in b["items"]:
            L += [f"- **{it['finding_id']}** — {it['program_status']}; validity: {it['technical_validity']}. "
                  f"Missing: {' '.join(it['missing_evidence'])} Eligibility: {it['eligibility_claim']}."]
    return "\n".join(L) + "\n"


def _business_md(bi: dict[str, Any]) -> list[str]:
    if not bi or bi.get("status") == "not_assessed":
        return ["**Business impact.** Not assessed (no business context in scope). "
                f"Submission: {(bi.get('submission_recommendation') or {}).get('decision', 'manual_review')}.", ""]
    out = [f"**Business impact.** {bi.get('business_priority')} (technical {bi.get('technical_priority')}) · "
           f"asset `{bi.get('asset_id') or 'unmapped'}` ({bi.get('asset_criticality') or '—'} tier, {bi.get('asset_environment') or 'unknown'}) · "
           f"data at risk: {', '.join(bi.get('data_classes_at_risk') or []) or '—'} · context: {bi.get('context_source')}"]
    pr = bi.get("program_expected_rating")
    if pr:
        out.append(f"Program's own rating for this category: **{pr['rating']}** ({pr['scale']}, matched on `{pr['matched_on']}`).")
    if bi.get("business_scenario"):
        out.append(f"Business scenario (not executed): {bi['business_scenario']}")
    for n in bi.get("notes") or []:
        out.append(f"- {n}")
    sub = bi.get("submission_recommendation") or {}
    out += [f"**Submission recommendation:** `{sub.get('decision')}` — {sub.get('why')}", ""]
    return out


def to_html(r: dict[str, Any], md: str) -> str:
    e = html.escape
    colors = {"RED": "#c62828", "YELLOW": "#f9a825", "GREEN": "#2e7d32", "NOT_ASSESSED": "#757575"}
    rows = "".join(
        f"<tr><td>{e(f['id'])}</td><td><span class='z' style='background:{colors[f['risk_zone']]}'>{e(f['risk_zone'])}</span></td>"
        f"<td>{e(f['severity'])}</td><td>{e(f['confidence'])}</td><td>{e(f['verification']['status'])}</td><td>{e((f.get('business_impact') or {}).get('business_priority') or '—')}</td><td>{e(f['title'])}</td></tr>"
        for f in r["findings"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{e(r['assessment']['name'])} — Security Assessment</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.4rem;text-align:left;vertical-align:top}}
.z{{color:#fff;padding:.1rem .5rem;border-radius:.3rem;font-weight:600}}pre{{white-space:pre-wrap;background:#f6f8fa;padding:1rem}}
.disc{{background:#fff8e1;border-left:4px solid #f9a825;padding:.8rem}}</style></head><body>
<h1>{e(r['assessment']['name'])}</h1><p class="disc">{e(r['disclaimer'])}</p>
<h2>Overall: <span class="z" style="background:{colors[r['summary']['overall_zone']]}">{e(r['summary']['overall_zone'])}</span></h2>
<table><tr><th>ID</th><th>Zone</th><th>Severity</th><th>Confidence</th><th>Verification</th><th>Business</th><th>Title</th></tr>{rows}</table>
<h2>Full report (Markdown source)</h2><pre>{e(md)}</pre></body></html>"""


def bounty_drafts(r: dict[str, Any]) -> dict[str, str]:
    drafts = {}
    for f in r["findings"]:
        if f["risk_zone"] == "GREEN":
            continue
        locs = ", ".join(f"{l.get('file') or l.get('url')}:{l.get('start_line', '')}" for l in f["locations"])
        drafts[f["id"]] = "\n".join([
            f"# {f['title']}", "",
            "> Draft for MANUAL review and submission. Verify every statement yourself; this tool does not submit, "
            "does not predict eligibility or rewards, and did not test the live asset.", "",
            f"**Weakness:** {f.get('cwe') or f['category']}  ",
            f"**Severity (tool assessment):** {f['severity']}" + (f" — CVSS {f['cvss']['vector']}" if f.get('cvss') and f['cvss'].get('vector') else ""), "",
            f"**Verification status:** {f['verification']['status']} ({f['confidence']} confidence)", "",
            f"**Business priority (tool assessment):** {(f.get('business_impact') or {}).get('business_priority') or 'not assessed'}"
            + (f" — program's own rating for this category: {(f['business_impact'].get('program_expected_rating') or {}).get('rating')}"
               if (f.get('business_impact') or {}).get('program_expected_rating') else ""), "",
            f"**Tool recommendation:** {((f.get('business_impact') or {}).get('submission_recommendation') or {}).get('decision', 'manual_review')} "
            "(you decide; the program decides eligibility)", "",
            "## Summary", f["description"], "",
            "## Affected component", f"{f['component']} — {locs}", "",
            "## Evidence", "```", f["evidence"][0]["content"][:1500], "```", "",
            "## Impact", f["technical_impact"], "",
            "## Safe reproduction outline (no live exploitation)",
            f"1. Obtain the referenced source at the pinned revision and open {locs}.",
            "2. Trace the data/authorization flow described above through the cited lines.",
            f"3. {f['safe_validation']}",
            "4. If the program explicitly permits it, the program's own test accounts/environment are the only place a "
            "dynamic confirmation should ever be attempted — manually and within its rules.", "",
            "## Suggested remediation", f["remediation"], "",
            "## Limitations", *[f"- {x}" for x in f.get("limitations", [])],
        ]) + "\n"
    return drafts


def write_all(run_dir: Path, report: dict[str, Any]) -> dict[str, str]:
    md = to_markdown(report)
    paths = {"json": run_dir / "report.json", "md": run_dir / "report.md", "html": run_dir / "report.html"}
    _write(paths["json"], json.dumps(report, indent=2, ensure_ascii=False))
    _write(paths["md"], md)
    _write(paths["html"], to_html(report, md))
    for fid, text in bounty_drafts(report).items():
        p = run_dir / "bounty" / f"{fid}.md"
        _write(p, text)
    return {k: str(v) for k, v in paths.items()}
