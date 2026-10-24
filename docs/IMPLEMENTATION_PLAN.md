# Phased implementation plan — status

| Phase | Deliverables | Acceptance criteria | Status |
|---|---|---|---|
| 1 Environment & research | Verified harness docs, tool versions, model ids | Every format/flag used is from official docs or `--help` of the pinned binary | ✅ done (RESOURCES.md, ADR-001) |
| 2 Architecture | ARCHITECTURE, THREAT_MODEL, PERMISSION_MATRIX, ADR | Trust boundaries and controls mapped to code | ✅ |
| 3 Secure foundation | policy.py, scope.py, ingest.py, netguard.py, sandbox.py, hook | Out-of-scope/redirect/SSRF/method/budget/write/command tests pass without LLM | ✅ tests: test_policy_paths, test_scope, test_netguard, test_hook |
| 4 Deterministic tools | semgrep/bandit/gitleaks/osv adapters, builtin checks, evidence | Ground-truth deterministic issues found; missing tools degrade gracefully | ✅ test_pipeline_e2e (runs with and without tools) |
| 5 Agents & coordinator | agents.yaml (12 agents), 16 skills, rendered configs for 3 harnesses | Configs parse; least privilege asserted; in sync | ✅ structurally (test_harness_and_static_guards); ⚠️ not run inside harnesses |
| 6 Scoring | risk.py, financial.py, dedup, verification rules | CVSS vectors match spec values; zones per rules; bad estimates rejected | ✅ test_risk_financial, test_findings_quality |
| 7 Reporting & bounty | report.py JSON/MD/HTML, bounty drafts | Schema-valid JSON, disclaimers, redaction, outputs only in run dir | ✅ |
| 8 Tests & hardening | 135 tests, adversarial fixture | All pass with and without external tools | ✅ (TEST_RESULTS.md) |
| 9 Docs | Setup, Windows, model strategy, limitations | Reproducible from a clean clone | ✅ |

## Next (v0.3 candidates)
1. Run the generated configs inside each harness and fix any schema drift (highest priority).
2. Pin resolved IPs into HTTPS connections (close the DNS-rebinding window).
3. zizmor adapter for GitHub Actions; optional pinned Slither on precompiled artifacts.
4. Go call-graph reachability via osv-scanner (`--call-analysis=go` does not run build scripts).
5. CVSS 4.0 scoring; EPSS/KEV enrichment from a pinned offline snapshot.
6. Optional MCP server exposing the CLI as typed tools (once each harness's hooks cover MCP calls).
