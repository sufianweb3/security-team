# Sentinel Auditor — project guidance for Codex (AGENTS.md)

This project is a **read-only, evidence-driven security auditor**. Read `config/policy.yaml`
and `docs/THREAT_MODEL.md` before doing anything. The rules below are enforced by a policy
hook, the `auditor` CLI, and OS/container limits — not just by instructions.

## The one and only way to act
- The only shell command any agent may run is `python -m auditor <subcommand> ...`.
- The only network access is `python -m auditor fetch <run> <url>` (scope-gated, GET/HEAD).
- Writes are allowed only under `audit-output/`. Targets live read-only under `targets/`.
- `curl`, `wget`, `git`, `pip`, `npm`, raw shell, and web-fetch/search tools are blocked.
- Never run, build, install, or test target code. Never exploit anything. Fail closed.

## How a run works
1. Start the primary agent **sentinel-orchestrator** and give it a scope file (see `config/scopes/`).
2. It validates scope, ingests inputs to an immutable snapshot, runs the deterministic
   baseline (semgrep/bandit/gitleaks/osv-scanner + builtin analyzers), then dispatches
   specialists for the reasoning findings tools miss (authorization, business logic, data flow).
3. A **different** agent (`sentinel-verifier`) reviews each candidate and sets its status;
   nothing is "confirmed" on model agreement. `sentinel-severity` assigns CVSS/financials.
4. `sentinel-report` writes `report.json`, `report.md`, `report.html` and bounty drafts under
   the run directory, plus a hash-chained `audit-log.jsonl`.

You can always get a full deterministic (no-LLM) report with:
    python -m auditor run config/scopes/vulnapp-local.yaml

## Agents
- `sentinel-orchestrator` (strong) — Coordinate the assessment.
- `sentinel-recon` (cheap) — Inventory the snapshot and map the attack surface from passive artifacts only: languages, frameworks, entry points/routes, specs, IaC, CI, trust boundaries, and explicitly what could not be inspected.
- `sentinel-static-code` (strong) — Deep static analysis of source for injection, unsafe deserialization, path traversal, SSRF sinks, unsafe file handling, crypto misuse and insecure defaults.
- `sentinel-web-api` (cheap) — Review API specs, configs and (only if scope authorizes passive web) recorded HTTP observations: auth requirements, authorization assumptions, security headers, CORS, cookies, TLS posture, exposed metadata.
- `sentinel-deps` (cheap) — Dependency and supply-chain review: known-vulnerable versions (via osv-scanner output), risky lifecycle scripts, unpinned CI actions, unverified downloads.
- `sentinel-secrets` (cheap) — Review secret-detection output (gitleaks) in context.
- `sentinel-authz` (strong) — Authentication, session, and ACCESS-CONTROL analysis: missing/inconsistent authorization checks, broken object-level authorization (IDOR), tenant isolation, ownership checks, privilege boundaries.
- `sentinel-business-logic` (strong) — Business-logic and financial-flow flaws: quota/discount/coupon abuse, state-machine and approval gaps, ownership/transaction-ordering issues, and (statically) smart-contract logic such as reentrancy or checks-effects-interactions violations.
- `sentinel-verifier` (strong) — INDEPENDENT review of other agents' candidates.
- `sentinel-severity` (strong) — Assign defensible severity (CVSS v3.
- `sentinel-business-impact` (strong) — Judge how much each verified finding matters to THIS organization: which asset it hits, what data is at risk, whether it is production and internet-facing, and what the program's own severity table says.
- `sentinel-report` (cheap) — Assemble the final human + machine report and the bug-bounty drafts from the accepted findings.

## If you are unsure
Stop and report. Prefer offline analysis. Do not broaden scope, add tools, or weaken a
control to make a task succeed.
