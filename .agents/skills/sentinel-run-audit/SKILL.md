---
name: sentinel-run-audit
description: "Run a complete Sentinel read-only security audit end to end (scope check, ingest, deterministic baseline, specialist dispatch, independent verification, scoring, report). Use when the user asks to audit, assess, or review the security of an authorized target or to start the Sentinel flow."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Run a Sentinel audit

You are (or are driving) `sentinel-orchestrator`. Never skip a step; never broaden scope.

## 0. Preconditions
- A scope file exists (see `config/scopes/*.yaml`). If the user gave a target but no scope,
  draft one from `config/scopes/vulnapp-local.yaml`, set `authorization.status: unconfirmed`,
  and ASK the user to confirm authorization before setting it to `authorized`.
- Public != authorized. A bug bounty target needs the program policy URL/file in scope.

## 1. Validate
`python -m auditor scope validate <scope.yaml>` → stop on any error. Read `network_mode`:
`offline` means no live requests at all.

## 2. Ingest + baseline (no LLM needed)
```
python -m auditor ingest <scope.yaml>          # prints run id: <assessment>/<run>
python -m auditor tools run <run>              # semgrep, bandit, gitleaks, osv-scanner + builtins
python -m auditor status <run>                 # coverage + what is pending
```
If a tool is missing, continue; the report will state the coverage gap.

## 3. Dispatch specialists (parallel where independent)
Give each: the run id, target id(s), inventory path `<run_dir>/inventory/<target>.json`, and the
specific question. Typical split:
- `sentinel-recon` → surface map + gaps (always)
- `sentinel-static-code` → confirm/dismiss tool data-flow findings; multi-file flows
- `sentinel-authz` → missing/inconsistent authorization, IDOR, tenant isolation
- `sentinel-business-logic` → invariants (money, quotas, state machines, contracts)
- `sentinel-web-api` → specs; passive web only if `network_mode=passive_web`
- `sentinel-deps` → supply chain + reachability notes
- `sentinel-secrets` → triage gitleaks output (fixtures vs real)

## 4. Verify (different agent than the author)
For every medium+ candidate: task `sentinel-verifier` with the finding ids.

## 5. Score
Task `sentinel-severity` for CVSS vectors and financial exposure (or "cannot be quantified").

## 5b. Business impact
`python -m auditor business context <run>`. If the scope has `business_context`, task
`sentinel-business-impact` with the verified medium+ finding ids; it records a P1–P5 business
priority and submission recommendation (never changes severity/zone). If not, tell the user
business priority is "not assessed" and that adding asset tiers/data classes to the scope enables it.

## 6. Report
Task `sentinel-report` (or run `python -m auditor report <run>`), then
`python -m auditor log verify <run>`. Summarize to the user: overall zone, RED items,
coverage gaps, the P1/P2 business-priority items and their submission recommendation, and where report.md/report.json/report.html and bounty drafts live.

## Budget discipline
Stop dispatching when coverage is adequate; precision beats volume. Max ~60 candidates per agent.
