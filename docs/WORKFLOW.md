# Audit workflow (sequence)

```
User            Orchestrator              Specialists                     auditor CLI / engine
 │ "audit X"        │                          │                                   │
 │────────────────► │ scope validate ─────────────────────────────────────────────►│ schema + semantics; offline if unclear
 │ (confirm auth) ◄─│ if status != authorized: ask user, stay offline              │
 │                  │ ingest ─────────────────────────────────────────────────────►│ read-only snapshot, run id
 │                  │ tools run ──────────────────────────────────────────────────►│ semgrep/bandit/gitleaks/osv + builtins
 │                  │ inventory ──────────────────────────────────────────────────►│ surface map + recommended agents
 │                  │── Task: recon/static/authz/biz/web/deps/secrets (parallel) ─►│
 │                  │                          │ read code (Read/Grep), reason     │
 │                  │                          │ write candidates JSON (audit-output)
 │                  │                          │ findings add ────────────────────►│ schema ✓, files exist ✓, excerpts match ✓
 │                  │◄──────── summaries ──────│                                   │ else reject / demote
 │                  │── Task: verifier (ids) ─►│ findings set-status ─────────────►│ independent reviewer ✓, no consensus ✓
 │                  │── Task: severity ───────►│ set-cvss / financial set ────────►│ CVSS computed, caps, estimate validated
 │                  │── Task: report ─────────►│ report / log verify ─────────────►│ JSON/MD/HTML + bounty drafts + log check
 │◄── summary: zone, RED items, coverage gaps, report paths                        │
```
Every arrow into the CLI passes the policy hook first; every network call passes netguard.
