# Bug bounty workflow (manual submission only)

1. **Scope from the program.** Copy `config/scopes/example-bugbounty-web.yaml`. Set
   `authorization.basis: bug_bounty_program`, the `program.policy_url` (and a local
   `policy_file` copy), `prohibited_tests`, `expires_at`. Put excluded hosts/paths/vuln classes
   in `exclusions`. Keep `status: unconfirmed` until **you** have read the policy and confirm.
2. **Prefer source.** If the program publishes source (or you have a public repo of the
   in-scope product), add it under `repositories` at a pinned commit. Static evidence is where
   this tool is strongest.
3. **Passive web only.** With `status: authorized` and `allowed_hosts`, the orchestrator may run
   a few `fetch` calls (GET/HEAD, rate-limited, budgeted). That's it — no scanning, no fuzzing,
   no parameter tampering, no auth testing. Many programs forbid automated scanning; the
   per-run budget is deliberately tiny.
4. **Run the audit** (`sentinel-run-audit`). Verification and scoring happen as usual.
5. **Read `report.md → Bug bounty notes`.** For each RED/YELLOW finding: program status
   (in-scope vs excluded category), technical validity, **missing evidence** a triager will ask
   for, duplicate-check status (only if you provide `known_issues_file`), and explicit
   "no eligibility claim / no reward estimate".
6. **Draft** in `bounty/<id>.md`: summary, evidence, impact, a *safe reproduction outline*
   (code walk-through), remediation, limitations.
7. **You** decide whether to do any dynamic confirmation — manually, only where and how the
   program permits (often with their test accounts) — and you submit manually.

What the system never does: submit reports, contact programs, create accounts, run additional
tests, claim uniqueness/eligibility, or predict payouts.
