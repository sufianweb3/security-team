# Example audit: vulnapp training fixture

`vulnapp-audit/` is the real output of `python scripts/example_audit.py` (2026-10-24, v0.3.0), which
replays a full agent-driven run through the same CLI the agents use:

1. Deterministic baseline (semgrep, bandit, gitleaks, osv-scanner, builtin checks) → 28 findings, all YELLOW.
2. Pre-recorded agent candidates (`agent-candidates/`): IDOR, missing admin role check, coupon
   compounding (things pattern tools miss) + a **hallucination demo** (an invented excerpt and
   an invented file).
3. Guardrails firing: the invented file is **rejected**; the invented excerpt is demoted to
   `unverified_hypothesis`; "consensus" as a basis is **refused**; the author verifying its own
   finding is **refused**; a financial estimate that multiplied a whole TVL by 1.0 is **rejected**.
4. Independent verification + CVSS: SQL injection (7.5) and the missing admin check (8.1)
   become **RED**; the IDOR is confirmed but CVSS 6.5 (read-only) keeps it **YELLOW** — zone
   follows impact, not alarm. Two items are excluded as false positives with rationale.
5. Business impact (`sentinel-business-impact`, context from the scope's `business_context`):
   SQL injection on the critical-tier shop API exposing customer PII/credentials is raised one
   step to **P1**; the IDOR on invoices (PII + payment data) is raised to **P2** although its
   technical severity stays medium/YELLOW; the coupon flaw is kept at P3. CI/build findings drop
   a step (not internet-exposed). Three guardrails fire: a raise citing data classes the owner
   never declared is **refused**, the IDOR's author assessing its own finding is **refused**, and
   a raise on an unverified tool finding is **refused**.
6. Report: overall **RED** (2 RED, 28 YELLOW; business priority P1 1 · P2 12 · P3 10 · P4 7), schema-valid JSON, Markdown, self-contained
   HTML, 30 bounty drafts, hash-chained audit log (verify = ok).

Files: `report.md` (start here) · `report.json` · `report.html` · `findings.json` (ledger incl.
rejected) · `bounty/*.md` · `audit-log.jsonl` · `example_audit_transcript.txt`.
Absolute paths were replaced with `<repo>` except inside `audit-log.jsonl` (editing it would
break its hash chain).
