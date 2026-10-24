---
name: sentinel-business-impact
description: "Judge how much a verified finding matters to the specific organization (asset tier, data at risk, environment, exposure, program severity table) and set a business priority P1-P5 with a submission recommendation, without changing technical severity. Use after verification and CVSS scoring."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Business impact ("is it really that critical for THIS company?")

Technical severity answers "how bad is this bug in general". Business priority answers
"how much does it matter here". They are recorded separately; this skill never touches
severity, CVSS, confidence, verification status or risk zone.

## Inputs (only these)
- `python -m auditor business context <run>`: the scope's `business_context`: assets with
  criticality tier, data classes, environment, internet exposure, optional `max_severity`
  (program asset-tier cap), and the program's `category_ratings` / `out_of_scope_impacts`.
- `python -m auditor business show <run> [id]`: the automatic assessment per finding.
- The cited code (via the inventory) to see what data a vulnerable path really touches.

If there is no `business_context`, stop: priority is "not assessed". Tell the orchestrator
the user (or program policy) must supply it. Never infer asset importance yourself.

## What the CLI does automatically
- Starts from technical severity (critical=P1, high=P2, medium=P3, low=P4, info=P5).
- Lowers one step each for: low-tier asset, non-production environment, not internet-exposed
  (at most two steps total).
- Clamps to the asset's `max_severity`.
- Looks up the program's own rating for the category, if published.
- Recommends: `do_not_submit` (out of scope / excluded), `needs_more_evidence` (not verified),
  `low_value`, `manual_review`, or `candidate_for_manual_submission`.

## Your review (one JSON per finding, in `<run_dir>/candidates/`)
```json
{"adjustment": 0,
 "affected_data_classes": ["pii", "payment"],
 "business_scenario": "Any logged-in customer can read another customer's invoices (names, addresses, amounts).",
 "rationale": "Invoices hold customer PII and payment amounts on the production billing asset; no further adjustment beyond the tier rules.",
 "program_rating_ref": "program policy section 'Severity', IDOR exposing PII = P2",
 "assumptions": ["Invoice table holds real customer data in production (owner-stated)"]}
```
`python -m auditor business set <run> <id> --reviewer sentinel-business-impact --file <path>`

- **Lower (-1/-2)** with a reason: data is public or synthetic, feature is disabled, an
  upstream control (VPN-only, IP allowlist) is documented in the context.
- **Keep (0)** when the context neither raises nor lowers it. This is the common answer.
- **Raise (+1, max)** only when the finding is verified, technical severity >= medium, the
  asset is high/critical tier, the context source is not `unknown`, and the affected data
  classes are declared for that asset and include a high-value class (pii, payment,
  credentials, health, funds, secrets, authentication, financial, customer_content).
  P1 also needs a CVSS vector. The CLI refuses anything else.
- You may not review a finding you contributed to.

## Never
- Invent user counts, revenue, regulatory fines or reward amounts.
- Treat "sounds scary" as business impact. Tie every claim to the asset and data in context.
- Claim program eligibility; the program decides.
