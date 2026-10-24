# Business impact methodology ("is it really that critical for THIS company?")

Technical severity (CVSS) answers *how bad is this class of bug, in general*. Bug bounty
programs and asset owners care about *how much it matters here*: a SQL injection in a test
fixture and one in the production billing API share a CVSS score but not a priority.
Sentinel records this as a **separate dimension, business priority (P1 highest … P5)**, set by
`sentinel-business-impact` and enforced by `auditor/business.py`.

Business priority **never changes** technical severity, CVSS, confidence, verification status
or risk zone. RED still means "technically severe and independently verified".

## Where the context comes from
Only from the scope file's `business_context` block (`schemas/scope.schema.json`), which lives
under `config/` and is write-protected from agents by every harness config and the hook. An agent
therefore cannot inflate an asset's importance; it can only reason over what the owner or the
program supplied.

```yaml
business_context:
  source: program_policy        # program_policy | owner_provided | unknown
  source_ref: https://hackerone.com/acme
  program_severity:
    scale: hackerone            # cvss31 | bugcrowd_vrt | hackerone | custom
    category_ratings: {idor: high, sql-injection: critical}
    out_of_scope_impacts: [missing-security-header]
  assets:
    - id: acme-api
      match: {hosts: [api.acme.example]}           # or target_ids + path_prefixes
      criticality: critical                        # program "Tier 1"
      max_severity: critical                       # optional program cap for this tier
      data_classes: [pii, payment, authentication]
      environment: production
      internet_exposed: true
```
No `business_context` ⇒ every finding says **"business priority: not assessed"** and the
report lists it as a limitation. Nothing is guessed.

## Deterministic rules
| Step | Rule |
|---|---|
| Start | critical→P1, high→P2, medium→P3, low→P4, informational→P5 (from technical severity) |
| Asset match | most specific wins (path/host match beats target-only); none ⇒ `asset_unknown`, priority = technical |
| Automatic modifiers (**down only**) | low-tier asset −1 · non-production environment −1 · not internet-exposed −1 · capped at −2 total |
| Reviewer lowers | −1 or −2 with a ≥40-char rationale (e.g. data is public, feature disabled) |
| Reviewer raises | **+1 at most**, refused unless ALL hold: verification is confirmed_static/strongly_supported · technical severity ≥ medium · asset tier high/critical · `source` ≠ unknown · affected data classes are declared for that asset and include a high-value class (pii, payment, credentials, health, funds, secrets, authentication, financial, customer_content) |
| P1 | additionally needs a CVSS vector on the finding |
| Asset cap | `max_severity` always clamps the result (program tier caps) |
| Independence | the reviewer must not be a contributor to the finding |
| Candidate smuggling | `business_*` fields in candidate findings are stripped at intake |

## Submission recommendation
| Decision | When |
|---|---|
| `do_not_submit` | category is excluded / an out-of-scope impact for the program, or the finding is a false positive |
| `needs_more_evidence` | not independently verified |
| `manual_review` | verified, but no business context |
| `low_value` | verified, business priority P4/P5 |
| `candidate_for_manual_submission` | verified, P1–P3. A human still checks duplicates, program rules and reproduction |

The tool never predicts eligibility or rewards and never submits anything.

## Commands
```
python -m auditor business context <run>                # what context the scope supplies
python -m auditor business show <run> [id]              # automatic assessment
python -m auditor business set <run> <id> --reviewer sentinel-business-impact --file <run_dir>/candidates/business-<id>.json
```
Review JSON fields (others are refused): `adjustment` (−2..1), `rationale`, `affected_data_classes`,
`business_scenario`, `program_rating_ref`, `assumptions`.

## Limitations
- The quality of the priority is bounded by the quality of the context. Copy asset tiers and
  severity tables from the program policy verbatim; mark `source: unknown` if you can't.
- Category matching for `category_ratings` is by Sentinel category or CWE id, not the program's
  own taxonomy (e.g. Bugcrowd VRT); map the categories you care about explicitly.
- In Codex, per-agent subcommand narrowing isn't possible (see PERMISSION_MATRIX), so the
  `--reviewer` name is self-declared there; the independence and raise rules still apply.
