---
name: sentinel-finding-format
description: "Write candidate findings in the exact Sentinel JSON format with verifiable evidence, and submit them through the CLI. Use whenever an agent is about to report a vulnerability or observation."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Finding format (schemas/finding.schema.json)

Write `<run_dir>/candidates/<your-agent>.json` as `{"findings": [ ... ]}` then
`python -m auditor findings add <run> --agent <your-agent> --file <that file>`.

Required fields per finding (omit `id`):
- `title`, `category` (e.g. sql-injection, idor, missing-authorization, business-logic,
  hardcoded-secret, vulnerable-dependency), `cwe` ("CWE-639") or null, `component`, `target_id`
- `locations[]`: `{file, start_line, end_line, function?, role}` — roles: source, propagation,
  sink, check, config, observation. Data-flow bugs need at least source AND sink.
- `evidence[]`: `{kind: code_excerpt|config_excerpt|spec_excerpt|doc_excerpt|http_observation,
  file, start_line, end_line, content}` — content must be VERBATIM lines from the snapshot
  (whitespace-insensitive). The CLI checks this; paraphrase ⇒ "not machine-verified" ⇒
  status forced to unverified_hypothesis. Keep excerpts minimal (≤15 lines). Never include secrets.
- `description`, `preconditions[]`, `attack_scenario` (plausible, NOT executed),
  `expected_boundary`, `observed_behavior`, `technical_impact`
- `severity` (critical|high|medium|low|informational) and `confidence` (high|medium|low) —
  independent. Critical requires a CVSS vector (else capped to high).
- `verification.status`: discovery agents use `potential` or `unverified_hypothesis`
  (self-confirmation is downgraded automatically).
- `safe_validation` (how a human can confirm WITHOUT touching the live target), `remediation`,
  `references[]`, `limitations[]`, `source: {"kind": "agent", "name": "<you>"}`.

Precision rules: one root cause per finding; cite the enforcing sibling when claiming a
missing check; state what you could NOT establish in `limitations`.
