---
name: sentinel-evidence-verification
description: "Independently verify other agents' candidate findings against the immutable snapshot and assign a verification status. Use for the verifier role or whenever a finding's validity is questioned."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Evidence verification (independent)

For each finding id (`python -m auditor findings show <run> <id>`):
1. Re-read every cited location yourself. Does the code say what the finding claims?
2. Reachability: route registered? auth guard? input actually attacker-controlled?
3. Prerequisites: what must be true (role, config, feature flag)? List missing ones.
4. Alternative explanations: framework auto-escaping, ORM parameterization, upstream
   middleware, DB constraints, compensating controls.
5. Choose the WEAKEST status the evidence supports:
   - confirmed_static: the code path is fully evidenced (source→sink / missing check) and reachable.
   - strongly_supported: evidence is strong but one prerequisite is unproven.
   - potential: plausible; needs safe manual verification.
   - unverified_hypothesis: evidence does not establish the claim.
   - false_positive / not_applicable: explain why.
6. `python -m auditor findings set-status <run> <id> --reviewer sentinel-verifier --status <s> --rationale "..." [--basis dataflow] [--missing "..."] [--alternative "..."]`
Forbidden bases: consensus / multiple agents agree. You cannot verify findings you authored.
