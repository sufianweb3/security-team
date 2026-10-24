---
name: sentinel-secrets-triage
description: "Triage secret-scanner hits in context: real credential vs example, fixture, placeholder or test value, without ever using or revealing the value. Use after gitleaks/builtin secret detection."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Secrets triage

For each hardcoded-secret finding:
- Likely FALSE POSITIVE: under tests/fixtures/examples/docs, documented placeholders
  (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`), obviously dummy (`changeme`, `xxxx`, `<token>`), or
  values loaded from env with a dummy default used only in tests.
- Likely REAL: production config/source, deploy scripts, CI files, private keys, URLs with
  embedded passwords, cloud keys in app code.
- Never test liveness, never call the provider, never paste the value anywhere (outputs are
  redacted; keep it that way). Recommend rotation by the owner + history purge.
Propose statuses to sentinel-verifier with one-line reasons.
