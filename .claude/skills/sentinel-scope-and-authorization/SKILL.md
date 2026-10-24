---
name: sentinel-scope-and-authorization
description: "Create, review or validate a Sentinel scope file and decide whether a target is authorized and which network mode applies. Use before any assessment, when a user names a new target, or when scope/authorization is ambiguous."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Scope & authorization

Rules: never assume a public system is authorized; ambiguity ⇒ `status: unconfirmed` ⇒ offline.

Checklist for a scope file (`schemas/scope.schema.json`):
1. `assessment.id` (lowercase slug), `name`, `type[]`.
2. `authorization.status` = `authorized` ONLY with a basis: own code, written permission,
   bug bounty program (policy URL or file REQUIRED), training lab, or public source review.
   Add `expires_at` for time-boxed programs.
3. Repositories need a full 40-hex commit (reproducibility).
4. Web: list exact hosts; `*.example.com` covers subdomains only (not the apex). No `*`.
   Private IPs/localhost only with `lab.allow_private_targets: true` for your own lab.
5. Put program exclusions in `exclusions.hosts/paths/vuln_categories` and prohibited test
   types in `authorization.program.prohibited_tests`.
6. `limits.max_http_requests` small (25–50). `min_interval_seconds` ≥ 2 for production.

Validate: `python -m auditor scope validate <file>`. Report errors verbatim; never "fix" scope
by widening it. Only the human can confirm authorization.
