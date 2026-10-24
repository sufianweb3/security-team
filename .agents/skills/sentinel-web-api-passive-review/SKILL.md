---
name: sentinel-web-api-passive-review
description: "Review OpenAPI/Swagger specs, web configs and scope-authorized passive HTTP observations (security headers, cookies, CORS, TLS metadata). Use for API/web configuration auditing without active testing."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Web/API passive review

Specs: `python -m auditor openapi <run> --target <id> --spec <path>` (plain-HTTP servers,
query-string API keys, operations with no security requirement). Then reason about
authorization assumptions per operation and mismatches with code.

Live (only if `python -m auditor status <run>` shows `network_mode: passive_web`):
`python -m auditor fetch <run> <in-scope-url>` — one GET, headers recorded, header checks added.
Allowed: a handful of seed URLs, `/.well-known/security.txt`, `robots.txt` if in scope.
NOT allowed: crawling, path guessing, parameter tampering, forged Origin headers, auth attempts,
OPTIONS/PUT/POST, anything listed in program `prohibited_tests`.

Severity discipline: a missing header alone is at most LOW (the CLI caps it). Report a CORS
issue as a real vulnerability only with evidence of credentialed reflection — which this tool
does not actively probe; otherwise it is an observation.
