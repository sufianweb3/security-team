---
name: sentinel-recon-inventory
description: "Map an ingested target's attack surface from passive artifacts: languages, frameworks, routes/entry points, specs, IaC, CI, trust boundaries, and what was not inspected. Use at the start of an audit or when an agent needs orientation."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Recon & inventory (passive only)

1. `python -m auditor inventory <run> --target <id>` → JSON with languages, frameworks,
   manifests/lockfiles, missing lockfiles, specs, IaC, CI, contracts, entry points, binaries.
2. Read entry points; group by trust boundary: unauthenticated, authenticated, admin,
   internal/service, CI/build, third-party callbacks/webhooks.
3. Note auth middleware/decorators and where they are (and are not) applied.
4. Record gaps explicitly: binaries, generated/minified code, excluded globs, missing
   lockfiles (dependency results then incomplete), absent specs.
5. Output a short surface map for the orchestrator. Do NOT crawl, enumerate hosts, or guess URLs.
