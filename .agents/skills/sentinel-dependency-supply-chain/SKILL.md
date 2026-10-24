---
name: sentinel-dependency-supply-chain
description: "Assess known-vulnerable dependencies and supply-chain risk (lockfiles, lifecycle scripts, unpinned CI actions, curl-pipe-sh, provenance) and judge reachability. Use for SCA and build/CI security review."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Dependencies & supply chain

1. osv-scanner results are already in the ledger after `tools run` (one finding per package).
   Run `python -m auditor supplychain <run> --target <id>` for lifecycle scripts, GitHub Actions
   pinning / pull_request_target / expression injection, Dockerfile curl|sh and root user.
2. For each vulnerable package: find imports/usages of the vulnerable API (grep the snapshot).
   Used ⇒ note the call site as evidence (reachability supported). Not found ⇒ say so; keep
   status potential. Never claim exploitability from a version match alone.
3. Missing lockfiles ⇒ results incomplete (limitation).
4. Never run installers, `npm/pip install`, builds, or update dependencies. Don't fetch packages.
Note: pin CI actions by SHA — mutable tags were hijacked in the March 2026 trivy-action
compromise (CVE-2026-33634); treat unpinned third-party actions as a real (low/medium) risk.
