---
name: sentinel-severity-cvss
description: "Assign defensible severity with CVSS v3.1 vectors, keeping severity, confidence, verification and risk zone independent. Use when scoring findings."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Severity & CVSS

- Only set a vector when each metric is justified by evidence:
  AV (network/adjacent/local/physical), AC, PR (none/low/high — e.g. "any logged-in user" = L),
  UI, S (changed only if impact crosses a security authority), C/I/A for the vulnerable component's data.
- `python -m auditor score --cvss "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"` to check a vector.
- `python -m auditor findings set-cvss <run> <id> --vector "<vector>" --rationale "<metric-by-metric>"`.
- The CLI derives severity from the score; critical without a vector is capped to high; missing
  headers alone are capped to low; upstream dependency CVSS describes the library, not the app.
Zones (computed): RED = high/critical + confirmed_static/strongly_supported + medium/high
confidence + verified evidence; GREEN = informational / nothing found in a COVERED component;
everything else YELLOW; uncovered components are NOT_ASSESSED (never green).
