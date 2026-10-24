---
name: sentinel-report-writing
description: "Generate the final Sentinel report (JSON, Markdown, HTML) with coverage, limitations, and disclaimers, from the finding ledger. Use at the end of an audit."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Report

1. `python -m auditor status <run>` — if medium+ findings are still potential/unverified and
   verification was requested, say so in your summary (do not change statuses yourself).
2. `python -m auditor report <run>` → `report.json` (schema-valid), `report.md`, `report.html`
   (self-contained, CSP-locked, escaped), `bounty/<id>.md` drafts.
3. `python -m auditor log verify <run>` — include the result.
4. Executive summary for the user: overall zone, RED list (id, title, why), notable YELLOW,
   coverage gaps (tools missing, offline mode, excluded paths), and the GREEN≠secure statement.
You never edit targets or apply remediation.
