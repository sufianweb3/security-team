---
name: sentinel-bug-bounty-packaging
description: "Prepare manual bug-bounty submission drafts: map findings to program scope and exclusions, list missing evidence, and produce a safe reproduction outline. Use when the scope basis is a bug bounty program."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Bug bounty packaging (manual submission only)

- The scope must reference the program policy (`authorization.program.policy_url|policy_file`).
  Read it: in-scope assets, excluded vuln classes, prohibited testing, disclosure rules.
- For each RED/YELLOW finding, the report's `bug_bounty.items[]` gives program status
  (in-scope vs excluded category), technical validity, missing evidence, duplicate-check status.
- Drafts in `<run_dir>/bounty/<id>.md` contain a SAFE reproduction outline (code walk-through);
  any dynamic confirmation must be done by the human, manually, only where the program allows.
- Never claim eligibility, uniqueness, or a reward amount. Never submit, contact the program,
  create accounts, or run extra tests. If `known_issues_file` is absent, say duplicates were not checked.
