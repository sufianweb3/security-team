# Permission matrix

Generated configs implement this table; `tests/test_harness_and_static_guards.py` asserts it.
All agents: read/glob/grep/list allowed (no `.env` outside targets, no host credential paths);
**edit/write only under `audit-output/**`**; webfetch/websearch **denied**; MCP **denied**;
shell **denied except** the listed `python -m auditor <subcommand>`; everything else denied
(`"*": "deny"` in OpenCode; deny rules + hook in Claude Code; permission profile + hook in Codex).

| Agent | Tier | Delegate (Task) | Allowed `auditor` subcommands | Notes |
|---|---|---|---|---|
| sentinel-orchestrator | strong | `sentinel-*` only | scope, ingest, inventory, tools, status, findings, score, business, report, bounty, log, run | only agent that can ingest/run; cannot verify its own findings |
| sentinel-recon | cheap | no | inventory, status, findings | passive mapping |
| sentinel-static-code | strong | no | inventory, status, findings | data-flow reasoning |
| sentinel-web-api | cheap | no | openapi, fetch, inventory, status, findings | only agent with `fetch` (scope-gated GET/HEAD) |
| sentinel-deps | cheap | no | supplychain, inventory, status, findings | never installs/updates |
| sentinel-secrets | cheap | no | inventory, status, findings | values always redacted |
| sentinel-authz | strong | no | inventory, status, findings | access-control reasoning |
| sentinel-business-logic | strong | no | inventory, status, findings | invariants, contracts (static) |
| sentinel-verifier | strong | no | findings, status, inventory | `set-status`; must be independent of the author (CLI-enforced) |
| sentinel-severity | strong | no | findings, score, financial, status | `set-cvss`, financial estimates (validated) |
| sentinel-business-impact | strong | no | business, findings, status, inventory | business priority only; raise ≤ +1 under CLI rules; must be independent of the author |
| sentinel-report | cheap | no | report, bounty, status, log | renders; cannot change findings |

## Enforcement layers per harness
| Layer | OpenCode | Claude Code | Codex |
|---|---|---|---|
| Per-agent tool permissions | ✅ frontmatter `permission` | ✅ `tools` + settings deny/allow | ⚠️ agents inherit parent sandbox (can't narrow per agent) — CLI + hook still apply |
| Bash/shell allowlist | ✅ `shell` globs per agent | ✅ `Bash(python -m auditor …:*)` allow + deny list | ✅ hook |
| Pre-tool hook | ✅ plugin → `policy_guard.py` | ✅ `PreToolUse` → `policy_guard.py` | ✅ `PreToolUse` → `policy_guard.py` (trust it in `/hooks`) |
| Filesystem | edit globs + hook + snapshot chmod | Edit/Write rules + hook + chmod | permission profile (`.` read, `audit-output` write) + hook + chmod |
| Network | webfetch/websearch deny; CLI netguard | WebFetch/WebSearch deny; CLI netguard | profile network proxy allowlist (`api.osv.dev`) + web_search off recommended; CLI netguard |
| Subagent spawning | `task` allowlist | `Agent` only for orchestrator | parent-controlled |

Per-agent subcommand narrowing in Codex relies on the agent instructions plus the verifier
independence check in the CLI (the CLI refuses a reviewer that authored the finding). This is
a documented gap — see LIMITATIONS.md.
