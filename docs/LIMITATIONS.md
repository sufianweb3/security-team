# Limitations and known gaps (honest list)

## Not verified in the build environment
- **The harness integrations were not executed.** OpenCode, Claude Code and Codex were not
  installed in the environment where this was built, so the generated `opencode.json`,
  `.opencode/agents/*.md`, the OpenCode plugin, `.claude/*`, and `.codex/*` were written from
  the official documentation (fetched 2026-10-24) and validated structurally (JSON/TOML/YAML
  parse, permission content, rendering tests) — but not by loading them in each harness.
  First thing to do on your machine: `opencode debug agents` (OpenCode), `/agents` (Claude
  Code), `/hooks` + `/subagents` (Codex), and confirm the hook blocks `curl` in each.
- OpenCode's shell tool is `shell` in current docs and `bash` in older versions; the generated
  configs carry identical rules under both keys plus a top-level `"*": "deny"`, so a renamed
  or new tool is denied by default. If a future rename blocks the CLI, add the new key in
  `scripts/setup.py` (never loosen `"*"`).
- Model ids for the `anthropic` OpenCode profile are left `null` (inherit) because they were
  not verified; fill them from `opencode models anthropic`.

## Enforcement gaps
- **Codex per-agent narrowing:** Codex custom agents inherit the parent's sandbox and approval
  settings and cannot narrow them; per-agent subcommand limits rely on instructions + the hook
  + CLI checks (e.g. reviewer independence). OpenCode and Claude Code enforce per-agent limits.
- **Hooks are guardrails, not perfect boundaries.** Codex docs say some tool paths can opt out
  of hooks and hosted tools (web search) don't pass through them; set `web_search = "disabled"`
  in your user config. Running any harness in bypass/yolo/auto-approve modes disables layers.
- **DNS rebinding window:** `netguard` resolves and checks the host, then `urllib` resolves
  again when connecting. A hostile DNS server could flip the answer in between. Mitigations:
  scope only hosts you trust to be the target, use the container egress proxy, or the offline
  profile. (Pinning the resolved IP into the TLS connection is a planned improvement.)
- **Egress beyond the CLI:** the harness's own model traffic and any tool not routed through
  `netguard` (osv-scanner → api.osv.dev) are controlled by harness sandbox/permission profiles
  or Docker/firewall, not by `netguard`.
- **Read-only snapshot on Windows** uses the read-only attribute; administrators can still
  write. On Linux, root ignores permission bits (the test skips that assertion as root). Use a
  normal user or the container (`read_only` FS + read-only mounts) for a hard guarantee.
- `semgrep --x-ignore-semgrepignore-files` (used so a target can't hide code with its own
  `.semgrepignore`) is marked INTERNAL by semgrep; it works in the pinned 1.182.1 but may change.

## Analysis coverage
- Static + passive only. No dynamic testing, ever — some real issues are only provable
  dynamically; those stay `potential` with a safe manual validation note.
- Dependency findings are version matches; reachability is not computed (osv-scanner call
  analysis is disabled because Rust call analysis runs build scripts; Go call analysis could be
  re-enabled safely in a future version).
- The bundled semgrep rule pack is small and targets common Python/JS/Solidity sinks. Install
  the pinned community rules for breadth (`scripts/fetch_semgrep_rules.py`, mind its license).
- Business-logic/authorization findings depend on model quality; the CLI guarantees their
  *evidence is real*, not that the model found everything.
- Business priority is only as good as the scope's `business_context`; without it, it is
  "not assessed". Program taxonomies (Bugcrowd VRT etc.) are not auto-mapped: list the
  categories you care about in `category_ratings`. See BUSINESS_IMPACT.md.
- CVSS v4.0 vectors are stored but not scored. EPSS/KEV enrichment is not implemented.
- Duplicate detection against previously disclosed issues requires a user-supplied
  `known_issues_file`; no public disclosure database is queried.
- Token/cost accounting is the harness's job; the engine logs only its own tool/network usage.

## Tests that cannot fully prove a property
- "No live exploit payloads are generated" is enforced structurally (no code path can send a
  body or non-GET/HEAD request; static tests assert this) — we cannot test the model's text.
- Harness-level permission behaviour is asserted on the generated config files, not by running
  each harness.
