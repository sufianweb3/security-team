# START HERE — instructions for the agent harness (OpenCode, Claude Code, Codex, …)

You (the coding agent) have been asked to **set up Sentinel Auditor and start the flow**.
Follow these steps exactly. Do not skip the security checks. Do not install anything not
listed here. If a step fails, stop and report the exact error to the user.

## 1. Read the rules first
Read `config/policy.yaml`, `AGENTS.md` (or `CLAUDE.md`), and `docs/THREAT_MODEL.md`.
This system is a **read-only vulnerability discovery tool**. It never exploits, never
runs target code, never sends anything but scope-gated GET/HEAD requests.

## 2. Python environment (Python 3.11+)
```bash
python -m venv .venv
# macOS/Linux:  source .venv/bin/activate      Windows PowerShell:  .venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

## 3. Optional but recommended: pinned security tools (hash-verified)
Ask the user before running this — it downloads four pinned tools from their official
release pages and verifies SHA-256 for each:
```bash
python scripts/install_tools.py
```
Without them the system still works (builtin analyzers), but the report will list the
missing coverage. On Windows, semgrep works best under WSL2 (see `docs/WINDOWS.md`).

## 4. Verify the environment and run the tests
```bash
python scripts/setup.py --check
python -m pytest
```
All tests must pass before continuing (some e2e assertions adapt to which tools exist).

## 5. Render the harness configuration for the harness you are
Pick the model profile (default `deepseek`; others: `anthropic`, `openai`, `inherit`):
```bash
python scripts/setup.py --harness opencode --profile deepseek   # if you are OpenCode
python scripts/setup.py --harness claude   --profile deepseek   # if you are Claude Code
python scripts/setup.py --harness codex    --profile deepseek   # if you are Codex
python scripts/setup.py --harness all      --profile inherit    # all harnesses, session model
```
Then tell the user to **restart the harness in this directory** so it loads the agents,
skills, permissions and the policy hook:
- OpenCode: `opencode` → press Tab to select `sentinel-orchestrator` (plugin guard auto-loads).
- Claude Code: `claude --agent sentinel-orchestrator` (accept the workspace trust prompt so
  the PreToolUse hook runs).
- Codex: trust the project (so `.codex/config.toml` + hooks load), approve the hook in
  `/hooks`, then ask Codex to use the `sentinel-run-audit` skill (`$sentinel-run-audit`).
Model providers (DeepSeek etc.) are configured per `docs/MODEL_STRATEGY.md`.

## 6. Smoke test (no LLM required)
```bash
python -m auditor run config/scopes/vulnapp-local.yaml
```
This audits the bundled intentionally vulnerable fixture and writes
`audit-output/vulnapp-local/<run>/report.{md,json,html}`. Compare with `examples/vulnapp-audit/`.
To replay the full agent-layer example (verification, CVSS, financials): `python scripts/example_audit.py`.

## 7. Start a real assessment
1. Copy a template from `config/scopes/` and fill it in. **Authorization is the user's
   decision**: leave `authorization.status: unconfirmed` until the user explicitly confirms
   they are authorized (own code, written permission, or a bug bounty program whose policy
   you reference). Unconfirmed ⇒ offline analysis only.
2. Optional but recommended for bug bounty work: fill in the scope's `business_context`
   (asset tiers, data classes, production/internet exposure, the program's severity table),
   copied from the program policy or provided by the owner. Without it, findings are ranked by
   technical severity only and business priority reads "not assessed". See
   `docs/BUSINESS_IMPACT.md`. Never invent these values.
3. Start the `sentinel-orchestrator` agent and say:
   *"Run the sentinel-run-audit skill on config/scopes/<your-scope>.yaml"*.

## What you must never do while setting up
- Disable or edit the policy hook, `config/policy.yaml`, or harness permission files to
  "make something work". Report the problem instead.
- Run `--dangerously-skip-permissions`, `--yolo`, auto-approve modes, or Codex
  `--dangerously-bypass-hook-trust`.
- Point the auditor at a target the user has not confirmed they are authorized to assess.
