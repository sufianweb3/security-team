# Model & cost strategy

Models are interchangeable reasoning engines, not security boundaries. Every agent references
a **tier** (`cheap` or `strong`) in `harness/agents.yaml`; `config/models.yaml` maps tiers to
each harness's model ids per **profile**. Re-render after changes:
`python scripts/setup.py --harness all --profile <deepseek|anthropic|openai|inherit>`.

## Verified identifiers (checked 2026-10-24 — re-verify before relying on them)
| Provider | Model id | Notes (source) |
|---|---|---|
| DeepSeek API | `deepseek-flash` | Served by DeepSeek-V4.1-Flash; legacy `deepseek-v4-flash` still accepted (api-docs.deepseek.com) |
| DeepSeek API | `deepseek-v4-pro` | Strongest DeepSeek model; DeepSeek's Codex catalog lists a 1,048,576-token context |
| OpenCode | `deepseek/deepseek-flash`, `deepseek/deepseek-v4-pro` | `provider/model` format; confirm with `opencode models deepseek` |
| Claude Code via DeepSeek | aliases `opus`→`deepseek-v4-pro`, `haiku`/`sonnet`→`deepseek-flash` | DeepSeek maps Claude names on its Anthropic-compatible endpoint |
| Codex (OpenAI) | `gpt-6.1-sol` (strong), `gpt-6-luna` (fast) | Codex subagents docs |
Free tiers, prices and rate limits change frequently: check the provider pricing page.
Tool-calling support is required for every agent (both DeepSeek models are used by DeepSeek's
own agent integrations, which rely on tool calls).

## Tier assignment
| Cheap (`deepseek-flash`) | Strong (`deepseek-v4-pro`) |
|---|---|
| recon, web-api, deps, secrets, report | orchestrator, static-code, authz, business-logic, verifier, severity |
Rule: the cheap tier never makes final severity/verification decisions; those agents are strong.
Deterministic tool evidence cannot be overridden by any model (the ledger only lets the verifier
change status, with machine-verified evidence, and severity follows CVSS).

## Provider setup per harness
**OpenCode** — run `/connect`, choose DeepSeek, paste the key (stored in
`~/.local/share/opencode/auth.json`, which the policy denies agents from reading).

**Claude Code** — environment (from DeepSeek's docs):
```bash
export ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
export ANTHROPIC_AUTH_TOKEN=<your DeepSeek key>
export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro
export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-flash
export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-flash
```
(PowerShell: `$env:NAME="value"`.) Do **not** set `CLAUDE_CODE_SUBAGENT_MODEL_FORCE`, or the
per-agent tiers are ignored.

**Codex** — providers can only be set in the **user** config `~/.codex/config.toml` (project
config ignores `model_provider`). Per DeepSeek's Codex guide: create `~/.codex/models.json`
(their catalog) and add:
```toml
model = "deepseek-flash"
model_provider = "deepseek"
model_catalog_json = "~/.codex/models.json"
web_search = "disabled"
[model_providers.deepseek]
name = "deepseek"
base_url = "https://api.deepseek.com/"
wire_api = "responses"
experimental_bearer_token = "<your DeepSeek key>"   # or use their setup script after reviewing it
```
Custom agents in `.codex/agents/*.toml` then select `deepseek-flash`/`deepseek-v4-pro` per tier.

## Budgets, retries, concurrency, fallback
| Control | Where |
|---|---|
| Per-run HTTP budget, per-host interval | scope `limits` + `policy.network` (netguard enforces) |
| Tool timeouts, output caps, max tool runs | `policy.tools`, `policy.budgets` (sandbox enforces) |
| Candidates per agent | `policy.budgets.max_candidate_findings_per_agent` (CLI truncates) |
| Agent step/turn limits | OpenCode `steps`, Claude `maxTurns` — add to `harness/agents.yaml` if desired |
| Concurrency | Codex `[agents] max_concurrent_threads_per_session = 6`; Claude `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`; OpenCode: orchestrator prompt |
| Structured outputs | candidates must validate against `schemas/finding.schema.json` (CLI rejects otherwise) |
| Model unavailable | re-render with `--profile inherit` (all agents use the session model) or edit the tier map; the deterministic pipeline needs no model |
| Token/cost logging | done by the harness (OpenCode session stats, Claude `/cost`, Codex usage). The engine logs its own tool/network usage in `audit-log.jsonl`. |
| Caching | Harness prompt caching; the engine caches TLS metadata per host within a run. Tool results are cached per run in `work/`. |
