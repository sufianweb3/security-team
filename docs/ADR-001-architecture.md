# ADR-001: Harness-agnostic, CLI-mediated, evidence-verified architecture

Status: Accepted (2026-10-24)

## Context
The requirement is a multi-agent, read-only security auditor with OpenCode as primary harness,
also usable from Claude Code and Codex, cheap models where possible, and safety that does not
rest on prompts. Harness capabilities verified from official docs on 2026-10-24:

| Capability | OpenCode | Claude Code | Codex |
|---|---|---|---|
| Custom agents | Markdown in `.opencode/agents/` (frontmatter: description, mode, model, temperature, steps, permission) | Markdown in `.claude/agents/` (name, description, tools, disallowedTools, model, permissionMode, maxTurns, skills, hooks…) | TOML in `.codex/agents/` (name, description, developer_instructions, model, model_reasoning_effort) |
| Subagent delegation | Task tool; `permission.task` globs | Agent tool; `tools: Agent(a, b)` allowlist for `--agent` main thread | spawn on request / instructions; inherits parent sandbox |
| Skills | `SKILL.md` in `.opencode/skills`, `.claude/skills`, `.agents/skills` | `.claude/skills` | `.agents/skills` |
| Permissions | allow/ask/deny per tool, glob patterns, last match wins, `"*"` wildcard | allow/ask/deny rules (`Bash(cmd:*)`, `Edit(path)`), deny wins | permission profiles (filesystem read/write/deny + network domain allowlist via proxy); agents can't override parent |
| Pre-tool interception | plugin `tool.execute.before` (throw to block) | `PreToolUse` command hook (exit 2 blocks) | `PreToolUse` command hook (exit 2 / deny JSON blocks; must be trusted in `/hooks`) |
| Project instructions | `AGENTS.md` | `CLAUDE.md` (can include AGENTS.md) | `AGENTS.md` |

## Options considered
1. **OpenCode-only native agents with prompt rules.** Simple, but violates "don't rely on the
   system prompt" and the multi-harness requirement.
2. **Custom MCP server exposing audit tools to each harness.** Uniform, but adds a long-running
   process, a new attack surface, and MCP tools are not uniformly coverable by each harness's
   permission/hook system (Codex hooks: "a useful guardrail, not a complete enforcement
   boundary"). Kept as a future option.
3. **External orchestrator framework (LangGraph/CrewAI etc.) calling models directly.** Loses
   the harnesses the user wants to use, adds heavy dependencies.
4. **(Chosen) A deterministic Python engine + CLI as the agents' only tool; canonical agent and
   skill definitions rendered per harness; a single policy hook shared by all harnesses.**

## Decision
Option 4. Rationale:
- One choke point (`python -m auditor …`) is easy to allow-list in every harness and enforces
  scope/read-only/network rules itself, so the *same* guarantees hold in all harnesses — and
  even if a harness permission is misconfigured.
- Canonical sources (`harness/agents.yaml`, `harness/skills/`, `config/models.yaml`) avoid
  three hand-maintained copies drifting apart; a test asserts the rendered files match.
- The deterministic pipeline provides a model-free baseline and ground truth for tests.

## Consequences
- Agents can't do ad-hoc shell exploration (grep/cat via shell); they use the harness's
  built-in Read/Grep/Glob tools (read-only) and the CLI. This is intentional.
- Adding a capability = adding a CLI subcommand + policy entry + tests (explicit approval path).
- Model/provider config differs per harness (Codex providers are user-level only); documented
  in MODEL_STRATEGY.md.
- Tool choice: semgrep CE (SAST, local rules, metrics off), bandit (Python), gitleaks (secrets,
  redacted), osv-scanner v2 (SCA; `--no-resolve`, call analysis off because Rust call analysis
  runs build scripts). Trivy was deliberately **not** made a default dependency after its
  March 2026 supply-chain compromise (CVE-2026-33634); it can be added later, pinned ≥0.71.0
  by hash, if container/IaC scanning is needed.
