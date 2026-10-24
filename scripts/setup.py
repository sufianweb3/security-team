#!/usr/bin/env python3
"""Render the per-harness agent + policy configuration from the canonical sources
(harness/agents.yaml + config/models.yaml) and verify the environment.

Usage:
  python scripts/setup.py --check                      # environment + tool availability
  python scripts/setup.py --harness all --profile deepseek
  python scripts/setup.py --harness opencode --profile inherit

Writes (idempotent, overwrites generated files only):
  opencode.json
  .opencode/agents/<name>.md                 (also .opencode/plugins/sentinel-guard.js ships in the repo)
  .claude/agents/<name>.md, .claude/settings.json, CLAUDE.md
  .codex/agents/<name>.toml, .codex/config.toml, .codex/hooks.json, AGENTS.md
This script itself makes no network calls and runs no target code."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import yaml  # noqa: E402

from auditor.policy import load_policy  # noqa: E402

AGENTS = yaml.safe_load((ROOT / "harness" / "agents.yaml").read_text(encoding="utf-8"))
MODELS = yaml.safe_load((ROOT / "config" / "models.yaml").read_text(encoding="utf-8"))
COMMON = AGENTS["prompt_common"]
HOOK = "hooks/policy_guard.py"
PY = "python" if os.name == "nt" else "python3"


def model_for(agent: dict, harness: str, profile: str) -> tuple[str | None, str | None]:
    tier = agent.get("tier", "cheap")
    prof = MODELS["profiles"].get(profile) or MODELS["profiles"]["inherit"]
    val = (prof.get(harness) or {}).get(tier)
    effort = (prof.get("codex") or {}).get(f"{tier}_effort") if harness == "codex" else None
    return val, effort


def agent_prompt(agent: dict) -> str:
    return f"{COMMON}\n\n# Your role: {agent['name']}\n\n{agent['role'].strip()}\n\n{agent.get('extra_prompt', '').strip()}\n"


def shell_perm(agent: dict) -> dict:
    """OpenCode shell permission object: deny everything except our CLI subcommands."""
    rules = {"*": "deny"}
    for sub in agent["subcommands"]:
        for py in ("python", "python3", "py"):
            rules[f"{py} -m auditor {sub}*"] = "allow"
    return rules


# ----------------------------------------------------------------- OpenCode
def render_opencode(profile: str) -> None:
    d = ROOT / ".opencode" / "agents"
    d.mkdir(parents=True, exist_ok=True)
    for a in AGENTS["agents"]:
        model, _ = model_for(a, "opencode", profile)
        perm = {
            "*": "deny",
            "read": {"*": "allow", "*.env": "deny", "*.env.*": "deny"},
            "glob": "allow", "grep": "allow", "list": "allow", "lsp": "allow",
            "todowrite": "allow", "todoread": "allow",
            "skill": {"*": "deny", "sentinel-*": "allow"},
            "external_directory": "deny",
            "edit": {"*": "deny", "audit-output/**": "allow"},
            "webfetch": "deny", "websearch": "deny",
            "shell": shell_perm(a),
            "bash": shell_perm(a),   # older OpenCode versions name the tool `bash`
        }
        if a.get("primary"):
            perm["question"] = "allow"
        if a.get("can_delegate"):
            perm["task"] = {"*": "deny", **{p: "allow" for p in a.get("delegates_to", [])}}
        else:
            perm["task"] = {"*": "deny"}
        fm = {"description": a["role"].strip().split(".")[0][:200],
              "mode": "primary" if a.get("primary") else "subagent",
              "temperature": 0.1, "permission": perm}
        if model:
            fm["model"] = model
        (d / f"{a['name']}.md").write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n" + agent_prompt(a), encoding="utf-8")
    cfg = {
        "$schema": "https://opencode.ai/config.json",
        "plugin": ["./.opencode/plugins/sentinel-guard.js"],
        # Fail closed: everything not listed is denied (covers renamed/new tools, e.g. `bash`).
        "permission": {"*": "deny",
                       "read": {"*": "allow", "*.env": "deny", "*.env.*": "deny"},
                       "glob": "allow", "grep": "allow", "list": "allow", "lsp": "allow",
                       "todowrite": "allow", "todoread": "allow", "question": "allow",
                       "skill": {"*": "deny", "sentinel-*": "allow"},
                       "task": {"*": "deny", "sentinel-*": "allow"},
                       "external_directory": "deny", "doom_loop": "ask",
                       "edit": {"*": "deny", "audit-output/**": "allow"},
                       "webfetch": "deny", "websearch": "deny",
                       "shell": {"*": "deny", "python -m auditor*": "allow", "python3 -m auditor*": "allow",
                                 "py -m auditor*": "allow"},
                       "bash": {"*": "deny", "python -m auditor*": "allow", "python3 -m auditor*": "allow",
                                "py -m auditor*": "allow"}},
    }
    (ROOT / "opencode.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(f"  opencode.json + {len(AGENTS['agents'])} agents (.opencode/agents/) [plugin guard: .opencode/plugins/sentinel-guard.js]")


# -------------------------------------------------------------- Claude Code
CLAUDE_TOOLS = {  # subcommand -> nothing; we gate via Bash deny-list + hook instead
}


def render_claude(profile: str) -> None:
    d = ROOT / ".claude" / "agents"
    d.mkdir(parents=True, exist_ok=True)
    for a in AGENTS["agents"]:
        model, _ = model_for(a, "claude", profile)
        tools = ["Read", "Grep", "Glob", "Bash", "Write", "Edit", "TodoWrite"]
        if a.get("can_delegate"):
            tools.append("Agent")
        fm = {"name": a["name"], "description": a["role"].strip().split(".")[0][:200],
              "tools": ", ".join(tools), "model": model or "inherit"}
        (d / f"{a['name']}.md").write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + agent_prompt(a), encoding="utf-8")
    # allow only our CLI; deny everything else; run the hook on every Bash + edit
    allow = [f"Bash(python -m auditor {s}:*)" for s in load_policy()["commands"]["allowed_subcommands"]]
    allow += [f"Bash(python3 -m auditor {s}:*)" for s in load_policy()["commands"]["allowed_subcommands"]]
    settings = {
        "permissions": {
            "allow": allow + ["Edit(audit-output/**)", "Write(audit-output/**)"],
            "deny": ["WebFetch", "WebSearch", "Bash(curl:*)", "Bash(wget:*)", "Bash(git:*)", "Bash(npm:*)",
                     "Bash(pip:*)", "Bash(pnpm:*)", "Bash(yarn:*)", "Bash(node:*)", "Bash(sh:*)", "Bash(bash:*)",
                     "Edit(targets/**)", "Write(targets/**)", "Edit(config/**)", "Write(config/**)",
                     "Edit(hooks/**)", "Write(hooks/**)", "Edit(auditor/**)", "Write(auditor/**)",
                     "Edit(.claude/**)", "Write(.claude/**)", "Read(~/.ssh/**)", "Read(~/.aws/**)",
                     "Read(~/.claude/.credentials.json)"],
            "ask": [],
        },
        "hooks": {
            "PreToolUse": [{"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch",
                            "hooks": [{"type": "command", "command": f'{PY} "$CLAUDE_PROJECT_DIR/{HOOK}"'}]}]
        },
    }
    (ROOT / ".claude").mkdir(exist_ok=True)
    (ROOT / ".claude" / "settings.json").write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    (ROOT / "CLAUDE.md").write_text(project_doc("Claude Code"), encoding="utf-8")
    print(f"  .claude/agents/ ({len(AGENTS['agents'])}) + .claude/settings.json + CLAUDE.md")


# ----------------------------------------------------------------- Codex
def render_codex(profile: str) -> None:
    d = ROOT / ".codex" / "agents"
    d.mkdir(parents=True, exist_ok=True)
    for a in AGENTS["agents"]:
        model, effort = model_for(a, "codex", profile)
        lines = [f'name = "{a["name"]}"',
                 f'description = {json.dumps(a["role"].strip().split(".")[0][:200])}']
        if model:
            lines.append(f'model = "{model}"')
        if effort:
            lines.append(f'model_reasoning_effort = "{effort}"')
        lines.append("developer_instructions = " + _toml_multiline(agent_prompt(a)))
        (d / f"{a['name'].replace('sentinel-', '')}.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Codex: project config cannot set a provider; we set a workspace-write-less posture via
    # permission profile and run the policy hook on PreToolUse. Model/provider is user-level
    # (see docs/MODEL_STRATEGY.md). We pin the read-only-ish profile + the guard hook here.
    config = f'''# Generated by scripts/setup.py — Codex project config for Sentinel Auditor.
# Provider/model selection is USER-LEVEL (~/.codex/config.toml); see docs/MODEL_STRATEGY.md.
# This project config enforces the policy guard hook and a constrained default profile.
default_permissions = "sentinel-audit"

[features]
hooks = true
network_proxy = true   # required for the domain allowlist below to be enforced

[agents]
max_concurrent_threads_per_session = 6

[permissions.sentinel-audit]
extends = ":workspace"
description = "Read project; write only audit-output/; policy hook gates all commands."

[permissions.sentinel-audit.filesystem]
glob_scan_max_depth = 4

[permissions.sentinel-audit.filesystem.":workspace_roots"]
"." = "read"
"audit-output" = "write"
"targets" = "write"   # only `python -m auditor ingest` writes here (shell is hook-restricted to the CLI)
"**/*.env" = "deny"

[permissions.sentinel-audit.network]
enabled = true

[permissions.sentinel-audit.network.domains]
"api.osv.dev" = "allow"   # dependency vulnerability lookups (osv-scanner)
# Add in-scope web hosts here ONLY for authorized passive_web scopes, e.g.:
# "www.acme.example" = "allow"
'''
    (ROOT / ".codex").mkdir(exist_ok=True)
    (ROOT / ".codex" / "config.toml").write_text(config, encoding="utf-8")
    hooks = {
        "description": "Sentinel Auditor read-only policy guard.",
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash|apply_patch|Edit|Write",
                "hooks": [{"type": "command",
                           "command": f'{PY} hooks/policy_guard.py',
                           "commandWindows": "py -3 hooks\\policy_guard.py",
                           "statusMessage": "Sentinel policy check"}]}]
        },
    }
    (ROOT / ".codex" / "hooks.json").write_text(json.dumps(hooks, indent=2) + "\n", encoding="utf-8")
    (ROOT / "AGENTS.md").write_text(project_doc("Codex (AGENTS.md)"), encoding="utf-8")
    print(f"  .codex/agents/ ({len(AGENTS['agents'])}) + .codex/config.toml + .codex/hooks.json + AGENTS.md")


def _toml_multiline(text: str) -> str:
    return '"""\n' + text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"') + '\n"""'


def project_doc(harness: str) -> str:
    orch = next(a for a in AGENTS["agents"] if a.get("primary"))
    names = "\n".join(f"- `{a['name']}` ({a.get('tier')}) — {a['role'].strip().split('.')[0]}." for a in AGENTS["agents"])
    return f"""# Sentinel Auditor — project guidance for {harness}

This project is a **read-only, evidence-driven security auditor**. Read `config/policy.yaml`
and `docs/THREAT_MODEL.md` before doing anything. The rules below are enforced by a policy
hook, the `auditor` CLI, and OS/container limits — not just by instructions.

## The one and only way to act
- The only shell command any agent may run is `python -m auditor <subcommand> ...`.
- The only network access is `python -m auditor fetch <run> <url>` (scope-gated, GET/HEAD).
- Writes are allowed only under `audit-output/`. Targets live read-only under `targets/`.
- `curl`, `wget`, `git`, `pip`, `npm`, raw shell, and web-fetch/search tools are blocked.
- Never run, build, install, or test target code. Never exploit anything. Fail closed.

## How a run works
1. Start the primary agent **{orch['name']}** and give it a scope file (see `config/scopes/`).
2. It validates scope, ingests inputs to an immutable snapshot, runs the deterministic
   baseline (semgrep/bandit/gitleaks/osv-scanner + builtin analyzers), then dispatches
   specialists for the reasoning findings tools miss (authorization, business logic, data flow).
3. A **different** agent (`sentinel-verifier`) reviews each candidate and sets its status;
   nothing is "confirmed" on model agreement. `sentinel-severity` assigns CVSS/financials.
4. `sentinel-report` writes `report.json`, `report.md`, `report.html` and bounty drafts under
   the run directory, plus a hash-chained `audit-log.jsonl`.

You can always get a full deterministic (no-LLM) report with:
    python -m auditor run config/scopes/vulnapp-local.yaml

## Agents
{names}

## If you are unsure
Stop and report. Prefer offline analysis. Do not broaden scope, add tools, or weaken a
control to make a task succeed.
"""


def install_skills(targets: list[str]) -> None:
    """Copy canonical skills (harness/skills) into harness discovery dirs.
    .agents/skills  -> read by OpenCode and Codex
    .claude/skills  -> read by Claude Code (OpenCode also reads it; names are identical, so
                       if both exist OpenCode sees duplicates of the same skill — harmless)."""
    src = ROOT / "harness" / "skills"
    for t in targets:
        dest = ROOT / t
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        print(f"  skills -> {t}/ ({len(list(src.iterdir()))})")


def check_env() -> int:
    from auditor.sandbox import find_tool
    policy = load_policy()
    print(f"Python: {sys.version.split()[0]}")
    ok = True
    for mod in ("yaml", "jsonschema"):
        try:
            __import__(mod)
            print(f"  [ok] python module {mod}")
        except ImportError:
            print(f"  [MISSING] python module {mod}  -> pip install {mod}")
            ok = False
    print("External tools (optional but recommended; absence = reduced coverage, not failure):")
    for t in policy["tools"]["allowlist"]:
        p = find_tool(t)
        print(f"  [{'ok' if p else '--'}] {t:14} {p or '(not found)'}")
    print("Harness CLIs (install the ones you use):")
    for cli in ("opencode", "claude", "codex"):
        print(f"  [{'ok' if shutil.which(cli) else '--'}] {cli}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Render Sentinel harness configs")
    ap.add_argument("--harness", choices=["opencode", "claude", "codex", "all"], default="all")
    ap.add_argument("--profile", default=MODELS["default_profile"],
                    help=f"model profile from config/models.yaml (default: {MODELS['default_profile']})")
    ap.add_argument("--check", action="store_true", help="environment check only")
    ap.add_argument("--python", help="interpreter used by hooks (default: python3; python on Windows)")
    args = ap.parse_args()
    global PY
    if args.python:
        PY = args.python
    if args.check:
        return check_env()
    if args.profile not in MODELS["profiles"]:
        print(f"unknown profile {args.profile!r}; choices: {list(MODELS['profiles'])}")
        return 2
    print(f"Rendering harness configs (profile={args.profile}):")
    skill_dirs = [".agents/skills"]
    if args.harness in ("claude", "all"):
        skill_dirs.append(".claude/skills")
    install_skills(skill_dirs)
    if args.harness in ("opencode", "all"):
        render_opencode(args.profile)
    if args.harness in ("claude", "all"):
        render_claude(args.profile)
    if args.harness in ("codex", "all"):
        render_codex(args.profile)
    print("Done. Review the generated files, then start your harness in this directory.")
    print("Deterministic smoke test: python -m auditor run config/scopes/vulnapp-local.yaml")
    return 0


if __name__ == "__main__":
    sys.exit(main())
