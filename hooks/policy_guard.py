#!/usr/bin/env python3
"""Universal pre-tool-use policy guard for OpenCode, Claude Code and Codex.

Input : one JSON object on stdin.
  * Claude Code / Codex PreToolUse: {"tool_name": ..., "tool_input": {...}, ...}
  * OpenCode plugin (.opencode/plugins/sentinel-guard.js): {"harness":"opencode","tool_name":..,"tool_input":..}
Output: exit 0 = allow; exit 2 + reason on stderr = deny (both Claude Code and
        Codex treat exit 2 as a block; the OpenCode plugin throws on non-zero).

FAIL CLOSED: unknown tools, unparsable input or internal errors => deny.
This hook is one layer of several. It does not replace harness permissions,
OS/container isolation, or the CLI's own checks (see docs/THREAT_MODEL.md)."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("SENTINEL_ROOT", str(ROOT))

# Tools that only read inside the workspace (still path-checked when a path is given).
READ_TOOLS = {"read", "glob", "grep", "list", "ls", "lsp", "notebookread", "view"}
# Orchestration / UX tools with no filesystem or network side effects.
NEUTRAL_TOOLS = {"task", "agent", "skill", "todowrite", "todoread", "update_plan", "question",
                 "exitplanmode", "sendmessage", "spawn_agent", "wait", "close_agent", "send_input",
                 "toolsearch", "list_mcp_resources"}
WRITE_TOOLS = {"write", "edit", "multiedit", "apply_patch", "patch", "notebookedit"}
SHELL_TOOLS = {"bash", "shell", "exec_command", "local_shell", "powershell", "unified_exec", "monitor"}
NET_TOOLS = {"webfetch", "websearch", "web_search", "fetch", "browser"}


def deny(reason: str, tool: str = "?") -> None:
    _log("deny", tool, reason)
    sys.stderr.write(f"[sentinel policy] BLOCKED {tool}: {reason}\n")
    sys.exit(2)


def allow(tool: str, reason: str) -> None:
    _log("allow", tool, reason)
    sys.exit(0)


def _log(decision: str, tool: str, reason: str) -> None:
    try:
        from auditor import audit_log
        audit_log.append(ROOT / "audit-output" / "_policy" / "decisions.jsonl", "policy.hook", "hook",
                         {"tool": tool, "reason": reason}, decision)
    except Exception:
        pass  # logging must never turn a deny into an allow


def patch_paths(patch: str) -> list[str]:
    return re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$", patch, re.M) + \
        re.findall(r"^\*\*\* Move to: (.+)$", patch, re.M)


def main() -> None:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw or "{}")
    except Exception:
        deny("unparsable hook input (fail closed)")
    tool = str(event.get("tool_name") or event.get("tool") or "").strip()
    tin = event.get("tool_input") or event.get("args") or {}
    if not isinstance(tin, dict):
        tin = {"value": tin}
    t = tool.lower()
    if not t:
        deny("no tool name (fail closed)")

    try:
        from auditor.policy import check_command, check_read_path, check_write_path
    except Exception as exc:
        deny(f"policy engine unavailable: {exc}", tool)

    if t.startswith("mcp__") or t.startswith("mcp_"):
        allowed = {x.strip().lower() for x in os.environ.get("SENTINEL_ALLOWED_MCP_TOOLS", "").split(",") if x.strip()}
        if t in allowed:
            allow(tool, "explicitly allowlisted MCP tool")
        deny("MCP tools are disabled unless explicitly allowlisted (SENTINEL_ALLOWED_MCP_TOOLS)", tool)

    if t in NET_TOOLS:
        deny("direct web access is disabled; use `python -m auditor fetch <run> <url>` (scope-gated GET/HEAD)", tool)

    if t in SHELL_TOOLS:
        cmd = tin.get("command") or tin.get("cmd") or ""
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        d = check_command(str(cmd))
        allow(tool, d.reason) if d.allow else deny(d.reason, tool)

    if t in WRITE_TOOLS:
        paths: list[str] = []
        for key in ("file_path", "filePath", "path", "notebook_path"):
            if tin.get(key):
                paths.append(str(tin[key]))
        if t in ("apply_patch", "patch"):
            paths += patch_paths(str(tin.get("command") or tin.get("patch") or tin.get("input") or tin.get("patchText") or ""))
        if not paths:
            deny("write without a resolvable path (fail closed)", tool)
        for p in paths:
            d = check_write_path(p.strip())
            if not d.allow:
                deny(d.reason, tool)
        allow(tool, "write inside audit-output/")

    if t in READ_TOOLS:
        for key in ("file_path", "filePath", "path"):
            v = tin.get(key)
            if isinstance(v, str) and (os.sep in v or "/" in v or v.startswith("~") or v.startswith(".")):
                d = check_read_path(v)
                if not d.allow:
                    deny(d.reason, tool)
        allow(tool, "read")

    if t in NEUTRAL_TOOLS:
        allow(tool, "orchestration tool")

    deny(f"unknown tool {tool!r} (fail closed; add it to hooks/policy_guard.py after review)", tool)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # any bug => deny
        sys.stderr.write(f"[sentinel policy] BLOCKED: internal error {exc}\n")
        sys.exit(2)
