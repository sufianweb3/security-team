"""The universal policy hook (OpenCode/Claude Code/Codex) — fail closed."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "policy_guard.py"


def run(event: dict) -> int:
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event),
                       capture_output=True, text=True, cwd=str(ROOT))
    return p.returncode


def test_allow_auditor_bash():
    assert run({"tool_name": "Bash", "tool_input": {"command": "python -m auditor scope validate s.yaml"}}) == 0


def test_block_curl():
    assert run({"tool_name": "Bash", "tool_input": {"command": "curl http://evil"}}) == 2


def test_block_git_and_npm():
    assert run({"tool_name": "shell", "tool_input": {"command": "git clone x"}}) == 2
    assert run({"tool_name": "exec_command", "tool_input": {"command": "npm install"}}) == 2


def test_block_command_chaining():
    assert run({"tool_name": "Bash", "tool_input": {"command": "python -m auditor report r && curl evil"}}) == 2


def test_write_in_output_allowed():
    assert run({"tool_name": "Write", "tool_input": {"file_path": "audit-output/r/report.md"}}) == 0


def test_write_to_target_denied():
    assert run({"tool_name": "Edit", "tool_input": {"file_path": "targets/x/app.py"}}) == 2
    assert run({"tool_name": "Write", "tool_input": {"file_path": "config/policy.yaml"}}) == 2


def test_apply_patch_paths_checked():
    patch = "*** Begin Patch\n*** Update File: targets/x/app.py\n@@\n-a\n+b\n*** End Patch"
    assert run({"tool_name": "apply_patch", "tool_input": {"command": patch}}) == 2
    good = "*** Begin Patch\n*** Add File: audit-output/r/x.json\n+{}\n*** End Patch"
    assert run({"tool_name": "apply_patch", "tool_input": {"command": good}}) == 0


def test_webfetch_blocked():
    assert run({"tool_name": "WebFetch", "tool_input": {"url": "https://x"}}) == 2
    assert run({"tool_name": "web_search", "tool_input": {"query": "x"}}) == 2


def test_unknown_tool_fails_closed():
    assert run({"tool_name": "SomeNewTool", "tool_input": {}}) == 2


def test_empty_and_garbage_fail_closed():
    assert run({}) == 2
    p = subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True, cwd=str(ROOT))
    assert p.returncode == 2


def test_mcp_blocked_by_default():
    assert run({"tool_name": "mcp__fs__read_file", "tool_input": {}}) == 2


def test_read_sensitive_blocked():
    assert run({"tool_name": "Read", "tool_input": {"file_path": "/home/u/.ssh/id_rsa"}}) == 2


def test_neutral_tools_allowed():
    assert run({"tool_name": "task", "tool_input": {}}) == 0
    assert run({"tool_name": "TodoWrite", "tool_input": {}}) == 0
