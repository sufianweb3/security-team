"""Harness configs stay least-privilege and in sync with harness/agents.yaml; the
codebase contains no exploit-capable code paths (static guard tests)."""
import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
AGENTS = yaml.safe_load((ROOT / "harness" / "agents.yaml").read_text(encoding="utf-8"))["agents"]
NAMES = {a["name"] for a in AGENTS}


def _fm(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, path
    return yaml.safe_load(m.group(1))


def test_generated_configs_in_sync(tmp_path):
    before = {p: p.read_text(encoding="utf-8") for p in (ROOT / ".opencode" / "agents").glob("*.md")}
    subprocess.run([sys.executable, str(ROOT / "scripts" / "setup.py"), "--harness", "all"], check=True,
                   capture_output=True, cwd=str(ROOT))
    after = {p: p.read_text(encoding="utf-8") for p in (ROOT / ".opencode" / "agents").glob("*.md")}
    assert set(before) == set(after)


def test_opencode_agents_least_privilege():
    files = list((ROOT / ".opencode" / "agents").glob("*.md"))
    assert {f.stem for f in files} == NAMES
    for f in files:
        fm = _fm(f)
        perm = fm["permission"]
        assert perm["*"] == "deny", f
        assert perm["webfetch"] == "deny" and perm["websearch"] == "deny", f
        assert perm["edit"]["*"] == "deny" and perm["edit"]["audit-output/**"] == "allow", f
        assert perm["shell"]["*"] == "deny", f
        assert all(k.startswith(("python -m auditor", "python3 -m auditor", "py -m auditor")) for k in perm["shell"] if k != "*"), f
        if fm["mode"] != "primary":
            assert perm["task"] == {"*": "deny"}, f"subagent {f.stem} must not delegate"


def test_only_orchestrator_can_ingest_or_run():
    for f in (ROOT / ".opencode" / "agents").glob("*.md"):
        shell = _fm(f)["permission"]["shell"]
        if f.stem != "sentinel-orchestrator":
            assert not any(" ingest" in k or " run*" in k for k in shell), f


def test_verifier_status_only_for_verifier_and_orchestrator():
    discovery = {"sentinel-recon", "sentinel-web-api", "sentinel-deps"}
    for a in AGENTS:
        if a["name"] in discovery:
            assert "score" not in a["subcommands"] and "financial" not in a["subcommands"]


def test_opencode_json_fail_closed():
    cfg = json.loads((ROOT / "opencode.json").read_text(encoding="utf-8"))
    assert cfg["permission"]["*"] == "deny"
    assert "./.opencode/plugins/sentinel-guard.js" in cfg["plugin"]


def test_claude_settings_hook_and_denies():
    s = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert "WebFetch" in s["permissions"]["deny"] and "Edit(targets/**)" in s["permissions"]["deny"]
    cmd = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "policy_guard.py" in cmd
    for f in (ROOT / ".claude" / "agents").glob("*.md"):
        fm = _fm(f)
        assert fm["name"] in NAMES
        assert "WebFetch" not in fm["tools"] and "WebSearch" not in fm["tools"]


def test_codex_config_parses_and_has_hook():
    cfg = tomllib.loads((ROOT / ".codex" / "config.toml").read_text(encoding="utf-8"))
    assert cfg["default_permissions"] == "sentinel-audit"
    roots = cfg["permissions"]["sentinel-audit"]["filesystem"][":workspace_roots"]
    assert roots["."] == "read" and roots["audit-output"] == "write"
    assert cfg["features"]["network_proxy"] is True
    hooks = json.loads((ROOT / ".codex" / "hooks.json").read_text(encoding="utf-8"))
    assert "policy_guard.py" in hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    for f in (ROOT / ".codex" / "agents").glob("*.toml"):
        a = tomllib.loads(f.read_text(encoding="utf-8"))
        assert a["name"] in NAMES and a["developer_instructions"]


def test_skills_valid_format():
    skills = list((ROOT / ".agents" / "skills").glob("*/SKILL.md"))
    assert len(skills) >= 10
    for p in skills:
        fm = _fm(p)
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", fm["name"]) and len(fm["name"]) <= 64
        assert fm["name"] == p.parent.name
        assert 1 <= len(fm["description"]) <= 1024


# ------------------------------------------------------------ static guards
PKG = ROOT / "auditor"


def _py_files():
    return [p for p in PKG.rglob("*.py")]


def test_no_shell_true_anywhere():
    for p in _py_files() + [ROOT / "hooks" / "policy_guard.py"]:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert isinstance(node.value, ast.Constant) and node.value.value is False, p


def test_no_state_changing_http_methods():
    src = "\n".join(p.read_text(encoding="utf-8") for p in _py_files())
    for verb in ("POST", "PUT", "DELETE", "PATCH"):
        assert not re.search(rf"method\s*=\s*['\"]{verb}['\"]", src), verb
    policy = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text(encoding="utf-8"))
    assert policy["network"]["allowed_methods"] == ["GET", "HEAD"]


def test_no_request_bodies_or_raw_sockets_outside_netguard():
    for p in _py_files():
        text = p.read_text(encoding="utf-8")
        if p.name != "netguard.py":
            assert "urllib.request" not in text and "socket.create_connection" not in text, p
        assert "data=" not in re.sub(r"#.*", "", text).replace("metadata=", ""), p


def test_no_exploit_toggle_in_policy():
    text = (ROOT / "config" / "policy.yaml").read_text(encoding="utf-8").lower()
    for word in ("exploit_enabled", "allow_exploit", "active_mode", "aggressive", "payload_enabled"):
        assert word not in text


def test_tool_allowlist_matches_adapters():
    policy = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text(encoding="utf-8"))
    allowed = set(policy["tools"]["allowlist"])
    src = (PKG / "adapters" / "external.py").read_text(encoding="utf-8") + (PKG / "ingest.py").read_text(encoding="utf-8")
    used = set(re.findall(r'run_tool\(\s*"([a-z-]+)"', src))
    assert used <= allowed, used - allowed
