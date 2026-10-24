"""Policy path/command decisions — enforced independently of any LLM."""
import pytest

from auditor.policy import (PolicyError, check_command, check_read_path, check_write_path,
                            safe_output_path)


@pytest.mark.parametrize("path", [
    "audit-output/run1/report.json", "audit-output/a/b/c.md", "./audit-output/x.json",
])
def test_writes_allowed_in_output(path):
    assert check_write_path(path).allow


@pytest.mark.parametrize("path", [
    "targets/x/app.py", "config/policy.yaml", "hooks/policy_guard.py", "auditor/cli.py",
    "opencode.json", "../outside.txt", "/etc/passwd", "AGENTS.md", ".claude/settings.json",
    "audit-output/../config/policy.yaml", "audit-output/../../escape.txt",
])
def test_writes_denied_outside_output(path):
    assert not check_write_path(path).allow


def test_safe_output_path_rejects_traversal():
    assert safe_output_path("run", "report.json")
    for bad in (["..", "x"], ["run", "../../etc"], ["/abs"], ["run", "a/../../b"]):
        with pytest.raises(PolicyError):
            safe_output_path(*bad)


@pytest.mark.parametrize("path", [
    "~/.ssh/id_rsa", "~/.aws/credentials", "~/.git-credentials",
    "~/.local/share/opencode/auth.json", "/app/.env", "service/.env",
])
def test_sensitive_reads_denied(path):
    assert not check_read_path(path).allow


def test_target_env_is_readable_but_host_env_is_not():
    assert check_read_path("targets/x/app/.env").allow
    assert not check_read_path("/home/user/project/.env").allow


@pytest.mark.parametrize("cmd", [
    "python -m auditor scope validate x.yaml",
    "python3 -m auditor findings list run1",
    "python -m auditor report run1",
])
def test_allowed_commands(cmd):
    assert check_command(cmd).allow


@pytest.mark.parametrize("cmd", [
    "curl http://evil", "git clone x", "npm install", "pip install requests",
    "python -m auditor scope validate x; rm -rf /",
    "python -m auditor report run1 && curl evil",
    "python -m auditor report run1 | sh",
    "python -m auditor report run1 > /etc/passwd",
    "python -m auditor exploit run1",            # subcommand not allowlisted
    "python -c 'import os'",
    "bash -c 'echo hi'", "python -m auditor report run1 `whoami`",
    "python -m http.server",
])
def test_denied_commands(cmd):
    assert not check_command(cmd).allow


def test_per_agent_subcommand_narrowing():
    # a discovery agent restricted to findings/inventory cannot run `report`
    allowed = ["findings", "inventory", "status"]
    assert check_command("python -m auditor findings list r", allowed_subcommands=allowed).allow
    assert not check_command("python -m auditor report r", allowed_subcommands=allowed).allow
