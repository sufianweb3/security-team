"""Execution of allowlisted external tools. shell=False, scrubbed environment,
timeouts, output caps, audit logging. Agents never construct argv: adapters do."""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from . import audit_log
from .policy import PolicyError, load_policy, project_root


@dataclass
class ToolResult:
    tool: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    available: bool = True


def find_tool(name: str) -> str | None:
    """Locate an allowlisted binary. Prefers project-local tools/bin (pinned install)."""
    policy = load_policy()
    if name not in policy["tools"]["allowlist"]:
        raise PolicyError(f"tool {name!r} is not allowlisted")
    local_bin = project_root() / "tools" / "bin"
    for cand in (name, name + ".exe", name + ".cmd"):
        p = local_bin / cand
        if p.exists():
            return str(p)
    env_override = os.environ.get(f"SENTINEL_{name.upper().replace('-', '_')}")
    if env_override and Path(env_override).exists():
        return env_override
    return shutil.which(name)


def scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    policy = load_policy()
    keep = set(policy["tools"]["env_passthrough"])
    env = {k: v for k, v in os.environ.items() if k in keep}
    # Defensive: tools must never inherit tokens or cloud credentials.
    env.update({
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "NO_COLOR": "1",
    })
    if extra:
        env.update(extra)
    return env


def run_tool(name: str, args: list[str], *, cwd: Path, log_path: Path,
             timeout: int | None = None, extra_env: dict[str, str] | None = None) -> ToolResult:
    policy = load_policy()
    exe = find_tool(name)
    if not exe:
        audit_log.append(log_path, "tool.unavailable", "sandbox", {"tool": name}, "skip")
        return ToolResult(name, [name, *args], 127, "", f"{name} not installed", 0.0, available=False)
    for a in args:
        if not isinstance(a, str) or "\x00" in a:
            raise PolicyError("invalid argument")
    argv = [exe, *args]
    timeout = timeout or int(policy["tools"]["default_timeout_seconds"])
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd), env=scrubbed_env(extra_env), shell=False,
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                              check=False)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc, out, err = 124, exc.stdout or b"", (exc.stderr or b"") + b"\n[timeout]"
    cap = int(policy["tools"]["max_output_bytes"])
    res = ToolResult(name, argv, rc, out[:cap].decode("utf-8", "replace"),
                     err[:cap].decode("utf-8", "replace"), round(time.monotonic() - start, 2))
    audit_log.append(log_path, "tool.run", "sandbox",
                     {"tool": name, "args": args, "rc": rc, "seconds": res.seconds}, "allow")
    return res
