"""Central policy loading and the deterministic decision functions shared by the
CLI and the harness hook. Everything here is pure / side-effect free so it can
be unit tested without any LLM or harness in the loop."""
from __future__ import annotations

import fnmatch
import os
import shlex
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = PROJECT_ROOT / "config" / "policy.yaml"


class PolicyError(Exception):
    """Raised when an action is denied by policy (fail closed)."""


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allow


@lru_cache(maxsize=4)
def load_policy(path: str | None = None) -> dict[str, Any]:
    p = Path(path) if path else POLICY_PATH
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception as exc:  # fail closed
        raise PolicyError(f"policy unreadable: {exc}") from exc
    if not isinstance(data, dict) or data.get("mode") != "read_only":
        raise PolicyError("policy missing or mode != read_only")
    return data


def project_root() -> Path:
    env = os.environ.get("SENTINEL_ROOT")
    return Path(env).resolve() if env else PROJECT_ROOT


def output_root(policy: dict | None = None) -> Path:
    policy = policy or load_policy()
    return (project_root() / policy["paths"]["output_dir"]).resolve()


def targets_root(policy: dict | None = None) -> Path:
    policy = policy or load_policy()
    return (project_root() / policy["paths"]["targets_dir"]).resolve()


def _rel_posix(path: str | os.PathLike, root: Path) -> str | None:
    """Return path relative to root (posix style) or None if outside root."""
    try:
        p = Path(os.path.expanduser(str(path)))
        if not p.is_absolute():
            p = root / p
        resolved = Path(os.path.normpath(str(p)))
        # resolve symlinks of the existing part to stop symlink escapes
        existing = resolved
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        real_prefix = existing.resolve()
        tail = resolved.relative_to(existing) if existing != resolved else Path()
        final = real_prefix / tail
        return PurePosixPath(final.relative_to(root.resolve()).as_posix()).as_posix()
    except (ValueError, OSError):
        return None


def _glob_match(rel: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        base = pattern[:-3]
        return rel == base or rel.startswith(base + "/")
    return fnmatch.fnmatchcase(rel, pattern)


def check_write_path(path: str | os.PathLike, policy: dict | None = None) -> Decision:
    """A write is allowed only inside output_dir and never into a protected path."""
    policy = policy or load_policy()
    root = project_root()
    rel = _rel_posix(path, root)
    if rel is None:
        return Decision(False, f"write outside project root denied: {path}")
    for pat in policy["paths"]["protected"]:
        if _glob_match(rel, pat):
            return Decision(False, f"write to protected path denied: {rel} (matches {pat})")
    out = policy["paths"]["output_dir"].rstrip("/")
    if rel == out or rel.startswith(out + "/"):
        return Decision(True, "inside output_dir")
    return Decision(False, f"writes are only allowed under {out}/ (got {rel})")


def check_read_path(path: str | os.PathLike, policy: dict | None = None) -> Decision:
    policy = policy or load_policy()
    raw = str(path)
    expanded = os.path.normpath(os.path.expanduser(raw)).replace("\\", "/")
    root = project_root()
    rel = _rel_posix(raw, root)
    tdir = policy["paths"]["targets_dir"].rstrip("/")
    in_targets = rel is not None and (rel == tdir or rel.startswith(tdir + "/"))
    for pat in policy["paths"]["sensitive_read_deny"]:
        if pat.startswith("**/") and in_targets:
            continue  # target .env files are in scope (secrets adapter redacts)
        pat_exp = os.path.normpath(os.path.expanduser(pat)).replace("\\", "/")
        if pat.startswith("**/"):
            if fnmatch.fnmatchcase(expanded, "*/" + pat[3:]) or fnmatch.fnmatchcase(os.path.basename(expanded), pat[3:]):
                return Decision(False, f"read of sensitive file denied: {raw}")
        elif _glob_match(expanded, pat_exp) or fnmatch.fnmatchcase(expanded, pat_exp):
            return Decision(False, f"read of host credential path denied: {raw}")
        elif pat.startswith("~/") and not in_targets:
            # home-agnostic: block the same credential location under ANY home directory
            tail = pat[2:]
            if tail.endswith("/**"):
                if f"/{tail[:-3]}/" in f"/{expanded}/" or expanded.endswith("/" + tail[:-3]):
                    return Decision(False, f"read of credential path denied: {raw}")
            elif expanded.endswith("/" + tail) or expanded == tail:
                return Decision(False, f"read of credential path denied: {raw}")
    return Decision(True, "read allowed")


def check_command(command: str, policy: dict | None = None,
                  allowed_subcommands: list[str] | None = None) -> Decision:
    """Shell commands are allowed only if they invoke the auditor CLI with an
    allowed sub-command and contain no chaining / redirection metacharacters."""
    policy = policy or load_policy()
    if not isinstance(command, str) or not command.strip():
        return Decision(False, "empty command")
    cmd = command.strip()
    for bad in policy["commands"]["forbidden_substrings"]:
        if bad in cmd:
            return Decision(False, f"shell metacharacter {bad!r} not allowed")
    prefix = next((p for p in policy["commands"]["allowed_prefixes"] if cmd.startswith(p)), None)
    if prefix is None:
        return Decision(False, "only 'python -m auditor <subcommand>' may be executed")
    try:
        argv = shlex.split(cmd, posix=True)
    except ValueError as exc:
        return Decision(False, f"unparsable command: {exc}")
    if len(argv) < 4:
        return Decision(False, "missing auditor subcommand")
    sub = argv[3]
    allowed = allowed_subcommands or policy["commands"]["allowed_subcommands"]
    if sub not in allowed:
        return Decision(False, f"auditor subcommand {sub!r} not allowed")
    return Decision(True, f"auditor {sub} allowed")


def require(decision: Decision) -> None:
    if not decision.allow:
        raise PolicyError(decision.reason)


def safe_output_path(*parts: str, policy: dict | None = None) -> Path:
    """Build a path under output_dir, refusing traversal. Used by every writer."""
    policy = policy or load_policy()
    base = output_root(policy)
    for part in parts:
        segs = str(part).replace("\\", "/").split("/")
        if (not part or os.path.isabs(str(part)) or ":" in str(part)
                or any(s in ("", ".", "..") for s in segs)):
            raise PolicyError(f"illegal path component: {part!r}")
    candidate = base.joinpath(*parts)
    require(check_write_path(candidate, policy))
    resolved = Path(os.path.normpath(str(candidate)))
    if base not in resolved.parents and resolved != base:
        raise PolicyError(f"path escapes output dir: {candidate}")
    return resolved
