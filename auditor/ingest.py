"""Input ingestion: create immutable, read-only snapshots of authorized inputs.

* Local directories are copied (never moved), symlinks are NOT followed, size
  limits apply, and the snapshot is chmod'ed read-only.
* Git repositories are fetched at a pinned commit with hardened git options:
  hooks disabled, no submodules, no LFS smudge, no file:// protocol, no
  credential prompts. Nothing in the repository is ever executed.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

from . import audit_log
from .policy import PolicyError, load_policy, project_root, targets_root
from .sandbox import run_tool
from .scope import Scope

HARDENED_GIT = [
    "-c", "core.hooksPath=/dev/null" if os.name != "nt" else "core.hooksPath=NUL",
    "-c", "core.fsmonitor=false",
    "-c", "core.symlinks=false",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "submodule.recurse=false",
    "-c", "fetch.recurseSubmodules=false",
    "-c", "credential.helper=",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false",
    "-c", "uploadpack.allowFilter=true",
]


def _make_read_only(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for f in filenames:
            p = Path(dirpath) / f
            try:
                os.chmod(p, stat.S_IREAD | (stat.S_IRGRP if os.name != "nt" else 0))
            except OSError:
                pass
        try:
            os.chmod(dirpath, stat.S_IREAD | stat.S_IEXEC | (stat.S_IRGRP | stat.S_IXGRP if os.name != "nt" else 0))
        except OSError:
            pass


def _make_writable(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, stat.S_IRWXU)
        for f in filenames:
            try:
                os.chmod(Path(dirpath) / f, stat.S_IREAD | stat.S_IWRITE)
            except OSError:
                pass


def snapshot_dir(src: Path, dest: Path, scope: Scope, log_path: Path) -> dict:
    policy = load_policy()
    lim = policy["ingest"]
    src = src.resolve()
    if not src.is_dir():
        raise PolicyError(f"local path not found: {src}")
    if dest.exists():
        _make_writable(dest)
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    files = total = skipped_links = skipped_big = 0
    manifest = hashlib.sha256()
    skip = set(lim["skip_dirs"])
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip and not (Path(dirpath) / d).is_symlink())
        for name in sorted(filenames):
            sp = Path(dirpath) / name
            rel = sp.relative_to(src).as_posix()
            if sp.is_symlink():
                skipped_links += 1
                continue
            if scope.source_excluded(rel):
                continue
            size = sp.stat().st_size
            if size > lim["max_file_bytes"]:
                skipped_big += 1
                continue
            files += 1
            total += size
            if files > lim["max_files"] or total > lim["max_total_bytes"]:
                raise PolicyError("ingest limits exceeded (files/bytes); narrow the scope")
            dp = dest / rel
            dp.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sp, dp, follow_symlinks=False)
            manifest.update(rel.encode() + b"\0" + hashlib.sha256(dp.read_bytes()).digest())
    if lim["make_read_only"]:
        _make_read_only(dest)
    info = {"files": files, "bytes": total, "skipped_symlinks": skipped_links,
            "skipped_oversize": skipped_big, "content_sha256": manifest.hexdigest()}
    audit_log.append(log_path, "ingest.local", "ingest", {"src": str(src), "dest": str(dest), **info}, "allow")
    return info


def fetch_repo(url: str, commit: str, dest: Path, scope: Scope, log_path: Path) -> dict:
    ok, why = scope.repo_allowed(url)
    if not ok:
        raise PolicyError(why)
    if dest.exists():
        _make_writable(dest)
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    steps = [
        ["init", "--quiet", str(dest)],
        [*HARDENED_GIT, "-C", str(dest), "remote", "add", "origin", url],
        [*HARDENED_GIT, "-C", str(dest), "fetch", "--quiet", "--depth", "1", "--no-tags", "origin", commit],
        [*HARDENED_GIT, "-C", str(dest), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        [*HARDENED_GIT, "-C", str(dest), "rev-parse", "HEAD"],
    ]
    head = ""
    for args in steps:
        res = run_tool("git", args, cwd=project_root(), log_path=log_path, timeout=900)
        if not res.available:
            raise PolicyError("git is not installed")
        if res.returncode != 0:
            raise PolicyError(f"git failed: {res.stderr[-500:]}")
        head = res.stdout.strip()
    if head != commit:
        raise PolicyError(f"checked-out commit {head} != pinned {commit}")
    shutil.rmtree(dest / ".git", ignore_errors=True)  # drop git metadata: nothing executable remains
    _make_read_only(dest)
    audit_log.append(log_path, "ingest.repo", "ingest", {"url": url, "commit": commit}, "allow")
    return {"commit": head}


def ingest_all(scope: Scope, log_path: Path) -> dict:
    """Snapshot every local/spec/doc/repo target into targets/<assessment>/<id>."""
    base = targets_root() / scope.assessment_id
    base.mkdir(parents=True, exist_ok=True)
    out: dict[str, dict] = {}
    t = scope.raw.get("targets") or {}
    root = project_root()
    for kind in ("local_paths", "api_specs", "documents"):
        for item in t.get(kind) or []:
            src = Path(os.path.expanduser(item["path"]))
            if not src.is_absolute():
                src = (scope.path.parent if scope.path else root) / src
            dest = base / item["id"]
            if src.is_file():
                if dest.exists():
                    _make_writable(dest)
                    shutil.rmtree(dest)
                dest.mkdir(parents=True)
                shutil.copyfile(src, dest / src.name, follow_symlinks=False)
                _make_read_only(dest)
                out[item["id"]] = {"kind": kind, "files": 1, "path": str(dest)}
            else:
                out[item["id"]] = {"kind": kind, "path": str(dest), **snapshot_dir(src, dest, scope, log_path)}
    for repo in t.get("repositories") or []:
        dest = base / repo["id"]
        out[repo["id"]] = {"kind": "repository", "path": str(dest),
                           **fetch_repo(repo["url"], repo["commit"], dest, scope, log_path)}
    (base.parent / f"{scope.assessment_id}.ingest.json").parent.mkdir(parents=True, exist_ok=True)
    return out
