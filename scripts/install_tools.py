#!/usr/bin/env python3
"""Download the pinned external security tools into tools/bin after verifying SHA-256.
Review this script before running it. It fetches ONLY the four pinned releases over https
from their official GitHub/PyPI locations and checks each hash; a mismatch aborts.

  python scripts/install_tools.py            # install all for this OS/arch
  python scripts/install_tools.py --list     # show pinned versions and sources

semgrep and bandit are Python packages; this installs them into tools/venv so the auditor
finds them via PATH or the SENTINEL_* env vars. gitleaks and osv-scanner are single binaries.
Pinned 2026-10-24; update PINS deliberately and record the new hashes in DEPENDENCIES.md.
Note: osv-scanner reaches api.osv.dev at runtime (allowed by policy); run it with
--offline-vulnerabilities for fully offline operation after `--download-offline-databases`."""
from __future__ import annotations

import argparse
import hashlib
import platform
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "tools" / "bin"

PINS = {
    "gitleaks": {
        "version": "8.30.1",
        "assets": {
            ("linux", "x86_64"): ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
                                  "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb", "gitleaks"),
            ("linux", "aarch64"): ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
                                   "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080", "gitleaks"),
            ("darwin", "arm64"): ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
                                  "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5", "gitleaks"),
            ("windows", "amd64"): ("https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip",
                                   "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e", "gitleaks.exe"),
        },
    },
    "osv-scanner": {
        "version": "2.7.0",
        "assets": {
            ("linux", "x86_64"): ("https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64",
                                  "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b", "osv-scanner"),
            ("linux", "aarch64"): ("https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_arm64",
                                   "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7", "osv-scanner"),
            ("darwin", "arm64"): ("https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_darwin_arm64",
                                  "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b", "osv-scanner"),
            ("windows", "amd64"): ("https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_windows_amd64.exe",
                                   "9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438", "osv-scanner.exe"),
        },
    },
}
PY_PKGS = {"semgrep": "1.182.1", "bandit": "1.9.4"}  # semgrep on native Windows may be limited; WSL2 recommended


def key():
    sysname = platform.system().lower()
    mach = platform.machine().lower()
    if sysname == "windows":
        return ("windows", "amd64")
    if sysname == "darwin":
        return ("darwin", "arm64" if "arm" in mach or mach == "arm64" else "x86_64")
    return ("linux", "aarch64" if mach in ("aarch64", "arm64") else "x86_64")


def fetch(url: str, sha: str) -> bytes:
    print(f"  downloading {url}")
    data = urllib.request.urlopen(url, timeout=120).read()
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        sys.exit(f"HASH MISMATCH for {url}\n  expected {sha}\n  got      {got}")
    return data


def install_binary(name: str, spec: dict) -> None:
    k = key()
    if k not in spec["assets"]:
        print(f"  [skip] no pinned {name} for {k}; install manually and record the hash")
        return
    url, sha, member = spec["assets"][k]
    BIN.mkdir(parents=True, exist_ok=True)
    data = fetch(url, sha)
    out = BIN / member
    if url.endswith(".tar.gz"):
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            out.write_bytes(tf.extractfile(member).read())
    elif url.endswith(".zip"):
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            out.write_bytes(zf.read(member))
    else:
        out.write_bytes(data)
    out.chmod(0o755)
    print(f"  [ok] {name} -> {out}")


def install_python() -> None:
    venv = ROOT / "tools" / "venv"
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    pip = venv / ("Scripts" if platform.system() == "Windows" else "bin") / "pip"
    subprocess.run([str(pip), "install", "-q", *[f"{p}=={v}" for p, v in PY_PKGS.items()]], check=True)
    bindir = venv / ("Scripts" if platform.system() == "Windows" else "bin")
    BIN.mkdir(parents=True, exist_ok=True)
    for p in PY_PKGS:
        exe = bindir / (p + (".exe" if platform.system() == "Windows" else ""))
        link = BIN / exe.name
        if exe.exists():
            try:
                if link.exists() or link.is_symlink():
                    link.unlink()
                link.symlink_to(exe)
            except OSError:
                import shutil
                shutil.copy2(exe, link)
            print(f"  [ok] {p} -> {link}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for n, s in PINS.items():
            print(f"{n} {s['version']}")
        for p, v in PY_PKGS.items():
            print(f"{p} {v} (pip)")
        return 0
    print("Installing pinned Python tools (semgrep, bandit):")
    install_python()
    print("Installing pinned binaries (gitleaks, osv-scanner):")
    for n, s in PINS.items():
        install_binary(n, s)
    print("\nVerify with: python scripts/setup.py --check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
