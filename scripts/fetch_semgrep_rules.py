#!/usr/bin/env python3
"""Optionally install a pinned copy of the community semgrep rules into tools/semgrep-rules.
Review before running. Clones ONE pinned commit over https with git hooks disabled, then
removes the .git directory so nothing executable remains. Set the commit in PIN after
reviewing it. Without this, the auditor uses only the small bundled rules/semgrep pack."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "tools" / "semgrep-rules"
REPO = "https://github.com/semgrep/semgrep-rules"
PIN = "REPLACE_WITH_REVIEWED_COMMIT_SHA"  # pin a specific reviewed commit; do not track a branch

HARDENED = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
            "-c", "submodule.recurse=false", "-c", "credential.helper="]


def main() -> int:
    if PIN.startswith("REPLACE"):
        print("Edit scripts/fetch_semgrep_rules.py and set PIN to a reviewed commit SHA first.")
        return 2
    if DEST.exists():
        print(f"{DEST} already exists; remove it to re-fetch.")
        return 0
    DEST.mkdir(parents=True)
    for args in (["init", "-q", str(DEST)],
                 [*HARDENED, "-C", str(DEST), "remote", "add", "origin", REPO],
                 [*HARDENED, "-C", str(DEST), "fetch", "-q", "--depth", "1", "origin", PIN],
                 [*HARDENED, "-C", str(DEST), "checkout", "-q", "--detach", "FETCH_HEAD"]):
        if subprocess.run(["git", *args]).returncode != 0:
            return 1
    import shutil
    shutil.rmtree(DEST / ".git", ignore_errors=True)
    print(f"Installed semgrep rules at {DEST}. Set SEMGREP_RULES_DIR or leave default.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
