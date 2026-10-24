# Windows setup

Windows is supported for the engine and all three harnesses. For the strongest isolation we
recommend **WSL2** (Ubuntu) — OpenCode's own docs have a Windows/WSL page, Codex's Linux sandbox
(bubblewrap) is available there, and semgrep is most reliable on Linux.

## Option A — WSL2 (recommended)
```powershell
wsl --install -d Ubuntu
```
Then inside Ubuntu follow docs/SETUP.md exactly. Keep the repo inside the Linux filesystem
(`~/sentinel-auditor`), not `/mnt/c/...`, for performance and correct permission bits.

## Option B — native Windows (PowerShell)
```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
py scripts\install_tools.py          # gitleaks + osv-scanner Windows binaries are pinned; semgrep may be limited natively
py scripts\setup.py --check
py -m pytest
py scripts\setup.py --harness all --profile deepseek --python py
```
Notes:
- `--python py` makes the generated hooks call `py` (Claude Code / Codex hook commands, the
  OpenCode plugin tries `py`, `python`, `python3` automatically or `SENTINEL_PYTHON`).
- Codex hooks get a `commandWindows` entry automatically.
- Read-only snapshots use the Windows read-only attribute (via `os.chmod`); NTFS ACLs are not
  modified. Administrators can still write — run the harness as a normal user.
- Claude Code on Windows needs Git for Windows (per Anthropic/DeepSeek docs).
- If semgrep does not run natively, run the engine in WSL or Docker Desktop (WSL2 backend):
  `docker compose -f docker/docker-compose.yml run --rm auditor run config/scopes/vulnapp-local.yaml`.
- Path separators are normalized by the policy engine; tests run on POSIX in CI — run
  `py -m pytest` on your machine to confirm.
