# Setup & operation

## Requirements
- Python 3.11+ (tested 3.12)
- At least one harness: OpenCode, Claude Code, or Codex (any recent version)
- Optional tools (strongly recommended): semgrep 1.182.1, bandit 1.9.4, gitleaks 8.30.1,
  osv-scanner 2.7.0 — install with `python scripts/install_tools.py` (pinned + SHA-256 checked).
  semgrep and bandit have conflicting dependencies, so the installer puts them in an isolated
  venv under `tools/` (we hit this conflict while building).

## Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/install_tools.py          # optional
python scripts/setup.py --check
python -m pytest
python scripts/setup.py --harness all --profile deepseek
```

## Running
Deterministic only (no LLM): `python -m auditor run <scope.yaml>`

Agent-driven:
- **OpenCode**: `opencode` → Tab to `sentinel-orchestrator` → "Run the sentinel-run-audit skill on config/scopes/x.yaml".
- **Claude Code**: `claude --agent sentinel-orchestrator` → same prompt. Accept the workspace trust prompt (needed for hooks).
- **Codex**: trust the project, approve the hook in `/hooks`, then `$sentinel-run-audit config/scopes/x.yaml`.

Step-by-step CLI (what agents call):
```
python -m auditor scope validate <scope>
python -m auditor ingest <scope>                       # → run id
python -m auditor tools run <run>
python -m auditor findings add <run> --agent <name> --file <run_dir>/candidates/<name>.json
python -m auditor findings list <run> [--zone RED] [--status potential]
python -m auditor findings set-status <run> <id> --reviewer sentinel-verifier --status ... --rationale "..."
python -m auditor findings set-cvss <run> <id> --vector "CVSS:3.1/..." --rationale "..."
python -m auditor financial set <run> <id> --file <run_dir>/candidates/fin-<id>.json
python -m auditor report <run>
python -m auditor log verify <run>
```

## Outputs (`audit-output/<assessment>/<run>/`)
`report.json` (schema-valid), `report.md`, `report.html` (self-contained, CSP-locked),
`bounty/<id>.md`, `findings.json` (ledger incl. rejected candidates), `inventory/`,
`work/` (raw tool output), `observations/` (HTTP observations), `audit-log.jsonl` (+ verify result).

## Docker (optional isolation for the engine + tools)
```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm auditor run config/scopes/vulnapp-local.yaml
docker compose -f docker/docker-compose.yml run --rm auditor-offline run config/scopes/vulnapp-local.yaml
```
Inputs/config are mounted read-only; only `targets/` and `audit-output/` are writable; caps are
dropped; the offline profile has no network. Docker cannot filter egress by domain — add an
egress proxy for that (see THREAT_MODEL.md).

## Adding a tool or integration (explicit approval path)
1. Review the tool's source, license, permissions and install scripts.
2. Pin version + SHA-256 in `scripts/install_tools.py`; record it in `docs/DEPENDENCIES.md`.
3. Add it to `config/policy.yaml > tools.allowlist` (human edit; agents cannot write there).
4. Write an adapter in `auditor/adapters/` that builds argv itself and parses output.
5. Add tests (including a static guard if it can touch the network).
