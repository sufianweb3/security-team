# Contributing to Sentinel Auditor

Thanks for helping improve Sentinel. This project handles security-sensitive workflows, so
contributions are reviewed with that in mind.

## Ground rules

1. **Never weaken a control to make something work.** The policy hook, harness permissions,
   CLI-only shell surface, read-only snapshots, network guard and audit log are load-bearing.
   If a feature needs a control changed, open an issue to discuss it first.
2. **Keep the tool read-only and passive.** No exploitation, no state-changing requests, no target
   execution, no live credential validation.
3. **No secrets or target data in commits.** Do not commit real scope credentials, tokens,
   customer data, `audit-output/`, `targets/`, or local tool installations.
4. **Evidence over claims.** New agent findings must be verifiable against the snapshot and must
   not self-confirm.

## Development setup

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

pip install -r requirements-dev.txt
python scripts/setup.py --check
python -m pytest
```

All tests must pass before a pull request is ready.

## Changing agents or skills

The canonical definitions are:

- [`harness/agents.yaml`](harness/agents.yaml) — the 12-agent roster, tiers and permissions
- [`harness/skills/`](harness/skills/) — the Agent Skills

Do **not** hand-edit the generated files under `.opencode/`, `.claude/`, `.codex/` or
`.agents/skills/`. Edit the canonical source, then re-render:

```bash
python scripts/setup.py --harness all --profile inherit
```

Add or update a test in `tests/test_harness_and_static_guards.py` when changing permissions or
generated configuration.

## Adding an external tool

External binaries are a security boundary. Follow the approval path in
[docs/SETUP.md](docs/SETUP.md):

1. Review the tool's source, license, permissions and install scripts.
2. Pin the version and SHA-256 in `scripts/install_tools.py`; record it in
   `docs/DEPENDENCIES.md`.
3. Add it to the allowlist in `config/policy.yaml` (human edit; agents cannot write there).
4. Write an adapter in `auditor/adapters/` that builds `argv` itself and parses the output.
5. Add tests, including a static guard if the tool can touch the network or write files.

## Pull request checklist

- [ ] `python -m pytest` passes (155 tests expected).
- [ ] No new network, shell or filesystem capability without a policy and test change.
- [ ] No secrets, real target data or generated audit output included.
- [ ] Documentation updated (`README.md` and/or `docs/`).
- [ ] Changes preserve deterministic output where applicable.
- [ ] Commit messages describe the security impact, not just the code change.

## Reporting a security issue in Sentinel

Please follow [SECURITY.md](SECURITY.md) instead of opening a public issue with exploit details.
