# What was missing or wrong in the original spec — and what we did

| # | Issue in the original brief | Why it matters | What this build does |
|---|---|---|---|
| 1 | OpenCode-only design; you also want Codex/Claude Code | Three hand-written configs drift apart | Canonical `harness/agents.yaml` + `harness/skills/` + `config/models.yaml` rendered per harness by `scripts/setup.py`; a test keeps them in sync |
| 2 | Assumed one permission model works everywhere | Codex subagents **cannot** narrow the parent's sandbox; Claude/OpenCode can | Enforcement moved into the shared CLI + universal hook; gap documented |
| 3 | "Use DeepSeek free models" without ids | Model names change; free tiers aren't guaranteed | Verified current ids (`deepseek-flash`, `deepseek-v4-pro`) and per-harness setup; profiles incl. `inherit` fallback |
| 4 | Codex provider config was implied to be per-project | Codex ignores `model_provider` in project config | Documented user-level setup (MODEL_STRATEGY.md) |
| 5 | Trivy was an obvious SCA candidate | Trivy/trivy-action were compromised in March 2026 (CVE-2026-33634) | Not a default; osv-scanner + pinned SHA-256 installs; GitHub Actions pinning check added |
| 6 | "Run approved tools" didn't consider tools executing target code | osv-scanner Rust call analysis runs build scripts; Slither `--compile` runs build tooling | Call analysis disabled; Slither not default; nothing ever runs `npm/pip/make/tests` |
| 7 | Scanners trust the target's own ignore/config files | A malicious repo can hide its code via `.semgrepignore`, `.gitleaks.toml`, `.gitignore` (we hit the `.gitignore` case for real during the build) | Our own gitleaks config + empty ignore path + `--ignore-gitleaks-allow`; semgrep `--no-git-ignore --x-ignore-semgrepignore-files`; osv `--no-ignore`; adversarial fixture + test |
| 8 | Git ingestion safety unspecified | Clone can trigger hooks, LFS filters, submodules, file:// tricks | Hardened git flags, pinned commit required, `.git` removed after checkout |
| 9 | "Multiple agents agree" risk was stated but not enforced | Prompts alone don't stop it | CLI rejects consensus as a basis and rejects self-verification by the author |
| 10 | Evidence standard had no mechanism | LLMs fabricate line numbers and excerpts | Every excerpt is checked against the immutable snapshot; fake files rejected, fake excerpts demoted |
| 11 | Severity/zone rules undefined at edges | Everything drifts to RED | Explicit rules: critical needs CVSS; header-only ≤ low; RED needs verified strong evidence; NOT_ASSESSED zone added so uncovered ≠ green |
| 12 | Financial estimates could still be invented | Big numbers look impressive | Validator rejects unsourced inputs, full-TVL style assumptions, high-confidence scenarios |
| 13 | Prompt injection from target content not addressed | Repos/web pages can instruct the agent | Capability-based controls make injected instructions inert (THREAT_MODEL.md) |
| 14 | HTTP "read-only" was undefined | Some GETs change state; redirects escape scope; SSRF to metadata | GET/HEAD only, no bodies/auth headers, scope re-check on every redirect, private/metadata IP block, tiny budgets, per-host rate limit |
| 15 | Bug bounty: automated scanning often prohibited | Getting banned / legal risk | Passive web is opt-in, budgeted, program `prohibited_tests` recorded; submission always manual |
| 16 | No audit-trail integrity | Can't prove what the tool did | Hash-chained, redacted audit log with verify command |
| 17 | "Windows primary" but tools differ on Windows | semgrep is most reliable on Linux | WSL2 recommended path + native path documented; hook commands have Windows variants |
| 18 | Report could imply security on GREEN | Misleading | Mandatory disclaimer; GREEN only for covered components |
| 19 | No deterministic mode spec | Models fail/are unavailable | `python -m auditor run` produces a full report with zero model calls |
| 20 | 11 agents (12 since v0.3 with sentinel-business-impact) may be over-engineering | Cost & coordination | Kept the 11 roles you asked for, but recon/web/deps/secrets/report run on the cheap tier and the orchestrator only dispatches what the inventory recommends |
