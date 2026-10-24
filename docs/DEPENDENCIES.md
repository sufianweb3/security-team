# Dependency inventory & licensing

Nothing third-party is bundled in this zip except references. Versions verified 2026-10-24.

## Runtime (Python, pip)
| Package | Version | License | Purpose | Source |
|---|---|---|---|---|
| PyYAML | 6.0.3 | MIT | YAML parsing (scope/policy/specs; `safe_load` only) | https://pypi.org/project/PyYAML/ |
| jsonschema | 4.26.0 | MIT | Schema validation (scope, finding, report) | https://pypi.org/project/jsonschema/ |
| pytest (dev) | 9.1.1 | MIT | Tests | https://pypi.org/project/pytest/ |

## External analysis tools (allowlisted in `config/policy.yaml`)
| Tool | Version | License | Purpose | Network | Pin / hash source |
|---|---|---|---|---|---|
| semgrep (CE) | 1.182.1 | LGPL-2.1 (engine) | SAST with local rules; `--metrics=off` | none (local rules only) | PyPI pin in `scripts/install_tools.py` |
| bandit | 1.9.4 | Apache-2.0 | Python SAST | none | PyPI pin |
| gitleaks | 8.30.1 | MIT | Secret detection (`--redact`) | none | SHA-256 from official `gitleaks_8.30.1_checksums.txt` (linux x64 `551f6f…1766`, arm64 `e4a487…b080`, windows x64 `d29144…c4e`) |
| osv-scanner | 2.7.0 | Apache-2.0 | SCA against OSV.dev; `--no-resolve`, call analysis disabled | `api.osv.dev` (or offline DB) | SHA-256 from official `osv-scanner_SHA256SUMS` (linux amd64 `160c62…218b`, arm64 `4061ef…d7`, windows amd64 `9964ed…8438`) |
| git | system | GPL-2.0 | Repository snapshot at pinned commit (hardened flags) | scope repo hosts | system package |

The gitleaks/osv-scanner hashes were cross-checked in the build environment: the downloaded
linux-arm64 artifacts matched the vendors' published checksums.

### Semgrep rules
- `rules/semgrep/sentinel-core.yaml` — written for this project, MIT.
- Optional community rules (`scripts/fetch_semgrep_rules.py`) come from
  https://github.com/semgrep/semgrep-rules under the **Semgrep Rules License v1.0**, which
  restricts some commercial/SaaS uses. Review it before use; they are not bundled.

## Evaluated but not enabled by default
| Tool | Why not default |
|---|---|
| Trivy | Supply-chain compromise in March 2026 (CVE-2026-33634: malicious v0.69.4, hijacked trivy-action/setup-trivy tags); later 0.71.0 fixes for path traversal / zip-bomb issues. Add only pinned by hash at ≥0.71.0 if container/IaC scanning is needed. |
| TruffleHog | AGPL-3.0 and its strength (live verification) is a prohibited action here. |
| Slither | AGPL-3.0; useful for Solidity — run manually/optionally. Its `--compile` path invokes build tooling, which conflicts with "never run target build steps"; only use on pre-compiled artifacts or without compilation. |
| zizmor | MIT GitHub Actions auditor — good candidate for v0.3 (builtin GHA checks cover the basics now). |
| Syft / Grype | Apache-2.0 SBOM/SCA; overlaps osv-scanner for v1. |
| OpenSSF Scorecard | Calls GitHub APIs about the repo owner's settings; useful for provenance, needs a token; out of v1 scope. |
| MCP servers | No MCP server is required; MCP tools are blocked by default by the hook (`SENTINEL_ALLOWED_MCP_TOOLS` to allow after review). |

## Harnesses (user-installed, not bundled)
OpenCode (https://opencode.ai, repo https://github.com/anomalyco/opencode), Claude Code
(https://docs.anthropic.com/en/docs/claude-code), Codex (https://developers.openai.com/codex).
