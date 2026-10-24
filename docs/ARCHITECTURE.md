# Architecture

Sentinel Auditor separates two layers:

1. **A deterministic Python engine (`auditor/`)** that holds every security control and all
   non-LLM analysis. It is fully testable without any model.
2. **A thin agent/harness layer** (OpenCode / Claude Code / Codex) that supplies *reasoning*
   — the findings that pattern tools cannot produce (authorization logic, business-logic
   invariants, cross-file data flow, false-positive triage) — and nothing else. Agents act
   only by calling the engine's CLI.

The models are interchangeable reasoning engines, **not** a security boundary. Everything that
must be true for safety is enforced below the model.

## Component responsibilities (`auditor/`)
| Module | Responsibility |
|---|---|
| `policy.py` | Loads `config/policy.yaml`; pure decision fns for write/read paths, commands, safe output paths. Used by CLI and the hook. |
| `scope.py` | Scope schema validation; host/URL/repo in-scope checks; network-mode decision (fail closed to offline). |
| `ingest.py` | Read-only snapshots: copy local dirs (no symlink follow, size caps, chmod read-only); fetch git repos at a pinned commit with hardened flags, then strip `.git`. Never executes target code. |
| `inventory.py` | Passive inventory: languages, frameworks, manifests/lockfiles, specs, IaC, CI, entry points, contracts, and an explicit "not inspected" list. |
| `sandbox.py` | Runs only allowlisted tools, `shell=False`, scrubbed env, timeouts, output caps, audit-logged. Agents never build argv. |
| `adapters/` | `external.py` (semgrep, bandit, gitleaks, osv-scanner) and `builtin.py` (supply-chain, OpenAPI, passive web headers, fallback secrets). Each returns findings + coverage. |
| `netguard.py` | The only network egress. GET/HEAD only, https, scope-gated, SSRF-hardened (DNS→public-IP check), redirect re-checking, per-host rate limit, request budget, no bodies/auth headers. |
| `findings.py` | Finding ledger: schema validation, excerpt verification against the snapshot, dedup/merge, verification-status rules (no self-confirm, no consensus), scoring. |
| `risk.py` | CVSS v3.1 base score, severity normalization + caps, confidence derivation, RED/YELLOW/GREEN zoning. |
| `financial.py` | Evidence-based financial exposure validation (rejects full-TVL assumptions, unsourced inputs, over-confident scenarios). |
| `report.py` | JSON/Markdown/HTML reports + bug-bounty drafts; writes only under the run dir. |
| `audit_log.py` | Append-only, hash-chained, redacted JSONL audit log with verification. |
| `pipeline.py` | Orchestrates a run; also the per-step building blocks agents call. |
| `cli.py` | `python -m auditor` — the only shell surface agents may use. |

## Data flow
```
scope.yaml ──validate──► ingest ──► targets/<a>/<id>/ (immutable, read-only)
                                     │
                     inventory ◄─────┤
                                     ▼
       deterministic analyzers: semgrep · bandit · gitleaks · osv-scanner
                                  builtin: supply-chain · openapi · web(passive)
                                     │ candidate findings (+ coverage)
                                     ▼
  agents add reasoning findings ──► findings ledger (evidence verified vs snapshot)
                                     │
            sentinel-verifier (independent) sets verification status
            sentinel-severity sets CVSS + financial exposure
            sentinel-business-impact sets business priority (P1-P5) from scope business_context
                                     ▼
                        score (zone/severity/confidence)
                                     ▼
    audit-output/<a>/<run>/ : report.json · report.md · report.html · bounty/*.md · audit-log.jsonl
```

## Why this shape (ADR summary)
Full ADR: [ADR-001-architecture.md](ADR-001-architecture.md). In short:
- **Single CLI as the agent's only tool** gives one choke point to allow/deny and audit, and
  means the same behaviour across all three harnesses.
- **Deterministic baseline that needs no model** guarantees a useful, reproducible report even
  when models are unavailable or wrong, and gives tests a ground truth.
- **Evidence verified against an immutable snapshot** is what stops "impressive-looking" AI
  findings: a claim that can't be matched to real code is demoted or rejected automatically.
- **No microservices / DB / queue**: a single-process engine + files is enough for v1 and is
  far easier to secure and reason about. Added only on demonstrated need.

## Trust boundaries
See [THREAT_MODEL.md](THREAT_MODEL.md). The sharp lines are: target materials are untrusted
input (never executed); the model's output is untrusted until its evidence is verified; the
network is default-deny; writes are confined to `audit-output/`.
