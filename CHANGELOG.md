# Changelog

## Unreleased
- Deterministic ordering of candidate findings before ingestion, so repeated runs produce stable
  finding ids when a scanner reports overlapping secrets in varying order.
- Windows portability for the test suite (UTF-8 file reads; no `os.geteuid` assumption). All 155
  tests now pass on Windows as well as Linux.

## 0.3.0 (2026-10-24)
- New agent `sentinel-business-impact` and skill `sentinel-business-impact`: a separate
  **business priority (P1–P5)** per finding answering "how much does this matter to this
  organization?", with a submission recommendation (do_not_submit / needs_more_evidence /
  manual_review / low_value / candidate_for_manual_submission).
- New optional scope block `business_context` (asset tiers, data classes, environment,
  internet exposure, program severity table, out-of-scope impacts, per-tier caps).
- New engine module `auditor/business.py` and CLI `python -m auditor business context|show|set`.
  Code-enforced rules: automatic modifiers only lower; a reviewer may raise by at most one step
  and only for verified, ≥ medium findings on high/critical assets with declared high-value data
  and a known context source; P1 needs a CVSS vector; asset caps always apply; reviewer must be
  independent of the author; business fields in candidate findings are stripped.
- Reports (JSON/Markdown/HTML) and bounty drafts show business priority, program rating and the
  recommendation; findings sort by zone, then business priority.
- 20 new tests (155 total).

## 0.2.0 (2026-10-24)
- Initial release: read-only multi-agent auditor for OpenCode, Claude Code and Codex.
