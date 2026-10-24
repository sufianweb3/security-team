---
name: sentinel-financial-exposure
description: "Produce an evidence-based potential financial exposure estimate for a finding, or state that it cannot be reliably quantified. Use when a finding touches money, balances, transfers, refunds, credits, or business continuity."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Financial exposure

Hierarchy: disclosure > cited_scale > scenario > unknown. If you lack sourced inputs, the
answer is: "Financial exposure cannot be reliably quantified from the available evidence."

Estimate JSON (write under the run dir, submit with
`python -m auditor financial set <run> <id> --file <run_dir>/candidates/fin-<id>.json`):
```json
{"method": "scenario", "category": "fraudulent_credit", "loss_type": "direct_loss",
 "currency": "USD", "time_horizon": "per abuse campaign before detection (assumed 7 days)",
 "inputs": [
   {"name": "average_cart_value", "value": 80, "source": "public pricing page URL", "source_date": "2026-10-01"},
   {"name": "exposure_fraction", "value": {"min": 0.0, "likely": 0.001, "max": 0.01},
    "source": "assumption: share of orders abusing the flaw", "source_date": "2026-10-24"}],
 "assumptions": ["..."], "calculation": "...", "range": {"min": 0, "most_plausible": 800, "max": 8000},
 "confidence": "low", "limitations": ["..."]}
```
Rejected automatically: unsourced inputs; full exposure of TVL/volume/valuation/balances
(requires `exposure_fraction` < 1 with a source); scenario with high confidence; min>likely>max.
Always distinguish potential exposure from actual loss and from any bounty payout.
