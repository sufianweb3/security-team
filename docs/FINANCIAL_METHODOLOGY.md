# Financial exposure methodology

Financial exposure is a **separate, optional** assessment. It is never derived from severity,
never presented as an actual loss, and never as a bounty prediction.

## Evidence hierarchy (method)
1. `disclosure` — verified public financial disclosures or incident data (cited).
2. `cited_scale` — credible, cited data on affected assets, limits, balances, business scale.
3. `scenario` — explicit scenario with labelled assumptions (confidence low/medium only).
4. `unknown` — default. Statement: *"Financial exposure cannot be reliably quantified from the
   available evidence."*

## Required fields (validated by `auditor/financial.py`)
`method, category, loss_type (direct_loss | indirect_cost | total_potential_exposure), currency,
time_horizon, inputs[] {name, value, source, source_date}, assumptions[], calculation,
range {min, most_plausible, max}, confidence, limitations[]`.

## Automatic rejections
- Any input missing a source or date.
- `disclosure`/`cited_scale` with assumption-only sources.
- Aggregate metrics (TVL, trading volume, valuation, market cap, total customer balances,
  revenue, AUM) **without an evidenced `exposure_fraction` < 1** — full exposure is never assumed.
- `scenario` with high confidence.
- A range that is not `0 ≤ min ≤ most_plausible ≤ max`.
A rejected estimate is replaced by the `unknown` statement and the rejection reason is logged.

## Recommended calculation pattern
`exposure = Σ base_value_i × exposure_fraction_i` evaluated at min / likely / max fractions,
where each fraction is justified by evidence (withdrawal limits, per-transaction caps,
rate limits, approval steps, detection windows). `financial.scenario_from_components()`
implements this.

## Example (from the bundled fixture)
Coupon-compounding flaw: orders/week × AOV × abused-share × discount obtained, all inputs
labelled as assumptions because the training fixture has no business data → USD 0–3,600,
most plausible 480, confidence low, horizon one week. A competing estimate that multiplied
an entire TVL by 1.0 was rejected by the CLI (see `examples/agent-candidates/fin-rejected-tvl.json`).
