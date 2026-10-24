---
name: sentinel-business-logic-review
description: "Analyze business invariants (payments, refunds, coupons, quotas, approvals, state machines, transaction ordering) and smart-contract logic statically for violations. Use when the target handles money, credits, limits, or multi-step workflows."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Business-logic review

1. Write down the invariant in one sentence ("a single-use coupon discounts a cart once").
2. Find the code that should enforce it; show the path where it does not (missing check,
   check-after-use, race window, non-idempotent update, compounding arithmetic, trust of
   client-sent prices/quantities, missing state transition guard).
3. State preconditions and the plausible sequence of normal requests that violates it — do not send them.
4. Smart contracts (static only): checks-effects-interactions order, reentrancy (external
   call before state write), access control on privileged functions, oracle/price trust,
   integer/rounding, unchecked return values. Never sign, simulate on mainnet forks against
   live state, or submit transactions.
5. Financial impact goes to sentinel-severity; do not invent amounts here.
