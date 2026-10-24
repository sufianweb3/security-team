# Risk classification methodology

Six **independent** dimensions are recorded per finding:

| Dimension | Values | Decided by |
|---|---|---|
| Risk zone | RED · YELLOW · GREEN (per component also NOT_ASSESSED) | `risk.zone()` — deterministic rules below |
| Technical severity | critical · high · medium · low · informational | CVSS v3.1 when a defensible vector exists; otherwise qualitative, capped |
| Confidence | high · medium · low | derived from evidence quality; a model can lower but never raise it |
| Verification status | confirmed_static · strongly_supported · potential · unverified_hypothesis · false_positive · not_applicable | sentinel-verifier, constrained by CLI rules |
| Financial exposure | range + method, or "cannot be reliably quantified" | sentinel-severity, validated by `financial.py` |
| Business priority | P1–P5, or not assessed | sentinel-business-impact, constrained by `business.py` from the scope's `business_context` (see BUSINESS_IMPACT.md) |

## Severity rules
1. If a CVSS v3.1 vector is set, severity = band of the computed base score
   (0 info, <4 low, <7 medium, <9 high, ≥9 critical). The vector's rationale is stored.
2. **Critical requires a vector.** Without one, critical is capped to high.
3. **Missing security header alone ⇒ at most low** (policy cap).
4. Dependency CVSS comes from the upstream advisory and describes the library, not the app;
   such findings stay `potential` until reachability is shown, so they cannot be RED.
5. CVSS 4.0 vectors are stored but not computed (limitation).

## Confidence derivation
- confirmed_static + ≥1 machine-verified evidence ⇒ high
- strongly_supported (or confirmed without verified evidence) ⇒ medium if verified evidence else low
- potential ⇒ medium for tool/merged findings with verified evidence, else low
- unverified_hypothesis ⇒ low

## Zone mapping
| Zone | Rule |
|---|---|
| **RED** | severity ∈ {critical, high} **and** status ∈ {confirmed_static, strongly_supported} **and** confidence ∈ {high, medium} **and** at least one machine-verified evidence item |
| **GREEN** | severity = informational (finding level); or a **covered** component with no RED/YELLOW findings |
| **YELLOW** | every other accepted finding (plausible, needs context or safe verification) |
| excluded | false_positive / not_applicable — listed in "Excluded" with rationale, not counted |
| **NOT_ASSESSED** | component with no analyzer coverage — never shown as GREEN |

## Edge cases
- **Tool says high, nobody verified it** → YELLOW (e.g. semgrep SQLi pattern). It becomes RED
  only after independent verification with verified evidence.
- **Agent says critical, evidence doesn't match the snapshot** → status forced to
  unverified_hypothesis, confidence low, YELLOW; verifier will usually mark it false_positive.
- **Two agents agree** → irrelevant. "consensus" as a basis is rejected by the CLI.
- **IDOR with read-only impact** → CVSS 6.5 (medium) ⇒ YELLOW even when confirmed. That is
  correct: zone follows impact, not alarm. (See the example report.)
- **Program excludes the category** → technical finding stays; `bounty.program_status =
  excluded_category`.
- **GREEN overall** requires every component GREEN *and covered*; the report always states
  GREEN ≠ secure.
