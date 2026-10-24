# Untrusted GitHub event data interpolated into a shell step

> Draft for MANUAL review and submission. Verify every statement yourself; this tool does not submit, does not predict eligibility or rewards, and did not test the live asset.

**Weakness:** CWE-78  
**Severity (tool assessment):** medium

**Verification status:** potential (medium confidence)

**Business priority (tool assessment):** P4

**Tool recommendation:** needs_more_evidence (you decide; the program decides eligibility)

## Summary
Attacker-controllable fields (titles, branch names, bodies) are expanded into a script before execution.

## Affected component
.github — .github/workflows/ci.yml:11, .github/workflows/ci.yml:13

## Evidence
```
ref: ${{ github.event.pull_request.head.sha }}
```

## Impact
Command execution in the CI runner with its token and secrets.

## Safe reproduction outline (no live exploitation)
1. Obtain the referenced source at the pinned revision and open .github/workflows/ci.yml:11, .github/workflows/ci.yml:13.
2. Trace the data/authorization flow described above through the cited lines.
3. Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
4. If the program explicitly permits it, the program's own test accounts/environment are the only place a dynamic confirmation should ever be attempted — manually and within its rules.

## Suggested remediation
Pass untrusted values through `env:` and reference them as quoted shell variables.

## Limitations
- Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.
