# Hardcoded Flask secret key

> Draft for MANUAL review and submission. Verify every statement yourself; this tool does not submit, does not predict eligibility or rewards, and did not test the live asset.

**Weakness:** CWE-798  
**Severity (tool assessment):** medium

**Verification status:** potential (medium confidence)

**Business priority (tool assessment):** P3 — program's own rating for this category: high

**Tool recommendation:** needs_more_evidence (you decide; the program decides eligibility)

## Summary
Flask secret_key is hardcoded; session cookies can be forged by anyone who knows it.

## Affected component
app — app/app.py:12

## Evidence
```
app.secret_key = "dev-secret-key-do-not-use-0001"
```

## Impact
Depends on reachability and attacker control of the input.

## Safe reproduction outline (no live exploitation)
1. Obtain the referenced source at the pinned revision and open app/app.py:12.
2. Trace the data/authorization flow described above through the cited lines.
3. Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
4. If the program explicitly permits it, the program's own test accounts/environment are the only place a dynamic confirmation should ever be attempted — manually and within its rules.

## Suggested remediation
Load the secret from the environment or a secret manager.

## Limitations
- Detected by pattern-based tool (semgrep); reachability and exploitability not established.
- Detected by pattern-based tool (bandit); reachability and exploitability not established.
