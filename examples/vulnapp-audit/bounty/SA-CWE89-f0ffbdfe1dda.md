# SQL query built from string formatting

> Draft for MANUAL review and submission. Verify every statement yourself; this tool does not submit, does not predict eligibility or rewards, and did not test the live asset.

**Weakness:** CWE-89  
**Severity (tool assessment):** high — CVSS CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

**Verification status:** confirmed_static (medium confidence)

**Business priority (tool assessment):** P1 — program's own rating for this category: critical

**Tool recommendation:** candidate_for_manual_submission (you decide; the program decides eligibility)

## Summary
SQL query built with string formatting and passed to execute(); use parameterized queries.

## Affected component
app — app/app.py:35

## Evidence
```
    cur = db().execute(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'")
```

## Impact
Depends on reachability and attacker control of the input.

## Safe reproduction outline (no live exploitation)
1. Obtain the referenced source at the pinned revision and open app/app.py:35.
2. Trace the data/authorization flow described above through the cited lines.
3. Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
4. If the program explicitly permits it, the program's own test accounts/environment are the only place a dynamic confirmation should ever be attempted — manually and within its rules.

## Suggested remediation
Use parameter placeholders (cursor.execute(sql, params)).

## Limitations
- Detected by pattern-based tool (semgrep); reachability and exploitability not established.
- Detected by pattern-based tool (bandit); reachability and exploitability not established.
