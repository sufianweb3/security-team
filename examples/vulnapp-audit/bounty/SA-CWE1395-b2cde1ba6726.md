# flask 0.12.2 has 4 known vulnerabilities (CVE-2018-1000656, CVE-2019-1010083, CVE-2023-30861…)

> Draft for MANUAL review and submission. Verify every statement yourself; this tool does not submit, does not predict eligibility or rewards, and did not test the live asset.

**Weakness:** CWE-1395  
**Severity (tool assessment):** high — CVSS CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

**Verification status:** potential (medium confidence)

**Business priority (tool assessment):** P3

**Tool recommendation:** needs_more_evidence (you decide; the program decides eligibility)

## Summary
PYSEC-2018-66; PYSEC-2019-179; PYSEC-2023-62; PYSEC-2026-2151; Flask is vulnerable to Denial of Service via incorrect encoding of JSON data

## Affected component
requirements.txt — requirements.txt:1

## Evidence
```
flask==0.12.2
```

## Impact
Depends on whether the application uses the vulnerable functionality.

## Safe reproduction outline (no live exploitation)
1. Obtain the referenced source at the pinned revision and open requirements.txt:1.
2. Trace the data/authorization flow described above through the cited lines.
3. Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
4. If the program explicitly permits it, the program's own test accounts/environment are the only place a dynamic confirmation should ever be attempted — manually and within its rules.

## Suggested remediation
Upgrade flask to a version that fixes all listed advisories; verify compatibility.

## Limitations
- Version match only; reachability of vulnerable code not established.
- Upstream CVSS describes the library, not this application.
