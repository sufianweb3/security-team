# eval of request data

> Draft for MANUAL review and submission. Verify every statement yourself; this tool does not submit, does not predict eligibility or rewards, and did not test the live asset.

**Weakness:** CWE-95  
**Severity (tool assessment):** high

**Verification status:** potential (medium confidence)

**Business priority (tool assessment):** P2

**Tool recommendation:** needs_more_evidence (you decide; the program decides eligibility)

## Summary
eval() of request data enables arbitrary code execution.

## Affected component
web — web/index.js:11

## Evidence
```
  res.send(String(eval(req.query.expr)));
```

## Impact
Depends on reachability and attacker control of the input.

## Safe reproduction outline (no live exploitation)
1. Obtain the referenced source at the pinned revision and open web/index.js:11.
2. Trace the data/authorization flow described above through the cited lines.
3. Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
4. If the program explicitly permits it, the program's own test accounts/environment are the only place a dynamic confirmation should ever be attempted — manually and within its rules.

## Suggested remediation
Never eval user input; use a safe expression parser.

## Limitations
- Detected by pattern-based tool (semgrep); reachability and exploitability not established.
