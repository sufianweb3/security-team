# Security Assessment Report — vulnapp training fixture (local, offline)

*Assessment ID:* `vulnapp-local` · *Generated:* 2026-10-23T19:20:03.887509Z · *Tool:* sentinel-auditor 0.3.0

> **Read-only assessment.** This assessment is limited to the inputs, scope, tools and analysis methods listed in this report. It was performed in read-only mode: nothing was exploited, no payloads were sent, and no target state was changed. A GREEN result means no material issue was identified in the assessed component within that coverage; it does NOT mean the system is secure. Findings marked potential or unverified require safe manual verification. Financial figures, where present, are potential exposure estimates, not actual losses and not bounty predictions.

## Executive summary

**Overall zone: 🔴 RED**

| Zone | Count |
|---|---|
| 🔴 RED | 2 |
| 🟡 YELLOW | 28 |
| 🟢 GREEN | 0 |

| Severity | Count |
|---|---|
| critical | 1 |
| high | 16 |
| medium | 9 |
| low | 4 |
| informational | 0 |

| Business priority | Count |
|---|---|
| P1 | 1 |
| P2 | 12 |
| P3 | 10 |
| P4 | 7 |

Zone, severity, confidence, verification status, business priority and financial exposure are independent dimensions. Business priority (P1 highest) says how much a finding matters to this organization given the asset and data context in scope (source: owner_provided); it never changes technical severity or zone.

## Scope

- Authorized: **True**
- Network mode: **offline**
- Assessment types: source_code, dependency_analysis, api_spec

## Components

| Component | Zone | Analyzers | Findings |
|---|---|---|---|
| vulnapp | 🔴 RED | semgrep, bandit, gitleaks, osv-scanner, builtin-supplychain, builtin-openapi | 30 |

## Findings

### SA-CWE89-f0ffbdfe1dda — SQL query built from string formatting

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🔴 RED | high (CVSS 7.5) | medium | confirmed_static | P1 | CWE-89 |

**Component:** `app` · **Category:** sql-injection · **Source:** tool:bandit, semgrep

**Location(s):** `app/app.py:35-35` (location)

**Description.** SQL query built with string formatting and passed to execute(); use parameterized queries.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    cur = db().execute(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'")
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.sqli-fstring-execute.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Use parameter placeholders (cursor.execute(sql, params)).
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P1 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, credentials · context: owner_provided
Program's own rating for this category: **critical** (custom, matched on `sql-injection`).
Business scenario (not executed): An unauthenticated visitor to the public /search endpoint could read the users table of the production shop: customer names, emails and password hashes.
- reviewer raised one step: Hits the critical-tier shop-api asset (production, internet-exposed); the vulnerable query runs against the same database that stores customer PII and credentia
**Submission recommendation:** `candidate_for_manual_submission` — verified with meaningful business priority; a human must review, check duplicates and program rules

**Verifier rationale.** Source request.args.get('q') (unauthenticated /search) flows into an f-string passed to db().execute with no binding.
**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established. Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://cwe.mitre.org/data/definitions/89.html, https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html

### SA-CWE862-32e2b204d175 — DELETE /admin/users/<id> lacks the admin role check its sibling enforces

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🔴 RED | high (CVSS 8.1) | high | confirmed_static | P2 | CWE-862 |

**Component:** `app` · **Category:** missing-authorization · **Source:** agent:sentinel-authz

**Location(s):** `app/app.py:59-65` (sink), `app/app.py:68-74` (check)

**Description.** delete_user is an admin route guarded only by login_required, while the adjacent promote_user also applies require_role("admin"). The OpenAPI spec additionally declares this DELETE with security: [].

Evidence (code_excerpt, ✅ verified against snapshot):

```
@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    db().execute("DELETE FROM users WHERE id = ?", (user_id,))
```

Evidence (code_excerpt, ✅ verified against snapshot):

```
@app.route("/admin/users/<int:user_id>/promote", methods=["POST"])
@login_required
@require_role("admin")
```

**Preconditions.** Attacker holds any valid (non-admin) account
**Plausible scenario (not executed).** A regular user issues DELETE /admin/users/<id> and the account row is deleted. (Not executed.)
**Expected boundary vs observed.** Only administrators can delete users. — *Observed:* Any authenticated user passes the only guard.
**Technical impact.** Unauthorized deletion of arbitrary user accounts (integrity/availability).
**Safe validation.** Static comparison of decorators; confirm no global before_request role check exists.
**Remediation.** Add @require_role("admin") to delete_user and a regression test asserting 403 for non-admins.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
Program's own rating for this category: **high** (custom, matched on `missing-authorization`).
**Submission recommendation:** `candidate_for_manual_submission` — verified with meaningful business priority; a human must review, check duplicates and program rules

**Verifier rationale.** delete_user carries only @login_required while promote_user adds @require_role('admin'); no global role check exists.
**References.** https://cwe.mitre.org/data/definitions/862.html

### SA-CWE1395-575c59d1ab0e — pyyaml 5.3 has 2 known vulnerabilities (CVE-2020-14343, CVE-2020-1747)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | critical (CVSS 9.8) | medium | potential | P2 | CWE-1395 |

**Component:** `requirements.txt` · **Category:** vulnerable-dependency · **Source:** tool:osv-scanner

**Location(s):** `requirements.txt:2-2` (location)

**Description.** PYSEC-2020-96; PYSEC-2021-142; Improper Input Validation in PyYAML; Improper Input Validation in PyYAML

Evidence (config_excerpt, ✅ verified against snapshot):

```
pyyaml==5.3
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by osv-scanner rule PyPI:pyyaml@5.3.
**Technical impact.** Depends on whether the application uses the vulnerable functionality.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Upgrade pyyaml to a version that fixes all listed advisories; verify compatibility.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P1) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Version match only; reachability of vulnerable code not established. Upstream CVSS describes the library, not this application.
**References.** https://osv.dev/vulnerability/CVE-2020-14343, https://osv.dev/vulnerability/CVE-2020-1747

### SA-CWE22-20f07c388222 — Request-controlled file path

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-22 |

**Component:** `app` · **Category:** path-traversal · **Source:** tool:semgrep

**Location(s):** `app/app.py:43-43` (location)

**Description.** File path derived from request data reaches a file API without normalization/containment checks.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    return send_file(os.path.join(BASE_DIR, name))
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.flask-path-traversal.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Use werkzeug.utils.safe_join / send_from_directory and validate against an allowlist.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established.
**References.** https://cwe.mitre.org/data/definitions/22.html

### SA-CWE259-cd50df01e875 — hardcoded password string: Possible hardcoded password: 'q8Vb…[REDACTED]'

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-259 |

**Component:** `app` · **Category:** hardcoded-secret · **Source:** tool:bandit, gitleaks

**Location(s):** `app/config.py:5-5` (location), `app/config.py:4-4` (location)

**Description.** Possible hardcoded password: 'q8Vb…[REDACTED]'

Evidence (code_excerpt, ✅ verified against snapshot):

```
AWS_…[REDACTED]
```

Evidence (code_excerpt, ✅ verified against snapshot):

```
AWS_ACCESS_KEY_ID = "AKIA…[REDACTED]"
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by bandit rule B105.
**Technical impact.** See CWE; impact depends on reachability.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** See https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
Program's own rating for this category: **high** (custom, matched on `hardcoded-secret`).
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (bandit); reachability and exploitability not established. Liveness of the credential was deliberately NOT tested (policy).
**References.** https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html, https://cwe.mitre.org/data/definitions/798.html

### SA-CWE295-5a9091e977fe — TLS verification disabled

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-295 |

**Component:** `app` · **Category:** tls-verification-disabled · **Source:** tool:bandit, semgrep

**Location(s):** `app/config.py:10-10` (location)

**Description.** TLS certificate verification disabled.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    return requests.get("https://rates.example.com/v1", verify=False, timeout=5).json()
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.requests-verify-false.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Remove verify=False; pin a CA bundle if needed.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established. Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://bandit.readthedocs.io/en/1.9.4/plugins/b501_request_with_no_cert_validation.html

### SA-CWE489-af8b8327cc71 — Flask debug mode enabled

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-489 |

**Component:** `app` · **Category:** debug-enabled · **Source:** tool:bandit, semgrep

**Location(s):** `app/app.py:93-93` (location)

**Description.** Flask debug mode exposes the Werkzeug debugger (code execution) if reachable.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    app.run(host="0.0.0.0", debug=True)
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.flask-debug.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** See rule references.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established. Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://bandit.readthedocs.io/en/1.9.4/plugins/b201_flask_debug_true.html

### SA-CWE502-a4c90675842c — Pickle deserialization of request data

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-502 |

**Component:** `app` · **Category:** deserialization · **Source:** tool:bandit, semgrep

**Location(s):** `app/app.py:56-56` (location)

**Description.** pickle.loads on request-derived data allows arbitrary code execution during deserialization.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    return jsonify(pickle.loads(bytes.fromhex(raw)) if raw else {})
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.pickle-untrusted.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Use JSON with a schema; never unpickle client data.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established. Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://docs.python.org/3/library/pickle.html, https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b301-pickle

### SA-CWE502-cc9c91b35af7 — Unsafe YAML deserialization

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-502 |

**Component:** `app` · **Category:** deserialization · **Source:** tool:bandit, semgrep

**Location(s):** `app/app.py:49-49` (location)

**Description.** yaml.load with an unsafe Loader can construct arbitrary Python objects.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    settings = yaml.load(request.data, Loader=yaml.Loader)
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.unsafe-yaml-load.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Use yaml.safe_load.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established. Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://cwe.mitre.org/data/definitions/502.html, https://bandit.readthedocs.io/en/1.9.4/plugins/b506_yaml_load.html

### SA-CWE78-6956e11f61fa — Command built from request data

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-78 |

**Component:** `web` · **Category:** command-injection · **Source:** tool:semgrep

**Location(s):** `web/index.js:7-7` (location)

**Description.** Shell command built from request data and executed with child_process.exec.

Evidence (code_excerpt, ✅ verified against snapshot):

```
  exec(`ping -c 1 ${req.query.host}`, (err, out) => res.send(out));
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.js.child-process-exec-template.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Use execFile/spawn with an argument array and strict validation.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-other` (medium tier, unknown) · data at risk: internal · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established.

### SA-CWE841-3dc2d1f78292 — External call before state update

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-841 |

**Component:** `contracts` · **Category:** reentrancy · **Source:** tool:semgrep

**Location(s):** `contracts/Vault.sol:15-17` (location)

**Description.** External call with value precedes a state write in the same function (possible reentrancy); verify with a reentrancy guard / CEI review.

Evidence (code_excerpt, ✅ verified against snapshot):

```
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.solidity.call-before-state-update.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** See rule references.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `vault-contract` (high tier, production) · data at risk: funds · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established.

### SA-CWE95-e2c5fee2d296 — eval of request data

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P2 | CWE-95 |

**Component:** `web` · **Category:** code-injection · **Source:** tool:semgrep

**Location(s):** `web/index.js:11-11` (location)

**Description.** eval() of request data enables arbitrary code execution.

Evidence (code_excerpt, ✅ verified against snapshot):

```
  res.send(String(eval(req.query.expr)));
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.js.eval-request.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Never eval user input; use a safe expression parser.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P2) · asset `shop-other` (medium tier, unknown) · data at risk: internal · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established.

### SA-CWE639-f1987c925021 — Any authenticated user can read any invoice (IDOR in get_invoice)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium (CVSS 6.5) | high | confirmed_static | P2 | CWE-639 |

**Component:** `app` · **Category:** idor · **Source:** agent:sentinel-authz

**Location(s):** `app/app.py:22-29` (sink), `app/app.py:84-84` (check)

**Description.** get_invoice looks up an invoice solely by the client-supplied id. owner_id is fetched and even returned, but never compared to the session user. Elsewhere (apply_coupon) the code scopes queries by current_user().id, showing the intended ownership pattern.

Evidence (code_excerpt, ✅ verified against snapshot):

```
row = db().execute("SELECT id, owner_id, total FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
if row is None:
    abort(404)
return jsonify({"id": row[0], "owner": row[1], "total": row[2]})
```

Evidence (code_excerpt, ✅ verified against snapshot):

```
cart = db().execute("SELECT id, total FROM carts WHERE user_id = ?", (current_user().id,)).fetchone()
```

**Preconditions.** Attacker holds any valid account (login_required is the only guard); Invoice ids are guessable integers (route uses <int:invoice_id>)
**Plausible scenario (not executed).** A logged-in user changes the numeric id in /invoices/<id> to another customer's invoice id and receives that invoice's owner and total. (Not executed.)
**Expected boundary vs observed.** A user can read only invoices where owner_id equals their user id. — *Observed:* Query filters by id only; no owner comparison on any path in the handler.
**Technical impact.** Horizontal disclosure of all customers' invoice data (owner id, totals).
**Safe validation.** Static: confirm no middleware or DB row-level policy enforces ownership; optionally write a unit test against a local throwaway DB fixture (never production).
**Remediation.** Filter by owner: WHERE id = ? AND owner_id = ? with current_user().id, or check row[1] == current_user().id and return 404 otherwise.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P2 (technical P3) · asset `shop-api` (critical tier, production) · data at risk: pii, payment · context: owner_provided
Program's own rating for this category: **high** (custom, matched on `idor`).
Business scenario (not executed): Any logged-in customer could read other customers' invoices: names, billing addresses and amounts paid.
- reviewer raised one step: Invoices on the critical-tier billing API carry customer PII and payment data; for a shop, cross-customer invoice disclosure is a reportable privacy incident, s
**Submission recommendation:** `candidate_for_manual_submission` — verified with meaningful business priority; a human must review, check duplicates and program rules

**Verifier rationale.** get_invoice is reachable by any session (login_required only), selects by id alone and never compares owner_id; no before_request hook, middleware or DB policy in the snapshot adds an ownership check.
**Limitations.** Assumes no ownership enforcement outside this file (e.g. DB RLS); none was found in the snapshot.
**References.** https://cwe.mitre.org/data/definitions/639.html, https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

### SA-CWE1395-20301f2d76bc — lodash 4.17.15 has 6 known vulnerabilities (CVE-2020-28500, CVE-2020-8203, CVE-2021-23337…)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high (CVSS 8.1) | medium | potential | P3 | CWE-1395 |

**Component:** `package-lock.json` · **Category:** vulnerable-dependency · **Source:** tool:osv-scanner

**Location(s):** `package-lock.json:7-7` (location)

**Description.** Regular Expression Denial of Service (ReDoS) in lodash; Command Injection in lodash; lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit`; Prototype Pollution in lodash; lodash vulnerable to Code Injection via `_.template` imports key names

Evidence (config_excerpt, ✅ verified against snapshot):

```
    "": {"name": "vulnapp-frontend", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by osv-scanner rule npm:lodash@4.17.15.
**Technical impact.** Depends on whether the application uses the vulnerable functionality.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Upgrade lodash to a version that fixes all listed advisories; verify compatibility.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P2) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Version match only; reachability of vulnerable code not established. Upstream CVSS describes the library, not this application.
**References.** https://osv.dev/vulnerability/CVE-2020-28500, https://osv.dev/vulnerability/CVE-2020-8203, https://osv.dev/vulnerability/CVE-2021-23337, https://osv.dev/vulnerability/CVE-2025-13465, https://osv.dev/vulnerability/CVE-2026-2950

### SA-CWE1395-7c30e220b78e — jinja2 2.10 has 6 known vulnerabilities (CVE-2019-10906, CVE-2020-28493, CVE-2024-22195…)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high (CVSS 7.8) | medium | potential | P3 | CWE-1395 |

**Component:** `requirements.txt` · **Category:** vulnerable-dependency · **Source:** tool:osv-scanner

**Location(s):** `requirements.txt:4-4` (location)

**Description.** PYSEC-2019-217; PYSEC-2021-66; Jinja2 vulnerable to sandbox breakout through attr filter selecting format method; Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter; Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter

Evidence (config_excerpt, ✅ verified against snapshot):

```
jinja2==2.10
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by osv-scanner rule PyPI:jinja2@2.10.
**Technical impact.** Depends on whether the application uses the vulnerable functionality.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Upgrade jinja2 to a version that fixes all listed advisories; verify compatibility.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P2) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Version match only; reachability of vulnerable code not established. Upstream CVSS describes the library, not this application.
**References.** https://osv.dev/vulnerability/CVE-2019-10906, https://osv.dev/vulnerability/CVE-2020-28493, https://osv.dev/vulnerability/CVE-2024-22195, https://osv.dev/vulnerability/CVE-2024-34064, https://osv.dev/vulnerability/CVE-2024-56326

### SA-CWE1395-b2cde1ba6726 — flask 0.12.2 has 4 known vulnerabilities (CVE-2018-1000656, CVE-2019-1010083, CVE-2023-30861…)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high (CVSS 7.5) | medium | potential | P3 | CWE-1395 |

**Component:** `requirements.txt` · **Category:** vulnerable-dependency · **Source:** tool:osv-scanner

**Location(s):** `requirements.txt:1-1` (location)

**Description.** PYSEC-2018-66; PYSEC-2019-179; PYSEC-2023-62; PYSEC-2026-2151; Flask is vulnerable to Denial of Service via incorrect encoding of JSON data

Evidence (config_excerpt, ✅ verified against snapshot):

```
flask==0.12.2
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by osv-scanner rule PyPI:flask@0.12.2.
**Technical impact.** Depends on whether the application uses the vulnerable functionality.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Upgrade flask to a version that fixes all listed advisories; verify compatibility.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P2) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Version match only; reachability of vulnerable code not established. Upstream CVSS describes the library, not this application.
**References.** https://osv.dev/vulnerability/CVE-2018-1000656, https://osv.dev/vulnerability/CVE-2019-1010083, https://osv.dev/vulnerability/CVE-2023-30861, https://osv.dev/vulnerability/CVE-2026-27205

### SA-CWE1395-d40da4c54a86 — requests 2.19.0 has 5 known vulnerabilities (CVE-2018-18074, CVE-2023-32681, CVE-2024-35195…)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high (CVSS 7.5) | medium | potential | P3 | CWE-1395 |

**Component:** `requirements.txt` · **Category:** vulnerable-dependency · **Source:** tool:osv-scanner

**Location(s):** `requirements.txt:3-3` (location)

**Description.** PYSEC-2018-28; PYSEC-2023-74; Requests vulnerable to .netrc credentials leak via malicious URLs; Requests `Session` object does not verify requests after making first request with verify=False; PYSEC-2026-2275

Evidence (config_excerpt, ✅ verified against snapshot):

```
requests==2.19.0
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by osv-scanner rule PyPI:requests@2.19.0.
**Technical impact.** Depends on whether the application uses the vulnerable functionality.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Upgrade requests to a version that fixes all listed advisories; verify compatibility.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P2) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Version match only; reachability of vulnerable code not established. Upstream CVSS describes the library, not this application.
**References.** https://osv.dev/vulnerability/CVE-2018-18074, https://osv.dev/vulnerability/CVE-2023-32681, https://osv.dev/vulnerability/CVE-2024-35195, https://osv.dev/vulnerability/CVE-2024-47081, https://osv.dev/vulnerability/CVE-2026-25645

### SA-CWE829-29feb4c08358 — pull_request_target workflow checks out untrusted PR code

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | high | medium | potential | P3 | CWE-829 |

**Component:** `.github` · **Category:** ci-privileged-untrusted-checkout · **Source:** tool:builtin-supplychain

**Location(s):** `.github/workflows/ci.yml:11-11` (location)

**Description.** pull_request_target runs with repository secrets; checking out the PR head lets fork authors run code in that privileged context if any later step executes it.

Evidence (config_excerpt, ✅ verified against snapshot):

```
          ref: ${{ github.event.pull_request.head.sha }}
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-supplychain rule gha-prt-checkout.
**Technical impact.** Theft of repository secrets / write token by any external contributor.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Use pull_request for untrusted code, or never execute checked-out PR code in pull_request_target jobs; restrict permissions.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P2) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.
**References.** https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

### SA-CWE306-96eb4643188a — DELETE /admin/users/{user_id} declares no authentication requirement

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | potential | P3 | CWE-306 |

**Component:** `openapi.yaml` · **Category:** missing-authentication · **Source:** tool:builtin-openapi

**Location(s):** `openapi.yaml:16-16` (location)

**Description.** The operation has no security requirement in the specification. The spec may be incomplete; the implementation must be checked.

Evidence (spec_excerpt, ✅ verified against snapshot):

```
  /admin/users/{user_id}:
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-openapi rule oas-no-security.
**Technical impact.** If the implementation matches the spec, unauthenticated users can invoke a sensitive operation.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Declare and enforce an authentication scheme for the operation.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P3) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Specification-only observation; implementation not verified.

### SA-CWE319-cd5348b991da — API server declared over plain HTTP: http://api.vulnapp.example.com

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | confirmed_static | P3 | CWE-319 |

**Component:** `openapi.yaml` · **Category:** cleartext-transport · **Source:** tool:builtin-openapi

**Location(s):** `openapi.yaml:4-4` (location)

**Description.** The specification advertises a non-TLS server URL.

Evidence (spec_excerpt, ✅ verified against snapshot):

```
  - url: http://api.vulnapp.example.com
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-openapi rule oas-http-server.
**Technical impact.** Credentials and data may transit in cleartext if clients use this server.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Serve the API only over HTTPS and update the specification.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P3) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `candidate_for_manual_submission` — verified with meaningful business priority; a human must review, check duplicates and program rules

**Limitations.** Detected by pattern-based tool (builtin-openapi); reachability and exploitability not established.

### SA-CWE605-2bdef207f461 — hardcoded bind all interfaces: Possible binding to all interfaces.

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | potential | P3 | CWE-605 |

**Component:** `app` · **Category:** insecure-binding · **Source:** tool:bandit

**Location(s):** `app/app.py:93-93` (location)

**Description.** Possible binding to all interfaces.

Evidence (code_excerpt, ✅ verified against snapshot):

```
    app.run(host="0.0.0.0", debug=True)
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by bandit rule B104.
**Technical impact.** See CWE; impact depends on reachability.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** See https://bandit.readthedocs.io/en/1.9.4/plugins/b104_hardcoded_bind_all_interfaces.html
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P3) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://bandit.readthedocs.io/en/1.9.4/plugins/b104_hardcoded_bind_all_interfaces.html

### SA-CWE798-a60a0caf6f12 — Hardcoded Flask secret key

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | potential | P3 | CWE-798 |

**Component:** `app` · **Category:** hardcoded-secret · **Source:** tool:bandit, semgrep

**Location(s):** `app/app.py:12-12` (location)

**Description.** Flask secret_key is hardcoded; session cookies can be forged by anyone who knows it.

Evidence (code_excerpt, ✅ verified against snapshot):

```
app.secret_key = "dev-secret-key-do-not-use-0001"
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by semgrep rule workspace.projects.875dd5b0-fed6-440d-9d73-6a7abf69dc8a.work.sentinel-auditor.rules.semgrep.sentinel.python.flask-hardcoded-secret-key.
**Technical impact.** Depends on reachability and attacker control of the input.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Load the secret from the environment or a secret manager.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P3 (technical P3) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
Program's own rating for this category: **high** (custom, matched on `hardcoded-secret`).
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (semgrep); reachability and exploitability not established. Detected by pattern-based tool (bandit); reachability and exploitability not established.
**References.** https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY, https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html

### SA-CWE840-049386d40d16 — Single-use coupon is never enforced and discounts compound on repeat calls

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium (CVSS 6.5) | medium | strongly_supported | P3 | CWE-840 |

**Component:** `app` · **Category:** business-logic · **Source:** agent:sentinel-business-logic

**Location(s):** `app/app.py:77-89` (sink)

**Description.** apply_coupon selects single_use but never checks or records redemption, and applies the percentage to the already-discounted cart total. Repeating the request reduces the total geometrically toward zero.

Evidence (code_excerpt, ✅ verified against snapshot):

```
coupon = db().execute("SELECT percent, single_use FROM coupons WHERE code = ?", (code,)).fetchone()
new_total = cart[1] * (100 - coupon[0]) / 100
db().execute("UPDATE carts SET total = ? WHERE id = ?", (new_total, cart[0]))
```

**Preconditions.** Attacker has an account and any valid coupon code
**Plausible scenario (not executed).** Calling /cart/apply-coupon N times with a 20% code reduces the total to 0.8^N of the original. (Not executed.)
**Expected boundary vs observed.** A single-use coupon reduces one order once. — *Observed:* No redemption record; discount re-applied on each call.
**Technical impact.** Fraudulent discounts / goods obtained below price.
**Safe validation.** Static trace of apply_coupon; local unit test on a throwaway DB calling the handler twice.
**Remediation.** Record redemptions (unique constraint on coupon+user/order), enforce single_use, compute discounts from the undiscounted subtotal, make the operation idempotent.
**Financial exposure.** Potential exposure (not an actual loss, not a bounty estimate): USD 0 – 3,600 (most plausible 480) over one abuse campaign before detection (assumed 7 days); method=scenario; confidence=low.

**Business impact.** P3 (technical P3) · asset `shop-api` (critical tier, production) · data at risk: payment · context: owner_provided
Program's own rating for this category: **medium** (custom, matched on `business-logic`).
Business scenario (not executed): A customer could re-apply a single-use coupon and pay less than intended on their own orders.
**Submission recommendation:** `candidate_for_manual_submission` — verified with meaningful business priority; a human must review, check duplicates and program rules

**Verifier rationale.** single_use is selected but never read; the total is re-discounted on every call. Unproven: whether a DB trigger elsewhere limits redemptions.
**References.** https://cwe.mitre.org/data/definitions/840.html

### SA-CWE494-f118c64fa98e — Dockerfile pipes a remote script into a shell

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | confirmed_static | P4 | CWE-494 |

**Component:** `Dockerfile` · **Category:** unverified-download · **Source:** tool:builtin-supplychain

**Location(s):** `Dockerfile:2-2` (location)

**Description.** Remote content is executed without integrity verification.

Evidence (config_excerpt, ✅ verified against snapshot):

```
RUN curl -fsSL https://get.example.com/install.sh | sh
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-supplychain rule docker-curl-pipe-sh.
**Technical impact.** Image build compromise if the remote host or path is compromised.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Download to a file, verify a pinned checksum/signature, then execute.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P3) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `low_value` — verified but low business priority; check the program accepts low-impact reports

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.

### SA-CWE78-5a21e2ded7a5 — Untrusted GitHub event data interpolated into a shell step

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | potential | P4 | CWE-78 |

**Component:** `.github` · **Category:** ci-script-injection · **Source:** tool:builtin-supplychain

**Location(s):** `.github/workflows/ci.yml:11-11` (location), `.github/workflows/ci.yml:13-13` (location)

**Description.** Attacker-controllable fields (titles, branch names, bodies) are expanded into a script before execution.

Evidence (config_excerpt, ✅ verified against snapshot):

```
ref: ${{ github.event.pull_request.head.sha }}
```

Evidence (config_excerpt, ✅ verified against snapshot):

```
run: echo "Testing PR ${{ github.event.pull_request.title }}"
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-supplychain rule gha-expression-injection.
**Technical impact.** Command execution in the CI runner with its token and secrets.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Pass untrusted values through `env:` and reference them as quoted shell variables.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P3) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `needs_more_evidence` — not independently verified; do not submit as-is

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.
**References.** https://securitylab.github.com/resources/github-actions-untrusted-input/

### SA-CWE829-faaa3349d116 — npm lifecycle script 'postinstall' runs on install and downloads remote code

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | medium | medium | confirmed_static | P4 | CWE-829 |

**Component:** `package.json` · **Category:** risky-lifecycle-script · **Source:** tool:builtin-supplychain

**Location(s):** `package.json:7-7` (location)

**Description.** The 'postinstall' script executes automatically during `npm install`. It was NOT executed by the auditor.

Evidence (config_excerpt, ✅ verified against snapshot):

```
    "postinstall": "curl -s http://cdn.example.com/setup.sh | sh"
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Installing dependencies should not execute unverified remote code. — *Observed:* scripts.postinstall = curl -s http://cdn.example.com/setup.sh | sh
**Technical impact.** Code execution on every developer/CI machine that installs the package; remote fetches allow a third party to change what runs.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Remove install-time scripts or pin and verify downloaded artifacts by hash; use `npm ci --ignore-scripts` in CI where possible.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P3) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `low_value` — verified but low business priority; check the program accepts low-impact reports

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.
**References.** https://docs.npmjs.com/cli/using-npm/scripts

### SA-CWE250-51fdf9d3461d — Container image runs as root (no non-root USER)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | low | medium | confirmed_static | P4 | CWE-250 |

**Component:** `Dockerfile` · **Category:** container-hardening · **Source:** tool:builtin-supplychain

**Location(s):** `Dockerfile:1-1` (location)

**Description.** No USER directive switching to a non-root account was found.

Evidence (config_excerpt, ✅ verified against snapshot):

```
FROM python:3.12-slim
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-supplychain rule docker-root-user.
**Technical impact.** Increases impact of any container escape or RCE.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Add a dedicated non-root user and `USER` directive.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P4) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `low_value` — verified but low business priority; check the program accepts low-impact reports

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.

### SA-CWE598-085a8c3b3eb4 — API key accepted in query string (legacyKey)

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | low | medium | confirmed_static | P4 | CWE-598 |

**Component:** `openapi.yaml` · **Category:** credential-in-url · **Source:** tool:builtin-openapi

**Location(s):** `openapi.yaml:8-8` (location)

**Description.** Query-string credentials leak into logs, proxies and browser history.

Evidence (spec_excerpt, ✅ verified against snapshot):

```
    legacyKey: {type: apiKey, in: query, name: api_key}
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-openapi rule oas-apikey-query.
**Technical impact.** Credential exposure via logs/referrers.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Accept API keys in a header.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P4) · asset `shop-api` (critical tier, production) · data at risk: pii, payment, credentials, authentication · context: owner_provided
**Submission recommendation:** `low_value` — verified but low business priority; check the program accepts low-impact reports

**Limitations.** Detected by pattern-based tool (builtin-openapi); reachability and exploitability not established.

### SA-CWE829-58ccb551a969 — GitHub Action not pinned to a commit SHA: actions/checkout@v4

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | low | medium | confirmed_static | P4 | CWE-829 |

**Component:** `.github` · **Category:** unpinned-ci-dependency · **Source:** tool:builtin-supplychain

**Location(s):** `.github/workflows/ci.yml:9-9` (location)

**Description.** Mutable tags can be force-pushed by whoever controls the action repository (as happened to aquasecurity/trivy-action in March 2026, CVE-2026-33634).

Evidence (config_excerpt, ✅ verified against snapshot):

```
- uses: actions/checkout@v4
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-supplychain rule gha-unpinned-action.
**Technical impact.** CI secrets exposure if the referenced action is compromised.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Pin third-party actions to a full commit SHA and update via a reviewed process.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P4) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `low_value` — verified but low business priority; check the program accepts low-impact reports

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.
**References.** https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions, https://nvd.nist.gov/vuln/detail/CVE-2026-33634

### SA-CWE829-7ddef4668ed8 — GitHub Action not pinned to a commit SHA: actions/setup-python@v5

| Zone | Severity | Confidence | Verification | Business priority | CWE |
|---|---|---|---|---|---|
| 🟡 YELLOW | low | medium | confirmed_static | P4 | CWE-829 |

**Component:** `.github` · **Category:** unpinned-ci-dependency · **Source:** tool:builtin-supplychain

**Location(s):** `.github/workflows/ci.yml:14-14` (location)

**Description.** Mutable tags can be force-pushed by whoever controls the action repository (as happened to aquasecurity/trivy-action in March 2026, CVE-2026-33634).

Evidence (config_excerpt, ✅ verified against snapshot):

```
- uses: actions/setup-python@v5
```

**Preconditions.** Code path is reachable in the deployed configuration (not verified by the tool).
**Plausible scenario (not executed).** Not established by the tool; requires analyst review of reachability and attacker control.
**Expected boundary vs observed.** Untrusted input should not reach this operation without validation/authorization. — *Observed:* Pattern matched by builtin-supplychain rule gha-unpinned-action.
**Technical impact.** CI secrets exposure if the referenced action is compromised.
**Safe validation.** Review the cited code and its callers statically; confirm attacker control of inputs using local tests against a disposable copy only. Do not test the live target.
**Remediation.** Pin third-party actions to a full commit SHA and update via a reviewed process.
**Financial exposure.** Financial exposure cannot be reliably quantified from the available evidence.

**Business impact.** P4 (technical P4) · asset `build-and-ci` (medium tier, production) · data at risk: secrets · context: owner_provided
- not internet-exposed (-1)
**Submission recommendation:** `low_value` — verified but low business priority; check the program accepts low-impact reports

**Limitations.** Detected by pattern-based tool (builtin-supplychain); reachability and exploitability not established.
**References.** https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions, https://nvd.nist.gov/vuln/detail/CVE-2026-33634

## Coverage

| Tool / analyzer | Available | Notes |
|---|---|---|
| semgrep | yes |  |
| bandit | yes |  |
| gitleaks | yes |  |
| osv-scanner | yes |  |
| builtin-supplychain | yes |  |
| builtin-openapi | yes |  |

## Limitations

- Static and passive analysis only; no dynamic testing or exploitation was performed.
- Reachability of vulnerable dependencies was not established unless stated per finding.
- LLM-assisted findings were only accepted when their evidence matched the immutable snapshot.
- Run was offline: no live web/API observations were made.

## Excluded (false positive / not applicable)

- SA-CWE259-177d4ec98692 hardcoded password string: Possible hardcoded password: 'pass…[REDACTED]' — false_positive: tests/test_login.py value is an explicit test-only dummy used by a placeholder assertion; not a deployed credential.
- SA-CWE798-752d6622c612 Admin password hardcoded in auth module (invented excerpt) — false_positive: Cited excerpt does not exist in app/auth.py; evidence failed snapshot verification (hallucinated candidate).

## Rejected candidates (1)

Candidates whose evidence could not be matched to the snapshot or that failed the schema:

- Secret in settings module (invented file): location file not found in snapshot: app/settings_prod.py
