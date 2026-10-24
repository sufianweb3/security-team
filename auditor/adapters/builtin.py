"""Built-in, dependency-free checks. These parse files; they never execute them.
They are clearly labelled `builtin-*` and are complements, not replacements, for
the external tools (absence of an external tool is reported as a coverage gap)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from ..redact import PATTERNS, redact
from . import base_finding, read_lines

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
GH_EXPR_IN_RUN = re.compile(r"\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|commits)|head_ref)[^}]*\}\}")
CURL_PIPE = re.compile(r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b")


def _line_of(text: str, needle: str) -> int:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 1


# ------------------------------------------------------------ supply chain
def supply_chain(target_dir: Path, target_id: str) -> tuple[list, dict]:
    out: list[dict] = []
    checked: list[str] = []
    for p in sorted(target_dir.rglob("package.json")):
        if "node_modules" in p.parts:
            continue
        rel = p.relative_to(target_dir).as_posix()
        checked.append(rel)
        text = p.read_text(encoding="utf-8", errors="replace")
        try:
            pkg = json.loads(text)
        except json.JSONDecodeError:
            continue
        for hook, cmd in (pkg.get("scripts") or {}).items():
            if hook in LIFECYCLE:
                ln = _line_of(text, f'"{hook}"')
                risky = bool(CURL_PIPE.search(cmd)) or "http" in cmd
                out.append(base_finding(
                    title=f"npm lifecycle script '{hook}' runs on install" + (" and downloads remote code" if risky else ""),
                    category="risky-lifecycle-script", cwe="CWE-829", target_id=target_id, file=rel,
                    start=ln, end=ln, excerpt=read_lines(target_dir, rel, ln), evidence_kind="config_excerpt",
                    tool="builtin-supplychain", rule_id=f"npm-lifecycle-{hook}",
                    description=f"The '{hook}' script executes automatically during `npm install`. "
                                "It was NOT executed by the auditor.",
                    severity="medium" if risky else "low",
                    impact="Code execution on every developer/CI machine that installs the package; remote fetches "
                           "allow a third party to change what runs.",
                    remediation="Remove install-time scripts or pin and verify downloaded artifacts by hash; "
                                "use `npm ci --ignore-scripts` in CI where possible.",
                    status="confirmed_static" if risky else "potential",
                    expected="Installing dependencies should not execute unverified remote code.",
                    observed=f"scripts.{hook} = {redact(cmd)[:200]}",
                    references=["https://docs.npmjs.com/cli/using-npm/scripts"]))
    for wf in sorted(list(target_dir.glob(".github/workflows/*.yml")) + list(target_dir.glob(".github/workflows/*.yaml"))):
        rel = wf.relative_to(target_dir).as_posix()
        checked.append(rel)
        text = wf.read_text(encoding="utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            continue
        on = doc.get(True, doc.get("on"))  # YAML 1.1 parses bare `on` as True
        triggers = set(on) if isinstance(on, (dict, list)) else {on} if isinstance(on, str) else set()
        for i, line in enumerate(text.splitlines(), 1):
            m = re.search(r"uses:\s*([^\s#]+)", line)
            if m and not m.group(1).startswith("./") and not SHA_PIN.search(m.group(1)) and "docker://" not in m.group(1):
                out.append(base_finding(
                    title=f"GitHub Action not pinned to a commit SHA: {m.group(1)}",
                    category="unpinned-ci-dependency", cwe="CWE-829", target_id=target_id, file=rel, start=i, end=i,
                    excerpt=line.strip(), evidence_kind="config_excerpt", tool="builtin-supplychain",
                    rule_id="gha-unpinned-action",
                    description="Mutable tags can be force-pushed by whoever controls the action repository "
                                "(as happened to aquasecurity/trivy-action in March 2026, CVE-2026-33634).",
                    severity="low", impact="CI secrets exposure if the referenced action is compromised.",
                    remediation="Pin third-party actions to a full commit SHA and update via a reviewed process.",
                    status="confirmed_static",
                    references=["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
                                "https://nvd.nist.gov/vuln/detail/CVE-2026-33634"]))
            if "run:" in line or line.startswith((" ", "\t")):
                g = GH_EXPR_IN_RUN.search(line)
                if g:
                    out.append(base_finding(
                        title="Untrusted GitHub event data interpolated into a shell step",
                        category="ci-script-injection", cwe="CWE-78", target_id=target_id, file=rel, start=i, end=i,
                        excerpt=line.strip(), evidence_kind="config_excerpt", tool="builtin-supplychain",
                        rule_id="gha-expression-injection",
                        description="Attacker-controllable fields (titles, branch names, bodies) are expanded into a "
                                    "script before execution.",
                        severity="medium", impact="Command execution in the CI runner with its token and secrets.",
                        remediation="Pass untrusted values through `env:` and reference them as quoted shell variables.",
                        status="potential",
                        references=["https://securitylab.github.com/resources/github-actions-untrusted-input/"]))
        if "pull_request_target" in triggers and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", text):
            ln = _line_of(text, "pull_request.head")
            out.append(base_finding(
                title="pull_request_target workflow checks out untrusted PR code",
                category="ci-privileged-untrusted-checkout", cwe="CWE-829", target_id=target_id, file=rel,
                start=ln, end=ln, excerpt=read_lines(target_dir, rel, ln), evidence_kind="config_excerpt",
                tool="builtin-supplychain", rule_id="gha-prt-checkout",
                description="pull_request_target runs with repository secrets; checking out the PR head lets "
                            "fork authors run code in that privileged context if any later step executes it.",
                severity="high", impact="Theft of repository secrets / write token by any external contributor.",
                remediation="Use pull_request for untrusted code, or never execute checked-out PR code in "
                            "pull_request_target jobs; restrict permissions.",
                status="potential",
                references=["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"]))
    for df in sorted(target_dir.rglob("Dockerfile")):
        rel = df.relative_to(target_dir).as_posix()
        checked.append(rel)
        text = df.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            if CURL_PIPE.search(line):
                out.append(base_finding(
                    title="Dockerfile pipes a remote script into a shell",
                    category="unverified-download", cwe="CWE-494", target_id=target_id, file=rel, start=i, end=i,
                    excerpt=line.strip(), evidence_kind="config_excerpt", tool="builtin-supplychain",
                    rule_id="docker-curl-pipe-sh", description="Remote content is executed without integrity verification.",
                    severity="medium", impact="Image build compromise if the remote host or path is compromised.",
                    remediation="Download to a file, verify a pinned checksum/signature, then execute.",
                    status="confirmed_static"))
        if not re.search(r"^\s*USER\s+(?!root\b)\S+", text, re.M):
            out.append(base_finding(
                title="Container image runs as root (no non-root USER)",
                category="container-hardening", cwe="CWE-250", target_id=target_id, file=rel, start=1, end=1,
                excerpt=text.splitlines()[0] if text else "", evidence_kind="config_excerpt",
                tool="builtin-supplychain", rule_id="docker-root-user",
                description="No USER directive switching to a non-root account was found.",
                severity="low", impact="Increases impact of any container escape or RCE.",
                remediation="Add a dedicated non-root user and `USER` directive.", status="confirmed_static"))
    return out, {"tool": "builtin-supplychain", "available": True, "files_checked": checked}


# ------------------------------------------------------------ secrets (fallback)
TEXT_EXT = {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".cfg", ".ini", ".toml", ".properties",
            ".rb", ".go", ".java", ".php", ".cs", ".sh", ".tf", ".xml", ".txt", ".md", ".conf"}


def secrets_builtin(target_dir: Path, target_id: str) -> tuple[list, dict]:
    from .external import PLACEHOLDER, TESTISH
    out: list[dict] = []
    for p in sorted(target_dir.rglob("*")):
        if not p.is_file() or (p.suffix.lower() not in TEXT_EXT and not p.name.startswith(".env")):
            continue
        rel = p.relative_to(target_dir).as_posix()
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for name, rx in PATTERNS:
                if name in ("jwt", "url-credentials"):
                    continue
                if rx.search(line):
                    likely_fp = bool(TESTISH.search(rel)) or bool(PLACEHOLDER.search(line))
                    out.append(base_finding(
                        title=f"Potential hardcoded credential ({name}) in {rel}",
                        category="hardcoded-secret", cwe="CWE-798", target_id=target_id, file=rel, start=i, end=i,
                        excerpt=redact(line.strip()), tool="builtin-secrets", rule_id=name,
                        description="Credential-shaped value (redacted). Not validated or used.",
                        severity="low" if likely_fp else "high",
                        impact="If real and active, grants access to the associated service.",
                        remediation="Rotate with the owner, remove from source/history, use a secret manager.",
                        limitations=["Fallback regex detector (gitleaks unavailable or complementary).",
                                     *(["Looks like a test fixture/example/placeholder."] if likely_fp else [])]))
                    break
    return out, {"tool": "builtin-secrets", "available": True}


# ------------------------------------------------------------ OpenAPI
def openapi(target_dir: Path, target_id: str, spec_rel: str) -> tuple[list, dict]:
    p = target_dir / spec_rel
    text = p.read_text(encoding="utf-8", errors="replace")
    try:
        spec = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
    except Exception as exc:
        return [], {"tool": "builtin-openapi", "available": True, "error": f"unparsable spec: {exc}"}
    out: list[dict] = []
    if not isinstance(spec, dict):
        return [], {"tool": "builtin-openapi", "available": True, "error": "spec is not a mapping"}
    for srv in spec.get("servers") or []:
        url = str(srv.get("url", ""))
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            ln = _line_of(text, url)
            out.append(base_finding(
                title=f"API server declared over plain HTTP: {url}", category="cleartext-transport", cwe="CWE-319",
                target_id=target_id, file=spec_rel, start=ln, end=ln, excerpt=read_lines(target_dir, spec_rel, ln),
                evidence_kind="spec_excerpt", tool="builtin-openapi", rule_id="oas-http-server",
                description="The specification advertises a non-TLS server URL.", severity="medium",
                impact="Credentials and data may transit in cleartext if clients use this server.",
                remediation="Serve the API only over HTTPS and update the specification.", status="confirmed_static"))
    global_sec = spec.get("security")
    schemes = (spec.get("components") or {}).get("securitySchemes") or {}
    for name, sch in schemes.items():
        if isinstance(sch, dict) and sch.get("type") == "apiKey" and sch.get("in") == "query":
            ln = _line_of(text, name)
            out.append(base_finding(
                title=f"API key accepted in query string ({name})", category="credential-in-url", cwe="CWE-598",
                target_id=target_id, file=spec_rel, start=ln, end=ln, excerpt=read_lines(target_dir, spec_rel, ln),
                evidence_kind="spec_excerpt", tool="builtin-openapi", rule_id="oas-apikey-query",
                description="Query-string credentials leak into logs, proxies and browser history.", severity="low",
                impact="Credential exposure via logs/referrers.", remediation="Accept API keys in a header.",
                status="confirmed_static"))
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                continue
            sec = op.get("security", global_sec)
            unauth = sec is None or sec == [] or sec == [{}]
            sensitive = method.lower() != "get" or re.search(r"admin|internal|user|account|payment|withdraw|transfer|token|key", path, re.I)
            if unauth and sensitive:
                ln = _line_of(text, f"{path}:")
                out.append(base_finding(
                    title=f"{method.upper()} {path} declares no authentication requirement",
                    category="missing-authentication", cwe="CWE-306", target_id=target_id, file=spec_rel,
                    start=ln, end=ln, excerpt=read_lines(target_dir, spec_rel, ln), evidence_kind="spec_excerpt",
                    tool="builtin-openapi", rule_id="oas-no-security",
                    description="The operation has no security requirement in the specification. The spec may be "
                                "incomplete; the implementation must be checked.",
                    severity="medium", impact="If the implementation matches the spec, unauthenticated users can "
                                              "invoke a sensitive operation.",
                    remediation="Declare and enforce an authentication scheme for the operation.", status="potential",
                    limitations=["Specification-only observation; implementation not verified."]))
    return out, {"tool": "builtin-openapi", "available": True, "spec": spec_rel}


# ------------------------------------------------------------ passive web headers
def web_headers(obs: dict[str, Any], target_id: str) -> list[dict]:
    h = obs["headers"]
    url = obs["final_url"]
    excerpt_of = lambda keys: "\n".join(f"{k}: {h[k]}" for k in keys if k in h) or "(header absent)"
    out = []
    checks = [
        ("strict-transport-security", url.startswith("https://"), "Missing HSTS header", "CWE-319",
         "Browsers may be downgraded to HTTP on first visit.", "Add Strict-Transport-Security with an adequate max-age."),
        ("content-security-policy", True, "Missing Content-Security-Policy", "CWE-1021",
         "No defence-in-depth against XSS/injection.", "Define a restrictive CSP."),
        ("x-content-type-options", True, "Missing X-Content-Type-Options: nosniff", "CWE-16",
         "MIME sniffing may enable content confusion.", "Send X-Content-Type-Options: nosniff."),
    ]
    for header, applies, title, cwe, impact, fix in checks:
        if applies and header not in h:
            out.append(base_finding(
                title=f"{title} on {url}", category="missing-security-header", cwe=cwe, target_id=target_id,
                file=None, start=None, end=None, url=url, excerpt=f"{header}: (absent)",
                evidence_kind="http_observation", tool="builtin-web", rule_id=f"hdr-{header}",
                description=f"Observed at {obs['observed_at']} via a single GET. Absence of a header is a "
                            "hardening gap, not a vulnerability by itself.",
                severity="low", impact=impact, remediation=fix, status="confirmed_static",
                limitations=["Header-only observation; no exploitability implied."]))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(base_finding(
            title=f"No clickjacking protection header on {url}", category="missing-security-header", cwe="CWE-1021",
            target_id=target_id, file=None, start=None, end=None, url=url, excerpt="x-frame-options: (absent)",
            evidence_kind="http_observation", tool="builtin-web", rule_id="hdr-framing",
            description="Neither X-Frame-Options nor CSP frame-ancestors was observed.", severity="low",
            impact="Clickjacking is possible only if sensitive state-changing UI exists on framable pages.",
            remediation="Send CSP frame-ancestors 'self' (or X-Frame-Options: DENY).", status="confirmed_static"))
    acao, acac = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(base_finding(
            title=f"CORS wildcard origin with credentials on {url}", category="cors-misconfiguration", cwe="CWE-942",
            target_id=target_id, file=None, start=None, end=None, url=url,
            excerpt=excerpt_of(["access-control-allow-origin", "access-control-allow-credentials"]),
            evidence_kind="http_observation", tool="builtin-web", rule_id="cors-wildcard-credentials",
            description="Observed in a normal response (no Origin header was forged). Browsers reject this "
                        "combination, but it indicates a permissive CORS policy that needs review.",
            severity="low", impact="Indicates permissive cross-origin policy.", remediation="Allowlist exact origins.",
            status="confirmed_static"))
    sc = h.get("set-cookie", "")
    if sc:
        missing = [f for f in ("secure", "httponly", "samesite") if f not in sc.lower()]
        if missing:
            out.append(base_finding(
                title=f"Cookie set without {', '.join(missing)} on {url}", category="cookie-attributes", cwe="CWE-614",
                target_id=target_id, file=None, start=None, end=None, url=url, excerpt="set-cookie: " + redact(sc)[:200],
                evidence_kind="http_observation", tool="builtin-web", rule_id="cookie-flags",
                description="Cookie attributes observed in a single response; purpose of the cookie unknown.",
                severity="low", impact="Session cookies without these flags are easier to steal or misuse.",
                remediation="Set Secure, HttpOnly and SameSite on session cookies.", status="confirmed_static"))
    server = h.get("server", "") + " " + h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server):
        out.append(base_finding(
            title=f"Software version disclosed in response headers on {url}", category="information-disclosure",
            cwe="CWE-200", target_id=target_id, file=None, start=None, end=None, url=url,
            excerpt=excerpt_of(["server", "x-powered-by"]), evidence_kind="http_observation", tool="builtin-web",
            rule_id="hdr-version-disclosure", description="Version strings help fingerprinting.",
            severity="informational", impact="Fingerprinting aid only.", remediation="Suppress version banners.",
            status="confirmed_static"))
    return out
