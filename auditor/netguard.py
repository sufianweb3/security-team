"""The ONLY place network requests are made. Read-only (GET/HEAD), scope-gated,
SSRF-hardened, rate-limited and budgeted. There is no code path that sends a
request body, a non-GET/HEAD method, or a request to an out-of-scope host."""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import urllib.request

from . import audit_log
from .policy import PolicyError, load_policy
from .scope import Scope


@dataclass
class HttpResult:
    url: str
    final_url: str
    status: int
    method: str
    headers: dict[str, str]
    body: bytes
    observed_at: str
    tls: dict[str, Any] | None = None


@dataclass
class NetGuard:
    scope: Scope
    log_path: Any
    policy: dict = field(default_factory=load_policy)
    _count: int = 0
    _last_hit: dict[str, float] = field(default_factory=dict)

    # -- SSRF defence: resolve host and reject private / blocked destinations --
    def _resolve_public(self, host: str) -> list[str]:
        net = self.policy["network"]
        if host.lower() in {h.lower() for h in net["blocked_hostnames"]}:
            raise PolicyError(f"blocked hostname: {host}")
        lab = bool((self.scope.raw.get("lab") or {}).get("allow_private_targets"))
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise PolicyError(f"DNS resolution failed for {host}: {exc}") from exc
        ips = sorted({i[4][0] for i in infos})
        for ip in ips:
            addr = ip_address(ip)
            is_private = not addr.is_global or addr.is_loopback or addr.is_link_local or addr.is_reserved
            if is_private and not lab:
                raise PolicyError(f"{host} resolves to non-public address {ip}: refused (SSRF guard)")
        return ips

    def _allowed_host_for_data(self, host: str) -> bool:
        return host.lower() in {h.lower() for h in self.policy["network"]["always_allowed_hosts"]}

    def get(self, url: str, method: str = "GET", *, data_endpoint: bool = False) -> HttpResult:
        net = self.policy["network"]
        method = method.upper()
        if method not in net["allowed_methods"]:
            raise PolicyError(f"HTTP method {method} not permitted (read-only GET/HEAD only)")

        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if data_endpoint:
            if not self._allowed_host_for_data(host):
                raise PolicyError(f"{host} is not an allowed data host")
            if parts.scheme != "https":
                raise PolicyError("data host requires https")
        else:
            ok, why = self.scope.url_in_scope(url)
            if not ok:
                audit_log.append(self.log_path, "net.denied", "netguard", {"url": url, "reason": why}, "deny")
                raise PolicyError(f"out of scope: {why}")

        budget = int(self.scope.limits.get("max_http_requests", net.get("max_http_requests_per_run", 200)))
        if self._count >= budget:
            raise PolicyError(f"HTTP request budget ({budget}) exhausted")

        interval = float(self.scope.limits.get("min_interval_seconds", net["min_interval_seconds_per_host"]))
        wait = interval - (time.monotonic() - self._last_hit.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)

        self._resolve_public(host)
        result = self._request(url, method, net)
        self._last_hit[host] = time.monotonic()
        self._count += 1
        audit_log.append(self.log_path, "net.request", "netguard",
                         {"url": url, "final_url": result.final_url, "method": method,
                          "status": result.status, "bytes": len(result.body)}, "allow")
        return result

    def _request(self, url: str, method: str, net: dict) -> HttpResult:
        redirects = 0
        current = url
        while True:
            parts = urlsplit(current)
            self._resolve_public((parts.hostname or "").lower())
            req = urllib.request.Request(current, method=method)
            req.add_header("User-Agent", net["user_agent"])
            req.add_header("Accept", "*/*")
            opener = urllib.request.build_opener(_NoRedirect())
            try:
                resp = opener.open(req, timeout=net["read_timeout_seconds"])
            except urllib.error.HTTPError as e:
                resp = e  # 4xx/5xx still carry headers we want
            except Exception as exc:
                raise PolicyError(f"request failed: {exc}") from exc
            status = resp.status if hasattr(resp, "status") else resp.getcode()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            if status in (301, 302, 303, 307, 308) and "location" in headers:
                redirects += 1
                if redirects > net["max_redirects"]:
                    raise PolicyError("too many redirects")
                loc = urllib.parse.urljoin(current, headers["location"])
                ok, why = self.scope.url_in_scope(loc)
                if not ok:
                    audit_log.append(self.log_path, "net.redirect_blocked", "netguard",
                                     {"from": current, "to": loc, "reason": why}, "deny")
                    raise PolicyError(f"redirect to out-of-scope destination blocked: {why}")
                current = loc
                continue
            body = b"" if method == "HEAD" else resp.read(net["max_response_bytes"] + 1)
            if len(body) > net["max_response_bytes"]:
                body = body[: net["max_response_bytes"]]
            tls = None
            if parts.scheme == "https":
                key = f"{parts.hostname}:{parts.port or 443}"
                if key not in _TLS_CACHE:
                    _TLS_CACHE[key] = _tls_info(parts.hostname, parts.port or 443)
                tls = _TLS_CACHE[key]
            return HttpResult(url=url, final_url=current, status=status, method=method,
                              headers=headers, body=body,
                              observed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                              tls=tls)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # we handle redirects manually (scope-checked)
        return None


import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402


_TLS_CACHE: dict = {}


def _tls_info(host: str | None, port: int) -> dict[str, Any] | None:
    if not host:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "not_after": cert.get("notAfter"),
                    "subject": dict(x[0] for x in cert.get("subject", [])).get("commonName"),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName"),
                }
    except Exception as exc:  # TLS probe failure is informational, never fatal
        return {"error": str(exc)}
