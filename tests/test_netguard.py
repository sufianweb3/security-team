"""Network guard: scope gating, SSRF defence, redirects, methods, budgets.
All network I/O is mocked — no real target is contacted."""
import io
import socket
import urllib.error

import pytest

from auditor import netguard
from auditor.netguard import NetGuard
from auditor.policy import PolicyError
from auditor.scope import Scope, validate

RAW = {
    "scope_version": 1,
    "assessment": {"id": "net1", "name": "Net test", "type": ["website"]},
    "authorization": {"status": "authorized", "basis": "written_permission"},
    "targets": {"web": {"allowed_hosts": ["app.example.com"], "passive_checks": ["security_headers"]}},
    "limits": {"max_http_requests": 3, "min_interval_seconds": 0.5},
}


class FakeResp:
    def __init__(self, status=200, headers=None, body=b"ok"):
        self.status = status
        self.headers = headers or {"Content-Type": "text/html"}
        self._body = body

    def read(self, n=-1):
        return self._body

    def getcode(self):
        return self.status


@pytest.fixture
def guard(tmp_path, monkeypatch):
    scope = validate(Scope(raw=RAW))
    g = NetGuard(scope, tmp_path / "log.jsonl")
    monkeypatch.setattr(netguard, "_tls_info", lambda *a, **k: None)
    monkeypatch.setattr(netguard.time, "sleep", lambda s: None)
    return g


def _dns(mapping):
    def fake(host, *a, **k):
        if host not in mapping:
            raise socket.gaierror("nx")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
    return fake


def _opener(responses, calls):
    class Op:
        def open(self, req, timeout=None):
            calls.append((req.get_method(), req.full_url, req.data))
            return responses.pop(0)
    return lambda *a, **k: Op()


def test_out_of_scope_rejected(guard, monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"evil.com": "93.184.216.34"}))
    monkeypatch.setattr(netguard.urllib.request, "build_opener", _opener([FakeResp()], calls))
    with pytest.raises(PolicyError):
        guard.get("https://evil.com/")
    assert calls == []


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.0.1", "::1", "fd00::1"])
def test_private_resolution_blocked(guard, monkeypatch, ip):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.example.com": ip}))
    monkeypatch.setattr(netguard.urllib.request, "build_opener", _opener([FakeResp()], calls))
    with pytest.raises(PolicyError, match="non-public"):
        guard.get("https://app.example.com/")
    assert calls == []


def test_only_get_head(guard):
    for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        with pytest.raises(PolicyError, match="not permitted"):
            guard.get("https://app.example.com/", method=m)


def test_redirect_to_out_of_scope_blocked(guard, monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.example.com": "93.184.216.34"}))
    redirect = FakeResp(302, {"Location": "https://evil.com/steal"})
    monkeypatch.setattr(netguard.urllib.request, "build_opener", _opener([redirect], calls))
    with pytest.raises(PolicyError, match="redirect"):
        guard.get("https://app.example.com/")
    assert len(calls) == 1


def test_redirect_to_metadata_blocked(guard, monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.example.com": "93.184.216.34"}))
    redirect = FakeResp(301, {"Location": "http://169.254.169.254/latest/meta-data/"})
    monkeypatch.setattr(netguard.urllib.request, "build_opener", _opener([redirect], calls))
    with pytest.raises(PolicyError):
        guard.get("https://app.example.com/")


def test_successful_get_records_and_sends_no_body(guard, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.example.com": "93.184.216.34"}))
    monkeypatch.setattr(netguard.urllib.request, "build_opener",
                        _opener([FakeResp(200, {"Server": "nginx/1.2"})], calls))
    res = guard.get("https://app.example.com/")
    assert res.status == 200 and res.headers["server"] == "nginx/1.2"
    assert calls[0][0] == "GET" and calls[0][2] is None
    assert (tmp_path / "log.jsonl").read_text().count("net.request") == 1


def test_budget_enforced(guard, monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", _dns({"app.example.com": "93.184.216.34"}))
    monkeypatch.setattr(netguard.urllib.request, "build_opener", _opener([FakeResp() for _ in range(10)], calls))
    for _ in range(3):
        guard.get("https://app.example.com/")
    with pytest.raises(PolicyError, match="budget"):
        guard.get("https://app.example.com/")


def test_offline_scope_blocks_everything(tmp_path):
    raw = {**RAW, "authorization": {"status": "unconfirmed", "basis": "written_permission"}}
    g = NetGuard(validate(Scope(raw=raw)), tmp_path / "l.jsonl")
    with pytest.raises(PolicyError, match="offline"):
        g.get("https://app.example.com/")


def test_data_host_only_osv(guard):
    with pytest.raises(PolicyError):
        guard.get("https://evil.com/x", data_endpoint=True)
