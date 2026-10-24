"""Scope validation, SSRF/scope gating, and fail-closed behaviour."""
import pytest

from auditor.scope import Scope, load_scope, validate

ROOT_OK = {
    "scope_version": 1,
    "assessment": {"id": "test-1", "name": "Test assessment", "type": ["website"]},
    "authorization": {"status": "authorized", "basis": "written_permission", "authorized_by": "me"},
    "targets": {"web": {"allowed_hosts": ["app.example.com", "*.api.example.com"],
                        "allowed_path_prefixes": ["/"], "passive_checks": ["security_headers"]}},
}


def _s(raw):
    return validate(Scope(raw=raw))


def test_valid_scope_passes():
    assert not _s(dict(ROOT_OK)).errors


def test_unconfirmed_auth_is_offline():
    raw = {**ROOT_OK, "authorization": {"status": "unconfirmed", "basis": "written_permission"}}
    s = _s(raw)
    assert not s.errors and s.network_mode == "offline"


def test_host_scope_matching():
    s = _s(dict(ROOT_OK))
    assert s.host_in_scope("app.example.com")
    assert s.host_in_scope("v2.api.example.com")      # wildcard subdomain
    assert not s.host_in_scope("api.example.com")     # apex not matched by *.api
    assert not s.host_in_scope("evil.com")
    assert not s.host_in_scope("app.example.com.evil.com")


def test_url_in_scope_and_exclusions():
    raw = {**ROOT_OK, "exclusions": {"paths": ["/admin"]}}
    s = _s(raw)
    assert s.url_in_scope("https://app.example.com/x")[0]
    assert not s.url_in_scope("http://app.example.com/x")[0]      # http not allowed
    assert not s.url_in_scope("https://app.example.com/admin")[0]  # excluded path
    assert not s.url_in_scope("https://evil.com/")[0]
    assert not s.url_in_scope("https://user:pw@app.example.com/")[0]  # creds in url


def test_overbroad_host_rejected():
    raw = {**ROOT_OK, "targets": {"web": {"allowed_hosts": ["*"]}}}
    assert _s(raw).errors


def test_repo_requires_full_commit():
    raw = {**ROOT_OK, "assessment": {"id": "repo-test", "name": "Repo test", "type": ["source_code"]},
           "targets": {"repositories": [{"id": "r", "url": "https://github.com/a/b", "commit": "abc123"}]}}
    assert any("40/64-hex" in e for e in _s(raw).errors)


def test_private_ip_needs_lab():
    raw = {**ROOT_OK, "targets": {"web": {"allowed_hosts": ["10.0.0.5"]}}}
    assert _s(raw).errors
    raw2 = {**raw, "lab": {"allow_private_targets": True}}
    assert not _s(raw2).errors


def test_bounty_requires_policy():
    raw = {**ROOT_OK, "authorization": {"status": "authorized", "basis": "bug_bounty_program",
                                        "program": {"name": "x"}}}
    assert any("policy" in e for e in _s(raw).errors)


def test_example_scopes_load(tmp_path):
    from auditor.policy import PROJECT_ROOT
    for name in ("vulnapp-local.yaml", "example-bugbounty-web.yaml"):
        s = load_scope(PROJECT_ROOT / "config" / "scopes" / name)
        assert not s.errors, (name, s.errors)
    # the GitHub template ships with a placeholder commit and must fail closed until edited
    tmpl = load_scope(PROJECT_ROOT / "config" / "scopes" / "example-github-repo.yaml")
    assert tmpl.errors
