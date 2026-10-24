"""Scope loading and validation. Fail closed: anything ambiguous => offline only."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from .policy import PROJECT_ROOT, PolicyError

SCHEMA_PATH = PROJECT_ROOT / "schemas" / "scope.schema.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
DEFAULT_REPO_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}
PASSIVE_CHECKS = {"security_headers", "cookies", "tls_metadata", "cors_observation",
                  "robots_txt", "security_txt", "well_known_metadata", "exposed_spec_docs"}


@dataclass
class Scope:
    raw: dict[str, Any]
    path: Path | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # ---- derived properties ------------------------------------------------
    @property
    def assessment_id(self) -> str:
        return self.raw["assessment"]["id"]

    @property
    def authorized(self) -> bool:
        auth = self.raw.get("authorization", {})
        if auth.get("status") != "authorized":
            return False
        exp = auth.get("expires_at")
        if exp:
            try:
                when = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                if when < datetime.now(timezone.utc):
                    return False
            except ValueError:
                return False
        return True

    @property
    def web(self) -> dict[str, Any]:
        return (self.raw.get("targets") or {}).get("web") or {}

    @property
    def network_mode(self) -> str:
        """'offline' unless authorization is explicit AND web hosts are listed."""
        if not self.authorized:
            return "offline"
        if self.web.get("allowed_hosts"):
            return "passive_web"
        return "offline"

    @property
    def business_context(self) -> dict[str, Any] | None:
        return self.raw.get("business_context") or None

    @property
    def limits(self) -> dict[str, Any]:
        return self.raw.get("limits") or {}

    @property
    def exclusions(self) -> dict[str, Any]:
        return self.raw.get("exclusions") or {}

    def passive_checks(self) -> set[str]:
        return set(self.web.get("passive_checks") or []) & PASSIVE_CHECKS

    # ---- host / url matching ----------------------------------------------
    def host_in_scope(self, host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        if not host:
            return False
        for ex in self.exclusions.get("hosts") or []:
            if _host_match(host, ex):
                return False
        return any(_host_match(host, pat) for pat in self.web.get("allowed_hosts") or [])

    def url_in_scope(self, url: str) -> tuple[bool, str]:
        if self.network_mode != "passive_web":
            return False, "scope is offline (authorization not explicit or no web hosts)"
        parts = urlsplit(url)
        allowed_schemes = {"https"} | ({"http"} if self.web.get("allow_plain_http") else set())
        if parts.scheme not in allowed_schemes:
            return False, f"scheme {parts.scheme!r} not allowed"
        if parts.username or parts.password:
            return False, "credentials in URL not allowed"
        if not self.host_in_scope(parts.hostname or ""):
            return False, f"host {parts.hostname!r} not in scope"
        path = parts.path or "/"
        for ex in self.exclusions.get("paths") or []:
            if path.startswith(ex):
                return False, f"path {path!r} excluded"
        prefixes = self.web.get("allowed_path_prefixes") or ["/"]
        if not any(path.startswith(p) for p in prefixes):
            return False, f"path {path!r} outside allowed prefixes"
        return True, "in scope"

    def repo_allowed(self, url: str) -> tuple[bool, str]:
        if not self.authorized:
            return False, "repository fetch requires authorization.status=authorized; supply a local_path instead"
        parts = urlsplit(url)
        if parts.scheme != "https":
            return False, "only https repository URLs are allowed"
        allowed = set(self.raw.get("targets", {}).get("repository_hosts") or DEFAULT_REPO_HOSTS)
        if (parts.hostname or "").lower() not in allowed:
            return False, f"repository host {parts.hostname!r} not allowed"
        return True, "ok"

    def source_excluded(self, rel_path: str) -> bool:
        return any(fnmatch.fnmatch(rel_path, g) for g in self.exclusions.get("source_globs") or [])

    def category_excluded(self, category: str) -> bool:
        return category in set(self.exclusions.get("vuln_categories") or [])

    def summary(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "authorized": self.authorized,
            "network_mode": self.network_mode,
            "types": self.raw["assessment"].get("type"),
            "passive_checks": sorted(self.passive_checks()),
            "errors": self.errors,
            "warnings": self.warnings,
        }


def _host_match(host: str, pattern: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base)   # wildcard never matches the apex
    return host == pattern


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    raw = json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)
    if not isinstance(raw, dict):
        raise PolicyError("scope file is not a mapping")
    scope = Scope(raw=raw, path=p)
    validate(scope)
    return scope


def validate(scope: Scope) -> Scope:
    raw = scope.raw
    if jsonschema is not None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        v = jsonschema.Draft202012Validator(schema)
        for err in sorted(v.iter_errors(raw), key=lambda e: list(e.path)):
            loc = "/".join(str(x) for x in err.path) or "<root>"
            scope.errors.append(f"{loc}: {err.message}")
    if scope.errors:
        return scope

    auth = raw["authorization"]
    if auth["status"] != "authorized":
        scope.warnings.append("authorization not explicit: running OFFLINE (no network to targets)")
    elif not scope.authorized:
        scope.warnings.append("authorization expired or unparsable expires_at: running OFFLINE")
    if auth.get("basis") == "bug_bounty_program" and not (auth.get("program") or {}).get("policy_url") \
            and not (auth.get("program") or {}).get("policy_file"):
        scope.errors.append("authorization.program.policy_url or policy_file required for bug_bounty_program")

    targets = raw.get("targets") or {}
    for repo in targets.get("repositories") or []:
        if not COMMIT_RE.match(str(repo.get("commit", ""))):
            scope.errors.append(f"repository {repo.get('id')}: commit must be a full 40/64-hex SHA (reproducibility)")
    web = targets.get("web") or {}
    for h in web.get("allowed_hosts") or []:
        if h in ("*", "*.*") or h.count("*") > 1 or ("*" in h and not h.startswith("*.")):
            scope.errors.append(f"web.allowed_hosts: overly broad or malformed pattern {h!r}")
        try:
            ip = ipaddress.ip_address(h)
            if not ip.is_global and not (raw.get("lab") or {}).get("allow_private_targets"):
                scope.errors.append(f"web.allowed_hosts: non-public IP {h} requires lab.allow_private_targets")
        except ValueError:
            pass
    unknown = set(web.get("passive_checks") or []) - PASSIVE_CHECKS
    if unknown:
        scope.errors.append(f"web.passive_checks: unsupported checks {sorted(unknown)}")
    for u in web.get("seed_urls") or []:
        host = urlsplit(u).hostname or ""
        if not scope.host_in_scope(host):
            scope.errors.append(f"seed url {u} not covered by allowed_hosts/exclusions")
    _validate_business(scope)
    if (raw.get("lab") or {}).get("allow_private_targets"):
        scope.warnings.append("LAB MODE: private/loopback targets permitted for explicitly listed hosts only")
    if not any(targets.get(k) for k in ("local_paths", "repositories", "api_specs", "documents", "web")):
        scope.errors.append("no targets defined")
    return scope


def _validate_business(scope: Scope) -> None:
    ctx = scope.raw.get("business_context")
    if not ctx:
        return
    targets = scope.raw.get("targets") or {}
    known = {t.get("id") for k in ("local_paths", "api_specs", "documents", "repositories")
             for t in targets.get(k) or []}
    hosts = set((targets.get("web") or {}).get("allowed_hosts") or [])
    ids = set()
    for a in ctx.get("assets") or []:
        if a["id"] in ids:
            scope.errors.append(f"business_context.assets: duplicate id {a['id']!r}")
        ids.add(a["id"])
        m = a.get("match") or {}
        if not (m.get("target_ids") or m.get("hosts")):
            scope.errors.append(f"business_context.assets[{a['id']}]: match needs target_ids or hosts")
        for t in m.get("target_ids") or []:
            if t not in known:
                scope.errors.append(f"business_context.assets[{a['id']}]: unknown target id {t!r}")
        for h in m.get("hosts") or []:
            if not scope.host_in_scope(h) and h not in hosts:
                scope.warnings.append(f"business_context.assets[{a['id']}]: host {h!r} is not in web scope")
    if ctx.get("source", "unknown") == "unknown":
        scope.warnings.append("business_context.source is 'unknown': business priority can only be lowered, never raised")


def require_valid(scope: Scope) -> Scope:
    if scope.errors:
        raise PolicyError("invalid scope: " + "; ".join(scope.errors))
    return scope
