"""Passive inventory of an ingested snapshot: languages, frameworks, manifests,
entry points, specs, IaC, CI, and an explicit record of what was not inspected."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

LANG_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".php": "php", ".cs": "csharp", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".swift": "swift", ".scala": "scala", ".sol": "solidity", ".vy": "vyper", ".move": "move",
    ".sh": "shell", ".ps1": "powershell", ".tf": "terraform", ".sql": "sql", ".html": "html",
}
MANIFESTS = {"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock",
             "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
             "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts",
             "gradle.lockfile", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
             "packages.lock.json", "foundry.toml", "hardhat.config.js", "hardhat.config.ts"}
LOCKFILES = {"poetry.lock", "Pipfile.lock", "uv.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
             "bun.lock", "go.sum", "Cargo.lock", "gradle.lockfile", "Gemfile.lock", "composer.lock", "packages.lock.json"}
FRAMEWORK_MARKERS = {
    "flask": re.compile(r"\bflask\b", re.I), "django": re.compile(r"\bdjango\b", re.I),
    "fastapi": re.compile(r"\bfastapi\b", re.I), "express": re.compile(r"\"express\""),
    "nextjs": re.compile(r"\"next\""), "spring": re.compile(r"spring-boot"), "rails": re.compile(r"\brails\b"),
    "laravel": re.compile(r"laravel/framework"), "gin": re.compile(r"gin-gonic/gin"),
    "openzeppelin": re.compile(r"openzeppelin", re.I),
}
ROUTE_PATTERNS = [
    re.compile(r"@(?:app|bp|blueprint|router|api)\.(?:route|get|post|put|patch|delete)\(\s*['\"]([^'\"]+)"),
    re.compile(r"\b(?:app|router)\.(?:get|post|put|patch|delete|all)\(\s*['\"`]([^'\"`]+)"),
    re.compile(r"path\(\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)"),
]
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".jar", ".class", ".so",
              ".dll", ".exe", ".bin", ".woff", ".woff2", ".ttf", ".mp4", ".wasm", ".pyc"}


def inventory(target_dir: Path, target_id: str) -> dict[str, Any]:
    langs: Counter[str] = Counter()
    manifests, lockfiles, specs, iac, ci, docs, binaries, routes = [], [], [], [], [], [], [], []
    frameworks: set[str] = set()
    secrets_like_files, contracts = [], []
    total = 0
    for p in sorted(target_dir.rglob("*")):
        if not p.is_file():
            continue
        total += 1
        rel = p.relative_to(target_dir).as_posix()
        name, ext = p.name, p.suffix.lower()
        if ext in BINARY_EXT:
            binaries.append(rel)
            continue
        if ext in LANG_EXT:
            langs[LANG_EXT[ext]] += 1
        if name in MANIFESTS:
            manifests.append(rel)
            if name in LOCKFILES:
                lockfiles.append(rel)
        low = name.lower()
        if low in ("openapi.yaml", "openapi.yml", "openapi.json", "swagger.json", "swagger.yaml") or \
                re.search(r"(openapi|swagger).*\.(ya?ml|json)$", low):
            specs.append(rel)
        if name == "Dockerfile" or low.endswith((".tf", ".tfvars")) or low in ("docker-compose.yml", "docker-compose.yaml") \
                or "/k8s/" in f"/{rel}" or "helm" in rel.lower():
            iac.append(rel)
        if rel.startswith(".github/workflows/") or low in (".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile"):
            ci.append(rel)
        if ext in (".md", ".rst", ".adoc", ".txt") and name not in MANIFESTS:
            docs.append(rel)
        if low in (".env", ".env.local", ".env.production", "credentials", "id_rsa", "secrets.yml") or low.endswith((".pem", ".key", ".p12")):
            secrets_like_files.append(rel)
        if ext in (".sol", ".vy", ".move"):
            contracts.append(rel)
        if ext in LANG_EXT or name in MANIFESTS:
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")[:400000]
            except OSError:
                continue
            if name in MANIFESTS:
                for fw, rx in FRAMEWORK_MARKERS.items():
                    if rx.search(text):
                        frameworks.add(fw)
            if ext in LANG_EXT:
                for i, line in enumerate(text.splitlines(), 1):
                    for rx in ROUTE_PATTERNS:
                        m = rx.search(line)
                        if m:
                            routes.append({"file": rel, "line": i, "route": m.group(1)})
    plan = recommend_agents(langs, manifests, specs, ci, iac, contracts, routes)
    return {
        "target_id": target_id,
        "files_total": total,
        "languages": dict(langs.most_common()),
        "frameworks": sorted(frameworks),
        "manifests": manifests,
        "lockfiles": lockfiles,
        "missing_lockfiles": _missing_lockfiles(manifests, lockfiles),
        "api_specs": specs,
        "iac": iac,
        "ci_workflows": ci,
        "docs": docs[:200],
        "smart_contracts": contracts,
        "entry_points": routes[:500],
        "secret_like_files": secrets_like_files,
        "not_inspected": {"binary_files": binaries[:200], "binary_count": len(binaries)},
        "recommended_agents": plan,
    }


def _missing_lockfiles(manifests: list[str], lockfiles: list[str]) -> list[str]:
    out = []
    dirs_with_lock = {str(Path(l).parent) for l in lockfiles}
    for m in manifests:
        if Path(m).name in ("package.json", "pyproject.toml", "Cargo.toml", "Gemfile", "composer.json") \
                and str(Path(m).parent) not in dirs_with_lock:
            out.append(m)
    return out


def recommend_agents(langs, manifests, specs, ci, iac, contracts, routes) -> list[str]:
    agents = ["sentinel-recon", "sentinel-secrets"]
    if langs:
        agents += ["sentinel-static-code", "sentinel-authz"]
    if manifests or ci or iac:
        agents.append("sentinel-deps")
    if specs or routes:
        agents.append("sentinel-web-api")
    if contracts or routes:
        agents.append("sentinel-business-logic")
    agents += ["sentinel-verifier", "sentinel-severity", "sentinel-report"]
    return list(dict.fromkeys(agents))


def write_inventory(inv: dict[str, Any], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(inv, indent=2), encoding="utf-8")
