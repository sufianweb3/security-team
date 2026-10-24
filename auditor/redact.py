"""Secret redaction used for every log line, agent-facing output and report."""
from __future__ import annotations

import math
import re
from collections import Counter

# High-signal credential patterns (subset; gitleaks remains the primary detector).
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b")),
    ("aws-secret-access-key", re.compile(r"(?i)aws(.{0,20})?(secret|private)?.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("github-fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)")),
    ("url-credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")),
    ("generic-assignment", re.compile(
        r"(?i)\b(pass(?:word|wd)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b"
        r"(\s*[:=]\s*|\s*=>\s*)(['\"])([^'\"\s]{6,})(['\"])")),
]

REDACTED = "[REDACTED]"


def _mask(value: str) -> str:
    if len(value) <= 8:
        return REDACTED
    return f"{value[:4]}…{REDACTED}"


def redact(text: str) -> str:
    """Redact known secret shapes. Keeps a 4-char prefix so humans can locate it."""
    if not text:
        return text
    out = text
    for name, pat in PATTERNS:
        if name == "url-credentials":
            out = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}:{REDACTED}@", out)
        elif name == "generic-assignment":
            out = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{_mask(m.group(4))}{m.group(5)}", out)
        elif name == "private-key-block":
            out = pat.sub("-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----", out)
        else:
            out = pat.sub(lambda m: _mask(m.group(0)), out)
    return out


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact_obj(obj):
    """Recursively redact strings inside JSON-like structures."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
