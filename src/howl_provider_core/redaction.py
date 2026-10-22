"""One set of secret-redaction rules for every Howl component that persists text.

Best effort: it lowers the chance a credential is written to an artifact, log or
receipt; it cannot prove one is absent. Redact before writing, never after.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"

#: Token shapes and ``key: value`` / ``key=value`` assignments that carry secrets.
SECRET_PATTERNS: tuple[str, ...] = (
    r"sk-[A-Za-z0-9_-]{12,}",
    r"gh[pousr]_[A-Za-z0-9_-]{12,}",
    r"github_pat_[A-Za-z0-9_-]+",
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z_-]{30,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"(?i)bearer\s+[A-Za-z0-9_./+=-]{15,}",
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{4,}",
    r"(?i)(?:authorization[\"']?\s*[:=]\s*[\"']?)(?:bearer\s+)?[^\s,\"'}]+",
    (
        r"(?i)(?:password|passwd|api[_-]?key|secret_key|secret|token|bearer)"
        r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?[^\s,\"'}]+"
    ),
    r"-----BEGIN[^-]*PRIVATE KEY-----[\s\S]*?-----END[^-]*PRIVATE KEY-----",
)

#: Mapping keys whose values are replaced outright by :func:`scrub`.
SECRET_KEYS: frozenset[str] = frozenset(
    {
        "authorization",
        "api_key",
        "api-key",
        "password",
        "passwd",
        "token",
        "access_token",
        "secret_key",
        "secret",
        "bearer",
    }
)

#: Environment variable names whose values are treated as secrets.
SECRET_ENV_MARKERS: tuple[str, ...] = ("KEY", "TOKEN", "SECRET", "PASSWORD")

_COMPILED = tuple(re.compile(p) for p in SECRET_PATTERNS)


def secret_env_values(environ: Mapping[str, str]) -> list[str]:
    """Values of environment variables whose names look like credentials."""
    return [
        value
        for key, value in environ.items()
        if value and any(marker in key.upper() for marker in SECRET_ENV_MARKERS)
    ]


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Replace known secret shapes, and each literal in ``secrets``, with ``[REDACTED]``."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    for pattern in _COMPILED:
        text = pattern.sub(REDACTED, text)
    return text


def scrub(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Redact strings anywhere in a JSON-like value; drop values under secret keys."""
    secrets = tuple(secrets)
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, Mapping):
        return {
            scrub(k, secrets): REDACTED if str(k).lower() in SECRET_KEYS else scrub(v, secrets)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(v, secrets) for v in value]
    return value
