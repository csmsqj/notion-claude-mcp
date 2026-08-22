# -*- coding: utf-8 -*-
"""Small, dependency-free redaction helpers for logs and job metadata."""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|"
    r"password|passwd|secret|private[_-]?key|client[_-]?secret)(?:$|[_-])"
)
_KEY_NAME = (
    r"[A-Za-z0-9_.-]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN|AUTH[_-]?TOKEN|"
    r"TOKEN|PASSWORD|PASSWD|SECRET|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)"
)

_QUOTED_ASSIGNMENT = re.compile(
    rf"(?i)(\b{_KEY_NAME}\b\s*(?:=|:)\s*)([\"'])(.*?)(\2)"
)
_UNQUOTED_ASSIGNMENT = re.compile(
    rf"(?i)(\b{_KEY_NAME}\b\s*(?:=|:)\s*)([^\s,;&|]+)"
)
_CLI_SECRET = re.compile(
    r"(?i)(--(?:api[-_]?key|access[-_]?token|refresh[-_]?token|auth[-_]?token|token|"
    r"password|secret|client[-_]?secret)(?:=|\s+))([^\s,;&|]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://[^\s/:@]+:)([^\s/@]+)(@)")
_COMMON_TOKENS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{12,}\b", re.I),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{12,}\b", re.I),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b", re.I),
]


def redact_text(value: str) -> str:
    """Redact common credentials embedded in free-form command/config text."""
    text = str(value)
    text = _QUOTED_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}", text)
    text = _UNQUOTED_ASSIGNMENT.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _CLI_SECRET.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    text = _BEARER.sub("Bearer " + REDACTED, text)
    text = _URL_CREDENTIALS.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", text)
    for pattern in _COMMON_TOKENS:
        text = pattern.sub(REDACTED, text)
    return text


def redact_value(value: Any, *, key: str = "") -> Any:
    """Recursively redact sensitive dictionary values and strings."""
    if key and _SENSITIVE_KEY.search(str(key)):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(item_key): redact_value(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value
