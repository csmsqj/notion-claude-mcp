#!/usr/bin/env python3
"""Fail closed on high-confidence private material in Git's index and history.

Prints only issue categories and counts; never prints matched values, lines,
URLs, credentials, local file contents, or user-specific paths.
"""
from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys

MAX_BLOB_SIZE = 3 * 1024 * 1024

PRIVATE_PATH_PATTERNS = [
    re.compile(r"^(?:gateway/(?:config|logs|trash)/|config/|logs/|runtime/|cache/|bin/|\.venv/)", re.I),
    re.compile(r"^(?:azure[_-]|90-azure-|hysteria2-test/|setup_fingerprint_http_proxy\.py$|workspace/recovery/)", re.I),
    re.compile(r"(^|/)(?:\.env(?:\..*)?|\.cloudflared|cloudflared\.yml|tunnel-settings\.json|current-url\.txt|notion-connection-details\.txt)$", re.I),
    re.compile(r"(^|/)(?:\.ssh/|id_rsa$|id_ed25519$|\.env/)", re.I),
    re.compile(r"\.(?:pem|p12|pfx|key|log|pid|bak)(?:$|[-.])", re.I),
]
PRIVATE_TEXT_PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "github-token": re.compile(rb"(?:github_pat_[A-Za-z0-9_]{24,}|gh[pousr]_[A-Za-z0-9_]{30,})"),
    "cloud-token": re.compile(rb"(?:xox[baprs]-[A-Za-z0-9-]{15,}|AIza[0-9A-Za-z_-]{30,})"),
    "api-token": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{24,}"),
    "tunnel-credential": re.compile(rb'"(?:TunnelSecret|AccountTag)"\s*:\s*"[^"]{8,}"'),
    "url-password": re.compile(rb"https?://[^\s/:@]{1,128}:[^\s/@]{3,128}@[^\s/]{3,128}"),
    "live-quick-tunnel": re.compile(rb"https?://[a-z0-9-]{6,}\.trycloudflare\.com", re.I),
    "live-quick-tunnel": re.compile(rb"https?://[a-z0-9-]{8,}\.trycloudflare\.com", re.I),
    "local-user-path": re.compile(rb"[A-Za-z]:\\Users\\(?!username\b|yourname\b)[^\\\r\n\"']{3,}\\", re.I),
}
REVIEW_PATTERNS = {
    "possible-email": re.compile(rb"[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I),
    "possible-ip": re.compile(rb"\b(?:[1-9]\d{0,2}\.){3}[1-9]\d{0,2}\b"),
}

def git(*args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("A Git inspection command failed (details suppressed).")
    return proc.stdout

def inspect(data: bytes, path: str, failures: collections.Counter, reviews: collections.Counter) -> None:
    path = path.replace("\\", "/")
    if any(pattern.search(path) for pattern in PRIVATE_PATH_PATTERNS):
        failures["private-file-tracked"] += 1
    if len(data) > MAX_BLOB_SIZE:
        failures["oversized-file-not-scanned"] += 1
        return
    if b"\x00" in data[:4096]:
        return
    known_fake_tokens = {
        "workspace/test-command-overlay-integration.py": {b"sk-offline-test-not-a-real-secret-123456"},
        "workspace/test-command-timeout-fix.py": {b"sk-abcdefghijklmnopqrstuvwxyz123456", b"github_pat_abcdefghijklmnopqrstuvwxyz"},
    }
    for name, pattern in PRIVATE_TEXT_PATTERNS.items():
        for match in pattern.finditer(data):
            value = match.group()
            if name in {"github-token", "api-token"} and value in known_fake_tokens.get(path, set()):
                continue
            if name == "local-user-path" and path == "README.md" and "你的用户名" in value.decode("utf-8", "replace"):
                continue
            failures[name] += 1
    for name, pattern in REVIEW_PATTERNS.items():
        if pattern.search(data):
            reviews[name] += 1

def audit_index(failures: collections.Counter, reviews: collections.Counter) -> int:
    paths = [p for p in git("ls-files", "-z").split(b"\0") if p]
    for path_bytes in paths:
        path = path_bytes.decode("utf-8", errors="surrogateescape")
        data = git("show", f":{path}")
        inspect(data, path, failures, reviews)
    return len(paths)

def audit_history(failures: collections.Counter, reviews: collections.Counter) -> int:
    items = [x for x in git("rev-list", "--objects", "HEAD").splitlines() if b" " in x]
    total = 0
    for item in items:
        sha_bytes, raw_path = item.split(b" ", 1)
        sha = sha_bytes.decode("ascii")
        if git("cat-file", "-t", sha).strip() != b"blob":
            continue
        size = int(git("cat-file", "-s", sha).strip())
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if size > MAX_BLOB_SIZE:
            failures["oversized-file-not-scanned"] += 1
            continue
        inspect(git("cat-file", "blob", sha), path, failures, reviews)
        total += 1
    for email in git("log", "HEAD", "--format=%aE%n%cE").splitlines():
        if email and not email.lower().endswith(b"@users.noreply.github.com"):
            failures["commit-email-not-anonymized"] += 1
    return total

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also scan every Git object reachable from history")
    args = parser.parse_args()
    failures: collections.Counter = collections.Counter()
    reviews: collections.Counter = collections.Counter()
    try:
        count = audit_index(failures, reviews)
        if args.history:
            old_count = audit_history(failures, reviews)
        else:
            old_count = 0
    except Exception:
        print("Privacy audit could not finish; refusing to certify this checkout.")
        return 2
    print(f"Privacy audit: inspected {count} staged/tracked files and {old_count} historical blobs.")
    for category, count in sorted(failures.items()):
        print(f"BLOCKED category={category} matches={count} (values suppressed)")
    for category, count in sorted(reviews.items()):
        print(f"REVIEW category={category} matches={count} (values suppressed)")
    if failures:
        print("FAIL: high-confidence private material needs review before publishing.")
        return 1
    print("PASS: no high-confidence private material detected in HEAD; review warnings manually.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
