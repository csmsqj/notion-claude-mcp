# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "runtime-patches"))

from command_jobs import CommandJobManager
from redaction import REDACTED, redact_text, redact_value


def command(code: str) -> str:
    parts = [sys.executable, "-c", code]
    if os.name == "nt":
        return subprocess.list2cmdline(parts)
    return " ".join(shlex.quote(part) for part in parts)


def test_redaction() -> None:
    secret_a = "sk-abcdefghijklmnopqrstuvwxyz123456"
    secret_b = "github_pat_abcdefghijklmnopqrstuvwxyz"
    text = f'Authorization: Bearer {secret_a} API_KEY="{secret_b}" --token={secret_a}'
    cleaned = redact_text(text)
    assert secret_a not in cleaned
    assert secret_b not in cleaned
    assert cleaned.count(REDACTED) >= 3
    payload = redact_value({"client_secret": secret_a, "command": text, "nested": [text]})
    assert secret_a not in repr(payload)
    assert payload["client_secret"] == REDACTED


def test_jobs() -> None:
    with tempfile.TemporaryDirectory() as temp:
        manager = CommandJobManager(temp, max_running=2, reuse_seconds=120)

        quick_id, reused = manager.start_or_reuse(command("print('QUICK_OK')"), temp, 5)
        assert not reused
        quick = manager.get(quick_id, wait_seconds=5)
        assert quick["status"] == "succeeded", quick
        assert quick["exit_code"] == 0
        assert "QUICK_OK" in quick["stdout"]

        slow_cmd = command("import time; time.sleep(1.0); print('SLOW_OK')")
        slow_id, reused = manager.start_or_reuse(slow_cmd, temp, 5)
        assert not reused
        duplicate_id, duplicate_reused = manager.start_or_reuse(slow_cmd, temp, 5)
        assert duplicate_reused and duplicate_id == slow_id
        running = manager.get(slow_id)
        assert running["status"] in {"running", "succeeded"}
        finished = manager.get(slow_id, wait_seconds=3)
        assert finished["status"] == "succeeded", finished
        assert "SLOW_OK" in finished["stdout"]

        timeout_id, reused = manager.start_or_reuse(
            command("import time; time.sleep(3.0)"), temp, 1, force_new=True
        )
        assert not reused
        timed_out = manager.get(timeout_id, wait_seconds=3)
        assert timed_out["status"] == "timed_out", timed_out
        assert timed_out["timed_out"] is True

        listed = manager.list_recent(10)
        assert {quick_id, slow_id, timeout_id}.issubset({item["job_id"] for item in listed})


def main() -> None:
    test_redaction()
    test_jobs()
    print("command timeout fix tests: OK")


if __name__ == "__main__":
    main()
