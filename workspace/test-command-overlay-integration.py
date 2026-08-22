# -*- coding: utf-8 -*-
"""Offline integration test for the v2.6 command overlay (does not start a server).

Two parts:
  1. Overlay installation, tool registration, schema, and audit redaction. These
     run anywhere and need no authorized path.
  2. A real short command through run_command/get_command_status. This needs the
     repository directory itself to be authorized at level 2 or higher in the
     local console, so it is skipped with a clear notice when it is not.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "runtime-patches" / "gateway-v21.py"
SPEC = importlib.util.spec_from_file_location("gateway_v26_offline_test", ENTRY)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)

policy = module.policy
tools = module.tools

assert module.PATCH_VERSION == "2.6.0"
assert "get_command_status" in tools.HANDLERS
assert "list_command_jobs" in tools.HANDLERS
run_schema = tools.TOOL_DEFS_BY_NAME["run_command"]["inputSchema"]["properties"]
assert "wait_seconds" in run_schema and "force_new" in run_schema

fake_secret = "sk-offline-test-not-a-real-secret-123456"
module.fileops.audit(
    "command_timeout_redaction_test",
    {"api_key": fake_secret, "command": "tool --token=" + fake_secret},
)
records = module.fileops.tail_audit(20)
record = next(item for item in records if item.get("action") == "command_timeout_redaction_test")
assert fake_secret not in repr(record)
assert "[REDACTED]" in repr(record)


def repo_exec_level() -> int:
    """Effective level for running commands with cwd = this repository."""
    try:
        _target, decision = policy.POLICY.evaluate(str(ROOT), policy.OP_READ)
    except policy.PolicyError:
        return 0
    return int(decision.level) if decision.allowed else 0


level = repo_exec_level()
if level < policy.LEVEL_WRITE:
    print(
        "command timeout overlay integration: PARTIAL OK "
        "(install, schema, and redaction verified; command execution skipped "
        f"because {ROOT} is not authorized at level 2 or higher)"
    )
    raise SystemExit(0)

command = subprocess.list2cmdline(
    [sys.executable, "-c", "import time; time.sleep(1.0); print('OVERLAY_OK')"]
)
result = tools.HANDLERS["run_command"](
    {"command": command, "cwd": str(ROOT), "wait_seconds": 0, "force_new": True}
)
assert result["status"] in {"running", "succeeded"}, result
if result["status"] == "running":
    result = tools.HANDLERS["get_command_status"]({"job_id": result["job_id"], "wait_seconds": 5})
assert result["status"] == "succeeded", result
assert result["exit_code"] == 0
assert "OVERLAY_OK" in result["stdout"]

listed = tools.HANDLERS["list_command_jobs"]({"limit": 5})
assert listed["count"] >= 1, listed
print("command timeout overlay integration: OK")
