"""Launch the MCP watchdog/supervisor without creating a Windows console window.

This is intentionally invoked by pythonw.exe, not python.exe, so Task Scheduler
never opens a console for the wrapper.  The child PowerShell process additionally
uses CREATE_NO_WINDOW and STARTF_USESHOWWINDOW/SW_HIDE; the PowerShell
-WindowStyle Hidden option alone is not reliable for scheduled tasks.

Only two trusted, fixed scripts are supported.  This file is not a general
command-execution interface and it never elevates privileges.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "gateway" / "logs"
SCRIPTS = {
    "watchdog": ROOT / "watchdog-notion-mcp.ps1",
    "supervisor": ROOT / "supervise-notion-mcp-watchdog.ps1",
}


def main() -> int:
    if os.name != "nt":
        raise RuntimeError("Windows-only scheduled task launcher")

    parser = argparse.ArgumentParser(description="Invisible local MCP watchdog launcher")
    parser.add_argument("--mode", choices=tuple(SCRIPTS), required=True)
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--failure-threshold", type=int, default=3)
    parser.add_argument("--public-failure-threshold", type=int, default=3)
    args = parser.parse_args()

    if not (10 <= args.interval <= 3600):
        parser.error("interval must be between 10 and 3600")
    if not (1 <= args.failure_threshold <= 20):
        parser.error("failure-threshold must be between 1 and 20")
    if not (1 <= args.public_failure_threshold <= 20):
        parser.error("public-failure-threshold must be between 1 and 20")

    ps_exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    script = SCRIPTS[args.mode]
    if not ps_exe.is_file() or not script.is_file():
        raise FileNotFoundError("PowerShell or the chosen watchdog script is missing")

    argv = [
        str(ps_exe),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
    ]
    if args.mode == "watchdog":
        argv.extend([
            "-CheckIntervalSeconds", str(args.interval),
            "-FailureThreshold", str(args.failure_threshold),
            "-PublicFailureThreshold", str(args.public_failure_threshold),
        ])

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with (LOG_DIR / f"{args.mode}-launcher.log").open("ab") as logfile:
        process = subprocess.Popen(
            argv,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=logfile,
            stderr=subprocess.STDOUT,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            close_fds=True,
        )
        return process.wait()


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with (LOG_DIR / "hidden-task-launcher-error.log").open(
            "a", encoding="utf-8"
        ) as handle:
            traceback.print_exc(file=handle)
        sys.exit(1)
    else:
        sys.exit(exit_code)
