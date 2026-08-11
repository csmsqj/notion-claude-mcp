# -*- coding: utf-8 -*-
"""Runtime policy overlay for Notion local gateway v2.1.

This file deliberately lives outside gateway/ because gateway Python sources and
its config directory are protected at permission level 3. START.cmd launches
this wrapper, which imports the original server, installs the overlay, and then
starts the unchanged server entry point.

Policy implemented here:
- Level 3 may run a conservative allowlist of test/build/lint/compiler commands.
- Safe commands are tokenized and run without shell=True; chaining/redirection
  and obvious path escapes are rejected from the level-3 fast path.
- Unknown, shell, network, install, cleanup, and destructive commands keep the
  original level-4 + one-shot approval requirement.
- Small file and empty-directory trash deletion stays at level 3.
- Non-empty-directory or permanent deletion requires level 4 + approval.
- Desktop confirmation lasts 120 seconds. No response executes nothing and the
  tool returns immediately; the pending approval can later be confirmed once.
"""
from __future__ import annotations

import ctypes
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PATCH_VERSION = "2.1.0"
PATCH_DIR = Path(__file__).resolve().parent
NOTION_ROOT = PATCH_DIR.parent
GATEWAY_DIR = NOTION_ROOT / "gateway"
if str(GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(GATEWAY_DIR))

import fileops  # noqa: E402
import policy  # noqa: E402
import server  # noqa: E402
import tools  # noqa: E402


@dataclass(frozen=True)
class CommandAssessment:
    safe: bool
    category: str
    reason: str
    argv: tuple[str, ...]


_SHELL_META = re.compile(r"[\r\n;&|<>`^%!] |\$\(", re.VERBOSE)
_PARENT_SEGMENT = re.compile(r"(^|[\\/])\.\.([\\/]|$)")
_WINDOWS_ABS = re.compile(r"^[A-Za-z]:[\\/]|^\\\\")
_SAFE_SCRIPT_ROOTS = {
    "test", "tests", "build", "check", "lint", "typecheck", "type-check",
    "format", "fmt", "verify", "compile", "package", "bundle", "unit",
    "integration", "e2e", "coverage",
}
_DANGEROUS_NAMES = {
    "rm", "rmdir", "rd", "del", "erase", "remove-item", "clear-content",
    "format", "diskpart", "cipher", "takeown", "icacls", "reg", "regedit",
    "sc", "shutdown", "restart-computer", "bcdedit", "vssadmin", "wmic",
    "taskkill", "kill", "killall", "dd", "mkfs", "robocopy", "xcopy",
    "curl", "wget", "ssh", "scp", "sftp", "ftp", "telnet",
    "powershell", "pwsh", "cmd", "cmd.exe", "bash", "sh", "zsh", "wsl",
}
_SAFE_DIRECT = {
    "pytest": "test", "py.test": "test", "tox": "test", "nox": "test",
    "ruff": "lint", "mypy": "type-check", "pyright": "type-check",
    "black": "format", "isort": "format", "flake8": "lint", "pylint": "lint",
    "eslint": "lint", "prettier": "format", "tsc": "compile",
    "jest": "test", "vitest": "test", "ctest": "test",
    "gcc": "compile", "g++": "compile", "clang": "compile",
    "clang++": "compile", "cl": "compile", "javac": "compile",
    "kotlinc": "compile", "rustc": "compile", "msbuild": "build",
    "webpack": "build", "rollup": "build", "esbuild": "build", "swc": "build",
}
_SAFE_PYTHON_MODULES = {
    "pytest", "unittest", "compileall", "build", "mypy", "pyright", "ruff",
    "black", "isort", "flake8", "pylint",
}
_SAFE_MAVEN_GOALS = {"compile", "test", "package", "verify", "test-compile"}
_SAFE_GRADLE_TASKS = {"build", "test", "check", "assemble", "classes", "jar"}
_SAFE_MAKE_TARGETS = {"all", "build", "test", "tests", "check", "lint", "verify", "compile", "package"}
_SAFE_GIT = {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files", "describe"}

_EXEC_CONTEXT = threading.local()
_DELETE_CONTEXT = threading.local()
_ORIGINAL_EVALUATE = policy.PolicyStore.evaluate
_ORIGINAL_DELETE_HANDLER = tools.t_delete_path
_ORIGINAL_GET_PERMISSION = tools.t_get_permission


def _split_command(command: str) -> list[str]:
    """Use Windows' own command-line parser; fall back to shlex for portability."""
    if os.name == "nt":
        argc = ctypes.c_int(0)
        parser = ctypes.windll.shell32.CommandLineToArgvW
        parser.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        parser.restype = ctypes.POINTER(ctypes.c_wchar_p)
        argv_ptr = parser(command, ctypes.byref(argc))
        if argv_ptr:
            try:
                return [argv_ptr[index] for index in range(argc.value)]
            finally:
                ctypes.windll.kernel32.LocalFree(ctypes.cast(argv_ptr, ctypes.c_void_p))
    return shlex.split(command, posix=(os.name != "nt"))


def _base_name(value: str) -> str:
    name = Path(value.strip().strip('"')).name.lower()
    for suffix in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _argument_paths_confined(args: list[str], cwd: Path) -> tuple[bool, str]:
    """Reject explicit ../ and absolute output/config paths outside cwd.

    Build systems can still execute project-defined hooks, so this is a guardrail,
    not an OS sandbox. Unknown/install/shell commands stay behind level 4.
    """
    for original in args:
        values = [original]
        if original.startswith("-") and "=" in original:
            values.append(original.split("=", 1)[1])
        for value in values:
            text = value.strip().strip('"')
            if not text or text in {".", "./", ".\\"}:
                continue
            if _PARENT_SEGMENT.search(text):
                return False, f"参数包含父目录跳转：{original}"
            if _WINDOWS_ABS.match(text):
                try:
                    candidate = Path(text)
                except OSError:
                    return False, f"无法解析绝对路径参数：{original}"
                if not _is_under(candidate, cwd):
                    return False, f"参数指向工作目录之外：{original}"
    return True, ""


def _first_non_option(args: list[str]) -> tuple[int, str]:
    for index, item in enumerate(args):
        if item and not item.startswith("-"):
            return index, item.lower()
    return -1, ""


def _safe_script_name(value: str) -> bool:
    root = value.lower().split(":", 1)[0]
    return root in _SAFE_SCRIPT_ROOTS and root not in {"clean", "install", "deploy", "publish"}


def _assess_python(args: list[str]) -> tuple[bool, str, str]:
    rest = list(args)
    while rest and re.fullmatch(r"-\d+(?:\.\d+)?", rest[0]):
        rest.pop(0)
    if len(rest) >= 2 and rest[0] == "-m":
        module = rest[1].lower().split(".", 1)[0]
        if module in _SAFE_PYTHON_MODULES:
            return True, "python-test-build", f"允许的 Python 模块：{module}"
        if module == "coverage":
            tail = [item.lower() for item in rest[2:]]
            if tail and tail[0] in {"report", "html", "xml", "json"}:
                return True, "python-coverage", "Coverage 报告命令"
            if len(tail) >= 3 and tail[0] == "run" and tail[1] == "-m" and tail[2] in _SAFE_PYTHON_MODULES:
                return True, "python-coverage", f"Coverage 运行安全模块：{tail[2]}"
        return False, "python-interpreter", "Python 仅允许 -m pytest/unittest/build/检查格式化模块；任意模块需要第 4 级"
    if rest:
        script = rest[0].lower().replace("/", "\\")
        action = rest[1].lower() if len(rest) > 1 else ""
        if script.endswith("manage.py") and action in {"test", "check"}:
            return True, "python-project-test", f"项目管理命令：{action}"
        if script.endswith("setup.py") and action in {"build", "sdist", "bdist_wheel", "check"}:
            return True, "python-package-build", f"Python 打包命令：{action}"
    return False, "python-interpreter", "任意 Python 脚本或 -c 代码可能绕过文件策略，需要第 4 级确认"


def _assess_package_manager(name: str, args: list[str]) -> tuple[bool, str, str]:
    index, first = _first_non_option(args)
    if index < 0:
        return False, "package-manager", "缺少明确的测试或构建子命令"
    if name == "npm":
        if first == "test":
            return True, "js-test", "npm test"
        if first in {"run", "run-script"} and index + 1 < len(args) and _safe_script_name(args[index + 1]):
            return True, "js-script", f"npm 安全脚本：{args[index + 1]}"
    elif name in {"pnpm", "yarn", "bun"}:
        if first in {"test", "build", "check", "lint", "typecheck"}:
            return True, "js-test-build", f"{name} {first}"
        if first in {"run", "run-script"} and index + 1 < len(args) and _safe_script_name(args[index + 1]):
            return True, "js-script", f"{name} 安全脚本：{args[index + 1]}"
        if _safe_script_name(first):
            return True, "js-script", f"{name} 安全脚本：{first}"
    return False, "package-manager", "安装、发布、清理或任意包脚本可能执行外部代码，需要第 4 级确认"


def assess_command(command: str, cwd: Path) -> CommandAssessment:
    text = command.strip()
    if not text:
        return CommandAssessment(False, "invalid", "命令不能为空", tuple())
    if len(text) > 4096:
        return CommandAssessment(False, "complex", "命令过长，无法作为第 3 级安全开发命令", tuple())
    if _SHELL_META.search(text):
        return CommandAssessment(False, "shell", "包含管道、重定向、命令连接或变量展开，必须走第 4 级确认", tuple())
    try:
        argv = _split_command(text)
    except (ValueError, OSError) as exc:
        return CommandAssessment(False, "parse-error", f"命令无法安全分词：{exc}", tuple())
    if not argv:
        return CommandAssessment(False, "invalid", "命令不能为空", tuple())
    confined, why = _argument_paths_confined(argv[1:], cwd)
    if not confined:
        return CommandAssessment(False, "path-escape", why, tuple(argv))

    name = _base_name(argv[0])
    lower_args = [item.lower() for item in argv[1:]]
    if name in _DANGEROUS_NAMES:
        return CommandAssessment(False, "dangerous", f"{name} 属于 shell、网络或破坏性命令", tuple(argv))

    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", name) or name == "py":
        safe, category, reason = _assess_python(lower_args)
        return CommandAssessment(safe, category, reason, tuple(argv))
    if name == "node":
        safe = bool(lower_args) and lower_args[0] in {"--test", "--check"}
        reason = "Node 内置测试/语法检查" if safe else "任意 Node 脚本或 -e 代码需要第 4 级确认"
        return CommandAssessment(safe, "node-test" if safe else "node-runtime", reason, tuple(argv))
    if name in {"npm", "pnpm", "yarn", "bun"}:
        safe, category, reason = _assess_package_manager(name, lower_args)
        return CommandAssessment(safe, category, reason, tuple(argv))
    if name in {"uv", "poetry", "pipenv"}:
        index, first = _first_non_option(lower_args)
        if first == "run" and index + 1 < len(argv) - 1:
            nested_text = subprocess.list2cmdline(list(argv[index + 2 :]))
            nested = assess_command(nested_text, cwd)
            if nested.safe:
                return CommandAssessment(True, f"{name}-run-{nested.category}", f"{name} run：{nested.reason}", tuple(argv))
        return CommandAssessment(False, "environment-manager", "仅允许运行已判定安全的测试/构建命令；同步、安装需第 4 级", tuple(argv))
    if name in _SAFE_DIRECT:
        return CommandAssessment(True, _SAFE_DIRECT[name], f"允许的开发工具：{name}", tuple(argv))
    if name == "vite":
        safe = bool(lower_args) and lower_args[0] == "build"
        return CommandAssessment(safe, "build" if safe else "dev-server", "vite build" if safe else "开发服务器需第 4 级", tuple(argv))
    if name == "go":
        safe = bool(lower_args) and lower_args[0] in {"test", "build", "vet", "fmt", "list"}
        return CommandAssessment(safe, "go-dev" if safe else "go-risky", f"go {lower_args[0]}" if safe else "Go install/generate/run/clean 需第 4 级", tuple(argv))
    if name == "cargo":
        safe = bool(lower_args) and lower_args[0] in {"test", "build", "check", "clippy", "fmt", "doc"}
        return CommandAssessment(safe, "rust-dev" if safe else "rust-risky", f"cargo {lower_args[0]}" if safe else "Cargo clean/install/run/publish 需第 4 级", tuple(argv))
    if name == "dotnet":
        safe = bool(lower_args) and lower_args[0] in {"test", "build", "restore", "format", "pack", "list", "--info", "--version"}
        return CommandAssessment(safe, "dotnet-dev" if safe else "dotnet-risky", f"dotnet {lower_args[0]}" if safe else "dotnet run/clean/publish/tool 需第 4 级", tuple(argv))
    if name in {"mvn", "mvnw"}:
        goals = [item for item in lower_args if item and not item.startswith("-")]
        safe = bool(goals) and all(item.split(":")[-1] in _SAFE_MAVEN_GOALS for item in goals)
        return CommandAssessment(safe, "java-build" if safe else "java-risky", "Maven 编译/测试/打包" if safe else "Maven clean/install/deploy 或未知目标需第 4 级", tuple(argv))
    if name in {"gradle", "gradlew"}:
        tasks = [item for item in lower_args if item and not item.startswith("-")]
        safe = bool(tasks) and all(item.split(":")[-1] in _SAFE_GRADLE_TASKS for item in tasks)
        return CommandAssessment(safe, "java-build" if safe else "java-risky", "Gradle 编译/测试" if safe else "Gradle clean/publish/未知任务需第 4 级", tuple(argv))
    if name in {"make", "nmake", "ninja"}:
        targets = [item for item in lower_args if item and not item.startswith(("-", "/")) and "=" not in item]
        safe = not targets or all(item in _SAFE_MAKE_TARGETS for item in targets)
        return CommandAssessment(safe, "native-build" if safe else "native-risky", "允许的 Make/Ninja 构建目标" if safe else "clean/install/未知构建目标需第 4 级", tuple(argv))
    if name == "cmake":
        blocked = any(item in {"--install", "-p", "-e"} for item in lower_args)
        return CommandAssessment(not blocked, "native-build" if not blocked else "cmake-risky", "CMake 配置/构建" if not blocked else "CMake install/script/-E 命令需第 4 级", tuple(argv))
    if name == "git":
        index, first = _first_non_option(lower_args)
        safe = index >= 0 and first in _SAFE_GIT
        return CommandAssessment(safe, "git-read" if safe else "git-write", f"git {first}" if safe else "Git 写入、清理、重置或未知操作需第 4 级", tuple(argv))

    return CommandAssessment(False, "unknown", f"命令 {name or argv[0]} 不在第 3 级开发命令白名单中", tuple(argv))


def _resolve_executable(value: str, cwd: Path) -> str:
    raw = value.strip().strip('"')
    has_path = any(mark in raw for mark in ("\\", "/"))
    suffixes = ("", ".exe", ".cmd", ".bat") if not Path(raw).suffix else ("",)
    if has_path:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        if candidate.exists():
            return str(candidate.resolve())
    name = _base_name(raw)
    local_dirs = [cwd / ".venv" / "Scripts", cwd / "venv" / "Scripts", cwd / "node_modules" / ".bin"]
    if name in {"gradlew", "mvnw"}:
        local_dirs.insert(0, cwd)
    for directory in local_dirs:
        for suffix in suffixes:
            candidate = directory / (Path(raw).name + suffix)
            if candidate.is_file():
                return str(candidate.resolve())
    path_parts = [item for item in os.environ.get("PATH", "").split(os.pathsep) if item and item not in {".", ".\\", "./"}]
    found = shutil.which(raw, path=os.pathsep.join(path_parts))
    return found or raw


def _decode_output(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("gb18030", errors="replace")


def run_safe_command(assessment: CommandAssessment, cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    """Run an approved level-3 development command without a general shell."""
    argv = list(assessment.argv)
    executable = _resolve_executable(argv[0], cwd)
    direct_argv = [executable, *argv[1:]]
    suffix = Path(executable).suffix.lower()
    if suffix in {".cmd", ".bat"}:
        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        exec_argv = [comspec, "/d", "/s", "/c", subprocess.list2cmdline(direct_argv)]
    else:
        exec_argv = direct_argv
    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    env.setdefault("PIP_NO_INPUT", "1")
    started = time.time()
    try:
        completed = subprocess.run(
            exec_argv,
            shell=False,
            cwd=str(cwd),
            capture_output=True,
            timeout=max(1, int(timeout_seconds)),
            text=False,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        exit_code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = (exc.stderr or b"") + b"\n[gateway] development command timed out"
        exit_code = -1
        timed_out = True
    except FileNotFoundError as exc:
        raise policy.PolicyError("COMMAND_NOT_FOUND", f"找不到命令：{argv[0]}。请确认编译器/测试工具已安装并在 PATH 中。") from exc
    except OSError as exc:
        raise policy.PolicyError("COMMAND_FAILED_TO_START", f"命令无法启动：{exc}") from exc
    limit = 60_000
    out_cut = len(stdout) > limit
    err_cut = len(stderr) > limit
    return {
        "command": subprocess.list2cmdline(argv),
        "cwd": str(cwd),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": int((time.time() - started) * 1000),
        "stdout": _decode_output(stdout[:limit]),
        "stderr": _decode_output(stderr[:limit]),
        "truncated": out_cut or err_cut,
        "command_classification": assessment.category,
        "policy_reason": assessment.reason,
        "safe_dev_command": True,
    }


def _evaluate_v21(self: policy.PolicyStore, raw_path: str, operation: str):
    target, decision = _ORIGINAL_EVALUATE(self, raw_path, operation)

    if operation == policy.OP_EXEC:
        assessment = getattr(_EXEC_CONTEXT, "assessment", None)
        if isinstance(assessment, CommandAssessment) and assessment.safe:
            protected, protected_reason = policy.looks_protected(target.path)
            blocked_codes = {"GLOBAL_LOCK", "DENY_LIST", "PATH_NOT_ALLOWED"}
            if decision.level >= policy.LEVEL_DELETE and decision.code not in blocked_codes and not protected:
                decision.allowed = True
                decision.needs_approval = False
                decision.code = ""
                decision.risk = "low"
                decision.classification = "dev-command"
                decision.reason = f"第 3 级安全开发命令直接放行：{assessment.reason}"
                decision.details = {"command_category": assessment.category}
            elif protected and decision.level < policy.LEVEL_FULL:
                decision.allowed = False
                decision.needs_approval = False
                decision.code = "EXEC_PROTECTED_CWD_REQUIRES_FULL"
                decision.risk = "blocked"
                decision.reason = f"工作目录属于受保护路径（{protected_reason}），命令执行需要第 4 级。"
        return target, decision

    if operation == policy.OP_DELETE and getattr(_DELETE_CONTEXT, "enforce", False):
        if not target.exists or decision.code in {"GLOBAL_LOCK", "DENY_LIST", "PATH_NOT_ALLOWED", "NOT_FOUND"}:
            return target, decision
        mode = str(getattr(_DELETE_CONTEXT, "mode", "trash"))
        nonempty_dir = False
        if target.path.is_dir():
            try:
                next(target.path.iterdir())
                nonempty_dir = True
            except StopIteration:
                nonempty_dir = False
            except OSError:
                nonempty_dir = True
        force_reason = ""
        force_risk = "high"
        force_code = ""
        if mode == "permanent":
            force_reason = "永久删除不可通过网关回收站恢复"
            force_risk = "critical"
            force_code = "PERMANENT_DELETE_REQUIRES_FULL"
        elif nonempty_dir:
            force_reason = "删除非空目录会一次移除整棵目录内容"
            force_risk = "high"
            force_code = "DIRECTORY_DELETE_REQUIRES_FULL"
        if force_reason:
            if decision.level < policy.LEVEL_FULL:
                decision.allowed = False
                decision.needs_approval = False
                decision.code = force_code
                decision.risk = "blocked"
                decision.classification = "permanent" if mode == "permanent" else "directory"
                decision.reason = f"{force_reason}；需要把该授权根设为第 4 级，并由用户确认。"
            elif decision.allowed:
                decision.needs_approval = True
                decision.code = ""
                decision.risk = force_risk
                decision.classification = "permanent" if mode == "permanent" else "directory"
                decision.reason = f"{force_reason}，必须先经用户确认。"
        return target, decision

    return target, decision


def _run_command_v21(args: dict[str, Any]) -> dict[str, Any]:
    command = str(args.get("command") or args.get("cmd") or "").strip()
    if not command:
        raise tools._fail("INVALID_ARGUMENT", "command 不能为空。")
    cwd_raw = str(args.get("cwd") or args.get("workdir") or "").strip()
    if not cwd_raw:
        raise tools._fail("INVALID_ARGUMENT", "必须显式给出 cwd（授权范围内的绝对工作目录）。")
    target = policy.resolve_target(cwd_raw)
    assessment = assess_command(command, target.path)
    _EXEC_CONTEXT.assessment = assessment
    try:
        cwd, info = tools._gate(
            "run_command",
            cwd_raw,
            policy.OP_EXEC,
            preview=command[:600],
            approval_context=tools._operation_context(command=command),
        )
    finally:
        _EXEC_CONTEXT.assessment = None
    if not cwd.is_dir():
        raise tools._fail("NOT_A_DIRECTORY", f"cwd 不是目录：{cwd}")
    if assessment.safe:
        payload = run_safe_command(assessment, cwd, int(policy.POLICY.setting("exec_timeout_seconds")))
    else:
        payload = fileops.run_command(command, cwd, int(policy.POLICY.setting("exec_timeout_seconds")))
        payload["command_classification"] = assessment.category
        payload["policy_reason"] = assessment.reason
        payload["safe_dev_command"] = False
    fileops.audit(
        "exec",
        {
            "tool": "run_command",
            "command": command,
            "cwd": str(cwd),
            "exit_code": payload["exit_code"],
            "classification": assessment.category,
            "safe_dev_command": assessment.safe,
            "approval_id": info.get("approval_id"),
        },
    )
    return tools._ok("run_command", payload, info)


def _delete_path_v21(args: dict[str, Any]) -> dict[str, Any]:
    mode = str(args.get("mode") or policy.POLICY.setting("delete_mode")).lower()
    if mode not in {"trash", "permanent"}:
        mode = str(policy.POLICY.setting("delete_mode"))
    _DELETE_CONTEXT.enforce = True
    _DELETE_CONTEXT.mode = mode
    try:
        return _ORIGINAL_DELETE_HANDLER(args)
    finally:
        _DELETE_CONTEXT.enforce = False
        _DELETE_CONTEXT.mode = ""


def _get_permission_v21(args: dict[str, Any]) -> dict[str, Any]:
    payload = _ORIGINAL_GET_PERMISSION(args)
    level = int(payload.get("level") or 0)
    operations = payload.get("operations", {})
    if level >= policy.LEVEL_DELETE and operations.get("read", {}).get("allowed"):
        operations["exec"] = {
            "allowed": True,
            "needs_approval": False,
            "code": "",
            "reason": (
                "第 3 级允许白名单内的测试、编译、构建、检查和格式化命令；"
                "未知、串联、安装、网络或破坏性命令仍要求第 4 级并人工确认。"
            ),
            "classification": "conditional-dev-command",
        }
    raw = str(args.get("path") or "")
    try:
        target = policy.resolve_target(raw)
        if target.exists and target.path.is_dir():
            try:
                nonempty = next(target.path.iterdir(), None) is not None
            except OSError:
                nonempty = True
            if nonempty:
                operations["delete"] = {
                    "allowed": level >= policy.LEVEL_FULL,
                    "needs_approval": level >= policy.LEVEL_FULL,
                    "code": "" if level >= policy.LEVEL_FULL else "DIRECTORY_DELETE_REQUIRES_FULL",
                    "reason": "非空目录删除属于重大删除，需要第 4 级并人工确认。",
                    "classification": "directory",
                }
    except policy.PolicyError:
        pass
    payload["exec_policy"] = "level3-safe-dev; level4-approved-general"
    return payload


def _approval_hint_v21(item_id: str, reason: str, mode: str, *, popup: str = "") -> str:
    if popup == "timeout":
        return (
            f"本机确认窗已等待 120 秒（审批单 {item_id}），无人操作；本次默认拒绝，任何操作都没有执行。"
            "现在停止重试或轮询，并让用户在本机确认窗或控制台亲自批准。"
            f"客户端不能代替用户批准。原因：{reason}"
        )
    return tools._ORIGINAL_APPROVAL_HINT(item_id, reason, mode, popup=popup)


MODEL_INSTRUCTIONS_V21 = r"""你正在通过本地网关访问用户这台 Windows 电脑上的文件。

访问控制是白名单制，授权根递归覆盖其全部子目录：
  第 1 级 只读：读取、列目录、搜索。
  第 2 级 读写：新建、覆盖、追加、移动、复制。
  第 3 级 开发：在第 2 级基础上，可删除普通小文件和空目录；还可直接运行网关白名单内的
          测试、编译、构建、检查、格式化命令。命令由网关安全分词并避免通用 shell。
  第 4 级 高风险控制：非空目录、永久删除、大文件、系统/凭据路径，以及未知、串联、安装、
          网络或破坏性 shell 命令，必须先取得用户明确同意。

命令规则：
- 测试/编译/构建请直接调用 run_command，并给出授权范围内的绝对 cwd；网关负责判级。
- 第 3 级只放行保守白名单；管道、重定向、&&、任意解释器代码、安装/发布/清理等不会降级放行。
- 不要用命令绕过 read_file/write_file/delete_path 的路径权限。

重大操作确认：
- 高风险操作自动弹出本机确认窗，窗口显示目标、风险、原因和命令预览。
- 用户点击批准：仅本次放行并立即执行；点击拒绝：停止且不要重复请求。
- 确认窗等待 120 秒。无人操作时本次默认拒绝，绝不执行；工具会返回并停止等待。
- 超时后的审批单会暂时保留，用户可稍后在本机控制台亲自批准。
- confirm_action 只能登记拒绝；客户端或模型不能代替本机批准。
- 超时后不要轮询、不要自己批准、不要重复弹窗；只说明没有执行并等待用户下一条消息。
- user_message 仅用于原样记录用户的明确拒绝，不得替用户表态。一次许可只生效一次。

路径规则：
- 所有路径必须是 Windows 绝对路径；不在授权根内就返回 PATH_NOT_ALLOWED。
- 路径不清楚时用 pick_path，让用户亲自在本机选择；新授权前先问清 1-4 级。
- 小文件删除默认进入网关回收站；非空目录和 permanent 删除一律视为重大删除。
- 每次读取、写入、删除、执行和拒绝都会进入审计记录。
"""


def install() -> None:
    if getattr(policy.PolicyStore, "_notion_v21_installed", False):
        return
    policy.PolicyStore._notion_v21_installed = True
    policy.PolicyStore.evaluate = _evaluate_v21

    policy.LEVEL_LABEL[policy.LEVEL_DELETE] = "开发：读写 + 小删除 + 安全测试/编译"
    policy.LEVEL_LABEL[policy.LEVEL_FULL] = "高风险控制（重大操作需确认）"
    policy.LEVEL_HINT[policy.LEVEL_DELETE] = (
        "可读写、删除普通小文件和空目录，并运行白名单内的测试、编译、构建、检查与格式化命令；"
        "非空目录、永久删除和危险命令需要第 4 级。"
    )
    policy.LEVEL_HINT[policy.LEVEL_FULL] = (
        "允许重大删除和通用命令，但每次高风险操作都必须由你在 120 秒本机确认窗或控制台批准。"
    )

    desired = {
        "approval_popup_seconds": 120,
        "approval_wait_seconds": 0,
        "exec_timeout_seconds": 300,
    }
    policy.DEFAULT_CONFIG.update(desired)
    try:
        policy.POLICY.update_settings(desired)
    except Exception:
        with policy.POLICY._lock:
            policy.POLICY._data.update(desired)

    popup_script = PATCH_DIR / "approve-popup-v21.ps1"
    if popup_script.exists():
        fileops.APPROVE_SCRIPT = popup_script

    tools._ORIGINAL_APPROVAL_HINT = tools._approval_hint
    tools._approval_hint = _approval_hint_v21
    tools.t_run_command = _run_command_v21
    tools.t_delete_path = _delete_path_v21
    tools.t_get_permission = _get_permission_v21
    tools.HANDLERS["run_command"] = _run_command_v21
    tools.HANDLERS["delete_path"] = _delete_path_v21
    tools.HANDLERS["get_permission"] = _get_permission_v21

    run_def = tools.TOOL_DEFS_BY_NAME["run_command"]
    run_def["title"] = "执行开发 / 受控命令"
    run_def["description"] = (
        "在授权目录运行命令：第 3 级可直接运行白名单内的测试、编译、构建、检查和格式化命令；"
        "命令连接、重定向、安装、网络、清理、任意脚本及其他未知/危险命令仅限第 4 级并逐次人工确认。"
    )
    run_def["inputSchema"]["properties"]["cwd"]["description"] = (
        "工作目录绝对路径；安全开发命令至少第 3 级，其他命令必须第 4 级"
    )
    delete_def = tools.TOOL_DEFS_BY_NAME["delete_path"]
    delete_def["description"] = (
        "删除文件或目录。第 3 级可删除进入回收站的普通小文件和空目录；"
        "非空目录、永久删除、大文件、系统或凭据类目标必须第 4 级并逐次人工确认。"
    )
    confirm_def = tools.TOOL_DEFS_BY_NAME["confirm_action"]
    confirm_def["description"] = (
        "高风险批准只能由用户在本机确认窗或控制台完成。"
        "客户端只能通过本工具登记拒绝，不能代替用户批准。"
    )

    server.MODEL_INSTRUCTIONS = MODEL_INSTRUCTIONS_V21
    server.SERVER_VERSION = PATCH_VERSION
    server.BaseHandler.server_version = f"NotionGateway/{PATCH_VERSION}"
    fileops.audit(
        "runtime_policy_installed",
        {
            "version": PATCH_VERSION,
            "safe_dev_level": 3,
            "general_exec_level": 4,
            "approval_popup_seconds": 120,
            "approval_wait_seconds": 0,
        },
    )


install()

if __name__ == "__main__":
    server.main()
