# -*- coding: utf-8 -*-
"""Notion local gateway policy v2.2.3 entry point.

User-selected access model:
- Level 1: read only.
- Level 2: file writes plus general local Python/shell/development commands.
- Level 3: level 2 plus deletion of ordinary small files.
- Level 4: directory deletion, permanent/large/protected deletion, and commands
  that visibly perform destructive cleanup; each requires explicit approval.
- Deleting an authorized root or a drive root is always forbidden.

Important boundary: arbitrary Python/shell code is not an OS sandbox. A command
can hide destructive behavior. This overlay blocks common destructive forms and
instructs the agent to use delete_path, but level 2 command execution still
means trusting the command/project under the current Windows account.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

PATCH_VERSION = "2.5.0"
PATCH_DIR = Path(__file__).resolve().parent
CORE_PATH = PATCH_DIR / "gateway-v21-core.py"
MODULE_NAME = "notion_gateway_v21_core"
SPEC = importlib.util.spec_from_file_location(MODULE_NAME, CORE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load runtime policy core: {CORE_PATH}")
core = importlib.util.module_from_spec(SPEC)
sys.modules[MODULE_NAME] = core
SPEC.loader.exec_module(core)

fileops = core.fileops
policy = core.policy
tools = core.tools
server = core.server
APPROVALS = tools.APPROVALS

# Common explicit deletion / destructive-cleanup spellings. This is deliberately
# a guardrail, not a claim that arbitrary code can be perfectly inspected.
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"(?i)(^|[\s;&|])(rm|rmdir|rd|del|erase|remove-item|clear-content|shred)(?=\s|$)"),
    re.compile(r"(?i)\b(shutil\.rmtree|os\.(remove|unlink|rmdir|removedirs)|pathlib\.Path\([^\n]*\)\.(unlink|rmdir))\s*\("),
    re.compile(r"(?i)\.(unlink|rmdir)\s*\("),
    re.compile(r"(?i)\b(fs\.(rm|rmdir|unlink|rmSync|rmdirSync|unlinkSync)|File\.Delete|Directory\.Delete)\s*\("),
    re.compile(r"(?i)\bgit\s+(clean\b|reset\s+--hard\b|checkout\s+--\s+\.|restore\s+\.)"),
    re.compile(r"(?i)\b(npm|pnpm|yarn|bun)\s+(run\s+)?clean\b"),
    re.compile(r"(?i)\b(cargo|dotnet|mvn|mvnw|gradle|gradlew|make|nmake)\s+clean\b"),
    re.compile(r"(?i)\b(format\s+[A-Za-z]:|diskpart\b|mkfs\b|dd\s+if=|bcdedit\b|vssadmin\b)"),
    re.compile(r"(?i)\brobocopy\b[^\r\n]*(/mir|/purge)\b"),
    re.compile(r"(?i)\b(reg\s+delete|sc\s+delete|shutdown\s+[/\-][sr]|restart-computer\b)"),
]

_ORIGINAL_EVALUATE = core._ORIGINAL_EVALUATE
_ORIGINAL_DELETE_HANDLER = core._ORIGINAL_DELETE_HANDLER
_EXEC_CONTEXT = core._EXEC_CONTEXT
_DELETE_CONTEXT = core._DELETE_CONTEXT


def assess_command(command: str, cwd: Path) -> core.CommandAssessment:
    """Allow general level-2 commands unless an obvious destructive form appears."""
    text = command.strip()
    if not text:
        return core.CommandAssessment(False, "invalid", "命令不能为空", tuple())
    try:
        argv = tuple(core._split_command(text))
    except Exception:
        # General shell syntax may not map to a single argv; shell=True will parse it.
        argv = (text,)
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            return core.CommandAssessment(
                False,
                "destructive-command",
                "命令包含显式删除、清理、磁盘/系统破坏动作；需要第 4 级逐次确认",
                argv,
            )
    return core.CommandAssessment(
        True,
        "local-command",
        "第 2 级允许的本地 Python / shell / 测试 / 编译命令",
        argv,
    )


def _same_path(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    return os.path.normcase(os.path.abspath(str(left))) == os.path.normcase(os.path.abspath(str(right)))


def evaluate_v22(self: policy.PolicyStore, raw_path: str, operation: str):
    target, decision = _ORIGINAL_EVALUATE(self, raw_path, operation)

    if operation == policy.OP_EXEC:
        assessment = getattr(_EXEC_CONTEXT, "assessment", None)
        if isinstance(assessment, core.CommandAssessment):
            blocked_codes = {"GLOBAL_LOCK", "DENY_LIST", "PATH_NOT_ALLOWED"}
            protected, protected_reason = policy.looks_protected(target.path)
            if assessment.safe:
                if decision.level >= policy.LEVEL_WRITE and decision.code not in blocked_codes and not protected:
                    decision.allowed = True
                    decision.needs_approval = False
                    decision.code = ""
                    decision.risk = "medium"
                    decision.classification = "local-command"
                    decision.reason = assessment.reason
                    decision.details = {"command_category": assessment.category, "sandboxed": False}
                elif protected and decision.level < policy.LEVEL_FULL:
                    decision.allowed = False
                    decision.needs_approval = False
                    decision.code = "EXEC_PROTECTED_CWD_REQUIRES_FULL"
                    decision.risk = "blocked"
                    decision.reason = f"工作目录属于受保护路径（{protected_reason}），命令执行需要第 4 级。"
            elif decision.code not in blocked_codes:
                if decision.level < policy.LEVEL_FULL:
                    decision.allowed = False
                    decision.needs_approval = False
                    decision.code = "DESTRUCTIVE_COMMAND_REQUIRES_FULL"
                    decision.risk = "blocked"
                    decision.classification = "destructive-command"
                    decision.reason = assessment.reason
                elif decision.allowed:
                    decision.needs_approval = True
                    decision.code = ""
                    decision.risk = "critical"
                    decision.classification = "destructive-command"
                    decision.reason = assessment.reason
        return target, decision

    if operation == policy.OP_DELETE and getattr(_DELETE_CONTEXT, "enforce", False):
        if not target.exists or decision.code in {"GLOBAL_LOCK", "DENY_LIST", "PATH_NOT_ALLOWED", "NOT_FOUND"}:
            return target, decision
        mode = str(getattr(_DELETE_CONTEXT, "mode", "trash"))
        is_directory = target.path.is_dir()
        deleting_authorized_root = bool(is_directory and decision.root_path and _same_path(target.path, decision.root_path))
        deleting_drive_root = bool(is_directory and policy.is_drive_root(target.path))

        if deleting_authorized_root or deleting_drive_root:
            decision.allowed = False
            decision.needs_approval = False
            decision.code = "ROOT_DELETE_FORBIDDEN"
            decision.risk = "blocked"
            decision.classification = "root-directory"
            decision.reason = "禁止通过网关删除驱动器根目录或当前授权根本身；请在本机人工处理。"
            return target, decision

        force_reason = ""
        force_risk = "high"
        force_code = ""
        if mode == "permanent":
            force_reason = "永久删除不可通过网关回收站恢复"
            force_risk = "critical"
            force_code = "PERMANENT_DELETE_REQUIRES_FULL"
        elif is_directory:
            force_reason = "删除目录（包括空目录）属于重大结构变更"
            force_risk = "high"
            force_code = "DIRECTORY_DELETE_REQUIRES_FULL"

        if force_reason:
            if decision.level < policy.LEVEL_FULL:
                decision.allowed = False
                decision.needs_approval = False
                decision.code = force_code
                decision.risk = "blocked"
                decision.classification = "permanent" if mode == "permanent" else "directory"
                decision.reason = f"{force_reason}；需要第 4 级并由用户明确确认。"
            elif decision.allowed:
                decision.needs_approval = True
                decision.code = ""
                decision.risk = force_risk
                decision.classification = "permanent" if mode == "permanent" else "directory"
                decision.reason = f"{force_reason}，必须先经用户确认。"
        return target, decision

    return target, decision


def run_command_v22(args: dict[str, Any]) -> dict[str, Any]:
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

    payload = fileops.run_command(command, cwd, int(policy.POLICY.setting("exec_timeout_seconds")))
    payload["command_classification"] = assessment.category
    payload["policy_reason"] = assessment.reason
    payload["level2_local_command"] = assessment.safe
    payload["os_sandboxed"] = False
    fileops.audit(
        "exec",
        {
            "tool": "run_command",
            "command": command,
            "cwd": str(cwd),
            "exit_code": payload["exit_code"],
            "classification": assessment.category,
            "level2_local_command": assessment.safe,
            "approval_id": info.get("approval_id"),
        },
    )
    return tools._ok("run_command", payload, info)


def get_permission_v22(args: dict[str, Any]) -> dict[str, Any]:
    payload = core._ORIGINAL_GET_PERMISSION(args)
    level = int(payload.get("level") or 0)
    operations = payload.get("operations", {})
    raw = str(args.get("path") or "")
    try:
        target = policy.resolve_target(raw)
        protected, protected_reason = policy.looks_protected(target.path)
    except policy.PolicyError:
        target = None
        protected, protected_reason = False, ""

    if level >= policy.LEVEL_WRITE and operations.get("read", {}).get("allowed") and not protected:
        operations["exec"] = {
            "allowed": True,
            "needs_approval": False,
            "code": "",
            "reason": "第 2 级允许一般本地 Python/shell/测试/编译命令；显式破坏性命令需要第 4 级确认。",
            "classification": "conditional-local-command",
        }
    elif protected:
        operations["exec"] = {
            "allowed": level >= policy.LEVEL_FULL,
            "needs_approval": level >= policy.LEVEL_FULL,
            "code": "" if level >= policy.LEVEL_FULL else "EXEC_PROTECTED_CWD_REQUIRES_FULL",
            "reason": f"工作目录属于受保护路径（{protected_reason}），命令执行需要第 4 级并确认。",
            "classification": "protected",
        }

    if target is not None and target.exists and target.path.is_dir():
        deleting_root = bool(payload.get("root") and _same_path(target.path, payload["root"]))
        if deleting_root or policy.is_drive_root(target.path):
            operations["delete"] = {
                "allowed": False,
                "needs_approval": False,
                "code": "ROOT_DELETE_FORBIDDEN",
                "reason": "禁止通过网关删除驱动器根目录或当前授权根本身。",
                "classification": "root-directory",
            }
        else:
            operations["delete"] = {
                "allowed": level >= policy.LEVEL_FULL,
                "needs_approval": level >= policy.LEVEL_FULL,
                "code": "" if level >= policy.LEVEL_FULL else "DIRECTORY_DELETE_REQUIRES_FULL",
                "reason": "目录删除属于第 4 级重大操作，需要逐次人工确认。",
                "classification": "directory",
            }
    payload["exec_policy"] = "level2-general-local; level4-obvious-destructive"
    payload["command_sandboxed"] = False
    return payload


# -------- 120-second desktop confirmation with quick-tunnel-safe return --------
def _read_popup_result(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    decision = str(data.get("decision") or "")
    return decision if decision in {"approve", "deny", "timeout"} else ""


def _finish_deferred_popup(process: subprocess.Popen[Any], out_file: Path, approval_id: str, timeout_seconds: int) -> None:
    decision = ""
    try:
        deadline = time.time() + max(20, int(timeout_seconds) + 20)
        while time.time() < deadline:
            decision = _read_popup_result(out_file)
            if decision:
                break
            if process.poll() is not None:
                decision = _read_popup_result(out_file)
                break
            time.sleep(0.25)
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass
        if decision in {"approve", "deny"}:
            try:
                item = APPROVALS.decide(
                    approval_id,
                    decision == "approve",
                    by="desktop",
                    user_reply="批准（本机确认窗，延迟返回）" if decision == "approve" else "拒绝（本机确认窗，延迟返回）",
                )
                fileops.audit(
                    "popup_deferred_" + decision,
                    {"approval_id": approval_id, "status": item.status, "transport": "quick-tunnel-safe"},
                )
            except KeyError:
                fileops.audit("popup_deferred_orphan", {"approval_id": approval_id, "decision": decision})
        elif decision == "timeout":
            # Fail closed for this attempt, but leave the approval pending so an
            # explicit later chat reply can authorize one retry.
            fileops.audit(
                "popup_deferred_timeout",
                {"approval_id": approval_id, "default": "no-execution", "seconds": timeout_seconds},
            )
        else:
            fileops.audit("popup_deferred_unavailable", {"approval_id": approval_id})
    finally:
        out_file.unlink(missing_ok=True)
        try:
            fileops._popup_lock.release()
        except RuntimeError:
            pass


def ask_desktop_v22(
    *,
    operation: str,
    path: str,
    risk: str,
    reason: str,
    preview: str,
    approval_id: str,
    timeout_seconds: int,
) -> str:
    script = PATCH_DIR / "approve-popup-v21.ps1"
    if os.name != "nt" or not script.exists():
        return "unavailable"
    if not fileops._popup_lock.acquire(blocking=False):
        return "unavailable"
    out_file = Path(tempfile.gettempdir()) / f"gw-approve-v22-{os.getpid()}-{os.urandom(4).hex()}.json"
    command = [
        "powershell.exe", "-STA", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(script), "-OutFile", str(out_file), "-Operation", operation,
        "-Path", path, "-Risk", risk, "-Reason", reason, "-Preview", preview[:1200],
        "-ApprovalId", approval_id, "-TimeoutSeconds", str(max(10, int(timeout_seconds))),
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError:
        fileops._popup_lock.release()
        return "unavailable"

    # Keep the HTTP request below the quick-tunnel ~100 second ceiling. The local
    # popup itself remains alive for the full configured 120 seconds.
    deadline = time.time() + min(85, max(10, int(timeout_seconds)))
    while time.time() < deadline:
        decision = _read_popup_result(out_file)
        if decision:
            out_file.unlink(missing_ok=True)
            fileops._popup_lock.release()
            return decision
        if process.poll() is not None:
            decision = _read_popup_result(out_file)
            out_file.unlink(missing_ok=True)
            fileops._popup_lock.release()
            return decision or "unavailable"
        time.sleep(0.20)

    threading.Thread(
        target=_finish_deferred_popup,
        args=(process, out_file, approval_id, int(timeout_seconds)),
        name=f"notion-approval-{approval_id}",
        daemon=True,
    ).start()
    return "deferred"


_ORIGINAL_APPROVAL_HINT = tools._approval_hint


def approval_hint_v22(item_id: str, reason: str, mode: str, *, popup: str = "") -> str:
    if popup == "deferred":
        return (
            f"审批单 {item_id} 的本机确认窗会继续显示到 120 秒；为避免公网隧道超时，当前请求已安全返回，"
            "任何操作都没有执行。停止轮询和自动重试，并让用户在本机确认窗或控制台亲自批准。"
        "客户端不能通过 confirm_action 批准。"
            f"原因：{reason}"
        )
    return _ORIGINAL_APPROVAL_HINT(item_id, reason, mode, popup=popup)


MODEL_INSTRUCTIONS_V22 = r"""你正在通过本地网关访问用户这台 Windows 电脑上的文件。授权根递归覆盖子目录。

权限级别：
1. 只读：读取、列目录、搜索。
2. 开发：第 1 级 + 创建、覆盖、追加、移动、复制，以及一般本地 Python、shell、测试、编译命令。
3. 项目维护：第 2 级 + 通过 delete_path 删除普通小文件；默认进入网关回收站。
4. 高风险：删除目录、永久删除、大文件或系统/凭据目标，以及检测到明显删除/清理/系统破坏的命令；每次人工确认。

硬性规则：
- 禁止通过网关删除驱动器根目录或当前授权根本身，即使是第 4 级也不放行。
- 删除目录（包括空目录）一律是第 4 级。普通小文件删除是第 3 级。
- 删除文件内容中的几行、修改代码、重写文件属于写入，第 2 级即可。
- 第 2 级可以运行一般 Python/shell 命令，但这不是操作系统沙箱。不要用命令规避 delete_path；
  任何删除、清理、重置或权限/磁盘破坏都必须改用受控工具或第 4 级确认。
- 命令 cwd 必须是授权范围内的 Windows 绝对目录；路径不明时用 pick_path，不得猜测或绕过白名单。

确认流程：
- 高风险操作弹出本机确认窗，总倒计时 120 秒。批准仅放行一次；明确拒绝后不得自动重试。
- 无人操作时本次默认不执行。审批单暂时保留，用户只能在本机确认窗或控制台亲自批准。
- confirm_action 只能登记拒绝，客户端或模型不能用它批准，避免伪造用户同意。
- 快速隧道同步请求最多安全等待约 85 秒；若返回 popup=deferred，窗口仍会在电脑上继续到 120 秒。
  此时停止轮询，告诉用户尚未执行，并等待用户下一条消息。
- user_message 仅用于原样记录用户的明确拒绝，不得替用户表态。

所有读取、写入、删除、命令、批准和拒绝都会进入审计日志。
"""


def install_v22() -> None:
    policy.PolicyStore.evaluate = evaluate_v22
    core.assess_command = assess_command

    policy.LEVEL_LABEL[policy.LEVEL_READ] = "只读"
    policy.LEVEL_LABEL[policy.LEVEL_WRITE] = "开发：读写 + 本地命令"
    policy.LEVEL_LABEL[policy.LEVEL_DELETE] = "项目维护：+ 普通小文件删除"
    policy.LEVEL_LABEL[policy.LEVEL_FULL] = "高风险：目录/重大删除需确认"
    policy.LEVEL_HINT[policy.LEVEL_WRITE] = (
        "可创建、修改、移动、复制文件，并执行一般本地 Python/shell/测试/编译命令；不允许文件删除。"
    )
    policy.LEVEL_HINT[policy.LEVEL_DELETE] = (
        "在第 2 级基础上，可通过 delete_path 删除普通小文件；目录、永久、大型和受保护删除仍需第 4 级。"
    )
    policy.LEVEL_HINT[policy.LEVEL_FULL] = (
        "可请求目录和其他重大删除或明显破坏性命令；每次都要经 120 秒本机确认窗或控制台批准。"
    )

    desired = {"approval_popup_seconds": 120, "approval_wait_seconds": 0, "exec_timeout_seconds": 300}
    policy.DEFAULT_CONFIG.update(desired)
    try:
        policy.POLICY.update_settings(desired)
    except Exception:
        with policy.POLICY._lock:
            policy.POLICY._data.update(desired)

    fileops.APPROVE_SCRIPT = PATCH_DIR / "approve-popup-v21.ps1"
    fileops.ask_desktop = ask_desktop_v22
    tools._approval_hint = approval_hint_v22
    tools.t_run_command = run_command_v22
    tools.t_get_permission = get_permission_v22
    tools.HANDLERS["run_command"] = run_command_v22
    tools.HANDLERS["get_permission"] = get_permission_v22
    # Keep the core delete wrapper: it sets the per-call delete context consumed above.
    tools.HANDLERS["delete_path"] = core._delete_path_v21

    # Keep action tools visible in fresh chats. Client connection settings
    # control outer confirmations; the gateway enforces per-call Level 4 risk.
    action_annotations = {
        "write_file": {"destructiveHint": True, "openWorldHint": False},
        "create_dir": {"destructiveHint": False, "openWorldHint": False},
        "move_path": {"destructiveHint": True, "openWorldHint": False},
        "copy_path": {"destructiveHint": True, "openWorldHint": False},
        "delete_path": {"destructiveHint": True, "openWorldHint": False},
        "run_command": {"destructiveHint": True, "openWorldHint": True},
        "pick_path": {"destructiveHint": False, "openWorldHint": False},
        "confirm_action": {"destructiveHint": False, "openWorldHint": False},
    }
    for tool_name, hints in action_annotations.items():
        annotations = tools.TOOL_DEFS_BY_NAME[tool_name].setdefault("annotations", {})
        annotations.update({"readOnlyHint": False, **hints})
        annotations.pop("requiresConfirmation", None)

    for definition in tools.TOOL_DEFS:
        definition.setdefault("outputSchema", {"type": "object", "additionalProperties": True})

    run_def = tools.TOOL_DEFS_BY_NAME["run_command"]
    run_def["title"] = "执行本地命令"
    run_def["description"] = (
        "在授权目录运行本地 Python、shell、测试或编译命令。一般命令从第 2 级起可执行；"
        "检测到显式删除、清理、磁盘或系统破坏动作时，必须第 4 级并逐次人工确认。"
    )
    run_def["inputSchema"]["properties"]["cwd"]["description"] = (
        "授权范围内的工作目录绝对路径；一般命令至少第 2 级"
    )
    delete_def = tools.TOOL_DEFS_BY_NAME["delete_path"]
    delete_def["description"] = (
        "第 3 级可删除进入回收站的普通小文件；删除任何目录、永久删除、大文件或受保护目标"
        "必须第 4 级并逐次确认。驱动器根和当前授权根本身始终禁止删除。"
    )
    confirm_def = tools.TOOL_DEFS_BY_NAME["confirm_action"]
    confirm_def["description"] = (
        "高风险批准只能由用户在本机确认窗或控制台完成。"
        "客户端只能通过本工具登记拒绝，不能代替用户批准。"
    )

    server.MODEL_INSTRUCTIONS = MODEL_INSTRUCTIONS_V22
    server.SERVER_VERSION = PATCH_VERSION
    server.BaseHandler.server_version = f"LocalFileMCPGateway/{PATCH_VERSION}"
    fileops.audit(
        "runtime_policy_installed",
        {
            "version": PATCH_VERSION,
            "general_exec_level": 2,
            "small_file_delete_level": 3,
            "directory_delete_level": 4,
            "root_delete": "forbidden",
            "popup_seconds": 120,
            "sync_wait_seconds": 85,
            "os_sandboxed": False,
        },
    )


install_v22()

if __name__ == "__main__":
    server.main()
