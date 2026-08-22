# -*- coding: utf-8 -*-
"""Install tunnel-safe asynchronous command execution on the active gateway."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from command_jobs import (
    CommandJobCapacityError,
    CommandJobManager,
    CommandJobNotFound,
    CommandJobStartError,
)
from redaction import redact_text, redact_value

SYNC_WAIT_SECONDS = 15
STATUS_WAIT_MAX_SECONDS = 10
MODEL_MARKER = "命令任务与超时回传："


def install_command_timeout_fix(
    core: Any,
    assess_command: Callable[[str, Path], Any],
    exec_context: Any,
    version: str,
) -> None:
    fileops = core.fileops
    policy = core.policy
    tools = core.tools
    server = core.server

    if not getattr(fileops.audit, "_v26_redacting", False):
        original_audit = fileops.audit

        def redacting_audit(action: str, payload: dict[str, Any]) -> None:
            safe = redact_value(payload)
            original_audit(action, safe if isinstance(safe, dict) else {})

        redacting_audit._v26_redacting = True  # type: ignore[attr-defined]
        fileops.audit = redacting_audit

    jobs = CommandJobManager(
        fileops.AUDIT_FILE.parent / "command-jobs",
        max_running=2,
        output_limit_bytes=60_000,
        reuse_seconds=120,
    )

    def guarded_assess(command: str, cwd: Path) -> Any:
        assessment = assess_command(command, cwd)
        if not assessment.safe:
            return assessment
        container = re.search(r"(?i)\.(ucas|utoc|pak)\b", command)
        whole_file = re.search(
            r"(?i)(ReadAllBytes\s*\(|\.read_bytes\s*\(|Get-Content\b[^\r\n]*-Raw)",
            command,
        )
        if container and whole_file:
            try:
                argv = tuple(core._split_command(command))
            except Exception:
                argv = (command,)
            return core.CommandAssessment(
                False,
                "resource-intensive-command",
                "命令会把大型游戏容器整体读入内存，可能压垮网关；请改为分块读取或专用流式工具",
                argv,
            )
        return assessment

    core.assess_command = guarded_assess

    def decorate(payload: dict[str, Any], assessment: Any, reused: bool) -> dict[str, Any]:
        payload["command_classification"] = assessment.category
        payload["policy_reason"] = assessment.reason
        payload["level2_local_command"] = assessment.safe
        payload["os_sandboxed"] = False
        payload["reused_existing_job"] = bool(reused)
        return payload

    def audit_state(
        action: str,
        payload: dict[str, Any],
        assessment: Any,
        info: dict[str, Any],
    ) -> None:
        fileops.audit(
            action,
            {
                "tool": "run_command",
                "job_id": payload.get("job_id"),
                "pid": payload.get("pid"),
                "command": payload.get("command_preview", ""),
                "cwd": payload.get("cwd"),
                "status": payload.get("status"),
                "exit_code": payload.get("exit_code"),
                "timed_out": payload.get("timed_out"),
                "job_duration_ms": payload.get("job_duration_ms"),
                "classification": assessment.category,
                "reused_existing_job": payload.get("reused_existing_job", False),
                "approval_id": info.get("approval_id"),
            },
        )

    def run_command(args: dict[str, Any]) -> dict[str, Any]:
        command = str(args.get("command") or "").strip()
        if not command:
            raise tools._fail("INVALID_ARGUMENT", "command 不能为空。")
        cwd_raw = str(args.get("cwd") or "").strip()
        if not cwd_raw:
            raise tools._fail("INVALID_ARGUMENT", "必须显式给出 cwd（授权范围内的绝对工作目录）。")
        target = policy.resolve_target(cwd_raw)
        assessment = guarded_assess(command, target.path)
        exec_context.assessment = assessment
        try:
            cwd, info = tools._gate(
                "run_command",
                cwd_raw,
                policy.OP_EXEC,
                preview=redact_text(command)[:600],
                approval_context=tools._operation_context(command=command),
            )
        finally:
            exec_context.assessment = None
        if not cwd.is_dir():
            raise tools._fail("NOT_A_DIRECTORY", f"cwd 不是目录：{cwd}")

        wait_seconds = max(0, min(SYNC_WAIT_SECONDS, int(args.get("wait_seconds", SYNC_WAIT_SECONDS))))
        try:
            job_id, reused = jobs.start_or_reuse(
                command,
                cwd,
                int(policy.POLICY.setting("exec_timeout_seconds")),
                force_new=bool(args.get("force_new", False)),
            )
            first = jobs.get(job_id, include_output=False)
        except CommandJobCapacityError as exc:
            raise tools._fail("COMMAND_CAPACITY_REACHED", str(exc)) from exc
        except CommandJobStartError as exc:
            raise tools._fail("COMMAND_START_FAILED", str(exc)) from exc

        if not reused:
            decorate(first, assessment, False)
            audit_state("exec_started", first, assessment, info)
        payload = jobs.get(job_id, wait_seconds=wait_seconds, include_output=True)
        decorate(payload, assessment, reused)
        action = "exec_reused" if reused else ("exec_deferred" if payload.get("status") == "running" else "exec_finished")
        audit_state(action, payload, assessment, info)
        return tools._ok("run_command", payload, info)

    def get_command_status(args: dict[str, Any]) -> dict[str, Any]:
        job_id = str(args.get("job_id") or "").strip()
        wait_seconds = max(0, min(STATUS_WAIT_MAX_SECONDS, int(args.get("wait_seconds", 0))))
        try:
            initial = jobs.get(job_id, include_output=False)
        except CommandJobNotFound as exc:
            raise tools._fail("COMMAND_JOB_NOT_FOUND", str(exc)) from exc
        _, info = tools._gate(
            "get_command_status",
            str(initial.get("cwd") or ""),
            policy.OP_READ,
            preview=f"command job {job_id}",
        )
        payload = jobs.get(job_id, wait_seconds=wait_seconds, include_output=True)
        fileops.audit(
            "exec_status",
            {
                "job_id": job_id,
                "status": payload.get("status"),
                "exit_code": payload.get("exit_code"),
                "timed_out": payload.get("timed_out"),
                "job_duration_ms": payload.get("job_duration_ms"),
            },
        )
        return tools._ok("get_command_status", payload, info)

    def list_command_jobs(args: dict[str, Any]) -> dict[str, Any]:
        limit = max(1, min(50, int(args.get("limit", 20))))
        visible: list[dict[str, Any]] = []
        for item in jobs.list_recent(limit * 3):
            try:
                _, decision = policy.POLICY.evaluate(str(item.get("cwd") or ""), policy.OP_READ)
            except policy.PolicyError:
                continue
            if decision.allowed:
                visible.append(item)
            if len(visible) >= limit:
                break
        return tools._ok(
            "list_command_jobs",
            {"jobs": visible, "count": len(visible), "summary": f"最近 {len(visible)} 个可见命令任务。"},
        )

    def render_job(payload: dict[str, Any]) -> str:
        status = str(payload.get("status") or "unknown")
        job_id = str(payload.get("job_id") or "")
        duration = int(payload.get("job_duration_ms") or 0)
        if status == "running":
            return (
                f"命令任务 {job_id} 已启动，PID {payload.get('pid')}，已运行 {duration} ms。\n"
                "它仍在本机后台运行；请用 get_command_status 查询，不要重复执行同一命令。"
            )
        if status == "unknown_after_restart":
            return f"命令任务 {job_id} 在网关重启前仍在运行，最终状态未知。请先检查目标结果，不要自动重跑。"
        lines = [f"命令任务 {job_id} 已结束：{status}，退出码 {payload.get('exit_code')}，耗时 {duration} ms。"]
        if payload.get("stdout"):
            lines.append("[stdout]\n" + str(payload["stdout"]))
        if payload.get("stderr"):
            lines.append("[stderr]\n" + str(payload["stderr"]))
        if payload.get("truncated"):
            lines.append("输出过长，已保留开头和结尾。")
        return "\n".join(lines)

    def render_jobs(payload: dict[str, Any]) -> str:
        lines = [str(payload.get("summary") or "命令任务列表")]
        for item in payload.get("jobs", []):
            lines.append(
                f"- {item.get('job_id')}: {item.get('status')} · PID {item.get('pid')} · "
                f"{item.get('job_duration_ms', 0)} ms · {item.get('command_preview', '')}"
            )
        return "\n".join(lines)

    definitions = [
        {
            "name": "get_command_status",
            "title": "查询命令任务状态",
            "description": "查询 run_command 返回的 job_id。仍在运行时只查询，不要重复调用 run_command。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": {"type": "string", "description": "run_command 返回的任务编号"},
                    "wait_seconds": {"type": "integer", "minimum": 0, "maximum": STATUS_WAIT_MAX_SECONDS},
                },
                "required": ["job_id"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
            "outputSchema": {"type": "object", "additionalProperties": True},
        },
        {
            "name": "list_command_jobs",
            "title": "列出最近命令任务",
            "description": "列出授权范围内最近的命令任务，用于找回 job_id 和确认是否仍在运行。",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50}},
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
            "outputSchema": {"type": "object", "additionalProperties": True},
        },
    ]
    handlers = {"get_command_status": get_command_status, "list_command_jobs": list_command_jobs}
    for definition in definitions:
        name = definition["name"]
        if name not in tools.TOOL_DEFS_BY_NAME:
            tools.TOOL_DEFS.append(definition)
        tools.TOOL_DEFS_BY_NAME[name] = definition
        tools.HANDLERS[name] = handlers[name]

    tools.t_run_command = run_command
    tools.HANDLERS["run_command"] = run_command
    tools._RENDERERS.update(
        {"run_command": render_job, "get_command_status": render_job, "list_command_jobs": render_jobs}
    )

    run_def = tools.TOOL_DEFS_BY_NAME["run_command"]
    run_def["description"] = (
        "在授权目录运行本地命令；最多同步等待约 15 秒。更久的命令返回 job_id，"
        "必须用 get_command_status 查询，不能重跑。明显破坏性或高资源命令仍需第 4 级确认。"
    )
    run_props = run_def["inputSchema"]["properties"]
    run_props["wait_seconds"] = {
        "type": "integer",
        "minimum": 0,
        "maximum": SYNC_WAIT_SECONDS,
        "description": "同步等待秒数，默认 15；随后返回运行中的 job_id",
    }
    run_props["force_new"] = {
        "type": "boolean",
        "description": "仅在明确需要重复执行同一命令时设为 true",
    }

    addition = (
        "\n\n命令任务与超时回传：\n"
        "- run_command 最多同步等待约 15 秒。若返回 status=running 和 job_id，命令仍在本机执行。\n"
        "- 必须用 get_command_status 查询，不能重跑；job_id 丢失时用 list_command_jobs 找回。\n"
        "- 同一 cwd 和命令在运行中或刚结束时会复用任务，避免传输超时导致重复执行。\n"
    )
    if MODEL_MARKER not in server.MODEL_INSTRUCTIONS:
        server.MODEL_INSTRUCTIONS += addition
    server.SERVER_VERSION = version
    server.BaseHandler.server_version = f"LocalFileMCPGateway/{version}"
    fileops.audit(
        "command_timeout_fix_installed",
        {
            "version": version,
            "sync_wait_seconds": SYNC_WAIT_SECONDS,
            "max_concurrent_commands": 2,
            "dedupe_seconds": 120,
            "output_storage": "file",
            "audit_redaction": True,
        },
    )
