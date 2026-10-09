# -*- coding: utf-8 -*-
"""Narrow, auditable development actions for the local MCP gateway.

These tools use the existing gateway authorization checks. They do not grant
platform permissions or bypass approval for protected local paths.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_BACKUP_NAME = re.compile(r"^backup/[A-Za-z0-9][A-Za-z0-9._/-]{0,90}$")
_MAX_TEXT_FILE_BYTES = 1024 * 1024
_MAX_REPLACEMENT_BYTES = 48 * 1024


def _branch_name(value: str) -> str:
    if not value:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"backup/agent-{stamp}-{secrets.token_hex(3)}"
    if (
        not _BACKUP_NAME.fullmatch(value)
        or ".." in value
        or "//" in value
        or "/./" in value
        or "@{" in value
        or value.endswith(("/", ".", ".lock"))
        or ".lock/" in value
    ):
        raise ValueError("分支名称必须以 backup/ 开头，且不含 Git 非法引用字符。")
    return value


def _git(cwd: Path, *argv: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return subprocess.run(
        ["git", "-C", str(cwd), *argv],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        shell=False,
        env=env,
        check=False,
    )


def install_development_tools(core: Any, exec_context: Any) -> None:
    """Register narrow actions; keep the gateway's policy and auditing."""
    policy = core.policy
    tools = core.tools
    fileops = core.fileops

    def _ensure_authorized_git_location(path: Path) -> None:
        try:
            _, decision = policy.POLICY.evaluate(str(path), policy.OP_READ)
        except policy.PolicyError as exc:
            raise tools._fail("PATH_NOT_ALLOWED", str(exc)) from exc
        if not decision.allowed or decision.level < policy.LEVEL_WRITE:
            raise tools._fail(
                "PATH_NOT_ALLOWED",
                "Git 仓库及其元数据必须位于已授予至少 2 级权限的路径内。",
            )

    def create_git_backup_branch(args: dict[str, Any]) -> dict[str, Any]:
        cwd_raw = str(args.get("cwd") or "").strip()
        if not cwd_raw:
            raise tools._fail("INVALID_ARGUMENT", "必须指定授权范围内的 Git 工作目录。")
        try:
            name = _branch_name(str(args.get("branch_name") or "").strip())
        except ValueError as exc:
            raise tools._fail("INVALID_BRANCH", str(exc)) from exc
        assessment = core.CommandAssessment(
            True,
            "git-backup-branch",
            "在当前 HEAD 创建新的备份分支，不切换、不覆盖已有分支",
            ("git", "branch", name),
        )
        previous = getattr(exec_context, "assessment", None)
        exec_context.assessment = assessment
        try:
            cwd, info = tools._gate(
                "create_git_backup_branch",
                cwd_raw,
                policy.OP_EXEC,
                preview=f"git branch {name}",
                approval_context=tools._operation_context(branch_name=name),
            )
        finally:
            exec_context.assessment = previous
        if not cwd.is_dir():
            raise tools._fail("NOT_A_DIRECTORY", f"不是文件夹：{cwd}")
        try:
            top = _git(cwd, "rev-parse", "--show-toplevel")
            gitdir = _git(cwd, "rev-parse", "--absolute-git-dir")
            if top.returncode or gitdir.returncode:
                raise tools._fail("NOT_GIT_REPOSITORY", "工作目录不是可用的 Git 仓库。")
            repository = Path(top.stdout.strip()).resolve()
            metadata = Path(gitdir.stdout.strip()).resolve()
            _ensure_authorized_git_location(repository)
            _ensure_authorized_git_location(metadata)
            valid = _git(repository, "check-ref-format", "--branch", name)
            if valid.returncode:
                raise tools._fail("INVALID_BRANCH", "Git 拒绝了该分支名称。")
            head = _git(repository, "rev-parse", "--verify", "HEAD")
            if head.returncode:
                raise tools._fail("NO_HEAD", "仓库尚未有有效的 HEAD 提交。")
            created = _git(repository, "branch", name)
            if created.returncode:
                raise tools._fail(
                    "GIT_BRANCH_FAILED",
                    "创建分支失败，可能已经存在同名分支：" + created.stderr.strip()[:240],
                )
        except subprocess.TimeoutExpired as exc:
            raise tools._fail("GIT_TIMEOUT", "本地 Git 命令执行超时。") from exc
        except OSError as exc:
            raise tools._fail("GIT_UNAVAILABLE", "无法调用本地 Git。") from exc
        payload = {
            "repository": str(repository),
            "branch": name,
            "commit": head.stdout.strip(),
            "checked_out": False,
            "overwrote_existing": False,
        }
        fileops.audit("git_backup_branch_created", {"tool": "create_git_backup_branch", **payload})
        return tools._ok("create_git_backup_branch", payload, info)

    def read_git_status(args: dict[str, Any]) -> dict[str, Any]:
        """Read Git porcelain status with fixed, bounded arguments."""
        cwd_raw = str(args.get("cwd") or "").strip()
        if not cwd_raw:
            raise tools._fail("INVALID_ARGUMENT", "必须指定已授权的 Git 仓库目录。")
        cwd, info = tools._gate("read_git_status", cwd_raw, policy.OP_READ)
        if not cwd.is_dir():
            raise tools._fail("NOT_A_DIRECTORY", f"不是文件夹：{cwd}")
        try:
            top = _git(cwd, "rev-parse", "--show-toplevel")
            gitdir = _git(cwd, "rev-parse", "--absolute-git-dir")
            if top.returncode or gitdir.returncode:
                raise tools._fail("NOT_GIT_REPOSITORY", "无法找到 Git 仓库。")
            repo = Path(top.stdout.strip()).resolve()
            metadata = Path(gitdir.stdout.strip()).resolve()
            for location in (repo, metadata):
                _, decision = policy.POLICY.evaluate(str(location), policy.OP_READ)
                if not decision.allowed:
                    raise tools._fail("PATH_NOT_ALLOWED", "Git 仓库或元数据目录不在授权范围内。")
            result = _git(
                repo, "-c", "core.fsmonitor=false", "status",
                "--porcelain=v1", "--branch", "--untracked-files=normal",
            )
            if result.returncode:
                raise tools._fail("GIT_STATUS_FAILED", result.stderr.strip()[:300])
        except subprocess.TimeoutExpired as exc:
            raise tools._fail("GIT_TIMEOUT", "读取 Git 状态超时。") from exc
        except OSError as exc:
            raise tools._fail("GIT_UNAVAILABLE", "无法调用本地 Git。") from exc
        limit = 20_000
        payload = {
            "repository": str(repo),
            "status": result.stdout[:limit],
            "truncated": len(result.stdout) > limit,
            "read_only": True,
        }
        fileops.audit("git_status_read", {"tool": "read_git_status", "repository": str(repo)})
        return tools._ok("read_git_status", payload, info)

    def create_text_file(args: dict[str, Any]) -> dict[str, Any]:
        """Create only: never overwrite or truncate an existing file."""
        raw_path = str(args.get("path") or "").strip()
        content = args.get("content")
        if not raw_path or not isinstance(content, str):
            raise tools._fail("INVALID_ARGUMENT", "必须传入文件绝对路径和文本内容。")
        data = content.encode("utf-8")
        if len(data) > 64 * 1024:
            raise tools._fail("PAYLOAD_TOO_LARGE", "新建文本文件的内容不得超过 64 KiB。")
        path, info = tools._gate(
            "create_text_file", raw_path, policy.OP_WRITE,
            preview=f"创建文本文件，{len(data)} 字节",
        )
        if not path.parent.is_dir() or path.is_symlink():
            raise tools._fail("INVALID_TARGET", "父目录必须已存在，目标不能是符号链接。")
        if any(part.lower() in {".git", ".ssh", ".venv", "node_modules"} for part in path.parts):
            raise tools._fail("INVALID_TARGET", "此专用工具不允许操作仓库元数据或依赖目录。")
        try:
            with path.open("x", encoding="utf-8", newline="") as handle:
                handle.write(content)
        except FileExistsError as exc:
            raise tools._fail("ALREADY_EXISTS", "文件已存在，拒绝覆盖。") from exc
        except OSError as exc:
            raise tools._fail("FILE_IO_ERROR", str(exc)) from exc
        payload = {"path": str(path), "created": True, "bytes_written": len(data)}
        fileops.audit("text_file_created", {"tool": "create_text_file", **payload})
        return tools._ok("create_text_file", payload, info)

    def replace_exact_text(args: dict[str, Any]) -> dict[str, Any]:
        raw_path = str(args.get("path") or "").strip()
        old = args.get("old_text")
        new = args.get("new_text")
        expected = str(args.get("expected_sha256") or "").strip().lower()
        if not raw_path or not isinstance(old, str) or not isinstance(new, str) or not old:
            raise tools._fail("INVALID_ARGUMENT", "需要 path、非空 old_text 及 new_text。")
        if old == new:
            raise tools._fail("INVALID_ARGUMENT", "替换前后内容相同。")
        if len(old.encode("utf-8")) > _MAX_REPLACEMENT_BYTES or len(new.encode("utf-8")) > _MAX_REPLACEMENT_BYTES:
            raise tools._fail("PAYLOAD_TOO_LARGE", "单次替换片段不得超过 48 KiB。")
        if expected and not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise tools._fail("INVALID_ARGUMENT", "expected_sha256 必须是 SHA-256 十六进制字符串。")

        context = tools._operation_context(
            old_sha256=hashlib.sha256(old.encode("utf-8")).hexdigest(),
            new_sha256=hashlib.sha256(new.encode("utf-8")).hexdigest(),
            expected_sha256=expected,
        )
        path, info = tools._gate(
            "replace_exact_text", raw_path, policy.OP_WRITE,
            preview=f"精确替换 {len(old)} 个字符",
            approval_context=context,
        )
        if not path.is_file() or path.is_symlink():
            raise tools._fail("NOT_A_FILE", "只能精确修改现有的普通文本文件。")
        try:
            data = path.read_bytes()
            if len(data) > _MAX_TEXT_FILE_BYTES:
                raise tools._fail("FILE_TOO_LARGE", "目标超过 1 MiB，请使用其他经授权的编辑方式。")
            original_hash = hashlib.sha256(data).hexdigest()
            if expected and original_hash != expected:
                raise tools._fail("FILE_CHANGED", "文件 SHA-256 不匹配，拒绝覆盖可能存在的新修改。")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise tools._fail("NON_UTF8_FILE", "仅支持 UTF-8 文本文件。") from exc
            matches = text.count(old)
            if matches != 1:
                raise tools._fail("MATCH_NOT_UNIQUE", f"旧文本匹配 {matches} 次，必须恰好一次。")
            updated = text.replace(old, new, 1)
            payload = fileops.write_text(path, updated, "overwrite", newline="")
        except OSError as exc:
            raise tools._fail("FILE_IO_ERROR", str(exc)) from exc
        payload.update({
            "replacements": 1,
            "previous_sha256": original_hash,
            "new_sha256": hashlib.sha256(updated.encode("utf-8")).hexdigest(),
        })
        fileops.audit(
            "exact_text_replaced",
            {"tool": "replace_exact_text", "path": str(path), "bytes_written": payload["bytes_written"]},
        )
        return tools._ok("replace_exact_text", payload, info)

    definitions = [
        {
            "name": "create_git_backup_branch",
            "title": "创建 Git 备份分支",
            "description": (
                "在已授权的本地 Git 仓库中，以当前 HEAD 创建 backup/ 前缀的新分支。"
                "不切换工作分支，也不覆盖已有分支。此操作会修改 Git 仓库元数据。"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": {"type": "string", "description": "授权范围内的 Git 工作目录绝对路径"},
                    "branch_name": {
                        "type": "string",
                        "description": "可选，必须以 backup/ 开头；默认生成唯一备份分支名称",
                    },
                },
                "required": ["cwd"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False, "destructiveHint": False,
                "idempotentHint": False, "openWorldHint": False,
            },
            "outputSchema": {"type": "object", "additionalProperties": True},
        },
        {
            "name": "read_git_status",
            "title": "读取 Git 工作区状态",
            "description": "读取已授权 Git 仓库的状态与分支名称，不修改仓库，不接受任意命令参数。",
            "inputSchema": {
                "type": "object",
                "properties": {"cwd": {"type": "string", "description": "授权目录内的 Git 工作目录绝对路径"}},
                "required": ["cwd"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": True, "destructiveHint": False,
                "idempotentHint": True, "openWorldHint": False,
            },
            "outputSchema": {"type": "object", "additionalProperties": True},
        },
        {
            "name": "create_text_file",
            "title": "只新建文本文件",
            "description": "在已授权且存在的文件夹中新建 UTF-8 文本文件，目标已存在时直接拒绝，不覆盖、删除或执行文件。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "新文件绝对路径"},
                    "content": {"type": "string", "description": "文件的 UTF-8 文本内容，最多 64 KiB"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False, "destructiveHint": False,
                "idempotentHint": False, "openWorldHint": False,
            },
            "outputSchema": {"type": "object", "additionalProperties": True},
        },
        {
            "name": "replace_exact_text",
            "title": "精确替换文件文本",
            "description": (
                "在经过授权的现有 UTF-8 文本文件中，匹配唯一的 old_text 并原子替换为 new_text。"
                "可通过 expected_sha256 检测文件变化；该操作会修改文件内容。"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "要修改的文件绝对路径"},
                    "old_text": {"type": "string", "description": "必须恰好匹配一次的原始文本"},
                    "new_text": {"type": "string", "description": "替换后文本"},
                    "expected_sha256": {
                        "type": "string",
                        "description": "可选：修改前文件的 SHA-256；不一致则拒绝写入",
                    },
                },
                "required": ["path", "old_text", "new_text"],
                "additionalProperties": False,
            },
            "annotations": {
                "readOnlyHint": False, "destructiveHint": True,
                "idempotentHint": False, "openWorldHint": False,
            },
            "outputSchema": {"type": "object", "additionalProperties": True},
        },
    ]
    handlers = {
        "create_git_backup_branch": create_git_backup_branch,
        "replace_exact_text": replace_exact_text,
        "read_git_status": read_git_status,
        "create_text_file": create_text_file,
    }
    for definition in definitions:
        name = definition["name"]
        if name not in tools.TOOL_DEFS_BY_NAME:
            tools.TOOL_DEFS.append(definition)
        tools.TOOL_DEFS_BY_NAME[name] = definition
        tools.HANDLERS[name] = handlers[name]