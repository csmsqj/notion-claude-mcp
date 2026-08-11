# -*- coding: utf-8 -*-
"""MCP 工具层：把客户端工具调用翻译成"先判权限，再执行，最后审计"。

设计要点：
  1. 每个会改变磁盘的工具都必须先 policy.evaluate()，拿到 Decision 才动手。
  2. Decision.needs_approval 为真时进入 approvals 队列并阻塞等待控制台裁决。
  3. 无论放行还是拒绝，都写 audit 日志，控制台"操作记录"直接读它。
"""
from __future__ import annotations

import time
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

import fileops
from approvals import APPROVALS, STATUS_APPROVED, approval_fingerprint
from policy import (
    LEVEL_LABEL,
    LEVEL_NAME_BY_VALUE,
    OP_DELETE,
    OP_EXEC,
    OP_READ,
    OP_WRITE,
    POLICY,
    PolicyError,
    resolve_target,
)

MAX_WRITE_CHARS = 400_000


def _fail(code: str, message: str, details: dict[str, Any] | None = None) -> PolicyError:
    return PolicyError(code, message, details)


OP_LABEL = {OP_READ: "读取", OP_WRITE: "写入", OP_DELETE: "删除", OP_EXEC: "执行命令"}
RISK_LABEL = {"low": "低风险", "medium": "中风险", "high": "高风险", "critical": "极高风险"}


def _approval_hint(item_id: str, reason: str, mode: str, *, popup: str = "") -> str:
    """审批未通过时给模型的指引。按 approval_mode 告诉它下一步该找谁。"""
    if popup == "timeout":
        return (
            f"已在用户电脑上弹出确认窗（审批单 {item_id}），但等待期内没有点击，操作没有执行。"
            f"请提示用户：确认窗可能被其他窗口挡住了，也可以在本机控制台的【受控审批】中批准。"
            f"模型不能代替本机批准。原因：{reason}"
        )
    if mode == "desktop":
        return (
            f"已在用户电脑上弹出确认窗（审批单 {item_id}），但暂时拿不到结果，操作没有执行。"
            f"请让用户在弹窗里点【批准】或【拒绝】，然后你再调用一次同样的工具。原因：{reason}"
        )
    if mode == "console":
        return (
            f"该操作属于受控操作，已生成审批单 {item_id}，当前策略要求只能在本机控制台裁决。"
            f"请告诉用户去控制台【受控审批】点批准，批准后你再调用一次同样的工具即可执行。原因：{reason}"
        )
    return (
        f"该操作属于受控操作，已生成审批单 {item_id}，还没有得到许可。"
        f"请让用户在本机确认窗或控制台【受控审批】中亲自批准；模型不能代替本机批准。"
        f"用户若不同意，可调用 confirm_action(decision=\"deny\") 记录拒绝。原因：{reason}"
    )


def _gate(
    tool: str,
    raw_path: str,
    operation: str,
    *,
    preview: str = "",
    approval_context: str = "",
) -> tuple[Path, dict[str, Any]]:
    """统一权限闸门。返回 (真实可用路径, 判定信息)。被拒绝或未批准时抛 PolicyError。"""
    target, decision = POLICY.evaluate(raw_path, operation)
    info = {
        "path": target.display,
        "level": decision.level,
        "level_name": decision.level_name,
        "level_label": LEVEL_LABEL.get(decision.level, "未授权"),
        "root": decision.root_path,
        "classification": decision.classification,
        "reason": decision.reason,
        "risk": decision.risk,
    }
    if not decision.allowed:
        fileops.audit(
            "denied",
            {"tool": tool, "operation": operation, "path": target.display, "code": decision.code, "reason": decision.reason},
        )
        raise _fail(decision.code or "PERMISSION_DENIED", decision.reason, info)
    if decision.needs_approval:
        mode = str(POLICY.setting("approval_mode"))
        fingerprint = approval_fingerprint(approval_context or preview)
        granted = APPROVALS.consume_grant(tool, operation, str(target.real), fingerprint)
        if granted is not None:
            info["approval_id"] = granted.id
            info["approval"] = "reused_grant"
            fileops.audit(
                "approval_reused",
                {"tool": tool, "operation": operation, "path": target.display, "approval_id": granted.id},
            )
            return target.path, info
        refused = APPROVALS.recent_denial(tool, operation, str(target.real), fingerprint)
        if refused is not None:
            # 刚被拒过就别再生成新单子刷屏，直接把拒绝结果回给模型。
            fileops.audit(
                "approval_recently_denied",
                {"tool": tool, "operation": operation, "path": target.display, "approval_id": refused.id},
            )
            info["approval_id"] = refused.id
            info["approval"] = "denied"
            extra = f"用户当时说：{refused.user_reply}。" if refused.user_reply else ""
            raise _fail(
                "APPROVAL_DENIED",
                f"这个操作用户刚刚已经拒绝过（审批单 {refused.id}）。{extra}"
                f"不要再重复请求；如果确有必要，先向用户说明为什么需要重新考虑，等他主动改口。",
                info,
            )
        item = APPROVALS.create(
            tool=tool,
            operation=operation,
            path=target.display,
            real_path=str(target.real),
            reason=decision.reason,
            risk=decision.risk,
            classification=decision.classification,
            details=decision.details,
            preview=preview,
            fingerprint_source=approval_context or preview,
            ttl_seconds=int(POLICY.setting("approval_ttl_seconds")),
        )
        fileops.audit(
            "approval_requested",
            {
                "tool": tool,
                "operation": operation,
                "path": target.display,
                "approval_id": item.id,
                "reason": decision.reason,
                "risk": decision.risk,
                "mode": mode,
            },
        )
        # desktop：直接在本机弹确认窗；console：仅由本机控制台裁决。
        popup = ""
        if mode == "desktop":
            popup_wait = int(POLICY.setting("approval_popup_seconds"))
            popup = fileops.ask_desktop(
                operation=OP_LABEL.get(operation, operation),
                path=target.display,
                risk=f"{RISK_LABEL.get(decision.risk, decision.risk)} · {decision.classification}",
                reason=decision.reason,
                preview=preview,
                approval_id=item.id,
                timeout_seconds=popup_wait,
            )
            if popup in {"approve", "deny"}:
                APPROVALS.decide(
                    item.id,
                    popup == "approve",
                    by="desktop",
                    user_reply="批准（本机确认窗）" if popup == "approve" else "拒绝（本机确认窗）",
                )
            fileops.audit(
                "popup_" + popup,
                {"tool": tool, "operation": operation, "path": target.display, "approval_id": item.id},
            )
        # 弹窗已经给出结论就不必再等；其余情况按模式决定等多久。
        if popup in {"approve", "deny"}:
            wait_seconds = 0
        else:
            wait_seconds = int(POLICY.setting("approval_wait_seconds"))
        status = APPROVALS.wait(item, wait_seconds)
        info["approval_id"] = item.id
        info["approval"] = status
        info["approval_mode"] = mode
        if popup:
            info["popup"] = popup
        if status != STATUS_APPROVED:
            fileops.audit(
                "approval_" + status,
                {"tool": tool, "operation": operation, "path": target.display, "approval_id": item.id},
            )
            if status == "pending":
                message = _approval_hint(item.id, decision.reason, mode, popup=popup)
            elif status == "expired":
                message = f"审批单 {item.id} 已过期。请重新调用工具，并及时完成确认。"
            else:
                who = {"console": "你在控制台", "desktop": "你在确认窗里"}.get(item.decided_by, "用户")
                extra = f"用户说明：{item.user_reply}。" if item.user_reply else ""
                message = f"该操作已被{who}拒绝（编号 {item.id}）。{extra}不要再重复尝试同一操作。"
            raise _fail("APPROVAL_" + status.upper(), message, info)
        if not APPROVALS.claim(item):
            # 同一张单子已被另一次重试用掉，不能重复放行。
            fileops.audit(
                "approval_already_used",
                {"tool": tool, "operation": operation, "path": target.display, "approval_id": item.id},
            )
            raise _fail(
                "APPROVAL_ALREADY_USED",
                f"审批 {item.id} 的放行凭证已被使用过。若仍需执行，请重新调用工具并让用户再确认一次。",
                info,
            )
        fileops.audit(
            "approval_approved",
            {
                "tool": tool,
                "operation": operation,
                "path": target.display,
                "approval_id": item.id,
                "by": item.decided_by,
            },
        )
    return target.path, info


def _ok(tool: str, payload: dict[str, Any], info: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {"ok": True, "tool": tool}
    result.update(payload)
    if info:
        result["permission"] = info
    return result


def _operation_context(**values: Any) -> str:
    return json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _same_or_under(child: Path, parent: Path) -> bool:
    try:
        child_norm = os.path.normcase(os.path.abspath(str(child)))
        parent_norm = os.path.normcase(os.path.abspath(str(parent)))
        return os.path.commonpath([child_norm, parent_norm]) == parent_norm
    except ValueError:
        return False


def _tree_members(path: Path):
    yield path
    if not path.is_dir() or path.is_symlink():
        return
    for current, dirnames, filenames in os.walk(path, followlinks=False):
        base = Path(current)
        for name in dirnames:
            yield base / name
        for name in filenames:
            yield base / name


def _validate_tree(
    path: Path,
    operation: str,
    *,
    approval_covered: bool,
    reject_symlinks: bool = False,
) -> None:
    for candidate in _tree_members(path):
        if reject_symlinks and candidate.is_symlink():
            raise _fail("SYMLINK_NOT_ALLOWED", f"递归复制不跟随符号链接，请先单独处理：{candidate}")
        _target, decision = POLICY.evaluate(str(candidate), operation)
        if not decision.allowed:
            raise _fail(decision.code or "PERMISSION_DENIED", decision.reason, {"path": str(candidate)})
        if decision.needs_approval and not approval_covered:
            raise _fail(
                "NESTED_APPROVAL_REQUIRED",
                f"递归目标中包含需要单独审批的路径：{candidate}。请缩小操作范围后重试。",
            )


def _validate_destination_tree(src: Path, dest: Path, *, approval_covered: bool) -> None:
    if not src.is_dir() or src.is_symlink():
        return
    for candidate in _tree_members(src):
        relative = candidate.relative_to(src)
        projected = dest if str(relative) == "." else dest / relative
        _target, decision = POLICY.evaluate(str(projected), OP_WRITE)
        if not decision.allowed:
            raise _fail(decision.code or "PERMISSION_DENIED", decision.reason, {"path": str(projected)})
        if decision.needs_approval and not approval_covered:
            raise _fail(
                "NESTED_APPROVAL_REQUIRED",
                f"目标树中包含需要单独审批的路径：{projected}。请缩小操作范围后重试。",
            )


def _approval_covered(info: dict[str, Any]) -> bool:
    return bool(info.get("approval_id") or info.get("approval") in {"approved", "reused_grant"})


def _forbid_authorized_root_mutation(path: Path) -> None:
    if path.is_dir() and any(
        os.path.normcase(os.path.abspath(root.path)) == os.path.normcase(os.path.abspath(str(path)))
        for root in POLICY.roots()
        if root.enabled
    ):
        raise _fail("ROOT_MUTATION_FORBIDDEN", "禁止移动或删除当前授权根本身；请在本机人工处理。")


# ---------------- 只读类工具 ----------------
def t_list_allowed_paths(args: dict[str, Any]) -> dict[str, Any]:
    roots = [root.to_json() for root in POLICY.roots()]
    return _ok(
        "list_allowed_paths",
        {
            "count": len(roots),
            "roots": roots,
            "denies": POLICY.denies(),
            "global_lock": bool(POLICY.setting("global_lock")),
            "system_protection": bool(POLICY.setting("system_protection")),
            "levels": [
                {"level": value, "name": name, "label": LEVEL_LABEL[value]}
                for value, name in LEVEL_NAME_BY_VALUE.items()
            ],
            "summary": (
                "以下是当前允许访问的本地路径及其权限级别；不在列表内的路径一律拒绝。"
                if roots
                else "当前没有任何授权路径，所有文件操作都会被拒绝。请让用户在控制台添加。"
            ),
        },
    )


def t_read_file(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("path", ""))
    path, info = _gate("read_file", raw, OP_READ)
    max_bytes = int(args.get("max_bytes") or POLICY.setting("max_read_bytes"))
    max_bytes = max(1024, min(max_bytes, int(POLICY.setting("max_read_bytes"))))
    payload = fileops.read_text_slice(
        path,
        start_line=int(args.get("start_line") or 1),
        max_bytes=max_bytes,
        max_lines=int(args.get("max_lines") or 2000),
    )
    fileops.audit("read", {"tool": "read_file", "path": str(path), "bytes": payload["size"]})
    return _ok("read_file", payload, info)


def t_list_dir(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("path", ""))
    path, info = _gate("list_dir", raw, OP_READ)
    entries, truncated = fileops.iter_dir(
        path,
        include_hidden=bool(args.get("include_hidden", False)),
        limit=int(args.get("limit") or 500),
        allow_path=_search_path_allowed,
    )
    fileops.audit("list", {"tool": "list_dir", "path": str(path), "count": len(entries)})
    return _ok(
        "list_dir",
        {"path": str(path), "count": len(entries), "truncated": truncated, "entries": entries},
        info,
    )


def _search_roots(scope: str) -> list[Path]:
    """搜索范围：给了 scope 就必须过读权限；没给就在所有已授权根内搜。"""
    if scope:
        path, _info = _gate("search", scope, OP_READ)
        return [path]
    if POLICY.setting("global_lock"):
        raise _fail("GLOBAL_LOCK", "全局开关处于【已锁定】状态，搜索被拒绝。")
    roots: list[Path] = []
    for root in POLICY.roots():
        if not root.enabled:
            continue
        target, decision = POLICY.evaluate(root.path, OP_READ)
        if decision.allowed:
            roots.append(target.path)
    if not roots:
        raise _fail("PATH_NOT_ALLOWED", "当前没有任何授权路径，无法搜索。请让用户在控制台添加访问路径。")
    return roots


def _search_path_allowed(path: Path) -> bool:
    try:
        _target, decision = POLICY.evaluate(str(path), OP_READ)
        return decision.allowed
    except PolicyError:
        return False


def t_search_files(args: dict[str, Any]) -> dict[str, Any]:
    pattern = str(args.get("pattern") or args.get("name") or "")
    roots = _search_roots(str(args.get("scope") or ""))
    limit = int(args.get("max_results") or POLICY.setting("search_max_results"))
    limit = max(1, min(limit, int(POLICY.setting("search_max_results"))))
    payload = fileops.search_names(
        roots,
        pattern,
        include_hidden=bool(args.get("include_hidden", False)),
        max_results=limit,
        timeout_seconds=int(POLICY.setting("search_timeout_seconds")),
        allow_path=_search_path_allowed,
    )
    payload["scope"] = [str(item) for item in roots]
    fileops.audit("search_files", {"pattern": pattern, "count": payload["count"]})
    return _ok("search_files", payload)


def t_search_content(args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or args.get("text") or "")
    roots = _search_roots(str(args.get("scope") or ""))
    limit = int(args.get("max_results") or POLICY.setting("search_max_results"))
    limit = max(1, min(limit, int(POLICY.setting("search_max_results"))))
    payload = fileops.search_content(
        roots,
        query,
        regex=bool(args.get("regex", False)),
        case_sensitive=bool(args.get("case_sensitive", False)),
        include_hidden=bool(args.get("include_hidden", False)),
        max_results=limit,
        timeout_seconds=int(POLICY.setting("search_timeout_seconds")),
        name_filter=str(args.get("name_filter") or ""),
        allow_path=_search_path_allowed,
    )
    payload["scope"] = [str(item) for item in roots]
    fileops.audit("search_content", {"query": query, "count": payload["count"]})
    return _ok("search_content", payload)


def _file_uri(path: str) -> str:
    try:
        return Path(path).resolve().as_uri()
    except ValueError:
        return "file:///" + path.replace("\\", "/").lstrip("/")


def t_compat_search(args: dict[str, Any]) -> dict[str, Any]:
    """OpenAI-compatible knowledge search over all authorized roots."""
    query = str(args.get("query") or "").strip()
    if not query:
        raise _fail("INVALID_ARGUMENT", "query 不能为空。")
    roots = _search_roots("")
    max_results = min(20, int(POLICY.setting("search_max_results")))
    timeout = max(1, int(POLICY.setting("search_timeout_seconds")) // 2)
    content = fileops.search_content(
        roots,
        query,
        regex=False,
        case_sensitive=False,
        include_hidden=False,
        max_results=max_results,
        timeout_seconds=timeout,
        allow_path=_search_path_allowed,
    )
    by_path: dict[str, dict[str, Any]] = {}
    for match in content.get("matches", []):
        path = str(match["path"])
        if path not in by_path:
            by_path[path] = {
                "id": path,
                "title": Path(path).name,
                "url": _file_uri(path),
                "text": str(match.get("text") or "")[:400],
            }

    if len(by_path) < max_results:
        names = fileops.search_names(
            roots,
            query,
            include_hidden=False,
            max_results=max_results - len(by_path),
            timeout_seconds=timeout,
            allow_path=_search_path_allowed,
        )
        for match in names.get("matches", []):
            path = str(match["path"])
            if path not in by_path:
                by_path[path] = {
                    "id": path,
                    "title": Path(path).name,
                    "url": _file_uri(path),
                    "text": path,
                }

    results = list(by_path.values())[:max_results]
    fileops.audit("search", {"query": query, "count": len(results), "compatibility": "openai"})
    return {
        "results": results,
        "query": query,
        "truncated": bool(content.get("truncated")) or len(by_path) > max_results,
    }


def t_compat_fetch(args: dict[str, Any]) -> dict[str, Any]:
    """OpenAI-compatible document fetch; the opaque id is an authorized path."""
    document_id = str(args.get("id") or "").strip()
    if not document_id:
        raise _fail("INVALID_ARGUMENT", "id 不能为空。")
    path, info = _gate("fetch", document_id, OP_READ)
    payload = fileops.read_text_slice(
        path,
        start_line=1,
        max_bytes=int(POLICY.setting("max_read_bytes")),
        max_lines=1_000_000,
    )
    fileops.audit("fetch", {"path": str(path), "bytes": payload["size"], "compatibility": "openai"})
    return {
        "id": str(path),
        "title": path.name,
        "text": payload.get("content", ""),
        "url": _file_uri(str(path)),
        "metadata": {
            "path": str(path),
            "size": payload.get("size"),
            "size_text": payload.get("size_text"),
            "total_lines": payload.get("total_lines"),
            "truncated": payload.get("truncated", False),
            "next_start_line": payload.get("next_start_line"),
            "permission_level": info.get("level"),
        },
    }


# ---------------- 写入类工具 ----------------
def t_write_file(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("path", ""))
    content = args.get("content", "")
    if not isinstance(content, str):
        raise _fail("INVALID_ARGUMENT", "content 必须是字符串。")
    if len(content) > MAX_WRITE_CHARS:
        raise _fail("PAYLOAD_TOO_LARGE", f"单次写入上限 {MAX_WRITE_CHARS} 字符，请分段写入。")
    mode = str(args.get("mode") or "overwrite").lower()
    preview = content[:600]
    context = _operation_context(mode=mode, content_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest())
    path, info = _gate("write_file", raw, OP_WRITE, preview=preview, approval_context=context)
    payload = fileops.write_text(path, content, mode)
    fileops.audit(
        "write",
        {"tool": "write_file", "path": str(path), "mode": mode, "bytes": payload["bytes_written"], "level": info["level"]},
    )
    return _ok("write_file", payload, info)


def t_create_dir(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("path", ""))
    path, info = _gate("create_dir", raw, OP_WRITE)
    payload = fileops.make_dir(path)
    fileops.audit("mkdir", {"tool": "create_dir", "path": str(path)})
    return _ok("create_dir", payload, info)


def t_move_path(args: dict[str, Any]) -> dict[str, Any]:
    src_raw = str(args.get("source") or args.get("path") or "")
    dest_raw = str(args.get("destination") or args.get("to") or "")
    overwrite = bool(args.get("overwrite", False))
    context = _operation_context(source=src_raw, destination=dest_raw, overwrite=overwrite)
    # 移动等于"从源删掉 + 在目标写入"，因此源要 delete 权限、目标要 write 权限
    src, src_info = _gate("move_path", src_raw, OP_DELETE, preview=context, approval_context=context)
    dest_target = resolve_target(dest_raw)
    if _same_or_under(dest_target.path, src) and src.is_dir():
        raise _fail("INVALID_DESTINATION", "不能把目录移动到自身或自身子目录。")
    if os.path.normcase(os.path.abspath(str(src))) == os.path.normcase(os.path.abspath(str(dest_target.path))):
        raise _fail("INVALID_DESTINATION", "源路径与目标路径相同。")
    _forbid_authorized_root_mutation(src)
    _validate_tree(src, OP_DELETE, approval_covered=_approval_covered(src_info))
    dest_delete_info: dict[str, Any] | None = None
    if dest_target.exists and overwrite:
        _dest_delete, dest_delete_info = _gate(
            "move_path",
            dest_raw,
            OP_DELETE,
            preview=context,
            approval_context=context,
        )
        _validate_tree(dest_target.path, OP_DELETE, approval_covered=_approval_covered(dest_delete_info))
    dest, dest_info = _gate("move_path", dest_raw, OP_WRITE, preview=context, approval_context=context)
    _validate_destination_tree(src, dest, approval_covered=_approval_covered(dest_info))
    payload = fileops.move_path(src, dest, overwrite=overwrite)
    fileops.audit("move", {"tool": "move_path", "source": str(src), "destination": str(dest)})
    permission = {"source": src_info, "destination": dest_info}
    if dest_delete_info is not None:
        permission["destination_delete"] = dest_delete_info
    return _ok("move_path", payload, permission)


def t_copy_path(args: dict[str, Any]) -> dict[str, Any]:
    src_raw = str(args.get("source") or args.get("path") or "")
    dest_raw = str(args.get("destination") or args.get("to") or "")
    overwrite = bool(args.get("overwrite", False))
    context = _operation_context(source=src_raw, destination=dest_raw, overwrite=overwrite)
    src, src_info = _gate("copy_path", src_raw, OP_READ, preview=context, approval_context=context)
    dest_target = resolve_target(dest_raw)
    if _same_or_under(dest_target.path, src) and src.is_dir():
        raise _fail("INVALID_DESTINATION", "不能把目录复制到自身或自身子目录。")
    if os.path.normcase(os.path.abspath(str(src))) == os.path.normcase(os.path.abspath(str(dest_target.path))):
        raise _fail("INVALID_DESTINATION", "源路径与目标路径相同。")
    _validate_tree(src, OP_READ, approval_covered=_approval_covered(src_info), reject_symlinks=True)
    dest, dest_info = _gate("copy_path", dest_raw, OP_WRITE, preview=context, approval_context=context)
    _validate_destination_tree(src, dest, approval_covered=_approval_covered(dest_info))
    payload = fileops.copy_path(src, dest, overwrite=overwrite)
    fileops.audit("copy", {"tool": "copy_path", "source": str(src), "destination": str(dest)})
    return _ok("copy_path", payload, {"source": src_info, "destination": dest_info})


# ---------------- 删除与执行 ----------------
def t_delete_path(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("path", ""))
    mode = str(args.get("mode") or POLICY.setting("delete_mode")).lower()
    if mode not in {"trash", "permanent"}:
        mode = str(POLICY.setting("delete_mode"))
    target = resolve_target(raw)
    preview = ""
    if target.exists and target.path.is_dir():
        try:
            names = [item.name for item in list(target.path.iterdir())[:12]]
            preview = "目录内容示例：" + ", ".join(names) if names else "空目录"
        except OSError:
            preview = ""
    context = _operation_context(path=raw, mode=mode)
    path, info = _gate("delete_path", raw, OP_DELETE, preview=preview, approval_context=context)
    _forbid_authorized_root_mutation(path)
    _validate_tree(path, OP_DELETE, approval_covered=_approval_covered(info))
    payload = fileops.delete_path(
        path,
        mode=mode,
        trash_copy_max_bytes=int(POLICY.setting("trash_copy_max_bytes")),
    )
    fileops.audit(
        "delete",
        {
            "tool": "delete_path",
            "path": str(path),
            "method": payload["method"],
            "size": payload["size"],
            "trashed_to": payload["trashed_to"],
            "classification": info["classification"],
        },
    )
    payload["note"] = (
        f"已移入网关回收站：{payload['trashed_to']}（保留 {POLICY.setting('trash_retention_days')} 天）"
        if payload["method"] == "trash"
        else "已永久删除，无法恢复。"
    )
    return _ok("delete_path", payload, info)


def t_run_command(args: dict[str, Any]) -> dict[str, Any]:
    command = str(args.get("command") or args.get("cmd") or "").strip()
    if not command:
        raise _fail("INVALID_ARGUMENT", "command 不能为空。")
    cwd_raw = str(args.get("cwd") or args.get("workdir") or "")
    if not cwd_raw:
        raise _fail("INVALID_ARGUMENT", "必须显式给出 cwd（工作目录绝对路径），它决定了权限判定范围。")
    cwd, info = _gate(
        "run_command",
        cwd_raw,
        OP_EXEC,
        preview=command[:600],
        approval_context=_operation_context(command=command),
    )
    if not cwd.is_dir():
        raise _fail("NOT_A_DIRECTORY", f"cwd 不是目录：{cwd}")
    payload = fileops.run_command(command, cwd, int(POLICY.setting("exec_timeout_seconds")))
    fileops.audit(
        "exec",
        {"tool": "run_command", "command": command, "cwd": str(cwd), "exit_code": payload["exit_code"]},
    )
    return _ok("run_command", payload, info)


def t_get_permission(args: dict[str, Any]) -> dict[str, Any]:
    """给模型的自查接口：先问"我对这个路径能做什么"，再决定调用哪个工具。"""
    raw = str(args.get("path", ""))
    result: dict[str, Any] = {"path": raw, "operations": {}}
    for operation in (OP_READ, OP_WRITE, OP_DELETE, OP_EXEC):
        target, decision = POLICY.evaluate(raw, operation)
        result["path"] = target.display
        result["operations"][operation] = {
            "allowed": decision.allowed,
            "needs_approval": decision.needs_approval,
            "code": decision.code,
            "reason": decision.reason,
            "classification": decision.classification,
        }
        result["level"] = decision.level
        result["level_label"] = LEVEL_LABEL.get(decision.level, "未授权")
        result["root"] = decision.root_path
    return _ok("get_permission", result)


def t_list_pending_approvals(args: dict[str, Any]) -> dict[str, Any]:
    """让模型能在对话里查"我还有哪些操作卡着等确认"。"""
    items = [item for item in APPROVALS.list_json(limit=50) if item["status"] == "pending"]
    brief = [
        {
            "approval_id": item["id"],
            "tool": item["tool"],
            "operation": item["operation"],
            "path": item["path"],
            "risk": item["risk"],
            "reason": item["reason"],
            "preview": item["preview"][:200],
            "seconds_left": item["seconds_left"],
        }
        for item in items
    ]
    return _ok(
        "list_pending_approvals",
        {
            "count": len(brief),
            "approval_mode": str(POLICY.setting("approval_mode")),
            "pending": brief,
            "summary": (
                f"有 {len(brief)} 个受控操作等待确认。"
                if brief
                else "当前没有等待确认的受控操作。"
            ),
        },
    )


def t_confirm_action(args: dict[str, Any]) -> dict[str, Any]:
    """记录用户在 Notion 对话里给出的同意 / 拒绝。

    默认的确认方式是本机弹窗；这个工具是弹窗被忽略 / 被挡住时的兜底通道。
    这里只负责"登记"，不直接执行；登记通过后模型要再调用一次原工具。
    approval_mode=console 时本工具一律拒绝，确保只有本机控制台能放行。
    """
    approval_id = str(args.get("approval_id") or "").strip()
    decision_text = str(args.get("decision") or "").strip().lower()
    user_reply = str(args.get("user_message") or "").strip()
    if not approval_id:
        raise _fail("INVALID_ARGUMENT", "approval_id 不能为空；它来自上一次工具调用返回的审批单编号。")
    if decision_text not in {"approve", "deny"}:
        raise _fail("INVALID_ARGUMENT", "decision 只能是 approve 或 deny。")
    if decision_text == "approve":
        fileops.audit("confirm_rejected_by_mode", {"approval_id": approval_id, "mode": "local-only"})
        raise _fail(
            "CONFIRM_REQUIRES_LOCAL",
            "为防止客户端或模型伪造用户同意，批准只能由用户在本机确认窗或控制台完成。"
            "请让用户打开 http://127.0.0.1:8876 的【受控审批】并亲自点击【批准】。",
        )
    item = APPROVALS.get(approval_id)
    if item is None:
        raise _fail("NOT_FOUND", f"找不到审批单 {approval_id}。请重新调用原工具生成一张新的。")
    if item.status == STATUS_APPROVED:
        return _ok(
            "confirm_action",
            {
                "approval_id": item.id,
                "status": item.status,
                "already": True,
                "summary": f"审批单 {item.id} 之前已经获准，现在可以直接调用 {item.tool} 执行。",
            },
        )
    if item.status != "pending":
        raise _fail(
            "APPROVAL_" + item.status.upper(),
            f"审批单 {item.id} 当前状态是 {item.status}，无法再次确认。请重新调用原工具。",
        )
    if not user_reply:
        raise _fail(
            "INVALID_ARGUMENT",
            "必须在 user_message 里原样带上用户表示同意/拒绝的那句话，用于留痕。不要自己编造用户的回答。",
        )
    approve = False
    updated = APPROVALS.decide(item.id, False, by="client", user_reply=user_reply)
    fileops.audit(
        "confirm_" + ("approved" if approve else "denied"),
        {
            "approval_id": updated.id,
            "tool": updated.tool,
            "operation": updated.operation,
            "path": updated.path,
            "by": "client",
            "user_message": user_reply[:200],
        },
    )
    if approve:
        summary = (
            f"已记录用户同意（审批单 {updated.id}）。现在请立刻再调用一次 {updated.tool}，参数保持不变，即可执行。"
            "该许可只能用一次。"
        )
    else:
        summary = f"已记录用户拒绝（审批单 {updated.id}）。请不要再尝试这个操作，并向用户确认下一步怎么做。"
    return _ok(
        "confirm_action",
        {
            "approval_id": updated.id,
            "status": updated.status,
            "tool": updated.tool,
            "operation": updated.operation,
            "path": updated.path,
            "next_step": f"重新调用 {updated.tool}" if approve else "停止该操作",
            "summary": summary,
        },
    )


def t_pick_path(args: dict[str, Any]) -> dict[str, Any]:
    """在用户本机弹出 Windows 原生"选择文件夹 / 打开文件"对话框，可选直接授权。"""
    mode = str(args.get("mode") or "folder").lower()
    initial = str(args.get("initial") or "")
    # 走隧道的请求超过 ~100 秒会被 Cloudflare 边缘掐断（524），所以这里比控制台侧更短。
    result = fileops.pick_path(mode=mode, initial=initial, timeout_seconds=85)
    if not result["ok"]:
        fileops.audit("pick_cancelled", {"mode": mode})
        return _ok(
            "pick_path",
            {
                "cancelled": True,
                "path": "",
                "summary": "用户在本机取消了选择，没有选中任何路径。请询问用户下一步怎么做，不要自己猜路径。",
            },
        )
    picked = result["path"]
    payload: dict[str, Any] = {"cancelled": False, "path": picked, "mode": result["mode"]}
    fileops.audit("pick_selected", {"mode": mode, "path": picked})
    target, decision = POLICY.evaluate(picked, OP_READ)
    payload["already_authorized"] = decision.allowed
    payload["level"] = decision.level
    payload["level_label"] = LEVEL_LABEL.get(decision.level, "未授权")
    payload["summary"] = (
        f"用户选择了 {picked}（当前权限：{payload['level_label']}）。"
        if decision.allowed
        else f"用户选择了 {picked}，但它尚未授权。为防止客户端自行提权，请让用户在本机控制台【访问路径】中添加并选择权限级别。"
    )
    return _ok("pick_path", payload)


HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "list_allowed_paths": t_list_allowed_paths,
    "get_permission": t_get_permission,
    "pick_path": t_pick_path,
    "list_pending_approvals": t_list_pending_approvals,
    "confirm_action": t_confirm_action,
    "read_file": t_read_file,
    "list_dir": t_list_dir,
    "search_files": t_search_files,
    "search_content": t_search_content,
    "search": t_compat_search,
    "fetch": t_compat_fetch,
    "write_file": t_write_file,
    "create_dir": t_create_dir,
    "move_path": t_move_path,
    "copy_path": t_copy_path,
    "delete_path": t_delete_path,
    "run_command": t_run_command,
}

_STR = {"type": "string"}
_INT = {"type": "integer"}
_BOOL = {"type": "boolean"}

TOOL_DEFS: list[dict[str, Any]] = [
    {
        "name": "list_allowed_paths",
        "title": "查看已授权路径",
        "description": (
            "列出本机当前允许你访问的所有路径及权限级别（1 只读 / 2 读写 / 3 可删小文件 / 4 完全控制）。"
            "任何文件操作前建议先调用一次，避免访问未授权路径。"
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "get_permission",
        "title": "查询路径权限",
        "description": "查询指定绝对路径上读 / 写 / 删除 / 执行分别是允许、需要人工批准还是被拒绝。",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {**_STR, "description": "绝对路径，例如 D:\\notion\\workspace"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "read_file",
        "title": "读取文件",
        "description": "读取授权范围内的 UTF-8 文本文件，可按起始行分页。二进制文件会被拒绝。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {**_STR, "description": "文件绝对路径"},
                "start_line": {**_INT, "minimum": 1, "description": "起始行号，默认 1"},
                "max_lines": {**_INT, "minimum": 1, "description": "最多返回行数，默认 2000"},
                "max_bytes": {**_INT, "minimum": 1024, "description": "最多返回字节数"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "list_dir",
        "title": "列出目录",
        "description": "列出授权范围内某个目录的子目录与文件（含大小、修改时间）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {**_STR, "description": "目录绝对路径"},
                "include_hidden": {**_BOOL, "description": "是否包含以点开头的隐藏项，默认 false"},
                "limit": {**_INT, "minimum": 1, "description": "最多返回条目数，默认 500"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "search_files",
        "title": "按文件名搜索",
        "description": "在授权路径内按文件名搜索，支持子串或通配符（*、?）。不传 scope 时搜索全部授权路径。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {**_STR, "description": "文件名关键字或通配符，例如 *.md"},
                "scope": {**_STR, "description": "限定搜索目录的绝对路径，可省略"},
                "include_hidden": _BOOL,
                "max_results": {**_INT, "minimum": 1},
            },
            "required": ["pattern"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "search_content",
        "title": "按内容搜索",
        "description": "在授权路径内的文本文件里搜索关键字或正则，返回文件路径、行号与该行内容。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {**_STR, "description": "要搜索的文本或正则"},
                "scope": {**_STR, "description": "限定搜索目录的绝对路径，可省略"},
                "regex": {**_BOOL, "description": "是否把 query 当正则，默认 false"},
                "case_sensitive": _BOOL,
                "include_hidden": _BOOL,
                "name_filter": {**_STR, "description": "只搜索匹配该通配符的文件名，例如 *.py"},
                "max_results": {**_INT, "minimum": 1},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
]

TOOL_DEFS += [
    {
        "name": "write_file",
        "title": "写入文件",
        "description": (
            "在权限 2 级及以上的路径写入 UTF-8 文本。mode=overwrite 覆盖、create 仅新建、append 追加。"
            "覆盖大文件或系统类文件时会转为受控审批，需要用户在本地控制台批准。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {**_STR, "description": "文件绝对路径"},
                "content": {**_STR, "description": "要写入的完整文本"},
                "mode": {"type": "string", "enum": ["overwrite", "create", "append"], "description": "默认 overwrite"},
            },
            "required": ["path", "content"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
    },
    {
        "name": "create_dir",
        "title": "新建目录",
        "description": "在权限 2 级及以上的路径下创建目录（等价 mkdir -p）。",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {**_STR, "description": "目录绝对路径"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
]

TOOL_DEFS += [
    {
        "name": "search",
        "title": "搜索本地知识",
        "description": "在所有已授权路径中搜索文本内容和文件名，使用 OpenAI 兼容的 search 结果格式。",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {**_STR, "description": "自然语言或关键字查询"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": _STR,
                            "title": _STR,
                            "url": _STR,
                            "text": _STR,
                        },
                        "required": ["id", "title", "url"],
                        "additionalProperties": True,
                    },
                }
            },
            "required": ["results"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "fetch",
        "title": "获取本地文档",
        "description": "按 search 返回的 id 读取完整文档，使用 OpenAI 兼容的 fetch 结果格式。",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {**_STR, "description": "search 结果中的文档 id"}},
            "required": ["id"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "id": _STR,
                "title": _STR,
                "text": _STR,
                "url": _STR,
                "metadata": {"type": "object", "additionalProperties": True},
            },
            "required": ["id", "title", "text", "url", "metadata"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
    },
]

TOOL_DEFS += [
    {
        "name": "move_path",
        "title": "移动 / 重命名",
        "description": "移动或重命名文件、目录。源需要 3 级（删除）权限，目标需要 2 级（写入）权限。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {**_STR, "description": "源绝对路径"},
                "destination": {**_STR, "description": "目标绝对路径"},
                "overwrite": {**_BOOL, "description": "目标已存在时是否覆盖，默认 false"},
            },
            "required": ["source", "destination"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
    {
        "name": "copy_path",
        "title": "复制",
        "description": "复制文件或目录。源需要读权限，目标需要写权限。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {**_STR, "description": "源绝对路径"},
                "destination": {**_STR, "description": "目标绝对路径"},
                "overwrite": _BOOL,
            },
            "required": ["source", "destination"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
]

TOOL_DEFS += [
    {
        "name": "delete_path",
        "title": "删除",
        "description": (
            "删除文件或目录。3 级路径只允许直接删除普通小文件与临时文件；"
            "大文件、非空大目录、系统或凭据类路径需要 4 级并由用户在控制台批准。"
            "默认先移入网关回收站，可恢复。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {**_STR, "description": "要删除的绝对路径"},
                "mode": {"type": "string", "enum": ["trash", "permanent"], "description": "默认跟随控制台设置"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
    {
        "name": "run_command",
        "title": "执行命令（受控）",
        "description": (
            "在 4 级授权目录内执行一条 shell 命令。每次调用都必须由用户在本地控制台批准，"
            "并受超时限制。仅在确有必要时使用。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {**_STR, "description": "要执行的命令行"},
                "cwd": {**_STR, "description": "工作目录绝对路径，必须在 4 级授权范围内"},
            },
            "required": ["command", "cwd"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
    },
]

TOOL_DEFS += [
    {
        "name": "pick_path",
        "title": "让用户在本机选择路径",
        "description": (
            "在用户电脑上弹出 Windows 原生的【选择文件夹】或【打开文件】对话框，由用户亲手点选路径并返回给你。"
            "当用户说\"我想让你看某个目录/文件\"但没给出准确路径、或给的路径不存在、或需要新授权时，用这个工具，"
            "不要自己猜路径。此工具只返回用户选中的路径，不会授予权限；新授权必须由用户在本机控制台选择级别。"
            "用户可能点取消，这时不要重试骚扰。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["folder", "file"],
                    "description": "folder 选文件夹（默认），file 选单个文件",
                },
                "initial": {**_STR, "description": "对话框初始定位的目录绝对路径，可省略"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "openWorldHint": True},
    },
    {
        "name": "list_pending_approvals",
        "title": "查看待确认的受控操作",
        "description": "列出当前卡在等待确认的受控操作及其审批单编号，用于向用户复述还有哪些操作在等他拍板。",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "confirm_action",
        "title": "登记用户拒绝受控操作",
        "description": (
            "受控操作默认会在用户电脑上直接弹确认窗，用户点一下即可，通常不需要这个工具。"
            "客户端只能用此工具登记拒绝。批准必须由用户在本机确认窗或控制台亲自完成，"
            "避免客户端或模型伪造用户同意。user_message 应保留用户拒绝的原话。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {**_STR, "description": "上一次工具调用返回的审批单编号"},
                "decision": {
                    "type": "string",
                    "enum": ["deny"],
                    "description": "只能登记拒绝；批准必须在本机完成",
                },
                "user_message": {**_STR, "description": "用户表示同意或拒绝的原话，用于审计留痕"},
            },
            "required": ["approval_id", "decision", "user_message"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False},
    },
]

TOOL_DEFS_BY_NAME = {item["name"]: item for item in TOOL_DEFS}


def _validate_schema(value: Any, schema: dict[str, Any], path: str = "arguments") -> None:
    expected = schema.get("type")
    if expected == "object":
        if not isinstance(value, dict):
            raise _fail("INVALID_ARGUMENT", f"{path} 必须是对象。")
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise _fail("INVALID_ARGUMENT", f"{path}.{key} 是必填参数。")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise _fail("INVALID_ARGUMENT", f"{path} 包含未知参数：{', '.join(unknown)}。")
        for key, item in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _validate_schema(item, child_schema, f"{path}.{key}")
    elif expected == "string":
        if not isinstance(value, str):
            raise _fail("INVALID_ARGUMENT", f"{path} 必须是字符串。")
    elif expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise _fail("INVALID_ARGUMENT", f"{path} 必须是整数。")
    elif expected == "boolean":
        if type(value) is not bool:
            raise _fail("INVALID_ARGUMENT", f"{path} 必须是布尔值。")
    elif expected == "array":
        if not isinstance(value, list):
            raise _fail("INVALID_ARGUMENT", f"{path} 必须是数组。")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_schema(item, item_schema, f"{path}[{index}]")
    if "enum" in schema and value not in schema["enum"]:
        raise _fail("INVALID_ARGUMENT", f"{path} 必须是以下值之一：{schema['enum']}。")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < int(schema["minimum"]):
            raise _fail("INVALID_ARGUMENT", f"{path} 不能小于 {schema['minimum']}。")
        if "maximum" in schema and value > int(schema["maximum"]):
            raise _fail("INVALID_ARGUMENT", f"{path} 不能大于 {schema['maximum']}。")


def render_text(tool: str, payload: dict[str, Any]) -> str:
    """给模型看的纯文本摘要。结构化数据仍在 structuredContent 里。"""
    renderer = _RENDERERS.get(tool)
    if renderer is not None:
        return renderer(payload)
    return payload.get("summary") or f"{tool} 执行完成。"


def _r_read_file(payload: dict[str, Any]) -> str:
    head = f"[{payload['path']} 第 {payload['start_line']}-{payload['end_line']} 行 / 共 {payload['total_lines']} 行"
    if payload.get("truncated"):
        head += f"，内容被截断，可用 start_line={payload['next_start_line']} 继续读取"
    return head + "]\n" + payload.get("content", "")


def _r_list_dir(payload: dict[str, Any]) -> str:
    lines = [f"{payload['path']}（{payload['count']} 项）"]
    for item in payload.get("entries", [])[:200]:
        kind = "DIR " if item.get("is_dir") else "FILE"
        lines.append(f"{kind} {item['name']}  {item.get('size_text', '')}  {item.get('mtime', '')}")
    if payload.get("truncated"):
        lines.append("... 条目过多已截断，请提高 limit 或进入子目录。")
    return "\n".join(lines)


def _r_search(payload: dict[str, Any]) -> str:
    suffix = "（已截断）" if payload.get("truncated") else ""
    lines = [f"命中 {payload['count']} 条{suffix}"]
    for item in payload.get("matches", [])[:200]:
        if "line" in item:
            lines.append(f"{item['path']}:{item['line']}: {item['text']}")
        else:
            lines.append(f"{item['path']}  {item.get('size_text', '')}")
    if payload.get("timed_out"):
        lines.append("搜索已达时间上限，结果可能不完整。")
    return "\n".join(lines)


def _r_compat_search(payload: dict[str, Any]) -> str:
    lines = [f"命中 {len(payload.get('results', []))} 个文档"]
    for item in payload.get("results", []):
        lines.append(f"{item.get('title', '')}  {item.get('id', '')}")
    return "\n".join(lines)


def _r_compat_fetch(payload: dict[str, Any]) -> str:
    return f"[{payload.get('title', '')}]\n{payload.get('text', '')}"


def _r_allowed(payload: dict[str, Any]) -> str:
    lines = [payload.get("summary", "")]
    for item in payload.get("roots", []):
        state = "启用" if item["enabled"] else "已停用"
        lines.append(f"[{item['level']}级 {item['level_label']}] {item['path']}  ({state})")
    if payload.get("denies"):
        lines.append("黑名单：" + "; ".join(payload["denies"]))
    if payload.get("global_lock"):
        lines.append("注意：全局开关处于【已锁定】，当前所有操作都会被拒绝。")
    return "\n".join(line for line in lines if line)


def _r_permission(payload: dict[str, Any]) -> str:
    lines = [
        f"{payload['path']}  权限级别：{payload.get('level_label', '未授权')}  授权根：{payload.get('root') or '无'}"
    ]
    for name, item in payload.get("operations", {}).items():
        if item["allowed"] and item["needs_approval"]:
            state = "需人工批准"
        elif item["allowed"]:
            state = "允许"
        else:
            state = "拒绝"
        lines.append(f"- {name}: {state}（{item['reason']}）")
    return "\n".join(lines)


def _r_write(payload: dict[str, Any]) -> str:
    return (
        f"已写入 {payload['path']}（{payload['mode']}，{payload['bytes_written']} 字节，"
        f"现大小 {payload['size_text']}）"
    )


def _r_mkdir(payload: dict[str, Any]) -> str:
    return f"目录已就绪：{payload['path']}"


def _r_move(payload: dict[str, Any]) -> str:
    return f"已移动：{payload['source']} -> {payload['destination']}"


def _r_copy(payload: dict[str, Any]) -> str:
    return f"已复制：{payload['source']} -> {payload['destination']}"


def _r_delete(payload: dict[str, Any]) -> str:
    return f"已删除 {payload['path']}（{payload['size_text']}）。{payload.get('note', '')}"


def _r_exec(payload: dict[str, Any]) -> str:
    parts = [f"退出码 {payload['exit_code']}，耗时 {payload['duration_ms']}ms"]
    if payload.get("stdout"):
        parts.append("--- stdout ---\n" + payload["stdout"])
    if payload.get("stderr"):
        parts.append("--- stderr ---\n" + payload["stderr"])
    if payload.get("timed_out"):
        parts.append("命令超时已被终止。")
    return "\n".join(parts)


def _r_pick(payload: dict[str, Any]) -> str:
    if payload.get("cancelled"):
        return payload.get("summary", "用户取消了选择。")
    lines = [f"用户选择：{payload['path']}"]
    if payload.get("root_id"):
        lines.append(f"已授权为第 {payload['level']} 级（{payload['level_label']}）")
    elif payload.get("already_authorized"):
        lines.append(f"当前权限：{payload['level_label']}")
    else:
        lines.append("该路径尚未授权。")
    lines.append(payload.get("summary", ""))
    return "\n".join(line for line in lines if line)


def _r_pending(payload: dict[str, Any]) -> str:
    lines = [payload.get("summary", ""), f"审批方式：{payload.get('approval_mode')}"]
    for item in payload.get("pending", []):
        lines.append(
            f"[{item['approval_id']}] {item['operation']} {item['path']}"
            f"（{item['risk']}，剩余 {item['seconds_left']}s）：{item['reason']}"
        )
    return "\n".join(line for line in lines if line)


def _r_confirm(payload: dict[str, Any]) -> str:
    return payload.get("summary", "已登记。")


_RENDERERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "read_file": _r_read_file,
    "list_dir": _r_list_dir,
    "search_files": _r_search,
    "search_content": _r_search,
    "search": _r_compat_search,
    "fetch": _r_compat_fetch,
    "list_allowed_paths": _r_allowed,
    "get_permission": _r_permission,
    "pick_path": _r_pick,
    "list_pending_approvals": _r_pending,
    "confirm_action": _r_confirm,
    "write_file": _r_write,
    "create_dir": _r_mkdir,
    "move_path": _r_move,
    "copy_path": _r_copy,
    "delete_path": _r_delete,
    "run_command": _r_exec,
}


def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    handler = HANDLERS.get(tool)
    if handler is None:
        raise _fail("UNKNOWN_TOOL", f"未知工具：{tool}")
    _validate_schema(args, TOOL_DEFS_BY_NAME[tool]["inputSchema"])
    started = time.time()
    payload = handler(args or {})
    payload["duration_ms"] = int((time.time() - started) * 1000)
    return payload
