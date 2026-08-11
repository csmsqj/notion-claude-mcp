# -*- coding: utf-8 -*-
"""实际文件操作 + 回收站 + 审计日志。

所有函数都假定调用方已经过 policy.evaluate() 放行；这里只负责"怎么做"，
不负责"能不能做"，避免权限判定散落到多处。
"""
from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from policy import (
    LOG_DIR,
    SKIP_WALK_DIR_NAMES,
    TRASH_DIR,
    PolicyError,
    _norm,
)

AUDIT_FILE = LOG_DIR / "audit.jsonl"
AUDIT_MAX_BYTES = 8 * 1024 * 1024
_audit_lock = threading.Lock()

TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".py", ".java", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".scss",
    ".xml", ".sql", ".sh", ".bat", ".cmd", ".ps1", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".cs",
    ".rb", ".php", ".kt", ".kts", ".gradle", ".properties", ".env", ".log", ".csv", ".tsv", ".vue",
}


def audit(action: str, payload: dict[str, Any]) -> None:
    """审计日志：一行一条 JSON，超过上限自动轮转一次。"""
    record = {"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "epoch": round(time.time(), 3), "action": action}
    record.update(payload)
    line = json.dumps(record, ensure_ascii=False)
    with _audit_lock:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            if AUDIT_FILE.exists() and AUDIT_FILE.stat().st_size > AUDIT_MAX_BYTES:
                AUDIT_FILE.replace(AUDIT_FILE.with_suffix(".jsonl.1"))
            with AUDIT_FILE.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass


def tail_audit(limit: int = 200) -> list[dict[str, Any]]:
    if not AUDIT_FILE.exists():
        return []
    try:
        with AUDIT_FILE.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            block = min(size, 512 * 1024)
            handle.seek(size - block)
            data = handle.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    items: list[dict[str, Any]] = []
    for line in data.splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    items.reverse()
    return items


def human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def entry_json(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"name": path.name, "path": str(path)}
    try:
        st = path.stat()
        is_dir = path.is_dir()
        info.update(
            {
                "is_dir": is_dir,
                "size": 0 if is_dir else st.st_size,
                "size_text": "-" if is_dir else human_bytes(st.st_size),
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                "hidden": bool(path.name.startswith(".")),
            }
        )
    except OSError as exc:
        info.update({"is_dir": False, "size": 0, "size_text": "-", "mtime": "", "error": str(exc)})
    return info


def read_text_slice(path: Path, *, start_line: int, max_bytes: int, max_lines: int) -> dict[str, Any]:
    """按行读取文本切片；二进制文件直接拒绝，避免把乱码塞进模型上下文。"""
    if not path.exists():
        raise PolicyError("NOT_FOUND", f"文件不存在：{path}")
    if path.is_dir():
        raise PolicyError("IS_A_DIRECTORY", f"目标是目录，请用 list_dir：{path}")
    size = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(8192)
    if b"\x00" in head:
        raise PolicyError("BINARY_FILE", f"这是二进制文件（{human_bytes(size)}），不支持文本读取。")
    start_line = max(1, int(start_line))
    max_bytes = max(1, int(max_bytes))
    max_lines = max(1, int(max_lines))
    lines: list[str] = []
    total_lines = 0
    used_bytes = 0
    truncated = False
    accepting = True
    end_line = start_line - 1
    next_start_line: int | None = None
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for index, line in enumerate(handle, start=1):
            total_lines = index
            if index < start_line:
                continue
            if not accepting:
                continue
            if len(lines) >= max_lines:
                truncated = True
                next_start_line = index
                accepting = False
                continue
            text = line.rstrip("\n").rstrip("\r")
            prefix = "\n" if lines else ""
            encoded = (prefix + text).encode("utf-8", errors="replace")
            remaining = max_bytes - used_bytes
            if len(encoded) > remaining:
                fragment = encoded[:max(0, remaining)].decode("utf-8", errors="ignore")
                if prefix and fragment.startswith("\n"):
                    fragment = fragment[1:]
                if fragment:
                    lines.append(fragment)
                    used_bytes += len((prefix + fragment).encode("utf-8"))
                    end_line = index
                truncated = True
                next_start_line = index + 1
                accepting = False
                continue
            lines.append(text)
            used_bytes += len(encoded)
            end_line = index
    return {
        "path": str(path),
        "size": size,
        "size_text": human_bytes(size),
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "truncated": truncated,
        "next_start_line": next_start_line if truncated else None,
        "content": "\n".join(lines),
    }


def write_text(path: Path, content: str, mode: str, *, newline: str = "") -> dict[str, Any]:
    """mode: overwrite / create / append。写入用临时文件 + os.replace 保证原子性。"""
    if mode not in {"overwrite", "create", "append"}:
        raise PolicyError("INVALID_ARGUMENT", "mode 只能是 overwrite / create / append。")
    if mode == "create" and path.exists():
        raise PolicyError("ALREADY_EXISTS", f"目标已存在，create 模式拒绝覆盖：{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "append":
        with path.open("a", encoding="utf-8", newline=newline) as handle:
            handle.write(content)
        final_size = path.stat().st_size
    else:
        tmp = path.with_name(path.name + f".gwtmp{os.getpid()}")
        try:
            with tmp.open("w", encoding="utf-8", newline=newline) as handle:
                handle.write(content)
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        final_size = path.stat().st_size
    return {
        "path": str(path),
        "mode": mode,
        "bytes_written": len(content.encode("utf-8")),
        "size": final_size,
        "size_text": human_bytes(final_size),
    }


def move_path(src: Path, dest: Path, *, overwrite: bool) -> dict[str, Any]:
    if not src.exists():
        raise PolicyError("NOT_FOUND", f"源路径不存在：{src}")
    if dest.exists():
        if not overwrite:
            raise PolicyError("ALREADY_EXISTS", f"目标已存在：{dest}")
        if dest.is_dir():
            shutil.rmtree(dest)
        else:
            dest.unlink()
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return {"source": str(src), "destination": str(dest)}


def copy_path(src: Path, dest: Path, *, overwrite: bool) -> dict[str, Any]:
    if not src.exists():
        raise PolicyError("NOT_FOUND", f"源路径不存在：{src}")
    if dest.exists() and not overwrite:
        raise PolicyError("ALREADY_EXISTS", f"目标已存在：{dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dest.exists() and not dest.is_dir():
            raise PolicyError("TYPE_CONFLICT", f"源是目录，但目标是文件：{dest}")
        shutil.copytree(str(src), str(dest), dirs_exist_ok=overwrite)
    else:
        if dest.exists() and dest.is_dir():
            raise PolicyError("TYPE_CONFLICT", f"源是文件，但目标是目录：{dest}")
        shutil.copy2(str(src), str(dest))
    return {"source": str(src), "destination": str(dest)}


def make_dir(path: Path) -> dict[str, Any]:
    path.mkdir(parents=True, exist_ok=True)
    return {"path": str(path), "created": True}


def _unique_trash_dir() -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = TRASH_DIR / f"{stamp}-{os.urandom(3).hex()}"
    base.mkdir(parents=True, exist_ok=True)
    return base


def delete_path(path: Path, *, mode: str, trash_copy_max_bytes: int) -> dict[str, Any]:
    """mode=trash 必须成功移入网关回收站；失败时保持原目标不变并拒绝降级删除。"""
    if not path.exists() and not path.is_symlink():
        raise PolicyError("NOT_FOUND", f"目标不存在：{path}")
    is_dir = path.is_dir() and not path.is_symlink()
    try:
        if is_dir:
            size = 0
            for current, _dirs, files in os.walk(path, onerror=lambda _e: None):
                for name in files:
                    try:
                        size += (Path(current) / name).stat().st_size
                    except OSError:
                        continue
                    if trash_copy_max_bytes > 0 and size > trash_copy_max_bytes:
                        break
                if trash_copy_max_bytes > 0 and size > trash_copy_max_bytes:
                    break
        else:
            size = path.stat().st_size
    except OSError as exc:
        raise PolicyError("ACCESS_DENIED", f"无法读取待删除目标：{path}") from exc
    trashed_to = ""
    method = "permanent"
    if mode == "trash":
        oversize = trash_copy_max_bytes > 0 and size > trash_copy_max_bytes
        if oversize:
            raise PolicyError(
                "TRASH_TOO_LARGE",
                f"目标大小 {human_bytes(size)} 超过回收站单次上限 {human_bytes(trash_copy_max_bytes)}；未删除。若确需永久删除，请显式使用 mode=permanent 并完成高风险审批。",
            )
        holder = _unique_trash_dir()
        target = holder / path.name
        try:
            shutil.move(str(path), str(target))
            trashed_to = str(target)
            method = "trash"
        except (OSError, shutil.Error) as exc:
            shutil.rmtree(holder, ignore_errors=True)
            raise PolicyError("TRASH_FAILED", f"无法把目标移入网关回收站，未执行永久删除：{path}") from exc
    if method == "permanent":
        if is_dir:
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    return {
        "path": str(path),
        "was_dir": is_dir,
        "size": size,
        "size_text": human_bytes(size),
        "method": method,
        "trashed_to": trashed_to,
    }


def purge_trash(retention_days: int) -> dict[str, Any]:
    """清理超过保留天数的回收站条目；retention_days=0 表示清空全部。"""
    if not TRASH_DIR.exists():
        return {"removed": 0, "freed": 0}
    cutoff = time.time() - retention_days * 86400 if retention_days > 0 else time.time() + 1
    removed = 0
    freed = 0
    for child in TRASH_DIR.iterdir():
        try:
            if child.stat().st_mtime > cutoff:
                continue
            if child.is_dir():
                for current, _dirs, files in os.walk(child):
                    for name in files:
                        try:
                            freed += (Path(current) / name).stat().st_size
                        except OSError:
                            continue
                shutil.rmtree(child, ignore_errors=True)
            else:
                freed += child.stat().st_size
                child.unlink(missing_ok=True)
            removed += 1
        except OSError:
            continue
    return {"removed": removed, "freed": freed, "freed_text": human_bytes(freed)}


def list_trash(limit: int = 100) -> list[dict[str, Any]]:
    if not TRASH_DIR.exists():
        return []
    items: list[dict[str, Any]] = []
    for holder in sorted(TRASH_DIR.iterdir(), key=lambda p: p.name, reverse=True)[:limit]:
        try:
            children = list(holder.iterdir()) if holder.is_dir() else [holder]
        except OSError:
            continue
        for child in children:
            info = entry_json(child)
            info["holder"] = holder.name
            items.append(info)
    return items


def iter_dir(
    path: Path,
    *,
    include_hidden: bool,
    limit: int,
    allow_path: Callable[[Path], bool] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    if not path.exists():
        raise PolicyError("NOT_FOUND", f"目录不存在：{path}")
    if not path.is_dir():
        raise PolicyError("NOT_A_DIRECTORY", f"不是目录：{path}")
    dirs: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    truncated = False
    try:
        with os.scandir(path) as scanner:
            for item in scanner:
                name = item.name
                if not include_hidden and name.startswith("."):
                    continue
                item_path = Path(item.path)
                if allow_path is not None and not allow_path(item_path):
                    continue
                if len(dirs) + len(files) >= limit:
                    truncated = True
                    break
                try:
                    is_dir = item.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                info = entry_json(item_path)
                info["is_dir"] = is_dir
                (dirs if is_dir else files).append(info)
    except PermissionError as exc:
        raise PolicyError("ACCESS_DENIED", f"系统拒绝访问该目录：{path}") from exc
    dirs.sort(key=lambda i: i["name"].lower())
    files.sort(key=lambda i: i["name"].lower())
    return dirs + files, truncated


def walk_scope(
    roots: list[Path],
    *,
    include_hidden: bool,
    deadline: float,
    allow_path: Callable[[Path], bool] | None = None,
) -> Iterator[Path]:
    """在给定的授权根内遍历，自动跳过 node_modules / .git 等噪音目录。"""
    seen: set[str] = set()
    for root in roots:
        key = _norm(root)
        if key in seen:
            continue
        seen.add(key)
        if root.is_file():
            if allow_path is None or allow_path(root):
                yield root
            continue
        for current, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            if time.time() > deadline:
                return
            dirnames[:] = [
                d
                for d in dirnames
                if d.lower() not in SKIP_WALK_DIR_NAMES
                and (include_hidden or not d.startswith("."))
                and (allow_path is None or allow_path(Path(current) / d))
            ]
            base = Path(current)
            for name in filenames:
                if not include_hidden and name.startswith("."):
                    continue
                candidate = base / name
                if allow_path is None or allow_path(candidate):
                    yield candidate


def search_names(
    roots: list[Path],
    pattern: str,
    *,
    include_hidden: bool,
    max_results: int,
    timeout_seconds: int,
    allow_path: Callable[[Path], bool] | None = None,
) -> dict[str, Any]:
    needle = pattern.strip()
    if not needle:
        raise PolicyError("INVALID_ARGUMENT", "搜索关键字不能为空。")
    glob_mode = any(ch in needle for ch in "*?[")
    lowered = needle.lower()
    deadline = time.time() + max(1, timeout_seconds)
    matches: list[dict[str, Any]] = []
    scanned = 0
    for candidate in walk_scope(roots, include_hidden=include_hidden, deadline=deadline, allow_path=allow_path):
        scanned += 1
        name = candidate.name
        hit = fnmatch.fnmatch(name.lower(), lowered) if glob_mode else lowered in name.lower()
        if not hit:
            continue
        matches.append(entry_json(candidate))
        if len(matches) >= max_results:
            break
    return {
        "pattern": pattern,
        "mode": "glob" if glob_mode else "substring",
        "scanned": scanned,
        "count": len(matches),
        "truncated": len(matches) >= max_results,
        "timed_out": time.time() > deadline,
        "matches": matches,
    }


def search_content(
    roots: list[Path],
    query: str,
    *,
    regex: bool,
    case_sensitive: bool,
    include_hidden: bool,
    max_results: int,
    timeout_seconds: int,
    name_filter: str = "",
    allow_path: Callable[[Path], bool] | None = None,
) -> dict[str, Any]:
    import re

    text = query
    if not text:
        raise PolicyError("INVALID_ARGUMENT", "搜索内容不能为空。")
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        matcher = re.compile(text if regex else re.escape(text), flags)
    except re.error as exc:
        raise PolicyError("INVALID_ARGUMENT", f"正则表达式无效：{exc}") from exc
    deadline = time.time() + max(1, timeout_seconds)
    hits: list[dict[str, Any]] = []
    files_scanned = 0
    for candidate in walk_scope(roots, include_hidden=include_hidden, deadline=deadline, allow_path=allow_path):
        if time.time() > deadline or len(hits) >= max_results:
            break
        if name_filter and not fnmatch.fnmatch(candidate.name.lower(), name_filter.lower()):
            continue
        suffix = candidate.suffix.lower()
        if suffix and suffix not in TEXT_SUFFIXES:
            continue
        try:
            if candidate.stat().st_size > 4 * 1024 * 1024:
                continue
        except OSError:
            continue
        files_scanned += 1
        try:
            with candidate.open("r", encoding="utf-8", errors="replace") as handle:
                for lineno, line in enumerate(handle, start=1):
                    if matcher.search(line):
                        snippet = line.rstrip()[:400]
                        hits.append({"path": str(candidate), "line": lineno, "text": snippet})
                        if len(hits) >= max_results:
                            break
        except (OSError, UnicodeError):
            continue
    return {
        "query": query,
        "regex": regex,
        "case_sensitive": case_sensitive,
        "files_scanned": files_scanned,
        "count": len(hits),
        "truncated": len(hits) >= max_results,
        "timed_out": time.time() > deadline,
        "matches": hits,
    }


def list_drives() -> list[dict[str, Any]]:
    """枚举可用盘符，供前端路径浏览器起步。"""
    drives: list[dict[str, Any]] = []
    if os.name != "nt":
        drives.append({"path": "/", "label": "/", "total": 0, "free": 0})
        return drives
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZAB":
        root = f"{letter}:\\"
        if not os.path.exists(root):
            continue
        total = free = 0
        try:
            usage = shutil.disk_usage(root)
            total, free = usage.total, usage.free
        except OSError:
            pass
        drives.append(
            {
                "path": root,
                "label": f"{letter}:",
                "total": total,
                "free": free,
                "total_text": human_bytes(total),
                "free_text": human_bytes(free),
            }
        )
    return drives


def run_command(command: str, cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    """受控命令执行：只在第 4 级 + 人工批准后调用。"""
    started = time.time()
    try:
        completed = subprocess.run(
            command,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            timeout=max(1, timeout_seconds),
            text=False,
        )
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = (exc.stderr or b"") + b"\n[gateway] command timed out"
        code = -1
        timed_out = True
    limit = 60000
    def decode(data: bytes) -> tuple[str, bool]:
        cut = len(data) > limit
        return data[:limit].decode("utf-8", errors="replace"), cut
    out_text, out_cut = decode(stdout)
    err_text, err_cut = decode(stderr)
    return {
        "command": command,
        "cwd": str(cwd),
        "exit_code": code,
        "timed_out": timed_out,
        "duration_ms": int((time.time() - started) * 1000),
        "stdout": out_text,
        "stderr": err_text,
        "truncated": out_cut or err_cut,
    }


# ---------------- 原生路径选择器 ----------------
PICKER_SCRIPT = Path(__file__).resolve().parent / "pick-path.ps1"
_picker_lock = threading.Lock()


def pick_path(mode: str = "folder", initial: str = "", timeout_seconds: int = 180) -> dict[str, Any]:
    """弹出 Windows 原生"打开文件 / 选择文件夹"对话框，返回用户选中的路径。

    这是最强的授权证明：路径是你在本机对话框里亲手点的，不是模型编的。
    同一时间只允许一个对话框，避免弹出一堆窗口互相抢焦点。
    """
    if mode not in {"folder", "file"}:
        raise PolicyError("INVALID_ARGUMENT", "mode 只能是 folder 或 file。")
    if os.name != "nt":
        raise PolicyError("UNSUPPORTED", "原生选择器目前只支持 Windows。")
    if not PICKER_SCRIPT.exists():
        raise PolicyError("INTERNAL_ERROR", f"缺少选择器脚本：{PICKER_SCRIPT}")
    if not _picker_lock.acquire(blocking=False):
        raise PolicyError("PICKER_BUSY", "已经有一个选择窗口打开了，请先在本机完成选择或点取消。")
    out_file = Path(tempfile.gettempdir()) / f"gw-pick-{os.getpid()}-{os.urandom(4).hex()}.json"
    try:
        command = [
            "powershell.exe",
            "-STA",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(PICKER_SCRIPT),
            "-OutFile",
            str(out_file),
            "-Mode",
            mode,
            "-Initial",
            initial or "",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=max(10, timeout_seconds),
                text=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PolicyError(
                "PICKER_TIMEOUT",
                f"选择窗口 {timeout_seconds} 秒内没有得到结果，已取消。请回到本机屏幕再试一次。",
            ) from exc
        if completed.returncode != 0 or not out_file.exists():
            detail = (completed.stderr or b"").decode("utf-8", errors="replace").strip()[:300]
            raise PolicyError("PICKER_FAILED", f"选择窗口启动失败：{detail or '没有产生结果文件'}")
        try:
            # 结果走 UTF-8 文件而非 stdout：PS 5.1 的 stdout 按控制台代码页编码，中文路径会乱
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError("PICKER_FAILED", f"选择窗口返回了无法解析的结果：{exc}") from exc
        if not data.get("ok"):
            return {"ok": False, "cancelled": True, "path": ""}
        return {"ok": True, "cancelled": False, "path": str(data.get("path") or ""), "mode": data.get("mode", mode)}
    finally:
        out_file.unlink(missing_ok=True)
        _picker_lock.release()


# ---------------- 桌面审批弹窗 ----------------
APPROVE_SCRIPT = Path(__file__).resolve().parent / "approve-popup.ps1"
_popup_lock = threading.Lock()


def ask_desktop(
    *,
    operation: str,
    path: str,
    risk: str,
    reason: str,
    preview: str,
    approval_id: str,
    timeout_seconds: int,
) -> str:
    """在本机弹出确认窗，返回 approve / deny / timeout / unavailable。

    弹窗是"点一下就完事"的路径：不需要用户在 Notion 里打字。
    同一时刻只弹一个；已经有窗开着时返回 unavailable，让调用方退回其他确认方式。
    """
    if os.name != "nt" or not APPROVE_SCRIPT.exists():
        return "unavailable"
    if not _popup_lock.acquire(blocking=False):
        return "unavailable"
    out_file = Path(tempfile.gettempdir()) / f"gw-approve-{os.getpid()}-{os.urandom(4).hex()}.json"
    try:
        command = [
            "powershell.exe",
            "-STA",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(APPROVE_SCRIPT),
            "-OutFile",
            str(out_file),
            "-Operation",
            operation,
            "-Path",
            path,
            "-Risk",
            risk,
            "-Reason",
            reason,
            "-Preview",
            preview[:1200],
            "-ApprovalId",
            approval_id,
            "-TimeoutSeconds",
            str(max(10, int(timeout_seconds))),
        ]
        try:
            # 比窗口自身倒计时多给 15 秒，让它有机会自己写完 timeout 结果
            subprocess.run(command, capture_output=True, timeout=max(25, timeout_seconds + 15), text=False)
        except subprocess.TimeoutExpired:
            return "timeout"
        if not out_file.exists():
            return "unavailable"
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "unavailable"
        decision = str(data.get("decision") or "")
        return decision if decision in {"approve", "deny", "timeout"} else "unavailable"
    finally:
        out_file.unlink(missing_ok=True)
        _popup_lock.release()
