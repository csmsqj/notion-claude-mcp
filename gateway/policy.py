# -*- coding: utf-8 -*-
"""路径访问策略：4 级权限 + 系统保护 + 受控（审批）判定。

权限级别（对应前端 4 档）：
  1 read   只读
  2 write  读 + 写（新建 / 覆盖 / 移动 / 复制）
  3 delete 读 + 写 + 删除普通或临时小文件
  4 full   完全控制；大文件、非空目录、系统与凭据类路径的破坏性操作走"受控"人工审批
"""
from __future__ import annotations

import copy
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GATEWAY_ROOT = Path(__file__).resolve().parent
NOTION_ROOT = GATEWAY_ROOT.parent
CONFIG_DIR = GATEWAY_ROOT / "config"
POLICY_FILE = CONFIG_DIR / "policy.json"
LOG_DIR = GATEWAY_ROOT / "logs"
TRASH_DIR = GATEWAY_ROOT / "trash"

LEVEL_READ = 1
LEVEL_WRITE = 2
LEVEL_DELETE = 3
LEVEL_FULL = 4

LEVEL_NAME_BY_VALUE = {
    LEVEL_READ: "read",
    LEVEL_WRITE: "write",
    LEVEL_DELETE: "delete",
    LEVEL_FULL: "full",
}
LEVEL_VALUE_BY_NAME = {name: value for value, name in LEVEL_NAME_BY_VALUE.items()}
LEVEL_LABEL = {
    LEVEL_READ: "只读",
    LEVEL_WRITE: "读 + 写",
    LEVEL_DELETE: "读写 + 删除普通小文件",
    LEVEL_FULL: "完全控制（大文件 / 系统文件受控审批）",
}
LEVEL_HINT = {
    LEVEL_READ: "只能读取、列目录、搜索。任何写入和删除都会被拒绝。",
    LEVEL_WRITE: "可读，可新建 / 覆盖 / 追加 / 移动 / 复制。删除一律拒绝。",
    LEVEL_DELETE: "在读写基础上，允许直接删除普通小文件和临时文件；大文件、非空目录、系统或凭据类路径会被拒绝。",
    LEVEL_FULL: "全部操作可用；但大文件、非空目录、系统或凭据类路径的破坏性操作要先经你确认——默认会在这台电脑上弹出一个确认窗，你点【批准】或【拒绝】就行。",
}

OP_READ = "read"
OP_WRITE = "write"
OP_DELETE = "delete"
OP_EXEC = "exec"

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "global_lock": False,
    "system_protection": True,
    "delete_mode": "trash",
    "approval_mode": "desktop",
    "safe_delete_max_bytes": 10 * 1024 * 1024,
    "safe_delete_max_entries": 50,
    "safe_overwrite_max_bytes": 10 * 1024 * 1024,
    "approval_wait_seconds": 60,
    "approval_popup_seconds": 90,
    "approval_ttl_seconds": 900,
    "trash_retention_days": 7,
    "trash_copy_max_bytes": 100 * 1024 * 1024,
    "max_read_bytes": 262144,
    "search_max_results": 200,
    "search_timeout_seconds": 8,
    "exec_timeout_seconds": 60,
    "roots": [],
    "denies": [],
}

# 受控操作由谁放行：
#   desktop 网关在本机弹出确认窗，你点【批准】/【拒绝】（默认；控制台按钮同时有效）
#   console 只认本机控制台的【批准】按钮，不弹窗（安静模式，最严）
APPROVAL_MODES = ("desktop", "console")

SETTABLE_KEYS = (
    "system_protection",
    "delete_mode",
    "approval_mode",
    "safe_delete_max_bytes",
    "safe_delete_max_entries",
    "safe_overwrite_max_bytes",
    "approval_wait_seconds",
    "approval_popup_seconds",
    "approval_ttl_seconds",
    "trash_retention_days",
    "trash_copy_max_bytes",
    "max_read_bytes",
    "search_max_results",
    "search_timeout_seconds",
    "exec_timeout_seconds",
)

INT_LIMITS = {
    "safe_delete_max_bytes": (1024, 8 * 1024 * 1024 * 1024),
    "safe_delete_max_entries": (1, 100000),
    "safe_overwrite_max_bytes": (1024, 8 * 1024 * 1024 * 1024),
    "approval_wait_seconds": (0, 600),
    "approval_popup_seconds": (15, 300),
    "approval_ttl_seconds": (60, 86400),
    "trash_retention_days": (0, 3650),
    "trash_copy_max_bytes": (0, 64 * 1024 * 1024 * 1024),
    "max_read_bytes": (1024, 8 * 1024 * 1024),
    "search_max_results": (1, 5000),
    "search_timeout_seconds": (1, 120),
    "exec_timeout_seconds": (1, 900),
}

WINDOWS_RESERVED_NAMES = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}

TEMP_EXTENSIONS = {".tmp", ".temp", ".log", ".bak", ".old", ".cache", ".pyc", ".pyo", ".swp", ".swo", ".part", ".crdownload"}
PROTECTED_EXTENSIONS = {".sys", ".efi", ".pem", ".key", ".pfx", ".ppk", ".p12", ".jks", ".keystore", ".ovpn", ".kdbx", ".asc"}
PROTECTED_FILE_NAMES = {
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "bootmgr",
    "bcd",
    "boot.ini",
    "ntuser.dat",
    "sam",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "authorized_keys",
    "credentials",
    ".htpasswd",
}
PROTECTED_DIR_NAMES = {
    "$recycle.bin",
    "system volume information",
    "windows",
    "system32",
    "syswow64",
    "winsxs",
    "boot",
    "recovery",
    "perflogs",
    "drivers",
}
SKIP_WALK_DIR_NAMES = {
    "$recycle.bin",
    "system volume information",
    "windows",
    "winsxs",
    "node_modules",
    ".git",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".gradle",
    ".idea",
    "$windows.~bt",
    "$windows.~ws",
}


def _norm(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _real(path: Path) -> Path:
    """尽量取真实路径；不存在时回退到最近的存在祖先再拼回剩余部分。"""
    try:
        return Path(os.path.realpath(str(path)))
    except OSError:
        return path


def resolve_target(raw: str) -> "ResolvedTarget":
    """把用户/模型给的路径解析成绝对真实路径，用于权限判定。"""
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError("INVALID_PATH", "路径不能为空。")
    text = raw.strip().strip('"').replace("/", os.sep)
    if "\x00" in text:
        raise PolicyError("INVALID_PATH", "路径包含 NUL 字节。")
    candidate = Path(os.path.expandvars(os.path.expanduser(text)))
    if not candidate.is_absolute():
        raise PolicyError("INVALID_PATH", f"必须使用绝对路径（收到：{raw}）。")
    candidate = Path(os.path.normpath(str(candidate)))
    exists = candidate.exists() or candidate.is_symlink()
    if exists:
        real = _real(candidate)
    else:
        # 逐级向上找到存在的祖先，避免不存在路径 realpath 结果不稳定
        parts: list[str] = []
        probe = candidate
        while True:
            parent = probe.parent
            if parent == probe:
                break
            parts.append(probe.name)
            probe = parent
            if probe.exists():
                break
        real = _real(probe).joinpath(*reversed(parts))
    return ResolvedTarget(raw=raw, path=candidate, real=real, exists=exists)


@dataclass
class ResolvedTarget:
    raw: str
    path: Path
    real: Path
    exists: bool

    @property
    def display(self) -> str:
        return str(self.path)


class PolicyError(Exception):
    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


@dataclass
class Decision:
    allowed: bool
    needs_approval: bool
    level: int
    level_name: str
    root_id: str | None
    root_path: str | None
    reason: str
    code: str = ""
    risk: str = "low"
    classification: str = "normal"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Root:
    id: str
    path: str
    level: int
    enabled: bool = True
    note: str = ""

    @property
    def norm(self) -> str:
        return _norm(self.path)

    def to_json(self) -> dict[str, Any]:
        exists = Path(self.path).exists()
        return {
            "id": self.id,
            "path": self.path,
            "level": self.level,
            "level_name": LEVEL_NAME_BY_VALUE[self.level],
            "level_label": LEVEL_LABEL[self.level],
            "enabled": self.enabled,
            "note": self.note,
            "exists": exists,
            "is_dir": Path(self.path).is_dir() if exists else False,
        }


def _is_under(child: str, parent: str) -> bool:
    """child 是否在 parent 之内（含自身）。两者都必须先 _norm 过。"""
    if child == parent:
        return True
    if not parent.endswith(os.sep):
        parent = parent + os.sep
    return child.startswith(parent)


def is_drive_root(path: Path) -> bool:
    return path.parent == path


def looks_protected(path: Path, *, exists: bool | None = None) -> tuple[bool, str]:
    """判断是否属于"系统 / 关键 / 凭据"类路径。返回 (是否受保护, 原因)。"""
    text = _norm(path)
    name = path.name.lower()
    stem = name.split(".")[0]
    if is_drive_root(path):
        return True, "驱动器根目录"
    system_root = _norm(os.environ.get("SystemRoot", r"C:\Windows"))
    program_dirs = [
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
    ]
    if _is_under(text, system_root):
        return True, "Windows 系统目录"
    for item in program_dirs:
        if item and _is_under(text, _norm(item)):
            return True, "程序安装 / 系统数据目录"
    parts_lower = [part.lower() for part in path.parts]
    for part in parts_lower:
        if part.rstrip(os.sep).lower() in PROTECTED_DIR_NAMES:
            return True, f"受保护目录段：{part}"
    if name in PROTECTED_FILE_NAMES or stem in WINDOWS_RESERVED_NAMES:
        return True, "系统保留 / 关键文件名"
    if path.suffix.lower() in PROTECTED_EXTENSIONS:
        return True, f"敏感扩展名：{path.suffix.lower()}"
    if name in {".env", ".npmrc", ".pypirc", ".git-credentials", ".netrc"} or name.startswith(".env."):
        return True, "凭据 / 配置密钥文件"
    if ".ssh" in parts_lower or ".gnupg" in parts_lower or ".aws" in parts_lower or ".kube" in parts_lower:
        return True, "密钥 / 凭据目录"
    if _is_under(text, _norm(NOTION_ROOT / "config")) or _is_under(text, _norm(GATEWAY_ROOT / "config")):
        return True, "网关自身配置目录（含 token 与策略）"
    if _is_under(text, _norm(GATEWAY_ROOT)) and path.suffix.lower() == ".py":
        return True, "网关自身源码"
    return False, ""


def is_temp_like(path: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in TEMP_EXTENSIONS:
        return True
    if name.startswith("~$") or name.startswith(".~") or name.endswith("~"):
        return True
    parts_lower = {part.lower() for part in path.parts}
    return bool(parts_lower & {"temp", "tmp", "__pycache__", ".cache", "cache"})


def dir_stats(path: Path, *, max_entries: int, max_bytes: int) -> tuple[int, int, bool]:
    """统计目录条目数与总字节；任一超过上限就提前返回 (计数, 字节, True)。"""
    entries = 0
    total = 0
    for current, dirnames, filenames in os.walk(path, onerror=lambda _e: None):
        dirnames[:] = [d for d in dirnames if d.lower() not in {"$recycle.bin", "system volume information"}]
        entries += len(dirnames) + len(filenames)
        for filename in filenames:
            try:
                total += (Path(current) / filename).stat().st_size
            except OSError:
                continue
            if total > max_bytes or entries > max_entries:
                return entries, total, True
        if entries > max_entries:
            return entries, total, True
    return entries, total, False


class PolicyStore:
    """策略持久化 + 判定入口。所有读写都加锁，HTTP 多线程下安全。"""

    def __init__(self, config_file: Path = POLICY_FILE) -> None:
        self.config_file = config_file
        self._lock = threading.RLock()
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        self.load()

    # ---------- 持久化 ----------
    def load(self) -> None:
        with self._lock:
            if self.config_file.exists():
                try:
                    raw = json.loads(self.config_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    raw = {}
                if isinstance(raw, dict):
                    merged = copy.deepcopy(DEFAULT_CONFIG)
                    merged.update({k: v for k, v in raw.items() if k in DEFAULT_CONFIG})
                    if merged.get("approval_mode") == "both":
                        merged["approval_mode"] = "desktop"
                    elif merged.get("approval_mode") == "notion":
                        merged["approval_mode"] = "console"
                    self._data = merged
            self._data["roots"] = [self._clean_root(item) for item in self._data.get("roots", []) if isinstance(item, dict)]
            self._data["roots"] = [item for item in self._data["roots"] if item]
            self._data["denies"] = [str(item) for item in self._data.get("denies", []) if isinstance(item, str)]

    def save(self) -> None:
        with self._lock:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.config_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, self.config_file)

    @staticmethod
    def _clean_root(item: dict[str, Any]) -> dict[str, Any] | None:
        path = item.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        level = item.get("level", LEVEL_READ)
        if isinstance(level, str):
            level = LEVEL_VALUE_BY_NAME.get(level.lower(), LEVEL_READ)
        try:
            level = int(level)
        except (TypeError, ValueError):
            level = LEVEL_READ
        level = min(LEVEL_FULL, max(LEVEL_READ, level))
        return {
            "id": str(item.get("id") or os.urandom(6).hex()),
            "path": os.path.normpath(path.strip()),
            "level": level,
            "enabled": bool(item.get("enabled", True)),
            "note": str(item.get("note") or "")[:200],
        }

    # ---------- 配置读取 ----------
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._data)

    def setting(self, key: str) -> Any:
        with self._lock:
            return self._data.get(key, DEFAULT_CONFIG.get(key))

    def roots(self) -> list[Root]:
        with self._lock:
            return [
                Root(id=item["id"], path=item["path"], level=item["level"], enabled=item["enabled"], note=item["note"])
                for item in self._data.get("roots", [])
            ]

    def denies(self) -> list[str]:
        with self._lock:
            return list(self._data.get("denies", []))

    # ---------- 配置写入 ----------
    def update_settings(self, updates: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            for key, value in updates.items():
                if key not in SETTABLE_KEYS:
                    continue
                if key == "delete_mode":
                    text = str(value).lower()
                    if text not in {"trash", "permanent"}:
                        raise PolicyError("INVALID_ARGUMENT", "delete_mode 只能是 trash 或 permanent。")
                    self._data[key] = text
                elif key == "approval_mode":
                    text = str(value).lower()
                    if text not in APPROVAL_MODES:
                        raise PolicyError("INVALID_ARGUMENT", f"approval_mode 只能是 {' / '.join(APPROVAL_MODES)}。")
                    self._data[key] = text
                elif key == "system_protection":
                    self._data[key] = bool(value)
                else:
                    try:
                        number = int(value)
                    except (TypeError, ValueError) as exc:
                        raise PolicyError("INVALID_ARGUMENT", f"{key} 必须是整数。") from exc
                    low, high = INT_LIMITS[key]
                    if not low <= number <= high:
                        raise PolicyError("INVALID_ARGUMENT", f"{key} 必须在 {low} 与 {high} 之间。")
                    self._data[key] = number
            self.save()
            return copy.deepcopy(self._data)

    def set_global_lock(self, locked: bool) -> None:
        with self._lock:
            self._data["global_lock"] = bool(locked)
            self.save()

    def add_root(self, path: str, level: int | str, note: str = "") -> Root:
        target = resolve_target(path)
        if not target.exists:
            raise PolicyError("NOT_FOUND", f"路径不存在：{target.display}")
        if not target.path.is_dir() and not target.path.is_file():
            raise PolicyError("INVALID_PATH", "只能授权文件或目录。")
        if isinstance(level, str):
            level_value = LEVEL_VALUE_BY_NAME.get(level.lower())
            if level_value is None:
                raise PolicyError("INVALID_ARGUMENT", f"未知权限级别：{level}")
        else:
            level_value = int(level)
        if level_value not in LEVEL_NAME_BY_VALUE:
            raise PolicyError("INVALID_ARGUMENT", f"权限级别必须是 1-4，收到 {level}")
        if is_drive_root(target.path):
            raise PolicyError("REJECTED", "禁止把整个驱动器根目录设为可访问路径。")
        with self._lock:
            norm = _norm(target.path)
            for item in self._data["roots"]:
                if _norm(item["path"]) == norm:
                    item["level"] = level_value
                    item["enabled"] = True
                    if note:
                        item["note"] = note[:200]
                    self.save()
                    return Root(item["id"], item["path"], item["level"], item["enabled"], item["note"])
            root = {
                "id": os.urandom(6).hex(),
                "path": str(target.path),
                "level": level_value,
                "enabled": True,
                "note": note[:200],
            }
            self._data["roots"].append(root)
            self.save()
            return Root(root["id"], root["path"], root["level"], root["enabled"], root["note"])

    def update_root(self, root_id: str, *, level: int | None = None, enabled: bool | None = None, note: str | None = None) -> Root:
        with self._lock:
            for item in self._data["roots"]:
                if item["id"] != root_id:
                    continue
                if level is not None:
                    value = LEVEL_VALUE_BY_NAME.get(str(level).lower()) if isinstance(level, str) else int(level)
                    if value not in LEVEL_NAME_BY_VALUE:
                        raise PolicyError("INVALID_ARGUMENT", f"权限级别必须是 1-4，收到 {level}")
                    item["level"] = value
                if enabled is not None:
                    item["enabled"] = bool(enabled)
                if note is not None:
                    item["note"] = str(note)[:200]
                self.save()
                return Root(item["id"], item["path"], item["level"], item["enabled"], item["note"])
        raise PolicyError("NOT_FOUND", f"未找到该授权路径：{root_id}")

    def remove_root(self, root_id: str) -> bool:
        with self._lock:
            before = len(self._data["roots"])
            self._data["roots"] = [item for item in self._data["roots"] if item["id"] != root_id]
            changed = len(self._data["roots"]) != before
            if changed:
                self.save()
            return changed

    def set_denies(self, patterns: list[str]) -> list[str]:
        cleaned = []
        for item in patterns:
            if isinstance(item, str) and item.strip():
                cleaned.append(item.strip()[:400])
        with self._lock:
            self._data["denies"] = cleaned[:200]
            self.save()
            return list(self._data["denies"])

    # ---------- 核心判定 ----------
    def match_root(self, target: ResolvedTarget) -> tuple[Root | None, int]:
        """返回命中的最深授权根与其级别。real 与原始路径都要落在根内，防止软链接绕过。"""
        best: Root | None = None
        best_len = -1
        norm_path = _norm(target.path)
        norm_real = _norm(target.real)
        for root in self.roots():
            if not root.enabled:
                continue
            base = root.norm
            if _is_under(norm_path, base) and _is_under(norm_real, base):
                if len(base) > best_len:
                    best = root
                    best_len = len(base)
        return best, (best.level if best else 0)

    def matches_deny(self, target: ResolvedTarget) -> str:
        """命中黑名单返回具体模式，否则返回空串。支持路径前缀与通配符。"""
        import fnmatch

        norm_path = _norm(target.path)
        norm_real = _norm(target.real)
        for pattern in self.denies():
            norm_pattern = _norm(pattern)
            if any(ch in pattern for ch in "*?["):
                if fnmatch.fnmatch(norm_path, norm_pattern) or fnmatch.fnmatch(norm_real, norm_pattern):
                    return pattern
                continue
            if _is_under(norm_path, norm_pattern) or _is_under(norm_real, norm_pattern):
                return pattern
        return ""

    def classify(self, target: ResolvedTarget, operation: str) -> tuple[str, str, dict[str, Any]]:
        """把目标分类成 normal / temp / large / system，供 3、4 级判定使用。"""
        details: dict[str, Any] = {}
        protected, protected_reason = looks_protected(target.path) if self.setting("system_protection") else (False, "")
        if protected:
            details["protected_reason"] = protected_reason
            return "system", protected_reason, details
        if operation == OP_DELETE:
            max_bytes = int(self.setting("safe_delete_max_bytes"))
        else:
            max_bytes = int(self.setting("safe_overwrite_max_bytes"))
        max_entries = int(self.setting("safe_delete_max_entries"))
        if target.exists and target.path.is_dir():
            entries, total, overflow = dir_stats(target.path, max_entries=max_entries, max_bytes=max_bytes)
            details.update({"dir_entries": entries, "dir_bytes": total})
            if entries == 0:
                return "normal", "空目录", details
            if overflow or entries > max_entries or total > max_bytes:
                return "large", f"目录较大（约 {entries} 个条目 / {total} 字节）", details
            return "normal", f"小目录（{entries} 个条目）", details
        size = 0
        if target.exists and target.path.is_file():
            try:
                size = target.path.stat().st_size
            except OSError:
                size = 0
            details["size"] = size
        if is_temp_like(target.path):
            if size > max_bytes:
                return "large", f"临时文件但体积较大（{size} 字节）", details
            return "temp", "临时 / 缓存类文件", details
        if size > max_bytes:
            return "large", f"文件较大（{size} 字节 > 上限 {max_bytes}）", details
        return "normal", "普通小文件", details

    def evaluate(self, raw_path: str, operation: str) -> tuple[ResolvedTarget, Decision]:
        """唯一权限入口：任何文件操作都必须先过这里。"""
        target = resolve_target(raw_path)
        if operation not in {OP_READ, OP_WRITE, OP_DELETE, OP_EXEC}:
            raise PolicyError("INVALID_ARGUMENT", f"未知操作类型：{operation}")
        if self.setting("global_lock"):
            return target, Decision(
                allowed=False,
                needs_approval=False,
                level=0,
                level_name="locked",
                root_id=None,
                root_path=None,
                reason="全局开关处于【已锁定】状态，所有操作都被拒绝。",
                code="GLOBAL_LOCK",
                risk="blocked",
            )
        deny = self.matches_deny(target)
        if deny:
            return target, Decision(
                allowed=False,
                needs_approval=False,
                level=0,
                level_name="denied",
                root_id=None,
                root_path=None,
                reason=f"命中黑名单规则：{deny}",
                code="DENY_LIST",
                risk="blocked",
            )
        root, level = self.match_root(target)
        if root is None:
            return target, Decision(
                allowed=False,
                needs_approval=False,
                level=0,
                level_name="none",
                root_id=None,
                root_path=None,
                reason="该路径不在任何已授权目录内。请在控制台【访问路径】里添加后重试。",
                code="PATH_NOT_ALLOWED",
                risk="blocked",
            )
        base = Decision(
            allowed=True,
            needs_approval=False,
            level=level,
            level_name=LEVEL_NAME_BY_VALUE[level],
            root_id=root.id,
            root_path=root.path,
            reason="",
        )
        if operation == OP_READ:
            base.reason = f"命中授权根 {root.path}（{LEVEL_LABEL[level]}），读取放行。"
            base.classification = "normal"
            return target, base
        if operation == OP_EXEC:
            if level < LEVEL_FULL:
                base.allowed = False
                base.code = "EXEC_REQUIRES_FULL"
                base.risk = "blocked"
                base.reason = f"命令执行需要第 4 级（完全控制），当前是第 {level} 级（{LEVEL_LABEL[level]}）。"
                return target, base
            base.needs_approval = True
            base.risk = "high"
            base.classification = "exec"
            base.reason = "命令执行属于受控操作，需要先经用户确认。"
            return target, base
        classification, why, details = self.classify(target, operation)
        base.classification = classification
        base.details = details
        if operation == OP_WRITE:
            return target, self._decide_write(base, target, root, level, classification, why)
        return target, self._decide_delete(base, target, root, level, classification, why)

    def _decide_write(
        self,
        base: Decision,
        target: ResolvedTarget,
        root: Root,
        level: int,
        classification: str,
        why: str,
    ) -> Decision:
        if level < LEVEL_WRITE:
            base.allowed = False
            base.code = "WRITE_DENIED"
            base.risk = "blocked"
            base.reason = f"该路径只有只读权限（第 1 级），写入被拒绝。授权根：{root.path}"
            return base
        if classification == "system":
            if level < LEVEL_FULL:
                base.allowed = False
                base.code = "SYSTEM_PATH_PROTECTED"
                base.risk = "blocked"
                base.reason = f"目标属于系统 / 凭据类路径（{why}），第 {level} 级不允许写入；如确需操作请把该根提升到第 4 级。"
                return base
            base.needs_approval = True
            base.risk = "high"
            base.reason = f"写入系统 / 凭据类路径（{why}），需要先经用户确认。"
            return base
        if classification == "large" and target.exists:
            if level < LEVEL_FULL:
                base.allowed = False
                base.code = "LARGE_TARGET_PROTECTED"
                base.risk = "blocked"
                base.reason = f"覆盖大目标被拒绝（{why}）；第 4 级可走受控审批。"
                return base
            base.needs_approval = True
            base.risk = "medium"
            base.reason = f"覆盖大目标（{why}），需要先经用户确认。"
            return base
        base.reason = f"写入放行（{why}）。授权根：{root.path}"
        return base

    def _decide_delete(
        self,
        base: Decision,
        target: ResolvedTarget,
        root: Root,
        level: int,
        classification: str,
        why: str,
    ) -> Decision:
        if level < LEVEL_DELETE:
            base.allowed = False
            base.code = "DELETE_DENIED"
            base.risk = "blocked"
            base.reason = f"该路径为第 {level} 级（{LEVEL_LABEL[level]}），不允许删除。"
            return base
        if not target.exists:
            base.allowed = False
            base.code = "NOT_FOUND"
            base.risk = "blocked"
            base.reason = f"目标不存在：{target.display}"
            return base
        if classification == "system":
            if level < LEVEL_FULL:
                base.allowed = False
                base.code = "SYSTEM_PATH_PROTECTED"
                base.risk = "blocked"
                base.reason = f"系统 / 凭据类路径禁止在第 3 级删除（{why}）。"
                return base
            base.needs_approval = True
            base.risk = "critical"
            base.reason = f"删除系统 / 凭据类路径（{why}），必须先经用户确认。"
            return base
        if classification == "large":
            if level < LEVEL_FULL:
                base.allowed = False
                base.code = "LARGE_TARGET_PROTECTED"
                base.risk = "blocked"
                base.reason = f"第 3 级只允许删除普通小文件与临时文件（{why}）。"
                return base
            base.needs_approval = True
            base.risk = "high"
            base.reason = f"删除大目标（{why}），需要先经用户确认。"
            return base
        base.reason = f"删除放行（{why}）。授权根：{root.path}"
        base.risk = "low" if classification == "temp" else "medium"
        return base


POLICY = PolicyStore()
