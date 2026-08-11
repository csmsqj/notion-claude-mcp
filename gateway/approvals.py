# -*- coding: utf-8 -*-
"""受控（人工审批）队列。

流程：
  1. MCP 工具命中 needs_approval → submit() 生成一条待审批记录，并阻塞等待。
  2. 控制台点【批准】/【拒绝】→ decide() 唤醒等待线程。
  3. 等待超时不丢失：记录转为 pending，用户之后批准会生成一次性放行凭证（grant），
     模型重试同一操作时被 consume_grant() 直接放行，避免 60 秒窗口错过就永久卡住。
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_EXPIRED = "expired"

MAX_RECORDS = 200


def approval_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class Approval:
    id: str
    tool: str
    operation: str
    path: str
    real_path: str
    reason: str
    risk: str
    classification: str
    details: dict[str, Any]
    preview: str
    created_at: float
    expires_at: float
    fingerprint: str = ""
    status: str = STATUS_PENDING
    decided_at: float = 0.0
    decided_by: str = ""
    user_reply: str = ""
    grant_used: bool = False
    event: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_json(self) -> dict[str, Any]:
        now = time.time()
        return {
            "id": self.id,
            "tool": self.tool,
            "operation": self.operation,
            "path": self.path,
            "real_path": self.real_path,
            "reason": self.reason,
            "risk": self.risk,
            "classification": self.classification,
            "details": self.details,
            "preview": self.preview,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "seconds_left": max(0, int(self.expires_at - now)) if self.status == STATUS_PENDING else 0,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "user_reply": self.user_reply,
            "grant_used": self.grant_used,
        }


class ApprovalQueue:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: dict[str, Approval] = {}
        self._order: list[str] = []
        self._listeners: list[Any] = []

    # ---------- 订阅（SSE） ----------
    def add_listener(self, queue: Any) -> None:
        with self._lock:
            self._listeners.append(queue)

    def remove_listener(self, queue: Any) -> None:
        with self._lock:
            if queue in self._listeners:
                self._listeners.remove(queue)

    def _broadcast(self, event: str, payload: dict[str, Any]) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for queue in listeners:
            try:
                queue.put_nowait({"event": event, "data": payload})
            except Exception:
                continue

    # ---------- 创建 ----------
    def recent_denial(
        self,
        tool: str,
        operation: str,
        real_path: str,
        fingerprint: str,
        within_seconds: int = 600,
    ) -> Approval | None:
        """最近是否刚拒绝过同一目标的同一操作。用于提醒模型别反复骚扰用户。"""
        key = os.path.normcase(os.path.normpath(real_path))
        now = time.time()
        with self._lock:
            for approval_id in reversed(self._order):
                item = self._items.get(approval_id)
                if item is None or item.status != STATUS_DENIED:
                    continue
                if item.tool != tool or item.operation != operation or item.fingerprint != fingerprint:
                    continue
                if now - item.decided_at > within_seconds:
                    continue
                if os.path.normcase(os.path.normpath(item.real_path)) == key:
                    return item
        return None

    def find_pending(self, tool: str, operation: str, real_path: str, fingerprint: str) -> Approval | None:
        """同一工具 + 操作 + 目标 + 内容指纹已有待裁决单时复用，避免模型重试把控制台刷满。"""
        key = os.path.normcase(os.path.normpath(real_path))
        now = time.time()
        with self._lock:
            for approval_id in reversed(self._order):
                item = self._items.get(approval_id)
                if item is None or item.status != STATUS_PENDING or now > item.expires_at:
                    continue
                if item.tool != tool or item.operation != operation or item.fingerprint != fingerprint:
                    continue
                if os.path.normcase(os.path.normpath(item.real_path)) == key:
                    return item
        return None

    def create(
        self,
        *,
        tool: str,
        operation: str,
        path: str,
        real_path: str,
        reason: str,
        risk: str,
        classification: str,
        details: dict[str, Any],
        preview: str,
        fingerprint_source: str,
        ttl_seconds: int,
    ) -> Approval:
        fingerprint = approval_fingerprint(fingerprint_source)
        existing = self.find_pending(tool, operation, real_path, fingerprint)
        if existing is not None:
            return existing
        now = time.time()
        item = Approval(
            id=uuid.uuid4().hex[:12],
            tool=tool,
            operation=operation,
            path=path,
            real_path=real_path,
            reason=reason,
            risk=risk,
            classification=classification,
            details=details,
            preview=preview,
            created_at=now,
            expires_at=now + max(30, int(ttl_seconds)),
            fingerprint=fingerprint,
        )
        with self._lock:
            # 双重检查：等锁期间可能已有并发线程建过同一张单
            duplicate = None
            for approval_id in reversed(self._order):
                other = self._items.get(approval_id)
                if (
                    other is not None
                    and other.status == STATUS_PENDING
                    and other.tool == tool
                    and other.operation == operation
                    and other.fingerprint == fingerprint
                    and os.path.normcase(os.path.normpath(other.real_path))
                    == os.path.normcase(os.path.normpath(real_path))
                ):
                    duplicate = other
                    break
            if duplicate is not None:
                return duplicate
            self._items[item.id] = item
            self._order.append(item.id)
            while len(self._order) > MAX_RECORDS:
                stale = self._order.pop(0)
                self._items.pop(stale, None)
        self._broadcast("approval_created", item.to_json())
        return item

    # ---------- 等待与裁决 ----------
    def wait(self, item: Approval, wait_seconds: int) -> str:
        if wait_seconds > 0:
            item.event.wait(timeout=wait_seconds)
        with self._lock:
            if item.status == STATUS_PENDING and time.time() > item.expires_at:
                item.status = STATUS_EXPIRED
                self._broadcast("approval_updated", item.to_json())
            return item.status

    def decide(self, approval_id: str, approve: bool, by: str = "console", user_reply: str = "") -> Approval:
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                raise KeyError(approval_id)
            if item.status in {STATUS_APPROVED, STATUS_DENIED}:
                return item
            if time.time() > item.expires_at:
                item.status = STATUS_EXPIRED
                item.event.set()
                self._broadcast("approval_updated", item.to_json())
                return item
            item.status = STATUS_APPROVED if approve else STATUS_DENIED
            item.decided_at = time.time()
            item.decided_by = by
            item.user_reply = user_reply[:400]
            item.event.set()
        self._broadcast("approval_updated", item.to_json())
        return item

    def get(self, approval_id: str) -> Approval | None:
        with self._lock:
            return self._items.get(approval_id)

    # ---------- 一次性放行凭证 ----------
    def claim(self, item: Approval) -> bool:
        """原子地占用一张已批准的单子。并发重试时只有第一个线程拿得到。"""
        with self._lock:
            if item.status != STATUS_APPROVED or item.grant_used:
                return False
            item.grant_used = True
            self._broadcast("approval_updated", item.to_json())
            return True

    def consume_grant(self, tool: str, operation: str, real_path: str, fingerprint: str) -> Approval | None:
        """仅放行工具、操作、路径和完整参数指纹都相同的一次重试。"""
        key = os.path.normcase(os.path.normpath(real_path))
        now = time.time()
        with self._lock:
            for approval_id in reversed(self._order):
                item = self._items.get(approval_id)
                if item is None or item.status != STATUS_APPROVED or item.grant_used:
                    continue
                if item.tool != tool or item.operation != operation or item.fingerprint != fingerprint:
                    continue
                if os.path.normcase(os.path.normpath(item.real_path)) != key:
                    continue
                if now > item.expires_at + 3600:
                    continue
                item.grant_used = True
                self._broadcast("approval_updated", item.to_json())
                return item
        return None

    # ---------- 查询 ----------
    def list_json(self, limit: int = 50) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            for item in self._items.values():
                if item.status == STATUS_PENDING and now > item.expires_at:
                    item.status = STATUS_EXPIRED
                    item.event.set()
            ids = list(reversed(self._order))[:limit]
            return [self._items[i].to_json() for i in ids if i in self._items]

    def pending_count(self) -> int:
        now = time.time()
        with self._lock:
            return sum(
                1
                for item in self._items.values()
                if item.status == STATUS_PENDING and now <= item.expires_at
            )


APPROVALS = ApprovalQueue()
