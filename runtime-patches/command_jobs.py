# -*- coding: utf-8 -*-
"""Bounded asynchronous command jobs for tunnel-safe MCP execution."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from redaction import redact_text

_JOB_ID = re.compile(r"^[a-f0-9]{20}$")


class CommandJobError(RuntimeError):
    pass


class CommandJobNotFound(CommandJobError):
    pass


class CommandJobCapacityError(CommandJobError):
    pass


class CommandJobStartError(CommandJobError):
    pass


@dataclass
class _Job:
    job_id: str
    fingerprint: str
    command: str
    command_preview: str
    cwd: str
    timeout_seconds: int
    process: subprocess.Popen[Any]
    stdout_path: Path
    stderr_path: Path
    metadata_path: Path
    started_epoch: float
    started_monotonic: float
    status: str = "running"
    exit_code: int | None = None
    timed_out: bool = False
    finished_epoch: float | None = None
    finished_monotonic: float | None = None
    event: threading.Event = field(default_factory=threading.Event)


class CommandJobManager:
    """Run commands in worker threads while returning MCP requests promptly."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        max_running: int = 2,
        output_limit_bytes: int = 60_000,
        reuse_seconds: int = 120,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_running = max(1, int(max_running))
        self.output_limit_bytes = max(1_024, int(output_limit_bytes))
        self.reuse_seconds = max(0, int(reuse_seconds))
        self._lock = threading.RLock()
        self._jobs: dict[str, _Job] = {}
        self._history: dict[str, dict[str, Any]] = {}
        self._load_history()

    @staticmethod
    def fingerprint(command: str, cwd: str | os.PathLike[str]) -> str:
        normalized = os.path.normcase(os.path.abspath(str(cwd)))
        return hashlib.sha256((normalized + "\0" + command).encode("utf-8", errors="replace")).hexdigest()

    def _load_history(self) -> None:
        for path in self.root.glob("*.json"):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            job_id = str(item.get("job_id") or "")
            if not _JOB_ID.fullmatch(job_id):
                continue
            if item.get("status") == "running":
                item["status"] = "unknown_after_restart"
                item["note"] = (
                    "网关曾在任务运行期间重启，无法确认子进程最终状态。先检查目标结果，不要自动重跑。"
                )
            self._history[job_id] = item

    def _metadata(self, job: _Job) -> dict[str, Any]:
        return {
            "job_id": job.job_id,
            "fingerprint": job.fingerprint,
            "command_preview": job.command_preview,
            "cwd": job.cwd,
            "pid": job.process.pid,
            "status": job.status,
            "exit_code": job.exit_code,
            "timed_out": job.timed_out,
            "timeout_seconds": job.timeout_seconds,
            "started_epoch": round(job.started_epoch, 3),
            "finished_epoch": round(job.finished_epoch, 3) if job.finished_epoch is not None else None,
            "stdout_path": str(job.stdout_path),
            "stderr_path": str(job.stderr_path),
        }

    def _persist_locked(self, job: _Job) -> None:
        item = self._metadata(job)
        self._history[job.job_id] = dict(item)
        temp = job.metadata_path.with_suffix(".json.tmp")
        try:
            temp.write_text(json.dumps(item, ensure_ascii=False, indent=2), encoding="utf-8")
            temp.replace(job.metadata_path)
        except OSError:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass

    def _find_reusable_locked(self, fingerprint: str) -> str | None:
        now = time.time()
        candidates: list[tuple[float, str, str]] = []
        for job in self._jobs.values():
            stamp = job.finished_epoch or job.started_epoch
            candidates.append((stamp, job.job_id, job.status))
        for job_id, item in self._history.items():
            if item.get("fingerprint") != fingerprint or job_id in self._jobs:
                continue
            stamp = float(item.get("finished_epoch") or item.get("started_epoch") or 0)
            candidates.append((stamp, job_id, str(item.get("status") or "")))
        for stamp, job_id, status in sorted(candidates, reverse=True):
            item_fp = (
                self._jobs[job_id].fingerprint
                if job_id in self._jobs
                else str(self._history.get(job_id, {}).get("fingerprint") or "")
            )
            if item_fp != fingerprint:
                continue
            if status == "running":
                return job_id
            if status == "unknown_after_restart":
                started = float(self._history.get(job_id, {}).get("started_epoch") or stamp)
                timeout = int(self._history.get(job_id, {}).get("timeout_seconds") or 300)
                if now - started <= timeout + self.reuse_seconds:
                    return job_id
            if now - stamp <= self.reuse_seconds:
                return job_id
        return None

    def start_or_reuse(
        self,
        command: str,
        cwd: str | os.PathLike[str],
        timeout_seconds: int,
        *,
        force_new: bool = False,
    ) -> tuple[str, bool]:
        command = str(command).strip()
        cwd_text = os.path.abspath(str(cwd))
        fingerprint = self.fingerprint(command, cwd_text)
        with self._lock:
            if not force_new:
                existing = self._find_reusable_locked(fingerprint)
                if existing:
                    return existing, True
            running = sum(1 for item in self._jobs.values() if item.status == "running")
            if running >= self.max_running:
                raise CommandJobCapacityError(
                    f"已有 {running} 个命令任务在运行；请先查询现有任务状态，避免压垮本地网关。"
                )

            job_id = secrets.token_hex(10)
            stdout_path = self.root / f"{job_id}.stdout.log"
            stderr_path = self.root / f"{job_id}.stderr.log"
            metadata_path = self.root / f"{job_id}.json"
            env = os.environ.copy()
            env.setdefault("GIT_TERMINAL_PROMPT", "0")
            env.setdefault("PIP_NO_INPUT", "1")
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
            stdout_handle = stdout_path.open("wb")
            stderr_handle = stderr_path.open("wb")
            try:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    cwd=cwd_text,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    env=env,
                    creationflags=flags,
                )
            except OSError as exc:
                raise CommandJobStartError(f"命令无法启动：{exc}") from exc
            finally:
                stdout_handle.close()
                stderr_handle.close()

            now_epoch = time.time()
            job = _Job(
                job_id=job_id,
                fingerprint=fingerprint,
                command=command,
                command_preview=redact_text(command)[:600],
                cwd=cwd_text,
                timeout_seconds=max(1, int(timeout_seconds)),
                process=process,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                metadata_path=metadata_path,
                started_epoch=now_epoch,
                started_monotonic=time.monotonic(),
            )
            self._jobs[job_id] = job
            self._persist_locked(job)
            threading.Thread(
                target=self._monitor,
                args=(job_id,),
                name=f"command-job-{job_id}",
                daemon=True,
            ).start()
            return job_id, False

    def _terminate_tree(self, process: subprocess.Popen[Any]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass

    def _monitor(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
        try:
            exit_code = job.process.wait(timeout=job.timeout_seconds)
            status = "succeeded" if exit_code == 0 else "failed"
            timed_out = False
        except subprocess.TimeoutExpired:
            self._terminate_tree(job.process)
            try:
                exit_code = job.process.wait(timeout=10)
            except (subprocess.TimeoutExpired, OSError):
                exit_code = -1
            status = "timed_out"
            timed_out = True
        except OSError:
            exit_code = -1
            status = "failed"
            timed_out = False
        with self._lock:
            job.exit_code = exit_code
            job.status = status
            job.timed_out = timed_out
            job.finished_epoch = time.time()
            job.finished_monotonic = time.monotonic()
            self._persist_locked(job)
            job.event.set()

    @staticmethod
    def _decode(data: bytes) -> str:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("gb18030", errors="replace")

    def _read_limited(self, path: Path) -> tuple[str, bool]:
        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                if size <= self.output_limit_bytes:
                    data = handle.read()
                    return self._decode(data), False
                first_size = self.output_limit_bytes // 2
                last_size = self.output_limit_bytes - first_size
                first = handle.read(first_size)
                handle.seek(max(0, size - last_size))
                last = handle.read(last_size)
            marker = f"\n[gateway] ... output truncated; total {size} bytes ...\n".encode()
            return self._decode(first + marker + last), True
        except OSError:
            return "", False

    def _snapshot_current(self, job: _Job, *, include_output: bool) -> dict[str, Any]:
        now_mono = job.finished_monotonic or time.monotonic()
        result = self._metadata(job)
        result["job_duration_ms"] = int((now_mono - job.started_monotonic) * 1000)
        if include_output:
            stdout, out_cut = self._read_limited(job.stdout_path)
            stderr, err_cut = self._read_limited(job.stderr_path)
            result.update({"stdout": stdout, "stderr": stderr, "truncated": out_cut or err_cut})
        else:
            result.update({"stdout": "", "stderr": "", "truncated": False})
        result["note"] = self._note_for_status(job.status)
        return result

    def _snapshot_history(self, item: dict[str, Any], *, include_output: bool) -> dict[str, Any]:
        result = dict(item)
        if result.get("status") == "running":
            result["status"] = "unknown_after_restart"
        started = float(result.get("started_epoch") or 0)
        finished = float(result.get("finished_epoch") or time.time())
        result["job_duration_ms"] = max(0, int((finished - started) * 1000))
        if include_output:
            stdout, out_cut = self._read_limited(Path(str(result.get("stdout_path") or "")))
            stderr, err_cut = self._read_limited(Path(str(result.get("stderr_path") or "")))
            result.update({"stdout": stdout, "stderr": stderr, "truncated": out_cut or err_cut})
        else:
            result.update({"stdout": "", "stderr": "", "truncated": False})
        result["note"] = self._note_for_status(str(result.get("status") or ""))
        return result

    @staticmethod
    def _note_for_status(status: str) -> str:
        if status == "running":
            return "命令仍在本机运行。使用 get_command_status 查询；不要重复执行同一命令。"
        if status == "unknown_after_restart":
            return "网关曾在任务运行期间重启，最终状态未知。先检查目标结果，不要自动重跑。"
        if status == "timed_out":
            return "命令达到本地运行上限并已请求终止。"
        return "命令已经结束。"

    def get(self, job_id: str, *, wait_seconds: int = 0, include_output: bool = True) -> dict[str, Any]:
        if not _JOB_ID.fullmatch(str(job_id)):
            raise CommandJobNotFound("任务编号格式无效。")
        with self._lock:
            job = self._jobs.get(job_id)
            history = self._history.get(job_id)
        if job is None:
            if history is None:
                raise CommandJobNotFound(f"找不到命令任务：{job_id}")
            return self._snapshot_history(history, include_output=include_output)
        if wait_seconds > 0 and job.status == "running":
            job.event.wait(timeout=max(0, int(wait_seconds)))
        with self._lock:
            return self._snapshot_current(job, include_output=include_output)

    def list_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        limit = max(1, min(100, int(limit)))
        with self._lock:
            ids = set(self._history) | set(self._jobs)
            items: list[dict[str, Any]] = []
            for job_id in ids:
                if job_id in self._jobs:
                    items.append(self._snapshot_current(self._jobs[job_id], include_output=False))
                else:
                    items.append(self._snapshot_history(self._history[job_id], include_output=False))
        items.sort(key=lambda item: float(item.get("started_epoch") or 0), reverse=True)
        return items[:limit]
