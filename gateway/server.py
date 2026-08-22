# -*- coding: utf-8 -*-
"""通用本地文件 MCP 网关。

一个进程起两个 HTTP 服务，端口分离是刻意设计：

  8875  MCP 端点（/mcp）——由 cloudflared 暴露到公网，使用 OAuth 2.1。
  8876  本地控制台（前端页面 + 管理 API）——只绑 127.0.0.1，绝不进隧道。

如果把控制台和 MCP 放同一个端口，拿到隧道地址的人就能打开控制台给自己授权，
所以这里必须分开。控制台只绑定 127.0.0.1，不接受公网访问；MCP 公网认证统一使用 OAuth 2.1。
"""
from __future__ import annotations

import argparse
import http.server
import json
import os
import queue
import secrets
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fileops  # noqa: E402
import tools  # noqa: E402
from oauth_provider import MAX_BODY_BYTES as OAUTH_MAX_BODY_BYTES, OAuthError, OAuthProvider  # noqa: E402
from approvals import APPROVALS  # noqa: E402
from policy import (  # noqa: E402
    CONFIG_DIR,
    GATEWAY_ROOT,
    LEVEL_HINT,
    LEVEL_LABEL,
    LEVEL_NAME_BY_VALUE,
    POLICY,
    PolicyError,
    resolve_target,
)

WEB_DIR = GATEWAY_ROOT / "web"
PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = (
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",  # v0 and older MCP clients
)
SERVER_NAME = "local-file-mcp-gateway"
SERVER_TITLE = "本地文件 MCP 网关"
SERVER_VERSION = "2.6.0"
MAX_BODY_BYTES = 4 * 1024 * 1024

MODEL_INSTRUCTIONS = r"""你正在通过本地网关访问用户这台 Windows 电脑上的文件。

访问控制是白名单制：只有被显式授权的路径才可访问，每个授权路径带一个权限级别。
  第 1 级 只读：只能读取、列目录、搜索。
  第 2 级 读写：可以新建、覆盖、追加、移动、复制。
  第 3 级 读写 + 删除：额外允许直接删除普通小文件和临时文件。
  第 4 级 完全控制：全部操作可用，但大文件、非空大目录、系统与凭据类路径的破坏性操作，
          以及任何命令执行，都属于"受控操作"，必须先取得用户明确同意。

一、选路径：不要猜，让用户点
用户说"看一下我某个目录/文件"却没给准确路径时，调用 pick_path，用户电脑上会弹出 Windows
原生选择窗口。选择路径不会自动授权；未授权路径必须由用户在本机控制台选择权限等级并添加。
用户点了取消就停下来问他，不要反复弹窗。

二、受控操作：用户在本机点一下确认
高风险操作会自动在用户电脑上弹出一个确认窗，显示要动的目标、风险和原因，用户点【批准】或【拒绝】即可。
  · 用户点了批准 → 工具直接执行成功，你什么都不用做。
  · 用户点了拒绝 → 返回 APPROVAL_DENIED，不要再重试同一操作，问用户下一步怎么办。
  · 返回里提示弹窗超时或被忽略 → 提醒用户检查被遮挡的确认窗，或到本机控制台亲自批准。
客户端和模型不能调用 confirm_action 批准；该工具只能登记拒绝。一次批准只放行一次。
用 list_pending_approvals 可以查询仍在等待本机确认的操作。

三、其他约定
1. 所有 path 参数必须是 Windows 绝对路径，例如 D:\projects\demo\note.md。相对路径会被拒绝。
2. 不确定能不能操作时，先调用 list_allowed_paths 或 get_permission，不要盲试。
3. 收到 PATH_NOT_ALLOWED 说明该路径没被授权：用 pick_path 让用户选择，再让他去本机控制台添加授权。
   不要试图换路径、用 .. 或软链接绕过，这些都会被拦下并记入审计。
4. 删除默认进网关回收站，可恢复；只有用户把模式设成 permanent 才不可恢复。
5. 每一次读写删除、每一次被拒绝的尝试都会记入本机审计日志，用户随时可查。
"""


# ==================== 通用 HTTP 基类 ====================
class BaseHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"LocalFileMCPGateway/{SERVER_VERSION}"

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            # A rejected request can be closed by a client before its body is drained.
            self.close_connection = True

    def log_message(self, fmt: str, *args: Any) -> None:  # 降噪：只打非 200
        message = fmt % args
        if ' 200 ' in message or ' 204 ' in message:
            return
        print(f"[{self.server_label}] {message}", file=sys.stderr)

    @property
    def server_label(self) -> str:
        return getattr(self.server, "label", "http")

    def read_body(self) -> Any:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return None
        try:
            length = int(raw_length)
        except ValueError:
            raise PolicyError("INVALID_ARGUMENT", "Content-Length 非法。")
        if length < 0 or length > MAX_BODY_BYTES:
            raise PolicyError("PAYLOAD_TOO_LARGE", f"请求体过大（上限 {MAX_BODY_BYTES} 字节）。")
        if length == 0:
            return None
        data = self.rfile.read(length)
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError("INVALID_JSON", "请求体不是合法 JSON。") from exc

    def send_payload(
        self,
        payload: Any,
        *,
        status: int = 200,
        extra: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def send_bytes(
        self,
        data: bytes,
        content_type: str,
        *,
        status: int = 200,
        head_only: bool = False,
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(data)


# ==================== MCP 端点（对外，8875） ====================
def error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def tool_result(tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    text = tools.render_text(tool, payload)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": False,
    }


def tool_error(tool: str, exc: PolicyError) -> dict[str, Any]:
    lines = [f"{exc.code}: {exc.message}"]
    level = exc.details.get("level_label")
    if level:
        lines.append(f"当前权限：{level}")
    if exc.code == "PATH_NOT_ALLOWED":
        lines.append("请让用户打开本地控制台（http://127.0.0.1:8876），在【访问路径】中添加该目录并选择权限级别。")
    payload = {"ok": False, "tool": tool, "error": {"code": exc.code, "message": exc.message, "details": exc.details}}
    return {"content": [{"type": "text", "text": "\n".join(lines)}], "structuredContent": payload, "isError": True}


class MCPHandler(BaseHandler):
    """Public MCP resource server plus its OAuth authorization server."""

    def _request_authority(self) -> tuple[str, int | None] | None:
        forwarded_host = self.headers.get("X-Forwarded-Host", "").split(",", 1)[0].strip()
        raw = forwarded_host or self.headers.get("Host", "").strip()
        if not raw or any(ch in raw for ch in " /\\\r\n\t"):
            return None
        try:
            parsed = urllib.parse.urlsplit("//" + raw)
            if not parsed.hostname or parsed.username or parsed.password or parsed.path:
                return None
            return parsed.hostname.lower(), parsed.port
        except ValueError:
            return None

    def _configured_public_origin(self) -> str:
        url_file = CONFIG_DIR / "current-url.txt"
        try:
            public_url = url_file.read_text(encoding="utf-8").strip()
            parsed = urllib.parse.urlsplit(public_url)
            if parsed.scheme == "https" and parsed.hostname and parsed.path.rstrip("/") == "/mcp":
                return f"https://{parsed.netloc}"
        except (OSError, ValueError):
            pass
        return ""

    def _host_allowed(self) -> bool:
        authority = self._request_authority()
        if authority is None:
            return False
        hostname, port = authority
        if hostname in {"127.0.0.1", "localhost", "::1"}:
            return port in {None, int(self.server.server_address[1])}  # type: ignore[attr-defined]
        configured = self._configured_public_origin()
        if not configured:
            return False
        parsed = urllib.parse.urlsplit(configured)
        expected_port = parsed.port or 443
        return hostname == (parsed.hostname or "").lower() and (port or 443) == expected_port

    def _external_origin(self) -> str:
        authority = self._request_authority()
        if authority and authority[0] not in {"127.0.0.1", "localhost", "::1"}:
            configured = self._configured_public_origin()
            if configured:
                return configured
        bind_host, bind_port = self.server.server_address[:2]  # type: ignore[attr-defined]
        if authority and authority[0] in {"127.0.0.1", "localhost", "::1"}:
            return f"http://{self.headers.get('Host', '').strip()}".rstrip("/")
        return f"http://{bind_host}:{bind_port}"

    def _resource_url(self) -> str:
        return self._external_origin() + "/mcp"

    def _origin_allowed(self) -> bool:
        """Reject browser requests from an untrusted Origin."""
        if not self._host_allowed():
            return False
        origin = self.headers.get("Origin", "").strip()
        if not origin:
            return True
        if origin == "null":
            return False
        try:
            parsed = urllib.parse.urlsplit(origin)
            normalized = origin.rstrip("/")
            trusted_origins = {
                self._external_origin(),
                "https://app.lobehub.com",
                "https://platform.kimi.ai",
                "https://manus.im",
            }
            return (
                normalized in trusted_origins
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
            )
        except ValueError:
            return False

    def _origin_denied(self) -> None:
        self.close_connection = True
        self.send_payload({"error": "forbidden", "error_description": "Origin is not allowed"}, status=403)

    def _protocol_header_allowed(self) -> bool:
        version = self.headers.get("MCP-Protocol-Version", "").strip()
        return not version or version in SUPPORTED_PROTOCOL_VERSIONS

    def _accepts_json(self) -> bool:
        accept = self.headers.get("Accept", "").lower()
        return not accept or "application/json" in accept or "*/*" in accept

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "").strip()
        if not header.startswith("Bearer "):
            return False
        token = header[len("Bearer "):].strip()
        if not token:
            return False
        return self.server.oauth.validate_access_token(  # type: ignore[attr-defined]
            token,
            self._external_origin(),
            self._resource_url(),
        )

    def _unauthorized(self, *, head_only: bool = False) -> None:
        metadata_url = self._external_origin() + "/.well-known/oauth-protected-resource/mcp"
        challenge = (
            'Bearer realm="local-file-mcp-gateway", error="invalid_token", '
            f'resource_metadata="{metadata_url}", scope="mcp"'
        )
        # Some clients POST initialize before OAuth discovery. Because an
        # unauthenticated body is deliberately not parsed, close HTTP/1.1 here;
        # otherwise its JSON bytes can become the prefix of the client's next
        # GET request (observed with v0/AI SDK as a malformed "{...}GET").
        self.close_connection = True
        self.send_payload(
            error_response(None, -32000, "OAuth authorization required"),
            status=401,
            extra={"WWW-Authenticate": challenge, "Connection": "close"},
            head_only=head_only,
        )

    def _send_html(self, body: str, *, status: int = 200, head_only: bool = False) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _send_redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_oauth_bytes(self) -> bytes | None:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self.send_payload({"error": "invalid_request", "error_description": "Content-Length is required"}, status=411)
            return None
        try:
            length = int(raw_length)
        except ValueError:
            self.send_payload({"error": "invalid_request", "error_description": "Invalid Content-Length"}, status=400)
            return None
        if length < 0 or length > OAUTH_MAX_BODY_BYTES:
            self.send_payload({"error": "invalid_request", "error_description": "OAuth request body is too large"}, status=413)
            return None
        return self.rfile.read(length)

    def _send_oauth_error(self, exc: OAuthError) -> None:
        extra = {"WWW-Authenticate": 'Basic realm="local-file-mcp-gateway-oauth"'} if exc.error == "invalid_client" else None
        self.send_payload(exc.payload(), status=exc.status, extra=extra)

    def _send_sse_bootstrap(self, *, head_only: bool = False) -> None:
        accept = self.headers.get("Accept", "").lower()
        if not head_only and "text/event-stream" not in accept and "*/*" not in accept:
            self.send_payload(
                {"error": "not_acceptable", "error_description": "Accept must allow text/event-stream"},
                status=406,
            )
            return
        session_id = (self.headers.get("Mcp-Session-Id") or "").strip()
        if session_id and not self.server.has_session(session_id):  # type: ignore[attr-defined]
            self.send_payload(
                {"error": "invalid_session", "error_description": "Unknown or expired Mcp-Session-Id"},
                status=404,
            )
            return
        if session_id:
            body = b": connected\n\n"
        else:
            body = f"event: endpoint\ndata: {self._resource_url()}\n\n".encode("utf-8")
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        origin = self.headers.get("Origin", "").strip()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)
            self.wfile.flush()

    def do_OPTIONS(self) -> None:
        if not self._origin_allowed():
            self._origin_denied()
            return
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, DELETE, OPTIONS")
        origin = self.headers.get("Origin", "").strip()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, DELETE, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Accept, Authorization, Content-Type, Last-Event-ID, MCP-Protocol-Version, Mcp-Session-Id",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self._handle_get(head_only=False)

    def do_HEAD(self) -> None:
        self._handle_get(head_only=True)

    def _handle_get(self, *, head_only: bool) -> None:
        if not self._origin_allowed():
            self._origin_denied()
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        issuer = self._external_origin()
        resource = self._resource_url()
        oauth = self.server.oauth  # type: ignore[attr-defined]
        if path == "/.well-known/oauth-authorization-server":
            self.send_payload(oauth.authorization_server_metadata(issuer), head_only=head_only)
            return
        if path in {"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"}:
            self.send_payload(oauth.protected_resource_metadata(resource, issuer), head_only=head_only)
            return
        if path in {"/.well-known/mcp.json", "/.well-known/mcp/server-card.json"}:
            self.send_payload(self.server.card(issuer), head_only=head_only)  # type: ignore[attr-defined]
            return
        if path == "/oauth/authorize":
            if head_only:
                self.send_payload({"error": "method_not_allowed"}, status=405, extra={"Allow": "GET"}, head_only=True)
                return
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            try:
                info = oauth.begin_authorization(params, issuer, resource)
            except OAuthError as exc:
                error_redirect = oauth.authorization_error_redirect(params, exc)
                if error_redirect:
                    self._send_redirect(error_redirect)
                else:
                    self._send_html(oauth.error_page(exc.error, exc.description), status=exc.status)
                return
            self._send_html(oauth.waiting_page(info))
            return
        if path == "/oauth/status":
            if head_only:
                self.send_payload({"ok": True}, head_only=True)
                return
            request_id = urllib.parse.parse_qs(parsed.query).get("request", [""])[0]
            try:
                self.send_payload(oauth.authorization_status(request_id))
            except OAuthError as exc:
                self._send_oauth_error(exc)
            return
        if path == "/mcp":
            if not self._authorized():
                self._unauthorized(head_only=head_only)
                return
            if not self._protocol_header_allowed():
                self.send_payload(
                    {"error": "invalid_request", "error_description": "Unsupported MCP-Protocol-Version"},
                    status=400,
                    head_only=head_only,
                )
                return
            # Manus opens an authenticated GET stream before sending initialize
            # and treats a spec-valid 405 as a failed connector. A short SSE
            # bootstrap keeps Streamable HTTP POST semantics unchanged.
            self._send_sse_bootstrap(head_only=head_only)
            return
        if path == "/healthz":
            self.send_payload(
                {"ok": True, "server": SERVER_NAME, "version": SERVER_VERSION, "auth": "oauth2.1"},
                head_only=head_only,
            )
            return
        self.send_payload({"error": "Unknown endpoint"}, status=404, head_only=head_only)

    def do_DELETE(self) -> None:
        if not self._origin_allowed():
            self._origin_denied()
            return
        if not self._protocol_header_allowed():
            self.send_payload({"error": "invalid_request", "error_description": "Unsupported MCP-Protocol-Version"}, status=400)
            return
        if urllib.parse.urlparse(self.path).path.rstrip("/") != "/mcp":
            self.send_payload({"error": "Unknown endpoint"}, status=404)
            return
        if not self._authorized():
            self._unauthorized()
            return
        session = self.headers.get("Mcp-Session-Id") or ""
        if not session or not self.server.has_session(session):  # type: ignore[attr-defined]
            self.send_payload(
                {"error": "invalid_session", "error_description": "Unknown or expired Mcp-Session-Id"},
                status=404,
            )
            return
        self.server.drop_session(session)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        if not self._origin_allowed():
            self._origin_denied()
            return
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        oauth = self.server.oauth  # type: ignore[attr-defined]
        if path == "/oauth/register":
            raw = self._read_oauth_bytes()
            if raw is None:
                return
            if self.headers.get_content_type().lower() != "application/json":
                self.send_payload({"error": "invalid_client_metadata", "error_description": "Content-Type must be application/json"}, status=400)
                return
            try:
                metadata = json.loads(raw.decode("utf-8"))
                if not isinstance(metadata, dict):
                    raise ValueError("metadata must be a JSON object")
                self.send_payload(oauth.register(metadata), status=201)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                self.send_payload({"error": "invalid_client_metadata", "error_description": str(exc)}, status=400)
            except OAuthError as exc:
                self._send_oauth_error(exc)
            return
        if path == "/oauth/token":
            raw = self._read_oauth_bytes()
            if raw is None:
                return
            if self.headers.get_content_type().lower() != "application/x-www-form-urlencoded":
                self.send_payload({"error": "invalid_request", "error_description": "Content-Type must be application/x-www-form-urlencoded"}, status=400)
                return
            params = urllib.parse.parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
            try:
                payload = oauth.token(
                    params,
                    self.headers.get("Authorization", ""),
                    self._external_origin(),
                    self._resource_url(),
                )
                self.send_payload(payload)
            except OAuthError as exc:
                self._send_oauth_error(exc)
            return
        if path != "/mcp":
            self.send_payload(error_response(None, -32601, "Unknown endpoint"), status=404)
            return
        if not self._protocol_header_allowed():
            self.send_payload({"error": "invalid_request", "error_description": "Unsupported MCP-Protocol-Version"}, status=400)
            return
        if not self._accepts_json():
            self.send_payload({"error": "not_acceptable", "error_description": "Accept must allow application/json"}, status=406)
            return
        if not self._authorized():
            self._unauthorized()
            return
        if self.headers.get_content_type().lower() != "application/json":
            self.send_payload(error_response(None, -32600, "Content-Type must be application/json"), status=415)
            return
        try:
            request = self.read_body()
        except PolicyError as exc:
            self.send_payload(error_response(None, -32600, exc.message), status=400)
            return
        if not isinstance(request, dict):
            self.send_payload(error_response(None, -32600, "Invalid Request"), status=400)
            return
        request_id = request.get("id")
        if request.get("jsonrpc") != "2.0":
            self.send_payload(error_response(request_id, -32600, "jsonrpc must be 2.0"), status=400)
            return
        method = str(request.get("method") or "")
        if not method:
            self.send_payload(error_response(request_id, -32600, "method is required"), status=400)
            return
        if not method.startswith("notifications/") and "id" not in request:
            self.send_payload(error_response(None, -32600, "Request id is required"), status=400)
            return
        session_id = self.headers.get("Mcp-Session-Id") or ""
        extra: dict[str, str] = {}
        if method == "initialize":
            session_id = self.server.new_session()  # type: ignore[attr-defined]
        elif not session_id or not self.server.has_session(session_id):  # type: ignore[attr-defined]
            self.send_payload(error_response(request_id, -32001, "Unknown or expired Mcp-Session-Id"), status=404)
            return
        elif method == "notifications/initialized":
            self.server.mark_initialized(session_id)  # type: ignore[attr-defined]
        elif method not in {"ping", "notifications/cancelled"} and not self.server.is_initialized(session_id):  # type: ignore[attr-defined]
            self.send_payload(error_response(request_id, -32002, "MCP session is not initialized"), status=400)
            return
        if session_id:
            extra["Mcp-Session-Id"] = session_id
        response = self.dispatch(request, method, request_id)
        if response is None:
            self.send_response(202)
            for key, value in extra.items():
                self.send_header(key, value)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_payload(response, extra=extra)

    def dispatch(self, request: dict[str, Any], method: str, request_id: Any) -> dict[str, Any] | None:
        if method in {"notifications/initialized", "notifications/cancelled"}:
            return None
        if method == "initialize":
            params = request.get("params") or {}
            if not isinstance(params, dict):
                return error_response(request_id, -32602, "params 必须是对象")
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "title": SERVER_TITLE, "version": SERVER_VERSION},
                "instructions": MODEL_INSTRUCTIONS,
            }
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools.TOOL_DEFS}}
        if method == "tools/call":
            params = request.get("params") or {}
            if not isinstance(params, dict):
                return error_response(request_id, -32602, "params 必须是对象")
            name = str(params.get("name") or "")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return error_response(request_id, -32602, "arguments 必须是对象")
            if name not in tools.TOOL_DEFS_BY_NAME:
                return error_response(request_id, -32602, f"未知工具：{name}")
            try:
                payload = tools.call(name, args)
                result = tool_result(name, payload)
            except PolicyError as exc:
                result = tool_error(name, exc)
            except FileNotFoundError as exc:
                result = tool_error(name, PolicyError("NOT_FOUND", f"路径不存在：{exc}"))
            except PermissionError as exc:
                result = tool_error(name, PolicyError("ACCESS_DENIED", f"系统拒绝访问：{exc}"))
            except OSError as exc:
                result = tool_error(name, PolicyError("OS_ERROR", f"系统错误：{exc}"))
            except Exception as exc:  # noqa: BLE001
                result = tool_error(name, PolicyError("INTERNAL_ERROR", f"内部错误：{exc}"))
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        return error_response(request_id, -32601, f"Unknown method: {method}")


# ==================== 本地控制台（只绑 127.0.0.1，8876） ====================
def _int_arg(params: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(params.get(key, [str(default)])[0])
    except (TypeError, ValueError):
        return default


def _str_arg(params: dict[str, list[str]], key: str, default: str = "") -> str:
    value = params.get(key)
    return value[0] if value else default


def _bool_arg(params: dict[str, list[str]], key: str) -> bool:
    return _str_arg(params, key).lower() in {"1", "true", "yes", "on"}


class ConsoleHandler(BaseHandler):
    def _client_is_local(self) -> bool:
        host = (self.client_address[0] or "").strip()
        return host in {"127.0.0.1", "::1", "localhost"}

    def _host_is_local(self) -> bool:
        raw_host = self.headers.get("Host", "").strip()
        try:
            parsed = urllib.parse.urlsplit("//" + raw_host)
            return (
                parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                and (parsed.port or 80) == self.server.server_address[1]
            )
        except ValueError:
            return False

    def _origin_is_local(self) -> bool:
        origin = self.headers.get("Origin", "").strip()
        if not origin:
            return True
        if origin == "null":
            return False
        try:
            parsed = urllib.parse.urlsplit(origin)
            return (
                parsed.scheme == "http"
                and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                and (parsed.port or 80) == self.server.server_address[1]
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
            )
        except ValueError:
            return False

    def _authorized(self, params: dict[str, list[str]]) -> bool:
        # The console is loopback-only. MCP's public authentication is OAuth;
        # keeping a second static token here only creates a legacy auth path.
        return self._client_is_local() and self._host_is_local() and self._origin_is_local()

    def _deny(self) -> None:
        self.close_connection = True
        self.send_payload({"ok": False, "error": "控制台只允许本机访问。"}, status=403)

    def do_OPTIONS(self) -> None:
        self.send_payload({"ok": False, "error": "控制台不接受跨域预检。"}, status=403)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        if path in {"", "/", "/index.html"}:
            self.serve_static("index.html")
            return
        if path.startswith("/static/"):
            self.serve_static(path[len("/static/"):])
            return
        if path == "/favicon.ico":
            self.send_bytes(b"", "image/x-icon")
            return
        if not path.startswith("/api/"):
            self.send_payload({"ok": False, "error": "Unknown endpoint"}, status=404)
            return
        if not self._authorized(params):
            self._deny()
            return
        try:
            self.handle_api_get(path, params)
        except PolicyError as exc:
            self.send_payload({"ok": False, "code": exc.code, "error": exc.message}, status=400)
        except Exception as exc:  # noqa: BLE001
            self.send_payload({"ok": False, "code": "INTERNAL", "error": str(exc)}, status=500)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if not parsed.path.startswith("/api/"):
            self.send_payload({"ok": False, "error": "Unknown endpoint"}, status=404)
            return
        if not self._authorized(params):
            self._deny()
            return
        if self.headers.get_content_type().lower() != "application/json":
            self.close_connection = True
            self.send_payload(
                {"ok": False, "code": "INVALID_CONTENT_TYPE", "error": "控制台 POST 必须使用 application/json。"},
                status=415,
            )
            return
        try:
            body = self.read_body() or {}
            if not isinstance(body, dict):
                raise PolicyError("INVALID_ARGUMENT", "请求体必须是 JSON 对象。")
            self.handle_api_post(parsed.path, body)
        except PolicyError as exc:
            self.send_payload({"ok": False, "code": exc.code, "error": exc.message}, status=400)
        except Exception as exc:  # noqa: BLE001
            self.send_payload({"ok": False, "code": "INTERNAL", "error": str(exc)}, status=500)

    def serve_static(self, name: str) -> None:
        safe = name.replace("\\", "/").lstrip("/")
        if ".." in safe:
            self.send_payload({"ok": False, "error": "非法路径"}, status=400)
            return
        web_root = WEB_DIR.resolve()
        target = (web_root / safe).resolve()
        if not target.is_relative_to(web_root) or not target.is_file():
            self.send_payload({"ok": False, "error": f"找不到文件：{safe}"}, status=404)
            return
        types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".json": "application/json; charset=utf-8",
        }
        headers = {
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        if target.suffix.lower() == ".html":
            headers.update({
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                ),
            })
        self.send_bytes(
            target.read_bytes(),
            types.get(target.suffix.lower(), "application/octet-stream"),
            extra=headers,
        )

    # ---------- 控制台 GET ----------
    def handle_api_get(self, path: str, params: dict[str, list[str]]) -> None:
        if path == "/api/state":
            self.send_payload(self.server.state_payload())  # type: ignore[attr-defined]
            return
        if path == "/api/drives":
            self.send_payload({"ok": True, "drives": fileops.list_drives()})
            return
        if path == "/api/browse":
            raw = _str_arg(params, "path")
            if not raw:
                self.send_payload({"ok": True, "path": "", "parent": "", "drives": fileops.list_drives(), "entries": []})
                return
            target = resolve_target(raw)
            if not target.path.exists():
                raise PolicyError("NOT_FOUND", f"路径不存在：{target.display}")
            entries, truncated = fileops.iter_dir(
                target.path,
                include_hidden=_bool_arg(params, "hidden"),
                limit=_int_arg(params, "limit", 800),
            )
            _root, level = POLICY.match_root(target)
            parent = "" if target.path.parent == target.path else str(target.path.parent)
            self.send_payload(
                {
                    "ok": True,
                    "path": target.display,
                    "parent": parent,
                    "level": level,
                    "level_label": LEVEL_LABEL.get(level, "未授权"),
                    "truncated": truncated,
                    "entries": entries,
                }
            )
            return
        if path == "/api/preview":
            raw = _str_arg(params, "path")
            if not raw:
                raise PolicyError("INVALID_ARGUMENT", "预览路径不能为空。")
            payload = tools.t_read_file(
                {
                    "path": raw,
                    "start_line": max(1, _int_arg(params, "start_line", 1)),
                    "max_bytes": min(
                        int(POLICY.setting("max_read_bytes")),
                        max(1024, _int_arg(params, "max_bytes", int(POLICY.setting("max_read_bytes")))),
                    ),
                    "max_lines": min(2000, max(1, _int_arg(params, "max_lines", 500))),
                }
            )
            self.send_payload(payload)
            return
        if path == "/api/search":
            keyword = _str_arg(params, "q")
            scope = _str_arg(params, "scope")
            if not keyword:
                raise PolicyError("INVALID_ARGUMENT", "搜索关键字不能为空。")
            roots = [resolve_target(scope).path] if scope else [Path(item.path) for item in POLICY.roots() if item.enabled]
            if not roots:
                raise PolicyError("INVALID_ARGUMENT", "请先选择一个搜索起点目录，或先添加授权路径。")
            payload = fileops.search_names(
                roots,
                keyword,
                include_hidden=_bool_arg(params, "hidden"),
                max_results=_int_arg(params, "limit", 300),
                timeout_seconds=int(POLICY.setting("search_timeout_seconds")),
            )
            annotated = []
            for item in payload["matches"]:
                target = resolve_target(item["path"])
                _root, level = POLICY.match_root(target)
                item["level"] = level
                annotated.append(item)
            payload["matches"] = annotated
            payload["ok"] = True
            self.send_payload(payload)
            return
        if path == "/api/approvals":
            self.send_payload({"ok": True, "items": APPROVALS.list_json(_int_arg(params, "limit", 50))})
            return
        if path == "/api/audit":
            self.send_payload({"ok": True, "items": fileops.tail_audit(_int_arg(params, "limit", 200))})
            return
        if path == "/api/trash":
            self.send_payload({"ok": True, "items": fileops.list_trash(_int_arg(params, "limit", 100))})
            return
        if path == "/api/oauth/requests":
            self.send_payload({"ok": True, "items": self.server.oauth.list_requests()})  # type: ignore[attr-defined]
            return
        if path == "/api/events":
            self.stream_events()
            return
        self.send_payload({"ok": False, "error": "Unknown API"}, status=404)

    def stream_events(self) -> None:
        """SSE 推送：审批单出现或被裁决时前端立刻刷新，不靠轮询。"""
        channel: queue.Queue = queue.Queue(maxsize=64)
        APPROVALS.add_listener(channel)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    message = channel.get(timeout=15)
                    block = f"event: {message['event']}\ndata: {json.dumps(message['data'], ensure_ascii=False)}\n\n"
                except queue.Empty:
                    block = ": ping\n\n"
                self.wfile.write(block.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            APPROVALS.remove_listener(channel)

    # ---------- 控制台 POST ----------
    def handle_api_post(self, path: str, body: dict[str, Any]) -> None:
        if path == "/api/roots/add":
            root = POLICY.add_root(
                str(body.get("path", "")),
                body.get("level", 1),
                str(body.get("note") or ""),
            )
            fileops.audit("root_added", {"path": root.path, "level": root.level})
            self.send_payload({"ok": True, "root": root.to_json(), "state": self.server.state_payload()})  # type: ignore[attr-defined]
            return
        if path == "/api/roots/update":
            root = POLICY.update_root(
                str(body.get("id", "")),
                level=body.get("level"),
                enabled=body.get("enabled"),
                note=body.get("note"),
            )
            fileops.audit("root_updated", {"path": root.path, "level": root.level, "enabled": root.enabled})
            self.send_payload({"ok": True, "root": root.to_json(), "state": self.server.state_payload()})  # type: ignore[attr-defined]
            return
        if path == "/api/roots/remove":
            removed = POLICY.remove_root(str(body.get("id", "")))
            fileops.audit("root_removed", {"id": body.get("id"), "removed": removed})
            self.send_payload({"ok": removed, "state": self.server.state_payload()})  # type: ignore[attr-defined]
            return
        if path == "/api/denies":
            patterns = body.get("patterns")
            if not isinstance(patterns, list):
                raise PolicyError("INVALID_ARGUMENT", "patterns 必须是数组。")
            saved = POLICY.set_denies([str(item) for item in patterns])
            fileops.audit("denies_updated", {"count": len(saved)})
            self.send_payload({"ok": True, "denies": saved})
            return
        if path == "/api/settings":
            updated = POLICY.update_settings(body if isinstance(body, dict) else {})
            fileops.audit("settings_updated", {"keys": sorted(body.keys())})
            self.send_payload({"ok": True, "settings": {k: v for k, v in updated.items() if k not in {"roots", "denies"}}})
            return
        if path == "/api/lock":
            if type(body.get("locked")) is not bool:
                raise PolicyError("INVALID_ARGUMENT", "locked 必须是布尔值。")
            locked = body["locked"]
            POLICY.set_global_lock(locked)
            fileops.audit("global_lock", {"locked": locked})
            self.send_payload({"ok": True, "state": self.server.state_payload()})  # type: ignore[attr-defined]
            return
        if path == "/api/approvals/decide":
            approval_id = str(body.get("id", ""))
            if type(body.get("approve")) is not bool:
                raise PolicyError("INVALID_ARGUMENT", "approve 必须是布尔值。")
            approve = body["approve"]
            try:
                item = APPROVALS.decide(approval_id, approve, by="console")
            except KeyError as exc:
                raise PolicyError("NOT_FOUND", f"未找到审批单：{approval_id}") from exc
            self.send_payload({"ok": True, "item": item.to_json()})
            return
        if path == "/api/pick":
            # 控制台按钮触发的原生选择器。弹窗会阻塞这个请求，所以前端要给足超时。
            mode = str(body.get("mode") or "folder").lower()
            result = fileops.pick_path(
                mode=mode,
                initial=str(body.get("initial") or ""),
                timeout_seconds=int(body.get("timeout_seconds") or 180),
            )
            if not result["ok"]:
                fileops.audit("pick_cancelled", {"mode": mode, "by": "console"})
                self.send_payload({"ok": True, "cancelled": True, "path": ""})
                return
            fileops.audit("pick_selected", {"mode": mode, "path": result["path"], "by": "console"})
            payload: dict[str, Any] = {"ok": True, "cancelled": False, "path": result["path"]}
            level = body.get("level")
            if level is not None:
                root = POLICY.add_root(result["path"], level, str(body.get("note") or "本机选择"))
                fileops.audit("root_added", {"path": root.path, "level": root.level, "by": "console_pick"})
                payload["root"] = root.to_json()
                payload["state"] = self.server.state_payload()  # type: ignore[attr-defined]
            self.send_payload(payload)
            return
        if path == "/api/oauth/decide":
            request_id = str(body.get("id") or "")
            if type(body.get("approve")) is not bool:
                raise PolicyError("INVALID_ARGUMENT", "approve 必须是布尔值。")
            try:
                result = self.server.oauth.decide_authorization(request_id, body["approve"])  # type: ignore[attr-defined]
            except OAuthError as exc:
                self.send_payload({"ok": False, **exc.payload()}, status=exc.status)
                return
            self.send_payload(result)
            return
        if path == "/api/trash/purge":
            days = body.get("retention_days")
            retention = int(days) if days is not None else int(POLICY.setting("trash_retention_days"))
            payload = fileops.purge_trash(max(0, retention))
            fileops.audit("trash_purged", payload)
            self.send_payload({"ok": True, **payload})
            return
        self.send_payload({"ok": False, "error": "Unknown API"}, status=404)


# ==================== 服务器装配 ====================
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"
    label = "http"

    def server_bind(self) -> None:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class MCPServer(ThreadedHTTPServer):
    label = "mcp"

    def __init__(self, address: tuple[str, int], oauth: OAuthProvider) -> None:
        super().__init__(address, MCPHandler)
        self.oauth = oauth
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def new_session(self) -> str:
        session_id = secrets.token_hex(16)
        with self._lock:
            now = time.time()
            self._sessions = {
                key: value
                for key, value in self._sessions.items()
                if now - float(value.get("last_seen", 0)) < 7200
            }
            self._sessions[session_id] = {"last_seen": now, "initialized": False}
        return session_id

    def has_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or time.time() - float(session.get("last_seen", 0)) >= 7200:
                self._sessions.pop(session_id, None)
                return False
            session["last_seen"] = time.time()
            return True

    def mark_initialized(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]["initialized"] = True
                self._sessions[session_id]["last_seen"] = time.time()

    def is_initialized(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            return bool(session and session.get("initialized"))

    def drop_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def card(self, issuer: str) -> dict[str, Any]:
        issuer = issuer.rstrip("/")
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "server": {"name": SERVER_NAME, "title": SERVER_TITLE, "version": SERVER_VERSION},
            "transport": {"type": "streamable_http", "endpoint": "/mcp", "methods": ["POST", "DELETE", "OPTIONS"]},
            "auth": {
                "type": "oauth2",
                "scheme": "Bearer",
                "authorizationUrl": issuer + "/oauth/authorize",
                "tokenUrl": issuer + "/oauth/token",
                "registrationUrl": issuer + "/oauth/register",
                "pkce": "S256",
            },
            "tools": {"count": len(tools.TOOL_DEFS), "names": [item["name"] for item in tools.TOOL_DEFS]},
            "capabilities": {"tools": {"listChanged": False}},
        }


class ConsoleServer(ThreadedHTTPServer):
    label = "console"

    def __init__(self, address: tuple[str, int], mcp_port: int, oauth: OAuthProvider) -> None:
        super().__init__(address, ConsoleHandler)
        self.mcp_port = mcp_port
        self.oauth = oauth

    def state_payload(self) -> dict[str, Any]:
        config = POLICY.snapshot()
        settings = {k: v for k, v in config.items() if k not in {"roots", "denies"}}
        url_file = CONFIG_DIR / "current-url.txt"
        public_url = url_file.read_text(encoding="utf-8").strip() if url_file.exists() else ""
        public_origin = public_url[:-4] if public_url.endswith("/mcp") else public_url.rstrip("/")
        tunnel_mode = "quick"
        stable_url = False
        tunnel_settings_file = CONFIG_DIR / "tunnel-settings.json"
        if tunnel_settings_file.exists():
            try:
                tunnel_settings = json.loads(tunnel_settings_file.read_text(encoding="utf-8-sig"))
                tunnel_mode = str(tunnel_settings.get("mode") or "quick")
                stable_url = tunnel_mode == "named" and bool(tunnel_settings.get("hostname"))
            except (OSError, json.JSONDecodeError):
                pass
        oauth_status = self.oauth.status()
        oauth_status.update({
            "issuer": public_origin,
            "authorization_endpoint": public_origin + "/oauth/authorize" if public_origin else "",
            "token_endpoint": public_origin + "/oauth/token" if public_origin else "",
            "registration_endpoint": public_origin + "/oauth/register" if public_origin else "",
        })
        return {
            "ok": True,
            "server": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
                "mcp_port": self.mcp_port,
                "console_port": self.server_address[1],
                "public_url": public_url,
                "local_url": f"http://127.0.0.1:{self.mcp_port}/mcp",
                "auth_mode": "OAuth 2.1",
                "oauth": oauth_status,
                "tunnel_mode": tunnel_mode,
                "stable_url": stable_url,
                "tunnel_running": bool(public_url),
                "tool_count": len(tools.TOOL_DEFS),
            },
            "settings": settings,
            "roots": [root.to_json() for root in POLICY.roots()],
            "denies": POLICY.denies(),
            "levels": [
                {
                    "level": value,
                    "name": name,
                    "label": LEVEL_LABEL[value],
                    "hint": LEVEL_HINT[value],
                }
                for value, name in LEVEL_NAME_BY_VALUE.items()
            ],
            "pending_approvals": APPROVALS.pending_count() + int(oauth_status.get("pending_authorizations", 0)),
            "tools": [
                {"name": item["name"], "title": item.get("title", item["name"]), "description": item["description"]}
                for item in tools.TOOL_DEFS
            ],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="本地文件 MCP 网关（OAuth 2.1 + 本地控制台）")
    parser.add_argument("--mcp-port", type=int, default=8875, help="MCP 端口，默认 8875")
    parser.add_argument("--console-port", type=int, default=8876, help="本地控制台端口，默认 8876")
    parser.add_argument("--mcp-host", default="127.0.0.1", help="MCP 绑定地址，默认 127.0.0.1")
    parser.add_argument("--open", action="store_true", help="启动后自动打开控制台页面")
    args = parser.parse_args(argv)

    for directory in (CONFIG_DIR, GATEWAY_ROOT / "logs", GATEWAY_ROOT / "trash", WEB_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    oauth = OAuthProvider(CONFIG_DIR)
    mcp_server = MCPServer((args.mcp_host, args.mcp_port), oauth)
    console_server = ConsoleServer(("127.0.0.1", args.console_port), args.mcp_port, oauth)

    console_url = f"http://127.0.0.1:{args.console_port}/"
    (CONFIG_DIR / "console-url.txt").write_text(console_url + "\n", encoding="utf-8")

    print(f"[gateway] MCP      : http://{args.mcp_host}:{args.mcp_port}/mcp （OAuth 2.1 + PKCE）", file=sys.stderr)
    print(f"[gateway] 控制台   : {console_url}", file=sys.stderr)
    print(f"[gateway] 授权路径 : {len(POLICY.roots())} 条，工具 {len(tools.TOOL_DEFS)} 个", file=sys.stderr)
    fileops.audit("gateway_started", {"mcp_port": args.mcp_port, "console_port": args.console_port, "auth": "oauth2.1"})

    threading.Thread(target=mcp_server.serve_forever, name="mcp", daemon=True).start()
    threading.Thread(target=console_server.serve_forever, name="console", daemon=True).start()

    if args.open:
        threading.Timer(1.0, lambda: webbrowser.open(console_url)).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[gateway] 正在停止……", file=sys.stderr)
    finally:
        mcp_server.shutdown()
        console_server.shutdown()
        mcp_server.server_close()
        console_server.server_close()
        fileops.audit("gateway_stopped", {})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
