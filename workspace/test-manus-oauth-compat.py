# -*- coding: utf-8 -*-
"""Regression coverage for Manus OAuth and HTTP transport interoperability."""
from __future__ import annotations

import http.client
import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "gateway"
sys.path.insert(0, str(GATEWAY))

import server  # noqa: E402

TOKEN = "manus-test-token"


class StubOAuth:
    def validate_access_token(self, token: str, issuer: str, resource: str) -> bool:
        return token == TOKEN


def start_server() -> tuple[server.MCPServer, threading.Thread, str, int]:
    httpd = server.MCPServer(("127.0.0.1", 0), StubOAuth())
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    return httpd, thread, host, port


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, response_headers, payload
    finally:
        connection.close()


def test_manus_origin_and_authenticated_get() -> None:
    httpd, thread, host, port = start_server()
    try:
        status, headers, _ = request(
            host,
            port,
            "OPTIONS",
            "/mcp",
            headers={
                "Origin": "https://manus.im",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization,mcp-protocol-version,last-event-id",
            },
        )
        assert status == 204
        assert headers["access-control-allow-origin"] == "https://manus.im"
        assert "Last-Event-ID" in headers["access-control-allow-headers"]

        status, headers, payload = request(
            host,
            port,
            "GET",
            "/mcp",
            headers={
                "Accept": "text/event-stream",
                "Authorization": f"Bearer {TOKEN}",
            },
        )
        text = payload.decode("utf-8")
        assert status == 200, text
        assert headers["content-type"].startswith("text/event-stream")
        assert "event: endpoint\n" in text
        assert "data: http://" in text and text.rstrip().endswith("/mcp")
        assert TOKEN not in text
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_initialize_and_list_tools_after_get() -> None:
    httpd, thread, host, port = start_server()
    common = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
    }
    try:
        initialize = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "Manus", "version": "test"},
                },
            },
            separators=(",", ":"),
        )
        status, headers, payload = request(host, port, "POST", "/mcp", body=initialize, headers=common)
        result = json.loads(payload.decode("utf-8"))
        assert status == 200, result
        assert result["result"]["protocolVersion"] == "2025-03-26"
        session_id = headers.get("mcp-session-id", "")
        assert session_id

        initialized_headers = dict(common)
        initialized_headers["Mcp-Session-Id"] = session_id
        initialized = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            separators=(",", ":"),
        )
        status, _, payload = request(
            host,
            port,
            "POST",
            "/mcp",
            body=initialized,
            headers=initialized_headers,
        )
        assert status == 202 and payload == b""

        listed = json.dumps(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            separators=(",", ":"),
        )
        status, _, payload = request(
            host,
            port,
            "POST",
            "/mcp",
            body=listed,
            headers=initialized_headers,
        )
        result = json.loads(payload.decode("utf-8"))
        names = {item["name"] for item in result["result"]["tools"]}
        assert status == 200, result
        assert {"list_allowed_paths", "list_dir", "read_file"}.issubset(names)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    test_manus_origin_and_authenticated_get()
    test_initialize_and_list_tools_after_get()
    print("Manus OAuth compatibility tests passed")
