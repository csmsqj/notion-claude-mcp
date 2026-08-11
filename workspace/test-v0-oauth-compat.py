# -*- coding: utf-8 -*-
"""Regression coverage for v0/AI SDK OAuth discovery compatibility."""
from __future__ import annotations

import http.client
import json
import sys
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "gateway"
sys.path.insert(0, str(GATEWAY))

import server  # noqa: E402


class StubOAuth:
    def validate_access_token(self, token: str, issuer: str, resource: str) -> bool:
        return False

    def protected_resource_metadata(self, resource: str, issuer: str) -> dict[str, Any]:
        return {
            "resource": resource.rstrip("/"),
            "authorization_servers": [issuer.rstrip("/")],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
        }


def test_v0_protocol_negotiation() -> None:
    assert "2024-11-05" in server.SUPPORTED_PROTOCOL_VERSIONS
    handler = object.__new__(server.MCPHandler)
    reply = handler.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "v0.app", "version": "1.0.0"},
            },
        },
        "initialize",
        1,
    )
    assert reply is not None
    assert reply["result"]["protocolVersion"] == "2024-11-05"


def test_unauthorized_post_does_not_poison_oauth_discovery() -> None:
    httpd = server.MCPServer(("127.0.0.1", 0), StubOAuth())
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        initialize = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "v0.app", "version": "1.0.0"},
                },
            },
            separators=(",", ":"),
        )
        connection.request(
            "POST",
            "/mcp",
            body=initialize,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        rejected = connection.getresponse()
        rejected_body = rejected.read()
        assert rejected.status == 401, rejected_body
        assert rejected.getheader("Connection", "").lower() == "close"
        assert "resource_metadata=" in rejected.getheader("WWW-Authenticate", "")

        # HTTPConnection transparently opens a fresh socket after Connection:
        # close. Before the fix, this reused the poisoned socket and returned
        # 501 with a method resembling '{initialize-json}GET'.
        connection.request(
            "GET",
            "/.well-known/oauth-protected-resource/mcp",
            headers={"Accept": "application/json"},
        )
        discovered = connection.getresponse()
        payload = json.loads(discovered.read().decode("utf-8"))
        assert discovered.status == 200, payload
        assert payload["scopes_supported"] == ["mcp"]
        assert payload["authorization_servers"]
    finally:
        connection.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    test_v0_protocol_negotiation()
    test_unauthorized_post_does_not_poison_oauth_discovery()
    print("v0 OAuth compatibility tests passed")
