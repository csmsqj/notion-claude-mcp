# -*- coding: utf-8 -*-
"""Regression coverage for LobeHub MCP OAuth interoperability."""
from __future__ import annotations

import base64
import http.client
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GATEWAY = ROOT / "gateway"
sys.path.insert(0, str(GATEWAY))

import server  # noqa: E402
from oauth_provider import OAuthError, OAuthProvider  # noqa: E402


class StubOAuth:
    def validate_access_token(self, token: str, issuer: str, resource: str) -> bool:
        return False


def test_confidential_dcr_accepts_basic_or_post() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        provider = OAuthProvider(Path(temporary))
        registration = provider.register(
            {
                "redirect_uris": ["https://app.lobehub.com/oauth/connector/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_post",
                "client_name": "LobeHub",
            }
        )
        client_id = registration["client_id"]
        client_secret = registration["client_secret"]

        post_id, _ = provider._authenticate_client(
            {"client_id": [client_id], "client_secret": [client_secret]}, ""
        )
        assert post_id == client_id

        encoded = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        basic_id, _ = provider._authenticate_client({}, f"Basic {encoded}")
        assert basic_id == client_id

        try:
            provider._authenticate_client({"client_id": [client_id]}, "")
        except OAuthError as exc:
            assert exc.error == "invalid_client"
        else:
            raise AssertionError("confidential client was accepted without a secret")


def test_lobehub_preflight_is_allowed() -> None:
    httpd = server.MCPServer(("127.0.0.1", 0), StubOAuth())
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request(
            "OPTIONS",
            "/mcp",
            headers={
                "Origin": "https://app.lobehub.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type,mcp-protocol-version",
            },
        )
        response = connection.getresponse()
        response.read()
        assert response.status == 204
        assert response.getheader("Access-Control-Allow-Origin") == "https://app.lobehub.com"
    finally:
        connection.close()
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    test_confidential_dcr_accepts_basic_or_post()
    test_lobehub_preflight_is_allowed()
    print("LobeHub OAuth compatibility tests passed")
