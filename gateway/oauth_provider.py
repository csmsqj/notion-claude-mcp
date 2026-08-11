# -*- coding: utf-8 -*-
"""Small OAuth 2.1 provider for the local MCP gateway.

The public MCP endpoint uses Authorization Code + PKCE, dynamic client
registration, short-lived access tokens, and rotating refresh tokens.  The
only interactive approval happens on the gateway computer in a native dialog;
there is no long-lived bearer token for a user to copy into an MCP client.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

ACCESS_TOKEN_TTL_SECONDS = 15 * 60
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60
CONSENT_TTL_SECONDS = 120
MAX_BODY_BYTES = 16 * 1024
MAX_REDIRECT_URIS = 10
MAX_CLIENTS = 256
MAX_CODES = 128
MAX_REQUESTS = 32
MAX_USED_REFRESH_TOKENS = 4096
SUPPORTED_GRANTS = ("authorization_code", "refresh_token")
SUPPORTED_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status

    def payload(self) -> dict[str, str]:
        return {"error": self.error, "error_description": self.description}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _first(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key, "")
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "")


def _optional_text(value: Any, maximum: int) -> str:
    return str(value).strip()[:maximum] if isinstance(value, str) and value.strip() else ""


def _append_query(uri: str, values: dict[str, str]) -> str:
    parts = urllib.parse.urlsplit(uri)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.extend((key, value) for key, value in values.items() if value != "")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), ""))


def validate_redirect_uris(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_REDIRECT_URIS:
        raise OAuthError("invalid_client_metadata", f"redirect_uris must contain 1-{MAX_REDIRECT_URIS} entries")
    redirects: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 2048:
            raise OAuthError("invalid_client_metadata", "redirect_uri must be a string of at most 2048 characters")
        parsed = urllib.parse.urlsplit(item)
        if parsed.fragment or not parsed.scheme or not parsed.netloc or not parsed.hostname:
            raise OAuthError("invalid_client_metadata", "redirect_uri must be absolute and must not contain a fragment")
        if parsed.username is not None or parsed.password is not None:
            raise OAuthError("invalid_client_metadata", "redirect_uri must not contain user information")
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise OAuthError("invalid_client_metadata", "HTTP redirect_uri is allowed only for loopback hosts")
        if parsed.scheme not in {"http", "https"}:
            raise OAuthError("invalid_client_metadata", "redirect_uri must use HTTPS or loopback HTTP")
        redirects.append(item)
    if len(set(redirects)) != len(redirects):
        raise OAuthError("invalid_client_metadata", "redirect_uris must be unique")
    return tuple(redirects)


def _redirect_uri_matches(registered: str, requested: str) -> bool:
    """RFC 8252 permits a loopback redirect to use an ephemeral port."""
    if registered == requested:
        return True
    try:
        left = urllib.parse.urlsplit(registered)
        right = urllib.parse.urlsplit(requested)
        loopback = {"localhost", "127.0.0.1", "::1"}
        return (
            left.scheme == "http"
            and right.scheme == "http"
            and (left.hostname or "").lower() in loopback
            and (left.hostname or "").lower() == (right.hostname or "").lower()
            and left.path == right.path
            and left.query == right.query
            and not left.fragment
            and not right.fragment
        )
    except ValueError:
        return False


def _valid_pkce_challenge(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is not None


def _verify_pkce(verifier: str, challenge: str) -> bool:
    if re.fullmatch(r"[A-Za-z0-9\-._~]{43,128}", verifier) is None:
        return False
    expected = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return hmac.compare_digest(expected, challenge)


class OAuthProvider:
    """Thread-safe, persistent OAuth state plus ephemeral codes/consent requests."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.config_dir / "oauth-state.json"
        self.key_file = self.config_dir / "oauth-signing-key.txt"
        self.popup_script = self.config_dir.parent.parent / "runtime-patches" / "oauth-consent.ps1"
        self._lock = threading.RLock()
        self._popup_lock = threading.Lock()
        self._clients: dict[str, dict[str, Any]] = {}
        self._refresh_tokens: dict[str, dict[str, Any]] = {}
        self._used_refresh_tokens: dict[str, dict[str, Any]] = {}
        self._codes: dict[str, dict[str, Any]] = {}
        self._requests: dict[str, dict[str, Any]] = {}
        self._signing_key = self._load_or_create_key()
        self._load_state()

    # ---------------- persistent state ----------------
    def _load_or_create_key(self) -> bytes:
        try:
            raw = self.key_file.read_text(encoding="ascii").strip()
            key = bytes.fromhex(raw)
            if len(key) >= 32:
                return key
        except (OSError, ValueError):
            pass
        key = secrets.token_bytes(32)
        self.key_file.write_text(key.hex() + "\n", encoding="ascii")
        try:
            os.chmod(self.key_file, 0o600)
        except OSError:
            pass
        return key

    def _load_state(self) -> None:
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        clients = payload.get("clients", {}) if isinstance(payload, dict) else {}
        refresh = payload.get("refresh_tokens", {}) if isinstance(payload, dict) else {}
        used_refresh = payload.get("used_refresh_tokens", {}) if isinstance(payload, dict) else {}
        if isinstance(clients, dict):
            self._clients = {str(k): v for k, v in clients.items() if isinstance(v, dict)}
        if isinstance(refresh, dict):
            self._refresh_tokens = {str(k): v for k, v in refresh.items() if isinstance(v, dict)}
        if isinstance(used_refresh, dict):
            self._used_refresh_tokens = {str(k): v for k, v in used_refresh.items() if isinstance(v, dict)}
        with self._lock:
            self._cleanup_locked()
            self._save_state_locked()

    def _save_state_locked(self) -> None:
        payload = {
            "version": 2,
            "clients": self._clients,
            "refresh_tokens": self._refresh_tokens,
            "used_refresh_tokens": self._used_refresh_tokens,
        }
        temporary = self.state_file.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.state_file)
        try:
            os.chmod(self.state_file, 0o600)
        except OSError:
            pass

    def _cleanup_locked(self) -> None:
        now = time.time()
        self._refresh_tokens = {
            key: value for key, value in self._refresh_tokens.items()
            if float(value.get("expires_at", 0)) > now
        }
        self._used_refresh_tokens = {
            key: value for key, value in self._used_refresh_tokens.items()
            if float(value.get("expires_at", 0)) > now
        }
        if len(self._used_refresh_tokens) > MAX_USED_REFRESH_TOKENS:
            ordered_used = sorted(
                self._used_refresh_tokens,
                key=lambda key: float(self._used_refresh_tokens[key].get("used_at", 0)),
            )
            for key in ordered_used[: len(self._used_refresh_tokens) - MAX_USED_REFRESH_TOKENS]:
                self._used_refresh_tokens.pop(key, None)
        self._codes = {
            key: value for key, value in self._codes.items()
            if float(value.get("expires_at", 0)) > now
        }
        for request in self._requests.values():
            if request.get("status") == "pending" and float(request.get("expires_at", 0)) <= now:
                request["status"] = "denied"
                request["message"] = "Authorization request expired."
                request["redirect"] = _append_query(
                    str(request.get("redirect_uri") or ""),
                    {"error": "access_denied", "error_description": "Authorization request expired", "state": str(request.get("state") or "")},
                )
        if len(self._requests) > MAX_REQUESTS:
            ordered = sorted(self._requests.items(), key=lambda item: float(item[1].get("created_at", 0)))
            for key, _value in ordered[: len(self._requests) - MAX_REQUESTS]:
                self._requests.pop(key, None)

    # ---------------- metadata and registration ----------------
    @staticmethod
    def authorization_server_metadata(issuer: str) -> dict[str, Any]:
        issuer = issuer.rstrip("/")
        return {
            "issuer": issuer,
            "authorization_endpoint": issuer + "/oauth/authorize",
            "token_endpoint": issuer + "/oauth/token",
            "registration_endpoint": issuer + "/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": list(SUPPORTED_GRANTS),
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": list(SUPPORTED_AUTH_METHODS),
            "scopes_supported": ["mcp"],
            "client_id_metadata_document_supported": False,
        }

    @staticmethod
    def protected_resource_metadata(resource: str, issuer: str) -> dict[str, Any]:
        return {
            "resource": resource.rstrip("/"),
            "authorization_servers": [issuer.rstrip("/")],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
            "resource_name": "Local file MCP gateway",
        }

    def register(self, metadata: dict[str, Any]) -> dict[str, Any]:
        redirects = validate_redirect_uris(metadata.get("redirect_uris"))
        raw_grants = metadata.get("grant_types", ["authorization_code", "refresh_token"])
        raw_responses = metadata.get("response_types", ["code"])
        if not isinstance(raw_grants, list) or not all(isinstance(item, str) for item in raw_grants):
            raise OAuthError("invalid_client_metadata", "grant_types must be an array of strings")
        if "authorization_code" not in raw_grants:
            raise OAuthError("invalid_client_metadata", "grant_types must include authorization_code")
        if any(item not in SUPPORTED_GRANTS for item in raw_grants):
            raise OAuthError("invalid_client_metadata", "grant_types contains an unsupported value")
        if not isinstance(raw_responses, list) or "code" not in raw_responses:
            raise OAuthError("invalid_client_metadata", "response_types must include code")
        method = str(metadata.get("token_endpoint_auth_method") or "none")
        if method not in SUPPORTED_AUTH_METHODS:
            raise OAuthError("invalid_client_metadata", "unsupported token_endpoint_auth_method")
        now = int(time.time())
        client_id = secrets.token_urlsafe(24)
        client_secret = secrets.token_urlsafe(32) if method != "none" else ""
        client = {
            "redirect_uris": list(redirects),
            "grant_types": [item for item in SUPPORTED_GRANTS if item in raw_grants],
            "token_endpoint_auth_method": method,
            "client_name": _optional_text(metadata.get("client_name"), 200),
            "secret_digest": _digest(client_secret) if client_secret else "",
            "issued_at": now,
        }
        with self._lock:
            self._cleanup_locked()
            if len(self._clients) >= MAX_CLIENTS:
                active_clients = {str(item.get("client_id") or "") for item in self._refresh_tokens.values()}
                removable = sorted(
                    ((cid, info) for cid, info in self._clients.items() if cid not in active_clients),
                    key=lambda item: int(item[1].get("issued_at", 0)),
                )
                if not removable:
                    raise OAuthError("invalid_client_metadata", "dynamic client registration limit reached", 503)
                self._clients.pop(removable[0][0], None)
            self._clients[client_id] = client
            self._save_state_locked()
        response: dict[str, Any] = {
            "client_id": client_id,
            "client_id_issued_at": now,
            "redirect_uris": list(redirects),
            "grant_types": list(client["grant_types"]),
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        }
        if client["client_name"]:
            response["client_name"] = client["client_name"]
        if client_secret:
            response["client_secret"] = client_secret
            response["client_secret_expires_at"] = 0
        return response

    # ---------------- authorization and local consent ----------------
    def begin_authorization(self, params: dict[str, Any], issuer: str, resource: str) -> dict[str, Any]:
        issuer = issuer.rstrip("/")
        resource = resource.rstrip("/")
        client_id = _first(params, "client_id")
        redirect_uri = _first(params, "redirect_uri")
        response_type = _first(params, "response_type")
        challenge = _first(params, "code_challenge")
        challenge_method = _first(params, "code_challenge_method")
        state = _first(params, "state")
        requested_resource = _first(params, "resource").rstrip("/")
        requested_scope = _first(params, "scope")
        if response_type != "code":
            raise OAuthError("unsupported_response_type", "response_type must be code")
        with self._lock:
            client = self._clients.get(client_id)
            if client is None:
                raise OAuthError("invalid_request", "unknown client_id")
            if not any(_redirect_uri_matches(item, redirect_uri) for item in client.get("redirect_uris", [])):
                raise OAuthError("invalid_request", "redirect_uri is not registered for this client")
        if challenge_method != "S256" or not _valid_pkce_challenge(challenge):
            raise OAuthError("invalid_request", "PKCE S256 code_challenge is required")
        if requested_resource and requested_resource != resource:
            raise OAuthError("invalid_target", "resource does not identify this MCP endpoint")
        if requested_scope and any(item != "mcp" for item in requested_scope.split()):
            raise OAuthError("invalid_scope", "only the mcp scope is supported")
        if len(state) > 2048:
            raise OAuthError("invalid_request", "state is too long")

        with self._lock:
            self._cleanup_locked()
            active = [item for item in self._requests.values() if item.get("status") == "pending"]
            if active:
                raise OAuthError("temporarily_unavailable", "another local authorization confirmation is already open", 429)
            request_id = secrets.token_urlsafe(24)
            request = {
                "id": request_id,
                "client_id": client_id,
                "client_name": client.get("client_name") or "OAuth client",
                "redirect_uri": redirect_uri,
                "code_challenge": challenge,
                "state": state,
                "scope": "mcp",
                "resource": resource,
                "issuer": issuer,
                "status": "pending",
                "message": "Waiting for approval on the gateway computer.",
                "created_at": time.time(),
                "expires_at": time.time() + CONSENT_TTL_SECONDS,
            }
            self._requests[request_id] = request
        self._launch_local_consent(request_id)
        return self.authorization_status(request_id)

    def authorization_error_redirect(self, params: dict[str, Any], exc: OAuthError) -> str:
        """Return a safe OAuth error callback only for a known client/redirect."""
        client_id = _first(params, "client_id")
        redirect_uri = _first(params, "redirect_uri")
        state = _first(params, "state")
        with self._lock:
            client = self._clients.get(client_id)
        if client is None or not any(
            _redirect_uri_matches(item, redirect_uri) for item in client.get("redirect_uris", [])
        ):
            return ""
        return _append_query(
            redirect_uri,
            {"error": exc.error, "error_description": exc.description, "state": state},
        )

    def _launch_local_consent(self, request_id: str) -> None:
        if os.name != "nt" or not self.popup_script.is_file():
            with self._lock:
                request = self._requests.get(request_id)
                if request and request.get("status") == "pending":
                    request["message"] = "The local dialog is unavailable; approve or deny this request in the local console."
            return
        if not self._popup_lock.acquire(blocking=False):
            with self._lock:
                request = self._requests.get(request_id)
                if request and request.get("status") == "pending":
                    request["message"] = "Another local dialog is open; approve or deny this request in the local console."
            return
        with self._lock:
            request = dict(self._requests.get(request_id) or {})
        out_file = Path(tempfile.gettempdir()) / f"local-mcp-oauth-{os.getpid()}-{request_id}.json"
        command = [
            "powershell.exe", "-STA", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(self.popup_script),
            "-OutFile", str(out_file),
            "-ClientName", str(request.get("client_name") or "OAuth client"),
            "-RedirectUri", str(request.get("redirect_uri") or ""),
            "-RequestId", request_id,
            "-TimeoutSeconds", str(CONSENT_TTL_SECONDS),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError:
            self._popup_lock.release()
            with self._lock:
                current = self._requests.get(request_id)
                if current and current.get("status") == "pending":
                    current["message"] = "Could not open the local dialog; approve or deny this request in the local console."
            return
        threading.Thread(
            target=self._watch_consent,
            args=(request_id, process, out_file),
            name=f"oauth-consent-{request_id}",
            daemon=True,
        ).start()

    def _watch_consent(self, request_id: str, process: subprocess.Popen[Any], out_file: Path) -> None:
        decision = ""
        try:
            deadline = time.time() + CONSENT_TTL_SECONDS + 20
            while time.time() < deadline:
                if out_file.exists():
                    try:
                        data = json.loads(out_file.read_text(encoding="utf-8"))
                        decision = str(data.get("decision") or "")
                    except (OSError, json.JSONDecodeError):
                        decision = ""
                    if decision:
                        break
                if process.poll() is not None:
                    break
                time.sleep(0.25)
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass
            self.decide_authorization(request_id, decision == "approve")
        finally:
            try:
                out_file.unlink(missing_ok=True)
            except OSError:
                pass
            self._popup_lock.release()

    def decide_authorization(self, request_id: str, approve: bool) -> dict[str, Any]:
        with self._lock:
            self._cleanup_locked()
            request = self._requests.get(request_id)
            if request is None:
                raise OAuthError("invalid_request", "authorization request not found", 404)
            if request.get("status") != "pending":
                return self.authorization_status(request_id)
            if not approve:
                request["status"] = "denied"
                request["message"] = "Authorization was denied on the gateway computer."
                request["redirect"] = _append_query(
                    request["redirect_uri"],
                    {"error": "access_denied", "state": request.get("state", "")},
                )
                return self.authorization_status(request_id)
            code = secrets.token_urlsafe(32)
            while code in self._codes:
                code = secrets.token_urlsafe(32)
            if len(self._codes) >= MAX_CODES:
                oldest = min(self._codes, key=lambda key: float(self._codes[key].get("created_at", 0)))
                self._codes.pop(oldest, None)
            self._codes[code] = {
                "client_id": request["client_id"],
                "redirect_uri": request["redirect_uri"],
                "code_challenge": request["code_challenge"],
                "resource": request["resource"],
                "issuer": request["issuer"],
                "scope": request["scope"],
                "created_at": time.time(),
                "expires_at": time.time() + AUTHORIZATION_CODE_TTL_SECONDS,
            }
            request["status"] = "approved"
            request["message"] = "Approved. Returning to the OAuth client."
            request["redirect"] = _append_query(
                request["redirect_uri"],
                {"code": code, "state": request.get("state", "")},
            )
            return self.authorization_status(request_id)

    def authorization_status(self, request_id: str) -> dict[str, Any]:
        with self._lock:
            self._cleanup_locked()
            request = self._requests.get(request_id)
            if request is None:
                raise OAuthError("invalid_request", "authorization request not found", 404)
            return {
                "ok": True,
                "id": request_id,
                "status": request.get("status", "error"),
                "message": request.get("message", ""),
                "client_name": request.get("client_name", "OAuth client"),
                "redirect_uri": request.get("redirect_uri", ""),
                "redirect": request.get("redirect", ""),
                "seconds_left": max(0, int(float(request.get("expires_at", 0)) - time.time())),
            }

    def list_requests(self) -> list[dict[str, Any]]:
        with self._lock:
            self._cleanup_locked()
            ordered = sorted(self._requests, key=lambda key: float(self._requests[key].get("created_at", 0)), reverse=True)
            return [self.authorization_status(key) for key in ordered[:20]]

    # ---------------- token endpoint ----------------
    def _authenticate_client(self, params: dict[str, Any], authorization: str) -> tuple[str, dict[str, Any]]:
        client_id = _first(params, "client_id")
        client_secret = _first(params, "client_secret")
        presented_method = "client_secret_post" if client_secret else "none"
        if authorization.startswith("Basic "):
            try:
                decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
                basic_id, separator, basic_secret = decoded.partition(":")
                if not separator:
                    raise ValueError("missing separator")
                client_id = urllib.parse.unquote(basic_id)
                client_secret = urllib.parse.unquote(basic_secret)
                presented_method = "client_secret_basic"
            except (ValueError, UnicodeDecodeError):
                raise OAuthError("invalid_client", "invalid HTTP Basic client credentials", 401)
        with self._lock:
            client = self._clients.get(client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id", 401)
        method = str(client.get("token_endpoint_auth_method") or "none")
        if method != presented_method:
            raise OAuthError("invalid_client", "wrong token endpoint authentication method", 401)
        expected_digest = str(client.get("secret_digest") or "")
        if method == "none":
            if client_secret:
                raise OAuthError("invalid_client", "public client must not send a client_secret", 401)
        elif not client_secret or not hmac.compare_digest(expected_digest, _digest(client_secret)):
            raise OAuthError("invalid_client", "invalid client_secret", 401)
        return client_id, client

    def token(self, params: dict[str, Any], authorization: str, issuer: str, resource: str) -> dict[str, Any]:
        issuer = issuer.rstrip("/")
        resource = resource.rstrip("/")
        client_id, client = self._authenticate_client(params, authorization)
        grant_type = _first(params, "grant_type")
        grants = client.get("grant_types") or list(SUPPORTED_GRANTS)
        if grant_type not in grants:
            raise OAuthError("unauthorized_client", "client is not registered for this grant type")
        requested_resource = _first(params, "resource").rstrip("/")
        if requested_resource and requested_resource != resource:
            raise OAuthError("invalid_target", "resource does not identify this MCP endpoint")
        if grant_type == "authorization_code":
            return self._exchange_code(params, client_id, issuer, resource, "refresh_token" in grants)
        if grant_type == "refresh_token":
            return self._exchange_refresh(params, client_id, issuer, resource)
        raise OAuthError("unsupported_grant_type", "supported grants are authorization_code and refresh_token")

    def _exchange_code(self, params: dict[str, Any], client_id: str, issuer: str, resource: str, issue_refresh: bool) -> dict[str, Any]:
        code = _first(params, "code")
        redirect_uri = _first(params, "redirect_uri")
        verifier = _first(params, "code_verifier")
        if not code or not verifier:
            raise OAuthError("invalid_grant", "code and code_verifier are required")
        with self._lock:
            self._cleanup_locked()
            code_data = self._codes.pop(code, None)
        if code_data is None:
            raise OAuthError("invalid_grant", "authorization code is unknown, expired, or already used")
        if not hmac.compare_digest(str(code_data.get("client_id") or ""), client_id):
            raise OAuthError("invalid_grant", "client_id mismatch")
        if not hmac.compare_digest(str(code_data.get("redirect_uri") or ""), redirect_uri):
            raise OAuthError("invalid_grant", "redirect_uri mismatch")
        if code_data.get("issuer") != issuer or code_data.get("resource") != resource:
            raise OAuthError("invalid_target", "authorization code was issued for another resource")
        if not _verify_pkce(verifier, str(code_data.get("code_challenge") or "")):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        return self._issue_tokens(
            client_id,
            issuer,
            resource,
            str(code_data.get("scope") or "mcp"),
            issue_refresh=issue_refresh,
        )

    def _exchange_refresh(self, params: dict[str, Any], client_id: str, issuer: str, resource: str) -> dict[str, Any]:
        raw_token = _first(params, "refresh_token")
        if not raw_token:
            raise OAuthError("invalid_grant", "refresh_token is required")
        token_digest = _digest(raw_token)
        with self._lock:
            self._cleanup_locked()
            token_data = self._refresh_tokens.pop(token_digest, None)
            if token_data is None:
                replay = self._used_refresh_tokens.get(token_digest)
                if replay is not None:
                    family_id = str(replay.get("family_id") or "")
                    self._refresh_tokens = {
                        key: value
                        for key, value in self._refresh_tokens.items()
                        if not family_id or value.get("family_id") != family_id
                    }
                    self._save_state_locked()
                    raise OAuthError("invalid_grant", "refresh token replay detected; token family revoked")
                raise OAuthError("invalid_grant", "refresh token is unknown, expired, or already used")
            if token_data.get("client_id") != client_id:
                self._save_state_locked()
                raise OAuthError("invalid_grant", "refresh token client mismatch")
            if token_data.get("issuer") != issuer or token_data.get("resource") != resource:
                self._save_state_locked()
                raise OAuthError("invalid_target", "refresh token was issued for another resource")
            requested_scope = _first(params, "scope")
            scope = str(token_data.get("scope") or "mcp")
            if requested_scope and requested_scope != scope:
                self._save_state_locked()
                raise OAuthError("invalid_scope", "refresh cannot expand or change scope")
            family_id = str(token_data.get("family_id") or secrets.token_urlsafe(18))
            self._used_refresh_tokens[token_digest] = {
                "family_id": family_id,
                "used_at": int(time.time()),
                "expires_at": int(token_data.get("expires_at") or time.time() + REFRESH_TOKEN_TTL_SECONDS),
            }
            return self._issue_tokens(client_id, issuer, resource, scope, family_id=family_id)

    def _issue_tokens(
        self,
        client_id: str,
        issuer: str,
        resource: str,
        scope: str,
        *,
        issue_refresh: bool = True,
        family_id: str = "",
    ) -> dict[str, Any]:
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
        claims = {
            "iss": issuer,
            "aud": resource,
            "sub": client_id,
            "client_id": client_id,
            "scope": scope,
            "iat": now,
            "exp": now + ACCESS_TOKEN_TTL_SECONDS,
            "jti": secrets.token_urlsafe(12),
        }
        payload = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = _b64url(hmac.new(self._signing_key, signing_input, hashlib.sha256).digest())
        access_token = f"{header}.{payload}.{signature}"
        if not issue_refresh:
            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECONDS,
                "scope": scope,
            }
        refresh_token = secrets.token_urlsafe(48)
        family_id = family_id or secrets.token_urlsafe(18)
        with self._lock:
            self._refresh_tokens[_digest(refresh_token)] = {
                "client_id": client_id,
                "issuer": issuer,
                "resource": resource,
                "scope": scope,
                "family_id": family_id,
                "created_at": now,
                "expires_at": now + REFRESH_TOKEN_TTL_SECONDS,
            }
            self._save_state_locked()
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            "refresh_token": refresh_token,
            "scope": scope,
        }

    def validate_access_token(self, token: str, issuer: str, resource: str) -> bool:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
            signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
            expected = hmac.new(self._signing_key, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64url(encoded_signature)):
                return False
            header = json.loads(_unb64url(encoded_header).decode("utf-8"))
            claims = json.loads(_unb64url(encoded_payload).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        now = int(time.time())
        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            return False
        if claims.get("iss") != issuer.rstrip("/") or claims.get("aud") != resource.rstrip("/"):
            return False
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= now:
            return False
        if not isinstance(claims.get("iat"), int) or claims["iat"] > now + 60:
            return False
        if "mcp" not in str(claims.get("scope") or "").split():
            return False
        client_id = claims.get("client_id")
        with self._lock:
            return isinstance(client_id, str) and client_id in self._clients

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._cleanup_locked()
            return {
                "enabled": True,
                "mode": "oauth2.1",
                "pkce": "S256",
                "dynamic_client_registration": True,
                "access_token_ttl_seconds": ACCESS_TOKEN_TTL_SECONDS,
                "refresh_token_ttl_seconds": REFRESH_TOKEN_TTL_SECONDS,
                "registered_clients": len(self._clients),
                "pending_authorizations": sum(1 for item in self._requests.values() if item.get("status") == "pending"),
                "legacy_static_token_enabled": False,
            }

    # ---------------- browser pages ----------------
    @staticmethod
    def waiting_page(info: dict[str, Any]) -> str:
        request_id = html.escape(str(info.get("id") or ""), quote=True)
        client_name = html.escape(str(info.get("client_name") or "OAuth client"))
        redirect_uri = html.escape(str(info.get("redirect_uri") or ""))
        return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>授权本地文件 MCP 网关</title>
<style>
:root{{--blue:#2783de;--line:#e6e5e3;--muted:#78756f;--text:#2c2c2b;--soft:#f7f7f5}}
*{{box-sizing:border-box}}body{{margin:0;background:#fff;color:var(--text);font:14px/1.65 system-ui,"Microsoft YaHei",sans-serif}}
main{{max-width:560px;margin:10vh auto;padding:24px}}.mark{{width:48px;height:48px;border-radius:14px;display:grid;place-items:center;background:#edf6ff;color:var(--blue);font-size:24px}}
.card{{margin-top:20px;border:1px solid var(--line);border-radius:14px;padding:24px;box-shadow:0 10px 30px rgba(30,35,40,.07)}}h1{{font-size:22px;margin:16px 0 6px}}p{{margin:8px 0;color:var(--muted)}}code{{display:block;padding:10px 12px;background:var(--soft);border-radius:8px;word-break:break-all;color:var(--text)}}
.status{{display:flex;gap:10px;align-items:center;margin-top:20px;padding:12px 14px;border-radius:9px;background:#edf6ff;color:#1769aa}}.dot{{width:9px;height:9px;border-radius:50%;background:var(--blue);box-shadow:0 0 0 5px rgba(39,131,222,.12)}}
small{{display:block;margin-top:16px;color:#99958f}}
</style></head><body><main><div class="mark">✓</div><h1>在本机确认 OAuth 授权</h1>
<p><b>{client_name}</b> 正在请求连接本地文件网关。</p><div class="card"><p>回调地址</p><code>{redirect_uri}</code>
<div class="status"><span class="dot"></span><span id="status">请在运行网关的 Windows 电脑上点击“允许连接”或“拒绝”。</span></div>
<small>页面会在确认后自动返回 MCP 客户端。请勿关闭此页。</small></div></main>
<script>
const id={json.dumps(request_id)};const status=document.getElementById('status');
async function poll(){{try{{const r=await fetch('/oauth/status?request='+encodeURIComponent(id),{{cache:'no-store'}});const d=await r.json();if(d.redirect){{location.replace(d.redirect);return}}status.textContent=d.message||'正在等待本机确认…';if(d.status==='error'||d.status==='denied')return}}catch(e){{status.textContent='连接暂时中断，正在重试…'}}setTimeout(poll,900)}}poll();
</script></body></html>"""

    @staticmethod
    def error_page(error: str, description: str) -> str:
        return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OAuth 授权失败</title>
<style>body{{font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif;max-width:560px;margin:10vh auto;padding:24px;color:#2c2c2b}}div{{border:1px solid #e6e5e3;border-radius:12px;padding:22px}}h1{{font-size:21px}}code{{color:#c0392b}}</style></head>
<body><div><h1>无法完成 OAuth 授权</h1><p><code>{html.escape(error)}</code></p><p>{html.escape(description)}</p><p>请关闭此页并在 MCP 客户端中重试。</p></div></body></html>"""
