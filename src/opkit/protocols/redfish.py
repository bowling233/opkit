"""Redfish protocol: a session-authenticated REST passthrough.

Redfish services are self-describing (``GET /redfish/v1`` returns the
service document, ``/Systems``, ``/Managers`` etc. lead anywhere from power
control to firmware), so opkit does not model Redfish semantics at all —
it manages the session and transports requests, exactly like the terminal
protocol manages PTYs. The agent explores the API itself:

    open_session(node1, protocol="redfish")
    redfish_request(node1, "GET", "/redfish/v1/Systems/1")

Session handling follows the DMTF spec: login POSTs credentials to
``/redfish/v1/SessionService/Sessions`` and receives an ``X-Auth-Token``
plus a session URL; every subsequent request carries the token; logout is
a DELETE of that URL. An expired token surfaces as HTTP 401 — one silent
re-login and retry is attempted per request.

TLS certificate verification is disabled project-wide; see tls_compat for
the legacy-cipher context that keeps old BMCs reachable.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from ..errors import ConfigError, ProtocolError
from .http import (
    MANAGED_REQUEST_HEADERS,
    HTTPResponseResult,
    build_rest_result,
    response_limit,
    split_endpoint,
    validate_relative_path,
    validate_request_headers,
)
from .tls_compat import compatible_ssl_context

if TYPE_CHECKING:
    from ..config import AccountConfig

# Module tunables (documented in README).
CONNECT_TIMEOUT_SECONDS = 10.0
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 2_000_000
SESSION_IDLE_TTL_SECONDS = 900.0
MAX_SESSION_LIFETIME_SECONDS = 3600.0
REAP_INTERVAL_SECONDS = 30.0

REDFISH_ROOT = "/redfish/v1"
LOGIN_PATH = f"{REDFISH_ROOT}/SessionService/Sessions"

# Everything auth-related belongs to this transport.
MANAGED_HEADERS = MANAGED_REQUEST_HEADERS | {"x-auth-token"}


@dataclass(frozen=True)
class RedfishProtocol:
    """Configuration for one ``redfish`` entry under a device."""

    endpoint: str
    scheme: str
    host: str
    port: int
    account: AccountConfig
    # Resolved login name: the protocol-level ``username`` overrides the
    # account's, so one credential account can serve devices that name
    # their users differently.
    username: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "account": self.account.name,
            "username": self.username,
            "tls_verification": False,
        }

    def brief(self) -> str:
        return self.endpoint


def parse_config(
    device_name: str,
    values: dict[str, Any],
    accounts: dict[str, AccountConfig],
) -> RedfishProtocol:
    """Build a :class:`RedfishProtocol` from raw YAML."""
    allowed = {"endpoint", "account", "username"}
    unknown = set(values) - allowed
    if unknown:
        raise ConfigError(
            f"redfish protocol for {device_name} has unknown keys: "
            f"{sorted(unknown)}"
        )
    scheme, host, port = split_endpoint(
        f"redfish protocol for {device_name}", values.get("endpoint")
    )
    account_name = values.get("account")
    if account_name is None:
        raise ConfigError(
            f"redfish protocol for {device_name} requires an account"
        )
    account = accounts.get(account_name)
    if account is None:
        raise ConfigError(
            f"redfish protocol for {device_name} references "
            f"unknown account: {account_name}"
        )
    username = values.get("username") or account.username
    if not username or not isinstance(username, str):
        raise ConfigError(
            f"redfish protocol for {device_name} requires a username "
            f"(protocol or account {account_name})"
        )
    if account.password is None:
        raise ConfigError(
            f"redfish protocol for {device_name}: account "
            f"{account.name} requires a password"
        )
    endpoint = f"{scheme}://{host}:{port}"
    return RedfishProtocol(
        endpoint=endpoint,
        scheme=scheme,
        host=host,
        port=port,
        account=account,
        username=username,
    )


class RedfishSession:
    """One authenticated Redfish service session on a BMC."""

    def __init__(self, device_name: str, protocol: RedfishProtocol) -> None:
        self.device_name = device_name
        self.protocol = protocol
        self.token: str | None = None
        self.session_url: str | None = None
        self.authenticated = False
        self.opened_at = time.time()
        self.last_activity_at = self.opened_at
        self._opened_monotonic = time.monotonic()
        self._last_activity_monotonic = self._opened_monotonic
        self._closed = False
        self._auth_lock = asyncio.Lock()
        self.client = httpx.AsyncClient(
            base_url=protocol.endpoint,
            verify=compatible_ssl_context(),
            timeout=httpx.Timeout(
                DEFAULT_REQUEST_TIMEOUT_SECONDS,
                connect=CONNECT_TIMEOUT_SECONDS,
            ),
            follow_redirects=False,
        )

    @property
    def alive(self) -> bool:
        return not self._closed

    def expired(self, now: float) -> bool:
        return (
            now - self._last_activity_monotonic >= SESSION_IDLE_TTL_SECONDS
            or now - self._opened_monotonic >= MAX_SESSION_LIFETIME_SECONDS
        )

    def _touch(self) -> None:
        self._last_activity_monotonic = time.monotonic()
        self.last_activity_at = time.time()

    async def ensure_authenticated(self) -> None:
        if self.authenticated:
            return
        async with self._auth_lock:
            if self.authenticated:
                return
            await self._login()

    async def _login(self) -> None:
        account = self.protocol.account
        try:
            response = await self.client.post(
                LOGIN_PATH,
                json={"UserName": self.protocol.username, "Password": account.password},
            )
        except httpx.HTTPError as exc:
            raise ProtocolError(
                f"Redfish login failed on {self.device_name}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if response.status_code != 201:
            raise ProtocolError(
                f"Redfish authentication failed for {self.device_name}: "
                f"HTTP {response.status_code} {_error_message(response)}"
            )
        token = response.headers.get("X-Auth-Token")
        if not token:
            raise ProtocolError(
                f"Redfish service on {self.device_name} issued no X-Auth-Token"
            )
        location = response.headers.get("Location")
        self.session_url = (
            urljoin(f"{self.protocol.endpoint}/", location) if location else None
        )
        self.token = token
        self.authenticated = True

    async def relogin(self) -> None:
        self.authenticated = False
        self.token = None
        self.session_url = None
        await self.ensure_authenticated()

    async def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        body_base64: str | None = None,
        form: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        limit_bytes: int | None = None,
    ) -> HTTPResponseResult:
        method = method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ProtocolError(f"unsupported HTTP method: {method}")
        validate_relative_path(path)
        supplied_bodies = sum(
            value is not None for value in (body, body_base64, form, json_body)
        )
        if supplied_bodies > 1:
            raise ProtocolError(
                "provide only one of body, body_base64, form, or json_body"
            )

        clean_headers = validate_request_headers(headers or {}, MANAGED_HEADERS)
        if body_base64 is not None:
            try:
                content: bytes | None = base64.b64decode(body_base64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ProtocolError("body_base64 is not valid base64") from exc
        elif body is not None:
            content = body.encode("utf-8")
        elif json_body is not None:
            content = json.dumps(json_body).encode("utf-8")
            clean_headers.setdefault("content-type", "application/json")
        else:
            content = None

        await self.ensure_authenticated()
        self._touch()
        started = time.monotonic()
        response = await self._send(
            method,
            path,
            query=query,
            headers=clean_headers,
            content=content,
            form=form,
            timeout_seconds=timeout_seconds,
        )
        if response.status_code == 401:
            # Token expired server-side; re-login once and retry.
            await self.relogin()
            response = await self._send(
                method,
                path,
                query=query,
                headers=clean_headers,
                content=content,
                form=form,
                timeout_seconds=timeout_seconds,
            )
        self._touch()
        return build_rest_result(
            response=response,
            device=self.device_name,
            method=method,
            path=path,
            started=started,
            limit=response_limit(limit_bytes),
        )

    async def _send(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str | list[str]] | None,
        headers: dict[str, str],
        content: bytes | None,
        form: dict[str, str] | None,
        timeout_seconds: float | None,
    ) -> httpx.Response:
        assert self.token is not None
        prepared_headers = {"x-auth-token": self.token, **headers}
        request_options: dict[str, object] = {
            "params": query,
            "headers": prepared_headers,
            "content": content,
            "data": form,
        }
        if timeout_seconds is not None:
            request_options["timeout"] = timeout_seconds
        try:
            return await self.client.request(method, path, **request_options)
        except httpx.HTTPError as exc:
            raise ProtocolError(
                f"Redfish request failed on {self.device_name}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def public_info(self) -> dict[str, Any]:
        return {
            "device": self.device_name,
            "connection_state": "open" if self.alive else "closed",
            "authenticated": self.authenticated,
            "opened_at": self.opened_at,
            "last_activity_at": self.last_activity_at,
        }

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.authenticated and self.session_url is not None:
                assert self.token is not None
                await self.client.delete(
                    self.session_url, headers={"X-Auth-Token": self.token}
                )
        except httpx.HTTPError:
            pass
        finally:
            await self.client.aclose()


def _error_message(response: httpx.Response) -> str:
    """Extract a Redfish extended error message, falling back to raw text."""
    try:
        payload = response.json()
        message = payload["error"]["message"]
        if isinstance(message, str):
            return message
    except (ValueError, KeyError, TypeError):
        pass
    text = response.text.strip()
    return text[:200] if text else ""


class RedfishManager:
    """Owns at most one Redfish session per device."""

    def __init__(self) -> None:
        self._sessions: dict[str, RedfishSession] = {}
        self._lock = asyncio.Lock()
        self._reaper_task: asyncio.Task[None] | None = None

    def _protocol_of(self, config: Any, device_name: str) -> RedfishProtocol:
        protocol = config.device_protocol(device_name, "redfish")
        if not isinstance(protocol, RedfishProtocol):
            raise ProtocolError(f"device {device_name} does not support redfish")
        return protocol

    async def _session_for(self, config: Any, device_name: str) -> RedfishSession:
        self._protocol_of(config, device_name)
        async with self._lock:
            existing = self._sessions.get(device_name)
            if existing is not None and existing.alive:
                return existing
            stale = existing
            session = RedfishSession(
                device_name,
                self._protocol_of(config, device_name),
            )
            self._sessions[device_name] = session
        if stale is not None:
            await stale.close()
        return session

    async def request(
        self,
        config: Any,
        device_name: str,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> HTTPResponseResult:
        session = await self._session_for(config, device_name)
        result = await session.request(method, path, **kwargs)
        self._ensure_reaper()
        return result

    async def open(self, config: Any, device_name: str) -> dict[str, Any]:
        """Login eagerly so open_session doubles as a credential probe."""
        session = await self._session_for(config, device_name)
        try:
            await session.ensure_authenticated()
        except Exception:
            async with self._lock:
                if self._sessions.get(device_name) is session:
                    self._sessions.pop(device_name, None)
            raise
        self._ensure_reaper()
        return session.public_info()

    async def status_of(self, config: Any, device_name: str) -> dict[str, Any]:
        self._protocol_of(config, device_name)
        async with self._lock:
            session = self._sessions.get(device_name)
        if session is None:
            return {
                "device": device_name,
                "connection_state": "closed",
                "authenticated": False,
                "opened_at": None,
                "last_activity_at": None,
            }
        return session.public_info()

    async def occupied(self, device_name: str) -> bool:
        async with self._lock:
            session = self._sessions.get(device_name)
        return session is not None and session.alive

    async def list_open(self) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                session.public_info() for session in self._sessions.values()
            ]

    async def close(self, device_name: str) -> None:
        async with self._lock:
            session = self._sessions.pop(device_name, None)
        if session is None:
            raise ProtocolError(f"no open redfish session for device: {device_name}")
        await session.close()

    async def close_all(self) -> int:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        if sessions:
            await asyncio.gather(*(session.close() for session in sessions))
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            self._reaper_task = None
        return len(sessions)

    def _ensure_reaper(self) -> None:
        if self._reaper_task is None:
            self._reaper_task = asyncio.create_task(
                self._reap_loop(), name="opkit-redfish-reaper"
            )

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(REAP_INTERVAL_SECONDS)
            now = time.monotonic()
            async with self._lock:
                expired = [
                    session
                    for session in self._sessions.values()
                    if not session.alive or session.expired(now)
                ]
            for session in expired:
                await session.close()
                async with self._lock:
                    self._sessions.pop(session.device_name, None)
