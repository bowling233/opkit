"""Authenticated HTTP protocol for appliance WebUIs.

One generic transport serves every vendor; what differs is the login dance.
Each vendor flow (TP-Link switch, ZTE BE7200, Mellanox Onyx) is an
:class:`AuthProfile` subclass registered in :data:`AUTH_PROFILES`, selected
by the ``auth`` field of an ``http`` device protocol. This replaces the old
design where each vendor was its own hardcoded device type.

The auth profiles carry real reverse-engineered knowledge: TP-Link's
scrambled-password logon plus ``g_tid`` CSRF token, ZTE's SHA-256
login-token digest with ``_sessionTOKEN`` injection into every POST,
Mellanox's multi-field Onyx login form. Cookies are handled by httpx;
profiles only manage the extra tokens.

Functional guards kept from the original backend: callers may not supply
headers the transport manages itself (authorization/cookie/host), paths
must stay relative to the configured endpoint. Output filtering of
sensitive response headers was dropped — opkit does not redact results.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

from ..errors import ConfigError, ProtocolError
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

HTTPMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
BodyEncoding = Literal["text", "base64"]

# Headers the transport manages; callers supplying them get an error because
# they would break session handling, not because they leak secrets.
MANAGED_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "host",
    "proxy-authorization",
}
_TEXT_MEDIA_TYPES = (
    "application/ecmascript",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "image/svg+xml",
)


@dataclass(frozen=True)
class HTTPResponseResult:
    """Result envelope for both the http and redfish transports."""

    device: str
    method: str
    path: str
    status_code: int
    headers: dict[str, str]
    body: str
    body_encoding: BodyEncoding
    truncated: bool
    elapsed_ms: int


def split_endpoint(
    label: str,
    endpoint: object,
    default_scheme: str | None = None,
) -> tuple[str, str, int]:
    """Parse ``scheme://host[:port]`` into its parts.

    Appliance endpoints are origins: userinfo, paths, queries, and fragments
    are all rejected so every request stays inside the configured device.
    """
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ConfigError(f"{label} requires an endpoint URL")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError(
            f"{label} endpoint must start with http:// or https://: {endpoint}"
        )
    if not parsed.hostname:
        raise ConfigError(f"{label} endpoint has no host: {endpoint}")
    if parsed.username or parsed.password:
        raise ConfigError(
            f"{label} endpoint must not embed credentials: {endpoint}"
        )
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ConfigError(
            f"{label} endpoint must be a bare origin without path/query: "
            f"{endpoint}"
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError(f"{label} endpoint has an invalid port: {endpoint}") from exc
    scheme = parsed.scheme
    return scheme, parsed.hostname, port or (
        443 if scheme == "https" else 80 if default_scheme is None else 80
    )


def validate_relative_path(path: str) -> None:
    """Reject absolute URLs, fragments, and anything off-device."""
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
        raise ProtocolError("path must be an absolute path on the selected device")
    if parsed.fragment:
        raise ProtocolError("path must not contain a URL fragment")


def validate_request_headers(headers: dict[str, str], managed: set[str]) -> dict[str, str]:
    """Lowercase header names, reject managed/invalid ones."""
    clean: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.strip().lower()
        if normalized in managed:
            raise ProtocolError(
                f"header {name} is managed by the protocol backend "
                "and cannot be supplied"
            )
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ProtocolError(f"invalid HTTP header name: {name}")
        clean[normalized] = value
    return clean


def response_limit(requested: int | None) -> int:
    """Per-call body cap, clamped under the always-on global maximum."""
    if requested is None:
        return MAX_RESPONSE_BYTES
    return max(256, min(requested, MAX_RESPONSE_BYTES))


def build_rest_result(
    *,
    response: httpx.Response,
    device: str,
    method: str,
    path: str,
    started: float,
    limit: int,
) -> HTTPResponseResult:
    """Truncate, then render the body as text or base64."""
    raw = response.content
    truncated = len(raw) > limit
    raw = raw[:limit]
    media_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
    textual = media_type.startswith("text/") or media_type in _TEXT_MEDIA_TYPES
    if textual:
        encoding = response.encoding or "utf-8"
        body = raw.decode(encoding, errors="replace")
        body_encoding: BodyEncoding = "text"
    else:
        body = base64.b64encode(raw).decode("ascii")
        body_encoding = "base64"
    return HTTPResponseResult(
        device=device,
        method=method,
        path=path,
        status_code=response.status_code,
        headers=dict(response.headers.items()),
        body=body,
        body_encoding=body_encoding,
        truncated=truncated,
        elapsed_ms=round((time.monotonic() - started) * 1000),
    )


class AuthProfile:
    """Vendor login/off/token behavior attached to an ``http`` protocol."""

    name: str = "none"

    async def login(self, session: "HTTPSession") -> None:
        session.authenticated = True

    async def logout(self, session: "HTTPSession") -> None:
        del session

    def inject_query(
        self,
        path: str,
        query: dict[str, str | list[str]] | None,
        session: "HTTPSession",
    ) -> dict[str, str | list[str]] | None:
        del path, session
        return query

    def inject_form(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None,
        session: "HTTPSession",
    ) -> dict[str, str] | None:
        del method, path, session
        return form

    def inject_content(
        self,
        method: str,
        headers: dict[str, str],
        content: bytes | None,
        session: "HTTPSession",
    ) -> bytes | None:
        del method, headers, session
        return content

    def is_auth_failure(self, response: httpx.Response) -> bool:
        return response.status_code in {401, 403}

    def observe(self, response: httpx.Response, session: "HTTPSession") -> None:
        del response, session


def _tplink_password_encode(password: str) -> str:
    salt = "RDpbLfCPsJZ7fiv"
    alphabet = (
        "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4r"
        "BL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro5"
        "10qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZL"
        "Eal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
    )
    encoded: list[str] = []
    for index in range(max(len(password), len(salt))):
        password_byte = ord(password[index]) if index < len(password) else 187
        salt_byte = ord(salt[index]) if index < len(salt) else 187
        encoded.append(alphabet[(password_byte ^ salt_byte) % len(alphabet)])
    return "".join(encoded)


class TplinkProfile(AuthProfile):
    """TP-Link WebUI: scrambled-password logon.cgi plus g_tid token."""

    name = "tplink"

    async def login(self, session: "HTTPSession") -> None:
        username, password = session.credentials()
        session.tokens.pop("tplink", None)
        session.client.cookies.clear()
        response = await session.client.post(
            "/logon.cgi",
            data={
                "username": username,
                "password": _tplink_password_encode(password),
                "logon": "Login",
            },
            follow_redirects=True,
        )
        self.observe(response, session)
        if response.status_code < 400 and not session.tokens.get("tplink"):
            response = await session.client.get("/")
            self.observe(response, session)
        if (
            response.status_code >= 400
            or "SessionID" not in session.client.cookies
            or not session.tokens.get("tplink")
        ):
            raise ProtocolError(
                f"TP-Link authentication failed for {session.device_name}"
            )
        session.authenticated = True

    async def logout(self, session: "HTTPSession") -> None:
        await session.client.get("/Logout.htm")

    def inject_query(
        self,
        path: str,
        query: dict[str, str | list[str]] | None,
        session: "HTTPSession",
    ) -> dict[str, str | list[str]] | None:
        if not urlsplit(path).path.endswith(".cgi"):
            return query
        prepared = dict(query or {})
        prepared["token"] = session.tokens.get("tplink", "")
        return prepared

    def inject_form(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None,
        session: "HTTPSession",
    ) -> dict[str, str] | None:
        if form is None:
            return None
        if not urlsplit(path).path.endswith(".cgi"):
            return form
        prepared = dict(form)
        prepared["token"] = session.tokens.get("tplink", "")
        return prepared

    def is_auth_failure(self, response: httpx.Response) -> bool:
        if response.status_code in {401, 403}:
            return True
        return (
            response.url.path.endswith("/logon.cgi")
            or 'action="/logon.cgi"' in response.text
        )

    def observe(self, response: httpx.Response, session: "HTTPSession") -> None:
        match = re.search(r"\bg_tid\s*=\s*['\"]?(\d+)", response.text)
        if match:
            session.tokens["tplink"] = match.group(1)


class ZteBe7200Profile(AuthProfile):
    """ZTE BE7200: login-token digest auth plus _sessionTOKEN on POSTs.

    The carrier firmware authenticates a fixed 'admin' user and rejects any
    other username, so set ``username: admin`` on the protocol config.
    """

    name = "zte-be7200"

    async def login(self, session: "HTTPSession") -> None:
        username, password = session.credentials()
        session.tokens.pop("zte-be7200", None)
        session.client.cookies.clear()
        token_response = await session.client.get(
            "/?_type=loginsceneData&_tag=login_token_json"
        )
        try:
            token_data = token_response.json()
            session_token = str(token_data["_sessionToken"])
            login_token = str(token_data["logintoken"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError(
                f"ZTE login-token request failed for {session.device_name}"
            ) from exc

        session.tokens["zte-be7200"] = session_token
        password_digest = hashlib.sha256(
            (password + login_token).encode("utf-8")
        ).hexdigest()
        response = await session.client.post(
            "/?_type=loginData&_tag=login_entry",
            data={
                "Username": username,
                "Password": password_digest,
                "action": "login",
                "Frm_Logintoken": "",
                "captchaCode": "",
                "_sessionTOKEN": session_token,
            },
        )
        self._capture_xsrf(response, session)
        try:
            result = response.json()
        except ValueError as exc:
            raise ProtocolError(
                f"ZTE authentication returned an invalid response for "
                f"{session.device_name}"
            ) from exc
        if response.status_code >= 400 or result.get("login_need_refresh") is not True:
            message = result.get("loginErrMsg") or "credentials were rejected"
            raise ProtocolError(
                f"ZTE authentication failed for {session.device_name}: {message}"
            )
        if result.get("sess_token"):
            session.tokens["zte-be7200"] = str(result["sess_token"])
        session.authenticated = True

    async def logout(self, session: "HTTPSession") -> None:
        await session.client.post(
            "/?_type=loginData&_tag=logout_entry",
            data={
                "IF_LogOff": "1",
                "_sessionTOKEN": session.tokens.get("zte-be7200", ""),
            },
        )

    def inject_form(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None,
        session: "HTTPSession",
    ) -> dict[str, str] | None:
        del path
        if form is None or method != "POST":
            return form
        prepared = dict(form)
        prepared["_sessionTOKEN"] = session.tokens.get("zte-be7200", "")
        return prepared

    def inject_content(
        self,
        method: str,
        headers: dict[str, str],
        content: bytes | None,
        session: "HTTPSession",
    ) -> bytes | None:
        if (
            content is None
            or method != "POST"
            or headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/x-www-form-urlencoded"
        ):
            return content
        fields = dict(parse_qsl(content.decode("utf-8"), keep_blank_values=True))
        fields["_sessionTOKEN"] = session.tokens.get("zte-be7200", "")
        return urlencode(fields).encode("utf-8")

    def is_auth_failure(self, response: httpx.Response) -> bool:
        if response.status_code in {401, 403}:
            return True
        return "SessionTimeout" in response.text

    def observe(self, response: httpx.Response, session: "HTTPSession") -> None:
        self._capture_xsrf(response, session)
        if response.url.params.get("_tag") == "login_token_json":
            try:
                token_data = response.json()
                session.tokens["zte-be7200"] = str(token_data["_sessionToken"])
            except (KeyError, TypeError, ValueError):
                pass

    @staticmethod
    def _capture_xsrf(response: httpx.Response, session: "HTTPSession") -> None:
        token = response.headers.get("x_xsrf_token") or response.headers.get(
            "x-xsrf-token"
        )
        if token:
            session.tokens["zte-be7200"] = token


class MellanoxProfile(AuthProfile):
    """Mellanox Onyx WebUI: multi-field launch-script login form."""

    name = "mellanox"

    async def login(self, session: "HTTPSession") -> None:
        username, password = session.credentials()
        session.client.cookies.clear()
        response = await session.client.post(
            "/admin/launch?script=rh&template=login&action=login",
            data={
                "d_user_id": "user_id",
                "t_user_id": "string",
                "c_user_id": "string",
                "e_user_id": "true",
                "f_user_id": username,
                "f_password": password,
                "Login": "Login",
            },
            follow_redirects=True,
        )
        if (
            response.status_code >= 400
            or "session" not in session.client.cookies
            or self.is_login_page(response)
        ):
            raise ProtocolError(
                f"Mellanox Onyx authentication failed for {session.device_name}"
            )
        session.authenticated = True

    async def logout(self, session: "HTTPSession") -> None:
        await session.client.get(
            "/admin/launch?script=rh&template=logout&action=logout"
        )

    def is_auth_failure(self, response: httpx.Response) -> bool:
        if response.status_code in {401, 403}:
            return True
        return self.is_login_page(response)

    @staticmethod
    def is_login_page(response: httpx.Response) -> bool:
        return (
            "template=login" in str(response.url)
            or "Please enter your username and password" in response.text
        )


AUTH_PROFILES: dict[str, AuthProfile] = {
    profile.name: profile
    for profile in (AuthProfile(), TplinkProfile(), ZteBe7200Profile(), MellanoxProfile())
}


@dataclass(frozen=True)
class HTTPProtocol:
    """Configuration for one ``http`` entry under a device."""

    endpoint: str
    scheme: str
    host: str
    port: int
    auth: str
    account: AccountConfig | None
    # Resolved login name: the protocol-level ``username`` overrides the
    # account's, so one credential account can serve devices that name
    # their users differently.
    username: str | None = None

    def summary(self) -> dict[str, Any]:
        info: dict[str, Any] = {
            "endpoint": self.endpoint,
            "auth": self.auth,
        }
        if self.username is not None:
            info["username"] = self.username
        if self.account is not None:
            info["account"] = self.account.name
        return info

    def brief(self) -> str:
        return f"{self.endpoint} auth={self.auth}"


def parse_config(
    device_name: str,
    values: dict[str, Any],
    accounts: dict[str, AccountConfig],
) -> HTTPProtocol:
    """Build an :class:`HTTPProtocol` from raw YAML."""
    allowed = {"endpoint", "auth", "account", "username"}
    unknown = set(values) - allowed
    if unknown:
        raise ConfigError(
            f"http protocol for {device_name} has unknown keys: {sorted(unknown)}"
        )
    scheme, host, port = split_endpoint(
        f"http protocol for {device_name}", values.get("endpoint")
    )
    auth = values.get("auth", "none")
    if auth not in AUTH_PROFILES:
        raise ConfigError(
            f"http protocol for {device_name} has unknown auth profile: {auth} "
            f"(available: {sorted(AUTH_PROFILES)})"
        )
    account_name = values.get("account")
    account: AccountConfig | None = None
    if account_name is not None:
        account = accounts.get(account_name)
        if account is None:
            raise ConfigError(
                f"http protocol for {device_name} references "
                f"unknown account: {account_name}"
            )
    if auth != "none":
        if account is None:
            raise ConfigError(
                f"http protocol for {device_name}: auth '{auth}' requires an account"
            )
        if account.password is None:
            raise ConfigError(
                f"http protocol for {device_name}: account {account.name} "
                "requires a password"
            )
        username = values.get("username") or account.username
        if not username or not isinstance(username, str):
            raise ConfigError(
                f"http protocol for {device_name}: auth '{auth}' requires a "
                f"username (protocol or account {account.name})"
            )
    else:
        username = values.get("username")
    endpoint = f"{scheme}://{host}:{port}"
    return HTTPProtocol(
        endpoint=endpoint,
        scheme=scheme,
        host=host,
        port=port,
        auth=auth,
        account=account,
        username=username,
    )


class HTTPSession:
    """One authenticated WebUI session: client, profile state, tokens."""

    def __init__(self, device_name: str, protocol: HTTPProtocol) -> None:
        self.device_name = device_name
        self.protocol = protocol
        self.profile = AUTH_PROFILES[protocol.auth]
        self.tokens: dict[str, str] = {}
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

    def credentials(self) -> tuple[str, str]:
        account = self.protocol.account
        assert account is not None
        username = self.protocol.username
        password = account.password
        if not username or password is None:
            raise ProtocolError(
                f"http protocol '{self.profile.name}' for {self.device_name} "
                "requires a username and password"
            )
        return username, password

    async def ensure_authenticated(self, *, force: bool = False) -> None:
        if self.authenticated and not force:
            return
        async with self._auth_lock:
            if self.authenticated and not force:
                return
            if self.authenticated:
                await self._logout_once()
            try:
                await self.profile.login(self)
            except httpx.HTTPError as exc:
                self.authenticated = False
                # Some transport errors stringify to ""; always carry the
                # exception class so failures stay diagnosable.
                raise ProtocolError(
                    f"authentication failed on {self.device_name}: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc

    async def _logout_once(self) -> None:
        try:
            await self.profile.logout(self)
        except httpx.HTTPError:
            pass
        self.authenticated = False

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
        timeout_seconds: float | None = None,
        limit_bytes: int | None = None,
    ) -> HTTPResponseResult:
        method = method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ProtocolError(f"unsupported HTTP method: {method}")
        validate_relative_path(path)
        supplied_bodies = sum(value is not None for value in (body, body_base64, form))
        if supplied_bodies > 1:
            raise ProtocolError("provide only one of body, body_base64, or form")

        clean_headers = validate_request_headers(headers or {}, MANAGED_REQUEST_HEADERS)
        if body_base64 is not None:
            try:
                content = base64.b64decode(body_base64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ProtocolError("body_base64 is not valid base64") from exc
        elif body is not None:
            content = body.encode("utf-8")
        else:
            content = None

        await self.ensure_authenticated()
        self._touch()
        started = time.monotonic()
        try:
            response = await self._send(
                method,
                path,
                query=query,
                headers=clean_headers,
                content=content,
                form=form,
                timeout_seconds=timeout_seconds,
            )
            if self.profile.is_auth_failure(response):
                await self.ensure_authenticated(force=True)
                response = await self._send(
                    method,
                    path,
                    query=query,
                    headers=clean_headers,
                    content=content,
                    form=form,
                    timeout_seconds=timeout_seconds,
                )
        except httpx.HTTPError as exc:
            raise ProtocolError(
                f"HTTP request failed on {self.device_name}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
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
        prepared_query = self.profile.inject_query(path, query, self)
        prepared_form = self.profile.inject_form(method, path, form, self)
        prepared_content = self.profile.inject_content(method, headers, content, self)
        request_options: dict[str, object] = {
            "params": prepared_query,
            "headers": headers,
            "content": prepared_content,
            "data": prepared_form,
        }
        if timeout_seconds is not None:
            request_options["timeout"] = timeout_seconds
        response = await self.client.request(method, path, **request_options)
        self.profile.observe(response, self)
        return response

    def public_info(self) -> dict[str, Any]:
        return {
            "device": self.device_name,
            "connection_state": "open" if self.alive else "closed",
            "authenticated": self.authenticated,
            "auth_profile": self.profile.name,
            "opened_at": self.opened_at,
            "last_activity_at": self.last_activity_at,
        }

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self.authenticated:
                await self._logout_once()
        except httpx.HTTPError:
            pass
        finally:
            await self.client.aclose()


class HTTPManager:
    """Owns at most one authenticated WebUI session per device."""

    def __init__(self) -> None:
        self._sessions: dict[str, HTTPSession] = {}
        self._lock = asyncio.Lock()
        self._reaper_task: asyncio.Task[None] | None = None

    def _protocol_of(self, config: Any, device_name: str) -> HTTPProtocol:
        protocol = config.device_protocol(device_name, "http")
        if not isinstance(protocol, HTTPProtocol):
            raise ProtocolError(f"device {device_name} does not support http")
        return protocol

    async def request(
        self,
        config: Any,
        device_name: str,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> HTTPResponseResult:
        session = await self.session_for(config, device_name)
        result = await session.request(method, path, **kwargs)
        self._ensure_reaper()
        return result

    async def session_for(self, config: Any, device_name: str) -> HTTPSession:
        self._protocol_of(config, device_name)
        async with self._lock:
            existing = self._sessions.get(device_name)
            if existing is not None and existing.alive:
                return existing
            stale = existing
            session = HTTPSession(device_name, self._protocol_of(config, device_name))
            self._sessions[device_name] = session
        if stale is not None:
            await stale.close()
        return session

    async def open(self, config: Any, device_name: str) -> dict[str, Any]:
        """Authenticate eagerly so open_session doubles as a login probe."""
        session = await self.session_for(config, device_name)
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
                "auth_profile": self._protocol_of(config, device_name).auth,
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
            raise ProtocolError(f"no open http session for device: {device_name}")
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
                self._reap_loop(), name="opkit-http-reaper"
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
