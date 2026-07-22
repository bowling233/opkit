"""Stateless SSH exec protocol, made session-persistent.

The original implementation opened a fresh TCP+SSH connection for every
command. Since every protocol in opkit now follows the same
open-session / operate / close-session lifecycle, exec keeps one asyncssh
connection per device (with keepalives) and runs commands through it.

One deliberate behavioral difference from a fresh-connection design: when
the cached connection dies mid-command we cannot know whether the remote
side started executing, so the error reports the ambiguity instead of
silently retrying.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import asyncssh

from ..errors import ConfigError, ProtocolError

if TYPE_CHECKING:
    from ..config import AccountConfig

# Module tunables (documented in README).
CONNECT_TIMEOUT_SECONDS = 15.0
DEFAULT_COMMAND_TIMEOUT_SECONDS = 60.0
SESSION_IDLE_TTL_SECONDS = 600.0
MAX_SESSION_LIFETIME_SECONDS = 3600.0
REAP_INTERVAL_SECONDS = 30.0


@dataclass(frozen=True)
class SSHExecProtocol:
    """Configuration for one ``ssh-exec`` entry under a device."""

    endpoint: str
    account: AccountConfig
    port: int = 22
    encoding: str = "utf-8"
    # Resolved login name: the protocol-level ``username`` overrides the
    # account's, so one credential account can serve devices that name
    # their users differently.
    username: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "port": self.port,
            "account": self.account.name,
            "username": self.username,
        }

    def brief(self) -> str:
        return f"{self.endpoint}:{self.port}"


@dataclass(frozen=True)
class SSHExecResult:
    device: str
    server_version: str | None
    stdout: str
    stderr: str
    exit_status: int | None
    exit_signal: str | None
    elapsed_ms: int


def parse_config(
    device_name: str,
    values: dict[str, Any],
    accounts: dict[str, AccountConfig],
) -> SSHExecProtocol:
    """Build an :class:`SSHExecProtocol` from raw YAML."""
    allowed = {"endpoint", "port", "encoding", "account", "username"}
    unknown = set(values) - allowed
    if unknown:
        raise ConfigError(
            f"ssh-exec protocol for {device_name} has unknown keys: "
            f"{sorted(unknown)}"
        )
    endpoint = values.get("endpoint")
    if not endpoint or not isinstance(endpoint, str):
        raise ConfigError(
            f"ssh-exec protocol for {device_name} requires an endpoint"
        )
    account_name = values.get("account")
    if account_name is None:
        raise ConfigError(f"ssh-exec protocol for {device_name} requires an account")
    account = accounts.get(account_name)
    if account is None:
        raise ConfigError(
            f"ssh-exec protocol for {device_name} references "
            f"unknown account: {account_name}"
        )
    port = values.get("port", 22)
    if not isinstance(port, int) or isinstance(port, bool):
        raise ConfigError(
            f"ssh-exec protocol for {device_name} requires an integer port"
        )
    encoding = values.get("encoding", "utf-8")
    if not isinstance(encoding, str):
        raise ConfigError(
            f"ssh-exec protocol for {device_name} requires a string encoding"
        )
    username = values.get("username") or account.username
    if not username or not isinstance(username, str):
        raise ConfigError(
            f"ssh-exec protocol for {device_name} requires a username "
            f"(protocol or account {account_name})"
        )
    return SSHExecProtocol(
        endpoint=endpoint, account=account, port=port, encoding=encoding,
        username=username,
    )


class SSHExecSession:
    """A cached, keepalive'd SSH connection used only for exec channels."""

    def __init__(self, device_name: str, protocol: SSHExecProtocol) -> None:
        self.device_name = device_name
        self.protocol = protocol
        self.connection: Any = None
        self.server_version: str | None = None
        self.opened_at = time.time()
        self.last_activity_at = self.opened_at
        self._opened_monotonic = time.monotonic()
        self._last_activity_monotonic = self._opened_monotonic
        self._closed = False
        self._lost = False

    @property
    def alive(self) -> bool:
        return not self._closed and not self._lost

    def expired(self, now: float) -> bool:
        return (
            now - self._last_activity_monotonic >= SESSION_IDLE_TTL_SECONDS
            or now - self._opened_monotonic >= MAX_SESSION_LIFETIME_SECONDS
        )

    def _touch(self) -> None:
        self._last_activity_monotonic = time.monotonic()
        self.last_activity_at = time.time()

    async def connect(self) -> None:
        account = self.protocol.account
        if account.ssh_private_key:
            client_keys = [
                asyncssh.import_private_key(
                    account.ssh_private_key,
                    account.ssh_private_key_passphrase,
                )
            ]
        else:
            client_keys = []
        try:
            self.connection = await asyncssh.connect(
                self.protocol.endpoint,
                port=self.protocol.port,
                username=self.protocol.username,
                password=account.password,
                client_keys=client_keys,
                known_hosts=None,
                config=None,
                connect_timeout=CONNECT_TIMEOUT_SECONDS,
                keepalive_interval=15,
                keepalive_count_max=2,
            )
            self.server_version = self.connection.get_extra_info("server_version")
        except (OSError, asyncssh.Error) as exc:
            await self.close()
            raise ProtocolError(
                f"cannot connect to {self.device_name}: {exc}"
            ) from exc

    async def ensure_connected(self) -> None:
        if self.alive and self.connection is not None:
            return
        await self.connect()

    async def run(
        self,
        command: str,
        *,
        stdin: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SSHExecResult:
        command_timeout = (
            DEFAULT_COMMAND_TIMEOUT_SECONDS
            if timeout_seconds is None
            else timeout_seconds
        )
        await self.ensure_connected()
        assert self.connection is not None
        self._touch()
        started = time.monotonic()
        try:
            result = await self.connection.run(
                command,
                input=stdin,
                encoding=self.protocol.encoding,
                check=False,
                timeout=command_timeout,
            )
        except TimeoutError as exc:
            raise ProtocolError(
                f"command timed out on {self.device_name} after "
                f"{command_timeout} seconds"
            ) from exc
        except (OSError, asyncssh.Error) as exc:
            # The connection died mid-command; its outcome is unknowable.
            self._lost = True
            asyncio.create_task(self.close())
            raise ProtocolError(
                f"the SSH connection to {self.device_name} failed or was lost "
                f"during execution ({exc}); the command outcome is unknown "
                "and a fresh connection will be established on the next call"
            ) from exc
        self._touch()
        return SSHExecResult(
            device=self.device_name,
            server_version=self.server_version,
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            exit_status=result.exit_status,
            exit_signal=result.exit_signal[0] if result.exit_signal else None,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )

    def public_info(self) -> dict[str, Any]:
        return {
            "device": self.device_name,
            "connection_state": "open" if self.alive else "closed",
            "server_version": self.server_version,
            "opened_at": self.opened_at,
            "last_activity_at": self.last_activity_at,
        }

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.connection is not None:
            self.connection.close()
            try:
                await self.connection.wait_closed()
            except (OSError, asyncssh.Error):
                pass
            self.connection = None


class SSHExecManager:
    """Owns at most one persistent exec connection per device."""

    def __init__(self) -> None:
        self._sessions: dict[str, SSHExecSession] = {}
        self._lock = asyncio.Lock()
        self._reaper_task: asyncio.Task[None] | None = None

    def _session_for(self, config: Any, device_name: str) -> SSHExecSession:
        protocol = config.device_protocol(device_name, "ssh-exec")
        if not isinstance(protocol, SSHExecProtocol):
            raise ProtocolError(f"device {device_name} does not support ssh-exec")
        return protocol

    async def _get_or_create(self, config: Any, device_name: str) -> SSHExecSession:
        self._session_for(config, device_name)
        async with self._lock:
            existing = self._sessions.get(device_name)
            if existing is not None and existing.alive:
                return existing
            stale = existing
            session = SSHExecSession(
                device_name,
                self._session_for(config, device_name),
            )
            self._sessions[device_name] = session
        if stale is not None:
            await stale.close()
        return session

    async def execute(
        self,
        config: Any,
        device_name: str,
        command: str,
        *,
        stdin: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SSHExecResult:
        session = await self._get_or_create(config, device_name)
        try:
            result = await session.run(
                command,
                stdin=stdin,
                timeout_seconds=timeout_seconds,
            )
        except Exception:
            async with self._lock:
                current = self._sessions.get(device_name)
                if current is session and not session.alive:
                    self._sessions.pop(device_name, None)
            raise
        self._ensure_reaper()
        return result

    async def open(self, config: Any, device_name: str) -> dict[str, Any]:
        """Connect eagerly so open_session doubles as a connectivity probe."""
        session = await self._get_or_create(config, device_name)
        try:
            await session.ensure_connected()
        except Exception:
            async with self._lock:
                if self._sessions.get(device_name) is session:
                    self._sessions.pop(device_name, None)
            raise
        self._ensure_reaper()
        return session.public_info()

    async def status_of(self, config: Any, device_name: str) -> dict[str, Any]:
        self._session_for(config, device_name)
        async with self._lock:
            session = self._sessions.get(device_name)
        if session is None:
            return {
                "device": device_name,
                "connection_state": "closed",
                "server_version": None,
                "opened_at": None,
                "last_activity_at": None,
            }
        return session.public_info()

    async def occupied(self, device_name: str) -> bool:
        async with self._lock:
            session = self._sessions.get(device_name)
        return session is not None and session.alive

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
            raise ProtocolError(f"no open ssh-exec session for device: {device_name}")
        await session.close()

    async def close_all(self) -> int:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            await session.close()
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            self._reaper_task = None
        return len(sessions)

    def _ensure_reaper(self) -> None:
        if self._reaper_task is None:
            self._reaper_task = asyncio.create_task(
                self._reap_loop(), name="opkit-ssh-exec-reaper"
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
