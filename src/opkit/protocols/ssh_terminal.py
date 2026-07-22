"""Interactive SSH terminal protocol (PTY sessions with byte cursors).

Append-only transcript on disk, cursor-based reads with quiet/deadline/limit
stop reasons, idempotent exchanges keyed by request_id, optimistic-concurrency
writes (outbound_seq / unsettled), idle-TTL and lifetime reaping.

Tunables that previously lived in the ``backends:`` config section are now
module-level constants — this project prefers fewer configuration knobs
over more.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

import asyncssh

from ..errors import ConfigError, ProtocolError

if TYPE_CHECKING:
    from ..config import AccountConfig

# Module tunables (documented in README).
CONNECT_TIMEOUT_SECONDS = 15.0
DEFAULT_QUIET_TIMEOUT_MS = 1000
DEFAULT_DEADLINE_MS = 15_000
DEFAULT_RESPONSE_LIMIT_BYTES = 200_000
MAX_SESSIONS = 10
SESSION_IDLE_TTL_SECONDS = 600.0
MAX_SESSION_LIFETIME_SECONDS = 3600.0
REAP_INTERVAL_SECONDS = 30.0

KEYS = {
    "ENTER": b"\r",
    "SPACE": b" ",
    "CTRL_C": b"\x03",
    "CTRL_Z": b"\x1a",
    "Q": b"q",
}

InputType = Literal["line", "text", "key"]
ReadStopReason = Literal["quiet", "deadline", "response_limit", "eof"]
ConnectionState = Literal["open", "closed"]


@dataclass(frozen=True)
class SSHTerminalProtocol:
    """Configuration for one ``ssh-terminal`` entry under a device."""

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
class SessionInfo:
    device: str
    connection_state: ConnectionState
    server_version: str | None
    opened_at: float
    last_activity_at: float
    cursor: int
    outbound_seq: int
    unsettled: bool


@dataclass(frozen=True)
class ReadResult:
    output: str
    from_cursor: int
    next_cursor: int
    read_stop_reason: ReadStopReason
    elapsed_ms: int
    connection_state: ConnectionState


@dataclass(frozen=True)
class ExchangeResult:
    output: str
    from_cursor: int
    write_cursor: int
    next_cursor: int
    read_stop_reason: ReadStopReason
    elapsed_ms: int
    connection_state: ConnectionState
    request_id: str
    outbound_seq: int


def parse_config(
    device_name: str,
    values: dict[str, Any],
    accounts: dict[str, AccountConfig],
) -> SSHTerminalProtocol:
    """Build an :class:`SSHTerminalProtocol` from raw YAML."""
    allowed = {"endpoint", "port", "encoding", "account", "username"}
    unknown = set(values) - allowed
    if unknown:
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} has unknown keys: "
            f"{sorted(unknown)}"
        )
    endpoint = values.get("endpoint")
    if not endpoint or not isinstance(endpoint, str):
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} requires an endpoint"
        )
    account_name = values.get("account")
    if account_name is None:
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} requires an account"
        )
    account = accounts.get(account_name)
    if account is None:
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} references "
            f"unknown account: {account_name}"
        )
    port = values.get("port", 22)
    if not isinstance(port, int) or isinstance(port, bool):
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} requires an integer port"
        )
    encoding = values.get("encoding", "utf-8")
    if not isinstance(encoding, str):
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} requires a string encoding"
        )
    username = values.get("username") or account.username
    if not username or not isinstance(username, str):
        raise ConfigError(
            f"ssh-terminal protocol for {device_name} requires a username "
            f"(protocol or account {account_name})"
        )
    return SSHTerminalProtocol(
        endpoint=endpoint, account=account, port=port, encoding=encoding,
        username=username,
    )


class SSHTerminalSession:
    """One interactive SSH channel with an append-only output transcript."""

    def __init__(
        self,
        device_name: str,
        protocol: SSHTerminalProtocol,
    ) -> None:
        self.device_name = device_name
        self.protocol = protocol
        self.connection: Any = None
        self.process: Any = None
        self.opened_at = time.time()
        self.last_activity_at = self.opened_at
        self._opened_monotonic = time.monotonic()
        self._last_activity_monotonic = self._opened_monotonic
        self._transcript = tempfile.TemporaryFile()
        self._cursor = 0
        self._last_output_at = self._opened_monotonic
        self._condition = asyncio.Condition()
        self._write_lock = asyncio.Lock()
        self._request_lock = asyncio.Lock()
        self._requests: dict[str, asyncio.Task[ExchangeResult]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._eof = False
        self._closed = False
        self.unsettled = False
        self.outbound_seq = 0
        self.server_version: str | None = None

    @property
    def connected(self) -> bool:
        return not self._closed and not self._eof and self.process is not None

    @property
    def cursor(self) -> int:
        return self._cursor

    def expired(self, now: float) -> bool:
        return (
            now - self._last_activity_monotonic >= SESSION_IDLE_TTL_SECONDS
            or now - self._opened_monotonic >= MAX_SESSION_LIFETIME_SECONDS
        )

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
            self.process = await self.connection.create_process(
                term_type="vt100",
                term_size=(4096, 200),
                encoding=None,
                stderr=asyncssh.STDOUT,
            )
        except (OSError, asyncssh.Error) as exc:
            await self.close()
            raise ProtocolError(
                f"cannot connect to {self.device_name}: {exc}"
            ) from exc

        self._reader_task = asyncio.create_task(
            self._read_output(), name=f"opkit-ssh-reader-{self.device_name}"
        )

    async def _read_output(self) -> None:
        try:
            while True:
                chunk = await self.process.stdout.read(65536)
                if not chunk:
                    break
                now = time.monotonic()
                async with self._condition:
                    os.write(self._transcript.fileno(), chunk)
                    self._cursor += len(chunk)
                    self._last_output_at = now
                    self._touch(now)
                    self._condition.notify_all()
        finally:
            async with self._condition:
                self._eof = True
                self._condition.notify_all()

    def _touch(self, now: float | None = None) -> None:
        self._last_activity_monotonic = now or time.monotonic()
        self.last_activity_at = time.time()

    async def read(
        self,
        cursor: int,
        *,
        quiet_timeout_ms: int | None = None,
        deadline_ms: int | None = None,
        response_limit_bytes: int | None = None,
    ) -> ReadResult:
        if cursor < 0:
            raise ProtocolError("cursor cannot be negative")
        if cursor > self.cursor:
            raise ProtocolError(
                f"cursor {cursor} is ahead of session cursor {self.cursor}"
            )

        quiet_ms = (
            DEFAULT_QUIET_TIMEOUT_MS
            if quiet_timeout_ms is None
            else quiet_timeout_ms
        )
        hard_ms = DEFAULT_DEADLINE_MS if deadline_ms is None else deadline_ms
        limit = (
            DEFAULT_RESPONSE_LIMIT_BYTES
            if response_limit_bytes is None
            else response_limit_bytes
        )
        started = time.monotonic()
        deadline = started + hard_ms / 1000

        async with self._condition:
            while True:
                now = time.monotonic()
                available = self._cursor - cursor

                if available >= limit:
                    reason = "response_limit"
                    break
                if self._eof:
                    reason = "eof"
                    break
                if available > 0 and now - self._last_output_at >= quiet_ms / 1000:
                    reason = "quiet"
                    break
                if now >= deadline:
                    reason = "deadline"
                    break

                if available > 0:
                    quiet_left = self._last_output_at + quiet_ms / 1000 - now
                    wait = min(deadline - now, quiet_left)
                else:
                    wait = deadline - now

                try:
                    await asyncio.wait_for(self._condition.wait(), timeout=max(0, wait))
                except TimeoutError:
                    pass

            end = min(self._cursor, cursor + limit)
            data = os.pread(self._transcript.fileno(), end - cursor, cursor)

        self._touch()
        self.unsettled = reason not in {"quiet", "eof"}
        return ReadResult(
            output=data.decode(self.protocol.encoding, errors="replace"),
            from_cursor=cursor,
            next_cursor=end,
            read_stop_reason=reason,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            connection_state="open" if self.connected else "closed",
        )

    async def exchange(
        self,
        *,
        request_id: str,
        data: str,
        cursor: int,
        input_type: InputType = "line",
        expected_outbound_seq: int | None = None,
        force_write: bool = False,
        quiet_timeout_ms: int | None = None,
        deadline_ms: int | None = None,
        response_limit_bytes: int | None = None,
    ) -> ExchangeResult:
        async with self._request_lock:
            task = self._requests.get(request_id)
            if task is None:
                task = asyncio.create_task(
                    self._exchange_once(
                        request_id=request_id,
                        data=data,
                        cursor=cursor,
                        input_type=input_type,
                        expected_outbound_seq=expected_outbound_seq,
                        force_write=force_write,
                        quiet_timeout_ms=quiet_timeout_ms,
                        deadline_ms=deadline_ms,
                        response_limit_bytes=response_limit_bytes,
                    )
                )
                self._requests[request_id] = task
        return await asyncio.shield(task)

    async def _exchange_once(
        self,
        *,
        request_id: str,
        data: str,
        cursor: int,
        input_type: InputType,
        expected_outbound_seq: int | None,
        force_write: bool,
        quiet_timeout_ms: int | None,
        deadline_ms: int | None,
        response_limit_bytes: int | None,
    ) -> ExchangeResult:
        payload = self._encode_input(data, input_type)
        can_interrupt = input_type == "key" and data.upper() == "CTRL_C"

        async with self._write_lock:
            if not self.connected:
                raise ProtocolError(
                    f"terminal for {self.device_name} is closed"
                )
            if (
                expected_outbound_seq is not None
                and expected_outbound_seq != self.outbound_seq
            ):
                raise ProtocolError(
                    f"outbound sequence is {self.outbound_seq}, "
                    f"expected {expected_outbound_seq}"
                )
            if self.unsettled and not force_write and not can_interrupt:
                raise ProtocolError(
                    "previous read ended before the stream became quiet; "
                    "read again, interrupt, or set force_write"
                )
            if cursor > self.cursor:
                raise ProtocolError(
                    f"cursor {cursor} is ahead of session cursor {self.cursor}"
                )

            write_cursor = self.cursor
            self.outbound_seq += 1
            outbound_seq = self.outbound_seq
            self.unsettled = True
            self.process.stdin.write(payload)
            await self.process.stdin.drain()
            self._touch()

        result = await self.read(
            cursor,
            quiet_timeout_ms=quiet_timeout_ms,
            deadline_ms=deadline_ms,
            response_limit_bytes=response_limit_bytes,
        )
        return ExchangeResult(
            output=result.output,
            from_cursor=result.from_cursor,
            write_cursor=write_cursor,
            next_cursor=result.next_cursor,
            read_stop_reason=result.read_stop_reason,
            elapsed_ms=result.elapsed_ms,
            connection_state=result.connection_state,
            request_id=request_id,
            outbound_seq=outbound_seq,
        )

    def _encode_input(self, data: str, input_type: InputType) -> bytes:
        if input_type == "line":
            return data.encode(self.protocol.encoding) + b"\r"
        if input_type == "text":
            return data.encode(self.protocol.encoding)
        if input_type == "key":
            try:
                return KEYS[data.upper()]
            except KeyError as exc:
                raise ProtocolError(f"unknown key: {data}") from exc
        raise ProtocolError(f"unknown input_type: {input_type}")

    def public_info(self) -> SessionInfo:
        return SessionInfo(
            device=self.device_name,
            connection_state="open" if self.connected else "closed",
            server_version=self.server_version,
            opened_at=self.opened_at,
            last_activity_at=self.last_activity_at,
            cursor=self.cursor,
            outbound_seq=self.outbound_seq,
            unsettled=self.unsettled,
        )

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process is not None:
            self.process.close()
        if self.connection is not None:
            self.connection.close()
            await self.connection.wait_closed()
        if self._reader_task is not None:
            self._reader_task.cancel()
            await asyncio.gather(self._reader_task, return_exceptions=True)
        async with self._condition:
            self._eof = True
            self._condition.notify_all()
        self._transcript.close()


class SSHTerminalManager:
    """Owns at most one terminal session per device."""

    def __init__(self) -> None:
        self._sessions: dict[str, SSHTerminalSession] = {}
        self._lock = asyncio.Lock()
        self._reaper_task: asyncio.Task[None] | None = None

    def _protocol_of(self, config: Any, device_name: str) -> SSHTerminalProtocol:
        protocol = config.device_protocol(device_name, "ssh-terminal")
        if not isinstance(protocol, SSHTerminalProtocol):
            raise ProtocolError(
                f"device {device_name} has no ssh-terminal protocol"
            )
        return protocol

    async def open(
        self,
        config: Any,
        device_name: str,
        *,
        quiet_timeout_ms: int | None = None,
        deadline_ms: int | None = None,
        response_limit_bytes: int | None = None,
    ) -> tuple[SSHTerminalSession, ReadResult]:
        self._protocol_of(config, device_name)

        async with self._lock:
            existing = self._sessions.get(device_name)
            if existing is not None and existing.connected:
                session = existing
                reuse_existing = True
                stale = None
            else:
                reuse_existing = False
                stale = existing
            if existing is not None:
                if not reuse_existing:
                    self._sessions.pop(device_name, None)
            if not reuse_existing:
                if len(self._sessions) >= MAX_SESSIONS:
                    raise ProtocolError("maximum number of SSH terminals reached")
                session = SSHTerminalSession(
                    device_name,
                    self._protocol_of(config, device_name),
                )
                self._sessions[device_name] = session

        if stale is not None:
            await stale.close()

        if reuse_existing:
            initial = await session.read(
                0,
                quiet_timeout_ms=quiet_timeout_ms,
                deadline_ms=deadline_ms,
                response_limit_bytes=response_limit_bytes,
            )
            return session, initial

        try:
            await session.connect()
            initial = await session.read(
                0,
                quiet_timeout_ms=quiet_timeout_ms,
                deadline_ms=deadline_ms,
                response_limit_bytes=response_limit_bytes,
            )
        except Exception:
            await session.close()
            async with self._lock:
                self._sessions.pop(device_name, None)
            raise

        self._ensure_reaper()
        return session, initial

    async def get(self, device_name: str) -> SSHTerminalSession:
        async with self._lock:
            try:
                return self._sessions[device_name]
            except KeyError as exc:
                raise ProtocolError(
                    f"no open terminal for device: {device_name}; "
                    "call open_session first"
                ) from exc

    async def list(self) -> list[SessionInfo]:
        async with self._lock:
            return [session.public_info() for session in self._sessions.values()]

    async def occupied(self, device_name: str) -> bool:
        async with self._lock:
            session = self._sessions.get(device_name)
        return session is not None and session.connected

    async def close(self, device_name: str) -> None:
        async with self._lock:
            session = self._sessions.get(device_name)
        if session is None:
            raise ProtocolError(f"no open terminal for device: {device_name}")
        await session.close()
        async with self._lock:
            self._sessions.pop(device_name, None)

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
                self._reap_loop(), name="opkit-ssh-terminal-reaper"
            )

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(REAP_INTERVAL_SECONDS)
            now = time.monotonic()
            async with self._lock:
                expired = [
                    session
                    for session in self._sessions.values()
                    if not session.connected or session.expired(now)
                ]
            for session in expired:
                await session.close()
                async with self._lock:
                    self._sessions.pop(session.device_name, None)
