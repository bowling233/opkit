"""MCP interface: the UI layer where agents meet devices.

Tools stay deliberately thin — each one resolves a (device, protocol)
pair and delegates to a protocol manager. Nine tools total: four generic
lifecycle/listing tools plus one operation tool per transport protocol
(ssh_terminal is the interactive-terminal operation).

The server never interprets commands or API payloads; it authenticates,
manages sessions, and moves bytes with typed envelopes.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, AsyncIterator

from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route

from .config import AppConfig, DeviceInfo
from .errors import ProtocolError
from .protocols.http import HTTPManager, HTTPResponseResult
from .protocols.redfish import RedfishManager
from .protocols.ssh_exec import SSHExecManager, SSHExecResult
from .protocols.ssh_terminal import (
    ExchangeResult,
    InputType,
    ReadResult,
    SSHTerminalManager,
)

SERVER_INSTRUCTIONS = """
Every configured device is a named machine that may expose several access
protocols at once (see list_devices — its descriptions tell you what
each machine is). All protocols share one lifecycle:
open_session establishes the connection, a per-protocol operation tool does
the work, close_session tears it down. Sessions also reap themselves after
idling, so leaking them is survivable but closing them is polite.

Device routing rules:
- Pass the exact device name from list_devices to any tool.
- When a device exposes multiple protocols and you omit `protocol`,
  open_session refuses rather than guess; name the channel you want
  (e.g. redfish for out-of-band power/sensors, ssh-exec for an OS shell).
- Operation tools are named after their protocol: ssh_exec only talks to
  ssh-exec protocols, http only to http protocols, etc.

ssh-exec keeps one persistent SSH connection per device; each
ssh_exec call is one command whose stdout/stderr/exit_status come back
structured. Start with read-only commands.

redfish gives you raw REST against a BMC. Login is handled by the server;
just send paths under /redfish/v1 with GET/POST/PATCH/DELETE and interpret
the JSON yourself. Discover with GET /redfish/v1, /redfish/v1/Systems,
/redfish/v1/Managers, /redfish/v1/Chassis. A 401 triggers one transparent
re-login. POST action payloads go through json_body.

http reaches vendor WebUIs. Cookies, vendor CSRF tokens, and re-login on
session expiry are managed by the server; supply only a relative path.
Start with GET while discovering an API.

ssh-terminal exposes an interactive PTY. Output accumulates into a
transcript you read through byte cursors: pass initial_output.next_cursor
from open_session into your first ssh_terminal call, then keep carrying
next_cursor forward. quiet means no new bytes arrived during
quiet_timeout_ms — it does not mean your command finished. The server does
not parse prompts or infer command success. input_type "line" appends a
newline, "text" sends raw characters, "key" sends special keys like CTRL_C.
Writes carry request_id for idempotency and expected_outbound_seq for
optimistic concurrency; if a previous read ended unsettled, ordinary
writes block until you read again (or force_write).
"""

PROTOCOL_ORDER = ("ssh-terminal", "ssh-exec", "http", "redfish")


def create_managers() -> dict[str, Any]:
    """One instance per protocol; shared by the MCP server and the CLI."""
    return {
        "ssh-terminal": SSHTerminalManager(),
        "ssh-exec": SSHExecManager(),
        "http": HTTPManager(),
        "redfish": RedfishManager(),
    }


def _create_mcp(
    managers: dict[str, Any],
    config: AppConfig,
    *,
    owns_sessions: bool,
    host: str = "127.0.0.1",
    port: int = 8000,
    http_path: str = "/mcp",
    json_response: bool = False,
) -> FastMCP:
    """Assemble a FastMCP instance with all tools registered.

    ``owns_sessions`` marks transports whose lifespan runs exactly once
    (stdio, sse): FastMCP's lifespan then closes device sessions at
    shutdown. The streamable-HTTP app runs in stateless mode where this
    library re-enters the lifespan on every request, so that instance gets
    owns_sessions=False and the outer ASGI app owns cleanup instead.
    """
    protocol_managers = list(managers.values())

    @asynccontextmanager
    async def lifespan(_: FastMCP[Any]) -> AsyncIterator[None]:
        if not owns_sessions:
            yield
            return
        try:
            yield
        finally:
            for manager in protocol_managers:
                await manager.close_all()

    mcp = FastMCP(
        "opkit",
        instructions=SERVER_INSTRUCTIONS,
        lifespan=lifespan,
        host=host,
        port=port,
        streamable_http_path=http_path,
        json_response=json_response,
    )
    _register_tools(mcp, managers, config)
    return mcp


def create_server(
    config: AppConfig,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    http_path: str = "/mcp",
    json_response: bool = False,
) -> FastMCP:
    """FastMCP server for the stdio and sse transports."""
    return _create_mcp(
        create_managers(),
        config,
        owns_sessions=True,
        host=host,
        port=port,
        http_path=http_path,
        json_response=json_response,
    )


def create_http_app(
    config: AppConfig,
    *,
    http_path: str = "/mcp",
    json_response: bool = False,
) -> Starlette:
    """ASGI app for the streamable-http transport.

    Stateless per the MCP spec: the server issues no Mcp-Session-Id, so a
    server restart is invisible to clients — they keep POSTing tools/call
    without any handshake. Device sessions live in our managers (keyed by
    device, not by MCP session), so they survive across requests and only
    the usual reaping applies.
    """
    managers = create_managers()
    mcp = _create_mcp(
        managers, config, owns_sessions=False, json_response=json_response
    )
    session_manager = StreamableHTTPSessionManager(
        app=mcp._mcp_server,
        json_response=json_response,
        stateless=True,
    )

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            async with session_manager.run():
                yield
        finally:
            for manager in managers.values():
                await manager.close_all()

    async def endpoint(request: Request) -> None:
        await session_manager.handle_request(
            request.scope, request.receive, request._send
        )

    return Starlette(
        lifespan=lifespan,
        routes=[Route(http_path, endpoint, methods=["GET", "POST", "DELETE"])],
    )


@dataclass(frozen=True)
class SessionStatus:
    """Uniform view of one live (or last-known) session across protocols."""

    device: str
    protocol: str
    connection_state: str
    opened_at: float | None = None
    last_activity_at: float | None = None
    authenticated: bool | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CloseResult:
    closed: bool
    device: str
    protocol: str


def _terminal_status(
    info: Any,
    *,
    extra_detail: dict[str, Any] | None = None,
) -> SessionStatus:
    detail = {
        key: getattr(info, key)
        for key in ("server_version", "cursor", "outbound_seq", "unsettled")
    }
    if extra_detail:
        detail.update(extra_detail)
    return SessionStatus(
        device=info.device,
        protocol="ssh-terminal",
        connection_state=info.connection_state,
        opened_at=info.opened_at,
        last_activity_at=info.last_activity_at,
        detail=detail,
    )


def _plain_status(protocol: str, info: dict[str, Any]) -> SessionStatus:
    base_keys = {
        "device",
        "connection_state",
        "opened_at",
        "last_activity_at",
        "authenticated",
    }
    return SessionStatus(
        device=str(info["device"]),
        protocol=protocol,
        connection_state=str(info["connection_state"]),
        opened_at=info.get("opened_at"),
        last_activity_at=info.get("last_activity_at"),
        authenticated=info.get("authenticated"),
        detail={
            key: value for key, value in info.items() if key not in base_keys
        },
    )


async def open_on(
    managers: dict[str, Any],
    config: AppConfig,
    device: str,
    protocol: str,
    **options: Any,
) -> SessionStatus:
    """Open a session on one protocol and normalize its status report."""
    if protocol == "ssh-terminal":
        session, initial = await managers[protocol].open(config, device, **options)
        return _terminal_status(
            session.public_info(), extra_detail={"initial_output": asdict(initial)}
        )
    info = await managers[protocol].open(config, device)
    return _plain_status(protocol, info)


async def statuses_of(
    managers: dict[str, Any], config: AppConfig
) -> list[SessionStatus]:
    """Snapshot every live session across all protocols."""
    statuses: list[SessionStatus] = []
    for info in await managers["ssh-terminal"].list():
        statuses.append(_terminal_status(info))
    for protocol in ("ssh-exec", "http", "redfish"):
        for info in await managers[protocol].list_open():
            statuses.append(_plain_status(protocol, info))
    return statuses


async def close_on(
    managers: dict[str, Any],
    config: AppConfig,
    device: str,
    protocol: str | None,
) -> CloseResult:
    """Close one session, resolving ambiguity when protocol is omitted."""
    target = protocol
    if target is None:
        open_protocols = [
            name for name in PROTOCOL_ORDER if await managers[name].occupied(device)
        ]
        if not open_protocols:
            raise ProtocolError(
                f"no open session for device: {device}; call open_session first"
            )
        if len(open_protocols) > 1:
            raise ProtocolError(
                f"device {device} has several open sessions "
                f"({open_protocols}); pass protocol explicitly"
            )
        target = open_protocols[0]
    if target not in managers:
        raise ProtocolError(f"unknown protocol: {target}")
    await managers[target].close(device)
    return CloseResult(closed=True, device=device, protocol=target)


def _register_tools(mcp: FastMCP, managers: dict[str, Any], config: AppConfig) -> None:
    terminals: SSHTerminalManager = managers["ssh-terminal"]
    exec_channels: SSHExecManager = managers["ssh-exec"]
    webuis: HTTPManager = managers["http"]
    bmcs: RedfishManager = managers["redfish"]

    @mcp.tool()
    def list_devices() -> list[DeviceInfo]:
        """List known devices and the protocols each one speaks.

        Each entry carries a short human-written description (vendor,
        model, role) — read it before connecting instead of guessing
        from the device name.
        """
        return [device.public_info() for device in config.devices.values()]

    @mcp.tool()
    async def open_session(
        device: str,
        protocol: str | None = None,
        quiet_timeout_ms: int | None = None,
        deadline_ms: int | None = None,
        response_limit_bytes: int | None = None,
    ) -> SessionStatus:
        """Open (or reuse) a session and report its status.

        protocol may be omitted when the device exposes exactly one.
        The timeout/limit knobs apply to ssh-terminal reads only; other
        protocols treat opening as a connectivity/credential probe.
        """
        resolved = config.resolve_protocol(device, protocol)
        options = {
            "quiet_timeout_ms": quiet_timeout_ms,
            "deadline_ms": deadline_ms,
            "response_limit_bytes": response_limit_bytes,
        }
        return await open_on(managers, config, device, resolved, **options)

    @mcp.tool()
    async def list_sessions() -> list[SessionStatus]:
        """List all sessions across devices and protocols."""
        return await statuses_of(managers, config)

    @mcp.tool()
    async def close_session(device: str, protocol: str | None = None) -> CloseResult:
        """Close one session; omit protocol when only one is open."""
        return await close_on(managers, config, device, protocol)

    @mcp.tool()
    async def ssh_exec(
        device: str,
        command: str,
        stdin: str | None = None,
        timeout_seconds: float | None = None,
    ) -> SSHExecResult:
        """Run one command through the device's persistent ssh-exec session."""
        return await exec_channels.execute(
            config,
            device,
            command,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
        )

    @mcp.tool()
    async def http(
        device: str,
        method: str,
        path: str,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        body_base64: str | None = None,
        form: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        limit_bytes: int | None = None,
    ) -> HTTPResponseResult:
        """Send one authenticated WebUI request over the device's http protocol.

        Paths are relative to the device endpoint and must begin with `/`.
        Supply at most one of body, body_base64, and form. Appliance pages can
        be huge — pass limit_bytes to keep the body short (truncated reports
        whether anything was cut).
        """
        return await webuis.request(
            config,
            device,
            method,
            path,
            query=query,
            headers=headers,
            body=body,
            body_base64=body_base64,
            form=form,
            timeout_seconds=timeout_seconds,
            limit_bytes=limit_bytes,
        )

    @mcp.tool()
    async def redfish(
        device: str,
        method: str,
        path: str,
        query: dict[str, str | list[str]] | None = None,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        body_base64: str | None = None,
        form: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
        limit_bytes: int | None = None,
    ) -> HTTPResponseResult:
        """Send one authenticated Redfish REST call over the device's protocol.

        Paths must begin with `/`, typically under /redfish/v1. Supply at
        most one of body, body_base64, form, and json_body.
        """
        return await bmcs.request(
            config,
            device,
            method,
            path,
            query=query,
            headers=headers,
            body=body,
            body_base64=body_base64,
            form=form,
            json_body=json_body,
            timeout_seconds=timeout_seconds,
            limit_bytes=limit_bytes,
        )

    @mcp.tool()
    async def ssh_terminal(
        device: str,
        cursor: int,
        data: str | None = None,
        request_id: str | None = None,
        input_type: InputType = "line",
        expected_outbound_seq: int | None = None,
        force_write: bool = False,
        quiet_timeout_ms: int | None = None,
        deadline_ms: int | None = None,
        response_limit_bytes: int | None = None,
    ) -> ExchangeResult:
        """Write one terminal input and read output from the caller's cursor.

        Omit `data` to read output without writing. Reusing request_id
        returns the original result without writing twice. Carry next_cursor
        from each read into the next call. write_cursor marks where this
        write occurred, so earlier bytes in output are late output. A
        deadline or response limit leaves the session unsettled and blocks
        ordinary writes until more output is read.
        """
        config.device_protocol(device, "ssh-terminal")
        session = await terminals.get(device)
        if data is None:
            read = await session.read(
                cursor,
                quiet_timeout_ms=quiet_timeout_ms,
                deadline_ms=deadline_ms,
                response_limit_bytes=response_limit_bytes,
            )
            return ExchangeResult(
                output=read.output,
                from_cursor=read.from_cursor,
                write_cursor=cursor,
                next_cursor=read.next_cursor,
                read_stop_reason=read.read_stop_reason,
                elapsed_ms=read.elapsed_ms,
                connection_state=read.connection_state,
                request_id="read-only",
                outbound_seq=session.outbound_seq,
            )
        if not request_id:
            raise ProtocolError(
                "request_id is required when writing (data is set)"
            )
        return await session.exchange(
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

