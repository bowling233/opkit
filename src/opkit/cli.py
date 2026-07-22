"""Command-line entry point: serve, validate, list, and probe.

Subcommands map one-to-one onto the MCP tools' semantics:

- ``serve``               run the MCP server (stdio by default)
- ``validate-config``     parse and validate a configuration file
- ``list-devices``        show what list_devices would report
- ``probe DEVICE``        open a session for real, dump its status,
                          and clean up — the manual smoke test

Errors exit with code 2 and a single ``error: ...`` line.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path

from .config import AppConfig, load_config
from .errors import OpkitError
from .mcp_server import (
    PROTOCOL_ORDER,
    create_http_app,
    create_managers,
    create_server,
    open_on,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opkit",
        description=(
            "Session-oriented connectivity between AI agents and machines "
            "over their native management protocols"
        ),
    )
    parser.add_argument("--config", required=True, type=Path, help="YAML device file")
    subparsers = parser.add_subparsers(dest="command")
    serve = subparsers.add_parser("serve", help="run the MCP server")
    serve.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default="stdio",
    )
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--http-path", default="/mcp")
    serve.add_argument("--json-response", action="store_true")
    subparsers.add_parser("validate-config", help="validate configuration and exit")
    subparsers.add_parser("list-devices", help="list configured devices as JSON")
    probe = subparsers.add_parser(
        "probe", help="open a session, dump its status, and close it"
    )
    probe.add_argument("device")
    probe.add_argument("--protocol", choices=PROTOCOL_ORDER)
    probe.add_argument("--quiet-timeout-ms", type=int)
    probe.add_argument("--deadline-ms", type=int)
    return parser


def _json(data: object) -> None:
    print(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            default=lambda value: asdict(value) if is_dataclass(value) else str(value),
        )
    )


async def _probe(config: AppConfig, device: str, protocol: str | None,
                 quiet_ms: int | None, deadline_ms: int | None) -> None:
    managers = create_managers()
    try:
        resolved = config.resolve_protocol(device, protocol)
        options: dict[str, object] = {}
        if resolved == "ssh-terminal":
            options = {
                "quiet_timeout_ms": quiet_ms,
                "deadline_ms": deadline_ms,
            }
        status = await open_on(managers, config, device, resolved, **options)
        _json({"session": status})
    finally:
        for manager in managers.values():
            await manager.close_all()


def main() -> None:
    args = build_parser().parse_args()
    command = args.command or "serve"
    try:
        config = load_config(args.config)
        if command == "validate-config":
            _json({"valid": True, "config": str(config.source)})
            return
        if command == "list-devices":
            _json([device.public_info() for device in config.devices.values()])
            return
        if command == "probe":
            asyncio.run(
                _probe(
                    config,
                    args.device,
                    getattr(args, "protocol", None),
                    args.quiet_timeout_ms,
                    args.deadline_ms,
                )
            )
            return
        if getattr(args, "transport", "stdio") == "streamable-http":
            # Stateless streamable HTTP: no Mcp-Session-Id is ever issued,
            # so clients survive server restarts without re-initializing.
            import uvicorn

            uvicorn.run(
                create_http_app(
                    config,
                    http_path=args.http_path,
                    json_response=args.json_response,
                ),
                host=args.host,
                port=args.port,
                log_level="info",
            )
            return
        mcp = create_server(config)
        mcp.run(transport=args.transport)
    except OpkitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
