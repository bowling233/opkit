"""Configuration model: accounts, devices, and their per-protocol configuration.

The schema centers on devices, not protocols — a physical machine appears
once under ``devices:`` and lists every way an agent may reach it:

    devices:
      - name: node1
        redfish:  {endpoint: https://10.0.0.3, account: lab-admin}
        ssh-exec: {endpoint: 10.0.0.3, account: lab-admin}

Each protocol's accepted keys and credential requirements are owned by the
protocol module itself (``parse_config``); this module only validates the
envelope (unique names, known protocol keys, known account references).
Credentials live in plaintext by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError, ProtocolError

from .protocols import http as _http_protocol
from .protocols import redfish as _redfish_protocol
from .protocols import ssh_exec as _ssh_exec_protocol
from .protocols import ssh_terminal as _ssh_terminal_protocol

# Single source of truth for which protocols a device can use.
# Key order also drives tooling output; keep stable.
PARSERS = {
    "ssh-terminal": _ssh_terminal_protocol.parse_config,
    "ssh-exec": _ssh_exec_protocol.parse_config,
    "http": _http_protocol.parse_config,
    "redfish": _redfish_protocol.parse_config,
}

PROTOCOL_NAMES = tuple(PARSERS)

ACCOUNT_FIELDS = {
    "username",
    "password",
    "ssh_private_key",
    "ssh_private_key_passphrase",
}


@dataclass(frozen=True)
class AccountConfig:
    """A named credential set referenced by device protocols."""

    name: str
    username: str | None = None
    password: str | None = None
    ssh_private_key: str | None = None
    ssh_private_key_passphrase: str | None = None


@dataclass(frozen=True)
class DeviceInfo:
    """What list_devices reveals: routing info, no secrets, one line per
    entry so a whole fleet fits in one cheap tool response."""

    name: str
    protocols: dict[str, str]


@dataclass(frozen=True)
class DeviceConfig:
    """One machine together with every protocol that reaches it."""

    name: str
    protocols: dict[str, Any]

    def public_info(self) -> DeviceInfo:
        return DeviceInfo(
            name=self.name,
            protocols={
                name: entry.brief()
                for name, entry in self.protocols.items()
            },
        )


@dataclass(frozen=True)
class AppConfig:
    accounts: dict[str, AccountConfig]
    devices: dict[str, DeviceConfig]
    source: Path | None = None

    def device(self, device_name: str) -> DeviceConfig:
        try:
            return self.devices[device_name]
        except KeyError as exc:
            raise ProtocolError(
                f"unknown device: {device_name}; call list_devices first"
            ) from exc

    def device_protocol(self, device_name: str, protocol: str) -> Any:
        device = self.device(device_name)
        try:
            return device.protocols[protocol]
        except KeyError as exc:
            raise ProtocolError(
                f"device {device_name} does not support {protocol}; "
                f"available protocols: {list(device.protocols)}"
            ) from exc

    def resolve_protocol(self, device_name: str, requested: str | None) -> str:
        """Pick the protocol for an operation when the caller omitted one."""
        device = self.device(device_name)
        available = list(device.protocols)
        if requested is not None:
            if requested not in available:
                raise ProtocolError(
                    f"device {device_name} does not support {requested}; "
                    f"available protocols: {available}"
                )
            return requested
        if len(available) == 1:
            return available[0]
        raise ProtocolError(
            f"device {device_name} exposes multiple protocols {available}; "
            "pass protocol explicitly"
        )


def load_config(path: str | Path) -> AppConfig:
    """Load and validate an operator configuration file."""
    source = Path(path).expanduser().resolve()
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot load configuration {source}: {exc}") from exc

    accounts = _load_accounts(raw.get("accounts") or [])
    devices = _load_devices(raw.get("devices") or [], accounts)
    if not devices:
        raise ConfigError(f"configuration {source} contains no devices")

    return AppConfig(accounts=accounts, devices=devices, source=source)


def _expect_mapping(label: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping, got {_type_name(value)}")
    return value


def _type_name(value: Any) -> str:
    return type(value).__name__


def _load_accounts(entries: Any) -> dict[str, AccountConfig]:
    if not isinstance(entries, list):
        raise ConfigError(
            f"accounts must be a list, got {_type_name(entries)}"
        )
    accounts: dict[str, AccountConfig] = {}
    for entry in entries:
        values = _expect_mapping("each account entry", entry)
        name = values.get("name")
        if not name or not isinstance(name, str):
            raise ConfigError(
                f"account entry {values!r} requires a string name"
            )
        unknown = set(values) - ACCOUNT_FIELDS - {"name"}
        if unknown:
            raise ConfigError(
                f"account {name} has unknown keys: {sorted(unknown)}"
            )
        if name in accounts:
            raise ConfigError(f"duplicate account name: {name}")
        fields: dict[str, Any] = {}
        for key in ACCOUNT_FIELDS:
            value = values.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                raise ConfigError(f"account {name}.{key} must be a string")
            fields[key] = value
        accounts[name] = AccountConfig(name=name, **fields)
    return accounts


def _load_devices(
    entries: Any,
    accounts: dict[str, AccountConfig],
) -> dict[str, DeviceConfig]:
    if not isinstance(entries, list):
        raise ConfigError(f"devices must be a list, got {_type_name(entries)}")
    devices: dict[str, DeviceConfig] = {}
    for entry in entries:
        values = _expect_mapping("each device entry", entry)
        name = values.get("name")
        if not name or not isinstance(name, str):
            raise ConfigError(f"device entry {values!r} requires a string name")
        if name in devices:
            raise ConfigError(f"duplicate device name: {name}")

        protocol_keys = [key for key in values if key != "name"]
        if not protocol_keys:
            raise ConfigError(f"device {name} has no protocols")
        unknown = set(protocol_keys) - set(PARSERS)
        if unknown:
            raise ConfigError(
                f"device {name} has unknown protocols: {sorted(unknown)} "
                f"(available: {list(PROTOCOL_NAMES)})"
            )

        protocols: dict[str, Any] = {}
        for protocol in protocol_keys:
            raw_config = _expect_mapping(
                f"{protocol} config of device {name}", values[protocol]
            )
            protocols[protocol] = PARSERS[protocol](name, raw_config, accounts)
        devices[name] = DeviceConfig(name=name, protocols=protocols)
    return devices
