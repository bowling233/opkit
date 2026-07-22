# Device skill: Mellanox Onyx (SN2700, Onyx 3.7.1134)

Agent-facing recipes for the Onyx WebUI's JSON command API — the most
efficient channel on this device: a CLI command round-trips over HTTP in a
few hundred bytes with structured JSON output, no PTY/terminal semantics
needed. Open a session with the `mellanox` auth profile first; the profile
handles the launch-script form login.

## Command channel: `POST /admin/launch?script=json`

- Headers: `content-type: application/json`.
- Body: `{"cmd": "<Onyx CLI command>"}` — exactly `cmd`, **not** `cmds`
  (a `cmds` array is this firmware's "no command found" trap).
- Response JSON: `status` (`OK`/`ERROR`), `executed_command`,
  `status_message` (the CLI error text on failure), and `data` (string for
  plain commands, object for commands Onyx parses, e.g. `show version`).
- The session executes at admin privilege **already inside configuration
  mode**: `username ...` works directly, while a literal
  `configure terminal` fails with "Unrecognized command".
- CLI help (`?`) does not pass through the JSON channel; use the
  `ssh-terminal` protocol when exploring syntax interactively.

## Account management (verified)

```
username <name> password <password>   # create user, no interactive retype over the API
username <name> ?                     # (ssh-terminal, config mode) — no sshkey subcommand
enable                                # new users land in user shell; admin users enter # without password
configuration write                   # persist; changes are lost otherwise
```

Inbound SSH public-key authentication is **not supported** on Onyx 3.7:
`username` has no `sshkey` subcommand, and `ssh client user` configures
keys for the switch acting as an *outbound* SSH client only. The WebUI has
no key management either — password auth is the only inbound option.

The exec SSH channel (`exec_command`) is rejected with "UNIX shell
commands cannot be executed using this account"; use the `ssh-terminal`
protocol (PTY) for CLI over SSH.

The built-in `admin` account **cannot be disabled, deleted, or renamed**
(the firmware answers "Admin account may not be disabled/deleted"). The
only hardening available is rotating its password — ideally to the shared
lab password so no default credential remains.

## Operation: rotate a user password

1. `POST` `{"cmd": "username <name> password <new-password>"}` — also
   creates the user if absent (default role: admin-capable, `enable`
   enters privileged mode without a password).
2. `POST` `{"cmd": "configuration write"}`.
3. Verify by opening a fresh session with the new credentials.
