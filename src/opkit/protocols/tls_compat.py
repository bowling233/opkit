"""TLS compatibility for old BMCs and appliance WebUIs.

Older management controllers commonly speak TLS 1.2 but offer only
static-RSA cipher suites, which modern OpenSSL defaults stopped
advertising years ago. This module restores interop with such devices by
appending four AES/SHA-2 RSA suites to Python's default cipher list.

This is kept deliberately despite opkit otherwise skipping defensive
hardening — it exists so connections succeed at all, not to protect
secrets. Certificate verification is always disabled project-wide;
TLS 1.0, SSLv3, 3DES, and RC4 remain off.

Both HTTP-family transports (the ``http`` and ``redfish`` protocols)
share this context via ``httpx.AsyncClient(verify=...)``.
"""

from __future__ import annotations

import ssl

_LEGACY_RSA_CIPHERS = (
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
)


def compatible_ssl_context() -> ssl.SSLContext:
    """Python's modern TLS defaults plus common older-BMC RSA suites."""
    context = ssl.create_default_context()
    default_ciphers = [
        cipher["name"]
        for cipher in context.get_ciphers()
        if cipher["protocol"] != "TLSv1.3"
    ]
    context.set_ciphers(":".join([*default_ciphers, *_LEGACY_RSA_CIPHERS]))
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
