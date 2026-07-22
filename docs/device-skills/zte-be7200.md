# Device skill: ZTE 问天 BE7200 Pro+ (ZXSLC SR7410, V1.0.0.4B8.8000)

Agent-facing recipes for operations beyond opkit's generic HTTP passthrough.
opkit itself stays semantics-free; an agent that needs one of these
operations reads this file, then drives `http` on the opened
session. All requests below work on a session opened with the `zte-be7200` auth
profile — the profile handles login and injects `_sessionTOKEN` into every
form POST automatically.

## Response conventions

All CGI endpoints answer `200` with XML (`<ajax_response_xml_root>`).
Success is `<IF_ERRORTYPE>SUCC</IF_ERRORTYPE>`; failures put a
human-readable Chinese message into `<IF_ERRORSTR>` with HTTP still 200 —
**always read the body, never trust the status code**. An expired session
yields `SessionTimeout` in the body, which opkit's profile already converts
into re-authentication.

## Secret encoding (shared by all password-bearing forms)

The WebUI never sends plaintext or hash passwords. For each request it
draws two random 16-digit decimal strings `d` and `s`, then:

- AES-256-CBC encrypt each secret with `key = SHA256(d)` and
  `iv = SHA256(s)[:16]` (CryptoJS ignores the upper half of a 32-byte IV),
  ZeroPadding, and base64-encodes the ciphertext;
- RSA-encrypt the string `"{d}+{s}"` with the firmware's built-in public
  key (PKCS#1 v1.5) and base64-encode that as the `encode` field.

The embedded RSA public key (extract once from
`/jquery/static/js/app.<hash>.js`, `setPublicKey("-----BEGIN PUBLIC KEY-----...")`):

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV
7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb
1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9
hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc
fYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkS
-----END PUBLIC KEY-----
```

Python equivalent:

```python
import hashlib, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def encode_para(value: str, d: str, s: str, pub) -> str:
    key = hashlib.sha256(d.encode()).digest()
    iv = hashlib.sha256(s.encode()).digest()[:16]
    data = value.encode() + b"\x00" * (16 - len(value.encode()) % 16)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(ct).decode()

def encode_key(d: str, s: str, pub) -> str:
    blob = pub.encrypt(f"{d}+{s}".encode(), padding.PKCS1v15())
    return base64.b64encode(blob).decode()
```

## Operation: reset the management password

WebUI path: 安全 → 重置密码. The login-flow `action=changepwd` endpoint
(`/?_type=loginData&_tag=login_changepwd`) is **not** usable here — it only
acts while the firmware is in the forced-first-login state
(`LOGIN_CHGPWD_ID` present in `/?_type=hiddenData&_tag=vue_userif_data`)
and otherwise silently no-ops.

1. Optionally read the current username:
   `GET /?_type=vueData&_tag=user_info_data` → XML `OBJ_USERINFO_ID`
   contains `Username` (fixed `admin`; the login profile pins it anyway).
2. `POST /?_type=vueData&_tag=user_info_data`,
   `content-type: application/x-www-form-urlencoded`:

   | field | value |
   |---|---|
   | `IF_ACTION` | `Apply` |
   | `_InstID` | `IGD.AU1` |
   | `Username` | `admin` |
   | `Right` | `1` |
   | `Password` | encoded **old** password |
   | `NewPassword` | encoded **new** password |
   | `encode` | RSA-wrapped `{d}+{s}` |

   Both secrets use the *same* fresh `d`/`s` pair. Success:
   `<IF_ERRORTYPE>SUCC</IF_ERRORTYPE>`. A wrong old password yields
   `IF_ERRORSTR` = 旧密码有误，请检查参数设置。

The change applies immediately; existing WebUI sessions stay alive, but the
account that just changed its password should be re-verified with a fresh
`open_session`.

## Operation notes

- Login token endpoint: `GET /?_type=loginsceneData&_tag=login_token_json`
  (handled by the `zte-be7200` profile; listed for debugging).
- Session/user info: `GET /?_type=hiddenData&_tag=vue_userif_data`.
- The SPA serves chunk code lazily from `/jquery/static/js/<n>.<hash>.js`;
  the chunk map lives in `manifest.<hash>.js`. For first contact with an
  unknown operation, drive the WebUI in a real browser once and distill the
  wire format into a recipe here (see README "Scope").
