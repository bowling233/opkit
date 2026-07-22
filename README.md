<div align="center">
  <h1> opkit </h1>

<center> Anything with a protocol can be connected and operated. </center>
</div>

**opkit** 是面向 AI Agent 运维场景的设备连接中间件，Agent 通过它连接、操作各类设备。它负责：

<sub><sup><strong>opkit</strong> is a device-connectivity middleware for AI-agent-driven operations: agents connect to and operate all kinds of devices through it. It is responsible for:</sup></sub>

- **凭据与会话管理**：
    - 访问设备的凭据对 Agent 不可见
    - 会话生命周期管理（例如 Redfish 如果不及时清理会话可能造成 BMC 卡死）  
    <sub><sup><strong>Credential and session management</strong>: device credentials stay invisible to the agent; session lifecycles are managed for it (e.g. an untidy Redfish logout can wedge a BMC).</sup></sub>
- **协议包装与适配**：
    - 对各类协议做基础包装，例如网络设备的 WebUI、SSH 终端等
    - 透传协议内容（例如终端字符、HTTP 报文），不对内容进行解析和识别  
    <sub><sup><strong>Protocol wrapping and adaptation</strong>: basic wrappers for each protocol — network-device WebUIs, SSH terminals, and so on — passing protocol content through (terminal characters, HTTP messages) without parsing or interpreting it.</sup></sub>

```mermaid
flowchart LR
    subgraph Agent 侧
        MCP[MCP 客户端]
        CLI[CLI]
        AstrBot[AstrBot Plugin]
    end
    subgraph opkit
        kernel[凭据与会话管理]
        proto[协议后端]
        kernel <--> proto
    end
    subgraph 设备
        webui[WebUI]
        sshd[SSH]
        bmc[BMC Redfish]
    end
    MCP --- kernel
    CLI --- kernel
    AstrBot --- kernel
    proto --> webui
    proto --> sshd
    proto --> bmc
```

## 使用方式 · USAGE

### MCP 工具

支持 HTTP 和 stdio，提供如下工具：

<sub><sup>Available over HTTP and stdio. The tools:</sup></sub>

- 会话管理：
    - `list_devices`：列出设备及其支持的协议
    - `open_session`：打开（或复用）会话，兼作连通性与凭据探针
    - `list_sessions`：列出当前所有会话
    - `close_session`：关闭会话  
    <sub><sup>Session management: <code>list_devices</code> lists devices and their protocols; <code>open_session</code> opens (or reuses) a session and doubles as a connectivity/credential probe; <code>list_sessions</code> lists everything currently open; <code>close_session</code> closes one.</sup></sub>
- 各类协议：
    - `ssh_exec`：SSH exec，单命令执行并返回结构化结果
    - `ssh_terminal`：SSH 终端的字节流写入与读取（`data` 省略时只读）
    - `http`：WebUI HTTP 请求
    - `redfish`：BMC Redfish 请求  
    <sub><sup>Per protocol: <code>ssh_exec</code> runs one command over SSH exec and returns a structured result; <code>ssh_terminal</code> writes and reads an SSH terminal's byte stream (omit <code>data</code> for a read-only poll); <code>http</code> sends WebUI HTTP requests; <code>redfish</code> sends BMC Redfish requests.</sup></sub>

### Astrbot Plugin(TODO)

### 配置 · CONFIGURATION

- **账户**：一份凭据，供各协议使用

    <sub><sup><strong>Accounts</strong>: one credential set, used by any protocol.</sup></sub>

    ```yaml
    accounts:
      - name: lab-admin
        username: admin
        password: plaintext-password   # intentional; keep this file out of VCS
      - name: net-op
        username: root
        ssh_private_key: |
          -----BEGIN OPENSSH PRIVATE KEY-----
    ```

- **设备和协议**：一个设备可以有多种协议，一个协议就是一种连接方式，不同协议的配置项不同  
    <sub><sup><strong>Devices and protocols</strong>: a device may expose several protocols; a protocol is one way in, and each protocol has its own config keys.</sup></sub>
- **用户名覆盖**：协议可设置 `username:` 覆盖账户的用户名，无需为部分用户名不可更改的厂商/协议创建多个凭据相同的账户  
    <sub><sup><strong>Username override</strong>: a protocol entry may set <code>username:</code> to override the account's — no need for duplicate accounts when a vendor fixes the login name.</sup></sub>

```yaml
devices:
  # One box, two channels.
  - name: node1
    redfish:
      endpoint: https://10.0.0.3
      account: lab-admin
    ssh-exec:
      endpoint: 10.0.0.3
      account: net-op

  - name: sw-core
    ssh-terminal:
      endpoint: 172.25.3.1
      port: 22
      account: net-op

  - name: cpe-ap
    http:
      endpoint: http://192.168.1.1
      auth: tplink                 # none | tplink | zte-be7200 | mellanox
      account: webui-only
```

`http` 协议下，不同设备有不同认证方式：

<sub><sup>Under the <code>http</code> protocol, different devices authenticate differently:</sup></sub>

| `auth` | Login flow | Username |
|---|---|---|
| `none` | 匿名访问 | — |
| `tplink` | 混淆密码 POST `/logon.cgi`；`g_tid` token 注入后续 `*.cgi` 请求 | 必填 |
| `zte-be7200` | password+login token 的 SHA-256 摘要；POST 请求注入 `_sessionTOKEN` | 必填——设置 `username: admin`（固件拒绝其他用户名） |
| `mellanox` | Onyx launch-script 表单登录 | 必填 |

<sub><sup><code>none</code>: anonymous. <code>tplink</code>: scrambled-password POST to <code>/logon.cgi</code> with a <code>g_tid</code> token injected into later <code>*.cgi</code> requests; username required. <code>zte-be7200</code>: SHA-256 digest of password + login token, with <code>_sessionTOKEN</code> injected into POSTs; set <code>username: admin</code> — the firmware rejects other names. <code>mellanox</code>: Onyx launch-script form login; username required.</sup></sub>

## 实测设备 · TESTED DEVICES

下表的传输行为均在生产硬件上端到端验证过（会话 open、operations、close）：

<sub><sup>Transport behavior in this table was verified end to end on production hardware (session open, operations, close):</sup></sub>

| Vendor and model | Software | Protocol |
| --- | --- | --- |
| Huawei S1730S-S48T4X-A1 | VRP 5.170 (V200R022C00SPC500) | `ssh-terminal` |
| Huawei S5720-28P-LI-AC | VRP 5.170 (V200R011C10SPC600) | `ssh-terminal` |
| Huawei S5720S-52P-LI-AC | VRP 5.170 (V200R011C10SPC600) | `ssh-terminal` |
| Huawei FutureMatrix S6720S-S24S28X-A | VRP 5.170 (V200R022C00SPC500) | `ssh-terminal` |
| MikroTik CCR2004-1G-12S+2XS (r3) | RouterOS 7.23.1 stable | `ssh-exec` |
| OpenWrt and ImmortalWrt devices | Various | `ssh-exec` |
| TP-Link TL-SG2226 / TL-SG2024D / TL-SE2206 | 2023–2024 WebUIs | `http: tplink` |
| ZTE 问天 BE7200 Pro+ (ZXSLC SR7410) | V1.0.0.4B8.8000 | `http: zte-be7200` |
| Mellanox SN2700 | Onyx 3.7.1134 | `http: mellanox` + `ssh-terminal` |

## 开发 · DEVELOPMENT

### 仓库结构

- `src`：源代码
- `docs/device-skills`：各类设备的操作经验  
    <sub><sup><code>src</code> holds the source; <code>docs/device-skills</code> collects operating experience for specific devices.</sup></sub>

### 新增协议

1. 写 `protocols/<name>.py`：协议的 dataclass + `parse_config`、拥有线上状态的 session 类、提供 `open / occupied / list_open / close / close_all` 的 manager。
2. 在 `opkit.config.PARSERS` 注册解析器。
3. 在 `opkit.mcp_server` 加它的操作工具。  
    <sub><sup>1. Write <code>protocols/&lt;name&gt;.py</code>: the protocol dataclass + <code>parse_config</code>, a session class owning its wire state, and a manager providing <code>open / occupied / list_open / close / close_all</code>. 2. Register the parser in <code>opkit.config.PARSERS</code>. 3. Add its operation tool in <code>opkit.mcp_server</code>.</sup></sub>

### WebUI 适配

一些厂商的 WebUI 对 Agent 不友好，直接抓取请求解析往往无法找到正确路径。一般建议 Agent 先使用浏览器操作 WebUI，同时抓取请求，然后形成 Skill。
<sub><sup>Some vendors' WebUIs are agent-hostile: sniffing requests up front rarely finds the right endpoints. The working approach is to drive the WebUI in a real browser once while capturing traffic, then distill that into a device skill.</sup></sub>

### 兼容性

为兼容各类老旧设备，默认采用如下配置：

<sub><sup>To stay compatible with aging devices, these defaults apply:</sup></sub>

- TLS/SSL
    - 证书验证全局关闭
    - 启用老版本协议（TLS 1.2 等）
- SSH
    - 主机公钥不校验
    - 启用弃用的 RSA 套件  
    <sub><sup>TLS/SSL: certificate verification is globally disabled; older protocol versions (TLS 1.2 and such) are enabled. SSH: host keys are not verified; deprecated RSA suites are enabled.</sup></sub>

### 安全性

协议内容透传不做脱敏，所以输出中的敏感内容可能仍会被暴露给 Agent，请使用可信的 Agent。  
<sub><sup>Protocol content is passed through without sanitization, so sensitive material in responses may still reach the agent — use agents you trust.</sup></sub>

调用方提交受管 header（cookie/authorization/host/x-auth-token）会被拒绝，因为那会破坏会话处理。  
<sub><sup>Callers submitting managed headers (cookie/authorization/host/x-auth-token) are rejected, because that would break session handling.</sup></sub>
