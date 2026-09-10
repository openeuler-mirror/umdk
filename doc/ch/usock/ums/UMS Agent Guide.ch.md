# UMS Agent Guide
本文档面向系统管理员与部署工程师，介绍 UMS 安全代理 ums_agent 的定位、架构、安装、配置、证书管理、服务运维与故障排查。UMS 与 Token 模式的基础概念详见 [UMS User Guide](./UMS%20User%20Guide.ch.md)，socket 编程接口详见 [UMS API Guide](./UMS%20API%20Guide.ch.md)。

## 1. 概述
### 1.1 定位
ums_agent 是 UMS 的**用户态安全代理**，作为 systemd 服务运行。在 SECURE Token 模式（`ub_token_mode=0`）下，ums_agent 基于TLS 1.3 加密通道在跨节点 UMS 内核模块之间带外交换 UB TokenValue，消除控制面 Token 明文传输风险。ums_agent 仅负责 TokenValue 的安全传输，不参与 Token 生成（TokenValue 由内核生成），不持久化存储 TokenValue（传输并下发后立即清零）。

LEGACY 与 DISABLE 模式下内核不使用 ums_agent。ums_agent 允许在这两种模式下启动（便于预部署），但内核不会向其提交 Token。

### 1.2 核心能力
- 基于 OpenSSL TLS 1.3 的跨节点加密通道建立与维护（连接池，按需建连）
- X.509 证书双向认证
- 与 UMS 内核模块的 Netlink 通信
- TokenValue 的安全协商、下发与清零
- systemd `Type=notify` 服务化运行，支持故障自动重启
- 以专用系统用户 `ums` 最小权限运行（仅 `CAP_NET_ADMIN`）

### 1.3 适用场景
- 生产环境，安全合规要求 TokenValue 加密传输
- 应用层未启用 TLS，需防止 TokenValue 泄露直接暴露数据面
- 应用层已启用 TLS，仍需对控制面凭据传输做纵深防御

模式选型与成本权衡详见 [UMS User Guide - 5. Token 模式与安全](./UMS%20User%20Guide.ch.md#5-token-模式与安全)。

## 2. TokenValue 交换过程
SECURE 模式下，一次 UMS 建链涉及四条通道：

| 通道 | 承载内容 | 说明 |
| ---- | -------- | ---- |
| TCP clcsock（控制面） | CLC 握手 Proposal/Accept/Confirm | SECURE 模式下 Token 字段填 0 占位 |
| TLS 1.3 通道（带外） | TokenValue | ums_agent 之间，默认端口 61080 |
| Netlink（节点内） | TOKEN_SUBMIT / TOKEN_DELIVER | UMS 内核 ↔ 本节点 ums_agent |
| UB 网络（数据面） | 应用数据 | 建链完成后经 URMA Jetty/SEG 传输 |

SECURE 模式下，CLC 握手（Proposal → Accept → Confirm）过程中 Token 字段填 0 占位，双方 TokenValue 通过 ums_agent TLS 1.3 通道带外交换。应用调用 `connect()` 触发 CLC Proposal 后，每个方向的 TokenValue 均由本端内核生成，沿以下路径送达对端内核：

本端内核生成 TokenValue → `TOKEN_SUBMIT`（Netlink）→ 本端 ums_agent → TLS 1.3 通道 → 对端 ums_agent → `TOKEN_DELIVER`（Netlink）→ 对端内核存储

反向流程同理。TokenValue 交换与 CLC Accept/Confirm 并行推进：双方内核均取得对端 TokenValue 后，CLC 协商握手方可完成，UMS 数据面 URMA 通道建链成功。

## 3. 前置条件
### 3.1 系统要求
| 要求 | 说明 |
| ---- | ---- |
| 操作系统 | openEuler（内核版本 ≥ 6.6） |
| UMS 内核模块 | 已安装并加载 `ums.ko`，且 `ub_token_mode=0`（SECURE） |
| UB 硬件 | 已部署 UB 网络设备，URMA 组件已安装配置 |
| 网络连通 | 所有节点间 TCP 可达（ums_agent 默认监听端口 61080） |
| 系统用户 | `umdk-ums-agent` 包安装时会自动创建系统用户 `ums` |

### 3.2 PKI 证书体系
SECURE 模式要求部署 X.509 证书体系。所有节点须使用同一 CA 签发的证书，ums_agent 同时充当 TLS 服务端与客户端，需分别配置服务端与客户端证书。

| 证书/文件 | 用途 | 要求 |
| --------- | ---- | ---- |
| CA 证书（ca.crt） | 验证对端证书链 | 所有节点一致 |
| 服务端证书（server.crt） | TLS 服务端身份认证 | 建议包含本节点 IP 的 SAN 扩展 |
| 服务端私钥（server.key） | 服务端证书对应私钥 | 必须加密存储（PEM 格式），口令载入 Keyring |
| 客户端证书（client.crt） | TLS 客户端身份认证 | 由同一 CA 签发 |
| 客户端私钥（client.key） | 客户端证书对应私钥 | 必须加密存储（PEM 格式），口令载入 Keyring |
| CRL（crl.pem，可选） | 证书吊销列表 | 启动时加载，更新需重启 ums_agent |

### 3.3 ums 系统用户
ums_agent 以专用系统用户 `ums` 运行。RPM 安装时通过 `%pre` 脚本自动创建：
```
用户名: ums
类型:   系统用户 (-r)
Shell:  /sbin/nologin
Home:   /var/lib/ums
```
如需手动创建：
```bash
sudo useradd -r -s /sbin/nologin -d /var/lib/ums ums
```

### 3.4 私钥口令与 Linux Keyring
ums_agent 启动时从 Linux Keyring（`@u` 用户密钥环）读取私钥解密口令。口令必须在 ums_agent 启动前加载。systemd 服务配置 `KeyringMode=shared`，确保服务可访问 `ums` 用户的 Keyring。

```bash
# 方式1：手动注入
# 以 ums 用户身份加载私钥口令到 Keyring (@u)
# <desc> 为配置文件中 prkey_pwd_desc 的值，<passphrase> 为私钥解密口令
# 注意：以下命令仅限开发测试环境，生产环境应使用符合安全规范的方式加载，避免命令行暴露口令明文
sudo -u ums keyctl add user <desc> <passphrase> @u

# 方式2：通过systemd预启动阶段（ExecStartPre）自动完成口令注入
# 通过systemd预启动阶段自动完成口令注入
# 在 ums_agent.service 文件的 [Service] 中配置ExecStartPre阶段执行脚本
# 示例：ExecStartPre=/etc/ums_agent/ums_prkey_pwd_init.sh

# 查看口令注入结果
sudo -u ums keyctl list @u
```

## 4. 安装
### 4.1 RPM 包信息
ums_agent 通过 `umdk-ums-agent` 子包安装，是 UMDK RPM 的一部分。

| 属性 | 值 |
| ---- | -- |
| 子包名 | `umdk-ums-agent` |
| 摘要 | UMS Agent daemon for secure token exchange |
| 运行时依赖 | `systemd-libs`、`glib2`、`libnl3`、`openssl`、`keyutils` |
| 安装前依赖 | `shadow-utils`（创建 ums 系统用户） |
| 构建依赖 | `systemd-devel`、`keyutils-libs-devel`、`openssl-devel` |

### 4.2 安装文件清单
| 文件路径 | 权限 | 属主 | 说明 |
| ------- | ---- | ---- | ---- |
| `/usr/sbin/ums_agent` | 750 | root:ums | ums_agent 可执行文件 |
| `/usr/lib/systemd/system/ums_agent.service` | 644 | root:root | systemd 服务单元 |
| `/etc/ums_agent/` | 750 | root:ums | 配置目录 |
| `/etc/ums_agent/ums_agent.conf` | 640 | root:ums | 主配置文件（`config(noreplace)`，升级不覆盖） |
| `/etc/rsyslog.d/ums_agent.conf` | 644 | root:root | rsyslog 日志配置 |
| `/etc/logrotate.d/ums_agent` | 644 | root:root | 日志轮转配置 |

说明：证书文件（`/etc/ums_agent/certs/`）不由 ums_agent 提供，需管理员自行生成并部署（见 [6. 证书与密钥管理](#6-证书与密钥管理)）。

### 4.3 安装与卸载
**安装**：
```bash
sudo rpm -ivh umdk-ums-agent-*.rpm
```
安装时自动执行：创建 `ums` 系统用户（`%pre`）→ 重启 rsyslog（`%post`）→ 通过 systemd 宏启用 `ums_agent.service`（不自动启动）。

**验证安装**：
```bash
ls -la /usr/sbin/ums_agent
systemctl cat ums_agent.service
ls -la /etc/ums_agent/
id ums
```

**卸载**：
```bash
sudo rpm -e umdk-ums-agent
```
卸载前会自动停止并禁用 `ums_agent.service`。

## 5. 配置
### 5.1 ums_agent.conf
配置文件路径：`/etc/ums_agent/ums_agent.conf`，权限 640，属主 root:ums。修改后需重启服务生效：
```bash
sudo systemctl restart ums_agent
```

**配置项参考**：

| 节 | 配置项 | 必填 | 默认值 | 说明 |
| -- | ------ | ---- | ------ | ---- |
| `[logging]` | `log_level` | 否 | `info` | 日志级别：emerg/alert/crit/err/warning/notice/info/debug |
| `[authenticate.client]` | `x509.truststore` | 是 | — | CA 证书路径，验证对端证书链，所有节点须一致 |
| `[authenticate.client]` | `x509.certificate` | 是 | — | 客户端证书路径 |
| `[authenticate.client]` | `x509.private_key` | 是 | — | 客户端私钥路径，须加密存储，口令载入 Keyring（`@u`） |
| `[authenticate.client]` | `x509.prkey_pwd_desc` | 是 | — | 客户端私钥口令在 Keyring（`@u`）的描述符，长度 < 128 字符 |
| `[authenticate.client]` | `x509.crl` | 否 | 空 | 客户端侧 CRL 路径 |
| `[authenticate.server]` | `x509.truststore` | 是 | — | CA 证书路径，同上 |
| `[authenticate.server]` | `x509.certificate` | 是 | — | 服务端证书路径 |
| `[authenticate.server]` | `x509.private_key` | 是 | — | 服务端私钥路径，须加密存储 |
| `[authenticate.server]` | `x509.prkey_pwd_desc` | 是 | — | 服务端私钥口令在 Keyring（`@u`）的描述符 |
| `[authenticate.server]` | `x509.crl` | 否 | 空 | 服务端侧 CRL 路径 |
| `[network]` | `listen_port` | 否 | `61080` | TLS 监听端口，范围 1024–65535 |
| `[network]` | `listen_addr` | 是 | — | TLS 监听地址，须与本节点建立 UMS socket 连接使用的本地 IP 一致；支持 IPv4/IPv6，不支持主机名 |
| `[network]` | `max_conns` | 否 | `1024` | 最大并发 TLS 连接数（连接池大小），范围 1–65535 |
| `[tls]` | `cipher_suite` | 否 | `TLS_AES_256_GCM_SHA384` | TLS 1.3 密码套件，当前仅支持此套件 |

**配置示例（SECURE 模式生产环境）**：
```ini
[logging]
# log_level optional value: emerg, alert, crit, err, warning, notice, info, debug
log_level=info

# Authenticate x509 Options
# -------------------------------------------------------------------------------
# x509.truststore    : (REQUIRED) Path to trusted CA certificate store (verify peer certificate)
# x509.crl           : Path to Certificate Revocation List (optional, can be empty)
# x509.certificate   : (REQUIRED) Path to local certificate (present identity to peer)
# x509.private_key   : (REQUIRED) Path to local private key (for TLS signing, private key file should be encrypted)
# x509.prkey_pwd_desc: (REQUIRED) Private key decryption password from Keyring (@u)
#                      IMPORTANT: Password must be stored in Keyring (@u) before service starts
#                                 Methods: 1) keyctl manually, 2) ExecStartPre in ums_agent.service
# -------------------------------------------------------------------------------

[authenticate.client]
x509.truststore=/etc/ums_agent/certs/ca.crt
# x509.crl=/etc/ums_agent/certs/crl.pem
x509.certificate=/etc/ums_agent/certs/client.crt
x509.private_key=/etc/ums_agent/certs/client.key
x509.prkey_pwd_desc=client_private_key_passphrase

[authenticate.server]
x509.truststore=/etc/ums_agent/certs/ca.crt
# x509.crl=/etc/ums_agent/certs/crl.pem
x509.certificate=/etc/ums_agent/certs/server.crt
x509.private_key=/etc/ums_agent/certs/server.key
x509.prkey_pwd_desc=server_private_key_passphrase

[network]
# listen_port: TCP/TLS listen port for inter-node ums_agent communication
listen_port=61080
# listen_addr: (REQUIRED) TCP/TLS listen address, must be consistent with the local IP address
#              used for establishing UMS socket connection
#              Format: IPv4 (e.g., 192.0.2.10) or IPv6 (e.g., 2001:db8::1)
#              Hostname is NOT supported
listen_addr=192.0.2.10

# max_conns: Maximum concurrent TCP/TLS connections (connection pool size), valid range: 1-65535
max_conns=1024

[tls]
# cipher_suite: TLS 1.3 cipher suite for secure channel
# Supported: TLS_AES_256_GCM_SHA384
cipher_suite=TLS_AES_256_GCM_SHA384
```

**配置要点**：
1. `listen_addr` 必须与该节点建立 UMS socket 连接所使用的本地 IP 一致，否则对端 ums_agent 无法回连。
2. ums_agent 同时作为 TLS 服务端和客户端，客户端与服务端证书须分别配置。
3. 私钥必须以加密形式存储（PEM），启动时通过 Keyring 查询口令解密。
4. `prkey_pwd_desc` 须与加载口令到 Keyring 时使用的描述符一致。
5. CRL 仅在启动时加载，更新 CRL 需重启 ums_agent。

### 5.2 内核模块参数
SECURE 模式要求 UMS 内核模块以 `ub_token_mode=0` 加载，参数完整说明与配置示例详见 [UMS User Guide - 3.4 内核模块参数配置](./UMS%20User%20Guide.ch.md#34-内核模块参数配置)。本节仅说明与 ums_agent 直接相关的 `ums_agent_uid`/`ums_agent_gid` 配置机制。

`ums_agent_uid` / `ums_agent_gid` 默认为 0（仅允许 root 注册）。生产环境推荐由 systemd `ExecStartPre` 在 ums_agent 启动前自动写入 `ums` 系统用户的 UID/GID（默认行为，详见 [5.3 systemd 服务](#53-systemd-服务)），使 ums_agent 以最小权限运行。

如需在模块加载时即采用 `ums` 用户身份校验（不依赖 `ExecStartPre`），可通过 `/etc/modprobe.d/ums.conf` 预配置：
```bash
# /etc/modprobe.d/ums.conf
options ums ub_token_mode=0 ums_agent_uid=<ums用户UID> ums_agent_gid=<ums用户GID>
```

注意：`ums_agent_uid`/`ums_agent_gid` 在 agent 在线时不可修改，修改需在 agent 离线时进行。

### 5.3 systemd 服务
默认服务单元：`/usr/lib/systemd/system/ums_agent.service`。如需自定义，创建 `/etc/systemd/system/ums_agent.service` 覆盖，修改后执行 `systemctl daemon-reload`。

**默认服务单元关键配置**：
```ini
[Unit]
Description=Security Agent for kernel UMS module
After=network.target
Documentation=man:ums_agent(8)

StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=notify
User=ums
Group=ums
KeyringMode=shared

ExecStartPre=+/bin/sh -c 'id -u ums > /sys/module/ums/parameters/ums_agent_uid'
ExecStartPre=+/bin/sh -c 'id -g ums > /sys/module/ums/parameters/ums_agent_gid'
ExecStart=/usr/sbin/ums_agent --config /etc/ums_agent/ums_agent.conf
ExecStopPost=+/bin/sh -c 'echo 0 > /sys/module/ums/parameters/ums_agent_uid'
ExecStopPost=+/bin/sh -c 'echo 0 > /sys/module/ums/parameters/ums_agent_gid'

CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=yes

Restart=on-failure
RestartSec=3s

KillSignal=SIGTERM
TimeoutStopSec=10s

[Install]
WantedBy=multi-user.target
```

| 配置项 | 说明 |
| ------ | ---- |
| `KeyringMode=shared` | **必须**，使 ums_agent 可访问 `ums` 用户 Keyring（`@u`）读取私钥口令 |
| `ExecStartPre` | 将 `ums_agent_uid`/`ums_agent_gid` 写为 `ums` 用户的 UID/GID，使 agent 以最小权限注册 |
| `ExecStopPost` | 服务停止后将 `ums_agent_uid`/`ums_agent_gid` 重置为 0（恢复 root-only） |
| `CapabilityBoundingSet=CAP_NET_ADMIN` | 仅授予 Netlink 通信所需最小能力 |
| `NoNewPrivileges=yes` | 阻止子进程获取额外权限 |

**命令行选项**：
```bash
ums_agent --config <path>   # 指定配置文件，路径必须位于 /etc/ums_agent/ 下
ums_agent --version         # 查看版本
ums_agent --help            # 查看帮助
```

## 6. 证书与密钥管理
### 6.1 证书目录与权限
```bash
sudo mkdir -p /etc/ums_agent/certs
sudo chown root:ums /etc/ums_agent/certs
sudo chmod 750 /etc/ums_agent/certs

# 证书文件
sudo chmod 644 /etc/ums_agent/certs/ca.crt
sudo chmod 644 /etc/ums_agent/certs/server.crt /etc/ums_agent/certs/client.crt
sudo chmod 640 /etc/ums_agent/certs/server.key /etc/ums_agent/certs/client.key
sudo chown root:ums /etc/ums_agent/certs/server.key /etc/ums_agent/certs/client.key
```

### 6.2 证书生成示例（开发测试环境）
以下步骤仅适用于开发测试环境，生产环境应使用组织内部 PKI 体系签发证书。

```bash
# 生成一个自签名的CA根证书以及对应的RSA私钥
openssl req -newkey rsa:2048 -passout pass:123456 -keyout ca_rsa_private.pem -x509 -days 365 -out ca.crt -subj "/C=CN/ST=Beijing/O=UMS-Test/CN=UMS Test CA"

# 为服务端生成RSA私钥文件（加密保护）和证书签名请求（CSR）文件
openssl req -newkey rsa:2048 -passout pass:srv123 -keyout server_rsa_private.pem -out server.csr -subj "/C=CN/ST=Beijing/O=UMS-Test/CN=ums-server"

# 使用CA根证书及私钥签发服务端证书
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca_rsa_private.pem -passin pass:123456 -CAcreateserial -out server.crt

# 为客户端生成RSA私钥文件（加密保护）和证书签名请求（CSR）文件
openssl req -newkey rsa:2048 -passout pass:clnt123 -keyout client_rsa_private.pem -out client.csr -subj "/C=CN/ST=Beijing/O=UMS-Test/CN=ums-client"

# 使用CA根证书及私钥签发客户端证书
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca_rsa_private.pem -passin pass:123456 -CAcreateserial -out client.crt

# 5. 部署
sudo cp ca.crt server.crt client.crt /etc/ums_agent/certs/
sudo cp server_encrypted.key /etc/ums_agent/certs/server.key
sudo cp client_encrypted.key /etc/ums_agent/certs/client.key

# 按 §6.1 设置目录与文件权限
```

### 6.3 证书更新
1. 申请新证书（使用现有 CA 重新签发，或使用新 CA）。
2. 替换证书与私钥文件。
3. 重新加载私钥口令到 Keyring（`@u`）。
4. 重启 ums_agent：
   ```bash
   sudo systemctl restart ums_agent
   ```
更换 CA 时，须确保所有节点同步更新，否则双向认证失败。

### 6.4 证书吊销示例
1. 生成 CRL：`openssl ca -gencrl -out crl.pem -config openssl.cnf`
2. 部署：`sudo cp crl.pem /etc/ums_agent/certs/crl.pem`
3. 在 `ums_agent.conf` 的 `[authenticate.client]` 与 `[authenticate.server]` 节配置 `x509.crl` 路径。
4. 重启 ums_agent。

CRL 仅在启动时加载，更新 CRL 需重启 ums_agent。

## 7. 服务管理
### 7.1 启动前检查
首次启动前确保：
1. 已安装 `umdk-ums-agent` 包
2. 证书已部署到 `/etc/ums_agent/certs/`
3. `/etc/ums_agent/ums_agent.conf` 已正确配置（尤其 `listen_addr`）
4. 私钥口令已加载到 Keyring（`@u`）
5. UMS 内核模块已加载且 `ub_token_mode=0`

### 7.2 常用命令
```bash
sudo systemctl start ums_agent      # 启动
sudo systemctl stop ums_agent       # 停止（停止后内核 available 置 0，后续 CLC 握手因无法提交 Token 而 Decline）
sudo systemctl restart ums_agent    # 重启
sudo systemctl status ums_agent     # 查看状态
sudo systemctl enable ums_agent     # 开机自启
sudo systemctl disable ums_agent    # 禁用开机自启
```

### 7.3 日志
ums_agent 日志通过 rsyslog 输出到 `/var/log/umdk/ums/ums_agent/ums_agent.log`，格式为：
```
RFC3339时间戳|严重级别|进程名[PID]|消息
```

```bash
# 实时跟踪日志文件
sudo tail -f /var/log/umdk/ums/ums_agent/ums_agent.log
# 通过 journalctl 实时跟踪服务日志
sudo journalctl -u ums_agent -f
# 按时间范围检索服务日志
sudo journalctl -u ums_agent --since "2026-05-28 10:00:00" --until "2026-05-28 11:00:00"
```

日志轮转由 logrotate 管理：最大保留 365 天，轮转 30 次，超过 1024k 自动轮转，压缩存储。默认配置文件为 `/etc/logrotate.d/ums_agent`，如有需要可自行修改。

## 8. 模式互通
### 8.1 互通矩阵
| 本端模式 \ 对端模式 | SECURE(0) | LEGACY(1) | DISABLE(2) |
| ------------------- | --------- | --------- | ---------- |
| SECURE(0) | 互通 | 不互通（`UMS_CLC_DECL_TOKMDMIS` (0x09990006)，回退 TCP） | 不互通（回退 TCP） |
| LEGACY(1) | 不互通（回退 TCP） | 互通 | 互通 |
| DISABLE(2) | 不互通（回退 TCP） | 互通 | 互通 |

规则：SECURE 仅与 SECURE 互通；LEGACY 与 DISABLE 之间可互通。所有节点须统一配置同一模式。

## 9. 故障排查
### 9.1 常见问题
| 现象 | 可能原因 | 排查建议 |
| ---- | -------- | -------- |
| `systemctl status ums_agent` 显示启动失败 | 配置文件缺失或必填项未填 | 检查 `/etc/ums_agent/ums_agent.conf`，确认 `listen_addr` 与证书/私钥文件路径已配置 |
| 日志报私钥口令读取失败 | Keyring 中未加载口令，或 `prkey_pwd_desc` 不匹配 | 以 `ums` 用户执行 `keyctl list @u` 确认口令已加载；核对描述符与配置一致 |
| TLS 握手失败 | 证书未由同一 CA 签发，或证书过期 | 确认所有节点 `ca.crt` 一致；`openssl x509 -in <cert> -noout -dates` 检查有效期 |
| UMS 内核 CLC 握手报错 `UMS_CLC_DECL_TOKMDMIS` (0x09990006) | 节点间 `ub_token_mode` 不一致 | 检查所有节点 `dmesg | grep "UMS_" | grep "ub_token_mode="`，统一为 SECURE(0) |
| ums_agent 在线但 UMS 建链仍 Decline | ums_agent 未成功注册到内核 | 查看内核日志 `dmesg | grep ums`，确认 agent available；确认 `ums_agent_uid/gid` 与运行用户匹配 |
| `ums_agent_uid` 修改返回 `-EBUSY` | agent 在线时不允许修改 | 先 `systemctl stop ums_agent`，再修改，再启动 |

### 9.2 诊断命令
```bash
# 内核侧：查看 token 模式（ub_token_mode 权限为 0，只能从加载日志确认，UMS 日志前缀为 [UMS_)
dmesg | grep "UMS_" | grep "ub_token_mode="
# 查看 agent 身份参数（0644，可读写）
cat /sys/module/ums/parameters/ums_agent_uid
cat /sys/module/ums/parameters/ums_agent_gid
# 查看 agent 注册与 token 相关内核日志
dmesg | grep "UMS_"

# agent 侧：服务状态与日志
systemctl status ums_agent
sudo tail -100 /var/log/umdk/ums/ums_agent/ums_agent.log

# 连接状态
cat /proc/net/ums
```

## 10. 相关文档
- [UMS User Guide](./UMS%20User%20Guide.ch.md)：UMS 介绍、安装、使用方式、Token 模式与安全说明。
- [UMS API Guide](./UMS%20API%20Guide.ch.md)：UMS socket 编程接口、proc/sysctl 服务接口、运行时模块参数查询。
