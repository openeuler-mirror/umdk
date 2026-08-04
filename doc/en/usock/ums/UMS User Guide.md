# UMS
## 1. Introduction
UMS is a kernel-level network protocol stack that is compatible with the standard socket API and based on the UB network for data transmission, transparently accelerating TCP communication. Developed as an extension of the SMC-R protocol and the kernel SMC-R source code, UMS implements a Shared Memory Communication (SMC) protocol based on UMDK. It is designed to fully leverage the performance advantages of Huawei's UB hardware, enhancing overall network transmission efficiency. As a high-performance communication protocol built on the UB network architecture, UMS offers low-latency, high-throughput data transfer capabilities, making it particularly suitable for performance-sensitive applications such as Redis, databases, AI training and inference, and distributed caching.

## 2. Software Architecture
**Maintains compatibility with standard TCP sockets.** \
UMS works in the Linux kernel space, maintains compatibility with the standard socket API, and utilizes the TCP protocol for connection establishment. In case of negotiation errors, it automatically falls back to standard TCP communication. By leveraging SMC-R's transparent replacement technology, UMS enables seamless network acceleration without requiring any modifications to the application layer.

**Based on UMDK-URMA API** \
UMS leverages the Huawei UMDK-URMA component to fully utilize the performance advantages of the UB network.

**Based on SMC-R protocol currently**
* Follows the fundamental workflow and data structure design of the SMC-R protocol, serving as a basis for further development.
* Optimized for low latency in small message scenarios, significantly improving transmission efficiency.
* Future enhancements will include: introducing multi-path communication mechanisms, improving flow control strategies, and achieving higher concurrency and stronger robustness.
* UMS will be based on UB protocol instead of SMC-R protocol in the future.

**Optional userspace security agent service ums_agent** \
UMS provides an optional userspace security agent service, ums_agent, which exchanges UB TokenValue out-of-band over a TLS 1.3 encrypted channel in SECURE Token mode, eliminating the risk of plaintext Token transmission over the control plane. ums_agent is packaged independently (`umdk-ums-agent`), deployed independently, and runs as a systemd service. It is only used by the kernel in SECURE mode. For deployment and operations details, see [UMS Agent Guide](./UMS%20Agent%20Guide.md).

## 3. Installation and Configuration
### 3.1 How to Check if the Kernel Supports the SMC Protocol
```bash
cat /boot/config-$(uname -r) | grep CONFIG_SMC
```
If the command output shows CONFIG_SMC=m, it indicates that the current kernel version supports the SMC protocol. Once the environment compatibility is confirmed, proceed with the deployment steps described below.

### 3.2 Build UMS RPM Packages
**Obtain from the UMDK build artifacts** \
Refer to the overall build steps for UMDK.

**Build UMS separately**
1. Navigate to the root directory of the UMDK project
2. tar -cvf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git $(ls -A)
3. rpmbuild -ba umdk.spec --with ums

**UMS Additional Build Options**

The following table lists RPM build options. Specify them with `--with <option>` when running `rpmbuild -ba umdk.spec`:

| Build Option | Default | Description |
| ------------ | ------- | ----------- |
| `--with ums` | Off | Build only UMS subpackages (`umdk-ums`, `umdk-ums-tools`, `umdk-ums-agent`). By default all UMDK subpackages are built; specifying this option builds only UMS-related subpackages |
| `--with 64kb` | Off | When specified, builds the `umdk-ums-64kb` package (for 64KB page size kernels), mutually exclusive with `umdk-ums`; when not specified, builds the `umdk-ums` package; this option is only supported on aarch64 architecture |
| `--with extra_ubcore_symbols` | Off | By default, UMS build depends on the ubcore headers and symbol table shipped with the kernel-devel package; when this option is enabled, UMS build depends on the ubcore headers and symbol table provided by the urma kernel module development package (built and installed separately), via `KBUILD_EXTRA_SYMBOLS` pointing to `/usr/include/ub/urma/Module.symvers` |

### 3.3 Install UMS
Note: UMS relies on the functionality of the URMA component. Before use, ensure that the URMA component is successfully installed and properly configured.

UMS build generates the following RPM packages:

| RPM Package | Description |
| ----------- | ----------- |
| `umdk-ums` | UMS kernel module |
| `umdk-ums-64kb` | UMS kernel module (aarch64 architecture, 64KB page kernel, mutually exclusive with `umdk-ums`) |
| `umdk-ums-tools` | UMS tools (including `ums_run`, `libums-preload.so`) |
| `umdk-ums-agent` | UMS userspace security agent service (used in SECURE mode) |

Note: Installing the `umdk` main package automatically installs the above UMS packages.

Installation commands:
```bash
# 4KB page kernel (x86_64 / aarch64 default)
rpm -ivh umdk-ums-*.rpm
# or aarch64 64KB page kernel
rpm -ivh umdk-ums-64kb-*.rpm

rpm -ivh umdk-ums-tools-*.rpm

# Install ums_agent additionally for SECURE mode
rpm -ivh umdk-ums-agent-*.rpm
```

Load the UMS kernel module:
```bash
modprobe ums
```

### 3.4 Kernel Module Parameter Configuration
The UMS kernel module (ums.ko) supports the following configuration parameters, which can be passed at module load time via `insmod`/`modprobe` commands, or persisted by writing to `/etc/modprobe.d/ums.conf`:

| Parameter | Value | Default | Description |
| --------- | ----- | ------- | ----------- |
| `ub_token_mode` | 0 / 1 / 2 | 0 (SECURE) | UB Token exchange mode: **0=SECURE**, TokenValue is exchanged out-of-band encrypted via ums_agent TLS 1.3 channel, requires deploying the ums_agent service; **1=LEGACY**, TokenValue is exchanged in plaintext via kernel CLC messages; **2=DISABLE**, UB Token access control is not enabled, Token policy is `UBCORE_TOKEN_NONE` |
| `ub_token_disable` | 0 / 1 | — | **Deprecated**, superseded by `ub_token_mode`, retained only for backward compatibility. Mapping: `0`→`ub_token_mode=1` (LEGACY), `1`→`ub_token_mode=2` (DISABLE). When specified together with `ub_token_mode`, `ub_token_mode` takes precedence |
| `ums_agent_uid` | unsigned 32-bit integer | 0 | UID of the process allowed to register as ums_agent, 0 means only root can register. In SECURE mode, typically written by systemd before ums_agent starts (`ExecStartPre`) with the ums system user's UID |
| `ums_agent_gid` | unsigned 32-bit integer | 0 | GID of the process allowed to register as ums_agent, same usage as `ums_agent_uid` |

Notes:
1. When `ub_token_mode` is not set, SECURE mode is the default; if the value is invalid, it falls back to SECURE mode with a log warning.
2. For security analysis and mode selection guidance for different Token modes, see [5. Token Mode and Security](#5-token-mode-and-security).
3. SECURE mode requires additional deployment of the ums_agent service, see [UMS Agent Guide](./UMS%20Agent%20Guide.md).
4. When the UMS kernel module is already loaded and running, the read/write permissions and query/modify methods for each parameter are described in [UMS API Guide - 2.3 UMS Runtime Module Parameters](./UMS%20API%20Guide.md#23-ums-runtime-module-parameters).

**Configuration Example**

Persist configuration via `/etc/modprobe.d/ums.conf`:
```bash
# /etc/modprobe.d/ums.conf
# ub_token_mode: 0=SECURE(default, requires ums_agent deployment), 1=LEGACY, 2=DISABLE
options ums ub_token_mode=0
```

Or specify at module load time via insmod/modprobe:
```bash
modprobe ums ub_token_mode=0
# or
insmod ums.ko ub_token_mode=0
```

In SECURE mode, `ums_agent_uid`/`ums_agent_gid` are typically written automatically by systemd before ums_agent starts with the ums system user's UID/GID, no manual configuration required; for details on this mechanism and pre-configuration, see [UMS Agent Guide - 5.2 Kernel Module Parameters](./UMS%20Agent%20Guide.md#52-kernel-module-parameters).

## 4. Usage Instructions
### 4.1 Usage Method
UMS provides the following two usage modes:
1. Direct usage
When creating a socket, set the protocol family to AF_SMC. No modifications are required for other socket-related interfaces.
```c
# Example:
sockfd = socket(AF_SMC, SOCK_STREAM, 0);
```

2. Transparent replacement (requires no modification to application code)
Via LD_PRELOAD: Preload the libsmc-preload.so dynamic library to intercept the application's socket() function and convert AF_INET to AF_SMC.
```bash
# Example: Transparently replace TCP socket interfaces in the ./foo application.
ums_run ./foo
```

## 5. Token Mode and Security
### 5.1 Token Mode Overview
UMS data plane URMA connections use UB Token for access control. The TokenValue exchange channel is determined by `ub_token_mode`. The three modes are compared as follows:

| Mode | Value | TokenValue Exchange Channel | CLC Message Token Field | ums_agent | Security Level |
| ---- | ----- | --------------------------- | ----------------------- | --------- | -------------- |
| SECURE | 0 | Out-of-band exchange via ums_agent TLS 1.3 encrypted channel | 0 (placeholder) | Required | High |
| LEGACY | 1 | Plaintext exchange via kernel CLC messages | Real value | Not required | Medium |
| DISABLE | 2 | No Token access control | 0 / `UBCORE_TOKEN_NONE` | Not required | Low |

**Mode interoperability rules**: SECURE mode only interoperates with SECURE mode; LEGACY and DISABLE interoperate with each other. When the modes of both connection parties do not match, the CLC handshake returns `UMS_CLC_DECL_TOKMDMIS`, the UMS connection negotiation fails and falls back to TCP. All nodes must be uniformly configured with the same mode.

### 5.2 Mode Selection Guidance
Token mode selection focuses on two core decisions:

1. **Do you need to enable UB Token access control?** If not, choose `DISABLE`.
2. **Is the risk of plaintext TokenValue transmission over the control plane acceptable?** If acceptable, choose `LEGACY`; if not acceptable, choose `SECURE`.

| Scenario | Recommended Token Mode | Rationale |
| -------- | ---------------------- | --------- |
| No security requirements, or UB hardware does not support Token access control | DISABLE(2) | Disables Token access control, reducing overhead |
| Need to enable UB Token access control, and plaintext TokenValue transmission risk is acceptable (e.g., test/dev environments, isolated internal networks) | LEGACY(1) | No need to deploy ums_agent, simpler operations; TokenValue is exchanged in plaintext via control plane CLC messages |
| Need to enable UB Token access control, and plaintext TokenValue transmission risk is not acceptable (e.g., production environments, security compliance requirements) | SECURE(0) | TokenValue is exchanged out-of-band via ums_agent TLS 1.3 encrypted channel, eliminating control plane credential leakage risk |

Note: The Token mode only affects how UMS internally exchanges TokenValue over the URMA channel, and is independent of TLS which operates at a different layer of the protocol stack. Whether the application enables TLS is unrelated to the chosen Token mode (see [5.3 Security Risks and Mitigation](#53-security-risks-and-mitigation)).

### 5.3 Security Risks and Mitigation
UMS, as a kernel network protocol stack comparable to TCP, does not provide message confidentiality or integrity protection by default.

- **Application-layer socket connection security**: When applications communicate over UMS, it is recommended to protect socket connections with TLS (covering authentication, data encryption, and integrity verification) to ensure end-to-end communication security.
- **UMS internal URMA channel TokenValue exchange security**: The UMS kernel module establishes data transmission channels based on URMA. If UB Token access control is enabled (i.e., `ub_token_mode` is set to SECURE or LEGACY), TokenValue must be exchanged during connection establishment as an access credential. The Token mode determines how TokenValue is exchanged:
  - In LEGACY mode, TokenValue is transmitted in plaintext during the CLC handshake. Even if the application layer has secured end-to-end communication via TLS, plaintext leakage of TokenValue can still be exploited to launch DoS attacks (injecting tampered data to trigger TLS decryption failures, causing connection drops).
  - In SECURE mode, TokenValue is exchanged out-of-band via the ums_agent TLS 1.3 encrypted channel, eliminating the risk of control plane credential plaintext leakage.
  - In DISABLE mode, UB Token access control is not enabled, and no TokenValue exchange occurs.

In summary, **application-layer TLS and Token mode operate at different layers of the protocol stack and are independent of each other**: application-layer TLS ensures end-to-end communication security for socket connections, while UMS SECURE mode further eliminates control plane credential leakage risk on this basis, strengthening defense in depth. The two work independently and cannot substitute each other.

## 6. Related Documents
- [UMS API Guide](./UMS%20API%20Guide.md): UMS socket programming interfaces, proc/sysctl service interface reference.
- [UMS Agent Guide](./UMS%20Agent%20Guide.md): Deployment, configuration, certificate, and service operations guide for the ums_agent security agent.
