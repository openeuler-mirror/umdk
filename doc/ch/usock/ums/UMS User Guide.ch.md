# UMS
## 1. 介绍
UMS是一种北向兼容标准socket API，南向基于UB网络进行数据传输，透明加速TCP通信的内核网络协议栈。UMS在SMC-R协议和内核SMC-R源码基础上进行二次开发，基于UMDK实现共享内存通信协议（SMC，Shared Memory Communication），旨在充分发挥华为UB硬件设备的性能优势，提升整体网络传输效率。作为构建在UB网络架构之上的高性能通信协议，UMS提供低延迟、高吞吐量的网络传输能力，特别适用于对网络性能要求苛刻的场景，如Redis、数据库、AI训推、分布式缓存等。

## 2. 软件架构
**向上兼容 TCP socket** \
ums运行在linux内核态，兼容标准socket接口，使用tcp握手协议完成建连流程(协商错误自动回退到tcp通信)，并采用SMC-R的透明替换技术，应用层无需感知即可实现网络加速。

**向下调用 UMDK-URMA API** \
底层调用华为UMDK-URMA组件能力，充分利用UB网络的性能优势。

**当前基于SMC-R协议**
* 遵循SMC-R协议的基本流程与数据结构设计，在此基础上进行二次开发
* 针对小消息通信场景进行延迟优化，显著提升传输效率
* 后续优化方向包括：引入多路径通信机制、增强流控策略，实现更高并发与更强鲁棒性。
* UMS未来将基于UB协议而非SMC-R协议实现

**可选的用户态安全代理服务 ums_agent** \
UMS提供可选的用户态安全代理服务 ums_agent，用于在 SECURE Token 模式下经 TLS 1.3 加密通道带外交换 UB TokenValue，消除控制面 Token 明文传输风险。ums_agent 独立打包（`umdk-ums-agent`）、独立部署、以 systemd 服务运行，仅在 SECURE 模式下被内核使用。其部署运维详见 [UMS Agent Guide](./UMS%20Agent%20Guide.ch.md)。

## 3. 安装与配置
### 3.1 查询内核是否支持smc协议
```bash
cat /boot/config-$(uname -r) | grep CONFIG_SMC
```
显示CONFIG_SMC=m 表示当前内核版本是支持smc协议的，确认环境支持以后，再按照下面描述的步骤进行环境部署

### 3.2 编译UMS RPM包
**从UMDK编译产物获取** \
参考UMDK整体编译步骤

**单独编译UMS**
1. 进入UMDK工程根目录下
2. tar -cvf /root/rpmbuild/SOURCES/umdk-26.06.0.tar.gz --exclude=.git $(ls -A)
3. rpmbuild -ba umdk.spec --with ums

**UMS 额外编译选项说明**

下表为 RPM 包构建选项， `rpmbuild -ba umdk.spec` 时通过 `--with <选项>` 指定：

| 编译选项 | 默认 | 说明 |
| -------- | ---- | ---- |
| `--with ums` | 关闭 | 仅构建 UMS 子包（`umdk-ums`、`umdk-ums-tools`、`umdk-ums-agent`）。默认构建 UMDK 全部子包，指定本选项后仅构建 UMS 相关子包 |
| `--with 64kb` | 关闭 | 指定后构建 `umdk-ums-64kb` 包（适配 64KB 页大小内核），与 `umdk-ums` 互斥；未指定时构建 `umdk-ums` 包；该选项仅支持 aarch64 架构 |
| `--with extra_ubcore_symbols` | 关闭 | UMS 构建默认依赖 kernel-devel 开发包自带的 ubcore 头文件与符号表；启用该选项时，UMS 构建依赖 urma 内核模块开发包（独立构建安装）提供的 ubcore 头文件与符号表（通过 `KBUILD_EXTRA_SYMBOLS` 指向 `/usr/include/ub/urma/Module.symvers` |

### 3.3 安装UMS
说明:UMS需要调用URMA组件的能力，使用前需保证URMA组件安装成功且正常配置。

UMS 构建生成以下 RPM 包：

| RPM 包 | 说明 |
| ------- | ---- |
| `umdk-ums` | UMS 内核模块 |
| `umdk-ums-64kb` | UMS 内核模块（aarch64 架构 64KB 页内核，与 `umdk-ums` 互斥） |
| `umdk-ums-tools` | UMS 工具（含 `ums_run`、`libums-preload.so`） |
| `umdk-ums-agent` | UMS 用户态安全代理服务（SECURE 模式下使用） |

说明：安装 `umdk` 主包时会自动安装上述 UMS 包。

安装命令：
```bash
# 4KB 页内核（x86_64 / aarch64 默认）
rpm -ivh umdk-ums-*.rpm
# 或 aarch64 64KB 页内核
rpm -ivh umdk-ums-64kb-*.rpm

rpm -ivh umdk-ums-tools-*.rpm

# SECURE 模式额外安装 ums_agent
rpm -ivh umdk-ums-agent-*.rpm
```

加载 UMS 内核模块：
```bash
modprobe ums
```

### 3.4 内核模块参数配置
UMS 内核模块（ums.ko）支持以下配置参数，可通过 `insmod`/`modprobe` 命令在模块加载时传参，或写入 `/etc/modprobe.d/ums.conf` 持久化配置：

| 参数 | 取值 | 默认值 | 说明 |
| ---- | ---- | ------ | ---- |
| `ub_token_mode` | 0 / 1 / 2 | 0（SECURE） | UB Token 交换模式：**0=SECURE**，TokenValue 经 ums_agent TLS 1.3 通道带外加密交换，需部署 ums_agent 服务；**1=LEGACY**，TokenValue 通过内核 CLC 消息明文交换；**2=DISABLE**，不启用 UB Token 访问控制，Token 策略为 `UBCORE_TOKEN_NONE` |
| `ub_token_disable` | 0 / 1 | — | **已废弃**，由 `ub_token_mode` 取代，仅为兼容旧版本保留。映射关系：`0`→`ub_token_mode=1`（LEGACY），`1`→`ub_token_mode=2`（DISABLE）。与 `ub_token_mode` 同时指定时以 `ub_token_mode` 为准 |
| `ums_agent_uid` | 无符号 32 位整数 | 0 | 允许注册为 ums_agent 的进程 UID，0 表示仅 root 可注册。SECURE 模式下通常由 systemd 在 ums_agent 启动前（`ExecStartPre`）写入 ums 系统用户的 UID |
| `ums_agent_gid` | 无符号 32 位整数 | 0 | 允许注册为 ums_agent 的进程 GID，用法同 `ums_agent_uid` |

说明：
1. `ub_token_mode` 未设置时默认 SECURE 模式；取值非法时回退到 SECURE 模式并输出日志告警。
2. 不同 Token 模式的安全分析与选型建议详见 [5. Token 模式与安全](#5-token-模式与安全)。
3. SECURE 模式需额外部署 ums_agent 服务，详见 [UMS Agent Guide](./UMS%20Agent%20Guide.ch.md)。
4. UMS内核模块已加载运行时，各参数的可读写性与查询/修改方式详见 [UMS API Guide - 2.3 UMS 运行时模块参数](./UMS%20API%20Guide.ch.md#23-ums-运行时模块参数)。

**配置示例**

通过 `/etc/modprobe.d/ums.conf` 持久化配置：
```bash
# /etc/modprobe.d/ums.conf
# ub_token_mode: 0=SECURE(默认,需部署ums_agent), 1=LEGACY, 2=DISABLE
options ums ub_token_mode=0
```

或通过 insmod/modprobe 在模块加载时指定：
```bash
modprobe ums ub_token_mode=0
# 或
insmod ums.ko ub_token_mode=0
```

SECURE 模式下 `ums_agent_uid`/`ums_agent_gid` 通常由 systemd 在 ums_agent 启动前自动写入 ums 系统用户的 UID/GID，无需手动配置；该机制及预配置方式详见 [UMS Agent Guide - 5.2 内核模块参数](./UMS%20Agent%20Guide.ch.md#52-内核模块参数)。

## 4. 使用说明
### 4.1 使用方式
UMS提供以下两种使用方式：
1. 直接使用
创建socket时，设置为 AF_SMC 协议族，不需要修改其他socket相关接口。
```c
# 示例
sockfd = socket(AF_SMC, SOCK_STREAM, 0);
```

2. 透明替换（不需要修改应用代码）
通过LD_PRELOAD：预加载libsmc-preload.so动态库，劫持应用的socket()函数，把AF_INET转换为AF_SMC类型。
```bash
# 示例：透明替换./foo 应用里的TCP socket接口
ums_run ./foo
```

## 5. Token 模式与安全
### 5.1 Token 模式概览
UMS 数据面 URMA 连接通过 UB Token 进行访问控制。TokenValue 的交换通道由 `ub_token_mode` 决定，三种模式对比如下：

| 模式 | 值 | TokenValue 交换通道 | CLC 消息 Token 字段 | ums_agent | 安全等级 |
| ---- | -- | ------------------- | ------------------- | --------- | -------- |
| SECURE | 0 | ums_agent TLS 1.3 加密通道带外交换 | 0（占位） | 需要 | 高 |
| LEGACY | 1 | 内核 CLC 消息明文交换 | 真实值 | 不需要 | 中 |
| DISABLE | 2 | 不使用 Token 访问控制 | 0 / `UBCORE_TOKEN_NONE` | 不需要 | 低 |

**模式互通规则**：SECURE 模式仅与 SECURE 模式互通；LEGACY 与 DISABLE 之间可互通。连接双方模式不匹配时，CLC 握手返回 `UMS_CLC_DECL_TOKMDMIS`，UMS 建链协商失败并回退到 TCP。所有节点需统一配置同一模式。

### 5.2 模式选择建议
Token 模式选型聚焦两个核心决策：

1. **是否需要开启 UB Token 访问控制？** 不需要则选 `DISABLE`。
2. **TokenValue 控制面明文传输风险是否可接受？** 可接受则选 `LEGACY`，不可接受则选 `SECURE`。

| 场景 | 推荐 Token 模式 | 理由 |
| ---- | --------------- | ---- |
| 无安全需求，或UB硬件不支持Token访问控制 | DISABLE(2) | 关闭 Token 访问控制，减少开销 |
| 需要开启 UB Token 访问控制，且 TokenValue 明文传输风险可接受（如测试/开发环境、网络已隔离的内部环境） | LEGACY(1) | 无需部署 ums_agent，运维简单；TokenValue 通过控制面 CLC 消息明文交换 |
| 需要开启 UB Token 访问控制，且 TokenValue 明文传输风险不可接受（如生产环境、有安全合规要求） | SECURE(0) | TokenValue 经 ums_agent TLS 1.3 加密通道带外交换，消除控制面凭据泄露风险 |

说明：Token 模式仅影响 UMS 内部 URMA 通道 TokenValue 的交换方式，与 TLS 工作于协议栈不同层级、互不相干。应用是否开启 TLS 与选用何种 Token 模式无关（详见 [5.3 安全风险及消减说明](#53-安全风险及消减说明)）。

### 5.3 安全风险及消减说明
UMS 作为内核网络协议栈对标 TCP，默认不提供消息机密性和完整性保护。

- **应用层 socket 连接安全**：应用基于 UMS 通信时，建议通过 TLS 保护 socket 连接（涵盖身份认证、数据加密与完整性校验），保障端到端通信安全。
- **UMS 内部 URMA 通道 TokenValue 交换安全**：UMS 内核模块基于 URMA 建立数据传输通道，若开启 UB Token 访问控制（即 `ub_token_mode` 取 SECURE 或 LEGACY），建链时需交换 TokenValue 作为访问凭据。Token 模式决定 TokenValue 的交换方式：
  - LEGACY 模式下 TokenValue 在 CLC 握手过程中明文传输。即便应用层已通过 TLS 保障 socket 连接端到端通信安全，TokenValue 明文泄露仍可能被用于发起 DoS（注入篡改数据触发 TLS 解密失败、导致连接中断）。
  - SECURE 模式下 TokenValue 经 ums_agent TLS 1.3 加密通道带外交换，消除控制面凭据明文泄露风险。
  - DISABLE 模式不启用 UB Token 访问控制，无 TokenValue 交换。

综上，**应用层 TLS 与 Token 模式工作于协议栈不同层级、互不相干**：应用层 TLS 保障 socket 连接端到端通信安全，UMS SECURE 模式在此基础上进一步消除控制面凭据泄漏风险，加强纵深防御。两者各自独立工作，不可相互替代。

## 6. 相关文档
- [UMS API Guide](./UMS%20API%20Guide.ch.md)：UMS socket 编程接口、proc/sysctl 服务接口参考。
- [UMS Agent Guide](./UMS%20Agent%20Guide.ch.md)：ums_agent 安全代理的部署、配置、证书与服务运维指南。
