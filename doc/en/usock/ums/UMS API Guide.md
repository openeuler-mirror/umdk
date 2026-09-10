# UMS
## 1. Supported standard socket API
UMS is a kernel-level network protocol stack that is compatible with the standard socket API and based on the UB network for data transmission, transparently accelerating TCP communication. The current standard socket apis supported by UMS are as follows.

### 1.1 int socket(int domain, int type, int protocal);
Create a socket：
1. The type parameter is restricted to SOCK_STREAM, and the protocol parameter only supports IPPROTO_IP or IPPROTO_TCP
2. In scenarios where UMS is directly used, the domain parameter should be specified as AF_SMC. In scenarios where transparent replacement is used, the domain value should be specified as AF_INET or AF_INET6. For details of the two scenarios, please refer to the UMS User Guide.md.

### 1.2 ssize_t send(int sockfd, const void *buf, size_t len, int flags);
Send data via socket fd.

### 1.3 ssize_t recv(int sockfd, void *buf, size_t len, int flags);
Receive data via socket fd.

### 1.4 ssize_t write(int fd, const void *buf, size_t count);
Send data via socket fd.

### 1.5 ssize_t read(int fd, void *buf, size_t count);
Receive data via socket fd.

### 1.6 int connect(int socket, const struct sockaddr *addr, socklen_t addrlen);
Establish a connection with the peer server.

### 1.7 int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
Bind the local address to the socket fd.

### 1.8 int listen(int sockfd, int backlog);
Convert the socket fd into a server-side socket fd that can receive connections.

### 1.9 int accept(int listenfd, struct sockaddr *addr, int *addrlen);
Accept the connection from the client side.

### 1.10 int shutdown(int sockfd, int howto);
Disconnect part of the data transmission channel of the socket.

### 1.11 int close(int fd);
Close the socket connection.

### 1.12 int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
Set the parameters related to sockets. Currently, UMS does not support all socket options. The supported options are as follows:
| level       | optname          |      support situation      |
| ----------- | ---------------- | --------------------------- |
| SOL_SOCKET  | SO_SNDBUF        |  Both the management plane and the data plane are supported. When the data plane is actually used, it will be normalized to 16KB*(2^n) (rounded up) |
| SOL_SOCKET  | SO_RCVBUF        |  Both the management plane and the data plane are supported. When the data plane is actually used, it will be normalized to 16KB*(2^n) (rounded up) |
| SOL_SOCKET  | SO_REUSEADDR     |  Management plane is supported |
| SOL_SOCKET  | SO_RCVTIMEO      |  Both the management plane and the data plane are supported |
| IPPROTO_TCP | TCP_USER_TIMEOUT |  Management plane is supported |
| IPPROTO_TCP | TCP_NODELAY      |  Both the management plane and the data plane are supported |
| IPPROTO_TCP | TCP_KEEPINTVL    |  Management plane is supported  |
| IPPROTO_TCP | TCP_KEEPIDLE     |  Management plane is supported  |
| IPPROTO_TCP | TCP_KEEPCNT      |  Management plane is supported  |
| IPPROTO_TCP | TCP_KEEPALIVE    |  Management plane is supported  |

### 1.13 int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
Get the parameters related to the socket fd.

## DFX API
### 2.1 UMS proc API
UMS supports the use of proc file system to show link status. For IPV4 connections, the usage is:
```bash
cat /proc/net/ums
```
For IPV6 connections, the usage is:
```bash
cat /proc/net/ums6
```

The display items are shown in the following table:
|     item     | introduction |
| ------------ | ------------ |
| SRC_IP:Port  | Local address, denoted as IP:PORT |
| DEST_IP:Port | Peer address, denoted as IP:PORT |
| State        | Indicates the current state of the UMS socket |
| Fallback     | UMS fallback item，True indicates that the connection has fallen back to TCP |
| SRC_EID, JETTY_ID  | The local Jetty's EID and Jetty ID. Displays N/A for non-UMS connections |
| DEST_EID, JETTY_ID | The peer Jetty's EID and Jetty ID. Displays N/A for non-UMS connections |

### 2.2 UMS sysctl API
UMS supports configuring and querying some attributes through the sysctl API. The usage is as follows: \
**query**
```bash
cat /proc/sys/net/ums/[attribute]
# or
sysctl net.ums.[attribute]
```
**config**
```bash
echo [value] > /proc/sys/net/ums/[attribute]
# or
sysctl -w net.ums.[attribute]=[vale]
```

The currently supported attributes and their configurable value are listed in the table below.
| attribute | configurable value | introduction |
| -----------  | ----------- |   -----------        |
| autocorking_size  | [1, 1073741824]       |  Corking size in UMS (bytes)  |
| rcv_buf           | [16384, 2147483648)   |  Receive Buffer Size (bytes)  |
| snd_buf           | [16384, 2147483648)   |  Send Buffer Size (bytes)     |

**Note**
1. The actual corking size will not exceed half of the send buffer size. If a larger value is configured, it will not take effect. Instead, half of the send buffer size will be used as the effective corking size.
2. It is recommended that users configure this parameter according to their needs after module mounting. The configuration takes effect immediately upon being set.

### 2.3 UMS Runtime Module Parameters
For the semantics, valid values, and load-time configuration of UMS kernel module parameters, see [UMS User Guide - 3.4 Kernel Module Parameter Configuration](./UMS%20User%20Guide.md#34-kernel-module-parameter-configuration). This section only describes the runtime access methods.

**Load-time only parameters (permission 0)**

The following parameters cannot be read or written after the UMS kernel module is loaded and running. They can only be specified at module load time (via `insmod`/`modprobe` command parameters, or by writing to `/etc/modprobe.d/ums.conf`):

| Parameter | Runtime Behavior |
| --------- | ---------------- |
| `ub_token_mode` | Not readable or writable; parsed once at load time, the effective value must be confirmed from kernel logs |
| `ub_token_disable` | **Deprecated**, not readable or writable; mapped once at load time to `ub_token_mode` (`0`→LEGACY, `1`→DISABLE) |

To check the effective token mode after loading, confirm via kernel logs: the module prints `ub_token_mode=SECURE/LEGACY/DISABLE(<value>)` at load time.
```bash
dmesg | grep "UMS_" | grep "ub_token_mode="
```

**Readable and writable parameters (permission 0644)**

The following parameters specify the UID/GID of processes allowed to register as ums_agent (effective only when `ub_token_mode=0`, i.e., SECURE mode). They can be queried and modified via `/sys/module/ums/parameters/<parameter>`:
```bash
# Query
cat /sys/module/ums/parameters/ums_agent_uid
cat /sys/module/ums/parameters/ums_agent_gid

# Modify (only writable when ums_agent is offline; writing while ums_agent is online returns -EBUSY)
echo <UID> > /sys/module/ums/parameters/ums_agent_uid
echo <GID> > /sys/module/ums/parameters/ums_agent_gid
```

| Parameter | sysfs Permission | Runtime Behavior |
| --------- | ---------------- | ---------------- |
| `ums_agent_uid` | 0644 | Readable; writable only when ums_agent is offline, writing while online returns `-EBUSY` |
| `ums_agent_gid` | 0644 | Readable; writable only when ums_agent is offline, writing while online returns `-EBUSY` |