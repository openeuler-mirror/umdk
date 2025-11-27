# UMS
## 1. 编程接口
UMS是一种北向兼容标准socket API，南向基于UB网络进行数据传输，透明加速TCP通信的内核网络协议栈。当前UMS支持的标准socket API如下所示。

### 1.1 int socket(int domain, int type, int protocal);
创建一个socket：
1. type仅支持SOCK_STREAM，protocol仅支持IPPROTO_IP或IPPROTO_TCP
2. 在直接使用UMS的场景，需指定domain为AF_SMC，在透明替换的场景，需指定domain值为AF_INET或AF_INET6，两种场景详情见UMS使用手册。

### 1.2 ssize_t send(int sockfd, const void *buf, size_t len, int flags);
通过socket fd发送数据

### 1.3 ssize_t recv(int sockfd, void *buf, size_t len, int flags);
通过socket fd接收数据

### 1.4 ssize_t write(int fd, const void *buf, size_t count);
通过socket fd发送消息。

### 1.5 ssize_t read(int fd, void *buf, size_t count);
通过socket fd接收消息。

### 1.6 int connect(int socket, const struct sockaddr *addr, socklen_t addrlen);
与对端server建立tcp连接。

### 1.7 int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
将本地地址与socket fd绑定。

### 1.8 int listen(int sockfd, int backlog);
将socket转换成可以接收连接的server端socket。

### 1.9 int accept(int listenfd, struct sockaddr *addr, int *addrlen);
接收client端的连接。

### 1.10 int shutdown(int sockfd, int howto);
断开socket部分数据传输通道。

### 1.11 int close(int fd);
关闭socket连接。

### 1.12 int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
设置与套接字相关的参数，目前并不支持所有socket选项，选项支持情况如下表:
| level       | optname          |      支持情况        |
| ----------- | ---------------- |   -----------        |
| SOL_SOCKET  | SO_SNDBUF        |  管理面和数据通路都支持，数据面实际使用时会归一化到16KB*(2^n) (向上取整)  |
| SOL_SOCKET  | SO_RCVBUF        |  管理面和数据通路都支持，数据面实际使用时会归一化到16KB*(2^n) (向上取整)  |
| SOL_SOCKET  | SO_REUSEADDR     |  管理面支持即可  |
| SOL_SOCKET  | SO_RCVTIMEO      |  管理面和数据面都支持  |
| IPPROTO_TCP | TCP_USER_TIMEOUT |  管理面支持，数据通路不支持  |
| IPPROTO_TCP | TCP_NODELAY      |  管理面和数据面都支持  |
| IPPROTO_TCP | TCP_KEEPINTVL    |  管理面支持，数据通路不支持  |
| IPPROTO_TCP | TCP_KEEPIDLE     |  管理面支持，数据通路不支持  |
| IPPROTO_TCP | TCP_KEEPCNT      |  管理面支持，数据通路不支持  |
| IPPROTO_TCP | TCP_KEEPALIVE    |  管理面支持，数据通路不支持  |

### 1.13 int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
获取与套接字相关的参数。

## 2. 服务接口
### 2.1 UMS proc接口
UMS支持使用proc file system输出当前系统中的链接状态，IPV4类型的连接，使用方式为：
```bash
cat /proc/net/ums
```
支持输出的状态项见下表：
| 状态项       | 说明         |
| -----------  | ----------- |
| SRC_IP:Port  | IP:PORT格式类型的本地地址输出        |
| DEST_IP:Port | IP:PORT格式类型的远端地址输出        |
| State        | UMS state选项，指示当前的UMS状态信息 |
| Fallback     | UMS fallback选项，False表示当前为非fallback状态，True表示当前为fallback状态 |
| SRC_EID, JETTY_ID  | 本地Jetty的EID信息和Jetty ID；非UMS连接不显示，打印N/A |
| DEST_EID, JETTY_ID | 对端Jetty的EID信息和Jetty ID；非UMS连接不显示，打印N/A |

IPV6类型的连接，使用方式为：
```bash
cat /proc/net/ums6
```
支持输出的状态项见下表:
| 状态项       | 说明         |
| -----------  | ----------- |
| SRC_IP:Port  | IP:PORT格式类型的本地地址输出        |
| DEST_IP:Port | IP:PORT格式类型的远端地址输出        |
| State        | UMS state选项，指示当前的UMS状态信息 |
| Fallback     | UMS fallback选项，False表示当前为非fallback状态，True表示当前为fallback状态 |
| SRC_EID, JETTY_ID  | 本地Jetty的EID信息和Jetty ID；非UMS连接不显示，打印N/A |
| DEST_EID, JETTY_ID | 对端Jetty的EID信息和Jetty ID；非UMS连接不显示，打印N/A |

### 2.2 UMS sysctl接口
UMS支持使用sysctl接口配置部分属性。使用方法包括: \
**查询**
```bash
cat /proc/sys/net/ums/[属性名]
# or
sysctl net.ums.[属性名]
```
**配置**
```bash
echo [值] > /proc/sys/net/ums/[属性名]
# or
sysctl -w net.ums.[属性名]=[值]
```

支持的属性名和配置值范围见下表:
| 状态项       | 取值范围     |      说明            |
| -----------  | ----------- |   -----------        |
| autocorking_size  | [1, 1073741824]       |  UMS中的聚合大小，单位为字节      |
| rcv_buf           | [16384, 2147483648)   |  接收缓冲区的大小配置，单位为字节  |
| snd_buf           | [16384, 2147483648)   |  发送缓冲区的大小配置，单位为字节  |

**注意**
1. 聚合大小实际使用时不会超过发送缓冲区的一半。如果配置过大，该字段的配置不会生效，会直接使用发送缓冲区的一半的值作为实际聚合大小。
2. 建议用户根据需求在模块挂载后进行配置，配置后生效一次。