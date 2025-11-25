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

## 3. 安装教程
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
2. tar -cvf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git $(ls -A)
3. rpmbuild -ba umdk.spec --with ums

**UMS 额外编译选项说明**
- RPM compilation Options \
   --with ko_sign                                    option, i.e. disable ko_sign by default.

**UMS 模块参数说明**
- ko insmod/modprobe Options \
   ub_token_disable=*                              option, i.e. 1:disable ub token, 0:enable ub token, default:0. \
     说明：开启ub token会影响性能，请使用者评估使用场景安全性，决策是否开启。

### 3.3 安装UMS
说明:UMS需要调用URMA组件的能力，使用前需保证URMA组件安装成功且正常配置。
```bash
rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-ums-*
modprobe ums
```

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

### 4.2 安全风险及消减说明
UMS建链无认证，数据传输为明文，存在安全风险。应用在使用UMS时，应对标TCP socket，在应用层开启TLS认证和加密传输，保证端到端通信安全。

* 更多的接口使用说明详见UMS接口手册。