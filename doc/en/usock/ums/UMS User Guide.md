# UMS
## 1. Introduction
UMS is a kernel-level network protocol stack that is compatible with the standard socket API and based on the UB network for data transmission, transparently accelerating TCP communication. Developed as an extension of the SMC-R protocol and the kernel SMC-R source code, UMS implements a Shared Memory Communication (SMC) protocol based on UMDK. It is designed to fully leverage the performance advantages of Huawei’s UB hardware, enhancing overall network transmission efficiency. As a high-performance communication protocol built on the UB network architecture, UMS offers low-latency, high-throughput data transfer capabilities, making it particularly suitable for performance-sensitive applications such as Redis, databases, AI training and inference, and distributed caching.

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

## 3. Installation Guide
### 3.1 How to Check if the Kernel Supports the SMC Protocol
```bash
cat /boot/config-$(uname -r) | grep CONFIG_SMC
```
If the command output shows CONFIG_SMC=m, it indicates that the current kernel version supports the SMC protocol. Once the environment compatibility is confirmed, proceed with the deployment steps described below.

### 3.2 Build UMS
**Obtain from the UMDK build artifacts** \
Refer to the overall build steps for UMDK in the Readme.md.

**Build separately**
1. Navigate to the root directory of the UMDK project
2. tar -cvf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git $(ls -A)
3. rpmbuild -ba umdk.spec --with ums

**Additional Build Options**
- RPM build Options \
   --with ko_sign                                    option, i.e. disable ko_sign by default.

**UMS Module Options**
- ko insmod/modprobe Options \
   ub_token_disable=*                              option, i.e. 1:disable ub token, 0:enable ub token, default:0. \
     Note: Enabling ub token may impact performance. Please evaluate the security requirements of your specific use case before deciding to enable it.

### 3.3 install UMS
Note: UMS relies on the functionality of the URMA component. Before use, ensure that the URMA component is successfully installed and properly configured.
```bash
rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-ums-*
modprobe ums
```

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

### 4.2 Security Risks and Mitigation Description
UMS connections are not authenticated, and data is transmitted in plaintext, posing security risks.
When using UMS, applications should follow the TCP socket and enable TLS authentication and encrypted
transmission at the application layer to ensure end-to-end communication security.

* For more detailed API usage instructions, please refer to the UMS API Guide.md.