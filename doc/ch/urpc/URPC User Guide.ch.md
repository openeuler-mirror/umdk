# 1. 介绍
统一远程过程调用，支持灵衢原生高性能主机间和设备间RPC通信，以及RPC加速。

# 2. 软件编译
使用RPM包编译构建
- rm -rf .git*
- mkdir -p /root/rpmbuild/SOURCES/
- tar -cvf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git $(ls -A)
- rpmbuild -bb umdk.spec --with urpc

# 3. 安装使用
- rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-urpc-*.rpm
- urpc_framework_example -i SERVER_IP -d DEV_NAME -T 1 -e 0 --server --eid EID -L --assign_mode 2 -R
- urpc_framework_example -i SERVER_IP -d DEV_NAME -T 1 -e 0 --client --eid EID -L --assign_mode 2 -R

指令样例:
- urpc_framework_example -i 192.168.100.100 -d udma0 -T 1 -e 0 --server --eid 4245:4944:0000:0000:0000:0000:0100:0000 -L --assign_mode 2 -R
- urpc_framework_example -i 192.168.100.100 -d udma0 -T 1 -e 0 --client --eid 4245:4944:0000:0000:0000:0000:0200:0000 -L --assign_mode 2 -R