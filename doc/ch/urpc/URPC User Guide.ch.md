# 1. 介绍
统一远程过程调用，支持灵衢原生高性能主机间和设备间RPC通信，以及RPC加速。

# 2. 软件编译

## URPC

### 使用RPM包编译构建URPC
```bash
rm -rf .git*
mkdir -p /root/rpmbuild/SOURCES/
tar -cvf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git $(ls -A)
rpmbuild -bb umdk.spec --with urpc
```

### 使用cmake编译URPC
```bash
cd src
mkdir build; cd build
cmake .. -DBUILD_ALL=disable -DBUILD_URPC=enable
make -j16
make install # 可选项，如果需要安装URPC则执行此命令
```

## UMQ

### 使用bazel编译UMQ
使用下述命令即可生成所有umq组件所需的动态库文件：
```bash
cd src/urpc/
bazel build //umq:libumq_so # so将在/src/urpc/bazel-bin/目录下生成
```
#### 编译模式
* bazel编译默认会使用opt模式进行编译，即包括`O2`优化、剥离符号表(`-Wl,-S`)等操作。
* `--config=release`，release版本是在默认优化上进行深度符号表剥离(`-Wl,-s`)。
* `--config=debug`, debug版本将进行`O0`优化同时完全保留符号表信息。

#### openssl依赖
* bazel默认（或者指定`--//umq:openssl_mode=bazel`）会使用`.bazelrc`内定义的openssl版本（静态编译）。如果用户希望使用系统内的so，可以加上``--//umq:openssl_mode=system`来指明使用系统版本。

# 3. 安装使用
- rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-urpc-*.rpm
- urpc_framework_example -i SERVER_IP -d DEV_NAME -T 1 -e 0 --server --eid EID -L --assign_mode 2 -R
- urpc_framework_example -i SERVER_IP -d DEV_NAME -T 1 -e 0 --client --eid EID -L --assign_mode 2 -R

**指令样例**:

```bash
urpc_framework_example -i 192.168.100.100 -d udma0 -T 1 -e 0 --server --eid 4245:4944:0000:0000:0000:0000:0100:0000 -L --assign_mode 2 -R
urpc_framework_example -i 192.168.100.100 -d udma0 -T 1 -e 0 --client --eid 4245:4944:0000:0000:0000:0000:0200:0000 -L --assign_mode 2 -R
```