# 修订记录

| 修订时间 | 修订章节 | 修订内容简介 | 修复问题单连接或问题背景 | 修订人员 |
|----|----|----|----|----|
| 2026.2.12 | ALL | 文档基线 |  | @qianguoxin、@jerry_lilijun、@guguguo0127 |
---

# 目 录

- [修订记录](#修订记录)

- [1 编译指南](#1-编译指南)
    - [1.1 组件简介](#11-组件简介)
    - [1.2 用户态组件单独编译](#12-用户态组件单独编译)
    - [1.3 内核态组件单独编译](#13-内核态组件单独编译)

- [2 安装指南](#2-安装指南)
    - [2.1 安装包概述](#21-安装包概述)
    - [2.2 安装依赖](#22-安装依赖)
    - [2.3 用户态安装](#23-用户态安装)
    - [2.4 URMA RPM包安装](#24-urma-rpm包安装)
    - [2.5 内核态ko安装](#25-内核态ko安装)

- [3 功能依赖](#3-功能依赖)

- [4 验证与运行示例](#4-验证与运行示例)
    - [4.1 设备验证](#41-设备验证)
    - [4.2 性能测试示例](#42-性能测试示例)

# 1 编译指南

## 1.1 组件简介

URMA组件是一个高性能通信组件，分为用户态和内核态两部分：

- 用户态：提供应用程序接口，有独立的源码仓库：https://gitcode.com/openeuler/umdk

- 内核态：位于OpenEuler内核源码的 drivers/ub/urma 目录中：https://gitcode.com/openeuler/kernel

## 1.2 用户态组件单独编译

**编译步骤**

1. 安装编译工具和软件包

```bash
yum install -y git rpm-build make cmake gcc glibc-devel kernel-devel libnl3-devel openssl-devel
```

2. 下载源码，进入源码src/路径下，创建并进入build构建目录

```bash
mkdir build
cd build
```

3. 执行配置与编译

```bash
cmake -DCMAKE_VERBOSE_MAKEFILE=on \
-DCMAKE_INSTALL_PREFIX=/usr \
-DBUILD_ALL=disable \
-DBUILD_URMA=enable \
-DBUILD_UDMA=disable \
-DBUILD_UMS=disable \
..
make -j$(nproc)
```

**参数说明**

- `-DCMAKE_VERBOSE_MAKEFILE=on`：显示详细的编译信息，便于排查问题

- `-DCMAKE_INSTALL_PREFIX=/usr`：指定安装路径为系统目录

- `-DBUILD_URMA=enable`：明确启用URMA模块编译

## 1.3 内核态组件单独编译

**前提条件**

在单独编译内核态组件前，必须完整运行一次内核的全量编译，确保依赖文件已正确生成。

**编译步骤**

1. 安装编译工具

```bash
yum install -y dpkg dpkg-devel openssl openssl-devel
yum install -y ncurses ncurses-devel bison flex bc libdrm build elfutils-libelf-devel
```

2. 进入内核源码目录

```bash
cd kernel
```

3. 配置内核（如果尚未配置）

```bash
make openeuler_defconfig
```

4. 单独编译URMA内核模块

```bash
make M=drivers/ub/urma -j$(nproc)
```

**编译结果**

编译完成后，会在 drivers/ub/urma 目录下生成 .ko 内核模块文件，包括 ubcore.ko、ubagg.ko、uburma.ko。可通过如下命令验证：

```bash
cd drivers/ub/urma
find . -type f -name "*.ko"
# ./drivers/ub/urma/ubcore/ubcore.ko
# ./drivers/ub/urma/ubagg/ubagg.ko
# ./drivers/ub/urma/uburma/uburma.ko
```

---
# 2 安装指南

## 2.1 安装包概述

URMA安装包分为aarch64和x86_64两种，分别支持ARM平台和X86平台。详细RPM包内容见下表：

**UMDK安装包描述**

<table style="width:83%;">
<colgroup>
<col style="width: 14%" />
<col style="width: 40%" />
<col style="width: 27%" />
</colgroup>
<thead>
<tr>
<th>组件</th>
<th>安装包</th>
<th>备注</th>
</tr>
</thead>
<tbody>
<tr>
<td rowspan="5">urma</td>
<td>umdk-urma-lib-xxx.rpm</td>
<td>urma用户态安装包</td>
</tr>
<tr>
<td>umdk-urma-bin-xxx.rpm</td>
<td>urma内核模块安装包，需要与内核配套使用</td>
</tr>
<tr>
<td>umdk-urma-devel-xxx.rpm</td>
<td>urma开发包，包含开发头文件等</td>
</tr>
<tr>
<td>umdk-urma-tools-xxx.rpm</td>
<td>urma工具包，包含urma_admin、urma_perftest等辅助命令</td>
</tr>
<tr>
<td>umdk-urma-examples-xxx.rpm</td>
<td>包含urma用户态编程API的使用示例</td>
</tr>
</tbody>
</table>

![](figures/urma_caution.png)

> urma组件间暂不支持跨发布版本单独升级

## 2.2 安装依赖

```bash
yum install -y rpm-build
yum install -y make
yum install -y cmake
yum install -y gcc
yum install -y gcc-c++
yum install -y glibc-devel
yum install -y openssl-devel
yum install -y glib2-devel
yum install -y libnl3-devel
yum install -y kernel-devel  # ubcore依赖，来自openEuler内核
```

## 2.3 用户态安装

### 方法1：使用 make install 编译安装

```bash
cd src
mkdir build
cd build
cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable
make install -j
```

### 方法2：单独编译RPM包

RPM包生成在路径 `/root/rpmbuild/RPMS/aarch64` 下：

```bash
mkdir -p /root/rpmbuild/SOURCES/
cd /UMDK
tar -czf /root/rpmbuild/SOURCES/umdk-26.06.0.tar.gz --exclude=.git `ls -A`
rpmbuild -ba umdk.spec --with urma
cd /root/rpmbuild/RPMS/aarch64
rpm -Uvh umdk-urma-lib-26.06.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-bin-26.06.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-tools-26.06.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-example-26.06.0-0.aarch64.rpm --force --nodeps
rpm -Uvh umdk-urma-devel-26.06.0-0.aarch64.rpm --force --nodeps
```

### 方法3：yum安装

```bash
yum install -y umdk-urma-lib-26.06.0-0.aarch64
yum install -y umdk-urma-bin-26.06.0-0.aarch64
yum install -y umdk-urma-example-26.06.0-0.aarch64
yum install -y umdk-urma-tools-26.06.0-0.aarch64
yum install -y umdk-urma-devel-26.06.0-0.aarch64
```

## 2.4 URMA RPM包安装

URMA子系统在UBUS系统中提供高带宽低时延的数据服务，支持在UBUS原生硬件平台上运行，UBUS原生硬件的驱动需要由海思提供。

**URMA支持平台组件图**

![](figures/urma-platform-arch.png)

![](figures/urma_notice.png)

URMA的安装通过RPM的方式，安装需要root权限。

![](figures/urma_warning.png)

**安装要点：**

1. URMA组件包含ubcore等内核模块，liburma-udma.so等各驱动版本需要强配套使用。

2. URMA推荐使用rpm包的方式安装，用户态组件（包含liburma.so、liburma_common.so等）默认安装在 `/usr/lib64/` 下，用户态驱动（liburma-udma.so）默认安装在 `/usr/lib64/urma/` 目录下。

3. 由于URMA子系统的组件liburma.so会打开安装同级目录的urma子目录上的驱动，如果应用需要指定urma安装目录，驱动需要按照以下格式安装：

   `/XXX/YYY/urma/liburma-udma.so`

URMA子系统对外提供的统一运行组件为 umdk-urma-lib 和 umdk-urma-bin 两个RPM包，umdk-urma-tools 包提供了URMA运行时管理工具。如果需要基于URMA进行开发，需要进一步安装 umdk-urma-devel 包。

**RPM安装命令：**

```bash
rpm -ivh umdk-urma-lib-26.06.0-B004.oe2403sp3.aarch64.rpm
rpm -ivh umdk-urma-bin-26.06.0-B004.oe2403sp3.aarch64.rpm
rpm -ivh umdk-urma-devel-26.06.0-B004.oe2403sp3.aarch64.rpm
rpm -ivh umdk-urma-tools-26.06.0-B004.oe2403sp3.aarch64.rpm
rpm -ivh umdk-urma-examples-26.06.0-B004.oe2403sp3.aarch64.rpm
```

## 2.5 内核态ko安装

安装RPM包后需要加载内核模块，ubcore、ubagg和uburma模块为必选加载，另外需要加载海思内核模块udma.ko（通过modprobe或insmod加载udma.ko，具体加载命令以海思提供为准）。

```bash
modprobe ubcore
modprobe uburma
modprobe ubagg
```

> **补充说明**：在某些平台上，可能需要更详细的内核模块加载顺序和参数。以下是包含海思内核模块的完整加载示例：
>
> ```bash
> cd /lib/modules/$(uname -r)/kernel/drivers
> insmod ub/ubfi/ubfi.ko.xz cluster=1  # 使用VF网卡时需移除 cluster=1 参数
> insmod iommu/ummu-core/ummu-core.ko.xz
> insmod ub/hisi-ub/kernelspace/ummu/drivers/ummu.ko.xz
> insmod ub/hisi-ub/kernelspace/ubus/ubus.ko.xz cc_en=0 um_entry_size=1
> insmod ub/hisi-ub/kernelspace/ubus/vendor/hisi/hisi_ubus.ko.xz msg_wait=2000 fe_msg=1 um_entry_size1=0 cfg_entry_offset=512
> insmod ub/hisi-ub/kernelspace/ubase/ubase.ko.xz
> insmod ub/hisi-ub/kernelspace/unic/unic.ko.xz tx_timeout_reset_bypass=1
> insmod ub/hisi-ub/kernelspace/cdma/cdma.ko.xz
> modprobe ubcore uburma
> modprobe udma dfx_switch=1 jfc_arm_mode=2 is_active=0 fast_destroy_tp=0
> modprobe ubagg
> ```

---
# 3 功能依赖

- **系统要求**：OpenEuler 24.03 SP3 或更高版本

- **内核版本**：与编译所用内核一致。举例：编译 OpenEuler 6.6.0 需使用对应 Linux-6.6.0 主线版本的 Linux 内核。

- **运行时依赖**：
  - liburma.so、liburma_common.so、liburma_ubagg.so（用户态库）
  - ubcore.ko、ubagg.ko、uburma.ko（内核模块）

---
# 4 验证与运行示例

## 4.1 设备验证

使用 urma_admin 工具检查设备是否正常扫描：

```bash
urma_admin show
```

输出示例：

```
num ubep_dev tp_type eid link
--- ---------------- -------- -------------------------------------------- --------
0 udma3 UB eid0 0000:0000:0000:00xx:00xx:00xx:00xx:1001 ACTIVE
1 udma3 UB eid1 0000:0000:0000:00xx:00xx:00xx:00xx:1002 ACTIVE
2 udma5 UB eid0 0000:0000:0000:00xx:00xx:00xx:00xx:1003 ACTIVE
3 udma5 UB eid1 0000:0000:0000:00xx:00xx:00xx:00xx:1004 ACTIVE
4 udma2 UB eid0 0000:0000:0000:00xx:00xx:00xx:00xx:1005 ACTIVE
5 udma4 UB eid0 0000:0000:0000:00xx:00xx:00xx:00xx:1006 ACTIVE
```

## 4.2 性能测试示例

```bash
systemctl start scbus-daemon.service

# 启动服务端
urma_perftest send_bw -d bonding_dev_0 -s 2 -n 10 -I 128 -p 1

# 启动客户端（替换 <server_ip> 为实际服务端IP）
urma_perftest send_bw -d bonding_dev_0 -s 2 -n 10 -I 128 -p 1 -S <server_ip>
```
