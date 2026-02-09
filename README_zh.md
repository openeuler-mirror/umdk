
# UMDK
#### 一、UMDK介绍
灵衢内存语义开发包（UMDK）是一套以内存语义为核心的分布式通信软件库。
为数据中心网络、超节点内、服务器内的卡与卡之间提供高性能的通信接口，使能和释放灵衢总线的硬件能力。

![UMDK组件图](./doc/images/UMDK_component_image.ch.png)

#### 二、组件介绍
1. URMA：统一内存语义，提供了单边、双边、原子操作等远端内存操作方式，是应用之间通信的基础。提供两类接口，一是北向应用编程接口，为应用提供通信API，二是南向驱动编程接口，为驱动开发者提供接入UMDK的API。

2. CAM：超节点通信加速库，提供灵衢超节点亲和的高性能训推通信加速，北向可对接vllm/SGlang/VeRL等主流社区，南向亲和昇腾超节点硬件及组网

3. URPC：统一远程过程调用，支持灵衢原生高性能主机间和设备间RPC通信，以及RPC加速。

4. ULOCK：统一状态同步，支持灵衢原生高性能状态同步，包含分布式锁DLock等，加速数据库等分布式应用全局资源分配。

5. USOCK：UB通信生态构建，兼容标准Socket编程接口，使能TCP应用零修改提升网络通信性能。

#### 三、编译运行
1. 编译环境要求
- 编译环境：kernel 6.6
- 同时你需要安装以下依赖包：

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
  yum install -y kernel-devel  # ubcore is necessary from openEuler kernel
```

2. 编译指导
- 您可以通过以下方式构建和安装umdk rpm包：

```bash
  mkdir -p /root/rpmbuild/SOURCES/
  tar -czf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git `ls -A`
  rpmbuild -ba umdk.spec
```

- RPM 编译选项
```bash
  $ --with asan                              option, i.e. disable asan by default
  $ --with test                              option, i.e. disable test by default
  $ --with urma                              option, i.e. disable urma by default
  $ --with urpc                              option, i.e. disable urpc by default
  $ --with dlock                             option, i.e. disable dlock by default
  $ --with ums                               option, i.e. disable ums by default
  $ --define 'kernel_version 6.6.92'         option, specify kernel version
  $ --define 'rpm_release  0'                option, specify release version
```

3. 部署指导
- 运行时依赖请检查前置驱动已加载，如未加载请手动加载
```bash
cd /lib/modules/$(uname -r)/kernel/drivers
insmod ub/ubfi/ubfi.ko.xz  cluster=1       # 使用vf网卡时需要将cluster=1参数去除
insmod iommu/ummu-core/ummu-core.ko.xz
cd /lib/modules/$(uname -r)/kernel/drivers/ub/hisi-ub/kernelspace
insmod ummu/drivers/ummu.ko.xz ipver=609
insmod ubus/ubus.ko.xz ipver=609  cc_en=0  um_entry_size=1
insmod ubus/vendor/hisi/hisi_ubus.ko.xz msg_wait=2000 fe_msg=1 um_entry_size1=0 cfg_entry_offset=512
insmod ubase/ubase.ko.xz
insmod unic/unic.ko.xz tx_timeout_reset_bypass=1
insmod cdma/cdma.ko.xz

```
- 安装rpm包
```bash
rpm -ivh /root/rpmbuild/RPMS/*/umdk*.rpm
cp -f /usr/bin/urma_perftest /usr/local/bin/
modprobe ubcore
modprobe uburma
cd /lib/modules/$(uname -r)/kernel/drivers
insmod ub/hisi-ub/kernelspace/udma/udma.ko.xz dfx_switch=1 ipver=609 fast_destroy_tp=0 jfc_arm_mode=2
modprobe ubagg #如果需要使能多路径
modprobe ums # 如果需要使能ums
```
-  添加权限
```bash
#如果没有权限，需要手动添加权限
chmod -R 777 /usr/lib64/urma
chmod 777 /dev/ummu/tid
chmod 755 /usr/lib64/liburma*
```

#### 四、参与贡献

我们非常欢迎开发者提交贡献, 如果您发现了一个bug或者有一些想法想要交流，欢迎[发邮件到dev列表](https://openeuler.org/zh/community/mailing-list) 或者[提交一个issue](https://gitee.com/openeuler/umdk/issues) 。

#### 五、许可

代码使用的许可证详见[LICENSES](./LICENSES/README)

doc目录下的文档使用许可证详见[LICENSE](./doc/LICENSE)