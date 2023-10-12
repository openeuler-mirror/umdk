# umdk

#### 介绍
统一内存开发工具包（UMDK）是一套以内存语义为核心的分布式通信软件栈。旨在通过软硬件协同设计新一代网络架构，颠覆传统通信形式，构建以内存语义互联为中心的计算原生网络。
#### 软件架构

```text

urma                          : URMA (Unified Remote Memory Access，统一远端内存访问)
                                URMA子系统在UBUS系统中提供高带宽低时延的数据服务。主要用于对数据中心的各种业务提供消息通信，数据转发的基础功能。对于大数据业务，减少端到端的通信时延。对于HPC和AI业务，提供高带宽、低时延的服务。
├── cmake                     : Cmake 配置文件, 包含如查找 kernel 版本等.
├── CMakeLists.txt            : Cmake 根文件.
├── cmake_uninstall.cmake.in  : Cmake 卸载文件.
├── common                    : 一些 C 语言公共组件, 像 list, hmap, etc.
├── include                   : 头文件，包含内外部所需的头文件
├── lib                       : 用户库, 包含 liburma.
├── tools                     : UMDK 工具, 包括 perftest, admin
├── transport_service         : TPS deamon
└── urma.spec                 : 执行 spec 文件以生成 RPM 包.

```

#### urma 安装教程

1. 编译环境要求
- 你需要安装以下依赖包：

```bash
  yum install -y rpm-build
  yum install -y cmake
  yum install -y make
  yum install -y gcc
  yum install -y gcc-c++
  yum install -y glib2-devel
  yum install -y libsecurec-devel
  yum install -y elfutils-devel
  yum install -y rdma-core-devel   # You may need to provide it yourself
```

2. 编译安装
- 您可以通过以下方式构建和安装ubus rpm包：

```bash
  tar -czf /root/rpmbuild/SOURCES/umdk-urma-1.3.0.tar.gz --exclude=.git `ls -A`
  rpmbuild -ba urma.spec
  rpm -ivh /root/rpmbuild/RPMS/*/umdk*.rpm
```
- 或者，您可以在代码文件夹中手动构建程序以进行调试：

```bash
  mkdir build
  cd build
  cmake ..
  make install
```

3. 编译选项
- RPM 编译选项

```bash
  $ --with transport_service_disable                  可选, i.e. 默认使能 TPS 功能
  $ --define 'kernel_version 4.19.90'                 可选, 指定 kernel 版本
  $ --define 'rpm_version 1.4.0'                      可选, 指定 rpm 版本
  $ --define 'rpm_release  B002'                      可选, 指定发布版本
```

- cmake 编译选项

```bash
  $ -DTPS=disable                                     可选, i.e. 默认使能 TPS 功能
```

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
