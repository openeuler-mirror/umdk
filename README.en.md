# umdk

#### Description
The Unified Memory Development Kit(UMDK) is a set of distributed communication software stack with memory semantics as the core. It aims to design a new-generation network architecture through software-hardware collaboration, subvert the traditional communication form, and build a computing native network centered on memory semantic interconnection.

#### Software Architecture

urma                                 : URMA (Unified Remote Memory Access)
                                          The URMA subsystem provides high-bandwidth and low-latency data
                                          services in the UBUS system. Provides basic functions of message
                                          communication and data forwarding for various services in the data
                                          center. For big data services, the end-to-end communication delay
                                          is reduced. High-bandwidth and low-latency services are provided for
                                          HPC and AI services.
├── cmake                     : Cmake configuration files, such as looking for kernel version, etc.
├── CMakeLists.txt            : Cmake root file.
├── cmake_uninstall.cmake.in  : Cmake uninstall file.
├── common                    : Some public functions of C language, such as list, hmap, etc. Each library will use.
├── include                   : Header files for external use and internal public use.
├── lib                       : User library, including liburma.
├── tools                     : UMDK tools, including perftest, admin
├── transport_service         : TPS deamon
└── urma.spec                 : Execute the spec file that generates the RPM package.


#### URMA Installation

1. Compile environment configuration
- You need to install the following dependency packages
  $ yum install -y rpm-build
  $ yum install -y cmake
  $ yum install -y make
  $ yum install -y gcc
  $ yum install -y gcc-c++
  $ yum install -y glib2-devel
  $ yum install -y libsecurec-devel
  $ yum install -y elfutils-devel
  $ yum install -y rdma-core-devel   # You may need to provide it yourself

- You need to find and install the package that matches the OS version.
  $ rpm -ivh kernel-devel*.rpm
  $ rpm -ivh kernel-headers*.rpm
  $ rpm -ivh ksecurec-devel*.rpm

2. Build and install
- You can build and install the ubus rpm packages by:
  $ cd urma
  $ tar -czf /root/rpmbuild/SOURCES/umdk-1.3.0.tar.gz --exclude=.git `ls -A`
  $ rpmbuild -ba umdk.spec
  $ rpm -ivh /root/rpmbuild/RPMS/*/umdk*.rpm

- Alternately, you can build your programs manually in the code folder for debug.
  $ mkdir build
  $ cd build
  $ cmake ..
  $ make install

3. Compilation Options
- RPM compilation Options
  $ --with transport_service_disable                  option, i.e. enable TPS by default
  $ --define 'kernel_version 4.19.90'                 option, specify kernel version
  $ --define 'rpm_version 1.4.0'                      option, specify rpm version
  $ --define 'rpm_release  B002'                      option, specify release version

- cmake compilation Options
  $ -DTPS=disable                                     option, i.e. enable tps service by default

#### Contribution

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


#### Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
