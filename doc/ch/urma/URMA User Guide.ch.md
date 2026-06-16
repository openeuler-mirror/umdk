# URMA

## 1. 介绍
URMA子系统在UBUS系统中提供高带宽低时延的数据服务。主要用于对数据中心的各种业务提供消息通信，数据转发的基础功能，同时为更高级的如语义编排功能奠定基础。对于大数据业务，减少端到端的通信时延。对于HPC和AI业务，提供高带宽、低时延的服务。

## 2. 编译安装
#### 安装教程
##### 编译URMA RPM包

**单独编译URMA**
方法一:
1. 进入UMDK工程根目录下

2. tar -czf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git `ls -A`

3. rpmbuild -ba umdk.spec --with urma

方法二:

4. 进入UMDK/src工程根目录下

5. mkdir build

6. cd build

7. cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable

8. make install -j

##### 安装URMA
说明:URMA需要调用URMA组件的能力，需要提前安装好URMA软件。
rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-urma-*.rpm
