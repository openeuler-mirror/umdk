# URMA

## 1. Introduction
The URMA subsystem provides high-bandwidth, low-latency data services within the UBUS system. It primarily offers foundational functionalities for message communication and data forwarding for various services in data centers, while also laying the groundwork for more advanced features such as semantic orchestration. For big data services, it reduces end-to-end communication latency. For HPC and AI services, it delivers high-bandwidth, low-latency services.

## 2. Compilation and Installation
#### Installation Guide
##### Compiling the URMA RPM Package

**Compiling URMA Separately**
Method 1:
1. Navigate to the root directory of the UMDK project.

2. tar -czf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git `ls -A`

3. rpmbuild -ba umdk.spec --with urma

Method 2:

4. Navigate to the root directory of the UMDK/src project.

5. mkdir build

6. cd build

7. cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable

8. make install -j

##### Install URMA
Note: URMA requires the ability to call the URMA component, and the URMA software must be installed in advance.
rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-urma-*.rpm
