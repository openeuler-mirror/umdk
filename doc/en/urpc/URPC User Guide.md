# 1. Introduction
Provides a high-performance RPC communication library with extremely low latency, ultra-high IOPS, and massive bandwidth.

# 2. Software Build

## Build and install RPM packages
```bash
rm -rf .git*
mkdir -p /root/rpmbuild/SOURCES/
tar -cvf /root/rpmbuild/SOURCES/umdk-25.12.0.tar.gz --exclude=.git $(ls -A)
rpmbuild -bb umdk.spec --with urpc
```

## Complie uRPC with cmake
```bash
cd src
mkdir build; cd build
cmake .. -DBUILD_ALL=disable -DBUILD_URPC=enable
make -j16
make install # optional, install uRPC if needed
```

# 3. Usage Guide
- rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-urpc-*.rpm
- urpc_framework_example -i SERVER_IP -d DEV_NAME -T 1 -e 0 --server --eid EID -L --assign_mode 2 -R
- urpc_framework_example -i SERVER_IP -d DEV_NAME -T 1 -e 0 --client --eid EID -L --assign_mode 2 -R

example:
```bash
urpc_framework_example -i 192.168.100.100 -d udma0 -T 1 -e 0 --server --eid 4245:4944:0000:0000:0000:0000:0100:0000 -L --assign_mode 2 -R
urpc_framework_example -i 192.168.100.100 -d udma0 -T 1 -e 0 --client --eid 4245:4944:0000:0000:0000:0000:0200:0000 -L --assign_mode 2 -R
```