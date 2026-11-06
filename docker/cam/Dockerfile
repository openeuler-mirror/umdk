# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: cam docker file sample.
# Create: 2026-05-11
# Note:
# History: 2026-05-11 create cam docker file sample.
#          2026-05-30 add CANN 9.0 build stage
#          2026-11-06 add CANN 9.2.1 build stages (a3 + a5); for the 9.2.1 presets
#                     torch/torch_npu bump to 2.14.0 (the CANN 9.2.x paired
#                     torch_npu 26.2.0 line drops pytorch 2.8.0 support) and
#                     SHMEM bumps to v1.7.0 (per-preset, older presets keep
#                     their original stack via SHMEM_VERSION)

ARG BUILD_ARG=a5_9.2.1_open

FROM docker.1ms.run/library/ubuntu:24.04 AS base

LABEL maintainer=liyuxing

SHELL ["/bin/bash", "-c"]

# Install system deps, miniconda, and python dependencies
RUN apt-get update && \
    apt-get install -y vim git cmake net-tools wget gcc g++ make iputils-ping iproute2 libnuma-dev && \
    apt-get install -y zlib1g-dev libbz2-dev libssl-dev libncurses-dev libsqlite3-dev libreadline-dev tk-dev libgdbm-dev libpcap-dev liblzma-dev libexpat1-dev && \
    git config --global http.sslVerify false && \
    git config --global https.sslVerify false && \
    wget --no-check-certificate https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh -O miniconda.sh && \
    bash miniconda.sh -b -p /opt/conda && \
    rm miniconda.sh && \
    export PATH="/opt/conda/bin:$PATH" && \
    conda init bash && \
    conda config --set remote_connect_timeout_secs 120.0 && \
    conda config --set remote_read_timeout_secs 300.0 && \
    conda config --set remote_max_retries 15 && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r && \
    conda config --add envs_dirs /opt/conda/envs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/conda/bin:$PATH"

RUN mkdir -p /root/.pip && printf '[global]\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple\ntrusted-host = pypi.tuna.tsinghua.edu.cn\ntimeout = 300\nretries = 10\n' > /root/.pip/pip.conf

RUN conda create -n cam_py311_pt28 python=3.11 -y && \
    conda run -n cam_py311_pt28 pip install --index-url https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn attrs cython numpy==1.24.0 decorator sympy cffi pyyaml pathlib2 psutil protobuf==3.20 scipy requests absl-py pybind11 pytest setuptools_scm ninja

# Build gtest 1.16.0
RUN cd /tmp && \
    wget --no-check-certificate https://github.com/google/googletest/archive/refs/tags/v1.16.0.tar.gz && \
    tar -xzf v1.16.0.tar.gz && \
    cd googletest-1.16.0 && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local . && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/googletest-1.16.0 /tmp/v1.16.0.tar.gz

# Build OpenMPI 5.0.7
RUN cd /tmp && \
    wget --no-check-certificate https://download.open-mpi.org/release/open-mpi/v5.0/openmpi-5.0.7.tar.gz && \
    tar -xzf openmpi-5.0.7.tar.gz && \
    cd openmpi-5.0.7 && \
    CC=gcc CXX=g++ ./configure --prefix=/usr/local/openmpi-5.0.7 --enable-orterun-prefix-by-default && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/openmpi-5.0.7 /tmp/openmpi-5.0.7.tar.gz

# Build nlohmann/json 3.12.0
RUN cd /tmp && \
    wget --no-check-certificate https://github.com/nlohmann/json/archive/refs/tags/v3.12.0.tar.gz && \
    tar -xzf v3.12.0.tar.gz && \
    cd json-3.12.0 && \
    mkdir build && cd build && \
    cmake .. -DJSON_BuildTests=OFF -DCMAKE_INSTALL_PREFIX=/usr && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/json-3.12.0 /tmp/v3.12.0.tar.gz

# ==========================================
# CANN 8.5
# ==========================================
FROM base AS config_a3_8.5_open

# Per-preset SHMEM source version (consumed by the final stage)
ENV SHMEM_VERSION=v1.3.0

# CANN installer requires python3.11 in PATH
RUN ln -s /opt/conda/envs/cam_py311_pt28/bin/python3 /usr/local/bin/python3.11 && \
    cd /tmp && \
    wget --no-check-certificate https://ascend-repo.obs.cn-east-2.myhuaweicloud.com/CANN/CANN%208.5.T63/Ascend-cann_8.5.0_linux-aarch64.run && \
    wget --no-check-certificate https://ascend-repo.obs.cn-east-2.myhuaweicloud.com/CANN/CANN%208.5.T63/Ascend-cann-A3-ops_8.5.0_linux-aarch64.run && \
    chmod +x *.run && \
    ./Ascend-cann_8.5.0_linux-aarch64.run --full -q && \
    ./Ascend-cann-A3-ops_8.5.0_linux-aarch64.run --install -q && \
    rm -rf /tmp/*.run

RUN cd /tmp && \
    wget --no-check-certificate https://gitcode.com/Ascend/pytorch/releases/download/v7.3.0-pytorch2.8.0/torch_npu-2.8.0.post2-cp311-cp311-manylinux_2_28_aarch64.whl && \
    conda run -n cam_py311_pt28 pip install torch_npu-2.8.0.post2-cp311-cp311-manylinux_2_28_aarch64.whl && \
    rm -rf /tmp/*

# ==========================================
# CANN 9.0
# ==========================================
FROM base AS config_a3_9.0_open

# Per-preset SHMEM source version (consumed by the final stage)
ENV SHMEM_VERSION=v1.3.0

# CANN installer requires python3.11 in PATH
RUN ln -s /opt/conda/envs/cam_py311_pt28/bin/python3 /usr/local/bin/python3.11 && \
    cd /tmp && \
    wget --no-check-certificate https://ascend.devcloud.huaweicloud.com/artifactory/cann-run-release/software/master/20260213000325157/aarch64/Ascend-cann-toolkit_9.0.0_linux-aarch64.run && \
    wget --no-check-certificate https://ascend.devcloud.huaweicloud.com/artifactory/cann-run-release/software/master/20260213000325157/aarch64/Ascend-cann-A3-ops_9.0.0_linux-aarch64.run && \
    chmod +x *.run && \
    ./Ascend-cann-toolkit_9.0.0_linux-aarch64.run --full -q && \
    ./Ascend-cann-A3-ops_9.0.0_linux-aarch64.run --install -q && \
    rm -rf /tmp/*.run

RUN cd /tmp && \
    wget --no-check-certificate https://gitcode.com/Ascend/pytorch/releases/download/v26.0.0-pytorch2.8.0/torch_npu-2.8.0.post4-cp311-cp311-manylinux_2_28_aarch64.whl && \
    conda run -n cam_py311_pt28 pip install torch_npu-2.8.0.post4-cp311-cp311-manylinux_2_28_aarch64.whl && \
    rm -rf /tmp/*

# ==========================================
# CANN 9.2.1 (A5 / Ascend 950)
# ==========================================
FROM base AS config_a5_9.2.1_open

# CANN installer requires python3.11 in PATH
RUN ln -s /opt/conda/envs/cam_py311_pt28/bin/python3 /usr/local/bin/python3.11 && \
    cd /tmp && \
    wget --no-check-certificate https://ascend-repo.obs.cn-east-2.myhuaweicloud.com/CANN/CANN%209.2.1/Ascend-cann-toolkit_9.2.1_linux-aarch64.run && \
    wget --no-check-certificate https://ascend-repo.obs.cn-east-2.myhuaweicloud.com/CANN/CANN%209.2.1/Ascend-cann-950-ops_9.2.1_linux-aarch64.run && \
    chmod +x *.run && \
    ./Ascend-cann-toolkit_9.2.1_linux-aarch64.run --full -q && \
    ./Ascend-cann-950-ops_9.2.1_linux-aarch64.run --install -q && \
    rm -rf /tmp/*.run

# CANN 9.2.x is paired with the torch_npu 26.2.0 line, which no longer ships a
# pytorch 2.8.0 build; use the latest paired pytorch (2.14.0) + torch_npu 2.14.0
# wheels from the same gitcode release.
RUN cd /tmp && \
    wget --no-check-certificate "https://gitcode.com/Ascend/pytorch/releases/download/v26.2.0-pytorch2.14.0/torch-2.14.0%2Bcpu-cp311-cp311-manylinux_2_28_aarch64.whl" && \
    wget --no-check-certificate "https://gitcode.com/Ascend/pytorch/releases/download/v26.2.0-pytorch2.14.0/torch_npu-2.14.0-cp311-cp311-manylinux_2_28_aarch64.whl" && \
    conda run -n cam_py311_pt28 pip install torch-2.14.0+cpu-cp311-cp311-manylinux_2_28_aarch64.whl torch_npu-2.14.0-cp311-cp311-manylinux_2_28_aarch64.whl && \
    rm -rf /tmp/*

# Per-preset SHMEM settings (consumed by the final stage). Kept at the end of
# the stage so that tweaking them does not invalidate the CANN install layers.
ENV SHMEM_VERSION=v1.7.0
ENV SHMEM_SOC_TYPE=Ascend950
ENV ACLSHMEM_UDMA_SUPPORT=ON

# ==========================================
# CANN 9.2.1 (A3)
# ==========================================
FROM base AS config_a3_9.2.1_open

# CANN installer requires python3.11 in PATH
RUN ln -s /opt/conda/envs/cam_py311_pt28/bin/python3 /usr/local/bin/python3.11 && \
    cd /tmp && \
    wget --no-check-certificate https://ascend-repo.obs.cn-east-2.myhuaweicloud.com/CANN/CANN%209.2.1/Ascend-cann-toolkit_9.2.1_linux-aarch64.run && \
    wget --no-check-certificate https://ascend-repo.obs.cn-east-2.myhuaweicloud.com/CANN/CANN%209.2.1/Ascend-cann-A3-ops_9.2.1_linux-aarch64.run && \
    chmod +x *.run && \
    ./Ascend-cann-toolkit_9.2.1_linux-aarch64.run --full -q && \
    ./Ascend-cann-A3-ops_9.2.1_linux-aarch64.run --install -q && \
    rm -rf /tmp/*.run

RUN cd /tmp && \
    wget --no-check-certificate "https://gitcode.com/Ascend/pytorch/releases/download/v26.2.0-pytorch2.14.0/torch-2.14.0%2Bcpu-cp311-cp311-manylinux_2_28_aarch64.whl" && \
    wget --no-check-certificate "https://gitcode.com/Ascend/pytorch/releases/download/v26.2.0-pytorch2.14.0/torch_npu-2.14.0-cp311-cp311-manylinux_2_28_aarch64.whl" && \
    conda run -n cam_py311_pt28 pip install torch-2.14.0+cpu-cp311-cp311-manylinux_2_28_aarch64.whl torch_npu-2.14.0-cp311-cp311-manylinux_2_28_aarch64.whl && \
    rm -rf /tmp/*

# Per-preset SHMEM settings (consumed by the final stage).
ENV SHMEM_VERSION=v1.7.0

# ==========================================
# Final stage
# ==========================================
FROM config_${BUILD_ARG} AS final

# Build and install SHMEM from source (version per preset via SHMEM_VERSION).
# For the Ascend950 preset (SHMEM_SOC_TYPE=Ascend950) the build also needs the
# nlohmann/json v3.11.3 sources in 3rdparty/json, mirroring scripts/build.sh.
RUN git clone --depth 1 --branch ${SHMEM_VERSION} https://gitcode.com/cann/shmem.git /tmp/shmem && \
    cd /tmp/shmem && \
    if [ -n "${SHMEM_SOC_TYPE:-}" ]; then \
        git clone --branch v3.11.3 --depth 1 https://gitcode.com/GitHub_Trending/js/json.git 3rdparty/json; \
    fi && \
    export PATH="/opt/conda/envs/cam_py311_pt28/bin:/opt/conda/bin:$PATH" && \
    source /usr/local/Ascend/ascend-toolkit/set_env.sh && \
    export SOURCE_DATE_EPOCH=0 && \
    export SOC_TYPE="${SHMEM_SOC_TYPE:-}" && \
    python3 setup.py bdist_wheel && \
    conda run -n cam_py311_pt28 pip install /tmp/shmem/dist/*.whl && \
    mkdir -p /usr/local/Ascend/shmem/latest/shmem && \
    cp -r /tmp/shmem/install/shmem/* /usr/local/Ascend/shmem/latest/shmem/ && \
    cp /tmp/shmem/scripts/set_env.sh /usr/local/Ascend/shmem/latest/set_env.sh && \
    cp /tmp/shmem/scripts/install.sh /usr/local/Ascend/shmem/latest/ && \
    mkdir -p /usr/local/Ascend/shmem/latest/scripts && \
    cp /tmp/shmem/scripts/uninstall.sh /usr/local/Ascend/shmem/latest/scripts/ && \
    chmod +x /usr/local/Ascend/shmem/latest/install.sh && \
    rm -rf /tmp/shmem

ENV GTEST_ROOT=/usr/local
ENV BASH_ENV=/etc/bashrc
ENV PATH="/usr/local/openmpi-5.0.7/bin:$PATH"
ENV LD_LIBRARY_PATH="/usr/local/openmpi-5.0.7/lib:/usr/local/Ascend/ascend-toolkit/latest/aarch64-linux/lib64:/usr/local/Ascend/ascend-toolkit/latest/aarch64-linux/devlib"

RUN echo 'export HISTSIZE=1000' >> /etc/bashrc && \
    echo 'export HISTFILESIZE=2000' >> /etc/bashrc && \
    echo 'shopt -s histappend' >> /etc/bashrc && \
    echo 'export PROMPT_COMMAND="history -a"' >> /etc/bashrc && \
    echo 'unset TMOUT' >> /etc/bashrc && \
    echo 'source /usr/local/Ascend/ascend-toolkit/set_env.sh' >> /etc/bashrc && \
    echo 'source /usr/local/Ascend/shmem/latest/set_env.sh' >> /etc/bashrc && \
    echo 'export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/usr/local/Ascend/ascend-toolkit/latest/aarch64-linux/lib64:/usr/local/Ascend/ascend-toolkit/latest/aarch64-linux/devlib"' >> /etc/bashrc && \
    echo 'source /etc/bashrc' >> ~/.bashrc && \
    echo 'conda activate cam_py311_pt28' >> ~/.bashrc

RUN export CANN_VERSION=$(head -n 1 /usr/local/Ascend/ascend-toolkit/latest/compiler/version.info) && \
    export TORCH_VERSION=$(conda run -n cam_py311_pt28 pip show torch | sed -n "s/^Version: //p") && \
    echo "=========================================" > /etc/motd && \
    echo "CAM Development Environment" >> /etc/motd && \
    echo "=========================================" >> /etc/motd && \
    echo "欢迎使用CAM开发环境容器" >> /etc/motd && \
    echo "" >> /etc/motd && \
    echo "可用环境：" >> /etc/motd && \
    echo "  - cam_py311_pt28: Python 3.11 + torch ${TORCH_VERSION}" >> /etc/motd && \
    echo "     · CAM/UMDK/vLLM/sgl/xccl 仓编译|运行" >> /etc/motd && \
    echo "" >> /etc/motd && \
    echo "已安装工具：" >> /etc/motd && \
    echo "  - CANN ${CANN_VERSION}" >> /etc/motd && \
    echo "  - SHMEM ${SHMEM_VERSION#v}" >> /etc/motd && \
    echo "  - OpenMPI 5.0.7" >> /etc/motd && \
    echo "  - gtest 1.16.0" >> /etc/motd && \
    echo "  - nlohmann/json 3.12.0" >> /etc/motd && \
    echo "" >> /etc/motd && \
    echo "默认激活: cam_py311_pt28 + CANN ${CANN_VERSION}" >> /etc/motd && \
    echo "=========================================" >> /etc/motd && \
    echo "cat /etc/motd" >> ~/.bashrc
