#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: cam nda build script (download and build shmem package)
# Create: 2026-07-07
# Note:

set -e

export MODULE_NAME="nda"
export MODULE_BUILD_OUT_PATH="${BUILD_OUT_PATH}/${MODULE_NAME}"

# Validate soc_type: nda only supports ascend950
if [[ -n "${SOC_TYPE}" && "${SOC_TYPE}" != "ascend950" ]]; then
    echo "Error: nda module only supports soc_type 'ascend950', but got '${SOC_TYPE}'"
    exit 1
fi

# rdma_backends source path (inside umdk)
RDMA_BACKENDS_SRC="${ROOT_PATH}/src/cam/framework/nda/src/device/gm2gm/engine/rdma_backends"

if [ ! -d "$MODULE_BUILD_OUT_PATH" ]; then
    mkdir -p "$MODULE_BUILD_OUT_PATH"
fi

cd "$MODULE_BUILD_OUT_PATH"

rm -rf shmem
# Download and build the shmem package
SHMEM_COMMIT_HASH="6a5f4b09695d6c38421ec37a4ee7aa6f700fd77f"
git clone https://gitcode.com/cann/shmem
cd shmem
git checkout "${SHMEM_COMMIT_HASH}" -b nda-base
cd ..

# Override the rdma_backends
cp -f ${RDMA_BACKENDS_SRC}/* shmem/src/device/gm2gm/engine/rdma_backends/

# Build shmem
cd shmem
EXTRA_OPTS=""
if [[ "${BUILD_TYPE}" == "Debug" ]]; then
    EXTRA_OPTS="-debug -enable_ascendc_dump"
fi
# Currently, the NDA function on Yunmai(xscale) network card only supports Ascend950
bash scripts/build.sh -enable_rdma -rdma_backend XSCALE -soc_type Ascend950 ${EXTRA_OPTS}
