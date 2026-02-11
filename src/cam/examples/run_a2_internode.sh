#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam moe a2 normal run script
# Create: 2026-02-11
# Note:
# History: 2026-02-11 create cam moe a2 normal run script

# set your master node ip
RANK0_IP=""
if [ -z "$RANK0_IP" ]; then
    echo please set RANK0_IP
fi
IP=$(hostname -I | awk '{print $1}')

# source operator set_env
source /ssd_2/rrq/opp/vendors/CAM/bin/set_env.bash

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir" || exit

export WORLD_SIZE=2
export HCCL_BUFFSIZE=3000
export HCCL_INTRA_PCIE_ENABLE=1
export HCCL_INTRA_ROCE_ENABLE=0
export HCCL_BUFFSIZE=4096

export HCCL_SOCKET_IFNAME=enp67s0f5

# set logs path
export ASCEND_PROCESS_LOG_PATH=$(pwd)/logs
export ASCEND_GLOBAL_LOG_LEVEL=3
rm -rf logs
mkdir logs


export MASTER_ADDR=${RANK0_IP}
if [ "${IP}" == "${RANK0_IP}" ]; then
  echo "env rank 0"
  export RANK=0
else
  echo "env rank 1"
  export RANK=1
fi

python ./moe_dispatch_combine_prefill_a2_sample.py