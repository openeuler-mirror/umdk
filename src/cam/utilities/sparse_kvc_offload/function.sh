# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

#!/bin/bash
function check_launch()
{
    if pgrep -f "python.*infer.py" > /dev/null; then
        echo "A Python process executing infer.py was detected to be running, and the script was interrupted and exited."
        exit 1
    else
        echo "No Python process running infer.py was detected."
    fi
}

function get_rank()
{
    filename=$(basename "$YAML")
    world_size=$(python3 -c "import yaml; print(yaml.safe_load(open('$YAML'))['world_size'])")
    if [ -n "$world_size" ]; then
        export WORLD_SIZE=$world_size
        echo "world_size is: $WORLD_SIZE"
        SERVER_NUM=$(( (WORLD_SIZE+15) / 16 ))
        echo "server_num is: $SERVER_NUM"

        if [ "$SERVER_NUM" -eq 1 ]; then
            LOCAL_HOST=`hostname -I|awk -F " " '{print$1}'`
            export IPs=($LOCAL_HOST)
        else
            export IPs=(${IPs[@]:0:$SERVER_NUM})
        fi
    else
        echo "Cannot find world_size in '$filename'"
        exit 1
    fi
}

function check_env_vars()
{
    export PYTORCH_NPU_ALLOC_CONF=expandable_segments:True
    LOCAL_HOST=`hostname -I|awk -F " " '{print$1}'`       # Obtain current server's IP
    export HCCL_SOCKET_IFNAME=enp                     # Socket prefix, to obtain Host IP for HCCL and HCCL group; modify to enp/eth accordingly
    MA_NUM_HOSTS=${#IPs[@]}                           # Number of servers
    export MASTER_ADDR=${IPs[0]}                      # IP of the master server
    export MASTER_PORT=6038                           # Port of the master server
    VC_TASK_INDEX=0                                   # Task index of the current server
    # obtain the task index of each server
    for i in "${!IPs[@]}";
    do
        echo "LOCAL_HOST=${LOCAL_HOST}, IPs[${i}]=${IPs[$i]}"
        if [ "$LOCAL_HOST" == "${IPs[$i]}" ]; then
            echo "Node Rank : ${i}"
            VC_TASK_INDEX=$i
            break
        fi
    done
    echo "VC_TASK_INDEX >>>" $VC_TASK_INDEX

    export MA_NUM_GPUS=16                       # Number of devices on each server. Should be the same for each server
    if [ "$WORLD_SIZE" -lt "$MA_NUM_GPUS" ]; then
        MA_NUM_GPUS=$WORLD_SIZE
    fi
    export LOCAL_WORLD_SIZE=${MA_NUM_GPUS}
    export RANK_OFFSET=`expr $VC_TASK_INDEX \* ${MA_NUM_GPUS}`

    # check world size
    if [ $MA_NUM_HOSTS ]; then
        export DEVICE_SIZE=$(($MA_NUM_GPUS*$MA_NUM_HOSTS))  # Total number of devices across all servers
        if [ ${DEVICE_SIZE} -ge  ${WORLD_SIZE} ]; then
            echo "[INFO] total ranks is ${DEVICE_SIZE}, and use ${WORLD_SIZE} ranks in actual!"
        else
            echo "[ERROR] total ranks is ${DEVICE_SIZE}, but use ${WORLD_SIZE} ranks in actual!"
            exit 0
        fi
    fi

    DATE=`date +%Y%m%d`
    # set result path
    DIR_PREFIX="res"
    export MODEL_NAME="moe"
    PREFIX=$(basename "$YAML")
    PREFIX="${PREFIX%.*}"
    NAME=${MODEL_NAME}_${PREFIX}
    export CASE_NAME=$NAME

    export RES_PATH="${DIR_PREFIX}/${DATE}/${NAME}"
    WORK_DIR=`pwd`
    DUMP_PRECISION_PATH=${WORK_DIR}'/'${RES_PATH}'/dump_data'
    mkdir -p ${WORK_DIR}'/'${RES_PATH}
    mkdir -p ${DUMP_PRECISION_PATH}
    echo "==================================>"

    export HCCL_IF_IP=$LOCAL_HOST
    export HCCL_IF_BASE_PORT=23456

    # 910c needs enable HCCL aiv
    export HCCL_OP_EXPANSION_MODE=AIV

    export HCCL_CONNECT_TIMEOUT=1200
    export HCCL_EXEC_TIMEOUT=1200
}

function launch_infer_task()
{
    cores=`cat /proc/cpuinfo|grep "processor" |wc -l`
    avg_core_per_rank=`expr $cores \/ $MA_NUM_GPUS`
    core_gap=`expr $avg_core_per_rank \- 1`
    for((i=0; i<${MA_NUM_GPUS}; i++))
    do
        echo $i
        start=`expr $i \* $avg_core_per_rank`
        end=`expr $start \+ $core_gap`
        cmdopt=$start"-"$end
        export LOCAL_RANK=$i
        export RANK_ID=$(expr $i + $RANK_OFFSET)
        if [ $i -eq 0 ];then

        taskset -c $cmdopt python3 infer.py \
                            --yaml_file_path=${YAML} 2>&1 | tee ${WORK_DIR}/${RES_PATH}/log_${LOCAL_RANK}.log &
        else
        taskset -c $cmdopt python3 infer.py \
                            --yaml_file_path=${YAML} &> ${WORK_DIR}/${RES_PATH}/log_${LOCAL_RANK}.log &
        fi
    done
}

