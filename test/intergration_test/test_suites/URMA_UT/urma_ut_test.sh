#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
#
set -e

CURRENT_PATH=$(cd $(dirname $0); pwd)

PROJECT_ROOT="$CURRENT_PATH/../../../../"
SRC_BUILD_DIR="$PROJECT_ROOT/src/build"
LOCAL_YAML="$CURRENT_PATH/test_env.yaml"
TARGET_YAML_DIR="/etc/ubus_ci"
TARGET_YAML_PATH="$TARGET_YAML_DIR/test_env.yaml"

LOG_SWITCH=${ENABLE_LOG:-"false"}

function run_test() {
    local test_file=$1

    if [ "$LOG_SWITCH" = "true" ]; then
        export PYTEST_ADDOPTS="--log-cli-level=INFO -s"
    else
        export PYTEST_ADDOPTS="--log-cli-level=ERROR"
    fi

    echo "------------------------------------------------"
    echo "Running pytest for: $test_file (Log Switch: $LOG_SWITCH)"
    pytest "$test_file"
}

function prepare_and_run() {
    echo $SRC_BUILD_DIR
    mkdir -p "$SRC_BUILD_DIR"
    cd "$SRC_BUILD_DIR"

    if [ -d "./build" ]; then
        rm -rf build
    fi
    #rpm -ivh /root/rpmbuild/RPMS/aarch64/umdk-urma-kmod-*.rpm
    cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable
    make install -j
    echo "URMA package installed successfully."
    
    #systemctl stop ubse
    #sleep 1
    #rmmod ubagg || exit 1
    #rmmod uburma || exit 1
    #rmmod ipourma || exit 1
    #rmmod udma
    #rmmod ubcore
    #modprobe ubcore g_ubcore_log_level=6
    #modprobe uburma g_uburma_log_level=6
    #modprobe ubagg
    #modprobe ipourma tx_ring_size=16 rx_ring_size-32 page_level=16 ctp_sl=6
    #modprobe udma debug_switch=1 jfc_arm_mode=2 well_know_jetty_pgsz_check=0
    #systemctl start ubse
    #sleep 1
    #echo "URMA drivers update installed successfully."
    echo "Configuring test environment YAML..."
    if [ ! -d "$TARGET_YAML_DIR" ]; then
        mkdir -p "$TARGET_YAML_DIR"
    fi

    if [ -f "$TARGET_YAML_PATH" ]; then
        echo "yam already exists"
    else
        cp -f "$LOCAL_YAML" "$TARGET_YAML_PATH"
    fi

    echo "Starting Pytest execution..."
    cd "$CURRENT_PATH"

    run_test "./test_urma_basic_loopback/test.py"
    run_test "./test_bonding_brpc/test.py"
    run_test "./test_bonding_hcom/test.py"
    run_test "./test_bonding_kvache/test.py"
    run_test "./test_bonding_vm_migration/test.py"

    echo "========================================"
    echo "All tasks finished at $(date)"
    exit 0
}

prepare_and_run
