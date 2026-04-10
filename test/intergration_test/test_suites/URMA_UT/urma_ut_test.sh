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

    find . -maxdepth 2 -type d -name "test_*" | while read -r test_dir; do
        if [ -f "$test_dir/test.py" ]; then
            echo "----------------------------------------"
            echo "Running test in: $test_dir"
            if pytest "$test_dir/test.py"; then
                echo -e "\033[32m[PASS]\033[0m $test_dir"
            else
                echo -e "\033[31m[FAIL]\033[0m $test_dir"
            fi
        fi
    done

    echo "========================================"
    echo "All tasks finished at $(date)"
    exit 0
}

prepare_and_run
