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

    cmake .. -D BUILD_ALL=disable -D BUILD_URMA=enable
    make install -j
    echo "URMA package installed successfully."

    echo "Configuring test environment YAML..."
    if [ ! -d "$TARGET_YAML_DIR" ]; then
        mkdir -p "$TARGET_YAML_DIR"
    fi

    if [ -f "$LOCAL_YAML" ]; then
        cp -f "$LOCAL_YAML" "$TARGET_YAML_PATH"
        echo "Copied $LOCAL_YAML to $TARGET_YAML_PATH"
    else
        echo "Error: Source YAML file not found at $LOCAL_YAML"
        exit 1
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
    echo -e "\033[32mSUCCESS\033[0m"
}

prepare_and_run