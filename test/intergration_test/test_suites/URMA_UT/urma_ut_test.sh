#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
#
set -e

CURRENT_PATH=$(cd $(dirname $0); pwd)
PROJECT_ROOT="$CURRENT_PATH/../../../../"
LOCAL_YAML="$CURRENT_PATH/test_env.yaml"
TARGET_YAML_DIR="/etc/ubus_ci"
TARGET_YAML_PATH="$TARGET_YAML_DIR/test_env.yaml"

LOG_SWITCH=${ENABLE_LOG:-"false"}

function prepare_and_run() {
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
    find ./ -name test.py | xargs -i pytest {}
    find ../URMA -name test.py | grep -v qemu | xargs -i pytest {}
    echo "========================================"
    echo "All tasks finished at $(date)"
    exit 0
}

prepare_and_run
