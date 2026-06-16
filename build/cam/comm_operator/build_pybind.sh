#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind building script
# Create: 2025-12-09
# Note:
# History: 2025-12-09 create pybind building script

set -e
EXT_PATH=$MODULE_BUILD_PATH/pybind
DIST_OUT_PATH=$MODULE_BUILD_OUT_PATH

if [ ! -d "$MODULE_BUILD_PATH" ]; then
    mkdir -p $MODULE_BUILD_PATH
fi

build_pybind() {
    if [ -d "$DIST_OUT_PATH/dist" ]; then
        rm -rf $DIST_OUT_PATH/dist
    fi
    cp -rf $MODULE_SRC_PATH/pybind $MODULE_BUILD_PATH
    cp -rf $MODULE_SRC_PATH/pybind/pytorch_extension $BUILD_PATH
    cd $EXT_PATH
    if [ -z "$CAM_COMM_PATH" ]; then
        CAM_COMM_PATH=$MODULE_SRC_PATH
        export CAM_COMM_PATH
    fi

    # 限制 C++ 编译并行度：可通过 CAM_BUILD_JOBS 环境变量配置，默认 8
    # Jenkins ECS 等内存受限环境建议设置为 2~4
    export MAX_JOBS=${CAM_BUILD_JOBS:-8}

    rm -rf build/ dist/ umdk_cam_op_lib_custom.egg-info/
    python3 setup.py bdist_wheel
    DIST_GEN_PATH=$EXT_PATH/dist
    if [ -d "$DIST_GEN_PATH" ]; then
        echo "copy $DIST_GEN_PATH to $DIST_OUT_PATH/"
        cp -rf $DIST_GEN_PATH $DIST_OUT_PATH
    else
        echo $DIST_GEN_PATH does not exist
        echo "build_pybind fail"
        return 1
    fi
}

build_pybind
