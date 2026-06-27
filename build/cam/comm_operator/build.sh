#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam comm_operator build script (include-list build with operator selection)
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script
#          2026-06-26 add -c/-a/-q operator selection via operator_registry.json +
#                     select_ops.py; drop coverage (-r) support

set -e

export MODULE_NAME="comm_operator"
export MODULE_SRC_PATH="${SRC_PATH}/${MODULE_NAME}"
export MODULE_SCRIPTS_PATH="${SCRIPTS_PATH}/${MODULE_NAME}"
export MODULE_BUILD_OUT_PATH="${BUILD_OUT_PATH}/${MODULE_NAME}"
export MODULE_TEST_PATH="${TEST_PATH}/${MODULE_NAME}"
export MODULE_BUILD_PATH="${BUILD_PATH}/${MODULE_NAME}"
IS_EXTRACT=0
SOC_VERSION="all"
ENABLE_UT_BUILD=0
ENABLE_PYBIND_BUILD=1
ENABLE_SRC_BUILD=1
ENABLE_CAM_COMM_BUILD=1
OP_SELECT=""        # -a 指定的算子列表（分号分隔），为空=全量
USE_W4A8=0          # -q 标志：1=编译 fused_deep_moe_w4a8 量化变体

build_cam_comm() {
    cd "$MODULE_SRC_PATH"
    if [ -d "./build" ]; then
        rm -rf "./build"
    fi
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
        && make && make install || {
            echo "build_cam_comm fail"
            return 1
        }
}

BuildTest() {
    cd "${MODULE_TEST_PATH}/ut_gtest"
    if [ -d "./build" ]; then
        rm -rf "./build"
    fi
    mkdir -p ./build
    cd build
    cmake .. && make -j && make install
    if [ $? -ne 0 ]; then
        echo "BuildTest fail"
        return 1
    fi
}

print_help() {
    echo "
    ./build.sh comm_operator <opt>...
    -x Extract the run package
    -c Target SOC VERSION (e.g. ascend910_93). If omitted, all registered
       SOC generations are built. Supported: [ascend910_93]
    -a Semicolon-separated operator list to compile (requires -c). Names must
       match the SOC support list in operator_registry.json. Omit to compile
       the full SOC set.
    -q Select the fused_deep_moe_w4a8 (quantization) variant instead of
       fused_deep_moe. The two share source filenames and are mutually exclusive.
       fused_deep_moe_fwk is independent and can coexist with either.
    -d Enable debug
    -t Enable UT build
    -p Enable pybind build
    "
}

while getopts "c:a:xdtqph" opt; do
    case $opt in
    c)
        SOC_VERSION=$OPTARG
        ;;
    a)
        OP_SELECT=$OPTARG
        ;;
    x)
        IS_EXTRACT=1
        ;;
    d)
        export BUILD_TYPE="Debug"
        ;;
    t)
        ENABLE_UT_BUILD=1
        ENABLE_SRC_BUILD=0
        ;;
    q)
        USE_W4A8=1
        ;;
    p)
        ENABLE_PYBIND_BUILD=1
        ENABLE_SRC_BUILD=0
        ;;
    h)
        print_help
        exit 0
        ;;
    esac
done

if [ ! -d "$BUILD_OUT_PATH/${MODULE_NAME}" ]; then
    mkdir -p "$BUILD_OUT_PATH/${MODULE_NAME}"
fi

# -a（指定算子）必须配合 -c（指定代际）使用；-q 与 -a 同样依赖 -c
if [ -n "$OP_SELECT" ] && [ "$SOC_VERSION" = "all" ]; then
    echo "ERROR: -a requires -c (specify a SOC generation first)"
    exit 1
fi

# 透传算子选择与量化标志给 compile_ascend_proj.sh
export CAM_OP_SELECT="$OP_SELECT"
export CAM_USE_W4A8="$USE_W4A8"

# 目前whl包和UT的编译暂时需要先将CAM算子包并安装到环境
# 在编译whl包和UT时屏蔽算子包编译，加快编译速度
if [ $ENABLE_SRC_BUILD -eq 1 ]; then
    if [ $ENABLE_CAM_COMM_BUILD -eq 1 ]; then
        build_cam_comm
    fi
    if [ ! -d "./build_out/comm_operator/run/" ]; then
        mkdir -p ${MODULE_BUILD_OUT_PATH}/run
    fi
    # SOC_VERSION=all 时遍历注册表所有代际；否则编译指定代际。
    # 算子选择/SHMEM/家族互斥由 compile_ascend_proj.sh + select_ops.py 处理。
    bash $MODULE_SCRIPTS_PATH/compile_ascend_proj.sh $MODULE_SRC_PATH $SOC_VERSION $IS_EXTRACT $BUILD_TYPE
fi

if [ $ENABLE_PYBIND_BUILD -eq 1 ]; then
    bash $MODULE_SCRIPTS_PATH/build_pybind.sh
fi

if [ $ENABLE_UT_BUILD -eq 1 ]; then
    BuildTest
fi
