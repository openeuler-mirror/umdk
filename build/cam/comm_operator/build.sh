#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script

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
ENABLE_PYBIND_BUILD=0
ENABLE_SRC_BUILD=0

print_help() {
    echo "
    ./build.sh comm_operator <opt>...
    -x Extract the run package
    -c Target SOC VERSION
    Support Soc: [ascend910_93, ascend910b4]
    -d Enable debug
    -t Enable UT build
    -p Enable pybind build
    -r Enable code coverage
    "
}

while getopts "c:xdtprh" opt; do
    case $opt in
    c)
        SOC_VERSION=$OPTARG
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
    p)
        ENABLE_PYBIND_BUILD=1
        ENABLE_SRC_BUILD=0
        ;;
    r)
        export BUILD_TYPE="Debug"
        export ENABLE_COV=1
        ;;
    h)
        print_help
        exit 0
        ;;
    esac
done

if [ ! -d "$BUILD_OUT_PATH/${MODULE_NAME}" ]; then
    mkdir $BUILD_OUT_PATH/${MODULE_NAME}
fi

# 目前whl包和UT的编译暂时需要先将CAM算子包并安装到环境
# 在编译whl包和UT时屏蔽算子包编译，加快编译速度
if [ $ENABLE_SRC_BUILD -eq 1 ]; then
    if [ ! -d "./build_out/comm_operator/run/" ]; then
        mkdir -p ${MODULE_BUILD_OUT_PATH}/run
    fi
    if [[ "$SOC_VERSION" == "all" ]]; then
        bash $MODULE_SCRIPTS_PATH/compile_ascend_proj.sh $MODULE_SRC_PATH ascend910_93 $IS_EXTRACT $BUILD_TYPE
    else
        bash $MODULE_SCRIPTS_PATH/compile_ascend_proj.sh $MODULE_SRC_PATH $SOC_VERSION $IS_EXTRACT $BUILD_TYPE
    fi
fi

if [ $ENABLE_PYBIND_BUILD -eq 1 ]; then
    bash $MODULE_SCRIPTS_PATH/build_pybind.sh
fi

if [ $ENABLE_UT_BUILD -eq 1 ]; then
    BuildTest
fi
