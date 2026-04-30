#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script

set -e

SCRIPT_PATH=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
export ROOT_PATH=$(cd "$(dirname "$0")/../../" && pwd)
echo ROOT_PATH: $ROOT_PATH
if [ ! -d "$ROOT_PATH/output/cam" ]; then
    mkdir -p $ROOT_PATH/output/cam
fi
export SRC_PATH="${ROOT_PATH}/src/cam"
export BUILD_OUT_PATH="${ROOT_PATH}/output/cam"
export SCRIPTS_PATH="${ROOT_PATH}/build/cam"
export TEST_PATH="${ROOT_PATH}/test/cam"
export BUILD_PATH="${ROOT_PATH}/build/cam/build_tmp"
export CAM_THIRD_PARTY_PATH="${ROOT_PATH}/src/cam/third_party"

export CPATH=${CAM_THIRD_PARTY_PATH}/catlass/include:${CPATH}

export BUILD_TYPE="Release"
MODULE_NAME="all"
MODULE_BUILD_ARG=""
IS_MODULE_EXIST=0

function print_help() {
    echo "
    ./build.sh [module name] <opt>...
    If there are no parameters, all modules are compiled in default mode
    module list: [comm_operator]

    opt:
    -d: Enable debug
    "
}

function process_arg() {
    while getopts "dh" opt; do
        case $opt in
        d)
            export BUILD_TYPE="Debug"
            ;;
        h)
            print_help
            exit 0
            ;;
        esac
    done
    shift $(($OPTIND-1))
}

function is_module_name() {
    if [ -z "$1" ]; then
        return 1
    fi

    if [[ $1 == -* ]]; then
        return 1
    else
        return 0
    fi
}

function prepare_cam_third_party() {
    local third_party="$1"
    local catlass_dir="${third_party}/catlass"

    if [[ -d "${catlass_dir}" && -d "${catlass_dir}/include" ]]; then
        echo "catlass submodule has existed: ${catlass_dir}"
        return 0
    fi

    echo "Initializing catlass submodule..."
    if git submodule update --init --recursive src/cam/third_party/catlass; then
        return 0
    else
        echo "Failed to initialize catlass submodule! You can manually run: git submodule update --init --recursive"
        return 1
    fi
}

if is_module_name $@; then
    MODULE_NAME=$1
    shift
else
    process_arg $@
fi

if [[ "$MODULE_NAME" == "all" || "$MODULE_NAME" == "comm_operator" ]]; then
    IS_MODULE_EXIST=1
    if ! prepare_cam_third_party "${CAM_THIRD_PARTY_PATH}"; then
        exit 1
    fi
    echo "${SCRIPTS_PATH}/comm_operator/build.sh $@"
    ${SCRIPTS_PATH}/comm_operator/build.sh $@
fi

if [ $IS_MODULE_EXIST -eq 0 ]; then
    echo "module not exist"
fi
