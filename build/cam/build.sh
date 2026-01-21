#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script

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
export BUILD_PATH="${ROOT_PATH}/build/cam"
export CAM_THIRD_PARTY_PATH="${ROOT_PATH}/src/cam/third_party"

export CPATH=${CAM_THIRD_PARTY_PATH}:${CAM_THIRD_PARTY_PATH}/catlass/include:${CPATH}

export BUILD_TYPE="Release"
MODULE_NAME="all"
MODULE_BUILD_ARG=""
IS_MODULE_EXIST=0

function PrintHelp() {
    echo "
    ./build.sh [module name] <opt>...
    If there are no parameters, all modules are compiled in default mode
    module list: [comm_operator]

    opt:
    -d: Enable debug
    "
}

function ProcessArg() {
    while getopts "dh" opt; do
        case $opt in
        d)
            export BUILD_TYPE="Debug"
            ;;
        h)
            PrintHelp
            exit 0
            ;;
        esac
    done
    shift $(($OPTIND-1))
}

function IsModuleName() {
    if [ -z "$1" ]; then
        return 1
    fi

    if [[ $1 == -* ]]; then
        return 1
    else
        return 0
    fi
}

function PrepareCamThirdParty() {
    local third_party="$1"
    local catlass_dir="${third_party}/catlass"

    if [[ ! -d "${third_party}" ]]; then
        mkdir -p "${third_party}"
    fi

    if [[ -d "${catlass_dir}" ]]; then
        echo "catlass has existed: ${catlass_dir}"
        return 0
    fi

    branch="catlass-v1-stable"
    echo "Clone catlass branch ${branch}..."
    if git clone --branch ${branch} --depth 1 https://gitcode.com/cann/catlass.git ${catlass_dir}; then
        return 0
    else
        echo "Clone catlass failed! You can manually download it and place it in ${third_party}"
        return 1
    fi
}

if IsModuleName $@; then
    MODULE_NAME=$1
    shift
else
    ProcessArg $@
fi

if [[ "$MODULE_NAME" == "all" || "$MODULE_NAME" == "comm_operator" ]]; then
    IS_MODULE_EXIST=1
    if ! PrepareCamThirdParty "${CAM_THIRD_PARTY_PATH}"; then
        exit 1
    fi
    echo "${SCRIPTS_PATH}/comm_operator/build.sh $@"
    ${SCRIPTS_PATH}/comm_operator/build.sh $@
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

if [ $IS_MODULE_EXIST -eq 0 ]; then
    echo "module not exist"
fi
