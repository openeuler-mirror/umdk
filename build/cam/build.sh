#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script (top-level entry, forwards options to the module script)
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script
#          2026-06-26 forward -c/-a/-q to comm_operator build, update help
#          2026-07-07 note -r (run package only) forwarding to comm_operator build

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
export BUILD_PATH="${ROOT_PATH}/build/cam/build_master"
export CAM_THIRD_PARTY_PATH="${ROOT_PATH}/src/cam/third_party"

export CPATH=${CAM_THIRD_PARTY_PATH}:${CAM_THIRD_PARTY_PATH}/catlass/include:${CPATH}

export BUILD_TYPE="Release"
MODULE_NAME="all"
MODULE_BUILD_ARG=""
IS_MODULE_EXIST=0

function print_help() {
    echo "
    ./build.sh [module name] <opt>...
    If there are no parameters, all modules are compiled in default mode
    module list: [comm_operator, nda]

    opt (forwarded to the module build script):
    -d: Enable debug
    -c <soc>: Target SOC generation (e.g. ascend910_93). Omit to build all
        registered generations. Supported: [ascend910_93, ascend950]
        - ascend950: only supports module 'nda'
        - ascend910_93: only supports module 'comm_operator'
    -a <ops>: Semicolon-separated operator list (requires -c)
    -q: Select the fused_deep_moe_w4a8 quantization variant
    -p: Build only the pybind (whl) package; skip the run package
    -r: Build only the run package; skip the whl package (mutually exclusive with -p)
    -h: Show this help
    "
}

# The top level consumes -d / -h / -c, but ALL options (including -c/-a/-q/-p/-r)
# are forwarded as-is to the submodule script. Since getopts only updates OPTIND without modifying $@,
# the caller's positional parameters stay intact and are passed to the submodule below.
# The leading ':' silences getopts' default error output for unknown options (-a/-q/-p/-r).
function process_arg() {
    while getopts ":dhc:" opt; do
        case $opt in
        d)
            export BUILD_TYPE="Debug"
            ;;
        c)
            export SOC_TYPE="$OPTARG"
            ;;
        h)
            print_help
            exit 0
            ;;
        \?)
            # Silently skip unknown options; let the submodule handle them
            ;;
        esac
    done
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
fi

process_arg $@

# Validate -c / MODULE_NAME combination.
# When -c is specified, 'all' is resolved to the single module allowed by that soc_type:
#   ascend950     -> all means nda only
#   ascend910_93  -> all means comm_operator only
if [[ -n "${SOC_TYPE}" ]]; then
    if [[ "${SOC_TYPE}" == "ascend950" ]]; then
        if [[ "${MODULE_NAME}" != "nda" && "${MODULE_NAME}" != "all" ]]; then
            echo "Error: -c ascend950 only supports module 'nda' (or 'all'), but got '${MODULE_NAME}'"
            exit 1
        fi
    elif [[ "${SOC_TYPE}" == "ascend910_93" ]]; then
        if [[ "${MODULE_NAME}" != "comm_operator" && "${MODULE_NAME}" != "all" ]]; then
            echo "Error: -c ascend910_93 only supports module 'comm_operator' (or 'all'), but got '${MODULE_NAME}'"
            exit 1
        fi
    else
        echo "Error: unsupported soc_type '${SOC_TYPE}', supported: [ascend910_93, ascend950]"
        exit 1
    fi
fi

# Build comm_operator unless -c restricts to nda (ascend950).
# With -c ascend910_93 or no -c, 'all'/'comm_operator' builds comm_operator.
if [[ "$MODULE_NAME" == "all" || "$MODULE_NAME" == "comm_operator" ]]; then
    if [[ -z "${SOC_TYPE}" || "${SOC_TYPE}" == "ascend910_93" ]]; then
        IS_MODULE_EXIST=1
        if ! prepare_cam_third_party "${CAM_THIRD_PARTY_PATH}"; then
            exit 1
        fi
        echo "${SCRIPTS_PATH}/comm_operator/build.sh $@"
        ${SCRIPTS_PATH}/comm_operator/build.sh $@
    fi
fi

# Build nda unless -c restricts to comm_operator (ascend910_93).
# With -c ascend950 or no -c, 'all'/'nda' builds nda.
if [[ "$MODULE_NAME" == "all" || "$MODULE_NAME" == "nda" ]]; then
    if [[ -z "${SOC_TYPE}" || "${SOC_TYPE}" == "ascend950" ]]; then
        IS_MODULE_EXIST=1
        echo "${SCRIPTS_PATH}/framework/nda/build.sh $@"
        ${SCRIPTS_PATH}/framework/nda/build.sh $@
    fi
fi

if [ $IS_MODULE_EXIST -eq 0 ]; then
    echo "module not exist"
fi
