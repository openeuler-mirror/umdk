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
export BUILD_PATH="${ROOT_PATH}/build/cam/build_feature"
export CAM_THIRD_PARTY_PATH="${ROOT_PATH}/src/cam/third_party"

# Do not pin a single catlass include here; compile_ascend_proj.sh selects
# catlass (910_93) vs catlass_v1.6.0 (ascend950) per SOC and prepends CPATH.
export CPATH=${CAM_THIRD_PARTY_PATH}:${CPATH}

export BUILD_TYPE="Release"
MODULE_NAME="all"
MODULE_BUILD_ARG=""
IS_MODULE_EXIST=0

function print_help() {
    echo "
    ./build.sh [module name] <opt>...
    If there are no parameters, all modules are compiled in default mode
    module list: [comm_operator]

    opt (forwarded to the module build script):
    -d: Enable debug
    -c <soc>: Target SOC generation (e.g. ascend910_93 / ascend950). Omit to
        build all registered generations. Supported: [ascend910_93, ascend950]
    -a <ops>: Semicolon-separated operator list (requires -c)
    -q: Select the fused_deep_moe_w4a8 quantization variant
    -p: Build only the pybind (whl) package; skip the run package
    -r: Build only the run package; skip the whl package (mutually exclusive with -p)
    -m: Build only the cam_comm library (framework/communicator); skip operator/run/whl
        (mutually exclusive with -p/-r; cam_feature only)
    -h: Show this help
    "
}

# 顶层只消费 -d / -h；其余选项（含 -c/-a/-q/-p/-r 及其参数）原样透传给子模块脚本。
# 函数内 shift 不影响调用者位置参数，故调用者 $@ 保持完整，由下方统一调用子脚本。
# 前导 ':' 静默 getopts 对未知选项（-c/-a/-q/-p/-r/-m）的默认错误输出。
function process_arg() {
    while getopts ":dh" opt; do
        case $opt in
        d)
            export BUILD_TYPE="Debug"
            ;;
        h)
            print_help
            exit 0
            ;;
        \?)
            # 未知选项静默跳过，交由子脚本处理
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
    # soc: ascend910_93 | ascend950 | empty(=all). Only 950 needs catlass_v1.6.0.
    local soc="${2:-}"
    # Two catlass trees:
    #   catlass         -> submodule, used by ascend910_93 (also 950 fallback)
    #   catlass_v1.6.0  -> Ascend950 preferred tree (cloned on demand; not in git)
    local catlass_dir="${third_party}/catlass"
    if [[ -d "${catlass_dir}/include" ]]; then
        echo "catlass tree catlass has existed: ${catlass_dir}"
    else
        echo "Initializing catlass tree catlass..."
        if ! git submodule update --init --recursive "src/cam/third_party/catlass"; then
            echo "Failed to initialize catlass! You can manually run: git submodule update --init --recursive src/cam/third_party/catlass"
            return 1
        fi
    fi

    if [[ -z "${soc}" || "${soc}" == "ascend950" ]]; then
        local v16_dir="${third_party}/catlass_v1.6.0"
        if [[ -d "${v16_dir}/include" ]]; then
            echo "catlass tree catlass_v1.6.0 has existed: ${v16_dir}"
        else
            # Not vendored in git (third_party is ignored). Try to fetch tag v1.6.0.
            # If clone fails, compile_ascend_proj.sh falls back to catlass for 950.
            echo "Fetching catlass_v1.6.0 (tag v1.6.0) into ${v16_dir}..."
            if git clone --depth 1 -b v1.6.0 https://gitcode.com/cann/catlass.git "${v16_dir}"; then
                echo "catlass_v1.6.0 ready: ${v16_dir}"
            else
                echo "WARN: failed to clone catlass_v1.6.0; ascend950 will fall back to src/cam/third_party/catlass"
                rm -rf "${v16_dir}" 2>/dev/null || true
            fi
        fi
    fi
    return 0
}

if is_module_name $@; then
    MODULE_NAME=$1
    shift
else
    process_arg $@
fi

# Restrict modules when -c is set (parsed loosely from remaining args).
SOC_TYPE=""
prev=""
for arg in "$@"; do
    if [[ "${prev}" == "-c" ]]; then
        SOC_TYPE="${arg}"
        break
    fi
    prev="${arg}"
done

if [[ -n "${SOC_TYPE}" ]]; then
    if [[ "${SOC_TYPE}" == "ascend950" ]]; then
        if [[ "${MODULE_NAME}" != "nda" && "${MODULE_NAME}" != "all" && "${MODULE_NAME}" != "comm_operator" ]]; then
            echo "Error: -c ascend950 supports modules 'nda'/'comm_operator' (or 'all'=both), but got '${MODULE_NAME}'"
            exit 1
        fi
    elif [[ "${SOC_TYPE}" == "ascend910_93" ]]; then
        :
    fi
fi

# Build comm_operator for 910_93 (default) and for 950 when selected.
if [[ "$MODULE_NAME" == "all" || "$MODULE_NAME" == "comm_operator" ]]; then
    if [[ -z "${SOC_TYPE}" || "${SOC_TYPE}" == "ascend910_93" || "${SOC_TYPE}" == "ascend950" ]]; then
        IS_MODULE_EXIST=1
        if ! prepare_cam_third_party "${CAM_THIRD_PARTY_PATH}" "${SOC_TYPE}"; then
            exit 1
        fi
        echo "${SCRIPTS_PATH}/comm_operator/build.sh $@"
        ${SCRIPTS_PATH}/comm_operator/build.sh $@
    fi
fi

if [ $IS_MODULE_EXIST -eq 0 ]; then
    echo "module not exist"
fi
