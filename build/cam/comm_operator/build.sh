#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam comm_operator build script (include-list build with operator selection)
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script
#          2026-06-26 add -c/-a/-q operator selection via operator_registry.json +
#                     select_ops.py; drop coverage (-r) support
#          2026-07-07 repurpose -r as "run package only" (skip whl) for
#                     incremental Jenkins builds; mutually exclusive with -p

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
ENABLE_RUN_ONLY=0    # -r flag: 1 = build only the run package, skip the whl
OP_SELECT=""        # -a operator list (semicolon-separated); empty = full set
USE_W4A8=0          # -q flag: 1 = compile the fused_deep_moe_w4a8 quantization variant

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
       Note: master has no w4a8 variant yet; -q takes effect once it is added.
    -d Enable debug
    -t Enable UT build
    -p Build only the pybind (whl) package; skip the run package build
    -r Build only the run package; skip the whl package build.
       Mutually exclusive with -p.
    "
}

while getopts "c:a:xdtqprh" opt; do
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
    r)
        ENABLE_RUN_ONLY=1
        ;;
    h)
        print_help
        exit 0
        ;;
    esac
done

# -r (run only) and -p (pybind only) are mutually exclusive: -p requests only
# the whl while -r requests skipping the whl, which is contradictory.
if [ "$ENABLE_RUN_ONLY" -eq 1 ] && [ "$ENABLE_PYBIND_BUILD" -eq 1 ] && [ "$ENABLE_SRC_BUILD" -eq 0 ]; then
    echo "ERROR: -r (run only) and -p (pybind only) are mutually exclusive"
    exit 1
fi
if [ "$ENABLE_RUN_ONLY" -eq 1 ]; then
    ENABLE_PYBIND_BUILD=0
fi

if [ ! -d "$BUILD_OUT_PATH/${MODULE_NAME}" ]; then
    mkdir $BUILD_OUT_PATH/${MODULE_NAME}
fi

# -a (operator selection) requires -c (SOC generation); -q also depends on -c
if [ -n "$OP_SELECT" ] && [ "$SOC_VERSION" = "all" ]; then
    echo "ERROR: -a requires -c (specify a SOC generation first)"
    exit 1
fi

# Forward the operator selection and quantization flag to compile_ascend_proj.sh
export CAM_OP_SELECT="$OP_SELECT"
export CAM_USE_W4A8="$USE_W4A8"

# Currently, building the whl package and UT requires the CAM operator package to be compiled and installed first
# Skip operator package compilation when building the whl package and UT to speed up compilation
if [ $ENABLE_SRC_BUILD -eq 1 ]; then
    if [ ! -d "./build_out/comm_operator/run/" ]; then
        mkdir -p ${MODULE_BUILD_OUT_PATH}/run
    fi
    # When SOC_VERSION=all, iterate over all registered SOC generations; otherwise build the specified SOC.
    # Operator selection / SHMEM / family mutex are handled by compile_ascend_proj.sh + select_ops.py.
    bash $MODULE_SCRIPTS_PATH/compile_ascend_proj.sh $MODULE_SRC_PATH $SOC_VERSION $IS_EXTRACT $BUILD_TYPE
fi

if [ $ENABLE_PYBIND_BUILD -eq 1 ]; then
    bash $MODULE_SCRIPTS_PATH/build_pybind.sh
fi

if [ $ENABLE_UT_BUILD -eq 1 ]; then
    BuildTest
fi
