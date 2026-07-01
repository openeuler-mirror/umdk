#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script - migrated to npu_op_* build system
# Create: 2025-07-20
# History: 2025-07-20 create cam building script
#          2026-06-08 migrate from legacy opbuild/msopgen to npu_op_* build system
#          2026-06-26 switch from exclude-list copy to include-list build with
#                     operator_registry.json + select_ops.py selection

set -e

# Operator registry path (operator identity = directory name under ascend_kernels/)
REGISTRY_PATH="${MODULE_SRC_PATH}/ascend_kernels/operator_registry.json"
# select_ops.py path
SELECT_OPS_SCRIPT="${SCRIPTS_PATH}/comm_operator/select_ops.py"

# Whether SHMEM is installed (determined by the SHMEM_HOME_PATH env variable)
shmem_installed=1
if [ -z "${SHMEM_HOME_PATH}" ]; then
    shmem_installed=0
fi

# -q (quantization) flag is forwarded by build.sh via CAM_USE_W4A8=1
use_w4a8=0
if [ "${CAM_USE_W4A8}" = "1" ]; then
    use_w4a8=1
fi

# -a operator list is forwarded by build.sh via CAM_OP_SELECT (semicolon-separated; empty = full set)
user_ops="${CAM_OP_SELECT:-}"

# Copy the op_host/op_kernel/op_api of the selected operator directories into the target project.
# utils is a shared header directory and is always copied; the rest are copied per the ops array
# (operator directory names). Unlike the old full-copy + exclude_list approach, only the operators
# resolved by select_ops.py are copied here, which fundamentally avoids same-name operators
# (the fused_deep_moe family) overwriting each other's files.
copy_ops_include() {
    local src_dir="$1" # source directory (ascend_kernels)
    local dst_dir="$2" # target directory (project root)
    local ops=($3)     # space-separated list of operator directory names

    # Ensure the target op_host, op_kernel and pregen autogen directories exist
    mkdir -p "$dst_dir/op_host" "$dst_dir/op_kernel" "$dst_dir/pregen/build_out/autogen"

    # Always copy the shared header directory utils (.h under op_host/op_kernel)
    if [ -d "$src_dir/utils/op_host" ]; then
        cp -rf "$src_dir/utils/op_host/"* "$dst_dir/op_host/" 2>/dev/null || true
    fi
    if [ -d "$src_dir/utils/op_kernel" ]; then
        cp -rf "$src_dir/utils/op_kernel/"* "$dst_dir/op_kernel/" 2>/dev/null || true
    fi

    # Copy op_host/op_kernel/op_api of each selected operator
    for name in "${ops[@]}"; do
        local subdir="$src_dir/$name"
        if [ ! -d "$subdir" ]; then
            echo "Warning: operator dir not found, skipping: $name"
            continue
        fi
        if [ -d "$subdir/op_host" ]; then
            cp -rf "$subdir/op_host/"* "$dst_dir/op_host/"
        fi
        if [ -d "$subdir/op_kernel" ]; then
            cp -rf "$subdir/op_kernel/"* "$dst_dir/op_kernel/"
        fi
        # op_api interface files are copied to pregen/build_out/autogen
        if [ -d "$subdir/op_api" ]; then
            cp -rf "$subdir/op_api/"* "$dst_dir/pregen/build_out/autogen/"
        fi
    done
}

# Call select_ops.py to resolve the final operator list, returned as space-separated directory names.
# On failure (registry/validation errors) select_ops.py prints the error and exits non-zero; set -e aborts.
resolve_ops() {
    local soc=$1
    local quant_arg=""
    local ops_arg=""
    if [ "$use_w4a8" = "1" ]; then
        quant_arg="--quant"
    fi
    if [ -n "$user_ops" ]; then
        ops_arg="--ops $user_ops"
    fi
    python3 "$SELECT_OPS_SCRIPT" \
        --registry "$REGISTRY_PATH" \
        --soc "$soc" \
        --shmem "$shmem_installed" \
        $quant_arg $ops_arg | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//'
}

# Read all registered SOC generations from the registry (space-separated)
list_soc_versions() {
    python3 -c "
import json
d = json.load(open('$REGISTRY_PATH'))
print(' '.join(d.get('soc_versions', {}).keys()))
"
}

# Build the operator project and deliver its artifacts to the specified location
build_ascend_proj() {
    local src_path=$1
    local soc_version=$2
    local is_extract=$3
    local build_type=$4
    local os_id=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
    local arch=$(uname -m)
    local proj_name="ascend_kernels_${soc_version}_proj"

    cd "$src_path"

    # Ensure the MODULE_BUILD_PATH directory exists
    if [ ! -d "${MODULE_BUILD_PATH}" ]; then
        mkdir -p ${MODULE_BUILD_PATH}
    fi

    if [ -d "${MODULE_BUILD_PATH}/${proj_name}" ]; then
        rm -rf ${MODULE_BUILD_PATH}/${proj_name}
    fi

    # Resolve the operator list to compile this run (include mode, validated+filtered by select_ops.py)
    # select_ops.py errors out on unregistered SOC / invalid operator name / -q conflicts.
    local selected_ops
    selected_ops=$(resolve_ops "$soc_version")
    if [ -z "$selected_ops" ]; then
        echo "ERROR: no operators resolved for SOC ${soc_version}"
        return 1
    fi
    echo "Selected operators for ${soc_version}: ${selected_ops}"

    # Use msopgen to generate the SOC-specific operator project and CMakePresets.json
    export OPS_PROJECT_NAME=aclnnInner

    echo "msopgen gen -i ./ascend_kernels/AddCustom.json -c ai_core-${soc_version} -f pytorch -lan cpp -out ${MODULE_BUILD_PATH}/${proj_name}"
    msopgen gen -i ./ascend_kernels/AddCustom.json -c ai_core-${soc_version} -f pytorch -lan cpp -out ${MODULE_BUILD_PATH}/${proj_name}
    rm -rf ${MODULE_BUILD_PATH}/${proj_name}/op_host/add_custom*
    rm -rf ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/add_custom*

    # Copy the top-level CMakeLists.txt (CMakePresets.json is generated by msopgen)
    cp ./ascend_kernels/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/

    # Copy the op_host and op_kernel CMakeLists.txt (new npu_op_* version)
    cp ./ascend_kernels/cmake_files/op_host/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/op_host/
    cp ./ascend_kernels/cmake_files/op_kernel/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/

    # Copy the op_host/op_kernel sources and op_api interface files of the selected operators (include mode)
    copy_ops_include "./ascend_kernels" "${MODULE_BUILD_PATH}/${proj_name}" "$selected_ops"

    # Copy the cmake_files/cmake directory (custom cmake functions, replaces the msopgen default cmake)
    cp -rf ./ascend_kernels/cmake_files/cmake ${MODULE_BUILD_PATH}/${proj_name}/

    # Set build_type into CMakePresets.json (called after msopgen generates it)
    python3 $SCRIPTS_PATH/comm_operator/set_conf.py ${MODULE_BUILD_PATH}/${proj_name}/CMakePresets.json $build_type True CAM

    # CANN package path: try setenv first, then derive from ASCEND_TOOLKIT_HOME
    if [ -z "${ASCEND_CANN_PACKAGE_PATH}" ]; then
        if [ -n "${ASCEND_TOOLKIT_HOME}" ]; then
            export ASCEND_CANN_PACKAGE_PATH="${ASCEND_TOOLKIT_HOME}"
        else
            export ASCEND_CANN_PACKAGE_PATH="/usr/local/Ascend/ascend-toolkit/latest"
        fi
    fi

    # Export CATLASS_HOME_PATH for kernel compilation if CPATH contains catlass
    if [ -z "${CATLASS_HOME_PATH}" ] && echo "${CPATH}" | grep -q "catlass"; then
        export CATLASS_HOME_PATH=$(echo "${CPATH}" | tr ':' '\n' | grep "catlass" | sed 's|/include||')
    fi

    cd ${MODULE_BUILD_PATH}/${proj_name}

    # Configure cmake
    cmake -S . -B build_out --preset=default -DCMAKE_BUILD_TYPE=$build_type

    # Patch kernel compile .make files to pass custom include paths to OPC tool.
    # The npu_op_* build system's simple_kernel_compile doesn't read custom_compile_options.ini,
    # so --compile-options="" is empty. We patch it here to include shmem/catlass paths.
    KERNEL_COMPILE_OPTS=""
    if [ -n "${SHMEM_HOME_PATH}" ]; then
        KERNEL_COMPILE_OPTS="-I${SHMEM_HOME_PATH}/shmem/include -I${SHMEM_HOME_PATH}/shmem/src/device"
    fi
    if [ -n "${CATLASS_HOME_PATH}" ]; then
        if [ -n "${KERNEL_COMPILE_OPTS}" ]; then
            KERNEL_COMPILE_OPTS="${KERNEL_COMPILE_OPTS} "
        fi
        KERNEL_COMPILE_OPTS="${KERNEL_COMPILE_OPTS}-I${CATLASS_HOME_PATH}/include"
    fi
    if [ -n "${KERNEL_COMPILE_OPTS}" ]; then
        echo "Patching kernel compile options: ${KERNEL_COMPILE_OPTS}"
        find build_out/op_kernel/CMakeFiles -name "build.make" -exec sed -i "s|--compile-options=\"\"|--compile-options=\\\"${KERNEL_COMPILE_OPTS}\\\"|g" {} +
    fi

    # Build parallelism: configurable via the CAM_BUILD_JOBS env variable, default 8
    # For memory-constrained environments such as Jenkins ECS, 2~4 is recommended
    BUILD_JOBS=${CAM_BUILD_JOBS:-8}
    cmake --build build_out --target binary -j${BUILD_JOBS}
    cmake --build build_out --target package -j${BUILD_JOBS}

    # Extract the run package based on is_extract
    if [ $is_extract -eq 1 ]; then
        if [ ! -d "$BUILD_OUT_PATH/comm_operator/extract" ]; then
            mkdir -p "$BUILD_OUT_PATH/comm_operator/extract"
        fi
        mkdir -p ${BUILD_OUT_PATH}/comm_operator/extract/${soc_version}
        build_out/*.run --extract=${BUILD_OUT_PATH}/comm_operator/extract/${soc_version}
    else
        cp build_out/*.run ${BUILD_OUT_PATH}/comm_operator/run/CAM_${soc_version}_${os_id}_${arch}.run
    fi
}

# ---- Entry point ----
# Usage: compile_ascend_proj.sh <src_path> <soc_version|all> <is_extract> <build_type>
src_path=$1
soc_arg=$2
is_extract=${3:-0}
build_type=${4:-Release}

if [ -z "$src_path" ] || [ -z "$soc_arg" ]; then
    echo "Usage: $0 <src_path> <soc_version|all> <is_extract> <build_type>"
    exit 1
fi

# Build output run directory
if [ ! -d "$BUILD_OUT_PATH/comm_operator/run" ]; then
    mkdir -p "$BUILD_OUT_PATH/comm_operator/run"
fi

if [ "$soc_arg" = "all" ]; then
    # Default: iterate over all registered SOC generations, compiling the full operator set for each
    # (select_ops.py drops SHMEM-requiring operators based on SHMEM availability)
    all_socs=$(list_soc_versions)
    if [ -z "$all_socs" ]; then
        echo "ERROR: no SOC versions registered in ${REGISTRY_PATH}"
        exit 1
    fi
    # -a selection is incompatible with the default all build: all mode iterates the full set per SOC
    # and does not accept a single-operator selection
    if [ -n "$user_ops" ]; then
        echo "ERROR: -a requires a specific -c SOC; cannot use -a with default (all) build"
        exit 1
    fi
    for soc in $all_socs; do
        echo "======== Building SOC: ${soc} ========"
        build_ascend_proj "$src_path" "$soc" "$is_extract" "$build_type"
    done
else
    build_ascend_proj "$src_path" "$soc_arg" "$is_extract" "$build_type"
fi
