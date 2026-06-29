#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script - migrated to npu_op_* build system
# Create: 2025-07-20
# History: 2025-07-20 create cam building script
#          2026-05-30 migrate from legacy opbuild/add_kernels_compile to npu_op_* build system
#          2026-06-27 migrate pregen autogen to per-operator op_api directories

set -e

# Define global exclusion list
exclude_list=()

copy_ops() {
    local src_dir="$1" # Source directory
    local dst_dir="$2" # Destination directory

    # Ensure op_host, op_kernel and pregen autogen exist in destination directory
    mkdir -p "$dst_dir/op_host" "$dst_dir/op_kernel" "$dst_dir/pregen/build_out/autogen"

    # Iterate over all direct subdirectories under source directory (including directories with spaces)
    find "$src_dir" -mindepth 1 -maxdepth 1 -type d -print0 | while IFS= read -r -d '' subdir; do
        # Verify subdirectory exists (double check)
        subdir_name=$(basename "$subdir")

        if [ -d "$subdir" ]; then
            # Check if current subdirectory is in the exclusion list
            skip=false
            for excluded_dir in "${exclude_list[@]}"; do
                if [ "$subdir_name" = "$excluded_dir" ]; then
                    skip=true
                    break
                fi
            done

            # Skip processing if in exclusion list
            if [ "$skip" = true ]; then
                continue
            fi

            # Process op_host directory
            if [ -d "$subdir/op_host" ]; then
                cp -rf "$subdir/op_host/"* "$dst_dir/op_host/"
            fi

            # Process op_kernel directory
            if [ -d "$subdir/op_kernel" ]; then
                cp -rf "$subdir/op_kernel/"* "$dst_dir/op_kernel/"
            fi

            # Process op_api directory (copy aclnn interface files to pregen/build_out/autogen)
            if [ -d "$subdir/op_api" ]; then
                cp -rf "$subdir/op_api/"* "$dst_dir/pregen/build_out/autogen/"
            fi
        fi
    done
}

# Build operator project and deliver artifacts to specified location
build_ascend_proj() {
    local src_path=$1
    local soc_version=$2
    local is_extract=$3
    local build_type=$4
    local os_id=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
    local arch=$(uname -m)
    local proj_name="ascend_kernels_${soc_version}_proj"

    # SOC version gate: 910b4 (a2) operators have been removed from master,
    # only ascend910_93 is supported now. Reject anything else early.
    if [[ "$soc_version" != "ascend910_93" ]]; then
        echo "ERROR: unsupported SOC version '$soc_version'. Only 'ascend910_93' is supported on this branch." >&2
        echo "       (ascend910b4 a2 operators have been removed; rebuild on a branch that carries them if needed.)" >&2
        exit 1
    fi

    cd "$src_path"

    # Ensure MODULE_BUILD_PATH directory exists
    if [ ! -d "${MODULE_BUILD_PATH}" ]; then
        mkdir -p ${MODULE_BUILD_PATH}
    fi

    if [ -d "${MODULE_BUILD_PATH}/${proj_name}" ]; then
        rm -rf ${MODULE_BUILD_PATH}/${proj_name}
    fi

    # Create project directory for new npu_op_* build system
    export OPS_PROJECT_NAME=aclnnInner

    echo "msopgen gen -i ./ascend_kernels/AddCustom.json" \
        " -c ai_core-${soc_version} -f pytorch -lan cpp" \
        " -out ${MODULE_BUILD_PATH}/${proj_name}"
    msopgen gen -i ./ascend_kernels/AddCustom.json \
        -c ai_core-${soc_version} -f pytorch -lan cpp \
        -out ${MODULE_BUILD_PATH}/${proj_name}
    rm -rf ${MODULE_BUILD_PATH}/${proj_name}/op_host/add_custom*
    rm  -rf ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/add_custom*

    # Copy top-level CMakeLists.txt
    cp ./ascend_kernels/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/

    # Copy op_host and op_kernel CMakeLists.txt (new npu_op_* version)
    cp ./ascend_kernels/cmake_files/op_host/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/op_host/
    cp ./ascend_kernels/cmake_files/op_kernel/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/

    # Only ascend910_93 is supported (see SOC gate above). All remaining operators
    # (fused_deep_moe, moe_dispatch_normal, moe_combine_normal, notify_dispatch,
    # dispatch_layout) are 910_93 compatible, so no exclusion is needed.
    echo "SOC ascend910_93: compiling all operators"

    # Copy op_host/op_kernel source files and op_api interface files for all operators
    copy_ops "./ascend_kernels" "${MODULE_BUILD_PATH}/${proj_name}"
    # Set build_type in CMakePresets.json
    python3 $SCRIPTS_PATH/comm_operator/set_conf.py \
        ${MODULE_BUILD_PATH}/${proj_name}/CMakePresets.json $build_type True CAM

    # Copy cmake_files/cmake directory (custom cmake functions, replaces msopgen default cmake)
    cp -rf ./ascend_kernels/cmake_files/cmake ${MODULE_BUILD_PATH}/${proj_name}/

    # copy_ops runs in a find|while subshell where exclude_list may not fully take effect,
    # so remove autogen files of excluded operators here as a supplement
    for excluded_dir in "${exclude_list[@]}"; do
        rm -f ${MODULE_BUILD_PATH}/${proj_name}/pregen/build_out/autogen/aclnn_${excluded_dir}.*
    done

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

    # Patch generated kernel compile .make files to pass custom include paths to OPC tool.
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
        find build_out/op_kernel/CMakeFiles -name "build.make" \
            -exec sed -i "s|--compile-options=\"\"|--compile-options=\\\"${KERNEL_COMPILE_OPTS}\\\"|g" {} +
    fi

    # Build parallelism: configurable via CAM_BUILD_JOBS env variable, default 8
    # Recommend 2~4 for memory-constrained environments such as Jenkins ECS
    BUILD_JOBS=${CAM_BUILD_JOBS:-8}
    cmake --build build_out --target binary -j${BUILD_JOBS}
    cmake --build build_out --target package -j${BUILD_JOBS}

    # Decide whether to extract the run package based on is_extract
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

build_ascend_proj $1 $2 $3 $4
