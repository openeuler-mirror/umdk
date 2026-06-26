#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script - migrated to npu_op_* build system
# Create: 2025-07-20
# History: 2025-07-20 create cam building script
#          2026-06-08 migrate from legacy opbuild/msopgen to npu_op_* build system

set -e

# 定义全局屏蔽列表
exclude_list=("fused_deep_moe_w4a8")
if [ -z "${SHMEM_HOME_PATH}" ]; then
    echo "Skipping shmem (SHMEM_HOME_PATH not set)"
    exclude_list+=("fused_deep_moe")
    exclude_list+=(
        "moe_combine_lowlatency_zb"
        "moe_combine_normal_zb"
        "moe_dispatch_lowlatency_zb"
        "moe_dispatch_normal_zb"
        "moe_dispatch_layout_zb"
        "moe_notify_dispatch_zb"
    )
else
    echo "Building zero-buffer operators (SHMEM_HOME_PATH set)"
    # zb dispatch_layout shares filenames with HCCL dispatch_layout; use zb version.
    exclude_list+=("dispatch_layout")
fi

copy_ops() {
    local src_dir="$1" # 源目录
    local dst_dir="$2" # 目标目录

    # 确保目标目录的op_host、op_kernel和pregen autogen存在
    mkdir -p "$dst_dir/op_host" "$dst_dir/op_kernel" "$dst_dir/pregen/build_out/autogen"

    # 遍历源目录下所有直接子目录（包括含空格的目录）
    find "$src_dir" -mindepth 1 -maxdepth 1 -type d -print0 | while IFS= read -r -d '' subdir; do
        # 检查子目录是否存在（双重验证）
        subdir_name=$(basename "$subdir")

        if [ -d "$subdir" ]; then
            # 检查当前子目录是否在屏蔽列表中
            skip=false
            for excluded_dir in "${exclude_list[@]}"; do
                if [ "$subdir_name" = "$excluded_dir" ]; then
                    skip=true
                    break
                fi
            done

            # 如果在屏蔽列表中，则跳过处理
            if [ "$skip" = true ]; then
                continue
            fi

            # 处理op_host目录
            if [ -d "$subdir/op_host" ]; then
                cp -rf "$subdir/op_host/"* "$dst_dir/op_host/"
            fi

            # 处理op_kernel目录
            if [ -d "$subdir/op_kernel" ]; then
                cp -rf "$subdir/op_kernel/"* "$dst_dir/op_kernel/"
            fi

            # 处理op_api目录（将aclnn接口文件复制到pregen/build_out/autogen）
            if [ -d "$subdir/op_api" ]; then
                cp -rf "$subdir/op_api/"* "$dst_dir/pregen/build_out/autogen/"
            fi
        fi
    done
}

# 构建算子工程并将其产物传到指定地点
build_ascend_proj() {
    local src_path=$1
    local soc_version=$2
    local is_extract=$3
    local build_type=$4
    local os_id=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
    local arch=$(uname -m)
    local proj_name="ascend_kernels_${soc_version}_proj"

    cd "$src_path"

    # 确保 MODULE_BUILD_PATH 目录存在
    if [ ! -d "${MODULE_BUILD_PATH}" ]; then
        mkdir -p ${MODULE_BUILD_PATH}
    fi

    if [ -d "${MODULE_BUILD_PATH}/${proj_name}" ]; then
        rm -rf ${MODULE_BUILD_PATH}/${proj_name}
    fi

    # 当前分支所有算子均为 ascend910_93 版本，不支持 ascend910b4
    if [[ "$soc_version" == "ascend910b4" ]]; then
        echo "Warning: ascend910b4 SOC version is not supported on this branch."
        echo "All operators on this branch are ascend910_93 versions only."
        echo "Skipping build for ascend910b4."
        return 0
    fi

    # 使用 msopgen 生成不同代际的算子工程及 CMakePresets.json 文件
    export OPS_PROJECT_NAME=aclnnInner

    echo "msopgen gen -i ./ascend_kernels/AddCustom.json -c ai_core-${soc_version} -f pytorch -lan cpp -out ${MODULE_BUILD_PATH}/${proj_name}"
    msopgen gen -i ./ascend_kernels/AddCustom.json -c ai_core-${soc_version} -f pytorch -lan cpp -out ${MODULE_BUILD_PATH}/${proj_name}
    rm -rf ${MODULE_BUILD_PATH}/${proj_name}/op_host/add_custom*
    rm -rf ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/add_custom*

    # 复制顶层CMakeLists.txt（CMakePresets.json 由 msopgen 生成）
    cp ./ascend_kernels/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/

    # 复制op_host和op_kernel的CMakeLists.txt（新npu_op_*版本）
    cp ./ascend_kernels/cmake_files/op_host/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/op_host/
    cp ./ascend_kernels/cmake_files/op_kernel/CMakeLists.txt ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/

    # 复制所有算子的op_host/op_kernel源文件和op_api接口文件
    copy_ops "./ascend_kernels" "${MODULE_BUILD_PATH}/${proj_name}"

    # 复制cmake_files/cmake目录（包含自定义编译函数，替换msopgen默认cmake）
    cp -rf ./ascend_kernels/cmake_files/cmake ${MODULE_BUILD_PATH}/${proj_name}/

    # copy_ops中的exclude_list在find|while子shell中可能不完全生效，
    # 因此在此处补充移除屏蔽列表中对应算子的autogen文件
    for excluded_dir in "${exclude_list[@]}"; do
        rm -f ${MODULE_BUILD_PATH}/${proj_name}/pregen/build_out/autogen/aclnn_${excluded_dir}.*
    done

    # 如果不需要编译shmem/fused_deep_moe/zero_buffer算子，移除相关的pregen文件
    if [ -z "${SHMEM_HOME_PATH}" ]; then
        rm -f ${MODULE_BUILD_PATH}/${proj_name}/pregen/build_out/autogen/*shmem*
        rm -f ${MODULE_BUILD_PATH}/${proj_name}/pregen/build_out/autogen/*fused_deep_moe*
        rm -f ${MODULE_BUILD_PATH}/${proj_name}/pregen/build_out/autogen/*zero_buffer*
    fi

    # 设置build_type到CMakePresets.json（在msopgen生成之后调用）
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

    # 构建并行度：可通过 CAM_BUILD_JOBS 环境变量配置，默认 8
    # Jenkins ECS 等内存受限环境建议设置为 2~4
    BUILD_JOBS=${CAM_BUILD_JOBS:-8}
    cmake --build build_out --target binary -j${BUILD_JOBS}
    cmake --build build_out --target package -j${BUILD_JOBS}

    # 根据is_extract判断是否抽取run包
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
