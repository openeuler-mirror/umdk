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

# 算子注册表路径（算子身份 = ascend_kernels/ 下的目录名）
REGISTRY_PATH="${MODULE_SRC_PATH}/ascend_kernels/operator_registry.json"
# select_ops.py 路径
SELECT_OPS_SCRIPT="${SCRIPTS_PATH}/comm_operator/select_ops.py"

# SHMEM 是否安装（由环境变量 SHMEM_HOME_PATH 判定）
shmem_installed=1
if [ -z "${SHMEM_HOME_PATH}" ]; then
    shmem_installed=0
fi

# -q (量化) 标志由 build.sh 通过 CAM_USE_W4A8=1 透传
use_w4a8=0
if [ "${CAM_USE_W4A8}" = "1" ]; then
    use_w4a8=1
fi

# -a 算子列表由 build.sh 通过 CAM_OP_SELECT 透传（分号分隔；为空=全量）
user_ops="${CAM_OP_SELECT:-}"

# 复制指定算子目录的 op_host/op_kernel/op_api 到目标工程。
# utils 为公共头目录，始终复制；其余按 ops 数组（算子目录名）复制。
# 与旧版全量拷贝+exclude_list 不同，这里只复制 select_ops.py 求解出的算子，
# 从根本上避免同名算子（fused_deep_moe 家族）文件互相覆盖的问题。
copy_ops_include() {
    local src_dir="$1" # 源目录 (ascend_kernels)
    local dst_dir="$2" # 目标目录 (工程根)
    local ops=($3)     # 空格分隔的算子目录名列表

    # 确保目标目录的 op_host、op_kernel 和 pregen autogen 存在
    mkdir -p "$dst_dir/op_host" "$dst_dir/op_kernel" "$dst_dir/pregen/build_out/autogen"

    # 始终复制公共头目录 utils（op_host/op_kernel 下的 .h）
    if [ -d "$src_dir/utils/op_host" ]; then
        cp -rf "$src_dir/utils/op_host/"* "$dst_dir/op_host/" 2>/dev/null || true
    fi
    if [ -d "$src_dir/utils/op_kernel" ]; then
        cp -rf "$src_dir/utils/op_kernel/"* "$dst_dir/op_kernel/" 2>/dev/null || true
    fi

    # 复制每个选中算子的 op_host/op_kernel/op_api
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
        # op_api 接口文件复制到 pregen/build_out/autogen
        if [ -d "$subdir/op_api" ]; then
            cp -rf "$subdir/op_api/"* "$dst_dir/pregen/build_out/autogen/"
        fi
    done
}

# 调用 select_ops.py 求解最终算子列表，返回空格分隔的算子目录名。
# 失败时（注册表/校验错误）select_ops.py 已打印错误并以非零退出，set -e 会中止。
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

# 读取注册表中所有已注册代际（空格分隔）
list_soc_versions() {
    python3 -c "
import json
d = json.load(open('$REGISTRY_PATH'))
print(' '.join(d.get('soc_versions', {}).keys()))
"
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

    # 求解本次要编译的算子列表（include 模式，由 select_ops.py 校验+过滤）
    # select_ops.py 在 soc 未注册/算子名非法/-q 冲突等情况下会报错并退出。
    local selected_ops
    selected_ops=$(resolve_ops "$soc_version")
    if [ -z "$selected_ops" ]; then
        echo "ERROR: no operators resolved for SOC ${soc_version}"
        return 1
    fi
    echo "Selected operators for ${soc_version}: ${selected_ops}"

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

    # 复制选中算子的 op_host/op_kernel 源文件和 op_api 接口文件（include 模式）
    copy_ops_include "./ascend_kernels" "${MODULE_BUILD_PATH}/${proj_name}" "$selected_ops"

    # 复制cmake_files/cmake目录（包含自定义编译函数，替换msopgen默认cmake）
    cp -rf ./ascend_kernels/cmake_files/cmake ${MODULE_BUILD_PATH}/${proj_name}/

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

# ---- 入口 ----
# 用法: compile_ascend_proj.sh <src_path> <soc_version|all> <is_extract> <build_type>
src_path=$1
soc_arg=$2
is_extract=${3:-0}
build_type=${4:-Release}

if [ -z "$src_path" ] || [ -z "$soc_arg" ]; then
    echo "Usage: $0 <src_path> <soc_version|all> <is_extract> <build_type>"
    exit 1
fi

# 构建输出 run 目录
if [ ! -d "$BUILD_OUT_PATH/comm_operator/run" ]; then
    mkdir -p "$BUILD_OUT_PATH/comm_operator/run"
fi

if [ "$soc_arg" = "all" ]; then
    # 默认：遍历注册表中所有已注册代际，每代际编译全量算子
    # （select_ops.py 会按 SHMEM 安装情况自动剔除相应算子）
    all_socs=$(list_soc_versions)
    if [ -z "$all_socs" ]; then
        echo "ERROR: no SOC versions registered in ${REGISTRY_PATH}"
        exit 1
    fi
    # -a 选择与默认 all 不兼容：all 模式下遍历每代际的全量集，不接受单算子指定
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
