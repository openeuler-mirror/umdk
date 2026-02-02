#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: cam building script
# Create: 2025-07-20
# Note:
# History: 2025-07-20 create cam building script

set -e

# 定义全局屏蔽列表
exclude_list=()
if [ -z "${SHMEM_HOME_PATH}" ]; then
    echo "Skipping shmem (SHMEM_HOME_PATH not set)"
    exclude_list+=("moe_combine_shmem" "moe_dispatch_shmem")
fi

copy_ops() {
    local src_dir="$1" # 源目录
    local dst_dir="$2" # 目标目录

    # 确保目标目录的ophost和opkernel存在
    mkdir -p "$dst_dir/op_host" "$dst_dir/op_kernel"

    # 遍历源目录下所有直接子目录 （包括含空格的目录）
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
        fi
    done
}

modify_func_cmake () {
  sed -i '/cmake_parse_arguments(OPBUILD.*)/a\
\
  if (DEFINED CANN_VERSION_MACRO AND NOT "${CANN_VERSION_MACRO}" STREQUAL "")\
    set(CANN_VERSION_FLAG "-D${CANN_VERSION_MACRO}")\
    message(STATUS "opbuild: Detected CANN_VERSION_MACRO = ${CANN_VERSION_MACRO}")\
  else()\
    set(CANN_VERSION_FLAG "")\
    message(WARNING "opbuild: No CANN_VERSION_MACRO defined! Possible #error in .cc files.")\
  endif()' cmake/func.cmake
 
# 在 -D_GLIBCXX_USE_CXX11_ABI 后添加 ${CANN_VERSION_FLAG}
  sed -i '/-D_GLIBCXX_USE_CXX11_ABI=/a\
                  ${CANN_VERSION_FLAG}' cmake/func.cmake
}

# 构建算子工程并将其产物传到指定地点
build_ascend_proj() {
    local os_id=$(grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"')
    local arch=$(uname -m)
    local soc_version=$2
    local is_extract=$3
    local build_type=$4
    local proj_name="ascend_kernels_${soc_version}_proj"
    # 修改默认算子名
    export OPS_PROJECT_NAME=aclnnInner
    # 使能AscendC算子覆盖率统计
    if [ -n "${ENABLE_COV}" ]; then
        export ASCENDC_COV=1
    fi
    # 进入编译路径
    cd $1

    # 确保 MODULE_BUILD_PATH 目录存在
    if [ ! -d "${MODULE_BUILD_PATH}" ]; then
        mkdir -p ${MODULE_BUILD_PATH}
    fi

    if [ -d "${MODULE_BUILD_PATH}/${proj_name}" ]; then
        rm -rf ${MODULE_BUILD_PATH}/${proj_name}
    fi
    echo "msopgen gen -i ./ascend_kernels/AddCustom.json -c ai_core-${soc_version} -f pytorch -lan cpp -out ${MODULE_BUILD_PATH}/${proj_name}"
    msopgen gen -i ./ascend_kernels/AddCustom.json -c ai_core-${soc_version} -f pytorch -lan cpp -out ${MODULE_BUILD_PATH}/${proj_name}
    rm -rf ${MODULE_BUILD_PATH}/${proj_name}/op_host/add_custom*
    rm  -rf ${MODULE_BUILD_PATH}/${proj_name}/op_kernel/add_custom*
    copy_ops "./ascend_kernels" "${MODULE_BUILD_PATH}/${proj_name}"
    python $SCRIPTS_PATH/comm_operator/set_conf.py ${MODULE_BUILD_PATH}/${proj_name}/CMakePresets.json $build_type True CAM
    cp -rf ./ascend_kernels/pregen ${MODULE_BUILD_PATH}/${proj_name}
    # if need to compile shmem opts: replace msopgen camke files with pregen {.ascend_kernels/pregen/cmake}
    if [ -n "${SHMEM_HOME_PATH}" ]; then
        cp -rf ./ascend_kernels/pregen/cmake ${MODULE_BUILD_PATH}/${proj_name}
    else
        rm -f ${MODULE_BUILD_PATH}/${proj_name}/pregen/build_out/autogen/*shmem*
    fi

    source $ASCEND_HOME_PATH/bin/setenv.bash || true
    cd ${MODULE_BUILD_PATH}/${proj_name}
    modify_func_cmake
    ./build.sh
    # 根据is_extract判断是否抽取run包
    if [ $is_extract -eq 1 ]; then
        if [ ! -d "$BUILD_OUT_PATH/comm_operator/extract" ]; then
            mkdir -p "$BUILD_OUT_PATH/comm_operator/extract"
        fi
        mkdir ${BUILD_OUT_PATH}/comm_operator/extract/${soc_version}
        build_out/*.run --extract=${BUILD_OUT_PATH}/comm_operator/extract/${soc_version}
    else
        cp build_out/*.run ${BUILD_OUT_PATH}/comm_operator/run/CAM_${soc_version}_${os_id}_${arch}.run
    fi
}

build_ascend_proj $1 $2 $3 $4
