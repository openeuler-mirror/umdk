#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: pybind building script
# Create: 2025-12-09
# Note:
# History: 2025-12-09 create pybind building script

set -e

build_pybind() {
    local build_tmp_dir="${MODULE_BUILD_PATH}/pybind"
    local wheel_out_dir="${MODULE_BUILD_OUT_PATH}/dist"

    # 清理之前的构建输出并重建
    rm -rf "${build_tmp_dir}" "${wheel_out_dir}"
    mkdir -p "${wheel_out_dir}"
    
    # 拷贝源码到临时编译路径
    cp -r $MODULE_SRC_PATH/pybind "${build_tmp_dir}"
    
    # 在临时目录中编译
    cd "${build_tmp_dir}"
    if python3 setup.py bdist_wheel --dist-dir="${wheel_out_dir}"; then
        if [ -d "${wheel_out_dir}" ] && [ "$(ls -A ${wheel_out_dir})" ]; then
            echo "Build packet successful! Wheel files generated in ${wheel_out_dir}"
        else
            echo "${wheel_out_dir} does not exist or is empty"
            echo "Build whl packet fail."
            return 1
        fi
    else
        echo "python3 setup.py bdist_wheel failed"
        return 1
    fi
}

build_pybind