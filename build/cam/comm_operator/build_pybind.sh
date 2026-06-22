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

    # Clean up previous build output and rebuild
    rm -rf "${build_tmp_dir}" "${wheel_out_dir}"
    mkdir -p "${wheel_out_dir}"
    
    # Copy source code to temporary build directory
    cp -r $MODULE_SRC_PATH/pybind "${build_tmp_dir}"
    
    # Limit C++ compilation parallelism: configurable via CAM_BUILD_JOBS env variable, default 4
    # For Jenkins ECS and other memory-constrained environments, recommended to set 2~4
    export MAX_JOBS=${CAM_BUILD_JOBS:-8}

    # Build in the temporary directory
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