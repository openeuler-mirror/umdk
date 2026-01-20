# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

# set custom compile options
if ("${CMAKE_BUILD_TYPE}x" STREQUAL "Debugx")
    add_ops_compile_options(ALL OPTIONS -g -O0)
endif()

add_ops_compile_options(ALL OPTIONS -DASCENDC_DUMP=0 --cce-auto-sync=off -I${CMAKE_CURRENT_SOURCE_DIR})

add_kernels_compile()
