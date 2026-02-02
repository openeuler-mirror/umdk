# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

# set custom compile options
if ("${CMAKE_BUILD_TYPE}x" STREQUAL "Debugx")
    add_ops_compile_options(ALL OPTIONS -g -O0)
endif()
# Code coverage configuration
if (DEFINED ENV{ENABLE_COV})
    add_ops_compile_options(ALL OPTIONS --save-temp-files)
endif()
add_ops_compile_options(ALL OPTIONS -DASCENDC_DUMP=0 --cce-auto-sync=off)

add_kernels_compile()