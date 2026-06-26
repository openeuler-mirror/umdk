# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.
# Migrated from legacy add_ops_compile_options/add_kernels_compile to npu_op_* build system

# Collect all kernel compile options into a single list to avoid overwriting in custom_compile_options.ini
set(KERNEL_COMPILE_OPTS)

# shmem include path (include/ for .h headers, src/device/ for internal .hpp files referenced relative to shmem/src/device)
if(DEFINED ENV{SHMEM_HOME_PATH})
    list(APPEND KERNEL_COMPILE_OPTS -I$ENV{SHMEM_HOME_PATH}/shmem/include -I$ENV{SHMEM_HOME_PATH}/shmem/src/device)
    message(STATUS ">>> [op_kernel] Added shmem include paths: -I$ENV{SHMEM_HOME_PATH}/shmem/include -I$ENV{SHMEM_HOME_PATH}/shmem/src/device")
endif()

# catlass include path
if(DEFINED ENV{CATLASS_HOME_PATH})
    list(APPEND KERNEL_COMPILE_OPTS -I$ENV{CATLASS_HOME_PATH}/include)
    message(STATUS ">>> [op_kernel] Added catlass include path: -I$ENV{CATLASS_HOME_PATH}/include")
elseif(DEFINED ENV{CPATH} AND "$ENV{CPATH}" MATCHES "catlass")
    string(REPLACE ":" ";" CPATH_LIST "$ENV{CPATH}")
    foreach(p ${CPATH_LIST})
        if(p MATCHES "catlass")
            list(APPEND KERNEL_COMPILE_OPTS -I${p})
            message(STATUS ">>> [op_kernel] Added catlass include path from CPATH: -I${p}")
            break()
        endif()
    endforeach()
endif()

# Common options: add current source dir as global header search path (from cam_feature)
list(APPEND KERNEL_COMPILE_OPTS -I${CMAKE_CURRENT_SOURCE_DIR} -DASCENDC_DUMP=0 --cce-auto-sync=off -DCATLASS_ARCH=2201)

# set custom compile options (single call to avoid overwriting)
if ("${CMAKE_BUILD_TYPE}x" STREQUAL "Debugx")
    npu_op_kernel_options("" ALL OPTIONS -g -O0 ${KERNEL_COMPILE_OPTS})
else()
    npu_op_kernel_options("" ALL OPTIONS ${KERNEL_COMPILE_OPTS})
endif()

# Collect AscendC kernel source files
npu_op_kernel_sources(ascendc_kernels
    KERNEL_DIR ./
)

# Compile AscendC kernels and link with tiling library
npu_op_kernel_library(ascendc_kernels
    SRC_BASE ${CMAKE_CURRENT_SOURCE_DIR}/
    TILING_LIBRARY cust_optiling
)

# Register kernel library into the package
npu_op_package_add(${package_name}
    LIBRARY ascendc_kernels
)
