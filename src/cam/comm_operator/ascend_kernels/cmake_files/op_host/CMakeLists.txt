# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.
# Migrated from legacy opbuild/manual add_library to npu_op_* build system

# =====================================================
# Detect CANN version include path globally
# =====================================================
if(DEFINED ENV{ASCEND_CANN_PACKAGE_PATH} AND NOT "$ENV{ASCEND_CANN_PACKAGE_PATH}" STREQUAL "")
    set(CANN_ROOT "$ENV{ASCEND_CANN_PACKAGE_PATH}")
elseif(DEFINED ASCEND_CANN_PACKAGE_PATH AND NOT "${ASCEND_CANN_PACKAGE_PATH}" STREQUAL "")
    set(CANN_ROOT "${ASCEND_CANN_PACKAGE_PATH}")
elseif(DEFINED ENV{ASCEND_TOOLKIT_HOME})
    set(CANN_ROOT "$ENV{ASCEND_TOOLKIT_HOME}")
else()
    set(CANN_ROOT "/usr/local/Ascend/ascend-toolkit/latest")
endif()

set(CANN83_PATH "${CANN_ROOT}/include/platform/platform_infos_def.h")
set(CANN82_PATH "${CANN_ROOT}/include/experiment/platform/platform/platform_infos_def.h")

if(EXISTS "${CANN83_PATH}")
    add_definitions(-DUSE_CANN83_PATH)
    set(ACTIVE_CANN_MACRO "-DUSE_CANN83_PATH")
    message(STATUS ">>> [op_host] Detected CANN 8.3+, defined USE_CANN83_PATH")
elseif(EXISTS "${CANN82_PATH}")
    add_definitions(-DUSE_CANN82_PATH)
    set(ACTIVE_CANN_MACRO "-DUSE_CANN82_PATH")
    message(STATUS ">>> [op_host] Detected CANN 8.2, defined USE_CANN82_PATH")
else()
    message(FATAL_ERROR ">>> [op_host] platform_infos_def.h not found!\n  Checked:\n   - ${CANN83_PATH}\n   - ${CANN82_PATH}")
endif()

# Collect custom compile options for npu_op_code_gen
# These are passed to compile_ascendc_all_ops_so.py via --compile-options
set(CODE_GEN_COMPILE_OPTS)
if(DEFINED ENV{SHMEM_HOME_PATH})
    list(APPEND CODE_GEN_COMPILE_OPTS -I$ENV{SHMEM_HOME_PATH}/shmem/include)
    message(STATUS ">>> [op_host] Added shmem compile option for code_gen: -I$ENV{SHMEM_HOME_PATH}/shmem/include")
endif()
if(DEFINED ENV{CATLASS_HOME_PATH})
    list(APPEND CODE_GEN_COMPILE_OPTS -I$ENV{CATLASS_HOME_PATH}/include)
    message(STATUS ">>> [op_host] Added catlass compile option for code_gen: -I$ENV{CATLASS_HOME_PATH}/include")
elseif(DEFINED ENV{CPATH} AND "$ENV{CPATH}" MATCHES "catlass")
    string(REPLACE ":" ";" CPATH_LIST "$ENV{CPATH}")
    foreach(p ${CPATH_LIST})
        if(p MATCHES "catlass")
            list(APPEND CODE_GEN_COMPILE_OPTS -I${p})
            message(STATUS ">>> [op_host] Added catlass compile option for code_gen from CPATH: -I${p}")
            break()
        endif()
    endforeach()
endif()

# shmem include path for host compilation
if(DEFINED ENV{SHMEM_HOME_PATH})
    include_directories($ENV{SHMEM_HOME_PATH}/shmem/include)
endif()

# Host-side include paths:
#  - ${CMAKE_CURRENT_SOURCE_DIR}: op_host root, so operators with nested op_tiling/ sources can
#    resolve shared headers copied into op_host/ (utils/op_host: tiling_base/, err/) via -I.
#  - pkg_inc/op_common: CANN-shipped op_host common headers (log/log.h, util/math_util.h, ...),
#    used by migrated ops-transformer operators. Skipped silently when absent (older CANN).
#  - include/aclnn: opdev/* headers for the l0op-style op_api layer (aclnnGroupedMatmul*).
# The same three paths are also appended to CODE_GEN_COMPILE_OPTS: npu_op_code_gen compiles
# all op_host sources in a separate process (compile_ascendc_all_ops_so.py) that does NOT
# inherit include_directories(), so they must be passed via --compile-options as well.
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set(CANN_ARCH_DIR "")
foreach(cand "aarch64-linux" "x86_64-linux" "linux")
    if(EXISTS "${CANN_ROOT}/${cand}/pkg_inc/op_common")
        set(CANN_ARCH_DIR "${CANN_ROOT}/${cand}")
        break()
    endif()
endforeach()
list(APPEND CODE_GEN_COMPILE_OPTS -I${CMAKE_CURRENT_SOURCE_DIR})
if(NOT "${CANN_ARCH_DIR}" STREQUAL "")
    include_directories("${CANN_ARCH_DIR}/pkg_inc/op_common")
    list(APPEND CODE_GEN_COMPILE_OPTS -I${CANN_ARCH_DIR}/pkg_inc/op_common)
    # migrated op_host sources include "util/math_util.h" (pkg_inc/op_common/op_host/util)
    if(EXISTS "${CANN_ARCH_DIR}/pkg_inc/op_common/op_host")
        include_directories("${CANN_ARCH_DIR}/pkg_inc/op_common/op_host")
        list(APPEND CODE_GEN_COMPILE_OPTS -I${CANN_ARCH_DIR}/pkg_inc/op_common/op_host)
    endif()
    # log/log.h (pkg_inc/op_common) includes "op_common/op_host/util/opbase_export.h" (needs -I pkg_inc)
    # and "dlog_pub.h" (pkg_inc/base)
    if(EXISTS "${CANN_ARCH_DIR}/pkg_inc")
        include_directories("${CANN_ARCH_DIR}/pkg_inc")
        list(APPEND CODE_GEN_COMPILE_OPTS -I${CANN_ARCH_DIR}/pkg_inc)
    endif()
    if(EXISTS "${CANN_ARCH_DIR}/pkg_inc/base")
        include_directories("${CANN_ARCH_DIR}/pkg_inc/base")
        list(APPEND CODE_GEN_COMPILE_OPTS -I${CANN_ARCH_DIR}/pkg_inc/base)
    endif()
endif()
if(EXISTS "${CANN_ROOT}/include/aclnn")
    include_directories("${CANN_ROOT}/include/aclnn")
    list(APPEND CODE_GEN_COMPILE_OPTS -I${CANN_ROOT}/include/aclnn)
endif()

# Collect all host-side source files (recursive: operators may keep upstream op_tiling/ subdirs)
file(GLOB_RECURSE ops_srcs ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

# =====================================================
# Step 1: Generate ACLNN stubs, op_proto.cc, fallback files
# =====================================================
npu_op_code_gen(
    SRC ${ops_srcs}
    PACKAGE ${package_name}
    COMPILE_OPTIONS -g ${ACTIVE_CANN_MACRO} ${CODE_GEN_COMPILE_OPTS}
    OUT_DIR ${ASCEND_AUTOGEN_PATH}
)

# =====================================================
# Step 2: ACLNN single-operator invocation library
# =====================================================
# Copy pre-generated autogen files from pregen/build_out/autogen/
file(GLOB pregen_files "${CMAKE_CURRENT_SOURCE_DIR}/../pregen/build_out/autogen/*")
file(COPY ${pregen_files} DESTINATION ${ASCEND_AUTOGEN_PATH})

# Copy any op_api/ files that exist locally
file(GLOB_RECURSE op_api_files "${CMAKE_CURRENT_SOURCE_DIR}/op_api/*")
if(op_api_files)
    file(COPY ${op_api_files} DESTINATION ${ASCEND_AUTOGEN_PATH})
endif()

file(GLOB aclnn_src ${ASCEND_AUTOGEN_PATH}/aclnn*.cpp)

npu_op_library(cust_opapi ACLNN
    ${aclnn_src}
)
# The migrated ops-transformer aclnn sources use the l0op composite pattern
# (l0op::Contiguous / ReFormat / TransData / ViewCopy live in the CANN built-in
# libopapi.so). The ACLNN target template only links nnopbase/ascendcl, so add
# libopapi as a direct dependency: it becomes a DT_NEEDED entry of
# libcust_opapi.so and the loader resolves the l0op builtins from it no matter
# whether torch_npu has libopapi in the global dlopen scope.
target_link_libraries(cust_opapi PRIVATE opapi)
target_compile_options(cust_opapi PRIVATE
    -fvisibility=hidden
)

# =====================================================
# Step 3: Operator prototype library (for graph compilation)
# =====================================================
file(GLOB proto_src ${ASCEND_AUTOGEN_PATH}/op_proto.cc)
set_source_files_properties(${proto_src} PROPERTIES GENERATED TRUE)

npu_op_library(cust_op_proto GRAPH
    ${ops_srcs}
    ${proto_src}
)
target_compile_options(cust_op_proto PRIVATE
    -fvisibility=hidden
)

# =====================================================
# Step 4: Tiling library
# =====================================================
file(GLOB fallback_src ${ASCEND_AUTOGEN_PATH}/fallback_*.cpp)
set_source_files_properties(${fallback_src} PROPERTIES GENERATED TRUE)

npu_op_library(cust_optiling TILING
    ${ops_srcs}
    ${fallback_src}
)
target_compile_options(cust_optiling PRIVATE
    -fvisibility=hidden
)

# =====================================================
# Step 5: Register all host-side libraries into the package
# =====================================================
npu_op_package_add(${package_name}
    LIBRARY
        cust_optiling
        cust_opapi
        cust_op_proto
)
