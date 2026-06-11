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

# Coverage option
if(DEFINED ENV{ENABLE_COV})
    message(STATUS "Coverage enabled via ENABLE_COV environment variable")
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage -lgcov)
endif()

# Collect all host-side source files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} ops_srcs)

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
