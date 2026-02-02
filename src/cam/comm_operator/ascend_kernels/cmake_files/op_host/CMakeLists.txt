# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} ops_srcs)

#===================================================
# Check for coverage option
#===================================================
if(DEFINED ENV{ENABLE_COV})
    message(STATUS "Coverage enabled via ENABLE_COV environment variable")
    add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
    add_link_options(--coverage -lgcov)
endif()

#===================================================
# Detect CANN version include path globally
#===================================================
set(CANN82_PATH "${ASCEND_CANN_PACKAGE_PATH}/include/experiment/platform/platform/platform_infos_def.h")
set(CANN83_PATH "${ASCEND_CANN_PACKAGE_PATH}/include/platform/platform_infos_def.h")

message(STATUS "ASCEND_CANN_PACKAGE_PATH = ${ASCEND_CANN_PACKAGE_PATH}")
message(STATUS "Checking for CANN include paths:")
message(STATUS "CANN82_PATH = ${CANN82_PATH}")
message(STATUS "CANN83_PATH = ${CANN83_PATH}")

if (EXISTS "${CANN83_PATH}")
    set(CANN_VERSION_MACRO "USE_CANN83_PATH")
    message(STATUS "Detected CANN 8.3+ include structure, using ${CANN83_PATH}")
elseif (EXISTS "${CANN82_PATH}")
    set(CANN_VERSION_MACRO "USE_CANN82_PATH")
    message(STATUS "Detected CANN 8.2 include structure, using ${CANN82_PATH}")
else()
    message(FATAL_ERROR 
            "Cannot find 'platform_infos_def.h' in expected location. \n"
            "Please verify that CANN is correctly installed and that either: \n"
            " ${CANN83_PATH} \n"
            " or \n"
            " ${CANN82_PATH} \n"
            "exists and contains the header file."
        )
endif()

if (CANN_VERSION_MACRO)
    add_compile_definitions(${CANN_VERSION_MACRO})
endif()

get_directory_property(current_defs COMPILE_DEFINITIONS)
message(STATUS "Compile definitions: ${current_defs}")

opbuild(OPS_SRC ${ops_srcs}
    OUT_DIR ${ASCEND_AUTOGEN_PATH}
)

if(DEFINED ENV{SHMEM_HOME_PATH})
    include_directories($ENV{SHMEM_HOME_PATH}/shmem/include)
endif()

file(GLOB group_proto_src ${ASCEND_AUTOGEN_PATH}/group_proto/*.cc)

add_library(cust_op_proto SHARED
    $<$<TARGET_EXISTS:group_proto_src>:${group_proto_src}>
    ${ops_srcs}
    ${ASCEND_AUTOGEN_PATH}/op_proto.cc
)
target_compile_definitions(cust_op_proto PRIVATE OP_PROTO_LIB)
target_compile_options(cust_op_proto PRIVATE
    -fvisibility=hidden
)
if(ENABLE_CROSS_COMPILE)
    target_link_directories(cust_op_proto PRIVATE
        ${CMAKE_COMPILE_COMPILER_LIBRARY}
        ${CMAKE_COMPILE_RUNTIME_LIBRARY}
    )
endif()
target_link_libraries(cust_op_proto PRIVATE
    intf_pub
    exe_graph
    register
    tiling_api
    -Wl,--whole-archive
    rt2_registry
    -Wl,--no-whole-archive
)
set_target_properties(cust_op_proto PROPERTIES OUTPUT_NAME
    cust_opsproto_rt2.0
)
file(GLOB fallback_src ${ASCEND_AUTOGEN_PATH}/fallback_*.cpp)
add_library(cust_optiling SHARED ${ops_srcs})
if (${fallback_src})
    target_sources(cust_optiling PRIVATE ${fallback_src})
endif()
target_compile_definitions(cust_optiling PRIVATE OP_TILING_LIB)
target_compile_options(cust_optiling PRIVATE
    -fvisibility=hidden
)
if(ENABLE_CROSS_COMPILE)
    target_link_directories(cust_optiling PRIVATE
        ${CMAKE_COMPILE_COMPILER_LIBRARY}
        ${CMAKE_COMPILE_RUNTIME_LIBRARY}
    )
endif()
target_link_libraries(cust_optiling PRIVATE
    nnopbase
    intf_pub
    exe_graph
    register
    tiling_api
    -Wl,--whole-archive
    rt2_registry
    -Wl,--no-whole-archive
)
set_target_properties(cust_optiling PROPERTIES OUTPUT_NAME
    cust_opmaster_rt2.0
)

file(GLOB pregen_file "../pregen/build_out/autogen/*")
file(COPY ${pregen_file} DESTINATION ${ASCEND_AUTOGEN_PATH})
file(GLOB aclnn_src ${ASCEND_AUTOGEN_PATH}/aclnn*.cpp)
file(GLOB aclnn_inc ${ASCEND_AUTOGEN_PATH}/aclnn_*.h)

if(NOT ASCEND_PACK_SHARED_LIBRARY)
    add_library(cust_opapi SHARED ${aclnn_src})
else()
    file(GLOB op_registry ${ASCEND_AUTOGEN_PATH}/custom_op_registry.cpp)
    add_library(cust_opapi SHARED ${aclnn_src} ${op_registry})
    target_compile_definitions(cust_opapi PRIVATE ACLNN_WITH_BINARY)
endif()

target_include_directories(cust_opapi PRIVATE $ENV{ASCEND_HOME_PATH}/aarch64-linux/include/experiment/platform/)

if(ENABLE_CROSS_COMPILE)
    target_link_directories(cust_opapi PRIVATE
        ${CMAKE_COMPILE_COMPILER_LIBRARY}
        ${CMAKE_COMPILE_RUNTIME_LIBRARY}
    )
endif()
if(NOT ASCEND_PACK_SHARED_LIBRARY)
    target_link_libraries(cust_opapi PRIVATE intf_pub ascendcl nnopbase)
else()
    add_library(cust_op_proto_obj OBJECT
        $<$<TARGET_EXISTS:group_proto_src>:${group_proto_src}>
        ${ops_srcs}
        ${ASCEND_AUTOGEN_PATH}/op_proto.cc
    )
    target_compile_definitions(cust_op_proto_obj PRIVATE OP_PROTO_LIB)
    target_compile_options(cust_op_proto_obj PRIVATE
        -fvisibility=hidden
    )
    if(ENABLE_CROSS_COMPILE)
        target_link_directories(cust_op_proto_obj PRIVATE
            ${CMAKE_COMPILE_COMPILER_LIBRARY}
            ${CMAKE_COMPILE_RUNTIME_LIBRARY}
    )
    endif()
    target_link_libraries(cust_op_proto_obj PRIVATE
        intf_pub
        exe_graph
        register
        tiling_api
        -Wl,--whole-archive
        rt2_registry
        -Wl,--no-whole-archive
    )
    add_library(cust_optiling_obj OBJECT ${ops_srcs})
    target_compile_definitions(cust_optiling_obj PRIVATE OP_TILING_LIB)
    target_compile_options(cust_optiling_obj PRIVATE
        -fvisibility=hidden
    )
    if(ENABLE_CROSS_COMPILE)
        target_link_directories(cust_optiling_obj PRIVATE
            ${CMAKE_COMPILE_COMPILER_LIBRARY}
            ${CMAKE_COMPILE_RUNTIME_LIBRARY}
        )
    endif()
    target_link_libraries(cust_optiling_obj PRIVATE
        intf_pub
        exe_graph
        register
        tiling_api
        -Wl,--whole-archive
        rt2_registry
        -Wl,--no-whole-archive
    )
    target_compile_options(cust_opapi PRIVATE -DLOG_CPP)
    if(DEFINED ENV{SHMEM_HOME_PATH})
        target_include_directories(cust_opapi INTERFACE ${CMAKE_SOURCE_DIR}/build_out/library/
                                    $ENV{SHMEM_HOME_PATH}/shmem/lib
                                    $ENV{SHMEM_HOME_PATH}/memfabric_hybrid/lib)
    else()
        target_include_directories(cust_opapi INTERFACE ${CMAKE_SOURCE_DIR}/build_out/library/)
    endif()

    target_link_libraries(cust_opapi PRIVATE intf_pub ascendcl nnopbase cust_optiling_obj cust_op_proto_obj ascend_opregistry ascend_kernels)
    add_dependencies(cust_opapi ascend_opregistry)
endif()

add_custom_target(optiling_compat ALL
    COMMAND ln -sf lib/linux/${CMAKE_SYSTEM_PROCESSOR}/$<TARGET_FILE_NAME:cust_optiling>
        ${CMAKE_CURRENT_BINARY_DIR}/liboptiling.so
)
if(NOT ASCEND_PACK_SHARED_LIBRARY)
    install(TARGETS cust_op_proto
        LIBRARY DESTINATION packages/vendors/${vendor_name}/op_proto/lib/linux/${CMAKE_SYSTEM_PROCESSOR})
    install(FILES ${ASCEND_AUTOGEN_PATH}/op_proto.h
        DESTINATION packages/vendors/${vendor_name}/op_proto/inc)
    file(GLOB GROUP_PROTO_HEADERS ${ASCEND_AUTOGEN_PATH}/group_proto/*.h)
    if (GROUP_PROTO_HEADERS)
        install(FILES ${GROUP_PROTO_HEADERS}
            DESTINATION packages/vendors/${vendor_name}/op_proto/inc)
    endif()
    install(TARGETS cust_optiling
        LIBRARY DESTINATION packages/vendors/${vendor_name}/op_impl/ai_core/tbe/op_tiling/lib/linux/${CMAKE_SYSTEM_PROCESSOR})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/liboptiling.so
        DESTINATION packages/vendors/${vendor_name}/op_impl/ai_core/tbe/op_tiling)
    install(TARGETS cust_opapi
        LIBRARY DESTINATION packages/vendors/${vendor_name}/op_api/lib)
    install(FILES ${aclnn_inc}
        DESTINATION packages/vendors/${vendor_name}/op_api/include)
else()
    file(GLOB group_inc ${ASCEND_AUTOGEN_PATH}/group_proto/*.h)
    install(TARGETS cust_opapi
        LIBRARY DESTINATION op_api/lib)
    install(FILES ${ASCEND_AUTOGEN_PATH}/op_proto.h
        DESTINATION op_api/include)
    install(FILES ${group_inc}
        DESTINATION op_api/include)
    install(FILES ${aclnn_inc}
        DESTINATION op_api/include)
endif()