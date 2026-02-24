cmake_minimum_required(VERSION 3.12)
project(comm_operator LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)

# 设置默认构建类型为 Release (如果未指定)
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

option(USE_CXX11_ABI "USE_CXX11_ABI" 0)

IF (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64")
    SET(ARCH aarch64)
ELSEIF (CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
    SET(ARCH x86_64)
ENDIF ()

if(USE_CXX11_ABI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=1")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=0")
endif()

message("== CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}")
message("== CMAKE_SOURCE_DIR ${CMAKE_SOURCE_DIR}")

# 获取环境变量
if (DEFINED ENV{ASCEND_HOME_PATH})
    set(ASCEND_HOME_PATH $ENV{ASCEND_HOME_PATH})
else ()
    message("ASCEND_HOME_PATH not set! using default path!")
    set(ASCEND_HOME_PATH /usr/local/Ascend/ascend-toolkit/latest)
endif ()

message("== ASCEND_HOME_PATH: ${ASCEND_HOME_PATH}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=deprecated-declarations -Wno-deprecated-declarations")
# 添加编译加固选项（由用户添加）
add_compile_options(-D_FORTIFY_SOURCE=2 -O2)
# Debug 模式添加 -g 并禁用优化
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_link_options(-s) # Release 模式剥离符号表
endif ()

add_link_options(-Wl,-z,relro,-z,now)


if(DEFINED ENV{ASCEND_OPP_PATH})
    set(ASCEND_OPP_PATH $ENV{ASCEND_OPP_PATH})
    set(CUST_OPAPI_PATH ${ASCEND_OPP_PATH}/vendors/CAM/op_api/)
else()
    message(FATAL_ERROR "Please set ASCEND_OPP_PATH, source /usr/local/Ascend/ascend-toolkit/set_env.sh ")
endif()

set(CAM_ROOT_PATH ${CMAKE_CURRENT_LIST_DIR})

include_directories(
    ${CAM_ROOT_PATH}/include
    ${CAM_ROOT_PATH}/framework/communicator
    ${CAM_ROOT_PATH}/framework/tools/socket
    ${ASCEND_HOME_PATH}/${ARCH}-linux/include/
    ${ASCEND_HOME_PATH}/${ARCH}-linux/include/hccl
    ${ASCEND_HOME_PATH}/${ARCH}-linux/include/hccl/
    ${ASCEND_HOME_PATH}/${ARCH}-linux/include/experiment
    ${ASCEND_HOME_PATH}/${ARCH}-linux/include/experiment/runtime/
    ${ASCEND_HOME_PATH}/${ARCH}-linux/include/experiment/msprof/
    ${CUST_OPAPI_PATH}/include/
)

link_directories(
    ${ASCEND_HOME_PATH}/${ARCH}-linux/lib64/
    ${CUST_OPAPI_PATH}/lib/
)

set(CMAKE_INSTALL_PREFIX "${CMAKE_SOURCE_DIR}/../../../output/cam/comm_operator/" CACHE PATH "Install directory" FORCE)

set(CAM_SOURCE_FILE framework/communicator/cam_comm.cpp framework/communicator/cam_comm.h
        cam_api.cpp
        framework/tools/socket/cam_socket_exchange.h
        framework/tools/socket/cam_socket_exchange.cpp
)

add_library(cam SHARED ${CAM_SOURCE_FILE})
add_library(cam_static STATIC ${CAM_SOURCE_FILE})
set_target_properties(cam_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

# 链接库
target_link_libraries(cam ascendcl runtime c_sec)
target_link_libraries(cam_static ascendcl runtime c_sec)

# 安装库
install(TARGETS cam LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
install(TARGETS cam_static DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
install(FILES include/cam_api.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include)
install(FILES include/cam_types.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include)