# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2025. All rights reserved.

cmake_minimum_required(VERSION 3.14.1)

project(dlock_ut_gtest)

add_compile_options(-Wall -Wno-noexcept-type -Wno-pmf-conversions -fno-access-control -fPIC -fno-omit-frame-pointer)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

# find GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
set(GTEST_LIBRARIES /usr/local/lib64/libgtest.a)

# find MockCpp
set(MOCKCPP_INCLUDE_DIRS /usr/local/include)
set(MOCKCPP_LIBRARIES /usr/local/lib/libmockcpp.a)
include_directories(${MOCKCPP_INCLUDE_DIRS})

# add test code
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} TEST_SOURCE_DIR)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/dlock_test TEST_SOURCE_DIR)

# generate the target file
add_executable(${PROJECT_NAME} ${TEST_SOURCE_DIR})

target_include_directories(${PROJECT_NAME} PRIVATE /usr/include/ub/umdk/)
target_include_directories(${PROJECT_NAME} PRIVATE /usr/include/ub/umdk/urma)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/urma/common/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/urma/lib/urma/core)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/urma/lib/urma/core/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/urma/lib/urma/bond/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/ulock/dlock/lib/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/ulock/dlock/lib/common)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/ulock/dlock/lib/server)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/../../../src/ulock/dlock/lib/client)

target_link_libraries(${PROJECT_NAME} ${GTEST_LIBRARIES} ${MOCKCPP_LIBRARIES})

if("${ASAN}" STREQUAL "enable")
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
endif()

target_link_libraries(${PROJECT_NAME} dlockc dlockm dlocks urma pthread ssl crypto)

# print build options
get_target_property(COMPILE_FLAGS ${PROJECT_NAME} COMPILE_OPTIONS)
get_target_property(LINK_FLAGS ${PROJECT_NAME} LINK_OPTIONS)
message(STATUS "Compiler id: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compile flags: ${COMPILE_FLAGS}")
message(STATUS "Link flags: ${LINK_FLAGS}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
