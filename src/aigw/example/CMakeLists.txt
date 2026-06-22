#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
#

cmake_minimum_required(VERSION 3.28)
project(aigw_test LANGUAGES C)

# -----------------------------
# Path hint for aigw installation (user can override via -DAIGW_DIR_HINT=...)
# -----------------------------
set(AIGW_DIR_HINT "${CMAKE_SOURCE_DIR}/../output/aigw" CACHE PATH "Path to aigw installation (must contain lib/libaigw.so and include/aigw.h)")

# -----------------------------
# Find aigw header file and library
# -----------------------------
find_path(AIGW_INCLUDE_DIR
    NAMES aigw.h
    PATHS ${AIGW_DIR_HINT}
    PATH_SUFFIXES include
    REQUIRED
)

find_library(AIGW_LIBRARY
    NAMES aigw
    PATHS ${AIGW_DIR_HINT}
    PATH_SUFFIXES lib lib64
    REQUIRED
)

get_filename_component(AIGW_LIB_DIR ${AIGW_LIBRARY} DIRECTORY)

message(STATUS "Found aigw.h: ${AIGW_INCLUDE_DIR}")
message(STATUS "Found libaigw.so: ${AIGW_LIBRARY}")

# -----------------------------
# Optional Redis support
# -----------------------------
option(ENABLE_REDIS "Enable Redis cache driver" OFF)

if(ENABLE_REDIS)
    find_library(HIREDIS_LIB hiredis REQUIRED)
    message(STATUS "Redis support enabled: using hiredis")
endif()

# -----------------------------
# Build the executable
# -----------------------------
add_executable(aigw_test_demo
    cgo/aigw_test_demo.c
    cgo/simple_cache.c
)

# Conditionally add Redis source file
if(ENABLE_REDIS)
    target_sources(aigw_test_demo PRIVATE cgo/redis_cache_driver.c)
    target_link_libraries(aigw_test_demo ${HIREDIS_LIB})
    target_compile_definitions(aigw_test_demo PRIVATE ENABLE_REDIS_DRIVER)
endif()

# Include directories
target_include_directories(aigw_test_demo PRIVATE
    ${AIGW_INCLUDE_DIR}
    cgo
    ../include
)

# Link libraries
target_link_libraries(aigw_test_demo
    ${AIGW_LIBRARY}
    pthread
)

# Enable PIE (Position Independent Executable)
set_property(TARGET aigw_test_demo PROPERTY POSITION_INDEPENDENT_CODE ON)

# -----------------------------
# Critical: Runtime library path setup + automatic copy of libaigw.so
# -----------------------------

# Set runtime library search path: look in the executable's directory
set_target_properties(aigw_test_demo PROPERTIES
    BUILD_RPATH "$ORIGIN"
    SKIP_BUILD_RPATH FALSE
    INSTALL_RPATH "$ORIGIN"
    BUILD_WITH_INSTALL_RPATH FALSE
)

# Automatically copy libaigw.so to the output directory after build
add_custom_command(TARGET aigw_test_demo POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${AIGW_LIBRARY}
        $<TARGET_FILE_DIR:aigw_test_demo>/
    COMMENT "Copying libaigw.so to output directory for runtime linking"
)
