# UBus code makefile
cmake_minimum_required(VERSION 3.12.1)
project(UBus)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "cmake")
set(CMAKE_C_COMPILER "/usr/bin/gcc")

set(CMAKE_FLAGS_PUBILC " -Wall -Werror -Wfloat-equal -Wtrampolines -g -O2 -rdynamic -Wl,-z,noexecstack,-z,relro,-z,now \
-fno-strict-aliasing -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -fPIC")

# PERF_CYCLE ENABLE
if("${PERF_CYCLE}" STREQUAL "enable")
    set(CMAKE_FLAGS_PUBILC "${CMAKE_FLAGS_PUBILC} -DPERF_CYCLE_FLAG")
endif("${PERF_CYCLE}" STREQUAL "enable")

set(CMAKE_FLAGS_ARM64 " -march=armv8-a+crc -DUB_ARCH_ARM64")
set(CMAKE_FLAGS_x86_64 " -msse4.2 -DUB_ARCH_X86_64")
if("${X86_CROSS_COMPILATION}" STREQUAL "enable")
    set(CMAKE_FLAGS_x86_64 " -DUB_ARCH_X86_64")
    message(STATUS "x86 cross compilation, disabling msse4.2!")
endif()
if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_ARM64} -std=c++11")
else()
    set(CMAKE_C_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_FLAGS_PUBILC} ${CMAKE_FLAGS_x86_64} -std=c++11")
endif()

set(CMAKE_SKIP_RPATH TRUE)

message(STATUS "CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")

include_directories(include)
add_subdirectory(include)
add_subdirectory(common)
add_subdirectory(lib)

# uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()