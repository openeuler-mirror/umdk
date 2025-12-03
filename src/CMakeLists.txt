# umdk code makefile
cmake_minimum_required(VERSION 3.12.1)
project(umdk
    VERSION 0.0.1
)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}")

if(NOT "${BUILD_ALL}" STREQUAL "disable" OR "${BUILD_URMA}" STREQUAL "enable")
    add_subdirectory(urma)
endif()

if(NOT "${BUILD_ALL}" STREQUAL "disable" OR "${BUILD_DLOCK}" STREQUAL "enable")
    add_subdirectory(ulock)
endif()

if(NOT "${BUILD_ALL}" STREQUAL "disable" OR "${BUILD_URPC}" STREQUAL "enable")
    add_subdirectory(urpc)
endif()

if(NOT "${BUILD_ALL}" STREQUAL "disable" OR "${BUILD_UMS}" STREQUAL "enable")
    add_subdirectory(usock)
endif()