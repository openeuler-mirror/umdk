find_package(GLIB REQUIRED COMPONENTS gobject)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} URMA_COMMON_SRCS)
if(NOT "${PERF_CYCLE}" STREQUAL "enable")
    list(REMOVE_ITEM URMA_COMMON_SRCS "${CMAKE_CURRENT_LIST_DIR}/ub_perf_cycle.c")
endif(NOT "${PERF_CYCLE}" STREQUAL "enable")

add_library(urma_common SHARED
    ${URMA_COMMON_SRCS}
)
add_library(urma_common_static STATIC
    ${URMA_COMMON_SRCS}
)

include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/include/common)

set_property(TARGET urma_common PROPERTY C_STANDARD 99)
set_target_properties(urma_common PROPERTIES VERSION 0.0.1 SOVERSION 0)
target_link_libraries(urma_common gobject-2.0 glib-2.0 -ldl -lrt)
target_link_libraries(urma_common_static gobject-2.0 glib-2.0 -ldl -lrt)

if("${PERF_CYCLE}" STREQUAL "enable")
    target_link_libraries(urma_common m)
endif("${PERF_CYCLE}" STREQUAL "enable")

if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS urma_common DESTINATION /usr/lib64)
endif()
