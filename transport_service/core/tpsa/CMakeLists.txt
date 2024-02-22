# Find required packages
find_package(GLIB REQUIRED COMPONENTS gobject)

aux_source_directory(${CMAKE_CURRENT_LIST_DIR} TPSA_SO_DIR_SRCS)

add_library(tpsa SHARED
    ${TPSA_SO_DIR_SRCS}
)

include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/transport_service/daemon/include)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/common)
include_directories(${CMAKE_SOURCE_DIR}/transport_service/core/tpsa/include)

set_property(TARGET tpsa PROPERTY C_STANDARD 99)
set_target_properties(tpsa PROPERTIES VERSION 0.0.1 SOVERSION 0)
target_link_libraries(tpsa gobject-2.0 glib-2.0 urma_common)

if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS tpsa DESTINATION /usr/lib64)
endif()