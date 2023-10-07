# Find required packages
find_package(GLIB REQUIRED COMPONENTS gobject)

aux_source_directory(. URMA_DIR_SRCS)

add_library(urma SHARED
    ${URMA_DIR_SRCS}
)

include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/include/common)
include_directories(${CMAKE_SOURCE_DIR}/lib/urma/include)

set_property(TARGET urma PROPERTY C_STANDARD 99)
set_target_properties(urma PROPERTIES VERSION 0.0.1 SOVERSION 0)
add_dependencies(urma urma_common)
target_link_libraries(urma urma_common gobject-2.0 glib-2.0 -ldl -lrt)
install(TARGETS urma DESTINATION /usr/lib64)