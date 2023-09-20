find_package(GLIB REQUIRED COMPONENTS gobject)
include_directories(${GLIB_INCLUDE_DIRS})
link_directories(${CMAKE_BINARY_DIR})

add_executable(tpsa_daemon "")
add_subdirectory(config)
add_subdirectory(core)
include_directories(include)
include_directories(../include/common)

set_target_properties(tpsa_daemon PROPERTIES
    C_STANDARD 99
    )

target_link_libraries(tpsa_daemon glib-2.0 pthread urma_common)
install(TARGETS tpsa_daemon DESTINATION /usr/sbin)