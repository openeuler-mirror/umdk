find_package(GLIB REQUIRED COMPONENTS)
include_directories(${GLIB_INCLUDE_DIRS})

add_subdirectory(config)

add_executable(urma_admin
    urma_admin.c
    urma_admin_log.c
    admin_parameters.c
    admin_file_ops.c
    admin_cmd.c
    admin_netlink.c
)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/common)
include_directories(/usr/include/libnl3)
target_link_libraries(urma_admin glib-2.0 nl-genl-3 nl-3)

if(CROSS_COMPILE)
    target_link_libraries(urma_admin pcre2-8)
endif()
set_target_properties(urma_admin PROPERTIES C_STANDARD 99)
if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS urma_admin DESTINATION /usr/bin)
endif()
