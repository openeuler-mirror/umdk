find_package(GLIB REQUIRED COMPONENTS)
include_directories(${GLIB_INCLUDE_DIRS})

set(UVS_ADMIN_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/tools/uvs_admin)
include_directories(${UVS_ADMIN_INCLUDE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/common)

add_subdirectory(config)
add_subdirectory(tpservice)
add_subdirectory(vport_table)
add_subdirectory(sip_table)
add_subdirectory(dip_table)
add_subdirectory(live_migrate_table)
add_subdirectory(global_cfg)

set(UVS_ADMIN_CORE_SOURCES
    uvs_admin.c
    uvs_admin_cmd.c
    uvs_admin_rootcmd.c
    uvs_admin_cmd_client.c
    uvs_admin_cmd_util.c
    uvs_admin_cmd_trace.c
    uvs_admin_log.c
)

set(UVS_ADMIN_SUBCOMMAND_OBJS
    $<TARGET_OBJECTS:tpservice>
    $<TARGET_OBJECTS:vport_table>
    $<TARGET_OBJECTS:sip_table>
    $<TARGET_OBJECTS:dip_table>
    $<TARGET_OBJECTS:live_migrate_table>
    $<TARGET_OBJECTS:global_cfg>
)

add_executable(uvs_admin
${UVS_ADMIN_CORE_SOURCES}
${UVS_ADMIN_SUBCOMMAND_OBJS}
)

target_link_libraries(uvs_admin urma_common glib-2.0)

if(CROSS_COMPILE)
    target_link_libraries(uvs_admin pcre2-8 ffi)
endif()

if("${FUZZ}" STREQUAL "enable")
target_link_libraries(uvs_admin /usr/local/lib64/libSecodefuzz.a)
endif("${FUZZ}" STREQUAL "enable")

set_target_properties(uvs_admin PROPERTIES C_STANDARD 99)
if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS uvs_admin DESTINATION /usr/bin PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE)
endif()
