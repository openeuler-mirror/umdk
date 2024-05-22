find_package(GLIB REQUIRED COMPONENTS gobject)
include_directories(${GLIB_INCLUDE_DIRS})
link_directories(${CMAKE_BINARY_DIR})

file(GLOB_RECURSE SRC_FILES
    "daemon/*.c"
)

add_executable(tpsa_daemon ${SRC_FILES})
add_executable(uvs_daemon ${SRC_FILES})
add_subdirectory(config)
add_subdirectory(core)
add_subdirectory(daemon)
include_directories(${PROJECT_SOURCE_DIR}/include/common)
include_directories(${CMAKE_CURRENT_LIST_DIR}/core/tpsa/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include/tpservice_cfg)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include/vport_table_cfg)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include/sip_table_cfg)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include/live_migrate_table_cfg)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include/global_cfg)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include/dip_table_cfg)
include_directories(${CMAKE_CURRENT_LIST_DIR}/daemon/include)

set_target_properties(tpsa_daemon PROPERTIES
    C_STANDARD 99
    )

set_target_properties(uvs_daemon PROPERTIES
    C_STANDARD 99
    )

target_link_libraries(tpsa_daemon tpsa glib-2.0 pthread urma_common)
if(CROSS_COMPILE)
    target_link_libraries(tpsa_daemon pcre2-8 ffi)
endif()

if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS tpsa_daemon DESTINATION /usr/sbin)
endif()

target_link_libraries(uvs_daemon tpsa glib-2.0 pthread urma_common)
if(CROSS_COMPILE)
    target_link_libraries(uvs_daemon pcre2-8 ffi)
endif()

if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS uvs_daemon DESTINATION /usr/sbin)
endif()
