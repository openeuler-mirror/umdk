# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

find_package(PkgConfig REQUIRED)

pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
pkg_check_modules(LIBNL3 REQUIRED IMPORTED_TARGET libnl-3.0)
pkg_check_modules(LIBNL_GENL3 REQUIRED IMPORTED_TARGET libnl-genl-3.0)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)
pkg_check_modules(KEYUTILS REQUIRED IMPORTED_TARGET libkeyutils)

add_executable(ums_agent
    ums_agent_main.c
    ums_agent_config.c
    ums_agent_config.h
    ums_agent_log.c
    ums_agent_log.h
    ums_agent_types.h
    ums_agent_utils.c
    ums_agent_utils.h
    ums_agent_epoll.c
    ums_agent_epoll.h
    ums_agent_tls_ctx.c
    ums_agent_tls_ctx.h
)

set_target_properties(ums_agent
    PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
)

target_include_directories(ums_agent
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(ums_agent
    PRIVATE
        PkgConfig::GLIB
        PkgConfig::LIBNL3
        PkgConfig::LIBNL_GENL3
        PkgConfig::SYSTEMD
        PkgConfig::OPENSSL
        PkgConfig::KEYUTILS
)

install(TARGETS ums_agent
    DESTINATION /usr/sbin
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/systemd/ums_agent.service
    DESTINATION /usr/lib/systemd/system
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

install(DIRECTORY DESTINATION /etc/ums_agent
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config/ums_agent/ums_agent.conf
    DESTINATION /etc/ums_agent
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config/rsyslog.d/ums_agent.conf
    DESTINATION /etc/rsyslog.d
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/config/logrotate.d/ums_agent
    DESTINATION /etc/logrotate.d
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
