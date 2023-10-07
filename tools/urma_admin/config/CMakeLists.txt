install(FILES "${CMAKE_SOURCE_DIR}/tools/urma_admin/config/urma_admin.conf"
    DESTINATION /etc/rsyslog.d/
    PERMISSIONS OWNER_WRITE OWNER_READ)