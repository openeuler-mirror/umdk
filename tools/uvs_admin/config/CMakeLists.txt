install(FILES "${CMAKE_SOURCE_DIR}/tools/uvs_admin/config/uvs_admin.conf"
    DESTINATION /etc/rsyslog.d/
    PERMISSIONS OWNER_WRITE OWNER_READ)