install(FILES "${CMAKE_SOURCE_DIR}/lib/urma/config/urma.conf"
    DESTINATION /etc/rsyslog.d/
    PERMISSIONS OWNER_WRITE OWNER_READ)
install(FILES "${CMAKE_SOURCE_DIR}/lib/urma/config/urma"
    DESTINATION /etc/logrotate.d/
    PERMISSIONS OWNER_WRITE OWNER_READ)