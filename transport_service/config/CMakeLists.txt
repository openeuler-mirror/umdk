install(FILES "${CMAKE_SOURCE_DIR}/transport_service/config/tpsa.conf"
        DESTINATION /etc/rsyslog.d/
        PERMISSIONS OWNER_WRITE OWNER_READ)

install(DIRECTORY DESTINATION /etc/tpsa)
install(FILES "${CMAKE_SOURCE_DIR}/transport_service/config/tpsa.ini" DESTINATION /etc/tpsa/)
install(FILES "${CMAKE_SOURCE_DIR}/transport_service/config/tpsa"
        DESTINATION /etc/logrotate.d/)

install(FILES "${CMAKE_SOURCE_DIR}/transport_service/config/uvsd.service"
        DESTINATION /usr/lib/systemd/system/
        PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
