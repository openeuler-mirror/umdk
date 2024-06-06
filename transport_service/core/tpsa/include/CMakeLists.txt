if("${URMA_INSTALL}" STREQUAL "enable")
    install(DIRECTORY DESTINATION /usr/include/umdk)
    install(FILES ${UVS_API_FILE} DESTINATION /usr/include/umdk)
endif()
