file(GLOB UVS_API_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/uvs_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/uvs_types.h"
    )

if("${URMA_INSTALL}" STREQUAL "enable")
    install(DIRECTORY DESTINATION /usr/include/umdk)
    install(FILES ${UVS_API_FILE} DESTINATION /usr/include/umdk)
endif()