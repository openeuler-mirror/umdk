file(GLOB URMA_API_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/urma_*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/ub_errno.h"
    )

if("${URMA_INSTALL}" STREQUAL "enable")
    install(DIRECTORY DESTINATION /usr/include/umdk)
    install(FILES ${URMA_API_FILE} DESTINATION /usr/include/umdk)
endif()

add_subdirectory(common)