file(GLOB URMA_API_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/urma_*.h"
    "ub_errno.h"
    )
install(DIRECTORY DESTINATION /usr/include/umdk)
install(FILES ${URMA_API_FILE} DESTINATION /usr/include/umdk)

add_subdirectory(common)