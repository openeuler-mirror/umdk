file(GLOB URMA_COMMON_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/ub_*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/urma_*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/compiler.h"
    )
if(NOT "${PERF_CYCLE}" STREQUAL "enable")
    list(REMOVE_ITEM URMA_COMMON_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ub_perf_cycle.h")
endif(NOT "${PERF_CYCLE}" STREQUAL "enable")

if("${URMA_INSTALL}" STREQUAL "enable")
    install(DIRECTORY DESTINATION /usr/include/umdk/common)
    install(FILES ${URMA_COMMON_FILE} DESTINATION /usr/include/umdk/common/)
endif()