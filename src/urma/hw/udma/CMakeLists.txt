aux_source_directory(${CMAKE_CURRENT_LIST_DIR} PROVIDER_UB_DIR_SRCS)

add_library(BETA_UDMA_SO SHARED ${PROVIDER_UB_DIR_SRCS})

# ST64B DISABLE
if("${UDMA_ST64B}" STREQUAL "enable")
    add_definitions(-DST64B)
    message(STATUS "SUPPORT ST64B!")
endif()

file(GLOB UDMA_API_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/include/udma_u_ctl.h"
    )

install(DIRECTORY DESTINATION /usr/include/ub/umdk/urma/udma)
install(FILES ${UDMA_API_FILE} DESTINATION /usr/include/ub/umdk/urma/udma)

target_include_directories(BETA_UDMA_SO PRIVATE ${CMAKE_SOURCE_DIR}/urma/lib/urma/core)
target_include_directories(BETA_UDMA_SO PRIVATE ${CMAKE_SOURCE_DIR}/urma/lib/urma/core/include)
target_include_directories(BETA_UDMA_SO PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/kernel_headers)
target_include_directories(BETA_UDMA_SO PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(BETA_UDMA_SO PRIVATE urma)
target_link_libraries(BETA_UDMA_SO PRIVATE urma_common)
target_link_libraries(BETA_UDMA_SO PRIVATE ummu)

set(UDMA_NAME urma-udma)
set_target_properties(BETA_UDMA_SO PROPERTIES OUTPUT_NAME ${UDMA_NAME})

set(CMAKE_C_FLAGS "-Wall -Wextra -O2 -Wfloat-equal -fno-common -std=gnu99 -Werror=implicit-function-declaration")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,now -s -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -ftrapv")
set(CMAKE_LD_FLAGS "-s")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wuninitialized -Wno-error -Wno-error=format -Wundef")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wdate-time -Wshadow -Wvla -Wdisabled-optimization")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wempty-body -Wignored-qualifiers -Wimplicit-fallthrough=3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wtype-limits -Wshift-negative-value -Wswitch-default")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wframe-larger-than=8192 -Wshift-overflow=2 -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-format-attribute -Wformat-nonliteral -Wduplicated-cond")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wtrampolines -Wlogical-op -Wsuggest-attribute=format")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wduplicated-branches -Wmissing-include-dirs -Wformat-signedness")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wreturn-local-addr -Wredundant-decls")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfloat-conversion -Wmissing-prototypes -Wstrict-prototypes")

include(GNUInstallDirs)
install(TARGETS BETA_UDMA_SO LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/urma OPTIONAL)
