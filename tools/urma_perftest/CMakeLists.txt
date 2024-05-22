find_package(GLIB REQUIRED COMPONENTS)
include_directories(${GLIB_INCLUDE_DIRS})

add_executable(urma_perftest
    urma_perftest.c
    perftest_parameters.c
    perftest_communication.c
    perftest_resources.c
    perftest_run_test.c
)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/common)
target_link_libraries(urma_perftest urma glib-2.0 pthread m)

if(CROSS_COMPILE)
    target_link_libraries(urma_perftest pcre2-8 ffi)
endif()

set_target_properties(urma_perftest PROPERTIES C_STANDARD 99)
if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS urma_perftest DESTINATION /usr/bin)
endif()
