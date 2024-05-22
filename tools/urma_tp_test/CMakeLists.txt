find_package(GLIB REQUIRED COMPONENTS)
include_directories(${GLIB_INCLUDE_DIRS})

add_executable(urma_tp_test
    urma_tp_test.c
    tp_test_para.c
    tp_test_res.c
    tp_test_comm.c
    run_test.c
)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/include/common)

target_link_libraries(urma_tp_test urma glib-2.0 pthread m)

if(CROSS_COMPILE)
    target_link_libraries(urma_tp_test pcre2-8 ffi)
endif()

if("${FUZZ}" STREQUAL "enable")
target_link_libraries(urma_tp_test /usr/local/lib64/libSecodefuzz.a)
endif("${FUZZ}" STREQUAL "enable")

set_target_properties(urma_tp_test PROPERTIES C_STANDARD 99)
if("${URMA_INSTALL}" STREQUAL "enable")
    install(TARGETS urma_tp_test DESTINATION /usr/bin)
endif()
