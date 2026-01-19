####################
# HFA library tests
####################

set(GTEST_INCLUDE_DIRS /root/.local/include/gtest)
set(GTEST_LIBRARIES /root/.local/lib/gtest/libgtest.a /root/.local/lib/gtest/libgtest_main.a)
option(ENABLE_GTEST "Enable Google Test" ON)
add_compile_options(-fPIC)

################
# avm_test test
################
add_executable(avm_test
                ./avm_test.cpp
                ${CMAKE_SOURCE_DIR}/src/acl_virtual_memory.cpp)

target_include_directories(avm_test PRIVATE
                $ENV{ASCEND_HOME_PATH}/include
                ${CMAKE_SOURCE_DIR}/include
                ${CMAKE_SOURCE_DIR}/src)

target_link_directories(avm_test PRIVATE
                ${ASCEND_COMMON_LIBS})

target_link_libraries(avm_test PUBLIC
                $ENV{ASCEND_TOOLKIT_HOME}/lib64/libascendcl.so
                -lrt
                -pthread
                hfa)

###################
# chunk props test
###################
add_executable(chunk_props_test
                ./chunk_props_test.cpp)

target_include_directories(chunk_props_test PRIVATE
                $ENV{ASCEND_HOME_PATH}/include
                ${CMAKE_SOURCE_DIR}/include
                ${CMAKE_SOURCE_DIR}/src)

target_link_directories(chunk_props_test PRIVATE
                ${ASCEND_COMMON_LIBS})

target_link_libraries(chunk_props_test PUBLIC
                hfa)

#################################
# aclrtMalloc() utilization test
#################################
add_executable(aclrt_util_test
                ./aclrt_utilization.cpp)

target_include_directories(aclrt_util_test PRIVATE
                $ENV{ASCEND_HOME_PATH}/include
                ${CMAKE_SOURCE_DIR}/include
                ${CMAKE_SOURCE_DIR}/src)

target_link_directories(aclrt_util_test PRIVATE
                ${ASCEND_COMMON_LIBS})

target_link_libraries(aclrt_util_test PUBLIC
                $ENV{ASCEND_TOOLKIT_HOME}/lib64/libascendcl.so
                -lrt
                -pthread
                -lsecurec)

#####################################################
# Performance test for aclrtMalloc() and aclrtFree()
#####################################################
add_executable(aclrt_alloc_test
                ./aclrt_alloc_test.cpp)

target_include_directories(aclrt_alloc_test PRIVATE
                $ENV{ASCEND_HOME_PATH}/include
                ${CMAKE_SOURCE_DIR}/include
                ${CMAKE_SOURCE_DIR}/src)

target_link_directories(aclrt_alloc_test PRIVATE
                ${ASCEND_COMMON_LIBS})

target_link_libraries(aclrt_alloc_test PUBLIC
                $ENV{ASCEND_TOOLKIT_HOME}/lib64/libascendcl.so
                -lrt
                -pthread
                -lsecurec)

####################################################
# gtest: realloc, fragmentation, HbmFastAlloc tests
####################################################
if(ENABLE_GTEST)
    add_executable(gtest
                    ./test_utils.cpp
                    ./gtest_main.cpp
                    ./realloc_test.cpp
                    ./fragmentation_test.cpp
                    ./hfa_mem_usage_test.cpp
                    ./aclrt_mem_usage_test.cpp
                    ./hfa_init_uninit_test.cpp
                    ./hfa_perf_test.cpp)

    target_include_directories(gtest PRIVATE
                    $ENV{ASCEND_HOME_PATH}/include
                    ${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_SOURCE_DIR}/src
                    ${GTEST_INCLUDE_DIRS})

    target_link_directories(gtest PRIVATE
                    /usr/local/Ascend/driver/lib64/common)


    target_link_libraries(gtest PUBLIC
                    hfa
                    ${GTEST_LIBRARIES})
endif()
