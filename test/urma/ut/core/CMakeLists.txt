# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

add_executable(urma_core_ut
    core_mock.cpp
    options_log_perf_test.cpp
    cmd_wrapper_test.cpp
    cp_api_test.cpp
    dp_main_device_test.cpp
)
target_link_options(urma_core_ut PRIVATE -Wl,--wrap=ioctl -Wl,--wrap=stat -Wl,--wrap=realpath
    -Wl,--wrap=opendir -Wl,--wrap=dladdr -Wl,--wrap=dlopen -Wl,--wrap=dlclose)
target_link_libraries(urma_core_ut PRIVATE urma_test_common ${URMA_STATIC} ${URMA_COMMON_STATIC}
    GTest::gtest_main dl rt pthread)

add_test(NAME urma_core_ut COMMAND urma_core_ut)
set_tests_properties(urma_core_ut PROPERTIES LABELS phase_core)
