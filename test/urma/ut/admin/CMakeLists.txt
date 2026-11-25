# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

add_executable(urma_admin_layout_ut
    admin_cmd_perf_layout_test.cpp
)
target_include_directories(urma_admin_layout_ut PRIVATE
    ${URMA_SRC_DIR}/tools/urma_admin
)
target_link_libraries(urma_admin_layout_ut PRIVATE
    urma_test_common
    GTest::gtest_main
)

add_test(NAME urma_admin_layout_ut COMMAND urma_admin_layout_ut)
set_tests_properties(urma_admin_layout_ut PROPERTIES LABELS phase_admin)
