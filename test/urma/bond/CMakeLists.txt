# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

add_executable(urma_bond_ut
    bond_test.cpp
    wr_slide_test.cpp
)
target_link_libraries(urma_bond_ut PRIVATE urma_test_common ${URMA_UBAGG_SO} ${URMA_SO} ${URMA_COMMON_SO}
    GTest::gtest_main nl-genl-3 nl-3 dl rt pthread)

add_test(NAME urma_bond_ut COMMAND urma_bond_ut)
set_tests_properties(urma_bond_ut PROPERTIES LABELS phase_bond)
