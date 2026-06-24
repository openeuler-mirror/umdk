# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

add_executable(urma_cmd_tlv_ut
    cmd_tlv_mock.cpp
    attr_layout_test.cpp
    wrapper_header_test.cpp
    high_level_cmd_test.cpp
)
target_link_options(urma_cmd_tlv_ut PRIVATE -Wl,--wrap=ioctl -Wl,--wrap=urma_query_eid)
target_link_libraries(urma_cmd_tlv_ut PRIVATE urma_test_common ${URMA_STATIC} ${URMA_COMMON_STATIC}
    GTest::gtest_main dl rt pthread)

add_test(NAME urma_cmd_tlv_ut COMMAND urma_cmd_tlv_ut)
set_tests_properties(urma_cmd_tlv_ut PROPERTIES LABELS phase_cmd_tlv)
