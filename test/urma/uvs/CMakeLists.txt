# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

add_executable(urma_uvs_ut
    uvs_mock.cpp
    tlv_ioctl_test.cpp
    public_api_test.cpp
    topo_helper_test.cpp
)
target_link_libraries(urma_uvs_ut PRIVATE urma_test_common ${URMA_TPSA_SO} ${URMA_COMMON_SO}
    GTest::gtest_main nl-genl-3 nl-3 dl rt pthread)

add_test(NAME urma_uvs_ut COMMAND urma_uvs_ut)
set_tests_properties(urma_uvs_ut PROPERTIES LABELS phase_uvs)
