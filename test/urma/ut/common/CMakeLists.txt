# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.

add_executable(urma_common_ut
    common_mock.cpp
    bitmap_hash_hmap_test.cpp
    dstring_test.cpp
    util_clock_test.cpp
)
target_link_options(urma_common_ut PRIVATE -Wl,--wrap=calloc -Wl,--wrap=gettimeofday
    -Wl,--wrap=fopen -Wl,--wrap=fgets -Wl,--wrap=fclose)
target_link_libraries(urma_common_ut PRIVATE urma_test_common ${URMA_COMMON_STATIC} GTest::gtest_main)

add_test(NAME urma_common_ut COMMAND urma_common_ut)
set_tests_properties(urma_common_ut PROPERTIES LABELS phase_common)
