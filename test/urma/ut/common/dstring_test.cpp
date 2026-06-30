/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA dynamic string unit tests.
 */

#include "common_fixture.h"

using namespace urma_test_common;

TEST(UrmaCommonTest, DynamicStringCoversMutationAndOwnership)
{
    struct dstring dstr = DSTRING_INITIALIZER;

    EXPECT_EQ(0U, dstring_get_len(nullptr));
    dstring_reset(nullptr);
    dstring_clear(nullptr);
    dstring_truncate(nullptr, 0);
    dstring_destroy(nullptr);
    EXPECT_EQ(nullptr, dstring_push_buf(nullptr, 1));
    EXPECT_EQ(-1, dstring_put_cstring(nullptr, "x"));
    EXPECT_EQ(-1, dstring_put_cstring(&dstr, nullptr));
    dstring_put_char(nullptr, 'x');
    EXPECT_EQ(nullptr, dstring_to_cstring(nullptr));
    EXPECT_FALSE(dstring_chomp(nullptr, '\n'));

    ASSERT_NE(nullptr, dstring_push_buf(&dstr, 3));
    std::memcpy(dstr.string, "abc", 3);
    EXPECT_STREQ("abc", dstring_to_cstring(&dstr));
    EXPECT_EQ(3U, dstring_get_len(&dstr));

    dstring_put_char(&dstr, 'd');
    EXPECT_EQ(0, dstring_put_cstring(&dstr, "ef"));
    dstring_printf(&dstr, "-%u-%s", 7U, "tail");
    EXPECT_STREQ("abcdef-7-tail", dstring_to_cstring(&dstr));

    EXPECT_TRUE(dstring_chomp(&dstr, 'l'));
    EXPECT_FALSE(dstring_chomp(&dstr, 'z'));
    dstring_truncate(&dstr, 4);
    EXPECT_STREQ("abcd", dstring_to_cstring(&dstr));
    dstring_clear(&dstr);
    EXPECT_EQ(0U, dstring_get_len(&dstr));
    EXPECT_STREQ("", dstring_to_cstring(&dstr));

    dstring_put_cstring(&dstr, "owned");
    /* pealing transfers buffer ownership to the caller and resets the dstring. */
    char *owned = dstring_pealing(&dstr);
    ASSERT_NE(nullptr, owned);
    EXPECT_STREQ("owned", owned);
    EXPECT_EQ(0U, dstring_get_len(&dstr));
    std::free(owned);

    dstring_destroy(&dstr);
}
