/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA common unit tests.
 */

#include <cerrno>
#include <climits>
#include <cstring>
#include <cstdlib>

#include <gtest/gtest.h>

#include "ub_bitmap.h"
#include "ub_dstring.h"
#include "ub_hash.h"
#include "ub_hmap.h"
#include "ub_util.h"

TEST(UrmaCommonTest, BitmapSetScanAndEqual)
{
    const size_t bitNum = UB_ULONG_BITS + 5;
    unsigned long *bitmap = ub_bitmap_alloc(bitNum);
    unsigned long *clone = nullptr;

    ASSERT_NE(nullptr, bitmap);
    EXPECT_EQ(bitNum, ub_bitmap_scan(bitmap, true, 0, bitNum));

    ub_bitmap_set1(bitmap, 3);
    ub_bitmap_set1(bitmap, UB_ULONG_BITS + 1);
    EXPECT_TRUE(ub_bitmap_is_set(bitmap, 3));
    EXPECT_TRUE(ub_bitmap_is_set(bitmap, UB_ULONG_BITS + 1));
    EXPECT_EQ(static_cast<size_t>(3), ub_bitmap_scan(bitmap, true, 0, bitNum));
    EXPECT_EQ(UB_ULONG_BITS + 1, ub_bitmap_scan(bitmap, true, 4, bitNum));

    clone = ub_bitmap_clone(bitmap, bitNum);
    ASSERT_NE(nullptr, clone);
    EXPECT_TRUE(ub_bitmap_equal(bitmap, clone, bitNum));

    ub_bitmap_set0(clone, 3);
    EXPECT_FALSE(ub_bitmap_equal(bitmap, clone, bitNum));

    ub_bitmap_free(clone);
    ub_bitmap_free(bitmap);
}

TEST(UrmaCommonTest, BitmapAllocOneMasksUnusedBits)
{
    const size_t bitNum = UB_ULONG_BITS + 3;
    unsigned long *bitmap = ub_bitmap_alloc_1(bitNum);

    ASSERT_NE(nullptr, bitmap);
    EXPECT_EQ(bitNum, ub_bitmap_scan(bitmap, false, 0, bitNum));
    EXPECT_EQ(bitNum, ub_bitmap_scan(bitmap, true, bitNum, bitNum));
    EXPECT_TRUE(ub_bitmap_is_set(bitmap, UB_ULONG_BITS + 2));
    EXPECT_FALSE(ub_bitmap_is_set(bitmap, UB_ULONG_BITS + 3));

    ub_bitmap_free(bitmap);
}

TEST(UrmaCommonTest, HashBytesMatchesStringHash)
{
    const char *value = "urma-hash";
    uint32_t bytesHash = ub_hash_bytes(value, static_cast<uint32_t>(std::strlen(value)), 0);
    uint32_t stringHash = ub_hash_string(value, 0);

    EXPECT_EQ(stringHash, bytesHash);
    EXPECT_NE(bytesHash, ub_hash_string("urma_hash", 0));
}

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
    char *owned = dstring_pealing(&dstr);
    ASSERT_NE(nullptr, owned);
    EXPECT_STREQ("owned", owned);
    EXPECT_EQ(0U, dstring_get_len(&dstr));
    std::free(owned);

    dstring_destroy(&dstr);
}

struct HmapTestNode {
    int key;
    ub_hmap_node node;
};

TEST(UrmaCommonTest, HmapInsertFindIterateAndRemove)
{
    ub_hmap hmap = {};
    HmapTestNode first = { 1, {} };
    HmapTestNode second = { 2, {} };
    HmapTestNode third = { 3, {} };
    HmapTestNode absent = { 4, {} };
    ub_hmap_node *node = nullptr;

    ASSERT_EQ(0, ub_hmap_init(&hmap, 4));
    EXPECT_EQ(0U, ub_hmap_count(&hmap));
    EXPECT_EQ(nullptr, ub_hmap_first(nullptr));
    EXPECT_EQ(nullptr, ub_hmap_first_with_hash(nullptr, 1));
    EXPECT_EQ(nullptr, ub_hmap_next(nullptr, nullptr));
    EXPECT_EQ(nullptr, ub_hmap_next_with_hash(nullptr, 1));

    ub_hmap_insert(&hmap, &first.node, 0x10);
    ub_hmap_insert(&hmap, &second.node, 0x10);
    ub_hmap_insert(&hmap, &third.node, 0x11);
    EXPECT_EQ(3U, ub_hmap_count(&hmap));

    node = ub_hmap_first_with_hash(&hmap, 0x10);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(0x10U, node->hash);
    EXPECT_NE(nullptr, ub_hmap_next_with_hash(node, 0x10));
    EXPECT_NE(nullptr, ub_hmap_first(&hmap));
    EXPECT_NE(nullptr, ub_hmap_next(&hmap, &second.node));

    ub_hmap_remove(&hmap, &absent.node);
    EXPECT_EQ(3U, ub_hmap_count(&hmap));
    ub_hmap_remove(&hmap, &second.node);
    EXPECT_EQ(2U, ub_hmap_count(&hmap));
    ub_hmap_remove(&hmap, &first.node);
    ub_hmap_remove(&hmap, &third.node);
    EXPECT_EQ(0U, ub_hmap_count(&hmap));

    ub_hmap_destroy(&hmap);
    EXPECT_EQ(nullptr, hmap.bucket);
}

TEST(UrmaCommonTest, UtilBitSearchCoversSetAndZeroPaths)
{
    unsigned long bits[3] = {};

    EXPECT_EQ(0U, ub_find_first_bit(bits, 0));
    EXPECT_EQ(130U, ub_find_first_bit(bits, 130));
    EXPECT_EQ(0U, ub_find_first_zero_bit(bits, 130));
    EXPECT_EQ(130U, ub_find_next_bit(bits, 130, 130));

    bits[0] = ~0UL;
    bits[1] = 0;
    bits[2] = 1UL << 1;
    EXPECT_EQ(64U, ub_find_first_zero_bit(bits, 130));
    EXPECT_EQ(0U, ub_find_first_bit(bits, 130));
    EXPECT_EQ(129U, ub_find_next_bit(bits, 130, 64));
    EXPECT_EQ(65U, ub_find_next_zero_bit(bits, 130, 65));

    bits[1] = ~0UL;
    bits[2] = ~0UL;
    EXPECT_EQ(130U, ub_find_first_zero_bit(bits, 130));
    EXPECT_EQ(130U, ub_find_next_zero_bit(bits, 130, 130));
}

TEST(UrmaCommonTest, UtilLargeMemAndHugePageBoundaries)
{
    uint8_t dst[8] = {};
    uint8_t src[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

    EXPECT_EQ(0, memset_s_large_buf(dst, sizeof(dst), 0xab, 4));
    EXPECT_EQ(0xab, dst[0]);
    EXPECT_EQ(0xab, dst[3]);
    EXPECT_EQ(0, memset_s_large_buf(dst, sizeof(dst), 0, 0));
    EXPECT_EQ(0, memcpy_s_large_buf(dst, sizeof(dst), src, sizeof(src)));
    EXPECT_EQ(0, std::memcmp(dst, src, sizeof(src)));
    EXPECT_EQ(0, memcpy_s_large_buf(dst, sizeof(dst), src, 0));

    EXPECT_EQ(nullptr, ub_hugemalloc(0, UB_HUGE_PAGE_SIZE_ANY, nullptr));
    EXPECT_EQ(-EINVAL, ub_hugefree(nullptr, 4096));
}

TEST(UrmaCommonTest, UtilStringConversionsAcceptValidAndRejectInvalid)
{
    bool boolValue = false;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;
    int intValue = 0;

    EXPECT_EQ(0, ub_str_to_bool("true", &boolValue));
    EXPECT_TRUE(boolValue);
    EXPECT_EQ(0, ub_str_to_bool("false", &boolValue));
    EXPECT_FALSE(boolValue);
    EXPECT_EQ(-EINVAL, ub_str_to_bool(nullptr, &boolValue));
    EXPECT_EQ(-EINVAL, ub_str_to_bool("", &boolValue));
    EXPECT_EQ(-EINVAL, ub_str_to_bool("yes", &boolValue));

    EXPECT_EQ(0, ub_str_to_u8("255", &u8));
    EXPECT_EQ(255U, u8);
    EXPECT_EQ(-EINVAL, ub_str_to_u8(nullptr, &u8));
    EXPECT_EQ(-EINVAL, ub_str_to_u8("-1", &u8));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u8("12x", &u8));
    EXPECT_EQ(-ERANGE, ub_str_to_u8("256", &u8));

    EXPECT_EQ(0, ub_str_to_u16("65535", &u16));
    EXPECT_EQ(65535U, u16);
    EXPECT_EQ(-ERANGE, ub_str_to_u16("65536", &u16));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u16("x", &u16));

    EXPECT_EQ(0, ub_str_to_u32("4294967295", &u32));
    EXPECT_EQ(UINT_MAX, u32);
    EXPECT_EQ(-ERANGE, ub_str_to_u32("4294967296", &u32));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u32("x", &u32));

    EXPECT_EQ(0, ub_str_to_u64("18446744073709551615", &u64));
    EXPECT_EQ(UINT64_MAX, u64);
    EXPECT_EQ(-EINVAL, ub_str_to_u64("-1", &u64));
    EXPECT_EQ(-ENOEXEC, ub_str_to_u64("x", &u64));

    EXPECT_EQ(0, ub_str_to_int("-12", &intValue));
    EXPECT_EQ(-12, intValue);
    EXPECT_EQ(-EINVAL, ub_str_to_int(nullptr, &intValue));
    EXPECT_EQ(-ENOEXEC, ub_str_to_int("1x", &intValue));
    EXPECT_EQ(-ERANGE, ub_str_to_int("2147483648", &intValue));
}
