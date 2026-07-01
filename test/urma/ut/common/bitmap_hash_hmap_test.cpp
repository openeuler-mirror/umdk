/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bitmap, hash and hmap unit tests.
 */

#include "common_fixture.h"

using namespace urma_test_common;

TEST(UrmaCommonTest, BitmapSetScanAndEqual)
{
    const size_t bitNum = UB_ULONG_BITS + 5;
    unsigned long *bitmap = ub_bitmap_alloc(bitNum);
    unsigned long *clone = nullptr;

    ASSERT_NE(nullptr, bitmap);
    EXPECT_EQ(bitNum, ub_bitmap_scan(bitmap, true, 0, bitNum));

    /* Cross a word boundary so scan/equal paths cover both first and second words. */
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
    EXPECT_EQ(nullptr, ub_hmap_next_with_hash(node, 0x12));
    EXPECT_NE(nullptr, ub_hmap_first(&hmap));
    EXPECT_NE(nullptr, ub_hmap_next(&hmap, &second.node));

    ub_hmap_remove(&hmap, &absent.node);
    EXPECT_EQ(3U, ub_hmap_count(&hmap));

    /* The first two nodes intentionally share a hash to exercise bucket collision links. */
    ub_hmap_remove(&hmap, &second.node);
    EXPECT_EQ(2U, ub_hmap_count(&hmap));
    ub_hmap_remove(&hmap, &first.node);
    ub_hmap_remove(&hmap, &third.node);
    EXPECT_EQ(0U, ub_hmap_count(&hmap));

    ub_hmap_destroy(&hmap);
    EXPECT_EQ(nullptr, hmap.bucket);
}
