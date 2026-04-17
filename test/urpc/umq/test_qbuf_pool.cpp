/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: qbuf pool unit tests
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include <cstring>

#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_types.h"

class QbufPoolTest : public ::testing::Test {
  public:
    void SetUp() override
    {
        (void)umq_buf_size_pow_small_set(BLOCK_SIZE_8K);
    }

    void TearDown() override
    {
        umq_io_buf_free();
        GlobalMockObject::verify();
    }
};

static uint64_t CalcSplitTotalSize(uint32_t blk_size, uint32_t blk_num)
{
    return static_cast<uint64_t>(blk_num) *
        ((UMQ_EMPTY_HEADER_COEFFICIENT + 1) * static_cast<uint32_t>(sizeof(umq_buf_t)) + blk_size);
}

TEST_F(QbufPoolTest, test_umq_buf_size_pow_small_set_invalid)
{
    // Invalid block size should fail.
    ASSERT_NE(umq_buf_size_pow_small_set(BLOCK_SIZE_MAX), UMQ_SUCCESS);
}

TEST_F(QbufPoolTest, test_umq_buf_size_pow_small_set_valid)
{
    // Valid block sizes should update small block size.
    ASSERT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_8K), UMQ_SUCCESS);
    ASSERT_EQ(umq_buf_size_small(), (1u << UMQ_QBUF_SIZE_POW_8K));

    ASSERT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_16K), UMQ_SUCCESS);
    ASSERT_EQ(umq_buf_size_small(), (1u << UMQ_QBUF_SIZE_POW_16K));

    ASSERT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_32K), UMQ_SUCCESS);
    ASSERT_EQ(umq_buf_size_small(), (1u << UMQ_QBUF_SIZE_POW_32K));

    ASSERT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_64K), UMQ_SUCCESS);
    ASSERT_EQ(umq_buf_size_small(), (1u << UMQ_QBUF_SIZE_POW_64K));
}

TEST_F(QbufPoolTest, test_qbuf_pool_init_invalid_mode)
{
    // Invalid mode should fail init.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = static_cast<uint64_t>(blk_size) * 2;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = static_cast<umq_buf_mode_t>(99);
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_COMBINE, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_NE(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);
}

TEST_F(QbufPoolTest, test_qbuf_pool_double_init)
{
    // Double init should be rejected.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = static_cast<uint64_t>(blk_size) * 2;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_COMBINE;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_COMBINE, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);
    ASSERT_NE(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    umq_qbuf_pool_uninit();
}

TEST_F(QbufPoolTest, test_qbuf_pool_combine_alloc_free)
{
    // Combine mode alloc/free path and info query.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = static_cast<uint64_t>(blk_size) * 1024;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_COMBINE;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_COMBINE, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    ASSERT_EQ(umq_qbuf_alloc(1024, 1, nullptr, &list), UMQ_SUCCESS);
    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_NE(qbuf->buf_data, nullptr);
    ASSERT_EQ(qbuf->headroom_size, 0);
    ASSERT_EQ(qbuf->first_fragment, 1);

    umq_buf_t *head = umq_qbuf_data_to_head(qbuf->buf_data);
    ASSERT_EQ(head, qbuf);

    ASSERT_EQ(umq_qbuf_headroom_reset(qbuf, 128), UMQ_SUCCESS);
    ASSERT_EQ(qbuf->headroom_size, 128);

    umq_qbuf_free(&list);

    umq_qbuf_pool_stats_t qbuf_pool_stats;
    memset(&qbuf_pool_stats, 0, sizeof(qbuf_pool_stats));

    ASSERT_EQ(umq_qbuf_pool_info_get(&qbuf_pool_stats), UMQ_SUCCESS);
    ASSERT_EQ(qbuf_pool_stats.qbuf_pool_info[0].mode, UMQ_BUF_COMBINE);

    umq_qbuf_pool_uninit();
}

TEST_F(QbufPoolTest, test_qbuf_pool_split_alloc_zero)
{
    // Split mode zero-size allocation path.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = CalcSplitTotalSize(blk_size, 1024);

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_SPLIT, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 16;
    ASSERT_NE(umq_qbuf_alloc(0, 1, &opt, &list), UMQ_SUCCESS);

    ASSERT_EQ(umq_qbuf_alloc(0, 2, nullptr, &list), UMQ_SUCCESS);
    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_EQ(qbuf->data_size, 0);

    umq_qbuf_free(&list);

    umq_qbuf_pool_uninit();
}

TEST_F(QbufPoolTest, test_qbuf_pool_split_alloc_with_data)
{
    // Split mode data allocation should fill headroom/data and link fragments if needed.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = CalcSplitTotalSize(blk_size, 1024);

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 64;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_SPLIT, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    // Request larger than one block to force multiple fragments.
    uint32_t request_size = blk_size + 128;
    ASSERT_EQ(umq_qbuf_alloc(request_size, 1, nullptr, &list), UMQ_SUCCESS);

    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_EQ(qbuf->first_fragment, 1);
    ASSERT_EQ(qbuf->headroom_size, cfg.headroom_size);
    ASSERT_NE(qbuf->qbuf_next, nullptr);

    umq_qbuf_free(&list);

    umq_qbuf_pool_uninit();
}

TEST_F(QbufPoolTest, test_qbuf_pool_return_to_global)
{
    // Freeing a large batch should trigger return_to_global in TLS cache.
    constexpr uint32_t kQbufPoolTlsMax = 2048;
    constexpr uint32_t kQbufPoolBatchCnt = 512;
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = CalcSplitTotalSize(blk_size, 4096);

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_SPLIT, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    uint32_t num = kQbufPoolTlsMax + kQbufPoolBatchCnt + 1;
    ASSERT_EQ(umq_qbuf_alloc(128, num, nullptr, &list), UMQ_SUCCESS);

    umq_qbuf_free(&list);

    umq_qbuf_pool_uninit();
}

TEST_F(QbufPoolTest, test_qbuf_alloc_errors_not_inited)
{
    // Not initialized paths should fail.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_NE(umq_qbuf_alloc(128, 1, nullptr, &list), UMQ_SUCCESS);
    ASSERT_EQ(umq_qbuf_data_to_head(nullptr), nullptr);
    ASSERT_NE(umq_qbuf_headroom_reset(nullptr, 0), UMQ_SUCCESS);
}

TEST_F(QbufPoolTest, test_qbuf_alloc_zero_in_combine)
{
    // Combine mode should reject zero-size alloc.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = static_cast<uint64_t>(blk_size) * 2;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_COMBINE;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_COMBINE, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_NE(umq_qbuf_alloc(0, 1, nullptr, &list), UMQ_SUCCESS);

    umq_qbuf_pool_uninit();
}

TEST_F(QbufPoolTest, test_qbuf_data_to_head_out_of_range)
{
    // Data pointer outside pool should return null.
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = static_cast<uint64_t>(blk_size) * 2;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = UMQ_BUF_COMBINE;
    cfg.total_size = total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.buf_addr = umq_io_buf_malloc(UMQ_BUF_COMBINE, total_size);
    cfg.disable_scale_cap = true;

    ASSERT_NE(cfg.buf_addr, nullptr);
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), UMQ_SUCCESS);

    char dummy[16];
    ASSERT_EQ(umq_qbuf_data_to_head(dummy), nullptr);

    umq_qbuf_pool_uninit();
}
