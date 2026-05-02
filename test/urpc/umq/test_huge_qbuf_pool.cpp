/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: huge qbuf pool unit tests
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include <cstring>
#include <malloc.h>
#include <vector>

#include "umq_errno.h"
#include "umq_huge_qbuf_pool.h"
#include "umq_qbuf_pool.h"
#include "umq_ub_private.h"

static uint64_t g_huge_pool_total_size = 0;
static uint64_t g_huge_pool_total_size_by_type[HUGE_QBUF_POOL_SIZE_TYPE_MAX] = {0};
static std::vector<void *> g_huge_allocated;
static int g_register_cnt = 0;
static int g_unregister_cnt = 0;

static int HugeMemInit(uint16_t mempool_id __attribute__((unused)),
                       huge_qbuf_pool_size_type_t type,
                       void **buf_addr)
{
    uint64_t alloc_size = g_huge_pool_total_size_by_type[type] != 0 ?
        g_huge_pool_total_size_by_type[type] : g_huge_pool_total_size;
    void *ptr = memalign(umq_buf_size_small(), alloc_size);
    if (ptr == nullptr) {
        return -UMQ_ERR_ENOMEM;
    }
    *buf_addr = ptr;
    g_huge_allocated.push_back(ptr);
    return UMQ_SUCCESS;
}

static void HugeMemUninit(uint16_t mempool_id __attribute__((unused)), void *buf_addr)
{
    if (buf_addr != nullptr) {
        free(buf_addr);
    }
}

static int RegisterSeg(uint8_t *ctx __attribute__((unused)),
                       uint16_t mempool_id __attribute__((unused)),
                       void *addr __attribute__((unused)),
                       uint64_t size __attribute__((unused)))
{
    g_register_cnt++;
    return UMQ_SUCCESS;
}

static int RegisterSegFail(uint8_t *ctx __attribute__((unused)),
                           uint16_t mempool_id __attribute__((unused)),
                           void *addr __attribute__((unused)),
                           uint64_t size __attribute__((unused)))
{
    return UMQ_FAIL;
}

static void UnregisterSeg(uint8_t *ctx __attribute__((unused)),
                         uint16_t mempool_id __attribute__((unused)))
{
    g_unregister_cnt++;
}

class HugeQbufPoolTest : public ::testing::Test {
  public:
    void TearDown() override
    {
        umq_huge_qbuf_pool_uninit();
        g_huge_allocated.clear();
        GlobalMockObject::verify();
    }
};

class HugeQbufPoolInitTest : public ::testing::Test {
  public:
    void SetUp() override
    {
        // Initialize all huge qbuf pool types to satisfy mempool_id mapping.
        huge_qbuf_pool_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.headroom_size = 0;
        cfg.mode = UMQ_BUF_COMBINE;
        cfg.memory_init_callback = HugeMemInit;
        cfg.memory_uninit_callback = HugeMemUninit;

        umq_huge_qbuf_pool_ctx_common_cfg_set(&cfg);

        for (int type = HUGE_QBUF_POOL_SIZE_TYPE_MID; type < HUGE_QBUF_POOL_SIZE_TYPE_MAX; ++type) {
            uint32_t blk_size = umq_huge_qbuf_get_size_by_type((huge_qbuf_pool_size_type_t)type);
            g_huge_pool_total_size_by_type[type] = static_cast<uint64_t>(blk_size) * 2;

            cfg.type = (huge_qbuf_pool_size_type_t)type;
            cfg.total_size = g_huge_pool_total_size_by_type[type];
            cfg.data_size = blk_size;
            ASSERT_EQ(umq_huge_qbuf_config_init(&cfg), UMQ_SUCCESS);
        }
    }

    void TearDown() override
    {
        umq_huge_qbuf_pool_uninit();
        g_huge_allocated.clear();
        GlobalMockObject::verify();
    }
};

TEST_F(HugeQbufPoolTest, test_huge_qbuf_config_init_invalid)
{
    // Invalid configs should fail.
    ASSERT_NE(umq_huge_qbuf_config_init(nullptr), UMQ_SUCCESS);

    huge_qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.mode = static_cast<umq_buf_mode_t>(99);
    cfg.type = HUGE_QBUF_POOL_SIZE_TYPE_MID;
    cfg.memory_init_callback = HugeMemInit;
    cfg.memory_uninit_callback = HugeMemUninit;
    ASSERT_NE(umq_huge_qbuf_config_init(&cfg), UMQ_SUCCESS);

    cfg.mode = UMQ_BUF_COMBINE;
    cfg.type = static_cast<huge_qbuf_pool_size_type_t>(99);
    ASSERT_NE(umq_huge_qbuf_config_init(&cfg), UMQ_SUCCESS);

    cfg.type = HUGE_QBUF_POOL_SIZE_TYPE_MID;
    cfg.memory_init_callback = nullptr;
    ASSERT_NE(umq_huge_qbuf_config_init(&cfg), UMQ_SUCCESS);
}

TEST_F(HugeQbufPoolInitTest, test_huge_qbuf_alloc_free_and_register)
{
    // Allocate, reset headroom, register/unregister segments.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_huge_qbuf_alloc(HUGE_QBUF_POOL_SIZE_TYPE_MID, 4096, 1, nullptr, &list), UMQ_SUCCESS);

    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_GT(qbuf->data_size, 0u);

    ASSERT_EQ(umq_huge_qbuf_headroom_reset(qbuf, 64), UMQ_SUCCESS);
    ASSERT_EQ(qbuf->headroom_size, 64);

    mempool_segment_ops_t ops;
    ops.register_seg_callback = RegisterSeg;
    ops.unregister_seg_callback = UnregisterSeg;
    ASSERT_EQ(umq_huge_qbuf_register_seg(nullptr, &ops), UMQ_SUCCESS);
    ASSERT_GT(g_register_cnt, 0);

    ops.register_seg_callback = RegisterSegFail;
    ASSERT_NE(umq_huge_qbuf_register_seg(nullptr, &ops), UMQ_SUCCESS);

    ops.unregister_seg_callback = UnregisterSeg;
    umq_huge_qbuf_unregister_seg(nullptr, &ops);
    ASSERT_GT(g_unregister_cnt, 0);

    umq_huge_qbuf_free(&list);
}

TEST_F(HugeQbufPoolInitTest, test_huge_qbuf_get_type_by_size)
{
    // Type by size should map to MID for 8x small.
    uint32_t small = umq_buf_size_small();
    huge_qbuf_pool_size_type_t type = umq_huge_qbuf_get_type_by_size(small * 8);
    ASSERT_EQ(type, HUGE_QBUF_POOL_SIZE_TYPE_MID);
}

TEST_F(HugeQbufPoolInitTest, test_huge_qbuf_get_size_by_type)
{
    // Size by type should be increasing.
    uint32_t mid_size = umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_MID);
    uint32_t big_size = umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_BIG);
    ASSERT_GT(big_size, mid_size);
}

TEST_F(HugeQbufPoolTest, test_huge_qbuf_alloc_not_inited)
{
    // Alloc without init should fail.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_NE(umq_huge_qbuf_alloc(HUGE_QBUF_POOL_SIZE_TYPE_MID, 1024, 1, nullptr, &list), UMQ_SUCCESS);
}

TEST_F(HugeQbufPoolTest, test_huge_qbuf_split_alloc_multi_fragment)
{
    // Split mode should allocate multiple fragments for large request.
    huge_qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    uint32_t blk_size = umq_huge_qbuf_get_size_by_type(HUGE_QBUF_POOL_SIZE_TYPE_MID);
    g_huge_pool_total_size = static_cast<uint64_t>(blk_size) * 64;

    cfg.total_size = g_huge_pool_total_size;
    cfg.data_size = blk_size;
    cfg.headroom_size = 0;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.type = HUGE_QBUF_POOL_SIZE_TYPE_MID;
    cfg.memory_init_callback = HugeMemInit;
    cfg.memory_uninit_callback = HugeMemUninit;

    for (uint32_t i = 0; i < (uint32_t)HUGE_QBUF_POOL_SIZE_TYPE_MAX; i++) {
        cfg.data_size = umq_huge_qbuf_get_size_by_type((huge_qbuf_pool_size_type_t)i);
        cfg.total_size = cfg.data_size * HUGE_QBUF_BUFFER_INC_BATCH;
        cfg.type = (huge_qbuf_pool_size_type_t)i;
        ASSERT_EQ(umq_huge_qbuf_config_init(&cfg), UMQ_SUCCESS);
    }
    umq_huge_qbuf_pool_ctx_common_cfg_set(&cfg);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_huge_qbuf_alloc(HUGE_QBUF_POOL_SIZE_TYPE_MID, blk_size + 128, 1, nullptr, &list), UMQ_SUCCESS);

    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_EQ(qbuf->first_fragment, 1);
    ASSERT_NE(qbuf->qbuf_next, nullptr);

    umq_huge_qbuf_free(&list);
}
