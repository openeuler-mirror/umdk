/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: shm qbuf pool unit tests
 */

#include "mockcpp/mockcpp.hpp"
#include "gtest/gtest.h"

#include <cstring>
#include <malloc.h>
#include <sys/mman.h>

#include "msg_ring.h"
#include "umq_errno.h"
#include "umq_qbuf_pool.h"
#include "umq_shm_qbuf_pool.h"

static uint64_t g_test_offset = 0;
static msg_ring_t *g_msg_ring_for_enqueue = nullptr;

static int TestEnqueue(uint64_t umq __attribute__((unused)), uint64_t *offset, uint32_t num)
{
    if (num == 0 || offset == nullptr) {
        return UMQ_FAIL;
    }
    g_test_offset = *offset;
    return UMQ_SUCCESS;
}

static int TestDequeue(uint64_t umq __attribute__((unused)), uint64_t *offset, uint32_t num)
{
    if (num == 0 || offset == nullptr) {
        return 0;
    }
    if (g_test_offset == 0) {
        return 0;
    }
    *offset = g_test_offset;
    g_test_offset = 0;
    return 1;
}

static int EnqueueToRing(uint64_t umq __attribute__((unused)), uint64_t *offset, uint32_t num)
{
    if (g_msg_ring_for_enqueue == nullptr || offset == nullptr || num == 0) {
        return UMQ_FAIL;
    }
    int ret = msg_ring_post_rx(g_msg_ring_for_enqueue, (char *)offset, sizeof(uint64_t));
    return (ret == 0) ? UMQ_SUCCESS : ret;
}

class ShmQbufPoolTest : public ::testing::Test {
  public:
    void SetUp() override
    {
        ASSERT_EQ(shm_qbuf_init(), UMQ_SUCCESS);
        // Ensure a stable small block size for all shm qbuf tests.
        (void)umq_buf_size_pow_small_set(BLOCK_SIZE_8K);
        uint32_t blk_size = umq_buf_size_small();
        // Allocate enough blocks to satisfy the batch fetch count (4) from global pool.
        total_size_ = static_cast<uint64_t>(16) *
            ((UMQ_EMPTY_HEADER_COEFFICIENT + 1) * static_cast<uint32_t>(sizeof(umq_buf_t)) + blk_size);

        buf_addr_ = memalign(blk_size, total_size_);
        ASSERT_NE(buf_addr_, nullptr);

        msg_ring_option_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.owner = true;
        cfg.tx_max_buf_size = 64;
        cfg.tx_depth = 16;
        cfg.rx_max_buf_size = 64;
        cfg.rx_depth = 16;

        const char *name = "umq_test_shm_qbuf_ring";
        shm_unlink(name);
        msg_ring_ = msg_ring_create(const_cast<char *>(name), strlen(name) + 1, &cfg);
        ASSERT_NE(msg_ring_, nullptr);

        shm_qbuf_pool_cfg_t pool_cfg;
        memset(&pool_cfg, 0, sizeof(pool_cfg));
        pool_cfg.buf_addr = buf_addr_;
        pool_cfg.total_size = total_size_;
        pool_cfg.data_size = blk_size;
        pool_cfg.headroom_size = 0;
        pool_cfg.mode = UMQ_BUF_SPLIT;
        pool_cfg.type = SHM_QBUF_POOL_TYPE_LOCAL;
        pool_cfg.local.umqh = 0x1234;
        pool_cfg.local.id = 0;
        pool_cfg.msg_ring = msg_ring_;

        pool_ = umq_shm_global_pool_init(&pool_cfg);
        ASSERT_NE(pool_, UMQ_INVALID_HANDLE);
    }

    void TearDown() override
    {
        if (pool_ != UMQ_INVALID_HANDLE) {
            umq_shm_global_pool_uninit(pool_);
        }
        if (msg_ring_ != nullptr) {
            msg_ring_destroy(msg_ring_);
        }
        if (buf_addr_ != nullptr) {
            free(buf_addr_);
        }
        shm_qbuf_uninit();
        GlobalMockObject::verify();
    }

    // SetUpTestCase 在所有 TEST_F 测试开始前执行一次
    static void SetUpTestCase()
    {
    }

    // TearDownTestCase 在所有 TEST_F 测试完成后执行一次
    static void TearDownTestCase()
    {
    }

  protected:
    void *buf_addr_ = nullptr;
    uint64_t total_size_ = 0;
    uint64_t pool_ = UMQ_INVALID_HANDLE;
    msg_ring_t *msg_ring_ = nullptr;
};

TEST_F(ShmQbufPoolTest, test_shm_qbuf_alloc_offset_and_free)
{
    // Basic alloc/free and offset conversion path.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    ASSERT_EQ(umq_shm_qbuf_alloc(pool_, 1024, 1, nullptr, &list), UMQ_SUCCESS);

    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);
    ASSERT_NE(qbuf->buf_data, nullptr);

    uint64_t qbuf_offset = umq_qbuf_to_offset(qbuf, pool_);
    umq_buf_t *qbuf2 = umq_offset_to_qbuf(qbuf_offset, pool_);
    ASSERT_EQ(qbuf2, qbuf);

    uint64_t data_offset = umq_qbuf_data_to_offset(qbuf->buf_data, pool_);
    char *data_ptr = umq_offset_to_qbuf_data(data_offset, qbuf->data_size, pool_);
    ASSERT_EQ(data_ptr, qbuf->buf_data);

    ASSERT_EQ(umq_shm_qbuf_headroom_reset(pool_, qbuf, 64), UMQ_SUCCESS);
    ASSERT_EQ(qbuf->headroom_size, 64);

    umq_shm_qbuf_free(pool_, &list);
}

TEST_F(ShmQbufPoolTest, test_shm_poll_and_return_to_global)
{
    // Feed a released qbuf into ring, then alloc should poll and return to global pool.
    g_msg_ring_for_enqueue = msg_ring_;

    umq_buf_list_t list0;
    QBUF_LIST_INIT(&list0);

    // Allocate several buffers to drain local cache to zero.
    for (int i = 0; i < 4; ++i) {
        umq_buf_list_t tmp;
        QBUF_LIST_INIT(&tmp);
        ASSERT_EQ(umq_shm_qbuf_alloc(pool_, 256, 1, nullptr, &tmp), UMQ_SUCCESS);
        umq_buf_t *qbuf = QBUF_LIST_FIRST(&tmp);
        ASSERT_NE(qbuf, nullptr);
        // Keep the first qbuf to enqueue; free the others later.
        if (i == 0) {
            QBUF_LIST_FIRST(&list0) = qbuf;
        } else {
            umq_shm_qbuf_free(pool_, &tmp);
        }
    }

    umq_buf_t *qbuf0 = QBUF_LIST_FIRST(&list0);
    ASSERT_NE(qbuf0, nullptr);

    // Convert qbuf to offset and enqueue into ring.
    ASSERT_EQ(umq_shm_qbuf_enqueue(qbuf0, 0x8888, pool_, false, EnqueueToRing), UMQ_SUCCESS);

    // This allocation should poll ring and return qbuf to global pool.
    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_shm_qbuf_alloc(pool_, 128, 1, nullptr, &list1), UMQ_SUCCESS);
    umq_shm_qbuf_free(pool_, &list1);
}

TEST_F(ShmQbufPoolTest, test_shm_offset_invalid_cases)
{
    // Validate offset boundary checks.
    ASSERT_EQ(umq_offset_to_qbuf(total_size_ + 1, pool_), nullptr);
    ASSERT_EQ(umq_offset_to_qbuf_data(total_size_ + 1, umq_buf_size_small(), pool_), nullptr);

    // In split mode, data region size is blk_num * blk_size (blk_num = 16 in SetUp()).
    uint64_t blk_size = umq_buf_size_small();
    uint64_t header_offset = static_cast<uint64_t>(16) * blk_size;
    uint64_t bad_offset = header_offset + 1;
    ASSERT_EQ(umq_offset_to_qbuf_data(bad_offset, umq_buf_size_small(), pool_), nullptr);
}

TEST_F(ShmQbufPoolTest, test_shm_qbuf_enqueue_dequeue)
{
    // Enqueue/dequeue via callbacks with rendezvous flag.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    ASSERT_EQ(umq_shm_qbuf_alloc(pool_, 256, 1, nullptr, &list), UMQ_SUCCESS);
    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);

    bool rendezvous = false;
    ASSERT_EQ(umq_shm_qbuf_enqueue(qbuf, 0x5678, pool_, true, TestEnqueue), UMQ_SUCCESS);

    umq_buf_t *deq = umq_shm_qbuf_dequeue(0x5678, 0x5678, pool_, &rendezvous, TestDequeue);
    ASSERT_NE(deq, nullptr);
    ASSERT_EQ(rendezvous, true);

    umq_buf_list_t free_list;
    QBUF_LIST_INIT(&free_list);
    QBUF_LIST_FIRST(&free_list) = deq;
    umq_shm_qbuf_free(pool_, &free_list);
}

TEST_F(ShmQbufPoolTest, test_shm_qbuf_enqueue_dequeue_fail)
{
    // Failure paths of enqueue/dequeue callbacks.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    ASSERT_EQ(umq_shm_qbuf_alloc(pool_, 256, 1, nullptr, &list), UMQ_SUCCESS);
    umq_buf_t *qbuf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(qbuf, nullptr);

    auto bad_enqueue = [](uint64_t, uint64_t *, uint32_t) { return UMQ_FAIL; };
    ASSERT_NE(umq_shm_qbuf_enqueue(qbuf, 0x5678, pool_, false, bad_enqueue), UMQ_SUCCESS);

    bool rendezvous = false;
    auto bad_dequeue = [](uint64_t, uint64_t *, uint32_t) { return 0; };
    ASSERT_EQ(umq_shm_qbuf_dequeue(0x5678, 0x5678, pool_, &rendezvous, bad_dequeue), nullptr);

    umq_shm_qbuf_free(pool_, &list);
}

TEST_F(ShmQbufPoolTest, test_shm_qbuf_alloc_mock_poll_failure)
{
    // Poll failure should not break allocation path.
    MOCKER(msg_ring_poll_rx_batch).stubs().will(returnValue(-1));

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    ASSERT_EQ(umq_shm_qbuf_alloc(pool_, 128, 1, nullptr, &list), UMQ_SUCCESS);
    umq_shm_qbuf_free(pool_, &list);
}

TEST(ShmQbufPoolCombineTest, test_shm_combine_mode_alloc)
{
    ASSERT_EQ(shm_qbuf_init(), UMQ_SUCCESS);
    // Combine mode init and basic alloc/free path.
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_8K);
    uint32_t blk_size = umq_buf_size_small();
    uint64_t total_size = static_cast<uint64_t>(blk_size) * 64;

    void *buf_addr = memalign(blk_size, total_size);
    ASSERT_NE(buf_addr, nullptr);

    msg_ring_option_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.owner = true;
    cfg.tx_max_buf_size = 64;
    cfg.tx_depth = 16;
    cfg.rx_max_buf_size = 64;
    cfg.rx_depth = 16;

    const char *name = "umq_test_shm_qbuf_ring_combine";
    shm_unlink(name);
    msg_ring_t *msg_ring = msg_ring_create(const_cast<char *>(name), strlen(name) + 1, &cfg);
    ASSERT_NE(msg_ring, nullptr);

    shm_qbuf_pool_cfg_t pool_cfg;
    memset(&pool_cfg, 0, sizeof(pool_cfg));
    pool_cfg.buf_addr = buf_addr;
    pool_cfg.total_size = total_size;
    pool_cfg.data_size = blk_size;
    pool_cfg.headroom_size = 0;
    pool_cfg.mode = UMQ_BUF_COMBINE;
    pool_cfg.type = SHM_QBUF_POOL_TYPE_LOCAL;
    pool_cfg.local.umqh = 0x2468;
    pool_cfg.local.id = 1;
    pool_cfg.msg_ring = msg_ring;

    uint64_t pool = umq_shm_global_pool_init(&pool_cfg);
    ASSERT_NE(pool, UMQ_INVALID_HANDLE);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_shm_qbuf_alloc(pool, 256, 1, nullptr, &list), UMQ_SUCCESS);
    umq_shm_qbuf_free(pool, &list);

    umq_shm_global_pool_uninit(pool);
    msg_ring_destroy(msg_ring);
    free(buf_addr);
    shm_qbuf_uninit();
}

TEST(ShmQbufPoolInvalidTest, test_shm_qbuf_invalid_pool)
{
    ASSERT_EQ(shm_qbuf_init(), UMQ_SUCCESS);
    // Invalid pool handle should fail.
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_NE(umq_shm_qbuf_alloc(0, 128, 1, nullptr, &list), UMQ_SUCCESS);
    shm_qbuf_uninit();
}

TEST(ShmQbufPoolInvalidTest, test_shm_qbuf_invalid_headroom_reset)
{
    ASSERT_EQ(shm_qbuf_init(), UMQ_SUCCESS);
    // Invalid pool for headroom reset should fail.
    ASSERT_NE(umq_shm_qbuf_headroom_reset(0, nullptr, 0), UMQ_SUCCESS);
    shm_qbuf_uninit();
}
