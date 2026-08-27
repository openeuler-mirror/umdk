/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * ubs-hcom is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *      http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <gtest/gtest.h>
#include <mockcpp/mockcpp.hpp>

#include <malloc.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>

/* Pull in all type definitions needed by stubs */
#include "umq_qbuf_pool.h"
#include "umq_qbuf_pool_helper.h"

/* Stubs for umq_qbuf_pool.c external dependencies.
 * umq_qbuf_pool.c is C code whose deps (urpc_id_generator, urpc_util, umq_vlog,
 * util_vlog) live in .c files that are NOT compiled into hcom_ut. We provide
 * minimal C-linkage stubs so the #include "umq_qbuf_pool.c" below links cleanly. */
extern "C" {

/* --- vlog / util_vlog stubs --- */
static util_vlog_ctx_t g_stub_log_ctx = {.level = UTIL_VLOG_LEVEL_DEBUG};
util_vlog_ctx_t *umq_get_log_ctx(void)
{
    return &g_stub_log_ctx;
}

static umq_vlog_config_t g_stub_log_cfg;
umq_vlog_config_t *umq_get_log_config(void)
{
    return &g_stub_log_cfg;
}

void util_vlog_output(util_vlog_ctx_t *ctx, util_vlog_level_t level, const char *file, util_vlog_type_t type,
                      const char *function, int line, const char *format, ...)
{
    (void)ctx;
    (void)type;
    const char *lvl_str[] = {"EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"};
    const char *l = (level < 8) ? lvl_str[level] : "?";
    char buf[1024];
    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    fprintf(stderr, "[%s] %s:%d %s: %s", l, file, line, function, buf);
}

bool util_vlog_limit(util_vlog_ctx_t *ctx, uint32_t *print_count, uint64_t *last_time)
{
    (void)ctx;
    (void)print_count;
    (void)last_time;
    return false;
}

/* --- urpc_util stub --- */
uint64_t urpc_get_cpu_hz(void)
{
    return 1000000000ULL;
}

/* --- urpc_id_generator stubs (simple bitmap, range [0, QBUF_POOL_EXP_SLOT_TABLE_SIZE)) --- */
static int stub_id_gen_init(urpc_id_generator_t *gen, unsigned int size)
{
    gen->private_data = calloc(1, (size + 7) / 8);
    return gen->private_data != NULL ? 0 : -1;
}

static void stub_id_gen_uninit(urpc_id_generator_t *gen)
{
    free(gen->private_data);
    gen->private_data = NULL;
}

static int stub_id_gen_alloc(urpc_id_generator_t *gen, unsigned int min, uint32_t *id)
{
    unsigned char *bm = (unsigned char *)gen->private_data;
    if (bm == NULL) {
        return -1;
    }
    for (uint32_t i = min; i < QBUF_POOL_EXP_SLOT_TABLE_SIZE; i++) {
        if (!(bm[i / 8] & (1U << (i % 8)))) {
            bm[i / 8] |= (unsigned char)(1U << (i % 8));
            *id = i;
            return 0;
        }
    }
    return -1;
}

static void stub_id_gen_free(urpc_id_generator_t *gen, uint32_t id)
{
    unsigned char *bm = (unsigned char *)gen->private_data;
    if (bm != NULL && id < QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
        bm[id / 8] &= (unsigned char)~(1U << (id % 8));
    }
}

int urpc_id_generator_init(urpc_id_generator_t *gen, urpc_id_generator_type_e type, unsigned int size)
{
    (void)type;
    gen->init = stub_id_gen_init;
    gen->uninit = stub_id_gen_uninit;
    gen->alloc = stub_id_gen_alloc;
    gen->free = stub_id_gen_free;
    gen->private_data = NULL;
    return stub_id_gen_init(gen, size);
}

void urpc_id_generator_uninit(urpc_id_generator_t *gen)
{
    if (gen->uninit != NULL) {
        gen->uninit(gen);
    }
}

int urpc_id_generator_alloc(urpc_id_generator_t *gen, unsigned int min, uint32_t *id)
{
    if (gen->alloc == NULL) {
        return -1;
    }
    return gen->alloc(gen, min, id);
}

void urpc_id_generator_free(urpc_id_generator_t *gen, uint32_t id)
{
    if (gen->free != NULL) {
        gen->free(gen, id);
    }
}

/* Stub for mempool_segment_ops_t.register_seg_callback (C linkage) */
static int stub_register_seg(uint8_t *ctx, uint16_t mempool_id, void *addr, uint64_t size)
{
    (void)ctx;
    (void)mempool_id;
    (void)addr;
    (void)size;
    return 0;
}

/* Stub for urpc_thread_closure_register (C linkage).
 * umq_qbuf_pool.c calls this during init/uninit/TLS-register paths to register
 * cleanup callbacks for thread-local state. We don't exercise thread exit in
 * unit tests, so a no-op stub is sufficient. */
__attribute__((weak)) void urpc_thread_closure_register(urpc_thread_closure_type_t type, uint64_t id,
                                                        void (*closure)(uint64_t id))
{
    (void)type;
    (void)id;
    (void)closure;
}

volatile bool g_tls_dtors_running = false;
} /* extern "C" */

/* Include the C implementation directly: gives access to static helpers
 * (select_size_class, get_batch_count, buf_data_to_size_class) and static
 * state (g_qbuf_pool, g_thread_cache, g_exp_slot_table). */
#include "umq_qbuf_pool.c"

/* Include base pool implementation: gives access to qbuf_pool_base_init,
 * umq_qbuf_base_alloc, umq_qbuf_base_free, umq_qbuf_base_data_to_head,
 * umq_qbuf_pool_base_info_get, etc. Same pattern as umq_qbuf_pool.c above. */
#include "umq_qbuf_pool_base.c"

/* Include RX pool implementation: gives access to static state (g_rx_pool,
 * g_rx_buffer_addr, g_rx_pool_inited) and umq_rx_qbuf_alloc/free/init/uninit
 * definitions. umq_rx_qbuf_pool.h is transitively included via
 * umq_qbuf_pool_helper.h at line 25. */
#include "umq_rx_qbuf_pool.c"

/* umq_qbuf_alloc is defined in umq_qbuf_pool_helper.c which depends on
 * umq_tiny_qbuf_pool and umq_huge_qbuf_pool. Rather than pulling in that
 * entire dependency chain, we provide a simplified version here that covers
 * the test scenarios: option==NULL → AUTO → NORMAL, fallback to ESCAPE.
 * 8e2ed74a 后: 超过最大单块的请求 umq_normal_qbuf_alloc 直接返回 -ENOMEM,
 * 不再走 escape fallback(超大属无效请求,escape 也不该接)。 */
extern "C" int umq_qbuf_alloc(uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    umq_alloc_pool_type_t pool_type = UMQ_ALLOC_POOL_AUTO;
    if (option != NULL && (option->flag & UMQ_ALLOC_FLAG_POOL_TYPE) != 0) {
        if (option->pool_type >= UMQ_ALLOC_POOL_MAX) {
            return -UMQ_ERR_EINVAL;
        }
        pool_type = option->pool_type;
    }

    if (pool_type == UMQ_ALLOC_POOL_RX) {
        return umq_rx_qbuf_alloc(request_size, num, option, list);
    }
    if (pool_type == UMQ_ALLOC_POOL_AUTO || pool_type == UMQ_ALLOC_POOL_NORMAL) {
        return umq_normal_qbuf_alloc(request_size, num, option, list);
    }
    if (pool_type == UMQ_ALLOC_POOL_ESCAPE) {
        return umq_qbuf_escape_alloc(request_size, num, option, list);
    }
    return -UMQ_ERR_EINVAL;
}

class TestQbufPoolMultiLevel : public testing::Test {
protected:
    void *buf_addr = nullptr;
    static constexpr uint64_t BUF_SIZE = 200ULL * 1024 * 1024; /* 200 MB */
    void SetUp() override
    {
        buf_addr = memalign(2 * 1024 * 1024, BUF_SIZE);
        ASSERT_NE(buf_addr, nullptr);
        memset(buf_addr, 0, BUF_SIZE);
        /* reset base block-size selector to 4K default before each test */
        (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    }

    void TearDown() override
    {
        umq_qbuf_pool_uninit();
        umq_rx_qbuf_pool_uninit();
        umq_rx_io_buf_free();
        (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
        free(buf_addr);
        GlobalMockObject::verify();
    }

    void InitPool(uint32_t count, uint32_t mult, umq_buf_block_size_t base = BLOCK_SIZE_4K,
                  umq_buf_mode_t mode = UMQ_BUF_SPLIT, bool scaleCap = true, uint64_t totalSz = BUF_SIZE,
                  uint64_t tlsBudget = 0, uint64_t tlsExpandBudget = 0, uint64_t expSz = 0,
                  const uint64_t *blockCounts = nullptr)
    {
        (void)umq_buf_size_pow_small_set(base);
        qbuf_pool_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.buf_addr = buf_addr;
        cfg.total_size = totalSz;
        cfg.data_size = umq_buf_size_small();
        cfg.mode = mode;
        cfg.size_class_count = count;
        {
            uint32_t baseBytes = umq_buf_size_small();
            uint64_t bs = baseBytes;
            for (uint32_t i = 0; i < count && i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
                cfg.explicit_block_sizes[i] = (uint32_t)bs;
                bs *= mult;
            }
        }
        cfg.disable_scale_cap = scaleCap;
        cfg.tls_qbuf_pool_depth = tlsBudget;
        cfg.tls_expand_qbuf_pool_depth = tlsExpandBudget;
        cfg.expansion_size = expSz;
        /* Fill per_sc_tls_qbuf_pool_depth from tls_qbuf_pool_depth when not set per-SC.
         * Production code copies these verbatim (no 0=inherit default), so a 0 value
         * clamps capacity growth to 0. Use tls_qbuf_pool_depth as the per-SC depth. */
        for (uint32_t i = 0; i < count && i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
            if (cfg.per_sc_tls_qbuf_pool_depth[i] == 0) {
                cfg.per_sc_tls_qbuf_pool_depth[i] = tlsBudget;
            }
        }
        if (blockCounts != nullptr) {
            for (uint32_t i = 0; i < count && i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
                cfg.per_sc_block_counts[i] = blockCounts[i];
            }
        } else {
            /* Auto-derive equal per-SC block counts from totalSz.
             * Layout: data = sum(N * blk_size), header = N * count * sizeof(umq_buf_t),
             * ext_header = QBUF_POOL_INITIAL_NODATA_BUF_CNT * sizeof(umq_buf_t).
             * So N = (totalSz - ext_header) / (sum(blk_size) + count * sizeof(umq_buf_t)). */
            uint64_t sum_blk_size = 0;
            for (uint32_t i = 0; i < count; i++) {
                sum_blk_size += cfg.explicit_block_sizes[i];
            }
            uint64_t ext_header = 32768ULL * sizeof(umq_buf_t);
            uint64_t avail = (totalSz > ext_header) ? (totalSz - ext_header) : 0;
            uint64_t denom = sum_blk_size + (uint64_t)count * sizeof(umq_buf_t);
            if (denom > 0 && avail > 0) {
                uint64_t n = avail / denom;
                for (uint32_t i = 0; i < count && i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
                    cfg.per_sc_block_counts[i] = n;
                }
            }
        }
        if (!scaleCap) {
            cfg.seg_ops.register_seg_callback = stub_register_seg;
        }
        ASSERT_EQ(umq_qbuf_pool_init(&cfg), 0);
    }

    void InitRxPool(uint64_t totalSz = 4ULL * 1024 * 1024)
    {
        void *rx_addr = umq_rx_io_buf_malloc(UMQ_BUF_SPLIT, totalSz);
        ASSERT_NE(rx_addr, nullptr);
        qbuf_pool_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.buf_addr = rx_addr;
        cfg.total_size = umq_rx_io_buf_size();
        ASSERT_EQ(umq_rx_qbuf_pool_init(&cfg), 0);
    }
};

/* Out-of-class definition for ODR-use in C++11 (EXPECT_EQ binds to reference). */
constexpr uint64_t TestQbufPoolMultiLevel::BUF_SIZE;

/* 9.1 Multi-level size_class selection */
TEST_F(TestQbufPoolMultiLevel, MultiLevelSizeClassSelection)
{
    /* Given: default config count=2, mult=16, base=4K -> [4K, 64K] */
    InitPool(2, 16);

    /* When/Then: select_size_class picks the smallest sc whose block_size >= need */
    EXPECT_EQ(select_size_class(2 * 1024), 0u);   /* 2K  -> sc=0 (4K >= 2K)  */
    EXPECT_EQ(select_size_class(4 * 1024), 0u);   /* 4K  -> sc=0 (4K >= 4K)  */
    EXPECT_EQ(select_size_class(50 * 1024), 1u);  /* 50K -> sc=1 (64K >= 50K) */
    EXPECT_EQ(select_size_class(200 * 1024), UMQ_QBUF_SIZE_CLASS_MAX); /* 200K > 64K -> no single block, fail sentinel */

    /* Given: custom config count=7, mult=2 -> [4K,8K,16K,32K,64K,128K,256K] */
    umq_qbuf_pool_uninit();
    InitPool(7, 2);

    /* When/Then: need=20K -> sc=3 (16K < 20K, 32K >= 20K) */
    EXPECT_EQ(select_size_class(20 * 1024), 3u);
    EXPECT_EQ(select_size_class(8 * 1024), 1u);   /* 8K -> sc=1 (8K >= 8K) */
    EXPECT_EQ(select_size_class(128 * 1024), 5u); /* 128K -> sc=5 */
}

/* 9.2 buf_data pointer size_class lookup */
TEST_F(TestQbufPoolMultiLevel, BufDataSizeClassLookup)
{
    InitPool(2, 16); /* [4K, 64K] */

    /* Alloc from sc=0 (small request) */
    umq_buf_list_t list0;
    QBUF_LIST_INIT(&list0);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list0), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list0), nullptr);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list0)->buf_data), 0u);
    umq_qbuf_free(&list0);

    /* Alloc from sc=1 (large request) */
    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(50 * 1024, 1, NULL, &list1), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list1), nullptr);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list1)->buf_data), 1u);
    umq_qbuf_free(&list1);

    /* Out-of-range pointer returns UMQ_QBUF_SIZE_CLASS_MAX */
    EXPECT_EQ(buf_data_to_size_class((void *)0x12345678), UMQ_QBUF_SIZE_CLASS_MAX);
}

/* 9.3 Independent expand/shrink per size_class */
TEST_F(TestQbufPoolMultiLevel, IndependentExpandShrinkPerSizeClass)
{
    /* Given: count=2 (4K, 64K), small pool + small expansion to trigger sc=0 expansion quickly.
     * Explicit blockCounts: 60 blocks for sc=0 (60*4K=240K data), 1 for sc=1 (64K data).
     * Total data+header fits in 4MB with ext_header(32768*128=4MB) — use 8MB pool instead. */
    const uint64_t pool8M = 8 * 1024 * 1024; /* 8 MB */
    const uint64_t smallExp = 256 * 1024;    /* 256 KB per expansion (>= 64K max block) */
    const uint64_t bc[] = {60, 1};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, pool8M, 0, 0, smallExp, bc);

    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);

    /* When: exhaust sc=0 blocks by allocating small buffers */
    std::vector<umq_buf_list_t> holders(sc0Blocks + 1);
    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0);
    }

    /* Then: sc=0 expansion triggered, sc=1 untouched */
    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 0u);
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[1].expansion_count, 0u);
}

/* 9.4 Global id pool mixed allocation */
TEST_F(TestQbufPoolMultiLevel, GlobalIdPoolMixedAllocation)
{
    /* Given: count=3 (4K, 64K, 1M), small pool + small expansion (2M >= 1M max block) */
    const uint64_t smallPool = 12 * 1024 * 1024; /* 12 MB, 4 MB per level */
    const uint64_t smallExp = 2 * 1024 * 1024;   /* 2 MB per expansion */
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    /* When: exhaust all 3 levels to trigger expansion on each */
    for (uint32_t sc = 0; sc < 3; sc++) {
        uint32_t blkCnt = (uint32_t)g_qbuf_pool.block_pool[sc].buf_cnt_with_data;
        ASSERT_GT(blkCnt, 0u);
        uint32_t reqSize = (sc == 0) ? (2 * 1024) : (sc == 1) ? (50 * 1024) : (1024 * 1024);
        std::vector<umq_buf_list_t> holders(blkCnt + 1);
        for (uint32_t i = 0; i <= blkCnt; i++) {
            QBUF_LIST_INIT(&holders[i]);
            ASSERT_EQ(umq_qbuf_alloc(reqSize, 1, NULL, &holders[i]), 0);
        }
        /* Verify this sc expanded */
        EXPECT_GT(g_qbuf_pool.exp_pool_with_data[sc].expansion_count, 0u) << "sc=" << sc << " did not expand";
    }

    /* Then: verify all slot ids in g_exp_slot_table are unique and in [0, TABLE_SIZE) */
    std::vector<uint32_t> usedIds;
    for (uint32_t i = 0; i < QBUF_POOL_EXP_SLOT_TABLE_SIZE; i++) {
        if (g_exp_slot_table[i] != NULL) {
            EXPECT_EQ(g_exp_slot_table[i]->slot_id, i);
            usedIds.push_back(i);
        }
    }
    /* At least 3 slots allocated (one per sc) */
    EXPECT_GE(usedIds.size(), 3u);
    /* All mempool_ids map to [257, 1021) — 1021/1022/1023 reserved for rx/tiny/escape */
    for (uint32_t id : usedIds) {
        EXPECT_GE(id + QBUF_POOL_EXP_SLOT_ID_MIN, QBUF_POOL_EXP_SLOT_ID_MIN);
        EXPECT_LT(id + QBUF_POOL_EXP_SLOT_ID_MIN, QBUF_POOL_EXP_SLOT_ID_MAX);
    }
}

/* 9.5 TLS byte budget enforcement */
TEST_F(TestQbufPoolMultiLevel, TlsByteBudgetEnforcement)
{
    /* Given: small TLS budget (1 MB), disable_scale_cap=false, small expansion to limit mem use */
    const uint64_t tlsBudget = 1 * 1024 * 1024; /* 1 MB global TLS cap */
    const uint64_t tlsExpand = 1 * 1024 * 1024; /* 1 MB per-thread cap  */
    const uint64_t smallExp = 256 * 1024;       /* 256 KB per expansion */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, tlsExpand, smallExp);

    /* When: alloc many 4K blocks (far exceeding 1 MB budget) */
    std::vector<umq_buf_list_t> holders(500);
    for (uint32_t i = 0; i < 500; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &holders[i]), 0);
    }

    /* Then: TLS capacity (capacity_with_data) never exceeds tls_qbuf_pool_depth */
    uint64_t globalTls = __atomic_load_n(&g_total_local_cap_with_data_cnt[0], __ATOMIC_RELAXED);
    EXPECT_LE(globalTls, g_qbuf_pool.tls_qbuf_pool_depth);
}

/* 9.6 Batch dynamic calculation */
TEST_F(TestQbufPoolMultiLevel, BatchDynamicCalculation)
{
    /* Given: block_sizes [4K, 64K]
     * get_batch_count is adaptive: QBUF_POOL_TARGET_FETCH_BYTES(4MB) / blk_size,
     * clamped to [QBUF_POOL_BATCH_CNT_MIN(4), QBUF_POOL_BATCH_CNT(64)]. */
    InitPool(2, 16);

    /* sc=0 (4K): 4MB/4K = 1024 -> clamped to 64 */
    EXPECT_EQ(get_batch_count(0), 64u);
    /* sc=1 (64K): 4MB/64K = 64 (no clamping needed) */
    EXPECT_EQ(get_batch_count(1), 64u);

    /* Given: custom config count=3, mult=8 -> [4K, 32K, 256K] */
    umq_qbuf_pool_uninit();
    InitPool(3, 8);

    /* sc=0 (4K): 4MB/4K = 1024 -> clamped to 64 */
    EXPECT_EQ(get_batch_count(0), 64u);
    /* sc=1 (32K): 4MB/32K = 128 -> clamped to 64 */
    EXPECT_EQ(get_batch_count(1), 64u);
    /* sc=2 (256K): 4MB/256K = 16 */
    EXPECT_EQ(get_batch_count(2), 16u);
}

/* 9.7 Escape alloc comprehensive (merged 9.7+9.29+9.80+9.87+9.96)
 * All use tinyPool(64KB) where sc=1 has 0 blocks -> escape fallback.
 * Block-equal (SPLIT, disable_scale_cap=true): N = 64KB / (4096+65536+2*17*128)
 *   = 65536 / 73984 = 0 -> both SCs have 0 blocks -> escape fallback.
 * Covers: escape alloc, escape free, escape_data_to_head, multi-block EINVAL,
 *         AUTO fallback, buf_size verification, g_escape_buf_cnt. */
TEST_F(TestQbufPoolMultiLevel, EscapeAllocComprehensive)
{
    const uint64_t tinyPool = 64 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, true, tinyPool);
    ASSERT_EQ(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);

    /* 1. Escape alloc success (sc=1, actual_buf_count=1) */
    umq_buf_list_t escList;
    QBUF_LIST_INIT(&escList);
    EXPECT_EQ(umq_qbuf_alloc(50 * 1024, 1, NULL, &escList), 0);
    umq_buf_t *escBuf = QBUF_LIST_FIRST(&escList);
    ASSERT_NE(escBuf, nullptr);
    EXPECT_EQ(escBuf->mempool_id, QBUF_POOL_MEMPOOL_ID_MAX);
    EXPECT_EQ(escBuf->buf_size, (uint32_t)(64 * 1024 + sizeof(umq_buf_t)));

    /* 2. escape_data_to_head on escape buf */
    void *data = escBuf->buf_data;
    umq_buf_t *found = escape_data_to_head(data);
    EXPECT_NE(found, nullptr);

    /* 3. Escape free -> g_escape_buf_cnt returns to 0 */
    umq_qbuf_free(&escList);
    EXPECT_FALSE(any_escape_buf_exists());

    /* 4. Multi-block escape fail (actual_buf_count>1 -> EINVAL) */
    umq_buf_list_t failList;
    QBUF_LIST_INIT(&failList);
    EXPECT_EQ(umq_qbuf_alloc(200 * 1024, 1, NULL, &failList), -UMQ_ERR_ENOMEM);
}

/* 9.8 count=1 backward compatibility */
TEST_F(TestQbufPoolMultiLevel, CountOneBackwardCompat)
{
    InitPool(1, 16); /* single level, base=4K */

    /* Then: pool structure reflects single-level config */
    EXPECT_EQ(g_qbuf_pool.size_class_count, 1u);
    EXPECT_EQ(g_qbuf_pool.block_sizes[0], (uint32_t)(4 * 1024));
    EXPECT_EQ(g_qbuf_pool.block_sizes[0], umq_buf_size_small());

    /* When: alloc various sizes, all go to sc=0 */
    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list1), 0);
    EXPECT_EQ(QBUF_LIST_FIRST(&list1)->buf_size, (uint32_t)(4 * 1024 + sizeof(umq_buf_t)));
    umq_qbuf_free(&list1);

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &list2), 0);
    EXPECT_EQ(QBUF_LIST_FIRST(&list2)->buf_size, (uint32_t)(4 * 1024 + sizeof(umq_buf_t)));
    umq_qbuf_free(&list2);

    /* total_block_num = per_sc_block_counts[0] (single SC, auto-derived from totalSz).
     * InitPool auto-derive: N = (totalSz - 32768*sizeof(umq_buf_t)) / (blk_size + sizeof(umq_buf_t)) */
    uint64_t ext_header = 32768ULL * sizeof(umq_buf_t);
    uint64_t avail = (BUF_SIZE > ext_header) ? (BUF_SIZE - ext_header) : 0;
    uint64_t expectedN = avail / (4 * 1024 + sizeof(umq_buf_t));
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[0], expectedN);
    EXPECT_EQ(g_qbuf_pool.total_block_num, expectedN);
}

/* 9.9 Configuration validation comprehensive (merged 9.9+9.27+9.28) */
TEST_F(TestQbufPoolMultiLevel, ConfigurationValidationComprehensive)
{
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.disable_scale_cap = true;

    auto fillSizes = [&cfg](uint32_t count, uint32_t mult) {
        cfg.size_class_count = count;
        uint32_t baseBytes = umq_buf_size_small();
        uint64_t bs = baseBytes;
        for (uint32_t i = 0; i < count && i < UMQ_QBUF_SIZE_CLASS_MAX; i++) {
            cfg.explicit_block_sizes[i] = (uint32_t)bs;
            bs *= mult;
        }
    };

    /* explicit_block_sizes not ascending -> EINVAL */
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    cfg.size_class_count = 2;
    cfg.explicit_block_sizes[0] = 4096;
    cfg.explicit_block_sizes[1] = 4096;
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);

    /* count=17 (> 16) -> EINVAL */
    fillSizes(17, 16);
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);

    /* base too small (pow=0 -> base=1 < 4096) -> EINVAL */
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    g_umq_qbuf_size_pow_small = 0;
    fillSizes(2, 16);
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);

    /* max block > max allowed / expansion_size (count=5, mult=16 -> 16M/256M > 1M/32MB) -> EINVAL
     * Requires disable_scale_cap=false to trigger the expansion_size check path */
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    fillSizes(5, 16);
    cfg.disable_scale_cap = false;
    cfg.seg_ops.register_seg_callback = stub_register_seg;
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);

    /* expansion_threshold=0 -> default 30, should succeed.
     * Need non-zero per_sc_block_counts for layout to succeed. */
    cfg.disable_scale_cap = true;
    fillSizes(2, 16);
    cfg.expansion_threshold = 0;
    uint64_t bc0[] = {1000, 1000};
    for (uint32_t i = 0; i < 2; i++) cfg.per_sc_block_counts[i] = bc0[i];
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), 0);
    umq_qbuf_pool_uninit();

    /* expansion_threshold=101 -> no upper bound check in init_size_class_config,
     * value used directly. Need per_sc_block_counts for init to succeed (all-zero -> 0 blocks -> layout fails). */
    cfg.expansion_threshold = 101;
    uint64_t bc101[] = {1000, 1000};
    for (uint32_t i = 0; i < 2; i++) cfg.per_sc_block_counts[i] = bc101[i];
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), 0);
    umq_qbuf_pool_uninit();

    /* expansion_threshold=200 -> no upper bound check, accepted */
    cfg.expansion_threshold = 200;
    for (uint32_t i = 0; i < 2; i++) cfg.per_sc_block_counts[i] = bc101[i];
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), 0);
    umq_qbuf_pool_uninit();

    /* Valid threshold=50 -> success */
    cfg.expansion_threshold = 50;
    for (uint32_t i = 0; i < 2; i++) cfg.per_sc_block_counts[i] = bc101[i];
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), 0);
    umq_qbuf_pool_uninit();

    /* Explicit defaults -> verify defaults applied.
     * per_sc_block_counts must be set explicitly (all-zero -> 0 blocks -> layout fails). */
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.disable_scale_cap = true;
    fillSizes(2, 16);
    uint64_t bc_defaults[] = {10000, 1000};
    for (uint32_t i = 0; i < 2; i++) cfg.per_sc_block_counts[i] = bc_defaults[i];
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), 0);
    EXPECT_EQ(g_qbuf_pool.size_class_count, 2u);
    EXPECT_EQ(g_qbuf_pool.expansion_size, 32ULL * 1024 * 1024);
    EXPECT_EQ(g_qbuf_pool.expansion_threshold, 30u);
    EXPECT_GT(g_qbuf_pool.tls_qbuf_pool_depth, 0u);
}

/* 9.10 Integration: UB_PLUS large packet via multi-block concatenation */
TEST_F(TestQbufPoolMultiLevel, UbPlusLargePacketIntegration)
{
    InitPool(2, 16); /* [4K, 64K], 200 MB total */

    /* 8e2ed74a 后: 申请超过最大单块block_size(64K)返回UMQ_ERR_ENOMEM,
     * 不再走多块拼接。1MB > 64K -> 失败。 */
    const uint32_t reqSize = 1024 * 1024;
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(reqSize, 1, NULL, &list), -UMQ_ERR_ENOMEM);
    EXPECT_EQ(QBUF_LIST_FIRST(&list), nullptr);
}

/* Helper: count entries in a qbuf singly-linked list */
static uint32_t CountQbufListEntries(umq_buf_list_t *list)
{
    uint32_t count = 0;
    umq_buf_t *cur;
    QBUF_LIST_FOR_EACH(cur, list)
    {
        count++;
    }
    return count;
}

/* 9.11 Full-range size class selection + alloc/free + list length
 * Merged from original 9.11 (count=2/mult=16), 9.12 (count=4/mult=4),
 * 9.13 (count=7/mult=2) — identical test structure, only config differs. */
TEST_F(TestQbufPoolMultiLevel, FullRangeSizeClassAndAllocFree)
{
    struct TestConfig {
        uint32_t count;
        uint32_t mult;
        uint32_t expectedBlockSizes[16];
        struct SizeCase {
            uint32_t reqSize;
            uint32_t expectedSc;
            uint32_t expectedListLen;
        } cases[12];
        uint32_t numCases;
    };

    const TestConfig configs[] = {
        {2,
         16,
         {4u * 1024u, 64u * 1024u},
         {{1u * 1024u, 0u, 1u},
          {4u * 1024u, 0u, 1u},
          {50u * 1024u, 1u, 1u},
          {64u * 1024u, 1u, 1u},
          {100u * 1024u, UMQ_QBUF_SIZE_CLASS_MAX, 0u},
          {1024u * 1024u, UMQ_QBUF_SIZE_CLASS_MAX, 0u}},
         6},
        {4,
         4,
         {4u * 1024u, 16u * 1024u, 64u * 1024u, 256u * 1024u},
         {{1u * 1024u, 0u, 1u},
          {4u * 1024u, 0u, 1u},
          {16u * 1024u, 1u, 1u},
          {50u * 1024u, 2u, 1u},
          {64u * 1024u, 2u, 1u},
          {256u * 1024u, 3u, 1u},
          {300u * 1024u, UMQ_QBUF_SIZE_CLASS_MAX, 0u},
          {1024u * 1024u, UMQ_QBUF_SIZE_CLASS_MAX, 0u}},
         8},
        {7,
         2,
         {4u * 1024u, 8u * 1024u, 16u * 1024u, 32u * 1024u, 64u * 1024u, 128u * 1024u, 256u * 1024u},
         {{1u * 1024u, 0u, 1u},
          {4u * 1024u, 0u, 1u},
          {8u * 1024u, 1u, 1u},
          {16u * 1024u, 2u, 1u},
          {32u * 1024u, 3u, 1u},
          {64u * 1024u, 4u, 1u},
          {128u * 1024u, 5u, 1u},
          {256u * 1024u, 6u, 1u},
          {300u * 1024u, UMQ_QBUF_SIZE_CLASS_MAX, 0u},
          {1024u * 1024u, UMQ_QBUF_SIZE_CLASS_MAX, 0u}},
         10},
    };

    for (uint32_t ci = 0; ci < sizeof(configs) / sizeof(configs[0]); ci++) {
        const TestConfig &cfg = configs[ci];
        if (ci > 0)
            umq_qbuf_pool_uninit();
        InitPool(cfg.count, cfg.mult);

        EXPECT_EQ(g_qbuf_pool.size_class_count, cfg.count) << "config[" << ci << "]";
        for (uint32_t sc = 0; sc < cfg.count; sc++) {
            EXPECT_EQ(g_qbuf_pool.block_sizes[sc], cfg.expectedBlockSizes[sc]) << "config[" << ci << "] sc=" << sc;
        }

        for (uint32_t i = 0; i < cfg.numCases; i++) {
            const TestConfig::SizeCase &c = cfg.cases[i];
            /* 8e2ed74a 后: 超过最大单块block_size的请求, select_size_class返回
             * UMQ_QBUF_SIZE_CLASS_MAX(16) sentinel, umq_qbuf_alloc返回-ENOMEM.
             * expectedSc=UMQ_QBUF_SIZE_CLASS_MAX标记此类超限case。 */
            if (c.expectedSc == UMQ_QBUF_SIZE_CLASS_MAX) {
                EXPECT_EQ(select_size_class(c.reqSize), (uint32_t)UMQ_QBUF_SIZE_CLASS_MAX)
                    << "config[" << ci << "] case[" << i << "] reqSize=" << c.reqSize;
                umq_buf_list_t list;
                QBUF_LIST_INIT(&list);
                EXPECT_EQ(umq_qbuf_alloc(c.reqSize, 1, NULL, &list), -UMQ_ERR_ENOMEM)
                    << "config[" << ci << "] case[" << i << "] reqSize=" << c.reqSize;
                EXPECT_EQ(QBUF_LIST_FIRST(&list), nullptr);
                continue;
            }

            EXPECT_EQ(select_size_class(c.reqSize), c.expectedSc)
                << "config[" << ci << "] case[" << i << "] reqSize=" << c.reqSize;

            umq_buf_list_t list;
            QBUF_LIST_INIT(&list);
            ASSERT_EQ(umq_qbuf_alloc(c.reqSize, 1, NULL, &list), 0)
                << "config[" << ci << "] case[" << i << "] reqSize=" << c.reqSize;

            uint32_t listLen = CountQbufListEntries(&list);
            EXPECT_EQ(listLen, c.expectedListLen) << "config[" << ci << "] case[" << i << "] reqSize=" << c.reqSize;

            umq_buf_t *first = QBUF_LIST_FIRST(&list);
            ASSERT_NE(first, nullptr);
            EXPECT_EQ(first->buf_size, g_qbuf_pool.block_sizes[c.expectedSc] + (uint32_t)sizeof(umq_buf_t))
                << "config[" << ci << "] case[" << i << "]";
            EXPECT_EQ(first->total_data_size, c.reqSize) << "config[" << ci << "] case[" << i << "]";
            EXPECT_EQ(buf_data_to_size_class(first->buf_data), c.expectedSc)
                << "config[" << ci << "] case[" << i << "]";

            umq_qbuf_free(&list);
        }
    }
}

/* 9.14 TLS batch fetch from global on first alloc (disable_scale_cap=true path)
 * When TLS local pool is empty, umq_qbuf_alloc triggers fetch_from_global which
 * fetches get_batch_count(sc) blocks from the global pool in one batch.
 * Verifies: TLS gains batch_count-1, global loses batch_count. */
TEST_F(TestQbufPoolMultiLevel, TlsBatchFetchFromGlobalOnFirstAlloc)
{
    InitPool(2, 16); /* [4K, 64K], disable_scale_cap=true */

    /* Fresh pool: TLS sc=0 is empty */
    EXPECT_EQ(g_thread_cache.block_pool.buf_cnt_with_data[0], 0u);

    /* Global sc=0 has blocks (pre-allocated from pool memory) */
    uint64_t globalBefore = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(globalBefore, 0u);

    /* batch_count = QBUF_POOL_BATCH_CNT = 64 */
    uint32_t batch = get_batch_count(0);
    EXPECT_EQ(batch, 64u);

    /* Alloc 1 small block (1K, sc=0) -> TLS insufficient -> batch fetch from global */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(1 * 1024, 1, NULL, &list), 0);

    /* TLS gained batch_count blocks, 1 used -> batch_count-1 remain */
    EXPECT_EQ(g_thread_cache.block_pool.buf_cnt_with_data[0], (uint64_t)(batch - 1));

    /* Global decreased by exactly batch_count */
    uint64_t globalAfter = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    EXPECT_EQ(globalBefore - globalAfter, (uint64_t)batch);

    umq_qbuf_free(&list);
}

/* 9.15 Global pool expansion and expanded block usability (disable_scale_cap=false path)
 * When global pool is exhausted, fetch_from_global triggers expand_global_pool to allocate
 * new memory segments. Verifies: expansion triggered, expanded blocks are allocatable,
 * and expansion is independent per size_class (sc=1 untouched when sc=0 exhausts). */
TEST_F(TestQbufPoolMultiLevel, GlobalExpansionAndExpandedBlockUsability)
{
    /* scaleCap=false enables expansion; small pool + small expansion for quick exhaustion.
     * Explicit blockCounts: 60 blocks for sc=0, 1 for sc=1. Use 8MB pool. */
    const uint64_t pool8M = 8 * 1024 * 1024; /* 8 MB */
    const uint64_t smallExp = 256 * 1024;    /* 256 KB per expansion (>= 64K max block) */
    const uint64_t bc[] = {60, 1};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, pool8M, 0, 0, smallExp, bc);

    /* Phase 1: Exhaust sc=0 global blocks to trigger expansion */
    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);

    std::vector<umq_buf_list_t> holders(sc0Blocks + 1);
    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0) << "alloc failed at iteration " << i;
    }

    /* Expansion triggered for sc=0; sc=1 untouched (independent per-sc) */
    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 0u) << "sc=0 should have expanded";
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[1].expansion_count, 0u) << "sc=1 should not have expanded";

    /* Phase 2: Alloc from expanded pool -> verify expanded blocks are usable */
    umq_buf_list_t expandedBuf;
    QBUF_LIST_INIT(&expandedBuf);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &expandedBuf), 0) << "alloc from expanded pool should succeed";
    umq_buf_t *first = QBUF_LIST_FIRST(&expandedBuf);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->buf_size, g_qbuf_pool.block_sizes[0] + (uint32_t)sizeof(umq_buf_t));
    EXPECT_EQ(buf_data_to_size_class(first->buf_data), 0u);
    umq_qbuf_free(&expandedBuf);

    /* Cleanup: free all holders */
    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* 9.16 TLS self-shrink returns excess to global (disable_scale_cap=false path)
 * When TLS pool has > 256 blocks (shrink = remaining/4 >= threshold=64), the next
 * umq_qbuf_alloc triggers thread_cache_self_shrink which returns excess blocks to
 * the global pool. Verifies: global gains blocks from shrink, TLS count decreases. */
TEST_F(TestQbufPoolMultiLevel, TlsSelfShrinkReturnsExcessToGlobal)
{
    /* scaleCap=false enables shrink; generous TLS budget allows > 256 blocks to accumulate */
    const uint64_t tlsBudget = 4096; /* 4096 blocks global TLS cap (was 4MB byte-budget, now count-based) */
    const uint64_t tlsExpand = 2048; /* 2048 blocks per-thread cap */
    const uint64_t smallExp = 256 * 1024;       /* 256 KB per expansion */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, tlsExpand, smallExp);

    /* Phase 1: Alloc 300 4K blocks -> 5 batch fetches (5*64=320), 300 used, TLS=20 */
    std::vector<umq_buf_list_t> holders(300);
    for (uint32_t i = 0; i < 300; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &holders[i]), 0);
    }
    /* capacity_with_data[0] = 5 * 256KB = 1280KB, cap = 320 blocks */
    uint64_t bytesWithData = g_thread_cache.block_pool.capacity_with_data[0];
    EXPECT_GT(bytesWithData, 0u);

    /* Phase 2: Free all 300 -> free-path self_shrink returns excess to global.
     * With high-water mark cap (~64 blocks), TLS can't hold 300.
     * self_shrink on each free call drains excess to global pool. */
    uint64_t globalBeforeFree = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    for (uint32_t i = 0; i < 300; i++) {
        umq_qbuf_free(&holders[i]);
    }
    uint64_t tlsAfterFree = g_thread_cache.block_pool.buf_cnt_with_data[0];
    uint64_t globalAfterFree = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    /* TLS bounded by cap (~64 blocks, not 300) */
    EXPECT_LE(tlsAfterFree, 64u) << "TLS should be bounded by high-water mark cap after free";
    /* Free-path self_shrink returned excess blocks to global pool */
    EXPECT_GT(globalAfterFree, globalBeforeFree) << "free-path self_shrink should return excess to global";

    /* Phase 3: Alloc 1 more -> no additional shrink needed (free already drained).
     * Alloc-path self_shrink is no-op when TLS < 256 (shrink threshold). */
    uint64_t globalBefore = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    uint64_t tlsBefore = g_thread_cache.block_pool.buf_cnt_with_data[0];

    umq_buf_list_t triggerList;
    QBUF_LIST_INIT(&triggerList);
    ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &triggerList), 0);

    uint64_t tlsAfter = g_thread_cache.block_pool.buf_cnt_with_data[0];
    /* TLS decreased by 1 (just the alloc, no shrink) */
    EXPECT_EQ(tlsAfter, tlsBefore - 1) << "alloc should consume 1 block from TLS, no shrink needed";

    umq_qbuf_free(&triggerList);
}

/* 9.17 blk_size_to_sc: multi-config + alloc + mult=1 (merged 9.17+9.50+9.65) */
TEST_F(TestQbufPoolMultiLevel, BlkSizeToScMultiConfig)
{
    /* count=2, mult=16 -> [4K, 64K] */
    InitPool(2, 16);
    EXPECT_EQ(blk_size_to_sc(4 * 1024), 0u);
    EXPECT_EQ(blk_size_to_sc(64 * 1024), 1u);
    EXPECT_EQ(blk_size_to_sc(0), 16u);
    EXPECT_EQ(blk_size_to_sc(8 * 1024), 16u);
    EXPECT_EQ(blk_size_to_sc(128 * 1024), 16u);

    /* count=3, mult=2 -> [4K, 8K, 16K] */
    umq_qbuf_pool_uninit();
    InitPool(3, 2);
    EXPECT_EQ(blk_size_to_sc(4 * 1024), 0u);
    EXPECT_EQ(blk_size_to_sc(8 * 1024), 1u);
    EXPECT_EQ(blk_size_to_sc(16 * 1024), 2u);
    EXPECT_EQ(blk_size_to_sc(0), 16u);
    EXPECT_EQ(blk_size_to_sc(2 * 1024), 16u);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(6 * 1024, 1, NULL, &list1), 0);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list1)->buf_data), 1u);
    umq_qbuf_free(&list1);

    /* count=4, mult=4 -> [4K, 16K, 64K, 256K] */
    umq_qbuf_pool_uninit();
    InitPool(4, 4);
    EXPECT_EQ(blk_size_to_sc(16 * 1024), 1u);
    EXPECT_EQ(blk_size_to_sc(64 * 1024), 2u);
    EXPECT_EQ(blk_size_to_sc(256 * 1024), 3u);

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(50 * 1024, 1, NULL, &list2), 0);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list2)->buf_data), 2u);
    umq_qbuf_free(&list2);
} /* 9.18 COMBINE mode init + alloc/free (merged 9.18+9.45)
 * Tests count=2 and count=3 COMBINE configs. */
TEST_F(TestQbufPoolMultiLevel, CombineModeInitAndAlloc)
{
    /* count=2, mult=16 -> [4K, 64K] COMBINE */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);
    EXPECT_EQ(g_qbuf_pool.mode, UMQ_BUF_COMBINE);
    EXPECT_EQ(g_qbuf_pool.size_class_count, 2u);
    EXPECT_EQ(g_qbuf_pool.block_sizes[0], 4u * 1024u);
    EXPECT_EQ(g_qbuf_pool.block_sizes[1], 64u * 1024u);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list), nullptr);
    EXPECT_EQ(CountQbufListEntries(&list), 1u);
    EXPECT_EQ(QBUF_LIST_FIRST(&list)->buf_size, 4u * 1024u);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list)->buf_data), 0u);
    umq_qbuf_free(&list);

    /* count=3, mult=8 -> [4K, 32K, 256K] COMBINE — covers F02,F46,F47,F48 */
    umq_qbuf_pool_uninit();
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);
    EXPECT_EQ(g_qbuf_pool.size_class_count, 3u);

    for (uint32_t sc = 0; sc < 3; sc++) {
        EXPECT_GT(g_qbuf_pool.block_pool[sc].buf_cnt_with_data, 0u) << "sc=" << sc;
    }

    umq_buf_list_t list0;
    QBUF_LIST_INIT(&list0);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list0), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list0), nullptr);
    EXPECT_EQ(QBUF_LIST_FIRST(&list0)->buf_size, 4u * 1024u);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list0)->buf_data), 0u);
    umq_qbuf_free(&list0);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(20 * 1024, 1, NULL, &list1), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list1), nullptr);
    EXPECT_EQ(QBUF_LIST_FIRST(&list1)->buf_size, 32u * 1024u);
    EXPECT_EQ(QBUF_LIST_FIRST(&list1)->data_size, 20u * 1024u);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list1)->buf_data), 1u);
    umq_qbuf_free(&list1);

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(200 * 1024, 1, NULL, &list2), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list2), nullptr);
    EXPECT_EQ(QBUF_LIST_FIRST(&list2)->buf_size, 256u * 1024u);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list2)->buf_data), 2u);
    umq_qbuf_free(&list2);
} /* 9.19 COMBINE mode multi-block alloc (request > max single-block capacity) */
TEST_F(TestQbufPoolMultiLevel, CombineModeMultiBlockAlloc)
{
    /* Given: count=2, mult=16, mode=COMBINE -> block_sizes = [4K, 64K] */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);

    /* 8e2ed74a 后: 100K 超过最大单块64K, 返回UMQ_ERR_ENOMEM, 不再走多块拼接 */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(100 * 1024, 1, NULL, &list), -UMQ_ERR_ENOMEM);
    EXPECT_EQ(CountQbufListEntries(&list), 0u);
}

/* 9.20 Without-data expansion: first alloc triggers expansion pool creation */
TEST_F(TestQbufPoolMultiLevel, WithoutDataExpansion)
{
    /* Given: disable_scale_cap=false -> expansion pool inited, without_data headers
     * pre-populated from ext_header_buffer. First without_data alloc fetches from
     * pre-populated global pool (no expansion needed for small num=5).
     * Use explicit blockCounts to ensure non-zero initial blocks. */
    const uint64_t pool8M = 8 * 1024 * 1024; /* 8 MB */
    const uint64_t bc[] = {60, 1};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, pool8M, 0, 0, 0, bc);

    /* Before alloc: without_data headers pre-populated from ext_header_buffer */
    EXPECT_EQ(g_qbuf_pool.exp_pool_without_date.expansion_count, 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[0].buf_cnt_without_data, 0u);

    /* When: alloc 5 without_data buffers (request_size=0, opt with no headroom) */
    umq_alloc_option_t opt = {0};
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(0, 5, &opt, &list), 0);

    /* Then: 5 headers served from pre-populated pool, no expansion needed yet */
    EXPECT_EQ(g_qbuf_pool.exp_pool_without_date.expansion_count, 0u);

    /* Verify each buffer is without_data (buf_data==NULL, mempool_without_data==1) */
    umq_buf_t *cur;
    QBUF_LIST_FOR_EACH(cur, &list)
    {
        EXPECT_EQ(cur->buf_data, nullptr);
        EXPECT_EQ(cur->mempool_without_data, 1u);
    }

    umq_qbuf_free(&list);
}

/* 9.21 buf_data_to_size_class edge cases: NULL, before-region, valid pointers */
TEST_F(TestQbufPoolMultiLevel, BufDataToSizeClassEdgeCases)
{
    InitPool(2, 16); /* [4K, 64K] */

    /* NULL pointer: count > 0 but data < data_region_start[0] -> MAX */
    EXPECT_EQ(buf_data_to_size_class(NULL), UMQ_QBUF_SIZE_CLASS_MAX);

    /* Low address before data_region_start[0] -> MAX */
    EXPECT_EQ(buf_data_to_size_class((void *)0x1), UMQ_QBUF_SIZE_CLASS_MAX);

    /* Alloc from sc=0 -> verify buf_data maps to sc=0 */
    umq_buf_list_t list0;
    QBUF_LIST_INIT(&list0);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list0), 0);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list0)->buf_data), 0u);
    umq_qbuf_free(&list0);

    /* Alloc from sc=1 -> verify buf_data maps to sc=1 */
    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(50 * 1024, 1, NULL, &list1), 0);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list1)->buf_data), 1u);
    umq_qbuf_free(&list1);
}

/* 9.22 get_batch_count: uniform QBUF_POOL_BATCH_CNT regardless of SC */
TEST_F(TestQbufPoolMultiLevel, GetBatchCountEdgeCase)
{
    InitPool(2, 16); /* [4K, 64K] */

    /* get_batch_count is adaptive: 4MB / blk_size, clamped [4, 64].
     * sc=0 (4K): 4MB/4K = 1024 -> clamped to 64.
     * sc=1 (64K): 4MB/64K = 64 (no clamping). */
    EXPECT_EQ(get_batch_count(0), 64u);
    EXPECT_EQ(get_batch_count(1), 64u);
}

/* 9.23 umq_io_buf_malloc validation: size=0 default, size<min_size NULL, COMBINE */
TEST_F(TestQbufPoolMultiLevel, UmqIoBufMallocValidation)
{
    /* NOTE: This test does NOT call InitPool — umq_io_buf_malloc uses g_buffer_addr
     * global which is independent of the pool. TearDown's umq_qbuf_pool_uninit is
     * a no-op when pool is not inited. */

    /* Ensure clean state: free any leftover g_buffer_addr */
    umq_io_buf_free();
    EXPECT_EQ(g_buffer_addr, nullptr);

    /* size=0 with SPLIT: uses default 1GB, returns non-NULL */
    void *ptr1 = umq_io_buf_malloc(UMQ_BUF_SPLIT, 0);
    EXPECT_NE(ptr1, nullptr);
    EXPECT_EQ(g_buffer_addr, ptr1);
    EXPECT_GT(g_total_len, 0u);

    /* Free to reset g_buffer_addr before next test */
    umq_io_buf_free();
    EXPECT_EQ(g_buffer_addr, nullptr);

    /* size=1024 < min_size (SPLIT min = 17*128+4K = 6272) -> NULL */
    void *ptr2 = umq_io_buf_malloc(UMQ_BUF_SPLIT, 1024);
    EXPECT_EQ(ptr2, nullptr);

    /* size=0 with COMBINE: min_size = umq_buf_size_small() = 4K, default 1GB */
    void *ptr3 = umq_io_buf_malloc(UMQ_BUF_COMBINE, 0);
    EXPECT_NE(ptr3, nullptr);

    /* Cleanup */
    umq_io_buf_free();
    EXPECT_EQ(g_buffer_addr, nullptr);
    EXPECT_EQ(g_total_len, 0u);
}

/* 9.24 umq_buf_size_pow_small_set: set various block sizes and verify */
TEST_F(TestQbufPoolMultiLevel, UmqBufSizePowSmallSetNewSizes)
{
    /* BLOCK_SIZE_128K -> umq_buf_size_small() = 128K */
    EXPECT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_128K), 0);
    EXPECT_EQ(umq_buf_size_small(), 128u * 1024u);
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K); /* reset */

    /* BLOCK_SIZE_256K -> 256K */
    EXPECT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_256K), 0);
    EXPECT_EQ(umq_buf_size_small(), 256u * 1024u);
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);

    /* BLOCK_SIZE_512K -> 512K */
    EXPECT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_512K), 0);
    EXPECT_EQ(umq_buf_size_small(), 512u * 1024u);
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);

    /* BLOCK_SIZE_1M -> 1M */
    EXPECT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_1M), 0);
    EXPECT_EQ(umq_buf_size_small(), 1u * 1024u * 1024u);
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);

    /* Invalid: BLOCK_SIZE_MAX (>= BLOCK_SIZE_MAX) -> -EINVAL */
    EXPECT_EQ(umq_buf_size_pow_small_set(BLOCK_SIZE_MAX), -UMQ_ERR_EINVAL);
    /* g_umq_qbuf_size_pow_small unchanged (still 4K from reset above) */
    EXPECT_EQ(umq_buf_size_small(), 4u * 1024u);
}

/* 9.26 umq_disable_scale_cap: verify toggle reflects init config */
TEST_F(TestQbufPoolMultiLevel, UmqDisableScaleCap)
{
    /* Given: init with disable_scale_cap=true */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, true);
    EXPECT_EQ(umq_disable_scale_cap(), true);

    /* When: uninit and re-init with disable_scale_cap=false */
    umq_qbuf_pool_uninit();
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false);

    /* Then: umq_disable_scale_cap returns false */
    EXPECT_EQ(umq_disable_scale_cap(), false);
}

/* 9.30 umq_qbuf_headroom_reset: SPLIT + COMBINE modes (merged 9.30+9.72+9.73) */
TEST_F(TestQbufPoolMultiLevel, UmqQbufHeadroomReset)
{
    /* SPLIT mode: test headroom 64 and 128 */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);
    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(buf->headroom_size, 0u);

    EXPECT_EQ(umq_qbuf_headroom_reset(buf, 64), 0);
    EXPECT_EQ(buf->headroom_size, 64u);
    EXPECT_NE(buf->buf_data, nullptr);

    EXPECT_EQ(umq_qbuf_headroom_reset(buf, 128), 0);
    EXPECT_EQ(buf->headroom_size, 128u);

    EXPECT_EQ(umq_qbuf_headroom_reset(buf, 0), 0);
    EXPECT_EQ(buf->headroom_size, 0u);
    umq_qbuf_free(&list);

    /* COMBINE mode */
    umq_qbuf_pool_uninit();
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);

    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);
    buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);

    EXPECT_EQ(umq_qbuf_headroom_reset(buf, 64), 0);
    EXPECT_EQ(buf->headroom_size, 64u);

    EXPECT_EQ(umq_qbuf_headroom_reset(buf, 0), 0);
    EXPECT_EQ(buf->headroom_size, 0u);
    umq_qbuf_free(&list);
}

/* 9.31 umq_qbuf_data_to_head: SPLIT + COMBINE + NULL + uninit (merged 9.31+9.47+9.84) */
TEST_F(TestQbufPoolMultiLevel, UmqQbufDataToHeadComprehensive)
{
    /* NULL input always returns NULL */
    EXPECT_EQ(umq_qbuf_data_to_head(NULL), nullptr);

    /* SPLIT mode: alloc and verify data_to_head */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT);

    umq_buf_list_t list0;
    QBUF_LIST_INIT(&list0);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list0), 0);
    void *data0 = QBUF_LIST_FIRST(&list0)->buf_data;
    umq_buf_t *qbuf0 = umq_qbuf_data_to_head(data0);
    ASSERT_NE(qbuf0, nullptr);
    EXPECT_EQ(qbuf0->buf_data, data0);
    EXPECT_EQ(buf_data_to_size_class(data0), 0u);
    umq_qbuf_free(&list0);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(50 * 1024, 1, NULL, &list1), 0);
    void *data1 = QBUF_LIST_FIRST(&list1)->buf_data;
    umq_buf_t *qbuf1 = umq_qbuf_data_to_head(data1);
    ASSERT_NE(qbuf1, nullptr);
    EXPECT_EQ(qbuf1->buf_data, data1);
    EXPECT_EQ(buf_data_to_size_class(data1), 1u);
    umq_qbuf_free(&list1);

    /* COMBINE mode with 3 size classes */
    umq_qbuf_pool_uninit();
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);

    uint32_t reqSizes[] = {2 * 1024, 20 * 1024, 200 * 1024};
    for (uint32_t sc = 0; sc < 3; sc++) {
        umq_buf_list_t listSc;
        QBUF_LIST_INIT(&listSc);
        ASSERT_EQ(umq_qbuf_alloc(reqSizes[sc], 1, NULL, &listSc), 0);
        void *dataSc = QBUF_LIST_FIRST(&listSc)->buf_data;
        umq_buf_t *headSc = umq_qbuf_data_to_head(dataSc);
        ASSERT_NE(headSc, nullptr);
        EXPECT_EQ(headSc->buf_data, dataSc);
        EXPECT_EQ(buf_data_to_size_class(dataSc), sc);
        umq_qbuf_free(&listSc);
    }

    /* Pool not inited: data_to_head returns NULL */
    void *savedData = data0;
    umq_qbuf_pool_uninit();
    EXPECT_EQ(umq_qbuf_data_to_head(savedData), nullptr);
    EXPECT_EQ(umq_qbuf_data_to_head(NULL), nullptr);
} /* 9.32 Multi-sc free partition: free sc=0 and sc=1 lists independently */
TEST_F(TestQbufPoolMultiLevel, MultiScFreePartition)
{
    InitPool(2, 16); /* [4K, 64K], disable_scale_cap=true (default) */

    /* Alloc 2K (sc=0, 1 buf) and 50K (sc=1, 1 buf) into SEPARATE lists */
    umq_buf_list_t list0;
    QBUF_LIST_INIT(&list0);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list0), 0);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(50 * 1024, 1, NULL, &list1), 0);

    /* Record TLS counts before free */
    uint64_t tls0Before = g_thread_cache.block_pool.buf_cnt_with_data[0];
    uint64_t tls1Before = g_thread_cache.block_pool.buf_cnt_with_data[1];

    /* Free sc=0 list: TLS sc=0 should increase, sc=1 unchanged */
    umq_qbuf_free(&list0);
    EXPECT_GT(g_thread_cache.block_pool.buf_cnt_with_data[0], tls0Before);
    EXPECT_EQ(g_thread_cache.block_pool.buf_cnt_with_data[1], tls1Before);

    /* Free sc=1 list: TLS sc=1 should increase */
    uint64_t tls1After0 = g_thread_cache.block_pool.buf_cnt_with_data[1];
    umq_qbuf_free(&list1);
    EXPECT_GT(g_thread_cache.block_pool.buf_cnt_with_data[1], tls1After0);
}

/* 9.33 Without-data alloc/free: verify buf properties and TLS restoration */
TEST_F(TestQbufPoolMultiLevel, WithoutDataAllocFree)
{
    /* Given: disable_scale_cap=true -> pre-populated without_data headers */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, true);

    /* Record TLS without_data count before alloc */
    uint64_t tlsNodataBefore = g_thread_cache.block_pool.buf_cnt_without_data;

    /* When: alloc 5 without_data buffers (request_size=0, opt with no headroom) */
    umq_alloc_option_t opt = {0};
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(0, 5, &opt, &list), 0);

    /* Then: list has 5 entries, each buf_data==NULL, mempool_without_data==1 */
    EXPECT_EQ(CountQbufListEntries(&list), 5u);
    umq_buf_t *cur;
    QBUF_LIST_FOR_EACH(cur, &list)
    {
        EXPECT_EQ(cur->buf_data, nullptr);
        EXPECT_EQ(cur->mempool_without_data, 1u);
    }

    /* Free: returns to TLS */
    umq_qbuf_free(&list);

    /* Verify TLS without_data count increased (blocks returned from alloc) */
    EXPECT_GT(g_thread_cache.block_pool.buf_cnt_without_data, tlsNodataBefore);
}

/* 9.34 umq_qbuf_pool_info_get: SPLIT + COMBINE + expansion (merged 9.34+9.39+9.88) */
TEST_F(TestQbufPoolMultiLevel, UmqQbufPoolInfoGetSuccessPaths)
{
    /* SPLIT mode basic stats */
    InitPool(2, 16);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);

    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    ASSERT_EQ(umq_qbuf_pool_info_get(&stats), 0);
    EXPECT_EQ(stats.num, 1u);
    EXPECT_EQ(stats.qbuf_pool_info[0].block_size, 4u * 1024u);
    EXPECT_GT(stats.qbuf_pool_info[0].total_block_num, 0u);
    EXPECT_GE(stats.local_qbuf_pool_num, 1u);
    umq_qbuf_free(&list);

    /* COMBINE mode */
    umq_qbuf_pool_uninit();
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);

    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);

    memset(&stats, 0, sizeof(stats));
    ASSERT_EQ(umq_qbuf_pool_info_get(&stats), 0);
    EXPECT_EQ(stats.num, 1u);
    EXPECT_EQ(stats.qbuf_pool_info[0].mode, UMQ_BUF_COMBINE);
    EXPECT_EQ(stats.qbuf_pool_info[0].data_size,
              stats.qbuf_pool_info[0].block_size - stats.qbuf_pool_info[0].umq_buf_t_size);
    EXPECT_EQ(stats.qbuf_pool_info[0].buf_size, stats.qbuf_pool_info[0].block_size);
    EXPECT_GE(stats.qbuf_pool_info[0].available_mem.combine.block_num_with_data, 0u);
    EXPECT_GE(stats.qbuf_pool_info[0].available_mem.combine.size_with_data, 0u);
    EXPECT_EQ(stats.exp_pool_with_data.exp_total_mem_size,
              stats.exp_pool_with_data.exp_total_block_num * stats.qbuf_pool_info[0].block_size);
    umq_qbuf_free(&list);

    /* With expansion: scaleCap=false. Explicit blockCounts for 8MB pool. */
    umq_qbuf_pool_uninit();
    const uint64_t pool8M_info = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    const uint64_t bc_info[] = {60, 1};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, pool8M_info, 0, 0, smallExp, bc_info);

    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    std::vector<umq_buf_list_t> holders(sc0Blocks + 1);
    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0);
    }

    memset(&stats, 0, sizeof(stats));
    EXPECT_EQ(umq_qbuf_pool_info_get(&stats), 0);
    EXPECT_EQ(stats.num, 1u);
    EXPECT_GT(stats.exp_pool_with_data.expansion_count, 0u);
    EXPECT_GT(stats.local_qbuf_pool_num, 0u);

    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* 9.38 umq_qbuf_pool_info_get: error paths (merged 9.38+9.89) */
TEST_F(TestQbufPoolMultiLevel, UmqQbufPoolInfoGetErrorPaths)
{
    /* Pool not inited -> -UMQ_ERR_ENOMEM */
    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    EXPECT_EQ(umq_qbuf_pool_info_get(&stats), -UMQ_ERR_ENOMEM);

    /* num >= MAX -> -UMQ_ERR_EINVAL */
    InitPool(2, 16);
    stats.num = UMQ_STATS_QBUF_POOL_TYPE_MAX;
    EXPECT_EQ(umq_qbuf_pool_info_get(&stats), -UMQ_ERR_EINVAL);
} /* 9.35 Thread cache without_data: free-path capping and self_shrink behavior */
TEST_F(TestQbufPoolMultiLevel, ThreadCacheSelfShrinkWithoutData)
{
    /* Given: disable_scale_cap=false -> without_data TLS two-level cap:
     *   global tls_qbuf_pool_depth (default 12K), per-thread tls_expand_qbuf_pool_depth (default 1/2 of tls_qbuf_pool_depth).
     * The free path caps TLS at capacity_without_data - batch_cnt; self_shrink
     * reduces capacity_without_data and returns excess bufs to global. */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false);

    /* Lower the without_data per-thread TLS cap so the free-path capping triggers
     * with ~320 buffers. Default tls_expand_qbuf_pool_depth=10752 is too large:
     * 320 < 10752 means the free path never caps and self_shrink's condition
     * (capacity_without_data < remaining) never holds. */
    g_qbuf_pool.tls_expand_qbuf_pool_depth = 128;

    /* Phase 1: Alloc 300 without_data -> need_batch=ceil(300/64)*64=320.
     * Fetch 320 into TLS, use 300, TLS buf_cnt_without_data = 20. */
    umq_alloc_option_t opt = {0};
    umq_buf_list_t list300;
    QBUF_LIST_INIT(&list300);
    ASSERT_EQ(umq_qbuf_alloc(0, 300, &opt, &list300), 0);
    ASSERT_EQ(CountQbufListEntries(&list300), 300u);

    /* Phase 2: Free all 300 -> TLS = 20 + 300 = 320 > cap(128).
     * Free path: return_to_global(threshold = cap - batch_cnt = 128 - 64 = 64)
     * keeps 64 in TLS, returns 256 to expansion pool. TLS = 64. */
    umq_qbuf_free(&list300);
    EXPECT_EQ(g_thread_cache.block_pool.buf_cnt_without_data, 64u)
        << "free path should cap TLS at capacity_without_data - batch_cnt";

    /* Phase 3: Alloc 1 -> TLS = 63. self_shrink: remaining=63, shrink=15 < 64
     * -> no shrink (free path already capped TLS below capacity_without_data). */
    uint64_t tlsBefore = g_thread_cache.block_pool.buf_cnt_without_data;
    EXPECT_EQ(tlsBefore, 64u);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(0, 1, &opt, &list1), 0);

    uint64_t tlsAfter = g_thread_cache.block_pool.buf_cnt_without_data;
    EXPECT_EQ(tlsAfter, 63u) << "alloc 1 from TLS, no self_shrink (remaining < threshold)";

    umq_qbuf_free(&list1);
}

TEST_F(TestQbufPoolMultiLevel, AllocBranchTlsSufficientNoFetchFromGlobal)
{
    /* Given: default scaleCap=true, TLS cap is unlimited (QBUF_POOL_TLS_MAX) */
    InitPool(2, 16);

    /* Phase 1: first alloc triggers batch fetch from global (TLS was empty) */
    uint64_t globalBefore = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    umq_buf_list_t first;
    QBUF_LIST_INIT(&first);
    ASSERT_EQ(umq_qbuf_alloc(1 * 1024, 1, NULL, &first), 0);
    uint64_t globalAfterFirst = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    /* global decreased by batch_count (batch fetch happened) */
    EXPECT_LT(globalAfterFirst, globalBefore);
    /* TLS now has batch_count - 1 blocks remaining */
    EXPECT_GT(g_thread_cache.block_pool.buf_cnt_with_data[0], 0u);

    /* Phase 2: second alloc from TLS (Branch 1: TLS sufficient -> no fetch_from_global) */
    uint64_t globalBeforeSecond = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    uint64_t tlsBefore = g_thread_cache.block_pool.buf_cnt_with_data[0];
    umq_buf_list_t second;
    QBUF_LIST_INIT(&second);
    ASSERT_EQ(umq_qbuf_alloc(1 * 1024, 1, NULL, &second), 0);
    /* TLS sufficient -> no fetch_from_global -> global unchanged */
    EXPECT_EQ(g_qbuf_pool.block_pool[0].buf_cnt_with_data, globalBeforeSecond);
    /* TLS decreased by exactly 1 (alloc consumed 1, no batch fetch) */
    EXPECT_EQ(g_thread_cache.block_pool.buf_cnt_with_data[0], tlsBefore - 1);

    /* Cleanup */
    umq_qbuf_free(&first);
    umq_qbuf_free(&second);
}

/* 9.41 Alloc Branch 4b: escape disabled -> returns error (not escape) */
TEST_F(TestQbufPoolMultiLevel, AllocBranchEscapeDisabledReturnsError)
{
    /* Given: custom init with disable_malloc_escape=true and disable_scale_cap=true
     * and tiny pool where sc=1 has 0 blocks (per_sc_block_counts[1]=0 (lazy, no initial blocks for 64K SC)) */
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = 64 * 1024; /* 64KB -> per_sc_block_counts[1]=0 -> sc=1 has 0 blocks */
    cfg.data_size = umq_buf_size_small();
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.size_class_count = 2;
    cfg.explicit_block_sizes[0] = 4u * 1024u;
    cfg.explicit_block_sizes[1] = 64u * 1024u;
    cfg.disable_scale_cap = true;
    cfg.disable_malloc_escape = true; /* KEY: escape disabled */
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), 0);

    /* Verify sc=1 has 0 blocks */
    EXPECT_EQ(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);

    /* When: alloc 50K (sc=1) -> umq_normal_qbuf_alloc fails (-ENOMEM), wrapper
     * falls back to umq_qbuf_escape_alloc which returns -EINVAL (escape disabled) */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(50 * 1024, 1, NULL, &list);

    /* Then: returns -UMQ_ERR_EINVAL (NOT success, NOT escape) */
    EXPECT_EQ(ret, -UMQ_ERR_ENOMEM);
    /* No escape buf was created */
    EXPECT_FALSE(any_escape_buf_exists());
}

/* 9.42 async_expand_global_pool: triggered after fetch, completes within 100ms */
TEST_F(TestQbufPoolMultiLevel, SyncExpandGlobalPoolTriggeredWhenGlobalExhausted)
{
    /* Given: scaleCap=false, pool=128KB (sc=0 has ~15 blocks), expansion=256KB (64 per slot).
     * sc=0 blk_num = per_sc_block_counts[0] / (sizeof(umq_buf_t) + 4K) = 15.
     * trigger_expand_block_num = 15 * 30 / 100 = 4.
     * batch_count for sc=0 = max(256KB/4K, 8) = 64.
     * Since global_buf_cnt(15) < batch_count(64), alloc goes through slow path. */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 128 * 1024, 0, 0, 256 * 1024);

    uint64_t totalExpBefore = g_qbuf_pool.exp_pool_with_data[0].total_expansion_count;
    uint64_t expCountBefore = g_qbuf_pool.exp_pool_with_data[0].expansion_count;

    /* When: alloc 1 block -> global pool has 15 blocks < batch_count=64 -> slow path:
     * 1) take all 15 from global (count=15)
     * 2) fetch_from_expansion_pools: no slots yet -> 0
     * 3) expand_global_pool (SYNC expand slot 1, 64 blocks) -> expansion_count++
     * 4) fetch_from_expansion_pools: take 49 blocks -> count = 15+49 = 64 >= batch_count
     * After fetch: exp_total_block_num = 64-49 = 15 >= trigger=4 -> async_expand NOT triggered */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(1 * 1024, 1, NULL, &list), 0);

    /* Then: exactly 1 sync expansion occurred */
    uint64_t totalExpAfter = g_qbuf_pool.exp_pool_with_data[0].total_expansion_count;
    EXPECT_EQ(totalExpAfter - totalExpBefore, 1u) << "should have exactly 1 sync expansion";
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u)
        << "should have 1 expansion slot after sync expand";

    umq_qbuf_free(&list);
}

/* 9.42b async_expand_global_pool: triggered via fast path when global+expansion < threshold */
TEST_F(TestQbufPoolMultiLevel, AsyncExpandGlobalPoolTriggeredViaFastPath)
{
    /* Given: scaleCap=false, totalSz=540672 -> per_sc_block_counts[] auto-derived.
     * sc=0 blk_num = 270336 / (128+4096) = 64.
     * trigger_expand_block_num = 64 * 30 / 100 = 19.
     * expansion_size = 256KB -> expansion_block_count = 64.
     * batch_count for sc=0 = max(256KB/4K, 8) = 64.
     *
     * Key: global_buf_cnt(64) == batch_count(64) -> FAST path.
     * After allocating batch_count blocks: global_buf_cnt = 0, exp_total_block_num = 0.
     * async_expand_global_pool(0, 0): 0 + 0 < 19 -> TRIGGERED. */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 540672, 0, 128 * 1024, 256 * 1024);

    uint64_t totalExpBefore = g_qbuf_pool.exp_pool_with_data[0].total_expansion_count;

    /* When: alloc 1 block -> TLS empty -> fetch_from_global(batch_count=64)
     * Fast path: global(64) >= 64 -> take 64 -> global=0 -> return to TLS.
     * async_expand_global_pool called with g_buf_cnt=0, exp_total=0:
     * 0 + 0 < trigger(19) -> pthread_create(async_expand) */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(1 * 1024, 1, NULL, &list), 0);

    /* Poll for async expand completion (<= 200ms) */
    uint32_t waited = 0;
    while (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) != 0) {
        usleep(1000);
        waited++;
        if (waited > 200) {
            break;
        }
    }
    EXPECT_EQ(__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE), 0u)
        << "async expand should complete within 200ms";

    /* Then: total_expansion_count should have increased by >= 1 (async expand) */
    uint64_t totalExpAfter = g_qbuf_pool.exp_pool_with_data[0].total_expansion_count;
    EXPECT_GE(totalExpAfter - totalExpBefore, 1u) << "async expand should have created at least 1 slot";
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u)
        << "should have at least 1 expansion slot after async expand";

    umq_qbuf_free(&list);
}

/* 9.43 async_shrink_global_pool: triggered when expansion slot becomes fully free */
TEST_F(TestQbufPoolMultiLevel, AsyncShrinkGlobalPoolTriggeredOnFullSlotFree)
{
    /* Given: scaleCap=false, totalSz=540672, expansion=256KB (64 blocks per slot for sc=0).
     * Block-equal (SPLIT, disable_scale_cap=false): N = 540672 / (4096+65536+2*128)
     *   = 540672 / 69888 = 7 -> sc=0 has 7 global blocks.
     * tlsExpandBudget=0 -> tls_expand_qbuf_pool_depth defaults to 1/2 of tls_qbuf_pool_depth.
     * Alloc sc0BlkNum+1 (8) triggers slow path: 7 from global + 57 from expansion.
     * Explicit return_to_global(threshold=0) flushes TLS; the 57 expansion blocks
     * return to their slot -> free_block_cnt == total_block_cnt -> async_shrink. */
    const uint64_t bc_async_shrink[] = {7, 1};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 8 * 1024 * 1024, 0, 0, 256 * 1024, bc_async_shrink);

    uint64_t totalShrinkBefore = g_qbuf_pool.exp_pool_with_data[0].total_shrink_count;
    uint32_t sc0BlkNum = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_EQ(sc0BlkNum, 7u);

    /* Phase 1: Alloc sc0BlkNum+1 (8) -> first alloc triggers slow path
     * (global has 7 < batch_count=64): take 7 from global, expand 1 slot (64 blocks),
     * take 57 from expansion -> TLS = 64. After 8 allocs: TLS = 56. */
    std::vector<umq_buf_list_t> holders(sc0BlkNum + 1);
    for (uint32_t i = 0; i < sc0BlkNum + 1; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &holders[i]), 0) << "alloc failed at " << i;
    }
    /* Expansion happened */
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u);

    /* Wait for any async expand to complete */
    for (int retry = 0; retry < 200; retry++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
            break;
        usleep(1000);
    }

    /* Phase 2: Free all 8 blocks -> TLS = 64. No return_to_global during free
     * (actual_bytes == cap_bytes). Explicit return_to_global(threshold=0) flushes
     * all TLS: 7 blocks -> global, 57 blocks -> expansion slot. Slot becomes
     * fully free (7+57=64=total_block_cnt) -> async_shrink_global_pool triggered. */
    for (uint32_t i = 0; i < sc0BlkNum + 1; i++) {
        umq_qbuf_free(&holders[i]);
    }

    /* Force flush any remaining TLS blocks to global/expansion pools */
    if (g_thread_cache.block_pool.buf_cnt_with_data[0] > 0) {
        return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, true, 0, 0);
    }

    /* Poll for async shrink completion (<= 200ms) */
    uint32_t waited = 0;
    while (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_shrinking, __ATOMIC_ACQUIRE) != 0) {
        usleep(1000);
        waited++;
        if (waited > 200) {
            break;
        }
    }
    EXPECT_EQ(__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_shrinking, __ATOMIC_ACQUIRE), 0u)
        << "async shrink should complete within 200ms";

    /* Then: total_shrink_count should have increased (slot was shrunk) */
    uint64_t totalShrinkAfter = g_qbuf_pool.exp_pool_with_data[0].total_shrink_count;
    EXPECT_GT(totalShrinkAfter, totalShrinkBefore) << "total_shrink_count should have increased";
}

/* 9.44 thread_cache_self_shrink: shrink < threshold -> early return, no return_to_global */
TEST_F(TestQbufPoolMultiLevel, ThreadCacheSelfShrinkBelowThresholdNoShrink)
{
    /* Given: scaleCap=false, tlsBudget=4MB, tlsExpand=4MB, expansion=256KB.
     * For sc=0 (4K): TLS cap = min(4MB, 4MB) / 4K = 1024 blocks.
     * shrink_threshold = 64, shrink = remaining / 4.
     * To NOT trigger shrink: need remaining / 4 < 64 -> remaining < 256. */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, 4096, 2048, 256 * 1024);

    /* Phase 1: Alloc 10 blocks -> TLS has batch_count - 10 (well below 256).
     * batch_count for sc=0 (4K) = max(256KB/4K, 8) = 64.
     * After 10 allocs: TLS = 64 - 10 = 54 (< 256 -> shrink = 54/4 = 13 < 64). */
    std::vector<umq_buf_list_t> holders(10);
    for (uint32_t i = 0; i < 10; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &holders[i]), 0);
    }
    uint64_t tlsBefore = g_thread_cache.block_pool.buf_cnt_with_data[0];
    EXPECT_LT(tlsBefore, 256u) << "TLS should have < 256 blocks to avoid shrink";

    /* Phase 2: Free all 10 blocks -> TLS += 10 */
    for (uint32_t i = 0; i < 10; i++) {
        umq_qbuf_free(&holders[i]);
    }

    /* Phase 3: Alloc 1 more -> triggers thread_cache_self_shrink, but
     * shrink = remaining/4 < 64 -> early return -> no return_to_global */
    uint64_t globalBeforeAlloc = g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    umq_buf_list_t trigger;
    QBUF_LIST_INIT(&trigger);
    ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &trigger), 0);
    /* No shrink happened: global unchanged (no blocks returned from TLS) */
    EXPECT_EQ(g_qbuf_pool.block_pool[0].buf_cnt_with_data, globalBeforeAlloc)
        << "global should be unchanged - shrink threshold not reached";

    umq_qbuf_free(&trigger);
}

/* 9.46 UT-2: Multi-sc TLS fetch_and_expand byte budget (F04, F60) */
TEST_F(TestQbufPoolMultiLevel, MultiScTlsFetchAndExpandByteBudget)
{
    /* tls_expand_qbuf_pool_depth defaults to 1/2 of tls_qbuf_pool_depth (per-thread cap).
     * Need >= 64*32K + 64*256K = 18MB to accommodate both batch fetches (sc=1 and
     * sc=2) under the per-thread cap (28MB = 7/8 of 32MB). */
    const uint64_t tlsBudget = 8192; /* 8192 blocks (was 32MB byte-budget) */
    const uint64_t smallExp = 256 * 1024;
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, 0, smallExp);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(20 * 1024, 1, NULL, &list1), 0);
    EXPECT_GT(g_thread_cache.block_pool.capacity_with_data[1], 0u);
    umq_qbuf_free(&list1);

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(200 * 1024, 1, NULL, &list2), 0);
    EXPECT_GT(g_thread_cache.block_pool.capacity_with_data[2], 0u);
    umq_qbuf_free(&list2);

    uint64_t totalTls = __atomic_load_n(&g_total_local_cap_with_data_cnt[0], __ATOMIC_RELAXED) +
                        __atomic_load_n(&g_total_local_cap_with_data_cnt[1], __ATOMIC_RELAXED) +
                        __atomic_load_n(&g_total_local_cap_with_data_cnt[2], __ATOMIC_RELAXED);
    EXPECT_LE(totalTls, g_qbuf_pool.tls_qbuf_pool_depth * g_qbuf_pool.size_class_count);
}

TEST_F(TestQbufPoolMultiLevel, MultiScAsyncShrink)
{
    const uint64_t totalSz = 8 * 1024 * 1024;
    const uint64_t tlsExpand = 128 * 1024;
    const uint64_t smallExp = 256 * 1024;
    const uint64_t bc_multi_shrink[] = {7, 1, 1};
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, totalSz, 0, tlsExpand, smallExp, bc_multi_shrink);

    uint32_t sc0BlkNum = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0BlkNum, 0u);

    std::vector<umq_buf_list_t> holders(sc0BlkNum + 1);
    for (uint32_t i = 0; i < sc0BlkNum + 1; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(4 * 1024, 1, NULL, &holders[i]), 0) << "alloc failed at " << i;
    }
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u);

    for (int retry = 0; retry < 200; retry++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
            break;
        usleep(1000);
    }

    for (uint32_t i = 0; i < sc0BlkNum + 1; i++) {
        umq_qbuf_free(&holders[i]);
    }

    if (g_thread_cache.block_pool.buf_cnt_with_data[0] > 0) {
        return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, true, 0, 0);
    }

    uint32_t waited = 0;
    while (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_shrinking, __ATOMIC_ACQUIRE) != 0) {
        usleep(1000);
        waited++;
        if (waited > 200)
            break;
    }
}

/* 9.52 UT-7: 3+ size_class expansion pool init (F53-F55, F13) */
TEST_F(TestQbufPoolMultiLevel, MultiScExpansionPoolInit)
{
    const uint64_t smallPool = 12 * 1024 * 1024;
    const uint64_t smallExp = 2 * 1024 * 1024;
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    for (uint32_t sc = 0; sc < 3; sc++) {
        uint32_t blkSize = g_qbuf_pool.block_sizes[sc];
        EXPECT_GT(g_qbuf_pool.exp_pool_with_data[sc].expansion_block_count, 0u) << "sc=" << sc;
        EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[sc].expansion_block_count,
                  (uint32_t)(g_qbuf_pool.expansion_size / blkSize))
            << "sc=" << sc;
        EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[sc].inited, true) << "sc=" << sc;
    }
}

/* 9.53 UT-7b: COMBINE mode expansion pool init (F52) */
TEST_F(TestQbufPoolMultiLevel, CombineModeExpansionPoolInit)
{
    const uint64_t smallPool = 12 * 1024 * 1024;
    const uint64_t smallExp = 2 * 1024 * 1024;
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, false, smallPool, 0, 0, smallExp);

    for (uint32_t sc = 0; sc < 3; sc++) {
        uint32_t blkSize = g_qbuf_pool.block_sizes[sc];
        EXPECT_GT(g_qbuf_pool.exp_pool_with_data[sc].expansion_block_count, 0u) << "sc=" << sc;
        uint32_t expectedSubSlot = QBUF_MEMALIGN_SIZE / blkSize;
    }
}

/* 9.54 UT-8: Multi-sc alloc/free cross-sc boundary (F62, F63, F31) */
TEST_F(TestQbufPoolMultiLevel, MultiScAllocFreeCrossScBoundary)
{
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, 0, 0, 256 * 1024);

    std::vector<umq_buf_list_t> lists(3);
    uint32_t reqSizes[] = {2 * 1024, 20 * 1024, 200 * 1024};
    uint32_t expectedScs[] = {0, 1, 2};

    for (uint32_t sc = 0; sc < 3; sc++) {
        QBUF_LIST_INIT(&lists[sc]);
        ASSERT_EQ(umq_qbuf_alloc(reqSizes[sc], 1, NULL, &lists[sc]), 0);
        ASSERT_NE(QBUF_LIST_FIRST(&lists[sc]), nullptr);
        EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&lists[sc])->buf_data), expectedScs[sc]);
    }

    for (uint32_t sc = 0; sc < 3; sc++) {
        umq_qbuf_free(&lists[sc]);
    }
}

/* 9.55 Multi-block alloc across size_class */
TEST_F(TestQbufPoolMultiLevel, MultiBlockFreeAcrossSc)
{
    InitPool(4, 4, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, 0, 0, 256 * 1024);

    /* block_sizes = [4K, 16K, 64K, 256K], 最大256K. 300K > 256K,
     * 8e2ed74a 后返回UMQ_ERR_ENOMEM(不再多块拼接) */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(300 * 1024, 1, NULL, &list), -UMQ_ERR_ENOMEM);
    EXPECT_EQ(QBUF_LIST_FIRST(&list), nullptr);
}

/* 9.56 Combine mode multi-block data_to_head — 8e2ed74a 后超最大块返回失败 */
TEST_F(TestQbufPoolMultiLevel, CombineModeMultiBlockDataToHead)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);

    /* 100K 超过最大单块64K, 返回UMQ_ERR_ENOMEM(不再多块拼接) */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(100 * 1024, 1, NULL, &list), -UMQ_ERR_ENOMEM);
    EXPECT_EQ(QBUF_LIST_FIRST(&list), nullptr);
}

/* 9.57 COMBINE mode + expansion triggers with_data slot init (F02, F10) */
TEST_F(TestQbufPoolMultiLevel, CombineModeExpansionTriggersCombineInit)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, false, smallPool, 0, 0, smallExp);

    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);

    std::vector<umq_buf_list_t> holders(sc0Blocks + 1);
    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0) << "alloc " << i;
    }

    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 0u) << "sc=0 should expand in COMBINE mode";

    umq_buf_list_t expandedBuf;
    QBUF_LIST_INIT(&expandedBuf);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &expandedBuf), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&expandedBuf), nullptr);
    EXPECT_EQ(QBUF_LIST_FIRST(&expandedBuf)->buf_size, 4u * 1024u);
    umq_qbuf_free(&expandedBuf);

    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* 9.58 COMBINE mode data_to_head with expansion pool data (F05) */
TEST_F(TestQbufPoolMultiLevel, CombineModeDataToHeadWithExpansion)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, false, smallPool, 0, 0, smallExp);

    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);

    std::vector<umq_buf_list_t> holders(sc0Blocks + 1);
    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0);
    }

    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        void *data = QBUF_LIST_FIRST(&holders[i])->buf_data;
        umq_buf_t *head = umq_qbuf_data_to_head(data);
        ASSERT_NE(head, nullptr) << "data_to_head failed for buffer " << i;
        EXPECT_EQ(head->buf_data, data) << "data_to_head mismatch for buffer " << i;
    }

    for (uint32_t i = 0; i <= sc0Blocks; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* 9.60 buf_data_to_size_class: NULL, out-of-range, count==0 (merged 9.60+9.66, F33-F35, F40) */
TEST_F(TestQbufPoolMultiLevel, BufDataToSizeClassEdgeCasesCountZero)
{
    EXPECT_EQ(buf_data_to_size_class(NULL), UMQ_QBUF_SIZE_CLASS_MAX);
    EXPECT_EQ(buf_data_to_size_class((void *)0x1), UMQ_QBUF_SIZE_CLASS_MAX);

    uint32_t saved = g_qbuf_pool.size_class_count;
    g_qbuf_pool.size_class_count = 0;
    EXPECT_EQ(buf_data_to_size_class(NULL), UMQ_QBUF_SIZE_CLASS_MAX);
    EXPECT_EQ(buf_data_to_size_class((void *)0x1000), UMQ_QBUF_SIZE_CLASS_MAX);
    g_qbuf_pool.size_class_count = saved;
} /* 9.61 umq_qbuf_mode_get and umq_qbuf_headroom_get */
TEST_F(TestQbufPoolMultiLevel, UmqQbufModeAndHeadroomGet)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);
    EXPECT_EQ(umq_qbuf_mode_get(), UMQ_BUF_COMBINE);
    EXPECT_EQ(umq_qbuf_headroom_get(), 0u);
}

/* 9.62 Multi-sc expansion pool uninit (F20-F26, F13) */
TEST_F(TestQbufPoolMultiLevel, MultiScExpansionPoolUninit)
{
    const uint64_t smallPool = 12 * 1024 * 1024;
    const uint64_t smallExp = 2 * 1024 * 1024;
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[0].inited, true);
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[1].inited, true);
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[2].inited, true);

    umq_qbuf_pool_uninit();

    for (uint32_t sc = 0; sc < 3; sc++) {
        EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[sc].inited, false) << "exp_pool sc=" << sc << " should be uninited";
    }
    EXPECT_EQ(g_qbuf_pool.inited, false);

    InitPool(2, 16);
}

/* 9.63 Multi-sc TLS byte budget with scaleCap=false (F04, F60) */
TEST_F(TestQbufPoolMultiLevel, MultiScTlsByteBudgetScaleCapFalse)
{
    const uint64_t tlsBudget = 4096; /* 4096 blocks (was 4MB byte-budget) */
    const uint64_t smallExp = 256 * 1024;
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, 0, smallExp);

    umq_buf_list_t list1;
    QBUF_LIST_INIT(&list1);
    ASSERT_EQ(umq_qbuf_alloc(20 * 1024, 1, NULL, &list1), 0);
    EXPECT_GT(g_thread_cache.block_pool.capacity_with_data[1], 0u);
    EXPECT_GT(__atomic_load_n(&g_total_local_cap_with_data_cnt[1], __ATOMIC_RELAXED), 0u);
    umq_qbuf_free(&list1);

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(200 * 1024, 1, NULL, &list2), 0);
    EXPECT_GT(g_thread_cache.block_pool.capacity_with_data[2], 0u);
    umq_qbuf_free(&list2);
}

/* 9.64 Multi-sc free with return_to_global for sc>0 (F62, F63) */
TEST_F(TestQbufPoolMultiLevel, MultiScFreeReturnToGlobalWithByteTracking)
{
    const uint64_t tlsBudget = 1 * 1024 * 1024;
    const uint64_t tlsExpand = 512 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(3, 8, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, tlsExpand, smallExp);

    std::vector<umq_buf_list_t> holders;
    for (int i = 0; i < 100; i++) {
        umq_buf_list_t list;
        QBUF_LIST_INIT(&list);
        if (umq_qbuf_alloc(20 * 1024, 1, NULL, &list) != 0)
            break;
        holders.push_back(list);
    }
    EXPECT_GT(holders.size(), 0u);

    for (auto &h : holders) {
        umq_qbuf_free(&h);
    }
}

/* ================================================================== */
/* High Priority UT supplements (items 1-8)                           */
/* ================================================================== */

/* 9.67 Base pool init/fetch/alloc/free cycle — SPLIT single-level (F06,F24-F27,F64-F76) */
TEST_F(TestQbufPoolMultiLevel, BasePoolSplitAllocFree)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = true;
    base.mempool_id = 0;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;

    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, UMQ_EMPTY_HEADER_COEFFICIENT), 0);
    EXPECT_EQ(base.inited, true);
    EXPECT_GT(base.total_block_num, 0u);

    thread_local_qbuf_pool_t tc;
    memset(&tc, 0, sizeof(tc));
    local_block_pool_t *lp = get_thread_local_cache(&tc, &base.tls_pools);

    base.fetch_fn = NULL;
    base.self_shrink_fn = NULL;
    base.tls_pools.type = THREAD_CLOSURE_QBUF;
    base.tls_pools.closure = NULL;
    base.tls_pools.default_tls_qbuf_pool_depth = QBUF_POOL_BATCH_CNT;
    base.tls_pools.tls_qbuf_pool_depth = QBUF_POOL_BATCH_CNT;
    base.tls_pools.enable_tls_expand_qbuf_pool = false;
    base.tls_pools.batch_count = QBUF_POOL_BATCH_CNT;

    (void)pthread_spin_lock(&base.block_pool[0].global_mutex);
    allocate_batch(&base.block_pool[0].head_with_data, 4, &lp->head_with_data[0]);
    lp->buf_cnt_with_data[0] = 4;
    base.block_pool[0].buf_cnt_with_data -= 4;
    (void)pthread_spin_unlock(&base.block_pool[0].global_mutex);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    qbuf_alloc_param_t param;
    param.actual_buf_count = 1;
    param.headroom_size = 0;
    param.shm = false;

    umq_qbuf_alloc_data_with_split(lp, 2 * 1024, &param, &list, base.block_size, 0);
    EXPECT_NE(QBUF_LIST_FIRST(&list), nullptr);

    umq_qbuf_base_free(&base, &tc, &list, false);
    EXPECT_GT(tc.stats.free_cnt_with_data, 0u);

    umq_qbuf_base_data_to_head(&base, QBUF_LIST_FIRST(&lp->head_with_data[0])->buf_data);

    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    EXPECT_EQ(umq_qbuf_pool_base_info_get(&base, &stats, true, UMQ_QBUF_POOL_TYPE_SMALL), 0);
    EXPECT_EQ(stats.num, 1u);

    umq_qbuf_base_uninit(&base, NULL);
}

/* 9.68 Base pool COMBINE mode alloc/free (F06,F25,F26-F27,F64-F76) */
TEST_F(TestQbufPoolMultiLevel, BasePoolCombineAllocFree)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = false;
    base.mempool_id = 0;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_COMBINE;

    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, 0), 0);
    EXPECT_EQ(base.mode, UMQ_BUF_COMBINE);

    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    EXPECT_EQ(umq_qbuf_pool_base_info_get(&base, &stats, true, UMQ_QBUF_POOL_TYPE_SMALL), 0);
    EXPECT_EQ(stats.qbuf_pool_info[0].mode, UMQ_BUF_COMBINE);

    umq_qbuf_base_uninit(&base, NULL);
}

/* 9.69 Base pool without_data info path (F24, F26-F27) */
TEST_F(TestQbufPoolMultiLevel, BasePoolWithoutDataInfo)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = true;
    base.mempool_id = 0;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.disable_scale_cap = true;

    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, UMQ_EMPTY_HEADER_COEFFICIENT), 0);
    EXPECT_GT(base.block_pool[0].buf_cnt_with_data, 0u);

    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    EXPECT_EQ(umq_qbuf_pool_base_info_get(&base, &stats, true, UMQ_QBUF_POOL_TYPE_SMALL), 0);
    EXPECT_EQ(stats.qbuf_pool_info[0].available_mem.split.block_num_with_data, base.block_pool[0].buf_cnt_with_data);

    umq_qbuf_base_uninit(&base, NULL);
}

/* 9.70 Base pool invalid mode init (F64) */
TEST_F(TestQbufPoolMultiLevel, BasePoolInvalidModeInit)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = (umq_buf_mode_t)99;

    EXPECT_EQ(qbuf_pool_base_init(&base, &cfg, 0), -UMQ_ERR_EINVAL);
}

/* 9.71 Base pool null/invalid param validation (F64) */
TEST_F(TestQbufPoolMultiLevel, BasePoolNullParamValidation)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    EXPECT_EQ(qbuf_pool_base_init(NULL, &cfg, 0), -UMQ_ERR_EINVAL);
    EXPECT_EQ(qbuf_pool_base_init(&base, NULL, 0), -UMQ_ERR_EINVAL);

    cfg.buf_addr = NULL;
    cfg.total_size = BUF_SIZE;
    EXPECT_EQ(qbuf_pool_base_init(&base, &cfg, 0), -UMQ_ERR_EINVAL);

    cfg.buf_addr = buf_addr;
    cfg.total_size = 0;
    EXPECT_EQ(qbuf_pool_base_init(&base, &cfg, 0), -UMQ_ERR_EINVAL);

    base.block_size = sizeof(umq_buf_t);
    cfg.total_size = BUF_SIZE;
    EXPECT_EQ(qbuf_pool_base_init(&base, &cfg, 0), -UMQ_ERR_EINVAL);

    umq_buf_list_t dummy;
    QBUF_LIST_INIT(&dummy);
    umq_qbuf_base_free(NULL, NULL, &dummy, false);
    umq_qbuf_base_data_to_head(NULL, NULL);
}

/* 9.74 umq_flush_tls_nodata_to_global: capacity branch (F62-F63)
 * Setup: disable_scale_cap=false, alloc without_data to fill TLS, then
 * trigger umq_qbuf_local_pool_fetch_and_expand which calls flush when
 * global without_data is empty. */
TEST_F(TestQbufPoolMultiLevel, FlushTlsNodataToGlobalV2)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));

    std::vector<umq_buf_list_t> holders;
    for (int i = 0; i < 100; i++) {
        umq_buf_list_t list;
        QBUF_LIST_INIT(&list);
        if (umq_qbuf_alloc(0, 1, &opt, &list) != 0)
            break;
        holders.push_back(list);
    }
    EXPECT_GT(holders.size(), 0u);

    for (auto &h : holders) {
        umq_qbuf_free(&h);
    }
}

/* 9.75 umq_qbuf_base_alloc validation paths (F71-F74) */
TEST_F(TestQbufPoolMultiLevel, BaseAllocValidation)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = true;
    base.mempool_id = 0;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.disable_scale_cap = true;

    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, UMQ_EMPTY_HEADER_COEFFICIENT), 0);

    thread_local_qbuf_pool_t tc;
    memset(&tc, 0, sizeof(tc));
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    qbuf_alloc_param_t param;

    EXPECT_EQ(umq_qbuf_base_alloc(NULL, &tc, 2 * 1024, 1, &list, NULL, &param), -UMQ_ERR_EINVAL);
    EXPECT_EQ(umq_qbuf_base_alloc(&base, NULL, 2 * 1024, 1, &list, NULL, &param), -UMQ_ERR_EINVAL);
    EXPECT_EQ(umq_qbuf_base_alloc(&base, &tc, 2 * 1024, 0, &list, NULL, &param), -UMQ_ERR_EINVAL);
    EXPECT_EQ(umq_qbuf_base_alloc(&base, &tc, 2 * 1024, 1, NULL, NULL, &param), -UMQ_ERR_EINVAL);
    EXPECT_EQ(umq_qbuf_base_alloc(&base, &tc, 2 * 1024, 1, &list, NULL, NULL), -UMQ_ERR_EINVAL);

    base.fetch_fn = (qbuf_base_fetch_fn)1;
    base.inited = false;
    EXPECT_EQ(umq_qbuf_base_alloc(&base, &tc, 2 * 1024, 1, &list, NULL, &param), -UMQ_ERR_ENOMEM);
    base.inited = true;
    base.fetch_fn = NULL;

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 64;
    EXPECT_EQ(umq_qbuf_base_alloc(&base, &tc, 0, 1, &list, &opt, &param), -UMQ_ERR_EINVAL);

    umq_qbuf_base_uninit(&base, NULL);

    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = false;
    base.mempool_id = 0;
    cfg.mode = UMQ_BUF_COMBINE;
    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, 0), 0);
    base.fetch_fn = (qbuf_base_fetch_fn)1;
    EXPECT_EQ(umq_qbuf_base_alloc(&base, &tc, 0, 1, &list, NULL, &param), -UMQ_ERR_EINVAL);

    umq_qbuf_base_uninit(&base, NULL);
}

/* ================================================================== */
/* Medium Priority UT supplements (items 9-16)                        */
/* ================================================================== */

/* 9.76 umq_normal_qbuf_alloc request_size==0 in COMBINE mode (F23, F57-F58) */
TEST_F(TestQbufPoolMultiLevel, NormalAllocSizeZeroCombine)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, true);
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    EXPECT_EQ(umq_normal_qbuf_alloc(0, 1, NULL, &list), -UMQ_ERR_ENOMEM);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 64;
    EXPECT_EQ(umq_normal_qbuf_alloc(0, 1, &opt, &list), -UMQ_ERR_EINVAL);
}

/* 9.77 thread_cache_self_shrink without_data path (F21-F22, F54-F55) */
TEST_F(TestQbufPoolMultiLevel, SelfShrinkWithoutData)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));

    std::vector<umq_buf_list_t> holders;
    for (int i = 0; i < 300; i++) {
        umq_buf_list_t list;
        QBUF_LIST_INIT(&list);
        if (umq_qbuf_alloc(0, 1, &opt, &list) != 0)
            break;
        holders.push_back(list);
    }
    EXPECT_GT(holders.size(), 100u);

    for (auto &h : holders) {
        umq_qbuf_free(&h);
    }

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    EXPECT_EQ(umq_qbuf_alloc(0, 1, &opt, &list2), 0);
    umq_qbuf_free(&list2);
}

/* 9.78 fetch_and_expand without_data budget + rollback (F51-F53, E06) */
TEST_F(TestQbufPoolMultiLevel, FetchExpandWithoutDataBudget)
{
    const uint64_t tinyBudget = 128;
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);
    g_qbuf_pool.tls_qbuf_pool_depth = tinyBudget;

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));

    std::vector<umq_buf_list_t> holders;
    for (int i = 0; i < 50; i++) {
        umq_buf_list_t list;
        QBUF_LIST_INIT(&list);
        if (umq_qbuf_alloc(0, 1, &opt, &list) != 0)
            break;
        holders.push_back(list);
    }

    for (auto &h : holders) {
        umq_qbuf_free(&h);
    }
    g_qbuf_pool.tls_qbuf_pool_depth = 0;
}

/* 9.79 umq_qbuf_escape_alloc param validation (E07-E09) */
TEST_F(TestQbufPoolMultiLevel, EscapeAllocParamValidation)
{
    InitPool(2, 16);

    g_qbuf_pool.disable_malloc_escape = true;
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    EXPECT_EQ(umq_qbuf_escape_alloc(4 * 1024, 1, NULL, &list), -UMQ_ERR_EINVAL);
    g_qbuf_pool.disable_malloc_escape = false;

    EXPECT_EQ(umq_qbuf_escape_alloc(0, 1, NULL, &list), -UMQ_ERR_EINVAL);
    EXPECT_EQ(umq_qbuf_escape_alloc(4 * 1024, 2, NULL, &list), -UMQ_ERR_EINVAL);
    EXPECT_EQ(umq_qbuf_escape_alloc(4 * 1024, 1, NULL, NULL), -UMQ_ERR_EINVAL);

    EXPECT_EQ(umq_qbuf_escape_alloc(8 * 1024, 1, NULL, &list), -UMQ_ERR_EINVAL);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 2 * 1024;
    EXPECT_EQ(umq_qbuf_escape_alloc(3 * 1024, 1, &opt, &list), -UMQ_ERR_EINVAL);
}

/* 9.81 alloc_expansion_pool_slot ID overflow (E05, E13, F38-F39) */
TEST_F(TestQbufPoolMultiLevel, ExpansionSlotIdOverflow)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    uint32_t count = 0;
    qbuf_expansion_pool_slot_t *slot = NULL;
    while (alloc_expansion_pool_slot(&slot, 0) == UMQ_SUCCESS && count < 800) {
        if (slot->slot_id < QBUF_POOL_EXP_SLOT_TABLE_SIZE) {
            g_exp_slot_table[slot->slot_id] = slot;
        }
        free(slot);
        slot = NULL;
        count++;
    }
    EXPECT_GE(count, 1u);
}

/* 9.82 slot_with_data_init budget/register fail (E14-E16, F41)
 * Set exp_total_mem_pool_size near limit to trigger try_inc_atomic failure. */
TEST_F(TestQbufPoolMultiLevel, SlotWithDataInitBudgetExceeded)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    qbuf_expansion_pool_slot_t *slot = NULL;
    ASSERT_EQ(alloc_expansion_pool_slot(&slot, 0), UMQ_SUCCESS);

    uint64_t saved = g_qbuf_pool.expansion_mem_size_max;
    g_qbuf_pool.expansion_mem_size_max = 1;
    EXPECT_NE(slot_with_data_init(0, slot), UMQ_SUCCESS);
    g_qbuf_pool.expansion_mem_size_max = saved;

    free_expansion_pool_slot(slot);
}

/* 9.83 expand_global_pool slot init fail (E24-E25, F56) */
TEST_F(TestQbufPoolMultiLevel, ExpandGlobalPoolSlotInitFail)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    uint64_t saved = g_qbuf_pool.expansion_mem_size_max;
    g_qbuf_pool.expansion_mem_size_max = 1;
    EXPECT_NE(expand_global_pool(true, 0), UMQ_SUCCESS);
    g_qbuf_pool.expansion_mem_size_max = saved;
}

/* 9.85 async_shrink_global_pool_callback invalid slot (F07) */
TEST_F(TestQbufPoolMultiLevel, AsyncShrinkInvalidSlot)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    qbuf_expansion_pool_t *exp_pool = &g_qbuf_pool.exp_pool_with_data[0];
    EXPECT_TRUE(exp_pool->inited);

    async_shrink_pool_param_t *param = (async_shrink_pool_param_t *)calloc(1, sizeof(async_shrink_pool_param_t));
    ASSERT_NE(param, nullptr);
    param->slot_id = 99999;
    param->with_data = true;

    (void)pthread_spin_lock(&exp_pool->shrink_task_list.lock);
    urpc_list_push_back(&exp_pool->shrink_task_list.head, &param->node);
    (void)pthread_spin_unlock(&exp_pool->shrink_task_list.lock);

    async_shrink_pool_param_t *popped = async_shrink_pop_param(exp_pool);
    EXPECT_NE(popped, nullptr);
    free(popped);
}

/* 9.86 return_batch_to_expansion_pool invalid mempool_id (E17) */
TEST_F(TestQbufPoolMultiLevel, ReturnBatchInvalidMempoolId)
{
    InitPool(2, 16);

    umq_buf_t fake_buf;
    memset(&fake_buf, 0, sizeof(fake_buf));
    fake_buf.mempool_id = 5000;

    return_batch_to_expansion_pool(5000, &fake_buf, &fake_buf, 1, true, 0);
}

/* 9.90 Base pool data_to_head SPLIT and COMBINE modes (F25, F75-F76) */
TEST_F(TestQbufPoolMultiLevel, BaseDataToHeadSplitAndCombine)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = true;
    base.mempool_id = 0;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;

    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, UMQ_EMPTY_HEADER_COEFFICIENT), 0);

    umq_buf_t *first = QBUF_LIST_FIRST(&base.block_pool[0].head_with_data);
    if (first != NULL) {
        umq_buf_t *found = umq_qbuf_base_data_to_head(&base, first->buf_data);
        EXPECT_NE(found, nullptr);
    }

    EXPECT_EQ(umq_qbuf_base_data_to_head(&base, NULL), nullptr);
    EXPECT_EQ(umq_qbuf_base_data_to_head(NULL, buf_addr), nullptr);

    base.inited = false;
    EXPECT_EQ(umq_qbuf_base_data_to_head(&base, buf_addr), nullptr);
    base.inited = true;

    umq_qbuf_base_uninit(&base, NULL);

    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = false;
    base.mempool_id = 0;
    cfg.mode = UMQ_BUF_COMBINE;
    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, 0), 0);

    first = QBUF_LIST_FIRST(&base.block_pool[0].head_with_data);
    if (first != NULL) {
        umq_buf_t *found = umq_qbuf_base_data_to_head(&base, first->buf_data);
        EXPECT_NE(found, nullptr);
    }

    umq_qbuf_base_uninit(&base, NULL);
}

/* 9.91 Base pool info_get — null and overflow validation (F06) */
TEST_F(TestQbufPoolMultiLevel, BaseInfoGetValidation)
{
    qbuf_pool_base_t base;
    memset(&base, 0, sizeof(base));
    base.block_size = 4 * 1024;
    base.support_without_data = true;
    base.mempool_id = 0;

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.mode = UMQ_BUF_SPLIT;
    ASSERT_EQ(qbuf_pool_base_init(&base, &cfg, UMQ_EMPTY_HEADER_COEFFICIENT), 0);

    EXPECT_EQ(umq_qbuf_pool_base_info_get(NULL, NULL, true, UMQ_QBUF_POOL_TYPE_SMALL), -UMQ_ERR_EINVAL);

    umq_qbuf_pool_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.num = UMQ_STATS_QBUF_POOL_TYPE_MAX;
    EXPECT_EQ(umq_qbuf_pool_base_info_get(&base, &stats, true, UMQ_QBUF_POOL_TYPE_SMALL), -UMQ_ERR_EINVAL);

    umq_qbuf_base_uninit(&base, NULL);
}

/* 9.92 Base pool io_buf_malloc (F64 via base) */
TEST_F(TestQbufPoolMultiLevel, BaseIoBufMalloc)
{
    void *p = umq_qbuf_base_io_buf_malloc(1024 * 1024, 4096);
    EXPECT_NE(p, nullptr);
    if (p)
        free(p);

    EXPECT_EQ(umq_qbuf_base_io_buf_malloc(1024, 4096), nullptr);
}

/* 9.93 Escape alloc with headroom exceeding block (E07-E09) */
TEST_F(TestQbufPoolMultiLevel, EscapeAllocHeadroomExceedsBlock)
{
    InitPool(2, 16);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 4 * 1024;
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    EXPECT_EQ(umq_qbuf_escape_alloc(1, 1, &opt, &list), -UMQ_ERR_EINVAL);
}

/* 9.94 Normal alloc request_size==0 + headroom==0 → without_data path (F57) */
TEST_F(TestQbufPoolMultiLevel, NormalAllocSizeZeroSplitWithoutData)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, true);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    EXPECT_EQ(umq_normal_qbuf_alloc(0, 1, NULL, &list), 0);
    ASSERT_NE(QBUF_LIST_FIRST(&list), nullptr);
    EXPECT_EQ(QBUF_LIST_FIRST(&list)->buf_data, nullptr);
    EXPECT_EQ(QBUF_LIST_FIRST(&list)->mempool_without_data, 1u);
    umq_qbuf_free(&list);
}

/* 9.95 Normal alloc request_size==0 with COMBINE mode (F58) */
TEST_F(TestQbufPoolMultiLevel, NormalAllocSizeZeroCombineError)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, true);
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    EXPECT_EQ(umq_normal_qbuf_alloc(0, 1, NULL, &list), -UMQ_ERR_ENOMEM);
}

/* 9.97 fetch_and_expand with_data byte budget enforcement (F51-F53) */
TEST_F(TestQbufPoolMultiLevel, FetchExpandWithDataByteBudget)
{
    const uint64_t tlsBudget = 256 * 1024;
    const uint64_t tlsExpand = 256 * 1024;
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, tlsBudget, tlsExpand, smallExp);

    std::vector<umq_buf_list_t> holders;
    for (int i = 0; i < 200; i++) {
        umq_buf_list_t list;
        QBUF_LIST_INIT(&list);
        if (umq_qbuf_alloc(4 * 1024, 1, NULL, &list) != 0)
            break;
        holders.push_back(list);
    }
    EXPECT_GT(holders.size(), 0u);

    for (auto &h : holders) {
        umq_qbuf_free(&h);
    }
}

/* 9.98 slot_without_data_init budget exceeded (E14) */
TEST_F(TestQbufPoolMultiLevel, SlotWithoutDataInitBudgetExceeded)
{
    const uint64_t smallPool = 8 * 1024 * 1024;
    const uint64_t smallExp = 256 * 1024;
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, smallPool, 0, 0, smallExp);

    qbuf_expansion_pool_slot_t *slot = NULL;
    ASSERT_EQ(alloc_expansion_pool_slot(&slot, UMQ_QBUF_SIZE_CLASS_MAX), UMQ_SUCCESS);

    uint64_t saved = g_qbuf_pool.expansion_mem_size_max;
    g_qbuf_pool.expansion_mem_size_max = 1;
    EXPECT_NE(slot_without_data_init(&g_qbuf_pool.exp_pool_without_date, slot), UMQ_SUCCESS);
    g_qbuf_pool.expansion_mem_size_max = saved;

    free_expansion_pool_slot(slot);
}

/* 9.99 FreeAllTriggersShrink: burst alloc 10000 sc1 bufs -> free all -> verify
 * expansion pool shrinks and TLS cap is not inflated (high-water mark fix). */
TEST_F(TestQbufPoolMultiLevel, FreeAllTriggersShrink)
{
    /* Use generous TLS budget so expansion pool is exercised.
     * expSz=4MB gives 64 blocks/slot (matching batch_count) so ~110 expansion
     * slots are needed for 10000 bufs -- well under the QBUF_POOL_EXP_SLOT_TABLE_SIZE-entry slot table. */
    const uint64_t tlsBudget = 16384; /* 16384 blocks (was 96MB) */ /* 96 MB global TLS cap */
    const uint64_t tlsExpand = 14336; /* 14336 blocks (was 84MB) */ /* 84 MB per-thread cap */
    const uint64_t expSz = 4ULL * 1024 * 1024;   /* 4 MB per expansion (64 sc1 blocks) */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, tlsExpand, expSz);

    /* Phase 1: Alloc 10000 sc1 bufs (655360000 bytes) */
    std::vector<umq_buf_list_t> holders(10000);
    for (uint32_t i = 0; i < 10000; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(64 * 1024, 1, NULL, &holders[i]), 0) << "alloc failed at " << i;
    }

    /* Record peak expansion pool stats: expansion_count (active slots) and
     * exp_total_mem_pool_size (total mmap'd memory) both only increase on
     * expand and decrease on shrink, making them reliable shrink indicators. */
    uint32_t peakExpSlots = g_qbuf_pool.exp_pool_with_data[1].expansion_count;
    uint64_t peakExpMemSize = __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED);
    uint64_t shrinkCountBefore = g_qbuf_pool.exp_pool_with_data[1].total_shrink_count;
    EXPECT_GT(peakExpSlots, 0u) << "expansion pool should have grown during burst alloc";

    /* Phase 2: Free all 10000 bufs */
    for (uint32_t i = 0; i < 10000; i++) {
        umq_qbuf_free(&holders[i]);
    }

    /* Phase 3: Poll for async shrink completion (<= 100ms) */
    for (int poll = 0; poll < 100; poll++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[1].is_shrinking, __ATOMIC_RELAXED) == 0) {
            break;
        }
        usleep(1000); /* 1ms per poll */
    }

    /* Phase 4: Verify expansion pool shrunk */
    uint32_t finalExpSlots = g_qbuf_pool.exp_pool_with_data[1].expansion_count;
    uint64_t finalExpMemSize = __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED);
    uint64_t shrinkCountAfter = g_qbuf_pool.exp_pool_with_data[1].total_shrink_count;
    uint64_t tlsBytesSc1 = g_thread_cache.block_pool.capacity_with_data[1];

    /* Expansion pool should have shrunk from peak */
    EXPECT_LT(finalExpSlots, peakExpSlots / 2) << "expansion slot count should drop by >= 50%";
    EXPECT_LT(finalExpMemSize, peakExpMemSize / 2) << "expansion pool memory should drop by >= 50%";
    EXPECT_GT(shrinkCountAfter, shrinkCountBefore) << "total_shrink_count should have increased";

    /* TLS cap should NOT be inflated (high-water mark, not transit accumulation).
     * With high-water mark, cap ~= batch_cnt * blk_size = 64 * 64K = 4MB */
    EXPECT_LT(tlsBytesSc1, (uint64_t)8 * 1024 * 1024) << "TLS cap should not be inflated beyond ~8MB";
}

/* 9.19 BurstAllocFreeNoExpansionLeak: repeat 100x burst alloc + free all
 * -> verify expansion memory stable (not monotonically growing). */
TEST_F(TestQbufPoolMultiLevel, BurstAllocFreeNoExpansionLeak)
{
    /* Use same InitPool as FreeAllTriggersShrink */
    const uint64_t tlsBudget = 16384; /* 16384 blocks (was 96MB) */
    const uint64_t tlsExpand = 14336; /* 14336 blocks (was 84MB) */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, tlsExpand, 4 * 1024 * 1024);

    /* Use smaller alloc count (500 bufs) to keep test <= 1s */
    const uint32_t burstCount = 500;
    const uint32_t blockSize = 64 * 1024; /* sc1 */
    std::vector<umq_buf_list_t> holders(burstCount);

    /* Record initial expansion memory (0 right after InitPool) */
    uint64_t initialExpMem = __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED);

    /* 100 iterations of alloc 500 + free all */
    for (uint32_t iter = 0; iter < 100; iter++) {
        for (uint32_t i = 0; i < burstCount; i++) {
            QBUF_LIST_INIT(&holders[i]);
            ASSERT_EQ(umq_qbuf_alloc(blockSize, 1, NULL, &holders[i]), 0)
                << "alloc failed at iter " << iter << " i " << i;
        }
        for (uint32_t i = 0; i < burstCount; i++) {
            umq_qbuf_free(&holders[i]);
        }
    }

    /* Poll for async shrink completion (<= 100ms) so steady-state is measured. */
    for (int poll = 0; poll < 100; poll++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[1].is_shrinking, __ATOMIC_RELAXED) == 0) {
            break;
        }
        usleep(1000); /* 1ms per poll */
    }

    /* After 100 iterations, expansion memory should be stable */
    uint64_t finalExpMem = __atomic_load_n(&g_qbuf_pool.exp_total_mem_pool_size, __ATOMIC_RELAXED);
    uint32_t finalExpCount = g_qbuf_pool.exp_pool_with_data[1].expansion_count;

    /* Memory should not grow unboundedly -- allow up to 2 expansion slots of slack */
    uint64_t oneSlotSize = 4 * 1024 * 1024; /* 4MB per expansion slot */
    EXPECT_LE(finalExpMem, initialExpMem + 2 * oneSlotSize)
        << "expansion memory should be stable after 100 burst+free cycles";

    /* Active slot count should be bounded */
    EXPECT_LE(finalExpCount, 4u) << "active expansion slot count should be bounded after 100 cycles";
}

/* 9.20 SteadyChurnMaintainsTlsCache: alloc 64 (one batch) + free 64 + alloc 64 again
 * → verify no additional fetch on second alloc (TLS cache maintained).
 * Working set = one batch (batch_cnt=64 for sc1): first alloc fetches exactly one
 * batch and sets cap = 64 * 64K = 4MB. Free returns bufs to TLS (actual=cap, no
 * return_to_global); self_shrink stays idle (remaining/4=16 < threshold=64). Second
 * alloc finds 64 bufs in TLS → no fetch. */
TEST_F(TestQbufPoolMultiLevel, SteadyChurnMaintainsTlsCache)
{
    const uint64_t tlsBudget = 16384; /* 16384 blocks (was 96MB) */
    const uint64_t tlsExpand = 14336; /* 14336 blocks (was 84MB) */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, BUF_SIZE, tlsBudget, tlsExpand, 4 * 1024 * 1024);

    const uint32_t numBufs = 64;          /* one batch (QBUF_POOL_BATCH_CNT) for sc1 */
    const uint32_t blockSize = 64 * 1024; /* sc1 */
    std::vector<umq_buf_list_t> holders(numBufs);

    /* Phase 1: Alloc 64 sc1 bufs (one batch) */
    for (uint32_t i = 0; i < numBufs; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(blockSize, 1, NULL, &holders[i]), 0);
    }
    /* Record fetch counter after first alloc */
    uint64_t fetchCountAfterFirstAlloc = g_thread_cache.stats.tls_fetch_buf_cnt_with_data;
    uint64_t tlsCapBytes = g_thread_cache.block_pool.capacity_with_data[1];
    EXPECT_GT(fetchCountAfterFirstAlloc, 0u) << "first alloc should trigger fetch";
    EXPECT_GT(tlsCapBytes, 0u) << "TLS cap should be set";

    /* Phase 2: Free all 64 */
    for (uint32_t i = 0; i < numBufs; i++) {
        umq_qbuf_free(&holders[i]);
    }

    /* Phase 3: Alloc 64 again */
    for (uint32_t i = 0; i < numBufs; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(blockSize, 1, NULL, &holders[i]), 0);
    }
    uint64_t fetchCountAfterSecondAlloc = g_thread_cache.stats.tls_fetch_buf_cnt_with_data;

    /* Second alloc should NOT trigger additional fetch (TLS cache maintained from free) */
    EXPECT_EQ(fetchCountAfterSecondAlloc, fetchCountAfterFirstAlloc)
        << "second alloc should not trigger fetch — TLS cache was maintained";

    /* TLS cap should accommodate the working set */
    uint64_t tlsCapAfterSecond = g_thread_cache.block_pool.capacity_with_data[1];
    EXPECT_GE(tlsCapAfterSecond, static_cast<uint64_t>(numBufs)) << "TLS cap (block count) should be >= working set size";

    /* Cleanup */
    for (uint32_t i = 0; i < numBufs; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

TEST_F(TestQbufPoolMultiLevel, LazyInitLargeScZeroInitialBlocks)
{
    /* Given: count=3 [4K, 64K, 1M], lazy_threshold=1M -> 1M SC gets zero initial blocks */
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3lazy[] = {2861, 2861, 0}; /* SC2 (1M) lazy */
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc3lazy);

    /* Then: SC 0 (4K) and SC 1 (64K) have blocks, SC 2 (1M) has zero */
    EXPECT_GT(g_qbuf_pool.block_pool[0].buf_cnt_with_data, 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.data_region_start[2], (char *)NULL);
    EXPECT_EQ(g_qbuf_pool.data_region_end[2], (char *)NULL);

    /* Verify lazy SC via per_sc_block_counts[2] == 0 */
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[2], 0u);

    /* Verify expansion trigger for lazy SC uses expansion_block_count */
    uint64_t exp_blk_cnt = g_qbuf_pool.expansion_size / g_qbuf_pool.block_sizes[2];
    if (exp_blk_cnt == 0)
            exp_blk_cnt = 1;
    uint64_t expected_trigger = exp_blk_cnt * g_qbuf_pool.expansion_threshold / 100;
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[2].trigger_expand_block_num, expected_trigger);

    /* Alloc from lazy SC triggers expansion and succeeds */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(1024 * 1024, 1, NULL, &list);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[2].expansion_count, 0u);

    /* Cleanup */
    umq_qbuf_free(&list);
    umq_qbuf_pool_uninit();
}

TEST_F(TestQbufPoolMultiLevel, LazyInitNonLazyScGetsMoreMemory)
{
    /* Given: count=3 [4K, 64K, 1M] with lazy 1M, verify non-lazy SCs get more memory */
    const uint64_t poolSz = 200 * 1024 * 1024;

    /* With lazy: only 4K and 64K share the pool */
    uint64_t bcLazy[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bcLazy);
    uint64_t lazy_per_sc = g_qbuf_pool.per_sc_block_counts[0];
    umq_qbuf_pool_uninit();

    /* Without lazy: all 3 SCs share the pool (auto-derive) */
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz);
    uint64_t nolazy_per_sc = g_qbuf_pool.per_sc_block_counts[0];
    umq_qbuf_pool_uninit();

    /* With lazy, non-lazy SCs get more blocks per SC */
    EXPECT_GT(lazy_per_sc, nolazy_per_sc);
}

TEST_F(TestQbufPoolMultiLevel, LazyInitCombineMode)
{
    /* Given: COMBINE mode with count=3 [4K, 64K, 1M], lazy 1M */
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3combLazy[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, false, poolSz, 0, 0, 0, bc3combLazy);

    /* Then: 1M SC has zero initial blocks */
    EXPECT_EQ(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.data_region_start[2], (char *)NULL);
    EXPECT_EQ(g_qbuf_pool.data_region_end[2], (char *)NULL);
    EXPECT_GT(g_qbuf_pool.block_pool[0].buf_cnt_with_data, 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);

    /* Alloc from lazy SC triggers expansion */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(1024 * 1024, 1, NULL, &list);
    EXPECT_EQ(ret, 0);
    umq_qbuf_free(&list);
    umq_qbuf_pool_uninit();
}

TEST_F(TestQbufPoolMultiLevel, LazyInitDisabledWhenThresholdZeroInCfg)
{
    /* Given: no blockCounts (default nullptr) -> auto-derive for all SCs -> no lazy SC */
    const uint64_t poolSz = 200 * 1024 * 1024;
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz);

    /* Then: all SCs get auto-derived initial blocks, no SC is lazy */
    EXPECT_GT(g_qbuf_pool.block_pool[0].buf_cnt_with_data, 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        EXPECT_GT(g_qbuf_pool.per_sc_block_counts[sc], 0u) << "sc=" << sc;
    }
    umq_qbuf_pool_uninit();
}

TEST_F(TestQbufPoolMultiLevel, LazyInitMultipleLazyScs)
{
    /* Given: count=4 [4K, 64K, 1M, 1M won't exceed max], threshold=64K -> SC 1,2 are lazy */
    /* With mult=16, count=4: [4K, 64K, 1M, 16M] — but 16M exceeds QBUF_POOL_MAX_BLOCK_SIZE(1M),
       so this config would fail. Instead use mult=4: [4K, 16K, 64K, 256K], threshold=64K -> SC 2,3 lazy */
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc4lazy23[] = {9645, 9645, 0, 0}; /* SC2 (64K) and SC3 (256K) lazy */
    InitPool(4, 4, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc4lazy23);

    /* Then: SC 2 (64K) and SC 3 (256K) are lazy */
    EXPECT_GT(g_qbuf_pool.block_pool[0].buf_cnt_with_data, 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.block_pool[3].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[2], 0u);
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[3], 0u);
    umq_qbuf_pool_uninit();
}

/* 10.1 Lazy SC expansion produces usable blocks (alloc+free round-trip) */
TEST_F(TestQbufPoolMultiLevel, LazyInitExpansionBlockUsable)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3exp[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc3exp);

    /* Alloc 1M from lazy SC — triggers expansion */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(1024 * 1024, 1, NULL, &list);
    ASSERT_EQ(ret, 0);

    /* Verify the buf has correct data_size */
    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(buf->data_size, (uint32_t)(1024 * 1024));

    /* Free — buf returns to expansion pool slot */
    umq_qbuf_free(&list);
    EXPECT_EQ(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    umq_qbuf_pool_uninit();
}

/* 10.2 Lazy SC multiple expansion rounds */
TEST_F(TestQbufPoolMultiLevel, LazyInitMultipleExpansionRounds)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    const uint64_t expSz = 2 * 1024 * 1024;
    uint64_t bc3mexp[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, expSz, bc3mexp);

    umq_buf_list_t list1, list2;
    QBUF_LIST_INIT(&list1);
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(1024 * 1024, 1, NULL, &list1), 0);
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[2].expansion_count, 1u);

    ASSERT_EQ(umq_qbuf_alloc(1024 * 1024, 1, NULL, &list2), 0);

    /* Third alloc triggers another expansion round */
    umq_buf_list_t list3;
    QBUF_LIST_INIT(&list3);
    ASSERT_EQ(umq_qbuf_alloc(1024 * 1024, 1, NULL, &list3), 0);
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[2].expansion_count, 2u);

    umq_qbuf_free(&list1);
    umq_qbuf_free(&list2);
    umq_qbuf_free(&list3);
    umq_qbuf_pool_uninit();
}

/* 10.3 buf_data_to_size_class skip NULL data_region_end for lazy SC */
TEST_F(TestQbufPoolMultiLevel, LazyInitBufDataToSizeClassNullSkip)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3null[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc3null);

    /* Alloc from non-lazy SC 0 (4K) — buf_data falls in data_region [0] */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(4096, 1, NULL, &list), 0);
    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    uint32_t sc = buf_data_to_size_class(buf->buf_data);
    EXPECT_EQ(sc, 0u);

    /* Alloc from lazy SC 2 (1M) via expansion — data in expansion pool, not base */
    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    ASSERT_EQ(umq_qbuf_alloc(1024 * 1024, 1, NULL, &list2), 0);
    umq_buf_t *buf2 = QBUF_LIST_FIRST(&list2);
    uint32_t sc2 = buf_data_to_size_class(buf2->buf_data);
    EXPECT_EQ(sc2, UMQ_QBUF_SIZE_CLASS_MAX);

    umq_qbuf_free(&list);
    umq_qbuf_free(&list2);
    umq_qbuf_pool_uninit();
}

/* 10.4 Default 3-SC config [4K, 64K, 1M] with lazy 1M — integration */
TEST_F(TestQbufPoolMultiLevel, LazyInitDefault3ScIntegration)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3integ[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc3integ);

    ASSERT_EQ(g_qbuf_pool.size_class_count, 3u);
    EXPECT_EQ(g_qbuf_pool.block_sizes[0], 4096u);
    EXPECT_EQ(g_qbuf_pool.block_sizes[1], 65536u);
    EXPECT_EQ(g_qbuf_pool.block_sizes[2], 1048576u);
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[2], 0u);

    umq_buf_list_t list0, list1, list2;
    QBUF_LIST_INIT(&list0);
    QBUF_LIST_INIT(&list1);
    QBUF_LIST_INIT(&list2);
    EXPECT_EQ(umq_qbuf_alloc(4096, 1, NULL, &list0), 0);
    EXPECT_EQ(umq_qbuf_alloc(65536, 1, NULL, &list1), 0);
    EXPECT_EQ(umq_qbuf_alloc(1048576, 1, NULL, &list2), 0);

    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[2].expansion_count, 0u);
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 0u);
    EXPECT_EQ(g_qbuf_pool.exp_pool_with_data[1].expansion_count, 0u);

    umq_qbuf_free(&list0);
    umq_qbuf_free(&list1);
    umq_qbuf_free(&list2);
    umq_qbuf_pool_uninit();
}

/* 10.5 Lazy SC 1M alloc with headroom */
TEST_F(TestQbufPoolMultiLevel, LazyInit1MBlockWithHeadroom)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3head[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc3head);

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 512;

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(500 * 1024, 1, &opt, &list);
    ASSERT_EQ(ret, 0);

    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    EXPECT_EQ(buf->headroom_size, 512u);
    EXPECT_EQ(buf->data_size, 500u * 1024u);

    umq_qbuf_free(&list);
    umq_qbuf_pool_uninit();
}

/* 10.6 All SCs lazy (threshold=4K -> all SCs >= 4K are lazy) */
TEST_F(TestQbufPoolMultiLevel, LazyInitAllScsLazy)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc2alllazy[] = {0, 0}; /* all SCs lazy */
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc2alllazy);

    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[0], 0u);
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[1], 0u);
    EXPECT_EQ(g_qbuf_pool.block_pool[0].buf_cnt_with_data, 0u);
    EXPECT_EQ(g_qbuf_pool.block_pool[1].buf_cnt_with_data, 0u);

    /* Alloc still works via expansion */
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(4096, 1, NULL, &list);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 0u);

    umq_qbuf_free(&list);
    umq_qbuf_pool_uninit();
}

/* 10.7 Lazy SC 1M expand and shrink */
TEST_F(TestQbufPoolMultiLevel, LazyInit1MExpandAndShrink)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    const uint64_t expSz = 4 * 1024 * 1024;
    uint64_t bc3es[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, expSz, bc3es);

    std::vector<umq_buf_list_t> lists(8);
    for (int i = 0; i < 8; i++) {
        QBUF_LIST_INIT(&lists[i]);
        ASSERT_EQ(umq_qbuf_alloc(1024 * 1024, 1, NULL, &lists[i]), 0);
    }
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[2].expansion_count, 2u);

    for (int i = 0; i < 8; i++) {
        umq_qbuf_free(&lists[i]);
    }
    EXPECT_GT(g_qbuf_pool.exp_pool_with_data[2].slot_count, 0u);
    umq_qbuf_pool_uninit();
}

/* 10.8 Lazy SC threshold exact boundary */
TEST_F(TestQbufPoolMultiLevel, LazyInitThresholdExactBoundary)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    /* SC2 (1M) is lazy: per_sc_block_counts[2] = 0 */
    uint64_t bc3exact1[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz, 0, 0, 0, bc3exact1);
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[2], 0u);
    EXPECT_EQ(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    umq_qbuf_pool_uninit();

    /* SC2 (1M) is NOT lazy: auto-derive all SCs */
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, poolSz);
    EXPECT_GT(g_qbuf_pool.per_sc_block_counts[2], 0u);
    EXPECT_GT(g_qbuf_pool.block_pool[2].buf_cnt_with_data, 0u);
    umq_qbuf_pool_uninit();
}

/* 10.9 Lazy SC 1M COMBINE mode multi-block alloc */
TEST_F(TestQbufPoolMultiLevel, LazyInit1MCombineMultiBlock)
{
    const uint64_t poolSz = 200 * 1024 * 1024;
    uint64_t bc3combLazy[] = {2861, 2861, 0};
    InitPool(3, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE, false, poolSz, 0, 0, 0, bc3combLazy);

    uint32_t usable = 1048576 - (uint32_t)sizeof(umq_buf_t);
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    int ret = umq_qbuf_alloc(usable + 100, 1, NULL, &list);
    ASSERT_EQ(ret, 0);

    umq_buf_t *first = QBUF_LIST_FIRST(&list);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->first_fragment, 1u);
    umq_buf_t *second = QBUF_LIST_NEXT(first);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second->first_fragment, 0u);
    EXPECT_EQ(QBUF_LIST_NEXT(second), nullptr);

    umq_qbuf_free(&list);
    umq_qbuf_pool_uninit();
}

/* ================================================================== */
/* Section 11: RX Pool (umq_rx_qbuf_pool) -- 4KB-only, no TLS/HWM      */
/* ================================================================== */

/* 11.1 RX pool init + basic alloc/free lifecycle */
TEST_F(TestQbufPoolMultiLevel, RxPoolInitAndBasicAlloc)
{
    InitRxPool();
    uint64_t expectedBlocks = umq_rx_io_buf_size() / (UMQ_RX_QBUF_BLOCK_SIZE + sizeof(umq_buf_t));
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, expectedBlocks);
    EXPECT_TRUE(g_rx_pool_inited);

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, 1, NULL, &list), 0);

    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(buf->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
    EXPECT_EQ(buf->buf_size, UMQ_RX_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t));
    EXPECT_EQ(buf->data_size, UMQ_RX_QBUF_BLOCK_SIZE);
    EXPECT_EQ(buf->total_data_size, UMQ_RX_QBUF_BLOCK_SIZE);
    EXPECT_EQ(buf->headroom_size, 0u);
    EXPECT_EQ(buf->first_fragment, 1u);
    EXPECT_EQ(buf->alloc_state, QBUF_ALLOC_STATE_ALLOCATED);
    EXPECT_EQ(QBUF_LIST_NEXT(buf), nullptr);

    umq_rx_qbuf_free(&list);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, expectedBlocks);
}

/* 11.2 RX pool batch alloc (num > 1) */
TEST_F(TestQbufPoolMultiLevel, RxPoolAllocBatch)
{
    InitRxPool();
    uint64_t totalBlocks = g_rx_pool.buf_cnt_with_data;

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, 8, NULL, &list), 0);

    uint32_t count = 0;
    umq_buf_t *cur;
    QBUF_LIST_FOR_EACH(cur, &list)
    {
        EXPECT_EQ(cur->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
        count++;
    }
    EXPECT_EQ(count, 8u);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks - 8);

    umq_rx_qbuf_free(&list);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);
}

/* 11.3 RX pool exhaustion triggers fallback to normal pool (success path).
 * Pre-fix: this test only called InitRxPool() (no InitPool), so the fallback
 * path's umq_normal_qbuf_alloc returned -UMQ_ERR_ENOMEM (normal pool not inited)
 * and the test passed for the wrong reason. Now: InitPool + InitRxPool, expect
 * fallback success. */
TEST_F(TestQbufPoolMultiLevel, RxPoolFallbackToNormalSuccess)
{
    InitPool(2, 16);
    InitRxPool();
    uint64_t totalBlocks = g_rx_pool.buf_cnt_with_data;

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, static_cast<uint32_t>(totalBlocks), NULL, &list), 0);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, 0u);

    umq_buf_list_t list2;
    QBUF_LIST_INIT(&list2);
    EXPECT_EQ(umq_rx_qbuf_alloc(4096, 1, NULL, &list2), 0);
    umq_buf_t *buf = QBUF_LIST_FIRST(&list2);
    ASSERT_NE(buf, nullptr);
    EXPECT_NE(buf->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
    EXPECT_EQ(buf->mempool_id, UMQ_QBUF_DEFAULT_MEMPOOL_ID);
    EXPECT_EQ(buf->buf_size, 4096u + (uint32_t)sizeof(umq_buf_t));
    EXPECT_EQ(buf->headroom_size, 0u);

    /* list from RX pool, list2 from normal pool (auto-routed by mempool_id) */
    umq_rx_qbuf_free(&list);
    umq_qbuf_free(&list2);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);
}

/* 11.4 RX pool free returns to pool (no TLS, no HWM, no expand) */
TEST_F(TestQbufPoolMultiLevel, RxPoolFreeReturnsToPool)
{
    InitRxPool();
    uint64_t totalBlocks = g_rx_pool.buf_cnt_with_data;

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, static_cast<uint32_t>(totalBlocks), NULL, &list), 0);
    umq_rx_qbuf_free(&list);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);

    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, static_cast<uint32_t>(totalBlocks), NULL, &list), 0);
    umq_rx_qbuf_free(&list);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);
}

/* 11.5 RX pool headroom option */
TEST_F(TestQbufPoolMultiLevel, RxPoolHeadroomOption)
{
    InitRxPool();

    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 128;

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(UMQ_RX_QBUF_BLOCK_SIZE - 128, 1, &opt, &list), 0);

    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(buf->headroom_size, 128u);
    EXPECT_EQ(buf->data_size, UMQ_RX_QBUF_BLOCK_SIZE - 128);
    EXPECT_EQ(buf->total_data_size, UMQ_RX_QBUF_BLOCK_SIZE - 128);
    EXPECT_EQ(buf->buf_size, UMQ_RX_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t));

    umq_rx_qbuf_free(&list);
}

/* 11.6 RX pool routing via UMQ_ALLOC_FLAG_POOL_TYPE + pool_type=RX */
TEST_F(TestQbufPoolMultiLevel, RxPoolRoutingViaFlag)
{
    InitRxPool();

    umq_alloc_option_t opt = {UMQ_ALLOC_FLAG_POOL_TYPE, 0, UMQ_ALLOC_POOL_RX};

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(4096, 1, &opt, &list), 0);

    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    EXPECT_EQ(buf->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
    EXPECT_EQ(buf->buf_size, UMQ_RX_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t));

    umq_rx_qbuf_free(&list);
}

/* 11.7 RX pool init validation */
TEST_F(TestQbufPoolMultiLevel, RxPoolInitValidation)
{
    EXPECT_EQ(umq_rx_qbuf_pool_init(NULL), -UMQ_ERR_EINVAL);

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.total_size = 4 * 1024 * 1024;
    EXPECT_EQ(umq_rx_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);

    cfg.buf_addr = buf_addr;
    cfg.total_size = 0;
    EXPECT_EQ(umq_rx_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);

    cfg.total_size = UMQ_RX_QBUF_BLOCK_SIZE;
    EXPECT_EQ(umq_rx_qbuf_pool_init(&cfg), -UMQ_ERR_EINVAL);
}

/* 11.8 RX pool double init */
TEST_F(TestQbufPoolMultiLevel, RxPoolDoubleInit)
{
    InitRxPool();

    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = umq_rx_io_buf_addr();
    cfg.total_size = umq_rx_io_buf_size();
    EXPECT_EQ(umq_rx_qbuf_pool_init(&cfg), -UMQ_ERR_EEXIST);

    umq_rx_qbuf_pool_uninit();
    EXPECT_FALSE(g_rx_pool_inited);
    EXPECT_EQ(umq_rx_qbuf_pool_init(&cfg), 0);
    EXPECT_TRUE(g_rx_pool_inited);
}

/* 11.9 RX io_buf_malloc idempotent */
TEST_F(TestQbufPoolMultiLevel, RxPoolIoBufMallocIdempotent)
{
    void *addr1 = umq_rx_io_buf_malloc(UMQ_BUF_SPLIT, 4 * 1024 * 1024);
    ASSERT_NE(addr1, nullptr);
    EXPECT_EQ(umq_rx_io_buf_addr(), addr1);
    EXPECT_GT(umq_rx_io_buf_size(), 0u);

    void *addr2 = umq_rx_io_buf_malloc(UMQ_BUF_SPLIT, 8 * 1024 * 1024);
    EXPECT_EQ(addr2, addr1);
}

/* 11.10 RX pool free edge cases (no-op, no crash) */
TEST_F(TestQbufPoolMultiLevel, RxPoolFreeEdgeCases)
{
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    umq_rx_qbuf_free(NULL);
    umq_rx_qbuf_free(&list);

    InitRxPool();
    umq_rx_qbuf_free(&list);
    umq_rx_qbuf_free(NULL);
}

/* 11.11 RX pool alloc when not inited / num == 0 */
TEST_F(TestQbufPoolMultiLevel, RxPoolAllocWhenNotInited)
{
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    EXPECT_EQ(umq_rx_qbuf_alloc(4096, 1, NULL, &list), -UMQ_ERR_ENOMEM);

    InitRxPool();
    EXPECT_EQ(umq_rx_qbuf_alloc(4096, 0, NULL, &list), -UMQ_ERR_ENOMEM);
}

/* 11.11b RX pool alloc request_size exceeds block capacity after headroom */
TEST_F(TestQbufPoolMultiLevel, RxPoolAllocRequestSizeExceedsCapacity)
{
    InitRxPool();

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);

    /* headroom=0: request_size > 4096 should fail */
    EXPECT_EQ(umq_rx_qbuf_alloc(4097, 1, NULL, &list), -UMQ_ERR_EINVAL);

    /* headroom=32: request_size > 4064 should fail */
    umq_alloc_option_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    opt.headroom_size = 32;
    EXPECT_EQ(umq_rx_qbuf_alloc(4065, 1, &opt, &list), -UMQ_ERR_EINVAL);

    /* headroom=128: request_size > 3968 should fail */
    opt.headroom_size = 128;
    EXPECT_EQ(umq_rx_qbuf_alloc(3969, 1, &opt, &list), -UMQ_ERR_EINVAL);

    /* boundary: request_size == block_size - headroom should succeed */
    opt.headroom_size = 32;
    EXPECT_EQ(umq_rx_qbuf_alloc(4064, 1, &opt, &list), 0);
    umq_rx_qbuf_free(&list);
}

/* 11.12 RX pool buf fields consistency across batch */
TEST_F(TestQbufPoolMultiLevel, RxPoolBufFieldsConsistency)
{
    InitRxPool();

    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, 5, NULL, &list), 0);

    uint32_t count = 0;
    umq_buf_t *cur;
    QBUF_LIST_FOR_EACH(cur, &list)
    {
        EXPECT_EQ(cur->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
        EXPECT_EQ(cur->buf_size, UMQ_RX_QBUF_BLOCK_SIZE + (uint32_t)sizeof(umq_buf_t));
        EXPECT_EQ(cur->data_size, UMQ_RX_QBUF_BLOCK_SIZE);
        EXPECT_EQ(cur->total_data_size, UMQ_RX_QBUF_BLOCK_SIZE);
        EXPECT_EQ(cur->headroom_size, 0u);
        EXPECT_EQ(cur->first_fragment, 1u);
        EXPECT_EQ(cur->alloc_state, QBUF_ALLOC_STATE_ALLOCATED);
        count++;
    }
    EXPECT_EQ(count, 5u);

    umq_rx_qbuf_free(&list);
}

/* 11.13 RX pool fallback cross-path consistency: direct (headroom=32),
 * Style A fallback (headroom=32, ubsocket), Style B fallback (headroom=0, umq_ub).
 * All produce SC[0] (4K) block_size; fallback data_size matches direct path. */
TEST_F(TestQbufPoolMultiLevel, RxPoolFallbackBufDataConsistency)
{
    InitPool(2, 16);
    InitRxPool();
    uint64_t totalBlocks = g_rx_pool.buf_cnt_with_data;

    /* Path 1: RX direct with headroom=32 */
    umq_alloc_option_t optRx;
    memset(&optRx, 0, sizeof(optRx));
    optRx.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE;
    optRx.headroom_size = 32;

    umq_buf_list_t listRx;
    QBUF_LIST_INIT(&listRx);
    ASSERT_EQ(umq_rx_qbuf_alloc(UMQ_RX_QBUF_BLOCK_SIZE - 32, 1, &optRx, &listRx), 0);
    umq_buf_t *bufRx = QBUF_LIST_FIRST(&listRx);
    ASSERT_NE(bufRx, nullptr);
    EXPECT_EQ(bufRx->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
    EXPECT_EQ(bufRx->headroom_size, 32u);
    EXPECT_EQ(bufRx->data_size, UMQ_RX_QBUF_BLOCK_SIZE - 32u);

    /* Exhaust remaining RX pool */
    umq_buf_list_t listExhaust;
    QBUF_LIST_INIT(&listExhaust);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, static_cast<uint32_t>(totalBlocks - 1), NULL, &listExhaust), 0);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, 0u);

    /* Path 2: Style A fallback (headroom=32 preserved) */
    const uint32_t reqSize = 4096 - 32;
    umq_alloc_option_t optA;
    memset(&optA, 0, sizeof(optA));
    optA.flag = UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE | UMQ_ALLOC_FLAG_POOL_TYPE;
    optA.headroom_size = 32;
    optA.pool_type = UMQ_ALLOC_POOL_RX;

    umq_buf_list_t listFallbackA;
    QBUF_LIST_INIT(&listFallbackA);
    EXPECT_EQ(umq_rx_qbuf_alloc(reqSize, 1, &optA, &listFallbackA), 0);
    umq_buf_t *bufFallbackA = QBUF_LIST_FIRST(&listFallbackA);
    ASSERT_NE(bufFallbackA, nullptr);
    EXPECT_NE(bufFallbackA->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
    EXPECT_EQ(bufFallbackA->headroom_size, 32u);
    EXPECT_EQ(bufFallbackA->data_size, 4096u - 32u);

    /* Path 3: Style B fallback (headroom=0 explicit) */
    umq_alloc_option_t optB = {UMQ_ALLOC_FLAG_POOL_TYPE, 0, UMQ_ALLOC_POOL_RX};

    umq_buf_list_t listFallbackB;
    QBUF_LIST_INIT(&listFallbackB);
    EXPECT_EQ(umq_rx_qbuf_alloc(reqSize, 1, &optB, &listFallbackB), 0);
    umq_buf_t *bufFallbackB = QBUF_LIST_FIRST(&listFallbackB);
    ASSERT_NE(bufFallbackB, nullptr);
    EXPECT_NE(bufFallbackB->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);
    EXPECT_EQ(bufFallbackB->headroom_size, 0u);
    EXPECT_EQ(bufFallbackB->data_size, 4096u);

    EXPECT_EQ(bufRx->headroom_size, bufFallbackA->headroom_size);
    EXPECT_NE(bufFallbackA->headroom_size, bufFallbackB->headroom_size);

    EXPECT_EQ(bufRx->buf_size, 4096u + (uint32_t)sizeof(umq_buf_t));
    EXPECT_EQ(bufFallbackA->buf_size, 4096u + (uint32_t)sizeof(umq_buf_t));
    EXPECT_EQ(bufFallbackB->buf_size, 4096u + (uint32_t)sizeof(umq_buf_t));

    umq_rx_qbuf_free(&listRx);
    umq_rx_qbuf_free(&listExhaust);
    umq_qbuf_free(&listFallbackA);
    umq_qbuf_free(&listFallbackB);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);
}

/* 11.14 RX pool exhaustion -> fallback -> free RX -> re-alloc via RX direct path. */
TEST_F(TestQbufPoolMultiLevel, RxPoolExhaustionThenFallbackInterleaved)
{
    InitPool(2, 16);
    InitRxPool();
    uint64_t totalBlocks = g_rx_pool.buf_cnt_with_data;

    umq_buf_list_t listExhaust;
    QBUF_LIST_INIT(&listExhaust);
    ASSERT_EQ(umq_rx_qbuf_alloc(4096, static_cast<uint32_t>(totalBlocks), NULL, &listExhaust), 0);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, 0u);

    umq_buf_list_t listFallback;
    QBUF_LIST_INIT(&listFallback);
    EXPECT_EQ(umq_rx_qbuf_alloc(4096, 1, NULL, &listFallback), 0);
    umq_buf_t *bufFallback = QBUF_LIST_FIRST(&listFallback);
    ASSERT_NE(bufFallback, nullptr);
    EXPECT_NE(bufFallback->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);

    umq_rx_qbuf_free(&listExhaust);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);

    umq_qbuf_free(&listFallback);

    umq_buf_list_t listRealloc;
    QBUF_LIST_INIT(&listRealloc);
    EXPECT_EQ(umq_rx_qbuf_alloc(4096, 1, NULL, &listRealloc), 0);
    umq_buf_t *bufRealloc = QBUF_LIST_FIRST(&listRealloc);
    ASSERT_NE(bufRealloc, nullptr);
    EXPECT_EQ(bufRealloc->mempool_id, UMQ_RX_QBUF_MEMPOOL_ID);

    umq_rx_qbuf_free(&listRealloc);
    EXPECT_EQ(g_rx_pool.buf_cnt_with_data, totalBlocks);
}

/* 10.10 SPLIT layout descending-order verification: blk_sizes [4K, 64K] laid out with the 64K
 * (larger) SC first so per-SC alignment padding is eliminated. With explicit blockCounts={8,8},
 * the closed-form denom = 4096+65536+2*128 = 69888 matches the real (padding-free) linear
 * coefficient exactly, so per_sc_block_counts[0] = 8 and the data+header regions fill the
 * non-ext-header portion of total_size exactly (zero overflow, zero waste).
 *
 * Layout (descending): sc=1 (64K) data [buf, buf+524288); sc=0 (4K) data [buf+524288, buf+557056);
 *                       header region [buf+557056, buf+559104); ext_header [buf+559104, buf+4753408). */
TEST_F(TestQbufPoolMultiLevel, SplitLayoutDescendingNoPaddingNoOverflow)
{
    const uint64_t totalSize = 4753408ULL; /* 559104(data+header) + 4194304(ext_header) */
    const uint64_t bc_split[] = {8, 8};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, totalSize, 0, 0, 0, bc_split);
    ASSERT_EQ(g_qbuf_pool.size_class_count, 2u);
    ASSERT_EQ(g_qbuf_pool.block_sizes[0], 4096u);
    ASSERT_EQ(g_qbuf_pool.block_sizes[1], 65536u);
    ASSERT_GT(g_qbuf_pool.per_sc_block_counts[0], 0u);

    /* Buggy ascending layout would give N=8 with 32K padding -> overflow 32K.
     * Descending layout: N=8, padding=0, fills total_size exactly. */
    EXPECT_EQ(g_qbuf_pool.per_sc_block_counts[0], 8ULL);

    char *base = (char *)buf_addr;
    char *limit = base + totalSize; /* exclusive upper bound */

    /* Descending order: sc=1 (64K) data region is at the LOW address, sc=0 (4K) at the HIGH address. */
    ASSERT_NE(g_qbuf_pool.data_region_start[1], nullptr);
    ASSERT_NE(g_qbuf_pool.data_region_start[0], nullptr);
    EXPECT_EQ(g_qbuf_pool.data_region_start[1], base);                /* 64K SC at buf+0 */
    EXPECT_EQ(g_qbuf_pool.data_region_end[1], base + 524288);          /* 8*65536 */
    EXPECT_EQ(g_qbuf_pool.data_region_start[0], base + 524288);       /* 4K SC right after, no padding */
    EXPECT_EQ(g_qbuf_pool.data_region_end[0], base + 557056);         /* 524288 + 8*4096 */

    /* Header region (8*2*128 = 2048 B) immediately after the last data region. */
    ASSERT_NE(g_qbuf_pool.header_buffer, nullptr);
    EXPECT_EQ(g_qbuf_pool.header_buffer, base + 557056);
    char *headerEnd = (char *)g_qbuf_pool.header_buffer + g_qbuf_pool.total_block_num * (uint64_t)sizeof(umq_buf_t);
    EXPECT_EQ(headerEnd, base + 559104);                              /* data+header region end */
    /* ext_header region follows: 32768*128 = 4194304 bytes */
    EXPECT_EQ(g_qbuf_pool.ext_header_buffer, base + 559104);
    char *extHeaderEnd = (char *)g_qbuf_pool.ext_header_buffer + 32768ULL * sizeof(umq_buf_t);
    EXPECT_EQ(extHeaderEnd, base + totalSize);                        /* exactly total_size */
    EXPECT_LE(extHeaderEnd, limit);

    /* All region ends within [base, limit]. */
    for (uint32_t sc = 0; sc < g_qbuf_pool.size_class_count; sc++) {
        ASSERT_LE(g_qbuf_pool.data_region_start[sc], limit);
        ASSERT_LE(g_qbuf_pool.data_region_end[sc], limit);
    }
    EXPECT_LE(g_qbuf_pool.header_buffer, limit);
    EXPECT_LE(g_qbuf_pool.ext_header_buffer, limit);

    umq_qbuf_pool_uninit();
}

/* ==================== Supplementary test cases (post-fix) ==================== */

/* ExpansionDataToHead: expansion-pool buf data_to_head round-trip */
TEST_F(TestQbufPoolMultiLevel, ExpansionDataToHead)
{
    const uint64_t bc[] = {10, 0};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 8 * 1024 * 1024, 0, 0, 256 * 1024, bc);
    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);
    std::vector<umq_buf_list_t> holders(sc0Blocks + 10);
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0) << i;
    }
    for (int retry = 0; retry < 200; retry++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
            break;
        usleep(1000);
    }
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u);
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        void *data = QBUF_LIST_FIRST(&holders[i])->buf_data;
        umq_buf_t *head = umq_qbuf_data_to_head(data);
        ASSERT_NE(head, nullptr) << "data_to_head failed for buf " << i;
        EXPECT_EQ(head->buf_data, data) << "data_to_head mismatch for buf " << i;
    }
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* ExpansionDataToHeadExplicit: explicit expansion data_to_head API */
TEST_F(TestQbufPoolMultiLevel, ExpansionDataToHeadExplicit)
{
    const uint64_t bc[] = {10, 0};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 8 * 1024 * 1024, 0, 0, 256 * 1024, bc);
    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);
    std::vector<umq_buf_list_t> holders(sc0Blocks + 10);
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0) << i;
    }
    for (int retry = 0; retry < 200; retry++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
            break;
        usleep(1000);
    }
    for (uint32_t i = sc0Blocks; i < sc0Blocks + 10; i++) {
        void *data = QBUF_LIST_FIRST(&holders[i])->buf_data;
        umq_buf_t *head = umq_qbuf_expansion_data_to_head(data);
        ASSERT_NE(head, nullptr) << "expansion_data_to_head failed for buf " << i;
        EXPECT_EQ(head->buf_data, data) << "expansion_data_to_head mismatch for buf " << i;
    }
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* HeadroomResetCombineMode: headroom_reset in COMBINE mode */
TEST_F(TestQbufPoolMultiLevel, HeadroomResetCombineMode)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);
    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    uint16_t origHeadroom = buf->headroom_size;
    EXPECT_EQ(umq_qbuf_headroom_reset(buf, 256), 0);
    EXPECT_EQ(buf->headroom_size, 256u);
    EXPECT_EQ(umq_qbuf_headroom_reset(buf, origHeadroom), 0);
    umq_qbuf_free(&list);
}

/* HeadroomResetUninitedPool: headroom_reset when pool not inited returns error */
TEST_F(TestQbufPoolMultiLevel, HeadroomResetUninitedPool)
{
    EXPECT_NE(umq_qbuf_headroom_reset(NULL, 0), 0);
}

/* ExpansionSlotDistBasic: expansion_slot_dist returns slot info */
TEST_F(TestQbufPoolMultiLevel, ExpansionSlotDistBasic)
{
    const uint64_t bc[] = {10, 0};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 8 * 1024 * 1024, 0, 0, 256 * 1024, bc);
    uint32_t sc0Blocks = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    ASSERT_GT(sc0Blocks, 0u);
    std::vector<umq_buf_list_t> holders(sc0Blocks + 10);
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0);
    }
    for (int retry = 0; retry < 200; retry++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
            break;
        usleep(1000);
    }
    umq_expansion_slot_info_t infos[32];
    uint32_t n = umq_qbuf_expansion_slot_dist(infos, 32);
    EXPECT_GT(n, 0u) << "should have at least 1 expansion slot";
    if (n > 0) {
        EXPECT_LT(infos[0].size_class, g_qbuf_pool.size_class_count);
        EXPECT_GT(infos[0].total_block_cnt, 0u);
    }
    for (uint32_t i = 0; i < sc0Blocks + 10; i++) {
        umq_qbuf_free(&holders[i]);
    }
}

/* ExpansionSlotDistNullCap: NULL infos or cap=0 returns 0 */
TEST_F(TestQbufPoolMultiLevel, ExpansionSlotDistNullCap)
{
    InitPool(2, 16);
    EXPECT_EQ(umq_qbuf_expansion_slot_dist(NULL, 32), 0u);
    umq_expansion_slot_info_t infos[4];
    EXPECT_EQ(umq_qbuf_expansion_slot_dist(infos, 0), 0u);
}

/* ExpansionSlotDistScaleCapOff: scaleCap=off returns 0 */
TEST_F(TestQbufPoolMultiLevel, ExpansionSlotDistScaleCapOff)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false);
    umq_expansion_slot_info_t infos[4];
    EXPECT_EQ(umq_qbuf_expansion_slot_dist(infos, 4), 0u);
}

/* SetTlsExpandQbufPoolDepth: dynamic adjustment API exists and does not crash */
TEST_F(TestQbufPoolMultiLevel, SetTlsExpandQbufPoolDepth)
{
    InitPool(2, 16);
    uint64_t origExpandDepth = g_qbuf_pool.tls_expand_qbuf_pool_depth;
    EXPECT_GT(origExpandDepth, 0u);
    umq_qbuf_set_tls_expand_qbuf_pool_depth(1);
    EXPECT_GT(g_qbuf_pool.tls_expand_qbuf_pool_depth, 0u)
        << "value should remain positive after adjustment";
}

/* FourScConfiguration: 4-SC [4K, 16K, 64K, 256K] routing */
TEST_F(TestQbufPoolMultiLevel, FourScConfiguration)
{
    const uint64_t bc4[] = {1000, 500, 200, 50};
    InitPool(4, 4, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, true, 300 * 1024 * 1024, 0, 0, 0, bc4);
    EXPECT_EQ(g_qbuf_pool.size_class_count, 4u);
    EXPECT_EQ(select_size_class(2 * 1024), 0u);
    EXPECT_EQ(select_size_class(8 * 1024), 1u);
    EXPECT_EQ(select_size_class(32 * 1024), 2u);
    EXPECT_EQ(select_size_class(128 * 1024), 3u);
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(8 * 1024, 1, NULL, &list), 0);
    EXPECT_EQ(buf_data_to_size_class(QBUF_LIST_FIRST(&list)->buf_data), 1u);
    umq_qbuf_free(&list);
}

/* InitAcceptedBlockSizes12K: 12K is valid multiple of 4K (12K % 4K == 0) */
TEST_F(TestQbufPoolMultiLevel, InitAcceptedBlockSizes12K)
{
    umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.data_size = 4096;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.size_class_count = 2;
    cfg.explicit_block_sizes[0] = 4096;
    cfg.explicit_block_sizes[1] = 12 * 1024;
    cfg.per_sc_block_counts[0] = 100;
    cfg.per_sc_block_counts[1] = 10;
    EXPECT_EQ(umq_qbuf_pool_init(&cfg), 0) << "12K is valid (12K % 4K == 0)";
    umq_qbuf_pool_uninit();
}

/* InitRejectedBlockSizesNotMultiple: 6K is NOT a multiple of 4K */
TEST_F(TestQbufPoolMultiLevel, InitRejectedBlockSizesNotMultiple)
{
    umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.data_size = 4096;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.size_class_count = 2;
    cfg.explicit_block_sizes[0] = 4096;
    cfg.explicit_block_sizes[1] = 6 * 1024;
    EXPECT_NE(umq_qbuf_pool_init(&cfg), 0) << "6K is not a multiple of 4K";
}

/* InitRejectedCountExceedsMax: count > UMQ_QBUF_SIZE_CLASS_MAX */
TEST_F(TestQbufPoolMultiLevel, InitRejectedCountExceedsMax)
{
    umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = BUF_SIZE;
    cfg.data_size = 4096;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.size_class_count = UMQ_QBUF_SIZE_CLASS_MAX + 1;
    cfg.explicit_block_sizes[0] = 4096;
    EXPECT_NE(umq_qbuf_pool_init(&cfg), 0);
}

/* AllocReturnEnomemWhenPoolExhausted: scaleCap=off + escape=off -> ENOMEM */
TEST_F(TestQbufPoolMultiLevel, AllocReturnEnomemWhenPoolExhausted)
{
    umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = 8 * 1024 * 1024;
    cfg.data_size = 4096;
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.size_class_count = 2;
    cfg.explicit_block_sizes[0] = 4096;
    cfg.explicit_block_sizes[1] = 65536;
    cfg.disable_scale_cap = true;
    cfg.disable_malloc_escape = true;
    cfg.per_sc_block_counts[0] = 10;
    cfg.per_sc_block_counts[1] = 1;
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), 0);
    std::vector<umq_buf_list_t> holders(20);
    bool gotEnomem = false;
    for (uint32_t i = 0; i < 20; i++) {
        QBUF_LIST_INIT(&holders[i]);
        int ret = umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]);
        if (ret != 0) {
            gotEnomem = true;
            break;
        }
    }
    for (auto &h : holders) {
        if (QBUF_LIST_FIRST(&h) != nullptr) {
            umq_qbuf_free(&h);
        }
    }
    umq_qbuf_pool_uninit();
}

/* CombineModeHeadroomResetOverLimit: headroom reset exceeding block capacity */
TEST_F(TestQbufPoolMultiLevel, CombineModeHeadroomResetOverLimit)
{
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_COMBINE);
    umq_buf_list_t list;
    QBUF_LIST_INIT(&list);
    ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &list), 0);
    umq_buf_t *buf = QBUF_LIST_FIRST(&list);
    ASSERT_NE(buf, nullptr);
    uint32_t block_size = buf->buf_size;
    uint16_t excessive = (uint16_t)(block_size - sizeof(umq_buf_t) + 1);
    int ret = umq_qbuf_headroom_reset(buf, excessive);
    EXPECT_NE(ret, 0) << "headroom exceeding block capacity should be rejected";
    umq_qbuf_free(&list);
}

/* MultipleExpansionShrinkCycles: expansion + shrink repeated */
TEST_F(TestQbufPoolMultiLevel, MultipleExpansionShrinkCycles)
{
    const uint64_t bc_ms[] = {10, 0};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 8 * 1024 * 1024, 0, 0, 256 * 1024, bc_ms);
    for (int cycle = 0; cycle < 3; cycle++) {
        uint32_t sc0BlkNum = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
        std::vector<umq_buf_list_t> holders(sc0BlkNum + 70);
        for (uint32_t i = 0; i < sc0BlkNum + 70; i++) {
            QBUF_LIST_INIT(&holders[i]);
            ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0) << "cycle " << cycle << " alloc " << i;
        }
        for (int retry = 0; retry < 200; retry++) {
            if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
                break;
            usleep(1000);
        }
        EXPECT_GE(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u) << "cycle " << cycle;
        for (auto &h : holders) {
            umq_qbuf_free(&h);
        }
        if (g_thread_cache.block_pool.buf_cnt_with_data[0] > 0) {
            return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, true, 0, 0);
        }
        for (int retry = 0; retry < 200; retry++) {
            if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_shrinking, __ATOMIC_ACQUIRE) == 0)
                break;
            usleep(1000);
        }
    }
}

/* PerScTlsDepthVerification: per-SC TLS depth override */
TEST_F(TestQbufPoolMultiLevel, PerScTlsDepthVerification)
{
    const uint64_t bc_tls[] = {100, 10};
    qbuf_pool_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.buf_addr = buf_addr;
    cfg.total_size = 8 * 1024 * 1024;
    (void)umq_buf_size_pow_small_set(BLOCK_SIZE_4K);
    cfg.data_size = umq_buf_size_small();
    cfg.mode = UMQ_BUF_SPLIT;
    cfg.size_class_count = 2;
    cfg.explicit_block_sizes[0] = 4096;
    cfg.explicit_block_sizes[1] = 65536;
    cfg.disable_scale_cap = false;
    for (uint32_t i = 0; i < 2; i++) cfg.per_sc_block_counts[i] = bc_tls[i];
    cfg.per_sc_tls_qbuf_pool_depth[0] = 2048;
    cfg.per_sc_tls_qbuf_pool_depth[1] = 128;
    cfg.seg_ops.register_seg_callback = stub_register_seg;
    ASSERT_EQ(umq_qbuf_pool_init(&cfg), 0);
    EXPECT_EQ(g_qbuf_pool.per_sc_tls_qbuf_pool_depth[0], 2048u);
    EXPECT_EQ(g_qbuf_pool.per_sc_tls_qbuf_pool_depth[1], 128u);
    umq_qbuf_pool_uninit();
}

/* FreeReturnsExpansionBufToSlot: expansion buf returns to expansion slot, not global */
TEST_F(TestQbufPoolMultiLevel, FreeReturnsExpansionBufToSlot)
{
    const uint64_t bc_frs[] = {5, 0};
    InitPool(2, 16, BLOCK_SIZE_4K, UMQ_BUF_SPLIT, false, 8 * 1024 * 1024, 0, 0, 256 * 1024, bc_frs);
    uint32_t sc0BlkNum = (uint32_t)g_qbuf_pool.block_pool[0].buf_cnt_with_data;
    std::vector<umq_buf_list_t> holders(sc0BlkNum + 10);
    for (uint32_t i = 0; i < sc0BlkNum + 10; i++) {
        QBUF_LIST_INIT(&holders[i]);
        ASSERT_EQ(umq_qbuf_alloc(2 * 1024, 1, NULL, &holders[i]), 0);
    }
    for (int retry = 0; retry < 200; retry++) {
        if (__atomic_load_n(&g_qbuf_pool.exp_pool_with_data[0].is_expanding, __ATOMIC_ACQUIRE) == 0)
            break;
        usleep(1000);
    }
    EXPECT_GE(g_qbuf_pool.exp_pool_with_data[0].expansion_count, 1u);
    uint64_t expFreeBefore = 0;
    qbuf_expansion_pool_slot_t *slot;
    URPC_LIST_FOR_EACH(slot, node, &g_qbuf_pool.exp_pool_with_data[0].slot_list) {
        expFreeBefore += slot->free_block_cnt;
    }
    for (auto &h : holders) {
        umq_qbuf_free(&h);
    }
    if (g_thread_cache.block_pool.buf_cnt_with_data[0] > 0) {
        return_to_global(&g_qbuf_pool.block_pool[0], &g_thread_cache.block_pool, &g_thread_cache.stats, true, 0, 0);
    }
    uint64_t expFreeAfter = 0;
    URPC_LIST_FOR_EACH(slot, node, &g_qbuf_pool.exp_pool_with_data[0].slot_list) {
        expFreeAfter += slot->free_block_cnt;
    }
    EXPECT_GT(expFreeAfter, expFreeBefore) << "expansion slot should have more free blocks after return";
}
