/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest allocator, per thread lock free mempool
 * Create: 2024-3-6
 */

#include <string.h>
#include <sys/mman.h>
#include <malloc.h>

#include "perftest_thread.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_perftest_util.h"
#include "urpc_list.h"
#include "urpc_framework_types.h"

#include "urpc_lib_perftest_allocator.h"

// layout: one_sge one_sge one_sge | 256 + 128 + 4K | one_sge one_sge one_sge | 256 + 128 + 4K | ...
typedef struct allocator_sges {
    urpc_list_t node;
    struct urpc_sge sge[0];
} allocator_sges_t;

typedef struct urpc_perftest_allocator_context {
    char *buf_addr;  // filled with allocator_sges_t elements
    urpc_list_t buf_head;
    uint64_t tsge;
    uint64_t buf_size_per_core;
    uint32_t buf_free;
} urpc_perftest_allocator_context_t;

static urpc_perftest_allocator_context_t *g_perftest_allocator_ctx;
static allocator_sges_t *g_perftest_one_sges[PERFTEST_THREAD_MAX_NUM];
static uint32_t g_perftest_allocator_ctx_num;
static allocator_sges_info_t g_buf_info;
static struct allocator_ctx g_plog_allocator_ctx;

uint32_t get_recv_max_sge_size(uint32_t sge_num, int i)
{
    if (sge_num == 1) {
        return g_buf_info.sge_size[i];
    }
    return g_buf_info.buf_size[i];
}

uint32_t get_set_sge_size(int i)
{
    return g_buf_info.buf_size[i];
}

static void allocator_sges_init(urpc_perftest_allocator_context_t *ctx, uint32_t one_sge_size)
{
    allocator_sges_t *buf;
    for (uint32_t i = 0; i < ctx->buf_free; i++) {
        buf = (allocator_sges_t *)(ctx->buf_addr + i * (g_buf_info.head_size + one_sge_size));
        urpc_list_push_back(&ctx->buf_head, &buf->node);
    }
}

static inline allocator_sges_t *allocator_sges_get(urpc_perftest_allocator_context_t *ctx)
{
    allocator_sges_t *buf = NULL;
    INIT_CONTAINER_PTR(buf, ctx->buf_head.next, node);  // list first

    urpc_list_remove(&buf->node);
    ctx->buf_free--;

    return buf;
}

static inline void allocator_sges_put(urpc_perftest_allocator_context_t *ctx, allocator_sges_t *buf)
{
    urpc_list_push_front(&ctx->buf_head, &buf->node);
    ctx->buf_free++;
}

static int urpc_perftest_allocator_sges_get(
    struct urpc_sge **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option)
{
    urpc_perftest_allocator_context_t *ctx = &g_perftest_allocator_ctx[perftest_thread_index()];
    if (URPC_UNLIKELY(ctx->buf_free == 0)) {
        return URPC_FAIL;
    }

    allocator_sges_t *allocator_sge = allocator_sges_get(ctx);
    void *addr = (void *)allocator_sge + g_buf_info.head_size;
    for (uint32_t i = 0; i < g_buf_info.count; i++) {
        allocator_sge->sge[i].length = g_buf_info.buf_size[i];
        allocator_sge->sge[i].flag = 0;
        allocator_sge->sge[i].addr = (uint64_t)(uintptr_t)(addr);
        allocator_sge->sge[i].mem_h = ctx->tsge;
        addr += g_buf_info.sge_size[i];
    }
    if (g_buf_info.count == 1) {
        allocator_sge->sge[0].length = g_buf_info.sge_size[0];
    }
    *sge = allocator_sge->sge;
    *num = g_buf_info.count;

    return URPC_SUCCESS;
}

static inline int urpc_perftest_allocator_sges_put(struct urpc_sge *sge, uint32_t num,
    urpc_allocator_option_t *option)
{
    uint32_t lcore_index = perftest_thread_index();
    urpc_perftest_allocator_context_t *ctx = &g_perftest_allocator_ctx[lcore_index];

    allocator_sges_t *allocator_sge = CONTAINER_OF_FIELD(sge, allocator_sges_t, sge);
    allocator_sges_put(ctx, allocator_sge);

    return URPC_SUCCESS;
}

static int urpc_plog_allocator_get_sges(urpc_sge_t **sge, uint32_t num, urpc_allocator_option_t *option)
{
    if (num == 0) {
        LOG_PRINT("num is 0\n");
        return URPC_FAIL;
    }

    urpc_sge_t *tmp_sge = calloc(num, sizeof(urpc_sge_t));
    if (tmp_sge == NULL) {
        LOG_PRINT("calloc sge failed\n");
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < num; i++) {
        tmp_sge[i].flag = SGE_FLAG_NO_MEM;
    }

    *sge = tmp_sge;

    return URPC_SUCCESS;
}

static int urpc_plog_allocator_put_sges(urpc_sge_t *sge, urpc_allocator_option_t *option)
{
    if (sge == NULL) {
        LOG_PRINT("sge is NULL\n");
        return URPC_FAIL;
    }

    free(sge);
    return URPC_SUCCESS;
}

static int urpc_plog_allocator_get_raw_buf(struct urpc_sge *sge, uint64_t total_size, urpc_allocator_option_t *option)
{
    if (sge == NULL) {
        LOG_PRINT("sge or num is NULL\n");
        return URPC_FAIL;
    }
    if (total_size > URPC_PERFTEST_ONE_SGE_SIZE) {
        LOG_PRINT("total_size id too large:%lu\n", total_size);
        return URPC_FAIL;
    }

    void *buf = eslab_get_buf(&g_plog_allocator_ctx.slab);
    if (buf == NULL) {
        LOG_PRINT("get buf is NULL\n");
        return URPC_FAIL;
    }
    sge->length = URPC_PERFTEST_ONE_SGE_SIZE;
    sge->flag = 0;
    sge->addr = (uint64_t)(uintptr_t)buf;
    sge->mem_h = g_plog_allocator_ctx.tsge;

    return URPC_SUCCESS;
}

static int urpc_plog_allocator_put_raw_buf(struct urpc_sge *sge, urpc_allocator_option_t *option)
{
    if (sge == NULL || sge[0].addr == 0) {
        LOG_PRINT("sge is NULL or addr is 0\n");
        return URPC_FAIL;
    }

    eslab_put_buf(&g_plog_allocator_ctx.slab, (void *)(uintptr_t)sge[0].addr);
    sge[0].length = 0;
    return URPC_SUCCESS;
}

static urpc_allocator_t g_allocator = {
    .get = urpc_perftest_allocator_sges_get,
    .put = urpc_perftest_allocator_sges_put,
    .get_raw_buf = urpc_plog_allocator_get_raw_buf,
    .put_raw_buf = urpc_plog_allocator_put_raw_buf,
    .get_sges = urpc_plog_allocator_get_sges,
    .put_sges = urpc_plog_allocator_put_sges,
};

urpc_allocator_t *urpc_perftest_allocator_get(void)
{
    return &g_allocator;
}

// use same sge buffer for send and recv, only used in early-rsp mode
static inline int allocator_use_one_buf_sges_get(
    struct urpc_sge **sge, uint32_t *num, uint64_t total_size, urpc_allocator_option_t *option)
{
    allocator_sges_t *allocator_sge = g_perftest_one_sges[perftest_thread_index()];
    *sge = allocator_sge->sge;
    *num = g_buf_info.count;
 
    return URPC_SUCCESS;
}

static inline int allocator_use_one_buf_sges_put(struct urpc_sge *sge, uint32_t num, urpc_allocator_option_t *option)
{
    return URPC_SUCCESS;
}

static void allocator_use_one_buf_init(uint32_t i)
{
    g_perftest_one_sges[i] = (allocator_sges_t *)g_perftest_allocator_ctx[i].buf_addr;
    allocator_sges_t *allocator_sge = g_perftest_one_sges[i];
    void *addr = (void *)allocator_sge + g_buf_info.head_size;
    for (uint32_t j = 0; j < g_buf_info.count; j++) {
        allocator_sge->sge[j].length = g_buf_info.buf_size[j];
        allocator_sge->sge[j].flag = 0;
        allocator_sge->sge[j].addr = (uint64_t)(uintptr_t)(addr);
        allocator_sge->sge[j].mem_h = g_perftest_allocator_ctx[i].tsge;
        addr += g_buf_info.sge_size[j];
    }
    if (g_buf_info.count == 1) {
        allocator_sge->sge[0].length = g_buf_info.sge_size[0];
    }
}

int urpc_perftest_allocator_init(uint32_t worker_num, uint32_t *buf_size, uint32_t buf_len, uint32_t element_num,
    bool alloc_buf, bool align)
{
    g_perftest_allocator_ctx = (urpc_perftest_allocator_context_t *)calloc(
        PERFTEST_THREAD_MAX_NUM, sizeof(urpc_perftest_allocator_context_t));
    if (g_perftest_allocator_ctx == NULL) {
        LOG_PRINT("allocator malloc context failed\n");
        return -1;
    }

    g_buf_info.count = buf_len;

    uint32_t one_sge_size = 0;
    for (uint32_t i = 0; i < buf_len; i++) {
        g_buf_info.buf_size[i] = buf_size[i];
        if (align) {
            uint32_t count = buf_size[i] / URPC_PERFTEST_ONE_SGE_SIZE;
            count += buf_size[i] % URPC_PERFTEST_ONE_SGE_SIZE == 0 ? 0 : 1;
            g_buf_info.sge_size[i] = count * URPC_PERFTEST_ONE_SGE_SIZE;
        } else {
            g_buf_info.sge_size[i] = buf_size[i];
        }
        one_sge_size += g_buf_info.sge_size[i];
    }
    g_buf_info.head_size = align ? URPC_PERFTEST_ONE_SGE_SIZE :
                                   (sizeof(urpc_list_t) + sizeof(struct urpc_sge) * buf_len);

    uint32_t num = alloc_buf ? element_num : 1;
    // worker thread注册的内存和queue创建时使用的内存需要相同 否则对端报ib_wc_status: local protection error
    // 而queue创建线程和worker线程不一定是同一个, tsge需要相同
    uint64_t mem_size = (uint64_t)(one_sge_size + g_buf_info.head_size) * num;

    // 4k aling
    uint64_t tatal_mem_size = (mem_size * (uint64_t)(worker_num + 1));
    tatal_mem_size += (URPC_PERFTEST_PAGE_SIZE - (tatal_mem_size % URPC_PERFTEST_PAGE_SIZE));

    char *addr = NULL;
    addr = memalign(URPC_PERFTEST_PAGE_SIZE, tatal_mem_size);
    if (addr == NULL) {
        LOG_PRINT("allocator malloc buffer failed\n");
        goto FREE_CTX;
    }

    uint64_t tsge = urpc_mem_seg_register((uint64_t)(uintptr_t)addr, tatal_mem_size);
    if (tsge == 0) {
        LOG_PRINT("urpc_mem_seg_register failed\n");
        goto MUNMAP_BUF_ADDR;
    }

    for (uint32_t i = 0; i < worker_num + 1; i++) {
        g_perftest_allocator_ctx[i].buf_addr = addr + i * mem_size;
        g_perftest_allocator_ctx[i].buf_size_per_core = mem_size;
        g_perftest_allocator_ctx[i].buf_free = num;
        g_perftest_allocator_ctx[i].tsge = tsge;
        urpc_list_init(&g_perftest_allocator_ctx[i].buf_head);

        allocator_sges_init(&g_perftest_allocator_ctx[i], one_sge_size);

        allocator_use_one_buf_init(i);
    }

    if (!alloc_buf) {
        g_allocator.get = allocator_use_one_buf_sges_get;
        g_allocator.put = allocator_use_one_buf_sges_put;
    }

    g_perftest_allocator_ctx_num = worker_num + 1;

    return 0;

MUNMAP_BUF_ADDR:
    (void)munmap(addr, mem_size * (worker_num + 1));

FREE_CTX:
    free(g_perftest_allocator_ctx);
    g_perftest_allocator_ctx = NULL;

    return -1;
}

void urpc_perftest_allocator_uninit(void)
{
    if (g_perftest_allocator_ctx == NULL) {
        return;
    }

    (void)urpc_mem_seg_unregister(g_perftest_allocator_ctx[0].tsge);
    (void)munmap(g_perftest_allocator_ctx[0].buf_addr,
        g_perftest_allocator_ctx[0].buf_size_per_core * g_perftest_allocator_ctx_num);

    free(g_perftest_allocator_ctx);
    g_perftest_allocator_ctx = NULL;
    g_perftest_allocator_ctx_num = 0;
}

uint32_t perftest_post_rx_buff(uint64_t qh, uint32_t post_num, uint32_t rx_buf_size)
{
    urpc_sge_t *sges;
    uint32_t sge_num = 0;
    uint32_t posted = 0;
    while (posted < post_num) {
        if ((g_allocator.get(&sges, &sge_num, rx_buf_size, NULL) != 0)) {
            LOG_PRINT("get sges failed\n");
            return URPC_U32_FAIL;
        }

        if (urpc_queue_rx_post(qh, sges, sge_num) != URPC_SUCCESS) {
            LOG_PRINT("post rx failed, posted %u\n", posted);
            (void)g_allocator.put(sges, sge_num, NULL);
            break;
        }
        posted++;
    }
    return posted;
}
