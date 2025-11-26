/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize allocator function
 * Create: 2024-1-1
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "queue.h"
#include "channel.h"
#include "ip_handshaker.h"
#include "urpc_lib_log.h"
#include "state.h"
#include "urpc_framework_api.h"
#include "urpc_dbuf_stat.h"
#include "allocator.h"

#define DEFAULT_ALLOCATOR_ALIGNMENT 4096 // Memory alignment method

typedef struct urpc_da_cfg {
    uint64_t addr;
    uint64_t addr_large;
    uint64_t tsge;
    uint64_t tsge_large;
    uint32_t total_size;
    uint32_t total_size_large;
    eslab_t slab;
    eslab_t slab_large;
    uint32_t large_sge_size;
} urpc_da_cfg_t;

static struct {
    urpc_da_cfg_t cfg;
    pthread_mutex_t lock;
} g_urpc_da_ctx = {
    .cfg = {0},
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static urpc_allocator_t *g_urpc_allocator = NULL;
static pthread_mutex_t g_urpc_allocator_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_urpc_allocator_inited = false;

static bool urpc_default_allocator_cfg_check(default_allocator_cfg_t *cfg)
{
    if (cfg->need_large_sge && (cfg->large_sge_size > DEFAULT_LARGE_SGE_MAX_SIZE)) {
        URPC_LIB_LOG_ERR("not supported size[%u] for large segment allocator\n", cfg->large_sge_size);
        return false;
    }
    return true;
}

// default_allocator will totaly alloc 1MB + xx MB memory, 1MB for 64B (16384 pics), xx MB for x KB (8192 pics)
int urpc_default_allocator_init(default_allocator_cfg_t *cfg)
{
    if (!urpc_default_allocator_cfg_check(cfg)) {
        return URPC_FAIL;
    }
    (void)pthread_mutex_lock(&g_urpc_da_ctx.lock);
    if (g_urpc_da_ctx.cfg.total_size != 0) {
        URPC_LIB_LOG_ERR("default allocator is already initialized\n");
        (void)pthread_mutex_unlock(&g_urpc_da_ctx.lock);
        return URPC_SUCCESS;
    }
    g_urpc_da_ctx.cfg.total_size = DEFAULT_SGE_NUM * DEFAULT_SGE_SIZE;
    void *buf_head;
    uint64_t total_size;
    void *buf = (void *)urpc_dbuf_aligned_alloc(URPC_DBUF_TYPE_ALLOCATOR,
        DEFAULT_ALLOCATOR_ALIGNMENT, g_urpc_da_ctx.cfg.total_size, &buf_head, &total_size);
    if (buf == NULL) {
        URPC_LIB_LOG_ERR("malloc default buf failed\n");
        goto UNSET;
    }
    g_urpc_da_ctx.cfg.addr = (uint64_t)(uintptr_t)buf;
    g_urpc_da_ctx.cfg.tsge = urpc_mem_seg_register((uint64_t)(uintptr_t)buf_head, (uint64_t)total_size);
    if (g_urpc_da_ctx.cfg.tsge == URPC_INVALID_HANDLE) {
        URPC_LIB_LOG_ERR("register default buf failed\n");
        goto FREE_ADDR;
    }
    eslab_init(&g_urpc_da_ctx.cfg.slab, buf, DEFAULT_SGE_SIZE, DEFAULT_SGE_NUM);
    URPC_LIB_LOG_DEBUG("default allocator get normal segment num[%u]\n", DEFAULT_SGE_NUM);

    if (cfg->need_large_sge) {
        g_urpc_da_ctx.cfg.large_sge_size = cfg->large_sge_size == 0 ? DEFAULT_LARGE_SGE_SIZE : cfg->large_sge_size;
        g_urpc_da_ctx.cfg.total_size_large = g_urpc_da_ctx.cfg.large_sge_size * DEFAULT_LARGE_SGE_NUM;
        buf = (void *)urpc_dbuf_aligned_alloc(URPC_DBUF_TYPE_ALLOCATOR,
            DEFAULT_ALLOCATOR_ALIGNMENT, g_urpc_da_ctx.cfg.total_size_large, &buf_head, &total_size);
        if (buf == NULL) {
            URPC_LIB_LOG_ERR("malloc default buf failed\n");
            goto UNINIT_ESLAB;
        }
        g_urpc_da_ctx.cfg.addr_large = (uint64_t)(uintptr_t)buf;
        g_urpc_da_ctx.cfg.tsge_large =
            urpc_mem_seg_register((uint64_t)(uintptr_t)buf_head, (uint64_t)total_size);
        if (g_urpc_da_ctx.cfg.tsge_large == URPC_INVALID_HANDLE) {
            URPC_LIB_LOG_ERR("register default buf failed\n");
            goto FREE_ADDR_LARGE;
        }
        eslab_init(&g_urpc_da_ctx.cfg.slab_large, buf, g_urpc_da_ctx.cfg.large_sge_size, DEFAULT_LARGE_SGE_NUM);
        URPC_LIB_LOG_DEBUG("default allocator get large segment num[%u]\n", DEFAULT_LARGE_SGE_NUM);
    }

    (void)pthread_mutex_unlock(&g_urpc_da_ctx.lock);
    return URPC_SUCCESS;

FREE_ADDR_LARGE:
    urpc_dbuf_free((void *)(uintptr_t)g_urpc_da_ctx.cfg.addr_large);
UNINIT_ESLAB:
    eslab_uninit(&g_urpc_da_ctx.cfg.slab);
    urpc_mem_seg_unregister(g_urpc_da_ctx.cfg.tsge);
FREE_ADDR:
    urpc_dbuf_free((void *)(uintptr_t)g_urpc_da_ctx.cfg.addr);
UNSET:
    memset(&g_urpc_da_ctx.cfg, 0, sizeof(urpc_da_cfg_t));
    (void)pthread_mutex_unlock(&g_urpc_da_ctx.lock);
    return URPC_FAIL;
}

void urpc_default_allocator_uninit(void)
{
    (void)pthread_mutex_lock(&g_urpc_da_ctx.lock);
    if (g_urpc_da_ctx.cfg.total_size == 0) {
        URPC_LIB_LOG_ERR("default allocator is not initialized\n");
        (void)pthread_mutex_unlock(&g_urpc_da_ctx.lock);
        return;
    }
    eslab_uninit(&g_urpc_da_ctx.cfg.slab);
    urpc_mem_seg_unregister(g_urpc_da_ctx.cfg.tsge);
    void *buf = (void *)(uintptr_t)g_urpc_da_ctx.cfg.addr;
    urpc_dbuf_free(buf);

    if (g_urpc_da_ctx.cfg.total_size_large != 0) {
        eslab_uninit(&g_urpc_da_ctx.cfg.slab_large);
        urpc_mem_seg_unregister(g_urpc_da_ctx.cfg.tsge_large);
        buf = (void *)(uintptr_t)g_urpc_da_ctx.cfg.addr_large;
        urpc_dbuf_free(buf);
    }
    memset(&g_urpc_da_ctx.cfg, 0, sizeof(urpc_da_cfg_t));
    (void)pthread_mutex_unlock(&g_urpc_da_ctx.lock);
    URPC_LIB_LOG_DEBUG("default allocator uninit success\n");
}

static eslab_t *urpc_default_allocator_head_eslab_judge(uint32_t count)
{
    if (DEFAULT_SGE_HEAD_SIZE * count > DEFAULT_LARGE_SGE_SIZE) {
        return NULL;
    } else if (DEFAULT_SGE_HEAD_SIZE * count > DEFAULT_SGE_SIZE) {
        if (g_urpc_da_ctx.cfg.total_size_large == 0) {
            return NULL;
        }
        return &g_urpc_da_ctx.cfg.slab_large;
    }
    return &g_urpc_da_ctx.cfg.slab;
}

static uint32_t urpc_default_allocator_size_check(urpc_allocator_option_t *option)
{
    if (option != NULL && ((option->qcustom_flag & QALLOCA_LARGE_SIZE_FLAG) != 0) &&
        (g_urpc_da_ctx.cfg.large_sge_size != 0)) {
        return g_urpc_da_ctx.cfg.large_sge_size;
    }
    return DEFAULT_SGE_SIZE;
}

static int urpc_default_allocator_get(urpc_sge_t **sge, uint32_t *num, uint64_t size, urpc_allocator_option_t *option)
{
    int ret = URPC_FAIL;
    if (num == NULL || sge == NULL) {
        URPC_LIB_LOG_ERR("parameter invalid\n");
        return ret;
    }
    eslab_t *slab, *pr_slab;
    uint64_t tsge;
    uint32_t count, length;
    length = urpc_default_allocator_size_check(option);
    if (length > DEFAULT_SGE_SIZE) {
        slab = &g_urpc_da_ctx.cfg.slab_large;
        tsge = g_urpc_da_ctx.cfg.tsge_large;
        count = size % g_urpc_da_ctx.cfg.large_sge_size == 0 ? size / g_urpc_da_ctx.cfg.large_sge_size :
                                                          size / g_urpc_da_ctx.cfg.large_sge_size + 1;
        length = g_urpc_da_ctx.cfg.large_sge_size;
    } else {
        slab = &g_urpc_da_ctx.cfg.slab;
        tsge = g_urpc_da_ctx.cfg.tsge;
        count = size % DEFAULT_SGE_SIZE == 0 ? size / DEFAULT_SGE_SIZE : size / DEFAULT_SGE_SIZE + 1;
        length = DEFAULT_SGE_SIZE;
    }

    if ((pr_slab = urpc_default_allocator_head_eslab_judge(count)) == NULL) {
        URPC_LIB_LOG_ERR("total_size too large:%lu,count:%u\n", size, count);
        return ret;
    }
    urpc_sge_t *pr = (urpc_sge_t *)eslab_get_buf(pr_slab);
    if (pr == NULL) {
        URPC_LIB_LOG_ERR("malloc failed\n");
        return ret;
    }

    void *buf = NULL;
    uint32_t i = 0;
    for (; i < count; i++) {
        buf = eslab_get_buf(slab);
        if (buf == NULL) {
            URPC_LIB_LOG_ERR("get buf is NULL\n");
            goto RESET;
        }
        pr[i].length = length;
        pr[i].flag = 0;
        pr[i].addr = (uint64_t)(uintptr_t)buf;
        pr[i].mem_h = tsge;
    }
    *num = count;
    *sge = pr;
    return URPC_SUCCESS;
RESET:
    for (uint32_t j = 0; j < i; j++) {
        eslab_put_buf(slab, (void *)(uintptr_t)pr[j].addr);
    }
    eslab_put_buf(pr_slab, (void *)pr);
    return ret;
}

static int urpc_default_allocator_put(urpc_sge_t *sge, uint32_t num, urpc_allocator_option_t *option)
{
    if (num <= 0 || sge == NULL) {
        URPC_LIB_LOG_ERR("parameter invalid\n");
        return URPC_FAIL;
    }
    eslab_t *slab, *pr_slab;
    uint64_t addr, total_size;
    uint32_t length = urpc_default_allocator_size_check(option);
    if (length > DEFAULT_SGE_SIZE) {
        slab = &g_urpc_da_ctx.cfg.slab_large;
        addr = g_urpc_da_ctx.cfg.addr_large;
        total_size = g_urpc_da_ctx.cfg.total_size_large;
    } else {
        slab = &g_urpc_da_ctx.cfg.slab;
        addr = g_urpc_da_ctx.cfg.addr;
        total_size = g_urpc_da_ctx.cfg.total_size;
    }
    pr_slab = urpc_default_allocator_head_eslab_judge(num);
    if (pr_slab == NULL) {
        URPC_LIB_LOG_ERR("total_size too large num:%u\n", num);
        return URPC_FAIL;
    }
    for (uint32_t i = 0; i < num; i++) {
        if (sge[i].addr == 0 || sge[i].addr < addr || (sge[i].addr - addr > total_size)) {
            URPC_LIB_LOG_ERR("sge[%u].addr is invalid\n", i);
            continue;
        }

        eslab_put_buf(slab, (void *)(uintptr_t)sge[i].addr);
        sge[i].length = 0;
    }

    eslab_put_buf(pr_slab, (void *)sge);
    sge->length = 0;
    return URPC_SUCCESS;
}

static urpc_allocator_t g_urpc_default_allocator = {
    .get = urpc_default_allocator_get,
    .put = urpc_default_allocator_put,
    .get_raw_buf = NULL,
    .put_raw_buf = NULL,
    .get_sges = NULL,
    .put_sges = NULL,
};

int urpc_allocator_register(urpc_allocator_t *allocator)
{
    if (urpc_state_get() != URPC_STATE_INIT) {
        return -URPC_ERR_EPERM;
    }

    if (allocator == NULL) {
        URPC_LIB_LOG_ERR("allocator is null\n");
        return URPC_FAIL;
    }

    (void)pthread_mutex_lock(&g_urpc_allocator_lock);
    if (g_urpc_allocator != NULL) {
        (void)pthread_mutex_unlock(&g_urpc_allocator_lock);
        URPC_LIB_LOG_ERR("urpc allocator already exists\n");
        return URPC_FAIL;
    }

    if (g_urpc_allocator_inited) {
        (void)pthread_mutex_unlock(&g_urpc_allocator_lock);
        URPC_LIB_LOG_ERR("only support register allocator once\n");
        return URPC_FAIL;
    }

    urpc_allocator_t *allocator_buf =
        (urpc_allocator_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_ALLOCATOR, sizeof(urpc_allocator_t));
    if (allocator_buf == NULL) {
        (void)pthread_mutex_unlock(&g_urpc_allocator_lock);
        URPC_LIB_LOG_ERR("malloc buf failed\n");
        return URPC_FAIL;
    }
    *allocator_buf = *allocator;

    /* To prevent allocator_get() get uninitialized value(by copy from the input arguments) */
    g_urpc_allocator = allocator_buf;
    g_urpc_allocator_inited = true;
    (void)pthread_mutex_unlock(&g_urpc_allocator_lock);
    URPC_LIB_LOG_INFO("register allocator successful\n");

    return URPC_SUCCESS;
}

int urpc_allocator_unregister(void)
{
    if (urpc_state_get() != URPC_STATE_INIT) {
        return -URPC_ERR_EPERM;
    }

    (void)pthread_mutex_lock(&g_urpc_allocator_lock);
    if (g_urpc_allocator == NULL) {
        (void)pthread_mutex_unlock(&g_urpc_allocator_lock);
        URPC_LIB_LOG_ERR("urpc allocator already null\n");
        return URPC_FAIL;
    }

    /**
     * flag: if support allocator register state update add allocator register
     * all the module that use allocator must be cleaned up in post_dp_callback before unregistering allocator;
     * currently, we clean up the worker queue for ext_general here
     */

    urpc_allocator_t *tmp = g_urpc_allocator;
    g_urpc_allocator = NULL;
    urpc_dbuf_free(tmp);
    g_urpc_allocator_inited = false;
    (void)pthread_mutex_unlock(&g_urpc_allocator_lock);
    URPC_LIB_LOG_INFO("unregister allocator successful\n");
    return URPC_SUCCESS;
}

urpc_allocator_t *default_allocator_get(void)
{
    return &g_urpc_default_allocator;
}
