/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc lib perftest allocator, per thread lock free mempool
 * Create: 2024-3-6
 */

#ifndef URPC_LIB_PERFTEST_ALLOCATOR_H
#define URPC_LIB_PERFTEST_ALLOCATOR_H

#include "urpc_framework_types.h"
#include "urpc_slab.h"
#include "urpc_lib_perftest_param.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ALLOCATOR_BLOCK_NUM (16 * 1024)
#define PLOG_HEADER_SGE_NUM     1
#define SIMULATE_PLOG_CMD_SIZE  96

#define URPC_PERFTEST_ALIGNED_SIZE 4096
#define URPC_PERFTEST_ONE_SGE_SIZE 4096
#define URPC_PERFTEST_PAGE_SIZE    4096

typedef struct allocator_sges_info {
    uint32_t sge_size[MAX_SGE_SIZE];
    uint32_t buf_size[MAX_SGE_SIZE];
    uint32_t count;
    uint32_t head_size;
} allocator_sges_info_t;

typedef struct allocator_ctx {
    uint64_t addr;
    uint64_t tsge;
    uint32_t total_size;
    eslab_t slab;
} allocator_ctx_t;

int urpc_perftest_allocator_init(uint32_t worker_num, uint32_t *buf_size, uint32_t buf_len, uint32_t element_num,
    bool alloc_buf, bool align);
void urpc_perftest_allocator_uninit(void);
urpc_allocator_t *urpc_perftest_allocator_get(void);

uint32_t get_recv_max_sge_size(uint32_t sge_num, int i);
uint32_t get_set_sge_size(int i);
uint32_t perftest_post_rx_buff(uint64_t qh, uint32_t post_num, uint32_t rx_buf_size);
int perftest_mem_remote_access_enable(uint32_t urpc_chid);

#ifdef __cplusplus
}
#endif

#endif  // URPC_LIB_PERFTEST_ALLOCATOR_H