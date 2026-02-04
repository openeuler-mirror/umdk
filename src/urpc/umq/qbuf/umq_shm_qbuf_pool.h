/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: define qbuf pool function for shared memory
 * Create: 2025-7-26
 * Note:
 * History: 2025-7-26
 */

#ifndef UMQ_SHM_QBUF_POOL_H
#define UMQ_SHM_QBUF_POOL_H

#include "qbuf_list.h"
#include "umq_dfx_types.h"
#include "umq_types.h"
#include "umq_qbuf_pool.h"
#include "msg_ring.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum shm_qbuf_pool_type {
    SHM_QBUF_POOL_TYPE_LOCAL,
    SHM_QBUF_POOL_TYPE_REMOTE
} shm_qbuf_pool_type_t;

typedef struct shm_qbuf_pool_cfg {
    void *buf_addr;             // buffer addr
    uint64_t total_size;        // total buffer size
    uint32_t data_size;         // size of one data slab
    uint32_t headroom_size;     // reserve head room size
    umq_buf_mode_t mode;
    shm_qbuf_pool_type_t type;
    union {
        struct {
            uint64_t umqh;
            uint32_t id;
        } local;
    };
    msg_ring_t *msg_ring;
} shm_qbuf_pool_cfg_t;

/*
 * init qbuf pool for shared memory
 */
uint64_t umq_shm_global_pool_init(shm_qbuf_pool_cfg_t *cfg);

/*
 * uninit qbuf pool for shared memory
 */
void umq_shm_global_pool_uninit(uint64_t pool);

/*
 * alloc memory from qbuf pool.
 * try to alloc from thread local pool.
 * if not enough, fetch some more memory fragments from global pool(from local) or
 * from qbuf return ring(from remote) to thread local pool.
 */
int umq_shm_qbuf_alloc(
    uint64_t pool, uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list);

/*
 * release memory to qbuf pool(to local) or qbuf return ring(to remote).
 * if memory fragments count in thread local pool reach threshold, return some of fragments to global pool.
 */
void umq_shm_qbuf_free(uint64_t pool, umq_buf_list_t *list);

/*
 * reset head room size of qbuf
 * if headroom_size is not appropriate, UMQ_FAIL will be returned
 */
int umq_shm_qbuf_headroom_reset(uint64_t pool, umq_buf_t *qbuf, uint16_t headroom_size);

/*
 * get umq_buf_t offset in memory region
 */
uint64_t umq_qbuf_to_offset(umq_buf_t *qbuf, uint64_t pool);
/*
 * get buf_data offset in memory region
 */
uint64_t umq_qbuf_data_to_offset(char *buf_data, uint64_t pool);

/*
 * get umq_buf_t in memory region by umq_buf_t offset, offset need to be validated
 */
umq_buf_t *umq_offset_to_qbuf(uint64_t offset, uint64_t pool);

/*
 * get buf_data in memory region by buf_data offset, offset need to be validated
 */
char *umq_offset_to_qbuf_data(uint64_t offset, uint32_t data_size, uint64_t pool);

/*
 * transfer qbuf/qbuf data ptr to offset, and enqueue qbuf offset to ring
 */
int umq_shm_qbuf_enqueue(umq_buf_t *qbuf, uint64_t umq, uint64_t pool, bool rendezvous,
    int (*enqueue)(uint64_t umq, uint64_t *offset, uint32_t num));

/*
 * dequeue qbuf offset from ring, and transfer qbuf/qbuf data offset to ptr
 */
umq_buf_t *umq_shm_qbuf_dequeue(uint64_t umq, uint64_t umq_tp, uint64_t pool, bool *rendezvous,
    int (*dequeue)(uint64_t umq, uint64_t *offset, uint32_t num));

#ifdef __cplusplus
}
#endif

#endif
