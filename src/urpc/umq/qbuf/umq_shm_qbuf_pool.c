/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: realize qbuf pool function for shared memory
 */

#include <unistd.h>
#include <sys/queue.h>

#include "umq_errno.h"
#include "umq_vlog.h"
#include "umq_inner.h"
#include "urpc_thread_closure.h"

#include "umq_shm_qbuf_pool.h"

#define RELEASE_THREAD_CACHE_TIMEOUT_MS (10)
#define QBUF_INVALID_OFFSET (0xFFFFFFFFFFFFFFFF)
#define SHM_QBUF_POOL_TLS_MAX (16) // max count of thread local buffer storage
#define SHM_QBUF_POOL_BATCH_CNT (4) // batch size when fetch from global or return to global
#define UMQ_OFFSET_DATA_BITS    (0x7FFFFFFFFFFFFFFF)    // 63 bits is intented for offset
#define UMQ_RENDEZVOUS_FLAG     (0x8000000000000000)    // use 1 bit to indicate whether read is needed

typedef struct local_qbuf_pool local_qbuf_pool_t;

typedef struct qbuf_pool {
    shm_qbuf_pool_type_t type;
    uint64_t umqh;
    void *data_buffer;  // 数据区起始地址，COMBINE模式为所有的数据起始位置，SPLIT模式为所有的数据起始位置+头部区大小
                        //，需要8K对齐
    void *header_buffer;        // 头部区起始地址，COMBINE模式为NULL，SPLIT模式为所有数据的起始位置
    void *ext_header_buffer;    // ext头部区起始地址，数据区指针为空，仅有头部，数量为分片数*16。combine模式为NULL
    uint64_t total_size;        // 内存池管理的内存总大小

    uint32_t block_size;        // headroom size + data size以8K为大小向上取整，如果是combine模式还包括umq_qbuf_t结构体大小
    uint32_t headroom_size;     // 预留的头部空间大小

    uint64_t total_block_num;
    uint32_t id;
    umq_buf_mode_t mode;

    global_block_pool_t block_pool;
    msg_ring_t *msg_ring;
} qbuf_pool_t;

typedef struct queue_local_pool {
    local_block_pool_t block_pool;
    qbuf_pool_t *global_pool;
} queue_local_pool_t;

struct local_qbuf_pool {
    queue_local_pool_t *pool;
    volatile uint32_t remove_ref_cnt;
};

typedef struct register_list_node {
    LIST_ENTRY(register_list_node) node;
    local_qbuf_pool_t *thread_cache;
    bool inited;
} register_list_node_t;

LIST_HEAD(register_list_head, register_list_node);

/*
 * register list contains: (1) read write lock(global); (2) list head(global); (3) list node(thread local);
 * 1. INSERT: Each thread will try to insert their list node(thread local) into list head(global) when the
 * first time trying to allocate shared memory. (under the protection of write lock(global))
 * 2. REMOVE: When a thread exits, it attempts to remove the list node(thread local) from the list(global).
 * (under the protection of write lock(global))
 * 3. ACCESS: uninit one shared memory qbuf pool needs to release the resource stored in each threads.
 * (under the protection of read lock(global))
 */
static pthread_rwlock_t g_register_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static struct register_list_head g_register_list_head;
static __thread register_list_node_t g_register_list_node = {0};

static __thread local_qbuf_pool_t g_thread_cache[UMQ_MAX_QUEUE_NUMBER] = {0};

static uint32_t release_thread_cache(local_qbuf_pool_t *tls_mgmt_pool)
{
    // Avoid concurrent access between destroy queue and thread exit.
    uint32_t ref = __atomic_fetch_add(&tls_mgmt_pool->remove_ref_cnt, 1, __ATOMIC_ACQ_REL);
    if (ref != 0) {
        return ref;
    }

    queue_local_pool_t *local_pool = tls_mgmt_pool->pool;
    if (local_pool == NULL) {
        __atomic_fetch_sub(&tls_mgmt_pool->remove_ref_cnt, 1, __ATOMIC_ACQ_REL);
        return 0;
    }

    qbuf_pool_t *pool = local_pool->global_pool;
    global_block_pool_t *gblk_pool = &pool->block_pool;
    local_block_pool_t *lblk_pool = &local_pool->block_pool;

    // return thread local buffer storage to global pool
    (void)pthread_mutex_lock(&gblk_pool->global_mutex);
    if (lblk_pool->head_with_data.first != NULL) {
        // release thread cache no need check double free
        gblk_pool->buf_cnt_with_data += release_to_global(&lblk_pool->head_with_data,
            &gblk_pool->head_with_data);
    }
    if (lblk_pool->head_without_data.first != NULL) {
        // release thread cache no need check double free
        gblk_pool->buf_cnt_without_data += release_to_global(&lblk_pool->head_without_data,
            &gblk_pool->head_without_data);
    }
    (void)pthread_mutex_unlock(&gblk_pool->global_mutex);

    // reset local record and free resource
    tls_mgmt_pool->pool = NULL;
    __atomic_fetch_sub(&tls_mgmt_pool->remove_ref_cnt, 1, __ATOMIC_ACQ_REL);

    free(local_pool);

    return 0;
}

// release all thread cache to global pool. should be called when thread exits
static ALWAYS_INLINE void release_thread_cache_array()
{
    (void)pthread_rwlock_wrlock(&g_register_rwlock);
    LIST_REMOVE(&g_register_list_node, node);

    for (uint32_t id = 0; id < UMQ_MAX_QUEUE_NUMBER; id++) {
        if (g_thread_cache[id].pool == NULL) {
            continue;
        }

        release_thread_cache(&g_thread_cache[id]);
    }

    (void)pthread_rwlock_unlock(&g_register_rwlock);
}

static void unregister_all_thread_cache(qbuf_pool_t *pool)
{
    struct timespec start;
    register_list_node_t *cur = NULL;
    (void)pthread_rwlock_rdlock(&g_register_rwlock);
    LIST_FOREACH(cur, &g_register_list_head, node) {
        uint32_t ref = 0;
        local_qbuf_pool_t *tls_mgmt_pool = &cur->thread_cache[pool->id];
        if ((ref = release_thread_cache(tls_mgmt_pool)) == 0) {
            continue;
        }

         /* if unregister operation release failed(which means that another thread is also operating
          * on this thread cache), wait until the next thread finish the release operation */
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        uint32_t desired = ref;
        while (!__atomic_compare_exchange_n(&tls_mgmt_pool->remove_ref_cnt, &desired, 0, true, __ATOMIC_RELEASE,
                                            __ATOMIC_ACQUIRE)) {
            if (desired != ref) {
                UMQ_VLOG_ERR(VLOG_UMQ, "unexpected exception, actual ref: %u, desired ref: %u\n", ref, desired);
                break;
            }

            if (is_timeout(&start, RELEASE_THREAD_CACHE_TIMEOUT_MS)) {
                UMQ_VLOG_ERR(VLOG_UMQ, "release thread cache for shared memory exceeds %d ms timeout\n",
                    RELEASE_THREAD_CACHE_TIMEOUT_MS);
                break;
            }

            usleep(1);
            desired = ref;
        }
    }
    (void)pthread_rwlock_unlock(&g_register_rwlock);
}

static queue_local_pool_t *register_thread_cache(qbuf_pool_t *pool)
{
    /* Here, only concurrency is guaranteed and not protect use after free. It is the user's responsibility
     * to ensure that the destroyed resources are not accessed. */
    if (!g_register_list_node.inited) {
        (void)pthread_rwlock_wrlock(&g_register_rwlock);
        g_register_list_node.thread_cache = g_thread_cache;
        LIST_INSERT_HEAD(&g_register_list_head, &g_register_list_node, node);
        (void)pthread_rwlock_unlock(&g_register_rwlock);
        g_register_list_node.inited = true;
    }

    queue_local_pool_t *local_pool = (queue_local_pool_t *)calloc(1, sizeof(queue_local_pool_t));
    if (local_pool == NULL) {
        return NULL;
    }

    local_pool->global_pool = pool;
    QBUF_LIST_INIT(&local_pool->block_pool.head_with_data);
    QBUF_LIST_INIT(&local_pool->block_pool.head_without_data);
    urpc_thread_closure_register(THREAD_CLOSURE_QBUF, 0, release_thread_cache_array);
    g_thread_cache[pool->id].pool = local_pool;

    return local_pool;
}

static ALWAYS_INLINE queue_local_pool_t *get_thread_cache(qbuf_pool_t *pool)
{
    queue_local_pool_t *local_pool = g_thread_cache[pool->id].pool;
    if (local_pool == NULL) {
        local_pool = register_thread_cache(pool);
    }

    return local_pool;
}

static void umq_shm_global_split_pool_init(shm_qbuf_pool_cfg_t *cfg, qbuf_pool_t *pool)
{
    QBUF_LIST_INIT(&pool->block_pool.head_without_data);
    uint32_t blk_size = umq_buf_size_small();
    uint64_t blk_num = cfg->total_size / ((UMQ_EMPTY_HEADER_COEFFICIENT + 1) * (uint64_t)sizeof(umq_buf_t) + blk_size);

    pool->block_size = blk_size;
    pool->total_block_num = blk_num;

    pool->data_buffer = cfg->buf_addr;
    pool->header_buffer = cfg->buf_addr + blk_num * blk_size;
    pool->ext_header_buffer = pool->header_buffer + blk_num * sizeof(umq_buf_t);

    if (pool->type == SHM_QBUF_POOL_TYPE_REMOTE) {
        return;
    }

    for (uint64_t i = 0; i < blk_num; i++) {
        umq_buf_t *buf = id_to_buf_with_data_split((char *)pool->header_buffer, i);
        buf->umqh = pool->umqh;
        buf->buf_size = blk_size + (uint32_t)sizeof(umq_buf_t);
        buf->data_size = blk_size;
        buf->total_data_size = buf->data_size;
        buf->headroom_size = 0;
        buf->token_id = 0;
        buf->buf_data = pool->data_buffer + i * blk_size;
        buf->mempool_id = 0;
        (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
        QBUF_LIST_INSERT_HEAD(&pool->block_pool.head_with_data, buf);
    }

    uint64_t head_without_data_count = blk_num * UMQ_EMPTY_HEADER_COEFFICIENT;
    for (uint64_t i = 0; i < head_without_data_count; i++) {
        umq_buf_t *head_buf = id_to_buf_without_data_split((char *)pool->ext_header_buffer, i);
        head_buf->umqh = pool->umqh;
        head_buf->buf_size = (uint32_t)sizeof(umq_buf_t);
        head_buf->data_size = 0;
        head_buf->total_data_size = 0;
        head_buf->headroom_size = 0;
        head_buf->token_id = 0;
        head_buf->buf_data = NULL;
        head_buf->mempool_id = 0;
        (void)memset(head_buf->qbuf_ext, 0, sizeof(head_buf->qbuf_ext));
        QBUF_LIST_INSERT_HEAD(&pool->block_pool.head_without_data, head_buf);
    }
    pool->block_pool.buf_cnt_with_data = blk_num;
    pool->block_pool.buf_cnt_without_data = head_without_data_count;
}

static void umq_shm_global_combine_pool_init(shm_qbuf_pool_cfg_t *cfg, qbuf_pool_t *pool)
{
    uint32_t blk_size = umq_buf_size_small();
    uint64_t blk_num = cfg->total_size / blk_size;

    pool->data_buffer = cfg->buf_addr;
    pool->header_buffer = NULL;
    pool->ext_header_buffer = NULL;

    pool->block_size = blk_size;
    pool->total_block_num = blk_num;

    if (pool->type == SHM_QBUF_POOL_TYPE_REMOTE) {
        return;
    }

    for (uint64_t i = 0; i < blk_num; i++) {
        umq_buf_t *buf = id_to_buf_combine((char *)pool->data_buffer, i, pool->block_size);
        buf->umqh = pool->umqh;
        buf->buf_size = blk_size;
        buf->data_size = blk_size - (uint32_t)sizeof(umq_buf_t);
        buf->total_data_size = buf->data_size;
        buf->headroom_size = 0;
        buf->token_id = 0;
        buf->buf_data = (char *)buf + sizeof(umq_buf_t);
        buf->mempool_id = 0;
        (void)memset(buf->qbuf_ext, 0, sizeof(buf->qbuf_ext));
        QBUF_LIST_INSERT_HEAD(&pool->block_pool.head_with_data, buf);
    }
    pool->block_pool.buf_cnt_with_data = blk_num;
    pool->block_pool.buf_cnt_without_data = 0;
}

// Internal function, validation performed by the caller
uint64_t umq_shm_global_pool_init(shm_qbuf_pool_cfg_t *cfg)
{
    qbuf_pool_t *pool = (qbuf_pool_t *)calloc(1, sizeof(qbuf_pool_t));
    if (pool == NULL) {
        return UMQ_INVALID_HANDLE;
    }

    (void)pthread_mutex_init(&pool->block_pool.global_mutex, NULL);
    QBUF_LIST_INIT(&pool->block_pool.head_with_data);
    pool->type = cfg->type;
    pool->mode = cfg->mode;
    pool->total_size = cfg->total_size;
    pool->headroom_size = cfg->headroom_size;
    pool->msg_ring = cfg->msg_ring;
    if (pool->type == SHM_QBUF_POOL_TYPE_LOCAL) {
        pool->id = cfg->local.id;
        pool->umqh = cfg->local.umqh;
    }

    if (cfg->mode == UMQ_BUF_SPLIT) {
        umq_shm_global_split_pool_init(cfg, pool);
    } else if (cfg->mode == UMQ_BUF_COMBINE) {
        umq_shm_global_combine_pool_init(cfg, pool);
    }

    return (uint64_t)(uintptr_t)pool;
}

void umq_shm_global_pool_uninit(uint64_t pool)
{
    qbuf_pool_t *_pool = (qbuf_pool_t *)(uintptr_t)pool;
    if (_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue buffer pool is invalid\n");
        return;
    }

    unregister_all_thread_cache(_pool);
    pthread_mutex_destroy(&_pool->block_pool.global_mutex);
    free(_pool);
}

static ALWAYS_INLINE int umq_shm_dequeue_qbuf(msg_ring_t *msg_ring, uint64_t *offset, uint32_t num)
{
    uint32_t max_num = num > SHM_QBUF_POOL_BATCH_CNT ? SHM_QBUF_POOL_BATCH_CNT : num;
    uint64_t *rx_data_ptr[SHM_QBUF_POOL_BATCH_CNT];
    for (uint32_t i = 0; i < max_num; i++) {
        rx_data_ptr[i] = &offset[i];
    }

    // poll offset from shm, then transform to qbuf
    uint32_t polled_buf_size[SHM_QBUF_POOL_BATCH_CNT];
    int ret =
        msg_ring_poll_rx_batch(msg_ring, (char **)&rx_data_ptr, sizeof(uint64_t), polled_buf_size, max_num);
    if (ret < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "ipc poll rx failed, status: %d\n", ret);
        return -UMQ_ERR_EAGAIN;
    }

    return ret;
}

// transform offset and its qbuf_data and qbuf_next to pointer
static ALWAYS_INLINE umq_buf_t *umq_shm_offset_to_qbuf_pointer(uint64_t offset, uint64_t pool, uint64_t umqh)
{
    umq_buf_t *head, *next, *result;
    result = umq_offset_to_qbuf(offset, pool);
    if (result == NULL) {
        return NULL;
    }

    next = result;
    do {
        head = next;
        head->buf_data = umq_offset_to_qbuf_data((uint64_t)(uintptr_t)head->buf_data, head->data_size, pool);
        head->qbuf_next = umq_offset_to_qbuf((uint64_t)(uintptr_t)head->qbuf_next, pool);
        head->umqh = umqh;
        next = head->qbuf_next;
    } while (next != NULL);

return result;
}

static ALWAYS_INLINE bool is_with_data(umq_buf_t *qbuf, qbuf_pool_t *pool)
{
    uint64_t addr = (uint64_t)(uintptr_t)qbuf;
    uint64_t from_addr = (uint64_t)(uintptr_t)pool->header_buffer;
    uint64_t to_addr = (uint64_t)(uintptr_t)pool->ext_header_buffer;

    return addr >= from_addr && addr < to_addr;
}

static ALWAYS_INLINE void umq_shm_poll_and_fill_global(qbuf_pool_t *pool)
{
    // poll released buf from msg_ring rx, and return them to global pool
    uint64_t qbuf_offset[SHM_QBUF_POOL_BATCH_CNT];
    uint32_t max_count = SHM_QBUF_POOL_BATCH_CNT;
    int ret = umq_shm_dequeue_qbuf(pool->msg_ring, qbuf_offset, max_count);
    if (ret < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "umq_shm_dequeue_qbuf failed, status: %d\n", ret);
        return;
    }

    for (int i = 0; i < ret; i++) {
        umq_buf_t *qbuf = umq_shm_offset_to_qbuf_pointer(qbuf_offset[i], (uint64_t)(uintptr_t)pool, pool->umqh);
        if (qbuf == NULL) {
            continue;
        }

        return_qbuf_to_global(&pool->block_pool, qbuf, is_with_data(qbuf, pool));
    }
}

static void umq_shm_qbuf_alloc_data_with_split(local_block_pool_t *local_pool, uint32_t request_size,
    qbuf_alloc_param_t *param, umq_buf_list_t *list, qbuf_pool_t *pool)
{
    uint32_t cnt = 0;
    umq_buf_t *cur_node;
    uint32_t headroom_size_temp = param->headroom_size;
    uint32_t total_data_size = request_size;
    uint32_t remaining_size = request_size;
    uint32_t max_data_capacity = umq_buf_size_small() - headroom_size_temp;
    bool first_fragment = true;

    QBUF_LIST_FOR_EACH(cur_node, &local_pool->head_with_data) {
        uint64_t id = buf_to_id_with_data_split(pool->header_buffer, (char *)cur_node);
        cur_node->buf_data = pool->data_buffer + id * umq_buf_size_small() + headroom_size_temp;
        cur_node->buf_size = umq_buf_size_small() + (uint32_t)sizeof(umq_buf_t);
        cur_node->headroom_size = headroom_size_temp;
        cur_node->total_data_size = total_data_size;
        cur_node->data_size = remaining_size >= max_data_capacity ? max_data_capacity : remaining_size;
        cur_node->first_fragment = first_fragment;
        if (cur_node->alloc_state == QBUF_ALLOC_STATE_ALLOCATED) {
            uint64_t buf_id = umq_buf_to_id((char *)cur_node, param->shm, true);
            UMQ_VLOG_ERR(VLOG_UMQ, "qbuf %lu in with_data pool already allocated\n", buf_id);
        }
        cur_node->alloc_state = QBUF_ALLOC_STATE_ALLOCATED;

        remaining_size -= cur_node->data_size;
        if (remaining_size == 0) {
            headroom_size_temp = param->headroom_size;
            total_data_size = request_size;
            remaining_size = request_size;
            first_fragment = true;
            max_data_capacity = umq_buf_size_small() - param->headroom_size;
        } else {
            headroom_size_temp = 0;
            total_data_size = 0;
            first_fragment = false;
            max_data_capacity = umq_buf_size_small();
        }
        if (++cnt == param->actual_buf_count) {
            break;
        }
    }

    umq_buf_t *head = QBUF_LIST_FIRST(&local_pool->head_with_data);
    // switch head node
    QBUF_LIST_FIRST(&local_pool->head_with_data) = QBUF_LIST_NEXT(cur_node);
    QBUF_LIST_NEXT(cur_node) = QBUF_LIST_FIRST(list);

    // set output
    QBUF_LIST_FIRST(list) = head;
    local_pool->buf_cnt_with_data -= param->actual_buf_count;
}

int umq_shm_qbuf_alloc(
    uint64_t pool, uint32_t request_size, uint32_t num, umq_alloc_option_t *option, umq_buf_list_t *list)
{
    qbuf_pool_t *_pool = (qbuf_pool_t *)(uintptr_t)pool;
    if (_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue buffer _pool is invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    queue_local_pool_t *local_pool = get_thread_cache(_pool);
    if (local_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "thread cache is not ready\n");
        return -UMQ_ERR_EINVAL;
    }

    local_block_pool_t *lblk_pool = &local_pool->block_pool;
    global_block_pool_t *gblk_pool = &local_pool->global_pool->block_pool;
    bool flag = (option != NULL && (option->flag & UMQ_ALLOC_FLAG_HEAD_ROOM_SIZE) != 0);
    qbuf_alloc_param_t param;
    param.shm = true;
    param.headroom_size = flag ? option->headroom_size : _pool->headroom_size;
    int ret = UMQ_SUCCESS;

    if (_pool->mode == UMQ_BUF_SPLIT) {
        param.actual_buf_count =
            num * ((request_size + param.headroom_size + umq_buf_size_small() - 1) >> umq_buf_size_pow_small());
    } else {
        uint32_t align_size = umq_buf_size_small() - (uint32_t)sizeof(umq_buf_t);
        param.actual_buf_count = num * ((request_size + param.headroom_size + align_size - 1) / align_size);
    }
    if (request_size == 0) {
        if (flag && param.headroom_size > 0) {
            UMQ_VLOG_ERR(VLOG_UMQ, "headroom_size not supported when request_size is 0\n");
            return -UMQ_ERR_EINVAL;
        }

        if (_pool->mode != UMQ_BUF_SPLIT) {
            UMQ_VLOG_ERR(VLOG_UMQ, "cannot alloc memory size 0 in combine mode\n");
            return -UMQ_ERR_ENOMEM;
        }

        // fetch from global first, if thread local qbuf is not enough for allocate operation
        while (lblk_pool->buf_cnt_without_data < num) {
            umq_shm_poll_and_fill_global(_pool);
            ret = fetch_from_global(gblk_pool, lblk_pool, false, SHM_QBUF_POOL_BATCH_CNT);
            if (ret <= 0) {
                UMQ_VLOG_ERR(VLOG_UMQ, "fetch from global failed, current size: %u, alloc num: %u, status: %d\n",
                    lblk_pool->buf_cnt_without_data, num, ret);
                return ret;
            }
        }

        umq_qbuf_alloc_nodata(lblk_pool, num, list, param.shm);

        return UMQ_SUCCESS;
    }

    // fetch from global first, if thread local qbuf is not enough for allocate operation
    while (lblk_pool->buf_cnt_with_data < param.actual_buf_count) {
        umq_shm_poll_and_fill_global(_pool);
        ret = fetch_from_global(gblk_pool, lblk_pool, true, SHM_QBUF_POOL_BATCH_CNT);
        if (ret <= 0) {
            UMQ_VLOG_ERR(VLOG_UMQ, "fetch from global failed, current size: %u, alloc num: %u, status: %d\n",
                lblk_pool->buf_cnt_with_data, param.actual_buf_count, ret);
            return ret;
        }
    }

    if (_pool->mode == UMQ_BUF_SPLIT) {
        umq_shm_qbuf_alloc_data_with_split(lblk_pool, request_size, &param, list, _pool);
    } else {
        umq_qbuf_alloc_data_with_combine(lblk_pool, request_size, &param, list);
    }

    return UMQ_SUCCESS;
}

static ALWAYS_INLINE int umq_shm_enqueue_qbuf(msg_ring_t *msg_ring, uint64_t offset)
{
    int ret = msg_ring_post_rx(msg_ring, (char *)&offset, sizeof(uint64_t));
    if (ret != 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "msg_ring post rx failed, status: %d\n", ret);
        return ret;
    }
    return UMQ_SUCCESS;
}

static ALWAYS_INLINE uint64_t umq_shm_qbuf_pointer_to_offset(umq_buf_t *qbuf, uint64_t pool)
{
    umq_buf_t *head, *next = qbuf;
    do {
        head = next;
        next = head->qbuf_next;
        head->buf_data = (char *)(uintptr_t)umq_qbuf_data_to_offset(head->buf_data, pool);
        head->qbuf_next = (umq_buf_t *)(uintptr_t)umq_qbuf_to_offset(head->qbuf_next, pool);
    } while (next != NULL);

    return umq_qbuf_to_offset(qbuf, pool);
}

static ALWAYS_INLINE void post_release_buf(qbuf_pool_t *pool, umq_buf_list_t *list)
{
    uint64_t offset = umq_shm_qbuf_pointer_to_offset(QBUF_LIST_FIRST(list), (uint64_t)(uintptr_t)pool);
    umq_shm_enqueue_qbuf(pool->msg_ring, offset);
}

void umq_shm_qbuf_free(uint64_t pool, umq_buf_list_t *list)
{
    qbuf_pool_t *_pool = (qbuf_pool_t *)(uintptr_t)pool;
    if (_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue buffer pool is invalid\n");
        return;
    }

    if (_pool->type == SHM_QBUF_POOL_TYPE_REMOTE) {
        post_release_buf(_pool, list);
        return;
    }

    queue_local_pool_t *local_pool = get_thread_cache(_pool);
    if (local_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "thread cache is not ready\n");
        return;
    }

    local_block_pool_t *lblk_pool = &local_pool->block_pool;
    global_block_pool_t *gblk_pool = &local_pool->global_pool->block_pool;

    // split mode and buf is in head no data zone
    if (_pool->mode == UMQ_BUF_SPLIT &&
        (void *)QBUF_LIST_FIRST(list) >= _pool->ext_header_buffer) {
        // put buf list before head of head_without_data
        uint32_t cnt = release_batch(list, &lblk_pool->head_without_data, true);
        lblk_pool->buf_cnt_without_data += cnt;

        /* if local list node count reaches SHM_QBUF_POOL_TLS_MAX + SHM_QBUF_POOL_BATCH_CNT,
         * return some nodes to global */
        if (lblk_pool->buf_cnt_without_data >= SHM_QBUF_POOL_TLS_MAX + SHM_QBUF_POOL_BATCH_CNT) {
            return_to_global(gblk_pool, lblk_pool, false, SHM_QBUF_POOL_TLS_MAX);
        }

        return;
    }

    uint32_t cnt = release_batch(list, &lblk_pool->head_with_data, true);
    lblk_pool->buf_cnt_with_data += cnt;

    /* if local list node count reaches SHM_QBUF_POOL_TLS_MAX + SHM_QBUF_POOL_BATCH_CNT,
     * return some nodes to global */
    if (lblk_pool->buf_cnt_with_data > SHM_QBUF_POOL_TLS_MAX + SHM_QBUF_POOL_BATCH_CNT) {
        return_to_global(gblk_pool, lblk_pool, true, SHM_QBUF_POOL_TLS_MAX);
    }
}

int umq_shm_qbuf_headroom_reset(uint64_t pool, umq_buf_t *qbuf, uint16_t headroom_size)
{
    qbuf_pool_t *_pool = (qbuf_pool_t *)(uintptr_t)pool;
    if (_pool == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "queue buffer pool is invalid\n");
        return -UMQ_ERR_EINVAL;
    }

    return headroom_reset(qbuf, headroom_size, _pool->mode, _pool->block_size);
}

uint64_t umq_qbuf_to_offset(umq_buf_t *qbuf, uint64_t pool)
{
    if (qbuf == NULL) {
        return QBUF_INVALID_OFFSET;
    }

    qbuf_pool_t *qbuf_pool = (qbuf_pool_t *)(uintptr_t)pool;
    return (uint64_t)(uintptr_t)qbuf - (uint64_t)(uintptr_t)qbuf_pool->data_buffer;
}

uint64_t umq_qbuf_data_to_offset(char *buf_data, uint64_t pool)
{
    if (buf_data == NULL) {
        return QBUF_INVALID_OFFSET;
    }

    qbuf_pool_t *qbuf_pool = (qbuf_pool_t *)(uintptr_t)pool;
    return (uint64_t)(uintptr_t)buf_data - (uint64_t)(uintptr_t)qbuf_pool->data_buffer;
}

umq_buf_t *umq_offset_to_qbuf(uint64_t offset, uint64_t pool)
{
    qbuf_pool_t *qbuf_pool = (qbuf_pool_t *)(uintptr_t)pool;
    if (offset > qbuf_pool->total_size - sizeof(umq_buf_t)) {
        return NULL;
    }

    uint64_t pool_addr = (uint64_t)(uintptr_t)qbuf_pool->data_buffer;
    uint64_t qbuf_addr = offset + pool_addr;

    bool split_buf_offset_invalid =
        (qbuf_pool->mode == UMQ_BUF_SPLIT) &&
        ((qbuf_addr < (uint64_t)(uintptr_t)qbuf_pool->header_buffer) ||
            (offset + sizeof(umq_buf_t) > qbuf_pool->total_block_num *
                (qbuf_pool->block_size + (UMQ_EMPTY_HEADER_COEFFICIENT + 1) * sizeof(umq_buf_t))) ||
            ((qbuf_addr - (uint64_t)(uintptr_t)qbuf_pool->header_buffer) % sizeof(umq_buf_t) != 0));

    bool combine_buf_offset_invalid =
        (qbuf_pool->mode == UMQ_BUF_COMBINE) &&
        ((offset > qbuf_pool->total_size - qbuf_pool->block_size) || (offset % qbuf_pool->block_size != 0));

    if (split_buf_offset_invalid || combine_buf_offset_invalid) {
        return NULL;
    }

    return (umq_buf_t *)(uintptr_t)qbuf_addr;
}

char *umq_offset_to_qbuf_data(uint64_t offset, uint32_t data_size, uint64_t pool)
{
    qbuf_pool_t *qbuf_pool = (qbuf_pool_t *)(uintptr_t)pool;
    if (offset > qbuf_pool->total_size - qbuf_pool->block_size || data_size > qbuf_pool->block_size) {
        return NULL;
    }

    uint64_t pool_addr = (uint64_t)(uintptr_t)qbuf_pool->data_buffer;
    uint64_t data_addr = offset + pool_addr;

    bool split_buf_offset_invalid = (qbuf_pool->mode == UMQ_BUF_SPLIT) &&
                                    ((data_addr + data_size > (uint64_t)(uintptr_t)qbuf_pool->header_buffer));

    bool combine_buf_offset_invalid =
        (qbuf_pool->mode == UMQ_BUF_COMBINE) &&
        ((offset < sizeof(umq_buf_t)) || ((offset - sizeof(umq_buf_t)) % qbuf_pool->block_size != 0));

    if (split_buf_offset_invalid || combine_buf_offset_invalid) {
        return NULL;
    }

    return (char *)(uintptr_t)data_addr;
}

int umq_shm_qbuf_enqueue(umq_buf_t *qbuf, uint64_t umq, uint64_t pool, bool rendezvous,
    int (*enqueue)(uint64_t umq, uint64_t *offset, uint32_t num))
{
    uint64_t qbuf_offset = umq_shm_qbuf_pointer_to_offset(qbuf, pool);
    if (qbuf_offset == QBUF_INVALID_OFFSET) {
        return UMQ_FAIL;
    }

    if (rendezvous) {
        qbuf_offset |= UMQ_RENDEZVOUS_FLAG;
    }

    int ret = enqueue(umq, &qbuf_offset, 1);
    if (ret != UMQ_SUCCESS) {
        umq_shm_offset_to_qbuf_pointer((qbuf_offset & UMQ_OFFSET_DATA_BITS), pool, qbuf->umqh);
    }
    return ret;
}

umq_buf_t *umq_shm_qbuf_dequeue(uint64_t umq, uint64_t umq_tp, uint64_t pool, bool *rendezvous,
    int (*dequeue)(uint64_t umq, uint64_t *offset, uint32_t num))
{
    uint64_t offset;
    int cnt = dequeue(umq_tp, &offset, 1);
    if (cnt <= 0) {
        return NULL;
    }
    *rendezvous = (offset & UMQ_RENDEZVOUS_FLAG);

    return umq_shm_offset_to_qbuf_pointer((offset & UMQ_OFFSET_DATA_BITS), pool, umq);
}