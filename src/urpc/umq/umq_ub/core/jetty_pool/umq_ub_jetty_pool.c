/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: jetty pool implementation for UMQ UB
 * Create: 2026-06-08
 * Note:
 * History: 2026-06-08
 */

#include <sys/eventfd.h>
#include <unistd.h>

#include "perf.h"
#include "umq_vlog.h"
#include "umq_errno.h"
#include "urpc_thread_closure.h"
#include "umq_ub_private.h"
#include "umq_ub_jetty_pool.h"

#define THREAD_LOCAL_JETTY_CACHE_SIZE 0
#define THREAD_LOCAL_JETTY_BATCH_SIZE 1  // Default batch size for allocating from global pool to cache
#define THREAD_LOCAL_JETTY_RETURN_BATCH_SIZE 1 // Default batch size for returning from cache to global pool
#define JETTY_POOL_NOTIFY_THRESHOLD 1
#define JETTY_POOL_MAX_NODES 65536
#define UMQ_JETTY_NODE_MIN_BORROW_LIMIT 2
#define UMQ_JETTY_NODE_BORROW_LIMIT_RATIO 1024

typedef struct jetty_pool {
    umq_ub_jetty_node_list_t jetty_node_list;
    urpc_list_t free_q;             // Pre-allocated nodes NOT assigned to any Sub UMQ
    urpc_list_t active_q;           // Nodes assigned to Sub UMQ, available for Logic UMQ
    urpc_list_t relay_q;
    urpc_list_t thread_cache_list;  // Registry of all active thread-local caches
    urpc_list_t avail_cb_list;      // Registered availability callbacks (fired when active_count rises)
    util_external_mutex_lock *avail_cb_lock;  // Protects avail_cb_list (separate from pool lock)
    pthread_spinlock_t lock;        // Pool-level lock (minimal lock usage)
    int event_fd;                   // Eventfd for idle jetty notification

    uint32_t free_count;            // Current count in free_q (protected by lock)
    uint32_t active_count;          // Current count in active_q (protected by lock)
    uint64_t in_use_count;          // Nodes currently borrowed by a Logic UMQ (state == IN_USE)
    uint64_t err_count;             // Nodes marked with is_jetty_err == true
    uint64_t acc_alloc_count;        // Cumulative allocs (nodes borrowed by Logic UMQ)
    uint64_t acc_free_count;         // Cumulative frees (nodes returned to pool)
    uint64_t acc_miss_count;         // Cumulative allocation misses (no available jetty)
    uint32_t node_count;            // Total allocated nodes
    uint32_t max_nodes;             // Max nodes allowed in pool (0 means use default JETTY_POOL_MAX_NODES)

    uint32_t batch_size;            // Batch size for allocating from active_q to cache (default 1)
    uint32_t cache_size;            // Thread-local cache size (default 16)
    uint32_t notify_threshold;      // Notify via eventfd when active_count >= threshold (default 16)
    uint32_t return_batch_size;     // Batch size for returning from cache to active_q (default 1)
} jetty_pool_t;

static __thread thread_local_jetty_cache_t g_thread_jetty_cache = {0};
static jetty_pool_t g_jetty_pool;
static bool g_jetty_pool_inited = false;

// Forward declarations
static void release_thread_cache(uint64_t id);
static void umq_ub_jetty_fire_avail_callbacks(void);

static ALWAYS_INLINE void recycle_node_to_free_q(jetty_pool_t *pool, jetty_pool_node_t *node)
{
    __atomic_store_n(&node->state, JETTY_POOL_NODE_IDLE, __ATOMIC_RELEASE);
    node->in_global_pool = true;
    urpc_list_push_back(&pool->free_q, &node->node);
    pool->free_count++;
}

static ALWAYS_INLINE void recycle_node_to_relay_q(jetty_pool_t *pool, jetty_pool_node_t *node)
{
    __atomic_store_n(&node->state, JETTY_POOL_NODE_IDLE, __ATOMIC_RELEASE);
    node->in_global_pool = true;
    urpc_list_push_back(&pool->relay_q, &node->node);
}

static ALWAYS_INLINE thread_local_jetty_cache_t *get_thread_jetty_cache(void)
{
    if (!g_thread_jetty_cache.inited) {
        urpc_list_init(&g_thread_jetty_cache.cache_list);
        urpc_list_init(&g_thread_jetty_cache.registry_node);
        g_thread_jetty_cache.cached_count = 0;
        g_thread_jetty_cache.inited = true;
        (void)umq_thread_closure_register(UMQ_TRANS_MODE_UB, THREAD_CLOSURE_JETTY_POOL, 0, release_thread_cache);
        (void)pthread_spin_lock(&g_jetty_pool.lock);
        urpc_list_push_back(&g_jetty_pool.thread_cache_list, &g_thread_jetty_cache.registry_node);
        (void)pthread_spin_unlock(&g_jetty_pool.lock);
    }
    return &g_thread_jetty_cache;
}

// Release all thread cache to global pool. should be called when thread exits
static ALWAYS_INLINE void release_thread_cache(uint64_t id)
{
    (void)id;
    if (!g_thread_jetty_cache.inited) {
        return;
    }

    if (!g_jetty_pool_inited) {
        while (!urpc_list_is_empty(&g_thread_jetty_cache.cache_list)) {
            jetty_pool_node_t *cached = (jetty_pool_node_t *)urpc_list_pop_front(
                &g_thread_jetty_cache.cache_list);
            free(cached);
        }
        g_thread_jetty_cache.cached_count = 0;
        g_thread_jetty_cache.inited = false;
        return;
    }

    (void)pthread_spin_lock(&g_jetty_pool.lock);
    urpc_list_remove(&g_thread_jetty_cache.registry_node);
    if (!urpc_list_is_empty(&g_thread_jetty_cache.cache_list)) {
        while (!urpc_list_is_empty(&g_thread_jetty_cache.cache_list)) {
            jetty_pool_node_t *cached = (jetty_pool_node_t *)urpc_list_pop_front(
                &g_thread_jetty_cache.cache_list);
            cached->in_global_pool = true;
            if (__atomic_load_n(&cached->state, __ATOMIC_ACQUIRE) == JETTY_POOL_NODE_ERR) {
                recycle_node_to_free_q(&g_jetty_pool, cached);
            } else {
                urpc_list_push_back(&g_jetty_pool.active_q, &cached->node);
                g_jetty_pool.active_count++;
            }
        }
        g_thread_jetty_cache.cached_count = 0;
    }
    (void)pthread_spin_unlock(&g_jetty_pool.lock);

    g_thread_jetty_cache.inited = false;
}

static int umq_ub_jetty_node_list_init(umq_ub_jetty_node_list_t *jetty_node_list, uint32_t node_cnt)
{
    int ret = UMQ_SUCCESS;
    if (node_cnt == 0 || node_cnt > JETTY_POOL_MAX_NODES) {
        UMQ_VLOG_ERR(VLOG_UMQ, "node cnt %u invalid\n", node_cnt);
        return -UMQ_ERR_EINVAL;
    }

    jetty_node_list->list_len = node_cnt;
    jetty_node_list->bitmap = urpc_bitmap_alloc(node_cnt);
    if (jetty_node_list->bitmap == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "alloc bitmap failed\n");
        return -UMQ_ERR_ENOMEM;
    }

    jetty_node_list->node_list = (jetty_pool_node_t **)calloc(node_cnt, sizeof(jetty_pool_node_t *));
    if (jetty_node_list->node_list == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc node list failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FREE_BITMAP;
    }

    jetty_node_list->lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (jetty_node_list->lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "jetty node list mutex create failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FREE_NODE_LIST;
    }
    return UMQ_SUCCESS;

FREE_NODE_LIST:
    free(jetty_node_list->node_list);
    jetty_node_list->node_list = NULL;

FREE_BITMAP:
    urpc_bitmap_free(jetty_node_list->bitmap);
    jetty_node_list->bitmap = NULL;

    return ret;
}

int umq_ub_jetty_pool_init(jetty_pool_config_t *config)
{
    if (g_jetty_pool_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "jetty pool already exists, only one pool allowed per process\n");
        return -UMQ_ERR_EEXIST;
    }

    urpc_list_init(&g_jetty_pool.free_q);
    urpc_list_init(&g_jetty_pool.active_q);
    urpc_list_init(&g_jetty_pool.relay_q);
    urpc_list_init(&g_jetty_pool.thread_cache_list);
    urpc_list_init(&g_jetty_pool.avail_cb_list);

    int event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event_fd < 0) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create jetty pool eventfd failed, errno: %d\n", errno);
        return -UMQ_ERR_EINVAL;
    }

    g_jetty_pool.event_fd = event_fd;
    g_jetty_pool.max_nodes = JETTY_POOL_MAX_NODES;
    g_jetty_pool.batch_size = THREAD_LOCAL_JETTY_BATCH_SIZE;
    g_jetty_pool.cache_size = THREAD_LOCAL_JETTY_CACHE_SIZE;
    g_jetty_pool.return_batch_size = THREAD_LOCAL_JETTY_RETURN_BATCH_SIZE;
    g_jetty_pool.notify_threshold = (config->notify_threshold > 0) ?
        config->notify_threshold : JETTY_POOL_NOTIFY_THRESHOLD;

    int ret = umq_ub_jetty_node_list_init(&g_jetty_pool.jetty_node_list, g_jetty_pool.max_nodes);
    if (ret != UMQ_SUCCESS) {
        goto CLOSE_FD;
    }

    (void)pthread_spin_init(&g_jetty_pool.lock, PTHREAD_PROCESS_PRIVATE);
    g_jetty_pool.avail_cb_lock = util_mutex_lock_create(UTIL_MUTEX_ATTR_EXCLUSIVE);
    if (g_jetty_pool.avail_cb_lock == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "create avail_cb_lock failed\n");
        goto DESTROY_LOCK;
    }
    g_jetty_pool_inited = true;
    return UMQ_SUCCESS;

DESTROY_LOCK:
    (void)pthread_spin_destroy(&g_jetty_pool.lock);

CLOSE_FD:
    (void)close(g_jetty_pool.event_fd);
    return ret;
}

static void umq_ub_jetty_node_list_uninit(umq_ub_jetty_node_list_t *jetty_node_list)
{
    if (jetty_node_list->node_list != NULL) {
        jetty_node_list->list_len = 0;
        free(jetty_node_list->node_list);
        jetty_node_list->node_list = NULL;
    }

    if (jetty_node_list->bitmap != NULL) {
        urpc_bitmap_free(jetty_node_list->bitmap);
        jetty_node_list->bitmap = NULL;
    }
    (void)util_mutex_lock_destroy(jetty_node_list->lock);
    jetty_node_list->lock = NULL;
}

void umq_ub_jetty_pool_uninit(void)
{
    if (!g_jetty_pool_inited) {
        return;
    }

    g_jetty_pool_inited = false;

    umq_ub_jetty_node_list_uninit(&g_jetty_pool.jetty_node_list);
    thread_local_jetty_cache_t *cache = NULL;
    thread_local_jetty_cache_t *cache_tmp = NULL;
    (void)pthread_spin_lock(&g_jetty_pool.lock);
    URPC_LIST_FOR_EACH_SAFE(cache, cache_tmp, registry_node, &g_jetty_pool.thread_cache_list) {
        while (!urpc_list_is_empty(&cache->cache_list)) {
            jetty_pool_node_t *cached = (jetty_pool_node_t *)urpc_list_pop_front(&cache->cache_list);
            free(cached);
        }
        cache->cached_count = 0;
        cache->inited = false;
        urpc_list_remove(&cache->registry_node);
    }
    (void)pthread_spin_unlock(&g_jetty_pool.lock);

    jetty_pool_node_t *iter = NULL;
    jetty_pool_node_t *tmp = NULL;
    URPC_LIST_FOR_EACH_SAFE(iter, tmp, node, &g_jetty_pool.free_q) {
        urpc_list_remove(&iter->node);
        free(iter);
    }
    URPC_LIST_FOR_EACH_SAFE(iter, tmp, node, &g_jetty_pool.active_q) {
        urpc_list_remove(&iter->node);
        free(iter);
    }
    URPC_LIST_FOR_EACH_SAFE(iter, tmp, node, &g_jetty_pool.relay_q) {
        urpc_list_remove(&iter->node);
        free(iter);
    }

    (void)close(g_jetty_pool.event_fd);
    (void)pthread_spin_destroy(&g_jetty_pool.lock);
    if (g_jetty_pool.avail_cb_lock != NULL) {
        (void)util_mutex_lock_destroy(g_jetty_pool.avail_cb_lock);
        g_jetty_pool.avail_cb_lock = NULL;
    }

    umq_ub_jetty_avail_cb_node_t *cb_iter = NULL;
    umq_ub_jetty_avail_cb_node_t *cb_tmp = NULL;
    URPC_LIST_FOR_EACH_SAFE(cb_iter, cb_tmp, node, &g_jetty_pool.avail_cb_list) {
        urpc_list_remove(&cb_iter->node);
        free(cb_iter);
    }

    memset(&g_jetty_pool, 0, sizeof(g_jetty_pool));
}

jetty_pool_node_t *umq_ub_jetty_pool_get_free_node(void)
{
    jetty_pool_node_t *node = NULL;
    (void)pthread_spin_lock(&g_jetty_pool.lock);
    if (!urpc_list_is_empty(&g_jetty_pool.free_q)) {
        node = (jetty_pool_node_t *)urpc_list_pop_front(&g_jetty_pool.free_q);
        g_jetty_pool.free_count--;
        pthread_spin_unlock(&g_jetty_pool.lock);
        memset(node, 0, sizeof(jetty_pool_node_t));
        return node;
    }
    (void)pthread_spin_unlock(&g_jetty_pool.lock);

    return (jetty_pool_node_t *)calloc(1, sizeof(jetty_pool_node_t));
}

void umq_ub_jetty_pool_put_free_node(jetty_pool_node_t *node)
{
    if (node == NULL) {
        return;
    }
    (void)pthread_spin_lock(&g_jetty_pool.lock);
    urpc_list_push_back(&g_jetty_pool.free_q, &node->node);
    g_jetty_pool.free_count++;
    (void)pthread_spin_unlock(&g_jetty_pool.lock);
}

int umq_ub_jetty_node_add(jetty_pool_node_t *node)
{
    if (!g_jetty_pool_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "jetty pool not initialized\n");
        return -UMQ_ERR_EINVAL;
    }

    jetty_pool_t *pool = &g_jetty_pool;

    (void)pthread_spin_lock(&pool->lock);
    jetty_pool_node_t *add_node = node;
    if (pool->node_count >= pool->max_nodes) {
        (void)pthread_spin_unlock(&pool->lock);
        UMQ_VLOG_ERR(VLOG_UMQ, "max jetty nodes %u reached\n", pool->max_nodes);
        return -UMQ_ERR_EMLINK;
    }
    add_node->in_global_pool = true;
    __atomic_store_n(&add_node->state, JETTY_POOL_NODE_IDLE, __ATOMIC_RELEASE);

    urpc_list_push_back(&pool->active_q, &add_node->node);
    pool->active_count++;
    pool->node_count++;
    uint32_t active_after_add = pool->active_count;
    (void)pthread_spin_unlock(&pool->lock);

    // Notify via eventfd when active_count reaches every notify_threshold
    if (active_after_add % pool->notify_threshold == 0) {
        if (eventfd_write(pool->event_fd, (uint64_t)active_after_add) == -1) {
            UMQ_VLOG_WARN(VLOG_UMQ, "eventfd_write failed, errno: %d\n", errno);
        }
    }
    umq_ub_jetty_fire_avail_callbacks();
    return UMQ_SUCCESS;
}

int umq_ub_jetty_node_remove(jetty_pool_node_t *node)
{
    if (!g_jetty_pool_inited) {
        UMQ_VLOG_ERR(VLOG_UMQ, "jetty pool not initialized\n");
        return -UMQ_ERR_EINVAL;
    }

    if (node == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "pool_node is NULL, already removed\n");
        return -UMQ_ERR_EINVAL;
    }

    jetty_pool_t *pool = &g_jetty_pool;
    // Try CAS IDLE→ERR to atomically claim the node.
    int expected = JETTY_POOL_NODE_IDLE;
    if (!__atomic_compare_exchange_n(&node->state, &expected, JETTY_POOL_NODE_ERR,
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        UMQ_VLOG_ERR(VLOG_UMQ, "cannot remove sub_umq, node state %d (expected IDLE)\n", expected);
        return -UMQ_ERR_EBUSY;
    }

    (void)pthread_spin_lock(&pool->lock);
    if (node->in_global_pool) {
        // Node in active_q: return to free_q for reassignment.
        urpc_list_remove(&node->node);
        pool->active_count--;
        recycle_node_to_free_q(pool, node);
    }
    pool->node_count--;
    (void)pthread_spin_unlock(&pool->lock);
    if (node->is_jetty_err) {
        (void)__atomic_sub_fetch(&pool->err_count, 1, __ATOMIC_RELAXED);
    }
    return UMQ_SUCCESS;
}

static inline uint32_t get_borrow_limit(uint32_t total_jetty_num, uint32_t remaining_jetty_num)
{
    uint32_t borrow_limit = 0;
    if (total_jetty_num != 0) {
        borrow_limit = UMQ_JETTY_NODE_BORROW_LIMIT_RATIO * remaining_jetty_num / total_jetty_num;
    }
    return borrow_limit > UMQ_JETTY_NODE_MIN_BORROW_LIMIT ? borrow_limit : UMQ_JETTY_NODE_MIN_BORROW_LIMIT;
}

jetty_pool_node_t *umq_ub_jetty_node_alloc(void)
{
    if (!g_jetty_pool_inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "jetty pool not initialized\n");
        return NULL;
    }

    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    jetty_pool_t *pool = &g_jetty_pool;

    thread_local_jetty_cache_t *cache = get_thread_jetty_cache();

    while (pool->active_count > 0) {
        // 1. Batch fetch from active_q to fill thread-local cache.
        //    active_q never contains ERR nodes (remove() moves them to free_q).
        if (cache->cached_count == 0) {
            (void)pthread_spin_lock(&pool->lock);
            uint32_t moved = urpc_list_move_n(&pool->active_q, &cache->cache_list, pool->batch_size);
            pool->active_count -= moved;
            jetty_pool_node_t *iter = NULL;
            URPC_LIST_FOR_EACH(iter, node, &cache->cache_list) {
                iter->in_global_pool = false;
            }
            (void)pthread_spin_unlock(&pool->lock);
            if (moved == 0) {
                // active_q is empty — no sub_umqs in pool
                break;
            }

            cache->cached_count += moved;
        }

        // 2. Try each cached node — remove() may have marked some as ERR while in cache.
        while (cache->cached_count > 0) {
            jetty_pool_node_t *node = (jetty_pool_node_t *)urpc_list_pop_front(&cache->cache_list);
            cache->cached_count--;

            uint32_t expected = JETTY_POOL_NODE_IDLE;
            if (!__atomic_compare_exchange_n(&node->state, &expected, JETTY_POOL_NODE_IN_USE,
                                             false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                if (expected == JETTY_POOL_NODE_ERR || node->is_jetty_err) {
                    (void)pthread_spin_lock(&pool->lock);
                    recycle_node_to_free_q(pool, node);
                    (void)pthread_spin_unlock(&pool->lock);
                }
                continue;
            }

            node->borrow_count = 0;
            node->borrow_limit = get_borrow_limit(pool->node_count, pool->active_count);
            (void)__atomic_add_fetch(&pool->in_use_count, 1, __ATOMIC_RELAXED);
            (void)__atomic_add_fetch(&pool->acc_alloc_count, 1, __ATOMIC_RELAXED);
            umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_ALLOC_JETTY_NODE, start_timestamp);
            return node;
        }
    }

    // 3. No available jettys.
    (void)__atomic_add_fetch(&pool->acc_miss_count, 1, __ATOMIC_RELAXED);
    UMQ_LIMIT_VLOG_DEBUG(VLOG_UMQ, "No available jetty\n");
    errno = UMQ_ERR_EMLINK;
    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_ALLOC_JETTY_NODE, start_timestamp);
    return NULL;
}

int umq_ub_jetty_node_free(jetty_pool_node_t *node)
{
    if (!g_jetty_pool_inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "jetty pool not initialized\n");
        return -UMQ_ERR_EINVAL;
    }

    uint64_t start_timestamp = umq_perf_get_start_timestamp();
    uint32_t expected = JETTY_POOL_NODE_IN_USE;
    if (!__atomic_compare_exchange_n(&node->state, &expected, JETTY_POOL_NODE_IDLE,
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return UMQ_SUCCESS;
    }

    jetty_pool_t *pool = &g_jetty_pool;
    (void)__atomic_sub_fetch(&pool->in_use_count, 1, __ATOMIC_RELAXED);
    (void)__atomic_add_fetch(&pool->acc_free_count, 1, __ATOMIC_RELAXED);
    if (node->is_jetty_err) {
        (void)pthread_spin_lock(&pool->lock);
        recycle_node_to_relay_q(pool, node);
        (void)pthread_spin_unlock(&pool->lock);
        umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_FREE_JETTY_NODE, start_timestamp);
        return UMQ_SUCCESS;
    }

    node->borrow_count = 0;
    thread_local_jetty_cache_t *cache = get_thread_jetty_cache();
    urpc_list_push_back(&cache->cache_list, &node->node);
    cache->cached_count++;

    // Check if cache exceeds limit, batch return excess to active_q
    if (cache->cached_count > pool->cache_size) {
        (void)pthread_spin_lock(&pool->lock);
        uint32_t to_mark = (pool->return_batch_size < cache->cached_count) ?
                            pool->return_batch_size : cache->cached_count;
        if (to_mark > 0) {
            jetty_pool_node_t *iter = NULL;
            uint32_t marked = 0;
            URPC_LIST_FOR_EACH(iter, node, &cache->cache_list) {
                if (marked >= to_mark) {
                    break;
                }
                iter->in_global_pool = true;
                marked++;
            }
        }

        uint32_t cnt = urpc_list_move_n(&cache->cache_list, &pool->active_q, to_mark);
        pool->active_count += cnt;
        cache->cached_count -= cnt;
        uint64_t value = (uint64_t)pool->active_count;
        (void)pthread_spin_unlock(&pool->lock);

        if ((value % pool->notify_threshold) < cnt) {
            if (eventfd_write(pool->event_fd, value) != 0) {
                UMQ_VLOG_WARN(VLOG_UMQ, "eventfd_write failed, errno: %d\n", errno);
            }
        }
        umq_ub_jetty_fire_avail_callbacks();
    }

    umq_perf_record_write(UMQ_PERF_RECORD_TRANSPORT_FREE_JETTY_NODE, start_timestamp);
    return UMQ_SUCCESS;
}

int umq_ub_jetty_pool_get_eventfd(void)
{
    if (!g_jetty_pool_inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "jetty pool not initialized\n");
        return -UMQ_ERR_EINVAL;
    }
    return g_jetty_pool.event_fd;
}

static void umq_ub_jetty_fire_avail_callbacks(void)
{
    // Try-lock: if another thread is already firing, skip — one wake is enough.
    if (util_mutex_try_lock(g_jetty_pool.avail_cb_lock) != 0) {
        return;
    }
    umq_ub_jetty_avail_cb_node_t *cb_node = NULL;
    umq_ub_jetty_avail_cb_node_t *cb_next = NULL;
    URPC_LIST_FOR_EACH_SAFE(cb_node, cb_next, node, &g_jetty_pool.avail_cb_list) {
        if (cb_node->cb != NULL) {
            cb_node->cb(cb_node->user_data);
        }
    }
    (void)util_mutex_unlock(g_jetty_pool.avail_cb_lock);
}

umq_ub_jetty_avail_cb_node_t *umq_ub_jetty_pool_register_avail_cb(umq_ub_jetty_avail_cb_t cb, void *user_data)
{
    if (!g_jetty_pool_inited) {
        UMQ_LIMIT_VLOG_ERR(VLOG_UMQ, "jetty pool not initialized\n");
        return NULL;
    }

    umq_ub_jetty_avail_cb_node_t *cb_node =
        (umq_ub_jetty_avail_cb_node_t *)calloc(1, sizeof(*cb_node));
    if (cb_node == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc jetty avail cb node failed\n");
        return NULL;
    }
    cb_node->cb = cb;
    cb_node->user_data = user_data;
    (void)util_mutex_lock(g_jetty_pool.avail_cb_lock);
    urpc_list_push_back(&g_jetty_pool.avail_cb_list, &cb_node->node);
    (void)util_mutex_unlock(g_jetty_pool.avail_cb_lock);
    return cb_node;
}

void umq_ub_jetty_pool_unregister_avail_cb(umq_ub_jetty_avail_cb_node_t *cb_node)
{
    if (cb_node == NULL) {
        return;
    }
    if (!g_jetty_pool_inited) {
        // pool torn down; just free the node (it's not in any list anymore)
        free(cb_node);
        return;
    }
    (void)util_mutex_lock(g_jetty_pool.avail_cb_lock);
    urpc_list_remove(&cb_node->node);
    (void)util_mutex_unlock(g_jetty_pool.avail_cb_lock);
    free(cb_node);
}

bool umq_ub_jetty_pool_has_avail(void)
{
    if (!g_jetty_pool_inited) {
        return false;
    }
    return __atomic_load_n(&g_jetty_pool.active_count, __ATOMIC_ACQUIRE) > 0;
}

umq_ub_jetty_node_list_t *umq_ub_jetty_pool_get_jetty_node_list(void)
{
    (void)__atomic_fetch_add(&g_jetty_pool.jetty_node_list.ref_cnt, 1, __ATOMIC_RELAXED);
    return &g_jetty_pool.jetty_node_list;
}

uint32_t umq_ub_jetty_pool_put_jetty_node_list(umq_ub_jetty_node_list_t *jetty_node_list)
{
    return __atomic_sub_fetch(&jetty_node_list->ref_cnt, 1, __ATOMIC_ACQ_REL);
}

void umq_ub_jetty_node_mark_err(jetty_pool_node_t *node)
{
    if (node == NULL) {
        return;
    }
    bool expected = false;
    if (!__atomic_compare_exchange_n(&node->is_jetty_err, &expected, true, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return; // was already true
    }
    (void)__atomic_add_fetch(&g_jetty_pool.err_count, 1, __ATOMIC_RELAXED);
}

int umq_ub_jetty_pool_stats_get(umq_ub_jetty_pool_stats_t *stats)
{
    if (stats == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "stats is NULL\n");
        return -UMQ_ERR_EINVAL;
    }
    if (!g_jetty_pool_inited) {
        memset(stats, 0, sizeof(*stats));
        return UMQ_SUCCESS;
    }
    jetty_pool_t *pool = &g_jetty_pool;
    (void)pthread_spin_lock(&pool->lock);
    stats->total_num = pool->node_count;
    stats->global_num = pool->active_count;
    uint32_t thread_cache_total = 0;
    thread_local_jetty_cache_t *cache = NULL;
    URPC_LIST_FOR_EACH(cache, registry_node, &pool->thread_cache_list) {
        thread_cache_total += cache->cached_count;
    }
    (void)pthread_spin_unlock(&pool->lock);
    stats->cache_num = thread_cache_total;
    stats->in_use_num = __atomic_load_n(&pool->in_use_count, __ATOMIC_RELAXED);
    stats->err_num = __atomic_load_n(&pool->err_count, __ATOMIC_RELAXED);
    stats->acc_alloc_num = __atomic_load_n(&pool->acc_alloc_count, __ATOMIC_RELAXED);
    stats->acc_free_num = __atomic_load_n(&pool->acc_free_count, __ATOMIC_RELAXED);
    stats->acc_miss_num = __atomic_load_n(&pool->acc_miss_count, __ATOMIC_RELAXED);
    return UMQ_SUCCESS;
}

