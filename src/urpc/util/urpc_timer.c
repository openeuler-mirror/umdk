/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc timing wheel
 * Create: 2024-11-07
 */

#include <pthread.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "urpc_dbuf_stat.h"
#include "urpc_framework_errno.h"
#include "urpc_hash.h"
#include "urpc_hmap.h"
#include "util_log.h"
#include "urpc_manage.h"

#include "urpc_timer.h"

#define URPC_TIMER_EPOLL_FD_NUM 32
#define URPC_TIMER_EPOLL_TIMEOUT 50

#define URPC_TIMER_HMAP_SIZE (16384)
#define URPC_TIMER_DEFAULT_NUM (8192)  // default timer cost 800KB

#define URPC_TIMING_WHEEL_HZ 500   /* 2ms per tick */
#define URPC_TIMER_MIN_SLEEP 10000 /* 10us minimum sleep time per slot */

/* timing wheel level depth and size. 1<<10 means 1024 ticks
   for level 0, 1024*1024 ticks for all levels. */
#define URPC_WHEEL_LEVEL_MAX 2
#define URPC_WHEEL_LEVEL_BITS (14u)  // 16384, support max 16k * 16k ticks, equals to 6.2days
#define URPC_WHEEL_LEVEL_SIZE (1u << URPC_WHEEL_LEVEL_BITS)
#define URPC_WHEEL_LEVEL_MASK (URPC_WHEEL_LEVEL_SIZE - 1)

#define URPC_TIMER_MAGIC_NUM 0x33445577u
#define URPC_TIMER_MIN_DELAY (10u)      /* 10ms */
#define URPC_TIMER_MAX_DELAY 0xFFFFFFFu /* in ms, 3 days */
#define URPC_TIMER_MAX_JOB 1000

// if client_chid == URPC_INVALID_ID_U32 && server_chid == URPC_INVALID_ID_U32 means use default timer
typedef struct urpc_timer_key {
    uint32_t client_chid;
    uint32_t server_chid;
} __attribute__((packed)) urpc_timer_key_t;

struct urpc_timer {
    uint32_t magic;    /* work around, used to determine whether the timer has been freed, so keep it in first place */
    urpc_list_t entry; /* list in timing wheel */
    urpc_list_t pool_entry; /* list in the pool */
    urpc_timer_key_t key;
    void (*func)(void *);
    void *args;
    uint64_t ticks; /* ticks required for timer to expire */
    uint64_t timeout;
    uint64_t end_ticks;   /* the exact point in ticks at which the timer expires */
    uint8_t periodic;
    uint8_t status;
};

typedef struct urpc_timer_pool_entry {
    struct urpc_hmap_node node;
    urpc_timer_key_t key;
    urpc_list_t head;
    uint32_t timer_num;
    volatile uint64_t stats[TIMER_STATS_TYPE_MAX];
    urpc_timer_t timer[0];
} urpc_timer_pool_entry_t;

typedef struct urpc_timing_wheel {
    pthread_spinlock_t lock;

    /* timing wheel cursors point to the slots */
    uint64_t cursors[URPC_WHEEL_LEVEL_MAX];

    /* timing wheel slots to store timer entries */
    urpc_list_t slots[URPC_WHEEL_LEVEL_MAX][URPC_WHEEL_LEVEL_SIZE];

    /* timing wheel total ticks since boot */
    uint64_t ticks;

    /* timing wheel total ticks that fall behind */
    uint64_t ticks_pending;

    /* timing wheel version when slots list been changed */
    uint64_t version;
} urpc_timing_wheel_t;

static struct {
    urpc_timing_wheel_t *tw;

    struct urpc_hmap pool;      // key: chid; value: timer_list
    pthread_spinlock_t p_lock;  // timer pool lock
    urpc_epoll_event_t event;

    int timer_fd;
} g_urpc_timing_wheel = {
    .timer_fd = -1,
};

static void urpc_timer_remove_from_timing_wheel(urpc_timer_t *timer);

static inline bool is_urpc_timer_key_same(urpc_timer_key_t *k1, urpc_timer_key_t *k2)
{
    return (k1->client_chid == k2->client_chid) && (k1->server_chid == k2->server_chid);
}

static inline void urpc_timer_key_fill(urpc_timer_key_t *key, uint32_t chid, bool is_server)
{
    key->client_chid = is_server ? URPC_INVALID_ID_U32 : chid;
    key->server_chid = is_server ? chid : URPC_INVALID_ID_U32;
}

static inline void urpc_timer_pool_entry_init(urpc_timer_pool_entry_t *entry)
{
    urpc_timer_t *t;
    for (uint32_t i = 0; i < entry->timer_num; i++) {
        t = &entry->timer[i];
        t->status = URPC_TIMER_STAT_INVALID;
        t->key = entry->key;
        urpc_list_push_back(&entry->head, &t->pool_entry);
    }
}

static inline void urpc_timer_pool_entry_uninit(urpc_timer_pool_entry_t *entry)
{
    urpc_timer_t *t;
    for (uint32_t i = 0; i < entry->timer_num; i++) {
        t = &entry->timer[i];
        // if timer is in timing wheel list, remove it
        if (URPC_UNLIKELY(t->status != URPC_TIMER_STAT_INVALID && t->status != URPC_TIMER_STAT_INITED)) {
            urpc_timer_remove_from_timing_wheel(t);
        }
    }
}

static inline urpc_timer_pool_entry_t *urpc_timer_pool_entry_lookup(urpc_timer_key_t *key, uint32_t key_hash)
{
    urpc_timer_pool_entry_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, node, key_hash, &g_urpc_timing_wheel.pool)
    {
        if (is_urpc_timer_key_same(key, &entry->key)) {
            return entry;
        }
    }

    return NULL;
}

int urpc_timer_pool_add(uint32_t chid, uint32_t num, bool is_server)
{
    urpc_timer_key_t key;
    urpc_timer_key_fill(&key, chid, is_server);
    urpc_timer_pool_entry_t *entry = NULL;
    uint32_t key_hash = urpc_hash_bytes(&key, sizeof(urpc_timer_key_t), 0);

    uint32_t timer_num = (chid == URPC_INVALID_ID_U32) ? URPC_TIMER_DEFAULT_NUM : num;
    urpc_timer_pool_entry_t *new_entry = (urpc_timer_pool_entry_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_TIMEOUT,
        sizeof(urpc_timer_pool_entry_t) + sizeof(urpc_timer_t) * timer_num);
    if (new_entry == NULL) {
        UTIL_LOG_ERR("malloc %u new timer in pool failed\n", timer_num);
        return URPC_FAIL;
    }

    new_entry->key = key;
    new_entry->timer_num = timer_num;
    urpc_list_init(&new_entry->head);
    urpc_timer_pool_entry_init(new_entry);

    pthread_spin_lock(&g_urpc_timing_wheel.p_lock);
    entry = urpc_timer_pool_entry_lookup(&key, key_hash);
    if (URPC_UNLIKELY(entry != NULL)) {
        pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);

        urpc_dbuf_free(new_entry);
        UTIL_LOG_INFO("add new timer in pool failed, entry already existed\n");
        return -URPC_ERR_EEXIST;
    }

    new_entry->stats[TIMER_ENTRY_TOTAL_NUM] = timer_num;
    new_entry->stats[TIMER_ENTRY_FREE_NUM] = timer_num;
    urpc_hmap_insert(&g_urpc_timing_wheel.pool, &new_entry->node, key_hash);

    pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);

    return URPC_SUCCESS;
}

void urpc_timer_pool_delete(uint32_t chid, bool is_server)
{
    urpc_timer_key_t key;
    urpc_timer_key_fill(&key, chid, is_server);
    urpc_timer_pool_entry_t *entry = NULL;
    uint32_t key_hash = urpc_hash_bytes(&key, sizeof(urpc_timer_key_t), 0);

    pthread_spin_lock(&g_urpc_timing_wheel.p_lock);
    entry = urpc_timer_pool_entry_lookup(&key, key_hash);
    if (entry != NULL) {
        urpc_hmap_remove(&g_urpc_timing_wheel.pool, &entry->node);
        urpc_timer_pool_entry_uninit(entry);
        urpc_dbuf_free(entry);
    }

    pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);
}

static urpc_timer_t *urpc_timer_pool_get(uint32_t chid, bool is_server)
{
    urpc_timer_t *t = NULL;
    urpc_timer_key_t key;
    urpc_timer_key_fill(&key, chid, is_server);
    urpc_timer_pool_entry_t *entry = NULL;
    uint32_t key_hash = urpc_hash_bytes(&key, sizeof(urpc_timer_key_t), 0);

    pthread_spin_lock(&g_urpc_timing_wheel.p_lock);
    entry = urpc_timer_pool_entry_lookup(&key, key_hash);
    if (URPC_LIKELY(entry != NULL)) {
        if (URPC_LIKELY(!urpc_list_is_empty(&entry->head))) {
            INIT_CONTAINER_PTR(t, entry->head.next, pool_entry);  // list first
            urpc_list_remove(&t->pool_entry);
        }
        entry->stats[TIMER_ENTRY_FREE_NUM]--;
        pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);

        return t;
    }

    pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);
    return NULL;
}

static void urpc_timer_pool_put(urpc_timer_t *t)
{
    urpc_timer_pool_entry_t *entry = NULL;
    uint32_t key_hash = urpc_hash_bytes(&t->key, sizeof(urpc_timer_key_t), 0);

    pthread_spin_lock(&g_urpc_timing_wheel.p_lock);
    entry = urpc_timer_pool_entry_lookup(&t->key, key_hash);
    if (URPC_LIKELY(entry != NULL)) {
        if (URPC_LIKELY(!urpc_list_is_in_list(&t->pool_entry))) {
            t->status = URPC_TIMER_STAT_INVALID;
            urpc_list_push_front(&entry->head, &t->pool_entry);
        }
        entry->stats[TIMER_ENTRY_FREE_NUM]++;
    } else {
        UTIL_LOG_WARN("timer not in pool\n");
    }
    pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);
}

static int urpc_timer_pool_init(void)
{
    int ret = urpc_hmap_init(&g_urpc_timing_wheel.pool, URPC_TIMER_HMAP_SIZE);
    if (ret != URPC_SUCCESS) {
        UTIL_LOG_ERR("timer pool hmap init failed\n");
        return URPC_FAIL;
    }

    (void)pthread_spin_init(&g_urpc_timing_wheel.p_lock, PTHREAD_PROCESS_PRIVATE);

    ret = urpc_timer_pool_add(URPC_INVALID_ID_U32, URPC_TIMER_DEFAULT_NUM, false);
    if (ret != URPC_SUCCESS) {
        UTIL_LOG_ERR("timer pool hmap init failed\n");
        urpc_timer_pool_delete(URPC_INVALID_ID_U32, false);
        urpc_hmap_uninit(&g_urpc_timing_wheel.pool);
        pthread_spin_destroy(&g_urpc_timing_wheel.p_lock);
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static void urpc_timer_pool_uninit(void)
{
    urpc_timer_pool_delete(URPC_INVALID_ID_U32, false);
    urpc_hmap_uninit(&g_urpc_timing_wheel.pool);
    pthread_spin_destroy(&g_urpc_timing_wheel.p_lock);
}

static inline uint64_t urpc_get_offset_by_level(uint64_t ticks, int level)
{
    uint64_t cur_ticks = ticks;
    for (int cur_level = level; cur_level > 0; cur_level--) {
        cur_ticks = cur_ticks >> URPC_WHEEL_LEVEL_BITS;
    }
    return cur_ticks;
}

static inline uint64_t urpc_time_ms_to_ticks(uint64_t ms)
{
    return ms * URPC_TIMING_WHEEL_HZ / MS_PER_SEC;
}

// when new timer is added to the tw, tw list is changed
static inline void urpc_timing_wheel_version_update(urpc_timing_wheel_t *tw)
{
    tw->version++;
}

static inline void urpc_timing_wheel_lock(urpc_timing_wheel_t *tw)
{
    pthread_spin_lock(&tw->lock);
}

static inline void urpc_timing_wheel_unlock(urpc_timing_wheel_t *tw)
{
    pthread_spin_unlock(&tw->lock);
}

// work around, used to determine whether the timer has been freed
static inline bool urpc_check_timer_magic(const urpc_timer_t *timer)
{
    return *(const uint32_t *)(void *)timer == URPC_TIMER_MAGIC_NUM;
}

/* Put timer to timing wheel slot */
static void urpc_schedule_timer(urpc_timing_wheel_t *tw, urpc_timer_t *timer)
{
    uint32_t level;
    uint64_t offset, pos;
    uint64_t remain_ticks = 0;

    if (URPC_LIKELY(timer->end_ticks > tw->ticks)) {
        remain_ticks = timer->end_ticks - tw->ticks;
    }

    /* for example. level size is 4, dealy is 4, cursor[0] is 0, cursor[1] is 0,
       so timer will be put into level 1 slot 1: slots[1][1]. when 4 ticks has
       passed, cursor[0] return to 0, cursor[1] is 1, so remain_ticks == 0
       and timer will be put into level 0 slot 0:slots[0][0]. */
    if (URPC_LIKELY(remain_ticks == 0)) {
        urpc_list_push_back(&tw->slots[0][tw->cursors[0]], &timer->entry);
        timer->status = URPC_TIMER_STAT_PENDING;
        return;
    }

    /* put the timer into the suitable level of timing wheel.
       start from high level to low level */
    for (level = URPC_WHEEL_LEVEL_MAX - 1; level >= 0; level--) {
        offset = urpc_get_offset_by_level(remain_ticks, level);
        if (offset > 0) {
            pos = (tw->cursors[level] + offset) & URPC_WHEEL_LEVEL_MASK;
            urpc_list_push_back(&tw->slots[level][pos], &timer->entry);
            timer->status = URPC_TIMER_STAT_PENDING;
            break;
        }
    }
}

static inline void urpc_free_timer(urpc_timer_t *timer)
{
    urpc_timer_pool_put(timer);
}

/* Invoke at most timers_count expired timers' callback function in the specified slot */
static int urpc_timing_wheel_process_one_slot(urpc_timing_wheel_t *tw, int timers_count)
{
    int remain_count = timers_count;
    urpc_timer_t *timer = NULL;
    urpc_timer_t *next = NULL;
    uint64_t version = tw->version;
    uint64_t begin_cycle = urpc_get_cpu_cycles();
    URPC_LIST_FOR_EACH_SAFE(timer, next, entry, &tw->slots[0][tw->cursors[0]])
    {
        remain_count--;
        if (URPC_UNLIKELY(remain_count < 0)) {
            return 0;
        }

        if (URPC_LIKELY(urpc_list_is_in_list(&timer->entry))) {
            urpc_list_remove(&timer->entry);
        } else {
            // timer已被相邻的上一个timer释放, 应退出遍历
            return 0;
        }

        if (timer->end_ticks > tw->ticks) {
            urpc_schedule_timer(tw, timer);
            continue;
        }

        timer->status = URPC_TIMER_STAT_RUNNING;
        // prevent module lock and timing wheel lock order dependency
        urpc_timing_wheel_unlock(tw);

        timer->func(timer->args);

        // prevent module lock and timing wheel lock order dependency
        urpc_timing_wheel_lock(tw);
        timer->status = URPC_TIMER_STAT_FINISH;

        if (URPC_UNLIKELY(!timer->periodic)) {
            urpc_free_timer(timer);
        } else {
            timer->end_ticks = timer->ticks + tw->ticks + tw->ticks_pending;
            urpc_schedule_timer(tw, timer);
        }

        if (URPC_UNLIKELY(tw->version != version)) {
            // timing wheel has been changed by cb_func
            return 0;
        }

        // 2 means timer cb has cost over half of tick time. and time calculation need both * MS_PER_SEC
        if (URPC_UNLIKELY(2 * (urpc_get_cpu_cycles() - begin_cycle) >= urpc_get_cpu_hz() / URPC_TIMING_WHEEL_HZ)) {
            return 0;
        }
    }

    return remain_count;
}

static inline void urpc_timer_rearrange(urpc_timing_wheel_t *tw, uint32_t level)
{
    urpc_timer_t *timer = NULL;
    urpc_timer_t *next = NULL;
    URPC_LIST_FOR_EACH_SAFE(timer, next, entry, &tw->slots[level][tw->cursors[level]])
    {
        if (urpc_list_is_in_list(&timer->entry)) {
            urpc_list_remove(&timer->entry);
        }
        urpc_schedule_timer(tw, timer);
    }
}

/* Drive the timing wheel one step forward */
static void urpc_timing_wheel_step_forward(urpc_timing_wheel_t *tw)
{
    /* take a step forward */
    tw->ticks++;

    for (uint32_t level = 0; level < URPC_WHEEL_LEVEL_MAX; level++) {
        tw->cursors[level]++;
        if (tw->cursors[level] >= URPC_WHEEL_LEVEL_SIZE) {
            tw->cursors[level] = 0;
        }

        /* timers in higher level should be migrated to lower level.
           it is possible to reassign the timer to the same level
           depending on how many ticks has been taken */
        if (level > 0) {
            urpc_timer_rearrange(tw, level);
        }

        /* cursor backs to 0 means higher level cursor should take a step
           forward. Otherwise, break the loop */
        if (tw->cursors[level] != 0) {
            break;
        }
    }
}

static void urpc_timer_process(urpc_timing_wheel_t *tw)
{
    int timers_count = URPC_TIMER_MAX_JOB;

    urpc_timing_wheel_lock(tw);

    tw->ticks_pending++;

    while (timers_count > 0) {
        timers_count = urpc_timing_wheel_process_one_slot(tw, timers_count);
        if (timers_count == 0 || tw->ticks_pending == 0) {
            break;
        }
        tw->ticks_pending--;
        urpc_timing_wheel_step_forward(tw);
    }

    urpc_timing_wheel_unlock(tw);
}

static void urpc_timing_wheel_stop(urpc_timing_wheel_t *tw)
{
    urpc_timer_t *timer = NULL;
    urpc_timer_t *next = NULL;

    urpc_timing_wheel_lock(tw);
    for (uint32_t level = 0; level < URPC_WHEEL_LEVEL_MAX; level++) {
        for (uint32_t slot = 0; slot < URPC_WHEEL_LEVEL_SIZE; slot++) {
            URPC_LIST_FOR_EACH_SAFE(timer, next, entry, &tw->slots[level][slot])
            {
                urpc_list_remove(&timer->entry);
                // resource need to be released in module uninit
                urpc_free_timer(timer);
            }
        }
    }
    urpc_timing_wheel_unlock(tw);
}

static void urpc_timer_fd_uninit(void)
{
    if (g_urpc_timing_wheel.timer_fd < 0) {
        return;
    }

    struct itimerspec time_cfg = {0};
    (void)timerfd_settime(g_urpc_timing_wheel.timer_fd, 0, &time_cfg, NULL);

    close(g_urpc_timing_wheel.timer_fd);
    g_urpc_timing_wheel.timer_fd = -1;
}

static int urpc_timer_fd_init(void)
{
    g_urpc_timing_wheel.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (g_urpc_timing_wheel.timer_fd < 0) {
        UTIL_LOG_ERR("create timer_fd failed, %s\n", strerror(errno));
        return URPC_FAIL;
    }

    struct itimerspec time_cfg;
    // initial value means start soon
    time_cfg.it_value.tv_sec = 0;
    time_cfg.it_value.tv_nsec = NS_PER_SEC / URPC_TIMING_WHEEL_HZ;
    // interval means timing wheel tick
    time_cfg.it_interval.tv_sec = 0;
    time_cfg.it_interval.tv_nsec = NS_PER_SEC / URPC_TIMING_WHEEL_HZ;

    if (timerfd_settime(g_urpc_timing_wheel.timer_fd, 0, &time_cfg, NULL) < 0) {
        UTIL_LOG_ERR("set timer_fd failed, %s\n", strerror(errno));
        goto CLOSE_TIMER_FD;
    }

    return URPC_SUCCESS;

CLOSE_TIMER_FD:
    close(g_urpc_timing_wheel.timer_fd);
    g_urpc_timing_wheel.timer_fd = -1;

    return URPC_FAIL;
}

static inline void urpc_timing_wheel_tick(uint32_t events, struct urpc_epoll_event *e)
{
    uint64_t timer_fd_readable = 0;
    int ret = read(g_urpc_timing_wheel.timer_fd, &timer_fd_readable, sizeof(uint64_t));
    if (URPC_UNLIKELY(ret != sizeof(uint64_t))) {
        UTIL_LOG_WARN("timer_fd readable event failed, ret %d, %s\n", ret, strerror(errno));
        return;
    }

    // timer_fd_readable is the number of timeout events
    for (uint64_t i = 0; i < timer_fd_readable; i++) {
        // timing wheel tick
        urpc_timer_process(g_urpc_timing_wheel.tw);
    }
}

int urpc_timing_wheel_init(void)
{
    // to avoid first call in x86 cost too much time, and lead to time errors in the first few cycles
    (void)urpc_get_cpu_hz();

    g_urpc_timing_wheel.tw = (urpc_timing_wheel_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_TIMEOUT,
        1, sizeof(urpc_timing_wheel_t));
    if (g_urpc_timing_wheel.tw == NULL) {
        return URPC_FAIL;
    }

    (void)pthread_spin_init(&g_urpc_timing_wheel.tw->lock, PTHREAD_PROCESS_PRIVATE);
    g_urpc_timing_wheel.tw->ticks = 0;
    g_urpc_timing_wheel.tw->ticks_pending = 0;
    for (uint32_t level = 0; level < URPC_WHEEL_LEVEL_MAX; level++) {
        g_urpc_timing_wheel.tw->cursors[level] = 0;
        for (uint32_t slot = 0; slot < URPC_WHEEL_LEVEL_SIZE; slot++) {
            urpc_list_init(&g_urpc_timing_wheel.tw->slots[level][slot]);
        }
    }

    if (urpc_timer_pool_init() != URPC_SUCCESS) {
        goto UNINIT_TIMING_WHEEL;
    }

    if (urpc_timer_fd_init() != URPC_SUCCESS) {
        goto UNINIT_TIMER_POOL;
    }

    g_urpc_timing_wheel.event.fd = g_urpc_timing_wheel.timer_fd;
    g_urpc_timing_wheel.event.args = NULL;
    g_urpc_timing_wheel.event.func = urpc_timing_wheel_tick;
    g_urpc_timing_wheel.event.events = EPOLLIN;
    if (urpc_mange_event_register(URPC_MANAGE_JOB_TYPE_LISTEN, &g_urpc_timing_wheel.event) != URPC_SUCCESS) {
        goto UNINIT_TIMER_FD;
    }

    UTIL_LOG_INFO("timing wheel init successful\n");
    return URPC_SUCCESS;

UNINIT_TIMER_FD:
    urpc_timer_fd_uninit();

UNINIT_TIMER_POOL:
    urpc_timer_pool_uninit();

UNINIT_TIMING_WHEEL:
    pthread_spin_destroy(&g_urpc_timing_wheel.tw->lock);
    urpc_dbuf_free(g_urpc_timing_wheel.tw);
    g_urpc_timing_wheel.tw = NULL;

    return URPC_FAIL;
}

void urpc_timing_wheel_uninit(void)
{
    if (g_urpc_timing_wheel.tw == NULL) {
        return;
    }

    urpc_timer_fd_uninit();

    urpc_timer_pool_uninit();

    urpc_timing_wheel_stop(g_urpc_timing_wheel.tw);
    pthread_spin_destroy(&g_urpc_timing_wheel.tw->lock);
    urpc_dbuf_free(g_urpc_timing_wheel.tw);
    g_urpc_timing_wheel.tw = NULL;
}

bool is_urpc_timer_running(urpc_timer_t *timer)
{
    if (URPC_UNLIKELY(timer == NULL || !urpc_check_timer_magic(timer))) {
        return false;
    }

    return timer->status == (uint8_t)URPC_TIMER_STAT_RUNNING;
}

urpc_timer_t *urpc_timer_create(uint32_t chid, bool is_server)
{
    urpc_timer_t *timer = urpc_timer_pool_get(chid, is_server);
    if (URPC_UNLIKELY(timer == NULL)) {
        UTIL_LOG_ERR("timer pool exhausted\n");
        return NULL;
    }

    timer->magic = URPC_TIMER_MAGIC_NUM;
    timer->entry.prev = NULL;
    timer->entry.next = NULL;
    timer->status = URPC_TIMER_STAT_INITED;
    timer->ticks = 0;
    timer->timeout = 0;

    return timer;
}

int urpc_timer_start(urpc_timer_t *timer, uint32_t timeout_ms, void (*func)(void *), void *args, bool periodic)
{
    if (URPC_UNLIKELY(timer == NULL || !urpc_check_timer_magic(timer))) {
        UTIL_LOG_ERR("start failed: timer has been freed or not inited\n");
        return URPC_FAIL;
    }

    // @args is permitted to be NULL
    if (URPC_UNLIKELY(func == NULL)) {
        UTIL_LOG_ERR("start failed: cb function is NULL\n");
        return URPC_FAIL;
    }

    if (URPC_UNLIKELY(timeout_ms < URPC_TIMER_MIN_DELAY || timeout_ms > URPC_TIMER_MAX_DELAY)) {
        UTIL_LOG_ERR("start failed: timeout %lu is out of range(%u ~ %u ms)\n", timeout_ms, URPC_TIMER_MIN_DELAY,
            URPC_TIMER_MAX_DELAY);
        return URPC_FAIL;
    }

    /* timer object should be protected, since the timer may have been added
       before and is running in the timing wheel */
    urpc_timing_wheel_lock(g_urpc_timing_wheel.tw);

    if (URPC_UNLIKELY(urpc_list_is_in_list(&timer->entry))) {
        urpc_list_remove(&timer->entry);
    }

    timer->args = args;
    timer->func = func;
    timer->timeout = timeout_ms;
    timer->ticks = urpc_time_ms_to_ticks(timeout_ms);
    // Generally, the timer starts at the middle of the ticks, and will stop at the very beginning of the end_ticks.
    // Therefore, we should plus 1 to the end_ticks to ensure the waiting time is longer than the preset value.
    timer->end_ticks = timer->ticks + g_urpc_timing_wheel.tw->ticks + g_urpc_timing_wheel.tw->ticks_pending + 1;
    timer->periodic = periodic;

    urpc_schedule_timer(g_urpc_timing_wheel.tw, timer);

    urpc_timing_wheel_version_update(g_urpc_timing_wheel.tw);
    urpc_timing_wheel_unlock(g_urpc_timing_wheel.tw);

    return URPC_SUCCESS;
}

int urpc_timer_restart(urpc_timer_t *timer)
{
    if (URPC_UNLIKELY(timer == NULL || !urpc_check_timer_magic(timer) || timer->ticks == 0)) {
        UTIL_LOG_ERR("restart failed: timer has been freed or not inited\n");
        return URPC_FAIL;
    }

    /* timer object should be protected, since the timer may have been added
       before and is running in the timing wheel */
    urpc_timing_wheel_lock(g_urpc_timing_wheel.tw);

    if (URPC_UNLIKELY(urpc_list_is_in_list(&timer->entry))) {
        urpc_list_remove(&timer->entry);
    }

    /* re-calculate the new end-ticks */
    timer->end_ticks = timer->ticks + g_urpc_timing_wheel.tw->ticks + g_urpc_timing_wheel.tw->ticks_pending;
    urpc_schedule_timer(g_urpc_timing_wheel.tw, timer);

    urpc_timing_wheel_version_update(g_urpc_timing_wheel.tw);
    urpc_timing_wheel_unlock(g_urpc_timing_wheel.tw);

    return URPC_SUCCESS;
}

static void urpc_timer_remove_from_timing_wheel_lockless(urpc_timer_t *timer)
{
    timer->magic = 0;  // 修改magic为0，防止被释放的timer重新入队
    if (urpc_list_is_in_list(&timer->entry)) {
        urpc_list_remove(&timer->entry);
        urpc_timing_wheel_version_update(g_urpc_timing_wheel.tw);
    }
}

static void urpc_timer_remove_from_timing_wheel(urpc_timer_t *timer)
{
    urpc_timing_wheel_lock(g_urpc_timing_wheel.tw);
    urpc_timer_remove_from_timing_wheel_lockless(timer);
    urpc_timing_wheel_unlock(g_urpc_timing_wheel.tw);
}

void urpc_timer_destroy(urpc_timer_t *timer)
{
    if (URPC_UNLIKELY(timer == NULL || !urpc_check_timer_magic(timer))) {
        UTIL_LOG_ERR("destroy failed: timer has been freed or not inited\n");
        return;
    }

    urpc_timing_wheel_lock(g_urpc_timing_wheel.tw);
    if (URPC_UNLIKELY(timer->status == URPC_TIMER_STAT_RUNNING)) {
        timer->periodic = false;
        urpc_timing_wheel_unlock(g_urpc_timing_wheel.tw);
        return;
    }

    urpc_timer_remove_from_timing_wheel_lockless(timer);
    urpc_timing_wheel_unlock(g_urpc_timing_wheel.tw);

    urpc_free_timer(timer);
}

void urpc_query_timer_info(uint32_t chid, bool is_server, uint64_t *stats, int stats_len)
{
    urpc_timer_key_t key;
    urpc_timer_key_fill(&key, chid, is_server);
    urpc_timer_pool_entry_t *entry = NULL;
    uint32_t key_hash = urpc_hash_bytes(&key, sizeof(urpc_timer_key_t), 0);

    pthread_spin_lock(&g_urpc_timing_wheel.p_lock);
    entry = urpc_timer_pool_entry_lookup(&key, key_hash);
    if (entry != NULL) {
        for (int i = 0; i < (int)TIMER_STATS_TYPE_MAX && i < stats_len; i++) {
            stats[i] = entry->stats[i];
        }
    }
    pthread_spin_unlock(&g_urpc_timing_wheel.p_lock);
}
