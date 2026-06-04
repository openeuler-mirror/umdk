/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond worker thread implementation
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "bondp_timewheel.h"
#include "ub_hash.h"
#include "ub_hmap.h"
#include "ub_util.h"
#include "urma_log.h"

#include "bondp_worker.h"

#define BONDP_WORKER_EVENT_NUM         (16)
#define BONDP_WORKER_HANDLER_MAP_SIZE  (64U)
#define BONDP_WORKER_MAX_ADVANCE_TICKS (64U)

typedef struct bondp_worker_event_handler {
    int fd;
    bondp_worker_event_fn_t handler;
    void *arg;
    bool deleting;
    uint32_t refcnt;
    struct ub_hmap_node hmap_node;
} bondp_worker_event_handler_t;

typedef struct bondp_worker {
    pthread_t thread;
    pthread_mutex_t lock;
    int epoll_fd;
    int wake_fd;
    bool running;
    uint64_t last_tick_ms;
    struct ub_hmap handler_map;
    tw_t *tw;
} bondp_worker_t;

static bondp_worker_t *bondp_worker = NULL;
static pthread_mutex_t bondp_worker_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t bondp_worker_event_hash(int fd)
{
    return ub_hash_bytes(&fd, sizeof(fd), 0);
}

static bondp_worker_event_handler_t *find_event_handler(bondp_worker_t *worker, int fd)
{
    bondp_worker_event_handler_t *entry = NULL;
    uint32_t hash = bondp_worker_event_hash(fd);

    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash, &worker->handler_map) {
        if (entry->fd == fd) {
            return entry;
        }
    }

    return NULL;
}

static int attach_event_handler(bondp_worker_t *worker, bondp_worker_event_handler_t *entry)
{
    struct epoll_event event = {
        .events = EPOLLIN,
        .data.fd = entry->fd,
    };

    if (find_event_handler(worker, entry->fd) != NULL) {
        return -EEXIST;
    }

    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, entry->fd, &event) != 0) {
        URMA_LOG_ERR("Failed to add fd %d to bond worker epoll, errno: %d.\n", entry->fd, errno);
        return -errno;
    }

    ub_hmap_insert(&worker->handler_map, &entry->hmap_node, bondp_worker_event_hash(entry->fd));
    return 0;
}

static int detach_event_handler(bondp_worker_t *worker, int fd)
{
    bondp_worker_event_handler_t *entry = find_event_handler(worker, fd);

    if (entry == NULL) {
        return -ENOENT;
    }

    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, entry->fd, NULL) != 0) {
        URMA_LOG_ERR("Failed to del fd %d from bond worker epoll, errno: %d.\n", entry->fd, errno);
        return -errno;
    }

    ub_hmap_remove(&worker->handler_map, &entry->hmap_node);
    entry->deleting = true;
    if (entry->refcnt == 0) {
        free(entry);
    }

    return 0;
}

static bondp_worker_event_handler_t *get_event_handler(bondp_worker_t *worker, int fd)
{
    bondp_worker_event_handler_t *entry = find_event_handler(worker, fd);

    if (entry == NULL || entry->deleting) {
        return NULL;
    }

    entry->refcnt++;
    return entry;
}

static void put_event_handler(bondp_worker_event_handler_t *entry)
{
    if (entry->refcnt == 0) {
        URMA_LOG_ERR("Bond worker event handler fd %d put without refs.\n", entry->fd);
        return;
    }

    entry->refcnt--;
    if (entry->deleting && entry->refcnt == 0) {
        free(entry);
    }
}

static void flush_event_handlers(bondp_worker_t *worker)
{
    bondp_worker_event_handler_t *entry = NULL;
    bondp_worker_event_handler_t *next = NULL;

    HMAP_FOR_EACH_SAFE (entry, next, hmap_node, &worker->handler_map) {
        ub_hmap_remove(&worker->handler_map, &entry->hmap_node);
        entry->deleting = true;
        free(entry);
    }
}

static uint64_t bondp_worker_now_ms(void)
{
    struct timespec ts = {0};

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        URMA_LOG_ERR("Failed to get bond worker monotonic time, errno: %d.\n", errno);
        return 0;
    }

    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int bondp_worker_get_wait_timeout_ms(bondp_worker_t *worker, uint64_t now_ms)
{
    uint32_t tick_ms = tw_get_tick_ms(worker->tw);
    uint64_t next_tick_ms = worker->last_tick_ms + tick_ms;

    if (tick_ms == 0 || now_ms >= next_tick_ms) {
        return 0;
    }

    return (int)(next_tick_ms - now_ms);
}

static void bondp_worker_advance_by_now(bondp_worker_t *worker)
{
    uint32_t tick_ms = tw_get_tick_ms(worker->tw);
    uint64_t now_ms = bondp_worker_now_ms();
    uint64_t tick_cnt;

    if (tick_ms == 0 || now_ms < worker->last_tick_ms + tick_ms) {
        return;
    }

    tick_cnt = (now_ms - worker->last_tick_ms) / tick_ms;
    tick_cnt = MIN(tick_cnt, BONDP_WORKER_MAX_ADVANCE_TICKS);
    worker->last_tick_ms += tick_cnt * tick_ms;
    tw_advance(worker->tw, tick_cnt);
}

static int bondp_worker_wakeup(bondp_worker_t *worker)
{
    uint64_t one = 1;
    ssize_t ret;

    do {
        ret = write(worker->wake_fd, &one, sizeof(one));
    } while (ret < 0 && errno == EINTR);

    if (ret == (ssize_t)sizeof(one) || (ret < 0 && errno == EAGAIN)) {
        return 0;
    }

    URMA_LOG_ERR("Failed to wake bond worker thread, errno: %d.\n", errno);
    return ret < 0 ? -errno : -EIO;
}

static void bondp_worker_drain_wakeup_fd(int wake_fd)
{
    uint64_t value;
    ssize_t ret;

    while (true) {
        ret = read(wake_fd, &value, sizeof(value));
        if (ret == (ssize_t)sizeof(value)) {
            continue;
        }
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
        break;
    }

    if (ret == 0) {
        URMA_LOG_WARN("Unexpected EOF while draining bond worker wake fd.\n");
        return;
    }

    URMA_LOG_WARN("Failed to drain bond worker wake fd, errno: %d.\n", errno);
}

static void bondp_worker_handle_epoll_event(bondp_worker_t *worker, int fd, uint32_t events)
{
    bondp_worker_event_handler_t *entry;

    if (fd == worker->wake_fd) {
        if ((events & EPOLLIN) != 0) {
            bondp_worker_drain_wakeup_fd(worker->wake_fd);
        }
        return;
    }

    if ((events & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) == 0) {
        return;
    }

    (void)pthread_mutex_lock(&worker->lock);
    entry = get_event_handler(worker, fd);
    if (entry == NULL) {
        (void)pthread_mutex_unlock(&worker->lock);
        return;
    }
    (void)pthread_mutex_unlock(&worker->lock);

    entry->handler(entry->arg);

    (void)pthread_mutex_lock(&worker->lock);
    put_event_handler(entry);
    (void)pthread_mutex_unlock(&worker->lock);
}

static void *bondp_worker_thread_main(void *arg)
{
    bondp_worker_t *worker = arg;
    struct epoll_event events[BONDP_WORKER_EVENT_NUM];

    while (true) {
        uint64_t now_ms = bondp_worker_now_ms();
        int timeout_ms = bondp_worker_get_wait_timeout_ms(worker, now_ms);
        int nfds = epoll_wait(worker->epoll_fd, events, BONDP_WORKER_EVENT_NUM, timeout_ms);

        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            URMA_LOG_ERR("Bond worker epoll_wait failed, errno: %d.\n", errno);
            (void)pthread_mutex_lock(&worker->lock);
            worker->running = false;
            (void)pthread_mutex_unlock(&worker->lock);
            break;
        }

        for (int i = 0; i < nfds; i++) {
            bondp_worker_handle_epoll_event(worker, events[i].data.fd, events[i].events);
        }

        (void)pthread_mutex_lock(&worker->lock);
        if (!worker->running) {
            (void)pthread_mutex_unlock(&worker->lock);
            break;
        }
        (void)pthread_mutex_unlock(&worker->lock);

        bondp_worker_advance_by_now(worker);
    }

    return NULL;
}

static bondp_worker_t *bondp_worker_create_instance(int *err_code)
{
    bondp_worker_t *worker;
    int ret;

    worker = calloc(1, sizeof(*worker));
    if (worker == NULL) {
        URMA_LOG_ERR("Failed to alloc bond worker.\n");
        *err_code = -ENOMEM;
        return NULL;
    }

    tw_cfg_t tw_cfg = {
        .tick_ms = TW_DEFAULT_TICK_MS,
        .slot_num = TW_DEFAULT_SLOT_NUM,
    };
    tw_t *tw = tw_create(&tw_cfg);
    if (tw == NULL) {
        *err_code = -ENOMEM;
        free(worker);
        return NULL;
    }

    worker->epoll_fd = -1;
    worker->wake_fd = -1;
    worker->tw = tw;

    ret = pthread_mutex_init(&worker->lock, NULL);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to init bond worker mutex, ret: %d.\n", ret);
        *err_code = -ret;
        goto ERR_TW;
    }

    if (ub_hmap_init(&worker->handler_map, BONDP_WORKER_HANDLER_MAP_SIZE) != 0) {
        URMA_LOG_ERR("Failed to init bond worker handler map.\n");
        *err_code = -ENOMEM;
        goto ERR_LOCK;
    }

    worker->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (worker->epoll_fd < 0) {
        URMA_LOG_ERR("Failed to create bond worker epoll fd, errno: %d.\n", errno);
        *err_code = -errno;
        goto ERR_MAP;
    }

    worker->wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (worker->wake_fd < 0) {
        URMA_LOG_ERR("Failed to create bond worker wake fd, errno: %d.\n", errno);
        *err_code = -errno;
        goto ERR_EPOLL;
    }

    struct epoll_event event = {
        .events = EPOLLIN,
        .data.fd = worker->wake_fd,
    };
    if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->wake_fd, &event) != 0) {
        URMA_LOG_ERR("Failed to add wake fd to bond worker epoll, errno: %d.\n", errno);
        *err_code = -errno;
        goto ERR_WAKE;
    }

    worker->last_tick_ms = bondp_worker_now_ms();
    worker->running = true;
    ret = pthread_create(&worker->thread, NULL, bondp_worker_thread_main, worker);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to create bond worker thread, ret: %d.\n", ret);
        *err_code = -ret;
        goto ERR_WAKE;
    }

    return worker;

ERR_WAKE:
    (void)close(worker->wake_fd);
ERR_EPOLL:
    (void)close(worker->epoll_fd);
ERR_MAP:
    ub_hmap_destroy(&worker->handler_map);
ERR_LOCK:
    (void)pthread_mutex_destroy(&worker->lock);
ERR_TW:
    tw_destroy(worker->tw);
    free(worker);
    return NULL;
}

int bondp_worker_create(void)
{
    bondp_worker_t *worker;
    int ret = 0;

    (void)pthread_mutex_lock(&bondp_worker_lock);
    if (bondp_worker != NULL) {
        URMA_LOG_ERR("Bond worker already created.\n");
        ret = -EEXIST;
        goto UNLOCK;
    }

    worker = bondp_worker_create_instance(&ret);
    if (worker == NULL) {
        goto UNLOCK;
    }

    bondp_worker = worker;
    ret = 0;

UNLOCK:
    (void)pthread_mutex_unlock(&bondp_worker_lock);
    return ret;
}

void bondp_worker_destroy(void)
{
    bondp_worker_t *worker;

    (void)pthread_mutex_lock(&bondp_worker_lock);
    worker = bondp_worker;
    if (worker == NULL) {
        (void)pthread_mutex_unlock(&bondp_worker_lock);
        return;
    }
    /*
     * Destroy is only called after external users have stopped accessing the
     * worker, so clearing the global pointer here is enough to prevent later
     * accidental reuse during teardown.
     */
    bondp_worker = NULL;

    (void)pthread_mutex_lock(&worker->lock);
    worker->running = false;
    (void)pthread_mutex_unlock(&worker->lock);
    (void)bondp_worker_wakeup(worker);

    (void)pthread_join(worker->thread, NULL);

    if (worker->wake_fd >= 0) {
        (void)close(worker->wake_fd);
    }
    if (worker->epoll_fd >= 0) {
        (void)close(worker->epoll_fd);
    }
    (void)pthread_mutex_lock(&worker->lock);
    flush_event_handlers(worker);
    (void)pthread_mutex_unlock(&worker->lock);
    ub_hmap_destroy(&worker->handler_map);
    (void)pthread_mutex_destroy(&worker->lock);
    tw_destroy(worker->tw);
    free(worker);
    (void)pthread_mutex_unlock(&bondp_worker_lock);
}

int bondp_worker_schedule(uint64_t delay_ms, bondp_worker_task_fn_t fn, void *arg, bondp_worker_task_id_t *task_id)
{
    bondp_worker_t *worker = bondp_worker;
    int ret = 0;

    if (worker == NULL) {
        return -ENODEV;
    }

    (void)pthread_mutex_lock(&worker->lock);
    ret = worker->running ? 0 : -EIO;
    (void)pthread_mutex_unlock(&worker->lock);
    if (ret != 0) {
        return ret;
    }

    ret = tw_schedule(worker->tw, delay_ms, fn, arg, task_id);
    if (ret == 0) {
        (void)bondp_worker_wakeup(worker);
    }

    return ret;
}

int bondp_worker_cancel(bondp_worker_task_id_t task_id)
{
    bondp_worker_t *worker = bondp_worker;
    int ret = 0;

    if (worker == NULL) {
        return -ENODEV;
    }

    (void)pthread_mutex_lock(&worker->lock);
    ret = worker->running ? 0 : -EIO;
    (void)pthread_mutex_unlock(&worker->lock);
    if (ret != 0) {
        return ret;
    }

    ret = tw_cancel(worker->tw, task_id);
    if (ret == 0) {
        (void)bondp_worker_wakeup(worker);
    }

    return ret;
}

int bondp_worker_add_fd(int fd, bondp_worker_event_fn_t handler, void *arg)
{
    bondp_worker_t *worker = bondp_worker;
    int ret = 0;

    if (fd < 0 || handler == NULL) {
        return -EINVAL;
    }

    bondp_worker_event_handler_t *entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        URMA_LOG_ERR("Failed to alloc bond worker event handler.\n");
        return -ENOMEM;
    }

    entry->fd = fd;
    entry->handler = handler;
    entry->arg = arg;

    if (worker == NULL) {
        ret = -ENODEV;
        goto FREE_ENTRY;
    }

    (void)pthread_mutex_lock(&worker->lock);
    ret = worker->running ? 0 : -EIO;
    if (ret != 0) {
        goto UNLOCK_WORKER;
    }
    ret = attach_event_handler(worker, entry);
    if (ret != 0) {
        goto UNLOCK_WORKER;
    }

UNLOCK_WORKER:
    (void)pthread_mutex_unlock(&worker->lock);
    if (ret != 0) {
        goto FREE_ENTRY;
    }

    (void)bondp_worker_wakeup(worker);
    return 0;

FREE_ENTRY:
    free(entry);
    return ret;
}

int bondp_worker_del_fd(int fd)
{
    bondp_worker_t *worker = bondp_worker;
    int ret = 0;

    if (fd < 0) {
        return -EINVAL;
    }

    if (worker == NULL) {
        return -ENODEV;
    }

    (void)pthread_mutex_lock(&worker->lock);
    ret = worker->running ? 0 : -EIO;
    if (ret != 0) {
        goto UNLOCK_WORKER;
    }
    ret = detach_event_handler(worker, fd);
    if (ret != 0) {
        goto UNLOCK_WORKER;
    }

UNLOCK_WORKER:
    (void)pthread_mutex_unlock(&worker->lock);
    if (ret != 0) {
        return ret;
    }

    (void)bondp_worker_wakeup(worker);
    return 0;
}
