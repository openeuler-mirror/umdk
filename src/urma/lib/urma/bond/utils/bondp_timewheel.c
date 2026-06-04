/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Timing wheel implementation
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "ub_hash.h"
#include "ub_hmap.h"
#include "ub_util.h"
#include "urma_log.h"

#include "bondp_timewheel.h"

#define TW_HMAP_MIN_SIZE (1024U)

typedef struct tw_task {
    tw_task_id_t task_id;
    uint64_t round;
    uint32_t slot_idx;
    tw_task_fn_t fn;
    void *arg;
    TAILQ_ENTRY(tw_task)
    slot_entry;
    struct ub_hmap_node hmap_node;
} tw_task_t;

TAILQ_HEAD(tw_task_head, tw_task);

typedef struct tw_slot {
    struct tw_task_head tasks;
} tw_slot_t;

struct tw {
    pthread_mutex_t lock;
    uint32_t tick_ms;
    uint32_t slot_num;
    uint64_t current_tick;
    uint64_t next_task_id;
    struct ub_hmap task_map;
    tw_slot_t *slots;
};

static uint32_t tw_task_hash(tw_task_id_t task_id)
{
    return ub_hash_bytes(&task_id, sizeof(task_id), 0);
}

static tw_task_t *tw_lookup_task(tw_t *tw, tw_task_id_t task_id)
{
    tw_task_t *task = NULL;
    uint32_t hash = tw_task_hash(task_id);

    HMAP_FOR_EACH_WITH_HASH (task, hmap_node, hash, &tw->task_map) {
        if (task->task_id == task_id) {
            return task;
        }
    }

    return NULL;
}

static void tw_task_free(tw_task_t *task)
{
    free(task);
}

static void tw_process_tick(tw_t *tw)
{
    struct tw_task_head due_tasks;
    tw_task_t *task = NULL;
    tw_task_t *next = NULL;
    uint32_t slot_idx;

    TAILQ_INIT(&due_tasks);

    (void)pthread_mutex_lock(&tw->lock);
    tw->current_tick++;
    slot_idx = (uint32_t)(tw->current_tick % tw->slot_num);
    task = TAILQ_FIRST(&tw->slots[slot_idx].tasks);
    while (task != NULL) {
        next = TAILQ_NEXT(task, slot_entry);
        if (task->round > 0) {
            task->round--;
            task = next;
            continue;
        }

        TAILQ_REMOVE(&tw->slots[slot_idx].tasks, task, slot_entry);
        ub_hmap_remove(&tw->task_map, &task->hmap_node);
        TAILQ_INSERT_TAIL(&due_tasks, task, slot_entry);
        task = next;
    }
    (void)pthread_mutex_unlock(&tw->lock);

    while ((task = TAILQ_FIRST(&due_tasks)) != NULL) {
        TAILQ_REMOVE(&due_tasks, task, slot_entry);
        task->fn(task->arg);
        tw_task_free(task);
    }
}

static int tw_init_slots(tw_t *tw)
{
    uint32_t i;

    tw->slots = calloc(tw->slot_num, sizeof(*tw->slots));
    if (tw->slots == NULL) {
        URMA_LOG_ERR("Failed to alloc timing wheel slots.\n");
        return -ENOMEM;
    }

    for (i = 0; i < tw->slot_num; i++) {
        TAILQ_INIT(&tw->slots[i].tasks);
    }

    return 0;
}

static int tw_init_task_map(tw_t *tw)
{
    uint32_t hmap_size = MAX(TW_HMAP_MIN_SIZE, tw->slot_num * 2U);

    if (ub_hmap_init(&tw->task_map, hmap_size) != 0) {
        URMA_LOG_ERR("Failed to init timing wheel task map.\n");
        return -ENOMEM;
    }

    return 0;
}

tw_t *tw_create(const tw_cfg_t *cfg)
{
    tw_t *tw = NULL;
    uint32_t tick_ms;
    uint32_t slot_num;
    int ret;

    if (cfg == NULL) {
        URMA_LOG_ERR("Invalid timing wheel config, cfg is NULL.\n");
        return NULL;
    }

    tick_ms = cfg->tick_ms == 0 ? TW_DEFAULT_TICK_MS : cfg->tick_ms;
    slot_num = cfg->slot_num == 0 ? TW_DEFAULT_SLOT_NUM : cfg->slot_num;
    if (tick_ms == 0 || slot_num == 0) {
        URMA_LOG_ERR("Invalid timing wheel config, tick_ms: %u, slot_num: %u.\n", tick_ms, slot_num);
        return NULL;
    }

    tw = calloc(1, sizeof(*tw));
    if (tw == NULL) {
        URMA_LOG_ERR("Failed to alloc timing wheel.\n");
        return NULL;
    }

    tw->tick_ms = tick_ms;
    tw->slot_num = slot_num;
    tw->next_task_id = 1;

    ret = pthread_mutex_init(&tw->lock, NULL);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to init timing wheel mutex, ret: %d.\n", ret);
        free(tw);
        return NULL;
    }

    ret = tw_init_slots(tw);
    if (ret != 0) {
        goto err_mutex;
    }

    ret = tw_init_task_map(tw);
    if (ret != 0) {
        goto err_slots;
    }

    return tw;
err_slots:
    free(tw->slots);
err_mutex:
    (void)pthread_mutex_destroy(&tw->lock);
    free(tw);
    return NULL;
}

void tw_destroy(tw_t *tw)
{
    tw_task_t *task = NULL;
    tw_task_t *next = NULL;

    if (tw == NULL) {
        return;
    }

    HMAP_FOR_EACH_SAFE (task, next, hmap_node, &tw->task_map) {
        ub_hmap_remove(&tw->task_map, &task->hmap_node);
        free(task);
    }

    ub_hmap_destroy(&tw->task_map);
    free(tw->slots);
    (void)pthread_mutex_destroy(&tw->lock);
    free(tw);
}

int tw_schedule(tw_t *tw, uint64_t delay_ms, tw_task_fn_t fn, void *arg, tw_task_id_t *task_id)
{
    tw_task_t *task = NULL;
    tw_task_id_t new_task_id;
    uint64_t delay_tick;
    uint64_t expire_tick;
    if (tw == NULL || fn == NULL || task_id == NULL) {
        URMA_LOG_ERR("Invalid param when scheduling timing wheel task.\n");
        return -EINVAL;
    }

    task = calloc(1, sizeof(*task));
    if (task == NULL) {
        URMA_LOG_ERR("Failed to alloc timing wheel task.\n");
        return -ENOMEM;
    }

    delay_tick = delay_ms == 0 ? 0 : 1 + (delay_ms - 1) / tw->tick_ms;
    if (delay_tick == 0) {
        delay_tick = 1;
    }

    (void)pthread_mutex_lock(&tw->lock);
    new_task_id = tw->next_task_id++;
    task->task_id = new_task_id;
    task->fn = fn;
    task->arg = arg;
    expire_tick = tw->current_tick + delay_tick;
    task->slot_idx = (uint32_t)(expire_tick % tw->slot_num);
    task->round = (delay_tick - 1U) / tw->slot_num;
    ub_hmap_insert(&tw->task_map, &task->hmap_node, tw_task_hash(task->task_id));
    TAILQ_INSERT_TAIL(&tw->slots[task->slot_idx].tasks, task, slot_entry);
    *task_id = task->task_id;
    (void)pthread_mutex_unlock(&tw->lock);
    return 0;
}

int tw_cancel(tw_t *tw, tw_task_id_t task_id)
{
    tw_task_t *task = NULL;
    int ret = 0;

    if (tw == NULL || task_id == 0) {
        URMA_LOG_ERR("Invalid param when canceling timing wheel task.\n");
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&tw->lock);
    task = tw_lookup_task(tw, task_id);
    if (task == NULL) {
        ret = -ENOENT;
        goto out_unlock;
    }

    TAILQ_REMOVE(&tw->slots[task->slot_idx].tasks, task, slot_entry);
    ub_hmap_remove(&tw->task_map, &task->hmap_node);
    tw_task_free(task);

out_unlock:
    (void)pthread_mutex_unlock(&tw->lock);
    return ret;
}

uint32_t tw_get_tick_ms(const tw_t *tw)
{
    if (tw == NULL) {
        return 0;
    }

    return tw->tick_ms;
}

void tw_advance(tw_t *tw, uint64_t tick_cnt)
{
    uint64_t i;

    if (tw == NULL || tick_cnt == 0) {
        return;
    }

    for (i = 0; i < tick_cnt; i++) {
        tw_process_tick(tw);
    }
}
