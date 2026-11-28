/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider cold/hot standby pjetty manager
 *
 * A single process-wide thread owns all transitions between HOT, COLD and
 * FAULTY pjettys of active_backup bonding jettys. Data path and health check
 * only post events; every p_jetty[] mutation and WR migration happens here,
 * serialized with the data path through comp->send_lock.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "ub_hmap.h"
#include "ub_list.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"
#include "urma_types.h"
#include "urma_ubagg.h"

#include "bondp_context_table.h"
#include "bondp_datapath.h"
#include "bondp_hash_table.h"
#include "bondp_types.h"

#include "bondp_cp_coldhot.h"

typedef enum bondp_coldhot_ev_type {
    BONDP_COLDHOT_EV_FAULT = 0,
    BONDP_COLDHOT_EV_FAILBACK,
    BONDP_COLDHOT_EV_RECONCILE,
} bondp_coldhot_ev_type_t;

typedef struct bondp_coldhot_event {
    struct ub_list node;
    bondp_coldhot_ev_type_t type;
    bondp_context_t *bdp_ctx;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
} bondp_coldhot_event_t;

static pthread_mutex_t g_coldhot_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_coldhot_cond = PTHREAD_COND_INITIALIZER;
/* Bounded wait for in-flight WRs to report their SUSPEND/FLUSH fake CRs
 * before a pjetty is deleted (flush/drain). */
#define BONDP_COLDHOT_DRAIN_TIMEOUT_MS 1000

static struct ub_list g_coldhot_events = UB_LIST_INITIALIZER(&g_coldhot_events);
static bool g_coldhot_list_inited = false;
static bool g_coldhot_running = false;
static bool g_coldhot_started = false;
static pthread_t g_coldhot_thread;
/* Signaled when the manager finishes the event it is currently processing. */
static pthread_cond_t g_coldhot_idle_cond = PTHREAD_COND_INITIALIZER;
/* Context of the event being processed now (protected by g_coldhot_lock). */
static bondp_context_t *g_coldhot_processing_ctx = NULL;

/* ------------------------------------------------------------------------- */
/* pjetty state helpers (all callers not holding send_lock use the atomic API) */

static inline int pjetty_state(const bondp_comp_t *comp, uint32_t idx)
{
    return atomic_load(&comp->pjetty_state[idx]);
}

static inline void pjetty_set_state(bondp_comp_t *comp, uint32_t idx, bondp_pjetty_state_t state)
{
    atomic_store(&comp->pjetty_state[idx], (int)state);
}

bool bondp_coldhot_has_cold(const bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return false;
    }
    for (uint32_t n = 0; n < bdp_comp->enabled_count; ++n) {
        uint32_t idx = bdp_comp->enabled_indices[n];
        if (idx >= URMA_UBAGG_DEV_MAX_NUM) {
            continue;
        }
        if (pjetty_state(bdp_comp, idx) == BONDP_PJETTY_COLD &&
            !atomic_load(&bdp_comp->bondp_ctx->port_status_bad[idx])) {
            return true;
        }
    }
    return false;
}

static uint32_t pjetty_priority(const bondp_comp_t *bdp_comp, uint32_t idx)
{
    for (uint32_t n = 0; n < bdp_comp->enabled_count; ++n) {
        if (bdp_comp->enabled_indices[n] == idx) {
            return n;
        }
    }
    return UINT32_MAX;
}

static uint32_t count_hot(const bondp_comp_t *bdp_comp)
{
    uint32_t cnt = 0;
    for (uint32_t n = 0; n < bdp_comp->enabled_count; ++n) {
        uint32_t idx = bdp_comp->enabled_indices[n];
        if (idx < URMA_UBAGG_DEV_MAX_NUM && pjetty_state(bdp_comp, idx) == BONDP_PJETTY_HOT) {
            cnt++;
        }
    }
    return cnt;
}

static int first_cold(const bondp_comp_t *bdp_comp)
{
    for (uint32_t n = 0; n < bdp_comp->enabled_count; ++n) {
        uint32_t idx = bdp_comp->enabled_indices[n];
        if (idx < URMA_UBAGG_DEV_MAX_NUM && pjetty_state(bdp_comp, idx) == BONDP_PJETTY_COLD &&
            !atomic_load(&bdp_comp->bondp_ctx->port_status_bad[idx])) {
            return (int)idx;
        }
    }
    return -1;
}

static int lowest_hot(const bondp_comp_t *bdp_comp)
{
    int found = -1;
    for (uint32_t n = 0; n < bdp_comp->enabled_count; ++n) {
        uint32_t idx = bdp_comp->enabled_indices[n];
        if (idx < URMA_UBAGG_DEV_MAX_NUM && pjetty_state(bdp_comp, idx) == BONDP_PJETTY_HOT) {
            found = (int)idx; /* keep scanning: later entries have lower priority */
        }
    }
    return found;
}

/* ------------------------------------------------------------------------- */
/* comp lookup / pjetty create & delete                                      */

/* Look the component up by vjetty id in the context-level vjetty registry (not
 * the pjetty-id table, which is empty once a vjetty loses all its pjettys) and
 * take a use_cnt reference under the registry lock. A concurrent delete takes
 * the same lock for write, so it cannot free the comp until we drop the ref.
 * Mirrors get_comp_by_cr(): the caller must call put_comp_ref() when done. */
static bondp_comp_t *get_comp_ref(bondp_context_t *bdp_ctx, uint32_t vjetty_id)
{
    if (bdp_ctx == NULL) {
        return NULL;
    }
    bondp_comp_t *found = NULL;
    bondp_comp_t *iter = NULL;
    pthread_rwlock_rdlock(&bdp_ctx->vjetty_list_lock);
    UB_LIST_FOR_EACH (iter, vjetty_node, &bdp_ctx->vjetty_list) {
        if (iter->v_jetty.jetty_id.id != vjetty_id) {
            continue;
        }
        found = iter;
        atomic_fetch_add(&found->use_cnt.atomic_cnt, 1);
        break;
    }
    pthread_rwlock_unlock(&bdp_ctx->vjetty_list_lock);

    if (found != NULL && atomic_load(&found->deleting)) {
        atomic_fetch_sub(&found->use_cnt.atomic_cnt, 1);
        return NULL;
    }
    return found;
}

static inline void put_comp_ref(bondp_comp_t *comp)
{
    if (comp != NULL) {
        atomic_fetch_sub(&comp->use_cnt.atomic_cnt, 1);
    }
}

static int build_pjetty_cfg(bondp_comp_t *comp, uint32_t idx, urma_jetty_cfg_t *p_cfg)
{
    bondp_context_t *bdp_ctx = comp->bondp_ctx;
    urma_jetty_cfg_t *v_cfg = &comp->v_jetty.jetty_cfg;

    if (v_cfg->jfs_cfg.jfc == NULL || v_cfg->shared.jfr == NULL) {
        return -1;
    }

    *p_cfg = *v_cfg;
    bondp_jfc_t *bdp_jfs_jfc = CONTAINER_OF_FIELD(v_cfg->jfs_cfg.jfc, bondp_jfc_t, v_jfc);
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(v_cfg->shared.jfr, bondp_comp_t, base);
    p_cfg->jfs_cfg.jfc = bdp_jfs_jfc->p_jfc[idx];
    p_cfg->shared.jfr = bdp_jfr->p_jfr[idx];
    if (comp->has_rplc_jfc && v_cfg->shared.jfc != NULL) {
        bondp_jfc_t *bdp_rplc_jfc = CONTAINER_OF_FIELD(v_cfg->shared.jfc, bondp_jfc_t, v_jfc);
        p_cfg->shared.jfc = bdp_rplc_jfc->p_jfc[idx];
    } else {
        p_cfg->shared.jfc = NULL;
    }
    if (bdp_ctx->bonding_level == BONDP_BONDING_LEVEL_PORT) {
        p_cfg->id = 0;
    }
    return 0;
}

static int add_pjetty_mapping(bondp_comp_t *comp, urma_jetty_id_t id)
{
    bondp_context_t *bdp_ctx = comp->bondp_ctx;

    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    int ret = bdp_p_vjetty_id_table_add_without_lock(&bdp_ctx->p_vjetty_id_table, id, JETTY,
                                                     comp->v_jetty.jetty_id.id, comp);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    if (ret == BONDP_HASH_MAP_COLLIDE_ERROR &&
        comp->v_jetty.jetty_id.id > 0 && comp->v_jetty.jetty_id.id < BONDP_MAX_WELL_KNOWN_JETTY_ID) {
        return 0;
    }
    return ret == 0 ? 0 : -1;
}

static void del_pjetty_mapping(bondp_comp_t *comp, urma_jetty_id_t id)
{
    bondp_context_t *bdp_ctx = comp->bondp_ctx;

    pthread_rwlock_wrlock(&bdp_ctx->p_vjetty_id_table.lock);
    (void)bdp_p_vjetty_id_table_del_without_lock(&bdp_ctx->p_vjetty_id_table, id, JETTY);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
}

/* Create the physical pjetty at idx and publish it as HOT. Caller must not hold
 * send_lock (urma_create_jetty may sleep). */
static int create_pjetty(bondp_comp_t *comp, uint32_t idx)
{
    bondp_context_t *bdp_ctx = comp->bondp_ctx;
    urma_jetty_cfg_t p_cfg;

    if (idx >= URMA_UBAGG_DEV_MAX_NUM || bdp_ctx->p_ctxs[idx] == NULL) {
        return -1;
    }
    if (build_pjetty_cfg(comp, idx, &p_cfg) != 0) {
        return -1;
    }

    urma_jetty_t *jetty = urma_create_jetty(bdp_ctx->p_ctxs[idx], &p_cfg);
    if (jetty == NULL) {
        URMA_LOG_ERR("Failed to create cold/hot pjetty, vjetty_id=%u, idx=%u.\n",
                     comp->v_jetty.jetty_id.id, idx);
        return -1;
    }
    jetty->jetty_cfg.user_ctx = (uint64_t)comp;

    if (add_pjetty_mapping(comp, jetty->jetty_id) != 0) {
        (void)urma_delete_jetty(jetty);
        return -1;
    }

    pthread_spin_lock(&comp->send_lock);
    comp->p_jetty[idx] = jetty;
    comp->pjettys_error_done[idx] = 0;
    atomic_store(&comp->valid[idx], true);
    pjetty_set_state(comp, idx, BONDP_PJETTY_HOT);
    pthread_spin_unlock(&comp->send_lock);

    URMA_LOG_WARN("Cold/hot pjetty created, vjetty_id=%u, idx=%u, jetty_id=%u.\n",
                  comp->v_jetty.jetty_id.id, idx, jetty->jetty_id.id);
    return 0;
}

/* Remove the physical pjetty at idx (if any). The pointer is cleared under
 * send_lock first so the data path never dereferences a deleted jetty; the
 * actual delete and the id-mapping removal run afterwards. */
static void delete_pjetty(bondp_comp_t *comp, uint32_t idx)
{
    const uint8_t need = PJETTY_SUSPEND_DONE | PJETTY_FLUSH_ERROR_DONE;
    urma_jetty_attr_t attr = {0};
    urma_jetty_t *old;
    int wait;

    if (idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return;
    }

    pthread_spin_lock(&comp->send_lock);
    old = comp->p_jetty[idx];
    comp->p_jetty[idx] = NULL;
    atomic_store(&comp->valid[idx], false);
    pthread_spin_unlock(&comp->send_lock);

    if (old == NULL) {
        return;
    }

    /* Flush and drain: trigger the hardware to report SUSPEND/FLUSH fake CRs
     * for every in-flight WR, and wait (bounded) for handle_fake_cr_with_store
     * to record them. Only then drop the id mapping and delete the jetty, so no
     * CR is left pointing at a removed local jetty.
     */
    attr.mask = JETTY_STATE;
    attr.state = URMA_JETTY_STATE_ERROR;
    (void)urma_modify_jetty(old, &attr);
    for (wait = 0; wait < BONDP_COLDHOT_DRAIN_TIMEOUT_MS; wait++) {
        if ((comp->pjettys_error_done[idx] & need) == need)
            break;
        (void)usleep(1000);
    }
    if (wait >= BONDP_COLDHOT_DRAIN_TIMEOUT_MS)
        URMA_LOG_WARN("Cold/hot pjetty drain timeout, vjetty_id=%u, idx=%u.\n",
                      comp->v_jetty.jetty_id.id, idx);

    del_pjetty_mapping(comp, old->jetty_id);
    if (urma_delete_jetty(old) != URMA_SUCCESS)
        URMA_LOG_WARN("Failed to delete cold/hot pjetty, vjetty_id=%u, idx=%u.\n",
                      comp->v_jetty.jetty_id.id, idx);
    URMA_LOG_DEBUG("Cold/hot pjetty drained and deleted, vjetty_id=%u, idx=%u.\n",
                   comp->v_jetty.jetty_id.id, idx);
}

int bondp_coldhot_activate_cold(bondp_comp_t *bdp_comp, uint32_t pjetty_idx)
{
    if (bdp_comp == NULL || pjetty_idx >= URMA_UBAGG_DEV_MAX_NUM) {
        return -1;
    }
    if (pjetty_state(bdp_comp, pjetty_idx) != BONDP_PJETTY_COLD) {
        return -1;
    }
    if (bdp_comp->p_jetty[pjetty_idx] == NULL) {
        return create_pjetty(bdp_comp, pjetty_idx);
    }
    pthread_spin_lock(&bdp_comp->send_lock);
    atomic_store(&bdp_comp->valid[pjetty_idx], true);
    pjetty_set_state(bdp_comp, pjetty_idx, BONDP_PJETTY_HOT);
    pthread_spin_unlock(&bdp_comp->send_lock);
    return 0;
}

static void demote_hot(bondp_comp_t *comp, uint32_t idx)
{
    if (pjetty_state(comp, idx) != BONDP_PJETTY_HOT)
        return;

    /* Stop new sends, park the in-flight WRs so they can be replayed on the
     * remaining/new HOT, then flush/drain and delete the physical pjetty. A
     * COLD slot holds no jetty instance. */
    pthread_spin_lock(&comp->send_lock);
    atomic_store(&comp->valid[idx], false);
    pjetty_set_state(comp, idx, BONDP_PJETTY_COLD);
    pthread_spin_unlock(&comp->send_lock);
    bondp_coldhot_pending_idx(comp, idx);
    delete_pjetty(comp, idx);
}

/* ------------------------------------------------------------------------- */
/* Event processing                                                          */

static void process_fault(bondp_coldhot_event_t *ev)
{
    bondp_comp_t *comp = get_comp_ref(ev->bdp_ctx, ev->vjetty_id);
    if (comp == NULL) {
        return;
    }
    /* Health fan-out may enqueue several faults for the same slot; only the
     * HOT one is meaningful. */
    if (ev->pjetty_idx >= URMA_UBAGG_DEV_MAX_NUM ||
        pjetty_state(comp, ev->pjetty_idx) != BONDP_PJETTY_HOT) {
        goto OUT;
    }
    /* Mark FAULTY first so count_hot()/promotion never counts a slot whose
     * p_jetty is being torn down, then flush/drain and delete. */
    pjetty_set_state(comp, ev->pjetty_idx, BONDP_PJETTY_FAULTY);
    delete_pjetty(comp, ev->pjetty_idx);

    if (!bondp_coldhot_active(comp)) {
        goto OUT;
    }

    if (count_hot(comp) < bondp_coldhot_effective_cnt(comp)) {
        int cand = first_cold(comp);
        if (cand >= 0 && bondp_coldhot_activate_cold(comp, (uint32_t)cand) == 0) {
            bondp_coldhot_replay_pending(comp);
        }
    }
OUT:
    put_comp_ref(comp);
}

static void process_failback(bondp_coldhot_event_t *ev)
{
    bondp_comp_t *comp = get_comp_ref(ev->bdp_ctx, ev->vjetty_id);
    if (comp == NULL || !bondp_coldhot_active(comp)) {
        put_comp_ref(comp);
        return;
    }
    uint32_t cand = ev->pjetty_idx;
    if (cand >= URMA_UBAGG_DEV_MAX_NUM) {
        goto OUT;
    }
    /* Never create a HOT pjetty for a port outside this vjetty's enabled set. */
    if (pjetty_priority(comp, cand) == UINT32_MAX) {
        goto OUT;
    }
    if (pjetty_state(comp, cand) == BONDP_PJETTY_HOT) {
        goto OUT;
    }
    if (pjetty_state(comp, cand) == BONDP_PJETTY_FAULTY) {
        pjetty_set_state(comp, cand, BONDP_PJETTY_COLD);
    }
    if (pjetty_state(comp, cand) != BONDP_PJETTY_COLD) {
        goto OUT;
    }

    int low = -1;
    if (count_hot(comp) >= bondp_coldhot_effective_cnt(comp)) {
        int l = lowest_hot(comp);
        if (l < 0) {
            goto OUT;
        }
        /* Only swap when the recovered pjetty has strictly higher priority. */
        if (pjetty_priority(comp, cand) >= pjetty_priority(comp, (uint32_t)l)) {
            goto OUT;
        }
        low = l;
    }

    /* Activate the recovered (higher-priority) pjetty first; the transient
     * extra HOT is acceptable. Then migrate the demoted HOT's in-flight WRs
     * onto the new HOT and drop the demoted pjetty (flush/drain + delete). */
    if (bondp_coldhot_activate_cold(comp, cand) != 0) {
        goto OUT;
    }
    if (low >= 0) {
        demote_hot(comp, (uint32_t)low);
    }
    bondp_coldhot_replay_pending(comp);
OUT:
    put_comp_ref(comp);
}

static void process_reconcile(bondp_coldhot_event_t *ev)
{
    bondp_comp_t *comp = get_comp_ref(ev->bdp_ctx, ev->vjetty_id);
    if (comp == NULL) {
        return;
    }

    uint32_t target = bondp_coldhot_effective_cnt(comp);
    uint32_t hot = count_hot(comp);
    while (hot > target) {
        int low = lowest_hot(comp);
        if (low < 0) {
            break;
        }
        demote_hot(comp, (uint32_t)low);
        hot--;
    }
    while (hot < target) {
        int cand = first_cold(comp);
        if (cand < 0) {
            break;
        }
        if (bondp_coldhot_activate_cold(comp, (uint32_t)cand) != 0) {
            break;
        }
        hot++;
    }
    bondp_coldhot_replay_pending(comp);
    put_comp_ref(comp);
}

static void process_event(bondp_coldhot_event_t *ev)
{
    switch (ev->type) {
        case BONDP_COLDHOT_EV_FAULT:
            process_fault(ev);
            break;
        case BONDP_COLDHOT_EV_FAILBACK:
            process_failback(ev);
            break;
        case BONDP_COLDHOT_EV_RECONCILE:
            process_reconcile(ev);
            break;
        default:
            break;
    }
}

/* ------------------------------------------------------------------------- */
/* Thread + event queue                                                      */

static void *coldhot_thread_main(void *arg)
{
    (void)arg;

    for (;;) {
        pthread_mutex_lock(&g_coldhot_lock);
        while (g_coldhot_running && ub_list_is_empty(&g_coldhot_events)) {
            (void)pthread_cond_wait(&g_coldhot_cond, &g_coldhot_lock);
        }
        if (!g_coldhot_running) {
            pthread_mutex_unlock(&g_coldhot_lock);
            break;
        }
        bondp_coldhot_event_t *ev = (bondp_coldhot_event_t *)ub_list_pop_front(&g_coldhot_events);
        /* Publish the in-flight context under the lock so cancel_ctx() can wait
         * for the manager to leave this context before tearing it down. */
        g_coldhot_processing_ctx = ev->bdp_ctx;
        pthread_mutex_unlock(&g_coldhot_lock);

        process_event(ev);

        pthread_mutex_lock(&g_coldhot_lock);
        g_coldhot_processing_ctx = NULL;
        (void)pthread_cond_broadcast(&g_coldhot_idle_cond);
        pthread_mutex_unlock(&g_coldhot_lock);
        free(ev);
    }
    return NULL;
}

int bondp_coldhot_start(void)
{
    int ret = 0;

    pthread_mutex_lock(&g_coldhot_lock);
    if (g_coldhot_running) {
        pthread_mutex_unlock(&g_coldhot_lock);
        return 0;
    }
    if (!g_coldhot_list_inited) {
        ub_list_init(&g_coldhot_events);
        g_coldhot_list_inited = true;
    }
    g_coldhot_running = true;
    ret = pthread_create(&g_coldhot_thread, NULL, coldhot_thread_main, NULL);
    if (ret != 0) {
        g_coldhot_running = false;
        pthread_mutex_unlock(&g_coldhot_lock);
        URMA_LOG_ERR("Failed to create cold/hot manager thread, ret=%d.\n", ret);
        return -ret;
    }
    g_coldhot_started = true;
    pthread_mutex_unlock(&g_coldhot_lock);
    return 0;
}

void bondp_coldhot_stop(void)
{
    pthread_mutex_lock(&g_coldhot_lock);
    if (!g_coldhot_started) {
        pthread_mutex_unlock(&g_coldhot_lock);
        return;
    }
    g_coldhot_running = false;
    (void)pthread_cond_broadcast(&g_coldhot_cond);
    pthread_mutex_unlock(&g_coldhot_lock);

    (void)pthread_join(g_coldhot_thread, NULL);

    pthread_mutex_lock(&g_coldhot_lock);
    bondp_coldhot_event_t *ev = NULL;
    bondp_coldhot_event_t *next = NULL;
    if (g_coldhot_list_inited) {
        UB_LIST_FOR_EACH_SAFE (ev, next, node, &g_coldhot_events) {
            ub_list_remove(&ev->node);
            free(ev);
        }
    }
    g_coldhot_started = false;
    pthread_mutex_unlock(&g_coldhot_lock);
}

static int post_event(bondp_coldhot_ev_type_t type, bondp_context_t *bdp_ctx,
                      uint32_t vjetty_id, uint32_t pjetty_idx)
{
    /* Context teardown: drop late events instead of queueing them against a
     * context that is about to be freed. */
    if (bdp_ctx == NULL || atomic_load(&bdp_ctx->coldhot_canceling)) {
        return -1;
    }
    if (bondp_coldhot_start() != 0) {
        return -1;
    }

    bondp_coldhot_event_t *ev = (bondp_coldhot_event_t *)calloc(1, sizeof(*ev));
    if (ev == NULL) {
        return -1;
    }
    ev->type = type;
    ev->bdp_ctx = bdp_ctx;
    ev->vjetty_id = vjetty_id;
    ev->pjetty_idx = pjetty_idx;

    pthread_mutex_lock(&g_coldhot_lock);
    if (!g_coldhot_running) {
        pthread_mutex_unlock(&g_coldhot_lock);
        free(ev);
        return -1;
    }
    ub_list_push_back(&g_coldhot_events, &ev->node);
    (void)pthread_cond_signal(&g_coldhot_cond);
    pthread_mutex_unlock(&g_coldhot_lock);
    return 0;
}

int bondp_coldhot_post_fault(bondp_context_t *bdp_ctx, uint32_t vjetty_id, uint32_t pjetty_idx)
{
    return post_event(BONDP_COLDHOT_EV_FAULT, bdp_ctx, vjetty_id, pjetty_idx);
}

int bondp_coldhot_post_failback(bondp_context_t *bdp_ctx, uint32_t vjetty_id, uint32_t pjetty_idx)
{
    return post_event(BONDP_COLDHOT_EV_FAILBACK, bdp_ctx, vjetty_id, pjetty_idx);
}

int bondp_coldhot_post_reconcile(bondp_context_t *bdp_ctx, uint32_t vjetty_id)
{
    return post_event(BONDP_COLDHOT_EV_RECONCILE, bdp_ctx, vjetty_id, 0);
}

void bondp_coldhot_cancel_ctx(bondp_context_t *bdp_ctx)
{
    if (bdp_ctx == NULL) {
        return;
    }
    /* Reject any event posted from now on, then drop queued ones and wait for
     * the in-flight one (if any) before the caller frees bdp_ctx/p_ctxs. */
    atomic_store(&bdp_ctx->coldhot_canceling, true);
    pthread_mutex_lock(&g_coldhot_lock);
    /* Drop every queued event for this context and wait until an already
     * running event for it has left. The context teardown frees bdp_ctx and
     * its p_ctxs right after this returns, so the manager must not touch them.
     */
    for (;;) {
        if (g_coldhot_list_inited) {
            bondp_coldhot_event_t *ev = NULL;
            bondp_coldhot_event_t *next = NULL;
            UB_LIST_FOR_EACH_SAFE (ev, next, node, &g_coldhot_events) {
                if (ev->bdp_ctx != bdp_ctx) {
                    continue;
                }
                ub_list_remove(&ev->node);
                free(ev);
            }
        }
        if (g_coldhot_processing_ctx != bdp_ctx) {
            break;
        }
        (void)pthread_cond_wait(&g_coldhot_idle_cond, &g_coldhot_lock);
    }
    pthread_mutex_unlock(&g_coldhot_lock);
}
