/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bonding provider datapath interrupt implementation
 * Create: 2026-07-21
 * Note:
 * History: 2026-07-21  Create file
 */

#include <sys/epoll.h>
#include <time.h>

#include "ub_util.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"

#include "bondp_types.h"

#include "bondp_dp_int.h"

#define BOND_EPOLL_NUM  (32)
#define BONDP_NS_PER_MS 1000000ULL

urma_status_t bondp_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);
    bool success_once = false;

    PERF_PROFILING_START(BOND_REARM_JFC);
    if (bdp_jfc->v_jfc.jfc_cfg.jfce == NULL) {
        URMA_LOG_ERR("Failed to rearm jfc: JFCE is NULL\n");
        PERF_PROFILING_END(BOND_REARM_JFC);
        return URMA_EINVAL;
    }

    /* Rearm writes the current CQ CI, so refresh standby JFCs as well. */
    for (uint32_t n = 0; n < bdp_jfc->enabled_count; ++n) {
        uint32_t i = bdp_jfc->enabled_indices[n];
        if (urma_rearm_jfc(bdp_jfc->p_jfc[i], solicited_only) == URMA_SUCCESS) {
            success_once = true;
        }
    }

    PERF_PROFILING_END(BOND_REARM_JFC);
    return success_once ? URMA_SUCCESS : URMA_FAIL;
}

static inline int bondp_get_monotonic_ms(uint64_t *now_ms)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return -1;
    }
    *now_ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / BONDP_NS_PER_MS;
    return 0;
}

static inline urma_jfce_t *bondp_find_p_jfce_by_fd(bondp_jfce_t *bdp_jfce, int fd)
{
    for (int i = 0; i < bdp_jfce->dev_num; i++) {
        if (bdp_jfce->p_jfce[i] != NULL && bdp_jfce->p_jfce[i]->fd == fd) {
            return bdp_jfce->p_jfce[i];
        }
    }
    return NULL;
}

static urma_jfc_t *bondp_wait_one_jfc_event(bondp_jfce_t *bdp_jfce, int fd)
{
    urma_jfce_t *p_jfce = bondp_find_p_jfce_by_fd(bdp_jfce, fd);
    if (p_jfce == NULL) {
        URMA_LOG_WARN("Failed to find fd=%d from p_jfce array.\n", fd);
        return NULL;
    }

    urma_jfc_t *p_jfc = NULL;
    int p_num = urma_wait_jfc(p_jfce, 1, 0, &p_jfc);
    if (p_num <= 0) {
        return NULL;
    }

    uint32_t nevents = 1;
    urma_ack_jfc(&p_jfc, &nevents, 1);

    urma_jfc_t *v_jfc = (urma_jfc_t *)p_jfc->jfc_cfg.user_ctx;
    if (v_jfc == NULL) {
        URMA_LOG_WARN("v_jfc is NULL, pjfc_id=%u.\n", p_jfc->jfc_id.id);
        return NULL;
    }
    return v_jfc;
}

static int bondp_collect_jfc_events(bondp_jfce_t *bdp_jfce, const struct epoll_event events[], int num,
                                    uint32_t jfc_cnt, urma_jfc_t *jfc[])
{
    int actual_num = 0;

    for (int i = 0; i < num; i++) {
        if ((uint32_t)actual_num >= jfc_cnt) {
            break;
        }
        urma_jfc_t *v_jfc = bondp_wait_one_jfc_event(bdp_jfce, events[i].data.fd);
        if (v_jfc == NULL) {
            continue;
        }
        jfc[actual_num++] = v_jfc;
    }
    return actual_num;
}

static inline int bondp_get_epoll_event_limit(bondp_jfce_t *bdp_jfce, uint32_t jfc_cnt)
{
    int epoll_event_limit = bdp_jfce->dev_num < BOND_EPOLL_NUM ? bdp_jfce->dev_num : BOND_EPOLL_NUM;

    if (epoll_event_limit > 0) {
        return epoll_event_limit;
    }
    return jfc_cnt < BOND_EPOLL_NUM ? jfc_cnt : BOND_EPOLL_NUM;
}

static inline bool bondp_update_retry_timeout(int time_out, uint64_t deadline_ms, int *wait_timeout)
{
    uint64_t now_ms = 0;

    if (time_out < 0) {
        *wait_timeout = time_out;
        return true;
    }
    if (bondp_get_monotonic_ms(&now_ms) != 0 || now_ms >= deadline_ms) {
        *wait_timeout = 0;
        return false;
    }
    *wait_timeout = (int)(deadline_ms - now_ms);
    return *wait_timeout != 0;
}

int bondp_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[])
{
    bondp_jfce_t *bdp_jfce = CONTAINER_OF_FIELD(jfce, bondp_jfce_t, v_jfce);

    PERF_PROFILING_START(BOND_WAIT_JFC);
    struct epoll_event events[BOND_EPOLL_NUM] = {0};
    int epoll_event_limit = bondp_get_epoll_event_limit(bdp_jfce, jfc_cnt);
    uint64_t deadline_ms = 0;
    int wait_timeout = time_out;

    if (jfc_cnt == 0) {
        PERF_PROFILING_END(BOND_WAIT_JFC);
        return 0;
    }
    if (time_out > 0) {
        if (bondp_get_monotonic_ms(&deadline_ms) != 0) {
            URMA_LOG_ERR("Failed to get monotonic time.\n");
            PERF_PROFILING_END(BOND_WAIT_JFC);
            return -1;
        }
        deadline_ms += (uint64_t)time_out;
    }

    do {
        int num = epoll_wait(bdp_jfce->v_jfce.fd, events, epoll_event_limit, wait_timeout);
        if (num < 0 || num > epoll_event_limit) {
            URMA_LOG_ERR("Epoll wait err, ret=%d.\n", num);
            PERF_PROFILING_END(BOND_WAIT_JFC);
            return -1;
        } else if (num == 0) {
            PERF_PROFILING_END(BOND_WAIT_JFC);
            return 0;
        }

        int actual_num = bondp_collect_jfc_events(bdp_jfce, events, num, jfc_cnt, jfc);
        if (actual_num > 0 || time_out == 0) {
            PERF_PROFILING_END(BOND_WAIT_JFC);
            return actual_num;
        }

        if (!bondp_update_retry_timeout(time_out, deadline_ms, &wait_timeout)) {
            break;
        }
    } while (time_out != 0 && wait_timeout != 0);

    PERF_PROFILING_END(BOND_WAIT_JFC);
    return 0;
}

void bondp_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt)
{
    // for now we do not need to call bondp_ack_multiple_die_jfc
    return;
}

static void *get_jetty_and_ret(uint64_t addr, int *ret)
{
    if (addr == 0) {
        *ret = -1;
        return NULL;
    }

    *ret = 0;
    return (void *)addr;
}

static int init_elment_vjetty(urma_async_event_t *v_event, urma_async_event_t *p_event)
{
    int ret = 0;

    switch (p_event->event_type) {
        case URMA_EVENT_JFC_ERR:
            v_event->element.jfc = (urma_jfc_t *)get_jetty_and_ret(
                p_event->element.jfc->jfc_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JFS_ERR:
            v_event->element.jfs = (urma_jfs_t *)get_jetty_and_ret(
                p_event->element.jfs->jfs_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JFR_ERR:
        case URMA_EVENT_JFR_LIMIT:
            v_event->element.jfr = (urma_jfr_t *)get_jetty_and_ret(
                p_event->element.jfr->jfr_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JETTY_ERR:
        case URMA_EVENT_JETTY_LIMIT:
            v_event->element.jetty = (urma_jetty_t *)get_jetty_and_ret(
                p_event->element.jetty->jetty_cfg.user_ctx, &ret);
            break;
        case URMA_EVENT_JETTY_GRP_ERR:
        case URMA_EVENT_PORT_ACTIVE:
        case URMA_EVENT_PORT_DOWN:
        case URMA_EVENT_DEV_FATAL:
            break;
        case URMA_EVENT_EID_CHANGE:
            v_event->element.eid_idx = 0;
            break;
        default:
            break;
    }
    return ret;
}

urma_status_t bondp_get_async_event(urma_context_t *ctx, urma_async_event_t *v_event)
{
    if (ctx == NULL || ctx->async_fd < 0 || v_event == NULL) {
        URMA_LOG_ERR("Invalid parameter\n");
        return URMA_EINVAL;
    }
    struct epoll_event event;
    urma_async_event_t *p_event;
    urma_status_t status;

    int nfds = epoll_wait(ctx->async_fd, &event, 1, 0);
    if (nfds == -1) {
        URMA_LOG_ERR("epoll_wait no event or err.\n");
        return URMA_FAIL;
    }

    if ((event.events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        URMA_LOG_ERR("bondp get error epoll_event=0x%x.\n", event.events);
        return URMA_FAIL;
    }
    if (event.events & EPOLLIN) {
        urma_context_t *p_contex = (urma_context_t *)event.data.ptr;
        p_event = calloc(1, sizeof(urma_async_event_t));
        if (p_event == NULL) {
            return URMA_ENOMEM;
        }
        status = urma_get_async_event(p_contex, p_event);
        if (status != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to get async event, status=%d\n", status);
            free(p_event);
            return status;
        }
        v_event->urma_ctx = ctx;
        if (init_elment_vjetty(v_event, p_event) != 0) {
            free(p_event);
            URMA_LOG_ERR("failed to get invalid jetty.\n");
            return URMA_EINVAL;
        }
        v_event->event_type = p_event->event_type;
        v_event->priv = p_event;
        URMA_LOG_DEBUG("Got async event successfully, event_type=%u\n", v_event->event_type);
        return URMA_SUCCESS;
    }
    return URMA_FAIL;
}

void bondp_ack_async_event(urma_async_event_t *event)
{
    if (event->priv == NULL) {
        URMA_LOG_ERR("Invalid parameter\n");
        return;
    }
    urma_async_event_t *p_event = (urma_async_event_t *)event->priv;
    urma_ack_async_event(p_event);
    URMA_LOG_DEBUG("Acked async event, event_type=%u\n", event->event_type);
    event->priv = NULL;
    free(p_event);
}
