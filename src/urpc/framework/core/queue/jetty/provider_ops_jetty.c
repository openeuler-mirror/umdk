/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: provider ops based on jetty
 */

#include <fcntl.h>
#include "urma_api.h"

#include "jetty_public_func.h"
#include "queue_send_recv.h"
#include "urpc_dbuf_stat.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_manage.h"

#include "provider_ops_jetty.h"

#define URPC_EID_MAP_PREFIX (0x0000FFFF)
#define MULTI_EID_PER_VF_MAX 256
#define MAX_IMPORT_EVENT_NUM 32

typedef struct urpc_register_pa_mem_in {
    uint64_t pa_addr;
    uint64_t len;
    urma_token_id_t *token_id;
    uint32_t fe_idx;
    urma_token_t token_value;
    uint32_t token_policy : 3;
    uint32_t rsvd1 : 29;
    uint32_t rsvd2;
    uint64_t user_ctx;
} urpc_register_pa_mem_in_t;

typedef struct urpc_register_pa_mem_out {
    urma_target_seg_t *tseg;
} urpc_register_pa_mem_out_t;

typedef struct urpc_unregister_pa_mem_in {
    urma_target_seg_t *tseg;
} urpc_unregister_pa_mem_in_t;

typedef struct urpc_unregister_pa_mem_out {
    int ret;
} urpc_unregister_pa_mem_out_t;

typedef struct jetty_provider_ctx {
    uint32_t urma_ref_cnt;
} jetty_provider_ctx_t;

static jetty_provider_ctx_t g_urpc_jetty_provider_ctx;
static uint32_t jetty_provider_init(provider_init_opt_t *opt);
static void jetty_provider_uninit(provider_t *provider);
static uint64_t jetty_provider_register_mem(provider_t *provider, mem_seg_register_param_t *param);
static int jetty_provider_unregister_mem(provider_t *provider, uint64_t mem_h, bool va);
static inline void jetty_provider_get_eid(provider_t *provider, urpc_eid_t *eid);

static provider_ops_t g_urpc_jetty_provider_ops = {
    .mode = PROVIDER_MODE_JETTY,
    .init = jetty_provider_init,
    .uninit = jetty_provider_uninit,
    .register_mem = jetty_provider_register_mem,
    .unregister_mem = jetty_provider_unregister_mem,
    .get_eid = jetty_provider_get_eid,
    .import_mem = jetty_provider_import_mem,
    .unimport_mem = jetty_provider_unimport_mem,
};

static inline bool is_eid_ipv6(const urma_eid_t *eid)
{
    return eid->in4.reserved != 0 || eid->in4.prefix != htonl(URPC_EID_MAP_PREFIX);
}

static urma_transport_type_t jetty_provider_get_dev_type(urpc_trans_mode_t mode)
{
    urma_transport_type_t type = URMA_TRANSPORT_INVALID;
    switch (mode) {
        case URPC_TRANS_MODE_UB:
            type = URMA_TRANSPORT_UB;
            break;
        default:
            break;
    }

    return type;
}

static uint32_t jetty_provider_get_dev_by_name(provider_init_opt_t *opt, urma_device_t **urma_dev,
                                               urma_eid_info_t *eid_info, uint32_t eid_info_num)
{
    *urma_dev = urma_get_device_by_name(opt->cfg->dev.dev_name);
    if (*urma_dev == NULL) {
        URPC_LIB_LOG_ERR("urma dev is null\n");
        return 0;
    }

    urma_transport_type_t dev_type = jetty_provider_get_dev_type(opt->cfg->trans_mode);
    if (dev_type != (*urma_dev)->type) {
        URPC_LIB_LOG_ERR("unsupported trans mode %d\n", (int)opt->cfg->trans_mode);
        return 0;
    }

    uint32_t i, num = 0;
    urma_eid_info_t *eid_list = urma_get_eid_list(*urma_dev, &num);
    if (eid_list == NULL || num == 0) {
        URPC_LIB_LOG_ERR("get urma eid list failed\n");
        return 0;
    }

    uint32_t idx = 0;
    for (i = 0; i < num; i++) {
        if ((opt->cfg->dev.is_ipv6 != 0) != is_eid_ipv6(&eid_list[i].eid)) {
            continue;
        }

        if (idx >= eid_info_num) {
            URPC_LIB_LOG_WARN("The number of eid exceeds the upper limit.\n");
            break;
        }

        eid_info[idx++] = eid_list[i];

        if (opt->flag.bs.multi_eid == 0) {
            break;
        }
    }

    urma_free_eid_list(eid_list);

    if ((opt->flag.bs.multi_eid == 0 && i == num) ||
        (opt->flag.bs.multi_eid != 0 && idx == 0)) {
        URPC_LIB_LOG_ERR("jetty provider get device by name %s for %s data plane failed\n", opt->cfg->dev.dev_name,
            opt->cfg->dev.is_ipv6 != 0 ? "ipv6" : "ipv4");

        return 0;
    }

    return idx;
}

static uint32_t jetty_provider_get_dev_by_eid_inner(urpc_trans_mode_t trans_mode, urma_eid_t *eid,
                                                    urma_device_t **urma_dev, urma_eid_info_t *eid_info,
                                                    uint32_t eid_info_num)
{
    urma_transport_type_t dev_type = jetty_provider_get_dev_type(trans_mode);
    if (dev_type == URMA_TRANSPORT_INVALID) {
        URPC_LIB_LOG_ERR("unsupported trans mode %d\n", (int)trans_mode);
        return 0;
    }

    int device_num = 0;
    urma_device_t **device_list = urma_get_device_list(&device_num);
    if (device_list == NULL || device_num == 0) {
        URPC_LIB_LOG_ERR("jetty provider get device list failed\n");
        return 0;
    }

    int i;
    uint32_t j, cnt = 0;
    for (i = 0; i < device_num; i++) {
        if (device_list[i]->type != dev_type) {
            continue;
        }

        urma_eid_info_t *eid_list = urma_get_eid_list(device_list[i], &cnt);
        if (eid_list == NULL || cnt == 0) {
            continue;
        }

        for (j = 0; j < cnt; j++) {
            if ((memcmp(eid, &eid_list[j].eid, sizeof(urma_eid_t)) == 0)) {
                *urma_dev = device_list[i];
                eid_info[0] = eid_list[j];
                break;
            }
        }

        urma_free_eid_list(eid_list);

        if (j != cnt) {
            break;
        }
    }

    urma_free_device_list(device_list);

    if (i == device_num) {
        URPC_LIB_LOG_ERR("jetty provider get device failed, EID " EID_FMT "\n", EID_ARGS(*eid));
        return 0;
    }

    return 1;
}

static uint32_t jetty_provider_get_dev_by_ip_addr(urpc_trans_info_t *cfg, urma_device_t **urma_dev,
                                                  urma_eid_info_t *eid_info, uint32_t eid_info_num)
{
    const char *ip_addr = cfg->assign_mode == DEV_ASSIGN_MODE_IPV4 ? cfg->ipv4.ip_addr : cfg->ipv6.ip_addr;
    urma_eid_t eid;
    int ret = urma_str_to_eid(ip_addr, &eid);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("format ip addr to eid failed\n");
        return 0;
    }

    return jetty_provider_get_dev_by_eid_inner(cfg->trans_mode, &eid, urma_dev, eid_info, eid_info_num);
}

static uint32_t jetty_provider_get_dev_by_eid(urpc_trans_info_t *cfg, urma_device_t **urma_dev,
                                              urma_eid_info_t *eid_info, uint32_t eid_info_num)
{
    urma_eid_t *eid = (urma_eid_t *)&cfg->ub.eid;
    return jetty_provider_get_dev_by_eid_inner(cfg->trans_mode, eid, urma_dev, eid_info, eid_info_num);
}

static uint32_t jetty_provider_get_dev(provider_init_opt_t *opt, urma_device_t **urma_dev,
                                       urma_eid_info_t *eid_info, uint32_t eid_info_num)
{
    // use dev_name to get device
    if (opt->cfg->assign_mode == DEV_ASSIGN_MODE_DEV) {
        return jetty_provider_get_dev_by_name(opt, urma_dev, eid_info, eid_info_num);
    }

    // use ip_addr and transmod to get device
    if ((opt->cfg->assign_mode == DEV_ASSIGN_MODE_IPV4) || (opt->cfg->assign_mode == DEV_ASSIGN_MODE_IPV6)) {
        return jetty_provider_get_dev_by_ip_addr(opt->cfg, urma_dev, eid_info, 1);
    }

    if (opt->cfg->assign_mode == DEV_ASSIGN_MODE_EID) {
        return jetty_provider_get_dev_by_eid(opt->cfg, urma_dev, eid_info, 1);
    }

    URPC_LIB_LOG_ERR("unsupported assign_mode %d, trans_mode %d\n", opt->cfg->assign_mode, opt->cfg->trans_mode);

    return 0;
}

static int trans_mode_opso_init(jetty_provider_t *jetty_provider)
{
    if (jetty_provider->urma_ctx->dev->type != URMA_TRANSPORT_UB) {
        return 0;
    }

    /* open source needs to import memory */
    if (mem_hmap_init() != 0) {
        return -1;
    }

    return 0;
}

static void trans_mode_opso_uninit(urma_transport_type_t type)
{
    if (type != URMA_TRANSPORT_UB) {
        return;
    }

    mem_hmap_uninit();
}

static void handle_async_event_jfc_err(queue_transport_ctx_t *queue_ctx, urma_async_event_t *event)
{
    queue_local_t *local = NULL;
    send_recv_queue_local_t *queue = NULL;
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(local, node, &queue_ctx->queue_list) {
        switch (local->queue.ops->mode) {
            case QUEUE_TRANS_MODE_JETTY:
                queue = (send_recv_queue_local_t *)(uintptr_t)local;
                if (queue->jfs_jfc == event->element.jfc || queue->jfr_jfc == event->element.jfc) {
                    atomic_fetch_add(&queue->local_q.err_msg_num, 1);
                    queue->local_q.queue.err_code = URPC_ERR_EVENT_JFC_ERR;
                }
                break;
            default:
                break;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
}

static void handle_async_event_jfr_err(queue_transport_ctx_t *queue_ctx, urma_async_event_t *event)
{
    queue_local_t *local = NULL;
    jfr_ctx_t *jfr_ctx = NULL;
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(local, node, &queue_ctx->queue_list) {
        switch (local->queue.ops->mode) {
            case QUEUE_TRANS_MODE_JETTY:
                jfr_ctx = CONTAINER_OF_FIELD(local->rq_ctx, jfr_ctx_t, ctx);
                if (jfr_ctx->jfr == event->element.jfr) {
                    atomic_fetch_add(&local->err_msg_num, 1);
                    local->queue.err_code = URPC_ERR_EVENT_JFR_ERR;
                }
                break;
            default:
                break;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
}

static void handle_async_event_jfr_limit(queue_transport_ctx_t *queue_ctx, urma_async_event_t *event)
{
    queue_local_t *local = NULL;
    jfr_ctx_t *jfr_ctx = NULL;
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(local, node, &queue_ctx->queue_list) {
        switch (local->queue.ops->mode) {
            case QUEUE_TRANS_MODE_JETTY:
                jfr_ctx = CONTAINER_OF_FIELD(local->rq_ctx, jfr_ctx_t, ctx);
                if (jfr_ctx->jfr == event->element.jfr) {
                    URPC_LIB_LOG_WARN("queue rx wr not enough for queue handle\n");
                    local->queue.err_code = URPC_ERR_EVENT_JFR_LIMIT;
                }
                break;
            default:
                break;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
}

static void handle_async_event_jetty_err(queue_transport_ctx_t *queue_ctx, urma_async_event_t *event)
{
    queue_local_t *local = NULL;
    send_recv_queue_local_t *queue = NULL;
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(local, node, &queue_ctx->queue_list) {
        switch (local->queue.ops->mode) {
            case QUEUE_TRANS_MODE_JETTY:
                queue = (send_recv_queue_local_t *)(uintptr_t)local;
                if (queue->jetty == event->element.jetty) {
                    atomic_fetch_add(&queue->local_q.err_msg_num, 1);
                    queue->local_q.queue.err_code = URPC_ERR_EVENT_JETTY_ERR;
                    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
                    return;
                }
                break;
            default:
                break;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
}

static void handle_async_event_jetty_limit(queue_transport_ctx_t *queue_ctx, urma_async_event_t *event)
{
    queue_local_t *local = NULL;
    send_recv_queue_local_t *queue = NULL;
    (void)pthread_mutex_lock(&queue_ctx->queue_list_mutex);
    URPC_LIST_FOR_EACH(local, node, &queue_ctx->queue_list) {
        switch (local->queue.ops->mode) {
            case QUEUE_TRANS_MODE_JETTY:
                queue = (send_recv_queue_local_t *)(uintptr_t)local;
                if (queue->jetty == event->element.jetty) {
                    URPC_LIB_LOG_WARN("queue rx wr not enough for queue handle\n");
                    queue->local_q.queue.err_code = URPC_ERR_EVENT_JETTY_LIMIT;
                    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
                    return;
                }
                break;
            default:
                break;
        }
    }
    (void)pthread_mutex_unlock(&queue_ctx->queue_list_mutex);
}

static void handle_async_event(uint32_t events, urpc_epoll_event_t *lev)
{
    if ((events & ((uint32_t)EPOLLERR | EPOLLHUP)) != 0) {
        URPC_LIB_LOG_WARN("exception event 0x%x\n", events);
        return;
    }

    queue_transport_ctx_t *queue_ctx = get_queue_transport_ctx();
    urma_context_t *urma_ctx = (urma_context_t *)lev->args;
    urma_async_event_t event = {0};
    urma_status_t status = urma_get_async_event(urma_ctx, &event);
    if (status != URMA_SUCCESS) {
        return;
    }

    // softub currently only report URMA_EVENT_JFC_ERR and URMA_EVENT_JETTY_ERR; other events are not handled in softub;
    switch (event.event_type) {
        case URMA_EVENT_JFC_ERR:
            handle_async_event_jfc_err(queue_ctx, &event);
            break;
        case URMA_EVENT_JFR_ERR:
            handle_async_event_jfr_err(queue_ctx, &event);
            break;
        case URMA_EVENT_JFS_ERR:
            URPC_LIB_LOG_WARN("jfs err\n");

            break;
        case URMA_EVENT_JFR_LIMIT:
            handle_async_event_jfr_limit(queue_ctx, &event);
            break;
        case URMA_EVENT_JETTY_ERR:
            handle_async_event_jetty_err(queue_ctx, &event);
            break;
        case URMA_EVENT_JETTY_LIMIT:
            handle_async_event_jetty_limit(queue_ctx, &event);
            break;
        case URMA_EVENT_JETTY_GRP_ERR:
            break;
        case URMA_EVENT_PORT_ACTIVE:
            URPC_LIB_LOG_WARN("port active, port_id:%u\n", event.element.port_id);

            break;
        case URMA_EVENT_PORT_DOWN:
            URPC_LIB_LOG_WARN("port down, port_id:%u\n", event.element.port_id);

            break;
        case URMA_EVENT_DEV_FATAL:
            URPC_LIB_LOG_WARN("dev fatal\n");

            break;
        case URMA_EVENT_EID_CHANGE:
            URPC_LIB_LOG_WARN("dev fatal\n");

            break;
        case URMA_EVENT_ELR_ERR:
            URPC_LIB_LOG_WARN("entity level error\n");

            break;
        case URMA_EVENT_ELR_DONE:
            URPC_LIB_LOG_WARN("entity flush done\n");

            break;
        default:
            break;
    }

    urma_ack_async_event(&event);
}

static int add_urma_async_event_listener(jetty_provider_t *jetty_provider)
{
    // async_fd is maintained by urma, no need to close here
    int async_fd = jetty_provider->urma_ctx->async_fd;
    int flags = fcntl(async_fd, F_GETFL);
    if (flags < 0) {
        URPC_LIB_LOG_ERR("failed to get file descriptor flags of urma async event: %s\n", strerror(errno));
        return -URPC_ERR_EINVAL;
    }

    int ret = fcntl(async_fd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0) {
        URPC_LIB_LOG_ERR("failed to change file descriptor of urma async event\n");
        return ret;
    }

    urpc_epoll_event_t *event =
        (urpc_epoll_event_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_PROVIDER, sizeof(urpc_epoll_event_t));
    if (event == NULL) {
        URPC_LIB_LOG_ERR("fail to malloc async_event\n");
        return -URPC_ERR_ENOMEM;
    }

    event->fd = async_fd;
    event->func = handle_async_event;
    event->args = jetty_provider->urma_ctx;
    event->events = EPOLLIN;
    event->is_handshaker_ctx = false;
    ret = urpc_mange_event_register(URPC_MANAGE_JOB_TYPE_LISTEN, event);
    if (ret != URPC_SUCCESS) {
        urpc_dbuf_free(event);
        return ret;
    }

    jetty_provider->event = event;

    return URPC_SUCCESS;
}

static int jetty_provider_init_sub_providers(urpc_trans_info_t *trans_info, urma_device_t *urma_dev, uint32_t index,
                                             uint32_t provider_idx)
{
    jetty_provider_t *jetty_provider =
        (jetty_provider_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_PROVIDER, 1, sizeof(jetty_provider_t));
    if (jetty_provider == NULL) {
        URPC_LIB_LOG_ERR("calloc jetty provider failed\n");
        return URPC_FAIL;
    }
    jetty_provider->urma_dev = urma_dev;

    if (urma_query_device(jetty_provider->urma_dev, &jetty_provider->dev_attr) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("query device failed, device name:%s\n", jetty_provider->urma_dev->name);
        goto RELEASE_PROVIDER;
    }

    // this may change after, soft ub one queue one context
    jetty_provider->urma_ctx = urma_create_context(jetty_provider->urma_dev, index);
    if (jetty_provider->urma_ctx == NULL) {
        URPC_LIB_LOG_ERR("create urma context failed\n");
        goto RELEASE_PROVIDER;
    }

    if (trans_mode_opso_init(jetty_provider) != 0) {
        goto DEL_CTX;
    }

    if (jetty_provider->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
        if (add_urma_async_event_listener(jetty_provider) != URPC_SUCCESS) {
            goto UNINIT_OPSO;
        }
    }

    jetty_provider->provider.ops = &g_urpc_jetty_provider_ops;
    jetty_provider->provider.idx = provider_idx;
    jetty_provider->provider.trans_mode = trans_info->trans_mode;
    jetty_provider->status = PROVIDER_CTX_STATUS_READY;

    g_urpc_jetty_provider_ctx.urma_ref_cnt++;

    provider_list_push((provider_t *)(uintptr_t)jetty_provider);

    return URPC_SUCCESS;

UNINIT_OPSO:
    trans_mode_opso_uninit(jetty_provider->urma_ctx->dev->type);
DEL_CTX:
    (void)urma_delete_context(jetty_provider->urma_ctx);
    jetty_provider->urma_ctx = NULL;

RELEASE_PROVIDER:
    urpc_dbuf_free(jetty_provider);

    return URPC_FAIL;
}

static uint32_t jetty_provider_init(provider_init_opt_t *opt)
{
    urma_init_attr_t init_attr = { 0 };
    if ((g_urpc_jetty_provider_ctx.urma_ref_cnt == 0) && urma_init(&init_attr) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("urma init failed\n");
        return 0;
    }

    uint32_t fail_cnt = 0;
    uint32_t provider_cnt = 0;
    uint32_t provider_idx = opt->start_idx;
    urma_device_t *urma_dev = NULL;
    urma_eid_info_t eid_list[MULTI_EID_PER_VF_MAX] = {0};
    uint32_t eid_cnt = jetty_provider_get_dev(opt, &urma_dev, eid_list, MULTI_EID_PER_VF_MAX);
    if (eid_cnt == 0) {
        goto EXIT;
    }

    for (uint32_t i = 0; i < eid_cnt; i++) {
        if (jetty_provider_init_sub_providers(opt->cfg, urma_dev, eid_list[i].eid_index, provider_idx) !=
            URPC_SUCCESS) {
            URPC_LIB_LOG_WARN("init jetty provider failed, dev: %s, eid[%u]: "EID_FMT"\n", urma_dev->name,
                eid_list[i].eid_index, EID_ARGS(eid_list[i].eid));
            fail_cnt++;
        } else {
            URPC_LIB_LOG_INFO("init jetty provider successful, dev: %s, eid[%u]: "EID_FMT"\n", urma_dev->name,
                eid_list[i].eid_index, EID_ARGS(eid_list[i].eid));
            provider_cnt++;
            provider_idx++;
        }
    }

    if (provider_cnt == 0) {
        URPC_LIB_LOG_ERR("init jetty provider failed\n");
    } else if (fail_cnt != 0) {
        URPC_LIB_LOG_WARN("init jetty provider partial failed\n");
    }

EXIT:
    if (g_urpc_jetty_provider_ctx.urma_ref_cnt == 0) {
        (void)urma_uninit();
    }

    return provider_cnt;
}

static void jetty_provider_uninit(provider_t *provider)
{
    provider_list_pop(provider);

    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;

    if (jetty_provider->event != NULL) {
        (void)urpc_mange_event_unregister(URPC_MANAGE_JOB_TYPE_LISTEN, jetty_provider->event);
        urpc_dbuf_free(jetty_provider->event);
        jetty_provider->event = NULL;
    }

    (void)urma_delete_context(jetty_provider->urma_ctx);
    jetty_provider->urma_ctx = NULL;
    urpc_dbuf_free(jetty_provider);
    if (--g_urpc_jetty_provider_ctx.urma_ref_cnt == 0) {
        (void)urma_uninit();
    }
}

static uint64_t jetty_provider_register_pa_mem(jetty_provider_t *jetty_provider, mem_seg_register_param_t *param)
{
    urma_token_id_t *token_id = urma_alloc_token_id(jetty_provider->urma_ctx);
    if (token_id == NULL) {
        URPC_LIB_LOG_ERR("alloc token id failed\n");
        return URPC_INVALID_HANDLE;
    }

    urma_token_t token;
    token.token = crypto_gen_rand_token();
    urpc_register_pa_mem_in_t urpc_in = {
        .pa_addr = param->addr,
        .len = param->len,
        .fe_idx = param->fe_idx,
        .token_id = token_id,
        .token_value = token,
        .token_policy = token_policy_get(),
        .user_ctx = token.token,
    };

    urpc_register_pa_mem_out_t urpc_out = {0};

    urma_user_ctl_in_t urma_in = {
        .addr = (uint64_t)(uintptr_t)&urpc_in,
        .len = sizeof(urpc_register_pa_mem_in_t),
        .opcode = USER_CTL_REGISTER_PA_MEM,
    };

    urma_user_ctl_out_t urma_out = {
        .addr = (uint64_t)(uintptr_t)&urpc_out,
        .len  = sizeof(urpc_register_pa_mem_out_t),
    };

    int ret = urma_user_ctl(jetty_provider->urma_ctx, &urma_in, &urma_out);
    if (ret != 0 || urpc_out.tseg == NULL) {
        URPC_LIB_LOG_ERR("urpc register pa addr failed\n");
        (void)urma_free_token_id(token_id);
        return URPC_INVALID_HANDLE;
    }

    param->token->token_id = token_id->token_id;
    param->token->token_value = token.token;

    URPC_LIB_LOG_INFO("urpc register pa addr success\n");
    return (uint64_t)(uintptr_t)(urpc_out.tseg);
}

static uint64_t jetty_provider_register_mem(provider_t *provider, mem_seg_register_param_t *param)
{
    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;
    if (jetty_provider->urma_ctx == NULL) {
        URPC_LIB_LOG_ERR("urma context is null\n");
        return URPC_INVALID_HANDLE;
    }

    if (!param->va) {
        return jetty_provider_register_pa_mem(jetty_provider, param);
    }

    urma_reg_seg_flag_t flag = {
        .bs.token_policy = token_policy_get(),
        .bs.cacheable = URMA_NON_CACHEABLE,
        .bs.reserved = 0,
        .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC
    };

    urma_token_t token;
    token.token = crypto_gen_rand_token();
    urma_seg_cfg_t seg_cfg = {
        .va = (uintptr_t)param->addr,
        .len = param->len,
        .token_id = NULL,
        .token_value = token,
        .flag = flag,
        .user_ctx = token.token,
        .iova = 0
    };
    return (uint64_t)(uintptr_t)urma_register_seg(jetty_provider->urma_ctx, &seg_cfg);
}

static int jetty_provider_unregister_pa_mem(jetty_provider_t *jetty_provider, urma_target_seg_t *tseg)
{
    urma_token_id_t *token_id = tseg->token_id;
    urpc_unregister_pa_mem_in_t urpc_in = {
        .tseg = tseg,
    };

    urpc_unregister_pa_mem_out_t urpc_out = {0};

    urma_user_ctl_in_t urma_in = {
        .addr = (uint64_t)(uintptr_t)&urpc_in,
        .len = sizeof(urpc_unregister_pa_mem_in_t),
        .opcode = USER_CTL_UNREGISTER_PA_MEM,
    };

    urma_user_ctl_out_t urma_out = {
        .addr = (uint64_t)(uintptr_t)&urpc_out,
        .len  = sizeof(urpc_unregister_pa_mem_out_t),
    };

    int ret = urma_user_ctl(jetty_provider->urma_ctx, &urma_in, &urma_out);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("urpc unregister pa addr failed\n");
        return ret;
    }

    (void)urma_free_token_id(token_id);
    URPC_LIB_LOG_INFO("urpc unregister pa addr success\n");
    return URPC_SUCCESS;
}

static int jetty_provider_unregister_mem(provider_t *provider, uint64_t mem_h, bool va)
{
    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;
    if (!va) {
        return jetty_provider_unregister_pa_mem(jetty_provider, (urma_target_seg_t *)(uintptr_t)mem_h);
    }

    if (urma_unregister_seg((urma_target_seg_t *)(uintptr_t)mem_h) != URMA_SUCCESS) {
        URPC_LIB_LOG_ERR("urma unregister segment failed\n");
        return URPC_FAIL;
    }
    return URPC_SUCCESS;
}

static inline void jetty_provider_get_eid(provider_t *provider, urpc_eid_t *eid)
{
    jetty_provider_t *jetty_provider = (jetty_provider_t *)(uintptr_t)provider;
    memcpy(eid, &jetty_provider->urma_ctx->eid, sizeof(urpc_eid_t));
}

URPC_CONSTRUCTOR(jetty_provider_ops_init, CONSTRUCTOR_PRIORITY_DRIVER)
{
    provider_register_ops(&g_urpc_jetty_provider_ops);
}
