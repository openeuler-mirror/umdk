/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa worker implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port core routines from daemon here
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "uvs_types.h"
#include "tpsa_log.h"
#include "ub_hash.h"
#include "uvs_tp_exception.h"
#include "tpsa_worker.h"

#define TPSA_MAX_EPOLL_NUM 2048
#define TPSA_MAX_TCP_CONN 1024
#define TPSA_CM_THREAD_PRIORITY (-20)
#define TPSA_MAX_EPOLL_WAIT 16
#define TPSA_EVENT_MAX_WAIT_MS 10 // 10ms
#define TPSA_SOCK_TIMEOUT 10 /* 10s */

#define TPSA_DEFAULT_SUSPEND_PERIOD 1000 // us
#define TPSA_DEFAULT_SUSPEND_CNT 3
#define TPSA_DEFAULT_SUS2ERR_PERIOD 30000000
#define TPSA_MTU_BITS_BASE_SHIFT 7

/* add temporarily for 1650 not support flush tp */
static bool g_tp_fast_destroy = false;
void tpsa_set_tp_fast_destroy(bool tp_fast_destory)
{
    g_tp_fast_destroy = tp_fast_destory;
}

bool tpsa_get_tp_fast_destroy(void)
{
    return g_tp_fast_destroy;
}

static int tpsa_handle_event_invalid(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg,
                                     char *dev_name, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    /* invalid state and event combination. Do nothing. */
    return 0;
}

/* TODO: refresh function pointer when we handle delete and refresh event in third node */
static tpsa_vtp_event_handler g_tpsa_worker_vtp_event_handler[MAX_VTP_NODE_STATE][MAX_VTP_EVENT_SIZE] = {
    {
        tpsa_handle_event_invalid,      /* [STATE_NORMAL][VTP_EVENT_SWITCH] */
        tpsa_handle_event_invalid,      /* [STATE_NORMAL][VTP_EVENT_ROLLBACK] */
        tpsa_handle_event_invalid,      /* [STATE_NORMAL][VTP_EVENT_SRC_DELETE] need to adapt */
        tpsa_handle_event_invalid,      /* [STATE_NORMAL][VTP_EVENT_DST_DELETE] */
        tpsa_handle_event_invalid       /* [STATE_NORMAL][VTP_EVENT_DIP_REFRESH] */
    },
    {
        uvs_lm_swap_tpg,                /* [STATE_READY][VTP_EVENT_SWITCH] */
        uvs_lm_handle_ready_rollback,   /* [STATE_READY][VTP_EVENT_ROLLBACK] */
        tpsa_handle_event_invalid,      /* [STATE_READY][VTP_EVENT_SRC_DELETE] */
        tpsa_handle_event_invalid,      /* [STATE_READY][VTP_EVENT_DST_DELETE] */
        uvs_lm_refresh_tpg              /* [STATE_READY][VTP_EVENT_DIP_REFRESH] */
    },
    {
        tpsa_handle_event_invalid,      /* [STATE_MIGRATING][VTP_EVENT_SWITCH] */
        uvs_lm_swap_tpg,                /* [STATE_MIGRATING][VTP_EVENT_ROLLBACK] */
        tpsa_handle_event_invalid,      /* [STATE_MIGRATING][VTP_EVENT_SRC_DELETE] */
        tpsa_handle_event_invalid,      /* [STATE_MIGRATING][VTP_EVENT_DST_DELETE] */
        tpsa_handle_event_invalid       /* [STATE_MIGRATING][VTP_EVENT_DIP_REFRESH] */
    },
    {
        tpsa_handle_event_invalid,      /* [STATE_ROLLBACK][VTP_EVENT_SWITCH] */
        tpsa_handle_event_invalid,      /* [STATE_ROLLBACK][VTP_EVENT_ROLLBACK] */
        tpsa_handle_event_invalid,      /* [STATE_ROLLBACK][VTP_EVENT_SRC_DELETE] */
        tpsa_handle_event_invalid,      /* [STATE_ROLLBACK][VTP_EVENT_DST_DELETE] */
        tpsa_handle_event_invalid       /* [STATE_ROLLBACK][VTP_EVENT_DIP_REFRESH] */
    }
};

static void tpsa_config_device_default_value(tpsa_nl_config_device_resp_t *resp, tpsa_nl_config_device_req_t *req)
{
    resp->rc_cnt = req->max_rc_cnt;
    resp->rc_depth = req->max_rc_depth;
    resp->slice = req->max_slice;
}

static int tpsa_worker_config_device(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_config_device_req_t *nlreq = (tpsa_nl_config_device_req_t *)nlmsg->req.data;
    vport_table_entry_t entry = {0};
    tpsa_nl_config_device_resp_t rsp;
    tpsa_global_cfg_t *global_cfg = &worker->global_cfg_ctx;

    (void)memset(&rsp, 0, sizeof(tpsa_nl_config_device_resp_t));
    tpsa_config_device_default_value(&rsp, nlreq);

    vport_key_t vport_key = {0};
    vport_key.fe_idx = nlmsg->src_fe_idx;
    (void)memcpy(vport_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    int res = tpsa_lookup_vport_table(&vport_key,
                                      &worker->table_ctx.vport_table,
                                      &entry);
    if (res != 0) {
        TPSA_LOG_ERR("Not find vport config in fe_idx %hu, use default value\n", nlmsg->src_fe_idx);
    } else {
        if (entry.mask.bs.rc_cnt != 0 && entry.rc_cfg.rc_cnt < nlreq->max_rc_cnt) {
            rsp.rc_cnt = entry.rc_cfg.rc_cnt;
        }

        if (entry.mask.bs.rc_depth != 0 && entry.rc_cfg.rc_depth < nlreq->max_rc_depth) {
            rsp.rc_depth = entry.rc_cfg.rc_depth;
        }
    }

    if (global_cfg->slice >= nlreq->min_slice && global_cfg->slice <= nlreq->max_slice) {
        rsp.slice = global_cfg->slice;
    }
    rsp.set_slice = global_cfg->mask.bs.slice;

    rsp.is_tpf_dev = nlreq->is_tpf_dev;
    if (nlreq->is_tpf_dev == true) {
        rsp.suspend_period =
            (global_cfg->mask.bs.suspend_period == 1 ? global_cfg->suspend_period : UVS_DERFAULT_SUSPEND_PERIOD_US);
        rsp.suspend_cnt = (global_cfg->mask.bs.suspend_cnt == 1 ? global_cfg->suspend_cnt : UVS_DERFAULT_SUSPEND_CNT);
    }

    rsp.ret = TPSA_NL_RESP_SUCCESS;

    tpsa_nl_msg_t *nlresp = tpsa_nl_config_device_resp(msg, &rsp);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(&worker->nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    free(nlresp);
    return 0;
}

static int tpsa_sock_handle_event(tpsa_worker_t *worker, struct epoll_event *ev)
{
    if (!(ev->events & EPOLLIN)) {
        return 0;
    }

    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx
    };

    if (ev->data.fd != worker->sock_ctx.listen_fd) {
        tpsa_sock_msg_t *msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
        if (msg == NULL) {
            return -ENOMEM;
        }

        static_assert(sizeof(tpsa_sock_msg_t) < TPSA_MAX_SOCKET_MSG_LEN, "socket msg size over max value");
        /* Prevent link down up sock small packets from being received multiple times, resulting in exceptions */
        if (tpsa_sock_recv_msg_timeout(ev->data.fd, (char*)msg, sizeof(tpsa_sock_msg_t),
            TPSA_SOCK_TIMEOUT, worker->epollfd) != 0) {
            free(msg);
            return -1;
        }
        int ret;
        switch (msg->msg_type) {
            case TPSA_FORWARD: /* Adapt to Alpha version */
                ret = tpsa_nl_send_msg(&worker->nl_ctx, &msg->content.nlmsg);
                break;
            case TPSA_CREATE_REQ:
            case TPSA_LM_TRANSFER:
                ret = uvs_create_vtp_req(&ctx, msg);
                break;
            case TPSA_CREATE_RESP:
                ret = uvs_create_vtp_resp(&ctx, msg);
                break;
            case TPSA_CREATE_ACK:
                ret = uvs_create_vtp_ack(&ctx, msg);
                break;
            case TPSA_CREATE_FINISH:
                ret = uvs_create_vtp_finish(&ctx, msg);
                break;
            case TPSA_DESTROY_REQ:
                ret = uvs_destroy_target_vtp(&ctx, msg);
                break;
            case TPSA_TABLE_SYC:
                ret = uvs_handle_table_sync(&ctx, msg);
                break;
            case TPSA_LM_MIG_REQ:
                ret = uvs_lm_handle_mig_req(&ctx, msg);
                break;
            case TPSA_LM_MIG_RESP:
                ret = uvs_lm_handle_mig_resp(&ctx, msg);
                break;
            case TPSA_TP_ERROR_REQ:
                ret = uvs_handle_sock_restore_tp_error_req(ctx.table_ctx, ctx.sock_ctx, ctx.ioctl_ctx, msg);
                break;
            case TPSA_TP_ERROR_RESP:
                ret = uvs_handle_sock_restore_tp_error_resp(ctx.table_ctx, ctx.sock_ctx, ctx.ioctl_ctx, msg);
                break;
            case TPSA_TP_ERROR_ACK:
                ret = uvs_handle_sock_restore_tp_error_ack(ctx.table_ctx, ctx.ioctl_ctx, msg);
                break;
            case TPSA_LM_NOTIFY:
                ret = uvs_lm_handle_notify(&ctx, msg);
                break;
            case TPSA_LM_ROLLBACK_REQ:
                ret = uvs_lm_handle_rollback_req(&ctx, msg);
                break;
            default:
                TPSA_LOG_ERR("Unexpected socket msg type received\n");
                ret = -1;
                break;
        }

        free(msg);

        return ret;
    }
    if (tpsa_handle_accept_fd(worker->epollfd, &worker->sock_ctx) != 0) {
        return -1;
    }
    return 0;
}

static inline uint32_t tpsa_mtu_enum_to_int(uvs_mtu_t mtu)
{
    return (uint32_t)(1 << ((uint32_t)mtu + TPSA_MTU_BITS_BASE_SHIFT));
}

static uvs_mtu_t tpsa_get_mtu(uint32_t mtu)
{
    if (mtu >= tpsa_mtu_enum_to_int(UVS_MTU_8192)) {
        return UVS_MTU_8192;
    } else if (mtu >= tpsa_mtu_enum_to_int(UVS_MTU_4096)) {
        return UVS_MTU_4096;
    } else if (mtu >= tpsa_mtu_enum_to_int(UVS_MTU_2048)) {
        return UVS_MTU_2048;
    } else if (mtu >= tpsa_mtu_enum_to_int(UVS_MTU_1024)) {
        return UVS_MTU_1024;
    } else if (mtu >= tpsa_mtu_enum_to_int(UVS_MTU_512)) {
        return UVS_MTU_512;
    } else if (mtu >= tpsa_mtu_enum_to_int(UVS_MTU_256)) {
        return UVS_MTU_256;
    } else {
        return (uvs_mtu_t)0;
    }
}

tpsa_nl_msg_t *tpsa_handle_nl_add_sip_req(sip_table_t *table, tpsa_nl_msg_t *msg)
{
    sip_table_entry_t entry_add = {0};
    tpsa_nl_add_sip_req_t *req;

    req = (tpsa_nl_add_sip_req_t *)(void *)msg->payload;
    (void)memcpy(entry_add.dev_name, req->dev_name, TPSA_MAX_DEV_NAME);
    (void)memcpy(&entry_add.addr, &req->netaddr, sizeof(tpsa_net_addr_t));
    entry_add.port_cnt = req->port_cnt;
    (void)memcpy(entry_add.port_id, req->port_id, TPSA_MAX_PORT_CNT);
    entry_add.prefix_len = req->prefix_len;
    entry_add.mtu = tpsa_get_mtu(req->mtu);
    if (sip_table_add(table, req->index, &entry_add) != 0) {
        return NULL;
    }
    return tpsa_get_add_sip_resp(msg);
}

tpsa_nl_msg_t *tpsa_handle_nl_del_sip_req(sip_table_t *table, tpsa_nl_msg_t *msg)
{
    tpsa_nl_del_sip_req_t *req;
    req = (tpsa_nl_del_sip_req_t *)(void *)msg->payload;

    if (sip_table_remove(table, req->index) != 0) {
        return NULL;
    }
    return tpsa_get_del_sip_resp(msg);
}

static void tpsa_init_ueid_cfg(tpsa_ioctl_cfg_t *cfg, tpsa_nl_dealloc_eid_req_t *nlreq,
    uint16_t fe_idx, tpsa_ueid_t value)
{
    if (nlreq->virtualization) {
        cfg->cmd.op_eid.in.fe_idx = fe_idx;
    } else {
        cfg->cmd.op_eid.in.fe_idx = TPSA_NON_VIRTUALIZATION_FE_IDX;
    }
    cfg->cmd.op_eid.in.upi = value.upi;
    cfg->cmd.op_eid.in.eid = value.eid;
    cfg->cmd.op_eid.in.eid_index = nlreq->eid_index;
}

static int tpsa_worker_lookup_ueid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_alloc_eid_req_t *nlreq = (tpsa_nl_alloc_eid_req_t *)nlmsg->req.data;
    vport_key_t key;
    tpsa_ueid_t value;
    int ret = 0;
    tpsa_nl_req_host_t *tmsg = (tpsa_nl_req_host_t *)msg->payload;

    key.fe_idx = nlmsg->src_fe_idx;
    (void)memcpy(key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);
    if (tpsa_lookup_vport_table_ueid(&key, &worker->table_ctx.vport_table, nlreq->eid_index, &value) < 0) {
        return -1;
    }

    if (nlreq->virtualization) {
        /* IOCTL to add ueid */
        tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            TPSA_LOG_ERR("Fail to create cfg request");
            return -1;
        }
        cfg->cmd_type = tmsg->req.opcode == TPSA_MSG_ALLOC_EID ?
            TPSA_CMD_ALLOC_EID : TPSA_CMD_DEALLOC_EID;
        tpsa_init_ueid_cfg(cfg, nlreq, nlmsg->src_fe_idx, value);
        (void)memcpy(cfg->cmd.op_eid.in.dev_name, (nlreq->virtualization == true ?
            nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);
        if (tpsa_ioctl(worker->ioctl_ctx.ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to alloc/dealloc eid in worker");
            free(cfg);
            return -1;
        }
        free(cfg);
    }

    /* Netlink to notify vtpn */
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_dicover_eid_resp(msg, &value, nlreq->eid_index, nlreq->virtualization);
    if (nlresp == NULL) {
        return -1;
    }
    if (tpsa_nl_send_msg(&worker->nl_ctx, nlresp) != 0) {
        ret = -1;
        goto free_resp;
    }
    TPSA_LOG_INFO("success resp ueid msg to pf.\n");

free_resp:
    free(nlresp);
    return ret;
}

static int tpsa_worker_alloc_ueid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    return tpsa_worker_lookup_ueid(worker, msg);
}

static int tpsa_worker_dealloc_ueid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    return tpsa_worker_lookup_ueid(worker, msg);
}

static int tpsa_worker_update_tpf_dev_info_resp(tpsa_worker_t *worker, tpsa_nl_msg_t *msg,
                                                tpsa_nl_update_tpf_dev_info_resp_t rsp)
{
    tpsa_nl_msg_t *nlresp = tpsa_nl_update_tpf_dev_info_resp(msg, &rsp);
    if (nlresp == NULL) {
        TPSA_LOG_INFO("failed to create update tpf dev resp\n");
        return -1;
    }

    if (tpsa_nl_send_msg(&worker->nl_ctx, nlresp) != 0) {
        free(nlresp);
        TPSA_LOG_INFO("failed to send tpsa nl msg\n");
        return -1;
    }

    free(nlresp);
    return 0;
}

static int tpsa_worker_del_tpf_dev_info(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_update_tpf_dev_info_req_t *nlreq;
    tpf_dev_table_t *tpf_dev_table;
    tpf_dev_table_key_t key;

    nlreq = (tpsa_nl_update_tpf_dev_info_req_t *)msg->payload;

    tpsa_nl_update_tpf_dev_info_resp_t rsp;
    (void)memset(&rsp, 0, sizeof(tpsa_nl_update_tpf_dev_info_resp_t));

    tpf_dev_table = &worker->table_ctx.tpf_dev_table;

    (void)strcpy(key.dev_name, nlreq->dev_name);

    if (tpf_dev_table_remove(tpf_dev_table, &key) != 0) {
        TPSA_LOG_ERR("can not remove tpf dev entry by key dev name %s\n", key.dev_name);
        rsp.ret = TPSA_NL_RESP_FAIL;
        (void)tpsa_worker_update_tpf_dev_info_resp(worker, msg, rsp);
        return -EPERM;
    }

    rsp.ret = TPSA_NL_RESP_SUCCESS;
    return tpsa_worker_update_tpf_dev_info_resp(worker, msg, rsp);
}

static int tpsa_worker_add_tpf_dev_info(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_update_tpf_dev_info_req_t *nlreq;
    tpf_dev_table_entry_t add_entry = {0};
    tpsa_cc_entry_t *cc_entry;
    tpf_dev_table_t *tpf_dev_table;
    tpf_dev_table_key_t key;

    nlreq = (tpsa_nl_update_tpf_dev_info_req_t *)msg->payload;
    cc_entry = (tpsa_cc_entry_t *)nlreq->data;

    uint32_t cc_entry_cnt = nlreq->cc_entry_cnt;
    tpsa_nl_update_tpf_dev_info_resp_t rsp;
    (void)memset(&rsp, 0, sizeof(tpsa_nl_update_tpf_dev_info_resp_t));

    if (cc_entry_cnt > TPSA_CC_IDX_TABLE_SIZE || cc_entry_cnt == 0) {
        TPSA_LOG_WARN("cc_entry_cnt is larger than the size of reserved array or array size is 0, cc_entry_cnt = %u.\n",
            cc_entry_cnt);
        rsp.ret = TPSA_NL_RESP_FAIL;
        (void)tpsa_worker_update_tpf_dev_info_resp(worker, msg, rsp);
        return -EFBIG;
    }

    tpf_dev_table = &worker->table_ctx.tpf_dev_table;

    (void)strcpy(key.dev_name, nlreq->dev_name);

    add_entry.dev_fea = nlreq->dev_fea;
    add_entry.cc_entry_cnt = cc_entry_cnt;
    TPSA_LOG_INFO("update tpf: %s dev info, clan:%d", key.dev_name, add_entry.dev_fea.bs.clan);
    (void)memcpy(add_entry.cc_array, cc_entry, sizeof(tpsa_cc_entry_t) * cc_entry_cnt);

    if (tpf_dev_table_add(tpf_dev_table, &key, &add_entry) != 0) {
        TPSA_LOG_ERR("can not add tpf dev entry by key dev name %s\n", key.dev_name);
        rsp.ret = TPSA_NL_RESP_FAIL;
        (void)tpsa_worker_update_tpf_dev_info_resp(worker, msg, rsp);
        return -EPERM;
    }

    rsp.ret = TPSA_NL_RESP_SUCCESS;
    return tpsa_worker_update_tpf_dev_info_resp(worker, msg, rsp);
}

static int tpsa_worker_update_tpf_dev_info(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_update_tpf_dev_info_req_t *nlreq = (tpsa_nl_update_tpf_dev_info_req_t *)msg->payload;
    if (nlreq->opcode == TPSA_NL_UPDATE_TPF_ADD) {
        return tpsa_worker_add_tpf_dev_info(worker, msg);
    } else if (nlreq->opcode == TPSA_NL_UPDATE_TPF_DEL) {
        return tpsa_worker_del_tpf_dev_info(worker, msg);
    }

    TPSA_LOG_WARN("opcode in update tpf info invalid %d\n", nlreq->opcode);
    return -1;
}

static void tpsa_check_lm_begin(tpsa_worker_t *worker)
{
    live_migrate_table_entry_t *cur, *next;
    int ret;

    (void)pthread_rwlock_wrlock(&worker->table_ctx.live_migrate_table.rwlock);
    if (worker->table_ctx.live_migrate_table.hmap.count == 0) {
        (void)pthread_rwlock_unlock(&worker->table_ctx.live_migrate_table.rwlock);
        return;
    }

    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx
    };

    HMAP_FOR_EACH_SAFE(cur, next, node, &worker->table_ctx.live_migrate_table.hmap) {
        vport_key_t fe_key = cur->key;
        fe_table_entry_t *fe_entry = fe_table_lookup(&worker->table_ctx.fe_table, &fe_key);
        if (fe_entry == NULL) {
            TPSA_LOG_DEBUG("Can't find fe entry in fe table, so live migrate failed");
            continue;
        }

        /* After receiving a request to stop processing link_create/delete, the vtp table will no longer be copied. */
        if (fe_entry->stop_proc_vtp == true) {
            continue;
        }

        ret = uvs_lm_send_mig_req(&ctx, cur, fe_entry);
        /* If the live migration of this fe fails, print err log and then continue the live migration of other fe. */
        if (ret != 0) {
            TPSA_LOG_DEBUG("fe_idx %hu, live migrate failed", fe_key.fe_idx);
        }
    }

    (void)pthread_rwlock_unlock(&worker->table_ctx.live_migrate_table.rwlock);
    return;
}

void uvs_rm_vtp_table_check_switch(uvs_ctx_t *ctx)
{
    deid_vtp_table_key_t deid_key = {
        .dst_eid = ctx->table_ctx->dip_table.refresh_entry->key.deid,
        .upi = ctx->table_ctx->dip_table.refresh_entry->key.upi,
        .trans_mode = TPSA_TP_RM,
    };

    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&ctx->table_ctx->deid_vtp_table, &deid_key);
    if (deid_entry == NULL) {
        TPSA_LOG_DEBUG("for rm mode, there no need to refresh.\n");
        return;
    }

    /* Traverse the vtp_list to complete channel_switch of all vf on a PF which communicate with lm source. */
    deid_vtp_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &deid_entry->vtp_list) {
        rm_vtp_table_entry_t *vtp_entry = cur->entry.content.rm_entry;
        tpsa_vtp_cfg_t vtp_cfg = { 0 };
        if (vtp_entry->node_status != STATE_READY || vtp_entry->vice_tpgn == UINT32_MAX) {
            TPSA_LOG_DEBUG("The virtual machine does not meet the switching conditions for rm mode.\n");
            continue;
        }
        int ret = g_tpsa_worker_vtp_event_handler[vtp_entry->node_status][VTP_EVENT_DIP_REFRESH](ctx, &vtp_cfg,
                                                                                                 NULL, &cur->entry);
        if (ret != 0) {
            TPSA_LOG_ERR("For rm mode, switch tpg failed,src eid = " EID_FMT ", dst eid = " EID_FMT ".\n",
                         EID_ARGS(vtp_entry->key.src_eid), EID_ARGS(vtp_entry->key.dst_eid));
        }
    }
    return;
}

void uvs_rc_vtp_table_check_switch(uvs_ctx_t *ctx)
{
    deid_vtp_table_key_t deid_key = {
        .dst_eid = ctx->table_ctx->dip_table.refresh_entry->key.deid,
        .upi = ctx->table_ctx->dip_table.refresh_entry->key.upi,
        .trans_mode = TPSA_TP_RC,
    };

    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&ctx->table_ctx->deid_vtp_table, &deid_key);
    if (deid_entry == NULL) {
        TPSA_LOG_DEBUG("for rc mode, there no need to refresh.\n");
        return;
    }

    /* Traverse the vtp_list to complete channel_switch of all vf on a PF which communicate with lm source. */
    deid_vtp_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &deid_entry->vtp_list) {
        tpsa_vtp_cfg_t vtp_cfg = { 0 };
        rc_vtp_table_entry_t *vtp_entry = cur->entry.content.rc_entry;
        if (vtp_entry->node_status != STATE_READY || vtp_entry->vice_tpgn == UINT32_MAX) {
            TPSA_LOG_DEBUG("The virtual machine does not meet the switching conditions for rc mode.\n");
            continue;
        }
        int ret = g_tpsa_worker_vtp_event_handler[vtp_entry->node_status][VTP_EVENT_DIP_REFRESH](ctx, &vtp_cfg,
                                                                                                 NULL, &cur->entry);
        if (ret != 0) {
            TPSA_LOG_DEBUG("For rc mode, switch tpg failed,src eid = " EID_FMT ", dst eid = " EID_FMT ".\n",
                         EID_ARGS(vtp_entry->src_eid), EID_ARGS(vtp_entry->key.dst_eid));
        }
    }
    return;
}

void uvs_um_vtp_table_check_switch(uvs_ctx_t *ctx)
{
    deid_vtp_table_key_t deid_key = {
        .dst_eid = ctx->table_ctx->dip_table.refresh_entry->key.deid,
        .upi = ctx->table_ctx->dip_table.refresh_entry->key.upi,
        .trans_mode = TPSA_TP_UM,
    };

    deid_vtp_table_entry_t *deid_entry = deid_vtp_table_lookup(&ctx->table_ctx->deid_vtp_table, &deid_key);
    if (deid_entry == NULL) {
        TPSA_LOG_DEBUG("for um mode, there no need to refresh.\n");
        return;
    }
    /* Traverse the vtp_list to complete channel_switch of all vf on a PF which communicate with lm source. */
    deid_vtp_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &deid_entry->vtp_list) {
        tpsa_vtp_cfg_t vtp_cfg = { 0 };
        um_vtp_table_entry_t *vtp_entry = cur->entry.content.um_entry;
        if (vtp_entry->node_status != STATE_NORMAL) {
            TPSA_LOG_DEBUG("The virtual machine does not meet the switching conditions  for um mode.\n");
            continue;
        }
        int ret = g_tpsa_worker_vtp_event_handler[vtp_entry->node_status][VTP_EVENT_DIP_REFRESH](ctx, &vtp_cfg,
                                                                                                 NULL, &cur->entry);
        if (ret != 0) {
            TPSA_LOG_DEBUG("For um mode, switch utp failed,src eid is " EID_FMT ", dst eid is " EID_FMT ".\n",
                           EID_ARGS(vtp_entry->key.src_eid), EID_ARGS(vtp_entry->key.dst_eid));
        }
    }
    return;
}

static void tpsa_check_tbl_refresh(tpsa_worker_t *worker)
{
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx
    };
    dip_table_t* dip_table = &worker->table_ctx.dip_table;

    (void)pthread_rwlock_wrlock(&dip_table->rwlock);
    if (!dip_table->tbl_refresh) {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return;
    }

    /* handle VTP_EVENT_REFRESH */
    uvs_rm_vtp_table_check_switch(&ctx);
    uvs_rc_vtp_table_check_switch(&ctx);
    uvs_um_vtp_table_check_switch(&ctx);

    (void)pthread_rwlock_unlock(&dip_table->rwlock);

    return;
}

static void tpsa_check_vf_delete(tpsa_worker_t *worker)
{
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx
    };
    vport_table_t* vport_table = &worker->table_ctx.vport_table;

    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    if (!vport_table->vf_destroy) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return;
    }
    uvs_lm_clean_up_resource(&ctx);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return;
}

static int tpsa_handle_fe2tpf_msg(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *tmsg = (tpsa_nl_req_host_t *)msg->payload;
    int ret = 0;

    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx
    };

    switch (tmsg->req.opcode) {
        case TPSA_MSG_CREATE_VTP:
            ret = uvs_create_vtp(&ctx, msg);
            break;
        case TPSA_MSG_DESTROY_VTP:
            ret = uvs_destroy_vtp(&ctx, msg);
            break;
        case TPSA_MSG_CONFIG_DEVICE:
            ret = tpsa_worker_config_device(worker, msg);
            break;
        case TPSA_MSG_ALLOC_EID:
            ret = tpsa_worker_alloc_ueid(worker, msg);
            break;
        case TPSA_MSG_DEALLOC_EID:
            ret = tpsa_worker_dealloc_ueid(worker, msg);
            break;
        case TPSA_MSG_STOP_PROC_VTP_MSG:
            ret = uvs_lm_handle_stop_proc_vtp_msg(&ctx, msg);
            break;
        case TPSA_MSG_QUERY_VTP_MIG_STATUS:
            ret = uvs_lm_handle_query_mig_status(&ctx, msg);
            break;
        case TPSA_MSG_FLOW_STOPPED:
            ret = uvs_lm_config_migrate_state_local(&ctx, msg, TPSA_MIG_STATE_START);
            break;
        case TPSA_MSG_MIG_ROLLBACK:
            ret = uvs_lm_handle_rollback(&ctx, msg);
            break;
        case TPSA_MSG_MIG_VM_START:
            ret = uvs_lm_config_migrate_state_local(&ctx, msg, TPSA_MIG_STATE_FINISH);
            break;
        default:
            TPSA_LOG_ERR("There is an unrecognized message type.\n");
            ret = -1;
            break;
    }
    return ret;
}

static int tpsa_handle_migrate_async(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    int ret = -1;
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx
    };

    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_migrate_vtp_req_t *mig_req = (tpsa_nl_migrate_vtp_req_t *)nlmsg->req.data;
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;

    vtp_node_state_t node_status;
    tpsa_lm_vtp_entry_t *lm_vtp_entry = (tpsa_lm_vtp_entry_t *)calloc(1, sizeof(struct tpsa_lm_vtp_entry));
    if (lm_vtp_entry == NULL) {
        TPSA_LOG_ERR("Fail to create vtp entry.\n");
        return -1;
    }

    if (uvs_lm_query_vtp_entry_status(msg, &ctx, &node_status, lm_vtp_entry) < 0) {
        TPSA_LOG_ERR("uvs lm query vtp entry status failed\n");
        free(lm_vtp_entry);
        return -1;
    }

    if (msg->msg_type == TPSA_NL_MIGRATE_VTP_SWITCH) {
        ret = g_tpsa_worker_vtp_event_handler[node_status][VTP_EVENT_SWITCH](&ctx, vtp_cfg,
                                                                             mig_req->dev_name, lm_vtp_entry);
    } else {
        ret = g_tpsa_worker_vtp_event_handler[node_status][VTP_EVENT_ROLLBACK](&ctx, vtp_cfg,
                                                                               mig_req->dev_name, lm_vtp_entry);
    }
    free(lm_vtp_entry);
    return ret;
}

static tpsa_nl_msg_t *tpsa_handle_nl_query_tp_req(tpsa_worker_t *worker, tpsa_nl_msg_t *req)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;
    tpsa_nl_msg_t *resp = NULL;
    tpsa_nl_query_tp_req_t *query_req = (tpsa_nl_query_tp_req_t *)req->payload;
    vport_table_entry_t *return_entry;
    vport_key_t key;
    int ret = -1;

    return_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (return_entry == NULL) {
        return NULL;
    }
    (void)memcpy(key.dev_name, query_req->dev_name, TPSA_MAX_DEV_NAME);
    key.fe_idx = query_req->fe_idx;
    ret = tpsa_lookup_vport_table(&key, &worker->table_ctx.vport_table, return_entry);
    if (ret != 0) {
        free(return_entry);
        TPSA_LOG_ERR("Failed to query vport entry\n");
        return NULL;
    }
    resp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_query_tp_resp_t), &src_eid, &dst_eid);
    if (resp == NULL) {
        free(return_entry);
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }
    resp->hdr.nlmsg_type = TPSA_NL_QUERY_TP_RESP;
    resp->msg_type = TPSA_NL_QUERY_TP_RESP;
    resp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)resp);
    resp->nlmsg_seq = req->nlmsg_seq;
    resp->transport_type = req->transport_type;

    tpsa_nl_query_tp_resp_t *query_tp_resp = (tpsa_nl_query_tp_resp_t *)resp->payload;
    query_tp_resp->ret = TPSA_NL_RESP_SUCCESS;
    query_tp_resp->retry_num = return_entry->tp_cfg.retry_num;
    query_tp_resp->retry_factor = return_entry->tp_cfg.retry_factor;
    query_tp_resp->ack_timeout = return_entry->tp_cfg.ack_timeout;
    query_tp_resp->dscp = return_entry->tp_cfg.dscp;
    query_tp_resp->oor_cnt = return_entry->tp_cfg.oor_cnt;
    free(return_entry);

    return resp;
}

static int tpsa_handle_nl_msg(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_msg_t *resp = NULL;
    tpsa_sock_msg_t *info = NULL;
    int ret = 0;

    switch (msg->msg_type) {
        case TPSA_NL_FE2TPF_REQ:
            return tpsa_handle_fe2tpf_msg(worker, msg);
        case TPSA_NL_MIGRATE_VTP_SWITCH:
        case TPSA_NL_MIGRATE_VTP_ROLLBACK:
            return tpsa_handle_migrate_async(worker, msg);
        /* Alpha begins */
        case TPSA_NL_QUERY_TP_REQ:
            resp = tpsa_handle_nl_query_tp_req(worker, msg);
            break;
        case TPSA_NL_CREATE_TP_REQ:
        case TPSA_NL_DESTROY_TP_REQ:
        case TPSA_NL_RESTORE_TP_REQ:
        case TPSA_NL_SET_AGENT_PID:
        case TPSA_NL_CREATE_TP_RESP:
        case TPSA_NL_DESTROY_TP_RESP:
        case TPSA_NL_QUERY_TP_RESP:
        case TPSA_NL_RESTORE_TP_RESP:
            info = tpsa_handle_nl_create_tp_req(msg);
            break;
        case TPSA_NL_ADD_SIP_REQ:
            resp = tpsa_handle_nl_add_sip_req(&worker->table_ctx.sip_table, msg);
            break;
        case TPSA_NL_DEL_SIP_REQ:
            resp = tpsa_handle_nl_del_sip_req(&worker->table_ctx.sip_table, msg);
            break;
        case TPSA_NL_TP_ERROR_REQ:
            return uvs_handle_nl_tp_error_req(&worker->table_ctx, &worker->sock_ctx, &worker->ioctl_ctx, msg);
        case TPSA_NL_TP_SUSPEND_REQ:
            return uvs_handle_nl_tp_suspend_req(&worker->table_ctx, &worker->ioctl_ctx, msg);
        case TPSA_NL_UPDATE_TPF_DEV_INFO_REQ:
            return tpsa_worker_update_tpf_dev_info(worker, msg);
        default:
            TPSA_LOG_ERR("Unexpected nl msg id %d type %d received\n", msg->nlmsg_seq, msg->msg_type);
            return -1;
    }

    if (msg->msg_type == TPSA_NL_QUERY_TP_REQ || msg->msg_type == TPSA_NL_ADD_SIP_REQ ||
        msg->msg_type == TPSA_NL_DEL_SIP_REQ) {
        if (tpsa_nl_send_msg(&worker->nl_ctx, resp) != 0) {
            ret = -1;
            goto free_msg_buf;
        }
        TPSA_LOG_INFO("[Enqueue local resp]---msg_id: %d\n", resp->nlmsg_seq);
    }

free_msg_buf:
    if (resp != NULL) {
        free(resp);
    }
    if (info != NULL) {
        free(info);
    }
    return ret;
}

static int tpsa_nl_handle_event(tpsa_worker_t *worker, const struct epoll_event *ev)
{
    if (!(ev->events & EPOLLIN)) {
        return 0;
    }
    static_assert(sizeof(tpsa_nl_msg_t) < TPSA_MAX_SOCKET_MSG_LEN, "nl msg size over max value");
    tpsa_nl_msg_t msg = { 0 };
    ssize_t recv_len = tpsa_nl_recv_msg(&worker->nl_ctx, &msg, sizeof(tpsa_nl_msg_t), worker->epollfd);
    if (recv_len < 0) {
        TPSA_LOG_ERR("Recv len is zero, event 0x%x fd = %d.\n", ev->events, ev->data.fd);
        return -1;
    }

    if (tpsa_handle_nl_msg(worker, &msg) != 0) {
        return -1;
    }

    return 0;
}

static void *tpsa_thread_main(void *arg)
{
    tpsa_worker_t *worker = (tpsa_worker_t *)arg;
    if (worker == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    (void)pthread_setname_np(pthread_self(), (const char *)"uvs_worker");
    pid_t tid = (pid_t)syscall(SYS_gettid);
    if (setpriority(PRIO_PROCESS, (id_t)tid, TPSA_CM_THREAD_PRIORITY) != 0) {
        TPSA_LOG_ERR("set priority failed: %s.\n", ub_strerror(errno));
        return NULL;
    }

    struct epoll_event events[TPSA_MAX_EPOLL_WAIT];
    while (worker->stop == false) {
        int num_events = epoll_wait(worker->epollfd, events, TPSA_MAX_EPOLL_WAIT, TPSA_EVENT_MAX_WAIT_MS);
        if (num_events == -1) {
            continue;
        }
        for (int i = 0; i < num_events; i++) {
            if ((events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
                TPSA_LOG_ERR("Exception event 0x%x fd = %d.\n", events[i].events, events[i].data.fd);
                (void)epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                (void)close(events[i].data.fd);
                continue;
            }
            /* An abnormal event causes err, but the daemon service does not exit */
            if (events[i].data.fd == worker->nl_ctx.fd && tpsa_nl_handle_event(worker, &events[i]) != 0) {
                TPSA_LOG_ERR("Failed to handle nl event.\n");
            }
            if (events[i].data.fd != worker->nl_ctx.fd && tpsa_sock_handle_event(worker, &events[i]) != 0) {
                TPSA_LOG_ERR("Failed to handle sock event\n");
            }
        }

        tpsa_check_lm_begin(worker);
        tpsa_check_tbl_refresh(worker);
        tpsa_check_vf_delete(worker);
    }
    return NULL;
}

static int tpsa_worker_thread_init(tpsa_worker_t *worker)
{
    int ret;
    pthread_attr_t attr;
    int epollfd;

    epollfd = epoll_create(TPSA_MAX_EPOLL_NUM);
    if (epollfd < 0) {
        TPSA_LOG_ERR("Failed to create epoll fd, nl->epollfd: %d, err: %s.\n",
            epollfd, ub_strerror(errno));
        return -1;
    }

    if (tpsa_add_epoll_event(epollfd, worker->sock_ctx.listen_fd, EPOLLIN) != 0) {
        TPSA_LOG_ERR("Add epoll event failed.\n");
        (void)close(epollfd);
        return -1;
    }

    ret = listen(worker->sock_ctx.listen_fd, TPSA_MAX_TCP_CONN);
    if (ret < 0) {
        TPSA_LOG_ERR("Server socket listen failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
        return -1;
    }

    if (tpsa_add_epoll_event(epollfd, worker->nl_ctx.fd, EPOLLIN) != 0) {
        TPSA_LOG_ERR("Add epoll event failed.\n");
        (void)close(epollfd);
        return -1;
    }

    (void)pthread_attr_init(&attr);
    worker->stop = false;
    worker->epollfd = epollfd;
    ret = pthread_create(&worker->thread, &attr, tpsa_thread_main, worker);
    if (ret < 0) {
        TPSA_LOG_ERR("pthread create failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
    }
    (void)pthread_attr_destroy(&attr);
    TPSA_LOG_INFO("thread listen (ep_fd=%d, ADD, nl_fd=%d, sock_listen_fd=%d) succeed.\n",
        epollfd, worker->nl_ctx.fd, worker->sock_ctx.listen_fd);
    return ret;
}

static void tpsa_worker_thread_uninit(tpsa_worker_t *worker)
{
    worker->stop = true;
    (void)pthread_join(worker->thread, NULL);
    if (worker->epollfd >= 0 && close(worker->epollfd) != 0) {
        TPSA_LOG_ERR("Failed to close epoll fd, epollfd: %d, err: %s.\n", worker->epollfd, ub_strerror(errno));
    }
}

static inline void tpsa_global_cfg_init(tpsa_global_cfg_t *global_cfg)
{
    global_cfg->mtu = UVS_MTU_1024;

    global_cfg->suspend_period = TPSA_DEFAULT_SUSPEND_PERIOD;
    global_cfg->suspend_cnt = TPSA_DEFAULT_SUSPEND_CNT;
    global_cfg->sus2err_period = TPSA_DEFAULT_SUS2ERR_PERIOD;
}

static int tpsa_set_nl_port(tpsa_nl_ctx_t *nl)
{
    /* set nl agent pid */
    tpsa_nl_msg_t msg = {0};
    msg.hdr.nlmsg_type = TPSA_NL_SET_AGENT_PID;
    msg.hdr.nlmsg_pid = (uint32_t)getpid();
    msg.hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)&msg);
    ssize_t ret = sendto(nl->fd, &msg.hdr, msg.hdr.nlmsg_len, 0,
        (struct sockaddr *)&nl->dst_addr, sizeof(struct sockaddr_nl));
    if (ret == -1) {
        (void)close(nl->fd);
        TPSA_LOG_ERR("Failed to sendto err: %s.\n", ub_strerror(errno));
        return -1;
    }
    TPSA_LOG_INFO("Finish sync UVS sip table\n");
    return 0;
}

static int tpsa_query_tpf_dev_info(tpsa_nl_ctx_t *nl)
{
    /* set nl agent pid */
    tpsa_nl_msg_t msg = {0};
    msg.hdr.nlmsg_type = TPSA_NL_QUERY_TPF_DEV_INFO;
    msg.hdr.nlmsg_pid = (uint32_t)getpid();
    msg.hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)&msg);
    ssize_t ret = sendto(nl->fd, &msg.hdr, msg.hdr.nlmsg_len, 0,
        (struct sockaddr *)&nl->dst_addr, sizeof(struct sockaddr_nl));
    if (ret == -1) {
        (void)close(nl->fd);
        TPSA_LOG_ERR("Failed to sendto err: %s.\n", ub_strerror(errno));
        return -1;
    }
    TPSA_LOG_INFO("Finish sync tpf dev info table\n");
    return 0;
}

tpsa_worker_t *tpsa_worker_init(uvs_init_attr_t *attr)
{
    tpsa_worker_t *worker = (tpsa_worker_t *)calloc(1, sizeof(tpsa_worker_t));
    if (worker == NULL) {
        return NULL;
    }

    tpsa_global_cfg_init(&worker->global_cfg_ctx);

    if (tpsa_table_init(&worker->table_ctx) != 0) {
        goto free_work;
    }

    if (tpsa_sock_server_init(&worker->sock_ctx, attr) != 0) {
        goto free_table;
    }

    if (tpsa_nl_server_init(&worker->nl_ctx) != 0) {
        goto free_sock_server;
    }

    if (tpsa_ioctl_init(&worker->ioctl_ctx) != 0) {
        goto free_nl_server;
    }

    if (tpsa_worker_thread_init(worker) != 0) {
        goto free_ioctl;
    }

    if (tpsa_set_nl_port(&worker->nl_ctx) != 0) {
        goto uninit_thread_work;
    }

    if (tpsa_query_tpf_dev_info(&worker->nl_ctx) != 0) {
        TPSA_LOG_ERR("failed to send nl msg for querying tpf dev info\n");
    }

    uvs_tp_exception_init();

    return worker;

uninit_thread_work:
    tpsa_worker_thread_uninit(worker);
free_ioctl:
    tpsa_ioctl_uninit(&worker->ioctl_ctx);
free_nl_server:
    tpsa_nl_server_uninit(&worker->nl_ctx);
free_sock_server:
    tpsa_sock_server_uninit(&worker->sock_ctx);
free_table:
    tpsa_table_uninit(&worker->table_ctx);
free_work:
    free(worker);
    return NULL;
}

void tpsa_worker_uninit(tpsa_worker_t *worker)
{
    if (worker == NULL) {
        return;
    }
    uvs_tp_exception_uninit();
    tpsa_worker_thread_uninit(worker);
    tpsa_ioctl_uninit(&worker->ioctl_ctx);
    tpsa_nl_server_uninit(&worker->nl_ctx);
    tpsa_sock_server_uninit(&worker->sock_ctx);
    tpsa_table_uninit(&worker->table_ctx);
    free(worker);
}
