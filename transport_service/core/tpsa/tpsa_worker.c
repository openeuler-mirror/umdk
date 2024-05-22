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

#include "uvs_stats.h"
#include "uvs_types.h"
#include "tpsa_log.h"
#include "ub_hash.h"
#include "uvs_private_api.h"
#include "uvs_tp_exception.h"
#include "uvs_tp_destroy.h"
#include "tpsa_worker.h"

#define TPSA_MAX_EPOLL_NUM 2048
#define TPSA_MAX_TCP_CONN 1024
#define TPSA_CM_THREAD_PRIORITY (-20)
#define TPSA_MAX_EPOLL_WAIT 16
#define TPSA_EVENT_MAX_WAIT_MS 10 // 10ms
#define TPSA_SOCK_TIMEOUT 10 /* 10s */

#define TPSA_DEFAULT_SUSPEND_PERIOD 1000 // us
#define TPSA_DEFAULT_SUSPEND_CNT 3
#define TPSA_DEFAULT_SUS2ERR_PERIOD 30000000 // us
#define TPSA_DEFAULT_WAIT_RESTORE_PERIOD 20000000 // us
#define TPSA_S2US 1000000L
#define TPSA_NS2US 1000L
#define TPSA_WAIT_LIST_RESTORE_INTERVAL 10000

/* add temporarily for 1650 not support flush tp */
static bool g_tp_fast_destroy = false;
static bool g_start_restore = false;
void tpsa_set_tp_fast_destroy(bool tp_fast_destory)
{
    g_tp_fast_destroy = tp_fast_destory;
}

bool tpsa_get_tp_fast_destroy(void)
{
    return g_tp_fast_destroy;
}

static int tpsa_handle_event_invalid(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg,
    vport_key_t *vport_key, tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
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
        uvs_lm_destroy_vtp_in_ready,      /* [STATE_READY][VTP_EVENT_SRC_DELETE] */
        tpsa_handle_event_invalid,      /* [STATE_READY][VTP_EVENT_DST_DELETE] */
        uvs_lm_refresh_tpg              /* [STATE_READY][VTP_EVENT_DIP_REFRESH] */
    },
    {
        tpsa_handle_event_invalid,      /* [STATE_MIGRATING][VTP_EVENT_SWITCH] */
        uvs_lm_swap_tpg,                /* [STATE_MIGRATING][VTP_EVENT_ROLLBACK] */
        uvs_lm_destroy_vtp_in_migrating,      /* [STATE_MIGRATING][VTP_EVENT_SRC_DELETE] */
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
    memcpy(vport_key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    tpsa_update_fe_rebooted(&worker->table_ctx.fe_table, &vport_key, true);
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
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
    };

    if (ev->data.fd != worker->sock_ctx.listen_fd) {
        tpsa_sock_msg_t *msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
        if (msg == NULL) {
            return -ENOMEM;
        }
        TPSA_LOG_DEBUG("socket msg size is %u\n", (uint32_t)sizeof(tpsa_sock_msg_t));
        static_assert(sizeof(tpsa_sock_msg_t) < TPSA_MAX_SOCKET_MSG_LEN, "socket msg size over max value");
        /* Prevent link down up sock small packets from being received multiple times, resulting in exceptions */
        if (tpsa_sock_recv_msg_timeout(ev->data.fd, (char*)msg, sizeof(tpsa_sock_msg_t),
            TPSA_SOCK_TIMEOUT, &worker->sock_ctx) != 0) {
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
                ret = uvs_handle_create_vtp_req(&ctx, msg);
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
            case TPSA_CREATE_FAIL_RESP:
                ret = uvs_hanlde_create_fail_resp(&ctx, msg);
                break;
            case TPSA_DESTROY_REQ:
                ret = uvs_handle_destroy_vtp_req(&ctx, msg);
                break;
            case TPSA_DESTROY_FINISH:
                ret = uvs_destory_vtp_finish(&ctx, msg);
                break;
            case TPSA_TABLE_SYC:
                ret = uvs_handle_table_sync(&ctx, msg);
                break;
            case TPSA_TABLE_SYC_RESP:
                ret = uvs_handle_table_sync_resp(&ctx, msg);
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

tpsa_nl_msg_t *tpsa_handle_nl_add_sip_req(tpf_dev_table_t *table, tpsa_nl_msg_t *msg)
{
    sip_table_entry_t entry_add = {0};
    tpsa_nl_add_sip_req_t *req;

    req = (tpsa_nl_add_sip_req_t *)(void *)msg->payload;
    if (strnlen(req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter, %s", req->dev_name);
        return NULL;
    }
    (void)memcpy(entry_add.dev_name, req->dev_name, UVS_MAX_DEV_NAME);
    (void)memcpy(&entry_add.addr, &req->netaddr, sizeof(uvs_net_addr_info_t));
    entry_add.port_cnt = req->port_cnt;
    (void)memcpy(entry_add.port_id, req->port_id, TPSA_MAX_PORT_CNT);
    entry_add.prefix_len = req->prefix_len;
    entry_add.mtu = (uvs_mtu_t)req->mtu;
    (void)memcpy(entry_add.netdev_name, req->netdev_name, UVS_MAX_DEV_NAME);

    if (tpsa_sip_table_add(table, req->index, &entry_add) != 0) {
        return tpsa_get_add_sip_resp(msg, TPSA_NL_RESP_FAIL);
    }
    return tpsa_get_add_sip_resp(msg, TPSA_NL_RESP_SUCCESS);
}

tpsa_nl_msg_t *tpsa_handle_nl_del_sip_req(tpf_dev_table_t *table, tpsa_nl_msg_t *msg)
{
    tpsa_nl_del_sip_req_t *req;
    req = (tpsa_nl_del_sip_req_t *)(void *)msg->payload;

    if (tpsa_sip_table_del(table, req->dev_name, req->index) != 0) {
        return tpsa_get_del_sip_resp(msg, TPSA_NL_RESP_FAIL);
    }
    return tpsa_get_del_sip_resp(msg, TPSA_NL_RESP_SUCCESS);
}

static int tpsa_worker_process_ueid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_alloc_eid_req_t *nlreq = (tpsa_nl_alloc_eid_req_t *)nlmsg->req.data;
    vport_key_t key;
    tpsa_ueid_t value;
    int ret = 0;

    if (strnlen(nlreq->tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter, %s", nlreq->tpf_name);
        return -EINVAL;
    }

    key.fe_idx = nlmsg->src_fe_idx;
    memcpy(key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);
    if (tpsa_lookup_vport_table_ueid(&key, &worker->table_ctx.vport_table, nlreq->eid_index, &value) < 0) {
        return -1;
    }

    tpsa_cmd_t cmd_type = (nlmsg->req.opcode == TPSA_MSG_ALLOC_EID) ? TPSA_CMD_ALLOC_EID : TPSA_CMD_DEALLOC_EID;
    if (tpsa_ioctl_op_ueid(&worker->ioctl_ctx, cmd_type, &key, &value, nlreq->eid_index) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to alloc/dealloc eid in worker");
        return -1;
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
    return tpsa_worker_process_ueid(worker, msg);
}

static int tpsa_worker_dealloc_ueid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    return tpsa_worker_process_ueid(worker, msg);
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
    tpf_dev_table_key_t key = {0};

    nlreq = (tpsa_nl_update_tpf_dev_info_req_t *)msg->payload;

    tpsa_nl_update_tpf_dev_info_resp_t rsp;
    (void)memset(&rsp, 0, sizeof(tpsa_nl_update_tpf_dev_info_resp_t));

    tpf_dev_table = &worker->table_ctx.tpf_dev_table;

    if (strnlen(nlreq->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter, %s", nlreq->dev_name);
        return -EINVAL;
    }
    (void)memcpy(key.dev_name, nlreq->dev_name, UVS_MAX_DEV_NAME);

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
    tpf_dev_table_key_t key = {0};

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
    if (strnlen(nlreq->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter, %s", nlreq->dev_name);
        return -EINVAL;
    }
    (void)memcpy(key.dev_name, nlreq->dev_name, UVS_MAX_DEV_NAME);

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
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
    };

    HMAP_FOR_EACH_SAFE(cur, next, node, &worker->table_ctx.live_migrate_table.hmap) {
        vport_key_t fe_key = cur->key;
        fe_table_entry_t *fe_entry = fe_table_lookup(&worker->table_ctx.fe_table, &fe_key);
        if (fe_entry == NULL) {
            TPSA_LOG_DEBUG("Can't find fe entry, there are no vtp entries that need to be migrated for this vf.\n");
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
        vport_key_t vport_key = {0};
        if (vtp_entry->node_status != STATE_READY || vtp_entry->vice_tpgn == UINT32_MAX) {
            TPSA_LOG_DEBUG("The virtual machine does not meet the switching conditions for rm mode.\n");
            continue;
        }
        int ret = g_tpsa_worker_vtp_event_handler[vtp_entry->node_status][VTP_EVENT_DIP_REFRESH](ctx, &vtp_cfg,
            &vport_key, &cur->entry, NULL);
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
        vport_key_t vport_key = {0};
        rc_vtp_table_entry_t *vtp_entry = cur->entry.content.rc_entry;
        if (vtp_entry->node_status != STATE_READY || vtp_entry->vice_tpgn == UINT32_MAX) {
            TPSA_LOG_DEBUG("The virtual machine does not meet the switching conditions for rc mode.\n");
            continue;
        }
        int ret = g_tpsa_worker_vtp_event_handler[vtp_entry->node_status][VTP_EVENT_DIP_REFRESH](ctx, &vtp_cfg,
            &vport_key, &cur->entry, NULL);
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
        vport_key_t vport_key = {0};
        um_vtp_table_entry_t *vtp_entry = cur->entry.content.um_entry;
        if (vtp_entry->node_status != STATE_NORMAL) {
            TPSA_LOG_DEBUG("The virtual machine does not meet the switching conditions  for um mode.\n");
            continue;
        }
        int ret = g_tpsa_worker_vtp_event_handler[vtp_entry->node_status][VTP_EVENT_DIP_REFRESH](ctx, &vtp_cfg,
            &vport_key, &cur->entry, NULL);
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
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
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
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
    };

    uvs_clean_deleted_vport(&ctx);
    return;
}

static void tpsa_clean_rebooted_fe(tpsa_worker_t *worker)
{
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .sock_ctx = &worker->sock_ctx,
        .nl_ctx = &worker->nl_ctx,
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
    };

    uvs_clean_rebooted_fe(&ctx);
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
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
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
        .ioctl_ctx = &worker->ioctl_ctx,
        .tpsa_attr = worker->tpsa_attr,
    };

    tpsa_nl_migrate_vtp_req_t *mig_req = (tpsa_nl_migrate_vtp_req_t *)msg->payload;
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

    if (strnlen(mig_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
            TPSA_LOG_ERR("Invalid parameter, %s", mig_req->dev_name);
            return -EINVAL;
    }
    vport_key_t vport_key = {0};
    vport_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(vport_key.tpf_name, mig_req->dev_name, UVS_MAX_DEV_NAME);
    if (msg->msg_type == TPSA_NL_MIGRATE_VTP_SWITCH) {
        ret = g_tpsa_worker_vtp_event_handler[node_status][VTP_EVENT_SWITCH](&ctx, vtp_cfg,
            &vport_key, lm_vtp_entry, NULL);
    } else {
        ret = g_tpsa_worker_vtp_event_handler[node_status][VTP_EVENT_ROLLBACK](&ctx, vtp_cfg,
            &vport_key, lm_vtp_entry, NULL);
    }
    free(lm_vtp_entry);
    return ret;
}

int uvs_destroy_target_vtp_for_lm(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_lm_vtp_entry_t lm_vtp_entry;
    tpsa_vtp_cfg_t vtp_cfg;
    vport_key_t vport_key = {0};
    vtp_node_state_t *node_status;

    if (tp_msg_ctx->trans_mode == TPSA_TP_RM) {
        rm_vtp_table_key_t vtp_key = {
            .src_eid = tp_msg_ctx->src.eid,
            .dst_eid = tp_msg_ctx->dst.eid,
        };
        rm_vtp_table_entry_t *vtp_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
                                                                 &tp_msg_ctx->vport_ctx.key, &vtp_key);
        if (vtp_entry == NULL) {
            return -1;
        }
        lm_vtp_entry.trans_mode = TPSA_TP_RM;
        lm_vtp_entry.content.rm_entry = vtp_entry;
        node_status = &(vtp_entry->node_status);
    } else {
        rc_vtp_table_key_t vtp_key = {
            .dst_eid = tp_msg_ctx->dst.eid,
            .jetty_id = tp_msg_ctx->dst.jetty_id,
        };
        rc_vtp_table_entry_t *vtp_entry = rc_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
                                                                 &tp_msg_ctx->vport_ctx.key, &vtp_key);
        if (vtp_entry == NULL) {
            return -1;
        }
        lm_vtp_entry.trans_mode = TPSA_TP_RC;
        lm_vtp_entry.content.rc_entry = vtp_entry;
        node_status = &(vtp_entry->node_status);
    }

    int ret = g_tpsa_worker_vtp_event_handler[*node_status][VTP_EVENT_SRC_DELETE](ctx, &vtp_cfg,
        &vport_key, &lm_vtp_entry, tp_msg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("handle vtp_event_src_delete failed when node status is %d.\n", (int)(*node_status));
        return ret;
    }

    *node_status = STATE_NORMAL;

    return 0;
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

    if (strnlen(query_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
            TPSA_LOG_ERR("Invalid parameter, %s", query_req->dev_name);
            return NULL;
    }

    return_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (return_entry == NULL) {
        return NULL;
    }
    (void)memcpy(key.tpf_name, query_req->dev_name, UVS_MAX_DEV_NAME);
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
            resp = tpsa_handle_nl_add_sip_req(&worker->table_ctx.tpf_dev_table, msg);
            break;
        case TPSA_NL_DEL_SIP_REQ:
            resp = tpsa_handle_nl_del_sip_req(&worker->table_ctx.tpf_dev_table, msg);
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

static int get_vtp_table_from_ubcore(int ubcore_fd, tpsa_ioctl_cfg_t **restore_vtp_tbl_cfg, uint32_t *vtp_cnt)
{
    tpsa_ioctl_cfg_t *ioctl_cfg;
    uint32_t arg_len, cnt;
    int32_t ret;

    /* IOCTL to get vtp table cnt */
    tpsa_ioctl_cfg_t *get_tbl_cnt_cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (get_tbl_cnt_cfg == NULL) {
        return -ENOMEM;
    }
    tpsa_ioctl_cmd_get_vtp_table_cnt(get_tbl_cnt_cfg);
    if (tpsa_ioctl(ubcore_fd, get_tbl_cnt_cfg) != 0) {
        TPSA_LOG_WARN("Fail to ioctl to get vtp table cnt");
        ret = -1;
        goto free_get_tbl_cnt_cfg;
    }

    cnt = get_tbl_cnt_cfg->cmd.get_vtp_table_cnt.out.vtp_cnt;
    if (cnt == 0) {
        ret = 0;
        TPSA_LOG_INFO("No VTP table need to restore");
        goto free_get_tbl_cnt_cfg;
    }

    /* IOCTL to restore table */
    arg_len = (uint32_t)sizeof(tpsa_ioctl_cfg_t) + cnt * (uint32_t)sizeof(tpsa_restored_vtp_entry_t);
    ioctl_cfg = (tpsa_ioctl_cfg_t *)calloc(1, arg_len);
    if (ioctl_cfg == NULL) {
        ret = -ENOMEM;
        goto free_get_tbl_cnt_cfg;
    }
    tpsa_ioctl_cmd_restore_vtp_table(ioctl_cfg, cnt);
    if (tpsa_ioctl(ubcore_fd, ioctl_cfg) != 0) {
        TPSA_LOG_WARN("Fail to ioctl to get vtp table from ubcore");
        ret = -1;
        goto free_restore_vtp_tbl_cfg;
    }

    *vtp_cnt = cnt;
    *restore_vtp_tbl_cfg = ioctl_cfg;
    return 0;

free_restore_vtp_tbl_cfg:
    free(ioctl_cfg);

free_get_tbl_cnt_cfg:
    free(get_tbl_cnt_cfg);
    return ret;
}

static int find_restored_table_param(tpsa_table_t *table_ctx, char *dev_name, dip_table_key_t *dip_key,
    uint32_t sip_idx, tpsa_restored_table_param_t *rparam)
{
    dip_table_entry_t *dip_entry = NULL;
    sip_table_entry_t sip_entry = {0};

    (void)pthread_rwlock_rdlock(&table_ctx->dip_table.rwlock);
    dip_entry = dip_table_lookup(&table_ctx->dip_table, dip_key);
    if (dip_entry != NULL) {
        rparam->dip = dip_entry->netaddr;
    } else {
        (void)pthread_rwlock_unlock(&table_ctx->dip_table.rwlock);
        TPSA_LOG_INFO("can not find dip_idx, peer_eid: " EID_FMT ", upi: %u\n", EID_ARGS(dip_key->deid), dip_key->upi);
        return -1;
    }
    (void)pthread_rwlock_unlock(&table_ctx->dip_table.rwlock);

    tpsa_sip_table_lookup(&table_ctx->tpf_dev_table, dev_name, sip_idx, &sip_entry);
    if (sip_entry.used) {
        rparam->sip = sip_entry.addr;
    } else {
        TPSA_LOG_INFO("can not find sip entry by key sip_idx %d, dev_name: %s, add to wait list\n",
            sip_idx, dev_name);
        return -1;
    }

    return 0;
}

static int insert_rm_tpg_table(tpsa_table_t *table_ctx, tpsa_restored_table_param_t* rparam,
    wait_restored_entry_t *restored_entry)
{
    tpsa_tpg_table_param_t tpsa_tpg_table_param = {0};
    rm_tpg_table_entry_t *rm_tpg_table_entry;
    rm_tpg_table_key_t rm_tpg_table_key;

    // first lookup, then add
    rm_tpg_table_key.dip = rparam->dip;
    rm_tpg_table_entry = rm_tpg_table_lookup(&table_ctx->rm_tpg_table, &rm_tpg_table_key);
    if (rm_tpg_table_entry != NULL) {
        rm_tpg_table_entry->use_cnt++;
        return 0;
    }

    tpsa_tpg_table_param.tpgn = restored_entry->entry.index.tpgn;
    tpsa_tpg_table_param.tp_cnt = restored_entry->entry.tp_cnt;
    tpsa_tpg_table_param.status = TPSA_TPG_LOOKUP_EXIST;
    tpsa_tpg_table_param.use_cnt = 1;
    tpsa_tpg_table_param.ljetty_id = restored_entry->entry.local_jetty;
    tpsa_tpg_table_param.leid = restored_entry->entry.local_eid;
    tpsa_tpg_table_param.dip = rparam->dip;
    tpsa_tpg_table_param.isLoopback = memcmp(&rparam->sip, &rparam->dip, sizeof(uvs_net_addr_info_t)) == 0;
    (void)memcpy(tpsa_tpg_table_param.tpn, restored_entry->entry.tpn,
                 TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
    if (rm_tpg_table_add(&table_ctx->rm_tpg_table, &rm_tpg_table_key, &tpsa_tpg_table_param) < 0) {
        TPSA_LOG_WARN("Fail to add rm_tpg_table");
        return -1;
    } else {
        TPSA_LOG_INFO("rm_tpg_table succeed, key: {" EID_FMT "}", EID_ARGS(rparam->dip.net_addr));
    }

    return 0;
}

static int insert_um_utp_table(tpsa_table_t *table_ctx, tpsa_restored_table_param_t *rparam,
    uint32_t utp_idx)
{
    utp_table_entry_t *utp_table_entry = NULL;
    utp_table_key_t utp_key;

    // first lookup, then add
    utp_key.sip = rparam->sip;
    utp_key.dip = rparam->dip;
    utp_table_entry = utp_table_lookup(&table_ctx->utp_table, &utp_key);
    if (utp_table_entry != NULL) {
        utp_table_entry->use_cnt++;
        return 0;
    }

    if (utp_table_add(&table_ctx->utp_table, &utp_key, utp_idx) < 0) {
        TPSA_LOG_WARN("Fail to add utp_table");
        return -1;
    } else {
        TPSA_LOG_INFO("utp_table_add succeed, key: {" EID_FMT ", " EID_FMT "}",
            EID_ARGS(utp_key.sip.net_addr), EID_ARGS(utp_key.dip.net_addr));
    }

    return 0;
}

static int insert_rm_vtp_table(tpsa_table_t *table_ctx, wait_restored_entry_t *restored_entry,
    uint32_t upi, bool share_mode)
{
    rm_vtp_table_entry_t *vtp_table_entry;
    vport_key_t vport_key = {0};
    rm_vtp_table_key_t vtp_key;
    uint32_t eid_index;
    int ret;

    vport_key.fe_idx = restored_entry->entry.fe_idx;
    (void)memcpy(vport_key.tpf_name, restored_entry->entry.dev_name, UVS_MAX_DEV_NAME);

    vtp_key.src_eid = restored_entry->entry.local_eid;
    vtp_key.dst_eid = restored_entry->entry.peer_eid;

    vtp_table_entry = rm_fe_vtp_table_lookup(&table_ctx->fe_table, &vport_key, &vtp_key);
    if (vtp_table_entry != NULL) {
        TPSA_LOG_INFO("VTP table already exists, fe_idx: %d, tpf_name: %s", vport_key.fe_idx, vport_key.tpf_name);
    } else {
        if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, upi, &restored_entry->entry.local_eid,
            &vport_key, &eid_index) != 0) {
            TPSA_LOG_INFO("find eid index failed");
            return -1;
        }

        tpsa_vtp_table_param_t vtp_param = {
            .vtpn = restored_entry->entry.vtpn,
            .tpgn = restored_entry->entry.index.tpgn,
            .valid = true,
            .location = restored_entry->entry.location,
            .local_jetty = restored_entry->entry.local_jetty,
            .eid_index = eid_index,
            .upi = upi,
            .local_eid = restored_entry->entry.local_eid,
            .share_mode = share_mode,
            .tpg_param = {0},
        };
        vtp_param.tpg_param.tp_cnt = restored_entry->entry.tp_cnt;
        vtp_param.tpg_param.tpgn = restored_entry->entry.index.tpgn;
        (void)memcpy(vtp_param.tpg_param.tpn, restored_entry->entry.tpn,
            TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

        // RM VTP table insert
        ret = rm_fe_vtp_table_add(table_ctx, &vport_key, &vtp_key, &vtp_param);
        if (ret < 0) {
            TPSA_LOG_WARN("Fail to add um_vtp_table");
            return -1;
        }
    }
    return 0;
}

static int insert_um_vtp_table(tpsa_table_t *table_ctx, wait_restored_entry_t *restored_entry,
    uint32_t upi)
{
    um_vtp_table_entry_t *vtp_table_entry;
    um_vtp_table_key_t vtp_key;
    vport_key_t vport_key = {0};
    int ret;

    vport_key.fe_idx = restored_entry->entry.fe_idx;
    (void)memcpy(vport_key.tpf_name, restored_entry->entry.dev_name, UVS_MAX_DEV_NAME);
    vtp_key.src_eid = restored_entry->entry.local_eid;
    vtp_key.dst_eid = restored_entry->entry.peer_eid;
    vtp_table_entry = um_fe_vtp_table_lookup(&table_ctx->fe_table, &vport_key, &vtp_key);
    if (vtp_table_entry != NULL) {
        TPSA_LOG_INFO("VTP table already exists, fe_idx: %d, tpf_name: %s", vport_key.fe_idx, vport_key.tpf_name);
    } else {
        tpsa_um_vtp_table_param_t uvtp_param = {
            .vtpn = restored_entry->entry.vtpn,
            .utp_idx = restored_entry->entry.index.utp_idx,
            .upi = upi,
        };

        ret = um_fe_vtp_table_add(table_ctx, &vport_key, &vtp_key, &uvtp_param);
        if (ret < 0) {
            TPSA_LOG_WARN("Fail to add um_vtp_table");
            return -1;
        }
    }

    return 0;
}

static int insert_restored_table(tpsa_table_t *table_ctx, wait_restored_entry_t *restored_entry,
    tpsa_restored_table_param_t* rparam, uint32_t upi)
{
    vport_table_entry_t *vport_entry = NULL;
    vport_key_t vport_key = {0};
    bool share_mode = false;

    int ret = 0;

    if (restored_entry->entry.trans_mode == URMA_TM_UM) {
        ret = insert_um_utp_table(table_ctx, rparam, restored_entry->entry.index.utp_idx);
        if (ret != 0) {
            return ret;
        }

        return insert_um_vtp_table(table_ctx, restored_entry, upi);
    } else if (restored_entry->entry.trans_mode == URMA_TM_RM) {
        vport_key.fe_idx = restored_entry->entry.fe_idx;
        (void)memcpy(vport_key.tpf_name, restored_entry->entry.dev_name, UVS_MAX_DEV_NAME);
        vport_entry = vport_table_lookup(&table_ctx->vport_table, &vport_key);
        if (vport_entry == NULL) {
            TPSA_LOG_ERR("cannot find vport entry, dev_name: %s, fe_idx: %u", vport_key.tpf_name, vport_key.fe_idx);
            return -1;
        }
        share_mode = vport_entry->tp_cfg.tp_mod_flag.bs.share_mode;
        if (share_mode) {
            ret = insert_rm_tpg_table(table_ctx, rparam, restored_entry);
            if (ret != 0) {
                return ret;
            }
        }
        // RM VTP table restore
        return insert_rm_vtp_table(table_ctx, restored_entry, upi, share_mode);
    }
    return 0;
}

static int handle_single_tbl_restore(tpsa_table_t *tbl_ctx, wait_restored_entry_t *restored_entry,
    bool sleep_when_fail)
{
    tpsa_restored_table_param_t rparam;
    tpsa_restored_vtp_entry_t *e;
    vport_key_t vport_key = {0};
    dip_table_key_t dip_key = {0};
    uint32_t upi;

    e = &restored_entry->entry;
    vport_key.fe_idx = e->fe_idx;
    (void)memcpy(vport_key.tpf_name, e->dev_name, UVS_MAX_DEV_NAME);
    if (tpsa_lookup_upi_by_eid(&vport_key, &tbl_ctx->vport_table, &e->local_eid, &upi) != 0) {
        TPSA_LOG_WARN("cannot find upi, fe_idx: %d, tpf_name: %s, local_eid: " EID_FMT "\n", vport_key.fe_idx,
            vport_key.tpf_name, EID_ARGS(e->local_eid));
        // add to tail of wait list
        wait_restored_list_add_restored_entry(&tbl_ctx->wait_restored_list, restored_entry);
        (void)(sleep_when_fail && usleep(TPSA_WAIT_LIST_RESTORE_INTERVAL));
        return -1;
    }

    dip_key.deid = e->peer_eid;
    dip_key.upi = upi;
    if (find_restored_table_param(tbl_ctx, e->dev_name, &dip_key, e->sip_idx, &rparam) != 0) {
        TPSA_LOG_WARN("cannot find utp key, tpf_name: %s, peer_eid: " EID_FMT ", upi: %d, sip_idx: %d\n",
            e->dev_name, EID_ARGS(dip_key.deid), dip_key.upi, e->sip_idx);
        // add to tail of wait list
        wait_restored_list_add_restored_entry(&tbl_ctx->wait_restored_list, restored_entry);
        (void)(sleep_when_fail && usleep(TPSA_WAIT_LIST_RESTORE_INTERVAL));
    } else {
        TPSA_LOG_INFO("utp key found, tpf_name: %s, peer_eid: " EID_FMT ", upi: %d, sip_idx: %d\n",
            e->dev_name, EID_ARGS(dip_key.deid), dip_key.upi, e->sip_idx);

        if (insert_restored_table(tbl_ctx, restored_entry, &rparam, upi) != 0) {
            TPSA_LOG_WARN("Fail to insert restored vtp table");
        } else {
            TPSA_LOG_INFO("VTP table add success, fe_idx: %d, tpf_name: %s", e->fe_idx, e->dev_name);
        }
        free(restored_entry);
    }
    return 0;
}

int tpsa_restore_vtp_table(tpsa_worker_t *worker)
{
    tpsa_restored_vtp_entry_t *restored_vtp_entry;
    wait_restored_entry_t *wait_restored_entry;
    tpsa_ioctl_cfg_t *restore_vtp_tbl_cfg = NULL;
    uint32_t vtp_cnt = 0, i;
    int ret = 0;

    if (get_vtp_table_from_ubcore(worker->ioctl_ctx.ubcore_fd, &restore_vtp_tbl_cfg, &vtp_cnt) != 0) {
        TPSA_LOG_ERR("Fail to get vtp table from ubcore");
        return -1;
    }

    // got tables from ubcore, then we should restore these tables
    for (i = 0; i < vtp_cnt; i++) {
        restored_vtp_entry = &restore_vtp_tbl_cfg->cmd.restore_vtp_table.out.entry[i];
        wait_restored_entry = (wait_restored_entry_t *)calloc(1, sizeof(wait_restored_entry_t));
        if (wait_restored_entry == NULL) {
            TPSA_LOG_ERR("Fail to malloc wait_restored_entry_t when add entry.\n");
            continue;
        }

        if (clock_gettime(CLOCK_REALTIME, &wait_restored_entry->start_timeval) != 0) {
            TPSA_LOG_ERR("Failed to clock_gettime when add entry.\n");
            free(wait_restored_entry);
            continue;
        }

        (void)memcpy(&wait_restored_entry->entry, restored_vtp_entry, sizeof(tpsa_restored_vtp_entry_t));
        (void)handle_single_tbl_restore(&worker->table_ctx, wait_restored_entry, false);
    }

    if (restore_vtp_tbl_cfg != NULL) {
        free(restore_vtp_tbl_cfg);
    }

    return ret;
}

static bool tpsa_is_wait_entry_timeout(struct timespec* start_timeval, uint32_t wait_restored_timeout)
{
    long time_diff;
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        TPSA_LOG_WARN("Failed to clock_gettime.\n");
        return true;
    }

    time_diff = (now.tv_sec - start_timeval->tv_sec) * TPSA_S2US +
        (now.tv_nsec - start_timeval->tv_nsec) / TPSA_NS2US;
    return time_diff > wait_restored_timeout;
}

int tpsa_restore_wait_list(tpsa_table_t *tbl_ctx, uint32_t wait_restored_timeout)
{
    wait_restored_entry_t *restored_entry;
    tpsa_restored_vtp_entry_t *e;

    UB_LIST_FOR_EACH_POP_FRONT(restored_entry, node, &tbl_ctx->wait_restored_list.list) {
        e = &restored_entry->entry;
        if (tpsa_is_wait_entry_timeout(&restored_entry->start_timeval, wait_restored_timeout)) {
            TPSA_LOG_INFO("table entry timeout, fe_idx: %d, vtpn: %d, local_jetty: %d, peer_jetty: %d, sip_idx: %d, \
                trans_mode: %d, tpgn: %d, dev_name: %s\n", e->fe_idx, e->vtpn, e->local_jetty, e->peer_jetty,
                e->sip_idx, (int)e->trans_mode, e->index.tpgn, e->dev_name);
            free(restored_entry);
            continue;
        }

        if (handle_single_tbl_restore(tbl_ctx, restored_entry, true) != 0) {
            return 0;
        }
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
                tpsa_del_socket(&worker->sock_ctx, events[i].data.fd);
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
        tpsa_clean_rebooted_fe(worker);
        if (g_start_restore) {
            static bool restore_flag = true;
            if (restore_flag) {
                if (tpsa_restore_vtp_table(worker) != 0) {
                    continue;
                }
                restore_flag = false;
            }
            if (tpsa_restore_wait_list(&worker->table_ctx, worker->global_cfg_ctx.wait_restored_timeout) != 0) {
                TPSA_LOG_ERR("restore table from ubcore failed\n");
                continue;
            }
        }
    }
    return NULL;
}

static int tpsa_worker_thread_init(tpsa_worker_t *worker)
{
    int ret;
    pthread_attr_t attr;
    int epollfd;

    if (uvs_ops_lock_init() != 0) {
        TPSA_LOG_ERR("Failed to init uvs ops lock.\n");
        return -1;
    }

    epollfd = epoll_create(TPSA_MAX_EPOLL_NUM);
    if (epollfd < 0) {
        uvs_ops_lock_uninit();
        TPSA_LOG_ERR("Failed to create epoll fd, nl->epollfd: %d, err: %s.\n",
            epollfd, ub_strerror(errno));
        return -1;
    }

    if (tpsa_add_epoll_event(epollfd, worker->nl_ctx.fd, EPOLLIN) != 0) {
        uvs_ops_lock_uninit();
        TPSA_LOG_ERR("Add epoll event failed.\n");
        (void)close(epollfd);
        return -1;
    }

    (void)pthread_attr_init(&attr);
    worker->stop = false;
    worker->epollfd = epollfd;
    ret = pthread_create(&worker->thread, &attr, tpsa_thread_main, worker);
    if (ret != 0) {
        TPSA_LOG_ERR("pthread create failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
    } else {
        TPSA_LOG_INFO("thread listen (ep_fd=%d, ADD, nl_fd=%d) succeed.\n", epollfd, worker->nl_ctx.fd);
    }
    (void)pthread_attr_destroy(&attr);
    return ret;
}

static void tpsa_epollfd_close(tpsa_worker_t *worker)
{
    if (worker->epollfd >= 0 && close(worker->epollfd) != 0) {
        TPSA_LOG_ERR("Failed to close epoll fd, epollfd: %d, err: %s.\n", worker->epollfd, ub_strerror(errno));
    }
}

static void tpsa_worker_thread_uninit(tpsa_worker_t *worker)
{
    worker->stop = true;
    (void)pthread_join(worker->thread, NULL);
    uvs_ops_lock_uninit();
}

static inline void tpsa_global_cfg_init(tpsa_global_cfg_t *global_cfg)
{
    global_cfg->mtu = UVS_MTU_1024;

    global_cfg->suspend_period = TPSA_DEFAULT_SUSPEND_PERIOD;
    global_cfg->suspend_cnt = TPSA_DEFAULT_SUSPEND_CNT;
    global_cfg->sus2err_period = TPSA_DEFAULT_SUS2ERR_PERIOD;
    global_cfg->wait_restored_timeout = TPSA_DEFAULT_WAIT_RESTORE_PERIOD;
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
    TPSA_LOG_INFO("Finish sync ubcore table info\n");
    g_start_restore = true;
    return 0;
}

tpsa_worker_t *tpsa_worker_init(uvs_init_attr_t *attr)
{
    if (attr == NULL) {
        return NULL;
    }

    tpsa_worker_t *worker = (tpsa_worker_t *)calloc(1, sizeof(tpsa_worker_t));
    if (worker == NULL) {
        return NULL;
    }

    worker->sock_ctx.listen_fd = -1;
    tpsa_global_cfg_init(&worker->global_cfg_ctx);

    if (tpsa_table_init(&worker->table_ctx) != 0) {
        goto free_work;
    }

    if (tpsa_nl_server_init(&worker->nl_ctx) != 0) {
        goto free_table;
    }

    if (tpsa_ioctl_init(&worker->ioctl_ctx) != 0) {
        goto free_nl_server;
    }

    if (uvs_statistic_ctx_init(&worker->statistic_ctx) != 0) {
        goto free_ioctl;
    }

    if (tpsa_worker_thread_init(worker) != 0) {
        goto free_statistic_ctx;
    }

    if (tpsa_set_nl_port(&worker->nl_ctx) != 0) {
        goto uninit_thread_work;
    }

    uvs_tp_exception_init();

    return worker;

uninit_thread_work:
    tpsa_worker_thread_uninit(worker);
free_statistic_ctx:
    uvs_statistic_ctx_uninit(&worker->statistic_ctx);
free_ioctl:
    tpsa_ioctl_uninit(&worker->ioctl_ctx);
free_nl_server:
    tpsa_nl_server_uninit(&worker->nl_ctx);
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
    uvs_statistic_ctx_uninit(&worker->statistic_ctx);
    tpsa_ioctl_uninit(&worker->ioctl_ctx);
    tpsa_nl_server_uninit(&worker->nl_ctx);
    tpsa_epollfd_close(worker);
    tpsa_table_uninit(&worker->table_ctx);
    free(worker);
}

int tpsa_worker_socket_init(tpsa_worker_t *worker)
{
    int ret;

    ret = listen(worker->sock_ctx.listen_fd, TPSA_MAX_TCP_CONN);
    if (ret < 0) {
        TPSA_LOG_ERR("Server socket listen failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
        return -1;
    }

    ret = tpsa_add_epoll_event(worker->epollfd, worker->sock_ctx.listen_fd, EPOLLIN);
    if (ret != 0) {
        return -1;
    }

    TPSA_LOG_INFO("thread listen (sock_listen_fd=%d) succeed.\n", worker->sock_ctx.listen_fd);
    return 0;
}