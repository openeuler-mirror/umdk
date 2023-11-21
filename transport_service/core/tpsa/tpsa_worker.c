/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa worker implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port core routines from daemon here
 */

#define _GNU_SOURCE
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
#define TPSA_NON_VIRTUALIZATION_FE_IDX 0xffff

#define TPSA_DEFAULT_SUSPEND_PERIOD 1000 // us
#define TPSA_DEFAULT_SUSPEND_CNT 3
#define TPSA_DEFAULT_SUS2ERR_PERIOD 30000000
#define TPSA_MTU_BITS_BASE_SHIFT 7

static void tpsa_config_device_default_value(tpsa_nl_config_device_resp_t *resp, tpsa_nl_config_device_req_t *req)
{
    resp->rc_cnt = req->max_rc_cnt;
    resp->rc_depth = req->max_rc_depth;
    resp->slice = req->max_slice;
}

static int tpsa_worker_config_device(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_config_device_req_t *nlreq = (tpsa_nl_config_device_req_t *)nlmsg->data;
    vport_table_entry_t entry = {0};
    tpsa_nl_config_device_resp_t rsp = {0};

    tpsa_config_device_default_value(&rsp, nlreq);

    vport_key_t vport_key = {0};
    vport_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(vport_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    int res = tpsa_lookup_vport_table(&vport_key,
                                      &worker->table_ctx.vport_table,
                                      &entry);
    if (res != 0) {
        TPSA_LOG_ERR("Not find vport config in fe_idx %hu, use default value\n", nlmsg->hdr.ep.src_function_id);
    } else {
        if (rsp.rc_cnt != 0 && entry.rc_cfg.rc_cnt < nlreq->max_rc_cnt) {
            rsp.rc_cnt = entry.rc_cfg.rc_cnt;
        }

        if (rsp.rc_depth != 0 && entry.rc_cfg.rc_depth < nlreq->max_rc_depth) {
            rsp.rc_depth = entry.rc_cfg.rc_depth;
        }

        if (rsp.slice != 0 && (rsp.slice >= nlreq->min_slice && rsp.slice <= nlreq->max_slice)) {
            rsp.slice = entry.rc_cfg.slice;
        } else {
            rsp.slice = nlreq->max_slice;
        }
    }

    rsp.is_tpf_dev = nlreq->is_tpf_dev;
    if (nlreq->is_tpf_dev == true) {
        tpsa_global_cfg_t *global_cfg = &worker->global_cfg_ctx;
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
        .ioctl_ctx = &worker->ioctl_ctx,
        .nl_ctx = &worker->nl_ctx,
        .sock_ctx = &worker->sock_ctx,
    };

    if (ev->data.fd != worker->sock_ctx.listen_fd) {
        tpsa_sock_msg_t *msg = calloc(1, sizeof(tpsa_sock_msg_t));
        if (msg == NULL) {
            TPSA_LOG_ERR("Failed to alloc msg\n");
            return -1;
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
            case TPSA_LM_CREATE_REQ:
                ret = uvs_lm_handle_req(&ctx, msg);
                break;
            case TPSA_LM_RESP:
                ret = uvs_lm_handle_resp(&ctx, msg);
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
        return 0;
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

static int tpsa_worker_alloc_eid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_alloc_eid_req_t *nlreq = (tpsa_nl_alloc_eid_req_t *)nlmsg->data;
    vport_key_t key;
    tpsa_ueid_t *ueid = NULL;
    tpsa_ueid_t value;
    int ret = 0;

    key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);
    (void)pthread_rwlock_rdlock(&worker->table_ctx.vport_table.rwlock);
    ueid = tpsa_lookup_vport_table_ueid(&key, nlreq->eid_index, &worker->table_ctx.vport_table);
    if (ueid == NULL) {
        (void)pthread_rwlock_unlock(&worker->table_ctx.vport_table.rwlock);
        return -1;
    }
    value = *ueid;
    (void)pthread_rwlock_unlock(&worker->table_ctx.vport_table.rwlock);

    /* IOCTL to add ueid */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create cfg request");
        return -1;
    }
    cfg->cmd_type = TPSA_CMD_ALLOC_EID;
    tpsa_init_ueid_cfg(cfg, nlreq, nlmsg->hdr.ep.src_function_id, value);
    (void)memcpy(cfg->cmd.op_eid.in.dev_name, (nlreq->virtualization == true ? nlreq->tpfdev_name : nlreq->dev_name),
        TPSA_MAX_DEV_NAME);
    if (nlreq->virtualization && tpsa_ioctl(worker->ioctl_ctx.ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to alloc eid in worker");
        ret = -1;
        goto free_cfg;
    }

    /* Netlink to notify vtpn */
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_dicover_eid_resp(msg, &value, nlreq->eid_index);
    if (nlresp == NULL) {
        ret = -1;
        goto free_cfg;
    }

    if (tpsa_nl_send_msg(&worker->nl_ctx, nlresp) != 0) {
        ret = -1;
        goto free_resp;
    }
    TPSA_LOG_INFO("success add ueid msg send pf.\n");

free_resp:
    free(nlresp);
free_cfg:
    free(cfg);
    return ret;
}

static int tpsa_worker_dealloc_eid(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_dealloc_eid_req_t *nlreq = (tpsa_nl_dealloc_eid_req_t *)nlmsg->data;
    vport_key_t key;
    tpsa_ueid_t *ueid = NULL;
    tpsa_ueid_t value;
    int ret = 0;

    key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);
    (void)pthread_rwlock_rdlock(&worker->table_ctx.vport_table.rwlock);
    ueid = tpsa_lookup_vport_table_ueid(&key, nlreq->eid_index, &worker->table_ctx.vport_table);
    if (ueid == NULL) {
        (void)pthread_rwlock_unlock(&worker->table_ctx.vport_table.rwlock);
        return -1;
    }
    value = *ueid;
    (void)pthread_rwlock_unlock(&worker->table_ctx.vport_table.rwlock);

    /* IOCTL to add ueid */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create cfg request");
        return -1;
    }
    cfg->cmd_type = TPSA_CMD_DEALLOC_EID;
    tpsa_init_ueid_cfg(cfg, nlreq, nlmsg->hdr.ep.src_function_id, value);
    (void)memcpy(cfg->cmd.op_eid.in.dev_name, (nlreq->virtualization == true ? nlreq->tpfdev_name : nlreq->dev_name),
        TPSA_MAX_DEV_NAME);
    if (nlreq->virtualization && tpsa_ioctl(worker->ioctl_ctx.ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to dealloc eid in worker");
        ret = -1;
        goto free_cfg;
    }
    /* Netlink to notify resp */
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_dicover_eid_resp(msg, &value, nlreq->eid_index);
    if (nlresp == NULL) {
        ret = -1;
        goto free_cfg;
    }
    if (tpsa_nl_send_msg(&worker->nl_ctx, nlresp) != 0) {
        ret = -1;
        goto free_resp;
    }
    TPSA_LOG_INFO("success add ueid msg send pf.\n");

free_resp:
    free(nlresp);
free_cfg:
    free(cfg);
    return ret;
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

static int tpsa_worker_update_tpf_dev_info(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_update_tpf_dev_info_req_t *nlreq;
    tpf_dev_table_entry_t add_entry = {0};
    tpsa_cc_entry_t *cc_entry;
    tpf_dev_table_t *tpf_dev_table;
    tpf_dev_table_key_t key;

    nlreq = (tpsa_nl_update_tpf_dev_info_req_t *)msg->payload;
    cc_entry = (tpsa_cc_entry_t *)nlreq->data;

    uint32_t cc_entry_cnt = nlreq->cc_entry_cnt;
    tpsa_nl_update_tpf_dev_info_resp_t rsp = {0};

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

static int tpsa_vtp_table_migrate(tpsa_worker_t *worker, live_migrate_table_entry_t *cur, fe_table_entry_t *fe_entry)
{
    int ret;
    tpsa_sock_msg_t *req = NULL;

    req = calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        TPSA_LOG_ERR("Fail to create live migrate request");
        return -1;
    }
    req->content.lmmsg.fe_idx = cur->key.fe_idx;
    req->content.lmmsg.stop_proc_vtp = fe_entry->stop_proc_vtp;
    (void)memcpy(req->content.lmmsg.dev_name, fe_entry->key.dev_name, TPSA_MAX_DEV_NAME);

    tpsa_vtp_table_index_t vtp_idx = {0};
    ret = tpsa_get_vtp_idx(fe_entry->key.fe_idx, fe_entry->key.dev_name, &vtp_idx, &worker->table_ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to get vtp idx to find peer tpsa address");
        goto free_live_migrate;
    }
    req->upi = vtp_idx.upi;
    req->local_eid = vtp_idx.local_eid;

    if (fe_entry->full_migrate == true) {
        /* Start full migration */
        ret = uvs_lm_vtp_table_full_migrate(fe_entry, req);
    } else {
        ret = uvs_lm_vtp_table_iterative_migrate(fe_entry, req);
    }

    if (ret != 0) {
        TPSA_LOG_ERR("Fail to copy vtp table to live migrate request");
        goto free_live_migrate;
    }
    req->msg_type = TPSA_LM_CREATE_REQ;
    req->content.lmmsg.mig_source = cur->dip;
    if (tpsa_sock_send_msg(&worker->sock_ctx, req, sizeof(tpsa_sock_msg_t), cur->dip) != 0) {
        TPSA_LOG_ERR("Failed to send live migrate message in worker\n");
        ret = -1;
        goto free_live_migrate;
    }

    ret = 0;

free_live_migrate:
    free(req);
    return ret;
}

static void tpsa_live_migrate_begin(tpsa_worker_t *worker)
{
    live_migrate_table_entry_t *cur, *next;
    int ret;

    if (worker->table_ctx.live_migrate_table.hmap.count == 0) {
        return;
    }

    (void)pthread_rwlock_wrlock(&worker->table_ctx.live_migrate_table.rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &worker->table_ctx.live_migrate_table.hmap) {
        vport_key_t fe_key = cur->key;
        fe_table_entry_t *fe_entry = fe_table_lookup(&worker->table_ctx.fe_table, &fe_key);
        if (fe_entry == NULL) {
            TPSA_LOG_WARN("Can't find fe entry in fe table, so live migrate failed");
            continue;
        }

        /* After receiving a request to stop processing link_create/delete, the vtp table will no longer be copied. */
        if (fe_entry->stop_proc_vtp == true) {
            continue;
        }

        ret = tpsa_vtp_table_migrate(worker, cur, fe_entry);
        /* If the live migration of this fe fails, print err log and then continue the live migration of other fe. */
        if (ret != 0) {
            TPSA_LOG_ERR("fe_idx %hu, live migrate failed", fe_key.fe_idx);
        }
    }

    (void)pthread_rwlock_unlock(&worker->table_ctx.live_migrate_table.rwlock);
    return;
}

static int tpsa_worker_stop_proc_vtp_msg(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_stop_proc_vtp_req_t *nlreq = (tpsa_nl_stop_proc_vtp_req_t *)nlmsg->data;
    vport_key_t key = {0};

    key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);

    (void)pthread_rwlock_wrlock(&worker->table_ctx.fe_table.rwlock);
    fe_table_entry_t *entry = fe_table_lookup(&worker->table_ctx.fe_table, &key);
    if (entry == NULL) {
        TPSA_LOG_WARN("Can't find fe entry in fe table in tpsa_worker_stop_proc_vtp_msg");
        (void)pthread_rwlock_unlock(&worker->table_ctx.fe_table.rwlock);
        return -1;
    }
    (void)pthread_rwlock_unlock(&worker->table_ctx.fe_table.rwlock);
    entry->stop_proc_vtp = true;

    (void)pthread_rwlock_wrlock(&worker->table_ctx.live_migrate_table.rwlock);
    live_migrate_table_entry_t *lm_entry = live_migrate_table_lookup(&worker->table_ctx.live_migrate_table, &key);
    if (lm_entry == NULL) {
        TPSA_LOG_ERR("can not find live_migrate by key fe_idx %hu\n", key.fe_idx);
        (void)pthread_rwlock_unlock(&worker->table_ctx.live_migrate_table.rwlock);
        return -1;
    }
    (void)pthread_rwlock_unlock(&worker->table_ctx.live_migrate_table.rwlock);
    /* When the migration source receives a stop processing link building requests(TPSA_MSG_STOP_PROC_VTP_MSG),
     * Synchronize the vtp table to the migration destination for the last time
    */
    tpsa_sock_msg_t *req = NULL;

    req = calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        TPSA_LOG_ERR("Fail to create live migrate request");
        return -1;
    }
    req->content.lmmsg.fe_idx = nlreq->mig_fe_idx;
    req->content.lmmsg.stop_proc_vtp = entry->stop_proc_vtp;
    req->msg_type = TPSA_LM_CREATE_REQ;
    req->content.lmmsg.mig_source = lm_entry->dip;
    (void)uvs_lm_vtp_table_lmmsg_copy(entry, req);

    if (tpsa_sock_send_msg(&worker->sock_ctx, req, sizeof(tpsa_sock_msg_t), lm_entry->dip) != 0) {
        TPSA_LOG_ERR("Failed to send live migrate message in worker\n");
        free(req);
        return -1;
    }

    free(req);
    return 0;
}

static int tpsa_handle_fe2tpf_msg(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *tmsg = (tpsa_msg_t *)msg->payload;
    int ret = 0;

    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .ioctl_ctx = &worker->ioctl_ctx,
        .nl_ctx = &worker->nl_ctx,
        .sock_ctx = &worker->sock_ctx,
    };

    switch (tmsg->hdr.opcode) {
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
            ret = tpsa_worker_alloc_eid(worker, msg);
            break;
        case TPSA_MSG_DEALLOC_EID:
            ret = tpsa_worker_dealloc_eid(worker, msg);
            break;
        case TPSA_MSG_STOP_PROC_VTP_MSG:
            ret = tpsa_worker_stop_proc_vtp_msg(worker, msg);
            break;
        case TPSA_MSG_QUERY_VTP_MIG_STATUS:
            TPSA_LOG_WARN("Currently not implement this msg handle\n");
            ret = 0;
            break;
        case TPSA_MSG_FLOW_STOPPED:
            TPSA_LOG_WARN("Currently not implement this msg handle\n");
            ret = 0;
            break;
        case TPSA_MSG_MIG_ROLLBACK:
            TPSA_LOG_WARN("Currently not implement this msg handle\n");
            ret = 0;
            break;
        case TPSA_MSG_MIG_VM_START:
            ret =  uvs_lm_handle_vm_start(&ctx, msg);
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
    uvs_ctx_t ctx = {
        .global_cfg_ctx = &worker->global_cfg_ctx,
        .table_ctx = &worker->table_ctx,
        .ioctl_ctx = &worker->ioctl_ctx,
        .nl_ctx = &worker->nl_ctx,
        .sock_ctx = &worker->sock_ctx,
    };
    vtp_node_state_t node_status;

    int res = uvs_lm_handle_async_proprocess(msg, &ctx, &node_status);
    if (res < 0) {
        TPSA_LOG_ERR("uvs lm preprocess lm switch failed\n");
        return -1;
    }

    if (msg->msg_type == TPSA_NL_MIGRATE_VTP_SWITCH) {
        if (node_status != STATE_NORMAL) {
            TPSA_LOG_ERR("Ignore this switch async event processing\n");
            return 0;
        }
        if (uvs_lm_handle_async_event(&ctx, msg) < 0) {
            TPSA_LOG_ERR("Fail to handle lm async vtp switch\n");
            return -1;
        }
    } else {
        if (node_status != STATE_MIGRATING) {
            TPSA_LOG_ERR("Ignore this rollback async event processing\n");
            return 0;
        }
        if (uvs_lm_handle_async_event(&ctx, msg) < 0) {
            TPSA_LOG_ERR("Fail to handle lm async vtp rollback\n");
            return -1;
        }
    }

    return 0;
}

static int tpsa_handle_nl_msg(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    tpsa_nl_msg_t *resp = NULL;
    tpsa_sock_msg_t *info = NULL;
    urma_eid_t peer_tpsa_eid;
    tpsa_net_addr_t dip;
    int ret = 0;

    switch (msg->msg_type) {
        case TPSA_NL_FE2TPF_REQ:
            return tpsa_handle_fe2tpf_msg(worker, msg);
        case TPSA_NL_MIGRATE_VTP_SWITCH:
        case TPSA_NL_MIGRATE_VTP_ROLLBACK:
            return tpsa_handle_migrate_async(worker, msg);
        /* Alpha begins */
        case TPSA_NL_QUERY_TP_REQ:
            resp = tpsa_handle_nl_query_tp_req(msg);
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
    } else if (msg->msg_type != TPSA_NL_FE2TPF_REQ) {
        tpsa_lookup_dip_table(&worker->table_ctx.dip_table, msg->dst_eid, &peer_tpsa_eid, &dip);
        if (tpsa_sock_send_msg(&worker->sock_ctx, info, sizeof(tpsa_sock_msg_t), peer_tpsa_eid) != 0) {
            TPSA_LOG_INFO("send msg failed, msg_type is:%d.\n", msg->msg_type);
            ret = -1;
            goto free_msg_buf;
        }
        TPSA_LOG_INFO("[Socket send nl req to remote]---msg_id: %d\n", msg->nlmsg_seq);
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

        tpsa_live_migrate_begin(worker);
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
    tpsa_worker_t *worker = calloc(1, sizeof(tpsa_worker_t));
    if (worker == NULL) {
        TPSA_LOG_ERR("Failed to create tpsa worker.\n");
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
