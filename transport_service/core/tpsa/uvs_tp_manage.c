/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs tp connection management file
 * Author: LI Yuxing
 * Create: 2023-8-21
 * Note:
 * History:
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "tpsa_log.h"
#include "tpsa_types.h"
#include "tpsa_worker.h"
#include "uvs_stats.h"
#include "uvs_tp_manage.h"

#define UVS_MAX_IPV4_BIT_LEN 32
#define UVS_MAX_IPV6_BIT_LEN 128
#define UVS_MAX_CNA_LEN 16

static inline uvs_mtu_t uvs_get_min_valid_mtu(uvs_mtu_t sip_mtu, uvs_mtu_t global_mtu)
{
    uint32_t sip_mtu_val = (uint32_t)sip_mtu;
    uint32_t global_mtu_val = (uint32_t)global_mtu;
    if (sip_mtu_val == 0) {
        return global_mtu;
    }
    if (global_mtu_val == 0) {
        return sip_mtu;
    }
    return sip_mtu_val < global_mtu_val ? sip_mtu : global_mtu;
}

static inline uvs_mtu_t uvs_get_mtu(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_global_cfg_t *global_cfg = ctx->global_cfg_ctx;
    sip_table_entry_t sip_entry = {0};

    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry);

    return uvs_get_min_valid_mtu(sip_entry.mtu, global_cfg->mtu);
}

uvs_mtu_t uvs_get_mtu_with_sip_mtu(uvs_ctx_t *ctx, uvs_mtu_t sip_mtu)
{
    tpsa_global_cfg_t *global_cfg = ctx->global_cfg_ctx;

    return uvs_get_min_valid_mtu(sip_mtu, global_cfg->mtu);
}

int uvs_response_create_fast(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx,
                             tpsa_nl_resp_status_t status, uint32_t vtpn)
{
    /* NETLINK to response to UBCORE */
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_vtp_resp_fast(msg, status, vtpn);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    uvs_cal_vtp_create_stat(msg, status);
    free(nlresp);
    TPSA_LOG_INFO("Finish fast NETLINK response vtpn to ubcore\n");

    return 0;
}

// create vtp success
static int uvs_response_create(tpsa_nl_ctx_t *nl_ctx, tpsa_resp_id_t *resp_id,
                               uint32_t vtpn, tpsa_nl_resp_status_t resp_status)
{
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_vtp_resp(resp_id, vtpn, resp_status);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    free(nlresp);
    TPSA_LOG_INFO("Finish NETLINK response vtpn to ubcore\n");

    return 0;
}

static int uvs_resp_nl_create_vtp(tpsa_nl_ctx_t *nl_ctx, tpsa_sock_msg_t *msg, uint32_t vtpn,
                                  tpsa_nl_resp_status_t resp_status)
{
    tpsa_resp_id_t resp_id = {0};
    vport_key_t vport_key = {0};
    int ret = 0;

    if (msg->msg_type == TPSA_CREATE_FINISH) {
        resp_id.is_need_resp = true;
        resp_id.nlmsg_seq = msg->content.finish.nlmsg_seq;
        resp_id.msg_id = msg->content.finish.msg_id;
        resp_id.src_fe_idx = msg->content.finish.src_function_id;

        vport_key.fe_idx = resp_id.src_fe_idx;
        (void)memcpy(vport_key.tpf_name, msg->content.finish.dev_name, UVS_MAX_DEV_NAME);
    } else if (msg->msg_type == TPSA_CREATE_FAIL_RESP) {
        resp_id.is_need_resp = true;
        resp_id.nlmsg_seq = msg->content.fail_resp.nlmsg_seq;
        resp_id.msg_id = msg->content.fail_resp.msg_id;
        resp_id.src_fe_idx = msg->content.fail_resp.src_function_id;

        vport_key.fe_idx = resp_id.src_fe_idx;
        (void)memcpy(vport_key.tpf_name, msg->content.fail_resp.dev_name, UVS_MAX_DEV_NAME);
    } else if (msg->msg_type == TPSA_TABLE_SYC_RESP) {
        resp_id = msg->content.tsync_resp.nl_resp_id;
        vport_key.fe_idx = resp_id.src_fe_idx;
        (void)memcpy(vport_key.tpf_name, msg->content.tsync_resp.dev_name, UVS_MAX_DEV_NAME);
    } else {
        TPSA_LOG_ERR("Invalid msg type:%d", (int)msg->msg_type);
        return -1;
    }

    ret = uvs_response_create(nl_ctx, &resp_id, vtpn, resp_status);
    if (ret != 0) {
        return ret;
    }

    uvs_vtp_state_t state = (resp_status == TPSA_NL_RESP_SUCCESS) ? UVS_VTP_SUCCESS_STATE : UVS_VTP_ERR_STATE;
    uvs_cal_vtp_statistic(&vport_key, msg->trans_mode, state);
    return 0;
}

tpsa_nl_msg_t *tpsa_nl_destory_vtp_resp(uint32_t vtpn, tpsa_sock_msg_t *msg)
{
    tpsa_nl_msg_t *nlresp = NULL;
    urma_eid_t local_eid = msg->local_eid;
    urma_eid_t peer_eid = msg->peer_eid;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_destroy_vtp_resp_t),
        &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    /* nl msg */
    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = msg->content.dfinish.resp_id.nlmsg_seq;
    nlresp->transport_type = TPSA_TRANSPORT_UB;

    /* tpsa msg */
    tpsa_nl_resp_host_t *resp_host = (tpsa_nl_resp_host_t *)nlresp->payload;
    resp_host->src_fe_idx = msg->content.dfinish.resp_id.src_fe_idx;
    resp_host->resp.len = (uint32_t)(sizeof(tpsa_nl_destroy_vtp_resp_t));
    resp_host->resp.msg_id = msg->content.dfinish.resp_id.msg_id;
    resp_host->resp.opcode = TPSA_MSG_DESTROY_VTP;

    /* resp msg */
    tpsa_nl_destroy_vtp_resp_t *create_vtp_resp = (tpsa_nl_destroy_vtp_resp_t *)resp_host->resp.data;
    create_vtp_resp->ret = TPSA_NL_RESP_SUCCESS;

    return nlresp;
}

int uvs_response_destroy(uint32_t vtpn, tpsa_sock_msg_t *msg, tpsa_nl_ctx_t *nl_ctx)
{
    tpsa_nl_msg_t *nlresp = tpsa_nl_destory_vtp_resp(vtpn, msg);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    free(nlresp);

    return 0;
}

int uvs_response_create_wait(uint32_t vtpn, tpsa_create_param_t *cparam, tpsa_nl_ctx_t *nl_ctx)
{
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_vtp_resp_wait(vtpn, cparam);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    free(nlresp);
    TPSA_LOG_INFO("Finish NETLINK response vtpn to ubcore\n");

    return 0;
}

int uvs_response_destroy_fast(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx,
                              tpsa_nl_resp_status_t status)
{
    tpsa_nl_msg_t *nlresp = tpsa_nl_destroy_vtp_resp(msg, status);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    uvs_cal_vtp_destroy(msg, status);
    free(nlresp);

    return 0;
}

static int uvs_remove_tpg_table(tpsa_table_t *table_ctx, tpsa_transport_mode_t trans_mode,
                                tpsa_tpg_table_index_t *tpg_idx, tpsa_tpg_info_t *find_tpg_info)
{
    int32_t ret = 0;

    if (trans_mode == TPSA_TP_RM) {
        rm_tpg_table_key_t k = {
            .dip = tpg_idx->dip,
        };
        ret = tpsa_remove_rm_tpg_table(&table_ctx->rm_tpg_table, &k, find_tpg_info);
    } else if (trans_mode == TPSA_TP_RC) {
        rc_tpg_table_key_t k = {
            .deid = tpg_idx->peer_eid,
            .djetty_id = tpg_idx->djetty_id,
        };
        ret = tpsa_remove_rc_tpg_table(table_ctx, &k, find_tpg_info);
        if ((ret == TPSA_REMOVE_NULL) && (tpg_idx->isLoopback)) {
            k.deid = tpg_idx->local_eid;
            k.djetty_id = tpg_idx->ljetty_id;
            ret = tpsa_remove_rc_tpg_table(table_ctx, &k, find_tpg_info);
        }
    }

    if (ret < 0) {
        TPSA_LOG_ERR("Failed to remove %s tpg table when destroy vtp, ret:%d\n",
            (trans_mode == TPSA_TP_RM) ? "rm" : "rc", ret);
    } else {
        TPSA_LOG_INFO("Remove tpgn %d, tp_cnt:%d, from %s tpg table when destroy vtp\n", find_tpg_info->tpgn,
            find_tpg_info->tp_cnt, (trans_mode == TPSA_TP_RM) ? "rm" : "rc");
    }

    return ret;
}

void destroy_tpg_error_process(tpsa_tpg_table_index_t *tpg_idx,
                               tpsa_table_t *table_ctx, tpsa_tpg_info_t *find_tpg_info,
                               tpg_exception_state_t tpg_state)
{
    uint32_t tp_cnt = find_tpg_info->tp_cnt;

    /* when tpg is destroyed, remove the entries recorded in tp state table corresponding to this tpg. */
    for (uint32_t i = 0; i < tp_cnt; i++) {
        tp_state_table_key_t key = {
            .tpn = find_tpg_info->tpn[i],
            .sip = tpg_idx->sip
        };

        tp_state_table_entry_t *entry = tp_state_table_lookup(&table_ctx->tp_state_table, &key);
        if (entry != NULL) {
            entry->tp_exc_state = INITIATOR_TP_STATE_DEL;
        } else {
            tp_state_table_entry_t add_entry = {0};
            add_entry.tp_exc_state = INITIATOR_TP_STATE_DEL;
            entry = tp_state_table_add(&table_ctx->tp_state_table, &key, &add_entry);
            if (entry == NULL) {
                TPSA_LOG_WARN("entry alloc failed \n");
            }
        }
    }

    tpg_state_table_key_t tpg_key = {
        .tpgn = find_tpg_info->tpgn,
        .sip = tpg_idx->sip,
    };

    tpg_state_table_entry_t *tpg_entry = tpg_state_table_lookup(&table_ctx->tpg_state_table, &tpg_key);
    if (tpg_entry != NULL) {
        TPSA_LOG_WARN("tpg %u already del process \n", find_tpg_info->tpgn);
        tpg_entry->tpg_exc_state = TPG_STATE_DEL;
    } else {
        tpg_state_table_entry_t add_tpg_entry = {0};
        add_tpg_entry.tpg_exc_state = tpg_state;
        add_tpg_entry.tp_cnt = tp_cnt;
        (void)memcpy(add_tpg_entry.tpn, find_tpg_info->tpn, sizeof(find_tpg_info->tpn));
        add_tpg_entry.tp_flush_cnt = tp_cnt;
        add_tpg_entry.tpgn = find_tpg_info->tpgn;
        tpg_entry = tpg_state_table_add(&table_ctx->tpg_state_table, &tpg_key, &add_tpg_entry);
        if (tpg_entry == NULL) {
            TPSA_LOG_WARN("tpg_entry alloc failed \n");
        }
    }
}

void uvs_table_remove_vtp_tpg(int32_t *vtpn, int32_t *tpgn, tpsa_tpg_table_index_t *tpg_idx,
                              tpsa_vtp_table_index_t *vtp_idx, tpsa_table_t *table_ctx)
{
    int32_t find_vtpn = -1;
    tpsa_tpg_info_t find_tpg_info = {0};
    int ret = -1;

    /* Remove vtpn from vtp table */
    vtp_idx->share_mode = true; /* share_mode is set to be true by default */
    find_vtpn = tpsa_remove_vtp_table(vtp_idx->trans_mode, vtp_idx, table_ctx);
    switch (find_vtpn) {
        case TPSA_REMOVE_INVALID:
            /* return when vtp is invalid */
            TPSA_LOG_WARN("Try to remove a vtp entry which is in progess.\n");
            *vtpn = find_vtpn;
            return;
        case TPSA_LOOKUP_NULL:
            TPSA_LOG_ERR("Failed to remove vtp table when destroy vtp\n");
            break;
        case TPSA_REMOVE_SERVER:
        default:
            *vtpn = find_vtpn;
            TPSA_LOG_INFO("Remove vtpn %d from vtp table when destroy initiator vtp\n", find_vtpn);
    }

    if (vtp_idx->share_mode) {
        /* Remove tpgn from tpg table */
        ret = uvs_remove_tpg_table(table_ctx, tpg_idx->trans_mode, tpg_idx, &find_tpg_info);
    } else {
        if (vtp_idx->use_cnt > 0) {
            TPSA_LOG_INFO("tpgn %d is in use, use count is %u.",
                vtp_idx->tpg_param.tpgn, vtp_idx->use_cnt);
            ret = TPSA_REMOVE_DUPLICATE;
        } else if (vtp_idx->use_cnt == 0) {
            (void)memcpy(&find_tpg_info,
                &vtp_idx->tpg_param, sizeof(tpsa_tpg_info_t));
            ret = 0;
            TPSA_LOG_INFO("detect non_share_mode and deleting tpgn = %u and tp_cnt = %u\n",
                find_tpg_info.tpgn, find_tpg_info.tp_cnt);
        }
    }

    if (ret == 0 && !tpsa_get_tp_fast_destroy()) {
        destroy_tpg_error_process(tpg_idx, table_ctx, &find_tpg_info, TPG_STATE_DEL);
    }

    *vtpn = find_vtpn;
    *tpgn = (ret == 0) ? (int32_t)find_tpg_info.tpgn : ret;
}

int uvs_handle_last_lm_req(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry)
{
    int res = -1;

    tpsa_sock_msg_t *msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (msg == NULL) {
        return -ENOMEM;
    }

    /* After the dest_mig responds to the src_mig, the stop_proc_vtp should be set to false
    and cannot affect the link establishment request after the migration is successful. */
    fe_entry->stop_proc_vtp = false;

    msg->msg_type = TPSA_LM_MIG_RESP;
    msg->content.lm_resp.last_mig_completed = true;
    /* The vf and dev_name of the migration source are sent by sock_message. */
    msg->content.lm_resp.mig_fe_idx = fe_entry->lm_fe_idx;
    (void)memcpy(msg->content.lm_resp.dev_name, fe_entry->lm_dev_name, UVS_MAX_DEV_NAME);
    res = tpsa_sock_send_msg(ctx->sock_ctx, msg, sizeof(tpsa_sock_msg_t), fe_entry->src_uvs_ip);
    if (res < 0) {
        TPSA_LOG_ERR("Failed to send a message to the mig source that the chain reconstruction is completed\n");
        free(msg);
        return res;
    }

    TPSA_LOG_INFO("when the migration dest completes the link reconstruction,send socket msg to source success.\n");
    free(msg);
    return 0;
}

/* When the reconstruction link of the mig in dest is completed, a complete mess needs to be sent to the source. */
int uvs_create_resp_to_lm_src(uvs_ctx_t *ctx, vport_key_t fe_key)
{
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &fe_key);
    if (fe_entry != NULL && fe_entry->stop_proc_vtp == true) {
        uint32_t num = fe_entry->rm_vtp_table.hmap.count +  fe_entry->rc_vtp_table.hmap.count +
                       fe_entry->um_vtp_table.hmap.count;
        if (fe_entry->vtp_migrate_num == num) {
            return uvs_handle_last_lm_req(ctx, fe_entry);
        }
    }

    TPSA_LOG_INFO("Success to resp to migration source when link rebuild ready.\n");
    return 0;
}

int uvs_send_table_sync_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, int ret)
{
    tpsa_sock_msg_t *resp = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (resp == NULL) {
        return -1;
    }

    resp->msg_type = TPSA_TABLE_SYC_RESP;

    resp->trans_mode = msg->trans_mode;
    resp->local_eid = msg->local_eid;
    resp->peer_eid = msg->peer_eid;
    resp->local_jetty = msg->local_jetty;
    resp->peer_jetty = msg->peer_jetty;
    resp->vtpn = msg->vtpn;
    resp->upi = msg->upi;
    resp->live_migrate = msg->live_migrate;

    tpsa_table_sync_resp_t *sync_resp = &resp->content.tsync_resp;
    tpsa_table_sync_t *req = &msg->content.tsync;

    sync_resp->nl_resp_id = req->nl_resp_id;
    sync_resp->opcode = req->opcode;
    (void)memcpy(sync_resp->dev_name, req->dev_name, UVS_MAX_DEV_NAME);
    sync_resp->ret = (ret == 0) ? TPSA_RESP_SUCCESS : TPSA_RESP_FAIL;

    if (tpsa_sock_send_msg(ctx->sock_ctx, resp, sizeof(tpsa_sock_msg_t), msg->src_uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send table sync resp in worker\n");
        free(resp);
        return -1;
    }

    free(resp);
    return 0;
}

static int tpsa_lookup_tpg_table_non_share_mode(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg,
    vport_key_t fe_key, tpsa_tpg_info_t *tpg, tpsa_tpg_status_t *status)
{
    rm_vtp_table_entry_t *share_mode_entry = NULL;
    rm_vtp_table_key_t vtp_key = {0};
    vtp_key.src_eid = msg->peer_eid;
    vtp_key.dst_eid = msg->local_eid;

    TPSA_LOG_DEBUG("fe_key.fe_idx = %hu and tpf_name %s",
        fe_key.fe_idx, fe_key.tpf_name);

    TPSA_LOG_DEBUG("vtp src eid = " EID_FMT " and dst eid" EID_FMT "\n",
                    vtp_key.src_eid, vtp_key.dst_eid);

    share_mode_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
        &fe_key, &vtp_key);
    if (share_mode_entry != NULL) {
        if (!share_mode_entry->share_mode) {
            (void)memcpy(tpg,
                share_mode_entry->tpg_param, sizeof(tpsa_tpg_info_t));
        }
    } else {
        TPSA_LOG_ERR("cannot find rm fe vtp with seid " EID_FMT " and deid " EID_FMT "\n",
                EID_ARGS(vtp_key.src_eid), EID_ARGS(vtp_key.dst_eid));
        return -1;
    }
    *status = TPSA_TPG_LOOKUP_EXIST;

    return 0;
}

static int uvs_map_target_vtp(int ubcore_fd, tpsa_create_param_t *cparam, uint32_t local_tpgn, uvs_net_addr_info_t *dip)
{
    /* IOCTL to map target vtp */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_map_target_vtp(cfg, cparam, local_tpgn, dip);
    if (tpsa_ioctl(ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to map vtp in worker");
        free(cfg);
        return -1;
    }

    free(cfg);
    return 0;
}

int uvs_handle_table_sync(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_table_sync_t *sync = &msg->content.tsync;
    uint32_t location = TPSA_TARGET;
    tpsa_tpg_status_t status;
    tpsa_tpg_info_t tpg;
    tpsa_tpg_table_index_t tpg_idx;
    int ret = 0;

    (void)memset(&tpg_idx, 0, sizeof(tpsa_tpg_table_index_t));
    tpg_idx.dip = msg->dip;
    tpg_idx.local_eid = msg->peer_eid;
    tpg_idx.peer_eid = msg->local_eid;
    tpg_idx.ljetty_id = msg->peer_jetty;
    tpg_idx.djetty_id = msg->local_jetty;
    tpg_idx.isLoopback = false;

    TPSA_LOG_INFO("src eid " EID_FMT " sjetty: %u, dst eid " EID_FMT ", djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid),
                  msg->peer_jetty);

    vport_key_t fe_key = {0};
    uint32_t eid_idx = 0;
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->peer_eid,
        &fe_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid failed, upi is %u, eid_idx is %u,  eid:" EID_FMT "\n",
                        msg->upi, eid_idx, EID_ARGS(msg->peer_eid));
        ret = -1;
        goto send_resp;
    }

    if (sync->share_mode) {
        status = tpsa_lookup_tpg_table(&tpg_idx, msg->trans_mode, ctx->table_ctx, &tpg);
    } else {
        if (tpsa_lookup_tpg_table_non_share_mode(ctx, msg,
            fe_key, &tpg, &status) != 0) {
            ret = -1;
            goto send_resp;
        }
    }

    if (status != TPSA_TPG_LOOKUP_EXIST) {
        TPSA_LOG_ERR("Wrong tpg number find when sync table");
        ret = -1;
        goto send_resp;
    }

    if (sync->opcode == TPSA_TABLE_ADD) {
        if (uvs_table_update(UINT32_MAX, tpg.tpgn, location, msg, ctx->table_ctx) < 0) {
            TPSA_LOG_ERR("Fail to sync table in target.");
            ret = -1;
            goto send_resp;
        }

        tpsa_create_param_t cparam;
        cparam.trans_mode = msg->trans_mode;
        cparam.local_eid = msg->peer_eid;
        cparam.peer_eid = msg->local_eid;
        cparam.local_jetty = msg->peer_jetty;
        cparam.peer_jetty = msg->local_jetty;
        cparam.fe_idx = fe_key.fe_idx;
        cparam.vtpn = UINT32_MAX;
        cparam.live_migrate = msg->live_migrate;
        cparam.location = TPSA_TARGET;
        if (uvs_map_target_vtp(ctx->ioctl_ctx->ubcore_fd, &cparam, msg->local_tpgn, &msg->dip) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to map target vtp in target");
            ret = -1;
            goto send_resp;
        }
        TPSA_LOG_INFO("Finish IOCTL to map target vtp in target.\n");

        if (uvs_create_resp_to_lm_src(ctx, fe_key) != 0) {
            TPSA_LOG_ERR("uvs create resp to live_migrate source failed");
            return -1;
        }
    }

send_resp:
    (void)uvs_send_table_sync_resp(ctx, msg, ret);
    return ret;
}

int uvs_handle_table_sync_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_table_sync_resp_t *tsync_resp = &msg->content.tsync_resp;

    TPSA_LOG_INFO("hanlde sync table resp, ret:%d, src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u",
                  (int)tsync_resp->ret, EID_ARGS(msg->local_eid), msg->local_jetty,
                  EID_ARGS(msg->peer_eid), msg->peer_jetty);

    vport_key_t vport_key = {0};
    vport_key.fe_idx = tsync_resp->nl_resp_id.src_fe_idx;
    (void)memcpy(vport_key.tpf_name, tsync_resp->dev_name, UVS_MAX_DEV_NAME);

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    if (uvs_get_tp_msg_ctx_local_site(msg, &vport_key, NULL, ctx->table_ctx, &tp_msg_ctx) != 0) {
        TPSA_LOG_ERR("Fail to get msg ctx");
        (void)uvs_resp_nl_create_vtp(ctx->nl_ctx, msg, UINT32_MAX, TPSA_NL_RESP_FAIL);
        return -1;
    }

    int32_t vtpn = -1;
    int32_t tpgn = -1;
    if (tsync_resp->ret != TPSA_RESP_SUCCESS &&
        uvs_destroy_rm_rc_vtp(ctx, &tp_msg_ctx, TPSA_INITIATOR, &vtpn, &tpgn) != 0) {
        TPSA_LOG_ERR("Fail to get destory rm rc vtp");
    }

    if (!tsync_resp->nl_resp_id.is_need_resp) {
        return 0;
    }

    tpsa_nl_resp_status_t resp_status = (tsync_resp->ret == TPSA_RESP_SUCCESS) ?
                                         TPSA_NL_RESP_SUCCESS : TPSA_NL_RESP_FAIL;
    if (uvs_resp_nl_create_vtp(ctx->nl_ctx, msg, msg->vtpn, resp_status) != 0) {
        TPSA_LOG_ERR("Fail to resp nl msg");
    }

    return 0;
}

int uvs_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_create_param_t *cparam, uint32_t number,
                uvs_net_addr_info_t *sip, uint32_t *vtpn)
{
    /* IOCTL to create vtp; */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_map_vtp(cfg, cparam, number, sip);
    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to map vtp in worker, seid: " EID_FMT ", deid: " EID_FMT "\n");
        free(cfg);
        return -1;
    }

    *vtpn = cfg->cmd.map_vtp.out.vtpn;
    free(cfg);
    return 0;
}

/* utp exist, create vtp and map in one ioctl */
int uvs_um_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx, uvs_map_param_t *uparam,
                   tpsa_create_param_t *cparam, utp_table_entry_t *utp_table_entry)
{
    int res;
    um_vtp_table_key_t um_vtp_key;

    vport_key_t fe_key = {0};
    fe_key.fe_idx = uparam->fe_idx;
    (void)memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    res = uvs_map_vtp(ioctl_ctx, cparam, utp_table_entry->utp_idx, &uparam->sip, uparam->vtpn);
    if (res < 0) {
        return -1;
    }
    TPSA_LOG_INFO("map um vtp success.vtpn %u, utp_idx %u", *uparam->vtpn, utp_table_entry->utp_idx);

    um_vtp_key.src_eid = cparam->local_eid;
    um_vtp_key.dst_eid = cparam->peer_eid;

    tpsa_um_vtp_table_param_t uvtp_param = {
        .vtpn = *uparam->vtpn,
        .utp_idx = utp_table_entry->utp_idx,
        .upi = cparam->upi,
    };

    res = um_fe_vtp_table_add(table_ctx, &fe_key, &um_vtp_key, &uvtp_param);
    if (res < 0) {
        tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            return -ENOMEM;
        }

        tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->sip, (urma_transport_mode_t)cparam->trans_mode,
            cparam->local_eid,  cparam->peer_eid, cparam->peer_jetty, cparam->location);
        (void)tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
        free(cfg);
        return -1;
    }

    utp_table_entry->use_cnt++;
    return 0;
}

int uvs_destroy_utp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                    utp_table_key_t *key, uint32_t utp_idx)
{
    /* IOCTL to destroy utp; */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_destroy_utp(cfg, key, utp_idx);
    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy utp in worker, idx:%u", utp_idx);
        free(cfg);
        return -1;
    }

    /* todo next, failed rollback */
    int ret = utp_table_remove(&table_ctx->utp_table, key);
    if (ret != 0) {
        TPSA_LOG_ERR("utp_table remove failed, idx:%u", utp_idx);
        free(cfg);
        return -1;
    }

    TPSA_LOG_INFO("destroy utp success, idx:%u", utp_idx);
    free(cfg);
    return 0;
}

/* utp not exist, create utp, create vtp and mapping in one ioctl */
int uvs_create_utp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                   tpsa_create_param_t *cparam, uvs_create_utp_param_t *uparam)
{
    int ret;
    um_vtp_table_key_t um_vtp_key;

    /* IOCTL to create utp; */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_create_utp(cfg, &tp_msg_ctx->vport_ctx.param, cparam, &uparam->key);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to create utp in worker");
        free(cfg);
        return -1;
    }

    *uparam->vtpn = cfg->cmd.create_utp.out.vtpn;
    uint32_t utpn = cfg->cmd.create_utp.out.idx;

    um_vtp_key.src_eid = cparam->local_eid;
    um_vtp_key.dst_eid = cparam->peer_eid;

    tpsa_um_vtp_table_param_t uvtp_param = {
        .vtpn = *uparam->vtpn,
        .utp_idx = utpn,
        .upi = cparam->upi,
    };

    ret = um_fe_vtp_table_add(ctx->table_ctx, &tp_msg_ctx->vport_ctx.key, &um_vtp_key, &uvtp_param);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to add um_vtp_table");
        goto ROLL_BACK;
    }

    ret = utp_table_add(&ctx->table_ctx->utp_table, &uparam->key, utpn);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to add utp_table");
        goto REMOVE_VTP_TABLE;
    }

    free(cfg);
    TPSA_LOG_INFO("add um vtp success, vtpn %u, utp_idx %d", *uparam->vtpn, utpn);
    uvs_cal_tp_statistic(cparam->tpf_name, cparam->trans_mode, UVS_TP_SUCCESS_STATE);
    return 0;

REMOVE_VTP_TABLE:
    (void)um_vtp_table_remove(&ctx->table_ctx->fe_table, &ctx->table_ctx->deid_vtp_table,
                              &tp_msg_ctx->vport_ctx.key, &um_vtp_key);
ROLL_BACK:
    /* roll back vtp first */
    (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->key.sip, (urma_transport_mode_t)cparam->trans_mode,
        cparam->local_eid, cparam->peer_eid, cparam->peer_jetty, cparam->location);
    (void)tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg);
    free(cfg);

    /* roll back utp */
    (void)uvs_destroy_utp(ctx->ioctl_ctx, ctx->table_ctx, &uparam->key, utpn);
    uvs_cal_tp_statistic(cparam->tpf_name, cparam->trans_mode, UVS_TP_DESTROY_STATE);
    return -1;
}

int uvs_clan_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx, uvs_map_param_t *uparam,
                     tpsa_create_param_t *cparam, ctp_table_entry_t *ctp_table_entry)
{
    int ret = uvs_map_vtp(ioctl_ctx, cparam, ctp_table_entry->ctp_idx, &uparam->sip, uparam->vtpn);
    if (ret < 0) {
        return ret;
    }

    TPSA_LOG_DEBUG("map clan vtp success.vtpn %u, ctp_idx %u", *uparam->vtpn, ctp_table_entry->ctp_idx);
    clan_vtp_table_key_t clan_vtp_key = { .dst_eid = cparam->peer_eid };
    tpsa_clan_vtp_table_param_t clan_vtp_param = {
        .vtpn = *uparam->vtpn,
        .ctp_idx = ctp_table_entry->ctp_idx,
    };

    vport_key_t fe_key = {0};
    fe_key.fe_idx = uparam->fe_idx;
    memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);
    ret = clan_fe_vtp_table_add(&table_ctx->fe_table, &fe_key, &clan_vtp_key, &clan_vtp_param);
    if (ret < 0) {
        tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            return -ENOMEM;
        }

        tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->sip, (urma_transport_mode_t)cparam->trans_mode,
            cparam->local_eid, cparam->peer_eid, cparam->peer_jetty, cparam->location);
        (void)tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
        free(cfg);
        return ret;
    }

    ctp_table_entry->use_cnt++;
    return 0;
}

int uvs_create_um_vtp_base(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                           tpsa_create_param_t *cparam, uint32_t *vtpn)
{
    int res = -1;
    utp_table_key_t utp_key = {
        .sip = tp_msg_ctx->src.ip,
        .dip = tp_msg_ctx->dst.ip,
    };

    utp_table_entry_t *utp_table_entry = utp_table_lookup(&ctx->table_ctx->utp_table, &utp_key);
    if (utp_table_entry != NULL) {
        TPSA_LOG_INFO("utp %u, already exist goto exist process", utp_table_entry->utp_idx);
        uvs_map_param_t uparam = {
            .fe_idx = cparam->fe_idx,
            .sip = utp_key.sip,
            .vtpn = vtpn,
        };

        res = uvs_um_map_vtp(ctx->ioctl_ctx, ctx->table_ctx, &uparam, cparam, utp_table_entry);
    } else {
        TPSA_LOG_INFO("utp not exist goto create process");
        uvs_create_utp_param_t uparam = {
            .key = utp_key,
            .vtpn = vtpn,
        };

        res = uvs_create_utp(ctx, tp_msg_ctx, cparam, &uparam);
    }

    return res;
}

int uvs_create_um_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->req.data;
    tpsa_nl_resp_status_t status = TPSA_NL_RESP_SUCCESS;
    sip_table_entry_t sip_entry = {0};
    um_vtp_table_key_t um_vtp_key;
    uint32_t vtpn;
    tpsa_create_param_t cparam;
    int ret = 0;

    um_vtp_key.src_eid = nlreq->local_eid;
    um_vtp_key.dst_eid = nlreq->peer_eid;
    um_vtp_table_entry_t *entry = um_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &tp_msg_ctx->vport_ctx.key,
                                                         &um_vtp_key);
    if (entry != NULL) {
        entry->use_cnt++;
        vtpn = entry->vtpn;
        TPSA_LOG_INFO("vtp already exist return vtpn %d, use cnt %u", vtpn, entry->use_cnt);
        goto NL_RETURN;
    }

    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry);
    cparam.trans_mode = nlreq->trans_mode;
    (void)memset(&cparam.dip, 0, sizeof(uvs_net_addr_info_t));
    cparam.local_eid = nlreq->local_eid;
    cparam.peer_eid = nlreq->peer_eid;
    cparam.local_jetty = nlreq->local_jetty;
    cparam.peer_jetty = nlreq->peer_jetty;
    cparam.eid_index = nlreq->eid_index;
    cparam.fe_idx = nlmsg->src_fe_idx;
    cparam.vtpn = nlreq->vtpn;
    cparam.live_migrate = false;
    cparam.clan_tp = false;
    cparam.msg_id = nlmsg->req.msg_id;
    cparam.nlmsg_seq = msg->nlmsg_seq;
    cparam.upi = tp_msg_ctx->upi;
    cparam.sig_loop = false; /* to do, need to adapt to loopback scene  */
    cparam.port_id = sip_entry.port_id[0];
    cparam.global_cfg = ctx->global_cfg_ctx;
    cparam.mtu = uvs_get_mtu(ctx, tp_msg_ctx);
    cparam.location = TPSA_INITIATOR;
    memcpy(cparam.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    ret = uvs_create_um_vtp_base(ctx, tp_msg_ctx, &cparam, &vtpn);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to create or map vtp um.");
    }

NL_RETURN:
    status = (ret == 0) ? TPSA_NL_RESP_SUCCESS : TPSA_NL_RESP_FAIL;
    if (uvs_response_create_fast(msg, ctx->nl_ctx, status, vtpn) < 0) {
        TPSA_LOG_ERR("Fail to response nl response in um.");
        return -1;
    }

    return 0;
}

int uvs_destroy_um_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    utp_table_key_t utp_key;
    um_vtp_table_key_t um_vtp_key;
    uint32_t utp_idx;
    uint32_t vtpn;

    (void)memset(&utp_key, 0, sizeof(utp_table_key_t));
    um_vtp_key.src_eid = tp_msg_ctx->src.eid;
    um_vtp_key.dst_eid = tp_msg_ctx->dst.eid;

    um_vtp_table_entry_t *um_vtp_entry = um_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &tp_msg_ctx->vport_ctx.key,
                                                                &um_vtp_key);
    if (um_vtp_entry == NULL) {
        TPSA_LOG_ERR("Fail to find vtp table by key destroy vtp request");
        return -1;
    }

    vtpn = um_vtp_entry->vtpn;

    um_vtp_entry->use_cnt--;
    if (um_vtp_entry->use_cnt != 0) {
        TPSA_LOG_INFO("ioctl to destroy um vtp in worker success, other jetty in use it, vtpn:%u, use cnt:%u",
            vtpn, um_vtp_entry->use_cnt);
        return 0;
    }

    utp_key.sip = tp_msg_ctx->src.ip;
    utp_key.dip = tp_msg_ctx->dst.ip;

    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_destroy_vtp(cfg, &utp_key.sip, URMA_TM_UM,
        tp_msg_ctx->src.eid, tp_msg_ctx->dst.eid, tp_msg_ctx->dst.jetty_id, TPSA_INITIATOR);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy vtp in worker");
        free(cfg);
        return -1;
    }

    free(cfg);
    /* todonext failed rollback? */
    (void)um_vtp_table_remove(&ctx->table_ctx->fe_table, &ctx->table_ctx->deid_vtp_table,
                              &tp_msg_ctx->vport_ctx.key, &um_vtp_key);

    utp_table_entry_t *utp_table_entry = utp_table_lookup(&ctx->table_ctx->utp_table, &utp_key);
    if (utp_table_entry == NULL) {
        /* todo rollback vtp? */
        TPSA_LOG_ERR("Fail to ioctl to destroy utp in worker");
        return -1;
    }

    utp_idx = utp_table_entry->utp_idx;
    utp_table_entry->use_cnt--;
    if (utp_table_entry->use_cnt == 0) {
        TPSA_LOG_INFO("no one use utp %u, destroy it.", utp_idx);
        (void)uvs_destroy_utp(ctx->ioctl_ctx, ctx->table_ctx, &utp_key, utp_idx);
        uvs_cal_tp_statistic(tp_msg_ctx->vport_ctx.key.tpf_name, tp_msg_ctx->trans_mode, UVS_TP_DESTROY_STATE);
    }

    TPSA_LOG_INFO("ioctl to destroy um vtp in worker success, vtpn:%u, utp_idx:%u",
        vtpn, utp_idx);

    return 0;
}

static int uvs_create_clan_vtp_base(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_tp_msg_ctx_t *tp_msg_ctx,
                                    uint32_t *vtpn)
{
    sip_table_entry_t sip_entry = { 0 };

    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry);

    ctp_table_key_t ctp_key = { .dip = tp_msg_ctx->dst.ip };
    ctp_table_entry_t *ctp_table_entry = ctp_table_lookup(&ctx->table_ctx->ctp_table, &ctp_key);

    int ret = 0;
    if (ctp_table_entry != NULL) {
        TPSA_LOG_INFO("ctp %u, already exist, try map to vtp", ctp_table_entry->ctp_idx);
        uvs_map_param_t uparam = {
            .fe_idx = cparam->fe_idx,
            .sip = sip_entry.addr,
            .vtpn = vtpn,
        };
        ret = uvs_clan_map_vtp(ctx->ioctl_ctx, ctx->table_ctx, &uparam, cparam, ctp_table_entry);
    } else {
        TPSA_LOG_INFO("ctp not exist, create ctp process");
        uvs_create_ctp_param_t uparam = {
            .key = ctp_key,
            .sip = sip_entry.addr,
            .prefix_len = sip_entry.prefix_len,
            .vtpn = vtpn
        };
        ret = uvs_create_ctp(ctx->ioctl_ctx, ctx->table_ctx, cparam, &uparam);
    }

    return ret;
}

int uvs_create_clan_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->req.data;
    uint32_t vtpn;

    clan_vtp_table_key_t clan_vtp_key = { .dst_eid = nlreq->peer_eid };
    clan_vtp_table_entry_t *entry = clan_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &tp_msg_ctx->vport_ctx.key,
                                                             &clan_vtp_key);
    if (entry != NULL) {
        entry->use_cnt++;
        vtpn = entry->vtpn;
        TPSA_LOG_INFO("vtp already exist return vtpn %d, use cnt %u", vtpn, entry->use_cnt);

        if (uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_SUCCESS, vtpn) < 0) {
            TPSA_LOG_ERR("Fail to response nl response in clan vtp");
            return -1;
        }
        return 0;
    }

    tpsa_create_param_t cparam;
    cparam.trans_mode = nlreq->trans_mode;
    cparam.dip = tp_msg_ctx->dst.ip;
    cparam.local_eid = nlreq->local_eid;
    cparam.peer_eid = nlreq->peer_eid;
    cparam.local_jetty = nlreq->local_jetty;
    cparam.peer_jetty = nlreq->peer_jetty;
    cparam.eid_index = nlreq->eid_index;
    cparam.fe_idx = nlmsg->src_fe_idx;
    cparam.vtpn = nlreq->vtpn;
    cparam.live_migrate = false;
    cparam.clan_tp = true;
    cparam.msg_id = nlmsg->req.msg_id;
    cparam.nlmsg_seq = msg->nlmsg_seq;
    cparam.upi = UINT32_MAX;
    cparam.sig_loop = false; /* to do, need to adapt to loopback scene  */
    cparam.location = TPSA_INITIATOR;
    memcpy(cparam.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    if (uvs_create_clan_vtp_base(ctx, &cparam, tp_msg_ctx, &vtpn) < 0) {
        TPSA_LOG_ERR("Fail to create or map vtp um.");
        return -1;
    }

    if (uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_SUCCESS, vtpn) < 0) {
        TPSA_LOG_ERR("Fail to response nl response in clan vtp");
        return -1;
    }
    return 0;
}

int uvs_destroy_ctp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx,
                    ctp_table_key_t *key, uvs_net_addr_info_t *sip, uint32_t ctp_idx)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_destroy_ctp(cfg, key, sip, ctp_idx);
    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy Ctp in worker, idx:%u", ctp_idx);
        free(cfg);
        return -1;
    }

    int ret = ctp_table_remove(&table_ctx->ctp_table, key);
    if (ret != 0) {
        TPSA_LOG_ERR("ctp table remove failed idx:%u", ctp_idx);
        free(cfg);
        return -1;
    }

    TPSA_LOG_INFO("destroy ctp success idx:%u", ctp_idx);
    free(cfg);
    return 0;
}

static uint32_t uvs_get_cna_len(uvs_net_addr_info_t *sip, uint32_t prefix_len)
{
    /* ipv4 */
    if (sip->type == UVS_NET_ADDR_TYPE_IPV4) {
        return ((prefix_len > UVS_MAX_IPV4_BIT_LEN) ? 0 : (UVS_MAX_IPV4_BIT_LEN - prefix_len));
    }

    /* ipv6 */
    return ((prefix_len > UVS_MAX_IPV6_BIT_LEN) ? 0 : (UVS_MAX_IPV6_BIT_LEN - prefix_len));
}

/* ctp not exist, create ctp, create vtp and mapping in one ioctl */
int uvs_create_ctp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_table_t *table_ctx, tpsa_create_param_t *cparam,
                   uvs_create_ctp_param_t *uparam)
{
    int ret;
    clan_vtp_table_key_t clan_vtp_key;

    vport_key_t fe_key = { 0 };
    fe_key.fe_idx = cparam->fe_idx;
    memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    /* IOCTL to create ctp; */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_create_ctp(cfg, cparam, &uparam->key, &uparam->sip,
                              uvs_get_cna_len(&uparam->sip, uparam->prefix_len));
    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to create ctp in worker");
        free(cfg);
        return -1;
    }

    *uparam->vtpn = cfg->cmd.create_ctp.out.vtpn;
    uint32_t ctpn = cfg->cmd.create_ctp.out.idx;

    clan_vtp_key.dst_eid = cparam->peer_eid;

    tpsa_clan_vtp_table_param_t clan_vtp_param = {
        .vtpn = *uparam->vtpn,
        .ctp_idx = ctpn,
    };

    ret = clan_fe_vtp_table_add(&table_ctx->fe_table, &fe_key, &clan_vtp_key, &clan_vtp_param);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to add clan_vtp_table");
        goto ROLL_BACK;
    }

    ret = ctp_table_add(&table_ctx->ctp_table, &uparam->key, ctpn);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to add ctp table");
        goto REMOVE_VTP_TABLE;
    }

    free(cfg);
    TPSA_LOG_INFO("add clan vtp success vtpn:%d, ctp_idx:%d", *uparam->vtpn, ctpn);
    return 0;

REMOVE_VTP_TABLE:
    (void) clan_vtp_table_remove(&table_ctx->fe_table, &fe_key, &clan_vtp_key);
ROLL_BACK:
    /* roll back vtp first */
    (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->sip, (urma_transport_mode_t)cparam->trans_mode,
                               cparam->local_eid, cparam->peer_eid, cparam->peer_jetty, cparam->location);
    (void) tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    free(cfg);

     /* roll back ctp */
    (void)uvs_destroy_ctp(ioctl_ctx, table_ctx, &uparam->key, &uparam->sip, ctpn);
    return -1;
}

static int uvs_reduce_ctp_use_cnt(uvs_ctx_t *ctx, ctp_table_key_t *ctp_key, uvs_net_addr_info_t *sip, uint32_t vtpn)
{
    ctp_table_entry_t *ctp_table_entry = ctp_table_lookup(&ctx->table_ctx->ctp_table, ctp_key);
    if (ctp_table_entry == NULL) {
        /* todo rollback vtp? */
        TPSA_LOG_ERR("Fail to ioctl to destroy ctp in worker");
        return -1;
    }

    uint32_t ctp_idx = ctp_table_entry->ctp_idx;
    ctp_table_entry->use_cnt--;
    if (ctp_table_entry->use_cnt == 0) {
        // ctp_table_entry should not been used
        TPSA_LOG_DEBUG("no one use ctp %u, destroy it.", ctp_idx);
        (void)uvs_destroy_ctp(ctx->ioctl_ctx, ctx->table_ctx, ctp_key, sip, ctp_idx);
    }

    TPSA_LOG_DEBUG("ioctl to destroy clan vtp in worker success, vtpn:%u, utp_idx:%u", vtpn, ctp_idx);
    return 0;
}

static int uvs_destroy_clan_vtp_base(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx,
                                     clan_vtp_table_key_t *clan_vtp_key, uint32_t vtpn)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->req.data;

    ctp_table_key_t ctp_key = { .dip = tp_msg_ctx->dst.ip };
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_destroy_vtp(cfg, &tp_msg_ctx->src.ip, (urma_transport_mode_t)nlreq->trans_mode,
        nlreq->local_eid, nlreq->peer_eid, nlreq->peer_jetty, TPSA_INITIATOR);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy vtp in worker");
        free(cfg);
        return -1;
    }
    free(cfg);

    /* todonext failed rollback? */
    (void)clan_vtp_table_remove(&ctx->table_ctx->fe_table, &tp_msg_ctx->vport_ctx.key, clan_vtp_key);

    int ret = uvs_reduce_ctp_use_cnt(ctx, &ctp_key, &tp_msg_ctx->src.ip, vtpn);
    if (ret < 0) {
        return ret;
    }
    ret = uvs_response_destroy_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_SUCCESS);
    if (ret < 0) {
        TPSA_LOG_ERR("Send tpsa NETLINK destroy vtp resp failed\n");
        return ret;
    }
    TPSA_LOG_DEBUG("Finish NETLINK tp ubcore when destroy clan vtp\n");
    return 0;
}

int uvs_destroy_clan_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->req.data;
    int ret = 0;
    clan_vtp_table_key_t clan_vtp_key = { .dst_eid = nlreq->peer_eid };
    clan_vtp_table_entry_t *clan_vtp_entry = clan_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
                                                                      &tp_msg_ctx->vport_ctx.key, &clan_vtp_key);
    if (clan_vtp_entry == NULL) {
        TPSA_LOG_ERR("Fail to find vtp table by key destroy vtp request");
        return -1;
    }

    uint32_t vtpn = clan_vtp_entry->vtpn;
    clan_vtp_entry->use_cnt--;
    if (clan_vtp_entry->use_cnt != 0) {
        TPSA_LOG_INFO("ioctl to destroy clan vtp in worker success, other jetty in use it, vtpn:%u, use cnt:%u",
            vtpn, clan_vtp_entry->use_cnt);
        ret = uvs_response_destroy_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_SUCCESS);
        if (ret < 0) {
            TPSA_LOG_WARN("Send tpsa NETLINK destroy vtp resp failed\n");
        }
        return ret;
    }

    ret = uvs_destroy_clan_vtp_base(ctx, msg, tp_msg_ctx, &clan_vtp_key, vtpn);
    if (ret < 0) {
        TPSA_LOG_WARN("create clan vtp failed");
    }
    return ret;
}

int uvs_sync_table(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uint32_t src_vtpn, uvs_net_addr_info_t *sip)
{
    vport_key_t key;
    key.fe_idx = cparam->fe_idx;
    memcpy(key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    if (tpsa_get_upi(&key, &ctx->table_ctx->vport_table, cparam->eid_index, &cparam->upi) < 0) {
        TPSA_LOG_ERR("Fail to get upi when init create msg!!! Use upi = 0 instead.");
        cparam->upi = 0;
    }

    tpsa_sock_msg_t *tsync = tpsa_sock_init_table_sync(cparam, TPSA_TABLE_ADD, src_vtpn, sip, &ctx->tpsa_attr);
    if (tpsa_sock_send_msg(ctx->sock_ctx, tsync, sizeof(tpsa_sock_msg_t), cparam->dst_uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp req in worker\n");
        free(tsync);
        return -1;
    }
    free(tsync);
    TPSA_LOG_WARN("Sync table with target when tpg already exists. Socket msg success.\n");

    return 0;
}

static void uvs_table_remove_reused_vtp_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_net_addr_info_t *sip)
{
    tpsa_tpg_table_index_t tpg_idx;
    tpsa_vtp_table_index_t vtp_idx;
    (void)memset(&tpg_idx, 0, sizeof(tpg_idx));
    (void)memset(&vtp_idx, 0, sizeof(vtp_idx));
    int32_t vtpn = 0;
    int32_t tpgn = 0;

    tpg_idx.dip = cparam->dip;
    tpg_idx.local_eid = cparam->local_eid;
    tpg_idx.peer_eid = cparam->peer_eid;
    tpg_idx.ljetty_id = cparam->local_jetty;
    tpg_idx.djetty_id = cparam->peer_jetty;
    tpg_idx.upi = cparam->upi;
    tpg_idx.trans_mode = cparam->trans_mode;
    tpg_idx.sip = *sip;

    uvs_end_point_t local = { *sip, cparam->local_eid, cparam->local_jetty };
    uvs_end_point_t peer = { cparam->dip, cparam->peer_eid, cparam->peer_jetty };

    tpg_idx.isLoopback = uvs_is_loopback(cparam->trans_mode, &local, &peer);
    tpg_idx.sig_loop = uvs_is_sig_loop(cparam->trans_mode, &local, &peer);

    vtp_idx.local_eid = cparam->local_eid;
    vtp_idx.peer_eid = cparam->peer_eid;
    vtp_idx.peer_jetty = cparam->peer_jetty;
    vtp_idx.local_jetty = cparam->local_jetty;
    vtp_idx.location = TPSA_INITIATOR,
    vtp_idx.isLoopback = tpg_idx.isLoopback,
    vtp_idx.upi = tpg_idx.upi,
    vtp_idx.sig_loop = tpg_idx.sig_loop,
    vtp_idx.trans_mode = cparam->trans_mode;
    vtp_idx.fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(vtp_idx.fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    uvs_table_remove_vtp_tpg(&vtpn, &tpgn, &tpg_idx, &vtp_idx, ctx->table_ctx);
}

int uvs_create_vtp_reuse_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_net_addr_info_t *sip,
                             tpsa_vtp_table_param_t *vtp_table_data, uvs_nl_resp_info_t *nl_resp)
{
    bool isLoopback = false;

    uvs_end_point_t local = { *sip, cparam->local_eid, cparam->local_jetty };
    uvs_end_point_t peer = { cparam->dip, cparam->peer_eid, cparam->peer_jetty };
    isLoopback = uvs_is_loopback(cparam->trans_mode, &local, &peer);

    TPSA_LOG_INFO("Reuse tpg %d when we create vtp.", vtp_table_data->tpgn);

    vport_key_t fe_key = {0};
    fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(fe_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);

    /* IOCTL to mapping vtp */
    if (uvs_map_vtp(ctx->ioctl_ctx, cparam, vtp_table_data->tpgn, sip, &vtp_table_data->vtpn) < 0) {
        return -1;
    }
    // this vtp_table_data->vtpn should not be changed after this step and will be sent to the driver
    TPSA_LOG_INFO("Finish IOCTL to mapping vtp in initiator.\n");
    TPSA_LOG_WARN("Add local vtp and tpg table when tpg already exists. vtpn: %d, tpgn %d\n",
                  vtp_table_data->vtpn, vtp_table_data->tpgn);
    vtp_table_data->valid = true;

    tpsa_tpg_table_param_t tpg_data = {0};
    tpg_data.use_cnt = 1;
    tpg_data.ljetty_id = cparam->local_jetty;
    tpg_data.leid = cparam->local_eid;
    tpg_data.dip = cparam->dip;
    tpg_data.isLoopback = isLoopback;
    tpg_data.live_migrate = cparam->live_migrate;

    vtp_table_data->share_mode = cparam->share_mode;
    if (uvs_table_add(cparam, ctx->table_ctx, &tpg_data, vtp_table_data) < 0) {
        TPSA_LOG_ERR("Failed to add table when create vtp and tpg already exists\n");
        goto unmap_vtp;
    }

    if (uvs_create_resp_to_lm_src(ctx, fe_key) != 0) {
        TPSA_LOG_ERR("uvs create resp to live_migrate source failed");
        goto remove_table;
    }

    /* Sync table with target */
    if (!isLoopback) {
        if (uvs_sync_table(ctx, cparam, vtp_table_data->vtpn, sip) < 0) {
            TPSA_LOG_ERR("Fail to sync table when reuse tpg");
            goto remove_table;
        }
        // resp ubcore, when recv TPSA_TABLE_SYC_RESP
        nl_resp->resp = false;
        nl_resp->status = TPSA_NL_RESP_IN_PROGRESS;
    } else {
        // resp ubcore immediately
        nl_resp->resp = true;
        nl_resp->status = TPSA_NL_RESP_SUCCESS;
    }
    nl_resp->vtpn = vtp_table_data->vtpn;
    return 0;

remove_table:
    uvs_table_remove_reused_vtp_tpg(ctx, cparam, sip);
unmap_vtp:
    uvs_unmap_vtp(ctx->ioctl_ctx, cparam, sip);
    return -1;
}

/*
    1. If the configration doesn't mention algorithm,
        pick the algorithm that is better with the same priority
    2. If the configration doesn't mention algorithm and priority,
        pick the higher priority and then pick the best algorithm
*/
static int tpsa_get_cc_query_result(tpf_dev_table_entry_t tpf_dev_table, tpsa_tp_mod_cfg_t *local_tp_cfg,
    uint32_t *cc_array_cnt, tpsa_tp_cc_entry_t *cc_result_array)
{
    bool set_cc_priority = local_tp_cfg->set_cc_priority;
    tpsa_cc_entry_t *cc_info_array = tpf_dev_table.cc_array;
    uint8_t cc_priority = local_tp_cfg->cc_priority;
    bool set_cc_alg = local_tp_cfg->set_cc_alg;
    uint16_t cc_alg = local_tp_cfg->cc_alg;
    uint32_t cnt = tpf_dev_table.cc_entry_cnt;
    uint32_t i;
    uint32_t j = 0;

    for (i = 0; i < cnt; i++) {
        if ((cc_info_array[i].cc_priority >= cc_priority || !set_cc_priority) &&
            (((0x1 << (uint16_t)cc_info_array[i].alg) & cc_alg) || !set_cc_alg)) {
            cc_result_array[j].alg = (urma_tp_cc_alg_t)cc_info_array[i].alg;
            cc_result_array[j].cc_priority = cc_info_array[i].cc_priority;
            cc_result_array[j].set_cc_priority = set_cc_priority;
            cc_result_array[j].cc_pattern_idx = cc_info_array[i].cc_pattern_idx;
            j++;
        }
    }
    *cc_array_cnt = j;

    return j == 0 ? -1 : 0;
}

static void tpsa_query_cc_algo(char *tpf_name, tpf_dev_table_t *tpf_dev_table, tpsa_tp_mod_cfg_t *tp_cfg,
                               uint32_t *cc_array_cnt, tpsa_tp_cc_entry_t *cc_result_array)
{
    tpf_dev_table_entry_t tpf_dev_table_entry;
    (void)pthread_rwlock_wrlock(&tpf_dev_table->rwlock);
    if (tpsa_lookup_tpf_dev_table(tpf_name, tpf_dev_table, &tpf_dev_table_entry) != 0) {
        TPSA_LOG_WARN("Failed to lookup tpf dev table");
    } else {
        if (tpsa_get_cc_query_result(tpf_dev_table_entry, tp_cfg,
            cc_array_cnt, cc_result_array) != 0) {
            tp_cfg->tp_mod_flag.bs.cc_en = 0;
            TPSA_LOG_WARN("Local side: cannot get cc query result given cc priority-%hhu and algorithm-%hu",
                tp_cfg->cc_priority, tp_cfg->cc_alg);
        }
    }
    (void)pthread_rwlock_unlock(&tpf_dev_table->rwlock);
}

static int uvs_create_lb_vtp(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, tpsa_ioctl_cfg_t *cfg,
                             uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_cmd_create_tpg_t *cmd = (tpsa_cmd_create_tpg_t *)calloc(1, sizeof(tpsa_cmd_create_tpg_t));
    if (cmd == NULL) {
        return -ENOMEM;
    }

    (void)memcpy(cmd, &cfg->cmd.create_tpg, sizeof(tpsa_cmd_create_tpg_t));
    (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));

    vport_param_t *vport_param = &tp_msg_ctx->vport_ctx.param;
    tpsa_init_vtp_cmd_param_t param;
    (void)memset(&param, 0, sizeof(tpsa_init_vtp_cmd_param_t));
    param.sip = tp_msg_ctx->src.ip;
    param.local_tp_cfg = vport_param->tp_cfg;
    param.mtu = cparam->mtu;
    param.cc_pattern_idx = vport_param->tp_cfg.cc_pattern_idx;
    param.udp_range = vport_param->tp_cfg.udp_range;
    param.local_net_addr_idx = vport_param->sip_idx;
    param.flow_label = vport_param->tp_cfg.flow_label;
    param.tp_cnt = vport_param->tp_cnt;

    tpsa_query_cc_algo(cparam->tpf_name, &ctx->table_ctx->tpf_dev_table, &param.local_tp_cfg,
                       &param.cc_array_cnt, param.cc_result_array);

    tpsa_ioctl_cmd_create_lb_vtp(cfg, cparam, cmd, &param);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to create lb vtp in worker");
        free(cmd);
        return -1;
    }

    free(cmd);
    TPSA_LOG_INFO("Finish IOCTL to create lb vtp in initiator.\n");

    return 0;
}

/* check rc ljetty already connect by others */
bool uvs_rc_check_ljetty(tpsa_table_t *table_ctx, uint32_t ljetty_id, urma_eid_t *local_eid,
                         uint32_t peer_jetty_id, urma_eid_t *peer_eid)
{
    jetty_peer_table_key_t key = {
        .ljetty_id = ljetty_id,
        .seid = *local_eid,
    };

    jetty_peer_table_entry_t *entry = jetty_peer_table_lookup(&table_ctx->jetty_peer_table, &key);
    if (entry == NULL) {
        return false;
    }

    if (peer_jetty_id != entry->djetty_id ||
        memcmp(&entry->deid, peer_eid, sizeof(urma_eid_t)) != 0) {
        TPSA_LOG_WARN("local jetty %u, leid:" EID_FMT " already connect by remote jetty %u, deid:" EID_FMT "\n",
                    ljetty_id, EID_ARGS(*local_eid), entry->djetty_id, EID_ARGS(entry->deid));
        return true;
    }

    return false;
}

int uvs_rc_valid_check(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, bool isLoopback)
{
    if (uvs_rc_check_ljetty(ctx->table_ctx, cparam->local_jetty, &cparam->local_eid,
                            cparam->peer_jetty, &cparam->peer_eid)) {
        return -1;
    }

    if (isLoopback) {
        if (uvs_rc_check_ljetty(ctx->table_ctx, cparam->peer_jetty, &cparam->peer_eid,
                                cparam->local_jetty, &cparam->local_eid)) {
            return -1;
        }
    }

    return 0;
}

static int uvs_no_share_mode_reuse_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam,
    uvs_net_addr_info_t *sip, tpsa_vtp_table_param_t *vtp_table_data, uvs_nl_resp_info_t *nl_resp)
{
    rm_vtp_table_entry_t *share_mode_entry = NULL;

    rm_vtp_table_key_t vtp_key = {0};
    vtp_key.src_eid = cparam->local_eid;
    vtp_key.dst_eid = cparam->peer_eid;
    vport_key_t vport_key = {0};
    (void)memcpy(vport_key.tpf_name, cparam->tpf_name, UVS_MAX_DEV_NAME);
    vport_key.fe_idx = cparam->fe_idx;
    share_mode_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
        &vport_key, &vtp_key);
    if (share_mode_entry != NULL) {
        if (!share_mode_entry->share_mode) {
            vtp_table_data->tpgn = share_mode_entry->tpg_param->tpgn;
        }
    } else {
        TPSA_LOG_INFO("cannot find rm fe vtp with seid " EID_FMT " and deid " EID_FMT "\n",
                EID_ARGS(vtp_key.src_eid), EID_ARGS(vtp_key.dst_eid));
        return 0;
    }

    if (uvs_create_vtp_reuse_tpg(ctx, cparam, sip, vtp_table_data, nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
        return -1;
    }

    return 0;
}

int uvs_create_vtp_preprocess(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, uvs_net_addr_info_t *sip,
                              tpsa_tpg_table_index_t *tpg_idx, uvs_nl_resp_info_t *nl_resp)
{
    tpsa_vtp_table_param_t vtp_table_data = {0};
    tpsa_tpg_info_t tpg;
    tpsa_tpg_status_t res = (tpsa_tpg_status_t)0;

    /* in non_share_mode scenarios, new tpg need to be created for each vtp */
    if (!cparam->share_mode) {
        return uvs_no_share_mode_reuse_tpg(ctx, cparam, sip, &vtp_table_data, nl_resp);
    }

    res = tpsa_lookup_tpg_table(tpg_idx, cparam->trans_mode, ctx->table_ctx, &tpg);
    if (res == TPSA_TPG_LOOKUP_EXIST) {
        if (cparam->trans_mode == TPSA_TP_RC && cparam->live_migrate == true) {
            /* for lm scenarios, alternative channels need to be created. */
            return 0;
        }
        vtp_table_data.tpgn = tpg.tpgn;
        if (uvs_create_vtp_reuse_tpg(ctx, cparam, sip, &vtp_table_data, nl_resp) < 0) {
            TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
            return -1;
        }

        return 0;
    } else if (res == TPSA_TPG_LOOKUP_IN_PROGRESS) {
        TPSA_LOG_INFO("TPSA connection establish is IN PROGESS! Add to wait table\n");
        if (uvs_add_wait(ctx->table_ctx, cparam, TPSA_INITIATOR) < 0) {
            TPSA_LOG_ERR("Fail to add wait table");
            return -1;
        }

        /* nl_resp */
        nl_resp->resp = false;
        nl_resp->status = TPSA_NL_RESP_IN_PROGRESS;
        nl_resp->vtpn = UINT32_MAX;

        return 0;
    } else if (res == TPSA_TPG_LOOKUP_ALREADY_BIND) {
        TPSA_LOG_INFO("TPSA RC jetty already bind by other rc jetty\n");

        /* nl_resp */
        nl_resp->resp = true;
        nl_resp->status = TPSA_NL_RESP_FAIL;
        nl_resp->vtpn = UINT32_MAX;

        return 0;
    } else if (res == TPSA_TPG_LOOKUP_NULL) {
        if (cparam->trans_mode == TPSA_TP_RC &&
            uvs_rc_valid_check(ctx, cparam, tpg_idx->isLoopback) < 0) {
            /* nl_resp */
            nl_resp->resp = true;
            nl_resp->status = TPSA_NL_RESP_FAIL;
            nl_resp->vtpn = UINT32_MAX;

            return 0;
        }

        // need to create new tpg
        return 0;
    }
    return 0;
}

int uvs_add_tpg_state_entry(tpsa_table_t *table_ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_tpg_info_t *tpg_info)
{
    tpg_state_table_entry_t add_entry = {0};
    add_entry.key.sip = tp_msg_ctx->src.ip;
    add_entry.key.tpgn = tpg_info->tpgn;

    add_entry.tpgn = tpg_info->tpgn;

    add_entry.tpg_exc_state = TPG_STATE_INIT;
    add_entry.dip = tp_msg_ctx->dst.ip;
    add_entry.peer_uvs_ip = tp_msg_ctx->peer.uvs_ip;
    add_entry.tpgn = tpg_info->tpgn;
    add_entry.tp_cnt = tpg_info->tp_cnt;
    (void)memcpy(add_entry.tpn, tpg_info->tpn, sizeof(tpg_info->tpn));
    add_entry.tp_flush_cnt = tpg_info->tp_cnt;

    return uvs_add_tpg_state_table(table_ctx, &add_entry);
}

int uvs_rmv_all_tp_state_entry(tpsa_table_t *table_ctx, uint32_t tpgn, uvs_net_addr_info_t *sip)
{
    tpg_state_table_key_t tpg_key = {.tpgn = tpgn, .sip = *sip};
    tpg_state_table_entry_t *entry = tpg_state_table_lookup(&table_ctx->tpg_state_table, &tpg_key);
    if (entry == NULL) {
        TPSA_LOG_WARN("tpn %d not exist", tpg_key.tpgn);
        return -ENXIO;
    }

    for (uint32_t i = 0; i < entry->tpgn && i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        tp_state_table_key_t tp_key = {.tpn = entry->tpn[i], .sip = *sip};
        (void)tp_state_table_remove(&table_ctx->tp_state_table, &tp_key);
    }
    return 0;
}

int uvs_rmv_tpg_state_entry(tpsa_table_t *table_ctx, uint32_t tpgn, uvs_net_addr_info_t *sip)
{
    tpg_state_table_key_t key = {.tpgn = tpgn, .sip = *sip};
    return tpg_state_table_remove(&table_ctx->tpg_state_table, &key);
}

int uvs_create_vtp_base(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_create_param_t *cparam,
                        tpsa_tpg_table_index_t *tpg_idx, uvs_nl_resp_info_t *nl_resp)
{
    tpsa_vtp_table_param_t vtp_table_data = {0};
    tpsa_tpg_table_param_t tpg_data = {0};
    sip_table_entry_t sip_entry = {0};
    tpsa_tpg_info_t tpg_info = {0};
    tpsa_sock_msg_t *req = NULL;
    int res = 0;

    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry);

    vtp_table_data.share_mode = cparam->share_mode;

    if (!vtp_table_data.share_mode) {
        TPSA_LOG_INFO("Detect non_share_mode vtp_table_data");
    }

    if (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_create_vtp_preprocess(ctx, cparam, &sip_entry.addr, tpg_idx, nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to preprocess create vtp req");
        return -1;
    }

    if (nl_resp->resp == true || nl_resp->status == TPSA_NL_RESP_IN_PROGRESS) {
        /* don't need to create new tpg */
        return 0;
    }

    /* IOCTL to create TPG; construct tp_param according to create output */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_create_tpg(cfg, cparam, &sip_entry.addr, &tp_msg_ctx->vport_ctx.param, &tp_msg_ctx->dst.ip);
    uvs_cal_multi_tp_statistic(cparam->tpf_name,
        cparam->trans_mode, UVS_TP_OPENING_STATE, cfg->cmd.create_tpg.in.tpg_cfg.tp_cnt);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to create tpg in worker");
        res = -1;
        goto free_cfg;
    }

    tpg_info.tpgn = cfg->cmd.create_tpg.out.tpgn;
    tpg_info.tp_cnt = cfg->cmd.create_tpg.in.tpg_cfg.tp_cnt;
    memcpy(tpg_info.tpn, cfg->cmd.create_tpg.out.tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

    if (uvs_add_tpg_state_entry(ctx->table_ctx, tp_msg_ctx, &tpg_info) != 0) {
        res = -1;
        goto destory_tpg;
    }
    TPSA_LOG_INFO("-------------------create tpgn: %d, tpn: %d in initiator with share mode: %u.\n",
        cfg->cmd.create_tpg.out.tpgn, cfg->cmd.create_tpg.out.tpn[0], vtp_table_data.share_mode);

    tpg_data.type = 0;
    tpg_data.use_cnt = 1;
    tpg_data.ljetty_id = cparam->local_jetty;
    tpg_data.leid = cparam->local_eid;
    tpg_data.dip = tp_msg_ctx->dst.ip;
    tpg_data.isLoopback = tpg_idx->isLoopback;
    tpg_data.live_migrate = cparam->live_migrate;
    tpg_data.tp_cnt = cfg->cmd.create_tpg.in.tpg_cfg.tp_cnt;
    if (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB && tpg_idx->isLoopback) {
        /* Loopback create vtp and response netlink */
        if (uvs_create_lb_vtp(ctx, cparam, cfg, tp_msg_ctx) < 0) {
            TPSA_LOG_ERR("Fail to create lb vtp");
            res = -1;
            goto destory_tpg;
        }

        TPSA_LOG_INFO("Finish create lb vtp when create vtp.\n");

        /* Add invalid vtpn to vtp table and tpg table to avoid duplication establish */
        vtp_table_data.vtpn = cfg->cmd.create_vtp.out.vtpn;
        vtp_table_data.valid = true;
        tpg_data.tpgn = cfg->cmd.create_vtp.in.tpgn;
        tpg_data.status = TPSA_TPG_LOOKUP_EXIST;
        /* nl_resp */
        nl_resp->resp = true;
        nl_resp->status = TPSA_NL_RESP_SUCCESS;
        nl_resp->vtpn = vtp_table_data.vtpn;
    } else {
        /* Create msg to connect to peer */
        tpsa_init_sock_req_param_t param = {0};
        param.local_tp_cfg = tp_msg_ctx->vport_ctx.param.tp_cfg;
        param.local_tp_cfg.port = cparam->port_id;
        param.peer_net_addr = tp_msg_ctx->dst.ip;
        param.local_mtu = (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB
                               ? uvs_get_min_valid_mtu(uvs_get_mtu(ctx, tp_msg_ctx), cfg->cmd.create_tpg.local_mtu)
                               : cfg->cmd.create_tpg.local_mtu);
        param.tpg_cfg = cfg->cmd.create_tpg.in.tpg_cfg;
        param.local_tpn = &cfg->cmd.create_tpg.out.tpn[0];
        param.local_net_addr_idx = tp_msg_ctx->vport_ctx.param.sip_idx;
        param.local_seg_size = SEG_SIZE;
        param.upi = (uint32_t)cparam->upi;
        param.tpgn = cfg->cmd.create_tpg.out.tpgn;
        param.tp_cnt = cfg->cmd.create_tpg.in.tpg_cfg.tp_cnt;
        param.cc_en = tp_msg_ctx->vport_ctx.param.tp_cfg.tp_mod_flag.bs.cc_en;

        tpsa_query_cc_algo(cparam->tpf_name, &ctx->table_ctx->tpf_dev_table, &param.local_tp_cfg,
                           &param.cc_array_cnt, param.cc_result_array);
        req = tpsa_sock_init_create_req(cparam, &param, &sip_entry.addr, &ctx->tpsa_attr);
        if (req == NULL) {
            TPSA_LOG_ERR("Fail to init create socket msg");
            res = -1;
            goto destory_lb_vtp;
        }
        if (tpsa_sock_send_msg(ctx->sock_ctx, req, sizeof(tpsa_sock_msg_t), tp_msg_ctx->peer.uvs_ip) != 0) {
            TPSA_LOG_ERR("Failed to send create vtp req in worker\n");
            res = -1;
            goto free_sock_req;
        }

        TPSA_LOG_INFO("Finish send socket message from initiator.\n");

        /* Add invalid vtpn to vtp table and tpg table to avoid duplication establish */
        vtp_table_data.vtpn = UINT32_MAX;
        vtp_table_data.valid = false;
        tpg_data.tpgn = cfg->cmd.create_tpg.out.tpgn;
        tpg_data.status = TPSA_TPG_LOOKUP_IN_PROGRESS;
        (void)memcpy(tpg_data.tpn, cfg->cmd.create_tpg.out.tpn,
            TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

        for (uint32_t i = 0; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
            TPSA_LOG_DEBUG("tpn get in uvs tpn[%u] = %u.\n", i, tpg_data.tpn[i]);
        }
    }

    vtp_table_data.upi = tpg_idx->upi;
    if (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_table_add(cparam, ctx->table_ctx, &tpg_data, &vtp_table_data) < 0) {
        TPSA_LOG_ERR("Failed to prefill table when create vtp\n");
        res = -1;
        goto free_sock_req;
    }

free_sock_req:
    if (req != NULL) {
        free(req);
    }
destory_lb_vtp:
    if (res != 0 && cparam->ta_data.trans_type == TPSA_TRANSPORT_UB && tpg_idx->isLoopback) {
        tpsa_ioctl_cmd_destroy_vtp(cfg, &sip_entry.addr, (urma_transport_mode_t)cparam->trans_mode,
            cparam->local_eid,  cparam->peer_eid, cparam->peer_jetty, TPSA_INITIATOR);
        (void)tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg);
    }
destory_tpg:
    if (res != 0) {
        tpsa_ioctl_cmd_destroy_tpg(cfg, &sip_entry.addr, cfg->cmd.create_tpg.out.tpgn,
            &cparam->ta_data);
        (void)tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg);
        (void)uvs_rmv_tpg_state_entry(ctx->table_ctx, cfg->cmd.create_tpg.out.tpgn, &sip_entry.addr);
    }
free_cfg:
    uvs_cal_multi_tp_statistic(cparam->tpf_name, cparam->trans_mode,
        UVS_TP_OPENING_FAIL_STATE, tpg_idx->tp_cnt);
    uvs_cal_vtp_statistic(&tp_msg_ctx->vport_ctx.key, cparam->trans_mode, UVS_VTP_ERR_STATE);
    free(cfg);
    return res;
}

/* when uvs reveive the message(TPSA_MSG_STOP_PROC_VTP_MSG), */
/* For new link building requests, uvs notifies the ubcore to try again after a period of time. */
bool uvs_is_fe_in_stop_proc(fe_table_t *fe_table, vport_key_t *key)
{
    (void)pthread_rwlock_rdlock(&fe_table->rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(fe_table, key);
    if (fe_entry != NULL && fe_entry->stop_proc_vtp == true) {
        (void)pthread_rwlock_unlock(&fe_table->rwlock);
        return true;
    }
    (void)pthread_rwlock_unlock(&fe_table->rwlock);
    return false;
}

static inline uint32_t uvs_make_mask_32(uint32_t prefix_len)
{
    if (prefix_len > 0 && prefix_len <= UINT32_WIDTH) {
        return htonl(~((1U << (UINT32_WIDTH - prefix_len)) - 1));
    }
    return 0;
}

static inline uint64_t uvs_make_mask_64(uint32_t prefix_len)
{
    if (prefix_len > 0 && prefix_len <= UINT64_WIDTH) {
        return htobe64(~((1ULL << (UINT64_WIDTH - prefix_len)) - 1));
    }
    return 0;
}

static bool uvs_in_same_subnet_ipv4(uvs_net_addr_info_t *sip, uvs_net_addr_info_t *dip, uint32_t prefix_len)
{
    uint32_t mask = uvs_make_mask_32(prefix_len);
    return ((sip->net_addr.in4.addr & mask) == (dip->net_addr.in4.addr & mask));
}

static bool uvs_in_same_subnet_ipv6(uvs_net_addr_info_t *sip, uvs_net_addr_info_t *dip, uint32_t prefix_len)
{
    uint64_t mask = uvs_make_mask_64((prefix_len > UINT64_WIDTH) ? (prefix_len - UINT64_WIDTH) : prefix_len);
    if (prefix_len > UINT64_WIDTH) {
        return ((sip->net_addr.in6.subnet_prefix == dip->net_addr.in6.subnet_prefix) &&
                ((sip->net_addr.in6.interface_id & mask) == (dip->net_addr.in6.interface_id & mask)));
    }
    return ((sip->net_addr.in6.subnet_prefix & mask) == (dip->net_addr.in6.subnet_prefix & mask));
}

static bool uvs_in_same_subnet(uvs_net_addr_info_t *sip, uvs_net_addr_info_t *dip, uint32_t prefix_len)
{
    if (sip->type != dip->type || prefix_len == 0) {
        TPSA_LOG_WARN("ip type not support, sip type:%d, dip type:%d, prefix len:%u",
            (int)sip->type, (int)dip->type, prefix_len);
        return false;
    }

    /* ipv4 */
    if (sip->type == UVS_NET_ADDR_TYPE_IPV4) {
        return uvs_in_same_subnet_ipv4(sip, dip, prefix_len);
    }

    /* ipv6 */
    return uvs_in_same_subnet_ipv6(sip, dip, prefix_len);
}

bool uvs_is_clan_domain(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->req.data;
    tpf_dev_table_entry_t tpf_dev_table_entry;
    sip_table_entry_t sip_entry;
    uint32_t sip_index;

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->tpf_dev_table.rwlock);
    int ret = tpsa_lookup_tpf_dev_table(nlreq->tpf_name, &ctx->table_ctx->tpf_dev_table, &tpf_dev_table_entry);
    if (ret != 0 || tpf_dev_table_entry.dev_fea.bs.clan == 0) {
        (void)pthread_rwlock_unlock(&ctx->table_ctx->tpf_dev_table.rwlock);
        TPSA_LOG_DEBUG("not support clan domain query ret:%d, dev clan fea:%d, tpf_dev name:%s, dev_name:%s",
            ret, tpf_dev_table_entry.dev_fea.bs.clan, nlreq->tpf_name, nlreq->dev_name);
        return false;
    }

    TPSA_LOG_DEBUG("dev suport clan domain!");
    if (tp_msg_ctx->vport_ctx.param.tp_cfg.force_g_domain) {
        TPSA_LOG_INFO("uvs cfg to force g domain");
        (void)pthread_rwlock_unlock(&ctx->table_ctx->tpf_dev_table.rwlock);
        return false;
    }
    sip_index = tp_msg_ctx->vport_ctx.param.sip_idx;
    if (sip_index >= TPSA_SIP_IDX_TABLE_SIZE || tpf_dev_table_entry.sip_table->entries[sip_index].used == false) {
        (void)pthread_rwlock_unlock(&ctx->table_ctx->tpf_dev_table.rwlock);
        TPSA_LOG_ERR("No available sip entry found");
        return false;
    }
    sip_entry = tpf_dev_table_entry.sip_table->entries[sip_index];
    (void)pthread_rwlock_unlock(&ctx->table_ctx->tpf_dev_table.rwlock);

    if (uvs_get_cna_len(&sip_entry.addr, sip_entry.prefix_len) > UVS_MAX_CNA_LEN) {
        TPSA_LOG_DEBUG("cna_len longer than max cna len, prefixlen: %u\n", sip_entry.prefix_len);
        return false;
    }

    TPSA_LOG_DEBUG("judge is same subnet src eid " EID_FMT " dst eid " EID_FMT ", prefixlen: %u\n",
                  EID_ARGS(sip_entry.addr.net_addr), EID_ARGS(tp_msg_ctx->dst.ip.net_addr), sip_entry.prefix_len);
    return uvs_in_same_subnet(&sip_entry.addr, &tp_msg_ctx->dst.ip, sip_entry.prefix_len);
}

static tpsa_create_param_t *tpsa_init_create_cparam(tpsa_nl_msg_t *msg, uint32_t upi, bool sig_loop,
    uint8_t port_id, uvs_mtu_t mtu)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->req.data;
    tpsa_create_param_t *cparam;

    cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t) + nlreq->ext_len +
        nlreq->udrv_in_len);
    if (cparam == NULL) {
        return NULL;
    }
    cparam->trans_mode = nlreq->trans_mode;
    (void)memset(&cparam->dip, 0, sizeof(uvs_net_addr_info_t));
    cparam->local_eid = nlreq->local_eid;
    cparam->peer_eid = nlreq->peer_eid;
    cparam->local_jetty = nlreq->local_jetty;
    cparam->peer_jetty = nlreq->peer_jetty;
    cparam->eid_index = nlreq->eid_index;
    cparam->fe_idx = nlmsg->src_fe_idx;
    cparam->upi = upi;
    cparam->vtpn = nlreq->vtpn;
    cparam->live_migrate = false;
    cparam->msg_id = nlmsg->req.msg_id;
    cparam->nlmsg_seq = msg->nlmsg_seq;
    cparam->sig_loop = sig_loop;
    memcpy(cparam->tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);
    cparam->ta_data = nlreq->ta_data;
    cparam->port_id = port_id;
    cparam->mtu = mtu;
    /* for alpha */
    cparam->udrv_in_len = nlreq->udrv_in_len;
    cparam->ext_len = nlreq->ext_len;
    (void)memcpy(cparam->udrv_ext, nlreq->udrv_ext, nlreq->udrv_in_len + nlreq->ext_len);
    return cparam;
}

static inline bool uvs_rc_in_same_vtp(urma_eid_t *local_eid, urma_eid_t *peer_eid,
                                      uint32_t local_jetty, uint32_t peer_jetty)
{
    rc_vtp_table_key_t local_key = { *peer_eid,  peer_jetty };
    rc_vtp_table_key_t peer_key = { *local_eid,  local_jetty };
    return (memcmp(&local_key, &peer_key, sizeof(rc_vtp_table_key_t)) == 0);
}

static inline bool uvs_um_in_same_vtp(urma_eid_t *local_eid, urma_eid_t *peer_eid)
{
    rm_vtp_table_key_t local_key = { *local_eid, *peer_eid };
    rm_vtp_table_key_t peer_key = { *peer_eid, *local_eid };
    return (memcmp(&local_key, &peer_key, sizeof(rm_vtp_table_key_t)) == 0);
}

bool uvs_is_loopback(tpsa_transport_mode_t trans_mode, uvs_end_point_t *local, uvs_end_point_t *peer)
{
    /*
    * Loopback mode means not have to negotiate with peer uvs. Only one tpg will be created.
    * RC mode not support one tpg bind to local_jetty and peer_jetty at the same time.
    * UM mode not have to use loopback procedure.
    */
    if (memcmp(&local->ip, &peer->ip, sizeof(uvs_net_addr_info_t)) == 0) {
        if (trans_mode == TPSA_TP_RM) {
            return true;
        }

        if (trans_mode == TPSA_TP_RC) {
            return uvs_rc_in_same_vtp(&local->eid, &peer->eid, local->jetty_id, peer->jetty_id);
        }
    }
    return false;
}

bool uvs_is_sig_loop(tpsa_transport_mode_t trans_mode, uvs_end_point_t *local, uvs_end_point_t *peer)
{
    /* sig_loog to recognize duplex mode vtp in same uvs */
    if (memcmp(&local->ip, &peer->ip, sizeof(uvs_net_addr_info_t)) == 0) {
        if (trans_mode == TPSA_TP_RC) {
            return uvs_rc_in_same_vtp(&local->eid, &peer->eid, local->jetty_id, peer->jetty_id);
        }
        if (trans_mode == TPSA_TP_RM) {
            return uvs_um_in_same_vtp(&local->eid, &peer->eid);
        }
    }
    return false;
}

int uvs_get_tp_msg_ctx(uvs_ctx_t *ctx, tpsa_nl_create_vtp_req_t *nlreq, uint16_t src_function_id,
                       uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tp_msg_ctx->trans_mode = nlreq->trans_mode;
    tp_msg_ctx->trans_type = nlreq->ta_data.trans_type;

    tp_msg_ctx->vport_ctx.key.fe_idx = src_function_id;
    memcpy(tp_msg_ctx->vport_ctx.key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    int ret = tpsa_lookup_vport_param(&tp_msg_ctx->vport_ctx.key, &ctx->table_ctx->vport_table,
                                      &tp_msg_ctx->vport_ctx.param);
    if (ret < 0) {
        TPSA_LOG_ERR("Can not find vport_table by dev:%s-%hu\n",
                     tp_msg_ctx->vport_ctx.key.tpf_name, src_function_id);
        return -1;
    }

    sip_table_entry_t sip_entry = {0};

    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry);
    tp_msg_ctx->src.ip = sip_entry.addr;
    tp_msg_ctx->src.eid = nlreq->local_eid;
    tp_msg_ctx->src.jetty_id = nlreq->local_jetty;

    if (tpsa_get_upi(&tp_msg_ctx->vport_ctx.key, &ctx->table_ctx->vport_table, nlreq->eid_index,
                     &tp_msg_ctx->upi) < 0) {
        TPSA_LOG_ERR("Fail to get upi when init create msg!!! Use upi = 0 instead.");
        tp_msg_ctx->upi = 0;
    }

    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid,
        tp_msg_ctx->upi, &tp_msg_ctx->peer.uvs_ip, &tp_msg_ctx->dst.ip);
    tp_msg_ctx->dst.eid = nlreq->peer_eid;
    tp_msg_ctx->dst.jetty_id = nlreq->peer_jetty;

    tp_msg_ctx->ta_data = nlreq->ta_data;
    tp_msg_ctx->trans_mode = nlreq->trans_mode;

    return 0;
}

static int uvs_handle_vtp_exist(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx, int32_t find_rst, uint32_t vtpn)
{
    TPSA_LOG_INFO("Find vtpn in vtp table. Now feedback vtpn through netlink message");
    uint32_t rsp_vtpn = UINT32_MAX;
    tpsa_nl_resp_status_t stat = TPSA_NL_RESP_IN_PROGRESS;

    if (find_rst == 0) {
        rsp_vtpn = vtpn;
        stat = TPSA_NL_RESP_SUCCESS;
    }
    if (find_rst == TPSA_RC_JETTY_ALREADY_BIND) {
        rsp_vtpn = UINT32_MAX;
        stat = TPSA_NL_RESP_FAIL;
    }

    /* NETLINK to feedback VTPN to UBCORE */
    if (uvs_response_create_fast(msg, nl_ctx, stat, rsp_vtpn) < 0) {
        TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
        return -1;
    }
    return 0;
}

/* vtp table */
int tpsa_lookup_vtp_table(tpsa_table_t *table_ctx, tpsa_transport_mode_t trans_mode,
                          uvs_tp_msg_ctx_t *tp_msg_ctx, uint32_t *vtpn)
{
    int status = TPSA_LOOKUP_NULL;
    switch (trans_mode) {
        case TPSA_TP_RM:
            status = tpsa_lookup_rm_vtp_table(table_ctx, &tp_msg_ctx->vport_ctx.key,
                                              &tp_msg_ctx->src, &tp_msg_ctx->dst, vtpn);
            break;
        case TPSA_TP_RC:
            status = tpsa_lookup_rc_vtp_table(table_ctx, &tp_msg_ctx->vport_ctx.key,
                                              &tp_msg_ctx->src, &tp_msg_ctx->dst, vtpn);
            break;
        case TPSA_TP_UM:
        default:
            TPSA_LOG_ERR("Invalid transport mode");
            break;
    }
    return status;
}

int uvs_create_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *req_host = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)req_host->req.data;
    tpsa_create_param_t *cparam = NULL;
    sip_table_entry_t sip_entry = {0};
    int32_t res = 0;
    bool isLoopback = false;
    bool sig_loop = false;

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    res = uvs_get_tp_msg_ctx(ctx, nlreq, req_host->src_fe_idx, &tp_msg_ctx);
    uvs_cal_vtp_statistic(&tp_msg_ctx.vport_ctx.key, tp_msg_ctx.trans_mode, UVS_VTP_OPENING_STATE);
    if (res < 0) {
        TPSA_LOG_ERR("Fail to get tp msg ctx.");
        (void)uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_FAIL, UINT32_MAX);
        return -1;
    }

    if (uvs_is_fe_in_stop_proc(&ctx->table_ctx->fe_table, &tp_msg_ctx.vport_ctx.key) ||
        uvs_is_fe_in_cleaning_proc(&ctx->table_ctx->fe_table, &tp_msg_ctx.vport_ctx.key) ||
        vport_in_cleaning_proc(&ctx->table_ctx->vport_table, &tp_msg_ctx.vport_ctx.key)) {
        TPSA_LOG_WARN("fe dev_name:%s, fe_idx:%u in cleaning proc", tp_msg_ctx.vport_ctx.key.tpf_name,
            tp_msg_ctx.vport_ctx.key.fe_idx);
        return uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_IN_PROGRESS, UINT32_MAX);
    }

    TPSA_LOG_INFO("create vtp seid " EID_FMT " sjetty: %u, sip: " EID_FMT ", "
                  "deid " EID_FMT ", djetty: %u, dip: " EID_FMT "\n",
                  EID_ARGS(nlreq->local_eid), nlreq->local_jetty, EID_ARGS(tp_msg_ctx.src.ip.net_addr),
                  EID_ARGS(nlreq->peer_eid), nlreq->peer_jetty, EID_ARGS(tp_msg_ctx.dst.ip.net_addr));

    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB && nlreq->trans_mode == TPSA_TP_UM &&
        tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.um_en == 0) {
        TPSA_LOG_ERR("Detect UM trans_mode and um_en equals 0 on local side");
        (void)uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_FAIL, UINT32_MAX);
        return -1;
    }

    /* clan tp not need to negotiate */
    if (uvs_is_clan_domain(ctx, msg, &tp_msg_ctx)) {
        TPSA_LOG_INFO("create vtp in clan domain");
        return uvs_create_clan_vtp(ctx, msg, &tp_msg_ctx);
    }

    /* um no need to negotiate */
    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB && nlreq->trans_mode == TPSA_TP_UM) {
        return uvs_create_um_vtp(ctx, msg, &tp_msg_ctx);
    }

    uint32_t vtpn = 0;
    /* check vtp table */
    TPSA_LOG_DEBUG("Adding rm vtp with seid = " EID_FMT " and deid = " EID_FMT" \n",
            EID_ARGS(tp_msg_ctx.src.eid), EID_ARGS(tp_msg_ctx.dst.eid));

    res = tpsa_lookup_vtp_table(ctx->table_ctx, nlreq->trans_mode, &tp_msg_ctx, &vtpn);
    if (res != TPSA_LOOKUP_NULL) {
        TPSA_LOG_INFO("reuse vtp");
        return uvs_handle_vtp_exist(msg, ctx->nl_ctx, res, vtpn);
    }

    res = 0;
    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx.vport_ctx.key.tpf_name,
        tp_msg_ctx.vport_ctx.param.sip_idx, &sip_entry);

    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        isLoopback = uvs_is_loopback(nlreq->trans_mode, &tp_msg_ctx.src, &tp_msg_ctx.dst);
        sig_loop = uvs_is_sig_loop(nlreq->trans_mode, &tp_msg_ctx.src, &tp_msg_ctx.dst);
    }
    tpsa_tpg_table_index_t tpg_idx;
    tpg_idx.dip = tp_msg_ctx.dst.ip;
    tpg_idx.local_eid = nlreq->local_eid;
    tpg_idx.peer_eid = nlreq->peer_eid;
    tpg_idx.ljetty_id = nlreq->local_jetty;
    tpg_idx.djetty_id = nlreq->peer_jetty;
    tpg_idx.isLoopback = isLoopback;
    tpg_idx.sig_loop = sig_loop;
    tpg_idx.upi = tp_msg_ctx.upi;
    tpg_idx.trans_mode = nlreq->trans_mode;
    tpg_idx.sip = sip_entry.addr;
    tpg_idx.tp_cnt = tp_msg_ctx.vport_ctx.param.tp_cnt;

    uvs_mtu_t mtu;
    mtu = uvs_get_mtu(ctx, &tp_msg_ctx);

    cparam = tpsa_init_create_cparam(msg, tp_msg_ctx.upi, sig_loop, sip_entry.port_id[0], mtu);
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam memory.");
        return -1;
    }
    cparam->dip = tp_msg_ctx.dst.ip;
    cparam->dst_uvs_ip = tp_msg_ctx.peer.uvs_ip;
    cparam->pattern = tp_msg_ctx.vport_ctx.param.pattern;
    cparam->location = TPSA_INITIATOR;
    if ((cparam->ta_data.trans_type == TPSA_TRANSPORT_UB && cparam->trans_mode == TPSA_TP_RM) &&
        tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.share_mode == 0) {
        cparam->share_mode = false;
        TPSA_LOG_INFO("Detect non-share_mode on local side, share_mode = %u and pattern = %u",
            tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.share_mode,
            tp_msg_ctx.vport_ctx.param.pattern);
    } else {
        cparam->share_mode = true;
        TPSA_LOG_DEBUG("Detect share_mode on local side");
    }

    uvs_nl_resp_info_t nl_resp = {
        .resp = false,
        .status = TPSA_NL_RESP_FAIL,
        .vtpn = UINT32_MAX,
    };

    if (uvs_create_vtp_base(ctx, &tp_msg_ctx, cparam, &tpg_idx, &nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to run create tpg base.");
        (void)uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_FAIL, UINT32_MAX);
        free(cparam);
        return -1;
    }

    if (nl_resp.resp == true) {
        /* NETLINK to feedback VTPN to UBCORE */
        if (uvs_response_create_fast(msg, ctx->nl_ctx, nl_resp.status, nl_resp.vtpn) < 0) {
            TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
            free(cparam);
            return -1;
        }
    }
    free(cparam);
    return 0;
}

static tpsa_tpg_status_t tpsa_reuse_target_tpg(uvs_ctx_t *ctx, uvs_net_addr_info_t *sip, uvs_net_addr_info_t *dip,
    tpsa_sock_msg_t *msg, tpsa_tpg_info_t *tpsa_tpg_info)
{
    tpsa_tpg_table_index_t tpg_idx;
    tpg_idx.dip = *dip;
    tpg_idx.local_eid = msg->peer_eid;
    tpg_idx.peer_eid = msg->local_eid;
    tpg_idx.ljetty_id = msg->peer_jetty;
    tpg_idx.djetty_id = msg->local_jetty;
    tpg_idx.upi = msg->upi;

    uvs_end_point_t local = { *sip, msg->local_eid, msg->local_jetty };
    uvs_end_point_t peer = { *dip, msg->peer_eid, msg->peer_jetty };
    tpg_idx.isLoopback = uvs_is_loopback(msg->trans_mode, &local, &peer);
    tpg_idx.sig_loop = uvs_is_sig_loop(msg->trans_mode, &local, &peer);
    tpg_idx.trans_mode = msg->trans_mode;
    tpg_idx.sip = *sip;
    tpg_idx.tp_cnt = msg->content.req.tpg_cfg.tp_cnt;

    if (msg->live_migrate == true && tpg_idx.trans_mode == TPSA_TP_RC) {
        return TPSA_TPG_LOOKUP_NULL;
    }

    return tpsa_lookup_tpg_table(&tpg_idx, tpg_idx.trans_mode, ctx->table_ctx, tpsa_tpg_info);
}

static int uvs_add_tpg_entry(tpsa_transport_type_t trans_type, tpsa_sock_msg_t *msg,
    tpsa_tpg_table_param_t *tparam, tpsa_table_t *table_ctx)
{
    if (trans_type == TPSA_TRANSPORT_UB && msg->trans_mode == TPSA_TP_RM) {
        if (tpsa_add_rm_tpg_table(tparam, &table_ctx->rm_tpg_table)) {
            TPSA_LOG_ERR("Failed to add rm tpg table\n");
            return -1;
        }
    } else if (trans_type == TPSA_TRANSPORT_UB && msg->trans_mode == TPSA_TP_RC) {
        if (tpsa_add_rc_tpg_table(msg->local_eid, msg->local_jetty, tparam, &table_ctx->rc_tpg_table)) {
            TPSA_LOG_ERR("Failed to add rc tpg table\n");
            return -1;
        }
        jetty_peer_table_param_t parm = {
            .seid = tparam->leid,
            .deid = msg->local_eid,
            .ljetty_id = tparam->ljetty_id,
            .djetty_id = msg->local_jetty
        };
        if (jetty_peer_table_add(&table_ctx->jetty_peer_table, &parm) != 0) {
            TPSA_LOG_ERR("Failed to add rc jetty peer table\n");
            return -1;
        }
    }
    return 0;
}

static void uvs_del_tpg_entry(tpsa_transport_type_t trans_type, tpsa_sock_msg_t *msg,
    tpsa_tpg_table_param_t *tparam, tpsa_table_t *table_ctx)
{
    if (trans_type != TPSA_TRANSPORT_UB) {
        return;
    }

    tpsa_tpg_info_t find_tpg_info;
    if (msg->trans_mode == TPSA_TP_RM) {
        rm_tpg_table_key_t k = {
            .dip = tparam->dip,
        };
        (void)tpsa_remove_rm_tpg_table(&table_ctx->rm_tpg_table, &k, &find_tpg_info);
    } else if (msg->trans_mode == TPSA_TP_RC) {
        rc_tpg_table_key_t k = {
            .deid = msg->local_eid,
            .djetty_id = msg->local_jetty,
        };
        (void)tpsa_remove_rc_tpg_table(table_ctx, &k, &find_tpg_info);
    }
}

static void tpsa_swap_jetty(struct tpsa_jetty_id *jetty, struct tpsa_jetty_id *tjetty)
{
    struct tpsa_jetty_id tmp;

    tmp = *jetty;
    *jetty = *tjetty;
    *tjetty = tmp;
}

static int uvs_get_tp_msg_ctx_peer_site(tpsa_sock_msg_t *msg, tpsa_table_t *table_ctx, struct tpsa_ta_data *ta_data,
                                        uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tp_msg_ctx->trans_type = ta_data->trans_type;
    tp_msg_ctx->trans_mode = msg->trans_mode;
    tp_msg_ctx->upi = msg->upi;

    /* Use reverse find in peer site */
    uint32_t eid_idx = 0;
    uvs_vport_ctx_t *vport_ctx = &tp_msg_ctx->vport_ctx;
    if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, msg->upi, &msg->peer_eid,
                                              &vport_ctx->key, &eid_idx) < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key upi:%u eid " EID_FMT "\n", msg->upi, EID_ARGS(msg->peer_eid));
        return -1;
    }

    if (tpsa_lookup_vport_param(&vport_ctx->key, &table_ctx->vport_table,
                                &vport_ctx->param) < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key dev_name:%s, fe_idx:%u",
            vport_ctx->key.tpf_name, vport_ctx->key.fe_idx);
        return -1;
    }

    /* In peer site, eid, and jetty_id is opposite in msg */
    sip_table_entry_t sip_entry = {0};
    tpsa_sip_table_lookup(&table_ctx->tpf_dev_table, vport_ctx->key.tpf_name,
        vport_ctx->param.sip_idx, &sip_entry);
    tp_msg_ctx->src.eid = msg->peer_eid;
    tp_msg_ctx->src.ip = sip_entry.addr;
    tp_msg_ctx->src.jetty_id = msg->peer_jetty;

    /* If the dip table of the third-party node has been refreshed,
        the IP information of the migration source cannot be correctly obtained from the dip table */
    if (msg->live_migrate == true) {
        tp_msg_ctx->dst.ip = msg->dip;
        tp_msg_ctx->peer.uvs_ip = msg->src_uvs_ip;
    } else {
        tpsa_lookup_dip_table(&table_ctx->dip_table, msg->local_eid,
                              msg->upi, &tp_msg_ctx->peer.uvs_ip, &tp_msg_ctx->dst.ip);
    }
    tp_msg_ctx->dst.eid = msg->local_eid;
    tp_msg_ctx->dst.jetty_id = msg->local_jetty;
    tp_msg_ctx->ta_data = *ta_data;
    tpsa_swap_jetty(&tp_msg_ctx->ta_data.jetty_id, &tp_msg_ctx->ta_data.tjetty_id);
    tp_msg_ctx->trans_mode = msg->trans_mode;

    return 0;
}

int tpsa_send_create_fail_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t* msg, uvs_net_addr_t *peer_uvs_ip)
{
    tpsa_sock_msg_t *resp = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (resp == NULL) {
        return -1;
    }

    resp->msg_type = TPSA_CREATE_FAIL_RESP;

    resp->trans_mode = msg->trans_mode;
    resp->local_eid = msg->local_eid;
    resp->peer_eid = msg->peer_eid;
    resp->local_jetty = msg->local_jetty;
    resp->peer_jetty = msg->peer_jetty;
    resp->vtpn = msg->vtpn;
    resp->upi = msg->upi;
    resp->live_migrate = msg->live_migrate;

    tpsa_create_fail_resp_t *fail_resp = &resp->content.fail_resp;
    tpsa_create_req_t *req = &msg->content.req;

    fail_resp->msg_id = req->msg_id;
    fail_resp->nlmsg_seq = req->nlmsg_seq;
    fail_resp->src_function_id = req->src_function_id;
    (void)memcpy(fail_resp->dev_name, req->dev_name, UVS_MAX_DEV_NAME);

    /* for alpha */
    fail_resp->ta_data = req->ta_data;
    fail_resp->udrv_in_len = req->udrv_in_len;
    fail_resp->ext_len = req->ext_len;
    (void)memcpy(fail_resp->udrv_ext, req->udrv_ext, sizeof(req->udrv_ext));

    if (tpsa_sock_send_msg(ctx->sock_ctx, resp, sizeof(tpsa_sock_msg_t), *peer_uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp resp in worker\n");
        free(resp);
        return -1;
    }
    free(resp);
    return 0;
}

static int uvs_get_final_share_mode(bool *final_share_mode, tpsa_sock_msg_t *msg,
    uvs_tp_msg_ctx_t tp_msg_ctx)
{
    tpsa_create_req_t *req = &msg->content.req;
    bool local_share_mode = req->share_mode;
    bool target_share_mode = true;

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && msg->trans_mode == TPSA_TP_RM) {
        if (req->pattern != tp_msg_ctx.vport_ctx.param.pattern) {
            TPSA_LOG_ERR("local side pattern mode is %u and target side is %u",
                req->pattern, tp_msg_ctx.vport_ctx.param.pattern);
            return -1;
        }

        if (tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.share_mode == 0) {
            TPSA_LOG_INFO("Detect non-share_mode on target side, share_mode = %u and pattern = %u",
                tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.share_mode,
                tp_msg_ctx.vport_ctx.param.pattern);
            target_share_mode = false;
        }

        /* negotiation for share_mode */
        if (!local_share_mode && target_share_mode) {
            /* todo: need to back to the local side and retry using share_mode */
            TPSA_LOG_ERR("Detect local side is non_share_mode and target side is share_mode");
            return -1;
        } else if (local_share_mode && !target_share_mode) {
            /* if local is using share_mode and target is using non-share_mode, using share_mode */
            TPSA_LOG_WARN("Detect local side is share_mode and target side is non-share_mode");
            target_share_mode = true;
        }
        *final_share_mode = target_share_mode;
    }

    return 0;
}

static tpsa_tpg_status_t tpsa_reuse_target_tpg_with_share_mode(uvs_ctx_t *ctx,
    rm_vtp_table_entry_t *share_mode_entry, uvs_tp_msg_ctx_t tp_msg_ctx, tpsa_tpg_info_t *tpg_info)
{
    rm_vtp_table_key_t vtp_key = {0};

    vtp_key.src_eid = tp_msg_ctx.src.eid;
    vtp_key.dst_eid = tp_msg_ctx.dst.eid;

    share_mode_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
        &tp_msg_ctx.vport_ctx.key, &vtp_key);
    if (share_mode_entry != NULL && share_mode_entry->tpg_param != NULL) {
        (void)memcpy(tpg_info,
            share_mode_entry->tpg_param, sizeof(tpsa_tpg_info_t));
        return TPSA_TPG_LOOKUP_EXIST;
    }
    return TPSA_TPG_LOOKUP_NULL;
}

static int uvs_create_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_cc_param_t resp_param = {0};
    tpsa_create_req_t *req = &msg->content.req;
    tpsa_tpg_table_param_t tparam = {0};
    tpsa_tpg_status_t status = (tpsa_tpg_status_t)0;
    sip_table_entry_t sip_entry = {0};
    tpsa_tpg_info_t tpg_info = {0};
    int32_t res = 0;
    uvs_mtu_t mtu;
    bool is_target;
    struct tpsa_init_sock_resp_param init_resp_param;
    tpsa_sock_msg_t *resp;
    bool final_share_mode = true;
    rm_vtp_table_entry_t *share_mode_entry = NULL;

    TPSA_LOG_INFO("src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    /* In live migration scenarios, skip this judgment. */
    if (msg->live_migrate == false && req->ta_data.trans_type == TPSA_TRANSPORT_UB && msg->trans_mode == TPSA_TP_RC &&
        uvs_rc_check_ljetty(ctx->table_ctx, msg->peer_jetty, &msg->peer_eid, msg->local_jetty, &msg->local_eid)) {
        TPSA_LOG_ERR("Fail to rc_check_sjetty");
        return -1;
    }

    uvs_tp_msg_ctx_t tp_msg_ctx = { 0 };
    if (uvs_get_tp_msg_ctx_peer_site(msg, ctx->table_ctx, &req->ta_data,  &tp_msg_ctx) < 0) {
        TPSA_LOG_ERR("Fail to get msg ctx");
        return -1;
    }

    if (uvs_is_fe_in_cleaning_proc(&ctx->table_ctx->fe_table, &tp_msg_ctx.vport_ctx.key) ||
        vport_in_cleaning_proc(&ctx->table_ctx->vport_table, &tp_msg_ctx.vport_ctx.key)) {
        TPSA_LOG_WARN("fe dev_name:%s, fe_idx:%u in cleaning proc", tp_msg_ctx.vport_ctx.key.tpf_name,
            tp_msg_ctx.vport_ctx.key.fe_idx);
        return -1;
    }

    if (uvs_get_final_share_mode(&final_share_mode, msg, tp_msg_ctx) != 0) {
        TPSA_LOG_ERR("Failed to negotiate for final share mode");
        return -1;
    }
    TPSA_LOG_INFO("finally, share mode is %u", (uint32_t)final_share_mode);

    vport_param_t *vport_param = &tp_msg_ctx.vport_ctx.param;
    tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx.vport_ctx.key.tpf_name,
        vport_param->sip_idx, &sip_entry);

    /* check if fe is in stop process create vtp req status */
    if (uvs_is_fe_in_stop_proc(&ctx->table_ctx->fe_table, &tp_msg_ctx.vport_ctx.key)) {
        msg->dip = sip_entry.addr;
        msg->src_uvs_ip = ctx->tpsa_attr.server_ip;
        res = uvs_lm_start_transfer_create_msg(ctx, msg, &tp_msg_ctx.vport_ctx.key);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to transfer tpsa create req");
        }
        return res;
    }

    tpsa_init_tpg_cmd_param_t param = {0};
    param.fe_idx = tp_msg_ctx.vport_ctx.key.fe_idx;
    param.tp_cfg = vport_param->tp_cfg;
    param.tp_cfg.port = sip_entry.port_id[0];
    param.sip = sip_entry.addr;
    param.dip = tp_msg_ctx.dst.ip;
    param.sip_idx = vport_param->sip_idx;
    param.mtu = uvs_get_mtu(ctx, &tp_msg_ctx);

    /* TODO: table check */
    /* IOCTL to create target tpg */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to malloc config mem");
        return -ENOMEM;
    }

    tpsa_ioctl_cmd_get_dev_info(cfg, tp_msg_ctx.vport_ctx.key.tpf_name, &sip_entry.addr,
        TPSA_TRANSPORT_UB);
    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to get dev info in target");
        res = -1;
        goto free_cfg;
    }
    TPSA_LOG_INFO("Finish IOCTL to get dev info in target.\n");

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && !cfg->cmd.get_dev_info.out.port_is_active) {
        TPSA_LOG_ERR("Failed to set up connection due to port unactive on target side with tpf_dev %s\n",
            cfg->cmd.get_dev_info.in.target_pf_name);
        res = -1;
        goto free_cfg;
    }

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        tpsa_query_cc_algo(cfg->cmd.get_dev_info.out.target_tpf_name, &ctx->table_ctx->tpf_dev_table, &param.tp_cfg,
                           &param.cc_array_cnt, param.cc_result_array);
    }

    tpsa_ioctl_cmd_create_target_tpg(cfg, msg, &param);

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && final_share_mode) {
        status = tpsa_reuse_target_tpg(ctx, &sip_entry.addr, &tp_msg_ctx.dst.ip, msg, &tpg_info);
    } else if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && !final_share_mode) {
        status = tpsa_reuse_target_tpg_with_share_mode(ctx, share_mode_entry, tp_msg_ctx,
            &tpg_info);
    }
    if ((final_share_mode && status <= TPSA_TPG_LOOKUP_NULL) ||
        (!final_share_mode && share_mode_entry == NULL)) {
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to create target tpg in worker");
            res = -1;
            goto free_cfg;
        }
        TPSA_LOG_INFO("--------------------create tpgn: %d, tpn: %d in target.\n",
            cfg->cmd.create_target_tpg.out.tpgn, cfg->cmd.create_target_tpg.out.tpn[0]);
        tpg_info.tpgn = cfg->cmd.create_target_tpg.out.tpgn;
        tpg_info.tp_cnt = cfg->cmd.create_target_tpg.in.tpg_cfg.tp_cnt;
        uvs_cal_multi_tp_statistic(tp_msg_ctx.vport_ctx.key.tpf_name,
            msg->trans_mode, UVS_TP_OPENING_STATE, tpg_info.tp_cnt);
        (void)memcpy(tpg_info.tpn, cfg->cmd.create_target_tpg.out.tpn,
            TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

        if (uvs_add_tpg_state_entry(ctx->table_ctx, &tp_msg_ctx, &tpg_info) != 0) {
            res = -1;
            goto destory_target_tpg;
        }
        // add tpg table
        tparam.tpgn = cfg->cmd.create_target_tpg.out.tpgn;
        tparam.status = TPSA_TPG_LOOKUP_IN_PROGRESS;
        tparam.use_cnt = 1;
        tparam.ljetty_id = msg->peer_jetty;
        tparam.leid =  msg->peer_eid;
        tparam.dip = tp_msg_ctx.dst.ip;
        tparam.live_migrate = msg->live_migrate;
        tparam.tp_cnt = cfg->cmd.create_target_tpg.in.tpg_cfg.tp_cnt;
        (void)memcpy(tparam.tpn, cfg->cmd.create_target_tpg.out.tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
        if (final_share_mode && uvs_add_tpg_entry(req->ta_data.trans_type, msg, &tparam, ctx->table_ctx) != 0) {
            goto destory_target_tpg;
        }
    }

    resp_param.target_cc_cnt = param.cc_array_cnt;
    resp_param.target_cc_en = param.tp_cfg.tp_mod_flag.bs.cc_en;
    (void)memcpy(resp_param.cc_result_array, param.cc_result_array,
        sizeof(tpsa_tp_cc_entry_t) * param.cc_array_cnt);
    mtu = cfg->cmd.create_target_tpg.local_mtu;
    is_target = status <= TPSA_TPG_LOOKUP_NULL ? true : false;

    (void)memset(&init_resp_param, 0, sizeof(struct tpsa_init_sock_resp_param));
    init_resp_param.tpgn = tpg_info.tpgn;
    init_resp_param.tpn = tpg_info.tpn;
    init_resp_param.tpg_cfg = &cfg->cmd.create_target_tpg.in.tpg_cfg;
    init_resp_param.mtu = mtu;
    init_resp_param.resp_param = &resp_param;
    init_resp_param.is_target = is_target;
    init_resp_param.sip = sip_entry.addr;
    init_resp_param.src_uvs_ip = ctx->tpsa_attr.server_ip;
    init_resp_param.share_mode = final_share_mode;

    resp = tpsa_sock_init_create_resp(msg, &init_resp_param);
    if (resp == NULL) {
        TPSA_LOG_ERR("Failed to construct create vtp resp in worker\n");
        res = -1;
        goto remove_tpg_entry;
    }

    resp->content.resp.ext_len = cfg->cmd.create_target_tpg.udrv_ext.out_len;
    (void)memcpy(resp->content.resp.ext, (char *)cfg->cmd.create_target_tpg.udrv_ext.out_addr,
		TPSA_UDRV_DATA_LEN);

    if (tpsa_sock_send_msg(ctx->sock_ctx, resp, sizeof(tpsa_sock_msg_t), tp_msg_ctx.peer.uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp resp in worker\n");
        res = -1;
        goto remove_tpg_entry;
    }

    TPSA_LOG_INFO("Finish socket send resp in target.\n");
    tpsa_sock_init_destroy_resp(resp);

remove_tpg_entry:
    if (res != 0 && status <= TPSA_TPG_LOOKUP_NULL) {
        uvs_del_tpg_entry(req->ta_data.trans_type, msg, &tparam, ctx->table_ctx);
    }
destory_target_tpg:
    if (res != 0 && status <= TPSA_TPG_LOOKUP_NULL) {
        tpsa_ioctl_cmd_destroy_tpg(cfg, &sip_entry.addr, tpg_info.tpgn,
            &cfg->cmd.create_target_tpg.ta_data);
        (void)tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg);
        (void)uvs_rmv_tpg_state_entry(ctx->table_ctx, tpg_info.tpgn, &sip_entry.addr);
    }
    uvs_cal_multi_tp_statistic(msg->content.req.dev_name, msg->trans_mode,
        UVS_TP_OPENING_FAIL_STATE, msg->content.req.tpg_cfg.tp_cnt);
free_cfg:
    free(cfg);
    return res;
}

int uvs_handle_create_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    int ret = 0;
    ret = uvs_create_vtp_req(ctx, msg);
    if (ret != 0) {
        uvs_cal_multi_tp_statistic(msg->content.req.dev_name, msg->trans_mode,
            UVS_TP_OPENING_FAIL_STATE, msg->content.req.tpg_cfg.tp_cnt);
        TPSA_LOG_INFO("create vtp req failed src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u",
            EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);
        (void)tpsa_send_create_fail_resp(ctx, msg, &msg->src_uvs_ip);
    }

    return ret;
}

static int tpsa_refresh_rm_wait_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_vtp_table_param_t *vtp_table_data,
                                      uvs_ctx_t *ctx)
{
    rm_wait_table_entry_t *entry = (rm_wait_table_entry_t *)calloc(1, sizeof(rm_wait_table_entry_t));
    if (entry == NULL) {
        return -ENOMEM;
    }

    rm_wait_table_key_t key = {
        .dip = tpg_idx->dip,
    };

    uvs_nl_resp_info_t nl_resp = {0};

    while (rm_wait_table_lookup(&ctx->table_ctx->rm_wait_table, &key) != NULL) {
        if (rm_wait_table_pop(&ctx->table_ctx->rm_wait_table, &key, entry) < 0) {
            TPSA_LOG_ERR("Fail to pop rm entry when refresh rm wait table");
            free(entry);
            return -1;
        }

        if (uvs_create_vtp_reuse_tpg(ctx, &entry->cparam, &tpg_idx->sip, vtp_table_data, &nl_resp) < 0) {
            TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
            free(entry);
            return -1;
        }

        if (!entry->cparam.live_migrate && nl_resp.resp == true) {
            if (uvs_response_create_wait(vtp_table_data->vtpn, &entry->cparam, ctx->nl_ctx) < 0) {
                TPSA_LOG_ERR("Fail to response nl when pop wait table");
                free(entry);
                return -1;
            }
        }

        (void)memset(entry, 0, sizeof(rm_wait_table_entry_t));
    }

    free(entry);
    return 0;
}

static int tpsa_refresh_rc_wait_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_vtp_table_param_t *vtp_table_data,
                                      uvs_ctx_t *ctx)
{
    rc_wait_table_entry_t *entry = (rc_wait_table_entry_t *)calloc(1, sizeof(rc_wait_table_entry_t));
    if (entry == NULL) {
        return -ENOMEM;
    }

    rc_wait_table_key_t key = {
        .deid = tpg_idx->peer_eid,
        .djetty_id = tpg_idx->djetty_id,
    };

    uvs_nl_resp_info_t nl_resp = {0};

    while (rc_wait_table_lookup(&ctx->table_ctx->rc_wait_table, &key) != NULL) {
        if (rc_wait_table_pop(&ctx->table_ctx->rc_wait_table, &key, entry) < 0) {
            TPSA_LOG_ERR("Fail to pop rc entry when refresh rc wait table");
            free(entry);
            return -1;
        }

        if (uvs_create_vtp_reuse_tpg(ctx, &entry->cparam, &tpg_idx->sip, vtp_table_data, &nl_resp) < 0) {
            TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
            free(entry);
            return -1;
        }

        if (!entry->cparam.live_migrate && nl_resp.resp == true) {
            if (uvs_response_create_wait(vtp_table_data->vtpn, &entry->cparam, ctx->nl_ctx) < 0) {
                TPSA_LOG_ERR("Fail to response nl when pop wait table");
                free(entry);
                return -1;
            }
        }

        (void)memset(entry, 0, sizeof(rc_wait_table_entry_t));
    }

    free(entry);
    return 0;
}

int tpsa_refresh_wait_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_vtp_table_param_t *vtp_table_data,
                            uvs_ctx_t *ctx)
{
    if (tpg_idx == NULL) {
        TPSA_LOG_ERR("Null pointer of tpg idx. Return.");
        return -1;
    }

    if (tpg_idx->trans_mode == TPSA_TP_RM) {
        if (tpsa_refresh_rm_wait_table(tpg_idx, vtp_table_data, ctx) < 0) {
            TPSA_LOG_ERR("Fail to refresh wait table (RM)");
            return -1;
        }
    } else {
        if (tpsa_refresh_rc_wait_table(tpg_idx, vtp_table_data, ctx) < 0) {
            TPSA_LOG_ERR("Fail to refresh wait table (RC)");
            return -1;
        }
    }

    return 0;
}

int uvs_get_tp_msg_ctx_local_site(tpsa_sock_msg_t *msg, vport_key_t *vport_key, struct tpsa_ta_data *ta_data,
                                  tpsa_table_t *table_ctx, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tp_msg_ctx->trans_type = TPSA_TRANSPORT_UB;
    tp_msg_ctx->trans_mode = msg->trans_mode;
    tp_msg_ctx->upi = msg->upi;

    uvs_vport_ctx_t *vport_ctx = &tp_msg_ctx->vport_ctx;
    vport_ctx->key = *vport_key;
    if (tpsa_lookup_vport_param(&vport_ctx->key, &table_ctx->vport_table, &vport_ctx->param) < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key dev_name:%s, fe_idx:%u",
            vport_ctx->key.tpf_name, vport_ctx->key.fe_idx);
        return -1;
    }

    sip_table_entry_t sip_entry = {0};
    tpsa_sip_table_lookup(&table_ctx->tpf_dev_table, vport_ctx->key.tpf_name,
        vport_ctx->param.sip_idx, &sip_entry);
    tp_msg_ctx->src.eid = msg->local_eid;
    tp_msg_ctx->src.ip = sip_entry.addr;
    tp_msg_ctx->src.jetty_id = msg->local_jetty;

    if (msg->live_migrate) {
        tp_msg_ctx->dst.ip = msg->dip;
        tp_msg_ctx->peer.uvs_ip = msg->src_uvs_ip;
    } else {
        tpsa_lookup_dip_table(&table_ctx->dip_table, msg->peer_eid,
            msg->upi, &tp_msg_ctx->peer.uvs_ip, &tp_msg_ctx->dst.ip);
    }
    tp_msg_ctx->dst.eid = msg->peer_eid;
    tp_msg_ctx->dst.jetty_id = msg->peer_jetty;

    if (ta_data != NULL) {
        tp_msg_ctx->trans_type = ta_data->trans_type;
        tp_msg_ctx->ta_data = *ta_data;
    }

    return 0;
}


int uvs_create_vtp_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    int res = 0;
    TPSA_LOG_INFO("src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    tpsa_create_resp_t *resp = &msg->content.resp;
    tpsa_ioctl_cfg_t *cfg = NULL;
    tpsa_sock_msg_t *ack = NULL;
    vport_key_t vport_key = {0};

    vport_key.fe_idx = resp->src_function_id;
    memcpy(vport_key.tpf_name, resp->dev_name, UVS_MAX_DEV_NAME);

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    if (uvs_get_tp_msg_ctx_local_site(msg, &vport_key, &resp->ta_data, ctx->table_ctx, &tp_msg_ctx) < 0) {
        TPSA_LOG_ERR("Fail to get msg ctx");
        res = -1;
        goto resp_tp_opening_fail;
    }
    /* IOCTL to create vtp */
    cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        res = -ENOMEM;
        goto resp_tp_opening_fail;
    }

    tpsa_ioctl_cmd_modify_tpg(cfg, msg, &tp_msg_ctx.src.ip);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify tpg in worker");
        free(cfg);
        res = -1;
        goto resp_tp_opening_fail;
    }
    TPSA_LOG_INFO("Finish IOCTL to modify tpg in initiator.\n");

    uvs_cal_tpg_statistic(resp->dev_name);
    uvs_cal_multi_tp_statistic(resp->dev_name, msg->trans_mode, UVS_TP_SUCCESS_STATE, resp->tpg_cfg.tp_cnt);
    free(cfg);
    /* Construct ack packet */
    ack = tpsa_sock_init_create_ack(msg, &tp_msg_ctx.src.ip, &ctx->tpsa_attr);
    if (ack == NULL) {
        TPSA_LOG_ERR("Failed to construct create vtp ack in worker\n");
        uvs_cal_multi_tp_statistic(resp->dev_name,
            msg->trans_mode, UVS_TP_OPENING_FAIL_STATE, resp->tpg_cfg.tp_cnt);
        return -1;
    }
    if (tpsa_sock_send_msg(ctx->sock_ctx, ack, sizeof(tpsa_sock_msg_t), tp_msg_ctx.peer.uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp ack in worker\n");
        free(ack);
        uvs_cal_multi_tp_statistic(resp->dev_name,
            msg->trans_mode, UVS_TP_OPENING_FAIL_STATE, resp->tpg_cfg.tp_cnt);
        return -1;
    }

    free(ack);
    TPSA_LOG_INFO("Finish socket ack message in initiator.\n");

resp_tp_opening_fail:
    if (res < 0) {
        uvs_cal_multi_tp_statistic(resp->dev_name,
            msg->trans_mode, UVS_TP_OPENING_FAIL_STATE, resp->tpg_cfg.tp_cnt);
    }
    return res;
}

static void uvs_ack_init_tpg_param(tpsa_tpg_info_t *tpg_param, tpsa_sock_msg_t *msg)
{
    tpg_param->tp_cnt = msg->content.ack.tpg_cfg.tp_cnt;
    for (uint32_t i = 0; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        tpg_param->tpn[i] = msg->content.ack.tp_param.uniq[i].peer_tpn;
    }
    tpg_param->tpgn = msg->peer_tpgn;
}

static int uvs_update_target_vtp_tpg(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg,
    uint32_t location, tpsa_tpg_info_t *tpg_param)
{
    /* Start to update target vtp and tpg table */
    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        if ((msg->content.ack.share_mode) &&
            uvs_table_update(UINT32_MAX, msg->peer_tpgn, location, msg, ctx->table_ctx) < 0) {
            TPSA_LOG_ERR("Fail to update table when ack receive.");
            return -1;
        } else if (!msg->content.ack.share_mode &&
            tpsa_update_rm_vtp_table(msg, location, UINT32_MAX, msg->peer_tpgn,
            ctx->table_ctx, tpg_param) < 0) {
            TPSA_LOG_ERR("Fail to update rm vtp table");
            return -1;
        }
    }
    return 0;
}

int uvs_create_vtp_ack(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    uint32_t location = TPSA_TARGET;
    tpsa_ioctl_cfg_t *cfg = NULL;
    int res = 0;
    tpsa_tpg_table_index_t tpg_idx;
    tpsa_vtp_table_param_t vtp_table_data;
    tpsa_sock_msg_t *finish;
    tpsa_tpg_info_t tpg_param = {0};

    (void)memset(&tpg_idx,
        0, sizeof(tpsa_tpg_table_index_t));
    (void)memset(&vtp_table_data,
        0, sizeof(tpsa_vtp_table_param_t));
    uvs_tp_msg_ctx_t tp_msg_ctx = { 0 };
    tpsa_cmd_tpf_t tpf;
    if (uvs_get_tp_msg_ctx_peer_site(msg, ctx->table_ctx, &msg->content.ack.ta_data, &tp_msg_ctx) < 0) {
        TPSA_LOG_INFO("failed to get tp mst ctx");
        res = -1;
        goto peer_tp_opening_fail;
    }

    TPSA_LOG_INFO("src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    if ((msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB && msg->content.ack.is_target == true) ||
        msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_IB) {
        /* IOCTL to modify tp to RTS */
        cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            res = -ENOMEM;
            goto peer_tp_opening_fail;
        }

        tpf.trans_type = TPSA_TRANSPORT_UB;
        tpf.netaddr = tp_msg_ctx.src.ip;

        cfg->cmd_type = TPSA_CMD_MODIFY_TARGET_TPG;
        cfg->cmd.modify_target_tpg.in.tpf = tpf;
        cfg->cmd.modify_target_tpg.in.tpgn = msg->peer_tpgn;
        cfg->cmd.modify_target_tpg.ta_data = msg->content.ack.ta_data;

        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to modify peer tpg in worker");
            res = -1;
            goto free_cfg;
        }
        TPSA_LOG_INFO("Finish IOCTL to modify target tpg in target.\n");

        if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB) {
            tpsa_create_param_t cparam;
            cparam.trans_mode = tp_msg_ctx.trans_mode;
            cparam.local_eid = tp_msg_ctx.src.eid;
            cparam.peer_eid = tp_msg_ctx.dst.eid;
            cparam.local_jetty = tp_msg_ctx.src.jetty_id;
            cparam.peer_jetty = tp_msg_ctx.dst.jetty_id;
            cparam.fe_idx = tp_msg_ctx.vport_ctx.key.fe_idx;
            cparam.vtpn = UINT32_MAX;
            cparam.live_migrate = msg->live_migrate;
            cparam.location = TPSA_TARGET;
            if (uvs_map_target_vtp(ctx->ioctl_ctx->ubcore_fd, &cparam, msg->local_tpgn, &msg->dip) != 0) {
                TPSA_LOG_ERR("Fail to ioctl to modify peer tpg in worker");
                res = -1;
                goto free_cfg;
            }
            TPSA_LOG_INFO("Finish IOCTL to map target tpg in target.\n");
        }
    }

    uvs_ack_init_tpg_param(&tpg_param, msg);
    uvs_cal_tpg_statistic(msg->content.ack.dev_name);
    uvs_cal_multi_tp_statistic(msg->content.ack.dev_name, msg->content.ack.tpg_cfg.trans_mode,
        UVS_TP_SUCCESS_STATE, msg->content.ack.tpg_cfg.tp_cnt);

    if (uvs_update_target_vtp_tpg(ctx, msg, location, &tpg_param) != 0) {
        res = -1;
        goto free_cfg;
    }

    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_create_resp_to_lm_src(ctx, tp_msg_ctx.vport_ctx.key) != 0) {
        TPSA_LOG_ERR("uvs create resp to live_migrate source failed");
        res = -1;
        goto free_cfg;
    }

    /* Wakeup wait table when initiator finish create */
    tpg_idx.dip = tp_msg_ctx.dst.ip;
    tpg_idx.local_eid = msg->peer_eid;
    tpg_idx.peer_eid = msg->local_eid;
    tpg_idx.ljetty_id = msg->peer_jetty;
    tpg_idx.djetty_id = msg->local_jetty;
    tpg_idx.isLoopback = (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
                       uvs_is_loopback(msg->trans_mode, &tp_msg_ctx.src, &tp_msg_ctx.dst));
    tpg_idx.upi = msg->upi;
    tpg_idx.trans_mode = msg->trans_mode;
    tpg_idx.sig_loop = uvs_is_sig_loop(msg->trans_mode, &tp_msg_ctx.src, &tp_msg_ctx.dst);
    tpg_idx.sip = tp_msg_ctx.src.ip;
    tpg_idx.tp_cnt = msg->content.ack.tpg_cfg.tp_cnt;

    vtp_table_data.location = TPSA_INITIATOR;
    vtp_table_data.vtpn = UINT32_MAX;
    vtp_table_data.tpgn = msg->peer_tpgn;
    vtp_table_data.valid = true;
    vtp_table_data.local_eid = msg->peer_eid;
    vtp_table_data.local_jetty = msg->peer_jetty;
    vtp_table_data.eid_index = 0; /* Need to fix */
    vtp_table_data.upi = msg->upi;

    finish = tpsa_sock_init_create_finish(msg, &tp_msg_ctx.src.ip);
    if (finish == NULL) {
        res = -1;
        goto free_cfg;
    }
    if (tpsa_sock_send_msg(ctx->sock_ctx, finish, sizeof(tpsa_sock_msg_t), tp_msg_ctx.peer.uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp finish in worker\n");
        res = -1;
        goto free_sock_finish;
    }

    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
        tpsa_refresh_wait_table(&tpg_idx, &vtp_table_data, ctx) < 0) {
        TPSA_LOG_ERR("Failed to refresh wait table when resp\n");
        res = -1;
        goto free_sock_finish;
    }
    TPSA_LOG_INFO("Finish socket finish message in target.\n");

free_sock_finish:
    free(finish);

free_cfg:
    if (cfg != NULL) {
        free(cfg);
    }
peer_tp_opening_fail:
    if (res < 0) {
        uvs_cal_multi_tp_statistic(msg->content.ack.dev_name,
            msg->content.ack.tpg_cfg.trans_mode, UVS_TP_OPENING_FAIL_STATE, msg->content.ack.tpg_cfg.tp_cnt);
    }
    return res;
}

static void uvs_table_init_finish_vtp_idx(tpsa_sock_msg_t *msg, tpsa_tpg_table_index_t *tpg_idx,
    tpsa_vtp_table_index_t *vtp_idx)
{
    vtp_idx->local_eid = msg->local_eid;
    vtp_idx->peer_eid = msg->peer_eid;
    vtp_idx->peer_jetty = msg->peer_jetty;
    vtp_idx->local_jetty = msg->local_jetty;
    vtp_idx->location = TPSA_INITIATOR;
    vtp_idx->isLoopback = tpg_idx->isLoopback;
    vtp_idx->upi = tpg_idx->upi;
    vtp_idx->sig_loop = tpg_idx->sig_loop;
    vtp_idx->trans_mode = msg->trans_mode;
    vtp_idx->fe_key.fe_idx = msg->content.finish.src_function_id;
    (void)memcpy(vtp_idx->fe_key.tpf_name, msg->content.finish.dev_name, UVS_MAX_DEV_NAME);
    vtp_idx->share_mode = msg->content.finish.share_mode;
}

void uvs_unmap_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_create_param_t *cparam, uvs_net_addr_info_t *sip)
{
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return;
    }
    tpsa_ioctl_cmd_destroy_vtp(cfg, sip, (urma_transport_mode_t)cparam->trans_mode, cparam->local_eid,
        cparam->peer_eid, cparam->peer_jetty, cparam->location);
    (void)tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    free(cfg);
}

int uvs_create_vtp_finish(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_vtp_table_index_t vtp_idx = {0};
    uint32_t vtpn = UINT32_MAX;
    int ret = 0;
    tpsa_tpg_table_index_t tpg_idx;
    tpsa_vtp_table_param_t vtp_table_data;
    tpsa_create_finish_t *finish_msg = &msg->content.finish;
    vport_key_t vport_key = {0};

    vport_key.fe_idx = finish_msg->src_function_id;
    memcpy(vport_key.tpf_name, finish_msg->dev_name, UVS_MAX_DEV_NAME);

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    if (uvs_get_tp_msg_ctx_local_site(msg, &vport_key, &finish_msg->ta_data, ctx->table_ctx, &tp_msg_ctx) < 0) {
        TPSA_LOG_ERR("Fail to get msg ctx");
        return -1;
    }

    TPSA_LOG_INFO("src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    tpsa_create_param_t cparam;
    cparam.trans_mode = msg->trans_mode;
    cparam.local_eid = msg->local_eid;
    cparam.peer_eid = msg->peer_eid;
    cparam.local_jetty = msg->local_jetty;
    cparam.peer_jetty = msg->peer_jetty;
    cparam.fe_idx = msg->content.finish.src_function_id;
    cparam.vtpn = msg->vtpn;
    cparam.live_migrate = msg->live_migrate;
    cparam.location = TPSA_INITIATOR;

    tpsa_tpg_info_t tpg_param = {0};
    tpg_param.tp_cnt = msg->content.finish.tpg_cfg.tp_cnt;
    for (uint32_t i = 0; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
        tpg_param.tpn[i] = msg->content.finish.tp_param.uniq[i].peer_tpn;
    }
    tpg_param.tpgn = msg->local_tpgn;

    if (msg->content.finish.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        if (!msg->migrate_third) {
            ret = uvs_map_vtp(ctx->ioctl_ctx, &cparam, msg->local_tpgn, &tp_msg_ctx.src.ip, &vtpn);
            if (ret < 0) {
                return ret;
            }

            if (msg->content.finish.share_mode) {
                if (uvs_table_update(vtpn, msg->local_tpgn, TPSA_INITIATOR, msg, ctx->table_ctx) < 0) {
                    TPSA_LOG_ERR("Fail to update vtp and tpg table when finish receive");
                    ret = -1;
                    goto free_unmap_vtp;
                }
            } else {
                if (tpsa_update_rm_vtp_table(msg, TPSA_INITIATOR, vtpn, msg->local_tpgn,
                    ctx->table_ctx, &tpg_param) < 0) {
                    TPSA_LOG_ERR("Fail to update rm vtp table");
                    ret = -1;
                    goto free_unmap_vtp;
                }
            }
        }
        if (uvs_create_resp_to_lm_src(ctx, tp_msg_ctx.vport_ctx.key) < 0) {
            TPSA_LOG_ERR("uvs create resp to live_migrate source failed in uvs_create_vtp_finish");
            ret = -1;
            goto uvs_table_remove_node;
        }
    }

    /* Wakeup wait table when initiator finish create */
    tpg_idx.dip = tp_msg_ctx.dst.ip;
    tpg_idx.local_eid = msg->local_eid;
    tpg_idx.peer_eid = msg->peer_eid;
    tpg_idx.ljetty_id = msg->local_jetty;
    tpg_idx.djetty_id = msg->peer_jetty;
    tpg_idx.isLoopback = false;
    tpg_idx.upi = msg->upi;
    tpg_idx.trans_mode = msg->trans_mode;
    tpg_idx.sig_loop = uvs_is_sig_loop(msg->trans_mode, &tp_msg_ctx.src, &tp_msg_ctx.dst);
    tpg_idx.sip = tp_msg_ctx.src.ip;
    tpg_idx.tp_cnt = msg->content.ack.tpg_cfg.tp_cnt;

    vtp_table_data.location = TPSA_INITIATOR;
    vtp_table_data.vtpn = UINT32_MAX;
    vtp_table_data.tpgn = msg->local_tpgn;
    vtp_table_data.valid = true;
    vtp_table_data.local_eid = msg->local_eid;
    vtp_table_data.local_jetty = msg->local_jetty;
    vtp_table_data.eid_index = 0; /* Need to fix */
    vtp_table_data.upi = msg->upi;

    if (!msg->live_migrate) {
        ret = uvs_resp_nl_create_vtp(ctx->nl_ctx, msg, vtpn, TPSA_NL_RESP_SUCCESS);
        if (ret < 0) {
            TPSA_LOG_ERR("Fail to response vtpn when finish receive in worker");
            goto uvs_table_remove_node;
        }
    }

    if (msg->content.finish.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        ret = tpsa_refresh_wait_table(&tpg_idx, &vtp_table_data, ctx);
        if (ret < 0) {
            TPSA_LOG_ERR("Failed to refresh wait table when finish\n");
            goto uvs_table_remove_node;
        }
    }
    TPSA_LOG_INFO("Finish Create VTP, TP and PEER all change to RTS.\n");

uvs_table_remove_node:
    if (ret != 0 && msg->content.finish.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_table_init_finish_vtp_idx(msg, &tpg_idx, &vtp_idx);
        uvs_table_remove_vtp_tpg((int32_t *)&vtpn, (int32_t *)&msg->local_tpgn,
            &tpg_idx, &vtp_idx, ctx->table_ctx);
        uvs_cal_multi_tp_statistic(tp_msg_ctx.vport_ctx.key.tpf_name,
            tp_msg_ctx.trans_mode, UVS_TP_DESTROY_STATE, tpg_idx.tp_cnt);
    }
free_unmap_vtp:
    if (ret != 0 && msg->content.finish.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_unmap_vtp(ctx->ioctl_ctx, &cparam, &tp_msg_ctx.src.ip);
    }
    if (ret != 0) {
        (void)uvs_resp_nl_create_vtp(ctx->nl_ctx, msg, vtpn, TPSA_NL_RESP_FAIL);
    }
    return ret;
}

static int uvs_ioctl_destroy_tpg(tpsa_ioctl_cfg_t *cfg, uvs_tp_msg_ctx_t *tp_msg_ctx, int32_t tpgn,
    uvs_ctx_t *ctx, struct tpsa_ta_data *ta_data)
{
    tpsa_ioctl_cmd_destroy_tpg(cfg, &tp_msg_ctx->src.ip, (uint32_t)tpgn, ta_data);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy tpg");
        return -1;
    }
    TPSA_LOG_INFO("Finish IOCTL to destroy tpgn:%u \n", tpgn);
    return 0;
}

static void uvs_change_tpg_to_error(uvs_ctx_t *ctx, tpsa_ioctl_cfg_t *cfg, uvs_tp_msg_ctx_t *tp_msg_ctx, int32_t tpgn)
{
    tpsa_ioctl_cmd_change_tpg_to_error(cfg, &tp_msg_ctx->src.ip, (uint32_t)tpgn);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to change tpg %u to error, try to destroy tpg", tpgn);
        cfg->cmd.change_tpg_to_error.out.tp_error_cnt = 0;
    } else {
        TPSA_LOG_INFO("Finish IOCTL to change tpg %u to error when destroy vtp, tp_error_cnt:%d\n",
            tpgn, cfg->cmd.change_tpg_to_error.out.tp_error_cnt);
    }

    if (cfg->cmd.change_tpg_to_error.out.tp_error_cnt == 0) {
        (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
        if (uvs_ioctl_destroy_tpg(cfg, tp_msg_ctx, tpgn, ctx, &tp_msg_ctx->ta_data) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to destroy tpg %u to error in worker", tpgn);
            return;
        }
        TPSA_LOG_INFO("Finish IOCTL to destroy tpg %u when tp_error_cnt is 0", tpgn);
        (void)uvs_rmv_all_tp_state_entry(ctx->table_ctx, (uint32_t)tpgn, &tp_msg_ctx->src.ip);
        (void)uvs_rmv_tpg_state_entry(ctx->table_ctx, (uint32_t)tpgn, &tp_msg_ctx->src.ip);
        return;
    }
    tpg_state_table_key_t key = {.tpgn = (uint32_t)tpgn, .sip = tp_msg_ctx->src.ip};
    (void)uvs_update_tpg_state_flush_cnt(&ctx->table_ctx->tpg_state_table, &key,
                                         cfg->cmd.change_tpg_to_error.out.tp_error_cnt);
    return;
}

int uvs_destroy_vtp_and_tpg(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, int32_t vtpn, int32_t tpgn, uint32_t location)
{
  /* IOCTL to destroy vtp and tpg */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    if ((tp_msg_ctx->ta_data.trans_type == TPSA_TRANSPORT_UB && vtpn >= 0) ||
        (vtpn == TPSA_REMOVE_SERVER && location == TPSA_TARGET)) {
        tpsa_ioctl_cmd_destroy_vtp(cfg, &tp_msg_ctx->src.ip, (urma_transport_mode_t)tp_msg_ctx->trans_mode,
            tp_msg_ctx->src.eid, tp_msg_ctx->dst.eid, tp_msg_ctx->dst.jetty_id, location);
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to destroy vtp in worker");
        } else {
            TPSA_LOG_DEBUG("Finish IOCTL to destroy vtp when destroy vtp :%d\n", vtpn);
        }

        (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    }

    bool tp_fast_destroy = tpsa_get_tp_fast_destroy();
    if (tp_msg_ctx->ta_data.trans_type == TPSA_TRANSPORT_UB && tpgn >= 0 && !tp_fast_destroy) {
        uvs_change_tpg_to_error(ctx, cfg, tp_msg_ctx, tpgn);
        /* TODO: checkout cfg->cmd.destroy_tpg.out */
    } else if (tp_msg_ctx->ta_data.trans_type == TPSA_TRANSPORT_IB ||
            (tp_msg_ctx->ta_data.trans_type == TPSA_TRANSPORT_UB && tpgn >= 0 && tp_fast_destroy)) {
        if (uvs_ioctl_destroy_tpg(cfg, tp_msg_ctx, tpgn, ctx, &tp_msg_ctx->ta_data) != 0) {
            free(cfg);
            return -1;
        }
        (void)uvs_rmv_tpg_state_entry(ctx->table_ctx, (uint32_t)tpgn, &tp_msg_ctx->src.ip);
    }
    free(cfg);

    return 0;
}

int tpsa_sock_send_destroy_req(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
                               uvs_direction_t direction, bool live_migrate,
                               tpsa_resp_id_t *resp_id)
{
    int ret = 0;
    tpsa_sock_msg_t *dmsg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (dmsg == NULL) {
        return -1;
    }

    dmsg->msg_type = TPSA_DESTROY_REQ;
    dmsg->local_eid = tp_msg_ctx->src.eid;
    dmsg->peer_eid = tp_msg_ctx->dst.eid;
    dmsg->local_jetty = tp_msg_ctx->src.jetty_id;
    dmsg->peer_jetty = tp_msg_ctx->dst.jetty_id;
    dmsg->trans_mode = tp_msg_ctx->trans_mode;
    dmsg->peer_tpgn = 0;
    dmsg->upi = tp_msg_ctx->upi;
    dmsg->live_migrate = live_migrate;
    if (live_migrate) {
        dmsg->dip = tp_msg_ctx->src.ip;
        dmsg->src_uvs_ip = ctx->tpsa_attr.server_ip;
    }
    dmsg->content.dreq.direction = direction;
    if (resp_id != NULL) {
        dmsg->content.dreq.resp_id = *resp_id;
    }
    dmsg->content.dreq.ta_data = tp_msg_ctx->ta_data;
    dmsg->content.dreq.ta_data.is_target = true;

    ret = tpsa_sock_send_msg(ctx->sock_ctx, dmsg, sizeof(tpsa_sock_msg_t), tp_msg_ctx->peer.uvs_ip);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to send destroy vtp req in worker\n");
    } else {
        TPSA_LOG_INFO("Finish socket destroy message in initiator\n");
    }

    free(dmsg);
    return ret;
}

static void uvs_table_init_destory_vtp_idx(uvs_tp_msg_ctx_t *tp_msg_ctx, uint32_t location,
                                           tpsa_tpg_table_index_t *tpg_idx, tpsa_vtp_table_index_t *vtp_idx)
{
    bool is_loopback = false;
    bool is_sigloop = false;

    // target side has no loopback vtp
    if (location == TPSA_INITIATOR) {
        is_loopback = uvs_is_loopback(tp_msg_ctx->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
        is_sigloop = uvs_is_sig_loop(tp_msg_ctx->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
    }

    tpg_idx->dip = tp_msg_ctx->dst.ip;
    tpg_idx->local_eid = tp_msg_ctx->src.eid;
    tpg_idx->peer_eid = tp_msg_ctx->dst.eid;
    tpg_idx->ljetty_id = tp_msg_ctx->src.jetty_id;
    tpg_idx->djetty_id = tp_msg_ctx->dst.jetty_id;
    tpg_idx->upi = tp_msg_ctx->upi;
    tpg_idx->isLoopback = is_loopback;
    tpg_idx->trans_mode = tp_msg_ctx->trans_mode;
    tpg_idx->sig_loop = is_sigloop;
    tpg_idx->sip = tp_msg_ctx->src.ip;
    tpg_idx->tp_cnt = tp_msg_ctx->vport_ctx.param.tp_cnt;

    vtp_idx->local_eid = tp_msg_ctx->src.eid;
    vtp_idx->peer_eid = tp_msg_ctx->dst.eid;
    vtp_idx->peer_jetty = tp_msg_ctx->dst.jetty_id;
    vtp_idx->local_jetty = tp_msg_ctx->src.jetty_id;
    vtp_idx->location = location,
    vtp_idx->isLoopback = tpg_idx->isLoopback,
    vtp_idx->upi = tpg_idx->upi,
    vtp_idx->sig_loop = tpg_idx->sig_loop,
    vtp_idx->trans_mode = tp_msg_ctx->trans_mode;
    vtp_idx->fe_key = tp_msg_ctx->vport_ctx.key;
    vtp_idx->share_mode = true; /* share mode is on by default */
}

int uvs_destroy_rm_rc_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, uint32_t location, int32_t *vtpn, int32_t *tpgn)
{
    int ret = 0;
    tpsa_vtp_table_index_t vtp_idx;
    tpsa_tpg_table_index_t tpg_idx;

    memset(&vtp_idx, 0, sizeof(vtp_idx));
    memset(&tpg_idx, 0, sizeof(tpg_idx));

    /* destroy vtp and tpg table */
    if (tp_msg_ctx->trans_type == TPSA_TRANSPORT_UB) {
        uvs_table_init_destory_vtp_idx(tp_msg_ctx, location, &tpg_idx, &vtp_idx);
        TPSA_LOG_INFO("location is %u when remove vtp and tpg\n", (uint32_t)location);
        uvs_table_remove_vtp_tpg(vtpn, tpgn, &tpg_idx, &vtp_idx, ctx->table_ctx);
        if ((*vtpn == TPSA_REMOVE_INVALID) || (*tpgn == TPSA_REMOVE_INVALID)) {
            TPSA_LOG_ERR("faile to destroy, vtpn:%d, tpgn:%d location: %d \n", *vtpn, *tpgn, location);
        }

        if (*vtpn == TPSA_REMOVE_SERVER && location == TPSA_TARGET) {
            TPSA_LOG_INFO("Found vtpn when destroy TARGET vtp. Remove it from table (No IOCTL)\n");
        }
        TPSA_LOG_INFO("now vtpn: %d, tpgn: %d\n", *vtpn, *tpgn);
    }

    uvs_cal_multi_tp_statistic(tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->trans_mode, UVS_TP_CLOSING_STATE, tpg_idx.tp_cnt);
    /* IOCTL to destroy vtp and tpg */
    ret = uvs_destroy_vtp_and_tpg(ctx, tp_msg_ctx, *vtpn, *tpgn, location);
    if (ret != 0) {
        TPSA_LOG_ERR("destroy vtp or tpg failed on the %d side. ret :%d\n", location, ret);
        uvs_cal_multi_tp_statistic(tp_msg_ctx->vport_ctx.key.tpf_name,
            tp_msg_ctx->trans_mode, UVS_TP_CLOSING_FAIL_STATE, tpg_idx.tp_cnt);
        return ret;
    }
    uvs_cal_multi_tp_statistic(tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->trans_mode, UVS_TP_DESTROY_STATE, tpg_idx.tp_cnt);

    return 0;
}

int uvs_destroy_initial_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_resp_id_t *nl_resp_id)
{
    int ret = 0;
    int32_t vtpn = -1;
    int32_t tpgn = -1;
    bool is_loopback = false;

   /* um no need to negotiate */
    if (tp_msg_ctx->trans_mode == TPSA_TP_UM) {
        return uvs_destroy_um_vtp(ctx, tp_msg_ctx);
    }

    if (tp_msg_ctx->trans_type == TPSA_TRANSPORT_UB) {
        is_loopback = uvs_is_loopback(tp_msg_ctx->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
    }

    ret = uvs_destroy_rm_rc_vtp(ctx, tp_msg_ctx, TPSA_INITIATOR, &vtpn, &tpgn);
    if (ret != 0) {
        return ret;
    }

    /* Send socket msg to notify server to destroy vtp */
    if (!is_loopback) {
        ret = tpsa_sock_send_destroy_req(ctx, tp_msg_ctx, TPSA_FROM_CLIENT_TO_SERVER, false, nl_resp_id);
        if (ret != 0) {
            TPSA_LOG_ERR("Failed to send socket msg to destroy vtp\n");
        }
        return ret;
    }

    TPSA_LOG_INFO("Success to destory initial vtp\n");
    return 0;
}

static inline void uvs_init_resp_id(tpsa_nl_msg_t *msg, tpsa_resp_id_t *msg_id)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;

    msg_id->is_need_resp = true;
    msg_id->nlmsg_seq = msg->nlmsg_seq;
    msg_id->msg_id = nlmsg->req.msg_id;
    msg_id->src_fe_idx = nlmsg->src_fe_idx;
}

static bool uvs_is_need_fast_resp(uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    if (tp_msg_ctx->trans_mode == TPSA_TP_UM) {
        return true;
    }
    if (tp_msg_ctx->trans_type == TPSA_TRANSPORT_UB) {
        return uvs_is_loopback(tp_msg_ctx->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
    }

    return false;
}

int uvs_destroy_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->req.data;
    int32_t res = -1;

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    tpsa_resp_id_t nl_resp_id;

    uvs_init_resp_id(msg, &nl_resp_id);
    res = uvs_get_tp_msg_ctx(ctx, nlreq, nlmsg->src_fe_idx, &tp_msg_ctx);
    if (res < 0) {
        TPSA_LOG_ERR("Fail to get msg ctx");
        return -1;
    }
    TPSA_LOG_INFO("destroy vtp seid " EID_FMT " sjetty: %u, sip: " EID_FMT ", deid " EID_FMT ", "
                  "djetty: %u, dip: " EID_FMT "\n",
                  EID_ARGS(nlreq->local_eid), nlreq->local_jetty, EID_ARGS(tp_msg_ctx.src.ip.net_addr),
                  EID_ARGS(nlreq->peer_eid), nlreq->peer_jetty, EID_ARGS(tp_msg_ctx.dst.ip.net_addr));

    if (uvs_is_fe_in_stop_proc(&ctx->table_ctx->fe_table, &tp_msg_ctx.vport_ctx.key)) {
        return uvs_response_destroy_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_IN_PROGRESS);
    }

    TPSA_LOG_INFO("destroy vtp on dev:%s, fe_idx %hu\n",
        tp_msg_ctx.vport_ctx.key.tpf_name, tp_msg_ctx.vport_ctx.key.fe_idx);

    /* clan domain no need to negotiate */
    if (uvs_is_clan_domain(ctx, msg, &tp_msg_ctx)) {
        TPSA_LOG_INFO("destroy vtp in clan domain");
        return uvs_destroy_clan_vtp(ctx, msg, &tp_msg_ctx);
    }

    res = uvs_destroy_initial_vtp(ctx, &tp_msg_ctx, &nl_resp_id);
    if (uvs_is_need_fast_resp(&tp_msg_ctx) == true || res != 0) {
        /* Netlink to resp destroy status to ubcore */
        tpsa_nl_resp_status_t resp_status = (res == 0) ? TPSA_NL_RESP_SUCCESS : TPSA_NL_RESP_FAIL;
        if (uvs_response_destroy_fast(msg, ctx->nl_ctx, resp_status) < 0) {
            TPSA_LOG_ERR("Fail to NETLINK <success> to ubcore when destroy vtp\n");
            return -1;
        }
        TPSA_LOG_INFO("Finish NETLINK <success> to ubcore when destroy vtp, ret:%d\n", res);
    }
    return 0;
}

/* When the status of the node is STATE_MIGRATING, directly trigger the delete operation */
int uvs_lm_destroy_vtp_in_migrating(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int32_t tpgn = -1;
    int32_t vtpn = -1;
    uint32_t location = TPSA_INITIATOR;
    tpsa_tpg_info_t find_tpg_info;
    int ret;

    tpsa_tpg_table_index_t tpg_idx;
    tpg_idx.dip = tp_msg_ctx->dst.ip;
    tpg_idx.local_eid = tp_msg_ctx->src.eid;
    tpg_idx.peer_eid = tp_msg_ctx->dst.eid;
    tpg_idx.ljetty_id = tp_msg_ctx->src.jetty_id;
    tpg_idx.djetty_id = tp_msg_ctx->dst.jetty_id;
    tpg_idx.sip = tp_msg_ctx->src.ip;
    tpg_idx.tp_cnt = tp_msg_ctx->vport_ctx.param.tp_cnt;

    if (lm_vtp_entry->trans_mode == TPSA_TP_RM) {
        location = lm_vtp_entry->content.rm_entry->location;
        rm_tpg_table_key_t key = {
            .dip = tp_msg_ctx->dst.ip,
        };
        tpg_idx.trans_mode = TPSA_TP_RM;
        ret = tpsa_remove_rm_tpg_table(&ctx->table_ctx->rm_tpg_table, &key, &find_tpg_info);
        if (ret < 0) {
            TPSA_LOG_ERR("Failed to remove rm tpg table when destroy vtp, ret:%d\n", ret);
        }
        if (ret == 0 && !tpsa_get_tp_fast_destroy()) {
            destroy_tpg_error_process(&tpg_idx, ctx->table_ctx, &find_tpg_info, TPG_STATE_DEL);
        }
    } else {
        location = lm_vtp_entry->content.rc_entry->location;
        rc_vtp_table_entry_t *rc_entry = lm_vtp_entry->content.rc_entry;
        rc_tpg_table_key_t rc_key = {
            .deid = tp_msg_ctx->dst.eid,
            .djetty_id = tp_msg_ctx->dst.jetty_id,
        };
        tpg_idx.trans_mode = TPSA_TP_RC;
        rc_tpg_table_entry_t *tpg_entry = rc_tpg_table_lookup(&ctx->table_ctx->rc_tpg_table, &rc_key);
        if (tpg_entry == NULL) {
            return -1;
        }
        tpg_entry->use_cnt--;
        tpgn = (tpg_entry->use_cnt > 0) ? TPSA_REMOVE_DUPLICATE : (int32_t)rc_entry->vice_tpgn;
        if (tpgn != TPSA_REMOVE_DUPLICATE && !tpsa_get_tp_fast_destroy()) {
            find_tpg_info.tpgn = tpg_entry->vice_tpgn;
            find_tpg_info.tp_cnt = tpg_entry->tp_cnt;
            (void)memcpy(find_tpg_info.tpn, tpg_entry->vice_tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
            destroy_tpg_error_process(&tpg_idx, ctx->table_ctx, &find_tpg_info, TPG_STATE_DEL);
        }
    }

    /* For third-party nodes in lm scenes, vtp_entry is reused and cannot be deleted. */
    if (uvs_destroy_vtp_and_tpg(ctx, tp_msg_ctx, vtpn, tpgn, location) < 0) {
        TPSA_LOG_ERR("destroy vtp or tpg failed when the status of vtp entry is STATE_MIGRATING.\n");
        return -1;
    }

    return 0;
}

/* When the status of the node is STATE_READY, performing switch first, then delete. */
int uvs_lm_destroy_vtp_in_ready(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret;

    /* First perform the switch and switch to the vice_tpg */
    ret = uvs_lm_refresh_tpg(ctx, vtp_cfg, vport_key, lm_vtp_entry, tp_msg_ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("Switch to vice tpg failed.\n");
        return ret;
    }

    /* Second, execute the action of deleting resources */
    ret = uvs_lm_destroy_vtp_in_migrating(ctx, vtp_cfg, vport_key, lm_vtp_entry, tp_msg_ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("Destroy vtp and tpg failed.\n");
        return ret;
    }

    return ret;
}

int uvs_hanlde_create_fail_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    int ret = 0;
    int32_t vtpn = -1;
    int32_t tpgn = -1;

    TPSA_LOG_INFO("hanlde create faild, src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    vport_key_t vport_key = {0};
    tpsa_create_fail_resp_t *resp = &msg->content.fail_resp;

    vport_key.fe_idx = resp->src_function_id;
    (void)memcpy(vport_key.tpf_name, resp->dev_name, UVS_MAX_DEV_NAME);

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    if (uvs_get_tp_msg_ctx_local_site(msg, &vport_key, &resp->ta_data, ctx->table_ctx, &tp_msg_ctx) < 0) {
        TPSA_LOG_ERR("Fail to get msg ctx");
        return -1;
    }

    ret = uvs_destroy_rm_rc_vtp(ctx, &tp_msg_ctx, TPSA_INITIATOR, &vtpn, &tpgn);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to get destory rm rc vtp");
    }

    if (msg->live_migrate) {
        return ret;
    }

    ret = uvs_resp_nl_create_vtp(ctx->nl_ctx, msg, UINT32_MAX, TPSA_NL_RESP_FAIL);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to resp nl msg");
    }

    return ret;
}

int uvs_handle_destroy_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    int32_t tpgn = -1;
    int32_t vtpn = -1;
    uint32_t location = TPSA_TARGET;
    TPSA_LOG_INFO("destroy vtp req on target side, src eid " EID_FMT " sjetty: %u, dst eid " EID_FMT ", djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    if (uvs_get_tp_msg_ctx_peer_site(msg, ctx->table_ctx, &msg->content.dreq.ta_data, &tp_msg_ctx) < 0) {
        return -1;
    }

    TPSA_LOG_INFO("destroy vtp ctx, dev_name:%s, fe_idx %hu, sip: " EID_FMT " dip: " EID_FMT " \n",
                  tp_msg_ctx.vport_ctx.key.tpf_name, tp_msg_ctx.vport_ctx.key.fe_idx,
                  EID_ARGS(tp_msg_ctx.src.ip.net_addr), EID_ARGS(tp_msg_ctx.dst.ip.net_addr));

    if (msg->live_migrate == true) {
        /* In lm scenes, destroy target vtp */
        return uvs_destroy_target_vtp_for_lm(ctx, &tp_msg_ctx);
    }

    if (msg->content.dreq.direction == TPSA_FROM_SERVER_TO_CLIENT) {
        location = TPSA_INITIATOR;
    }

    if (uvs_destroy_rm_rc_vtp(ctx, &tp_msg_ctx, location, &vtpn, &tpgn) != 0) {
        TPSA_LOG_ERR("destroy vtp or tpg faied on the target side.\n");
        return -1;
    }

    if (msg->content.dreq.resp_id.is_need_resp == false) {
        TPSA_LOG_INFO("Destroy vtp Success from target side\n");
        return 0;
    }

    tpsa_sock_msg_t *finish = tpsa_sock_init_destroy_finish(msg, &tp_msg_ctx.src.ip);
    if (finish == NULL) {
        free(finish);
        return -1;
    }
    if (tpsa_sock_send_msg(ctx->sock_ctx, finish, sizeof(tpsa_sock_msg_t), tp_msg_ctx.peer.uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp finish in worker\n");
        free(finish);
        return -1;
    }
    free(finish);
    TPSA_LOG_INFO("Destroy vtp Success from target side\n");

    return 0;
}

int uvs_destory_vtp_finish(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    int ret = -1;

    TPSA_LOG_INFO("src eid " EID_FMT " sjetty: %u dst eid " EID_FMT " djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    /* Netlink to notify destroy status to ubcore */
    ret = uvs_response_destroy(msg->vtpn, msg, ctx->nl_ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to response vtpn when finish receive in worker");
        return -1;
    }
    TPSA_LOG_INFO("Finish NETLINK <success> to ubcore when destroy vtp\n");

    return 0;
}