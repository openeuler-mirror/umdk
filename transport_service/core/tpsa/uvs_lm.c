/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs live migration implementation file
 * Author: LI Yuxing
 * Create: 2023-8-16
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

#include "uvs_tp_destroy.h"
#include "uvs_private_api.h"
#include "uvs_lm.h"

void uvs_lm_set_dip_info(uvs_net_addr_info_t *dst, uvs_net_addr_info_t *src)
{
    dst->net_addr = src->net_addr;
    dst->type = src->type;
    dst->vlan = src->vlan;
}

static int uvs_response_migrate_fast(tpsa_nl_msg_t *msg, tpsa_genl_ctx_t *genl_ctx,
                                     tpsa_mig_resp_status_t status)
{
    /* NETLINK to response to UBCORE */
    tpsa_nl_msg_t *nlresp = tpsa_nl_mig_msg_resp_fast(msg, status);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_genl_send_msg(genl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    free(nlresp);
    TPSA_LOG_INFO("Finish fast NETLINK response mig msg status to ubcore\n");

    return 0;
}

static void uvs_lm_init_tp_msg_ctx(tpsa_table_t *table_ctx, vport_table_entry_t *vport_entry, uvs_net_addr_info_t *sip,
                                   tpsa_create_param_t *cparam, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tp_msg_ctx->trans_type = cparam->ta_data.trans_type;
    tp_msg_ctx->trans_mode = cparam->trans_mode;
    tp_msg_ctx->upi = cparam->upi;
    tp_msg_ctx->ta_data = cparam->ta_data;

    tp_msg_ctx->vport_ctx.key = vport_entry->key;

    if (cparam->trans_mode != TPSA_TP_UM) {
        // UM mode will fill outside this function
        tpsa_fill_vport_param(vport_entry, &tp_msg_ctx->vport_ctx.param);
    }

    tp_msg_ctx->src.eid = cparam->local_eid;
    tp_msg_ctx->src.jetty_id = cparam->local_jetty;
    tp_msg_ctx->src.ip = *sip;

    (void)tpsa_lookup_dip_table(&table_ctx->dip_table, cparam->peer_eid, cparam->upi, &tp_msg_ctx->peer.uvs_ip,
        &tp_msg_ctx->dst.ip);

    tp_msg_ctx->dst.eid = cparam->peer_eid;
    tp_msg_ctx->dst.jetty_id = cparam->peer_jetty;
}

int uvs_lm_swap_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    /* Lookup sip and vport entry */
    sip_table_entry_t sip_entry = {0};
    int ret;
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }

    ret = tpsa_lookup_vport_table(vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (ret < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %hu\n", vport_key->fe_idx);
        free(vport_entry);
        return ret;
    }

    ret = tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_entry->key.tpf_name,
        vport_entry->sip_idx, &sip_entry);
    if (ret != 0 && tp_msg_ctx->trans_type == TPSA_TRANSPORT_UB) {
        TPSA_LOG_ERR("Can not find sip table by tpf_name %s and sip_idx %u\n",
            vport_entry->key.tpf_name, vport_entry->sip_idx);
        free(vport_entry);
        return ret;
    }
    free(vport_entry);

    uint32_t vice_tpgn = UINT32_MAX;
    if (tpsa_vtp_tpgn_swap(ctx->table_ctx, &vice_tpgn, lm_vtp_entry) < 0) {
        TPSA_LOG_ERR("Fail to swap tpgn");
        return -1;
    }

    /* IOCTL to modify vtp */
    if (uvs_ioctl_cmd_modify_vtp(ctx->ioctl_ctx, vtp_cfg, &sip_entry.addr, vice_tpgn) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify vtp");

        /* swap back */
        if (tpsa_vtp_tpgn_swap(ctx->table_ctx, &vice_tpgn, lm_vtp_entry) < 0) {
            TPSA_LOG_ERR("Fail to swap tpgn");
            return -1;
        }

        return -1;
    }

    return 0;
}

int uvs_lm_handle_ready_rollback(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg,
    vport_key_t *vport_key, tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = -1;

    ret = tpsa_vtp_node_status_change(STATE_NORMAL, lm_vtp_entry);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to change node status");
        return -1;
    }

    TPSA_LOG_INFO("Change node status to rollback when ready");
    return 0;
}

int uvs_lm_create_vtp(uvs_ctx_t *ctx, tpsa_create_param_t *cparam,
                      uvs_net_addr_info_t *sip, vport_table_entry_t *vport_entry, bool migrateThird)
{
    bool isLoopback = false;

    if (memcmp(sip, &cparam->dip, sizeof(uvs_net_addr_info_t)) == 0) {
        isLoopback = true;
        if (memcmp(&cparam->local_eid, &cparam->peer_eid, sizeof(urma_eid_t)) == 0) {
            cparam->sig_loop = true;
        }
        /* The migrate third node does not have a link reconstruction in the loopback scenario. */
        if (migrateThird == true) {
            return 0;
        }
    }

    tpsa_tpg_table_index_t tpg_idx;
    (void)memset(&tpg_idx, 0, sizeof(tpsa_tpg_table_index_t));
    tpg_idx.dip = cparam->dip;
    tpg_idx.sip = *sip;
    tpg_idx.local_eid = cparam->local_eid;
    tpg_idx.peer_eid = cparam->peer_eid;
    tpg_idx.ljetty_id = cparam->local_jetty;
    tpg_idx.djetty_id = cparam->peer_jetty;
    tpg_idx.isLoopback = isLoopback;
    tpg_idx.sig_loop = cparam->sig_loop;
    tpg_idx.upi = cparam->upi;

    uvs_nl_resp_info_t nl_resp = {
        .resp = false,
        .status = TPSA_NL_RESP_FAIL,
        .vtpn = UINT32_MAX,
    };

    uvs_tp_msg_ctx_t tp_msg_ctx = { 0 };
    uvs_lm_init_tp_msg_ctx(ctx->table_ctx, vport_entry, sip, cparam, &tp_msg_ctx);
    uvs_lm_set_dip_info(&tp_msg_ctx.dst.ip, &cparam->dip);
    tp_msg_ctx.peer.uvs_ip = cparam->dst_uvs_ip;

    TPSA_LOG_INFO("cparam share mode:%u, tp_msg_ctx share mode:%u\n",
        cparam->share_mode, tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.share_mode);
    tp_msg_ctx.vport_ctx.param.tp_cfg.tp_mod_flag.bs.share_mode = cparam->share_mode;

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

    TPSA_LOG_INFO("final lm share_mode is %u", (uint32_t)cparam->share_mode);

    if (uvs_create_vtp_base(ctx, &tp_msg_ctx, cparam, &tpg_idx, &nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to run create tpg base.");
        return -1;
    }

    return 0;
}

int uvs_lm_handle_rm_req(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq, sip_table_entry_t *sip_entry,
                         vport_table_entry_t *vport_entry, tpsa_notify_table_t *notify_table)
{
    rm_vtp_table_entry_t *entry;

    /* invalidation check */
    if (lmreq->rm_vtp_num > TPSA_LM_REQ_SIZE) {
        TPSA_LOG_ERR("Invalid rm num when handle lm req");
        return -1;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_RM;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->live_migrate = true;
    cparam->migrate_third = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
    memcpy(cparam->tpf_name, vport_entry->key.tpf_name, UVS_MAX_DEV_NAME);
    cparam->mtu = uvs_get_mtu_with_sip_mtu(ctx, sip_entry->mtu);

    uint32_t i = 0;
    for (; i < lmreq->rm_vtp_num; i++) {
        entry = &lmreq->total_vtp[i].content.rm_entry;
        if (entry->eid_index >= TPSA_EID_IDX_TABLE_SIZE) {
            TPSA_LOG_ERR("Fail to get rm entry when lm\n");
            free(cparam);
            return -1;
        }

        (void)tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, entry->key.dst_eid, entry->upi, &cparam->dst_uvs_ip,
            &cparam->dip);
        if (entry->location != TPSA_INITIATOR) {
            if (tpsa_notify_table_update(notify_table, &cparam->dst_uvs_ip, entry, NULL) < 0) {
                TPSA_LOG_ERR("Fail to add tpsa noti table(RM) when handle lm target\n");
                free(cparam);
                return -1;
            }

            if (entry->location == TPSA_TARGET) {
                continue;
            }
        }

        if (vport_entry->ueid[entry->eid_index].entry == NULL) {
            TPSA_LOG_ERR("Fail to get rm vport/subport entry when lm, entry index:%u\n", entry->eid_index);
            free(cparam);
            return -1;
        }

        cparam->local_eid = entry->key.src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->local_jetty = entry->src_jetty_id;
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;
        cparam->sig_loop = false;
        cparam->upi = entry->upi;
        cparam->pattern = vport_entry->ueid[entry->eid_index].entry->pattern;
        cparam->share_mode = entry->share_mode;

        if (uvs_lm_create_vtp(ctx, cparam, &sip_entry->addr, vport_entry->ueid[entry->eid_index].entry, false) < 0) {
            TPSA_LOG_ERR("Fail to create RM vtp when lm");
            free(cparam);
            return -1;
        }
    }

    free(cparam);
    TPSA_LOG_INFO("Finish handle initiator rm type");
    return 0;
}

int uvs_lm_handle_rc_req(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq, sip_table_entry_t *sip_entry,
                         vport_table_entry_t *vport_entry, tpsa_notify_table_t *notify_table)
{
    rc_vtp_table_entry_t *entry;

    /* invalidation check */
    if ((lmreq->rm_vtp_num + lmreq->rc_vtp_num) > TPSA_LM_REQ_SIZE ||
        lmreq->rc_vtp_num > TPSA_LM_REQ_SIZE || lmreq->rm_vtp_num > TPSA_LM_REQ_SIZE) {
        TPSA_LOG_ERR("Invalid rc num when handle lm req");
        return -1;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_RC;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->live_migrate = true;
    cparam->migrate_third = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
    memcpy(cparam->tpf_name, vport_entry->key.tpf_name, UVS_MAX_DEV_NAME);
    cparam->mtu = uvs_get_mtu_with_sip_mtu(ctx, sip_entry->mtu);

    uint32_t i = 0;
    for (; i < lmreq->rc_vtp_num; i++) {
        entry = &lmreq->total_vtp[lmreq->rm_vtp_num + i].content.rc_entry;
        if (entry->eid_index >= TPSA_EID_IDX_TABLE_SIZE) {
            TPSA_LOG_ERR("Fail to get rm entry when lm");
            free(cparam);
            return -1;
        }

        (void)tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, entry->key.dst_eid, entry->upi, &cparam->dst_uvs_ip,
            &cparam->dip);
        if (entry->location != TPSA_INITIATOR) {
            if (tpsa_notify_table_update(notify_table, &cparam->dst_uvs_ip, NULL, entry) < 0) {
                TPSA_LOG_ERR("Fail to add tpsa noti table(RC) when handle lm target");
                free(cparam);
                return -1;
            }

            if (entry->location == TPSA_TARGET) {
                continue;
            }
        }

        if (vport_entry->ueid[entry->eid_index].entry == NULL) {
            TPSA_LOG_ERR("Fail to get rc vport/subport entry when lm, entry index:%u\n", entry->eid_index);
            free(cparam);
            return -1;
        }

        cparam->local_eid = entry->src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->local_jetty = entry->src_jetty_id;
        cparam->peer_jetty = entry->key.jetty_id;
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;
        cparam->upi = entry->upi;
        cparam->pattern = vport_entry->ueid[entry->eid_index].entry->pattern;

        if ((memcmp(&cparam->local_eid, &cparam->peer_eid, sizeof(urma_eid_t)) == 0) &&
            cparam->local_jetty == cparam->peer_jetty) {
            cparam->sig_loop = true;
        } else {
            cparam->sig_loop = false;
        }

        if (uvs_lm_create_vtp(ctx, cparam, &sip_entry->addr, vport_entry->ueid[entry->eid_index].entry, false) < 0) {
            TPSA_LOG_ERR("Fail to create RC vtp when lm");
            free(cparam);
            return -1;
        }
    }

    TPSA_LOG_INFO("Finish handle initiator rc type");
    free(cparam);
    return 0;
}

static int uvs_lm_handle_um_req(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq,
                                sip_table_entry_t *sip_entry, vport_table_entry_t *vport_entry)
{
    um_vtp_table_entry_t *entry;
    uint32_t total_vtp_num = lmreq->rm_vtp_num + lmreq->rc_vtp_num + lmreq->um_vtp_num;

    /* invalidation check */
    if (total_vtp_num > TPSA_LM_REQ_SIZE) {
        TPSA_LOG_ERR("Invalid um num when handle lm req");
        return -1;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_UM;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->live_migrate = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
    memcpy(cparam->tpf_name, vport_entry->key.tpf_name, UVS_MAX_DEV_NAME);
    cparam->mtu = uvs_get_mtu_with_sip_mtu(ctx, sip_entry->mtu);
    cparam->location = TPSA_INITIATOR;

    uvs_tp_msg_ctx_t tp_msg_ctx = { 0 };
    tp_msg_ctx.ta_data = cparam->ta_data;
    tp_msg_ctx.trans_mode = cparam->trans_mode;

    uint32_t i = lmreq->rm_vtp_num + lmreq->rc_vtp_num;
    for (; i < total_vtp_num; i++) {
        entry = &lmreq->total_vtp[i].content.um_entry;

        uint32_t eid_index = entry->eid_index;
        cparam->eid_index = eid_index;
        cparam->local_eid = entry->key.src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->vtpn = entry->vtpn;
        cparam->upi = entry->upi;

        uvs_lm_init_tp_msg_ctx(ctx->table_ctx, vport_entry, &sip_entry->addr, cparam, &tp_msg_ctx);
        if (tpsa_lookup_vport_param_with_eid_idx(&vport_entry->key, &ctx->table_ctx->vport_table,
            eid_index, &tp_msg_ctx.vport_ctx.param, &tp_msg_ctx.lm_ctx) != 0) {
            TPSA_LOG_ERR("Eid index is invaild or cannot find vport/subport entry, eid index:%u\n", eid_index);
            free(cparam);
            return -1;
        }

        cparam->pattern = vport_entry->ueid[eid_index].entry->pattern;
        if (uvs_create_um_vtp_base(ctx, &tp_msg_ctx, cparam, &entry->vtpn) < 0) {
            TPSA_LOG_ERR("Fail to create UM vtp in third node when lm");
            free(cparam);
            return -1;
        }
    }

    free(cparam);
    return 0;
}

static void uvs_lm_notification_init(tpsa_notify_table_t *notify_table, tpsa_notify_table_key_t *key,
                                     uvs_net_addr_info_t *sip, tpsa_sock_msg_t *msg, uvs_socket_init_attr_t *tpsa_attr)
{
    msg->msg_type = TPSA_LM_NOTIFY;

    tpsa_notify_table_entry_t *entry = tpsa_notify_table_lookup(notify_table, key);
    /* incalidation check */
    if ((entry->rm_size + entry->rc_size) > TPSA_LM_REQ_SIZE) {
        TPSA_LOG_ERR("Invalid notification entry size.");
        return;
    }

    uint32_t i = 0;
    for (; i < entry->rm_size; i++) {
        msg->content.lmnoti.target_vtp[i].content.rm_entry = entry->rm_target[i];
        msg->content.lmnoti.target_vtp[i].location = TPSA_TARGET;
        msg->content.lmnoti.target_vtp[i].trans_mode = TPSA_TP_RM;
    }
    msg->content.lmnoti.target_rm_num = entry->rm_size;

    for (; i < (entry->rm_size + entry->rc_size); i++) {
        msg->content.lmnoti.target_vtp[i].content.rc_entry = entry->rc_target[i - entry->rm_size];
        msg->content.lmnoti.target_vtp[i].location = TPSA_TARGET;
        msg->content.lmnoti.target_vtp[i].trans_mode = TPSA_TP_RC;
    }
    msg->content.lmnoti.target_rc_num = entry->rc_size;

    msg->content.lmnoti.dip = *sip;
    msg->content.lmnoti.dst_uvs_ip = tpsa_attr->server_ip;
}

static int uvs_lm_handle_target_send(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, uvs_net_addr_info_t *sip,
                                     tpsa_notify_table_t *notify_table)
{
    tpsa_notify_table_entry_t *notify_cur, *notify_next;
    tpsa_notify_table_key_t key = {0};
    int ret = 0;

    tpsa_sock_msg_t *notimsg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (notimsg == NULL) {
        return -ENOMEM;
    }

    (void)memset(notimsg, 0, sizeof(tpsa_sock_msg_t));

    notimsg->upi = msg->upi;
    notimsg->local_eid = msg->local_eid;

    HMAP_FOR_EACH_SAFE(notify_cur, notify_next, node, &notify_table->hmap) {
        key = notify_cur->key;

        uvs_lm_notification_init(notify_table, &key, sip, notimsg, &ctx->tpsa_attr);
        if ((notimsg->content.lmnoti.target_rm_num == 0) && (notimsg->content.lmnoti.target_rc_num == 0)) {
            /* init fail. */
            TPSA_LOG_ERR("Failed to init lm notification\n");
            ret = -1;
            goto free_and_exit;
        }

        ret = tpsa_sock_send_msg(ctx->sock_ctx, notimsg, sizeof(tpsa_sock_msg_t), key.peer_uvs_ip);
        if (ret < 0) {
            TPSA_LOG_ERR("Failed to send lm notification\n");
            goto free_and_exit;
        }

        (void)memset(notimsg, 0, sizeof(tpsa_sock_msg_t));
    }

free_and_exit:
    free(notimsg);
    return ret;
}

static int uvs_lm_config_migrate_state(uvs_ctx_t *ctx, vport_table_entry_t *vport_entry,
                                       uvs_net_addr_info_t *sip, tpsa_mig_state_t state)
{
    /* IOCTL to config state when receive lm req */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        return -ENOMEM;
    }

    uint32_t config_loop = vport_entry->ueid_max_cnt / TPSA_MAX_EID_CONFIG_CNT;
    if (vport_entry->ueid_max_cnt % TPSA_MAX_EID_CONFIG_CNT != 0) {
        config_loop += 1;
    }

    tpsa_cmd_tpf_t tpf = {
        .trans_type = TPSA_TRANSPORT_UB,
        .netaddr = sip->net_addr,
    };

    uint32_t i = 0;
    uint32_t res_cnt = 0;
    for (; i < config_loop; i++) {
        tpsa_ioctl_cmd_config_state(cfg, vport_entry, &tpf,
                                    state, (i * TPSA_MAX_EID_CONFIG_CNT));
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to migrate state, %d", (int)state);
            free(cfg);
            return -1;
        }
        res_cnt += cfg->cmd.config_state.out.cnt;
    }

    free(cfg);

    if (res_cnt != vport_entry->ueid_max_cnt) {
        TPSA_LOG_ERR("Fail to ioctl to config function state, config %u of total %u",
                     res_cnt, vport_entry->ueid_max_cnt);
        return -1;
    }

    return 0;
}

/* Used to record the number of migrated vtp entries */
static void uvs_lm_record_vtp_num(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq, fe_table_entry_t *fe_entry, uint32_t *vtp_num)
{
    /* Superimpose the number of full and iteratively migrated vtp nodes. */
    *vtp_num = lmreq->rm_vtp_num + lmreq->rc_vtp_num + lmreq->um_vtp_num;
    fe_entry->vtp_migrate_num += *vtp_num;
    fe_entry->src_uvs_ip = lmreq->src_uvs_ip;
    fe_entry->lm_fe_idx = lmreq->fe_idx;
    (void)memcpy(fe_entry->lm_dev_name, lmreq->dev_name, UVS_MAX_DEV_NAME);

    return;
}

static int uvs_lm_handle_rebuild_link(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, sip_table_entry_t *sip_entry,
                                      vport_table_entry_t *vport_entry)
{
    int ret = -1;
    tpsa_lm_req_t *lmreq = &msg->content.lmmsg;

    /* create nofity table to save notify entry */
    tpsa_notify_table_t *notify_table = (tpsa_notify_table_t *)calloc(1, sizeof(tpsa_notify_table_t));
    if (notify_table == NULL) {
        return -ENOMEM;
    }

    ret = tpsa_notify_table_create(notify_table);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to create notify table");
        free(notify_table);
        return -1;
    }

    if (lmreq->rm_vtp_num != 0) {
        ret = uvs_lm_handle_rm_req(ctx, lmreq, sip_entry, vport_entry, notify_table);
        if (ret < 0) {
            TPSA_LOG_ERR("Fail to handle rm initiator when lm");
            goto destroy_table;
        }
    }

    if (lmreq->rc_vtp_num != 0) {
        ret = uvs_lm_handle_rc_req(ctx, lmreq, sip_entry, vport_entry, notify_table);
        if (ret < 0) {
            TPSA_LOG_ERR("Fail to handle rc initiator when lm");
            goto destroy_table;
        }
    }

    if (lmreq->um_vtp_num != 0) {
        ret = uvs_lm_handle_um_req(ctx, lmreq, sip_entry, vport_entry);
        if (ret < 0) {
            TPSA_LOG_ERR("Fail to handle um when lm");
            goto destroy_table;
        }
    }

    ret = uvs_lm_handle_target_send(ctx, msg, &sip_entry->addr, notify_table);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to handle target when lm");
        goto destroy_table;
    }

destroy_table:
    tpsa_notify_table_destroy(notify_table);
    free(notify_table);
    return ret;
}

int uvs_lm_handle_mig_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_req_t *lmreq = &msg->content.lmmsg;
    sip_table_entry_t sip_entry = {0};
    uint32_t eid_idx;
    fe_table_entry_t *fe_entry;
    uint32_t vtp_num = 0;
    vport_key_t vport_key = {0};

    /* local_eid refers to the eid of the migrated virtual machine */
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->local_eid,
                                              &vport_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport key lookup failed, upi:%u, eid:" EID_FMT "\n", msg->upi, EID_ARGS(msg->local_eid));
        return -1;
    }

    TPSA_LOG_INFO("dst_mig recv vtp entries from src,fe_idx:%u, dev_name:%s.\n", vport_key.fe_idx, vport_key.tpf_name);

    if (vport_set_lm_location(&ctx->table_ctx->vport_table, &vport_key, LM_DESTINATION) != 0) {
        TPSA_LOG_ERR("Fail to set lm vport entry location in migrate destination.\n");
        return -1;
    }

    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }

    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", vport_key.fe_idx);
        goto free_vport;
    }
    res = tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_key.tpf_name, vport_entry->sip_idx, &sip_entry);
    if (res != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf name %s and sip_idx %u\n", vport_key.tpf_name, vport_entry->sip_idx);
        goto free_vport;
    }
    /* First time need to config state */
    fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &vport_key);
    if (fe_entry == NULL) {
        if (uvs_lm_config_migrate_state(ctx, vport_entry, &sip_entry.addr, TPSA_MIG_STATE_START) < 0) {
            TPSA_LOG_ERR("Fail to ioctl to config state when receive lm req");
            goto free_vport;
        }

        fe_entry = fe_table_add(&ctx->table_ctx->fe_table, &vport_key);
        if (fe_entry == NULL) {
            TPSA_LOG_ERR("fe_table_add failed");
            goto free_vport;
        }
    }
    fe_entry->stop_proc_vtp = lmreq->stop_proc_vtp;

    /* Record the number of live migrated vtp nodes */
    uvs_lm_record_vtp_num(ctx, lmreq, fe_entry, &vtp_num);
    if (vtp_num == 0) {
        TPSA_LOG_INFO("No vtp entries need to be processed in this mig req.\n");
        free(vport_entry);
        return uvs_create_resp_to_lm_src(ctx, vport_key);
    }

    if (uvs_lm_handle_rebuild_link(ctx, msg, &sip_entry, vport_entry) < 0) {
        TPSA_LOG_ERR("Fail to handle rebuild link");
        goto free_vport;
    }

    free(vport_entry);
    return 0;

free_vport:
    free(vport_entry);
    return -1;
}

static vport_table_entry_t *uvs_lm_hanlde_notify_pre_check(uvs_ctx_t *ctx, sip_table_entry_t *sip_entry,
    ueid_key_t ukey, uint32_t entry_index)
{
    vport_table_entry_t *vport_entry = NULL;
    vport_key_t vport_key = {0};
    urma_eid_t eid = ukey.eid;
    uint32_t upi = ukey.upi;
    uint32_t eid_index;

    do {
        if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, upi,
            &eid, &vport_key, &eid_index) != 0) {
            TPSA_LOG_ERR("Fail to lookup vport key by ueid when lm, upi:%u, eid:" EID_FMT "\n", upi, EID_ARGS(eid));
            break;
        }

        vport_entry = vport_table_lookup(&ctx->table_ctx->vport_table, &vport_key);
        if (vport_entry == NULL) {
            TPSA_LOG_ERR("Fail to lookup vport entry when lm, tpf name %s, fe idx:%u\n",
                vport_key.tpf_name, vport_key.fe_idx);
            break;
        }

        if (entry_index >= TPSA_EID_IDX_TABLE_SIZE || vport_entry->ueid[entry_index].entry == NULL) {
            TPSA_LOG_ERR("Eid index is invaild or cannot find vport/subport entry, eid index:%u\n", entry_index);
            break;
        }

        if (tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_entry->key.tpf_name,
            vport_entry->sip_idx, sip_entry) != 0) {
            TPSA_LOG_ERR("Can not find sip by tpf name %s and sip_idx %u\n",
                vport_entry->key.tpf_name, vport_entry->sip_idx);
            break;
        }
        return vport_entry;
    } while (0);
    return NULL;
}

static int uvs_lm_handle_rm_noti(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_notification_t *notify = &msg->content.lmnoti;
    vport_table_entry_t *vport_entry = NULL;
    rm_vtp_table_entry_t *entry = NULL;
    sip_table_entry_t sip_entry = {0};
    ueid_key_t ukey = {0};
    uint32_t i = 0;

    /* invalidation check */
    if (notify->target_rm_num > TPSA_LM_REQ_SIZE) {
        TPSA_LOG_ERR("Invalid target rm num when handle rm noti\n");
        return -1;
    }

    if (notify->target_rm_num == 0) {
        TPSA_LOG_INFO("No need to handle rm mode.\n");
        return 0;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_RM;
    cparam->dip = notify->dip;
    cparam->dst_uvs_ip = notify->dst_uvs_ip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->live_migrate = true;
    /* as third node, this flag is true */
    cparam->migrate_third = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;

    for (; i < notify->target_rm_num; i++) {
        entry = &notify->target_vtp[i].content.rm_entry;
        ukey.eid = entry->key.dst_eid;
        ukey.upi = msg->upi;

        vport_entry = uvs_lm_hanlde_notify_pre_check(ctx, &sip_entry, ukey, entry->eid_index);
        if (vport_entry == NULL) {
            TPSA_LOG_ERR("Failed to pre check notify of rm type in third node\n");
            goto rm_exit;
        }

        memcpy(cparam->tpf_name, vport_entry->key.tpf_name, UVS_MAX_DEV_NAME);

        cparam->upi = entry->upi;
        cparam->local_eid = entry->key.dst_eid;
        cparam->peer_eid = entry->key.src_eid;
        cparam->fe_idx = vport_entry->key.fe_idx;
        cparam->pattern = vport_entry->ueid[entry->eid_index].entry->pattern;
        cparam->share_mode = entry->share_mode;

        if (uvs_lm_create_vtp(ctx, cparam, &sip_entry.addr, vport_entry->ueid[entry->eid_index].entry, true) < 0) {
            TPSA_LOG_ERR("Fail to create rm vtp in third node when lm\n");
            goto rm_exit;
        }
    }

    free(cparam);
    TPSA_LOG_INFO("Finish handle target rm type in third node\n");
    return 0;

rm_exit:
    free(cparam);
    return -1;
}

static int uvs_lm_handle_rc_noti(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_notification_t *notify = &msg->content.lmnoti;
    vport_table_entry_t *vport_entry = NULL;
    rc_vtp_table_entry_t *entry = NULL;
    sip_table_entry_t sip_entry = {0};
    ueid_key_t ukey = {0};
    uint32_t i = 0;

    /* invalidation check */
    if ((notify->target_rm_num + notify->target_rc_num) > TPSA_LM_REQ_SIZE ||
        notify->target_rm_num > TPSA_LM_REQ_SIZE || notify->target_rc_num > TPSA_LM_REQ_SIZE) {
        TPSA_LOG_ERR("Invalid target rc num when handle rc noti\n");
        return -1;
    }

    if (notify->target_rc_num == 0) {
        TPSA_LOG_INFO("No need to handle rc mode.\n");
        return 0;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_RC;
    cparam->dip = notify->dip;
    cparam->dst_uvs_ip = notify->dst_uvs_ip;
    cparam->live_migrate = true;
    /* as third node, this flag is true */
    cparam->migrate_third = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;

    for (; i < notify->target_rc_num; i++) {
        entry = &notify->target_vtp[notify->target_rm_num + i].content.rc_entry;
        ukey.eid = entry->key.dst_eid;
        ukey.upi = msg->upi;

        vport_entry = uvs_lm_hanlde_notify_pre_check(ctx, &sip_entry, ukey, entry->eid_index);
        if (vport_entry == NULL) {
            TPSA_LOG_ERR("Failed to pre check notify of rc type in third node\n");
            goto rc_exit;
        }

        memcpy(cparam->tpf_name, vport_entry->key.tpf_name, UVS_MAX_DEV_NAME);

        cparam->fe_idx = vport_entry->key.fe_idx;
        cparam->pattern = vport_entry->ueid[entry->eid_index].entry->pattern;
        cparam->local_eid = entry->key.dst_eid;
        cparam->peer_eid = entry->src_eid;
        cparam->local_jetty = entry->key.jetty_id;
        cparam->peer_jetty = entry->src_jetty_id;
        cparam->upi = entry->upi;

        if (uvs_lm_create_vtp(ctx, cparam, &sip_entry.addr, vport_entry->ueid[entry->eid_index].entry, true) < 0) {
            TPSA_LOG_ERR("Fail to create rc vtp in third node when lm\n");
            goto rc_exit;
        }
    }

    free(cparam);
    TPSA_LOG_INFO("Finish handle target rc type in third node\n");
    return 0;

rc_exit:
    free(cparam);
    return -1;
}

int uvs_lm_handle_notify(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    /* handle target */
    if (uvs_lm_handle_rm_noti(ctx, msg) < 0) {
        TPSA_LOG_ERR("Fail to handle rm notification when lm");
        return -1;
    }

    if (uvs_lm_handle_rc_noti(ctx, msg) < 0) {
        TPSA_LOG_ERR("Fail to handle rc notification when lm");
        return -1;
    }

    return 0;
}

int uvs_lm_config_migrate_state_local(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, tpsa_mig_state_t state)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    vport_table_entry_t *vport_entry = NULL;
    int ret = 0;

    TPSA_LOG_INFO("lm config local migrate state[%u], fe_idx[%u], tpf_name[%s]",
        state, nlreq->mig_fe_idx, nlreq->dev_name);
    vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }
    /* Lookup sip and vport entry */
    sip_table_entry_t sip_entry = {0};
    vport_key_t vport_key = {0};
    vport_key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(vport_key.tpf_name, nlreq->dev_name, UVS_MAX_DEV_NAME);

    ret = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Can not find vport entry by tpf_name[%s] and fe_idx[%u]\n",
            vport_key.tpf_name, vport_key.fe_idx);
        goto resp_ubcore;
    }
    ret = tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_key.tpf_name,
        vport_entry->sip_idx, &sip_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf_name[%s] and sip_idx[%u]\n",
            vport_key.tpf_name, vport_entry->sip_idx);
        goto resp_ubcore;
    }

    ret = uvs_lm_config_migrate_state(ctx, vport_entry, &sip_entry.addr, state);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to ioctl to config state");
    }

resp_ubcore:
    ret = uvs_response_migrate_fast(msg, ctx->genl_ctx,
        (ret == 0 ? TPSA_MIG_MSG_PROC_SUCCESS : TPSA_MIG_MSG_PROC_FAILURE));
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
    }
    free(vport_entry);
    return ret;
}

static int uvs_lm_query_rm_vtp_entry_status(tpsa_vtp_cfg_t *vtp_cfg, uvs_ctx_t *ctx, vtp_node_state_t *node_status,
                                            vport_key_t *fe_key, struct tpsa_lm_vtp_entry *lm_vtp_entry)
{
    rm_vtp_table_key_t vtp_key = {
        .src_eid = vtp_cfg->local_eid,
        .dst_eid = vtp_cfg->peer_eid,
    };

    rm_vtp_table_entry_t *vtp_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, fe_key, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("Can't find vtp entry in rm vtp table");
        return TPSA_LOOKUP_NULL;
    }

    *node_status = vtp_entry->node_status;
    lm_vtp_entry->content.rm_entry = vtp_entry;
    lm_vtp_entry->trans_mode = TPSA_TP_RM;

    return 0;
}

static int uvs_lm_query_rc_vtp_entry_status(tpsa_vtp_cfg_t *vtp_cfg, uvs_ctx_t *ctx, vtp_node_state_t *node_status,
                                            vport_key_t *fe_key, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    rc_vtp_table_key_t vtp_key = {
        .dst_eid = vtp_cfg->peer_eid,
        .jetty_id = vtp_cfg->peer_jetty,
    };

    rc_vtp_table_entry_t *vtp_entry = rc_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, fe_key, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("Can't find vtp entry in rc vtp table");
        return TPSA_LOOKUP_NULL;
    }

    *node_status = vtp_entry->node_status;
    lm_vtp_entry->content.rc_entry = vtp_entry;
    lm_vtp_entry->trans_mode = TPSA_TP_RC;

    return 0;
}

int uvs_lm_query_vtp_entry_status(tpsa_nl_msg_t *msg, uvs_ctx_t *ctx, vtp_node_state_t *node_status,
                                  tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    tpsa_nl_migrate_vtp_req_t *mig_req = (tpsa_nl_migrate_vtp_req_t *)msg->payload;
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;
    int ret;
    vport_key_t fe_key;

    fe_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(fe_key.tpf_name, mig_req->dev_name, UVS_MAX_DEV_NAME);

    if (vtp_cfg->trans_mode == TPSA_TP_RM) {
        ret = uvs_lm_query_rm_vtp_entry_status(vtp_cfg, ctx, node_status, &fe_key, lm_vtp_entry);
    } else {
        ret = uvs_lm_query_rc_vtp_entry_status(vtp_cfg, ctx, node_status, &fe_key, lm_vtp_entry);
    }

    return ret;
}

static int uvs_lm_rollback_req_init(tpsa_sock_msg_t *rbreq, uvs_ctx_t *ctx, vport_key_t *key)
{
    rbreq->msg_type = TPSA_LM_ROLLBACK_REQ;
    vport_table_entry_t entry = {0};
    int ret = tpsa_lookup_vport_table(key, &ctx->table_ctx->vport_table, &entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to init rollback req.\n");
        return -1;
    }

    rbreq->upi = entry.ueid[0].upi;
    rbreq->local_eid = entry.ueid[0].eid;

    return 0;
}

int uvs_lm_handle_rollback(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    live_migrate_table_entry_t *lm_entry;
    live_migrate_table_entry_t lm_entry_local = {0};
    int ret = 0;

    TPSA_LOG_INFO("lm initiator handle rollback, fe_idx[%u], tpf_name[%s].\n", nlreq->mig_fe_idx, nlreq->dev_name);

    if (uvs_lm_config_migrate_state_local(ctx, msg, TPSA_MIG_STATE_FINISH) < 0) {
        TPSA_LOG_ERR("Fail to config state FINISH when receive rollback nl msg");
        return -1;
    }

    tpsa_sock_msg_t *rbreq = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (rbreq == NULL) {
        return -ENOMEM;
    }

    /* lookup destination node tpsa address and send msg */
    live_migrate_table_key_t key = {0};
    key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(key.tpf_name, nlreq->dev_name, UVS_MAX_DEV_NAME);

    (void)pthread_rwlock_rdlock(&ctx->table_ctx->live_migrate_table.rwlock);
    lm_entry = live_migrate_table_lookup(&ctx->table_ctx->live_migrate_table, &key);
    if (lm_entry == NULL) {
        (void)pthread_rwlock_unlock(&ctx->table_ctx->live_migrate_table.rwlock);
        TPSA_LOG_ERR("Can't find lm entry in live migrate table, send rollback msg failed");
        ret = TPSA_LOOKUP_NULL;
        goto free_req;
    }
    lm_entry_local = *lm_entry;
    (void)pthread_rwlock_unlock(&ctx->table_ctx->live_migrate_table.rwlock);

    if (uvs_lm_rollback_req_init(rbreq, ctx, &key) < 0) {
        TPSA_LOG_ERR("Failed to init rollback req\n");
        goto free_req;
    }

    ret = tpsa_sock_send_msg(ctx->sock_ctx, rbreq, sizeof(tpsa_sock_msg_t), lm_entry_local.uvs_ip);
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to send rollback msg\n");
        goto free_req;
    }

free_req:
    free(rbreq);
    return ret;
}

int uvs_lm_handle_rollback_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    TPSA_LOG_INFO("lm receive rollback req.\n");

    /* Lookup sip and vport entry */
    vport_table_entry_t vport_entry_local = {0};
    vport_table_entry_t *vport_entry = NULL;
    sip_table_entry_t sip_entry = {0};
    vport_key_t vport_key = {0};
    uint32_t eid_idx;
    int ret = 0;

    ret = vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi,
        &msg->local_eid, &vport_key, &eid_idx);
    if (ret != 0) {
        TPSA_LOG_ERR("Can not find vport key by upi[%u] and eid[ " EID_FMT " ].\n",
            msg->upi, EID_ARGS(msg->local_eid));
        return -1;
    }

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->vport_table.rwlock);
    vport_entry = vport_table_lookup(&ctx->table_ctx->vport_table, &vport_key);
    if (vport_entry == NULL) {
        (void)pthread_rwlock_unlock(&ctx->table_ctx->vport_table.rwlock);
        TPSA_LOG_ERR("Can not find vport entry by tpf_name[%s] and fe_idx[%u].\n",
            vport_key.tpf_name, vport_key.fe_idx);
        ret = -1;
        goto ret_return;
    }
    vport_entry->lm_attr.is_rollback = true;
    vport_entry_local = *vport_entry;
    (void)pthread_rwlock_unlock(&ctx->table_ctx->vport_table.rwlock);

    ret = tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_key.tpf_name,
        vport_entry_local.sip_idx, &sip_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf_name[%s] and sip_idx[%u]\n",
            vport_key.tpf_name, vport_entry_local.sip_idx);
        goto ret_return;
    }

    /* config rollback state to driver */
    ret = uvs_lm_config_migrate_state(ctx, &vport_entry_local, &sip_entry.addr, TPSA_MIG_STATE_ROLLBACK);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to ioctl to config rollback state in mig dest\n.");
    }

ret_return:
    return ret;
}

int uvs_lm_handle_query_mig_status(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    tpsa_mig_resp_status_t status = TPSA_MIG_MSG_PROC_SUCCESS;
    fe_table_entry_t *fe_entry;
    int ret = 0;

    TPSA_LOG_INFO("lm initiator handle query status, fe_idx is %u", nlreq->mig_fe_idx);
    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(fe_key.tpf_name, nlreq->dev_name, UVS_MAX_DEV_NAME);

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
    fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_WARN("key fe_idx %hu not exist in fe_table when handle query status", fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
        status = TPSA_VTP_MIG_COMPLETE;
        ret = TPSA_LOOKUP_NULL;
        goto resp_and_ret;
    }

    if (fe_entry->link_ready) {
        status = TPSA_VTP_MIG_COMPLETE;
    } else {
        status = TPSA_VTP_MIG_UNCOMPLETE;
    }
    (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);

resp_and_ret:
    /* response to ubcore via nl */
    if (uvs_response_migrate_fast(msg, ctx->genl_ctx, status) < 0) {
        TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
        ret = -1;
    }

    return ret;
}

int uvs_lm_handle_mig_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_resp_t lm_resp = msg->content.lm_resp;

    TPSA_LOG_INFO("migrate source receives the resp from migration dest.");
    if (lm_resp.last_mig_completed == true) {
        vport_key_t fe_key = {0};
        fe_key.fe_idx = lm_resp.mig_fe_idx;
        (void)memcpy(fe_key.tpf_name, lm_resp.dev_name, UVS_MAX_DEV_NAME);

        (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
        fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &fe_key);
        if (fe_entry == NULL) {
            TPSA_LOG_WARN("key fe_idx %hu,dev_name:%s not exist in fe_table when handle lm resp",
                fe_key.fe_idx, fe_key.tpf_name);
            (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
            return TPSA_LOOKUP_NULL;
        }
        /* Record that the migration destination has completed link reconstruction */
        fe_entry->link_ready = true;
        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
    }

    return 0;
}

int uvs_lm_for_rm_vtp_table(rm_vtp_table_t *rm_vtp_table, tpsa_sock_msg_t *req,
    lm_wait_sync_table_entry_t *lm_sync_entry)
{
    rm_vtp_table_entry_t *vtp_cur, *vtp_next;
    uint32_t total_num = req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num +
        req->content.lmmsg.um_vtp_num;
    uint32_t i = total_num;

    if (lm_sync_entry != NULL) {
        lm_wait_sync_vtp_t *cur, *next;
        UB_LIST_FOR_EACH_SAFE(cur, next, node, &lm_sync_entry->lm_wait_sync_vtp_list) {
            if (cur->trans_mode == TPSA_TP_RM) {
                if (i >= TPSA_LM_REQ_SIZE) {
                    TPSA_LOG_WARN("vtp buff is full when handle rm, live migrate process terminated");
                    return -1;
                }
                req->content.lmmsg.total_vtp[i].location = cur->vtp_entry.rm_entry.location;
                req->content.lmmsg.total_vtp[i].trans_mode = TPSA_TP_RM;
                req->content.lmmsg.total_vtp[i].content.rm_entry = cur->vtp_entry.rm_entry;
                req->content.lmmsg.total_vtp[i].lm_need_del = true;
                i++;
                ub_list_remove(&cur->node);
                free(cur);
            }
        }
    }

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &rm_vtp_table->hmap) {
        if (vtp_cur->migration_status == true) {
            continue;
        }
        if (i >= TPSA_LM_REQ_SIZE) {
            TPSA_LOG_WARN("vtp buff is full when handle rm, live migrate process terminated");
            return -1;
        }

        req->content.lmmsg.total_vtp[i].location = vtp_cur->location;
        req->content.lmmsg.total_vtp[i].trans_mode = TPSA_TP_RM;
        req->content.lmmsg.total_vtp[i].content.rm_entry = *vtp_cur;

        vtp_cur->migration_status = true;
        i += 1;
    }

    req->content.lmmsg.rm_vtp_num = (i - total_num);

    return 0;
}

static int uvs_lm_for_rc_vtp_table(rc_vtp_table_t *rc_vtp_table, tpsa_sock_msg_t *req,
    lm_wait_sync_table_entry_t *lm_sync_entry)
{
    rc_vtp_table_entry_t *vtp_cur, *vtp_next;
    uint32_t total_num = req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num +
        req->content.lmmsg.um_vtp_num;
    uint32_t i = total_num;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &rc_vtp_table->hmap) {
        if (vtp_cur->migration_status == true) {
            continue;
        }
        if (i >= TPSA_LM_REQ_SIZE) {
            TPSA_LOG_WARN("vtp buff is full when handle rc, live migrate process terminated");
            return -1;
        }

        req->content.lmmsg.total_vtp[i].location = vtp_cur->location;
        req->content.lmmsg.total_vtp[i].trans_mode = TPSA_TP_RC;
        req->content.lmmsg.total_vtp[i].content.rc_entry = *vtp_cur;

        vtp_cur->migration_status = true;
        i += 1;
    }

    req->content.lmmsg.rc_vtp_num = (i - total_num);

    return 0;
}

static int uvs_lm_for_um_vtp_table(um_vtp_table_t *um_vtp_table, tpsa_sock_msg_t *req,
    lm_wait_sync_table_entry_t *lm_sync_entry)
{
    um_vtp_table_entry_t *vtp_cur, *vtp_next;
    uint32_t total_num = req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num +
        req->content.lmmsg.um_vtp_num;
    uint32_t i = total_num;

    if (lm_sync_entry != NULL) {
        lm_wait_sync_vtp_t *cur, *next;
        UB_LIST_FOR_EACH_SAFE(cur, next, node, &lm_sync_entry->lm_wait_sync_vtp_list) {
            if (cur->trans_mode == TPSA_TP_UM) {
                if (i >= TPSA_LM_REQ_SIZE) {
                    TPSA_LOG_WARN("vtp buff is full when handle rm, live migrate process terminated");
                    return -1;
                }
                req->content.lmmsg.total_vtp[i].trans_mode = TPSA_TP_UM;
                req->content.lmmsg.total_vtp[i].content.um_entry = cur->vtp_entry.um_entry;
                req->content.lmmsg.total_vtp[i].lm_need_del = true;
                i++;
                ub_list_remove(&cur->node);
                free(cur);
            }
        }
    }
    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &um_vtp_table->hmap) {
        if (vtp_cur->migration_status == true) {
            continue;
        }
        if (i >= TPSA_LM_REQ_SIZE) {
            TPSA_LOG_WARN("vtp buff is full when handle um, live migrate process terminated");
            return -1;
        }

        req->content.lmmsg.total_vtp[i].trans_mode = TPSA_TP_UM;
        req->content.lmmsg.total_vtp[i].content.um_entry = *vtp_cur;

        vtp_cur->migration_status = true;
        i += 1;
    }

    req->content.lmmsg.um_vtp_num = (i - total_num);

    return 0;
}

static int uvs_lm_vtp_table_lmmsg_copy(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req,
    lm_wait_sync_table_entry_t *lm_sync_entry)
{
    /* don't change the copy sequence */
    if (uvs_lm_for_rm_vtp_table(&fe_entry->rm_vtp_table, req, lm_sync_entry) != 0) {
        return -1;
    }
    if (uvs_lm_for_rc_vtp_table(&fe_entry->rc_vtp_table, req, lm_sync_entry) != 0) {
        return -1;
    }
    if (uvs_lm_for_um_vtp_table(&fe_entry->um_vtp_table, req, lm_sync_entry) != 0) {
        return -1;
    }

    return 0;
}

static int uvs_lm_vtp_table_iterative_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req,
    lm_wait_sync_table_entry_t *lm_sync_entry)
{
    int ret;
    struct timespec time_end = {0};
    struct timespec time_start = fe_entry->time_start;

    ret = clock_gettime(CLOCK_REALTIME, &time_end);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to clock_gettime in live migrate.\n");
        return ret;
    }

    long time_value = (time_end.tv_sec - time_start.tv_sec) * CLOCK_SEC_TO_NSEC +
                      (time_end.tv_nsec - time_start.tv_nsec);
    /* Start the timer and scan every 100ms */
    if (time_value >= CLOCK_TIME_OUT_NSEC) {
        ret = uvs_lm_vtp_table_lmmsg_copy(fe_entry, req, lm_sync_entry);
        if (ret != 0) {
            TPSA_LOG_ERR("live migrate message copy failed, when full_migrate is false.\n");
            return ret;
        }
        ret = clock_gettime(CLOCK_REALTIME, &fe_entry->time_start);
        if (ret != 0) {
            TPSA_LOG_ERR("Failed to clock_gettime for time_start in live migrate.\n");
            return ret;
        }
    }

    return 0;
}

static int uvs_lm_vtp_table_full_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req,
    lm_wait_sync_table_entry_t *lm_sync_entry)
{
    int ret;

    ret = uvs_lm_vtp_table_lmmsg_copy(fe_entry, req, lm_sync_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("live migrate message copy failed.\n");
        return ret;
    }

    fe_entry->full_migrate = false;
    ret = clock_gettime(CLOCK_REALTIME, &fe_entry->time_start);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to clock_gettime in live migrate.\n");
        return ret;
    }

    return 0;
}

int uvs_lm_send_mig_req(uvs_ctx_t *ctx, live_migrate_table_entry_t *cur, fe_table_entry_t *fe_entry)
{
    lm_wait_sync_table_entry_t *lm_sync_entry = NULL;
    tpsa_vtp_table_index_t vtp_idx = {0};
    tpsa_sock_msg_t *req = NULL;
    int ret;

    req = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        return -ENOMEM;
    }
    req->content.lmmsg.fe_idx = cur->key.fe_idx;
    req->content.lmmsg.stop_proc_vtp = fe_entry->stop_proc_vtp;
    (void)memcpy(req->content.lmmsg.dev_name, fe_entry->key.tpf_name, UVS_MAX_DEV_NAME);

    ret = vport_set_lm_location(&ctx->table_ctx->vport_table, &fe_entry->key, LM_SOURCE);
    if (ret != 0) {
        TPSA_LOG_ERR("Fail to set lm vport entry location in migrate source.\n");
        goto free_live_migrate;
    }

    ret = tpsa_get_vtp_idx(fe_entry->key.fe_idx, fe_entry->key.tpf_name, sizeof(fe_entry->key.tpf_name),
                           &vtp_idx, ctx->table_ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to get vtp idx to find peer tpsa address.\n");
        goto free_live_migrate;
    }
    req->upi = vtp_idx.upi;
    req->local_eid = vtp_idx.local_eid;

    lm_sync_entry = lm_wait_sync_table_lookup(&ctx->table_ctx->live_migrate_table, &cur->key);
    if (fe_entry->full_migrate == true) {
        /* Start full migration */
        ret = uvs_lm_vtp_table_full_migrate(fe_entry, req, lm_sync_entry);
    } else {
        ret = uvs_lm_vtp_table_iterative_migrate(fe_entry, req, lm_sync_entry);
    }

    /* If there are no vtp_entries for migration, there is no need to send a message to the migration destination. */
    if (req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num + req->content.lmmsg.um_vtp_num == 0) {
        ret = 0;
        goto free_live_migrate;
    }

    if (ret != 0) {
        TPSA_LOG_ERR("Fail to copy vtp table to live migrate request");
        goto free_live_migrate;
    }
    req->msg_type = TPSA_LM_MIG_REQ;
    req->content.lmmsg.src_uvs_ip = ctx->tpsa_attr.server_ip;
    if (tpsa_sock_send_msg(ctx->sock_ctx, req, sizeof(tpsa_sock_msg_t), cur->uvs_ip) != 0) {
        TPSA_LOG_ERR("Failed to send live migrate message\n");
        ret = -1;
        goto free_live_migrate;
    }

    ret = 0;

free_live_migrate:
    free(req);
    return ret;
}

static int uvs_lm_init_last_mig_req(tpsa_nl_function_mig_req_t *nlreq, tpsa_sock_msg_t *req, fe_table_entry_t *entry,
    uvs_ctx_t *ctx)
{
    tpsa_vtp_table_index_t vtp_idx;

    (void)memset(&vtp_idx, 0, sizeof(vtp_idx));
    req->msg_type = TPSA_LM_MIG_REQ;
    req->content.lmmsg.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(req->content.lmmsg.dev_name, nlreq->dev_name, UVS_MAX_DEV_NAME);
    req->content.lmmsg.stop_proc_vtp = entry->stop_proc_vtp;
    req->content.lmmsg.src_uvs_ip = ctx->tpsa_attr.server_ip;
    if (tpsa_get_vtp_idx(nlreq->mig_fe_idx, nlreq->dev_name, UVS_MAX_DEV_NAME, &vtp_idx, ctx->table_ctx) < 0) {
        TPSA_LOG_INFO("Fail to get vtp idx in init last mig req.\n");
        return 0;
    }
    req->peer_eid = vtp_idx.local_eid;

    lm_wait_sync_table_entry_t *lm_sync_entry =
        lm_wait_sync_table_lookup(&ctx->table_ctx->live_migrate_table, &entry->key);
    if (uvs_lm_vtp_table_lmmsg_copy(entry, req, lm_sync_entry) < 0) {
        TPSA_LOG_ERR("live migrate message copy failed, when handle stop process vtp msg.\n");
        return -1;
    }

    return 0;
}

int uvs_lm_handle_stop_proc_vtp_msg(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    vport_key_t key = {0};
    int ret;

    TPSA_LOG_INFO("lm initiator handle stop process vtp message, fe_idx is %u:%s", nlreq->mig_fe_idx, nlreq->dev_name);
    key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(key.tpf_name, nlreq->dev_name, UVS_MAX_DEV_NAME);

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
    fe_table_entry_t *entry = fe_table_lookup(&ctx->table_ctx->fe_table, &key);
    if (entry == NULL) {
        TPSA_LOG_ERR("Can't find fe entry in fe table in uvs_lm_handle_stop_proc_vtp_msg");
        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
        return -1;
    }
    (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
    entry->stop_proc_vtp = true;

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->live_migrate_table.rwlock);
    live_migrate_table_entry_t *lm_entry = live_migrate_table_lookup(&ctx->table_ctx->live_migrate_table, &key);
    if (lm_entry == NULL) {
        TPSA_LOG_ERR("can not find live_migrate by key fe_idx %hu\n", key.fe_idx);
        (void)pthread_rwlock_unlock(&ctx->table_ctx->live_migrate_table.rwlock);
        return -1;
    }
    (void)pthread_rwlock_unlock(&ctx->table_ctx->live_migrate_table.rwlock);
    /* When the migration source receives a stop processing link building requests(TPSA_MSG_STOP_PROC_VTP_MSG),
     * Synchronize the vtp table to the migration destination for the last time
    */
    tpsa_sock_msg_t *req = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        return -ENOMEM;
    }

    vport_table_entry_t vport_entry;
    ret = tpsa_lookup_vport_table(&entry->key, &ctx->table_ctx->vport_table, &vport_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("live migrate tpsa_lookup_vport_table failed, when handle stop process vtp msg.\n");
        goto free_and_ret;
    }
    req->local_eid = vport_entry.ueid[0].eid;
    req->upi = vport_entry.ueid[0].upi;

    ret = uvs_lm_init_last_mig_req(nlreq, req, entry, ctx);
    if (ret < 0) {
        TPSA_LOG_ERR("Failed to init last mig req\n");
        goto free_and_ret;
    }
    ret = tpsa_sock_send_msg(ctx->sock_ctx, req, sizeof(tpsa_sock_msg_t), lm_entry->uvs_ip);

    TPSA_LOG_INFO("Success to synchronize the vtp entries from src_migration to dst_migration.\n");
free_and_ret:
    free(req);
    return ret;
}

int uvs_lm_start_transfer_create_msg(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, vport_key_t *key)
{
    /* lookup destination node tpsa address and send msg */
    live_migrate_table_entry_t *lm_entry = live_migrate_table_lookup(&ctx->table_ctx->live_migrate_table, key);
    if (lm_entry == NULL) {
        TPSA_LOG_WARN("Can't find lm entry in live migrate table, send transfer msg failed");
        return TPSA_LOOKUP_NULL;
    }

    msg->msg_type = TPSA_LM_TRANSFER;
    msg->live_migrate = true;

    if (tpsa_sock_send_msg(ctx->sock_ctx, msg, sizeof(tpsa_sock_msg_t), lm_entry->uvs_ip) < 0) {
        TPSA_LOG_ERR("Failed to send transfer msg\n");
        return -1;
    }

    return 0;
}

static void uvs_init_rc_vtp_cfg(uint16_t fe_idx, rc_vtp_table_entry_t *vtp_entry, tpsa_vtp_cfg_flag_t vtp_flag,
    tpsa_vtp_cfg_t *vtp_cfg)
{
    vtp_cfg->fe_idx = fe_idx;
    vtp_cfg->vtpn = vtp_entry->vtpn;
    vtp_cfg->local_jetty = vtp_entry->src_jetty_id;
    vtp_cfg->local_eid = vtp_entry->src_eid;
    vtp_cfg->peer_eid = vtp_entry->key.dst_eid;
    vtp_cfg->peer_jetty = vtp_entry->key.jetty_id;
    vtp_cfg->flag = vtp_flag;
    vtp_cfg->trans_mode = TPSA_TP_RC;
    vtp_cfg->number.tpgn = vtp_entry->vice_tpgn;
}

static int uvs_rc_vtp_modify_to_vice_tpg(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret = -1;
    sip_table_entry_t sip_entry = { 0 };
    tpsa_vtp_cfg_flag_t vtp_flag;
    vtp_flag.bs.clan_tp = 0;
    vtp_flag.bs.migrate = 1;
    vtp_flag.bs.reserve = 0;

    tpsa_vtp_cfg_t vtp_cfg;
    uint32_t vice_tpgn;
    rc_vtp_table_entry_t *vtp_entry = lm_vtp_entry->content.rc_entry;
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("vtp entry is null when modify to vice tpg in rc mode.\n");
        return -1;
    }
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to create vport entry in rc mode");
        return -1;
    }

    if (vport_table_lookup_by_ueid(&ctx->table_ctx->vport_table, vtp_entry->upi,
                                   &vtp_entry->src_eid, vport_entry) != 0) {
        TPSA_LOG_ERR("Fail to lookup vport when switch rc link.\n");
        ret = -1;
        goto free_vport_entry;
    }
    if (tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_entry->key.tpf_name, vport_entry->sip_idx,
        &sip_entry) != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf name %s and sip_idx %u\n",
            vport_entry->key.tpf_name, vport_entry->sip_idx);
        ret = -1;
        goto free_vport_entry;
    }

    uvs_init_rc_vtp_cfg(vport_entry->key.fe_idx, vtp_entry, vtp_flag, &vtp_cfg);
    if (uvs_ioctl_cmd_modify_vtp(ctx->ioctl_ctx, &vtp_cfg, &sip_entry.addr, vtp_entry->vice_tpgn) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify vtp for rc mode.\n");
        ret = -1;
        goto free_vport_entry;
    }

    /* Exchange tpg and vice_tpg in the vtp table, in rc tpg table, swap the tpn and vice_tpn. */
    vice_tpgn = UINT32_MAX;
    ret = tpsa_rc_tpg_swap(ctx->table_ctx, &vice_tpgn, lm_vtp_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("tpg swap failed in rc tpg and rc vtp table.\n");
        goto free_vport_entry;
    }

    ret = 0;

free_vport_entry:
    free(vport_entry);
    return ret;
}

static int uvs_rm_vtp_modify_to_vice_tpg(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret = -1;
    sip_table_entry_t sip_entry = { 0 };
    tpsa_vtp_cfg_flag_t vtp_flag;
    vtp_flag.bs.clan_tp = 0;
    vtp_flag.bs.migrate = 1;
    vtp_flag.bs.reserve = 0;

    tpsa_vtp_cfg_t vtp_cfg;
    uint32_t vice_tpgn;
    rm_vtp_table_entry_t *vtp_entry = lm_vtp_entry->content.rm_entry;
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("vtp entry is null when modify to vice tpg in rm mode.\n");
        return -1;
    }
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to create vport entry");
        return -1;
    }

    urma_eid_t src_eid = vtp_entry->key.src_eid;
    if (vport_table_lookup_by_ueid(&ctx->table_ctx->vport_table, vtp_entry->upi, &src_eid, vport_entry) != 0) {
        TPSA_LOG_ERR("Fail to lookup vport when switch rm link.\n");
        goto free_vport_entry;
    }
    if (tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_entry->key.tpf_name,
        vport_entry->sip_idx, &sip_entry) != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf name %s and sip_idx %u\n",
            vport_entry->key.tpf_name, vport_entry->sip_idx);
        goto free_vport_entry;
    }

    vtp_cfg.fe_idx = vport_entry->key.fe_idx;
    vtp_cfg.vtpn = vtp_entry->vtpn;
    vtp_cfg.local_jetty = vtp_entry->src_jetty_id;
    vtp_cfg.local_eid = vtp_entry->key.src_eid;
    vtp_cfg.peer_eid = vtp_entry->key.dst_eid;
    vtp_cfg.peer_jetty = UINT32_MAX;
    vtp_cfg.flag = vtp_flag;
    vtp_cfg.trans_mode = TPSA_TP_RM;
    vtp_cfg.number.tpgn = vtp_entry->vice_tpgn;

    if (uvs_ioctl_cmd_modify_vtp(ctx->ioctl_ctx, &vtp_cfg, &sip_entry.addr, vtp_entry->vice_tpgn) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify vtp for rm mode.\n");
        goto free_vport_entry;
    }

    /* Exchange tpg and vice_tpg in the vtp table. */
    vice_tpgn = UINT32_MAX;
    ret = tpsa_rm_vtp_tpgn_swap(&vice_tpgn, lm_vtp_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("tpg swap failed in rm tpg and rc vtp table.\n");
        goto free_vport_entry;
    }

    ret = 0;

free_vport_entry:
    free(vport_entry);
    return ret;
}

static int uvs_lm_modify_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, sip_table_entry_t *sip_entry,
    vport_table_entry_t *vport_entry, um_vtp_table_entry_t *vtp_entry,  uint32_t vice_utp)
{
    tpsa_vtp_cfg_flag_t vtp_flag;
    vtp_flag.bs.clan_tp = 0;
    vtp_flag.bs.migrate = 1;
    vtp_flag.bs.reserve = 0;
    tpsa_vtp_cfg_t vtp_cfg;
    vtp_cfg.fe_idx = vport_entry->key.fe_idx;
    vtp_cfg.vtpn = vtp_entry->vtpn;
    vtp_cfg.local_jetty = UINT32_MAX;
    vtp_cfg.local_eid = vtp_entry->key.src_eid;
    vtp_cfg.peer_eid = vtp_entry->key.dst_eid;
    vtp_cfg.peer_jetty = UINT32_MAX;
    vtp_cfg.flag = vtp_flag;
    vtp_cfg.trans_mode = TPSA_TP_UM;
    vtp_cfg.number.utpn = vice_utp;

    if (uvs_ioctl_cmd_modify_vtp(ioctl_ctx, &vtp_cfg, &sip_entry->addr, vice_utp) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify vtp");
        return -1;
    }

    return 0;
}

static int uvs_um_create_new_commu_channel(uvs_ctx_t *ctx, sip_table_entry_t *sip_entry,
    vport_table_entry_t *vport_entry, um_vtp_table_entry_t *vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    utp_table_key_t utp_key = {
        .sip = sip_entry->addr,
        .dip = tp_msg_ctx->src.ip,
    };
    int ret;
    uint32_t utpn;

    utp_table_entry_t *utp_table_entry = utp_table_lookup(&ctx->table_ctx->utp_table, &utp_key);
    if (utp_table_entry != NULL) {
        /* There is available utp for direct reuse, modify vtp and return success. */
        utp_table_entry->use_cnt++;
        ret = uvs_lm_modify_vtp(ctx->ioctl_ctx, sip_entry, vport_entry, vtp_entry, utp_table_entry->utp_idx);
        if (ret < 0) {
            utp_table_entry->use_cnt--;
            TPSA_LOG_ERR("Fail to modify vtp for reuse utp.\n");
        }
        return ret;
    }
    /* There is no available utp and create a new utp, and modify vtp to switch the communication channel. */
    tpsa_ioctl_cfg_t *cfg = (tpsa_ioctl_cfg_t *)calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create tpg request");
        return -1;
    }
    vport_param_t vport_param = { 0 };
    tpsa_fill_vport_param(vport_entry, &vport_param);

    bool clan = uvs_is_clan_domain(ctx, &vport_entry->key, &vport_param, &utp_key.sip, &utp_key.dip);
    tpsa_lm_ioctl_cmd_create_utp(cfg, &vport_param, sip_entry, &utp_key, clan);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to create utp in live migration");
        ret = -1;
        goto free_ioctl_cfg;
    }
    utpn = cfg->cmd.create_utp.out.idx;
    ret = utp_table_add(&ctx->table_ctx->utp_table, &utp_key, utpn);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to add utp_table in um link rebuild");
        goto destroy_utp;
    }
    /* Call the function modify_vtp to complete the communication channel switching */
    ret = uvs_lm_modify_vtp(ctx->ioctl_ctx, sip_entry, vport_entry, vtp_entry, utpn);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to modify vtp when rebuild um link");
        goto remove_utp_table;
    }

    free(cfg);
    return 0;

remove_utp_table:
    (void)utp_table_remove(&ctx->table_ctx->utp_table, &utp_key);
destroy_utp:
    uvs_destroy_utp(ctx->ioctl_ctx, ctx->table_ctx, &utp_key, utpn);
free_ioctl_cfg:
    free(cfg);
    return ret;
}

/*
 * in um mode, when a management plane message arrives:
 * 1.UTP used for communicate between the third-party node and the src_migration, the reference count is reduced by 1.
 * 2.Create the UTP used for communication between the third-party node and the migration destination.
 * 3.Call the function modify_vtp to complete the communication channel switching.
*/
static int uvs_lm_switch_utp(uvs_ctx_t *ctx, um_vtp_table_entry_t *vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = -1;
    sip_table_entry_t sip_entry = { 0 };
    utp_table_key_t utp_key;
    utp_table_entry_t *utp_table_entry;
    if (vtp_entry == NULL || tp_msg_ctx == NULL) {
        TPSA_LOG_ERR("vtp entry or tp_msg_ctx is null when modify to vice tpg in um mode.\n");
        return -1;
    }
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to create vport entry");
        return -1;
    }

    if (vport_table_lookup_by_ueid(&ctx->table_ctx->vport_table, vtp_entry->upi,
                                   &vtp_entry->key.src_eid, vport_entry) != 0) {
        TPSA_LOG_ERR("Fail to lookup vport when rebuild um link.\n");
        ret = -1;
        goto free_vport_entry;
    }
    if (tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, vport_entry->key.tpf_name, vport_entry->sip_idx,
        &sip_entry) != 0) {
        TPSA_LOG_ERR("Can not find sip by tpf name %s and sip_idx %u\n",
            vport_entry->key.tpf_name, vport_entry->sip_idx);
        ret = -1;
        goto free_vport_entry;
    }

    utp_key.sip = sip_entry.addr;
    utp_key.dip = tp_msg_ctx->dst.ip; /* dst.ip --> old dip */
    /* first, lookup the utp which used to communicate with the live migration source and decrement the use_cnt */
    utp_table_entry = utp_table_lookup(&ctx->table_ctx->utp_table, &utp_key);
    if (utp_table_entry != NULL) {
        utp_table_entry->use_cnt--;
    } else {
        TPSA_LOG_ERR("Link does not exist in um mode.\n");
        ret = -1;
        goto free_vport_entry;
    }

    /* Second, create a new UTP to communicate with the migration destination */
    ret = uvs_um_create_new_commu_channel(ctx, &sip_entry, vport_entry, vtp_entry, tp_msg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("for um mode, create new communition channel failed.\n");
        goto free_vport_entry;
    }
    /* upsate the status of the vtp node. */
    vtp_entry->node_status = STATE_MIGRATING;

    ret = 0;

free_vport_entry:
    free(vport_entry);
    return ret;
}

int uvs_lm_refresh_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
                       tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = -1;

    if (lm_vtp_entry->trans_mode == TPSA_TP_RM) {
        ret = uvs_rm_vtp_modify_to_vice_tpg(ctx, lm_vtp_entry);
    } else if (lm_vtp_entry->trans_mode == TPSA_TP_RC) {
        ret = uvs_rc_vtp_modify_to_vice_tpg(ctx, lm_vtp_entry);
    } else {
        ret = uvs_lm_switch_utp(ctx, lm_vtp_entry->content.um_entry, tp_msg_ctx);
    }

    return ret;
}

static int uvs_lm_get_tp_msg_ctx(uvs_ctx_t *ctx, tpsa_transport_mode_t trans_mode, vport_key_t *vport_key,
                                 uvs_tp_msg_ctx_t *tp_msg_ctx, uvs_lm_vtp_info_t *vtp_info)
{
    tp_msg_ctx->trans_type = TPSA_TRANSPORT_UB;
    tp_msg_ctx->trans_mode = trans_mode;
    tp_msg_ctx->upi = vtp_info->upi;

    tp_msg_ctx->vport_ctx.key = *vport_key;

    uint32_t eid_idx = 0;
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table,
                                              vtp_info->upi, &vtp_info->local_eid,
                                              vport_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport key lookup failed, upi:%u, eid:" EID_FMT "\n",
                      vtp_info->upi, EID_ARGS(vtp_info->local_eid));
        return -1;
    }

    int ret = tpsa_lookup_vport_param_with_eid_idx(vport_key, &ctx->table_ctx->vport_table, eid_idx,
        &tp_msg_ctx->vport_ctx.param, &tp_msg_ctx->lm_ctx);
    if (ret != 0) {
        TPSA_LOG_INFO("can't faind vport dev_name:%s, fe_idx:%d when clean lm vport\n",
            vport_key->tpf_name, vport_key->fe_idx);
        return ret;
    }
    sip_table_entry_t sip_entry = {0};

    ret = tpsa_sip_table_lookup(&ctx->table_ctx->tpf_dev_table, tp_msg_ctx->vport_ctx.key.tpf_name,
        tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry);
    if (ret != 0 && tp_msg_ctx->trans_type == TPSA_TRANSPORT_UB) {
        TPSA_LOG_ERR("Can not find sip by tpf name %s and sip_idx %u\n",
            tp_msg_ctx->vport_ctx.key.tpf_name, tp_msg_ctx->vport_ctx.param.sip_idx);
        return ret;
    }
    tp_msg_ctx->src.ip = sip_entry.addr;
    tp_msg_ctx->src.eid = vtp_info->local_eid;
    tp_msg_ctx->src.jetty_id = vtp_info->local_jetty;

    (void)tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, vtp_info->peer_eid, vtp_info->upi, &tp_msg_ctx->peer.uvs_ip,
        &tp_msg_ctx->dst.ip);
    tp_msg_ctx->dst.eid = vtp_info->peer_eid;
    tp_msg_ctx->dst.jetty_id = vtp_info->peer_jetty;
    tp_msg_ctx->ta_data.trans_type = TPSA_TRANSPORT_UB;

    return 0;
}

static void uvs_lm_cparam_init(tpsa_create_param_t *cparam, tpsa_lm_vtp_entry_t *vtp_entry,
                               uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_tpg_table_index_t *tpg_idx, bool sig_loop)
{
    cparam->trans_mode = vtp_entry->trans_mode;
    cparam->dip = tp_msg_ctx->dst.ip;
    cparam->local_eid = tpg_idx->local_eid;
    cparam->peer_eid = tpg_idx->peer_eid;
    cparam->local_jetty = tpg_idx->ljetty_id;
    cparam->peer_jetty = tpg_idx->djetty_id;
    cparam->eid_index = UINT32_MAX;
    cparam->upi = tpg_idx->upi;
    cparam->live_migrate = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->sig_loop = sig_loop;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
}

static tpsa_create_param_t *uvs_lm_init_delete_link_info(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *vtp_entry,
    uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_tpg_table_index_t *tpg_idx, tpsa_vtp_table_index_t *vtp_idx)
{
    bool isLoopback = false;
    bool sig_loop = false;
    tpsa_create_param_t *cparam;
    cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return NULL;
    }

    isLoopback = uvs_is_loopback(vtp_entry->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
    sig_loop = uvs_is_sig_loop(vtp_entry->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);

    /* init of tpg_idx and vtp_idx */
    if (vtp_entry->trans_mode == TPSA_TP_RM) {
        tpg_idx->local_eid = vtp_entry->content.rm_entry->key.src_eid;
        tpg_idx->peer_eid = vtp_entry->content.rm_entry->key.dst_eid;
        tpg_idx->ljetty_id = vtp_entry->content.rm_entry->src_jetty_id;
        tpg_idx->djetty_id = UINT32_MAX;
        tpg_idx->upi = vtp_entry->content.rm_entry->upi;

        vtp_idx->location =  vtp_entry->content.rm_entry->location;
        cparam->vtpn = vtp_entry->content.rm_entry->vtpn;
    } else {
        tpg_idx->local_eid = vtp_entry->content.rc_entry->src_eid;
        tpg_idx->peer_eid = vtp_entry->content.rc_entry->key.dst_eid;
        tpg_idx->ljetty_id = vtp_entry->content.rc_entry->src_jetty_id;
        tpg_idx->djetty_id = vtp_entry->content.rc_entry->key.jetty_id;
        tpg_idx->upi = vtp_entry->content.rc_entry->upi;

        vtp_idx->location =  vtp_entry->content.rc_entry->location;
        cparam->vtpn = vtp_entry->content.rc_entry->vtpn;
    }

    tpg_idx->dip = tp_msg_ctx->dst.ip;
    tpg_idx->peer_uvs_ip = tp_msg_ctx->peer.uvs_ip;
    tpg_idx->isLoopback = isLoopback;
    tpg_idx->sig_loop = sig_loop;
    tpg_idx->sip = tp_msg_ctx->src.ip;
    tpg_idx->tp_cnt = tp_msg_ctx->vport_ctx.param.tp_cnt;
    tpg_idx->trans_mode = vtp_entry->trans_mode;

    vtp_idx->local_eid = tpg_idx->local_eid;
    vtp_idx->peer_eid = tpg_idx->peer_eid;
    vtp_idx->local_jetty = tpg_idx->ljetty_id;
    vtp_idx->peer_jetty = tpg_idx->djetty_id;
    vtp_idx->upi = tpg_idx->upi;
    vtp_idx->isLoopback = isLoopback;
    vtp_idx->sig_loop = sig_loop;
    vtp_idx->trans_mode = tpg_idx->trans_mode;

    /* init of cparam */
    uvs_lm_cparam_init(cparam, vtp_entry, tp_msg_ctx, tpg_idx, sig_loop);

    return cparam;
}

/* Resource cleanup at the migration source */
static int uvs_lm_cleanup_resource_in_src(uvs_ctx_t *ctx, tpsa_vtp_table_index_t *vtp_idx,
    tpsa_tpg_table_index_t *tpg_idx, uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_create_param_t *cparam)
{
    int32_t vtpn = -1;
    int32_t tpgn = -1;
    int ret = -1;

    uvs_table_remove_vtp_tpg(&vtpn, &tpgn, tpg_idx, vtp_idx, ctx->table_ctx);
    ret = uvs_destroy_vtp_and_tpg(ctx, tp_msg_ctx, vtpn, tpgn, vtp_idx->location);
    if (ret < 0) {
        TPSA_LOG_ERR("destroy vtp or tpg faied when destroy resource in source.\n");
        return ret;
    }
    uvs_direction_t dirction =
        (vtp_idx->location == TPSA_INITIATOR ? TPSA_FROM_CLIENT_TO_SERVER : TPSA_FROM_SERVER_TO_CLIENT);
    if (!vtp_idx->isLoopback) {
        ret = tpsa_sock_send_destroy_req(ctx, tp_msg_ctx, dirction, NULL);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static int uvs_lm_cleanup_resource(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *vtp_entry,
    vport_key_t *vport_key, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_vtp_table_index_t vtp_idx;
    tpsa_tpg_table_index_t tpg_idx;
    bool isLoopback = false;
    int ret = 0;

    (void)memset(&vtp_idx, 0, sizeof(vtp_idx));
    (void)memset(&tpg_idx, 0, sizeof(tpg_idx));
    tpsa_create_param_t *cparam = uvs_lm_init_delete_link_info(ctx, vtp_entry, tp_msg_ctx, &tpg_idx, &vtp_idx);
    if (cparam == NULL) {
        TPSA_LOG_ERR("Cparam init failed when init link info.\n");
        return -1;
    }

    cparam->fe_idx = vport_key->fe_idx;
    vtp_idx.fe_key = *vport_key;
    (void)memcpy(cparam->tpf_name, vport_key->tpf_name, UVS_MAX_DEV_NAME);

    /* The vtp location is clent or server, which directly triggers deletion. */
    if (vtp_idx.location != TPSA_DUPLEX) {
        ret = uvs_lm_cleanup_resource_in_src(ctx, &vtp_idx, &tpg_idx, tp_msg_ctx, cparam);
        if (ret != 0) {
            TPSA_LOG_ERR("Client up resource failed when the vtp entry is target or initator.\n");
        }
        goto out;
    }
    /* If it is duplex and it is not a self-loopback scenario, deletion needs to be triggered twice. */
    isLoopback = uvs_is_loopback(vtp_entry->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
    vtp_idx.location = TPSA_INITIATOR;
    ret = uvs_lm_cleanup_resource_in_src(ctx, &vtp_idx, &tpg_idx, tp_msg_ctx, cparam);
    if (ret != 0) {
        TPSA_LOG_ERR("Client up resource failed when the vtp entry is initator.\n");
        goto out;
    }

    if (!isLoopback) {
        vtp_idx.location = TPSA_TARGET;
        ret = uvs_lm_cleanup_resource_in_src(ctx, &vtp_idx, &tpg_idx, tp_msg_ctx, cparam);
        if (ret != 0) {
            TPSA_LOG_ERR("Client up resource failed when the vtp entry is target.\n");
            goto out;
        }
    }

out:
    free(cparam);
    return ret;
}

static int uvs_lm_src_notify_third_restore(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx,
    uvs_lm_vtp_info_t *vtp_info)
{
    int ret = 0;
    tpsa_sock_msg_t *msg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (msg == NULL) {
        return -1;
    }

    msg->local_eid = vtp_info->local_eid;
    msg->peer_eid = vtp_info->peer_eid;
    msg->msg_type = TPSA_LM_NOTIFY_THIRD;
    msg->upi = vtp_info->upi;

    ret = tpsa_sock_send_msg(ctx->sock_ctx, msg, sizeof(tpsa_sock_msg_t), tp_msg_ctx->peer.uvs_ip);
    TPSA_LOG_INFO("Finish src notify third restore vtp, ret:%d.\n", ret);

    free(msg);
    return ret;
}

static int uvs_lm_cleanup_resource_for_rm(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry, vport_key_t *vport_key)
{
    rm_vtp_table_entry_t *vtp_cur, *vtp_next;
    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    int ret = 0;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &fe_entry->rm_vtp_table.hmap) {
        (void)memset(&tp_msg_ctx, 0, sizeof(uvs_tp_msg_ctx_t));
        tp_msg_ctx.trans_mode = TPSA_TP_RM;
        uvs_lm_vtp_info_t vtp_info = {
            .local_eid = vtp_cur->key.src_eid,
            .peer_eid = vtp_cur->key.dst_eid,
            .local_jetty = vtp_cur->src_jetty_id,
            .peer_jetty = UINT32_MAX,
            .upi = vtp_cur->upi,
        };
        tpsa_lm_vtp_entry_t vtp_entry = {
            .trans_mode = TPSA_TP_RM,
            .content = { .rm_entry = vtp_cur, },
        };
        ret = uvs_lm_get_tp_msg_ctx(ctx, TPSA_TP_RM, vport_key, &tp_msg_ctx, &vtp_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Tp msg ctx init failed when delete rm link.\n");
            return ret;
        }
        tp_msg_ctx.lm_ctx.location = LM_SOURCE;
        tp_msg_ctx.lm_ctx.is_rollback = false;
        ret = uvs_lm_cleanup_resource(ctx, &vtp_entry, vport_key, &tp_msg_ctx);
        if (ret != 0) {
            TPSA_LOG_ERR("Uvs cleanup resource failed for rm mode, %d.\n", ret);
            return ret;
        }
        if (uvs_lm_src_notify_third_restore(ctx, &tp_msg_ctx, &vtp_info) != 0) {
            TPSA_LOG_ERR("Fail to notify third node to restore vtp.\n");
        }
    }

    TPSA_LOG_INFO("Finish handle link delete for rm type. dev_name is %s, fe_idx is %u.\n",
                  fe_entry->key.tpf_name, fe_entry->key.fe_idx);
    return 0;
}

static int uvs_lm_cleanup_resource_for_rc(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry, vport_key_t *vport_key)
{
    rc_vtp_table_entry_t *vtp_cur, *vtp_next;
    uvs_tp_msg_ctx_t tp_msg_ctx;
    int ret = 0;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &fe_entry->rc_vtp_table.hmap) {
        (void)memset(&tp_msg_ctx, 0, sizeof(uvs_tp_msg_ctx_t));
        tp_msg_ctx.trans_mode = TPSA_TP_RC;
        uvs_lm_vtp_info_t vtp_info = {
            .local_eid = vtp_cur->src_eid,
            .peer_eid = vtp_cur->key.dst_eid,
            .local_jetty = vtp_cur->src_jetty_id,
            .peer_jetty = vtp_cur->key.jetty_id,
            .upi = vtp_cur->upi,
        };
        ret = uvs_lm_get_tp_msg_ctx(ctx, TPSA_TP_RC, vport_key, &tp_msg_ctx, &vtp_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Tp msg ctx init failed when delete rc link.\n");
            return ret;
        }
        tpsa_lm_vtp_entry_t vtp_entry = {
            .trans_mode = TPSA_TP_RC,
            .content = { .rc_entry = vtp_cur, },
        };
        ret = uvs_lm_cleanup_resource(ctx, &vtp_entry, vport_key, &tp_msg_ctx);
        if (ret != 0) {
            TPSA_LOG_ERR("Uvs cleanup resource failed for rc mode, %d.\n", ret);
            return ret;
        }
    }

    TPSA_LOG_INFO("Finish handle link delete for rc type. dev_name is %s, fe_idx is %u.\n",
                  fe_entry->key.tpf_name, fe_entry->key.fe_idx);
    return 0;
}

static int uvs_lm_cleanup_resource_for_um(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry, vport_key_t *vport_key)
{
    um_vtp_table_entry_t *vtp_cur, *vtp_next;
    uvs_tp_msg_ctx_t tp_msg_ctx;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &fe_entry->um_vtp_table.hmap) {
        uvs_lm_vtp_info_t vtp_info = {
            .local_eid = vtp_cur->key.src_eid,
            .peer_eid = vtp_cur->key.dst_eid,
            .local_jetty = UINT32_MAX,
            .peer_jetty = UINT32_MAX,
            .upi = vtp_cur->upi,
        };
        (void)memset(&tp_msg_ctx, 0, sizeof(uvs_tp_msg_ctx_t));
        int ret = uvs_lm_get_tp_msg_ctx(ctx, TPSA_TP_UM, vport_key, &tp_msg_ctx, &vtp_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Tp msg ctx init failed when delete rc link.\n");
            return ret;
        }
        tp_msg_ctx.lm_ctx.location = LM_SOURCE;
        tp_msg_ctx.lm_ctx.is_rollback = false;
        ret = uvs_destroy_um_vtp(ctx, &tp_msg_ctx);
        if (ret != 0) {
            TPSA_LOG_ERR("Destroy um vtp failed in um link delete.\n");
            return ret;
        }
    }

    return 0;
}

void uvs_lm_clean_vport(uvs_ctx_t *ctx, vport_key_t *vport_key)
{
    int ret = 0;
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, vport_key);
    if (fe_entry == NULL) {
        return;
    }

    if (fe_entry->rm_vtp_table.hmap.count != 0) {
        ret = uvs_lm_cleanup_resource_for_rm(ctx, fe_entry, vport_key);
    }
    if (fe_entry->rc_vtp_table.hmap.count != 0) {
        ret = uvs_lm_cleanup_resource_for_rc(ctx, fe_entry, vport_key);
    }
    if (fe_entry->um_vtp_table.hmap.count != 0) {
        ret = uvs_lm_cleanup_resource_for_um(ctx, fe_entry, vport_key);
    }

    if (ret != 0) {
        TPSA_LOG_ERR("rm clean vport failed dev_name:%s:%d.\n", vport_key->tpf_name, vport_key->fe_idx);
    }

    if (live_migrate_table_remove(&ctx->table_ctx->live_migrate_table, vport_key) != 0) {
        TPSA_LOG_ERR("can not del live_migrate by key fe_idx %hu, dev_name:%s\n",
            vport_key->fe_idx, vport_key->tpf_name);
    } else {
        TPSA_LOG_INFO("success remove live migrate table, fe_key is %hu, dev_name is %s.\n",
            vport_key->fe_idx, vport_key->tpf_name);
    }
    return;
}

void uvs_lm_restore_vtp_status(fe_table_entry_t *fe_entry)
{
    rm_vtp_table_t *rm_vtp_table = NULL;
    rc_vtp_table_t *rc_vtp_table = NULL;
    um_vtp_table_t *um_vtp_table = NULL;

    /* restore rm vtp status */
    rm_vtp_table_entry_t *cur_rm, *next_rm;
    rm_vtp_table = &fe_entry->rm_vtp_table;
    HMAP_FOR_EACH_SAFE(cur_rm, next_rm, node, &rm_vtp_table->hmap) {
        cur_rm->migration_status = false;
        cur_rm->node_status = STATE_NORMAL;
    }
    /* restore rc vtp status */
    rc_vtp_table_entry_t *cur_rc, *next_rc;
    rc_vtp_table = &fe_entry->rc_vtp_table;
    HMAP_FOR_EACH_SAFE(cur_rc, next_rc, node, &rc_vtp_table->hmap) {
        cur_rc->migration_status = false;
        cur_rc->node_status = STATE_NORMAL;
    }
    /* restore um vtp status */
    um_vtp_table_entry_t *cur_um, *next_um;
    um_vtp_table = &fe_entry->um_vtp_table;
    HMAP_FOR_EACH_SAFE(cur_um, next_um, node, &um_vtp_table->hmap) {
        cur_um->migration_status = false;
        cur_um->node_status = STATE_NORMAL;
    }
    TPSA_LOG_INFO("Success restore all vtp entry\n");
    return;
}

int uvs_lm_rollback_process(tpsa_table_t *table_ctx, uvs_ueid_t *dueid, vport_key_t *vport_key)
{
    TPSA_LOG_INFO("Start to hanlde rollback event from gaea.\n");
    if (live_migrate_table_remove(&table_ctx->live_migrate_table, vport_key) != 0) {
        // only key is not exist
        return -1;
    }

    (void)pthread_rwlock_wrlock(&table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&table_ctx->fe_table, vport_key);
    if (fe_entry == NULL) {
        (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
        TPSA_LOG_ERR("Can not find fe entry by fe_idx[%u], tpf_name[%s].\n", vport_key->fe_idx, vport_key->tpf_name);
        return 0;
    }
    uvs_lm_restore_vtp_status(fe_entry);
    fe_entry->stop_proc_vtp = false;
    (void)pthread_rwlock_unlock(&table_ctx->fe_table.rwlock);
    return 0;
}

int uvs_lm_handle_rm_dst_rollback_delete(uvs_ctx_t *ctx, rm_vtp_table_entry_t *rm_entry,
    uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_vtp_cfg_t *vtp_cfg)
{
    tpsa_tpg_info_t find_tpg_info = {0};
    uint32_t location = TPSA_TARGET;
    int tpgn = -1;
    int vtpn = -1;
    int ret = 0;

    if (tp_msg_ctx->lm_ctx.direction == TPSA_FROM_SERVER_TO_CLIENT) {
        location = TPSA_INITIATOR;
    }
    if (rm_entry->node_status == STATE_MIGRATING) {
        // first we need to swap to lm source, then we delete tpgn
        tpsa_lm_vtp_entry_t lm_entry;
        lm_entry.trans_mode = TPSA_TP_RM;
        lm_entry.content.rm_entry = rm_entry;
        ret = uvs_rm_vtp_modify_to_vice_tpg(ctx, &lm_entry);
        if (ret != 0) {
            TPSA_LOG_ERR("Fail to swap tpg when rollback.\n");
            return -1;
        }
    }

    tpgn = rm_entry->vice_tpgn;
    // vice tpgn is lm dest, tpgn is lm source
    if (rm_entry->share_mode) {
        rm_tpg_table_key_t key = {
            .sip = tp_msg_ctx->src.ip.net_addr,
            .dip = tp_msg_ctx->dst.ip.net_addr,
        };
        ret = tpsa_remove_rm_tpg_table(&ctx->table_ctx->rm_tpg_table, &key, &find_tpg_info);
        if (ret != 0) {
            TPSA_LOG_INFO("Tpgn is null or still in use.\n");
            return 0;
        }
    } else {
        if (rm_entry->vice_use_cnt > 0) {
            rm_entry->vice_use_cnt -= 1;
        }
        TPSA_LOG_INFO("Current non_share mode use count:%u.\n", rm_entry->vice_use_cnt);
        if (rm_entry->vice_use_cnt != 0) {
            return 0;
        }
        tpg_state_table_key_t tpg_state_key = {.tpgn = (uint32_t)tpgn, .sip = tp_msg_ctx->src.ip.net_addr};
        ret = tpg_state_find_tpg_info(&ctx->table_ctx->tpg_state_table, &tpg_state_key, &find_tpg_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Fail to find tpg state when dst normal delete.\n");
            return -1;
        }
        TPSA_LOG_INFO("detect non_share_mode and deleting tpgn = %u and tp_cnt = %u, ret = %u\n",
            find_tpg_info.tpgn, find_tpg_info.tp_cnt, ret);
    }
    tpgn = find_tpg_info.tpgn;

    if (uvs_destroy_vtp_and_tpg(ctx, tp_msg_ctx, vtpn, tpgn, location) < 0) {
        TPSA_LOG_ERR("destroy tpg failed when rollback.\n");
        return -1;
    }
    // restore vtp entry status
    rm_entry->node_status = STATE_NORMAL;
    rm_entry->vice_tpgn = UINT32_MAX;
    rm_entry->migration_status = false;
    TPSA_LOG_INFO("Success destroy vice tpgn:%u, location:%u when dst rollback.\n", tpgn, location);

    return 0;
}

static void uvs_lm_clear_dst_delete_vtp(uvs_ctx_t *ctx, rm_vtp_table_entry_t *rm_entry,
    uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    deid_vtp_table_key_t deid_key = {
        .dst_eid = rm_entry->key.dst_eid,
        .upi = rm_entry->upi,
        .trans_mode = TPSA_TP_RM,
    };
    deid_rm_vtp_list_remove(&ctx->table_ctx->deid_vtp_table, &deid_key, &rm_entry->key);

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &tp_msg_ctx->vport_ctx.key);
    if (fe_entry == NULL) {
        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
        TPSA_LOG_WARN("Fail to look up fe entry by tpf_name[%s], fe_idx[%u].\n",
            tp_msg_ctx->vport_ctx.key.tpf_name, tp_msg_ctx->vport_ctx.key.fe_idx);
        return;
    }
    ub_hmap_remove(&fe_entry->rm_vtp_table.hmap, &rm_entry->node);
    (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
    free(rm_entry);
}

int uvs_lm_handle_rm_dst_normal_delete(uvs_ctx_t *ctx, rm_vtp_table_entry_t *rm_entry,
    uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_vtp_cfg_t *vtp_cfg)
{
    tpsa_tpg_info_t find_tpg_info = {0};
    uint32_t location = TPSA_TARGET;
    bool isdelete = true; // whether to remove vtpn entry
    int tpgn = -1;
    int vtpn = -1;
    int ret = 0;

    if (tp_msg_ctx->lm_ctx.direction == TPSA_FROM_SERVER_TO_CLIENT) {
        location = TPSA_INITIATOR;
    }

    tpgn = (rm_entry->node_status == STATE_MIGRATING ? rm_entry->tpgn : rm_entry->vice_tpgn);

    if (rm_entry->vice_location == TPSA_DUPLEX) {
        rm_entry->vice_location = (location == TPSA_INITIATOR ? TPSA_TARGET : TPSA_INITIATOR);
        isdelete = false;
    }

    vtpn = (location == TPSA_INITIATOR ? rm_entry->vtpn : UINT32_MAX);

    if (rm_entry->share_mode) {
        rm_tpg_table_key_t key = {
            .sip = tp_msg_ctx->src.ip.net_addr,
            .dip = tp_msg_ctx->dst.ip.net_addr,
        };
        ret = tpsa_remove_rm_tpg_table(&ctx->table_ctx->rm_tpg_table, &key, &find_tpg_info);
        if (ret == TPSA_REMOVE_NULL) {
            TPSA_LOG_INFO("Tpgn is null or still in use.\n");
            return -1;
        } else if (ret == TPSA_REMOVE_DUPLICATE) {
            tpgn = -1;
            goto remove_vtp;
        }
    } else {
        if (rm_entry->vice_use_cnt > 0) {
            rm_entry->vice_use_cnt -= 1;
        }
        TPSA_LOG_INFO("Current non_share mode use count:%u.\n", rm_entry->vice_use_cnt);
        if (rm_entry->vice_use_cnt != 0) {
            tpgn = -1;
            goto remove_vtp;
        }
        tpg_state_table_key_t tpg_state_key = {.tpgn = (uint32_t)tpgn, .sip = tp_msg_ctx->src.ip.net_addr};
        ret = tpg_state_find_tpg_info(&ctx->table_ctx->tpg_state_table, &tpg_state_key, &find_tpg_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Fail to find tpg state when dst normal delete.\n");
            return -1;
        }
        TPSA_LOG_INFO("detect non_share_mode and deleting tpgn = %u and tp_cnt = %u, ret = %u\n",
            find_tpg_info.tpgn, find_tpg_info.tp_cnt, ret);
    }
    tpgn = find_tpg_info.tpgn;

remove_vtp:
    if (uvs_destroy_vtp_and_tpg(ctx, tp_msg_ctx, vtpn, tpgn, location) < 0) {
        TPSA_LOG_ERR("destroy tpg failed when rollback.\n");
        return -1;
    }

    if (isdelete) {
        uvs_lm_clear_dst_delete_vtp(ctx, rm_entry, tp_msg_ctx);
    }

    TPSA_LOG_INFO("Suceess destroy dst tpgn:%u, location:%u when src delete.\n", tpgn, location);

    return 0;
}

int uvs_lm_handle_rm_src_normal_delete(uvs_ctx_t *ctx, rm_vtp_table_entry_t *rm_entry,
    uvs_tp_msg_ctx_t *tp_msg_ctx, tpsa_vtp_cfg_t *vtp_cfg)
{
    tpsa_tpg_info_t find_tpg_info = {0};
    uint32_t location = TPSA_TARGET;
    int tpgn = -1;
    int vtpn = -1;
    int ret = 0;

    if (tp_msg_ctx->lm_ctx.direction == TPSA_FROM_SERVER_TO_CLIENT) {
        location = TPSA_INITIATOR;
    }
    tpgn = (rm_entry->node_status == STATE_MIGRATING ? rm_entry->vice_tpgn : rm_entry->tpgn);

    if (rm_entry->location == TPSA_DUPLEX) {
        rm_entry->location = (location == TPSA_INITIATOR ? TPSA_TARGET : TPSA_INITIATOR);
    }

    if (rm_entry->share_mode) {
        rm_tpg_table_key_t key = {
            .sip = tp_msg_ctx->src.ip.net_addr,
            .dip = tp_msg_ctx->dst.ip.net_addr,
        };
        ret = tpsa_remove_rm_tpg_table(&ctx->table_ctx->rm_tpg_table, &key, &find_tpg_info);
        if (ret != 0) {
            TPSA_LOG_INFO("Tpgn is null or still in use.\n");
            return -1;
        }
    } else {
        if (rm_entry->use_cnt > 0) {
            rm_entry->use_cnt -= 1;
        }
        TPSA_LOG_INFO("Current non_share mode use count:%u.\n", rm_entry->use_cnt);
        if (rm_entry->use_cnt != 0) {
            return 0;
        }
        tpg_state_table_key_t tpg_state_key = {.tpgn = (uint32_t)tpgn, .sip = tp_msg_ctx->src.ip.net_addr};
        ret = tpg_state_find_tpg_info(&ctx->table_ctx->tpg_state_table, &tpg_state_key, &find_tpg_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Fail to find tpg state when rollback.\n");
            return -1;
        }
        TPSA_LOG_INFO("detect non_share_mode and deleting tpgn = %u and tp_cnt = %u, ret = %u\n",
            find_tpg_info.tpgn, find_tpg_info.tp_cnt, ret);
    }
    tpgn = find_tpg_info.tpgn;

    if (uvs_destroy_vtp_and_tpg(ctx, tp_msg_ctx, vtpn, tpgn, location) < 0) {
        TPSA_LOG_ERR("destroy tpg failed when rollback.\n");
        return -1;
    }

    if (rm_entry->node_status == STATE_MIGRATING) {
        rm_entry->vice_tpgn = UINT32_MAX;
    } else {
        rm_entry->tpgn = UINT32_MAX;
    }

    TPSA_LOG_INFO("Suceess destroy src tpgn:%u, location:%u when src delete.\n", tpgn, location);
    return 0;
}

int uvs_lm_handle_dst_delete(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = 0;

    if (tp_msg_ctx->trans_mode != TPSA_TP_RM) {
        TPSA_LOG_ERR("For dst deletion unexpected trans_mode[%u].\n", tp_msg_ctx->trans_mode);
        return -1;
    }

    if (tp_msg_ctx->lm_ctx.is_rollback) {
        ret = uvs_lm_handle_rm_dst_rollback_delete(ctx, lm_vtp_entry->content.rm_entry, tp_msg_ctx, vtp_cfg);
    } else {
        ret = uvs_lm_handle_rm_dst_normal_delete(ctx, lm_vtp_entry->content.rm_entry, tp_msg_ctx, vtp_cfg);
    }

    if (ret != 0) {
        TPSA_LOG_ERR("Failed to handle dst delete.\n");
    }
    return ret;
}

int uvs_lm_handle_src_delete(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, vport_key_t *vport_key,
    tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = 0;
    if (tp_msg_ctx->lm_ctx.is_rollback) {
        TPSA_LOG_ERR("For src deletion rollback should not happen.\n");
        return -1;
    } else {
        if (lm_vtp_entry->trans_mode != TPSA_TP_RM) {
            TPSA_LOG_ERR("For src deletion unexpected trans_mode[%u].\n", lm_vtp_entry->trans_mode);
            return -1;
        }
        ret = uvs_lm_handle_rm_src_normal_delete(ctx, lm_vtp_entry->content.rm_entry, tp_msg_ctx, vtp_cfg);
    }

    if (ret != 0) {
        TPSA_LOG_ERR("Failed to handle src delete.\n");
    }
    return ret;
}

int uvs_lm_thrid_restore_vtp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    rm_vtp_table_entry_t *rm_entry = NULL;
    vport_key_t vport_key = {0};
    uint32_t eid_index;
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->peer_eid,
                                              &vport_key, &eid_index) < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key upi:%u eid " EID_FMT "\n", msg->upi, EID_ARGS(msg->peer_eid));
        return -1;
    }

    rm_vtp_table_key_t vtp_key = {
        .src_eid = msg->peer_eid,
        .dst_eid = msg->local_eid,
    };
    rm_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &vport_key, &vtp_key);
    if (rm_entry == NULL) {
        TPSA_LOG_ERR("Fail to find rm entry, src eid " EID_FMT ", dst eid " EID_FMT ".\n",
            EID_ARGS(vtp_key.src_eid), EID_ARGS(vtp_key.dst_eid));
        return -1;
    }
    rm_entry->migration_status = false;
    rm_entry->node_status = STATE_NORMAL;
    rm_entry->vice_tpgn = UINT32_MAX;
    rm_entry->location = rm_entry->vice_location;
    rm_entry->use_cnt = rm_entry->vice_use_cnt;

    TPSA_LOG_ERR("Success restore rm entry, src eid " EID_FMT ", dst eid " EID_FMT ".\n",
            EID_ARGS(vtp_key.src_eid), EID_ARGS(vtp_key.dst_eid));
    return 0;
}