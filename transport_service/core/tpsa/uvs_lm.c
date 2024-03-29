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

#include "uvs_lm.h"

static int uvs_response_migrate_fast(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx,
                                     tpsa_mig_resp_status_t status)
{
    /* NETLINK to response to UBCORE */
    tpsa_nl_msg_t *nlresp = tpsa_nl_mig_msg_resp_fast(msg, status);
    if (nlresp == NULL) {
        return -1;
    }

    if (tpsa_nl_send_msg(nl_ctx, nlresp) != 0) {
        free(nlresp);
        return -1;
    }

    free(nlresp);
    TPSA_LOG_INFO("Finish fast NETLINK response mig msg status to ubcore\n");

    return 0;
}

static void uvs_lm_init_tp_msg_ctx(vport_table_entry_t *vport_entry, uvs_end_point_t *src, uvs_end_point_t *dst,
                                   urma_eid_t *peer_tpsa_eid, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tpsa_fill_vport_param(vport_entry, &tp_msg_ctx->vport_ctx.param);
    tp_msg_ctx->vport_ctx.key = vport_entry->key;
    tp_msg_ctx->peer.tpsa_eid = *peer_tpsa_eid;
    tp_msg_ctx->src = *src;
    tp_msg_ctx->dst = *dst;
}

int uvs_lm_swap_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, char *dev_name, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    /* Lookup sip and vport entry */
    sip_table_entry_t sip_entry = {0};
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }
    vport_key_t vport_key = {0};
    vport_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(vport_key.dev_name, dev_name, TPSA_MAX_DEV_NAME);
    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %hu\n", vtp_cfg->fe_idx);
        free(vport_entry);
        return -1;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
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
                                 char *dev_name, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret = -1;

    ret = tpsa_vtp_node_status_change(STATE_ROLLBACK, lm_vtp_entry);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to change node status");
        return -1;
    }

    TPSA_LOG_INFO("Change node status to rollback when ready");
    return 0;
}

int uvs_lm_create_vtp(uvs_ctx_t *ctx, tpsa_create_param_t *cparam,
                      tpsa_net_addr_t *sip, vport_table_entry_t *vport_entry)
{
    urma_eid_t peer_tpsa_eid = {0};
    tpsa_net_addr_t dip;
    bool isLoopback = false;

    (void)memset(&dip, 0, sizeof(tpsa_net_addr_t));
    if (cparam->dip_valid) {
        dip = cparam->dip;
        peer_tpsa_eid = cparam->dip.eid;
    } else {
        tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid,
                              cparam->upi, &peer_tpsa_eid, &dip);
    }

    if (memcmp(sip, &dip, sizeof(tpsa_net_addr_t)) == 0) {
        isLoopback = true;
        if (memcmp(&cparam->local_eid, &cparam->peer_eid, sizeof(urma_eid_t)) == 0) {
            cparam->sig_loop = true;
        }

        if (cparam->dip_valid) {
            return 0;
        }
    }

    tpsa_tpg_table_index_t tpg_idx;
    (void)memset(&tpg_idx, 0, sizeof(tpsa_tpg_table_index_t));
    tpg_idx.dip = dip;
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
    uvs_end_point_t src = { *sip, cparam->local_eid, cparam->local_jetty };
    uvs_end_point_t dst = { dip, cparam->peer_eid, cparam->peer_jetty };
    uvs_tp_msg_ctx_t tp_msg_ctx = { 0 };
    uvs_lm_init_tp_msg_ctx(vport_entry, &src, &dst, &peer_tpsa_eid, &tp_msg_ctx);

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
    tpsa_net_addr_t dip;
    urma_eid_t peer_tpsa_eid = {0};

    (void)memset(&dip, 0, sizeof(tpsa_net_addr_t));
    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));

    cparam->trans_mode = TPSA_TP_RM;
    cparam->dip = lmdip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->live_migrate = true;
    cparam->dip_valid = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
    (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
    (void)memcpy(cparam->local_tpf_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
    cparam->mtu = sip_entry->mtu;

    uint32_t i = 0;
    for (; i < lmreq->rm_vtp_num; i++) {
        entry = &lmreq->total_vtp[i].content.rm_entry;
        if (entry == NULL) {
            TPSA_LOG_ERR("Fail to get rm entry when lm");
            free(cparam);
            return -1;
        }

        if (entry->location != TPSA_INITIATOR) {
            tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, entry->key.dst_eid,
                entry->upi, &peer_tpsa_eid, &dip);

            if (tpsa_notify_table_update(notify_table, &peer_tpsa_eid, entry, NULL) < 0) {
                TPSA_LOG_ERR("Fail to add tpsa noti table(RM) when handle lm target");
                free(cparam);
                return -1;
            }

            if (entry->location == TPSA_TARGET) {
                continue;
            }
        }

        cparam->local_eid = entry->key.src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->local_jetty = entry->src_jetty_id;
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;
        cparam->sig_loop = false;
        cparam->upi = vport_entry->ueid[entry->eid_index].upi;

        if (uvs_lm_create_vtp(ctx, cparam, &sip_entry->addr, vport_entry) < 0) {
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
    tpsa_net_addr_t dip;
    urma_eid_t peer_tpsa_eid = {0};

    (void)memset(&dip, 0, sizeof(tpsa_net_addr_t));
    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));

    cparam->trans_mode = TPSA_TP_RC;
    cparam->dip = lmdip;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->live_migrate = true;
    cparam->dip_valid = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
    (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
    (void)memcpy(cparam->local_tpf_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
    cparam->mtu = sip_entry->mtu;

    uint32_t i = 0;
    for (; i < lmreq->rc_vtp_num; i++) {
        entry = &lmreq->total_vtp[lmreq->rm_vtp_num + i].content.rc_entry;
        if (entry == NULL) {
            TPSA_LOG_ERR("Fail to get rc entry when lm");
            free(cparam);
            return -1;
        }

        if (entry->location != TPSA_INITIATOR) {
            tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, entry->key.dst_eid,
                entry->upi, &peer_tpsa_eid, &dip);

            if (tpsa_notify_table_update(notify_table, &peer_tpsa_eid, NULL, entry) < 0) {
                TPSA_LOG_ERR("Fail to add tpsa noti table(RC) when handle lm target");
                free(cparam);
                return -1;
            }

            if (entry->location == TPSA_TARGET) {
                continue;
            }
        }

        cparam->local_eid = entry->src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->local_jetty = entry->src_jetty_id;
        cparam->peer_jetty = entry->key.jetty_id;
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;
        if ((memcmp(&cparam->local_eid, &cparam->peer_eid, sizeof(urma_eid_t)) == 0) &&
            cparam->local_jetty == cparam->peer_jetty) {
            cparam->sig_loop = true;
        } else {
            cparam->sig_loop = false;
        }
        cparam->upi = vport_entry->ueid[entry->eid_index].upi;

        if (uvs_lm_create_vtp(ctx, cparam, &sip_entry->addr, vport_entry) < 0) {
            TPSA_LOG_ERR("Fail to create RC vtp when lm");
            free(cparam);
            return -1;
        }
    }

    TPSA_LOG_INFO("Finish handle initiator rc type");
    free(cparam);
    return 0;
}

int uvs_lm_handle_um_req(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq,
                         sip_table_entry_t *sip_entry, vport_table_entry_t *vport_entry)
{
    um_vtp_table_entry_t *entry;

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        return -ENOMEM;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));

    cparam->trans_mode = TPSA_TP_UM;
    cparam->dip = lmdip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->eid_index = 0; /* TODO: fix */
    cparam->live_migrate = true;
    cparam->dip_valid = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
    (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
    (void)memcpy(cparam->local_tpf_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
    cparam->mtu = sip_entry->mtu;

    uvs_tp_msg_ctx_t tp_msg_ctx = { 0 };
    uint32_t i = lmreq->rm_vtp_num + lmreq->rc_vtp_num;
    uint32_t total_vtp_num = lmreq->rm_vtp_num + lmreq->rc_vtp_num + lmreq->um_vtp_num;
    for (; i < total_vtp_num; i++) {
        entry = &lmreq->total_vtp[i].content.um_entry;

        cparam->local_eid = entry->key.src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->vtpn = entry->vtpn;

        urma_eid_t peer_tpsa_eid = {0};
        tpsa_net_addr_t dip;
        (void)memset(&dip, 0, sizeof(tpsa_net_addr_t));
        tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid,
            entry->upi, &peer_tpsa_eid, &dip);
        uvs_end_point_t src = { sip_entry->addr, cparam->local_eid, cparam->local_jetty };
        uvs_end_point_t dst = { dip, cparam->peer_eid, cparam->peer_jetty };
        uvs_lm_init_tp_msg_ctx(vport_entry, &src, &dst, &peer_tpsa_eid, &tp_msg_ctx);

        if (uvs_create_um_vtp_base(ctx, &tp_msg_ctx, cparam, &entry->vtpn) < 0) {
            TPSA_LOG_ERR("Fail to create RC vtp when lm");
            free(cparam);
            return -1;
        }
    }

    free(cparam);
    return 0;
}

static void uvs_lm_notification_init(tpsa_notify_table_t *notify_table, tpsa_notify_table_key_t *key,
                                     tpsa_net_addr_t *sip, tpsa_sock_msg_t *msg)
{
    msg->msg_type = TPSA_LM_NOTIFY;

    tpsa_notify_table_entry_t *entry = tpsa_notify_table_lookup(notify_table, key);

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
}

int uvs_lm_handle_target_send(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, tpsa_net_addr_t *sip,
                              tpsa_notify_table_t *notify_table)
{
    int ret = 0;

    tpsa_sock_msg_t *notimsg = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (notimsg == NULL) {
        return -ENOMEM;
    }
    notimsg->upi = msg->upi;
    notimsg->local_eid = msg->local_eid;

    tpsa_notify_table_entry_t *notify_cur, *notify_next;
    tpsa_notify_table_key_t key = {0};

    HMAP_FOR_EACH_SAFE(notify_cur, notify_next, node, &notify_table->hmap) {
        key = notify_cur->key;

        uvs_lm_notification_init(notify_table, &key, sip, notimsg);

        ret = tpsa_sock_send_msg(ctx->sock_ctx, notimsg, sizeof(tpsa_sock_msg_t), key.peer_tpsa_eid);
        if (ret < 0) {
            TPSA_LOG_ERR("Failed to send lm notification\n");
            free(notimsg);
            return ret;
        }
    }

    free(notimsg);

    return ret;
}

static int uvs_lm_config_migrate_state(uvs_ctx_t *ctx, vport_table_entry_t *vport_entry,
                                       tpsa_net_addr_t *sip, tpsa_mig_state_t state)
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
        .netaddr = *sip,
    };

    uint32_t i = 0;
    for (; i < config_loop; i++) {
        tpsa_ioctl_cmd_config_state(cfg, vport_entry, &tpf,
                                    state, (i * TPSA_MAX_EID_CONFIG_CNT));
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to migrate state, %d", (int)state);
            free(cfg);
            return -1;
        }
    }

    uint32_t res_cnt = cfg->cmd.config_state.out.cnt;
    free(cfg);

    if (res_cnt != vport_entry->ueid_max_cnt) {
        TPSA_LOG_ERR("Fail to ioctl to config function state, config %u of total %u",
                     res_cnt, vport_entry->ueid_max_cnt);
        return -1;
    }

    return 0;
}

/* Used to record the number of migrated vtp entries */
void uvs_lm_record_vtp_num(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq, fe_table_entry_t *fe_entry)
{
    /* Superimpose the number of full and iteratively migrated vtp nodes. */
    uint32_t total_vtp_num = lmreq->rm_vtp_num + lmreq->rc_vtp_num + lmreq->um_vtp_num;
    fe_entry->vtp_migrate_num += total_vtp_num;
    fe_entry->mig_source = lmreq->mig_source;
    fe_entry->lm_fe_idx = lmreq->fe_idx;
    (void)memcpy(fe_entry->lm_dev_name, lmreq->dev_name, TPSA_MAX_DEV_NAME);

    return;
}

int uvs_lm_handle_rebuild_link(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg, sip_table_entry_t *sip_entry,
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
        TPSA_LOG_ERR("Fail to create noti table");
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
    /* Lookup sip and vport entry */
    sip_table_entry_t sip_entry = {0};
    uint32_t eid_idx;
    fe_table_entry_t *fe_entry;

    vport_key_t vport_key = {0};
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->local_eid,
                                              &vport_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid failed, upi is %u, eid_idx is %u,  eid:" EID_FMT "\n",
                       msg->upi, eid_idx, EID_ARGS(msg->local_eid));
        return -1;
    }

    TPSA_LOG_INFO("fe_idx is %u, dev_name is %s, upi is %u, eid:" EID_FMT ".\n", vport_key.fe_idx, vport_key.dev_name,
                  msg->upi, EID_ARGS(msg->local_eid));
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }

    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", lmreq->fe_idx);
        goto free_vport;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);

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
    uvs_lm_record_vtp_num(ctx, lmreq, fe_entry);

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

static int uvs_lm_handle_rm_noti(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_notification_t *notify = &msg->content.lmnoti;
    rm_vtp_table_entry_t *entry;
    sip_table_entry_t sip_entry = {0};
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        free(vport_entry);
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_RM;
    cparam->dip = notify->dip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->live_migrate = true;
    cparam->dip_valid = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->upi = msg->upi;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;

    uint32_t i = 0;
    int32_t res = -1;
    urma_eid_t deid = {0};
    for (; i < notify->target_rm_num; i++) {
        entry = &notify->target_vtp[i].content.rm_entry;
        if (entry == NULL) {
            TPSA_LOG_ERR("Fail to get rm entry when lm");
            goto rm_exit;
        }

        deid = entry->key.dst_eid;

        if (vport_table_lookup_by_ueid(&ctx->table_ctx->vport_table, msg->upi, &deid, vport_entry) != 0) {
            TPSA_LOG_ERR("Fail to lookup vport when lm");
            goto rm_exit;
        }
        cparam->fe_idx = vport_entry->key.fe_idx;
        (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
        (void)memcpy(cparam->local_tpf_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));

        cparam->local_eid = entry->key.dst_eid;
        cparam->peer_eid = entry->key.src_eid;

        tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
        res = uvs_lm_create_vtp(ctx, cparam, &sip_entry.addr, vport_entry);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to create RM vtp when lm");
            goto rm_exit;
        }
    }

    TPSA_LOG_INFO("Finish handle target rm type");

rm_exit:
    free(vport_entry);
    free(cparam);
    return res;
}

static int uvs_lm_handle_rc_noti(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_notification_t *notify = &msg->content.lmnoti;
    rc_vtp_table_entry_t *entry;
    sip_table_entry_t sip_entry = {0};

    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }

    tpsa_create_param_t *cparam = (tpsa_create_param_t *)calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        free(vport_entry);
        return -ENOMEM;
    }

    cparam->trans_mode = TPSA_TP_RC;
    cparam->dip = notify->dip;
    cparam->live_migrate = true;
    cparam->dip_valid = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->upi = msg->upi;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;

    uint32_t i = 0;
    int32_t res = -1;
    urma_eid_t deid = {0};
    for (; i < notify->target_rc_num; i++) {
        entry = &notify->target_vtp[notify->target_rm_num + i].content.rc_entry;
        if (entry == NULL) {
            TPSA_LOG_ERR("Fail to get rc entry when lm");
            goto rc_exit;
        }

        deid = entry->key.dst_eid;

        if (vport_table_lookup_by_ueid(&ctx->table_ctx->vport_table, msg->upi, &deid, vport_entry) != 0) {
            TPSA_LOG_ERR("Fail to lookup vport when lm");
            goto rc_exit;
        }
        cparam->fe_idx = vport_entry->key.fe_idx;
        (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));
        (void)memcpy(cparam->local_tpf_name, vport_entry->key.dev_name, sizeof(vport_entry->key.dev_name));

        cparam->local_eid = entry->key.dst_eid;
        cparam->peer_eid = entry->src_eid;
        cparam->local_jetty = entry->key.jetty_id;
        cparam->peer_jetty = entry->src_jetty_id;

        tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
        res = uvs_lm_create_vtp(ctx, cparam, &sip_entry.addr, vport_entry);
        if (res < 0) {
            TPSA_LOG_ERR("Fail to create RC vtp when lm");
            goto rc_exit;
        }
    }

    TPSA_LOG_INFO("Finish handle target rc type");

rc_exit:
    free(vport_entry);
    free(cparam);
    return res;
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

    TPSA_LOG_INFO("lm config local migrate state, fe_idx is %u", nlreq->mig_fe_idx);
    /* Lookup sip and vport entry */
    tpsa_net_addr_t sip;
    (void)memset(&sip, 0, sizeof(tpsa_net_addr_t));
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }
    vport_key_t vport_key = {0};
    vport_key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(vport_key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);
    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", nlreq->mig_fe_idx);
        goto free_vport;
    }

    if (uvs_lm_config_migrate_state(ctx, vport_entry, &sip, state) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to config state");
        goto free_vport;
    }

    /* response success to ubcore via nl */
    if (uvs_response_migrate_fast(msg, ctx->nl_ctx, TPSA_MIG_MSG_PROC_SUCCESS) < 0) {
        TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
        free(vport_entry);
        return -1;
    }

    free(vport_entry);
    return 0;

free_vport:
    /* response failure to ubcore via nl */
    if (uvs_response_migrate_fast(msg, ctx->nl_ctx, TPSA_MIG_MSG_PROC_FAILURE) < 0) {
        TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
    }

    free(vport_entry);
    return -1;
}

int uvs_lm_query_rm_vtp_entry_status(tpsa_vtp_cfg_t *vtp_cfg, uvs_ctx_t *ctx, vtp_node_state_t *node_status,
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

int uvs_lm_query_rc_vtp_entry_status(tpsa_vtp_cfg_t *vtp_cfg, uvs_ctx_t *ctx, vtp_node_state_t *node_status,
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
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_migrate_vtp_req_t *mig_req = (tpsa_nl_migrate_vtp_req_t *)nlmsg->req.data;
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;
    int ret;
    vport_key_t fe_key;

    fe_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(fe_key.dev_name, mig_req->dev_name, TPSA_MAX_DEV_NAME);

    if (vtp_cfg->trans_mode == TPSA_TP_RM) {
        ret = uvs_lm_query_rm_vtp_entry_status(vtp_cfg, ctx, node_status, &fe_key, lm_vtp_entry);
    } else {
        ret = uvs_lm_query_rc_vtp_entry_status(vtp_cfg, ctx, node_status, &fe_key, lm_vtp_entry);
    }

    return ret;
}

static int uvs_lm_rollback_req_init(tpsa_sock_msg_t *rbreq, uvs_ctx_t *ctx, uint16_t mig_fe_idx,
                                    char *dev_name)
{
    rbreq->msg_type = TPSA_LM_ROLLBACK_REQ;

    tpsa_vtp_table_index_t vtp_idx = {0};
    if (tpsa_get_vtp_idx(mig_fe_idx, dev_name, &vtp_idx, ctx->table_ctx) < 0) {
        TPSA_LOG_ERR("Fail to get vtp idx");
        return -1;
    }
    rbreq->upi = vtp_idx.upi;
    rbreq->local_eid = vtp_idx.local_eid;

    return 0;
}

int uvs_lm_handle_rollback(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    int ret = 0;

    TPSA_LOG_INFO("lm initiator handle rollback, fe_idx is %u", nlreq->mig_fe_idx);
    /* TODO: modify local vtp table */

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
    (void)memcpy(key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);

    live_migrate_table_entry_t *lm_entry = live_migrate_table_lookup(&ctx->table_ctx->live_migrate_table, &key);
    if (lm_entry == NULL) {
        TPSA_LOG_WARN("Can't find lm entry in live migrate table, send rollback msg failed");
        ret = TPSA_LOOKUP_NULL;
        goto free_req;
    }

    if (uvs_lm_rollback_req_init(rbreq, ctx, nlreq->mig_fe_idx, nlreq->dev_name) < 0) {
        TPSA_LOG_ERR("Failed to init rollback req\n");
        goto free_req;
    }

    ret = tpsa_sock_send_msg(ctx->sock_ctx, rbreq, sizeof(tpsa_sock_msg_t), lm_entry->dip);
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
    tpsa_nl_function_mig_req_t *rbreq = &msg->content.rbreq;
    uint32_t eid_idx;
    TPSA_LOG_INFO("lm handle rollback req");

    /* Lookup sip and vport entry */
    tpsa_net_addr_t sip;
    (void)memset(&sip, 0, sizeof(tpsa_net_addr_t));
    vport_table_entry_t *vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        return -ENOMEM;
    }

    vport_key_t vport_key = {0};
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->local_eid,
                                              &vport_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid failed, upi is %u, eid_idx is %u,  eid:" EID_FMT "\n",
                       msg->upi, eid_idx, EID_ARGS(msg->local_eid));
        return -1;
    }

    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", rbreq->mig_fe_idx);
        goto free_vport;
    }

    /* config rollback state to driver */
    if (uvs_lm_config_migrate_state(ctx, vport_entry, &sip, TPSA_MIG_STATE_ROLLBACK) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to config state when receive vm start nl msg");
        goto free_vport;
    }

    return 0;

free_vport:
    free(vport_entry);
    return -1;
}

int uvs_lm_handle_query_mig_status(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    int ret = 0;
    tpsa_mig_resp_status_t status = TPSA_MIG_MSG_PROC_SUCCESS;

    TPSA_LOG_INFO("lm initiator handle query status, fe_idx is %u", nlreq->mig_fe_idx);
    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(fe_key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &fe_key);
    if (fe_entry == NULL) {
        TPSA_LOG_WARN("key fe_idx %hu not exist in fe_table when handle query status", fe_key.fe_idx);
        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
        status = TPSA_MIG_MSG_PROC_FAILURE;
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
    if (uvs_response_migrate_fast(msg, ctx->nl_ctx, status) < 0) {
        TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
        ret = -1;
    }

    return ret;
}

int uvs_lm_handle_mig_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_resp_t lm_resp = msg->content.lm_resp;

    if (lm_resp.last_mig_completed == true) {
        vport_key_t fe_key = {0};
        fe_key.fe_idx = lm_resp.mig_fe_idx;
        (void)memcpy(fe_key.dev_name, lm_resp.dev_name, TPSA_MAX_DEV_NAME);

        (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
        fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &fe_key);
        if (fe_entry == NULL) {
            TPSA_LOG_WARN("key fe_idx %hu not exist in fe_table when handle lm resp", fe_key.fe_idx);
            (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
            return TPSA_LOOKUP_NULL;
        }
        /* Record that the migration destination has completed link reconstruction */
        fe_entry->link_ready = true;
        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);

        if (live_migrate_table_remove(&ctx->table_ctx->live_migrate_table, &fe_key) != 0) {
            TPSA_LOG_ERR("can not del live_migrate by key fe_idx %hu\n", fe_key.fe_idx);
            return -1;
        }
    }

    return 0;
}

int uvs_lm_for_rm_vtp_table(rm_vtp_table_t *rm_vtp_table, tpsa_sock_msg_t *req)
{
    rm_vtp_table_entry_t *vtp_cur, *vtp_next;
    uint32_t total_num = req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num +
        req->content.lmmsg.um_vtp_num;
    uint32_t i = total_num;

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

int uvs_lm_for_rc_vtp_table(rc_vtp_table_t *rc_vtp_table, tpsa_sock_msg_t *req)
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

int uvs_lm_for_um_vtp_table(um_vtp_table_t *um_vtp_table, tpsa_sock_msg_t *req)
{
    um_vtp_table_entry_t *vtp_cur, *vtp_next;
    uint32_t total_num = req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num +
        req->content.lmmsg.um_vtp_num;
    uint32_t i = total_num;

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

int uvs_lm_vtp_table_lmmsg_copy(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req)
{
    /* don't change the copy sequence */
    if (uvs_lm_for_rm_vtp_table(&fe_entry->rm_vtp_table, req) != 0) {
        return -1;
    }
    if (uvs_lm_for_rc_vtp_table(&fe_entry->rc_vtp_table, req) != 0) {
        return -1;
    }
    if (uvs_lm_for_um_vtp_table(&fe_entry->um_vtp_table, req) != 0) {
        return -1;
    }

    return 0;
}

static int uvs_lm_vtp_table_iterative_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req)
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
        ret = uvs_lm_vtp_table_lmmsg_copy(fe_entry, req);
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

static int uvs_lm_vtp_table_full_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req)
{
    int ret;

    ret = uvs_lm_vtp_table_lmmsg_copy(fe_entry, req);
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
    int ret;
    tpsa_sock_msg_t *req = NULL;
    tpsa_config_t cfg;

    req = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        return -ENOMEM;
    }
    req->content.lmmsg.fe_idx = cur->key.fe_idx;
    req->content.lmmsg.stop_proc_vtp = fe_entry->stop_proc_vtp;
    (void)memcpy(req->content.lmmsg.dev_name, fe_entry->key.dev_name, TPSA_MAX_DEV_NAME);

    tpsa_vtp_table_index_t vtp_idx = {0};
    ret = tpsa_get_vtp_idx(fe_entry->key.fe_idx, fe_entry->key.dev_name, &vtp_idx, ctx->table_ctx);
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
    cfg = uvs_get_config();
    req->content.lmmsg.mig_source.in4.addr = (uint32_t)cfg.tpsa_server_ip.s_addr;
    if (tpsa_sock_send_msg(ctx->sock_ctx, req, sizeof(tpsa_sock_msg_t), cur->dip) != 0) {
        TPSA_LOG_ERR("Failed to send live migrate message\n");
        ret = -1;
        goto free_live_migrate;
    }

    ret = 0;

free_live_migrate:
    free(req);
    return ret;
}

int uvs_lm_handle_stop_proc_vtp_msg(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;
    vport_key_t key = {0};
    int ret;
    tpsa_config_t cfg;

    key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);

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
    tpsa_sock_msg_t *req = NULL;

    req = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (req == NULL) {
        return -ENOMEM;
    }
    req->content.lmmsg.fe_idx = nlreq->mig_fe_idx;
    req->content.lmmsg.stop_proc_vtp = entry->stop_proc_vtp;
    req->msg_type = TPSA_LM_MIG_REQ;
    cfg = uvs_get_config();
    req->content.lmmsg.mig_source.in4.addr = (uint32_t)cfg.tpsa_server_ip.s_addr;
    ret = uvs_lm_vtp_table_lmmsg_copy(entry, req);
    if (ret < 0) {
        TPSA_LOG_ERR("live migrate message copy failed, when handle stop process vtp msg.\n");
        goto free_and_ret;
    }

    /* If there are no vtp_entries for migration, there is no need to send a message to the migration destination. */
    if (req->content.lmmsg.rm_vtp_num + req->content.lmmsg.rc_vtp_num + req->content.lmmsg.um_vtp_num == 0) {
        ret = 0;
        goto free_and_ret;
    }

    ret = tpsa_sock_send_msg(ctx->sock_ctx, req, sizeof(tpsa_sock_msg_t), lm_entry->dip);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to send live migrate message\n");
    }

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

    if (tpsa_sock_send_msg(ctx->sock_ctx, msg, sizeof(tpsa_sock_msg_t), lm_entry->dip) < 0) {
        TPSA_LOG_ERR("Failed to send transfer msg\n");
        return -1;
    }

    return 0;
}

int uvs_rc_vtp_modify_to_vice_tpg(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *lm_vtp_entry)
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
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);

    vtp_cfg.fe_idx = vport_entry->key.fe_idx;
    vtp_cfg.vtpn = vtp_entry->vtpn;
    vtp_cfg.local_jetty = vtp_entry->src_jetty_id;
    vtp_cfg.local_eid = vtp_entry->src_eid;
    vtp_cfg.peer_eid = vtp_entry->key.dst_eid;
    vtp_cfg.peer_jetty = vtp_entry->key.jetty_id;
    vtp_cfg.flag = vtp_flag;
    vtp_cfg.trans_mode = TPSA_TP_RC;
    vtp_cfg.number.tpgn = vtp_entry->vice_tpgn;

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

int uvs_rm_vtp_modify_to_vice_tpg(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *lm_vtp_entry)
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
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);

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

int uvs_lm_modify_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, sip_table_entry_t *sip_entry, vport_table_entry_t *vport_entry,
                      um_vtp_table_entry_t *vtp_entry,  uint32_t vice_utp)
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

int uvs_um_create_new_commu_channel(uvs_ctx_t *ctx, sip_table_entry_t *sip_entry,
                                    vport_table_entry_t *vport_entry, um_vtp_table_entry_t *vtp_entry)
{
    utp_table_key_t utp_key = {
        .sip = sip_entry->addr,
        .dip = ctx->table_ctx->dip_table.refresh_entry->netaddr,
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
    tpsa_lm_ioctl_cmd_create_utp(cfg, &vport_param, sip_entry, &utp_key);
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
    (void)uvs_destroy_utp(ctx->ioctl_ctx, ctx->table_ctx, &utp_key, utpn);
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
int uvs_lm_switch_utp(uvs_ctx_t *ctx, um_vtp_table_entry_t *vtp_entry)
{
    int ret = -1;
    sip_table_entry_t sip_entry = { 0 };
    utp_table_key_t utp_key;
    utp_table_entry_t *utp_table_entry;
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("vtp entry is null when modify to vice tpg in um mode.\n");
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
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    utp_key.sip = sip_entry.addr;
    utp_key.dip = ctx->table_ctx->dip_table.old_netaddr;
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
    ret = uvs_um_create_new_commu_channel(ctx, &sip_entry, vport_entry, vtp_entry);
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

int uvs_lm_refresh_tpg(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg, char *dev_name, tpsa_lm_vtp_entry_t *lm_vtp_entry)
{
    int ret = -1;

    if (lm_vtp_entry->trans_mode == TPSA_TP_RM) {
        ret = uvs_rm_vtp_modify_to_vice_tpg(ctx, lm_vtp_entry);
    } else if (lm_vtp_entry->trans_mode == TPSA_TP_RC) {
        ret = uvs_rc_vtp_modify_to_vice_tpg(ctx, lm_vtp_entry);
    } else {
        ret = uvs_lm_switch_utp(ctx, lm_vtp_entry->content.um_entry);
    }

    return ret;
}

int uvs_lm_get_tp_msg_ctx(uvs_ctx_t *ctx, vport_del_list_node_t *list_node,
                          uvs_tp_msg_ctx_t *tp_msg_ctx, uvs_lm_vtp_info_t *vtp_info)
{
    vport_param_t *vport_param = &tp_msg_ctx->vport_ctx.param;

    tp_msg_ctx->vport_ctx.key = list_node->vport_key;
    vport_param->sip_idx = list_node->sip_idx;
    vport_param->tp_cnt = list_node->tp_cnt;

    sip_table_entry_t sip_entry = {0};
    tpsa_lookup_sip_table(tp_msg_ctx->vport_ctx.param.sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    tp_msg_ctx->src.ip = sip_entry.addr;
    tp_msg_ctx->src.eid = vtp_info->local_eid;
    tp_msg_ctx->src.jetty_id = vtp_info->local_jetty;

    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, vtp_info->peer_eid, vtp_info->upi,
                          &tp_msg_ctx->peer.tpsa_eid, &tp_msg_ctx->dst.ip);
    tp_msg_ctx->dst.eid = vtp_info->peer_eid;
    tp_msg_ctx->dst.jetty_id = vtp_info->peer_jetty;

    return 0;
}

void uvs_lm_cparam_init(tpsa_create_param_t *cparam, tpsa_lm_vtp_entry_t *vtp_entry,
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
    cparam->dip_valid = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->sig_loop = sig_loop;
    cparam->ta_data.trans_type = TPSA_TRANSPORT_UB;
}

tpsa_create_param_t *uvs_lm_init_delete_link_info(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *vtp_entry,
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
    } else if (vtp_entry->trans_mode == TPSA_TP_RC) {
        tpg_idx->local_eid = vtp_entry->content.rc_entry->src_eid;
        tpg_idx->peer_eid = vtp_entry->content.rc_entry->key.dst_eid;
        tpg_idx->ljetty_id = vtp_entry->content.rc_entry->src_jetty_id;
        tpg_idx->djetty_id = vtp_entry->content.rc_entry->key.jetty_id;
        tpg_idx->upi = vtp_entry->content.rc_entry->upi;

        vtp_idx->location =  vtp_entry->content.rc_entry->location;
        cparam->vtpn = vtp_entry->content.rc_entry->vtpn;
    } else {
        tpg_idx->local_eid = vtp_entry->content.um_entry->key.src_eid;
        tpg_idx->peer_eid = vtp_entry->content.um_entry->key.dst_eid;
        tpg_idx->ljetty_id = UINT32_MAX;
        tpg_idx->djetty_id = UINT32_MAX;
        tpg_idx->upi = vtp_entry->content.um_entry->upi;
        cparam->vtpn = vtp_entry->content.um_entry->vtpn;
    }

    tpg_idx->dip = tp_msg_ctx->dst.ip;
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
int uvs_cleanup_resource_from_client(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *vtp_entry,
                                     vport_del_list_node_t *list_node, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int32_t vtpn = -1;
    int32_t tpgn = -1;
    tpsa_vtp_table_index_t vtp_idx;
    tpsa_tpg_table_index_t tpg_idx;
    int ret = 0;

    tpsa_create_param_t *cparam = uvs_lm_init_delete_link_info(ctx, vtp_entry, tp_msg_ctx, &tpg_idx, &vtp_idx);
    if (cparam == NULL) {
        TPSA_LOG_ERR("Cparam init failed when init link info.\n");
        return -1;
    }

    cparam->fe_idx = list_node->vport_key.fe_idx;
    vtp_idx.fe_key = list_node->vport_key;
    (void)memcpy(cparam->dev_name, list_node->vport_key.dev_name, sizeof(list_node->vport_key.dev_name));
    (void)memcpy(cparam->local_tpf_name, list_node->vport_key.dev_name, sizeof(list_node->vport_key.dev_name));
    uvs_table_remove_initiator(&vtpn, &tpgn, &tpg_idx, &vtp_idx, ctx->table_ctx);
    ret = uvs_destroy_vtp_base(ctx, cparam, tp_msg_ctx, vtpn, tpgn);
    if (ret != 0) {
        TPSA_LOG_ERR("Destroy vtp base failed in lm delete link for rm mode.\n");
        free(cparam);
        return ret;
    }

    free(cparam);
    return 0;
}

int uvs_cleanup_resource_from_server(uvs_ctx_t *ctx, tpsa_lm_vtp_entry_t *vtp_entry,
                                     vport_del_list_node_t *list_node, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = 0;
    int32_t vtpn = -1;
    int32_t tpgn = -1;
    tpsa_vtp_table_index_t vtp_idx;
    tpsa_tpg_table_index_t tpg_idx;
    tpsa_sock_msg_t *dmsg = NULL;

    tpsa_create_param_t *cparam = uvs_lm_init_delete_link_info(ctx, vtp_entry, tp_msg_ctx, &tpg_idx, &vtp_idx);
    if (cparam == NULL) {
        TPSA_LOG_ERR("Cparam init failed when init link info.\n");
        return -1;
    }
    cparam->fe_idx = list_node->vport_key.fe_idx;
    vtp_idx.fe_key = list_node->vport_key;
    (void)memcpy(cparam->dev_name, list_node->vport_key.dev_name, sizeof(list_node->vport_key.dev_name));
    (void)memcpy(cparam->local_tpf_name, list_node->vport_key.dev_name, sizeof(list_node->vport_key.dev_name));
    vtp_idx.location = TPSA_TARGET;
    uvs_table_remove_initiator(&vtpn, &tpgn, &tpg_idx, &vtp_idx, ctx->table_ctx);
    if (uvs_destroy_vtp_and_tpg(ctx, cparam, tp_msg_ctx, vtpn, tpgn) < 0) {
        TPSA_LOG_ERR("destroy vtp or tpg faied.\n");
        ret = -1;
        goto free_cparam;
    }
    if (!vtp_idx.isLoopback) {
       /* we start to notify peer to destroy tpg */
        dmsg = tpsa_sock_init_destroy_req(cparam, (uint32_t)tpgn,
            &tp_msg_ctx->src.ip, tp_msg_ctx->vport_ctx.param.tp_cnt, false);
        if (dmsg == NULL) {
            ret = -1;
            goto free_cparam;
        }

        ret = tpsa_sock_send_msg(ctx->sock_ctx, dmsg, sizeof(tpsa_sock_msg_t), tp_msg_ctx->peer.tpsa_eid);
        if (ret != 0) {
            TPSA_LOG_ERR("Failed to send destroy vtp req in worker\n");
            goto free_dmsg;
        }
    }

    ret = 0;
    TPSA_LOG_INFO("Finish socket destroy message in initiator\n");

free_dmsg:
    if (dmsg != NULL) {
        free(dmsg);
    }
free_cparam:
    free(cparam);
    return ret;
}

int uvs_cleanup_resource_for_rm(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry, vport_del_list_node_t *list_node)
{
    rm_vtp_table_entry_t *vtp_cur, *vtp_next;
    uvs_tp_msg_ctx_t tp_msg_ctx;
    int ret = 0;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &fe_entry->rm_vtp_table.hmap) {
        (void)memset(&tp_msg_ctx, 0, sizeof(uvs_tp_msg_ctx_t));
        uvs_lm_vtp_info_t vtp_info = {
            .local_eid = vtp_cur->key.src_eid,
            .peer_eid = vtp_cur->key.dst_eid,
            .local_jetty = vtp_cur->src_jetty_id,
            .peer_jetty = UINT32_MAX,
            .upi = vtp_cur->upi,
        };
        ret = uvs_lm_get_tp_msg_ctx(ctx, list_node, &tp_msg_ctx, &vtp_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Tp msg ctx init failed when delete rm link.\n");
            return ret;
        }
        tpsa_lm_vtp_entry_t vtp_entry = {
            .trans_mode = TPSA_TP_RM,
            .content = { .rm_entry = vtp_cur, },
        };
        if (vtp_cur->location != TPSA_TARGET) {
            ret = uvs_cleanup_resource_from_client(ctx, &vtp_entry, list_node, &tp_msg_ctx);
            if (ret != 0) {
                TPSA_LOG_ERR("Client up resource from client is failed in rm mode.\n");
                return ret;
            }
            if (vtp_cur->location == TPSA_INITIATOR) {
                continue;
            }
        }
        /* Deletion triggered by server side */
        ret = uvs_cleanup_resource_from_server(ctx, &vtp_entry, list_node, &tp_msg_ctx);
        if (ret != 0) {
            TPSA_LOG_ERR("Client up resource from server is failed in rm mode.\n");
            return ret;
        }
    }

    TPSA_LOG_INFO("Finish handle link delete for rm type. dev_name is %s, fe_idx is %u.\n",
                  fe_entry->key.dev_name, fe_entry->key.fe_idx);
    return 0;
}

int uvs_cleanup_resource_for_rc(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry, vport_del_list_node_t *list_node)
{
    rc_vtp_table_entry_t *vtp_cur, *vtp_next;
    uvs_tp_msg_ctx_t tp_msg_ctx;
    int ret = 0;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &fe_entry->rc_vtp_table.hmap) {
        (void)memset(&tp_msg_ctx, 0, sizeof(uvs_tp_msg_ctx_t));
        uvs_lm_vtp_info_t vtp_info = {
            .local_eid = vtp_cur->src_eid,
            .peer_eid = vtp_cur->key.dst_eid,
            .local_jetty = vtp_cur->src_jetty_id,
            .peer_jetty = vtp_cur->key.jetty_id,
            .upi = vtp_cur->upi,
        };
        ret = uvs_lm_get_tp_msg_ctx(ctx, list_node, &tp_msg_ctx, &vtp_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Tp msg ctx init failed when delete rc link.\n");
            return ret;
        }
        tpsa_lm_vtp_entry_t vtp_entry = {
            .trans_mode = TPSA_TP_RC,
            .content = { .rc_entry = vtp_cur, },
        };
        if (vtp_cur->location != TPSA_TARGET) {
            ret = uvs_cleanup_resource_from_client(ctx, &vtp_entry, list_node, &tp_msg_ctx);
            if (ret != 0) {
                TPSA_LOG_ERR("Client up resource from client is failed in rc mode.\n");
                return ret;
            }
            if (vtp_cur->location == TPSA_INITIATOR) {
                continue;
            }
        }

        /* Deletion triggered by server side */
        ret = uvs_cleanup_resource_from_server(ctx, &vtp_entry, list_node, &tp_msg_ctx);
        if (ret != 0) {
            TPSA_LOG_ERR("Client up resource from server is failed in rm mode.\n");
            return ret;
        }
    }

    TPSA_LOG_INFO("Finish handle link delete for rc type. dev_name is %s, fe_idx is %u.\n",
                  fe_entry->key.dev_name, fe_entry->key.fe_idx);
    return 0;
}

int uvs_cleanup_resource_for_um(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry, vport_del_list_node_t *list_node)
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
        int ret = uvs_lm_get_tp_msg_ctx(ctx, list_node, &tp_msg_ctx, &vtp_info);
        if (ret != 0) {
            TPSA_LOG_ERR("Tp msg ctx init failed when delete rc link.\n");
            return ret;
        }
        ret = uvs_destroy_um_vtp(ctx, &tp_msg_ctx, TPSA_TP_UM);
        if (ret != 0) {
            TPSA_LOG_ERR("Destroy um vtp failed in um link delete.\n");
            return ret;
        }
    }

    return 0;
}

void uvs_lm_clean_up_resource(uvs_ctx_t *ctx)
{
    int ret = 0;
    vport_del_list_node_t *cur, *next;
    vport_table_t *vport_table = &ctx->table_ctx->vport_table;

    UB_LIST_FOR_EACH_SAFE(cur, next, node, &vport_table->vport_delete_list) {
        fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &cur->vport_key);
        if (fe_entry == NULL) {
            ub_list_remove(&cur->node);
            free(cur);
            continue;
        }
        if (fe_entry->rm_vtp_table.hmap.count != 0) {
            ret = uvs_cleanup_resource_for_rm(ctx, fe_entry, cur);
        }
        if (fe_entry->rc_vtp_table.hmap.count != 0) {
            ret = uvs_cleanup_resource_for_rc(ctx, fe_entry, cur);
        }
        if (fe_entry->um_vtp_table.hmap.count != 0) {
            ret = uvs_cleanup_resource_for_um(ctx, fe_entry, cur);
        }

        ub_list_remove(&cur->node);
        free(cur);
    }

    if (ret != 0) {
        TPSA_LOG_ERR("Del link for rm mode faied, dev_name:%s:%d.\n", cur->vport_key.dev_name, cur->vport_key.fe_idx);
    }

    /* The flag needs to be set to false to indicate that the virtual machine has performed resource cleanup. */
    vport_table->vf_destroy = false;

    return;
}
