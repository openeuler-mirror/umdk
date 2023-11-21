/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs live migration implementation file
 * Author: LI Yuxing
 * Create: 2023-8-16
 * Note:
 * History:
 */

#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "uvs_lm.h"

static int uvs_response_migrate_fast(tpsa_nl_msg_t *msg, tpsa_nl_ctx_t *nl_ctx,
                                     tpsa_nl_resp_status_t status)
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

int uvs_lm_create_vtp(uvs_ctx_t *ctx, tpsa_create_param_t *cparam,
                      tpsa_net_addr_t *sip, vport_table_entry_t *vport_entry)
{
    urma_eid_t peer_tpsa_eid = {0};
    tpsa_net_addr_t dip = {0};
    bool isLoopback = false;

    if (cparam->migrateThird) {
        dip = cparam->dip;
        peer_tpsa_eid = cparam->dip.eid;
    } else {
        tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid,
                              &peer_tpsa_eid, &dip);
    }

    if (memcmp(sip, &dip, sizeof(tpsa_net_addr_t)) == 0) {
        isLoopback = true;

        if (cparam->migrateThird) {
            return 0;
        }
    }

    tpsa_tpg_table_index_t tpg_idx = {0};
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

    if (uvs_create_vtp_base(ctx, cparam, &tpg_idx, &nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to run create tpg base.");
        return -1;
    }

    return 0;
}

int uvs_lm_handle_rm_req(uvs_ctx_t *ctx, tpsa_lm_req_t *lmreq, sip_table_entry_t *sip_entry,
                         vport_table_entry_t *vport_entry, tpsa_notify_table_t *notify_table)
{
    rm_vtp_table_entry_t *entry;
    tpsa_net_addr_t dip = {0};
    urma_eid_t peer_tpsa_eid = {0};

    tpsa_create_param_t *cparam = calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam when lm");
        return -1;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));

    cparam->trans_mode = TPSA_TP_RM;
    cparam->dip = lmdip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->liveMigrate = true;
    cparam->migrateThird = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, TPSA_MAX_DEV_NAME);
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
            tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, entry->key.dst_eid, &peer_tpsa_eid, &dip);
 
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
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;
        cparam->sig_loop = false;

        if (memcmp(&cparam->local_eid, &cparam->peer_eid, sizeof(urma_eid_t)) == 0) {
            cparam->sig_loop = true;
        }
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
    tpsa_net_addr_t dip = {0};
    urma_eid_t peer_tpsa_eid = {0};

    tpsa_create_param_t *cparam = calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam when lm");
        return -1;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));

    cparam->trans_mode = TPSA_TP_RC;
    cparam->dip = lmdip;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->liveMigrate = true;
    cparam->migrateThird = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, TPSA_MAX_DEV_NAME);
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
            tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, entry->key.dst_eid, &peer_tpsa_eid, &dip);
 
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

    tpsa_create_param_t *cparam = calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam when lm");
        return -1;
    }

    tpsa_net_addr_t lmdip;
    (void)memset(&lmdip, 0, sizeof(tpsa_net_addr_t));

    cparam->trans_mode = TPSA_TP_UM;
    cparam->dip = lmdip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->fe_idx = vport_entry->key.fe_idx;
    cparam->eid_index = 0; /* TODO: fix */
    cparam->liveMigrate = true;
    cparam->migrateThird = false;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, TPSA_MAX_DEV_NAME);
    cparam->mtu = sip_entry->mtu;

    uint32_t i = lmreq->rm_vtp_num + lmreq->rc_vtp_num;
    uint32_t total_vtp_num = lmreq->rm_vtp_num + lmreq->rc_vtp_num + lmreq->um_vtp_num;
    for (; i < total_vtp_num; i++) {
        entry = &lmreq->total_vtp[i].content.um_entry;

        cparam->local_eid = entry->key.src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->vtpn = entry->vtpn;

        if (uvs_create_um_vtp_base(ctx, cparam, vport_entry, &entry->vtpn) < 0) {
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

    tpsa_sock_msg_t *notimsg = calloc(1, sizeof(tpsa_sock_msg_t));
    if (notimsg == NULL) {
        TPSA_LOG_ERR("Fail to alloc socket msg");
        return -1;
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
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to alloc destroy vtp request ");
        return -1;
    }

    uint32_t config_loop = vport_entry->ueid_max_cnt / TPSA_MAX_EID_CONFIG_CNT;
    if (vport_entry->ueid_max_cnt % TPSA_MAX_EID_CONFIG_CNT != 0) {
        config_loop += 1;
    }

    tpsa_cmd_tpf_t tpf = {
        .trans_type = URMA_TRANSPORT_UB,
        .netaddr = *sip,
    };

    uint32_t i = 0;
    for (; i < config_loop; i++) {
        tpsa_ioctl_cmd_config_state(cfg, vport_entry, &tpf,
                                    state, (i * TPSA_MAX_EID_CONFIG_CNT));
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to map vtp in worker");
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
    tpsa_notify_table_t *notify_table = calloc(1, sizeof(tpsa_notify_table_t));
    if (notify_table == NULL) {
        TPSA_LOG_ERR("Fail to alloc noti table");
        return ret;
    }

    ret = tpsa_notify_table_create(notify_table);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to create noti table");
        free(notify_table);
        return -1;
    }

    ret = uvs_lm_handle_rm_req(ctx, lmreq, sip_entry, vport_entry, notify_table);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to handle rm initiator when lm");
        goto destroy_table;
    }

    ret = uvs_lm_handle_rc_req(ctx, lmreq, sip_entry, vport_entry, notify_table);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to handle rc initiator when lm");
        goto destroy_table;
    }

    ret = uvs_lm_handle_um_req(ctx, lmreq, sip_entry, vport_entry);
    if (ret < 0) {
        TPSA_LOG_ERR("Fail to handle um when lm");
        goto destroy_table;
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

int uvs_lm_handle_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_lm_req_t *lmreq = &msg->content.lmmsg;
    /* Lookup sip and vport entry */
    sip_table_entry_t sip_entry = {0};
    uint32_t eid_idx;

    vport_key_t vport_key = {0};
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->local_eid,
                                              &vport_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid failed, upi is %u, eid_idx is %u,  eid:"EID_FMT"\n",
                       msg->upi, eid_idx, EID_ARGS(msg->local_eid));
        return -1;
    }

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry when handle lm req");
        return -1;
    }

    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", lmreq->fe_idx);
        goto free_vport;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);

    /* First time need to config state */
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &vport_key);
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
    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry when lm");
        return -1;
    }

    tpsa_create_param_t *cparam = calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam when lm");
        free(vport_entry);
        return -1;
    }

    cparam->trans_mode = TPSA_TP_RM;
    cparam->dip = notify->dip;
    cparam->local_jetty = UINT32_MAX;
    cparam->peer_jetty = UINT32_MAX;
    cparam->liveMigrate = true;
    cparam->migrateThird = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->upi = msg->upi;

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
        (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, TPSA_MAX_DEV_NAME);

        cparam->local_eid = entry->key.src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;

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

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry when lm");
        return -1;
    }

    tpsa_create_param_t *cparam = calloc(1, sizeof(tpsa_create_param_t));
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam when lm");
        free(vport_entry);
        return -1;
    }

    cparam->trans_mode = TPSA_TP_RC;
    cparam->dip = notify->dip;
    cparam->liveMigrate = true;
    cparam->migrateThird = true;
    cparam->msg_id = UINT32_MAX;
    cparam->nlmsg_seq = UINT32_MAX;
    cparam->upi = msg->upi;

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
        (void)memcpy(cparam->dev_name, vport_entry->key.dev_name, TPSA_MAX_DEV_NAME);

        cparam->local_eid = entry->src_eid;
        cparam->peer_eid = entry->key.dst_eid;
        cparam->local_jetty = entry->src_jetty_id;
        cparam->peer_jetty = entry->key.jetty_id;
        cparam->eid_index = entry->eid_index;
        cparam->vtpn = entry->vtpn;

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

int uvs_lm_handle_vm_start(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_mig_vm_start_t *nlreq = (tpsa_nl_mig_vm_start_t *)nlmsg->data;

    TPSA_LOG_INFO("lm handle vm start, fe_idx is %u", nlreq->mig_fe_idx);
    /* Lookup sip and vport entry */
    tpsa_net_addr_t sip = {0};
    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry when handle lm req");
        return -1;
    }
    vport_key_t vport_key = {0};
    vport_key.fe_idx = nlreq->mig_fe_idx;
    (void)memcpy(vport_key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);
    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", nlreq->mig_fe_idx);
        goto free_vport;
    }

    if (uvs_lm_config_migrate_state(ctx, vport_entry, &sip, TPSA_MIG_STATE_FINISH) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to config state when receive vm start nl msg");
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

int uvs_lm_handle_rm_async_proprocess(tpsa_nl_migrate_vtp_req_t *mig_req, uvs_ctx_t *ctx,
                                      vtp_node_state_t *node_status)
{
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;

    rm_vtp_table_key_t vtp_key = {
        .src_eid = vtp_cfg->local_eid,
        .dst_eid = vtp_cfg->peer_eid,
    };

    vport_key_t fe_key;
    fe_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(fe_key.dev_name, mig_req->dev_name, TPSA_MAX_DEV_NAME);
    rm_vtp_table_entry_t *vtp_entry = rm_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &fe_key, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("Can't find vtp entry in rm vtp table");
        return TPSA_LOOKUP_NULL;
    }

    *node_status = vtp_entry->node_status;
    return 0;
}

int uvs_lm_handle_rc_async_proprocess(tpsa_nl_migrate_vtp_req_t *mig_req, uvs_ctx_t *ctx,
                                      vtp_node_state_t *node_status)
{
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;
    rc_vtp_table_key_t vtp_key = {
        .dst_eid = vtp_cfg->peer_eid,
        .jetty_id = vtp_cfg->peer_jetty,
    };

    vport_key_t fe_key;
    fe_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(fe_key.dev_name, mig_req->dev_name, TPSA_MAX_DEV_NAME);

    rc_vtp_table_entry_t *vtp_entry = rc_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &fe_key, &vtp_key);
    if (vtp_entry == NULL) {
        TPSA_LOG_ERR("Can't find vtp entry in rc vtp table");
        return TPSA_LOOKUP_NULL;
    }

    *node_status = vtp_entry->node_status;
    return 0;
}

int uvs_lm_handle_async_proprocess(tpsa_nl_msg_t *msg, uvs_ctx_t *ctx, vtp_node_state_t *node_status)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_migrate_vtp_req_t *mig_req = (tpsa_nl_migrate_vtp_req_t *)nlmsg->data;
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;
    int ret;

    if (vtp_cfg->trans_mode == TPSA_TP_RM) {
        ret = uvs_lm_handle_rm_async_proprocess(mig_req, ctx, node_status);
    } else {
        ret = uvs_lm_handle_rc_async_proprocess(mig_req, ctx, node_status);
    }

    return ret;
}

int uvs_lm_handle_async_event(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    /* TODO: switch according to vtp entry status */
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_migrate_vtp_req_t *mig_req = (tpsa_nl_migrate_vtp_req_t *)nlmsg->data;
    tpsa_vtp_cfg_t *vtp_cfg = (tpsa_vtp_cfg_t *)&mig_req->vtp_cfg;

    /* Lookup sip and vport entry */
    sip_table_entry_t sip_entry = {0};
    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry when handle lm req");
        return -1;
    }
    vport_key_t vport_key = {0};
    vport_key.fe_idx = vtp_cfg->fe_idx;
    (void)memcpy(vport_key.dev_name, mig_req->dev_name, TPSA_MAX_DEV_NAME);
    int res = tpsa_lookup_vport_table(&vport_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %hu\n", vtp_cfg->fe_idx);
        free(vport_entry);
        return -1;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    free(vport_entry);

    /* Swap tpgn in vtp table */
    tpsa_vtp_table_index_t vtp_idx = {
        .local_eid = vtp_cfg->local_eid,
        .peer_eid = vtp_cfg->peer_eid,
        .peer_jetty = vtp_cfg->peer_jetty,
        .local_jetty = vtp_cfg->local_jetty,
        .location = TPSA_DUPLEX, /* does't care */
        .isLoopback = false, /* does't care */
        .fe_key = vport_key,
        .upi = UINT16_MAX, /* does't care */
        .sig_loop = false, /* does't care */
    };

    uint32_t vice_tpgn = UINT32_MAX;
    if (tpsa_vtp_tpgn_swap(vtp_cfg->trans_mode, &vtp_idx, ctx->table_ctx, &vice_tpgn) < 0) {
        TPSA_LOG_ERR("Fail to swap tpgn");
        (void)tpsa_vtp_node_status_change(vtp_cfg->trans_mode, &vtp_idx, ctx->table_ctx);
        return -1;
    }

    /* IOCTL to modify vtp */
    if (uvs_ioctl_cmd_modify_vtp(ctx->ioctl_ctx, vtp_cfg, &sip_entry.addr, vice_tpgn) < 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify vtp");

        /* swap back */
        if (tpsa_vtp_tpgn_swap(vtp_cfg->trans_mode, &vtp_idx, ctx->table_ctx, &vice_tpgn) < 0) {
            TPSA_LOG_ERR("Fail to swap tpgn");
            (void)tpsa_vtp_node_status_change(vtp_cfg->trans_mode, &vtp_idx, ctx->table_ctx);
            return -1;
        }

        (void)tpsa_vtp_node_status_change(vtp_cfg->trans_mode, &vtp_idx, ctx->table_ctx);
        return -1;
    }

    return 0;
}

static void uvs_lm_rollback_req_init(tpsa_sock_msg_t *rbreq, uint16_t mig_fe_idx,
                                     char *dev_name)
{
    rbreq->msg_type = TPSA_LM_ROLLBACK_REQ;

    rbreq->content.rbreq.mig_fe_idx = mig_fe_idx;
    (void)memcpy(rbreq->content.rbreq.dev_name, dev_name, TPSA_MAX_DEV_NAME);
}

int uvs_lm_handle_rollback(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_mig_req_t *nlreq = (tpsa_nl_mig_req_t *)nlmsg->data;
    int ret = 0;

    TPSA_LOG_INFO("lm initiator handle rollback, fe_idx is %u", nlreq->mig_fe_idx);
    /* TODO: modify local vtp table */

    tpsa_sock_msg_t *rbreq = calloc(1, sizeof(tpsa_sock_msg_t));
    if (rbreq == NULL) {
        TPSA_LOG_ERR("Fail to alloc socket msg");
        return -1;
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

    uvs_lm_rollback_req_init(rbreq, nlreq->mig_fe_idx, nlreq->dev_name);

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
    tpsa_nl_mig_req_t *rbreq = &msg->content.rbreq;

    TPSA_LOG_INFO("lm handle rollback req, fe_idx is %u", rbreq->mig_fe_idx);
    /* Lookup sip and vport entry */
    tpsa_net_addr_t sip = {0};
    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry when handle lm req");
        return -1;
    }
    vport_key_t vport_key = {0};
    vport_key.fe_idx = rbreq->mig_fe_idx;
    (void)memcpy(vport_key.dev_name, rbreq->dev_name, TPSA_MAX_DEV_NAME);
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

int uvs_lm_handle_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
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

int uvs_lm_vtp_table_iterative_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req)
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
            TPSA_LOG_ERR("live migrate message copy failed, when  full_migrate is false.\n");
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

int uvs_lm_vtp_table_full_migrate(fe_table_entry_t *fe_entry, tpsa_sock_msg_t *req)
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