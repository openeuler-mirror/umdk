/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs tp connection management file
 * Author: LI Yuxing
 * Create: 2023-8-21
 * Note:
 * History:
 */

#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "tpsa_log.h"
#include "tpsa_types.h"
#include "uvs_tp_manage.h"

#define UVS_MAX_IPV4_BIT_LEN 32
#define UVS_MAX_IPV6_BIT_LEN 128
#define UVS_MAX_CNA_LEN 16

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

    free(nlresp);
    TPSA_LOG_INFO("Finish fast NETLINK response vtpn to ubcore\n");

    return 0;
}

int uvs_response_create(uint32_t vtpn, tpsa_sock_msg_t *msg, tpsa_nl_ctx_t *nl_ctx)
{
    tpsa_nl_msg_t *nlresp = tpsa_nl_create_vtp_resp(vtpn, msg);
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

    free(nlresp);

    return 0;
}

static int uvs_remove_tpg_table(tpsa_transport_mode_t trans_mode, tpsa_tpg_table_index_t *tpg_idx,
                                tpsa_table_t *table_ctx, uint32_t *tpn, bool *del_tp_state_tbl)
{
    int32_t find_tpgn = -1;
    bool del_tp_state_tbl_ = false;

    if (trans_mode == TPSA_TP_RM) {
        rm_tpg_table_key_t k = {
            .dip = tpg_idx->dip,
        };

        rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(&table_ctx->rm_tpg_table, &k);
        if (entry != NULL && (entry->use_cnt - 1) == 0) {
            (void)memcpy(tpn, entry->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
            del_tp_state_tbl_ = true;
        }

        find_tpgn = tpsa_remove_rm_tpg_table(entry, &table_ctx->rm_tpg_table);
    } else if (trans_mode == TPSA_TP_RC) {
        rc_tpg_table_key_t k = {
            .deid = tpg_idx->peer_eid,
            .djetty_id = tpg_idx->djetty_id,
        };

        rc_tpg_table_entry_t *entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, &k);
        if ((entry == NULL) && (tpg_idx->isLoopback)) {
            k.deid = tpg_idx->local_eid;
            k.djetty_id = tpg_idx->ljetty_id;

            entry = rc_tpg_table_lookup(&table_ctx->rc_tpg_table, &k);
        }

        if (entry != NULL && (entry->use_cnt - 1) == 0) {
            (void)memcpy(tpn, entry->tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
            del_tp_state_tbl_ = true;
        }

        find_tpgn = tpsa_remove_rc_tpg_table(entry, tpg_idx, &table_ctx->rc_tpg_table);
    }

    if ((find_tpgn < 0) && (find_tpgn != TPSA_REMOVE_DUPLICATE)) {
        TPSA_LOG_ERR("Failed to remove %s tpg table when destroy vtp\n", (trans_mode == TPSA_TP_RM) ? "rm" : "rc");
    } else {
        if (find_tpgn == TPSA_REMOVE_DUPLICATE) {
            TPSA_LOG_INFO("Remove one duplicate tpgn from %s tpg table when destroy vtp\n",
                          (trans_mode == TPSA_TP_RM) ? "rm" : "rc");
        } else {
            if (del_tp_state_tbl_) {
                *del_tp_state_tbl = true;
            }
            TPSA_LOG_INFO("Remove tpgn %d from %s tpg table when destroy vtp\n", find_tpgn,
                          (trans_mode == TPSA_TP_RM) ? "rm" : "rc");
        }
    }

    return find_tpgn;
}

static void destroy_tpg_error_process(tpsa_tpg_table_index_t *tpg_idx, uint32_t find_tpgn,
                                      tpsa_table_t *table_ctx, uint32_t *tpn,
                                      tpg_exception_state_t tpg_state)
{
    uint32_t tp_cnt = tpg_idx->tp_cnt;

    if (tpg_idx->trans_mode == TPSA_TP_RC) {
        tp_cnt = TPSA_MIN_TP_NUM;
    }

    /* when tpg is destroyed, remove the entries recorded in tp state table corresponding to this tpg. */
    for (uint32_t i = 0; i < tp_cnt; i++) {
        tp_state_table_key_t key = {
            .tpn = tpn[i],
            .local_dev_eid = tpg_idx->sip.eid
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
        .tpgn = find_tpgn,
        .local_dev_eid = tpg_idx->sip.eid
    };

    tpg_state_table_entry_t *tpg_entry = tpg_state_table_lookup(&table_ctx->tpg_state_table, &tpg_key);
    if (tpg_entry != NULL) {
        TPSA_LOG_WARN("tpg %u already del process \n", find_tpgn);
    } else {
        tpg_state_table_entry_t add_tpg_entry = {0};
        add_tpg_entry.tpg_exc_state = tpg_state;
        add_tpg_entry.tp_cnt = tp_cnt;
        add_tpg_entry.tp_flush_cnt = tp_cnt;
        add_tpg_entry.tpgn = find_tpgn;
        tpg_entry = tpg_state_table_add(&table_ctx->tpg_state_table, &tpg_key, &add_tpg_entry);
        if (tpg_entry == NULL) {
            TPSA_LOG_WARN("tpg_entry alloc failed \n");
        }
    }
}

void uvs_table_remove_initiator(int32_t *vtpn, int32_t *tpgn, tpsa_tpg_table_index_t *tpg_idx,
                                tpsa_msg_t *msg, tpsa_table_t *table_ctx)
{
    int32_t find_vtpn = -1;
    int32_t find_tpgn = -1;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)msg->data;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP] = {0};
    bool del_tp_state_tbl = false;

    tpsa_vtp_table_index_t vtp_idx = {0};
    vtp_idx.local_eid = nlreq->local_eid,
    vtp_idx.peer_eid = nlreq->peer_eid,
    vtp_idx.peer_jetty = nlreq->peer_jetty,
    vtp_idx.local_jetty = nlreq->local_jetty,
    vtp_idx.location = TPSA_INITIATOR,
    vtp_idx.isLoopback = tpg_idx->isLoopback,
    vtp_idx.upi = tpg_idx->upi,
    vtp_idx.sig_loop = tpg_idx->sig_loop,
    vtp_idx.fe_key.fe_idx = msg->hdr.ep.src_function_id;
    (void)memcpy(vtp_idx.fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    /* Remove vtpn from vtp table */
    find_vtpn = tpsa_remove_vtp_table(nlreq->trans_mode, &vtp_idx, table_ctx);
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

    /* Remove tpgn from tpg table */
    find_tpgn = uvs_remove_tpg_table(nlreq->trans_mode, tpg_idx, table_ctx, tpn, &del_tp_state_tbl);
    if (del_tp_state_tbl) {
        destroy_tpg_error_process(tpg_idx, (uint32_t)find_tpgn, table_ctx, tpn, INITIATOR_TPG_STATE_DEL);
    }

    *vtpn = find_vtpn;
    *tpgn = find_tpgn;
}

void uvs_table_remove_target(int32_t *vtpn, int32_t *tpgn, tpsa_tpg_table_index_t *tpg_idx,
                             tpsa_sock_msg_t *msg, tpsa_table_t *table_ctx)
{
    int32_t find_vtpn = -1;
    int32_t find_tpgn = -1;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP] = {0};
    bool del_tp_state_tbl = false;
    uint32_t eid_idx;

    tpsa_vtp_table_index_t vtp_idx = {0};
    vtp_idx.local_eid = msg->peer_eid;
    vtp_idx.peer_eid = msg->local_eid;
    vtp_idx.peer_jetty = msg->local_jetty;
    vtp_idx.location = TPSA_TARGET;
    vtp_idx.isLoopback = false;
    vtp_idx.upi = UINT32_MAX;
    vtp_idx.sig_loop = false; /* for target don't care */

    if (vport_table_lookup_by_ueid_return_key(&table_ctx->vport_table, msg->upi, &msg->peer_eid,
        &vtp_idx.fe_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid, upi %u, eid_idx is %u, eid:"EID_FMT"\n",
                      msg->upi, eid_idx, EID_ARGS(msg->peer_eid));
        return;
    }

    TPSA_LOG_INFO("destroy vtp dev:%s fe_idx %hu\n", vtp_idx.fe_key.dev_name, vtp_idx.fe_key.fe_idx);

    /* Remove vtpn from vtp table */
    find_vtpn = tpsa_remove_vtp_table(msg->trans_mode, &vtp_idx, table_ctx);
    switch (find_vtpn) {
        case TPSA_REMOVE_INVALID:
            /* return when vtp is invalid */
            TPSA_LOG_WARN("Try to remove a vtp entry which is in progess.\n");
            *vtpn = find_vtpn;
            return;
        case TPSA_LOOKUP_NULL:
            TPSA_LOG_INFO("Failed to remove vtp table when destroy target vtp\n");
            break;
        case TPSA_REMOVE_SERVER:
        default:
            *vtpn = find_vtpn;
            TPSA_LOG_INFO("Remove vtpn %d from vtp table when destroy target vtp\n", find_vtpn);
    }
    /* TODO: confirm vtpn = nlreq->vtpn */

    /* Remove tpgn from tpg table */
    find_tpgn = uvs_remove_tpg_table(msg->trans_mode, tpg_idx, table_ctx, tpn, &del_tp_state_tbl);
    if (del_tp_state_tbl) {
        destroy_tpg_error_process(tpg_idx, (uint32_t)find_tpgn, table_ctx, tpn, INITIATOR_TPG_STATE_DEL);
    }

    *vtpn = find_vtpn;
    *tpgn = find_tpgn;
}

void uvs_reverse_lookup_ip(tpsa_sock_msg_t *msg, sip_table_entry_t *sip_entry, tpsa_net_addr_t *dip,
                           urma_eid_t *peer_tpsa_eid, tpsa_table_t *table_ctx)
{
    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));

    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return;
    }

    int res = vport_table_lookup_by_ueid(&table_ctx->vport_table, msg->upi, &msg->peer_eid, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by upi %u eid:"EID_FMT"\n", msg->upi, EID_ARGS(msg->peer_eid));
        free(vport_entry);
        return;
    }
    tpsa_lookup_sip_table(vport_entry->sip_idx, sip_entry, &table_ctx->sip_table);
    tpsa_lookup_dip_table(&table_ctx->dip_table, msg->local_eid, peer_tpsa_eid, dip);

    free(vport_entry);
}

int uvs_handle_last_lm_req(uvs_ctx_t *ctx, fe_table_entry_t *fe_entry)
{
    int res = -1;

    tpsa_sock_msg_t *msg = calloc(1, sizeof(tpsa_sock_msg_t));
    if (msg == NULL) {
        TPSA_LOG_ERR("Fail to create lm resp msg");
        return -1;
    }

    msg->msg_type = TPSA_LM_RESP;
    msg->content.lm_resp.last_mig_completed = true;
    /* The vf and dev_name of the migration source are sent by sock_message. */
    msg->content.lm_resp.mig_fe_idx = fe_entry->lm_fe_idx;
    (void)memcpy(msg->content.lm_resp.dev_name, fe_entry->lm_dev_name, TPSA_MAX_DEV_NAME);
    res = tpsa_sock_send_msg(ctx->sock_ctx, msg, sizeof(tpsa_sock_msg_t), fe_entry->mig_source);
    if (res < 0) {
        TPSA_LOG_ERR("Failed to send a message to the mig source that the chain reconstruction is completed\n");
        free(msg);
        return res;
    }

    TPSA_LOG_INFO("when the migration des completes the chain reconstruction send socket msg to source success.\n");
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

    return 0;
}

int uvs_handle_table_sync(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_table_sync_t *sync = &msg->content.tsync;
    urma_eid_t peer_tpsa_eid = {0};
    tpsa_net_addr_t dip = {0};
    uint32_t location = TPSA_TARGET;
    tpsa_tpg_status_t status;
    tpsa_tpg_info_t tpg;

    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, msg->local_eid, &peer_tpsa_eid, &dip);

    tpsa_tpg_table_index_t tpg_idx = {0};
    tpg_idx.dip = dip;
    tpg_idx.local_eid = msg->peer_eid;
    tpg_idx.peer_eid = msg->local_eid;
    tpg_idx.ljetty_id = msg->peer_jetty;
    tpg_idx.djetty_id = msg->local_jetty;
    tpg_idx.isLoopback = false;

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u, dst eid "EID_FMT", djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid),
                  msg->peer_jetty);

    status = tpsa_lookup_tpg_table(&tpg_idx, msg->trans_mode, ctx->table_ctx, &tpg);
    if (status != TPSA_TPG_LOOKUP_EXIST) {
        TPSA_LOG_ERR("Wrong tpg number find when sync table");
        return -1;
    }

    if (sync->opcode == TPSA_TABLE_ADD) {
        if (uvs_table_update(UINT32_MAX, tpg.tpgn, location, msg, ctx->table_ctx) < 0) {
            TPSA_LOG_ERR("Fail to sync table in target.");
            return -1;
        }
        vport_key_t fe_key = {0};
        uint32_t eid_idx;
        if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->peer_eid,
                                                  &fe_key, &eid_idx) != 0) {
            TPSA_LOG_INFO("vport_table_lookup_by_ueid failed, upi is %u, eid_idx is %u,  eid:"EID_FMT"\n",
                           msg->upi, eid_idx, EID_ARGS(msg->local_eid));
            return -1;
        }
        if (uvs_create_resp_to_lm_src(ctx, fe_key) != 0) {
            TPSA_LOG_ERR("uvs create resp to livemigrate source failed");
            return -1;
        }
    }

    return 0;
}

int uvs_map_vtp(tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_create_param_t *cparam, uint32_t number,
                tpsa_net_addr_t *sip, uint32_t *vtpn)
{
    /* IOCTL to create vtp; */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create map vtp request");
        return -1;
    }

    tpsa_ioctl_cmd_map_vtp(cfg, cparam, number, sip);
    if (tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to map vtp in worker");
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
    (void)memcpy(fe_key.dev_name, cparam->dev_name, TPSA_MAX_DEV_NAME);

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
    };

    res = um_fe_vtp_table_add(&table_ctx->fe_table, &fe_key, &um_vtp_key, &uvtp_param);
    if (res < 0) {
        tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            TPSA_LOG_ERR("Fail to create vtp mapping rollback request");
            return -1;
        }

        tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->sip, cparam->trans_mode,
            cparam->local_eid,  cparam->peer_eid,  cparam->peer_jetty);
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
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to destroy utp request");
        return -1;
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
int uvs_create_utp(uvs_ctx_t *ctx, vport_table_entry_t *vport_entry,
                   tpsa_create_param_t *cparam, uvs_create_utp_param_t *uparam)
{
    int ret;
    um_vtp_table_key_t um_vtp_key;

    vport_key_t fe_key = {0};
    fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(fe_key.dev_name, cparam->dev_name, TPSA_MAX_DEV_NAME);

    /* IOCTL to create utp; */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create utp request");
        return -1;
    }

    tpsa_ioctl_cmd_create_utp(cfg, vport_entry, cparam, &uparam->key);
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
    };

    ret = um_fe_vtp_table_add(&ctx->table_ctx->fe_table, &fe_key, &um_vtp_key, &uvtp_param);
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
    return 0;

REMOVE_VTP_TABLE:
    (void)um_vtp_table_remove(&ctx->table_ctx->fe_table, &fe_key, &um_vtp_key);
ROLL_BACK:
    /* roll back vtp first */
    (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->key.sip, cparam->trans_mode,
        cparam->local_eid, cparam->peer_eid, cparam->peer_jetty);
    (void)tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg);
    free(cfg);

    /* roll back utp */
    (void)uvs_destroy_utp(ctx->ioctl_ctx, ctx->table_ctx, &uparam->key, utpn);
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
    (void)memcpy(fe_key.dev_name, cparam->dev_name, TPSA_MAX_DEV_NAME);
    ret = clan_fe_vtp_table_add(&table_ctx->fe_table, &fe_key, &clan_vtp_key, &clan_vtp_param);
    if (ret < 0) {
        tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            TPSA_LOG_ERR("Fail to create clan vtp mapping rollback request");
            return -1;
        }

        tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->sip, cparam->trans_mode, cparam->local_eid, cparam->peer_eid,
                                   cparam->peer_jetty);
        (void)tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
        free(cfg);
        return ret;
    }

    ctp_table_entry->use_cnt++;
    return 0;
}

int uvs_create_um_vtp_base(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, vport_table_entry_t *vport_entry,
                           uint32_t *vtpn)
{
    int res = -1;
    utp_table_key_t utp_key = {0};
    urma_eid_t peer_tpsa_eid = {0};
    sip_table_entry_t sip_entry = {0};

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    utp_key.sip = sip_entry.addr;
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid, &peer_tpsa_eid, &utp_key.dip);

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

        res = uvs_create_utp(ctx, vport_entry, cparam, &uparam);
    }

    return res;
}

int uvs_create_um_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->data;
    sip_table_entry_t sip_entry = {0};
    um_vtp_table_key_t um_vtp_key;

    uint32_t vtpn;
    int res = 0;

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    um_vtp_key.src_eid = nlreq->local_eid;
    um_vtp_key.dst_eid = nlreq->peer_eid;

    um_vtp_table_entry_t *entry = um_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &fe_key, &um_vtp_key);
    if (entry != NULL) {
        entry->use_cnt++;
        vtpn = entry->vtpn;
        TPSA_LOG_INFO("vtp already exist return vtpn %d, use cnt %u", vtpn, entry->use_cnt);
        goto NL_RETURN;
    }

    res = tpsa_lookup_vport_table(&fe_key,
                                  &ctx->table_ctx->vport_table,
                                  vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", nlmsg->hdr.ep.src_function_id);
        free(vport_entry);
        return -1;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    tpsa_create_param_t cparam = {
        .trans_mode = nlreq->trans_mode,
        .dip = {0},
        .local_eid = nlreq->local_eid,
        .peer_eid = nlreq->peer_eid,
        .local_jetty = nlreq->local_jetty,
        .peer_jetty = nlreq->peer_jetty,
        .eid_index = nlreq->eid_index,
        .fe_idx = nlmsg->hdr.ep.src_function_id,
        .vtpn = nlreq->vtpn,
        .liveMigrate = false,
        .migrateThird = false,
        .clan_tp = false,
        .msg_id = nlmsg->hdr.msg_id,
        .nlmsg_seq = msg->nlmsg_seq,
        .upi = UINT32_MAX,
        .sig_loop = false, /* to do, need to adapt to loopback scene  */
        .port_id = sip_entry.port_id[0],
        .global_cfg = ctx->global_cfg_ctx,
        .mtu = sip_entry.mtu,
    };
    (void)memcpy(cparam.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    if (uvs_create_um_vtp_base(ctx, &cparam, vport_entry, &vtpn) < 0) {
        TPSA_LOG_ERR("Fail to create or map vtp um.");
        free(vport_entry);
        return -1;
    }

NL_RETURN:
    if (uvs_response_create_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_SUCCESS, vtpn) < 0) {
        TPSA_LOG_ERR("Fail to response nl response in um.");
        free(vport_entry);
        return -1;
    }

    free(vport_entry);
    return 0;
}

int uvs_destroy_um_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;
    urma_eid_t peer_tpsa_eid;
    utp_table_key_t utp_key = {0};
    sip_table_entry_t sip_entry = {0};
    um_vtp_table_key_t um_vtp_key;
    uint32_t utp_idx;
    uint32_t vtpn;
    int res = 0;

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    um_vtp_key.src_eid = nlreq->local_eid;
    um_vtp_key.dst_eid = nlreq->peer_eid;

    um_vtp_table_entry_t *um_vtp_entry = um_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &fe_key, &um_vtp_key);
    if (um_vtp_entry == NULL) {
        TPSA_LOG_ERR("Fail to find vtp table by key destroy vtp request");
        free(vport_entry);
        return -1;
    }

    vtpn = um_vtp_entry->vtpn;

    um_vtp_entry->use_cnt--;
    if (um_vtp_entry->use_cnt != 0) {
        TPSA_LOG_INFO("ioctl to destroy um vtp in worker success, other jetty in use it, vtpn:%u, use cnt:%u",
            vtpn, um_vtp_entry->use_cnt);

        tpsa_nl_msg_t *nlresp = tpsa_nl_destroy_vtp_resp(msg, TPSA_NL_RESP_SUCCESS);
        if (nlresp == NULL) {
            TPSA_LOG_INFO("Get tpsa NETLINK destroy vtp resp failed\n");
            free(vport_entry);
            return -1;
        }

        if (tpsa_nl_send_msg(ctx->nl_ctx, nlresp) != 0) {
            TPSA_LOG_INFO("Send tpsa NETLINK destroy vtp resp failed\n");
            res = -1;
        }

        free(vport_entry);
        free(nlresp);
        return res;
    }

    res = tpsa_lookup_vport_table(&fe_key,
                                  &ctx->table_ctx->vport_table,
                                  vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", nlmsg->hdr.ep.src_function_id);
        free(vport_entry);
        return -1;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    utp_key.sip = sip_entry.addr;
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid, &peer_tpsa_eid, &utp_key.dip);

    free(vport_entry);

    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to alloc destroy vtp request ");
        return -1;
    }

    tpsa_ioctl_cmd_destroy_vtp(cfg, &utp_key.sip, nlreq->trans_mode,
        nlreq->local_eid, nlreq->peer_eid, nlreq->peer_jetty);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy vtp in worker");
        free(cfg);
        return -1;
    }

    free(cfg);
    /* todonext failed rollback? */
    (void)um_vtp_table_remove(&ctx->table_ctx->fe_table, &fe_key, &um_vtp_key);

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
    }

    TPSA_LOG_INFO("ioctl to destroy um vtp in worker success, vtpn:%u, utp_idx:%u",
        vtpn, utp_idx);

    tpsa_nl_msg_t *nlresp = tpsa_nl_destroy_vtp_resp(msg, (tpsa_nl_resp_status_t)res);
    if (nlresp == NULL) {
        TPSA_LOG_INFO("Get tpsa NETLINK destroy vtp resp failed\n");
        return -1;
    }

    if (tpsa_nl_send_msg(ctx->nl_ctx, nlresp) != 0) {
        TPSA_LOG_INFO("Send tpsa NETLINK destroy vtp resp failed\n");
        free(nlresp);
        return -1;
    }

    free(nlresp);
    TPSA_LOG_INFO("Finish NETLINK tp ubcore when destroy um vtp\n");
    return 0;
}

int uvs_create_clan_vtp_base(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, vport_key_t *fe_key, uint32_t *vtpn)
{
    sip_table_entry_t sip_entry = { 0 };
    int ret = tpsa_lookup_vport_sip(fe_key, ctx->table_ctx, &sip_entry);
    if (ret < 0) {
        return ret;
    }

    ctp_table_key_t ctp_key = { 0 };
    urma_eid_t peer_tpsa_eid;
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid, &peer_tpsa_eid, &ctp_key.dip);

    ctp_table_entry_t *ctp_table_entry = ctp_table_lookup(&ctx->table_ctx->ctp_table, &ctp_key);
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
            .vtpn = vtpn,
            .prefix_len = sip_entry.prefix_len,
        };
        ret = uvs_create_ctp(ctx->ioctl_ctx, ctx->table_ctx, cparam, &uparam);
    }

    return ret;
}

int uvs_create_clan_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->data;
    uint32_t vtpn;
    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    clan_vtp_table_key_t clan_vtp_key = { .dst_eid = nlreq->peer_eid };
    clan_vtp_table_entry_t *entry = clan_fe_vtp_table_lookup(&ctx->table_ctx->fe_table, &fe_key, &clan_vtp_key);
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

    tpsa_create_param_t cparam = {
        .trans_mode = nlreq->trans_mode,
        .dip = {0},
        .local_eid = nlreq->local_eid,
        .peer_eid = nlreq->peer_eid,
        .local_jetty = nlreq->local_jetty,
        .peer_jetty = nlreq->peer_jetty,
        .eid_index = nlreq->eid_index,
        .fe_idx = nlmsg->hdr.ep.src_function_id,
        .vtpn = nlreq->vtpn,
        .liveMigrate = false,
        .migrateThird = false,
        .clan_tp = true,
        .msg_id = nlmsg->hdr.msg_id,
        .nlmsg_seq = msg->nlmsg_seq,
        .upi = UINT32_MAX,
        .sig_loop = false, /* to do, need to adapt to loopback scene  */
    };
    (void)memcpy(cparam.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);
    (void)memcpy(cparam.local_tpf_name, nlreq->tpfdev_name, TPSA_MAX_DEV_NAME);

    if (uvs_create_clan_vtp_base(ctx, &cparam, &fe_key, &vtpn) < 0) {
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
                    ctp_table_key_t *key, tpsa_net_addr_t *sip, uint32_t ctp_idx)
{
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to calloc ioctl cfg");
        return -1;
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

static uint32_t uvs_get_cna_len(tpsa_net_addr_t *sip, uint32_t prefix_len)
{
    /* ipv4 */
    if (sip->type == TPSA_NET_ADDR_TYPE_IPV4) {
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
    (void)memcpy(fe_key.dev_name, cparam->dev_name, TPSA_MAX_DEV_NAME);

    /* IOCTL to create ctp; */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create ctp request");
        return -1;
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
    (void) memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    tpsa_ioctl_cmd_destroy_vtp(cfg, &uparam->sip, cparam->trans_mode,
                               cparam->local_eid, cparam->peer_eid, cparam->peer_jetty);
    (void) tpsa_ioctl(ioctl_ctx->ubcore_fd, cfg);
    free(cfg);

     /* roll back ctp */
    (void)uvs_destroy_ctp(ioctl_ctx, table_ctx, &uparam->key, &uparam->sip, ctpn);
    return -1;
}

static int uvs_reduce_ctp_use_cnt(uvs_ctx_t *ctx, ctp_table_key_t *ctp_key, tpsa_net_addr_t *sip, uint32_t vtpn)
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

int uvs_destroy_clan_vtp_base(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, vport_key_t *fe_key,
                              clan_vtp_table_key_t *clan_vtp_key, uint32_t vtpn)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;

    sip_table_entry_t sip_entry = { 0 };
    urma_eid_t peer_tpsa_eid;
    int ret = tpsa_lookup_vport_sip(fe_key, ctx->table_ctx, &sip_entry);
    if (ret < 0) {
        return ret;
    }

    ctp_table_key_t ctp_key = {0};
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid, &peer_tpsa_eid, &ctp_key.dip);
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to alloc destroy vtp request ");
        return -1;
    }

    tpsa_ioctl_cmd_destroy_vtp(cfg, &sip_entry.addr, nlreq->trans_mode, nlreq->local_eid, nlreq->peer_eid,
                               nlreq->peer_jetty);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to destroy vtp in worker");
        free(cfg);
        return -1;
    }
    free(cfg);

    /* todonext failed rollback? */
    (void)clan_vtp_table_remove(&ctx->table_ctx->fe_table, fe_key, clan_vtp_key);

    ret = uvs_reduce_ctp_use_cnt(ctx, &ctp_key, &sip_entry.addr, vtpn);
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

int uvs_destroy_clan_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;
    int ret = 0;
    vport_key_t fe_key = { 0 };
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    clan_vtp_table_key_t clan_vtp_key = { .dst_eid = nlreq->peer_eid };
    clan_vtp_table_entry_t *clan_vtp_entry = clan_fe_vtp_table_lookup(&ctx->table_ctx->fe_table,
                                                                      &fe_key, &clan_vtp_key);
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

    ret = uvs_destroy_clan_vtp_base(ctx, msg, &fe_key, &clan_vtp_key, vtpn);
    if (ret < 0) {
        TPSA_LOG_WARN("create clan vtp failed");
    }
    return ret;
}

int uvs_sync_table(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, urma_eid_t *peer_tpsa_eid)
{
    int32_t upi = tpsa_get_upi(cparam->dev_name, cparam->fe_idx, cparam->eid_index,
                               &ctx->table_ctx->vport_table);
    if (upi < 0) {
        TPSA_LOG_ERR("Fail to get upi when init create msg!!! Use upi = 0 instead.");
        upi = 0;
    }

    tpsa_sock_msg_t *tsync = tpsa_sock_init_table_sync(cparam, UINT32_MAX, TPSA_TABLE_ADD,
                                                       (uint32_t)upi, &ctx->table_ctx->vport_table);
    if (tpsa_sock_send_msg(ctx->sock_ctx, tsync, sizeof(tpsa_sock_msg_t), *peer_tpsa_eid) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp req in worker\n");
        free(tsync);
        return -1;
    }
    free(tsync);
    TPSA_LOG_WARN("Sync table with target when tpg already exists. Socket msg success.\n");

    return 0;
}

int uvs_create_vtp_reuse_tpg(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, tpsa_net_addr_t *sip,
                             tpsa_vtp_table_param_t *vtp_table_data)
{
    urma_eid_t peer_tpsa_eid = {0};
    tpsa_net_addr_t dip = {0};
    bool isLoopback = false;

    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid, &peer_tpsa_eid, &dip);

    uvs_end_point_t local = { *sip, cparam->local_eid, cparam->local_jetty };
    uvs_end_point_t peer = { dip, cparam->peer_eid, cparam->peer_jetty };
    isLoopback = uvs_is_loopback(cparam->trans_mode, &local, &peer);

    TPSA_LOG_INFO("Reuse tpg %d when we create vtp.", vtp_table_data->tpgn);

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
    tpg_data.dip = dip;
    tpg_data.isLoopback = isLoopback;

    if (uvs_table_add(cparam, ctx->table_ctx, &tpg_data, vtp_table_data) < 0) {
        TPSA_LOG_ERR("Failed to add table when create vtp and tpg already exists\n");
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(fe_key.dev_name, cparam->dev_name, TPSA_MAX_DEV_NAME);

    if (uvs_create_resp_to_lm_src(ctx, fe_key) != 0) {
        TPSA_LOG_ERR("uvs create resp to livemigrate source failed");
        return -1;
    }

    /* Sync table with target */
    if (!isLoopback) {
        if (uvs_sync_table(ctx, cparam, &peer_tpsa_eid) < 0) {
            TPSA_LOG_ERR("Fail to sync table when reuse tpg");
            return -1;
        }
    }

    return 0;
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
            cc_result_array[j].alg = cc_info_array[i].alg;
            cc_result_array[j].cc_priority = cc_info_array[i].cc_priority;
            cc_result_array[j].set_cc_priority = set_cc_priority;
            cc_result_array[j].cc_pattern_idx = cc_info_array[i].cc_pattern_idx;
            j++;
        }
    }
    *cc_array_cnt = j;

    return j == 0 ? -1 : 0;
}

int uvs_create_lb_vtp(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, tpsa_ioctl_cfg_t *cfg,
                      tpsa_net_addr_t *dip, vport_table_entry_t *vport_entry)
{
    tpsa_cmd_create_tpg_t *cmd = calloc(1, sizeof(tpsa_cmd_create_tpg_t));
    tpf_dev_table_entry_t tpf_dev_table_entry;
    if (cmd == NULL) {
        return -1;
    }

    (void)memcpy(cmd, &cfg->cmd.create_tpg, sizeof(tpsa_cmd_create_tpg_t));
    (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));

    tpsa_init_vtp_cmd_param_t param = {0};
    param.sip = *dip;
    param.local_tp_cfg = vport_entry->tp_cfg;
    param.mtu = cparam->mtu;
    param.cc_pattern_idx = vport_entry->tp_cfg.cc_pattern_idx;
    param.udp_range = vport_entry->tp_cfg.udp_range;
    param.local_net_addr_idx = vport_entry->sip_idx;
    param.flow_label = vport_entry->tp_cfg.flow_label;
    param.tp_cnt = vport_entry->tp_cnt;

    TPSA_LOG_INFO("Loop back :lookup tpf dev table using tpf name %s", cparam->local_tpf_name);
    int ret = tpsa_lookup_tpf_dev_table(cparam->local_tpf_name, &ctx->table_ctx->tpf_dev_table, &tpf_dev_table_entry);
    if (ret != 0) {
        TPSA_LOG_WARN("Failed to lookup tpf dev table");
    } else {
        if (tpsa_get_cc_query_result(tpf_dev_table_entry, &param.local_tp_cfg,
            &param.cc_array_cnt, param.cc_result_array) != 0) {
            param.local_tp_cfg.tp_mod_flag.bs.cc_en = 0;
            TPSA_LOG_WARN("Local side: cannot get cc query result given cc priority-%hhu and algorithm-%hu",
                param.local_tp_cfg.cc_priority, param.local_tp_cfg.cc_alg);
        }
    }

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
bool uvs_rc_check_ljetty(uint32_t ljetty_id, urma_eid_t *local_eid,
                         tpsa_transport_mode_t trans_mode, tpsa_table_t *table_ctx)
{
    if (trans_mode != TPSA_TP_RC) {
        return false;
    }

    jetty_peer_table_key_t key = {
        .ljetty_id = ljetty_id,
        .seid = *local_eid,
    };

    jetty_peer_table_entry_t *entry = jetty_peer_table_lookup(&table_ctx->jetty_peer_table, &key);
    if (entry == NULL) {
        return false;
    }

    TPSA_LOG_WARN("local jetty %u, leid:"EID_FMT" already connect by remote jetty %u, deid:"EID_FMT"\n",
                  ljetty_id, EID_ARGS(*local_eid), entry->djetty_id, EID_ARGS(entry->deid));
    return true;
}

int uvs_rc_valid_check(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, bool isLoopback)
{
    if (uvs_rc_check_ljetty(cparam->local_jetty, &cparam->local_eid,
                            cparam->trans_mode, ctx->table_ctx)) {
        return -1;
    }

    if (isLoopback) {
        if (uvs_rc_check_ljetty(cparam->peer_jetty, &cparam->local_eid,
                                cparam->trans_mode, ctx->table_ctx)) {
            return -1;
        }
    }

    return 0;
}

int uvs_create_vtp_preprocess(uvs_ctx_t *ctx, tpsa_create_param_t *cparam, tpsa_net_addr_t *sip,
                              tpsa_tpg_table_index_t *tpg_idx, uvs_nl_resp_info_t *nl_resp)
{
    tpsa_vtp_table_param_t vtp_table_data = {0};
    tpsa_tpg_info_t tpg;
    tpsa_tpg_status_t res = 0;

    res = tpsa_lookup_tpg_table(tpg_idx, cparam->trans_mode, ctx->table_ctx, &tpg);
    if (res == TPSA_TPG_LOOKUP_EXIST) {
        vtp_table_data.tpgn = tpg.tpgn;
        if (uvs_create_vtp_reuse_tpg(ctx, cparam, sip, &vtp_table_data) < 0) {
            TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
            return -1;
        }

        /* nl_resp */
        nl_resp->resp = true;
        nl_resp->status = TPSA_NL_RESP_SUCCESS;
        nl_resp->vtpn = vtp_table_data.vtpn;
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
        nl_resp->status = TPSA_RC_JETTY_ALREADY_BIND;
        nl_resp->vtpn = UINT32_MAX;

        return 0;
    } else if (res == TPSA_TPG_LOOKUP_NULL) {
        if (uvs_rc_valid_check(ctx, cparam, tpg_idx->isLoopback) < 0) {
            /* nl_resp */
            nl_resp->resp = true;
            nl_resp->status = TPSA_RC_JETTY_ALREADY_BIND;
            nl_resp->vtpn = UINT32_MAX;

            return 0;
        }

        // need to create new tpg
        return 0;
    }
    return 0;
}

int uvs_create_vtp_base(uvs_ctx_t *ctx, tpsa_create_param_t *cparam,
                        tpsa_tpg_table_index_t *tpg_idx, uvs_nl_resp_info_t *nl_resp)
{
    tpsa_vtp_table_param_t vtp_table_data = {0};
    tpsa_tpg_table_param_t tpg_data = {0};
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    jetty_peer_table_param_t parm = {0};
    urma_eid_t peer_tpsa_eid = {0};
    tpf_dev_table_entry_t tpf_dev_table_entry;

    int res = -1;

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = cparam->fe_idx;
    (void)memcpy(fe_key.dev_name, cparam->dev_name, TPSA_MAX_DEV_NAME);

    res = tpsa_lookup_vport_table(&fe_key, &ctx->table_ctx->vport_table, vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key dev:%s-%hu\n", fe_key.dev_name, fe_key.fe_idx);
        free(vport_entry);
        return -1;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);

    if (cparam->liveMigrate && cparam->migrateThird) {
        dip = cparam->dip;
        peer_tpsa_eid = cparam->dip.eid;
    } else {
        tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, cparam->peer_eid, &peer_tpsa_eid, &dip);
    }

    if (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_create_vtp_preprocess(ctx, cparam, &sip_entry.addr, tpg_idx, nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to preprocess create vtp req");
        free(vport_entry);
        return -1;
    }

    if (nl_resp->resp == true || nl_resp->status == TPSA_NL_RESP_IN_PROGRESS) {
        /* don't need to create new tpg */
        free(vport_entry);
        return 0;
    }

    /* IOCTL to create TPG; construct tp_param according to create output */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create tpg request");
        free(vport_entry);
        return -1;
    }

    tpsa_ioctl_cmd_create_tpg(cfg, cparam, sip_entry.addr, vport_entry);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to create tpg in worker");
        free(cfg);
        free(vport_entry);
        return -1;
    }
    TPSA_LOG_INFO("-------------------create tpgn: %d, tpn: %d in initiator.\n",
        cfg->cmd.create_tpg.out.tpgn, cfg->cmd.create_tpg.out.tpn[0]);
    cparam->udrv_ext_len = cfg->cmd.create_tpg.udrv_ext.out_len;

    tpg_data.type = 0;
    tpg_data.use_cnt = 1;
    tpg_data.ljetty_id = cparam->local_jetty;
    tpg_data.leid = cparam->local_eid;
    tpg_data.dip = dip;
    tpg_data.isLoopback = tpg_idx->isLoopback;

    if (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB && tpg_idx->isLoopback) {
        /* Loopback create vtp and response netlink */
        if (uvs_create_lb_vtp(ctx, cparam, cfg, &dip, vport_entry) < 0) {
            TPSA_LOG_ERR("Fail to create lb vtp");
            free(cfg);
            free(vport_entry);
            return -1;
        }

        TPSA_LOG_INFO("Finish create lb vtp when create vtp.\n");

        /* Add invalid vtpn to vtp table and tpg table to avoid duplication establish */
        vtp_table_data.vtpn = cfg->cmd.create_vtp.out.vtpn;
        vtp_table_data.valid = true;
        tpg_data.tpgn = cfg->cmd.create_vtp.in.tpgn;
        tpg_data.status = TPSA_TPG_LOOKUP_EXIST;

        parm.seid = cparam->peer_eid;
        parm.ljetty_id = cparam->peer_jetty;
        parm.deid = cparam->local_eid;
        parm.djetty_id = cparam->local_jetty;
        /* Start to add target jetty-peer table */
        if (tpsa_worker_jetty_peer_table_add(ctx->table_ctx, cparam->trans_mode, &parm) < 0) {
            TPSA_LOG_ERR("Fail to add jetty peer table.");
            /* todo rollback? */
            free(cfg);
            free(vport_entry);
            return -1;
        }

        parm.seid = cparam->local_eid;
        parm.ljetty_id = cparam->local_jetty;
        parm.deid = cparam->peer_eid;
        parm.djetty_id = cparam->peer_jetty;
        /* Start to add target jetty-peer table */
        if (tpsa_worker_jetty_peer_table_add(ctx->table_ctx, cparam->trans_mode, &parm) < 0) {
            TPSA_LOG_ERR("Fail to add jetty peer table.");
            /* todo rollback? */
            free(cfg);
            free(vport_entry);
            return -1;
        }

        /* nl_resp */
        nl_resp->resp = true;
        nl_resp->status = TPSA_NL_RESP_SUCCESS;
        nl_resp->vtpn = vtp_table_data.vtpn;
    } else {
        /* Create msg to connect to peer */
        tpsa_init_sock_param_t param = {0};
        param.local_tp_cfg = vport_entry->tp_cfg;
        param.local_tp_cfg.port = cparam->port_id;
        param.peer_net_addr = dip;
        param.local_mtu = (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB ?
            sip_entry.mtu : cfg->cmd.create_tpg.local_mtu);
        param.tpg_cfg = cfg->cmd.create_tpg.in.tpg_cfg;
        param.local_tpn = &cfg->cmd.create_tpg.out.tpn[0];
        param.local_net_addr_idx = vport_entry->sip_idx;
        param.local_seg_size = SEG_SIZE;
        param.upi = (uint32_t)cparam->upi;
        param.tpgn = cfg->cmd.create_tpg.out.tpgn;
        param.tp_cnt = cfg->cmd.create_tpg.in.tpg_cfg.tp_cnt;
        param.cc_en = vport_entry->tp_cfg.tp_mod_flag.bs.cc_en;

        TPSA_LOG_INFO("Lookup tpf dev table using tpf name %s", cparam->local_tpf_name);
        res = tpsa_lookup_tpf_dev_table(cparam->local_tpf_name, &ctx->table_ctx->tpf_dev_table, &tpf_dev_table_entry);
        if (res != 0) {
            TPSA_LOG_WARN("Failed to lookup tpf dev table");
        } else {
            if (tpsa_get_cc_query_result(tpf_dev_table_entry, &param.local_tp_cfg,
                &param.cc_array_cnt, param.cc_result_array) != 0) {
                param.local_tp_cfg.tp_mod_flag.bs.cc_en = 0;
                TPSA_LOG_WARN("Local side: cannot get cc query result given cc priority-%hhu and algorithm-%hu",
                    param.local_tp_cfg.cc_priority, param.local_tp_cfg.cc_alg);
            }
        }

        tpsa_sock_msg_t *req = tpsa_sock_init_create_req(cparam, &param);
        if (req == NULL) {
            TPSA_LOG_ERR("Fail to init create socket msg");
            free(cfg);
            free(vport_entry);
            return -1;
        }
        if (tpsa_sock_send_msg(ctx->sock_ctx, req, sizeof(tpsa_sock_msg_t), peer_tpsa_eid) != 0) {
            TPSA_LOG_ERR("Failed to send create vtp req in worker\n");
            free(req);
            free(cfg);
            free(vport_entry);
            return -1;
        }

        free(req);
        TPSA_LOG_INFO("Finish send socket message from initiator.\n");

        /* Add invalid vtpn to vtp table and tpg table to avoid duplication establish */
        vtp_table_data.vtpn = UINT32_MAX;
        vtp_table_data.valid = false;
        tpg_data.tpgn = cfg->cmd.create_tpg.out.tpgn;
        tpg_data.status = TPSA_TPG_LOOKUP_IN_PROGRESS;
        (void)memcpy(tpg_data.tpn, cfg->cmd.create_tpg.out.tpn,
            TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

        for (uint32_t i = 0; i < TPSA_MAX_TP_CNT_IN_GRP; i++) {
            TPSA_LOG_INFO("tpn get in uvs tpn[%u] = %u.\n", i, tpg_data.tpn[i]);
        }
    }

    free(cfg);
    free(vport_entry);

    vtp_table_data.upi = tpg_idx->upi;
    if (cparam->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_table_add(cparam, ctx->table_ctx, &tpg_data, &vtp_table_data) < 0) {
        TPSA_LOG_ERR("Failed to prefill table when create vtp\n");
        return -1;
    }

    return 0;
}

/* when uvs reveive the message(TPSA_MSG_STOP_PROC_VTP_MSG), */
/* For new link building requests, uvs notifies the ubcore to try again after a period of time. */
int uvs_retry_link_establish(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, bool *stop_proc_vtp)
{
    vport_key_t key = {0};
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->data;

    key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &key);
    if (fe_entry != NULL && fe_entry->stop_proc_vtp == true) {
        *stop_proc_vtp = true;
        tpsa_nl_resp_status_t stat = TPSA_NL_RESP_IN_PROGRESS;
        if (uvs_response_create_fast(msg, ctx->nl_ctx, stat, UINT32_MAX) < 0) {
            TPSA_LOG_ERR("Fail to response nl response when receive a mess to stop processing new connection req\n");
            (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
            return -1;
        }

        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
        return 0;
    }

    *stop_proc_vtp = false;
    return 0;
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

static bool uvs_in_same_subnet_ipv4(tpsa_net_addr_t *sip, tpsa_net_addr_t *dip, uint32_t prefix_len)
{
    uint32_t mask = uvs_make_mask_32(prefix_len);
    return ((sip->eid.in4.addr & mask) == (dip->eid.in4.addr & mask));
}

static bool uvs_in_same_subnet_ipv6(tpsa_net_addr_t *sip, tpsa_net_addr_t *dip, uint32_t prefix_len)
{
    uint64_t mask = uvs_make_mask_64((prefix_len > UINT64_WIDTH) ? (prefix_len - UINT64_WIDTH) : prefix_len);
    if (prefix_len > UINT64_WIDTH) {
        return ((sip->eid.in6.subnet_prefix == dip->eid.in6.subnet_prefix) &&
                ((sip->eid.in6.interface_id & mask) == (dip->eid.in6.interface_id & mask)));
    }
    return ((sip->eid.in6.subnet_prefix & mask) == (dip->eid.in6.subnet_prefix & mask));
}

static bool uvs_in_same_subnet(tpsa_net_addr_t *sip, tpsa_net_addr_t *dip, uint32_t prefix_len)
{
    if (sip->type != dip->type || prefix_len == 0) {
        TPSA_LOG_WARN("ip type not support, sip type:%d, dip type:%d, prefix len:%u",
            (int)sip->type, (int)dip->type, prefix_len);
        return false;
    }

    /* ipv4 */
    if (sip->type == TPSA_NET_ADDR_TYPE_IPV4) {
        return uvs_in_same_subnet_ipv4(sip, dip, prefix_len);
    }

    /* ipv6 */
    return uvs_in_same_subnet_ipv6(sip, dip, prefix_len);
}

bool uvs_is_clan_domain(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->data;
    tpf_dev_table_entry_t tpf_dev_table_entry;
    int ret = tpsa_lookup_tpf_dev_table(nlreq->tpfdev_name, &ctx->table_ctx->tpf_dev_table, &tpf_dev_table_entry);
    if (ret != 0 || tpf_dev_table_entry.dev_fea.bs.clan == 0) {
        TPSA_LOG_DEBUG("not support clan domain query ret:%d, dev clan fea:%d, tpf_dev name:%s, dev_name:%s",
            ret, tpf_dev_table_entry.dev_fea.bs.clan, nlreq->tpfdev_name, nlreq->dev_name);
        return false;
    }

    TPSA_LOG_DEBUG("dev suport clan domain!");
    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return false;
    }
    ret = tpsa_lookup_vport_table(&fe_key, &ctx->table_ctx->vport_table, vport_entry);
    if (ret < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", fe_key.fe_idx);
        free(vport_entry);
        return false;
    }
    if (vport_entry->tp_cfg.force_g_domain) {
        free(vport_entry);
        TPSA_LOG_INFO("uvs cfg to force g domain");
        return false;
    }

    sip_table_entry_t sip_entry = { 0 };
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    free(vport_entry);
    if (uvs_get_cna_len(&sip_entry.addr, sip_entry.prefix_len) > UVS_MAX_CNA_LEN) {
        TPSA_LOG_DEBUG("cna_len longer than max cna len, prefixlen: %u\n", sip_entry.prefix_len);
        return false;
    }

    tpsa_net_addr_t dip = {0};
    urma_eid_t peer_tpsa_eid;
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid, &peer_tpsa_eid, &dip);

    TPSA_LOG_DEBUG("judge is same subnet src eid "EID_FMT" dst eid "EID_FMT", prefixlen: %u\n",
                  EID_ARGS(sip_entry.addr.eid), EID_ARGS(dip.eid), sip_entry.prefix_len);
    return uvs_in_same_subnet(&sip_entry.addr, &dip, sip_entry.prefix_len);
}

static tpsa_create_param_t *tpsa_init_create_cparam(tpsa_nl_msg_t *msg, uint32_t upi, bool sig_loop,
    uint8_t port_id, uvs_mtu_t mtu)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->data;
    tpsa_create_param_t *cparam;

    cparam = calloc(1, sizeof(tpsa_create_param_t) + TPSA_UDRV_DATA_LEN);
    if (cparam == NULL) {
        return NULL;
    }
    cparam->trans_mode = nlreq->trans_mode;
    (void)memset(&cparam->dip, 0, sizeof(tpsa_net_addr_t));
    cparam->local_eid = nlreq->local_eid;
    cparam->peer_eid = nlreq->peer_eid;
    cparam->local_jetty = nlreq->local_jetty;
    cparam->peer_jetty = nlreq->peer_jetty;
    cparam->eid_index = nlreq->eid_index;
    cparam->fe_idx = nlmsg->hdr.ep.src_function_id;
    cparam->upi = upi;
    cparam->vtpn = nlreq->vtpn;
    cparam->liveMigrate = false;
    cparam->migrateThird = false;
    cparam->msg_id = nlmsg->hdr.msg_id;
    cparam->nlmsg_seq = msg->nlmsg_seq;
    cparam->sig_loop = sig_loop;
    (void)memcpy(cparam->dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);
    (void)memcpy(cparam->local_tpf_name, nlreq->tpfdev_name, TPSA_MAX_DEV_NAME);
    cparam->ta_data = nlreq->ta_data;
    cparam->port_id = port_id;
    cparam->mtu = mtu;

    if ((nlreq->udrv_in_len + nlreq->udrv_out_len) > TPSA_UDRV_DATA_LEN) {
        TPSA_LOG_INFO("buf len is short\n");
        free(cparam);
        return NULL;
    }
    cparam->udrv_in_len = nlreq->udrv_in_len;
    cparam->udrv_out_len = nlreq->udrv_out_len;
    if ((nlreq->udrv_in_len + nlreq->udrv_out_len) <= TPSA_UDRV_DATA_LEN) {
        cparam->udrv_ext_len = TPSA_UDRV_DATA_LEN - (nlreq->udrv_in_len + nlreq->udrv_out_len);
    } else {
        cparam->udrv_ext_len = 0;
    }
    // udrv_data: udrv_in_len + udrv_out_len + tp_ext_len
    (void)memcpy(cparam->udrv_data, nlreq->udrv_data, nlreq->udrv_in_len);
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
    if (memcmp(&local->ip, &peer->ip, sizeof(tpsa_net_addr_t)) == 0) {
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
    if (memcmp(&local->ip, &peer->ip, sizeof(tpsa_net_addr_t)) == 0) {
        if (trans_mode == TPSA_TP_RC) {
            return uvs_rc_in_same_vtp(&local->eid, &peer->eid, local->jetty_id, peer->jetty_id);
        }
        if (trans_mode == TPSA_TP_RM) {
            return uvs_um_in_same_vtp(&local->eid, &peer->eid);
        }
    }
    return false;
}

int uvs_create_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)nlmsg->data;
    tpsa_vtp_table_param_t vtp_table_data = {0};
    tpsa_create_param_t *cparam = NULL;
    urma_eid_t peer_tpsa_eid = {0};
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    int32_t res = 0;
    bool isLoopback = false;
    bool sig_loop = false;

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u, dst eid "EID_FMT", djetty: %u\n",
                  EID_ARGS(nlreq->local_eid), nlreq->local_jetty, EID_ARGS(nlreq->peer_eid),
                  nlreq->peer_jetty);

    /* clan tp not need to negotiate */
    if (uvs_is_clan_domain(ctx, msg)) {
        TPSA_LOG_INFO("create vtp in clan domain");
        return uvs_create_clan_vtp(ctx, msg);
    }

    /* um no need to negotiate */
    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB && nlreq->trans_mode == TPSA_TP_UM) {
        return uvs_create_um_vtp(ctx, msg);
    }

    bool stop_proc_vtp;
    res = uvs_retry_link_establish(ctx, msg, &stop_proc_vtp);
    if (stop_proc_vtp == true) {
        return res;
    }

    /* check vtp table */
    res = tpsa_lookup_vtp_table(TPSA_INITIATOR, nlmsg, ctx->table_ctx);
    if (res != TPSA_LOOKUP_NULL) {
        TPSA_LOG_INFO("Find vtpn in vtp table. Now feedback vtpn through netlink message");
        vtp_table_data.vtpn = UINT32_MAX;
        tpsa_nl_resp_status_t stat = TPSA_NL_RESP_IN_PROGRESS;

        if (res >= 0) {
            vtp_table_data.vtpn = (uint32_t)res;
            stat = TPSA_NL_RESP_SUCCESS;
        }
        if (res == TPSA_RC_JETTY_ALREADY_BIND) {
            vtp_table_data.vtpn = UINT32_MAX;
            stat = TPSA_RC_JETTY_ALREADY_BIND;
        }
        /* NETLINK to feedback VTPN to UBCORE */
        if (uvs_response_create_fast(msg, ctx->nl_ctx, stat, vtp_table_data.vtpn) < 0) {
            TPSA_LOG_ERR("Fail to response nl response when find vtpn in vtp table.");
            return -1;
        }

        return 0;
    }

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    res = tpsa_lookup_vport_table(&fe_key,
                                  &ctx->table_ctx->vport_table,
                                  vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", nlmsg->hdr.ep.src_function_id);
        free(vport_entry);
        return -1;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid, &peer_tpsa_eid, &dip);
    int32_t upi = tpsa_get_upi(fe_key.dev_name, fe_key.fe_idx, nlreq->eid_index, &ctx->table_ctx->vport_table);
    if (upi < 0) {
        TPSA_LOG_ERR("Fail to get upi when init create msg.");
        free(vport_entry);
        return -1;
    }
    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_end_point_t local = { sip_entry.addr, nlreq->local_eid, nlreq->local_jetty };
        uvs_end_point_t peer = { dip, nlreq->peer_eid, nlreq->peer_jetty };
        isLoopback = uvs_is_loopback(nlreq->trans_mode, &local, &peer);
        sig_loop = uvs_is_sig_loop(nlreq->trans_mode, &local, &peer);
    }
    tpsa_tpg_table_index_t tpg_idx = {
        .dip = dip,
        .local_eid = nlreq->local_eid,
        .peer_eid = nlreq->peer_eid,
        .ljetty_id = nlreq->local_jetty,
        .djetty_id = nlreq->peer_jetty,
        .isLoopback = isLoopback,
        .sig_loop = sig_loop,
        .upi = (uint32_t)upi,
    };
    free(vport_entry);

    cparam = tpsa_init_create_cparam(msg, (uint32_t)upi, sig_loop, sip_entry.port_id[0], sip_entry.mtu);
    if (cparam == NULL) {
        TPSA_LOG_ERR("Fail to alloc cparam memory.");
        return -1;
    }

    uvs_nl_resp_info_t nl_resp = {
        .resp = false,
        .status = TPSA_NL_RESP_FAIL,
        .vtpn = UINT32_MAX,
    };

    if (uvs_create_vtp_base(ctx, cparam, &tpg_idx, &nl_resp) < 0) {
        TPSA_LOG_ERR("Fail to run create tpg base.");
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

static tpsa_tpg_status_t tpsa_reuse_target_tpg(uvs_ctx_t *ctx, tpsa_net_addr_t *sip, tpsa_net_addr_t *dip,
    tpsa_sock_msg_t *msg, tpsa_tpg_info_t *tpsa_tpg_info)
{
    tpsa_tpg_table_index_t tpg_idx;
    tpg_idx.dip = *dip;
    tpg_idx.local_eid = msg->peer_eid;
    tpg_idx.peer_eid = msg->local_eid;
    tpg_idx.ljetty_id = msg->peer_jetty;
    tpg_idx.djetty_id = msg->local_jetty;

    uvs_end_point_t local = { *sip, msg->local_eid, msg->local_jetty };
    uvs_end_point_t peer = { *dip, msg->peer_eid, msg->peer_jetty };
    tpg_idx.isLoopback = uvs_is_loopback(msg->trans_mode, &local, &peer);
    tpg_idx.trans_mode = msg->trans_mode;

    return tpsa_lookup_tpg_table(&tpg_idx, tpg_idx.trans_mode, ctx->table_ctx, tpsa_tpg_info);
}

int uvs_create_vtp_req(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    tpsa_cc_param_t resp_param = {0};
    tpf_dev_table_entry_t tpf_dev_table_entry;
    tpsa_create_req_t *req = &msg->content.req;
    urma_eid_t peer_tpsa_eid = {0};
    tpsa_tpg_status_t status = 0;
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    tpsa_tpg_info_t tpg_info;
    int32_t res = -1;
    uint32_t eid_index;

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u dst eid "EID_FMT" djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_rc_check_ljetty(msg->peer_jetty, &msg->peer_eid, msg->trans_mode, ctx->table_ctx)) {
        TPSA_LOG_ERR("Fail to rc_check_sjetty");
        return -1;
    }

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry\n");
        return -1;
    }

    res = vport_table_lookup_by_ueid_return_eid_idx(&ctx->table_ctx->vport_table, msg->upi, &msg->peer_eid,
                                                    vport_entry, &eid_index);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key upi:%u eid "EID_FMT"\n", msg->upi, EID_ARGS(msg->peer_eid));
        free(vport_entry);
        return -1;
    }
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, msg->local_eid, &peer_tpsa_eid, &dip);

    tpsa_init_tpg_cmd_param_t param = {0};
    param.fe_idx = vport_entry->key.fe_idx;
    param.tp_cfg = vport_entry->tp_cfg;
    param.tp_cfg.port = sip_entry.port_id[0];
    param.sip = sip_entry.addr;
    param.dip = dip;
    param.sip_idx = vport_entry->sip_idx;
    param.mtu = sip_entry.mtu;

    free(vport_entry);

    /* TODO: table check */
    /* IOCTL to create target tpg */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to create tp request req");
        return -1;
    }

    tpsa_ioctl_cmd_get_dev_info(cfg, &sip_entry.addr, URMA_TRANSPORT_UB, msg->peer_eid, eid_index);
    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to get dev info in target");
        free(cfg);
        return -1;
    }
    TPSA_LOG_INFO("Finish IOCTL to get dev info in target.\n");

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && !cfg->cmd.get_dev_info.out.port_is_active) {
        TPSA_LOG_ERR("Failed to set up connection due to port unactive on target side with pf_dev %s\n",
            cfg->cmd.get_dev_info.out.target_pf_name);
        free(cfg);
        return -1;
    }

    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        TPSA_LOG_INFO("Lookup tpf dev table using tpf name %s", cfg->cmd.get_dev_info.out.target_tpf_name);
        res = tpsa_lookup_tpf_dev_table(cfg->cmd.get_dev_info.out.target_tpf_name, &ctx->table_ctx->tpf_dev_table,
            &tpf_dev_table_entry);
        if (res != 0) {
            TPSA_LOG_WARN("Failed to lookup tpf dev table");
        } else {
            if (tpsa_get_cc_query_result(tpf_dev_table_entry, &param.tp_cfg,
                &param.cc_array_cnt, param.cc_result_array) != 0) {
                param.tp_cfg.tp_mod_flag.bs.cc_en = 0;
                TPSA_LOG_WARN("Local side: cannot get cc query result given cc priority-%hhu and algorithm-%hu",
                    param.tp_cfg.cc_priority, param.tp_cfg.cc_alg);
            }
        }
    }

    tpsa_ioctl_cmd_create_target_tpg(cfg, msg, &param);
    if (req->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        status = tpsa_reuse_target_tpg(ctx, &sip_entry.addr, &dip, msg, &tpg_info);
    }
    if (status <= TPSA_TPG_LOOKUP_NULL) {
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to create target tpg in worker");
            free(cfg);
            return -1;
        }
        TPSA_LOG_INFO("--------------------create tpgn: %d, tpn: %d in target.\n",
            cfg->cmd.create_target_tpg.out.tpgn, cfg->cmd.create_target_tpg.out.tpn[0]);
        tpg_info.tpgn = cfg->cmd.create_target_tpg.out.tpgn;
        (void)memcpy(tpg_info.tpn, cfg->cmd.create_target_tpg.out.tpn,
            TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));

        // add tpg table
        tpsa_tpg_table_param_t tparam = {0};
        tparam.tpgn = cfg->cmd.create_target_tpg.out.tpgn;
        tparam.status = TPSA_TPG_LOOKUP_IN_PROGRESS;
        tparam.use_cnt = 1;
        tparam.ljetty_id = msg->peer_jetty;
        tparam.leid =  msg->peer_eid;
        tparam.dip = dip;

        (void)memcpy(tparam.tpn, cfg->cmd.create_target_tpg.out.tpn, TPSA_MAX_TP_CNT_IN_GRP * sizeof(uint32_t));
        if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && msg->trans_mode == TPSA_TP_RM) {
            if (tpsa_add_rm_tpg_table(&tparam, &ctx->table_ctx->rm_tpg_table)) {
                TPSA_LOG_ERR("Failed to add rm tpg table\n");
                free(cfg);
                return -1;
            }
        } else if (req->ta_data.trans_type == TPSA_TRANSPORT_UB && msg->trans_mode == TPSA_TP_RC) {
            if (tpsa_add_rc_tpg_table(msg->local_eid, msg->local_jetty, &tparam, &ctx->table_ctx->rc_tpg_table)) {
                TPSA_LOG_ERR("Failed to add rc tpg table\n");
                free(cfg);
                return -1;
            }
        }
    }

    resp_param.target_cc_cnt = param.cc_array_cnt;
    resp_param.target_cc_en = param.tp_cfg.tp_mod_flag.bs.cc_en;
    (void)memcpy(resp_param.cc_result_array,
        param.cc_result_array, sizeof(tpsa_tp_cc_entry_t) * param.cc_array_cnt);
    tpsa_sock_msg_t *resp = tpsa_sock_init_create_resp(msg, tpg_info.tpgn, tpg_info.tpn,
        &cfg->cmd.create_target_tpg.in.tpg_cfg,
        (req->ta_data.trans_type == TPSA_TRANSPORT_UB ? sip_entry.mtu :
        cfg->cmd.create_target_tpg.local_mtu), &resp_param);
    resp->content.resp.is_target = status <= TPSA_TPG_LOOKUP_NULL ? true : false;
    resp->content.resp.udrv_in_len = req->udrv_in_len;
    resp->content.resp.udrv_out_len = req->udrv_out_len;
    resp->content.resp.udrv_ext_len = cfg->cmd.create_target_tpg.udrv_ext.out_len;
    (void)memcpy((char *)resp->content.resp.udrv_data,
        (char *)req->udrv_data, TPSA_UDRV_DATA_LEN);

    free(cfg);

    if (tpsa_sock_send_msg(ctx->sock_ctx, resp, sizeof(tpsa_sock_msg_t), peer_tpsa_eid) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp resp in worker\n");
        free(resp);
        return -1;
    }

    free(resp);
    TPSA_LOG_INFO("Finish socket send resp in target.\n");

    return 0;
}

static int tpsa_refresh_rm_wait_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_vtp_table_param_t *vtp_table_data,
                                      tpsa_net_addr_t *sip, uvs_ctx_t *ctx)
{
    rm_wait_table_entry_t *entry = calloc(1, sizeof(rm_wait_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc entry when refresh rm wait table");
        return -1;
    }

    rm_wait_table_key_t key = {
        .dip = tpg_idx->dip,
    };

    tpsa_create_param_t cparam = {
        .trans_mode = TPSA_TP_RM,
        .local_jetty = UINT32_MAX,
        .peer_jetty = UINT32_MAX,
        .clan_tp = false,
    };

    while (rm_wait_table_lookup(&ctx->table_ctx->rm_wait_table, &key) != NULL) {
        if (rm_wait_table_pop(&ctx->table_ctx->rm_wait_table, &key, entry) < 0) {
            TPSA_LOG_ERR("Fail to pop rm entry when refresh rm wait table");
            free(entry);
            return -1;
        }

        cparam.local_eid = entry->vtp_entry.key.src_eid;
        cparam.peer_eid = entry->vtp_entry.key.dst_eid;
        cparam.dip = entry->key.dip;
        cparam.fe_idx = entry->fe_idx;
        cparam.eid_index = entry->vtp_entry.eid_index;
        cparam.vtpn = entry->vtp_entry.vtpn;
        cparam.liveMigrate = entry->liveMigrate;
        cparam.migrateThird = entry->migrateThird;
        cparam.msg_id = entry->msg_id;
        cparam.nlmsg_seq = entry->nlmsg_seq;
        (void)memcpy(cparam.dev_name, entry->dev_name, TPSA_MAX_DEV_NAME);

        if (uvs_create_vtp_reuse_tpg(ctx, &cparam, sip, vtp_table_data) < 0) {
            TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
            free(entry);
            return -1;
        }

        if (!entry->liveMigrate) {
            if (uvs_response_create_wait(vtp_table_data->vtpn, &cparam, ctx->nl_ctx) < 0) {
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
                                      tpsa_net_addr_t *sip, uvs_ctx_t *ctx)
{
    rc_wait_table_entry_t *entry = calloc(1, sizeof(rc_wait_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc entry when refresh rc wait table");
        return -1;
    }

    rc_wait_table_key_t key = {
        .deid = tpg_idx->peer_eid,
        .djetty_id = tpg_idx->djetty_id,
    };

    tpsa_create_param_t cparam = {
        .trans_mode = TPSA_TP_RC,
        .clan_tp = false,
    };

    while (rc_wait_table_lookup(&ctx->table_ctx->rc_wait_table, &key) != NULL) {
        if (rc_wait_table_pop(&ctx->table_ctx->rc_wait_table, &key, entry) < 0) {
            TPSA_LOG_ERR("Fail to pop rc entry when refresh rc wait table");
            free(entry);
            return -1;
        }

        cparam.local_eid = entry->vtp_entry.src_eid;
        cparam.peer_eid = entry->vtp_entry.key.dst_eid;
        cparam.local_jetty = entry->vtp_entry.src_jetty_id;
        cparam.peer_jetty = entry->vtp_entry.key.jetty_id;
        cparam.eid_index = entry->vtp_entry.eid_index;
        cparam.fe_idx = entry->fe_idx;
        cparam.dip = entry->dip;
        cparam.vtpn = entry->vtp_entry.vtpn;
        cparam.liveMigrate = entry->liveMigrate;
        cparam.migrateThird = entry->migrateThird;
        cparam.msg_id = entry->msg_id;
        cparam.nlmsg_seq = entry->nlmsg_seq;
        (void)memcpy(cparam.dev_name, entry->dev_name, TPSA_MAX_DEV_NAME);

        if (uvs_create_vtp_reuse_tpg(ctx, &cparam, sip, vtp_table_data) < 0) {
            TPSA_LOG_ERR("Fail to create vtp when reuse tpg");
            free(entry);
            return -1;
        }

        if (!entry->liveMigrate) {
            if (uvs_response_create_wait(vtp_table_data->vtpn, &cparam, ctx->nl_ctx) < 0) {
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

int tpsa_refresh_wait_table(tpsa_tpg_table_index_t *tpg_idx, tpsa_transport_mode_t trans_mode,
                            tpsa_vtp_table_param_t *vtp_table_data, tpsa_net_addr_t *sip,
                            uvs_ctx_t *ctx)
{
    if (trans_mode == TPSA_TP_RM) {
        if (tpsa_refresh_rm_wait_table(tpg_idx, vtp_table_data, sip, ctx) < 0) {
            TPSA_LOG_ERR("Fail to refresh wait table (RM)");
            return -1;
        }
    } else {
        if (tpsa_refresh_rc_wait_table(tpg_idx, vtp_table_data, sip, ctx) < 0) {
            TPSA_LOG_ERR("Fail to refresh wait table (RC)");
            return -1;
        }
    }

    return 0;
}

int uvs_create_vtp_resp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    urma_eid_t peer_tpsa_eid = {0};
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u dst eid "EID_FMT" djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    /* IOCTL to create vtp */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to alloc create vtp request ");
        return -1;
    }

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        free(cfg);
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = msg->content.resp.src_function_id;
    (void)memcpy(fe_key.dev_name, msg->content.resp.dev_name, TPSA_MAX_DEV_NAME);

    int32_t res = tpsa_lookup_vport_table(&fe_key,
                                          &ctx->table_ctx->vport_table,
                                          vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", msg->content.resp.src_function_id);
        free(cfg);
        free(vport_entry);
        return -1;
    }
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);

    tpsa_ioctl_cmd_modify_tpg(cfg, msg, &sip_entry.addr);
    if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
        TPSA_LOG_ERR("Fail to ioctl to modify tpg in worker");
        free(cfg);
        free(vport_entry);
        return -1;
    }
    TPSA_LOG_INFO("Finish IOCTL to modify tpg in initiator.\n");

    free(cfg);
    free(vport_entry);

    if (msg->liveMigrate && msg->migrateThird) {
        dip = msg->dip;
        peer_tpsa_eid = msg->dip.eid;
    } else {
        tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, msg->peer_eid, &peer_tpsa_eid, &dip);
    }

    /* Construct ack packet */
    tpsa_sock_msg_t *ack = tpsa_sock_init_create_ack(msg);

    if (tpsa_sock_send_msg(ctx->sock_ctx, ack, sizeof(tpsa_sock_msg_t), peer_tpsa_eid) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp ack in worker\n");
        free(ack);
        return -1;
    }

    free(ack);
    TPSA_LOG_INFO("Finish socket ack message in initiator.\n");

    return 0;
}

int uvs_create_vtp_ack(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    urma_eid_t peer_tpsa_eid = {0};
    jetty_peer_table_param_t parm = {0};
    uint32_t location = TPSA_TARGET;

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u dst eid "EID_FMT" djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    uvs_reverse_lookup_ip(msg, &sip_entry, &dip, &peer_tpsa_eid, ctx->table_ctx);

    if ((msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB && msg->content.ack.is_target == true) ||
        msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_IB) {
        /* IOCTL to modify tp to RTS */
        tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
        if (cfg == NULL) {
            TPSA_LOG_ERR("Fail to alloc modify target tp request req");
            return -1;
        }

        tpsa_cmd_tpf_t tpf = {
            .trans_type = URMA_TRANSPORT_UB,
            .netaddr = sip_entry.addr,
        };

        cfg->cmd_type = TPSA_CMD_MODIFY_TARGET_TPG;
        cfg->cmd.modify_target_tpg.in.tpf = tpf;
        cfg->cmd.modify_target_tpg.in.tpgn = msg->peer_tpgn;
        cfg->cmd.modify_target_tpg.ta_data = msg->content.ack.ta_data;

        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to modify peer tpg in worker");
            free(cfg);
            return -1;
        }

        free(cfg);

        TPSA_LOG_INFO("Finish IOCTL to modify target tpg in target.\n");
    }

    /* Start to update target vtp and tpg table */
    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_table_update(UINT32_MAX, msg->peer_tpgn, location, msg, ctx->table_ctx) < 0) {
        TPSA_LOG_ERR("Fail to update table when ack receive.");
        return -1;
    }

    vport_key_t fe_key = {0};
    uint32_t eid_idx;
    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, msg->upi, &msg->peer_eid,
                                              &fe_key, &eid_idx) != 0) {
        TPSA_LOG_INFO("vport_table_lookup_by_ueid failed, upi is %u, eid_idx is %u,  eid:"EID_FMT"\n",
                       msg->upi, eid_idx, EID_ARGS(msg->local_eid));
        return -1;
    }
    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
        uvs_create_resp_to_lm_src(ctx, fe_key) != 0) {
        TPSA_LOG_ERR("uvs create resp to livemigrate source failed");
        return -1;
    }

    /* Start to add target jetty-peer table */
    parm.seid = msg->peer_eid;
    parm.ljetty_id = msg->peer_jetty;
    parm.deid = msg->local_eid;
    parm.djetty_id = msg->local_jetty;
    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
        tpsa_worker_jetty_peer_table_add(ctx->table_ctx, msg->trans_mode, &parm) < 0) {
        /* todo rollback? */
        return -1;
    }

    uvs_end_point_t local = { sip_entry.addr, msg->local_eid, msg->local_jetty };
    uvs_end_point_t peer = { dip, msg->peer_eid, msg->peer_jetty };
    /* Wakeup wait table when initiator finish create */
    tpsa_tpg_table_index_t tpg_idx = {
        .dip = dip,
        .local_eid = msg->peer_eid,
        .peer_eid = msg->local_eid,
        .ljetty_id = msg->peer_jetty,
        .djetty_id = msg->local_jetty,
        .isLoopback = (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
                       uvs_is_loopback(msg->trans_mode, &local, &peer)),
    };

    tpsa_vtp_table_param_t vtp_table_data = {
        .location = TPSA_INITIATOR,
        .vtpn = UINT32_MAX,
        .tpgn = msg->peer_tpgn,
        .valid = true,
        .local_eid = msg->peer_eid,
        .local_jetty = msg->peer_jetty,
        .eid_index = 0, /* TODO: fix */
        .upi = msg->upi,
    };

    tpsa_sock_msg_t *finish = tpsa_sock_init_create_finish(msg);
    if (finish == NULL) {
        return -1;
    }
    if (tpsa_sock_send_msg(ctx->sock_ctx, finish, sizeof(tpsa_sock_msg_t), peer_tpsa_eid) != 0) {
        TPSA_LOG_ERR("Failed to send create vtp finish in worker\n");
        free(finish);
        return -1;
    }

    free(finish);

    if (msg->content.ack.ta_data.trans_type == TPSA_TRANSPORT_UB &&
        tpsa_refresh_wait_table(&tpg_idx, msg->trans_mode, &vtp_table_data, &sip_entry.addr, ctx) < 0) {
        TPSA_LOG_ERR("Failed to refresh wait table when resp\n");
        return -1;
    }

    TPSA_LOG_INFO("Finish socket finish message in target.\n");
    return 0;
}

int uvs_create_vtp_finish(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    urma_eid_t peer_tpsa_eid = {0};
    uint32_t vtpn;
    int ret;

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u dst eid "EID_FMT" djetty: %u\n",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry %u\n");
        return -1;
    }

    vport_key_t fe_key = {0};
    fe_key.fe_idx = msg->content.finish.src_function_id;
    (void)memcpy(fe_key.dev_name, msg->content.finish.dev_name, TPSA_MAX_DEV_NAME);

    ret = tpsa_lookup_vport_table(&fe_key,
                                  &ctx->table_ctx->vport_table, vport_entry);
    if (ret < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key dev:%s-%hu\n", fe_key.dev_name, fe_key.fe_idx);
        goto free_vport;
    }

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    if (msg->liveMigrate && msg->migrateThird) {
        dip = msg->dip;
        peer_tpsa_eid = msg->dip.eid;
    } else {
        tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, msg->peer_eid, &peer_tpsa_eid, &dip);
    }

    tpsa_create_param_t cparam = {
        .trans_mode = msg->trans_mode,
        .local_eid = msg->local_eid,
        .peer_eid = msg->peer_eid,
        .local_jetty = msg->local_jetty,
        .peer_jetty = msg->peer_jetty,
        .fe_idx = msg->content.finish.src_function_id,
        .vtpn = msg->vtpn,
    };

    if (msg->content.finish.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        ret = uvs_map_vtp(ctx->ioctl_ctx, &cparam, msg->local_tpgn, &sip_entry.addr, &vtpn);
        if (ret < 0) {
            goto free_vport;
        }

        ret = uvs_table_update(vtpn, msg->local_tpgn, TPSA_INITIATOR, msg, ctx->table_ctx);
        if (ret < 0) {
            TPSA_LOG_ERR("Fail to update vtp and tpg table when finish receive");
            goto free_vport;
        }

        if (uvs_create_resp_to_lm_src(ctx, fe_key) < 0) {
            TPSA_LOG_ERR("uvs create resp to livemigrate source failed in uvs_create_vtp_finish");
            goto free_vport;
        }
    }

    /* Wakeup wait table when initiator finish create */
    tpsa_tpg_table_index_t tpg_idx = {
        .dip = dip,
        .local_eid = msg->local_eid,
        .peer_eid = msg->peer_eid,
        .ljetty_id = msg->local_jetty,
        .djetty_id = msg->peer_jetty,
        .isLoopback = false,
    };

    tpsa_vtp_table_param_t vtp_table_data = {
        .location = TPSA_INITIATOR,
        .vtpn = UINT32_MAX,
        .tpgn = msg->local_tpgn,
        .valid = true,
        .local_eid = msg->local_eid,
        .local_jetty = msg->local_jetty,
        .eid_index = 0, /* TODO: fix */
        .upi = msg->upi,
    };

    if (!msg->liveMigrate) {
        ret = uvs_response_create(vtpn, msg, ctx->nl_ctx);
        if (ret < 0) {
            TPSA_LOG_ERR("Fail to response vtpn when finish receive in worker");
            goto free_vport;
        }
    }

    if (msg->content.finish.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        ret = tpsa_refresh_wait_table(&tpg_idx, msg->trans_mode, &vtp_table_data, &sip_entry.addr, ctx);
        if (ret < 0) {
            TPSA_LOG_ERR("Failed to refresh wait table when finish\n");
            goto free_vport;
        }
    }
    TPSA_LOG_INFO("Finish Create VTP, TP and PEER all change to RTS.\n");

free_vport:
    free(vport_entry);
    return ret;
}

static int uvs_destroy_vtp_base(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, vport_table_entry_t *vport_entry,
                                int32_t vtpn, int32_t tpgn)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;
    urma_eid_t peer_tpsa_eid = {0};
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    bool isLoopback = false;

    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid, &peer_tpsa_eid, &dip);
    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_end_point_t local = { sip_entry.addr, nlreq->local_eid, nlreq->local_jetty };
        uvs_end_point_t peer = { dip, nlreq->peer_eid, nlreq->peer_jetty };
        isLoopback = uvs_is_loopback(nlreq->trans_mode, &local, &peer);
    }

    /* IOCTL to destroy vtp and tpg */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to alloc destroy vtp request ");
        return -1;
    }

    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB && vtpn >= 0) {
        tpsa_ioctl_cmd_destroy_vtp(cfg, &sip_entry.addr, nlreq->trans_mode,
            nlreq->local_eid, nlreq->peer_eid, nlreq->peer_jetty);
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to destroy vtp in worker");
            free(cfg);
            return -1;
        }
        TPSA_LOG_INFO("Finish IOCTL to destroy vtp when destroy vtp\n");

        (void)memset(cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    }

    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB && tpgn >= 0) {
        TPSA_LOG_INFO("TPG is not in use now. Start to destroy.\n");
        tpsa_ioctl_cmd_change_tpg_to_error(cfg, &sip_entry.addr, (uint32_t)tpgn);
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to destroy tpg in worker");
            free(cfg);
            return -1;
        }
        /* TODO: checkout cfg->cmd.destroy_tpg.out */
        TPSA_LOG_INFO("Finish IOCTL for change tpg to error when destroy vtp\n");
    } else if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_IB) {
        nlreq->ta_data.is_target = 0;
        tpsa_ioctl_cmd_destroy_tpg(cfg, &sip_entry.addr, (uint32_t)tpgn, &nlreq->ta_data);
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to destroy tpg in worker");
            free(cfg);
            return -1;
        }
        TPSA_LOG_INFO("Finish IOCTL for destroy tpgn:%u\n", tpgn);
    }

    free(cfg);

    if (!isLoopback) {
        /* we start to notify peer to destroy tpg */
        int32_t upi = tpsa_get_upi((nlreq->virtualization == true ? nlreq->tpfdev_name : nlreq->dev_name),
            nlmsg->hdr.ep.src_function_id, nlreq->eid_index, &ctx->table_ctx->vport_table);
        if (upi < 0) {
            TPSA_LOG_ERR("Fail to get upi when init create msg!!! Use upi = 0 instead.");
            upi = 0;
        }

        tpsa_sock_msg_t *dmsg = tpsa_sock_init_destroy_req(msg, (uint32_t)tpgn, &dip, (uint32_t)upi,
                                                           vport_entry->tp_cnt, &nlreq->ta_data);

        if (tpsa_sock_send_msg(ctx->sock_ctx, dmsg, sizeof(tpsa_sock_msg_t), peer_tpsa_eid) != 0) {
            TPSA_LOG_ERR("Failed to send destroy vtp req in worker\n");
            free(dmsg);
            return -1;
        }

        free(dmsg);
        TPSA_LOG_INFO("Finish socket destroy message in initiator\n");
    }

    /* Netlink to notify destroy status to ubcore */
    if (uvs_response_destroy_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_SUCCESS) < 0) {
        TPSA_LOG_ERR("Fail to NETLINK <success> to ubcore when destroy vtp\n");
        return -1;
    }
    TPSA_LOG_INFO("Finish NETLINK <success> to ubcore when destroy vtp\n");

    return 0;
}

/* when uvs reveive the message(TPSA_MSG_STOP_PROC_VTP_MSG), */
/* for deleting linking building requests, add a timeout retry mechanism. */
int uvs_retry_link_delete(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg, bool *stop_proc_vtp)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;
    vport_key_t key = {0};

    key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(key.dev_name, nlreq->dev_name, TPSA_MAX_DEV_NAME);

    (void)pthread_rwlock_wrlock(&ctx->table_ctx->fe_table.rwlock);
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, &key);
    if (fe_entry != NULL && fe_entry->stop_proc_vtp == true) {
        *stop_proc_vtp = true;
        if (uvs_response_destroy_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_IN_PROGRESS) < 0) {
            TPSA_LOG_ERR("When UVS receives mess to stop processing delete connection req, response ubcore failed\n");
            (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
            return -1;
        }

        (void)pthread_rwlock_unlock(&ctx->table_ctx->fe_table.rwlock);
        return 0;
    }

    *stop_proc_vtp = false;
    return 0;
}

int uvs_destroy_vtp(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)msg->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;
    urma_eid_t peer_tpsa_eid = {0};
    sip_table_entry_t sip_entry = {0};
    tpsa_net_addr_t dip = {0};
    int32_t vtpn = -1;
    int32_t tpgn = -1;
    int32_t res = -1;
    bool isLoopback = false;
    bool sig_loop = false;

    TPSA_LOG_INFO("src eid "EID_FMT" sjetty: %u, dst eid "EID_FMT", djetty: %u\n",
                  EID_ARGS(nlreq->local_eid), nlreq->local_jetty, EID_ARGS(nlreq->peer_eid),
                  nlreq->peer_jetty);

    /* clan domain no need to negotiate */
    if (uvs_is_clan_domain(ctx, msg)) {
        TPSA_LOG_INFO("destroy vtp in clan domain");
        return uvs_destroy_clan_vtp(ctx, msg);
    }

    /* um no need to negotiate */
    if (nlreq->trans_mode == TPSA_TP_UM) {
        return uvs_destroy_um_vtp(ctx, msg);
    }

    bool stop_proc_vtp;
    res = uvs_retry_link_delete(ctx, msg, &stop_proc_vtp);
    if (stop_proc_vtp == true) {
        return res;
    }

    vport_table_entry_t *vport_entry = calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry\n");
        return -1;
    }

    TPSA_LOG_INFO("destroy vtp fe_idx %hu\n", nlmsg->hdr.ep.src_function_id);

    vport_key_t fe_key = {0};
    fe_key.fe_idx = nlmsg->hdr.ep.src_function_id;
    (void)memcpy(fe_key.dev_name, (nlreq->virtualization == true ?
        nlreq->tpfdev_name : nlreq->dev_name), TPSA_MAX_DEV_NAME);

    res = tpsa_lookup_vport_table(&fe_key,
                                  &ctx->table_ctx->vport_table,
                                  vport_entry);
    if (res < 0) {
        TPSA_LOG_ERR("Can not find vport_table by key %u\n", nlmsg->hdr.ep.src_function_id);
        free(vport_entry);
        return -1;
    }
    tpsa_lookup_sip_table(vport_entry->sip_idx, &sip_entry, &ctx->table_ctx->sip_table);
    tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, nlreq->peer_eid, &peer_tpsa_eid, &dip);

    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_end_point_t local = { sip_entry.addr, nlreq->local_eid, nlreq->local_jetty };
        uvs_end_point_t peer = { dip, nlreq->peer_eid, nlreq->peer_jetty };
        isLoopback = uvs_is_loopback(nlreq->trans_mode, &local, &peer);
        sig_loop = uvs_is_sig_loop(nlreq->trans_mode, &local, &peer);
    }
    tpsa_tpg_table_index_t tpg_idx = {
        .dip = dip,
        .local_eid = nlreq->local_eid,
        .peer_eid = nlreq->peer_eid,
        .ljetty_id = nlreq->local_jetty,
        .djetty_id = nlreq->peer_jetty,
        .isLoopback = isLoopback,
        .sig_loop = sig_loop,
        .upi = vport_entry->ueid[nlreq->eid_index].upi,
        .trans_mode = nlreq->trans_mode,
        .sip = sip_entry.addr,
        .tp_cnt = vport_entry->tp_cnt
    };
    if (nlreq->ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_table_remove_initiator(&vtpn, &tpgn, &tpg_idx, nlmsg, ctx->table_ctx);

        if ((vtpn == TPSA_REMOVE_INVALID) || (tpgn == TPSA_REMOVE_INVALID) || (vtpn == TPSA_REMOVE_SERVER)) {
            if (uvs_response_destroy_fast(msg, ctx->nl_ctx, TPSA_NL_RESP_IN_PROGRESS) < 0) {
                TPSA_LOG_ERR("Fail to NETLINK <in progress> to ubcore when destroy vtp\n");
                free(vport_entry);
                return -1;
            }
            TPSA_LOG_INFO("Finish NETLINK <in progress> to ubcore when destroy vtp\n");
        }
    }

    if (uvs_destroy_vtp_base(ctx, msg, vport_entry, vtpn, tpgn) < 0) {
        TPSA_LOG_ERR("Fail to run destroy vtp base when destroy vtp\n");
        free(vport_entry);
        return -1;
    }
    free(vport_entry);
    return 0;
}

int uvs_destroy_target_vtp(uvs_ctx_t *ctx, tpsa_sock_msg_t *msg)
{
    /* TODO: tpsa_destroy_req_t from msg not used */
    sip_table_entry_t sip_entry;
    tpsa_net_addr_t dip;
    urma_eid_t peer_tpsa_eid = {0};
    int32_t tpgn = -1;
    int32_t vtpn = -1;
    bool isLoopback = false;

    TPSA_LOG_INFO("vtp src eid "EID_FMT" sjetty: %u, dst eid "EID_FMT"\n, djetty: %u",
                  EID_ARGS(msg->local_eid), msg->local_jetty, EID_ARGS(msg->peer_eid), msg->peer_jetty);

    uvs_reverse_lookup_ip(msg, &sip_entry, &dip, &peer_tpsa_eid, ctx->table_ctx);

    if (msg->content.dreq.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_end_point_t local = { sip_entry.addr, msg->local_eid, msg->local_jetty };
        uvs_end_point_t peer = { dip, msg->peer_eid, msg->peer_jetty };
        isLoopback = uvs_is_loopback(msg->trans_mode, &local, &peer);
    }

    tpsa_tpg_table_index_t tpg_idx = {
        .dip = dip,
        .local_eid = msg->peer_eid,
        .peer_eid = msg->local_eid,
        .ljetty_id = msg->peer_jetty,
        .djetty_id = msg->local_jetty,
        .isLoopback = isLoopback,
        .trans_mode = msg->trans_mode,
        .sip = sip_entry.addr,
        .tp_cnt = msg->content.dreq.tp_cnt
    };

    if (msg->content.dreq.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        uvs_table_remove_target(&vtpn, &tpgn, &tpg_idx, msg, ctx->table_ctx);

        if ((vtpn == TPSA_REMOVE_INVALID) || (tpgn == TPSA_REMOVE_INVALID)) {
            TPSA_LOG_ERR("Can't remove invalid tpg entry when destroy target vtp\n");
            return -1;
        }
    }
    if (vtpn == TPSA_REMOVE_SERVER) {
        TPSA_LOG_INFO("Found vtpn when destroy TARGET vtp. Remove it from table (No IOCTL)\n");
    }

    /* IOCTL to destroy vtp and tpg */
    tpsa_ioctl_cfg_t *cfg = calloc(1, sizeof(tpsa_ioctl_cfg_t));
    if (cfg == NULL) {
        TPSA_LOG_ERR("Fail to alloc destroy vtp request ");
        return -1;
    }

    if (msg->content.dreq.ta_data.trans_type == TPSA_TRANSPORT_UB && tpgn >= 0) {
        tpsa_ioctl_cmd_change_tpg_to_error(cfg, &sip_entry.addr, (uint32_t)tpgn);
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to change tpg %u to error in worker", tpgn);
            free(cfg);
            return -1;
        }
        TPSA_LOG_INFO("Finish IOCTL to change tpg %u to error when destroy target vtp\n", tpgn);
        /* TODO: checkout cfg->cmd.destroy_tpg.out */
    } else if (msg->content.dreq.ta_data.trans_type == TPSA_TRANSPORT_IB) {
        tpsa_ioctl_cmd_destroy_tpg(cfg, &sip_entry.addr, (uint32_t)tpgn, &msg->content.dreq.ta_data);
        if (tpsa_ioctl(ctx->ioctl_ctx->ubcore_fd, cfg) != 0) {
            TPSA_LOG_ERR("Fail to ioctl to destroy tpg");
            free(cfg);
            return -1;
        }
        TPSA_LOG_INFO("Finish IOCTL to destroy target tpgn %u\n", tpgn);
    }

    if (msg->content.dreq.ta_data.trans_type == TPSA_TRANSPORT_UB) {
        (void)tpsa_worker_jetty_peer_table_remove(ctx->table_ctx, msg->trans_mode, msg->peer_jetty,
            &msg->peer_eid);
    }
    free(cfg);

    return 0;
}