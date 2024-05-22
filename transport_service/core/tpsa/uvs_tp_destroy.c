/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs tp resource destroy source file
 * Author: Xu Zhicong
 * Create: 2024-1-18
 * Note:
 * History:
 */
#include <errno.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <pthread.h>

#include "tpsa_log.h"
#include "tpsa_types.h"
#include "tpsa_worker.h"
#include "uvs_tp_manage.h"
#include "uvs_private_api.h"

/* vpt list in single fe */
typedef struct vtp_idx_list_node {
    struct ub_list node;
    tpsa_vtp_table_index_t vtp_idx;
} vtp_idx_list_node_t;

/* fe list need to clean resource */
typedef struct fe_list_node {
    struct ub_list node;
    vport_key_t vport_key;
} fe_list_node_t;

static void uvs_free_vtp_list(struct ub_list *vtp_list)
{
    vtp_idx_list_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, vtp_list) {
        ub_list_remove(&cur->node);
        free(cur);
    }
    return;
}

static void uvs_add_um_vtp_to_del(uvs_ctx_t *ctx, vport_key_t *vport_key, um_vtp_table_t *um_vtp_table,
                                  struct ub_list *vtp_list)
{
    um_vtp_table_entry_t *vtp_cur, *vtp_next;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &um_vtp_table->hmap) {
        vtp_idx_list_node_t *vtp_node = (vtp_idx_list_node_t *)calloc(1, sizeof(vtp_idx_list_node_t));
        if (vtp_node == NULL) {
            continue;
        }
        tpsa_vtp_table_index_t *vtp_idx = &vtp_node->vtp_idx;
        vtp_idx->local_eid = vtp_cur->key.src_eid;
        vtp_idx->peer_eid = vtp_cur->key.dst_eid;

        vtp_idx->local_jetty = UINT32_MAX;
        vtp_idx->peer_jetty = UINT32_MAX;

        vtp_idx->location = TPSA_INITIATOR;
        vtp_idx->trans_mode = TPSA_TP_UM;
        vtp_idx->upi = vtp_cur->upi;
        vtp_idx->fe_key = *vport_key;
        ub_list_push_back(vtp_list, &vtp_node->node);
    }
}

static void uvs_add_rc_vtp_to_del(uvs_ctx_t *ctx, vport_key_t *vport_key, rc_vtp_table_t *rc_vtp_table,
                                  struct ub_list *vtp_list)
{
    rc_vtp_table_entry_t *vtp_cur, *vtp_next;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &rc_vtp_table->hmap) {
        vtp_idx_list_node_t *vtp_node = (vtp_idx_list_node_t *)calloc(1, sizeof(vtp_idx_list_node_t));
        if (vtp_node == NULL) {
            continue;
        }
        tpsa_vtp_table_index_t *vtp_idx = &vtp_node->vtp_idx;
        vtp_idx->local_eid = vtp_cur->src_eid;
        vtp_idx->peer_eid = vtp_cur->key.dst_eid;

        vtp_idx->local_jetty = vtp_cur->src_jetty_id;
        vtp_idx->peer_jetty = vtp_cur->key.jetty_id;

        vtp_idx->location = vtp_cur->location;
        vtp_idx->trans_mode = TPSA_TP_RC;
        vtp_idx->upi = vtp_cur->upi;
        vtp_idx->fe_key = *vport_key;
        ub_list_push_back(vtp_list, &vtp_node->node);
    }
}

static void uvs_add_rm_vtp_to_del(uvs_ctx_t *ctx, vport_key_t *vport_key, rm_vtp_table_t *rm_vtp_table,
                                  struct ub_list *vtp_list)
{
    rm_vtp_table_entry_t *vtp_cur, *vtp_next;

    HMAP_FOR_EACH_SAFE(vtp_cur, vtp_next, node, &rm_vtp_table->hmap) {
        vtp_idx_list_node_t *vtp_node = (vtp_idx_list_node_t *)calloc(1, sizeof(vtp_idx_list_node_t));
        if (vtp_node == NULL) {
            continue;
        }
        tpsa_vtp_table_index_t *vtp_idx = &vtp_node->vtp_idx;
        vtp_idx->local_eid = vtp_cur->key.src_eid;
        vtp_idx->peer_eid = vtp_cur->key.dst_eid;

        vtp_idx->local_jetty = vtp_cur->src_jetty_id;
        vtp_idx->peer_jetty = UINT32_MAX;

        vtp_idx->location = vtp_cur->location;
        vtp_idx->trans_mode = TPSA_TP_RM;
        vtp_idx->upi = vtp_cur->upi;
        vtp_idx->fe_key = *vport_key;
        ub_list_push_back(vtp_list, &vtp_node->node);
    }
}

static void uvs_get_vtp_delete_list(uvs_ctx_t *ctx, vport_key_t *vport_key, struct ub_list *vtp_list)
{
    fe_table_entry_t *fe_entry = fe_table_lookup(&ctx->table_ctx->fe_table, vport_key);
    if (fe_entry == NULL) {
        return;
    }

    if (fe_entry->um_vtp_table.hmap.count != 0) {
        uvs_add_um_vtp_to_del(ctx, vport_key, &fe_entry->um_vtp_table, vtp_list);
    }
    if (fe_entry->rc_vtp_table.hmap.count != 0) {
        uvs_add_rc_vtp_to_del(ctx, vport_key, &fe_entry->rc_vtp_table, vtp_list);
    }
    if (fe_entry->rm_vtp_table.hmap.count != 0) {
        uvs_add_rm_vtp_to_del(ctx, vport_key, &fe_entry->rm_vtp_table, vtp_list);
    }

    return;
}

static int uvs_init_tp_msg_ctx(uvs_ctx_t *ctx, tpsa_vtp_table_index_t *vtp_idx,
                               uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    tp_msg_ctx->trans_type = TPSA_TRANSPORT_UB;
    tp_msg_ctx->trans_mode = vtp_idx->trans_mode;
    tp_msg_ctx->upi = vtp_idx->upi;

    tp_msg_ctx->vport_ctx.key = vtp_idx->fe_key;

    int ret = tpsa_lookup_vport_param(&vtp_idx->fe_key, &ctx->table_ctx->vport_table,
                                      &tp_msg_ctx->vport_ctx.param);
    if (ret != 0) {
        TPSA_LOG_INFO("can't faind vport dev_name:%s, fe_idx:%d when clean fe\n",
            vtp_idx->fe_key.tpf_name, vtp_idx->fe_key.fe_idx);
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

    tp_msg_ctx->src.eid = vtp_idx->local_eid;
    tp_msg_ctx->src.jetty_id = vtp_idx->local_jetty;
    tp_msg_ctx->src.ip = sip_entry.addr;

    (void)tpsa_lookup_dip_table(&ctx->table_ctx->dip_table, vtp_idx->peer_eid,
        tp_msg_ctx->upi, &tp_msg_ctx->peer.uvs_ip, &tp_msg_ctx->dst.ip);
    tp_msg_ctx->dst.eid = vtp_idx->peer_eid;
    tp_msg_ctx->dst.jetty_id = vtp_idx->peer_jetty;

    return 0;
}

static int uvs_destroy_targe_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    int ret = 0;
    int32_t vtpn = -1;
    int32_t tpgn = -1;
    ret = uvs_destroy_rm_rc_vtp(ctx, tp_msg_ctx, TPSA_TARGET, &vtpn, &tpgn);
    if (ret != 0) {
        return ret;
    }

    bool loopback = uvs_is_loopback(tp_msg_ctx->trans_mode, &tp_msg_ctx->src, &tp_msg_ctx->dst);
    if (!loopback) {
        ret = tpsa_sock_send_destroy_req(ctx, tp_msg_ctx, TPSA_FROM_SERVER_TO_CLIENT, NULL);
    }
    return ret;
}

static void uvs_get_fe_list_to_clean(fe_table_t *fe_table, struct ub_list *fe_list)
{
    fe_table_entry_t *cur, *next;
    HMAP_FOR_EACH_SAFE(cur, next, node, &fe_table->hmap) {
        if (!cur->fe_rebooted) {
            continue;
        }

        fe_list_node_t *fe_node = (fe_list_node_t *)calloc(1, sizeof(fe_list_node_t));
        if (fe_node == NULL) {
            continue;
        }
        fe_node->vport_key = cur->key;
        ub_list_push_back(fe_list, &fe_node->node);
    }
}

static void uvs_get_vport_list_to_clean(vport_table_t *vport_table, struct ub_list *vport_list)
{
    vport_table_entry_t *cur, *next;

    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &vport_table->hmap) {
        if (!cur->deleting) {
            continue;
        }

        fe_list_node_t *vport_node = (fe_list_node_t *)calloc(1, sizeof(fe_list_node_t));
        if (vport_node == NULL) {
            continue;
        }
        vport_node->vport_key = cur->key;
        ub_list_push_back(vport_list, &vport_node->node);
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
}

static void uvs_free_fe_list(struct ub_list *fe_list)
{
    fe_list_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, fe_list) {
        ub_list_remove(&cur->node);
        free(cur);
    }
    return;
}

/*
* Destory target side loopback VTP.
*/
static int uvs_destroy_lb_target_vtp(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx)
{
    /*
    * For Loopback, client and server in same UVS.
    * Find the Initial side ctx, and call destroy function directly
    */
    uvs_tp_msg_ctx_t initial_ctx = *tp_msg_ctx;
    uint32_t eid_idx = 0;

    initial_ctx.src = tp_msg_ctx->dst;
    initial_ctx.dst = tp_msg_ctx->src;

    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx->vport_table, initial_ctx.upi, &initial_ctx.src.eid,
        &initial_ctx.vport_ctx.key, &eid_idx) != 0) {
        TPSA_LOG_WARN("failed to find upi %u,eid_idx is %u,eid:" EID_FMT "\n",
            tp_msg_ctx->upi, eid_idx, EID_ARGS(initial_ctx.src.eid));
        return -1;
    }

    if (tpsa_lookup_vport_param_with_eid_idx(&initial_ctx.vport_ctx.key, &ctx->table_ctx->vport_table,
        eid_idx, &initial_ctx.vport_ctx.param, &initial_ctx.lm_ctx) != 0) {
        TPSA_LOG_WARN("vport not exit, dev_name:%s, fe_idx:%d\n",
            initial_ctx.vport_ctx.key.tpf_name, initial_ctx.vport_ctx.key.fe_idx);
        return -1;
    }

    return uvs_destroy_initial_vtp(ctx, &initial_ctx, NULL);
}

static void uvs_clean_single_fe(uvs_ctx_t *ctx, vport_key_t *vport_key)
{
    uvs_tp_msg_ctx_t tp_msg_ctx = {0};
    vtp_idx_list_node_t *cur, *next;
    struct ub_list vtp_list;
    bool loop_back = false;
    int ret = 0;

    TPSA_LOG_INFO("Clean FE dev_name:%s, fe_idx:%d", vport_key->tpf_name, vport_key->fe_idx);

    tpsa_lookup_vport_and_fill_lm_ctx(vport_key, &ctx->table_ctx->vport_table, &tp_msg_ctx.lm_ctx);

    // 1. Get all VTP list in FE
    ub_list_init(&vtp_list);
    uvs_get_vtp_delete_list(ctx, vport_key, &vtp_list);

    // 2. Clean all VTP resource.
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &vtp_list) {
        TPSA_LOG_INFO("clean vtp, tran_mode:%d , location:%d, seid " EID_FMT " sjetty: %u, "
            "deid " EID_FMT ", djetty: %u\n", (int)cur->vtp_idx.trans_mode, cur->vtp_idx.location,
            EID_ARGS(cur->vtp_idx.local_eid), cur->vtp_idx.local_jetty,
            EID_ARGS(cur->vtp_idx.peer_eid), cur->vtp_idx.peer_jetty);

        if (uvs_init_tp_msg_ctx(ctx, &cur->vtp_idx, &tp_msg_ctx) != 0) {
            TPSA_LOG_WARN("init tp ctx failed");
            continue;
        }

        // 2.1 Client side destroy VTP process
        // Destroy local VTP, and send destroy req msg to Server.
        if (cur->vtp_idx.location == TPSA_INITIATOR || cur->vtp_idx.location == TPSA_DUPLEX) {
            ret |= uvs_destroy_initial_vtp(ctx, &tp_msg_ctx, NULL);
            uvs_cal_vtp_statistic(vport_key, tp_msg_ctx.trans_mode, UVS_VTP_DESTROY_STATE);
        }

        // 2.1 Server side destroy VTP process.
        // Destroy local VTP, and send destroy req msg to Client.
        if ((cur->vtp_idx.location == TPSA_TARGET || cur->vtp_idx.location == TPSA_DUPLEX)) {
            loop_back = uvs_is_loopback(tp_msg_ctx.trans_mode, &tp_msg_ctx.src, &tp_msg_ctx.dst);
            ret |= (loop_back ? uvs_destroy_lb_target_vtp(ctx, &tp_msg_ctx) :
                                uvs_destroy_targe_vtp(ctx, &tp_msg_ctx));
        }

        if (ret != 0) {
            TPSA_LOG_WARN("clean vtp failed ret: %d", ret);
            ret = 0;
        }
    }
    // 4. Free VTP list
    uvs_free_vtp_list(&vtp_list);
}

void uvs_clear_vport_ueid(uvs_ctx_t *ctx, vport_key_t *vport_key)
{
    (void)pthread_rwlock_rdlock(&ctx->table_ctx->vport_table.rwlock);
    vport_table_entry_t *vport_entry = vport_table_lookup(&ctx->table_ctx->vport_table, vport_key);
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to lookup vport entry");
        (void)pthread_rwlock_unlock(&ctx->table_ctx->vport_table.rwlock);
        return;
    }
    for (uint32_t i = 0; i < vport_entry->ueid_max_cnt && i < TPSA_EID_IDX_TABLE_SIZE; i++) {
        if (!vport_entry->ueid[i].is_valid) {
            continue;
        }
        if (vport_entry->ueid[i].used == false) {
            continue;
        }
        (void)tpsa_ioctl_op_ueid(ctx->ioctl_ctx, TPSA_CMD_DEALLOC_EID, vport_key, &vport_entry->ueid[i], i);
        vport_entry->ueid[i].used = false;
    }
    (void)pthread_rwlock_unlock(&ctx->table_ctx->vport_table.rwlock);
}

void uvs_clean_rebooted_fe(uvs_ctx_t *ctx)
{
    if (!ctx->table_ctx->fe_table.clean_res) {
        return;
    }

    // 1. Get all rebooted FE list.
    struct ub_list fe_list;
    ub_list_init(&fe_list);
    uvs_get_fe_list_to_clean(&ctx->table_ctx->fe_table, &fe_list);

    // 2. Clean rebooted fe VTP resource, clear ueid
    fe_list_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &fe_list) {
        uvs_clean_single_fe(ctx, &cur->vport_key);
        uvs_clear_vport_ueid(ctx, &cur->vport_key);
        tpsa_update_fe_rebooted(&ctx->table_ctx->fe_table, &cur->vport_key, false);
    }

    // 3. Free FE list
    uvs_free_fe_list(&fe_list);

    // 4. Update clean_res flag in fe_table
    uvs_update_fe_table_clean_res(&ctx->table_ctx->fe_table);
}

static void uvs_clean_single_vport(uvs_ctx_t *ctx, vport_key_t *vport_key)
{
    // 1. Clean VTP resource of vport
    if (live_migrate_table_lookup(&ctx->table_ctx->live_migrate_table, vport_key) != NULL) {
        uvs_lm_clean_vport(ctx, vport_key);
    } else {
        uvs_clean_single_fe(ctx, vport_key);
    }

    // 2. Clean ueid
    uvs_clear_vport_ueid(ctx, vport_key);

    // 3. Remove vport entry
    (void)vport_table_remove(&ctx->table_ctx->vport_table, vport_key);
    return;
}

void uvs_clean_deleted_vport(uvs_ctx_t *ctx)
{
    if (!ctx->table_ctx->vport_table.clean_res) {
        return;
    }

    // 1. Get all deleted vport list.
    struct ub_list vport_list;
    ub_list_init(&vport_list);
    uvs_get_vport_list_to_clean(&ctx->table_ctx->vport_table, &vport_list);

    // 2. Clean vport resource
    fe_list_node_t *cur, *next;
    UB_LIST_FOR_EACH_SAFE(cur, next, node, &vport_list) {
        uvs_clean_single_vport(ctx, &cur->vport_key);
    }

    // 3. Free vport list
    uvs_free_fe_list(&vport_list);

    // 4. Update vport clean resource flag
    vport_update_clean_res(&ctx->table_ctx->vport_table);
}