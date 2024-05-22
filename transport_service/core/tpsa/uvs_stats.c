/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs vport and tpf link statistic header file
 * Author: Yexiaokang
 * Create: 2024-1-18
 * Note:
 * History:
 */

#include "tpsa_log.h"
#include "ub_get_clock.h"
#include "uvs_stats.h"

typedef struct vtp_stats_info {
    uint64_t vtp_est;
    uint64_t vtp_active;
    uint64_t vtp_failed;
    uint64_t vtp_opening;
} vtp_stats_info_t;

typedef struct uvs_vport_stats_info {
    vtp_stats_info_t rm_vtp;
    vtp_stats_info_t rc_vtp;
    vtp_stats_info_t um_vtp;
} uvs_vport_stats_info_t;

typedef struct uvs_vport_statistic_node {
    struct ub_hmap_node node;
    uvs_vport_stats_info_t statistic;
    vport_key_t key;
} uvs_vport_statistic_node_t;

typedef struct uvs_tpf_statistic_node {
    struct ub_hmap_node node;
    uvs_tpf_statistic_t statistic;
    uvs_tpf_statistic_key_t key;
} uvs_tpf_statistic_node_t;

typedef struct uvs_vport_map_key {
    char tpf[URMA_MAX_DEV_NAME];
    uvs_vport_info_key_t vport_key;
} uvs_vport_map_key_t;

typedef struct uvs_vport_key_map_node {
    struct ub_hmap_node node;
    uvs_vport_statistic_node_t *statistic;
    // Query vport_key based on tpf and vport_name.
    uvs_vport_map_key_t key;
} uvs_vport_key_map_node_t;

static bool g_global_statistic_enable = false;

static uvs_statistic_ctx_t *g_statistic_ctx = NULL;

void uvs_set_global_statistic_enable(bool enable)
{
    g_global_statistic_enable = enable;
    TPSA_LOG_INFO("%s the global statistic switch", (enable ? "enable" : "disable"));
}

#define UVS_STATISTIC_TABLE_SIZE 10240
static int uvs_create_statistic_table(uvs_statistic_table_t *table)
{
    (void)pthread_rwlock_init(&table->lock, NULL);
    if (ub_hmap_init(&table->hmap, UVS_STATISTIC_TABLE_SIZE) != 0) {
        (void)pthread_rwlock_destroy(&table->lock);
        return -1;
    }

    return 0;
}

static void uvs_destroy_vport_statistic_table(uvs_statistic_table_t *table)
{
    uvs_vport_statistic_node_t *cur, *next;

    (void)pthread_rwlock_wrlock(&table->lock);
    /* destroy client/server sock table */
    HMAP_FOR_EACH_SAFE(cur, next, node, &table->hmap) {
        ub_hmap_remove(&table->hmap, &cur->node);
        free(cur);
    }
    ub_hmap_destroy(&table->hmap);
    (void)pthread_rwlock_unlock(&table->lock);
    (void)pthread_rwlock_destroy(&table->lock);
}

static void uvs_destroy_tpf_statistic_table(uvs_statistic_table_t *table)
{
    uvs_tpf_statistic_node_t *cur, *next;

    (void)pthread_rwlock_wrlock(&table->lock);
    /* destroy client/server sock table */
    HMAP_FOR_EACH_SAFE(cur, next, node, &table->hmap) {
        ub_hmap_remove(&table->hmap, &cur->node);
        free(cur);
    }
    ub_hmap_destroy(&table->hmap);
    (void)pthread_rwlock_unlock(&table->lock);
    (void)pthread_rwlock_destroy(&table->lock);
}

static void uvs_destroy_key_map_table(uvs_statistic_table_t *table)
{
    uvs_vport_key_map_node_t *cur, *next;

    (void)pthread_rwlock_wrlock(&table->lock);
    /* destroy client/server sock table */
    HMAP_FOR_EACH_SAFE(cur, next, node, &table->hmap) {
        ub_hmap_remove(&table->hmap, &cur->node);
        free(cur);
    }
    ub_hmap_destroy(&table->hmap);
    (void)pthread_rwlock_unlock(&table->lock);
    (void)pthread_rwlock_destroy(&table->lock);
}

int uvs_statistic_ctx_init(uvs_statistic_ctx_t *ctx)
{
    if (ctx == NULL) {
        TPSA_LOG_ERR("ctx is null_ptr");
        return -1;
    }

    if (uvs_create_statistic_table(&ctx->tpf_table) != 0) {
        TPSA_LOG_ERR("uvs_create_statistic_table tpf err");
        return -1;
    }

    if (uvs_create_statistic_table(&ctx->vport_table) != 0) {
        TPSA_LOG_ERR("uvs_create_statistic_table vport err");
        goto free_tpf_table;
    }

    if (uvs_create_statistic_table(&ctx->map_table) != 0) {
        TPSA_LOG_ERR("uvs_create_statistic_table map err");
        goto free_vport_table;
    }

    g_statistic_ctx = ctx;
    TPSA_LOG_INFO("uvs statistic init complete.");
    return 0;

free_vport_table:
    uvs_destroy_tpf_statistic_table(&ctx->vport_table);
free_tpf_table:
    uvs_destroy_tpf_statistic_table(&ctx->tpf_table);
    return -1;
}

void uvs_statistic_ctx_uninit(uvs_statistic_ctx_t *ctx)
{
    if (ctx == NULL) {
        TPSA_LOG_WARN("the ctx has been released");
        return;
    }

    if (ctx != g_statistic_ctx) {
        TPSA_LOG_WARN("the ctx not match g_statistic_ctx");
        return;
    }

    uvs_destroy_tpf_statistic_table(&ctx->tpf_table);
    uvs_destroy_vport_statistic_table(&ctx->vport_table);
    uvs_destroy_key_map_table(&ctx->map_table);
    g_statistic_ctx = NULL;
    TPSA_LOG_INFO("uvs statistic uninit complete.");
}

static uvs_vport_statistic_node_t *lookup_vport_statistic_node(const vport_key_t *key)
{
    uint32_t hash = ub_hash_bytes(key, sizeof(*key), 0);
    uvs_vport_statistic_node_t *cur = NULL;
    uvs_vport_statistic_node_t *target = NULL;

    (void)pthread_rwlock_rdlock(&g_statistic_ctx->vport_table.lock);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &g_statistic_ctx->vport_table.hmap) {
        if (memcmp(&cur->key, key, sizeof(vport_key_t)) == 0) {
            target = cur;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_statistic_ctx->vport_table.lock);

    return target;
}

static uvs_tpf_statistic_node_t *lookup_tpf_statistic_node(const uvs_tpf_statistic_key_t *key)
{
    uint32_t hash = ub_hash_bytes(key, sizeof(*key), 0);
    uvs_tpf_statistic_node_t *cur = NULL;
    uvs_tpf_statistic_node_t *target = NULL;

    (void)pthread_rwlock_rdlock(&g_statistic_ctx->tpf_table.lock);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &g_statistic_ctx->tpf_table.hmap) {
        if (memcmp(cur->key.tpf, key->tpf, URMA_MAX_DEV_NAME) == 0) {
            target = cur;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_statistic_ctx->tpf_table.lock);

    return target;
}

static uvs_vport_key_map_node_t *lookup_map_node(const uvs_vport_map_key_t *key)
{
    uint32_t hash = ub_hash_bytes(key, sizeof(*key), 0);
    uvs_vport_key_map_node_t *cur = NULL;
    uvs_vport_key_map_node_t *target = NULL;

    (void)pthread_rwlock_rdlock(&g_statistic_ctx->map_table.lock);
    HMAP_FOR_EACH_WITH_HASH(cur, node, hash, &g_statistic_ctx->map_table.hmap) {
        if (memcmp(&cur->key, key, sizeof(uvs_vport_map_key_t)) == 0) {
            target = cur;
            break;
        }
    }
    (void)pthread_rwlock_unlock(&g_statistic_ctx->map_table.lock);

    return target;
}

static uvs_vport_statistic_node_t *add_vport_statistic_node(const vport_key_t *key)
{
    uvs_vport_statistic_node_t *vport_node =
        (uvs_vport_statistic_node_t *)calloc(1, sizeof(uvs_vport_statistic_node_t));
    if (vport_node == NULL) {
        return NULL;
    }

    vport_node->key = *key;
    uint32_t hash = ub_hash_bytes(key, sizeof(*key), 0);
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->vport_table.lock);
    ub_hmap_insert(&g_statistic_ctx->vport_table.hmap, &vport_node->node, hash);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->vport_table.lock);

    return vport_node;
}

static uvs_tpf_statistic_node_t *add_tpf_statistic_node(const uvs_tpf_statistic_key_t *key)
{
    uvs_tpf_statistic_node_t *tpf_node =
        (uvs_tpf_statistic_node_t *)calloc(1, sizeof(uvs_tpf_statistic_node_t));
    if (tpf_node == NULL) {
        return NULL;
    }

    tpf_node->key = *key;
    uint32_t hash = ub_hash_bytes(key, sizeof(*key), 0);
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->tpf_table.lock);
    ub_hmap_insert(&g_statistic_ctx->tpf_table.hmap, &tpf_node->node, hash);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->tpf_table.lock);

    return tpf_node;
}

static uvs_vport_key_map_node_t *add_map_node(const uvs_vport_map_key_t *key,
    uvs_vport_statistic_node_t *statistic_node)
{
    uvs_vport_key_map_node_t *node =
        (uvs_vport_key_map_node_t *)calloc(1, sizeof(uvs_vport_key_map_node_t));
    if (node == NULL) {
        return NULL;
    }

    node->key = *key;
    node->statistic = statistic_node;
    uint32_t hash = ub_hash_bytes(key, sizeof(*key), 0);
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->map_table.lock);
    ub_hmap_insert(&g_statistic_ctx->map_table.hmap, &node->node, hash);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->map_table.lock);

    return node;
}

static void remove_vport_statistic_node(uvs_vport_statistic_node_t *statistic_node)
{
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->vport_table.lock);
    ub_hmap_remove(&g_statistic_ctx->vport_table.hmap, &statistic_node->node);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->vport_table.lock);
}

static void remove_key_map_node(uvs_vport_key_map_node_t *node)
{
    if (node->statistic != NULL) {
        remove_vport_statistic_node(node->statistic);
    }
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->map_table.lock);
    ub_hmap_remove(&g_statistic_ctx->map_table.hmap, &node->node);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->map_table.lock);
}

int uvs_add_vport_statistic_config(const uvs_vport_info_t *info)
{
    vport_key_t key = { 0 };
    (void)memcpy(key.tpf_name, info->tpf_name, URMA_MAX_DEV_NAME);
    key.fe_idx = info->fe_idx;
    uvs_vport_statistic_node_t *node = lookup_vport_statistic_node(&key);
    if (node != NULL) {
        TPSA_LOG_ERR("tpf nema %s, vport has been added", info->tpf_name, info->key.name);
        return -1;
    }

    node = add_vport_statistic_node(&key);
    if (node == NULL) {
        TPSA_LOG_ERR("tpf name %s, vport add failed", info->tpf_name, info->key.name);
        return -1;
    }

    uvs_vport_map_key_t map_key;
    (void)memcpy(map_key.tpf, info->tpf_name, URMA_MAX_DEV_NAME);
    map_key.vport_key = info->key;
    if (add_map_node(&map_key, node) != NULL) {
        TPSA_LOG_ERR("tpf name %s, vport add map node failed", info->tpf_name, info->key.name);
        remove_vport_statistic_node(node);
        free(node);
        return -1;
    }

    return 0;
}

int uvs_del_vport_statistic_config(const uvs_vport_info_t *info)
{
    uvs_vport_map_key_t key = { 0 };
    key.vport_key = info->key;
    (void)memcpy(key.tpf, info->tpf_name, URMA_MAX_DEV_NAME);
    uvs_vport_key_map_node_t *map_node = lookup_map_node(&key);
    if (map_node == NULL) {
        TPSA_LOG_ERR("del tpf %s and vport %s not match", key.tpf, key.vport_key.name);
        return -1;
    }

    remove_key_map_node(map_node);
    if (map_node->statistic != NULL) {
        free(map_node->statistic);
    }
    free(map_node);

    return 0;
}

static inline void cal_vtp_success_statistic(vtp_stats_info_t *vtp_info)
{
    vtp_info->vtp_opening--;
    vtp_info->vtp_est++;
    vtp_info->vtp_active++;
}

static inline void cal_vtp_failed_statistic(vtp_stats_info_t *vtp_info)
{
    vtp_info->vtp_opening--;
    vtp_info->vtp_failed++;
}

static inline void cal_vtp_destroy_statistic(vtp_stats_info_t *vtp_info)
{
    vtp_info->vtp_active--;
}

static inline void cal_vtp_opening_statistic(vtp_stats_info_t *vtp_info)
{
    vtp_info->vtp_opening++;
}

static vtp_stats_info_t *uvs_get_vtp_by_mode(uvs_vport_stats_info_t *st,
    tpsa_transport_mode_t mode)
{
    vtp_stats_info_t *info = NULL;
    switch (mode) {
        case TPSA_TP_RM:
            info = &st->rm_vtp;
            break;
        case TPSA_TP_RC:
            info = &st->rc_vtp;
            break;
        case TPSA_TP_UM:
            info = &st->um_vtp;
            break;
        default:
            TPSA_LOG_ERR("the mode %d of the vport statistics are incorrect.", mode);
            break;
    }

    return info;
}

static void cal_vtp_statistic(uvs_vport_stats_info_t *st, tpsa_transport_mode_t mode,
    uvs_vtp_state_t state)
{
    vtp_stats_info_t *info = uvs_get_vtp_by_mode(st, mode);
    if (info == NULL) {
        return;
    }

    switch (state) {
        case UVS_VTP_OPENING_STATE:
            cal_vtp_opening_statistic(info);
            break;
        case UVS_VTP_SUCCESS_STATE:
            cal_vtp_success_statistic(info);
            break;
        case UVS_VTP_ERR_STATE:
            cal_vtp_failed_statistic(info);
            break;
        case UVS_VTP_DESTROY_STATE:
            cal_vtp_destroy_statistic(info);
            break;
        case UVS_VTP_UNKNOWN:
        default:
            TPSA_LOG_ERR("the state %hu of the vport statistics are incorrect.", state);
            break;
    }
}

static void cal_tp_est_statistic(uvs_tpf_statistic_t *st, tpsa_transport_mode_t mode)
{
    switch (mode) {
        case TPSA_TP_RM:
            st->rm_tp_est++;
            st->rm_tp_active++;
            break;
        case TPSA_TP_RC:
            st->rc_tp_est++;
            st->rc_tp_active++;
            break;
        case TPSA_TP_UM:
            st->utp_est++;
            st->utp_active++;
            break;
        default:
            TPSA_LOG_ERR("the mode %hu of the tp est statistics are incorrect.", mode);
            break;
    }
}

static void cal_tp_destroy_statistic(uvs_tpf_statistic_t *st, tpsa_transport_mode_t mode)
{
    switch (mode) {
        case TPSA_TP_RM:
            st->rm_tp_active--;
            break;
        case TPSA_TP_RC:
            st->rc_tp_active--;
            break;
        case TPSA_TP_UM:
            st->utp_active--;
            break;
        default:
            TPSA_LOG_ERR("the mode %hu of the tpf destroy statistics are incorrect.", mode);
            break;
    }
}

static void cal_tp_statistic(uvs_tpf_statistic_t *st, tpsa_transport_mode_t mode,
    uvs_tp_state_t state)
{
    switch (state) {
        case UVS_TP_SUCCESS_STATE:
            st->tp_opening--;
            cal_tp_est_statistic(st, mode);
            break;
        case UVS_TP_DESTROY_STATE:
            st->tp_closing--;
            cal_tp_destroy_statistic(st, mode);
            break;
        case UVS_TP_OPENING_STATE:
            st->tp_opening++;
            break;
        case UVS_TP_OPENING_FAIL_STATE:
            st->tp_opening--;
            break;
        case UVS_TP_CLOSING_STATE:
            st->tp_closing++;
            break;
        case UVS_TP_CLOSING_FAIL_STATE:
            st->tp_closing--;
            break;
        case UVS_TP_UNKNOWN:
        default:
            TPSA_LOG_ERR("the state %hu and mode %hu of the tpf tp statistics "
                         "are incorrect.", state, mode);
            break;
    }
}

void uvs_cal_vtp_statistic(vport_key_t *vport_key, tpsa_transport_mode_t mode,
    uvs_vtp_state_t state)
{
    if (!g_global_statistic_enable) {
        return;
    }

    uvs_vport_statistic_node_t *vport_node = lookup_vport_statistic_node(vport_key);
    if (vport_node == NULL) {
        return;
    }

    cal_vtp_statistic(&vport_node->statistic, mode, state);
}

void uvs_cal_vtp_create_stat(tpsa_nl_msg_t *msg, tpsa_nl_resp_status_t status)
{
    tpsa_nl_req_host_t *req_host = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)req_host->req.data;
    vport_key_t key = { 0 };
    key.fe_idx = req_host->src_fe_idx;
    (void)memcpy(key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    if (status == TPSA_NL_RESP_SUCCESS) {
        uvs_cal_vtp_statistic(&key, nlreq->trans_mode, UVS_VTP_SUCCESS_STATE);
    } else {
        uvs_cal_vtp_statistic(&key, nlreq->trans_mode, UVS_VTP_ERR_STATE);
    }
}

void uvs_cal_vtp_destroy(tpsa_nl_msg_t *msg, tpsa_nl_resp_status_t status)
{
    tpsa_nl_req_host_t *req_host = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)req_host->req.data;
    vport_key_t key = { 0 };
    key.fe_idx = req_host->src_fe_idx;
    (void)memcpy(key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    if (status == TPSA_NL_RESP_SUCCESS) {
        uvs_cal_vtp_statistic(&key, nlreq->trans_mode, UVS_VTP_DESTROY_STATE);
    } else {
        TPSA_LOG_ERR("destroy vtp failed");
    }
}

void uvs_cal_tp_change_state_statistic(const char* tpf_name, uvs_tp_change_state_t state)
{
    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("the tpf_name: %s is incorrect.", tpf_name);
        return;
    }
    switch (state) {
        case UVS_TP_TO_ERR_STATE:
            tpf_node->statistic.tp_error++;
            break;
        case UVS_TP_TO_SUSPEND_STATE:
            tpf_node->statistic.tp_suspend++;
            break;
        case UVS_TP_AWAY_ERR_STATE:
            tpf_node->statistic.tp_error--;
            break;
        case UVS_TP_AWAY_SUSPEND_STATE:
            tpf_node->statistic.tp_suspend--;
            break;
        case UVS_TP_SUSPEND_TO_ERR_STATE:
            tpf_node->statistic.tp_suspend--;
            tpf_node->statistic.tp_error++;
            break;
        default:
            TPSA_LOG_ERR("the state of the tpf tp statistics is incorrect.");
            break;
    }
    TPSA_LOG_ERR("the state %d of the tpf_name:%s tp statistics is incorrect.", state, tpf_name);
}

void uvs_cal_multi_tp_statistic(const char* tpf_name, tpsa_transport_mode_t mode,
    uvs_tp_state_t state, uint32_t tp_cnt)
{
    for (uint32_t i = 0 ; i < tp_cnt; i++) {
        uvs_cal_tp_statistic(tpf_name, mode, state);
    }
}

void uvs_cal_tp_statistic(const char* tpf_name, tpsa_transport_mode_t mode, uvs_tp_state_t state)
{
    if (!g_global_statistic_enable) {
        return;
    }

    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node != NULL) {
        cal_tp_statistic(&tpf_node->statistic, mode, state);
        return;
    }

    tpf_node = add_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("add tpf statistic node tpf nema %s err", tpf_name);
        return;
    }

    cal_tp_statistic(&tpf_node->statistic, mode, state);
}

void uvs_cal_tpg_statistic(const char* tpf_name)
{
    if (!g_global_statistic_enable) {
        return;
    }

    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node != NULL) {
        tpf_node->statistic.rm_tpg_est++;
        return;
    }

    tpf_node = add_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("add tpf statistic table tpf nema %s err", tpf_name);
        return;
    }

    tpf_node->statistic.rm_tpg_est++;
}

static void uvs_load_vport_statistic(uvs_vport_statistic_t *st,
    const uvs_vport_stats_info_t *vport_st)
{
    st->rm_vtp_est     = vport_st->rm_vtp.vtp_est;
    st->rc_vtp_est     = vport_st->rc_vtp.vtp_est;
    st->um_vtp_est     = vport_st->um_vtp.vtp_est;
    st->rm_vtp_active  = vport_st->rm_vtp.vtp_active;
    st->rc_vtp_active  = vport_st->rc_vtp.vtp_active;
    st->um_vtp_active  = vport_st->um_vtp.vtp_active;
    st->rm_vtp_failed  = vport_st->rm_vtp.vtp_failed;
    st->rc_vtp_failed  = vport_st->rc_vtp.vtp_failed;
    st->um_vtp_failed  = vport_st->um_vtp.vtp_failed;
    st->rm_vtp_opening = vport_st->rm_vtp.vtp_opening;
    st->rc_vtp_opening = vport_st->rc_vtp.vtp_opening;
    st->um_vtp_opening = vport_st->um_vtp.vtp_opening;
}

int uvs_query_vport_statistic_inner(const char* tpf_name, uvs_vport_info_key_t *vport,
    uvs_vport_statistic_t *st)
{
    uvs_vport_map_key_t key = { 0 };
    key.vport_key = *vport;
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_vport_key_map_node_t *map_node = lookup_map_node(&key);
    if (map_node == NULL || map_node->statistic == NULL) {
        TPSA_LOG_ERR("uvs query tpf %s and vport %s not match", tpf_name, vport);
        return -1;
    }

    uvs_load_vport_statistic(st, (const uvs_vport_stats_info_t *)map_node->statistic);
    return 0;
}

int uvs_query_tpf_statistic_inner(const char* tpf_name, uvs_tpf_statistic_t *st)
{
    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("uvs query tpf %s not match", tpf_name);
        return -1;
    }

    *st = tpf_node->statistic;
    return 0;
}