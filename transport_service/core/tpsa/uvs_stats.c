/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs vport and tpf link statistic header file
 * Author: Yexiaokang
 * Create: 2024-1-18
 * Note:
 * History:
 */

#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#endif
#include "tpsa_log.h"
#include "ub_get_clock.h"
#include "uvs_stats.h"

#define UVS_SECOND_TO_US 1000000
#define RC_TP_CNT 2


typedef struct vtp_stats_info {
    uint64_t vtp_est;
    uint64_t vtp_active;
    uint64_t vtp_failed;
    uint64_t vtp_opening;
    uint64_t next_update_time; /* relies on virtual traffic updates per second, ms */
    uint64_t vtp_cnt; /* Number of connections established within the period specified by vtp_per_us */
} vtp_stats_info_t;

typedef struct uvs_vport_stats_info {
    vtp_stats_info_t rm_vtp;
    vtp_stats_info_t rc_vtp;
    vtp_stats_info_t um_vtp;
} uvs_vport_stats_info_t;

struct vport_limit_rate_config {
    uint32_t rm_vtp_max_cnt;
    uint32_t rc_vtp_max_cnt;
    uint32_t um_vtp_max_cnt;
    uint64_t vtp_per_us; /* us */
};

typedef struct uvs_vport_statistic_node {
    struct ub_hmap_node node;
    uvs_vport_stats_info_t statistic;
    struct vport_limit_rate_config limit_config;
    vport_key_t key;
#ifndef __cplusplus
    atomic_uint use_cnt; // subport and port reference counting, if 0, delete current node
#else
    std::atomic_uint use_cnt;
#endif
} uvs_vport_statistic_node_t;

typedef struct uvs_tpf_statistic_node {
    struct ub_hmap_node node;
    uvs_tpf_statistic_t statistic;
    uvs_tpf_statistic_key_t key;
#ifndef __cplusplus
    atomic_uint use_cnt; // subport and port reference counting, if 0, delete current node
#else
    std::atomic_uint use_cnt;
#endif
} uvs_tpf_statistic_node_t;

static bool g_global_statistic_enable = false;

static uvs_statistic_ctx_t *g_statistic_ctx = NULL;

void uvs_set_global_statistic_enable(bool enable)
{
    g_global_statistic_enable = enable;
    TPSA_LOG_INFO("%s the global statistic switch.\n", (enable ? "enable" : "disable"));
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

int uvs_statistic_ctx_init(uvs_statistic_ctx_t *ctx)
{
    if (ctx == NULL) {
        TPSA_LOG_ERR("ctx is null_ptr.\n");
        return -1;
    }

    if (uvs_create_statistic_table(&ctx->tpf_table) != 0) {
        TPSA_LOG_ERR("uvs_create_statistic_table tpf err.\n");
        return -1;
    }

    if (uvs_create_statistic_table(&ctx->vport_table) != 0) {
        uvs_destroy_tpf_statistic_table(&ctx->tpf_table);
        TPSA_LOG_ERR("uvs_create_statistic_table vport err.\n");
        return -1;
    }

    g_statistic_ctx = ctx;
    TPSA_LOG_INFO("uvs statistic init complete.\n");
    return 0;
}

void uvs_statistic_ctx_uninit(uvs_statistic_ctx_t *ctx)
{
    if (ctx == NULL) {
        TPSA_LOG_WARN("the ctx has been released.\n");
        return;
    }

    if (ctx != g_statistic_ctx) {
        TPSA_LOG_WARN("the ctx not match g_statistic_ctx.\n");
        return;
    }

    uvs_destroy_tpf_statistic_table(&ctx->tpf_table);
    uvs_destroy_vport_statistic_table(&ctx->vport_table);
    g_statistic_ctx = NULL;
    TPSA_LOG_INFO("uvs statistic uninit complete.\n");
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

/* tpf is an input parameter of uvs_query_tpf_statistic_inner, which may not be the same as the
    input parameter tpf_name (64 bytes) of uvs_add_vport. A character string is required. */
uint32_t uvs_tpf_hash_bytes(const uvs_tpf_statistic_key_t *key)
{
    return ub_hash_bytes(key->tpf, strlen(key->tpf), 0);
}

static uvs_tpf_statistic_node_t *lookup_tpf_statistic_node(const uvs_tpf_statistic_key_t *key)
{
    uint32_t hash = uvs_tpf_hash_bytes(key);
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

static uvs_vport_statistic_node_t *add_vport_statistic_node(const vport_key_t *key,
    struct vport_limit_rate_config config)
{
    uvs_vport_statistic_node_t *vport_node =
        (uvs_vport_statistic_node_t *)calloc(1, sizeof(uvs_vport_statistic_node_t));
    if (vport_node == NULL) {
        return NULL;
    }

    vport_node->key = *key;
    vport_node->limit_config = config;
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
    uint32_t hash = uvs_tpf_hash_bytes(key);
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->tpf_table.lock);
    ub_hmap_insert(&g_statistic_ctx->tpf_table.hmap, &tpf_node->node, hash);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->tpf_table.lock);

    return tpf_node;
}

static void remove_vport_statistic_node(uvs_vport_statistic_node_t *statistic_node)
{
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->vport_table.lock);
    ub_hmap_remove(&g_statistic_ctx->vport_table.hmap, &statistic_node->node);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->vport_table.lock);
}

static void remove_tpf_statistic_node(uvs_tpf_statistic_node_t *node)
{
    (void)pthread_rwlock_wrlock(&g_statistic_ctx->tpf_table.lock);
    ub_hmap_remove(&g_statistic_ctx->tpf_table.hmap, &node->node);
    (void)pthread_rwlock_unlock(&g_statistic_ctx->tpf_table.lock);
}

static inline uint64_t uvs_get_vtp_per_us(uint32_t second)
{
    return (uint64_t)(get_cpu_mhz(false) * second * UVS_SECOND_TO_US);
}

static void limit_config_init(struct vport_limit_rate_config *config,
    const uvs_vport_info_t *info)
{
    if (info->mask.bs.rc_max_cnt != 0) {
        config->rc_vtp_max_cnt = info->rc_max_cnt;
        TPSA_LOG_DEBUG("uvs config rc vtp mac cnt %u.\n", info->rc_max_cnt);
    }
    if (info->mask.bs.rm_vtp_max_cnt != 0) {
        config->rm_vtp_max_cnt = info->rm_vtp_max_cnt;
        TPSA_LOG_DEBUG("uvs config rm vtp mac cnt %u.\n", info->rm_vtp_max_cnt);
    }
    if (info->mask.bs.um_vtp_max_cnt != 0) {
        config->um_vtp_max_cnt = info->um_vtp_max_cnt;
        TPSA_LOG_DEBUG("uvs config um vtp mac cnt %u.\n", info->um_vtp_max_cnt);
    }
    if (info->mask.bs.vtp_per_second != 0) {
        config->vtp_per_us = uvs_get_vtp_per_us(info->vtp_per_second);
        TPSA_LOG_DEBUG("uvs config vtp per second %u to cpu per ms %lu.\n",
            info->vtp_per_second, config->vtp_per_us);
    }
    TPSA_LOG_INFO("uvs vport mask value %u.\n", info->mask.value);
}

static uvs_vport_statistic_node_t *uvs_add_vtp_config_node(
    const uvs_vport_info_t *info, const vport_key_t *key)
{
    uvs_vport_statistic_node_t *node = lookup_vport_statistic_node(key);
    if (node != NULL) {
        (void)atomic_fetch_add(&node->use_cnt, 1U);
        TPSA_LOG_INFO("tpf name %s, fe_idx %u already exists, use cnt %u update complete.\n",
                      key->tpf_name, key->fe_idx, atomic_load(&node->use_cnt));
        return node;
    }

    struct vport_limit_rate_config config = { 0 };
    limit_config_init(&config, info);
    node = add_vport_statistic_node(key, config);
    if (node == NULL) {
        TPSA_LOG_ERR("tpf name %s, fe_idx %u add failed.\n", key->tpf_name, key->fe_idx);
        return NULL;
    }
    atomic_store(&node->use_cnt, 1U);

    return node;
}

static void uvs_try_del_vtp_node(const vport_key_t *vport)
{
    uvs_vport_statistic_node_t *node = lookup_vport_statistic_node(vport);
    if (node == NULL) {
        TPSA_LOG_WARN("tpf %s and fe_idx %u not exists.\n", vport->tpf_name, vport->fe_idx);
        return;
    }

    (void)atomic_fetch_sub(&node->use_cnt, 1U);
    if (atomic_load(&node->use_cnt) != 0) {
        return;
    }

    remove_vport_statistic_node(node);
    free(node);
    TPSA_LOG_INFO("del tpf %s and fe_idx %u config complete.\n", vport->tpf_name, vport->fe_idx);
}

static uvs_tpf_statistic_node_t *uvs_add_tp_config_node(const char tpf_name[URMA_MAX_DEV_NAME])
{
    uvs_tpf_statistic_key_t tpf_key = { 0 };
    (void)memcpy(tpf_key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&tpf_key);
    if (tpf_node != NULL) {
        (void)atomic_fetch_add(&tpf_node->use_cnt, 1U);
        TPSA_LOG_INFO("tpf name %s already exists, use cnt %u update complete.\n",
                      tpf_name, atomic_load(&tpf_node->use_cnt));
        return tpf_node;
    }

    tpf_node = add_tpf_statistic_node(&tpf_key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("add tpf statistic node tpf name %s err.\n", tpf_name);
        return NULL;
    }

    atomic_store(&tpf_node->use_cnt, 1U);
    TPSA_LOG_INFO("tpf name %s first add config complete.\n", tpf_name);

    return tpf_node;
}

static void uvs_try_del_tp_node(const char tpf_name[URMA_MAX_DEV_NAME])
{
    uvs_tpf_statistic_key_t tpf_key = { 0 };
    (void)memcpy(tpf_key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&tpf_key);
    if (tpf_node == NULL) {
        TPSA_LOG_INFO("tpf name %s not exists.\n", tpf_name);
        return;
    }

    (void)atomic_fetch_sub(&tpf_node->use_cnt, 1U);
    if (atomic_load(&tpf_node->use_cnt) == 0) {
        remove_tpf_statistic_node(tpf_node);
        free(tpf_node);
    }
    TPSA_LOG_INFO("tpf name %s del statistic config complete.\n", tpf_name);
}

void uvs_add_vport_statistic_config(const uvs_vport_info_t *info)
{
    vport_key_t key = { 0 };
    (void)memcpy(key.tpf_name, info->tpf_name, URMA_MAX_DEV_NAME);
    key.fe_idx = info->fe_idx;
    uvs_vport_statistic_node_t *vtp_node = uvs_add_vtp_config_node(info, &key);
    if (vtp_node == NULL) {
        return;
    }

    if (uvs_add_tp_config_node(info->tpf_name) == NULL) {
        uvs_try_del_vtp_node(&key);
    }
}

void uvs_del_vport_statistic_config(const char tpf_name[URMA_MAX_DEV_NAME], const vport_key_t *vport)
{
    uvs_try_del_vtp_node(vport);
    uvs_try_del_tp_node(tpf_name);
}

static inline void cal_vtp_success_statistic(vtp_stats_info_t *vtp_info)
{
    if (vtp_info->vtp_opening > 0) {
        vtp_info->vtp_opening--;
    } else {
        TPSA_LOG_DEBUG("num of vtp_opening is zero.\n");
    }
    vtp_info->vtp_est++;
    vtp_info->vtp_active++;
}

static inline void cal_vtp_failed_statistic(vtp_stats_info_t *vtp_info)
{
    if (vtp_info->vtp_opening > 0) {
        vtp_info->vtp_opening--;
    } else {
        TPSA_LOG_DEBUG("num of vtp_opening is zero.\n");
    }
    vtp_info->vtp_failed++;
}

static inline void cal_vtp_destroy_statistic(vtp_stats_info_t *vtp_info)
{
    if (vtp_info->vtp_active > 0) {
        vtp_info->vtp_active--;
    } else {
        TPSA_LOG_DEBUG("num of vtp_opening is zero.\n");
    }
}

static inline void cal_vtp_opening_statistic(vtp_stats_info_t *vtp_info)
{
    vtp_info->vtp_opening++;
    vtp_info->vtp_cnt++;
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
            TPSA_LOG_ERR("the mode %d of the vport statistics are incorrect.\n", mode);
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
            TPSA_LOG_ERR("the state %hu of the vport statistics are incorrect.\n", state);
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
            TPSA_LOG_ERR("the mode %hu of the tp est statistics are incorrect.\n", mode);
            break;
    }
}

static void cal_tp_destroy_statistic(uvs_tpf_statistic_t *st, tpsa_transport_mode_t mode)
{
    switch (mode) {
        case TPSA_TP_RM:
            if (st->rm_tp_active > 0) {
                st->rm_tp_active--;
            } else {
                TPSA_LOG_DEBUG("num of rm_tp_active is zero.\n");
            }
            break;
        case TPSA_TP_RC:
            if (st->rc_tp_active > 0) {
                st->rc_tp_active--;
            } else {
                TPSA_LOG_DEBUG("num of rc_tp_active is zero.\n");
            }
            break;
        case TPSA_TP_UM:
            if (st->utp_active > 0) {
                st->utp_active--;
            } else {
                TPSA_LOG_DEBUG("num of utp_active is zero.\n");
            }
            break;
        default:
            TPSA_LOG_ERR("the mode %hu of the tpf destroy statistics are incorrect.\n", mode);
            break;
    }
}

static void cal_tp_statistic(uvs_tpf_statistic_t *st, tpsa_transport_mode_t mode,
    uvs_tp_state_t state)
{
    switch (state) {
        case UVS_TP_SUCCESS_STATE:
            if (st->tp_opening > 0) {
                st->tp_opening--;
            } else {
                TPSA_LOG_DEBUG("num of tp_opening is zero.\n");
            }
            cal_tp_est_statistic(st, mode);
            break;
        case UVS_TP_DESTROY_STATE:
            if (st->tp_closing > 0) {
                st->tp_closing--;
            } else {
                TPSA_LOG_DEBUG("num of tp_closing is zero.\n");
            }
            cal_tp_destroy_statistic(st, mode);
            break;
        case UVS_TP_OPENING_STATE:
            st->tp_opening++;
            break;
        case UVS_TP_OPENING_FAIL_STATE:
            if (st->tp_opening > 0) {
                st->tp_opening--;
            } else {
                TPSA_LOG_DEBUG("num of tp_opening is zero.\n");
            }
            break;
        case UVS_TP_CLOSING_STATE:
            st->tp_closing++;
            break;
        case UVS_TP_CLOSING_FAIL_STATE:
            if (st->tp_closing > 0) {
                st->tp_closing--;
            } else {
                TPSA_LOG_DEBUG("num of tp_opening is zero.\n");
            }
            break;
        case UVS_TP_UNKNOWN:
        default:
            TPSA_LOG_ERR("the state %hu and mode %hu of the tpf tp statistics "
                         "are incorrect.\n", state, mode);
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

void uvs_cal_vtp_create_stat(tpsa_nl_msg_t *msg, int status)
{
    tpsa_nl_req_host_t *req_host = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)req_host->req.data;
    if (strnlen(nlreq->tpf_name, UVS_MAX_DEV_NAME) > UVS_MAX_DEV_NAME - 1) {
        TPSA_LOG_ERR("Invalid tpf_name length.\n");
        return;
    }
    vport_key_t key = { 0 };
    key.fe_idx = req_host->src_fe_idx;
    (void)memcpy(key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    if (status == TPSA_NL_RESP_SUCCESS) {
        uvs_cal_vtp_statistic(&key, nlreq->trans_mode, UVS_VTP_SUCCESS_STATE);
    } else {
        uvs_cal_vtp_statistic(&key, nlreq->trans_mode, UVS_VTP_ERR_STATE);
    }
}

void uvs_cal_vtp_destroy_nl(tpsa_nl_msg_t *msg, int status)
{
    tpsa_nl_req_host_t *req_host = (tpsa_nl_req_host_t *)msg->payload;
    tpsa_nl_create_vtp_req_t *nlreq = (tpsa_nl_create_vtp_req_t *)req_host->req.data;
    if (strnlen(nlreq->tpf_name, UVS_MAX_DEV_NAME) > UVS_MAX_DEV_NAME - 1) {
        TPSA_LOG_ERR("Invalid tpf_name length.\n");
        return;
    }
    vport_key_t key = { 0 };
    key.fe_idx = req_host->src_fe_idx;
    (void)memcpy(key.tpf_name, nlreq->tpf_name, UVS_MAX_DEV_NAME);

    if (status == TPSA_NL_RESP_SUCCESS) {
        if (is_uvs_create_rc_shared_tp(nlreq->trans_mode, nlreq->sub_trans_mode, nlreq->rc_share_tp)) {
            uvs_cal_vtp_statistic(&key, TPSA_TP_RM, UVS_VTP_DESTROY_STATE);
        } else {
            uvs_cal_vtp_statistic(&key, nlreq->trans_mode, UVS_VTP_DESTROY_STATE);
        }
    } else {
        TPSA_LOG_ERR("destroy vtp failed.\n");
    }
}

void uvs_cal_vtp_destroy_socket(tpsa_sock_msg_t *msg)
{
    if (strnlen(msg->content.dfinish.src_tpf_name, UVS_MAX_DEV_NAME) > UVS_MAX_DEV_NAME - 1) {
        TPSA_LOG_ERR("Invalid tpf_name length.\n");
        return;
    }
    vport_key_t key = { 0 };
    key.fe_idx = msg->content.dfinish.src_fe_idx;
    (void)memcpy(key.tpf_name, msg->content.dfinish.src_tpf_name, UVS_MAX_DEV_NAME);
    uvs_cal_vtp_statistic(&key, msg->trans_mode, UVS_VTP_DESTROY_STATE);
}

void uvs_cal_tp_change_state_statistic(const char tpf_name[URMA_MAX_DEV_NAME], uvs_tp_change_state_t state)
{
    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("the tpf_name: %s is incorrect.\n", tpf_name);
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
            if (tpf_node->statistic.tp_error > 0) {
                tpf_node->statistic.tp_error--;
            } else {
                TPSA_LOG_DEBUG("num of tp_error is zero.\n");
            }
            break;
        case UVS_TP_AWAY_SUSPEND_STATE:
            if (tpf_node->statistic.tp_suspend > 0) {
                tpf_node->statistic.tp_suspend--;
            } else {
                TPSA_LOG_DEBUG("num of tp_suspend is zero.\n");
            }
            break;
        case UVS_TP_SUSPEND_TO_ERR_STATE:
            if (tpf_node->statistic.tp_suspend > 0) {
                tpf_node->statistic.tp_suspend--;
            } else {
                TPSA_LOG_DEBUG("num of tp_suspend is zero.\n");
            }
            tpf_node->statistic.tp_error++;
            break;
        default:
            TPSA_LOG_ERR("the state of the tpf tp statistics is incorrect.\n");
            break;
    }
}

void uvs_cal_multi_tp_statistic(const char tpf_name[URMA_MAX_DEV_NAME], tpsa_transport_mode_t mode,
    uvs_tp_state_t state, uint32_t tp_cnt)
{
    uvs_tpf_statistic_key_t tpf_key = { 0 };

    if (!g_global_statistic_enable) {
        return;
    }

    (void)memcpy(tpf_key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&tpf_key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("lookup multi tp statistic node tpf name %s err.\n", tpf_name);
        return;
    }

    uint32_t cnt = mode == TPSA_TP_RC ? RC_TP_CNT : tp_cnt;
    for (uint32_t i = 0 ; i < cnt; i++) {
        cal_tp_statistic(&tpf_node->statistic, mode, state);
    }
}

void uvs_cal_tp_statistic(const char tpf_name[URMA_MAX_DEV_NAME], tpsa_transport_mode_t mode, uvs_tp_state_t state)
{
    if (!g_global_statistic_enable) {
        return;
    }

    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("lookup tpf statistic node tpf name %s err.\n", tpf_name);
        return;
    }

    cal_tp_statistic(&tpf_node->statistic, mode, state);
}

void uvs_cal_tpg_statistic(const char tpf_name[URMA_MAX_DEV_NAME])
{
    if (!g_global_statistic_enable) {
        return;
    }

    uvs_tpf_statistic_key_t key = { 0 };
    (void)memcpy(key.tpf, tpf_name, URMA_MAX_DEV_NAME);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("not lookup tpf statistic table tpf name %s err.\n", tpf_name);
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

int uvs_query_vport_statistic_inner(const vport_key_t *vport, uvs_vport_statistic_t *st)
{
    uvs_vport_statistic_node_t *vport_node = lookup_vport_statistic_node(vport);
    if (vport_node == NULL) {
        TPSA_LOG_ERR("uvs query vport %s , but not find.\n", vport->tpf_name);
        return -1;
    }

    uvs_load_vport_statistic(st, (const uvs_vport_stats_info_t *)&vport_node->statistic);
    return 0;
}

int uvs_query_tpf_statistic_inner(const char* tpf_name, uvs_tpf_statistic_t *st)
{
    uvs_tpf_statistic_key_t key = { 0 };
    (void)strcpy(key.tpf, tpf_name);
    uvs_tpf_statistic_node_t *tpf_node = lookup_tpf_statistic_node(&key);
    if (tpf_node == NULL) {
        TPSA_LOG_ERR("uvs query tpf %s not match.\n", tpf_name);
        return -1;
    }

    *st = tpf_node->statistic;
    return 0;
}

static bool is_limit(vtp_stats_info_t *vtp_info, uint32_t max_value, uint64_t vtp_per_us)
{
    if (max_value == 0 || vtp_per_us == 0) {
        return false;
    }

    uint64_t cur_tm = get_cycles();
    /* Check whether the current time meets the next update time requirement */
    if (vtp_info->next_update_time < cur_tm) { // update time and cnt
        vtp_info->next_update_time = cur_tm + vtp_per_us;
        vtp_info->vtp_cnt = 0;
        return false;
    }

    /* The maximum number of connections is not reached in the current period */
    return (vtp_info->vtp_cnt >= max_value);
}

static bool is_limit_create_vport_inner(uvs_vport_statistic_node_t *node,
    tpsa_transport_mode_t mode)
{
    switch (mode) {
        case TPSA_TP_RM:
            return is_limit((&(node->statistic.rm_vtp)),
                            node->limit_config.rm_vtp_max_cnt,
                            node->limit_config.vtp_per_us);
        case TPSA_TP_RC:
            return is_limit((&(node->statistic.rc_vtp)),
                            node->limit_config.rc_vtp_max_cnt,
                            node->limit_config.vtp_per_us);
        case TPSA_TP_UM:
            return is_limit((&(node->statistic.um_vtp)),
                            node->limit_config.um_vtp_max_cnt,
                            node->limit_config.vtp_per_us);
        default:
            TPSA_LOG_ERR("the mode %u of the vport opening statistics are incorrect.\n", (uint32_t)mode);
    }

    return false;
}

bool is_limit_create_vport(const vport_key_t *vport_key, tpsa_transport_mode_t mode)
{
    if (!g_global_statistic_enable) {
        return false;
    }

    uvs_vport_statistic_node_t *vport_node = lookup_vport_statistic_node(vport_key);
    if (vport_node == NULL) {
        return false;
    }

    return is_limit_create_vport_inner(vport_node, mode);
}