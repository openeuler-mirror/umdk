/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs vport and tpf link statistic
 * Author: Yexiaokang
 * Create: 2024-1-18
 * Note:
 * History:
 */

#ifndef UVS_STATIS_H
#define UVS_STATIS_H

#include <stdint.h>
#include <stdbool.h>

#include "urma_types.h"
#include "ub_hmap.h"
#include "ub_hash.h"
#include "uvs_lm_table.h"
#include "tpsa_net.h"
#include "tpsa_nl.h"
#include "tpsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum uvs_vtp_state {
    UVS_VTP_OPENING_STATE = 0,
    UVS_VTP_SUCCESS_STATE,
    UVS_VTP_ERR_STATE,
    UVS_VTP_DESTROY_STATE,
    UVS_VTP_UNKNOWN
} uvs_vtp_state_t;

typedef enum uvs_tp_state {
    UVS_TP_OPENING_STATE = 0,
    UVS_TP_SUCCESS_STATE,
    UVS_TP_OPENING_FAIL_STATE,

    UVS_TP_CLOSING_STATE,
    UVS_TP_DESTROY_STATE,
    UVS_TP_CLOSING_FAIL_STATE,
    UVS_TP_UNKNOWN
} uvs_tp_state_t;

typedef enum uvs_tp_change_state {
    UVS_TP_TO_ERR_STATE,
    UVS_TP_TO_SUSPEND_STATE,
    UVS_TP_AWAY_ERR_STATE,
    UVS_TP_AWAY_SUSPEND_STATE,
    UVS_TP_SUSPEND_TO_ERR_STATE,
} uvs_tp_change_state_t;

typedef struct uvs_tpf_statistic_key {
    char tpf[URMA_MAX_DEV_NAME];
} uvs_tpf_statistic_key_t;

typedef struct uvs_statistic_table {
    struct ub_hmap hmap;
    pthread_rwlock_t lock;
} uvs_statistic_table_t;

typedef struct uvs_statistic_context {
    uvs_statistic_table_t vport_table;
    uvs_statistic_table_t tpf_table;
} uvs_statistic_ctx_t;

int uvs_statistic_ctx_init(uvs_statistic_ctx_t *ctx);

void uvs_statistic_ctx_uninit(uvs_statistic_ctx_t *ctx);

void uvs_set_global_statistic_enable(bool enable);

// need add/del subport and vport config info
void uvs_add_vport_statistic_config(const uvs_vport_info_t *info);
void uvs_del_vport_statistic_config(const char tpf_name[URMA_MAX_DEV_NAME],
    const vport_key_t *vport);

bool is_limit_create_vport(const vport_key_t *vport_key, tpsa_transport_mode_t mode);
void uvs_cal_vtp_create_stat(tpsa_nl_msg_t *msg, int status);

void uvs_cal_vtp_destroy_nl(tpsa_nl_msg_t *msg, int status);

void uvs_cal_vtp_destroy_socket(tpsa_sock_msg_t *msg);

void uvs_cal_tp_change_state_statistic(const char tpf_name[URMA_MAX_DEV_NAME], uvs_tp_change_state_t state);

void uvs_cal_vtp_statistic(vport_key_t *vport_key, tpsa_transport_mode_t mode,
    uvs_vtp_state_t state);

void uvs_cal_multi_tp_statistic(const char tpf_name[URMA_MAX_DEV_NAME], tpsa_transport_mode_t mode,
    uvs_tp_state_t state, uint32_t tp_cnt);

void uvs_cal_tp_statistic(const char tpf_name[URMA_MAX_DEV_NAME],
    tpsa_transport_mode_t mode, uvs_tp_state_t state);

void uvs_cal_tpg_statistic(const char tpf_name[URMA_MAX_DEV_NAME]);

int uvs_query_vport_statistic_inner(const vport_key_t *vport, uvs_vport_statistic_t *st);

int uvs_query_tpf_statistic_inner(const char *tpf_name, uvs_tpf_statistic_t *st);
#ifdef __cplusplus
}
#endif

#endif
