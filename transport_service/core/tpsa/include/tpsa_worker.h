/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa worker header file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port core routines from daemon here
 */

#ifndef TPSA_WORKER_H
#define TPSA_WORKER_H

#include "uvs_types.h"
#include "tpsa_table.h"
#include "tpsa_sock.h"
#include "tpsa_nl.h"
#include "tpsa_net.h"
#include "tpsa_tbl_manage.h"
#include "tpsa_ioctl.h"
#include "uvs_tp_manage.h"
#include "tpsa_types.h"
#include "uvs_lm.h"
#include "urma_types.h"
#include "uvs_stats.h"

#ifdef __cplusplus
extern "C" {
#endif
#define MAX_VTP_EVENT_SIZE 5

enum uvs_vtp_event {
    VTP_EVENT_SWITCH = 0,
    VTP_EVENT_ROLLBACK,
    VTP_EVENT_SRC_DELETE,
    VTP_EVENT_DST_DELETE,
    VTP_EVENT_DIP_REFRESH,
};
typedef struct tpsa_worker {
    tpsa_global_cfg_t global_cfg_ctx;
    tpsa_table_t table_ctx;
    tpsa_sock_ctx_t sock_ctx;
    tpsa_nl_ctx_t nl_ctx;
    tpsa_ioctl_ctx_t ioctl_ctx;
    uvs_socket_init_attr_t tpsa_attr; /* IP information of local uvs module */
    uvs_statistic_ctx_t statistic_ctx; // statistic_ctx table
    bool stop;
    pthread_t thread;
    int epollfd;
} tpsa_worker_t;

typedef int (*tpsa_vtp_event_handler)(uvs_ctx_t *ctx, tpsa_vtp_cfg_t *vtp_cfg,
    vport_key_t *vport_key, tpsa_lm_vtp_entry_t *lm_vtp_entry, uvs_tp_msg_ctx_t *tp_msg_ctx);

tpsa_worker_t *tpsa_worker_init(uvs_init_attr_t *attr);
void tpsa_worker_uninit(tpsa_worker_t *worker);
int tpsa_worker_socket_init(tpsa_worker_t *worker);

int uvs_destroy_target_vtp_for_lm(uvs_ctx_t *ctx, uvs_tp_msg_ctx_t *tp_msg_ctx);
/**
 * get ctx.
 * Return: 0 on success, other value on error.
 */
tpsa_worker_t *uvs_get_worker(void);   /* obselete, not to be exposed in the future */

bool tpsa_get_tp_fast_destroy(void);
void tpsa_set_tp_fast_destroy(bool tp_fast_destory);
user_ops_t get_user_ops_type(const char *user_ops);

int tpsa_restore_vtp_table(tpsa_worker_t *worker);
int tpsa_restore_wait_list(tpsa_table_t *tbl_ctx, uint32_t wait_restored_timeout);

#ifdef __cplusplus
}
#endif

#endif