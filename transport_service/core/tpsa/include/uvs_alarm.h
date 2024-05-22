/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: uvs alarm header file
 * Author: Wuyuyan
 * Create: 2024-05-06
 * Note:
 * History: 2024-05-06 create this file to support alarm type definition in uvs
 */

#ifndef UVS_ALARM_H
#define UVS_ALARM_H

#include "uvs_types.h"
#include "tpsa_table.h"
#include "tpsa_sock.h"
#include "tpsa_nl.h"
#include "tpsa_tbl_manage.h"
#include "tpsa_worker.h"

/* 50ms */
#define UVS_EXPIRATION_TIME_DUR 50
#define UVS_ALARM_MAX_RETRY_TIME 40
#define UVS_MAX_ALARM_EXEC_CNT 16

typedef enum uvs_alarm_type {
    UVS_NL_CREATE_VTP_ALARM         = 0,
    UVS_SOCK_CREATE_VTP_REQ_ALARM   = 1,
} uvs_alarm_type_t;

typedef int(*on_alarm_cb_t)(tpsa_worker_t *worker, uint8_t retry_num_left, void *arg);

typedef struct uvs_nl_create_vtp_alarm_arg {
    tpsa_nl_msg_t nl_msg;
} uvs_nl_create_vtp_alarm_arg_t;

typedef struct uvs_sock_create_vtp_req_alarm_arg {
    tpsa_sock_msg_t sock_msg;
    int fd;
} uvs_sock_create_vtp_req_alarm_arg_t;

typedef struct uvs_alarm_node {
    struct ub_list node;
    uvs_alarm_type_t type;
    uint64_t set_ts;        /* ms */
    uint64_t exp_ts;        /* ms */
    uint8_t retry_num_left; /* initialized as max_retry_num */
    void *arg;
    on_alarm_cb_t cb;
} uvs_alarm_node_t;

typedef struct uvs_alarm {
    uvs_alarm_type_t type;
    uint64_t exp_time_dur; /* ms */
    uint8_t max_retry_num;
    on_alarm_cb_t cb;
} uvs_alarm_t;

/*
* alarm list ops
*/
int uvs_set_alarm(tpsa_worker_t *worker, uvs_alarm_type_t type, void *arg);
void uvs_process_expired_timer(tpsa_worker_t *worker);
static inline void uvs_alarm_list_destroy(struct ub_list *alarm_list)
{
    uvs_alarm_node_t *cur_alarm, *next_alarm;
    UB_LIST_FOR_EACH_SAFE(cur_alarm, next_alarm, node, alarm_list) {
        ub_list_remove(&cur_alarm->node);
        free(cur_alarm->arg);
        cur_alarm->arg = NULL;
        cur_alarm->cb = NULL;
        free(cur_alarm);
    }
}

/* set alarm for different task types */
int uvs_set_nl_create_vtp_alarm(tpsa_worker_t *worker, tpsa_nl_msg_t *msg);
void uvs_set_sock_create_vtp_req_alarm(tpsa_worker_t *worker, tpsa_sock_msg_t *msg, int fd);

/* cb func for different task types */
int uvs_handle_nl_create_vtp_task_retry(tpsa_worker_t *worker, uint8_t retry_num_left, void *arg);
int uvs_handle_sock_create_vtp_req_task_retry(tpsa_worker_t *worker, uint8_t retry_num_left, void *arg);

#endif