/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define notify msg api
 * Create: 2024-5-8
 * Note:
 * History: 2024-5-8
 */

#ifndef NOTIFY_H
#define NOTIFY_H

#include "urpc_list.h"
#include "urpc_framework_types.h"
#include "urpc_hmap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct queue_notify_msg {
    urpc_list_t node;
    urpc_sge_t *args;
    uint32_t args_sge_num;
    urpc_poll_event_t event;
    urpc_poll_err_event_t err_event;
    uint32_t urpc_chid;
    uint64_t req_h;
    uint64_t urpc_qh;
    void *user_ctx;
    uint32_t err_code;
} queue_notify_msg_t;

typedef struct queue_notify_msg_info {
    struct urpc_hmap_node node;
    uint64_t qh;
    urpc_list_t list;
    pthread_spinlock_t list_lock;
} queue_notify_msg_info_t;

typedef struct queue_notify_data {
    uint32_t client_chid;
    uint32_t server_chid;
    uint32_t req_id;
    urpc_poll_event_t event;
    urpc_poll_err_event_t err_event;
    urpc_sge_t *args;
    uint64_t send_qh;
    void *user_ctx;
    uint32_t args_num;
} queue_notify_data_t;

int urpc_notify_table_init(void);
void urpc_notify_table_uninit(void);
void generate_queue_notify_msg(queue_notify_data_t *rp_data, uint32_t err_code);
int poll_notify_msg(uint64_t qh, urpc_poll_msg_t *msgs, int num);
int add_queue_notify_msg_table(uint64_t qh);
void rm_queue_notify_msg_table(uint64_t qh);
bool queue_in_notify_msg_table(uint64_t qh);
void queue_notify_msg_table_rdlock(void);
void queue_notify_msg_table_unlock(void);

#ifdef __cplusplus
}
#endif

#endif
