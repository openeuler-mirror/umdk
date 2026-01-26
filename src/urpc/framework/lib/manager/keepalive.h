/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define keepalive task management
 * Create: 2024-11-19
 */

#ifndef KEEPALIVE_H
#define KEEPALIVE_H

#include <pthread.h>

#include "channel.h"
#include "protocol.h"
#include "queue.h"
#include "urpc_hmap.h"
#include "urpc_list.h"
#include "urpc_timer.h"
#include "urpc_framework_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_KEEPALIVE_VERSION 0
#define URPC_KEEPALIVE_MSG_SIZE (2048)
#define URPC_KEEPALIVE_HDR_SIZE (sizeof(urpc_req_head_t) + sizeof(urpc_keepalive_head_t))

#define URPC_KEEPALIVE_TASK_STOPPED 0
#define URPC_KEEPALIVE_TASK_RUNNING 1

// keepalive channel id
typedef struct urpc_keepalive_id {
    union {
        struct {
            uint32_t client_chid;
            uint32_t server_chid;
        };
        uint64_t id;
    };
} urpc_keepalive_id_t;

typedef struct urpc_keepalive_entry {
    pthread_spinlock_t lock;
    urpc_instance_key_t key;
    struct urpc_hmap_node task_node;

    uint64_t cpu_cycles;
    uint8_t remote_version;
    uint8_t primary_is_server : 1;  // local is primary logic server, been attached as server firstly [and attach to
                                    // server]
    uint8_t has_client : 1;
    uint8_t has_server : 1;
    uint8_t client_status : 1; // 1 valid, 0 stopped
    uint8_t rsvd : 4;

    // if local is logic server
    struct urpc_hmap_node server_id_node;
    urpc_list_t list;  // in reachable list
    urpc_keepalive_id_t server_task_id;
    uint64_t user_ctx;                                  // used for keepalive callback
    uint32_t server_chid[URPC_MAX_CHANNEL_PER_CLIENT];  // server channel id, local logic server use
    uint8_t server_chid_num;

    // if local is logic client
    urpc_timer_t *timer;
    struct urpc_hmap_node client_id_node;
    struct urpc_hmap_node server_info_node;
    urpc_keepalive_id_t client_task_id;
    urpc_host_info_inner_t server_inner;
} urpc_keepalive_task_entry_t;

typedef struct urpc_keepalive_task_info {
    urpc_host_info_t *server;  // used for logic client
    uint64_t user_ctx;
    uint32_t server_chid;
    uint32_t client_chid;
    uint8_t remote_version;
    uint8_t is_server : 1;
    uint8_t remote_primary_is_server : 1;
    uint8_t rsvd : 6;
} urpc_keepalive_task_info_t;

int urpc_keepalive_init(urpc_keepalive_config_t *cfg);
void urpc_keepalive_uninit(void);

int urpc_keepalive_probe_init(urpc_keepalive_config_t *cfg);
void urpc_keepalive_probe_uninit(void);

uint64_t urpc_keepalive_queue_handle_get(void);
uint32_t urpc_keepalive_cycle_time_get(void);
uint32_t urpc_keepalive_check_time_get(void);
uint32_t urpc_keepalive_release_time_get(void);
keepalive_callback_t urpc_keepalive_callback_get(void);

int urpc_keepalive_request_send(urpc_keepalive_task_entry_t *entry);
void urpc_keepalive_process_msg(struct urpc_poll_msg *msgs, int poll_num, urpc_poll_option_t *poll_opt);
int urpc_keepalive_msg_send(urpc_keepalive_id_t *id);

int urpc_keepalive_task_init(void);
void urpc_keepalive_task_uninit(void);

bool urpc_keepalive_task_primary_is_client(urpc_instance_key_t *key);

int urpc_keepalive_task_create(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info);
void urpc_keepalive_task_delete(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info);

int keepalive_task_restart(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info);
int keepalive_task_stop(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info);

int urpc_keepalive_task_server_chid_add(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info);
void urpc_keepalive_task_server_chid_delete(urpc_instance_key_t *key, urpc_keepalive_task_info_t *info);

void urpc_keepalive_check(void *args);
void urpc_keepalive_task_timestamp_update(urpc_keepalive_id_t *id, bool is_server);
int urpc_keepalive_task_entry_info_get(urpc_keepalive_id_t *id, bool is_server, urpc_keepalive_event_info_t *info);

#ifdef __cplusplus
}
#endif

#endif