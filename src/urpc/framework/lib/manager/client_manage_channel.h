/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize client manage channel id maintainer, one client to one server maintains one manager channel
 * Create: 2024-8-28
 */

#ifndef CLIENT_MANAGE_CHANNEL_H
#define CLIENT_MANAGE_CHANNEL_H

#include <stdbool.h>
#include <stdint.h>

#include "urpc_framework_types.h"
#include "channel.h"

#ifdef __cplusplus
extern "C" {
#endif

int client_manage_channel_init(void);
void client_manage_channel_uninit(void);
uint32_t client_manage_channel_ref_get(urpc_host_info_t *server);
uint32_t client_manage_channel_put(urpc_host_info_t *server, uint32_t channel_id, bool delayed, bool is_async);
void client_manage_channel_delayed_reset(
    urpc_host_info_t *server, urpc_instance_key_t *key, uint32_t server_chid, uint32_t client_chid);
server_node_t *manage_channel_get_server_node(urpc_channel_info_t *channel);
void urpc_client_manage_channel_ctx_lock(void);
void urpc_client_manage_channel_ctx_unlock(void);

#ifdef __cplusplus
}
#endif

#endif
