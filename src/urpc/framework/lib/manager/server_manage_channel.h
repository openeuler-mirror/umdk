/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize server manage channel, one client to one server maintains one manager channel
 * Create: 2024-8-29
 */

#ifndef SERVER_MANAGE_CHANNEL_H
#define SERVER_MANAGE_CHANNEL_H

#ifdef __cplusplus
extern "C" {
#endif

void server_manage_channel_uninit(void);
int server_manage_channel_get(urpc_instance_key_t *client, uint32_t client_manage_chid, uint64_t user_ctx,
    uint32_t *mange_chid, uint32_t *mapped_id);
uint32_t server_manage_channel_put(urpc_instance_key_t *client, bool delayed, bool skip_ka_task_delete);
void server_mange_channel_delayed_reset(urpc_instance_key_t *client, uint32_t server_chid, uint32_t client_chid);

#ifdef __cplusplus
}
#endif

#endif