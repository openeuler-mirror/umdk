/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Token proxy module interface for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-12
 * Note:
 *   This module is NOT thread-safe. All operations must occur within a
 *   single-threaded epoll event loop.
 * History: 2026-05-12  Create File
 */

#ifndef UMS_AGENT_TOKEN_PROXY_H
#define UMS_AGENT_TOKEN_PROXY_H

#include <stdint.h>

int ums_agent_tp_init(uint16_t listen_port);
void ums_agent_tp_deinit(void);

void ums_agent_tp_timer_tick(void);

#endif /* UMS_AGENT_TOKEN_PROXY_H */
