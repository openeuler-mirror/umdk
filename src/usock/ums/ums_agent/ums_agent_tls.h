/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: TLS module interface for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-07
 * Note:
 *   This module is NOT thread-safe. All operations must occur within a
 *   single-threaded epoll event loop. The caller is responsible for
 *   ensuring that no concurrent access to global state occurs.
 * History: 2026-05-07  Create File
 */

#ifndef UMS_AGENT_TLS_H
#define UMS_AGENT_TLS_H

#include <stdint.h>

#include "ums_agent_types.h"
#include "ums_agent_config.h"
#include "ums_agent_tls_conn.h"

int ums_agent_tls_init(const struct ums_agent_config *config);
void ums_agent_tls_deinit(void);

void ums_agent_tls_handle_event(int fd, uint32_t events);
void ums_agent_tls_timer_tick(const struct ums_agent_config *config);

#endif /* UMS_AGENT_TLS_H */
