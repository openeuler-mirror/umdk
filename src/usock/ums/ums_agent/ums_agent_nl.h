/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Netlink communication layer for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-13
 * Note:
 *   This module is NOT thread-safe. All operations must occur within a
 *   single-threaded epoll event loop. The caller is responsible for
 *   ensuring that no concurrent access to global state occurs.
 * History: 2026-05-13  Create File
 */

#ifndef UMS_AGENT_NL_H
#define UMS_AGENT_NL_H

#include <stdbool.h>
#include <stdint.h>

#include "ums_agent_types.h"

#define UMS_GENL_NAME    "UMS_GENL"
#define UMS_GENL_VERSION 1

enum ums_nl_cmd {
    UMS_CMD_UNSPEC,
    UMS_CMD_READY,
    UMS_CMD_DOWN,
    UMS_CMD_TOKEN_SUBMIT,
    UMS_CMD_TOKEN_SUBMIT_FAIL,
    UMS_CMD_TOKEN_DELIVER,
    __UMS_CMD_MAX,
    UMS_CMD_MAX = __UMS_CMD_MAX - 1
};

enum ums_nl_attr {
    UMS_ATTR_UNSPEC,
    UMS_ATTR_ROLE,
    UMS_ATTR_RESULT,
    UMS_ATTR_INITIATOR_ID,
    UMS_ATTR_CLC_SESSION_ID,
    UMS_ATTR_DST_IP,
    UMS_ATTR_DST_IP6,
    UMS_ATTR_FIRST_CONTACT,
    UMS_ATTR_JETTY_TOKEN,
    UMS_ATTR_SEG_TOKEN,
    __UMS_ATTR_MAX,
    UMS_ATTR_MAX = __UMS_ATTR_MAX - 1
};

enum ums_process_role {
    UMS_ROLE_AGENT = 1,
};

/*
 * Callback for UMS_CMD_TOKEN_SUBMIT messages from the kernel.
 *
 * Return values:
 *   0       - accepted, TOKEN_DELIVER will be sent asynchronously after
 *             the token is proxied to the peer
 *   -errno  - rejected, the netlink layer will send TOKEN_SUBMIT_FAIL with
 *             -ret as the result code to the kernel immediately
 */
typedef int (*ums_agent_nl_token_submit_cb)(struct ums_token_entry *entry);

int ums_agent_nl_init(void);
void ums_agent_nl_deinit(void);

bool ums_agent_nl_owns_fd(int fd);
void ums_agent_nl_handle_event(int fd, uint32_t events);

void ums_agent_nl_set_token_submit_cb(ums_agent_nl_token_submit_cb cb);
int ums_agent_nl_send_token_submit_fail(uint32_t clc_session_id,
    const uint8_t *initiator_id, int result);
int ums_agent_nl_send_token_deliver(uint32_t clc_session_id,
    const uint8_t *initiator_id,
    uint32_t peer_jetty_token, uint32_t peer_seg_token,
    uint8_t first_contact);

#endif /* UMS_AGENT_NL_H */
