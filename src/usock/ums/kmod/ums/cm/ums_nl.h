/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UB Memory based Socket(UMS)
 *
 * Description: UMS Generic Netlink interface for kernel-agent communication
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * UMS implementation:
 *     Author: Hu Ying
 */

#ifndef UMS_NL_H
#define UMS_NL_H

#include <linux/types.h>
#include "ums_types.h"

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

int __init ums_nl_init(void);
void ums_nl_exit(void);

bool ums_nl_agent_available(void);

int ums_nl_register_and_submit_tokens(struct ums_sock *ums, bool first_contact);
void ums_nl_unregister_clc_session(u32 clc_session_id, const u8 *initiator_id);

#endif /* UMS_NL_H */
