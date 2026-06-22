/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider failback netlink helpers.
 */
#ifndef BONDP_FAILBACK_H
#define BONDP_FAILBACK_H

#include <netlink/msg.h>

#ifdef __cplusplus
extern "C" {
#endif

void bondp_fb_handle_notify_nl_msg(struct nlattr *attrs[]);
void bondp_fb_handle_done_nl_msg(struct nlattr *attrs[]);

int bondp_fb_init(void);
void bondp_fb_uninit(void);

#ifdef __cplusplus
}
#endif

#endif // BONDP_FAILBACK_H
