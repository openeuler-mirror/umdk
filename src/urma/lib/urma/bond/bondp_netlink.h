/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider support netlink.
 */
#ifndef BONDP_NETLINK_H
#define BONDP_NETLINK_H

#ifdef __cplusplus
extern "C" {
#endif

int bondp_nl_init(void);
void bondp_nl_uninit(void);

#ifdef __cplusplus
}
#endif

#endif // BONDP_NETLINK_H
