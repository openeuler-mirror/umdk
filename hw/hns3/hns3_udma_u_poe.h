/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#ifndef _UDMA_U_POE_H
#define _UDMA_U_POE_H

#include "urma_types.h"

struct udma_jfc_notify_init_attr {
	uint64_t	notify_addr;
	uint8_t		notify_mode; /* Use enum udma_jfc_notify_mode */
	uint8_t		reserved[7];
};

struct udma_jfc_init_attr {
	uint64_t	jfc_ex_mask; /* Use enum udma_jfc_init_attr_mask */
	uint64_t	create_flags; /* Use enum udma_jfc_create_flags */
	uint8_t		poe_channel; /* poe channel to use */
	uint8_t		reserved[7];
	struct udma_jfc_notify_init_attr notify_init_attr;
};

struct udma_create_jfc_ex {
	urma_jfc_cfg_t			*cfg;
	struct udma_jfc_init_attr	*attr;
};

struct udma_poe_init_attr {
	uint64_t rsv; /* reserved for extension, now must be 0 */
	uint64_t poe_addr; /* 0 for disable */
};

struct udma_config_poe_channel_in {
	struct udma_poe_init_attr	*init_attr;
	uint8_t				poe_channel;
};

struct udma_update_jfs_ci_in {
	urma_jfs_t	*jfs;
	uint32_t	wqe_cnt;
};

#endif /* _UDMA_U_POE_H */
