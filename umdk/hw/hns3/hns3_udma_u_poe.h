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

#endif /* _UDMA_U_POE_H */
