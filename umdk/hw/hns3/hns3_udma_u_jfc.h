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

#ifndef _UDMA_U_JFC_H
#define _UDMA_U_JFC_H

#include "urma_types.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_jfs.h"

struct udma_u_jfc {
	urma_jfc_t		urma_jfc;
	pthread_spinlock_t	lock;
	uint32_t		lock_free;
	uint32_t		cqn;
	uint32_t		ci;
	uint32_t		depth;
	uint32_t		cqe_cnt;
	uint32_t		cqe_size;
	uint32_t		cqe_shift;
	struct udma_buf		buf;
	uint32_t		*db;
	uint32_t		arm_sn;
	uint32_t		caps_flag;
};

static inline struct udma_u_jfc *to_udma_jfc(const urma_jfc_t *jfc)
{
	return container_of(jfc, struct udma_u_jfc, urma_jfc);
}

urma_jfc_t *udma_u_create_jfc(urma_context_t *ctx, const urma_jfc_cfg_t *cfg);
urma_status_t udma_u_delete_jfc(urma_jfc_t *jfc);

#endif  /* _UDMA_U_JFC_H */
