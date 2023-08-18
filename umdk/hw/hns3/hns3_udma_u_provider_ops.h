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

#ifndef _UDMA_PROVIDER_OPS_H
#define _UDMA_PROVIDER_OPS_H

#include <stdatomic.h>
#include <linux/types.h>
#include "urma_provider.h"
#include "urma_log.h"
#include "urma_ex_api.h"
#include "hns3_udma_u_common.h"

#ifndef PCI_VENDOR_ID_HUAWEI
#define PCI_VENDOR_ID_HUAWEI			0x19E5
#endif

#define HNS3_DEV_ID_UDMA_OVER_UBL		0xA260
#define HNS3_DEV_ID_UDMA			0xA261

#define UDMA_JFR_TABLE_SIZE			8
#define UDMA_JETTY_TABLE_SIZE			8
#define UDMA_JFS_QP_TABLE_SIZE			99

extern urma_provider_ops_t g_udma_u_provider_ops;

struct udma_u_context {
	urma_context_t		urma_ctx;
	void			*uar;
	uint64_t		db_addr;
	uint32_t		max_jfc_cqe;

	uint32_t		cqe_size;
	uint32_t		page_size;

	struct udma_db_page	*db_list[UDMA_DB_TYPE_NUM];
	pthread_mutex_t		db_list_mutex;

	uint32_t		max_jfr_wr;
	uint32_t		max_jfr_sge;
	uint32_t		max_jfs_wr;
	uint32_t		max_jfs_sge;

	uint32_t		num_qps_shift;
	uint32_t		num_jfs_shift;
	uint32_t		num_jfr_shift;
	uint32_t		num_jetty_shift;

	pthread_rwlock_t	jfr_table_lock;
	struct udma_hmap	jfr_table;
	pthread_rwlock_t	jfs_qp_table_lock;
	struct udma_hmap	jfs_qp_table;
	pthread_rwlock_t	jetty_table_lock;
	struct udma_hmap	jetty_table;

	void			*reset_state;
};

struct udma_jetty_node {
	struct udma_hmap_node	node;
};

struct udma_reset_state {
	uint32_t is_reset;
};

static inline struct udma_u_context *to_udma_ctx(urma_context_t *ctx)
{
	return container_of(ctx, struct udma_u_context, urma_ctx);
}

static inline void udma_write64(struct udma_u_context *ctx,
				uint64_t *dest, uint64_t *val)
{
	struct udma_reset_state *state = (struct udma_reset_state *)ctx->reset_state;

	if (state && state->is_reset)
		return;

	atomic_store_explicit((_Atomic(uint64_t) *)dest,
			      (uint64_t)(*val), memory_order_relaxed);
}

#endif /* _UDMA_PROVIDER_OPS_H */
