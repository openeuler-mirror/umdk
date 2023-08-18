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

#ifndef _UDMA_U_JFR_H
#define _UDMA_U_JFR_H

#include "urma_types.h"
#include "hns3_udma_u_common.h"

#define UDMA_JFR_GRH_HEAD_SZ		40

struct udma_u_jfr_idx_que {
	struct udma_buf		idx_buf;
	uint32_t		entry_shift;
	uint64_t		*bitmap;
	uint32_t		bitmap_cnt;
	uint32_t		head;
	uint32_t		tail;
};

struct um_header {
	char data[UDMA_JFR_GRH_HEAD_SZ];
};

struct udma_u_jfr {
	urma_jfr_t                urma_jfr;
	pthread_spinlock_t        lock;
	uint32_t                  lock_free;
	uint32_t                  wqe_cnt;
	uint32_t                  wqe_shift;
	uint32_t                  max_sge;
	uint32_t                  user_max_sge; /* max sge allow user assign */
	uint64_t                  *wrid;
	struct udma_u_jfr_idx_que idx_que;
	struct udma_buf           wqe_buf;
	uint32_t                  *db;
	uint32_t                  jfrn;
	uint32_t                  cap_flags;
	urma_transport_mode_t     trans_mode;
	struct um_header          *um_header_que;
	urma_target_seg_t         *um_header_seg;
};

struct udma_jfr_node {
	struct udma_hmap_node	node;
	struct udma_u_jfr	*jfr;
};

#define UDMA_JFR_IDX_QUE_ENTRY_SZ	4

static inline struct udma_u_jfr *to_udma_jfr(const urma_jfr_t *jfr)
{
	return container_of(jfr, struct udma_u_jfr, urma_jfr);
}

static inline struct udma_jfr_node *to_udma_jfr_node(struct udma_hmap_node *node)
{
	return container_of(node, struct udma_jfr_node, node);
}

urma_jfr_t *udma_u_create_jfr(urma_context_t *ctx, const urma_jfr_cfg_t *cfg);
urma_status_t udma_u_delete_jfr(urma_jfr_t *jfr);

#endif /* _UDMA_U_JFR_H */
