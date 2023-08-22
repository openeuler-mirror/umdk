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

#ifndef _UDMA_JFS_H
#define _UDMA_JFS_H

#include "urma_types.h"
#include "urma_provider.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"

#define UDMA_SIZE_CONNECT_NODE_TABLE 99
#define UDMA_SGE_IN_WQE 2

#define max(a, b) ((a) > (b) ? (a) : (b))

struct connect_node_table {
	pthread_rwlock_t	rwlock;
	struct udma_hmap	hmap;
};

struct udma_wq {
	pthread_spinlock_t  lock;
	uintptr_t           *wrid;
	uint32_t            wqe_cnt;
	uint32_t            head;
	uint32_t            tail;
	uint32_t            max_gs;
	uint32_t            ext_sge_cnt;
	uint32_t            wqe_shift;
	uint32_t            shift;
	int                 offset;
	uint8_t             priority;
};

struct udma_sge_ex {
	int      offset;
	uint32_t sge_cnt;
	int      sge_shift;
};

struct udma_qp {
	uint32_t		qp_num;
	/* shared by jfs and jetty */
	uint32_t		jetty_id;
	uint32_t		flags;
	void			*dwqe_page;
	struct udma_buf		buf;
	struct udma_wq		sq;
	struct udma_sge_ex	ex_sge;
	urma_mtu_t		path_mtu;
	uint32_t		max_inline_data;
	struct udp_srcport	um_srcport;
	uint32_t		*sdb;
};

struct connect_node {
	struct udma_hmap_node	hmap_node;
	struct udma_qp		*qp;
	urma_target_jetty_t	*tjfr;
};

struct udma_jfs_qp_node {
	struct udma_hmap_node	node;
	struct udma_qp		*jfs_qp;
};

struct udma_u_jfs {
	urma_jfs_t				base;
	uint32_t				jfs_id;
	urma_transport_mode_t			tp_mode;
	uint32_t				lock_free;
	pthread_spinlock_t			lock;
	union {
		struct connect_node_table	tjfr_tbl;
		struct udma_qp			*um_qp;
	};
};

struct udma_jfs_node {
	struct udma_hmap_node	node;
	struct udma_u_jfs		*jfs;
};

#define UDMA_MIN_JFS_DEPTH 64

static inline struct udma_u_jfs *to_udma_jfs(const urma_jfs_t *jfs)
{
	return container_of(jfs, struct udma_u_jfs, base);
}

static inline struct udma_jfs_qp_node *to_udma_jfs_qp_node(struct udma_hmap_node *node)
{
	return container_of(node, struct udma_jfs_qp_node, node);
}

static inline struct udma_jfs_node *to_udma_jfs_node(struct udma_hmap_node *node)
{
	return container_of(node, struct udma_jfs_node, node);
}

urma_jfs_t *udma_u_create_jfs(urma_context_t *ctx, const urma_jfs_cfg_t *cfg);
urma_status_t udma_u_delete_jfs(urma_jfs_t *jfs);
urma_status_t verify_jfs_init_attr(urma_context_t *ctx,
				   const urma_jfs_cfg_t *cfg);
struct udma_qp *udma_alloc_qp(struct udma_u_context *udma_ctx,
			      const urma_jfs_cfg_t *jfs_cfg,
			      uint32_t jetty_id, bool is_jetty);

#endif /* _UDMA_JFS_H */
