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

#ifndef _UDMA_U_JETTY_H
#define _UDMA_U_JETTY_H

#include "urma_types.h"
#include "urma_provider.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jfr.h"
#include "hns3_udma_u_jfs.h"

#define UDMA_TGT_NODE_TABLE_SIZE 64

struct rc_node {
	struct udma_qp			*qp;
	const urma_target_jetty_t	*tjetty;
};

struct tgt_node {
	struct udma_hmap_node	hmap_node;
	struct udma_qp		*qp;
	urma_target_jetty_t	*tjetty;
};

struct tgt_node_table {
	pthread_rwlock_t	rwlock;
	struct udma_hmap	hmap;
};

struct udma_u_jetty {
	urma_jetty_t			urma_jetty;
	bool				share_jfr;
	struct udma_u_jfr		*udma_jfr;
	urma_transport_mode_t		tp_mode;
	uint32_t			jfs_lock_free;
	pthread_spinlock_t		lock;
	union {
		struct tgt_node_table	*tjetty_tbl;
		struct rc_node		*rc_node;
		struct udma_qp		*um_qp;
	};
};

struct udma_jetty_node {
	struct udma_hmap_node	node;
	struct udma_u_jetty	*jetty;
};

struct udma_u_target_jetty {
	urma_target_jetty_t urma_target_jetty;
	atomic_uint         refcnt;
};

static inline struct udma_u_jetty *to_udma_jetty(const urma_jetty_t *jetty)
{
	return container_of(jetty, struct udma_u_jetty, urma_jetty);
}

static inline struct tgt_node *to_tgt_node(struct udma_hmap_node *hmap_node)
{
	return container_of(hmap_node, struct tgt_node, hmap_node);
}

static inline struct udma_jetty_node *to_udma_jetty_node(struct udma_hmap_node *node)
{
	return container_of(node, struct udma_jetty_node, node);
}

static inline struct udma_u_target_jetty *to_udma_target_jetty(const urma_target_jetty_t *tjetty)
{
	return container_of(tjetty, struct udma_u_target_jetty, urma_target_jetty);
}

static inline bool is_jetty(struct udma_u_context *udma_ctx, uint32_t qpn)
{
	uint8_t qpn_prefix;
	int hight, low;

	hight = udma_ctx->num_qps_shift - 1; /* length and real idx diff 1 */
	low = hight - UDMA_JETTY_X_PREFIX_BIT_NUM + 1; /* need top 2 bits */

	qpn_prefix = FIELD_GET(GENMASK(hight, low), qpn);

	return qpn_prefix == UDMA_JETTY_QPN_PREFIX;
}

urma_jetty_t *udma_u_create_jetty(urma_context_t *ctx,
				  const urma_jetty_cfg_t *jetty_cfg);
urma_status_t udma_u_delete_jetty(urma_jetty_t *jetty);
urma_target_jetty_t *udma_u_import_jetty(urma_context_t *ctx,
					 const urma_rjetty_t *rjetty,
					 const urma_key_t *rjetty_key);
urma_status_t udma_u_unimport_jetty(urma_target_jetty_t *target_jetty, bool force);
urma_status_t udma_u_advise_jetty(urma_jetty_t *jetty,
				  const urma_target_jetty_t *remote_jetty);
urma_status_t udma_u_unadvise_jetty(urma_jetty_t *jetty,
				    urma_target_jetty_t *remote_jetty,
				    bool force);

#endif /* _UDMA_U_JETTY_H */
