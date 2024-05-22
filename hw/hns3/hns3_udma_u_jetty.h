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

#include <string.h>
#include <stdatomic.h>
#include "urma_types.h"
#include "urma_provider.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jfr.h"
#include "hns3_udma_u_jfs.h"

#define UDMA_TGT_NODE_TABLE_SIZE 64

struct rc_node {
	struct udma_qp		*qp;
	urma_target_jetty_t	*tjetty;
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
	uint8_t				sub_trans_mode;
};

struct udma_jetty_node {
	struct udma_hmap_node	node;
	struct udma_u_jetty	*jetty;
};

struct udma_u_target_jetty {
	urma_target_jetty_t urma_target_jetty;
	atomic_uint         refcnt;
};

static inline struct udma_u_jetty *to_udma_jetty(urma_jetty_t *jetty)
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

static inline struct udma_u_target_jetty *to_udma_target_jetty(urma_target_jetty_t *urma_target_jetty)
{
	return container_of(urma_target_jetty, struct udma_u_target_jetty,
			    urma_target_jetty);
}

static inline bool is_jetty(struct udma_u_context *udma_ctx, uint32_t qpn)
{
	uint8_t qpn_prefix;
	int hight, low;

	hight = udma_ctx->num_qps_shift - 1; /* length and real idx diff 1 */
	low = hight - HNS3_UDMA_JETTY_X_PREFIX_BIT_NUM + 1; /* need top 2 bits */

	qpn_prefix = FIELD_GET(GENMASK(hight, low), qpn);

	return qpn_prefix == HNS3_UDMA_JETTY_QPN_PREFIX;
}

static inline void fill_um_jetty_qp(struct udma_qp *qp,
				    struct hns3_udma_create_jetty_resp resp)
{
	qp->qp_num = resp.create_tp_resp.qpn;
	qp->flags = resp.create_tp_resp.cap_flags;
	qp->path_mtu = (urma_mtu_t)resp.create_tp_resp.path_mtu;
	qp->um_srcport = resp.create_tp_resp.um_srcport;
	qp->sq.priority = resp.create_tp_resp.priority;
	memcpy(&qp->um_srcport, &resp.create_tp_resp.um_srcport,
	       sizeof(struct udp_srcport));
}

static inline void fill_rc_jetty_qp(struct udma_qp *qp,
				    struct hns3_udma_create_jetty_resp resp)
{
	qp->qp_num = resp.create_tp_resp.qpn;
	qp->flags = resp.create_tp_resp.cap_flags;
	qp->sq.priority = resp.create_tp_resp.priority;
}

urma_jetty_t *udma_u_create_jetty(urma_context_t *ctx,
				  urma_jetty_cfg_t *jetty_cfg);
urma_status_t udma_u_delete_jetty(urma_jetty_t *jetty);
urma_status_t udma_u_bind_jetty(urma_jetty_t *jetty,
				urma_target_jetty_t *remote_jetty);
urma_status_t udma_u_unbind_jetty(urma_jetty_t *jetty);
urma_target_jetty_t *udma_u_import_jetty(urma_context_t *ctx,
					 urma_rjetty_t *rjetty,
					 urma_token_t *rjetty_token);
urma_status_t udma_u_unimport_jetty(urma_target_jetty_t *target_jetty);
struct udma_qp *get_qp_of_jetty(struct udma_u_jetty *udma_jetty,
				urma_jfs_wr_t *wr);
urma_status_t udma_u_post_jetty_send_wr(urma_jetty_t *jetty,
					urma_jfs_wr_t *wr,
					urma_jfs_wr_t **bad_wr);
urma_status_t udma_u_post_jetty_recv_wr(urma_jetty_t *jetty,
					urma_jfr_wr_t *wr,
					urma_jfr_wr_t **bad_wr);
urma_status_t verify_jfs_init_attr(urma_context_t *ctx,
				   urma_jfs_cfg_t *cfg);
urma_status_t udma_u_modify_jetty(urma_jetty_t *jetty,
				  urma_jetty_attr_t *jetty_attr);
urma_status_t udma_add_to_qp_table(struct udma_u_context *ctx, struct udma_qp *qp,
				   uint32_t qpn);
void udma_remove_from_qp_table(struct udma_u_context *ctx, uint32_t qpn);
void delete_jetty_node(struct udma_u_context *udma_ctx, uint32_t id);
urma_status_t insert_jetty_node(struct udma_u_context *udma_ctx,
				void *pointer, bool is_jetty, uint32_t id);
int udma_u_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);

#endif /* _UDMA_U_JETTY_H */
