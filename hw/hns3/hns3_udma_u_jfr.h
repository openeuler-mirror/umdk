/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei HNS3_UDMA Linux driver
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

#ifndef _HNS3_UDMA_U_JFR_H
#define _HNS3_UDMA_U_JFR_H

#include "urma_types.h"
#include "hns3_udma_u_common.h"

#define HNS3_UDMA_JFR_GRH_HEAD_SZ	40

struct hns3_udma_u_jfr_idx_que {
	struct hns3_udma_buf	idx_buf;
	uint32_t		entry_shift;
	uint64_t		*bitmap;
	uint32_t		bitmap_cnt;
	uint32_t		head;
	uint32_t		tail;
};

struct hns3_udma_u_inl_sge {
	void			*addr;
	uint32_t		len;
};

struct hns3_udma_u_inl_wqe {
	struct hns3_udma_u_inl_sge	*sg_list;
	uint32_t			sge_cnt;
};

struct um_header {
	char data[HNS3_UDMA_JFR_GRH_HEAD_SZ];
};

struct hns3_udma_u_jfr {
	urma_jfr_t                urma_jfr;
	urma_transport_mode_t     trans_mode;
	uint32_t                  lock_free;
	pthread_spinlock_t        lock;
	uint32_t                  max_sge;
	uint32_t                  user_max_sge; /* max sge allow user assign */
	uint64_t                  *wrid;
	uint32_t                  *db;
	uint32_t                  jfrn;
	uint32_t                  cap_flags;
	struct um_header          *um_header_que;
	urma_target_seg_t         *um_header_seg;
	uint32_t                  srqn;
	struct hns3_udma_u_jfr_idx_que idx_que;
	struct hns3_udma_buf           wqe_buf;
	uint32_t                  wqe_cnt;
	uint32_t                  wqe_shift;
	bool                      share_jfr;
};

struct hns3_udma_jfr_node {
	struct hns3_udma_hmap_node	node;
	struct hns3_udma_u_jfr		*jfr;
};

#define HNS3_UDMA_JFR_IDX_QUE_ENTRY_SZ	4

static inline struct hns3_udma_u_jfr *to_hns3_udma_jfr(urma_jfr_t *jfr)
{
	return container_of(jfr, struct hns3_udma_u_jfr, urma_jfr);
}

static inline struct hns3_udma_jfr_node *to_hns3_udma_jfr_node(struct hns3_udma_hmap_node *node)
{
	return container_of(node, struct hns3_udma_jfr_node, node);
}

static inline void *get_jfr_wqe(struct hns3_udma_u_jfr *jfr, uint32_t n)
{
	return (char *)jfr->wqe_buf.buf + (n << jfr->wqe_shift);
}

urma_jfr_t *hns3_udma_u_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg);
struct hns3_udma_u_jetty;
urma_jfr_t *hns3_udma_u_create_jfr_rq(urma_context_t *ctx, urma_jfr_cfg_t *cfg,
				      struct hns3_udma_u_jetty *jetty);
urma_status_t hns3_udma_u_delete_jfr(urma_jfr_t *jfr);
urma_target_jetty_t *hns3_udma_u_import_jfr(urma_context_t *ctx,
					    urma_rjfr_t *rjfr,
					    urma_token_t *token);
urma_status_t hns3_udma_u_unimport_jfr(urma_target_jetty_t *target_jfr);
urma_status_t hns3_udma_u_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr);
urma_status_t hns3_udma_u_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr,
				      urma_jfr_wr_t **bad_wr);
urma_status_t post_recv_one_rq(struct hns3_udma_u_jfr *udma_jfr,
			       urma_jfr_wr_t *wr);
urma_status_t post_recv_one(struct hns3_udma_u_jfr *udma_jfr,
			    urma_jfr_wr_t *wr);
void update_srq_db(struct hns3_udma_u_context *ctx, struct hns3_udma_u_jfr *jfr);

#endif /* _HNS3_UDMA_U_JFR_H */
