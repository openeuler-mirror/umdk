// SPDX-License-Identifier: GPL-2.0
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

#include <malloc.h>
#include <string.h>
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_segment.h"
#include "hns3_udma_u_jfr.h"

static int verify_jfr_init_attr(struct udma_u_context *udma_ctx,
				urma_jfr_cfg_t *cfg)
{
	if (!cfg->max_sge ||
	    !cfg->depth || cfg->depth > udma_ctx->max_jfr_wr ||
	    cfg->max_sge > udma_ctx->max_jfr_sge) {
		UDMA_LOG_ERR("invalid jfr cfg, depth = %u, max_sge = %u.\n",
			     cfg->depth, cfg->max_sge);
		return EINVAL;
	}

	if (cfg->trans_mode != URMA_TM_UM && cfg->trans_mode != URMA_TM_RC) {
		UDMA_LOG_ERR("The jfr trans_mode(%d) is not supported.\n", cfg->trans_mode);
		return EINVAL;
	}

	return 0;
}

static void init_jfr_param(struct udma_u_jfr *jfr, urma_jfr_cfg_t *cfg)
{
	jfr->wqe_cnt = roundup_pow_of_two(cfg->depth);

	if (cfg->trans_mode == URMA_TM_UM) {
		/* reserved for UM header */
		jfr->max_sge = roundup_pow_of_two(cfg->max_sge + 1);
		jfr->user_max_sge = jfr->max_sge - 1;
	} else {
		jfr->max_sge = roundup_pow_of_two(cfg->max_sge);
		jfr->user_max_sge = jfr->max_sge;
	}

	jfr->wqe_shift = udma_ilog32(roundup_pow_of_two(UDMA_HW_SGE_SIZE *
							jfr->max_sge));
	jfr->trans_mode = cfg->trans_mode;
}

static int alloc_jfr_idx_que(struct udma_u_jfr *jfr)
{
	struct udma_u_jfr_idx_que *idx_que = &jfr->idx_que;
	uint32_t buf_size;

	idx_que->entry_shift = udma_ilog32(UDMA_JFR_IDX_QUE_ENTRY_SZ);
	idx_que->bitmap = udma_bitmap_alloc(jfr->wqe_cnt, &idx_que->bitmap_cnt);
	if (!idx_que->bitmap) {
		UDMA_LOG_ERR("failed to alloc jfr idx que bitmap.\n");
		return ENOMEM;
	}

	buf_size = to_udma_hem_entries_size(jfr->wqe_cnt, idx_que->entry_shift);
	if (udma_alloc_buf(&idx_que->idx_buf, buf_size, UDMA_HW_PAGE_SIZE)) {
		UDMA_LOG_ERR("failed to alloc jfr idx que buf.\n");
		udma_bitmap_free(idx_que->bitmap);
		idx_que->bitmap = NULL;
		return ENOMEM;
	}

	idx_que->head = 0;
	idx_que->tail = 0;

	return 0;
}

static int alloc_jfr_wqe_buf(struct udma_u_jfr *jfr)
{
	uint32_t buf_size = to_udma_hem_entries_size(jfr->wqe_cnt, jfr->wqe_shift);

	return udma_alloc_buf(&jfr->wqe_buf, buf_size, UDMA_HW_PAGE_SIZE);
}

static int alloc_jfr_buf(struct udma_u_jfr *jfr, struct udma_u_jetty *jetty)
{
	if (alloc_jfr_idx_que(jfr)) {
		UDMA_LOG_ERR("failed to alloc jfr idx que.\n");
		return ENOMEM;
	}

	if (jetty == NULL) {
		if (alloc_jfr_wqe_buf(jfr)) {
			UDMA_LOG_ERR("failed to alloc jfr wqe buf.\n");
			goto err_alloc_buf;
		}
	} else if (jetty->tp_mode == URMA_TM_RC) {
		jfr->wqe_buf.buf = jetty->rc_node->qp->buf.buf +
				   jetty->rc_node->qp->rq.offset;
	} else {
		jfr->wqe_buf.buf = jetty->um_qp->buf.buf +
				   jetty->um_qp->rq.offset;
	}

	jfr->wrid = (uint64_t *)calloc(jfr->wqe_cnt, sizeof(*jfr->wrid));
	if (!jfr->wrid) {
		UDMA_LOG_ERR("failed to alloc jfr wrid.\n");
		goto err_alloc_wrid;
	}

	return 0;

err_alloc_wrid:
	if (jetty == NULL)
		udma_free_buf(&jfr->wqe_buf);
err_alloc_buf:
	udma_free_buf(&jfr->idx_que.idx_buf);
	udma_bitmap_free(jfr->idx_que.bitmap);

	return ENOMEM;
}

static void free_jfr_buf(struct udma_u_jfr *jfr)
{
	free(jfr->wrid);
	if (jfr->share_jfr)
		udma_free_buf(&jfr->wqe_buf);
	udma_free_buf(&jfr->idx_que.idx_buf);
	udma_bitmap_free(jfr->idx_que.bitmap);
}

static int exec_jfr_create_cmd(urma_context_t *ctx, struct udma_u_jfr *jfr,
			       urma_jfr_cfg_t *cfg, struct udma_u_jetty *jetty)
{
	struct hns3_udma_create_jfr_resp resp = {};
	struct hns3_udma_create_jfr_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	cmd.buf_addr = (uintptr_t)jfr->wqe_buf.buf;
	cmd.idx_addr = (uintptr_t)jfr->idx_que.idx_buf.buf;
	cmd.db_addr = (uintptr_t)jfr->db;
	if (jetty != NULL) {
		if (jetty->tp_mode == URMA_TM_RC) {
			cmd.wqe_buf_addr = (uintptr_t)jetty->rc_node->qp->buf.buf;
			cmd.sqe_cnt = jetty->rc_node->qp->sq.wqe_cnt;
			cmd.sqe_shift = jetty->rc_node->qp->sq.wqe_shift;
			cmd.sge_cnt = jetty->rc_node->qp->ex_sge.sge_cnt;
			cmd.sge_shift = jetty->rc_node->qp->ex_sge.sge_shift;
			cmd.share_jfr = jetty->share_jfr;
		} else {
			cmd.wqe_buf_addr = (uintptr_t)jetty->um_qp->buf.buf;
			cmd.sqe_cnt = jetty->um_qp->sq.wqe_cnt;
			cmd.sqe_shift = jetty->um_qp->sq.wqe_shift;
			cmd.sge_cnt = jetty->um_qp->ex_sge.sge_cnt;
			cmd.sge_shift = jetty->um_qp->ex_sge.sge_shift;
			cmd.share_jfr = jetty->share_jfr;
		}
	}

	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfr(ctx, &jfr->urma_jfr, cfg, &udata);
	if (ret)
		return ret;
	jfr->jfrn = jfr->urma_jfr.jfr_id.id;
	jfr->cap_flags = resp.jfr_caps;
	jfr->srqn = resp.srqn;

	return 0;
}

static int insert_jfr_node(struct udma_u_context *ctx, struct udma_u_jfr *jfr)
{
	struct udma_jfr_node *jfr_node;

	jfr_node = (struct udma_jfr_node *)malloc(sizeof(struct udma_jfr_node));
	if (!jfr_node) {
		UDMA_LOG_ERR("failed to alloc jfr node.\n");
		return ENOMEM;
	}
	jfr_node->jfr = jfr;
	(void)pthread_rwlock_wrlock(&ctx->jfr_table_lock);
	if (!udma_hmap_insert(&ctx->jfr_table, &jfr_node->node, jfr->urma_jfr.jfr_id.id)) {
		free(jfr_node);
		jfr_node = NULL;
		UDMA_LOG_ERR("failed to insert jfr_node.\n");
		(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);
		return EINVAL;
	}
	(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);

	return 0;
}

static void delete_jfr_node(struct udma_u_context *ctx, struct udma_u_jfr *jfr)
{
	struct udma_jfr_node *jfr_node;
	struct udma_hmap_node *node;

	(void)pthread_rwlock_wrlock(&ctx->jfr_table_lock);
	node = udma_hmap_first_with_hash(&ctx->jfr_table, jfr->urma_jfr.jfr_id.id);
	if (node) {
		jfr_node = to_udma_jfr_node(node);
		if (jfr_node->jfr == jfr) {
			udma_hmap_remove(&ctx->jfr_table, node);
			(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);
			free(jfr_node);
			return;
		}
	}
	(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);
	UDMA_LOG_ERR("failed to find jfr node.\n");
}

int alloc_um_header_que(urma_context_t *ctx, struct udma_u_jfr *jfr)
{
	urma_seg_cfg_t seg_cfg = {};

	jfr->um_header_que = (struct um_header *)calloc(jfr->wqe_cnt,
							sizeof(struct um_header));
	if (!jfr->um_header_que) {
		UDMA_LOG_ERR("failed to alloc jfr grh head que.\n");
		return ENOMEM;
	}

	seg_cfg.flag.bs.token_policy = 1;
	seg_cfg.flag.bs.cacheable = 0;
	seg_cfg.flag.bs.access = URMA_ACCESS_LOCAL_WRITE;
	seg_cfg.va = (uint64_t)jfr->um_header_que;
	seg_cfg.len = jfr->wqe_cnt * UDMA_JFR_GRH_HEAD_SZ;

	jfr->um_header_seg = udma_u_register_seg(ctx, &seg_cfg);
	if (!jfr->um_header_seg) {
		free(jfr->um_header_que);
		UDMA_LOG_ERR("failed to register seg for grh head que.\n");
		return ENOMEM;
	}

	return 0;
}

void free_um_header_que(struct udma_u_jfr *jfr)
{
	udma_u_unregister_seg(jfr->um_header_seg);
	jfr->um_header_seg = NULL;

	free(jfr->um_header_que);
	jfr->um_header_que = NULL;
}

urma_jfr_t *udma_u_create_jfr_rq(urma_context_t *ctx, urma_jfr_cfg_t *cfg,
				 struct udma_u_jetty *jetty)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_u_jfr *jfr;

	if (verify_jfr_init_attr(udma_ctx, cfg))
		return NULL;

	jfr = (struct udma_u_jfr *)calloc(1, sizeof(*jfr));
	if (!jfr)
		return NULL;

	jfr->lock_free = cfg->flag.bs.lock_free;
	jfr->share_jfr = false;
	if (pthread_spin_init(&jfr->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_init_lock_rq;

	init_jfr_param(jfr, cfg);
	if (alloc_jfr_buf(jfr, jetty))
		goto err_alloc_buf_rq;

	jfr->db = (uint32_t *)udma_alloc_sw_db(udma_ctx, UDMA_JFR_TYPE_DB);
	if (!jfr->db)
		goto err_alloc_db_rq;

	if (exec_jfr_create_cmd(ctx, jfr, cfg, jetty)) {
		UDMA_LOG_ERR("ubcore create jfr failed.\n");
		goto err_create_jfr_rq;
	}

	if (insert_jfr_node(udma_ctx, jfr)) {
		UDMA_LOG_ERR("insert jfr node failed.\n");
		goto err_insert_jfr_rq;
	}

	if (cfg->trans_mode == URMA_TM_UM) {
		if (alloc_um_header_que(ctx, jfr)) {
			UDMA_LOG_ERR("alloc grh que failed.\n");
			goto err_alloc_um_header;
		}
	}

	return &jfr->urma_jfr;

err_alloc_um_header:
	delete_jfr_node(udma_ctx, jfr);
err_insert_jfr_rq:
	urma_cmd_delete_jfr(&jfr->urma_jfr);
err_create_jfr_rq:
	udma_free_sw_db(udma_ctx, jfr->db, UDMA_JFR_TYPE_DB);
err_alloc_db_rq:
	free_jfr_buf(jfr);
err_alloc_buf_rq:
	(void)pthread_spin_destroy(&jfr->lock);
err_init_lock_rq:
	free(jfr);

	return NULL;
}

urma_jfr_t *udma_u_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_u_jfr *jfr;

	if (verify_jfr_init_attr(udma_ctx, cfg))
		return NULL;

	jfr = (struct udma_u_jfr *)memalign(UDMA_HW_PAGE_SIZE, sizeof(*jfr));
	if (!jfr)
		return NULL;
	memset(jfr, 0, sizeof(*jfr));
	jfr->lock_free = cfg->flag.bs.lock_free;
	jfr->share_jfr = true;
	if (pthread_spin_init(&jfr->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_init_lock;

	init_jfr_param(jfr, cfg);
	if (alloc_jfr_buf(jfr, NULL))
		goto err_alloc_buf;

	jfr->db = (uint32_t *)udma_alloc_sw_db(udma_ctx, UDMA_JFR_TYPE_DB);
	if (!jfr->db)
		goto err_alloc_db;

	if (exec_jfr_create_cmd(ctx, jfr, cfg, NULL)) {
		UDMA_LOG_ERR("ubcore create jfr failed.\n");
		goto err_create_jfr;
	}

	if (insert_jfr_node(udma_ctx, jfr)) {
		UDMA_LOG_ERR("insert jfr node failed.\n");
		goto err_insert_jfr;
	}

	if (insert_jetty_node(udma_ctx, jfr, false, jfr->jfrn)) {
		UDMA_LOG_ERR("insert jetty node failed.\n");
		goto err_insert_jetty;
	}

	if (cfg->trans_mode == URMA_TM_UM) {
		if (alloc_um_header_que(ctx, jfr)) {
			UDMA_LOG_ERR("alloc grh que failed.\n");
			goto err_alloc_um_header;
		}
	}

	return &jfr->urma_jfr;

err_alloc_um_header:
	delete_jetty_node(udma_ctx, jfr->jfrn);
err_insert_jetty:
	delete_jfr_node(udma_ctx, jfr);
err_insert_jfr:
	urma_cmd_delete_jfr(&jfr->urma_jfr);
err_create_jfr:
	udma_free_sw_db(udma_ctx, jfr->db, UDMA_JFR_TYPE_DB);
err_alloc_db:
	free_jfr_buf(jfr);
err_alloc_buf:
	(void)pthread_spin_destroy(&jfr->lock);
err_init_lock:
	free(jfr);

	return NULL;
}

urma_status_t udma_u_delete_jfr(urma_jfr_t *jfr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jfr->urma_ctx);
	struct udma_u_jfr *udma_jfr = to_udma_jfr(jfr);
	int ret;

	if (udma_jfr->trans_mode == URMA_TM_UM)
		free_um_header_que(udma_jfr);

	delete_jfr_node(udma_ctx, udma_jfr);
	if (udma_jfr->share_jfr)
		delete_jetty_node(udma_ctx, udma_jfr->jfrn);
	ret = urma_cmd_delete_jfr(jfr);
	if (ret) {
		UDMA_LOG_ERR("urma_cmd_delete_jfr failed, ret:%d.\n", ret);
		return URMA_FAIL;
	}

	udma_free_sw_db(udma_ctx, udma_jfr->db, UDMA_JFR_TYPE_DB);
	free_jfr_buf(udma_jfr);
	(void)pthread_spin_destroy(&udma_jfr->lock);
	free(udma_jfr);

	return URMA_SUCCESS;
}

static inline bool udma_jfrwq_overflow(struct udma_u_jfr *jfr)
{
	struct udma_u_jfr_idx_que *idx_que = &jfr->idx_que;

	return (idx_que->head - idx_que->tail) >= jfr->wqe_cnt;
}

static inline urma_status_t check_post_jfr_valid(struct udma_u_jfr *jfr,
						 urma_jfr_wr_t *wr,
						 uint32_t max_sge)
{
	if (udma_jfrwq_overflow(jfr)) {
		UDMA_LOG_ERR("failed to check jfrwq status, jfrwq is full.\n");
		return URMA_ENOMEM;
	}

	if (wr->src.num_sge > max_sge) {
		UDMA_LOG_ERR("failed to check sge, wr->src.num_sge = %d, max_sge = %u.\n",
			     wr->src.num_sge, max_sge);
		return URMA_EINVAL;
	}

	return URMA_SUCCESS;
}

static urma_status_t get_wqe_idx(struct udma_u_jfr *jfr, uint32_t *wqe_idx)
{
	struct udma_u_jfr_idx_que *idx_que = &jfr->idx_que;

	if (udma_bitmap_use_idx(idx_que->bitmap, idx_que->bitmap_cnt,
				jfr->wqe_cnt, wqe_idx))
		return URMA_ENOMEM;

	return URMA_SUCCESS;
}

static inline void set_data_seg(struct udma_wqe_data_seg *dseg,
				urma_sge_t *sg)
{
	dseg->lkey = htole32(sg->tseg->seg.token_id);
	dseg->addr = htole64(sg->addr);
	dseg->len = htole32(sg->len);
}

static void *get_idx_buf(struct udma_u_jfr_idx_que *idx_que, uint32_t n)
{
	return (char *)idx_que->idx_buf.buf + (n << idx_que->entry_shift);
}

static inline void fill_wqe_idx(struct udma_u_jfr *jfr, uint32_t wqe_idx)
{
	struct udma_u_jfr_idx_que *idx_que = &jfr->idx_que;
	uint32_t *idx_buf;
	uint32_t head;

	head = idx_que->head & (jfr->wqe_cnt - 1);

	idx_buf = (uint32_t *)get_idx_buf(idx_que, head);
	*idx_buf = htole32(wqe_idx);

	idx_que->head++;
}

static void *set_um_header_sge(struct udma_u_jfr *jfr,
			       uint32_t wqe_idx, void *wqe)
{
	struct udma_wqe_data_seg *dseg = (struct udma_wqe_data_seg *)wqe;

	dseg->addr = htole64((uint64_t)&jfr->um_header_que[wqe_idx]);
	dseg->len = htole32(UDMA_JFR_GRH_HEAD_SZ);
	dseg->lkey = htole32(jfr->um_header_seg->seg.token_id);
	dseg++;

	return dseg;
}

static inline void fill_recv_sge_to_wqe(urma_jfr_wr_t *wr, void *wqe,
					uint32_t max_sge)
{
	struct udma_wqe_data_seg *dseg = (struct udma_wqe_data_seg *)wqe;
	uint32_t i, cnt;

	for (i = 0, cnt = 0; i < wr->src.num_sge; i++) {
		/* Skip zero-length sge */
		if (!wr->src.sge[i].len)
			continue;
		set_data_seg(dseg + cnt, wr->src.sge + i);
		cnt++;
	}

	if (cnt < max_sge)
		memset(dseg + cnt, 0, (max_sge - cnt) * UDMA_HW_SGE_SIZE);
}

urma_status_t post_recv_one_rq(struct udma_u_jfr *udma_jfr, urma_jfr_wr_t *wr)
{
	uint32_t wqe_idx, max_sge;
	urma_status_t ret;
	void *wqe;

	max_sge = udma_jfr->user_max_sge;
	ret = check_post_jfr_valid(udma_jfr, wr, max_sge);
	if (ret) {
		UDMA_LOG_ERR("failed to check post, jfrn = %u.\n",
			     udma_jfr->urma_jfr.jfr_id.id);
		return ret;
	}

	wqe_idx = udma_jfr->idx_que.head & (udma_jfr->wqe_cnt - 1);
	wqe = get_jfr_wqe(udma_jfr, wqe_idx);

	if (unlikely(udma_jfr->trans_mode == URMA_TM_UM))
		wqe = set_um_header_sge(udma_jfr, wqe_idx, wqe);

	fill_recv_sge_to_wqe(wr, wqe, max_sge);

	udma_jfr->idx_que.head++;

	udma_jfr->wrid[wqe_idx] = (uint64_t)wr->user_ctx;

	return ret;
}

urma_status_t post_recv_one(struct udma_u_jfr *udma_jfr, urma_jfr_wr_t *wr)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx, max_sge;
	void *wqe;

	max_sge = udma_jfr->user_max_sge;
	ret = check_post_jfr_valid(udma_jfr, wr, max_sge);
	if (unlikely(ret)) {
		UDMA_LOG_ERR("failed to check post, jfrn = %u.\n",
			     udma_jfr->urma_jfr.jfr_id.id);
		return ret;
	}

	ret = get_wqe_idx(udma_jfr, &wqe_idx);
	if (unlikely(ret)) {
		UDMA_LOG_ERR("failed to get jfr wqe idx.\n");
		return ret;
	}
	wqe = get_jfr_wqe(udma_jfr, wqe_idx);
	if (unlikely(udma_jfr->trans_mode == URMA_TM_UM))
		wqe = set_um_header_sge(udma_jfr, wqe_idx, wqe);

	fill_recv_sge_to_wqe(wr, wqe, max_sge);
	fill_wqe_idx(udma_jfr, wqe_idx);

	udma_jfr->wrid[wqe_idx] = (uint64_t)wr->user_ctx;

	return ret;
}

void update_srq_db(struct udma_u_context *ctx, struct udma_u_jfr *jfr)
{
	struct udma_u_db db = {};

	udma_reg_write(&db, UDMA_DB_TAG, jfr->srqn);
	udma_reg_write(&db, UDMA_DB_CMD, UDMA_SRQ_DB);
	udma_reg_write(&db, UDMA_DB_PI, jfr->idx_que.head);

	udma_write64(ctx, (uint64_t *)(ctx->uar + UDMA_DB_CFG0_OFFSET),
		    (uint64_t *)&db);
}

urma_status_t udma_u_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr,
				 urma_jfr_wr_t **bad_wr)
{
	struct udma_u_context *ctx = to_udma_ctx(jfr->urma_ctx);
	struct udma_u_jfr *udma_jfr = to_udma_jfr(jfr);
	urma_status_t ret = URMA_SUCCESS;
	uint32_t nreq;

	if (!udma_jfr->lock_free)
		(void)pthread_spin_lock(&udma_jfr->lock);

	if (!udma_jfr->share_jfr) {
		for (nreq = 0; wr; ++nreq, wr = wr->next) {
			ret = post_recv_one_rq(udma_jfr, wr);
			if (ret) {
				*bad_wr = wr;
				break;
			}
		}
	} else {
		for (nreq = 0; wr; ++nreq, wr = wr->next) {
			ret = post_recv_one(udma_jfr, wr);
			if (ret) {
				*bad_wr = wr;
				break;
			}
		}
	}

	if (nreq) {
		udma_to_device_barrier();
		if (udma_jfr->cap_flags & HNS3_UDMA_JFR_CAP_RECORD_DB)
			*udma_jfr->db = udma_jfr->idx_que.head & UDMA_DB_PROD_IDX_M;
		else
			update_srq_db(ctx, udma_jfr);
	}

	if (!udma_jfr->lock_free)
		(void)pthread_spin_unlock(&udma_jfr->lock);

	return ret;
}

urma_target_jetty_t *udma_u_import_jfr(urma_context_t *ctx,
				       urma_rjfr_t *rjfr,
				       urma_token_t *token)
{
	struct udma_u_target_jetty *udma_target_jfr;
	urma_cmd_udrv_priv_t udata = {};
	urma_target_jetty_t *tjfr;
	urma_tjfr_cfg_t cfg = {};
	int ret;

	udma_target_jfr = (struct udma_u_target_jetty *)
			  calloc(1, sizeof(struct udma_u_target_jetty));
	if (!udma_target_jfr) {
		UDMA_LOG_ERR("udma_target_jfr alloc failed.\n");
		return NULL;
	}

	tjfr = &udma_target_jfr->urma_target_jetty;
	tjfr->urma_ctx = ctx;
	tjfr->id = rjfr->jfr_id;
	tjfr->trans_mode = rjfr->trans_mode;
	cfg.jfr_id = rjfr->jfr_id;
	cfg.token = token;
	cfg.trans_mode = rjfr->trans_mode;
	udma_set_udata(&udata, NULL, 0, NULL, 0);
	ret = urma_cmd_import_jfr(ctx, tjfr, &cfg, &udata);
	if (ret) {
		UDMA_LOG_ERR("import jfr failed.\n");
		free(udma_target_jfr);
		return NULL;
	}

	atomic_init(&udma_target_jfr->refcnt, 1);
	return tjfr;
}

urma_status_t udma_u_unimport_jfr(urma_target_jetty_t *target_jfr)
{
	struct udma_u_target_jetty *udma_target_jfr = to_udma_target_jetty(target_jfr);
	int ret;

	if (udma_target_jfr->refcnt > 1) {
		UDMA_LOG_ERR("the target jfr is still being used, id = %d.\n",
			     target_jfr->id.id);
		return URMA_FAIL;
	}

	ret = urma_cmd_unimport_jfr(target_jfr);
	if (ret != 0) {
		UDMA_LOG_ERR("unimport jfr failed.\n");
		return URMA_FAIL;
	}
	free(udma_target_jfr);

	return URMA_SUCCESS;
}

urma_status_t udma_u_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr)
{
	struct udma_u_jfr *udma_jfr = to_udma_jfr(jfr);
	uint32_t jfr_limit;
	int ret;

	if (attr->mask & JFR_STATE) {
		UDMA_LOG_ERR("JFR status change is not supported.\n");
		return URMA_FAIL;
	}

	if (!(attr->mask & JFR_RX_THRESHOLD)) {
		UDMA_LOG_ERR("JFR threshold mask is not set.\n");
		return URMA_FAIL;
	}

	jfr_limit = attr->rx_threshold;
	if (jfr_limit > udma_jfr->wqe_cnt) {
		UDMA_LOG_ERR("JFR limit(%u) larger than wqe num(%u).\n",
			     jfr_limit, udma_jfr->wqe_cnt);
		return URMA_FAIL;
	}

	ret = urma_cmd_modify_jfr(jfr, attr, NULL);
	if (ret != 0) {
		UDMA_LOG_ERR("modify jfr failed.\n");
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}
