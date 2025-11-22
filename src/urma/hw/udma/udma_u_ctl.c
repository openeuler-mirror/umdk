// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "urma_private.h"
#include "udma_u_common.h"
#include "udma_u_buf.h"
#include "udma_u_db.h"
#include "udma_u_jfs.h"
#include "udma_u_jfr.h"
#include "udma_u_jfc.h"
#include "udma_u_jetty.h"
#include "udma_u_ctl.h"

static void udma_u_uninit_queue_buf(struct udma_u_jetty_queue *q)
{
	if (q->wrid) {
		free(q->wrid);
		q->wrid = NULL;
	}

	q->qbuf = NULL;
	q->qbuf_curr = NULL;
	q->qbuf_end = NULL;
}

static int udma_u_init_queue_buf(struct udma_u_jetty_queue *q, uint32_t max_entry_cnt,
				 uint32_t baseblk_size, uint32_t page_size, void *qbuff)
{
	uint32_t buf_shift;
	uint32_t entry_cnt;

	entry_cnt = roundup_pow_of_two(max_entry_cnt);
	buf_shift = align_power2(entry_cnt * baseblk_size);
	q->baseblk_shift = align_power2(baseblk_size);
	q->qbuf_size = align((1U << buf_shift), page_size);
	q->baseblk_cnt = q->qbuf_size >> q->baseblk_shift;
	q->baseblk_mask = q->baseblk_cnt - 1U;

	q->wrid = (uintptr_t *)malloc(q->baseblk_cnt * sizeof(uint64_t));
	if (!q->wrid) {
		UDMA_LOG_ERR("failed to alloc STARS buffer for wrid!\n");
		return ENOMEM;
	}

	q->qbuf = qbuff;
	q->qbuf_curr = q->qbuf;
	q->qbuf_end = q->qbuf + q->qbuf_size;

	return 0;
}

static int udma_u_init_jfs_queue_buf(struct udma_u_jetty_queue *q,
				     struct udma_u_jfs_cfg_ex *cfg_ex)
{
	uint32_t buf_size = cfg_ex->cstm_cfg.sq.buff_size;
	bool cstm = !!cfg_ex->cstm_cfg.flag.bs.sq_cstm;
	uint32_t max_entry_cnt = cfg_ex->sqebb_num;
	uint32_t min_wqebb_cnt;

	min_wqebb_cnt = (cstm && cfg_ex->jetty_type == UDMA_U_CCU_JETTY_TYPE) ?
		UDMA_MIN_CCU_WQEBB_CNT : UDMA_MIN_JFS_WQEBB_CNT;
	q->baseblk_shift = UDMA_JFS_WQEBB_SHIFT;
	q->baseblk_cnt = cstm ? (buf_size >> q->baseblk_shift) : max_entry_cnt;
	q->baseblk_mask = q->baseblk_cnt - 1U;
	if (q->baseblk_cnt != roundup_pow_of_two(q->baseblk_cnt) ||
		q->baseblk_cnt < min_wqebb_cnt ||
		q->baseblk_cnt > UDMA_MAX_JFS_WQEBB_CNT) {
		UDMA_LOG_ERR("invalid sqebb num %u!\n", q->baseblk_cnt);
		return EINVAL;
	}
	q->qbuf_size = cstm ? buf_size : q->baseblk_cnt << q->baseblk_shift;

	q->wrid = (uintptr_t *)malloc(q->baseblk_cnt * sizeof(uint64_t));
	if (q->wrid == NULL) {
		UDMA_LOG_ERR("failed to alloc jfs STARS buffer for wrid!\n");
		return ENOMEM;
	}

	if (cstm) {
		q->qbuf = cfg_ex->cstm_cfg.sq.buff;
	} else if (q->ctx->hugepage_enable) {
		q->hugepage = udma_u_alloc_hugepage(q->ctx, q->qbuf_size);
		if (q->hugepage) {
			q->qbuf = q->hugepage->va_start;
		} else {
			UDMA_LOG_WARN("failed to alloc hugepage buf, switch to alloc standard buf.");
			q->qbuf = udma_u_alloc_buf(q->qbuf_size);
		}
	} else {
		q->qbuf = udma_u_alloc_buf(q->qbuf_size);
	}

	if (q->qbuf == NULL) {
		UDMA_LOG_ERR("failed to alloc queue buffer.\n");
		free(q->wrid);
		q->wrid = NULL;
		return ENOMEM;
	}

	q->qbuf_curr = q->qbuf;
	q->qbuf_end = q->qbuf + q->qbuf_size;

	return 0;
}

static int udma_u_create_idx_que_ex(struct udma_u_jfr *jfr, struct udma_u_jfr_cfg_ex *cfg_ex)
{
	struct udma_u_jfr_cstm_cfg *cstm_cfg = &cfg_ex->cstm_cfg;
	struct udma_u_jfr_idx_que *idx_que = &jfr->idx_que;

	idx_que->entry_shift = udma_u_ilog32(UDMA_JFR_IDX_QUE_ENTRY_SZ);
	idx_que->buf.length = (uint32_t)align(jfr->wqe_cnt << idx_que->entry_shift,
					      UDMA_HW_PAGE_SIZE);

	if (idx_que->buf.length != cstm_cfg->idx_que.buff_size) {
		UDMA_LOG_ERR("idx_que length is wrong, size = %u.\n", idx_que->buf.length);
		return EINVAL;
	}

	idx_que->buf.buf = cstm_cfg->idx_que.buff;

	idx_que->bitmap = udma_bitmap_alloc(jfr->wqe_cnt, &idx_que->bitmap_cnt);
	if (!idx_que->bitmap)
		return ENOMEM;

	return 0;
}

static int udma_u_create_rq_ex(struct udma_u_context *udma_ctx, struct udma_u_jfr *jfr,
			       struct udma_u_jfr_cfg_ex *cfg_ex)
{
	struct udma_u_jfr_cstm_cfg *cstm_cfg = &cfg_ex->cstm_cfg;
	struct udma_u_jetty_queue *rq = &jfr->rq;
	uint32_t sge_per_wqe;
	uint32_t wqebb_cnt;
	uint32_t ret;

	sge_per_wqe = min(jfr->max_sge, udma_ctx->jfr_sge);
	wqebb_cnt = sge_per_wqe * jfr->wqe_cnt;
	ret = udma_u_init_queue_buf(rq, wqebb_cnt, UDMA_JFR_WQEBB,
				    UDMA_HW_PAGE_SIZE, cstm_cfg->rq.buff);
	if (ret) {
		UDMA_LOG_ERR("init queue buf error, ret = %u.\n", ret);
		return EINVAL;
	}

	if (rq->qbuf_size != cstm_cfg->rq.buff_size) {
		UDMA_LOG_ERR("user cfg buffsize is error, rq->qbuf_size = %u.\n",
			     rq->qbuf_size);
		udma_u_uninit_queue_buf(rq);
		return EINVAL;
	}

	return 0;
}

static int udma_u_verify_que_cstm_cfg(struct udma_u_que_cfg_ex *que_cfg)
{
	if (que_cfg->buff == NULL || que_cfg->buff_size == 0) {
		UDMA_LOG_ERR("cstm cfg is invalid, que_cfg->buff_size = %u.\n",
			     que_cfg->buff_size);
		return EINVAL;
	}

	if (((uint64_t)que_cfg->buff & (uint64_t)PARTITION_ALIGNMENT) != 0) {
		UDMA_LOG_ERR("queue addr is not partition alignment.\n");
		return EINVAL;
	}

	return 0;
}

static int udma_u_verify_jfr_cstm_cfg(struct udma_u_jfr_cstm_cfg *cstm_cfg)
{
	if (!cstm_cfg->flag.bs.idxq_cstm || udma_u_verify_que_cstm_cfg(&cstm_cfg->idx_que)) {
		UDMA_LOG_ERR("jfr idxq cstm cfg is invalid, idxq_cstm = %d.\n",
			     cstm_cfg->flag.bs.idxq_cstm);
		return EINVAL;
	}

	if (!cstm_cfg->flag.bs.rq_cstm || udma_u_verify_que_cstm_cfg(&cstm_cfg->rq)) {
		UDMA_LOG_ERR("jfr rq cstm cfg is invalid, rq_cstm = %d.\n",
			     cstm_cfg->flag.bs.rq_cstm);
		return EINVAL;
	}

	if (!cstm_cfg->flag.bs.swdb_cstm || cstm_cfg->sw_db == NULL) {
		UDMA_LOG_ERR("jfr swdb cstm cfg is invalid, swdb_cstm = %d.\n",
			     cstm_cfg->flag.bs.swdb_cstm);
		return EINVAL;
	}

	return 0;
}

static int udma_u_verify_jfr_param_ex(urma_context_t *ctx, struct udma_u_jfr_cfg_ex *cfg_ex)
{
	if (cfg_ex == NULL || ctx == NULL) {
		UDMA_LOG_ERR("jfr ctx or cfg is null.\n");
		return EINVAL;
	}

	if (udma_u_verify_jfr_param(ctx, &cfg_ex->base_cfg))
		return EINVAL;

	return udma_u_verify_jfr_cstm_cfg(&cfg_ex->cstm_cfg);
}

static void udma_u_init_jfr_param_ex(struct udma_u_jfr *udma_jfr,
				     struct udma_u_jfr_cfg_ex *cfg_ex)
{
	struct udma_u_jfr_cstm_cfg *cstm_cfg;
	urma_jfr_cfg_t *base_cfg;

	base_cfg = &cfg_ex->base_cfg;
	cstm_cfg = &cfg_ex->cstm_cfg;
	udma_jfr->rq.cstm = cstm_cfg->flag.bs.rq_cstm;
	udma_jfr->idx_que.cstm = cstm_cfg->flag.bs.idxq_cstm;
	udma_jfr->swdb_cstm = cstm_cfg->flag.bs.swdb_cstm;
	udma_u_init_jfr_param(udma_jfr, base_cfg);
}

static urma_jfr_t *udma_u_create_jfr_ex(urma_context_t *ctx,
					struct udma_u_jfr_cfg_ex *cfg_ex)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jfr *udma_jfr;
	int ret;

	if (udma_u_verify_jfr_param_ex(ctx, cfg_ex))
		return NULL;

	udma_jfr = (struct udma_u_jfr *)calloc(1, sizeof(*udma_jfr));
	if (!udma_jfr) {
		UDMA_LOG_ERR("alloc jfr ex failed.\n");
		return NULL;
	}

	udma_u_init_jfr_param_ex(udma_jfr, cfg_ex);

	if (!udma_jfr->lock_free &&
		pthread_spin_init(&udma_jfr->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_spin_init;

	if (udma_u_create_idx_que_ex(udma_jfr, cfg_ex)) {
		UDMA_LOG_ERR("failed to create jfr idx que.\n");
		goto err_create_idx_que;
	}

	if (udma_u_create_rq_ex(udma_ctx, udma_jfr, cfg_ex)) {
		UDMA_LOG_ERR("failed to create jfr rqe buf.\n");
		goto err_create_rq;
	}

	udma_jfr->sw_db = cfg_ex->cstm_cfg.sw_db;

	ret = exec_jfr_create_cmd(ctx, udma_jfr, &cfg_ex->base_cfg);
	if (ret) {
		UDMA_LOG_ERR("urma cmd create jfr failed, ret = %d.\n", ret);
		goto err_exec_cmd;
	}

	if (udma_u_insert_jfr_node(udma_ctx, udma_jfr))
		goto err_insert_node;

	return &udma_jfr->base;

err_insert_node:
	(void)urma_cmd_delete_jfr(&udma_jfr->base);
err_exec_cmd:
	if (udma_jfr->rq.wrid)
		free(udma_jfr->rq.wrid);
err_create_rq:
	udma_bitmap_free(udma_jfr->idx_que.bitmap);
err_create_idx_que:
	if (!udma_jfr->lock_free)
		(void)pthread_spin_destroy(&udma_jfr->lock);
err_spin_init:
	free(udma_jfr);

	return NULL;
}

static int udma_u_create_sq_ex(struct udma_u_jetty_queue *sq,
			       struct udma_u_jfs_cfg_ex *cfg_ex)
{
	urma_jfs_cfg_t *base_cfg = &cfg_ex->base_cfg;
	int ret;

	sq->lock_free = !!base_cfg->flag.bs.lock_free;
	if (!sq->lock_free &&
	    pthread_spin_init(&sq->lock, PTHREAD_PROCESS_PRIVATE))
		return EINVAL;

	udma_u_init_sq_param(sq, base_cfg);

	sq->max_sge_num = base_cfg->max_sge;
	sq->sqe_bb_cnt = 1;
	ret = udma_u_init_jfs_queue_buf(sq, cfg_ex);
	if (ret) {
		UDMA_LOG_ERR("init queue buf wrong, ret = %d.\n", ret);
		goto err_init_sq_buf;
	}

	return 0;

err_init_sq_buf:
	if (!sq->lock_free)
		(void)pthread_spin_destroy(&sq->lock);
	return EFAULT;
}

static int udma_u_verify_jfs_cstm_cfg(struct udma_u_jfs_cstm_cfg *cstm_cfg)
{
	if (cstm_cfg->flag.bs.sq_cstm && udma_u_verify_que_cstm_cfg(&cstm_cfg->sq)) {
		UDMA_LOG_ERR("invalid sq buff parameter.\n");
		return EINVAL;
	}

	if (cstm_cfg->flag.bs.sq_cstm && ((cstm_cfg->sq.buff_size & (UDMA_JFS_WQEBB - 1)) != 0)) {
		UDMA_LOG_ERR("queue len is not partition alignment.\n");
		return EINVAL;
	}

	return 0;
}

static int udma_u_verify_jfs_param_ex(urma_context_t *ctx, struct udma_u_jfs_cfg_ex *cfg_ex)
{
	urma_device_attr_t *attr;
	urma_jfs_cfg_t *jfs_cfg;

	if (ctx == NULL) {
		UDMA_LOG_ERR("urma ctx is null.\n");
		return EINVAL;
	}

	if (cfg_ex == NULL) {
		UDMA_LOG_ERR("cfg ex is null.\n");
		return EINVAL;
	}

	attr = &ctx->dev->sysfs_dev->dev_attr;
	jfs_cfg = &cfg_ex->base_cfg;

	if ((jfs_cfg->max_inline_data != 0 && jfs_cfg->max_inline_data > attr->dev_cap.max_jfs_inline_len) ||
	    (jfs_cfg->max_sge > attr->dev_cap.max_jfs_sge) || (jfs_cfg->max_rsge > attr->dev_cap.max_jfs_rsge) ||
	    (cfg_ex->base_cfg.trans_mode == URMA_TM_RC)) {
		UDMA_LOG_ERR("jfs cfg out of range, depth:%u, max_depth:%u, inline_data:%u, max_inline_len:%u, " \
			     "sge:%hhu, max_sge:%u, rsge:%hhu, max_rsge:%u, trans_mode = %u.\n",
			     jfs_cfg->depth, attr->dev_cap.max_jfs_depth,
			     jfs_cfg->max_inline_data, attr->dev_cap.max_jfs_inline_len,
			     jfs_cfg->max_sge, attr->dev_cap.max_jfs_sge,
			     jfs_cfg->max_rsge, attr->dev_cap.max_jfs_rsge,
			     cfg_ex->base_cfg.trans_mode);
		return EINVAL;
	}

	return udma_u_verify_jfs_cstm_cfg(&cfg_ex->cstm_cfg);
}

static urma_jfs_t *udma_u_create_jfs_ex(urma_context_t *ctx,
					struct udma_u_jfs_cfg_ex *cfg_ex)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jfs *jfs;

	if (udma_u_verify_jfs_param_ex(ctx, cfg_ex))
		return NULL;

	jfs = (struct udma_u_jfs *)calloc(1, sizeof(struct udma_u_jfs));
	if (jfs == NULL) {
		UDMA_LOG_ERR("alloc jfs failed.\n");
		return NULL;
	}

	jfs->sq.ctx = udma_ctx;
	if (udma_u_create_sq_ex(&jfs->sq, cfg_ex)) {
		UDMA_LOG_ERR("failed to create sq.\n");
		goto err_create_sq;
	}

	jfs->sq.cstm = cfg_ex->cstm_cfg.flag.bs.sq_cstm;
	jfs->pi_type = cfg_ex->pi_type;
	jfs->jfs_type = (uint32_t)cfg_ex->jetty_type;
	jfs->sq.db.id = cfg_ex->id;
	cfg_ex->base_cfg.depth = 1;
	if (udma_u_exec_jfs_create_cmd(ctx, jfs, &cfg_ex->base_cfg)) {
		UDMA_LOG_ERR("failed to exec jfs create cmd.\n");
		goto err_exec_cmd;
	}

	jfs->sq.db.id = jfs->base.jfs_id.id;
	jfs->sq.db.type = UDMA_MMAP_JETTY_DSQE;
	if (udma_u_alloc_db(ctx, &jfs->sq.db)) {
		UDMA_LOG_ERR("failed to alloc db.\n");
		goto err_alloc_db;
	}

	jfs->sq.dwqe_addr = (void *)jfs->sq.db.addr;

	return &jfs->base;

err_alloc_db:
	urma_cmd_delete_jfs(&jfs->base);
err_exec_cmd:
	udma_u_delete_sq(&jfs->sq);
err_create_sq:
	free(jfs);

	return NULL;
}

static void udma_u_init_jfs_cfg_ex(struct udma_u_jetty_cfg_ex *cfg_ex, struct udma_u_jfs_cfg_ex *jfs_cfg)
{
	jfs_cfg->base_cfg = cfg_ex->base_cfg.jfs_cfg;
	jfs_cfg->cstm_cfg = cfg_ex->jfs_cstm;
	jfs_cfg->sqebb_num = cfg_ex->sqebb_num;
	jfs_cfg->jetty_type = cfg_ex->jetty_type;
}

static int udma_u_create_jetty_check_cap(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg)
{
	urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;
	urma_jfr_cfg_t *jfr_cfg = &jetty_cfg->shared.jfr->jfr_cfg;
	urma_jfs_cfg_t *jfs_cfg = &jetty_cfg->jfs_cfg;

	if ((jfs_cfg->max_inline_data != 0 && jfs_cfg->max_inline_data > cap->max_jfs_inline_len) ||
	    (jfr_cfg->depth == 0 || jfr_cfg->depth > cap->max_jfr_depth) ||
	    (jfs_cfg->max_sge > cap->max_jfs_sge || jfs_cfg->max_rsge > cap->max_jfs_rsge || \
	     jfr_cfg->max_sge > cap->max_jfr_sge)) {
		UDMA_LOG_ERR("jetty cfg out of range, jfs_depth:%u, max_jfs_depth: %u, " \
			"inline_data:%u, max_jfs_inline_len: %u, jfr_depth:%u, max_jfr_depth: %u, " \
			"jfs_sge:%hhu, max_jfs_sge:%u, jfs_rsge:%hhu, max_jfs_rsge:%u, jfr_sge:%hhu, max_jfr_sge:%u.\n",
			jfs_cfg->depth, cap->max_jfs_depth, jfs_cfg->max_inline_data, cap->max_jfs_inline_len,
			jfr_cfg->depth, cap->max_jfr_depth, jfs_cfg->max_sge, cap->max_jfs_sge,
			jfs_cfg->max_rsge, cap->max_jfs_rsge, jfr_cfg->max_sge, cap->max_jfr_sge);
		return EINVAL;
	}

	return 0;
}

static int udma_u_check_jetty_param_ex(urma_context_t *ctx,
				       struct udma_u_jetty_cfg_ex *cfg_ex)
{
	urma_jetty_cfg_t *jetty_cfg = &cfg_ex->base_cfg;
	urma_transport_mode_t trans_mode;

	if (jetty_cfg->jfs_cfg.jfc == NULL) {
		UDMA_LOG_ERR("jfc in jfs_cfg is null.\n");
		return EINVAL;
	}

	if (jetty_cfg->flag.bs.share_jfr == URMA_NO_SHARE_JFR ||
	    jetty_cfg->shared.jfr == NULL ||
	    jetty_cfg->shared.jfr->jfr_cfg.jfc == NULL) {
		UDMA_LOG_ERR("only support share jfr.\n");
		return EINVAL;
	}

	trans_mode = jetty_cfg->jfs_cfg.trans_mode;
	if (trans_mode != URMA_TM_RM && trans_mode != URMA_TM_RC &&
	    trans_mode != URMA_TM_UM) {
		UDMA_LOG_ERR("invalid jetty parameter, jetty trans_mode = %d.\n",
			     (int)trans_mode);
		return EINVAL;
	}

	if (udma_u_create_jetty_check_cap(ctx, jetty_cfg))
		return EINVAL;

	return 0;
}

static int udma_u_check_jetty_cfg_ex(struct udma_u_jetty_cfg_ex *cfg_ex)
{
	if (cfg_ex->jetty_type > UDMA_U_NORMAL_JETTY_TYPE) {
		UDMA_LOG_ERR("invalid jetty type %u.\n", cfg_ex->jetty_type);
		return EINVAL;
	}

	return 0;
}

static int udma_u_verify_jetty_param_ex(urma_context_t *ctx,
					struct udma_u_jetty_cfg_ex *cfg_ex)
{
	if (ctx == NULL || cfg_ex == NULL) {
		UDMA_LOG_ERR("jetty ctx or cfg_ex is null.\n");
		return EINVAL;
	}

	if (udma_u_check_jetty_cfg_ex(cfg_ex))
		return EINVAL;

	if (udma_u_check_jetty_param_ex(ctx, cfg_ex))
		return EINVAL;

	if (udma_u_verify_jfs_cstm_cfg(&cfg_ex->jfs_cstm)) {
		UDMA_LOG_ERR("jetty jfs_cstm is invalid.\n");
		return EINVAL;
	}

	return 0;
}

static void udma_u_init_jetty_param_ex(struct udma_u_jetty *jetty,
				       struct udma_u_jetty_cfg_ex *cfg_ex)
{
	jetty->jfr = to_udma_u_jfr(cfg_ex->base_cfg.shared.jfr);
	jetty->sq.cstm = cfg_ex->jfs_cstm.flag.bs.sq_cstm != 0 ? true : false;
	jetty->jetty_type = (uint32_t)cfg_ex->jetty_type;
	jetty->pi_type = cfg_ex->pi_type;
	cfg_ex->base_cfg.jfs_cfg.depth = 1;
}

static urma_jetty_t *udma_u_create_jetty_ex(urma_context_t *ctx, struct udma_u_jetty_cfg_ex *cfg_ex)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jfs_cfg_ex jfs_cfg = {};
	struct udma_u_jetty *jetty;
	int ret;

	if (udma_u_verify_jetty_param_ex(ctx, cfg_ex))
		return NULL;

	jetty = (struct udma_u_jetty *)calloc(1, sizeof(struct udma_u_jetty));
	if (jetty == NULL) {
		UDMA_LOG_ERR("jetty memory allocation failed.\n");
		return NULL;
	}

	if (init_jetty_trans_mode(jetty, &cfg_ex->base_cfg))
		goto err_init_jetty_trans_mode;

	udma_u_init_jfs_cfg_ex(cfg_ex, &jfs_cfg);
	jetty->sq.ctx = udma_ctx;
	ret = udma_u_create_sq_ex(&jetty->sq, &jfs_cfg);
	if (ret != 0) {
		UDMA_LOG_ERR("jetty create sq failed, ret = %d.\n", ret);
		goto err_init_jetty_trans_mode;
	}

	udma_u_init_jetty_param_ex(jetty, cfg_ex);

	if (exec_jetty_create_cmd(ctx, jetty, &cfg_ex->base_cfg)) {
		UDMA_LOG_ERR("failed to create jetty.\n");
		goto err_jetty_create_cmd;
	}

	jetty->sq.db.id = jetty->base.jetty_id.id;
	jetty->sq.db.type = UDMA_MMAP_JETTY_DSQE;
	if (udma_u_alloc_db(ctx, &jetty->sq.db)) {
		UDMA_LOG_ERR("failed to alloc db.\n");
		goto err_alloc_db;
	}

	jetty->sq.dwqe_addr = (void *)jetty->sq.db.addr;
	jetty->sq.idx = jetty->base.jetty_id.id;
	if (insert_jetty_node(udma_ctx, jetty)) {
		UDMA_LOG_ERR("failed to insert jetty_queue.\n");
		goto err_insert_node;
	}

	return &jetty->base;
err_insert_node:
	udma_u_free_db(ctx, &jetty->sq.db);
err_alloc_db:
	urma_cmd_delete_jetty(&jetty->base);
err_jetty_create_cmd:
	udma_u_delete_sq(&jetty->sq);
err_init_jetty_trans_mode:
	free(jetty);

	return NULL;
}

static int udma_u_jfc_cmd_ex(urma_context_t *ctx, struct udma_u_jfc *jfc,
			     struct udma_u_jfc_cfg_ex *cfg, uint32_t jfc_depth)
{
	struct udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};

	cmd.mode = (uint32_t)cfg->jfc_mode;
	cmd.buf_len = jfc_depth;

	udma_u_set_udata(&udata, &cmd, sizeof(cmd), NULL, 0);

	return urma_cmd_create_jfc(ctx, &jfc->base, &cfg->base_cfg, &udata);
}

static int udma_u_verify_jfc_param_ex(urma_context_t *ctx, struct udma_u_jfc_cfg_ex *cfg_ex)
{
	urma_device_cap_t *cap;

	if (ctx == NULL || cfg_ex == NULL) {
		UDMA_LOG_ERR("invalid param, jfc ctx or cfg_ex is null.\n");
		return EINVAL;
	}

	if (cfg_ex->jfc_mode < UDMA_U_STARS_JFC_TYPE ||
	    cfg_ex->jfc_mode > UDMA_U_CCU_JFC_TYPE) {
		UDMA_LOG_ERR("invalid param, STARS jfc mode = %u.\n",
			     cfg_ex->jfc_mode);
		return EINVAL;
	}

	cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;

	if (!cfg_ex->base_cfg.depth || cfg_ex->base_cfg.depth > cap->max_jfc_depth) {
		UDMA_LOG_ERR("invalid STARS jfc depth = %u, cap depth = %u.\n",
			     cfg_ex->base_cfg.depth, cap->max_jfc_depth);
		return EINVAL;
	}

	if (cfg_ex->base_cfg.ceqn >= cap->ceq_cnt) {
		UDMA_LOG_ERR("invalid STARS jfc ceqn = %u, cap ceq cnt = %u.\n",
			     cfg_ex->base_cfg.ceqn, cap->ceq_cnt);
		return EINVAL;
	}

	return 0;
}

static urma_jfc_t *udma_u_create_jfc_ex(urma_context_t *ctx,
					struct udma_u_jfc_cfg_ex *cfg_ex)
{
	struct udma_u_jfc *jfc;
	uint32_t depth;
	int ret;

	if (udma_u_verify_jfc_param_ex(ctx, cfg_ex))
		return NULL;

	jfc = (struct udma_u_jfc *)calloc(1, sizeof(*jfc));
	if (!jfc) {
		UDMA_LOG_ERR("failed to alloc user udma STARS jfc memory.\n");
		return NULL;
	}

	jfc->cq.lock_free = cfg_ex->base_cfg.flag.bs.lock_free;
	jfc->mode = cfg_ex->jfc_mode;
	if (!jfc->cq.lock_free &&
	    pthread_spin_init(&jfc->cq.lock, PTHREAD_PROCESS_PRIVATE)) {
		UDMA_LOG_ERR("failed to init user udma STARS jfc spinlock.\n");
		goto err_init_lock;
	}

	depth = cfg_ex->base_cfg.depth < UDMA_U_MIN_JFC_DEPTH ?
		UDMA_U_MIN_JFC_DEPTH : roundup_pow_of_two(cfg_ex->base_cfg.depth);

	ret = udma_u_jfc_cmd_ex(ctx, jfc, cfg_ex, depth);
	if (ret) {
		UDMA_LOG_ERR("udma STARS jfc failed to create urma cmd, ret = %d.\n", ret);
		goto err_create_jfc;
	}

	jfc->arm_sn = 1;

	return &jfc->base;

err_create_jfc:
	if (!jfc->cq.lock_free)
		pthread_spin_destroy(&jfc->cq.lock);
err_init_lock:
	free(jfc);

	return NULL;
}

static int udma_u_jfr_ops_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			     urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op)
{
	struct udma_u_jfr_cfg_ex cfg_ex;
	urma_jfr_t *jfr = NULL;

	if (op == UDMA_U_USER_CTL_CREATE_JFR_EX) {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_jfr_cfg_ex), op) ||
		    !udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(urma_jfr_t *), op))
			return EINVAL;

		(void)memcpy(&cfg_ex, (void *)in->addr, sizeof(struct udma_u_jfr_cfg_ex));
		jfr = udma_u_create_jfr_ex(ctx, &cfg_ex);
		if (jfr == NULL)
			return EFAULT;

		memcpy((void *)out->addr, &jfr, sizeof(urma_jfr_t *));
		atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
	} else {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(urma_jfr_t *), op))
			return EINVAL;

		(void)memcpy(&jfr, (void *)in->addr, sizeof(urma_jfr_t *));
		if (jfr == NULL)
			return EINVAL;

		if (udma_u_delete_jfr(jfr))
			return EFAULT;

		atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
	}

	return 0;
}

static void udma_fill_jfs_ex_out(urma_user_ctl_out_t *out, urma_jfs_t *jfs)
{
	struct udma_u_jfs *udma_jfs = to_udma_u_jfs(jfs);
	struct udma_u_jfs_info jfs_info;

	jfs_info.jfs = jfs;
	jfs_info.dwqe_addr = udma_jfs->sq.dwqe_addr;
	jfs_info.db_addr = jfs_info.dwqe_addr + UDMA_DOORBELL_OFFSET;

	(void)memcpy((void *)out->addr, &jfs_info, sizeof(struct udma_u_jfs_info));
}

static int udma_u_jfs_ops_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			     urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op)
{
	struct udma_u_jfs_cfg_ex cfg_ex;
	urma_jfs_t *jfs = NULL;

	if (op == UDMA_U_USER_CTL_CREATE_JFS_EX) {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_jfs_cfg_ex), op) ||
		    !udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(struct udma_u_jfs_info), op))
			return EINVAL;

		(void)memcpy(&cfg_ex, (void *)in->addr, sizeof(struct udma_u_jfs_cfg_ex));
		jfs = udma_u_create_jfs_ex(ctx, &cfg_ex);
		if (jfs == NULL)
			return EFAULT;

		udma_fill_jfs_ex_out(out, jfs);
		atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
	} else {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(urma_jfs_t *), op))
			return EINVAL;

		(void)memcpy(&jfs, (void *)in->addr, sizeof(urma_jfs_t *));
		if (jfs == NULL)
			return EINVAL;

		if (udma_u_delete_jfs(jfs))
			return EFAULT;

		atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
	}

	return 0;
}

static int udma_u_jfc_ops_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			     urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op)
{
	struct udma_u_jfc_cfg_ex cfg_ex;
	urma_jfc_t *jfc = NULL;

	if (op == UDMA_U_USER_CTL_CREATE_JFC_EX) {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_jfc_cfg_ex), op) ||
		    !udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(urma_jfc_t *), op))
			return EINVAL;

		(void)memcpy(&cfg_ex, (void *)(uintptr_t)in->addr, sizeof(struct udma_u_jfc_cfg_ex));
		jfc = udma_u_create_jfc_ex(ctx, &cfg_ex);
		if (jfc == NULL)
			return EFAULT;

		memcpy((void *)out->addr, &jfc, sizeof(urma_jfc_t *));
		atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
	} else {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(urma_jfc_t *), op))
			return EINVAL;

		(void)memcpy(&jfc, (void *)(uintptr_t)in->addr, sizeof(urma_jfc_t *));
		if (jfc == NULL)
			return EINVAL;

		if (udma_u_delete_jfc(jfc))
			return EFAULT;

		atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
	}

	return 0;
}

static void udma_fill_create_jetty_ex_out(urma_user_ctl_out_t *out, urma_jetty_t *jetty)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	struct udma_u_jetty_info jetty_info;

	jetty_info.jetty = jetty;
	jetty_info.dwqe_addr = udma_jetty->sq.dwqe_addr;
	jetty_info.db_addr = jetty_info.dwqe_addr + UDMA_DOORBELL_OFFSET;
	(void)memcpy((void *)out->addr, &jetty_info, sizeof(struct udma_u_jetty_info));
}

static int udma_u_jetty_ops_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			       urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op)
{
	struct udma_u_jetty_cfg_ex cfg_ex;
	urma_jetty_t *jetty = NULL;

	if (op == UDMA_U_USER_CTL_CREATE_JETTY_EX) {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_jetty_cfg_ex), op) ||
		    !udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(struct udma_u_jetty_info), op))
			return EINVAL;

		(void)memcpy(&cfg_ex, (void *)in->addr, sizeof(struct udma_u_jetty_cfg_ex));
		jetty = udma_u_create_jetty_ex(ctx, &cfg_ex);
		if (jetty == NULL)
			return EFAULT;

		udma_fill_create_jetty_ex_out(out, jetty);
		atomic_fetch_add(&ctx->ref.atomic_cnt, 1);
	} else {
		if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(urma_jetty_t *), op))
			return EINVAL;

		(void)memcpy(&jetty, (void *)in->addr, sizeof(urma_jetty_t *));
		if (jetty == NULL)
			return EINVAL;

		if (udma_u_delete_jetty(jetty))
			return EFAULT;

		atomic_fetch_sub(&ctx->ref.atomic_cnt, 1);
	}

	return 0;
}

static void udma_set_post_info(struct udma_u_jetty_queue *sq,
			       struct udma_jfs_sqe_ctl *ctrl,
			       struct udma_u_post_info *info)
{
	info->ctrl = (uint64_t *)ctrl;
	info->dwqe_addr = (uint64_t *)sq->dwqe_addr;
	info->pi = sq->pi;
	info->db_addr = (void *)((char *)sq->db.addr + UDMA_DOORBELL_OFFSET);
}

static bool udma_valid_reduce_opcode(struct udma_u_context *udma_ctx,
				     struct udma_u_jfs_wr_ex *cur_wr_ex)
{
	if (!udma_ctx->reduce_enable) {
		UDMA_LOG_ERR("Not support reduce!\n");
		return false;
	}

	if (cur_wr_ex->wr.opcode != URMA_OPC_WRITE &&
	    cur_wr_ex->wr.opcode != URMA_OPC_WRITE_NOTIFY && cur_wr_ex->wr.opcode != URMA_OPC_READ) {
		UDMA_LOG_ERR("Invalid opcode(%u) for reduce ops!\n", cur_wr_ex->wr.opcode);
		return false;
	}

	if (cur_wr_ex->reduce_opcode < REDUCE_OPCODE_MIN || cur_wr_ex->reduce_opcode > REDUCE_OPCODE_MAX) {
		UDMA_LOG_ERR("Invalid reduce opcode(%u) for reduce ops!\n", cur_wr_ex->reduce_opcode);
		return false;
	}

	if (cur_wr_ex->reduce_data_type > REDUCE_DATA_TYPE_MAX) {
		UDMA_LOG_ERR("Invalid reduce data_type(%u) for reduce ops!\n", cur_wr_ex->reduce_data_type);
		return false;
	}

	return true;
}

static urma_status_t
udma_u_post_sq_wr_ex(struct udma_u_context *udma_ctx, struct udma_u_jetty_queue *sq,
		     struct udma_u_jfs_wr_ex **bad_wr, struct udma_u_wr_ex *wr_ex,
		     struct udma_u_post_info *info)
{
	struct udma_u_jfs_wr_ex *cur_wr_ex;
	struct udma_jfs_sqe_ctl *wqe_addr;
	urma_status_t ret = URMA_SUCCESS;
	bool dwqe_enable = false;
	urma_jfs_wr_t *it;
	urma_jfs_wr_t *wr;
	int wr_cnt = 0;

	wr = &(wr_ex->wr->wr);
	if (!sq->lock_free)
		(void)pthread_spin_lock(&sq->lock);

	for (it = wr; it != NULL; it = (urma_jfs_wr_t *)it->next) {
		cur_wr_ex = to_udma_u_jfs_wr_ex(it);
		if (cur_wr_ex->reduce_en && !udma_valid_reduce_opcode(udma_ctx, cur_wr_ex)) {
			ret = URMA_EINVAL;
			*bad_wr = cur_wr_ex;
			goto out;
		}

		ret = udma_u_post_one_wr(udma_ctx, sq, it, &wqe_addr, &dwqe_enable);
		if (ret) {
			*bad_wr = cur_wr_ex;
			goto out;
		}

		if (cur_wr_ex->reduce_en) {
			wqe_addr->udf_flag = 1;
			wqe_addr->udf_type = 0;
			wqe_addr->reduce_data_type = cur_wr_ex->reduce_data_type;
			wqe_addr->reduce_opcode = cur_wr_ex->reduce_opcode;
		}

		wr_cnt++;
	}
out:
	if (wr_cnt != 0) {
		udma_to_device_barrier();
		wqe_addr->sqe_bb_idx = sq->pi;
		if (wr_ex->db_en) {
			if (wr_cnt == 1 && dwqe_enable && (sq->pi - sq->ci == 1))
				mmio_memcpy_x64((uint64_t *)sq->dwqe_addr, (uint64_t *)wqe_addr);
			else
				udma_update_sq_db(sq);
		} else {
			udma_set_post_info(sq, wqe_addr, info);
		}
	}

	if (!sq->lock_free)
		(void)pthread_spin_unlock(&sq->lock);

	return ret;
}

static urma_status_t udma_u_post_jetty_wr_ex(struct udma_u_wr_ex *wr_ex,
					     struct udma_u_post_info *info)
{
	struct udma_u_jfs_wr_ex **bad_wr;
	struct udma_u_context *udma_ctx;
	struct udma_u_jetty *udma_jetty;
	urma_jetty_t *urma_jetty;
	urma_status_t ret;

	urma_jetty = wr_ex->jetty;
	bad_wr = wr_ex->bad_wr;
	udma_ctx = to_udma_u_ctx(urma_jetty->urma_ctx);
	udma_jetty = to_udma_u_jetty(urma_jetty);

	ret = udma_u_post_sq_wr_ex(udma_ctx, &udma_jetty->sq, bad_wr,
				wr_ex, info);
	if (ret)
		UDMA_LOG_ERR("Jetty post sq wr_ex failed, ret = %d, id = %u.\n",
			     ret, udma_jetty->sq.idx);

	return ret;
}

static urma_status_t udma_u_post_jfs_wr_ex(struct udma_u_wr_ex *wr_ex,
					   struct udma_u_post_info *info)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	urma_status_t ret;
	urma_jfs_t *jfs;

	jfs = wr_ex->jfs;
	udma_jfs = to_udma_u_jfs(jfs);
	udma_ctx = to_udma_u_ctx(jfs->urma_ctx);

	ret = udma_u_post_sq_wr_ex(udma_ctx, &udma_jfs->sq, wr_ex->bad_wr,
				wr_ex, info);
	if (ret)
		UDMA_LOG_ERR("JFS post sq wr_ex failed, ret = %d, id = %u.\n",
			     ret, udma_jfs->sq.idx);

	return ret;
}

static int udma_u_post_wr_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			     urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op)
{
	struct udma_u_post_info info;
	struct udma_u_wr_ex wr_ex;

	RTE_SET_USED(ctx);
	if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_wr_ex), op) ||
	    !udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(struct udma_u_post_info), op))
		return EINVAL;

	(void)memcpy(&wr_ex, (void *)in->addr, sizeof(struct udma_u_wr_ex));

	if (!wr_ex.is_jetty) {
		if (udma_u_post_jfs_wr_ex(&wr_ex, &info))
			return EFAULT;
	} else {
		if (udma_u_post_jetty_wr_ex(&wr_ex, &info))
			return EFAULT;
	}

	(void)memcpy((void *)out->addr, &info, sizeof(info));

	return 0;
}

static int udma_u_update_ci_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			       urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op)
{
	struct udma_u_update_ci update_info = {};
	struct udma_u_jetty *udma_jetty;
	struct udma_u_jetty_queue *sq;
	struct udma_u_jfs *udma_jfs;
	urma_jetty_t *jetty;
	urma_jfs_t *jfs;

	RTE_SET_USED(ctx);
	RTE_SET_USED(out);
	if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_update_ci), op))
		return EINVAL;

	(void)memcpy(&update_info, (void *)in->addr, sizeof(struct udma_u_update_ci));

	if (!update_info.is_jetty) {
		jfs = update_info.jfs;
		if (jfs == NULL)
			return EINVAL;
		udma_jfs = to_udma_u_jfs(jfs);
		sq = &udma_jfs->sq;
	} else {
		jetty = update_info.jetty;
		if (jetty == NULL)
			return EINVAL;
		udma_jetty = to_udma_u_jetty(jetty);
		sq = &udma_jetty->sq;
	}

	sq->ci += (update_info.ci - sq->ci) & (sq->baseblk_cnt - 1);
	sq->ci++;

	sq->old_entry_idx = update_info.ci;

	return 0;
}

static int udma_u_query_ue_info(urma_context_t *ctx, urma_user_ctl_in_t *in,
				urma_user_ctl_out_t *out,
				enum udma_u_user_ctl_opcode op)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_ue_info info = {};

	RTE_SET_USED(in);
	if (!udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(struct udma_u_ue_info), op))
		return EINVAL;

	info.ue_id = udma_ctx->ue_id;
	info.chip_id = udma_ctx->chip_id;
	info.die_id = udma_ctx->die_id;

	(void)memcpy((void *)out->addr, &info, sizeof(struct udma_u_ue_info));

	return 0;
}

static int udma_u_ctrlq_query_tp_sport(urma_context_t *ctx, urma_user_ctl_in_t *in,
				       urma_user_ctl_out_t *out,
				       enum udma_u_user_ctl_opcode op)
{
	urma_udrv_t udrv_data = {};
	int ret;

	if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_tp_sport_in), op) ||
	    !udma_u_user_ctl_check_param(out->addr, out->len, (uint32_t)sizeof(struct udma_u_tp_sport_out), op))
		return EINVAL;

	in->opcode = UDMA_USER_CTL_QUERY_TP_SPORT;

	ret = urma_cmd_user_ctl(ctx, in, out, &udrv_data);
	if (ret)
		UDMA_LOG_ERR("failed to query tp sport, ret: %d.\n", ret);

	return ret;
}

int udma_u_query_cqe_aux_info(urma_context_t *ctx, urma_user_ctl_in_t *in,
			      urma_user_ctl_out_t *out,
			      enum udma_u_user_ctl_opcode op)
{
#define UDMA_USER_CTL_QUERY_CQE_AUX_INFO 10
	urma_udrv_t udrv_data = {};
	int ret;

	if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_cqe_info_in), op))
		return EINVAL;

	in->opcode = UDMA_USER_CTL_QUERY_CQE_AUX_INFO;

	ret = urma_cmd_user_ctl(ctx, in, out, &udrv_data);
	if (ret)
		UDMA_LOG_ERR("failed to query cqe aux info, ret: %d.\n", ret);

	in->opcode = UDMA_U_USER_CTL_QUERY_CQE_AUX_INFO;

	return ret;
}

static int udma_u_query_ae_aux_info(urma_context_t *ctx, urma_user_ctl_in_t *in,
				       urma_user_ctl_out_t *out,
				       enum udma_u_user_ctl_opcode op)
{
#define UDMA_USER_CTL_QUERY_AE_AUX_INFO 11
	urma_udrv_t udrv_data = {};
	int ret;

	if (!udma_u_user_ctl_check_param(in->addr, in->len, (uint32_t)sizeof(struct udma_u_ae_info_in), op))
		return EINVAL;

	in->opcode = UDMA_USER_CTL_QUERY_AE_AUX_INFO;

	ret = urma_cmd_user_ctl(ctx, in, out, &udrv_data);
	if (ret)
		UDMA_LOG_ERR("failed to query cqe aux info, ret: %d.\n", ret);

	in->opcode = UDMA_U_USER_CTL_QUERY_AE_AUX_INFO;

	return ret;
}

static udma_u_user_ctl_ops g_udma_u_user_ctl_ops[] = {
	[UDMA_U_USER_CTL_CREATE_JFR_EX] = udma_u_jfr_ops_ex,
	[UDMA_U_USER_CTL_DELETE_JFR_EX] = udma_u_jfr_ops_ex,
	[UDMA_U_USER_CTL_CREATE_JFS_EX] = udma_u_jfs_ops_ex,
	[UDMA_U_USER_CTL_DELETE_JFS_EX] = udma_u_jfs_ops_ex,
	[UDMA_U_USER_CTL_CREATE_JFC_EX] = udma_u_jfc_ops_ex,
	[UDMA_U_USER_CTL_DELETE_JFC_EX] = udma_u_jfc_ops_ex,
	[UDMA_U_USER_CTL_CREATE_JETTY_EX] = udma_u_jetty_ops_ex,
	[UDMA_U_USER_CTL_DELETE_JETTY_EX] = udma_u_jetty_ops_ex,
	[UDMA_U_USER_CTL_POST_WR] = udma_u_post_wr_ex,
	[UDMA_U_USER_CTL_UPDATE_CI] = udma_u_update_ci_ex,
	[UDMA_U_USER_CTL_QUERY_UE_INFO] = udma_u_query_ue_info,
	[UDMA_U_USER_CTL_QUERY_TP_SPORT] = udma_u_ctrlq_query_tp_sport,
	[UDMA_U_USER_CTL_QUERY_CQE_AUX_INFO] = udma_u_query_cqe_aux_info,
	[UDMA_U_USER_CTL_QUERY_AE_AUX_INFO] = udma_u_query_ae_aux_info,
};

bool udma_u_user_ctl_check_param(uint64_t addr, uint32_t in_len, uint32_t len,
				 enum udma_u_user_ctl_opcode opcode)
{
	if (addr == 0 || (in_len != len)) {
		UDMA_LOG_ERR("parameter invalid in user ctl process,"
			     "opcode = %u, len = %u.\n", opcode, in_len);
		return false;
	}

	return true;
}

int udma_u_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in,
		    urma_user_ctl_out_t *out)
{
	if (ctx == NULL || in == NULL || out == NULL) {
		UDMA_LOG_ERR("parameter invalid in urma_user_ctl.\n");
		return URMA_EINVAL;
	}

	if (in->opcode >= UDMA_U_USER_CTL_MAX) {
		UDMA_LOG_ERR("invalid opcode: 0x%x.\n", in->opcode);
		return URMA_ENOPERM;
	}

	return g_udma_u_user_ctl_ops[in->opcode](ctx, in, out,
		(enum udma_u_user_ctl_opcode)in->opcode);
}
