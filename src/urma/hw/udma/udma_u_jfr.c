// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include "urma_private.h"
#include "udma_u_buf.h"
#include "udma_u_db.h"
#include "udma_u_jfc.h"
#include "udma_u_jfr.h"

int udma_u_verify_jfr_param(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
{
	urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;

	if (!cfg->max_sge || !cfg->depth || cfg->depth > cap->max_jfr_depth ||
	    cfg->max_sge > cap->max_jfr_sge) {
		UDMA_LOG_ERR("Invalid jfr param, depth = %u, max_sge = %u.\n",
			     cfg->depth, cfg->max_sge);
		return EINVAL;
	}

	if (cfg->flag.bs.token_policy > URMA_TOKEN_PLAIN_TEXT) {
		UDMA_LOG_ERR("jfr token policy = %d is not supported now.\n",
			     cfg->flag.bs.token_policy);
		return EINVAL;
	}

	return 0;
}

void udma_u_init_jfr_param(struct udma_u_jfr *jfr, urma_jfr_cfg_t *cfg)
{
	if (cfg->depth < UDMA_U_MIN_JFR_DEPTH)
		jfr->wqe_cnt = UDMA_U_MIN_JFR_DEPTH;
	else
		jfr->wqe_cnt = roundup_pow_of_two(cfg->depth);

	jfr->max_sge = roundup_pow_of_two(cfg->max_sge);
	jfr->rq.trans_mode  = cfg->trans_mode;
	jfr->wqe_shift = udma_u_ilog32(roundup_pow_of_two(UDMA_SGE_SIZE *
							  jfr->max_sge));
	jfr->lock_free = cfg->flag.bs.lock_free;
}

static int udma_u_create_rq(struct udma_u_context *udma_ctx,
			    struct udma_u_jfr *jfr)
{
	struct udma_u_jetty_queue *rq = &jfr->rq;
	uint32_t sge_per_wqe;
	uint32_t wqebb_cnt;

	sge_per_wqe = min(jfr->max_sge, udma_ctx->jfr_sge);
	wqebb_cnt = sge_per_wqe * jfr->wqe_cnt;

	if (!udma_u_alloc_queue_buf(rq, wqebb_cnt, UDMA_JFR_WQEBB,
				   UDMA_HW_PAGE_SIZE, true)) {
		UDMA_LOG_ERR("failed to alloc jfr wqe buf.\n");
		return EINVAL;
	}

	return 0;
}

int exec_jfr_create_cmd(urma_context_t *ctx, struct udma_u_jfr *jfr,
			urma_jfr_cfg_t *cfg)
{
	struct udma_create_jetty_ucmd cmd = {};
	struct udma_create_jfr_resp resp = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	cmd.buf_addr = (uintptr_t)jfr->rq.qbuf;
	cmd.buf_len = jfr->rq.qbuf_size;
	/* JFR only support record db */
	cmd.db_addr = (uintptr_t)jfr->sw_db;
	cmd.jfr_sleep_buf = (uintptr_t)jfr->long_sleeptime;
	cmd.idx_addr = (uintptr_t)jfr->idx_que.buf.buf;
	cmd.idx_len = jfr->idx_que.buf.length;
	cmd.jetty_addr = (uintptr_t)&jfr->rq;
	cmd.non_pin = jfr->rq.cstm;
	cmd.is_hugepage = jfr->rq.hugepage != NULL;

	udma_u_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfr(ctx, &jfr->base, cfg, &udata);
	if (ret)
		return ret;

	jfr->cap_flags = resp.jfr_caps;
	jfr->rq.idx = jfr->base.jfr_id.id;

	return 0;
}

static int udma_u_alloc_jfr_idx_que(struct udma_u_jfr *jfr)
{
	struct udma_u_jfr_idx_que *idx_que = &jfr->idx_que;
	uint32_t buf_size;

	idx_que->entry_shift = udma_u_ilog32(UDMA_JFR_IDX_QUE_ENTRY_SZ);
	idx_que->bitmap = udma_bitmap_alloc(jfr->wqe_cnt, &idx_que->bitmap_cnt);
	if (!idx_que->bitmap)
		return ENOMEM;

	buf_size = align(jfr->wqe_cnt << idx_que->entry_shift,
			 UDMA_HW_PAGE_SIZE);
	idx_que->buf.length = align(buf_size, UDMA_HW_PAGE_SIZE);
	idx_que->buf.buf = udma_u_alloc_buf(idx_que->buf.length);
	if (!idx_que->buf.buf) {
		udma_bitmap_free(idx_que->bitmap);
		idx_que->bitmap = NULL;
		return ENOMEM;
	}

	return 0;
}

static void udma_u_free_idx_que(struct udma_u_jfr_idx_que *idx_que)
{
	if (!idx_que->cstm)
		udma_u_free_buf(idx_que->buf.buf, idx_que->buf.length);

	udma_bitmap_free(idx_que->bitmap);
}

int udma_u_insert_jfr_node(struct udma_u_context *udma_ctx, struct udma_u_jfr *jfr)
{
	uint32_t jettys_in_tbl = 1 << udma_ctx->jettys_in_tbl_shift;
	uint32_t mask = jettys_in_tbl - 1;
	struct udma_u_jfr **jfr_array;
	uint32_t table_id;

	table_id = jfr->rq.idx >> udma_ctx->jettys_in_tbl_shift;
	pthread_rwlock_wrlock(&udma_ctx->jfr_table_lock);
	if (!udma_ctx->jfr_table[table_id].refcnt) {
		udma_ctx->jfr_table[table_id].jfr_array = (struct udma_u_jfr **)calloc(jettys_in_tbl,
							sizeof(struct udma_u_jfr *));
		if (!udma_ctx->jfr_table[table_id].jfr_array) {
			pthread_rwlock_unlock(&udma_ctx->jfr_table_lock);
			return URMA_ENOMEM;
		}
	}

	jfr_array = udma_ctx->jfr_table[table_id].jfr_array;
	++udma_ctx->jfr_table[table_id].refcnt;
	jfr_array[jfr->rq.idx & mask] = jfr;
	pthread_rwlock_unlock(&udma_ctx->jfr_table_lock);

	return URMA_SUCCESS;
}

urma_jfr_t *udma_u_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jfr *udma_jfr;
	int ret;

	if (udma_u_verify_jfr_param(ctx, cfg))
		return NULL;

	udma_jfr = (struct udma_u_jfr *)calloc(1, sizeof(*udma_jfr));
	if (!udma_jfr) {
		UDMA_LOG_ERR("alloc jfr failed.\n");
		return NULL;
	}

	udma_u_init_jfr_param(udma_jfr, cfg);

	if (!udma_jfr->lock_free &&
	    pthread_spin_init(&udma_jfr->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_spin_init;

	if (udma_u_alloc_jfr_idx_que(udma_jfr)) {
		UDMA_LOG_ERR("failed to create jfr idx que.\n");
		goto err_alloc_idx;
	}

	udma_jfr->rq.ctx = udma_ctx;
	if (udma_u_create_rq(udma_ctx, udma_jfr)) {
		UDMA_LOG_ERR("failed to create jfr rqe buf.\n");
		goto err_create_rq;
	}

	udma_jfr->sw_db = (uint32_t *)udma_u_alloc_sw_db(udma_ctx,
							 UDMA_JFR_TYPE_DB);
	if (!udma_jfr->sw_db)
		goto err_alloc_sw_db;

	udma_jfr->long_sleeptime = (bool *)udma_u_alloc_sw_db(udma_ctx, UDMA_JFR_PAYLOAD);
	if (!udma_jfr->long_sleeptime)
		goto err_alloc_jfr_sleep_buf;

	*udma_jfr->long_sleeptime = false;
	ret = exec_jfr_create_cmd(ctx, udma_jfr, cfg);
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
	udma_u_free_sw_db(udma_ctx, (uint32_t *)udma_jfr->long_sleeptime, UDMA_JFR_PAYLOAD);
err_alloc_jfr_sleep_buf:
	udma_u_free_sw_db(udma_ctx, udma_jfr->sw_db, UDMA_JFR_TYPE_DB);
err_alloc_sw_db:
	udma_u_free_queue_buf(&udma_jfr->rq);
err_create_rq:
	udma_u_free_idx_que(&udma_jfr->idx_que);
err_alloc_idx:
	if (!udma_jfr->lock_free)
		pthread_spin_destroy(&udma_jfr->lock);
err_spin_init:
	free(udma_jfr);
	return NULL;
}

static void udma_u_jfr_table_remove(struct udma_u_context *udma_ctx,
					     struct udma_u_jfr *jfr)
{
	uint32_t mask = (1 << udma_ctx->jettys_in_tbl_shift) - 1;
	uint32_t table_id = jfr->rq.idx >> udma_ctx->jettys_in_tbl_shift;

	(void)pthread_rwlock_wrlock(&udma_ctx->jfr_table_lock);
	if (udma_ctx->jfr_table[table_id].refcnt == 0) {
		(void)pthread_rwlock_unlock(&udma_ctx->jfr_table_lock);
		return;
	}
	if (!--udma_ctx->jfr_table[table_id].refcnt) {
		free(udma_ctx->jfr_table[table_id].jfr_array);
		udma_ctx->jfr_table[table_id].jfr_array = NULL;
	} else {
		udma_ctx->jfr_table[table_id].jfr_array[jfr->rq.idx & mask] = NULL;
	}
	(void)pthread_rwlock_unlock(&udma_ctx->jfr_table_lock);
}

static void udma_u_free_jfr(urma_jfr_t *jfr)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jfr->urma_ctx);
	struct udma_u_jfr *udma_jfr = to_udma_u_jfr(jfr);

	if (jfr->jfr_cfg.jfc)
		udma_u_clean_jfc(jfr->jfr_cfg.jfc, jfr->jfr_id.id);

	udma_u_free_sw_db(udma_ctx, (uint32_t *)udma_jfr->long_sleeptime, UDMA_JFR_PAYLOAD);

	if (!udma_jfr->swdb_cstm)
		udma_u_free_sw_db(udma_ctx, udma_jfr->sw_db, UDMA_JFR_TYPE_DB);

	udma_u_free_queue_buf(&udma_jfr->rq);

	udma_u_free_idx_que(&udma_jfr->idx_que);

	if (!udma_jfr->lock_free)
		(void)pthread_spin_destroy(&udma_jfr->lock);

	udma_u_jfr_table_remove(udma_ctx, udma_jfr);
	free(udma_jfr);
}

urma_status_t udma_u_delete_jfr(urma_jfr_t *jfr)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jfr->urma_ctx);
	struct udma_u_jfr *udma_jfr = to_udma_u_jfr(jfr);
	int ret;

	ret = urma_cmd_delete_jfr(jfr);
	if (ret) {
		UDMA_LOG_ERR("urma cmd delete jfr failed, ret = %d.\n", ret);
		goto delete_err;
	}

	udma_u_free_jfr(jfr);

	return URMA_SUCCESS;

delete_err:
	udma_u_jfr_table_remove(udma_ctx, udma_jfr);

	return URMA_FAIL;
}

urma_status_t udma_u_delete_jfr_batch(urma_jfr_t **jfr, int jfr_cnt, urma_jfr_t **bad_jfr)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfr *udma_jfr;
	int ret;
	int i;

	if (!jfr) {
		UDMA_LOG_ERR("jfr array is null.\n");
		return URMA_EINVAL;
	}

	if (!jfr_cnt) {
		UDMA_LOG_ERR("jfr cnt is 0.\n");
		return URMA_EINVAL;
	}

	ret = urma_cmd_delete_jfr_batch(jfr, jfr_cnt, bad_jfr);
	if (ret) {
		UDMA_LOG_ERR("urma cmd delete jfr failed, ret = %d.\n", ret);
		goto delete_err;
	}

	for (i = 0; i < jfr_cnt; i++)
		udma_u_free_jfr(jfr[i]);

	return URMA_SUCCESS;

delete_err:
	for (i = 0; i < jfr_cnt; i++) {
		udma_ctx = to_udma_u_ctx(jfr[i]->urma_ctx);
		udma_jfr = to_udma_u_jfr(jfr[i]);
		udma_u_jfr_table_remove(udma_ctx, udma_jfr);
	}

	return URMA_FAIL;
}

int udma_verify_modify_jfr(struct udma_u_jfr *jfr, uint32_t jfr_limit)
{
	if (jfr_limit > jfr->wqe_cnt) {
		UDMA_LOG_ERR("JFR limit(%u) larger than wqe num(%u).\n",
			     jfr_limit, jfr->wqe_cnt);
		return EINVAL;
	}

	return 0;
}

static void udma_reset_sw_u_jfr_queue(struct udma_u_jfr *udma_jfr)
{
	udma_u_init_bitmap(udma_jfr->idx_que.bitmap, udma_jfr->idx_que.bitmap_cnt);

	udma_jfr->rq.pi = 0;
	udma_jfr->rq.ci = 0;
	*udma_jfr->sw_db = 0;
}

urma_status_t udma_u_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr)
{
	struct udma_u_jfr *udma_jfr = to_udma_u_jfr(jfr);
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (!(attr->mask & (JFR_RX_THRESHOLD | JFR_STATE))) {
		UDMA_LOG_ERR("modify jfr mask is error or not set, jfr_id = %u.\n",
			     jfr->jfr_id.id);
		return URMA_EINVAL;
	}

	if (attr->mask & JFR_RX_THRESHOLD) {
		ret = udma_verify_modify_jfr(udma_jfr, attr->rx_threshold);
		if (ret) {
			UDMA_LOG_ERR("verify modify jfr failed.\n");
			return URMA_EINVAL;
		}
	}

	ret = urma_cmd_modify_jfr(jfr, attr, &udata);
	if (ret) {
		UDMA_LOG_ERR("urma cmd modify jfr failed.\n");
		return URMA_FAIL;
	}

	if ((attr->mask & JFR_STATE) && attr->state == URMA_JFR_STATE_READY)
		udma_reset_sw_u_jfr_queue(udma_jfr);

	return URMA_SUCCESS;
}

urma_status_t udma_u_unimport_jfr(urma_target_jetty_t *target_jfr)
{
	struct udma_u_target_jetty *tjfr = to_udma_u_target_jetty(target_jfr);

	if (urma_cmd_unimport_jfr(target_jfr)) {
		UDMA_LOG_ERR("unimport jfr failed.\n");
		return URMA_FAIL;
	}

	tjfr->token_value = 0;

	free(tjfr);

	return URMA_SUCCESS;
}

static void fill_wqe_idx(struct udma_u_jfr *jfr, uint32_t wqe_idx)
{
	uint32_t *idx_buf;
	uint32_t head;

	head = jfr->rq.pi & (jfr->wqe_cnt - 1);

	idx_buf = (uint32_t *)get_idx_buf(&jfr->idx_que, head);
	*idx_buf = htole32(wqe_idx);

	jfr->rq.pi++;
}

static void fill_recv_sge_to_wqe(urma_jfr_wr_t *wr, void *wqe, struct udma_u_jfr *jfr)
{
	struct udma_wqe_sge *sge = (struct udma_wqe_sge *)wqe;
	uint32_t total_len = 0;
	uint32_t i, cnt;

	for (i = 0, cnt = 0; i < wr->src.num_sge; i++) {
		if (!wr->src.sge[i].len)
			continue;
		total_len += wr->src.sge[i].len;
		set_data_of_sge(sge + cnt, wr->src.sge + i);
		cnt++;
	}

	if (total_len > UDMA_JFR_LARGE_PACKAGE)
		*jfr->long_sleeptime = true;

	if (cnt < jfr->max_sge)
		(void)memset(sge + cnt, 0, (jfr->max_sge - cnt) * UDMA_SGE_SIZE);
}

static urma_status_t post_recv_one(struct udma_u_jfr *jfr, urma_jfr_wr_t *wr)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;
	void *wqe;

	if (wr->src.num_sge > jfr->max_sge) {
		UDMA_LOG_ERR("failed to check sge, wr->num_sge = %u, max_sge = %u, jfrn = %u.\n",
			     wr->src.num_sge, jfr->max_sge, jfr->base.jfr_id.id);
		return URMA_EINVAL;
	}

	if (udma_jfrwq_overflow(jfr)) {
		UDMA_LOG_ERR("failed to check jfrwq status, jfrwq is full, jfrn = %u.\n",
			     jfr->base.jfr_id.id);
		return URMA_ENOMEM;
	}

	if (udma_bitmap_use_idx(jfr->idx_que.bitmap, jfr->idx_que.bitmap_cnt,
				jfr->wqe_cnt, &wqe_idx)) {
		UDMA_LOG_ERR("failed to get jfr wqe idx.\n");
		return URMA_ENOMEM;
	}
	wqe = get_jfr_wqe(jfr, wqe_idx);

	fill_recv_sge_to_wqe(wr, wqe, jfr);
	fill_wqe_idx(jfr, wqe_idx);

	jfr->rq.wrid[wqe_idx] = wr->user_ctx;

	return ret;
}

urma_status_t udma_u_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr,
				 urma_jfr_wr_t **bad_wr)
{
	struct udma_u_jfr *udma_jfr = to_udma_u_jfr(jfr);
	urma_status_t ret = URMA_SUCCESS;
	uint32_t nreq;

	if (!udma_jfr->lock_free)
		(void)pthread_spin_lock(&udma_jfr->lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		ret = post_recv_one(udma_jfr, wr);
		if (ret) {
			*bad_wr = wr;
			break;
		}
	}

	if (nreq) {
		udma_to_device_barrier();
		*udma_jfr->sw_db = udma_jfr->rq.pi & UDMA_JFR_DB_PROD_IDX_M;
	}

	if (!udma_jfr->lock_free)
		(void)pthread_spin_unlock(&udma_jfr->lock);

	return ret;
}

urma_status_t udma_u_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg,
			       urma_jfr_attr_t *attr)
{
	int ret;

	ret = urma_cmd_query_jfr(jfr, cfg, attr);
	if (ret) {
		UDMA_LOG_ERR("failed to query jfr in urma cmd, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

urma_target_jetty_t *udma_u_import_jfr_ex(urma_context_t *ctx,
					  urma_rjfr_t *rjfr,
					  urma_token_t *token_value,
					  urma_active_tp_cfg_t *active_tp_cfg)
{
	struct udma_u_target_jetty *tjfr;
	urma_tjfr_cfg_t cfg;

	tjfr = (struct udma_u_target_jetty *)calloc(1, sizeof(*tjfr));
	if (tjfr == NULL) {
		UDMA_LOG_ERR("target jfr alloc in exp failed.\n");
		return NULL;
	}

	cfg.token = token_value;
	cfg.jfr_id = rjfr->jfr_id;
	cfg.trans_mode = rjfr->trans_mode;
	cfg.tp_type = rjfr->tp_type;
	if (rjfr->flag.bs.token_policy != URMA_TOKEN_NONE) {
		tjfr->token_value = token_value->token;
		tjfr->token_value_valid = true;
	}

	if (urma_cmd_import_jfr_ex(ctx, &tjfr->urma_tjetty,
				   &cfg, (urma_import_jfr_ex_cfg_t *)active_tp_cfg, NULL) != 0) {
		UDMA_LOG_ERR("ubcore exp import jfr failed.\n");
		free(tjfr);
		return NULL;
	}

	udma_u_swap_endian128(rjfr->jfr_id.eid.raw, tjfr->le_eid.raw);

	return &tjfr->urma_tjetty;
}
