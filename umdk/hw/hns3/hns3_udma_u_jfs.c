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

#include <linux/kernel.h>
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfs.h"

urma_status_t verify_jfs_init_attr(urma_context_t *ctx,
				   const urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);

	if (!cfg->depth || cfg->depth > udma_ctx->max_jfs_wr ||
	    !cfg->max_sge || cfg->max_sge > udma_ctx->max_jfs_sge) {
		URMA_LOG_ERR("Invalid jfs cfg: sq depth: %u, sq max_sge: %u.\n",
			     cfg->depth, cfg->max_sge);
		return URMA_EINVAL;
	}

	return URMA_SUCCESS;
}

static int udma_jfs_init_connect_table(struct udma_u_jfs *jfs)
{
	int ret;

	(void)pthread_rwlock_init(&jfs->tjfr_tbl.rwlock, NULL);
	ret = udma_hmap_init(&jfs->tjfr_tbl.hmap, UDMA_SIZE_CONNECT_NODE_TABLE);
	if (ret)
		URMA_LOG_ERR("failed to init tjfr table.\n");

	return ret;
}

static urma_status_t alloc_qp_wqe_buf(struct udma_u_context *ctx, struct udma_qp *qp)
{
	int buf_size = to_udma_hem_entries_size(qp->sq.wqe_cnt, qp->sq.wqe_shift);

	qp->ex_sge.offset = buf_size;
	buf_size += to_udma_hem_entries_size(qp->ex_sge.sge_cnt,
					    qp->ex_sge.sge_shift);

	if (udma_alloc_buf(&qp->buf, buf_size, UDMA_HW_PAGE_SIZE)) {
		URMA_LOG_ERR("qp wqe buf alloc failed!\n");
		return URMA_ENOMEM;
	}

	return URMA_SUCCESS;
}

static void init_sq_param(struct udma_qp *qp, const urma_jfs_cfg_t *cfg)
{
	uint32_t max_inline_data;
	uint32_t total_sge_cnt;
	uint32_t ext_sge_cnt;
	uint32_t cfg_depth;
	int wqe_sge_cnt;
	uint32_t max_gs;

	cfg_depth = roundup_pow_of_two(cfg->depth);
	qp->sq.wqe_cnt = cfg_depth < UDMA_MIN_JFS_DEPTH ?
			 UDMA_MIN_JFS_DEPTH : cfg_depth;
	qp->sq.wqe_shift = UDMA_SQ_WQE_SHIFT;
	qp->sq.shift = udma_ilog32(qp->sq.wqe_cnt);

	max_inline_data = roundup_pow_of_two(cfg->max_inline_data);
	qp->max_inline_data = max_inline_data;
	ext_sge_cnt = max_inline_data / UDMA_HW_SGE_SIZE;
	max_gs = max(ext_sge_cnt, cfg->max_sge);
	qp->sq.max_gs = max_gs;

	if (cfg->trans_mode == URMA_TM_UM)
		wqe_sge_cnt = max_gs;
	else
		wqe_sge_cnt = max_gs - UDMA_SGE_IN_WQE;

	if (wqe_sge_cnt > 0) {
		total_sge_cnt = roundup_pow_of_two(qp->sq.wqe_cnt * wqe_sge_cnt);
		qp->sq.ext_sge_cnt = max(total_sge_cnt,
					 (uint32_t)UDMA_HW_PAGE_SIZE / UDMA_HW_SGE_SIZE);
	}

	qp->ex_sge.sge_shift = UDMA_HW_SGE_SHIFT;
	qp->ex_sge.sge_cnt = qp->sq.ext_sge_cnt;
}

static urma_status_t alloc_qp_wqe(struct udma_u_context *udma_ctx,
				  struct udma_qp *qp,
				  const urma_jfs_cfg_t *jfs_cfg)
{
	urma_status_t ret;

	init_sq_param(qp, jfs_cfg);

	qp->sq.wrid = (uintptr_t *)calloc(qp->sq.wqe_cnt, sizeof(uintptr_t));
	if (qp->sq.wrid == NULL) {
		URMA_LOG_ERR("failed to calloc sq wrid in jetty\n");
		return URMA_ENOMEM;
	}

	ret = alloc_qp_wqe_buf(udma_ctx, qp);
	if (ret) {
		URMA_LOG_ERR("alloc_jetty_wqe_buf failed.\n");
		free(qp->sq.wrid);
		qp->sq.wrid = NULL;
	}

	return ret;
}

struct udma_qp *udma_alloc_qp(struct udma_u_context *udma_ctx,
			      const urma_jfs_cfg_t *jfs_cfg,
			      uint32_t jetty_id, bool is_jetty)
{
	enum udma_db_type db_type;
	struct udma_qp *qp;
	int ret;

	qp = (struct udma_qp *)calloc(1, sizeof(struct udma_qp));
	if (!qp) {
		URMA_LOG_ERR("alloc qp failed.\n");
		return NULL;
	}

	db_type = is_jetty ? UDMA_JETTY_TYPE_DB : UDMA_JFS_TYPE_DB;
	qp->sdb = (uint32_t *)udma_alloc_sw_db(udma_ctx, db_type);
	if (!qp->sdb) {
		URMA_LOG_ERR("alloc sw db failed.\n");
		goto err_alloc_qp;
	}

	ret = alloc_qp_wqe(udma_ctx, qp, jfs_cfg);
	if (ret) {
		URMA_LOG_ERR("alloc_qp_wqe failed.\n");
		goto err_alloc_sw_db;
	}
	qp->jetty_id = jetty_id;

	return qp;

err_alloc_sw_db:
	udma_free_sw_db(udma_ctx, qp->sdb, UDMA_JETTY_TYPE_DB);
err_alloc_qp:
	free(qp);

	return NULL;
}

static int alloc_table_qp(struct udma_u_jfs *jfs, urma_context_t *ctx,
			  const urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx;
	int ret;

	ret = verify_jfs_init_attr(ctx, cfg);
	if (ret)
		return ret;

	udma_ctx = to_udma_ctx(ctx);

	if (jfs->tp_mode == URMA_TM_RM) {
		ret = udma_jfs_init_connect_table(jfs);
		if (ret) {
			URMA_LOG_ERR("init connect table failed.\n");
			return ENOMEM;
		}
	}  else if (jfs->tp_mode == URMA_TM_UM) {
		jfs->um_qp = udma_alloc_qp(udma_ctx, cfg, jfs->jfs_id, false);
		if (!jfs->um_qp) {
			URMA_LOG_ERR("alloc qp failed.\n");
			return ENOMEM;
		}
	} else {
		URMA_LOG_ERR("do not support this tp_mode.\n");
		return ENOMEM;
	}

	return ret;
}

static urma_status_t udma_add_to_qp_table(struct udma_u_context *ctx,
					  urma_jfs_t *jfs, struct udma_qp *qp,
					  uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;

	if (ctx == NULL || qp == NULL) {
		URMA_LOG_ERR("ctx or qp is NULL.\n");
		return URMA_EINVAL;
	}

	qp_node = (struct udma_jfs_qp_node *)calloc(1, sizeof(*qp_node));
	if (qp_node == NULL) {
		URMA_LOG_ERR("failed to calloc qp_node.\n");
		return URMA_ENOMEM;
	}
	qp_node->jfs_qp = qp;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	if (!udma_hmap_insert(&ctx->jfs_qp_table, &qp_node->node, qpn)) {
		free(qp_node);
		qp_node = NULL;
		URMA_LOG_ERR("failed to insert qp_node into jfs qp table.\n");
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		return URMA_EINVAL;
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);

	return URMA_SUCCESS;
}

static void udma_remove_from_qp_table(struct udma_u_context *ctx, uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;
	struct udma_hmap_node *node;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	node = udma_hmap_first_with_hash(&ctx->jfs_qp_table, qpn);
	if (node) {
		qp_node = to_udma_jfs_qp_node(node);
		udma_hmap_remove(&ctx->jfs_qp_table, node);
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		free(qp_node);
		return;
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
}

static int exec_jfs_create_cmd(urma_context_t *ctx, struct udma_u_jfs *jfs,
			       const urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_create_jfs_resp resp = {};
	struct udma_create_jfs_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (jfs->tp_mode == URMA_TM_UM) {
		cmd.create_tp_ucmd.buf_addr = (uintptr_t)jfs->um_qp->buf.buf;
		cmd.create_tp_ucmd.sdb_addr = (uintptr_t)jfs->um_qp->sdb;
	}

	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfs(ctx, &jfs->base, cfg, &udata);
	if (ret) {
		URMA_LOG_ERR("urma cmd create jfs failed.\n");
		return ret;
	}

	jfs->jfs_id = jfs->base.jfs_id.id;

	if (jfs->tp_mode == URMA_TM_UM) {
		jfs->um_qp->qp_num = resp.create_tp_resp.qpn;
		jfs->um_qp->path_mtu = (urma_mtu_t)resp.create_tp_resp.path_mtu;
		jfs->um_qp->sq.priority = resp.create_tp_resp.priority;
		memcpy(&jfs->um_qp->um_srcport, &resp.create_tp_resp.um_srcport,
		       sizeof(struct udp_srcport));
		ret = udma_add_to_qp_table(udma_ctx, &jfs->base, jfs->um_qp,
					   jfs->um_qp->qp_num);
		if (ret)
			URMA_LOG_ERR("add to qp table failed for um jfs, ret = %d.\n", ret);
	}

	return ret;
}

static void udma_jfs_free_table(struct udma_u_jfs *jfs)
{
	struct connect_node *cur, *next;

	(void)pthread_rwlock_rdlock(&jfs->tjfr_tbl.rwlock);
	HMAP_FOR_EACH_SAFE(cur, next, hmap_node, &jfs->tjfr_tbl.hmap) {
		(void)pthread_rwlock_unlock(&jfs->tjfr_tbl.rwlock);
		udma_u_unadvise_jfr(&jfs->base, cur->tjfr, false);
		(void)pthread_rwlock_rdlock(&jfs->tjfr_tbl.rwlock);
	}
	(void)pthread_rwlock_unlock(&jfs->tjfr_tbl.rwlock);
	udma_hmap_destroy(&jfs->tjfr_tbl.hmap);
}

static void um_free_qp(struct udma_u_jfs *jfs)
{
	struct udma_u_context *udma_ctx;

	if (jfs->um_qp) {
		udma_ctx = to_udma_ctx(jfs->base.urma_ctx);
		udma_free_sw_db(udma_ctx, jfs->um_qp->sdb, UDMA_JFS_TYPE_DB);
		free(jfs->um_qp->sq.wrid);
		jfs->um_qp->sq.wrid = NULL;
		udma_free_buf(&jfs->um_qp->buf);
		free(jfs->um_qp);
		jfs->um_qp = NULL;
	}
}

static void delete_qp_node_table(struct udma_u_jfs *jfs)
{
	if (jfs->tp_mode == URMA_TM_RM)
		udma_jfs_free_table(jfs);
	else if (jfs->tp_mode == URMA_TM_UM)
		um_free_qp(jfs);
}

urma_jfs_t *udma_u_create_jfs(urma_context_t *ctx, const urma_jfs_cfg_t *cfg)
{
	struct udma_u_jfs *jfs;
	int ret;

	if (ctx == NULL) {
		URMA_LOG_ERR("Invalid parameter.\n");
		return NULL;
	}

	jfs = (struct udma_u_jfs *)calloc(1, sizeof(*jfs));
	if (jfs == NULL) {
		URMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}

	jfs->tp_mode = cfg->trans_mode;
	jfs->base.urma_ctx = ctx;
	jfs->base.jfs_id.eid = ctx->eid;
	jfs->base.jfs_id.uasid = ctx->uasid;
	jfs->base.jfs_cfg = *cfg;
	jfs->lock_free = cfg->flag.bs.lock_free;

	ret = alloc_table_qp(jfs, ctx, cfg);
	if (ret)
		goto error_alloc_table_qp;

	ret = exec_jfs_create_cmd(ctx, jfs, cfg);
	if (ret) {
		URMA_LOG_ERR("failed to create jfs, mode = %d, ret = %d\n",
			     jfs->tp_mode, ret);
		goto error_create_jfs;
	}

	if (pthread_spin_init(&jfs->lock, PTHREAD_PROCESS_PRIVATE))
		goto error_init_lock;

	return &(jfs->base);

error_init_lock:
	urma_cmd_delete_jfs(&jfs->base);
error_create_jfs:
	delete_qp_node_table(jfs);
error_alloc_table_qp:
	free(jfs);

	return NULL;
}

urma_status_t udma_u_delete_jfs(urma_jfs_t *jfs)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	int ret;

	if (jfs == NULL || jfs->urma_ctx == NULL) {
		URMA_LOG_ERR("Invalid parameter.\n");
		return URMA_EINVAL;
	}

	udma_jfs = to_udma_jfs(jfs);
	udma_ctx = to_udma_ctx(jfs->urma_ctx);

	if (udma_jfs->tp_mode == URMA_TM_UM)
		udma_remove_from_qp_table(udma_ctx, udma_jfs->um_qp->qp_num);

	delete_qp_node_table(udma_jfs);

	ret = urma_cmd_delete_jfs(jfs);
	if (ret) {
		URMA_LOG_ERR("jfs delete failed!\n");
		return URMA_FAIL;
	}

	pthread_spin_destroy(&udma_jfs->lock);

	free(udma_jfs);
	return URMA_SUCCESS;
}
