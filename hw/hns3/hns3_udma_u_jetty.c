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

#include "urma_types.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jetty.h"

urma_status_t verify_jfs_init_attr(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);

	if (!cfg->depth || cfg->depth > udma_ctx->max_jfs_wr ||
	    cfg->max_sge > udma_ctx->max_jfs_sge) {
		UDMA_LOG_ERR("Invalid jfs cfg: sq depth: %u, max_jfs_wr:%u, sq max_sge: %u, udma_ctx->max_jfs_sge: %u.\n",
			     cfg->depth, udma_ctx->max_jfs_wr, cfg->max_sge, udma_ctx->max_jfs_sge);
		return URMA_EINVAL;
	}

	return URMA_SUCCESS;
}

static urma_status_t alloc_jfr(struct udma_u_jetty *jetty, urma_context_t *ctx,
			       urma_jetty_cfg_t *jetty_cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	urma_jfr_t *urma_jfr;

	if (jetty->share_jfr) {
		jetty->udma_jfr = to_udma_jfr(jetty_cfg->shared.jfr);
	} else {
		if (!udma_ctx->dca_ctx.unit_size)
			urma_jfr = udma_u_create_jfr_rq(ctx, jetty_cfg->jfr_cfg, jetty);
		else
			urma_jfr = udma_u_create_jfr(ctx, jetty_cfg->jfr_cfg);
		if (!urma_jfr) {
			UDMA_LOG_ERR("failed to create jfr.\n");
			return URMA_FAIL;
		}
		jetty->udma_jfr = to_udma_jfr(urma_jfr);
	}

	return URMA_SUCCESS;
}

static urma_status_t alloc_qp_node_table(struct udma_u_jetty *jetty,
					 struct udma_u_context *udma_ctx,
					 urma_jetty_cfg_t *jetty_cfg)
{
	urma_status_t ret;

	ret = verify_jfs_init_attr(&udma_ctx->urma_ctx, &jetty_cfg->jfs_cfg);
	if (ret)
		return ret;

	if (jetty->tp_mode == URMA_TM_UM) {
		if (jetty->udma_jfr == NULL)
			jetty->um_qp = udma_alloc_qp(udma_ctx, true,
						     &jetty_cfg->jfs_cfg,
						     jetty_cfg->jfr_cfg);
		else
			jetty->um_qp = udma_alloc_qp(udma_ctx, true,
						     &jetty_cfg->jfs_cfg, NULL);
		if (!jetty->um_qp) {
			UDMA_LOG_ERR("UM qp alloc failed, jetty_id = %u.\n",
				     jetty->urma_jetty.jetty_id.id);
			return URMA_ENOMEM;
		}
	} else {
		jetty->rc_node = (struct rc_node *)calloc(1, sizeof(struct rc_node));
		if (!jetty->rc_node) {
			UDMA_LOG_ERR("RC node alloc failed, jetty_id = %u.\n",
				     jetty->urma_jetty.jetty_id.id);
			return URMA_ENOMEM;
		}

		if (jetty->udma_jfr == NULL)
			jetty->rc_node->qp = udma_alloc_qp(udma_ctx, true,
							   &jetty_cfg->jfs_cfg,
							   jetty_cfg->jfr_cfg);
		else
			jetty->rc_node->qp = udma_alloc_qp(udma_ctx, true,
							   &jetty_cfg->jfs_cfg, NULL);
		if (!jetty->rc_node->qp) {
			UDMA_LOG_ERR("alloc rc_node failed.\n");
			goto err_alloc_rc_node_qp;
		}
	}

	return URMA_SUCCESS;
err_alloc_rc_node_qp:
	free(jetty->rc_node);
	jetty->rc_node = NULL;

	return URMA_ENOMEM;
}

urma_status_t udma_add_to_qp_table(struct udma_u_context *ctx, struct udma_qp *qp,
				   uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;

	qp_node = (struct udma_jfs_qp_node *)calloc(1, sizeof(*qp_node));
	if (qp_node == NULL) {
		UDMA_LOG_ERR("failed to calloc qp_node.\n");
		return URMA_ENOMEM;
	}
	qp_node->jfs_qp = qp;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	if (!udma_hmap_insert(&ctx->jfs_qp_table, &qp_node->node, qpn)) {
		UDMA_LOG_ERR("failed insert qp_node into jfs_qp_table.\n");
		free(qp_node);
		qp_node = NULL;
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		return URMA_EINVAL;
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
	return URMA_SUCCESS;
}

void udma_remove_from_qp_table(struct udma_u_context *ctx, uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;
	struct udma_hmap_node *node;

	node = udma_table_first_with_hash(&ctx->jfs_qp_table,
					  &ctx->jfs_qp_table_lock, qpn);
	if (node) {
		qp_node = to_udma_jfs_qp_node(node);
		(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
		udma_hmap_remove(&ctx->jfs_qp_table, node);
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		free(qp_node);
		return;
	}
	UDMA_LOG_ERR("failed to find jetty qp.\n");
}

static urma_status_t init_jetty_qp(urma_context_t *ctx,
				   struct udma_u_jetty *jetty,
				   struct hns3_udma_create_jetty_resp resp)
{
	urma_status_t ret = URMA_SUCCESS;
	struct udma_qp *qp = NULL;

	if (jetty->tp_mode == URMA_TM_UM) {
		qp = jetty->um_qp;
		fill_um_jetty_qp(qp, resp);
		qp->jetty_id = jetty->urma_jetty.jetty_id.id;
	}
	if (jetty->tp_mode == URMA_TM_RC) {
		jetty->rc_node->qp->jetty_id = jetty->urma_jetty.jetty_id.id;
		if (jetty->sub_trans_mode == URMA_SUB_TRANS_MODE_USER_TP) {
			qp = jetty->rc_node->qp;
			fill_rc_jetty_qp(qp, resp);
		}
	}

	if ((qp != NULL) && (qp->flags & HNS3_UDMA_QP_CAP_DIRECT_WQE)) {
		ret = mmap_dwqe(ctx, qp);
		if (ret)
			UDMA_LOG_ERR("mmap dwqe failed\n");
	}

	return ret;
}

static urma_status_t exec_jetty_create_cmd(urma_context_t *ctx,
					   struct udma_u_jetty *jetty,
					   urma_jetty_cfg_t *cfg)
{
	struct hns3_udma_create_jetty_resp resp = {};
	struct hns3_udma_create_jetty_ucmd cmd = {};
	urma_status_t ret = URMA_SUCCESS;
	urma_cmd_udrv_priv_t udata = {};

	if (!jetty->share_jfr) {
		cmd.jfr_id = jetty->udma_jfr->jfrn;
		cmd.srqn = jetty->udma_jfr->srqn;
	}

	if (jetty->tp_mode == URMA_TM_UM) {
		cmd.create_tp_ucmd.buf_addr = (uint64_t)jetty->um_qp->buf.buf;
		cmd.create_tp_ucmd.sdb_addr = (uint64_t)jetty->um_qp->sdb;
	} else {
		cmd.buf_addr = (uint64_t)jetty->rc_node->qp->buf.buf;
		cmd.sdb_addr = (uint64_t)jetty->rc_node->qp->sdb;
	}

	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (urma_cmd_create_jetty(ctx, &jetty->urma_jetty, cfg, &udata)) {
		UDMA_LOG_ERR("urma cmd create jetty failed.\n");
		return URMA_ENOMEM;
	}

	ret = init_jetty_qp(ctx, jetty, resp);
	if (ret)
		urma_cmd_delete_jetty(&jetty->urma_jetty);

	return ret;
}

static void rc_free_node(struct udma_u_context *udma_ctx, struct udma_u_jetty *udma_jetty)
{
	struct udma_qp *qp = udma_jetty->rc_node->qp;

	if (udma_jetty->rc_node->tjetty)
		udma_u_unbind_jetty(&udma_jetty->urma_jetty);

	udma_free_sw_db(udma_ctx, qp->sdb, UDMA_JETTY_TYPE_DB);

	if (qp->dca_wqe.bufs)
		free(qp->dca_wqe.bufs);
	else
		udma_free_buf(&qp->buf);

	free(qp->sq.wrid);
	free(qp);
	free(udma_jetty->rc_node);
}

static void um_free_qp(struct udma_u_jetty *udma_jetty)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(udma_jetty->urma_jetty.urma_ctx);

	udma_free_sw_db(udma_ctx, udma_jetty->um_qp->sdb, UDMA_JETTY_TYPE_DB);
	udma_free_buf(&udma_jetty->um_qp->buf);
	free(udma_jetty->um_qp->sq.wrid);
	free(udma_jetty->um_qp);
}

static void delete_jetty_qp_node(struct udma_u_context *udma_ctx,
				 struct udma_u_jetty *udma_jetty)
{
	if (udma_jetty->tp_mode == URMA_TM_UM)
		um_free_qp(udma_jetty);
	else
		rc_free_node(udma_ctx, udma_jetty);
}

void delete_jetty_node(struct udma_u_context *udma_ctx, uint32_t id)
{
	uint32_t mask = (1 << udma_ctx->jettys_in_tbl_shift) - 1;
	uint32_t table_id;

	table_id = id >> udma_ctx->jettys_in_tbl_shift;
	pthread_rwlock_wrlock(&udma_ctx->jetty_table_lock);
	if (!--udma_ctx->jetty_table[table_id].refcnt)
		free(udma_ctx->jetty_table[table_id].table);
	else
		udma_ctx->jetty_table[table_id].table[id & mask].jetty = NULL;
	pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
}

urma_status_t insert_jetty_node(struct udma_u_context *udma_ctx,
				void *pointer, bool is_jetty, uint32_t id)
{
	uint32_t jettys_in_tbl = 1 << udma_ctx->jettys_in_tbl_shift;
	uint32_t mask = jettys_in_tbl - 1;
	struct common_jetty *jetty_table;
	uint32_t table_id;

	table_id = id >> udma_ctx->jettys_in_tbl_shift;
	pthread_rwlock_wrlock(&udma_ctx->jetty_table_lock);
	if (!udma_ctx->jetty_table[table_id].refcnt) {
		udma_ctx->jetty_table[table_id].table = (struct common_jetty *)calloc(jettys_in_tbl,
							sizeof(struct common_jetty));
		if (!udma_ctx->jetty_table[table_id].table) {
			pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
			return URMA_ENOMEM;
		}
	}

	jetty_table = udma_ctx->jetty_table[table_id].table;
	++udma_ctx->jetty_table[table_id].refcnt;
	jetty_table[id & mask].is_jetty = is_jetty;
	jetty_table[id & mask].jetty = pointer;
	pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);

	return URMA_SUCCESS;
}

urma_status_t verify_jetty_trans_mode(urma_jetty_cfg_t *jetty_cfg)
{
	urma_transport_mode_t jfs_trans_mode = jetty_cfg->jfs_cfg.trans_mode;
	urma_transport_mode_t jfr_trans_mode;

	if (jetty_cfg->flag.bs.share_jfr)
		jfr_trans_mode = jetty_cfg->shared.jfr->jfr_cfg.trans_mode;
	else
		jfr_trans_mode = jetty_cfg->jfr_cfg->trans_mode;

	if (jfs_trans_mode != jfr_trans_mode) {
		UDMA_LOG_ERR("jfs_trans_mode: %u is different from jfr_trans_mode: %u.\n",
			     jfs_trans_mode, jfr_trans_mode);
		return URMA_EINVAL;
	}

	if (jfs_trans_mode != URMA_TM_UM && jfs_trans_mode != URMA_TM_RC) {
		UDMA_LOG_ERR("The jetty trans_mode(%d) is not supported.\n", jfs_trans_mode);
		return URMA_EINVAL;
	}

	return URMA_SUCCESS;
}

static inline void init_jetty_param(struct udma_u_jetty *udma_jetty,
				    urma_jetty_cfg_t *jetty_cfg)
{
	udma_jetty->tp_mode = jetty_cfg->jfs_cfg.trans_mode;
	udma_jetty->share_jfr = jetty_cfg->flag.bs.share_jfr;
	udma_jetty->jfs_lock_free = jetty_cfg->jfs_cfg.flag.bs.lock_free;
	udma_jetty->urma_jetty.jetty_cfg = *jetty_cfg;
	udma_jetty->sub_trans_mode = jetty_cfg->jfs_cfg.flag.bs.sub_trans_mode;
}

static int exec_jetty_delete_cmd(struct udma_u_context *ctx, struct udma_u_jetty *jetty)
{
	struct udma_qp *qp = NULL;

	if (jetty->tp_mode == URMA_TM_UM)
		qp = jetty->um_qp;
	if (jetty->tp_mode == URMA_TM_RC &&
	    jetty->sub_trans_mode == URMA_SUB_TRANS_MODE_USER_TP)
		qp = jetty->rc_node->qp;
	if ((qp != NULL) && (qp->flags & HNS3_UDMA_QP_CAP_DIRECT_WQE))
		munmap_dwqe(jetty->um_qp);

	return urma_cmd_delete_jetty(&jetty->urma_jetty);
}

static urma_jetty_t *udma_u_create_jetty_rq(urma_context_t *ctx,
					    urma_jetty_cfg_t *jetty_cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_u_jetty *udma_jetty;
	urma_status_t ret;

	udma_jetty = (struct udma_u_jetty *)calloc(1, sizeof(*udma_jetty));
	if (!udma_jetty) {
		UDMA_LOG_ERR("failed to alloc jetty.\n");
		return NULL;
	}

	ret = verify_jetty_trans_mode(jetty_cfg);
	if (ret) {
		UDMA_LOG_ERR("failed verify jetty trans mode.\n");
		goto err_alloc_jetty;
	}

	init_jetty_param(udma_jetty, jetty_cfg);

	ret = alloc_qp_node_table(udma_jetty, udma_ctx, jetty_cfg);
	if (ret)
		goto err_alloc_jetty;

	ret = alloc_jfr(udma_jetty, ctx, jetty_cfg);
	if (ret)
		goto err_alloc_qp_node_table;

	ret = exec_jetty_create_cmd(ctx, udma_jetty, jetty_cfg);
	if (ret) {
		UDMA_LOG_ERR("exec jetty create cmd failed.\n");
		goto err_exec_jetty_create_cmd;
	}

	if (pthread_spin_init(&udma_jetty->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_init_lock;

	ret = insert_jetty_node(udma_ctx, udma_jetty, true,
				udma_jetty->urma_jetty.jetty_id.id);
	if (ret) {
		UDMA_LOG_ERR("insert jetty node failed.\n");
		goto err_insert_jetty_node;
	}

	return &udma_jetty->urma_jetty;

err_insert_jetty_node:
	(void)pthread_spin_destroy(&udma_jetty->lock);
err_init_lock:
	(void)exec_jetty_delete_cmd(udma_ctx, udma_jetty);
err_exec_jetty_create_cmd:
	if (!udma_jetty->share_jfr)
		udma_u_delete_jfr(&udma_jetty->udma_jfr->urma_jfr);
err_alloc_qp_node_table:
	delete_jetty_qp_node(udma_ctx, udma_jetty);
err_alloc_jetty:
	free(udma_jetty);

	return NULL;
}

urma_jetty_t *udma_u_create_jetty(urma_context_t *ctx,
				  urma_jetty_cfg_t *jetty_cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_u_jetty *udma_jetty;
	urma_status_t ret;

	if (!jetty_cfg->flag.bs.share_jfr && udma_ctx->dca_ctx.unit_size == 0)
		return udma_u_create_jetty_rq(ctx, jetty_cfg);

	udma_jetty = (struct udma_u_jetty *)calloc(1, sizeof(*udma_jetty));
	if (!udma_jetty) {
		UDMA_LOG_ERR("failed to alloc jetty.\n");
		return NULL;
	}

	ret = verify_jetty_trans_mode(jetty_cfg);
	if (ret) {
		UDMA_LOG_ERR("failed verify jetty trans mode.\n");
		goto err_alloc_jetty;
	}

	init_jetty_param(udma_jetty, jetty_cfg);

	ret = alloc_jfr(udma_jetty, ctx, jetty_cfg);
	if (ret)
		goto err_alloc_jetty;

	ret = alloc_qp_node_table(udma_jetty, udma_ctx, jetty_cfg);
	if (ret)
		goto err_alloc_qp_node_table;

	ret = exec_jetty_create_cmd(ctx, udma_jetty, jetty_cfg);
	if (ret) {
		UDMA_LOG_ERR("exec jetty create cmd failed.\n");
		goto err_exec_jetty_create_cmd;
	}

	if (pthread_spin_init(&udma_jetty->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_init_lock;

	ret = insert_jetty_node(udma_ctx, udma_jetty, true,
				udma_jetty->urma_jetty.jetty_id.id);
	if (ret) {
		UDMA_LOG_ERR("insert jetty node failed.\n");
		goto err_insert_jetty_node;
	}

	return &udma_jetty->urma_jetty;

err_insert_jetty_node:
	(void)pthread_spin_destroy(&udma_jetty->lock);
err_init_lock:
	(void)exec_jetty_delete_cmd(udma_ctx, udma_jetty);
err_exec_jetty_create_cmd:
	delete_jetty_qp_node(udma_ctx, udma_jetty);
err_alloc_qp_node_table:
	if (!udma_jetty->share_jfr)
		udma_u_delete_jfr(&udma_jetty->udma_jfr->urma_jfr);
err_alloc_jetty:
	free(udma_jetty);

	return NULL;
}

urma_status_t udma_u_delete_jetty(urma_jetty_t *jetty)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret;

	ret = exec_jetty_delete_cmd(udma_ctx, udma_jetty);
	if (ret) {
		UDMA_LOG_ERR("urma_cmd_delete_jetty failed, ret:%d.\n", ret);
		return URMA_FAIL;
	}

	delete_jetty_node(udma_ctx, udma_jetty->urma_jetty.jetty_id.id);
	(void)pthread_spin_destroy(&udma_jetty->lock);

	if (!udma_jetty->share_jfr) {
		udma_u_delete_jfr(&udma_jetty->udma_jfr->urma_jfr);
		udma_jetty->udma_jfr = NULL;
	}

	delete_jetty_qp_node(udma_ctx, udma_jetty);

	free(udma_jetty);

	return URMA_SUCCESS;
}

urma_target_jetty_t *udma_u_import_jetty(urma_context_t *ctx,
					 urma_rjetty_t *rjetty,
					 urma_token_t *rjetty_token)
{
	struct udma_u_target_jetty *udma_target_jetty;
	urma_cmd_udrv_priv_t udata = {};
	urma_target_jetty_t *tjetty;
	urma_tjetty_cfg_t cfg = {};
	int ret;

	udma_target_jetty = (struct udma_u_target_jetty *)
			    calloc(1, sizeof(struct udma_u_target_jetty));
	if (!udma_target_jetty) {
		UDMA_LOG_ERR("target jetty alloc failed.\n");
		return NULL;
	}

	tjetty = &udma_target_jetty->urma_target_jetty;
	tjetty->urma_ctx = ctx;
	tjetty->id = rjetty->jetty_id;
	tjetty->trans_mode = rjetty->trans_mode;
	tjetty->flag = rjetty->flag;
	if (tjetty->flag.bs.sub_trans_mode != URMA_SUB_TRANS_MODE_USER_TP) {
		cfg.jetty_id = rjetty->jetty_id;
		cfg.token = rjetty_token;
		cfg.trans_mode = rjetty->trans_mode;
		udma_set_udata(&udata, NULL, 0, NULL, 0);
		ret = urma_cmd_import_jetty(ctx, tjetty, &cfg, &udata);
		if (ret) {
			UDMA_LOG_ERR("import jetty failed, ret = %d.\n", ret);
			free(udma_target_jetty);
			return NULL;
		}
	}

	atomic_init(&udma_target_jetty->refcnt, 1);

	return tjetty;
}

urma_status_t udma_u_unimport_jetty(urma_target_jetty_t *target_jetty)
{
	struct udma_u_target_jetty *udma_target_jetty = to_udma_target_jetty(target_jetty);
	int ret;

	if (udma_target_jetty->refcnt > 1) {
		UDMA_LOG_ERR("the target jetty is still being used, id = %u.\n",
			     target_jetty->id.id);
		return URMA_FAIL;
	}

	if (target_jetty->flag.bs.sub_trans_mode != URMA_SUB_TRANS_MODE_USER_TP) {
		ret = urma_cmd_unimport_jetty(target_jetty);
		if (ret) {
			UDMA_LOG_ERR("unimport jetty failed, ret = %d.\n", ret);
			return URMA_FAIL;
		}
	}
	free(udma_target_jetty);

	return URMA_SUCCESS;
}

static urma_status_t verify_jetty_bind(struct udma_u_jetty *udma_jetty)
{
	if (udma_jetty->tp_mode != URMA_TM_RC) {
		UDMA_LOG_ERR("Invalid jetty type.\n");
		return URMA_EINVAL;
	}

	if (udma_jetty->rc_node == NULL) {
		UDMA_LOG_ERR("RC node is invalid.\n");
		return URMA_EINVAL;
	}

	if (udma_jetty->rc_node->qp == NULL) {
		UDMA_LOG_ERR("RC node qp is null.\n");
		return URMA_EINVAL;
	}

	return URMA_SUCCESS;
}

static urma_status_t exec_jetty_bind_cmd(urma_jetty_t *jetty,
					 urma_target_jetty_t *tjetty,
					 struct udma_qp *qp)
{
	struct hns3_udma_create_tp_resp resp = {};
	struct hns3_udma_create_tp_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	cmd.is_jetty = true;
	cmd.ini_id.jetty_id = jetty->jetty_id.id;
	cmd.tgt_id.jetty_id = tjetty->id.id;
	cmd.buf_addr = (uint64_t)qp->buf.buf;

	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_bind_jetty(jetty, tjetty, &udata);
	if (ret) {
		UDMA_LOG_ERR("urma cmd bind jetty failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	qp->qp_num = resp.qpn;
	qp->flags = resp.cap_flags;
	qp->path_mtu = (urma_mtu_t)resp.path_mtu;
	qp->sq.priority = resp.priority;

	if (resp.cap_flags & HNS3_UDMA_QP_CAP_DIRECT_WQE) {
		ret = mmap_dwqe(jetty->urma_ctx, qp);
		if (ret) {
			urma_cmd_unbind_jetty(jetty);
			UDMA_LOG_ERR("mmap dwqe failed\n");
			return URMA_FAIL;
		}
	}

	return URMA_SUCCESS;
}

urma_status_t udma_u_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty)
{
	struct udma_u_target_jetty *udma_target_jetty = to_udma_target_jetty(tjetty);
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret;

	ret = verify_jetty_bind(udma_jetty);
	if (ret) {
		UDMA_LOG_ERR("Invalid input parameters of bind_jetty.\n");
		return URMA_EINVAL;
	}

	if (udma_jetty->rc_node->tjetty == tjetty) {
		UDMA_LOG_INFO("reentry bind jetty, jetty_id = %u, tjetty_id = %u.\n",
			      jetty->jetty_id.id, tjetty->id.id);
		return URMA_SUCCESS;
	}

	if (udma_jetty->rc_node->tjetty != NULL) {
		UDMA_LOG_ERR("The jetty has already bind a remote jetty.\n");
		return URMA_EEXIST;
	}

	if (udma_jetty->sub_trans_mode != tjetty->flag.bs.sub_trans_mode) {
		UDMA_LOG_ERR("The sub_trans_mode does not match.\n");
		return URMA_EINVAL;
	}

	if (tjetty->flag.bs.sub_trans_mode != URMA_SUB_TRANS_MODE_USER_TP) {
		ret = exec_jetty_bind_cmd(jetty, tjetty, udma_jetty->rc_node->qp);
		if (ret) {
			UDMA_LOG_ERR("exec jetty bind cmd failed.\n");
			return URMA_FAIL;
		}
	}

	udma_jetty->rc_node->tjetty = tjetty;
	jetty->remote_jetty = (urma_target_jetty_t *)tjetty;
	(void)atomic_fetch_add(&udma_target_jetty->refcnt, 1);
	return URMA_SUCCESS;
}

urma_status_t udma_u_unbind_jetty(urma_jetty_t *jetty)
{
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	struct udma_u_target_jetty *udma_target_jetty;
	urma_target_jetty_t *tjetty;
	int ret;

	ret = verify_jetty_bind(udma_jetty);
	if (ret) {
		UDMA_LOG_ERR("Invalid input parameters of unbind_jetty.\n");
		return URMA_EINVAL;
	}

	tjetty = udma_jetty->rc_node->tjetty;
	if (tjetty == NULL) {
		UDMA_LOG_ERR("The jetty has not bind a remote jetty.\n");
		return URMA_FAIL;
	}

	if (tjetty->flag.bs.sub_trans_mode != URMA_SUB_TRANS_MODE_USER_TP) {
		if (udma_jetty->rc_node->qp->flags & HNS3_UDMA_QP_CAP_DIRECT_WQE)
			munmap_dwqe(udma_jetty->rc_node->qp);
		ret = urma_cmd_unbind_jetty(jetty);
		if (ret) {
			UDMA_LOG_ERR("urma_cmd_unbind_jetty failed.\n");
			return URMA_FAIL;
		}
	}

	udma_target_jetty = to_udma_target_jetty(tjetty);
	(void)atomic_fetch_sub(&udma_target_jetty->refcnt, 1);
	jetty->remote_jetty = NULL;
	udma_jetty->rc_node->tjetty = NULL;

	return URMA_SUCCESS;
}

static struct udma_qp *get_qp_for_tjetty(struct udma_u_jetty *udma_jetty,
					 urma_target_jetty_t *tjetty)
{
	struct udma_qp *udma_qp = NULL;

	if (udma_jetty->rc_node->tjetty == NULL) {
		UDMA_LOG_ERR("The jetty not bind a remote jetty, jetty_id = %u.\n",
			     udma_jetty->urma_jetty.jetty_id.id);
		return NULL;
	}

	udma_qp = udma_jetty->rc_node->qp;

	return udma_qp;
}

/* get qp related to target jetty when post send */
struct udma_qp *get_qp_of_jetty(struct udma_u_jetty *udma_jetty,
				urma_jfs_wr_t *wr)
{
	struct udma_qp *udma_qp = NULL;

	if (udma_jetty->tp_mode != URMA_TM_RC && !wr->tjetty) {
		UDMA_LOG_ERR("Failed to get jetty qp, tjetty of wr is null.\n");
		return NULL;
	}

	if (udma_jetty->tp_mode == URMA_TM_UM)
		return udma_jetty->um_qp;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
	case URMA_OPC_SEND_IMM:
	case URMA_OPC_SEND_INVALIDATE:
	case URMA_OPC_WRITE:
	case URMA_OPC_WRITE_IMM:
	case URMA_OPC_WRITE_NOTIFY:
		udma_qp = get_qp_for_tjetty(udma_jetty, wr->tjetty);
		break;
	default:
		UDMA_LOG_ERR("Unsupported or invalid opcode: %u\n",
			     (uint32_t)wr->opcode);
		return NULL;
	}

	return udma_qp;
}

static urma_status_t udma_u_post_jetty_rc_wr(struct udma_u_context *udma_ctx,
					     struct udma_u_jetty *udma_jetty,
					     urma_jfs_wr_t *wr,
					     urma_jfs_wr_t **bad_wr)
{
	struct udma_qp *udma_qp;
	urma_status_t ret;
	uint32_t nreq;
	void *wqe;

	udma_qp = udma_jetty->rc_node->qp;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret)
		return ret;

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		ret = udma_u_post_rcqp_wr(udma_ctx, udma_qp, wr, &wqe, nreq);
		if (ret) {
			*bad_wr = wr;
			break;
		}
	}

	if (likely(nreq)) {
		udma_qp->sq.head += nreq;
		*udma_qp->sdb = udma_qp->sq.head;
		udma_u_ring_sq_doorbell(udma_ctx, udma_qp, wqe, nreq);
	}

	if (udma_qp->flush_status == UDMA_FLUSH_STATU_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

	return ret;
}

static urma_status_t udma_u_post_jetty_um_wr(struct udma_u_context *udma_ctx,
					     struct udma_u_jetty *udma_jetty,
					     urma_jfs_wr_t *wr,
					     urma_jfs_wr_t **bad_wr)
{
	struct udma_qp *udma_qp;
	uint32_t wr_cnt = 0;
	urma_status_t ret;
	urma_jfs_wr_t *it;
	void *wqe;

	udma_qp = udma_jetty->um_qp;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret)
		return ret;

	for (it = wr; it != NULL; it = it->next) {
		ret = udma_u_post_umqp_wr(udma_ctx, udma_qp, it, &wqe);
		if (ret) {
			*bad_wr = it;
			break;
		}
		wr_cnt++;
	}

	if (likely(wr_cnt))
		udma_u_ring_sq_doorbell(udma_ctx, udma_qp, wqe, wr_cnt);

	if (udma_qp->flush_status == UDMA_FLUSH_STATU_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

	return ret;
}

urma_status_t udma_u_post_jetty_send_wr(urma_jetty_t *jetty,
					urma_jfs_wr_t *wr,
					urma_jfs_wr_t **bad_wr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	urma_status_t ret;

	if (!udma_jetty->jfs_lock_free)
		(void)pthread_spin_lock(&udma_jetty->lock);

	if (udma_jetty->tp_mode == URMA_TM_RC)
		ret = udma_u_post_jetty_rc_wr(udma_ctx, udma_jetty, wr, bad_wr);
	else
		ret = udma_u_post_jetty_um_wr(udma_ctx, udma_jetty, wr, bad_wr);

	if (!udma_jetty->jfs_lock_free)
		(void)pthread_spin_unlock(&udma_jetty->lock);

	return ret;
}

urma_status_t udma_u_post_jetty_recv_wr(urma_jetty_t *jetty,
					urma_jfr_wr_t *wr,
					urma_jfr_wr_t **bad_wr)
{
	struct udma_u_context *ctx = to_udma_ctx(jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	struct udma_u_jfr *udma_jfr = udma_jetty->udma_jfr;
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

urma_status_t udma_u_modify_jetty(urma_jetty_t *jetty,
				  urma_jetty_attr_t *jetty_attr)
{
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	urma_jfr_attr_t jfr_attr = {};

	if (udma_jetty->share_jfr) {
		UDMA_LOG_ERR("modify jetty failed, jfr is shared.\n");
		return URMA_FAIL;
	}

	jfr_attr.mask = jetty_attr->mask;
	jfr_attr.rx_threshold = jetty_attr->rx_threshold;

	return udma_u_modify_jfr(&udma_jetty->udma_jfr->urma_jfr, &jfr_attr);
}

int udma_u_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr)
{
	struct udma_u_jetty *udma_jetty = to_udma_jetty(jetty);
	struct udma_qp *qp;
	int n_flushed = 0;

	if (udma_jetty->tp_mode == URMA_TM_RC)
		qp = udma_jetty->rc_node->qp;
	else if (udma_jetty->tp_mode == URMA_TM_UM)
		qp = udma_jetty->um_qp;
	else
		return n_flushed;

	if (!udma_jetty->jfs_lock_free)
		(void)pthread_spin_lock(&udma_jetty->lock);

	for (; n_flushed < cr_cnt; ++n_flushed) {
		if (qp->sq.head == qp->sq.tail)
			break;

		udma_fill_scr(qp, cr + n_flushed);
	}

	if (!udma_jetty->jfs_lock_free)
		(void)pthread_spin_unlock(&udma_jetty->lock);

	return n_flushed;
}
