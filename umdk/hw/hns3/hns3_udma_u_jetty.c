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

#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jetty.h"

static urma_status_t udma_init_tgt_connect_table(struct udma_u_jetty *udma_jetty)
{
	struct tgt_node_table *tbl;

	tbl = (struct tgt_node_table *)calloc(1, sizeof(struct tgt_node_table));
	if (!tbl) {
		URMA_LOG_ERR("alloc tbl failed!\n");
		return URMA_ENOMEM;
	}

	(void)pthread_rwlock_init(&tbl->rwlock, NULL);
	if (udma_hmap_init(&tbl->hmap, UDMA_TGT_NODE_TABLE_SIZE)) {
		URMA_LOG_ERR("udma_hmap_init failed!\n");
		free(tbl);
		return URMA_ENOMEM;
	}

	udma_jetty->tjetty_tbl = tbl;

	return URMA_SUCCESS;
}

static urma_status_t alloc_jfr(struct udma_u_jetty *jetty, urma_context_t *ctx,
			       const urma_jetty_cfg_t *jetty_cfg)
{
	urma_jfr_t *urma_jfr;

	if (jetty->share_jfr) {
		jetty->udma_jfr = to_udma_jfr(jetty_cfg->shared.jfr);
	} else {
		urma_jfr = udma_u_create_jfr(ctx, jetty_cfg->jfr_cfg);
		if (!urma_jfr) {
			URMA_LOG_ERR("failed to create jfr.\n");
			return URMA_ENOMEM;
		}
		jetty->udma_jfr = to_udma_jfr(urma_jfr);
	}

	return URMA_SUCCESS;
}

static urma_status_t alloc_qp_node_table(struct udma_u_jetty *jetty,
					 struct udma_u_context *udma_ctx,
					 const urma_jetty_cfg_t *jetty_cfg)
{
	urma_status_t ret;

	ret = verify_jfs_init_attr(&udma_ctx->urma_ctx, jetty_cfg->jfs_cfg);
	if (ret)
		return ret;

	if (jetty->tp_mode == URMA_TM_UM) {
		jetty->um_qp = udma_alloc_qp(udma_ctx, jetty_cfg->jfs_cfg,
					     jetty->urma_jetty.jetty_id.id, true);
		if (!jetty->um_qp) {
			URMA_LOG_ERR("um qp alloc failed, jetty_id = %d.\n",
				     jetty->urma_jetty.jetty_id.id);
			return URMA_ENOMEM;
		}
	} else if (jetty->tp_mode == URMA_TM_RM) {
		ret = udma_init_tgt_connect_table(jetty);
		if (ret) {
			URMA_LOG_ERR("connect jetty table init failed, jetty_id = %d.\n",
				     jetty->urma_jetty.jetty_id.id);
			return URMA_ENOMEM;
		}
	} else {
		jetty->rc_node = (struct rc_node *)calloc(1, sizeof(struct rc_node));
		if (!jetty->rc_node) {
			URMA_LOG_ERR("RC node alloc failed, jetty_id = %d.\n",
				     jetty->urma_jetty.jetty_id.id);
			return URMA_ENOMEM;
		}

		jetty->rc_node->qp = udma_alloc_qp(udma_ctx, jetty_cfg->jfs_cfg,
						   jetty->urma_jetty.jetty_id.id,
						   true);
		if (!jetty->rc_node->qp) {
			URMA_LOG_ERR("alloc rc_node failed.\n");
			goto err_alloc_rc_node_qp;
		}
	}

	return URMA_SUCCESS;
err_alloc_rc_node_qp:
	free(jetty->rc_node);
	jetty->rc_node = NULL;

	return URMA_ENOMEM;
}

static urma_status_t udma_add_to_qp_table(struct udma_u_context *ctx,
					  urma_jetty_t *jetty, struct udma_qp *qp,
					  uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;

	qp_node = (struct udma_jfs_qp_node *)calloc(1, sizeof(*qp_node));
	if (qp_node == NULL) {
		URMA_LOG_ERR("failed to calloc qp_node.\n");
		return URMA_ENOMEM;
	}
	qp_node->jfs_qp = qp;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	if (!udma_hmap_insert(&ctx->jfs_qp_table, &qp_node->node, qpn)) {
		URMA_LOG_ERR("failed insert qp_node into jfs_qp_table.\n");
		free(qp_node);
		qp_node = NULL;
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
	URMA_LOG_ERR("failed to find jetty qp.\n");
}

static urma_status_t exec_jetty_create_cmd(urma_context_t *ctx,
					   struct udma_u_jetty *jetty,
					   const urma_jetty_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_create_jetty_resp resp = {};
	struct udma_create_jetty_ucmd cmd = {};
	urma_status_t ret = URMA_SUCCESS;
	urma_cmd_udrv_priv_t udata = {};

	if (!jetty->share_jfr)
		cmd.jfr_id = jetty->udma_jfr->urma_jfr.jfr_id.id;

	if (jetty->tp_mode == URMA_TM_UM) {
		cmd.create_tp_ucmd.buf_addr = (uint64_t)jetty->um_qp->buf.buf;
		cmd.create_tp_ucmd.sdb_addr = (uint64_t)jetty->um_qp->sdb;
	} else if (jetty->tp_mode == URMA_TM_RC) {
		cmd.buf_addr = (uint64_t)jetty->rc_node->qp->buf.buf;
		cmd.sdb_addr = (uint64_t)jetty->rc_node->qp->sdb;
	}

	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	if (urma_cmd_create_jetty(ctx, &jetty->urma_jetty, cfg, &udata))
		return URMA_ENOMEM;

	if (jetty->tp_mode == URMA_TM_UM) {
		jetty->um_qp->qp_num = resp.create_tp_resp.qpn;
		jetty->um_qp->path_mtu = (urma_mtu_t)resp.create_tp_resp.path_mtu;
		jetty->um_qp->um_srcport = resp.create_tp_resp.um_srcport;
		jetty->um_qp->sq.priority = resp.create_tp_resp.priority;
		memcpy(&jetty->um_qp->um_srcport, &resp.create_tp_resp.um_srcport,
		       sizeof(struct udp_srcport));
		ret = udma_add_to_qp_table(udma_ctx, &jetty->urma_jetty,
					   jetty->um_qp, jetty->um_qp->qp_num);
		if (ret)
			URMA_LOG_ERR("add to qp table failed for um jetty, ret = %d.\n", ret);
	}

	return ret;
}

static void udma_free_tjetty_tbl(struct udma_u_jetty *udma_jetty)
{
	if (udma_jetty->tjetty_tbl) {
		udma_hmap_destroy(&udma_jetty->tjetty_tbl->hmap);
		free(udma_jetty->tjetty_tbl);
		udma_jetty->tjetty_tbl = NULL;
	}
}

static void rc_free_node(struct udma_u_jetty *udma_jetty)
{
	struct udma_u_context *udma_ctx;
	struct udma_qp *qp;

	if (udma_jetty->rc_node) {
		qp = udma_jetty->rc_node->qp;
		if (qp) {
			udma_ctx = to_udma_ctx(udma_jetty->urma_jetty.urma_ctx);
			udma_free_sw_db(udma_ctx, qp->sdb,
					UDMA_JETTY_TYPE_DB);
			free(qp->sq.wrid);
			qp->sq.wrid = NULL;
			udma_free_buf(&qp->buf);
			free(qp);
			qp = NULL;
		}

		free(udma_jetty->rc_node);
		udma_jetty->rc_node = NULL;
	}
}

static void um_free_qp(struct udma_u_jetty *udma_jetty)
{
	struct udma_u_context *udma_ctx;

	if (udma_jetty->um_qp) {
		udma_ctx = to_udma_ctx(udma_jetty->urma_jetty.urma_ctx);
		udma_free_sw_db(udma_ctx, udma_jetty->um_qp->sdb,
				UDMA_JETTY_TYPE_DB);
		free(udma_jetty->um_qp->sq.wrid);
		udma_jetty->um_qp->sq.wrid = NULL;
		udma_free_buf(&udma_jetty->um_qp->buf);
		free(udma_jetty->um_qp);
		udma_jetty->um_qp = NULL;
	}
}

static void delete_qp_node_table(struct udma_u_jetty *udma_jetty)
{
	if (udma_jetty->tp_mode == URMA_TM_UM)
		um_free_qp(udma_jetty);
	else if (udma_jetty->tp_mode == URMA_TM_RM)
		udma_free_tjetty_tbl(udma_jetty);
	else
		rc_free_node(udma_jetty);
}

static void delete_jetty_node(struct udma_u_context *udma_ctx,
			      struct udma_u_jetty *udma_jetty)
{
	struct udma_jetty_node *jetty_node;
	struct udma_hmap_node *node;

	node = udma_table_first_with_hash(&udma_ctx->jetty_table,
					  &udma_ctx->jetty_table_lock,
					  udma_jetty->urma_jetty.jetty_id.id);
	if (node) {
		jetty_node = to_udma_jetty_node(node);
		if (jetty_node->jetty == udma_jetty) {
			(void)pthread_rwlock_wrlock(&udma_ctx->jetty_table_lock);
			udma_hmap_remove(&udma_ctx->jetty_table, node);
			(void)pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
			free(jetty_node);
			return;
		}
	}
	URMA_LOG_ERR("failed to find jetty node.\n");
}

static urma_status_t insert_jetty_node(struct udma_u_context *udma_ctx,
				       struct udma_u_jetty *udma_jetty)
{
	struct udma_jetty_node *jetty_node;

	jetty_node = (struct udma_jetty_node *)calloc(1, sizeof(struct udma_jetty_node));
	if (!jetty_node) {
		URMA_LOG_ERR("alloc jetty node failed.\n");
		return URMA_ENOMEM;
	}
	jetty_node->jetty = udma_jetty;
	(void)pthread_rwlock_wrlock(&udma_ctx->jetty_table_lock);
	if (!udma_hmap_insert(&udma_ctx->jetty_table, &jetty_node->node,
			      udma_jetty->urma_jetty.jetty_id.id)) {
		URMA_LOG_ERR("failed to add jetty_node into jetty_table.\n");
		free(jetty_node);
		jetty_node = NULL;
		(void)pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
		return URMA_EINVAL;
	}
	(void)pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
	return URMA_SUCCESS;
}

urma_status_t verify_jetty_trans_mode(const urma_jetty_cfg_t *jetty_cfg)
{
	urma_transport_mode_t jfs_trans_mode = jetty_cfg->jfs_cfg->trans_mode;
	urma_transport_mode_t jfr_trans_mode;

	if (jetty_cfg->flag.bs.share_jfr)
		jfr_trans_mode = jetty_cfg->shared.jfr->jfr_cfg.trans_mode;
	else
		jfr_trans_mode = jetty_cfg->jfr_cfg->trans_mode;

	if (jfs_trans_mode == jfr_trans_mode)
		return URMA_SUCCESS;

	URMA_LOG_ERR("jfs_trans_mode: %d is different from jfr_trans_mode: %d.\n",
		     jfs_trans_mode, jfr_trans_mode);

	return URMA_EINVAL;
}

urma_jetty_t *udma_u_create_jetty(urma_context_t *ctx,
				  const urma_jetty_cfg_t *jetty_cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_u_jetty *udma_jetty;
	urma_status_t ret;

	udma_jetty = (struct udma_u_jetty *)calloc(1, sizeof(*udma_jetty));
	if (!udma_jetty) {
		URMA_LOG_ERR("failed to alloc jetty.\n");
		return NULL;
	}

	ret = verify_jetty_trans_mode(jetty_cfg);
	if (ret) {
		URMA_LOG_ERR("failed verify jetty trans mode.\n");
		goto err_alloc_jetty;
	}

	udma_jetty->tp_mode = jetty_cfg->jfs_cfg->trans_mode;
	udma_jetty->share_jfr = jetty_cfg->flag.bs.share_jfr;
	udma_jetty->jfs_lock_free = jetty_cfg->jfs_cfg->flag.bs.lock_free;
	udma_jetty->urma_jetty.jetty_cfg = *jetty_cfg;

	ret = alloc_jfr(udma_jetty, ctx, jetty_cfg);
	if (ret)
		goto err_alloc_jetty;

	ret = alloc_qp_node_table(udma_jetty, udma_ctx, jetty_cfg);
	if (ret)
		goto err_alloc_qp_node_table;

	ret = exec_jetty_create_cmd(ctx, udma_jetty, jetty_cfg);
	if (ret) {
		URMA_LOG_ERR("exec jetty create cmd failed.\n");
		goto err_exec_jetty_create_cmd;
	}

	if (pthread_spin_init(&udma_jetty->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_init_lock;

	ret = insert_jetty_node(udma_ctx, udma_jetty);
	if (ret) {
		URMA_LOG_ERR("insert jetty node failed.\n");
		goto err_insert_jetty_node;
	}

	return &udma_jetty->urma_jetty;

err_insert_jetty_node:
	pthread_spin_destroy(&udma_jetty->lock);
err_init_lock:
	urma_cmd_delete_jetty(&udma_jetty->urma_jetty);
err_exec_jetty_create_cmd:
	delete_qp_node_table(udma_jetty);
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

	if (udma_jetty->tp_mode == URMA_TM_UM)
		udma_remove_from_qp_table(udma_ctx, udma_jetty->um_qp->qp_num);

	delete_qp_node_table(udma_jetty);
	delete_jetty_node(udma_ctx, udma_jetty);
	pthread_spin_destroy(&udma_jetty->lock);

	ret = urma_cmd_delete_jetty(jetty);
	if (ret) {
		URMA_LOG_ERR("jetty delete failed!\n");
		return URMA_FAIL;
	}

	if (!udma_jetty->share_jfr) {
		if (udma_jetty->udma_jfr) {
			udma_u_delete_jfr(&udma_jetty->udma_jfr->urma_jfr);
			udma_jetty->udma_jfr = NULL;
		}
	}

	free(udma_jetty);

	return URMA_SUCCESS;
}
