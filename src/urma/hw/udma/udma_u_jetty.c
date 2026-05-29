// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include "udma_u_common.h"
#include "udma_u_jfs.h"
#include "udma_u_jfr.h"
#include "udma_u_jfc.h"
#include "udma_u_buf.h"
#include "udma_u_db.h"
#include "udma_u_jetty.h"

static int exec_jetty_active_cmd(struct udma_u_jetty *jetty, urma_jetty_cfg_t *cfg)
{
	struct udma_create_jetty_resp resp = {};
	struct udma_create_jetty_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (cfg->jfs_cfg.priority >= UDMA_MAX_PRIORITY) {
		UDMA_LOG_ERR("user mode jetty priority is out of range, priority is %u.\n",
			     cfg->jfs_cfg.priority);
		return EINVAL;
	}

	cmd.buf_addr = (uintptr_t)jetty->sq.qbuf;
	cmd.buf_len = jetty->sq.qbuf_size;
	cmd.db_addr = (uintptr_t)jetty->sq.db.addr;
	cmd.jetty_addr = (uintptr_t)&jetty->sq;
	cmd.sqe_bb_cnt = jetty->sq.sqe_bb_cnt;
	cmd.pi_type = jetty->sq.pi_type;
	cmd.jetty_type = jetty->jetty_type;
	cmd.non_pin = jetty->sq.cstm;
	cmd.is_hugepage = jetty->sq.hugepage != NULL;

	udma_u_set_udata(&udata, &cmd, (uint32_t)sizeof(cmd), &resp, (uint32_t)sizeof(resp));
	ret = urma_cmd_active_jetty(&jetty->base, &udata);
	if (ret) {
		UDMA_LOG_ERR("URMA active jetty failed.\n");
		return ret;
	}

	ret = udma_u_set_sq_by_resp(&jetty->sq, &resp);
	if (ret != 0) {
		(void)urma_cmd_deactive_jetty(&jetty->base, NULL);
		return ret;
	}

	jetty->sq.idx = jetty->base.jetty_id.id;
	jetty->sq.db.id = jetty->base.jetty_id.id;

	return 0;
}

int exec_jetty_create_cmd(urma_context_t *ctx, struct udma_u_jetty *jetty,
				 urma_jetty_cfg_t *cfg)
{
	struct udma_create_jetty_resp resp = {};
	struct udma_create_jetty_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (cfg->jfs_cfg.priority >= UDMA_MAX_PRIORITY) {
		UDMA_LOG_ERR("user mode jetty priority is out of range, priority is %u.\n",
			     cfg->jfs_cfg.priority);
		return EINVAL;
	}

	cmd.buf_addr = (uintptr_t)jetty->sq.qbuf;
	cmd.buf_len = jetty->sq.qbuf_size;
	cmd.db_addr = (uintptr_t)jetty->sq.db.addr;
	cmd.jetty_addr = (uintptr_t)&jetty->sq;
	cmd.sqe_bb_cnt = jetty->sq.sqe_bb_cnt;
	cmd.pi_type = jetty->sq.pi_type;
	cmd.jetty_type = jetty->jetty_type;
	cmd.non_pin = jetty->sq.cstm;
	cmd.dtu_en = jetty->sq.dtu_en;
	cmd.is_hugepage = jetty->sq.hugepage != NULL;
	udma_u_set_udata(&udata, &cmd, (uint32_t)sizeof(cmd), &resp, (uint32_t)sizeof(resp));
	ret = urma_cmd_create_jetty(ctx, &jetty->base, cfg, &udata);
	if (ret) {
		UDMA_LOG_ERR("URMA create JETTY failed.\n");
		return ret;
	}
	ret = udma_u_set_sq_by_resp(&jetty->sq, &resp);
	if (ret != 0) {
		(void)urma_cmd_delete_jetty(&jetty->base);
		return ret;
	}

	jetty->sq.idx = jetty->base.jetty_id.id;
	jetty->sq.db.id = jetty->base.jetty_id.id;

	return 0;
}

int init_jetty_trans_mode(struct udma_u_jetty *jetty, urma_jetty_cfg_t *cfg)
{
	urma_jfr_cfg_t *jfr_cfg = &cfg->shared.jfr->jfr_cfg;

	if (cfg->jfs_cfg.trans_mode == jfr_cfg->trans_mode) {
		jetty->sq.trans_mode = jfr_cfg->trans_mode;
		return 0;
	}

	UDMA_LOG_ERR("transport mode of JFS and JFR is not equal,"
		     "JFS trans_mode is %u, JFR trans_mode is %u.\n",
		     cfg->jfs_cfg.trans_mode, jfr_cfg->trans_mode);

	return EINVAL;
}

int add_jetty_to_grp(struct udma_u_jetty *jetty, urma_jetty_cfg_t *cfg)
{
	struct udma_u_jetty_grp *udma_jetty_grp;
	int ret = 0;

	if (!cfg->jetty_grp)
		return 0;

	if (jetty->sq.trans_mode != URMA_TM_RM) {
		UDMA_LOG_ERR("JETTY must be RM model, if assigned group.\n");
		return EINVAL;
	}

	udma_jetty_grp = to_udma_u_jetty_grp(cfg->jetty_grp);

	(void)pthread_spin_lock(&udma_jetty_grp->lock);
	if (udma_jetty_grp->jetty_cnt >= MAX_JETTY_IN_GRP) {
		UDMA_LOG_ERR("JETTY group is already full.\n");
		ret = EINVAL;
		goto out;
	}

	++udma_jetty_grp->jetty_cnt;
	jetty->jetty_grp = udma_jetty_grp;
out:
	(void)pthread_spin_unlock(&udma_jetty_grp->lock);
	return ret;
}

void remove_jetty_from_grp(struct udma_u_jetty *jetty)
{
	struct udma_u_jetty_grp *jetty_grp = jetty->jetty_grp;

	if (!jetty_grp)
		return;

	(void)pthread_spin_lock(&jetty_grp->lock);

	/* Prevent jetty_cnt from being abnormally reduced to 0. */
	if (jetty_grp->jetty_cnt > 0)
		--jetty_grp->jetty_cnt;

	(void)pthread_spin_unlock(&jetty_grp->lock);

	jetty->jetty_grp = NULL;
}

urma_status_t insert_jetty_node(struct udma_u_context *udma_ctx,
				struct udma_u_jetty *pointer)
{
	uint32_t jettys_in_tbl = 1 << udma_ctx->jettys_in_tbl_shift;
	uint32_t mask = jettys_in_tbl - 1;
	struct udma_u_jetty **jetty_array;
	uint32_t id = pointer->sq.idx;
	uint32_t table_id;

	table_id = id >> udma_ctx->jettys_in_tbl_shift;
	pthread_rwlock_wrlock(&udma_ctx->jetty_table_lock);
	if (!udma_ctx->jetty_table[table_id].refcnt) {
		udma_ctx->jetty_table[table_id].jetty_array = (struct udma_u_jetty **)calloc(jettys_in_tbl,
								sizeof(struct udma_u_jetty *));
		if (!udma_ctx->jetty_table[table_id].jetty_array) {
			pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
			return URMA_ENOMEM;
		}
	}

	jetty_array = udma_ctx->jetty_table[table_id].jetty_array;
	++udma_ctx->jetty_table[table_id].refcnt;
	jetty_array[id & mask] = pointer;
	pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);

	return URMA_SUCCESS;
}

static int udma_u_active_jetty_prepare(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	int ret;

	ret = init_jetty_trans_mode(udma_jetty, cfg);
	if (ret) {
		UDMA_LOG_ERR("init JETTY transport mode failed when active JETTY, ret = %d.\n", ret);
		return ret;
	}

	ret = add_jetty_to_grp(udma_jetty, cfg);
	if (ret) {
		UDMA_LOG_ERR("active JETTY add JETTY to group failed, ret = %d.\n", ret);
		return ret;
	}

	udma_jetty->sq.sq_reserved = udma_jetty->sq.ctx->sq_reserved;
	udma_jetty->sq.db.id = jetty->jetty_cfg.id;
	ret = udma_u_create_sq(&udma_jetty->sq, &cfg->jfs_cfg);
	if (ret) {
		UDMA_LOG_ERR("active JETTY create SQ failed, ret = %d.\n", ret);
		remove_jetty_from_grp(udma_jetty);
		return ret;
	}

	udma_jetty->jfr = to_udma_u_jfr(cfg->shared.jfr);

	return 0;
}

urma_jetty_t *udma_u_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jetty *jetty;
	int ret;

	jetty = (struct udma_u_jetty *)calloc(1, sizeof(struct udma_u_jetty));
	if (jetty == NULL) {
		UDMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}

	jetty->sq.ctx = udma_ctx;
	jetty->sq.dtu_en = udma_ctx->dtu_enable;
	ret = udma_u_active_jetty_prepare(&jetty->base, cfg);
	if (ret)
		goto err_active_jetty_prepare;

	jetty->jetty_type = UDMA_URMA_NORMAL_JETTY_TYPE;
	if (exec_jetty_create_cmd(ctx, jetty, cfg)) {
		if(jetty->sq.dtu_en) {
			jetty->sq.dtu_en = false;
			if (!udma_u_alloc_queue_buf(&jetty->sq, jetty->sq.sqe_bb_cnt * cfg->jfs_cfg.depth,
			    UDMA_JFS_WQEBB, jetty->sq.aligned_size, true)) {
				UDMA_LOG_ERR("failed to alloc JETTY SQ after DTU failed.\n");
				goto err_jetty_create_cmd;
			}
			if (exec_jetty_create_cmd(ctx, jetty, cfg))
				goto err_jetty_create_cmd;
		} else {
			UDMA_LOG_ERR("failed to create jetty.\n");
			goto err_jetty_create_cmd;
		}
	}

	jetty->sq.db.type = UDMA_MMAP_JETTY_DSQE;
	if (udma_u_alloc_db(ctx, &jetty->sq.db))
		goto err_alloc_db;

	jetty->sq.dwqe_addr = (void *)jetty->sq.db.addr;
	if (insert_jetty_node(udma_ctx, jetty))
		goto err_insert_node;

	return &jetty->base;

err_insert_node:
	udma_u_free_db(ctx, &jetty->sq.db);
err_alloc_db:
	(void)urma_cmd_delete_jetty(&jetty->base);
err_jetty_create_cmd:
	udma_u_delete_sq(&jetty->sq);
	remove_jetty_from_grp(jetty);
err_active_jetty_prepare:
	free(jetty);

	return NULL;
}

void udma_u_jetty_table_remove(struct udma_u_context *udma_ctx,
					     struct udma_u_jetty *jetty)
{
	uint32_t mask = (1 << udma_ctx->jettys_in_tbl_shift) - 1;
	uint32_t table_id = jetty->sq.idx >> udma_ctx->jettys_in_tbl_shift;

	(void)pthread_rwlock_wrlock(&udma_ctx->jetty_table_lock);

	if (udma_ctx->jetty_table[table_id].refcnt == 0) {
		(void)pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
		return;
	}

	if (!udma_ctx->jetty_table[table_id].jetty_array[jetty->sq.idx & mask]) {
		(void)pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
		return;
	}
	udma_ctx->jetty_table[table_id].jetty_array[jetty->sq.idx & mask] = NULL;

	if (!--udma_ctx->jetty_table[table_id].refcnt) {
		free(udma_ctx->jetty_table[table_id].jetty_array);
		udma_ctx->jetty_table[table_id].jetty_array = NULL;
	}
	(void)pthread_rwlock_unlock(&udma_ctx->jetty_table_lock);
}

static urma_status_t udma_u_delete_jetty_prepare(urma_jetty_t *jetty)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	struct udma_u_jetty_queue *sq = &udma_jetty->sq;
	int ret;

	if (sq->trans_mode == URMA_TM_RC && sq->tjetty) {
		ret = udma_u_unbind_jetty(jetty);
		if (ret) {
			UDMA_LOG_ERR("unbind JETTY failed, JETTY id %u.\n", sq->idx);
			return URMA_FAIL;
		}
	}

	return URMA_SUCCESS;
}

static void udma_u_free_jetty_prepare(urma_jetty_t* jetty)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	urma_jfc_t *send_jfc;
	urma_jfc_t *recv_jfc;

	send_jfc = jetty->jetty_cfg.jfs_cfg.jfc;

	if (jetty->jetty_cfg.flag.bs.share_jfr == URMA_NO_SHARE_JFR)
		recv_jfc = jetty->jetty_cfg.jfr_cfg->jfc;
	else
		recv_jfc = jetty->jetty_cfg.shared.jfr->jfr_cfg.jfc;

	if (!!send_jfc)
		udma_u_clean_jfc(send_jfc, jetty->jetty_id.id);

	if (!!recv_jfc && send_jfc != recv_jfc)
		udma_u_clean_jfc(recv_jfc, jetty->jetty_id.id);

	udma_u_jetty_table_remove(udma_ctx, udma_jetty);
	udma_u_free_db(jetty->urma_ctx, &udma_jetty->sq.db);
	udma_u_delete_sq(&udma_jetty->sq);
	remove_jetty_from_grp(udma_jetty);
}

static void udma_u_free_jetty_detail(urma_jetty_t *jetty)
{
	udma_u_free_jetty_prepare(jetty);
	free(jetty);
}

urma_status_t udma_u_delete_jetty(urma_jetty_t *jetty)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	int ret;

	ret = udma_u_delete_jetty_prepare(jetty);
	if (ret)
		goto delete_err;

	ret = urma_cmd_delete_jetty(jetty);
	if (ret) {
		UDMA_LOG_ERR("jetty delete failed, ret = %d.\n", ret);
		goto delete_err;
	}

	udma_u_free_jetty_detail(jetty);

	return URMA_SUCCESS;

delete_err:
	udma_u_jetty_table_remove(udma_ctx, udma_jetty);

	return URMA_FAIL;
}

urma_status_t udma_u_delete_jetty_batch(urma_jetty_t **jetty, int jetty_cnt, urma_jetty_t **bad_jetty)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jetty *udma_jetty;
	int ret;
	int i;

	if (!jetty) {
		UDMA_LOG_ERR("jetty array is null.\n");
		return URMA_EINVAL;
	}

	if (!jetty_cnt) {
		UDMA_LOG_ERR("JETTY count is 0.\n");
		return URMA_EINVAL;
	}

	for (i = 0; i < jetty_cnt; i++) {
		ret = udma_u_delete_jetty_prepare(jetty[i]);
		if (ret) {
			*bad_jetty = jetty[0];
			goto delete_err;
		}
	}

	ret = urma_cmd_delete_jetty_batch(jetty, jetty_cnt, bad_jetty);
	if (ret) {
		UDMA_LOG_ERR("batch JETTY delete failed, ret = %d.\n", ret);
		goto delete_err;
	}

	for (i = 0; i < jetty_cnt; i++)
		udma_u_free_jetty_detail(jetty[i]);

	return 0;

delete_err:
	for (i--; i >= 0; i--) {
		udma_ctx = to_udma_u_ctx(jetty[i]->urma_ctx);
		udma_jetty = to_udma_u_jetty(jetty[i]);
		udma_u_jetty_table_remove(udma_ctx, udma_jetty);
	}

	return URMA_FAIL;
}

static int udma_check_jetty_grp_info(urma_tjetty_cfg_t *cfg)
{
	if (cfg->type == URMA_JETTY_GROUP) {
		if (cfg->trans_mode != URMA_TM_RM) {
			UDMA_LOG_ERR("import JETTY group only support RM, transmode is %u.\n",
				     cfg->trans_mode);
			return EINVAL;
		}

		if (cfg->policy != URMA_JETTY_GRP_POLICY_HASH_HINT) {
			UDMA_LOG_ERR("import JETTY group only support hint, policy is %u.\n",
				     cfg->policy);
			return EINVAL;
		}
	}

	return 0;
}

urma_status_t udma_u_unimport_jetty(urma_target_jetty_t *target_jetty)
{
	struct udma_u_target_jetty *rjetty = to_udma_u_target_jetty(target_jetty);

	if (target_jetty->trans_mode == URMA_TM_RC &&
	    target_jetty->tp.tpn != INVALID_TPN) {
		UDMA_LOG_ERR("the RC target JETTY is still being used, id = %u.\n",
			     target_jetty->id.id);
		return URMA_FAIL;
	}

	if (urma_cmd_unimport_jetty(target_jetty)) {
		UDMA_LOG_ERR("URMA command unimport JETTY failed.\n");
		return URMA_FAIL;
	}

	rjetty->token_value = 0;

	free(rjetty);

	return URMA_SUCCESS;
}

urma_status_t udma_u_post_jetty_send_wr(urma_jetty_t *urma_jetty,
					urma_jfs_wr_t *wr,
					urma_jfs_wr_t **bad_wr)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(urma_jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(urma_jetty);
	urma_status_t ret;

	ret = udma_u_post_sq_wr(udma_ctx, &udma_jetty->sq, wr, bad_wr);
	if (ret)
		UDMA_LOG_ERR("JETTY post sq wr failed, ret = %d, id = %u.\n",
			     ret, udma_jetty->sq.idx);

	return ret;
}

urma_status_t udma_u_post_jetty_recv_wr(urma_jetty_t *urma_jetty,
					urma_jfr_wr_t *wr,
					urma_jfr_wr_t **bad_wr)
{
	struct udma_u_jetty *jetty = to_udma_u_jetty(urma_jetty);
	urma_jfr_t *urma_jfr = &jetty->jfr->base;
	urma_status_t ret;

	ret = udma_u_post_jfr_wr(urma_jfr, wr, bad_wr);
	if (ret)
		UDMA_LOG_ERR("JETTY post jfr wr failed, ret = %d, id = %u.\n",
			     ret, jetty->sq.idx);

	return ret;
}

urma_status_t udma_u_unbind_jetty(urma_jetty_t *jetty)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	urma_target_jetty_t *tjetty = jetty->remote_jetty;
	int ret;

	if (tjetty == NULL || udma_jetty->sq.tjetty == NULL) {
		UDMA_LOG_ERR("the jetty not bind a remote jetty, id = %u.\n",
			     jetty->jetty_id.id);
		return URMA_EINVAL;
	}

	if (udma_jetty->sq.trans_mode != URMA_TM_RC ||
	    tjetty->trans_mode != URMA_TM_RC) {
		UDMA_LOG_ERR("the transport mode of JETTY or target JETTY is not RC.\n");
		return URMA_EINVAL;
	}

	ret = urma_cmd_unbind_jetty(jetty);
	if (ret) {
		UDMA_LOG_ERR("URMA command unbind JETTY failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	udma_jetty->sq.tjetty = NULL;
	tjetty->tp.tpn = INVALID_TPN;

	return URMA_SUCCESS;
}

urma_status_t udma_u_modify_jetty(urma_jetty_t *jetty,
				  urma_jetty_attr_t *jetty_attr)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if ((jetty_attr->mask & (uint32_t)JETTY_STATE) == 0) {
		UDMA_LOG_ERR("modify jetty mask is error or not set, jetty_id = %u.\n",
			     jetty->jetty_id.id);
		return URMA_EINVAL;
	}

	ret = urma_cmd_modify_jetty(jetty, jetty_attr, &udata);
	if (ret) {
		UDMA_LOG_ERR("URMA command modify JETTY failed.\n");
		return URMA_FAIL;
	}

	if (jetty_attr->state == URMA_JETTY_STATE_READY)
		udma_reset_sw_u_jetty_queue(&udma_jetty->sq);

	return URMA_SUCCESS;
}

urma_jetty_grp_t *udma_u_create_jetty_grp(urma_context_t *ctx,
					  urma_jetty_grp_cfg_t *cfg)
{
	struct udma_u_jetty_grp *jetty_grp;
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (cfg->policy != URMA_JETTY_GRP_POLICY_HASH_HINT) {
		UDMA_LOG_ERR("policy %u not support.\n", cfg->policy);
		return NULL;
	}

	jetty_grp = (struct udma_u_jetty_grp *)calloc(1, sizeof(*jetty_grp));
	if (!jetty_grp) {
		UDMA_LOG_ERR("alloc JETTY group failed.\n");
		return NULL;
	}

	if (pthread_spin_init(&jetty_grp->lock, PTHREAD_PROCESS_PRIVATE)) {
		UDMA_LOG_ERR("init JETTY group lock failed.\n");
		goto err_spin_init;
	}

	ret = urma_cmd_create_jetty_grp(ctx, &jetty_grp->base, cfg, &udata);
	if (ret) {
		UDMA_LOG_ERR("URMA command create JETTY group failed.\n");
		goto err_cmd_create_jetty_grp;
	}

	return &jetty_grp->base;

err_cmd_create_jetty_grp:
	(void)pthread_spin_destroy(&jetty_grp->lock);
err_spin_init:
	free(jetty_grp);
	return NULL;
}

urma_status_t udma_u_delete_jetty_grp(urma_jetty_grp_t *jetty_grp)
{
	struct udma_u_jetty_grp *udma_jetty_grp = to_udma_u_jetty_grp(jetty_grp);
	int ret;

	if (udma_jetty_grp->jetty_cnt > 0) {
		UDMA_LOG_ERR("jetty group been used, jetty_cnt is %u.\n",
			     udma_jetty_grp->jetty_cnt);
		return URMA_FAIL;
	}

	ret = urma_cmd_delete_jetty_grp(jetty_grp);
	if (ret) {
		UDMA_LOG_ERR("URMA command delete JETTY group failed.\n");
		return URMA_FAIL;
	}

	(void)pthread_spin_destroy(&udma_jetty_grp->lock);
	free(udma_jetty_grp);

	return URMA_SUCCESS;
}

int udma_u_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr)
{
	struct udma_u_jetty *udma_u_jetty = to_udma_u_jetty(jetty);
	struct udma_u_jetty_queue *sq = &udma_u_jetty->sq;
	uint32_t local_id = jetty->jetty_id.id;
	int n_flushed;

	if (!sq->flush_flag)
		return 0;

	if (!sq->lock_free)
		(void)pthread_spin_lock(&sq->lock);

	for (n_flushed = 0; n_flushed < cr_cnt; n_flushed++) {
		if (sq->ci == sq->pi)
			break;
		udma_u_flush_sq(local_id, sq, cr + n_flushed, true);
	}

	if (!sq->lock_free)
		(void)pthread_spin_unlock(&sq->lock);

	return n_flushed;
}

urma_status_t udma_u_query_jetty(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg,
				 urma_jetty_attr_t *attr)
{
	int ret;

	ret = urma_cmd_query_jetty(jetty, cfg, attr);
	if (ret) {
		UDMA_LOG_ERR("failed to query JETTY in URMA command, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

urma_target_jetty_t *udma_u_import_jetty_ex(urma_context_t *ctx,
					    urma_rjetty_t *rjetty,
					    urma_token_t *token_value,
					    urma_active_tp_cfg_t *active_tp_cfg)
{
	urma_tjetty_cfg_t cfg = {rjetty->jetty_id, rjetty->flag,
				 token_value, rjetty->trans_mode,
				 rjetty->policy, rjetty->type, rjetty->tp_type};
	urma_cmd_udrv_priv_t udrv_data = {};
	struct udma_u_target_jetty *tjetty;

	if (rjetty->type != URMA_JETTY && rjetty->type != URMA_JETTY_GROUP) {
		UDMA_LOG_ERR("the JETTY type %u cannot import JETTY ex.\n",
			     rjetty->type);
		return NULL;
	}

	if (udma_check_jetty_grp_info(&cfg))
		return NULL;

	tjetty = (struct udma_u_target_jetty *)calloc(1, sizeof(*tjetty));
	if (tjetty == NULL) {
		UDMA_LOG_ERR("target JETTY alloc failed in imported JETTY ex.\n");
		return NULL;
	}

	udma_u_set_udata(&udrv_data, NULL, 0, NULL, 0);
	if (urma_cmd_import_jetty_ex(ctx, &tjetty->urma_tjetty, &cfg,
				     (urma_import_jetty_ex_cfg_t *)active_tp_cfg, &udrv_data) != 0) {
		UDMA_LOG_ERR("URMA command import JETTY in export failed.\n");
		free(tjetty);
		return NULL;
	}

	if (rjetty->trans_mode == URMA_TM_RC)
		tjetty->urma_tjetty.tp.tpn = INVALID_TPN;

	if (rjetty->flag.bs.token_policy != URMA_TOKEN_NONE) {
		tjetty->token_value_valid = true;
		tjetty->token_value = token_value->token;
	}

	udma_u_swap_endian128(rjetty->jetty_id.eid.raw, tjetty->le_eid.raw);

	return &tjetty->urma_tjetty;
}

urma_status_t udma_u_bind_jetty_ex(urma_jetty_t *jetty,
				   urma_target_jetty_t *tjetty,
				   urma_active_tp_cfg_t *active_tp_cfg)
{
	struct udma_u_target_jetty *udma_tjetty = to_udma_u_target_jetty(tjetty);
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	int ret;

	if (udma_jetty->sq.trans_mode != URMA_TM_RC ||
	    tjetty->trans_mode != URMA_TM_RC) {
		UDMA_LOG_ERR("the transport mode of JETTY or target JETTY in export is not RC.\n");
		return URMA_EINVAL;
	}

	if (udma_jetty->sq.tjetty == udma_tjetty) {
		UDMA_LOG_INFO("reentry bind JETTY in exp, jetty_id = %u, tjetty_id = %u.\n",
			      jetty->jetty_id.id, tjetty->id.id);
		return URMA_SUCCESS;
	}

	if (udma_jetty->sq.tjetty != NULL) {
		UDMA_LOG_ERR("the RC JETTY has bound a remote JETTY in export,"
			     "jetty_id = %u.\n", jetty->jetty_id.id);
		return URMA_EEXIST;
	}

	if (tjetty->tp.tpn != INVALID_TPN) {
		UDMA_LOG_ERR("the target JETTY has been bound in export, id = %u.\n",
			     tjetty->id.id);
		return URMA_EINVAL;
	}

	ret = urma_cmd_bind_jetty_ex(jetty, tjetty,
				     (urma_bind_jetty_ex_cfg_t *)active_tp_cfg, NULL);
	if (ret != 0) {
		UDMA_LOG_ERR("URMA command bind JETTY in export failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	udma_jetty->sq.tjetty = udma_tjetty;

	return URMA_SUCCESS;
}

urma_status_t udma_u_alloc_jetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg,
				urma_jetty_t **jetty)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jetty *udma_jetty;
	urma_cmd_udrv_priv_t udata;
	int ret;

	udma_jetty = (struct udma_u_jetty *)calloc(1, sizeof(struct udma_u_jetty));
	if (udma_jetty == NULL) {
		UDMA_LOG_ERR("UDMA JETTY allocation failed.\n");
		return URMA_ENOMEM;
	}

	ret = urma_cmd_alloc_jetty(ctx, cfg, &udma_jetty->base, &udata);
	if (ret) {
		UDMA_LOG_ERR("alloc jetty failed, ret = %d.\n", ret);
		free(udma_jetty);
		return URMA_FAIL;
	}

	*jetty = &udma_jetty->base;
	udma_jetty->sq.ctx = udma_ctx;

	return URMA_SUCCESS;
}

urma_status_t udma_u_free_jetty(urma_jetty_t *jetty)
{
	urma_cmd_udrv_priv_t udata;
	int ret;

	ret = urma_cmd_free_jetty(jetty, &udata);
	if (ret) {
		UDMA_LOG_ERR("free jetty failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	free(jetty);

	return URMA_SUCCESS;
}

static uint64_t udma_jetty_opt[] = {
	URMA_JFS_DEPTH,
	URMA_JFS_FLAG,
	URMA_JFS_TRANS_MODE,
	URMA_JFS_PRIORITY,
	URMA_JFS_MAX_SGE,
	URMA_JFS_MAX_RSGE,
	URMA_JFS_MAX_INLINE_DATA,
	URMA_JFS_RNR_RETRY,
	URMA_JFS_ERR_TIMEOUT,
	URMA_JFS_BIND_JFC,
	URMA_JFS_USER_CTX,
	URMA_JFS_SQE_BASE_ADDR,
	URMA_JFS_ID,
	URMA_JFS_DB_ADDR,
	URMA_JFS_DB_STATUS,
	URMA_JFS_PI,
	URMA_JFS_PI_TYPE,
	URMA_JFS_CI,
	URMA_JFS_FULL_CTX,
	URMA_JETTY_ID,
	URMA_JETTY_FLAG,
	URMA_JETTY_BIND_JFR,
	URMA_JETTY_BIND_RX_JFC,
	URMA_JETTY_BIND_JTG,
	URMA_JETTY_USER_CTX,
	URMA_JETTY_FULL_CTX,
};

static struct udma_u_jetty_opt_info opt_info[] = {
	{sizeof(uint32_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, JETTY_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, JFS_IGNORE | JETTY_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, 0, JFS_MODE},
	{sizeof(uint64_t), PERM_R, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint16_t), PERM_R, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint16_t), PERM_R | PERM_W, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint16_t), PERM_R, 0, JFS_MODE | JETTY_MODE},
	{UDMA_JFS_CTX_SIZE, PERM_R, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, 0, JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, 0, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, 0, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, 0, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, 0, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, JETTY_IGNORE, JETTY_MODE},
	{UDMA_JETTY_CTX_SIZE, PERM_R, 0, JETTY_MODE},
};

urma_status_t udma_u_verify_jetty_opt(uint64_t opt, void *buf, uint32_t len,
				      enum udma_u_set_get_jetty_opt_mode jetty_mode,
				      enum udma_u_set_get_jetty_opt_perm jetty_perm)
{
	uint32_t opt_index = ARRAY_SIZE(udma_jetty_opt);
	uint32_t i;

	if (buf == NULL) {
		UDMA_LOG_ERR("JETTY/JFS option buffer is null\n");
		return URMA_EINVAL;
	}

	for (i = 0; i < ARRAY_SIZE(udma_jetty_opt); i++) {
		if (udma_jetty_opt[i] == opt) {
			opt_index = i;
			break;
		}
	}

	if (opt_index >= ARRAY_SIZE(opt_info) || (opt_info[opt_index].mode & jetty_mode) == 0) {
		UDMA_LOG_ERR("option %lu mode %u is invalid\n", opt, jetty_mode);
		return URMA_EINVAL;
	}

	if (len != opt_info[opt_index].buf_len) {
		UDMA_LOG_ERR("option %lu length %u error, should be %u\n",
			     opt, len, opt_info[opt_index].buf_len);
		return URMA_EINVAL;
	}

	if ((opt_info[opt_index].perm & jetty_perm) == 0) {
		UDMA_LOG_ERR("option %lu not allow read\n", opt);
		return URMA_EINVAL;
	}

	/* The EEXIST return value indicates that there is no need to enter kernel mode. */
	if (opt_info[opt_index].ignore_attr & jetty_mode) {
		UDMA_LOG_ERR("option %lu no need to trap kernel\n", opt);
		return URMA_EEXIST;
	}

	return URMA_SUCCESS;
}

urma_status_t udma_u_set_jetty_field(struct udma_u_jetty_queue *sq, uint64_t opt, void *buf)
{
	uint8_t in_data;

	switch (opt) {
	case URMA_JFS_SQE_BASE_ADDR:
		sq->qbuf = (void *)(uintptr_t)(*((uint64_t *)buf));
		if (!sq->qbuf) {
			UDMA_LOG_ERR("set SQE base address is null.\n");
			return URMA_EINVAL;
		}
		sq->cstm = true;
		break;
	case URMA_JFS_DB_STATUS:
		in_data = *((uint8_t *)buf);
		if (in_data > 1) {
			UDMA_LOG_ERR("doorbell status %hhu is invalid\n", in_data);
			return URMA_EINVAL;
		}
		sq->db_status = in_data;
		if (sq->db_status == 0 && sq->need_ring_db) {
			if (!sq->lock_free)
				(void)pthread_spin_lock(&sq->lock);

			sq->need_ring_db = false;
			udma_update_sq_db(sq);

			if (!sq->lock_free)
				(void)pthread_spin_unlock(&sq->lock);
		}
		break;
	case URMA_JFS_PI_TYPE:
		in_data = *((uint8_t *)buf);
		if (in_data > 1) {
			UDMA_LOG_ERR("doorbell status %hhu is invalid\n", in_data);
			return URMA_EINVAL;
		}
		sq->pi_type = in_data;
		break;
	default:
		break;
	}

	return URMA_SUCCESS;
}

urma_status_t udma_u_set_jetty_opt(urma_jetty_t *jetty, uint64_t opt, void *buf, uint32_t len)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	urma_cmd_udrv_priv_t udata;
	urma_status_t verify_ret;
	urma_status_t urma_ret;
	int ret;

	verify_ret = udma_u_verify_jetty_opt(opt, buf, len, JETTY_MODE, PERM_W);
	if (verify_ret && verify_ret != URMA_EEXIST)
		return verify_ret;

	urma_ret = udma_u_set_jetty_field(&udma_jetty->sq, opt, buf);
	if (urma_ret)
		return urma_ret;

	if (verify_ret == URMA_EEXIST)
		return URMA_SUCCESS;

	ret = urma_cmd_set_jetty_opt(jetty, opt, buf, len, &udata);
	if (ret) {
		UDMA_LOG_ERR("set JETTY option failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

void udma_u_get_jetty_field(struct udma_u_jetty_queue *sq, uint64_t opt, void *buf)
{
	switch (opt) {
	case URMA_JFS_SQE_BASE_ADDR:
		*((uint64_t *)buf) = (uint64_t)(uintptr_t)sq->qbuf;
		break;
	case URMA_JFS_DB_ADDR:
		*((uint64_t *)buf) = (uint64_t)(uintptr_t)(sq->dwqe_addr + UDMA_DOORBELL_OFFSET);
		break;
	case URMA_JFS_DB_STATUS:
		*((uint8_t *)buf) = sq->db_status;
		break;
	case URMA_JFS_PI_TYPE:
		*((uint8_t *)buf) = sq->pi_type;
		break;
	default:
		break;
	}
}

void udma_u_get_jfs_cfg_field(urma_jfs_cfg_t *jfs_cfg, uint64_t opt, void *buf)
{
	switch (opt) {
	case URMA_JFS_DEPTH:
		*((uint32_t *)buf) = jfs_cfg->depth;
		break;
	case URMA_JFS_FLAG:
		*((uint32_t *)buf) = jfs_cfg->flag.value;
		break;
	case URMA_JFS_TRANS_MODE:
		*((uint32_t *)buf) = jfs_cfg->trans_mode;
		break;
	case URMA_JFS_PRIORITY:
		*((uint8_t *)buf) = jfs_cfg->priority;
		break;
	case URMA_JFS_MAX_SGE:
		*((uint8_t *)buf) = jfs_cfg->max_sge;
		break;
	case URMA_JFS_MAX_RSGE:
		*((uint8_t *)buf) = jfs_cfg->max_rsge;
		break;
	case URMA_JFS_MAX_INLINE_DATA:
		*((uint32_t *)buf) = jfs_cfg->max_inline_data;
		break;
	case URMA_JFS_RNR_RETRY:
		*((uint8_t *)buf) = jfs_cfg->rnr_retry;
		break;
	case URMA_JFS_ERR_TIMEOUT:
		*((uint8_t *)buf) = jfs_cfg->err_timeout;
		break;
	case URMA_JFS_BIND_JFC:
		*((uint64_t *)buf) = (uint64_t)(uintptr_t)jfs_cfg->jfc;
		break;
	case URMA_JFS_USER_CTX:
		*((uint64_t *)buf) = jfs_cfg->user_ctx;
		break;
	default:
		break;
	}
}

static void udma_u_get_jetty_cfg_field(urma_jetty_cfg_t *jetty_cfg, uint64_t opt, void *buf)
{
	switch (opt) {
	case URMA_JETTY_ID:
		*((uint32_t *)buf) = jetty_cfg->id;
		break;
	case URMA_JETTY_FLAG:
		*((uint32_t *)buf) = jetty_cfg->flag.value;
		break;
	case URMA_JETTY_BIND_JFR:
		*((uint64_t *)buf) =
			(uint64_t)(uintptr_t)jetty_cfg->shared.jfr;
		break;
	case URMA_JETTY_BIND_RX_JFC:
		*((uint64_t *)buf) =
			(uint64_t)(uintptr_t)jetty_cfg->shared.jfc;
		break;
	case URMA_JETTY_BIND_JTG:
		*((uint64_t *)buf) = (uint64_t)(uintptr_t)jetty_cfg->jetty_grp;
		break;
	case URMA_JETTY_USER_CTX:
		*((uint64_t *)buf) = jetty_cfg->user_ctx;
		break;
	default:
		udma_u_get_jfs_cfg_field(&jetty_cfg->jfs_cfg, opt, buf);
		break;
	}
}

urma_status_t udma_u_get_jetty_opt(urma_jetty_t *jetty, uint64_t opt, void *buf, uint32_t len)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	urma_cmd_udrv_priv_t udata;
	urma_status_t urma_ret;
	int ret;

	urma_ret = udma_u_verify_jetty_opt(opt, buf, len, JETTY_MODE, PERM_R);
	if (urma_ret && urma_ret != URMA_EEXIST)
		return urma_ret;

	if (urma_ret != URMA_EEXIST) {
		ret = urma_cmd_get_jetty_opt(jetty, opt, buf, len, &udata);
		if (ret) {
			UDMA_LOG_ERR("get JETTY option failed, ret = %d.\n", ret);
			return URMA_FAIL;
		}
	}

	udma_u_get_jetty_field(&udma_jetty->sq, opt, buf);
	udma_u_get_jetty_cfg_field(&jetty->jetty_cfg, opt, buf);

	return URMA_SUCCESS;
}

static int udma_u_active_jetty_after(urma_jetty_t *jetty)
{
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	int ret;

	udma_jetty->sq.db.type = UDMA_MMAP_JETTY_DSQE;

	ret = udma_u_alloc_db(jetty->urma_ctx, &udma_jetty->sq.db);
	if (ret)
		return ret;

	udma_jetty->sq.dwqe_addr = (void *)udma_jetty->sq.db.addr;

	ret = insert_jetty_node(udma_jetty->sq.ctx, udma_jetty);
	if (ret)
		udma_u_free_db(jetty->urma_ctx, &udma_jetty->sq.db);

	return ret;
}

urma_status_t udma_u_active_jetty(urma_jetty_t *jetty)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jetty->urma_ctx);
	struct udma_u_jetty *udma_jetty = to_udma_u_jetty(jetty);
	urma_jetty_cfg_t *cfg = &jetty->jetty_cfg;
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	udma_jetty->sq.dtu_en = udma_ctx->dtu_enable;
	ret = udma_u_active_jetty_prepare(jetty, cfg);
	if (ret)
		return ret;

	udma_jetty->jetty_type = UDMA_URMA_EX_JETTY_TYPE;
	ret = exec_jetty_active_cmd(udma_jetty, cfg);
	if (ret) {
		if (udma_jetty->sq.dtu_en) {
			udma_jetty->sq.dtu_en = false;
			if (!udma_u_alloc_queue_buf(&udma_jetty->sq, udma_jetty->sq.sqe_bb_cnt * cfg->jfs_cfg.depth,
			    UDMA_JFS_WQEBB, udma_jetty->sq.aligned_size, true)) {
				UDMA_LOG_ERR("failed to alloc JETTY SQ after DTU failed.\n");
				goto err_active_jetty_cmd;
			}
			if (exec_jetty_active_cmd(udma_jetty, cfg))
				goto err_active_jetty_cmd;
		} else {
			UDMA_LOG_ERR("failed to create jetty.\n");
			goto err_active_jetty_cmd;
		}
	}

	ret = udma_u_active_jetty_after(jetty);
	if (ret)
		goto err_active_jetty_after;

	return URMA_SUCCESS;
err_active_jetty_after:
	urma_cmd_deactive_jetty(jetty, &udata);
err_active_jetty_cmd:
	udma_u_delete_sq(&udma_jetty->sq);
	remove_jetty_from_grp(udma_jetty);

	return URMA_FAIL;
}

urma_status_t udma_u_deactive_jetty(urma_jetty_t *jetty)
{
	urma_cmd_udrv_priv_t udata;
	int ret;

	ret = udma_u_delete_jetty_prepare(jetty);
	if (ret)
		return URMA_FAIL;

	ret = urma_cmd_deactive_jetty(jetty, &udata);
	if (ret) {
		UDMA_LOG_ERR("deactivate JETTY failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	udma_u_free_jetty_prepare(jetty);

	return URMA_SUCCESS;
}
