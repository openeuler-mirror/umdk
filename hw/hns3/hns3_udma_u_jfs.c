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
#include "hns3_udma_u_jetty.h"
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

static inline void enable_wqe(struct udma_qp *qp, void *sq_wqe, uint32_t index)
{
	struct udma_jfs_wqe *wqe = (struct udma_jfs_wqe *)sq_wqe;
	/*
	 * The pipeline can sequentially post all valid WQEs in wq buf,
	 * including those new WQEs waiting for doorbell to update the PI again.
	 * Therefore, the valid bit of WQE MUST be updated after all of fields
	 * and extSGEs have been written into DDR instead of cache.
	 */

	udma_reg_write_bool(wqe, UDMAWQE_OWNER, !(index & BIT(qp->sq.shift)));
}

static inline void *get_wqe(struct udma_qp *qp, uint32_t offset)
{
	if (qp->buf.buf)
		return (char *)qp->buf.buf + offset;
	else
		return NULL;
}

static void *get_send_wqe(struct udma_qp *qp, uint32_t n)
{
	return get_wqe(qp, qp->sq.offset + (n << qp->sq.wqe_shift));
}

static void *get_send_sge_ex(struct udma_qp *qp, uint32_t n)
{
	return get_wqe(qp, qp->ex_sge.offset + (n << qp->ex_sge.sge_shift));
}

static inline uint32_t udma_get_sgl_total_len(const urma_sg_t *sg)
{
	uint32_t len = 0;

	for (uint32_t i = 0; i < sg->num_sge; i++)
		len += sg->sge[i].len;

	return len;
}

static int udma_parse_write_wr(const urma_rw_wr_t *rw,
			       struct udma_jfs_wr_info *wr_info,
			       struct udma_sge *sg_list, bool is_inline)
{
	if (!rw->src.sge || !rw->dst.sge || !rw->dst.sge[0].tseg) {
		URMA_LOG_ERR("parse write wr failed, invalid rw parameters.\n");
		return EINVAL;
	}

	wr_info->num_sge = rw->src.num_sge;
	for (uint32_t i = 0; i < wr_info->num_sge; i++) {
		sg_list->len = rw->src.sge[i].len;
		sg_list->addr = rw->src.sge[i].addr;
		if (!is_inline) {
			if (!rw->src.sge[i].tseg) {
				URMA_LOG_ERR("parse write wr failed, tseg is null.\n");
				return EINVAL;
			}
			sg_list->lkey = rw->src.sge[i].tseg->seg.key_id;
		}
		sg_list++;
	}
	wr_info->dst_addr = rw->dst.sge[0].addr;
	wr_info->total_len = udma_get_sgl_total_len(&rw->src);
	wr_info->rkey = rw->dst.sge[0].tseg->seg.key_id;

	return 0;
}

static int udma_parse_send_wr(const urma_send_wr_t *send,
			      struct udma_jfs_wr_info *wr_info,
			      struct udma_sge *sg_list, bool is_inline)
{
	uint32_t total_length = 0;

	if (!send->src.sge) {
		URMA_LOG_ERR("parse send wr failed, invalid send parameters.\n");
		return EINVAL;
	}

	wr_info->num_sge = send->src.num_sge;
	for (uint32_t i = 0; i < wr_info->num_sge; i++) {
		sg_list->len = send->src.sge[i].len;
		if (!is_inline) {
			if (!send->src.sge[i].tseg) {
				URMA_LOG_ERR("parse send wr failed, tseg is null.\n");
				return EINVAL;
			}
			sg_list->lkey = send->src.sge[i].tseg->seg.key_id;
		}
		sg_list->addr = send->src.sge[i].addr;
		total_length += send->src.sge[i].len;
		sg_list++;
	}
	wr_info->total_len = total_length;

	return 0;
}

static int udma_parse_notify_params(urma_rw_wr_t *rw,
				    struct udma_jfs_wr_info *wr_info)
{
	if (rw->dst.sge) {
		if (rw->dst.sge[1].addr % NOTIFY_OFFSET_4B_ALIGN) {
			URMA_LOG_ERR("notify offset %uB should be aligned to 4B.\n",
				     rw->dst.sge[1].addr);
			return EINVAL;
		}
		wr_info->inv_key_immtdata = UDMA_GET_NOTIFY_DATA(rw->dst.sge[1].addr,
								 rw->notify_data);
	}

	return 0;
}

static int udma_parse_jfs_wr(urma_jfs_wr_t *wr, struct udma_jfs_wr_info *wr_info,
			     struct udma_sge *sg_list)
{
	bool is_inline = false;

	if (wr->flag.bs.inline_flag == 1)
		is_inline = true;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
		wr_info->opcode = UDMA_OPCODE_SEND;
		return udma_parse_send_wr(&wr->send, wr_info, sg_list, is_inline);
	case URMA_OPC_SEND_IMM:
		wr_info->opcode = UDMA_OPCODE_SEND_WITH_IMM;
		wr_info->inv_key_immtdata = wr->send.imm_data;
		return udma_parse_send_wr(&wr->send, wr_info, sg_list, is_inline);
	case URMA_OPC_SEND_INVALIDATE:
		if (!wr->send.tseg) {
			URMA_LOG_ERR("parse wr failed, tseg of send is null.\n");
			return EINVAL;
		}
		wr_info->opcode = UDMA_OPCODE_SEND_WITH_INV;
		wr_info->inv_key_immtdata = wr->send.tseg->seg.key_id;
		return udma_parse_send_wr(&wr->send, wr_info, sg_list, is_inline);
	case URMA_OPC_WRITE:
		wr_info->opcode = UDMA_OPCODE_RDMA_WRITE;
		return udma_parse_write_wr(&wr->rw, wr_info, sg_list, is_inline);
	case URMA_OPC_WRITE_IMM:
		wr_info->opcode = UDMA_OPCODE_RDMA_WRITE_WITH_IMM;
		wr_info->inv_key_immtdata = wr->rw.notify_data;
		return udma_parse_write_wr(&wr->rw, wr_info, sg_list, is_inline);
	case URMA_OPC_WRITE_NOTIFY:
		if (udma_parse_notify_params(&wr->rw, wr_info)) {
			URMA_LOG_ERR("parse wr failed, invalid notify parameters.\n");
			return EINVAL;
		}
		wr_info->opcode = UDMA_OPCODE_RDMA_WRITE_WITH_NOTIFY;
		return udma_parse_write_wr(&wr->rw, wr_info, sg_list, is_inline);
	case URMA_OPC_READ:
	case URMA_OPC_CAS:
	case URMA_OPC_CAS_WITH_MASK:
	case URMA_OPC_FAA:
	case URMA_OPC_FAA_WITH_MASK:
		URMA_LOG_ERR("Alpha doesn't support opcode :%u\n",
			     (uint32_t)wr->opcode);
		return EINVAL;
	case URMA_OPC_NOP:
	case URMA_OPC_LAST:
	default:
		URMA_LOG_ERR("Invalid opcode :%u\n", (uint32_t)wr->opcode);
		return EINVAL;
	}
}

static inline void set_data_seg(struct udma_wqe_data_seg *dseg,
				struct udma_sge *sg_list)
{
	dseg->lkey = htole32(sg_list->lkey);
	dseg->addr = htole64(sg_list->addr);
	dseg->len = htole32(sg_list->len);
}

static void set_rc_sge(struct udma_wqe_data_seg *dseg, struct udma_qp *qp,
		       uint32_t num_sge, struct udma_sge *sg_list,
		       struct udma_sge_info *sge_info)
{
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		if (i < UDMA_SGE_IN_WQE) {
			set_data_seg(dseg, sg_list + i);
			dseg++;
		} else {
			dseg = (struct udma_wqe_data_seg *)
				get_send_sge_ex(qp, sge_info->start_idx &
						(qp->ex_sge.sge_cnt - 1));
			set_data_seg(dseg, sg_list + i);
			sge_info->start_idx++;
		}
	}
}

void set_um_sge(struct udma_qp *qp, uint32_t num_sge,
		struct udma_sge *sg_list, struct udma_sge_info *sge_info)
{
	struct udma_wqe_data_seg *dseg;
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		dseg = (struct udma_wqe_data_seg *)
			get_send_sge_ex(qp, sge_info->start_idx &
					(qp->ex_sge.sge_cnt - 1));
		set_data_seg(dseg, sg_list + i);
		sge_info->start_idx++;
	}
}

static uint32_t mtu_enum_to_int(urma_mtu_t mtu)
{
	switch (mtu) {
	case URMA_MTU_256:
		return UDMA_MTU_NUM_256;
	case URMA_MTU_512:
		return UDMA_MTU_NUM_512;
	case URMA_MTU_1024:
		return UDMA_MTU_NUM_1024;
	case URMA_MTU_2048:
		return UDMA_MTU_NUM_2048;
	case URMA_MTU_4096:
		return UDMA_MTU_NUM_4096;
	case URMA_MTU_8192:
		return UDMA_MTU_NUM_8192;
	default:
		return 0;
	}
}

static bool check_inl_data_len(struct udma_qp *qp, uint32_t len)
{
	uint32_t mtu = mtu_enum_to_int(qp->path_mtu);

	return (len <= qp->max_inline_data && len <= mtu);
}

static void get_src_buf_info(void **src_addr, uint32_t *src_len,
			     struct udma_sge *sg_list, int buf_idx)
{
	*src_addr = (void *)(uintptr_t)sg_list[buf_idx].addr;
	*src_len = sg_list[buf_idx].len;
}

static urma_status_t fill_ext_sge_inl_data(struct udma_qp *qp,
					   struct udma_sge_info *sge_info,
					   struct udma_sge *sg_list,
					   uint32_t num_buf)
{
	uint32_t sge_sz = sizeof(struct udma_wqe_data_seg);
	void *dst_addr, *src_addr, *tail_bound_addr;
	uint32_t sge_mask = qp->ex_sge.sge_cnt - 1;
	uint32_t src_len, tail_len;
	uint32_t i;

	if (sge_info->total_len > qp->sq.ext_sge_cnt * sge_sz)
		return URMA_EINVAL;

	dst_addr = get_send_sge_ex(qp, sge_info->start_idx & sge_mask);
	tail_bound_addr = get_send_sge_ex(qp, qp->ex_sge.sge_cnt);

	for (i = 0; i < num_buf; i++) {
		tail_len = (uintptr_t)tail_bound_addr - (uintptr_t)dst_addr;
		get_src_buf_info(&src_addr, &src_len, sg_list, i);

		if (src_len < tail_len) {
			memcpy(dst_addr, src_addr, src_len);
			dst_addr = (char *)dst_addr + src_len;
		} else if (src_len == tail_len) {
			memcpy(dst_addr, src_addr, src_len);
			dst_addr = get_send_sge_ex(qp, 0);
		} else {
			memcpy(dst_addr, src_addr, tail_len);
			dst_addr = get_send_sge_ex(qp, 0);
			src_addr = (char *)src_addr + tail_len;
			src_len -= tail_len;

			memcpy(dst_addr, src_addr, src_len);
			dst_addr = (char *)dst_addr + src_len;
		}
	}

	sge_info->valid_num = DIV_ROUND_UP(sge_info->total_len, sge_sz);
	sge_info->start_idx += sge_info->valid_num;

	return URMA_SUCCESS;
}

static urma_status_t set_rc_inl(struct udma_qp *qp, struct udma_jfs_wr_info *wr_info,
				struct udma_jfs_wqe *wqe,
				struct udma_sge_info *sge_info,
				struct udma_sge *sg_list)
{
	urma_status_t ret;
	void *dseg = wqe;
	uint32_t i;

	if (wr_info->opcode == UDMA_OPCODE_RDMA_READ) {
		URMA_LOG_ERR("send inline not support opcode READ\n");
		return URMA_EINVAL;
	}

	if (!check_inl_data_len(qp, sge_info->total_len)) {
		URMA_LOG_ERR("Invalid inline data len 0x%x, max inline data len 0x%x, mtu 0x%x\n",
			     sge_info->total_len, qp->max_inline_data, qp->path_mtu);
		return URMA_EINVAL;
	}

	dseg = (char *)dseg + sizeof(struct udma_jfs_wqe);

	if (sge_info->total_len <= UDMA_MAX_RC_INL_INN_SZ) {
		udma_reg_clear(wqe, UDMAWQE_INLINE_TYPE);

		for (i = 0; i < wr_info->num_sge; i++) {
			memcpy(dseg, (void *)(uintptr_t)(sg_list[i].addr),
			       sg_list[i].len);
			dseg = (char *)dseg + sg_list[i].len;
		}
	} else {
		udma_reg_enable(wqe, UDMAWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, sge_info, sg_list,
					    wr_info->num_sge);
		if (ret) {
			URMA_LOG_ERR("Fill extra sge fail\n");
			return ret;
		}

		udma_reg_write(wqe, UDMAWQE_SGE_NUM, sge_info->valid_num);
	}

	return URMA_SUCCESS;
}

static void set_um_inl_seg(struct udma_jfs_um_wqe *wqe, uint8_t *data)
{
	uint32_t *loc = (uint32_t *)data;
	uint32_t tmp_data;

	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_15_0, *loc & 0xffff);
	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_23_16,
		      (*loc >> UDMAUMWQE_INLINE_SHIFT2) & 0xff);

	tmp_data = *loc >> UDMAUMWQE_INLINE_SHIFT3;
	loc++;
	tmp_data |= ((*loc & 0xffff) << UDMAUMWQE_INLINE_SHIFT1);

	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_47_24, tmp_data);
	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_63_48,
		      *loc >> UDMAUMWQE_INLINE_SHIFT2);
}

static void fill_ud_inn_inl_data(struct udma_jfs_wr_info *wr_info,
				 struct udma_jfs_um_wqe *wqe,
				 struct udma_sge *sg_list)
{
	uint8_t data[UDMA_MAX_UM_INL_INN_SZ] = {};
	void *tmp = data;
	uint32_t i;

	for (i = 0; i < wr_info->num_sge; i++) {
		memcpy(tmp, (void *)(uintptr_t)sg_list[i].addr, sg_list[i].len);
		tmp += sg_list[i].len;
	}

	set_um_inl_seg(wqe, data);
}

static urma_status_t set_um_inl(struct udma_qp *qp,
				struct udma_jfs_wr_info *wr_info,
				struct udma_jfs_um_wqe *wqe,
				struct udma_sge_info *sge_info,
				struct udma_sge *sg_list)
{
	urma_status_t ret;

	if (!check_inl_data_len(qp, sge_info->total_len)) {
		URMA_LOG_ERR("Invalid inline data len 0x%x, max inline data len 0x%x, mtu 0x%x\n",
			     sge_info->total_len, qp->max_inline_data,
			     qp->path_mtu);
		return URMA_EINVAL;
	}

	if (sge_info->total_len <= UDMA_MAX_UM_INL_INN_SZ) {
		udma_reg_clear(wqe, UDMAUMWQE_INLINE_TYPE);

		fill_ud_inn_inl_data(wr_info, wqe, sg_list);
	} else {
		udma_reg_enable(wqe, UDMAUMWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, sge_info, sg_list,
					    wr_info->num_sge);
		if (ret) {
			URMA_LOG_ERR("Fill extra sge fail\n");
			return ret;
		}

		udma_reg_write(wqe, UDMAUMWQE_SGE_NUM, sge_info->valid_num);
	}

	return URMA_SUCCESS;
}

static void udma_set_um_wqe_udpspn(struct udma_jfs_um_wqe *jfs_wqe,
				   struct udma_qp *qp)
{
	uint16_t data_udp_start_l, data_udp_start_h;

	udma_reg_write(jfs_wqe, UDMAUMWQE_UDPSPN, qp->um_srcport.um_data_udp_start);
	data_udp_start_l = (qp->um_srcport.um_data_udp_start + 1) &
			   (BIT(qp->um_srcport.um_udp_range) - 1);
	data_udp_start_h = qp->um_srcport.um_data_udp_start >>
			   qp->um_srcport.um_udp_range;
	qp->um_srcport.um_data_udp_start = data_udp_start_l |
					   data_udp_start_h <<
					   qp->um_srcport.um_udp_range;
}

static urma_status_t udma_set_um_wqe(struct udma_u_context *udma_ctx, void *wqe,
			     struct udma_qp *qp, urma_jfs_wr_t *wr,
			     struct udma_sge_info *sge_info)
{
	struct udma_jfs_um_wqe *jfs_wqe = (struct udma_jfs_um_wqe *)wqe;
	struct udma_sge sg_list[UDMA_MAX_SGE_NUM];
	struct udma_jfs_wr_info wr_info = {};
	urma_status_t ret = URMA_SUCCESS;
	uint32_t qpn, qpn_shift;

	memset(jfs_wqe, 0, sizeof(struct udma_jfs_um_wqe));

	wr_info.num_sge = 1;

	if (udma_parse_jfs_wr(wr, &wr_info, &sg_list[0]) != 0) {
		URMA_LOG_ERR("Failed to parse wr\n");
		return URMA_EINVAL;
	}

	sge_info->total_len = wr_info.total_len;
	if (sge_info->total_len == 0)
		wr_info.num_sge = 0;

	udma_reg_write(jfs_wqe, UDMAUMWQE_OPCODE, wr_info.opcode);
	udma_reg_write_bool(jfs_wqe, UDMAUMWQE_CQE, wr->flag.bs.complete_enable);
	udma_reg_write_bool(jfs_wqe, UDMAUMWQE_SE, wr->flag.bs.solicited_enable);
	udma_reg_write_bool(jfs_wqe, UDMAUMWQE_INLINE, wr->flag.bs.inline_flag);
	udma_reg_write(jfs_wqe, UDMAUMWQE_MSG_START_SGE_IDX, sge_info->start_idx &
		       (qp->ex_sge.sge_cnt - 1));
	udma_reg_write(jfs_wqe, UDMAUMWQE_IMMT_DATA,
		       (uint32_t)(wr_info.inv_key_immtdata));
	udma_reg_write(jfs_wqe, UDMAUMWQE_SGE_NUM, wr_info.num_sge);
	udma_reg_write(jfs_wqe, UDMAUMWQE_HOPLIMIT, UDMA_HOPLIMIT_NUM);

	qpn_shift = udma_ctx->num_qps_shift - UDMA_JETTY_X_PREFIX_BIT_NUM -
		    udma_ctx->num_jetty_shift;
	if (is_jetty(udma_ctx, qp->qp_num)) {
		qpn = gen_qpn(UDMA_JETTY_QPN_PREFIX <<
			      (udma_ctx->num_qps_shift - UDMA_JETTY_X_PREFIX_BIT_NUM),
			      wr->tjetty->id.id << qpn_shift, 0);
		udma_reg_write(jfs_wqe, UDMAUMWQE_DGID_H,
			       *(uint32_t *)(wr->tjetty->id.eid.raw + GID_H_SHIFT));
	} else {
		qpn = gen_qpn(UDMA_JFR_QPN_PREFIX <<
			      (udma_ctx->num_qps_shift - UDMA_JETTY_X_PREFIX_BIT_NUM),
			      wr->tjetty->id.id << qpn_shift, 0);
		udma_reg_write(jfs_wqe, UDMAUMWQE_DGID_H,
			       *(uint32_t *)(wr->tjetty->id.eid.raw + GID_H_SHIFT));
	}

	if (qp->um_srcport.um_spray_en)
		udma_set_um_wqe_udpspn(jfs_wqe, qp);

	udma_reg_write(jfs_wqe, UDMAUMWQE_DQPN, qpn);
	udma_reg_write(jfs_wqe, UDMAUMWQE_MSG_LEN, htole32(sge_info->total_len));

	if (wr->flag.bs.inline_flag == 1)
		ret = set_um_inl(qp, &wr_info, jfs_wqe, sge_info, &sg_list[0]);
	else
		set_um_sge(qp, wr_info.num_sge, &sg_list[0], sge_info);

	enable_wqe(qp, wqe, qp->sq.head);

	return ret;
}

static urma_status_t udma_set_rm_wqe(void *wqe, struct udma_qp *qp, urma_jfs_wr_t *wr,
			   struct udma_sge_info *sge_info)
{
	struct udma_sge sg_list[UDMA_MAX_SGE_NUM];
	struct udma_jfs_wr_info wr_info = {};
	urma_status_t ret = URMA_SUCCESS;
	struct udma_wqe_data_seg *dseg;
	struct udma_jfs_wqe *jfs_wqe;

	jfs_wqe = (struct udma_jfs_wqe *)wqe;
	dseg = (struct udma_wqe_data_seg *)(jfs_wqe + 1);

	wr_info.num_sge = 1;

	if (udma_parse_jfs_wr(wr, &wr_info, &sg_list[0]) != 0) {
		URMA_LOG_ERR("Failed to parse wr\n");
		return URMA_EINVAL;
	}

	udma_reg_write(jfs_wqe, UDMAWQE_OPCODE, wr_info.opcode);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_CQE, wr->flag.bs.complete_enable);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_FENCE, wr->flag.bs.fence);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_SE, wr->flag.bs.solicited_enable);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_INLINE, wr->flag.bs.inline_flag);
	udma_reg_write(jfs_wqe, UDMAWQE_MSG_START_SGE_IDX,
		       sge_info->start_idx & (qp->ex_sge.sge_cnt - 1));
	udma_reg_write(jfs_wqe, UDMAWQE_INV_KEY_IMMTDATA,
		       (uint32_t)(wr_info.inv_key_immtdata));

	sge_info->valid_num = wr_info.num_sge;
	sge_info->total_len = wr_info.total_len;
	if (sge_info->total_len == 0)
		sge_info->valid_num = 0;
	jfs_wqe->va = htole64(wr_info.dst_addr);
	jfs_wqe->msg_len = htole32(sge_info->total_len);
	jfs_wqe->rkey = htole32(wr_info.rkey);
	udma_reg_write(jfs_wqe, UDMAWQE_SGE_NUM, sge_info->valid_num);

	if (wr->flag.bs.inline_flag == 1)
		ret = set_rc_inl(qp, &wr_info, jfs_wqe, sge_info, &sg_list[0]);
	else
		set_rc_sge(dseg, qp, wr_info.num_sge, &sg_list[0], sge_info);

	enable_wqe(qp, wqe, qp->sq.head);

	return ret;
}

static int udma_wq_overflow(struct udma_wq *wq, struct udma_cq *cq)
{
	uint32_t cur;

	cur = wq->head - wq->tail;
	if (cur < wq->wqe_cnt)
		return 0;

	pthread_spin_lock(&cq->udma_lock.lock);
	cur = wq->head - wq->tail;
	pthread_spin_unlock(&cq->udma_lock.lock);

	return cur >= wq->wqe_cnt;
}

static void udma_write512(uint64_t *dest, uint64_t *val)
{
	mmio_memcpy_x64(dest, val, sizeof(uint64x2x4_t));
}

static void udma_write_dwqe(struct udma_u_context *ctx, struct udma_qp *qp,
			    void *wqe)
{
#define PRIORITY_OFFSET 2
	struct udma_reset_state *state = (struct udma_reset_state *)ctx->reset_state;
	struct udma_jfs_wqe *udma_wqe = (struct udma_jfs_wqe *)wqe;

	if (state && state->is_reset)
		return;

	/* All kinds of DirectWQE have the same header field layout */
	udma_reg_enable(udma_wqe, UDMAWQE_FLAG);
	udma_reg_write(udma_wqe, UDMAWQE_DB_SL_L, qp->sq.priority);
	udma_reg_write(udma_wqe, UDMAWQE_DB_SL_H, qp->sq.priority >> PRIORITY_OFFSET);
	udma_reg_write(udma_wqe, UDMAWQE_WQE_IDX, qp->sq.head);

	udma_write512((uint64_t *)qp->dwqe_page, (uint64_t *)wqe);
}

static void udma_update_sq_db(struct udma_u_context *ctx, struct udma_qp *qp)
{
	struct udma_u_db sq_db = {};

	udma_reg_write(&sq_db, UDMA_DB_TAG, qp->qp_num);
	udma_reg_write(&sq_db, UDMA_DB_CMD, UDMA_SQ_DB);
	udma_reg_write(&sq_db, UDMA_DB_PI, qp->sq.head);
	udma_reg_write(&sq_db, UDMA_DB_SL, qp->sq.priority);

	udma_write64(ctx, (uint64_t *)(ctx->uar + UDMA_DB_CFG0_OFFSET),
		     (uint64_t *)&sq_db);
}

static struct udma_qp *get_qp(struct udma_u_jfs *udma_jfs, urma_jfs_wr_t *wr)
{
	struct udma_hmap_node *hmap_node = NULL;
	struct connect_node *udma_connect_node;
	struct udma_qp *udma_qp = NULL;
	uint32_t tjfr_index;

	if (!wr->tjetty) {
		URMA_LOG_ERR("Failed to get jfs qp, tjetty of wr is null.\n");
		return NULL;
	}

	if (udma_jfs->tp_mode == URMA_TM_UM)
		return udma_jfs->um_qp;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
	case URMA_OPC_SEND_IMM:
	case URMA_OPC_SEND_INVALIDATE:
	case URMA_OPC_WRITE:
	case URMA_OPC_WRITE_IMM:
	case URMA_OPC_WRITE_NOTIFY:
		tjfr_index = udma_get_tgt_hash(&wr->tjetty->id);
		hmap_node = udma_table_first_with_hash(&udma_jfs->tjfr_tbl.hmap,
						       &udma_jfs->tjfr_tbl.rwlock,
						       tjfr_index);
		break;
	case URMA_OPC_READ:
	case URMA_OPC_CAS:
	case URMA_OPC_CAS_WITH_MASK:
	case URMA_OPC_FAA:
	case URMA_OPC_FAA_WITH_MASK:
		URMA_LOG_ERR("Alpha doesn't support opcode :%u\n",
			     (uint32_t)wr->opcode);
		return NULL;
	case URMA_OPC_NOP:
	case URMA_OPC_LAST:
	default:
		URMA_LOG_ERR("Invalid opcode: %u\n", (uint32_t)wr->opcode);
		return NULL;
	}

	if (!hmap_node)
		return NULL;

	udma_connect_node = CONTAINER_OF_FIELD(hmap_node, struct connect_node,
					       hmap_node);
	udma_qp = udma_connect_node->qp;

	return udma_qp;
}

static int exec_jfs_flush_cqe_cmd(struct udma_u_context *udma_ctx,
				  struct udma_qp *qp)
{
	urma_context_t *ctx = &udma_ctx->urma_ctx;
	struct flush_cqe_param fcp = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_USER_CTL_FLUSH_CQE;
	in.addr = (uint64_t)&fcp;
	in.len = (uint32_t)sizeof(struct flush_cqe_param);

	fcp.qpn = qp->qp_num;
	fcp.sq_producer_idx = qp->sq.head;

	return urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
}

urma_status_t udma_u_post_qp_wr(struct udma_u_context *udma_ctx,
				struct udma_qp *udma_qp,
				urma_jfs_wr_t *wr,
				urma_transport_mode_t tp_mode)
{
	struct udma_sge_info sge_info = {};
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;
	void *wqe;

	sge_info.start_idx = udma_qp->next_sge;
	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		URMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}
	if (udma_wq_overflow(&udma_qp->sq, &udma_qp->verbs_qp.cq)) {
		URMA_LOG_ERR("JFS overflow.\n");
		ret = URMA_ENOMEM;
		goto out;
	}
	wqe_idx = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	wqe = get_send_wqe(udma_qp, wqe_idx);
	udma_qp->sq.wrid[wqe_idx] = wr->user_ctx;

	if (tp_mode == URMA_TM_UM)
		ret = udma_set_um_wqe(udma_ctx, wqe, udma_qp, wr, &sge_info);
	else
		ret = udma_set_rm_wqe(wqe, udma_qp, wr, &sge_info);
	if (ret)
		goto out;

	udma_qp->sq.head += 1;
	udma_qp->next_sge = sge_info.start_idx;

	udma_to_device_barrier();

	if (udma_qp->flags & UDMA_QP_CAP_DIRECT_WQE)
		udma_write_dwqe(udma_ctx, udma_qp, wqe);
	else
		udma_update_sq_db(udma_ctx, udma_qp);

	*udma_qp->sdb = udma_qp->sq.head;
	if (udma_qp->flush_status == UDMA_FLUSH_STATUS_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

out:
	return ret;
}

urma_status_t udma_u_post_jfs_wr(const urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				 urma_jfs_wr_t **bad_wr)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	struct udma_qp *udma_qp;
	urma_status_t ret;
	urma_jfs_wr_t *it;

	udma_jfs = to_udma_jfs(jfs);
	udma_ctx = to_udma_ctx(jfs->urma_ctx);

	if (!udma_jfs->lock_free)
		(void)pthread_spin_lock(&udma_jfs->lock);

	for (it = wr; it != NULL; it = (urma_jfs_wr_t *)(void *)it->next) {
		udma_qp = get_qp(udma_jfs, it);
		if (udma_qp == NULL) {
			URMA_LOG_ERR("failed to get qp, opcode = 0x%x.\n",
				     it->opcode);
			ret = URMA_EINVAL;
			*bad_wr = (urma_jfs_wr_t *)it;
			goto out;
		}

		ret = udma_u_post_qp_wr(udma_ctx, udma_qp, it, udma_jfs->tp_mode);
		if (ret) {
			*bad_wr = (urma_jfs_wr_t *)it;
			goto out;
		}
	}
out:
	if (!udma_jfs->lock_free)
		(void)pthread_spin_unlock(&udma_jfs->lock);

	return ret;
}

static urma_status_t udma_u_post_qp_wr_ex(struct udma_u_context *udma_ctx,
					  struct udma_qp *udma_qp,
					  urma_jfs_wr_t *wr,
					  urma_transport_mode_t tp_mode)
{
	struct udma_sge_info sge_info = {};
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;
	void *wqe;

	sge_info.start_idx = udma_qp->next_sge;
	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		URMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}
	if (udma_wq_overflow(&udma_qp->sq, &udma_qp->verbs_qp.cq)) {
		URMA_LOG_ERR("JFS overflow. pi = %d, ci = %d.\n",
			     udma_qp->sq.head, udma_qp->sq.tail);
		ret = URMA_ENOMEM;
		goto out;
	}
	wqe_idx = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	wqe = get_send_wqe(udma_qp, wqe_idx);
	udma_qp->sq.wrid[wqe_idx] = wr->user_ctx;

	if (tp_mode == URMA_TM_UM)
		ret = udma_set_um_wqe(udma_ctx, wqe, udma_qp, wr, &sge_info);
	else
		ret = udma_set_rm_wqe(wqe, udma_qp, wr, &sge_info);
	if (ret)
		goto out;

	udma_qp->sq.head += 1;
	udma_qp->next_sge = sge_info.start_idx;

	udma_to_device_barrier();

	if (udma_qp->flush_status == UDMA_FLUSH_STATUS_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

out:
	return ret;
}

int udma_u_post_jfs_wr_ex(const urma_context_t *ctx,
			  urma_user_ctl_in_t *in,
			  urma_user_ctl_out_t *out)
{
	urma_post_and_ret_db_out_t ex_out;
	urma_status_t ret = URMA_SUCCESS;
	urma_post_and_ret_db_in_t ex_in;
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	struct udma_qp *udma_qp;
	urma_jfs_wr_t **it;

	memcpy(&ex_in, (void *)in->addr, in->len);
	if (ex_in.wr == NULL) {
		URMA_LOG_ERR("wr of ex_in is NULL!\n");
		return EINVAL;
	}

	udma_jfs = to_udma_jfs(ex_in.jfs);
	udma_ctx = to_udma_ctx((urma_context_t *)ctx);

	if (!udma_jfs->lock_free)
		(void)pthread_spin_lock(&udma_jfs->lock);

	for (it = &ex_in.wr; *it != NULL; *it = (*it)->next) {
		udma_qp = get_qp(udma_jfs, *it);
		if (udma_qp == NULL) {
			URMA_LOG_ERR("Failed to get qp, opcode = 0x%x.\n",
				     (*it)->opcode);
			ret = URMA_EINVAL;
			ex_out.bad_wr = it;
			goto out;
		}

		ret = udma_u_post_qp_wr_ex(udma_ctx, udma_qp, *it, udma_jfs->tp_mode);
		if (ret) {
			ex_out.bad_wr = it;
			goto out;
		}
	}

	ex_out.db_addr = (uint64_t)(udma_ctx->db_addr);
	ex_out.db_data = (uint64_t)udma_qp->qp_num;
	memcpy((void *)out->addr, &ex_out, out->len);
out:
	if (!udma_jfs->lock_free)
		(void)pthread_spin_unlock(&udma_jfs->lock);

	return ret == URMA_SUCCESS ? 0 : EINVAL;
}
