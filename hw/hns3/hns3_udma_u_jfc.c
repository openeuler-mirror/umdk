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

#include <math.h>
#include <unistd.h>
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfr.h"
#include "hns3_udma_u_jfc.h"

static int check_jfc_cfg(struct udma_u_context *udma_ctx, urma_jfc_cfg_t *cfg)
{
	if (!cfg->depth || roundup_pow_of_two(cfg->depth) > udma_ctx->max_jfc_cqe) {
		URMA_LOG_ERR("invalid jfc cfg, cfg->depth = %d, udma_ctx->max_jfc_cqe = %d.\n",
			     cfg->depth, udma_ctx->max_jfc_cqe);
		return EINVAL;
	}

	return 0;
}

static void set_jfc_size(struct udma_u_context *udma_ctx, struct udma_u_jfc *jfc,
			 urma_jfc_cfg_t *cfg)
{
	jfc->cqe_cnt = roundup_pow_of_two(cfg->depth);
	jfc->cqe_size = udma_ctx->cqe_size;
	jfc->cqe_shift = udma_ilog32(udma_ctx->cqe_size);
}

static int alloc_jfc_buf(struct udma_u_jfc *jfc)
{
	int buf_size = to_udma_hem_entries_size(jfc->cqe_cnt, jfc->cqe_shift);

	return udma_alloc_buf(&jfc->buf, buf_size, UDMA_HW_PAGE_SIZE);
}

static int udma_u_check_notify_attr(struct udma_jfc_notify_init_attr *notify_attr)
{
	switch (notify_attr->notify_mode) {
	case UDMA_JFC_NOTIFY_MODE_4B_ALIGN:
	case UDMA_JFC_NOTIFY_MODE_DDR_4B_ALIGN:
		break;
	case UDMA_JFC_NOTIFY_MODE_64B_ALIGN:
	case UDMA_JFC_NOTIFY_MODE_DDR_64B_ALIGN:
		URMA_LOG_ERR("Doesn't support notify mode %u\n",
			     notify_attr->notify_mode);
		return EINVAL;
	default:
		URMA_LOG_ERR("Invalid notify mode %u\n",
			     notify_attr->notify_mode);
		return EINVAL;
	}

	if (notify_attr->notify_addr & UDMA_ADDR_4K_MASK) {
		URMA_LOG_ERR("Notify addr should be aligned to 4k.\n",
			     notify_attr->notify_addr);
		return EINVAL;
	}

	return 0;
}

static int udma_u_check_jfc_attr_ex(struct udma_jfc_init_attr *attr)
{
	int ret = 0;

	if (attr->jfc_ex_mask != UDMA_JFC_NOTIFY_OR_POE_CREATE_FLAGS) {
		URMA_LOG_ERR("Invalid comp mask %u\n", attr->jfc_ex_mask);
		return EINVAL;
	}

	switch (attr->create_flags) {
	case UDMA_JFC_CREATE_ENABLE_POE_MODE:
		break;
	case UDMA_JFC_CREATE_ENABLE_NOTIFY:
		ret = udma_u_check_notify_attr(&attr->notify_init_attr);
		break;
	default:
		URMA_LOG_ERR("Invalid create flags %u\n", attr->create_flags);
		return EINVAL;
	}

	return ret;
}

static struct udma_u_jfc *udma_u_create_jfc_common(urma_jfc_cfg_t *cfg,
						   struct udma_u_context *udma_ctx)
{
	struct udma_u_jfc *jfc;

	if (check_jfc_cfg(udma_ctx, cfg))
		goto err;

	jfc = (struct udma_u_jfc *)calloc(1, sizeof(*jfc));
	if (!jfc) {
		URMA_LOG_ERR("alloc udma_ctx memory failed.\n");
		goto err;
	}

	jfc->lock_free = cfg->flag.bs.lock_free;
	if (!jfc->lock_free &&
	    pthread_spin_init(&jfc->lock, PTHREAD_PROCESS_PRIVATE)) {
		URMA_LOG_ERR("alloc udma_ctx spinlock failed.\n");
		goto err_lock;
	}

	set_jfc_size(udma_ctx, jfc, cfg);
	if (alloc_jfc_buf(jfc))
		goto err_buf;

	jfc->db = (uint32_t *)udma_alloc_sw_db(udma_ctx, UDMA_JFC_TYPE_DB);
	if (!jfc->db)
		goto err_db;

	return jfc;

err_db:
	udma_free_buf(&jfc->buf);
err_buf:
	if (!jfc->lock_free)
		pthread_spin_destroy(&jfc->lock);
err_lock:
	free(jfc);
err:
	return NULL;
}

static void free_err_jfc(struct udma_u_jfc *jfc, struct udma_u_context *udma_ctx)
{
	udma_free_sw_db(udma_ctx, jfc->db, UDMA_JFC_TYPE_DB);
	udma_free_buf(&jfc->buf);
	pthread_spin_destroy(&jfc->lock);
	free(jfc);
}

urma_jfc_t *udma_u_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_create_jfc_resp resp = {};
	struct udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	struct udma_u_jfc *jfc;
	int ret;

	jfc = udma_u_create_jfc_common(cfg, udma_ctx);
	if (!jfc)
		return NULL;

	cmd.buf_addr = (uintptr_t)jfc->buf.buf;
	cmd.db_addr = (uintptr_t)jfc->db;
	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfc(ctx, &jfc->urma_jfc, cfg, &udata);
	if (ret) {
		URMA_LOG_ERR("urma cmd create jfc failed, ret = %d.\n", ret);
		free_err_jfc(jfc, udma_ctx);
		return NULL;
	}
	jfc->ci = 0;
	jfc->arm_sn = 1;
	jfc->cqn = jfc->urma_jfc.jfc_id.id;
	jfc->caps_flag = resp.jfc_caps;

	return &jfc->urma_jfc;
}

static urma_jfc_t *create_jfc_ex(urma_context_t *ctx,
				 struct udma_create_jfc_ex *cfg_ex)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_create_jfc_resp resp = {};
	struct udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	struct udma_u_jfc *jfc;
	int ret;

	jfc = udma_u_create_jfc_common(cfg_ex->cfg, udma_ctx);
	if (!jfc)
		return NULL;

	cmd.buf_addr = (uintptr_t)jfc->buf.buf;
	cmd.db_addr = (uintptr_t)jfc->db;
	cmd.jfc_attr_ex.jfc_ex_mask = cfg_ex->attr->jfc_ex_mask;
	cmd.jfc_attr_ex.create_flags = cfg_ex->attr->create_flags;
	cmd.jfc_attr_ex.poe_channel = cfg_ex->attr->poe_channel;
	cmd.jfc_attr_ex.notify_addr = cfg_ex->attr->notify_init_attr.notify_addr;
	cmd.jfc_attr_ex.notify_mode = cfg_ex->attr->notify_init_attr.notify_mode;
	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfc(ctx, &jfc->urma_jfc, cfg_ex->cfg, &udata);
	if (ret) {
		URMA_LOG_ERR("urma cmd create jfc failed.\n");
		free_err_jfc(jfc, udma_ctx);
		return NULL;
	}
	jfc->ci = 0;
	jfc->arm_sn = 1;
	jfc->cqn = jfc->urma_jfc.jfc_id.id;
	jfc->caps_flag = resp.jfc_caps;

	return &jfc->urma_jfc;
}

int udma_u_create_jfc_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			 urma_user_ctl_out_t *out)
{
	struct udma_create_jfc_ex cfg_ex;
	urma_jfc_t *jfc;
	int ret;

	memcpy(&cfg_ex, (void *)in->addr, in->len);

	ret = udma_u_check_jfc_attr_ex(cfg_ex.attr);
	if (ret) {
		URMA_LOG_ERR("Invalid jfc attr ex\n");
		return EINVAL;
	}

	jfc = create_jfc_ex((urma_context_t *)ctx, &cfg_ex);
	if (jfc == NULL)
		return EFAULT;

	memcpy((void *)out->addr, &jfc, sizeof(urma_jfc_t *));

	return 0;
}

urma_status_t udma_u_delete_jfc(urma_jfc_t *jfc)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_jfc = to_udma_jfc(jfc);
	int ret;

	if (udma_jfc->reserved_jfr) {
		ret = udma_u_delete_jfr(&udma_jfc->reserved_jfr->urma_jfr);
		if (ret) {
			URMA_LOG_ERR("delete reserved jfr of jfc failed, \
				     ret:%d, errno:%d.\n", ret, errno);
			return URMA_FAIL;
		}
	}

	ret = urma_cmd_delete_jfc(jfc);
	if (ret) {
		URMA_LOG_ERR("delete jfc failed, ret:%d, errno:%d.\n",
			     ret, errno);
		return URMA_FAIL;
	}

	udma_free_sw_db(udma_ctx, udma_jfc->db, UDMA_JFC_TYPE_DB);
	udma_free_buf(&udma_jfc->buf);
	pthread_spin_destroy(&udma_jfc->lock);
	free(udma_jfc);

	return URMA_SUCCESS;
}

int udma_u_delete_jfc_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
			 urma_user_ctl_out_t *out)
{
	urma_status_t ret;
	urma_jfc_t *jfc;

	memcpy(&jfc, (void *)in->addr, in->len);

	ret = udma_u_delete_jfc(jfc);
	if (ret)
		return EFAULT;

	return 0;
}

static struct udma_jfc_cqe *get_cqe(struct udma_u_jfc *jfc, int n)
{
	return (struct udma_jfc_cqe *)((char *)jfc->buf.buf + n * jfc->cqe_size);
}

static void *get_sw_cqe(struct udma_u_jfc *jfc, int n)
{
	struct udma_jfc_cqe *cqe = get_cqe(jfc, n & (jfc->cqe_cnt - 1));

	return (udma_reg_read(cqe, CQE_OWNER) ^ (!!(n & jfc->cqe_cnt))) ? cqe : NULL;
}

static struct udma_jfc_cqe *next_cqe_sw(struct udma_u_jfc *jfc)
{
	return (struct udma_jfc_cqe *)get_sw_cqe(jfc, jfc->ci);
}

static enum urma_cr_status get_cr_status(uint8_t status)
{
	static const struct {
		uint32_t cqe_status;
		enum urma_cr_status cr_status;
	} map[] = {
		{ UDMA_CQE_SUCCESS, URMA_CR_SUCCESS },
		{ UDMA_CQE_LOCAL_LENGTH_ERR, URMA_CR_LOC_LEN_ERR },
		{ UDMA_CQE_LOCAL_QP_OP_ERR, URMA_CR_LOC_OPERATION_ERR },
		{ UDMA_CQE_LOCAL_PROT_ERR, URMA_CR_LOC_ACCESS_ERR },
		{ UDMA_CQE_WR_FLUSH_ERR, URMA_CR_WR_FLUSH_ERR },
		{ UDMA_CQE_MEM_MANAGERENT_OP_ERR, URMA_CR_LOC_ACCESS_ERR },
		{ UDMA_CQE_BAD_RESP_ERR, URMA_CR_REM_RESP_LEN_ERR },
		{ UDMA_CQE_LOCAL_ACCESS_ERR, URMA_CR_LOC_ACCESS_ERR },
		{ UDMA_CQE_REMOTE_INVAL_REQ_ERR, URMA_CR_REM_UNSUPPORTED_REQ_ERR },
		{ UDMA_CQE_REMOTE_ACCESS_ERR, URMA_CR_REM_ACCESS_ABORT_ERR },
		{ UDMA_CQE_REMOTE_OP_ERR, URMA_CR_REM_OPERATION_ERR },
		{ UDMA_CQE_TRANSPORT_RETRY_EXC_ERR, URMA_CR_ACK_TIMEOUT_ERR },
		{ UDMA_CQE_RNR_RETRY_EXC_ERR, URMA_CR_RNR_RETRY_CNT_EXC_ERR },
		{ UDMA_CQE_REMOTE_ABORTED_ERR, URMA_CR_REM_ACCESS_ABORT_ERR },
		{ UDMA_CQE_GENERAL_ERR, URMA_CR_LOC_LEN_ERR },
	};

	for (uint32_t i = 0; i < ARRAY_SIZE(map); ++i) {
		if (status == map[i].cqe_status)
			return map[i].cr_status;
	}

	URMA_LOG_ERR("Invalid CQE status.\n");
	return URMA_CR_LOC_ACCESS_ERR;
}

static void handle_recv_inl_cqe(struct udma_jfc_cqe *cqe, struct udma_u_jfr *jfr,
				urma_cr_t *cr)
{
	uint32_t wqe_idx, data_len, sge_idx;
	struct udma_wqe_data_seg *sge_list;
	uint8_t *cqe_inl_buf;
	uint32_t size;

	wqe_idx = udma_reg_read(cqe, CQE_WQE_IDX);
	sge_list = (struct udma_wqe_data_seg *)((char *)jfr->wqe_buf.buf +
					       (wqe_idx << jfr->wqe_shift));
	cqe_inl_buf = (uint8_t *)cqe->pld_in_cqe;
	data_len = le32toh(cqe->byte_cnt);

	for (sge_idx = 0; (sge_idx < jfr->max_sge) && (data_len); sge_idx++) {
		size = sge_list[sge_idx].len < data_len ?
		       sge_list[sge_idx].len : data_len;
		memcpy((void *)(uintptr_t)sge_list[sge_idx].addr,
		       (void *)cqe_inl_buf, size);
		data_len -= size;
		cqe_inl_buf += size;
	}
	cr->completion_len = cqe->byte_cnt - data_len;

	if (data_len)
		udma_reg_write(cqe, CQE_STATUS, UDMA_CQE_LOCAL_LENGTH_ERR);
}

static struct udma_u_jfr *get_jfr_from_cqe(struct udma_u_context *ctx,
					   struct udma_jfc_cqe *cqe)
{
	struct udma_jfr_node *jfr_node;
	struct udma_hmap_node *node;
	struct udma_u_jfr *jfr;
	uint32_t qpn;
	uint32_t jid;

	qpn = udma_reg_read(cqe, CQE_LCL_QPN);
	jid = get_jid_from_qpn(qpn, ctx->num_qps_shift, ctx->num_jfr_shift);
	(void)pthread_rwlock_rdlock(&ctx->jfr_table_lock);
	node = udma_hmap_first_with_hash(&ctx->jfr_table, jid);
	(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);
	if (!node)
		return NULL;
	jfr_node = to_udma_jfr_node(node);
	jfr = jfr_node->jfr;

	return jfr;
}

static struct udma_u_jetty *get_jetty_from_cqe(struct udma_u_context *ctx,
					       struct udma_jfc_cqe *cqe, uint32_t qpn,
					       uint32_t jid)
{
	struct udma_jetty_node *jetty_node;
	struct udma_u_jetty *jetty = NULL;
	struct udma_hmap_node *node;
	uint32_t table_id;
	uint32_t mask;

	table_id = jid >> ctx->jettys_in_tbl_shift;
	mask = (1 << ctx->jettys_in_tbl_shift) - 1;

	if (ctx->jetty_table[table_id].refcnt)
		jetty = ctx->jetty_table[table_id].table[jid & mask];

	return jetty;
}

static void udma_parse_opcode_for_res(struct udma_jfc_cqe *cqe, urma_cr_t *cr)
{
	uint8_t opcode = udma_reg_read(cqe, CQE_OPCODE);

	switch (opcode) {
	case HW_CQE_OPC_SEND:
		cr->opcode = URMA_CR_OPC_SEND;
		break;
	case HW_CQE_OPC_SEND_WITH_IMM:
		cr->imm_data = udma_reg_read(cqe, CQE_RKEY_IMMTDATA);
		cr->opcode = URMA_CR_OPC_SEND_WITH_IMM;
		break;
	case HW_CQE_OPC_RDMA_WRITE_WITH_IMM:
	case HW_CQE_OPC_PERSISTENCE_WRITE_WITH_IMM:
		cr->imm_data = udma_reg_read(cqe, CQE_RKEY_IMMTDATA);
		cr->opcode = URMA_CR_OPC_WRITE_WITH_IMM;
		break;
	case HW_CQE_OPC_SEND_WITH_INV:
		cr->invalid_token.token_id = udma_reg_read(cqe, CQE_RKEY_IMMTDATA);
		cr->opcode = URMA_CR_OPC_SEND_WITH_INV;
		break;
	default:
		cr->opcode = (urma_cr_opcode_t)UINT8_MAX;
		URMA_LOG_ERR("Receive invalid opcode :%u\n", opcode);
		cr->status = URMA_CR_UNSUPPORTED_OPCODE_ERR;
		break;
	}
}

static void handle_um_header(struct udma_u_jfr *jfr, uint32_t wqe_idx,
			     urma_cr_t *cr)
{
	uint32_t *header = (uint32_t *)&jfr->um_header_que[wqe_idx];
	uint32_t deid;

	memcpy(&deid, header + UM_HEADER_DEID, sizeof(uint32_t));
	urma_u32_to_eid(deid, &cr->remote_id.eid);
}

static int parse_cqe_for_res(struct udma_u_context *udma_ctx,
				       struct udma_jfc_cqe *cqe, urma_cr_t *cr)
{
	static struct udma_u_jetty *jetty;
	static struct udma_u_jfr *jfr;
	uint32_t wqe_idx;
	uint32_t rmt_qpn;
	bool if_jetty;
	uint32_t qpn;
	uint32_t jid;

	wqe_idx = udma_reg_read(cqe, CQE_WQE_IDX);
	qpn = udma_reg_read(cqe, CQE_LCL_QPN);
	rmt_qpn = udma_reg_read(cqe, CQE_RMT_QPN);

	if_jetty = is_jetty(udma_ctx, qpn);
	if (if_jetty) {
		jid = get_jid_from_qpn(qpn, udma_ctx->num_qps_shift, udma_ctx->num_jetty_shift);
		if ((jetty == NULL) || (jetty->urma_jetty.jetty_id.id != jid))
			jetty = get_jetty_from_cqe(udma_ctx, cqe, qpn, jid);
		if (jetty == NULL) {
			URMA_LOG_INFO("failed to poll jfc. QP 0x%x has been destroyed", qpn);
			return JFC_POLL_ERR;
		}
	}

	if (udma_reg_read(cqe, CQE_CQE_INLINE) == CQE_INLINE_ENABLE) {
		if (if_jetty) {
			jfr = jetty->udma_jfr;
		} else {
			jfr = get_jfr_from_cqe(udma_ctx, cqe);
			if (jfr == NULL) {
				URMA_LOG_INFO("failed to poll jfc. QP 0x%x has been destroyed", qpn);
				return JFC_POLL_ERR;
			}
		}
		handle_recv_inl_cqe(cqe, jfr, cr);
	}
	if (if_jetty) {
		jfr = jetty->udma_jfr;
		cr->local_id = jetty->urma_jetty.jetty_id.id;
		cr->remote_id.id = get_jid_from_qpn(rmt_qpn,
						    udma_ctx->num_qps_shift,
						    udma_ctx->num_jetty_shift);
	} else {
		jfr = get_jfr_from_cqe(udma_ctx, cqe);
		if (jfr == NULL) {
			URMA_LOG_INFO("failed to poll jfc for jfr. QP 0x%x destroyed",
					qpn);
			return JFC_POLL_ERR;
		}
		cr->local_id = jfr->jfrn;
		cr->remote_id.id = get_jid_from_qpn(rmt_qpn,
						    udma_ctx->num_qps_shift,
						    udma_ctx->num_jfs_shift);
	}
	if (!jfr->lock_free)
		pthread_spin_lock(&jfr->lock);
	udma_bitmap_free_idx(jfr->idx_que.bitmap,
			     jfr->idx_que.bitmap_cnt, wqe_idx);
	jfr->idx_que.tail++;
	if (!jfr->lock_free)
		pthread_spin_unlock(&jfr->lock);
	cr->user_ctx = jfr->wrid[wqe_idx];

	if (jfr->trans_mode == URMA_TM_UM)
		handle_um_header(jfr, wqe_idx, cr);

	udma_parse_opcode_for_res(cqe, cr);

	return JFC_OK;
}

static void dca_detach_qp_buf(struct udma_u_context *ctx, struct udma_qp *qp)
{
	struct udma_dca_detach_attr attr = {};
	bool is_empty;

	(void)pthread_spin_lock(&qp->sq.lock);

	is_empty = qp->sq.head == qp->sq.tail;
	if (is_empty && qp->sq.wqe_cnt > 0)
		attr.sq_idx = qp->sq.head & (qp->sq.wqe_cnt - 1);
	attr.qpn = qp->qp_num;

	(void)pthread_spin_unlock(&qp->sq.lock);

	if (is_empty)
		exec_detach_dca_mem_cmd(ctx, &attr);
}

static struct udma_qp *get_sqp_in_hash(struct udma_u_context *udma_ctx, uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;
	struct udma_hmap_node *node;

	node = udma_table_first_with_hash(&(udma_ctx->jfs_qp_table),
					&(udma_ctx->jfs_qp_table_lock), qpn);
	if (!node) {
		URMA_LOG_ERR("Failed to search for node in jfs_qp_table. QP 0x%x has been destroyed", qpn);
		return NULL;
	}
	qp_node = to_udma_jfs_qp_node(node);
	return qp_node->jfs_qp;
}

static int parse_cqe_for_req(struct udma_u_context *udma_ctx,
			     struct udma_jfc_cqe *cqe,
			     urma_cr_t *cr)
{
	static struct udma_qp *sqp;
	struct udma_u_jetty *jetty;
	uint32_t wqe_idx;
	bool if_jetty;
	uint32_t jid;
	uint32_t qpn;

	qpn = udma_reg_read(cqe, CQE_LCL_QPN);
	wqe_idx = udma_reg_read(cqe, CQE_WQE_IDX);
	if_jetty = is_jetty(udma_ctx, qpn);
	if ((sqp == NULL) || sqp->qp_num != qpn) {
		if (if_jetty) {
			jid = get_jid_from_qpn(qpn, udma_ctx->num_qps_shift, udma_ctx->num_jetty_shift);
			jetty = get_jetty_from_cqe(udma_ctx, cqe, qpn, jid);
			if (jetty == NULL) {
				URMA_LOG_ERR("Failed to poll jfc for jetty. QP 0x%x has been destroyed", qpn);
				return JFC_POLL_ERR;
			}
			if (jetty->tp_mode == URMA_TM_RC)
				sqp = jetty->rc_node->qp;
			else
				sqp = get_sqp_in_hash(udma_ctx, qpn);
		} else {
			sqp = get_sqp_in_hash(udma_ctx, qpn);
		}
	}
	if (sqp == NULL)
		return JFC_POLL_ERR;
	sqp->sq.tail += (wqe_idx - sqp->sq.tail) & (sqp->sq.wqe_cnt - 1);

	cr->flag.bs.jetty = if_jetty ? 1 : 0;
	/* jfs also uses jetty_id */
	cr->local_id = sqp->jetty_id;
	cr->user_ctx = sqp->sq.wrid[sqp->sq.tail & (sqp->sq.wqe_cnt - 1)];
	cr->flag.bs.s_r = 1;
	cr->tpn = qpn;

	sqp->sq.tail++;
	if (sqp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		dca_detach_qp_buf(udma_ctx, sqp);

	return 0;
}

static int parse_cqe_for_jfc(struct udma_u_context *udma_ctx, struct udma_u_jfc *jfc,
			     urma_cr_t *cr)
{
	struct udma_jfc_cqe *cqe = jfc->cqe;
	static struct udma_u_jetty *jetty;
	static struct udma_u_jfr *jfr;
	int ret = JFC_OK;
	uint8_t status;
	uint32_t qpn;

	memset(cr, 0, sizeof(urma_cr_t));
	cr->completion_len = udma_reg_read(cqe, CQE_BYTE_CNT);
	qpn = udma_reg_read(cqe, CQE_LCL_QPN);
	status = udma_reg_read(cqe, CQE_STATUS);
	cr->status = get_cr_status(status);

	cr->tpn = qpn;
	if (udma_reg_read(cqe, CQE_S_R) == CQE_FOR_SEND)
		ret = parse_cqe_for_req(udma_ctx, cqe, cr);
	else
		ret = parse_cqe_for_res(udma_ctx, cqe, cr);

	return ret;
}

static void dump_err_cqe(struct udma_jfc_cqe *cqe, struct udma_u_jfc *udma_u_jfc)
{
	uint32_t *temp_cqe = (uint32_t *)cqe;

	URMA_LOG_ERR("CQ(0x%lx) CQE(0x%x): 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
		     udma_u_jfc->cqn, udma_u_jfc->ci - 1, *(temp_cqe),
		     *(++temp_cqe), *(++temp_cqe), *(++temp_cqe), *(++temp_cqe),
		     *(++temp_cqe), *(++temp_cqe), *(++temp_cqe));
}

int exec_jfc_flush_cqe_cmd(struct udma_u_context *udma_ctx,
			   struct udma_jfc_cqe *cqe)
{
	urma_context_t *ctx = &(udma_ctx->urma_ctx);
	struct udma_jfs_qp_node *qp_node;
	struct flush_cqe_param fcp = {};
	urma_user_ctl_out_t out = {};
	struct udma_hmap_node *node;
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	struct udma_qp *qp;

	in.opcode = (uint32_t)UDMA_USER_CTL_FLUSH_CQE;
	in.addr = (uint64_t)&fcp;
	in.len = (uint32_t)sizeof(struct flush_cqe_param);

	fcp.qpn = udma_reg_read(cqe, CQE_LCL_QPN);
	if (udma_reg_read(cqe, CQE_S_R) == CQE_FOR_SEND) {
		node = udma_table_first_with_hash(&(udma_ctx->jfs_qp_table),
						  &(udma_ctx->jfs_qp_table_lock),
						  fcp.qpn);
		qp_node = to_udma_jfs_qp_node(node);
		qp = qp_node->jfs_qp;
		qp->flush_status = UDMA_FLUSH_STATU_ERR;
		fcp.sq_producer_idx = qp->sq.head;
	}

	return urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
}

static int udma_u_poll_one(struct udma_u_context *udma_ctx,
			   struct udma_u_jfc *udma_u_jfc,
			   urma_cr_t *cr)
{
	struct udma_jfc_cqe *cqe;
	uint8_t status;

	cqe = next_cqe_sw(udma_u_jfc);
	if (!cqe)
		return JFC_EMPTY;

	udma_u_jfc->cqe = cqe;
	++udma_u_jfc->ci;

	udma_from_device_barrier();

	if (parse_cqe_for_jfc(udma_ctx, udma_u_jfc, cr))
		return JFC_POLL_ERR;

	status = udma_reg_read(cqe, CQE_STATUS);
	if (status != UDMA_CQE_SUCCESS && status != UDMA_CQE_WR_FLUSH_ERR) {
		dump_err_cqe(cqe, udma_u_jfc);
		if (exec_jfc_flush_cqe_cmd(udma_ctx, cqe))
			URMA_LOG_ERR("flush cqe failed.\n");
	}

	return JFC_OK;
}

int udma_u_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_u_jfc = to_udma_jfc(jfc);
	bool need_cq_clean = false;
	int err = JFC_POLL_ERR;
	int npolled;

	if (!udma_u_jfc->lock_free)
		pthread_spin_lock(&udma_u_jfc->lock);

	for (npolled = 0; npolled < cr_cnt; ++npolled) {
		err = udma_u_poll_one(udma_ctx, udma_u_jfc, cr + npolled);
		if (err == JFC_EMPTY)
			break;
		if (err == JFC_POLL_ERR) {
			need_cq_clean = true;
			--npolled;
		}
	}

	if (npolled || need_cq_clean) {
		if (udma_u_jfc->caps_flag & UDMA_JFC_CAP_RECORD_DB)
			*udma_u_jfc->db = udma_u_jfc->ci & UDMA_DB_CONS_IDX_M;
		else
			update_cq_db(udma_ctx, udma_u_jfc);
	}

	if (!udma_u_jfc->lock_free)
		pthread_spin_unlock(&udma_u_jfc->lock);

	/* Try to shrink the DCA mem */
	if (udma_ctx->dca_ctx.mem_cnt > 0)
		udma_u_shrink_dca_mem(udma_ctx);

	return npolled;
}

urma_status_t udma_u_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr)
{
	int ret;

	if (!(attr->mask & (JFC_MODERATE_COUNT | JFC_MODERATE_PERIOD))) {
		URMA_LOG_ERR("JFC modify mask is not set or invalid.\n");
		return URMA_FAIL;
	}

	ret = urma_cmd_modify_jfc(jfc, attr, NULL);
	if (ret != 0) {
		URMA_LOG_ERR("modify jfc failed.\n");
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

urma_status_t udma_u_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_jfc = to_udma_jfc(jfc);
	struct udma_u_db jfc_db = {};
	uint32_t ci;

	ci = udma_jfc->ci & UDMA_DB_CONS_IDX_M;

	udma_reg_write(&jfc_db, UDMA_DB_TAG, jfc->jfc_id.id);
	udma_reg_write(&jfc_db, UDMA_DB_CMD, UDMA_CQ_DB_NTR);
	udma_reg_write(&jfc_db, UDMA_DB_JFC_CI, ci);
	udma_reg_write(&jfc_db, UDMA_DB_JFC_NOTIFY, !!solicited_only);
	udma_reg_write(&jfc_db, UDMA_DB_JFC_CMD_SN, udma_jfc->arm_sn);

	udma_write64(udma_ctx, (uint64_t *)(udma_ctx->uar + UDMA_DB_CFG0_OFFSET),
		     (uint64_t *)&jfc_db);

	return URMA_SUCCESS;
}

urma_jfce_t *udma_u_create_jfce(urma_context_t *ctx)
{
	struct udma_jfce *jfce = (struct udma_jfce *)calloc(1, sizeof(struct udma_jfce));

	if (jfce == NULL) {
		URMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}
	jfce->base.urma_ctx = ctx;

	/* get jetty_id of jfce from ubcore */
	jfce->base.fd = urma_cmd_create_jfce(ctx);
	if (jfce->base.fd < 0) {
		URMA_LOG_ERR("ubcore create jfce failed, fd = %d.\n",
			     jfce->base.fd);
		free(jfce);
		return NULL;
	}

	return &jfce->base;
}

urma_status_t udma_u_delete_jfce(urma_jfce_t *jfce)
{
	if (jfce->fd < 0) {
		URMA_LOG_ERR("Invalid parameter, fd = %d.\n", jfce->fd);
		return URMA_EINVAL;
	}
	(void)close(jfce->fd);

	struct udma_jfce *udma_jfce = container_of(jfce, struct udma_jfce, base);

	free(udma_jfce);

	return URMA_SUCCESS;
}

int udma_u_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
		   urma_jfc_t *jfc[])
{
	struct udma_jfce *udma_jfce;

	if (jfce == NULL || jfc_cnt == 0 || jfc == NULL) {
		URMA_LOG_ERR("Invalid parameter, jfce = 0x%p, jfc_cnt = %u, jfc = 0x%p.\n",
			     jfce, jfc_cnt, jfc);
		return -1;
	}

	udma_jfce = container_of(jfce, struct udma_jfce, base);

	return urma_cmd_wait_jfc(udma_jfce->base.fd, jfc_cnt, time_out, jfc);
}

void udma_u_ack_jfc(urma_jfc_t **jfc, uint32_t *nevents, uint32_t jfc_cnt)
{
	struct udma_u_jfc *udma_jfc;
	uint32_t i;

	for (i = 0; i < jfc_cnt; i++) {
		if (jfc[i] == NULL || nevents[i] == 0)
			continue;
		udma_jfc = to_udma_jfc(jfc[i]);
		udma_jfc->arm_sn++;
	}

	return urma_cmd_ack_jfc(jfc, nevents, jfc_cnt);
}

static int udma_u_check_poe_cfg(struct udma_u_context *udma_ctx, uint8_t poe_channel,
				struct udma_poe_init_attr *init_attr)
{
	if (!init_attr || !udma_ctx) {
		URMA_LOG_ERR("invalid ctx or attr\n");
		return EINVAL;
	}

	if (poe_channel >= udma_ctx->poe_ch_num) {
		URMA_LOG_ERR("invalid POE channel %u >= %u\n",
			     poe_channel, udma_ctx->poe_ch_num);
		return EINVAL;
	}

	return 0;
}

static int config_poe_channel(urma_context_t *ctx, uint8_t poe_channel,
			      struct udma_poe_init_attr *init_attr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_poe_info poe_channel_info = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	int ret;

	ret = udma_u_check_poe_cfg(udma_ctx, poe_channel, init_attr);
	if (ret)
		return EINVAL;

	poe_channel_info.poe_channel = poe_channel;
	poe_channel_info.en = !!init_attr->poe_addr;
	poe_channel_info.poe_addr = init_attr->poe_addr;

	in.opcode = (uint32_t)UDMA_CONFIG_POE_CHANNEL;
	in.addr = (uint64_t)&poe_channel_info;
	in.len = (uint32_t)sizeof(struct udma_poe_info);

	ret = urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
	if (ret)
		URMA_LOG_ERR("failed to config POE channel %u, ret = %d\n",
			     poe_channel, ret);

	return ret;
}

int udma_u_config_poe_channel(urma_context_t *ctx,
			      urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
	struct udma_config_poe_channel_in poe_in;
	int ret;

	memcpy(&poe_in, (void *)in->addr, in->len);
	ret = config_poe_channel((urma_context_t *)ctx,
				 poe_in.poe_channel, poe_in.init_attr);

	return ret;
}

static int query_poe_channel(urma_context_t *ctx, uint8_t poe_channel,
			     struct udma_poe_init_attr *init_attr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_poe_info poe_channel_info_out = {};
	struct udma_poe_info poe_channel_info_in = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	int ret;

	ret = udma_u_check_poe_cfg(udma_ctx, poe_channel, init_attr);
	if (ret)
		return EINVAL;

	poe_channel_info_in.poe_channel = poe_channel;

	in.opcode = (uint32_t)UDMA_QUERY_POE_CHANNEL;
	in.addr = (uint64_t)&poe_channel_info_in;
	in.len = (uint32_t)sizeof(struct udma_poe_info);
	out.addr = (uint64_t)&poe_channel_info_out;
	out.len = (uint32_t)sizeof(struct udma_poe_info);

	ret = urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
	if (ret) {
		URMA_LOG_ERR("failed to query POE channel %u, ret = %d\n",
			     poe_channel, ret);
		return ret;
	}
	init_attr->poe_addr = poe_channel_info_out.en ?
			      poe_channel_info_out.poe_addr : 0;

	return ret;
}

int udma_u_query_poe_channel(urma_context_t *ctx,
			     urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
	uint8_t poe_channel;
	int ret;

	memcpy(&poe_channel, (void *)in->addr, in->len);
	ret = query_poe_channel((urma_context_t *)ctx, poe_channel,
				(struct udma_poe_init_attr *)out->addr);

	return ret;
}

static struct udma_qp *poe_find_qp(urma_jfs_t *jfs)
{
	struct connect_node *udma_connect_node;
	struct udma_hmap_node *hmap_node;
	struct udma_hmap *hmap_tjfr;
	struct udma_u_jfs *udma_jfs;
	pthread_rwlock_t *rwlock;
	struct udma_qp *qp;

	udma_jfs = to_udma_jfs(jfs);
	hmap_tjfr = &(udma_jfs->tjfr_tbl.hmap);
	rwlock = &(udma_jfs->tjfr_tbl.rwlock);
	(void)pthread_rwlock_rdlock(rwlock);
	hmap_node = udma_hmap_first(hmap_tjfr);
	(void)pthread_rwlock_unlock(rwlock);
	if (hmap_node != NULL) {
		udma_connect_node = CONTAINER_OF_FIELD(hmap_node,
						       struct connect_node,
						       hmap_node);
		qp = udma_connect_node->qp;
		return qp;
	}

	return NULL;
}

static void update_jfs_ci(urma_jfs_t *jfs, uint32_t wqe_cnt)
{
	struct udma_qp *qp;

	if (!jfs)
		return;

	qp = poe_find_qp(jfs);
	if (!qp)
		return;

	qp->sq.tail += wqe_cnt;
}

int udma_u_update_jfs_ci(urma_context_t *ctx, urma_user_ctl_in_t *in,
			 urma_user_ctl_out_t *out)
{
	struct udma_update_jfs_ci_in update_in;

	if (in->len > sizeof(update_in)) {
		URMA_LOG_ERR("the length of the input parameter is too long, len = %u.\n",
			     in->len);
		return EINVAL;
	}

	memcpy(&update_in, (void *)in->addr, in->len);
	update_jfs_ci(update_in.jfs, update_in.wqe_cnt);

	return 0;
}

urma_status_t udma_u_get_async_event(urma_context_t *ctx,
				     urma_async_event_t *event)
{
	return urma_cmd_get_async_event(ctx, event);
}

void udma_u_ack_async_event(urma_async_event_t *event)
{
	urma_cmd_ack_async_event(event);
}
