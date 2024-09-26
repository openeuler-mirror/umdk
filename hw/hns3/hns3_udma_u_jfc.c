// SPDX-License-Identifier: GPL-2.0
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

#include <math.h>
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_segment.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_abi.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfr.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_jfc.h"

static int check_jfc_cfg(struct hns3_udma_u_context *hns3_udma_ctx, urma_jfc_cfg_t *cfg)
{
	if (!cfg->depth || roundup_pow_of_two(cfg->depth) > hns3_udma_ctx->max_jfc_cqe) {
		HNS3_UDMA_LOG_ERR("invalid jfc cfg, cfg->depth = %u, hns3_udma_ctx->max_jfc_cqe = %u.\n",
			     cfg->depth, hns3_udma_ctx->max_jfc_cqe);
		return EINVAL;
	}

	return 0;
}

static void set_jfc_size(struct hns3_udma_u_context *udma_ctx, struct hns3_udma_u_jfc *jfc,
			 urma_jfc_cfg_t *cfg)
{
	jfc->cqe_cnt = roundup_pow_of_two(cfg->depth);
	jfc->cqe_size = udma_ctx->cqe_size;
	jfc->cqe_shift = hns3_udma_ilog32(udma_ctx->cqe_size);
}

static int alloc_jfc_buf(struct hns3_udma_u_jfc *jfc)
{
	uint32_t buf_size = to_hns3_udma_hem_entries_size(jfc->cqe_cnt, jfc->cqe_shift);

	return hns3_udma_alloc_buf(&jfc->buf, buf_size, HNS3_UDMA_HW_PAGE_SIZE);
}

struct hns3_udma_u_jfc *hns3_udma_u_create_jfc_common(urma_jfc_cfg_t *cfg,
						      struct hns3_udma_u_context *udma_ctx)
{
	struct hns3_udma_u_jfc *jfc;

	if (check_jfc_cfg(udma_ctx, cfg))
		goto err;

	jfc = (struct hns3_udma_u_jfc *)calloc(1, sizeof(*jfc));
	if (!jfc) {
		HNS3_UDMA_LOG_ERR("alloc hns3_udma_ctx memory failed.\n");
		goto err;
	}

	jfc->lock_free = cfg->flag.bs.lock_free;
	if (!jfc->lock_free &&
	    pthread_spin_init(&jfc->lock, PTHREAD_PROCESS_PRIVATE)) {
		HNS3_UDMA_LOG_ERR("alloc hns3_udma_ctx spinlock failed.\n");
		goto err_lock;
	}

	set_jfc_size(udma_ctx, jfc, cfg);
	if (alloc_jfc_buf(jfc))
		goto err_buf;

	jfc->db = (uint32_t *)hns3_udma_alloc_sw_db(udma_ctx, HNS3_UDMA_JFC_TYPE_DB);
	if (!jfc->db)
		goto err_db;

	return jfc;

err_db:
	hns3_udma_free_buf(&jfc->buf);
err_buf:
	if (!jfc->lock_free)
		(void)pthread_spin_destroy(&jfc->lock);
err_lock:
	free(jfc);
err:
	return NULL;
}

void free_err_jfc(struct hns3_udma_u_jfc *jfc, struct hns3_udma_u_context *udma_ctx)
{
	hns3_udma_free_sw_db(udma_ctx, jfc->db, HNS3_UDMA_JFC_TYPE_DB);
	hns3_udma_free_buf(&jfc->buf);
	if (!jfc->lock_free)
		(void)pthread_spin_destroy(&jfc->lock);
	free(jfc);
}

urma_jfc_t *hns3_udma_u_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(ctx);
	struct hns3_udma_create_jfc_resp resp = {};
	struct hns3_udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	struct hns3_udma_u_jfc *jfc;
	int ret;

	jfc = hns3_udma_u_create_jfc_common(cfg, udma_ctx);
	if (!jfc)
		return NULL;

	cmd.buf_addr = (uintptr_t)jfc->buf.buf;
	cmd.db_addr = (uintptr_t)jfc->db;
	hns3_udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfc(ctx, &jfc->urma_jfc, cfg, &udata);
	if (ret) {
		HNS3_UDMA_LOG_ERR("urma cmd create jfc failed, ret = %d.\n", ret);
		free_err_jfc(jfc, udma_ctx);
		return NULL;
	}
	jfc->ci = 0;
	jfc->arm_sn = 1;
	jfc->cqn = jfc->urma_jfc.jfc_id.id;
	jfc->caps_flag = resp.jfc_caps;

	return &jfc->urma_jfc;
}

urma_status_t hns3_udma_u_delete_jfc(urma_jfc_t *jfc)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(jfc->urma_ctx);
	struct hns3_udma_u_jfc *udma_jfc = to_hns3_udma_jfc(jfc);
	int ret;

	ret = urma_cmd_delete_jfc(jfc);
	if (ret) {
		HNS3_UDMA_LOG_ERR("urma_cmd_delete_jfc failed, ret:%d.\n", ret);
		return URMA_FAIL;
	}

	free_err_jfc(udma_jfc, udma_ctx);

	return URMA_SUCCESS;
}

static struct hns3_udma_jfc_cqe *get_cqe(struct hns3_udma_u_jfc *jfc, int n)
{
	return (struct hns3_udma_jfc_cqe *)((char *)jfc->buf.buf + n * jfc->cqe_size);
}

static void *get_sw_cqe(struct hns3_udma_u_jfc *jfc, int n)
{
	struct hns3_udma_jfc_cqe *cqe = get_cqe(jfc, n & (jfc->cqe_cnt - 1));

	return (cqe->owner ^ (!!(n & jfc->cqe_cnt))) ? cqe : NULL;
}

static struct hns3_udma_jfc_cqe *next_cqe_sw(struct hns3_udma_u_jfc *jfc)
{
	return (struct hns3_udma_jfc_cqe *)get_sw_cqe(jfc, jfc->ci);
}

static enum urma_cr_status get_cr_status(uint8_t status)
{
	static const struct {
		uint32_t cqe_status;
		enum urma_cr_status cr_status;
	} map[] = {
		{ HNS3_UDMA_CQE_SUCCESS, URMA_CR_SUCCESS },
		{ HNS3_UDMA_CQE_LOCAL_LENGTH_ERR, URMA_CR_LOC_LEN_ERR },
		{ HNS3_UDMA_CQE_LOCAL_QP_OP_ERR, URMA_CR_LOC_OPERATION_ERR },
		{ HNS3_UDMA_CQE_LOCAL_PROT_ERR, URMA_CR_LOC_ACCESS_ERR },
		{ HNS3_UDMA_CQE_WR_FLUSH_ERR, URMA_CR_WR_FLUSH_ERR },
		{ HNS3_UDMA_CQE_MEM_MANAGERENT_OP_ERR, URMA_CR_LOC_ACCESS_ERR },
		{ HNS3_UDMA_CQE_BAD_RESP_ERR, URMA_CR_REM_RESP_LEN_ERR },
		{ HNS3_UDMA_CQE_LOCAL_ACCESS_ERR, URMA_CR_LOC_ACCESS_ERR },
		{ HNS3_UDMA_CQE_REMOTE_INVAL_REQ_ERR, URMA_CR_REM_UNSUPPORTED_REQ_ERR },
		{ HNS3_UDMA_CQE_REMOTE_ACCESS_ERR, URMA_CR_REM_ACCESS_ABORT_ERR },
		{ HNS3_UDMA_CQE_REMOTE_OP_ERR, URMA_CR_REM_OPERATION_ERR },
		{ HNS3_UDMA_CQE_TRANSPORT_RETRY_EXC_ERR, URMA_CR_ACK_TIMEOUT_ERR },
		{ HNS3_UDMA_CQE_RNR_RETRY_EXC_ERR, URMA_CR_RNR_RETRY_CNT_EXC_ERR },
		{ HNS3_UDMA_CQE_REMOTE_ABORTED_ERR, URMA_CR_REM_ACCESS_ABORT_ERR },
		{ HNS3_UDMA_CQE_GENERAL_ERR, URMA_CR_LOC_LEN_ERR },
	};

	for (uint32_t i = 0; i < ARRAY_SIZE(map); ++i) {
		if (status == map[i].cqe_status)
			return map[i].cr_status;
	}

	HNS3_UDMA_LOG_ERR("invalid CQE status.\n");
	return URMA_CR_LOC_ACCESS_ERR;
}

static void handle_recv_inl_cqe(struct hns3_udma_jfc_cqe *cqe, struct hns3_udma_u_jfr *jfr,
				urma_cr_t *cr)
{
	struct hns3_udma_wqe_data_seg *sge_list;
	uint8_t *cqe_inl_buf;
	uint32_t data_len;
	uint32_t sge_idx;
	uint32_t size;

	sge_list = (struct hns3_udma_wqe_data_seg *)((char *)jfr->wqe_buf.buf +
					       (cqe->wqe_idx << jfr->wqe_shift));
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
		cr->status = URMA_CR_LOC_LEN_ERR;
}

static void hns3_udma_parse_opcode_for_res(struct hns3_udma_jfc_cqe *cqe, urma_cr_t *cr)
{
	uint8_t opcode = cqe->opcode;

	switch (opcode) {
	case HW_CQE_OPC_SEND:
		cr->opcode = URMA_CR_OPC_SEND;
		break;
	case HW_CQE_OPC_SEND_WITH_IMM:
		cr->imm_data = hns3_udma_reg_read(cqe, CQE_RKEY_IMMTDATA);
		cr->opcode = URMA_CR_OPC_SEND_WITH_IMM;
		break;
	case HW_CQE_OPC_RDMA_WRITE_WITH_IMM:
	case HW_CQE_OPC_PERSISTENCE_WRITE_WITH_IMM:
		cr->imm_data = hns3_udma_reg_read(cqe, CQE_RKEY_IMMTDATA);
		cr->opcode = URMA_CR_OPC_WRITE_WITH_IMM;
		break;
	case HW_CQE_OPC_SEND_WITH_INV:
		cr->invalid_token.token_id = hns3_udma_reg_read(cqe, CQE_RKEY_IMMTDATA);
		cr->opcode = URMA_CR_OPC_SEND_WITH_INV;
		break;
	default:
		cr->opcode = (urma_cr_opcode_t)UINT8_MAX;
		HNS3_UDMA_LOG_ERR("receive invalid opcode :%u.\n", opcode);
		cr->status = URMA_CR_UNSUPPORTED_OPCODE_ERR;
		break;
	}
}

static void handle_um_header(struct hns3_udma_u_jfr *jfr, uint32_t wqe_idx,
			     urma_cr_t *cr)
{
	uint32_t *header = (uint32_t *)&jfr->um_header_que[wqe_idx];
	uint32_t deid;

	memcpy(&deid, header + UM_HEADER_DEID, sizeof(uint32_t));
	urma_u32_to_eid(deid, &cr->remote_id.eid);
}

static struct hns3_udma_u_jfr *get_common_jfr(struct hns3_udma_u_context *udma_ctx,
					      struct hns3_udma_jfc_cqe *cqe,
					      urma_cr_t *cr)
{
	struct hns3_udma_u_jetty *jetty = NULL;
	struct common_jetty *jetty_table;
	struct hns3_udma_u_jfr *jfr;
	uint32_t qpn = cr->tpn;
	bool is_jetty = false;
	uint32_t table_id;
	uint32_t mask;

	cr->remote_id.id = cqe->rmt_qpn;
	table_id = qpn >> udma_ctx->jettys_in_tbl_shift;
	mask = (1 << udma_ctx->jettys_in_tbl_shift) - 1;
	if (udma_ctx->jetty_table[table_id].refcnt) {
		jetty_table = udma_ctx->jetty_table[table_id].table;
		is_jetty = jetty_table[qpn & mask].is_jetty;
	} else {
		HNS3_UDMA_LOG_INFO("Failed to poll jfc in get_common_jfr. QP 0x%x has been destroyed.\n", qpn);
		return NULL;
	}
	if (is_jetty) {
		jetty = (struct hns3_udma_u_jetty *)jetty_table[qpn & mask].jetty;
		if (!jetty) {
			HNS3_UDMA_LOG_INFO("Failed to poll jfc in get_common_jfr. QP 0x%x has been destroyed.\n", qpn);
			return NULL;
		}
		jfr = jetty->hns3_udma_jfr;
		cr->local_id = qpn;
	} else {
		jfr = (struct hns3_udma_u_jfr *)jetty_table[qpn & mask].jetty;
		if (jfr == NULL) {
			HNS3_UDMA_LOG_INFO("Failed to poll jfc in get_common_jfr. QP 0x%x has been destroyed.\n", qpn);
			return NULL;
		}
		cr->local_id = jfr->jfrn;
	}

	return jfr;
}

static int parse_cqe_for_res(struct hns3_udma_u_context *udma_ctx,
			     struct hns3_udma_jfc_cqe *cqe, urma_cr_t *cr)
{
	struct hns3_udma_u_jfr *jfr;
	uint32_t wqe_idx;

	jfr = get_common_jfr(udma_ctx, cqe, cr);
	if (!jfr)
		return JFC_POLL_ERR;

	if (cqe->cqe_inline == CQE_INLINE_ENABLE)
		handle_recv_inl_cqe(cqe, jfr, cr);

	wqe_idx = hns3_udma_reg_read(cqe, CQE_WQE_IDX);
	if (!jfr->share_jfr) {
		cr->user_ctx = jfr->wrid[jfr->idx_que.tail & (jfr->wqe_cnt - 1)];
		jfr->idx_que.tail++;
	} else {
		cr->user_ctx = jfr->wrid[wqe_idx];
		if (!jfr->lock_free)
			pthread_spin_lock(&jfr->lock);
		hns3_udma_bitmap_free_idx(jfr->idx_que.bitmap,
				     jfr->idx_que.bitmap_cnt, wqe_idx);
		jfr->idx_que.tail++;
		if (!jfr->lock_free)
			pthread_spin_unlock(&jfr->lock);
	}

	if (jfr->trans_mode == URMA_TM_UM)
		handle_um_header(jfr, wqe_idx, cr);

	hns3_udma_parse_opcode_for_res(cqe, cr);
	cr->flag.bs.s_r = 1;

	return JFC_OK;
}

static void dca_detach_qp_buf(struct hns3_udma_u_context *ctx, struct hns3_udma_qp *qp)
{
	struct hns3_udma_dca_detach_attr attr = {};
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

struct hns3_udma_qp *get_qp_from_qpn(struct hns3_udma_u_context *udma_ctx, uint32_t qpn)
{
	struct common_jetty *jetty_table = NULL;
	struct hns3_udma_u_jetty *jetty;
	struct hns3_udma_qp *sqp = NULL;
	struct hns3_udma_u_jfs *jfs;
	bool is_jetty = false;
	uint32_t table_id;
	uint32_t mask;

	table_id = qpn >> udma_ctx->jettys_in_tbl_shift;
	if (table_id >= HNS3_UDMA_JETTY_TABLE_NUM) {
		HNS3_UDMA_LOG_ERR("table_id(%u) is invalid.\n", table_id);
		return NULL;
	}

	if (udma_ctx->jetty_table[table_id].refcnt == 0) {
		HNS3_UDMA_LOG_ERR("jetty_table(table_id = %u) is invalid.\n", table_id);
		return NULL;
	}

	mask = (1 << udma_ctx->jettys_in_tbl_shift) - 1;
	jetty_table = udma_ctx->jetty_table[table_id].table;
	is_jetty = jetty_table[qpn & mask].is_jetty;

	if (is_jetty) {
		jetty = (struct hns3_udma_u_jetty *)jetty_table[qpn & mask].jetty;
		if (jetty == NULL) {
			HNS3_UDMA_LOG_ERR("Failed to poll jfc in get_common_qp. QP 0x%x has been destroyed.\n", qpn);
			return NULL;
		}
		if (jetty->tp_mode == URMA_TM_RC)
			sqp = jetty->rc_node->qp;
		else
			sqp = jetty->um_qp;
	} else {
		jfs = (struct hns3_udma_u_jfs *)jetty_table[qpn & mask].jetty;
		if (jfs == NULL) {
			HNS3_UDMA_LOG_ERR("Failed to poll jfc in get_common_qp. QP 0x%x has been destroyed.\n", qpn);
			return NULL;
		}
		sqp = jfs->um_qp;
	}

	return sqp;
}

static int parse_cqe_for_req(struct hns3_udma_u_context *udma_ctx,
			     struct hns3_udma_jfc_cqe *cqe,
			     urma_cr_t *cr)
{
	struct hns3_udma_qp *sqp = NULL;

	sqp = get_qp_from_qpn(udma_ctx, cr->tpn);
	if (sqp == NULL)
		return JFC_POLL_ERR;

	sqp->sq.tail += (cqe->wqe_idx - sqp->sq.tail) & (sqp->sq.wqe_cnt - 1);

	/* jfs also uses jetty_id */
	cr->local_id = sqp->jetty_id;
	cr->user_ctx = sqp->sq.wrid[sqp->sq.tail & (sqp->sq.wqe_cnt - 1)];
	cr->flag.bs.s_r = 0;
	cr->flag.bs.jetty = sqp->is_jetty;

	++sqp->sq.tail;
	if (sqp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		dca_detach_qp_buf(udma_ctx, sqp);

	return 0;
}

static int parse_cqe_for_jfc(struct hns3_udma_u_context *udma_ctx, struct hns3_udma_u_jfc *jfc,
			     urma_cr_t *cr)
{
	struct hns3_udma_jfc_cqe *cqe = jfc->cqe;
	int ret;

	cr->completion_len = cqe->byte_cnt;
	cr->tpn = cqe->lcl_qpn;
	cr->status = get_cr_status(cqe->status);

	if (cqe->s_r == CQE_FOR_SEND)
		ret = parse_cqe_for_req(udma_ctx, cqe, cr);
	else
		ret = parse_cqe_for_res(udma_ctx, cqe, cr);

	return ret;
}

static void dump_err_cqe(struct hns3_udma_jfc_cqe *cqe, struct hns3_udma_u_jfc *udma_u_jfc)
{
	uint32_t *temp_cqe = (uint32_t *)cqe;

	HNS3_UDMA_LOG_ERR("CQ(0x%lx) CQE(0x%x): 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
		     udma_u_jfc->cqn, udma_u_jfc->ci - 1, temp_cqe[0],
		     temp_cqe[1], temp_cqe[2], temp_cqe[3], temp_cqe[4],
		     temp_cqe[5], temp_cqe[6], temp_cqe[7]);
}

int exec_jfc_flush_cqe_cmd(struct hns3_udma_u_context *udma_ctx,
			   struct hns3_udma_jfc_cqe *cqe)
{
	urma_context_t *ctx = &(udma_ctx->urma_ctx);
	struct flush_cqe_param fcp = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	struct hns3_udma_qp *qp;

	in.opcode = (uint32_t)HNS3_UDMA_USER_CTL_FLUSH_CQE;
	in.addr = (uint64_t)&fcp;
	in.len = (uint32_t)sizeof(struct flush_cqe_param);

	fcp.qpn = hns3_udma_reg_read(cqe, CQE_LCL_QPN);
	if (hns3_udma_reg_read(cqe, CQE_S_R) == CQE_FOR_SEND) {
		qp = get_qp_from_qpn(udma_ctx, fcp.qpn);
		if (!qp) {
			HNS3_UDMA_LOG_ERR("get qp is null.\n");
			return -EINVAL;
		}

		qp->flush_status = HNS3_UDMA_FLUSH_STATU_ERR;
		fcp.sq_producer_idx = qp->sq.head;
	}

	return urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
}

static int hns3_udma_u_poll_one(struct hns3_udma_u_context *udma_ctx,
				struct hns3_udma_u_jfc *udma_u_jfc,
				urma_cr_t *cr)
{
	struct hns3_udma_jfc_cqe *cqe;

	cqe = next_cqe_sw(udma_u_jfc);
	if (!cqe)
		return JFC_EMPTY;

	udma_u_jfc->cqe = cqe;
	++udma_u_jfc->ci;

	hns3_udma_from_device_barrier();

	if (parse_cqe_for_jfc(udma_ctx, udma_u_jfc, cr))
		return JFC_POLL_ERR;

	if (cr->status != URMA_CR_SUCCESS && cr->status != URMA_CR_WR_FLUSH_ERR) {
		dump_err_cqe(cqe, udma_u_jfc);
		if (exec_jfc_flush_cqe_cmd(udma_ctx, cqe))
			HNS3_UDMA_LOG_ERR("flush cqe failed.\n");
	}

	return JFC_OK;
}

int hns3_udma_u_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(jfc->urma_ctx);
	struct hns3_udma_u_jfc *udma_u_jfc = to_hns3_udma_jfc(jfc);
	bool need_cq_clean = false;
	int err = JFC_POLL_ERR;
	int npolled;

	if (hns3_udma_state_reseted(udma_ctx)) {
		cr->status = URMA_CR_WR_FLUSH_ERR_DONE;
		npolled = HNS3_UDMA_POLL_SCR_CNT;

		return npolled;
	}

	if (!udma_u_jfc->lock_free)
		pthread_spin_lock(&udma_u_jfc->lock);

	for (npolled = 0; npolled < cr_cnt; ++npolled) {
		err = hns3_udma_u_poll_one(udma_ctx, udma_u_jfc, cr + npolled);
		if (err == JFC_EMPTY)
			break;
		if (err == JFC_POLL_ERR) {
			need_cq_clean = true;
			--npolled;
		}
	}

	if (npolled || need_cq_clean) {
		if (udma_u_jfc->caps_flag & HNS3_UDMA_JFC_CAP_RECORD_DB)
			*udma_u_jfc->db = udma_u_jfc->ci & HNS3_UDMA_DB_CONS_IDX_M;
		else
			update_cq_db(udma_ctx, udma_u_jfc);
	}

	if (!udma_u_jfc->lock_free)
		pthread_spin_unlock(&udma_u_jfc->lock);

	/* Try to shrink the DCA mem */
	if (udma_ctx->dca_ctx.mem_cnt > 0)
		hns3_udma_u_shrink_dca_mem(udma_ctx);

	return npolled;
}

urma_status_t hns3_udma_u_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr)
{
	int ret;

	if (!(attr->mask & (JFC_MODERATE_COUNT | JFC_MODERATE_PERIOD))) {
		HNS3_UDMA_LOG_ERR("JFC modify mask is not set or invalid.\n");
		return URMA_FAIL;
	}

	ret = urma_cmd_modify_jfc(jfc, attr, NULL);
	if (ret != 0) {
		HNS3_UDMA_LOG_ERR("modify jfc failed. ret = %d\n", ret);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

urma_status_t hns3_udma_u_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(jfc->urma_ctx);
	struct hns3_udma_u_jfc *udma_u_jfc = to_hns3_udma_jfc(jfc);
	struct hns3_udma_u_db jfc_db = {};
	uint32_t ci;

	ci = udma_u_jfc->ci & HNS3_UDMA_DB_CONS_IDX_M;

	hns3_udma_reg_write(&jfc_db, HNS3_UDMA_DB_TAG, jfc->jfc_id.id);
	hns3_udma_reg_write(&jfc_db, HNS3_UDMA_DB_CMD, HNS3_UDMA_CQ_DB_NTR);
	hns3_udma_reg_write(&jfc_db, HNS3_UDMA_DB_JFC_CI, ci);
	hns3_udma_reg_write(&jfc_db, HNS3_UDMA_DB_JFC_NOTIFY, !!solicited_only);
	hns3_udma_reg_write(&jfc_db, HNS3_UDMA_DB_JFC_CMD_SN, udma_u_jfc->arm_sn);

	hns3_udma_write64(udma_ctx, (uint64_t *)(udma_ctx->uar + HNS3_UDMA_DB_CFG0_OFFSET),
			  (uint64_t *)&jfc_db);

	return URMA_SUCCESS;
}

urma_jfce_t *hns3_udma_u_create_jfce(urma_context_t *ctx)
{
	struct hns3_udma_jfce *jfce = (struct hns3_udma_jfce *)calloc(1, sizeof(struct hns3_udma_jfce));
	if (!jfce) {
		HNS3_UDMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}

	jfce->base.urma_ctx = ctx;

	/* get jetty_id of jfce from ubcore */
	jfce->base.fd = urma_cmd_create_jfce(ctx);
	if (jfce->base.fd < 0) {
		HNS3_UDMA_LOG_ERR("ubcore create jfce failed, fd = %d.\n",
			     jfce->base.fd);
		free(jfce);
		return NULL;
	}

	return &jfce->base;
}

urma_status_t hns3_udma_u_delete_jfce(urma_jfce_t *jfce)
{
	if (jfce->fd < 0) {
		HNS3_UDMA_LOG_ERR("invalid parameter, fd = %d.\n", jfce->fd);
		return URMA_EINVAL;
	}
	(void)close(jfce->fd);

	struct hns3_udma_jfce *udma_jfce = container_of(jfce, struct hns3_udma_jfce, base);

	free(udma_jfce);

	return URMA_SUCCESS;
}

int hns3_udma_u_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
		    urma_jfc_t *jfc[])
{
	struct hns3_udma_jfce *udma_jfce;

	if (!jfce || !jfc_cnt || !jfc) {
		HNS3_UDMA_LOG_ERR("invalid parameter, jfc_cnt = %u.\n", jfc_cnt);
		return -1;
	}

	udma_jfce = container_of(jfce, struct hns3_udma_jfce, base);

	return urma_cmd_wait_jfc(udma_jfce->base.fd, jfc_cnt, time_out, jfc);
}

void hns3_udma_u_ack_jfc(urma_jfc_t **jfc, uint32_t *nevents, uint32_t jfc_cnt)
{
	struct hns3_udma_u_jfc *udma_jfc;
	uint32_t i;

	for (i = 0; i < jfc_cnt; i++) {
		if (jfc[i] == NULL || nevents[i] == 0)
			continue;
		udma_jfc = to_hns3_udma_jfc(jfc[i]);
		udma_jfc->arm_sn++;
	}

	return urma_cmd_ack_jfc(jfc, nevents, jfc_cnt);
}

urma_status_t hns3_udma_u_get_async_event(urma_context_t *ctx,
				     urma_async_event_t *event)
{
	return urma_cmd_get_async_event(ctx, event);
}

void hns3_udma_u_ack_async_event(urma_async_event_t *event)
{
	urma_cmd_ack_async_event(event);
}
