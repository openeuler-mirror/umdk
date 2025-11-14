// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ummu_api.h>
#include "urma_provider.h"
#include "urma_private.h"
#include "udma_u_buf.h"
#include "udma_u_db.h"
#include "udma_u_ctl.h"
#include "udma_u_jfc.h"

static int udma_u_check_jfc_cfg(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
	urma_device_cap_t *cap = &ctx->dev->sysfs_dev->dev_attr.dev_cap;

	if (cfg->depth == 0 || cfg->depth > cap->max_jfc_depth) {
		UDMA_LOG_ERR("invalid jfc cfg depth = %u, cap depth = %u.\n",
			     cfg->depth, cap->max_jfc_depth);
		return EINVAL;
	}

	if (cfg->ceqn >= cap->ceq_cnt) {
		UDMA_LOG_ERR("invalid ceqn = %u, cap ceq cnt = %u.\n",
			     cfg->ceqn, cap->ceq_cnt);
		return EINVAL;
	}

	return 0;
}

static int udma_u_jfc_cmd(urma_context_t *ctx, struct udma_u_jfc *jfc,
			  urma_jfc_cfg_t *cfg)
{
	struct udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};

	cmd.buf_addr = (uintptr_t)jfc->cq.qbuf;
	cmd.db_addr = (uintptr_t)jfc->sw_db;
	cmd.buf_len = jfc->cq.qbuf_size;
	cmd.is_hugepage = jfc->cq.hugepage != NULL;

	udma_u_set_udata(&udata, &cmd, sizeof(cmd), NULL, 0);

	return urma_cmd_create_jfc(ctx, &jfc->base, cfg, &udata);
}

static int udma_u_create_cq(struct udma_u_jetty_queue *cq, urma_jfc_cfg_t *cfg)
{
	uint32_t depth;

	cq->lock_free = cfg->flag.bs.lock_free;
	if (!cq->lock_free &&
	    pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE)) {
		UDMA_LOG_ERR("failed to init lock.\n");
		return EFAULT;
	}

	depth = cfg->depth < UDMA_U_MIN_JFC_DEPTH ? UDMA_U_MIN_JFC_DEPTH : cfg->depth;
	if (!udma_u_alloc_queue_buf(cq, depth, cq->ctx->cqe_size, UDMA_HW_PAGE_SIZE, false)) {
		UDMA_LOG_ERR("failed to alloc jfc wqe buf.\n");
		goto err_alloc_buf;
	}

	return 0;

err_alloc_buf:
	if (!cq->lock_free)
		(void)pthread_spin_destroy(&cq->lock);

	return EFAULT;
}

static void udma_u_delete_cq(struct udma_u_jetty_queue *cq)
{
	udma_u_free_queue_buf(cq);

	if (!cq->lock_free)
		(void)pthread_spin_destroy(&cq->lock);
}

urma_jfc_t *udma_u_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jfc *jfc;
	int ret;

	ret = udma_u_check_jfc_cfg(ctx, cfg);
	if (ret)
		return NULL;

	jfc = (struct udma_u_jfc *)calloc(1, sizeof(*jfc));
	if (!jfc) {
		UDMA_LOG_ERR("failed to alloc user udma jfc memory.\n");
		return NULL;
	}

	jfc->cq.ctx = udma_ctx;
	if (udma_u_create_cq(&jfc->cq, cfg)) {
		UDMA_LOG_ERR("failed to create cq.\n");
		goto err_create_cq;
	}

	jfc->sw_db = (uint32_t *)udma_u_alloc_sw_db(udma_ctx, UDMA_JFC_TYPE_DB);
	if (!jfc->sw_db) {
		UDMA_LOG_ERR("failed to create alloc user jfc sw db.\n");
		goto err_alloc_sw_db;
	}

	ret = udma_u_jfc_cmd(ctx, jfc, cfg);
	if (ret) {
		UDMA_LOG_ERR("udma jfc failed to create urma cmd.\n");
		goto err_create_jfc;
	}

	jfc->cq_shift = align_power2(jfc->cq.baseblk_cnt);
	jfc->cq.idx = jfc->base.jfc_id.id;
	jfc->arm_sn = 1;

	return &jfc->base;

err_create_jfc:
	udma_u_free_sw_db(udma_ctx, jfc->sw_db, UDMA_JFC_TYPE_DB);
err_alloc_sw_db:
	udma_u_delete_cq(&jfc->cq);
err_create_cq:
	free(jfc);
	return NULL;
}

urma_status_t udma_u_delete_jfc(urma_jfc_t *jfc)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_jfc = to_udma_u_jfc(jfc);

	if (urma_cmd_delete_jfc(jfc)) {
		UDMA_LOG_ERR("ubcore delete jfc failed.\n");
		return URMA_FAIL;
	}

	if (!udma_jfc->mode) {
		udma_u_free_sw_db(udma_ctx, udma_jfc->sw_db, UDMA_JFC_TYPE_DB);
		udma_u_free_queue_buf(&udma_jfc->cq);
	}

	if (!udma_jfc->cq.lock_free)
		(void)pthread_spin_destroy(&udma_jfc->cq.lock);

	free(udma_jfc);

	return URMA_SUCCESS;
}

static enum jfc_poll_state udma_u_get_cr_status(uint8_t src_status,
						uint8_t substatus,
						enum urma_cr_status *dst_status)
{
#define UDMA_SRC_STATUS_NUM 7
#define UDMA_SUB_STATUS_NUM 5

struct udma_cr_status {
	bool is_valid;
	enum urma_cr_status cr_status;
};

	static struct udma_cr_status map[UDMA_SRC_STATUS_NUM][UDMA_SUB_STATUS_NUM] = {
		{{true, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS},
		 {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
		{{true, URMA_CR_UNSUPPORTED_OPCODE_ERR}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS},
		 {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
		{{false, URMA_CR_SUCCESS}, {true, URMA_CR_LOC_LEN_ERR}, {true, URMA_CR_LOC_ACCESS_ERR},
		 {true, URMA_CR_REM_RESP_LEN_ERR}, {true, URMA_CR_LOC_DATA_POISON}},
		{{false, URMA_CR_SUCCESS}, {true, URMA_CR_REM_UNSUPPORTED_REQ_ERR}, {true, URMA_CR_REM_ACCESS_ABORT_ERR},
		 {false, URMA_CR_SUCCESS}, {true, URMA_CR_REM_DATA_POISON}},
		{{true, URMA_CR_RNR_RETRY_CNT_EXC_ERR}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS},
		 {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
		{{true, URMA_CR_ACK_TIMEOUT_ERR}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS},
		 {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}},
		{{true, URMA_CR_WR_FLUSH_ERR}, {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS},
		 {false, URMA_CR_SUCCESS}, {false, URMA_CR_SUCCESS}}
	};

	if ((src_status < UDMA_SRC_STATUS_NUM) && (substatus < UDMA_SUB_STATUS_NUM) &&
	    map[src_status][substatus].is_valid) {
		*dst_status = map[src_status][substatus].cr_status;
		return JFC_OK;
	}

	UDMA_LOG_ERR("cqe_status (%u) substatus (%u) is invalid.",
		     src_status, substatus);

	return JFC_POLL_ERR;
}

static void handle_recv_inl_cqe(struct udma_u_jfc_cqe *cqe, uint8_t opcode,
				struct udma_u_jfr *jfr, urma_cr_t *cr)
{
	uint32_t rqe_idx, data_len, sge_idx, size;
	struct udma_wqe_sge *sge_list;
	void *cqe_inl_buf;

	rqe_idx = cqe->entry_idx;
	sge_list = (struct udma_wqe_sge *)(jfr->rq.qbuf +
					   (rqe_idx << jfr->wqe_shift));
	data_len = cqe->byte_cnt;
	if (opcode == HW_CQE_OPC_SEND)
		cqe_inl_buf = &cqe->data_l;
	else
		cqe_inl_buf = &cqe->inline_data;

	for (sge_idx = 0; (sge_idx < jfr->max_sge) && (data_len); sge_idx++) {
		size = sge_list[sge_idx].length < data_len ?
		       sge_list[sge_idx].length : data_len;
		(void)memcpy((void *)(uintptr_t)sge_list[sge_idx].va,
		       cqe_inl_buf, size);
		data_len -= size;
		cqe_inl_buf += size;
	}
	cr->completion_len = cqe->byte_cnt - data_len;

	if (data_len) {
		cqe->status = UDMA_CQE_LOCAL_OP_ERR;
		cqe->substatus = UDMA_CQE_LOCAL_LENGTH_ERR;
	}
}

static void udma_u_parse_opcode_for_res(struct udma_u_jfc_cqe *cqe, urma_cr_t *cr)
{
	uint8_t opcode = cqe->opcode;
	int ret;

	switch (opcode) {
	case HW_CQE_OPC_SEND:
		cr->opcode = URMA_CR_OPC_SEND;
		break;
	case HW_CQE_OPC_SEND_WITH_IMM:
		cr->imm_data = (uint64_t)cqe->data_h << UDMA_IMM_DATA_SHIFT |
			       cqe->data_l;
		cr->opcode = URMA_CR_OPC_SEND_WITH_IMM;
		break;
	case HW_CQE_OPC_SEND_WITH_INV:
		cr->invalid_token.token_id = cqe->data_l & (uint32_t)UDMA_U_CQE_INV_TOKEN_ID;
		cr->invalid_token.token_value.token = cqe->data_h;
		cr->opcode = URMA_CR_OPC_SEND_WITH_INV;
		ret = ummu_free_tid(cr->invalid_token.token_id);
		if (ret)
			UDMA_LOG_ERR("invalidation of tid failed, ret = %d.\n", ret);

		cr->invalid_token.token_id <<= UDMA_TID_SHIFT;
		break;
	case HW_CQE_OPC_WRITE_WITH_IMM:
		cr->imm_data = (uint64_t)cqe->data_h << UDMA_IMM_DATA_SHIFT |
			       cqe->data_l;
		cr->opcode = URMA_CR_OPC_WRITE_WITH_IMM;
		break;
	default:
		cr->opcode = (urma_cr_opcode_t)UINT8_MAX;
		UDMA_LOG_ERR("receive invalid opcode :%u.\n", opcode);
		cr->status = URMA_CR_UNSUPPORTED_OPCODE_ERR;
		break;
	}
}

static bool udma_u_update_jfr_idx(struct udma_u_context *udma_ctx,
				  struct udma_u_jfc_cqe *cqe, urma_cr_t *cr,
				  bool is_clean)
{
	struct udma_u_jetty_queue *queue;
	bool is_jetty = !!cqe->is_jetty;
	uint8_t opcode = cqe->opcode;
	struct udma_u_jetty *jetty;
	struct udma_u_jfr *jfr;
	uint32_t entry_idx;
	uint32_t table_id;
	uint32_t jetty_id;
	uint32_t mask;

	table_id = cr->local_id >> udma_ctx->jettys_in_tbl_shift;
	mask = (1 << udma_ctx->jettys_in_tbl_shift) - 1;
	jetty_id = cr->local_id;

	if (is_jetty) {
		if (udma_ctx->jetty_table[table_id].refcnt) {
			jetty = (struct udma_u_jetty *)udma_ctx->jetty_table[table_id].jetty_array[jetty_id & mask];
			if (!jetty) {
				UDMA_LOG_INFO("Failed to get jetty. JT 0x%x has been destroyed.\n", jetty_id);
				return true;
			}
			cr->user_data = (uintptr_t)&jetty->base;
			jfr = jetty->jfr;
		} else {
			UDMA_LOG_INFO("Failed to poll jfc. JT 0x%x has been destroyed.\n", jetty_id);
			return true;
		}
	} else {
		if (udma_ctx->jfr_table[table_id].refcnt) {
			jfr = (struct udma_u_jfr *)udma_ctx->jfr_table[table_id].jfr_array[jetty_id & mask];
			if (!jfr) {
				UDMA_LOG_INFO("Failed to get jetty. JT 0x%x has been destroyed.\n", jetty_id);
				return true;
			}
			cr->user_data = (uintptr_t)&jfr->base;
		} else {
			UDMA_LOG_INFO("Failed to poll jfc. JFR 0x%x has been destroyed.\n", jetty_id);
			return true;
		}
	}

	queue = &jfr->rq;
	entry_idx = cqe->entry_idx;
	cr->user_ctx = queue->wrid[entry_idx & (queue->baseblk_cnt - (uint32_t)1)];

	if (!is_clean && cqe->inline_en != 0)
		handle_recv_inl_cqe(cqe, opcode, jfr, cr);

	if (!jfr->lock_free)
		(void)pthread_spin_lock(&jfr->lock);

	udma_bitmap_free_idx(jfr->idx_que.bitmap, jfr->idx_que.bitmap_cnt, entry_idx);
	queue->ci++;

	if (!jfr->lock_free)
		(void)pthread_spin_unlock(&jfr->lock);

	return false;
}

static enum jfc_poll_state udma_u_parse_cqe_for_recv(struct udma_u_context *udma_ctx,
						     struct udma_u_jfc_cqe *cqe,
						     urma_cr_t *cr)
{
	uint8_t substatus;
	uint8_t status;

	if (udma_u_update_jfr_idx(udma_ctx, cqe, cr, false))
		return JFC_POLL_ERR;

	udma_u_parse_opcode_for_res(cqe, cr);
	status = cqe->status;
	substatus = cqe->substatus;
	if (udma_u_get_cr_status(status, substatus, &cr->status))
		return JFC_POLL_ERR;

	return JFC_OK;
}

static enum jfc_poll_state udma_u_parse_cqe_for_send(struct udma_u_jfc_cqe *cqe,
						     urma_cr_t *cr)
{
#define UDMA_FLUSH_DONE 1U
	struct udma_u_jetty_queue *queue;
	struct udma_u_jetty *jetty;
	struct udma_u_jfs *jfs;

	queue = (struct udma_u_jetty_queue *)((uint64_t)cqe->user_data_h << UDMA_ADDR_SHIFT |
		cqe->user_data_l);
	if (queue == NULL) {
		UDMA_LOG_ERR("jetty queue is null, id = %u.\n", cr->local_id);
		return JFC_POLL_ERR;
	}

	if (udma_u_get_cr_status(cqe->status, cqe->substatus, &cr->status) != JFC_OK)
		return JFC_POLL_ERR;

	if (cqe->fd == UDMA_FLUSH_DONE) {
		cr->status = URMA_CR_WR_FLUSH_ERR_DONE;
		queue->flush_flag = true;
	} else {
		queue->ci += (cqe->entry_idx - queue->ci) & queue->baseblk_mask;
		cr->user_ctx = queue->wrid[queue->ci & queue->baseblk_mask];
		queue->ci++;
	}

	if (!!cr->flag.bs.jetty) {
		jetty = to_udma_u_jetty_from_queue(queue);
		cr->user_data = (uintptr_t)&jetty->base;
	} else {
		jfs = container_of(queue, struct udma_u_jfs, sq);
		cr->user_data = (uintptr_t)&jfs->base;
	}

	return JFC_OK;
}

static enum jfc_poll_state udma_u_parse_cqe_for_jfc(struct udma_u_context *udma_ctx,
						    struct udma_u_jfc_cqe *cqe,
						    urma_cr_t *cr)
{
	enum jfc_poll_state ret;

	cr->flag.bs.s_r = cqe->s_r;
	cr->flag.bs.jetty = cqe->is_jetty;
	cr->completion_len = cqe->byte_cnt;
	cr->tpn = cqe->tpn;
	cr->local_id = cqe->local_num_h << UDMA_SRC_IDX_SHIFT | cqe->local_num_l;
	cr->remote_id.id = cqe->rmt_idx;
	udma_u_swap_endian128((uint8_t *)(cqe->rmt_eid), cr->remote_id.eid.raw);

	if (cqe->s_r == (uint8_t)CQE_FOR_RECEIVE)
		ret = udma_u_parse_cqe_for_recv(udma_ctx, cqe, cr);
	else
		ret = udma_u_parse_cqe_for_send(cqe, cr);

	return ret;
}

static struct udma_u_jfc_cqe *get_next_cqe(struct udma_u_jfc *jfc, uint32_t n)
{
#define UDMA_CQE_INVALID 0U
	struct udma_u_jfc_cqe *cqe;
	uint32_t valid_owner;

	cqe = (struct udma_u_jfc_cqe *)get_u_buf_entry(&jfc->cq, n);
	valid_owner = (n >> jfc->cq_shift) & UDMA_JFC_DB_VALID_OWNER_M;
	if ((cqe->owner ^ valid_owner) == UDMA_CQE_INVALID)
		return NULL;

	return cqe;
}

static void dump_cqe_aux_info(urma_context_t *ctx, urma_cr_t *cr)
{
	struct udma_u_cqe_info_in info_in;
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	int ret;

	info_in.status = cr->status;
	info_in.s_r = cr->flag.bs.s_r;
	in.addr = (uint64_t)&info_in;
	in.len = sizeof(struct udma_u_cqe_info_in);

	ret = udma_u_query_cqe_aux_info(ctx, &in, &out, 0);
	if (ret)
		UDMA_LOG_ERR("query cqe aux info failed, ret = %d.\n", ret);
}

static enum jfc_poll_state udma_u_poll_one(struct udma_u_context *udma_ctx,
					   struct udma_u_jfc *udma_u_jfc,
					   urma_cr_t *cr)
{
	struct udma_u_jfc_cqe *cqe = get_next_cqe(udma_u_jfc, udma_u_jfc->cq.ci);
	if (cqe == NULL)
		return JFC_EMPTY;

	udma_from_device_barrier();
	++udma_u_jfc->cq.ci;

	if (udma_u_parse_cqe_for_jfc(udma_ctx, cqe, cr))
		return JFC_POLL_ERR;

	if (cr->status != URMA_CR_SUCCESS && udma_ctx->dump_aux_info)
		dump_cqe_aux_info(&udma_ctx->urma_ctx, cr);

	return JFC_OK;
}

int udma_u_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_u_jfc = to_udma_u_jfc(jfc);
	enum jfc_poll_state ret = JFC_OK;
	uint32_t ci;
	int npolled;

	if (!udma_u_jfc->cq.lock_free)
		(void)pthread_spin_lock(&udma_u_jfc->cq.lock);

	for (npolled = 0; npolled < cr_cnt; ++npolled) {
		ret = udma_u_poll_one(udma_ctx, udma_u_jfc, cr + npolled);
		if (ret != JFC_OK)
			break;
	}

	if (npolled) {
		ci = udma_u_jfc->cq.ci;
		*udma_u_jfc->sw_db = ci & UDMA_U_JFC_DB_CI_IDX_M;
	}

	if (!udma_u_jfc->cq.lock_free)
		(void)pthread_spin_unlock(&udma_u_jfc->cq.lock);

	return ret == JFC_POLL_ERR ? -UDMA_INTER_ERR : npolled;
}

int udma_u_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
		    urma_jfc_t *jfc[])
{
	return urma_cmd_wait_jfc(jfce->fd, jfc_cnt, time_out, jfc);
}

void udma_u_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt)
{
	struct udma_u_jfc *udma_jfc;
	uint32_t i;

	for (i = 0; i < jfc_cnt; i++) {
		if (!jfc[i] || !nevents[i])
			continue;
		udma_jfc = to_udma_u_jfc(jfc[i]);
		udma_jfc->arm_sn++;
	}

	return urma_cmd_ack_jfc(jfc, nevents, jfc_cnt);
}

urma_status_t udma_u_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_jfc = to_udma_u_jfc(jfc);
	struct udma_jfc_db db;

	db.ci = udma_jfc->cq.ci & UDMA_U_JFC_DB_CI_IDX_M;
	db.notify = solicited_only;
	db.arm_sn = udma_jfc->arm_sn;
	db.type = UDMA_CQ_ARM_DB;
	db.jfcn = udma_jfc->cq.idx;

	udma_u_write64((uint64_t *)(udma_ctx->db.addr + UDMA_JFC_HW_DB_OFFSET),
		       (uint64_t *)&db);

	return URMA_SUCCESS;
}

urma_jfce_t *udma_u_create_jfce(urma_context_t *ctx)
{
	urma_jfce_t *jfce =
		(urma_jfce_t *)calloc(1, sizeof(urma_jfce_t));

	if (!jfce) {
		UDMA_LOG_ERR("jfce memory allocation failed.\n");
		return NULL;
	}
	jfce->urma_ctx = ctx;

	jfce->fd = urma_cmd_create_jfce(ctx);
	if (jfce->fd < 0) {
		UDMA_LOG_ERR("ubcore create jfce failed, fd = %d.\n",
			     jfce->fd);
		free(jfce);
		return NULL;
	}

	return jfce;
}

urma_status_t udma_u_delete_jfce(urma_jfce_t *jfce)
{
	if (jfce->fd < 0) {
		UDMA_LOG_ERR("invalid parameter, fd = %d.\n", jfce->fd);
		return URMA_EINVAL;
	}
	(void)close(jfce->fd);

	free(jfce);

	return URMA_SUCCESS;
}

static int udma_u_check_jfc_cqe_period(uint16_t cqe_period)
{
	uint16_t period[] = {
		UDMA_CQE_PERIOD_0,
		UDMA_CQE_PERIOD_4,
		UDMA_CQE_PERIOD_16,
		UDMA_CQE_PERIOD_64,
		UDMA_CQE_PERIOD_256,
		UDMA_CQE_PERIOD_1024,
		UDMA_CQE_PERIOD_4096,
		UDMA_CQE_PERIOD_16384
	};
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(period); ++i) {
		if (cqe_period == period[i])
			return 0;
	}

	return EINVAL;
}

static int udma_u_check_jfc_attr(urma_jfc_attr_t *attr)
{
	if (!(attr->mask & (JFC_MODERATE_COUNT | JFC_MODERATE_PERIOD))) {
		UDMA_LOG_ERR("JFC modify mask is not set or invalid.\n");
		return EINVAL;
	}

	if ((attr->mask & JFC_MODERATE_COUNT) &&
	    (attr->moderate_count >= UDMA_CQE_COALESCE_CNT_MAX)) {
		UDMA_LOG_ERR("cqe coalesce cnt %u is invalid.\n",
			     attr->moderate_count);
		return EINVAL;
	}

	if ((attr->mask & JFC_MODERATE_PERIOD) &&
	    (udma_u_check_jfc_cqe_period(attr->moderate_period))) {
		UDMA_LOG_ERR("cqe coalesce period %u is invalid.\n",
			     attr->moderate_period);
		return EINVAL;
	}

	return 0;
}

urma_status_t udma_u_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr)
{
	int ret;

	if (udma_u_check_jfc_attr(attr))
		return URMA_EINVAL;

	ret = urma_cmd_modify_jfc(jfc, attr, NULL);
	if (ret) {
		UDMA_LOG_ERR("modify jfc failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
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

void udma_u_clean_jfc(struct urma_jfc *jfc, uint32_t jetty_id)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_u_jfc = to_udma_u_jfc(jfc);
	struct udma_u_jetty_queue *cq;
	struct udma_u_jfc_cqe *dest;
	struct udma_u_jfc_cqe *cqe;
	uint32_t nfreed = 0;
	uint32_t local_id;
	uint8_t owner_bit;
	uint32_t cqe_size;
	urma_cr_t cr;
	uint32_t pi;

	if (udma_u_jfc->mode != (uint32_t)UDMA_U_NORMAL_JFC_TYPE)
		return;

	cq = &udma_u_jfc->cq;
	if (!cq->lock_free)
		(void)pthread_spin_lock(&cq->lock);

	cqe_size = 1U << cq->baseblk_shift;

	for (pi = cq->ci; get_next_cqe(udma_u_jfc, pi) != NULL; ++pi) {
		if (pi > cq->ci + cq->baseblk_cnt)
			break;
	}

	while ((int) --pi - (int) cq->ci >= 0) {
		cqe = (struct udma_u_jfc_cqe *)get_u_buf_entry(cq, pi);
		udma_from_device_barrier();
		local_id = (cqe->local_num_h << UDMA_SRC_IDX_SHIFT) | cqe->local_num_l;
		if (local_id == jetty_id) {
			if (cqe->s_r == (uint8_t)CQE_FOR_RECEIVE) {
				cr.local_id = local_id;
				(void)udma_u_update_jfr_idx(udma_ctx, cqe, &cr, true);
			}

			++nfreed;
		} else if (!!nfreed) {
			dest = (struct udma_u_jfc_cqe *)get_u_buf_entry(cq, pi + nfreed);
			udma_from_device_barrier();
			owner_bit = dest->owner;
			(void)memcpy(dest, cqe, cqe_size);
			dest->owner = owner_bit;
		}
	}

	if (!!nfreed) {
		cq->ci += nfreed;
		udma_to_device_barrier();
		*udma_u_jfc->sw_db = cq->ci & (uint32_t)UDMA_U_JFC_DB_CI_IDX_M;
	}

	if (!cq->lock_free)
		(void)pthread_spin_unlock(&cq->lock);
}
