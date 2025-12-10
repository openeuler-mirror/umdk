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
#include <string.h>
#include <sys/types.h>
#include "udma_u_buf.h"
#include "udma_u_db.h"
#include "udma_u_jfc.h"
#include "udma_u_jfs.h"

static uint32_t get_ctl_len(uint8_t opcode)
{
	switch (opcode) {
	case UDMA_OPCODE_WRITE_WITH_IMM:
		return SQE_WRITE_IMM_CTL_LEN;
	case UDMA_OPCODE_WRITE_WITH_NOTIFY:
		return SQE_WRITE_NOTIFY_CTL_LEN;
	default:
		return SQE_NORMAL_CTL_LEN;
	}
}

static uint32_t get_sge_num(uint8_t opcode, struct udma_jfs_sqe_ctl *wqe_ctl)
{
	switch (opcode) {
	case UDMA_OPCODE_CAS:
	case UDMA_OPCODE_FAA:
		return UDMA_ATOMIC_SGE_NUM + 1;
	default:
		return wqe_ctl->sge_num;
	}
}

static uint32_t get_wqebb_cnt(struct udma_jfs_sqe_ctl *wqe_ctl)
{
	uint8_t opcode = wqe_ctl->opcode;
	uint32_t sqe_ctl_len = get_ctl_len(opcode);
	uint32_t inline_len;
	uint32_t sge_num;

	switch (opcode) {
	case UDMA_OPCODE_SEND:
	case UDMA_OPCODE_SEND_WITH_IMM:
	case UDMA_OPCODE_SEND_WITH_INVALID:
	case UDMA_OPCODE_WRITE:
	case UDMA_OPCODE_WRITE_WITH_IMM:
	case UDMA_OPCODE_WRITE_WITH_NOTIFY:
		if (wqe_ctl->flag & UDMAWQE_INLINE_EN) {
			inline_len = wqe_ctl->inline_msg_len;
			return (sqe_ctl_len + inline_len - 1) / UDMA_JFS_WQEBB + 1;
		}
		break;
	case UDMA_OPCODE_NOP:
		return NOP_WQEBB_CNT;
	default:
		break;
	}

	sge_num = get_sge_num(opcode, wqe_ctl);

	return sq_cal_wqebb_num(sqe_ctl_len, sge_num, UDMA_JFS_WQEBB);
}

static bool udma_check_atomic_len(uint32_t len, uint8_t opcode)
{
	switch (len) {
	case UDMA_ATOMIC_LEN_4:
	case UDMA_ATOMIC_LEN_8:
		return true;
	case UDMA_ATOMIC_LEN_16:
		if (opcode == URMA_OPC_CAS)
			return true;
		UDMA_LOG_ERR("the atomic opcode must be CAS when len is 16.\n");
		return false;
	default:
		UDMA_LOG_ERR("invalid atomic len %u.\n", len);
		return false;
	}
}

int udma_u_exec_jfs_create_cmd(urma_context_t *ctx, struct udma_u_jfs *jfs,
			       urma_jfs_cfg_t *cfg)
{
	struct udma_create_jetty_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (cfg->priority >= UDMA_MAX_PRIORITY) {
		UDMA_LOG_ERR("user mode jfs priority is out of range, priority is %u.\n",
			     cfg->priority);
		return EINVAL;
	}

	cmd.buf_addr = (uintptr_t)jfs->sq.qbuf;
	cmd.buf_len = jfs->sq.qbuf_size;
	cmd.jetty_addr = (uintptr_t)&jfs->sq;
	cmd.sqe_bb_cnt = jfs->sq.sqe_bb_cnt;
	cmd.pi_type = jfs->pi_type;
	cmd.non_pin = jfs->sq.cstm;
	cmd.is_hugepage = jfs->sq.hugepage != NULL;
	cmd.jetty_type = jfs->jfs_type;
	cmd.jfs_id = jfs->sq.db.id;
	udma_u_set_udata(&udata, &cmd, (uint32_t)sizeof(cmd), NULL, 0);
	ret = urma_cmd_create_jfs(ctx, &jfs->base, cfg, &udata);
	if (ret != 0)
		UDMA_LOG_ERR("failed to urma cmd create jfs, ret is %d.\n", ret);

	return ret;
}

int udma_u_create_sq(struct udma_u_jetty_queue *sq, urma_jfs_cfg_t *cfg)
{
	uint32_t sqe_bb_cnt;

	sq->lock_free = cfg->flag.bs.lock_free;

	if (!sq->lock_free &&
	    pthread_spin_init(&sq->lock, PTHREAD_PROCESS_PRIVATE))
		goto err_init_lock;

	udma_u_init_sq_param(sq, cfg);

	sqe_bb_cnt = sq_cal_wqebb_num(SQE_WRITE_NOTIFY_CTL_LEN,
				      cfg->max_sge, UDMA_JFS_WQEBB);
	if (sqe_bb_cnt > MAX_SQE_BB_NUM)
		sqe_bb_cnt = MAX_SQE_BB_NUM;
	sq->sqe_bb_cnt = sqe_bb_cnt;
	sq->max_sge_num = cfg->max_sge;
	if (!udma_u_alloc_queue_buf(sq, sqe_bb_cnt * cfg->depth,
				    UDMA_JFS_WQEBB, UDMA_HW_PAGE_SIZE, true)) {
		UDMA_LOG_ERR("failed to alloc jfs wqe buf.\n");
		goto err_alloc_buf;
	}

	return 0;

err_alloc_buf:
	if (!sq->lock_free)
		(void)pthread_spin_destroy(&sq->lock);
err_init_lock:
	return EINVAL;
}

void udma_u_delete_sq(struct udma_u_jetty_queue *sq)
{
	udma_u_free_queue_buf(sq);

	if (!sq->lock_free)
		(void)pthread_spin_destroy(&sq->lock);
}

urma_jfs_t *udma_u_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_u_ctx(ctx);
	struct udma_u_jfs *jfs;

	if (cfg->trans_mode == URMA_TM_RC) {
		UDMA_LOG_ERR("jfs not support RC transmode.\n");
		return NULL;
	}

	jfs = (struct udma_u_jfs *)calloc(1, sizeof(struct udma_u_jfs));
	if (jfs == NULL) {
		UDMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}

	jfs->sq.ctx = udma_ctx;
	if (udma_u_create_sq(&jfs->sq, cfg)) {
		UDMA_LOG_ERR("failed to create sq.\n");
		goto err_create_sq;
	}

	jfs->jfs_type = UDMA_URMA_NORMAL_JETTY_TYPE;
	if (udma_u_exec_jfs_create_cmd(ctx, jfs, cfg))
		goto err_exec_cmd;

	jfs->sq.db.id = jfs->base.jfs_id.id;
	jfs->sq.db.type = UDMA_MMAP_JETTY_DSQE;
	if (udma_u_alloc_db(ctx, &jfs->sq.db))
		goto err_alloc_db;

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

static void udma_u_free_jfs(urma_jfs_t *jfs)
{
	struct udma_u_jfs *udma_jfs = to_udma_u_jfs(jfs);

	if (!!jfs->jfs_cfg.jfc)
		udma_u_clean_jfc(jfs->jfs_cfg.jfc, jfs->jfs_id.id);

	udma_u_free_db(jfs->urma_ctx, &udma_jfs->sq.db);
	udma_u_delete_sq(&udma_jfs->sq);
	free(udma_jfs);
}

urma_status_t udma_u_delete_jfs(urma_jfs_t *jfs)
{
	if (urma_cmd_delete_jfs(jfs))
		return URMA_FAIL;

	udma_u_free_jfs(jfs);

	return URMA_SUCCESS;
}

urma_status_t udma_u_delete_jfs_batch(urma_jfs_t **jfs, int jfs_cnt, urma_jfs_t **bad_jfs)
{
	int i;

	if (!jfs) {
		UDMA_LOG_ERR("jfs array is null.\n");
		return URMA_EINVAL;
	}

	if (!jfs_cnt) {
		UDMA_LOG_ERR("jfs cnt is 0.\n");
		return URMA_EINVAL;
	}

	if (urma_cmd_delete_jfs_batch(jfs, jfs_cnt, bad_jfs))
		return URMA_FAIL;

	for (i = 0; i < jfs_cnt; i++)
		udma_u_free_jfs(jfs[i]);

	return URMA_SUCCESS;
}

#ifdef ST64B
static void st64b(uint64_t *src, uint64_t *dst)
{
	asm volatile (
		"mov x9, %0\n"
		"mov x10, %1\n"
		"ldr x0, [x9]\n"
		"ldr x1, [x9, #8]\n"
		"ldr x2, [x9, #16]\n"
		"ldr x3, [x9, #24]\n"
		"ldr x4, [x9, #32]\n"
		"ldr x5, [x9, #40]\n"
		"ldr x6, [x9, #48]\n"
		"ldr x7, [x9, #56]\n"
		".inst 0xf83f9140\n"
		::"r" (src), "r"(dst):"cc", "memory"
	);
}
#endif

static void udma_write_dsqe(struct udma_u_jetty_queue *sq,
			    struct udma_jfs_sqe_ctl *ctrl)
{
	ctrl->sqe_bb_idx = sq->pi;
#ifdef ST64B
	st64b(((uint64_t *)ctrl), (uint64_t *)sq->dwqe_addr);
#else
	mmio_memcpy_x64((uint64_t *)sq->dwqe_addr, (uint64_t *)ctrl);
#endif
}

static bool udma_check_sge_num_and_opcode(urma_opcode_t opcode, struct udma_u_jetty_queue *sq,
					  urma_jfs_wr_t *wr, uint8_t *udma_opcode)
{
	switch (opcode) {
	case URMA_OPC_READ:
		*udma_opcode = UDMA_OPCODE_READ;
		goto read_sge_check;
	case URMA_OPC_WRITE:
		*udma_opcode = UDMA_OPCODE_WRITE;
		goto default_sge_num;
	case URMA_OPC_WRITE_IMM:
		*udma_opcode = UDMA_OPCODE_WRITE_WITH_IMM;
		goto write_with_imm_sge_check;
	case URMA_OPC_WRITE_NOTIFY:
		*udma_opcode = UDMA_OPCODE_WRITE_WITH_NOTIFY;
		goto write_with_notify_sge_check;
	case URMA_OPC_SEND:
		*udma_opcode = UDMA_OPCODE_SEND;
		goto send_sge_check;
	case URMA_OPC_SEND_IMM:
		*udma_opcode = UDMA_OPCODE_SEND_WITH_IMM;
		goto send_sge_check;
	case URMA_OPC_SEND_INVALIDATE:
		*udma_opcode = UDMA_OPCODE_SEND_WITH_INVALID;
		goto send_sge_check;
	case URMA_OPC_CAS:
		*udma_opcode = UDMA_OPCODE_CAS;
		goto cas_faa_sge_check;
	case URMA_OPC_FADD:
		*udma_opcode = UDMA_OPCODE_FAA;
		goto cas_faa_sge_check;
	case URMA_OPC_NOP:
		*udma_opcode = UDMA_OPCODE_NOP;
		goto default_sge_num;
	default:
		UDMA_LOG_ERR("Invalid opcode :%u\n", (uint8_t)opcode);
		return true;
	}

cas_faa_sge_check:
	return sq->max_sge_num == 0;
read_sge_check:
	return wr->rw.dst.num_sge > UDMA_JFS_MAX_SGE_READ || wr->rw.dst.num_sge > sq->max_sge_num;
write_with_notify_sge_check:
	return wr->rw.src.num_sge > UDMA_JFS_MAX_SGE_NOTIFY || wr->rw.src.num_sge > sq->max_sge_num;
write_with_imm_sge_check:
	return wr->rw.src.num_sge > UDMA_JFS_MAX_SGE_WRITE_IMM || wr->rw.src.num_sge > sq->max_sge_num;
send_sge_check:
	return wr->send.src.num_sge > sq->max_sge_num;
default_sge_num:
	return wr->rw.src.num_sge > sq->max_sge_num;
}

static void handle_sq_inline(void *dst_addr, urma_sge_t *sgl, uint32_t i,
			     struct udma_u_jetty_queue *sq)
{
	uint64_t tail_len;

	if ((uint8_t *)dst_addr + sgl[i].len <= (uint8_t *)sq->qbuf_end) {
		(void)memcpy(dst_addr, (void *)sgl[i].addr, sgl[i].len);
	} else {
		tail_len = (uint64_t)sq->qbuf_end - (uint64_t)dst_addr;
		(void)memcpy(dst_addr, (void *)sgl[i].addr, tail_len);
		(void)memcpy(sq->qbuf, (void *)(sgl[i].addr + tail_len), (uint64_t)sgl[i].len - tail_len);
	}
}

static uint32_t get_max_inline_size(uint8_t opcode, uint32_t sq_inline_size)
{
	switch (opcode) {
	case UDMA_OPCODE_WRITE_WITH_IMM:
		return UDMA_MIN(sq_inline_size, SQE_WRITE_IMM_INLINE_SIZE);
	case UDMA_OPCODE_WRITE_WITH_NOTIFY:
		return UDMA_MIN(sq_inline_size, SQE_WRITE_NTF_INLINE_SIZE);
	default:
		return sq_inline_size;
	}
}

static int udma_fill_send_sqe(struct udma_jfs_sqe_ctl *ctrl, urma_jfs_wr_t *wr,
			      struct udma_u_jetty_queue *sq, urma_target_jetty_t *tjetty, uint32_t *wqe_cnt)
{
	struct udma_u_target_jetty *udma_tjetty;
	struct udma_wqe_sge *sge;
	uint32_t total_len = 0;
	uint32_t sge_num = 0;
	urma_sge_t *sgl;
	void *dst_addr;
	uint32_t i;

	sgl = wr->send.src.sge;

	sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)ctrl, (uint32_t)sizeof(struct udma_jfs_sqe_ctl),
						       (uint8_t *)sq->qbuf, (uint8_t *)sq->qbuf_end);

	if (wr->flag.bs.inline_flag) {
		for (i = 0; i < wr->send.src.num_sge; i++) {
			if (total_len + sgl[i].len > sq->max_inline_size) {
				UDMA_LOG_ERR("inline_size %u is over max_size %u.\n",
					     total_len + sgl[i].len, sq->max_inline_size);
				return EINVAL;
			}
			dst_addr = udma_inc_ptr_wrap((uint8_t *)sge, total_len,
						     (uint8_t *)sq->qbuf, (uint8_t *)sq->qbuf_end);
			handle_sq_inline(dst_addr, sgl, i, sq);
			total_len += sgl[i].len;
		}
		ctrl->inline_msg_len = total_len;
		*wqe_cnt = (SQE_NORMAL_CTL_LEN + total_len - 1) / UDMA_JFS_WQEBB + 1;
	} else {
		for (i = 0; i < wr->send.src.num_sge; i++) {
			if (sgl[i].len == 0)
				continue;
			sge->length = sgl[i].len;
			sge->va = sgl[i].addr;
			sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)sge,
								       (uint32_t)sizeof(struct udma_wqe_sge),
								       (uint8_t *)sq->qbuf, (uint8_t *)sq->qbuf_end);
			sge_num++;
		}
		*wqe_cnt = (SQE_NORMAL_CTL_LEN + (sge_num - 1) * UDMA_SGE_SIZE) / UDMA_JFS_WQEBB + 1;
	}

	ctrl->sge_num = sge_num;
	udma_tjetty = to_udma_u_target_jetty(tjetty);
	ctrl->rmt_jetty_or_seg_id = tjetty->id.id;
	ctrl->token_en = udma_tjetty->token_value_valid;
	ctrl->rmt_token_value = udma_tjetty->token_value;
	ctrl->target_hint = wr->send.target_hint;

	return 0;
}

static int udma_fill_write_sqe(struct udma_jfs_sqe_ctl *ctrl, urma_jfs_wr_t *wr,
			       struct udma_wqe_info *wqe_info, struct udma_u_jetty_queue *sq)
{
	struct udma_u_segment *udma_seg;
	struct udma_wqe_sge *sge;
	uint32_t inline_size = 0;
	uint32_t total_len = 0;
	uint32_t sge_num = 0;
	uint32_t ctrl_len;
	urma_sge_t *sgl;
	void *dst_addr;
	uint32_t i;

	sgl = wr->rw.src.sge;
	ctrl_len = get_ctl_len(wqe_info->opcode);
	inline_size = get_max_inline_size(wqe_info->opcode, sq->max_inline_size);

	sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)ctrl, ctrl_len, (uint8_t *)sq->qbuf,
						       (uint8_t *)sq->qbuf_end);

	if (wr->flag.bs.inline_flag) {
		for (i = 0; i < wr->rw.src.num_sge; i++) {
			if (total_len + sgl[i].len > inline_size) {
				UDMA_LOG_ERR("inline_size %u is over max_size %u.\n",
					     total_len + sgl[i].len, inline_size);
				return EINVAL;
			}
			dst_addr = udma_inc_ptr_wrap((uint8_t *)sge, total_len,
						     (uint8_t *)sq->qbuf, (uint8_t *)sq->qbuf_end);
			handle_sq_inline(dst_addr, sgl, i, sq);
			total_len += sgl[i].len;
		}
		ctrl->inline_msg_len = total_len;
		wqe_info->wqe_cnt = (ctrl_len + total_len - 1) / UDMA_JFS_WQEBB + 1;
	} else {
		for (i = 0; i < wr->rw.src.num_sge; i++) {
			if (sgl[i].len == 0)
				continue;
			sge->length = sgl[i].len;
			sge->va = sgl[i].addr;
			sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)sge,
								       (uint32_t)sizeof(struct udma_wqe_sge),
								       (uint8_t *)sq->qbuf, (uint8_t *)sq->qbuf_end);
			sge_num++;
		}
		wqe_info->wqe_cnt = (ctrl_len + (sge_num - 1) * UDMA_SGE_SIZE) / UDMA_JFS_WQEBB + 1;
	}

	sgl = wr->rw.dst.sge;
	udma_seg = to_udma_u_seg(sgl[0].tseg);
	ctrl->sge_num = sge_num;
	ctrl->rmt_jetty_or_seg_id = udma_seg->tid;
	ctrl->token_en = udma_seg->token_value_valid;
	ctrl->rmt_token_value = udma_seg->token_value.token;
	ctrl->target_hint = wr->rw.target_hint;
	ctrl->rmt_addr_l_or_token_id = sgl[0].addr & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->rmt_addr_h_or_token_value = (sgl[0].addr >> UDMA_SQE_CTL_RMA_ADDR_OFFSET) & UDMA_SQE_CTL_RMA_ADDR_BIT;

	return 0;
}

static int udma_fill_read_sqe(struct udma_jfs_sqe_ctl *ctrl, urma_jfs_wr_t *wr,
			      uint32_t *wqe_cnt, struct udma_u_jetty_queue *sq)
{
	struct udma_u_segment *udma_seg;
	struct udma_wqe_sge *sge;
	uint32_t sge_num = 0;
	urma_sge_t *sgl;
	uint32_t i;

	sgl = wr->rw.dst.sge;
	sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)ctrl,
						      sizeof(struct udma_jfs_sqe_ctl),
						      (uint8_t *)sq->qbuf,
						      (uint8_t *)sq->qbuf_end);

	for (i = 0; i < wr->rw.dst.num_sge; i++) {
		if (sgl[i].len == 0)
			continue;
		sge->length = sgl[i].len;
		sge->va = sgl[i].addr;
		sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)sge,
						     sizeof(struct udma_wqe_sge),
						     (uint8_t *)sq->qbuf,
						     (uint8_t *)sq->qbuf_end);
		sge_num++;
	}
	*wqe_cnt = (SQE_NORMAL_CTL_LEN + (sge_num - 1) * UDMA_SGE_SIZE) / UDMA_JFS_WQEBB + 1;

	sgl = wr->rw.src.sge;
	udma_seg = to_udma_u_seg(sgl[0].tseg);

	ctrl->rmt_addr_l_or_token_id = sgl[0].addr & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->rmt_addr_h_or_token_value = (sgl[0].addr >> UDMA_SQE_CTL_RMA_ADDR_OFFSET) & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->sge_num = sge_num;
	ctrl->rmt_jetty_or_seg_id = udma_seg->tid;
	ctrl->token_en = udma_seg->token_value_valid;
	ctrl->rmt_token_value = udma_seg->token_value.token;

	return 0;
}

static int udma_fill_cas_sqe(struct udma_jfs_sqe_ctl *ctrl, urma_jfs_wr_t *wr, struct udma_u_jetty_queue *sq)
{
	struct udma_u_segment *udma_seg;
	struct udma_wqe_sge *sge;
	urma_sge_t *sgl;

	sgl = wr->cas.src;
	if (!udma_check_atomic_len(sgl->len, wr->opcode))
		return EINVAL;
	sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)ctrl,
						      sizeof(struct udma_jfs_sqe_ctl),
						      (uint8_t *)sq->qbuf,
						      (uint8_t *)sq->qbuf_end);

	sge->length = sgl->len;
	sge->va = sgl->addr;

	sgl = wr->cas.dst;
	udma_seg = to_udma_u_seg(sgl->tseg);

	ctrl->rmt_addr_l_or_token_id = sgl->addr & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->rmt_addr_h_or_token_value = (sgl->addr >> UDMA_SQE_CTL_RMA_ADDR_OFFSET) & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->rmt_jetty_or_seg_id = udma_seg->tid;
	ctrl->token_en = udma_seg->token_value_valid;
	ctrl->rmt_token_value = udma_seg->token_value.token;
	ctrl->sge_num = UDMA_ATOMIC_SGE_NUM;

	if (sge->length <= UDMA_ATOMIC_LEN_8) {
		memcpy(udma_inc_ptr_wrap((uint8_t *)ctrl, SQE_ATOMIC_DATA_FIELD, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), &wr->cas.swap_data, sge->length);
		memcpy(udma_inc_ptr_wrap((uint8_t *)ctrl, SQE_ATOMIC_DATA_FIELD + sge->length, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), &wr->cas.cmp_data, sge->length);
	} else {
		memcpy(udma_inc_ptr_wrap((uint8_t *)ctrl, SQE_ATOMIC_DATA_FIELD, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), (void *)wr->cas.swap_addr, sge->length);
		memcpy(udma_inc_ptr_wrap((uint8_t *)ctrl, SQE_ATOMIC_DATA_FIELD + sge->length, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), (void *)wr->cas.cmp_addr, sge->length);
	}

	return 0;
}

static int udma_fill_faa_sqe(struct udma_jfs_sqe_ctl *ctrl, urma_jfs_wr_t *wr, struct udma_u_jetty_queue *sq)
{
	struct udma_u_segment *udma_seg;
	struct udma_wqe_sge *sge;
	urma_sge_t *sgl;

	sgl = wr->faa.src;
	if (!udma_check_atomic_len(sgl->len, wr->opcode))
		return EINVAL;
	sge = (struct udma_wqe_sge *)udma_inc_ptr_wrap((uint8_t *)ctrl,
						      sizeof(struct udma_jfs_sqe_ctl),
						      (uint8_t *)sq->qbuf,
						      (uint8_t *)sq->qbuf_end);

	sge->length = sgl->len;
	sge->va = sgl->addr;

	sgl = wr->faa.dst;
	udma_seg = to_udma_u_seg(sgl->tseg);

	ctrl->rmt_addr_l_or_token_id = sgl->addr & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->rmt_addr_h_or_token_value = (sgl->addr >> UDMA_SQE_CTL_RMA_ADDR_OFFSET) & UDMA_SQE_CTL_RMA_ADDR_BIT;
	ctrl->rmt_jetty_or_seg_id = udma_seg->tid;
	ctrl->token_en = udma_seg->token_value_valid;
	ctrl->rmt_token_value = udma_seg->token_value.token;
	ctrl->sge_num = UDMA_ATOMIC_SGE_NUM;

	if (sge->length <= UDMA_ATOMIC_LEN_8)
		memcpy(udma_inc_ptr_wrap((uint8_t *)ctrl, SQE_ATOMIC_DATA_FIELD, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), &wr->faa.operand,
					 sge->length);
	else
		memcpy(udma_inc_ptr_wrap((uint8_t *)ctrl, SQE_ATOMIC_DATA_FIELD, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), (void *)wr->faa.operand_addr, sge->length);
	return 0;
}

static int udma_parse_jfs_wr(struct udma_jfs_sqe_ctl *wqe_ctl,
			     urma_jfs_wr_t *wr, struct udma_u_jetty_queue *sq,
			     struct udma_wqe_info *wqe_info, urma_target_jetty_t *tjetty)
{
	struct udma_u_target_jetty *udma_tjetty;
	struct udma_token_info *token_info;
	struct udma_u_segment *udma_seg;
	urma_sge_t *sgl;
	int ret;

	switch (wqe_info->opcode) {
	case UDMA_OPCODE_SEND:
		return udma_fill_send_sqe(wqe_ctl, wr, sq, tjetty, &wqe_info->wqe_cnt);
	case UDMA_OPCODE_SEND_WITH_IMM:
		ret = udma_fill_send_sqe(wqe_ctl, wr, sq, tjetty, &wqe_info->wqe_cnt);
		if (ret)
			return ret;
		memcpy((void *)((char *)wqe_ctl + SQE_SEND_IMM_FIELD), &wr->send.imm_data,
		       sizeof(uint64_t));
		return ret;
	case UDMA_OPCODE_SEND_WITH_INVALID:
		ret = udma_fill_send_sqe(wqe_ctl, wr, sq, tjetty, &wqe_info->wqe_cnt);
		if (ret)
			return ret;
		udma_seg = to_udma_u_seg(wr->send.tseg);
		wqe_ctl->rmt_addr_l_or_token_id = udma_seg->tid;
		wqe_ctl->rmt_addr_h_or_token_value = udma_seg->token_value.token;
		return ret;
	case UDMA_OPCODE_WRITE:
		return udma_fill_write_sqe(wqe_ctl, wr, wqe_info, sq);
	case UDMA_OPCODE_WRITE_WITH_IMM:
		ret = udma_fill_write_sqe(wqe_ctl, wr, wqe_info, sq);
		if (ret)
			return ret;
		udma_tjetty = to_udma_u_target_jetty(tjetty);
		token_info = (struct udma_token_info *)
			     ((void *)((char *)wqe_ctl + WRITE_IMM_TOKEN_FIELD));
		memcpy((void *)((char *)wqe_ctl + SQE_WRITE_IMM_FIELD), &wr->rw.notify_data,
		       sizeof(uint64_t));
		token_info->token_id = tjetty->id.id;
		token_info->token_value = udma_tjetty->token_value;
		return ret;
	case UDMA_OPCODE_WRITE_WITH_NOTIFY:
		ret = udma_fill_write_sqe(wqe_ctl, wr, wqe_info, sq);
		if (ret)
			return ret;
		sgl = wr->rw.dst.sge;
		udma_seg = to_udma_u_seg(sgl[1].tseg);
		token_info = (struct udma_token_info *)
			     ((void *)((char *)wqe_ctl + WRITE_NOTIFY_TOKEN_FIELD));
		token_info->token_id = udma_seg->tid;
		token_info->token_value = udma_seg->token_value.token;
		memcpy(udma_inc_ptr_wrap((uint8_t *)wqe_ctl, SQE_NOTIFY_ADDR_FIELD, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), &sgl[1].addr,
					 sizeof(uint64_t));
		memcpy(udma_inc_ptr_wrap((uint8_t *)wqe_ctl, SQE_NOTIFY_DATA_FIELD, (uint8_t *)sq->qbuf,
					 (uint8_t *)sq->qbuf_end), &wr->rw.notify_data,
					 sizeof(uint64_t));
		return ret;
	case UDMA_OPCODE_READ:
		return udma_fill_read_sqe(wqe_ctl, wr, &wqe_info->wqe_cnt, sq);
	case UDMA_OPCODE_CAS:
		wqe_info->wqe_cnt = UDMA_ATOMIC_WQE_BB_NUM;
		return udma_fill_cas_sqe(wqe_ctl, wr, sq);
	case UDMA_OPCODE_FAA:
		wqe_info->wqe_cnt = UDMA_ATOMIC_WQE_BB_NUM;
		return udma_fill_faa_sqe(wqe_ctl, wr, sq);
	default:
		return 0;
	}
}

static bool udma_check_sq_overflow(struct udma_u_jetty_queue *sq, urma_jfs_wr_t *wr,
				   struct udma_wqe_info *wqe_info)
{
	uint32_t wqe_bb_cnt = MAX_SQE_BB_NUM;
	uint32_t max_inline_size = 0;
	uint32_t wqe_ctrl_len = 0;
	uint32_t num_sge_wr = 0;
	uint32_t total_len = 0;
	uint32_t udma_opcode;
	uint32_t sge_num = 0;
	urma_sge_t *sgl;
	uint32_t i;

	if (!udma_sq_overflow(sq, wqe_bb_cnt))
		return false;

	udma_opcode = wqe_info->opcode;

	if (udma_opcode == UDMA_OPCODE_FAA || udma_opcode == UDMA_OPCODE_CAS) {
		wqe_bb_cnt = UDMA_ATOMIC_WQE_BB_NUM;
		return udma_sq_overflow(sq, wqe_bb_cnt);
	}

	if (udma_opcode == UDMA_OPCODE_NOP) {
		wqe_bb_cnt = NOP_WQEBB_CNT;
		return udma_sq_overflow(sq, wqe_bb_cnt);
	}

	wqe_ctrl_len = get_ctl_len(udma_opcode);

	if (udma_opcode <= UDMA_OPCODE_SEND_WITH_INVALID) {
		num_sge_wr = wr->send.src.num_sge;
		sgl = wr->send.src.sge;
	} else if (udma_opcode >= UDMA_OPCODE_WRITE && udma_opcode <= UDMA_OPCODE_WRITE_WITH_NOTIFY) {
		num_sge_wr = wr->rw.src.num_sge;
		sgl = wr->rw.src.sge;
	} else {
		num_sge_wr = wr->rw.dst.num_sge;
		sgl = wr->rw.dst.sge;
	}

	if (wr->flag.bs.inline_flag && udma_opcode != UDMA_OPCODE_READ) {
		max_inline_size = get_max_inline_size(udma_opcode, sq->max_inline_size);
		for (i = 0; i < num_sge_wr; i++) {
			total_len += sgl[i].len;
			if (total_len > max_inline_size) {
				UDMA_LOG_ERR("inline_size %u is over max_size %u.\n",
					      total_len, max_inline_size);
				return true;
			}
		}
		wqe_bb_cnt = (wqe_ctrl_len + total_len - 1) / UDMA_JFS_WQEBB + 1;
	} else {
		for (i = 0; i < num_sge_wr; i++)
			sgl[i].len == 0 ? 0 : sge_num++;

		wqe_bb_cnt = (wqe_ctrl_len + (sge_num - 1) * UDMA_SGE_SIZE) / UDMA_JFS_WQEBB + 1;
	}

	return udma_sq_overflow(sq, wqe_bb_cnt);
}

static urma_status_t udma_set_sqe(struct udma_jfs_sqe_ctl *wqe_ctl,
				  struct udma_u_jetty_queue *sq,
				  urma_jfs_wr_t *wr, struct udma_wqe_info *wqe_info)
{
	struct udma_u_target_jetty *udma_tjetty;
	urma_target_jetty_t *tjetty;

	if (udma_check_sq_overflow(sq, wr, wqe_info)) {
		UDMA_LOG_ERR("JFS overflow.\n");
		return URMA_EINVAL;
	}

	(void)memset(wqe_ctl, 0, sizeof(*wqe_ctl));
	wqe_ctl->opcode = wqe_info->opcode;
	wqe_ctl->flag = wr->flag.value;
	wqe_ctl->owner = ((sq->pi & sq->baseblk_cnt) == 0 ? 1 : 0);

	if (wqe_info->opcode == UDMA_OPCODE_NOP) {
		wqe_info->wqe_cnt = NOP_WQEBB_CNT;
		return URMA_SUCCESS;
	}

	if (sq->trans_mode == URMA_TM_RC)
		tjetty = &sq->tjetty->urma_tjetty;
	else
		tjetty = wr->tjetty;

	udma_tjetty = to_udma_u_target_jetty(tjetty);

	wqe_ctl->tp_id = tjetty->tp.tpn;

	memcpy(wqe_ctl->rmt_eid, &udma_tjetty->le_eid.raw, sizeof(uint8_t) *
	       URMA_EID_SIZE);

	wqe_ctl->rmt_jetty_type = (uint8_t)(tjetty->type);
	if (udma_parse_jfs_wr(wqe_ctl, wr, sq, wqe_info, tjetty) != 0) {
		UDMA_LOG_ERR("Failed to parse wr\n");
		return URMA_EINVAL;
	}

	return URMA_SUCCESS;
}

urma_status_t udma_u_post_one_wr(struct udma_u_context *udma_ctx,
				 struct udma_u_jetty_queue *sq,
				 urma_jfs_wr_t *wr,
				 struct udma_jfs_sqe_ctl **wqe_addr,
				 bool *dwqe_enable)
{
	struct udma_wqe_info wqe_info = {};
	uint32_t wqebb_cnt;
	urma_status_t ret;
	uint32_t i;

	if (udma_check_sge_num_and_opcode(wr->opcode, sq, wr, &wqe_info.opcode)) {
		UDMA_LOG_ERR("wr sge num or opcode is invalid.\n");
		return URMA_EINVAL;
	}

	ret = udma_set_sqe((struct udma_jfs_sqe_ctl *)sq->qbuf_curr, sq, wr, &wqe_info);
	if (ret)
		return ret;

	wqebb_cnt = wqe_info.wqe_cnt;
	if (wqebb_cnt == 1 && udma_ctx->dwqe_enable)
		*dwqe_enable = true;

	*wqe_addr = (struct udma_jfs_sqe_ctl *)sq->qbuf_curr;

	sq->qbuf_curr = udma_inc_ptr_wrap((uint8_t *)sq->qbuf_curr,
					  wqebb_cnt << sq->baseblk_shift,
					  (uint8_t *)sq->qbuf,
					  (uint8_t *)sq->qbuf_end);
	for (i = 0; i < wqebb_cnt; i++)
		sq->wrid[(sq->pi + i) & (sq->baseblk_cnt - 1)] = wr->user_ctx;
	sq->pi += wqebb_cnt;

	return URMA_SUCCESS;
}

urma_status_t udma_u_post_sq_wr(struct udma_u_context *udma_ctx,
				struct udma_u_jetty_queue *sq, urma_jfs_wr_t *wr,
				urma_jfs_wr_t **bad_wr)
{
	struct udma_jfs_sqe_ctl *wqe_addr;
	urma_status_t ret = URMA_SUCCESS;
	bool dwqe_enable = false;
	urma_jfs_wr_t *it;
	int wr_cnt = 0;

	if (!sq->lock_free)
		(void)pthread_spin_lock(&sq->lock);

	for (it = wr; it != NULL; it = (urma_jfs_wr_t *)(void *)it->next) {
		ret = udma_u_post_one_wr(udma_ctx, sq, it, &wqe_addr, &dwqe_enable);
		if (ret) {
			*bad_wr = (urma_jfs_wr_t *)it;
			break;
		}
		wr_cnt++;
	}

	if (wr_cnt) {
		UDMA_TO_DEVICE_BARRIER();

		if (wr_cnt == 1 && dwqe_enable && (sq->pi - sq->ci == 1))
			udma_write_dsqe(sq, wqe_addr);
		else
			udma_update_sq_db(sq);
	}

	if (!sq->lock_free)
		(void)pthread_spin_unlock(&sq->lock);

	return ret;
}

urma_status_t udma_u_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				 urma_jfs_wr_t **bad_wr)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	urma_status_t ret;

	udma_jfs = to_udma_u_jfs(jfs);
	udma_ctx = to_udma_u_ctx(jfs->urma_ctx);

	ret = udma_u_post_sq_wr(udma_ctx, &udma_jfs->sq, wr, bad_wr);
	if (ret)
		UDMA_LOG_ERR("JFS post sq wr failed, jfs id = %u.\n",
			     udma_jfs->sq.idx);

	return ret;
}

void udma_reset_sw_u_jetty_queue(struct udma_u_jetty_queue *sq)
{
	sq->qbuf_curr = sq->qbuf;
	sq->pi = 0;
	sq->ci = 0;
	sq->flush_flag = false;
}

urma_status_t udma_u_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *jfs_attr)
{
	struct udma_u_jfs *udma_jfs = to_udma_u_jfs(jfs);
	int ret;

	if (!(jfs_attr->mask & JFS_STATE)) {
		UDMA_LOG_ERR("modify jfs mask is error or not set, jfs_id = %u.\n",
			     jfs->jfs_id.id);
		return URMA_EINVAL;
	}

	ret = urma_cmd_modify_jfs(jfs, jfs_attr, NULL);
	if (ret) {
		UDMA_LOG_ERR("urma cmd modify jfs failed, ret = %d\n", ret);
		return URMA_FAIL;
	}

	if (jfs_attr->state == URMA_JETTY_STATE_READY)
		udma_reset_sw_u_jetty_queue(&udma_jfs->sq);

	return URMA_SUCCESS;
}

urma_status_t udma_u_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg,
			       urma_jfs_attr_t *attr)
{
	int ret;

	ret = urma_cmd_query_jfs(jfs, cfg, attr);
	if (ret) {
		UDMA_LOG_ERR("failed to query jfs in urma cmd, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

static void copy_from_sq(struct udma_u_jetty_queue *sq, uint32_t wqebb_cnt,
			 struct udma_jfs_wqebb *tmp_sq)
{
	uint32_t remain = sq->baseblk_cnt - (sq->ci & (sq->baseblk_cnt - 1));
	uint32_t field_h;
	uint32_t field_l;
	uint32_t offset;

	offset = (sq->ci & (sq->baseblk_cnt - 1)) * UDMA_JFS_WQEBB;
	field_h = remain > wqebb_cnt ? wqebb_cnt : remain;
	field_l = wqebb_cnt > field_h ? wqebb_cnt - field_h : 0;

	(void)memcpy((void *)tmp_sq, sq->qbuf + offset, field_h * sizeof(struct udma_jfs_wqebb));

	if (field_l)
		(void)memcpy(tmp_sq + field_h, sq->qbuf, field_l * sizeof(struct udma_jfs_wqebb));
}

static void udma_u_process_opcode_for_cr(struct udma_jfs_sqe_ctl *wqe_ctl,
					 urma_cr_t *cr)
{
	uint8_t opcode;

	opcode = wqe_ctl->opcode;

	switch (opcode) {
	case UDMA_OPCODE_SEND:
	case UDMA_OPCODE_WRITE:
	case UDMA_OPCODE_READ:
	case UDMA_OPCODE_CAS:
	case UDMA_OPCODE_FAA:
	case UDMA_OPCODE_WRITE_WITH_NOTIFY:
		break;
	case UDMA_OPCODE_SEND_WITH_IMM:
		memcpy(&cr->imm_data, (void *)((char *)wqe_ctl + SQE_SEND_IMM_FIELD),
		       sizeof(uint64_t));
		break;
	case UDMA_OPCODE_SEND_WITH_INVALID:
		cr->invalid_token.token_id = wqe_ctl->rmt_addr_l_or_token_id & UDMA_SQE_CTL_TOKEN_ID_BIT;
		cr->invalid_token.token_value.token = wqe_ctl->rmt_addr_h_or_token_value;
		break;
	case UDMA_OPCODE_WRITE_WITH_IMM:
		memcpy(&cr->imm_data, (void *)((char *)wqe_ctl + SQE_WRITE_IMM_FIELD),
		       sizeof(uint64_t));
		break;
	default:
		UDMA_LOG_ERR("invalid opcode %u when flush jfs.\n", opcode);
		break;
	}

	/* Fill in UINT8_MAX for send direction */
	cr->opcode = (urma_cr_opcode_t)UINT8_MAX;
}

static void fill_cr_by_wqe_ctl(struct udma_jfs_sqe_ctl *wqe_ctl,
			       urma_cr_t *cr)
{
	struct udma_wqe_sge *sge;
	uint32_t src_sge_num = 0;
	uint64_t total_len = 0;
	uint32_t ctrl_len;
	uint32_t i;

	(void)memset(cr, 0, sizeof(urma_cr_t));

	cr->status = URMA_CR_WR_UNHANDLED;
	udma_u_process_opcode_for_cr(wqe_ctl, cr);
	cr->remote_id.id = wqe_ctl->rmt_jetty_or_seg_id;
	cr->tpn = wqe_ctl->tp_id;

	if (wqe_ctl->flag & UDMAWQE_INLINE_EN) {
		cr->completion_len = wqe_ctl->inline_msg_len;
		return;
	}

	src_sge_num = wqe_ctl->sge_num;
	ctrl_len = get_ctl_len(wqe_ctl->opcode);
	sge = (struct udma_wqe_sge *)((void *)((char *)wqe_ctl + ctrl_len));
	for (i = 0; i < src_sge_num; i++) {
		total_len += sge->length;
		sge++;
	}

	if (total_len > UINT32_MAX) {
		cr->completion_len = UINT32_MAX;
		UDMA_LOG_WARN("total_len %lu is overflow.\n", total_len);
	} else {
		cr->completion_len = total_len;
	}
}

void udma_u_flush_sq(uint32_t local_id, struct udma_u_jetty_queue *sq,
		     urma_cr_t *cr, bool is_jetty)
{
	struct udma_jfs_wqebb tmp_sq[MAX_SQE_BB_NUM];
	struct udma_jfs_sqe_ctl *wqe_ctl;
	uint32_t wqebb_cnt;

	copy_from_sq(sq, MAX_SQE_BB_NUM, tmp_sq);
	wqe_ctl = (struct udma_jfs_sqe_ctl *)(void *)tmp_sq;
	fill_cr_by_wqe_ctl(wqe_ctl, cr);
	cr->local_id = local_id;
	cr->user_ctx = sq->wrid[sq->ci & (sq->baseblk_cnt - 1)];
	cr->flag.bs.jetty = is_jetty;

	wqebb_cnt = get_wqebb_cnt(wqe_ctl);
	sq->ci += wqebb_cnt;
}

int udma_u_flush_jfs(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr)
{
	struct udma_u_jfs *udma_jfs = to_udma_u_jfs(jfs);
	struct udma_u_jetty_queue *sq;
	int n_flushed;

	sq = &udma_jfs->sq;
	if (!sq->flush_flag)
		return 0;

	if (!sq->lock_free)
		(void)pthread_spin_lock(&sq->lock);

	for (n_flushed = 0; n_flushed < cr_cnt; ++n_flushed) {
		if (sq->ci == sq->pi)
			break;
		udma_u_flush_sq(jfs->jfs_id.id, sq, cr + n_flushed, false);
	}

	if (!sq->lock_free)
		(void)pthread_spin_unlock(&sq->lock);

	return n_flushed;
}
