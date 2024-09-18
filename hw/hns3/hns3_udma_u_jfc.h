/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _HNS3_UDMA_U_JFC_H
#define _HNS3_UDMA_U_JFC_H

#include "urma_types.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_jfr.h"

#define CQE_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))

#define CQE_OPCODE CQE_FIELD_LOC(4, 0)
#define CQE_S_R CQE_FIELD_LOC(6, 6)
#define CQE_OWNER CQE_FIELD_LOC(7, 7)
#define CQE_STATUS CQE_FIELD_LOC(15, 8)
#define CQE_WQE_IDX CQE_FIELD_LOC(31, 16)
#define CQE_RKEY_IMMTDATA CQE_FIELD_LOC(63, 32)
#define CQE_CQE_INLINE CQE_FIELD_LOC(89, 88)
#define CQE_LCL_QPN CQE_FIELD_LOC(119, 96)
#define CQE_BYTE_CNT CQE_FIELD_LOC(159, 128)
#define CQE_PORT_TYPE CQE_FIELD_LOC(209, 208)
#define CQE_RMT_QPN CQE_FIELD_LOC(247, 224)

enum {
	CQE_FOR_SEND,
	CQE_FOR_RECEIVE,
};

enum {
	HNS3_UDMA_CQE_SUCCESS			= 0x00,
	HNS3_UDMA_CQE_LOCAL_LENGTH_ERR		= 0x01,
	HNS3_UDMA_CQE_LOCAL_QP_OP_ERR		= 0x02,
	HNS3_UDMA_CQE_LOCAL_PROT_ERR		= 0x04,
	HNS3_UDMA_CQE_WR_FLUSH_ERR		= 0x05,
	HNS3_UDMA_CQE_MEM_MANAGERENT_OP_ERR	= 0x06,
	HNS3_UDMA_CQE_BAD_RESP_ERR		= 0x10,
	HNS3_UDMA_CQE_LOCAL_ACCESS_ERR		= 0x11,
	HNS3_UDMA_CQE_REMOTE_INVAL_REQ_ERR	= 0x12,
	HNS3_UDMA_CQE_REMOTE_ACCESS_ERR		= 0x13,
	HNS3_UDMA_CQE_REMOTE_OP_ERR		= 0x14,
	HNS3_UDMA_CQE_TRANSPORT_RETRY_EXC_ERR	= 0x15,
	HNS3_UDMA_CQE_RNR_RETRY_EXC_ERR		= 0x16,
	HNS3_UDMA_CQE_REMOTE_ABORTED_ERR	= 0x22,
	HNS3_UDMA_CQE_GENERAL_ERR		= 0x23,
};

enum hw_cqe_opcode {
	HW_CQE_OPC_RDMA_WRITE_WITH_IMM		= 0x00,
	HW_CQE_OPC_SEND				= 0x01,
	HW_CQE_OPC_SEND_WITH_IMM		= 0x02,
	HW_CQE_OPC_SEND_WITH_INV		= 0x03,
	HW_CQE_OPC_PERSISTENCE_WRITE_WITH_IMM	= 0x04,
	HW_CQE_OPC_RESIZE_CODING		= 0x16,
	HW_CQE_OPC_ERROR_CODING			= 0x1e,
};

enum jfc_poll_state {
	JFC_OK			= 0,
	JFC_EMPTY		= 1,
	JFC_POLL_ERR		= 2,
};

#define	CQE_INLINE_ENABLE	1
#define	UM_HEADER_DEID		8
#define HNS3_UDMA_POLL_SCR_CNT	1

struct hns3_udma_jfc_cqe {
	/* byte4 */
	uint32_t		opcode : 5;
	uint32_t		rq_inline : 1;
	uint32_t		s_r : 1;
	uint32_t		owner : 1;
	uint32_t		status : 8;
	uint32_t		wqe_idx : 16;

	union {
		uint32_t	rkey;
		uint32_t	immtdata;
	};

	/* byte12 */
	uint32_t		xrc_srqn : 24;
	uint32_t		cqe_inline : 2;
	uint32_t		rsv0 : 6;

	/* byte16 */
	uint32_t		lcl_qpn : 24;
	uint32_t		sub_status : 8;

	uint32_t		byte_cnt;
	uint32_t		smac;
	uint32_t		byte_28;

	/* byte32 */
	uint32_t		rmt_qpn : 24;
	uint32_t		byte_35 : 8;

	uint32_t		pld_in_cqe[8];
};

struct hns3_udma_u_jfc {
	urma_jfc_t			urma_jfc;
	pthread_spinlock_t		lock;
	uint32_t			lock_free;
	uint32_t			cqn;
	uint32_t			pi;
	uint32_t			ci;
	uint32_t			depth;
	uint32_t			cqe_cnt;
	uint32_t			cqe_size;
	uint32_t			cqe_shift;
	struct hns3_udma_buf		buf;
	struct hns3_udma_jfc_cqe	*cqe;
	uint32_t			*db;
	uint32_t			arm_sn;
	uint32_t			caps_flag;
};

struct hns3_udma_jfce {
	urma_jfce_t base;
};

static inline uint32_t get_jid_from_qpn(uint32_t qpn, uint32_t num_qps_shift,
					uint32_t num_jetty_x_shift)
{
	uint32_t high;
	int low;

	/* num_qps_shift must be greater than HNS3_UDMA_JETTY_X_PREFIX_BIT_NUM */
	high = num_qps_shift - HNS3_UDMA_JETTY_X_PREFIX_BIT_NUM;
	low = high - num_jetty_x_shift;
	if (low < 0)
		return FIELD_GET(GENMASK(num_jetty_x_shift - 1, 0), qpn);

	return FIELD_GET(GENMASK(high - 1, low), qpn);
}

static inline void update_cq_db(struct hns3_udma_u_context *udma_ctx,
				struct hns3_udma_u_jfc *udma_u_jfc)
{
	struct hns3_udma_u_db cq_db = {};

	hns3_udma_reg_write(&cq_db, HNS3_UDMA_DB_TAG, udma_u_jfc->cqn);
	hns3_udma_reg_write(&cq_db, HNS3_UDMA_DB_CMD, HNS3_UDMA_CQ_DB_PTR);
	hns3_udma_reg_write(&cq_db, HNS3_UDMA_DB_JFC_CI, udma_u_jfc->ci);
	hns3_udma_reg_write(&cq_db, HNS3_UDMA_DB_JFC_CMD_SN, 1);

	hns3_udma_write64(udma_ctx, (uint64_t *)(udma_ctx->uar + HNS3_UDMA_DB_CFG0_OFFSET),
		    (uint64_t *)&cq_db);
}

static inline struct hns3_udma_u_jfc *to_hns3_udma_jfc(urma_jfc_t *jfc)
{
	return container_of(jfc, struct hns3_udma_u_jfc, urma_jfc);
}

static inline bool hns3_udma_state_reseted(struct hns3_udma_u_context *ctx)
{
	struct hns3_udma_reset_state *state = (struct hns3_udma_reset_state *)ctx->reset_state;

	if (state && state->is_reset)
		return true;

	return false;
}

struct hns3_udma_u_jfc *hns3_udma_u_create_jfc_common(urma_jfc_cfg_t *cfg,
						      struct hns3_udma_u_context *udma_ctx);
void free_err_jfc(struct hns3_udma_u_jfc *jfc, struct hns3_udma_u_context *udma_ctx);
urma_jfc_t *hns3_udma_u_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg);
urma_status_t hns3_udma_u_delete_jfc(urma_jfc_t *jfc);
struct hns3_udma_qp *get_qp_from_qpn(struct hns3_udma_u_context *udma_ctx, uint32_t qpn);
urma_status_t hns3_udma_u_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr);
int hns3_udma_u_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
urma_status_t hns3_udma_u_rearm_jfc(urma_jfc_t *jfc, bool solicited_only);
urma_jfce_t *hns3_udma_u_create_jfce(urma_context_t *ctx);
urma_status_t hns3_udma_u_delete_jfce(urma_jfce_t *jfce);
int hns3_udma_u_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
			 urma_jfc_t *jfc[]);
void hns3_udma_u_ack_jfc(urma_jfc_t **jfc, uint32_t *nevents, uint32_t jfc_cnt);
urma_status_t hns3_udma_u_get_async_event(urma_context_t *ctx,
					  urma_async_event_t *event);
void hns3_udma_u_ack_async_event(urma_async_event_t *event);

#endif  /* _HNS3_UDMA_U_JFC_H */
