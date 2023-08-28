/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _UDMA_U_JFC_H
#define _UDMA_U_JFC_H

#include "urma_types.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_jfs.h"

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
	UDMA_CQE_SUCCESS					= 0x00,
	UDMA_CQE_LOCAL_LENGTH_ERR			= 0x01,
	UDMA_CQE_LOCAL_QP_OP_ERR			= 0x02,
	UDMA_CQE_LOCAL_PROT_ERR				= 0x04,
	UDMA_CQE_WR_FLUSH_ERR				= 0x05,
	UDMA_CQE_MEM_MANAGERENT_OP_ERR		= 0x06,
	UDMA_CQE_BAD_RESP_ERR				= 0x10,
	UDMA_CQE_LOCAL_ACCESS_ERR			= 0x11,
	UDMA_CQE_REMOTE_INVAL_REQ_ERR		= 0x12,
	UDMA_CQE_REMOTE_ACCESS_ERR			= 0x13,
	UDMA_CQE_REMOTE_OP_ERR				= 0x14,
	UDMA_CQE_TRANSPORT_RETRY_EXC_ERR	= 0x15,
	UDMA_CQE_RNR_RETRY_EXC_ERR			= 0x16,
	UDMA_CQE_REMOTE_ABORTED_ERR			= 0x22,
	UDMA_CQE_GENERAL_ERR				= 0x23,
	UDMA_CQE_XRC_VIOLATION_ERR			= 0x24,
};

enum hw_cqe_opcode {
	HW_CQE_OPC_RDMA_WRITE_WITH_IMM            = 0x00,
	HW_CQE_OPC_SEND                           = 0x01,
	HW_CQE_OPC_SEND_WITH_IMM                  = 0x02,
	HW_CQE_OPC_SEND_WITH_INV                  = 0x03,
	HW_CQE_OPC_PERSISTENCE_WRITE_WITH_IMM     = 0x04,
	HW_CQE_OPC_RESIZE_CODING                  = 0x16,
	HW_CQE_OPC_ERROR_CODING                   = 0x1e,
};

enum jfc_poll_state {
	JFC_OK               = 0,
	JFC_EMPTY            = 1,
	JFC_POLL_ERR         = 2,
};

#define	CQE_INLINE_ENABLE	1
#define	UM_HEADER_DEID		8

struct udma_jfc_cqe {
	uint32_t		byte_4;
	union {
		uint32_t	rkey;
		uint32_t	immtdata;
	};
	uint32_t		byte_12;
	uint32_t		byte_16;
	uint32_t		byte_cnt;
	uint32_t		smac;
	uint32_t		byte_28;
	uint32_t		byte_32;
	uint32_t		pld_in_cqe[8];
};

struct udma_u_jfc {
	urma_jfc_t		urma_jfc;
	pthread_spinlock_t	lock;
	uint32_t		lock_free;
	uint32_t		cqn;
	uint32_t		ci;
	uint32_t		depth;
	uint32_t		cqe_cnt;
	uint32_t		cqe_size;
	uint32_t		cqe_shift;
	struct udma_buf		buf;
	struct udma_jfc_cqe	*cqe;
	uint32_t		*db;
	uint32_t		arm_sn;
	uint32_t		caps_flag;
};

static inline uint32_t get_jid_from_qpn(uint32_t qpn, uint32_t num_qps_shift,
					uint32_t num_jetty_x_shift)
{
	int high, low;

	/* num_qps_shift must be greater than UDMA_JETTY_X_PREFIX_BIT_NUM */
	high = num_qps_shift - UDMA_JETTY_X_PREFIX_BIT_NUM;
	low = high - num_jetty_x_shift;
	if (low < 0)
		return FIELD_GET(GENMASK(num_jetty_x_shift - 1, 0), qpn);

	return FIELD_GET(GENMASK(high - 1, low), qpn);
}

static inline void update_cq_db(struct udma_u_context *udma_ctx,
				struct udma_u_jfc *udma_u_jfc)
{
	struct udma_u_db cq_db = {};

	udma_reg_write(&cq_db, UDMA_DB_TAG, udma_u_jfc->cqn);
	udma_reg_write(&cq_db, UDMA_DB_CMD, UDMA_CQ_DB_PTR);
	udma_reg_write(&cq_db, UDMA_DB_JFC_CI, udma_u_jfc->ci);
	udma_reg_write(&cq_db, UDMA_DB_JFC_CMD_SN, 1);

	udma_write64(udma_ctx, (uint64_t *)(udma_ctx->uar + UDMA_DB_CFG0_OFFSET),
		    (uint64_t *)&cq_db);
}

static inline struct udma_u_jfc *to_udma_jfc(const urma_jfc_t *jfc)
{
	return container_of(jfc, struct udma_u_jfc, urma_jfc);
}

urma_jfc_t *udma_u_create_jfc(urma_context_t *ctx, const urma_jfc_cfg_t *cfg);
urma_status_t udma_u_delete_jfc(urma_jfc_t *jfc);
int udma_u_poll_jfc(const urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
urma_status_t udma_u_modify_jfc(urma_jfc_t *jfc, const urma_jfc_attr_t *attr);

#endif  /* _UDMA_U_JFC_H */
