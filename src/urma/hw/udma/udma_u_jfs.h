/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_JFS_H__
#define __UDMA_U_JFS_H__

#include "urma_types.h"
#include "urma_provider.h"
#include "udma_u_common.h"

struct udma_jfs_sqe_ctl {
	/* byte 4 */
	uint32_t sqe_bb_idx : 16;
	uint32_t flag : 7;
	uint32_t udf_flag : 1;
	uint32_t rsv0 : 3;
	uint32_t nf : 1;
	uint32_t token_en : 1;
	uint32_t rmt_jetty_type : 2;
	uint32_t owner : 1;
	/* byte 8 */
	uint32_t target_hint : 8;
	uint32_t opcode : 8;
	uint32_t rsv1 : 6;
	uint32_t inline_msg_len : 10;
	/* byte 12 */
	uint32_t tp_id : 24;
	uint32_t sge_num : 8;
	/* byte 16 */
	uint32_t rmt_jetty_or_seg_id : 20;
	uint32_t rsv2 : 12;
	/* byte 20 - 32 */
	uint8_t rmt_eid[URMA_EID_SIZE];
	/* byte 36 */
	uint32_t rmt_token_value;
	/* byte 40 */
	uint32_t udf_type : 8;
	uint32_t reduce_data_type : 4;
	uint32_t reduce_opcode : 4;
	uint32_t rsv3 : 16;
	/* byte 44 - 48*/
	uint32_t rmt_addr_l_or_token_id;
	uint32_t rmt_addr_h_or_token_value;
};

struct udma_wqe_info {
	uint8_t opcode;
	uint32_t wqe_cnt;
};

struct udma_jfs_wqebb {
	uint32_t value[16];
};

struct udma_token_info {
	uint32_t token_id : 20;
	uint32_t rsv : 12;
	uint32_t token_value;
};

enum udma_jfs_opcode {
	UDMA_OPCODE_SEND = 0x00,
	UDMA_OPCODE_SEND_WITH_IMM,
	UDMA_OPCODE_SEND_WITH_INVALID,
	UDMA_OPCODE_WRITE,
	UDMA_OPCODE_WRITE_WITH_IMM,
	UDMA_OPCODE_WRITE_WITH_NOTIFY,
	UDMA_OPCODE_READ,
	UDMA_OPCODE_CAS,
	UDMA_OPCODE_FAA = 0xb,
	UDMA_OPCODE_NOP = 0x11,
	UDMA_OPCODE_INVALID = 0x12,
};

#define MAX_SQE_BB_NUM 4
#define UDMA_JFS_MAX_SGE_READ 6
#define UDMA_JFS_MAX_SGE_NOTIFY 11
#define UDMA_JFS_MAX_SGE_WRITE_IMM 12
#define NOP_WQEBB_CNT 1
#define SQE_NORMAL_CTL_LEN 48
#define SQE_WRITE_IMM_CTL_LEN 64
#define SQE_WRITE_NOTIFY_CTL_LEN 80
#define SQE_WRITE_IMM_INLINE_SIZE 192u
#define SQE_WRITE_NTF_INLINE_SIZE 176u
#define UDMA_ATOMIC_WQE_BB_NUM 2
#define UDMA_SQE_CTL_RMA_ADDR_BIT GENMASK(31, 0)
#define UDMA_SQE_CTL_TOKEN_ID_BIT GENMASK(19, 0)
#define UDMA_SQE_CTL_RMA_ADDR_OFFSET 32

#define UDMASQE_FIELD_LOC(h, l)   ((uint64_t)(h) << 32 | (l))

#define UDMAWQE_INLINE_EN 0x40

#define SQE_SEND_IMM_FIELD 40
#define SQE_WRITE_IMM_FIELD 48
#define WRITE_IMM_TOKEN_FIELD 56
#define WRITE_NOTIFY_TOKEN_FIELD 48
#define SQE_NOTIFY_ADDR_FIELD 56
#define SQE_NOTIFY_DATA_FIELD 64
#define SQE_ATOMIC_DATA_FIELD 64

#define UDMA_ATOMIC_LEN_4 4
#define UDMA_ATOMIC_LEN_8 8
#define UDMA_ATOMIC_LEN_16 16
#define UDMA_ATOMIC_SGE_NUM 1

#define UDMA_MAX_PRIORITY 16

static inline void udma_u_init_sq_param(struct udma_u_jetty_queue *sq,
					urma_jfs_cfg_t *cfg)
{
	sq->max_inline_size = cfg->max_inline_data;
	sq->pi = 0;
	sq->ci = 0;
}

static inline bool udma_sq_overflow(struct udma_u_jetty_queue *sq,
				    uint32_t wqebb_cnt)
{
	return sq->pi - sq->ci + wqebb_cnt > sq->baseblk_cnt;
}

static inline void udma_update_sq_db(struct udma_u_jetty_queue *sq)
{
	uint32_t *db_addr = (uint32_t *)(sq->db.addr + UDMA_DOORBELL_OFFSET);
	*db_addr = sq->pi;
}

static inline uint32_t sq_cal_wqebb_num(uint32_t sqe_ctl_len, uint32_t sge_num,
					uint32_t wqebb_size)
{
	return (sqe_ctl_len + (sge_num - (uint32_t)1) * (uint32_t)UDMA_SGE_SIZE) /
		wqebb_size + (uint32_t)1;
}

static inline uint32_t get_max_sge_num(uint8_t max_sge, uint32_t max_inline_size)
{
	uint32_t size = (max_inline_size == 0) ?
			1 : ((max_inline_size - (uint32_t)1) / UDMA_SGE_SIZE + (uint32_t)1);
	return UDMA_MAX(max_sge, size);
}

urma_status_t udma_u_post_sq_wr(struct udma_u_context *udma_ctx,
				struct udma_u_jetty_queue *sq, urma_jfs_wr_t *wr,
				urma_jfs_wr_t **bad_wr);
urma_status_t udma_u_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				 urma_jfs_wr_t **bad_wr);
int udma_u_create_sq(struct udma_u_jetty_queue *sq, urma_jfs_cfg_t *cfg);
urma_jfs_t *udma_u_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg);
urma_status_t udma_u_delete_jfs(urma_jfs_t *jfs);
void udma_u_delete_sq(struct udma_u_jetty_queue *sq);
void udma_u_lock_delete_sq(struct udma_u_jetty_queue *sq);
urma_status_t udma_u_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *jfs_attr);
urma_status_t udma_u_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg,
			       urma_jfs_attr_t *attr);
int udma_u_flush_jfs(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr);
void udma_u_flush_sq(uint32_t local_id, struct udma_u_jetty_queue *sq,
		     urma_cr_t *cr, bool is_jetty);
int udma_u_set_sq_by_resp(struct udma_u_jetty_queue *sq,
			  struct udma_create_jetty_resp *resp);
int udma_u_exec_jfs_create_cmd(urma_context_t *ctx,
			       struct udma_u_jfs *jfs,
			       urma_jfs_cfg_t *cfg);
urma_status_t udma_u_post_one_wr(struct udma_u_context *udma_ctx,
				 struct udma_u_jetty_queue *sq,
				 urma_jfs_wr_t *wr,
				 struct udma_jfs_sqe_ctl **wqe_addr,
				 bool *dwqe_enable);
void udma_reset_sw_u_jetty_queue(struct udma_u_jetty_queue *sq);
urma_status_t udma_u_delete_jfs_batch(urma_jfs_t **jfs, int jfs_cnt, urma_jfs_t **bad_jfs);
urma_status_t udma_u_alloc_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg,
			      urma_jfs_t **jfs);
urma_status_t udma_u_set_jfs_opt(urma_jfs_t *jfs, uint64_t opt, void *buf, uint32_t len);
urma_status_t udma_u_active_jfs(urma_jfs_t *jfs);
urma_status_t udma_u_get_jfs_opt(urma_jfs_t *jfs, uint64_t opt, void *buf, uint32_t len);
urma_status_t udma_u_deactive_jfs(urma_jfs_t *jfs);
urma_status_t udma_u_free_jfs(urma_jfs_t *jfs);

#endif /* __UDMA_U_JFS_H__ */
