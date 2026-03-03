/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_JFC_H__
#define __UDMA_U_JFC_H__

#include "urma_types.h"
#include "udma_u_common.h"

#define UDMA_U_MIN_JFC_DEPTH 64

#define UDMA_U_JFC_DB_CI_IDX_M GENMASK(21, 0)
#define UDMA_U_CQE_INV_TOKEN_ID GENMASK(19, 0)

struct udma_u_jfc_cqe {
	/* DW0 */
	uint32_t s_r : 1;
	uint32_t is_jetty : 1;
	uint32_t owner : 1;
	uint32_t inline_en : 1;
	uint32_t opcode : 3;
	uint32_t fd : 1;
	uint32_t rsv : 8;
	uint32_t substatus : 8;
	uint32_t status : 8;
	/* DW1 */
	uint32_t entry_idx : 16;
	uint32_t local_num_l : 16;
	/* DW2 */
	uint32_t local_num_h : 4;
	uint32_t rmt_idx : 20;
	uint32_t rsv1 : 8;
	/* DW3 */
	uint32_t tpn : 24;
	uint32_t rsv2 : 8;
	/* DW4 */
	uint32_t byte_cnt;
	/* DW5 ~ DW6 */
	uint32_t user_data_l;
	uint32_t user_data_h;
	/* DW7 ~ DW10 */
	uint32_t rmt_eid[4];
	/* DW11 ~ DW12 */
	uint32_t data_l;
	uint32_t data_h;
	/* DW13 ~ DW15 */
	uint32_t inline_data[3];
};

static inline void *get_u_buf_entry(struct udma_u_jetty_queue *cq, uint32_t n)
{
	return (char *)cq->qbuf + ((n & cq->baseblk_mask) << cq->baseblk_shift);
}

urma_jfc_t *udma_u_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg);
urma_status_t udma_u_alloc_jfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg, urma_jfc_t **jfc);
urma_status_t udma_u_set_jfc_opt(urma_jfc_t *jfc, uint64_t opt, void *buf, uint32_t len);
urma_status_t udma_u_active_jfc(urma_jfc_t *jfc);
urma_status_t udma_u_get_jfc_opt(urma_jfc_t *jfc, uint64_t opt, void *buf, uint32_t len);
urma_status_t udma_u_deactive_jfc(urma_jfc_t *jfc);
urma_status_t udma_u_free_jfc(urma_jfc_t *jfc);
urma_status_t udma_u_delete_jfc(urma_jfc_t *jfc);
int udma_u_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
int udma_u_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
		    urma_jfc_t *jfc[]);
void udma_u_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);
urma_status_t udma_u_rearm_jfc(urma_jfc_t *jfc, bool solicited_only);
urma_jfce_t *udma_u_create_jfce(urma_context_t *ctx);
urma_status_t udma_u_delete_jfce(urma_jfce_t *jfce);
urma_status_t udma_u_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr);
urma_status_t udma_u_get_async_event(urma_context_t *ctx,
				     urma_async_event_t *event);
void udma_u_ack_async_event(urma_async_event_t *event);
void udma_u_clean_jfc(struct urma_jfc *jfc, uint32_t jetty_id);
int udma_u_query_cqe_aux_info(urma_context_t *ctx, urma_user_ctl_in_t *in,
			      urma_user_ctl_out_t *out,
			      enum udma_u_user_ctl_opcode op);
#endif /* __UDMA_U_JFC_H__ */
