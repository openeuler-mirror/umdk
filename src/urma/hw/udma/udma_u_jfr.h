/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_JFR_H__
#define __UDMA_U_JFR_H__

#include "udma_u_common.h"

#define UDMA_JFR_IDX_QUE_ENTRY_SZ 4
#define UDMA_JFR_DB_PROD_IDX_M GENMASK(15, 0)
#define UDMA_U_MIN_JFR_DEPTH 64
#define UDMA_JFR_LARGE_PACKAGE 4096

static inline bool udma_jfrwq_overflow(struct udma_u_jfr *jfr)
{
	return (jfr->rq.pi - jfr->rq.ci) >= jfr->wqe_cnt;
}

static inline void *get_jfr_wqe(struct udma_u_jfr *jfr, uint32_t n)
{
	return (char *)jfr->rq.qbuf + (n << jfr->wqe_shift);
}

static inline void *get_idx_buf(struct udma_u_jfr_idx_que *idx_que, uint32_t n)
{
	return (char *)idx_que->buf.buf + (n << idx_que->entry_shift);
}

static inline void set_data_of_sge(struct udma_wqe_sge *sge, const urma_sge_t *sg)
{
	sge->va = htole64(sg->addr);
	sge->length = htole32(sg->len);
}

urma_jfr_t *udma_u_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg);
urma_status_t udma_u_delete_jfr(urma_jfr_t *jfr);
urma_status_t udma_u_delete_jfr_batch(urma_jfr_t **jfr, int jfr_cnt, urma_jfr_t **bad_jfr);
urma_status_t udma_u_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr,
				 urma_jfr_wr_t **bad_wr);
int udma_verify_modify_jfr(struct udma_u_jfr *jfr, uint32_t jfr_limit);
urma_status_t udma_u_unimport_jfr(urma_target_jetty_t *target_jfr);
urma_status_t udma_u_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr);
urma_status_t udma_u_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg,
			       urma_jfr_attr_t *attr);
int udma_u_verify_jfr_param(urma_context_t *ctx, urma_jfr_cfg_t *cfg);
void udma_u_init_jfr_param(struct udma_u_jfr *jfr, urma_jfr_cfg_t *cfg);
int exec_jfr_create_cmd(urma_context_t *ctx, struct udma_u_jfr *jfr,
			urma_jfr_cfg_t *cfg);
urma_target_jetty_t *udma_u_import_jfr_ex(urma_context_t *ctx,
					  urma_rjfr_t *rjfr,
					  urma_token_t *token_value,
					  urma_active_tp_cfg_t *active_tp_cfg);
int udma_u_insert_jfr_node(struct udma_u_context *udma_ctx, struct udma_u_jfr *jfr);
#endif /* __UDMA_U_JFR_H__ */
