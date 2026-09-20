/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_DB_H__
#define __UDMA_U_DB_H__

#include "udma_u_common.h"

void *udma_u_alloc_sw_db(struct udma_u_context *ctx, enum udma_db_type type);
void udma_u_free_sw_db(struct udma_u_context *ctx, uint32_t *db,
		       enum udma_db_type type);
int udma_u_alloc_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db);
void udma_u_free_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db);
uint64_t *udma_bitmap_alloc(uint32_t n_bits, uint32_t *bitmap_cnt);

static inline void udma_bitmap_free(uint64_t *bitmap)
{
	free(bitmap);
}

static inline uint32_t udma_get_dsqe_db_offset(struct udma_u_context *udma_u_ctx, struct udma_u_doorbell *db)
{
	return (db->id + (uint32_t)1) % (udma_u_ctx->page_size / UDMA_HW_PAGE_SIZE) * UDMA_HW_PAGE_SIZE;
}

#endif /* __UDMA_U_DB_H__ */
