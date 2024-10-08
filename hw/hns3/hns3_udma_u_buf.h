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

#ifndef _HNS3_UDMA_U_BUF_H
#define _HNS3_UDMA_U_BUF_H

#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"

#define HNS3_UDMA_DCA_MAX_MEM_SIZE ~0UL

struct hns3_udma_u_dca_mem {
	struct list_head	entry;
	struct hns3_udma_buf	buf;
};

struct hns3_udma_dca_buf {
	void		**bufs;
	uint32_t	max_cnt;
	uint32_t	shift;
	uint32_t	dcan;
};

static inline uintptr_t dca_mem_to_key(struct hns3_udma_u_dca_mem *dca_mem)
{
	return (uintptr_t)dca_mem;
}

static inline void *dca_mem_addr(struct hns3_udma_u_dca_mem *dca_mem,
				 uint32_t offset)
{
	return dca_mem->buf.buf + offset;
}

void hns3_udma_u_shrink_dca_mem(struct hns3_udma_u_context *ctx);
void exec_detach_dca_mem_cmd(struct hns3_udma_u_context *ctx,
			     struct hns3_udma_dca_detach_attr *attr);
void exec_deregister_dca_mem_cmd(struct hns3_udma_u_context *ctx,
				 struct hns3_udma_dca_dereg_attr *attr);
bool hns3_udma_dca_start_post(struct hns3_udma_u_dca_ctx *ctx, uint32_t dcan);
void hns3_udma_dca_stop_post(struct hns3_udma_u_dca_ctx *ctx, uint32_t dcan);

int hns3_udma_u_attach_dca_mem(struct hns3_udma_u_context *ctx,
			       struct hns3_udma_dca_attach_attr *attr,
			       uint32_t size, struct hns3_udma_dca_buf *buf,
			       bool force);
int hns3_udma_alloc_buf(struct hns3_udma_buf *buf, uint32_t size, int page_size);
void hns3_udma_free_buf(struct hns3_udma_buf *buf);
void ubn_u_free_dca_mem(struct hns3_udma_u_dca_mem *mem);

#endif /* _HNS3_UDMA_U_BUF_H */
