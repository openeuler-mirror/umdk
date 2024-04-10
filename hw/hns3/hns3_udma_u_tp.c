// SPDX-License-Identifier: GPL-2.0
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

#include <sys/mman.h>
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_tp.h"

int mmap_dwqe(struct urma_context *urma_ctx, struct udma_qp *qp)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(urma_ctx);
	off_t offset;

	offset = get_mmap_offset(qp->qp_num, udma_ctx->page_size,
				 HNS3_UDMA_MMAP_DWQE_PAGE);
	qp->dwqe_page = mmap(NULL, HNS3_UDMA_DWQE_PAGE_SIZE, PROT_WRITE,
			     MAP_SHARED, urma_ctx->dev_fd, offset);
	if (qp->dwqe_page == MAP_FAILED) {
		URMA_LOG_ERR("failed to mmap direct wqe page, QPN = %lu.\n",
			     qp->qp_num);
		return EINVAL;
	}

	return 0;
}

