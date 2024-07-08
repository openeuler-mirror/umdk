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
#include "hns3_udma_u_jfc.h"
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
		UDMA_LOG_ERR("failed to mmap direct wqe page, QPN = %lu.\n",
			     qp->qp_num);
		return EINVAL;
	}

	return 0;
}

void munmap_dwqe(struct udma_qp *qp)
{
	if (qp->dwqe_page) {
		if (!(munmap(qp->dwqe_page, HNS3_UDMA_DWQE_PAGE_SIZE)))
			UDMA_LOG_ERR("failed to munmap direct wqe page, QPN = %lu.\n",
				     qp->qp_num);
		qp->dwqe_page = NULL;
	}
}

int udma_u_get_tpn(urma_jetty_t *jetty)
{
	return jetty->jetty_id.id;
}

int udma_u_modify_user_tp(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg,
			  urma_tp_attr_t *attr, urma_tp_attr_mask_t mask)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_qp *qp = NULL;

	qp = get_qp_from_qpn(udma_ctx, tpn);
	if (qp == NULL)
		return EINVAL;
	qp->path_mtu = attr->mtu;

	return urma_cmd_modify_tp(ctx, tpn, cfg, attr, mask);
}
