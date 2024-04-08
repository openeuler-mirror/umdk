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

#ifndef _UDMA_U_TP_H
#define _UDMA_U_TP_H

#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_jetty.h"
#include "urma_provider.h"

#define max(a, b) ((a) > (b) ? (a) : (b))

struct jfs_conn_node {
	struct connect_node	*tgt_conn_node;
	struct udma_jfs_qp_node	*qp_conn_node;
};

int mmap_dwqe(struct urma_context *urma_ctx, struct udma_qp *qp);
#endif /* _UDMA_U_TP_H */
