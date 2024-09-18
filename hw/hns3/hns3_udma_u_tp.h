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

#ifndef _HNS3_UDMA_U_TP_H
#define _HNS3_UDMA_U_TP_H

#include "hns3_udma_u_jfs.h"
#include "urma_provider.h"

#define max(a, b) ((a) > (b) ? (a) : (b))

int mmap_dwqe(struct urma_context *urma_ctx, struct hns3_udma_qp *qp);
void munmap_dwqe(struct hns3_udma_qp *qp);
int hns3_udma_u_get_tpn(urma_jetty_t *jetty);
int hns3_udma_u_modify_user_tp(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg,
			       urma_tp_attr_t *attr, urma_tp_attr_mask_t mask);

#endif /* _HNS3_UDMA_U_TP_H */
