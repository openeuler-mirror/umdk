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

#ifndef _HNS3_UDMA_U_DB_H
#define _HNS3_UDMA_U_DB_H

#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"

void *hns3_udma_alloc_sw_db(struct hns3_udma_u_context *ctx, enum hns3_udma_db_type type);
void hns3_udma_free_sw_db(struct hns3_udma_u_context *ctx, uint32_t *db,
			  enum hns3_udma_db_type type);

#endif /* _HNS3_UDMA_U_DB_H */
