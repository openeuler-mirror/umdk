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

#ifndef _UDMA_U_BUF_H
#define _UDMA_U_BUF_H

#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"

int udma_alloc_buf(struct udma_buf *buf, uint32_t size, int page_size);
void udma_free_buf(struct udma_buf *buf);

#endif /* _UDMA_U_BUF_H */
