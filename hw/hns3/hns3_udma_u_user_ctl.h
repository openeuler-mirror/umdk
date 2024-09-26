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

#ifndef _HNS3_UDMA_U_USER_CTL_H
#define _HNS3_UDMA_U_USER_CTL_H

int hns3_udma_u_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in,
			 urma_user_ctl_out_t *out);

#endif /* _HNS3_UDMA_U_USER_CTL_H */
