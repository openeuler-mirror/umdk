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

#ifndef _HNS3_UDMA_U_USER_CTL_API_H
#define _HNS3_UDMA_U_USER_CTL_API_H

#include "urma_types.h"

struct hns3_udma_query_hw_id_out {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t func_id;
	uint32_t reserved;
};

enum hns3_udma_u_user_ctl_opcode {
	HNS3_UDMA_U_USER_CTL_QUERY_HW_ID,
	HNS3_UDMA_U_USER_CTL_MAX,
};

#endif /* _HNS3_UDMA_U_USER_CTL_API_H */
