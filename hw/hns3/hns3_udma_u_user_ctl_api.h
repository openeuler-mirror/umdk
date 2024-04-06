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

struct hns3_udma_jfc_notify_init_attr {
	uint64_t	notify_addr;
	uint8_t		notify_mode; /* Use enum hns3_udma_jfc_notify_mode */
	uint8_t		reserved[7];
};

struct hns3_udma_jfc_init_attr {
	uint64_t	jfc_ex_mask; /* Use enum hns3_udma_jfc_init_attr_mask */
	uint64_t	create_flags; /* Use enum hns3_udma_jfc_create_flags */
	uint8_t		poe_channel; /* poe channel to use */
	uint8_t		reserved[7];
	struct hns3_udma_jfc_notify_init_attr notify_init_attr;
};

struct hns3_udma_create_jfc_ex_in {
	urma_jfc_cfg_t			*cfg;
	struct hns3_udma_jfc_init_attr	*attr;
};

struct hns3_udma_user_ctl_create_jfc_ex_out {
	urma_jfc_t *jfc;
};

struct hns3_udma_user_ctl_delete_jfc_ex_in {
	urma_jfc_t *jfc;
};

struct hns3_udma_poe_init_attr {
	uint64_t rsv; /* reserved for extension, now must be 0 */
	uint64_t poe_addr; /* 0 for disable */
};

struct hns3_udma_config_poe_channel_in {
	struct hns3_udma_poe_init_attr	*init_attr;
	uint8_t				poe_channel;
};

struct hns3_udma_user_ctl_query_poe_channel_in {
	uint8_t poe_channel;
};

struct hns3_udma_user_ctl_query_poe_channel_out {
	struct hns3_udma_poe_init_attr *init_attr;
};

struct hns3_udma_query_hw_id_out {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t func_id;
	uint32_t reserved;
};

enum hns3_udma_u_user_ctl_opcode {
	HNS3_UDMA_U_USER_CTL_CONFIG_POE_CHANNEL,
	HNS3_UDMA_U_USER_CTL_QUERY_POE_CHANNEL,
	HNS3_UDMA_U_USER_CTL_CREATE_JFC_EX,
	HNS3_UDMA_U_USER_CTL_DELETE_JFC_EX,
	HNS3_UDMA_U_USER_CTL_QUERY_HW_ID,
	HNS3_UDMA_U_USER_CTL_MAX,
};

#endif /* _HNS3_UDMA_U_USER_CTL_API_H */
