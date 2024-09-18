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

enum hns3_queue_type {
	JFS_TYPE,
	JETTY_TYPE,
};

struct hns3_udma_update_queue_ci_in {
	enum hns3_queue_type		type;
	union {
		urma_jfs_t	*jfs;
		urma_jetty_t	*jetty;
	};
	uint32_t		wqe_cnt;
	urma_target_jetty_t	*tjetty;
};

struct hns3_udma_post_and_ret_db_in {
	enum hns3_queue_type		type;
	union {
		urma_jfs_t	*jfs;
		urma_jetty_t	*jetty;
	};
	urma_jfs_wr_t		*wr;
};

struct hns3_udma_post_and_ret_db_out {
	urma_jfs_wr_t		**bad_wr;
	uint64_t		db_addr;
	uint64_t		db_data;
};

struct hns3_udma_query_hw_id_out {
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t func_id;
	uint32_t reserved;
};

struct hns3_u_udma_get_jetty_info_in {
	enum hns3_queue_type		type;
	union {
		urma_jfs_t	*jfs;
		urma_jetty_t	*jetty;
	};
};

struct hns3_u_udma_get_jetty_info_out {
	void		*queue_addr;
	uint32_t	queue_length;
	void		*ext_sge_addr;
	uint32_t	ext_sge_length;
	void		*user_ctx_addr;
	uint32_t	user_ctx_length;
	void		*db_addr;
	void		*dwqe_addr;
	void		*ext_sge_tail_addr;
	uint32_t	sl;
	void		*head_idx;
	void		*sge_idx;
	bool		dwqe_enable;
};

enum hns3_udma_u_user_ctl_opcode {
	HNS3_UDMA_U_USER_CTL_POST_SEND_AND_RET_DB,
	HNS3_UDMA_U_USER_CTL_CONFIG_POE_CHANNEL,
	HNS3_UDMA_U_USER_CTL_QUERY_POE_CHANNEL,
	HNS3_UDMA_U_USER_CTL_CREATE_JFC_EX,
	HNS3_UDMA_U_USER_CTL_DELETE_JFC_EX,
	HNS3_UDMA_U_USER_CTL_UPDATE_QUEUE_CI,
	HNS3_UDMA_U_USER_CTL_QUERY_HW_ID,
	HNS3_UDMA_U_USER_CTL_GET_JETTY_INFO,
	HNS3_UDMA_U_USER_CTL_MAX,
};

#endif /* _HNS3_UDMA_U_USER_CTL_API_H */
