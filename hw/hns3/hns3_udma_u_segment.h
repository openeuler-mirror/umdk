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

#ifndef _UDMA_U_SEGMENT_H
#define _UDMA_U_SEGMENT_H

#include "urma_types.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jfc.h"

#define UDMA_RESERVED_JFR_SGE	1

struct udma_u_seg {
	urma_target_seg_t	urma_seg;
	urma_token_t		token;
};

urma_target_seg_t *udma_u_register_seg(urma_context_t *ctx,
				       urma_seg_cfg_t *seg_cfg);
urma_status_t udma_u_unregister_seg(urma_target_seg_t *target_seg);
urma_target_seg_t *udma_u_import_seg(urma_context_t *ctx, urma_seg_t *seg,
				     urma_token_t *token, uint64_t addr,
				     urma_import_seg_flag_t flag);
urma_status_t udma_u_unimport_seg(urma_target_seg_t *target_seg);
#endif /* _UDMA_U_SEGMENT_H */
