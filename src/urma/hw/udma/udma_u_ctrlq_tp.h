/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_CTRLQ_TP_H__
#define __UDMA_U_CTRLQ_TP_H__

#include "udma_u_common.h"

int udma_u_ctrlq_get_tp_list(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt,
			     urma_tp_info_t *tp_list);
int udma_u_ctrlq_get_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle,
			     uint8_t *tp_attr_cnt, uint32_t *tp_attr_bitmap,
			     urma_tp_attr_value_t *tp_attr);

int udma_u_ctrlq_set_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle,
			     const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
			     const urma_tp_attr_value_t *tp_attr);
#endif /* __UDMA_U_CTRLQ_TP_H__ */
