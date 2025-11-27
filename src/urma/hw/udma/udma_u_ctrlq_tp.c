// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <string.h>
#include "udma_u_common.h"
#include "udma_u_ctrlq_tp.h"

int udma_u_ctrlq_get_tp_list(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt,
			     urma_tp_info_t *tp_list)
{
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	ret = urma_cmd_get_tp_list(ctx, cfg, tp_cnt, tp_list, &udata);
	if (ret)
		UDMA_LOG_ERR("urma get tp list failed, ret = %d.\n", ret);

	return ret;
}

int udma_u_ctrlq_set_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle,
			     const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
			     const urma_tp_attr_value_t *tp_attr)
{
	int ret;

	ret = urma_cmd_set_tp_attr(ctx, tp_handle, tp_attr_cnt, tp_attr_bitmap, tp_attr, NULL);
	if (ret)
		UDMA_LOG_ERR("urma cmd set tp attr failed, ret = %d.\n", ret);

	return ret;
}

int udma_u_ctrlq_get_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle,
			     uint8_t *tp_attr_cnt, uint32_t *tp_attr_bitmap,
			     urma_tp_attr_value_t *tp_attr)
{
	int ret;

	ret = urma_cmd_get_tp_attr(ctx, tp_handle, tp_attr_cnt, tp_attr_bitmap, tp_attr, NULL);
	if (ret)
		UDMA_LOG_ERR("urma cmd get tp attr failed, ret = %d.\n", ret);

	return ret;
}
