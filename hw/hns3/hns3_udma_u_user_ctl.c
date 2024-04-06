// SPDX-License-Identifier: GPL-2.0
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

#include <string.h>
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_abi.h"
#include "hns3_udma_u_user_ctl_api.h"

static int udma_u_query_hw_id(urma_context_t *ctx, urma_user_ctl_in_t *in,
			      urma_user_ctl_out_t *out)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct hns3_udma_query_hw_id_out ex_out = {};

	ex_out.chip_id = udma_ctx->chip_id;
	ex_out.die_id = udma_ctx->die_id;
	ex_out.func_id = udma_ctx->func_id;
	memcpy((void *)out->addr, &ex_out, min(out->len, sizeof(struct hns3_udma_query_hw_id_out)));

	return 0;
}

typedef int (*udma_u_user_ctl_ops)(urma_context_t *ctx, urma_user_ctl_in_t *in,
				   urma_user_ctl_out_t *out);

static udma_u_user_ctl_ops g_udma_u_user_ctl_ops[] = {
	[HNS3_UDMA_U_USER_CTL_QUERY_HW_ID] = udma_u_query_hw_id,
};

int udma_u_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in,
		    urma_user_ctl_out_t *out)
{
	if ((ctx == NULL) || (in == NULL) || (out == NULL)) {
		URMA_LOG_ERR("parameter invalid in urma_user_ctl.\n");
		return EINVAL;
	}

	if (in->opcode >= HNS3_UDMA_U_USER_CTL_MAX) {
		URMA_LOG_ERR("invalid opcode: 0x%x.\n", (int)in->opcode);
		return URMA_ENOPERM;
	}
	return g_udma_u_user_ctl_ops[in->opcode](ctx, in, out);
}
