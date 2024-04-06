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
#include "hns3_udma_u_jfc.h"
#include "hns3_udma_u_abi.h"
#include "hns3_udma_u_user_ctl_api.h"
static int udma_u_check_poe_cfg(struct udma_u_context *udma_ctx, uint8_t poe_channel,
				struct hns3_udma_poe_init_attr *init_attr)
{
	if (!init_attr || !udma_ctx) {
		URMA_LOG_ERR("invalid ctx or attr\n");
		return EINVAL;
	}

	if (poe_channel >= udma_ctx->poe_ch_num) {
		URMA_LOG_ERR("invalid POE channel %u >= %u\n",
			     poe_channel, udma_ctx->poe_ch_num);
		return EINVAL;
	}

	return 0;
}

static int config_poe_channel(urma_context_t *ctx, uint8_t poe_channel,
			      struct hns3_udma_poe_init_attr *init_attr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_poe_info poe_channel_info = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	int ret;

	ret = udma_u_check_poe_cfg(udma_ctx, poe_channel, init_attr);
	if (ret)
		return EINVAL;

	poe_channel_info.poe_channel = poe_channel;
	poe_channel_info.en = !!init_attr->poe_addr;
	poe_channel_info.poe_addr = init_attr->poe_addr;

	in.opcode = (uint32_t)UDMA_CONFIG_POE_CHANNEL;
	in.addr = (uint64_t)&poe_channel_info;
	in.len = (uint32_t)sizeof(struct udma_poe_info);

	ret = urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
	if (ret)
		URMA_LOG_ERR("failed to config POE channel %u, ret = %d\n",
			     poe_channel, ret);

	return ret;
}

static int udma_u_config_poe_channel(urma_context_t *ctx,
				     urma_user_ctl_in_t *in,
				     urma_user_ctl_out_t *out)
{
	struct hns3_udma_config_poe_channel_in poe_in;
	int ret;

	memcpy(&poe_in, (void *)in->addr, min(in->len,
		sizeof(struct hns3_udma_config_poe_channel_in)));
	ret = config_poe_channel((urma_context_t *)ctx,
				 poe_in.poe_channel, poe_in.init_attr);

	return ret;
}

static int query_poe_channel(urma_context_t *ctx, uint8_t poe_channel,
			     struct hns3_udma_poe_init_attr *init_attr)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_poe_info poe_channel_info_out = {};
	struct udma_poe_info poe_channel_info_in = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	int ret;

	ret = udma_u_check_poe_cfg(udma_ctx, poe_channel, init_attr);
	if (ret)
		return EINVAL;

	poe_channel_info_in.poe_channel = poe_channel;

	in.opcode = (uint32_t)UDMA_QUERY_POE_CHANNEL;
	in.addr = (uint64_t)&poe_channel_info_in;
	in.len = (uint32_t)sizeof(struct udma_poe_info);
	out.addr = (uint64_t)&poe_channel_info_out;
	out.len = (uint32_t)sizeof(struct udma_poe_info);

	ret = urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
	if (ret) {
		URMA_LOG_ERR("failed to query POE channel %u, ret = %d\n",
			     poe_channel, ret);
		return ret;
	}
	init_attr->poe_addr = poe_channel_info_out.en ?
			      poe_channel_info_out.poe_addr : 0;

	return ret;
}

static int udma_u_query_poe_channel(urma_context_t *ctx, urma_user_ctl_in_t *in,
				    urma_user_ctl_out_t *out)
{
	uint8_t poe_channel;
	int ret;

	memcpy(&poe_channel, (void *)in->addr, min(in->len, sizeof(uint8_t)));
	ret = query_poe_channel((urma_context_t *)ctx, poe_channel,
				(struct hns3_udma_poe_init_attr *)out->addr);

	return ret;
}


static int udma_u_check_notify_attr(struct hns3_udma_jfc_notify_init_attr *notify_attr)
{
	switch (notify_attr->notify_mode) {
	case HNS3_UDMA_JFC_NOTIFY_MODE_4B_ALIGN:
	case HNS3_UDMA_JFC_NOTIFY_MODE_DDR_4B_ALIGN:
		break;
	case HNS3_UDMA_JFC_NOTIFY_MODE_64B_ALIGN:
	case HNS3_UDMA_JFC_NOTIFY_MODE_DDR_64B_ALIGN:
		URMA_LOG_ERR("Doesn't support notify mode %u\n",
			     notify_attr->notify_mode);
		return EINVAL;
	default:
		URMA_LOG_ERR("Invalid notify mode %u\n",
			     notify_attr->notify_mode);
		return EINVAL;
	}

	if (notify_attr->notify_addr & HNS3_UDMA_ADDR_4K_MASK) {
		URMA_LOG_ERR("Notify addr should be aligned to 4k.\n",
			     notify_attr->notify_addr);
		return EINVAL;
	}

	return 0;
}

static int udma_u_check_jfc_attr_ex(struct hns3_udma_jfc_init_attr *attr)
{
	int ret = 0;

	if (attr->jfc_ex_mask != HNS3_UDMA_JFC_NOTIFY_OR_POE_CREATE_FLAGS) {
		URMA_LOG_ERR("Invalid comp mask %u\n", attr->jfc_ex_mask);
		return EINVAL;
	}

	switch (attr->create_flags) {
	case HNS3_UDMA_JFC_CREATE_ENABLE_POE_MODE:
		break;
	case HNS3_UDMA_JFC_CREATE_ENABLE_NOTIFY:
		ret = udma_u_check_notify_attr(&attr->notify_init_attr);
		break;
	default:
		URMA_LOG_ERR("Invalid create flags %u\n", attr->create_flags);
		return EINVAL;
	}

	return ret;
}

static urma_jfc_t *create_jfc_ex(urma_context_t *ctx,
				 struct hns3_udma_create_jfc_ex_in *cfg_ex)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct hns3_udma_create_jfc_resp resp = {};
	struct hns3_udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	struct udma_u_jfc *jfc;
	int ret;

	jfc = udma_u_create_jfc_common(cfg_ex->cfg, udma_ctx);
	if (!jfc)
		return NULL;

	cmd.buf_addr = (uintptr_t)jfc->buf.buf;
	cmd.db_addr = (uintptr_t)jfc->db;
	cmd.jfc_attr_ex.jfc_ex_mask = cfg_ex->attr->jfc_ex_mask;
	cmd.jfc_attr_ex.create_flags = cfg_ex->attr->create_flags;
	cmd.jfc_attr_ex.poe_channel = cfg_ex->attr->poe_channel;
	cmd.jfc_attr_ex.notify_addr = cfg_ex->attr->notify_init_attr.notify_addr;
	cmd.jfc_attr_ex.notify_mode = cfg_ex->attr->notify_init_attr.notify_mode;
	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfc(ctx, &jfc->urma_jfc, cfg_ex->cfg, &udata);
	if (ret) {
		URMA_LOG_ERR("urma cmd create jfc failed.\n");
		free_err_jfc(jfc, udma_ctx);
		return NULL;
	}
	jfc->ci = 0;
	jfc->arm_sn = 1;
	jfc->cqn = jfc->urma_jfc.jfc_id.id;
	jfc->caps_flag = resp.jfc_caps;

	return &jfc->urma_jfc;
}

static int udma_u_create_jfc_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
				urma_user_ctl_out_t *out)
{
	struct hns3_udma_create_jfc_ex_in cfg_ex;
	urma_jfc_t *jfc;
	int ret;

	memcpy(&cfg_ex, (void *)in->addr, min(in->len, sizeof(struct hns3_udma_create_jfc_ex_in)));

	ret = udma_u_check_jfc_attr_ex(cfg_ex.attr);
	if (ret) {
		URMA_LOG_ERR("Invalid jfc attr ex\n");
		return EINVAL;
	}

	jfc = create_jfc_ex((urma_context_t *)ctx, &cfg_ex);
	if (jfc == NULL)
		return EFAULT;

	memcpy((void *)out->addr, &jfc, sizeof(urma_jfc_t *));

	return 0;
}

static int udma_u_delete_jfc_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
				urma_user_ctl_out_t *out)
{
	urma_status_t ret;
	urma_jfc_t *jfc;

	memcpy(&jfc, (void *)in->addr, min(in->len, sizeof(urma_jfc_t)));

	ret = udma_u_delete_jfc(jfc);
	if (ret)
		return EFAULT;

	return 0;
}

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
	[HNS3_UDMA_U_USER_CTL_CONFIG_POE_CHANNEL] = udma_u_config_poe_channel,
	[HNS3_UDMA_U_USER_CTL_QUERY_POE_CHANNEL] = udma_u_query_poe_channel,
	[HNS3_UDMA_U_USER_CTL_CREATE_JFC_EX] = udma_u_create_jfc_ex,
	[HNS3_UDMA_U_USER_CTL_DELETE_JFC_EX] = udma_u_delete_jfc_ex,
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
