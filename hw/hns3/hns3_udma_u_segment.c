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

#include "urma_log.h"
#include "urma_provider.h"
#include "hns3_udma_u_segment.h"

urma_target_seg_t *udma_u_register_seg(urma_context_t *ctx,
				       urma_seg_cfg_t *seg_cfg)
{
	urma_cmd_udrv_priv_t udata = {};
	struct udma_u_seg *seg;

	if (!seg_cfg->token_value || seg_cfg->flag.bs.access >= URMA_SEG_ACCESS_GUARD) {
		URMA_LOG_ERR("Invalid seg cfg parameters, access = 0x%x.\n",
			     seg_cfg->flag.bs.access);
		return NULL;
	}

	seg = (struct udma_u_seg *)calloc(1, sizeof(struct udma_u_seg));
	if (!seg)
		return NULL;

	/* register va */
	seg->urma_seg.seg.ubva.eid = ctx->eid;
	seg->urma_seg.seg.ubva.uasid = ctx->uasid;
	seg->urma_seg.seg.ubva.va = seg_cfg->va;
	seg->urma_seg.seg.len = seg_cfg->len;
	seg->urma_seg.seg.attr.bs.token_policy = seg_cfg->flag.bs.token_policy;
	seg->urma_seg.seg.attr.bs.cacheable = seg_cfg->flag.bs.cacheable;
	seg->urma_seg.seg.attr.bs.dsva = false;
	seg->urma_seg.seg.attr.bs.access = seg_cfg->flag.bs.access;
	seg->urma_seg.user_ctx = seg_cfg->user_ctx;
	(void)memcpy(&seg->token, seg_cfg->token_value, sizeof(urma_token_t));
	seg->urma_seg.urma_ctx = ctx;

	if (urma_cmd_register_seg(ctx, &seg->urma_seg, seg_cfg, &udata) != 0) {
		URMA_LOG_ERR("failed to register segment.\n");
		free(seg);
		return NULL;
	}

	return &seg->urma_seg;
}

urma_status_t udma_u_unregister_seg(urma_target_seg_t *target_seg)
{
	urma_status_t ret = URMA_SUCCESS;
	struct udma_u_seg *seg;

	if (target_seg == NULL) {
		URMA_LOG_ERR("Invalid parameter.\n");
		return URMA_FAIL;
	}
	seg = CONTAINER_OF_FIELD(target_seg, struct udma_u_seg, urma_seg);

	if (urma_cmd_unregister_seg(target_seg) != 0) {
		URMA_LOG_ERR("failed to unregister segment.\n");
		ret = URMA_FAIL;
	}
	free(seg);

	return ret;
}

urma_target_seg_t *udma_u_import_seg(urma_context_t *ctx, urma_seg_t *seg,
				     urma_token_t *token, uint64_t addr,
				     urma_import_seg_flag_t flag)
{
	urma_cmd_udrv_priv_t udata = {};
	urma_import_tseg_cfg_t cfg = {};
	urma_target_seg_t *tseg;
	int ret;

	tseg = (urma_target_seg_t *)calloc(1, sizeof(urma_target_seg_t));
	if (!tseg) {
		URMA_LOG_ERR("target seg alloc failed.\n");
		return NULL;
	}

	cfg.ubva = seg->ubva;
	cfg.len = seg->len;
	cfg.attr = seg->attr;
	cfg.token_id = seg->token_id;
	cfg.token = token;
	udma_set_udata(&udata, NULL, 0, NULL, 0);
	ret = urma_cmd_import_seg(ctx, tseg, &cfg, &udata);
	if (ret) {
		URMA_LOG_ERR("import seg failed.\n");
		free(tseg);
		return NULL;
	}

	return tseg;
}

urma_status_t udma_u_unimport_seg(urma_target_seg_t *target_seg)
{
	int ret;

	ret = urma_cmd_unimport_seg(target_seg);
	if (ret != 0) {
		URMA_LOG_ERR("unimport seg failed.\n");
		return URMA_FAIL;
	}
	free(target_seg);

	return URMA_SUCCESS;
}
