// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <ummu_api.h>
#include "udma_u_tid.h"

static int udma_exec_alloc_tid_cmd(urma_context_t *ctx, uint32_t tid,
				   urma_token_id_t *keyid)
{
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	udma_u_set_udata(&udata, &tid, sizeof(tid), NULL, 0);
	ret = urma_cmd_alloc_token_id(ctx, keyid, &udata);
	if (ret)
		UDMA_LOG_ERR("URMA command alloc TID failed, ret = %d.\n", ret);

	return ret;
}

static urma_token_id_t *udma_u_alloc_tid_common(urma_context_t *ctx, enum ummu_mapt_mode mapt_mode)
{
	struct ummu_tid_attr tid_attr = {.mode = mapt_mode};
	struct udma_u_tid *udma_tid;
	uint32_t tid;
	int ret;

	udma_tid = (struct udma_u_tid *)calloc(1, sizeof(*udma_tid));
	if (udma_tid == NULL) {
		UDMA_LOG_ERR("allocate UDMA TID failed.\n");
		return NULL;
	}

	ret = ummu_allocate_tid(&tid_attr, &tid);
	if (ret != 0) {
		UDMA_LOG_ERR("UMMU allocate TID failed, ret = %d.\n", ret);
		goto err_ummu_alloc_tid;
	}

	if (tid > UDMA_MAX_TID) {
		UDMA_LOG_ERR("UMMU allocate TID overflow.\n");
		goto err_cmd_alloc_key_id;
	}

	udma_tid->tid = tid;
	udma_tid->base.token_id = tid << UDMA_TID_SHIFT;
	ret = udma_exec_alloc_tid_cmd(ctx, udma_tid->base.token_id, &udma_tid->base);
	if (ret != 0)
		goto err_cmd_alloc_key_id;

	udma_tid->base.urma_ctx = ctx;

	return &udma_tid->base;

err_cmd_alloc_key_id:
	ret = ummu_free_tid(tid);
	if (ret != 0)
		UDMA_LOG_ERR("UMMU free TID failed, ret = %d.\n", ret);
err_ummu_alloc_tid:
	free(udma_tid);
	return NULL;
}

urma_status_t udma_u_free_tid(urma_token_id_t *tid)
{
	struct udma_u_tid *udma_tid = to_udma_u_tid(tid);
	int ret;

	ret = urma_cmd_free_token_id(tid);
	if (ret != 0) {
		UDMA_LOG_ERR("URMA command free TID failed, ret = %d.\n", ret);
		return URMA_FAIL;
	}

	ret = ummu_free_tid(udma_tid->tid);
	if (ret != 0)
		UDMA_LOG_ERR("UMMU free TID failed, ret = %d.\n", ret);

	free(udma_tid);

	return URMA_SUCCESS;
}

urma_token_id_t *udma_u_alloc_tid(urma_context_t *ctx)
{
	return udma_u_alloc_tid_common(ctx, MAPT_MODE_TABLE);
}

urma_token_id_t *udma_u_alloc_tid_ex(urma_context_t *ctx, urma_token_id_flag_t flag)
{
	if (flag.bs.multi_seg != 0)
		return udma_u_alloc_tid_common(ctx, MAPT_MODE_TABLE);
	else
		return udma_u_alloc_tid_common(ctx, MAPT_MODE_ENTRY);
}
