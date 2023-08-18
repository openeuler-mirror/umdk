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

#include <math.h>
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfc.h"

static int check_jfc_cfg(struct udma_u_context *udma_ctx, const urma_jfc_cfg_t *cfg)
{
	if (!cfg->depth || roundup_pow_of_two(cfg->depth) > udma_ctx->max_jfc_cqe) {
		URMA_LOG_ERR("invalid jfc cfg, cfg->depth = %d, udma_ctx->max_jfc_cqe = %d.\n",
			     cfg->depth, udma_ctx->max_jfc_cqe);
		return EINVAL;
	}

	return 0;
}

static void set_jfc_size(struct udma_u_context *udma_ctx, struct udma_u_jfc *jfc,
			 const urma_jfc_cfg_t *cfg)
{
	jfc->cqe_cnt = roundup_pow_of_two(cfg->depth);
	jfc->cqe_size = udma_ctx->cqe_size;
	jfc->cqe_shift = udma_ilog32(udma_ctx->cqe_size);
}

static int alloc_jfc_buf(struct udma_u_jfc *jfc)
{
	int buf_size = to_udma_hem_entries_size(jfc->cqe_cnt, jfc->cqe_shift);

	return udma_alloc_buf(&jfc->buf, buf_size, UDMA_HW_PAGE_SIZE);
}

static struct udma_u_jfc *udma_u_create_jfc_common(const urma_jfc_cfg_t *cfg,
						   struct udma_u_context *udma_ctx)
{
	struct udma_u_jfc *jfc;
	int ret;

	ret = check_jfc_cfg(udma_ctx, cfg);
	if (ret)
		goto err;

	jfc = (struct udma_u_jfc *)calloc(1, sizeof(*jfc));
	if (!jfc) {
		URMA_LOG_ERR("alloc udma_ctx memory failed.\n");
		goto err;
	}

	jfc->lock_free = cfg->flag.bs.lock_free;
	ret = pthread_spin_init(&jfc->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		URMA_LOG_ERR("alloc udma_ctx spinlock failed.\n");
		goto err_lock;
	}

	set_jfc_size(udma_ctx, jfc, cfg);
	if (alloc_jfc_buf(jfc))
		goto err_buf;

	jfc->db = (uint32_t *)udma_alloc_sw_db(udma_ctx, UDMA_JFC_TYPE_DB);
	if (!jfc->db)
		goto err_db;

	return jfc;

err_db:
	udma_free_buf(&jfc->buf);
err_buf:
	pthread_spin_destroy(&jfc->lock);
err_lock:
	free(jfc);
err:
	return NULL;
}

static void free_err_jfc(struct udma_u_jfc *jfc, struct udma_u_context *udma_ctx)
{
	udma_free_sw_db(udma_ctx, jfc->db, UDMA_JFC_TYPE_DB);
	udma_free_buf(&jfc->buf);
	pthread_spin_destroy(&jfc->lock);
	free(jfc);
}

urma_jfc_t *udma_u_create_jfc(urma_context_t *ctx, const urma_jfc_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_create_jfc_resp resp = {};
	struct udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	struct udma_u_jfc *jfc;
	int ret;

	jfc = udma_u_create_jfc_common(cfg, udma_ctx);
	if (!jfc)
		return NULL;

	cmd.buf_addr = (uintptr_t)jfc->buf.buf;
	cmd.db_addr = (uintptr_t)jfc->db;
	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfc(ctx, &jfc->urma_jfc, cfg, &udata);
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

urma_status_t udma_u_delete_jfc(urma_jfc_t *jfc)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(jfc->urma_ctx);
	struct udma_u_jfc *udma_jfc = to_udma_jfc(jfc);
	int ret;

	ret = urma_cmd_delete_jfc(jfc);
	if (ret) {
		URMA_LOG_ERR("delete jfc failed, ret:%d, errno:%d.\n",
			     ret, errno);
		return URMA_FAIL;
	}

	udma_free_sw_db(udma_ctx, udma_jfc->db, UDMA_JFC_TYPE_DB);
	udma_free_buf(&udma_jfc->buf);
	pthread_spin_destroy(&udma_jfc->lock);
	free(udma_jfc);

	return URMA_SUCCESS;
}
