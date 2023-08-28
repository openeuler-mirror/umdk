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

#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include "hns3_udma_u_jfr.h"
#include "hns3_udma_u_jfc.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_segment.h"
#include "hns3_udma_u_provider_ops.h"

static urma_ops_t g_udma_u_ops = {
	/* OPs name */
	.name = "UDMA_CP_OPS",

	.create_jfc = udma_u_create_jfc,
	.modify_jfc = udma_u_modify_jfc,
	.delete_jfc = udma_u_delete_jfc,
	.create_jfs = udma_u_create_jfs,
	.delete_jfs = udma_u_delete_jfs,
	.create_jfr = udma_u_create_jfr,
	.modify_jfr = udma_u_modify_jfr,
	.delete_jfr = udma_u_delete_jfr,
	.import_jfr = udma_u_import_jfr,
	.unimport_jfr = udma_u_unimport_jfr,
	.advise_jfr = udma_u_advise_jfr,
	.unadvise_jfr = udma_u_unadvise_jfr,
	.create_jetty = udma_u_create_jetty,
	.modify_jetty = udma_u_modify_jetty,
	.delete_jetty = udma_u_delete_jetty,
	.import_jetty = udma_u_import_jetty,
	.unimport_jetty = udma_u_unimport_jetty,
	.advise_jetty = udma_u_advise_jetty,
	.unadvise_jetty = udma_u_unadvise_jetty,
	.bind_jetty = udma_u_bind_jetty,
	.unbind_jetty = udma_u_unbind_jetty,
	.create_jfce = udma_u_create_jfce,
	.delete_jfce = udma_u_delete_jfce,
	.register_seg = udma_u_register_seg,
	.unregister_seg = udma_u_unregister_seg,
	.post_jfs_wr = udma_u_post_jfs_wr,
	.post_jfr_wr = udma_u_post_jfr_wr,
	.post_jetty_send_wr = udma_u_post_jetty_send_wr,
	.post_jetty_recv_wr = udma_u_post_jetty_recv_wr,
	.poll_jfc = udma_u_poll_jfc,
	.rearm_jfc = udma_u_rearm_jfc,
	.wait_jfc = udma_u_wait_jfc,
	.ack_jfc = udma_u_ack_jfc,
};

static urma_match_entry_t match_table[] = {
	{PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_UDMA_OVER_UBL},
	{PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_UDMA},
	{}
};

static urma_status_t udma_u_query_device(const urma_device_t *dev,
					 urma_device_attr_t *dev_attr)
{
	return URMA_SUCCESS;
}

static urma_status_t udma_u_init_urma_ctx_cfg(urma_device_t *dev,
					      urma_context_cfg_t *cfg,
					      int cmd_fd, uint32_t uasid)
{
	cfg->dev = dev;
	cfg->ops = &g_udma_u_ops;
	cfg->dev_fd = cmd_fd;
	cfg->uasid = uasid;

	return URMA_SUCCESS;
}

static urma_status_t udma_u_alloc_db(struct udma_u_context *udma_u_ctx, int cmd_fd)
{
	off_t offset;

	offset = get_mmap_offset(0, udma_u_ctx->page_size, UDMA_MMAP_UAR_PAGE);
	udma_u_ctx->uar = mmap(NULL, udma_u_ctx->page_size, PROT_READ | PROT_WRITE,
			       MAP_SHARED, cmd_fd, offset);
	if (udma_u_ctx->uar == MAP_FAILED) {
		URMA_LOG_ERR("failed to mmap uar page, errno:%d.\n", errno);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

static void udma_u_free_db(struct udma_u_context *udma_u_ctx)
{
	int ret;

	ret = munmap(udma_u_ctx->uar, (size_t)udma_u_ctx->page_size);
	if (ret != 0)
		URMA_LOG_ERR("failed to munmap uar.\n");
}

static urma_status_t init_reset_state(struct udma_u_context *udma_u_ctx, int cmd_fd)
{
	off_t offset;

	offset = get_mmap_offset(0, udma_u_ctx->page_size, UDMA_MMAP_RESET_PAGE);
	udma_u_ctx->reset_state = mmap(NULL, (size_t)udma_u_ctx->page_size, PROT_READ,
				       MAP_SHARED, cmd_fd, offset);
	if (udma_u_ctx->reset_state == MAP_FAILED) {
		URMA_LOG_ERR("failed to mmap reset page, errno:%d.\n", errno);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

static void uninit_reset_state(struct udma_u_context *udma_u_ctx)
{
	int ret;

	ret = munmap(udma_u_ctx->reset_state, (size_t)udma_u_ctx->page_size);
	if (ret != 0)
		URMA_LOG_ERR("failed to munmap reset state.\n");
}

static urma_status_t udma_u_init_context(struct udma_u_context *udma_u_ctx,
					 struct udma_create_ctx_resp *resp,
					 int cmd_fd)
{
	urma_status_t ret;

	udma_u_ctx->page_size = sysconf(_SC_PAGESIZE);
	udma_u_ctx->num_qps_shift = resp->num_qps_shift;
	udma_u_ctx->num_jfr_shift = resp->num_jfr_shift;
	udma_u_ctx->num_jfs_shift = resp->num_jfs_shift;
	udma_u_ctx->num_jetty_shift = resp->num_jetty_shift;
	udma_u_ctx->max_jfc_cqe = resp->max_jfc_cqe;
	udma_u_ctx->cqe_size = resp->cqe_size;
	udma_u_ctx->max_jfr_wr = resp->max_jfr_wr;
	udma_u_ctx->max_jfr_sge = resp->max_jfr_sge;
	udma_u_ctx->max_jfs_wr = resp->max_jfs_wr;
	udma_u_ctx->max_jfs_sge = resp->max_jfs_sge;
	udma_u_ctx->db_addr = resp->db_addr;

	ret = udma_u_alloc_db(udma_u_ctx, cmd_fd);
	if (ret) {
		URMA_LOG_ERR("failed to alloc db.\n");
		return ret;
	}

	ret = init_reset_state(udma_u_ctx, cmd_fd);
	if (ret) {
		URMA_LOG_ERR("failed to init reset state.\n");
		udma_u_free_db(udma_u_ctx);
	}

	return ret;
}

static void udma_u_uninit_context(struct udma_u_context *udma_u_ctx)
{
	uninit_reset_state(udma_u_ctx);
	udma_u_free_db(udma_u_ctx);
}

static void udma_u_destroy_jfr_table(struct udma_u_context *ctx)
{
	struct udma_jfr_node *cur, *next;

	(void)pthread_rwlock_wrlock(&ctx->jfr_table_lock);
	HMAP_FOR_EACH_SAFE(cur, next, node, &ctx->jfr_table) {
		udma_hmap_remove(&ctx->jfr_table, &cur->node);
		free(cur);
	}
	(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);
	udma_hmap_destroy(&ctx->jfr_table);
	(void)pthread_rwlock_destroy(&ctx->jfr_table_lock);
}

static void udma_u_destroy_jfs_qp_table(struct udma_u_context *ctx)
{
	struct udma_jfs_qp_node *cur, *next;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	HMAP_FOR_EACH_SAFE(cur, next, node, &ctx->jfs_qp_table) {
		udma_hmap_remove(&ctx->jfs_qp_table, &cur->node);
		free(cur);
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
	udma_hmap_destroy(&ctx->jfs_qp_table);
	(void)pthread_rwlock_destroy(&ctx->jfs_qp_table_lock);
}

static void udma_u_destroy_jetty_table(struct udma_u_context *ctx)
{
	struct udma_jetty_node *cur, *next;

	(void)pthread_rwlock_wrlock(&ctx->jetty_table_lock);
	HMAP_FOR_EACH_SAFE(cur, next, node, &ctx->jetty_table) {
		udma_hmap_remove(&ctx->jetty_table, &cur->node);
		free(cur);
	}
	(void)pthread_rwlock_unlock(&ctx->jetty_table_lock);
	udma_hmap_destroy(&ctx->jetty_table);
	(void)pthread_rwlock_destroy(&ctx->jetty_table_lock);
}

static urma_status_t init_jetty_x_table(struct udma_u_context *udma_u_ctx)
{
	urma_status_t ret = URMA_SUCCESS;

	(void)pthread_rwlock_init(&udma_u_ctx->jfs_qp_table_lock, NULL);
	if (udma_hmap_init(&udma_u_ctx->jfs_qp_table, UDMA_JFS_QP_TABLE_SIZE)) {
		URMA_LOG_ERR("init jfs table failed.\n");
		ret = URMA_ENOMEM;
		goto err_init_jfs_table;
	}

	(void)pthread_rwlock_init(&udma_u_ctx->jfr_table_lock, NULL);
	if (udma_hmap_init(&udma_u_ctx->jfr_table, UDMA_JFR_TABLE_SIZE)) {
		URMA_LOG_ERR("init jfr table failed.\n");
		ret = URMA_ENOMEM;
		goto err_init_jfr_table;
	}

	(void)pthread_rwlock_init(&udma_u_ctx->jetty_table_lock, NULL);
	if (udma_hmap_init(&udma_u_ctx->jetty_table, UDMA_JETTY_TABLE_SIZE)) {
		URMA_LOG_ERR("init jetty table failed.\n");
		ret = URMA_ENOMEM;
		goto err_init_jetty_table;
	}

	return ret;

err_init_jetty_table:
	pthread_rwlock_destroy(&udma_u_ctx->jetty_table_lock);
	udma_hmap_destroy(&udma_u_ctx->jfr_table);
err_init_jfr_table:
	pthread_rwlock_destroy(&udma_u_ctx->jfr_table_lock);
	udma_hmap_destroy(&udma_u_ctx->jfs_qp_table);
err_init_jfs_table:
	pthread_rwlock_destroy(&udma_u_ctx->jfs_qp_table_lock);

	return ret;
}

static urma_context_t *udma_u_create_context(urma_device_t *dev, int cmd_fd, uint32_t uasid)
{
	struct udma_create_ctx_resp resp = {};
	struct udma_create_ctx_ucmd cmd = {};
	urma_cmd_udrv_priv_t udrv_data = {};
	struct udma_u_context *udma_u_ctx;
	urma_context_cfg_t cfg = {};
	urma_status_t ret;

	udma_u_ctx = (struct udma_u_context *)calloc(1, sizeof(struct udma_u_context));
	if (udma_u_ctx == NULL) {
		URMA_LOG_ERR("failed to alloc memory for udma_u ctx.\n");
		return NULL;
	}

	ret = udma_u_init_urma_ctx_cfg(dev, &cfg, cmd_fd, uasid);
	if (ret != URMA_SUCCESS) {
		URMA_LOG_ERR("udma_u init urma ctx failed.");
		goto err_init_urma_ctx_cfg;
	}

	udma_set_udata(&udrv_data, &cmd, sizeof(cmd), &resp, sizeof(resp));

	if (urma_cmd_create_context(&udma_u_ctx->urma_ctx, &cfg, &udrv_data))
		goto err_init_urma_ctx_cfg;

	ret = udma_u_init_context(udma_u_ctx, &resp, cmd_fd);
	if (ret != URMA_SUCCESS) {
		URMA_LOG_ERR("udma_u init ctx failed.");
		goto err_init_context;
	}

	ret = init_jetty_x_table(udma_u_ctx);
	if (ret)
		goto err_init_jetty_x_table;

	return &udma_u_ctx->urma_ctx;

err_init_jetty_x_table:
	udma_u_uninit_context(udma_u_ctx);
err_init_context:
	(void)urma_cmd_delete_context(&udma_u_ctx->urma_ctx);
err_init_urma_ctx_cfg:
	free(udma_u_ctx);

	return NULL;
}

static urma_status_t udma_u_delete_context(urma_context_t *ctx)
{
	struct udma_u_context *udma_u_ctx = to_udma_ctx(ctx);

	udma_u_destroy_jfr_table(udma_u_ctx);
	udma_u_destroy_jfs_qp_table(udma_u_ctx);
	udma_u_destroy_jetty_table(udma_u_ctx);
	udma_u_uninit_context(udma_u_ctx);
	if (urma_cmd_delete_context(&udma_u_ctx->urma_ctx))
		URMA_LOG_ERR("udma_u destroy ctx failed.\n");

	free(udma_u_ctx);

	return URMA_SUCCESS;
}

static urma_status_t udma_u_init(const urma_init_attr_t *conf)
{
	return URMA_SUCCESS;
}

static urma_status_t udma_u_uinit(void)
{
	return URMA_SUCCESS;
}

urma_provider_ops_t g_udma_u_provider_ops = {
	.name = "udma_v1",
	.attr = {
		.version = 1,
		.transport_type = URMA_TRANSPORT_IB,
	},
	.match_table = match_table,
	.init = udma_u_init,
	.uninit = udma_u_uinit,
	.query_device = udma_u_query_device,
	.create_context = udma_u_create_context,
	.delete_context = udma_u_delete_context,
};
