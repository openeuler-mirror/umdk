// SPDX-License-Identifier: GPL-2.0
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

#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include "hns3_udma_u_jfr.h"
#include "hns3_udma_u_jfc.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_segment.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_user_ctl.h"
#include "hns3_udma_u_provider_ops.h"

static urma_ops_t g_hns3_udma_u_ops = {
	/* OPs name */
	.name = "HNS3_UDMA_CP_OPS",

	.create_jfc = hns3_udma_u_create_jfc,
	.modify_jfc = hns3_udma_u_modify_jfc,
	.delete_jfc = hns3_udma_u_delete_jfc,
	.create_jfs = hns3_udma_u_create_jfs,
	.flush_jfs = hns3_udma_u_flush_jfs,
	.delete_jfs = hns3_udma_u_delete_jfs,
	.create_jfr = hns3_udma_u_create_jfr,
	.modify_jfr = hns3_udma_u_modify_jfr,
	.delete_jfr = hns3_udma_u_delete_jfr,
	.import_jfr = hns3_udma_u_import_jfr,
	.unimport_jfr = hns3_udma_u_unimport_jfr,
	.create_jetty = hns3_udma_u_create_jetty,
	.flush_jetty = hns3_udma_u_flush_jetty,
	.delete_jetty = hns3_udma_u_delete_jetty,
	.import_jetty = hns3_udma_u_import_jetty,
	.unimport_jetty = hns3_udma_u_unimport_jetty,
	.bind_jetty = hns3_udma_u_bind_jetty,
	.unbind_jetty = hns3_udma_u_unbind_jetty,
	.create_jfce = hns3_udma_u_create_jfce,
	.delete_jfce = hns3_udma_u_delete_jfce,
	.get_tpn = hns3_udma_u_get_tpn,
	.modify_tp = hns3_udma_u_modify_user_tp,
	.register_seg = hns3_udma_u_register_seg,
	.unregister_seg = hns3_udma_u_unregister_seg,
	.import_seg = hns3_udma_u_import_seg,
	.unimport_seg = hns3_udma_u_unimport_seg,
	.get_async_event = hns3_udma_u_get_async_event,
	.ack_async_event = hns3_udma_u_ack_async_event,
	.user_ctl = hns3_udma_u_user_ctl,
	.post_jfs_wr = hns3_udma_u_post_jfs_wr,
	.post_jfr_wr = hns3_udma_u_post_jfr_wr,
	.post_jetty_send_wr = hns3_udma_u_post_jetty_send_wr,
	.post_jetty_recv_wr = hns3_udma_u_post_jetty_recv_wr,
	.poll_jfc = hns3_udma_u_poll_jfc,
	.rearm_jfc = hns3_udma_u_rearm_jfc,
	.wait_jfc = hns3_udma_u_wait_jfc,
	.ack_jfc = hns3_udma_u_ack_jfc,
};

static urma_match_entry_t match_table[] = {
	{PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_HNS3_UDMA_OVER_UBL},
	{PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_HNS3_UDMA},
	{PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_HNS3_UDMA_OVER_UBL_VF},
	{PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_HNS3_UDMA_OVER_UBL_TMP_VF},
	{}
};

static urma_status_t hns3_udma_u_query_device(urma_device_t *dev,
					      urma_device_attr_t *dev_attr)
{
	return URMA_SUCCESS;
}

static void hns3_udma_u_init_urma_ctx_cfg(urma_device_t *dev,
					  urma_context_cfg_t *cfg,
					  int dev_fd, uint32_t eid_index)
{
	cfg->dev = dev;
	cfg->ops = &g_hns3_udma_u_ops;
	cfg->dev_fd = dev_fd;
	cfg->eid_index = eid_index;
}

static urma_status_t hns3_udma_u_alloc_db(struct hns3_udma_u_context *udma_u_ctx, int dev_fd)
{
	off_t offset;

	offset = get_mmap_offset(0, udma_u_ctx->page_size, HNS3_UDMA_MMAP_UAR_PAGE);
	udma_u_ctx->uar = mmap(NULL, udma_u_ctx->page_size, PROT_READ | PROT_WRITE,
			       MAP_SHARED, dev_fd, offset);
	if (udma_u_ctx->uar == MAP_FAILED) {
		HNS3_UDMA_LOG_ERR("failed to mmap uar page, errno:%d.\n", errno);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

static void hns3_udma_u_free_db(struct hns3_udma_u_context *udma_u_ctx)
{
	int ret;

	ret = munmap(udma_u_ctx->uar, (size_t)udma_u_ctx->page_size);
	if (ret != 0)
		HNS3_UDMA_LOG_ERR("failed to munmap uar.\n");
	udma_u_ctx->uar = NULL;
}

static urma_status_t init_reset_state(struct hns3_udma_u_context *udma_u_ctx, int dev_fd)
{
	off_t offset;

	offset = get_mmap_offset(0, udma_u_ctx->page_size, HNS3_UDMA_MMAP_RESET_PAGE);
	udma_u_ctx->reset_state = mmap(NULL, (size_t)udma_u_ctx->page_size, PROT_READ,
				       MAP_SHARED, dev_fd, offset);
	if (udma_u_ctx->reset_state == MAP_FAILED) {
		HNS3_UDMA_LOG_ERR("failed to mmap reset page, errno:%d.\n", errno);
		return URMA_FAIL;
	}

	return URMA_SUCCESS;
}

static void uninit_reset_state(struct hns3_udma_u_context *udma_u_ctx)
{
	int ret;

	ret = munmap(udma_u_ctx->reset_state, (size_t)udma_u_ctx->page_size);
	if (ret != 0)
		HNS3_UDMA_LOG_ERR("failed to munmap reset state.\n");
}

static urma_status_t hns3_udma_u_init_context(struct hns3_udma_u_context *udma_u_ctx,
					      struct hns3_udma_create_ctx_resp *resp,
					      int dev_fd)
{
	urma_status_t ret;

	udma_u_ctx->page_size = sysconf(_SC_PAGESIZE);
	udma_u_ctx->num_qps_shift = resp->num_qps_shift;
	udma_u_ctx->max_jfc_cqe = resp->max_jfc_cqe;
	udma_u_ctx->cqe_size = resp->cqe_size;
	udma_u_ctx->max_jfr_wr = resp->max_jfr_wr;
	udma_u_ctx->max_jfr_sge = resp->max_jfr_sge;
	udma_u_ctx->max_jfs_wr = resp->max_jfs_wr;
	udma_u_ctx->max_jfs_sge = resp->max_jfs_sge;
	udma_u_ctx->poe_ch_num = resp->poe_ch_num;
	udma_u_ctx->db_addr = resp->db_addr;
	udma_u_ctx->chip_id = resp->chip_id;
	udma_u_ctx->die_id = resp->die_id;
	udma_u_ctx->func_id = resp->func_id;

	ret = hns3_udma_u_alloc_db(udma_u_ctx, dev_fd);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to alloc db.\n");
		return ret;
	}

	ret = init_reset_state(udma_u_ctx, dev_fd);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to init reset state.\n");
		hns3_udma_u_free_db(udma_u_ctx);
	}

	return ret;
}

static void hns3_udma_u_uninit_context(struct hns3_udma_u_context *udma_u_ctx)
{
	uninit_reset_state(udma_u_ctx);
	hns3_udma_u_free_db(udma_u_ctx);
}

static void hns3_udma_cleanup_dca_mem(struct hns3_udma_u_context *ctx)
{
	struct hns3_udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct hns3_udma_dca_dereg_attr dereg_attr = {};
	struct hns3_udma_u_dca_mem *mem, *tmp;

	pthread_spin_lock(&dca_ctx->lock);
	list_for_each_entry_safe(mem, tmp, &dca_ctx->mem_list, entry) {
		dereg_attr.free_key = dca_mem_to_key(mem);
		exec_deregister_dca_mem_cmd(ctx, &dereg_attr);
		list_del(&mem->entry);
		ubn_u_free_dca_mem(mem);
	}
	pthread_spin_unlock(&dca_ctx->lock);
}

static void uninit_dca_context(struct hns3_udma_u_context *udma_u_ctx)
{
	struct hns3_udma_u_dca_ctx *dca_ctx = &udma_u_ctx->dca_ctx;
	int ret;

	if (!dca_ctx->unit_size)
		return;

	hns3_udma_cleanup_dca_mem(udma_u_ctx);

	if (dca_ctx->buf_status) {
		ret = munmap(dca_ctx->buf_status, (size_t)udma_u_ctx->page_size);
		if (ret != 0)
			HNS3_UDMA_LOG_ERR("Failed to munmap dca.\n");
		dca_ctx->buf_status = NULL;
	}

	(void)pthread_spin_destroy(&dca_ctx->lock);
}

static void hns3_udma_u_destroy_jfr_table(struct hns3_udma_u_context *ctx)
{
	struct hns3_udma_jfr_node *cur, *next;

	(void)pthread_rwlock_wrlock(&ctx->jfr_table_lock);
	HMAP_FOR_EACH_SAFE(cur, next, node, &ctx->jfr_table) {
		hns3_udma_hmap_remove(&ctx->jfr_table, &cur->node);
		free(cur);
	}
	(void)pthread_rwlock_unlock(&ctx->jfr_table_lock);
	hns3_udma_hmap_destroy(&ctx->jfr_table);
	(void)pthread_rwlock_destroy(&ctx->jfr_table_lock);
}

static void hns3_udma_u_destroy_jfs_qp_table(struct hns3_udma_u_context *ctx)
{
	struct hns3_udma_jfs_qp_node *cur, *next;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	HMAP_FOR_EACH_SAFE(cur, next, node, &ctx->jfs_qp_table) {
		hns3_udma_hmap_remove(&ctx->jfs_qp_table, &cur->node);
		free(cur);
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
	hns3_udma_hmap_destroy(&ctx->jfs_qp_table);
	(void)pthread_rwlock_destroy(&ctx->jfs_qp_table_lock);
}

static urma_status_t init_jetty_x_table(struct hns3_udma_u_context *udma_u_ctx)
{
	urma_status_t ret = URMA_SUCCESS;
	int i;

	(void)pthread_rwlock_init(&udma_u_ctx->jfs_qp_table_lock, NULL);
	if (hns3_udma_hmap_init(&udma_u_ctx->jfs_qp_table, HNS3_UDMA_JFS_QP_TABLE_SIZE)) {
		HNS3_UDMA_LOG_ERR("init jfs table failed.\n");
		ret = URMA_ENOMEM;
		goto err_init_jfs_table;
	}

	(void)pthread_rwlock_init(&udma_u_ctx->jfr_table_lock, NULL);
	if (hns3_udma_hmap_init(&udma_u_ctx->jfr_table, HNS3_UDMA_JFR_TABLE_SIZE)) {
		HNS3_UDMA_LOG_ERR("init jfr table failed.\n");
		ret = URMA_ENOMEM;
		goto err_init_jfr_table;
	}

	if (udma_u_ctx->num_qps_shift > HNS3_UDMA_JETTY_TABLE_SHIFT)
		udma_u_ctx->jettys_in_tbl_shift =
			udma_u_ctx->num_qps_shift - HNS3_UDMA_JETTY_TABLE_SHIFT;
	else
		udma_u_ctx->jettys_in_tbl_shift = 0;

	udma_u_ctx->jettys_in_tbl = 1 << udma_u_ctx->jettys_in_tbl_shift;
	for (i = 0; i < HNS3_UDMA_JETTY_TABLE_NUM; i++)
		udma_u_ctx->jetty_table[i].refcnt = 0;
	(void)pthread_rwlock_init(&udma_u_ctx->jetty_table_lock, NULL);
	return ret;

err_init_jfr_table:
	pthread_rwlock_destroy(&udma_u_ctx->jfr_table_lock);
	hns3_udma_hmap_destroy(&udma_u_ctx->jfs_qp_table);
err_init_jfs_table:
	pthread_rwlock_destroy(&udma_u_ctx->jfs_qp_table_lock);

	return ret;
}

static uint64_t get_env_val(char *env)
{
	uint64_t val = 0;
	char *end = NULL;

	errno = 0;
	if (env) {
		while (*env != '\0' && isspace(*env))
			env++;

		if (*env != '-')
			val = strtoul(env, &end, 0);

		if (errno == ERANGE || *env == '-' || *end) {
			HNS3_UDMA_LOG_ERR("The env val is error!\n");
			return 0;
		}
	}

	return val;
}

static void load_dca_config_from_env_var(struct hns3_udma_dca_context_attr *attr)
{
	uint32_t align_unit_size;
	uint64_t unit_size;
	uint64_t max_size;
	uint64_t min_size;
	uint64_t tp_num;
	char *env;

	unit_size = get_env_val(getenv("HNS3_UDMA_DCA_UNIT_SIZE"));
	if (unit_size == 0)
		return; /* Disable DCA only for this process */

	if (unit_size <= UINT32_MAX &&
	    ALIGN_OVER_BOUND((uint32_t)unit_size, (uint32_t)sysconf(_SC_PAGESIZE))) {
		attr->comp_mask |= HNS3_UDMA_CONTEXT_MASK_DCA_UNIT_SIZE;
		attr->dca_unit_size = unit_size;
	} else {
		HNS3_UDMA_LOG_ERR("The DCA_UNIT_SIZE is too large!\n");
		return;
	}

	align_unit_size = align(unit_size, sysconf(_SC_PAGESIZE));
	/*
	 * not set OR 0: Unlimited memory pool increase.
	 * others: Maximum memory pool size to be increased.
	 */
	max_size = get_env_val(getenv("HNS3_UDMA_DCA_MAX_SIZE"));
	if (max_size > 0 && ALIGN_OVER_UNIT_SIZE(max_size, align_unit_size)) {
		attr->comp_mask |= HNS3_UDMA_CONTEXT_MASK_DCA_MAX_SIZE;
		attr->dca_max_size = max_size;
	}

	/*
	 * not set: The memory pool cannot be reduced.
	 * others: The size of free memory in the pool cannot exceed this value.
	 * 0: Always reduce the free memory in the pool.
	 */
	min_size = get_env_val(getenv("HNS3_UDMA_DCA_MIN_SIZE"));
	if (min_size > 0 && ALIGN_OVER_UNIT_SIZE(min_size, align_unit_size)) {
		attr->comp_mask |= HNS3_UDMA_CONTEXT_MASK_DCA_MIN_SIZE;
		attr->dca_min_size = min_size;
	}

	env = getenv("HNS3_UDMA_DCA_PRIME_TP_NUM");
	if (env) {
		attr->comp_mask |= HNS3_UDMA_CONTEXT_MASK_DCA_PRIME_QPS;
		tp_num = get_env_val(env);
		if (tp_num <= MAX_TP_CNT)
			attr->dca_prime_qps = tp_num;
		else
			HNS3_UDMA_LOG_ERR("The DCA_PRIME_TP_NUM is too large!\n");
	}
}

static void ucontext_set_cmd(struct hns3_udma_create_ctx_ucmd *cmd,
			     struct hns3_udma_dca_context_attr *attr)
{
	if (attr->comp_mask & HNS3_UDMA_CONTEXT_MASK_DCA_UNIT_SIZE)
		cmd->dca_unit_size = attr->dca_unit_size;

	if (attr->comp_mask & HNS3_UDMA_CONTEXT_MASK_DCA_PRIME_QPS) {
		cmd->comp |= HNS3_UDMA_CONTEXT_MASK_DCA_PRIME_QPS;
		cmd->dca_max_qps = attr->dca_prime_qps;
	}
}

static void set_dca_pool_param(struct hns3_udma_u_context *ctx,
			       struct hns3_udma_dca_context_attr *attr)
{
	struct hns3_udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;

	if (attr->comp_mask & HNS3_UDMA_CONTEXT_MASK_DCA_UNIT_SIZE)
		dca_ctx->unit_size = align(attr->dca_unit_size, ctx->page_size);

	/* If not set, the memory pool can be expanded unlimitedly. */
	if (attr->comp_mask & HNS3_UDMA_CONTEXT_MASK_DCA_MAX_SIZE)
		dca_ctx->max_size = DIV_ROUND_UP(attr->dca_max_size,
					dca_ctx->unit_size) * dca_ctx->unit_size;
	else
		dca_ctx->max_size = HNS3_UDMA_DCA_MAX_MEM_SIZE;

	/* If not set, the memory pool cannot be shrunk. */
	if (attr->comp_mask & HNS3_UDMA_CONTEXT_MASK_DCA_MIN_SIZE)
		dca_ctx->min_size = DIV_ROUND_UP(attr->dca_min_size,
					dca_ctx->unit_size) * dca_ctx->unit_size;
	else
		dca_ctx->min_size = HNS3_UDMA_DCA_MAX_MEM_SIZE;

	HNS3_UDMA_LOG_INFO("Support DCA, unit %u, max %lu, min %lu Bytes.\n",
	       dca_ctx->unit_size, dca_ctx->max_size, dca_ctx->min_size);
}

static int mmap_dca(struct hns3_udma_u_context *ctx, int dev_fd, size_t size)
{
	struct hns3_udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;
	off_t offset;
	void *addr;

	offset = get_mmap_offset(0, ctx->page_size, HNS3_UDMA_MMAP_TYPE_DCA);

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, offset);
	if (addr == MAP_FAILED) {
		HNS3_UDMA_LOG_ERR("failed to mmap dca addr.\n");
		return URMA_FAIL;
	}

	dca_ctx->buf_status = (atomic_ulong *)addr;
	dca_ctx->sync_status = (atomic_ulong *)(addr + size / DCA_BITS_HALF);

	return URMA_SUCCESS;
}

static int init_dca_context(struct hns3_udma_u_context *ctx, int dev_fd,
			    struct hns3_udma_create_ctx_resp *resp,
			    struct hns3_udma_dca_context_attr *attr)
{
	const uint32_t bits_per_qp = 2 * HNS3_UDMA_DCA_BITS_PER_STATUS;
	struct hns3_udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;
	int mmap_size = resp->dca_mmap_size;
	int max_qps = resp->dca_qps;
	int ret;

	if (!resp->dca_mode || !attr->dca_unit_size)
		return 0;

	INIT_LIST_HEAD(&dca_ctx->mem_list);
	ret = pthread_spin_init(&dca_ctx->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret) {
		HNS3_UDMA_LOG_ERR("Failed to init DCA spin lock ret %d.\n", ret);
		return ret;
	}

	set_dca_pool_param(ctx, attr);
	if (!mmap_dca(ctx, dev_fd, mmap_size)) {
		dca_ctx->status_size = mmap_size;
		dca_ctx->max_qps = min_t(int, max_qps,
					 mmap_size * BIT_CNT_PER_BYTE / bits_per_qp);
	}

	return 0;
}

static urma_context_t *hns3_udma_u_create_context(urma_device_t *dev,
						  uint32_t eid_index, int dev_fd)
{
	struct hns3_udma_dca_context_attr hns3_udma_env_attr = {};
	struct hns3_udma_create_ctx_resp resp = {};
	struct hns3_udma_create_ctx_ucmd cmd = {};
	urma_cmd_udrv_priv_t udrv_data = {};
	struct hns3_udma_u_context *udma_u_ctx;
	urma_context_cfg_t cfg = {};
	urma_status_t ret;

	udma_u_ctx = (struct hns3_udma_u_context *)calloc(1, sizeof(struct hns3_udma_u_context));
	if (udma_u_ctx == NULL) {
		HNS3_UDMA_LOG_ERR("failed to alloc memory for hns3_udma_u ctx.\n");
		return NULL;
	}

	hns3_udma_u_init_urma_ctx_cfg(dev, &cfg, dev_fd, eid_index);

	load_dca_config_from_env_var(&hns3_udma_env_attr);
	ucontext_set_cmd(&cmd, &hns3_udma_env_attr);
	hns3_udma_set_udata(&udrv_data, &cmd, sizeof(cmd), &resp, sizeof(resp));

	if (urma_cmd_create_context(&udma_u_ctx->urma_ctx, &cfg, &udrv_data))
		goto free_ctx;

	ret = hns3_udma_u_init_context(udma_u_ctx, &resp, dev_fd);
	if (ret != URMA_SUCCESS) {
		HNS3_UDMA_LOG_ERR("hns3_udma_u init ctx failed.\n");
		goto err_cmd;
	}

	if (init_dca_context(udma_u_ctx, dev_fd, &resp, &hns3_udma_env_attr))
		goto err_init_context;

	ret = init_jetty_x_table(udma_u_ctx);
	if (ret)
		goto err_init_dca;

	return &udma_u_ctx->urma_ctx;

err_init_dca:
	uninit_dca_context(udma_u_ctx);
err_init_context:
	hns3_udma_u_uninit_context(udma_u_ctx);
err_cmd:
	(void)urma_cmd_delete_context(&udma_u_ctx->urma_ctx);
free_ctx:
	free(udma_u_ctx);

	return NULL;
}

static urma_status_t hns3_udma_u_delete_context(urma_context_t *ctx)
{
	struct hns3_udma_u_context *udma_u_ctx = to_hns3_udma_ctx(ctx);
	urma_status_t ret = URMA_SUCCESS;

	(void)pthread_rwlock_destroy(&udma_u_ctx->jetty_table_lock);
	hns3_udma_u_destroy_jfr_table(udma_u_ctx);
	hns3_udma_u_destroy_jfs_qp_table(udma_u_ctx);
	uninit_dca_context(udma_u_ctx);
	hns3_udma_u_uninit_context(udma_u_ctx);
	if (urma_cmd_delete_context(&udma_u_ctx->urma_ctx)) {
		HNS3_UDMA_LOG_ERR("hns3_udma_u destroy ctx failed.\n");
		ret = URMA_FAIL;
	}

	free(udma_u_ctx);

	return ret;
}

static urma_status_t hns3_udma_u_init(urma_init_attr_t *conf)
{
	hns3_udma_getenv_log_level();
	return URMA_SUCCESS;
}

static urma_status_t hns3_udma_u_uinit(void)
{
	return URMA_SUCCESS;
}

urma_provider_ops_t g_hns3_udma_u_provider_ops = {
	.name = "hns3_udma_v1",
	.attr = {
		.version = 1,
		.transport_type = URMA_TRANSPORT_HNS_UB,
	},
	.match_table = match_table,
	.init = hns3_udma_u_init,
	.uninit = hns3_udma_u_uinit,
	.query_device = hns3_udma_u_query_device,
	.create_context = hns3_udma_u_create_context,
	.delete_context = hns3_udma_u_delete_context,
};
