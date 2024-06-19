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

#include <errno.h>
#include <sys/mman.h>
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_buf.h"

int udma_alloc_buf(struct udma_buf *buf, uint32_t size, int page_size)
{
	int ret;

	buf->length = align(size, page_size);
	buf->buf = mmap(NULL, buf->length, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf->buf == MAP_FAILED)
		return errno;

	ret = madvise(buf->buf, buf->length, MADV_DONTFORK);
	if (ret) {
		munmap(buf->buf, buf->length);
		URMA_LOG_ERR("madvise failed! ret=%d\n", ret);
	}

	return ret;
}

void udma_free_buf(struct udma_buf *buf)
{
	if (!buf->buf)
		return;

	munmap(buf->buf, buf->length);
}

#define DCAN_TO_SYNC_BIT(n) ((n) * UDMA_DCA_BITS_PER_STATUS)
#define DCAN_TO_STAT_BIT(n) DCAN_TO_SYNC_BIT(n)

#define MAX_DCA_TRY_LOCK_TIMES 10
bool udma_dca_start_post(struct udma_u_dca_ctx *ctx, uint32_t dcan)
{
	atomic_ulong *st = ctx->sync_status;
	int try_times = 0;

	if (!st || dcan >= ctx->max_qps)
		return true;

	while (test_and_set_bit_lock(st, DCAN_TO_SYNC_BIT(dcan)))
		if (try_times++ > MAX_DCA_TRY_LOCK_TIMES)
			return false;

	return true;
}

static bool check_dca_is_attached(struct udma_u_dca_ctx *ctx, uint32_t dcan)
{
	atomic_ulong *st = ctx->buf_status;

	if (!st || dcan >= ctx->max_qps)
		return false;

	return atomic_test_bit(st, DCAN_TO_STAT_BIT(dcan));
}

static int exec_attach_dca_mem_cmd(struct udma_u_context *ctx,
				   struct udma_dca_attach_attr *attr,
				   struct udma_dca_attach_resp *resp)
{
	urma_context_t *urma_ctx = &(ctx->urma_ctx);
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_DCA_MEM_ATTACH;
	in.addr = (uint64_t)attr;
	in.len = (uint32_t)sizeof(struct udma_dca_attach_attr);
	out.addr = (uint64_t)resp;
	out.len = (uint32_t)sizeof(struct udma_dca_attach_resp);

	return urma_cmd_user_ctl(urma_ctx, &in, &out, &udrv_data);
}

static bool add_dca_mem_enabled(struct udma_u_dca_ctx *ctx, uint32_t alloc_size)
{
	bool enable;

	(void)pthread_spin_lock(&ctx->lock);

	if (ctx->max_size == UDMA_DCA_MAX_MEM_SIZE ||
	    ctx->max_size >= ctx->curr_size + alloc_size) {
		enable = true;
	} else {
		URMA_LOG_ERR("pool size 0x%x doesn't exceed max size 0x%x!",
			     ctx->curr_size + alloc_size, ctx->max_size);
		enable = false;
	}

	(void)pthread_spin_unlock(&ctx->lock);

	return enable;
}

static struct udma_u_dca_mem *udma_u_alloc_dca_mem(uint32_t size)
{
	struct udma_u_dca_mem *mem = NULL;
	int ret;

	mem = (struct udma_u_dca_mem *)calloc(1, sizeof(struct udma_u_dca_mem));
	if (!mem) {
		URMA_LOG_ERR("malloc udma_u_dca_mem failed!");
		return NULL;
	}

	ret = udma_alloc_buf(&mem->buf, size, UDMA_HW_PAGE_SIZE);
	if (ret) {
		free(mem);
		URMA_LOG_ERR("alloc buf failed! ret=%d\n", ret);
		return NULL;
	}

	return mem;
}

static int exec_register_dca_mem_cmd(struct udma_u_context *ctx,
				     struct udma_u_dca_mem *mem)
{
	urma_context_t *urma_ctx = &(ctx->urma_ctx);
	struct udma_dca_reg_attr attr = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	attr.addr = (uintptr_t)dca_mem_addr(mem, 0);
	attr.key = dca_mem_to_key(mem);
	attr.size = mem->buf.length;

	in.opcode = (uint32_t)UDMA_DCA_MEM_REG;
	in.addr = (uint64_t)&attr;
	in.len = (uint32_t)sizeof(struct udma_dca_reg_attr);

	return  urma_cmd_user_ctl(urma_ctx, &in, &out, &udrv_data);
}

void ubn_u_free_dca_mem(struct udma_u_dca_mem *mem)
{
	udma_free_buf(&mem->buf);
	free(mem);
}

static int add_dca_mem(struct udma_u_context *ctx, uint32_t size)
{
	struct udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct udma_u_dca_mem *mem;
	int ret;

	if (!add_dca_mem_enabled(&ctx->dca_ctx, size))
		return ENOMEM;

	/* Step 1: Alloc DCA mem address */
	mem = udma_u_alloc_dca_mem(DIV_ROUND_UP(size, dca_ctx->unit_size) *
				   dca_ctx->unit_size);
	if (!mem)
		return ENOMEM;

	/* Step 2: Register DCA mem uobject to pin user address */
	ret = exec_register_dca_mem_cmd(ctx, mem);
	if (ret) {
		URMA_LOG_ERR("register dca mem failed!");
		ubn_u_free_dca_mem(mem);
		return ret;
	}

	/* Step 3: Add DCA mem node to pool */
	(void)pthread_spin_lock(&dca_ctx->lock);
	INIT_LIST_HEAD(&mem->entry);
	list_add_tail(&dca_ctx->mem_list, &mem->entry);
	dca_ctx->mem_cnt++;
	dca_ctx->curr_size += mem->buf.length;
	(void)pthread_spin_unlock(&dca_ctx->lock);

	return 0;
}

static int exec_query_dca_mem_cmd(struct udma_u_context *ctx,
				  struct udma_dca_query_attr *attr,
				  struct udma_dca_query_resp *resp)
{
	urma_context_t *urma_ctx = &(ctx->urma_ctx);
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_DCA_MEM_QUERY;
	in.addr = (uint64_t)attr;
	in.len = (uint32_t)sizeof(struct udma_dca_query_attr);
	out.addr = (uint64_t)resp;
	out.len = (uint32_t)sizeof(struct udma_dca_query_resp);

	return urma_cmd_user_ctl(urma_ctx, &in, &out, &udrv_data);
}

static struct udma_u_dca_mem *key_to_dca_mem(struct udma_u_dca_ctx *ctx,
					     uintptr_t key)
{
	struct udma_u_dca_mem *mem;

	list_for_each_entry(mem, &ctx->mem_list, entry) {
		if (dca_mem_to_key(mem) == key)
			return mem;
	}

	return NULL;
}

static void config_dca_pages(void *addr, struct udma_dca_buf *buf,
			     uint32_t page_index, int page_count)
{
	void **pages = &buf->bufs[page_index];
	int page_size = 1 << buf->shift;
	void *cur_addr = addr;
	int i;

	for (i = 0; i < page_count; i++) {
		pages[i] = cur_addr;
		cur_addr += page_size;
	}
}

static int setup_dca_buf(struct udma_u_context *ctx, struct udma_dca_buf *buf,
			 uint32_t page_count, uint64_t qpn)
{
	struct udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct udma_dca_query_attr attr = {};
	struct udma_dca_query_resp resp = {};
	struct udma_u_dca_mem *mem;
	uint32_t idx = 0;
	int ret;

	while (idx < page_count && idx < buf->max_cnt) {
		resp.page_count = 0;
		attr.qpn = qpn;
		attr.page_idx = idx;
		ret = exec_query_dca_mem_cmd(ctx, &attr, &resp);
		if (ret)
			return ENOMEM;
		if (resp.page_count < 1)
			break;

		(void)pthread_spin_lock(&dca_ctx->lock);
		mem = key_to_dca_mem(dca_ctx, resp.mem_key);
		if (mem && resp.mem_ofs < mem->buf.length) {
			config_dca_pages(dca_mem_addr(mem, resp.mem_ofs),
					 buf, idx, resp.page_count);
		} else {
			(void)pthread_spin_unlock(&dca_ctx->lock);
			break;
		}
		(void)pthread_spin_unlock(&dca_ctx->lock);

		idx += resp.page_count;
	}

	return (idx >= page_count) ? 0 : ENOMEM;
}

#define DCA_EXPAND_MEM_TRY_TIMES 3
int udma_u_attach_dca_mem(struct udma_u_context *ctx,
			  struct udma_dca_attach_attr *attr,
			  uint32_t size, struct udma_dca_buf *buf, bool force)
{
	uint32_t buf_pages = size >> buf->shift;
	struct udma_dca_attach_resp resp = {};
	bool is_new_buf = true;
	uint32_t try_times = 0;
	int ret = 0;

	if (!force && check_dca_is_attached(&ctx->dca_ctx, buf->dcan))
		return 0;

	do {
		resp.alloc_pages = 0;
		ret = exec_attach_dca_mem_cmd(ctx, attr, &resp);
		if (ret)
			break;

		if (resp.alloc_pages >= buf_pages) {
			is_new_buf = !!(resp.alloc_flags &
					HNS3_UDMA_DCA_ATTACH_FLAGS_NEW_BUFFER);
			break;
		}

		ret = add_dca_mem(ctx, size);
		if (ret)
			break;
	} while (try_times++ < DCA_EXPAND_MEM_TRY_TIMES);

	if (ret || resp.alloc_pages < buf_pages) {
		URMA_LOG_ERR("attach failed, size %u count %u != %u, ret = %d.\n",
			     size, buf_pages, resp.alloc_pages, ret);
		return ENOMEM;
	}

	/* No need config user address if DCA config not changed */
	if (!is_new_buf && buf->bufs[0])
		return 0;

	buf->dcan = resp.dcan;

	return setup_dca_buf(ctx, buf, buf_pages, attr->qpn);
}

void udma_dca_stop_post(struct udma_u_dca_ctx *ctx, uint32_t dcan)
{
	atomic_ulong *st = ctx->sync_status;

	if (!st || dcan >= ctx->max_qps)
		return;

	clear_bit_unlock(st, DCAN_TO_SYNC_BIT(dcan));
}

static bool shrink_dca_mem_enabled(struct udma_u_dca_ctx *ctx)
{
	bool enable;

	pthread_spin_lock(&ctx->lock);
	enable = ctx->mem_cnt > 0 && ctx->min_size < ctx->curr_size;
	pthread_spin_unlock(&ctx->lock);

	return enable;
}

static int exec_shrink_dca_mem_cmd(struct udma_u_context *ctx,
				   struct udma_dca_shrink_attr *attr,
				   struct udma_dca_shrink_resp *resp)
{
	urma_context_t *urma_ctx = &(ctx->urma_ctx);
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_DCA_MEM_SHRINK;
	in.addr = (uint64_t)attr;
	in.len = (uint32_t)sizeof(struct udma_dca_shrink_attr);
	out.addr = (uint64_t)resp;
	out.len = (uint32_t)sizeof(struct udma_dca_shrink_resp);

	return urma_cmd_user_ctl(urma_ctx, &in, &out, &udrv_data);
}

int exec_deregister_dca_mem_cmd(struct udma_u_context *ctx,
				struct udma_dca_dereg_attr *attr)
{
	urma_context_t *urma_ctx = &(ctx->urma_ctx);
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_DCA_MEM_DEREG;
	in.addr = (uint64_t)attr;
	in.len = (uint32_t)sizeof(struct udma_dca_shrink_attr);

	return urma_cmd_user_ctl(urma_ctx, &in, &out, &udrv_data);
}

int exec_detach_dca_mem_cmd(struct udma_u_context *ctx,
			    struct udma_dca_detach_attr *attr)
{
	urma_context_t *urma_ctx = &(ctx->urma_ctx);
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_DCA_MEM_DETACH;
	in.addr = (uint64_t)attr;
	in.len = (uint32_t)sizeof(struct udma_dca_shrink_attr);

	return urma_cmd_user_ctl(urma_ctx, &in, &out, &udrv_data);
}

void udma_u_shrink_dca_mem(struct udma_u_context *ctx)
{
	struct udma_u_dca_ctx *dca_ctx = &ctx->dca_ctx;
	struct udma_dca_shrink_attr attr = {};
	struct udma_dca_shrink_resp resp = {};
	struct udma_u_dca_mem *mem;
	int dca_mem_cnt;
	int ret;

	(void)pthread_spin_lock(&dca_ctx->lock);
	dca_mem_cnt = ctx->dca_ctx.mem_cnt;
	(void)pthread_spin_unlock(&dca_ctx->lock);
	while (dca_mem_cnt > 0 && shrink_dca_mem_enabled(dca_ctx)) {
		resp.free_mems = 0;
		/* Step 1: Use any DCA mem uobject to shrink pool */
		(void)pthread_spin_lock(&dca_ctx->lock);
		mem = list_tail(&dca_ctx->mem_list, struct udma_u_dca_mem,
				entry);
		(void)pthread_spin_unlock(&dca_ctx->lock);
		if (!mem) {
			URMA_LOG_ERR("dca shrink failed, mem list is empty!");
			break;
		}

		attr.reserved_size = dca_ctx->min_size;
		ret = exec_shrink_dca_mem_cmd(ctx, &attr, &resp);
		if (ret) {
			URMA_LOG_ERR("dca shrink failed, ret = %d.\n", ret);
			break;
		}

		if (resp.free_mems < 1)
			break;

		/* Step 2: Remove shrunk DCA mem node from pool */
		(void)pthread_spin_lock(&dca_ctx->lock);
		mem = key_to_dca_mem(dca_ctx, resp.free_key);
		if (mem) {
			list_del(&mem->entry);
			dca_ctx->mem_cnt--;
			dca_ctx->curr_size -= mem->buf.length;
		}
		(void)pthread_spin_unlock(&dca_ctx->lock);
		if (!mem) {
			URMA_LOG_ERR("dca shrink failed, free_key is invalid!");
			break;
		}

		/* Step 3: Destroy DCA mem uobject */
		ubn_u_free_dca_mem(mem);
		/* No any free memory after deregister 1 DCA mem */
		if (resp.free_mems <= 1)
			break;

		dca_mem_cnt--;
	}
}
