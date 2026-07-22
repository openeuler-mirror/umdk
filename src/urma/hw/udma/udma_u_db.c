// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 * thanks to rdma-core-master/providers/hns/hns_roce_u_db.c code.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include "udma_u_buf.h"
#include "udma_u_db.h"

void udma_u_init_bitmap(uint64_t *bitmap, uint32_t bitmap_cnt)
{
	for (uint32_t i = 0; i < bitmap_cnt; ++i)
		bitmap[i] = ~(0ULL);
}

uint64_t *udma_bitmap_alloc(uint32_t n_bits, uint32_t *bitmap_cnt)
{
	uint64_t *bitmap;

	*bitmap_cnt = align(n_bits, UDMA_BITS_PER_LONG) / UDMA_BITS_PER_LONG;
	bitmap = (uint64_t *)calloc(*bitmap_cnt, sizeof(uint64_t));
	if (!bitmap) {
		UDMA_LOG_ERR("failed to calloc bitmap!\n");
		return NULL;
	}

	udma_u_init_bitmap(bitmap, *bitmap_cnt);

	return bitmap;
}

int udma_bitmap_use_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			uint32_t n_bits, uint32_t *idx)
{
	uint32_t bit_num;
	uint32_t i;

	for (i = 0; i < bitmap_cnt && bitmap[i] == 0; ++i)
		;
	if (i == bitmap_cnt) {
		UDMA_LOG_ERR("all bitmaps have been used! bitmap count = %u\n",
			     bitmap_cnt);
		return ENOMEM;
	}

	bit_num = ffsl(bitmap[i]);
	*idx = (i << UDMA_BITS_PER_LONG_SHIFT) + bit_num - 1;

	if (*idx >= n_bits) {
		UDMA_LOG_ERR("the index exceeds the range of the bitmap!\n");
		return ENOMEM;
	}

	bitmap[i] &= ~(1ULL << (bit_num - 1));

	return 0;
}

void udma_bitmap_free_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			  uint32_t idx)
{
	uint32_t bitmap_num;
	uint32_t bit_num;

	bitmap_num = idx >> UDMA_BITS_PER_LONG_SHIFT;
	if (bitmap_num >= bitmap_cnt)
		return;

	bit_num = idx % UDMA_BITS_PER_LONG;
	bitmap[bitmap_num] |= (1ULL << bit_num);
}

static struct udma_u_db_page *udma_add_db_page(struct udma_u_context *ctx,
					       enum udma_db_type type)
{
	struct udma_u_db_page *db_page;
	uint32_t page_size;

	page_size = ctx->page_size;
	db_page = (struct udma_u_db_page *)calloc(1, sizeof(*db_page));
	if (!db_page) {
		UDMA_LOG_ERR("failed to calloc SW DB page!\n");
		return NULL;
	}

	/* allocate bitmap space for sw db and init all bitmap to 1 */
	db_page->num_db = page_size / UDMA_DB_SIZE;
	db_page->use_cnt = 0;
	db_page->bitmap = udma_bitmap_alloc(db_page->num_db, &db_page->bitmap_cnt);
	if (!db_page->bitmap)
		goto err_map;

	db_page->buf.length = page_size;
	if (type == UDMA_JFR_PAYLOAD)
		db_page->buf.buf = udma_u_alloc_buf(db_page->buf.length);
	else
		db_page->buf.buf = udma_u_alloc_kernel_buf(ctx, db_page->buf.length);
	if (!db_page->buf.buf)
		goto err_buf;

	/* add the set ctx->db_list */
	db_page->prev = NULL;
	db_page->next = ctx->db_list[type];
	ctx->db_list[type] = db_page;
	if (db_page->next)
		db_page->next->prev = db_page;

	return db_page;
err_buf:
	udma_bitmap_free(db_page->bitmap);
err_map:
	free(db_page);

	return NULL;
}

static void udma_clear_db_page(struct udma_u_db_page *db_page)
{
	if (db_page->buf.buf)
		udma_u_free_buf(db_page->buf.buf, db_page->buf.length);

	udma_bitmap_free(db_page->bitmap);
	free(db_page);
}

void *udma_u_alloc_sw_db(struct udma_u_context *ctx, enum udma_db_type type)
{
	struct udma_u_db_page *db_page;
	void *db = NULL;
	uint32_t npos;

	(void)pthread_mutex_lock(&ctx->db_list_mutex);

	for (db_page = ctx->db_list[type]; db_page != NULL; db_page = db_page->next)
		if (db_page->use_cnt < db_page->num_db)
			goto found;

	db_page = udma_add_db_page(ctx, type);
	if (!db_page)
		goto out;

found:
	(void)udma_bitmap_use_idx(db_page->bitmap, db_page->bitmap_cnt,
				  db_page->num_db, &npos);

	db = (char *)db_page->buf.buf + npos * UDMA_DB_SIZE;
	*(uint32_t *)db = 0;

	++db_page->use_cnt;
out:
	(void)pthread_mutex_unlock(&ctx->db_list_mutex);

	return db;
}

void udma_u_free_sw_db(struct udma_u_context *ctx, uint32_t *db,
		       enum udma_db_type type)
{
	struct udma_u_db_page *db_page;
	uint32_t page_size;
	uint32_t npos;

	(void)pthread_mutex_lock(&ctx->db_list_mutex);

	page_size = ctx->page_size;
	for (db_page = ctx->db_list[type]; db_page != NULL; db_page = db_page->next)
		if (((uintptr_t)db & (~((uintptr_t)page_size - 1))) ==
						(uintptr_t)(db_page->buf.buf))
			goto found;

	goto out;

found:
	--db_page->use_cnt;
	if (!db_page->use_cnt) {
		if (db_page->prev)
			db_page->prev->next = db_page->next;
		else
			ctx->db_list[type] = db_page->next;

		if (db_page->next)
			db_page->next->prev = db_page->prev;

		udma_clear_db_page(db_page);

		goto out;
	}

	npos = ((uintptr_t)db - (uintptr_t)db_page->buf.buf) / UDMA_DB_SIZE;
	udma_bitmap_free_idx(db_page->bitmap, db_page->bitmap_cnt, npos);

out:
	(void)pthread_mutex_unlock(&ctx->db_list_mutex);
}

int udma_u_alloc_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db)
{
	struct udma_u_context *udma_u_ctx = to_udma_u_ctx(urma_ctx);
	off_t offset;

	offset = get_mmap_offset(db->id, udma_u_ctx->page_size, db->type);

	db->addr = mmap(NULL, udma_u_ctx->page_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, urma_ctx->dev_fd, offset);
	if (db->addr == MAP_FAILED) {
		UDMA_LOG_ERR("failed to mmap doorbell page, id = %u, type = %u.\n",
			     db->id, db->type);
		return EINVAL;
	}

	if (db->type == UDMA_MMAP_JETTY_DSQE)
		db->addr = db->addr + udma_get_dsqe_db_offset(udma_u_ctx, db);

	return 0;
}

void udma_u_free_db(struct urma_context *urma_ctx, struct udma_u_doorbell *db)
{
	struct udma_u_context *udma_u_ctx = to_udma_u_ctx(urma_ctx);

	if (db->addr == MAP_FAILED || db->addr == NULL)
		return;

	if (db->type == UDMA_MMAP_JETTY_DSQE)
		db->addr = db->addr - udma_get_dsqe_db_offset(udma_u_ctx, db);

	munmap((void *)db->addr, (size_t)udma_u_ctx->page_size);
	db->addr = NULL;
}
