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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ub_bitmap.h"
#include "hns3_udma_u_db.h"

static const uint32_t db_size[] = {
	[UDMA_JFS_TYPE_DB]	= 64,
	[UDMA_JFR_TYPE_DB]	= 64,
	[UDMA_JETTY_TYPE_DB]	= 64,
	[UDMA_JFC_TYPE_DB]	= 64,
};

static struct udma_db_page *udma_add_db_page(struct udma_u_context *ctx,
					     enum udma_db_type type)
{
	struct udma_db_page *db_page;
	int page_size;

	page_size = ctx->page_size;
	db_page = (struct udma_db_page *)calloc(1, sizeof(*db_page));
	if (!db_page)
		goto err_page;

	/* allocate bitmap space for sw db and init all bitmap to 1 */
	db_page->num_db = page_size / db_size[type];
	db_page->use_cnt = 0;
	db_page->bitmap = udma_bitmap_alloc(db_page->num_db, &db_page->bitmap_cnt);
	if (!db_page->bitmap)
		goto err_map;

	if (udma_alloc_buf(&db_page->buf, page_size, page_size))
		goto err;

	/* add the set ctx->db_list */
	db_page->prev = NULL;
	db_page->next = ctx->db_list[type];
	ctx->db_list[type] = db_page;
	if (db_page->next)
		db_page->next->prev = db_page;

	return db_page;
err:
	udma_bitmap_free(db_page->bitmap);

err_map:
	free(db_page);

err_page:
	return NULL;
}

static void udma_clear_db_page(struct udma_db_page *page)
{
	udma_free_buf(&page->buf);
	udma_bitmap_free(page->bitmap);
	free(page);
}

void *udma_alloc_sw_db(struct udma_u_context *ctx, enum udma_db_type type)
{
	struct udma_db_page *page;
	void *db = NULL;
	uint32_t npos;
	int ret;

	pthread_mutex_lock(&ctx->db_list_mutex);

	for (page = ctx->db_list[type]; page != NULL; page = page->next)
		if (page->use_cnt < page->num_db)
			goto found;

	page = udma_add_db_page(ctx, type);
	if (!page)
		goto out;

found:
	ret = udma_bitmap_use_idx(page->bitmap, page->bitmap_cnt,
				  page->num_db, &npos);
	if (ret)
		goto out;

	++page->use_cnt;
	db = (char *)page->buf.buf + npos * db_size[type];

out:
	pthread_mutex_unlock(&ctx->db_list_mutex);

	return db;
}

void udma_free_sw_db(struct udma_u_context *ctx, uint32_t *db,
		     enum udma_db_type type)
{
	struct udma_db_page *db_page;
	uint32_t page_size;
	uint32_t npos;

	pthread_mutex_lock(&ctx->db_list_mutex);

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

	npos = ((uintptr_t)db - (uintptr_t)db_page->buf.buf) / db_size[type];
	udma_bitmap_free_idx(db_page->bitmap, db_page->bitmap_cnt, npos);

out:
	pthread_mutex_unlock(&ctx->db_list_mutex);
}
