// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include <stdio.h>
#include "udma_u_buf.h"

bool udma_u_alloc_queue_buf(struct udma_u_jetty_queue *q, uint32_t max_entry_cnt,
			    uint32_t baseblk_size, uint32_t page_size,
			    bool wrid_en)
{
	uint32_t buf_shift;
	uint32_t entry_cnt;

	entry_cnt = roundup_pow_of_two(max_entry_cnt);
	buf_shift = align_power2(entry_cnt * baseblk_size);
	q->baseblk_shift = align_power2(baseblk_size);
	q->qbuf_size = align((1U << buf_shift), page_size);
	q->baseblk_cnt = q->qbuf_size >> q->baseblk_shift;
	q->baseblk_mask = q->baseblk_cnt - 1U;

	if (wrid_en) {
		q->wrid = (uintptr_t *)malloc(q->baseblk_cnt * sizeof(uint64_t));
		if (!q->wrid) {
			UDMA_LOG_ERR("failed to alloc buffer for wrid.\n");
			return false;
		}
	}

	if (q->ctx->hugepage_enable) {
		q->hugepage = udma_u_alloc_hugepage(q->ctx, q->qbuf_size);
		if (q->hugepage) {
			q->qbuf = q->hugepage->va_start;
		} else {
			UDMA_LOG_WARN("failed to alloc hugepage buf, switch to alloc normal buf.");
			q->qbuf = udma_u_alloc_buf(q->qbuf_size);
		}
	} else {
		q->qbuf = udma_u_alloc_buf(q->qbuf_size);
	}

	if (!q->qbuf) {
		UDMA_LOG_ERR("failed to alloc queue buffer.\n");
		if (wrid_en) {
			free(q->wrid);
			q->wrid = NULL;
		}
		return false;
	}
	q->qbuf_curr = q->qbuf;
	q->qbuf_end = q->qbuf + q->qbuf_size;

	return true;
}

void udma_u_free_queue_buf(struct udma_u_jetty_queue *q)
{
	if (q->wrid != NULL) {
		free(q->wrid);
		q->wrid = NULL;
	}

	if (q->cstm)
		return;

	if (q->qbuf != NULL) {
		if (q->hugepage)
			udma_u_free_hugepage(q->ctx, q->hugepage);
		else
			udma_u_free_buf(q->qbuf, q->qbuf_size);
		q->qbuf = NULL;
		q->qbuf_curr = NULL;
		q->qbuf_end = NULL;
	}
}

void *udma_u_alloc_buf(uint32_t buf_size)
{
	void *buf;
	int ret;

	buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		UDMA_LOG_ERR("mmap failed, buf_size=%u.\n", buf_size);
		return NULL;
	}

	ret = madvise(buf, buf_size, MADV_DONTFORK);
	if (ret) {
		(void)munmap(buf, buf_size);
		UDMA_LOG_ERR("buf madvise failed! ret = %d\n", ret);
		return NULL;
	}

	return buf;
}

static void udma_u_hugepage_add(struct udma_u_context *ctx,
				struct udma_u_hugepage_priv *priv)
{
	if (!ctx->hugepage_list) {
		ctx->hugepage_list = priv;
		priv->next = NULL;
	} else {
		priv->next = ctx->hugepage_list;
		ctx->hugepage_list->pre = priv;
		ctx->hugepage_list = priv;
	}
	priv->pre = NULL;
}

static void udma_u_hugepage_del(struct udma_u_context *ctx,
				struct udma_u_hugepage_priv *priv)
{
	if (priv->pre)
		priv->pre->next = priv->next;
	else
		ctx->hugepage_list = priv->next;

	if (priv->next)
		priv->next->pre = priv->pre;
}

static struct udma_u_hugepage_priv *
udma_u_alloc_hugepage_priv(struct udma_u_context *ctx, uint32_t len)
{
	off_t offset = get_mmap_offset((UDMA_HUGEPAGE_SIZE / ctx->page_size >> MAP_INDEX_SHIFT), ctx->page_size, UDMA_MMAP_HUGEPAGE);
	struct udma_u_hugepage_priv *priv;
	int ret;

	priv = (struct udma_u_hugepage_priv *)calloc(1, sizeof(*priv));
	if (!priv) {
		UDMA_LOG_ERR("alloc hugepage_priv failed.\n");
		return NULL;
	}

	priv->va_len = align(len, UDMA_HUGEPAGE_SIZE);
	priv->left_va_len = priv->va_len;
	priv->va_base = mmap(NULL, priv->va_len, PROT_READ | PROT_WRITE,
			    MAP_SHARED, ctx->urma_ctx.dev_fd, offset);
	if (priv->va_base == MAP_FAILED) {
		UDMA_LOG_ERR("mmap failed, buf_size=%u.\n", priv->va_len);
		goto err_mmap;
	}

	ret = madvise(priv->va_base, priv->va_len, MADV_DONTFORK);
	if (ret) {
		UDMA_LOG_ERR("buf madvise failed! ret = %d\n", ret);
		goto err_madvise;
	}
	udma_u_hugepage_add(ctx, priv);

	return priv;

err_madvise:
	(void)munmap(priv->va_base, priv->va_len);
err_mmap:
	free(priv);

	return NULL;
}

struct udma_u_hugepage *udma_u_alloc_hugepage(struct udma_u_context *ctx, uint32_t len)
{
	struct udma_u_hugepage_priv *priv = NULL;
	struct udma_u_hugepage *hugepage;

	hugepage = (struct udma_u_hugepage *)calloc(1, sizeof(*hugepage));
	if (!hugepage) {
		UDMA_LOG_ERR("alloc hugepage failed.\n");
		return NULL;
	}

	pthread_mutex_lock(&ctx->hugepage_lock);
	if (ctx->hugepage_list && ctx->hugepage_list->left_va_len >= len)
		priv = ctx->hugepage_list;

	if (!priv) {
		priv = udma_u_alloc_hugepage_priv(ctx, len);
		if (!priv) {
			pthread_mutex_unlock(&ctx->hugepage_lock);
			free(hugepage);
			return NULL;
		}
	}

	hugepage->va_start = priv->va_base + priv->left_va_offset;
	hugepage->va_len = len;
	hugepage->priv = priv;
	priv->left_va_offset += len;
	priv->left_va_len -= len;
	priv->refcnt++;
	pthread_mutex_unlock(&ctx->hugepage_lock);

	return hugepage;
}

void udma_u_free_hugepage(struct udma_u_context *ctx, struct udma_u_hugepage *hugepage)
{
	pthread_mutex_lock(&ctx->hugepage_lock);
	hugepage->priv->refcnt--;
	if (hugepage->priv->refcnt) {
		pthread_mutex_unlock(&ctx->hugepage_lock);
		free(hugepage);
		return;
	}

	(void)munmap(hugepage->priv->va_base, hugepage->priv->va_len);
	udma_u_hugepage_del(ctx, hugepage->priv);
	pthread_mutex_unlock(&ctx->hugepage_lock);

	free(hugepage->priv);
	hugepage->priv = NULL;
	free(hugepage);
}

void udma_u_destroy_hugepage(struct udma_u_context *ctx)
{
	struct udma_u_hugepage_priv *priv;

	pthread_mutex_lock(&ctx->hugepage_lock);
	while (ctx->hugepage_list) {
		priv = ctx->hugepage_list;
		udma_u_hugepage_del(ctx, priv);
		(void)munmap(priv->va_base, priv->va_len);
		free(priv);
	}
	pthread_mutex_unlock(&ctx->hugepage_lock);
	(void)pthread_mutex_destroy(&ctx->hugepage_lock);
}
