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

#include "hns3_udma_u_common.h"

void udma_hmap_remove(struct udma_hmap *hmap, const struct udma_hmap_node *node)
{
	struct udma_hmap_node *pre_node =
		(struct udma_hmap_node *)&hmap->bucket[node->hash & hmap->mask];
	struct udma_hmap_node *tmp_node = pre_node->next;

	while (tmp_node != NULL) {
		struct udma_hmap_node *next_node = tmp_node->next;

		if (tmp_node == node) {
			pre_node->next = next_node;
			hmap->count--;
			return;
		}
		pre_node = tmp_node;
		tmp_node = next_node;
	}
}

uint64_t *udma_bitmap_alloc(uint32_t n_bits, uint32_t *bitmap_cnt)
{
	uint64_t *bitmap;
	uint32_t i;

	*bitmap_cnt = align(n_bits, BIT_CNT_PER_LONG) /
			    BIT_CNT_PER_LONG;
	bitmap = (uint64_t *)calloc(*bitmap_cnt, sizeof(uint64_t));
	if (!bitmap)
		return NULL;

	for (i = 0; i < *bitmap_cnt; ++i)
		bitmap[i] = ~(0UL);

	return bitmap;
}

void udma_bitmap_free(uint64_t *bitmap)
{
	free(bitmap);
}

int udma_bitmap_use_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
		     uint32_t n_bits, uint32_t *idx)
{
	uint32_t bit_num;
	uint32_t i;

	for (i = 0; i < bitmap_cnt && bitmap[i] == 0; ++i)
		;
	if (i == bitmap_cnt)
		return ENOMEM;

	bit_num = ffsl(bitmap[i]);
	bitmap[i] &= ~(1ULL << (bit_num - 1));

	*idx = i * BIT_CNT_PER_LONG + (bit_num - 1);

	if (*idx >= n_bits)
		return ENOMEM;

	return 0;
}

void udma_bitmap_free_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			  uint32_t idx)
{
	uint32_t bitmap_num;
	uint32_t bit_num;

	bitmap_num = idx / BIT_CNT_PER_LONG;
	if (bitmap_num >= bitmap_cnt)
		return;

	bit_num = idx % BIT_CNT_PER_LONG;
	bitmap[bitmap_num] |= (1ULL << bit_num);
}
