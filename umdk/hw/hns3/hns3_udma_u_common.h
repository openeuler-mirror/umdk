/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _UDMA_U_COMMON_H
#define _UDMA_U_COMMON_H

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include "hns3_udma_u_abi.h"

#define check_types_match(expr1, expr2)		\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#ifndef container_of
#define container_off(containing_type, member)	\
	offsetof(containing_type, member)
#define container_of(member_ptr, containing_type, member)		\
	 ((containing_type *)						\
	  ((char *)(member_ptr)						\
	   - container_off(containing_type, member))			\
	  + check_types_match(*(member_ptr), ((containing_type *)0)->member))
#endif

/* the sw doorbell type */
enum udma_db_type {
	UDMA_JFS_TYPE_DB,
	UDMA_JFR_TYPE_DB,
	UDMA_JETTY_TYPE_DB,
	UDMA_JFC_TYPE_DB,
	UDMA_DB_TYPE_NUM
};

static inline void udma_set_udata(urma_cmd_udrv_priv_t *udrv_data, void *in_addr,
				  uint32_t in_len, void *out_addr,
				  uint32_t out_len)
{
	udrv_data->in_addr = (uint64_t)in_addr;
	udrv_data->in_len = in_len;
	udrv_data->out_addr = (uint64_t)out_addr;
	udrv_data->out_len = out_len;
}

/* command value is offset[7:0] */
static inline void udma_mmap_set_command(int command, off_t *offset)
{
	*offset |= (command & MAP_COMMAND_MASK);
}

/* index value is offset[32:8] */
static inline void udma_mmap_set_index(unsigned long index, off_t *offset)
{
	*offset |= ((index & MAP_INDEX_MASK) << MAP_INDEX_SHIFT);
}

static inline off_t get_mmap_offset(uint32_t idx, int page_size, int cmd)
{
	off_t offset = 0;

	udma_mmap_set_command(cmd, &offset);
	udma_mmap_set_index(idx, &offset);

	return offset * page_size;
}

struct udma_hmap_node {
	struct udma_hmap_node	*next;
	uint32_t		hash;
};

struct udma_hmap_head {
	struct udma_hmap_node	*next;
};

struct udma_hmap {
	uint32_t		count;
	uint32_t		mask;
	struct udma_hmap_head	*bucket;
};

void udma_hmap_remove(struct udma_hmap *hmap, const struct udma_hmap_node *node);

static inline struct udma_hmap_node *udma_hmap_first_from_idx(const struct udma_hmap *hmap,
							      uint32_t idx)
{
	struct udma_hmap_node *node = NULL;

	if (hmap == NULL || hmap->bucket == NULL)
		return NULL;

	for (uint32_t i = idx; i < hmap->mask + 1; i++) {
		node = hmap->bucket[i].next;
		if (node != NULL)
			break;
	}
	return node;
}

static inline struct udma_hmap_node *udma_hmap_first(const struct udma_hmap *hmap)
{
	return udma_hmap_first_from_idx(hmap, 0);
}

static inline struct udma_hmap_node *udma_hmap_next(const struct udma_hmap *hmap,
						    const struct udma_hmap_node *pre_node)
{
	struct udma_hmap_node *node = pre_node->next;

	if (node != NULL)
		return node;

	return udma_hmap_first_from_idx(hmap, (pre_node->hash & hmap->mask) + 1);
}

#define OBJ_OFFSETOF(obj_ptr, field) offsetof(typeof(*(obj_ptr)), field)

/* get the structure object from the pointer of the given field by type of obj_ptr */
#define OBJ_CONTAINING(field_ptr, obj_ptr, field) \
	((typeof(obj_ptr))(void *)((char *)(field_ptr) - OBJ_OFFSETOF(obj_ptr, field)))

/* get the structure object from the pointer of the given field by struct type,
 * Then assign the structure object to the obj_ptr
 */
#define ASSIGN_CONTAINER_PTR(obj_ptr, field_ptr, field) \
	((obj_ptr) = OBJ_CONTAINING(field_ptr, obj_ptr, field), (void)0)

/* initialize obj_ptr and  ASSIGN_CONTAINER_PTR to avoid compile warnings. */
#define INIT_CONTAINER_PTR(obj_ptr, field_ptr, field) \
	((obj_ptr) = NULL, ASSIGN_CONTAINER_PTR(obj_ptr, field_ptr, field))

#define HMAP_FOR_EACH(NODE, MEMBER, TABLE) \
	for (INIT_CONTAINER_PTR(NODE, udma_hmap_first(TABLE), MEMBER); \
		(((NODE) != OBJ_CONTAINING(NULL, (NODE), MEMBER)) || ((NODE) = NULL)); \
		ASSIGN_CONTAINER_PTR((NODE), udma_hmap_next(TABLE, &(NODE)->MEMBER), MEMBER))

#define HMAP_FOR_EACH_SAFE(NODE, NEXT, MEMBER, HMAP) \
	for (INIT_CONTAINER_PTR((NODE), udma_hmap_first(HMAP), MEMBER); \
		((((NODE) != OBJ_CONTAINING(NULL, (NODE), MEMBER)) || ((NODE) = NULL)) ? \
		INIT_CONTAINER_PTR(NEXT, udma_hmap_next(HMAP, &(NODE)->MEMBER), MEMBER), 1 : 0); \
		(NODE) = (NEXT))

static inline uint32_t calc_mask(uint32_t capacity)
{
	uint32_t mask = 0;
	uint32_t i = 0;

	while (mask < capacity) {
		mask |= 1U << i;
		i++;
	}

	return mask >> 1;
}

/*
 * When inserting more nodes than count, the lookup performance will be reduced.
 */
static inline int udma_hmap_init(struct udma_hmap *map, uint32_t count)
{
	map->count = 0;
	map->mask = calc_mask(count);
	map->bucket = (struct udma_hmap_head *)calloc(1, sizeof(struct udma_hmap_head) *
						      (map->mask + 1));
	if (map->bucket != NULL)
		return 0;

	return -1;
}

static inline void udma_hmap_destroy(struct udma_hmap *hmap)
{
	free(hmap->bucket);
	hmap->bucket = NULL;
}

#endif /* _UDMA_U_COMMON_H */
