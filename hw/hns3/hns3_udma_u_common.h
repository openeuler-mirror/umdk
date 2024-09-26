/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _HNS3_UDMA_U_COMMON_H
#define _HNS3_UDMA_U_COMMON_H

#include <unistd.h>
#include <arm_neon.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/kernel.h>
#include "urma_provider.h"
#include "hns3_udma_u_abi.h"

#define HNS3_UDMA_HW_PAGE_SHIFT		12
#define HNS3_UDMA_HW_PAGE_SIZE		(1 << HNS3_UDMA_HW_PAGE_SHIFT)
#define HNS3_UDMA_HW_SGE_SIZE		16
#define HNS3_UDMA_SQ_WQE_SHIFT		6
#define HNS3_UDMA_HW_SGE_SHIFT		4
#define BIT_CNT_PER_BYTE		8
#define BIT_CNT_PER_LONG		(BIT_CNT_PER_BYTE * sizeof(uint64_t))
#define HNS3_UDMA_DB_CFG0_OFFSET	0x0230
#define BITS_PER_UINT32			32
#define BITS_PER_LONG			64

#define min(x, y) ((x) < (y) ? (x) : (y))

/* get the structure object from the pointer of the given field by struct type */
#define CONTAINER_OF_FIELD(field_ptr, struct_type, field) \
	((struct_type *)(void *)((char *)(field_ptr) - offsetof(struct_type, field)))

#if INT_MAX >= 2147483647
#define builtin_ilog32_nz(v) \
	(((int)sizeof(uint32_t) * CHAR_BIT) - __builtin_clz(v))
#elif LONG_MAX >= 2147483647L
#define builtin_ilog32_nz(v) \
	(((int)sizeof(uint32_t) * CHAR_BIT) - __builtin_clzl(v))
#endif

#if INT_MAX >= 9223372036854775807LL
#define builtin_ilog64_nz(v) \
	(((int)sizeof(uint32_t) * CHAR_BIT) - __builtin_clz(v))
#elif LONG_MAX >= 9223372036854775807LL
#define builtin_ilog64_nz(v) \
	(((int)sizeof(uint64_t) * CHAR_BIT) - __builtin_clzl(v))
#endif

#define ilog32(_v) (builtin_ilog32_nz(_v)&-!!(_v))
#define ilog64(_v) (builtin_ilog64_nz(_v)&-!!(_v))

#define hns3_udma_ilog32(n)		ilog32((uint32_t)(n) - 1)

#define check_types_match(expr1, expr2)		\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#define __bf_shf(x) (__builtin_ffsll(x) - 1)

#define BUILD_ASSERT(cond) \
	do { (void)sizeof(char[1 - 2 * !(cond)]); } while (0)

#define BUILD_ASSERT_OR_ZERO(cond) \
	(sizeof(char [1 - 2 * !(cond)]) - 1)

#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

#define FIELD_PREP(_mask, _val)                                                \
	({                                                                     \
		((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);          \
	})

#define BIT(nr) (1UL << (nr))

#define FIELD_GET(_mask, _reg)						       \
	({								       \
		(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask));        \
	})

#define hns3_udma_reg_enable(ptr, field)                                       \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                      \
		BUILD_ASSERT_OR_ZERO((((field) >> 32) / 32) ==                 \
			((((field) << 32) >> 32) / 32));                       \
		BUILD_ASSERT(((field) >> 32) == (((field) << 32) >> 32));      \
		*((uint32_t *)_ptr + ((field) >> 32) / 32) |=                  \
			htole32(BIT((((field) << 32) >> 32) % 32));            \
	})

#define hns3_udma_reg_clear(ptr, field)                                        \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                      \
		BUILD_ASSERT_OR_ZERO((((field) >> 32) / 32) ==                 \
			((((field) << 32) >> 32) / 32));                       \
		BUILD_ASSERT(((field) >> 32) >= (((field) << 32) >> 32));      \
		*((uint32_t *)_ptr + ((field) >> 32) / 32) &=                  \
			~htole32(GENMASK(((field) >> 32) % 32,                 \
			(((field) << 32) >> 32) % 32));                        \
	})

#define hns3_udma_reg_write_bool(ptr, field, val)                              \
	({                                                                     \
		(val) ? hns3_udma_reg_enable(ptr, field) :                     \
			hns3_udma_reg_clear(ptr, field);                       \
	})

#define hns3_udma_reg_write(ptr, field, val)                                   \
	({                                                                     \
		const uint32_t _val = val;                                     \
		hns3_udma_reg_clear(ptr, field);                               \
		*((uint32_t *)(ptr) + ((field) >> 32) / 32) |=                 \
			htole32(FIELD_PREP(GENMASK(((field) >> 32) % 32,       \
			(((field) << 32) >> 32) % 32), _val));                 \
	})

#define hns3_udma_reg_read(ptr, field)                                         \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                      \
		BUILD_ASSERT_OR_ZERO((((field) >> 32) / 32) ==                 \
			((((field) << 32) >> 32) / 32));                       \
		BUILD_ASSERT(((field) >> 32) >= (((field) << 32) >> 32));      \
		FIELD_GET(GENMASK(((field) >> 32) % 32,                        \
			(((field) << 32) >> 32) % 32),                         \
			le32toh(*((uint32_t *)_ptr + ((field) >> 32) / 32)));  \
	})

#ifndef container_of
#define container_off(containing_type, member)	\
	offsetof(containing_type, member)
#define container_of(member_ptr, containing_type, member)		\
	 ((containing_type *)						\
	  ((char *)(member_ptr)						\
	   - container_off(containing_type, member))			\
	  + check_types_match(*(member_ptr), ((containing_type *)0)->member))
#endif

#define hns3_udma_to_device_barrier() {asm volatile("dsb st" ::: "memory"); }
#define hns3_udma_from_device_barrier() {asm volatile("dsb ld" ::: "memory"); }

#define MMIO_MEMCPY_X64_LEN 64
static inline void _mmio_memcpy_x64_64b(void *dest, const void *src)
{
	vst4q_u64((uint64_t *)dest, vld4q_u64((const uint64_t *)src));
}

static inline void _mmio_memcpy_x64(void *dest, const void *src, size_t bytecnt)
{
	do {
		_mmio_memcpy_x64_64b(dest, src);
		bytecnt -= sizeof(uint64x2x4_t);
		src += sizeof(uint64x2x4_t);
		dest += sizeof(uint64x2x4_t);
	} while (bytecnt > 0);
}

static inline void mmio_memcpy_x64(void *dest, const void *src, size_t bytecount)
{
	if (__builtin_constant_p((bytecount) == MMIO_MEMCPY_X64_LEN))
		_mmio_memcpy_x64_64b((dest), (src));
	else
		_mmio_memcpy_x64((dest), (src), (bytecount));
}

struct hns3_udma_buf {
	void			*buf;
	uint32_t		length;
};

/* the sw doorbell type */
enum hns3_udma_db_type {
	HNS3_UDMA_JFS_TYPE_DB,
	HNS3_UDMA_JFR_TYPE_DB,
	HNS3_UDMA_JETTY_TYPE_DB,
	HNS3_UDMA_JFC_TYPE_DB,
	HNS3_UDMA_DB_TYPE_NUM
};

struct hns3_udma_db_page {
	struct hns3_udma_db_page	*prev, *next;
	struct hns3_udma_buf		buf;
	uint32_t			num_db;
	uint32_t			use_cnt;
	uintptr_t			*bitmap;
	uint32_t			bitmap_cnt;
};

struct hns3_udma_u_db {
	uint32_t byte_4;
	uint32_t parameter;
};

enum {
	HNS3_UDMA_SQ_DB,
	HNS3_UDMA_RQ_DB,
	HNS3_UDMA_SRQ_DB,
	HNS3_UDMA_CQ_DB_PTR,
	HNS3_UDMA_CQ_DB_NTR,
};

struct hns3_udma_wqe_data_seg {
	uint32_t len;
	uint32_t lkey;
	uint64_t addr;
};

#define HNS3_UDMA_DB_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))
#define HNS3_UDMA_DB_TAG HNS3_UDMA_DB_FIELD_LOC(23, 0)
#define HNS3_UDMA_DB_CMD HNS3_UDMA_DB_FIELD_LOC(27, 24)
#define HNS3_UDMA_DB_PI HNS3_UDMA_DB_FIELD_LOC(47, 32)
#define HNS3_UDMA_DB_SL HNS3_UDMA_DB_FIELD_LOC(50, 48)
#define HNS3_UDMA_DB_JFC_CI HNS3_UDMA_DB_FIELD_LOC(55, 32)
#define HNS3_UDMA_DB_JFC_NOTIFY HNS3_UDMA_DB_FIELD_LOC(56, 56)
#define HNS3_UDMA_DB_JFC_CMD_SN HNS3_UDMA_DB_FIELD_LOC(58, 57)
#define HNS3_UDMA_DB_CONS_IDX_M GENMASK(23, 0)
#define HNS3_UDMA_DB_PROD_IDX_M GENMASK(23, 0)

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

static inline uint64_t roundup_pow_of_two(uint64_t n)
{
	return n == 1 ? 1 : 1ULL << ilog64(n - 1);
}

#define hns3_udma_hw_page_align(x)	align(x, sysconf(_SC_PAGESIZE))

static inline uint32_t to_hns3_udma_hem_entries_size(int count, int buf_shift)
{
	return hns3_udma_hw_page_align(count << buf_shift);
}

static inline void hns3_udma_set_udata(urma_cmd_udrv_priv_t *udrv_data, void *in_addr,
				       uint32_t in_len, void *out_addr,
				       uint32_t out_len)
{
	udrv_data->in_addr = (uint64_t)in_addr;
	udrv_data->in_len = in_len;
	udrv_data->out_addr = (uint64_t)out_addr;
	udrv_data->out_len = out_len;
}

/* command value is offset[7:0] */
static inline void hns3_udma_mmap_set_command(int command, off_t *offset)
{
	*offset |= (command & HNS3_UDMA_MAP_COMMAND_MASK);
}

/* index value is offset[32:8] */
static inline void hns3_udma_mmap_set_index(unsigned long index, off_t *offset)
{
	*offset |= ((index & HNS3_UDMA_MAP_INDEX_MASK) << HNS3_UDMA_MAP_INDEX_SHIFT);
}

static inline off_t get_mmap_offset(uint32_t idx, int page_size, int cmd)
{
	off_t offset = 0;

	hns3_udma_mmap_set_command(cmd, &offset);
	hns3_udma_mmap_set_index(idx, &offset);

	return offset * page_size;
}

/*
 * Hmap uses list to resolve hash conflicts in a bucket
 * NOT multi-thread safe in the current version
 */
struct hns3_udma_hmap_node {
	struct hns3_udma_hmap_node	*next;
	uint32_t		hash;
};

struct hns3_udma_hmap_head {
	struct hns3_udma_hmap_node	*next;
};

struct hns3_udma_hmap {
	uint32_t		count;
	uint32_t		mask;
	struct hns3_udma_hmap_head	*bucket;
};

void hns3_udma_hmap_remove(struct hns3_udma_hmap *hmap, const struct hns3_udma_hmap_node *node);

static inline struct hns3_udma_hmap_node *hns3_udma_hmap_first_with_hash(const struct hns3_udma_hmap *hmap,
									 uint32_t hash)
{
	struct hns3_udma_hmap_head *head = &hmap->bucket[hash & hmap->mask];
	struct hns3_udma_hmap_node *node;

	node = head->next;

	while ((node != NULL) && node->hash != hash)
		node = node->next;

	return node;
}

static inline struct hns3_udma_hmap_node *hns3_udma_table_first_with_hash(const struct hns3_udma_hmap *hmap,
									  pthread_rwlock_t *rwlock,
									  uint32_t hash)
{
	struct hns3_udma_hmap_node *node;

	(void)pthread_rwlock_rdlock(rwlock);
	node = hns3_udma_hmap_first_with_hash(hmap, hash);
	(void)pthread_rwlock_unlock(rwlock);

	return node;
}

static inline bool hns3_udma_hmap_insert(struct hns3_udma_hmap *hmap, struct hns3_udma_hmap_node *node,
					 uint32_t hash)
{
	struct hns3_udma_hmap_head *head = &hmap->bucket[hash & hmap->mask];

	if (hns3_udma_hmap_first_with_hash(hmap, hash))
		return false;

	node->hash = hash;
	node->next = head->next;
	head->next = node;
	hmap->count++;
	return true;
}

static inline struct hns3_udma_hmap_node *hns3_udma_hmap_first_from_idx(const struct hns3_udma_hmap *hmap,
									uint32_t idx)
{
	struct hns3_udma_hmap_node *node = NULL;

	if (hmap == NULL || hmap->bucket == NULL)
		return NULL;

	for (uint32_t i = idx; i < hmap->mask + 1; i++) {
		node = hmap->bucket[i].next;
		if (node != NULL)
			break;
	}
	return node;
}

static inline struct hns3_udma_hmap_node *hns3_udma_hmap_first(const struct hns3_udma_hmap *hmap)
{
	return hns3_udma_hmap_first_from_idx(hmap, 0);
}

static inline struct hns3_udma_hmap_node *hns3_udma_hmap_next(const struct hns3_udma_hmap *hmap,
							      const struct hns3_udma_hmap_node *pre_node)
{
	struct hns3_udma_hmap_node *node = pre_node->next;

	if (node != NULL)
		return node;

	return hns3_udma_hmap_first_from_idx(hmap, (pre_node->hash & hmap->mask) + 1);
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
	for (INIT_CONTAINER_PTR(NODE, hns3_udma_hmap_first(TABLE), MEMBER); \
		(((NODE) != OBJ_CONTAINING(NULL, (NODE), MEMBER)) || ((NODE) = NULL)); \
		ASSIGN_CONTAINER_PTR((NODE), hns3_udma_hmap_next(TABLE, &(NODE)->MEMBER), MEMBER))

#define HMAP_FOR_EACH_SAFE(NODE, NEXT, MEMBER, HMAP) \
	for (INIT_CONTAINER_PTR((NODE), hns3_udma_hmap_first(HMAP), MEMBER); \
		((((NODE) != OBJ_CONTAINING(NULL, (NODE), MEMBER)) || ((NODE) = NULL)) ? \
		INIT_CONTAINER_PTR(NEXT, hns3_udma_hmap_next(HMAP, &(NODE)->MEMBER), MEMBER), 1 : 0); \
		(NODE) = (NEXT))

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))

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
static inline int hns3_udma_hmap_init(struct hns3_udma_hmap *map, uint32_t count)
{
	map->count = 0;
	map->mask = calc_mask(count);
	map->bucket = (struct hns3_udma_hmap_head *)calloc(1, sizeof(struct hns3_udma_hmap_head) *
							   (map->mask + 1));
	if (map->bucket != NULL)
		return 0;

	return -1;
}

static inline void hns3_udma_hmap_destroy(struct hns3_udma_hmap *hmap)
{
	free(hmap->bucket);
	hmap->bucket = NULL;
}

#define EID_OFFSET	32

uint64_t *hns3_udma_bitmap_alloc(uint32_t n_bits, uint32_t *bitmap_cnt);
void hns3_udma_bitmap_free(uint64_t *bitmap);
int hns3_udma_bitmap_use_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			     uint32_t n_bits, uint32_t *idx);
void hns3_udma_bitmap_free_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			       uint32_t idx);

#endif /* _HNS3_UDMA_U_COMMON_H */
