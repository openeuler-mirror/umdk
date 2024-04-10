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

#include <arm_neon.h>
#include <limits.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/kernel.h>
#include "urma_provider.h"
#include "hns3_udma_u_abi.h"

#define UDMA_HW_PAGE_SHIFT	12
#define UDMA_HW_PAGE_SIZE	(1 << UDMA_HW_PAGE_SHIFT)
#define UDMA_HW_SGE_SIZE	16
#define UDMA_SQ_WQE_SHIFT	6
#define UDMA_HW_SGE_SHIFT	4
#define BIT_CNT_PER_BYTE	8
#define BIT_CNT_PER_LONG	(BIT_CNT_PER_BYTE * sizeof(uint64_t))
#define UDMA_DB_CFG0_OFFSET	0x0230
#define BITS_PER_UINT32		32
#define BITS_PER_LONG		64

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

#define udma_ilog32(n)		ilog32((uint32_t)(n) - 1)

#define check_types_match(expr1, expr2)		\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#define __bf_shf(x) (__builtin_ffsll(x) - 1)

#define BUILD_ASSERT(cond) ((void)sizeof(char[1 - 2 * !(cond)]))

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

#define udma_reg_enable(ptr, field)                                            \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                      \
		BUILD_ASSERT((((field) >> 32) / 32) ==                 \
			((((field) << 32) >> 32) / 32));                       \
		BUILD_ASSERT(((field) >> 32) == (((field) << 32) >> 32));      \
		*((uint32_t *)_ptr + ((field) >> 32) / 32) |=                  \
			htole32(BIT((((field) << 32) >> 32) % 32));            \
	})

#define udma_reg_clear(ptr, field)                                             \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                      \
		BUILD_ASSERT((((field) >> 32) / 32) ==                 \
			((((field) << 32) >> 32) / 32));                       \
		BUILD_ASSERT(((field) >> 32) >= (((field) << 32) >> 32));      \
		*((uint32_t *)_ptr + ((field) >> 32) / 32) &=                  \
			~htole32(GENMASK(((field) >> 32) % 32,                 \
			(((field) << 32) >> 32) % 32));                        \
	})

#define udma_reg_write_bool(ptr, field, val)                                   \
	({                                                                     \
		(val) ? udma_reg_enable(ptr, field) :                          \
			udma_reg_clear(ptr, field);                            \
	})

#define udma_reg_write(ptr, field, val)                                        \
	({                                                                     \
		const uint32_t _val = val;                                     \
		udma_reg_clear(ptr, field);                                    \
		*((uint32_t *)(ptr) + ((field) >> 32) / 32) |=                 \
			htole32(FIELD_PREP(GENMASK(((field) >> 32) % 32,       \
			(((field) << 32) >> 32) % 32), _val));                 \
	})

#define udma_reg_read(ptr, field)                                              \
	({                                                                     \
		const uint32_t *_ptr = (uint32_t *)(ptr);                      \
		BUILD_ASSERT((((field) >> 32) / 32) ==                 \
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

#define udma_to_device_barrier() asm volatile("dsb st" ::: "memory")
#define udma_from_device_barrier() asm volatile("dsb ld" ::: "memory")

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

struct udma_buf {
	void			*buf;
	uint32_t		length;
};

/* the sw doorbell type */
enum udma_db_type {
	UDMA_JFS_TYPE_DB,
	UDMA_JFR_TYPE_DB,
	UDMA_JETTY_TYPE_DB,
	UDMA_JFC_TYPE_DB,
	UDMA_DB_TYPE_NUM
};

struct udma_db_page {
	struct udma_db_page	*prev, *next;
	struct udma_buf		buf;
	uint32_t		num_db;
	uint32_t		use_cnt;
	uintptr_t		*bitmap;
	uint32_t		bitmap_cnt;
};

struct udma_u_db {
	uint32_t byte_4;
	uint32_t parameter;
};

enum {
	UDMA_SQ_DB,
	UDMA_RQ_DB,
	UDMA_SRQ_DB,
	UDMA_CQ_DB_PTR,
	UDMA_CQ_DB_NTR,
};

struct udma_wqe_data_seg {
	uint32_t len;
	uint32_t lkey;
	uint64_t addr;
};

#define UDMA_DB_FIELD_LOC(h, l) ((uint64_t)(h) << 32 | (l))
#define UDMA_DB_TAG UDMA_DB_FIELD_LOC(23, 0)
#define UDMA_DB_CMD UDMA_DB_FIELD_LOC(27, 24)
#define UDMA_DB_PI UDMA_DB_FIELD_LOC(47, 32)
#define UDMA_DB_SL UDMA_DB_FIELD_LOC(50, 48)
#define UDMA_DB_JFC_CI UDMA_DB_FIELD_LOC(55, 32)
#define UDMA_DB_JFC_NOTIFY UDMA_DB_FIELD_LOC(56, 56)
#define UDMA_DB_JFC_CMD_SN UDMA_DB_FIELD_LOC(58, 57)
#define UDMA_DB_CONS_IDX_M GENMASK(23, 0)
#define UDMA_DB_PROD_IDX_M GENMASK(23, 0)

static inline uint64_t roundup_pow_of_two(uint64_t n)
{
	return n == 1 ? 1 : 1ULL << ilog64(n - 1);
}

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1) & ~(align - 1);
}

#define udma_hw_page_align(x)	align(x, UDMA_HW_PAGE_SIZE)

static inline uint32_t to_udma_hem_entries_size(int count, int buf_shift)
{
	return udma_hw_page_align(count << buf_shift);
}

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
	*offset |= (command & HNS3_UDMA_MAP_COMMAND_MASK);
}

/* index value is offset[32:8] */
static inline void udma_mmap_set_index(unsigned long index, off_t *offset)
{
	*offset |= ((index & HNS3_UDMA_MAP_INDEX_MASK) << HNS3_UDMA_MAP_INDEX_SHIFT);
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

static inline struct udma_hmap_node *udma_hmap_first_with_hash(const struct udma_hmap *hmap,
							       uint32_t hash)
{
	struct udma_hmap_head *head = &hmap->bucket[hash & hmap->mask];
	struct udma_hmap_node *node;

	if (head == NULL)
		return NULL;

	node = head->next;

	while ((node != NULL) && node->hash != hash)
		node = node->next;

	return node;
}

static inline struct udma_hmap_node *udma_table_first_with_hash(const struct udma_hmap *hmap,
								pthread_rwlock_t *rwlock,
								uint32_t hash)
{
	struct udma_hmap_node *node;

	(void)pthread_rwlock_rdlock(rwlock);
	node = udma_hmap_first_with_hash(hmap, hash);
	(void)pthread_rwlock_unlock(rwlock);

	return node;
}

static inline bool udma_hmap_insert(struct udma_hmap *hmap, struct udma_hmap_node *node,
				  uint32_t hash)
{
	struct udma_hmap_head *head = &hmap->bucket[hash & hmap->mask];

	if (udma_hmap_first_with_hash(hmap, hash))
		return false;

	node->hash = hash;
	node->next = head->next;
	head->next = node;
	hmap->count++;
	return true;
}

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

#define HASH_OFFSET_B0 8
#define HASH_OFFSET_B1 16

#define HASH_SEED_1	0x85ebca6b
#define HASH_SEED_2	0xc2b2ae35
#define HASH_C1		0xcc9e2d51
#define HASH_C2		0x1b873593
#define HASH_N		0xe6546b64
#define HASH_R1		15
#define HASH_R2		13
#define HASH_M		5
#define EID_OFFSET	32

static inline uint32_t udma_mhash_finish(uint32_t hash_value)
{
	uint32_t ret_val = hash_value;

	ret_val ^= ret_val >> HASH_OFFSET_B1;
	ret_val *= HASH_SEED_1;
	ret_val ^= ret_val >> HASH_R2;
	ret_val *= HASH_SEED_2;
	ret_val ^= ret_val >> HASH_OFFSET_B1;

	return ret_val;
}

static inline uint32_t udma_hash_finish(uint32_t hash_value, uint32_t final)
{
	return udma_mhash_finish(hash_value ^ final);
}

static inline uint32_t udma_hash_rot(uint32_t a, uint32_t b)
{
	uint32_t base = 32;

	return (a << b) | (a >> (base - b));
}

static inline uint32_t udma_mhash_add__(uint32_t hash_value, uint32_t data)
{
	/* zero-valued 'data' will not change the 'hash' value */
	uint32_t data_val = data;

	if (data == 0)
		return hash_value;

	data_val *= HASH_C1;
	data_val = udma_hash_rot(data_val, HASH_R1);
	data_val *= HASH_C2;

	return hash_value ^ data_val;
}

static inline uint32_t udma_mhash_add(uint32_t hash_value, uint32_t data)
{
	uint32_t local_hash_value = hash_value;

	local_hash_value = udma_mhash_add__(local_hash_value, data);
	local_hash_value = udma_hash_rot(local_hash_value, HASH_R2);
	return local_hash_value * HASH_M + HASH_N;
}

static inline uint32_t udma_hash_add(uint32_t hash_value, uint32_t data)
{
	return udma_mhash_add(hash_value, data);
}

static inline uint32_t udma_hash_add64(uint32_t hash_value, uint64_t data)
{
	return udma_hash_add(udma_hash_add(hash_value, (uint32_t)data),
			     data >> BITS_PER_UINT32);
}

static inline uint32_t udma_hash_uint64_base(const uint64_t key,
					     const uint32_t base)
{
	return udma_hash_finish(udma_hash_add64(base, key), HASH_OFFSET_B0);
}

static inline uint32_t udma_hash_uint64(const uint64_t key)
{
	return udma_hash_uint64_base(key, 0);
}

static inline uint32_t udma_get_tgt_hash(const urma_jetty_id_t *id)
{
	uint64_t idx;

	idx = id->eid.in4.addr;
	idx = idx << EID_OFFSET;
	idx |= id->id;

	return udma_hash_uint64(idx);
}

void udma_hmap_remove(struct udma_hmap *hmap, const struct udma_hmap_node *node);

uint64_t *udma_bitmap_alloc(uint32_t n_bits, uint32_t *bitmap_cnt);
void udma_bitmap_free(uint64_t *bitmap);
int udma_bitmap_use_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			uint32_t n_bits, uint32_t *idx);
void udma_bitmap_free_idx(uint64_t *bitmap, uint32_t bitmap_cnt,
			  uint32_t idx);

#endif /* _UDMA_U_COMMON_H */
