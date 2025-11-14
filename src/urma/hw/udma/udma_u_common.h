/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_COMMON_H__
#define __UDMA_U_COMMON_H__

#include <unistd.h>
#include <stdatomic.h>
#include <arm_neon.h>
#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "urma_provider.h"
#include "udma_u_ctl.h"
#include "udma_u_abi.h"
#include "udma_u_log.h"

#define UDMA_JFS_WQEBB 64
#define UDMA_JFR_WQEBB 16U
#define UDMA_MIN_JFS_WQEBB_CNT 64
#define UDMA_MIN_CCU_WQEBB_CNT 16
#define UDMA_MAX_JFS_WQEBB_CNT 32768
#define UDMA_HUGEPAGE_SIZE 2097152
#define UDMA_HW_PAGE_SIZE 4096U
#define UDMA_BITS_PER_LONG 64
#define UDMA_BITS_PER_LONG_SHIFT 6
#define UDMA_JFS_WQEBB_SHIFT 6
#define UDMA_SGE_SIZE 16

#define UDMA_JFC_DB_OFFSET 0
#define min(x, y) ((x) < (y) ? (x) : (y))
#define RTE_SET_USED(x) (void)(x)

struct udma_u_doorbell {
	uint32_t id;
	enum db_mmap_type type;
	void volatile *addr;
};

struct udma_u_buf {
	void *buf;
	uint32_t length;
};

struct udma_u_db_page {
	struct udma_u_db_page *prev, *next;
	struct udma_u_buf buf;
	uint32_t num_db;
	uint32_t use_cnt;
	uintptr_t *bitmap;
	uint32_t bitmap_cnt;
};

struct udma_u_hugepage_priv {
	void *va_base;
	uint32_t va_len;
	uint32_t left_va_offset;
	uint32_t left_va_len;
	uint32_t refcnt;
	struct udma_u_hugepage_priv *pre;
	struct udma_u_hugepage_priv *next;
};

struct udma_u_hugepage {
	void *va_start;
	uint32_t va_len;
	struct udma_u_hugepage_priv *priv;
};

/* 32 */
#define UDMA_JETTY_TABLE_NUM 1 << 5

struct udma_u_context {
	urma_context_t		urma_ctx;
	void			*db_addr;
	uint32_t		page_size;
	struct udma_u_db_page	*db_list[UDMA_DB_TYPE_NUM];
	pthread_mutex_t		db_list_mutex;
	struct udma_u_doorbell	db;
	uint8_t			cqe_size;
	bool			dwqe_enable;
	bool			reduce_enable;
	uint32_t		ue_id;
	uint32_t		chip_id;
	uint32_t		die_id;
	bool			dump_aux_info;
	uint32_t		jfr_sge;
	bool			hugepage_enable;
	pthread_mutex_t		hugepage_lock;
	struct udma_u_hugepage_priv *hugepage_list;
	struct {
		struct udma_u_jetty	**jetty_array;
		int			refcnt;
	} jetty_table[UDMA_JETTY_TABLE_NUM];
	struct {
		struct udma_u_jfr	**jfr_array;
		int			refcnt;
	} jfr_table[UDMA_JETTY_TABLE_NUM];
	pthread_rwlock_t	jetty_table_lock;
	pthread_rwlock_t	jfr_table_lock;
	uint32_t		jettys_in_tbl_shift;
	uint32_t		jettys_in_tbl;
};

struct udma_u_jetty_queue {
	struct udma_u_context *ctx;
	/* Command queue */
	void *qbuf; /* Base virtual address of command buffer */
	void *qbuf_end;
	uint32_t qbuf_size; /* Command buffer size */
	void *qbuf_curr; /* Virtual address to store the current command */
	uint32_t pi; /* Producer index of a queue. */
	uint32_t ci; /* Consumer index of a queue */
	uint32_t idx; /* JETTY ID */
	struct udma_u_doorbell db; /* doorbell info */
	/* Wqe or cqe base block */
	uint32_t baseblk_shift;
	uint32_t baseblk_cnt;
	uint32_t baseblk_mask;
	uintptr_t *wrid; /* Work Request ID */
	pthread_spinlock_t lock; /* protect the @qbuf, @qbuf_curr, @wrid, @pi, and @ci. */
	uint32_t max_inline_size;
	void *dwqe_addr;
	struct udma_u_target_jetty *tjetty;
	urma_transport_mode_t trans_mode;
	uint32_t sqe_bb_cnt;
	uint32_t max_sge_num;
	bool flush_flag;
	uint32_t old_entry_idx;
	bool lock_free;
	bool cstm; /* sq ctrl flag */
	struct udma_u_hugepage *hugepage;
};

struct udma_wqe_sge {
	uint32_t length;
	uint32_t token_id;
	uint64_t va;
};

struct udma_u_jfr_idx_que {
	struct udma_u_buf buf;
	uint32_t entry_shift;
	uint64_t *bitmap;
	uint32_t bitmap_cnt;
	bool cstm;
};

struct udma_u_jfr {
	urma_jfr_t base;
	struct udma_u_jetty_queue rq;
	struct udma_u_jfr_idx_que idx_que;
	uint32_t wqe_cnt;
	uint32_t wqe_shift;
	uint32_t max_sge;
	uint32_t cap_flags;
	bool swdb_cstm;
	uint32_t *sw_db;
	pthread_spinlock_t lock;
	bool lock_free;
	bool *long_sleeptime;
};

struct udma_u_jfs {
	urma_jfs_t base;
	struct udma_u_jetty_queue sq;
	bool pi_type;
	uint32_t jfs_type;
};

struct udma_u_jetty {
	urma_jetty_t base;
	struct udma_u_jetty_queue sq;
	struct udma_u_jfr *jfr;
	struct udma_u_jetty_grp *jetty_grp;
	uint32_t jetty_type;
	bool pi_type;
};

struct udma_u_jfc {
	urma_jfc_t base;
	struct udma_u_jetty_queue cq;
	uint32_t *sw_db;
	uint32_t arm_sn;
	uint32_t mode;
	uint32_t cq_shift;
};

struct udma_u_tid {
	urma_token_id_t base;
	uint32_t tid;
};

struct udma_u_jetty_grp {
	urma_jetty_grp_t base;
	uint32_t jetty_cnt;
	pthread_spinlock_t lock;
};

struct udma_u_segment {
	urma_target_seg_t urma_tseg;
	urma_token_t token_value;
	bool token_value_valid;
	uint64_t len;                 /* specify the length of the segment to be registered */
	uint64_t va;                  /* specify the address of the segment to be registered */
	uint32_t tid;
};

struct udma_u_target_jetty {
	urma_target_jetty_t urma_tjetty;
	urma_eid_t le_eid;
	uint32_t token_value;
	bool token_value_valid;
};

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

#define ilog32(_v) ((uint32_t)builtin_ilog32_nz(_v)&((_v) == 0UL ? 0UL : 0xFFFFFFFFUL))
#define ilog64(_v) ((uint64_t)builtin_ilog64_nz(_v)&((_v) == 0ULL ? 0ULL : 0xFFFFFFFFFFFFFFFFULL))

#define udma_u_ilog32(n) ilog32((uint32_t)(n) - 1)

#define check_types_match(expr1, expr2)		\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (UDMA_BITS_PER_LONG - 1 - (h))))

#define BIT(nr) (1UL << (nr))

#ifndef container_of
#define container_off(containing_type, member)                                 \
	offsetof(containing_type, member)
#define container_of(member_ptr, containing_type, member)                      \
	 ((containing_type *)                                                  \
	  ((void *)(member_ptr)                                                \
	   - container_off(containing_type, member))                           \
	  + (uint8_t)check_types_match(*(member_ptr), ((containing_type *)0)->member))
#endif

#define udma_to_device_barrier() {asm volatile("dmb st" ::: "memory"); }
#define udma_from_device_barrier() {asm volatile("dmb ld" ::: "memory"); }

#define ARRAY_SIZE(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))

static inline void udma_u_set_udata(urma_cmd_udrv_priv_t *udrv_data,
				    void *in_addr, uint32_t in_len,
				    void *out_addr, uint32_t out_len)
{
	udrv_data->in_addr = (uint64_t)in_addr;
	udrv_data->in_len = in_len;
	udrv_data->out_addr = (uint64_t)out_addr;
	udrv_data->out_len = out_len;
}

static inline uint64_t roundup_pow_of_two(uint64_t n)
{
	return n == 1ULL ? 1ULL : 1ULL << ilog64(n - 1ULL);
}

static inline unsigned long align(unsigned long val, unsigned long align)
{
	return (val + align - 1UL) & ~(align - 1UL);
}

static inline void mmio_memcpy_x64(uint64_t *dest, uint64_t *val)
{
	vst4q_u64(dest, vld4q_u64(val));
}

static inline struct udma_u_context *to_udma_u_ctx(urma_context_t *ctx)
{
	return container_of(ctx, struct udma_u_context, urma_ctx);
}

static inline struct udma_u_jfr *to_udma_u_jfr(urma_jfr_t *jfr)
{
	return container_of(jfr, struct udma_u_jfr, base);
}

/* index value is offset[32:8] */
static inline void udma_mmap_set_index(unsigned long index, off_t *offset)
{
	unsigned long offset_u = (unsigned long)*offset;
	offset_u |= ((index & (unsigned long)MAP_INDEX_MASK) << MAP_INDEX_SHIFT);
	*offset = (off_t)offset_u;
}

/* command value is offset[7:0] */
static inline void udma_mmap_set_command(uint32_t command, off_t *offset)
{
	uint32_t offset_u = (uint32_t)*offset;
	offset_u |= (command & (uint32_t)MAP_COMMAND_MASK);
	*offset = (off_t)offset_u;
}

static inline off_t get_mmap_offset(uint32_t idx, int page_size, uint32_t cmd)
{
	off_t offset = 0;

	udma_mmap_set_command(cmd, &offset);
	udma_mmap_set_index(idx, &offset);

	return offset * page_size;
}

static inline struct udma_u_jfs *to_udma_u_jfs(urma_jfs_t *jfs)
{
	return container_of(jfs, struct udma_u_jfs, base);
}

static inline struct udma_u_jetty *to_udma_u_jetty(urma_jetty_t *jetty)
{
	return container_of(jetty, struct udma_u_jetty, base);
}

static inline struct udma_u_jfc *to_udma_u_jfc(urma_jfc_t *jfc)
{
	return container_of(jfc, struct udma_u_jfc, base);
}

static inline struct udma_u_target_jetty *
to_udma_u_target_jetty(urma_target_jetty_t *target_jetty)
{
	return container_of(target_jetty, struct udma_u_target_jetty, urma_tjetty);
}

static inline void *udma_inc_ptr_wrap(uint8_t *ptr, uint32_t inc,
				      uint8_t *qbuf, uint8_t *qbuf_end)
{
	return ((ptr + inc) < qbuf_end) ?
		(ptr + inc) : qbuf + (ptr + inc - qbuf_end);
}

static inline uint32_t align_power2(uint32_t n)
{
	uint32_t res = 0;

	while ((1U << res) < n)
		res++;

	return res;
}

static inline struct udma_u_tid *to_udma_u_tid(urma_token_id_t *key_id)
{
	return container_of(key_id, struct udma_u_tid, base);
}

static inline struct udma_u_jetty_grp *
to_udma_u_jetty_grp(urma_jetty_grp_t *jetty_grp)
{
	return container_of(jetty_grp, struct udma_u_jetty_grp, base);
}

static inline struct udma_u_jfr *
to_udma_u_jfr_from_queue(struct udma_u_jetty_queue *queue)
{
	return container_of(queue, struct udma_u_jfr, rq);
}

static inline struct udma_u_jetty *
to_udma_u_jetty_from_queue(struct udma_u_jetty_queue *queue)
{
	return container_of(queue, struct udma_u_jetty, sq);
}

static inline struct udma_u_segment *to_udma_u_seg(urma_target_seg_t *seg)
{
	return container_of(seg, struct udma_u_segment, urma_tseg);
}

static inline void udma_u_write64(uint64_t *dest, uint64_t *val)
{
	atomic_store_explicit((_Atomic(uint64_t) *)(void *)dest,
			      (uint64_t)(*val), memory_order_relaxed);
}

static inline uint32_t calc_mask(uint32_t capacity)
{
	return ((uint32_t)1 << ilog32(capacity)) - (uint32_t)1;
}

static inline void udma_u_swap_endian128(uint8_t *src, uint8_t *dst)
{
	*(uint64_t *)(dst + sizeof(uint64_t)) = __builtin_bswap64(*(uint64_t *)(src));
	*(uint64_t *)(dst) = __builtin_bswap64(*(uint64_t *)(src + sizeof(uint64_t)));
}

static inline struct udma_u_jfs_wr_ex *to_udma_u_jfs_wr_ex(urma_jfs_wr_t *urma_wr)
{
	return container_of(urma_wr, struct udma_u_jfs_wr_ex, wr);
}

typedef int (*udma_u_user_ctl_ops)(urma_context_t *ctx, urma_user_ctl_in_t *in,
				   urma_user_ctl_out_t *out, enum udma_u_user_ctl_opcode op);

bool udma_u_user_ctl_check_param(uint64_t addr, uint32_t in_len, uint32_t len,
				 enum udma_u_user_ctl_opcode opcode);
int udma_u_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in,
		    urma_user_ctl_out_t *out);

#endif /* __UDMA_U_COMMON_H__ */
