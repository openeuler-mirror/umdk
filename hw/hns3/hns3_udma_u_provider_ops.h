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

#ifndef _UDMA_PROVIDER_OPS_H
#define _UDMA_PROVIDER_OPS_H

#include <stdatomic.h>
#include <linux/types.h>
#include "urma_provider.h"
#include "urma_log.h"
#include "hns3_udma_u_common.h"

#ifndef PCI_VENDOR_ID_HUAWEI
#define PCI_VENDOR_ID_HUAWEI			0x19E5
#endif

#define HNS3_DEV_ID_UDMA_OVER_UBL		0xA260
#define HNS3_DEV_ID_UDMA			0xA261

#define UDMA_JFR_TABLE_SIZE			8
#define UDMA_JETTY_TABLE_SIZE			8
#define UDMA_DCA_BITS_PER_STATUS		1
#define DCA_BITS_HALF 2

#define MAX_TP_CNT				0x8000
#define ALIGN_OVER_BOUND(val, align_size)\
	(((val + align_size - 1) & ~(align_size - 1)) < val ? false : true)

#define ALIGN_OVER_UNIT_SIZE(val, align_size)\
	((DIV_ROUND_UP(val, align_size) * align_size) < val ? false : true)

#define list_entry(LINK, TYPE, MEMBER) \
	((TYPE *)((char *)(LINK)-(uint64_t)(&((TYPE *)0)->MEMBER)))

#define list_tail(LIST, TYPE, MEMBER)		\
	list_entry((LIST)->prev, TYPE, MEMBER)

#define list_next_entry(POS, MEMBER) \
	list_entry((POS)->MEMBER.next, typeof(*(POS)), MEMBER)

#define list_first_entry(PTR, TYPE, MEMBER) \
	list_entry((PTR)->next, TYPE, MEMBER)

#define list_for_each_entry(POS, HEAD, MEMBER)				\
	for ((POS) = list_first_entry(HEAD, typeof(*(POS)), MEMBER);	\
	     &(POS)->MEMBER != (HEAD);					\
	     (POS) = list_next_entry(POS, MEMBER))

#define min_t(t, a, b) \
	({ \
		t _ta = (a); \
		t _tb = (b); \
		_ta > _tb ? _tb : _ta; \
	})

extern urma_provider_ops_t g_udma_u_provider_ops;

struct udma_dca_context_attr {
	uint64_t comp_mask;
	uint32_t dca_prime_qps;
	uint32_t dca_unit_size;
	uint64_t dca_max_size;
	uint64_t dca_min_size;
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct udma_u_dca_ctx {
	struct list_head	mem_list;
	pthread_spinlock_t	lock;
	uint32_t		mem_cnt;
	uint32_t		unit_size;
	uint64_t		max_size;
	uint64_t		min_size;
	uint64_t		curr_size;
	uint32_t		max_qps;
	uint32_t		status_size;
	atomic_ulong		*buf_status;
	atomic_ulong		*sync_status;
};

#define UDMA_JETTY_TABLE_SHIFT 5
#define UDMA_JETTY_TABLE_NUM (1 << UDMA_JETTY_TABLE_SHIFT)

struct common_jetty {
	bool is_jetty;
	void *jetty;
};

struct udma_u_context {
	urma_context_t		urma_ctx;
	void			*uar;
	uint64_t		db_addr;
	uint32_t		max_jfc_cqe;

	uint32_t		cqe_size;
	uint32_t		page_size;

	struct udma_db_page	*db_list[UDMA_DB_TYPE_NUM];
	pthread_mutex_t		db_list_mutex;

	uint32_t		max_jfr_wr;
	uint32_t		max_jfr_sge;
	uint32_t		max_jfs_wr;
	uint32_t		max_jfs_sge;

	uint32_t		num_qps_shift;
	uint32_t		num_jfs_shift;
	uint32_t		num_jfr_shift;
	uint32_t		num_jetty_shift;

	pthread_rwlock_t	jfr_table_lock;
	struct udma_hmap	jfr_table;
	pthread_rwlock_t	jfs_qp_table_lock;
	struct udma_hmap	jfs_qp_table;
	pthread_rwlock_t	jetty_table_lock;
	struct {
		struct common_jetty	*table;
		int			refcnt;
	} jetty_table[UDMA_JETTY_TABLE_NUM];
	uint32_t		jettys_in_tbl_shift;
	uint32_t		jettys_in_tbl;

	uint8_t			poe_ch_num;
	void			*reset_state;
	struct udma_u_dca_ctx	dca_ctx;
	uint8_t			chip_id;
	uint8_t			die_id;
	uint8_t			func_id;
};

struct udma_reset_state {
	uint32_t is_reset;
};

static inline struct udma_u_context *to_udma_ctx(urma_context_t *ctx)
{
	return container_of(ctx, struct udma_u_context, urma_ctx);
}

static inline void udma_write64(struct udma_u_context *ctx,
				uint64_t *dest, uint64_t *val)
{
	struct udma_reset_state *state = (struct udma_reset_state *)ctx->reset_state;

	if (state && state->is_reset)
		return;

	atomic_store_explicit((_Atomic(uint64_t) *)dest,
			      (uint64_t)(*val), memory_order_relaxed);
}

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void list_del(struct list_head *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = NULL;
	entry->prev = NULL;
}

static inline void __list_add(struct list_head *new_node,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new_node;
	new_node->next = next;
	new_node->prev = prev;
	prev->next = new_node;
}

static inline void list_add_tail(struct list_head *head, struct list_head *tail)
{
	__list_add(tail, head->prev, head);
}

#endif /* _UDMA_PROVIDER_OPS_H */
