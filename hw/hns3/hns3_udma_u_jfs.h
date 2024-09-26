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

#ifndef _HNS3_UDMA_JFS_H
#define _HNS3_UDMA_JFS_H

#include "urma_types.h"
#include "urma_provider.h"
#include "hns3_udma_u_buf.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"

#define HNS3_UDMA_SIZE_CONNECT_NODE_TABLE 99
#define HNS3_UDMA_JFS_QP_TABLE_SIZE 99
#define HNS3_UDMA_FLUSH_STATU_ERR 1
#define GID_H_SHIFT 12
#define NOTIFY_OFFSET_4B_ALIGN 4

struct connect_node_table {
	pthread_rwlock_t	rwlock;
	struct hns3_udma_hmap	hmap;
};

struct hns3_udma_jfs_wqe {
	/* byte4 */
	uint32_t		opcode : 5;
	uint32_t		db_sl_l : 2;
	uint32_t		owner : 1;
	uint32_t		cqe : 1;
	uint32_t		fence : 1;
	uint32_t		so : 1;
	uint32_t		se : 1;
	uint32_t		inline_flag : 1;
	uint32_t		db_sl_h : 2;
	uint32_t		wqe_idx : 16;
	uint32_t		flag : 1;

	uint32_t		msg_len;
	union {
		uint32_t	inv_key;
		uint32_t	immtdata;
		uint32_t	new_rkey;
	};

	/* byte16 */
	uint32_t		byte_16 : 24;
	uint32_t		sge_num : 8;

	/* byte20 */
	uint32_t		msg_start_sge_idx : 24;
	uint32_t		reduce_core : 7;
	uint32_t		inline_type : 1;

	uint32_t		rkey;
	uint64_t		va;
};

struct hns3_udma_jfs_um_wqe {
	struct hns3_udma_jfs_wqe	jfs_wqe;
	uint32_t			data[8];
};

struct hns3_udma_spinlock {
	pthread_spinlock_t	lock;
	int			need_lock;
};

struct hns3_udma_wq {
	pthread_spinlock_t	lock;
	uintptr_t		*wrid;
	uint32_t		wqe_cnt;
	uint32_t		head;
	uint32_t		tail;
	uint32_t		max_gs;
	uint32_t		ext_sge_cnt;
	uint32_t		wqe_shift;
	uint32_t		shift;
	int			offset;
	uint8_t			priority;
};

struct hns3_udma_qp_buf {
	void		*buf;
	uint32_t	length;
};

struct hns3_udma_sge_ex {
	int		offset;
	uint32_t	sge_cnt;
	int		sge_shift;
};

#define HNS3_UDMA_MTU_NUM_256  256
#define HNS3_UDMA_MTU_NUM_512  512
#define HNS3_UDMA_MTU_NUM_1024 1024
#define HNS3_UDMA_MTU_NUM_2048 2048
#define HNS3_UDMA_MTU_NUM_4096 4096
#define HNS3_UDMA_MTU_NUM_8192 8192

struct hns3_udma_qp {
	uint32_t			qp_num;
	/* shared by jfs and jetty */
	uint32_t			jetty_id;
	uint64_t			flags;
	void				*dwqe_page;
	struct hns3_udma_spinlock	hns3_udma_lock;
	struct hns3_udma_buf		buf;
	struct hns3_udma_dca_buf	dca_wqe;
	struct hns3_udma_wq		sq;
	struct hns3_udma_sge_ex		ex_sge;
	struct hns3_udma_wq		rq;
	uint32_t			buf_size;
	uint32_t			next_sge;
	urma_mtu_t			path_mtu;
	uint32_t			max_inline_data;
	uint32_t			flush_status;
	struct udp_srcport		um_srcport;
	uint32_t			*sdb;
	bool				is_jetty;
};

struct connect_node {
	struct hns3_udma_hmap_node	hmap_node;
	struct hns3_udma_qp		*qp;
	urma_target_jetty_t		*tjfr;
};

struct hns3_udma_jfs_qp_node {
	struct hns3_udma_hmap_node	node;
	struct hns3_udma_qp		*jfs_qp;
};

struct hns3_udma_u_jfs {
	urma_jfs_t				base;
	uint32_t				jfs_id;
	struct hns3_udma_qp_buf			wqe_buf;
	urma_transport_mode_t			tp_mode;
	uint32_t				lock_free;
	pthread_spinlock_t			lock;
	union {
		struct connect_node_table	tjfr_tbl;
		struct hns3_udma_qp		*um_qp;
	};
};

struct hns3_udma_jfs_node {
	struct hns3_udma_hmap_node	node;
	struct hns3_udma_u_jfs		*jfs;
};

enum hns3_udma_jfs_opcode {
	HNS3_UDMA_OPCODE_SEND				= 0x00,
	HNS3_UDMA_OPCODE_SEND_WITH_INV			= 0x01,
	HNS3_UDMA_OPCODE_SEND_WITH_IMM			= 0x02,
	HNS3_UDMA_OPCODE_RDMA_WRITE			= 0x03,
	HNS3_UDMA_OPCODE_RDMA_WRITE_WITH_IMM		= 0x04,
	HNS3_UDMA_OPCODE_RDMA_READ			= 0x05,
	HNS3_UDMA_OPCODE_ATOM_CMP_AND_SWAP		= 0x06,
	HNS3_UDMA_OPCODE_ATOM_FETCH_AND_ADD		= 0x07,
	HNS3_UDMA_OPCODE_ATOM_MSK_CMP_AND_SWAP		= 0x08,
	HNS3_UDMA_OPCODE_ATOM_MSK_FETCH_AND_ADD		= 0x09,
	HNS3_UDMA_OPCODE_FAST_REG_PMR			= 0x0a,
	HNS3_UDMA_OPCODE_BIND_MW			= 0x0c,
	HNS3_UDMA_OPCODE_NOP				= 0x13,
	HNS3_UDMA_OPCODE_RDMA_WRITE_WITH_NOTIFY		= 0x16,
	HNS3_UDMA_OPCODE_ATOMIC_WRITE			= 0x17,
	HNS3_UDMA_OPCODE_PERSISTENCE_WRITE		= 0x19,
	HNS3_UDMA_OPCODE_PERSISTENCE_WRITE_WITH_IMM	= 0x1a,
	HNS3_UDMA_OPCODE_JFS_MAX			= 0x1f,
};

#define HNS3_UDMAWQE_FIELD_LOC(h, l)		((uint64_t)(h) << 32 | (l))
#define HNS3_UDMAUMWQE_FIELD_LOC(h, l)	((uint64_t)(h) << 32 | (l))

#define HNS3_UDMAWQE_OPCODE HNS3_UDMAWQE_FIELD_LOC(4, 0)
#define HNS3_UDMAWQE_DB_SL_L HNS3_UDMAWQE_FIELD_LOC(6, 5)
#define HNS3_UDMAWQE_SQPN_L HNS3_UDMAWQE_FIELD_LOC(6, 5)
#define HNS3_UDMAWQE_OWNER HNS3_UDMAWQE_FIELD_LOC(7, 7)
#define HNS3_UDMAWQE_CQE HNS3_UDMAWQE_FIELD_LOC(8, 8)
#define HNS3_UDMAWQE_FENCE HNS3_UDMAWQE_FIELD_LOC(9, 9)
#define HNS3_UDMAWQE_SO HNS3_UDMAWQE_FIELD_LOC(10, 10)
#define HNS3_UDMAWQE_SE HNS3_UDMAWQE_FIELD_LOC(11, 11)
#define HNS3_UDMAWQE_INLINE HNS3_UDMAWQE_FIELD_LOC(12, 12)
#define HNS3_UDMAWQE_DB_SL_H HNS3_UDMAWQE_FIELD_LOC(14, 13)
#define HNS3_UDMAWQE_WQE_IDX HNS3_UDMAWQE_FIELD_LOC(30, 15)
#define HNS3_UDMAWQE_SQPN_H HNS3_UDMAWQE_FIELD_LOC(30, 13)
#define HNS3_UDMAWQE_FLAG HNS3_UDMAWQE_FIELD_LOC(31, 31)
#define HNS3_UDMAWQE_MSG_LEN HNS3_UDMAWQE_FIELD_LOC(63, 32)
#define HNS3_UDMAWQE_INV_KEY_IMMTDATA HNS3_UDMAWQE_FIELD_LOC(95, 64)
#define HNS3_UDMAWQE_XRC_SRQN HNS3_UDMAWQE_FIELD_LOC(119, 96)
#define HNS3_UDMAWQE_SGE_NUM HNS3_UDMAWQE_FIELD_LOC(127, 120)
#define HNS3_UDMAWQE_MSG_START_SGE_IDX HNS3_UDMAWQE_FIELD_LOC(151, 128)
#define HNS3_UDMAWQE_REDUCE_CODE HNS3_UDMAWQE_FIELD_LOC(158, 152)
#define HNS3_UDMAWQE_INLINE_TYPE HNS3_UDMAWQE_FIELD_LOC(159, 159)
#define HNS3_UDMAWQE_RKEY HNS3_UDMAWQE_FIELD_LOC(191, 160)
#define HNS3_UDMAWQE_VA_L HNS3_UDMAWQE_FIELD_LOC(223, 192)
#define HNS3_UDMAWQE_VA_H HNS3_UDMAWQE_FIELD_LOC(255, 224)
#define HNS3_UDMAWQE_LEN0 HNS3_UDMAWQE_FIELD_LOC(287, 256)
#define HNS3_UDMAWQE_LKEY0 HNS3_UDMAWQE_FIELD_LOC(319, 288)
#define HNS3_UDMAWQE_VA0_L HNS3_UDMAWQE_FIELD_LOC(351, 320)
#define HNS3_UDMAWQE_VA0_H HNS3_UDMAWQE_FIELD_LOC(383, 352)
#define HNS3_UDMAWQE_LEN1 HNS3_UDMAWQE_FIELD_LOC(415, 384)
#define HNS3_UDMAWQE_LKEY1 HNS3_UDMAWQE_FIELD_LOC(447, 416)
#define HNS3_UDMAWQE_VA1_L HNS3_UDMAWQE_FIELD_LOC(479, 448)
#define HNS3_UDMAWQE_VA1_H HNS3_UDMAWQE_FIELD_LOC(511, 480)

#define HNS3_UDMAWQE_MW_TYPE HNS3_UDMAWQE_FIELD_LOC(256, 256)
#define HNS3_UDMAWQE_MW_RA_EN HNS3_UDMAWQE_FIELD_LOC(258, 258)
#define HNS3_UDMAWQE_MW_RR_EN HNS3_UDMAWQE_FIELD_LOC(259, 259)
#define HNS3_UDMAWQE_MW_RW_EN HNS3_UDMAWQE_FIELD_LOC(260, 260)

#define HNS3_UDMAUMWQE_OPCODE HNS3_UDMAUMWQE_FIELD_LOC(4, 0)
#define HNS3_UDMAUMWQE_CQE HNS3_UDMAUMWQE_FIELD_LOC(8, 8)
#define HNS3_UDMAUMWQE_SE HNS3_UDMAUMWQE_FIELD_LOC(11, 11)
#define HNS3_UDMAUMWQE_INLINE HNS3_UDMAUMWQE_FIELD_LOC(12, 12)
#define HNS3_UDMAUMWQE_MSG_LEN HNS3_UDMAUMWQE_FIELD_LOC(63, 32)
#define HNS3_UDMAUMWQE_IMMT_DATA HNS3_UDMAUMWQE_FIELD_LOC(95, 64)
#define HNS3_UDMAUMWQE_SGE_NUM HNS3_UDMAUMWQE_FIELD_LOC(127, 120)
#define HNS3_UDMAUMWQE_MSG_START_SGE_IDX HNS3_UDMAUMWQE_FIELD_LOC(151, 128)
#define HNS3_UDMAUMWQE_INLINE_TYPE HNS3_UDMAUMWQE_FIELD_LOC(159, 159)
#define HNS3_UDMAUMWQE_UDPSPN HNS3_UDMAUMWQE_FIELD_LOC(191, 176)
#define HNS3_UDMAUMWQE_DQPN HNS3_UDMAUMWQE_FIELD_LOC(247, 224)
#define HNS3_UDMAUMWQE_HOPLIMIT HNS3_UDMAUMWQE_FIELD_LOC(279, 272)
#define HNS3_UDMAUMWQE_DGID_H HNS3_UDMAUMWQE_FIELD_LOC(511, 480)

#define HNS3_UDMAUMWQE_INLINE_DATA_15_0 HNS3_UDMAUMWQE_FIELD_LOC(63, 48)
#define HNS3_UDMAUMWQE_INLINE_DATA_23_16 HNS3_UDMAUMWQE_FIELD_LOC(127, 120)
#define HNS3_UDMAUMWQE_INLINE_DATA_47_24 HNS3_UDMAUMWQE_FIELD_LOC(151, 128)
#define HNS3_UDMAUMWQE_INLINE_DATA_63_48 HNS3_UDMAUMWQE_FIELD_LOC(175, 160)

#define HNS3_UDMAUMWQE_INLINE_SHIFT1 8
#define HNS3_UDMAUMWQE_INLINE_SHIFT2 16
#define HNS3_UDMAUMWQE_INLINE_SHIFT3 24

#define HNS3_UDMAWQE_SQPN_L_WIDTH 2

#define HNS3_UDMA_SGE_IN_WQE 2

#define HNS3_UDMA_MAX_RC_INL_INN_SZ 32
#define HNS3_UDMA_MAX_UM_INL_INN_SZ 8

#define HNS3_UDMA_NOTIFY_ADDR_MASK 0xffffffUL
#define HNS3_UDMA_NOTIFY_GET_ADDR(a) ((uint64_t)((a) & HNS3_UDMA_NOTIFY_ADDR_MASK))
#define HNS3_UDMA_NOTIFY_SHIFT_DATA(d) ((uint64_t)(((d) << 16) << 8))
#define HNS3_UDMA_GET_NOTIFY_DATA(a, d) (HNS3_UDMA_NOTIFY_GET_ADDR(a) | HNS3_UDMA_NOTIFY_SHIFT_DATA(d))

#define gen_qpn(high, mid, low) ((high) | (mid) | (low))

#define HNS3_UDMA_BIT_MASK(nr) (1UL << ((nr) % 64))
#define HNS3_UDMA_BIT_WORD(nr) ((nr) / 64)

#define HNS3_UDMA_MIN_JFS_DEPTH 64

#define HNS3_UDMA_HOPLIMIT_NUM 0xff

#define HNS3_UDMA_MAX_SGE_NUM 64

struct hns3_udma_sge_info {
	uint32_t	valid_num; /* sge length is not 0 */
	uint32_t	start_idx; /* start position of extend sge */
	uint32_t	total_len; /* total length of valid sges */
};

struct hns3_udma_sge {
	uint32_t	len;
	uint32_t	lkey;
	uint64_t	addr;
};

struct hns3_udma_jfs_wr_info {
	uint32_t	total_len;
	uint64_t	inv_key_immtdata;
	uint8_t		opcode;
	uint32_t	num_sge;
	uint64_t	dst_addr;
	uint32_t	rkey;
};

#if __GNUC__ >= 3
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#define hns3_udma_page_align(x) align(x, HNS3_UDMA_HW_PAGE_SIZE)
#define hns3_udma_page_count(x) (hns3_udma_page_align(x) / HNS3_UDMA_HW_PAGE_SIZE)

static inline bool atomic_test_bit(atomic_ulong *p, uint32_t nr)
{
	atomic_ulong *map = p;

	map += HNS3_UDMA_BIT_WORD(nr);
	return !!(atomic_load(map) & HNS3_UDMA_BIT_MASK(nr));
}

static inline bool test_and_set_bit_lock(atomic_ulong *p, uint32_t nr)
{
	uint64_t mask = HNS3_UDMA_BIT_MASK(nr);
	atomic_ulong *map = p;

	map += HNS3_UDMA_BIT_WORD(nr);
	if (atomic_load(map) & mask)
		return true;

	return (atomic_fetch_or(map, mask) & mask) != 0;
}

static inline void clear_bit_unlock(atomic_ulong *p, uint32_t nr)
{
	atomic_ulong *map = p;

	map += HNS3_UDMA_BIT_WORD(nr);
	atomic_fetch_and(map, ~HNS3_UDMA_BIT_MASK(nr));
}

static inline struct hns3_udma_u_jfs *to_hns3_udma_jfs(urma_jfs_t *jfs)
{
	return container_of(jfs, struct hns3_udma_u_jfs, base);
}

static inline struct hns3_udma_jfs_qp_node *to_hns3_udma_jfs_qp_node(struct hns3_udma_hmap_node *node)
{
	return container_of(node, struct hns3_udma_jfs_qp_node, node);
}

static inline struct hns3_udma_jfs_node *to_hns3_udma_jfs_node(struct hns3_udma_hmap_node *node)
{
	return container_of(node, struct hns3_udma_jfs_node, node);
}

inline void hns3_udma_fill_scr(struct hns3_udma_qp *qp, urma_cr_t *cr)
{
	struct hns3_udma_wq *wq = &qp->sq;

	cr->local_id = qp->jetty_id;
	cr->user_ctx = wq->wrid[wq->tail & (wq->wqe_cnt - 1)];
	cr->flag.bs.s_r = 0;
	cr->flag.bs.jetty = qp->is_jetty;
	cr->tpn = qp->qp_num;
	cr->status = URMA_CR_WR_FLUSH_ERR;

	++wq->tail;
}

urma_jfs_t *hns3_udma_u_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg);
urma_status_t hns3_udma_u_delete_jfs(urma_jfs_t *jfs);
urma_status_t hns3_udma_u_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				      urma_jfs_wr_t **bad_wr);
urma_status_t hns3_udma_u_post_rcqp_wr(struct hns3_udma_u_context *udma_ctx,
				       struct hns3_udma_qp *udma_qp,
				       urma_jfs_wr_t *wr, void **wqe, uint32_t nreq);
urma_status_t hns3_udma_u_post_umqp_wr(struct hns3_udma_u_context *udma_ctx,
				       struct hns3_udma_qp *udma_qp, urma_jfs_wr_t *wr,
				       void **wqe_addr);
urma_status_t hns3_udma_u_post_qp_wr_ex(struct hns3_udma_u_context *udma_ctx,
					struct hns3_udma_qp *udma_qp, urma_jfs_wr_t *wr,
					urma_transport_mode_t tp_mode);
struct hns3_udma_qp *hns3_udma_alloc_qp(struct hns3_udma_u_context *udma_ctx, bool is_jetty,
					urma_jfs_cfg_t *jfs_cfg, urma_jfr_cfg_t *jfr_cfg);
void hns3_udma_u_ring_sq_doorbell(struct hns3_udma_u_context *udma_ctx,
				  struct hns3_udma_qp *udma_qp, void *wqe, uint32_t num);
void exec_jfs_flush_cqe_cmd(struct hns3_udma_u_context *udma_ctx,
			    struct hns3_udma_qp *qp);
urma_status_t check_dca_valid(struct hns3_udma_u_context *udma_ctx, struct hns3_udma_qp *qp);
int hns3_udma_u_flush_jfs(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr);
void *get_send_wqe(struct hns3_udma_qp *qp, uint32_t n);
void *get_send_sge_ex(struct hns3_udma_qp *qp, uint32_t n);

#endif /* _HNS3_UDMA_JFS_H */
