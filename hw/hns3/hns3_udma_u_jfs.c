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

#include <linux/kernel.h>
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfs.h"

static urma_status_t alloc_qp_wqe_buf(struct udma_u_context *ctx, struct udma_qp *qp,
				      bool check_dca, urma_jfr_cfg_t *jfr_cfg)
{
	int buf_size = to_udma_hem_entries_size(qp->sq.wqe_cnt, qp->sq.wqe_shift);

	qp->ex_sge.offset = buf_size;
	buf_size += to_udma_hem_entries_size(qp->ex_sge.sge_cnt,
					     qp->ex_sge.sge_shift);

	/* RC RQ */
	if (jfr_cfg != NULL) {
		qp->rq.offset = buf_size;
		buf_size += to_udma_hem_entries_size(qp->rq.wqe_cnt, qp->rq.wqe_shift);
	}

	if (check_dca && ctx->dca_ctx.unit_size > 0) {
		/* when DCA enable, use a buffer list to store page address */
		qp->buf.buf = NULL;
		qp->buf_size = buf_size;
		qp->dca_wqe.max_cnt = udma_page_count(buf_size);
		qp->dca_wqe.shift = UDMA_HW_PAGE_SHIFT;
		qp->dca_wqe.dcan = UDMA_DCA_INVALID_DCA_NUM;
		qp->dca_wqe.bufs = (void **)calloc(qp->dca_wqe.max_cnt,
						   sizeof(void *));
		if (!qp->dca_wqe.bufs) {
			URMA_LOG_ERR("DCA wqe bufs alloc failed!\n");
			return URMA_ENOMEM;
		}
	} else if (udma_alloc_buf(&qp->buf, buf_size, UDMA_HW_PAGE_SIZE)) {
		URMA_LOG_ERR("qp wqe buf alloc failed!\n");
		return URMA_ENOMEM;
	}

	return URMA_SUCCESS;
}

static void init_sq_param(struct udma_qp *qp, urma_jfs_cfg_t *cfg, urma_jfr_cfg_t *jfr_cfg)
{
	uint32_t max_inline_data;
	uint32_t total_sge_cnt;
	uint32_t ext_sge_cnt;
	uint32_t cfg_depth;
	int wqe_sge_cnt;
	uint32_t max_gs;

	cfg_depth = roundup_pow_of_two(cfg->depth);
	qp->sq.wqe_cnt = cfg_depth < UDMA_MIN_JFS_DEPTH ?
			 UDMA_MIN_JFS_DEPTH : cfg_depth;
	qp->sq.wqe_shift = UDMA_SQ_WQE_SHIFT;
	qp->sq.shift = udma_ilog32(qp->sq.wqe_cnt);

	max_inline_data = roundup_pow_of_two(cfg->max_inline_data);
	qp->max_inline_data = max_inline_data;
	ext_sge_cnt = max_inline_data / UDMA_HW_SGE_SIZE;
	max_gs = max(ext_sge_cnt, cfg->max_sge);
	qp->sq.max_gs = max_gs;

	if (cfg->trans_mode == URMA_TM_UM)
		wqe_sge_cnt = max_gs;
	else
		wqe_sge_cnt = max_gs - UDMA_SGE_IN_WQE;

	if (wqe_sge_cnt > 0) {
		total_sge_cnt = roundup_pow_of_two(qp->sq.wqe_cnt * wqe_sge_cnt);
		qp->sq.ext_sge_cnt = max(total_sge_cnt,
					 (uint32_t)UDMA_HW_PAGE_SIZE / UDMA_HW_SGE_SIZE);
	}

	qp->ex_sge.sge_shift = UDMA_HW_SGE_SHIFT;
	qp->ex_sge.sge_cnt = qp->sq.ext_sge_cnt;

	/* rc rq param */
	if (jfr_cfg != NULL) {
		qp->rq.wqe_cnt = roundup_pow_of_two(jfr_cfg->depth);
		qp->rq.wqe_shift = udma_ilog32(roundup_pow_of_two(UDMA_HW_SGE_SIZE *
					       roundup_pow_of_two(jfr_cfg->max_sge)));
	}
}

static urma_status_t alloc_qp_wqe(struct udma_u_context *udma_ctx,
				  struct udma_qp *qp,
				  urma_jfs_cfg_t *jfs_cfg,
				  urma_jfr_cfg_t *jfr_cfg)
{
	urma_status_t ret;

	init_sq_param(qp, jfs_cfg, jfr_cfg);

	qp->sq.wrid = (uintptr_t *)calloc(qp->sq.wqe_cnt, sizeof(uintptr_t));
	if (qp->sq.wrid == NULL) {
		URMA_LOG_ERR("failed to calloc sq wrid in jetty\n");
		return URMA_ENOMEM;
	}

	ret = alloc_qp_wqe_buf(udma_ctx, qp, jfs_cfg->trans_mode != URMA_TM_UM,
			       jfr_cfg);
	if (ret) {
		URMA_LOG_ERR("alloc_jetty_wqe_buf failed.\n");
		free(qp->sq.wrid);
		qp->sq.wrid = NULL;
	}

	return ret;
}

struct udma_qp *udma_alloc_qp(struct udma_u_context *udma_ctx,
			      urma_jfs_cfg_t *jfs_cfg,
			      urma_jfr_cfg_t *jfr_cfg,
			      uint32_t jetty_id, bool is_jetty)
{
	enum udma_db_type db_type;
	struct udma_qp *qp;
	int ret;

	qp = (struct udma_qp *)calloc(1, sizeof(struct udma_qp));
	if (!qp) {
		URMA_LOG_ERR("alloc qp failed.\n");
		return NULL;
	}

	db_type = is_jetty ? UDMA_JETTY_TYPE_DB : UDMA_JFS_TYPE_DB;
	qp->sdb = (uint32_t *)udma_alloc_sw_db(udma_ctx, db_type);
	if (!qp->sdb) {
		URMA_LOG_ERR("alloc sw db failed.\n");
		goto err_alloc_qp;
	}

	ret = alloc_qp_wqe(udma_ctx, qp, jfs_cfg, jfr_cfg);
	if (ret) {
		URMA_LOG_ERR("alloc_qp_wqe failed.\n");
		goto err_alloc_sw_db;
	}
	qp->jetty_id = jetty_id;
	qp->is_jetty = is_jetty;

	return qp;

err_alloc_sw_db:
	udma_free_sw_db(udma_ctx, qp->sdb, db_type);
err_alloc_qp:
	free(qp);

	return NULL;
}

static int alloc_table_qp(struct udma_u_jfs *jfs,
			  struct udma_u_context *udma_ctx, urma_jfs_cfg_t *cfg)
{
	int ret;

	ret = verify_jfs_init_attr(&udma_ctx->urma_ctx, cfg);
	if (ret)
		return ret;

	if (jfs->tp_mode == URMA_TM_UM) {
		jfs->um_qp = udma_alloc_qp(udma_ctx, cfg, NULL, jfs->jfs_id, false);
		if (!jfs->um_qp) {
			URMA_LOG_ERR("alloc qp failed.\n");
			return ENOMEM;
		}
	} else {
		URMA_LOG_ERR("do not support this tp_mode.\n");
		return ENOMEM;
	}

	return ret;
}

static urma_status_t udma_add_to_qp_table(struct udma_u_context *ctx,
					  urma_jfs_t *jfs, struct udma_qp *qp,
					  uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;

	if (ctx == NULL || qp == NULL) {
		URMA_LOG_ERR("ctx or qp is NULL.\n");
		return URMA_EINVAL;
	}

	qp_node = (struct udma_jfs_qp_node *)calloc(1, sizeof(*qp_node));
	if (qp_node == NULL) {
		URMA_LOG_ERR("failed to calloc qp_node.\n");
		return URMA_ENOMEM;
	}
	qp_node->jfs_qp = qp;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	if (!udma_hmap_insert(&ctx->jfs_qp_table, &qp_node->node, qpn)) {
		free(qp_node);
		qp_node = NULL;
		URMA_LOG_ERR("failed to insert qp_node into jfs qp table.\n");
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		return URMA_EINVAL;
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);

	return URMA_SUCCESS;
}

static void udma_remove_from_qp_table(struct udma_u_context *ctx, uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;
	struct udma_hmap_node *node;

	(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
	node = udma_hmap_first_with_hash(&ctx->jfs_qp_table, qpn);
	if (node) {
		qp_node = to_udma_jfs_qp_node(node);
		udma_hmap_remove(&ctx->jfs_qp_table, node);
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		free(qp_node);
		return;
	}
	(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
}

static int exec_jfs_create_cmd(urma_context_t *ctx, struct udma_u_jfs *jfs,
			       urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(ctx);
	struct udma_create_jfs_resp resp = {};
	struct udma_create_jfs_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	if (jfs->tp_mode == URMA_TM_UM) {
		cmd.create_tp_ucmd.buf_addr = (uintptr_t)jfs->um_qp->buf.buf;
		cmd.create_tp_ucmd.sdb_addr = (uintptr_t)jfs->um_qp->sdb;
	}

	udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfs(ctx, &jfs->base, cfg, &udata);
	if (ret) {
		URMA_LOG_ERR("urma cmd create jfs failed.\n");
		return ret;
	}

	jfs->jfs_id = jfs->base.jfs_id.id;

	if (jfs->tp_mode == URMA_TM_UM) {
		jfs->um_qp->qp_num = resp.create_tp_resp.qpn;
		jfs->um_qp->flags = resp.create_tp_resp.cap_flags;
		if (resp.create_tp_resp.cap_flags & UDMA_QP_CAP_DIRECT_WQE) {
			ret = mmap_dwqe(ctx, jfs->um_qp);
			if (ret) {
				urma_cmd_delete_jfs(&jfs->base);
				URMA_LOG_ERR("mmap dwqe failed\n");
				return URMA_FAIL;
			}
		}
		jfs->um_qp->path_mtu = (urma_mtu_t)resp.create_tp_resp.path_mtu;
		jfs->um_qp->sq.priority = resp.create_tp_resp.priority;
		memcpy(&jfs->um_qp->um_srcport, &resp.create_tp_resp.um_srcport,
		       sizeof(struct udp_srcport));
		ret = udma_add_to_qp_table(udma_ctx, &jfs->base, jfs->um_qp,
					   jfs->um_qp->qp_num);
		if (ret)
			URMA_LOG_ERR("add to qp table failed for um jfs, ret = %d.\n", ret);
	}

	return ret;
}

static void um_free_qp(struct udma_u_context *udma_ctx, struct udma_u_jfs *jfs)
{
	if (jfs->um_qp) {
		udma_free_sw_db(udma_ctx, jfs->um_qp->sdb, UDMA_JFS_TYPE_DB);
		free(jfs->um_qp->sq.wrid);
		jfs->um_qp->sq.wrid = NULL;
		udma_free_buf(&jfs->um_qp->buf);
		free(jfs->um_qp);
		jfs->um_qp = NULL;
	}
}

void delete_qp_node_table(struct udma_u_context *udma_ctx, struct udma_u_jfs *jfs)
{
	if (jfs->tp_mode == URMA_TM_UM)
		um_free_qp(udma_ctx, jfs);
}

urma_jfs_t *udma_u_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *jfs;
	int ret;

	if (!ctx) {
		URMA_LOG_ERR("Invalid parameter.\n");
		return NULL;
	}
	udma_ctx = to_udma_ctx(ctx);

	jfs = (struct udma_u_jfs *)calloc(1, sizeof(*jfs));
	if (!jfs) {
		URMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}

	jfs->tp_mode = cfg->trans_mode;
	jfs->base.urma_ctx = ctx;
	jfs->base.jfs_id.eid = ctx->eid;
	jfs->base.jfs_id.uasid = ctx->uasid;
	jfs->base.jfs_cfg = *cfg;
	jfs->lock_free = cfg->flag.bs.lock_free;

	ret = alloc_table_qp(jfs, udma_ctx, cfg);
	if (ret)
		goto error;

	ret = exec_jfs_create_cmd(ctx, jfs, cfg);
	if (ret) {
		URMA_LOG_ERR("failed to create jfs, mode = %d, ret = %d.\n",
			     jfs->tp_mode, ret);
		goto error_create_jfs;
	}

	ret = insert_jetty_node(udma_ctx, jfs, false, jfs->jfs_id);
	if (ret) {
		URMA_LOG_ERR("failed to insert jetty node, ret = %d.\n",
			     ret);
		goto error_insert;
	}

	if (pthread_spin_init(&jfs->lock, PTHREAD_PROCESS_PRIVATE))
		goto error_init_lock;

	return &jfs->base;

error_init_lock:
	delete_jetty_node(udma_ctx, jfs->jfs_id);
error_insert:
	urma_cmd_delete_jfs(&jfs->base);
error_create_jfs:
	delete_qp_node_table(udma_ctx, jfs);
error:
	free(jfs);

	return NULL;
}

urma_status_t udma_u_delete_jfs(urma_jfs_t *jfs)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	int ret;

	if (jfs == NULL || jfs->urma_ctx == NULL) {
		URMA_LOG_ERR("Invalid parameter.\n");
		return URMA_EINVAL;
	}

	udma_jfs = to_udma_jfs(jfs);
	udma_ctx = to_udma_ctx(jfs->urma_ctx);

	if (udma_jfs->tp_mode == URMA_TM_UM)
		udma_remove_from_qp_table(udma_ctx, udma_jfs->um_qp->qp_num);

	delete_jetty_node(udma_ctx, udma_jfs->jfs_id);
	delete_qp_node_table(udma_ctx, udma_jfs);

	ret = urma_cmd_delete_jfs(jfs);
	if (ret) {
		URMA_LOG_ERR("jfs delete failed!\n");
		return URMA_FAIL;
	}

	pthread_spin_destroy(&udma_jfs->lock);

	free(udma_jfs);

	return URMA_SUCCESS;
}

static inline void *get_wqe(struct udma_qp *qp, uint32_t offset)
{
	if (!!qp->dca_wqe.bufs)
		return qp->dca_wqe.bufs[offset >> qp->dca_wqe.shift] +
			(offset & ((1 << qp->dca_wqe.shift) - 1));
	else if (qp->buf.buf)
		return (char *)qp->buf.buf + offset;
	else
		return NULL;
}

static void *get_send_wqe(struct udma_qp *qp, uint32_t n)
{
	return get_wqe(qp, qp->sq.offset + (n << qp->sq.wqe_shift));
}

static void *get_send_sge_ex(struct udma_qp *qp, uint32_t n)
{
	return get_wqe(qp, qp->ex_sge.offset + (n << qp->ex_sge.sge_shift));
}

static inline uint32_t udma_get_sgl_total_len(urma_sg_t *sg)
{
	uint32_t len = 0;

	for (uint32_t i = 0; i < sg->num_sge; i++)
		len += sg->sge[i].len;

	return len;
}

static uint32_t mtu_enum_to_int(urma_mtu_t mtu)
{
	switch (mtu) {
	case URMA_MTU_256:
		return UDMA_MTU_NUM_256;
	case URMA_MTU_512:
		return UDMA_MTU_NUM_512;
	case URMA_MTU_1024:
		return UDMA_MTU_NUM_1024;
	case URMA_MTU_2048:
		return UDMA_MTU_NUM_2048;
	case URMA_MTU_4096:
		return UDMA_MTU_NUM_4096;
	case URMA_MTU_8192:
		return UDMA_MTU_NUM_8192;
	default:
		return 0;
	}
}

static bool check_inl_data_len(struct udma_qp *qp, uint32_t len)
{
	uint32_t mtu = mtu_enum_to_int(qp->path_mtu);

	return (len <= qp->max_inline_data && len <= mtu);
}

static void get_src_buf_info(void **src_addr, uint32_t *src_len,
			     struct udma_sge *sg_list, int buf_idx)
{
	*src_addr = (void *)(uintptr_t)sg_list[buf_idx].addr;
	*src_len = sg_list[buf_idx].len;
}

static int fill_ext_sge_inl_data(struct udma_qp *qp, uint32_t total_len,
				 struct udma_sge *sg_list, uint32_t num_buf)
{
	uint32_t sge_sz = sizeof(struct udma_wqe_data_seg);
	void *dst_addr, *src_addr, *tail_bound_addr;
	uint32_t sge_mask = qp->ex_sge.sge_cnt - 1;
	uint32_t src_len, tail_len;
	uint32_t valid_num;
	uint32_t i;

	if (total_len > qp->sq.ext_sge_cnt * sge_sz)
		return EINVAL;

	dst_addr = get_send_sge_ex(qp, qp->next_sge & sge_mask);
	tail_bound_addr = get_send_sge_ex(qp, qp->ex_sge.sge_cnt);

	for (i = 0; i < num_buf; i++) {
		tail_len = (uintptr_t)tail_bound_addr - (uintptr_t)dst_addr;
		get_src_buf_info(&src_addr, &src_len, sg_list, i);

		if (src_len < tail_len) {
			memcpy(dst_addr, src_addr, src_len);
			dst_addr = (char *)dst_addr + src_len;
		} else if (src_len == tail_len) {
			memcpy(dst_addr, src_addr, src_len);
			dst_addr = get_send_sge_ex(qp, 0);
		} else {
			memcpy(dst_addr, src_addr, tail_len);
			dst_addr = get_send_sge_ex(qp, 0);
			src_addr = (char *)src_addr + tail_len;
			src_len -= tail_len;

			memcpy(dst_addr, src_addr, src_len);
			dst_addr = (char *)dst_addr + src_len;
		}
	}

	valid_num = DIV_ROUND_UP(total_len, sge_sz);
	qp->next_sge += valid_num;

	return 0;
}

static int set_rc_inl(struct udma_qp *qp, uint32_t num_sge, uint32_t total_len,
		      struct udma_jfs_wqe *wqe, struct udma_sge *sg_list)
{
	void *dseg = wqe;
	uint32_t i;
	int ret;

	if (!check_inl_data_len(qp, total_len)) {
		URMA_LOG_ERR("Invalid inline data len 0x%x, max inline data len 0x%x, mtu 0x%x\n",
			     total_len, qp->max_inline_data, qp->path_mtu);
		return EINVAL;
	}

	dseg = (char *)dseg + sizeof(struct udma_jfs_wqe);

	if (total_len <= UDMA_MAX_RC_INL_INN_SZ) {
		udma_reg_clear(wqe, UDMAWQE_INLINE_TYPE);

		for (i = 0; i < num_sge; i++) {
			memcpy(dseg, (void *)(uintptr_t)(sg_list[i].addr),
			       sg_list[i].len);
			dseg = (char *)dseg + sg_list[i].len;
		}
	} else {
		udma_reg_enable(wqe, UDMAWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, total_len, sg_list, num_sge);
		if (ret) {
			URMA_LOG_ERR("Fill extra sge fail\n");
			return ret;
		}
	}

	return 0;
}

static void set_um_inl_seg(struct udma_jfs_um_wqe *wqe, uint8_t *data)
{
	uint32_t *loc = (uint32_t *)data;
	uint32_t tmp_data;

	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_15_0, *loc & 0xffff);
	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_23_16,
		      (*loc >> UDMAUMWQE_INLINE_SHIFT2) & 0xff);

	tmp_data = *loc >> UDMAUMWQE_INLINE_SHIFT3;
	loc++;
	tmp_data |= ((*loc & 0xffff) << UDMAUMWQE_INLINE_SHIFT1);

	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_47_24, tmp_data);
	udma_reg_write(wqe, UDMAUMWQE_INLINE_DATA_63_48,
		      *loc >> UDMAUMWQE_INLINE_SHIFT2);
}

static void fill_ud_inn_inl_data(uint32_t num_sge, struct udma_jfs_um_wqe *wqe,
				 struct udma_sge *sg_list)
{
	uint8_t data[UDMA_MAX_UM_INL_INN_SZ] = {};
	void *tmp = data;
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		memcpy(tmp, (void *)(uintptr_t)sg_list[i].addr, sg_list[i].len);
		tmp += sg_list[i].len;
	}

	set_um_inl_seg(wqe, data);
}

static int set_um_inl(struct udma_qp *qp, uint32_t num_sge, uint32_t total_len,
		      struct udma_jfs_um_wqe *wqe, struct udma_sge *sg_list)
{
	int ret;

	if (!check_inl_data_len(qp, total_len)) {
		URMA_LOG_ERR("Invalid inline data len 0x%x, max inline data len 0x%x, mtu 0x%x\n",
			     total_len, qp->max_inline_data, qp->path_mtu);
		return EINVAL;
	}

	if (total_len <= UDMA_MAX_UM_INL_INN_SZ) {
		udma_reg_clear(wqe, UDMAUMWQE_INLINE_TYPE);

		fill_ud_inn_inl_data(num_sge, wqe, sg_list);
	} else {
		udma_reg_enable(wqe, UDMAUMWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, total_len, sg_list, num_sge);
		if (ret) {
			URMA_LOG_ERR("Fill extra sge fail\n");
			return ret;
		}
	}

	return 0;
}

static inline void set_data_seg(struct udma_wqe_data_seg *dseg,
				struct udma_sge *sg_list)
{
	dseg->lkey = htole32(sg_list->lkey);
	dseg->addr = htole64(sg_list->addr);
	dseg->len = htole32(sg_list->len);
}

static void set_rc_sge(struct udma_wqe_data_seg *dseg, struct udma_qp *qp,
		       uint32_t num_sge, struct udma_sge *sg_list)
{
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		if (i < UDMA_SGE_IN_WQE) {
			set_data_seg(dseg, sg_list + i);
			dseg++;
		} else {
			dseg = (struct udma_wqe_data_seg *)
				get_send_sge_ex(qp, qp->next_sge &
						(qp->ex_sge.sge_cnt - 1));
			set_data_seg(dseg, sg_list + i);
			qp->next_sge++;
		}
	}
}

static void set_um_sge(struct udma_qp *qp, uint32_t num_sge, struct udma_sge *sg_list)
{
	struct udma_wqe_data_seg *dseg;
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		dseg = (struct udma_wqe_data_seg *)
			get_send_sge_ex(qp, qp->next_sge &
					(qp->ex_sge.sge_cnt - 1));
		set_data_seg(dseg, sg_list + i);
		qp->next_sge++;
	}
}

static int udma_parse_rc_write_wr(urma_rw_wr_t *rw, struct udma_jfs_wqe *jfs_wqe,
				  struct udma_qp *qp, bool is_inline)
{
	struct udma_wqe_data_seg *dseg = (struct udma_wqe_data_seg *)(jfs_wqe + 1);
	struct udma_sge sg_list[UDMA_MAX_SGE_NUM];
	uint32_t total_length = 0;
	uint32_t valid_num = 0;
	int ret = 0;

	for (uint32_t i = 0; i < rw->src.num_sge; i++) {
		if (rw->src.sge[i].len == 0)
			continue;
		sg_list[valid_num].len = rw->src.sge[i].len;
		sg_list[valid_num].addr = rw->src.sge[i].addr;
		if (!is_inline)
			sg_list[valid_num].lkey = rw->src.sge[i].tseg->seg.token_id;
		total_length += rw->src.sge[i].len;
		valid_num++;
	}
	jfs_wqe->va = htole64(rw->dst.sge[0].addr);
	jfs_wqe->rkey = htole32(rw->dst.sge[0].tseg->seg.token_id);
	jfs_wqe->msg_len = htole32(total_length);
	udma_reg_write(jfs_wqe, UDMAWQE_SGE_NUM, valid_num);

	if (is_inline)
		ret = set_rc_inl(qp, valid_num, total_length, jfs_wqe, &sg_list[0]);
	else
		set_rc_sge(dseg, qp, valid_num, &sg_list[0]);

	return ret;
}

static int udma_parse_rc_send_wr(urma_send_wr_t *send, struct udma_jfs_wqe *jfs_wqe,
				 struct udma_qp *qp, bool is_inline)
{
	struct udma_wqe_data_seg *dseg = (struct udma_wqe_data_seg *)(jfs_wqe + 1);
	struct udma_sge sg_list[UDMA_MAX_SGE_NUM];
	uint32_t total_length = 0;
	uint32_t valid_num = 0;
	int ret = 0;

	for (uint32_t i = 0; i < send->src.num_sge; i++) {
		if (send->src.sge[i].len == 0)
			continue;
		sg_list[valid_num].len = send->src.sge[i].len;
		if (!is_inline)
			sg_list[valid_num].lkey = send->src.sge[i].tseg->seg.token_id;
		sg_list[valid_num].addr = send->src.sge[i].addr;
		total_length += send->src.sge[i].len;
		valid_num++;
	}

	jfs_wqe->msg_len = htole32(total_length);
	udma_reg_write(jfs_wqe, UDMAWQE_SGE_NUM, valid_num);

	if (is_inline)
		ret = set_rc_inl(qp, valid_num, total_length, jfs_wqe, &sg_list[0]);
	else
		set_rc_sge(dseg, qp, valid_num, &sg_list[0]);

	return ret;
}

static int udma_parse_um_send_wr(urma_send_wr_t *send, struct udma_jfs_um_wqe *jfs_wqe,
				 struct udma_qp *qp, bool is_inline)
{
	struct udma_sge sg_list[UDMA_MAX_SGE_NUM];
	uint32_t total_length = 0;
	uint32_t valid_num = 0;
	int ret = 0;

	for (uint32_t i = 0; i < send->src.num_sge; i++) {
		if (send->src.sge[i].len == 0)
			continue;
		sg_list[valid_num].len = send->src.sge[i].len;
		if (!is_inline)
			sg_list[valid_num].lkey = send->src.sge[i].tseg->seg.token_id;
		sg_list[valid_num].addr = send->src.sge[i].addr;
		total_length += send->src.sge[i].len;
		valid_num++;
	}

	udma_reg_write(jfs_wqe, UDMAUMWQE_MSG_LEN, htole32(total_length));
	udma_reg_write(jfs_wqe, UDMAUMWQE_SGE_NUM, valid_num);

	if (is_inline)
		ret = set_um_inl(qp, valid_num, total_length, jfs_wqe, &sg_list[0]);
	else
		set_um_sge(qp, valid_num, &sg_list[0]);

	return ret;
}

static int udma_parse_notify_params(urma_rw_wr_t *rw,
				    struct udma_jfs_wqe *jfs_wqe)
{
	uint64_t notify_data;

	if (rw->dst.sge) {
		if (rw->dst.sge[1].addr % NOTIFY_OFFSET_4B_ALIGN) {
			URMA_LOG_ERR("notify offset %uB should be aligned to 4B.\n",
				     rw->dst.sge[1].addr);
			return EINVAL;
		}
		notify_data = UDMA_GET_NOTIFY_DATA(rw->dst.sge[1].addr,
						   rw->notify_data);
		udma_reg_write(jfs_wqe, UDMAWQE_INV_KEY_IMMTDATA,
			      (uint32_t)notify_data);
	}

	return 0;
}

static int udma_parse_rc_jfs_wr(urma_jfs_wr_t *wr, struct udma_jfs_wqe *jfs_wqe,
				struct udma_qp *qp)
{
	bool is_inline = false;

	if (wr->flag.bs.inline_flag == 1)
		is_inline = true;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
		udma_reg_write(jfs_wqe, UDMAWQE_OPCODE, UDMA_OPCODE_SEND);
		return udma_parse_rc_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_SEND_IMM:
		udma_reg_write(jfs_wqe, UDMAWQE_OPCODE, UDMA_OPCODE_SEND_WITH_IMM);
		udma_reg_write(jfs_wqe, UDMAWQE_INV_KEY_IMMTDATA,
			       (uint32_t)(wr->send.imm_data));
		return udma_parse_rc_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_SEND_INVALIDATE:
		udma_reg_write(jfs_wqe, UDMAWQE_OPCODE, UDMA_OPCODE_SEND_WITH_INV);
		udma_reg_write(jfs_wqe, UDMAWQE_INV_KEY_IMMTDATA,
			       (uint32_t)(wr->send.tseg->seg.token_id));
		return udma_parse_rc_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_WRITE:
		udma_reg_write(jfs_wqe, UDMAWQE_OPCODE, UDMA_OPCODE_RDMA_WRITE);
		return udma_parse_rc_write_wr(&wr->rw, jfs_wqe, qp, is_inline);
	case URMA_OPC_WRITE_IMM:
		udma_reg_write(jfs_wqe, UDMAWQE_OPCODE,
			       UDMA_OPCODE_RDMA_WRITE_WITH_IMM);
		udma_reg_write(jfs_wqe, UDMAWQE_INV_KEY_IMMTDATA,
			       (uint32_t)(wr->rw.notify_data));
		return udma_parse_rc_write_wr(&wr->rw, jfs_wqe, qp, is_inline);
	case URMA_OPC_WRITE_NOTIFY:
		if (udma_parse_notify_params(&wr->rw, jfs_wqe)) {
			URMA_LOG_ERR("parse wr failed, invalid notify parameters.\n");
			return EINVAL;
		}
		udma_reg_write(jfs_wqe, UDMAWQE_OPCODE,
			       UDMA_OPCODE_RDMA_WRITE_WITH_NOTIFY);
		return udma_parse_rc_write_wr(&wr->rw, jfs_wqe, qp, is_inline);
	default:
		URMA_LOG_ERR("Unsupported or invalid opcode :%u\n",
			     (uint32_t)wr->opcode);
		return EINVAL;
	}
}

static int udma_parse_um_jfs_wr(urma_jfs_wr_t *wr, struct udma_jfs_um_wqe *jfs_wqe,
				struct udma_qp *qp)
{
	bool is_inline = false;

	if (wr->flag.bs.inline_flag == 1)
		is_inline = true;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
		udma_reg_write(jfs_wqe, UDMAUMWQE_OPCODE, UDMA_OPCODE_SEND);
		return udma_parse_um_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_SEND_IMM:
		udma_reg_write(jfs_wqe, UDMAUMWQE_OPCODE, UDMA_OPCODE_SEND_WITH_IMM);
		udma_reg_write(jfs_wqe, UDMAUMWQE_IMMT_DATA,
			       (uint32_t)(wr->send.imm_data));
		return udma_parse_um_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	default:
		URMA_LOG_ERR("Unsupported or invalid opcode :%u\n",
			     (uint32_t)wr->opcode);
		return EINVAL;
	}
}

static void udma_set_um_wqe_udpspn(struct udma_jfs_um_wqe *jfs_wqe,
				   struct udma_qp *qp)
{
	uint16_t data_udp_start_l, data_udp_start_h;

	udma_reg_write(jfs_wqe, UDMAUMWQE_UDPSPN, qp->um_srcport.um_data_udp_start);
	data_udp_start_l = (qp->um_srcport.um_data_udp_start + 1) &
			   (BIT(qp->um_srcport.um_udp_range) - 1);
	data_udp_start_h = qp->um_srcport.um_data_udp_start >>
			   qp->um_srcport.um_udp_range;
	qp->um_srcport.um_data_udp_start = data_udp_start_l |
					   data_udp_start_h <<
					   qp->um_srcport.um_udp_range;
}

static urma_status_t udma_set_um_wqe(struct udma_u_context *udma_ctx, void *wqe,
				     struct udma_qp *qp, urma_jfs_wr_t *wr)
{
	struct udma_jfs_um_wqe *jfs_wqe = (struct udma_jfs_um_wqe *)wqe;
	uint32_t qpn;

	memset(jfs_wqe, 0, sizeof(struct udma_jfs_um_wqe));
	udma_reg_write(jfs_wqe, UDMAUMWQE_MSG_START_SGE_IDX,
		       qp->next_sge & (qp->ex_sge.sge_cnt - 1));

	if (udma_parse_um_jfs_wr(wr, jfs_wqe, qp) != 0) {
		URMA_LOG_ERR("Failed to parse wr.\n");
		return URMA_EINVAL;
	}

	udma_reg_write_bool(jfs_wqe, UDMAUMWQE_CQE, wr->flag.bs.complete_enable);
	udma_reg_write_bool(jfs_wqe, UDMAUMWQE_SE, wr->flag.bs.solicited_enable);
	udma_reg_write_bool(jfs_wqe, UDMAUMWQE_INLINE, wr->flag.bs.inline_flag);
	udma_reg_write(jfs_wqe, UDMAUMWQE_HOPLIMIT, UDMA_HOPLIMIT_NUM);

	qpn = wr->tjetty->id.id;
	udma_reg_write(jfs_wqe, UDMAUMWQE_DGID_H,
		       *(uint32_t *)(wr->tjetty->id.eid.raw + GID_H_SHIFT));

	if (qp->um_srcport.um_spray_en)
		udma_set_um_wqe_udpspn(jfs_wqe, qp);

	udma_reg_write(jfs_wqe, UDMAUMWQE_DQPN, qpn);

	udma_reg_write_bool(jfs_wqe, UDMAWQE_OWNER, !(qp->sq.head & BIT(qp->sq.shift)));

	return URMA_SUCCESS;
}

static urma_status_t udma_set_rc_wqe(void *wqe, struct udma_qp *qp,
				     urma_jfs_wr_t *wr)
{
	struct udma_jfs_wqe *jfs_wqe = (struct udma_jfs_wqe *)wqe;
	urma_status_t ret = URMA_SUCCESS;

	udma_reg_write(jfs_wqe, UDMAWQE_MSG_START_SGE_IDX,
		       qp->next_sge & (qp->ex_sge.sge_cnt - 1));

	if (udma_parse_rc_jfs_wr(wr, jfs_wqe, qp) != 0) {
		URMA_LOG_ERR("Failed to parse wr.\n");
		return URMA_EINVAL;
	}

	udma_reg_write_bool(jfs_wqe, UDMAWQE_CQE, wr->flag.bs.complete_enable);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_FENCE, wr->flag.bs.fence);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_SE, wr->flag.bs.solicited_enable);
	udma_reg_write_bool(jfs_wqe, UDMAWQE_INLINE, wr->flag.bs.inline_flag);


	return ret;
}

static int udma_wq_overflow(struct udma_wq *wq)
{
	uint32_t cur;

	cur = wq->head - wq->tail;

	return cur >= wq->wqe_cnt;
}

static void udma_sve_write512(uint64_t *dest, uint64_t *val)
{
	asm volatile(
		"ldr z0, [%0]\n" \
		"str z0, [%1]\n"  \
		::"r" (val), "r"(dest):"cc", "memory"
	);
}

static void udma_write_dca_wqe(struct udma_qp *qp, void *wqe)
{
#define RCWQE_SQPN_L_WIDTH 2
	struct udma_jfs_wqe *udma_wqe = (struct udma_jfs_wqe *)wqe;

	udma_reg_write(udma_wqe, UDMAWQE_SQPN_L, qp->qp_num);
	udma_reg_write(udma_wqe, UDMAWQE_SQPN_H,
		       qp->qp_num >> RCWQE_SQPN_L_WIDTH);
}

static void udma_write_dwqe(struct udma_u_context *ctx, struct udma_qp *qp,
			    void *wqe)
{
#define PRIORITY_OFFSET 2
	struct udma_reset_state *state = (struct udma_reset_state *)ctx->reset_state;
	struct udma_jfs_wqe *udma_wqe = (struct udma_jfs_wqe *)wqe;

	if (state && state->is_reset)
		return;

	/* All kinds of DirectWQE have the same header field layout */
	udma_reg_enable(udma_wqe, UDMAWQE_FLAG);
	udma_reg_write(udma_wqe, UDMAWQE_DB_SL_L, qp->sq.priority);
	udma_reg_write(udma_wqe, UDMAWQE_DB_SL_H, qp->sq.priority >> PRIORITY_OFFSET);
	udma_reg_write(udma_wqe, UDMAWQE_WQE_IDX, qp->sq.head);

	udma_sve_write512((uint64_t *)qp->dwqe_page, (uint64_t *)udma_wqe);
}

static void udma_update_sq_db(struct udma_u_context *ctx, struct udma_qp *qp)
{
	struct udma_u_db sq_db = {};

	udma_reg_write(&sq_db, UDMA_DB_TAG, qp->qp_num);
	udma_reg_write(&sq_db, UDMA_DB_CMD, UDMA_SQ_DB);
	udma_reg_write(&sq_db, UDMA_DB_PI, qp->sq.head);
	udma_reg_write(&sq_db, UDMA_DB_SL, qp->sq.priority);

	udma_write64(ctx, (uint64_t *)(ctx->uar + UDMA_DB_CFG0_OFFSET),
		     (uint64_t *)&sq_db);
}

struct udma_qp *get_qp(struct udma_u_jfs *udma_jfs, urma_jfs_wr_t *wr)
{
	struct udma_hmap_node *hmap_node = NULL;
	struct connect_node *udma_connect_node;
	struct udma_qp *udma_qp = NULL;
	uint32_t tjfr_index;

	if (!wr->tjetty) {
		URMA_LOG_ERR("Failed to get jfs qp, tjetty of wr is null.\n");
		return NULL;
	}

	if (udma_jfs->tp_mode == URMA_TM_UM)
		return udma_jfs->um_qp;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
	case URMA_OPC_SEND_IMM:
	case URMA_OPC_SEND_INVALIDATE:
	case URMA_OPC_WRITE:
	case URMA_OPC_WRITE_IMM:
	case URMA_OPC_WRITE_NOTIFY:
		tjfr_index = udma_get_tgt_hash(&wr->tjetty->id);
		hmap_node = udma_table_first_with_hash(&udma_jfs->tjfr_tbl.hmap,
						       &udma_jfs->tjfr_tbl.rwlock,
						       tjfr_index);
		break;
	default:
		URMA_LOG_ERR("Unsupported or invalid opcode: %u.\n",
			     (uint32_t)wr->opcode);
		return NULL;
	}

	if (!hmap_node)
		return NULL;

	udma_connect_node = CONTAINER_OF_FIELD(hmap_node, struct connect_node,
					       hmap_node);
	udma_qp = udma_connect_node->qp;

	return udma_qp;
}

static int exec_jfs_flush_cqe_cmd(struct udma_u_context *udma_ctx,
				  struct udma_qp *qp)
{
	urma_context_t *ctx = &udma_ctx->urma_ctx;
	struct flush_cqe_param fcp = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)UDMA_USER_CTL_FLUSH_CQE;
	in.addr = (uint64_t)&fcp;
	in.len = (uint32_t)sizeof(struct flush_cqe_param);

	fcp.qpn = qp->qp_num;
	fcp.sq_producer_idx = qp->sq.head;

	return urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
}

static int dca_attach_qp_buf(struct udma_u_context *ctx, struct udma_qp *qp)
{
	struct udma_dca_attach_attr attr = {};
	bool force = false;
	uint32_t idx;
	int ret;

	(void)pthread_spin_lock(&qp->sq.lock);

	if (qp->sq.wqe_cnt > 0) {
		idx = qp->sq.head & (qp->sq.wqe_cnt - 1);
		attr.sq_offset = idx << qp->sq.wqe_shift;
	}

	if (qp->ex_sge.sge_cnt > 0) {
		idx = qp->next_sge & (qp->ex_sge.sge_cnt - 1);
		attr.sge_offset = idx << qp->ex_sge.sge_shift;
	}

	attr.qpn = qp->qp_num;

	if (!udma_dca_start_post(&ctx->dca_ctx, qp->dca_wqe.dcan))
		/* Force attach if failed to sync dca status */
		force = true;

	ret = udma_u_attach_dca_mem(ctx, &attr, qp->buf_size, &qp->dca_wqe,
				    force);
	if (ret)
		udma_dca_stop_post(&ctx->dca_ctx, qp->dca_wqe.dcan);

	(void)pthread_spin_unlock(&qp->sq.lock);

	return ret;
}

static urma_status_t check_dca_valid(struct udma_u_context *udma_ctx, struct udma_qp *qp)
{
	int ret;

	if (qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH) {
		ret = dca_attach_qp_buf(udma_ctx, qp);
		if (ret) {
			URMA_LOG_ERR("failed to attach DCA for QP %u send!\n",
				     qp->qp_num);
			return URMA_ENOMEM;
		}
	}

	return URMA_SUCCESS;
}

void udma_u_ring_sq_doorbell(struct udma_u_context *udma_ctx,
			     struct udma_qp *udma_qp, void *wqe, uint32_t num)
{
	udma_to_device_barrier();
	if (num == 1 && udma_qp->flags & UDMA_QP_CAP_DIRECT_WQE)
		udma_write_dwqe(udma_ctx, udma_qp, wqe);
	else
		udma_update_sq_db(udma_ctx, udma_qp);
}

urma_status_t udma_u_post_rcqp_wr(struct udma_u_context *udma_ctx,
				  struct udma_qp *udma_qp,
				  urma_jfs_wr_t *wr, void **wqe)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret) {
		URMA_LOG_ERR("Failed to check send, qpn = %lu.\n", udma_qp->qp_num);
		goto out;
	}

	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		URMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}

	if (udma_wq_overflow(&udma_qp->sq)) {
		URMA_LOG_ERR("JFS overflow.\n");
		ret = URMA_ENOMEM;
		goto out;
	}

	wqe_idx = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	*wqe = get_send_wqe(udma_qp, wqe_idx);
	udma_qp->sq.wrid[wqe_idx] = wr->user_ctx;

	ret = udma_set_rc_wqe(*wqe, udma_qp, wr);
	if (ret)
		goto out;

	udma_qp->sq.head += 1;
	if (udma_qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_write_dca_wqe(udma_qp, *wqe);

	*udma_qp->sdb = udma_qp->sq.head;
	if (udma_qp->flush_status == UDMA_FLUSH_STATU_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

out:
	if (udma_qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_dca_stop_post(&udma_ctx->dca_ctx, udma_qp->dca_wqe.dcan);

	return ret;
}

urma_status_t udma_u_post_qp_wr(struct udma_u_context *udma_ctx,
				struct udma_qp *udma_qp,
				urma_jfs_wr_t *wr, void **wqe,
				urma_transport_mode_t tp_mode)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret) {
		URMA_LOG_ERR("Failed to check send, qpn = %lu.\n", udma_qp->qp_num);
		goto out;
	}

	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		URMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}

	if (udma_wq_overflow(&udma_qp->sq)) {
		URMA_LOG_ERR("JFS overflow.\n");
		ret = URMA_ENOMEM;
		goto out;
	}

	wqe_idx = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	*wqe = get_send_wqe(udma_qp, wqe_idx);
	udma_qp->sq.wrid[wqe_idx] = wr->user_ctx;

	ret = udma_set_um_wqe(udma_ctx, *wqe, udma_qp, wr);
	if (ret)
		goto out;

	udma_qp->sq.head += 1;
	if (udma_qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_write_dca_wqe(udma_qp, *wqe);

	udma_to_device_barrier();

	udma_u_ring_sq_doorbell(udma_ctx, udma_qp, *wqe, 1);

	*udma_qp->sdb = udma_qp->sq.head;
	if (udma_qp->flush_status == UDMA_FLUSH_STATU_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

out:
	if (udma_qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_dca_stop_post(&udma_ctx->dca_ctx, udma_qp->dca_wqe.dcan);

	return ret;
}

urma_status_t udma_u_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				 urma_jfs_wr_t **bad_wr)
{
	struct udma_u_context *udma_ctx;
	struct udma_u_jfs *udma_jfs;
	struct udma_qp *udma_qp;
	urma_status_t ret;
	urma_jfs_wr_t *it;
	void *wqe;

	udma_jfs = to_udma_jfs(jfs);
	udma_ctx = to_udma_ctx(jfs->urma_ctx);

	if (!udma_jfs->lock_free)
		(void)pthread_spin_lock(&udma_jfs->lock);

	for (it = wr; it != NULL; it = (urma_jfs_wr_t *)(void *)it->next) {
		udma_qp = get_qp(udma_jfs, it);
		if (udma_qp == NULL) {
			URMA_LOG_ERR("failed to get qp, opcode = 0x%x.\n",
				     it->opcode);
			ret = URMA_EINVAL;
			*bad_wr = (urma_jfs_wr_t *)it;
			goto out;
		}

		ret = udma_u_post_qp_wr(udma_ctx, udma_qp, it, &wqe,
					udma_jfs->tp_mode);
		if (ret) {
			*bad_wr = (urma_jfs_wr_t *)it;
			goto out;
		}
	}
out:
	if (!udma_jfs->lock_free)
		(void)pthread_spin_unlock(&udma_jfs->lock);

	return ret;
}

urma_status_t udma_u_post_qp_wr_ex(struct udma_u_context *udma_ctx,
				   struct udma_qp *udma_qp, urma_jfs_wr_t *wr,
				   urma_transport_mode_t tp_mode)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_index;
	void *wqe;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret) {
		URMA_LOG_ERR("failed to check send, qpn = %lu.\n",
			     udma_qp->qp_num);
		goto out;
	}

	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		URMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}
	if (udma_wq_overflow(&udma_qp->sq)) {
		URMA_LOG_ERR("JFS overflow. pi = %u, ci = %u.\n",
				udma_qp->sq.head, udma_qp->sq.tail);
		ret = URMA_ENOMEM;
		goto out;
	}
	wqe_index = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	wqe = get_send_wqe(udma_qp, wqe_index);
	udma_qp->sq.wrid[wqe_index] = wr->user_ctx;

	if (tp_mode == URMA_TM_UM)
		ret = udma_set_um_wqe(udma_ctx, wqe, udma_qp, wr);
	else
		ret = udma_set_rc_wqe(wqe, udma_qp, wr);
	if (ret)
		goto out;

	udma_qp->sq.head = udma_qp->sq.head + 1;

	if (udma_qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_write_dca_wqe(udma_qp, wqe);

	udma_to_device_barrier();

	*udma_qp->sdb = udma_qp->sq.head;
	if (udma_qp->flush_status == UDMA_FLUSH_STATU_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

out:
	if (udma_qp->flags & UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		udma_dca_stop_post(&udma_ctx->dca_ctx, udma_qp->dca_wqe.dcan);

	return ret;
}
