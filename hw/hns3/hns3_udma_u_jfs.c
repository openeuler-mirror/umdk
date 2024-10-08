// SPDX-License-Identifier: GPL-2.0
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

#include <linux/kernel.h>
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_tp.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_jfs.h"

static urma_status_t alloc_qp_wqe_buf(struct hns3_udma_u_context *ctx, struct hns3_udma_qp *qp,
				      bool check_dca, urma_jfr_cfg_t *jfr_cfg)
{
	uint32_t buf_size = to_hns3_udma_hem_entries_size(qp->sq.wqe_cnt, qp->sq.wqe_shift);

	qp->ex_sge.offset = buf_size;
	buf_size += to_hns3_udma_hem_entries_size(qp->ex_sge.sge_cnt,
					     qp->ex_sge.sge_shift);

	/* RC RQ */
	if (jfr_cfg != NULL) {
		qp->rq.offset = buf_size;
		buf_size += to_hns3_udma_hem_entries_size(qp->rq.wqe_cnt, qp->rq.wqe_shift);
	}

	if (check_dca && ctx->dca_ctx.unit_size > 0) {
		/* when DCA enable, use a buffer list to store page address */
		qp->buf.buf = NULL;
		qp->buf_size = buf_size;
		qp->dca_wqe.max_cnt = hns3_udma_page_count(buf_size);
		qp->dca_wqe.shift = HNS3_UDMA_HW_PAGE_SHIFT;
		qp->dca_wqe.dcan = HNS3_UDMA_DCA_INVALID_DCA_NUM;
		qp->dca_wqe.bufs = (void **)calloc(qp->dca_wqe.max_cnt,
						   sizeof(void *));
		if (!qp->dca_wqe.bufs) {
			HNS3_UDMA_LOG_ERR("DCA wqe bufs alloc failed!\n");
			return URMA_ENOMEM;
		}
	} else if (hns3_udma_alloc_buf(&qp->buf, buf_size, ctx->page_size)) {
		HNS3_UDMA_LOG_ERR("qp wqe buf alloc failed!\n");
		return URMA_ENOMEM;
	}

	return URMA_SUCCESS;
}

static void init_sq_param(struct hns3_udma_qp *qp, urma_jfs_cfg_t *cfg, urma_jfr_cfg_t *jfr_cfg)
{
	uint32_t max_inline_data;
	uint32_t total_sge_cnt;
	uint32_t ext_sge_cnt;
	uint32_t cfg_depth;
	int wqe_sge_cnt;
	uint32_t max_gs;
	uint32_t rq_cnt;

	cfg_depth = roundup_pow_of_two(cfg->depth);
	qp->sq.wqe_cnt = cfg_depth < HNS3_UDMA_MIN_JFS_DEPTH ?
			 HNS3_UDMA_MIN_JFS_DEPTH : cfg_depth;
	qp->sq.wqe_shift = HNS3_UDMA_SQ_WQE_SHIFT;
	qp->sq.shift = hns3_udma_ilog32(qp->sq.wqe_cnt);

	max_inline_data = roundup_pow_of_two(cfg->max_inline_data);
	qp->max_inline_data = max_inline_data;
	ext_sge_cnt = max_inline_data / HNS3_UDMA_HW_SGE_SIZE;
	max_gs = max(ext_sge_cnt, cfg->max_sge);
	qp->sq.max_gs = max_gs;

	if (cfg->trans_mode == URMA_TM_UM)
		wqe_sge_cnt = max_gs;
	else
		wqe_sge_cnt = max_gs - HNS3_UDMA_SGE_IN_WQE;

	if (wqe_sge_cnt > 0) {
		total_sge_cnt = roundup_pow_of_two(qp->sq.wqe_cnt * wqe_sge_cnt);
		qp->sq.ext_sge_cnt = max(total_sge_cnt,
					 (uint32_t)HNS3_UDMA_HW_PAGE_SIZE / HNS3_UDMA_HW_SGE_SIZE);
	}

	qp->ex_sge.sge_shift = HNS3_UDMA_HW_SGE_SHIFT;
	qp->ex_sge.sge_cnt = qp->sq.ext_sge_cnt;

	/* rc rq param */
	if (jfr_cfg != NULL) {
		qp->rq.wqe_cnt = roundup_pow_of_two(jfr_cfg->depth);
		if (jfr_cfg->trans_mode == URMA_TM_UM)
			rq_cnt = roundup_pow_of_two(jfr_cfg->max_sge + 1);
		else
			rq_cnt = roundup_pow_of_two(jfr_cfg->max_sge);
		qp->rq.wqe_shift = hns3_udma_ilog32(roundup_pow_of_two(HNS3_UDMA_HW_SGE_SIZE *
								  rq_cnt));
	}
}

static urma_status_t alloc_qp_wqe(struct hns3_udma_u_context *udma_ctx,
				  struct hns3_udma_qp *qp,
				  urma_jfs_cfg_t *jfs_cfg,
				  urma_jfr_cfg_t *jfr_cfg)
{
	urma_status_t ret;

	init_sq_param(qp, jfs_cfg, jfr_cfg);

	qp->sq.wrid = (uintptr_t *)calloc(qp->sq.wqe_cnt, sizeof(uintptr_t));
	if (!qp->sq.wrid) {
		HNS3_UDMA_LOG_ERR("failed to calloc sq wrid in jetty.\n");
		return URMA_ENOMEM;
	}

	ret = alloc_qp_wqe_buf(udma_ctx, qp, jfs_cfg->trans_mode != URMA_TM_UM,
			       jfr_cfg);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to alloc jetty wqe buf.\n");
		free(qp->sq.wrid);
		qp->sq.wrid = NULL;
	}

	return ret;
}

struct hns3_udma_qp *hns3_udma_alloc_qp(struct hns3_udma_u_context *udma_ctx, bool is_jetty,
					urma_jfs_cfg_t *jfs_cfg, urma_jfr_cfg_t *jfr_cfg)
{
	enum hns3_udma_db_type db_type;
	struct hns3_udma_qp *qp;
	int ret;

	qp = (struct hns3_udma_qp *)calloc(1, sizeof(struct hns3_udma_qp));
	if (!qp) {
		HNS3_UDMA_LOG_ERR("alloc qp failed.\n");
		return NULL;
	}

	db_type = is_jetty ? HNS3_UDMA_JETTY_TYPE_DB : HNS3_UDMA_JFS_TYPE_DB;
	qp->sdb = (uint32_t *)hns3_udma_alloc_sw_db(udma_ctx, db_type);
	if (!qp->sdb) {
		HNS3_UDMA_LOG_ERR("alloc sw db failed.\n");
		goto err_alloc_qp;
	}

	ret = alloc_qp_wqe(udma_ctx, qp, jfs_cfg, jfr_cfg);
	if (ret) {
		HNS3_UDMA_LOG_ERR("alloc qp wqe failed.\n");
		goto err_alloc_sw_db;
	}
	qp->is_jetty = is_jetty;

	return qp;

err_alloc_sw_db:
	hns3_udma_free_sw_db(udma_ctx, qp->sdb, db_type);
err_alloc_qp:
	free(qp);

	return NULL;
}

static int alloc_jfs_qp_node(struct hns3_udma_u_jfs *jfs, struct hns3_udma_u_context *udma_ctx,
			     urma_jfs_cfg_t *cfg)
{
	int ret;

	ret = verify_jfs_init_attr(&udma_ctx->urma_ctx, cfg);
	if (ret)
		return ret;

	jfs->um_qp = hns3_udma_alloc_qp(udma_ctx, false, cfg, NULL);
	if (!jfs->um_qp) {
		HNS3_UDMA_LOG_ERR("alloc qp failed.\n");
		return ENOMEM;
	}

	return ret;
}

static int exec_jfs_create_cmd(urma_context_t *ctx, struct hns3_udma_u_jfs *jfs,
			       urma_jfs_cfg_t *cfg)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(ctx);
	struct hns3_udma_create_jfs_resp resp = {};
	struct hns3_udma_create_jfs_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	cmd.create_tp_ucmd.buf_addr = (uintptr_t)jfs->um_qp->buf.buf;
	cmd.create_tp_ucmd.sdb_addr = (uintptr_t)jfs->um_qp->sdb;

	hns3_udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfs(ctx, &jfs->base, cfg, &udata);
	if (ret) {
		HNS3_UDMA_LOG_ERR("urma cmd create jfs failed.\n");
		return ret;
	}

	jfs->jfs_id = jfs->base.jfs_id.id;
	jfs->um_qp->qp_num = resp.create_tp_resp.qpn;
	jfs->um_qp->flags = resp.create_tp_resp.cap_flags;
	jfs->um_qp->path_mtu = (urma_mtu_t)resp.create_tp_resp.path_mtu;
	jfs->um_qp->sq.priority = resp.create_tp_resp.priority;

	if (resp.create_tp_resp.cap_flags & HNS3_UDMA_QP_CAP_DIRECT_WQE) {
		ret = mmap_dwqe(ctx, jfs->um_qp);
		if (ret) {
			HNS3_UDMA_LOG_ERR("mmap dwqe failed\n");
			goto err_mmap_dwqe;
		}
	}

	memcpy(&jfs->um_qp->um_srcport, &resp.create_tp_resp.um_srcport,
		sizeof(struct udp_srcport));
	ret = hns3_udma_add_to_qp_table(udma_ctx, jfs->um_qp, jfs->um_qp->qp_num);
	if (ret) {
		HNS3_UDMA_LOG_ERR("add to qp table failed for um jfs, ret = %d.\n", ret);
		goto err_add_qp_table;
	}

	return ret;

err_add_qp_table:
	if (resp.create_tp_resp.cap_flags & HNS3_UDMA_QP_CAP_DIRECT_WQE)
		munmap_dwqe(jfs->um_qp);
err_mmap_dwqe:
	urma_cmd_delete_jfs(&jfs->base);
	return ret;
}

static void delete_jfs_qp_node(struct hns3_udma_u_context *udma_ctx, struct hns3_udma_u_jfs *jfs)
{
	if (jfs->um_qp->dca_wqe.bufs)
		free(jfs->um_qp->dca_wqe.bufs);
	else
		hns3_udma_free_buf(&jfs->um_qp->buf);
	free(jfs->um_qp->sq.wrid);
	jfs->um_qp->sq.wrid = NULL;
	hns3_udma_free_sw_db(udma_ctx, jfs->um_qp->sdb, HNS3_UDMA_JFS_TYPE_DB);
	free(jfs->um_qp);
	jfs->um_qp = NULL;
}

static int exec_jfs_delete_cmd(struct hns3_udma_u_context *ctx, struct hns3_udma_u_jfs *jfs)
{
	hns3_udma_remove_from_qp_table(ctx, jfs->um_qp->qp_num);

	if (jfs->um_qp->flags & HNS3_UDMA_QP_CAP_DIRECT_WQE)
		munmap_dwqe(jfs->um_qp);

	return urma_cmd_delete_jfs(&jfs->base);
}

urma_jfs_t *hns3_udma_u_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
	struct hns3_udma_u_context *udma_ctx;
	struct hns3_udma_u_jfs *jfs;
	int ret;

	if (!ctx || cfg->trans_mode != URMA_TM_UM) {
		HNS3_UDMA_LOG_ERR("Invalid parameter.\n");
		return NULL;
	}
	udma_ctx = to_hns3_udma_ctx(ctx);

	jfs = (struct hns3_udma_u_jfs *)calloc(1, sizeof(*jfs));
	if (!jfs) {
		HNS3_UDMA_LOG_ERR("memory allocation failed.\n");
		return NULL;
	}

	jfs->tp_mode = cfg->trans_mode;
	jfs->base.urma_ctx = ctx;
	jfs->base.jfs_id.eid = ctx->eid;
	jfs->base.jfs_id.uasid = ctx->uasid;
	jfs->base.jfs_cfg = *cfg;
	jfs->lock_free = cfg->flag.bs.lock_free;

	ret = alloc_jfs_qp_node(jfs, udma_ctx, cfg);
	if (ret)
		goto error;

	ret = exec_jfs_create_cmd(ctx, jfs, cfg);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to create jfs, mode = %d, ret = %d.\n",
			     jfs->tp_mode, ret);
		goto error_create_jfs;
	}

	ret = insert_jetty_node(udma_ctx, jfs, false, jfs->jfs_id);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to insert jetty node, ret = %d.\n", ret);
		goto error_insert;
	}

	if (pthread_spin_init(&jfs->lock, PTHREAD_PROCESS_PRIVATE))
		goto error_init_lock;

	return &jfs->base;

error_init_lock:
	delete_jetty_node(udma_ctx, jfs->jfs_id);
error_insert:
	(void)exec_jfs_delete_cmd(udma_ctx, jfs);
error_create_jfs:
	delete_jfs_qp_node(udma_ctx, jfs);
error:
	free(jfs);

	return NULL;
}

urma_status_t hns3_udma_u_delete_jfs(urma_jfs_t *jfs)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(jfs->urma_ctx);
	struct hns3_udma_u_jfs *udma_jfs = to_hns3_udma_jfs(jfs);
	int ret;

	if (jfs->jfs_cfg.trans_mode != URMA_TM_UM) {
		HNS3_UDMA_LOG_ERR("Invalid parameter.\n");
		return URMA_EINVAL;
	}

	(void)pthread_spin_destroy(&udma_jfs->lock);
	delete_jetty_node(udma_ctx, udma_jfs->jfs_id);

	ret = exec_jfs_delete_cmd(udma_ctx, udma_jfs);
	if (ret) {
		HNS3_UDMA_LOG_ERR("urma_cmd_delete_jfs failed, ret:%d.\n", ret);
		return URMA_FAIL;
	}

	free(udma_jfs);

	return URMA_SUCCESS;
}

static inline void *get_wqe(struct hns3_udma_qp *qp, uint32_t offset)
{
	if (!!qp->dca_wqe.bufs)
		return qp->dca_wqe.bufs[offset >> qp->dca_wqe.shift] +
			(offset & ((1 << qp->dca_wqe.shift) - 1));
	else if (qp->buf.buf)
		return (char *)qp->buf.buf + offset;
	else
		return NULL;
}

void *get_send_wqe(struct hns3_udma_qp *qp, uint32_t n)
{
	return get_wqe(qp, qp->sq.offset + (n << qp->sq.wqe_shift));
}

void *get_send_sge_ex(struct hns3_udma_qp *qp, uint32_t n)
{
	return get_wqe(qp, qp->ex_sge.offset + (n << qp->ex_sge.sge_shift));
}

static inline uint32_t hns3_udma_get_sgl_total_len(urma_sg_t *sg)
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
		return HNS3_UDMA_MTU_NUM_256;
	case URMA_MTU_512:
		return HNS3_UDMA_MTU_NUM_512;
	case URMA_MTU_1024:
		return HNS3_UDMA_MTU_NUM_1024;
	case URMA_MTU_2048:
		return HNS3_UDMA_MTU_NUM_2048;
	case URMA_MTU_4096:
		return HNS3_UDMA_MTU_NUM_4096;
	case URMA_MTU_8192:
		return HNS3_UDMA_MTU_NUM_8192;
	default:
		return 0;
	}
}

static bool check_inl_data_len(struct hns3_udma_qp *qp, uint32_t len)
{
	uint32_t mtu = mtu_enum_to_int(qp->path_mtu);

	return (len <= qp->max_inline_data && len <= mtu);
}

static void get_src_buf_info(void **src_addr, uint32_t *src_len,
			     struct hns3_udma_sge *sg_list, int buf_idx)
{
	*src_addr = (void *)(uintptr_t)sg_list[buf_idx].addr;
	*src_len = sg_list[buf_idx].len;
}

static int fill_ext_sge_inl_data(struct hns3_udma_qp *qp, uint32_t total_len,
				 struct hns3_udma_sge *sg_list, uint32_t num_buf)
{
	uint32_t sge_sz = sizeof(struct hns3_udma_wqe_data_seg);
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

static int set_rc_inl(struct hns3_udma_qp *qp, uint32_t num_sge, uint32_t total_len,
		      struct hns3_udma_jfs_wqe *wqe, struct hns3_udma_sge *sg_list)
{
	void *dseg = wqe;
	uint32_t i;
	int ret;

	if (!check_inl_data_len(qp, total_len)) {
		HNS3_UDMA_LOG_ERR("Invalid inline len 0x%x, max inline len 0x%x, mtu 0x%x.\n",
			     total_len, qp->max_inline_data, qp->path_mtu);
		return EINVAL;
	}

	dseg = (char *)dseg + sizeof(struct hns3_udma_jfs_wqe);

	if (total_len <= HNS3_UDMA_MAX_RC_INL_INN_SZ) {
		wqe->inline_type = 0;

		for (i = 0; i < num_sge; i++) {
			memcpy(dseg, (void *)(uintptr_t)(sg_list[i].addr),
			       sg_list[i].len);
			dseg = (char *)dseg + sg_list[i].len;
		}
	} else {
		wqe->inline_type = 1;

		ret = fill_ext_sge_inl_data(qp, total_len, sg_list, num_sge);
		if (ret) {
			HNS3_UDMA_LOG_ERR("Fill extra sge fail\n");
			return ret;
		}
	}

	return 0;
}

static void set_um_inl_seg(struct hns3_udma_jfs_um_wqe *wqe, uint8_t *data)
{
	uint32_t *loc = (uint32_t *)data;
	uint32_t tmp_data;

	hns3_udma_reg_write(wqe, HNS3_UDMAUMWQE_INLINE_DATA_15_0, *loc & 0xffff);
	hns3_udma_reg_write(wqe, HNS3_UDMAUMWQE_INLINE_DATA_23_16,
		      (*loc >> HNS3_UDMAUMWQE_INLINE_SHIFT2) & 0xff);

	tmp_data = *loc >> HNS3_UDMAUMWQE_INLINE_SHIFT3;
	loc++;
	tmp_data |= ((*loc & 0xffff) << HNS3_UDMAUMWQE_INLINE_SHIFT1);

	hns3_udma_reg_write(wqe, HNS3_UDMAUMWQE_INLINE_DATA_47_24, tmp_data);
	hns3_udma_reg_write(wqe, HNS3_UDMAUMWQE_INLINE_DATA_63_48,
		       *loc >> HNS3_UDMAUMWQE_INLINE_SHIFT2);
}

static void fill_um_inn_inl_data(uint32_t num_sge, struct hns3_udma_jfs_um_wqe *wqe,
				 struct hns3_udma_sge *sg_list)
{
	uint8_t data[HNS3_UDMA_MAX_UM_INL_INN_SZ] = {};
	void *tmp = data;
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		memcpy(tmp, (void *)(uintptr_t)sg_list[i].addr, sg_list[i].len);
		tmp += sg_list[i].len;
	}

	set_um_inl_seg(wqe, data);
}

static int set_um_inl(struct hns3_udma_qp *qp, uint32_t num_sge, uint32_t total_len,
		      struct hns3_udma_jfs_um_wqe *wqe, struct hns3_udma_sge *sg_list)
{
	int ret;

	if (!check_inl_data_len(qp, total_len)) {
		HNS3_UDMA_LOG_ERR("Invalid inline len 0x%x, max inline len 0x%x, mtu 0x%x.\n",
			     total_len, qp->max_inline_data, qp->path_mtu);
		return EINVAL;
	}

	if (total_len <= HNS3_UDMA_MAX_UM_INL_INN_SZ) {
		hns3_udma_reg_clear(wqe, HNS3_UDMAUMWQE_INLINE_TYPE);

		fill_um_inn_inl_data(num_sge, wqe, sg_list);
	} else {
		hns3_udma_reg_enable(wqe, HNS3_UDMAUMWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, total_len, sg_list, num_sge);
		if (ret) {
			HNS3_UDMA_LOG_ERR("Fill extra sge fail.\n");
			return ret;
		}
	}

	return 0;
}

static inline void set_data_seg(struct hns3_udma_wqe_data_seg *dseg,
				struct hns3_udma_sge *sg_list)
{
	dseg->lkey = htole32(sg_list->lkey);
	dseg->addr = htole64(sg_list->addr);
	dseg->len = htole32(sg_list->len);
}

static void set_rc_sge(struct hns3_udma_wqe_data_seg *dseg, struct hns3_udma_qp *qp,
		       uint32_t num_sge, struct hns3_udma_sge *sg_list)
{
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		if (i < HNS3_UDMA_SGE_IN_WQE) {
			set_data_seg(dseg, sg_list + i);
			dseg++;
		} else {
			dseg = (struct hns3_udma_wqe_data_seg *)
				get_send_sge_ex(qp, qp->next_sge &
						(qp->ex_sge.sge_cnt - 1));
			set_data_seg(dseg, sg_list + i);
			qp->next_sge++;
		}
	}
}

static void set_um_sge(struct hns3_udma_qp *qp, uint32_t num_sge, struct hns3_udma_sge *sg_list)
{
	struct hns3_udma_wqe_data_seg *dseg;
	uint32_t i;

	for (i = 0; i < num_sge; i++) {
		dseg = (struct hns3_udma_wqe_data_seg *)
			get_send_sge_ex(qp, qp->next_sge &
					(qp->ex_sge.sge_cnt - 1));
		set_data_seg(dseg, sg_list + i);
		qp->next_sge++;
	}
}

static int hns3_udma_parse_rc_write_wr(urma_rw_wr_t *rw, struct hns3_udma_jfs_wqe *jfs_wqe,
				       struct hns3_udma_qp *qp, bool is_inline)
{
	struct hns3_udma_wqe_data_seg *dseg = (struct hns3_udma_wqe_data_seg *)(jfs_wqe + 1);
	struct hns3_udma_sge sg_list[HNS3_UDMA_MAX_SGE_NUM];
	uint32_t total_num_sge =  rw->src.num_sge;
	uint32_t total_length = 0;
	uint32_t valid_num = 0;
	int ret = 0;

	for (uint32_t i = 0; i < total_num_sge; i++) {
		if (unlikely(rw->src.sge[i].len == 0))
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
	jfs_wqe->sge_num = valid_num;

	if (is_inline)
		ret = set_rc_inl(qp, valid_num, total_length, jfs_wqe, &sg_list[0]);
	else
		set_rc_sge(dseg, qp, valid_num, &sg_list[0]);

	return ret;
}

static int hns3_udma_parse_rc_send_wr(urma_send_wr_t *send, struct hns3_udma_jfs_wqe *jfs_wqe,
				      struct hns3_udma_qp *qp, bool is_inline)
{
	struct hns3_udma_wqe_data_seg *dseg = (struct hns3_udma_wqe_data_seg *)(jfs_wqe + 1);
	struct hns3_udma_sge sg_list[HNS3_UDMA_MAX_SGE_NUM];
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
	jfs_wqe->sge_num = valid_num;

	if (is_inline)
		ret = set_rc_inl(qp, valid_num, total_length, jfs_wqe, &sg_list[0]);
	else
		set_rc_sge(dseg, qp, valid_num, &sg_list[0]);

	return ret;
}

static int hns3_udma_parse_um_send_wr(urma_send_wr_t *send, struct hns3_udma_jfs_um_wqe *jfs_wqe,
				      struct hns3_udma_qp *qp, bool is_inline)
{
	struct hns3_udma_sge sg_list[HNS3_UDMA_MAX_SGE_NUM];
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

	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_MSG_LEN, htole32(total_length));
	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_SGE_NUM, valid_num);

	if (is_inline)
		ret = set_um_inl(qp, valid_num, total_length, jfs_wqe, &sg_list[0]);
	else
		set_um_sge(qp, valid_num, &sg_list[0]);

	return ret;
}

static int hns3_udma_parse_notify_params(urma_rw_wr_t *rw,
					 struct hns3_udma_jfs_wqe *jfs_wqe)
{
	uint64_t notify_data;

	if (rw->dst.sge) {
		if (rw->dst.sge[1].addr % NOTIFY_OFFSET_4B_ALIGN) {
			HNS3_UDMA_LOG_ERR("notify offset %uB should be aligned to 4B.\n",
				     rw->dst.sge[1].addr);
			return EINVAL;
		}
		notify_data = HNS3_UDMA_GET_NOTIFY_DATA(rw->dst.sge[1].addr,
						   rw->notify_data);
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_INV_KEY_IMMTDATA,
			      (uint32_t)notify_data);
	}

	return 0;
}

static int hns3_udma_parse_rc_jfs_wr(urma_jfs_wr_t *wr, struct hns3_udma_jfs_wqe *jfs_wqe,
				     struct hns3_udma_qp *qp)
{
	bool is_inline = wr->flag.bs.inline_flag == 1;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
		jfs_wqe->opcode = HNS3_UDMA_OPCODE_SEND;
		return hns3_udma_parse_rc_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_SEND_IMM:
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_OPCODE, HNS3_UDMA_OPCODE_SEND_WITH_IMM);
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_INV_KEY_IMMTDATA,
			       (uint32_t)(wr->send.imm_data));
		return hns3_udma_parse_rc_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_SEND_INVALIDATE:
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_OPCODE, HNS3_UDMA_OPCODE_SEND_WITH_INV);
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_INV_KEY_IMMTDATA,
			       (uint32_t)(wr->send.tseg->seg.token_id));
		return hns3_udma_parse_rc_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_WRITE:
		jfs_wqe->opcode = HNS3_UDMA_OPCODE_RDMA_WRITE;
		return hns3_udma_parse_rc_write_wr(&wr->rw, jfs_wqe, qp, is_inline);
	case URMA_OPC_WRITE_IMM:
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_OPCODE,
			       HNS3_UDMA_OPCODE_RDMA_WRITE_WITH_IMM);
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_INV_KEY_IMMTDATA,
			       (uint32_t)(wr->rw.notify_data));
		return hns3_udma_parse_rc_write_wr(&wr->rw, jfs_wqe, qp, is_inline);
	case URMA_OPC_WRITE_NOTIFY:
		if (hns3_udma_parse_notify_params(&wr->rw, jfs_wqe)) {
			HNS3_UDMA_LOG_ERR("parse wr failed, invalid notify parameters.\n");
			return EINVAL;
		}
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAWQE_OPCODE,
			       HNS3_UDMA_OPCODE_RDMA_WRITE_WITH_NOTIFY);
		return hns3_udma_parse_rc_write_wr(&wr->rw, jfs_wqe, qp, is_inline);
	default:
		HNS3_UDMA_LOG_ERR("Unsupported or invalid opcode :%u.\n",
			     (uint32_t)wr->opcode);
		return EINVAL;
	}
}

static int hns3_udma_parse_um_jfs_wr(urma_jfs_wr_t *wr, struct hns3_udma_jfs_um_wqe *jfs_wqe,
				     struct hns3_udma_qp *qp)
{
	bool is_inline = wr->flag.bs.inline_flag == 1;

	switch (wr->opcode) {
	case URMA_OPC_SEND:
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_OPCODE, HNS3_UDMA_OPCODE_SEND);
		return hns3_udma_parse_um_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	case URMA_OPC_SEND_IMM:
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_OPCODE, HNS3_UDMA_OPCODE_SEND_WITH_IMM);
		hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_IMMT_DATA,
			       (uint32_t)(wr->send.imm_data));
		return hns3_udma_parse_um_send_wr(&wr->send, jfs_wqe, qp, is_inline);
	default:
		HNS3_UDMA_LOG_ERR("Unsupported or invalid opcode :%u.\n",
			     (uint32_t)wr->opcode);
		return EINVAL;
	}
}

static void hns3_udma_set_um_wqe_udpspn(struct hns3_udma_jfs_um_wqe *jfs_wqe,
					struct hns3_udma_qp *qp)
{
	uint16_t data_udp_start_l, data_udp_start_h;

	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_UDPSPN, qp->um_srcport.um_data_udp_start);
	data_udp_start_l = (qp->um_srcport.um_data_udp_start + 1) &
			   (BIT(qp->um_srcport.um_udp_range) - 1);
	data_udp_start_h = qp->um_srcport.um_data_udp_start >>
			   qp->um_srcport.um_udp_range;
	qp->um_srcport.um_data_udp_start = data_udp_start_l |
					   data_udp_start_h <<
					   qp->um_srcport.um_udp_range;
}

static urma_status_t hns3_udma_set_um_wqe(struct hns3_udma_u_context *udma_ctx, void *wqe,
					  struct hns3_udma_qp *qp, urma_jfs_wr_t *wr)
{
	struct hns3_udma_jfs_um_wqe *jfs_wqe = (struct hns3_udma_jfs_um_wqe *)wqe;
	uint32_t qpn;

	memset(jfs_wqe, 0, sizeof(struct hns3_udma_jfs_um_wqe));
	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_MSG_START_SGE_IDX,
		       qp->next_sge & (qp->ex_sge.sge_cnt - 1));

	if (hns3_udma_parse_um_jfs_wr(wr, jfs_wqe, qp) != 0) {
		HNS3_UDMA_LOG_ERR("Failed to parse wr.\n");
		return URMA_EINVAL;
	}

	hns3_udma_reg_write_bool(jfs_wqe, HNS3_UDMAUMWQE_CQE, wr->flag.bs.complete_enable);
	hns3_udma_reg_write_bool(jfs_wqe, HNS3_UDMAUMWQE_SE, wr->flag.bs.solicited_enable);
	hns3_udma_reg_write_bool(jfs_wqe, HNS3_UDMAUMWQE_INLINE, wr->flag.bs.inline_flag);
	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_HOPLIMIT, HNS3_UDMA_HOPLIMIT_NUM);

	qpn = wr->tjetty->id.id;
	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_DGID_H,
		       *(uint32_t *)(wr->tjetty->id.eid.raw + GID_H_SHIFT));

	if (qp->um_srcport.um_spray_en)
		hns3_udma_set_um_wqe_udpspn(jfs_wqe, qp);

	hns3_udma_reg_write(jfs_wqe, HNS3_UDMAUMWQE_DQPN, qpn);

	hns3_udma_reg_write_bool(jfs_wqe, HNS3_UDMAWQE_OWNER, !(qp->sq.head & BIT(qp->sq.shift)));

	return URMA_SUCCESS;
}

static urma_status_t hns3_udma_set_rc_wqe(void *wqe, struct hns3_udma_qp *qp,
					  urma_jfs_wr_t *wr, uint32_t nreq)
{
	struct hns3_udma_jfs_wqe *jfs_wqe = (struct hns3_udma_jfs_wqe *)wqe;

	jfs_wqe->msg_start_sge_idx = qp->next_sge & (qp->ex_sge.sge_cnt - 1);

	if (hns3_udma_parse_rc_jfs_wr(wr, jfs_wqe, qp) != 0) {
		HNS3_UDMA_LOG_ERR("Failed to parse wr.\n");
		return URMA_EINVAL;
	}

	jfs_wqe->cqe = wr->flag.bs.complete_enable;
	jfs_wqe->fence = wr->flag.bs.fence;
	jfs_wqe->se = wr->flag.bs.solicited_enable;
	jfs_wqe->inline_flag = wr->flag.bs.inline_flag;
	jfs_wqe->owner = !((qp->sq.head + nreq) & BIT(qp->sq.shift));

	return URMA_SUCCESS;
}

static bool hns3_udma_wq_overflow(struct hns3_udma_wq *wq)
{
	uint32_t cur;

	cur = wq->head - wq->tail;

	return cur >= wq->wqe_cnt;
}

static void hns3_udma_sve_write512(uint64_t *dest, uint64_t *val)
{
	asm volatile(
		"ldr z0, [%0]\n" \
		"str z0, [%1]\n"  \
		::"r" (val), "r"(dest):"cc", "memory"
	);
}

static void hns3_udma_write_dca_wqe(struct hns3_udma_qp *qp, void *wqe)
{
#define RCWQE_SQPN_L_WIDTH 2
	struct hns3_udma_jfs_wqe *hns3_udma_wqe = (struct hns3_udma_jfs_wqe *)wqe;

	hns3_udma_reg_write(hns3_udma_wqe, HNS3_UDMAWQE_SQPN_L, qp->qp_num);
	hns3_udma_reg_write(hns3_udma_wqe, HNS3_UDMAWQE_SQPN_H,
		       qp->qp_num >> RCWQE_SQPN_L_WIDTH);
}

static void hns3_udma_write_dwqe(struct hns3_udma_u_context *ctx, struct hns3_udma_qp *qp,
				 void *wqe)
{
#define PRIORITY_OFFSET 2
	struct hns3_udma_reset_state *state = (struct hns3_udma_reset_state *)ctx->reset_state;
	struct hns3_udma_jfs_wqe *hns3_udma_wqe = (struct hns3_udma_jfs_wqe *)wqe;

	if (state && state->is_reset)
		return;

	/* All kinds of DirectWQE have the same header field layout */
	hns3_udma_reg_enable(hns3_udma_wqe, HNS3_UDMAWQE_FLAG);
	hns3_udma_reg_write(hns3_udma_wqe, HNS3_UDMAWQE_DB_SL_L, qp->sq.priority);
	hns3_udma_reg_write(hns3_udma_wqe, HNS3_UDMAWQE_DB_SL_H, qp->sq.priority >> PRIORITY_OFFSET);
	hns3_udma_reg_write(hns3_udma_wqe, HNS3_UDMAWQE_WQE_IDX, qp->sq.head);

	hns3_udma_sve_write512((uint64_t *)qp->dwqe_page, (uint64_t *)hns3_udma_wqe);
}

static void hns3_udma_update_sq_db(struct hns3_udma_u_context *ctx, struct hns3_udma_qp *qp)
{
	struct hns3_udma_u_db sq_db = {};

	hns3_udma_reg_write(&sq_db, HNS3_UDMA_DB_TAG, qp->qp_num);
	hns3_udma_reg_write(&sq_db, HNS3_UDMA_DB_CMD, HNS3_UDMA_SQ_DB);
	hns3_udma_reg_write(&sq_db, HNS3_UDMA_DB_PI, qp->sq.head);
	hns3_udma_reg_write(&sq_db, HNS3_UDMA_DB_SL, qp->sq.priority);

	hns3_udma_write64(ctx, (uint64_t *)(ctx->uar + HNS3_UDMA_DB_CFG0_OFFSET), (uint64_t *)&sq_db);
}

void exec_jfs_flush_cqe_cmd(struct hns3_udma_u_context *udma_ctx,
			    struct hns3_udma_qp *qp)
{
	urma_context_t *ctx = &udma_ctx->urma_ctx;
	struct flush_cqe_param fcp = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};

	in.opcode = (uint32_t)HNS3_UDMA_USER_CTL_FLUSH_CQE;
	in.addr = (uint64_t)&fcp;
	in.len = (uint32_t)sizeof(struct flush_cqe_param);

	fcp.qpn = qp->qp_num;
	fcp.sq_producer_idx = qp->sq.head;

	(void)urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
}

static int dca_attach_qp_buf(struct hns3_udma_u_context *ctx, struct hns3_udma_qp *qp)
{
	struct hns3_udma_dca_attach_attr attr = {};
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

	if (!hns3_udma_dca_start_post(&ctx->dca_ctx, qp->dca_wqe.dcan))
		/* Force attach if failed to sync dca status */
		force = true;

	ret = hns3_udma_u_attach_dca_mem(ctx, &attr, qp->buf_size, &qp->dca_wqe,
					 force);
	if (ret)
		hns3_udma_dca_stop_post(&ctx->dca_ctx, qp->dca_wqe.dcan);

	(void)pthread_spin_unlock(&qp->sq.lock);

	return ret;
}

urma_status_t check_dca_valid(struct hns3_udma_u_context *udma_ctx, struct hns3_udma_qp *qp)
{
	int ret;

	/* TODO: Check qp params valid */
	if (qp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH) {
		ret = dca_attach_qp_buf(udma_ctx, qp);
		if (ret) {
			HNS3_UDMA_LOG_ERR("failed to attach DCA for QP %lu send!\n",
				     qp->qp_num);
			return URMA_ENOMEM;
		}
	}

	return URMA_SUCCESS;
}

void hns3_udma_u_ring_sq_doorbell(struct hns3_udma_u_context *udma_ctx,
				  struct hns3_udma_qp *udma_qp, void *wqe, uint32_t num)
{
	hns3_udma_to_device_barrier();
	if (num == 1 && udma_qp->flags & HNS3_UDMA_QP_CAP_DIRECT_WQE)
		hns3_udma_write_dwqe(udma_ctx, udma_qp, wqe);
	else
		hns3_udma_update_sq_db(udma_ctx, udma_qp);
}

urma_status_t hns3_udma_u_post_rcqp_wr(struct hns3_udma_u_context *udma_ctx,
				       struct hns3_udma_qp *udma_qp,
				       urma_jfs_wr_t *wr, void **wqe, uint32_t nreq)
{
	bool dca_enable = udma_qp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH;
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;

	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		HNS3_UDMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}

	if (hns3_udma_wq_overflow(&udma_qp->sq)) {
		HNS3_UDMA_LOG_ERR("JFS overflow.\n");
		ret = URMA_ENOMEM;
		goto out;
	}

	wqe_idx = (udma_qp->sq.head + nreq) & (udma_qp->sq.wqe_cnt - 1);
	*wqe = get_send_wqe(udma_qp, wqe_idx);
	udma_qp->sq.wrid[wqe_idx] = wr->user_ctx;

	ret = hns3_udma_set_rc_wqe(*wqe, udma_qp, wr, nreq);
	if (ret)
		goto out;

	if (dca_enable)
		hns3_udma_write_dca_wqe(udma_qp, *wqe);

out:
	if (dca_enable)
		hns3_udma_dca_stop_post(&udma_ctx->dca_ctx, udma_qp->dca_wqe.dcan);

	return ret;
}

urma_status_t hns3_udma_u_post_umqp_wr(struct hns3_udma_u_context *udma_ctx,
				       struct hns3_udma_qp *udma_qp,
				       urma_jfs_wr_t *wr, void **wqe)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_idx;

	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		HNS3_UDMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}

	if (hns3_udma_wq_overflow(&udma_qp->sq)) {
		HNS3_UDMA_LOG_ERR("JFS overflow.\n");
		ret = URMA_ENOMEM;
		goto out;
	}

	wqe_idx = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	*wqe = get_send_wqe(udma_qp, wqe_idx);
	udma_qp->sq.wrid[wqe_idx] = wr->user_ctx;

	ret = hns3_udma_set_um_wqe(udma_ctx, *wqe, udma_qp, wr);
	if (ret)
		goto out;

	udma_qp->sq.head += 1;
	if (udma_qp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_write_dca_wqe(udma_qp, *wqe);

	*udma_qp->sdb = udma_qp->sq.head;

out:
	if (udma_qp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_dca_stop_post(&udma_ctx->dca_ctx, udma_qp->dca_wqe.dcan);

	return ret;
}

urma_status_t hns3_udma_u_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				      urma_jfs_wr_t **bad_wr)
{
	struct hns3_udma_u_context *udma_ctx;
	struct hns3_udma_u_jfs *udma_jfs;
	struct hns3_udma_qp *udma_qp;
	uint32_t wr_cnt = 0;
	urma_status_t ret;
	urma_jfs_wr_t *it;
	void *wqe;

	udma_jfs = to_hns3_udma_jfs(jfs);
	udma_ctx = to_hns3_udma_ctx(jfs->urma_ctx);

	if (udma_jfs->tp_mode != URMA_TM_UM)
		return URMA_EINVAL;

	if (!udma_jfs->lock_free)
		(void)pthread_spin_lock(&udma_jfs->lock);

	udma_qp = udma_jfs->um_qp;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret) {
		*bad_wr = (urma_jfs_wr_t *)wr;
		goto out;
	}

	for (it = wr; it != NULL; it = (urma_jfs_wr_t *)(void *)it->next) {
		ret = hns3_udma_u_post_umqp_wr(udma_ctx, udma_qp, it, &wqe);
		if (ret) {
			*bad_wr = (urma_jfs_wr_t *)it;
			break;
		}
		wr_cnt++;
	}
out:
	if (likely(wr_cnt))
		hns3_udma_u_ring_sq_doorbell(udma_ctx, udma_qp, wqe, wr_cnt);

	if (!udma_jfs->lock_free)
		(void)pthread_spin_unlock(&udma_jfs->lock);

	return ret;
}

urma_status_t hns3_udma_u_post_qp_wr_ex(struct hns3_udma_u_context *udma_ctx,
					struct hns3_udma_qp *udma_qp, urma_jfs_wr_t *wr,
					urma_transport_mode_t tp_mode)
{
	urma_status_t ret = URMA_SUCCESS;
	uint32_t wqe_index;
	void *wqe;

	ret = check_dca_valid(udma_ctx, udma_qp);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to check send, qpn = %lu.\n",
			     udma_qp->qp_num);
		goto out;
	}

	if (wr->send.src.num_sge > udma_qp->sq.max_gs) {
		ret = udma_qp->sq.max_gs > 0 ? URMA_EINVAL : URMA_ENOPERM;
		HNS3_UDMA_LOG_ERR("Invalid wr sge num, ret = 0x%x.\n", ret);
		goto out;
	}
	if (hns3_udma_wq_overflow(&udma_qp->sq)) {
		HNS3_UDMA_LOG_ERR("JFS overflow. pi = %u, ci = %u.\n",
			     udma_qp->sq.head, udma_qp->sq.tail);
		ret = URMA_ENOMEM;
		goto out;
	}
	wqe_index = udma_qp->sq.head & (udma_qp->sq.wqe_cnt - 1);
	wqe = get_send_wqe(udma_qp, wqe_index);
	udma_qp->sq.wrid[wqe_index] = wr->user_ctx;

	if (tp_mode == URMA_TM_UM)
		ret = hns3_udma_set_um_wqe(udma_ctx, wqe, udma_qp, wr);
	else
		ret = hns3_udma_set_rc_wqe(wqe, udma_qp, wr, 0);
	if (ret)
		goto out;

	udma_qp->sq.head = udma_qp->sq.head + 1;

	if (udma_qp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_write_dca_wqe(udma_qp, wqe);

	hns3_udma_to_device_barrier();

	*udma_qp->sdb = udma_qp->sq.head;
	if (udma_qp->flush_status == HNS3_UDMA_FLUSH_STATU_ERR)
		exec_jfs_flush_cqe_cmd(udma_ctx, udma_qp);

out:
	if (udma_qp->flags & HNS3_UDMA_QP_CAP_DYNAMIC_CTX_ATTACH)
		hns3_udma_dca_stop_post(&udma_ctx->dca_ctx, udma_qp->dca_wqe.dcan);

	return ret;
}

int hns3_udma_u_flush_jfs(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr)
{
	struct hns3_udma_u_jfs *udma_jfs = to_hns3_udma_jfs(jfs);
	struct hns3_udma_qp *qp = udma_jfs->um_qp;
	int n_flushed;

	if (!udma_jfs->lock_free)
		(void)pthread_spin_lock(&udma_jfs->lock);

	for (n_flushed = 0; n_flushed < cr_cnt; ++n_flushed) {
		if (qp->sq.head == qp->sq.tail)
			break;

		hns3_udma_fill_scr(qp, cr + n_flushed);
	}

	if (!udma_jfs->lock_free)
		(void)pthread_spin_unlock(&udma_jfs->lock);

	return n_flushed;
}
