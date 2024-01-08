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

#include <sys/mman.h>
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_db.h"
#include "hns3_udma_u_tp.h"

static int alloc_jfs_conn_nodes(struct jfs_conn_node *conn_nodes)
{
	/* if advise success, node will be free in unadvise */
	conn_nodes->tgt_conn_node = (struct connect_node *)calloc(1, sizeof(struct connect_node));
	if (conn_nodes->tgt_conn_node == NULL) {
		URMA_LOG_ERR("failed to calloc tgt_conn_node\n");
		return ENOMEM;
	}

	conn_nodes->qp_conn_node = (struct udma_jfs_qp_node *)
				   calloc(1, sizeof(struct udma_jfs_qp_node));
	if (conn_nodes->qp_conn_node == NULL) {
		URMA_LOG_ERR("failed to calloc qp_conn_node\n");
		free(conn_nodes->tgt_conn_node);
		return ENOMEM;
	}
	return 0;
}

static void fill_qp_conn_node(struct jfs_conn_node *conn_nodes, urma_jfs_t *jfs,
			      urma_target_jetty_t *tjfr,
			      struct udma_create_tp_resp *udma_tp_resp)
{
	struct udma_u_jfs *udma_jfs;

	udma_jfs = to_udma_jfs(jfs);
	conn_nodes->tgt_conn_node->qp->jetty_id = udma_jfs->jfs_id;
	conn_nodes->tgt_conn_node->qp->flags = udma_tp_resp->cap_flags;
	conn_nodes->tgt_conn_node->qp->qp_num = udma_tp_resp->qpn;
	conn_nodes->tgt_conn_node->qp->path_mtu = (urma_mtu_t)udma_tp_resp->path_mtu;
	conn_nodes->qp_conn_node->jfs_qp = conn_nodes->tgt_conn_node->qp;
	conn_nodes->tgt_conn_node->qp->sq.priority = udma_tp_resp->priority;
	conn_nodes->tgt_conn_node->tjfr = (urma_target_jetty_t *)tjfr;
}

static urma_status_t udma_add_conn(pthread_rwlock_t *rwlock, struct udma_hmap *hmap,
				   uint32_t key, struct udma_hmap_node *hmap_node)
{
	(void)pthread_rwlock_wrlock(rwlock);
	if (!udma_hmap_insert(hmap, hmap_node, key)) {
		(void)pthread_rwlock_unlock(rwlock);
		return URMA_EEXIST;
	}
	(void)pthread_rwlock_unlock(rwlock);
	return URMA_SUCCESS;
}

static urma_status_t udma_add_qp_conn(urma_jfs_t *jfs,
				      const struct jfs_conn_node *conn_nodes)
{
	struct udma_jfs_qp_node *qp_conn_node;
	struct udma_u_context *udma_u_ctx;

	udma_u_ctx = to_udma_ctx(jfs->urma_ctx);
	qp_conn_node = conn_nodes->qp_conn_node;
	return udma_add_conn(&udma_u_ctx->jfs_qp_table_lock,
			     &udma_u_ctx->jfs_qp_table,
			     qp_conn_node->jfs_qp->qp_num, &qp_conn_node->node);
}

static struct udma_hmap_node *udma_delete_conn(pthread_rwlock_t *rwlock,
					       struct udma_hmap *hmap,
					       uint32_t key)
{
	struct udma_hmap_node *hmap_node;

	hmap_node = udma_table_first_with_hash(hmap, rwlock, key);
	if (hmap_node == NULL) {
		URMA_LOG_ERR("hmap find failed.\n");
		return hmap_node;
	}
	(void)pthread_rwlock_wrlock(rwlock);
	udma_hmap_remove(hmap, hmap_node);
	(void)pthread_rwlock_unlock(rwlock);

	return hmap_node;
}

static int mmap_dwqe(struct urma_context *urma_ctx, struct udma_qp *qp)
{
	struct udma_u_context *udma_ctx = to_udma_ctx(urma_ctx);
	off_t offset;

	offset = get_mmap_offset(qp->qp_num, udma_ctx->page_size,
				 UDMA_MMAP_DWQE_PAGE);
	qp->dwqe_page = mmap(NULL, UDMA_DWQE_PAGE_SIZE, PROT_WRITE,
			     MAP_SHARED, urma_ctx->dev_fd, offset);
	if (qp->dwqe_page == MAP_FAILED) {
		URMA_LOG_ERR("failed to mmap direct wqe page, QPN = %u.",
			     qp->qp_num);
		return EINVAL;
	}

	return 0;
}

static urma_status_t alloc_jfs_node(urma_target_jetty_t *tjfr, urma_jfs_t *jfs,
			  struct jfs_conn_node *conn_nodes,
			  struct connect_node_table *tbl)
{
	struct udma_hmap_node *tgt_hmap_node;
	struct udma_u_context *udma_u_ctx;
	int ret;

	tgt_hmap_node = udma_table_first_with_hash(&tbl->hmap, &tbl->rwlock,
						   udma_get_tgt_hash(&tjfr->id));
	if (tgt_hmap_node != NULL) {
		URMA_LOG_INFO("TP is existed!\n");
		return URMA_EEXIST;
	}

	ret = alloc_jfs_conn_nodes(conn_nodes);
	if (ret) {
		URMA_LOG_ERR("memory allocation failed.\n");
		return URMA_ENOMEM;
	}

	udma_u_ctx = to_udma_ctx(jfs->urma_ctx);
	conn_nodes->tgt_conn_node->qp = udma_alloc_qp(udma_u_ctx, &jfs->jfs_cfg,
						      jfs->jfs_id.id, false);
	if (!conn_nodes->tgt_conn_node->qp) {
		URMA_LOG_ERR("alloc qp for jfs node failed.\n");
		goto err_free_tgt_conn_node;
	}

	return URMA_SUCCESS;
err_free_tgt_conn_node:
	free(conn_nodes->qp_conn_node);
	free(conn_nodes->tgt_conn_node);

	return URMA_FAIL;
}

static void fill_udma_tp_info(struct udma_create_tp_ucmd *udma_tp_info,
			      struct connect_node *tgt_conn_node, urma_jfs_t *jfs,
			      urma_target_jetty_t *tjfr)
{
	udma_tp_info->ini_id.jfs_id = jfs->jfs_id.id;
	udma_tp_info->tgt_id.jfr_id = tjfr->id.id;
	udma_tp_info->buf_addr = (uint64_t)tgt_conn_node->qp->buf.buf;
	udma_tp_info->is_jetty = false;
	udma_tp_info->sdb_addr = (uintptr_t)tgt_conn_node->qp->sdb;
}

static int exec_jfs_advise_jfr_cmd(urma_jfs_t *jfs,
				   urma_target_jetty_t *tjfr,
				   struct jfs_conn_node *conn_nodes)
{
	struct udma_create_tp_ucmd udma_tp_info = {};
	struct udma_create_tp_resp udma_tp_resp = {};
	urma_cmd_udrv_priv_t udata = {};
	int ret;

	fill_udma_tp_info(&udma_tp_info, conn_nodes->tgt_conn_node, jfs, tjfr);
	udma_set_udata(&udata, &udma_tp_info, sizeof(udma_tp_info),
		       &udma_tp_resp, sizeof(udma_tp_resp));
	ret = urma_cmd_advise_jfr(jfs, tjfr, &udata);
	if (ret) {
		URMA_LOG_ERR("urma_cmd_advise_jfr failed\n");
		return ret;
	}

	fill_qp_conn_node(conn_nodes, jfs, tjfr, &udma_tp_resp);

	if (udma_tp_resp.cap_flags & UDMA_QP_CAP_DIRECT_WQE) {
		ret = mmap_dwqe(jfs->urma_ctx, conn_nodes->tgt_conn_node->qp);
		if (ret) {
			urma_cmd_unadvise_jfr(jfs, (urma_target_jetty_t *)tjfr);
			URMA_LOG_ERR("mmap dwqe failed\n");
		}
	}

	return ret;
}

static int verify_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
	struct udma_u_jfs *udma_jfs;

	if (jfs == NULL || tjfr == NULL) {
		URMA_LOG_ERR("jfs or tjfr is null!\n");
		return EINVAL;
	}

	udma_jfs = to_udma_jfs(jfs);
	if (udma_jfs->tp_mode != URMA_TM_RM) {
		URMA_LOG_ERR("Invalid jfs type.\n");
		return EINVAL;
	}

	return 0;
}

static void udma_remove_from_qp_table(struct udma_u_context *ctx, uint32_t qpn)
{
	struct udma_jfs_qp_node *qp_node;
	struct udma_hmap_node *hmap_node;

	hmap_node = udma_table_first_with_hash(&ctx->jfs_qp_table,
					  &ctx->jfs_qp_table_lock, qpn);
	if (hmap_node) {
		qp_node = to_udma_jfs_qp_node(hmap_node);
		(void)pthread_rwlock_wrlock(&ctx->jfs_qp_table_lock);
		udma_hmap_remove(&ctx->jfs_qp_table, hmap_node);
		(void)pthread_rwlock_unlock(&ctx->jfs_qp_table_lock);
		free(qp_node);
		return;
	}
	URMA_LOG_ERR("failed to find jetty qp.\n");
}

static void free_tgt_conn_node(struct udma_u_context *udma_u_ctx,
			       struct connect_node *tgt_conn_node)
{
	udma_free_sw_db(udma_u_ctx, tgt_conn_node->qp->sdb, UDMA_JFS_TYPE_DB);
	if (udma_u_ctx->dca_ctx.unit_size > 0)
		free(tgt_conn_node->qp->dca_wqe.bufs);
	else
		udma_free_buf(&tgt_conn_node->qp->buf);
	free(tgt_conn_node->qp->sq.wrid);
	free(tgt_conn_node->qp);
	free(tgt_conn_node);
}

urma_status_t udma_u_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
	struct udma_u_target_jetty *target_udma_jfr;
	struct connect_node_table *tjfr_tbl;
	struct jfs_conn_node conn_nodes;
	struct udma_u_jfs *udma_jfs;
	uint32_t tjfr_index;
	urma_status_t ret;

	if (verify_advise_jfr(jfs, tjfr)) {
		URMA_LOG_ERR("Invalid input parameters of advise_jfr.\n");
		return URMA_EINVAL;
	}

	udma_jfs = to_udma_jfs(jfs);
	target_udma_jfr = to_udma_target_jetty(tjfr);
	tjfr_tbl = &udma_jfs->tjfr_tbl;
	tjfr_index = udma_get_tgt_hash(&tjfr->id);

	ret = alloc_jfs_node(tjfr, jfs, &conn_nodes, tjfr_tbl);
	if (ret) {
		URMA_LOG_ERR("alloc jfs node failed.\n");
		return ret;
	}

	if (exec_jfs_advise_jfr_cmd(jfs, tjfr, &conn_nodes)) {
		URMA_LOG_ERR("exec_jfs_advise_jfr_cmd failed\n");
		goto err_free_jfs_node;
	}

	ret = udma_add_conn(&tjfr_tbl->rwlock, &tjfr_tbl->hmap, tjfr_index,
			   &conn_nodes.tgt_conn_node->hmap_node);
	if (ret) {
		URMA_LOG_INFO("jfr connection existed. jfs id = 0x%x, tjfr id = 0x%x\n",
				  jfs->jfs_id.id, tjfr->id.id);
		return ret;
	}

	ret = udma_add_qp_conn(jfs, &conn_nodes);
	if (ret) {
		URMA_LOG_ERR("failed add qp conn.\n");
		goto err_add_qp_conn;
	}
	(void)atomic_fetch_add(&target_udma_jfr->refcnt, 1);

	return URMA_SUCCESS;
err_add_qp_conn:
	udma_delete_conn(&tjfr_tbl->rwlock, &tjfr_tbl->hmap, tjfr_index);
	urma_cmd_unadvise_jfr(jfs, (urma_target_jetty_t *)tjfr);
err_free_jfs_node:
	free_tgt_conn_node(to_udma_ctx(jfs->urma_ctx), conn_nodes.tgt_conn_node);
	free(conn_nodes.qp_conn_node);

	return URMA_FAIL;
}

urma_status_t udma_u_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr)
{
	struct udma_u_target_jetty *udma_target_jfr = to_udma_target_jetty(tjfr);
	struct udma_hmap_node *tjfr_hmap_node;
	struct connect_node_table *tjfr_tbl;
	struct connect_node *tjfr_del_node;
	struct udma_u_context *udma_u_ctx;
	struct udma_u_jfs *udma_jfs;
	uint32_t tgt_index;
	int ret;

	ret = verify_advise_jfr(jfs, tjfr);
	if (ret) {
		URMA_LOG_ERR("Invalid input parameters of unadvise_jfr.\n");
		return URMA_EINVAL;
	}

	udma_jfs = to_udma_jfs(jfs);
	tjfr_tbl = &udma_jfs->tjfr_tbl;
	tgt_index = udma_get_tgt_hash(&tjfr->id);

	(void)atomic_fetch_sub(&udma_target_jfr->refcnt, 1);
	urma_cmd_unadvise_jfr(jfs, tjfr);
	tjfr_hmap_node = udma_delete_conn(&tjfr_tbl->rwlock, &tjfr_tbl->hmap,
					  tgt_index);
	if (tjfr_hmap_node == NULL) {
		URMA_LOG_ERR("tjfr_tbl hmap find failed.\n");
		return URMA_FAIL;
	}
	tjfr_del_node = CONTAINER_OF_FIELD(tjfr_hmap_node,
					   struct connect_node, hmap_node);

	udma_u_ctx = to_udma_ctx(jfs->urma_ctx);
	udma_remove_from_qp_table(udma_u_ctx, tjfr_del_node->qp->qp_num);

	if (tjfr_del_node->qp->flags & UDMA_QP_CAP_DIRECT_WQE)
		munmap(tjfr_del_node->qp->dwqe_page, UDMA_DWQE_PAGE_SIZE);

	free_tgt_conn_node(udma_u_ctx, tjfr_del_node);

	return URMA_SUCCESS;
}
