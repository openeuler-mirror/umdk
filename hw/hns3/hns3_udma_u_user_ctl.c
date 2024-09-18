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

#include <string.h>
#include "hns3_udma_u_common.h"
#include "hns3_udma_u_provider_ops.h"
#include "hns3_udma_u_jfc.h"
#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_jetty.h"
#include "hns3_udma_u_abi.h"
#include "hns3_udma_u_user_ctl_api.h"

static int hns3_udma_u_post_jfs_ex(urma_jfs_t *jfs, urma_jfs_wr_t *wr,
				   struct hns3_udma_post_and_ret_db_out *ex_out)
{
	urma_status_t ret = URMA_SUCCESS;
	struct hns3_udma_u_context *udma_ctx;
	struct hns3_udma_qp *udma_qp = NULL;
	struct hns3_udma_u_jfs *udma_jfs;
	urma_jfs_wr_t *it;

	udma_jfs = to_hns3_udma_jfs(jfs);
	udma_ctx = to_hns3_udma_ctx(jfs->urma_ctx);

	if (udma_jfs->tp_mode != URMA_TM_UM)
		return URMA_EINVAL;

	if (!udma_jfs->lock_free)
		(void)pthread_spin_lock(&udma_jfs->lock);

	for (it = wr; it != NULL; it = it->next) {
		udma_qp = udma_jfs->um_qp;
		if (!udma_qp) {
			HNS3_UDMA_LOG_ERR("failed to get qp, opcode = 0x%x.\n",
				     it->opcode);
			ret = URMA_EINVAL;
			ex_out->bad_wr = &it;
			goto out;
		}

		ret = hns3_udma_u_post_qp_wr_ex(udma_ctx, udma_qp, it, udma_jfs->tp_mode);
		if (ret) {
			ex_out->bad_wr = &it;
			goto out;
		}
	}

	ex_out->db_addr = (uint64_t)udma_ctx->db_addr;
	ex_out->db_data = (uint64_t)udma_qp->qp_num;
out:
	if (!udma_jfs->lock_free)
		(void)pthread_spin_unlock(&udma_jfs->lock);

	return ret == URMA_SUCCESS ? 0 : EINVAL;
}

static int hns3_udma_u_post_jetty_ex(urma_jetty_t *jetty, urma_jfs_wr_t *wr,
				     struct hns3_udma_post_and_ret_db_out *ex_out)
{
	struct hns3_udma_u_context *udma_ctx;
	struct hns3_udma_u_jetty *udma_jetty;
	struct hns3_udma_qp *udma_qp = NULL;
	urma_jfs_wr_t *it;
	urma_status_t ret;

	ret = URMA_SUCCESS;
	udma_jetty = to_hns3_udma_jetty(jetty);
	udma_ctx = to_hns3_udma_ctx(jetty->urma_ctx);

	if (!udma_jetty->jfs_lock_free)
		(void)pthread_spin_lock(&udma_jetty->lock);

	for (it = wr; it != NULL; it = it->next) {
		udma_qp = get_qp_of_jetty(udma_jetty, it);
		if (!udma_qp) {
			HNS3_UDMA_LOG_ERR("failed to find qp, opcode = 0x%x.\n",
				     it->opcode);
			ret = URMA_EINVAL;
			ex_out->bad_wr = &it;
			goto out;
		}

		ret = hns3_udma_u_post_qp_wr_ex(udma_ctx, udma_qp, it, udma_jetty->tp_mode);
		if (ret) {
			ex_out->bad_wr = &it;
			goto out;
		}
	}

	ex_out->db_addr = (uint64_t)udma_ctx->db_addr;
	ex_out->db_data = (uint64_t)udma_qp->qp_num;
out:
	if (!udma_jetty->jfs_lock_free)
		(void)pthread_spin_unlock(&udma_jetty->lock);

	return ret == URMA_SUCCESS ? 0 : EINVAL;
}

static int hns3_udma_u_post_send_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
				    urma_user_ctl_out_t *out)
{
	struct hns3_udma_post_and_ret_db_out ex_out = {};
	struct hns3_udma_post_and_ret_db_in *ex_in;
	int ret;

	if (in->len < sizeof(struct hns3_udma_post_and_ret_db_in)) {
		HNS3_UDMA_LOG_ERR("Invalid input: len %u.\n", in->len);
		return EINVAL;
	}

	if (!out->addr || out->len < sizeof(struct hns3_udma_post_and_ret_db_out)) {
		HNS3_UDMA_LOG_ERR("Invalid output: len %u or addr is null.\n", out->len);
		return EINVAL;
	}

	ex_in = (struct hns3_udma_post_and_ret_db_in *)in->addr;
	if (!ex_in->jfs || !ex_in->wr) {
		HNS3_UDMA_LOG_ERR("jetty or wr is invalid.\n");
		return EINVAL;
	}
	if (ex_in->type == JFS_TYPE) {
		ret = hns3_udma_u_post_jfs_ex(ex_in->jfs, ex_in->wr, &ex_out);
	} else if (ex_in->type == JETTY_TYPE) {
		ret = hns3_udma_u_post_jetty_ex(ex_in->jetty, ex_in->wr, &ex_out);
	} else {
		HNS3_UDMA_LOG_ERR("failed to post send ex, type = 0x%x.\n", ex_in->type);
		ret = EINVAL;
		goto out;
	}
	memcpy((void *)out->addr, &ex_out,
	       sizeof(struct hns3_udma_post_and_ret_db_out));
out:
	return ret;
}

static int hns3_udma_u_check_poe_cfg(struct hns3_udma_u_context *udma_ctx, uint8_t poe_channel,
				     struct hns3_udma_poe_init_attr *init_attr)
{
	if (!init_attr || !udma_ctx) {
		HNS3_UDMA_LOG_ERR("invalid ctx or attr\n");
		return EINVAL;
	}

	if (poe_channel >= udma_ctx->poe_ch_num) {
		HNS3_UDMA_LOG_ERR("invalid POE channel %u >= %u\n",
			     poe_channel, udma_ctx->poe_ch_num);
		return EINVAL;
	}

	return 0;
}

static int config_poe_channel(urma_context_t *ctx, uint8_t poe_channel,
			      struct hns3_udma_poe_init_attr *init_attr)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(ctx);
	struct hns3_udma_poe_info poe_channel_info = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	int ret;

	ret = hns3_udma_u_check_poe_cfg(udma_ctx, poe_channel, init_attr);
	if (ret)
		return EINVAL;

	poe_channel_info.poe_channel = poe_channel;
	poe_channel_info.en = !!init_attr->poe_addr;
	poe_channel_info.poe_addr = init_attr->poe_addr;

	in.opcode = (uint32_t)HNS3_UDMA_CONFIG_POE_CHANNEL;
	in.addr = (uint64_t)&poe_channel_info;
	in.len = (uint32_t)sizeof(struct hns3_udma_poe_info);

	ret = urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
	if (ret)
		HNS3_UDMA_LOG_ERR("failed to config POE channel %u, ret = %d\n",
			     poe_channel, ret);

	return ret;
}

static int hns3_udma_u_config_poe_channel(urma_context_t *ctx,
					  urma_user_ctl_in_t *in,
					  urma_user_ctl_out_t *out)
{
	struct hns3_udma_config_poe_channel_in poe_in = {};
	int ret;

	if ((in->len < sizeof(struct hns3_udma_config_poe_channel_in)) || (in->addr == NULL)) {
		HNS3_UDMA_LOG_ERR("fail check input in config poe channel.\n");
		return EINVAL;
	}
	memcpy(&poe_in, (void *)in->addr, sizeof(struct hns3_udma_config_poe_channel_in));
	if (poe_in.init_attr == NULL) {
		HNS3_UDMA_LOG_ERR("failed to config poe channel. init_attr is null\n");
		return EINVAL;
	}
	ret = config_poe_channel((urma_context_t *)ctx,
				 poe_in.poe_channel, poe_in.init_attr);

	return ret;
}

static int query_poe_channel(urma_context_t *ctx, uint8_t poe_channel,
			     struct hns3_udma_poe_init_attr *init_attr)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(ctx);
	struct hns3_udma_poe_info poe_channel_info_out = {};
	struct hns3_udma_poe_info poe_channel_info_in = {};
	urma_user_ctl_out_t out = {};
	urma_user_ctl_in_t in = {};
	urma_udrv_t udrv_data = {};
	int ret;

	ret = hns3_udma_u_check_poe_cfg(udma_ctx, poe_channel, init_attr);
	if (ret)
		return EINVAL;

	poe_channel_info_in.poe_channel = poe_channel;

	in.opcode = (uint32_t)HNS3_UDMA_QUERY_POE_CHANNEL;
	in.addr = (uint64_t)&poe_channel_info_in;
	in.len = (uint32_t)sizeof(struct hns3_udma_poe_info);
	out.addr = (uint64_t)&poe_channel_info_out;
	out.len = (uint32_t)sizeof(struct hns3_udma_poe_info);

	ret = urma_cmd_user_ctl(ctx, &in, &out, &udrv_data);
	if (ret) {
		HNS3_UDMA_LOG_ERR("failed to query POE channel %u, ret = %d\n",
			     poe_channel, ret);
		return ret;
	}
	init_attr->poe_addr = poe_channel_info_out.en ?
			      poe_channel_info_out.poe_addr : 0;

	return ret;
}

static int hns3_udma_u_query_poe_channel(urma_context_t *ctx, urma_user_ctl_in_t *in,
					 urma_user_ctl_out_t *out)
{
	struct hns3_udma_poe_init_attr *init_attr;
	uint8_t poe_channel;

	if (in->len < sizeof(uint8_t)) {
		HNS3_UDMA_LOG_ERR("Invalid input: len %u\n", in->len);
		return EINVAL;
	}

	if (!out->addr || out->len < sizeof(struct hns3_udma_user_ctl_query_poe_channel_out)) {
		HNS3_UDMA_LOG_ERR("Invalid output: len %u or addr is null\n", out->len);
		return EINVAL;
	}

	init_attr = ((struct hns3_udma_user_ctl_query_poe_channel_out *)out->addr)->init_attr;
	if (init_attr == NULL) {
		HNS3_UDMA_LOG_ERR("Invalid input: init attr is null\n");
		return EINVAL;
	}

	memcpy(&poe_channel, (void *)in->addr, sizeof(uint8_t));

	return query_poe_channel(ctx, poe_channel, init_attr);
}

static struct hns3_udma_qp *find_jfs_qp(struct hns3_udma_u_jfs *jfs)
{
	if (jfs->tp_mode == URMA_TM_UM)
		return jfs->um_qp;

	return NULL;
}

static int update_jfs_ci(urma_jfs_t *jfs, uint32_t wqe_cnt)
{
	struct hns3_udma_qp *qp;

	if (!jfs) {
		HNS3_UDMA_LOG_ERR("jfs is null.\n");
		return EINVAL;
	}

	if (wqe_cnt == 0) {
		HNS3_UDMA_LOG_ERR("input wqe num is zero.\n");
		return EINVAL;
	}

	qp = find_jfs_qp(to_hns3_udma_jfs(jfs));
	if (!qp) {
		HNS3_UDMA_LOG_ERR("can't find qp by jfs.\n");
		return EINVAL;
	}

	if (qp->sq.head - qp->sq.tail < wqe_cnt) {
		HNS3_UDMA_LOG_ERR("input wqe num is wrong, wqe_cnt = %d.\n", wqe_cnt);
		return EINVAL;
	}

	qp->sq.tail += wqe_cnt;
	return 0;
}

static struct hns3_udma_qp *find_jetty_qp(struct hns3_udma_u_jetty *jetty)
{
	if (jetty->tp_mode == URMA_TM_RC) {
		if (jetty->rc_node->tjetty == NULL) {
			HNS3_UDMA_LOG_ERR("The jetty not bind a remote jetty, jetty_id = %d.\n",
				     jetty->urma_jetty.jetty_id.id);
			return NULL;
		}

		return jetty->rc_node->qp;
	}

	if (jetty->tp_mode == URMA_TM_UM)
		return jetty->um_qp;

	return NULL;
}

static int update_jetty_ci(urma_jetty_t *jetty, uint32_t wqe_cnt)
{
	struct hns3_udma_qp *qp;

	if (!jetty) {
		HNS3_UDMA_LOG_ERR("jetty is null.\n");
		return EINVAL;
	}

	if (wqe_cnt == 0) {
		HNS3_UDMA_LOG_ERR("input wqe num is zero.\n");
		return EINVAL;
	}

	qp = find_jetty_qp(to_hns3_udma_jetty(jetty));
	if (!qp) {
		HNS3_UDMA_LOG_ERR("can't find qp by jetty.\n");
		return EINVAL;
	}

	if (qp->sq.head - qp->sq.tail < wqe_cnt) {
		HNS3_UDMA_LOG_ERR("input wqe num is wrong, wqe_cnt = %d.\n", wqe_cnt);
		return EINVAL;
	}

	qp->sq.tail += wqe_cnt;
	return 0;
}

static int hns3_udma_u_update_queue_ci(urma_context_t *ctx, urma_user_ctl_in_t *in,
				       urma_user_ctl_out_t *out)
{
	struct hns3_udma_update_queue_ci_in update_in = {};
	int ret;

	if (in->len < sizeof(struct hns3_udma_update_queue_ci_in)) {
		HNS3_UDMA_LOG_ERR("Invalid input: len %u\n", in->len);
		return EINVAL;
	}
	memcpy(&update_in, (void *)in->addr, sizeof(struct hns3_udma_update_queue_ci_in));
	if (update_in.type == JFS_TYPE) {
		ret = update_jfs_ci(update_in.jfs, update_in.wqe_cnt);
	} else if (update_in.type == JETTY_TYPE) {
		ret = update_jetty_ci(update_in.jetty, update_in.wqe_cnt);
	} else {
		HNS3_UDMA_LOG_ERR("failed to update ci, type = 0x%x.\n",
			     update_in.type);
		ret = EINVAL;
	}

	return ret;
}

static int hns3_udma_u_check_notify_attr(struct hns3_udma_jfc_notify_init_attr *notify_attr)
{
	switch (notify_attr->notify_mode) {
	case HNS3_UDMA_JFC_NOTIFY_MODE_4B_ALIGN:
	case HNS3_UDMA_JFC_NOTIFY_MODE_DDR_4B_ALIGN:
		break;
	case HNS3_UDMA_JFC_NOTIFY_MODE_64B_ALIGN:
	case HNS3_UDMA_JFC_NOTIFY_MODE_DDR_64B_ALIGN:
		HNS3_UDMA_LOG_ERR("Doesn't support notify mode %u\n",
			     notify_attr->notify_mode);
		return EINVAL;
	default:
		HNS3_UDMA_LOG_ERR("Invalid notify mode %u\n",
			     notify_attr->notify_mode);
		return EINVAL;
	}

	if (notify_attr->notify_addr & HNS3_UDMA_ADDR_4K_MASK) {
		HNS3_UDMA_LOG_ERR("Notify addr should be aligned to 4k.\n");
		return EINVAL;
	}

	return 0;
}

static int hns3_udma_u_check_jfc_attr_ex(struct hns3_udma_jfc_init_attr *attr)
{
	int ret = 0;

	if (attr->jfc_ex_mask != HNS3_UDMA_JFC_NOTIFY_OR_POE_CREATE_FLAGS) {
		HNS3_UDMA_LOG_ERR("Invalid comp mask %u\n", attr->jfc_ex_mask);
		return EINVAL;
	}

	switch (attr->create_flags) {
	case HNS3_UDMA_JFC_CREATE_ENABLE_POE_MODE:
		break;
	case HNS3_UDMA_JFC_CREATE_ENABLE_NOTIFY:
		ret = hns3_udma_u_check_notify_attr(&attr->notify_init_attr);
		break;
	default:
		HNS3_UDMA_LOG_ERR("Invalid create flags %u\n", attr->create_flags);
		return EINVAL;
	}

	return ret;
}

static urma_jfc_t *create_jfc_ex(urma_context_t *ctx,
				 struct hns3_udma_create_jfc_ex_in *cfg_ex)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(ctx);
	struct hns3_udma_create_jfc_resp resp = {};
	struct hns3_udma_create_jfc_ucmd cmd = {};
	urma_cmd_udrv_priv_t udata = {};
	struct hns3_udma_u_jfc *jfc;
	int ret;

	jfc = hns3_udma_u_create_jfc_common(cfg_ex->cfg, udma_ctx);
	if (!jfc)
		return NULL;

	cmd.buf_addr = (uintptr_t)jfc->buf.buf;
	cmd.db_addr = (uintptr_t)jfc->db;
	cmd.jfc_attr_ex.jfc_ex_mask = cfg_ex->attr->jfc_ex_mask;
	cmd.jfc_attr_ex.create_flags = cfg_ex->attr->create_flags;
	cmd.jfc_attr_ex.poe_channel = cfg_ex->attr->poe_channel;
	cmd.jfc_attr_ex.notify_addr = cfg_ex->attr->notify_init_attr.notify_addr;
	cmd.jfc_attr_ex.notify_mode = cfg_ex->attr->notify_init_attr.notify_mode;
	hns3_udma_set_udata(&udata, &cmd, sizeof(cmd), &resp, sizeof(resp));
	ret = urma_cmd_create_jfc(ctx, &jfc->urma_jfc, cfg_ex->cfg, &udata);
	if (ret) {
		HNS3_UDMA_LOG_ERR("urma cmd create jfc failed.\n");
		free_err_jfc(jfc, udma_ctx);
		return NULL;
	}
	jfc->ci = 0;
	jfc->arm_sn = 1;
	jfc->cqn = jfc->urma_jfc.jfc_id.id;
	jfc->caps_flag = resp.jfc_caps;

	return &jfc->urma_jfc;
}

static int hns3_udma_u_create_jfc_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
				     urma_user_ctl_out_t *out)
{
	struct hns3_udma_create_jfc_ex_in cfg_ex = {};
	urma_jfc_t *jfc;
	int ret;

	if (in->len < sizeof(struct hns3_udma_create_jfc_ex_in)) {
		HNS3_UDMA_LOG_ERR("Invalid input: len %u\n", in->len);
		return EINVAL;
	}

	if (!out->addr || out->len < sizeof(urma_jfc_t *)) {
		HNS3_UDMA_LOG_ERR("Invalid output: len %u or addr is null\n", out->len);
		return EINVAL;
	}
	memcpy(&cfg_ex, (void *)in->addr, sizeof(struct hns3_udma_create_jfc_ex_in));

	if ((cfg_ex.attr == NULL) || (cfg_ex.cfg == NULL))
		return EINVAL;
	ret = hns3_udma_u_check_jfc_attr_ex(cfg_ex.attr);
	if (ret) {
		HNS3_UDMA_LOG_ERR("Invalid jfc attr ex\n");
		return EINVAL;
	}

	jfc = create_jfc_ex((urma_context_t *)ctx, &cfg_ex);
	if (jfc == NULL)
		return EFAULT;

	memcpy((void *)out->addr, &jfc, sizeof(urma_jfc_t *));

	return 0;
}

static int hns3_udma_u_delete_jfc_ex(urma_context_t *ctx, urma_user_ctl_in_t *in,
				     urma_user_ctl_out_t *out)
{
	struct hns3_udma_user_ctl_delete_jfc_ex_in delete_jfc;
	urma_status_t ret;
	urma_jfc_t *jfc;

	if ((in->len < sizeof(struct hns3_udma_user_ctl_delete_jfc_ex_in)) || (in->addr == NULL)) {
		HNS3_UDMA_LOG_ERR("Invalid input: len %u or addr is NULL\n", in->len);
		return EINVAL;
	}
	memcpy((void *)&delete_jfc, (void *)in->addr,
		sizeof(struct hns3_udma_user_ctl_delete_jfc_ex_in));
	jfc = (urma_jfc_t *)delete_jfc.jfc;
	ret = hns3_udma_u_delete_jfc(jfc);
	if (ret)
		return EFAULT;

	return 0;
}

static int hns3_udma_u_query_hw_id(urma_context_t *ctx, urma_user_ctl_in_t *in,
				   urma_user_ctl_out_t *out)
{
	struct hns3_udma_u_context *udma_ctx = to_hns3_udma_ctx(ctx);
	struct hns3_udma_query_hw_id_out ex_out = {};

	if ((out->addr == NULL) || (out->len < sizeof(struct hns3_udma_query_hw_id_out))) {
		HNS3_UDMA_LOG_ERR("Invalid output: len %u, or addr is NULL.\n", out->len);
		return EINVAL;
	}
	ex_out.chip_id = udma_ctx->chip_id;
	ex_out.die_id = udma_ctx->die_id;
	ex_out.func_id = udma_ctx->func_id;
	memcpy((void *)out->addr, &ex_out, sizeof(struct hns3_udma_query_hw_id_out));

	return 0;
}

static void hns3_udma_u_get_jetty_info_set_info_out(struct hns3_u_udma_get_jetty_info_out *info_out,
						    struct hns3_udma_qp *qp,
						    struct hns3_udma_u_context *udma_ctx)
{
	info_out->queue_addr = qp->buf.buf + qp->sq.offset;
	info_out->ext_sge_addr = qp->buf.buf + qp->ex_sge.offset;
	info_out->user_ctx_addr = (void *)qp->sq.wrid;
	info_out->head_idx = &qp->sq.head;
	info_out->sl = qp->sq.priority;
	info_out->queue_length = qp->sq.wqe_cnt;
	info_out->ext_sge_length = qp->ex_sge.sge_cnt;
	info_out->user_ctx_length = qp->sq.wqe_cnt;
	info_out->db_addr = udma_ctx->uar + HNS3_UDMA_DB_CFG0_OFFSET;
	info_out->dwqe_addr = qp->dwqe_page;
	info_out->ext_sge_tail_addr = get_send_sge_ex(qp, qp->ex_sge.sge_cnt);
	info_out->sge_idx = &qp->next_sge;
	info_out->dwqe_enable = !!(qp->flags & HNS3_UDMA_QP_CAP_DIRECT_WQE);
}

int hns3_udma_u_get_jetty_info(urma_context_t *ctx, urma_user_ctl_in_t *in,
			       urma_user_ctl_out_t *out)
{
	struct hns3_u_udma_get_jetty_info_in *info_in;
	struct hns3_udma_u_jetty *udma_jetty;
	struct hns3_udma_u_context *udma_ctx;
	struct hns3_udma_u_jfs *udma_jfs;
	struct hns3_udma_qp *qp;

	if ((in->len < sizeof(struct hns3_u_udma_get_jetty_info_in)) || (in->addr == NULL) ||
		(out->addr == NULL) || (out->len < sizeof(struct hns3_u_udma_get_jetty_info_out))) {
		HNS3_UDMA_LOG_ERR("Invalid input for getting jetty info.\n");
		return EINVAL;
	}

	info_in = (struct hns3_u_udma_get_jetty_info_in *)in->addr;

	if (!info_in->jetty) {
		HNS3_UDMA_LOG_ERR("Jetty is null.\n");
		return EINVAL;
	}

	if (info_in->type == JFS_TYPE && info_in->jfs) {
		udma_jfs = to_hns3_udma_jfs(info_in->jfs);
		qp = udma_jfs->um_qp;
	} else if (info_in->type == JETTY_TYPE && info_in->jetty) {
		udma_jetty = to_hns3_udma_jetty(info_in->jetty);
		if (udma_jetty->tp_mode == URMA_TM_RC)
			qp = udma_jetty->rc_node->qp;
		else
			qp = udma_jetty->um_qp;
	} else {
		HNS3_UDMA_LOG_ERR("Invalid parameter for query jetty/jfs info.\n");
		return EINVAL;
	}

	if (!qp) {
		HNS3_UDMA_LOG_ERR("qp is NULL for getting jetty/jfs info.\n");
		return EINVAL;
	}

	udma_ctx = to_hns3_udma_ctx(ctx);

	hns3_udma_u_get_jetty_info_set_info_out((struct hns3_u_udma_get_jetty_info_out *)out->addr,
						qp, udma_ctx);

	return 0;
}

typedef int (*hns3_udma_u_user_ctl_ops)(urma_context_t *ctx, urma_user_ctl_in_t *in,
					urma_user_ctl_out_t *out);

static hns3_udma_u_user_ctl_ops g_hns3_udma_u_user_ctl_ops[] = {
	[HNS3_UDMA_U_USER_CTL_POST_SEND_AND_RET_DB] = hns3_udma_u_post_send_ex,
	[HNS3_UDMA_U_USER_CTL_CONFIG_POE_CHANNEL] = hns3_udma_u_config_poe_channel,
	[HNS3_UDMA_U_USER_CTL_QUERY_POE_CHANNEL] = hns3_udma_u_query_poe_channel,
	[HNS3_UDMA_U_USER_CTL_CREATE_JFC_EX] = hns3_udma_u_create_jfc_ex,
	[HNS3_UDMA_U_USER_CTL_DELETE_JFC_EX] = hns3_udma_u_delete_jfc_ex,
	[HNS3_UDMA_U_USER_CTL_UPDATE_QUEUE_CI] = hns3_udma_u_update_queue_ci,
	[HNS3_UDMA_U_USER_CTL_QUERY_HW_ID] = hns3_udma_u_query_hw_id,
	[HNS3_UDMA_U_USER_CTL_GET_JETTY_INFO] = hns3_udma_u_get_jetty_info,
};

int hns3_udma_u_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in,
		    urma_user_ctl_out_t *out)
{
	if (in->opcode >= HNS3_UDMA_U_USER_CTL_MAX) {
		HNS3_UDMA_LOG_ERR("invalid opcode: 0x%x.\n", (int)in->opcode);
		return URMA_ENOPERM;
	}
	if ((in->opcode != HNS3_UDMA_U_USER_CTL_QUERY_HW_ID) && (in->addr == NULL)) {
		HNS3_UDMA_LOG_ERR("input addr invalid in urma_user_ctl.\n");
		return EINVAL;
	}
	return g_hns3_udma_u_user_ctl_ops[in->opcode](ctx, in, out);
}
