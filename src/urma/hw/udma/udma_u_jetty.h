/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_JETTY_H__
#define __UDMA_U_JETTY_H__

#include "urma_types.h"
#include "udma_u_common.h"

#define INVALID_TPN UINT32_MAX
#define MAX_JETTY_IN_GRP 32

urma_jetty_t *udma_u_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg);
urma_status_t udma_u_delete_jetty(urma_jetty_t *jetty);
urma_status_t udma_u_delete_jetty_batch(urma_jetty_t **jetty, int jetty_cnt, urma_jetty_t **bad_jetty);
urma_status_t udma_u_unimport_jetty(urma_target_jetty_t *target_jetty);
urma_status_t udma_u_unbind_jetty(urma_jetty_t *jetty);
urma_status_t udma_u_post_jetty_send_wr(urma_jetty_t *urma_jetty,
					urma_jfs_wr_t *wr,
					urma_jfs_wr_t **bad_wr);
urma_status_t udma_u_post_jetty_recv_wr(urma_jetty_t *urma_jetty,
					urma_jfr_wr_t *wr,
					urma_jfr_wr_t **bad_wr);
urma_status_t udma_u_modify_jetty(urma_jetty_t *jetty,
				  urma_jetty_attr_t *jetty_attr);
urma_status_t udma_u_query_jetty(urma_jetty_t *jetty,
				 urma_jetty_cfg_t *cfg,
				 urma_jetty_attr_t *attr);
urma_jetty_grp_t *udma_u_create_jetty_grp(urma_context_t *ctx,
					  urma_jetty_grp_cfg_t *cfg);
urma_status_t udma_u_delete_jetty_grp(urma_jetty_grp_t *jetty_grp);
int udma_u_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);
int exec_jetty_create_cmd(urma_context_t *ctx, struct udma_u_jetty *jetty,
			  urma_jetty_cfg_t *cfg);
int init_jetty_trans_mode(struct udma_u_jetty *jetty,
			  urma_jetty_cfg_t *cfg);
int add_jetty_to_grp(struct udma_u_jetty *jetty, urma_jetty_cfg_t *cfg);
void remove_jetty_from_grp(struct udma_u_jetty *jetty);
urma_target_jetty_t *udma_u_import_jetty_ex(urma_context_t *ctx,
					    urma_rjetty_t *rjetty,
					    urma_token_t *token_value,
					    urma_active_tp_cfg_t *active_tp_cfg);
urma_status_t udma_u_bind_jetty_ex(urma_jetty_t *jetty,
				   urma_target_jetty_t *tjetty,
				   urma_active_tp_cfg_t *active_tp_cfg);
urma_status_t insert_jetty_node(struct udma_u_context *udma_ctx,
				struct udma_u_jetty *pointer);
void udma_u_jetty_table_remove(struct udma_u_context *udma_ctx,
				struct udma_u_jetty *jetty);
#endif /* __UDMA_U_JETTY_H__ */
