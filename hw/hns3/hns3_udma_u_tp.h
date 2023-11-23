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

#ifndef _UDMA_U_TP_H
#define _UDMA_U_TP_H

#include "hns3_udma_u_jfs.h"
#include "hns3_udma_u_jetty.h"
#include "urma_provider.h"

#define max(a, b) ((a) > (b) ? (a) : (b))

struct jfs_conn_node {
	struct connect_node	*tgt_conn_node;
	struct udma_jfs_qp_node	*qp_conn_node;
};

urma_status_t udma_u_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);
urma_status_t udma_u_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);
urma_status_t udma_u_advise_seg(urma_jfs_t *jfs,
				urma_target_seg_t *target_seg);
urma_status_t udma_u_unadvise_seg(urma_jfs_t *jfs, urma_target_seg_t *target_seg,
				  bool force);
#endif /* _UDMA_U_TP_H */
