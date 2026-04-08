/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond datapth ops header file
 * Author: Ma Chuan
 * Create: 2025-02-12
 * Note:
 * History: 2025-02-12   Create File
 */

#ifndef BONDP_DATAPATH_H
#define BONDP_DATAPATH_H

#include "urma_types.h"

urma_status_t bondp_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
urma_status_t bondp_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);

urma_status_t bondp_post_jetty_recv_wr(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);
urma_status_t bondp_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);

int bondp_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
int bondp_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);

#endif // BONDP_DATAPATH_H
