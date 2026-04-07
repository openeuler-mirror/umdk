/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond Component header
 * Author: Ma Chuan
 * Create: 2025-02-12
 * Note:
 * History: 2025-02-12  Create File
 */
#ifndef BONDP_COMP_H
#define BONDP_COMP_H
#include <sys/epoll.h>
#include "bondp_types.h"
#include "bondp_hash_table.h"

#define BOND_EPOLL_NUM (32)

typedef struct bdp_vjfce_info {
    hmap_node_t node;
    int key; // fd of pjfce
    urma_jfce_t *p_jfce;
} bdp_vjfce_info_t;


void bondp_ack_multiple_die_jfc(urma_jfc_t *jfc[], uint32_t jfc_cnt);

void bdp_vjfce_info_table_close_fd(bondp_jfce_t *bdp_jfce);

int bondp_insert_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce);
void bondp_remove_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce);

#endif // BONDP_COMP_H
