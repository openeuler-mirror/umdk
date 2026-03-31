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

/* A common function to create urma components such as jfc, jfs, jfr etc. */
bondp_comp_t *bondp_create_comp(urma_context_t *ctx, bondp_comp_type_t type, void *cfg);
/* A common function to delete urma components created by bondp_create_comp */
urma_status_t bondp_delete_comp(void *comp, bondp_comp_type_t type);

int bdp_vjfce_info_table_create(bondp_hash_table_t *tbl, uint32_t size);

int bdp_vjfce_info_table_add(bondp_hash_table_t *tbl, bdp_vjfce_info_t *node);

void bdp_vjfce_info_table_del(bondp_hash_table_t *tbl, int key);

bdp_vjfce_info_t *bdp_vjfce_info_table_lookup(bondp_hash_table_t *tbl, int key);

void bdp_vjfce_info_table_destroy(bondp_hash_table_t *tbl);

void bondp_ack_multiple_die_jfc(urma_jfc_t *jfc[], uint32_t jfc_cnt);

void bdp_vjfce_info_table_close_fd(bondp_comp_t *bdp_comp);

int bondp_insert_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce);
void bondp_remove_p_jfce(urma_jfce_t *v_jfce, urma_jfce_t *p_jfce);

#endif // BONDP_COMP_H