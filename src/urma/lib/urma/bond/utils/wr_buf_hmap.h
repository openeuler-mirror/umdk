/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider WR buffer hmap header. WR buffer depends on this hmap abstraction.
 * Author: Ma Chuan
 * Create: 2025-02-21
 * Note:
 * History: 2025-02-21
 */
#ifndef WR_BUF_TABLE_H
#define WR_BUF_TABLE_H

#include "urma_types.h"
#include "bondp_hash_table.h"

#define WR_BUF_HMAP_FUNC_CONTINUE (1)
#define WR_BUF_HMAP_FUNC_SUCCESS (0)

typedef hmap_node_t wr_buf_hmap_handle;

typedef struct wr_buf_extra_value {
    uint64_t user_ctx;       /* Original user ctx */
    /* jfs wr only */
    urma_jfs_wr_flag_t flag; /* Original jfs flag */
    uint32_t msn;            /* Current msn of tmp jfs wr */
    void *v_conn;            /* Should be NOT NULL */
    int send_idx;            /* Current  */
    int target_idx;          /* Current */
    urma_transport_mode_t trans_mode;
    urma_opcode_t original_opcode; /* Original jfs opcode before bond rewrites */
    urma_target_jetty_t *vtjetty; /* Original vtjetty of jfs wr */
} wr_buf_extra_value_t;

typedef struct wr_buf_node {
    uint32_t key;
    union {
        void *wr;
        urma_jfs_wr_t *jfs_wr;
        urma_jfr_wr_t *jfr_wr;
    };
    wr_buf_extra_value_t value;
    wr_buf_hmap_handle hh;
} wr_buf_node_t;

typedef struct ub_hmap wr_buf_hmap_t;

typedef int (*wr_buf_hmap_delete_wr_func_t)(void *);
typedef int (*wr_buf_hmap_visit_node_func_t)(wr_buf_node_t *, void *);

int wr_buf_hmap_create(wr_buf_hmap_t *map, size_t size);
/**
 * User need to remove and release all data in the map manually
 * e.x. using wr_buf_hmap_traverse_and_remove
*/
void wr_buf_hmap_destroy(wr_buf_hmap_t *map);

int wr_buf_hmap_insert(wr_buf_hmap_t *map, uint32_t key, void *wr, wr_buf_extra_value_t *value);

int wr_buf_hmap_remove(wr_buf_hmap_t *map, uint32_t key);

wr_buf_node_t *wr_buf_hmap_get(wr_buf_hmap_t *map, uint32_t key);
/** Remove key-value pair from map and return the node
 * This function gives out the ownership of wr_buf_node
 * User needs to free the return value
*/
wr_buf_node_t *wr_buf_hmap_move_out(wr_buf_hmap_t *map, uint32_t key);
/**
 * Traverse the hmap with function func
 * and remove all nodes from the hmap
 * Traverse will be interrupted if the function returns value other than WR_BUF_HMAP_FUNC_SUCCESS
 * This function will free space of node but will not free wr in the node
 * User need to free wr in input function
*/
void wr_buf_hmap_traverse_and_remove(wr_buf_hmap_t *map, wr_buf_hmap_delete_wr_func_t func);
/**
 * Skip current node when ret == WR_BUF_HMAP_FUNC_CONTINUE
 * End traverse when ret != WR_BUF_HMAP_FUNC_SUCCESS && ret != WR_BUF_HMAP_FUNC_CONTINUE
 * Visited nodes with ret == WR_BUF_HMAP_FUNC_SUCCESS will be removed from the map and released,
 * other nodes will be retained in the map
 * This function will free space of node but will not free wr in the node
 * User need to free wr in input function
*/
void wr_buf_hmap_traverse_and_remove_with_args(wr_buf_hmap_t *map, wr_buf_hmap_visit_node_func_t func, void *args);

uint32_t wr_buf_hmap_count(wr_buf_hmap_t *map);
#endif // __WR_BUF_TABLE_H__