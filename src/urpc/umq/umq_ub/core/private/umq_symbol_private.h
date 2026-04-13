/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UMQ dynamic symbol loading for URMA and UVS
 * Create: 2026-3-23
 * Note: Only used by UB transport mode
 */

#ifndef UMQ_SYMBOL_PRIVATE_H
#define UMQ_SYMBOL_PRIVATE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "urma_types.h"

// === URMA function pointer types - Device/Init ===
typedef urma_status_t (*urma_init_t)(urma_init_attr_t *conf);
typedef urma_status_t (*urma_uninit_t)(void);
typedef urma_device_t** (*urma_get_device_list_t)(int *num_devices);
typedef void (*urma_free_device_list_t)(urma_device_t **device_list);
typedef urma_eid_info_t* (*urma_get_eid_list_t)(urma_device_t *dev, uint32_t *cnt);
typedef void (*urma_free_eid_list_t)(urma_eid_info_t *eid_list);
typedef urma_status_t (*urma_query_device_t)(urma_device_t *dev, urma_device_attr_t *dev_attr);
typedef urma_context_t* (*urma_create_context_t)(urma_device_t *dev, uint32_t eid_index);
typedef urma_status_t (*urma_delete_context_t)(urma_context_t *ctx);

// === URMA function pointer types - JFC ===
typedef urma_jfc_t* (*urma_create_jfc_t)(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg);
typedef urma_status_t (*urma_delete_jfc_t)(urma_jfc_t *jfc);
typedef urma_status_t (*urma_rearm_jfc_t)(urma_jfc_t *jfc, bool solicited_only);
typedef int (*urma_poll_jfc_t)(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);
typedef int (*urma_wait_jfc_t)(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);
typedef void (*urma_ack_jfc_t)(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

// === URMA function pointer types - JFCE ===
typedef urma_jfce_t* (*urma_create_jfce_t)(urma_context_t *ctx);
typedef urma_status_t (*urma_delete_jfce_t)(urma_jfce_t *jfce);

// === URMA function pointer types - JFR ===
typedef urma_jfr_t* (*urma_create_jfr_t)(urma_context_t *ctx, urma_jfr_cfg_t *jfr_cfg);
typedef urma_status_t (*urma_delete_jfr_t)(urma_jfr_t *jfr);
typedef urma_status_t (*urma_modify_jfr_t)(urma_jfr_t *jfr, urma_jfr_attr_t *attr);

// === URMA function pointer types - Jetty ===
typedef urma_jetty_t* (*urma_create_jetty_t)(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg);
typedef urma_status_t (*urma_delete_jetty_t)(urma_jetty_t *jetty);
typedef urma_status_t (*urma_modify_jetty_t)(urma_jetty_t *jetty, urma_jetty_attr_t *attr);
typedef urma_status_t (*urma_bind_jetty_t)(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);
typedef urma_status_t (*urma_unbind_jetty_t)(urma_jetty_t *jetty);
typedef urma_target_jetty_t* (*urma_import_jetty_t)(urma_context_t *ctx, urma_rjetty_t *rjetty,
    urma_token_t *token_value);
typedef urma_status_t (*urma_unimport_jetty_t)(urma_target_jetty_t *target_jfr);
typedef int (*urma_flush_jetty_t)(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);
typedef urma_status_t (*urma_post_jetty_send_wr_t)(urma_jetty_t *jetty,
    urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);
typedef urma_status_t (*urma_post_jetty_recv_wr_t)(urma_jetty_t *jetty,
    urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);

// === URMA function pointer types - Segment ===
typedef urma_target_seg_t* (*urma_register_seg_t)(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg);
typedef urma_status_t (*urma_unregister_seg_t)(urma_target_seg_t *target_seg);
typedef urma_target_seg_t* (*urma_import_seg_t)(urma_context_t *ctx, urma_seg_t *seg,
    urma_token_t *token_value, uint64_t addr, urma_import_seg_flag_t flag);
typedef urma_status_t (*urma_unimport_seg_t)(urma_target_seg_t *tseg);

// === URMA function pointer types - Async Event ===
typedef urma_status_t (*urma_get_async_event_t)(urma_context_t *ctx, urma_async_event_t *event);
typedef void (*urma_ack_async_event_t)(urma_async_event_t *event);

// === URMA function pointer types - Log ===
typedef urma_status_t (*urma_log_set_level_t)(urma_vlog_level_t level);
typedef urma_status_t (*urma_register_log_func_t)(urma_log_cb_t func);
typedef urma_status_t (*urma_unregister_log_func_t)(void);

// === URMA function pointer types - Utility ===
typedef int (*urma_str_to_eid_t)(const char *buf, urma_eid_t *eid);

// === UVS function pointer types ===
typedef int (*uvs_get_path_set_t)(const void *src_bonding_eid, const void *dst_bonding_eid, uint32_t tp_type,
    bool multi_path, void *path_set);

// === DFX perf ===
typedef urma_status_t (*urma_start_perf_t)(void);
typedef urma_status_t (*urma_stop_perf_t)(void);
typedef urma_status_t (*urma_get_perf_info_t)(char *perf_buf, uint32_t *length);

// === Combined URMA + UVS symbol structure ===
typedef struct umq_symbol_urma {
    // Device/Init
    urma_init_t urma_init;
    urma_uninit_t urma_uninit;
    urma_get_device_list_t urma_get_device_list;
    urma_free_device_list_t urma_free_device_list;
    urma_get_eid_list_t urma_get_eid_list;
    urma_free_eid_list_t urma_free_eid_list;
    urma_query_device_t urma_query_device;
    urma_create_context_t urma_create_context;
    urma_delete_context_t urma_delete_context;

    // JFC
    urma_create_jfc_t urma_create_jfc;
    urma_delete_jfc_t urma_delete_jfc;
    urma_rearm_jfc_t urma_rearm_jfc;
    urma_poll_jfc_t urma_poll_jfc;
    urma_wait_jfc_t urma_wait_jfc;
    urma_ack_jfc_t urma_ack_jfc;

    // JFCE
    urma_create_jfce_t urma_create_jfce;
    urma_delete_jfce_t urma_delete_jfce;

    // JFR
    urma_create_jfr_t urma_create_jfr;
    urma_delete_jfr_t urma_delete_jfr;
    urma_modify_jfr_t urma_modify_jfr;

    // Jetty
    urma_create_jetty_t urma_create_jetty;
    urma_delete_jetty_t urma_delete_jetty;
    urma_modify_jetty_t urma_modify_jetty;
    urma_bind_jetty_t urma_bind_jetty;
    urma_unbind_jetty_t urma_unbind_jetty;
    urma_import_jetty_t urma_import_jetty;
    urma_unimport_jetty_t urma_unimport_jetty;
    urma_flush_jetty_t urma_flush_jetty;
    urma_post_jetty_send_wr_t urma_post_jetty_send_wr;
    urma_post_jetty_recv_wr_t urma_post_jetty_recv_wr;

    // Segment
    urma_register_seg_t urma_register_seg;
    urma_unregister_seg_t urma_unregister_seg;
    urma_import_seg_t urma_import_seg;
    urma_unimport_seg_t urma_unimport_seg;

    // Async Event
    urma_get_async_event_t urma_get_async_event;
    urma_ack_async_event_t urma_ack_async_event;

    // Log
    urma_log_set_level_t urma_log_set_level;
    urma_register_log_func_t urma_register_log_func;
    urma_unregister_log_func_t urma_unregister_log_func;

    // Utility
    urma_str_to_eid_t urma_str_to_eid;

    // UVS
    uvs_get_path_set_t uvs_get_path_set;

    // DFX
    urma_start_perf_t urma_start_perf;
    urma_stop_perf_t urma_stop_perf;
    urma_get_perf_info_t urma_get_perf_info;
} umq_symbol_urma_t;

// Get the global UMQ symbol instance
umq_symbol_urma_t *umq_symbol_urma(void);

// Load URMA and UVS symbols (called during initialization)
int umq_symbol_urma_load(umq_symbol_urma_t *sym);

#endif  // UMQ_SYMBOL_PRIVATE_H
