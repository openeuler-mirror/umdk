/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond provider types header file
 * Author: Ma Chuan
 * Create: 2025-02-05
 * Note:
 * History: 2025-02-05   Create File
 */
#ifndef BONDP_TYPES_H
#define BONDP_TYPES_H

#include <pthread.h>
#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#endif
#include "bondp_hash_table.h"
#include "bondp_wr_buf.h"
#include "topo_info.h"
#include "ub_list.h"
#include "urma_types.h"
#include "urma_ubagg.h"
#include <stdbool.h>

#define BONDP_MAX_NUM_JFRS            (10240)
#define BONDP_MAX_NUM_JETTYS          (10240)
#define BONDP_MAX_NUM_SEGS            (10240)
#define BONDP_MAX_NUM_RSEGS           (10240)
#define BONDP_MAX_WR_LIST_NUM         (300)
#define BONDP_MAX_SGE_NUM             (32)
#define PRIMARY_EID_NUM               (2)
#define PORT_EID_MAX_NUM_PER_DEV      (9)
#define PORT_EID_MAX_NUM              (PORT_EID_MAX_NUM_PER_DEV * PRIMARY_EID_NUM)
#define BONDP_MAX_WELL_KNOWN_JETTY_ID (1024)
/* Use single die primary eid and port eid to create urma_context */
#define SINGLE_DIE_DEVNUM             (11)
#define SINGLE_DIE_IODIE_NUM          (1)
#define URMA_JETTY_ID_FMT             "(" EID_FMT ", uasid: %u, id: %u)"
#define URMA_JETTY_ID_UNPACK(...)     __VA_ARGS__
#define URMA_JETTY_ID_ARGS(jetty_id)  URMA_JETTY_ID_UNPACK(EID_ARGS((jetty_id)->eid), \
                                                           (jetty_id)->uasid, (jetty_id)->id)

struct bondp_target_jetty;


typedef enum bondp_health_mode {
    HEALTH_MODE_BACKUP_CHECK,
    HEALTH_MODE_PRIMARY_CHECK,
} bondp_health_mode_t;

typedef struct bondp_health_sub_task {
    int local_idx;
    int target_idx;
    bool valid;
    bool probe_pending;
#ifndef __cplusplus
    atomic_bool link_ok;
#else
    std::atomic_bool link_ok;
#endif
    uint64_t user_ctx;
} bondp_health_sub_task_t;

typedef struct bondp_fallback_task {
    bool pending;
    bool local_rebuilt;
    bool req_sent;
    bool resp_received;
    bool relink_done;
    uint8_t req_seq;
    uint32_t remote_primary_pjetty_id;
    uint32_t primary_target_idx;
} bondp_fallback_task_t;

typedef struct bondp_health_task {
    struct bondp_target_jetty *bdp_tjetty;
    struct bondp_comp *bondp_jetty;
    uint64_t next_probe_ts_us;
    int primary_local_idx;
    int active_local_idx;
    bondp_health_mode_t mode;
    uint32_t backoff_cnt;
    bondp_fallback_task_t fallback_task;
    uint32_t vjetty_id;
    bondp_health_sub_task_t sub_tasks[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    hmap_node_t hmap_node;
} bondp_health_task_t;

typedef struct bondp_heath_check_ctx {
    void *check_buf;
    uint64_t check_buf_len;
    int health_check_fd;
    bondp_hash_table_t task_table;
    pthread_spinlock_t event_lock;
    struct ub_list event_list;
} bondp_heath_check_ctx_t;

typedef struct bondp_health_check_cfg {
    bool primary_backup_switch;             /* PrimaryBackupSwitch, default true */
    bool auto_fallback_primary;             /* AutoFallbackPrimary, default true */
    uint64_t health_check_start_ms;         /* HealthCheckStart, 100ms~3600000ms, default 2000ms */
    uint64_t health_check_interval_ms;      /* HealthCheckInterval, 1000ms~3600000ms, default 32000ms */
    uint64_t primary_check_start_ms;        /* PrimaryCheckStart, 100ms~3600000ms, default 2000ms */
    uint64_t primary_check_interval_ms;     /* PrimaryCheckInterval, 100ms~60000ms, default 1000ms */
    uint32_t primary_check_max_backoff_cnt; /* PrimaryCheckMaxBackoffCnt, 1~100, default 13 */
} bondp_health_check_cfg_t;

typedef struct bondp_health_thread_ctx {
    bool health_check_enable;
    int health_epoll_fd;
    pthread_t health_thread;
    bondp_health_check_cfg_t cfg;
    pthread_rwlock_t health_ctx_lock;
    struct ub_list health_ctx_list;
#ifndef __cplusplus
    atomic_bool health_thread_stop;
#else
    std::atomic_bool health_thread_stop;
#endif
} bondp_health_thread_ctx_t;

/** Process-granularity global variable */
typedef struct bondp_global_context {
    uint32_t pid;
    topo_map_t *topo_map;
    bool skip_load_topo;
    bondp_health_thread_ctx_t health_thread_ctx;
} bondp_global_context_t;

extern bondp_global_context_t *g_bondp_global_ctx;

typedef struct bondp_device {
    urma_device_t v_dev;
    urma_device_t p_devs[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
} bondp_device_t;

/**
 *  The first field is exposed to user.
 *  p_ctxs and p_devs stores neccesary parameters of slave devices.
 */
typedef struct bondp_context {
    urma_context_t v_ctx;
    urma_context_t *p_ctxs[URMA_UBAGG_DEV_MAX_NUM]; /* every unit is symmetrical. */
    /* This variable represents the maximum number of times all available devices need to be traversed. */
    /* In general mode, dev_num is the same as the number of non-empty devices in the first few positions. */
    /* In matrix server mode, dev_num is always PRIMARY_EID_NUM + PROT_EID_MAX_NUM, */
    /* and valid devices are confirmed through the non-null p_ctxs[i]. */
    int dev_num;
    bondp_bonding_mode_t bonding_mode;
    bondp_bonding_level_t bonding_level;
    topo_map_t *topo_map;
    /* Record the mapping from the locally created jetty's pjetty.jetty_id.id to the vjetty.jetty_id.id, */
    /* used to restore the local_id in CR. */
    bondp_hash_table_t p_vjetty_id_table;
    int real_async_fd; /* vcontex async_fd */
    bondp_heath_check_ctx_t bondp_heath_check_ctx;
    bondp_hash_table_t remote_v2p_token_id_table;
#ifndef __cplusplus
    atomic_ulong token_id_cnt;
#else
    std::atomic_ulong token_id_cnt;
#endif
} bondp_context_t;

typedef struct bondp_jfc {
    urma_jfc_t v_jfc;
    urma_jfc_t *p_jfc[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
    int lasted_polled_jfc_idx;
    urma_ref_t use_cnt; /* Initialize to 0 */
    wr_buf_t wr_buf;
    pthread_spinlock_t wr_lock;
} bondp_jfc_t;

typedef struct bondp_tseg {
    urma_target_seg_t v_tseg;
    urma_target_seg_t *p_tseg[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
    bondp_context_t *bondp_ctx;
    urma_ref_t use_cnt; /* Initialize to 0 */
    uint64_t p_orig_handle[URMA_UBAGG_DEV_MAX_NUM];
    uint64_t v_orig_handle;
} bondp_tseg_t;

typedef struct bondp_jfce {
    urma_jfce_t v_jfce;
    urma_jfce_t *p_jfce[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
    bondp_context_t *bondp_ctx;
    urma_ref_t use_cnt; /* Initialize to 0 */
} bondp_jfce_t;

typedef enum bondp_comp_type {
    BONDP_COMP_JFS,
    BONDP_COMP_JFR,
    BONDP_COMP_JETTY,
    BONDP_COMP_TYPE_MAX
} bondp_comp_type_t;

typedef enum pjetty_error_done_type {
    PJETTY_SUSPEND_DONE = 1,
    PJETTY_FLUSH_ERROR_DONE = 2
} pjetty_error_done_type_t;

/** A struct to mimic Polymorphism in creating/deleting some components of urma.
 * This will introduce extra memory cost due to union size taking the largest size.
 */
typedef struct bondp_comp {
    union {
        void *base;
        urma_jfs_t v_jfs;
        urma_jfr_t v_jfr;
        urma_jetty_t v_jetty;
    };
    union {
        void *members[URMA_UBAGG_DEV_MAX_NUM];
        urma_jfs_t *p_jfs[URMA_UBAGG_DEV_MAX_NUM];
        urma_jfr_t *p_jfr[URMA_UBAGG_DEV_MAX_NUM];
        urma_jetty_t *p_jetty[URMA_UBAGG_DEV_MAX_NUM];
    };
    int dev_num;
    uint32_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    uint32_t active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_count;
    bondp_context_t *bondp_ctx;
    uint8_t pjettys_error_done[URMA_UBAGG_DEV_MAX_NUM];
    bondp_hash_table_t v_conn_table;
    bondp_comp_type_t comp_type;
    urma_ref_t use_cnt; /* Initialize to 0 */
    // send
    bondp_jfc_t *send_jfc;
    bool valid[URMA_UBAGG_DEV_MAX_NUM];
    urma_target_seg_t *check_tseg[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t sqe_cnt[URMA_UBAGG_DEV_MAX_NUM];
    // recv
    bondp_jfc_t *recv_jfc;
    uint32_t rqe_cnt[URMA_UBAGG_DEV_MAX_NUM];
} bondp_comp_t;

typedef struct bondp_target_jetty {
    urma_target_jetty_t v_tjetty;
    urma_token_t import_token_value;
    bool import_token_valid;
    urma_target_jetty_t *p_tjetty[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    urma_target_seg_t *p_check_tseg[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    int local_dev_num;
    int target_dev_num;
    uint32_t local_active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_count;
    bool valid[URMA_UBAGG_DEV_MAX_NUM];
} bondp_target_jetty_t;

typedef struct bondp_import_target_seg {
    urma_target_seg_t v_tseg;
    urma_target_seg_t *p_tseg[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    int local_dev_num;
    int target_dev_num;
    bool is_reused;
    uint64_t p_orig_handle[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    uint64_t v_orig_handle;
} bondp_import_tseg_t;

typedef struct urma_bond_seg_info_out {
    urma_seg_t base;
    urma_seg_t slaves[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
} urma_bond_seg_info_out_t;

typedef struct urma_bond_id_info_out {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
    bool is_multipath; // deprecated
    uint8_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    bool is_health_check_enable;
    urma_bond_seg_info_out_t health_check_seg;
    bool connected[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
} urma_bond_id_info_out_t;

static inline bool is_valid_dev_num(int dev_num)
{
    return dev_num > 0 && dev_num <= URMA_UBAGG_DEV_MAX_NUM;
}

bool is_valid_ctx(bondp_context_t *ctx);

bool is_valid_bdp_tjetty(bondp_target_jetty_t *bdp_tjetty);

bool is_valid_import_tseg(bondp_import_tseg_t *rtseg);

/* Get index of matrix server port in p_ctx, p_jetty, etc. */
static inline int get_matrix_port_p_idx(int primary_idx, int port_idx)
{
    return primary_idx * PORT_EID_MAX_NUM_PER_DEV + port_idx + PRIMARY_EID_NUM;
}

static inline bool is_empty_eid(urma_eid_t *eid)
{
    return eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0;
}

static inline bool is_single_dev_mode(bondp_context_t *ctx)
{
    return ctx->bonding_mode == BONDP_BONDING_MODE_STANDALONE;
}
#endif // BONDP_TYPES_H
