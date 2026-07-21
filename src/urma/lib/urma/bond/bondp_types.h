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

#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#endif
#include <stdbool.h>

#include "bondp_hash_table.h"
#include "bondp_wr_buf.h"
#include "bondp_topo_info.h"
#include "ub_list.h"
#include "urma_private.h"
#include "urma_types.h"
#include "urma_ubagg.h"

#define BONDP_MAX_NUM_JETTYS          (10240)
#define BONDP_MAX_NUM_RSEGS           (10240)
#define BONDP_MAX_WR_LIST_NUM         (300)
#define PRIMARY_EID_NUM               (2)
#define PORT_EID_MAX_NUM_PER_DEV      (9)
#define PORT_EID_MAX_NUM              (PORT_EID_MAX_NUM_PER_DEV * PRIMARY_EID_NUM)
#define BONDP_MAX_WELL_KNOWN_JETTY_ID (1024)
/* Use single die primary eid and port eid to create urma_context */
#define SINGLE_DIE_DEVNUM             (11)
#define SINGLE_DIE_IODIE_NUM          (1)
#define URMA_JETTY_ID_FMT             "(" EID_FMT ", uasid=%u, id=%u)"
#define URMA_JETTY_ID_UNPACK(...)     __VA_ARGS__
#define URMA_JETTY_ID_ARGS(jetty_id)  URMA_JETTY_ID_UNPACK(EID_ARGS((jetty_id)->eid), \
                                                           (jetty_id)->uasid, (jetty_id)->id)
typedef urma_user_info_ext_hdr_t bondp_seg_ext_priv_t;
typedef urma_user_info_ext_hdr_t bondp_rjetty_ext_priv_t;

static inline bool bondp_seg_has_user_info(const urma_seg_t *seg)
{
    return seg != NULL && seg->attr.bs.has_user_info != 0;
}

static inline void bondp_seg_set_user_info(urma_seg_t *seg, bool enable)
{
    if (seg == NULL) {
        return;
    }

    if (enable) {
        seg->attr.bs.has_user_info = 1;
    } else {
        seg->attr.bs.has_user_info = 0;
    }
}

static inline bondp_seg_ext_priv_t *bondp_seg_get_priv_ext(urma_seg_t *seg)
{
    return (bondp_seg_ext_priv_t *)((uintptr_t)seg + sizeof(*seg));
}

static inline const bondp_seg_ext_priv_t *bondp_seg_get_priv_ext_const(const urma_seg_t *seg)
{
    return (const bondp_seg_ext_priv_t *)((uintptr_t)seg + sizeof(*seg));
}

static inline bondp_rjetty_ext_priv_t *bondp_rjetty_get_priv_ext(urma_rjetty_t *rjetty)
{
    return (bondp_rjetty_ext_priv_t *)((uintptr_t)rjetty + sizeof(*rjetty));
}

static inline const bondp_rjetty_ext_priv_t *bondp_rjetty_get_priv_ext_const(const urma_rjetty_t *rjetty)
{
    return (const bondp_rjetty_ext_priv_t *)((uintptr_t)rjetty + sizeof(*rjetty));
}

static inline bool bondp_rjetty_has_user_info(const urma_rjetty_t *rjetty)
{
    return rjetty != NULL && rjetty->flag.bs.has_user_info != 0;
}

typedef struct bondp_hc_ctx bondp_hc_ctx_t;
typedef struct bondp_fb_ctx bondp_fb_ctx_t;

/** Process-granularity global variable */
typedef struct bondp_global_context {
    uint32_t pid;
    bool skip_load_topo;
    bool enable_failover;
    bool enable_failback;
    bool enable_health_check;
    uint64_t health_check_interval_ms;
    uint32_t failover_route[IODIE_NUM][IODIE_NUM][URMA_ACTIVE_PORT_PER_DIE][URMA_FAILOVER_LINK_NUM];
    bondp_path_t path[IODIE_NUM * IODIE_NUM * URMA_ACTIVE_PORT_PER_DIE + 1];
    int max_cr_cnt_per_dev;
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
    /* Record the mapping from the locally created jetty's pjetty.jetty_id.id to the vjetty.jetty_id.id, */
    /* used to restore the local_id in CR. */
    bondp_hash_table_t p_vjetty_id_table;
    int real_async_fd; /* vcontex async_fd */
    bondp_hc_ctx_t *hc_ctx;
    bondp_fb_ctx_t *fb_ctx;
    bondp_hash_table_t remote_v2p_token_id_table;
    bool msn_enable;
    bool seg_cache_enable;
    uint32_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
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
#ifndef __cplusplus
    atomic_int lasted_polled_jfc_idx;
#else
    std::atomic_int lasted_polled_jfc_idx;
#endif
    uint32_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    uint32_t active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_count;
#ifndef __cplusplus
    atomic_uint fast_return_count;
#else
    std::atomic_uint fast_return_count;
#endif
    urma_ref_t use_cnt; /* Initialize to 0 */
} bondp_jfc_t;

typedef struct bondp_tseg {
    urma_target_seg_t v_tseg;
    urma_target_seg_t *p_tseg[URMA_UBAGG_DEV_MAX_NUM];
    int dev_num;
    bondp_context_t *bondp_ctx;
    urma_ref_t use_cnt;
#ifndef __cplusplus
    atomic_bool deleting;
#else
    std::atomic_bool deleting;
#endif
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
#ifndef __cplusplus
    atomic_bool deleting;
#else
    std::atomic_bool deleting;
#endif
    // send
    bool modify_to_error;
    pthread_spinlock_t send_lock;
    wr_buf_t send_wr_buf;
#ifndef __cplusplus
    atomic_bool valid[URMA_UBAGG_DEV_MAX_NUM];
    atomic_bool rebuild_done[URMA_UBAGG_DEV_MAX_NUM];
    atomic_uint msn;
#else
    std::atomic_bool valid[URMA_UBAGG_DEV_MAX_NUM];
    std::atomic_bool rebuild_done[URMA_UBAGG_DEV_MAX_NUM];
    std::atomic_uint msn;
#endif
#ifndef __cplusplus
    atomic_uint sqe_cnt[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
#else
    std::atomic_uint sqe_cnt[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
#endif
    // recv
    wr_buf_t recv_wr_buf;
    uint32_t rqe_cnt[URMA_UBAGG_DEV_MAX_NUM];
} bondp_comp_t;

typedef struct bondp_target_jetty {
    urma_target_jetty_t v_tjetty;
    urma_token_t import_token_value;
    bool import_token_valid;
    bool skip_import_vjetty;
    urma_target_jetty_t *p_tjetty[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    urma_target_seg_t *p_check_tseg[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    int local_dev_num;
    int target_dev_num;
    uint32_t local_active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t active_count;
#ifndef __cplusplus
    atomic_bool valid[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
#else
    std::atomic_bool valid[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
#endif
    urma_ref_t use_cnt;
    bool is_msn_enabled;
    bool hc_registered;
    uint32_t hc_node_idx;
    struct ub_list hc_entry;
} bondp_target_jetty_t;

typedef struct bondp_import_target_seg {
    urma_target_seg_t v_tseg;
    urma_target_seg_t *p_tseg[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    int local_dev_num;
    int target_dev_num;
    bool is_reused;
    bool skip_import_vseg;
    urma_ref_t use_cnt;
    uint64_t p_orig_handle[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    uint64_t v_orig_handle;
} bondp_import_tseg_t;

typedef struct urma_bond_seg_info_out {
    urma_seg_base_t slaves[URMA_UBAGG_DEV_MAX_NUM];
} urma_bond_seg_info_out_t;

typedef struct urma_bond_id_info_out {
    urma_jetty_id_t slave_id[URMA_UBAGG_DEV_MAX_NUM];
    bool is_msn_enabled;
    uint8_t enabled_indices[URMA_UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    bool is_health_check_enable;
    urma_bond_seg_info_out_t health_check_seg;
    bool connected[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
} urma_bond_id_info_out_t;

static inline void bondp_seg_to_base(const urma_seg_t *seg, urma_seg_base_t *base)
{
    base->ubva = seg->ubva;
    base->len = seg->len;
    base->attr.value = seg->attr.value;
    base->token_id = seg->token_id;
}

static inline void bondp_seg_base_to_seg(const urma_seg_base_t *base, urma_seg_t *seg)
{
    seg->ubva = base->ubva;
    seg->len = base->len;
    seg->attr.value = base->attr.value;
    seg->token_id = base->token_id;
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
