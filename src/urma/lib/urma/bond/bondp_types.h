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

#include <stdbool.h>
#include "urma_types.h"
#include "urma_ubagg.h"
#include "bondp_hash_table.h"
#include "bondp_bitmap.h"
#include "topo_info.h"
#include "bondp_bitmap_id_store.h"

#define BONDP_MAX_NUM_JFRS (10240)
#define BONDP_MAX_NUM_JETTYS (10240)
#define BONDP_MAX_NUM_SEGS (10240)
#define BONDP_MAX_NUM_RSEGS (10240)
#define PRIMARY_EID_NUM (2)
#define PORT_EID_MAX_NUM_PER_DEV (9)
#define PORT_EID_MAX_NUM (PORT_EID_MAX_NUM_PER_DEV * PRIMARY_EID_NUM)
#define BONDP_MAX_WELL_KNOWN_JETTY_ID    (1024)
/* Use single die primary eid and port eid to create urma_context */
#define SINGLE_DIE_DEVNUM (11)
#define SINGLE_DIE_IODIE_NUM (1)
#define URMA_JETTY_ID_FMT "("EID_FMT", uasid: %u, id: %u)"
#define URMA_JETTY_ID_UNPACK(...) __VA_ARGS__
#define URMA_JETTY_ID_ARGS(jetty_id) URMA_JETTY_ID_UNPACK(EID_ARGS((jetty_id)->eid), \
    (jetty_id)->uasid, (jetty_id)->id)

/** Process-granularity global variable */
typedef struct bondp_global_context {
    uint32_t pid;
    topo_map_t *topo_map;
    bool skip_load_topo;
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
    union {
        urma_device_t *p_devs[URMA_UBAGG_DEV_MAX_NUM];
        struct {
            urma_device_t *primary_devs[PRIMARY_EID_NUM];
            urma_device_t *port_devs[PORT_EID_MAX_NUM];
        };
    };
    union {
        struct {
            urma_context_t *p_ctxs[URMA_UBAGG_DEV_MAX_NUM]; /* every unit is symmetrical. */
        };
        /* The following struct is valid only when the node is in matrix server */
        struct {
            urma_context_t *primary_ctxs[PRIMARY_EID_NUM];
            urma_context_t *port_ctxs[PORT_EID_MAX_NUM];   /* primary[0]->port[0:9], primary[1]->port[9:18] */
        };
    };
    /* This variable represents the maximum number of times all available devices need to be traversed. */
    /* In general mode, dev_num is the same as the number of non-empty devices in the first few positions. */
    /* In matrix server mode, dev_num is always PRIMARY_EID_NUM + PROT_EID_MAX_NUM, */
    /* and valid devices are confirmed through the non-null p_ctxs[i]. */
    int dev_num;
    topo_map_t *topo_map;               /* Only valid when the node is in matrix server */
    bondp_id_store_t ljetty_id_store;   /* alloc jetty_id.id and store urma_jetty pointer */
    bondp_bitmap_t token_id_bitmap;     /* alloc token_id used by urma_jetty */
    bondp_hash_table_t tjetty_id_table; /* match target jetty's pjetty_id to vjetty_id */
    /* Record the mapping from the locally created jetty's pjetty.jetty_id.id to the vjetty.jetty_id.id, */
    /* used to restore the local_id in CR. */
    bondp_hash_table_t p_vjetty_id_table;
    /* The mapping of pjetty_ids to vjetty_ids of all remote jettys that have been obtained. */
    bondp_hash_table_t remote_p2v_jetty_id_table;
    int real_async_fd; /* vcontex async_fd */
    bondp_hash_table_t remote_v2p_token_id_table;
    #ifndef __cplusplus
    atomic_ulong token_id_cnt;
    #else
    std::atomic_ulong token_id_cnt;
    #endif
} bondp_context_t;

typedef enum bondp_comp_type {
    BONDP_COMP_JFCE,
    BONDP_COMP_JFC,
    BONDP_COMP_JFS,
    BONDP_COMP_JFR,
    BONDP_COMP_JETTY,
    BONDP_COMP_SEGMENT, /* register segment */
    BONDP_COMP_TYPE_MAX
} bondp_comp_type_t;
/** A struct to mimic Polymorphism in creating/deleting some components of urma.
 * This will introduce extra memory cost due to union size taking the largest size.
 */
typedef struct bondp_comp {
    union {
        void *base;
        urma_jfce_t v_jfce;
        urma_jfc_t v_jfc;
        urma_jfs_t v_jfs;
        urma_jfr_t v_jfr;
        urma_jetty_t v_jetty;
        urma_target_seg_t v_tseg;
    };
    union {
        void *members[URMA_UBAGG_DEV_MAX_NUM];
        urma_jfce_t *p_jfce[URMA_UBAGG_DEV_MAX_NUM];
        urma_jfc_t *p_jfc[URMA_UBAGG_DEV_MAX_NUM];
        urma_jfs_t *p_jfs[URMA_UBAGG_DEV_MAX_NUM];
        urma_jfr_t *p_jfr[URMA_UBAGG_DEV_MAX_NUM];
        urma_jetty_t *p_jetty[URMA_UBAGG_DEV_MAX_NUM];
        urma_target_seg_t *p_tseg[URMA_UBAGG_DEV_MAX_NUM];
    };
    int dev_num;
    bondp_context_t *bondp_ctx;
    void *comp_ctx;
    bool is_multipath;
    bondp_comp_type_t comp_type;
    urma_ref_t use_cnt; /* Initialize to 0 */
    uint64_t p_orig_handle[URMA_UBAGG_DEV_MAX_NUM];
    uint64_t v_orig_handle;
} bondp_comp_t;

typedef struct bondp_target_jetty {
    urma_target_jetty_t v_tjetty;
    urma_target_jetty_t *p_tjetty[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_DEV_MAX_NUM];
    int local_dev_num;
    int target_dev_num;
    bool is_in_matrix_server;
    bool is_multipath;
    int direct_local_port[PORT_EID_MAX_NUM];
    int direct_tjetty_port[PORT_EID_MAX_NUM];
    int direct_route_num;
    bool local_valid[URMA_UBAGG_DEV_MAX_NUM];
    bool target_valid[URMA_UBAGG_DEV_MAX_NUM];
    urma_bond_id_info_out_t rvjetty_id_info;   /* remote jetty id info */
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

static inline bool is_valid_dev_num(int dev_num)
{
    return dev_num > 0 && dev_num <= URMA_UBAGG_DEV_MAX_NUM;
}

static inline bool is_in_matrix_server(bondp_context_t *ctx)
{
    return ctx->topo_map != NULL;
}

bool is_valid_ctx(bondp_context_t *ctx);

bool is_valid_bondp_comp(bondp_comp_t *comp);

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

static inline bool is_multipath_jetty(urma_jetty_t *jetty)
{
    return jetty->jetty_cfg.jfs_cfg.flag.bs.multi_path;
}

static inline bool is_multipath_comp(bondp_comp_t *bdp_comp)
{
    return bdp_comp->is_multipath;
}

static inline bool is_single_dev_mode(urma_context_t *ctx)
{
    return ctx->aggr_mode == URMA_AGGR_MODE_STANDALONE;
}
#endif // BONDP_TYPES_H
