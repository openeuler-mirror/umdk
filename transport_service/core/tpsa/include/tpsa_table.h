/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa table header file
 * Author: Ji Lei
 * Create: 2023-07-03
 * Note:
 * History: 2023-07-03 tpsa table create search header
 */

#ifndef TPSA_TABLE_H
#define TPSA_TABLE_H

#include <semaphore.h>

#include "urma_types.h"
#include "ub_hmap.h"
#include "ub_list.h"
#include "tpsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_TPF_DEV_TABLE_SIZE          100
#define TPSA_FE_TABLE_SIZE          100
#define TPSA_VTP_TABLE_SIZE          20000
#define TPSA_SIP_IDX_TABLE_SIZE  1024 /* 1823: 16; 1650: 1024; 1636: N/A */
#define TPSA_EID_IDX_TABLE_SIZE  1024
#define TPSA_MAX_PORT_CNT 16
#define MAX_VTP_NODE_STATE 4

typedef struct vport_key {
    char tpf_name[UVS_MAX_DEV_NAME];
    uint16_t fe_idx;
} __attribute__((packed)) vport_key_t;

typedef vport_key_t live_migrate_table_key_t;

/* Record the vtp node status of the migrate destination and migrateThird */
typedef enum vtp_node_state {
    STATE_NORMAL = 0,
    STATE_READY,
    STATE_MIGRATING,
    STATE_ROLLBACK
} vtp_node_state_t;

typedef struct tpsa_tpg_info {
    uint32_t tp_cnt;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    uint32_t tpgn;
} tpsa_tpg_info_t;

/*
 * rm_vtp table
 * only worker thread operate, lock no need
 * the vtp table is diveded by virtual machine; the primary key is fe_idx, the secondary key is src_eid+dst_edi+location
 * primary table is fe_table. the secondary table is rm_vtp_table
 * Whether it is client or server, src_eid represents its own, dst_eid represents the peer
 */
typedef struct rm_vtp_table_key {
    urma_eid_t src_eid;
    urma_eid_t dst_eid;
} __attribute__((packed)) rm_vtp_table_key_t;

typedef struct rm_vtp_table_entry {
    struct ub_hmap_node node;
    rm_vtp_table_key_t key;
    uint32_t vtpn;
    uint32_t tpgn;
    uint32_t vice_tpgn; /* for live migration scenario */
    bool valid;
    uint32_t location;
    uint32_t src_jetty_id;
    uint32_t eid_index;
    uint32_t upi;
    bool migration_status; /* true means that this node has been migrated to the destination */
    vtp_node_state_t node_status;
    tpsa_tpg_info_t *tpg_param;
    bool share_mode;
    uint32_t use_cnt;
} rm_vtp_table_entry_t;

typedef struct rm_vtp_table {
    struct ub_hmap hmap;
    pthread_rwlock_t vtp_table_lock;
} rm_vtp_table_t;

/*
 * rc_vtp table
 * only worker thread operate, lock no need
 * Whether it is client or server, src_eid represents its own, dst_eid represents the peer, jetty_id represent the peer
 */
typedef struct rc_vtp_table_key {
    urma_eid_t dst_eid;
    uint32_t jetty_id;
} __attribute__((packed)) rc_vtp_table_key_t;

typedef struct rc_vtp_table_entry {
    struct ub_hmap_node node;
    rc_vtp_table_key_t key;
    uint32_t vtpn;
    uint32_t tpgn;
    uint32_t vice_tpgn; /* for live migration scenario */
    bool valid;
    uint32_t location;
    urma_eid_t src_eid;
    uint32_t src_jetty_id;
    uint32_t eid_index;
    uint32_t upi;
    bool migration_status;
    vtp_node_state_t node_status;
} rc_vtp_table_entry_t;

typedef struct rc_vtp_table {
    struct ub_hmap hmap;
} rc_vtp_table_t;

/*
 * um_vtp table
 * only worker thread operate, lock no need
 */
typedef struct um_vtp_table_key {
    urma_eid_t src_eid;
    urma_eid_t dst_eid;
} um_vtp_table_key_t;

typedef struct um_vtp_table_entry {
    struct ub_hmap_node node;
    um_vtp_table_key_t key;
    uint32_t vtpn;
    uint32_t utp_idx;
    uint32_t use_cnt;
    bool migration_status;
    uint32_t upi;
    vtp_node_state_t node_status;
} um_vtp_table_entry_t;

typedef struct um_vtp_table {
    struct ub_hmap hmap;
} um_vtp_table_t;

/*
 * clan_vtp table
 * only worker thread operate, lock no need
 */
typedef struct clan_vtp_table_key {
    urma_eid_t dst_eid;
} clan_vtp_table_key_t;

typedef struct clan_vtp_table_entry {
    struct ub_hmap_node node;
    clan_vtp_table_key_t key;
    uint32_t vtpn;
    uint32_t ctp_idx;
    uint32_t use_cnt;
    bool migration_status;
} clan_vtp_table_entry_t;

typedef struct clan_vtp_table {
    struct ub_hmap hmap;
} clan_vtp_table_t;

/* This died_vtp hash table is used to record entries using the same died in the vtp table. */
typedef struct deid_vtp_table_key {
    urma_eid_t dst_eid;
    uint32_t upi;
    tpsa_transport_mode_t trans_mode;
} __attribute__((packed)) deid_vtp_table_key_t;

typedef struct deid_vtp_table_entry {
    struct ub_hmap_node node;
    deid_vtp_table_key_t key;
    struct ub_list vtp_list; /* List of vtp entries which has the same deid */
    pthread_spinlock_t vtp_list_lock;
} deid_vtp_table_entry_t;

typedef struct tpsa_lm_vtp_entry {
    tpsa_transport_mode_t trans_mode;

    union {
        rm_vtp_table_entry_t *rm_entry;
        rc_vtp_table_entry_t *rc_entry;
        um_vtp_table_entry_t *um_entry;
    } content;
}tpsa_lm_vtp_entry_t;

typedef struct deid_vtp_node {
    struct ub_list node; /* Add to vtp_list */
    tpsa_lm_vtp_entry_t entry;
} deid_vtp_node_t;

typedef struct died_vtp_table {
    struct ub_hmap hmap;
} deid_vtp_table_t;

typedef struct fe_table_entry {
    struct ub_hmap_node node;
    vport_key_t key; /* the key of tha hash table */
    rm_vtp_table_t rm_vtp_table; /* a secondary hash table with function entity as the primary key */
    rc_vtp_table_t rc_vtp_table;
    um_vtp_table_t um_vtp_table;
    clan_vtp_table_t clan_vtp_table;
    bool fe_rebooted; /* VF rebooted, need to clean all resource */
    bool stop_proc_vtp; /* true means that uvs receive the msg TPSA_MSG_STOP_PROC_VTP_MSG */
    bool link_ready; /* true means that the destination of live migration has completed link reconstruction. */
    bool full_migrate; /* true means that full migration for the first time  */
    struct timespec time_start; /* The beginning of iterative migration */
    uint32_t vtp_migrate_num; /* Used to record the number of vtp nodes that have been live migrated */
    uvs_net_addr_t src_uvs_ip; /* the ip of migrate source */
    char lm_dev_name[UVS_MAX_DEV_NAME]; /* Record the vfid and dev_name of the migrate source */
    uint16_t lm_fe_idx;
} fe_table_entry_t;

typedef struct fe_table {
    struct ub_hmap hmap;
    bool clean_res; /* There is rebooted vf, need to clean resource */
    pthread_rwlock_t rwlock;
} fe_table_t;

/*
 * rm tpg table
 * only worker thread operate, lock no need
 */
typedef struct rm_tpg_table_key {
    uvs_net_addr_info_t dip;
} __attribute__((packed)) rm_tpg_table_key_t;

typedef enum tpsa_tpg_status {
    TPSA_TPG_LOOKUP_NULL = 1,
    TPSA_TPG_LOOKUP_IN_PROGRESS = 2,
    TPSA_TPG_LOOKUP_EXIST = 3,
    TPSA_TPG_LOOKUP_ALREADY_BIND = 4,
} tpsa_tpg_status_t;

typedef struct rm_tpg_table_entry {
    struct ub_hmap_node node;
    rm_tpg_table_key_t key;
    int type;
    uint32_t tpgn;
    uint32_t tp_cnt;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    tpsa_tpg_status_t status;
    uint32_t use_cnt;
} rm_tpg_table_entry_t;

typedef struct rm_tpg_table {
    struct ub_hmap hmap;
} rm_tpg_table_t;

/*
 * rc tpg table
 * only worker thread operate, lock no need
 */
typedef struct rc_tpg_table_key {
    urma_eid_t deid;
    uint32_t djetty_id;
} __attribute__((packed)) rc_tpg_table_key_t;

typedef struct rc_tpg_entry {
    struct ub_hmap_node node;
    rc_tpg_table_key_t key;
    int type;
    uint32_t tpgn;
    uint32_t vice_tpgn;
    uint32_t tp_cnt;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    uint32_t vice_tpn[TPSA_MAX_TP_CNT_IN_GRP];
    tpsa_tpg_status_t status;
    uint32_t use_cnt;
    uint32_t ljetty_id;
    urma_eid_t leid;
} rc_tpg_table_entry_t;

typedef struct rc_tpg_table {
    struct ub_hmap hmap;
} rc_tpg_table_t;

/*
 * jetty peer table
 * only worker thread operate, lock no need
 */
typedef struct jetty_peer_table_key {
    uint32_t ljetty_id;
    urma_eid_t seid;
} __attribute__((packed)) jetty_peer_table_key_t;

typedef struct jetty_peer_table_entry {
    struct ub_hmap_node node;
    jetty_peer_table_key_t key;
    uint32_t djetty_id;
    urma_eid_t deid;
} jetty_peer_table_entry_t;

typedef struct jetty_peer_table {
    struct ub_hmap hmap;
} jetty_peer_table_t;

/*
 * utp table
 * only worker thread operate, lock no need
 */
typedef struct utp_table_key {
    uvs_net_addr_info_t sip;
    uvs_net_addr_info_t dip;
} utp_table_key_t;

typedef struct utp_table_entry {
    struct ub_hmap_node node;
    utp_table_key_t key;
    uint32_t utp_idx;
    uint32_t use_cnt;
} utp_table_entry_t;

typedef struct utp_table {
    struct ub_hmap hmap;
} utp_table_t;

/*
 * ctp table
 * only worker thread operate, lock no need
 */
typedef struct ctp_table_key {
    uvs_net_addr_info_t dip;
} ctp_table_key_t;

typedef struct ctp_table_entry {
    struct ub_hmap_node node;
    ctp_table_key_t key;
    uint32_t ctp_idx;
    uint32_t use_cnt;
} ctp_table_entry_t;

typedef struct ctp_table {
    struct ub_hmap hmap;
} ctp_table_t;

/*
 * vport idx table
 * worker and uvs_admin thread operate, need lock
 */
typedef struct tpsa_ueid {
    uint32_t upi;
    urma_eid_t eid;
    bool is_valid;
} tpsa_ueid_t;

typedef struct tpsa_ueid_cfg {
    urma_eid_t eid;
    uint32_t upi;
    uint32_t eid_index;
} tpsa_ueid_cfg_t;

typedef union vport_entry_mask {
    struct {
        uint64_t dev_name            : 1;
        uint64_t fe_idx              : 1;
        uint64_t sip_idx             : 1;
        uint64_t tp_cnt              : 1;
        uint64_t flow_label          : 1;
        uint64_t oor_cnt             : 1;
        uint64_t retry_num           : 1;
        uint64_t retry_factor        : 1;
        uint64_t ack_timeout         : 1;
        uint64_t dscp                : 1;
        uint64_t cc_pattern_idx      : 1;
        uint64_t data_udp_start      : 1;
        uint64_t ack_udp_start       : 1;
        uint64_t udp_range           : 1;
        uint64_t hop_limit           : 1;
        uint64_t port                : 1;
        uint64_t mn                  : 1;
        uint64_t loop_back           : 1;
        uint64_t ack_resp            : 1;
        uint64_t bonding             : 1;
        uint64_t oos_cnt             : 1;
        uint64_t rc_cnt              : 1;
        uint64_t rc_depth            : 1;
        uint64_t slice               : 1;
        uint64_t eid                 : 1;
        uint64_t eid_index           : 1;
        uint64_t upi                 : 1;
        uint64_t pattern             : 1;
        uint64_t virtualization      : 1;
        uint64_t min_jetty_cnt       : 1;
        uint64_t max_jetty_cnt       : 1;
        uint64_t min_jfr_cnt         : 1;
        uint64_t max_jfr_cnt         : 1;
        uint64_t flag_um_en          : 1;
        uint64_t flag_share_mode     : 1;
        uint64_t reserved            : 29;
    } bs;
    uint64_t value;
} vport_entry_mask_t;

typedef struct vport_table_entry {
    struct ub_hmap_node node;
    vport_key_t key;
    bool deleting;
    vport_entry_mask_t mask;
    uint32_t sip_idx;
    uint32_t tp_cnt;
    tpsa_tp_mod_cfg_t tp_cfg;
    tpsa_rc_cfg_t rc_cfg;
    uint32_t ueid_max_cnt;
    tpsa_ueid_t ueid[TPSA_EID_IDX_TABLE_SIZE];
    uint32_t pattern;
    uint32_t virtualization;
    uint32_t min_jetty_cnt;
    uint32_t max_jetty_cnt;
    uint32_t min_jfr_cnt;
    uint32_t max_jfr_cnt;
    sem_t *sem;
} vport_table_entry_t;

typedef struct vport_table {
    struct ub_hmap hmap;
    bool clean_res; /* there is deleting vport, need clean resource */
    pthread_rwlock_t rwlock;
} vport_table_t;

/*
 * vport param
 * to cache vport table, avoid frequent find operation
 */
typedef struct vport_param {
    uint32_t sip_idx;
    uint32_t tp_cnt;
    tpsa_tp_mod_cfg_t tp_cfg;
    tpsa_rc_cfg_t rc_cfg;
    uint32_t pattern;
} vport_param_t;

typedef union dip_table_modify_mask {
    struct {
        uint32_t eid            : 1;
        uint32_t upi            : 1;
        uint32_t uvs_ip         : 1;
        uint32_t net_addr       : 1;
        uint32_t reserved       : 28;
    } bs;
    uint32_t value;
} dip_table_modify_mask_t;

typedef struct dip_table_key {
    urma_eid_t deid;
    uint32_t upi;
} dip_table_key_t;

typedef struct dip_table_entry {
    struct ub_hmap_node node;
    dip_table_key_t key; /* key */
    uvs_net_addr_t peer_uvs_ip; /* peer tps server address */
    uvs_net_addr_info_t netaddr;
} dip_table_entry_t;

typedef struct dip_table {
    struct ub_hmap hmap;
    bool tbl_refresh;
    dip_table_entry_t *refresh_entry; /* Record the entry which dip has changed */
    uvs_net_addr_info_t new_netaddr; /* The underly ip before refresh */
    pthread_rwlock_t rwlock;
} dip_table_t;

/* wait table is used to store create vtp requests.
   when a create finish, we will wakeup wait msg and reuse
   tpg to create vtp. */
typedef struct rm_wait_table_key {
    uvs_net_addr_info_t dip;
} rm_wait_table_key_t;

typedef struct rm_wait_table_entry {
    struct ub_hmap_node node;
    rm_wait_table_key_t key;
    tpsa_create_param_t cparam;
} rm_wait_table_entry_t;

typedef struct rm_wait_table {
    struct ub_hmap hmap;
} rm_wait_table_t;

typedef struct rc_wait_table_key {
    urma_eid_t deid;
    uint32_t djetty_id;
} __attribute__((packed)) rc_wait_table_key_t;

typedef struct rc_wait_table_entry {
    struct ub_hmap_node node;
    rc_wait_table_key_t key;
    tpsa_create_param_t cparam;
} rc_wait_table_entry_t;

typedef struct rc_wait_table {
    struct ub_hmap hmap;
} rc_wait_table_t;

/*
 * tp state table
 * only worker thread operate, lock no need
 */
typedef struct tp_state_table_key {
    uint32_t tpn;
    uvs_net_addr_info_t sip;
} __attribute__((packed)) tp_state_table_key_t;

typedef enum tp_exception_state {
    INITIATOR_TP_STATE_RESET = 0,
    INITIATOR_TP_STATE_RTS,
    INITIATOR_TP_STATE_SUSPENDED,
    INITIATOR_TP_STATE_ERR,
    TARGET_TP_STATE_RTR,
    TARGET_TP_STATE_ERR,
    INITIATOR_TP_STATE_DEL,
    TARGET_TP_STATE_DEL,
    TP_STATE_INIT,
} tp_exception_state_t;

typedef struct tp_state_table_entry {
    struct ub_hmap_node node;
    tp_state_table_key_t key;
    tp_exception_state_t tp_exc_state;
    uint32_t tpgn;
    uint32_t tpn;
    uint32_t tx_psn;
    uint32_t rx_psn;
    uint32_t peer_tpn;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uvs_net_addr_info_t dip;
    uvs_net_addr_t peer_uvs_ip;
    uint64_t timestamp[TPSA_SUSPEND2ERROR_CNT];
    uint32_t suspend_cnt;
} tp_state_table_entry_t;

typedef struct tp_state_table {
    struct ub_hmap hmap;
} tp_state_table_t;

/*
 * tpg state table
 * only worker thread operate, lock no need
 */
typedef struct tpg_state_table_key {
    uint32_t tpgn;
    uvs_net_addr_info_t sip;
} __attribute__((packed)) tpg_state_table_key_t;

typedef enum tpg_exception_state {
    TPG_STATE_INIT = 0,
    TPG_STATE_DEL = 1,
} tpg_exception_state_t;

typedef struct tpg_state_table_entry {
    struct ub_hmap_node node;
    tpg_state_table_key_t key;
    tpg_exception_state_t tpg_exc_state;
    uvs_net_addr_info_t dip;
    uvs_net_addr_t peer_uvs_ip;
    uint32_t tpgn;
    uint32_t tp_cnt;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    uint32_t tp_flush_cnt;
} tpg_state_table_entry_t;

typedef struct tpg_state_table {
    struct ub_hmap hmap;
} tpg_state_table_t;

typedef struct tpf_dev_table_key {
    char dev_name[UVS_MAX_DEV_NAME];
} tpf_dev_table_key_t;

typedef struct sip_table_entry {
    char dev_name[UVS_MAX_DEV_NAME];
    uvs_net_addr_info_t addr;
    uint32_t prefix_len;
    uint8_t port_cnt;
    uint8_t port_id[TPSA_MAX_PORT_CNT];
    uvs_mtu_t mtu;
    char netdev_name[UVS_MAX_DEV_NAME];
    bool used;
} sip_table_entry_t;

typedef struct sip_table {
    sip_table_entry_t entries[TPSA_SIP_IDX_TABLE_SIZE];
} sip_table_t;

typedef struct tpf_dev_table_entry {
    struct ub_hmap_node node;
    tpf_dev_table_key_t key;
    tpsa_device_feat_t dev_fea;
    tpsa_cc_entry_t cc_array[TPSA_CC_IDX_TABLE_SIZE];
    uint32_t cc_entry_cnt;
    sip_table_t *sip_table;
} tpf_dev_table_entry_t;

typedef struct tpf_dev_table {
    struct ub_hmap hmap;
    pthread_rwlock_t rwlock;
} tpf_dev_table_t;

typedef struct tpsa_vtp_table_index {
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t peer_jetty;
    uint32_t local_jetty;
    uint32_t location;
    vport_key_t fe_key;
    uint32_t upi;
    bool isLoopback; /* for the secne sip==dip */
    /* On the basis of sip==dip,for rm mode, sig_loop is true, which means seid==deid */
    /* for rc mode, sig_loop is true, which means seid=deid and local_jetty==peer_jetty */
    bool sig_loop;
    tpsa_transport_mode_t trans_mode;
    bool share_mode;
    /* use only for non-share_mode with rm mode */
    tpsa_tpg_info_t tpg_param;
    uint32_t use_cnt;
} tpsa_vtp_table_index_t;

typedef struct tpsa_vtp_table_param {
    uint32_t vtpn;
    uint32_t tpgn;
    bool valid;
    uint32_t location;
    uint32_t local_jetty;
    uint32_t eid_index;
    uint32_t upi;
    urma_eid_t local_eid;
    bool share_mode;
    /* only use for non-share_mode with RM mode */
    tpsa_tpg_info_t tpg_param;
} tpsa_vtp_table_param_t;

typedef struct tpsa_um_vtp_table_param {
    uint32_t vtpn;
    uint32_t utp_idx;
    uint32_t upi;
} tpsa_um_vtp_table_param_t;

typedef struct tpsa_clan_vtp_table_param {
    uint32_t vtpn;
    uint32_t ctp_idx;
} tpsa_clan_vtp_table_param_t;

typedef struct tpsa_tpg_table_index {
    uvs_net_addr_info_t dip;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t ljetty_id;
    uint32_t djetty_id;
    uint32_t upi;
    bool isLoopback;
    tpsa_transport_mode_t trans_mode;
    bool sig_loop;
    uvs_net_addr_info_t sip;
    uint32_t tp_cnt;
} tpsa_tpg_table_index_t;

typedef struct tpg_table_param {
    int type;
    uint32_t tpgn;
    uint32_t tp_cnt;
    uint32_t tpn[TPSA_MAX_TP_CNT_IN_GRP];
    tpsa_tpg_status_t status;
    uint32_t use_cnt;
    uint32_t ljetty_id;
    urma_eid_t leid;
    uvs_net_addr_info_t dip;
    bool isLoopback;
    bool live_migrate;
} tpsa_tpg_table_param_t;

typedef struct jetty_peer_table_param {
    urma_eid_t seid;
    urma_eid_t deid;
    uint32_t ljetty_id;
    uint32_t djetty_id;
} jetty_peer_table_param_t;

typedef struct wait_restored_entry {
    struct ub_list node;
    tpsa_restored_vtp_entry_t entry;
    struct timespec start_timeval;
} wait_restored_entry_t;

typedef struct wait_restored_list {
    struct ub_list list;
} wait_restored_list_t;

/*
 * fe table opts
 */
int fe_table_create(fe_table_t *fe_table);
fe_table_entry_t *fe_table_lookup(fe_table_t *fe_table, vport_key_t *key);
fe_table_entry_t *fe_table_add(fe_table_t *fe_table, vport_key_t *key);
void fe_table_remove(fe_table_t *fe_table, fe_table_entry_t *fe_entry);

/*
 * rc vtp table opts
 */
rc_vtp_table_entry_t *rc_vtp_table_lookup(rc_vtp_table_t *rc_vtp_table, rc_vtp_table_key_t *key);
int rc_vtp_table_add(deid_vtp_table_t *deid_vtp_table, fe_table_entry_t *entry,
                     rc_vtp_table_key_t *key, tpsa_vtp_table_param_t *vtp_table_data);
void rc_vtp_table_destroy(rc_vtp_table_t *rc_vtp_table);

/*
 * rm vtp table opts
 */
rm_vtp_table_entry_t *rm_vtp_table_lookup(rm_vtp_table_t *rm_vtp_table, rm_vtp_table_key_t *key);
int rm_vtp_table_add(deid_vtp_table_t *deid_vtp_table, fe_table_entry_t *entry,
                     rm_vtp_table_key_t *key, tpsa_vtp_table_param_t *vtp_table_data);
void rm_vtp_table_destroy(rm_vtp_table_t *rm_vtp_table);

/*
 * um vtp table opts
 */
um_vtp_table_entry_t *um_vtp_table_lookup(um_vtp_table_t *um_vtp_table, um_vtp_table_key_t *key);
int um_vtp_table_add(deid_vtp_table_t *deid_vtp_table, fe_table_entry_t *entry, um_vtp_table_key_t *key,
                     tpsa_um_vtp_table_param_t *uparam);
int um_vtp_table_remove(fe_table_t *fe_table, deid_vtp_table_t *deid_vtp_table,
                        vport_key_t *fe_key, um_vtp_table_key_t *vtp_key);
void um_vtp_table_destroy(um_vtp_table_t *um_vtp_table);

/*
* clan vtp table opts
*/
clan_vtp_table_entry_t *clan_vtp_table_lookup(clan_vtp_table_t *clan_vtp_table, clan_vtp_table_key_t *key);
int clan_vtp_table_add(clan_vtp_table_t *clan_vtp_table, clan_vtp_table_key_t *key,
                       uint32_t vtpn, uint32_t ctp_idx);
int clan_vtp_table_remove(fe_table_t *fe_table, vport_key_t *fe_key, clan_vtp_table_key_t *vtp_key);
void clan_vtp_table_destroy(clan_vtp_table_t *clan_vtp_table);
/*
 * rm tpg table opts
 */
int rm_tpg_table_create(rm_tpg_table_t *rm_tpg_table);
rm_tpg_table_entry_t *rm_tpg_table_lookup(rm_tpg_table_t *rm_tpg_table, rm_tpg_table_key_t *key);
int rm_tpg_table_add(rm_tpg_table_t *rm_tpg_table, rm_tpg_table_key_t *key, tpsa_tpg_table_param_t *param);
void rm_tpg_table_destroy(rm_tpg_table_t *rm_tpg_table);

/*
 * rc tpg table opts
 */
int rc_tpg_table_create(rc_tpg_table_t *rc_tpg_table);
rc_tpg_table_entry_t *rc_tpg_table_lookup(rc_tpg_table_t *rc_tpg_table, rc_tpg_table_key_t *key);
int rc_tpg_table_add(rc_tpg_table_t *rc_tpg_table, rc_tpg_table_key_t *key, tpsa_tpg_table_param_t *param);
void rc_tpg_table_destroy(rc_tpg_table_t *rc_tpg_table);

/*
 * utp table opts
 */
int utp_table_create(utp_table_t *utp_table);
utp_table_entry_t *utp_table_lookup(utp_table_t *utp_table, utp_table_key_t *key);
int utp_table_add(utp_table_t *utp_table, utp_table_key_t *key, uint32_t utp_idx);
int utp_table_remove(utp_table_t *utp_table, utp_table_key_t *key);
void utp_table_destroy(utp_table_t *utp_table);

/*
* ctp table opts
*/
int ctp_table_create(ctp_table_t *ctp_table);
ctp_table_entry_t *ctp_table_lookup(ctp_table_t *ctp_table, ctp_table_key_t *key);
int ctp_table_add(ctp_table_t *ctp_table, ctp_table_key_t *key, uint32_t ctp_idx);
int ctp_table_remove(ctp_table_t *ctp_table, ctp_table_key_t *key);
void ctp_table_destroy(ctp_table_t *ctp_table);

/*
 * vport table opts
 */
int vport_table_create(vport_table_t *vport_table);
vport_table_entry_t *vport_table_lookup(vport_table_t *vport_table,
    vport_key_t *key);
int vport_table_add(vport_table_t *vport_table, vport_table_entry_t *add_entry);
int vport_table_remove(vport_table_t *vport_table, vport_key_t *key);
int vport_table_lookup_by_ueid(vport_table_t *vport_table, uint32_t upi, urma_eid_t *eid,
    vport_table_entry_t *ret_entry);
int vport_table_lookup_by_ueid_return_key(vport_table_t *vport_table, uint32_t upi, urma_eid_t *eid,
                                          vport_key_t *key, uint32_t *eid_index);
int vport_set_deleting(vport_table_t *vport_table, vport_key_t *key, sem_t *sem);
void vport_update_clean_res(vport_table_t *vport_table);
bool vport_in_cleaning_proc(vport_table_t *vport_table, vport_key_t *key);

void vport_table_destroy(vport_table_t *vport_table);

/*
 * tpf dev table opts
 */
int tpf_dev_table_create(tpf_dev_table_t *tpf_dev_table);
void tpf_dev_table_destroy(tpf_dev_table_t *tpf_dev_table);
int tpf_dev_table_add(tpf_dev_table_t *tpf_dev_table, tpf_dev_table_key_t *key, tpf_dev_table_entry_t *add_entry);
int tpf_dev_table_remove(tpf_dev_table_t *tpf_dev_table, tpf_dev_table_key_t *key);
tpf_dev_table_entry_t *tpf_dev_table_lookup(tpf_dev_table_t *tpf_dev_table, tpf_dev_table_key_t *key);

/*
 * jetty_peer table opts
 */
int jetty_peer_table_create(jetty_peer_table_t *jetty_peer_table);
jetty_peer_table_entry_t *jetty_peer_table_lookup(jetty_peer_table_t *jetty_peer_table,
                                                  jetty_peer_table_key_t *key);
int jetty_peer_table_add(jetty_peer_table_t *jetty_peer_table, jetty_peer_table_param_t *parm);
int jetty_peer_table_remove(jetty_peer_table_t *jetty_peer_table, jetty_peer_table_key_t *key);
void jetty_peer_table_destroy(jetty_peer_table_t *jetty_peer_table);

/*
 * rm wait table opts
 */
int rm_wait_table_create(rm_wait_table_t *rm_wait_table);
rm_wait_table_entry_t *rm_wait_table_lookup(rm_wait_table_t *rm_table, rm_wait_table_key_t *key);
int rm_wait_table_add(rm_wait_table_t *rm_table, rm_wait_table_key_t *key,
                      rm_wait_table_entry_t *add_entry);
int rm_wait_table_remove(rm_wait_table_t *rm_table, rm_wait_table_key_t *key);
int rm_wait_table_pop(rm_wait_table_t *rm_table, rm_wait_table_key_t *key,
                      rm_wait_table_entry_t *pop_entry);
void rm_wait_table_destroy(rm_wait_table_t *rm_wait_table);

/*
 * rc wait table opts
 */
int rc_wait_table_create(rc_wait_table_t *rc_wait_table);
rc_wait_table_entry_t *rc_wait_table_lookup(rc_wait_table_t *rc_table, rc_wait_table_key_t *key);
int rc_wait_table_add(rc_wait_table_t *rc_table, rc_wait_table_key_t *key,
                      rc_wait_table_entry_t *add_entry);
int rc_wait_table_remove(rc_wait_table_t *rc_table, rc_wait_table_key_t *key);
int rc_wait_table_pop(rc_wait_table_t *rc_table, rc_wait_table_key_t *key,
                      rc_wait_table_entry_t *pop_entry);
void rc_wait_table_destroy(rc_wait_table_t *rc_wait_table);

/*
 * dip table opts
 */
int dip_table_create(dip_table_t *dip_table);
dip_table_entry_t *dip_table_lookup(dip_table_t *dip_table, dip_table_key_t *key);
int dip_table_add(dip_table_t *dip_table, dip_table_key_t *key, dip_table_entry_t *add_entry);
int dip_table_remove(dip_table_t *dip_table, dip_table_key_t *key);
int dip_table_modify(dip_table_t *dip_table, dip_table_key_t *old_key,
    dip_table_entry_t *new_entry, dip_table_modify_mask_t mask);

void dip_table_destroy(dip_table_t *dip_table);

/*
 * ueid table opts
 */
tpsa_ueid_t *vport_table_lookup_ueid(vport_table_t *vport_table, vport_key_t *key, uint32_t ueid_index);
int vport_table_add_ueid(vport_table_t *vport_table, vport_key_t *key, tpsa_ueid_cfg_t *ueid);
int vport_table_del_ueid(vport_table_t *vport_table, vport_key_t *key, uint32_t eid_index);

/*
 * tp state opts
 */
int tp_state_table_create(tp_state_table_t *tp_state_table);
tp_state_table_entry_t *tp_state_table_lookup(tp_state_table_t *tp_state_table, tp_state_table_key_t *key);
/* User needs to lookup entry before calling tp_state_table_add() */
tp_state_table_entry_t *tp_state_table_add(tp_state_table_t *tp_state_table, tp_state_table_key_t *key,
                                           tp_state_table_entry_t *add_entry);
int tp_state_table_add_with_duplication_check(tp_state_table_t *tp_state_table, tp_state_table_key_t *key,
                                              tp_state_table_entry_t *add_entry);
int tp_state_table_remove(tp_state_table_t *tp_state_table, tp_state_table_key_t *key);
void tp_state_table_destroy(tp_state_table_t *tp_state_table);

/*
 * tpg state opts
 */
int tpg_state_table_create(tpg_state_table_t *tpg_state_table);
tpg_state_table_entry_t *tpg_state_table_lookup(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key);
/* User needs to lookup entry before calling tpg_state_table_add() */
tpg_state_table_entry_t *tpg_state_table_add(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key,
                                             tpg_state_table_entry_t *add_entry);
int uvs_update_tpg_state_flush_cnt(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key, uint32_t flush_cnt);
int tpg_state_table_remove(tpg_state_table_t *tpg_state_table, tpg_state_table_key_t *key);
void tpg_state_table_destroy(tpg_state_table_t *tpg_state_table);

/*
 * deid_vtp_table opts
 */
int deid_vtp_table_create(deid_vtp_table_t *deid_vtp_table);
void deid_rm_vtp_list_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key, rm_vtp_table_key_t *vtp_key);
void deid_rc_vtp_list_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key, rc_vtp_table_key_t *vtp_key);
void deid_um_vtp_list_remove(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key, um_vtp_table_key_t *vtp_key);
void deid_vtp_table_destroy(deid_vtp_table_t *deid_vtp_table);
deid_vtp_table_entry_t *deid_vtp_table_lookup(deid_vtp_table_t *deid_vtp_table, deid_vtp_table_key_t *key);

/*
 * wait_restored_list opts
 */
void wait_restored_list_create(wait_restored_list_t *wait_restored_list);
wait_restored_entry_t *wait_restored_list_add(wait_restored_list_t *wait_restored_list,
                                              tpsa_restored_vtp_entry_t *restored_vtp_entry);
void wait_restored_list_add_restored_entry(wait_restored_list_t *wait_restored_list,
                                           wait_restored_entry_t *entry);
void wait_restored_list_destroy(wait_restored_list_t *wait_restored_list);
#ifdef __cplusplus
}
#endif

#endif
