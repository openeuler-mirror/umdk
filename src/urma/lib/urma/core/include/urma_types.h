/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: URMA type header file
 * Author: Ouyang Changchun, Bojie Li, Yan Fangfang, Qian Guoxin
 * Create: 2021-07-13
 * Note:
 * History: 2021-07-13   Create File
 */

#ifndef URMA_TYPES_H
#define URMA_TYPES_H

#include <stdint.h>
#include <pthread.h>
#ifndef __cplusplus
#include <stdatomic.h>
#else
#include <atomic>
#endif
#include <sys/socket.h>
#include <arpa/inet.h>
#include "urma_opcode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URMA_GET_VERSION(a, b) (((a) << 16) + ((b) > 65535 ? 65535 : (b)))
#define URMA_API_VERSION ((0 << 16) + 9)        // Current Version: 0.9
#define MAX_PORT_CNT 8
#define URMA_MAX_JETTY_IN_JETTY_GRP 32U
#define URMA_MAX_NAME 64
#define URMA_MAX_PATH 4096
#define URMA_EID_SIZE (16)
#define URMA_IPV4_MAP_IPV6_PREFIX (0x0000ffff)
#define URMA_MAX_EID_CNT 1024     /* refer to UBCORE_MAX_SIP */
#define URMA_CC_IDX_TABLE_SIZE 81 /* support 9 priorities and 9 algorithms */
                                  /* same as UBCORE_CC_IDX_TABLE_SIZE */

#define URMA_EID_STR_LEN (39)
#define EID_FMT "%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#define EID_RAW_ARGS(eid) eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6], eid[7], eid[8], eid[9], eid[10], \
        eid[11], eid[12], eid[13], eid[14], eid[15]
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)
#define URMA_SEG_TOKEN_ID_INVALID 0xffffffff

/* refer to UBCORE_MAX_DEV_NAME */
#define URMA_MAX_DEV_NAME 64
#define URMA_GUID_SIZE (16)

#define URMA_IP_ADDR_BYTES 16       /* refer to UBCORE_IP_ADDR_BYTES */
#define URMA_MAC_BYTES 6            /* refer to UBCORE_MAC_BYTES */

typedef struct urma_init_attr {
    uint64_t token;        /* [Optional] security token */
    uint32_t uasid;        /* [Optional] uasid to set and reserve. If the parameter is 0,
                              the system will randomly assign a non-0 value. */
} urma_init_attr_t;

/* device information */
typedef enum urma_mtu {
    URMA_MTU_256      = 1,
    URMA_MTU_512,
    URMA_MTU_1024,
    URMA_MTU_2048,
    URMA_MTU_4096,
    URMA_MTU_8192,
} urma_mtu_t;

typedef enum urma_port_state {
    URMA_PORT_NOP         = 0,
    URMA_PORT_DOWN,
    URMA_PORT_INIT,
    URMA_PORT_ARMED,
    URMA_PORT_ACTIVE,
    URMA_PORT_ACTIVE_DEFER,
} urma_port_state_t;

typedef enum urma_speed {
    URMA_SP_10M  = 0,
    URMA_SP_100M,
    URMA_SP_1G,
    URMA_SP_2_5G,
    URMA_SP_5G,
    URMA_SP_10G,
    URMA_SP_14G,
    URMA_SP_25G,
    URMA_SP_40G,
    URMA_SP_50G,
    URMA_SP_100G,
    URMA_SP_200G,
    URMA_SP_400G,
    URMA_SP_800G,
} urma_speed_t;

typedef enum urma_link_width {
    URMA_LINK_X1  = 0x1,
    URMA_LINK_X2  = 0x1 << 1,
    URMA_LINK_X4  = 0x1 << 2,
    URMA_LINK_X8  = 0x1 << 3,
    URMA_LINK_X16 = 0x1 << 4,
    URMA_LINK_X32 = 0x1 << 5,
} urma_link_width_t;

typedef union urma_eid {
    uint8_t raw[URMA_EID_SIZE]; /* Network Order */
    struct {
        uint64_t reserved;      /* If IPv4 mapped to IPv6, == 0 */
        uint32_t prefix;        /* If IPv4 mapped to IPv6, == 0x0000ffff */
        uint32_t addr;          /* If IPv4 mapped to IPv6, == IPv4 addr */
    } in4;
    struct {
        uint64_t subnet_prefix;
        uint64_t interface_id;
    } in6;
} urma_eid_t;

void urma_u32_to_eid(uint32_t ipv4, urma_eid_t *eid);
int urma_str_to_eid(const char *buf, urma_eid_t *eid);

typedef struct urma_ref {
#ifndef __cplusplus
    atomic_ulong atomic_cnt;
#else
    std::atomic_ulong atomic_cnt;
#endif
} urma_ref_t;

typedef struct urma_port_attr {
    urma_mtu_t max_mtu;             /* [Public] MTU_256, MTU_512, MTU_1024 etc. */
    urma_port_state_t state;        /* [Public] PORT_DOWN, PORT_INIT, PORT_ACTIVE */
    urma_link_width_t active_width; /* [Public] link width: X1, X2, X4. */
    urma_speed_t active_speed;      /* [Public] bandwidth. */
    urma_mtu_t active_mtu;          /* [Public] current effective mtu. */
} urma_port_attr_t;

typedef union urma_device_feature {
    struct {
        uint32_t oor               :   1;  /* [Public] URMA_OUT_OF_ORDER_RECEIVING. */
        uint32_t jfc_per_wr        :   1;  /* [Public] URMA_JFC_PER_WR. */
        uint32_t stride_op         :   1;  /* [Public] URMA_STRIDE_OP. */
        uint32_t load_store_op     :   1;  /* [Public] URMA_LOAD_STORE_OP. */
        uint32_t non_pin           :   1;  /* [Public] URMA_NON_PIN. */
        uint32_t pmem              :   1;  /* [Public] URMA_PERSISTENCE_MEM. */
        uint32_t jfc_inline        :   1;  /* [Public] URMA_JFC_INLINE. */
        uint32_t spray_en          :   1;  /* [Public] URMA_SPRAY_ENABLE for UDP port. */
        uint32_t selective_retrans :   1;  /* [Public] URMA_SELECTIVE_RETRANS. */
        uint32_t live_migrate      :   1;  /* [Public] support live migration. */
        uint32_t dca               :   1;  /* [Public] for user tp */
        uint32_t jetty_grp         :   1;  /* [Public] support jetty group. */
        uint32_t error_suspend     :   1;  /* [Public] support suspend jetty or jfs on error. */
        uint32_t outorder_comp     :   1;  /* [Public] support out-of-order completion. */
        uint32_t mn                :   1;  /* [Public] for user tp */
        uint32_t clan              :   1;  /* [Public] for user tp */
        uint32_t muti_seg_per_token_id : 1;
        uint32_t reserved          :   15;
    } bs;
    uint32_t value;
} urma_device_feature_t;

typedef union urma_atomic_feature {
    struct {
        uint32_t cas               :   1;
        uint32_t swap              :   1;
        uint32_t fetch_and_add     :   1;
        uint32_t fetch_and_sub     :   1;
        uint32_t fetch_and_and     :   1;
        uint32_t fetch_and_or      :   1;
        uint32_t fetch_and_xor     :   1;
        uint32_t reserved          :   25;
    } bs;
    uint32_t value;
} urma_atomic_feature_t;

typedef enum urma_sub_trans_mode_cap {
    URMA_RC_TP_DST_ORDERING = 0x1,      /*  rc mode with tp dst ordering  */
    URMA_RC_TA_DST_ORDERING = 0x1 << 1, /*  rc mode with ta dst ordering  */
    URMA_RC_USER_TP         = 0x1 << 2, /*  rc mode with user tp */
} urma_sub_trans_mode_cap_t;

typedef union urma_order_type_cap {
    struct {
        uint32_t ot : 1;
        uint32_t oi : 1;
        uint32_t ol : 1;
        uint32_t no   : 1;
        uint32_t reserved : 28;
    } bs;
    uint32_t value;
} urma_order_type_cap_t;

typedef union urma_tp_type_cap {
    struct {
        uint32_t rtp : 1;
        uint32_t ctp : 1;
        uint32_t utp : 1;
        uint32_t reserved : 29;
    } bs;
    uint32_t value;
} urma_tp_type_cap_t;

typedef union urma_tp_feature {
    struct {
        uint32_t rm_multi_path : 1;
        uint32_t rc_multi_path : 1;
        uint32_t reserved : 30;
    } bs;
    uint32_t value;
} urma_tp_feature_t;


typedef struct urma_device_cap {
    urma_device_feature_t feature;     /* [Public] support feature of device, such as OOO, LS etc. */
    uint32_t max_jfc;                  /* [Public] max number of jfc supported by the device. */
    uint32_t max_jfs;                  /* [Public] max number of jfs supported by the device. */
    uint32_t max_jfr;                  /* [Public] max number of jfr supported by the device. */
    uint32_t max_jetty;                /* [Public] max number of jetty supported by the device. */
    uint32_t max_jetty_grp;            /* [Public] max number of jetty group supported by the device. */
    uint32_t max_jetty_in_jetty_grp;   /* [Public] max number of jetty per jetty group supported by the device. */
    uint32_t max_jfc_depth;            /* [Public] max depth of jfc supported by the device. */
    uint32_t max_jfs_depth;            /* [Public] max depth of jfs supported by the device. */
    uint32_t max_jfr_depth;            /* [Public] max depth of jfr supported by the device. */
    uint32_t max_jfs_inline_len;       /* [Public] max inline length(byte) supported by the jfs. */
    uint32_t max_jfs_sge;              /* [Public] max number of sge supported by the jfs. */
    uint32_t max_jfs_rsge;             /* [Public] max number of remote sge supported by the jfs. */
    uint32_t max_jfr_sge;              /* [Public] max number of sge supported by the jfr. */
    uint64_t max_msg_size;             /* [Public] max message size supported by the device. */
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint32_t max_cas_size;
    uint32_t max_swap_size;
    uint32_t max_fetch_and_add_size;
    uint32_t max_fetch_and_sub_size;
    uint32_t max_fetch_and_and_size;
    uint32_t max_fetch_and_or_size;
    uint32_t max_fetch_and_xor_size;
    urma_atomic_feature_t atomic_feat; /* [Public] support atomic feature of device */
    uint16_t trans_mode;               /* [Public] bit OR of supported transport modes */
    uint16_t sub_trans_mode_cap;       /* [Public] bit OR of supported transport modes cap, urma_sub_trans_mode_cap_t */
    uint16_t congestion_ctrl_alg;      /* [Public] one or more mode from urma_congestion_ctrl_alg_t */
    uint32_t ceq_cnt;                  /* [Public] ceq_cnt */
    uint32_t max_tp_in_tpg;            /* [Public] max tp in tpg */
    uint32_t max_eid_cnt;              /* [Public] max eid count */
    uint64_t page_size_cap;            /* [Public] page size capability, must include PAGE_SIZE(4k) */
    uint32_t max_oor_cnt;              /* [Public] max OOR window size by packet, only for user tp */
    uint32_t mn;                       /* [Public] only for user tp */
    uint32_t max_netaddr_cnt;          /* [Public] only for user tp */
    urma_order_type_cap_t rm_order_cap;
    urma_order_type_cap_t rc_order_cap;
    urma_tp_type_cap_t rm_tp_cap;
    urma_tp_type_cap_t rc_tp_cap;
    urma_tp_type_cap_t um_tp_cap;
    urma_tp_feature_t tp_feature;
} urma_device_cap_t;

typedef struct urma_guid {
    uint8_t raw[URMA_GUID_SIZE];
} urma_guid_t;

typedef struct urma_device_attr {
    urma_guid_t guid;                 /* [Public] */
    urma_device_cap_t dev_cap;        /* [Public] capabilities of device. */
    uint8_t port_cnt;                 /* [Public] port number of device. */
    struct urma_port_attr port_attr[MAX_PORT_CNT];
    uint32_t reserved_jetty_id_min;
    uint32_t reserved_jetty_id_max;
} urma_device_attr_t;

/* security information */
typedef struct urma_token {
    uint32_t token;
} urma_token_t;

struct urma_sysfs_dev;
struct urma_ref;
struct urma_ops;
struct urma_provider_ops;

typedef enum urma_transport_type {
    URMA_TRANSPORT_INVALID = -1,
    URMA_TRANSPORT_UB      = 0,
    URMA_TRANSPORT_MAX
} urma_transport_type_t;

typedef enum urma_transport_mode {
    URMA_TM_RM = 0x1,      /* Reliable message */
    URMA_TM_RC = 0x1 << 1, /* Reliable connection */
    URMA_TM_UM = 0x1 << 2, /* Unreliable message */
} urma_transport_mode_t;

typedef enum urma_tp_cc_alg {
    URMA_TP_CC_NONE = 0,
    URMA_TP_CC_DCQCN,
    URMA_TP_CC_DCQCN_AND_NETWORK_CC,
    URMA_TP_CC_LDCP,
    URMA_TP_CC_LDCP_AND_CAQM,
    URMA_TP_CC_LDCP_AND_OPEN_CC,
    URMA_TP_CC_HC3,
    URMA_TP_CC_DIP,
    URMA_TP_CC_ACC,
    URMA_TP_CC_NUM,
} urma_tp_cc_alg_t; /* larger means better */

typedef enum urma_congestion_ctrl_alg {
    URMA_CC_NONE = 0x1 << URMA_TP_CC_NONE,
    URMA_CC_DCQCN = 0x1 << URMA_TP_CC_DCQCN,
    URMA_CC_DCQCN_AND_NETWORK_CC = 0x1 << URMA_TP_CC_DCQCN_AND_NETWORK_CC,
    URMA_CC_LDCP = 0x1 << URMA_TP_CC_LDCP,
    URMA_CC_LDCP_AND_CAQM = 0x1 << URMA_TP_CC_LDCP_AND_CAQM,
    URMA_CC_LDCP_AND_OPEN_CC = 0x1 << URMA_TP_CC_LDCP_AND_OPEN_CC,
    URMA_CC_HC3 = 0x1 << URMA_TP_CC_HC3,
    URMA_CC_DIP = 0x1 << URMA_TP_CC_DIP,
    URMA_CC_ACC = 0x1 << URMA_TP_CC_ACC
} urma_congestion_ctrl_alg_t;

typedef struct urma_cc_entry {
    urma_tp_cc_alg_t alg;
    uint8_t cc_pattern_idx;
    uint8_t cc_priority;
} __attribute__((packed)) urma_cc_entry_t;

typedef struct urma_device {
    char name[URMA_MAX_NAME];         /* [Public] urma device's name, the names of devices
                                         in different transport modes are different. */
    char path[URMA_MAX_PATH];         /* [Public] urma device's path in sysfs. */
    urma_transport_type_t type;       /* [Public] urma device's transport type. */
    struct urma_provider_ops *ops;    /* [Private] urma device driver's ops. */
    struct urma_sysfs_dev *sysfs_dev; /* [Private] internal device corresponding to the urma device */
} urma_device_t;

typedef enum urma_context_opt_name {
    URMA_OPT_AGGR_MODE,
} urma_opt_name_t;

typedef enum urma_context_aggr_mode {
    URMA_AGGR_MODE_STANDALONE,
    URMA_AGGR_MODE_ACTIVE_BACKUP,
    URMA_AGGR_MODE_BALANCE,
} urma_context_aggr_mode_t;

typedef struct urma_context {
    struct urma_device *dev;  /* [Private] point to the corresponding urma device. */
    struct urma_ops *ops;     /* [Private] operation of urma device. */
    int dev_fd;               /* [Private] fd of urma device's sysfs file. */
    int async_fd;             /* [Private] fd of urma device's async event file. */
    pthread_mutex_t mutex;    /* [Private] mutex of urma context. */
    urma_eid_t eid;           /* [Public] eid of urma device. */
    uint32_t eid_index;
    uint32_t uasid;           /* [Public] uasid of current process. */
    struct urma_ref ref;      /* [Private] reference count of urma context. */
    urma_context_aggr_mode_t aggr_mode; /* [Public] aggregated mode of urma context */
} urma_context_t;

typedef struct urma_eid_info {
    urma_eid_t eid;
    uint32_t eid_index;       /* 0~UBCORE_MAX_EID_CNT -1 */
} urma_eid_info_t;

typedef struct urma_jfce_cfg {
    uint32_t depth;
    uint64_t user_ctx;
} urma_jfce_cfg_t;

typedef struct urma_jfce {
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    int fd;                   /* [Private] fd of completed event. */
    struct urma_ref ref;      /* [Private] reference count of urma context. */
} urma_jfce_t;

typedef union urma_jfc_flag {
    struct {
        uint32_t lock_free      : 1;
        uint32_t jfc_inline     : 1;
        uint32_t reserved       : 30;
    } bs;
    uint32_t value;
} urma_jfc_flag_t;

typedef struct urma_jfc_cfg {
    uint32_t depth;       /* [Required] the depth of jfc, no greater than urma_device_cap_t->jfc_depth */
    urma_jfc_flag_t flag; /* [Optional] see urma_jfc_flag_t, set flag.value to be 0 by default */
    uint32_t ceqn;        /* [Optional] event queue id, no greater than urma_device_cap_t->ceq_cnt
                              set to 0 by default */
    urma_jfce_t *jfce;    /* [Required] the event of jfc */
    uint64_t user_ctx;    /* [Optional] private data of jfc, set to NULL by default */
} urma_jfc_cfg_t;

typedef enum urma_jfc_attr_mask {
    JFC_MODERATE_COUNT = 0x1,
    JFC_MODERATE_PERIOD = 0x1 << 1
} urma_jfc_attr_mask_t;

typedef struct urma_jfc_attr {
    uint32_t mask; /* mask value, refer to urma_jfc_attr_mask_t */
    uint16_t moderate_count;
    uint16_t moderate_period; /* in micro seconds */
} urma_jfc_attr_t;

typedef struct urma_jetty_id {
    urma_eid_t eid;
    uint32_t uasid; /* maybe zero(stand for kernel) or non-zero(stand for app) */
    uint32_t id;
} urma_jetty_id_t;

typedef struct urma_jetty_id urma_jfs_id_t;
typedef struct urma_jetty_id urma_jfr_id_t;
typedef struct urma_jetty_id urma_jfc_id_t;

typedef struct urma_jfc {
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    urma_jfc_id_t jfc_id;     /* [Public] see urma_jetty_id. */
    urma_jfc_cfg_t jfc_cfg;   /* [Public] storage jfc config. */
    uint64_t handle;
    pthread_mutex_t event_mutex;
    pthread_cond_t event_cond;
    uint32_t comp_events_acked;
    uint32_t async_events_acked;
} urma_jfc_t;

#define URMA_SUB_TRANS_MODE_TA_DST_ORDERING_ENABLE (0x1)
#define URMA_SUB_TRANS_MODE_USER_TP (0x2)

typedef enum urma_order_type {
    URMA_DEF_ORDER,
    URMA_OT, // target ordering
    URMA_OI, // initiator ordering
    URMA_OL, // low layer ordering
    URMA_NO  // unreliable non ordering
} urma_order_type_t;

typedef union urma_jfs_flag {
    struct {
        uint32_t lock_free      : 1;  /* default as 0, lock protected */
        uint32_t error_suspend  : 1;  /* 0: error continue; 1: error suspend */
        uint32_t outorder_comp  : 1;  /* 0: not support; 1: support out-of-order completion */
        uint32_t order_type     : 8;  /* (0x0): default, auto config by driver */
                                      /* (0x1): OT, target ordering */
                                      /* (0x2): OI, initiator ordering */
                                      /* (0x3): OL, low layer ordering */
                                      /* (0x4): UNO, unreliable non ordering */
        uint32_t multi_path     : 1;  /* 1: multi-path, 0: single path, for ubagg only. */
        uint32_t ctp_rc_mul_path_mode : 1; /* 1: ctp rc mode multi-path */
        uint32_t reserved       : 19;
    } bs;
    uint32_t value;
} urma_jfs_flag_t;

typedef struct urma_jfs_cfg {
    uint32_t depth;           /* [Required] the depth of jfs, defaut urma_device_cap_t->jfs_depth */
    urma_jfs_flag_t flag;     /* [Optional] see urma_jfs_flag_t definition */
    urma_transport_mode_t trans_mode; /* [Required] transport mode, must be supported by the device */
    uint8_t priority;         /* [Optional] set the priority of JFS, ranging from [0, 15]
                                 Services with low delay need to set high priority. */
    uint8_t max_sge;          /* [Optional] max sge count in one wr, defaut urma_device_cap_t->max_jfs_sge */
    uint8_t max_rsge;         /* [Optional] max remote sge count in one wr, defaut urma_device_cap_t->max_jfs_sge */
    uint32_t max_inline_data; /* [Optional] the max inline data size of JFS. if the parameter is 0,
                                 the system will assign device's max inline data length. */
    uint8_t rnr_retry;        /* [Optional] number of times that jfs will resend packets before report error,
                                 when the remote side is not ready to receive (RNR), ranging from [0, 7],
                                 the value 0 means never retry and,
                                 the value 7 means retry infinite number of times for RDMA devices */
    uint8_t err_timeout;      /* [Optional] the timeout before report error, ranging from [0, 31],
                                 the actual timeout in usec is caculated by: 4.096*(2^err_timeout) */
    urma_jfc_t *jfc;          /* [Required] need to specify jfc */
    uint64_t user_ctx;        /* [Optional] private data of jfs */
} urma_jfs_cfg_t;

typedef struct urma_jfs {
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    urma_jfs_id_t jfs_id;     /* [Public] see urma_jetty_id. */
    urma_jfs_cfg_t jfs_cfg;   /* [Public] storage jfs config. */
    uint64_t handle;
    pthread_mutex_t event_mutex;
    pthread_cond_t event_cond;
    uint32_t async_events_acked;
} urma_jfs_t;

typedef enum urma_jfs_attr_mask {
    JFS_STATE = 0x1
} urma_jfs_attr_mask_t;

typedef urma_jetty_state_t urma_jfs_state_t;

typedef struct urma_jfs_attr {
    uint32_t mask;  /* mask value refer to urma_jfs_attr_mask_t */
    urma_jfs_state_t state;
} urma_jfs_attr_t;

typedef union urma_jfr_flag {
    struct {
        uint32_t token_policy   : 3;  /* 0: URMA_TOKEN_NONE
                                         1: URMA_TOKEN_PLAIN_TEXT
                                         2: URMA_TOKEN_SIGNED
                                         3: URMA_TOKEN_ALL_ENCRYPTED
                                         4: URMA_TOKEN_RESERVED */
        uint32_t tag_matching   : 1;  /* 0: URMA_NO_TAG_MATCHING.
                                         1: URMA_WITH_TAG_MATCHING. */
        uint32_t lock_free      : 1;
        uint32_t order_type     : 8;  /* (0x0): default, auto config by driver */
                                      /* (0x1): OT, target ordering */
                                      /* (0x2): OI, initiator ordering */
                                      /* (0x3): OL, low layer ordering */
                                      /* (0x4): UNO, unreliable non ordering */
        uint32_t reserved       : 19;
    } bs;
    uint32_t value;
} urma_jfr_flag_t;

typedef struct urma_jfr_cfg {
    uint32_t id;           /* [Optional] specify jfr id. If the parameter is 0,
                              the system will randomly assign a non-0 value. */
    uint32_t depth;        /* [Required] total depth, include berth, defaut urma_device_cap_t->jfr_depth. */
    urma_jfr_flag_t flag;  /* [Optional] whether is in TAG_matching, whether is in DC/IDC mode. */
    urma_transport_mode_t trans_mode; /* [Required] transport mode, must be supported by the device */
    uint8_t max_sge;       /* [Optional] max sge count in one wr, defaut urma_device_cap_t->max_jfr_sge. */
    uint8_t min_rnr_timer; /* [Optional] the minimum RNR NACK timer, ranging from [0, 31], i.e.
                              the time before jfr sends NACK to the sender for the reason of "ready to receive" */
    urma_jfc_t *jfc;       /* [Required] need to specify jfc. */
    urma_token_t token_value;       /* [Required] specify token_value for jfr. */
    uint64_t user_ctx;     /* [Optional] private data of jfr */
} urma_jfr_cfg_t;

typedef enum urma_jfr_attr_mask {
    JFR_RX_THRESHOLD = 0x1,
    JFR_STATE = 0x1 << 1
} urma_jfr_attr_mask_t;

typedef struct urma_jfr_attr {
    uint32_t mask;   // mask value refer to urma_jfr_attr_mask_t
    uint32_t rx_threshold;
    urma_jfr_state_t state;
} urma_jfr_attr_t;

typedef struct urma_jfr {
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    urma_jfr_id_t jfr_id;     /* [Public] see urma_jetty_id. */
    urma_jfr_cfg_t jfr_cfg;   /* [Public] storage jfr config. */
    uint64_t handle;
    pthread_mutex_t event_mutex;
    pthread_cond_t event_cond;
    uint32_t async_events_acked;
} urma_jfr_t;

typedef union urma_import_jetty_flag {
    struct {
        uint32_t token_policy   : 3;
        uint32_t order_type     : 8;  /* (0x0): default, auto config by driver */
                                      /* (0x1): OT, target ordering */
                                      /* (0x2): OI, initiator ordering */
                                      /* (0x3): OL, low layer ordering */
                                      /* (0x4): UNO, unreliable non ordering */
        uint32_t share_tp    : 1; /* 1: shared tp; 0: non-shared tp. When rc mode is not ta dst ordering,
                                        this flag can only be set to 0. */
        uint32_t reserved       : 20;
    } bs;
    uint32_t value;
} urma_import_jetty_flag_t;

typedef enum urma_tp_type {
    URMA_RTP,
    URMA_CTP,
    URMA_UTP
} urma_tp_type_t;

typedef struct urma_rjfr {
    urma_jfr_id_t jfr_id; /* see urma_jetty_id */
    urma_transport_mode_t trans_mode;
    urma_import_jetty_flag_t flag;
    urma_tp_type_t tp_type;
} urma_rjfr_t;

typedef struct urma_tp {
    uint32_t tpn; /* vtpn */
} urma_tp_t;

typedef union urma_jetty_flag {
    struct {
        uint32_t share_jfr : 1; /* 0: URMA_NO_SHARE_JFR.
                                   1: URMA_SHARE_JFR. */
        uint32_t reserved  : 31;
    } bs;
    uint32_t value;
} urma_jetty_flag_t;

typedef struct urma_jetty_grp urma_jetty_grp_t;

typedef struct urma_jetty_cfg {
    uint32_t id;                 /* [Optional] user specified jetty id. */
    urma_jetty_flag_t flag;      /* [Optional] Connection or connection less */

    /* send configuration */
    urma_jfs_cfg_t jfs_cfg;     /* [Required] see urma_jfs_cfg_t */

    /* recv configuration */
    union {
        struct {
            urma_jfr_t *jfr;     /* [Optional] shared jfr to receive msg */
            urma_jfc_t *jfc;     /* [Optional] To replace the jfc related to the above jfr */
        } shared;                /* [Optional] */
        urma_jfr_cfg_t *jfr_cfg; /* deprecated */
    };                           /* [Required] */
    urma_jetty_grp_t *jetty_grp; /* [Optional] user specified jetty group. */
    uint64_t user_ctx;           /* [Optional] private data of jetty */
} urma_jetty_cfg_t;

typedef enum urma_jetty_grp_policy {
    URMA_JETTY_GRP_POLICY_RR = 0,
    URMA_JETTY_GRP_POLICY_HASH_HINT = 1
} urma_jetty_grp_policy_t;

typedef enum urma_target_type {
    URMA_JFR = 0,
    URMA_JETTY,
    URMA_JETTY_GROUP
} urma_target_type_t;

typedef struct urma_rjetty {
    urma_jetty_id_t jetty_id;
    urma_transport_mode_t trans_mode;
    urma_jetty_grp_policy_t policy;
    urma_target_type_t type;
    urma_import_jetty_flag_t flag;
    urma_tp_type_t tp_type;
} urma_rjetty_t;

typedef struct urma_target_jetty {
    urma_context_t *urma_ctx;    /* [Private] point to urma context. */
    urma_jetty_id_t id;          /* [Private] see urma_jetty_id. */
    uint64_t handle;
    urma_transport_mode_t trans_mode;
    urma_tp_t tp;
    urma_target_type_t type; // todo supplementary target type
    urma_import_jetty_flag_t flag;
    urma_jetty_grp_policy_t policy;
    urma_tp_type_t tp_type;
} urma_target_jetty_t;

typedef enum urma_jetty_attr_mask {
    JETTY_RX_THRESHOLD = 0x1,
    JETTY_STATE = 0x1 << 1
} urma_jetty_attr_mask_t;

typedef struct urma_jetty_attr {
    uint32_t mask;   // mask value refer to urma_jetty_attr_mask_t
    uint32_t rx_threshold;
    urma_jetty_state_t state;
} urma_jetty_attr_t;

typedef struct urma_jetty {
    urma_context_t *urma_ctx;           /* [Private] point to urma context. */
    urma_jetty_id_t jetty_id;           /* [Public] see urma_jetty_id. */
    urma_target_jetty_t *remote_jetty;  /* [Private] Only valid for connection mode Jetty.
                                           After the bind succeeds, the pointer is not null. */
    urma_jetty_cfg_t jetty_cfg;         /* [Public] storage jetty config. */
    uint64_t handle;
    pthread_mutex_t event_mutex;
    pthread_cond_t event_cond;
    uint32_t async_events_acked;
} urma_jetty_t;

typedef struct urma_notifier {
    urma_context_t *urma_ctx;
    int fd;
    void *incomplete_tjetty_list;
} urma_notifier_t;

typedef enum urma_notify_type {
    URMA_IMPORT_JETTY_NOTIFY = 0,
    URMA_BIND_JETTY_NOTIFY
} urma_notify_type_t;

typedef struct urma_notify {
    urma_notify_type_t type;
    urma_status_t status;
    uint64_t user_ctx;
    union {
        urma_target_jetty_t *tjetty; /* IMPORT */
        urma_jetty_t *jetty; /* BIND */
    };
} urma_notify_t;

typedef union urma_jetty_grp_flag {
    struct {
        uint32_t token_policy : 3;   /* 0: URMA_TOKEN_NONE
                                        1: URMA_TOKEN_PLAIN_TEXT
                                        2: URMA_TOKEN_SIGNED
                                        3: URMA_TOKEN_ALL_ENCRYPTED
                                        4: URMA_TOKEN_RESERVED */
        uint32_t reserved     : 29;
    } bs;
    uint32_t value;
} urma_jetty_grp_flag_t;

typedef struct urma_jetty_grp_cfg {
    char name[URMA_MAX_NAME];
    urma_jetty_grp_flag_t flag;
    urma_token_t token_value;       /* [Required] specify token_value for Jetty group. */
    uint32_t id;                    /* [Optional] specify Jetty group id.
                                       If the parameter is 0, UMDK will assign a non_0 value. */
    urma_jetty_grp_policy_t policy; /* Hash or RR(on default) */
    uint64_t user_ctx;              /* [Optional] private data of jetty */
} urma_jetty_grp_cfg_t;

struct urma_jetty_grp {
    urma_context_t *urma_ctx;
    urma_jetty_id_t jetty_grp_id;
    urma_jetty_grp_cfg_t cfg;
    uint32_t jetty_cnt;
    urma_jetty_t **jetty_list;
    pthread_mutex_t list_mutex;
    uint64_t handle;     /* use to quickly get uobj of jetty group in kernel module */
    pthread_mutex_t event_mutex;
    pthread_cond_t event_cond;
    uint32_t async_events_acked;
};

/* memory information */
typedef struct urma_ubva {
    urma_eid_t eid;
    uint32_t uasid; // 24 bit for UB
    uint64_t va;
} __attribute__((packed)) urma_ubva_t;

/* segment definition */
typedef union urma_reg_seg_flag {
    struct {
        uint32_t token_policy   : 3;  /* 0: URMA_TOKEN_NONE.
                                         1: URMA_TOKEN_PLAIN_TEXT.
                                         2: URMA_TOKEN_SIGNED.
                                         3: URMA_TOKEN_ALL_ENCRYPTED.
                                         4: URMA_TOKEN_RESERVED. */
        uint32_t cacheable      : 1;  /* 0: URMA_NON_CACHEABLE.
                                         1: URMA_CACHEABLE. */
        uint32_t dsva           : 1;
        uint32_t access         : 6;  /* (0x1): URMA_ACCESS_LOCAL_ONLY.
                                         (0x1 << 1): URMA_ACCESS_READ.
                                         (0x1 << 2): URMA_ACCESS_WRITE.
                                         (0x1 << 3): URMA_ACCESS_ATOMIC. */
        uint32_t non_pin        : 1;  /* 0: segment pages pinned.
                                         1: segment pages non-pinned. */
        uint32_t user_iova      : 1;  /* 0: segment without user iova addr.
                                         1: segment with user iova addr. */
        uint32_t token_id_valid : 1;  /* 0: token id in cfg is invalid.
                                         1: token id in cfg is valid. */
        uint32_t reserved       : 18;
    } bs;
    uint32_t value;
} urma_reg_seg_flag_t;

typedef union urma_seg_attr {
    struct {
        uint32_t token_policy   : 3;  /* 0: URMA_TOKEN_NONE.
                                         1: URMA_TOKEN_PLAIN_TEXT.
                                         2: URMA_TOKEN_SIGNED.
                                         3: URMA_TOKEN_ALL_ENCRYPTED.
                                         4: URMA_TOKEN_RESERVED. */
        uint32_t cacheable      : 1;  /* 0: URMA_NON_CACHEABLE.
                                         1: URMA_CACHEABLE. */
        uint32_t dsva           : 1;
        uint32_t access         : 6;  /* (0x1): URMA_ACCESS_LOCAL_WRITE.
                                         (0x1 << 1): URMA_ACCESS_READ.
                                         (0x1 << 2): URMA_ACCESS_WRITE.
                                         (0x1 << 3): URMA_ACCESS_ATOMIC. */
        uint32_t non_pin        : 1;  /* 0: segment pages pinned.
                                         1: segment pages non-pinned. */
        uint32_t user_iova      : 1;  /* 0: segment without user iova addr.
                                         1: segment with user iova addr. */
        uint32_t user_token_id  : 1;  /* 0: token_id is allocated and should be freed by urma.
                                         1: token_id is allocated by user in urma_seg_cfg. */
        uint32_t reserved       : 18;
    } bs;
    uint32_t value;
} urma_seg_attr_t;

typedef union urma_import_seg_flag {
    struct {
        uint32_t cacheable      : 1;  /* 0: URMA_NON_CACHEABLE.
                                         1: URMA_CACHEABLE. */
        uint32_t access         : 6;  /*  (0x1): URMA_ACCESS_LOCAL_ONLY.
                                          (0x1 << 1): URMA_ACCESS_READ.
                                          (0x1 << 2): URMA_ACCESS_WRITE.
                                          (0x1 << 3): URMA_ACCESS_ATOMIC.
                                      */
        uint32_t mapping        : 1;  /* 0: URMA_SEG_NOMAP/
                                         1: URMA_SEG_MAPPED. */
        uint32_t reserved       : 24;
    } bs;
    uint32_t value;
} urma_import_seg_flag_t;

typedef union urma_token_id_flag {
    struct {
        uint32_t multi_seg  : 1;
        uint32_t reserved   : 31;
    } bs;
    uint32_t value;
} urma_token_id_flag_t;

typedef struct urma_token_id {
    urma_context_t *urma_ctx;
    uint32_t token_id;
    uint64_t handle;
    urma_ref_t ref;
    urma_token_id_flag_t flag;
} urma_token_id_t;

typedef struct urma_seg_cfg {
    uint64_t va;                  /* specify the address of the segment to be registered */
    uint64_t len;                 /* specify the length of the segment to be registered */
    urma_token_id_t *token_id;
    urma_token_t token_value;        /* Security authentication for access */
    urma_reg_seg_flag_t flag;
    uint64_t user_ctx;
    uint64_t iova;                /* user iova, maybe zero-based-address */
} urma_seg_cfg_t;

typedef struct urma_seg {
    urma_ubva_t ubva;      /* [Public] ubva of segment. */
    uint64_t len;          /* [Public] length of segment. */
    urma_seg_attr_t attr;  /* [Public] include: access flag, token policy, cacheability. */
    uint32_t token_id;     /* [Private] match token */
} urma_seg_t;

typedef struct urma_target_seg {
    urma_seg_t seg;           /* [Private] see urma_seg_t. */
    uint64_t user_ctx;        /* [Private] private data of segment */
    uint64_t mva;             /* [Public] mapping addr when import remote seg. */
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    urma_token_id_t *token_id; /* When registering seg, it is a valid address; when importing seg, it is NULL */
    uint64_t handle;
} urma_target_seg_t;

typedef struct urma_user_ctl_in {
    uint64_t addr;   /* [Required] the address of the input parameter buffer. */
    uint32_t len;    /* [Required] the length of the input parameter buffer */
    /*
     * Opcode is simultaneously recognized by user and driver.
     * User opcode should be distinguished with enum urma_user_ctl_ops_t, which is only used by URMA.
     */
    uint32_t opcode; /* [Required] */
} urma_user_ctl_in_t;

typedef struct urma_user_ctl_out {
    uint64_t addr;  /* [Optional] the address of the output parameter buffer. */
    uint32_t len;   /* [Optional] the length of the output parameter buffer */
    uint32_t reserved;
} urma_user_ctl_out_t;

typedef struct urma_user_target_seg {
    urma_seg_attr_t attr;
    uint32_t token_id;
    urma_token_t token_value;
} urma_user_tseg_t;

typedef struct urma_sge {
    uint64_t addr;
    uint32_t len;
    /* Driver verification
     * remote seg: Either tseg or user tseg is not NULL.
     *             If both of them are not NULL, ignore user_tseg.
     * local seg: user_tseg is not supported, tseg must not NULL.
     */
    urma_target_seg_t *tseg;
    urma_user_tseg_t *user_tseg;   /* To support the exemption of import_seg */
} urma_sge_t;

typedef struct urma_sg {
    urma_sge_t *sge;
    uint32_t num_sge;
} urma_sg_t;

/* wr for batch operations */
typedef union urma_jfs_wr_flag {
    struct {
        uint32_t place_order : 2;      /* 0: There is no order with other WR
                                          1: relax order
                                          2: strong order
                                          3: reserve */ /* see urma_order_type_t */
        uint32_t comp_order : 1;       /* 0: There is no completion order with othwe WR.
                                          1: Completion order with previous WR. */
        uint32_t fence : 1;            /* 0: There is not fence.
                                          1: Fence with previous read and atomic WR */
        uint32_t solicited_enable : 1; /* 0: There is not solicited.
                                          1: solicited. It will trigger an event on remote side */
        uint32_t complete_enable : 1;  /* 0: Do not notify local process after the task is complete.
                                          1: Notify local process after the task is completed. */
        uint32_t inline_flag : 1;      /* 0: not inline.
                                          1: inline data. */
        uint32_t reserved : 25;
    } bs;
    uint32_t value;
} urma_jfs_wr_flag_t;

typedef union urma_jfr_wr_flag {
    struct {
        uint32_t complete_type : 1;    /* 0: Write completion record to jfc.
                                          1: Write completion record to complete flag (CF) address */
        uint32_t reserved      : 31;
    } bs;
    uint32_t value;
} urma_jfr_wr_flag_t;

typedef struct urma_rw_wr {
    urma_sg_t src;         /* including total data length. src is local va for write, and remote va for read.
                              only support 1 src sge in read operation. */
    urma_sg_t dst;         /* dst is remote va for write, and local va for read.
                              only support 1 dst sge in write operation. */
    uint8_t target_hint;   // required when using jetty group
    uint64_t notify_data;  // notify data or imm data in host byte order;
} urma_rw_wr_t;

typedef struct urma_send_wr {
    urma_sg_t src;         // including total data length
    uint8_t target_hint;   // required when using jetty group
    uint64_t imm_data;     // imm_data in host byte order;
    urma_target_seg_t *tseg; /* tseg used only when send with invalidate */
} urma_send_wr_t;

typedef struct urma_cas_wr {
    urma_sge_t *dst;    // len is the data length of CAS operation
    urma_sge_t *src;    // local address for destination original value writeback, len represents the buffer length.
    union {                 // Value compared with destination value
        uint64_t cmp_data;  // When the len <= 8B, it indicates the CMP value.
        uint64_t cmp_addr;  // When the len > 8B, it indicates the data address.
    };
    union { // If destination value is the same as cmp_data, destination value will be changed to swap_data
        uint64_t swap_data; // When the len <= 8B, it indicates the swap value.
        uint64_t swap_addr; // When the len > 8B, it indicates the data address.
    };
} urma_cas_wr_t;

typedef struct urma_faa_wr {
    urma_sge_t *dst;    // len is the data length of FAA operation
    urma_sge_t *src;    // local address for destination original value writeback, len represents the buffer length.
    union {
        uint64_t operand;   // When the len <= 8B, it indicates the operand value.
        uint64_t operand_addr;   // When the len > 8B, it indicates the data address.
    };
} urma_faa_wr_t;

typedef struct urma_jfs_wr  {
    urma_opcode_t opcode;
    urma_jfs_wr_flag_t flag;
    urma_target_jetty_t *tjetty;
    uint64_t user_ctx; // completion data
    union {
        urma_rw_wr_t rw;
        urma_send_wr_t send;
        urma_cas_wr_t cas;
        urma_faa_wr_t faa;
    };
    struct urma_jfs_wr *next;
} urma_jfs_wr_t;

typedef struct urma_jfr_wr  {
    urma_sg_t src;                 // includeing buffer length
    uint64_t user_ctx;            // completion data, eg. wr id
    struct urma_jfr_wr *next;
} urma_jfr_wr_t;

typedef union urma_cr_flag {
    struct {
        uint8_t s_r             : 1;     // Indicate CR stands for sending or receiving, 0: send, 1: recv.
        uint8_t jetty           : 1;     // Indicate CR stands for jetty or jfs/jfr, 0: jfs/jfr, 1: jetty.
        uint8_t suspend_done    : 1;     // Real CR associated with the WR, user_ctx is valid
        uint8_t flush_err_done  : 1;     // Real CR associated with the WR, user_ctx is valid
        uint8_t reserved        : 4;
    } bs;
    uint8_t value;
} urma_cr_flag_t;

typedef struct urma_cr_token {
    uint32_t token_id;
    urma_token_t token_value;
} urma_cr_token_t;

typedef struct urma_cr {
    urma_cr_status_t status;
    uint64_t user_ctx;             // user_ctx related to a work request
    urma_cr_opcode_t opcode;       // Only for recv
    urma_cr_flag_t flag;           // indicate notify data or swap data is valid or not
    uint32_t completion_len;       // The number of bytes transferred

    uint32_t local_id;             // Local jetty ID, or JFS ID, or JFR ID, depends on flag
    urma_jetty_id_t remote_id;     // Valid only for receiving CR. The remote jetty where the
                                   // received msg comes from Jetty ID or JFS ID, depends on flag.
    union {
        uint64_t imm_data;         // Valid only for receiving CR: send/write/read with imm.
        urma_cr_token_t invalid_token; // Valid only for receiving CR: send with invalidate.
    };
    uint32_t tpn ;                 // TP number or TPG number
    uintptr_t user_data;           // e.g. use as pointer to local jetty struct.
} urma_cr_t;

typedef struct urma_async_event {
    /* may be SW queue error, may be HW port error */
    const urma_context_t *urma_ctx;
    union {
        urma_jfc_t *jfc;
        urma_jfs_t *jfs;
        urma_jfr_t *jfr;
        urma_jetty_t *jetty;
        urma_jetty_grp_t *jetty_grp;
        uint32_t port_id;
        uint32_t eid_idx;
    } element;
    urma_async_event_type_t event_type;
    void *priv;
} urma_async_event_t;

/* URMA region definition */
typedef union urma_ur_attr {
    struct {
        uint32_t reserved       : 32;
    } bs;
    uint32_t value;
} urma_ur_attr_t;

typedef union urma_import_ur_flag {
    struct {
        uint32_t mapping        : 2;  /* 0: URMA_SEG_NOMAP
                                         1: URMA_SEG_MAPPED_MVA
                                         2: URMA_SEG_MAPPED_DSVA */
        uint32_t reserved       : 30;
    } bs;
    uint32_t value;
} urma_import_ur_flag_t;

#define UR_NAME_MAX_LEN 256
#define JFR_NAME_MAX_LEN 256
#define URMA_MAX_SEGS_PER_UR_OPT  64   // Max number of SEGS per attach/detach ur

// In parametre for create UR
typedef struct urma_ur {
    char name[UR_NAME_MAX_LEN]; // UR url name
    uint64_t size;
    urma_ur_attr_t attr;  // include: access flag, token policy, cacheability, dsva
    uint64_t token;
    uint64_t user_ctx;
} urma_ur_t;

// Out parametre for import UR
typedef struct urma_target_ur {
    char name[UR_NAME_MAX_LEN]; // UR url name
    uint64_t size;
    urma_import_ur_flag_t flag;  // include: access flag, token policy, cacheability, dsva
    urma_target_seg_t **tseg_list;
    uint32_t cnt;
} urma_target_ur_t;

typedef struct urma_seg_info {
    urma_seg_t seg;
    uint32_t idx_in_ur;
} urma_seg_info_t;

// Out parametre for lookup UR
typedef struct urma_ur_info {
    char name[UR_NAME_MAX_LEN]; // UR url name
    uint64_t size; // limit size, by byte
    urma_ur_attr_t attr;  // include: access flag, token policy, cacheability, dsva
    uint32_t cnt; //
    urma_seg_info_t seg_list[0];    // cnt * sizeof(urma_seg_info_t)
} urma_ur_info_t;

typedef struct urma_jfr_info {
    char name[JFR_NAME_MAX_LEN]; // jfr url name
    urma_eid_t eid;
    uint32_t uasid;
    uint32_t id;
} urma_jfr_info_t;

typedef union urma_tp_cfg_flag {
    struct {
        uint32_t target : 1; /* 0: initiator, 1: target */
        uint32_t loopback : 1;
        uint32_t dca_enable : 1;
        /* for the bonding case, the hardware selects the port
         * ignoring the port of the tp context and
         * selects the port based on the hash value
         * along with the information in the bonding group table.
         */
        uint32_t bonding : 1;
        uint32_t reserved : 28;
    } bs;
    uint32_t value;
} urma_tp_cfg_flag_t;

typedef struct urma_tp_cfg {
    urma_tp_cfg_flag_t flag;                /* flag of initial tp */
    /* transport layer attributes */
    urma_transport_mode_t trans_mode;
    uint8_t retry_num;
    uint8_t retry_factor;                   /* for calculate the time slot to retry */
    uint8_t ack_timeout;
    uint8_t dscp;
    uint32_t oor_cnt;                       /* OOR window size: by packet */
} urma_tp_cfg_t;

typedef union urma_tp_attr_mask {
    struct {
        uint32_t flag : 1;
        uint32_t peer_tpn : 1;
        uint32_t state : 1;
        uint32_t tx_psn : 1;
        uint32_t rx_psn : 1; /* modify both rx psn and tx psn when restore tp */
        uint32_t mtu : 1;
        uint32_t cc_pattern_idx : 1;
        uint32_t oos_cnt : 1;
        uint32_t local_net_addr_idx : 1;
        uint32_t peer_net_addr : 1;
        uint32_t data_udp_start : 1;
        uint32_t ack_udp_start : 1;
        uint32_t udp_range : 1;
        uint32_t hop_limit : 1;
        uint32_t flow_label : 1;
        uint32_t port_id : 1;
        uint32_t mn : 1;
        uint32_t peer_trans_type : 1;
        uint32_t reserved : 14;
    } bs;
    uint32_t value;
} urma_tp_attr_mask_t;

typedef union urma_tp_mod_flag {
    struct {
        uint32_t oor_en      : 1; /* out of order receive, 0: disable 1: enable */
        uint32_t sr_en       : 1; /* selective retransmission, 0: disable 1: enable */
        uint32_t cc_en       : 1; /* congestion control algorithm, 0: disable 1: enable */
        uint32_t cc_alg      : 4; /* The value is ubcore_tp_cc_alg_t */
        uint32_t spray_en    : 1; /* spray with src udp port, 0: disable 1: enable */
        uint32_t clan        : 1; /* clan domain, 0: disable 1: enable */
        uint32_t reserved    : 23;
    } bs;
    uint32_t value;
} urma_tp_mod_flag_t;

typedef enum urma_tp_state {
    URMA_TP_STATE_RESET = 0,
    URMA_TP_STATE_PASSIVE,
    URMA_TP_STATE_ACTIVE,
    URMA_TP_STATE_BRAKE,
    URMA_TP_STATE_ERROR
} urma_tp_state_t;

typedef struct urma_net_addr {
    sa_family_t sin_family;     /* AF_INET/AF_INET6 */
    union {
        struct in_addr in4;
        struct in6_addr in6;
    };
    uint64_t vlan;
    uint8_t mac[URMA_MAC_BYTES];
    uint32_t prefix_len;
} urma_net_addr_t;

typedef struct urma_net_addr_info {
    urma_net_addr_t netaddr;
    uint32_t index;
} urma_net_addr_info_t;

typedef struct urma_tp_attr {
    urma_tp_mod_flag_t flag;
    uint32_t peer_tpn;
    urma_tp_state_t state;
    uint32_t tx_psn;
    uint32_t rx_psn;
    urma_mtu_t mtu;
    uint8_t cc_pattern_idx;
    uint32_t oos_cnt; /* out of standing packet cnt */
    uint32_t local_net_addr_idx;
    urma_net_addr_t peer_net_addr;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint8_t udp_range;
    uint8_t hop_limit;
    uint32_t flow_label;
    uint8_t port_id;
    uint8_t mn; /* 0~15, a packet contains only one msg if mn is set as 0 */
    urma_transport_type_t peer_trans_type;
} urma_tp_attr_t;

typedef union urma_get_tp_cfg_flag {
    struct {
        uint32_t ctp             : 1;
        uint32_t rtp              : 1;
        uint32_t utp             : 1;
        uint32_t uboe            : 1;
        uint32_t pre_defined     : 1;
        uint32_t dynamic_defined : 1;
        uint32_t reserved        : 26;
    } bs;
    uint32_t value;
} urma_get_tp_cfg_flag_t;

typedef struct urma_get_tp_cfg {
    urma_get_tp_cfg_flag_t flag;
    urma_transport_mode_t trans_mode;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
} urma_get_tp_cfg_t;

typedef struct urma_tp_info {
    uint64_t tp_handle;
} urma_tp_info_t;

typedef struct urma_active_tp_attr {
    uint32_t tx_psn;
    uint32_t rx_psn;
    uint64_t reserved;
} urma_active_tp_attr_t;

typedef struct urma_active_tp_cfg {
    uint64_t tp_handle;
    uint64_t peer_tp_handle;
    uint64_t tag;
    urma_active_tp_attr_t tp_attr;
} urma_active_tp_cfg_t;

typedef struct urma_active_tp_cfg urma_import_jetty_ex_cfg_t;
typedef struct urma_active_tp_cfg urma_import_jfr_ex_cfg_t;
typedef struct urma_active_tp_cfg urma_bind_jetty_ex_cfg_t;

#pragma pack(1)
typedef struct urma_tp_attr_value {
    uint8_t retry_times_init : 3;
    uint8_t at : 5;
    uint8_t sip[URMA_IP_ADDR_BYTES];
    uint8_t dip[URMA_IP_ADDR_BYTES];
    uint8_t sma[URMA_MAC_BYTES];
    uint8_t dma[URMA_MAC_BYTES];
    uint16_t vlan_id : 12;
    uint8_t vlan_en : 1;
    uint8_t dscp : 6;
    uint8_t at_times : 5;
    uint8_t sl : 4;
    uint8_t ttl;
    uint8_t reserved[78];
} urma_tp_attr_value_t;
#pragma pack()

/* callback information */
typedef void (*urma_async_event_cb)(urma_async_event_t *event, void *cb_arg);

/* callback function type for urma_advise_jfr/jetty_async. User must define callback function to handle result.
  advise_result is the result of advise jfr or jetty */
typedef void (*urma_advise_async_cb_func)(urma_status_t advise_result, void *cb_arg);

typedef enum urma_vlog_level {
    URMA_VLOG_LEVEL_EMERG = 0,
    URMA_VLOG_LEVEL_ALERT = 1,
    URMA_VLOG_LEVEL_CRIT = 2,
    URMA_VLOG_LEVEL_ERR = 3,
    URMA_VLOG_LEVEL_WARNING = 4,
    URMA_VLOG_LEVEL_NOTICE = 5,
    URMA_VLOG_LEVEL_INFO = 6,
    URMA_VLOG_LEVEL_DEBUG = 7,
    URMA_VLOG_LEVEL_MAX = 8,
} urma_vlog_level_t;

typedef void (*urma_log_cb_t)(int level, char *message);

#ifdef __cplusplus
}
#endif

#endif // URMA_TYPES_H
