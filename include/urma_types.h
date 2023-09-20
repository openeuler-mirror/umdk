/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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

#include "urma_opcode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PORT_CNT 8
#define URMA_MAX_NAME 64
#define URMA_MAX_PATH 4096
#define URMA_EID_SIZE (16)
#define URMA_IPV4_MAP_IPV6_PREFIX (0x0000ffff)

#define URMA_EID_STR_LEN (39)
#define EID_FMT "%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#define EID_RAW_ARGS(eid) eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6], eid[7], eid[8], eid[9], eid[10], \
        eid[11], eid[12], eid[13], eid[14], eid[15]
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)
#define URMA_SEG_KEY_ID_INVALID 0xffffffff

typedef struct urma_init_attr {
    uint64_t token;        /* [Optional] security token */
    uint32_t uasid;        /* [Optional] uasid to set and reserve. If the parameter is 0,
                              the system will randomly assign a non-0 value. */
    uint8_t enable_uds;    /* [Optional] 0: do not connect ubsc via uds; 1: connect ubsc via uds */
} urma_init_attr_t;

/* device infomation */
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
    URMA_LINK_X1  = 0x1 << 0,
    URMA_LINK_X2  = 0x1 << 1,
    URMA_LINK_X4  = 0x1 << 2,
    URMA_LINK_X8  = 0x1 << 3,
    URMA_LINK_X16 = 0x1 << 4,
    URMA_LINK_X32 = 0x1 << 5,
} urma_link_width_t;

typedef union urma_eid {
    uint8_t raw[URMA_EID_SIZE]; /* Network Order */
    struct {
        uint64_t resv;          /* If IPv4 mapped to IPv6, == 0 */
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

typedef struct urma_port_attr {
    urma_mtu_t max_mtu;             /* [Public] MTU_256, MTU_512, MTU_1024 etc. */
    urma_port_state_t state;        /* [Public] PORT_DOWN, PORT_INIT, PORT_ACTIVE */
    urma_link_width_t active_width; /* [Public] link width: X1, X2, X4. */
    urma_speed_t active_speed;      /* [Public] bandwidth. */
    urma_mtu_t active_mtu;          /* [Public] current effective mtu. */
} urma_port_attr_t;

typedef union urma_device_feat {
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
        uint32_t reserved          :   23;
    } bs;
    uint32_t value;
} urma_device_feat_t;

typedef struct urma_device_cap {
    urma_device_feat_t feature;      /* [Public] support feature of device, such as OOO, LS etc. */
    uint32_t max_jfc;                /* [Public] max number of jfc supported by the device. */
    uint32_t max_jfs;                /* [Public] max number of jfs supported by the device. */
    uint32_t max_jfr;                /* [Public] max number of jfr supported by the device. */
    uint32_t max_jetty;              /* [Public] max number of jetty supported by the device. */
    uint32_t max_jfc_depth;          /* [Public] max depth of jfc supported by the device. */
    uint32_t max_jfs_depth;          /* [Public] max depth of jfs supported by the device. */
    uint32_t max_jfr_depth;          /* [Public] max depth of jfr supported by the device. */
    uint32_t max_jfs_inline_len;     /* [Public] max inline length(byte) supported by the jfs. */
    uint32_t max_jfs_sge;            /* [Public] max number of sge supported by the jfs. */
    uint32_t max_jfs_rsge;           /* [Public] max number of remote sge supported by the jfs. */
    uint32_t max_jfr_sge;            /* [Public] max number of sge supported by the jfr. */
    uint64_t max_rmem_size;          /* [Public] max TPA space size supported by the device. */
    uint64_t max_msg_size;             /* [Public] max message size supported by the device. */
    uint16_t trans_mode;             /* [Public] bit OR of supported transport modes */
    uint16_t congestion_ctrl_alg;    /* [Public] one or more mode from urma_congestion_ctrl_alg_t */
    uint32_t comp_vector_cnt;        /* [Public] completion vector count */
} urma_device_cap_t;

typedef struct urma_device_attr {
    urma_eid_t eid;            /* [Public]. */
    uint32_t max_eid_cnt;
    uint64_t guid;             /* [Public] */
    urma_device_cap_t dev_cap; /* [Public] capabilities of device. */
    uint8_t port_cnt;          /* [Public] port number of device. */
    struct urma_port_attr port_attr[MAX_PORT_CNT];
    uint16_t vf_cnt;           /* PF: greater than or equal to 0; VF:must be 0. */
} urma_device_attr_t;

/* security infomation */
typedef struct urma_key {
    uint32_t key;
} urma_key_t;

typedef struct urma_dukey_param {
    uint8_t mask;    // mask of the element that performs the derived operation
    urma_eid_t eid;
    uint32_t uasid;
    /* to add more */
} urma_dukey_param_t;

struct urma_sysfs_dev;
struct urma_ref;
struct urma_ops;
struct urma_provider_ops;

typedef enum urma_transport_type {
    URMA_TRANSPORT_INVALID = -1,
    URMA_TRANSPORT_UB,
    URMA_TRANSPORT_IB,
    URMA_TRANSPORT_IP,
    URMA_TRANSPORT_MAX
} urma_transport_type_t;

typedef enum urma_transport_mode {
    URMA_TM_RM = 0x1,      /* Reliable message */
    URMA_TM_RC = 0x1 << 1, /* Reliable connection */
    URMA_TM_UM = 0x1 << 2, /* Unreliable message */
} urma_transport_mode_t;

typedef enum urma_tp_cc_alg {
    URMA_TP_CC_PFC = 0,
    URMA_TP_CC_DCQCN,
    URMA_TP_CC_DCQCN_AND_NETWORK_CC,
    URMA_TP_CC_LDCP,
    URMA_TP_CC_LDCP_AND_CAQM,
    URMA_TP_CC_LDCP_AND_OPEN_CC,
    URMA_TP_CC_HC3,
    URMA_TP_CC_DIP
} urma_tp_cc_alg_t;

typedef enum urma_congestion_ctrl_alg {
    URMA_CC_PFC = 0x1 << URMA_TP_CC_PFC,
    URMA_CC_DCQCN = 0x1 << URMA_TP_CC_DCQCN,
    URMA_CC_DCQCN_AND_NETWORK_CC = 0x1 << URMA_TP_CC_DCQCN_AND_NETWORK_CC,
    URMA_CC_LDCP = 0x1 << URMA_TP_CC_LDCP,
    URMA_CC_LDCP_AND_CAQM = 0x1 << URMA_TP_CC_LDCP_AND_CAQM,
    URMA_CC_LDCP_AND_OPEN_CC = 0x1 << URMA_TP_CC_LDCP_AND_OPEN_CC,
    URMA_CC_HC3 = 0x1 << URMA_TP_CC_HC3,
    URMA_CC_DIP = 0x1 << URMA_TP_CC_DIP
} urma_congestion_ctrl_alg_t;

typedef struct urma_device {
    char name[URMA_MAX_NAME];         /* [Public] urma device's name, the names of devices
                                         in different transport modes are different. */
    char path[URMA_MAX_PATH];         /* [Public] urma device's path in sysfs. */
    urma_transport_type_t type;       /* [Public] urma device's transport type. */
    urma_eid_t eid;                   /* [Public] urma device's entity_id, eid may conflict
                                         under different transmission modes. */
    struct urma_provider_ops *ops;    /* [Private] urma device driver's ops. */
    struct urma_sysfs_dev *sysfs_dev; /* [Private] internal device corresponding to the urma device */
} urma_device_t;

typedef struct urma_context {
    struct urma_device *dev;  /* [Private] point to the corresponding urma device. */
    struct urma_ops *ops;     /* [Private] operation of urma device. */
    int dev_fd;               /* [Private] fd of urma device's sysfs file. */
    int async_fd;             /* [Private] fd of urma device's async event file. */
    pthread_mutex_t mutex;    /* [Private] mutex of urma context. */
    urma_eid_t eid;           /* [Public] eid of urma device. */
    uint32_t uasid;           /* [Public] uasid of current process. */
    struct urma_ref *ref;     /* [Private] reference count of urma context. */
} urma_context_t;

typedef struct urma_jfce_cfg {
    uint32_t depth;
    void *user_ctx;
} urma_jfce_cfg_t;

typedef struct urma_jfce {
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    int fd;                   /* [Private] fd of completed event. */
    uint32_t refcnt;          /* [Private] reference count of jfce. */
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
    uint32_t eq_id;       /* [Optional] event queue id, no greater than urma_device_cap_t->comp_vector_cnt
                              set to 0 by default */
    urma_jfce_t *jfce;    /* [Required] the event of jfc */
    void *user_ctx;       /* [Optional] private data of jfc, set to NULL by default */
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

typedef union urma_jfs_flag {
    struct {
        uint32_t mode           : 2;  /* 0: URMA_IDC_MODE.
                                         1: URMA_DC_MODE.
                                         2: URMA_LS_MODE */
        uint32_t lock_free      : 1;  /* default as 0, lock protected */
        uint32_t reserved       : 29;
    } bs;
    uint32_t value;
} urma_jfs_flag_t;

typedef struct urma_jfs_cfg {
    uint32_t depth;           /* [Required] the depth of jfs, defaut urma_device_cap_t->jfs_depth */
    urma_jfs_flag_t flag;     /* [Optional] whether is in DC/IDC mode, DC: Direct Command, IDC: InDirect Command. */
                              /* [Optional] reliability:reliable service or unreliable service */
    urma_transport_mode_t trans_mode; /* [Required] transport mode, must be supported by the device */
    uint8_t priority;         /* [Optional] set the priority of JFS, ranging from [0, 15]
                                 Services with low delay need to set high priority. */
    uint8_t max_sge;          /* [Optional] max sge count in one wr, defaut urma_device_cap_t->max_jfs_sge */
    uint8_t max_rsge;         /* [Optional] max remote sge count in one wr, defaut urma_device_cap_t->max_jfs_sge */
    uint32_t max_inline_data; /* [Optional] the max inline data size of JFS. if the parameter is 0,
                                 the system will assign device's max inline data length. */
    uint8_t retry_cnt;        /* [Optional] number of times that jfs will resend packets before report error,
                                 when the remote side does not response, ranging from [0, 7],
                                 the value 0 means never retry */
    uint8_t rnr_retry;        /* [Optional] number of times that jfs will resend packets before report error,
                                 when the remote side is not ready to receive (RNR), ranging from [0, 7],
                                 the value 0 means never retry and,
                                 the value 7 means retry infinite number of times for RDMA devices */
    uint8_t err_timeout;      /* [Optional] the timeout before report error, ranging from [0, 31],
                                 the actual timeout in usec is caculated by: 4.096*(2^err_timeout) */
    urma_jfc_t *jfc;          /* [Required] need to specify jfc */
    void *user_ctx;           /* [Optional] private data of jfs */
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

typedef union urma_jfr_flag {
    struct {
        uint32_t key_policy     : 3;  /* 0: URMA_KEY_NONE
                                         1: URMA_KEY_PLAIN_TEXT
                                         2: URMA_KEY_SIGNED
                                         3: URMA_KEY_ALL_ENCRYPTED
                                         4: URMA_KEY_RESERVED */
        uint32_t tag_matching   : 1;  /* 0: URMA_NO_TAG_MATCHING.
                                         1: URMA_WITH_TAG_MATCHING. */
        uint32_t lock_free      : 1;
        uint32_t reserved       : 27;
    } bs;
    uint32_t value;
} urma_jfr_flag_t;

typedef struct urma_jfr_cfg {
    uint32_t depth;        /* [Required] total depth, include berth, defaut urma_device_cap_t->jfr_depth. */
    urma_jfr_flag_t flag;  /* [Optional] whether is in TAG_matching, whether is in DC/IDC mode. */
    urma_transport_mode_t trans_mode; /* [Required] transport mode, must be supported by the device */
    uint8_t max_sge;       /* [Optional] max sge count in one wr, defaut urma_device_cap_t->max_jfr_sge. */
    uint8_t min_rnr_timer; /* [Optional] the minimum RNR NACK timer, ranging from [0, 31], i.e.
                              the time before jfr sends NACK to the sender for the reason of "ready to receive" */
    urma_jfc_t *jfc;       /* [Required] need to specify jfc. */
    urma_key_t ukey;       /* [Required] specify key for jfr. */
    uint32_t id;           /* [Optional] specify jfr id. If the parameter is 0,
                              the system will randomly assign a non-0 value. */
    void *user_ctx;        /* [Optional] private data of jfr */
} urma_jfr_cfg_t;

typedef enum urma_jfr_attr_mask {
    JFR_RX_THRESHOLD = 0x1
} urma_jfr_attr_mask_t;

typedef struct urma_jfr_attr {
    uint32_t mask;   // mask value refer to urma_jfr_attr_mask_t
    uint32_t rx_threshold;
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

typedef enum urma_tp_type {
    URMA_TP = 0, /* Single TP */
    URMA_TPG = 0x1, /* TP group */
} urma_tp_type_t;

typedef struct urma_rjfr {
    urma_jfr_id_t jfr_id; /* see urma_jetty_id */
    urma_transport_mode_t trans_mode;
} urma_rjfr_t;

typedef struct urma_tp {
    uint8_t type; /* TP or TPG(TP group) */
    uint32_t tpn;
} urma_tp_t;

typedef struct urma_stats {
    uint64_t bytes;          /* [Public] Bytes of recv/send. */
    uint64_t packets;        /* [Public] pkts of recv/send. */
    uint64_t err_packets;    /* [Public] error pkts of recv/send. */
} urma_stats_t;

typedef struct urma_jetty_stats {
    urma_stats_t jfs_stats;
    urma_stats_t jfr_stats;
    urma_stats_t jetty_send_stats;
    urma_stats_t jetty_recv_stats;
} urma_jetty_stats_t;

typedef union urma_jetty_flag {
    struct {
        uint32_t share_jfr : 1; /* 0: URMA_NO_SHARE_JFR.
                                   1: URMA_SHARE_JFR. */
        uint32_t reserved  : 29;
    } bs;
    uint32_t value;
} urma_jetty_flag_t;

typedef struct urma_jetty_cfg {
    uint32_t id;                 /* [Optional] user specified jetty id. */
    urma_jetty_flag_t flag;      /* [Optional] Connection or connection less */

    /* send configuration */
    urma_jfs_cfg_t *jfs_cfg;     /* [Required] see urma_jfs_cfg_t */

    /* recv configuration */
    union {
        struct {
            urma_jfr_t *jfr;     /* [Optional] shared jfr to receive msg */
            urma_jfc_t *jfc;     /* [Optional] To replace the jfc related to the above jfr */
        } shared;                /* [Optional] */
        urma_jfr_cfg_t *jfr_cfg; /* [Optional] Param to create an new internal jfr. */
    };                           /* [Required] */
    void *user_ctx;              /* [Optional] private data of jetty */
} urma_jetty_cfg_t;

typedef struct urma_rjetty {
    urma_jetty_id_t jetty_id;
    urma_transport_mode_t trans_mode;
} urma_rjetty_t;

typedef enum urma_target_type {
    URMA_JFR = 0,
    URMA_JETTY,
    URMA_JFR_GROUP,
    URMA_JETTY_GROUP
} urma_target_type_t;

typedef struct urma_target_jetty {
    urma_context_t *urma_ctx;    /* [Private] point to urma context. */
    urma_jetty_id_t id;        /* [Private] see urma_jetty_id. */
    uint64_t handle;
    urma_transport_mode_t trans_mode;
    urma_tp_t tp;
    urma_target_type_t type; // todo supplementary target type
} urma_target_jetty_t;

typedef enum urma_jetty_attr_mask {
    JETTY_RX_THRESHOLD = 0x1
} urma_jetty_attr_mask_t;

typedef struct urma_jetty_attr {
    uint32_t mask;   // mask value refer to urma_jetty_attr_mask_t
    uint32_t rx_threshold;
} urma_jetty_attr_t;

typedef struct urma_jetty {
    urma_context_t *urma_ctx;       /* [Private] point to urma context. */
    urma_jetty_id_t jetty_id;           /* [Public] see urma_jetty_id. */
    urma_target_jetty_t *remote_jetty;  /* [Private] Only valid for connection mode Jetty.
                                       After the bind succeeds, the pointer is not null. */
    urma_jetty_cfg_t jetty_cfg;         /* [Public] storage jetty config. */
    uint64_t handle;
    pthread_mutex_t event_mutex;
    pthread_cond_t event_cond;
    uint32_t async_events_acked;
} urma_jetty_t;

/* memory infomation */
typedef struct urma_ubva {
    urma_eid_t eid;
    uint32_t uasid; // 24 bit for UB; 16 bit for IB
    uint64_t va;
} __attribute__((packed)) urma_ubva_t;

/* segment definition */
typedef union urma_reg_seg_flag {
    struct {
        uint32_t key_policy     : 3;  /* 0: URMA_KEY_NONE.
                                         1: URMA_KEY_PLAIN_TEXT.
                                         2: URMA_KEY_SIGNED.
                                         3: URMA_KEY_ALL_ENCRYPTED.
                                         4: URMA_KEY_RESERVED. */
        uint32_t cacheable      : 1;  /* 0: URMA_NON_CACHEABLE.
                                         1: URMA_CACHEABLE. */
        uint32_t dsva           : 1;
        uint32_t access         : 6;  /* (0x1): URMA_ACCESS_LOCAL_WRITE.
                                         (0x1 << 1): URMA_ACCESS_REMOTE_READ.
                                         (0x1 << 2): URMA_ACCESS_REMOTE_WRITE.
                                         (0x1 << 3): URMA_ACCESS_REMOTE_ATOMIC.
                                         (0x1 << 4)：URMA_ACCESS_REMOTE_INVALIDATE. */
        uint32_t non_pin        : 1;  /* 0: segment pages pinned.
                                         1: segment pages non-pinned. */
        uint32_t user_iova      : 1;  /* 0: segment without user iova addr.
                                         1: segment with user iova addr. */
        uint32_t reserved       : 19;
    } bs;
    uint32_t value;
} urma_reg_seg_flag_t;

typedef union urma_seg_attr {
    struct {
        uint32_t key_policy     : 3;  /* 0: URMA_KEY_NONE.
                                         1: URMA_KEY_PLAIN_TEXT.
                                         2: URMA_KEY_SIGNED.
                                         3: URMA_KEY_ALL_ENCRYPTED.
                                         4: URMA_KEY_RESERVED. */
        uint32_t cacheable      : 1;  /* 0: URMA_NON_CACHEABLE.
                                         1: URMA_CACHEABLE. */
        uint32_t dsva           : 1;
        uint32_t access         : 6;  /* (0x1): URMA_ACCESS_LOCAL_WRITE.
                                         (0x1 << 1): URMA_ACCESS_REMOTE_READ.
                                         (0x1 << 2): URMA_ACCESS_REMOTE_WRITE.
                                         (0x1 << 3): URMA_ACCESS_REMOTE_ATOMIC.
                                         (0x1 << 4): URMA_ACCESS_REMOTE_INVALIDATE. */
        uint32_t non_pin        : 1;  /* 0: segment pages pinned.
                                         1: segment pages non-pinned. */
        uint32_t user_iova      : 1;  /* 0: segment without user iova addr.
                                         1: segment with user iova addr. */
        uint32_t reserved       : 19;
    } bs;
    uint32_t value;
} urma_seg_attr_t;

typedef union urma_import_seg_flag {
    struct {
        uint32_t cacheable      : 1;  /* 0: URMA_NON_CACHEABLE.
                                         1: URMA_CACHEABLE. */
        uint32_t access         : 6;  /*  (0x1 << 0): URMA_ACCESS_LOCAL_WRITE.
                                          (0x1 << 1): URMA_ACCESS_REMOTE_READ.
                                          (0x1 << 2): URMA_ACCESS_REMOTE_WRITE.
                                          (0x1 << 3): URMA_ACCESS_REMOTE_ATOMIC.
                                          (0x1 << 4)：URMA_ACCESS_REMOTE_INVALIDATE.
                                      */
        uint32_t mapping        : 1;  /* 0: URMA_SEG_NOMAP/
                                         1: URMA_SEG_MAPPED. */
        uint32_t reserved       : 24;
    } bs;
    uint32_t value;
} urma_import_seg_flag_t;

typedef struct urma_key_id {
    urma_context_t *urma_ctx;
    uint32_t key_id;
    uint64_t handle;
} urma_key_id_t;

typedef struct urma_seg_cfg {
    uint64_t va;                  /* specify the address of the segment to be registered */
    uint64_t len;                 /* specify the length of the segment to be registered */
    uint32_t key_id;              /* TODO delete */
    urma_key_id_t *keyid;
    const urma_key_t *key;        /* Security authentication for access */
    urma_reg_seg_flag_t flag;
    uintptr_t user_ctx;
    int64_t iova;                /* user iova, maybe zero-based-address */
} urma_seg_cfg_t;

typedef struct urma_seg {
    urma_ubva_t ubva;      /* [Public] ubva of segment. */
    uint64_t len;          /* [Public] length of segment. */
    urma_seg_attr_t attr;  /* [Public] include: access flag, key policy, cacheability. */
    uint32_t key_id;       /* [Private] match key */
    uintptr_t user_ctx;    /* [Private] private data of segment */
} urma_seg_t;

typedef struct urma_target_seg {
    urma_seg_t seg;           /* [Private] see urma_seg_t. */
    uint64_t mva;             /* [Public] mapping addr when import remote seg. */
    urma_context_t *urma_ctx; /* [Private] point to urma context. */
    urma_key_id_t *keyid; /* When registering seg, it is a valid address; when importing seg, it is NULL */
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
    uint32_t rsv;
} urma_user_ctl_out_t;

typedef struct urma_sge {
    uint64_t addr;
    uint32_t len;
    urma_target_seg_t *tseg;
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
    urma_sg_t src; // including total data length. src is local va for write, and remote va for read.
    urma_sg_t dst; // dst is remote va for write, and local va for read.
    uint64_t notify_data;   // notify data or imm data in host byte order;
} urma_rw_wr_t;

typedef struct urma_send_wr {
    urma_sg_t src;  // including total data length
    uint8_t target_hint;   /* required when using jetty group */
    uint64_t imm_data;     // imm_data in host byte order;
    urma_target_seg_t *tseg; /* tseg used only when send with invalidate */
} urma_send_wr_t;

typedef struct urma_cas_wr {
    urma_sge_t *dst;    // len is the data length of CAS operation, less than or equal to 8B
    urma_sge_t *src;    // local address for destination original value writeback, len represents the buffer length.
    uint64_t cmp_data;  // Value compared with destination value
    uint64_t swap_data; // If destination value is the same as cmp_data, destination value will be changed to swap_data
} urma_cas_wr_t;

typedef struct urma_cas_mask_wr {
    urma_cas_wr_t cas;
    uint64_t cmp_msk;
    uint64_t swap_msk;
} urma_cas_mask_wr_t;

typedef struct urma_faa_wr {
    urma_sge_t *dst;    // len is the data length of FAA operation
    urma_sge_t *src;    // local address for destination original value writeback, len represents the buffer length.
    uint64_t operand;   // Addend
} urma_faa_wr_t;

typedef struct urma_faa_mask_wr {
    urma_faa_wr_t faa;
    uint64_t msk;
} urma_faa_mask_wr_t;

typedef struct urma_jfs_wr  {
    urma_opcode_t opcode;
    urma_jfs_wr_flag_t flag;
    urma_target_jetty_t *tjetty;
    uintptr_t user_ctx; // completion data
    union {
        urma_rw_wr_t rw;
        urma_send_wr_t send;
        urma_cas_wr_t cas;
        urma_cas_mask_wr_t cas_mask;
        urma_faa_wr_t faa;
        urma_faa_mask_wr_t faa_mask;
    };
    struct urma_jfs_wr *next;
} urma_jfs_wr_t;

typedef struct urma_jfr_wr  {
    urma_sg_t src;                 // includeing buffer length
    uintptr_t user_ctx;            // completion data, eg. wr id
    struct urma_jfr_wr *next;
} urma_jfr_wr_t;

typedef union urma_cr_flag {
    struct {
        uint8_t inline_flag     : 1;     // Indicate CR contain inline data or not
        uint8_t s_r             : 1;     // Indicate CR stands for sending or receiving, 0: send, 1: recv.
        uint8_t jetty           : 1;     // Indicate CR stands for jetty or jfs/jfr, 0: jfs/jfr, 1: jetty.
        uint32_t reserved       : 29;
    } bs;
    uint8_t value;
} urma_cr_flag_t;

typedef struct urma_cr_key {
    uint32_t key_id;
    urma_key_t ukey;
} urma_cr_key_t;

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
        urma_cr_key_t invalid_key; // Valid only for receiving CR: send with invalidate.
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
        uint32_t port_id;
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
    urma_ur_attr_t attr;  // include: access flag, key policy, cacheability, dsva
    uint64_t token;
    uintptr_t user_ctx;
} urma_ur_t;

// Out parametre for import UR
typedef struct urma_target_ur {
    char name[UR_NAME_MAX_LEN]; // UR url name
    uint64_t size;
    urma_import_ur_flag_t flag;  // include: access flag, key policy, cacheability, dsva
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
    urma_ur_attr_t attr;  // include: access flag, key policy, cacheability, dsva
    uint32_t cnt; //
    urma_seg_info_t seg_list[0];    // cnt * sizeof(urma_seg_info_t)
} urma_ur_info_t;

typedef struct urma_jfr_info {
    char name[JFR_NAME_MAX_LEN]; // jfr url name
    urma_eid_t eid;
    uint32_t uasid;
    uint32_t id;
    // urma_key_t key;
} urma_jfr_info_t;

/* callback infomation */
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
