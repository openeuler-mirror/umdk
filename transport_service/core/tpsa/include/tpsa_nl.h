/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa netlink header file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port netlink functions from tpsa_connect and daemon here
 */

#ifndef TPSA_NL_H
#define TPSA_NL_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>
#include "ub_util.h"
#include "urma_types.h"
#include "tpsa_log.h"
#include "tpsa_table.h"
#include "tpsa_types.h"
#include "uvs_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_NL_MSG_BUF_LEN 1024
#define TPSA_NETLINK_UBCORE_TYPE 24
#define TPSA_NET_LINK_PORT 100
#define TPSA_LM_REQ_SIZE 16
#define TPSA_MAX_SOCKET_MSG_LEN (1024 * 3)

// Must be the same as UBCORE_MSG_RESP_XXX
#define TPSA_NL_RESP_LIMIT_RATE (-EBUSY)
#define TPSA_NL_RESP_RC_JETTY_ALREADY_BIND (-EEXIST)
#define TPSA_NL_RESP_IN_PROGRESS (-EINPROGRESS)
#define TPSA_NL_RESP_FAIL (-EPERM)
#define TPSA_NL_RESP_SUCCESS 0

typedef enum tpsa_nlmsg_type {
    TPSA_NL_QUERY_STATS = 1,
	TPSA_NL_QUERY_RES,
	TPSA_NL_ADD_EID,
	TPSA_NL_DEL_EID,
	TPSA_NL_SET_EID_MODE,
	TPSA_NL_SET_NS_MODE,
	TPSA_NL_SET_DEV_NS,
	TPSA_NL_SET_GENL_PID,
	TPSA_NL_UVS_INIT_RES,
    TPSA_NL_QUERY_TP_REQ,
    TPSA_NL_QUERY_TP_RESP,
    TPSA_NL_RESTORE_TP_REQ,
    TPSA_NL_RESTORE_TP_RESP,
    TPSA_NL_FE2TPF_REQ,
    TPSA_NL_TPF2FE_RESP,
    TPSA_NL_ADD_SIP_REQ,
    TPSA_NL_ADD_SIP_RESP,
    TPSA_NL_DEL_SIP_REQ,
    TPSA_NL_DEL_SIP_RESP,
    TPSA_NL_TP_ERROR_REQ,
    TPSA_NL_TP_SUSPEND_REQ,
    TPSA_NL_MIGRATE_VTP_SWITCH,
    TPSA_NL_MIGRATE_VTP_ROLLBACK,
    TPSA_NL_UPDATE_TPF_DEV_INFO_REQ,
    TPSA_NL_UPDATE_TPF_DEV_INFO_RESP,
} tpsa_nlmsg_type_t;

typedef enum tpsa_sock_type {
    TPSA_CREATE_REQ = 0,
    TPSA_CREATE_RESP,
    TPSA_CREATE_ACK,
    TPSA_DESTROY_REQ,
    TPSA_DESTROY_FINISH,
    TPSA_CREATE_FAIL_RESP,
    TPSA_TABLE_SYC,
    TPSA_TABLE_SYC_RESP,
    TPSA_LM_MIG_REQ,
    TPSA_LM_MIG_RESP,
    TPSA_TP_ERROR_REQ,
    TPSA_TP_ERROR_RESP,
    TPSA_TP_ERROR_ACK,
    TPSA_LM_NOTIFY,
    TPSA_LM_ROLLBACK_REQ,
    TPSA_LM_TRANSFER,
    TPSA_LM_NOTIFY_THIRD,
    TPSA_GENERAL_ACK
} tpsa_sock_type_t;

typedef struct tpsa_nl_query_tp_req {
    urma_transport_mode_t trans_mode;
    char dev_name[UVS_MAX_DEV_NAME];
    uint16_t fe_idx;
} tpsa_nl_query_tp_req_t;

typedef struct tpsa_nl_query_tp_resp {
    int ret;
    uint8_t retry_num;
    uint8_t retry_factor;
    uint8_t ack_timeout;
    uint8_t dscp;
    uint32_t oor_cnt;
} tpsa_nl_query_tp_resp_t;

typedef struct tpsa_nl_create_vtp_req {
    uint32_t vtpn;
    tpsa_transport_mode_t trans_mode;
    uint32_t sub_trans_mode;
    uint32_t rc_share_tp;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t eid_index;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    char dev_name[UVS_MAX_DEV_NAME];
    bool virtualization;
    char tpf_name[UVS_MAX_DEV_NAME];
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint32_t udrv_in_len;
    uint32_t ext_len;
    uint8_t udrv_ext[0];
} tpsa_nl_create_vtp_req_t;

typedef struct tpsa_nl_create_vtp_resp {
    int ret;
    uint32_t vtpn;
} tpsa_nl_create_vtp_resp_t;

typedef tpsa_nl_create_vtp_req_t tpsa_nl_destroy_vtp_req_t;

typedef struct tpsa_nl_destroy_vtp_resp {
    int ret;
} tpsa_nl_destroy_vtp_resp_t;

typedef enum tpsa_pattern {
    TPSA_PATTERN_1 = 0,
    TPSA_PATTERN_3
} tpsa_pattern_t;

typedef struct tpsa_nl_alloc_eid_req {
    uint32_t eid_index;
    char dev_name[UVS_MAX_DEV_NAME];
    tpsa_pattern_t eid_type;
    bool virtualization;
    char tpf_name[UVS_MAX_DEV_NAME];
} tpsa_nl_alloc_eid_req_t;

typedef struct tpsa_nl_alloc_eid_resp {
    int ret;
    urma_eid_t eid;
    uint32_t eid_index;
    uint32_t upi;
    uint16_t fe_idx;
} tpsa_nl_alloc_eid_resp_t;

typedef struct tpsa_nl_alloc_eid_req tpsa_nl_dealloc_eid_req_t;
typedef struct tpsa_nl_alloc_eid_resp tpsa_nl_dealloc_eid_resp_t;

typedef struct tpsa_nl_function_mig_req {
    uint16_t mig_fe_idx; /* The virtual machine number for live migration */
    char dev_name[UVS_MAX_DEV_NAME];
} tpsa_nl_function_mig_req_t;

typedef struct tpsa_nl_mig_resp {
    uint16_t mig_fe_idx;
    tpsa_mig_resp_status_t status;
} tpsa_nl_mig_resp_t;

typedef struct tpsa_nl_config_device_req {
    char dev_name[UVS_MAX_DEV_NAME];
    uint32_t max_rc_cnt;
    uint32_t max_rc_depth;
    uint32_t min_slice;                 /* TA slice size byte */
    uint32_t max_slice;                 /* TA slice size byte */
    bool is_tpf_dev;
    bool virtualization;
    char tpf_name[UVS_MAX_DEV_NAME];
} tpsa_nl_config_device_req_t;

typedef struct tpsa_nl_config_device_resp {
    int ret;
    uint32_t rc_cnt;
    uint32_t rc_depth;
    uint32_t slice;                 /* TA slice size byte */
    uint32_t set_slice;
    bool is_tpf_dev;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
} tpsa_nl_config_device_resp_t;

typedef enum tpsa_nl_update_tpf_opcode {
    TPSA_NL_UPDATE_TPF_ADD = 0,
    TPSA_NL_UPDATE_TPF_DEL,
} tpsa_nl_update_tpf_opcode_t;

typedef struct tpsa_nl_update_tpf_dev_info_req {
    char dev_name[UVS_MAX_DEV_NAME];
    char netdev_name[UVS_MAX_DEV_NAME];
    tpsa_device_feat_t dev_fea;
    uint32_t cc_entry_cnt;
    tpsa_nl_update_tpf_opcode_t opcode;
    uint8_t data[0];
} tpsa_nl_update_tpf_dev_info_req_t; // same as ubcore_update_tpf_dev_info_req_t

typedef struct tpsa_nl_update_tpf_dev_info_resp {
    int ret;
} tpsa_nl_update_tpf_dev_info_resp_t;

typedef struct tpsa_netlink_msg {
    struct nlmsghdr hdr;
    uint32_t nlmsg_seq;
    tpsa_nlmsg_type_t msg_type;
    urma_eid_t src_eid;
    urma_eid_t dst_eid;
    tpsa_transport_type_t transport_type;
    uint32_t payload_len;
    uint8_t payload[TPSA_NL_MSG_BUF_LEN];
} tpsa_nl_msg_t;

struct tpsa_lm_req_entry {
    bool lm_need_del;
    uint32_t location;
    tpsa_transport_mode_t trans_mode;

    union {
        rm_vtp_table_entry_t rm_entry;
        rc_vtp_table_entry_t rc_entry;
        um_vtp_table_entry_t um_entry;
    } content;
};

typedef struct tpsa_lm_notification {
    uvs_net_addr_info_t dip;
    uvs_net_addr_t dst_uvs_ip; /* In a live migration scenario, the tpsa_ip of the migration destination. */
    uint32_t target_rm_num;
    uint32_t target_rc_num;

    struct tpsa_lm_req_entry target_vtp[TPSA_LM_REQ_SIZE];
} tpsa_lm_notification_t;

typedef struct tpsa_lm_req {
    char dev_name[UVS_MAX_DEV_NAME];
    uint16_t fe_idx;
    bool stop_proc_vtp;

    uint32_t rm_vtp_num;
    uint32_t rc_vtp_num;
    uint32_t um_vtp_num;
    uvs_net_addr_t src_uvs_ip; /* the tpsa_ip of the migrate source */

    /* by default, vtp entry is construct in "RM -> RC -> UM" sequence */
    struct tpsa_lm_req_entry total_vtp[TPSA_LM_REQ_SIZE];
} tpsa_lm_req_t;

typedef struct tpsa_lm_resp {
    uint16_t mig_fe_idx;
    bool last_mig_completed;
    char dev_name[UVS_MAX_DEV_NAME];
} tpsa_lm_resp_t;

typedef struct tpsa_nl_tp_error_req {
    uint32_t tpgn;
    uint32_t tpn;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint32_t tx_psn;
    uint32_t peer_tpn;
    tpsa_transport_mode_t trans_mode;
    uint32_t sip_idx;
    urma_eid_t local_eid;
    uint32_t local_jetty_id;
    urma_eid_t peer_eid;
    uint32_t peer_jetty_id;
    char tpf_dev_name[UVS_MAX_DEV_NAME];
} tpsa_nl_tp_error_req_t;

typedef struct tpsa_tp_error_msg {
    tpsa_nl_tp_error_req_t nl_tp_err_req;
    uvs_net_addr_info_t dip;
} tpsa_tp_error_msg_t;

typedef struct tpsa_sock_msg {
    struct uvs_base_header base;
    tpsa_sock_type_t msg_type;

    tpsa_transport_mode_t trans_mode;
    uvs_net_addr_info_t sip;
    uvs_net_addr_t src_uvs_ip;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    uint32_t vtpn;
    uint32_t local_tpgn;
    uint32_t peer_tpgn;
    uint32_t upi;
    bool live_migrate;
    bool migrate_third;
    union {
        tpsa_create_req_t req;
        tpsa_create_resp_t resp;
        tpsa_create_ack_t ack;
        tpsa_create_fail_resp_t fail_resp;
        tpsa_destroy_req_t dreq;
        tpsa_destroy_finish_t dfinish;
        tpsa_table_sync_t tsync;
        tpsa_table_sync_resp_t tsync_resp;
        tpsa_nl_msg_t nlmsg;
        tpsa_lm_req_t lmmsg;  /* live migrate message */
        tpsa_lm_resp_t lm_resp;
        tpsa_lm_notification_t lmnoti;
        tpsa_nl_function_mig_req_t rbreq;
        tpsa_tp_error_msg_t tp_err_msg;
    } content;
} tpsa_sock_msg_t;

typedef struct tpsa_nl_add_sip_req {
    uvs_net_addr_info_t netaddr;
    char dev_name[UVS_MAX_DEV_NAME];
    uint8_t port_cnt;
    uint8_t port_id[TPSA_MAX_PORT_CNT];
    uint32_t index;
    uint32_t mtu;
    char netdev_name[UVS_MAX_DEV_NAME]; /* for change mtu */
} tpsa_nl_add_sip_req_t;

typedef struct tpsa_nl_add_sip_resp {
    int ret;
} tpsa_nl_add_sip_resp_t;

typedef struct tpsa_nl_del_sip_req {
    char dev_name[UVS_MAX_DEV_NAME];
    uint32_t index;
} tpsa_nl_del_sip_req_t;

typedef struct tpsa_nl_del_sip_resp {
    int ret;
} tpsa_nl_del_sip_resp_t;

typedef struct tpsa_nl_tp_suspend_req {
    uint32_t tpgn;
    uint32_t tpn;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint32_t sip_idx;
    char tpf_dev_name[UVS_MAX_DEV_NAME];
} tpsa_nl_tp_suspend_req_t;

typedef struct tpsa_nl_migrate_vtp_req {
    tpsa_vtp_cfg_t vtp_cfg;
    char dev_name[UVS_MAX_DEV_NAME];
    tpsa_nlmsg_type_t msg_type;
} tpsa_nl_migrate_vtp_req_t;

typedef struct tpsa_genl_context {
    struct nl_sock *sock;
    int genl_id;
    void *args;
    int fd;
} tpsa_genl_ctx_t;

static inline uint32_t tpsa_netlink_msg_len(const tpsa_nl_msg_t *msg)
{
    return offsetof(tpsa_nl_msg_t, payload) + msg->payload_len;
}

tpsa_sock_msg_t *tpsa_handle_nl_create_tp_req(tpsa_nl_msg_t *req);
tpsa_nl_msg_t *tpsa_get_add_sip_resp(tpsa_nl_msg_t *req, int status);
tpsa_nl_msg_t *tpsa_get_del_sip_resp(tpsa_nl_msg_t *req, int status);

tpsa_nl_msg_t *tpsa_alloc_nlmsg(uint32_t payload_len, const urma_eid_t *src_eid, const urma_eid_t *dst_eid);
tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_fast(tpsa_nl_msg_t *nlreq, int status, uint32_t vtpn);
tpsa_nl_msg_t *tpsa_nl_create_vtp_resp(tpsa_resp_id_t *resp_id, uint32_t vtpn, int resp_status);
tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_wait(uint32_t vtpn, tpsa_create_param_t *cparam);
tpsa_nl_msg_t *tpsa_nl_destroy_vtp_resp(tpsa_nl_msg_t *req, int status);
tpsa_nl_msg_t *tpsa_nl_config_device_resp(tpsa_nl_msg_t *req, tpsa_nl_config_device_resp_t *resp);
tpsa_nl_msg_t *tpsa_nl_update_tpf_dev_info_resp(tpsa_nl_msg_t *req, tpsa_nl_update_tpf_dev_info_resp_t *resp);

tpsa_nl_msg_t *tpsa_nl_mig_msg_resp_fast(tpsa_nl_msg_t *req, tpsa_mig_resp_status_t status);

int tpsa_nl_create_dicover_eid_resp(tpsa_genl_ctx_t *genl_ctx, tpsa_nl_msg_t *req, tpsa_ueid_t *ueid, int ret);

int tpsa_genl_init(tpsa_genl_ctx_t *genl_ctx);
void tpsa_genl_uninit(struct nl_sock *sock);
int tpsa_genl_send_msg(tpsa_genl_ctx_t *genl, tpsa_nl_msg_t *tpsa_msg);
int tpsa_get_init_res(tpsa_genl_ctx_t *genl);
int tpsa_genl_handle_event(tpsa_genl_ctx_t *genl_ctx);
int tpsa_nl_set_nonblock_opt(int fd);
#ifdef __cplusplus
}
#endif

#endif
