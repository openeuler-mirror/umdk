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

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_NL_MSG_BUF_LEN 1024
#define TPSA_NETLINK_UBCORE_TYPE 24
#define TPSA_NET_LINK_PORT 100
#define TPSA_LM_REQ_SIZE 15  /* TODO: fix */
#define TPSA_MAX_SOCKET_MSG_LEN 12000
typedef enum tpsa_nlmsg_type {
    TPSA_NL_CREATE_TP_REQ = NLMSG_MIN_TYPE, /* 0x10 */
    TPSA_NL_CREATE_TP_RESP,
    TPSA_NL_DESTROY_TP_REQ,
    TPSA_NL_DESTROY_TP_RESP,
    TPSA_NL_QUERY_TP_REQ,
    TPSA_NL_QUERY_TP_RESP,
    TPSA_NL_RESTORE_TP_REQ,
    TPSA_NL_RESTORE_TP_RESP,
    TPSA_NL_SET_AGENT_PID,
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
    TPSA_NL_QUERY_TPF_DEV_INFO,
    TPSA_NL_UPDATE_TPF_DEV_INFO_REQ,
    TPSA_NL_UPDATE_TPF_DEV_INFO_RESP,
} tpsa_nlmsg_type_t;

typedef enum tpsa_sock_type {
    TPSA_CREATE_REQ = 0,
    TPSA_CREATE_RESP,
    TPSA_CREATE_ACK,
    TPSA_CREATE_FINISH,
    TPSA_DESTROY_REQ,
    TPSA_TABLE_SYC,
    TPSA_LM_CREATE_REQ,
    TPSA_LM_RESP,
    TPSA_FORWARD,
    TPSA_TP_ERROR_REQ,
    TPSA_TP_ERROR_RESP,
    TPSA_TP_ERROR_ACK,
    TPSA_LM_NOTIFY,
    TPSA_LM_ROLLBACK_REQ
} tpsa_sock_type_t;

typedef enum tpsa_nl_resp_status {
    TPSA_NL_RESP_IN_PROGRESS = -2,
    TPSA_NL_RESP_FAIL = -1,
    TPSA_NL_RESP_SUCCESS = 0
} tpsa_nl_resp_status_t;

typedef struct tpsa_nl_query_tp_req {
    urma_transport_mode_t trans_mode;
} tpsa_nl_query_tp_req_t;

typedef struct tpsa_nl_query_tp_resp {
    tpsa_nl_resp_status_t ret;
    bool tp_exist;
    uint32_t tpn; /* must set if tp exist is true */
    urma_eid_t dst_eid; /* underlay */
    tpsa_net_addr_t src_addr; /* underlay */
    tpsa_net_addr_t dst_addr; /* underlay */
    tpsa_multipath_tp_cfg_t cfg;
} tpsa_nl_query_tp_resp_t;

typedef struct tpsa_nl_create_vtp_req {
    uint32_t vtpn;
    tpsa_transport_mode_t trans_mode;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t eid_index;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    char dev_name[TPSA_MAX_DEV_NAME];
    bool virtualization;
    char tpfdev_name[TPSA_MAX_DEV_NAME];
    /* for alpha */
    struct tpsa_ta_data ta_data;
    uint32_t udrv_in_len;
    uint32_t udrv_out_len;
    uint8_t udrv_data[0];
} tpsa_nl_create_vtp_req_t;

typedef struct tpsa_nl_create_vtp_resp {
    tpsa_nl_resp_status_t ret;
    uint32_t vtpn;
    uint32_t udrv_out_len;
    uint8_t udrv_out_data[0];
} tpsa_nl_create_vtp_resp_t;

typedef tpsa_nl_create_vtp_req_t tpsa_nl_destroy_vtp_req_t;

typedef struct tpsa_nl_destroy_vtp_resp {
    tpsa_nl_resp_status_t ret;
} tpsa_nl_destroy_vtp_resp_t;

typedef enum tpsa_pattern {
    TPSA_PATTERN_1 = 0,
    TPSA_PATTERN_3
} tpsa_pattern_t;

typedef struct tpsa_nl_alloc_eid_req {
    uint32_t eid_index;
    char dev_name[TPSA_MAX_DEV_NAME];
    tpsa_pattern_t eid_type;
    bool virtualization;
    char tpfdev_name[TPSA_MAX_DEV_NAME];
} tpsa_nl_alloc_eid_req_t;

typedef struct tpsa_nl_alloc_eid_resp {
    tpsa_nl_resp_status_t ret;
    urma_eid_t eid;
    uint32_t eid_index;
    uint32_t upi;
} tpsa_nl_alloc_eid_resp_t;

typedef struct tpsa_nl_alloc_eid_req tpsa_nl_dealloc_eid_req_t;
typedef struct tpsa_nl_alloc_eid_resp tpsa_nl_dealloc_eid_resp_t;

typedef struct tpsa_nl_mig_req {
    uint16_t mig_fe_idx; /* The virtual machine number for live migration */
    char dev_name[TPSA_MAX_DEV_NAME];
} tpsa_nl_mig_req_t;

typedef struct tpsa_nl_mig_resp {
    uint16_t mig_fe_idx;
    tpsa_mig_resp_status_t status;
} tpsa_nl_mig_resp_t;

typedef tpsa_nl_mig_req_t tpsa_nl_stop_proc_vtp_req_t;
typedef tpsa_nl_mig_req_t tpsa_nl_query_vtp_mig_status_t;
typedef tpsa_nl_mig_req_t tpsa_nl_flow_stopped_t;
typedef tpsa_nl_mig_req_t tpsa_nl_mig_rollback_t;
typedef tpsa_nl_mig_req_t tpsa_nl_mig_vm_start_t;

typedef tpsa_nl_mig_resp_t tpsa_nl_stop_proc_vtp_resp_t;
typedef tpsa_nl_mig_resp_t tpsa_nl_query_vtp_stop_status_resp_t;
typedef tpsa_nl_mig_resp_t tpsa_nl_flow_stopped_resp_t;
typedef tpsa_nl_mig_resp_t tpsa_nl_mig_rollback_resp_t;
typedef tpsa_nl_mig_resp_t tpsa_nl_mig_vm_start_resp_t;

typedef struct tpsa_nl_config_device_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint32_t max_rc_cnt;
    uint32_t max_rc_depth;
    uint32_t min_slice;                 /* TA slice size byte */
    uint32_t max_slice;                 /* TA slice size byte */
    bool is_tpf_dev;
    bool virtualization;
    char tpfdev_name[TPSA_MAX_DEV_NAME];
} tpsa_nl_config_device_req_t;

typedef struct tpsa_nl_config_device_resp {
    tpsa_nl_resp_status_t ret;
    uint32_t rc_cnt;
    uint32_t rc_depth;
    uint32_t slice;                 /* TA slice size byte */
    bool is_tpf_dev;
    uint32_t suspend_period;
    uint32_t suspend_cnt;
} tpsa_nl_config_device_resp_t;

typedef struct tpsa_nl_update_tpf_dev_info_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    tpsa_device_feat_t dev_fea;
    uint32_t cc_entry_cnt;
    uint8_t data[0];
} tpsa_nl_update_tpf_dev_info_req_t; // same as ubcore_update_tpf_dev_info_req_t

typedef struct tpsa_nl_update_tpf_dev_info_resp {
    tpsa_nl_resp_status_t ret;
} tpsa_nl_update_tpf_dev_info_resp_t;

typedef struct tpsa_netlink_msg {
    struct nlmsghdr hdr;
    uint32_t nlmsg_seq;
    tpsa_nlmsg_type_t msg_type;
    tpsa_transport_type_t transport_type;
    urma_eid_t src_eid;
    urma_eid_t dst_eid;
    uint32_t payload_len;
    uint8_t payload[TPSA_NL_MSG_BUF_LEN];
} __attribute__((packed)) tpsa_nl_msg_t;

struct tpsa_lm_req_entry {
    uint32_t location;
    tpsa_transport_mode_t trans_mode;

    union {
        rm_vtp_table_entry_t rm_entry;
        rc_vtp_table_entry_t rc_entry;
        um_vtp_table_entry_t um_entry;
    } content;
};

typedef struct tpsa_lm_notification {
    tpsa_net_addr_t dip;
    uint32_t target_rm_num;
    uint32_t target_rc_num;

    struct tpsa_lm_req_entry target_vtp[TPSA_LM_REQ_SIZE];
} tpsa_lm_notification_t;

typedef struct tpsa_lm_req {
    char dev_name[TPSA_MAX_DEV_NAME];
    uint16_t fe_idx;
    bool stop_proc_vtp;

    uint32_t rm_vtp_num;
    uint32_t rc_vtp_num;
    uint32_t um_vtp_num;
    urma_eid_t mig_source;

    /* by default, vtp entry is construct in "RM -> RC -> UM" sequence */
    struct tpsa_lm_req_entry total_vtp[TPSA_LM_REQ_SIZE];
} tpsa_lm_req_t;

typedef struct tpsa_lm_resp {
    uint16_t mig_fe_idx;
    bool last_mig_completed;
    char dev_name[TPSA_MAX_DEV_NAME];
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
} tpsa_nl_tp_error_req_t;

typedef struct tpsa_tp_error_msg {
    tpsa_nl_tp_error_req_t nl_tp_err_req;
    urma_eid_t peer_dev_eid;
} tpsa_tp_error_msg_t;

typedef struct tpsa_sock_msg {
    tpsa_sock_type_t msg_type;

    tpsa_transport_mode_t trans_mode;
    tpsa_net_addr_t dip;
    urma_eid_t local_eid;
    urma_eid_t peer_eid;
    uint32_t local_jetty;
    uint32_t peer_jetty;
    uint32_t vtpn;
    uint32_t local_tpgn;
    uint32_t peer_tpgn;
    uint32_t upi;
    bool liveMigrate;
    bool migrateThird;

    union {
        tpsa_create_req_t req;
        tpsa_create_resp_t resp;
        tpsa_create_ack_t ack;
        tpsa_create_finish_t finish;
        tpsa_destroy_req_t dreq;
        tpsa_table_sync_t tsync;
        tpsa_nl_msg_t nlmsg;
        tpsa_lm_req_t lmmsg;  /* live migrate message */
        tpsa_lm_resp_t lm_resp;
        tpsa_lm_notification_t lmnoti;
        tpsa_nl_mig_req_t rbreq;
        tpsa_tp_error_msg_t tp_err_msg;
    } content;
} tpsa_sock_msg_t;

typedef struct tpsa_netlink_context {
    int fd;
    struct sockaddr_nl src_addr; /* TPS netlink addr */
    struct sockaddr_nl dst_addr; /* ubcore netlink addr */
} tpsa_nl_ctx_t;

typedef struct tpsa_nl_add_sip_req {
    tpsa_net_addr_t netaddr;
    uint32_t prefix_len;
    char dev_name[TPSA_MAX_DEV_NAME];
    uint8_t port_cnt;
    uint8_t port_id[TPSA_MAX_PORT_CNT];
    uint32_t index;
    uint32_t mtu;
} tpsa_nl_add_sip_req_t;

typedef struct tpsa_nl_add_sip_resp {
    tpsa_nl_resp_status_t ret;
} tpsa_nl_add_sip_resp_t;

typedef struct tpsa_nl_del_sip_req {
    uint32_t index;
} tpsa_nl_del_sip_req_t;

typedef struct tpsa_nl_del_sip_resp {
    tpsa_nl_resp_status_t ret;
} tpsa_nl_del_sip_resp_t;

typedef struct tpsa_nl_tp_suspend_req {
    uint32_t tpgn;
    uint32_t tpn;
    uint16_t data_udp_start;
    uint16_t ack_udp_start;
    uint32_t sip_idx;
} tpsa_nl_tp_suspend_req_t;

typedef struct tpsa_nl_migrate_vtp_req {
    tpsa_vtp_cfg_t vtp_cfg;
    char dev_name[TPSA_MAX_DEV_NAME];
    tpsa_nlmsg_type_t msg_type;
} tpsa_nl_migrate_vtp_req_t;

static inline uint32_t tpsa_netlink_msg_len(const tpsa_nl_msg_t *msg)
{
    return offsetof(tpsa_nl_msg_t, payload) + msg->payload_len;
}

/* Send len is hidden in msg->hdr.nlmsg_len, close fd if failed */
int tpsa_nl_send_msg(tpsa_nl_ctx_t *nl, tpsa_nl_msg_t *msg);

/* Close fd if failed */
static ssize_t inline tpsa_nl_recv_msg(tpsa_nl_ctx_t *nl, tpsa_nl_msg_t *msg, size_t len, int epollfd)
{
    if (len > sizeof(tpsa_nl_msg_t)) {
        TPSA_LOG_ERR("Exceeded the maximum length of message buf.\n");
        return -1;
    }

    socklen_t addr_len = (socklen_t)sizeof(struct sockaddr_nl);
    ssize_t recv_len = recvfrom(nl->fd, msg, len, 0, (struct sockaddr *)&nl->src_addr, &addr_len);
    if (recv_len <= 0) {
        return -1;
    }
    return recv_len;
}

tpsa_nl_msg_t *tpsa_handle_nl_query_tp_req(tpsa_nl_msg_t *req);
tpsa_sock_msg_t *tpsa_handle_nl_create_tp_req(tpsa_nl_msg_t *req);
tpsa_nl_msg_t *tpsa_get_add_sip_resp(tpsa_nl_msg_t *req);
tpsa_nl_msg_t *tpsa_get_del_sip_resp(tpsa_nl_msg_t *req);

int tpsa_nl_server_init(tpsa_nl_ctx_t *nl);
void tpsa_nl_server_uninit(tpsa_nl_ctx_t *nl);
tpsa_nl_msg_t *tpsa_alloc_nlmsg(uint32_t payload_len, const urma_eid_t *src_eid, const urma_eid_t *dst_eid);
tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_fast(tpsa_nl_msg_t *nlreq, tpsa_nl_resp_status_t status, uint32_t vtpn);
tpsa_nl_msg_t *tpsa_nl_create_vtp_resp(uint32_t vtpn, tpsa_sock_msg_t *msg);
tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_wait(uint32_t vtpn, tpsa_create_param_t *cparam);
tpsa_nl_msg_t *tpsa_nl_destroy_vtp_resp(tpsa_nl_msg_t *req, tpsa_nl_resp_status_t status);
tpsa_nl_msg_t *tpsa_nl_config_device_resp(tpsa_nl_msg_t *req, tpsa_nl_config_device_resp_t *resp);
tpsa_nl_msg_t *tpsa_nl_update_tpf_dev_info_resp(tpsa_nl_msg_t *req, tpsa_nl_update_tpf_dev_info_resp_t *resp);

tpsa_nl_msg_t *tpsa_nl_mig_msg_resp_fast(tpsa_nl_msg_t *req, tpsa_mig_resp_status_t status);

tpsa_nl_msg_t *tpsa_nl_create_dicover_eid_resp(tpsa_nl_msg_t *req, tpsa_ueid_t *ueid, uint32_t index);
#ifdef __cplusplus
}
#endif

#endif
