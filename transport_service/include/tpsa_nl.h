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

#ifdef __cplusplus
extern "C" {
#endif

#define TPSA_MAC_BYTES 6
#define TPSA_MSG_BUF_LEN 512
#define TPSA_NETLINK_UBCORE_TYPE 24
#define TPSA_NET_LINK_PORT 100

typedef enum tpsa_nl_msg_type {
    TPSA_NL_CREATE_TP_REQ = NLMSG_MIN_TYPE, /* 0x10 */
    TPSA_NL_CREATE_TP_RESP,
    TPSA_NL_DESTROY_TP_REQ,
    TPSA_NL_DESTROY_TP_RESP,
    TPSA_NL_QUERY_TP_REQ,
    TPSA_NL_QUERY_TP_RESP,
    TPSA_NL_RESTORE_TP_REQ,
    TPSA_NL_RESTORE_TP_RESP,
    TPSA_NL_SET_AGENT_PID
} tpsa_nl_msg_type_t;

typedef enum tpsa_transport_type {
    TPSA_TRANSPORT_INVALID = -1,
    TPSA_TRANSPORT_UB,
    TPSA_TRANSPORT_IB,
    TPSA_TRANSPORT_IP,
    TPSA_TRANSPORT_MAX
} tpsa_transport_type_t;

typedef enum tpsa_nl_resp_status {
    TPSA_NL_RESP_FAIL = -1,
    TPSA_NL_RESP_SUCCESS = 0
} tpsa_nl_resp_status_t;

typedef struct tpsa_net_addr {
    urma_eid_t base;
    uint64_t vlan; /* available for UBOE */
    uint8_t mac[TPSA_MAC_BYTES]; /* available for UBOE */
} tpsa_net_addr_t;

typedef struct tpsa_nl_query_tp_req {
    urma_transport_mode_t trans_mode;
} tpsa_nl_query_tp_req_t;

typedef union tpsa_tp_flag {
    struct {
        uint32_t target : 1;         /* 0: initiator, 1: target */
        uint32_t oor_en : 1;         /* out of order receive, 0: disable 1: enable */
        uint32_t sr_en : 1;          /* selective retransmission, 0: disable 1: enable */
        uint32_t cc_en : 1;          /* congestion control algorithm, 0: disable 1: enable */
        uint32_t cc_alg : 4;         /* The value is ubcore_tp_cc_alg_t */
        uint32_t spray_en : 1;       /* spray with src udp port, 0: disable 1: enable */
        uint32_t reserved : 23;
    } bs;
    uint32_t value;
} tpsa_tp_flag_t;

typedef struct tpsa_multipath_tp_cfg {
    tpsa_tp_flag_t flag;
    uint16_t data_rctp_start;
    uint16_t ack_rctp_start;
    uint16_t data_rmtp_start;
    uint16_t ack_rmtp_start;
    uint8_t udp_range;
    uint16_t congestion_alg;
} tpsa_multipath_tp_cfg_t;

typedef struct tpsa_nl_query_tp_resp {
    tpsa_nl_resp_status_t ret;
    bool tp_exist;
    uint32_t tpn; /* must set if tp exist is true */
    urma_eid_t dst_eid; /* underlay */
    tpsa_net_addr_t src_addr; /* underlay */
    tpsa_net_addr_t dst_addr; /* underlay */
    tpsa_multipath_tp_cfg_t cfg;
} tpsa_nl_query_tp_resp_t;

typedef enum tpsa_mtu {
    TPSA_MTU_256      = 1,
    TPSA_MTU_512,
    TPSA_MTU_1024,
    TPSA_MTU_2048,
    TPSA_MTU_4096,
    TPSA_MTU_8192
} tpsa_mtu_t;

typedef enum tpsa_ta_type {
    TPSA_TA_NONE = 0,
    TPSA_TA_JFS_TJFR,
    TPSA_TA_JETTY_TJETTY,
    TPSA_TA_VIRT /* virtualization */
} tpsa_ta_type_t;

typedef struct tpsa_ta {
    tpsa_ta_type_t type;
    urma_jetty_id_t jetty_id; /* local jetty id */
    urma_jetty_id_t tjetty_id; /* peer jetty id */
} tpsa_ta_t;

typedef enum tpsa_transport_mode {
    TPSA_TP_RM = 0x1,     /* Reliable message */
    TPSA_TP_RC = 0x1 << 1, /* Reliable connection */
    TPSA_TP_UM = 0x1 << 2 /* Unreliable message */
} tpsa_transport_mode_t;

typedef struct tpsa_nl_create_tp {
    uint32_t tpn;
    tpsa_net_addr_t local_net_addr;
    tpsa_net_addr_t peer_net_addr;
    tpsa_transport_mode_t trans_mode;
    tpsa_multipath_tp_cfg_t cfg;
    uint32_t rx_psn;
    tpsa_mtu_t mtu;
    tpsa_ta_t ta;
    uint32_t ext_len;
    uint32_t udrv_in_len;
    uint8_t ext_udrv[0];
} tpsa_nl_create_tp_t;

typedef struct tpsa_netlink_msg {
    struct nlmsghdr hdr;
    uint32_t nlmsg_seq;
    tpsa_nl_msg_type_t msg_type;
    tpsa_transport_type_t transport_type;
    urma_eid_t src_eid;
    urma_eid_t dst_eid;
    uint32_t payload_len;
    char payload[TPSA_MSG_BUF_LEN];
} __attribute__((packed)) tpsa_nl_msg_t;

typedef struct tpsa_netlink_context {
    int fd;
    struct sockaddr_nl src_addr; /* TPS netlink addr */
    struct sockaddr_nl dst_addr; /* ubcore netlink addr */
} tpsa_nl_ctx_t;

static inline uint32_t tpsa_netlink_msg_len(const tpsa_nl_msg_t *msg)
{
    return offsetof(tpsa_nl_msg_t, payload) + msg->payload_len;
}

/* Send len is hidden in msg->hdr.nlmsg_len, close fd if faild */
int tpsa_nl_send_msg(tpsa_nl_ctx_t *nl, tpsa_nl_msg_t *msg);

/* Close fd if faild */
static ssize_t inline tpsa_nl_recv_msg(tpsa_nl_ctx_t *nl, tpsa_nl_msg_t *msg, size_t len, int epollfd)
{
    if (len > sizeof(tpsa_nl_msg_t)) {
        TPSA_LOG_ERR("Exceeded the maximum length of message buf.\n");
        return -1;
    }

    socklen_t addr_len = sizeof(struct sockaddr_nl);
    ssize_t recv_len = recvfrom(nl->fd, msg, len, 0, (struct sockaddr *)&nl->src_addr, &addr_len);
    if (recv_len <= 0) {
        return -1;
    }
    return recv_len;
}

int tpsa_nl_server_init(tpsa_nl_ctx_t *nl);
void tpsa_nl_server_uninit(tpsa_nl_ctx_t *nl);

#ifdef __cplusplus
}
#endif

#endif