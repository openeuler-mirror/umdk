/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa netlink implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port netlink functions from tpsa_connect and daemon here
 */
#include <errno.h>

#include "tpsa_log.h"
#include "tpsa_net.h"
#include "tpsa_nl.h"

/* Set fd to be nonblocking */
static int tpsa_nl_set_nonblock_opt(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        TPSA_LOG_ERR("Failed to get flags of fd, err: %d.\n", errno);
        return -1;
    }
    if (fcntl(fd, F_SETFL, (uint32_t)flags | O_NONBLOCK) == -1) {
        TPSA_LOG_ERR("Failed to set fd to non block, err: %d.\n", errno);
        return -1;
    }
    return 0;
}

int tpsa_nl_server_init(tpsa_nl_ctx_t *nl)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, TPSA_NETLINK_UBCORE_TYPE);
    if (fd == -1) {
        TPSA_LOG_ERR("create socket err: [%d]%s\n", errno, ub_strerror(errno));
        return -1;
    }

    (void)memset(&nl->src_addr, 0, sizeof(struct sockaddr_nl));
    nl->src_addr.nl_family = AF_NETLINK;
    nl->src_addr.nl_pid = (uint32_t)getpid();
    nl->src_addr.nl_groups = 0;
    nl->dst_addr.nl_family = AF_NETLINK;
    nl->dst_addr.nl_pid = 0; // to kernel
    nl->dst_addr.nl_groups = 0;

    if (tpsa_nl_set_nonblock_opt(fd) != 0) {
        TPSA_LOG_ERR("Failed to set netlink opt, err: %s.\n", ub_strerror(errno));
        (void)close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&nl->src_addr, sizeof(struct sockaddr_nl)) != 0) {
        TPSA_LOG_ERR("Failed to bind port, err: [%d]%s.\n", errno, ub_strerror(errno));
        (void)close(fd);
        return -1;
    }
    nl->fd = fd;
    return 0;
}

void tpsa_nl_server_uninit(tpsa_nl_ctx_t *nl)
{
    (void)close(nl->fd);
    nl->fd = -1;
}

int tpsa_nl_send_msg(tpsa_nl_ctx_t *nl, tpsa_nl_msg_t *msg)
{
    if (msg == NULL || nl == NULL) {
        return -1;
    }

    if (msg->hdr.nlmsg_len > sizeof(tpsa_nl_msg_t)) {
        TPSA_LOG_ERR("Maximum message length exceeded\n");
        return -1;
    }

    ssize_t ret = sendto(nl->fd, &msg->hdr, msg->hdr.nlmsg_len, 0,
        (struct sockaddr *)&nl->dst_addr, sizeof(struct sockaddr_nl));
    if (ret == -1) {
        TPSA_LOG_ERR("sendto err: %s.\n", ub_strerror(errno));
        return -1;
    }
    return 0;
}

tpsa_nl_msg_t *tpsa_alloc_nlmsg(uint32_t payload_len, const urma_eid_t *src_eid, const urma_eid_t *dst_eid)
{
    tpsa_nl_msg_t *msg = calloc(1, sizeof(tpsa_nl_msg_t) + payload_len);
    if (msg == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl message.");
        return NULL;
    }
    msg->src_eid = *src_eid;
    msg->dst_eid = *dst_eid;
    msg->payload_len = payload_len;
    return msg;
}

static void tpsa_query_tp(tpsa_nl_query_tp_resp_t *query_tp_resp, urma_eid_t src_eid, urma_eid_t dst_eid)
{
    /* TODO: table check and assignment */
    query_tp_resp->dst_eid = dst_eid;
    query_tp_resp->src_addr.eid = src_eid;
    query_tp_resp->src_addr.type = TPSA_NET_ADDR_TYPE_IPV4;
    query_tp_resp->dst_addr.eid = dst_eid;
    query_tp_resp->dst_addr.type = TPSA_NET_ADDR_TYPE_IPV4;
    query_tp_resp->tp_exist = false;
    query_tp_resp->tpn = 0;
    query_tp_resp->ret = TPSA_NL_RESP_SUCCESS;

    return;
}

tpsa_nl_msg_t *tpsa_handle_nl_query_tp_req(tpsa_nl_msg_t *req)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *resp = NULL;

    resp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_query_tp_resp_t), &src_eid, &dst_eid);
    if (resp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    resp->hdr.nlmsg_type = TPSA_NL_QUERY_TP_RESP;
    resp->msg_type = TPSA_NL_QUERY_TP_RESP;
    resp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)resp);
    resp->nlmsg_seq = req->nlmsg_seq;
    resp->transport_type = req->transport_type;

    tpsa_nl_query_tp_resp_t *query_tp_resp = (tpsa_nl_query_tp_resp_t *)resp->payload;

    /* to delete later */
    if (req->transport_type == TPSA_TRANSPORT_IB) {
        tpsa_netaddr_entry_t *src = NULL, *dst = NULL;
        if (tpsa_get_underlay_info(&src_eid, &dst_eid, &src, &dst) != 0) {
            TPSA_LOG_WARN("Failed to look up underlay info.\n");
        } else {
            query_tp_resp->dst_eid =  dst->underlay.eid;
            query_tp_resp->src_addr = src->underlay.netaddr[0];
            query_tp_resp->dst_addr = dst->underlay.netaddr[0];
            query_tp_resp->cfg = dst->underlay.cfg;
        }
    }

    tpsa_query_tp(query_tp_resp, src_eid, dst_eid);

    return resp;
}

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_fast(tpsa_nl_msg_t *nlreq, tpsa_nl_resp_status_t status, uint32_t vtpn)
{
    urma_eid_t src_eid = nlreq->src_eid;
    urma_eid_t dst_eid = nlreq->dst_eid;

    tpsa_nl_msg_t *nlresp = NULL;
    tpsa_msg_t *reqmsg = (tpsa_msg_t *)nlreq->payload;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_create_vtp_resp_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = nlreq->nlmsg_seq;
    nlresp->transport_type = nlreq->transport_type;

    tpsa_msg_t *msg = (tpsa_msg_t *)nlresp->payload;
    msg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    msg->hdr.ep = reqmsg->hdr.ep;
    msg->hdr.len = (uint32_t)sizeof(tpsa_nl_create_vtp_resp_t);
    msg->hdr.msg_id = reqmsg->hdr.msg_id;
    msg->hdr.opcode = reqmsg->hdr.opcode;

    tpsa_nl_create_vtp_resp_t *create_vtp_resp = (tpsa_nl_create_vtp_resp_t *)msg->data;
    create_vtp_resp->ret = status;
    create_vtp_resp->vtpn = vtpn;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp(uint32_t vtpn, tpsa_sock_msg_t *msg)
{
    tpsa_nl_msg_t *nlresp = NULL;
    urma_eid_t local_eid = msg->local_eid;
    urma_eid_t peer_eid = msg->peer_eid;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_create_vtp_resp_t) + msg->content.finish.udrv_out_len,
        &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    /* nl msg */
    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = msg->content.finish.nlmsg_seq;
    nlresp->transport_type = TPSA_TRANSPORT_UB;

    /* tpsa msg */
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)nlresp->payload;
    tpsa_msg_ep_t ep = {
        .src_function_id = msg->content.finish.src_function_id,
    };
    nlmsg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    nlmsg->hdr.ep = ep;
    nlmsg->hdr.len = (uint32_t)(sizeof(tpsa_nl_create_vtp_resp_t) + msg->content.finish.udrv_out_len);
    nlmsg->hdr.msg_id = msg->content.finish.msg_id;
    nlmsg->hdr.opcode = TPSA_MSG_CREATE_VTP;

    /* resp msg */
    tpsa_nl_create_vtp_resp_t *create_vtp_resp = (tpsa_nl_create_vtp_resp_t *)nlmsg->data;
    create_vtp_resp->ret = TPSA_NL_RESP_SUCCESS;
    create_vtp_resp->vtpn = vtpn;
    /* for alpha */
    create_vtp_resp->udrv_out_len = msg->content.finish.udrv_out_len;
    (void)memcpy((char *)create_vtp_resp->udrv_out_data,
        (char *)msg->content.finish.udrv_data + msg->content.finish.udrv_in_len, msg->content.finish.udrv_out_len);

    create_vtp_resp->udrv_out_len = msg->content.finish.udrv_out_len;
    (void)memcpy((char *)create_vtp_resp->udrv_out_data,
        (char *)msg->content.finish.udrv_data + msg->content.finish.udrv_in_len, msg->content.finish.udrv_out_len);
    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_wait(uint32_t vtpn, tpsa_create_param_t *cparam)
{
    tpsa_nl_msg_t *nlresp = NULL;
    urma_eid_t local_eid = cparam->local_eid;
    urma_eid_t peer_eid = cparam->peer_eid;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_create_vtp_resp_t), &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = cparam->nlmsg_seq;
    nlresp->transport_type = TPSA_TRANSPORT_UB;

    tpsa_msg_t *nlmsg = (tpsa_msg_t *)nlresp->payload;
    tpsa_msg_ep_t ep = {
        .src_function_id = cparam->fe_idx,
    };

    nlmsg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    nlmsg->hdr.ep = ep;
    nlmsg->hdr.len = (uint32_t)sizeof(tpsa_nl_create_vtp_resp_t);
    nlmsg->hdr.msg_id = cparam->msg_id;
    nlmsg->hdr.opcode = TPSA_MSG_CREATE_VTP;

    tpsa_nl_create_vtp_resp_t *create_vtp_resp = (tpsa_nl_create_vtp_resp_t *)nlmsg->data;
    create_vtp_resp->ret = TPSA_NL_RESP_SUCCESS;
    create_vtp_resp->vtpn = vtpn;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_destroy_vtp_resp(tpsa_nl_msg_t *req, tpsa_nl_resp_status_t status)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)req->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->data;

    urma_eid_t local_eid = nlreq->local_eid;
    urma_eid_t peer_eid = nlreq->peer_eid;
    tpsa_nl_msg_t *nlresp = NULL;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_destroy_vtp_resp_t), &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_msg_t *nlresp_msg = (tpsa_msg_t *)nlresp->payload;

    nlresp_msg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    nlresp_msg->hdr.ep = nlmsg->hdr.ep;
    nlresp_msg->hdr.len = (uint32_t)sizeof(tpsa_nl_destroy_vtp_resp_t);
    nlresp_msg->hdr.msg_id = nlmsg->hdr.msg_id;
    nlresp_msg->hdr.opcode = nlmsg->hdr.opcode;

    tpsa_nl_destroy_vtp_resp_t *destroy_vtp_resp = (tpsa_nl_destroy_vtp_resp_t *)nlresp_msg->data;
    destroy_vtp_resp->ret = status;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_config_device_resp(tpsa_nl_msg_t *req, tpsa_nl_config_device_resp_t *resp)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *nlresp = NULL;
    tpsa_msg_t *reqmsg = (tpsa_msg_t *)req->payload;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_config_device_resp_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_msg_t *msg = (tpsa_msg_t *)nlresp->payload;
    msg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    msg->hdr.ep = reqmsg->hdr.ep;
    msg->hdr.len = (uint32_t)sizeof(tpsa_nl_config_device_resp_t);
    msg->hdr.msg_id = reqmsg->hdr.msg_id;
    msg->hdr.opcode = reqmsg->hdr.opcode;

    tpsa_nl_config_device_resp_t *config_vtp_resp = (tpsa_nl_config_device_resp_t *)msg->data;
    memcpy(config_vtp_resp, resp, sizeof(tpsa_nl_config_device_resp_t));

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_update_tpf_dev_info_resp(tpsa_nl_msg_t *req, tpsa_nl_update_tpf_dev_info_resp_t *resp)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;
    tpsa_nl_msg_t *nlresp = NULL;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_UPDATE_TPF_DEV_INFO_RESP;
    nlresp->msg_type = TPSA_NL_UPDATE_TPF_DEV_INFO_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_nl_update_tpf_dev_info_resp_t *update_tpf_dev_info_resp =
        (tpsa_nl_update_tpf_dev_info_resp_t *)(void *)nlresp->payload;

    update_tpf_dev_info_resp->ret = resp->ret;
    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_mig_msg_resp_fast(tpsa_nl_msg_t *req, tpsa_mig_resp_status_t status)
{
    tpsa_msg_t *nlmsg = (tpsa_msg_t *)req->payload;
    tpsa_nl_mig_req_t *nlreq = (tpsa_nl_mig_req_t *)nlmsg->data;

    urma_eid_t null_eid = {0};
    tpsa_nl_msg_t *nlresp = NULL;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_mig_resp_t), &null_eid, &null_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_msg_t *nlresp_msg = (tpsa_msg_t *)nlresp->payload;

    nlresp_msg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    nlresp_msg->hdr.ep = nlmsg->hdr.ep;
    nlresp_msg->hdr.len = (uint32_t)sizeof(tpsa_nl_mig_resp_t);
    nlresp_msg->hdr.msg_id = nlmsg->hdr.msg_id;
    nlresp_msg->hdr.opcode = nlmsg->hdr.opcode;

    tpsa_nl_mig_resp_t *msg_resp = (tpsa_nl_mig_resp_t *)nlresp_msg->data;
    msg_resp->mig_fe_idx = nlreq->mig_fe_idx;
    msg_resp->status = status;

    return nlresp;
}

tpsa_sock_msg_t *tpsa_handle_nl_create_tp_req(tpsa_nl_msg_t *req)
{
    tpsa_sock_msg_t *info = calloc(1, sizeof(tpsa_sock_msg_t));
    if (info == NULL) {
        TPSA_LOG_ERR("Fail to create tp request");
        return NULL;
    }

    info->content.nlmsg = *req;
    info->msg_type = TPSA_FORWARD;

    return info;
}

tpsa_nl_msg_t *tpsa_get_add_sip_resp(tpsa_nl_msg_t *req)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *resp = NULL;

    resp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t), &src_eid, &dst_eid);
    if (resp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    resp->hdr.nlmsg_type = TPSA_NL_ADD_SIP_RESP;
    resp->msg_type = TPSA_NL_ADD_SIP_RESP;
    resp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)resp);
    resp->nlmsg_seq = req->nlmsg_seq;
    resp->transport_type = req->transport_type;

    tpsa_nl_add_sip_resp_t *add_sip_resp = (tpsa_nl_add_sip_resp_t *)(void *)resp->payload;
    add_sip_resp->ret = TPSA_NL_RESP_SUCCESS;

    return resp;
}

tpsa_nl_msg_t *tpsa_get_del_sip_resp(tpsa_nl_msg_t *req)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *resp = NULL;

    resp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t), &src_eid, &dst_eid);
    if (resp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    resp->hdr.nlmsg_type = TPSA_NL_DEL_SIP_RESP;
    resp->msg_type = TPSA_NL_DEL_SIP_RESP;
    resp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)resp);
    resp->nlmsg_seq = req->nlmsg_seq;
    resp->transport_type = req->transport_type;

    tpsa_nl_del_sip_resp_t *del_sip_resp = (tpsa_nl_del_sip_resp_t *)(void *)resp->payload;
    del_sip_resp->ret = TPSA_NL_RESP_SUCCESS;

    return resp;
}

tpsa_nl_msg_t *tpsa_nl_create_dicover_eid_resp(tpsa_nl_msg_t *req, tpsa_ueid_t *ueid, uint32_t index)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *nlresp = NULL;
    tpsa_msg_t *reqmsg = (tpsa_msg_t *)req->payload;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_msg_t) + sizeof(tpsa_nl_alloc_eid_resp_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_msg_t *msg = (tpsa_msg_t *)nlresp->payload;
    msg->hdr.type = TPSA_MSG_TYPE_TPF2FE;
    msg->hdr.ep = reqmsg->hdr.ep;
    msg->hdr.len = (uint32_t)sizeof(tpsa_nl_alloc_eid_resp_t);
    msg->hdr.msg_id = reqmsg->hdr.msg_id;
    msg->hdr.opcode = reqmsg->hdr.opcode;

    tpsa_nl_alloc_eid_resp_t *create_eid_resp = (tpsa_nl_alloc_eid_resp_t *)msg->data;
    create_eid_resp->ret = TPSA_NL_RESP_SUCCESS;
    create_eid_resp->eid = ueid->eid;
    create_eid_resp->eid_index = index;
    create_eid_resp->upi = ueid->upi;
    return nlresp;
}