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
    tpsa_nl_msg_t *msg = (tpsa_nl_msg_t *)calloc(1, sizeof(tpsa_nl_msg_t) + payload_len);
    if (msg == NULL) {
        return NULL;
    }
    msg->src_eid = *src_eid;
    msg->dst_eid = *dst_eid;
    msg->payload_len = payload_len;
    return msg;
}

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_fast(tpsa_nl_msg_t *nlreq, tpsa_nl_resp_status_t status, uint32_t vtpn)
{
    urma_eid_t src_eid = nlreq->src_eid;
    urma_eid_t dst_eid = nlreq->dst_eid;

    tpsa_nl_msg_t *nlresp = NULL;
    tpsa_nl_req_host_t *reqmsg = (tpsa_nl_req_host_t *)nlreq->payload;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_create_vtp_resp_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = nlreq->nlmsg_seq;
    nlresp->transport_type = nlreq->transport_type;

    tpsa_nl_resp_host_t *resp_host = (tpsa_nl_resp_host_t *)nlresp->payload;
    resp_host->src_fe_idx = reqmsg->src_fe_idx;
    resp_host->resp.len = (uint32_t)sizeof(tpsa_nl_create_vtp_resp_t);
    resp_host->resp.msg_id = reqmsg->req.msg_id;
    resp_host->resp.opcode = reqmsg->req.opcode;

    tpsa_nl_create_vtp_resp_t *create_vtp_resp = (tpsa_nl_create_vtp_resp_t *)resp_host->resp.data;
    create_vtp_resp->ret = status;
    create_vtp_resp->vtpn = vtpn;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp(tpsa_resp_id_t *resp_id, uint32_t vtpn, tpsa_nl_resp_status_t resp_status)
{
    tpsa_nl_msg_t *nlresp = NULL;
    urma_eid_t local_eid; // to be deleted
    urma_eid_t peer_eid;  // to be deleted
    (void)memset(&local_eid, 0, sizeof(local_eid));
    (void)memset(&peer_eid, 0, sizeof(peer_eid));

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_create_vtp_resp_t),
        &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    /* nl msg */
    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = resp_id->nlmsg_seq;
    nlresp->transport_type = TPSA_TRANSPORT_UB;

    /* tpsa msg */
    tpsa_nl_resp_host_t *resp_host = (tpsa_nl_resp_host_t *)nlresp->payload;
    resp_host->src_fe_idx = resp_id->src_fe_idx;
    resp_host->resp.len = (uint32_t)(sizeof(tpsa_nl_create_vtp_resp_t));
    resp_host->resp.msg_id = resp_id->msg_id;
    resp_host->resp.opcode = TPSA_MSG_CREATE_VTP;

    /* resp msg */
    tpsa_nl_create_vtp_resp_t *create_vtp_resp = (tpsa_nl_create_vtp_resp_t *)resp_host->resp.data;
    create_vtp_resp->ret = resp_status;
    create_vtp_resp->vtpn = vtpn;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_wait(uint32_t vtpn, tpsa_create_param_t *cparam)
{
    tpsa_nl_msg_t *nlresp = NULL;
    urma_eid_t local_eid = cparam->local_eid;
    urma_eid_t peer_eid = cparam->peer_eid;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_create_vtp_resp_t), &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = cparam->nlmsg_seq;
    nlresp->transport_type = TPSA_TRANSPORT_UB;

    tpsa_nl_resp_host_t *nlmsg = (tpsa_nl_resp_host_t *)nlresp->payload;
    nlmsg->src_fe_idx = cparam->fe_idx;
    nlmsg->resp.len = (uint32_t)sizeof(tpsa_nl_create_vtp_resp_t);
    nlmsg->resp.msg_id = cparam->msg_id;
    nlmsg->resp.opcode = TPSA_MSG_CREATE_VTP;

    tpsa_nl_create_vtp_resp_t *create_vtp_resp = (tpsa_nl_create_vtp_resp_t *)nlmsg->resp.data;
    create_vtp_resp->ret = TPSA_NL_RESP_SUCCESS;
    create_vtp_resp->vtpn = vtpn;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_destroy_vtp_resp(tpsa_nl_msg_t *req, tpsa_nl_resp_status_t status)
{
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)req->payload;
    tpsa_nl_destroy_vtp_req_t *nlreq = (tpsa_nl_destroy_vtp_req_t *)nlmsg->req.data;

    urma_eid_t local_eid = nlreq->local_eid;
    urma_eid_t peer_eid = nlreq->peer_eid;
    tpsa_nl_msg_t *nlresp = NULL;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_destroy_vtp_resp_t), &local_eid, &peer_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_nl_resp_host_t *nlresp_msg = (tpsa_nl_resp_host_t *)nlresp->payload;

    nlresp_msg->src_fe_idx = nlmsg->src_fe_idx;
    nlresp_msg->resp.len = (uint32_t)sizeof(tpsa_nl_destroy_vtp_resp_t);
    nlresp_msg->resp.msg_id = nlmsg->req.msg_id;
    nlresp_msg->resp.opcode = nlmsg->req.opcode;

    tpsa_nl_destroy_vtp_resp_t *destroy_vtp_resp = (tpsa_nl_destroy_vtp_resp_t *)nlresp_msg->resp.data;
    destroy_vtp_resp->ret = status;

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_config_device_resp(tpsa_nl_msg_t *req, tpsa_nl_config_device_resp_t *resp)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *nlresp = NULL;
    tpsa_nl_req_host_t *reqmsg = (tpsa_nl_req_host_t *)req->payload;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_config_device_resp_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_nl_resp_host_t *msg = (tpsa_nl_resp_host_t *)nlresp->payload;
    msg->src_fe_idx = reqmsg->src_fe_idx;
    msg->resp.len = (uint32_t)sizeof(tpsa_nl_config_device_resp_t);
    msg->resp.msg_id = reqmsg->req.msg_id;
    msg->resp.opcode = reqmsg->req.opcode;

    tpsa_nl_config_device_resp_t *config_vtp_resp = (tpsa_nl_config_device_resp_t *)msg->resp.data;
    memcpy(config_vtp_resp, resp, sizeof(tpsa_nl_config_device_resp_t));

    return nlresp;
}

tpsa_nl_msg_t *tpsa_nl_update_tpf_dev_info_resp(tpsa_nl_msg_t *req, tpsa_nl_update_tpf_dev_info_resp_t *resp)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;
    tpsa_nl_msg_t *nlresp = NULL;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t), &src_eid, &dst_eid);
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
    tpsa_nl_req_host_t *nlmsg = (tpsa_nl_req_host_t *)req->payload;
    tpsa_nl_function_mig_req_t *nlreq = (tpsa_nl_function_mig_req_t *)nlmsg->req.data;

    urma_eid_t null_eid = {0};
    tpsa_nl_msg_t *nlresp = NULL;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_mig_resp_t), &null_eid, &null_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_nl_resp_host_t *nlresp_msg = (tpsa_nl_resp_host_t *)nlresp->payload;

    nlresp_msg->src_fe_idx = nlmsg->src_fe_idx;
    nlresp_msg->resp.len = (uint32_t)sizeof(tpsa_nl_mig_resp_t);
    nlresp_msg->resp.msg_id = nlmsg->req.msg_id;
    nlresp_msg->resp.opcode = nlmsg->req.opcode;

    tpsa_nl_mig_resp_t *msg_resp = (tpsa_nl_mig_resp_t *)nlresp_msg->resp.data;
    msg_resp->mig_fe_idx = nlreq->mig_fe_idx;
    msg_resp->status = status;

    return nlresp;
}

tpsa_sock_msg_t *tpsa_handle_nl_create_tp_req(tpsa_nl_msg_t *req)
{
    tpsa_sock_msg_t *info = (tpsa_sock_msg_t *)calloc(1, sizeof(tpsa_sock_msg_t));
    if (info == NULL) {
        return NULL;
    }

    info->content.nlmsg = *req;
    info->msg_type = TPSA_FORWARD;

    return info;
}

tpsa_nl_msg_t *tpsa_get_add_sip_resp(tpsa_nl_msg_t *req, tpsa_nl_resp_status_t status)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *resp = NULL;

    resp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_add_sip_resp_t), &src_eid, &dst_eid);
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
    add_sip_resp->ret = status;

    return resp;
}

tpsa_nl_msg_t *tpsa_get_del_sip_resp(tpsa_nl_msg_t *req, tpsa_nl_resp_status_t status)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *resp = NULL;

    resp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_del_sip_resp_t), &src_eid, &dst_eid);
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
    del_sip_resp->ret = status;

    return resp;
}

tpsa_nl_msg_t *tpsa_nl_create_dicover_eid_resp(tpsa_nl_msg_t *req, tpsa_ueid_t *ueid, uint32_t index,
    bool virtualization)
{
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;

    tpsa_nl_msg_t *nlresp = NULL;
    tpsa_nl_req_host_t *reqmsg = (tpsa_nl_req_host_t *)req->payload;

    nlresp = tpsa_alloc_nlmsg(sizeof(tpsa_nl_resp_host_t) + sizeof(tpsa_nl_alloc_eid_resp_t), &src_eid, &dst_eid);
    if (nlresp == NULL) {
        TPSA_LOG_ERR("Fail to alloc nl msg");
        return NULL;
    }

    nlresp->hdr.nlmsg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->msg_type = TPSA_NL_TPF2FE_RESP;
    nlresp->hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)nlresp);
    nlresp->nlmsg_seq = req->nlmsg_seq;
    nlresp->transport_type = req->transport_type;

    tpsa_nl_resp_host_t *msg = (tpsa_nl_resp_host_t *)nlresp->payload;
    msg->src_fe_idx = reqmsg->src_fe_idx;
    msg->resp.len = (uint32_t)sizeof(tpsa_nl_alloc_eid_resp_t);
    msg->resp.msg_id = reqmsg->req.msg_id;
    msg->resp.opcode = reqmsg->req.opcode;

    tpsa_nl_alloc_eid_resp_t *create_eid_resp = (tpsa_nl_alloc_eid_resp_t *)msg->resp.data;
    create_eid_resp->ret = TPSA_NL_RESP_SUCCESS;
    create_eid_resp->eid = ueid->eid;
    create_eid_resp->eid_index = index;
    create_eid_resp->upi = ueid->upi;
    create_eid_resp->fe_idx = reqmsg->src_fe_idx;

    return nlresp;
}