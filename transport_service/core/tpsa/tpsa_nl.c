/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa netlink implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port netlink functions from tpsa_connect and daemon here
 */
#include <errno.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "tpsa_log.h"
#include "tpsa_net.h"
#include "tpsa_worker.h"
#include "tpsa_nl.h"

#define UBCORE_GENL_FAMILY_NAME		"UBCORE_GENL"
#define UBCORE_GENL_FAMILY_VERSION	1
#define TPSA_MAX_NL_BUFFER_SIZE (208 * 1024)
enum {
    UBCORE_ATTR_UNSPEC,
	UBCORE_HDR_COMMAND,
	UBCORE_HDR_ARGS_LEN,
	UBCORE_HDR_ARGS_ADDR,
	UBCORE_ATTR_NS_MODE,
	UBCORE_ATTR_DEV_NAME,
	UBCORE_ATTR_NS_FD,
	UBCORE_MSG_SEQ,
	UBCORE_MSG_TYPE,
	UBCORE_TRANSPORT_TYPE,
	UBORE_SRC_ID,
	UBORE_DST_ID,
	UBCORE_PAYLOAD_LEN,
	UBCORE_PAYLOAD_DATA,
	UBCORE_ATTR_AFTER_LAST,
	NUM_UBCORE_ATTR = UBCORE_ATTR_AFTER_LAST,
    UBCORE_ATTR_MAX = UBCORE_ATTR_AFTER_LAST - 1
};

static struct nla_policy g_uvs_policy[NUM_UBCORE_ATTR] = {
    [UBCORE_ATTR_UNSPEC] = { 0 },
    [UBCORE_HDR_COMMAND] = { .type = NLA_U32 },
    [UBCORE_HDR_ARGS_LEN] = { .type = NLA_U32 },
    [UBCORE_HDR_ARGS_ADDR] = { .type = NLA_U64 },
    [UBCORE_ATTR_NS_MODE] = { .type = NLA_U8 },
    [UBCORE_ATTR_DEV_NAME] = { .type = NLA_STRING },
    [UBCORE_ATTR_NS_FD] = { .type = NLA_U32 },
    [UBCORE_MSG_SEQ] = { .type = NLA_U32 },
    [UBCORE_MSG_TYPE] = { .type = NLA_U32 },
    [UBCORE_TRANSPORT_TYPE] = { .type = NLA_U32 },
    [UBORE_SRC_ID] = { .type = NLA_UNSPEC },
    [UBORE_DST_ID] = { .type = NLA_UNSPEC },
    [UBCORE_PAYLOAD_LEN] = { .type = NLA_U32 },
    [UBCORE_PAYLOAD_DATA] = { .type = NLA_UNSPEC }
};

/* Set fd to be nonblocking */
int tpsa_nl_set_nonblock_opt(int fd)
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

int tpsa_genl_send_msg(tpsa_genl_ctx_t *genl, tpsa_nl_msg_t *tpsa_msg)
{
    int ret = 0;
    void *msg_hdr;
    struct nl_msg *msg;
    int nlmsg_flags = 0;
    if (genl == NULL || genl->sock == NULL || tpsa_msg == NULL) {
        TPSA_LOG_WARN("no netlink to send message\n");
        return -1;
    }
    msg = nlmsg_alloc();
    if (msg == NULL) {
        TPSA_LOG_ERR("Unable to allocate netlink message\n");
        return -1;
    }
    if (tpsa_msg->msg_type == TPSA_NL_UVS_INIT_RES) {
        nlmsg_flags = NLM_F_DUMP;
    }

    msg_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, genl->genl_id, 0, nlmsg_flags,
                          (uint8_t)tpsa_msg->msg_type, UBCORE_GENL_FAMILY_VERSION);
    if (msg_hdr == NULL) {
        TPSA_LOG_ERR("Unable to write genl header\n");
        nlmsg_free(msg);
        return -1;
    }
    if (nla_put_u32(msg, UBCORE_MSG_SEQ, tpsa_msg->nlmsg_seq) ||
        nla_put_u32(msg, UBCORE_MSG_TYPE, (uint32_t)tpsa_msg->msg_type) ||
        nla_put_u32(msg, UBCORE_TRANSPORT_TYPE, (uint32_t)tpsa_msg->transport_type) ||
        nla_put(msg, UBORE_SRC_ID, sizeof(urma_eid_t), &tpsa_msg->src_eid) ||
        nla_put(msg, UBORE_DST_ID, sizeof(urma_eid_t), &tpsa_msg->dst_eid) ||
        nla_put_u32(msg, UBCORE_PAYLOAD_LEN, tpsa_msg->payload_len)) {
        TPSA_LOG_ERR("genl put nla err\n");
        nlmsg_free(msg);
        return -1;
    }
    if (tpsa_msg->payload_len > 0) {
        ret = nla_put(msg, UBCORE_PAYLOAD_DATA, (int32_t)tpsa_msg->payload_len, tpsa_msg->payload);
        if (ret != 0) {
            TPSA_LOG_ERR("genl put payload err %d\n", ret);
            nlmsg_free(msg);
            return -1;
        }
    }
    ret = nl_send_auto(genl->sock, msg);
    if (ret < 0) {
        TPSA_LOG_ERR("genl send failed, ret:%d, cmd:%u.\n", ret, (uint32_t)tpsa_msg->msg_type);
        nlmsg_free(msg);
        return ret;
    }
    TPSA_LOG_INFO("genl send success, cmd:%u.\n", (uint32_t)tpsa_msg->msg_type);
    nlmsg_free(msg);
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

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp_fast(tpsa_nl_msg_t *nlreq, int status, uint32_t vtpn)
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

tpsa_nl_msg_t *tpsa_nl_create_vtp_resp(tpsa_resp_id_t *resp_id, uint32_t vtpn, int resp_status)
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

tpsa_nl_msg_t *tpsa_nl_destroy_vtp_resp(tpsa_nl_msg_t *req, int status)
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

tpsa_nl_msg_t *tpsa_get_add_sip_resp(tpsa_nl_msg_t *req, int status)
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

tpsa_nl_msg_t *tpsa_get_del_sip_resp(tpsa_nl_msg_t *req, int status)
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

static int tpsa_genl_cb_handler(struct nl_msg *msg, void *arg)
{
    tpsa_worker_t *worker = (tpsa_worker_t *)arg;
    struct nlattr *attrs[NUM_UBCORE_ATTR];
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    tpsa_nl_msg_t tpsa_msg = {0};

    if (genlmsg_validate(hdr, 0, UBCORE_ATTR_MAX, g_uvs_policy) ||
        genlmsg_parse(hdr, 0, attrs, UBCORE_ATTR_MAX, g_uvs_policy) < 0) {
        TPSA_LOG_ERR("genl invalid data returned\n");
        nl_msg_dump(msg, stderr);
        return -1;
    }
    if (attrs[UBCORE_MSG_SEQ]) {
        tpsa_msg.nlmsg_seq = nla_get_u32(attrs[UBCORE_MSG_SEQ]);
    }

    if (attrs[UBCORE_MSG_TYPE]) {
        tpsa_msg.msg_type = (tpsa_nlmsg_type_t)nla_get_u32(attrs[UBCORE_MSG_TYPE]);
    }

    if (attrs[UBCORE_TRANSPORT_TYPE]) {
        tpsa_msg.transport_type = (tpsa_transport_type_t)nla_get_u32(attrs[UBCORE_TRANSPORT_TYPE]);
    }

    if (attrs[UBORE_SRC_ID]) {
        (void)memcpy(&tpsa_msg.src_eid, nla_data(attrs[UBORE_SRC_ID]), URMA_EID_SIZE);
    }

    if (attrs[UBORE_DST_ID]) {
        (void)memcpy(&tpsa_msg.dst_eid, nla_data(attrs[UBORE_DST_ID]), URMA_EID_SIZE);
    }

    if (attrs[UBCORE_PAYLOAD_LEN] && attrs[UBCORE_PAYLOAD_DATA]) {
        tpsa_msg.payload_len = nla_get_u32(attrs[UBCORE_PAYLOAD_LEN]);
        (void)memcpy(tpsa_msg.payload, nla_data(attrs[UBCORE_PAYLOAD_DATA]),
                       tpsa_msg.payload_len);
    }
    TPSA_LOG_INFO("genl recv msg: %u seq %d\n", (uint32_t)tpsa_msg.msg_type, tpsa_msg.nlmsg_seq);
    if (tpsa_handle_nl_msg(worker, &tpsa_msg) != 0) {
        return -1;
    }

    return 0;
}

static void tpsa_genl_set_cb(struct nl_sock *sock, nl_recvmsg_msg_cb_t func, void *arg)
{
    int ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, func, arg);
    if (ret) {
        TPSA_LOG_ERR("set genl cb fail, ret:%d\n", ret);
    }
}

int tpsa_genl_init(tpsa_genl_ctx_t *genl_ctx)
{
    int genl_id;
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) {
        TPSA_LOG_ERR("Failed to nl_socket_alloc\n");
        return -1;
    }

    if (genl_connect(sock)) {
        TPSA_LOG_ERR("Failed to nl_connect, errno:%d\n", errno);
        nl_socket_free(sock);
        return -1;
    }

    genl_id = genl_ctrl_resolve(sock, UBCORE_GENL_FAMILY_NAME);
    if (genl_id < 0) {
        TPSA_LOG_ERR("Resolving of \"%s\" failed, ret:%d\n", UBCORE_GENL_FAMILY_NAME, genl_id);
        nl_close(sock);
        nl_socket_free(sock);
        return -1;
    }

    int ret = nl_socket_set_buffer_size(sock, TPSA_MAX_NL_BUFFER_SIZE, TPSA_MAX_NL_BUFFER_SIZE);
    if (ret < 0) {
       TPSA_LOG_ERR("set netlink buffer failed, ret: %u", ret);
    }

    nl_socket_disable_auto_ack(sock);
    tpsa_genl_set_cb(sock, tpsa_genl_cb_handler, genl_ctx->args);
    genl_ctx->sock = sock;
    genl_ctx->genl_id = genl_id;
    genl_ctx->fd = nl_socket_get_fd(sock);
    return 0;
}

void tpsa_genl_uninit(struct nl_sock *sock)
{
    nl_close(sock);
    nl_socket_free(sock);
}

int tpsa_get_init_res(tpsa_genl_ctx_t *genl)
{
    int ret;
    tpsa_nl_msg_t msg = {0};
    msg.hdr.nlmsg_type = TPSA_NL_UVS_INIT_RES;
    msg.hdr.nlmsg_pid = (uint32_t)getpid();
    msg.hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)&msg);
    msg.msg_type = TPSA_NL_UVS_INIT_RES;
    if (tpsa_genl_send_msg(genl, &msg)) {
        TPSA_LOG_ERR("Failed to send get_dev err: %s.\n", ub_strerror(errno));
        return -1;
    }
    ret = tpsa_genl_handle_event(genl);
    TPSA_LOG_INFO("process init res:%d\n", ret);
    return 0;
}

int tpsa_genl_handle_event(tpsa_genl_ctx_t *genl_ctx)
{
    int ret = nl_recvmsgs_default(genl_ctx->sock);
    if (ret < 0) {
        TPSA_LOG_ERR("nl_recvmsgs_default failed, ret = %d.\n", ret);
        return -1;
    }
    return 0;
}
