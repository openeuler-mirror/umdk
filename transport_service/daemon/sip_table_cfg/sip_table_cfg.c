/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa service process sip table ops file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#include <errno.h>
#include <stdlib.h>

#include "tpsa_daemon.h"
#include "tpsa_table.h"
#include "tpsa_log.h"
#include "sip_table_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SIP_MTU_BITS_BASE_SHIFT (7)
#define SIP_MTU_ENUME_TO_UIN32(value) (1 << (value + SIP_MTU_BITS_BASE_SHIFT))

tpsa_response_t *process_sip_table_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_sip_table_show_req_t *show_req = NULL;
    sip_table_t *sip_table = NULL;
    sip_table_entry_t *entry = NULL;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    ctx = get_tpsa_daemon_ctx();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return NULL;
    }

    show_req = (tpsa_sip_table_show_req_t *)req->req;
    sip_table = &ctx->worker->table_ctx.sip_table;

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_sip_table_show_rsp_t));
    if (rsp == NULL) {
        TPSA_LOG_ERR("can not alloc rsp mem\n");
        return NULL;
    }

    tpsa_sip_table_show_rsp_t *show_rsp = (tpsa_sip_table_show_rsp_t *)rsp->rsp;

    (void)pthread_rwlock_rdlock(&sip_table->rwlock);
    entry = sip_table_lookup(sip_table, show_req->sip_idx);
    if (entry == NULL) {
        TPSA_LOG_ERR("can not find sip_idx by key sip_idx %d\n", show_req->sip_idx);
        show_rsp->res = -ENXIO;
    } else {
        show_rsp->res = 0;
        show_rsp->vlan = (uint16_t)entry->addr.vlan;
        show_rsp->port_cnt = entry->port_cnt;
        (void)memcpy(show_rsp->port_id, entry->port_id, TPSA_PORT_CNT_MAX);
        show_rsp->is_ipv6 = (bool)entry->addr.type;
        (void)memcpy(&show_rsp->sip, &entry->addr.eid, TPSA_EID_SIZE);
        (void)memcpy(show_rsp->mac, entry->addr.mac, TPSA_MAC_BYTES);
        (void)memcpy(show_rsp->dev_name, entry->dev_name, TPSA_MAX_DEV_NAME);
        show_rsp->prefix_len = entry->prefix_len;
        show_rsp->mtu = entry->mtu;
    }
    (void)pthread_rwlock_unlock(&sip_table->rwlock);

    rsp->cmd_type = SIP_TABLE_SHOW;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_sip_table_show_rsp_t);

    return rsp;
}

static int sip_table_ioctl(tpsa_daemon_ctx_t *ctx, sip_table_entry_t *entry, uint32_t cmd_type)
{
    tpsa_ioctl_cfg_t cfg = {0};
    tpsa_op_sip_parm_t parm = {0};

    (void)memcpy(&parm.netaddr, &entry->addr, sizeof(tpsa_net_addr_t));
    (void)memcpy(parm.dev_name, entry->dev_name, TPSA_MAX_DEV_NAME);
    parm.port_cnt = entry->port_cnt;
    (void)memcpy(parm.port_id, entry->port_id, TPSA_PORT_CNT_MAX);
    parm.prefix_len = entry->prefix_len;
    parm.mtu = SIP_MTU_ENUME_TO_UIN32(entry->mtu);

    cfg.cmd_type = cmd_type;
    cfg.cmd.op_sip.in.parm = parm;

    return tpsa_ioctl(ctx->worker->ioctl_ctx.ubcore_fd, &cfg);
}

tpsa_response_t *process_sip_table_add(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_sip_table_add_req_t *add_req = NULL;
    sip_table_entry_t entry = {0};
    int ret;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    ctx = get_tpsa_daemon_ctx();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return NULL;
    }

    add_req = (tpsa_sip_table_add_req_t *)req->req;
    entry.addr.vlan = add_req->vlan;
    entry.port_cnt = 1;
    entry.port_id[0] = add_req->port_id; // TODO Support multiple ports
    entry.addr.type = (tpsa_net_addr_type_t)add_req->is_ipv6;
    (void)memcpy(&entry.addr.eid, &add_req->sip, TPSA_EID_SIZE);
    (void)memcpy(entry.addr.mac, add_req->mac, TPSA_MAC_BYTES);
    (void)memcpy(entry.dev_name, add_req->dev_name, TPSA_MAX_DEV_NAME);
    entry.prefix_len = add_req->prefix_len;
    entry.mtu = add_req->mtu;

    ret = sip_table_ioctl(ctx, &entry, TPSA_CMD_ADD_SIP);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add sip to ubcore.\n");
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_sip_table_add_rsp_t));
    if (rsp == NULL) {
        TPSA_LOG_ERR("can not alloc rsp mem\n");
        return NULL;
    }

    tpsa_sip_table_add_rsp_t *add_rsp = (tpsa_sip_table_add_rsp_t *)(rsp->rsp);
    add_rsp->res = ret;

    rsp->cmd_type = SIP_TABLE_ADD;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_sip_table_add_rsp_t);

    return rsp;
}

tpsa_response_t *process_sip_table_del(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_sip_table_del_req_t *del_req = NULL;
    sip_table_t *sip_table = NULL;
    sip_table_entry_t *entry = NULL;
    int ret;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    ctx = get_tpsa_daemon_ctx();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return NULL;
    }

    del_req = (tpsa_sip_table_del_req_t *)req->req;
    sip_table = &ctx->worker->table_ctx.sip_table;

    (void)pthread_rwlock_rdlock(&sip_table->rwlock);
    entry = sip_table_lookup(sip_table, del_req->sip_idx);
    (void)pthread_rwlock_unlock(&sip_table->rwlock);
    if (entry == NULL) {
        TPSA_LOG_ERR("can not find sip_idx by key sip_idx %d\n", del_req->sip_idx);
        ret = -ENXIO;
    } else {
        ret = sip_table_ioctl(ctx, entry, TPSA_CMD_DEL_SIP);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_sip_table_del_rsp_t));
    if (rsp == NULL) {
        TPSA_LOG_ERR("can not alloc rsp mem\n");
        return NULL;
    }

    tpsa_sip_table_del_rsp_t *del_rsp = (tpsa_sip_table_del_rsp_t *)(rsp->rsp);
    del_rsp->res = ret;

    rsp->cmd_type = SIP_TABLE_DEL;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_sip_table_del_rsp_t);

    return rsp;
}

#ifdef __cplusplus
}
#endif

