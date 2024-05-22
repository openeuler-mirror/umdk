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

static void sip_init_show_rsp(tpsa_sip_table_show_rsp_t *show_rsp, sip_table_entry_t *entry)
{
    show_rsp->res = 0;
    show_rsp->vlan = (uint16_t)entry->addr.vlan;
    show_rsp->port_cnt = entry->port_cnt;
    (void)memcpy(show_rsp->port_id, entry->port_id, TPSA_PORT_CNT_MAX);
    show_rsp->net_addr_type = (bool)entry->addr.type;
    (void)memcpy(&show_rsp->net_addr, &entry->addr.net_addr, TPSA_EID_SIZE);
    (void)memcpy(show_rsp->mac, entry->addr.mac, ETH_ADDR_LEN);
    (void)memcpy(show_rsp->dev_name, entry->dev_name, UVS_MAX_DEV_NAME);
    show_rsp->mtu = entry->mtu;
}

tpsa_response_t *process_sip_table_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_sip_table_show_req_t *show_req = NULL;
    sip_table_entry_t entry;
    tpf_dev_table_entry_t tpf_dev_table_entry;
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

    show_req = (tpsa_sip_table_show_req_t *)req->req;
    if (show_req->sip_idx >= TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid parameter\n");
        return NULL;
    }
    if (strnlen(show_req->tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }
    (void)pthread_rwlock_wrlock(&ctx->worker->table_ctx.tpf_dev_table.rwlock);
    ret = tpsa_lookup_tpf_dev_table(show_req->tpf_name, &ctx->worker->table_ctx.tpf_dev_table, &tpf_dev_table_entry);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&ctx->worker->table_ctx.tpf_dev_table.rwlock);
        TPSA_LOG_ERR("tpf table not found");
        return NULL;
    }
    entry = tpf_dev_table_entry.sip_table->entries[show_req->sip_idx];
    (void)pthread_rwlock_unlock(&ctx->worker->table_ctx.tpf_dev_table.rwlock);
    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_sip_table_show_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }
    tpsa_sip_table_show_rsp_t *show_rsp = (tpsa_sip_table_show_rsp_t *)rsp->rsp;
    if (entry.used == false) {
        TPSA_LOG_ERR("can not find sip_idx by key sip_idx %d\n", show_req->sip_idx);
        show_rsp->res = -ENXIO;
    } else {
        sip_init_show_rsp(show_rsp, &entry);
    }

    rsp->cmd_type = SIP_TABLE_SHOW;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_sip_table_show_rsp_t);

    return rsp;
}

tpsa_response_t *process_sip_table_add(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_sip_table_add_req_t *add_req = NULL;
    sip_table_entry_t entry = {0};
    uint32_t index = 0;
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
    if (strnlen(add_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }

    entry.addr.vlan = add_req->vlan;
    entry.port_cnt = 1;
    entry.port_id[0] = add_req->port_id; // TODO Support multiple ports
    entry.addr.type = add_req->net_addr_type;
    (void)memcpy(&entry.addr.net_addr, &add_req->net_addr, TPSA_EID_SIZE);
    (void)memcpy(entry.addr.mac, add_req->mac, ETH_ADDR_LEN);
    (void)memcpy(entry.dev_name, add_req->dev_name, UVS_MAX_DEV_NAME);
    entry.mtu = add_req->mtu;
    entry.used = true;

    ret = tpsa_sip_lookup_by_entry(&ctx->worker->table_ctx, entry.dev_name, &entry, &index);
    if (ret != 0) {
        if (ret == EEXIST) {
            TPSA_LOG_INFO("sip already exist, sip_index is %d\n", index);
        } else {
            TPSA_LOG_WARN("failed to lookup sip by entry, tpf table not ready\n");
        }
        goto send_rsp;
    }

    ret = sip_table_add_ioctl(&ctx->worker->ioctl_ctx, &entry, &index);
    if (ret != 0) {
        if (ret == EEXIST) {
            TPSA_LOG_INFO("sip in ubcore already exist, sip_idx %u.\n", index);
        } else {
            TPSA_LOG_ERR("can not add sip to ubcore.\n");
        }
    }

send_rsp:
    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_sip_table_add_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_sip_table_add_rsp_t *add_rsp = (tpsa_sip_table_add_rsp_t *)(rsp->rsp);
    add_rsp->res = ret;
    add_rsp->index = index;

    rsp->cmd_type = SIP_TABLE_ADD;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_sip_table_add_rsp_t);

    return rsp;
}

tpsa_response_t *process_sip_table_del(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_sip_table_del_req_t *del_req = NULL;
    sip_table_entry_t entry;
    tpf_dev_table_entry_t tpf_dev_table_entry;
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
    if (del_req->sip_idx >= TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("Invalid parameter\n");
        return NULL;
    }
    if (strnlen(del_req->tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }
    (void)pthread_rwlock_wrlock(&ctx->worker->table_ctx.tpf_dev_table.rwlock);
    ret = tpsa_lookup_tpf_dev_table(del_req->tpf_name, &ctx->worker->table_ctx.tpf_dev_table, &tpf_dev_table_entry);
    if (ret != 0) {
        (void)pthread_rwlock_unlock(&ctx->worker->table_ctx.tpf_dev_table.rwlock);
        TPSA_LOG_ERR("tpf table not found");
        return NULL;
    }
    entry = tpf_dev_table_entry.sip_table->entries[del_req->sip_idx];
    (void)pthread_rwlock_unlock(&ctx->worker->table_ctx.tpf_dev_table.rwlock);

    if (entry.used == false) {
        TPSA_LOG_ERR("sip_idx: %u has been deleted\n", del_req->sip_idx);
        ret = -ENXIO;
    } else {
        ret = sip_table_del_ioctl(&ctx->worker->ioctl_ctx, &entry);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_sip_table_del_rsp_t));
    if (rsp == NULL) {
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

