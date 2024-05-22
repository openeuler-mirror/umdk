/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa service process dip table ops file
 * Author: Chen Wen
 * Create: 2023-08-23
 * Note:
 * History: 2023-08-23 Chen Wen Initial version
 */
#include <stdlib.h>
#include <errno.h>

#include "tpsa_daemon.h"
#include "tpsa_table.h"
#include "tpsa_log.h"
#include "dip_table_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

tpsa_response_t *process_dip_table_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_dip_table_show_req_t *show_req = NULL;
    dip_table_t *dip_table = NULL;
    dip_table_entry_t *entry = NULL;
    dip_table_key_t key = {0};

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    ctx = get_tpsa_daemon_ctx();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return NULL;
    }

    show_req = (tpsa_dip_table_show_req_t *)req->req;
    dip_table = &ctx->worker->table_ctx.dip_table;
    key.deid = show_req->eid;
    key.upi = show_req->upi;

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_dip_table_show_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }
    tpsa_dip_table_show_rsp_t *show_rsp = (tpsa_dip_table_show_rsp_t *)rsp->rsp;

    (void)pthread_rwlock_rdlock(&dip_table->rwlock);
    entry = dip_table_lookup(dip_table, &key);
    if (entry == NULL) {
        TPSA_LOG_ERR("can not find dip by key: " EID_FMT " and upi: %u\n",
            EID_ARGS(show_req->eid), show_req->upi);
        show_rsp->res = -ENXIO;
    } else {
        show_rsp->res = 0;
        show_rsp->eid = entry->key.deid;
        show_rsp->upi = entry->key.upi;
        show_rsp->uvs_ip = entry->peer_uvs_ip;
        show_rsp->net_addr = entry->netaddr;
    }
    (void)pthread_rwlock_unlock(&dip_table->rwlock);

    rsp->cmd_type = DIP_TABLE_SHOW;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_dip_table_show_rsp_t);

    return rsp;
}

tpsa_response_t *process_dip_table_add(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_dip_table_add_req_t *add_req = NULL;
    dip_table_entry_t add_entry = {0};
    dip_table_t *dip_table = NULL;
    int ret;
    dip_table_key_t key = {0};

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    ctx = get_tpsa_daemon_ctx();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return NULL;
    }

    add_req = (tpsa_dip_table_add_req_t *)req->req;
    dip_table = &ctx->worker->table_ctx.dip_table;
    key.deid = add_req->eid;
    key.upi = add_req->upi;

    if (dip_table_lookup(dip_table, &key) != NULL) {
        TPSA_LOG_ERR("Try to add dip entry while entry already exists.");
        TPSA_LOG_ERR("Use modify command instead. key: "EID_FMT" and upi: %u\n",
            EID_ARGS(add_req->eid), add_req->upi);
        ret = -ENXIO;
    } else {
        add_entry.key.deid = add_req->eid;
        add_entry.key.upi = add_req->upi;
        add_entry.peer_uvs_ip = add_req->uvs_ip;
        add_entry.netaddr = add_req->net_addr;

        ret = dip_table_add(dip_table, &key, &add_entry);
        if (ret != 0) {
            TPSA_LOG_ERR("can not add dip_table by key: "EID_FMT" and upi %u\n",
                EID_ARGS(add_req->eid), add_req->upi);
        }
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_dip_table_add_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_dip_table_add_rsp_t *add_rsp = (tpsa_dip_table_add_rsp_t *)(rsp->rsp);
    add_rsp->res = ret;

    rsp->cmd_type = DIP_TABLE_ADD;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_dip_table_add_rsp_t);

    return rsp;
}

tpsa_response_t *process_dip_table_del(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_dip_table_del_req_t *del_req = NULL;
    dip_table_t *dip_table = NULL;
    dip_table_entry_t *entry = NULL;
    dip_table_key_t key = {0};
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

    del_req = (tpsa_dip_table_del_req_t *)req->req;
    dip_table = &ctx->worker->table_ctx.dip_table;
    key.deid = del_req->eid;
    key.upi = del_req->upi;

    (void)pthread_rwlock_rdlock(&dip_table->rwlock);
    entry = dip_table_lookup(dip_table, &key);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        TPSA_LOG_ERR("can not find dip by key: "EID_FMT" and upi %u\n",
            EID_ARGS(del_req->eid), del_req->upi);
        ret = -ENXIO;
    } else {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        ret = dip_table_remove(dip_table, &key);
        if (ret != 0) {
            TPSA_LOG_ERR("can not del dip_table by key: "EID_FMT" and upi %u\n",
                EID_ARGS(del_req->eid), del_req->upi);
        }
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_dip_table_del_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_dip_table_del_rsp_t *del_rsp = (tpsa_dip_table_del_rsp_t *)(rsp->rsp);
    del_rsp->res = ret;

    rsp->cmd_type = DIP_TABLE_DEL;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_dip_table_del_rsp_t);

    return rsp;
}

tpsa_response_t *process_dip_table_modify(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_dip_table_modify_req_t *modify_req = NULL;
    dip_table_t *dip_table = NULL;
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

    modify_req = (tpsa_dip_table_modify_req_t *)req->req;
    dip_table = &ctx->worker->table_ctx.dip_table;

    dip_table_key_t old_key;
    dip_table_entry_t new_entry;
    old_key.deid = modify_req->old_eid;
    old_key.upi = modify_req->old_upi;
    new_entry.key.deid = modify_req->new_eid;
    new_entry.key.upi = modify_req->new_upi;
    new_entry.peer_uvs_ip = modify_req->new_uvs_ip;
    new_entry.netaddr = modify_req->new_net_addr;
    ret = dip_table_modify(dip_table, &old_key, &new_entry, modify_req->mask);

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_dip_table_modify_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_dip_table_modify_rsp_t *modify_rsp = (tpsa_dip_table_modify_rsp_t *)(rsp->rsp);
    modify_rsp->res = ret;

    rsp->cmd_type = DIP_TABLE_MODIFY;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_dip_table_modify_rsp_t);

    return rsp;
}

#ifdef __cplusplus
}
#endif

