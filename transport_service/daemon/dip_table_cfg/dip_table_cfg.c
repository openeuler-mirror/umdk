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
    key.deid = show_req->deid;
    key.upi = show_req->upi;

    (void)pthread_rwlock_rdlock(&dip_table->rwlock);
    entry = dip_table_lookup(dip_table, &key);
    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_dip_table_show_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }
    tpsa_dip_table_show_rsp_t *show_rsp = (tpsa_dip_table_show_rsp_t *)rsp->rsp;

    if (entry == NULL) {
        TPSA_LOG_ERR("can not find dip by key: " EID_FMT " and upi: %u\n",
            EID_ARGS(show_req->deid), show_req->upi);
        show_rsp->res = -ENXIO;
    } else {
        show_rsp->res = 0;
        show_rsp->dip = entry->key.deid;
        show_rsp->upi = entry->key.upi;
        show_rsp->peer_tpsa = entry->peer_tps;
        show_rsp->underlay_eid = entry->underlay_eid;
        show_rsp->netaddr = entry->netaddr;
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
    key.deid = add_req->dip;
    key.upi = add_req->upi;

    if (dip_table_lookup(dip_table, &key) != NULL) {
        TPSA_LOG_ERR("Try to add dip entry while entry already exists.");
        TPSA_LOG_ERR("Use modify command instead. key: "EID_FMT" and upi: %u\n",
            EID_ARGS(add_req->dip), add_req->upi);
        ret = -ENXIO;
    } else {
        add_entry.key.deid = add_req->dip;
        add_entry.key.upi = add_req->upi;
        add_entry.peer_tps = add_req->peer_tpsa;
        add_entry.underlay_eid = add_req->underlay_eid;
        add_entry.netaddr = add_req->netaddr;

        ret = dip_table_add(dip_table, &key, &add_entry);
        if (ret != 0) {
            TPSA_LOG_ERR("can not add dip_table by key: "EID_FMT" and upi %u\n",
                EID_ARGS(add_req->dip), add_req->upi);
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
    key.deid = del_req->dip;
    key.upi = del_req->upi;

    (void)pthread_rwlock_rdlock(&dip_table->rwlock);
    entry = dip_table_lookup(dip_table, &key);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        TPSA_LOG_ERR("can not find dip by key: "EID_FMT" and upi %u\n",
            EID_ARGS(del_req->dip), del_req->upi);
        ret = -ENXIO;
    } else {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        ret = dip_table_remove(dip_table, &key);
        if (ret != 0) {
            TPSA_LOG_ERR("can not del dip_table by key: "EID_FMT" and upi %u\n",
                EID_ARGS(del_req->dip), del_req->upi);
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

static int dip_table_modify(dip_table_t *dip_table, tpsa_dip_table_modify_req_t *modify_req)
{
    dip_table_entry_t *entry = NULL;
    dip_table_key_t old_key = {0};

    old_key.deid = modify_req->old_dip;
    old_key.upi = modify_req->old_upi;

    (void)pthread_rwlock_rdlock(&dip_table->rwlock);
    entry = dip_table_lookup(dip_table, &old_key);
    if (entry == NULL) {
        TPSA_LOG_ERR("can not find dip by key: "EID_FMT" and upi %u\n",
            EID_ARGS(modify_req->old_dip), modify_req->old_upi);
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
        return -ENXIO;
    }

    if (modify_req->mask.bs.netaddr > 0) {
        dip_table->old_netaddr = entry->netaddr;
        entry->netaddr = modify_req->new_netaddr;
        /* Mark refresh entry */
        dip_table->tbl_refresh = true;
        dip_table->refresh_entry = entry;
    }

    if (modify_req->mask.bs.peer_tpsa > 0) {
        entry->peer_tps = modify_req->new_peer_tpsa;
    }

    if (modify_req->mask.bs.underlay_eid > 0) {
        entry->underlay_eid = modify_req->new_underlay_eid;
    }

    if (modify_req->mask.bs.dip > 0 && modify_req->mask.bs.upi) {
        /* generate a new entry and del the old one */
        dip_table_entry_t add_entry = {0};
        dip_table_key_t new_key = {0};

        add_entry.key.deid = modify_req->new_dip;
        add_entry.key.upi = modify_req->new_upi;
        add_entry.peer_tps = entry->peer_tps;
        add_entry.underlay_eid = entry->underlay_eid;
        add_entry.netaddr = entry->netaddr;
        (void)pthread_rwlock_unlock(&dip_table->rwlock);

        new_key.deid = modify_req->new_dip;
        new_key.upi = modify_req->new_upi;

        if (dip_table_add(dip_table, &new_key, &add_entry) != 0) {
            TPSA_LOG_ERR("can not add dip_table by deid: "EID_FMT" and upi %u\n",
                EID_ARGS(modify_req->new_dip), modify_req->new_upi);
        }

        if (dip_table_remove(dip_table, &old_key) != 0) {
            TPSA_LOG_ERR("can not del dip_table by key: "EID_FMT" and upi %u\n",
                EID_ARGS(modify_req->old_dip), modify_req->old_upi);
        }

        /* TODO: fresh table */
    } else {
        (void)pthread_rwlock_unlock(&dip_table->rwlock);
    }

    return 0;
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

    ret = dip_table_modify(dip_table, modify_req);

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

