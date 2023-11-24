/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa live_migrate table cfg Interface file
 * Author: Sun Fang
 * Create: 2023-08-02
 * Note:
 * History: 2023-08-02 Sun Fang Initial version
 */
#include <stdlib.h>

#include "tpsa_daemon.h"
#include "tpsa_table.h"
#include "tpsa_log.h"
#include "live_migrate_table_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

tpsa_response_t *process_live_migrate_table_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_live_migrate_show_req_t *show_req = NULL;
    live_migrate_table_t *live_migrate_table = NULL;
    live_migrate_table_key_t key = {0};
    live_migrate_table_entry_t *entry = NULL;
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

    show_req = (tpsa_live_migrate_show_req_t *)req->req;
    live_migrate_table = &ctx->worker->table_ctx.live_migrate_table;
    key.fe_idx = show_req->fe_idx;
    (void)memcpy(key.dev_name, show_req->dev_name, TPSA_MAX_DEV_NAME);

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_live_migrate_show_rsp_t));
    if (rsp == NULL) {
        TPSA_LOG_ERR("can not alloc rsp mem\n");
        return NULL;
    }

    tpsa_live_migrate_show_rsp_t *show_rsp = (tpsa_live_migrate_show_rsp_t *)(rsp->rsp);

    (void)pthread_rwlock_rdlock(&live_migrate_table->rwlock);
    entry = live_migrate_table_lookup(live_migrate_table, &key);
    if (entry == NULL) {
        TPSA_LOG_ERR("can not find live_migrate by key fe_idx %hu\n", key.fe_idx);
        ret = -1;
    } else {
        ret = 0;
        (void)memcpy(&show_rsp->dip, &entry->dip, TPSA_EID_SIZE);
        (void)memcpy(show_rsp->dev_name, entry->key.dev_name, TPSA_MAX_DEV_NAME);
        show_rsp->flag = entry->live_migrate_flag;
    }
    show_rsp->res = ret;
    (void)pthread_rwlock_unlock(&live_migrate_table->rwlock);

    rsp->cmd_type = LIVE_MIGRATE_TABLE_SHOW;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_live_migrate_show_rsp_t);

    return rsp;
}

tpsa_response_t *process_live_migrate_table_add(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_live_migrate_add_req_t *add_req = NULL;
    live_migrate_table_t *live_migrate_table = NULL;
    live_migrate_table_key_t key = {0};
    live_migrate_table_entry_t entry = {0};
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

    add_req = (tpsa_live_migrate_add_req_t *)req->req;
    live_migrate_table = &ctx->worker->table_ctx.live_migrate_table;
    key.fe_idx = add_req->fe_idx;
    (void)memcpy(key.dev_name, add_req->dev_name, TPSA_MAX_DEV_NAME);
    (void)memcpy(&entry.dip, &add_req->dip, TPSA_EID_SIZE);
    entry.live_migrate_flag = LIVE_MIGRATE_TRUE;

    ret = live_migrate_table_add(live_migrate_table, &key, &entry);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add live migrate by key fe_idx %hu\n", key.fe_idx);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_live_migrate_add_rsp_t));
    if (rsp == NULL) {
        TPSA_LOG_ERR("can not alloc rsp mem\n");
        return NULL;
    }

    tpsa_live_migrate_add_rsp_t *add_rsp = (tpsa_live_migrate_add_rsp_t *)(rsp->rsp);
    add_rsp->res = ret;

    rsp->cmd_type = LIVE_MIGRATE_TABLE_ADD;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_live_migrate_add_rsp_t);

    return rsp;
}

tpsa_response_t *process_live_migrate_table_del(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_live_migrate_del_req_t *del_req = NULL;
    live_migrate_table_t *live_migrate_table = NULL;
    live_migrate_table_key_t key = {0};
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

    del_req = (tpsa_live_migrate_del_req_t *)req->req;
    live_migrate_table = &ctx->worker->table_ctx.live_migrate_table;
    key.fe_idx = del_req->fe_idx;
    (void)memcpy(key.dev_name, del_req->dev_name, TPSA_MAX_DEV_NAME);

    ret = live_migrate_table_remove(live_migrate_table, &key);
    if (ret != 0) {
        TPSA_LOG_ERR("can not del live_migrate by key fe_idx %hu\n", key.fe_idx);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_live_migrate_del_rsp_t));
    if (rsp == NULL) {
        TPSA_LOG_ERR("can not alloc rsp mem\n");
        return NULL;
    }

    tpsa_live_migrate_del_rsp_t *del_rsp = (tpsa_live_migrate_del_rsp_t *)(rsp->rsp);
    del_rsp->res = ret;

    rsp->cmd_type = LIVE_MIGRATE_TABLE_DEL;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_live_migrate_del_rsp_t);

    return rsp;
}

#ifdef __cplusplus
}
#endif

