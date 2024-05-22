/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa vport table cfg Interface file
 * Author: Ji Lei
 * Create: 2023-07-15
 * Note:
 * History: 2023-07-15 Ji lei Initial version
 */
#include <stdlib.h>
#include <errno.h>

#include "tpsa_daemon.h"
#include "tpsa_table.h"
#include "tpsa_log.h"
#include "vport_table_cfg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VPORT_TABLE_DEFAULT_UM_EN 1

tpsa_response_t *process_vport_table_show(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_vport_show_req_t *show_req = NULL;
    vport_table_t *vport_table = NULL;
    vport_key_t key = {0};
    vport_table_entry_t *entry = NULL;
    vport_table_entry_t tmp_entry = {0};
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
    show_req = (tpsa_vport_show_req_t *)req->req;
    if (strnlen(show_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }

    vport_table = &ctx->worker->table_ctx.vport_table;
    key.fe_idx = show_req->fe_idx;
    (void)memcpy(key.tpf_name, show_req->dev_name, UVS_MAX_DEV_NAME);

    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    entry = vport_table_lookup(vport_table, &key);
    if (entry == NULL) {
        TPSA_LOG_ERR("can not find vport by key dev_name:%s fe_idx %hu\n", key.tpf_name, key.fe_idx);
        ret = -1;
    } else {
        tmp_entry = *entry;
        ret = 0;
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_vport_show_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_vport_show_rsp_t *show_rsp = (tpsa_vport_show_rsp_t *)(rsp->rsp);
    show_rsp->res = ret;
    (void)memcpy(show_rsp->args.dev_name, tmp_entry.key.tpf_name, UVS_MAX_DEV_NAME);
    show_rsp->args.fe_idx = tmp_entry.key.fe_idx;
    show_rsp->args.sip_idx = tmp_entry.sip_idx;
    show_rsp->args.tp_cnt = tmp_entry.tp_cnt;
    show_rsp->args.tp_cfg = tmp_entry.tp_cfg;
    show_rsp->args.rc_cfg = tmp_entry.rc_cfg;
    show_rsp->args.pattern = tmp_entry.pattern;
    show_rsp->args.virtualization = tmp_entry.virtualization;
    show_rsp->args.min_jetty_cnt = tmp_entry.min_jetty_cnt;
    show_rsp->args.max_jetty_cnt = tmp_entry.max_jetty_cnt;
    show_rsp->args.min_jfr_cnt = tmp_entry.min_jfr_cnt;
    show_rsp->args.max_jfr_cnt = tmp_entry.max_jfr_cnt;

    rsp->cmd_type = VPORT_TABLE_SHOW;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_vport_show_rsp_t);

    return rsp;
}

static int tpsa_get_dev_feature_ioctl(tpsa_daemon_ctx_t *ctx, char* dev_name, tpsa_device_feat_t *feat,
    uint32_t *max_ueid_cnt)
{
    tpsa_ioctl_cfg_t cfg = {0};
    int ret;

    cfg.cmd_type = TPSA_CMD_GET_DEV_FEATURE;
    (void)strcpy(cfg.cmd.get_dev_feature.in.dev_name, dev_name);

    ret = tpsa_ioctl(ctx->worker->ioctl_ctx.ubcore_fd, &cfg);
    *feat = cfg.cmd.get_dev_feature.out.feature;
    *max_ueid_cnt = cfg.cmd.get_dev_feature.out.max_ueid_cnt;
    return ret;
}

static int tpsa_verify_single_capability(uint32_t config_feat, uint32_t local_cap, const char* cap_name)
{
    if (config_feat == 1) {
        if (local_cap == 0) {
            TPSA_LOG_ERR("The %s is not supported by the device", cap_name);
            return -EINVAL;
        }
        TPSA_LOG_INFO("The %s is supported by the device", cap_name);
    }

    return 0;
}

static int tpsa_verify_local_device_capability(tpsa_tp_mod_flag_t config, tpsa_device_feat_t feat)
{
    int ret;

    ret = tpsa_verify_single_capability(config.bs.oor_en, feat.bs.oor, g_tpsa_capability[TPSA_CAP_OOR]);
    if (ret != 0) {
        return ret;
    }

    ret = tpsa_verify_single_capability(config.bs.sr_en, feat.bs.selective_retrans,
        g_tpsa_capability[TPSA_CAP_SR]);
    if (ret != 0) {
        return ret;
    }

    ret = tpsa_verify_single_capability(config.bs.spray_en, feat.bs.spray_en, g_tpsa_capability[TPSA_CAP_SPRAY]);
    if (ret != 0) {
        return ret;
    }

    ret = tpsa_verify_single_capability(config.bs.dca_enable, feat.bs.dca, g_tpsa_capability[TPSA_CAP_DCA]);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static void fill_vport_info(vport_table_entry_t *entry, tpsa_vport_args_t *args, uint32_t max_ueid_cnt)
{
    (void)memcpy(entry->key.tpf_name, args->dev_name, UVS_MAX_DEV_NAME);
    entry->key.fe_idx = args->fe_idx;
    entry->mask.value = args->mask.value;
    entry->sip_idx = args->sip_idx;
    entry->tp_cnt = args->tp_cnt;
    entry->tp_cfg = args->tp_cfg;
    entry->rc_cfg = args->rc_cfg;
    entry->pattern = args->pattern;
    entry->virtualization = args->virtualization;
    entry->min_jetty_cnt = args->min_jetty_cnt;
    entry->max_jetty_cnt = args->max_jetty_cnt;
    entry->min_jfr_cnt = args->min_jfr_cnt;
    entry->max_jfr_cnt = args->max_jfr_cnt;
    entry->ueid_max_cnt = max_ueid_cnt;
    /*
     * only use um_en in cloud scenarios;
     * in non-cloud scenarios, set um_en to true.
     */
    entry->tp_cfg.tp_mod_flag.bs.um_en = VPORT_TABLE_DEFAULT_UM_EN;
    entry->tp_cfg.tp_mod_flag.bs.share_mode = args->tp_cfg.tp_mod_flag.bs.share_mode;
}

tpsa_response_t *process_vport_table_add(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_vport_add_req_t *add_req = NULL;
    vport_table_t *vport_table = NULL;
    vport_table_entry_t entry = {0};
    tpsa_device_feat_t feat;
    uint32_t max_ueid_cnt;

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

    add_req = (tpsa_vport_add_req_t *)req->req;
    if (strnlen(add_req->args.dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }

    ret = tpsa_get_dev_feature_ioctl(ctx, add_req->args.dev_name, &feat, &max_ueid_cnt);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to get sr en\n");
        goto create_rsp;
    }
    ret = tpsa_verify_local_device_capability(add_req->args.tp_cfg.tp_mod_flag, feat);
    if (ret != 0) {
        goto create_rsp;
    }

    vport_table = &ctx->worker->table_ctx.vport_table;
    fill_vport_info(&entry, &add_req->args, max_ueid_cnt);

    ret = vport_table_add(vport_table, &entry);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add vport, dev: %s, fe_idx: %hu\n", entry.key.tpf_name, entry.key.fe_idx);
        goto create_rsp;
    }

    tpsa_global_cfg_t *global_cfg = &ctx->worker->global_cfg_ctx;
    ret = uvs_ioctl_cmd_set_vport_cfg(&ctx->worker->ioctl_ctx, &entry, global_cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("can not ioctl vport, dev: %s, fe_idx: %hu\n", entry.key.tpf_name, entry.key.fe_idx);
        if (vport_table_remove(vport_table, &entry.key) != 0) {
            TPSA_LOG_ERR("failed to del vport, dev: %s, fe_idx: %hu\n", entry.key.tpf_name, entry.key.fe_idx);
        }
    }

create_rsp:
    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_vport_add_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_vport_add_rsp_t *add_rsp = (tpsa_vport_add_rsp_t *)(rsp->rsp);
    add_rsp->res = ret;

    rsp->cmd_type = VPORT_TABLE_ADD;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_vport_add_rsp_t);

    return rsp;
}

tpsa_response_t *process_vport_table_del(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_vport_del_req_t *del_req = NULL;
    vport_table_t *vport_table = NULL;
    vport_key_t key = {0};
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

    del_req = (tpsa_vport_del_req_t *)req->req;
    if (strnlen(del_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }
    vport_table = &ctx->worker->table_ctx.vport_table;
    key.fe_idx = del_req->fe_idx;
    (void)memcpy(key.tpf_name, del_req->dev_name, UVS_MAX_DEV_NAME);

    ret = vport_set_deleting(vport_table, &key, NULL);
    if (ret != 0) {
        TPSA_LOG_ERR("can not del vport by key dev_name:%s, fe_idx %hu\n", key.tpf_name, key.fe_idx);
    } else {
        (void)uvs_ioctl_cmd_clear_vport_cfg(&ctx->worker->ioctl_ctx, &key);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_vport_del_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_vport_del_rsp_t *del_rsp = (tpsa_vport_del_rsp_t *)(rsp->rsp);
    del_rsp->res = ret;

    rsp->cmd_type = VPORT_TABLE_DEL;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_vport_del_rsp_t);

    return rsp;
}

tpsa_response_t *process_vport_table_show_ueid(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_vport_show_ueid_req_t *show_req = NULL;
    vport_table_t *vport_table = NULL;
    vport_key_t key = {0};
    tpsa_ueid_t *ueid = NULL;
    int ret = 0;

    if (read_len != (req->req_len + (ssize_t)sizeof(tpsa_request_t))) {
        TPSA_LOG_ERR("req_len not correct drop req, type: %d, len: %d\n", req->cmd_type, req->req_len);
        return NULL;
    }

    ctx = get_tpsa_daemon_ctx();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return NULL;
    }

    show_req = (tpsa_vport_show_ueid_req_t *)req->req;
    if (strnlen(show_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }

    vport_table = &ctx->worker->table_ctx.vport_table;
    key.fe_idx = show_req->fe_idx;
    (void)memcpy(key.tpf_name, show_req->dev_name, UVS_MAX_DEV_NAME);

    ueid = vport_table_lookup_ueid(vport_table, &key, show_req->eid_idx);
    if (ueid == NULL) {
        ret = -1;
    }
    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_vport_show_ueid_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_vport_show_ueid_rsp_t *show_rsp = (tpsa_vport_show_ueid_rsp_t *)(rsp->rsp);
    show_rsp->res = ret;
    if (ueid != NULL) {
        show_rsp->eid = ueid->eid;
        show_rsp->upi = ueid->upi;
    }
    rsp->cmd_type = VPORT_TABLE_SHOW_UEID;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_vport_show_ueid_rsp_t);

    return rsp;
}

tpsa_response_t *process_vport_table_add_ueid(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_vport_add_ueid_req_t *add_req = NULL;
    vport_table_t *vport_table = NULL;
    vport_key_t key = {0};
    tpsa_ueid_cfg_t ueid;
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

    add_req = (tpsa_vport_add_ueid_req_t *)req->req;
    if (strnlen(add_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }
    vport_table = &ctx->worker->table_ctx.vport_table;
    key.fe_idx = add_req->fe_idx;
    (void)memcpy(key.tpf_name, add_req->dev_name, UVS_MAX_DEV_NAME);

    ueid.eid = add_req->eid;
    ueid.upi = add_req->upi;
    ueid.eid_index = add_req->eid_idx;
    ret = vport_table_add_ueid(vport_table, &key, &ueid);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add vport by key dev_name: %s fe_idx %hu\n", key.tpf_name, key.fe_idx);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_vport_add_ueid_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_vport_add_ueid_rsp_t *add_rsp = (tpsa_vport_add_ueid_rsp_t *)(rsp->rsp);
    add_rsp->res = ret;

    rsp->cmd_type = VPORT_TABLE_ADD_UEID;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_vport_add_ueid_rsp_t);

    return rsp;
}

tpsa_response_t *process_vport_table_del_ueid(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_vport_del_ueid_req_t *del_req = NULL;
    vport_table_t *vport_table = NULL;
    vport_key_t key = {0};
    tpsa_ueid_t ueid;
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

    del_req = (tpsa_vport_del_ueid_req_t *)req->req;
    if (strnlen(del_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }
    vport_table = &ctx->worker->table_ctx.vport_table;
    key.fe_idx = del_req->fe_idx;
    (void)memcpy(key.tpf_name, del_req->dev_name, UVS_MAX_DEV_NAME);

    (void)memset(&ueid, 0, sizeof(tpsa_ueid_t));
    ret = vport_table_del_ueid(vport_table, &key, del_req->eid_idx);
    if (ret != 0) {
        TPSA_LOG_ERR("can not del vport by key fe_idx %hu\n", key.fe_idx);
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_vport_del_ueid_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }

    tpsa_vport_del_ueid_rsp_t *del_rsp = (tpsa_vport_del_ueid_rsp_t *)(rsp->rsp);
    del_rsp->res = ret;

    rsp->cmd_type = VPORT_TABLE_DEL_UEID;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_vport_del_ueid_rsp_t);

    return rsp;
}

static int tpsa_ioctl_set_upi(int ubcore_fd, const tpsa_ioctl_cfg_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    tpsa_cmd_set_upi_t arg = {0};

    hdr.command = (uint32_t)TPSA_CMD_SET_UPI;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_set_upi_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->cmd.set_upi.in.dev_name, UVS_MAX_DEV_NAME);
    arg.in.upi = cfg->cmd.set_upi.in.upi;
    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("set pattern3 upi ioctl failed, ret:%d, cmd:%u.\n", ret, hdr.command);
        return ret;
    }

    TPSA_LOG_INFO("set pattern3 upi ioctl success");
    return ret;
}

tpsa_response_t *process_vport_table_set_upi(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_set_upi_req_t *set_req = NULL;
    tpsa_ioctl_cfg_t cfg;
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
    set_req = (tpsa_set_upi_req_t *)req->req;
    if (strnlen(set_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }
    cfg.cmd.set_upi.in.upi = set_req->upi;
    (void)memcpy(cfg.cmd.set_upi.in.dev_name, set_req->dev_name, UVS_MAX_DEV_NAME);
    ret = tpsa_ioctl_set_upi(ctx->worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to ioctl set upi\n");
        return NULL;
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_set_upi_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }
    tpsa_set_upi_rsp_t *set_rsp = (tpsa_set_upi_rsp_t *)(rsp->rsp);
    set_rsp->res = ret;
    rsp->cmd_type = VPORT_TABLE_SET_UPI;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_set_upi_rsp_t);

    return rsp;
}

static int tpsa_ioctl_show_upi(int ubcore_fd, tpsa_ioctl_cfg_t *cfg)
{
    int ret;
    urma_cmd_hdr_t hdr;
    tpsa_cmd_show_upi_t arg = {0};

    hdr.command = (uint32_t)TPSA_CMD_SHOW_UPI;
    hdr.args_len = (uint32_t)sizeof(tpsa_cmd_show_upi_t);
    hdr.args_addr = (uint64_t)&arg;

    (void)memcpy(arg.in.dev_name, cfg->cmd.show_upi.in.dev_name, UVS_MAX_DEV_NAME);
    ret = ioctl(ubcore_fd, TPSA_CMD, &hdr);
    if (ret != 0) {
        TPSA_LOG_ERR("show pattern3 upi ioctl failed, ret:%d, cmd:%u.\n", ret, hdr.command);
        return ret;
    }
    cfg->cmd.show_upi.out.upi = arg.out.upi;
    TPSA_LOG_INFO("show upi ioctl success");
    return ret;
}

tpsa_response_t *process_vport_table_show_upi(tpsa_request_t *req, ssize_t read_len)
{
    tpsa_response_t *rsp;
    tpsa_daemon_ctx_t *ctx = NULL;
    tpsa_show_upi_req_t *show_req = NULL;
    tpsa_ioctl_cfg_t cfg;
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
    show_req = (tpsa_show_upi_req_t *)req->req;
    if (strnlen(show_req->dev_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter.");
        return NULL;
    }
    (void)strcpy(cfg.cmd.show_upi.in.dev_name, show_req->dev_name);
    ret = tpsa_ioctl_show_upi(ctx->worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_WARN("failed to ioctl show upi\n");
    }

    rsp = calloc(1, sizeof(tpsa_response_t) + sizeof(tpsa_show_upi_rsp_t));
    if (rsp == NULL) {
        return NULL;
    }
    tpsa_show_upi_rsp_t *show_rsp = (tpsa_show_upi_rsp_t *)(rsp->rsp);
    show_rsp->res = ret;
    show_rsp->upi = ret == 0 ? cfg.cmd.show_upi.out.upi : 0;
    rsp->cmd_type = VPORT_TABLE_SHOW_UPI;
    rsp->rsp_len = (ssize_t)sizeof(tpsa_show_upi_rsp_t);

    return rsp;
}

#ifdef __cplusplus
}
#endif

