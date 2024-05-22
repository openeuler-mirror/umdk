/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa api file
 * Author: Zheng Hongqin
 * Create: 2023-11-22
 * Note:
 * History:
 */

#include <errno.h>
#include "uvs_types_str.h"
#include "uvs_tp_exception.h"
#include "uvs_api.h"
#include "uvs_private_api.h"
#include "tpsa_worker.h"
#include "tpsa_ioctl.h"
#include "uvs_stats.h"
#include "tpsa_types.h"

#define UVS_DEFAULT_UM_EN 1
#define UVS_DEFAULT_FLAG_UM_EN 1

const char *g_tpsa_capability[TPSA_CAP_NUM] = {
    [TPSA_CAP_OOR] = "out of order receive",
    [TPSA_CAP_SR] = "selective retransmission",
    [TPSA_CAP_SPRAY] = "spray with src udp port",
    [TPSA_CAP_DCA] = "administrate dynamic connection"
};

#define UVS_FILL_GLOBAL_CFG_WITH_MASK(in, out, field)	                                 \
    do {                                                                                 \
        if ((in)->mask.bs.field) {                                                       \
            (out)->mask.bs.field = (in)->mask.bs.field;                                  \
            (out)->field = (in)->field;                                                  \
            TPSA_LOG_INFO("uvs add global info " #field ":%u", (uint32_t)(in)->field);   \
        }                                                                                \
    } while (0)

int uvs_add_global_info(uvs_global_info_t *info)
{
    if (info == NULL) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    tpsa_global_cfg_t *global_cfg_ctx = &uvs_worker->global_cfg_ctx;
    /* global_cfg->mask and local global mask is different */
    TPSA_LOG_INFO("uvs add global info mask:%u", info->mask.value);

    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, mtu);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, slice);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, suspend_cnt);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, suspend_period);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, sus2err_period);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, hop_limit);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, udp_port_start);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, udp_port_end);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, udp_range);

    global_cfg_ctx->flag.bs.um_en = info->mask.bs.flag_um_en == 0 ? (uint32_t)UVS_DEFAULT_UM_EN : info->flag.bs.um_en;
    global_cfg_ctx->mask.bs.flag_um_en = UVS_DEFAULT_FLAG_UM_EN;

    int ret = uvs_ioctl_cmd_set_global_cfg(&uvs_worker->ioctl_ctx, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to add global configurations.\n");
        return -1;
    }

    TPSA_LOG_INFO("Add global configurations successfully!\n");
    return 0;
}

uvs_global_info_t *uvs_list_global_info(void)
{
    uvs_global_info_t *info = (uvs_global_info_t *)calloc(1, sizeof(uvs_global_info_t));
    if (info == NULL) {
        TPSA_LOG_ERR("failed to alloc global cfg.\n");
        return NULL;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        free(info);
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return NULL;
    }

    info->mtu = uvs_worker->global_cfg_ctx.mtu;
    info->slice = uvs_worker->global_cfg_ctx.slice;
    info->suspend_cnt = uvs_worker->global_cfg_ctx.suspend_cnt;
    info->suspend_period = uvs_worker->global_cfg_ctx.suspend_period;
    info->sus2err_period = uvs_worker->global_cfg_ctx.sus2err_period;

    info->hop_limit = uvs_worker->global_cfg_ctx.hop_limit;
    info->udp_port_start = uvs_worker->global_cfg_ctx.udp_port_start;
    info->udp_port_end = uvs_worker->global_cfg_ctx.udp_port_end;
    info->udp_range = uvs_worker->global_cfg_ctx.udp_range;

    return info;
}

static void uvs_fill_vport_by_global(vport_table_entry_t *vport_entry, tpsa_global_cfg_t *global_cfg_ctx)
{
    if (global_cfg_ctx->mask.bs.slice) {
        vport_entry->rc_cfg.slice = global_cfg_ctx->slice;
        vport_entry->mask.bs.slice = global_cfg_ctx->mask.bs.slice;
    }
    if (global_cfg_ctx->mask.bs.udp_range) {
        vport_entry->tp_cfg.udp_range = (uint8_t)global_cfg_ctx->udp_range;
        vport_entry->mask.bs.udp_range = global_cfg_ctx->mask.bs.udp_range;
    }
    if (global_cfg_ctx->mask.bs.udp_port_start) {
        vport_entry->tp_cfg.data_udp_start = global_cfg_ctx->udp_port_start;
        vport_entry->tp_cfg.ack_udp_start = global_cfg_ctx->udp_port_start;
        vport_entry->mask.bs.data_udp_start = global_cfg_ctx->mask.bs.udp_port_start;
        vport_entry->mask.bs.ack_udp_start = global_cfg_ctx->mask.bs.udp_port_start;
    }
    if (global_cfg_ctx->mask.bs.hop_limit) {
        vport_entry->tp_cfg.hop_limit = global_cfg_ctx->hop_limit;
        vport_entry->mask.bs.hop_limit = global_cfg_ctx->mask.bs.hop_limit;
    }
}

static void uvs_fill_vport_mask(vport_entry_mask_t *mask, uvs_vport_info_t *info)
{
    mask->bs.dev_name = info->mask.bs.tpf_name;
    mask->bs.fe_idx = info->mask.bs.fe_idx;
    mask->bs.sip_idx = info->mask.bs.sip_idx;
    mask->bs.tp_cnt = info->tp_info.mask.bs.tp_cnt_per_tpg;
    mask->bs.pattern = info->mask.bs.flag_pattern;
    mask->bs.virtualization = info->mask.bs.virtualization;
    mask->bs.max_jetty_cnt = info->mask.bs.jetty_max_cnt;
    mask->bs.min_jetty_cnt = info->mask.bs.jetty_min_cnt;
    mask->bs.max_jfr_cnt = info->mask.bs.jfr_max_cnt;
    mask->bs.min_jfr_cnt = info->mask.bs.jfr_min_cnt;
    mask->bs.flow_label = info->tp_info.mask.bs.flow_label;
    mask->bs.oor_cnt = info->tp_info.mask.bs.oor_cnt;
    mask->bs.retry_num = info->tp_info.mask.bs.retry_times;
    mask->bs.retry_factor = info->tp_info.mask.bs.retry_factor;
    mask->bs.ack_timeout = info->tp_info.mask.bs.ack_timeout;
    mask->bs.dscp = info->tp_info.mask.bs.dscp;
    mask->bs.rc_cnt = info->mask.bs.rct_cnt;
    mask->bs.rc_depth = info->mask.bs.rct_depth;
    mask->bs.eid = info->mask.bs.eid;
    mask->bs.upi = info->mask.bs.upi;
    mask->bs.eid_index = info->mask.bs.eid;
    mask->bs.flag_share_mode = info->mask.bs.flag_share_mode;
}

static void uvs_fill_vport_entry(
    vport_table_entry_t *vport_entry, uvs_vport_info_t *info, tpsa_worker_t *worker)
{
    (void)memcpy(vport_entry->key.tpf_name, info->tpf_name, UVS_MAX_DEV_NAME);
    vport_entry->key.fe_idx = info->fe_idx;
    vport_entry->sip_idx = info->sip_idx;
    vport_entry->tp_cnt = info->tp_info.tp_cnt_per_tpg;
    vport_entry->pattern = info->flag.bs.pattern;
    vport_entry->virtualization = info->virtualization;
    vport_entry->max_jetty_cnt = info->jetty_max_cnt;
    vport_entry->min_jetty_cnt = info->jetty_min_cnt;
    vport_entry->max_jfr_cnt = info->jfr_max_cnt;
    vport_entry->min_jfr_cnt = info->jfr_min_cnt;

    vport_entry->tp_cfg.flow_label = info->tp_info.flow_label;
    vport_entry->tp_cfg.oor_cnt = info->tp_info.oor_cnt;
    vport_entry->tp_cfg.retry_num = info->tp_info.retry_times;
    vport_entry->tp_cfg.retry_factor = info->tp_info.retry_factor;
    vport_entry->tp_cfg.ack_timeout = info->tp_info.ack_timeout;
    vport_entry->tp_cfg.dscp = info->tp_info.dscp;
    vport_entry->tp_cfg.cc_priority = info->tp_info.cc_pri;
    vport_entry->tp_cfg.set_cc_priority = true;

    vport_entry->tp_cfg.tp_mod_flag.bs.oor_en = info->tp_info.flag.bs.oor_en;
    vport_entry->tp_cfg.tp_mod_flag.bs.sr_en = info->tp_info.flag.bs.sr_en;
    vport_entry->tp_cfg.tp_mod_flag.bs.cc_en = info->tp_info.flag.bs.cc_en;
    vport_entry->tp_cfg.tp_mod_flag.bs.spray_en = info->tp_info.flag.bs.spray_en;
    vport_entry->tp_cfg.tp_mod_flag.bs.dca_enable = info->tp_info.flag.bs.dca_enable;
    vport_entry->tp_cfg.tp_mod_flag.bs.um_en = info->flag.bs.um_en;
    vport_entry->tp_cfg.tp_mod_flag.bs.share_mode = info->flag.bs.share_mode;
    vport_entry->mask.bs.flag_um_en = info->mask.bs.flag_um_en;

    tpsa_global_cfg_t *global_cfg_ctx = &worker->global_cfg_ctx;
     /* if the user doesn't config um_en in vport table, use global table's value */
    if (!info->mask.bs.flag_um_en) {
        vport_entry->tp_cfg.tp_mod_flag.bs.um_en = global_cfg_ctx->flag.bs.um_en;
        vport_entry->mask.bs.flag_um_en = global_cfg_ctx->mask.bs.flag_um_en;
        TPSA_LOG_INFO("config um_en in vport table as %u", global_cfg_ctx->flag.bs.um_en);
    }

    uvs_fill_vport_by_global(vport_entry, global_cfg_ctx);

    vport_entry->rc_cfg.rc_cnt = info->rct_cnt;
    vport_entry->rc_cfg.rc_depth = info->rct_depth;

    vport_entry->ueid[0].upi = info->upi;
    (void)memcpy(&vport_entry->ueid[0].eid, &info->eid.eid, sizeof(uvs_eid_t));
    vport_entry->ueid[0].is_valid = true;
    uvs_fill_vport_mask(&vport_entry->mask, info);
}

static void uvs_fill_vport_info(uvs_vport_info_t *info, vport_table_entry_t *vport_entry)
{
    (void)memcpy(info->tpf_name, vport_entry->key.tpf_name, UVS_MAX_DEV_NAME);
    info->fe_idx = vport_entry->key.fe_idx;
    info->sip_idx = vport_entry->sip_idx;
    info->tp_info.tp_cnt_per_tpg = vport_entry->tp_cnt;
    info->flag.bs.pattern = vport_entry->pattern;
    info->virtualization = vport_entry->virtualization;
    info->jetty_max_cnt = vport_entry->max_jetty_cnt;
    info->jetty_min_cnt = vport_entry->min_jetty_cnt;
    info->jfr_max_cnt = vport_entry->max_jfr_cnt;
    info->jfr_min_cnt = vport_entry->min_jfr_cnt;

    info->tp_info.flow_label = vport_entry->tp_cfg.flow_label;
    info->tp_info.oor_cnt = vport_entry->tp_cfg.oor_cnt;
    info->tp_info.retry_times = vport_entry->tp_cfg.retry_num;
    info->tp_info.retry_factor = vport_entry->tp_cfg.retry_factor;
    info->tp_info.ack_timeout = vport_entry->tp_cfg.ack_timeout;
    info->tp_info.dscp = vport_entry->tp_cfg.dscp;
    info->tp_info.cc_pri = vport_entry->tp_cfg.cc_priority;

    info->tp_info.flag.bs.oor_en = vport_entry->tp_cfg.tp_mod_flag.bs.oor_en;
    info->tp_info.flag.bs.sr_en = vport_entry->tp_cfg.tp_mod_flag.bs.sr_en;
    info->tp_info.flag.bs.cc_en = vport_entry->tp_cfg.tp_mod_flag.bs.cc_en;
    info->tp_info.flag.bs.spray_en = vport_entry->tp_cfg.tp_mod_flag.bs.spray_en;
    info->tp_info.flag.bs.dca_enable = vport_entry->tp_cfg.tp_mod_flag.bs.dca_enable;

    info->rct_cnt = vport_entry->rc_cfg.rc_cnt;
    info->rct_depth = vport_entry->rc_cfg.rc_depth;

    info->upi = vport_entry->ueid[0].upi;
    (void)memcpy(&info->eid.eid, &vport_entry->ueid[0].eid, sizeof(uvs_eid_t));
}

static void uvs_modify_vport_info(vport_table_entry_t *entry, uvs_vport_info_t *mod_info)
{
    entry->max_jetty_cnt = mod_info->mask.bs.jetty_max_cnt ? mod_info->jetty_max_cnt : entry->max_jetty_cnt;
    entry->max_jfr_cnt = mod_info->mask.bs.jfr_max_cnt ? mod_info->jfr_max_cnt : entry->max_jfr_cnt;
    entry->rc_cfg.rc_cnt = mod_info->mask.bs.rct_cnt ? mod_info->rct_cnt : entry->rc_cfg.rc_cnt;
    entry->rc_cfg.rc_depth = mod_info->mask.bs.rct_depth ? mod_info->rct_depth : entry->rc_cfg.rc_depth;

    entry->tp_cfg.oor_cnt = mod_info->tp_info.mask.bs.oor_cnt ? mod_info->tp_info.oor_cnt : entry->tp_cfg.oor_cnt;
    entry->tp_cnt = mod_info->tp_info.mask.bs.tp_cnt_per_tpg ? mod_info->tp_info.tp_cnt_per_tpg : entry->tp_cnt;
    entry->tp_cfg.retry_num =
        mod_info->tp_info.mask.bs.retry_times ? mod_info->tp_info.retry_times : entry->tp_cfg.retry_num;
    entry->tp_cfg.retry_factor =
        mod_info->tp_info.mask.bs.retry_factor ? mod_info->tp_info.retry_factor : entry->tp_cfg.retry_factor;
    entry->tp_cfg.ack_timeout =
        mod_info->tp_info.mask.bs.ack_timeout ? mod_info->tp_info.ack_timeout : entry->tp_cfg.ack_timeout;
    entry->tp_cfg.dscp = mod_info->tp_info.mask.bs.dscp ? mod_info->tp_info.dscp : entry->tp_cfg.dscp;
    entry->ueid[0].upi = mod_info->mask.bs.upi ? mod_info->upi : entry->ueid[0].upi;
    if (mod_info->mask.bs.eid != 0) {
        (void)memcpy(&entry->ueid[0].eid, &mod_info->eid.eid, sizeof(uvs_eid_t));
    }

    entry->tp_cfg.tp_mod_flag.bs.oor_en =
        mod_info->tp_info.mask.bs.flag_oor_en ? mod_info->tp_info.flag.bs.oor_en : entry->tp_cfg.tp_mod_flag.bs.oor_en;
    entry->tp_cfg.tp_mod_flag.bs.sr_en =
        mod_info->tp_info.mask.bs.flag_sr_en ? mod_info->tp_info.flag.bs.sr_en : entry->tp_cfg.tp_mod_flag.bs.sr_en;
    entry->tp_cfg.tp_mod_flag.bs.cc_en =
        mod_info->tp_info.mask.bs.flag_cc_en ? mod_info->tp_info.flag.bs.cc_en : entry->tp_cfg.tp_mod_flag.bs.cc_en;
    entry->tp_cfg.tp_mod_flag.bs.spray_en = mod_info->tp_info.mask.bs.flag_spray_en
                                                ? mod_info->tp_info.flag.bs.spray_en
                                                : entry->tp_cfg.tp_mod_flag.bs.spray_en;
    entry->tp_cfg.tp_mod_flag.bs.dca_enable = mod_info->tp_info.mask.bs.flag_dca_enable
                                                  ? mod_info->tp_info.flag.bs.dca_enable
                                                  : entry->tp_cfg.tp_mod_flag.bs.dca_enable;
}

static int uvs_get_dev_feature_ioctl(
    tpsa_worker_t *worker, char *dev_name, tpsa_device_feat_t *feat, uint32_t *max_ueid_cnt)
{
    tpsa_ioctl_cfg_t cfg;
    (void)memset(&cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    int ret;

    cfg.cmd_type = TPSA_CMD_GET_DEV_FEATURE;
    (void)memcpy(cfg.cmd.get_dev_feature.in.dev_name, dev_name, UVS_MAX_DEV_NAME);

    ret = tpsa_ioctl(worker->ioctl_ctx.ubcore_fd, &cfg);
    *feat = cfg.cmd.get_dev_feature.out.feature;
    *max_ueid_cnt = cfg.cmd.get_dev_feature.out.max_ueid_cnt;

    return ret;
}

static int uvs_verify_single_capability(uint32_t config_feat, uint32_t local_cap, const char *cap_name)
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

static int uvs_verify_local_device_capability(tpsa_tp_mod_flag_t config, tpsa_device_feat_t feat)
{
    int ret;

    ret = uvs_verify_single_capability(config.bs.oor_en, feat.bs.oor, g_tpsa_capability[TPSA_CAP_OOR]);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_verify_single_capability(config.bs.sr_en, feat.bs.selective_retrans, g_tpsa_capability[TPSA_CAP_SR]);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_verify_single_capability(config.bs.spray_en, feat.bs.spray_en, g_tpsa_capability[TPSA_CAP_SPRAY]);
    if (ret != 0) {
        return ret;
    }

    ret = uvs_verify_single_capability(config.bs.dca_enable, feat.bs.dca, g_tpsa_capability[TPSA_CAP_DCA]);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int uvs_add_vport(uvs_vport_info_t *info)
{
    int ret = 0;
    uint32_t max_ueid_cnt = 0;
    tpsa_device_feat_t feat;
    vport_table_entry_t *entry = NULL;
    tpsa_worker_t *uvs_worker = NULL;

    if (info == NULL || strnlen(info->tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    if (info->type != UVS_PORT_TYPE_UBPORT) {
        TPSA_LOG_ERR("failed to add vport entry!\n");
        return -1;
    }

    entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("can not alloc vport entry memory\n");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        free(entry);
        return -1;
    }

    uvs_fill_vport_entry(entry, info, uvs_worker);
    ret = uvs_get_dev_feature_ioctl(uvs_worker, entry->key.tpf_name, &feat, &max_ueid_cnt);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to get sr en\n");
        free(entry);
        return -1;
    }
    ret = uvs_verify_local_device_capability(entry->tp_cfg.tp_mod_flag, feat);
    if (ret != 0) {
        free(entry);
        return -1;
    }
    entry->ueid_max_cnt = max_ueid_cnt;

    ret = vport_table_add(&uvs_worker->table_ctx.vport_table, entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to add vport entry!\n");
        free(entry);
        return -1;
    }

    ret = uvs_ioctl_cmd_set_vport_cfg(&uvs_worker->ioctl_ctx, entry, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("can not ioctl vport, dev: %s, fe_idx: %hu\n", entry->key.tpf_name, entry->key.fe_idx);
        if (vport_table_remove(&uvs_worker->table_ctx.vport_table, &entry->key) != 0) {
            TPSA_LOG_ERR("failed to del vport, dev: %s, fe_idx: %hu\n", entry->key.tpf_name, entry->key.fe_idx);
        }
        free(entry);
        return -1;
    }

    (void)uvs_add_vport_statistic_config(info);
    TPSA_LOG_INFO("add vport entry successfully!\n");
    free(entry);
    return 0;
}

int uvs_del_vport(const char *tpf_name, uint16_t fe_idx)
{
    int ret = 0;
    vport_key_t key = {0};
    tpsa_worker_t *uvs_worker = NULL;
    sem_t sem;

    if (tpf_name == NULL || strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    key.fe_idx = fe_idx;
    (void)memcpy(key.tpf_name, tpf_name, UVS_MAX_DEV_NAME);

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    (void)sem_init(&sem, 0, 0);
    ret = vport_set_deleting(&uvs_worker->table_ctx.vport_table, &key, &sem);
    if (ret != 0) {
        (void)sem_destroy(&sem);
        TPSA_LOG_ERR("can not del vport by key dev_name:%s, fe_idx %hu\n", key.tpf_name, key.fe_idx);
        return -1;
    }

    (void)uvs_ioctl_cmd_clear_vport_cfg(&uvs_worker->ioctl_ctx, &key);
    (void)sem_wait(&sem);
    (void)sem_destroy(&sem);
    TPSA_LOG_INFO("success delete vport entry!\n");
    return 0;
}

int uvs_show_vport(char *tpf_name, uint16_t fe_idx, uvs_vport_info_t *info)
{
    int ret = 0;
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_entry_t *vport_entry = NULL;
    vport_key_t key = {0};

    if (tpf_name == NULL || info == NULL || strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry\n");
        return -1;
    }

    key.fe_idx = fe_idx;
    (void)memcpy(key.tpf_name, tpf_name, UVS_MAX_DEV_NAME);

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        free(vport_entry);
        return -1;
    }

    ret = tpsa_lookup_vport_table(&key, &uvs_worker->table_ctx.vport_table, vport_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to show vport info!\n");
        free(vport_entry);
        return -1;
    }

    info->type = UVS_PORT_TYPE_UBPORT;
    uvs_fill_vport_info(info, vport_entry);
    free(vport_entry);
    TPSA_LOG_INFO("success to show vport entry!\n");
    return 0;
}

int uvs_modify_vport(uvs_vport_info_t *info)
{
    if (info == NULL || strnlen(info->tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret = 0;
    uint32_t max_ueid_cnt = 0;
    tpsa_device_feat_t feat;
    vport_key_t key = {0};
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_entry_t *entry = NULL;
    vport_table_entry_t *vport_entry = NULL;

    key.fe_idx = info->fe_idx;
    (void)memcpy(key.tpf_name, info->tpf_name, UVS_MAX_DEV_NAME);

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (entry == NULL) {
        return -1;
    }
    vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        free(entry);
        return -1;
    }

    ret = tpsa_lookup_vport_table(&key, &uvs_worker->table_ctx.vport_table, entry);
    if (ret != 0) {
        TPSA_LOG_ERR("the vport entry %s-%u does not exist\n", key.tpf_name, key.fe_idx);
        goto free_memory;
    }

    *vport_entry = *entry;
    uvs_modify_vport_info(vport_entry, info);
    ret = uvs_get_dev_feature_ioctl(uvs_worker, vport_entry->key.tpf_name, &feat, &max_ueid_cnt);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to get sr en\n");
        goto free_memory;
    }
    ret = uvs_verify_local_device_capability(vport_entry->tp_cfg.tp_mod_flag, feat);
    if (ret != 0) {
        goto free_memory;
    }

    ret = vport_table_remove(&uvs_worker->table_ctx.vport_table, &key);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to add the vport entry %s-%u\n", key.tpf_name, key.fe_idx);
        goto free_memory;
    }

    ret = vport_table_add(&uvs_worker->table_ctx.vport_table, vport_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to add the vport entry %s-%u\n", key.tpf_name, key.fe_idx);
        goto free_memory;
    }

    ret = uvs_ioctl_cmd_set_vport_cfg(&uvs_worker->ioctl_ctx, entry, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("can not ioctl vport, dev: %s, fe_idx: %hu\n", entry->key.tpf_name, entry->key.fe_idx);
        if (vport_table_remove(&uvs_worker->table_ctx.vport_table, &entry->key) != 0) {
            TPSA_LOG_ERR("failed to del vport, dev: %s, fe_idx: %hu\n", entry->key.tpf_name, entry->key.fe_idx);
        }
        ret = vport_table_add(&uvs_worker->table_ctx.vport_table, entry);
        if (ret != 0) {
            TPSA_LOG_ERR("failed to add the vport entry %s-%u\n", entry->key.tpf_name, entry->key.fe_idx);
        }
        goto free_memory;
    }

    TPSA_LOG_INFO("modify the vport entry %s-%u successfully\n", key.tpf_name, key.fe_idx);

free_memory:
    free(entry);
    free(vport_entry);
    return ret;
}

int uvs_add_sip(uvs_sip_info_t *sip_info, uint32_t *sip_idx)
{
    int ret = 0;
    tpsa_worker_t *uvs_worker = NULL;
    sip_table_entry_t add_entry = {0};

    if (sip_info == NULL || sip_idx == NULL || strnlen(sip_info->tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }
    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    if (strnlen(sip_info->tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter, %s.", sip_info->tpf_name);
        return -EINVAL;
    }

    (void)memcpy(add_entry.dev_name, sip_info->tpf_name, UVS_MAX_DEV_NAME);
    (void)memcpy(add_entry.addr.mac, sip_info->mac, ETH_ADDR_LEN);
    (void)memcpy(&add_entry.addr.net_addr, &sip_info->sip, sizeof(uvs_net_addr_t));
    add_entry.addr.vlan = sip_info->vlan;
    add_entry.prefix_len = sip_info->msk;
    add_entry.mtu = uvs_worker->global_cfg_ctx.mtu;

    add_entry.port_cnt = sip_info->port_cnt;
    add_entry.port_id[0] = sip_info->port_id[0];
    add_entry.addr.type = sip_info->type;

    ret = tpsa_sip_table_query_unused_idx(&uvs_worker->table_ctx, add_entry.dev_name, sip_idx);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to query unused sip index\n");
        return -1;
    }

    ret = sip_table_ioctl(&uvs_worker->ioctl_ctx, &add_entry, TPSA_CMD_ADD_SIP);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add sip to ubcore and fail to add sip entrty to sip table\n");
        return -1;
    }

    TPSA_LOG_INFO("success to sip_idx %u to sip table\n", sip_idx);
    return 0;
}

int uvs_delete_sip(const char *tpf_name)
{
    int ret = 0;
    tpsa_worker_t *uvs_worker = NULL;
    sip_table_entry_t *sip_entry_list;
    uint32_t max_sip_cnt = 0;
    uint32_t i, j;

    if (tpf_name == NULL || strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    sip_entry_list = tpsa_get_sip_entry_list(&uvs_worker->table_ctx, (char *)tpf_name, &max_sip_cnt);
    if (sip_entry_list == NULL) {
        TPSA_LOG_ERR("cannot get sip list from ubcore\n");
        return -1;
    }
    for (i = 0; i < max_sip_cnt; i++) {
        ret = sip_table_ioctl(&uvs_worker->ioctl_ctx, &sip_entry_list[i], TPSA_CMD_DEL_SIP);
        if (ret != 0) {
            TPSA_LOG_ERR("cannot delete sip from ubcore\n");
            goto roll_back_sip;
        }
    }
    tpsa_free_sip_entry_list(sip_entry_list);
    TPSA_LOG_INFO("delete %s tpf_dev: sip successfully\n", tpf_name);
    return 0;

roll_back_sip:
    for (j = 0; j < i; j++) {
        (void)sip_table_ioctl(&uvs_worker->ioctl_ctx, &sip_entry_list[j], TPSA_CMD_ADD_SIP);
    }
    tpsa_free_sip_entry_list(sip_entry_list);
    return -1;
}

void uvs_free_sip_list(uvs_sip_info_t **sip, uint32_t cnt)
{
    if (sip == NULL || cnt == 0) {
        TPSA_LOG_ERR("sip info is NULL!\n");
        return;
    }

    for (uint32_t i = 0; i < cnt; ++i) {
        if (sip[i] != NULL) {
            free(sip[i]);
            sip[i] = NULL;
        }
    }
    free(sip);
    sip = NULL;

    TPSA_LOG_INFO("free sip info memory successfully\n");
    return;
}

uvs_sip_info_t **uvs_get_list_sip(uint32_t *cnt)
{
    uint32_t sip_idx;
    uint32_t i = 0;
    tpsa_worker_t *uvs_worker = NULL;
    uvs_sip_info_t **sip_info = NULL;
    int tpf_cnt = 0;
    char tpf_dev[UVS_MAX_DEV_NAME];
    uint32_t max_sip_cnt = 0;

    if (cnt == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return NULL;
    }

    uvs_tpf_t **tpf = uvs_list_tpf(&tpf_cnt);
    if (tpf == NULL) {
        return NULL;
    }
    (void)memcpy(tpf_dev, tpf[0]->name, UVS_MAX_DEV_NAME);
    uvs_free_tpf(tpf, (uint32_t)tpf_cnt);

    sip_table_entry_t *sip_entry_list = tpsa_get_sip_entry_list(&uvs_worker->table_ctx, tpf_dev, &max_sip_cnt);
    if (sip_entry_list == NULL) {
        TPSA_LOG_ERR("cannot get sip list from ubcore\n");
        return NULL;
    }
    *cnt = max_sip_cnt;

    sip_info = (uvs_sip_info_t **)calloc(1, *cnt * sizeof(uvs_sip_info_t *));
    if (sip_info == NULL) {
        tpsa_free_sip_entry_list(sip_entry_list);
        return NULL;
    }

    for (sip_idx = 0; sip_idx < max_sip_cnt; ++sip_idx) {
        sip_info[i] = (uvs_sip_info_t *)calloc(1, sizeof(uvs_sip_info_t));
        if (sip_info[i] == NULL) {
            uvs_free_sip_list(sip_info, *cnt);
            tpsa_free_sip_entry_list(sip_entry_list);
            return NULL;
        }
        (void)memcpy(sip_info[i]->tpf_name, sip_entry_list[sip_idx].dev_name, UVS_MAX_DEV_NAME);
        (void)memcpy(sip_info[i]->mac, sip_entry_list[sip_idx].addr.mac, ETH_ADDR_LEN);
        (void)memcpy(&sip_info[i]->sip, &sip_entry_list[sip_idx].addr.net_addr, sizeof(urma_eid_t));
        sip_info[i]->vlan = (uint16_t)sip_entry_list[sip_idx].addr.vlan;
        sip_info[i]->msk = sip_entry_list[sip_idx].prefix_len;
        sip_info[i]->port_cnt = sip_entry_list[sip_idx].port_cnt;
        sip_info[i]->port_id[0] = sip_entry_list[sip_idx].port_id[0];
        sip_info[i]->type = (uvs_net_addr_type_t)sip_entry_list[sip_idx].addr.type;
        i++;
        if (i == *cnt) {
            break;
        }
    }
    tpsa_free_sip_entry_list(sip_entry_list);
    TPSA_LOG_INFO("get sip info list successful\n");
    return sip_info;
}

int uvs_query_fe_idx(const char *tpf_name, const uvs_devid_t *devid, uint16_t *fe_idx)
{
    if (tpf_name == NULL || devid == NULL || fe_idx == NULL ||
        strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_WARN("Input invalid");
        return -1;
    }

    tpsa_cmd_query_fe_idx_t cfg;
    (void)memcpy(cfg.in.dev_name, tpf_name, strlen(tpf_name));
    cfg.in.dev_name[strlen(tpf_name)] = '\0';
    cfg.in.devid = *devid;

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        return -1;
    }

    int ret = uvs_ioctl_query_fe_idx(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        return ret;
    }

    *fe_idx = cfg.out.fe_idx;
    return 0;
}

int uvs_config_dscp_vl(const char* tpf_name, uint8_t *dscp, uint8_t *vl, uint8_t num)
{
    if (tpf_name == NULL || dscp == NULL || vl == NULL || num > URMA_MAX_DEV_NAME ||
        strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_WARN("Input invalid, num:%d", num);
        return -1;
    }

    tpsa_cmd_config_dscp_vl_t cfg;
    (void)memcpy(cfg.in.dev_name, tpf_name, strlen(tpf_name));
    cfg.in.dev_name[strlen(tpf_name)] = '\0';

    cfg.in.num = MIN(num, TPSA_MAX_DSCP_VL_NUM);
    for (uint32_t i = 0; i < cfg.in.num; i++) {
        cfg.in.dscp[i] = dscp[i];
        cfg.in.vl[i] = vl[i];
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        return -1;
    }
    return uvs_ioctl_config_dscp_vl(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
}

void uvs_free_tpf(uvs_tpf_t **tpfs, uint32_t cnt)
{
    if (tpfs == NULL || cnt == 0) {
        return;
    }

    for (uint32_t i = 0; i < cnt; i++) {
        if (tpfs[i] != NULL) {
            free(tpfs[i]);
        }
    }

    free(tpfs);
}

uvs_tpf_t **uvs_list_tpf(int *cnt)
{
    uint32_t cur_cnt = 0;
    tpf_dev_table_entry_t *cur = NULL;
    tpf_dev_table_entry_t *next = NULL;

    if (cnt == NULL) {
        TPSA_LOG_WARN("Input invalid, cnt must alloc memory");
        return NULL;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_WARN("Can not get uvs_worker ctx");
        *cnt = -1;
        return NULL;
    }

    tpf_dev_table_t *tpf_table = &uvs_worker->table_ctx.tpf_dev_table;
    (void)pthread_rwlock_rdlock(&tpf_table->rwlock);
    uint32_t tpf_cnt = ub_hmap_count(&tpf_table->hmap);
    if (tpf_cnt == 0) {
        *cnt = 0;
        (void)pthread_rwlock_unlock(&tpf_table->rwlock);
        return NULL;
    }

    uvs_tpf_t **tpf_list = (uvs_tpf_t **)calloc(1, tpf_cnt * sizeof(uvs_tpf_t *));
    if (tpf_list == NULL) {
        *cnt = -1;
        (void)pthread_rwlock_unlock(&tpf_table->rwlock);
        return NULL;
    }

    HMAP_FOR_EACH_SAFE(cur, next, node, &tpf_table->hmap) {
        tpf_list[cur_cnt] = (uvs_tpf_t *)calloc(1, sizeof(uvs_tpf_t));
        if (tpf_list[cur_cnt] == NULL) {
            goto ROLLBACK;
        }

        (void)memcpy(tpf_list[cur_cnt]->name, cur->key.dev_name, UVS_MAX_DEV_NAME);
        cur_cnt++;
    }

    (void)pthread_rwlock_unlock(&tpf_table->rwlock);
    *cnt = (int)cur_cnt;
    return tpf_list;

ROLLBACK:
    uvs_free_tpf(tpf_list, cur_cnt);
    *cnt = -1;
    (void)pthread_rwlock_unlock(&tpf_table->rwlock);
    return NULL;
}

user_ops_t get_user_ops_type(const char *user_ops)
{
    if (user_ops == NULL) {
        TPSA_LOG_ERR("user ops invalid");
        return USER_OPS_MAX;
    }

    if (strcmp(user_ops, "gaea") == 0) {
        return USER_OPS_GAEA;
    }

    return USER_OPS_MAX;
}

int uvs_register_user_ops(uvs_user_ops_t *user_ops)
{
    if (user_ops == NULL || user_ops->lookup_netaddr_by_ueid == NULL || user_ops->name == NULL) {
        TPSA_LOG_ERR("user ops invalid");
        return -1;
    }

    user_ops_t user_ops_type = get_user_ops_type(user_ops->name);
    uvs_ops_mutex_lock();
    uvs_user_ops_t *ops = get_uvs_user_ops(user_ops_type);
    if (ops == NULL) {
        uvs_ops_mutex_unlock();
        TPSA_LOG_ERR("user ops invalid");
        return -1;
    }

    ops->name = strdup(user_ops->name);
    ops->lookup_netaddr_by_ueid = user_ops->lookup_netaddr_by_ueid;
    if (ops->name == NULL) {
        uvs_ops_mutex_unlock();
        TPSA_LOG_ERR("fail to strdup user ops name");
        return -1;
    }
    uvs_ops_mutex_unlock();
    return 0;
}

void uvs_unregister_user_ops(uvs_user_ops_t *user_ops)
{
    if (user_ops == NULL || user_ops->name == NULL) {
        TPSA_LOG_ERR("user ops invalid");
        return;
    }

    user_ops_t user_ops_type = get_user_ops_type(user_ops->name);
    uvs_ops_mutex_lock();
    uvs_user_ops_t *ops = get_uvs_user_ops(user_ops_type);
    if (ops == NULL) {
        uvs_ops_mutex_unlock();
        TPSA_LOG_ERR("user ops invalid");
        return;
    }
    free((char *)ops->name);
    ops->name = NULL;
    ops->lookup_netaddr_by_ueid = NULL;
    uvs_ops_mutex_unlock();
}

int uvs_query_vport_statistic(const char* tpf_name, uvs_vport_info_key_t *vport, uvs_vport_statistic_t *st)
{
    if (tpf_name == NULL || strnlen(tpf_name, URMA_MAX_DEV_NAME) >= URMA_MAX_DEV_NAME ||
        vport == NULL || st == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }

    return uvs_query_vport_statistic_inner(tpf_name, vport, st);
}

int uvs_query_tpf_statistic(const char* tpf_name, uvs_tpf_statistic_t *st)
{
    if (tpf_name == NULL || strnlen(tpf_name, URMA_MAX_DEV_NAME) >= URMA_MAX_DEV_NAME ||
        st == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }

    return uvs_query_tpf_statistic_inner(tpf_name, st);
}