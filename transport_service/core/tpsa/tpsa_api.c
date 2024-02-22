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
#include "tpsa_worker.h"
#include "tpsa_ioctl.h"
#include "tpsa_types.h"

const char *g_tpsa_capability[TPSA_CAP_NUM] = {
    [TPSA_CAP_OOR] = "out of order receive",
    [TPSA_CAP_SR] = "selective retransmission",
    [TPSA_CAP_SPRAY] = "spray with src udp port",
    [TPSA_CAP_DCA] = "administrate dynamic connection"
};

static uvs_user_ops_t g_uvs_gaea_ops;

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
    }
    if (global_cfg_ctx->mask.bs.udp_range) {
        vport_entry->tp_cfg.udp_range = (uint8_t)global_cfg_ctx->udp_range;
    }
    if (global_cfg_ctx->mask.bs.udp_port_start) {
        vport_entry->tp_cfg.data_udp_start = global_cfg_ctx->udp_port_start;
        vport_entry->tp_cfg.ack_udp_start = global_cfg_ctx->udp_port_start;
    }
    if (global_cfg_ctx->mask.bs.hop_limit) {
        vport_entry->tp_cfg.hop_limit = global_cfg_ctx->hop_limit;
    }
}

static void uvs_fill_vport_entry(
    vport_table_entry_t *vport_entry, uvs_vport_info_t *info, tpsa_worker_t *worker, uint32_t max_ueid_cnt)
{
    (void)strcpy(vport_entry->key.dev_name, info->tpf_name);
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
    uvs_fill_vport_by_global(vport_entry, &worker->global_cfg_ctx);

    vport_entry->rc_cfg.rc_cnt = info->rc_cnt;
    vport_entry->rc_cfg.rc_depth = info->rc_depth;
    vport_entry->rc_cfg.slice = worker->global_cfg_ctx.slice;

    vport_entry->ueid_max_cnt = max_ueid_cnt;
    vport_entry->ueid[0].upi = info->upi;
    (void)memcpy(&vport_entry->ueid[0].eid, &info->eid.eid, sizeof(uvs_eid_t));
    vport_entry->ueid[0].is_valid = true;
    vport_entry->mask.value = 0xffffffffffffffff;
}

static void uvs_fill_vport_info(uvs_vport_info_t *info, vport_table_entry_t *vport_entry)
{
    (void)strcpy(info->tpf_name, vport_entry->key.dev_name);
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

    info->rc_cnt = vport_entry->rc_cfg.rc_cnt;
    info->rc_depth = vport_entry->rc_cfg.rc_depth;

    info->upi = vport_entry->ueid[0].upi;
    (void)memcpy(&info->eid.eid, &vport_entry->ueid[0].eid, sizeof(uvs_eid_t));
}

#define UVS_MOD_VPORT_INFO_WITH_MASK(vport_info, mod_vport_info, mask) \
    ((vport_info) = (mask) ? (mod_vport_info) : (vport_info))

static void uvs_modify_vport_info(vport_table_entry_t *entry, uvs_vport_info_t *mod_info)
{
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->max_jetty_cnt, mod_info->jetty_max_cnt, mod_info->mask.bs.jetty_max_cnt);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->max_jfr_cnt, mod_info->jfr_max_cnt, mod_info->mask.bs.jfr_max_cnt);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->rc_cfg.rc_cnt, mod_info->rc_cnt, mod_info->mask.bs.rc_cnt);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->rc_cfg.rc_depth, mod_info->rc_depth, mod_info->mask.bs.rc_depth);

    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.flow_label, mod_info->tp_info.flow_label, mod_info->tp_info.mask.bs.flow_label);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->tp_cfg.oor_cnt, mod_info->tp_info.oor_cnt, mod_info->tp_info.mask.bs.oor_cnt);
    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cnt, mod_info->tp_info.tp_cnt_per_tpg, mod_info->tp_info.mask.bs.tp_cnt_per_tpg);
    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.retry_num, mod_info->tp_info.retry_times, mod_info->tp_info.mask.bs.retry_times);
    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.retry_factor, mod_info->tp_info.retry_factor, mod_info->tp_info.mask.bs.retry_factor);
    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.ack_timeout, mod_info->tp_info.ack_timeout, mod_info->tp_info.mask.bs.ack_timeout);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->tp_cfg.dscp, mod_info->tp_info.dscp, mod_info->tp_info.mask.bs.dscp);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->ueid[0].upi, mod_info->upi, mod_info->mask.bs.upi);
    if (mod_info->mask.bs.eid != 0) {
        (void)memcpy(&entry->ueid[0].eid, &mod_info->eid.eid, sizeof(uvs_eid_t));
    }

    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.tp_mod_flag.bs.oor_en, mod_info->tp_info.flag.bs.oor_en, mod_info->tp_info.mask.bs.flag_oor_en);
    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.tp_mod_flag.bs.sr_en, mod_info->tp_info.flag.bs.sr_en, mod_info->tp_info.mask.bs.flag_sr_en);
    UVS_MOD_VPORT_INFO_WITH_MASK(
        entry->tp_cfg.tp_mod_flag.bs.cc_en, mod_info->tp_info.flag.bs.cc_en, mod_info->tp_info.mask.bs.flag_cc_en);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->tp_cfg.tp_mod_flag.bs.spray_en,
        mod_info->tp_info.flag.bs.spray_en,
        mod_info->tp_info.mask.bs.flag_spray_en);
    UVS_MOD_VPORT_INFO_WITH_MASK(entry->tp_cfg.tp_mod_flag.bs.dca_enable,
        mod_info->tp_info.flag.bs.dca_enable,
        mod_info->tp_info.mask.bs.flag_dca_enable);
}

static int uvs_get_dev_feature_ioctl(
    tpsa_worker_t *worker, char *dev_name, tpsa_device_feat_t *feat, uint32_t *max_ueid_cnt)
{
    tpsa_ioctl_cfg_t cfg;
    (void)memset(&cfg, 0, sizeof(tpsa_ioctl_cfg_t));
    int ret;

    cfg.cmd_type = TPSA_CMD_GET_DEV_FEATURE;
    (void)strcpy(cfg.cmd.get_dev_feature.in.dev_name, dev_name);

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

static inline bool uvs_check_config(tpsa_tp_mod_flag_t tp_flag)
{
    if (tp_flag.bs.oor_en || tp_flag.bs.sr_en || tp_flag.bs.spray_en || tp_flag.bs.dca_enable) {
        return true;
    }
    return false;
}

static int uvs_check_tp_flag_config(vport_table_entry_t *entry, tpsa_worker_t *worker, uint32_t *max_ueid_cnt)
{
    int ret;
    tpsa_device_feat_t feat;

    if (uvs_check_config(entry->tp_cfg.tp_mod_flag)) {
        ret = uvs_get_dev_feature_ioctl(worker, entry->key.dev_name, &feat, max_ueid_cnt);
        if (ret != 0) {
            TPSA_LOG_ERR("failed to get sr en\n");
            return -1;
        }
        ret = uvs_verify_local_device_capability(entry->tp_cfg.tp_mod_flag, feat);
        if (ret != 0) {
            return -1;
        }
    }
    return 0;
}

int uvs_add_vport(uvs_vport_info_t *info)
{
    int ret = 0;
    uint32_t max_ueid_cnt;
    vport_table_entry_t *entry = NULL;
    tpsa_worker_t *uvs_worker = NULL;

    if (info == NULL) {
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
    ret = uvs_check_tp_flag_config(entry, uvs_worker, &max_ueid_cnt);
    if (ret != 0) {
        free(entry);
        return -1;
    }
    uvs_fill_vport_entry(entry, info, uvs_worker, max_ueid_cnt);

    ret = vport_table_add(&uvs_worker->table_ctx.vport_table, entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to add vport entry!\n");
        free(entry);
        return -1;
    }

    ret = uvs_ioctl_cmd_set_vport_cfg(&uvs_worker->ioctl_ctx, entry, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("can not ioctl vport, dev: %s, fe_idx: %hu\n", entry->key.dev_name, entry->key.fe_idx);
        if (vport_table_remove(&uvs_worker->table_ctx.vport_table, &entry->key) != 0) {
            TPSA_LOG_ERR("failed to del vport, dev: %s, fe_idx: %hu\n", entry->key.dev_name, entry->key.fe_idx);
        }
        free(entry);
        return -1;
    }

    TPSA_LOG_INFO("add vport entry successfully!\n");
    free(entry);
    return 0;
}

int uvs_del_vport(const char *tpf_name, uint16_t fe_idx)
{
    int ret = 0;
    vport_key_t key = {0};
    tpsa_worker_t *uvs_worker = NULL;

    if (tpf_name == NULL) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    key.fe_idx = fe_idx;
    (void)strcpy(key.dev_name, tpf_name);
    uvs_worker = uvs_get_worker();

    ret = vport_table_remove(&uvs_worker->table_ctx.vport_table, &key);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to delete vport entry!\n");
        return -1;
    }

    TPSA_LOG_INFO("success delete vport entry!\n");
    return 0;
}

int uvs_show_vport(char *tpf_name, uint16_t fe_idx, uvs_vport_info_t *info)
{
    int ret = 0;
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_entry_t *vport_entry = NULL;
    vport_key_t key = {0};

    if (tpf_name == NULL || info == NULL) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    vport_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (vport_entry == NULL) {
        TPSA_LOG_ERR("Fail to alloc vport entry\n");
        return -1;
    }

    key.fe_idx = fe_idx;
    (void)strcpy(key.dev_name, tpf_name);
    uvs_worker = uvs_get_worker();

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
    if (info == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }

    int ret = 0;
    uint32_t max_ueid_cnt;
    vport_key_t key = {0};
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_entry_t *entry = NULL;
    vport_table_entry_t *vport_entry = NULL;

    key.fe_idx = info->fe_idx;
    (void)strcpy(key.dev_name, info->tpf_name);
    uvs_worker = uvs_get_worker();

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
        TPSA_LOG_ERR("the vport entry %s-%u does not exist\n", key.dev_name, key.fe_idx);
        goto free_memory;
    }

    *vport_entry = *entry;
    uvs_modify_vport_info(vport_entry, info);
    if (info->tp_info.mask.bs.flag_oor_en || info->tp_info.mask.bs.flag_sr_en || info->tp_info.mask.bs.flag_spray_en ||
        info->tp_info.mask.bs.flag_dca_enable) {
        ret = uvs_check_tp_flag_config(vport_entry, uvs_worker, &max_ueid_cnt);
        if (ret != 0) {
            goto free_memory;
        }
    }

    ret = vport_table_remove(&uvs_worker->table_ctx.vport_table, &key);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to add the vport entry %s-%u\n", key.dev_name, key.fe_idx);
        goto free_memory;
    }

    ret = vport_table_add(&uvs_worker->table_ctx.vport_table, vport_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to add the vport entry %s-%u\n", key.dev_name, key.fe_idx);
        goto free_memory;
    }

    ret = uvs_ioctl_cmd_set_vport_cfg(&uvs_worker->ioctl_ctx, entry, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("can not ioctl vport, dev: %s, fe_idx: %hu\n", entry->key.dev_name, entry->key.fe_idx);
        if (vport_table_remove(&uvs_worker->table_ctx.vport_table, &entry->key) != 0) {
            TPSA_LOG_ERR("failed to del vport, dev: %s, fe_idx: %hu\n", entry->key.dev_name, entry->key.fe_idx);
        }
        ret = vport_table_add(&uvs_worker->table_ctx.vport_table, entry);
        if (ret != 0) {
            TPSA_LOG_ERR("failed to add the vport entry %s-%u\n", entry->key.dev_name, entry->key.fe_idx);
        }
        goto free_memory;
    }

    TPSA_LOG_INFO("modify the vport entry %s-%u successfully\n", key.dev_name, key.fe_idx);

free_memory:
    free(entry);
    free(vport_entry);
    return ret;
}

static uint32_t uvs_discover_sip_info(sip_table_t *sip_table)
{
    uint32_t sip_idx;
    uint32_t cnt = 0;

    (void)pthread_rwlock_rdlock(&sip_table->rwlock);
    for (sip_idx = 0; sip_idx < TPSA_SIP_IDX_TABLE_SIZE; ++sip_idx) {
        if (sip_table->entries[sip_idx].used == false) {
            continue;
        }

        cnt++;
    }
    (void)pthread_rwlock_unlock(&sip_table->rwlock);

    return cnt;
}

int uvs_add_sip(uvs_sip_info_t *sip_info)
{
    int ret = 0;
    uint32_t sip_idx = 0;
    tpsa_worker_t *uvs_worker = NULL;
    sip_table_entry_t add_entry = {0};

    if (sip_info == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }
    uvs_worker = uvs_get_worker();

    (void)strcpy(add_entry.dev_name, sip_info->tpf_name);
    (void)memcpy(add_entry.addr.mac, sip_info->mac, ETH_ADDR_LEN);
    (void)memcpy(&add_entry.addr.eid, &sip_info->sip, sizeof(uvs_net_addr_t));
    add_entry.addr.vlan = sip_info->vlan;
    add_entry.prefix_len = sip_info->msk;
    add_entry.mtu = uvs_worker->global_cfg_ctx.mtu;

    add_entry.port_cnt = sip_info->port_cnt;
    add_entry.port_id[0] = sip_info->port_id[0];
    add_entry.addr.type = (tpsa_net_addr_type_t)sip_info->type;

    (void)pthread_rwlock_rdlock(&uvs_worker->table_ctx.sip_table.rwlock);
    while (sip_idx < TPSA_SIP_IDX_TABLE_SIZE && uvs_worker->table_ctx.sip_table.entries[sip_idx].used == true) {
        sip_idx++;
    }
    (void)pthread_rwlock_unlock(&uvs_worker->table_ctx.sip_table.rwlock);

    if (sip_idx == TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("failed to add sip entry to sip table\n");
        return -1;
    }

    ret = uvs_ioctl_op_sip_table(&uvs_worker->ioctl_ctx, &add_entry, TPSA_CMD_ADD_SIP);
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
    sip_table_entry_t *entry = NULL;
    uint32_t sip_idx;

    if (tpf_name == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    (void)pthread_rwlock_rdlock(&uvs_worker->table_ctx.sip_table.rwlock);
    for (sip_idx = 0; sip_idx < TPSA_SIP_IDX_TABLE_SIZE; ++sip_idx) {
        if (uvs_worker->table_ctx.sip_table.entries[sip_idx].used == false ||
            strcmp(uvs_worker->table_ctx.sip_table.entries[sip_idx].dev_name, tpf_name) != 0) {
            continue;
        }

        entry = sip_table_lookup(&uvs_worker->table_ctx.sip_table, sip_idx);
        TPSA_LOG_INFO(
            "find dev_name %s and sip_idx %u\n", uvs_worker->table_ctx.sip_table.entries[sip_idx].dev_name, sip_idx);
        break;
    }
    (void)pthread_rwlock_unlock(&uvs_worker->table_ctx.sip_table.rwlock);

    if (sip_idx >= TPSA_SIP_IDX_TABLE_SIZE) {
        TPSA_LOG_ERR("cannot find sip info: %s\n", tpf_name);
        return -1;
    }

    ret = uvs_ioctl_op_sip_table(&uvs_worker->ioctl_ctx, entry, TPSA_CMD_DEL_SIP);
    if (ret != 0) {
        TPSA_LOG_ERR("cannot delete sip from ubcore\n");
        return -1;
    }

    TPSA_LOG_INFO("delete sip %s successfully\n", tpf_name);
    return 0;
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

    if (cnt == NULL) {
        TPSA_LOG_ERR("Invalid parameter");
        return NULL;
    }

    uvs_worker = uvs_get_worker();
    *cnt = uvs_discover_sip_info(&uvs_worker->table_ctx.sip_table);
    if (*cnt == 0) {
        TPSA_LOG_ERR("can not find any sip info\n");
        return NULL;
    }

    sip_info = (uvs_sip_info_t **)calloc(1, *cnt * sizeof(uvs_sip_info_t *));
    if (sip_info == NULL) {
        return NULL;
    }

    (void)pthread_rwlock_rdlock(&uvs_worker->table_ctx.sip_table.rwlock);
    for (sip_idx = 0; sip_idx < TPSA_SIP_IDX_TABLE_SIZE; ++sip_idx) {
        if (uvs_worker->table_ctx.sip_table.entries[sip_idx].used == false) {
            continue;
        }

        sip_info[i] = (uvs_sip_info_t *)calloc(1, sizeof(uvs_sip_info_t));
        if (sip_info[i] == NULL) {
            (void)pthread_rwlock_unlock(&uvs_worker->table_ctx.sip_table.rwlock);
            uvs_free_sip_list(sip_info, *cnt);
            return NULL;
        }

        (void)strcpy(
            sip_info[i]->tpf_name, uvs_worker->table_ctx.sip_table.entries[sip_idx].dev_name);
        (void)memcpy(
            sip_info[i]->mac, uvs_worker->table_ctx.sip_table.entries[sip_idx].addr.mac, TPSA_MAC_BYTES);
        (void)memcpy(&sip_info[i]->sip,
            &uvs_worker->table_ctx.sip_table.entries[sip_idx].addr.eid,
            sizeof(urma_eid_t));
        sip_info[i]->vlan = (uint16_t)uvs_worker->table_ctx.sip_table.entries[sip_idx].addr.vlan;
        sip_info[i]->msk = uvs_worker->table_ctx.sip_table.entries[sip_idx].prefix_len;
        sip_info[i]->port_cnt = uvs_worker->table_ctx.sip_table.entries[sip_idx].port_cnt;
        sip_info[i]->port_id[0] = uvs_worker->table_ctx.sip_table.entries[sip_idx].port_id[0];
        sip_info[i]->type = (uvs_net_addr_type_t)uvs_worker->table_ctx.sip_table.entries[sip_idx].addr.type;
        i++;
        if (i == *cnt) {
            break;
        }
    }
    (void)pthread_rwlock_unlock(&uvs_worker->table_ctx.sip_table.rwlock);

    TPSA_LOG_INFO("get sip info list successful\n");
    return sip_info;
}

int uvs_query_fe_idx(const char *tpf_name, const uvs_devid_t *devid, uint16_t *fe_idx)
{
    if (tpf_name == NULL || devid == NULL || fe_idx == NULL) {
        TPSA_LOG_WARN("Input invalid");
        return -1;
    }

    tpsa_cmd_query_fe_idx_t cfg;
    (void)strcpy(cfg.in.dev_name, tpf_name);
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
    if (tpf_name == NULL || dscp == NULL || vl == NULL || num > URMA_MAX_DEV_NAME) {
        TPSA_LOG_WARN("Input invalid, num:%d", num);
        return -1;
    }
    tpsa_cmd_config_dscp_vl_t cfg;
    (void)strcpy(cfg.in.dev_name, tpf_name);

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

        (void)memcpy(tpf_list[cur_cnt]->name,
            cur->key.dev_name, UVS_MAX_DEV_NAME);
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
    switch (user_ops_type) {
        case USER_OPS_GAEA:
            g_uvs_gaea_ops.name = strdup(user_ops->name);
            g_uvs_gaea_ops.lookup_netaddr_by_ueid = user_ops->lookup_netaddr_by_ueid;
            if (g_uvs_gaea_ops.name == NULL || g_uvs_gaea_ops.lookup_netaddr_by_ueid == NULL) {
                return -1;
            }
            break;
        case USER_OPS_MAX:
        default:
            return -1;
    }
    return 0;
}

void uvs_unregister_user_ops(uvs_user_ops_t *user_ops)
{
    user_ops_t user_ops_type = get_user_ops_type(user_ops->name);
    switch (user_ops_type) {
        case USER_OPS_GAEA:
            free((char *)g_uvs_gaea_ops.name);
            g_uvs_gaea_ops.name = NULL;
            g_uvs_gaea_ops.lookup_netaddr_by_ueid = NULL;
            break;
        case USER_OPS_MAX:
        default:
            break;
    }
}

uvs_user_ops_t* get_uvs_user_ops(user_ops_t user_ops)
{
    switch (user_ops) {
        case USER_OPS_GAEA:
            return &g_uvs_gaea_ops;
        case USER_OPS_MAX:
        default:
            TPSA_LOG_ERR("user ops invalid");
            return NULL;
    }
}