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
#include "uvs_event.h"
#include "uvs_private_api.h"
#include "tpsa_worker.h"
#include "tpsa_ioctl.h"
#include "uvs_stats.h"
#include "tpsa_types.h"
#include "tpsa_table.h"
#include "uvs_lm.h"

#define UVS_DEFAULT_UM_EN 1
#define UVS_DEFAULT_FLAG_UM_EN 1
#define UVS_DEFAULT_CC_ALG (0x1 << 3) /* LDCP */
#define UVS_DEFAULT_VPORT_EID_IDX 0
#define UVS_DEFAULT_UEID_MAX_CNT 256
#define UVS_DEFAULT_MIG_LIST_MAX_DEPTH 64
#define UVS_DEFAULT_UPI_MIN 0X0
#define UVS_DEFAULT_UPI_MAX 0xFFFFFF

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

int uvs_register_event_cb(uvs_event_cb_t cb_func, void *cb_arg)
{
    if (cb_func == NULL || cb_arg == NULL) {
        TPSA_LOG_ERR("Failed to register event callback: invalid cb_func\n");
        return -1;
    }
    return uvs_event_set_cb(cb_func, cb_arg);
}

int uvs_unregister_event_cb(void)
{
    return uvs_event_set_cb(NULL, NULL);
}

static bool uvs_check_mtu_valid(uvs_mtu_t mtu)
{
    return (mtu == UVS_MTU_1024 || mtu == UVS_MTU_4096 || mtu == UVS_MTU_8192);
}

static bool uvs_check_udp_mask_valid(uvs_global_info_t *info)
{
    return info->mask.bs.udp_port_start && info->mask.bs.udp_port_end &&
        info->mask.bs.udp_range;
}

static bool uvs_check_udp_valid(uvs_global_info_t *info)
{
    if (info->udp_range == 0) {
        return false;
    }

    return (info->udp_port_end - info->udp_port_start) >= info->udp_range;
}

static int uvs_global_info_check_param_valid(uvs_global_info_t *info)
{
    if (info->mask.bs.mtu && !uvs_check_mtu_valid(info->mtu)) {
        TPSA_LOG_ERR("failed to check mtu and mtu is %u", (uint32_t)info->mtu);
        return -1;
    }
    if (uvs_check_udp_mask_valid(info) && !uvs_check_udp_valid(info)) {
        TPSA_LOG_ERR("failed to check udp mask:%u or udp_port_start:%u, "
            "udp_port_end:%u, udp_range:%u",
            info->mask.value, info->udp_port_start, info->udp_port_end, info->udp_range);
        return -1;
    }

    return 0;
}

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

    if (uvs_global_info_check_param_valid(info) != 0) {
        return -1;
    }

    tpsa_global_cfg_t *global_cfg_ctx = &uvs_worker->global_cfg_ctx;
    /* global_cfg->mask and local global mask is different */
    TPSA_LOG_INFO("uvs add global info mask:%u", info->mask.value);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, mtu);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, slice);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, suspend_period);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, suspend_cnt);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, sus2err_period);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, sus2err_cnt);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, hop_limit);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, udp_port_start);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, udp_port_end);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, udp_range);
    UVS_FILL_GLOBAL_CFG_WITH_MASK(info, global_cfg_ctx, tbl_input_done);

    if (info->mask.bs.sus2err_period) {
        uvs_convert_sus2err_period_to_clock_cycle(info->sus2err_period);
    }

    global_cfg_ctx->mask.bs.flag_um_en = UVS_DEFAULT_FLAG_UM_EN;
    global_cfg_ctx->flag.bs.um_en = info->mask.bs.flag_um_en == 0 ? (uint32_t)UVS_DEFAULT_UM_EN : info->flag.bs.um_en;

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
    info->suspend_period = uvs_worker->global_cfg_ctx.suspend_period;
    info->suspend_cnt = uvs_worker->global_cfg_ctx.suspend_cnt;
    info->sus2err_period = uvs_worker->global_cfg_ctx.sus2err_period;
    info->sus2err_cnt = uvs_worker->global_cfg_ctx.sus2err_cnt;
    info->tbl_input_done = uvs_worker->global_cfg_ctx.tbl_input_done;

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

static uint32_t uvs_get_cc_alg_union(uvs_cc_t *cc_list, uint8_t cc_cnt)
{
    uint32_t cc_alg = 0;
    for (uint32_t i = 0; i < cc_cnt; i++) {
        cc_alg |= 1 << cc_list[i];
    }
    return cc_alg;
}

static int uvs_vport_link_ueid_entry_to_vport(vport_table_t *vport_table,
    uvs_vport_info_t *info, vport_table_entry_t *parent_entry, vport_table_entry_t *port_entry)
{
    tpsa_ueid_cfg_t ueid = {0};
    (void)memcpy(&ueid.eid, &info->eid.eid, sizeof(urma_eid_t));
    ueid.upi = info->upi;
    ueid.eid_index = info->eid.eid_idx;

    if (vport_ueid_tbl_add_entry(parent_entry, &ueid, port_entry) != 0) {
        TPSA_LOG_ERR("failed to add ueid entry. port info: name %s, port_type %u, tpf_name %s, fe_idx %u,"
            "eid_idx %u, upi %u, eid " EID_FMT "\n",
            info->key.name, (uint32_t)port_entry->type, port_entry->key.tpf_name,
            port_entry->key.fe_idx, info->eid.eid_idx,
            ueid.upi, EID_ARGS(ueid.eid));
        return -EINVAL;
    }

    if (port_entry->type == UVS_PORT_TYPE_UBSUBPORT && ueid_table_add(vport_table, &port_entry->key,
        ueid.upi, ueid.eid, ueid.eid_index) != 0) {
        parent_entry->ueid[ueid.eid_index].entry = NULL;
        parent_entry->ueid[ueid.eid_index].is_valid = false;
        TPSA_LOG_ERR("failed to add ueid, dev_name:%s fe_idx:%d\n", port_entry->key.tpf_name,
                     port_entry->key.fe_idx);
        return -EINVAL;
    }
    TPSA_LOG_INFO("Suceess to add ueid entry. port info: name %s, port_type %u, tpf_name %s,"
            " fe_idx %u, eid_idx %u, upi %u, eid " EID_FMT "\n",
            port_entry->port_key.name, (uint32_t)port_entry->type, port_entry->key.tpf_name,
            port_entry->key.fe_idx, info->eid.eid_idx,
            info->upi, EID_ARGS(info->eid.eid));
    return 0;
}

static int uvs_del_ueid_entry_with_type_vport(vport_table_t *vport_table,
    vport_table_entry_t *parent_entry)
{
    if (vport_ueid_tbl_del_entry(parent_entry, UVS_DEFAULT_VPORT_EID_IDX) != 0) {
        TPSA_LOG_ERR("failed to del ueid entry. port name %s\n",
            parent_entry->port_key.name);
        return -EINVAL;
    }
    ueid_table_rmv(vport_table, &parent_entry->ueid[UVS_DEFAULT_VPORT_EID_IDX].eid,
        parent_entry->ueid[UVS_DEFAULT_VPORT_EID_IDX].upi);
    TPSA_LOG_INFO("success to del ueid entry. port name %s and type %u\n",
        parent_entry->port_key.name, (uint32_t)parent_entry->type);
    return 0;
}

static int uvs_vport_add_ueid_entry(vport_table_t *vport_table,
    vport_table_entry_t *vport_entry, uvs_vport_info_t *info)
{
    vport_table_entry_t *port_entry = NULL;
    port_entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (port_entry == NULL) {
        TPSA_LOG_ERR("failed to calloc port entry");
        return -1;
    }
    (void)memcpy(port_entry,
        vport_entry, sizeof(vport_table_entry_t));
    if (info->type == UVS_PORT_TYPE_UBPORT) {
        /* vport link to itself */
        (void)pthread_rwlock_wrlock(&vport_table->rwlock);
        if (uvs_vport_link_ueid_entry_to_vport(vport_table, info,
            vport_entry, port_entry) != 0) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            free(port_entry);
            return -1;
        }
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return 0;
    } else if (info->type == UVS_PORT_TYPE_UBSUBPORT) {
        /* find vport entry first then add subport pointer to vport's ueid list */
        vport_table_entry_t *parent_entry = NULL;
        uvs_vport_info_key_t key = {0};
        (void)memcpy(key.name, info->parent_name, UVS_MAX_VPORT_NAME);
        (void)pthread_rwlock_wrlock(&vport_table->rwlock);
        parent_entry = tpsa_vport_lookup_by_port_key_no_look(vport_table, &key);
        if (parent_entry == NULL) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            TPSA_LOG_ERR("failed to find parent entry");
            free(port_entry);
            return -1;
        }
        if (uvs_vport_link_ueid_entry_to_vport(vport_table, info,
            parent_entry, port_entry) != 0) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            free(port_entry);
            return -1;
        }
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return 0;
    }

    return 0;
}

static int uvs_vport_del_ueid_entry(vport_table_t *vport_table,
    vport_table_entry_t *vport_entry)
{
    uvs_vport_info_key_t port_key = {0};

    (void)memcpy(&port_key,
        &vport_entry->port_key, sizeof(uvs_vport_info_key_t));
    if (vport_entry->type == UVS_PORT_TYPE_UBPORT) {
        /* vport unlink from itself */
        if (uvs_del_ueid_entry_with_type_vport(vport_table, vport_entry) != 0) {
            TPSA_LOG_ERR("failed to del ueid entry linked with vport");
            return -1;
        }
    } else if (vport_entry->type == UVS_PORT_TYPE_UBSUBPORT) {
        if (tpsa_vport_find_del_port_key(vport_table, &port_key) != 0) {
            TPSA_LOG_ERR("failed to del ueid entry linked with subport");
            return -1;
        }
    } else {
        TPSA_LOG_ERR("unexpected type %u", (uint32_t)vport_entry->type);
    }
    return 0;
}

static void uvs_fill_vport_entry_subport(vport_table_entry_t *port_entry,
                                         vport_table_entry_t *parent_entry)
{
     /* these fields need to be filled by vport's value */
    port_entry->key.fe_idx = parent_entry->key.fe_idx;
    port_entry->sip_idx = parent_entry->sip_idx;
    port_entry->virtualization = parent_entry->virtualization;
    port_entry->max_jetty_cnt = parent_entry->max_jetty_cnt;
    port_entry->min_jetty_cnt = parent_entry->min_jetty_cnt;
    port_entry->max_jfr_cnt = parent_entry->max_jfr_cnt;
    port_entry->min_jfr_cnt = parent_entry->min_jfr_cnt;
    port_entry->rc_cfg.rc_cnt = parent_entry->rc_cfg.rc_cnt;
    port_entry->rc_cfg.rc_depth = parent_entry->rc_cfg.rc_depth;
}

static void uvs_fill_vport_entry_vport(vport_table_entry_t *port_entry,
                                       uvs_vport_info_t *info)
{
    /* vport can get these fields directly from vport info */
    port_entry->key.fe_idx = info->fe_idx;
    port_entry->sip_idx = info->sip_idx;
    port_entry->virtualization = info->virtualization;
    port_entry->max_jetty_cnt = info->jetty_max_cnt;
    port_entry->min_jetty_cnt = info->jetty_min_cnt;
    port_entry->max_jfr_cnt = info->jfr_max_cnt;
    port_entry->min_jfr_cnt = info->jfr_min_cnt;
    port_entry->rc_cfg.rc_cnt = info->rct_cnt;
    port_entry->rc_cfg.rc_depth = info->rct_depth;
}

static int uvs_fill_vport_entry(vport_table_entry_t *port_entry, uvs_vport_info_t *info,
                                tpsa_worker_t *worker)
{
    bool isSubport = info->type == UVS_PORT_TYPE_UBSUBPORT;
    vport_table_entry_t *parent_entry = NULL;
    /* subport's value need to given by vport's value */
    if (isSubport) {
        /* find vport entry */
        uvs_vport_info_key_t key = {0};
        vport_table_t *vport_table = &worker->table_ctx.vport_table;
        (void)memcpy(key.name, info->parent_name, UVS_MAX_VPORT_NAME);
        (void)pthread_rwlock_rdlock(&vport_table->rwlock);
        parent_entry = tpsa_vport_lookup_by_port_key_no_look(vport_table, &key);
        if (parent_entry == NULL) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            TPSA_LOG_ERR("failed to find parent entry");
            return -1;
        }
        uvs_fill_vport_entry_subport(port_entry, parent_entry);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
    } else {
        uvs_fill_vport_entry_vport(port_entry, info);
    }

    (void)memcpy(port_entry->key.tpf_name, info->tpf_name, UVS_MAX_DEV_NAME);
    (void)memcpy(&port_entry->port_key,
        &info->key, sizeof(uvs_vport_info_key_t));
    port_entry->tp_cnt = info->tp_info.tp_cnt_per_tpg;
    port_entry->pattern = info->flag.bs.pattern;

    port_entry->tp_cfg.flow_label = info->tp_info.flow_label;
    port_entry->tp_cfg.oor_cnt = info->tp_info.oor_cnt;
    port_entry->tp_cfg.retry_num = info->tp_info.retry_times;
    port_entry->tp_cfg.retry_factor = info->tp_info.retry_factor;
    port_entry->tp_cfg.ack_timeout = info->tp_info.ack_timeout;
    port_entry->tp_cfg.dscp = info->tp_info.dscp;

    port_entry->tp_cfg.tp_mod_flag.bs.oor_en = info->tp_info.flag.bs.oor_en;
    port_entry->tp_cfg.tp_mod_flag.bs.sr_en = info->tp_info.flag.bs.sr_en;
    port_entry->tp_cfg.tp_mod_flag.bs.spray_en = info->tp_info.flag.bs.spray_en;
    port_entry->tp_cfg.tp_mod_flag.bs.dca_enable = info->tp_info.flag.bs.dca_enable;
    port_entry->tp_cfg.tp_mod_flag.bs.um_en = info->flag.bs.um_en;
    port_entry->tp_cfg.tp_mod_flag.bs.share_mode = info->flag.bs.share_mode;
    port_entry->mask.bs.flag_um_en = info->mask.bs.flag_um_en;

    /* cc related param */
    port_entry->tp_cfg.tp_mod_flag.bs.cc_en = info->tp_info.flag.bs.cc_en;

    port_entry->tp_cfg.set_cc_priority = true;
    port_entry->tp_cfg.cc_priority = info->tp_info.cc_pri;

    port_entry->tp_cfg.set_cc_alg = true;
    port_entry->tp_cfg.tp_mod_flag.bs.cc_alg =
        (info->tp_info.mask.bs.cc_list & info->tp_info.mask.bs.cc_cnt) == 1 ?
        uvs_get_cc_alg_union(info->tp_info.cc_list, info->tp_info.cc_cnt) : UVS_DEFAULT_CC_ALG;

    port_entry->type = info->type;

    tpsa_global_cfg_t *global_cfg_ctx = &worker->global_cfg_ctx;
     /* if the user doesn't config um_en in vport table, use global table's value */
    if (!info->mask.bs.flag_um_en) {
        port_entry->tp_cfg.tp_mod_flag.bs.um_en = global_cfg_ctx->flag.bs.um_en;
        port_entry->mask.bs.flag_um_en = global_cfg_ctx->mask.bs.flag_um_en;
        TPSA_LOG_INFO("config um_en in vport table as %u", global_cfg_ctx->flag.bs.um_en);
    }

    uvs_fill_vport_by_global(port_entry, global_cfg_ctx);

    /*
        subport only has its only ueid info, vport will manage more ueid info
            including itself and other subports
    */
    if (info->type == UVS_PORT_TYPE_UBSUBPORT) {
        port_entry->ueid[0].upi = info->upi;
        (void)memcpy(&port_entry->ueid[0].eid, &info->eid.eid, sizeof(uvs_eid_t));
        port_entry->ueid[0].is_valid = true;
    }
    uvs_fill_vport_mask(&port_entry->mask, info);

    return 0;
}

static void uvs_fill_vport_info(uvs_vport_info_t *info, vport_table_entry_t *vport_entry)
{
    (void)memcpy(info->key.name,
        vport_entry->port_key.name, UVS_MAX_VPORT_NAME);

    info->fe_idx = vport_entry->key.fe_idx;

    (void)memcpy(info->tpf_name,
        vport_entry->key.tpf_name, UVS_MAX_VPORT_NAME);

    info->sip_idx = vport_entry->sip_idx;
    info->tp_info.tp_cnt_per_tpg = vport_entry->tp_cnt;
    info->flag.bs.share_mode = vport_entry->tp_cfg.tp_mod_flag.bs.share_mode;
    info->flag.bs.pattern = vport_entry->pattern;
    info->flag.bs.um_en = vport_entry->tp_cfg.tp_mod_flag.bs.um_en;
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

    /* both vport and subport save their own ueid with idx 0 */
    info->upi = vport_entry->ueid[0].upi;
    (void)memcpy(&info->eid.eid, &vport_entry->ueid[0].eid, sizeof(uvs_eid_t));
    info->type = vport_entry->type;
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

static int uvs_check_duplicate_port_entry_with_name(vport_table_t *vport_table,
    uvs_vport_info_key_t *port_key)
{
    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    if (tpsa_vport_lookup_by_port_key_no_look(vport_table, port_key) == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_INFO("No existed vport table found so continue to add port!\n");
        return 0;
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return -1;
}

static int uvs_check_port_eid_idx(uvs_vport_info_t *info)
{
    uint32_t eid_idx = info->eid.eid_idx;
    if (info->type == UVS_PORT_TYPE_UBPORT && eid_idx != UVS_DEFAULT_VPORT_EID_IDX) {
        TPSA_LOG_ERR("failed to check eid_idx with vport\n");
        return -1;
    } else if (info->type == UVS_PORT_TYPE_UBSUBPORT && eid_idx == UVS_DEFAULT_VPORT_EID_IDX) {
        TPSA_LOG_ERR("failed to check eid_idx with subport\n");
        return -1;
    }
    if (eid_idx >= UVS_DEFAULT_UEID_MAX_CNT) {
        TPSA_LOG_ERR("failed to check eid_idx with eid_idx %u larger than 255\n", eid_idx);
        return -1;
    }
    return 0;
}

static int uvs_check_upi_validation(uint32_t upi)
{
    if (upi >= UVS_DEFAULT_UPI_MIN && upi <= UVS_DEFAULT_UPI_MAX) {
        return 0;
    }
    TPSA_LOG_ERR("failed to check upi %u, valid range [0X 00 00 00, 0X FF FF FF]", upi);
    return -1;
}

int uvs_add_vport(uvs_vport_info_t *info)
{
    int ret = 0;
    uint32_t max_ueid_cnt = 0;
    tpsa_device_feat_t feat;
    vport_table_entry_t *entry = NULL;
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_t *vport_table = NULL;

    if (info == NULL || strnlen(info->tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME ||
        strnlen(info->parent_name, UVS_MAX_VPORT_NAME) >= UVS_MAX_VPORT_NAME ||
        strnlen(info->key.name, UVS_MAX_VPORT_NAME) >= UVS_MAX_VPORT_NAME) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    if ((uvs_check_port_eid_idx(info) != 0) || (uvs_check_upi_validation(info->upi) != 0)) {
        TPSA_LOG_ERR("failed to pass input param validation");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }
    vport_table = &uvs_worker->table_ctx.vport_table;

    if (uvs_check_duplicate_port_entry_with_name(vport_table, &info->key) != 0) {
        TPSA_LOG_ERR("failed to add port because it's already existed by name %s", info->key.name);
        return -1;
    }

    entry = (vport_table_entry_t *)calloc(1, sizeof(vport_table_entry_t));
    if (entry == NULL) {
        TPSA_LOG_ERR("can not alloc vport entry memory\n");
        return -1;
    }

    if (uvs_fill_vport_entry(entry, info, uvs_worker) != 0) {
        TPSA_LOG_ERR("fail to fill port entry\n");
        free(entry);
        return -1;
    }

    if (info->type == UVS_PORT_TYPE_UBPORT) {
        TPSA_LOG_INFO("Detect vport type\n");
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
    }

    if (uvs_vport_add_ueid_entry(vport_table, entry, info) != 0) {
        TPSA_LOG_ERR("failed to add ueid entry to vport table\n");
        free(entry);
        return -1;
    }

    if (info->type == UVS_PORT_TYPE_UBSUBPORT) {
        uvs_add_vport_statistic_config(info); // subport and vport key is same, add use cnt
        TPSA_LOG_INFO("Detect now is adding subport, no need to add to vport table\n");
        free(entry);
        return 0;
    }

    ret = vport_table_add(vport_table, entry);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to add vport entry!\n");
        if (entry->ueid[info->eid.eid_idx].entry != NULL) {
            free(entry->ueid[info->eid.eid_idx].entry);
            entry->ueid[info->eid.eid_idx].entry = NULL;
        }
        free(entry);
        return -1;
    }

    ret = uvs_ioctl_cmd_set_vport_cfg(&uvs_worker->ioctl_ctx, entry, &uvs_worker->global_cfg_ctx);
    if (ret != 0) {
        TPSA_LOG_ERR("can not ioctl vport, dev: %s, fe_idx: %hu\n", entry->key.tpf_name, entry->key.fe_idx);
        if (vport_table_remove(vport_table, &entry->key) != 0) {
            TPSA_LOG_ERR("failed to del vport, dev: %s, fe_idx: %hu\n", entry->key.tpf_name, entry->key.fe_idx);
        }
        free(entry);
        return -1;
    }

    uvs_add_vport_statistic_config(info);
    TPSA_LOG_INFO("add vport entry successfully!\n");
    free(entry);
    return 0;
}

int uvs_del_vport(uvs_vport_info_key_t *key)
{
    int ret = 0;
    uvs_vport_info_key_t port_key = {0};
    tpsa_worker_t *uvs_worker = NULL;
    sem_t sem;

    if (key == NULL || strnlen(key->name, UVS_MAX_VPORT_NAME) == UVS_MAX_VPORT_NAME) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    (void)memcpy(port_key.name, key->name, UVS_MAX_VPORT_NAME);
    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    vport_table_entry_t *port_entry = NULL;
    vport_table_t *vport_table = &uvs_worker->table_ctx.vport_table;
    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    port_entry = tpsa_vport_lookup_by_port_key_no_look(vport_table, &port_key);
    if (port_entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("failed to find port entry by name %s!\n", key->name);
        return -1;
    }

    vport_key_t vport_key = {0};
    (void)memcpy(vport_key.tpf_name,
        port_entry->key.tpf_name, sizeof(char) * UVS_MAX_DEV_NAME);
    vport_key.fe_idx = port_entry->key.fe_idx;
    if (port_entry->type == UVS_PORT_TYPE_UBPORT) {
        // check if all subports are deleted, then del the vport entry
        if (tpsa_vport_del_check(port_entry) != 0) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            return -1;
        }

        if (uvs_vport_del_ueid_entry(&uvs_worker->table_ctx.vport_table, port_entry) != 0) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            return -1;
        }
        (void)pthread_rwlock_unlock(&vport_table->rwlock);

        (void)sem_init(&sem, 0, 0);
        ret = vport_set_deleting(&uvs_worker->table_ctx.vport_table, &vport_key, &sem);
        if (ret != 0) {
            (void)sem_destroy(&sem);
            TPSA_LOG_ERR("can not del vport by key dev_name:%s, fe_idx %hu\n",
                vport_key.tpf_name, vport_key.fe_idx);
            return -1;
        }

        (void)uvs_ioctl_cmd_clear_vport_cfg(&uvs_worker->ioctl_ctx, &vport_key);
        (void)sem_wait(&sem);
        (void)sem_destroy(&sem);
        // sub use cnt, if use cnt is 0, delete node
        uvs_del_vport_statistic_config(vport_key.tpf_name, &vport_key);
    } else if (port_entry->type == UVS_PORT_TYPE_UBSUBPORT) {
        if (uvs_vport_del_ueid_entry(&uvs_worker->table_ctx.vport_table, port_entry) != 0) {
            (void)pthread_rwlock_unlock(&vport_table->rwlock);
            return -1;
        }
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        uvs_del_vport_statistic_config(vport_key.tpf_name, &vport_key);
    } else {
        TPSA_LOG_ERR("Unexpected type %u\n", (uint32_t)port_entry->type);
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        return -1;
    }

    TPSA_LOG_INFO("success delete port entry with name %s!\n", key->name);
    return 0;
}

int uvs_show_vport(uvs_vport_info_key_t *key, uvs_vport_info_t *info)
{
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_entry_t *vport_entry = NULL;

    if (key == NULL || strnlen(key->name, UVS_MAX_VPORT_NAME) == UVS_MAX_VPORT_NAME ||
        info == NULL) {
        TPSA_LOG_ERR("Invalid parameter!\n");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    vport_table_t *vport_table = &uvs_worker->table_ctx.vport_table;
    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    vport_entry = tpsa_vport_lookup_by_port_key_no_look(vport_table, key);
    if (vport_entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_ERR("failed to show vport info!\n");
        return -1;
    }
    uvs_fill_vport_info(info, vport_entry);
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    TPSA_LOG_INFO("success to show port entry and entry name is %s!\n", info->key.name);
    return 0;
}

int uvs_modify_vport(uvs_vport_info_t *info)
{
    int ret;

    if (info == NULL || strnlen(info->tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid parameter");
        return -1;
    }

    ret = uvs_del_vport(&info->key);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to del old port");
        return ret;
    }

    ret = uvs_add_vport(info);
    if (ret != 0) {
        TPSA_LOG_ERR("failed to add new port");
        return ret;
    }

    TPSA_LOG_INFO("modify the vport entry %s-%u, key name %s and eid_idx successfully\n",
        info->tpf_name, info->fe_idx, info->key.name);
    return 0;
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

    (void)memcpy(add_entry.dev_name, sip_info->tpf_name, UVS_MAX_DEV_NAME);
    (void)memcpy(add_entry.addr.mac, sip_info->mac, ETH_ADDR_LEN);
    (void)memcpy(&add_entry.addr.net_addr, &sip_info->sip, sizeof(uvs_net_addr_t));
    add_entry.addr.vlan = sip_info->vlan;
    add_entry.addr.prefix_len = sip_info->msk;
    /* cloud scenario, mtu's value is given by global mtu after negotiation */
    add_entry.mtu = (uvs_mtu_t)0;

    add_entry.port_cnt = sip_info->port_cnt;
    add_entry.port_id[0] = sip_info->port_id[0];
    add_entry.addr.type = sip_info->type;

    ret = tpsa_sip_lookup_by_entry(&uvs_worker->table_ctx, add_entry.dev_name, &add_entry, sip_idx);
    if (ret != 0) {
        if (ret == EEXIST) {
            TPSA_LOG_INFO("sip already exist, sip_index is %d\n", *sip_idx);
            return 0;
        }

        TPSA_LOG_WARN("failed to lookup sip by entry, tpf table not ready\n");
        return -1;
    }

    TPSA_LOG_INFO("sip not exist, uvs may not ready or sip index never add, try ioctl\n.");
    ret = sip_table_add_ioctl(&uvs_worker->ioctl_ctx, &add_entry, sip_idx);
    if (ret != 0) {
        if (ret == EEXIST) {
            TPSA_LOG_INFO("sip already exist, sip_indx is %d\n", *sip_idx);
            return 0;
        }

        TPSA_LOG_ERR("can not add sip to ubcore and fail to add sip entrty to sip table\n");
        return -1;
    }

    TPSA_LOG_INFO("success add to sip_idx %u to sip table\n", *sip_idx);
    return 0;
}

int uvs_delete_sip(const char *tpf_name)
{
    int ret = 0;
    tpsa_worker_t *uvs_worker = NULL;
    sip_table_entry_t *sip_entry_list;
    uint32_t max_sip_cnt = 0;
    uint32_t i, j;
    uint32_t sip_idx;

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
        ret = sip_table_del_ioctl(&uvs_worker->ioctl_ctx, &sip_entry_list[i]);
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
        (void)sip_table_add_ioctl(&uvs_worker->ioctl_ctx, &sip_entry_list[j], &sip_idx);
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
        sip_info[i]->msk = sip_entry_list[sip_idx].addr.prefix_len;
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
    if (tpf_name == NULL || dscp == NULL || vl == NULL || num > TPSA_MAX_DSCP_VL_NUM ||
        strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME) {
        TPSA_LOG_WARN("Input invalid, num:%d", num);
        return -1;
    }

    tpsa_cmd_config_dscp_vl_t cfg = {0};
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.num = num;
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

int uvs_query_dscp_vl(const char* tpf_name, uint8_t *dscp, uint8_t num, uint8_t *vl)
{
    if (tpf_name == NULL || dscp == NULL || vl == NULL || num > TPSA_MAX_DSCP_VL_NUM ||
        strnlen(tpf_name, URMA_MAX_DEV_NAME) == URMA_MAX_DEV_NAME) {
        TPSA_LOG_WARN("Input invalid, num:%d", num);
        return -1;
    }
    tpsa_cmd_query_dscp_vl_t cfg = {0};
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.num = num;
    for (uint32_t i = 0; i < cfg.in.num; i++) {
        cfg.in.dscp[i] = dscp[i];
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        return -1;
    }

    if (uvs_ioctl_query_dscp_vl(uvs_worker->ioctl_ctx.ubcore_fd, &cfg) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < cfg.in.num; i++) {
        vl[i] = cfg.out.vl[i];
    }
    return 0;
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
        (void)memcpy(tpf_list[cur_cnt]->netdev_name, cur->netdev_name, UVS_MAX_DEV_NAME);
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
    if (user_ops == NULL || user_ops->lookup_netaddr_by_ueid == NULL || user_ops->name == NULL ||
        strnlen(user_ops->name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
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
    vport_table_entry_t *entry = NULL;
    tpsa_worker_t *uvs_worker = NULL;
    vport_table_t *vport_table = NULL;
    vport_key_t key = { 0 };

    if (tpf_name == NULL || strnlen(tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME ||
        vport == NULL || strnlen(vport->name, UVS_MAX_VPORT_NAME) >= UVS_MAX_VPORT_NAME || st == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }
    vport_table = &uvs_worker->table_ctx.vport_table;

    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    entry = vport_table_lookup_by_info_key(vport_table, vport);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&vport_table->rwlock);
        TPSA_LOG_INFO("No existed vport table found!\n");
        return -1;
    }
    key = entry->key;
    (void)pthread_rwlock_unlock(&vport_table->rwlock);

    return uvs_query_vport_statistic_inner(&key, st);
}

int uvs_query_tpf_statistic(const char* tpf_name, uvs_tpf_statistic_t *st)
{
    if (tpf_name == NULL || strnlen(tpf_name, UVS_MAX_DEV_NAME) == UVS_MAX_DEV_NAME ||
        st == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }

    return uvs_query_tpf_statistic_inner(tpf_name, st);
}

int uvs_delete_dip(uvs_ueid_t *ueid)
{
    if (ueid == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }
    return 0;
}

int uvs_update_dip(uvs_ueid_t *ueid, uvs_net_addr_info_t *old_dip, uvs_net_addr_info_t *new_dip)
{
    tpsa_worker_t *uvs_worker = NULL;
    vport_key_t vport_key = {0};
    uint32_t eid_index;
    int ret = 0;

    if (ueid == NULL || old_dip == NULL || new_dip == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    dip_table_key_t update_key = {0};
    (void)memcpy(&update_key.deid, &ueid->eid, UVS_EID_SIZE);
    update_key.upi = ueid->upi;

    // if we cannot find vport by this ueid, then we do nothing of this dip update
    ret = vport_table_lookup_by_ueid_return_key(&uvs_worker->table_ctx.vport_table,
        update_key.upi, &update_key.deid, &vport_key, &eid_index);
    if (ret != 0) {
        TPSA_LOG_INFO("Can not find vport by eid: " EID_FMT " upi: %u, drop this dip change\n",
            EID_ARGS(update_key.deid), update_key.upi);
        return 0;
    }
    (void)pthread_rwlock_wrlock(&uvs_worker->table_ctx.dip_table.rwlock);
    ret = dip_table_add_update_list(&uvs_worker->table_ctx.dip_table, &update_key, old_dip, new_dip);
    (void)pthread_rwlock_unlock(&uvs_worker->table_ctx.dip_table.rwlock);
    return ret;
}

int uvs_add_migration_task(uvs_ueid_t *dueid, uvs_net_addr_t *dip)
{
    if (dueid == NULL || dip == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }
    int ret;
    uint32_t eid_idx;
    tpsa_worker_t *ctx = NULL;
    live_migrate_table_t *live_migrate_table = NULL;
    live_migrate_table_key_t key = {0};
    live_migrate_table_entry_t entry = {0};

    ctx = uvs_get_worker();
    if (ctx == NULL) {
        TPSA_LOG_ERR("get_tpsa_daemon_ctx failed\n");
        return -1;
    }

    if (vport_table_lookup_by_ueid_return_key(&ctx->table_ctx.vport_table, dueid->upi, (urma_eid_t *)&dueid->eid, &key,
        &eid_idx) != 0) {
        TPSA_LOG_INFO("upi %u,eid_idx is %u,eid:" EID_FMT "\n", dueid->upi, eid_idx, EID_ARGS(dueid->eid));
        return -1;
    }

    (void)memcpy(&entry.uvs_ip, dip, TPSA_EID_SIZE);
    live_migrate_table = &ctx->table_ctx.live_migrate_table;

    ret = live_migrate_table_add(live_migrate_table, &key, &entry);
    if (ret != 0) {
        TPSA_LOG_ERR("can not add live migrate by key fe_idx %hu\n", key.fe_idx);
    }

    return ret;
}

static int tpsa_fill_mig_entry_by_vport_key(vport_table_t *vport_table, vport_key_t *key,
    uvs_mig_entry_list_t *mig_list, tpsa_fe_stats_t *stats, uint32_t cnt)
{
    int idx = 0;
    (void)pthread_rwlock_wrlock(&vport_table->rwlock);
    for (uint32_t i = 0; i < cnt; i++) {
        vport_table_entry_t *vport_entry = vport_table_lookup(vport_table, &key[i]);
        if (vport_entry == NULL) {
            continue;
        }
        uint64_t hits = stats[i].tx_pkt + stats[i].rx_pkt;
        for (uint32_t j = 0; j < vport_entry->ueid_max_cnt; j++) {
            if (vport_entry->ueid[i].used == false) {
                continue;
            }
            if (idx > UVS_DEFAULT_MIG_LIST_MAX_DEPTH) {
                (void)pthread_rwlock_unlock(&vport_table->rwlock);
                TPSA_LOG_ERR("ueid count exceed limit(64)\n");
                return -1;
            }
            mig_list[idx]->upi = vport_entry->ueid[j].upi;
            (void)memcpy(&mig_list[idx]->eid.eid, &vport_entry->ueid[j].eid, sizeof(uvs_eid_t));
            mig_list[idx]->hits = hits;
            idx++;
        }
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
    return idx;
}
int uvs_list_migration_task(uvs_mig_entry_list_t *mig_list, uint32_t *cnt)
{
    if (mig_list == NULL || cnt == NULL) {
        TPSA_LOG_ERR("Input invalid");
        return -1;
    }
    *cnt = 0;
    int ret = 0;
    uint32_t key_cnt;
    live_migrate_table_key_t *live_migrate_key = NULL;
    tpsa_worker_t *uvs_worker = NULL;
    tpsa_fe_stats_t *stats = NULL;

    uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx");
        return -1;
    }

    key_cnt = live_migrate_table_return_key(&uvs_worker->table_ctx.live_migrate_table, &live_migrate_key);
    if (key_cnt <= 0) {
        return key_cnt;
    }

    sip_table_entry_t sip_entry = {0};
    ret = find_sip_by_vport_key(&uvs_worker->table_ctx.vport_table, &(live_migrate_key[0]),
        &uvs_worker->table_ctx.tpf_dev_table, &sip_entry);
    if (ret != 0) {
        goto free_key;
    }

    stats = (tpsa_fe_stats_t *)calloc(sizeof(tpsa_fe_stats_t), key_cnt);
    if (stats == NULL) {
        TPSA_LOG_ERR("Failed to alloc tpsa_fe_stats.\n");
        ret = -ENOMEM;
        goto free_key;
    }

    ret = tpsa_ioctl_cmd_list_migrate_entry(&uvs_worker->ioctl_ctx, key_cnt, live_migrate_key, stats,
        &sip_entry.addr.net_addr);
    if (ret != 0) {
        goto free_stats;
    }

    *cnt = tpsa_fill_mig_entry_by_vport_key(&uvs_worker->table_ctx.vport_table, live_migrate_key, mig_list, stats,
        key_cnt);
    if (*cnt < 0) {
        ret = -1;
        goto free_stats;
    }
    ret = 0;

free_stats:
    free(stats);
free_key:
    free(live_migrate_key);
    return ret;
}

static void uvs_fill_stats_val(uvs_cmd_dfx_query_stats_t cfg, uvs_stats_val_t *val)
{
    val->tx_pkt = cfg.out.tx_pkt;
    val->rx_pkt = cfg.out.rx_pkt;
    val->tx_bytes = cfg.out.tx_bytes;
    val->rx_bytes = cfg.out.rx_bytes;
    val->tx_pkt_err = cfg.out.tx_pkt_err;
    val->rx_pkt_err = cfg.out.rx_pkt_err;

    val->tx_timeout_cnt = cfg.out.tx_timeout_cnt;
    val->rx_ce_pkt = cfg.out.rx_ce_pkt;
}

int uvs_query_stats(const char *tpf_name, uvs_stats_key_t *key, uvs_stats_val_t *val)
{
    int ret;

    if (tpf_name == NULL || key == NULL || val == NULL) {
        TPSA_LOG_ERR("Input invalid, null pointer");
        return -1;
    }

    if (key->type != UVS_STATS_VTP && key->type != UVS_STATS_TP &&
        key->type != UVS_STATS_TPG && key->type != UVS_STATS_DEV) {
        TPSA_LOG_ERR("Type %d not supported yet", key->type);
        return -1;
    }

    if (strnlen(tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid tpf_name");
        return -1;
    }

    uvs_cmd_dfx_query_stats_t cfg = {0};
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.type = key->type;
    cfg.in.id = key->id;
    cfg.in.ext = key->ext;

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        return -1;
    }

    ret = uvs_ioctl_dfx_query_stats(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("dfx query stats ioctl failed, key type:%u src:%lu", cfg.in.type, cfg.in.id);
        return ret;
    }

    val->key = *key;
    uvs_fill_stats_val(cfg, val);

    return ret;
}

static void uvs_fill_query_res_vtp(uvs_res_vtp_ioctl_val_t *vtp_res, uint32_t tp_mode, uvs_res_vtp_val_t *vtp_val)
{
    vtp_val->vtpn = vtp_res->vtpn;
    vtp_val->seid = vtp_res->local_eid;
    vtp_val->sjetty_id = vtp_res->local_jetty;
    vtp_val->deid = vtp_res->peer_eid;
    vtp_val->djetty_id = vtp_res->peer_jetty;
    vtp_val->fe_idx = vtp_res->fe_idx;
    // rm and rs_share
    if (tp_mode == UVS_TM_RM || tp_mode == UVS_TM_RC) {
        vtp_val->tpgn = vtp_res->tpgn;
    } else if (tp_mode == UVS_TM_UM) {
        vtp_val->utpn = vtp_res->utpn;
    }
}

static int uvs_dfx_rm_rc_lookup_vtpn(tpsa_worker_t *uvs_worker, uvs_res_vtp_key_t *vtp,
    tpsa_cmd_dfx_query_res_t *cfg, uint32_t *eid_index)
{
    int ret = -1;
    vport_key_t vport_key = {0};
    urma_eid_t seid = {0};
    urma_eid_t deid = {0};

    switch (vtp->tp_mode) {
        case UVS_TM_RM:
            (void)memcpy(&seid, &vtp->rm.seid, sizeof(urma_eid_t));
            (void)memcpy(&deid, &vtp->rm.deid, sizeof(urma_eid_t));
            break;
        case UVS_TM_RC:
            if ((vtp->sub_tp_mode == 1) && (vtp->share_mode == 1)) {
                // rs_share
                (void)memcpy(&seid, &vtp->rs_share.seid, sizeof(urma_eid_t));
                (void)memcpy(&deid, &vtp->rs_share.deid, sizeof(urma_eid_t));
                break;
            }
            TPSA_LOG_ERR("unsupport dfx vtp res query sub tp mode: %d, share mode: %d",
                vtp->sub_tp_mode, vtp->share_mode);
            return -1;
        default:
            TPSA_LOG_ERR("unsupport dfx vtp res query type: %d", vtp->tp_mode);
            return -1;
    }
    ret = vport_table_lookup_by_ueid_return_key(&uvs_worker->table_ctx.vport_table,
        vtp->upi, &seid, &vport_key, eid_index);
    if (ret != 0) {
        TPSA_LOG_WARN("Can't find rm/rc vport key with upi: %u, seid: " EID_FMT ".",
            vtp->upi, EID_ARGS(seid));
        return ret;
    }
    ret = tpsa_lookup_rm_vtp_table(&uvs_worker->table_ctx, &vport_key,
        &seid, &deid, &cfg->in.key);
    if (ret != 0) {
        TPSA_LOG_WARN("Can't find rm/rc vtp table tpf_name: %s, fe_idx: %u,"
            "seid: " EID_FMT ", deid:" EID_FMT".", vport_key.tpf_name, vport_key.fe_idx,
            EID_ARGS(seid), EID_ARGS(deid));
        return ret;
    }
    // dev->ops->query_res中查询vtp的key为vptn, key_ext为fe_idx
    cfg->in.key_ext = vport_key.fe_idx;
    return 0;
}

static int uvs_dfx_um_lookup_vtpn(tpsa_worker_t *uvs_worker, uvs_res_vtp_key_t *vtp,
    tpsa_cmd_dfx_query_res_t *cfg, uint32_t *eid_index)
{
    int ret = -1;
    vport_key_t vport_key = {0};
    urma_eid_t seid = {0};
    urma_eid_t deid = {0};

    (void)memcpy(&seid, &vtp->um.seid, sizeof(urma_eid_t));
    (void)memcpy(&deid, &vtp->um.deid, sizeof(urma_eid_t));
    um_vtp_table_key_t um_vtp_key = {
        .src_eid = seid,
        .dst_eid = deid,
    };

    ret = vport_table_lookup_by_ueid_return_key(&uvs_worker->table_ctx.vport_table,
        vtp->upi, &seid, &vport_key, eid_index);
    if (ret != 0) {
        TPSA_LOG_WARN("Can't find um vport key with upi: %u, seid: " EID_FMT ".",
            vtp->upi, EID_ARGS(seid));
        return ret;
    }

    um_vtp_table_entry_t *um_vtp_entry = um_fe_vtp_table_lookup(&uvs_worker->table_ctx.fe_table,
        &vport_key, &um_vtp_key);
    if (um_vtp_entry == NULL) {
        TPSA_LOG_WARN("Can't find um vtp entry with tpf_name: %s, fe_idx: %u,"
            "seid: " EID_FMT ", deid:" EID_FMT".", vport_key.tpf_name, vport_key.fe_idx,
            EID_ARGS(um_vtp_key.src_eid), EID_ARGS(um_vtp_key.dst_eid));
        return -1;
    }

    cfg->in.key = um_vtp_entry->vtpn;
    cfg->in.key_ext = vport_key.fe_idx;
    *eid_index = um_vtp_entry->eid_index;
    return 0;
}

static int uvs_ioctl_dfx_query_res_vtp(tpsa_worker_t *uvs_worker, const char *tpf_name,
    uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = -1;
    tpsa_cmd_dfx_query_res_t cfg = {0};
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);
    uint32_t eid_index;

    cfg.in.type = key->type;
    cfg.in.key_cnt = 1;

    switch (key->vtp.tp_mode) {
        case UVS_TM_RM:
            ret = uvs_dfx_rm_rc_lookup_vtpn(uvs_worker, &key->vtp, &cfg, &eid_index);
            break;
        case UVS_TM_RC:
            if ((key->vtp.sub_tp_mode == 1) && (key->vtp.share_mode == 1)) {
                // rs_share
                ret = uvs_dfx_rm_rc_lookup_vtpn(uvs_worker, &key->vtp, &cfg, &eid_index);
                break;
            }
            TPSA_LOG_ERR("unsupport dfx vtp rc res query sub tp mode: %d, share mode %d",
                key->vtp.sub_tp_mode, key->vtp.share_mode);
            return -1;
        case UVS_TM_UM:
            ret = uvs_dfx_um_lookup_vtpn(uvs_worker, &key->vtp, &cfg, &eid_index);
            break;
        default:
            TPSA_LOG_ERR("unsupport dfx res query type: %d", key->type);
            return -1;
    }
    if (ret != 0) {
        TPSA_LOG_WARN("can't find vtpn with tp mode: %d", key->vtp.tp_mode);
        return -EAGAIN; // 430适配GAEA需求，找不到反固定错码
    }

    ret = uvs_ioctl_dfx_query_res(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("dfx query res ioctl failed type: %d", key->type);
        return ret;
    }

    val->vtp.key = key->vtp;
    val->vtp.eid_index = eid_index;
    uvs_fill_query_res_vtp(&cfg.out.vtp, key->vtp.tp_mode, &val->vtp);
    return ret;
}

static void uvs_fill_query_res_tp(uvs_res_tp_ioctl_val_t *tp_res, uvs_res_tp_val_t *tp_val)
{
    tp_val->tx_psn = tp_res->tx_psn;
    tp_val->rx_psn = tp_res->rx_psn;
    tp_val->dscp = tp_res->dscp;
    tp_val->oor_en = tp_res->oor_en;
    tp_val->selective_retrans_en = tp_res->selective_retrans_en;
    tp_val->state = tp_res->state;
    tp_val->data_udp_start = tp_res->data_udp_start;
    tp_val->ack_udp_start = tp_res->ack_udp_start;
    tp_val->udp_range = tp_res->udp_range;
    tp_val->spray_en = tp_res->spray_en;
}

static int uvs_ioctl_dfx_query_res_tp(tpsa_worker_t *uvs_worker, const char *tpf_name,
    uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = -1;

    tpsa_cmd_dfx_query_res_t cfg = {0};
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.type = key->type;
    cfg.in.key_cnt = 1;
    cfg.in.key = key->tp.tpn;

    ret = uvs_ioctl_dfx_query_res(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("dfx query res ioctl failed type: %d", key->type);
        return ret;
    }

    val->tp.key = key->tp;
    uvs_fill_query_res_tp(&cfg.out.tp, &val->tp);
    return ret;
}

static void uvs_fill_query_res_tpg(uvs_res_tpg_ioctl_val_t *tpg_res, uvs_res_tpg_val_t *tpg_val)
{
    tpg_val->tp_cnt = tpg_res->tp_cnt;
    tpg_val->dscp = tpg_res->dscp;
    (void)memcpy(tpg_val->tp_state, tpg_res->tp_state, sizeof(tpg_val->tp_state));
    (void)memcpy(tpg_val->tpn, tpg_res->tpn, sizeof(tpg_val->tpn));
}

// Support rs share and rm non share
static int uvs_dfx_rs_rm_lookup_tpg(tpsa_worker_t *uvs_worker, uvs_res_tpg_key_t *tpg,
    tpsa_cmd_dfx_query_res_t *cfg, uint32_t *tpgn)
{
    int ret = -1;
    vport_key_t vport_key = {0};
    uint32_t eid_index;
    urma_eid_t seid = {0};
    urma_eid_t deid = {0};

    switch (tpg->tp_mode) {
        case UVS_TM_RM:
            if (tpg->share_mode == 0) {
                // rm_non_share
                (void)memcpy(&seid, &tpg->rm_non_share.seid, sizeof(urma_eid_t));
                (void)memcpy(&deid, &tpg->rm_non_share.deid, sizeof(urma_eid_t));
                break;
            }
            TPSA_LOG_ERR("unsupport dfx tpg rm res query share mode: %d", tpg->share_mode);
            return -1;
        case UVS_TM_RC:
            // rs_share
            if ((tpg->sub_tp_mode == 1) && (tpg->share_mode == 1)) {
                (void)memcpy(&seid, &tpg->rs_share.seid, sizeof(urma_eid_t));
                (void)memcpy(&deid, &tpg->rs_share.deid, sizeof(urma_eid_t));
                break;
            }
            TPSA_LOG_ERR("unsupport dfx tpg rs res query sub_tp_mode: %d, share_mode: %d",
                tpg->sub_tp_mode, tpg->share_mode);
            return -1;
        default:
            TPSA_LOG_ERR("unsupport dfx tpg res query type: %d", tpg->tp_mode);
            return -1;
    }

    ret = vport_table_lookup_by_ueid_return_key(&uvs_worker->table_ctx.vport_table,
        tpg->upi, &seid, &vport_key, &eid_index);
    if (ret != 0) {
        TPSA_LOG_ERR("tpg can't find vport_key with upi: %u, seid: " EID_FMT ".",
            tpg->upi, EID_ARGS(seid));
        return ret;
    }

    rm_vtp_table_key_t vtp_key = {.src_eid = seid, .dst_eid = deid };
    rm_vtp_table_entry_t *vtp_table_entry = rm_fe_vtp_table_lookup(&uvs_worker->table_ctx.fe_table,
        &vport_key, &vtp_key);
    if (vtp_table_entry == NULL) {
        TPSA_LOG_ERR("Can not find vtp_table_entry with tpf_name: %s, fe_idx: %u,",
            vport_key.tpf_name, vport_key.fe_idx);
        return -1;
    }

    if (tpg->tp_mode == UVS_TM_RM && vtp_table_entry->share_mode == 1) {
        TPSA_LOG_WARN("RM: Global share mode == 1 but query share mode = %d.", tpg->share_mode);
        return -EAGAIN;
    }

    *tpgn = vtp_table_entry->tpgn;
    return 0;
}

static int uvs_ioctl_dfx_query_res_tpg(tpsa_worker_t *uvs_worker, const char *tpf_name,
    uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = -1;

    tpsa_cmd_dfx_query_res_t cfg = {0};
    uint32_t tpgn;
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.type = key->type;
    cfg.in.key_cnt = 1;

    switch (key->tpg.tp_mode) {
        case UVS_TM_RM:
            if (key->tpg.share_mode == 1) {
                // rm share
                rm_tpg_table_key_t tpg_key = {
                    .sip = key->tpg.rm.sip,
                    .dip = key->tpg.rm.dip,
                };
                rm_tpg_table_entry_t *entry = rm_tpg_table_lookup(&uvs_worker->table_ctx.rm_tpg_table, &tpg_key);
                if (entry == NULL) {
                    TPSA_LOG_WARN("dfx query res, Can't find entry, key sip " EID_FMT " , dip: " EID_FMT " ",
                        EID_ARGS(tpg_key.sip), EID_ARGS(tpg_key.dip));
                    return -EAGAIN;
                }
                tpgn = entry->tpgn;
                ret = 0;
            } else {
                // rm_non_share
                ret = uvs_dfx_rs_rm_lookup_tpg(uvs_worker, &key->tpg, &cfg, &tpgn);
            }
            break;
        case UVS_TM_RC:
            // rs_share
            if ((key->tpg.sub_tp_mode == 1) && (key->tpg.share_mode == 1)) {
                ret = uvs_dfx_rs_rm_lookup_tpg(uvs_worker, &key->tpg, &cfg, &tpgn);
                break;
            }
            TPSA_LOG_ERR("unsupport dfx rc res query sub_tp_mode: %d, share_mode: %d",
                key->tpg.sub_tp_mode, key->tpg.share_mode);
            return -1;
        default:
            TPSA_LOG_ERR("unsupport dfx res query type: %d", key->tpg.tp_mode);
            return -1;
    }
    if (ret != 0) {
        TPSA_LOG_WARN("can't find tpgn with tp type: %d, share_mode: %d",
            key->vtp.tp_mode, key->tpg.share_mode);
        return -EAGAIN; // 430适配GAEA需求，找不到反固定错码
    }

    cfg.in.key = tpgn;
    ret = uvs_ioctl_dfx_query_res(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("dfx query res ioctl failed type: %d", key->type);
        return ret;
    }

    val->tpg.key = key->tpg;
    val->tpg.tpgn = tpgn;
    uvs_fill_query_res_tpg(&cfg.out.tpg, &val->tpg);
    return ret;
}

static void uvs_fill_query_res_utp(uvs_res_utp_ioctl_val_t *utp_res, uvs_res_utp_val_t *utp_val)
{
    utp_val->utpn = utp_res->utpn;
    utp_val->data_udp_start = utp_res->data_udp_start;
    utp_val->udp_range = utp_res->udp_range;
    utp_val->flag = utp_res->flag;
}

static int uvs_ioctl_dfx_query_res_utp(tpsa_worker_t *uvs_worker, const char *tpf_name,
    uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = -1;

    tpsa_cmd_dfx_query_res_t cfg = {0};
    sip_table_entry_t sip_entry = {0};
    urma_eid_t remote_eid = {0};
    uvs_net_addr_t peer_uvs_ip = {0};

    uvs_net_addr_info_t dip;

    (void)memset(&dip, 0, sizeof(uvs_net_addr_info_t));
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.type = key->type;
    cfg.in.key_cnt = 1;

    ret = tpsa_sip_table_lookup(&uvs_worker->table_ctx.tpf_dev_table, cfg.in.dev_name,
        key->utp.sip_idx, &sip_entry);
    if (ret != 0) {
        TPSA_LOG_ERR("can't get sip table with sid_idx: %d", key->utp.sip_idx);
        return -EAGAIN;  // 430适配GAEA需求，找不到反固定错码
    }

    (void)memcpy(&remote_eid, &key->utp.deid, sizeof(urma_eid_t));
    ret = tpsa_lookup_dip_table(&uvs_worker->table_ctx.dip_table, remote_eid, key->utp.upi, &peer_uvs_ip, &dip);
    if (ret != 0) {
        TPSA_LOG_ERR("can't get dip table with upi: %u, seid: " EID_FMT ".",
            key->utp.upi, EID_ARGS(remote_eid));
        return -EAGAIN;
    }

    utp_table_key_t utp_key = {
        .sip = sip_entry.addr,
        .dip = dip,
    };

    utp_table_entry_t *utp_entry = utp_table_lookup(&uvs_worker->table_ctx.utp_table, &utp_key);
    if (utp_entry == NULL) {
        TPSA_LOG_ERR("can't get utp entry with utp key");
        return -EAGAIN;
    }

    cfg.in.key = utp_entry->utp_idx;

    ret = uvs_ioctl_dfx_query_res(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("dfx query res ioctl failed type: %d", key->type);
        if (errno == 1) {
            return 0;
        }
        return ret;
    }

    val->utp.key = key->utp;
    uvs_fill_query_res_utp(&cfg.out.utp, &val->utp);
    return ret;
}

static void uvs_fill_query_res_tpf(uvs_res_tpf_ioctl_val_t *tpf_res, uvs_res_tpf_val_t *tpf_val)
{
    tpf_val->vtp_cnt = tpf_res->vtp_cnt;
    tpf_val->tp_cnt = tpf_res->tp_cnt;
    tpf_val->tpg_cnt = tpf_res->tpg_cnt;
    tpf_val->utp_cnt = tpf_res->utp_cnt;
}

static void uvs_get_vport_eid_cnt(vport_table_t *vport_table, const char *vport_name, uint32_t *eid_cnt)
{
    vport_table_entry_t *cur, *next;

    (void)pthread_rwlock_rdlock(&vport_table->rwlock);
    HMAP_FOR_EACH_SAFE(cur, next, node, &vport_table->hmap) {
        if (strncmp(vport_name, cur->port_key.name, UVS_MAX_VPORT_NAME) != 0) {
            continue;
        }

        for (uint32_t i = 0; i < cur->ueid_max_cnt; i++) {
            if (cur->ueid[i].used) {
                (*eid_cnt)++;
            }
        }
    }
    (void)pthread_rwlock_unlock(&vport_table->rwlock);
}

static int uvs_ioctl_dfx_query_res_tpf(tpsa_worker_t *uvs_worker, const char *tpf_name,
    uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = -1;
    tpsa_cmd_dfx_query_res_t cfg = {0};
    (void)strncpy(cfg.in.dev_name, tpf_name, URMA_MAX_DEV_NAME - 1);

    cfg.in.type = key->type;
    cfg.in.key = 0;
    cfg.in.key_ext = 0;
    cfg.in.key_cnt = 1;

    ret = uvs_ioctl_dfx_query_res(uvs_worker->ioctl_ctx.ubcore_fd, &cfg);
    if (ret != 0) {
        TPSA_LOG_ERR("dfx query res ioctl failed type: %d", key->type);
        return ret;
    }

    val->tpf.key = key->tpf;
    uvs_fill_query_res_tpf(&cfg.out.tpf, &val->tpf);
    return ret;
}

static int uvs_dfx_query_res_vport(tpsa_worker_t *uvs_worker, const char *tpf_name,
    uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = 0;
    uvs_get_vport_eid_cnt(&uvs_worker->table_ctx.vport_table, key->vport.vport_name,
        &val->vport.eid_used_cnt);
    val->vport.key = key->vport;
    return ret;
}

int uvs_del_migration_task(uvs_ueid_t *dueid)
{
    if (dueid == NULL) {
        TPSA_LOG_ERR("Input invalid.\n");
        return -1;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        TPSA_LOG_ERR("Can not get uvs_worker ctx\n");
        return -1;
    }

    vport_key_t vport_key = {0};
    uint32_t eid_index;
    int ret;

    ret = vport_table_lookup_by_ueid_return_key(&uvs_worker->table_ctx.vport_table,
        dueid->upi, (urma_eid_t *)&dueid->eid, &vport_key, &eid_index);
    if (ret != 0) {
        TPSA_LOG_INFO("Can not find vport by eid: " EID_FMT " upi: %u, goto normal case.\n",
            EID_ARGS(dueid->eid), dueid->upi);
        goto normal_end;
    }

    ret = uvs_lm_rollback_process(&uvs_worker->table_ctx, dueid, &vport_key);

    return ret;
normal_end:

    return ret;
}

int uvs_query_resource(const char *tpf_name, uvs_res_key_t *key, uvs_res_val_t *val)
{
    int ret = -1;

    if (tpf_name == NULL || key == NULL || val == NULL) {
        TPSA_LOG_ERR("uvs query resource with null ptr");
        return ret;
    }

    if (key->type != UVS_RES_VTP && key->type != UVS_RES_UTP && key->type != UVS_RES_TPG &&
        key->type != UVS_RES_TP && key->type != UVS_RES_VPORT && key->type != UVS_RES_TPF) {
        TPSA_LOG_ERR("Input invalid, num:%d", key->type);
        return ret;
    }

    if (strnlen(tpf_name, UVS_MAX_DEV_NAME) >= UVS_MAX_DEV_NAME) {
        TPSA_LOG_ERR("Invalid tpf_name");
        return ret;
    }

    tpsa_worker_t *uvs_worker = uvs_get_worker();
    if (uvs_worker == NULL) {
        return ret;
    }

    switch (key->type) {
        case UVS_RES_VTP:
            ret = uvs_ioctl_dfx_query_res_vtp(uvs_worker, tpf_name, key, val);
            break;
        case UVS_RES_TP:
            ret = uvs_ioctl_dfx_query_res_tp(uvs_worker, tpf_name, key, val);
            break;
        case UVS_RES_TPG:
            ret = uvs_ioctl_dfx_query_res_tpg(uvs_worker, tpf_name, key, val);
            break;
        case UVS_RES_UTP:
            ret = uvs_ioctl_dfx_query_res_utp(uvs_worker, tpf_name, key, val);;
            break;
        case UVS_RES_TPF:
            ret = uvs_ioctl_dfx_query_res_tpf(uvs_worker, tpf_name, key, val);;
            break;
        case UVS_RES_VPORT:
            ret = uvs_dfx_query_res_vport(uvs_worker, tpf_name, key, val);;
            break;
        default:
            TPSA_LOG_ERR("unsupport dfx res query type: %d", key->type);
            break;
    }

    return ret;
}