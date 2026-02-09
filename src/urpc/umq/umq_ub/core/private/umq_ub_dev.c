/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: UMQ UB device info maintenance
 * Create: 2026-2-8
 * Note:
 * Create: 2026-2-8
 */

#include "umq_types.h"
#include "urma_api.h"

#include "umq_ub_private.h"

static struct {
    urma_device_t **urma_dev;
    umq_dev_info_t *umq_dev;
    int dev_num;
} g_umq_global_dev; // read only area

int umq_ub_dev_str_get(umq_dev_assign_t *dev_info, char *dev_str, int dev_str_len)
{
    int ret;
    char *ip_addr;
    switch (dev_info->assign_mode) {
        case UMQ_DEV_ASSIGN_MODE_DEV:
            ret = snprintf(dev_str, dev_str_len, "%s[%u]", dev_info->dev.dev_name, dev_info->dev.eid_idx);
            if (ret < 0 || ret >= dev_str_len) {
                UMQ_VLOG_ERR(VLOG_UMQ, "snprintf failed, ret: %d\n", ret);
                return UMQ_FAIL;
            }
            break;
        case UMQ_DEV_ASSIGN_MODE_EID:
            ret = snprintf(dev_str, dev_str_len, "" EID_FMT "", EID_ARGS(dev_info->eid.eid));
            if (ret < 0 || ret >= dev_str_len) {
                UMQ_VLOG_ERR(VLOG_UMQ, "snprintf failed, ret: %d\n", ret);
                return UMQ_FAIL;
            }
            break;
        case UMQ_DEV_ASSIGN_MODE_IPV4:
        /* fall-through */
        case UMQ_DEV_ASSIGN_MODE_IPV6:
            ip_addr =
                dev_info->assign_mode == UMQ_DEV_ASSIGN_MODE_IPV4 ? dev_info->ipv4.ip_addr : dev_info->ipv6.ip_addr;
            ret = snprintf(dev_str, dev_str_len, "%s", ip_addr);
            if (ret < 0 || ret >= dev_str_len) {
                UMQ_VLOG_ERR(VLOG_UMQ, "snprintf failed, ret: %d\n", ret);
                return UMQ_FAIL;
            }
            break;
        default:
            UMQ_VLOG_ERR(VLOG_UMQ, "assign mode: %d not supported\n", dev_info->assign_mode);
            return -UMQ_ERR_EINVAL;
    }

    return UMQ_SUCCESS;
}

static int umq_ub_dev_eid_set(urma_device_t *urma_dev, umq_dev_info_t *umq_dev_info)
{
    uint32_t eid_cnt = 0;
    urma_eid_info_t *eid_info_list = urma_get_eid_list(urma_dev, &eid_cnt);
    if (eid_info_list == NULL || eid_cnt == 0) {
        UMQ_VLOG_WARN(VLOG_UMQ_URMA_API, "urma_get_eid_list failed, dev: %s, errno: %d\n", urma_dev->name, errno);
        return UMQ_SUCCESS;
    }

    if (eid_cnt >= UMQ_MAX_EID_CNT) {
        urma_free_eid_list(eid_info_list);
        UMQ_VLOG_ERR(VLOG_UMQ, "number of eid exceeds the maximum limit %d, dev: %s\n", UMQ_MAX_EID_CNT,
            urma_dev->name);
        return -UMQ_ERR_ENOMEM;
    }

    for (uint32_t i = 0; i < eid_cnt; i++) {
        memcpy(&umq_dev_info->ub.eid_list[i].eid, &eid_info_list[i].eid, sizeof(urma_eid_t));
        umq_dev_info->ub.eid_list[i].eid_index = eid_info_list[i].eid_index;
    }

    // notice: umq_dev_info.umq_trans_mode is NOT set
    umq_dev_info->ub.eid_cnt = eid_cnt;
    (void)strncpy(umq_dev_info->dev_name, urma_dev->name, UMQ_DEV_NAME_SIZE);

    urma_free_eid_list(eid_info_list);

    return UMQ_SUCCESS;
}

int umq_ub_dev_info_init(void)
{
    int ret = UMQ_SUCCESS;
    g_umq_global_dev.urma_dev = urma_get_device_list(&g_umq_global_dev.dev_num);
    if (g_umq_global_dev.urma_dev == NULL || g_umq_global_dev.dev_num <= 0) {
        UMQ_VLOG_ERR(VLOG_UMQ_URMA_API, "urma_get_device_list failed, errno %d\n", errno);
        return -UMQ_ERR_ENODEV;
    }

    g_umq_global_dev.umq_dev = calloc(g_umq_global_dev.dev_num, sizeof(umq_dev_info_t));
    if (g_umq_global_dev.umq_dev == NULL) {
        UMQ_VLOG_ERR(VLOG_UMQ, "calloc umq_dev_info failed\n");
        ret = -UMQ_ERR_ENOMEM;
        goto FREE_DEV_LIST;
    }

    for (int i = 0; i < g_umq_global_dev.dev_num; i++) {
        ret = umq_ub_dev_eid_set(g_umq_global_dev.urma_dev[i], &g_umq_global_dev.umq_dev[i]);
        if (ret != UMQ_SUCCESS) {
            UMQ_VLOG_WARN(VLOG_UMQ, "get dev info for dev: %s failed, status: %d\n",
                g_umq_global_dev.urma_dev[i]->name, ret);
            goto FREE_UMQ_DEV;
        }
    }

    return UMQ_SUCCESS;

FREE_UMQ_DEV:
    free(g_umq_global_dev.umq_dev);
    g_umq_global_dev.umq_dev = NULL;

FREE_DEV_LIST:
    urma_free_device_list(g_umq_global_dev.urma_dev);
    g_umq_global_dev.dev_num = 0;

    return ret;
}

void umq_ub_dev_info_uninit(void)
{
    if (g_umq_global_dev.umq_dev != NULL) {
        free(g_umq_global_dev.umq_dev);
        g_umq_global_dev.umq_dev = NULL;
    }

    if (g_umq_global_dev.urma_dev != NULL) {
        urma_free_device_list(g_umq_global_dev.urma_dev);
        g_umq_global_dev.urma_dev = NULL;
    }

    g_umq_global_dev.dev_num = 0;
}

int umq_ub_dev_num_get(void)
{
    return g_umq_global_dev.dev_num;
}

void umq_ub_dev_info_dump(umq_trans_mode_t umq_trans_mode, int num, umq_dev_info_t *out)
{
    int i;
    for (i = 0; i < num && i < g_umq_global_dev.dev_num; i++) {
        memcpy(&out[i], &g_umq_global_dev.umq_dev[i], sizeof(umq_dev_info_t));
        out[i].umq_trans_mode = umq_trans_mode;
    }
}

int umq_ub_dev_info_dump_by_name(char *dev_name, umq_trans_mode_t umq_trans_mode, umq_dev_info_t *out)
{
    for (int i = 0; i < g_umq_global_dev.dev_num; i++) {
        if (strcmp(g_umq_global_dev.umq_dev[i].dev_name, dev_name) == 0) {
            memcpy(out, &g_umq_global_dev.umq_dev[i], sizeof(umq_dev_info_t));
            out->umq_trans_mode = umq_trans_mode;
            return UMQ_SUCCESS;
        }
    }

    UMQ_VLOG_ERR(VLOG_UMQ, "get dev info by name failed, dev_name %s\n", dev_name);
    return -UMQ_ERR_ENODEV;
}

int umq_ub_dev_lookup_by_name(char *dev_name, uint32_t eid_index, umq_ub_raw_dev_t *out)
{
    for (int i = 0; i < g_umq_global_dev.dev_num; i++) {
        for (uint32_t j = 0; j < g_umq_global_dev.umq_dev[i].ub.eid_cnt; j++) {
            if ((g_umq_global_dev.umq_dev[i].ub.eid_list[j].eid_index == eid_index) &&
                (strcmp(g_umq_global_dev.umq_dev[i].dev_name, dev_name) == 0)) {
                out->urma_dev = g_umq_global_dev.urma_dev[i];
                out->eid = g_umq_global_dev.umq_dev[i].ub.eid_list[j].eid;
                out->eid_index = g_umq_global_dev.umq_dev[i].ub.eid_list[j].eid_index;
                return UMQ_SUCCESS;
            }
        }
    }

    return -UMQ_ERR_ENODEV;
}

int umq_ub_dev_lookup_by_eid(umq_eid_t *eid, umq_ub_raw_dev_t *out)
{
    for (int i = 0; i < g_umq_global_dev.dev_num; i++) {
        for (uint32_t j = 0; j < g_umq_global_dev.umq_dev[i].ub.eid_cnt; j++) {
            if ((memcmp(eid, &g_umq_global_dev.umq_dev[i].ub.eid_list[j].eid, sizeof(umq_eid_t)) == 0)) {
                out->urma_dev = g_umq_global_dev.urma_dev[i];
                out->eid = g_umq_global_dev.umq_dev[i].ub.eid_list[j].eid;
                out->eid_index = g_umq_global_dev.umq_dev[i].ub.eid_list[j].eid_index;
                return UMQ_SUCCESS;
            }
        }
    }

    return -UMQ_ERR_ENODEV;
}
