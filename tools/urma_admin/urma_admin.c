/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: ubus_tools
 * Author: Qian Guoxin
 * Create: 2021-11-30
 * Note:
 * History: 2021-11-30   create file
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include<sys/types.h>

#include "ub_list.h"
#include "urma_types.h"
#include "urma_types_str.h"

#include "admin_parameters.h"
#include "admin_file_ops.h"
#include "urma_admin_log.h"
#include "admin_cmd.h"

#define UINT8_INVALID (0xff)
#define MAX_UPI_CNT 1000
#define ADMIN_CC_ALG_MAX 255 /* 0xFF: Support 8 congestion algorithms */

typedef struct admin_show_ubep {
    struct ub_list node;
    char dev_name[URMA_ADMIN_MAX_DEV_NAME];
    urma_device_attr_t dev_attr;
    urma_transport_type_t tp_type;
    urma_eid_info_t *eid_list;
} admin_show_ubep_t;

static void admin_parse_port_attr(const char *sysfs_path, admin_show_ubep_t *ubep)
{
    uint8_t i;
    char *port_path = calloc(1, DEV_PATH_MAX);
    if (port_path == NULL) {
        return;
    }

    for (i = 0; i < ubep->dev_attr.port_cnt; i++) {
        if (snprintf(port_path, DEV_PATH_MAX, "%s/port%u", sysfs_path, i) <= 0) {
            (void)printf("snprintf failed, path: %s, port_num:%u.\n", sysfs_path, i);
            continue;
        }

        struct urma_port_attr *port_attr = &(ubep->dev_attr.port_attr[i]);

        (void)admin_parse_file_value_u32(port_path, "max_mtu", (uint32_t *)&port_attr->max_mtu);
        (void)admin_parse_file_value_u32(port_path, "state", (uint32_t *)&port_attr->state);
        (void)admin_parse_file_value_u32(port_path, "active_width", (uint32_t *)&port_attr->active_width);
        (void)admin_parse_file_value_u32(port_path, "active_speed", (uint32_t *)&port_attr->active_speed);
        (void)admin_parse_file_value_u32(port_path, "active_mtu", (uint32_t *)&port_attr->active_mtu);
    }
    free(port_path);
}

static void admin_parse_device_attr(const char *sysfs_path, admin_show_ubep_t *ubep)
{
    char tmp_value[VALUE_LEN_MAX];
    char tmp_eid[VALUE_LEN_MAX] = {0};

    urma_device_attr_t *dev_attr = &ubep->dev_attr;
    (void)admin_parse_file_value_u64(sysfs_path, "guid", &dev_attr->guid);

    (void)admin_parse_file_value_u32(sysfs_path, "feature", &dev_attr->dev_cap.feature.value);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfc", &dev_attr->dev_cap.max_jfc);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfs", &dev_attr->dev_cap.max_jfs);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfr", &dev_attr->dev_cap.max_jfr);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jetty", &dev_attr->dev_cap.max_jetty);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jetty_grp", &dev_attr->dev_cap.max_jetty_grp);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jetty_in_jetty_grp", &dev_attr->dev_cap.max_jetty_in_jetty_grp);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfc_depth", &dev_attr->dev_cap.max_jfc_depth);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfs_depth", &dev_attr->dev_cap.max_jfs_depth);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfr_depth", &dev_attr->dev_cap.max_jfr_depth);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfs_inline_size", &dev_attr->dev_cap.max_jfs_inline_len);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfs_sge", &dev_attr->dev_cap.max_jfs_sge);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfs_rsge", &dev_attr->dev_cap.max_jfs_rsge);
    (void)admin_parse_file_value_u32(sysfs_path, "max_jfr_sge", &dev_attr->dev_cap.max_jfr_sge);
    (void)admin_parse_file_value_u64(sysfs_path, "max_msg_size", &dev_attr->dev_cap.max_msg_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_atomic_size", &dev_attr->dev_cap.max_atomic_size);
    (void)admin_parse_file_value_u32(sysfs_path, "atomic_feat", &dev_attr->dev_cap.atomic_feat.value);
    (void)admin_parse_file_value_u16(sysfs_path, "trans_mode", &dev_attr->dev_cap.trans_mode);
    (void)admin_parse_file_value_u16(sysfs_path, "congestion_ctrl_alg", &dev_attr->dev_cap.congestion_ctrl_alg);
    (void)admin_parse_file_value_u32(sysfs_path, "ceq_cnt", &dev_attr->dev_cap.ceq_cnt);
    (void)admin_parse_file_value_u8(sysfs_path, "port_count", &dev_attr->port_cnt);
    (void)admin_parse_file_value_u32(sysfs_path, "max_eid_cnt", &dev_attr->max_eid_cnt);
    (void)admin_parse_file_value_u32(sysfs_path, "max_tp_in_tpg", &dev_attr->dev_cap.max_tp_in_tpg);

    ubep->eid_list = calloc(1, dev_attr->max_eid_cnt * sizeof(urma_eid_info_t));
    if (ubep->eid_list == NULL) {
        return;
    }
    for (uint32_t i = 0; i < dev_attr->max_eid_cnt; i++) {
        if (snprintf(tmp_eid, VALUE_LEN_MAX, "eid%u/eid", i) <= 0) {
            (void)printf("snprintf failed, eid idx: %u.\n", i);
        }
        ubep->eid_list[i].eid_index = i;
        if (admin_parse_file_str(sysfs_path, tmp_eid, tmp_value, VALUE_LEN_MAX) <= 0 ||
            admin_str_to_eid(tmp_value, &ubep->eid_list[i].eid) != 0) {
            ubep->eid_list[i].eid.in4.prefix = 0;  // invalid
        }
    }
    if (ubep->dev_attr.port_cnt > 0 && ubep->dev_attr.port_cnt != UINT8_INVALID) {
        admin_parse_port_attr(sysfs_path, ubep);
    }
}

static admin_show_ubep_t *admin_get_ubep_info(const struct dirent *dent)
{
    admin_show_ubep_t *ubep;
    char *sysfs_path;

    if (dent->d_name[0] == '.') {
        return NULL;
    }

    ubep = calloc(1, sizeof(admin_show_ubep_t));
    if (ubep == NULL) {
        return NULL;
    }

    sysfs_path = calloc(1, DEV_PATH_MAX);
    if (sysfs_path == NULL) {
        goto free_ubep;
    }
    if (admin_merge_sysfs_path(sysfs_path, SYS_CLASS_PATH, dent->d_name) != 0) {
        goto free_sysfs_path;
    }

    if (admin_read_dev_file(dent->d_name, "ubdev", ubep->dev_name, URMA_ADMIN_MAX_DEV_NAME) <= 0) {
        ubep->dev_name[0] = 0;
    }

    int ret = admin_parse_file_value_u32(sysfs_path, "transport_type", (uint32_t *)&ubep->tp_type);
    if (ret != 0) {
        ubep->tp_type = URMA_TRANSPORT_INVALID;
        (void)printf("parse transport_type failed, %s.\n", sysfs_path);
        goto free_sysfs_path;
    }
    admin_parse_device_attr(sysfs_path, ubep);

    free(sysfs_path);
    return ubep;

free_sysfs_path:
    free(sysfs_path);
free_ubep:
    free(ubep);
    return NULL;
}

static int find_ubep_list(struct ub_list *ubep_list, const tool_config_t *cfg)
{
    DIR *class_dir;
    struct dirent *dent;
    admin_show_ubep_t *ubep;

    class_dir = opendir(SYS_CLASS_PATH);
    if (class_dir == NULL) {
        (void)printf("%s open failed, errno: %d.\n", SYS_CLASS_PATH, errno);
        return -1;
    }

    while ((dent = readdir(class_dir)) != NULL) {
        // If a device is specified, it will be printed only if the name matches, based on prefix method.
        if (cfg->specify_device == true && strcmp(dent->d_name, cfg->dev_name) != 0) {
            continue;
        }
        ubep = admin_get_ubep_info(dent);
        if (ubep == NULL) {
            continue;
        }
        ub_list_insert_after(ubep_list, &ubep->node);
    }

    if (closedir(class_dir) < 0) {
        (void)printf("Failed to close dir: %s, errno: %d.\n", SYS_CLASS_PATH, errno);
        return -1;
    }
    return 0;
}

static inline void print_ubep_simple_info(const admin_show_ubep_t *ubep, int index, const tool_config_t *cfg)
{
    urma_eid_t eid = {0};

    for (uint32_t i = 0; i < ubep->dev_attr.max_eid_cnt; i++) {
        if (i > 0 && memcmp(&ubep->eid_list[i].eid, &eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }
        (void)printf("%-3d  %-16s    %-8s    eid%u "EID_FMT"    %-8s    \n",
            index, ubep->dev_name, urma_tp_type_to_string(ubep->tp_type), ubep->eid_list[i].eid_index,
            EID_ARGS(ubep->eid_list[i].eid), urma_port_state_to_string(ubep->dev_attr.port_attr[0].state));
    }
}

static inline void print_device_feat_str(urma_device_feature_t feat)
{
    uint8_t i;

    (void)printf("feature                    : 0x%x [", feat.value);
    for (i = 0; i < URMA_DEVICE_FEAT_NUM; i++) {
        if (!!(feat.value & (1 << i))) {
            (void)printf("%s ", urma_device_feat_to_string(i));
        }
    }
    (void)printf("]\n");
}

static inline void print_atomic_feat_str(urma_atomic_feature_t feat)
{
    uint8_t i;

    (void)printf("atomic_feature             : 0x%x [", feat.value);
    for (i = 0; i < URMA_ATOMIC_FEAT_NUM; i++) {
        if (!!(feat.value & (1 << i))) {
            (void)printf("%s ", urma_atomic_feat_to_string(i));
        }
    }
    (void)printf("]\n");
}

#define urma_char_bits 8
static inline void print_congestion_ctrl_alg_str(uint16_t cc_alg)
{
    uint8_t i;

    (void)printf("congestion_ctrl_alg        : 0x%x [", cc_alg);
    for (i = 0; i < sizeof(cc_alg) * urma_char_bits; i++) {
        if (!!(cc_alg & (1 << i))) {
            (void)printf("%s ", urma_congestion_ctrl_alg_to_string(i));
        }
    }
    (void)printf("]\n");
}

static void print_trans_mode_str(uint16_t trans_mode)
{
    (void)printf("trans_mode                 : 0x%x [", (uint32_t)trans_mode);
    if (!!(trans_mode & URMA_TM_RM)) {
        (void)printf("%s ", urma_trans_mode_to_string(URMA_TM_RM));
    }
    if (!!(trans_mode & URMA_TM_RC)) {
        (void)printf("%s ", urma_trans_mode_to_string(URMA_TM_RC));
    }
    if (!!(trans_mode & URMA_TM_UM)) {
        (void)printf("%s ", urma_trans_mode_to_string(URMA_TM_UM));
    }

    (void)printf("]\n");
}

static void print_ubep_whole_info(const admin_show_ubep_t *ubep, int index, const tool_config_t *cfg)
{
    urma_eid_t eid = {0};
    uint32_t i;

    (void)printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    (void)printf("name                       : %-16s\n", ubep->dev_name);
    (void)printf("transport_type             : %u [%s]\n", ubep->tp_type, urma_tp_type_to_string(ubep->tp_type));
    for (i = 0; i < ubep->dev_attr.max_eid_cnt; i++) {
        if (i > 0 && memcmp(&ubep->eid_list[i].eid, &eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }
        (void)printf("eid%u                       : "EID_FMT"\n", ubep->eid_list[i].eid_index,
        EID_ARGS(ubep->eid_list[i].eid));
    }
    (void)printf("guid                       : %lu\n", ubep->dev_attr.guid);
    print_device_feat_str(ubep->dev_attr.dev_cap.feature);

    (void)printf("max_jfc                    : %u\n", ubep->dev_attr.dev_cap.max_jfc);
    (void)printf("max_jfs                    : %u\n", ubep->dev_attr.dev_cap.max_jfs);
    (void)printf("max_jfr                    : %u\n", ubep->dev_attr.dev_cap.max_jfr);
    (void)printf("max_jetty                  : %u\n", ubep->dev_attr.dev_cap.max_jetty);
    (void)printf("max_jetty_grp              : %u\n", ubep->dev_attr.dev_cap.max_jetty_grp);
    (void)printf("max_jetty_in_jetty_grp     : %u\n", ubep->dev_attr.dev_cap.max_jetty_in_jetty_grp);
    (void)printf("max_jfc_depth              : %u\n", ubep->dev_attr.dev_cap.max_jfc_depth);
    (void)printf("max_jfs_depth              : %u\n", ubep->dev_attr.dev_cap.max_jfs_depth);
    (void)printf("max_jfr_depth              : %u\n", ubep->dev_attr.dev_cap.max_jfr_depth);
    (void)printf("max_jfs_inline_size        : %u\n", ubep->dev_attr.dev_cap.max_jfs_inline_len);
    (void)printf("max_jfs_sge                : %u\n", ubep->dev_attr.dev_cap.max_jfs_sge);
    (void)printf("max_jfs_rsge               : %u\n", ubep->dev_attr.dev_cap.max_jfs_rsge);
    (void)printf("max_jfr_sge                : %u\n", ubep->dev_attr.dev_cap.max_jfr_sge);
    (void)printf("max_msg_size               : %lu\n", ubep->dev_attr.dev_cap.max_msg_size);
    (void)printf("max_atomic_size            : %u\n", ubep->dev_attr.dev_cap.max_atomic_size);
    print_atomic_feat_str(ubep->dev_attr.dev_cap.atomic_feat);
    print_trans_mode_str(ubep->dev_attr.dev_cap.trans_mode);
    print_congestion_ctrl_alg_str(ubep->dev_attr.dev_cap.congestion_ctrl_alg);
    (void)printf("ceq_cnt                    : %u\n", ubep->dev_attr.dev_cap.ceq_cnt);
    (void)printf("max_tp_in_tpg              : %u\n", ubep->dev_attr.dev_cap.max_tp_in_tpg);

    (void)printf("port_count                 : %u\n", ubep->dev_attr.port_cnt);
    for (i = 0; i < ubep->dev_attr.port_cnt && ubep->dev_attr.port_cnt != UINT8_INVALID; i++) {
        (void)printf("port%u:\n", (uint32_t)i);
        (void)printf("  max_mtu              : %u [%s]\n", ubep->dev_attr.port_attr[i].max_mtu,
            urma_mtu_to_string(ubep->dev_attr.port_attr[i].max_mtu));
        (void)printf("  state                : %u [%s]\n", ubep->dev_attr.port_attr[i].state,
            urma_port_state_to_string(ubep->dev_attr.port_attr[i].state));
        (void)printf("  active_width         : %u [%s]\n", ubep->dev_attr.port_attr[i].active_width,
            urma_link_width_to_string(ubep->dev_attr.port_attr[i].active_width));
        (void)printf("  active_speed         : %u [%s]\n", ubep->dev_attr.port_attr[i].active_speed,
            urma_speed_to_string(ubep->dev_attr.port_attr[i].active_speed));
        (void)printf("  active_mtu           : %u [%s]\n", ubep->dev_attr.port_attr[i].active_mtu,
            urma_mtu_to_string(ubep->dev_attr.port_attr[i].active_mtu));
    }
    (void)printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}

static void print_ubep_list(const struct ub_list *ubep_list, const tool_config_t *cfg)
{
    int cnt = 0;
    admin_show_ubep_t *ubep, *next;

    if (cfg->whole_info == false) {
        (void)printf("num  ubep_dev            tp_type     eid                                        link        \n");
        (void)printf("---  ----------------    --------    ---------------------------------------    --------    \n");
    }

    UB_LIST_FOR_EACH_SAFE(ubep, next, node, ubep_list) {
        if (ubep == NULL) {
            break;
        }
        if (cfg->whole_info == false) {
            print_ubep_simple_info(ubep, cnt++, cfg);
        } else {
            print_ubep_whole_info(ubep, cnt++, cfg);
        }
    }
}

static void free_ubep_list(struct ub_list *ubep_list)
{
    admin_show_ubep_t *ubep, *next;
    UB_LIST_FOR_EACH_SAFE(ubep, next, node, ubep_list) {
        if (ubep == NULL) {
            return;
        }
        ub_list_remove(&ubep->node);
        free(ubep->eid_list);
        free(ubep);
    }
}

static int admin_show_ubep(const tool_config_t *cfg)
{
    int ret;
    struct ub_list ubep_list;

    ub_list_init(&ubep_list);

    ret = find_ubep_list(&ubep_list, cfg);
    if (ret != 0) {
        (void)printf("Failed to find ubep.\n");
        goto free_list;
    }

    print_ubep_list(&ubep_list, cfg);

free_list:
    free_ubep_list(&ubep_list);
    return ret;
}

static int admin_set_ubep_cc_alg(const tool_config_t *cfg)
{
    int ret;
    char tmp_value[VALUE_LEN_MAX] = {0};

    if (cfg->dev_name[0] == 0 || cfg->cc_alg == 0 || cfg->cc_alg > ADMIN_CC_ALG_MAX) {
        (void)printf("set ubep cc_alg failed, invalid parameter.\n");
        return -1;
    }

    if (sprintf(tmp_value, "%hu", cfg->cc_alg) <= 0) {
        (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
        return -1;
    }
    ret = admin_write_dev_file(cfg->dev_name, "congestion_ctrl_alg", tmp_value, sizeof(uint16_t) + 1);

    return ret;
}

static int admin_set_ubep_upi(const tool_config_t *cfg)
{
    int ret;
    char tmp_path[FILE_PATH_MAX] = {0};
    char tmp_value[VALUE_LEN_MAX] = {0};

    if (cfg->dev_name[0] == 0 || cfg->idx > MAX_UPI_CNT) {
        (void)printf("set ubep upi failed, invalid parameter.\n");
        return -1;
    }

    if (cfg->fe_idx == OWN_FE_IDX) {
        if (snprintf(tmp_path, FILE_PATH_MAX - 1, "upi") <= 0) {
            (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
            return -1;
        }
    } else {
        if (snprintf(tmp_path, FILE_PATH_MAX - 1, "fe%u/upi", cfg->fe_idx) <= 0) {
            (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
            return -1;
        }
    }

    if (snprintf(tmp_value, VALUE_LEN_MAX - 1, "%u=%u", cfg->idx, cfg->upi) <= 0) {
        (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
        return -1;
    }

    ret = admin_write_dev_file(cfg->dev_name, tmp_path, tmp_value, (uint32_t)strlen(tmp_value));

    return ret;
}

static inline void print_ubep_upi(const char *upi_str)
{
    (void)printf("%s\n", upi_str);
}

static int admin_show_ubep_upi(const tool_config_t *cfg)
{
    uint32_t max_upi_cnt;
    char *tmp_buf;
    uint64_t buf_len;
    char tmp_path[FILE_PATH_MAX] = {0};

    if (cfg->dev_name[0] == 0) {
        (void)printf("show ubep upi failed, invalid parameter.\n");
        return -1;
    }

    if (cfg->fe_idx == OWN_FE_IDX) {
        if (snprintf(tmp_path, FILE_PATH_MAX - 1, "upi") <= 0) {
            (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
            return -1;
        }
    } else {
        if (snprintf(tmp_path, FILE_PATH_MAX - 1, "fe%u/upi", cfg->fe_idx) <= 0) {
            (void)printf("snprintf failed, dev_name: %s.\n", cfg->dev_name);
            return -1;
        }
    }

    max_upi_cnt = admin_read_dev_file_value_u32(cfg->dev_name, "max_upi_cnt");
    if (max_upi_cnt == 0) {
        (void)printf("read max_upi_cnt failed, dev_name: %s.\n", cfg->dev_name);
        return -1;
    }
#define ADMIN_UPI_STR_LEN (9)    /* 2^20 <= 8bit, add 1 bit space */
    buf_len = (uint64_t)max_upi_cnt * ADMIN_UPI_STR_LEN + 1;
    tmp_buf = calloc(1, buf_len);
    if (tmp_buf == NULL) {
        return -ENOMEM;
    }

    if (admin_read_dev_file(cfg->dev_name, tmp_path, tmp_buf, (uint32_t)buf_len) <= 0) {
        free(tmp_buf);
        return -1;
    }

    print_ubep_upi(tmp_buf);
    free(tmp_buf);
    return 0;
}

static int execute_command(const tool_config_t *cfg)
{
    int ret;

    switch (cfg->cmd) {
        case TOOL_CMD_SHOW:
            ret = admin_show_ubep(cfg);
            break;
        case TOOL_CMD_ADD_EID:
            ret = admin_add_eid(cfg);
            break;
        case TOOL_CMD_DEL_EID:
            ret = admin_del_eid(cfg);
            break;
        case TOOL_CMD_SET_EID_MODE:
            ret = admin_set_eid_mode(cfg);
            break;
        case TOOL_CMD_SET_CC_ALG:
            ret = admin_set_ubep_cc_alg(cfg);
            break;
        case TOOL_CMD_SET_UPI:
            ret = admin_set_ubep_upi(cfg);
            break;
        case TOOL_CMD_SHOW_UPI:
            ret = admin_show_ubep_upi(cfg);
            break;
        case TOOL_CMD_SHOW_UTP:
            ret = admin_show_udp(cfg);
            break;
        case TOOL_CMD_SHOW_STATS:
            ret = admin_show_stats(cfg);
            break;
        case TOOL_CMD_SHOW_RES:
            ret = admin_show_res(cfg);
            break;
        case TOOL_CMD_SET_NS_MODE:
            ret = admin_set_ns_mode(cfg);
            break;
        case TOOL_CMD_SET_DEV_NS:
            ret = admin_set_dev_ns(cfg);
            break;
        case TOOL_CMD_NUM:
        default:
            ret = -1;
            break;
    }

    return ret;
}

#define  MAX_CMDLINE_LEN 896   /* must less than MAX_LOG_LEN */
static int admin_check_cmd_len(int argc, char *argv[])
{
    uint32_t len = 0;
    for (int i = 0; i < argc; i++) {
        len += strlen(argv[i]);
    }
    if ((int)len + argc > MAX_CMDLINE_LEN) {
        URMA_ADMIN_LOG("user: %s, cmd len out of range.\n", getlogin());
        return -1;
    }
    return 0;
}

static void admin_log_cmd(int argc, char *argv[], int ret)
{
    int i;
    char cmd[MAX_CMDLINE_LEN] = {0};
    for (i = 0; i < argc; i++) {
        (void)strcat(cmd, argv[i]);
        (void)strcat(cmd, " ");
    }
    URMA_ADMIN_LOG("user: %s, cmd: %s, ret:%d.\n", getlogin(), cmd, ret);
}

int main(int argc, char *argv[])
{
    int ret;
    tool_config_t tool_cfg;

    if (admin_check_cmd_len(argc, argv) != 0) {
        (void)printf("user: %s, cmd len out of range.\n", getlogin());
        return -1;
    }

    ret = admin_parse_args(argc, argv, &tool_cfg);
    if (ret != 0) {
        (void)printf("Invalid parameter.\n");
        admin_log_cmd(argc, argv, ret);
        return ret;
    }
    if (tool_cfg.cmd == TOOL_CMD_NUM) {
        admin_log_cmd(argc, argv, ret);
        return 0;
    }

    ret = execute_command(&tool_cfg);
    if (ret != 0) {
        (void)printf("Failed to execute command.\n");
        admin_log_cmd(argc, argv, ret);
        return ret;
    }

    admin_log_cmd(argc, argv, ret);
    return ret;
}
