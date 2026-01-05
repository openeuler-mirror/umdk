/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: eid sub-command source file for urma_admin
 * Author: Wang Hang
 * Create: 2025-12-29
 * Note:
 * History: 2025-12-29   create file
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>

#include "ub_list.h"
#include "urma_types.h"
#include "urma_types_str.h"

#include "admin_file_ops.h"
#include "admin_log.h"
#include "admin_netlink.h"
#include "admin_parameters.h"

#include "admin_cmd.h"

static int cmd_show_usage(admin_config_t *cfg)
{
    printf("Usage: urma_admin show\n"
           "       urma_admin show topo\n");
    return 0;
}

#define UINT8_INVALID (0xff)

typedef struct admin_show_ubep {
    struct ub_list node;
    char dev_name[URMA_ADMIN_MAX_DEV_NAME];
    urma_device_attr_t dev_attr;
    urma_transport_type_t tp_type;
    urma_eid_info_t *eid_list;
    char net_dev_name[URMA_ADMIN_MAX_DEV_NAME];
} admin_show_ubep_t;

static void admin_parse_port_attr(const char *sysfs_path, admin_show_ubep_t *ubep)
{
    uint8_t i;
    char *port_path = calloc(1, DEV_PATH_MAX);
    if (port_path == NULL) {
        return;
    }

    for (i = 0; i < ubep->dev_attr.port_cnt; i++) {
        if (snprintf(port_path, DEV_PATH_MAX - 1, "%s/port%u", sysfs_path, i) <= 0) {
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

static bool has_bonding_dev_prefix(const char *dev_name)
{
    const char *prefix = "bonding_dev";

    for (int i = 0; prefix[i] != '\0'; i++) {
        if (dev_name[i] != prefix[i] || dev_name[i] == '\0') {
            return false;
        }
    }
    return true;
}

static int admin_parse_device_attr(const char *sysfs_path, admin_show_ubep_t *ubep)
{
    char tmp_value[VALUE_LEN_MAX];

    urma_device_attr_t *dev_attr = &ubep->dev_attr;
    (void)admin_parse_file_str(sysfs_path, "guid", tmp_value, VALUE_LEN_MAX);
    (void)admin_str_to_eid(tmp_value, (urma_eid_t *)&dev_attr->guid);

    (void)admin_parse_file_str(sysfs_path, "net_dev", ubep->net_dev_name, URMA_ADMIN_MAX_DEV_NAME);
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
    (void)admin_parse_file_value_u32(sysfs_path, "max_read_size", &dev_attr->dev_cap.max_read_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_write_size", &dev_attr->dev_cap.max_write_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_cas_size", &dev_attr->dev_cap.max_cas_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_swap_size", &dev_attr->dev_cap.max_swap_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_fetch_and_add_size", &dev_attr->dev_cap.max_fetch_and_add_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_fetch_and_sub_size", &dev_attr->dev_cap.max_fetch_and_sub_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_fetch_and_and_size", &dev_attr->dev_cap.max_fetch_and_and_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_fetch_and_or_size", &dev_attr->dev_cap.max_fetch_and_or_size);
    (void)admin_parse_file_value_u32(sysfs_path, "max_fetch_and_xor_size", &dev_attr->dev_cap.max_fetch_and_xor_size);
    (void)admin_parse_file_value_u32(sysfs_path, "atomic_feat", &dev_attr->dev_cap.atomic_feat.value);
    (void)admin_parse_file_value_u16(sysfs_path, "trans_mode", &dev_attr->dev_cap.trans_mode);
    (void)admin_parse_file_value_u16(sysfs_path, "congestion_ctrl_alg", &dev_attr->dev_cap.congestion_ctrl_alg);
    (void)admin_parse_file_value_u32(sysfs_path, "ceq_cnt", &dev_attr->dev_cap.ceq_cnt);
    (void)admin_parse_file_value_u8(sysfs_path, "port_count", &dev_attr->port_cnt);
    (void)admin_parse_file_value_u32(sysfs_path, "max_eid_cnt", &dev_attr->dev_cap.max_eid_cnt);
    (void)admin_parse_file_value_u32(sysfs_path, "max_tp_in_tpg", &dev_attr->dev_cap.max_tp_in_tpg);

    admin_parse_reserved_jetty(sysfs_path, "reserved_jetty_id", &dev_attr->reserved_jetty_id_min,
                               &dev_attr->reserved_jetty_id_max);

    if (dev_attr->dev_cap.max_jetty_in_jetty_grp > URMA_MAX_JETTY_IN_JETTY_GRP) {
        (void)printf("max_jetty_in_jetty_grp %u is larger than URMA_MAX_JETTY_IN_JETTY_GRP %u."
                     " Use URMA_MAX_JETTY_IN_JETTY_GRP.\n",
                     dev_attr->dev_cap.max_jetty_in_jetty_grp, URMA_MAX_JETTY_IN_JETTY_GRP);
        dev_attr->dev_cap.max_jetty_in_jetty_grp = URMA_MAX_JETTY_IN_JETTY_GRP;
    }

    if (dev_attr->port_cnt > MAX_PORT_CNT) {
        (void)printf("port_cnt %u is larger than MAX_PORT_CNT %u. Use MAX_PORT_CNT.\n", (uint32_t)dev_attr->port_cnt,
                     (uint32_t)MAX_PORT_CNT);
        dev_attr->port_cnt = MAX_PORT_CNT;
    }

    if (dev_attr->dev_cap.max_eid_cnt > URMA_MAX_EID_CNT) {
        (void)printf("max_eid_cnt %u is larger than URMA_MAX_EID_CNT %d. Use URMA_MAX_EID_CNT.\n",
                     dev_attr->dev_cap.max_eid_cnt, URMA_MAX_EID_CNT);
        dev_attr->dev_cap.max_eid_cnt = URMA_MAX_EID_CNT;
    }

    ubep->eid_list = calloc(1, dev_attr->dev_cap.max_eid_cnt * sizeof(urma_eid_info_t));
    if (ubep->eid_list == NULL) {
        (void)printf("Failed to malloc eid_list, %s.\n", sysfs_path);
        return -1;
    }

    admin_read_eid_list(sysfs_path, ubep->eid_list, dev_attr->dev_cap.max_eid_cnt);

    if (ubep->dev_attr.port_cnt > 0 && ubep->dev_attr.port_cnt != UINT8_INVALID) {
        admin_parse_port_attr(sysfs_path, ubep);
    }

    if (has_bonding_dev_prefix(ubep->dev_name)) {
        ubep->dev_attr.port_attr[0].state = URMA_PORT_ACTIVE; /* bonding dev port 0 state is always active */
    }
    return 0;
}

static admin_show_ubep_t *admin_get_ubep_info(const struct dirent *dent)
{
    admin_show_ubep_t *ubep;
    char *sysfs_path;

    if (dent->d_name[0] == '.' || strcmp(dent->d_name, "ubcore") == 0) {
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

    ret = admin_parse_device_attr(sysfs_path, ubep);
    if (ret != 0) {
        (void)printf("parse device attr failed, %s.\n", sysfs_path);
        goto free_sysfs_path;
    }

    free(sysfs_path);
    return ubep;

free_sysfs_path:
    free(sysfs_path);
free_ubep:
    free(ubep);
    return NULL;
}

static void sort_ubep_list(struct ub_list *ubep_list)
{
    struct ub_list *tmp_list;
    admin_show_ubep_t *ubep, *ubep_next;
    int flag = 0;

    while (!flag) {
        flag = 1;
        if (ubep_list == NULL || ubep_list->next == NULL) {
            return;
        }
        tmp_list = ubep_list->next;
        while (tmp_list->next != NULL && tmp_list->next != ubep_list) {
            ubep = CONTAINER_OF_FIELD(tmp_list, admin_show_ubep_t, node);
            ubep_next = CONTAINER_OF_FIELD(tmp_list->next, admin_show_ubep_t, node);
            if (strcmp(ubep->dev_name, ubep_next->dev_name) > 0) {
                ubep->node.next = ubep_next->node.next;
                ubep_next->node.next->prev = &ubep->node;
                ubep_next->node.next = &ubep->node;
                ubep->node.prev->next = &ubep_next->node;
                ubep_next->node.prev = ubep->node.prev;
                ubep->node.prev = &ubep_next->node;
                flag = 0;
            } else {
                tmp_list = tmp_list->next;
            }
        }
    }
    return;
}

static int find_ubep_list(struct ub_list *ubep_list, const admin_config_t *cfg)
{
    DIR *class_dir;
    struct dirent *dent;
    admin_show_ubep_t *ubep;

    class_dir = opendir(SYS_CLASS_PATH);
    if (class_dir == NULL) {
        (void)printf("%s open failed, errno: %d.\n", SYS_CLASS_PATH, errno);
        URMA_ADMIN_LOG("%s open failed, errno: %d.\n", SYS_CLASS_PATH, errno);
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
        URMA_ADMIN_LOG("Failed to close dir: %s, errno: %d.\n", SYS_CLASS_PATH, errno);
        return -1;
    }
    return 0;
}

static uint32_t get_valid_eid_cnt(const admin_show_ubep_t *ubep)
{
    urma_eid_t eid = {0};
    uint32_t cnt = 0;

    for (uint32_t i = 0; i < ubep->dev_attr.dev_cap.max_eid_cnt; i++) {
        if (memcmp(&ubep->eid_list[i].eid, &eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }
        cnt++;
    }
    return cnt;
}

static void print_ubep_simple_info(const admin_show_ubep_t *ubep, int *index, const admin_config_t *cfg)
{
    if (get_valid_eid_cnt(ubep) == 0) {
        (void)printf("%-3d  %-16s    %-56s    %-8s    %-16s \n", (*index)++, ubep->dev_name,
                     urma_tp_type_to_string(ubep->tp_type),
                     urma_port_state_to_string(ubep->dev_attr.port_attr[0].state), ubep->net_dev_name);

        return;
    }
    urma_eid_t eid = {0};

    for (uint32_t i = 0; i < ubep->dev_attr.dev_cap.max_eid_cnt; i++) {
        if (memcmp(&ubep->eid_list[i].eid, &eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }
        (void)printf("%-3d  %-16s    %-8s    eid%u " EID_FMT "    %-8s\n", (*index)++, ubep->dev_name,
                     urma_tp_type_to_string(ubep->tp_type), ubep->eid_list[i].eid_index,
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

static void print_ubep_eids(const admin_show_ubep_t *ubep)
{
    urma_eid_t eid = {0};
    uint32_t i;

    for (i = 0; i < ubep->dev_attr.dev_cap.max_eid_cnt; i++) {
        if (memcmp(&ubep->eid_list[i].eid, &eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }
        (void)printf("  eid%u                     : " EID_FMT "\n", ubep->eid_list[i].eid_index,
                     EID_ARGS(ubep->eid_list[i].eid));
    }
}

static void print_ubep_whole_info(const admin_show_ubep_t *ubep, int *index, const admin_config_t *cfg)
{
    uint32_t i;

    (void)printf("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    (void)printf("name                       : %-16s\n", ubep->dev_name);
    (void)printf("transport_type             : %u [%s]\n", ubep->tp_type, urma_tp_type_to_string(ubep->tp_type));
    (void)printf("eids                       :\n");
    print_ubep_eids(ubep);

    (void)printf("guid                       : " EID_FMT "\n", EID_ARGS(ubep->dev_attr.guid));
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
    (void)printf("max_read_size              : %u\n", ubep->dev_attr.dev_cap.max_read_size);
    (void)printf("max_write_size             : %u\n", ubep->dev_attr.dev_cap.max_write_size);
    (void)printf("max_cas_size               : %u\n", ubep->dev_attr.dev_cap.max_cas_size);
    (void)printf("max_swap_size              : %u\n", ubep->dev_attr.dev_cap.max_swap_size);
    (void)printf("max_fetch_and_add_size     : %u\n", ubep->dev_attr.dev_cap.max_fetch_and_add_size);
    (void)printf("max_fetch_and_sub_size     : %u\n", ubep->dev_attr.dev_cap.max_fetch_and_sub_size);
    (void)printf("max_fetch_and_and_size     : %u\n", ubep->dev_attr.dev_cap.max_fetch_and_and_size);
    (void)printf("max_fetch_and_or_size      : %u\n", ubep->dev_attr.dev_cap.max_fetch_and_or_size);
    (void)printf("max_fetch_and_xor_size     : %u\n", ubep->dev_attr.dev_cap.max_fetch_and_xor_size);
    print_atomic_feat_str(ubep->dev_attr.dev_cap.atomic_feat);
    print_trans_mode_str(ubep->dev_attr.dev_cap.trans_mode);
    print_congestion_ctrl_alg_str(ubep->dev_attr.dev_cap.congestion_ctrl_alg);
    (void)printf("ceq_cnt                    : %u\n", ubep->dev_attr.dev_cap.ceq_cnt);
    (void)printf("max_tp_in_tpg              : %u\n", ubep->dev_attr.dev_cap.max_tp_in_tpg);

    (void)printf("port_count                 : %u\n", ubep->dev_attr.port_cnt);
    (void)printf("reserved_jetty_id_min      : %u\n", ubep->dev_attr.reserved_jetty_id_min);
    (void)printf("reserved_jetty_id_max      : %u\n", ubep->dev_attr.reserved_jetty_id_max);
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

static void print_ubep_list(const struct ub_list *ubep_list, const admin_config_t *cfg)
{
    int cnt = 0;
    admin_show_ubep_t *ubep, *next;

    if (cfg->whole_info == false) {
        (void)printf("num  ubep_dev            tp_type     eid                                             link\n");

        (void)printf("---  ----------------    --------    --------------------------------------------    --------\n");
    }

    UB_LIST_FOR_EACH_SAFE (ubep, next, node, ubep_list) {
        if (ubep == NULL) {
            break;
        }
        if (cfg->whole_info == false) {
            print_ubep_simple_info(ubep, &cnt, cfg);
        } else {
            print_ubep_whole_info(ubep, &cnt, cfg);
        }
    }
}

static void free_ubep_list(struct ub_list *ubep_list)
{
    admin_show_ubep_t *ubep, *next;
    UB_LIST_FOR_EACH_SAFE (ubep, next, node, ubep_list) {
        if (ubep == NULL) {
            return;
        }
        ub_list_remove(&ubep->node);
        free(ubep->eid_list);
        free(ubep);
    }
}

static int cmd_show_default(admin_config_t *cfg)
{
    int ret;
    struct ub_list ubep_list;

    ub_list_init(&ubep_list);

    ret = find_ubep_list(&ubep_list, cfg);
    if (ret != 0) {
        (void)printf("Failed to find ubep.\n");
        goto free_list;
    }

    sort_ubep_list(&ubep_list);
    print_ubep_list(&ubep_list, cfg);

free_list:
    free_ubep_list(&ubep_list);
    return ret;
}

bool admin_is_eid_valid(const char *eid)
{
    for (int i = 0; i < EID_LEN; i++) {
        if (eid[i] != 0) {
            return true;
        }
    }
    return false;
}

static void admin_print_topo_map(tool_topo_map_t *topo_map)
{
    uint32_t i, j, k;
    tool_topo_info_t *cur_node_info;

    (void)printf("========================== topo map start =============================\n");
    for (i = 0; i < topo_map->node_num; i++) {
        cur_node_info = topo_map->topo_infos + i;
        if (!admin_is_eid_valid(cur_node_info->bonding_eid)) {
            continue;
        }

        (void)printf("===================== node %d start =======================\n", i);
        (void)printf("bonding eid: " EID_FMT "\n", EID_ARGS(*(urma_eid_t *)cur_node_info->bonding_eid));
        for (j = 0; j < IODIE_NUM; j++) {
            (void)printf("**primary eid %d: " EID_FMT "\n", j,
                         EID_ARGS(*(urma_eid_t *)cur_node_info->io_die_info[j].primary_eid));
            for (k = 0; k < MAX_PORT_NUM; k++) {
                (void)printf("****port eid %d: " EID_FMT "\n", k,
                             EID_ARGS(*(urma_eid_t *)cur_node_info->io_die_info[j].port_eid[k]));
                (void)printf("****peer_port eid %d: " EID_FMT "\n", k,
                             EID_ARGS(*(urma_eid_t *)cur_node_info->io_die_info[j].peer_port_eid[k]));
            }
        }
        (void)printf("===================== node %d end =======================\n", i);
    }
    (void)printf("========================== topo map end =============================\n");
}

static int cmd_show_topo(admin_config_t *cfg)
{
    tool_topo_map_t *topo_map = calloc(1, sizeof(tool_topo_map_t));
    if (topo_map == NULL) {
        return -ENOMEM;
    }

    int ret = 0;

    int node_num = MAX_NODE_NUM;
    for (int i = 0; i < node_num; ++i) {
        admin_core_cmd_topo_info_t arg = {0};
        arg.in.node_idx = i;

        struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_GET_TOPO_INFO, 0);
        if (msg == NULL) {
            ret = -ENOMEM;
            goto free_topo;
        }

        admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(admin_core_cmd_topo_info_t));
        admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);
        ret = admin_nl_send_recv_msg_default(msg);
        admin_nl_free_msg(msg);
        if (ret < 0) {
            goto free_topo;
        }

        topo_map->topo_infos[i] = arg.out.topo_info;
        topo_map->node_num = arg.out.node_num;
        node_num = arg.out.node_num;
    }
    admin_print_topo_map(topo_map);
    free(topo_map);
    return 0;

free_topo:
    free(topo_map);
    return ret;
}

int admin_cmd_show(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_show_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_show_default}, //
        {"topo", cmd_show_topo},  //
        {0},                      //
    };
    return exec_cmd(cfg, cmds);
}
