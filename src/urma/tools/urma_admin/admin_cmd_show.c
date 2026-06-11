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
#include <netlink/errno.h>
#include <netlink/genl/genl.h>
#include <stdio.h>

#include "ub_list.h"
#include "urma_private.h"
#include "urma_types.h"
#include "urma_types_str.h"

#include "admin_file_ops.h"
#include "admin_log.h"
#include "admin_netlink.h"
#include "admin_parameters.h"

#include "admin_cmd.h"

static int cmd_show_usage(admin_config_t *cfg)
{
    (void)cfg;
    printf("Usage:\n"
           "  urma_admin show [--dev <DEV>] [--brief|--all] [--whole]  Show URMA devices information\n"
           "  urma_admin show topo [NODE_ID]           Show topology of specified node, default is current node\n"
           "  urma_admin show dev <DEV> jfc         [JFC_ID]\n"
           "  urma_admin show dev <DEV> jfs         [JFS_ID]\n"
           "  urma_admin show dev <DEV> jfr         [JFR_ID]\n"
           "  urma_admin show dev <DEV> jetty       [JETTY_ID]\n"
           "  urma_admin show dev <DEV> jetty_group [JETTY_GROUP_ID]\n"
           "  urma_admin show dev <DEV> rc          [RC_ID]\n"
           "  urma_admin show dev <DEV> seg         [TOKEN_ID]\n"
           "  urma_admin show dev <dev> tp [tp_id]  Show tpid_list (or single tpid state) of device\n"
           "  urma_admin show dev <dev> tpreuse     Show tpid_reuse of device\n"
           "\n"
           "Options:\n"
           "  <dev>      Device name (e.g., udma1)\n"
           "  <node_id>  Node ID (e.g., 1)\n"
           "  <dev_name> Device name (e.g., bonding_dev_0)\n"
           "  <jfx>      Resource type: jfs|jfr|jetty|jfc|seg\n"
           "  <jfx_id>   Resource ID (e.g., 0)\n"
           "  <tp_id>    Transport point id (e.g., 1)\n"
           "  --brief    Default behavior. If bonding devices exist, show bonding devices only;\n"
           "             otherwise show all udma devices.\n"
           "  --all      Show all devices\n"
           "  --whole    Show whole information of devices\n");
    return 0;
}

#define UINT8_INVALID (0xff)

#define UBAGG_DEV_MAX_NUM       (20)
#define UBAGG_MAX_PORT_NUM      (9)
#define ADMIN_V2P_RES_BUF_SIZE (64 * 1024)

enum admin_show_res_type {
    ADMIN_SHOW_RES_JETTY = 0,
    ADMIN_SHOW_RES_JFS,
    ADMIN_SHOW_RES_JFR,
    ADMIN_SHOW_RES_JFC,
    ADMIN_SHOW_RES_SEG,
};

typedef struct admin_ubagg_ubva {
    urma_eid_t eid;
    uint32_t uasid;
    uint64_t va;
} __attribute__((packed)) admin_ubagg_ubva_t;

typedef struct admin_ubagg_seg_info {
    admin_ubagg_ubva_t ubva;
    uint64_t len;
    uint32_t seg_attr;
    uint32_t token_id;
} admin_ubagg_seg_info_t;

typedef struct admin_ubagg_seg_exchange_info {
    admin_ubagg_seg_info_t base;
    admin_ubagg_seg_info_t slaves[UBAGG_DEV_MAX_NUM];
    int dev_num;
} admin_ubagg_seg_exchange_info_t;

typedef struct admin_ubagg_jetty_id {
    urma_eid_t eid;
    uint32_t uasid;
    uint32_t id;
} admin_ubagg_jetty_id_t;

typedef struct admin_ubagg_jetty_exchange_info {
    admin_ubagg_jetty_id_t slaves[UBAGG_DEV_MAX_NUM];
    bool is_multipath;
    uint8_t enabled_indices[UBAGG_DEV_MAX_NUM];
    uint32_t enabled_count;
    bool is_health_check_enable;
    admin_ubagg_seg_exchange_info_t health_check_seg;
} admin_ubagg_jetty_exchange_info_t;

typedef struct admin_core_cmd_show_res {
    struct {
        char dev_name[URMA_MAX_NAME];
        uint32_t type;
        uint32_t key;
        uint32_t key_cnt;
    } in;
    struct {
        uint64_t addr;
        uint32_t len;
        uint64_t save_ptr;
    } out;
} admin_core_cmd_show_res_t;

typedef struct admin_show_ubep {
    struct ub_list node;
    char dev_name[URMA_ADMIN_MAX_DEV_NAME];
    urma_device_attr_t dev_attr;
    urma_transport_type_t tp_type;
    urma_eid_info_t *eid_list;
    char net_dev_name[URMA_ADMIN_MAX_DEV_NAME];
    bool is_bonding_dev;
    char phy_dev_names[IODIE_NUM][URMA_ADMIN_MAX_DEV_NAME];
    uint32_t phy_primary_eid_idx[IODIE_NUM];
    uint32_t phy_port_eid_idx[IODIE_NUM][PORT_NUM];
} admin_show_ubep_t;

static void parse_bonding_phy_devs(admin_show_ubep_t *ubep);
static void format_phy_dev_names(const admin_show_ubep_t *ubep, char *buf, size_t buf_len);
static void print_related_udma_eids(admin_show_ubep_t *ubep, int *index, bool show_phy_dev_col);
static void free_ubep_list(struct ub_list *ubep_list);
static bool is_eid_idx_related_to_bonding(const admin_show_ubep_t *bonding_ubep, uint32_t phy_idx, uint32_t eid_idx);
static admin_show_ubep_t *admin_get_ubep_info_by_name(const char *dev_name, const admin_config_t *cfg);
bool admin_is_eid_valid(const char *eid);

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

static void admin_parse_priority_attr(const char *sysfs_path, admin_show_ubep_t *ubep)
{
    uint8_t i;
    char *priority_path = calloc(1, DEV_PATH_MAX);
    if (priority_path == NULL) {
        return;
    }
    for (i = 0; i < URMA_MAX_PRIORITY_CNT; i++) {
        if (snprintf(priority_path, DEV_PATH_MAX - 1, "%s/priority/priority%u", sysfs_path, i) <= 0) {
            (void)printf("snprintf failed, path: %s, priority_num:%u.\n", sysfs_path, i);
            continue;
        }

        struct urma_sl_info *priority_attr = &(ubep->dev_attr.dev_cap.priority_info[i]);

        (void)admin_parse_file_value_u32(priority_path, "sl", (uint32_t *)&priority_attr->SL);
        (void)admin_parse_file_value_u32(priority_path, "tp_type", (uint32_t *)&priority_attr->tp_type.value);
    }
    free(priority_path);
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

    admin_parse_priority_attr(sysfs_path, ubep);

    admin_parse_port_attr(sysfs_path, ubep);

    if (has_bonding_dev_prefix(ubep->dev_name)) {
        ubep->dev_attr.port_attr[0].state = URMA_PORT_ACTIVE; /* bonding dev port 0 state is always active */
    }
    return 0;
}

static admin_show_ubep_t *admin_get_ubep_info(const struct dirent *dent, const admin_config_t *cfg)
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
    ubep->is_bonding_dev = has_bonding_dev_prefix(ubep->dev_name);

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
    if (cfg != NULL && cfg->specify_device && ubep->is_bonding_dev) {
        parse_bonding_phy_devs(ubep);
    }

    free(sysfs_path);
    return ubep;

free_sysfs_path:
    free(sysfs_path);
free_ubep:
    free(ubep);
    return NULL;
}

static admin_show_ubep_t *admin_get_ubep_info_by_name(const char *dev_name, const admin_config_t *cfg)
{
    if (dev_name == NULL || dev_name[0] == '\0') {
        return NULL;
    }

    admin_show_ubep_t *ubep = calloc(1, sizeof(admin_show_ubep_t));
    if (ubep == NULL) {
        return NULL;
    }
    char *sysfs_path = calloc(1, DEV_PATH_MAX);
    if (sysfs_path == NULL) {
        free(ubep);
        return NULL;
    }

    if (admin_merge_sysfs_path(sysfs_path, SYS_CLASS_PATH, dev_name) != 0) {
        goto free_all;
    }
    if (admin_read_dev_file(dev_name, "ubdev", ubep->dev_name, URMA_ADMIN_MAX_DEV_NAME) <= 0) {
        ubep->dev_name[0] = 0;
    }
    ubep->is_bonding_dev = has_bonding_dev_prefix(ubep->dev_name);

    int ret = admin_parse_file_value_u32(sysfs_path, "transport_type", (uint32_t *)&ubep->tp_type);
    if (ret != 0) {
        goto free_all;
    }
    ret = admin_parse_device_attr(sysfs_path, ubep);
    if (ret != 0) {
        goto free_all;
    }
    if (cfg != NULL && cfg->specify_device && ubep->is_bonding_dev) {
        parse_bonding_phy_devs(ubep);
    }

    free(sysfs_path);
    return ubep;

free_all:
    free(sysfs_path);
    free(ubep->eid_list);
    free(ubep);
    return NULL;
}

static void sort_ubep_list(struct ub_list *ubep_list)
{
    struct ub_list *tmp_list;
    admin_show_ubep_t *ubep, *ubep_next;
    int flag = 0;

    while (flag == 0) {
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
        ubep = admin_get_ubep_info(dent, cfg);
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

static void parse_bonding_phy_devs(admin_show_ubep_t *ubep)
{
    if (ubep == NULL || ubep->is_bonding_dev == false || ubep->eid_list == NULL) {
        return;
    }
    for (uint32_t i = 0; i < IODIE_NUM; i++) {
        ubep->phy_primary_eid_idx[i] = UINT32_MAX;
        for (uint32_t j = 0; j < PORT_NUM; j++) {
            ubep->phy_port_eid_idx[i][j] = UINT32_MAX;
        }
    }

    urma_eid_t invalid_eid = {0};
    for (uint32_t i = 0; i < ubep->dev_attr.dev_cap.max_eid_cnt; i++) {
        if (memcmp(&ubep->eid_list[i].eid, &invalid_eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }

        admin_urma_topo_bonding_dev_t bonding_dev = {0};
        if (admin_cmd_get_topo_bonding_dev_by_eid(&ubep->eid_list[i].eid, &bonding_dev) != 0) {
            continue;
        }
        for (uint32_t j = 0; j < IODIE_NUM; j++) {
            if (bonding_dev.physical_devs[j].dev_name[0] == '\0') {
                continue;
            }
            (void)snprintf(ubep->phy_dev_names[j], URMA_ADMIN_MAX_DEV_NAME, "%s",
                           bonding_dev.physical_devs[j].dev_name);
            ubep->phy_primary_eid_idx[j] = bonding_dev.physical_devs[j].primary_eid_idx;
            for (uint32_t k = 0; k < PORT_NUM; k++) {
                ubep->phy_port_eid_idx[j][k] = bonding_dev.physical_devs[j].port_eid_idx[k];
            }
        }
        return;
    }
}

static void format_phy_dev_names(const admin_show_ubep_t *ubep, char *buf, size_t buf_len)
{
    if (ubep == NULL || buf == NULL || buf_len == 0) {
        return;
    }

    if (ubep->is_bonding_dev == false) {
        (void)snprintf(buf, buf_len, "-");
        return;
    }

    bool first = true;
    int offset = 0;
    for (uint32_t i = 0; i < IODIE_NUM; i++) {
        if (ubep->phy_dev_names[i][0] == '\0') {
            continue;
        }
        int ret = snprintf(buf + offset, buf_len - (size_t)offset, "%s%s", first ? "" : ",", ubep->phy_dev_names[i]);
        if (ret < 0) {
            return;
        }
        if ((size_t)ret >= buf_len - (size_t)offset) {
            return;
        }
        offset += ret;
        first = false;
    }
    if (first) {
        (void)snprintf(buf, buf_len, "-");
    }
}

static void print_ubep_simple_info(admin_show_ubep_t *ubep, int *index, bool show_phy_dev_col)
{
    bool need_print_sub_eids = (show_phy_dev_col && ubep->is_bonding_dev);
    char phy_dev_names[URMA_ADMIN_MAX_DEV_NAME * IODIE_NUM] = {0};
    if (show_phy_dev_col) {
        format_phy_dev_names(ubep, phy_dev_names, sizeof(phy_dev_names));
    }

    if (get_valid_eid_cnt(ubep) == 0) {
        if (show_phy_dev_col) {
            (void)printf("%-3d  %-16s    %-56s    %-8s    %-16s    %-24s\n", (*index)++, ubep->dev_name,
                         urma_tp_type_to_string(ubep->tp_type),
                         urma_port_state_to_string(ubep->dev_attr.port_attr[0].state), ubep->net_dev_name,
                         phy_dev_names);
        } else {
            (void)printf("%-3d  %-16s    %-56s    %-8s    %-16s \n", (*index)++, ubep->dev_name,
                         urma_tp_type_to_string(ubep->tp_type),
                         urma_port_state_to_string(ubep->dev_attr.port_attr[0].state), ubep->net_dev_name);
        }
        if (need_print_sub_eids) {
            print_related_udma_eids(ubep, index, show_phy_dev_col);
        }

        return;
    }
    urma_eid_t eid = {0};

    for (uint32_t i = 0; i < ubep->dev_attr.dev_cap.max_eid_cnt; i++) {
        if (memcmp(&ubep->eid_list[i].eid, &eid, sizeof(urma_eid_t)) == 0) {
            continue;
        }
        if (show_phy_dev_col) {
            (void)printf("%-3d  %-16s    %-8s    eid%u " EID_FMT "    %-8s    %-24s\n", (*index)++, ubep->dev_name,
                         urma_tp_type_to_string(ubep->tp_type), ubep->eid_list[i].eid_index,
                         EID_ARGS(ubep->eid_list[i].eid), urma_port_state_to_string(ubep->dev_attr.port_attr[0].state),
                         phy_dev_names);
        } else {
            (void)printf("%-3d  %-16s    %-8s    eid%u " EID_FMT "    %-8s\n", (*index)++, ubep->dev_name,
                         urma_tp_type_to_string(ubep->tp_type), ubep->eid_list[i].eid_index,
                         EID_ARGS(ubep->eid_list[i].eid), urma_port_state_to_string(ubep->dev_attr.port_attr[0].state));
        }
    }
    if (need_print_sub_eids) {
        print_related_udma_eids(ubep, index, show_phy_dev_col);
    }
}

static inline void print_device_feat_str(urma_device_feature_t feat)
{
    uint8_t i;

    (void)printf("feature                    : 0x%x [", feat.value);
    for (i = 0; i < URMA_DEVICE_FEAT_NUM; i++) {
        if ((feat.value & (1 << i)) != 0) {
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
        if ((feat.value & (1 << i)) != 0) {
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
        if ((cc_alg & (1 << i)) != 0) {
            (void)printf("%s ", urma_congestion_ctrl_alg_to_string(i));
        }
    }
    (void)printf("]\n");
}

static void print_trans_mode_str(uint16_t trans_mode)
{
    (void)printf("trans_mode                 : 0x%x [", (uint32_t)trans_mode);
    if ((trans_mode & URMA_TM_RM) != 0) {
        (void)printf("%s ", urma_trans_mode_to_string(URMA_TM_RM));
    }
    if ((trans_mode & URMA_TM_RC) != 0) {
        (void)printf("%s ", urma_trans_mode_to_string(URMA_TM_RC));
    }
    if ((trans_mode & URMA_TM_UM) != 0) {
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

static void print_related_udma_eids(admin_show_ubep_t *ubep, int *index, bool show_phy_dev_col)
{
    if (ubep == NULL || ubep->is_bonding_dev == false) {
        return;
    }
    /* Refresh relation from kernel before each display. */
    parse_bonding_phy_devs(ubep);

    for (uint32_t i = 0; i < IODIE_NUM; i++) {
        if (ubep->phy_dev_names[i][0] == '\0') {
            continue;
        }
        admin_show_ubep_t *phy_ubep = admin_get_ubep_info_by_name(ubep->phy_dev_names[i], NULL);
        if (phy_ubep == NULL) {
            continue;
        }
        int tmp_index = 0;
        int *cur_index = (index == NULL) ? &tmp_index : index;
        char phy_dev_names[URMA_ADMIN_MAX_DEV_NAME * IODIE_NUM] = {0};
        if (show_phy_dev_col) {
            format_phy_dev_names(phy_ubep, phy_dev_names, sizeof(phy_dev_names));
        }

        for (uint32_t eid_i = 0; eid_i < phy_ubep->dev_attr.dev_cap.max_eid_cnt; eid_i++) {
            if (!is_eid_idx_related_to_bonding(ubep, i, phy_ubep->eid_list[eid_i].eid_index)) {
                continue;
            }
            if (!admin_is_eid_valid((const char *)&phy_ubep->eid_list[eid_i].eid)) {
                continue;
            }
            if (show_phy_dev_col) {
                (void)printf("%-3d  %-16s    %-8s    eid%u " EID_FMT "    %-8s    %-24s\n", (*cur_index)++,
                             phy_ubep->dev_name, urma_tp_type_to_string(phy_ubep->tp_type),
                             phy_ubep->eid_list[eid_i].eid_index, EID_ARGS(phy_ubep->eid_list[eid_i].eid),
                             urma_port_state_to_string(phy_ubep->dev_attr.port_attr[0].state), phy_dev_names);
            } else {
                (void)printf("%-3d  %-16s    %-8s    eid%u " EID_FMT "    %-8s\n", (*cur_index)++,
                             phy_ubep->dev_name, urma_tp_type_to_string(phy_ubep->tp_type),
                             phy_ubep->eid_list[eid_i].eid_index, EID_ARGS(phy_ubep->eid_list[eid_i].eid),
                             urma_port_state_to_string(phy_ubep->dev_attr.port_attr[0].state));
            }
        }
        free(phy_ubep->eid_list);
        free(phy_ubep);
    }
}

static bool is_eid_idx_related_to_bonding(const admin_show_ubep_t *bonding_ubep, uint32_t phy_idx, uint32_t eid_idx)
{
    if (bonding_ubep == NULL || phy_idx >= IODIE_NUM) {
        return false;
    }
    if (bonding_ubep->phy_primary_eid_idx[phy_idx] == eid_idx) {
        return true;
    }
    for (uint32_t i = 0; i < PORT_NUM; i++) {
        if (bonding_ubep->phy_port_eid_idx[phy_idx][i] == eid_idx) {
            return true;
        }
    }
    return false;
}

static void print_ubep_prioritys(const admin_show_ubep_t *ubep)
{
    printf("priority  :    0    1    2    3    4    5    6    7    8    9   10   11   12   13   14   15\n");
    printf("      sl  :");
    for (int i = 0; i < URMA_MAX_PRIORITY_CNT; ++i) {
        printf("%5d", ubep->dev_attr.dev_cap.priority_info[i].SL);
    }
    printf("\n");
    printf(" tp_type  :");
    for (int i = 0; i < URMA_MAX_PRIORITY_CNT; ++i) {
        printf("  %s", urma_tp_type_en_to_string(ubep->dev_attr.dev_cap.priority_info[i].tp_type));
    }
    printf("\n");
}

static void print_ubep_whole_info(admin_show_ubep_t *ubep, int *index, const admin_config_t *cfg)
{
    (void)index;
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
    print_ubep_prioritys(ubep);
    if (cfg->specify_device && ubep->is_bonding_dev) {
        char phy_dev_names[URMA_ADMIN_MAX_DEV_NAME * IODIE_NUM] = {0};
        format_phy_dev_names(ubep, phy_dev_names, sizeof(phy_dev_names));
        (void)printf("physical_devs              : %s\n", phy_dev_names);
        (void)printf("sub_udma_devs eids:\n");
        (void)printf("num  ubep_dev            tp_type     eid                                             link        sub_udma_devs\n");
        (void)printf("---  ----------------    --------    --------------------------------------------    --------    ------------------------\n");
        int sub_idx = 0;
        print_related_udma_eids(ubep, &sub_idx, true);
    }
    (void)printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}

static bool ubep_list_has_bonding_dev(const struct ub_list *ubep_list)
{
    admin_show_ubep_t *ubep, *next;
    UB_LIST_FOR_EACH_SAFE (ubep, next, node, ubep_list) {
        if (ubep == NULL) {
            break;
        }
        if (ubep->is_bonding_dev) {
            return true;
        }
    }
    return false;
}

static void print_ubep_list(const struct ub_list *ubep_list, const admin_config_t *cfg)
{
    int cnt = 0;
    admin_show_ubep_t *ubep, *next;
    bool has_bonding_dev = ubep_list_has_bonding_dev(ubep_list);
    bool brief_only_bonding = (!cfg->specify_device && cfg->brief_info && has_bonding_dev);
    bool show_phy_dev_col = (cfg->specify_device && has_bonding_dev);

    if (cfg->whole_info == false) {
        if (show_phy_dev_col) {
            (void)printf("num  ubep_dev            tp_type     eid                                             link        sub_udma_devs\n");
            (void)printf("---  ----------------    --------    --------------------------------------------    --------    ------------------------\n");
        } else {
            (void)printf("num  ubep_dev            tp_type     eid                                             link\n");
            (void)printf("---  ----------------    --------    --------------------------------------------    --------\n");
        }
    }

    UB_LIST_FOR_EACH_SAFE (ubep, next, node, ubep_list) {
        if (ubep == NULL) {
            break;
        }
        if (brief_only_bonding && !ubep->is_bonding_dev) {
            continue;
        }
        if (cfg->whole_info == false) {
            print_ubep_simple_info(ubep, &cnt, show_phy_dev_col);
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

static int cmd_show_dev_usage(admin_config_t *cfg)
{
    (void)cfg;
    printf("Usage:\n"
           "  urma_admin show dev <DEV>\n"
           "  urma_admin show dev <DEV> jfc   [JFC_ID]\n"
           "  urma_admin show dev <DEV> jfs   [JFS_ID]\n"
           "  urma_admin show dev <DEV> jfr   [JFR_ID]\n"
           "  urma_admin show dev <DEV> jetty [JETTY_ID]\n"
           "  urma_admin show dev <DEV> jetty_group [JETTY_GROUP_ID]\n"
           "  urma_admin show dev <DEV> rc    [RC_ID]\n"
           "  urma_admin show dev <DEV> seg   [TOKEN_ID]\n"
           "  urma_admin show dev <dev> tp           Show all tpid_list of <dev>\n"
           "  urma_admin show dev <dev> tp <tp_id>   Show state of <tp_id> on <dev>\n"
           "  urma_admin show dev <dev> tpreuse      Show all tpid_reuse of <dev>\n");
    return 0;
}

static bool is_eid_equal(const urma_eid_t *eid1, const urma_eid_t *eid2)
{
    for (int i = 0; i < URMA_EID_SIZE; i++) {
        if (eid1->raw[i] != eid2->raw[i]) {
            return false;
        }
    }
    return true;
}

int admin_get_device_name_by_eid(const urma_eid_t *eid, char *dev_name, size_t dev_name_len)
{
    int ret = 0;
    struct ub_list ubep_list;
    admin_show_ubep_t *ubep, *next;
    admin_config_t cfg = {0};
    cfg.specify_device = false;

    ub_list_init(&ubep_list);
    ret = find_ubep_list(&ubep_list, &cfg);
    if (ret != 0) {
        (void)printf("Failed to find ubep.\n");
        goto free_list;
    }

    UB_LIST_FOR_EACH_SAFE (ubep, next, node, &ubep_list) {
        if (ubep == NULL) {
            break;
        }
        for (uint32_t i = 0; i < ubep->dev_attr.dev_cap.max_eid_cnt; i++) {
            if (is_eid_equal(&ubep->eid_list[i].eid, eid)) {
                if (dev_name_len == 0 || snprintf(dev_name, dev_name_len, "%s", ubep->dev_name) < 0) {
                    ret = -1;
                }
                goto free_list;
            }
        }
    }
    ret = -1; // not found

free_list:
    free_ubep_list(&ubep_list);
    return ret;
}

int admin_get_eid_list_by_eid(urma_eid_t *eid, urma_eid_info_t **eid_info_list, char *dev_name)
{
    int ret = 0;
    int dev_fd = -1;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char dev_path[URMA_MAX_PATH] = {0};
    urma_eid_info_t *tmp_eid_list = NULL;
    uint32_t eid_cnt = 0;
    bool found = false;

    if (eid == NULL || dev_name == NULL || eid_info_list == NULL) {
        printf("Invalid input parameters.\n");
        return -1;
    }

    dir = opendir("/dev/uburma");
    if (dir == NULL) {
        printf("Failed to open /dev/uburma directory.\n");
        return -1;
    }

    tmp_eid_list = (urma_eid_info_t *)calloc(1, URMA_MAX_EID_CNT * sizeof(urma_eid_info_t));
    if (tmp_eid_list == NULL) {
        printf("Failed to allocate memory for EID list.\n");
        closedir(dir);
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (snprintf(dev_path, URMA_MAX_PATH, "%s/%s", "/dev/uburma", entry->d_name) <= 0) {
            printf("Failed to construct device path.\n");
            continue;
        }

        dev_fd = urma_open_cdev(dev_path);
        if (dev_fd < 0) {
            printf("Failed to open device %s\n", entry->d_name);
            continue;
        }

        ret = urma_cmd_get_eid_list(dev_fd, URMA_MAX_EID_CNT, tmp_eid_list, &eid_cnt);
        if (ret != 0) {
            printf("Device %s has no EID configured\n", entry->d_name);
            close(dev_fd);
            continue;
        }

        for (uint32_t i = 0; i < eid_cnt; i++) {
            if (memcmp(&tmp_eid_list[i].eid, eid, sizeof(urma_eid_t)) == 0) {
                size_t name_len = strnlen(entry->d_name, URMA_MAX_NAME - 1);
                found = true;
                (void)memcpy(dev_name, entry->d_name, name_len);
                dev_name[name_len] = '\0';
                *eid_info_list = tmp_eid_list;
                break;
            }
        }

        close(dev_fd);

        if (found) {
            break;
        }
    }
    closedir(dir);

    if (!found) {
        printf("EID not found.\n");
        urma_free_eid_list(tmp_eid_list);
        return -1;
    }

    return 0;
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

static void urma_eid_to_ipv6_str(const urma_eid_t *eid, char *out, size_t out_len)
{
    int ret = snprintf(out, out_len, EID_FMT, EID_RAW_ARGS(eid->raw));
    if (ret <= 0 || (size_t)ret >= out_len) {
        (void)printf("Failed convert eid to full format, ret = %d.\n", ret);
    }
}

static tool_topo_info_t *admin_find_topo_node(tool_topo_map_t *topo_map, uint32_t node_id)
{
    if (topo_map == NULL) {
        return NULL;
    }
    for (uint32_t i = 0; i < topo_map->node_num; i++) {
        if (topo_map->topo_infos[i].node_id == node_id) {
            return &topo_map->topo_infos[i];
        }
    }
    return NULL;
}

static int admin_collect_related_agg_dev_idxs(const tool_topo_info_t *node_info, const char *dev_name, bool *matched,
                                              uint32_t *matched_cnt, admin_urma_topo_bonding_dev_t *bonding_cache,
                                              bool *cache_valid)
{
    if (node_info == NULL || dev_name == NULL || matched == NULL || matched_cnt == NULL || bonding_cache == NULL ||
        cache_valid == NULL) {
        return -EINVAL;
    }
    *matched_cnt = 0;
    for (uint32_t i = 0; i < DEV_NUM; i++) {
        matched[i] = false;
        cache_valid[i] = false;
    }

    for (uint32_t i = 0; i < DEV_NUM; i++) {
        const tool_topo_agg_dev_t *agg_dev = &node_info->agg_devs[i];
        if (!admin_is_eid_valid(agg_dev->agg_eid)) {
            continue;
        }

        if (admin_cmd_get_topo_bonding_dev_by_eid((const urma_eid_t *)agg_dev->agg_eid, &bonding_cache[i]) != 0) {
            continue;
        }
        cache_valid[i] = true;

        if (strcmp(dev_name, bonding_cache[i].dev_name) == 0) {
            matched[i] = true;
            (*matched_cnt)++;
            continue;
        }

        for (uint32_t iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
            if (strcmp(dev_name, bonding_cache[i].physical_devs[iodie_idx].dev_name) == 0) {
                matched[i] = true;
                (*matched_cnt)++;
                break;
            }
        }
    }
    return *matched_cnt == 0 ? -ENODEV : 0;
}

static int admin_print_topo_map(tool_topo_map_t *topo_map, uint32_t node_id, const admin_config_t *cfg)
{
    (void)printf("========================== topo map start =============================\n");
    bool matched_agg_devs[DEV_NUM] = {0};
    bool bonding_cache_valid[DEV_NUM] = {0};
    admin_urma_topo_bonding_dev_t bonding_cache[DEV_NUM] = {0};
    uint32_t matched_cnt = 0;
    tool_topo_info_t *cur_node_info = admin_find_topo_node(topo_map, node_id);
    if (cur_node_info == NULL) {
        (void)printf("Node %d topo info not found.\n", node_id);
        return -ENODEV;
    }

    if (cfg != NULL && cfg->specify_device) {
        int ret = admin_collect_related_agg_dev_idxs(cur_node_info, cfg->dev_name, matched_agg_devs, &matched_cnt,
                                                     bonding_cache, bonding_cache_valid);
        if (ret != 0) {
            (void)printf("Device %s has no related aggregation device.\n", cfg->dev_name);
            return ret;
        }
    }
    (void)printf("===================== show node %d topo info =======================\n", node_id);
    for (uint32_t iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
        (void)printf("IODie %d:\n", iodie_idx);
        for (uint32_t port_idx = 0; port_idx < PORT_NUM; port_idx++) {
            uint32_t idx = iodie_idx * PORT_NUM + port_idx;
            bool has_connection = false;
            bool first_line = true;
            for (uint32_t remote_idx = 0; remote_idx < IODIE_NUM * PORT_NUM; remote_idx++) {
                if (cur_node_info->links[idx][remote_idx]) {
                    uint32_t remote_iodie = remote_idx / PORT_NUM;
                    uint32_t remote_port = remote_idx % PORT_NUM;
                    if (first_line) {
                        (void)printf("Port %d: Connected to IODie %d, Port %d\n",
                                     port_idx, remote_iodie, remote_port);
                        first_line = false;
                    } else {
                        (void)printf("        Connected to IODie %d, Port %d\n",
                                     remote_iodie, remote_port);
                    }
                    has_connection = true;
                }
            }
            if (!has_connection) {
                (void)printf("Port %d: Not connected\n", port_idx);
            }
        }
        (void)printf("\n");
    }
    char eid_str[INET6_ADDRSTRLEN];
    for (uint32_t agg_dev_idx = 0; agg_dev_idx < DEV_NUM; agg_dev_idx++) {
        if (cfg != NULL && cfg->specify_device && matched_agg_devs[agg_dev_idx] == false) {
            continue;
        }
        admin_urma_topo_bonding_dev_t bonding_dev = {0};
        bool has_bonding_name = false;
        tool_topo_agg_dev_t *agg_dev = &cur_node_info->agg_devs[agg_dev_idx];
        if (!admin_is_eid_valid(agg_dev->agg_eid)) {
            continue;
        }
        urma_eid_to_ipv6_str((urma_eid_t *)agg_dev->agg_eid, eid_str, sizeof(eid_str));
        if (bonding_cache_valid[agg_dev_idx]) {
            bonding_dev = bonding_cache[agg_dev_idx];
            has_bonding_name = bonding_dev.dev_name[0] != '\0';
        } else if (admin_cmd_get_topo_bonding_dev_by_eid((urma_eid_t *)agg_dev->agg_eid, &bonding_dev) == 0 &&
                   bonding_dev.dev_name[0] != '\0') {
            has_bonding_name = true;
        }
        if (has_bonding_name) {
            (void)printf("Dev %d (%s): %s\n", agg_dev_idx, bonding_dev.dev_name, eid_str);
        } else {
            (void)printf("Dev %d: %s\n", agg_dev_idx, eid_str);
        }
        for (uint32_t iodie_idx = 0; iodie_idx < IODIE_NUM; iodie_idx++) {
            tool_topo_ue_t *ue = &agg_dev->ues[iodie_idx];
            if (!admin_is_eid_valid(ue->primary_eid)) {
                continue;
            }
            urma_eid_to_ipv6_str((urma_eid_t *)ue->primary_eid, eid_str, sizeof(eid_str));

            if (has_bonding_name && bonding_dev.physical_devs[iodie_idx].dev_name[0] != '\0') {
                printf("\t UE %d (%s):\n", iodie_idx, bonding_dev.physical_devs[iodie_idx].dev_name);
            } else {
                printf("\t UE %d:\n", iodie_idx);
            }
            printf("\t\t Chip id: %d\n", ue->chip_id);
            printf("\t\t Die id: %d\n", ue->die_id);
            printf("\t\t Entity id: %d\n", ue->entity_id);
            printf("\t\t Primary eid:\n");
            printf("\t\t\t %s\n", eid_str);

            printf("\t\t Port eid:\n");
            for (uint32_t port_idx = 0; port_idx < PORT_NUM; port_idx++) {
                if (!admin_is_eid_valid(ue->port_eid[port_idx])) {
                    (void)printf("\t\t\t Port %d: Invalid EID\n", port_idx);
                } else {
                    urma_eid_to_ipv6_str((urma_eid_t *)ue->port_eid[port_idx], eid_str, sizeof(eid_str));
                    (void)printf("\t\t\t Port %d: %s\n", port_idx, eid_str);
                }
            }
        }
    }
    (void)printf("========================== topo map end =============================\n");
    return 0;
}

static uint32_t get_cur_node_id(tool_topo_map_t *topo_map)
{
    uint32_t node_id = 0;
    for (uint32_t i = 0; i < topo_map->node_num; i++) {
        tool_topo_info_t *cur_node_info = topo_map->topo_infos + i;
        if (cur_node_info->is_current != 0) {
            node_id = cur_node_info->node_id;
            break;
        }
    }
    return node_id;
}

int admin_cmd_get_topo_info(tool_topo_map_t *topo_map)
{
    int ret = 0;
    admin_core_cmd_topo_info_t *arg = NULL;
    uint32_t node_num = MAX_NODE_NUM;
    for (uint32_t i = 0; i < node_num; ++i) {
        arg = calloc(1, sizeof(admin_core_cmd_topo_info_t));
        if (arg == NULL) {
            ret = -ENOMEM;
            goto free_topo;
        }
        arg->in.node_idx = i;

        struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_GET_TOPO_INFO, 0, UBCORE_GENL);
        if (msg == NULL) {
            ret = -ENOMEM;
            goto free_topo;
        }

        admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(admin_core_cmd_topo_info_t));
        admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)arg);
        ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
        admin_nl_free_msg(msg);
        if (ret < 0) {
            goto free_topo;
        }

        topo_map->topo_infos[i] = arg->out.topo_info;
        topo_map->node_num = arg->out.node_num;
        node_num = arg->out.node_num;
        free(arg);
    }
    return ret;
free_topo:
    free(arg);
    return ret;
}

int admin_cmd_get_topo_bonding_dev_by_eid(const urma_eid_t *agg_eid,
    admin_urma_topo_bonding_dev_t *out)
{
    int ret;
    admin_core_cmd_topo_bonding_dev_t *arg = NULL;

    if (agg_eid == NULL || out == NULL) {
        return -EINVAL;
    }

    arg = calloc(1, sizeof(admin_core_cmd_topo_bonding_dev_t));
    if (arg == NULL) {
        return -ENOMEM;
    }
    arg->in.agg_eid = *agg_eid;

    struct nl_msg *msg = admin_nl_alloc_msg(UBAGG_NL_GET_PHYSICAL_DEVICE, 0, UBAGG_GENL);
    if (msg == NULL) {
        free(arg);
        return -ENOMEM;
    }
    admin_nl_put_u64(msg, UBAGG_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)arg);
    ret = admin_nl_send_recv_msg_default_silent_errno(msg, -NLE_OBJ_NOTFOUND, UBAGG_GENL);
    if (ret == 0) {
        memcpy(out, &arg->out.bonding_dev, sizeof(admin_urma_topo_bonding_dev_t));
    }
    admin_nl_free_msg(msg);
    free(arg);
    return ret;
}

static const char *tpid_status_to_string(uint32_t status)
{
    static const char * const tpid_status_str[] = {
        "RESET", "RTR", "RTS", "SUSPENDED", "ERR",
    };
    if (status >= (sizeof(tpid_status_str) / sizeof(tpid_status_str[0]))) {
        return "UNKNOWN";
    }
    return tpid_status_str[status];
}

static const char *tpid_trans_mode_to_string(uint32_t trans_mode)
{
    switch (trans_mode) {
        case URMA_TM_RM:
            return "RM";
        case URMA_TM_RC:
            return "RC";
        case URMA_TM_UM:
            return "UM";
        default:
            return "UNKNOWN";
    }
}

static const char *tpid_tp_type_to_string(uint32_t tp_type)
{
    static const char * const tp_type_str[] = {
        "RTP", "CTP", "UTP",
    };
    if (tp_type >= (sizeof(tp_type_str) / sizeof(tp_type_str[0]))) {
        return "UNKNOWN";
    }
    return tp_type_str[tp_type];
}

static const char *tpid_share_mode_to_string(uint32_t share_mode)
{
    static const char * const share_mode_str[] = {
        "NONE", "NODE", "CONTAINER", "JETTY", "CUSTOM",
    };
    if (share_mode >= (sizeof(share_mode_str) / sizeof(share_mode_str[0]))) {
        return "UNKNOWN";
    }
    return share_mode_str[share_mode];
}

static const char *tpid_link_type_to_string(uint32_t link_type)
{
    switch (link_type) {
        case 0:
            return "ETHERNET";
        case 1:
            return "UBOE";
        default:
            return "UNKNOWN";
    }
}

static const char *tpid_owner_type_to_string(uint32_t owner_type)
{
    static const char * const owner_type_str[] = {
        "NONE", "USER_AWARE", "USER_UNAWARE",
    };
    if (owner_type >= (sizeof(owner_type_str) / sizeof(owner_type_str[0]))) {
        return "UNKNOWN";
    }
    return owner_type_str[owner_type];
}

static void print_tpid_list_hdr(const admin_show_tpid_list_hdr_t *hdr, uint32_t index)
{
    char local_eid_str[INET6_ADDRSTRLEN] = {0};
    char peer_eid_str[INET6_ADDRSTRLEN] = {0};

    urma_eid_to_ipv6_str(&hdr->local_eid, local_eid_str, sizeof(local_eid_str));
    urma_eid_to_ipv6_str(&hdr->peer_eid, peer_eid_str, sizeof(peer_eid_str));

    (void)printf("==================== tpid_list[%u] ====================\n", index);
    (void)printf("local_eid     : %s\n", local_eid_str);
    (void)printf("peer_eid      : %s\n", peer_eid_str);
    (void)printf("trans_mode    : %u [%s]\n", hdr->trans_mode, tpid_trans_mode_to_string(hdr->trans_mode));
    (void)printf("share_mode    : %u [%s]\n", hdr->share_mode, tpid_share_mode_to_string(hdr->share_mode));
    (void)printf("tp_type       : %u [%s]\n", hdr->tp_type, tpid_tp_type_to_string(hdr->tp_type));
    (void)printf("link_type     : %u [%s]\n", hdr->link_type, tpid_link_type_to_string(hdr->link_type));
    (void)printf("acnt          : %u\n", hdr->acnt);
    (void)printf("ucnt          : %u\n", hdr->ucnt);
    (void)printf("capacity      : %u\n", hdr->capacity);
    (void)printf("ref_cnt       : %u\n", hdr->ref_cnt);
    (void)printf("aware_list    : %u node(s)\n", hdr->aware_node_cnt);
    (void)printf("unaware_list  : %u node(s)\n", hdr->unaware_node_cnt);
}

static void print_tpid_node(const admin_show_tpid_node_t *node, const char *kind)
{
    admin_tp_handle_t h;

    h.value = node->tp_handle;
    (void)printf("  [%-7s] tp_handle=0x%-16llx tpid=%-10llu\n", kind,
                 (unsigned long long)node->tp_handle, (unsigned long long)h.bs.tpid);
    (void)printf("            tpn_start=%-10llu tp_cnt=%-5llu trans_mode=%llu [%s]\n",
                 (unsigned long long)h.bs.tpn_start, (unsigned long long)h.bs.tp_cnt,
                 (unsigned long long)h.bs.trans_mode,
                 tpid_trans_mode_to_string((uint32_t)h.bs.trans_mode));
    (void)printf("            ctp=%llu rtp=%llu utp=%llu uboe=%llu pre_defined=%llu dynamic_defined=%llu\n",
                 (unsigned long long)h.bs.ctp, (unsigned long long)h.bs.rtp,
                 (unsigned long long)h.bs.utp, (unsigned long long)h.bs.uboe,
                 (unsigned long long)h.bs.pre_defined, (unsigned long long)h.bs.dynamic_defined);
}

static const char *tpid_reuse_state_to_string(uint32_t state)
{
    static const char * const reuse_state_str[] = {
        "RESET", "READY", "ERROR",
    };
    if (state >= (sizeof(reuse_state_str) / sizeof(reuse_state_str[0]))) {
        return "UNKNOWN";
    }
    return reuse_state_str[state];
}

static void print_tpid_reuse_one(const admin_show_tpid_reuse_entry_t *entry, uint32_t index)
{
    char local_eid_str[INET6_ADDRSTRLEN] = {0};
    char peer_eid_str[INET6_ADDRSTRLEN] = {0};

    urma_eid_to_ipv6_str(&entry->local_eid, local_eid_str, sizeof(local_eid_str));
    urma_eid_to_ipv6_str(&entry->peer_eid, peer_eid_str, sizeof(peer_eid_str));

    (void)printf("==================== tpid_reuse[%u] ====================\n", index);
    (void)printf("local_eid     : %s\n", local_eid_str);
    (void)printf("peer_eid      : %s\n", peer_eid_str);
    (void)printf("trans_mode    : %u [%s]\n", entry->trans_mode, tpid_trans_mode_to_string(entry->trans_mode));
    (void)printf("share_mode    : %u [%s]\n", entry->share_mode, tpid_share_mode_to_string(entry->share_mode));
    (void)printf("tp_type       : %u [%s]\n", entry->tp_type, tpid_tp_type_to_string(entry->tp_type));
    (void)printf("link_type     : %u [%s]\n", entry->link_type, tpid_link_type_to_string(entry->link_type));
    (void)printf("stag          : 0x%llx\n", (unsigned long long)entry->stag);
    (void)printf("dtag          : 0x%llx\n", (unsigned long long)entry->dtag);
    (void)printf("tp_handle     : 0x%llx\n", (unsigned long long)entry->tp_handle);
    (void)printf("reuse_state   : %u [%s]\n", entry->reuse_state, tpid_reuse_state_to_string(entry->reuse_state));
    (void)printf("ref_cnt       : %u\n", entry->ref_cnt);
    (void)printf("use_cnt       : %d\n", entry->use_cnt);
}

typedef struct tpid_show_print_ctx {
    const char *dev_name;
    uint64_t tpid;
    uint32_t list_idx;
    uint32_t reuse_idx;
    bool any;
} tpid_show_print_ctx_t;

/* Parse one streamed dumpit record and print it. Called per netlink message. */
static int tpid_show_msg_cb(struct nl_msg *msg, void *arg)
{
    tpid_show_print_ctx_t *ctx = (tpid_show_print_ctx_t *)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct nlattr *attrs[ADMIN_TPID_SHOW_ATTR_MAX + 1];
    uint32_t rec_type;
    uint32_t dlen;
    void *data;

    if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
        return NL_OK;
    }
    if (genlmsg_parse(nlh, 0, attrs, ADMIN_TPID_SHOW_ATTR_MAX, NULL) < 0) {
        return NL_OK;
    }
    if (attrs[ADMIN_TPID_SHOW_ATTR_REC_TYPE] == NULL || attrs[ADMIN_TPID_SHOW_ATTR_REC_DATA] == NULL) {
        return NL_OK;
    }
    rec_type = nla_get_u32(attrs[ADMIN_TPID_SHOW_ATTR_REC_TYPE]);
    data = nla_data(attrs[ADMIN_TPID_SHOW_ATTR_REC_DATA]);
    dlen = (uint32_t)nla_len(attrs[ADMIN_TPID_SHOW_ATTR_REC_DATA]);
    ctx->any = true;

    switch (rec_type) {
        case ADMIN_TPID_SHOW_REC_LIST_HDR: {
            admin_show_tpid_list_hdr_t hdr = {0};
            if (dlen < sizeof(hdr)) {
                break;
            }
            (void)memcpy(&hdr, data, sizeof(hdr));
            print_tpid_list_hdr(&hdr, ctx->list_idx++);
            break;
        }
        case ADMIN_TPID_SHOW_REC_AWARE_NODE:
        case ADMIN_TPID_SHOW_REC_UNAWARE_NODE: {
            admin_show_tpid_node_t node = {0};
            if (dlen < sizeof(node)) {
                break;
            }
            (void)memcpy(&node, data, sizeof(node));
            print_tpid_node(&node, rec_type == ADMIN_TPID_SHOW_REC_AWARE_NODE ? "aware" : "unaware");
            break;
        }
        case ADMIN_TPID_SHOW_REC_TPID_STATE: {
            admin_show_tpid_state_t st = {0};
            if (dlen < sizeof(st)) {
                break;
            }
            (void)memcpy(&st, data, sizeof(st));
            if (st.found == 0) {
                (void)printf("TP_ID %llu not found on dev %s.\n", (unsigned long long)ctx->tpid, ctx->dev_name);
            } else {
                (void)printf("status        : %u [%s]\n", st.status, tpid_status_to_string(st.status));
                (void)printf("owner_type    : %u [%s]\n", st.owner_type,
                             tpid_owner_type_to_string(st.owner_type));
                (void)printf("alloced       : %u\n", st.alloced);
                (void)printf("ref_cnt       : %u\n", st.ref_cnt);
            }
            break;
        }
        case ADMIN_TPID_SHOW_REC_REUSE_ENTRY: {
            admin_show_tpid_reuse_entry_t entry = {0};
            if (dlen < sizeof(entry)) {
                break;
            }
            (void)memcpy(&entry, data, sizeof(entry));
            print_tpid_reuse_one(&entry, ctx->reuse_idx++);
            break;
        }
        default:
            break;
    }
    return NL_OK;
}

static int admin_cmd_show_tpid_list(admin_config_t *cfg, bool query_tpid, uint64_t tpid)
{
    admin_core_cmd_show_tpid_list_t arg = {0};
    tpid_show_print_ctx_t ctx = {0};
    struct nl_msg *msg;
    int ret;

    (void)snprintf(arg.in.dev_name, URMA_MAX_NAME, "%s", cfg->dev_name);
    arg.in.query_tpid = query_tpid ? 1 : 0;
    arg.in.tpid = tpid;

    msg = admin_nl_alloc_msg(URMA_CORE_SHOW_TPID_LIST, NLM_F_DUMP, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }
    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(arg));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    ctx.dev_name = cfg->dev_name;
    ctx.tpid = tpid;
    if (!query_tpid) {
        (void)printf("dev_name      : %s\n", cfg->dev_name);
    }
    ret = admin_nl_send_recv_msg(msg, tpid_show_msg_cb, &ctx, UBCORE_GENL);
    admin_nl_free_msg(msg);
    if (ret != 0) {
        (void)printf("Failed to query tpid list of dev %s, ret=%d.\n", cfg->dev_name, ret);
        return ret;
    }
    if (!query_tpid && !ctx.any) {
        (void)printf("No tpid_list found.\n");
    }
    return 0;
}

static int cmd_show_dev_tp(admin_config_t *cfg)
{
    int ret;
    bool query_tpid = false;
    uint64_t tpid = 0;

    char *arg_tpid = pop_arg(cfg);
    if (arg_tpid != NULL) {
        ret = admin_str_to_u64(arg_tpid, &tpid);
        if (ret != 0) {
            (void)printf("Invalid TP_ID: %s.\n", arg_tpid);
            return -EINVAL;
        }
        query_tpid = true;
    }

    return admin_cmd_show_tpid_list(cfg, query_tpid, tpid);
}

static int admin_cmd_show_tpid_reuse(admin_config_t *cfg)
{
    admin_core_cmd_show_tpid_reuse_t arg = {0};
    tpid_show_print_ctx_t ctx = {0};
    struct nl_msg *msg;
    int ret;

    (void)snprintf(arg.in.dev_name, URMA_MAX_NAME, "%s", cfg->dev_name);

    msg = admin_nl_alloc_msg(URMA_CORE_SHOW_TPID_REUSE, NLM_F_DUMP, UBCORE_GENL);
    if (msg == NULL) {
        return -ENOMEM;
    }
    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(arg));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    ctx.dev_name = cfg->dev_name;
    (void)printf("dev_name        : %s\n", cfg->dev_name);
    ret = admin_nl_send_recv_msg(msg, tpid_show_msg_cb, &ctx, UBCORE_GENL);
    admin_nl_free_msg(msg);
    if (ret != 0) {
        (void)printf("Failed to query tpid reuse of dev %s, ret=%d.\n", cfg->dev_name, ret);
        return ret;
    }
    if (!ctx.any) {
        (void)printf("No tpid_reuse found.\n");
    }
    return 0;
}

static int cmd_show_dev_tpreuse(admin_config_t *cfg)
{
    return admin_cmd_show_tpid_reuse(cfg);
}

static int cmd_show_topo(admin_config_t *cfg)
{
    uint32_t node_id;
    int ret;
    tool_topo_map_t *topo_map = calloc(1, sizeof(tool_topo_map_t));
    if (topo_map == NULL) {
        return -ENOMEM;
    }
    if ((ret = admin_cmd_get_topo_info(topo_map)) != 0) {
        (void)printf("Failed to get topo info, ret=%d.\n", ret);
        goto free_topo;
    }
    char *arg = pop_arg(cfg);
    ret = admin_str_to_u16(arg, &cfg->idx);
    if (ret == 0) {
        node_id = cfg->idx;
    } else {
        node_id = get_cur_node_id(topo_map);
    }
    ret = admin_print_topo_map(topo_map, node_id, cfg);
    free(topo_map);
    return ret;

free_topo:
    free(topo_map);
    return ret;
}

static int parse_jfx_type(const char *arg, uint32_t *type)
{
    if (arg == NULL || type == NULL) {
        return -EINVAL;
    }
    if (strcmp(arg, "jfs") == 0) {
        *type = ADMIN_SHOW_RES_JFS;
    } else if (strcmp(arg, "jfr") == 0) {
        *type = ADMIN_SHOW_RES_JFR;
    } else if (strcmp(arg, "jetty") == 0) {
        *type = ADMIN_SHOW_RES_JETTY;
    } else if (strcmp(arg, "jfc") == 0) {
        *type = ADMIN_SHOW_RES_JFC;
    } else if (strcmp(arg, "seg") == 0) {
        *type = ADMIN_SHOW_RES_SEG;
    } else {
        (void)printf("Invalid res type: %s, supported: jfs|jfr|jetty|jfc|seg\n", arg);
        return -EINVAL;
    }
    return 0;
}

static void print_v2p_list_res(const uint8_t *buf, uint32_t len, uint32_t type)
{
    uint32_t id_count = len / sizeof(uint32_t);
    const uint32_t *ids = (const uint32_t *)buf;
    const char *type_name = (type == ADMIN_SHOW_RES_JETTY) ? "jetty" :
                            (type == ADMIN_SHOW_RES_JFS) ? "jfs" :
                            (type == ADMIN_SHOW_RES_JFR) ? "jfr" :
                            (type == ADMIN_SHOW_RES_JFC) ? "jfc" :
                            (type == ADMIN_SHOW_RES_SEG) ? "seg" : "unknown";

    (void)printf("---------- %s list ----------\n", type_name);
    (void)printf("count: %u\n", id_count);
    for (uint32_t i = 0; i < id_count; i++) {
        (void)printf("%s_id[%u] = %u\n", type_name, i, ids[i]);
    }
}

static void print_v2p_jetty_detail(const admin_ubagg_jetty_exchange_info_t *info)
{
    (void)printf("enabled_count      : %u\n", info->enabled_count);
    (void)printf("is_health_check    : %s\n", info->is_health_check_enable ? "true" : "false");
    (void)printf("slaves:\n");
    for (uint32_t i = 0; i < UBAGG_DEV_MAX_NUM; i++) {
        if (info->slaves[i].id == 0) {
            continue;
        }
        (void)printf("  slave[%u]: eid=" EID_FMT " uasid=%u id=%u\n",
                     i, EID_ARGS(info->slaves[i].eid),
                     info->slaves[i].uasid, info->slaves[i].id);
    }
}

static void print_v2p_jfc_jfs_detail(const uint8_t *buf, uint32_t len)
{
    uint32_t slave_count = len / sizeof(admin_ubagg_jetty_id_t);
    const admin_ubagg_jetty_id_t *slaves = (const admin_ubagg_jetty_id_t *)buf;
    (void)printf("slaves:\n");
    for (uint32_t i = 0; i < slave_count; i++) {
        if (slaves[i].id == 0) {
            continue;
        }
        (void)printf("  slave[%u]: eid=" EID_FMT " uasid=%u id=%u\n",
                     i, EID_ARGS(slaves[i].eid),
                     slaves[i].uasid, slaves[i].id);
    }
}

static void print_v2p_seg_detail(const admin_ubagg_seg_exchange_info_t *info)
{
    (void)printf("base: eid=" EID_FMT " uasid=%u va=0x%lx len=%lu token_id=%u\n",
                 EID_ARGS(info->base.ubva.eid), info->base.ubva.uasid,
                 info->base.ubva.va, info->base.len, info->base.token_id);
    (void)printf("slaves:\n");
    for (uint32_t i = 0; i < UBAGG_DEV_MAX_NUM; i++) {
        if (info->slaves[i].len == 0) {
            continue;
        }
        (void)printf("  slave[%u]: eid=" EID_FMT " uasid=%u va=0x%lx len=%lu token_id=%u\n",
                     i, EID_ARGS(info->slaves[i].ubva.eid), info->slaves[i].ubva.uasid,
                     info->slaves[i].ubva.va, info->slaves[i].len, info->slaves[i].token_id);
    }
}

static void print_v2p_show_res(const uint8_t *buf, uint32_t len, uint32_t type)
{
    switch (type) {
        case ADMIN_SHOW_RES_JETTY:
        case ADMIN_SHOW_RES_JFR:
            print_v2p_jetty_detail((const admin_ubagg_jetty_exchange_info_t *)buf);
            break;
        case ADMIN_SHOW_RES_JFS:
        case ADMIN_SHOW_RES_JFC:
            print_v2p_jfc_jfs_detail(buf, len);
            break;
        case ADMIN_SHOW_RES_SEG:
            print_v2p_seg_detail((const admin_ubagg_seg_exchange_info_t *)buf);
            break;
        default:
            (void)printf("Unsupported res type: %u\n", type);
            break;
    }
}

static int admin_cmd_show_dev_res(const char *dev_name, uint32_t type,
    uint32_t key, uint32_t key_cnt)
{
    int ret;
    uint8_t *out_buf = NULL;
    admin_core_cmd_show_res_t arg = {0};

    out_buf = calloc(1, ADMIN_V2P_RES_BUF_SIZE);
    if (out_buf == NULL) {
        return -ENOMEM;
    }

    (void)strncpy(arg.in.dev_name, dev_name, URMA_MAX_NAME - 1);
    arg.in.type = type;
    arg.in.key = key;
    arg.in.key_cnt = key_cnt;
    arg.out.addr = (uint64_t)(uintptr_t)out_buf;
    arg.out.len = ADMIN_V2P_RES_BUF_SIZE;

    struct nl_msg *msg = admin_nl_alloc_msg(URMA_CORE_GET_V2P_RES, 0, UBCORE_GENL);
    if (msg == NULL) {
        free(out_buf);
        return -ENOMEM;
    }

    admin_nl_put_u32(msg, UBCORE_HDR_ARGS_LEN, (uint32_t)sizeof(admin_core_cmd_show_res_t));
    admin_nl_put_u64(msg, UBCORE_HDR_ARGS_ADDR, (uint64_t)(uintptr_t)&arg);

    ret = admin_nl_send_recv_msg_default(msg, UBCORE_GENL);
    admin_nl_free_msg(msg);
    if (ret != 0) {
        (void)printf("Failed to query v2p res, ret=%d.\n", ret);
        free(out_buf);
        return ret;
    }

    if (key_cnt == 0) {
        print_v2p_list_res(out_buf, arg.out.len, type);
    } else {
        print_v2p_show_res(out_buf, arg.out.len, type);
    }

    free(out_buf);
    return 0;
}

static int cmd_show_dev_bonding(admin_config_t *cfg)
{
    int ret;
    char *arg;

    uint32_t type;
    arg = pop_arg(cfg);
    if (arg == NULL) {
        (void)printf("No res type specified.\n");
        return -EINVAL;
    }
    ret = parse_jfx_type(arg, &type);
    if (ret != 0) {
        return ret;
    }

    arg = pop_arg(cfg);
    if (arg != NULL) {
        uint32_t jfx_id;
        ret = admin_str_to_u32(arg, &jfx_id);
        if (ret != 0) {
            (void)printf("Invalid jfx_id: %s\n", arg);
            return -EINVAL;
        }
        return admin_cmd_show_dev_res(cfg->dev_name, type, jfx_id, 1);
    }

    return admin_cmd_show_dev_res(cfg->dev_name, type, 0, 0);
}

static int cmd_show_dev(admin_config_t *cfg)
{
    int ret;

    if ((ret = pop_arg_dev(cfg)) != 0) {
        return ret;
    }

    if (cfg->argc == 0) {
        return cmd_show_default(cfg);
    }

    if (strncmp(cfg->dev_name, "bonding_dev", strlen("bonding_dev")) == 0) {
        return cmd_show_dev_bonding(cfg);
    }

    static const admin_cmd_t cmds[] = {
        {NULL, cmd_show_dev_usage},
        {"jfc", admin_cmd_show_dev_jfc},
        {"jfs", admin_cmd_show_dev_jfs},
        {"jfr", admin_cmd_show_dev_jfr},
        {"jetty", admin_cmd_show_dev_jetty},
        {"jetty_group", admin_cmd_show_dev_jetty_group},
        {"rc", admin_cmd_show_dev_rc},
        {"seg", admin_cmd_show_dev_seg},
        {"tp", cmd_show_dev_tp},
        {"tpreuse", cmd_show_dev_tpreuse},
        {0},
    };
    return exec_cmd(cfg, cmds);
}

int admin_cmd_show(admin_config_t *cfg)
{
    if (cfg->help) {
        return cmd_show_usage(cfg);
    }
    static const admin_cmd_t cmds[] = {
        {NULL, cmd_show_default},  //
        {"dev", cmd_show_dev},     //
        {"topo", cmd_show_topo},   //
        {0},                       //
    };
    return exec_cmd(cfg, cmds);
}
