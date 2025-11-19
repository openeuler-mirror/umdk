/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: urma device source file
 * Author: Yan Fangfang
 * Create: 2022-07-08
 * Note:
 * History: 2022-07-08
 */

#include "urma_device.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>

#include "ub_util.h"
#include "urma_log.h"
#include "urma_private.h"

#define URMA_MAX_VALUE_LEN 64   // value length for urma_read_sysfs_device tmp_value arry
#define URMA_CLASS_PATH "/sys/class/ubcore"
#define URMA_CLASS_PATH_OBSOLETED "/sys/class/uburma"

#define URMA_EID_SUBPATH "eids/eid%u"
#define URMA_EID_SUBPATH_OBSOLETED "eid%u/eid"

#define URMA_DEV_PATH "/dev/uburma"
#define URMA_PORT_LEN 16
#define URMA_DEV_PATH_MAX  (URMA_MAX_SYSFS_PATH + URMA_PORT_LEN)

#define URMA_RSVD_JETTY_ID_PARAM_NUM 2

static char g_urma_class_path[URMA_MAX_SYSFS_PATH] = URMA_CLASS_PATH;

ssize_t urma_read_sysfs_file(const char *dir, const char *file, char *buf, size_t size)
{
    char path[URMA_MAX_SYSFS_PATH] = {0};
    int fd = -1;
    ssize_t len;
    char *file_path;

    if (snprintf(path, URMA_MAX_SYSFS_PATH, "%s/%s", dir, file) < 0) {
        URMA_LOG_ERR("snprintf failed");
        return -1;
    }
    file_path = realpath(path, NULL);
    if (file_path == NULL) {
        URMA_LOG_WARN("file_path:%s is not standardize.\n", path);
        return -1;
    }
    fd = open(file_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        URMA_LOG_ERR("Failed open file: %s, errno: %d.\n", file_path, errno);
        free(file_path);
        return -1;
    }

    len = read(fd, buf, size);
    if (len <= 0 || len > (ssize_t)size) {
        URMA_LOG_ERR("Failed read file: %s, ret:%zd, errno:%d.\n", file_path, len, errno);
        (void)close(fd);
        free(file_path);
        return -1;
    }
    (void)close(fd);
    free(file_path);

    if (buf[len - 1] == '\n') {
        len = len - 1;
        buf[len] = '\0';
    } else if (len < (ssize_t)size) {
        buf[len] = '\0';
    } else {
        // If >= size, it will fail directly
        return -1;
    }
    return len;
}

static inline bool urma_eid_is_valid(urma_eid_t *eid)
{
    return !(eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0);
}

static uint32_t read_eid_list_sysyf(urma_sysfs_dev_t *sysfs_dev, char *subpath,
    urma_eid_info_t *eid_list, uint32_t max_eid_cnt)
{
    char tmp_eid[URMA_MAX_NAME] = {0};
    char tmp_value[URMA_MAX_NAME] = {0};
    uint32_t cnt_idx = 0;
    urma_eid_t eid = {0};

    for (uint32_t i = 0; i < max_eid_cnt; i++) {
        if (snprintf(tmp_eid, URMA_MAX_NAME, subpath, i) <= 0) {
            URMA_LOG_ERR("printf failed, eid idx: %u.\n", i);
            continue;
        }
        if (urma_read_sysfs_file(sysfs_dev->sysfs_path, tmp_eid, tmp_value, URMA_MAX_NAME) <= 0) {
            URMA_LOG_ERR("Failed to read sysfs file");
            continue;
        }
        if (urma_str_to_eid(tmp_value, &eid) != 0 || !urma_eid_is_valid(&eid)) {
            continue;
        }
        eid_list[cnt_idx].eid_index = i;
        (void)memcpy(&eid_list[cnt_idx++].eid, &eid, sizeof(urma_eid_t));
    }
    return cnt_idx;
}

static int read_eid_sysfs_with_index(urma_sysfs_dev_t *sysfs_dev, char *pattern,
    uint32_t eid_index, urma_eid_t *eid)
{
    char tmp_eid[URMA_MAX_NAME] = {0};
    char tmp_value[URMA_MAX_NAME] = {0};

    if (snprintf(tmp_eid, URMA_MAX_NAME, pattern, eid_index) <= 0) {
        URMA_LOG_ERR("snprintf failed, eid idx: %u.\n", eid_index);
        return -1;
    }
    if (urma_read_sysfs_file(sysfs_dev->sysfs_path, tmp_eid, tmp_value, URMA_MAX_NAME) <= 0) {
        URMA_LOG_ERR("Failed to read sysfs file");
        return -1;
    }
    if (urma_str_to_eid(tmp_value, eid) != 0 || !urma_eid_is_valid(eid)) {
        URMA_LOG_ERR("Failed to parse eid value, dev name:%s, eid idx:%u\n", sysfs_dev->dev_name, eid_index);
        return -1;
    }
    return 0;
}

static int urma_ioctl_get_eid_list(urma_device_t *dev, uint32_t max_eid_cnt,
    urma_eid_info_t *eid_list, uint32_t *eid_cnt)
{
    int dev_fd = urma_open_cdev(dev->path);
    if (dev_fd < 0) {
        URMA_LOG_ERR("Failed to open urma cdev with path %s\n", dev->path);
        return -1;
    }

    int ret = urma_cmd_get_eid_list(dev_fd, max_eid_cnt, eid_list, eid_cnt);
    close(dev_fd);
    return ret;
}

uint32_t urma_read_eid_list(urma_device_t *dev,
    urma_eid_info_t *eid_list, uint32_t max_eid_cnt)
{
    uint32_t eid_cnt = 0;
    if (urma_ioctl_get_eid_list(dev, max_eid_cnt, eid_list, &eid_cnt) == 0) {
        return eid_cnt;
    }

    if (strcmp(g_urma_class_path, URMA_CLASS_PATH) == 0) {
        return read_eid_list_sysyf(dev->sysfs_dev, URMA_EID_SUBPATH, eid_list, max_eid_cnt);
    } else {
        // to adapt old ko
        return read_eid_list_sysyf(dev->sysfs_dev, URMA_EID_SUBPATH_OBSOLETED, eid_list, max_eid_cnt);
    }
}

int urma_read_eid_with_index(urma_sysfs_dev_t *sysfs_dev,
    uint32_t eid_index, urma_eid_t *eid)
{
    if (strcmp(g_urma_class_path, URMA_CLASS_PATH) == 0) {
        return read_eid_sysfs_with_index(sysfs_dev, "eids/eid%u", eid_index, eid);
    } else {
        // to adapt old ko
        return read_eid_sysfs_with_index(sysfs_dev, "eid%u/eid", eid_index, eid);
    }
}

static int urma_query_device_attr(urma_sysfs_dev_t *sysfs_dev)
{
    char cdev_path[URMA_MAX_PATH] = {0};

    if (snprintf(cdev_path, URMA_MAX_PATH, "%s/%s", URMA_DEV_PATH, sysfs_dev->dev_name) <= 0) {
        URMA_LOG_ERR("Failed to get cdev_path, dev_name: %s.\n", sysfs_dev->dev_name);
        return -1;
    }

    int dev_fd = urma_open_cdev(cdev_path);
    if (dev_fd < 0) {
        URMA_LOG_ERR("Failed to open urma cdev, path %s.\n", cdev_path);
        return -1;
    }

    int ret = urma_cmd_query_device_attr(dev_fd, sysfs_dev);
    (void)close(dev_fd);
    return ret;
}

static inline uint8_t urma_parse_value_u8(const char *sysfs_path, char *file)
{
    uint8_t u8;
    char tmp_value[URMA_MAX_VALUE_LEN];
    if (urma_read_sysfs_file(sysfs_path, file, tmp_value, URMA_MAX_VALUE_LEN) <= 0) {
        return 0;
    }
    return ub_str_to_u8(tmp_value, &u8) != 0 ? 0 : u8;
}

static inline uint16_t urma_parse_value_u16(const char *sysfs_path, char *file)
{
    uint16_t u16;
    char tmp_value[URMA_MAX_VALUE_LEN];
    if (urma_read_sysfs_file(sysfs_path, file, tmp_value, URMA_MAX_VALUE_LEN) <= 0) {
        return 0;
    }
    return ub_str_to_u16(tmp_value, &u16) != 0 ? 0 : u16;
}

static inline uint32_t urma_parse_value_u32(const char *sysfs_path, char *file)
{
    uint32_t u32;
    char tmp_value[URMA_MAX_VALUE_LEN];
    if (urma_read_sysfs_file(sysfs_path, file, tmp_value, URMA_MAX_VALUE_LEN) <= 0) {
        return 0;
    }
    return ub_str_to_u32(tmp_value, &u32) != 0 ? 0 : u32;
}

static inline uint64_t urma_parse_value_u64(const char *sysfs_path, char *file)
{
    uint64_t u64;
    char tmp_value[URMA_MAX_VALUE_LEN];
    if (urma_read_sysfs_file(sysfs_path, file, tmp_value, URMA_MAX_VALUE_LEN) <= 0) {
        return 0;
    }
    return ub_str_to_u64(tmp_value, &u64) != 0 ? 0 : u64;
}

static inline void urma_parse_string(const char *sysfs_path, char *file, char *dst_str, uint32_t len)
{
    if (urma_read_sysfs_file(sysfs_path, file, dst_str, len) <= 0) {
        dst_str[0] = 0; // invalid
    }
    return;
}

static void urma_parse_rsvd_jetty_range(const char *sysfs_path, char *file, uint32_t *min, uint32_t *max)
{
    char tmp_value[URMA_MAX_VALUE_LEN] = {0};
    if (urma_read_sysfs_file(sysfs_path, file, tmp_value, URMA_MAX_VALUE_LEN) <= 0) {
        URMA_LOG_ERR("parse sysfs:%s failed \n", sysfs_path);
        return;
    }

    if (sscanf(tmp_value, "%u-%u", min, max) != URMA_RSVD_JETTY_ID_PARAM_NUM) {
        *min = UINT32_MAX;
        *max = UINT32_MAX;
        URMA_LOG_ERR("parse rsvd jetty:%s failed \n", tmp_value);
    }
}

static void urma_parse_port_attr(const char *sysfs_path, urma_device_attr_t *attr)
{
    uint8_t i;
    char port_path[URMA_DEV_PATH_MAX];

    for (i = 0; i < attr->port_cnt && i < MAX_PORT_CNT; i++) {
        if (snprintf(port_path, URMA_DEV_PATH_MAX - 1, "%s/port%u", sysfs_path, i) <= 0) {
            URMA_LOG_ERR("snprintf failed, path: %s, port_num:%hhu.\n", sysfs_path, i);
            continue;
        }

        attr->port_attr[i].max_mtu = (urma_mtu_t)urma_parse_value_u32(port_path, "max_mtu");
        attr->port_attr[i].state = (urma_port_state_t)urma_parse_value_u32(port_path, "state");
        attr->port_attr[i].active_width = (urma_link_width_t)urma_parse_value_u32(port_path, "active_width");
        attr->port_attr[i].active_speed = (urma_speed_t)urma_parse_value_u32(port_path, "active_speed");
        attr->port_attr[i].active_mtu = (urma_mtu_t)urma_parse_value_u32(port_path, "active_mtu");
    }
}

void urma_update_port_attr(urma_sysfs_dev_t *sysfs_dev)
{
    urma_parse_port_attr(sysfs_dev->sysfs_path, &sysfs_dev->dev_attr);
}

static void urma_parse_device_attr(urma_sysfs_dev_t *sysfs_dev)
{
    char tmp_value[URMA_MAX_VALUE_LEN];
    char *sysfs_path = sysfs_dev->sysfs_path;
    urma_device_attr_t *attr = &sysfs_dev->dev_attr;

    if (urma_read_sysfs_file(sysfs_path, "guid", tmp_value, URMA_MAX_VALUE_LEN) != -1) {
        (void)urma_str_to_eid(tmp_value, (urma_eid_t *)&attr->guid);
    }

    attr->dev_cap.feature.value = urma_parse_value_u32(sysfs_path, "feature");
    attr->dev_cap.max_jfc = urma_parse_value_u32(sysfs_path, "max_jfc");
    attr->dev_cap.max_jfs = urma_parse_value_u32(sysfs_path, "max_jfs");
    attr->dev_cap.max_jfr = urma_parse_value_u32(sysfs_path, "max_jfr");
    attr->dev_cap.max_jetty = urma_parse_value_u32(sysfs_path, "max_jetty");
    attr->dev_cap.max_jetty_grp = urma_parse_value_u32(sysfs_path, "max_jetty_grp");
    attr->dev_cap.max_jetty_in_jetty_grp = urma_parse_value_u32(sysfs_path, "max_jetty_in_jetty_grp");
    attr->dev_cap.max_jfc_depth = urma_parse_value_u32(sysfs_path, "max_jfc_depth");
    attr->dev_cap.max_jfs_depth = urma_parse_value_u32(sysfs_path, "max_jfs_depth");
    attr->dev_cap.max_jfr_depth = urma_parse_value_u32(sysfs_path, "max_jfr_depth");
    attr->dev_cap.max_jfs_inline_len = urma_parse_value_u32(sysfs_path, "max_jfs_inline_size");
    attr->dev_cap.max_jfs_sge = urma_parse_value_u32(sysfs_path, "max_jfs_sge");
    attr->dev_cap.max_jfs_rsge = urma_parse_value_u32(sysfs_path, "max_jfs_rsge");
    attr->dev_cap.max_jfr_sge = urma_parse_value_u32(sysfs_path, "max_jfr_sge");
    attr->dev_cap.max_msg_size = urma_parse_value_u64(sysfs_path, "max_msg_size");
    attr->dev_cap.max_read_size = urma_parse_value_u32(sysfs_path, "max_read_size");
    attr->dev_cap.max_write_size = urma_parse_value_u32(sysfs_path, "max_write_size");
    attr->dev_cap.max_cas_size = urma_parse_value_u32(sysfs_path, "max_cas_size");
    attr->dev_cap.max_swap_size = urma_parse_value_u32(sysfs_path, "max_swap_size");
    attr->dev_cap.max_fetch_and_add_size = urma_parse_value_u32(sysfs_path, "max_fetch_and_add_size");
    attr->dev_cap.max_fetch_and_sub_size = urma_parse_value_u32(sysfs_path, "max_fetch_and_sub_size");
    attr->dev_cap.max_fetch_and_and_size = urma_parse_value_u32(sysfs_path, "max_fetch_and_and_size");
    attr->dev_cap.max_fetch_and_or_size = urma_parse_value_u32(sysfs_path, "max_fetch_and_or_size");
    attr->dev_cap.max_fetch_and_xor_size = urma_parse_value_u32(sysfs_path, "max_fetch_and_xor_size");
    attr->dev_cap.atomic_feat.value = urma_parse_value_u32(sysfs_path, "atomic_feat");
    attr->dev_cap.trans_mode = urma_parse_value_u16(sysfs_path, "trans_mode");
    attr->dev_cap.sub_trans_mode_cap = urma_parse_value_u16(sysfs_path, "sub_trans_mode_cap");
    attr->dev_cap.congestion_ctrl_alg = urma_parse_value_u16(sysfs_path, "congestion_ctrl_alg");
    attr->dev_cap.ceq_cnt = urma_parse_value_u32(sysfs_path, "ceq_cnt");
    attr->dev_cap.max_tp_in_tpg = urma_parse_value_u32(sysfs_path, "max_tp_in_tpg");
    attr->port_cnt = urma_parse_value_u8(sysfs_path, "port_count");
    attr->dev_cap.max_eid_cnt = urma_parse_value_u16(sysfs_path, "max_eid_cnt");
    attr->dev_cap.page_size_cap = urma_parse_value_u64(sysfs_path, "page_size_cap");
    attr->dev_cap.max_oor_cnt = urma_parse_value_u32(sysfs_path, "max_oor_cnt");
    attr->dev_cap.mn = urma_parse_value_u32(sysfs_path, "mn");
    attr->dev_cap.max_netaddr_cnt = urma_parse_value_u32(sysfs_path, "max_netaddr_cnt");

    if (attr->port_cnt > 0 && attr->port_cnt != MAX_PORT_CNT) {
        urma_parse_port_attr(sysfs_path, attr);
    }

    urma_parse_rsvd_jetty_range(sysfs_path, "reserved_jetty_id",
        &attr->reserved_jetty_id_min, &attr->reserved_jetty_id_max);
}

static void urma_read_sysfs_dev_attrs(urma_sysfs_dev_t *sysfs_dev)
{
    urma_parse_string(sysfs_dev->sysfs_path, "ubdev", sysfs_dev->dev_name, URMA_MAX_NAME);
    urma_parse_string(sysfs_dev->sysfs_path, "driver_name", sysfs_dev->driver_name, URMA_MAX_NAME);

    sysfs_dev->transport_type = (urma_transport_type_t)urma_parse_value_u32(sysfs_dev->sysfs_path, "transport_type");
    sysfs_dev->vendor_id = urma_parse_value_u16(sysfs_dev->sysfs_path, "device/vendor");
    sysfs_dev->device_id = urma_parse_value_u16(sysfs_dev->sysfs_path, "device/device");

    if (urma_query_device_attr(sysfs_dev) == 0) {
        return;
    }
    urma_parse_device_attr(sysfs_dev);
}

void urma_discover_sysfs_path(void)
{
    struct stat stat_buf;
    int ret;

    ret = stat(g_urma_class_path, &stat_buf);
    if (ret == 0) {
        return;
    }

    ret = stat(URMA_CLASS_PATH_OBSOLETED, &stat_buf);
    if (ret == 0) {
        (void)strncpy(g_urma_class_path, URMA_CLASS_PATH_OBSOLETED, URMA_MAX_SYSFS_PATH - 1);
        URMA_LOG_WARN("urma sysfs path is obseleted");
        return;
    }
    URMA_LOG_WARN("urma sysfs path is not found");
    return;
}

urma_sysfs_dev_t *urma_read_sysfs_device(const struct dirent *dent)
{
    int ret;
    urma_sysfs_dev_t *sysfs_dev = NULL;
    struct stat stat_buf;

    if (dent->d_name[0] == '.' || strcmp(dent->d_name, "ubcore") == 0) {
        return NULL;
    }

    sysfs_dev = calloc(1, sizeof(urma_sysfs_dev_t));
    if (sysfs_dev == NULL) {
        return NULL;
    }

    ret = snprintf(sysfs_dev->sysfs_path, URMA_MAX_SYSFS_PATH - 1, "%s/%s",  g_urma_class_path, dent->d_name);
    if (ret <= 0) {
        URMA_LOG_ERR("snprintf failed, dev_name: %s.\n", dent->d_name);
        goto out;
    }

    if (stat(sysfs_dev->sysfs_path, &stat_buf) != 0) {
        URMA_LOG_WARN("Coudn't stat %s.\n", sysfs_dev->sysfs_path);
        goto out;
    }

    if (!S_ISDIR(stat_buf.st_mode)) {
        URMA_LOG_WARN("%s not dir.\n", sysfs_dev->sysfs_path);
        goto out;
    }

    urma_read_sysfs_dev_attrs(sysfs_dev);
    sysfs_dev->time_created = stat_buf.st_mtim;

    return sysfs_dev;

out:
    free(sysfs_dev);
    return NULL;
}

static bool urma_match_device(const urma_sysfs_dev_t *sdev, const urma_driver_t *driver)
{
    urma_provider_ops_t *ops = driver->ops;
    const urma_match_entry_t *match_table = ops->match_table;

    if (match_table != NULL) {
        /* match vendor id and device id */
        for (int i = 0; match_table[i].vendor_id != 0 && match_table[i].device_id != 0; i++) {
            if (sdev->vendor_id == match_table[i].vendor_id && sdev->device_id == match_table[i].device_id) {
                return true;
            }
        }
    }
    return strcmp(sdev->driver_name, ops->name) == 0;
}

bool urma_match_driver(urma_sysfs_dev_t *sysfs_dev, struct ub_list *driver_list)
{
    urma_driver_t *driver;
    UB_LIST_FOR_EACH(driver, node, driver_list) {
        if (urma_match_device(sysfs_dev, driver)) {
            sysfs_dev->driver = driver;
            return true;
        }
    }
    return false;
}

static urma_device_t *urma_alloc_device(urma_sysfs_dev_t *sysfs_dev)
{
    urma_device_t *dev = calloc(1, sizeof(urma_device_t));
    if (dev == NULL) {
        return NULL;
    }
    dev->ops = sysfs_dev->driver->ops;
    dev->type = sysfs_dev->transport_type;
    dev->sysfs_dev = sysfs_dev;
    (void)memcpy(dev->name, sysfs_dev->dev_name, URMA_MAX_NAME);
    if (snprintf(dev->path, URMA_MAX_PATH, "%s/%s", URMA_DEV_PATH, sysfs_dev->dev_name) <= 0) {
        URMA_LOG_ERR("snprintf failed");
        goto FAIL_OUT;
    }
    sysfs_dev->urma_device = dev;
    return dev;

FAIL_OUT:
    sysfs_dev->urma_device = NULL;
    free(dev);
    return NULL;
}

static inline bool urma_time_cmp_eq(struct timespec *time1, struct timespec *time2)
{
    /* Todo: check (time1->tv_sec == time2->tv_sec && time1->tv_nsec == time2->tv_nsec) in container */
    return true;
}

static int urma_check_loaded_devices(urma_sysfs_dev_t *sysfs_dev,
    struct ub_list *dev_name_list)
{
    urma_sysfs_dev_name_t *sysfs_dev_name = NULL;
    urma_sysfs_dev_name_t *next = NULL;

    UB_LIST_FOR_EACH_SAFE(sysfs_dev_name, next, node, dev_name_list) {
        if (strcmp(sysfs_dev_name->dev_name, sysfs_dev->dev_name) == 0 &&
            urma_time_cmp_eq(&sysfs_dev_name->time_created,
            &sysfs_dev->time_created) == true) {
            return 0;
        }
    }
    return -1;
}

static void urma_get_dev_name_list(struct ub_list *dev_name_list, urma_sysfs_dev_t *sysfs_dev)
{
    urma_sysfs_dev_name_t *sysfs_dev_name = calloc(1, sizeof(urma_sysfs_dev_name_t));
    if (sysfs_dev_name == NULL) {
        return;
    }
    (void)strncpy(sysfs_dev_name->dev_name, sysfs_dev->dev_name, URMA_MAX_NAME);
    sysfs_dev_name->time_created = sysfs_dev->time_created;
    ub_list_insert_after(dev_name_list, &sysfs_dev_name->node);
}

static void urma_free_dev_name_list(struct ub_list *dev_name_list)
{
    urma_sysfs_dev_name_t *sysfs_dev, *next;

    UB_LIST_FOR_EACH_SAFE(sysfs_dev, next, node, dev_name_list) {
        if (sysfs_dev == NULL) {
            continue;
        }
        ub_list_remove(&sysfs_dev->node);
        free(sysfs_dev);
    }
}

uint32_t urma_discover_devices(struct ub_list *dev_list, struct ub_list *driver_list)
{
    DIR *class_dir = NULL;
    struct dirent *dent = NULL;
    urma_sysfs_dev_t *sysfs_dev = NULL;
    struct ub_list dev_name_list = UB_LIST_INITIALIZER(&dev_name_list);
    uint32_t cnt = (uint32_t)ub_list_size(dev_list);

    class_dir = opendir(g_urma_class_path);
    if (class_dir == NULL) {
        URMA_LOG_ERR("%s open failed, errno: %d.\n", g_urma_class_path, errno);
        return 0;
    }

    while ((dent = readdir(class_dir)) != NULL) {
        sysfs_dev = urma_read_sysfs_device(dent);
        if (sysfs_dev == NULL) {
            continue;
        }
        urma_device_t *device = NULL;
        device = urma_find_dev_by_name(dev_list, sysfs_dev->dev_name);
        if (device != NULL && urma_time_cmp_eq(&device->sysfs_dev->time_created,
            &sysfs_dev->time_created)) {
            urma_get_dev_name_list(&dev_name_list, sysfs_dev);
            free(sysfs_dev);
            continue;
        }
        if (!urma_match_driver(sysfs_dev, driver_list)) {
            free(sysfs_dev);
            continue;
        }
        if (urma_alloc_device(sysfs_dev) == NULL) {
            free(sysfs_dev);
            continue;
        }
        ub_list_insert_after(dev_list, &sysfs_dev->node);
        urma_get_dev_name_list(&dev_name_list, sysfs_dev);
        cnt++;
    }
    if (closedir(class_dir) < 0) {
        URMA_LOG_ERR("Failed close dir: %s, errno: %d.\n", g_urma_class_path, errno);
    }

    /* remove unloaded urma_device in dev_list */
    urma_sysfs_dev_t *next;
    UB_LIST_FOR_EACH_SAFE(sysfs_dev, next, node, dev_list) {
        if ((sysfs_dev->flag & URMA_SYSFS_DEV_FLAG_DRIVER_CREATED) != 0) {
            // sysfs_dev created by driver.
            continue;
        }
        if (urma_check_loaded_devices(sysfs_dev, &dev_name_list) == 0) {
            continue;
        }
        ub_list_remove(&sysfs_dev->node);
        sysfs_dev->driver = NULL;
        if (sysfs_dev->urma_device != NULL) {
            free(sysfs_dev->urma_device);
            sysfs_dev->urma_device = NULL;
        }
        free(sysfs_dev);
        cnt--;
    }

    urma_free_dev_name_list(&dev_name_list);

    return cnt;
}

urma_device_t *urma_find_dev_by_name(struct ub_list *dev_list, const char *dev_name)
{
    urma_sysfs_dev_t *sysfs_dev;

    UB_LIST_FOR_EACH(sysfs_dev, node, dev_list) {
        if (strcmp(sysfs_dev->dev_name, dev_name) == 0) {
            return sysfs_dev->urma_device;
        }
    }
    return NULL;
}

void urma_free_devices(struct ub_list *dev_list)
{
    urma_sysfs_dev_t *sysfs_dev, *next;

    UB_LIST_FOR_EACH_SAFE(sysfs_dev, next, node, dev_list) {
        if (sysfs_dev == NULL) {
            continue;
        }
        ub_list_remove(&sysfs_dev->node);
        sysfs_dev->driver = NULL;
        if (sysfs_dev->urma_device != NULL) {
            free(sysfs_dev->urma_device);
            sysfs_dev->urma_device = NULL;
        }
        free(sysfs_dev);
    }
}
