/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
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
#define URMA_CLASS_PATH  "/sys/class/ubcore"
#define URMA_DEV_PATH "/dev/uburma"
#define URMA_PORT_LEN 16
#define URMA_DEV_PATH_MAX  (URMA_MAX_SYSFS_PATH + URMA_PORT_LEN)

ssize_t urma_read_sysfs_file(const char *dir, const char *file, char *buf, size_t size)
{
    char path[URMA_MAX_SYSFS_PATH] = {0};
    int fd = -1;
    ssize_t len;
    char *file_path;

    if (snprintf(path, URMA_MAX_SYSFS_PATH - 1, "%s/%s", dir, file) < 0) {
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
        free(file_path);
        (void)close(fd);
        return -1;
    }
    free(file_path);
    (void)close(fd);

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

ssize_t urma_write_sysfs_file(const char *dir, char *buf, size_t size)
{
    int fd = -1;
    ssize_t len;
    char *file_path;

    file_path = realpath(dir, NULL);
    if (file_path == NULL) {
        URMA_LOG_ERR("file_path:%s is not standardize.\n", dir);
        return -1;
    }
    fd = open(file_path, O_RDWR);
    if (fd < 0) {
        URMA_LOG_ERR("Failed open file: %s, errno: %d.\n", file_path, errno);
        free(file_path);
        return -1;
    }

    len = write(fd, buf, size);
    if (len <= 0 || len > (ssize_t)size) {
        URMA_LOG_ERR("Failed write file: %s, ret:%d, size:%d, errno:%d.\n", file_path, len, size, errno);
        free(file_path);
        (void)close(fd);
        return -1;
    }
    free(file_path);
    (void)close(fd);

    buf[len] = '\0';
    return len;
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

static void urma_parse_port_attr(const char *sysfs_path, urma_device_attr_t *attr)
{
    uint8_t i;
    char port_path[URMA_DEV_PATH_MAX];

    for (i = 0; i < attr->port_cnt; i++) {
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

    (void)urma_read_sysfs_file(sysfs_path, "guid", tmp_value, URMA_MAX_VALUE_LEN);
    (void)urma_str_to_eid(tmp_value, (urma_eid_t *)&attr->guid);

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
    attr->dev_cap.max_atomic_size = urma_parse_value_u32(sysfs_path, "max_atomic_size");
    attr->dev_cap.atomic_feat.value = urma_parse_value_u32(sysfs_path, "atomic_feat");
    attr->dev_cap.trans_mode = urma_parse_value_u16(sysfs_path, "trans_mode");
    attr->dev_cap.congestion_ctrl_alg = urma_parse_value_u16(sysfs_path, "congestion_ctrl_alg");
    attr->dev_cap.ceq_cnt = urma_parse_value_u32(sysfs_path, "ceq_cnt");
    attr->dev_cap.max_tp_in_tpg = urma_parse_value_u32(sysfs_path, "max_tp_in_tpg");
    attr->port_cnt = urma_parse_value_u8(sysfs_path, "port_count");
    attr->dev_cap.max_eid_cnt = urma_parse_value_u16(sysfs_path, "max_eid_cnt");

    if (attr->port_cnt > 0 && attr->port_cnt != MAX_PORT_CNT) {
        urma_parse_port_attr(sysfs_path, attr);
    }
}

static void urma_read_sysfs_dev_attrs(urma_sysfs_dev_t *sysfs_dev)
{
    urma_parse_string(sysfs_dev->sysfs_path, "ubdev", sysfs_dev->dev_name, URMA_MAX_NAME);
    urma_parse_string(sysfs_dev->sysfs_path, "driver_name", sysfs_dev->driver_name, URMA_MAX_NAME);

    sysfs_dev->transport_type = (urma_transport_type_t)urma_parse_value_u32(sysfs_dev->sysfs_path, "transport_type");
    sysfs_dev->vendor_id = urma_parse_value_u16(sysfs_dev->sysfs_path, "device/vendor");
    sysfs_dev->device_id = urma_parse_value_u16(sysfs_dev->sysfs_path, "device/device");

    urma_parse_device_attr(sysfs_dev);
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

    ret = snprintf(sysfs_dev->sysfs_path, URMA_MAX_SYSFS_PATH - 1, "%s/%s", URMA_CLASS_PATH, dent->d_name);
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

static bool urma_match_driver(urma_sysfs_dev_t *sysfs_dev, struct ub_list *driver_list)
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

static int urma_check_loaded_devices(const char *dev_name, struct ub_list *dev_name_list)
{
    urma_sysfs_dev_name_t *sysfs_dev_name = NULL;
    urma_sysfs_dev_name_t *next = NULL;

    UB_LIST_FOR_EACH_SAFE(sysfs_dev_name, next, node, dev_name_list) {
        if (strcmp(sysfs_dev_name->dev_name, dev_name) == 0) {
            return 0;
        }
    }
    return -1;
}

static void urma_get_dev_name_list(struct ub_list *dev_name_list, urma_sysfs_dev_t *sysfs_dev)
{
    urma_sysfs_dev_name_t *sysfs_dev_name = calloc(1, sizeof(urma_sysfs_dev_t));
    if (sysfs_dev_name == NULL) {
        return;
    }
    (void)strcpy(sysfs_dev_name->dev_name, sysfs_dev->dev_name);
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

    class_dir = opendir(URMA_CLASS_PATH);
    if (class_dir == NULL) {
        URMA_LOG_ERR("%s open failed, errno: %d.\n", URMA_CLASS_PATH, errno);
        return 0;
    }

    while ((dent = readdir(class_dir)) != NULL) {
        sysfs_dev = urma_read_sysfs_device(dent);
        if (sysfs_dev == NULL) {
            continue;
        }
        urma_device_t *device = NULL;
        device = urma_find_dev_by_name(dev_list, sysfs_dev->dev_name);
        if (device != NULL) {
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
        URMA_LOG_ERR("Failed close dir: %s, errno: %d.\n", URMA_CLASS_PATH, errno);
    }

    /* remove unloaded urma_device in dev_list */
    urma_sysfs_dev_t *next;
    UB_LIST_FOR_EACH_SAFE(sysfs_dev, next, node, dev_list) {
        if (urma_check_loaded_devices(sysfs_dev->dev_name, &dev_name_list) == 0) {
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
