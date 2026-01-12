/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description: file ops for urma_admin
 * Author: Qian Guoxin
 * Create: 2023-01-04
 * Note:
 * History: 2023-01-04   create file
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "admin_parameters.h"

#include "admin_file_ops.h"

#define ADMIN_RESERVED_JETTY_PARAM_NUM 2

static int open_file(const char *dir, const char *file, int flag)
{
    char *path;
    char *real_path;
    int fd;

    path = calloc(1, DEV_PATH_MAX);
    if (path == NULL) {
        return -1;
    }
    if (snprintf(path, DEV_PATH_MAX - 1, "%s/%s", dir, file) < 0) {
        free(path);
        return -1;
    }

    real_path = realpath(path, NULL);
    if (real_path == NULL) {
        (void)printf("file_path:%s is not standardize, errno: %d.\n", path, errno);
        free(path);
        return -1;
    }

    fd = open(real_path, flag);
    if (fd < 0) {
        (void)printf("Failed open file: %s, errno: %d.\n", real_path, errno);
        free(real_path);
        free(path);
        return -1;
    }

    free(real_path);
    free(path);
    return fd;
}

static inline void close_file(int fd)
{
    if (fd >= 0) {
        (void)close(fd);
    }
}

static int read_file(const char *dir, const char *file, char *buf, uint32_t size)
{
    int fd;
    ssize_t ret;

    fd = open_file(dir, file, O_RDONLY);
    if (fd < 0) {
        (void)printf("Failed open file: %s/%s, errno: %d.\n", dir, file, errno);
        return -1;
    }

    ret = read(fd, buf, (size_t)size);
    if (ret < 0 || (uint32_t)ret >= size) {
        (void)printf("Failed read file: %s/%s, ret:%ld, errno:%d.\n", dir, file, ret, errno);
        close_file(fd);
        return -1;
    }

    if ((ret >= 1) && (buf[ret - 1] == '\n')) {
        ret = ret - 1;
        buf[ret] = '\0';
    } else if (ret < size) {
        buf[ret] = '\0';
    } else {
        // If >= size, it will fail directly
        ret = -1;
    }

    close_file(fd);
    return (int)ret;
}

static int write_file(const char *dir, const char *file, const char *buf, uint32_t size)
{
    int fd;
    ssize_t ret;

    fd = open_file(dir, file, O_WRONLY);
    if (fd < 0) {
        (void)printf("Failed open file: %s/%s, errno: %d.\n", dir, file, errno);
        return -1;
    }

    ret = write(fd, buf, (size_t)size);
    if ((uint32_t)ret != size) {
        (void)printf("Failed write file: %s/%s, ret: %ld, errno: %d.\n", dir, file, ret, errno);
        close_file(fd);
        return -1;
    }

    close_file(fd);
    return 0;
}

int admin_merge_sysfs_path(char *sysfs_path, const char *path, const char *dir)
{
    struct stat stat_buf;
    if (snprintf(sysfs_path, DEV_PATH_MAX - 1, "%s/%s", path, dir) <= 0) {
        (void)printf("String splicing filed, path:%s, dir:%s.\n", path, dir);
        return -1;
    }

    if (stat(sysfs_path, &stat_buf) != 0 || !S_ISDIR(stat_buf.st_mode)) {
        return -1;
    }
    return 0;
}

int admin_read_dev_file(const char *dev_name, const char *file, char *buf, uint32_t size)
{
    int ret;
    char *sysfs_path;

    sysfs_path = calloc(1, DEV_PATH_MAX);
    if (sysfs_path == NULL) {
        return -1;
    }
    if (admin_merge_sysfs_path(sysfs_path, SYS_CLASS_PATH, dev_name) != 0) {
        goto free_sysfs_path;
    }

    ret = read_file(sysfs_path, file, buf, size);
    if (ret < 0) {
        (void)printf("read file %s/%s failed.\n", sysfs_path, file);
        goto free_sysfs_path;
    }

    free(sysfs_path);
    return ret;

free_sysfs_path:
    free(sysfs_path);
    return -1;
}

uint32_t admin_read_dev_file_value_u32(const char *dev_name, const char *file)
{
    int ret;
    uint32_t value;
    char *sysfs_path;
    char tmp_value[VALUE_LEN_MAX];

    sysfs_path = calloc(1, DEV_PATH_MAX);
    if (sysfs_path == NULL) {
        return 0;
    }
    if (admin_merge_sysfs_path(sysfs_path, SYS_CLASS_PATH, dev_name) != 0) {
        goto free_sysfs_path;
    }

    ret = read_file(sysfs_path, file, tmp_value, VALUE_LEN_MAX);
    if (ret < 0) {
        (void)printf("read file %s/%s failed.\n", sysfs_path, file);
        goto free_sysfs_path;
    }

    free(sysfs_path);
    ret = admin_str_to_u32(tmp_value, &value);
    if (ret != 0) {
        (void)printf("file %s: str %s to u64 failed, ret:%d.\n", file, tmp_value, ret);
        return 0;
    }
    return value;

free_sysfs_path:
    free(sysfs_path);
    return 0;
}

int admin_write_dev_file(const char *dev_name, const char *file, const char *buf, uint32_t size)
{
    char *sysfs_path;

    sysfs_path = calloc(1, DEV_PATH_MAX);
    if (sysfs_path == NULL) {
        return -1;
    }
    if (admin_merge_sysfs_path(sysfs_path, SYS_CLASS_PATH, dev_name) != 0) {
        goto free_sysfs_path;
    }

    if (write_file(sysfs_path, file, buf, size) < 0) {
        (void)printf("write file %s/%s failed.\n", sysfs_path, file);
        goto free_sysfs_path;
    }

    free(sysfs_path);
    return 0;

free_sysfs_path:
    free(sysfs_path);
    return -1;
}

int admin_parse_file_str(const char *file_path, char *file, char *buf, uint32_t size)
{
    return read_file(file_path, file, buf, size);
}

int admin_parse_file_value_u8(const char *file_path, char *file, uint8_t *u8)
{
    char tmp_value[VALUE_LEN_MAX];
    if (read_file(file_path, file, tmp_value, VALUE_LEN_MAX) <= 0) {
        (void)printf("read file %s/%s failed.\n", file_path, file);
        return -1;
    }
    return admin_str_to_u8(tmp_value, u8);
}

int admin_parse_file_value_u16(const char *file_path, char *file, uint16_t *u16)
{
    char tmp_value[VALUE_LEN_MAX];
    if (read_file(file_path, file, tmp_value, VALUE_LEN_MAX) <= 0) {
        (void)printf("read file %s/%s failed.\n", file_path, file);
        return -1;
    }
    return admin_str_to_u16(tmp_value, u16);
}

int admin_parse_file_value_u32(const char *file_path, char *file, uint32_t *u32)
{
    char tmp_value[VALUE_LEN_MAX];
    if (read_file(file_path, file, tmp_value, VALUE_LEN_MAX) <= 0) {
        (void)printf("read file %s/%s failed.\n", file_path, file);
        return -1;
    }
    return admin_str_to_u32(tmp_value, u32);
}

int admin_parse_file_value_u64(const char *file_path, char *file, uint64_t *u64)
{
    char tmp_value[VALUE_LEN_MAX];
    if (read_file(file_path, file, tmp_value, VALUE_LEN_MAX) <= 0) {
        (void)printf("read file %s/%s failed.\n", file_path, file);
        return -1;
    }
    return admin_str_to_u64(tmp_value, u64);
}

void admin_parse_reserved_jetty(const char *file_path, char *file, uint32_t *min, uint32_t *max)
{
    char tmp_value[VALUE_LEN_MAX] = {0};
    if (read_file(file_path, file, tmp_value, VALUE_LEN_MAX) <= 0) {
        *min = UINT32_MAX;
        *max = UINT32_MAX;
        (void)printf("read file %s/%s failed.\n", file_path, file);
        return;
    }

    if (sscanf(tmp_value, "%u-%u", min, max) != ADMIN_RESERVED_JETTY_PARAM_NUM) {
        *min = UINT32_MAX;
        *max = UINT32_MAX;
        (void)printf("Parse reserved jetty range failed value:%s\n", tmp_value);
        return;
    }

    return;
}

void admin_read_eid_list(const char *sysfs_path, urma_eid_info_t *eid_list, uint32_t max_eid_cnt)
{
    char tmp_eid[VALUE_LEN_MAX] = {0};
    char tmp_value[VALUE_LEN_MAX];
    for (uint32_t i = 0; i < max_eid_cnt; i++) {
        if (snprintf(tmp_eid, VALUE_LEN_MAX, "eids/eid%u", i) <= 0) {
            (void)printf("snprintf failed, eid idx: %u.\n", i);
        }
        eid_list[i].eid_index = i;
        if (admin_parse_file_str(sysfs_path, tmp_eid, tmp_value, VALUE_LEN_MAX) <= 0 ||
            admin_str_to_eid(tmp_value, &eid_list[i].eid) != 0) {
            eid_list[i].eid.in4.prefix = 0; // invalid
        }
    }
}
