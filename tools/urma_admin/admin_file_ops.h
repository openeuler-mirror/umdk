/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: file ops header file for urma_admin
 * Author: Qian Guoxin
 * Create: 2023-01-04
 * Note:
 * History: 2023-01-04   create file
 */

#ifndef ADMIN_FILE_OPS_H
#define ADMIN_FILE_OPS_H

#include <stdint.h>

#define SYS_CLASS_PATH  "/sys/class/ubcore"
#define CDEV_PATH  "/dev/uburma"
#define DEV_PATH_MAX  1024
#define VALUE_LEN_MAX 64
#define FILE_PATH_MAX  128

int admin_merge_sysfs_path(char *sysfs_path, const char *path, const char *dir);

int admin_read_dev_file(const char *dev_name, const char *file, char *buf, uint32_t size);

uint32_t admin_read_dev_file_value_u32(const char *dev_name, const char *file);

int admin_write_dev_file(const char *dev_name, const char *file, const char *buf, uint32_t size);

int admin_parse_file_str(const char *file_path, char *file, char *buf, uint32_t size);

int admin_parse_file_value_u8(const char *file_path, char *file, uint8_t *u8);
int admin_parse_file_value_u16(const char *file_path, char *file, uint16_t *u16);
int admin_parse_file_value_u32(const char *file_path, char *file, uint32_t *u32);
int admin_parse_file_value_u64(const char *file_path, char *file, uint64_t *u64);

#endif
