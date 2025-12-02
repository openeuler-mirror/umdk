/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: URMA common header file
 * Author: Ouyang Changchun, Bojie Li, Yan Fangfang, Qian Guoxin
 * Create: 2021-07-14
 * Note:
 * History: 2021-07-14   Create File
 */

#ifndef URMA_PRIVATE_H
#define URMA_PRIVATE_H

#include <stdint.h>

#include "ub_list.h"
#include "urma_provider.h"

#define URMA_MAX_SYSFS_PATH 256

typedef struct urma_driver {
    struct urma_provider_ops *ops;
    struct ub_list node; /* Add to driver list */
} urma_driver_t;

typedef struct urma_sysfs_dev {
    char dev_name[URMA_MAX_NAME];
    char sysfs_path[URMA_MAX_SYSFS_PATH];
    char driver_name[URMA_MAX_NAME];
    urma_transport_type_t transport_type; /* transport type */
    urma_driver_t *driver;
    urma_device_t *urma_device;
    urma_device_attr_t dev_attr;
    uint16_t device_id;
    uint16_t vendor_id;
    struct ub_list node; /* Add to device list */
    uint32_t flag;
    struct timespec time_created;
} urma_sysfs_dev_t;

typedef struct urma_sysfs_dev_name {
    char dev_name[URMA_MAX_NAME];
    struct ub_list node; /* Add to dev_name_list */
    struct timespec time_created;
} urma_sysfs_dev_name_t;

int urma_init_jetty_cfg(urma_jetty_cfg_t *p, urma_jetty_cfg_t *cfg);
void urma_uninit_jetty_cfg(urma_jetty_cfg_t *p);
int urma_query_eid(urma_device_t *dev, uint32_t eid_index, urma_eid_t *eid);
int urma_open_cdev(char *path);

#endif // URMA_PRIVATE_H
