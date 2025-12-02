/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 * Description: urma device header file
 * Author: Yan Fangfang
 * Create: 2022-07-08
 * Note:
 * History: 2021-07-08   Create File
 */

#ifndef URMA_DEVICE_H
#define URMA_DEVICE_H

#include <dirent.h>

#include "ub_list.h"
#include "urma_private.h"
#include "urma_provider.h"

void urma_update_port_attr(urma_sysfs_dev_t *sysfs_dev);
uint32_t urma_discover_devices(struct ub_list *dev_list, struct ub_list *driver_list);
urma_device_t *urma_find_dev_by_name(struct ub_list *dev_list, const char *dev_name);
void urma_free_devices(struct ub_list *dev_list);
urma_sysfs_dev_t *urma_read_sysfs_device(const struct dirent *dent);
bool urma_match_driver(urma_sysfs_dev_t *sysfs_dev, struct ub_list *driver_list);
uint32_t urma_read_eid_list(urma_device_t *dev, urma_eid_info_t *eid_list, uint32_t max_eid_cnt);
int urma_read_eid_with_index(urma_sysfs_dev_t *sysfs_dev, uint32_t eid_index, urma_eid_t *eid);
void urma_discover_sysfs_path(void);

#endif
