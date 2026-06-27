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
#include "urma_perf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URMA_MAX_SYSFS_PATH 256
#define URMA_UBAGG_DEV_PREFIX "bonding_dev"
#define URMA_JFCE_CNT_MAX_DEV_NUM 64

typedef struct urma_user_info_ext_hdr {
    uint32_t len;
    char data[0];
} urma_user_info_ext_hdr_t;

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
urma_status_t urma_check_opt_valid(void *opt_mask_addr, const opt_map_t *table,
    size_t table_cnt, uint64_t opt, uint32_t len);
urma_status_t urma_set_options_common(void *obj, const opt_map_t *table,
    size_t table_cnt, uint64_t opt, void *buf, uint32_t len,
    void *cfg_base, void *opt_base, void *jfs_cfg_base);

static inline bool urma_is_bonding_dev(char *dev_name)
{
    if (strnlen(dev_name, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        return false;
    }
    
    return memcmp(dev_name, URMA_UBAGG_DEV_PREFIX,
        strlen(URMA_UBAGG_DEV_PREFIX)) == 0;
}

void urma_ubagg_switch_init(void);
void urma_ubagg_switch_inc(void);
uint32_t urma_ubagg_switch_get(void);

typedef struct urma_jfce_cnt_info {
    char dev_name[URMA_MAX_NAME];
    uint64_t jfce_total_cnt;
    uint64_t jfce_thresh_cnt;
} urma_jfce_cnt_info_t;

urma_status_t urma_get_jfce_cnt_info(urma_jfce_cnt_info_t *info_arr, uint32_t *cnt);


/**
 * just for urma perftest profiling
*/
#define UDMA_PERF_PROFILING_START(type, dev_name) \
    uint64_t __perf_start_##type = 0; \
    do { \
        if (urma_perf_is_enabled() && (!urma_is_bonding_dev(dev_name))) { \
            __perf_start_##type = urma_get_perf_timestamp(); \
        } \
    } while (0); \

#define UDMA_PERF_PROFILING_END(type, dev_name) \
    do { \
        uint64_t perf_end = 0; \
        if (urma_perf_is_enabled() && (!urma_is_bonding_dev(dev_name))) { \
            perf_end = urma_get_perf_timestamp(); \
            urma_step_perf(type, perf_end - __perf_start_##type); \
        } \
    } while (0); \

#define PERF_PROFILING_START(type) \
    uint64_t __perf_start_##type = 0; \
    do { \
        if (urma_perf_is_enabled()) { \
            __perf_start_##type = urma_get_perf_timestamp(); \
        } \
    } while (0)

#define PERF_PROFILING_END(type) \
    do { \
        if (urma_perf_is_enabled()) { \
            uint64_t _perf_end = urma_get_perf_timestamp(); \
            urma_step_perf(type, _perf_end - __perf_start_##type); \
        } \
    } while (0)

bool urma_perf_is_enabled(void);
uint64_t urma_get_perf_timestamp(void);
urma_status_t urma_step_perf(urma_perf_record_type_t type, uint64_t delta);

#ifdef __cplusplus
}
#endif

#endif // URMA_PRIVATE_H
