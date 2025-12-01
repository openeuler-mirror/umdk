/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: obmem impl header
 * Create: 2025-9-11
 * Note:
 * History: 2025-9-11
 */

#ifndef OBMEM_COMMON_H
#define OBMEM_COMMON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OBMM_EID_LEN    16

typedef struct obmem_export_info {
    uint32_t token_id;
    uint64_t uba;
    uint64_t size;
} obmem_export_info_t;

typedef struct obmem_export_memory_param {
    uint64_t len;
    uint8_t deid[OBMM_EID_LEN];
    bool cacheable;
} obmem_export_memory_param_t;

typedef struct obmem_import_memory_param {
    uint16_t import_cna;
    uint16_t export_cna;
    uint8_t seid[OBMM_EID_LEN];
    uint8_t deid[OBMM_EID_LEN];
    bool cacheable;
} obmem_import_memory_param_t;

/* memory sharing: export */
void *obmem_export_memory(obmem_export_memory_param_t *export_param, uint64_t *handle, obmem_export_info_t *exp);

int obmem_release_export_memory(uint64_t handle, void *ptr, uint64_t len);

/* memory sharing: import */
void *obmem_import_memory(obmem_import_memory_param_t *import_param, obmem_export_info_t *exp, uint64_t *handle);

int obmem_release_import_memory(uint64_t handle, void *ptr, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif // OBMEM_COMMON_H
