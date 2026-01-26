/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc id generator
 */

#ifndef URPC_ID_GENERATOR_H
#define URPC_ID_GENERATOR_H

#include <stdint.h>
#include <pthread.h>
#include "urpc_bitmap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum urpc_id_generator_type {
    URPC_ID_GENERATOR_TYPE_BITMAP,
    URPC_ID_GENERATOR_TYPE_BITMAP_AUTO_INC,
    URPC_ID_GENERATOR_TYPE_NUM
} urpc_id_generator_type_e;

struct urpc_id_generator;

typedef int (*id_generator_init_t)(struct urpc_id_generator *generator, unsigned size);
typedef void (*id_generator_uninit_t)(struct urpc_id_generator *generator);
typedef int (*id_generator_alloc_t)(struct urpc_id_generator *generator, unsigned int min, uint32_t *id);
typedef void (*id_generator_free_t)(struct urpc_id_generator *generator, uint32_t id);

typedef struct urpc_id_generator {
    id_generator_init_t init;
    id_generator_uninit_t uninit;
    id_generator_alloc_t alloc;
    id_generator_free_t free;
    void *private_data;
} urpc_id_generator_t;

int urpc_id_generator_init(urpc_id_generator_t *generator, urpc_id_generator_type_e type, unsigned size);
void urpc_id_generator_uninit(urpc_id_generator_t *generator);
int urpc_id_generator_alloc(urpc_id_generator_t *generator, unsigned int min, uint32_t *id);
void urpc_id_generator_free(urpc_id_generator_t *generator, uint32_t id);

#ifdef __cplusplus
}
#endif

#endif