/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: UVS API
 * Author: Zheng Hongqin
 * Create: 2023-10-11
 * Note:
 * History:
 */

#ifndef UVS_API_H
#define UVS_API_H

#include <stdbool.h>
#include <stdint.h>

#include "uvs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * init uvs so.
 * @param[in] [Required] attr: server config;
 * Return: 0 on success, other value on error.
 */
int uvs_so_init(uvs_init_attr_t *attr);

/**
 * uninit uvs so.
 */
void uvs_so_uninit(void);

/**
 * Add global configurations.
 * @param[in] [Required] info: pointer of global configurations;
 * Return: 0 on success, other value on error.
 */
int uvs_add_global_info(uvs_global_info_t *info);

/**
 * Delete global configurations.
 * Return: 0 on success, other value on error.
 */
int uvs_del_global_info(void);

/**
 * Delete global configurations.
 * Return: pointer of global configurations; NULL means no global configurations returned;
 * Note: uvs_list_global_info() needs to be called to free memory;
 */
uvs_global_info_t *uvs_list_global_info(void);

/**
 * Delete global configurations.
 * @param[in] info: global configurations needed to modify;
 * Return: 0 on success, other value on error.
 */
int uvs_modify_global_info(uvs_global_mod_info_t *info);

#endif