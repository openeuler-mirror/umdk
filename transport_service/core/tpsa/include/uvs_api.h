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
 * List global configurations.
 * Return: pointer of global configurations; NULL means no global configurations returned;
 * Note: free() needs to be called to free memory after calling uvs_list_global_info();
 */
uvs_global_info_t *uvs_list_global_info(void);

/**
 * Add the vport table entry.
 * @param[in] [Required] info: pointer of vport table entry;
 * Return: 0 on success, other value on error.
 */
int uvs_add_vport(uvs_vport_info_t *info);

/**
 * Delete the vport table entry.
 * @param[in] [Required] tpf_name: tpf device name;
 * @param[in] [Required] fe_idx: the id of vf;
 * Return: 0 on success, other value on error.
 */
int uvs_del_vport(const char *tpf_name, uint16_t fe_idx);

/**
 * Show the vport table entry.
 * @param[in] [Required] tpf_name: tpf device name;
 * @param[in] [Required] fe_idx: the id of vf;
 * @param[out] [Required] info: the vport entry;
 * Return: 0 on success, other value on error.
 */
int uvs_show_vport(char *tpf_name, uint16_t fe_idx, uvs_vport_info_t *info);

/**
 * Modify the vport table entry.
 * @param[in] [Required] info: pointer of modified vport info ;
 * Return: 0 on success, other value on error.
 */
int uvs_modify_vport(uvs_vport_info_t *info);

/**
 * Add sip table entry.
 * @param[in] [Required] sip_info: pointer of sip table entry;
 * Return: 0 on success, other value on error.
 */
int uvs_add_sip(uvs_sip_info_t *sip_info);

/**
 * Delete sip table entry.
 * @param[in] [Required] tpf_name: tpf device name;
 * Return: 0 on success, other value on error.
 */
int uvs_delete_sip(const char *tpf_name);

/**
 * List sip table entry.
 * @param[out] cnt: count of sip table entry;
 * Return: pointer of sip table entry; NULL means no sip table entry returned;
 * Note: uvs_free_sip_list() needs to be called to free memory after calling uvs_get_list_sip();
 */
uvs_sip_info_t **uvs_get_list_sip(uint32_t *cnt);

/**
 * Free sip table entry memory.
 * @param[in] [Required] sip: pointer of sip table entry;
 * @param[in] [Required] cnt: count of sip table entry;
 * Return: void.
 */
void uvs_free_sip_list(uvs_sip_info_t **sip, uint32_t cnt);

/**
* query fe_idx
* @param[in] tpf_name: tpf dev name
* @param[in] devid: devid of vf
* @param[out] fe_idx: fe index
*/
int uvs_query_fe_idx(const char* tpf_name, const uvs_devid_t *devid, uint16_t *fe_idx);

/**
* config dscp vl mapping
* @param[in] tpf_name: the tpf dev name
* @param[in] dscp: the dscp value array
* @param[in] vl: the vl value array
* @param[in] num: array num, range is [0, 64]
*/
int uvs_config_dscp_vl(const char *tpf_name, uint8_t *dscp, uint8_t *vl, uint8_t num);

/**
* call this func when uvs_adapter active/construct
* @param[in] user_ops: user option
* Return: 0 on success, other value on error.
*/
int uvs_register_user_ops(uvs_user_ops_t *user_ops);

/**
* call this func when uvs_adapter deactive/destruct
* @param[in] user_ops: user option
* Return: void.
*/
void uvs_unregister_user_ops(uvs_user_ops_t *user_ops);

/**
* call this func to query all tpf name in uvs
* @param[out] cnt: cnt save in uvs
* Return: tpf name array pointer. NULL on failed.
*/
uvs_tpf_t **uvs_list_tpf(int *cnt);

/**
* call this func to free all tpf name memory which alloc in uvs_list_tpf func.
* @param[in] tpfs: tpf name array pointer
* @param[in] cnt: tpf name array entry cnt
* Return: void.
*/
void uvs_free_tpf(uvs_tpf_t **tpfs, uint32_t cnt);

/**
* call this func to get user ops.
* @param[in] user_ops: user ops
* Return: uvs_user_ops pointer. NULL on falied
*/
uvs_user_ops_t* get_uvs_user_ops(user_ops_t user_ops);

#ifdef __cplusplus
}
#endif

#endif