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
 * init uvs socket.
 * @param[in] [Required] attr: server config;
 * Return: 0 on success, other value on error.
 */
int uvs_socket_init(uvs_socket_init_attr_t *attr);

/**
 * uninit uvs socket.
 */
void uvs_socket_uninit(void);

/**
 * restore table from ubcore.
 * Return: 0 on success, other value on error.
 */
int uvs_restore_table(void);

/**
 * notify uvs that vport and sip add finished.
 */
void uvs_table_input_finish(void);

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
 * @param[in] [Required] key: name;
 * Return: 0 on success, other value on error.
 */
int uvs_del_vport(uvs_vport_info_key_t *key);

/**
 * Show the vport table entry.
 * @param[in] [Required] name: info key;
 * @param[out] [Required] info: the vport entry;
 * Return: 0 on success, other value on error.
 */
int uvs_show_vport(uvs_vport_info_key_t *key, uvs_vport_info_t *info);

/**
 * Modify the vport table entry.
 * @param[in] [Required] info: pointer of modified vport info ;
 * Return: 0 on success, other value on error.
 */
int uvs_modify_vport(uvs_vport_info_t *info);

/**
 * Add sip table entry.
 * @param[in] [Required] sip_info: pointer of sip table entry;
 * @param[out] [Required] sip_idx: the index of sip entry;
 * Return: 0 on success, other value on error.
 */
int uvs_add_sip(uvs_sip_info_t *sip_info, uint32_t *sip_idx);

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
* query dscp vl mapping
* @param[in] tpf_name: the tpf dev name
* @param[in] dscp: the dscp value array
* @param[in] num: array num, range is [0, 64]
* @param[out] vl: the vl value array
*/
int uvs_query_dscp_vl(const char *tpf_name, uint8_t *dscp, uint8_t num, uint8_t *vl);

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
* call this func to query vport link statistics by tpf name and vport
* @param[in] tpf_name: tpf name
* @param[in] vport: vport name
* @param[out] st: vport statistics, including normal and abnormal link setup statistics
* Return: 0 on success, other value on error.
*/
int uvs_query_vport_statistic(const char* tpf_name, uvs_vport_info_key_t *vport,
    uvs_vport_statistic_t *st);

/**
* call this func to query tpf link statistics by tpf name
* @param[in] tpf_name: tpf name
* @param[out] st: tpf statistics, including normal and abnormal link setup statistics
* Return: 0 on success, other value on error.
*/
int uvs_query_tpf_statistic(const char* tpf_name, uvs_tpf_statistic_t *st);

/**
 * Register a callback function
 * @cb_func: user supplied event callback function
 * @cb_arg: pointer to the user defined parameters for the callback
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_register_event_cb(uvs_event_cb_t cb_func, void *cb_arg);

/**
 * Unregister the callback function
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_unregister_event_cb(void);

/**
 * Not used for now
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_delete_dip(uvs_ueid_t *ueid);

/**
 * Update the dip of third node
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_update_dip(uvs_ueid_t *ueid, uvs_net_addr_info_t *old_dip, uvs_net_addr_info_t *new_dip);

/**
 * notify uvs to start live migration
 * @dueid: user supplied peer ueid
 * @dip: user supplied peer ip
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_add_migration_task(uvs_ueid_t *dueid, uvs_net_addr_t *dip);

/**
 * Get the list of ueid and hits in live migrate
 * @mig_list: list of ueid and hits in live migrate
 * @cnt: count of mig_list
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_list_migration_task(uvs_mig_entry_list_t *mig_list, uint32_t *cnt);

/**
 * notify uvs to terminate live migration
 * @dueid: user supplied peer ueid
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_del_migration_task(uvs_ueid_t *dueid);

/**
 * Get statistics info depend on tpf name and keys
 * @param[in] tpf_name:tpf name to locate ubcore device
 * @param[in] key:stats keys (type and id) used for find statistics
 * @param[out] val:value found depend on type and id in key
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_query_stats(const char *tpf_name, uvs_stats_key_t *key, uvs_stats_val_t *val);

/**
 * Get resource info depend on tpf name and keys
 * @param[in] tpf_name:tpf name to locate device
 * @param[in] key: resource keys used for find val
 * @param[out] val:value found depend on key
 * Return: 0 (URMA_SUCCESS) on success, other value on error
 */
int uvs_query_resource(const char *tpf_name, uvs_res_key_t *key, uvs_res_val_t *val);

#ifdef __cplusplus
}
#endif

#endif