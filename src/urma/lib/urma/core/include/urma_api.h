/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: URMA API
 * Author: Ouyang changchun, Bojie Li, Yan Fangfang, Qian Guoxin
 * Create: 2021-07-13
 * Note:
 * History: 2021-07-13   Create File
 */
#ifndef URMA_API_H
#define URMA_API_H

#include <stdbool.h>
#include <stdint.h>

#include "urma_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Init urma environment.
 * @param[in] [Required] conf: urma init attr, a random uasid will be assigned when conf is null.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_init(urma_init_attr_t *conf);

/**
 * Un-init urma environment, it will free uasid.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_uninit(void);

/* Device Manage API */
/**
 *  Get device list.
 * @param[out] num_devices: number of urma device;
 * Return: pointer array of urma_device; NULL means no device returned;
 * Note: urma_free_device_list() needs to be called to free memory;
 */
urma_device_t **urma_get_device_list(int *num_devices);

/**
*  free device list.
* @param[in] [Required] device_list: pointer array of urma_device,return value of urma_get_device_list.
                         Can be called after using urma_device list;
* Return: void;
*/
void urma_free_device_list(urma_device_t **device_list);

/**
 *  Get eid list.
 * @param[in] [Required] dev: device pointer
 * @param[out] cnt: Return the number of valid eids;
 * Return: If it succeeds, it will return the eid_info array pointer, and the number of elements
 * is cnt; if it fails, it will return NULL; it will be released by the user calling
 */
urma_eid_info_t *urma_get_eid_list(urma_device_t *dev, uint32_t *cnt);

/**
 *  free eid list.
 * @param[in] [Required] eid_list: The eid array pointer to be released
 * Return: void;
 */
void urma_free_eid_list(urma_eid_info_t *eid_list);

/**
 *  Get device by device name.
 * @param[in] [Required] dev_name: device's name;
 * Return: urma_device; NULL means no device returned;
 */
urma_device_t *urma_get_device_by_name(char *dev_name);

/**
 *  Get device by device eid.
 * @param[in] [Required] eid: device's eid;
 * @param[in] [Required] type: device's transport type;
 * Return: urma_device; NULL means no device returned;
 */
urma_device_t *urma_get_device_by_eid(urma_eid_t eid, urma_transport_type_t type);

/**
 * Query the attributes and capabilities of urma devices.
 * @param[in] [Required] dev: urma_device;
 * @param[out] dev_attr: Return device attributes, user needs to allocate and free the memory;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_query_device(urma_device_t *dev, urma_device_attr_t *dev_attr);

/**
 * Create an urma context on the urma device.
 * @param[in] [Required] dev: urma device, by get_device apis.
 * @param[in] [Required] eid_index: device's eid index.
 * Return urma context pointer on success, NULL on error.
 */
urma_context_t *urma_create_context(urma_device_t *dev, uint32_t eid_index);

/**
 * Delete the created urma context.
 * @param[in] [Required] ctx: handle of the created context.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_context(urma_context_t *ctx);

/**
 * Set option of urma context.
 * @param[in] [Required] ctx: handle of the created context.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_set_context_opt(urma_context_t *ctx, urma_opt_name_t opt_name, const void *opt_value,
                                   size_t opt_len);

/**
 * Create a jetty for completion (jfc).
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] jfc_cfg: configuration including: depth, flag, jfce, user context;
 * Return: the handle of created jfc, not NULL on success; NULL on error
 */
urma_jfc_t *urma_create_jfc(urma_context_t *ctx, urma_jfc_cfg_t *jfc_cfg);

/**
 * Modify JFC attributes.
 * @param[in] [Required] jfc: specify JFC;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr);

/**
 * Delete the created jfc.
 * @param[in] [Required] jfc: handle of the created jfc;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jfc(urma_jfc_t *jfc);

/**
 * Delete the created jfc in a batch.
 * @param[in] [Required] jfc_arr: the array of the jfc pointer;
 * @param[in] [Required] jfc_num: array length;
 * @param[out] [Required] bad_jfc: the address of the first failed jfc pointer;
 * Return: 0 on success, EINVAL on invalid parameter, other value on other batch
 * delete errors.
 * If delete error happens(except invalid parameter), stop at the first failed
 * jfc and return, these jfc before the failed jfc will be deleted normally.
 */
urma_status_t urma_delete_jfc_batch(urma_jfc_t **jfc_arr, int jfc_num, urma_jfc_t **bad_jfc);

/**
 * Create a jetty for send (jfs).
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] jfs_cfg: address to pu the jfs config;
 * Return: the handle of created jfs, not NULL on success, NULL on error
 */
urma_jfs_t *urma_create_jfs(urma_context_t *ctx, urma_jfs_cfg_t *jfs_cfg);

/**
 * Modify a jetty for send (jfs).
 * @param[in] [Required] jfs: the jfs created before;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr);

/**
 * Query a jetty for send (jfs).
 * @param[in] [Required] jfs: the jfs created before;
 * @param[out] [Required] cfg: config of jfs;
 * @param[out] [Required] attr: attributes of jfs;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_query_jfs(urma_jfs_t *jfs, urma_jfs_cfg_t *cfg, urma_jfs_attr_t *attr);

/**
 * Delete the created jfs.
 * @param[in] [Required] jfs: the jfs created before;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jfs(urma_jfs_t *jfs);

/**
 * Delete the created jfs in a batch.
 * @param[in] [Required] jfs_arr: the array of the jfs pointer;
 * @param[in] [Required] jfs_num: array length;
 * @param[out] [Required] bad_jfs: the address of the first failed jfs pointer;
 * Return: 0 on success, EINVAL on invalid parameter, other value on other batch
 * delete errors.
 * If delete error happens(except invalid parameter), stop at the first failed
 * jfs and return, these jfs before the failed jfs will be deleted normally.
 */
urma_status_t urma_delete_jfs_batch(urma_jfs_t **jfs_arr, int jfs_num, urma_jfs_t **bad_jfs);

/**
 * Poll the CRs for all the WRs that posted to JFS, but are not completed.
 * Call the API after modify JFS to error, or polled a suspened done CR.
 * CRs with status of URMA_CR_WR_FLUSH_ERR will be returned on success.
 * @param[in] [Required] jfs: the jfs created before;
 * @param[in] [Required] cr_cnt: Number of CR expected to be received.;
 * @param[out] [Required] cr: Address for storing CR;
 * Return: the number of CR returned, 0 means no CR returned, -1 on error
 */
int urma_flush_jfs(urma_jfs_t *jfs, int cr_cnt, urma_cr_t *cr);

/**
 * Create a jetty for receive (jfr).
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] jfr_cfg: address to put the jfr config;
 * Return: the handle of created jfr, not NULL on success, NULL on error
 */
urma_jfr_t *urma_create_jfr(urma_context_t *ctx, urma_jfr_cfg_t *jfr_cfg);

/**
 * Modify JFR attributes.
 * @param[in] [Required] jfr: specify JFR;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr);

/**
 * Query a jetty for recv(jfr).
 * @param[in] [Required] jfr: the jfr created before;
 * @param[out] [Required] cfg: config of jfr;
 * @param[out] [Required] attr: attributes of jfr;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_query_jfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr);

/**
 * Delete the created jfr.
 * @param[in] [Required] jfr: the jfr created before;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jfr(urma_jfr_t *jfr);

/**
 * Delete the created jfr in a batch.
 * @param[in] [Required] jfr_arr: the array of the jfr pointer;
 * @param[in] [Required] jfr_num: array length;
 * @param[out] [Required] bad_jfr: the address of the first failed jfr pointer;
 * Return: 0 on success, EINVAL on invalid parameter, other value on other batch
 * delete errors.
 * If delete error happens(except invalid parameter), stop at the first failed
 * jfr and return, these jfr before the failed jfr will be deleted normally.
 */
urma_status_t urma_delete_jfr_batch(urma_jfr_t **jfr_arr, int jfr_num, urma_jfr_t **bad_jfr);

/**
 * Import a remote jfr to local node.
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] rjfr: the information of remote jfr to import into user node, trans_mode required,
 *            trans_mode same to create_jfr trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty/protection table;
 * Return: the address of target jfr, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value);

/**
 * Import a remote jfr to local node by control plane.
 * Note: trans_mode from rjfr should be the same as the trans_mode of get_tp_list,
 * users should obey this rule in case of unexpected errors.
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] rjfr: the information of remote jfr to import into user node, trans_mode required,
 *            trans_mode same to create_jfr trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty/protection table;
 * @param[in] [Required] cfg: tp active configuration to exchange with target;
 * Return: the address of target jfr, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jfr_ex(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value,
                                        urma_import_jfr_ex_cfg_t *cfg);

/**
 * Unimport the imported remote jfr.
 * @param[in] [Required] target_jfr: the target jfr to unimport;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_jfr(urma_target_jetty_t *target_jfr);

/**
 *  Advise jfr: construct the transport channel for jfs and remote jfr.
 * @param[in] [Required] jfs: jfs to use to construct the transport channel;
 * @param[in] [Required] tjfr: target jfr information including full qualified jfr id;
 * Return: 0 on success, URMA_EEXIST if the jfr has been advised, other value on error
 */
urma_status_t urma_advise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);

/**
 *  Async API for urma_advise_jfr
 *  Advise jfr: construct the transport channel for jfs and remote jfr.
 * @param[in] [Required] jfs: jfs to use to construct the transport channel;
 * @param[in] [Required] tjfr: target jfr information including full qulified jfr id;
 * @param[in] [Required] cb_func: user defined callback function.
 * @param[in] [Required] cb_arg: user defined arguments for the callback function.
 * Return: 0 on success, URMA_EEXIST if the jfr has been advised, other value on error.
 * Note: User must define callback function to handle result,
 *  as the async respone will call the cb_func and pass the result to it.
 */
urma_status_t urma_advise_jfr_async(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, urma_advise_async_cb_func cb_fun,
                                    void *cb_arg);

/**
 *  Unadvise jfr: disconnect the transport channel for jfs and remote jfr. Optional API for optimization
 * @param[in] [Required] jfs: jfs to use to construct the transport channel;
 * @param[in] [Required] tjfr: target jfr information including full qualified jfr id;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr);

/**
 ******************** Beginning of URMA JETTY APIs ***************************
 */

/**
 * Create jetty, which is a pair of jfs and jfr
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] jetty_cfg: pointer of the jetty config;
 * Return: the handle of created jetty, not NULL on success, NULL on error
 */
urma_jetty_t *urma_create_jetty(urma_context_t *ctx, urma_jetty_cfg_t *jetty_cfg);

/**
 * Modify jetty attributes.
 * @param[in] [Required] jetty: specify jetty;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr);

/**
 * Query jetty attributes.
 * @param[in] [Required] jetty: specify jetty;
 * @param[out] [Required] cfg: cconfig to query;
 * @param[out] [Required] attr: attributes to query;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_query_jetty(urma_jetty_t *jetty, urma_jetty_cfg_t *cfg, urma_jetty_attr_t *attr);

/**
 * Delete the created jetty.
 * @param[in] [Required] jetty: the jetty created before;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jetty(urma_jetty_t *jetty);

/**
 * Delete the created jetty in a batch.
 * @param[in] [Required] jetty_arr: the array of the jetty pointer;
 * @param[in] [Required] jetty_num: array length;
 * @param[out] [Required] bad_jetty: the address of the first failed jetty pointer;
 * Return: 0 on success, EINVAL on invalid parameter, other value on other batch
 * delete errors.
 * If delete error happens(except invalid parameter), stop at the first failed
 * jetty and return, these jetty before the failed jetty will be deleted normally.
 */
urma_status_t urma_delete_jetty_batch(urma_jetty_t **jetty_arr, int jetty_num, urma_jetty_t **bad_jetty);

/**
 * Import a remote jetty.
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] rjetty: information of remote jetty to import, including jetty id and trans_mode,
 *            trans_mode same to create_jetty trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty protection table;
 * Return: the address of target jetty, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value);

/**
 * Import a remote jetty by control plane.
 * Note: trans_mode from rjetty should be the same as the trans_mode of get_tp_list,
 * users should obey this rule in case of unexpected errors.
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] rjetty: information of remote jetty to import, including jetty id and trans_mode,
 *            trans_mode same to create_jetty trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty protection table;
 * @param[in] [Required] cfg: tp active configuration to exchange with target;
 * Return: the address of target jetty, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jetty_ex(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *token_value,
                                          urma_import_jetty_ex_cfg_t *cfg);

/**
 * Unimport the imported remote jetty.
 * @param[in] [Required] tjetty: the target jetty to unimport;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_jetty(urma_target_jetty_t *tjetty);

/**
 *  Advise jetty: construct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to construct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * Return: 0 on success, URMA_EEXIST if the jetty has been advised, other value on error
 * Note: A local jetty can be advised with several remote jetties. A connectionless jetty is free to call the adivse API
 */
/* todo: available after implementing URMA_TM_RM(IB_RC) */
urma_status_t urma_advise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

/**
 *  Unadvise jetty: deconstruct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to deconstruct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * Return: 0 on success, other value on error
 */
/* todo: available after implementing URMA_TM_RM(IB_RC) */
urma_status_t urma_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

/**
 *  Bind jetty: construct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to construct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * Return: 0 on success, URMA_EEXIST if the jetty has been binded, other value on error
 * Note: A local jetty can be binded with only one remote jetty. Only supported by jetty under URMA_TM_RC.
 */
urma_status_t urma_bind_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty);

/**
 *  Bind jetty: construct the transport channel between local jetty and remote jetty by control plane.
 * Note: trans_mode from tjetty should be the same as the trans_mode of get_tp_list,
 * users should obey this rule in case of unexpected errors.
 * @param[in] [Required] jetty: local jetty to construct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * Return: 0 on success, URMA_EEXIST if the jetty has been binded, other value on error;
 * @param[in] [Required] cfg: tp active configuration to exchange with target;
 * Note: A local jetty can be binded with only one remote jetty. Only supported by jetty under URMA_TM_RC.
 */
urma_status_t urma_bind_jetty_ex(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, urma_bind_jetty_ex_cfg_t *cfg);

/**
 *  Unbind jetty: deconstruct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to deconstruct the transport channel;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unbind_jetty(urma_jetty_t *jetty);

/**
 * Poll the CRs for all the WRs that posted to Jetty, but are not completed.
 * Call the API after modify Jetty to error, or polled a suspened done CR.
 * CRs with status of URMA_CR_WR_FLUSH_ERR will be returned on success.
 * @param[in] [Required] jetty: the jetty created before;
 * @param[in] [Required] cr_cnt: Number of CR expected to be received.;
 * @param[out] [Required] cr: Address for storing CR;
 * Return: the number of CR returned, 0 means no CR returned, -1 on error
 */
int urma_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr);

/**
 * Import a remote jetty asynchronously.
 * @param[in] [Required] notifier: data structure used for sensing asynchronous link establishment results;
 * @param[in] [Required] rjetty: information of remote jetty to import, including jetty id and trans_mode,
 *            trans_mode same to create_jetty trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty protection table;
 * @param[in] [Required] user_ctx: user_ctx create by user;
 * @param[in] [Required] timeout: task timeout set by user (milliseconds);
 * Return: the address of target jetty, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jetty_async(urma_notifier_t *notifier, const urma_rjetty_t *rjetty,
                                             const urma_token_t *token_value, uint64_t user_ctx, int timeout);

/**
 * Unimport the imported remote jetty asynchronously.
 * @param[in] [Required] tjetty: the target jetty to unimport;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_jetty_async(urma_target_jetty_t *tjetty);

/**
 *  Bind jetty asynchronously: construct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] notifier: data structure used for sensing asynchronous link establishment results;
 * @param[in] [Required] jetty: local jetty to construct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * @param[in] [Required] user_ctx: user_ctx create by user;
 * @param[in] [Required] timeout: task timeout set by user (milliseconds);
 * Return: 0 on success, URMA_EEXIST if the jetty has been binded, other value on error
 * Note: A local jetty can be binded with only one remote jetty. Only supported by jetty under URMA_TM_RC.
 */
urma_status_t urma_bind_jetty_async(urma_notifier_t *notifier, urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                                    uint64_t user_ctx, int timeout);

/**
 *  Unbind jetty: deconstruct the transport channel between local jetty and remote jetty asynchronously.
 * @param[in] [Required] jetty: local jetty to deconstruct the transport channel;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unbind_jetty_async(urma_jetty_t *jetty);

/**
 * Create a data structure for sensing asynchronous link establishment results.
 * @param[in] [Required] ctx: the urma context created before;
 * Return: the address of urma notifier, not NULL on success, NULL on error
 */
urma_notifier_t *urma_create_notifier(urma_context_t *ctx);

/**
 * Delete the created notifier.
 * @param[in] [Required] notifier: data structure used for sensing asynchronous link establishment results;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_notifier(urma_notifier_t *notifier);

/**
 * Wait for asynchronous event notification to obtain the connection establishment result.
 * @param[in] [Required] notifier: data structure used for sensing asynchronous link establishment results;
 * @param[in] [Required] cnt: expected number of target jetty to return;
 * @param[in] [Required] timeout: max time to wait (milliseconds),
                         timeout = 0: return immediately even if no events are ready,
                         timeout = -1: an infinite timeout;
 * @param[out] [Required] notify: created by user to store target jetty results;
 * Return: the number of target jetty returned, 0 means no target jetty returned, -1 on error
 */
int urma_wait_notify(urma_notifier_t *notifier, uint32_t cnt, urma_notify_t *notify, int timeout);

/**
 * This interface is no longer functional and will be removed later.
 * Keep parameter checks to ensure the function works as before.
 */
urma_status_t urma_ack_notify(urma_context_t *ctx, uint32_t cnt, urma_notify_t *notify);

/**
 ******************** Beginning of URMA JETTY GROUP APIs ***************************
 */

/**
 * Create jetty group
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] cfg: pointer of the jetty group config;
 * Return: the handle of created jetty group, not NULL on success, NULL on error
 */
urma_jetty_grp_t *urma_create_jetty_grp(urma_context_t *ctx, urma_jetty_grp_cfg_t *cfg);

/**
 * Destroy jetty group
 * @param[in] [Required] jetty_grp: the Jetty group created before;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jetty_grp(urma_jetty_grp_t *jetty_grp);

/**
 * Create a jfce
 * @param[in] [Required] ctx: the urma context created before;
 * Return: the address of created jfce, not NULL on success, NULL on error
 */
urma_jfce_t *urma_create_jfce(urma_context_t *ctx);

/**
 * Delete a jfce
 * @param[in] [Required] jfce: the jfce to be deleted;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jfce(urma_jfce_t *jfce);

/**
 *  Get asyn event.
 * @param[in] [Required] ctx: handle of the created urma context;
 * @param[out] [Required] event: the address to put event
 * Return: 0 on success, other value on error
 */
urma_status_t urma_get_async_event(urma_context_t *ctx, urma_async_event_t *event);

/**
 *  Ack asyn event.
 * @param[in] [Required] event: the address to ack event;
 * Return: void
 */
void urma_ack_async_event(urma_async_event_t *event);

/**
 *  Request to assign a token id. token id is used to register the segment with the protection table.
 * @param[in] [Required] ctx: specifies the urma context.
 * Return: pointer to key id on success, NULL on error.
 */
urma_token_id_t *urma_alloc_token_id(urma_context_t *ctx);

/**
 *  Request to assign a token id. token id is used to register multiple segments with the protection table.
 *  Can use table mode or entry mode based on flag.
 * @param[in] [Required] ctx: specifies the urma context.
 * @param[in] [Required] flag: decides the mode of token id. use table mode if enable multi_seg in flag.
 * Return: pointer to key id on success, NULL on error.
 * Note: if use table mode, the VA address page alignment is required when register the segments.
 */
urma_token_id_t *urma_alloc_token_id_ex(urma_context_t *ctx, urma_token_id_flag_t flag);

/**
 * Request to release token id.
 * @param[in] [Required] token_id: Specifies the token id to be released.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_free_token_id(urma_token_id_t *token_id);

/**
 * Register a memory segment on specified va address for local or remote access.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] seg_cfg: Specify cfg of seg to be registered, including address, len, token, and so on;
 * Return: pointer to target segment on success, NULL on error
 * And the immedidate data wrote from clients is polled from this common jfc.
 */
urma_target_seg_t *urma_register_seg(urma_context_t *ctx, urma_seg_cfg_t *seg_cfg);

/**
 * Unregister a local memory segment on specified va address.
 * @param[in] [Required] target_seg: target segment to be unregistered;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unregister_seg(urma_target_seg_t *target_seg);

/**
 * Import a memory segment on specified ubva address.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] seg: handle of memory segment to import;
 * @param[in] [Required] token_value: token of remote side to put into output protection table;
 * @param[in] [Optional] addr: the virtual address to which the segment will be mapped;
 * @param[in] [Required] flag: flag to indicate the import attribute of memory segment;
 * Return: pointer to target segment on success, NULL on error
 */
urma_target_seg_t *urma_import_seg(urma_context_t *ctx, urma_seg_t *seg, urma_token_t *token_value, uint64_t addr,
                                   urma_import_seg_flag_t flag);

/**
 *  Unimport a memory segment on specified ubva address.
 * @param[in] [Required] tseg: the address of the target segment to unimport;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_seg(urma_target_seg_t *tseg);

/**
 * post a request to read, write, atomic or send data.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] wr: the posting request all information, including src addr, dst addr, len, jfc, flag, ordering etc.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);

/**
 * post a request to recv data.
 * @param[in] jfr: the jfr created before, which is used to put command;
 * @param[in] wr: the posting request all information, including sge, flag.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);

/**
 * post a request to read, write, atomic or send data.
 * @param[in] jetty: the jetty created before, which is used to put command;
 * @param[in] wr: the posting request all information, including src addr, dst addr, len, jfc, flag, ordering etc.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);

/**
 * post a request to recv data.
 * @param[in] jetty: the jetty created before, which is used to put command;
 * @param[in] wr: the posting request all information, including sge, flag.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jetty_recv_wr(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);

/**
 * Write data to remote node.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] target_jfr: destination jetty receiver;
 * @param[in] dst_tseg: the dst target seg imported before;
 * @param[in] src_tseg: the src target seg registered before;
 * @param[in] dst: destination address(mapping va on user node or rva in ubva on home node) to be written into
 * @param[in] src: source address(local process address space) to fetch data
 * @param[in] len: the data len to be written
 * @param[in] flag: flag to control jfs work request attritube
 * @param[in] user_ctx: the user context, such as request id(rid) etc.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_write(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr, urma_target_seg_t *dst_tseg,
                         urma_target_seg_t *src_tseg, uint64_t dst, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag,
                         uint64_t user_ctx);

/**
 * Read data from remote node.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] target_jfr: destination jetty receiver;
 * @param[in] dst_tseg: the seg registered before;
 * @param[in] src_tseg: the target seg imported before;
 * @param[in] dst: destination address(local process address space) to be written into
 * @param[in] src: source address(mapping va or rva in ubva) to fetch data
 * @param[in] len: the data len to be written
 * @param[in] flag: the flag to control jfs work request attritube
 * @param[in] user_ctx: the user context, such as request id(rid) etc.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_read(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr, urma_target_seg_t *dst_tseg,
                        urma_target_seg_t *src_tseg, uint64_t dst, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag,
                        uint64_t user_ctx);

/**
 * Send data to remote node.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] target_jfr: destination jetty receiver(with full qualifed jfr id);
 * @param[in] src_tseg: the seg registered before, can be NULL only when flag.bs.inline_flag == URMA_INLINE_ENABLE
 * @param[in] src: source address for sending;
 * @param[in] len: data length;
 * @param[in] flag: flag to control jfs work request attritube
 * @param[in] user_ctx: the user context, such as request id(rid) etc;
 * Return: 0 on success, other value on error.
 */
urma_status_t urma_send(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr, urma_target_seg_t *src_tseg, uint64_t src,
                        uint32_t len, urma_jfs_wr_flag_t flag, uint64_t user_ctx);

/**
 *  Assign local buffer to receive data from remote node.
 * @param[in] jfr: jetty receiver;
 * @param[in] recv_tseg: the locally registered segment before for receiving;
 * @param[in] buf: buffer address for receiving;
 * @param[in] len: buffer length;
 * @param[in] user_ctx: the user context, such as request id(rid) etc;
 * Return: 0 on success, other value on error.
 */
urma_status_t urma_recv(urma_jfr_t *jfr, urma_target_seg_t *recv_tseg, uint64_t buf, uint32_t len, uint64_t user_ctx);

/**
 *  Poll jfc to get completion record.
 * @param[in] jfc: jetty completion queue to poll
 * @param[in] cr_cnt: the expected number of completion record to get
 * @param[out] cr: the completion record array to fill at least cr_cnt completion records
 * Return: the number of completion record returned, 0 means no completion record returned, less than 0 on error
 * Note that: at most 16 completion records can be polled for RDMA device
 */
int urma_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);

/**
 *  Arm jfc with interrupt mode.
 * @param[in] jfc: jetty completion queue to arm to interrupt mode
 * @param[in] solicited_only: indicate it will trigger event only for packets with solicited flag.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_rearm_jfc(urma_jfc_t *jfc, bool solicited_only);

/**
 *  Wait jfce for event of any completion message is generated.
 * @param[in] jfce: jetty event channel to wait on
 * @param[in] jfc_cnt: expected jfc count to return
 * @param[in] time_out: max time to wait (milliseconds),
 *            timeout = 0: return immediately even if no events are ready,
 *            timeout = -1: an infinite timeout
 * @param[out] jfc: address to put the jfc handle
 * Return: the number of jfc returned, 0 means no jfc returned, -1 on error
 */
int urma_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[]);

/**
 *  Confirm that a JFC generated event has been processed.
 * @param[in] jfc: jfc pointer array to be acknowledged
 * @param[in] nevents: event count array to be acknowledged
 * @param[in] jfc_cnt: number of elements in the array
 * Return: void
 */
void urma_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

/**
 *  Get or allocate a uasid.
 * @param[out] uasid: the address to put uasid
 * Return: 0 on success, other value on error
 */
urma_status_t urma_get_uasid(uint32_t *uasid);

/**
 * User defined control of the context.
 * @param[in] ctx: the created urma context pointer;
 * @param[in] in: user ioctl cmd;
 * @param[out] out: result of execution;
 * Return: 0 on success, other value on error
 * Note: This API only supports UB hardware currently.
 */
urma_status_t urma_user_ctl(urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out);

/**
 * User register own log function, default rsyslog.
 * @param[in] func: log callback func;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_register_log_func(urma_log_cb_t func);

/**
 * User unregister own log function, use rsyslog.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unregister_log_func(void);

/**
 * get log level.
 * Return: urma_vlog_level_t
 */
urma_vlog_level_t urma_log_get_level(void);

/**
 * set log level.
 * @param[in] level: log level to set;
 */
void urma_log_set_level(urma_vlog_level_t level);

/**
 * get log thread tag.
 * Return: const char *
 */
const char *urma_log_get_thread_tag(void);

/**
 * set log thread tag.
 * @param[in] tag: log tag per thread;
 */
void urma_log_set_thread_tag(const char *tag);

/**
 * User tp only.
 * Get tpn of tp created when creating jetty.
 * @param[in] jetty: the created jetty pointer;
 * Return: >= 0 on success, return as tpn; < 0 on error
 */
int urma_get_tpn(urma_jetty_t *jetty);

/**
 * Get net address info list, user tp only.
 * @param[in] ctx: the created urma context pointer;
 * @param[out] cnt: numer of net address info;
 * Return: pointer of net address list; NULL on error
 */
urma_net_addr_info_t *urma_get_net_addr_list(urma_context_t *ctx, uint32_t *cnt);

/**
 * Free net address info list.
 * @param[in] net_addr_list: pointer of net address list
 */
void urma_free_net_addr_list(urma_net_addr_info_t *net_addr_list);

/**
 * Modify tp by user connection.
 * @param[in] ctx: the created urma context pointer;
 * @param[in] tpn: tpn of tp created before;
 * @param[in] cfg: tp configurations filled by user;
 * @param[in] attr: tp attributes filled by user;
 * @param[in] mask: bitmap configurations for tp attributes;
 * Return: 0 on success; other values on error
 */
int urma_modify_tp(urma_context_t *ctx, uint32_t tpn, urma_tp_cfg_t *cfg, urma_tp_attr_t *attr,
                   urma_tp_attr_mask_t mask);

/**
 * get available tp list from control plane.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] tp_cfg: tp configuration to get;
 * @param[in && out] [Required] tp_cnt: tp_cnt is the length of tp_list buffer as in parameter;
 *                                      tp_cnt is the number of tp as out parameter;
 * @param[out] [Required] tp_list: tp list to get, the buffer is allocated by user;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_get_tp_list(urma_context_t *ctx, urma_get_tp_cfg_t *cfg, uint32_t *tp_cnt, urma_tp_info_t *tp_list);

/**
 * set tp attribution values in control plane.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] tp_handle: tp_handle got by urma_get_tp_list;
 * @param[in] [Required] tp_attr_cnt: number of tp attributions;
 * @param[in] [Required] tp_attr_bitmap: tp attributions bitmap, current bitmap is as follow:
 *       0-retry_times_init: 3 bit       1-at: 5 bit                2-SIP: 128 bit
 *       3-DIP: 128 bit                  4-SMA: 48 bit              5-DMA: 48 bit
 *       6-vlan_id: 12 bit               7-vlan_en: 1 bit           8-dscp: 6 bit
 *       9-at_times: 5 bit               10-sl: 4 bit               11-ttl: 8 bit
 * @param[in] [Required] tp_attr: tp attribution values to set;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_set_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, const uint8_t tp_attr_cnt,
                               const uint32_t tp_attr_bitmap, const urma_tp_attr_value_t *tp_attr);

/**
 * get tp attribution values in control plane.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] tp_handle: tp_handle got by urma_get_tp_list;
 * @param[out] [Required] tp_attr_cnt: number of tp attributions;
 * @param[out] [Required] tp_attr_bitmap: tp attributions bitmap, current bitmap is as follow:
 *       0-retry_times_init: 3 bit       1-at: 5 bit                2-SIP: 128 bit
 *       3-DIP: 128 bit                  4-SMA: 48 bit              5-DMA: 48 bit
 *       6-vlan_id: 12 bit               7-vlan_en: 1 bit           8-dscp: 6 bit
 *       9-at_times: 5 bit               10-sl: 4 bit               11-ttl: 8 bit
 * @param[out] [Required] tp_attr: tp attribution values to get;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_get_tp_attr(const urma_context_t *ctx, const uint64_t tp_handle, uint8_t *tp_attr_cnt,
                               uint32_t *tp_attr_bitmap, urma_tp_attr_value_t *tp_attr);

#ifdef __cplusplus
}
#endif

#endif
