/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Import a remote jfr to local node.
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] rjfr: the information of remote jfr to import into user node, trans_mode required,
 *            trans_mode same to create_jfr trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty/protection table;
 * Return: the address of target jfr, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token_value);

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
urma_status_t urma_advise_jfr_async(urma_jfs_t *jfs, urma_target_jetty_t *tjfr,
    urma_advise_async_cb_func cb_fun, void *cb_arg);

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
 * Import a remote jetty.
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] rjetty: information of remote jetty to import, including jetty id and trans_mode,
 *            trans_mode same to create_jetty trans_mode;
 * @param[in] [Required] token_value: token to put into output jetty protection table;
 * Return: the address of target jetty, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, urma_rjetty_t *rjetty,
    urma_token_t *token_value);


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
 *  Async API for urma_advise_jetty
 *  Advise jfr: construct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to construct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * @param[in] [Required] cb_func: user defined callback function.
 * @param[in] [Required] cb_arg: user defined arguments for the callback function.
 * Return: 0 on success, URMA_EEXIST if the jetty has been advised, other value on error.
 * Note: User must define callback function to handle result,
 *  as the async respone will call the cb_func and pass the result to it.
 */
/* todo: available after implementing URMA_TM_RM(IB_RC) */
urma_status_t urma_advise_jetty_async(urma_jetty_t *jfs, urma_target_jetty_t *tjetty,
    urma_advise_async_cb_func cb_fun, void *cb_arg);

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
 * Note: in current IB provider, all segments to be registerred must use a common jfc,
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
 * @param[in] [Required] token_value: token to put into output protection table;
 * @param[in] [Optional] addr: the virtual address to which the segment will be mapped;
 * @param[in] [Required] flag: flag to indicate the import attribute of memory segment;
 * Return: pointer to target segment on success, NULL on error
 */
urma_target_seg_t *urma_import_seg(urma_context_t *ctx, urma_seg_t *seg,
    urma_token_t *token_value, uint64_t addr, urma_import_seg_flag_t flag);

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
urma_status_t urma_write(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,
    urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg,
    uint64_t dst, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag, uint64_t user_ctx);
 
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
urma_status_t urma_read(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,
    urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg,
    uint64_t dst, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag, uint64_t user_ctx);

/**
 * Send data to remote node.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] target_jfr: destination jetty receiver(with full qualifed jfr id);
 * @param[in] src_tseg: the seg registered before;
 * @param[in] src: source address for sending;
 * @param[in] len: data length;
 * @param[in] flag: flag to control jfs work request attritube
 * @param[in] user_ctx: the user context, such as request id(rid) etc;
 * Return: 0 on success, other value on error.
 */
urma_status_t urma_send(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,
    urma_target_seg_t *src_tseg, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag, uint64_t user_ctx);

/**
 *  Assign local buffer to receive data from remote node.
 * @param[in] jfr: jetty receiver;
 * @param[in] recv_tseg: the locally registered segment before for receiving;
 * @param[in] buf: buffer address for receiving;
 * @param[in] len: buffer length;
 * @param[in] user_ctx: the user context, such as request id(rid) etc;
 * Return: 0 on success, other value on error.
 */
urma_status_t urma_recv(urma_jfr_t *jfr, urma_target_seg_t *recv_tseg,
    uint64_t buf, uint32_t len, uint64_t user_ctx);

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
 * Note: Repeatedly calling this API without calling [urma_poll_jfc] may lead to
 *       incorrect number of jfc in IP provider. This error is controllable.
 */
int urma_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
    urma_jfc_t *jfc[]);

/**
 *  Confirm that a JFC generated event has been processed.
 * @param[in] jfc: jfc pointer array to be acknowledged
 * @param[in] nevents: event count array to be acknowledged
 * @param[in] jfc_cnt: number of elements in the array
 * Return: void
 */
void urma_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt);

/**
 *  Allocate DSVA address range.
 * @param[in] size: the DSVA address range size
 * Return: DSVA address range base, 0 on error
 */
uint64_t urma_dsva_alloc(uint32_t size);

/**
 *  Free DSVA address.
 * @param[in] dsva: the DSVA address
 * Return: 0 on success, other value on error
 */
urma_status_t urma_dsva_free(uint64_t dsva);

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

#ifdef __cplusplus
}
#endif

#endif
