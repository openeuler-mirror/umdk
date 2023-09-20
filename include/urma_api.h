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
urma_status_t urma_init(const urma_init_attr_t *conf);

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
 *  Get device by device name.
 * @param[in] [Required] dev_name: device's name;
 * Return: urma_device; NULL means no device returned;
 */
urma_device_t *urma_get_device_by_name(const char *dev_name);

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
urma_status_t urma_query_device(const urma_device_t *dev, urma_device_attr_t *dev_attr);

/**
 * Create an urma context on the urma device.
 * @param[in] [Required] dev: urma device, by get_device apis.
 * Return urma context pointer on success, NULL on error.
 */
urma_context_t *urma_create_context(urma_device_t *dev);

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
urma_jfc_t *urma_create_jfc(urma_context_t *ctx, const urma_jfc_cfg_t *jfc_cfg);

/**
 * Modify JFC attributes.
 * @param[in] [Required] jfc: specify JFC;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jfc(urma_jfc_t *jfc, const urma_jfc_attr_t *attr);

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
urma_jfs_t *urma_create_jfs(urma_context_t *ctx, const urma_jfs_cfg_t *jfs_cfg);

/**
 * Delete the created jfs.
 * @param[in] [Required] jfs: the jfs created before;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_delete_jfs(urma_jfs_t *jfs);

 /**
 * Create a jetty for receive (jfr).
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] jfr_cfg: address to put the jfr config;
 * Return: the handle of created jfr, not NULL on success, NULL on error
 */
urma_jfr_t *urma_create_jfr(urma_context_t *ctx, const urma_jfr_cfg_t *jfr_cfg);

/**
 * Modify JFR attributes.
 * @param[in] [Required] jfr: specify JFR;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jfr(urma_jfr_t *jfr, const urma_jfr_attr_t *attr);

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
 * @param[in] [Required] key: key to put into output jetty/protection table;
 * Return: the address of target jfr, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jfr(urma_context_t *ctx, const urma_rjfr_t *rjfr, const urma_key_t *key);

/**
 * Unimport the imported remote jfr.
 * @param[in] [Required] target_jfr: the target jfr to unimport;
 * @param[in] [Required] force: unimport jfr by force;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_jfr(urma_target_jetty_t *target_jfr, bool force);

/**
 *  Advise jfr: construct the transport channel for jfs and remote jfr.
 * @param[in] [Required] jfs: jfs to use to construct the transport channel;
 * @param[in] [Required] tjfr: target jfr information including full qualified jfr id;
 * Return: 0 on success, URMA_EEXIST if the jfr has been advised, other value on error
 */
urma_status_t urma_advise_jfr(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr);

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
urma_status_t urma_advise_jfr_async(urma_jfs_t *jfs, const urma_target_jetty_t *tjfr,
    urma_advise_async_cb_func cb_fun, void *cb_arg);

/**
 *  Unadvise jfr: disconnect the transport channel for jfs and remote jfr. Optional API for optimization
 * @param[in] [Required] jfs: jfs to use to construct the transport channel;
 * @param[in] [Required] tjfr: target jfr information including full qualified jfr id;
 * @param[in] [Required] force: destroy the transport channel by force;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unadvise_jfr(urma_jfs_t *jfs, urma_target_jetty_t *tjfr, bool force);

/**
 ******************** Beginning of URMA JETTY APIs ***************************
 */

/**
 * Create jetty, which is a pair of jfs and jfr
 * @param[in] [Required] ctx: the urma context created before;
 * @param[in] [Required] jetty_cfg: pointer of the jetty config;
 * Return: the handle of created jetty, not NULL on success, NULL on error
 */
urma_jetty_t *urma_create_jetty(urma_context_t *ctx, const urma_jetty_cfg_t *jetty_cfg);

/**
 * Modify jetty attributes.
 * @param[in] [Required] jetty: specify jetty;
 * @param[in] [Required] attr: attributes to be modified;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_modify_jetty(urma_jetty_t *jetty, const urma_jetty_attr_t *attr);

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
 * @param[in] [Required] rjetty_key: key to put into output jetty protection table;
 * Return: the address of target jetty, not NULL on success, NULL on error
 */
urma_target_jetty_t *urma_import_jetty(urma_context_t *ctx, const urma_rjetty_t *rjetty, const urma_key_t *rjetty_key);


/**
 * Unimport the imported remote jetty.
 * @param[in] [Required] tjetty: the target jetty to unimport;
 * @param[in] [Required] force: flag to indicate how to unimport jetty;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_jetty(urma_target_jetty_t *tjetty, bool force);

/**
 *  Advise jetty: construct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to construct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * Return: 0 on success, URMA_EEXIST if the jetty has been advised, other value on error
 * Note: A local jetty can be advised with several remote jetties. A connectionless jetty is free to call the adivse API
 */
urma_status_t urma_advise_jetty(urma_jetty_t *jetty, const urma_target_jetty_t *tjetty);

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
urma_status_t urma_advise_jetty_async(urma_jetty_t *jfs, const urma_target_jetty_t *tjetty,
    urma_advise_async_cb_func cb_fun, void *cb_arg);

/**
 *  Unadvise jetty: deconstruct the transport channel between local jetty and remote jetty.
 * @param[in] [Required] jetty: local jetty to deconstruct the transport channel;
 * @param[in] [Required] tjetty: target jetty imported before;
 * @param[in] [Required] force: force to destroy corresponding qp under IB_XRC
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unadvise_jetty(urma_jetty_t *jetty, urma_target_jetty_t *tjetty, bool force);

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
 * @param[in] [Required] force: flag to indicate how to unbind jetty;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unbind_jetty(urma_jetty_t *jetty, bool force);

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
urma_status_t urma_get_async_event(const urma_context_t *ctx, urma_async_event_t *event);

/**
 *  Ack asyn event.
 * @param[in] [Required] event: the address to ack event;
 * Return: void
 */
void urma_ack_async_event(urma_async_event_t *event);

/**
 *  Register event handler.
 * @param[in] [Required] cb: event handler
 * Return: 0 on success, other value on error
 */
urma_status_t urma_reg_async_event_cb(const urma_async_event_cb *cb);

/**
 *  Request to assign a key id. Key id is used to register the segment with the protection table.
 * @param[in] [Required] ctx: specifies the urma context.
 * Return: pointer to key id on success, NULL on error.
 */
urma_key_id_t *urma_alloc_key_id(urma_context_t *ctx);

/**
 * Request to release key id.
 * @param[in] [Required] key_id: Specifies the key id to be released.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_free_key_id(urma_key_id_t *key_id);

/**
 * Register a memory segment on specified va address for local or remote access.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] seg_cfg: Specify cfg of seg to be registered, including address, len, key, and so on;
 * Return: pointer to target segment on success, NULL on error
 * Note: in current IB provider, all segments to be registerred must use a common jfc,
 * And the immedidate data wrote from clients is polled from this common jfc.
 */
urma_target_seg_t *urma_register_seg(urma_context_t *ctx, const urma_seg_cfg_t *seg_cfg);

/**
 * Unregister a local memory segment on specified va address.
 * @param[in] [Required] target_seg: target segment to be unregistered;
 * @param[in] [Required] force: unregister the segment on force regardless of the possbile users;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unregister_seg(urma_target_seg_t *target_seg, bool force);

/**
 * Import a memory segment on specified ubva address.
 * @param[in] [Required] ctx: the created urma context pointer;
 * @param[in] [Required] seg: handle of memory segment to import;
 * @param[in] [Required] key: key to put into output protection table;
 * @param[in] [Optional] addr: the virtual address to which the segment will be mapped;
 * @param[in] [Required] flag: flag to indicate the import attribute of memory segment;
 * Return: pointer to target segment on success, NULL on error
 */
urma_target_seg_t *urma_import_seg(urma_context_t *ctx, const urma_seg_t *seg,
    const urma_key_t *key, uint64_t addr, urma_import_seg_flag_t flag);

/**
 *  Unimport a memory segment on specified ubva address.
 * @param[in] [Required] tseg: the address of the target segment to unimport;
 * @param[in] [Required] force: flag to indicate how to unimport segment;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_seg(urma_target_seg_t *tseg, bool force);

/**
 ******************** Beginning of L2 API for URMA Region ********************
*/
#ifdef L2API_ENABLE
/**
 * Create and register a urma region (ur) with specified name and size.
 * @param[in] name: the urma region name to create;
 * @param[in] size: size of urma region;
 * @param[in] flag: flag to indicate the attribute of urma region;
 * @param[in] user_ctx: user context;
 * @param[out] ur: returned urma region handle;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_create_ur(const char *name, uint64_t size, urma_ur_attr_t flag, uintptr_t user_ctx,
    urma_ur_t **ur);

/**
 * Unregister a local memory segment on specified va address.
 * @param[in] ur: handle of the created urma context to be destroyed;
 * @param[in] force: destroy the urma region on force regardless of the possbile users;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_destroy_ur(urma_ur_t *ur, bool force);

/**
 * Attach one or more memory segments into specified ur.
 * @param[in] ur_name: the created urma region name;
 * @param[in] start_idx: start index to attach seg list;
 * @param[in] seg_list: list of memory segment to attach;
 * @param[in] seg_cnt: seg count in the seg list;
 * Return: the number segment of successfully attached.
 */
uint32_t urma_attach_ur(const char *ur_name, uint32_t start_idx, const urma_target_seg_t **seg_list, uint32_t seg_cnt);

/**
 *  Dettach one or more memory segments from specified ur.
 * @param[in] ur_name: the created urma region name;
 * @param[in] seg_list: the list of the segments to be detached;
 * @param[in] seg_cnt: seg count in the seg list;
 * @param[in] force: flag to indicate how to detach segments;
 * Return: the number segment of successfully detached.
 */
uint32_t urma_detach_ur(const char *ur_name, const urma_target_seg_t **seg_list, uint32_t seg_cnt, bool force);

/**
 * Import a urma region, including all segments inside.
 * @param[in] ctx: the created urma context pointer;
 * @param[in] ur_info: handle of urma region to import;
 * @param[in] token_list: token list to put into output protection table, one for each segment in ur;
 * @param[in] token_cnt: token count in the token list;
 * @param[in] addr: the start virtual address to which the urma region will be mapped from;
 * @param[in] flag: flag to indicate the import attribute of urma region;
 * Return: pointer to target ur on success, NULL on error
 */
urma_target_ur_t *urma_import_ur(urma_context_t *ctx, const urma_ur_info_t *ur_info,
    const urma_key_t **token_list, uint32_t token_cnt, uint64_t addr, urma_import_ur_flag_t flag);

/**
 *  Unimport a target urma region.
 * @param[in] tgt_ur: the address of the target urma region to unimport;
 * @param[in] force: flag to indicate how to unimport target urma region;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unimport_ur(urma_target_ur_t *tgt_ur, bool force);

/**
 *  Get urma region list from ubsc, just return each urma region name.
 * @param[in] cnt: specify the number of ur that can be stored in the ur_list.
 * @param[out] ur_list: the address to put the urma region name list;
 * @param[out] ret_cnt: Returns the actual number of ur;
 * Return: 0 on success, other value on error
 *         URMA_EAGAIN: Application according to ret_cnt allocate more space and try calling this interface again.
 *         When return URMA_EAGAIN, the ur_list does not contain any valid information.
 * Note: Applications need to be allocated and released ur_list memory.
 */
urma_status_t urma_get_ur_list(uint32_t req_cnt, char *ur_list, uint32_t *ret_cnt);

/**
 * Lookup urma region with specified name.
 * @param[in] ur_name: the urma region name;
 * @param[in] req_cnt: specify the number of seg that can be stored in the ur_info.
 * @param[out] ur_info: returned urma region info, including attribute, seg list etc;
 * Return: 0 on success, other value on error
 *         URMA_EAGAIN: Application according to ur_info returns cnt to allocate more space
 *         and try calling this interface again.
 *         When return URMA_EAGAIN, the ur_info does not contain any valid information.
 * Note: Applications need to be allocated and released ur_info memory.
 */
urma_status_t urma_lookup_ur(const char *ur_name, uint32_t req_cnt, urma_ur_info_t *ur_info);

/**
 ******************** Beginning of L2 API for named jfr ********************
*/

/**
 * register a jfr to ubsc with specified name and size.
 * @param[in] jfr_name: the jfr name to create;
 * @param[in] jfr: the handle of created jfr
 * Return: 0 on success, other value on error
 */
urma_status_t urma_register_named_jfr(const char *jfr_name, const urma_jfr_t *jfr);

/**
 * unregister a named jfr to ubsc.
 * @param[in] jfr_name: the jfr name to destroy;
 * Return: 0 on success, other value on error
 */
urma_status_t urma_unregister_named_jfr(const char *jfr_name);

/**
 *  Get named jfr list from ubsc, just return each named jfr name.
 * @param[in] req_cnt: specify the number of ur that can be stored in the ur_list.
 * @param[out] jfr_list: the address to put the named jfr name list;
 * @param[out] ret_cnt: Returns the actual number of named_jfr;
 * Return: 0 on success, other value on error
 *         URMA_EAGAIN: Application according to ret_cnt allocate more space and try calling this interface again.
 *         When return URMA_EAGAIN, the jfr_list does not contain any valid information.
 * Note: Applications need to be allocated and released jfr_list memory.
 */
urma_status_t urma_get_named_jfr_list(uint32_t req_cnt, char *jfr_list, uint32_t *ret_cnt);

/**
 * Lookup named jfr info with specified name.
 * @param[in] jfr_name: the named jfr name;
 * @param[out] jfr_info: returned named jfr info, including eid\uasid etc;
 * Return: 0 on success, other value on error
 * Note: Applications need to be allocated and released jfr_info memory.
 */
urma_status_t urma_lookup_named_jfr(const char *jfr_name, urma_jfr_info_t *jfr_info);
#endif

/**
 * post a request to read, write, atomic or send data.
 * @param[in] jfs: the jfs created before, which is used to put command;
 * @param[in] wr: the posting request all information, including src addr, dst addr, len, jfc, flag, ordering etc.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jfs_wr(const urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);

/**
 * post a request to recv data.
 * @param[in] jfr: the jfr created before, which is used to put command;
 * @param[in] wr: the posting request all information, including sge, flag.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jfr_wr(const urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);

/**
 * post a request to read, write, atomic or send data.
 * @param[in] jetty: the jetty created before, which is used to put command;
 * @param[in] wr: the posting request all information, including src addr, dst addr, len, jfc, flag, ordering etc.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jetty_send_wr(const urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr);

/**
 * post a request to recv data.
 * @param[in] jetty: the jetty created before, which is used to put command;
 * @param[in] wr: the posting request all information, including sge, flag.
 * @param[in] bad_wr: the first of failure request.
 * Return: 0 on success, other value on error
 */
urma_status_t urma_post_jetty_recv_wr(const urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr);

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
urma_status_t urma_write(const urma_jfs_t *jfs, const urma_target_jetty_t *target_jfr,
    const urma_target_seg_t *dst_tseg, const urma_target_seg_t *src_tseg,
    uint64_t dst, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag, uintptr_t user_ctx);

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
urma_status_t urma_read(const urma_jfs_t *jfs, const urma_target_jetty_t *target_jfr,
    const urma_target_seg_t *dst_tseg, const urma_target_seg_t *src_tseg,
    uint64_t dst, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag, uintptr_t user_ctx);

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
urma_status_t urma_send(const urma_jfs_t *jfs, const urma_target_jetty_t *target_jfr,
    const urma_target_seg_t *src_tseg, uint64_t src, uint32_t len, urma_jfs_wr_flag_t flag, uintptr_t user_ctx);

/**
 *  Assign local buffer to receive data from remote node.
 * @param[in] jfr: jetty receiver;
 * @param[in] recv_tseg: the locally registered segment before for receiving;
 * @param[in] buf: buffer address for receiving;
 * @param[in] len: buffer length;
 * @param[in] user_ctx: the user context, such as request id(rid) etc;
 * Return: 0 on success, other value on error.
 */
urma_status_t urma_recv(const urma_jfr_t *jfr, urma_target_seg_t *recv_tseg,
    uint64_t buf, uint32_t len, uintptr_t user_ctx);


/**
 *  Poll jfc to get completion record.
 * @param[in] jfc: jetty completion queue to poll
 * @param[in] cr_cnt: the expected number of completion record to get
 * @param[out] cr: the completion record array to fill at least cr_cnt completion records
 * Return: the number of completion record returned, 0 means no completion record returned, -1 on error
 * Note that: at most 16 completion records can be polled for RDMA device
 */
int urma_poll_jfc(const urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr);

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
int urma_wait_jfc(const urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out,
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
uint64_t urma_alloc(uint32_t size);

/**
 *  Free DSVA address.
 * @param[in] dsva: the DSVA address
 * Return: 0 on success, other value on error
 */
urma_status_t urma_free(uint64_t dsva);

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
urma_status_t urma_user_ctl(const urma_context_t *ctx, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out);

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
