/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: Public header file of URPC function
 * Create: 2024-1-1
 * Note:
 * History: 2024-1-1
 */

#ifndef URPC_API_H
#define URPC_API_H

#include "urpc_framework_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* base api */
/**
 * Initialize URPC
 * @param[in] cfg: URPC configuration, such as device name
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows.
 * -URPC_ERR_EPERM: Already initialized.
 * -URPC_ERR_EINVAL: Invalid parameter.
 * -URPC_ERR_INIT_PART_FAIL: Partial providers init failed
 * URPC_FAIL: Common error code.
 */
int urpc_init(urpc_config_t *cfg);

/**
 * unInitialize URPC
 */
void urpc_uninit(void);

/**
 * Register allocator for URPC
 * @param[in] allocator: Allocator pointer
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_allocator_register(struct urpc_allocator *allocator);

/**
 * Unegister allocator for URPC
 * @param[in] : None
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EPERM: URPC allocator is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_allocator_unregister(void);

/**
 * a memory segment enable featrue: can be access by remote.
 * @param[in] urpc_chid: id of channel can remote access the memory segment
 * @param[in] mem_h: mem seg handle
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid channel
 * -URPC_ERR_EBUSY: channel can not afford more mem_h
 */
int urpc_mem_seg_remote_access_enable(uint32_t urpc_chid, uint64_t mem_h);
 
/**
 * a memory segment dsiable featrue: can be access by remote.
 * @param[in] urpc_chid: id of channel can remote access the memory segment
 * @param[in] mem_h: mem seg handle
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid channel
 */
int urpc_mem_seg_remote_access_disable(uint32_t urpc_chid, uint64_t mem_h);

/* channel api */
/**
 * Create URPC channel and save context information for function calls
 * @param[in]: None
 * Return: Channel ID (urpc_chid) on success, URPC_U32_FAIL on failure
 */
uint32_t urpc_channel_create(void);

/**
 * Destroy URPC channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid channel
 * -URPC_ERR_EBUSY: Channel is busy
 */
int urpc_channel_destroy(uint32_t urpc_chid);

/**
 * Query URPC channel configuration
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[out] cfg: Configuration information for the channel (cfg)
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_channel_cfg_get(uint32_t urpc_chid, urpc_ccfg_get_t *cfg);

/**
 * Set URPC channel configuration
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] cfg: Configuration information for the channel (cfg)
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_channel_cfg_set(uint32_t urpc_chid, urpc_ccfg_set_t *cfg);

/**
 * async or sync attach server to URPC channel, query server capabilities
 * (such as queue information, function information), and attempt to establish a connection
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] server: server information (server)
 * @param[in] option: configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_channel_server_attach(uint32_t urpc_chid, urpc_host_info_t *server, urpc_channel_connect_option_t *option);

/**
 * async or sync refresh URPC channel to server, such as after add local and remote queue,
 * we need notify server to advise queue in not quikly relpy mode.
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] option: configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_channel_server_refresh(uint32_t urpc_chid, urpc_channel_connect_option_t *option);

/**
 * async or sync detach server from URPC channel and break connection
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] server: server information (server)
 * @param[in] option: configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_channel_server_detach(uint32_t urpc_chid, urpc_host_info_t *server, urpc_channel_connect_option_t *option);

/**
 * Start control plane listening thread after URPC server resources are created, allowing clients to attach
 * @param[in] cfg: URPC control plane configuration, such as server listen address
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EPERM: URPC is not ready yet
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_server_start(urpc_control_plane_config_t *cfg);

/**
 * Bind queue to URPC channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_ENOMEM: No memory
 * -URPC_ERR_EBUSY: Channel is busy or can not afford more queue
 * URPC_FAIL: Common error code
 */

/**
 * async or sync bind queue from URPC channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * @param[in] attr: Queue attributes (attr)
 * @param[in] option: asynchronous configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_channel_queue_add(
    uint32_t urpc_chid, uint64_t urpc_qh, urpc_channel_queue_attr_t attr, urpc_channel_connect_option_t *option);

/**
 * async or sync unbind queue from URPC channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * @param[in] attr: Queue attributes (attr)
 * @param[in] option: asynchronous configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_channel_queue_rm(
    uint32_t urpc_chid, uint64_t urpc_qh, urpc_channel_queue_attr_t attr, urpc_channel_connect_option_t *option);

/**
 * Pair up local queue and remote queue of the input channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] local_qh: Local queue handle (local_qh) to be paired
 * @param[in] remote_qh: Remote queue handle (remote_qh) to be paired
 * @param[in] option: asynchronous configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * -URPC_ERR_ENOMEM: No memory
 * URPC_FAIL: Common error code
 */
int urpc_channel_queue_pair(
    uint32_t urpc_chid, uint64_t local_qh, uint64_t remote_qh, urpc_channel_connect_option_t *option);

/**
 * Unpair local queue and remote queue of the input channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] local_qh: Local queue handle (local_qh) to be unpaired
 * @param[in] remote_qh: Remote queue handle (remote_qh) to be unpaired
 * @param[in] option: asynchronous configuration
 * Return: under the synchronous configuration, return URPC_SUCCESS on success, error code on failure,
 * under the asynchronous configuration, return task id, task id >= 0, task generation successful, otherwise, failure
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_channel_queue_unpair(
    uint32_t urpc_chid, uint64_t local_qh, uint64_t remote_qh, urpc_channel_connect_option_t *option);

/**
 * Query information for queues bound to URPC channel
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[out] info: Detailed information for the channel after exchange (info)
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * URPC_FAIL: Common error code
 */
int urpc_channel_queue_query(uint32_t urpc_chid, urpc_channel_qinfos_t *info);

/* queue api */
/**
 * Create URPC queue and create specific transmission resources (jetty/sq/cq, etc.)
 * @param[in] trans_mode: Transmission mode for queue (base on jetty or other)
 * @param[in] cfg: Configuration information for queue (cfg)
 * Return Queue handle (urpc_qh) on success, URPC_INVALID_HANDLE on failure
 */
uint64_t urpc_queue_create(enum urpc_queue_trans_mode trans_mode, urpc_qcfg_create_t *cfg);

/**
 * Modify URPC queue status.
 * @param[in] urpc_qh: Queue handle (local urpc_qh)
 * @param[in] status: Target queue status
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * URPC_FAIL: Common error code
 * -URPC_ERR_JETTY_ERROR : queue not available, need destroy queue
 * -URPC_ERR_EINVAL: Invalid parameter
 * and other URMA status code
 */
int urpc_queue_modify(uint64_t urpc_qh, urpc_queue_status_t status);

/**
 * Destroy URPC queue
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EBUSY: Queue is busy
 * -URPC_ERR_EAGAIN: Need retry
 * -URPC_ERR_JETTY_ERROR : queue not available
 * and other URMA status code
 */
int urpc_queue_destroy(uint64_t urpc_qh);

/**
 * Query URPC queue statistics
 * @param[in] urpc_qh: Queue handle (urpc_qh), only support local queue, not support remote queue
 * @param[out] stats: Queue statistics in order of urpc_stats_type_t
 * @param[in] stats_len: Stats array size
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_queue_stats_get(uint64_t urpc_qh, uint64_t *stats, int stats_len);

/**
 * Query URPC queue error statistics
 * @param[in] urpc_qh: Queue handle (urpc_qh), only support local queue, not support remote queue
 * @param[out] stats: Queue error statistics in order of urpc_error_stats_type_t
 * @param[in] stats_len: Stats array size
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_queue_error_stats_get(uint64_t urpc_qh, uint64_t *stats, int stats_len);

/**
 * Query URPC error statistics, this interface returns error statistics when local queue is not selected in wrs
 * processing. If local queue is selected, get error statistics in urpc_queue_error_stats_get
 * @param[out] stats: Error statistics in order of urpc_error_stats_type_t
 * @param[in] stats_len: Stats array size
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_error_stats_get(uint64_t *stats, int stats_len);

/**
 * Query URPC queue statistics type name
 * @param[in] type: Queue statistics type
 * Return name of queue statistics type
 */
const char *urpc_queue_stats_name_get(urpc_stats_type_t type);

/**
 * Query URPC queue error statistics type name
 * @param[in] type: Queue error statistics type
 * Return name of queue error statistics type
 */
const char *urpc_queue_error_stats_name_get(urpc_error_stats_type_t type);

/**
 * Query URPC queue configuration
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * @param[out] cfg: Configuration information for the queue (cfg)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_queue_cfg_get(uint64_t urpc_qh, urpc_qcfg_get_t *cfg);

/**
 * Modify URPC queue configuration
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * @param[in] cfg: Configuration information for the queue (cfg)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_queue_cfg_set(uint64_t urpc_qh, urpc_qcfg_set_t *cfg);

/**
 * Query URPC queue interrupt fd
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * Return fd >= 0 on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_queue_interrupt_fd_get(uint64_t urpc_qh);

/**
 * Query status of queue
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * @param[out] status: Status of queue (status)
 * Return: URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_queue_status_query(uint64_t urpc_qh, urpc_queue_status_t *status);

/**
 * Post queue rx buffer.
 * @param[in] urpc_qh: Queue Handle (urpc_qh)
 * @param[in] args: SGE array for function arguments (args)
 * @param[in] args_sge_num: Number of SGEs for function arguments (args_sge_num)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_ENOMEM: No memory
 * -URPC_ERR_TRANSPORT_ERR: URMA return failed
 */
int urpc_queue_rx_post(uint64_t urpc_qh, urpc_sge_t *args, uint32_t args_sge_num);

/* function api */
/**
 * Register custom function with URPC
 * @param[in] info: Function information (info)
 * @param[out] func_id: Function ID assigned by URPC (func_id)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_ENOMEM: No memory
 * URPC_FAIL: Common error code
 */
int urpc_func_register(urpc_handler_info_t *info, uint64_t *func_id);

/**
 * Unregister custom function with URPC
 * @param[in] func_id: Function ID assigned by URPC (func_id)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_func_unregister(uint64_t func_id);

/**
 * Query local information and get custom function ID assigned by URPC
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] name: Function name
 * Return Function ID assigned by URPC on success, URPC_INVALID_FUNC_ID on failure
 */
uint64_t urpc_func_id_get(uint32_t urpc_chid, const char *name);

/* datapath api */
/**
 * Call URPC function
 * @param[in] chid: Channel ID for function call (chid)
 * @param[in] wr: Basic description of call task (wr)
 * @param[in] option: Extended parameters for call task (option)
 * Return Request handle (req_h) on success, URPC_U64_FAIL on failure (get error code from errno),
 * the specific errno is as follows
 * URPC_ERR_EINVAL: Invalid parameter
 * URPC_ERR_SESSION_CLOSE: Channel Invalid
 * URPC_ERR_LOCAL_QUEUE_ERR: Local queue error
 * URPC_ERR_REMOTE_QUEUE_ERR: Remote queue error
 * URPC_ERR_EAGAIN: Need Retry
 * URPC_ERR_CIPHER_ERR: Cipher error
 */
uint64_t urpc_func_call(uint32_t chid, urpc_call_wr_t *wr, urpc_call_option_t *option);

/**
 * URPC reference read
 * @param[in] urpc_qh: Queue handle (urpc_qh)
 * @param[in] req_ctx: Context information for function request (ctx)
 * @param[in] wr: Basic description of reference task (wr)
 * @param[in] option: Option parameters for reference task
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_ENOMEM: No memory
 * and other URMA status code
 */
int urpc_ref_read(uint64_t urpc_qh, void *req_ctx, urpc_ref_wr_t *wr, urpc_ref_option_t *option);

/**
 * Get URPC function poll event
 * @param[in] urpc_chid: Channel ID to get (urpc_chid, -1 if not specified)
 * @param[in] option: Filtering parameters (option)
 * @param[out] msg[]: Message information array
 * @param[in] max_msg_num: Maximum number of messages to retrieve
 * Return Number of messages retrieved (msg num) on success, error code on failure,
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_SESSION_CLOSE: Channel Invalid
 */
int urpc_func_poll(uint32_t urpc_chid, urpc_poll_option_t *option, urpc_poll_msg_t msg[], uint32_t max_msg_num);

/**
 * Wait notify to get URPC function poll event
 * @param[in] urpc_chid: Channel ID to get (urpc_chid, -1 if not specified)
 * @param[in] req_h: Request handle for wait
 * @param[in] option: Filtering parameters (option)
 * @param[out] msg[]: Message information array
 * @param[in] max_msg_num: Maximum number of messages to retrieve
 * Return Number of messages retrieved (msg num) on success, error code on failure,
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_TIMEOUT: Wait rsp timeout
 */
int urpc_func_poll_wait(uint32_t urpc_chid, uint64_t req_h, urpc_poll_option_t *option,
                        urpc_poll_msg_t msg[], uint32_t max_msg_num);

/**
 * URPC function poll callback function
 * @param[in] urpc_chid: Channel ID
 * @param[in] l_qh: Local queue handle
 * @param[in] msg[]: Message information array
 * @param[in] msg_num: number of messages to retrieve
 * Will be supported in future versions
*/
typedef void (*urpc_func_poll_cb_t)(uint32_t urpc_chid, uint64_t l_qh, urpc_poll_msg_t msg[], uint32_t msg_num);

/**
 * URPC function poll callback function register
 * @param[in] poll_cb: URPC function poll callback function
 * Return 0 on success, error code on failure
 * Will be supported in future versions
 */
int urpc_func_poll_cb_register(urpc_func_poll_cb_t poll_cb);

/**
 * URPC function poll callback function unregister
 * Return URPC_SUCCESS on success, error code on failure
 * URPC_FAIL: Common error code, the specific error code is as follows
 * Will be supported in future versions
 */
int urpc_func_poll_cb_unregister(void);

/**
 * Execute custom URPC function and call back registered custom function
 * @param[in] func_id: Function ID (func_id)
 * @param[in] args: SGE array for function arguments (args)
 * @param[in] args_sge_num: Number of SGEs for function arguments (args_sge_num)
 * @param[out] rsps: SGE array for function response (rsps)
 * @param[out] rsps_sge_num: Number of SGEs for function response (rsps_sge_num)
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_func_exec(uint64_t func_id, urpc_sge_t *args, uint32_t args_sge_num, urpc_sge_t **rsps,
    uint32_t *rsps_sge_num);

/**
 * Execute custom async URPC function and call back registered custom function
 * @param[in] func_id: Function ID (func_id)
 * @param[in] args: SGE array for function arguments (args)
 * @param[in] args_sge_num: Number of SGEs for function arguments (args_sge_num)
 * @param[in] req_ctx: request context
 * @param[in] qh: queue unique identifier
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_func_async_exec(uint64_t func_id, urpc_sge_t *args, uint32_t args_sge_num, void* req_ctx, uint64_t qh);

/**
 * Return URPC function call and release req_ctx (even for early_rsp mode, call this interface with wr=NULL)
 * @param[in] urpc_qh: Queue ID (urpc_qh)
 * @param[in] req_ctx: Context information for function request.
 * When return code is -URPC_ERR_EINVAL/-URPC_ERR_EAGAIN/-URMA_EAGAIN, req_ctx is not released.
 * When return code is URPC_SUCCESS/-URPC_ERR_ENOMEM/-URPC_ERR_REMOTE_QUEUE_ERR/-URPC_ERR_CIPHER_ERR
 * and other URMA status code, req_ctx is released.
 * @param[in] wr: Basic description of Return task (wr). Release req_ctx when wr is NULL.
 * @param[in] option: Option parameters for Return task
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_ENOMEM: No memory
 * -URPC_ERR_EAGAIN: Need Retry
 * -URPC_ERR_REMOTE_QUEUE_ERR: Get remote queue failed
 * -URPC_ERR_CIPHER_ERR: Cipher error
 * and other URMA status code
 */
int urpc_func_return(uint64_t urpc_qh, void *req_ctx, urpc_return_wr_t *wr, urpc_return_option_t *option);


/**
 * Get URPC header size
 * @param[in] type: URPC head type, URPC req/ack/rsp
 * @param[in] flag: Flag
 * Return Header size on success, URPC_U32_FAIL on failure
 */
uint32_t urpc_hdr_size_get(urpc_hdr_type_t hdr_type, uint16_t flag __attribute__((unused)));

/**
 * Register a memory segment on specified virtual address for local or remote access.
 * @param[in] va: The virtual address of the segment to be registered
 * @param[in] len: The length of the segment to be registered
 * Return mem seg handle(mem_h) on success, URPC_INVALID_HANDLE on failure
 */
uint64_t urpc_mem_seg_register(uint64_t va, uint64_t len);

/**
 * Unregister a memory segment on specified mem_h.
 * @param[in] mem_h: Mem seg handle
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * URPC_FAIL: Common error code
 */
int urpc_mem_seg_unregister(uint64_t mem_h);

/**
 * Get mem segment token_id and token_value on specified mem_h.
 * @param[in] mem_h: Mem seg handle(pa or va)
 * @param[out] token: Include token_id and token_value for mem sge
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * URPC_FAIL: Common error code
 */
int urpc_mem_seg_token_get(uint64_t mem_h, mem_seg_token_t *token);

/**
 * Set configuration for uRPC log.
 * @param[in] config: Configuration, if 'func' is set to NULL, the default log output function is used
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_log_config_set(urpc_log_config_t *config);

/**
 * Get configuration for uRPC log.
 * @param[out] config: Configuration, 'flag' & 'func'(when using default log output function) do not have valid values
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_log_config_get(urpc_log_config_t *config);

/**
 * Set the config of URPC SSL module.
 * @param[in] cfg: Config of URPC SSL module
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EPERM: URPC is not ready yet
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL: Common error code
 */
int urpc_ssl_config_set(urpc_ssl_config_t *cfg);

/**
 * Register URPC ctrl msg callback function.
 * @param[in] ctrl_cb: Callback function
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_ctrl_msg_cb_register(urpc_ctrl_cb_t ctrl_cb);

/**
 * Get urpc asynchronous events.
 * @param[out] msg[]: event information array
 * @param[in] num: Maximum number of events to retrieve
 * Return Number of events retrieved (event num) on success, error code on failure,
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 */
int urpc_async_event_get(urpc_async_event_t events[], int num);

/**
 * Get urpc event file descriptor
 * Return the event file descriptor
 */
int urpc_async_event_fd_get(void);

/**
 * mark task canceled
 * @param[in] urpc_chid: Channel ID (urpc_chid)
 * @param[in] task_id: task id
 * Return: return URPC_SUCCESS on success, error code on failure,
 * the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * -URPC_ERR_EPERM: URPC is not ready yet
 * URPC_FAIL: Common error code
 */
int urpc_channel_task_cancel(uint32_t urpc_chid, int task_id);

/**
 * Register URPC performance statistics func.
 * @param[in] perf_recorder: Callback function
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * -URPC_ERR_EINVAL: Invalid parameter
 * URPC_FAIL:  Common error code
 */
int urpc_perf_recorder_register(urpc_perf_recorder_t perf_recorder);

/**
 * Unregister URPC performance statistics func.
 * Return URPC_SUCCESS on success, error code on failure, the specific error code is as follows
 * URPC_FAIL:  Common error code
 */
int urpc_perf_recorder_unregister(void);

#ifdef __cplusplus
}
#endif

#endif
