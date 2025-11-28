/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ function
 * Create: 2025-7-7
 * Note:
 * History: 2025-7-7
 */

#ifndef UMQ_API_H
#define UMQ_API_H

#include "umq_types.h"
#include "umq_errno.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Singleton Execution
 * Init umq
 * @param[in] cfg: init config of umq
 * Return 0 on success, error code on failure
 */
int umq_init(umq_init_cfg_t *cfg);

/**
 * Singleton Execution
 * Uninit umq
 */
void umq_uninit(void);

/**
 * Thread safety function
 * Create umq
 * @param[in] option: Configuration information for umq
 * Return umq handle (umqh) on success, 0 on failure (get error code from errno)
 */
uint64_t umq_create(umq_create_option_t *option);

/**
 * Thread safety function
 * Destroy umq
 * @param[in] umqh: umq handle
 * Return 0 on success, error code on failure
 */
int umq_destroy(uint64_t umqh);

/**
 * Thread safe function
 * Get info for umq bind
 * @param[in] umqh: umq handle
 * @param[out] bind_info: buf of bind info
 * @param[in] bind_info_size: buf size of bind info
 * Return buf size of bind info get
 */
uint32_t umq_bind_info_get(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size);

/**
 * Thread safety function
 * Bind umq
 * @param[in] umqh: umq handle
 * @param[in] bind_info: buf of bind info
 * @param[in] bind_info_size: buf size of bind info
 * Return 0 on success, error code on failure
 * In condition of base api, umq is responsible for post rx when bind
 * In condition of pro api, user should post rx after umq bind success
 */
int umq_bind(uint64_t umqh, uint8_t *bind_info, uint32_t bind_info_size);

/**
 * Thread safety function
 * Unbind umq
 * @param[in] umqh: umq handle
 * Return 0 on success, error code on failure
 * In condition of base api, umq is responsible for flush rx and tx
 * In condition of pro api, user responsible flush rx and tx after unbind
 */
int umq_unbind(uint64_t umqh);

/**
 * User should ensure thread safety if io_lock_free is true
 * Query umq state
 * @param[in] umqh: umq handle
 * Return umq state
 */
umq_state_t umq_state_get(uint64_t umqh);

/**
 * User should ensure thread safety if io_lock_free is true
 * Alloc umq buf, qbuf list with qbuf_next.
 * @param[in] request_size: size of qbuf request to alloc
 * @param[in] request_qbuf_num: num of qbuf request to alloc
 * @param[in] umqh: umq handle, use for mode ipc/ubmm
 * @param[in] option: alloc option param
 * (1) mode ipc/ubmm, each queue has a small shared memory pool. When using shared memory via ipc or ubmm,
 * you need to pass the umqh parameter to specify which queue's memory pool the request is coming from.
 * (2) In other scenarios, memory will be allocated from the global memory pool, which supports hierarchical
 * expansion with sizes including 8KB, 256KB, and 8MB.
 * Return umq_buf_t *qbuf on success, NULL on failure (get error code from errno)
 */
umq_buf_t *umq_buf_alloc(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh, umq_alloc_option_t *option);

/**
 * User should ensure thread safety if io_lock_free is true
 * Free umq buf, qbuf list with qbuf_next.
 * @param[in] qbuf: buf for enqueue/dequeue
 */
void umq_buf_free(umq_buf_t *qbuf);

/**
 * User should ensure thread safety if io_lock_free is true
 * Break and free the qbufs of first batch
 * @param[in] qbuf: list of qbuf
 * Return first qbuf addr of next batch, return NULL if not exist
 */
umq_buf_t *umq_buf_break_and_free(umq_buf_t *qbuf);

/**
 * User should ensure thread safety if io_lock_free is true
 * Reset header room size for qbuf
 * @param[in] qbuf: list of qbuf
 * @param[in] headroom_size: head room size to reset
 * Return 0 on success, error code on failure
 */
int umq_buf_headroom_reset(umq_buf_t *qbuf, uint16_t headroom_size);

/**
 * User should ensure thread safety if io_lock_free is true
 * Reset total size and data size for qbuf to initial capacity
 * @param[in] qbuf: list of qbuf
 * Return 0 on success, error code on failure
 */
int umq_buf_reset(umq_buf_t *qbuf);

/**
 * User should ensure thread safety if io_lock_free is true
 * Get corresponding umq_buf_t from buf_data pointer
 * @param[in] data: pointer of buf_data
 * Return umq_buf_t *qbuf on success, NULL on failure (get error code from errno)
 */
umq_buf_t *umq_data_to_head(void *data);

/**
 * User should ensure thread safety if io_lock_free is true
 * Enqueue umq buf
 * @param[in] umqh: umq handle
 * @param[in] qbuf: qbuf need to enqueue. no more than UMQ_BATCH_SIZE work requeses once
 * @param[out] bad_qbuf: qbuf list faild to enqueue. user should free these buf
 * Return 0 on success, error code on failure
 */
int umq_enqueue(uint64_t umqh, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);

/**
 * User should ensure thread safety if io_lock_free is true
 * Dequeue umq buf
 * @param[in] umqh: umq handle
 * Return dequeue qbuf on success, NULL on failure (get error code from errno)
 */
umq_buf_t *umq_dequeue(uint64_t umqh);

/**
 * User should ensure thread safety if io_lock_free is true
 * Notify umq to send buf
 * @param[in] umqh: umq handle
 */
void umq_notify(uint64_t umqh);

/**
 * User should ensure thread safety if io_lock_free is true
 * Arm interrupt of umq
 * @param[in] umqh: umq handle
 * @param[in] solicated: solicated flag
 * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or UMQ_FAIL will be returned
 * Return 0 on success, error code on failure
 */
int umq_rearm_interrupt(uint64_t umqh, bool solicated, umq_interrupt_option_t *option);

/**
 * User should ensure thread safety if io_lock_free is true
 * Sleep and wait for interrupt
 * @param[in] wait_umqh: umq handle which is waitting for interrupt
 * @param[in] time_out: max time to wait (milliseconds),
 *            timeout = 0: return immediately event if no events are ready,
 *            timeout = -1: an infinite timeout
 * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or 0 will be returned
 * Return num of umq which has been wakeup on success, error code on failure
 */
int32_t umq_wait_interrupt(uint64_t wait_umqh, int time_out, umq_interrupt_option_t *option);

/**
 * User should ensure thread safety if io_lock_free is true
 * Confirm that a interrupt generated event has been processed
 * @param[in] umqh: umq handle
 * @param[in] nevents: event count to be acknowledged
 * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or nothing will be done
 */
void umq_ack_interrupt(uint64_t umqh, uint32_t nevents, umq_interrupt_option_t *option);

/**
 * User should ensure thread safety if io_lock_free is true
 * Execute dfx command
 * @param[in] cmd: dfx command, user should set perf or stats
 * @param[out] result_ctl: command result
 */
void umq_dfx_cmd_process(umq_dfx_cmd_t *cmd, umq_dfx_result_t *result_ctl);

/**
 * Split the head linked list at the node
 * The new list starts from node and continues to the end of the original list
 * @param[in] head: head pointer of the original buf list.
 * @param[in] node: a pointer to the node at the split position.
 * Return 0 on success, error code on failure
 */
int umq_buf_split(umq_buf_t *head, umq_buf_t *node);

/** Thread safety function
 * get the fd for listening to asynchronous events
 * @param[in] trans_info: transport info, consistent with the trans_info carried in the umq_init interface parameters
 * Return fd >= 0 on success, < 0 on failure
 */
int umq_async_event_fd_get(umq_trans_info_t *trans_info);

/**
 *  Get asyn event.
 * @param[in] trans_info: transport info, consistent with the trans_info carried in the umq_init interface parameters
 * @param[out] event: the address to put event
 * Return: 0 on success, other value on error
 */
int umq_get_async_event(umq_trans_info_t *trans_info, umq_async_event_t *event);

/**
 *  Ack asyn event.
 * @param[in] event: the address to ack event;
 * Return: void
 */
void umq_ack_async_event(umq_async_event_t *event);
/**
 * Set configuration for UMQ log.
 * @param[in] config: Configuration, if 'func' is set to NULL, the default log output function is used
 * Return UMQ_SUCCESS on success, error code on failure, the specific error code is as follows
 * -UMQ_ERR_EINVAL: Invalid parameter
 */
int umq_log_config_set(umq_log_config_t *config);

/**
 * Get configuration for UMQ log.
 * @param[in] config: Configuration, 'flag' & 'func'(when using default log output function) do not have valid values
 * Return UMQ_SUCCESS on success, error code on failure, the specific error code is as follows
 * -UMQ_ERR_EINVAL: Invalid parameter
 */
int umq_log_config_get(umq_log_config_t *config);

#ifdef __cplusplus
}
#endif

#endif
