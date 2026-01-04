/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Public header file of UMQ transport layer function
 * Create: 2025-7-16
 * Note:
 * History: 2025-7-16
 */

#ifndef UMQ_TP_API_H
#define UMQ_TP_API_H

#include "umq_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umq_ops {
    umq_trans_mode_t mode;

    /**
    * Thread safety function
    * Init umq
    * @param[in] cfg: init config of umq
    * Return uint8_t *ctx on success , NULL on failure (get error code from errno)
    */
    uint8_t* (*umq_tp_init)(umq_init_cfg_t *cfg);

    /**
    * Thread safety function
    * Uninit umq
    */
    void (*umq_tp_uninit)(uint8_t *ctx);

    /**
    * Thread safety function
    * Create umq
    * @param[in] umqh: umq handle
    * @param[in] ctx: UMQ context
    * @param[in] option: Configuration information for umq
    * Return umq handle (umqh_tp) on success, 0 on failure (get error code from errno)
    */
    uint64_t (*umq_tp_create)(uint64_t umqh, uint8_t *ctx, umq_create_option_t *option);

    /**
    * Thread safety function
    * Destroy umq
    * @param[in] umqh_tp: umq handle
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_destroy)(uint64_t umqh_tp);

    /**
    * Thread safe function
    * @param[in] umqh_tp: umq handle
    * Get info for umq bind
    * @param[out] bind_info: buf of bind info
    * @param[in] bind_info_size: buf size of bind info
    * Return buf size of bind info get
    */
    uint32_t (*umq_tp_bind_info_get)(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size);

    /**
    * Thread safety function
    * Bind umq
    * @param[in] umqh_tp: umq handle
    * @param[in] bind_info: buf of bind info
    * @param[in] bind_info_size: buf size of bind info
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_bind)(uint64_t umqh_tp, uint8_t *bind_info, uint32_t bind_info_size);

    /**
    * Thread safety function
    * Unbind umq
    * @param[in] umqh_tp: umq handle
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_unbind)(uint64_t umqh_tp);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Set umq state
    * @param[in] umqh_tp: umq handle
    * @param[in] state: umq state want to set(Only Support Set ERR STATE)
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_state_set)(uint64_t umqh_tp, umq_state_t state);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Query umq state
    * @param[in] umqh_tp: umq handle
    * Return umq state
    */
    umq_state_t (*umq_tp_state_get)(uint64_t umqh_tp);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Alloc umq buf, qbuf list with qbuf_next.
    * @param[in] request_size: size of qbuf request to alloc
    * @param[in] request_qbuf_num: num of qbuf request to alloc
    * @param[in] umqh_tp: Queue handle, use for mode ubmm
    * @param[in] option: alloc option param
    * mode ubmm: only alloc buf from umqh_tp pool
    * mode ub/ib: alloc buf from thread local pool first, then alloc buf from global pool
    * Return umq_buf_t *qbuf on success, NULL on failure (get error code from errno)
    */
    umq_buf_t *(*umq_tp_buf_alloc)(uint32_t request_size, uint32_t request_qbuf_num, uint64_t umqh_tp,
                                   umq_alloc_option_t *option);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Free umq buf, qbuf list with qbuf_next.
    * @param[in] qbuf: buf for enqueue/dequeue
    * @param[in] umqh_tp: Queue handle which qbuf alloc from
    */
    void (*umq_tp_buf_free)(umq_buf_t *qbuf, uint64_t umqh_tp);

    /**
    * Set log config for umq.
    * @param[in] config: if 'func' is set to NULL, the default log output function is used
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_log_config_set)(umq_log_config_t *config);

    /**
    * Reset log config for umq.
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_log_config_reset)(void);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Reset header room size for qbuf
    * @param[in] qbuf: list of qbuf
    * @param[in] headroom_size: head room size to reset
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_buf_headroom_reset)(umq_buf_t *qbuf, uint16_t headroom_size);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Enqueue umq buf
    * @param[in] umqh_tp: umq handle
    * @param[in] qbuf: qbuf need to enqueue. no more than UMQ_BATCH_SIZE work requeses once
    * @param[out] bad_qbuf: qbuf list faild to enqueue. user should free these buf
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_enqueue)(uint64_t umqh_tp, umq_buf_t *qbuf, umq_buf_t **bad_qbuf);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Dequeue umq buf
    * @param[in] umqh_tp: umq handle
    * Return dequeue qbuf on success, NULL on failure (get error code from errno)
    */
    umq_buf_t* (*umq_tp_dequeue)(uint64_t umqh_tp);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Notify umq to send buf
    * @param[in] umqh_tp: umq handle array
    */
    void (*umq_tp_notify)(uint64_t umqh_tp);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Arm interrupt of umq
    * @param[in] umqh_tp: umq handle
    * @param[in] solicated: solicated flag
    * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or UMQ_FAIL will be returned
    * Return 0 on success, error code on failure
    */
    int (*umq_tp_rearm_interrupt)(uint64_t umqh_tp, bool solicated, umq_interrupt_option_t *option);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Sleep and wait for interrupt
    * @param[in] wait_umqh_tp: umq handle which is waitting for interrupt
    * @param[in] time_out: max time to wait (milliseconds),
    *            timeout = 0: return immediately event if no events are ready,
    *            timeout = -1: an infinite timeout
    * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or 0 will be returned
    * Return num of umq which has been wakeup on success, error code on failure
    */
    int (*umq_tp_wait_interrupt)(uint64_t wait_umqh_tp, int time_out, umq_interrupt_option_t *option);

    /**
    * User should ensure thread safety if io_lock_free is true
    * Confirm that a interrupt generated event has been processed
    * @param[in] umqh_tp: umq handle
    * @param[in] nevents: event count to be acknowledged
    * @param[in] option: option param. user should specify UMQ_IO_TX or UMQ_IO_RX, or nothing will be done
    */
    void (*umq_tp_ack_interrupt)(uint64_t umqh_tp, uint32_t nevents, umq_interrupt_option_t *option);

    /**
     * Thread safety function
     * get the fd for listening to asynchronous events
     * @param[in] dev_info: device info
     * Return fd >= 0 on success, < 0 on failure
     */
    int (*umq_tp_async_event_fd_get)(umq_trans_info_t *trans_info);

    /**
     *  Get asyn event.
     * @param[in] dev_info: device info;
     * @param[out] event: the address to put event
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_async_event_get)(umq_trans_info_t *trans_info, umq_async_event_t *event);

    /**
     *  Ack asyn event.
     * @param[in] event: the address to ack event;
     * Return: void
     */
    void (*umq_tp_aync_event_ack)(umq_async_event_t *event);

    /**
     * add dev
     * @param[in] trans_info: device info
     * @param[in] cfg: init config of umq
     * return: 0 on success, other value on error
     */
    int (*umq_tp_dev_add)(umq_trans_info_t *trans_info, umq_init_cfg_t *cfg);

    /**
     * Get primary and port eid from topo info.
     * @param[in] route: parameter that contains src_v_eid and dst_v_eid, refers to umq_route_t;
     * @param[out] route_list: a list buffer, containing all routes returned;
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_get_topo)(const umq_route_t *route, umq_route_list_t *route_list);

    /**
     * Thread safety function
     * User defined control of the context.
     * @param[in] umqh_tp: umq tp handle
     * @param[in] in: user ctl cmd
     * @param[out] out: result of excution
     * Return 0 on success, error code on failure
     */
    int (*umq_tp_user_ctl)(uint64_t umqh_tp, umq_user_ctl_in_t *in, umq_user_ctl_out_t *out);

    /**
     * Get mempool config.
     * @param[in] umqh_tp: umq tp handle
     * @param[in] mempool_id: mempool id, the ID of the memory pool from which the buffer was obtained
     * @param[out] mempool_state: mempool state
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_mempool_state_get)(uint64_t umqh_tp, uint32_t mempool_id, umq_mempool_state_t *mempool_state);

    /**
     * Refresh mempool state.
     * @param[in] umqh_tp: umq tp handle
     * @param[in] mempool_id: mempool id, the ID of the memory pool from which the buffer was obtained
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_mempool_state_refresh)(uint64_t umqh_tp, uint32_t mempool_id);

    /**
    * Get device information.
    * @param[in] dev_name: device name
    * @param[in] umq_trans_mode: umq trans mdoe
    * @param[out] umq_dev_info: device information
    * Return: 0 on success, other value on error
    */
    int (*umq_tp_dev_info_get)(char *dev_name,  umq_trans_mode_t umq_trans_mode, umq_dev_info_t *umq_dev_info);
    /**
     * Get umq cfg.
     * @param[in] umqh_tp: umq tp handle
     * @param[out] cfg: umq cfg
     * Return: 0 on success, other value on error
     */
    int (*umq_tp_cfg_get)(uint64_t umqh_tp, umq_cfg_get_t *cfg);
} umq_ops_t;

typedef umq_ops_t* (*umq_ops_get_t)(void);

#ifdef __cplusplus
}
#endif

#endif
