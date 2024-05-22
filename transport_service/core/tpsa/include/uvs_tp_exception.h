/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: uvs tp exception
 * Author: Yu Hua
 * Create: 2023-08-29
 * Note:
 * History: 2023-08-29 uvs tp exception
 */

#ifndef UVS_TP_EXCEPTION_H
#define UVS_TP_EXCEPTION_H

#include "tpsa_worker.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint16_t next_port(uint16_t port, uint32_t tpn)
{
    uint16_t port_ = (uint16_t)ub_hash_add(port, tpn);
    return (port_ == port) ? port_ + 1 : port_;
}

void uvs_tp_exception_init(void);
void uvs_convert_sus2err_period_to_clock_cycle(uint32_t sus2err_period);
void uvs_tp_exception_uninit(void);

/* handle netlink */
int uvs_handle_nl_tp_error_req(uvs_ctx_t *ctx, tpsa_nl_msg_t *msg);
int uvs_handle_nl_tp_suspend_req(tpsa_worker_t *worker, tpsa_nl_msg_t *msg);

/* handle socket */
int uvs_handle_sock_restore_tp_error_req(tpsa_table_t *table_ctx, tpsa_sock_ctx_t *sock_ctx,
                                         tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_sock_msg_t *msg);
int uvs_handle_sock_restore_tp_error_resp(tpsa_table_t *table_ctx, tpsa_sock_ctx_t *sock_ctx,
                                          tpsa_ioctl_ctx_t *ioctl_ctx, tpsa_sock_msg_t *msg);
int uvs_handle_sock_restore_tp_error_ack(tpsa_table_t *table_ctx, tpsa_ioctl_ctx_t *ioctl_ctx,
                                         tpsa_sock_msg_t *msg);
#ifdef __cplusplus
}
#endif

#endif
