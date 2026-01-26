/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define cancel api
 * Create: 2024-5-8
 * Note:
 * History: 2024-5-8
 */
 
#include <pthread.h>

#include "urpc_lib_log.h"
#include "dp.h"
#include "channel.h"
#include "notify.h"
#include "cancel.h"

static void client_report_cancel_msg(req_entry_t *req_entry, void *user_ctx)
{
    queue_notify_data_t rp_data;
    rp_data.client_chid = req_entry->local_chid;
    rp_data.server_chid = req_entry->remote_chid;
    rp_data.req_id = req_entry->req_id;
    rp_data.args = req_entry->args;
    rp_data.args_num = req_entry->args_num;
    rp_data.user_ctx = user_ctx;
    rp_data.send_qh = req_entry->send_qh;
    rp_data.event = POLL_EVENT_REQ_ERR;
    generate_queue_notify_msg(&rp_data, URPC_ERR_TIMEOUT);
}

// do nothing, just set req_entry_t to invalid
void urpc_cancel_timeout_process(void *args)
{
    req_entry_t *entry = (req_entry_t *)args;
    URPC_LIB_LOG_WARN("start timeout process, cid = %d, sid = %d, rsn = %d, args_num = %d\n",
        entry->local_chid, entry->remote_chid, entry->req_id, entry->args_num);
    (void)pthread_mutex_lock(&entry->lock);
    if (is_req_entry_timeout(entry)) {
        tx_ctx_t *tx_ctx = (tx_ctx_t *)entry->ctx;
        if (tx_ctx != NULL) {
            if ((tx_ctx->call_mode & FUNC_CALL_MODE_WAIT_RSP) != 0) {
                urpc_process_rsp_callback(entry, URPC_ERR_TIMEOUT);
                (void)pthread_mutex_unlock(&entry->lock);
                return;
            }
            /* SEND_PUSH mode should report req_err msg when timeout is triggered */
            client_report_cancel_msg(entry, (void *)tx_ctx->user_ctx);
            tx_ctx->sge_handover_completed = URPC_TRUE;
            tx_ctx_try_put(tx_ctx);
        }
        req_entry_put(entry);
    }
    (void)pthread_mutex_unlock(&entry->lock);
}