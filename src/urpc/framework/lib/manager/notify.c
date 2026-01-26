/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define notify msg api
 * Create: 2024-5-8
 * Note:
 * History: 2024-5-8
 */

#include <pthread.h>

#include "urpc_dbuf_stat.h"
#include "urpc_lib_log.h"
#include "queue.h"
#include "urpc_hash.h"
#include "notify.h"

#define MAX_QUEUE_MSG_NUM (2000)

static struct {
    struct urpc_hmap msg_table;
    pthread_rwlock_t msg_lock;
    bool msg_table_is_init;
} g_urpc_queue_msg_ctx = {0};

void fill_req_err_msg(urpc_poll_msg_t *msg, queue_notify_msg_t *q_msg)
{
    msg->event = POLL_EVENT_REQ_ERR;
    msg->req_err.args = q_msg->args;
    msg->req_err.args_sge_num = q_msg->args_sge_num;
    msg->req_err.req_h = q_msg->req_h;
    msg->req_err.user_ctx = q_msg->user_ctx;
    msg->req_err.urpc_chid = q_msg->urpc_chid;
    msg->req_err.err_code = q_msg->err_code;
}

void fill_event_err_msg(urpc_poll_msg_t *msg, queue_notify_msg_t *q_msg)
{
    msg->event = POLL_EVENT_ERR;
    msg->event_err.args = q_msg->args;
    msg->event_err.args_sge_num = q_msg->args_sge_num;
    msg->event_err.err_code = (int32_t)q_msg->err_code;
    msg->event_err.err_event = q_msg->err_event;
    msg->event_err.urpc_qh = q_msg->urpc_qh;
    msg->event_err.urpc_chid = q_msg->urpc_chid;
}

int poll_notify_msg(uint64_t qh, urpc_poll_msg_t *msgs, int num)
{
    queue_notify_msg_info_t *msg = NULL;
    queue_notify_msg_t *cur = NULL;
    queue_notify_msg_t *next = NULL;
    int queue_msg_cnt = 0;
    bool find = false;

    queue_local_t *local_q = (queue_local_t *)(uintptr_t)qh;
    if (local_q->notify == 0) {
        return 0;
    }

    uint32_t hash = urpc_hash_uint64(qh);
    (void)pthread_rwlock_rdlock(&g_urpc_queue_msg_ctx.msg_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(msg, node, hash, &g_urpc_queue_msg_ctx.msg_table) {
        if (msg->qh == qh) {
            find = true;
            break;
        }
    }

    if (find == false) {
        (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
        return queue_msg_cnt;
    }

    (void)pthread_spin_lock(&msg->list_lock);
    if (urpc_list_is_empty(&msg->list)) {
        local_q->notify = 0;
        (void)pthread_spin_unlock(&msg->list_lock);
        (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
        return queue_msg_cnt;
    }

    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &msg->list) {
        if (queue_msg_cnt == num) {
            (void)pthread_spin_unlock(&msg->list_lock);
            (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
            return queue_msg_cnt;
        }

        urpc_poll_msg_t *cur_msg = msgs + queue_msg_cnt;
        switch (cur->event) {
            case POLL_EVENT_REQ_ERR:
                fill_req_err_msg(cur_msg, cur);
                break;
            case POLL_EVENT_ERR:
                fill_event_err_msg(cur_msg, cur);
                break;
            default:
                URPC_LIB_LOG_ERR("poll event err, event %d\n", cur->event);
                break;
        }
        urpc_list_remove(&cur->node);
        urpc_dbuf_free(cur);
        queue_msg_cnt++;
    }
    local_q->notify = 0;
    (void)pthread_spin_unlock(&msg->list_lock);
    (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
    return queue_msg_cnt;
}

void generate_queue_notify_msg(queue_notify_data_t *rp_data, uint32_t err_code)
{
    queue_notify_msg_info_t *info = NULL;
    bool find = false;

    uint32_t hash = urpc_hash_uint64(rp_data->send_qh);
    (void)pthread_rwlock_rdlock(&g_urpc_queue_msg_ctx.msg_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(info, node, hash, &g_urpc_queue_msg_ctx.msg_table) {
        if (info->qh == rp_data->send_qh) {
            find = true;
            break;
        }
    }

    if (!find) {
        URPC_LIB_LIMIT_LOG_ERR("qh deleted: cid = %u, sid = %u rsn = %u\n",
            rp_data->client_chid, rp_data->server_chid, rp_data->req_id);
        (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
        return;
    }

    queue_notify_msg_t *queue_msg =
        (queue_notify_msg_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_NOTIFY, 1, sizeof(queue_notify_msg_t));
    if (queue_msg == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("queue msg result alloc failed\n");
        (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
        return;
    }

    queue_t *l_q = (queue_t *)(uintptr_t)rp_data->send_qh;
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)l_q;

    queue_msg->args = rp_data->args;
    queue_msg->args_sge_num = rp_data->args_num;
    queue_msg->event = rp_data->event;
    queue_msg->urpc_chid = rp_data->client_chid;
    queue_msg->req_h = rp_data->req_id;
    queue_msg->user_ctx = rp_data->user_ctx;
    queue_msg->err_code = err_code;
    queue_msg->err_event = rp_data->err_event;
    queue_msg->urpc_qh = rp_data->send_qh;
    (void)pthread_spin_lock(&info->list_lock);
    urpc_list_push_back(&info->list, &queue_msg->node);
    local_q->notify = 1;
    (void)pthread_spin_unlock(&info->list_lock);
    (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
}

int add_queue_notify_msg_table(uint64_t qh)
{
    queue_notify_msg_info_t *queue_msg = (queue_notify_msg_info_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_NOTIFY,
        1, sizeof(queue_notify_msg_info_t));
    if (queue_msg == NULL) {
        URPC_LIB_LOG_ERR("alloc queue msg info failed\n");
        return URPC_FAIL;
    }

    queue_msg->qh = (uint64_t)(uintptr_t)qh;
    urpc_list_init(&queue_msg->list);
    (void)pthread_spin_init(&queue_msg->list_lock, PTHREAD_PROCESS_PRIVATE);

    (void)pthread_rwlock_wrlock(&g_urpc_queue_msg_ctx.msg_lock);
    urpc_hmap_insert(&g_urpc_queue_msg_ctx.msg_table, &queue_msg->node, urpc_hash_uint64(queue_msg->qh));
    (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
    URPC_LIB_LOG_INFO("add queue to queue msg table success\n");
    return URPC_SUCCESS;
}

static void release_queue_notify_msg_list(uint64_t qh, queue_notify_msg_info_t *info)
{
    queue_notify_msg_t *cur = NULL;
    queue_notify_msg_t *next = NULL;
    queue_local_t *local_q = (queue_local_t *)(uintptr_t)qh;
    (void)pthread_spin_lock(&info->list_lock);
    URPC_LIST_FOR_EACH_SAFE(cur, next, node, &info->list) {
        URPC_LIB_LOG_ERR("queue msg not poll by usr, cid %u, rsn %u, args_num %u\n",
            cur->urpc_chid, cur->req_h, cur->args_sge_num);
        urpc_list_remove(&cur->node);
        urpc_dbuf_free(cur);
    }
    local_q->notify = 0;
    (void)pthread_spin_unlock(&info->list_lock);
    (void)pthread_spin_destroy(&info->list_lock);
    urpc_dbuf_free(info);
}

void rm_queue_notify_msg_table(uint64_t qh)
{
    queue_notify_msg_info_t *info = NULL;
    bool find = false;

    uint32_t hash = urpc_hash_uint64(qh);
    (void)pthread_rwlock_wrlock(&g_urpc_queue_msg_ctx.msg_lock);
    URPC_HMAP_FOR_EACH_WITH_HASH(info, node, hash, &g_urpc_queue_msg_ctx.msg_table) {
        if (info->qh == qh) {
            find = true;
            break;
        }
    }

    if (find == false) {
        URPC_LIB_LOG_WARN("queue not find in queue msg table\n");
        (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
        return;
    }

    urpc_hmap_remove(&g_urpc_queue_msg_ctx.msg_table, &info->node);
    (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
    release_queue_notify_msg_list(qh, info);
    URPC_LIB_LOG_INFO("rm queue msg table success\n");
}

int urpc_notify_table_init(void)
{
    if (g_urpc_queue_msg_ctx.msg_table_is_init) {
        URPC_LIB_LOG_INFO("msg table has been initialized\n");
        return URPC_SUCCESS;
    }
    int ret = urpc_hmap_init(&g_urpc_queue_msg_ctx.msg_table, MAX_QUEUE_MSG_NUM);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("msg table init failed, ret:%d\n", ret);
        return ret;
    }
    (void)pthread_rwlock_init(&g_urpc_queue_msg_ctx.msg_lock, NULL);

    g_urpc_queue_msg_ctx.msg_table_is_init = true;
    return URPC_SUCCESS;
}

void urpc_notify_table_uninit(void)
{
    if (!g_urpc_queue_msg_ctx.msg_table_is_init) {
        URPC_LIB_LOG_INFO("msg table not been initialized\n");
        return;
    }

    queue_notify_msg_info_t *info_cur = NULL;
    queue_notify_msg_info_t *info_next = NULL;

    (void)pthread_rwlock_wrlock(&g_urpc_queue_msg_ctx.msg_lock);
    URPC_HMAP_FOR_EACH_SAFE(info_cur, info_next, node, &g_urpc_queue_msg_ctx.msg_table) {
        urpc_hmap_remove(&g_urpc_queue_msg_ctx.msg_table, &info_cur->node);
        URPC_LIB_LOG_ERR("queue in queue msg table not remove\n");
        release_queue_notify_msg_list((uint64_t)(uintptr_t)info_cur->qh, info_cur);
    }
    (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
    (void)pthread_rwlock_destroy(&g_urpc_queue_msg_ctx.msg_lock);
    urpc_hmap_uninit(&g_urpc_queue_msg_ctx.msg_table);

    g_urpc_queue_msg_ctx.msg_table_is_init = false;
}

// lock free: The function call context must be within the scope of msg_lock.
bool queue_in_notify_msg_table(uint64_t qh)
{
    queue_notify_msg_info_t *info = NULL;
    uint32_t hash = urpc_hash_uint64(qh);
    URPC_HMAP_FOR_EACH_WITH_HASH(info, node, hash, &g_urpc_queue_msg_ctx.msg_table) {
        if (info->qh == qh) {
            return true;
        }
    }
    return false;
}

void queue_notify_msg_table_rdlock(void)
{
    (void)pthread_rwlock_rdlock(&g_urpc_queue_msg_ctx.msg_lock);
}

void queue_notify_msg_table_unlock(void)
{
    (void)pthread_rwlock_unlock(&g_urpc_queue_msg_ctx.msg_lock);
}