/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * File Name     : dlock_client_dp.cpp
 * Description   : dlock client data plane process
 * History       : create file & add functions
 * 1.Date        : 2023-12-11
 * Author        : huying
 * Modification  : Created file
 */

#include "dlock_types.h"
#include "dlock_client.h"
#include "dlock_common.h"
#include "dlock_log.h"
#include "utils.h"

namespace dlock {
int (dlock_client::*g_async_check[LOCK_OPS_MAX])(client_entry_c&, void*) = {
    [LOCK_EXCLUSIVE] = &dlock_client::trylock_result_check,
    [LOCK_SHARED] = &dlock_client::trylock_result_check,
    [UNLOCK] = &dlock_client::unlock_or_extend_result_check,
    [EXTEND_LOCK_EXCLUSIVE] = &dlock_client::unlock_or_extend_result_check,
    [EXTEND_LOCK_SHARED] = &dlock_client::unlock_or_extend_result_check,
};

int dlock_client::trans_trylock_op_to_extend(client_entry_c *p_client, lock_entry_c *p_lock_entry,
    struct lock_cmd_msg *p_cmd_ret, void *result) const
{
    p_lock_entry->m_lock_state = (p_cmd_ret->op_ret == static_cast<int>(DLOCK_FAIL)) ?
        LOCK_INITIALIZED : p_lock_entry->m_lock_state;
    p_lock_entry->m_ref_count = (p_cmd_ret->op_ret == static_cast<int>(DLOCK_FAIL)) ?
        0 : p_lock_entry->m_ref_count;
    if (p_cmd_ret->op_ret == static_cast<int>(DLOCK_NOT_READY)) {
        p_lock_entry->m_ref_count--;
    }
    if ((p_lock_entry->m_lock_type != DLOCK_FAIR) &&
        (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS))) {
        p_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_RET]++;
        DLOCK_LOG_DEBUG("trylock failed with ret %d", p_cmd_ret->op_ret);
        return p_cmd_ret->op_ret;
    }
    int ret = p_lock_entry->update_state_with_cmd_msg(p_cmd_ret, result);
    return (ret == static_cast<int>(DLOCK_SUCCESS)) ? static_cast<int>(DLOCK_ALREADY_LOCKED) : ret;
}

int dlock_client::trylock(int client_id, const struct lock_request *req, void *result)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    if (p_client->m_async_flag) {
        p_client->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("trylock: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    int lock_id = req->lock_id;
    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock);
    lock_map_t::iterator lock_iter = p_client->m_lock_map.find(lock_id);
    if (lock_iter == p_client->m_lock_map.end()) {
        shared_locker.unlock();
        p_client->m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
        DLOCK_LOG_DEBUG("lock %d has not been got", lock_id);
        return static_cast<int>(DLOCK_LOCK_NOT_GET);
    }
    shared_locker.unlock();
    lock_entry_c *p_lock_entry = lock_iter->second;
    if ((p_lock_entry->m_lock_type == DLOCK_ATOMIC) && (req->lock_op != static_cast<int>(LOCK_EXCLUSIVE))) {
        p_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
        DLOCK_LOG_DEBUG("invalid lock op %d for trylock, lock_id: %d", req->lock_op, lock_id);
        return static_cast<int>(DLOCK_EINVAL);
    }
    if (req->expire_time == 0u) {
        return p_lock_entry->update_state_with_cmd_msg(nullptr, result);
    }

    struct lock_cmd_msg cmd_msg = {0};
    uint16_t message_id = p_client->m_p_jetty_mgr->generate_message_id();
    int ret = p_lock_entry->fill_cmd_msg(client_id, message_id, req, cmd_msg);
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        if (ret == static_cast<int>(DLOCK_ALREADY_LOCKED)) {
            static_cast<void>(p_lock_entry->update_state_with_cmd_msg(nullptr, result));
            return ret;
        }
        return (ret == static_cast<int>(DLOCK_DONE)) ? static_cast<int>(DLOCK_SUCCESS) : ret;
    }
    bool reentrant = ((cmd_msg.op_code == static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND)) ||
        (cmd_msg.op_code == static_cast<uint8_t>(SHARED_LOCK_EXTEND)));

    struct lock_cmd_msg *p_cmd_ret = nullptr;
    ret = static_cast<int>(xchg_cmd_msg(*p_client, cmd_msg, &p_cmd_ret));
    if ((ret != static_cast<int>(DLOCK_SUCCESS)) || (p_cmd_ret == nullptr)) {
        DLOCK_LOG_DEBUG("xchg_cmd_msg error");
        /* m_ref_count has been added 1 in fill_cmd_msg for lock_extend */
        p_lock_entry->m_ref_count -= reentrant ? 1 : 0;
        return ret;
    }

    /* trylock for lock with local state *_LOCKED will be transformed to an extend op */
    if (reentrant) {
        return trans_trylock_op_to_extend(p_client, p_lock_entry, p_cmd_ret, result);
    }
    if ((p_lock_entry->m_lock_type != DLOCK_FAIR) && (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS))) {
        p_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_RET]++;
        DLOCK_LOG_DEBUG("trylock failed with ret %d", p_cmd_ret->op_ret);
        return p_cmd_ret->op_ret;
    }

    return p_lock_entry->update_state_with_cmd_msg(p_cmd_ret, result);
}

int dlock_client::unlock(int client_id, int lock_id, void *result)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    if (p_client->m_async_flag) {
        p_client->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("unlock: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock);
    lock_map_t::iterator lock_iter = p_client->m_lock_map.find(lock_id);
    if (lock_iter == p_client->m_lock_map.end()) {
        shared_locker.unlock();
        p_client->m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
        DLOCK_LOG_DEBUG("lock %d has not been got", lock_id);
        return static_cast<int>(DLOCK_LOCK_NOT_GET);
    }
    shared_locker.unlock();

    if ((lock_iter->second->m_ref_count == 0u) && (lock_iter->second->m_lock_type != DLOCK_FAIR)) {
        p_client->m_stats.stats[DEBUG_STATS_ALREADY_UNLOCKED]++;
        DLOCK_LOG_DEBUG("lock %d has not been locked", lock_id);
        return static_cast<int>(DLOCK_ALREADY_UNLOCKED);
    } else if (lock_iter->second->m_ref_count > 1) {
        DLOCK_LOG_DEBUG("lock %d has been locked %d times", lock_id, lock_iter->second->m_ref_count);
        p_client->m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
        lock_iter->second->m_ref_count--;
        return static_cast<int>(DLOCK_ALREADY_LOCKED);
    }

    lock_entry_c *p_lock_entry = lock_iter->second;
    struct lock_request req = {0};
    struct lock_cmd_msg cmd_msg = {0};
    dlock_status_t ret;
    struct lock_cmd_msg *res = nullptr;
    uint16_t message_id = p_client->m_p_jetty_mgr->generate_message_id();

    req.lock_id = lock_id;
    req.lock_op = static_cast<uint16_t>(UNLOCK);
    ret = static_cast<dlock_status_t>(p_lock_entry->fill_cmd_msg(client_id, message_id, &req, cmd_msg));
    if (ret != DLOCK_SUCCESS) {
        return (ret == DLOCK_DONE) ? static_cast<int>(DLOCK_SUCCESS) : static_cast<int>(ret);
    }

    /* If replica_enable is false, the lock in primary server has been unlocked, but client does not receive
     * a response and update the local lock state. As a result, when the primary server is faulty and a new
     * primary server is started to restore the lock state from clients, the local lock state of the client
     * is synchronized to the server, causing the lock state to be abnormal. To avoid the problem, the client
     * clears the local lock value before sending an unlock request. */
    p_lock_entry->clear_lock_val();

    ret = xchg_cmd_msg(*p_client, cmd_msg, &res);
    if ((ret != DLOCK_SUCCESS) || (res == nullptr)) {
        DLOCK_LOG_DEBUG("xchg_cmd_msg error");
        /* m_ref_count has been subtracked 1 in fill_cmd_msg */
        p_lock_entry->m_ref_count++;
        return static_cast<int>(ret);
    }

    if (res->op_ret == static_cast<int>(DLOCK_NOT_READY)) {
        /* m_ref_count has been subtracked 1 in fill_cmd_msg */
        p_lock_entry->m_ref_count++;
        p_client->m_stats.stats[DEBUG_STATS_NOT_READY]++;
        DLOCK_LOG_DEBUG("unlock failed with ret %d", res->op_ret);
        return res->op_ret;
    }
    if ((p_lock_entry->m_lock_type != DLOCK_FAIR) && (res->op_ret != static_cast<uint8_t>(DLOCK_SUCCESS))) {
        p_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_RET]++;
        DLOCK_LOG_DEBUG("bad result %x", res->op_ret);
        p_lock_entry->m_lock_state = LOCK_INITIALIZED;
        p_lock_entry->m_ref_count = 0;
        return static_cast<int>(DLOCK_FAIL);
    }

    return p_lock_entry->update_state_with_cmd_msg(res, result);
}

int dlock_client::lock_extend(int client_id, const struct lock_request *req, void *result)
{
    struct lock_cmd_msg cmd_msg = {0};
    int ret;
    struct lock_cmd_msg *p_cmd_ret = nullptr;

    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    if (p_client->m_async_flag) {
        p_client->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("lock_extend: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock);
    lock_map_t::iterator lock_iter = p_client->m_lock_map.find(req->lock_id);
    if (lock_iter == p_client->m_lock_map.end()) {
        shared_locker.unlock();
        p_client->m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
        DLOCK_LOG_DEBUG("lock %d has not been got", req->lock_id);
        return static_cast<int>(DLOCK_LOCK_NOT_GET);
    }
    shared_locker.unlock();
    lock_entry_c *p_lock_entry = lock_iter->second;
    if (p_lock_entry->m_ref_count == 0u) {
        p_client->m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
        DLOCK_LOG_DEBUG("lock %d has not been locked, invalid status", req->lock_id);
        return static_cast<int>(DLOCK_EINVAL);
    }

    uint16_t message_id = p_client->m_p_jetty_mgr->generate_message_id();
    ret = p_lock_entry->fill_cmd_msg(client_id, message_id, req, cmd_msg);
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }

    ret = static_cast<int>(xchg_cmd_msg(*p_client, cmd_msg, &p_cmd_ret));
    if ((ret != static_cast<int>(DLOCK_SUCCESS)) || (p_cmd_ret == nullptr)) {
        DLOCK_LOG_DEBUG("xchg_cmd_msg error");
        return ret;
    }

    if (p_cmd_ret->op_ret == static_cast<int>(DLOCK_NOT_READY)) {
        p_client->m_stats.stats[DEBUG_STATS_NOT_READY]++;
        DLOCK_LOG_ERR("extend lock failed with ret %d", p_cmd_ret->op_ret);
        return p_cmd_ret->op_ret;
    }

    if ((p_lock_entry->m_lock_type != DLOCK_FAIR) && (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS))) {
        DLOCK_LOG_DEBUG("extend lock failed with ret %d", p_cmd_ret->op_ret);
        p_lock_entry->m_lock_state = LOCK_INITIALIZED;
        p_lock_entry->m_ref_count = 0;
        return p_cmd_ret->op_ret;
    }

    return p_lock_entry->update_state_with_cmd_msg(p_cmd_ret, result);
}

uint32_t dlock_client::batch_trylock_construct_cmd_msg(client_entry_c &p_client_entry, unsigned int lock_num,
    const struct lock_request *p_reqs, struct lock_op_res *op_res, uint8_t *buf)
{
    uint16_t message_id = p_client_entry.m_p_jetty_mgr->generate_message_id();
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct lock_cmd_msg *p_cmd_msg = nullptr;
    uint32_t msg_len = 0;
    int ret;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for (int i = 0; i < static_cast<int>(lock_num); i++) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_reqs[i].lock_id);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_reqs[%d]: lock %d has not been got", i, p_reqs[i].lock_id);
            op_res[i].op_ret = static_cast<int>(DLOCK_LOCK_NOT_GET);
            continue;
        }
        shared_locker.unlock();

        p_lock_entry = lock_iter->second;
        if ((p_lock_entry->m_lock_type == DLOCK_ATOMIC) && (p_reqs[i].lock_op != static_cast<int>(LOCK_EXCLUSIVE))) {
            p_client_entry.m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
            DLOCK_LOG_DEBUG("p_reqs[%d]: invalid lock op %d for trylock, lock_id: %d",
                i, p_reqs[i].lock_op, p_reqs[i].lock_id);
            op_res[i].op_ret = static_cast<int>(DLOCK_EINVAL);
            continue;
        }

        if (p_reqs[i].expire_time == 0u) {
            op_res[i].op_ret = p_lock_entry->update_state_with_cmd_msg(nullptr,
                reinterpret_cast<void *>(&op_res[i]));
            continue;
        }

        p_cmd_msg = reinterpret_cast<struct lock_cmd_msg *>(buf + msg_len);
        ret = p_lock_entry->fill_cmd_msg(p_client_entry.m_client_id, message_id, &p_reqs[i], *p_cmd_msg);
        if (ret != static_cast<int>(DLOCK_SUCCESS)) {
            if (ret == static_cast<int>(DLOCK_ALREADY_LOCKED)) {
                static_cast<void>(p_lock_entry->update_state_with_cmd_msg(nullptr,
                    reinterpret_cast<void *>(&op_res[i])));
                op_res[i].op_ret = ret;
                continue;
            }
            op_res[i].op_ret = (ret == static_cast<int>(DLOCK_DONE)) ? static_cast<int>(DLOCK_SUCCESS) : ret;
            continue;
        }
        msg_len += sizeof(struct lock_cmd_msg);
        set_bit(static_cast<uint32_t>(i), p_client_entry.m_batch_bitmap);
    }

    return msg_len;
}

void dlock_client::batch_trylock_update_state_with_cmd_msg(client_entry_c &p_client_entry,
    unsigned int lock_num, const struct lock_request *p_reqs, struct lock_op_res *op_res)
{
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(p_client_entry.m_p_jetty_mgr->m_cr_data);
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct lock_cmd_msg *p_cmd_ret =
        reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    unsigned long pos;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for_each_set_bit(pos, p_client_entry.m_batch_bitmap, lock_num) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_reqs[pos].lock_id);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_reqs[%ld]: lock %d has not been got", pos, p_reqs[pos].lock_id);
            op_res[pos].op_ret = static_cast<int>(DLOCK_LOCK_NOT_GET);
            p_cmd_ret++;
            continue;
        }
        shared_locker.unlock();
        p_lock_entry = lock_iter->second;

        if ((p_cmd_ret->op_code == static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND)) ||
            (p_cmd_ret->op_code == static_cast<uint8_t>(SHARED_LOCK_EXTEND))) {
            p_lock_entry->m_lock_state = (p_cmd_ret->op_ret == static_cast<int>(DLOCK_FAIL)) ?
                LOCK_INITIALIZED : p_lock_entry->m_lock_state;
            p_lock_entry->m_ref_count = (p_cmd_ret->op_ret == static_cast<int>(DLOCK_FAIL)) ?
                0 : p_lock_entry->m_ref_count;

            if ((p_lock_entry->m_lock_type != DLOCK_FAIR) &&
                (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS))) {
                DLOCK_LOG_DEBUG("p_reqs[%ld]: trylock %d failed with ret %d", pos,
                    p_reqs[pos].lock_id, p_cmd_ret->op_ret);
                op_res[pos].op_ret = p_cmd_ret->op_ret;
                p_cmd_ret++;
                continue;
            }
            op_res[pos].op_ret = p_lock_entry->update_state_with_cmd_msg(p_cmd_ret,
                reinterpret_cast<void *>(&op_res[pos]));
            op_res[pos].op_ret = (op_res[pos].op_ret == static_cast<int>(DLOCK_SUCCESS)) ?
                static_cast<int>(DLOCK_ALREADY_LOCKED) : op_res[pos].op_ret;
            p_cmd_ret++;
            continue;
        }

        if ((p_lock_entry->m_lock_type != DLOCK_FAIR) &&
            (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS))) {
            DLOCK_LOG_DEBUG("p_reqs[%ld]: trylock %d failed with ret %d", pos, p_reqs[pos].lock_id, p_cmd_ret->op_ret);
            op_res[pos].op_ret = p_cmd_ret->op_ret;
            p_cmd_ret++;
            continue;
        }

        op_res[pos].op_ret = p_lock_entry->update_state_with_cmd_msg(p_cmd_ret,
            reinterpret_cast<void *>(&op_res[pos]));
        p_cmd_ret++;
    }
}

void dlock_client::batch_set_op_ret(const client_entry_c &p_client_entry, struct lock_op_res *op_res, int op_ret) const
{
    unsigned long pos;

    for_each_set_bit(pos, p_client_entry.m_batch_bitmap, MAX_LOCK_BATCH_SIZE) {
        op_res[pos].op_ret = op_ret;
    }
}

void dlock_client::batch_trylock_update_ref_count_on_bad_resp(client_entry_c &p_client_entry,
    unsigned int lock_num, const struct lock_request *p_reqs, uint8_t *buf)
{
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct lock_cmd_msg *p_cmd_msg = reinterpret_cast<struct lock_cmd_msg *>(buf);
    unsigned long pos;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for_each_set_bit(pos, p_client_entry.m_batch_bitmap, lock_num) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_reqs[pos].lock_id);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_reqs[%ld]: lock %d has not been got", pos, p_reqs[pos].lock_id);
            p_cmd_msg++;
            continue;
        }
        shared_locker.unlock();
        p_lock_entry = lock_iter->second;

        if ((p_cmd_msg->op_code == static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND)) ||
            (p_cmd_msg->op_code == static_cast<uint8_t>(SHARED_LOCK_EXTEND))) {
            p_lock_entry->m_ref_count--;
        }
    }
}

int dlock_client::batch_trylock(int client_id, unsigned int lock_num,
    const struct lock_request *p_reqs, void *p_results)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client_entry = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client_entry == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    if (p_client_entry->m_async_flag) {
        p_client_entry->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("batch_trylock: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    struct urma_buf *p_tx_buf = m_p_urma_ctx->get_memory();
    if (p_tx_buf == nullptr) {
        p_client_entry->m_stats.stats[DEBUG_STATS_NO_URMA_BUF]++;
        DLOCK_LOG_DEBUG("clientMgr does not have enough urma buf to use");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    struct lock_op_res *op_res = reinterpret_cast<struct lock_op_res *>(p_results);
    int ret;
    uint32_t msg_len;
    struct urma_buf *p_rx_buf = nullptr;

    bitmap_zero(lock_num, p_client_entry->m_batch_bitmap);
    msg_len = batch_trylock_construct_cmd_msg(*p_client_entry, lock_num, p_reqs, op_res, p_tx_buf->buf);
    if (msg_len == 0u) {
        DLOCK_LOG_DEBUG("no valid lock cmd msg to be sent");
        ret = static_cast<int>(DLOCK_SUCCESS);
        goto exit;
    }

    ret = static_cast<int>(xchg_batch_lock_cmd_msg(*p_client_entry, p_tx_buf, msg_len, &p_rx_buf));
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        DLOCK_LOG_DEBUG("xchg_batch_lock_cmd_msg error");
        batch_set_op_ret(*p_client_entry, op_res, ret);
        batch_trylock_update_ref_count_on_bad_resp(*p_client_entry, lock_num, p_reqs, p_tx_buf->buf);
        ret = static_cast<int>(DLOCK_SUCCESS);
        goto exit;
    }

    batch_trylock_update_state_with_cmd_msg(*p_client_entry, lock_num, p_reqs, op_res);
    ret = static_cast<int>(DLOCK_SUCCESS);

exit:
    m_p_urma_ctx->release_memory(p_tx_buf);
    return ret;
}

uint32_t dlock_client::batch_unlock_construct_cmd_msg(client_entry_c &p_client_entry, unsigned int lock_num,
    const int *p_lock_ids, struct lock_op_res *op_res, uint8_t *buf)
{
    uint16_t message_id = p_client_entry.m_p_jetty_mgr->generate_message_id();
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct lock_cmd_msg *p_cmd_msg = nullptr;
    struct lock_request req = {0};
    uint32_t msg_len = 0;
    int ret;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for (int i = 0; i < static_cast<int>(lock_num); i++) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_lock_ids[i]);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_lock_ids[%d]: lock %d has not been got", i, p_lock_ids[i]);
            op_res[i].op_ret = static_cast<int>(DLOCK_LOCK_NOT_GET);
            continue;
        }
        shared_locker.unlock();

        p_lock_entry = lock_iter->second;

        if ((p_lock_entry->m_ref_count == 0u) && (p_lock_entry->m_lock_type != DLOCK_FAIR)) {
            p_client_entry.m_stats.stats[DEBUG_STATS_ALREADY_UNLOCKED]++;
            DLOCK_LOG_DEBUG("p_lock_ids[%d]: lock %d has not been locked", i, p_lock_ids[i]);
            op_res[i].op_ret = static_cast<int>(DLOCK_ALREADY_UNLOCKED);
            continue;
        }

        if (p_lock_entry->m_ref_count > 1) {
            p_client_entry.m_stats.stats[DEBUG_STATS_ALREADY_LOCKED]++;
            DLOCK_LOG_DEBUG("p_lock_ids[%d]: lock %d has been locked %d times",
                i, p_lock_ids[i], p_lock_entry->m_ref_count);
            p_lock_entry->m_ref_count--;
            op_res[i].op_ret = static_cast<int>(DLOCK_ALREADY_LOCKED);
            continue;
        }

        req.lock_id = p_lock_ids[i];
        req.lock_op = static_cast<int>(UNLOCK);
        p_cmd_msg = reinterpret_cast<struct lock_cmd_msg *>(buf + msg_len);
        ret = p_lock_entry->fill_cmd_msg(p_client_entry.m_client_id, message_id, &req, *p_cmd_msg);
        if (ret != static_cast<int>(DLOCK_SUCCESS)) {
            op_res[i].op_ret = (ret == static_cast<int>(DLOCK_DONE)) ? static_cast<int>(DLOCK_SUCCESS) : ret;
            continue;
        }
        msg_len += sizeof(struct lock_cmd_msg);
        set_bit(static_cast<uint32_t>(i), p_client_entry.m_batch_bitmap);

        /* If replica_enable is false, the lock in primary server has been unlocked, but client does not receive
        * a response and update the local lock state. As a result, when the primary server is faulty and a new
        * primary server is started to restore the lock state from clients, the local lock state of the client
        * is synchronized to the server, causing the lock state to be abnormal. To avoid the problem, the client
        * clears the local lock value before sending an unlock request. */
        p_lock_entry->clear_lock_val();
    }

    return msg_len;
}

void dlock_client::batch_unlock_update_state_with_cmd_msg(client_entry_c &p_client_entry, unsigned int lock_num,
    const int *p_lock_ids, struct lock_op_res *op_res)
{
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(p_client_entry.m_p_jetty_mgr->m_cr_data);
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct lock_cmd_msg *p_cmd_ret = reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    unsigned long pos;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for_each_set_bit(pos, p_client_entry.m_batch_bitmap, lock_num) {
        if (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS)) {
            DLOCK_LOG_DEBUG("p_lock_ids[%ld]: unlock %d failed with ret %d", pos, p_lock_ids[pos], p_cmd_ret->op_ret);
            op_res[pos].op_ret = p_cmd_ret->op_ret;
            p_cmd_ret++;
            continue;
        }

        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_lock_ids[pos]);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_lock_ids[%ld]: lock %d has not been got", pos, p_lock_ids[pos]);
            op_res[pos].op_ret = static_cast<int>(DLOCK_LOCK_NOT_GET);
            p_cmd_ret++;
            continue;
        }
        shared_locker.unlock();

        p_lock_entry = lock_iter->second;
        op_res[pos].op_ret = p_lock_entry->update_state_with_cmd_msg(p_cmd_ret,
            reinterpret_cast<void *>(&op_res[pos]));
        p_cmd_ret++;
    }
}

void dlock_client::batch_unlock_update_ref_count_on_bad_resp(client_entry_c &p_client_entry,
    unsigned int lock_num, const int *p_lock_ids)
{
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    unsigned long pos;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for_each_set_bit(pos, p_client_entry.m_batch_bitmap, lock_num) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_lock_ids[pos]);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("batch_unlock, p_reqs[%ld]: lock %d has not been got", pos, p_lock_ids[pos]);
            continue;
        }
        shared_locker.unlock();
        p_lock_entry = lock_iter->second;

        p_lock_entry->m_ref_count++;
    }
}

int dlock_client::batch_unlock(int client_id, unsigned int lock_num, const int *p_lock_ids, void *p_results)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client_entry = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client_entry == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    if (p_client_entry->m_async_flag) {
        p_client_entry->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("batch_unlock: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    struct urma_buf *p_tx_buf = m_p_urma_ctx->get_memory();
    if (p_tx_buf == nullptr) {
        p_client_entry->m_stats.stats[DEBUG_STATS_NO_URMA_BUF]++;
        DLOCK_LOG_DEBUG("clientMgr does not have enough urma buf to use");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    struct lock_op_res *op_res = reinterpret_cast<struct lock_op_res *>(p_results);
    uint32_t msg_len;
    int ret;
    struct urma_buf *p_rx_buf = nullptr;

    bitmap_zero(lock_num, p_client_entry->m_batch_bitmap);
    msg_len = batch_unlock_construct_cmd_msg(*p_client_entry, lock_num, p_lock_ids, op_res, p_tx_buf->buf);
    if (msg_len == 0u) {
        DLOCK_LOG_DEBUG("no valid cmd msg to be sent");
        ret =  static_cast<int>(DLOCK_SUCCESS);
        goto exit;
    }

    ret = static_cast<int>(xchg_batch_lock_cmd_msg(*p_client_entry, p_tx_buf, msg_len, &p_rx_buf));
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        DLOCK_LOG_DEBUG("xchg_batch_lock_cmd_msg error");
        batch_set_op_ret(*p_client_entry, op_res, ret);
        batch_unlock_update_ref_count_on_bad_resp(*p_client_entry, lock_num, p_lock_ids);
        ret = static_cast<int>(DLOCK_SUCCESS);
        goto exit;
    }

    batch_unlock_update_state_with_cmd_msg(*p_client_entry, lock_num, p_lock_ids, op_res);
    ret = static_cast<int>(DLOCK_SUCCESS);

exit:
    m_p_urma_ctx->release_memory(p_tx_buf);
    return ret;
}

uint32_t dlock_client::batch_lock_extend_construct_cmd_msg(client_entry_c &p_client_entry,
    unsigned int lock_num, const struct lock_request *p_reqs, struct lock_op_res *op_res, uint8_t *buf)
{
    uint16_t message_id = p_client_entry.m_p_jetty_mgr->generate_message_id();
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct lock_cmd_msg *p_cmd_msg = nullptr;
    uint32_t msg_len = 0;
    int ret;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for (int i = 0; i < static_cast<int>(lock_num); i++) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_reqs[i].lock_id);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_reqs[%d]: lock %d has not been got", i, p_reqs[i].lock_id);
            op_res[i].op_ret = static_cast<int>(DLOCK_LOCK_NOT_GET);
            continue;
        }
        shared_locker.unlock();

        p_lock_entry = lock_iter->second;

        if (p_lock_entry->m_ref_count == 0u) {
            p_client_entry.m_stats.stats[DEBUG_STATS_EINVAL_LOCK_OP]++;
            DLOCK_LOG_DEBUG("p_reqs[%d]: lock %d has not been locked", i, p_reqs[i].lock_id);
            op_res[i].op_ret = static_cast<int>(DLOCK_EINVAL);
            continue;
        }

        p_cmd_msg = reinterpret_cast<struct lock_cmd_msg *>(buf + msg_len);
        ret = p_lock_entry->fill_cmd_msg(p_client_entry.m_client_id, message_id, &p_reqs[i], *p_cmd_msg);
        if (ret != static_cast<int>(DLOCK_SUCCESS)) {
            op_res[i].op_ret = ret;
            continue;
        }
        msg_len += sizeof(struct lock_cmd_msg);
        set_bit(static_cast<uint32_t>(i), p_client_entry.m_batch_bitmap);
    }

    return msg_len;
}

void dlock_client::batch_lock_extend_update_state_with_cmd_msg(client_entry_c &p_client_entry, unsigned int lock_num,
    const struct lock_request *p_reqs, struct lock_op_res *op_res)
{
    lock_map_t::iterator lock_iter;
    lock_entry_c *p_lock_entry = nullptr;
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(p_client_entry.m_p_jetty_mgr->m_cr_data);
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct lock_cmd_msg *p_cmd_ret = reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    unsigned long pos;

    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock, std::defer_lock);
    for_each_set_bit(pos, p_client_entry.m_batch_bitmap, lock_num) {
        shared_locker.lock();
        lock_iter = p_client_entry.m_lock_map.find(p_reqs[pos].lock_id);
        if (lock_iter == p_client_entry.m_lock_map.end()) {
            shared_locker.unlock();
            p_client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
            DLOCK_LOG_DEBUG("p_reqs[%ld]: lock %d has not been got", pos, p_reqs[pos].lock_id);
            op_res[pos].op_ret = static_cast<int>(DLOCK_LOCK_NOT_GET);
            p_cmd_ret++;
            continue;
        }
        shared_locker.unlock();
        p_lock_entry = lock_iter->second;

        if (p_cmd_ret->op_ret != static_cast<int>(DLOCK_SUCCESS)) {
            DLOCK_LOG_DEBUG("p_reqs[%ld]: extend lock failed with ret %d", pos, p_cmd_ret->op_ret);
            op_res[pos].op_ret = p_cmd_ret->op_ret;
            p_cmd_ret++;
            continue;
        }

        op_res[pos].op_ret = p_lock_entry->update_state_with_cmd_msg(p_cmd_ret,
            reinterpret_cast<void *>(&op_res[pos]));
        p_cmd_ret++;
    }
}

int dlock_client::batch_lock_extend(int client_id, unsigned int lock_num,
    const struct lock_request *p_reqs, void *p_results)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client_entry = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client_entry == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    if (p_client_entry->m_async_flag) {
        p_client_entry->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("batch_lock_extend: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    struct urma_buf *p_tx_buf = m_p_urma_ctx->get_memory();
    if (p_tx_buf == nullptr) {
        p_client_entry->m_stats.stats[DEBUG_STATS_NO_URMA_BUF]++;
        DLOCK_LOG_DEBUG("clientMgr does not have enough urma buf to use");
        return static_cast<int>(DLOCK_ENOMEM);
    }

    struct lock_op_res *op_res = reinterpret_cast<struct lock_op_res *>(p_results);
    uint32_t msg_len;
    int ret;
    struct urma_buf *p_rx_buf = nullptr;

    bitmap_zero(lock_num, p_client_entry->m_batch_bitmap);
    msg_len = batch_lock_extend_construct_cmd_msg(*p_client_entry, lock_num, p_reqs, op_res, p_tx_buf->buf);
    if (msg_len == 0u) {
        DLOCK_LOG_DEBUG("no valid lock cmd msg to be sent");
        ret = static_cast<int>(DLOCK_SUCCESS);
        goto exit;
    }

    ret = static_cast<int>(xchg_batch_lock_cmd_msg(*p_client_entry, p_tx_buf, msg_len, &p_rx_buf));
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        DLOCK_LOG_DEBUG("xchg_batch_lock_cmd_msg error");
        batch_set_op_ret(*p_client_entry, op_res, ret);
        ret = static_cast<int>(DLOCK_SUCCESS);
        goto exit;
    }

    batch_lock_extend_update_state_with_cmd_msg(*p_client_entry, lock_num, p_reqs, op_res);
    ret = static_cast<int>(DLOCK_SUCCESS);

exit:
    m_p_urma_ctx->release_memory(p_tx_buf);
    return ret;
}

int dlock_client::async_request(client_entry_c &client_entry, lock_entry_c &lock_entry,
    const struct lock_request *req) const
{
    int ret;
    struct lock_cmd_msg cmd_msg = {0};
    uint8_t *encrypted_req;
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    uint32_t expected_len = sizeof(struct lock_cmd_msg) + rx_data_offset;
    uint16_t message_id = client_entry.m_p_jetty_mgr->generate_message_id();

    ret = lock_entry.async_fill_cmd_msg(client_entry.m_client_id, message_id, req, cmd_msg);
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return (ret == static_cast<int>(DLOCK_DONE)) ? static_cast<int>(DLOCK_SUCCESS) : ret;
    }

    /* If replica_enable is false, the lock in primary server has been unlocked, but client does not receive
     * a response and update the local lock state. As a result, when the primary server is faulty and a new
     * primary server is started to restore the lock state from clients, the local lock state of the client
     * is synchronized to the server, causing the lock state to be abnormal. To avoid the problem, the client
     * clears the local lock value before sending an unlock request. */
    if (req->lock_op == static_cast<int>(UNLOCK)) {
        lock_entry.clear_lock_val();
    }

    encrypted_req = (uint8_t *)malloc(sizeof(uint8_t) * expected_len);
    if (encrypted_req == nullptr) {
        client_entry.m_stats.stats[DEBUG_STATS_ENOMEM]++;
        DLOCK_LOG_ERR("cmd msg cipher buf: malloc error (errno=%d %m)", errno);
        return static_cast<int>(DLOCK_ENOMEM);
    }
    client_entry.m_p_jetty_mgr->m_dlock_cipher->m_data_offset = 0;
    ret = static_cast<int>(client_entry.m_p_jetty_mgr->cmd_msg_cipher(static_cast<int>(ENCRYPTION),
        reinterpret_cast<uint8_t *>(&cmd_msg), sizeof(cmd_msg), encrypted_req, m_ssl_enable));
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        client_entry.m_stats.stats[DEBUG_STATS_ENCRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("encrypt msg error");
        free(encrypted_req);
        return ret;
    }
    ret = static_cast<int>(client_entry.m_p_jetty_mgr->post_send_after_recv(
        (m_ssl_enable ? (encrypted_req) : reinterpret_cast<uint8_t *>(&cmd_msg)),
        expected_len, reinterpret_cast<uint64_t>(&client_entry)));
    free(encrypted_req);
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        client_entry.m_stats.stats[DEBUG_STATS_BAD_RESPONSE]++;
        DLOCK_LOG_DEBUG("send async request error");
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }
    client_entry.m_async_id = lock_entry.m_lock_id;
    client_entry.m_async_op = req->lock_op;
    client_entry.m_async_flag = true;
    static_cast<void>(gettimeofday(&client_entry.m_async_start, nullptr));
    return static_cast<int>(DLOCK_SUCCESS);
}

int dlock_client::async_lock_request(int client_id, const struct lock_request *req)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }
    std::shared_lock<std::shared_mutex> client_map_shared_locker(m_client_map_rwlock);
    client_map_t::iterator client_iter = m_client_map.find(client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    client_map_shared_locker.unlock();
    client_entry_c *p_client_entry = client_iter->second;
    if (p_client_entry->m_async_flag) {
        p_client_entry->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("async_lock_request: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }
    int lock_id = req->lock_id;
    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock);
    lock_map_t::iterator lock_iter = p_client_entry->m_lock_map.find(lock_id);
    if (lock_iter == p_client_entry->m_lock_map.end()) {
        shared_locker.unlock();
        p_client_entry->m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
        DLOCK_LOG_DEBUG("lock %d has not been got", lock_id);
        return static_cast<int>(DLOCK_LOCK_NOT_GET);
    }
    shared_locker.unlock();
    lock_entry_c *p_lock_entry = lock_iter->second;
    return async_request(*p_client_entry, *p_lock_entry, req);
}

int dlock_client::get_lock_entry(client_entry_c &client_entry, lock_entry_c **p_lock_entry)
{
    std::shared_lock<std::shared_mutex> shared_locker(m_map_rwlock);
    lock_map_t::iterator lock_iter = client_entry.m_lock_map.find(client_entry.m_async_id);
    if (lock_iter == client_entry.m_lock_map.end()) {
        shared_locker.unlock();
        client_entry.m_stats.stats[DEBUG_STATS_LOCK_NOT_GET]++;
        DLOCK_LOG_DEBUG("lock %d has not been got", client_entry.m_async_id);
        return static_cast<int>(DLOCK_LOCK_NOT_GET);
    }
    shared_locker.unlock();
    *p_lock_entry = lock_iter->second;
    if (*p_lock_entry == nullptr) {
        client_entry.m_stats.stats[DEBUG_STATS_FAIL]++;
        DLOCK_LOG_ERR("invalid lock entry, reinit client please");
        return static_cast<int>(DLOCK_FAIL);
    }
    return static_cast<int>(DLOCK_SUCCESS);
}

int dlock_client::trylock_result_check(client_entry_c &client_entry, void *result)
{
    int ret = 0;
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(client_entry.m_p_jetty_mgr->m_cr_data);
    struct lock_cmd_msg *p_cmd_ret = reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    lock_entry_c *p_lock_entry = nullptr;

    ret = get_lock_entry(client_entry, &p_lock_entry);
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }
    bool reentrant = ((p_cmd_ret->op_code == static_cast<uint8_t>(EXCLUSIVE_LOCK_EXTEND)) ||
        (p_cmd_ret->op_code == static_cast<uint8_t>(SHARED_LOCK_EXTEND)));
    ret = p_lock_entry->async_update_state_with_cmd_msg(p_cmd_ret, result);
    /* trylock for lock with local state *_LOCKED will be transformed to an extend op */
    if (reentrant && (ret == static_cast<int>(DLOCK_SUCCESS))) {
        ret = p_cmd_ret->op_ret = static_cast<int>(DLOCK_ALREADY_LOCKED);
        p_lock_entry->m_ref_count++;
    }
    return ret;
}

int dlock_client::unlock_or_extend_result_check(client_entry_c &client_entry, void *result)
{
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(client_entry.m_p_jetty_mgr->m_cr_data);
    struct lock_cmd_msg *p_cmd_ret = reinterpret_cast<struct lock_cmd_msg *>(p_rx_buf->buf + rx_data_offset);
    lock_entry_c *p_lock_entry = nullptr;
    int ret;

    ret = get_lock_entry(client_entry, &p_lock_entry);
    if (ret != static_cast<int>(DLOCK_SUCCESS)) {
        return ret;
    }
    return p_lock_entry->async_update_state_with_cmd_msg(p_cmd_ret, result);
}

int dlock_client::async_result_check(int client_id, void *result)
{
    uint32_t expected_len = m_ssl_enable ? (AES_IV_LEN + sizeof(struct lock_cmd_msg)) :
        sizeof(struct lock_cmd_msg);

    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }
    dlock_status_t ret;
    struct timeval tv_end;
    uint32_t comp_len;
    std::shared_lock<std::shared_mutex> shared_locker(m_client_map_rwlock);
    client_map_t::iterator client_iter = m_client_map.find(client_id);
    if (client_iter == m_client_map.end()) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }
    shared_locker.unlock();
    client_entry_c *p_client_entry = client_iter->second;
    if (!p_client_entry->m_async_flag) {
        p_client_entry->m_stats.stats[DEBUG_STATS_NO_ASYNC]++;
        DLOCK_LOG_DEBUG("no outstanding async op for client");
        return static_cast<int>(DLOCK_NO_ASYNC);
    }
    ret = p_client_entry->m_p_jetty_mgr->check_recv(comp_len);
    if (ret == DLOCK_ASYNC_AGAIN) {
        static_cast<void>(gettimeofday(&tv_end, nullptr));
        if ((tv_end.tv_sec - p_client_entry->m_async_start.tv_sec) * ONE_MILLION +
            (tv_end.tv_usec - p_client_entry->m_async_start.tv_usec) > LOCK_TIMEOUT) {
            DLOCK_LOG_WARN("timeout on check recv status");
            p_client_entry->m_async_flag = false;
            p_client_entry->m_stats.stats[DEBUG_STATS_ETIMEOUT]++;
            return static_cast<int>(DLOCK_ETIMEOUT);
        }
        return static_cast<int>(ret);
    }
    if ((ret == DLOCK_FAIL) || (p_client_entry->m_p_jetty_mgr->m_cr_data == 0u) ||
        (comp_len != expected_len)) {
        p_client_entry->m_stats.stats[DEBUG_STATS_BAD_RESPONSE]++;
        DLOCK_LOG_DEBUG("error on check recv status, ret %d", static_cast<int>(ret));
        p_client_entry->m_async_flag = false;
        return static_cast<int>(DLOCK_BAD_RESPONSE);
    }
    p_client_entry->m_async_flag = false;
    p_client_entry->m_p_jetty_mgr->m_dlock_cipher->m_data_offset = AES_IV_LEN;
    struct urma_buf *p_rx_buf = reinterpret_cast<struct urma_buf *>(p_client_entry->m_p_jetty_mgr->m_cr_data);
    ret = p_client_entry->m_p_jetty_mgr->cmd_msg_cipher(static_cast<int>(DECRYPTION),
        p_rx_buf->buf, comp_len, m_ssl_enable);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry->m_stats.stats[DEBUG_STATS_DECRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("decrypt msg error");
        return static_cast<int>(ret);
    }
    return (this->*g_async_check[p_client_entry->m_async_op])(*p_client_entry, result);
}

int dlock_client::check_resp_lock_cmd_msg(const struct lock_cmd_msg &lock_cmd_req,
    const struct lock_cmd_msg &lock_cmd_resp) const
{
    if (memcmp(&lock_cmd_req, &lock_cmd_resp, DLOCK_LOCK_CMD_MSG_CMP_SIZE) != 0) {
        return -1;
    }

    if (lock_cmd_resp.lock_offset != lock_cmd_req.lock_offset) {
        return -1;
    }

    return 0;
}

int dlock_client::check_batch_resp_lock_cmd_msg(const struct lock_cmd_msg *lock_cmd_reqs,
    const struct lock_cmd_msg *lock_cmd_resps, uint32_t cmd_num) const
{
    const struct lock_cmd_msg *req = lock_cmd_reqs;
    const struct lock_cmd_msg *resp = lock_cmd_resps;

    for (uint32_t i = 0; i < cmd_num; i++) {
        if (check_resp_lock_cmd_msg(*req, *resp) != 0) {
            return -1;
        }

        req++;
        resp++;
    }

    return 0;
}

template <typename T>
dlock_status_t dlock_client::xchg_cmd_msg(client_entry_c &p_client_entry, T &req, T **p_resp)
{
    dlock_status_t ret;
    uint8_t *encrypted_req;
    uint32_t comp_len;
    struct urma_buf *p_rx_buf = nullptr;
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    uint32_t expected_len = sizeof(T) + rx_data_offset;

    encrypted_req = (uint8_t *)malloc(sizeof(uint8_t) * expected_len);
    if (encrypted_req == nullptr) {
        p_client_entry.m_stats.stats[DEBUG_STATS_ENOMEM]++;
        DLOCK_LOG_ERR("cmd msg cipher buf: malloc error (errno=%d %m)", errno);
        return DLOCK_ENOMEM;
    }
    p_client_entry.m_p_jetty_mgr->m_dlock_cipher->m_data_offset = 0;
    ret = p_client_entry.m_p_jetty_mgr->cmd_msg_cipher(static_cast<int>(ENCRYPTION),
        reinterpret_cast<uint8_t *>(&req), sizeof(req), encrypted_req, m_ssl_enable);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_ENCRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("encrypt msg error");
        free(encrypted_req);
        return ret;
    }

    ret = p_client_entry.m_p_jetty_mgr->send_and_get_res(
        (reinterpret_cast<uint8_t *>(m_ssl_enable ? (encrypted_req) : reinterpret_cast<uint8_t *>(&req))),
        expected_len, reinterpret_cast<uint64_t>(&p_client_entry), comp_len);
    free(encrypted_req);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_NETWORK_FAIL]++;
        DLOCK_LOG_DEBUG("send_and_get_res error");
        return DLOCK_BAD_RESPONSE;
    }
    if (comp_len != expected_len) {
        p_client_entry.m_stats.stats[DEBUG_STATS_BAD_RESPONSE]++;
        DLOCK_LOG_DEBUG("response error");
        return DLOCK_BAD_RESPONSE;
    }

    p_rx_buf = reinterpret_cast<struct urma_buf *>(p_client_entry.m_p_jetty_mgr->m_cr_data);
    T *p_resp_temp = reinterpret_cast<T *>(p_rx_buf->buf + rx_data_offset);

    p_client_entry.m_p_jetty_mgr->m_dlock_cipher->m_data_offset = AES_IV_LEN;
    ret = p_client_entry.m_p_jetty_mgr->cmd_msg_cipher(static_cast<int>(DECRYPTION),
        p_rx_buf->buf, comp_len, m_ssl_enable);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_DECRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("decrypt msg error");
        return ret;
    }

    if (check_resp_lock_cmd_msg(req, *p_resp_temp) != 0) {
        p_client_entry.m_stats.stats[DEBUG_STATS_BAD_RESPONSE]++;
        DLOCK_LOG_DEBUG("check response msg error");
        return DLOCK_BAD_RESPONSE;
    }

    *p_resp = p_resp_temp;
    return DLOCK_SUCCESS;
}

dlock_status_t dlock_client::xchg_batch_lock_cmd_msg(client_entry_c &p_client_entry,
    struct urma_buf *p_tx_buf, uint32_t msg_len, struct urma_buf **p_rx_buf)
{
    dlock_status_t ret;
    uint32_t comp_len;
    uint32_t rx_data_offset = m_ssl_enable ? AES_IV_LEN : 0;
    uint32_t expected_len = msg_len + rx_data_offset;

    struct urma_buf *p_encrypted_tx_buf = m_p_urma_ctx->get_memory();
    if (p_encrypted_tx_buf == nullptr) {
        p_client_entry.m_stats.stats[DEBUG_STATS_NO_URMA_BUF]++;
        DLOCK_LOG_DEBUG("clientMgr does not have enough urma buf to use");
        return DLOCK_ENOMEM;
    }

    p_client_entry.m_p_jetty_mgr->m_dlock_cipher->m_data_offset = 0;
    ret = p_client_entry.m_p_jetty_mgr->cmd_msg_cipher(static_cast<int>(ENCRYPTION),
        p_tx_buf->buf, expected_len, p_encrypted_tx_buf->buf, m_ssl_enable);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_ENCRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("encrypt msg error");
        m_p_urma_ctx->release_memory(p_encrypted_tx_buf);
        return ret;
    }

    ret = p_client_entry.m_p_jetty_mgr->send_and_get_res(
        (m_ssl_enable ? p_encrypted_tx_buf->buf : p_tx_buf->buf),
        expected_len, reinterpret_cast<uint64_t>(&p_client_entry), comp_len);
    m_p_urma_ctx->release_memory(p_encrypted_tx_buf);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_NETWORK_FAIL]++;
        DLOCK_LOG_DEBUG("send_and_get_res error");
        return DLOCK_BAD_RESPONSE;
    }
    if (comp_len != expected_len) {
        p_client_entry.m_stats.stats[DEBUG_STATS_BAD_RESPONSE]++;
        DLOCK_LOG_DEBUG("response error");
        return DLOCK_BAD_RESPONSE;
    }

    struct urma_buf *p_rx_buf_temp = reinterpret_cast<struct urma_buf *>(p_client_entry.m_p_jetty_mgr->m_cr_data);
    p_client_entry.m_p_jetty_mgr->m_dlock_cipher->m_data_offset = AES_IV_LEN;
    ret = p_client_entry.m_p_jetty_mgr->cmd_msg_cipher(static_cast<int>(DECRYPTION),
        p_rx_buf_temp->buf, comp_len, m_ssl_enable);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_DECRYPT_FAIL]++;
        DLOCK_LOG_DEBUG("decrypt msg error");
        return ret;
    }

    if (check_batch_resp_lock_cmd_msg(reinterpret_cast<struct lock_cmd_msg *>(reinterpret_cast<void *>(p_tx_buf->buf)),
        reinterpret_cast<struct lock_cmd_msg *>(reinterpret_cast<void *>(p_rx_buf_temp->buf + rx_data_offset)),
        (msg_len / sizeof(struct lock_cmd_msg))) != 0) {
        p_client_entry.m_stats.stats[DEBUG_STATS_BAD_RESPONSE]++;
        DLOCK_LOG_DEBUG("check response msg error");
        return DLOCK_BAD_RESPONSE;
    }

    *p_rx_buf = p_rx_buf_temp;
    return DLOCK_SUCCESS;
}

dlock_status_t dlock_client::post_faa_and_get_res(client_entry_c &p_client_entry, uint32_t offset,
    uint64_t add_val, uint64_t *res_val) const
{
    dlock_status_t ret;

    ret = p_client_entry.m_p_jetty_mgr->post_faa_and_get_res(reinterpret_cast<uint64_t>(&p_client_entry),
        offset, add_val, res_val);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_NETWORK_FAIL]++;
        DLOCK_LOG_DEBUG("post faa and get res error");
        return ret;
    }

    return DLOCK_SUCCESS;
}

int dlock_client::atomic64_faa(int client_id, int obj_id, uint64_t add_val, uint64_t *res_val)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    if (p_client->m_async_flag) {
        p_client->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("atomic64_faa: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    object_entry_c *p_object = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(p_client->m_omap_rwlock);
        auto it = p_client->m_object_map.find(obj_id);
        if (it == p_client->m_object_map.end()) {
            p_client->m_stats.stats[DEBUG_STATS_OBJECT_NOT_GET]++;
            DLOCK_LOG_ERR("object id %d has not been got by client", obj_id);
            return static_cast<int>(DLOCK_OBJECT_NOT_GET);
        }
        p_object = it->second;
    }

    return post_faa_and_get_res(*p_client, p_object->m_offset, add_val, res_val);
}

dlock_status_t dlock_client::post_cas_and_get_res(client_entry_c &p_client_entry, uint32_t offset,
    uint64_t cmp_val, uint64_t swap_val) const
{
    dlock_status_t ret;

    ret = p_client_entry.m_p_jetty_mgr->post_cas_and_get_res(reinterpret_cast<uint64_t>(&p_client_entry),
        offset, cmp_val, swap_val);
    if (ret != DLOCK_SUCCESS) {
        if (ret != DLOCK_OBJECT_CAS_FAILED) {
            p_client_entry.m_stats.stats[DEBUG_STATS_NETWORK_FAIL]++;
        }
        p_client_entry.m_stats.stats[DEBUG_STATS_OBJECT_CAS_FAILED]++;
        DLOCK_LOG_DEBUG("post cas and get res error");
        return ret;
    }

    return DLOCK_SUCCESS;
}

int dlock_client::atomic64_cas(int client_id, int obj_id, uint64_t cmp_val, uint64_t swap_val)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    if (p_client->m_async_flag) {
        p_client->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("atomic64_cas: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    object_entry_c *p_object = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(p_client->m_omap_rwlock);
        auto it = p_client->m_object_map.find(obj_id);
        if (it == p_client->m_object_map.end()) {
            p_client->m_stats.stats[DEBUG_STATS_OBJECT_NOT_GET]++;
            DLOCK_LOG_ERR("object id %d has not been got by client", obj_id);
            return static_cast<int>(DLOCK_OBJECT_NOT_GET);
        }
        p_object = it->second;
    }

    return post_cas_and_get_res(*p_client, p_object->m_offset, cmp_val, swap_val);
}

dlock_status_t dlock_client::post_read_and_get_res(client_entry_c &p_client_entry, uint32_t offset,
    uint64_t *res_val) const
{
    dlock_status_t ret;

    ret = p_client_entry.m_p_jetty_mgr->post_read_and_get_res(reinterpret_cast<uint64_t>(&p_client_entry),
        offset, res_val);
    if (ret != DLOCK_SUCCESS) {
        p_client_entry.m_stats.stats[DEBUG_STATS_NETWORK_FAIL]++;
        DLOCK_LOG_DEBUG("post read and get res error");
        return ret;
    }

    return DLOCK_SUCCESS;
}

int dlock_client::atomic64_get_snapshot(int client_id, int obj_id, uint64_t *res_val)
{
    if (!m_is_inited) {
        DLOCK_LOG_DEBUG("the clientMgr has not been inited");
        return static_cast<int>(DLOCK_CLIENTMGR_NOT_INIT);
    }

    client_entry_c *p_client = dlock_get_client_entry(m_client_map_rwlock, m_client_map, client_id);
    if (p_client == nullptr) {
        DLOCK_LOG_DEBUG("client has not been inited");
        return static_cast<int>(DLOCK_CLIENT_NOT_INIT);
    }

    if (p_client->m_async_flag) {
        p_client->m_stats.stats[DEBUG_STATS_EASYNC]++;
        DLOCK_LOG_DEBUG("atomic64_get_snapshot: an async op is ongoing for client");
        return static_cast<int>(DLOCK_EASYNC);
    }

    object_entry_c *p_object = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(p_client->m_omap_rwlock);
        auto it = p_client->m_object_map.find(obj_id);
        if (it == p_client->m_object_map.end()) {
            p_client->m_stats.stats[DEBUG_STATS_OBJECT_NOT_GET]++;
            DLOCK_LOG_ERR("object id %d has not been got by client", obj_id);
            return static_cast<int>(DLOCK_OBJECT_NOT_GET);
        }
        p_object = it->second;
    }

    return post_read_and_get_res(*p_client, p_object->m_offset, res_val);
}
};
