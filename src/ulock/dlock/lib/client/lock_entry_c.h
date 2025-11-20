/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : lock_entry_c.h
 * Description   : header file for lock entry class in the client lib
 * History       : create file & add functions
 * 1.Date        : 2021-06-16
 * Author        : zhangjun
 * Modification  : Created file
 */

#ifndef __LOCK_ENTRY_C_H__
#define __LOCK_ENTRY_C_H__

#include "dlock_types.h"
#include "dlock_common.h"
#include "dlock_descriptor.h"

namespace dlock {
class dlock_client;
class client_entry_c;

struct op_ret_req {
    dlock_status_t op_ret;
    enum dlock_req_code op_code;
    debug_stats_code_t stats_code;
};

class lock_entry_c {
    friend class dlock_client;
public:
    lock_entry_c() = delete;
    lock_entry_c(int32_t lock_id, enum dlock_type lock_type, uint32_t lock_offset, uint32_t lease_time,
        client_entry_c *client);
    ~lock_entry_c();
    int fill_cmd_msg(int  client_id, uint16_t message_id,
        const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    int update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    void fill_update_msg(struct update_lock_body *p_msg_update) const;
    void lock_update(struct update_lock_body *p_msg_update);
    int async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int async_fill_cmd_msg(int client_id, uint16_t message_id,
        const struct lock_request *req, struct lock_cmd_msg &cmd_msg);

    void set_m_client(client_entry_c *p_client_entry);

    dlock_descriptor* m_lock_desc;
protected:
    int atomic_fill_cmd_msg(int  client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    int atomic_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int rw_fill_cmd_msg(int  client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    int rw_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int fair_fill_cmd_msg(const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    int fair_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int atomic_async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int rw_async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int fair_async_update_state_with_cmd_msg(struct lock_cmd_msg *p_cmd_msg, void *result);
    int atomic_async_fill_cmd_msg(int  client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    int rw_async_fill_cmd_msg(int  client_id, const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    int fair_async_fill_cmd_msg(const struct lock_request *req, struct lock_cmd_msg &cmd_msg);
    void clear_lock_val(void);
    void init_cmd_msg_common_field(uint16_t message_id, struct lock_cmd_msg &cmd_msg) const;

private:
    void debug_stats_count_incre(debug_stats_code_t stats_code);

    int32_t m_lock_id;
    enum dlock_type m_lock_type;
    uint32_t m_lock_offset;
    uint32_t m_lease_time;
    unsigned int m_ref_count;
    enum dlock_state m_lock_state;
    lock_state m_lock_val;
    bool m_lock_updated;
    client_entry_c *m_client;
};
};
#endif
