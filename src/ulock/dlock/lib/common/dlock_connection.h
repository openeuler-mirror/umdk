/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_connection.h
 * Description   : dlock connection header
 * History       : create file & add functions
 * 1.Date        : 2022-09-15
 * Author        : huying
 * Modification  : Created file
 */

#ifndef __DLOCK_CONNECTION_H__
#define __DLOCK_CONNECTION_H__

#include <cstdint>
#include <sys/types.h>
#include <cstring>
#include <dlock_common.h>

namespace dlock {

enum class dlock_recv_state_t : uint8_t {
    RECV_STATE_IDLE = 0,
    RECV_STATE_HDR,
    RECV_STATE_BODY,
};

class dlock_connection {
public:
    dlock_connection();
    virtual ~dlock_connection();

    virtual ssize_t send(const void *buf, size_t len, int flags);
    virtual ssize_t recv(void *buf, size_t len, int flags);

    virtual void set_fd(int fd);
    virtual int get_fd() const;

    virtual bool is_ssl_enabled() const;

    void set_peer_info(dlock_conn_peer_t peer_type, int peer_id);
    void get_peer_info(dlock_conn_peer_info_t &peer_info) const;
    int rand_init_next_message_id(void);
    uint16_t generate_message_id(void);
    uint16_t get_next_message_id(void) const;
    void set_next_message_id(uint16_t next_message_id);

    int init_recv_buf();
    void set_recv_state(dlock_recv_state_t state);
    dlock_recv_state_t get_recv_state() const;
    uint8_t *get_recv_buf();
    size_t get_recv_offset() const;
    void set_recv_offset(size_t offset);
    void advance_recv_offset(size_t len);
    size_t get_expected_total_len() const;
    void set_expected_total_len(size_t len);
    void discard_current_msg();
    void complete_current_msg();
    void shift_recv_buf(size_t consumed);
    bool is_msg_recv_complete() const;
    bool is_recv_buf_full() const;
    size_t get_recv_space() const;
    uint8_t *get_recv_write_ptr();

private:
    dlock_conn_peer_info_t m_peer_info;
    uint16_t m_next_message_id;
    dlock_recv_state_t m_recv_state;
    uint8_t *m_recv_buf;
    size_t m_recv_offset;
    size_t m_expected_total_len;
};
};
#endif /* __DLOCK_CONNECTION_H__ */
