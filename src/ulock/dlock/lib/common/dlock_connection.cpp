/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * File Name     : dlock_connection.cpp
 * Description   : dlock connection module
 * History       : create file & add functions
 * 1.Date        : 2022-09-15
 * Author        : huying
 * Modification  : Created file
 */
#include <openssl/rand.h>
#include <cerrno>

#include "dlock_log.h"
#include "dlock_connection.h"

namespace dlock {
dlock_connection::dlock_connection()
    : m_next_message_id(0), m_recv_state(dlock_recv_state_t::RECV_STATE_IDLE),
      m_recv_buf(nullptr), m_recv_offset(0), m_expected_total_len(0)
{
    DLOCK_LOG_DEBUG("dlock_connection construct");
    m_peer_info.peer_type = DLOCK_CONN_PEER_DEFAULT;
    m_peer_info.peer_id = 0;
}

dlock_connection::~dlock_connection()
{
    DLOCK_LOG_DEBUG("dlock_connection deconstruct");
    if (m_recv_buf != nullptr) {
        free(m_recv_buf);
        m_recv_buf = nullptr;
    }
}

ssize_t dlock_connection::send(const void *buf, size_t len, int flags)
{
    static_cast<void>(buf);
    static_cast<void>(len);
    static_cast<void>(flags);
    return 0;
}

ssize_t dlock_connection::recv(void *buf, size_t len, int flags)
{
    static_cast<void>(buf);
    static_cast<void>(len);
    static_cast<void>(flags);
    return 0;
}

bool dlock_connection::is_ssl_enabled() const
{
    return false;
}

void dlock_connection::set_fd(int fd)
{
    static_cast<void>(fd);
    return;
}

int dlock_connection::get_fd() const
{
    return -1;
}

void dlock_connection::set_peer_info(dlock_conn_peer_t peer_type, int peer_id)
{
    m_peer_info.peer_type = peer_type;
    m_peer_info.peer_id = peer_id;
}

void dlock_connection::get_peer_info(dlock_conn_peer_info_t &peer_info) const
{
    peer_info.peer_type = m_peer_info.peer_type;
    peer_info.peer_id = m_peer_info.peer_id;
}

int dlock_connection::rand_init_next_message_id(void)
{
    int ret = RAND_priv_bytes(reinterpret_cast<unsigned char *>(&m_next_message_id), sizeof(m_next_message_id));
    if (ret != 1) {
        DLOCK_LOG_ERR("failed to generate random next message id, ret: %d", ret);
        return -1;
    }
    return 0;
}

uint16_t dlock_connection::generate_message_id(void)
{
    return (m_next_message_id++);
}

uint16_t dlock_connection::get_next_message_id(void) const
{
    return m_next_message_id;
}

void dlock_connection::set_next_message_id(uint16_t next_message_id)
{
    m_next_message_id = next_message_id;
}

int dlock_connection::init_recv_buf()
{
    if (m_recv_buf != nullptr) {
        return 0;
    }
    m_recv_buf = static_cast<uint8_t *>(malloc(DLOCK_MAX_CTRL_MSG_SIZE));
    if (m_recv_buf == nullptr) {
        DLOCK_LOG_ERR("malloc error (errno=%d %m)", errno);
        return -1;
    }
    return 0;
}

void dlock_connection::set_recv_state(dlock_recv_state_t state)
{
    m_recv_state = state;
}

dlock_recv_state_t dlock_connection::get_recv_state() const
{
    return m_recv_state;
}

uint8_t *dlock_connection::get_recv_buf()
{
    return m_recv_buf;
}

size_t dlock_connection::get_recv_offset() const
{
    return m_recv_offset;
}

void dlock_connection::set_recv_offset(size_t offset)
{
    m_recv_offset = offset;
}

void dlock_connection::advance_recv_offset(size_t len)
{
    m_recv_offset += len;
}

size_t dlock_connection::get_expected_total_len() const
{
    return m_expected_total_len;
}

void dlock_connection::set_expected_total_len(size_t len)
{
    m_expected_total_len = len;
}

void dlock_connection::discard_current_msg()
{
    size_t consume_len = m_expected_total_len < m_recv_offset ? m_expected_total_len : m_recv_offset;
    shift_recv_buf(consume_len);
    m_recv_state = dlock_recv_state_t::RECV_STATE_IDLE;
    m_expected_total_len = 0;
}

void dlock_connection::complete_current_msg()
{
    shift_recv_buf(m_expected_total_len);
    m_recv_state = dlock_recv_state_t::RECV_STATE_IDLE;
    m_expected_total_len = 0;
}

void dlock_connection::shift_recv_buf(size_t consumed)
{
    if (consumed >= m_recv_offset) {
        m_recv_offset = 0;
        return;
    }

    size_t remaining = m_recv_offset - consumed;
    memmove(m_recv_buf, m_recv_buf + consumed, remaining);
    m_recv_offset = remaining;
}

bool dlock_connection::is_msg_recv_complete() const
{
    return m_recv_offset >= m_expected_total_len;
}

bool dlock_connection::is_recv_buf_full() const
{
    return m_recv_offset >= DLOCK_MAX_CTRL_MSG_SIZE;
}

size_t dlock_connection::get_recv_space() const
{
    return DLOCK_MAX_CTRL_MSG_SIZE - m_recv_offset;
}

uint8_t *dlock_connection::get_recv_write_ptr()
{
    return m_recv_buf + m_recv_offset;
}
};
