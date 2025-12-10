/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * File Name     : test_ssl_connection.cpp
 * Description   : dlock unit test cases for the functions of ssl_connection class
 * History       : create file & add functions
 * 1.Date        : 2024-3-19
 * Author        : huying
 * Modification  : Created file
 */
#include <stdlib.h>

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "mockcpp/mockcpp.h"
#include "mockcpp/mockcpp.hpp"

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"

#include "dlock_types.h"
#include "utils.h"
#include "ssl_connection.h"
#include "test_dlock_comm.h"

class test_ssl_init : public testing::Test {
protected:
    ssl_connection *m_conn;
    ssl_init_attr_t m_ssl_init_attr;

    void SetUp()
    {
        int ret = generate_ssl_file();
        ASSERT_EQ(ret, 0);

        int sockfd = 12345;
        m_conn = new(std::nothrow) ssl_connection(sockfd);
        ASSERT_NE(m_conn, nullptr);

        default_server_ssl_init_attr(m_ssl_init_attr);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_conn;
        (void)delete_ssl_file();
    }
};

class test_send : public testing::Test {
protected:
    uint8_t *m_buff;
    size_t m_msg_len;
    ssl_connection *m_conn;
    ssl_init_attr_t m_ssl_init_attr;

    void SetUp()
    {
        int ret = generate_ssl_file();
        ASSERT_EQ(ret, 0);

        int sockfd = 12345;
        m_msg_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_CLIENT_INIT_REQ_BODY_LEN;
        m_buff = construct_control_msg(CLIENT_INIT_REQUEST, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
            m_msg_len, 1, 0);
        m_conn = new(std::nothrow) ssl_connection(sockfd);

        ASSERT_NE(m_buff, nullptr);
        ASSERT_NE(m_conn, nullptr);

        MOCKER(SSL_accept).stubs().will(returnValue(1));
        default_server_ssl_init_attr(m_ssl_init_attr);
        ret = m_conn->ssl_init(true, m_ssl_init_attr);
        ASSERT_EQ(ret, 0);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        free(m_buff);
        delete m_conn;
        (void)delete_ssl_file();
    }
};

class test_recv : public testing::Test {
protected:
    uint8_t *m_buff;
    size_t m_recv_len;
    ssl_connection *m_conn;
    ssl_init_attr_t m_ssl_init_attr;

    void SetUp()
    {
        int ret = generate_ssl_file();
        ASSERT_EQ(ret, 0);

        int sockfd = 12345;
        m_recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_CLIENT_INIT_RESP_BODY_LEN;
        m_buff = (uint8_t *)malloc(m_recv_len);
        m_conn = new(std::nothrow) ssl_connection(sockfd);

        ASSERT_NE(m_buff, nullptr);
        ASSERT_NE(m_conn, nullptr);

        MOCKER(SSL_accept).stubs().will(returnValue(1));
        default_server_ssl_init_attr(m_ssl_init_attr);
        ret = m_conn->ssl_init(true, m_ssl_init_attr);
        ASSERT_EQ(ret, 0);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        free(m_buff);
        delete m_conn;
        (void)delete_ssl_file();
    }
};

TEST_F(test_ssl_init, test_SSL_library_init_failed)
{
    // SSL_library_init -> OPENSSL_init_ssl
    MOCKER(OPENSSL_init_ssl).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_OpenSSL_add_all_algorithms_failed)
{
    // SSL_library_init -> OPENSSL_init_ssl
    MOCKER(OPENSSL_init_ssl).stubs().will(returnValue(1));
    // OpenSSL_add_all_algorithms -> OPENSSL_init_crypto
    MOCKER(OPENSSL_init_crypto).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_CTX_new_failed)
{
    MOCKER(SSL_CTX_new).stubs().will(returnValue((SSL_CTX *)nullptr));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_CTX_set_min_proto_version_failed)
{
    // SSL_CTX_set_min_proto_version -> SSL_CTX_ctrl
    MOCKER(SSL_CTX_ctrl).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_CTX_load_verify_locations_failed)
{
    MOCKER(SSL_CTX_load_verify_locations).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_CTX_use_certificate_file_failed)
{
    MOCKER(SSL_CTX_use_certificate_file).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_CTX_check_private_key_failed)
{
    MOCKER(SSL_CTX_check_private_key).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_new_failed)
{
    MOCKER(SSL_new).stubs().will(returnValue((SSL *)nullptr));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_SSL_set_fd_failed)
{
    MOCKER(SSL_set_fd).stubs().will(returnValue(0));

    int ret = m_conn->ssl_init(true, m_ssl_init_attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_ssl_init, test_is_ssl_enabled)
{
    bool ret = m_conn->is_ssl_enabled();
    EXPECT_EQ(ret, true);
}

TEST_F(test_ssl_init, test_cert_verify_callback_wrapper_invalid_param)
{
    int ret = m_conn->cert_verify_callback_wrapper(nullptr, nullptr);
    EXPECT_EQ(ret, 0);
}

TEST_F(test_send, test_invalid_param)
{
    ssize_t ret = m_conn->send(nullptr, m_msg_len, 0);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_send, test_blocking_SSL_ERROR_WANT_WRITE_timeout)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_WANT_WRITE));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, 0);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST_F(test_send, test_blocking_SSL_ERROR_ZERO_RETURN)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_ZERO_RETURN));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, 0);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_send, test_blocking_other_error)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SSL));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, 0);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_send, test_non_blocking_succ)
{
    MOCKER(SSL_write).stubs().will(returnValue(m_msg_len));
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_NONE));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, ssize_t(m_msg_len));
}

TEST_F(test_send, test_non_blocking_SSL_ERROR_WANT_WRITE)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_WANT_WRITE));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST_F(test_send, test_non_blocking_SSL_ERROR_ZERO_RETURN)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_ZERO_RETURN));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_send, test_non_blocking_other_error)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SSL));

    ssize_t ret = m_conn->send(m_buff, m_msg_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_recv, test_invalid_param)
{
    ssize_t ret = m_conn->recv(nullptr, m_recv_len, 0);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_recv, test_blocking_SSL_ERROR_WANT_READ_timeout)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_WANT_READ));

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, 0);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST_F(test_recv, test_blocking_SSL_ERROR_ZERO_RETURN)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_ZERO_RETURN));

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, 0);
    EXPECT_EQ(ret, 0);
}

TEST_F(test_recv, test_blocking_ssl_r_unexpected_eof_while_reading)
{
#if ((OPENSSL_VERSION_NUMBER >= 0x30000000L) || (OPENSSL_VERSION_NUMBER == 0x1010105fL))
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SSL));
    MOCKER(ERR_peek_last_error).stubs().will(returnValue((unsigned long)SSL_R_UNEXPECTED_EOF_WHILE_READING));
#else
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SYSCALL));
    MOCKER(ERR_peek_last_error).stubs().will(returnValue((unsigned long)0));
#endif

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, 0);
    EXPECT_EQ(ret, 0);
}

TEST_F(test_recv, test_blocking_other_error)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SSL));
    MOCKER(ERR_peek_last_error).stubs().will(returnValue((unsigned long)0));

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, 0);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_recv, test_non_blocking_SSL_ERROR_WANT_READ)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_WANT_READ));

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST_F(test_recv, test_non_blocking_SSL_ERROR_ZERO_RETURN)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_ZERO_RETURN));

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, 0);
}

TEST_F(test_recv, test_non_blocking_ssl_r_unexpected_eof_while_reading)
{
#if ((OPENSSL_VERSION_NUMBER >= 0x30000000L) || (OPENSSL_VERSION_NUMBER == 0x1010105fL))
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SSL));
    MOCKER(ERR_peek_last_error).stubs().will(returnValue((unsigned long)SSL_R_UNEXPECTED_EOF_WHILE_READING));
#else
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SYSCALL));
    MOCKER(ERR_peek_last_error).stubs().will(returnValue((unsigned long)0));
#endif

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, 0);
}

TEST_F(test_recv, test_non_blocking_other_error)
{
    MOCKER(SSL_get_error).stubs().will(returnValue(SSL_ERROR_SSL));
    MOCKER(ERR_peek_last_error).stubs().will(returnValue((unsigned long)0));

    ssize_t ret = m_conn->recv(m_buff, m_recv_len, MSG_DONTWAIT);
    EXPECT_EQ(ret, -1);
}
