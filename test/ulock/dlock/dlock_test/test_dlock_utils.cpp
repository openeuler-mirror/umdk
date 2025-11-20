/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * File Name     : test_dlock_uitls.cpp
 * Description   : dlock unit test cases for the functions in utils.cpp
 * History       : create file & add functions
 * 1.Date        : 2024-3-19
 * Author        : huying
 * Modification  : Created file
 */
#include <stdlib.h>
#include <sys/socket.h>

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "mockcpp/mockcpp.h"
#include "mockcpp/mockcpp.hpp"

#include "utils.h"
#include "tcp_connection.h"
#include "dlock_connection.h"
#include "test_dlock_comm.h"

#ifndef MOCKER_CPP
#define MOCKER_CPP(api, TT) MOCKCPP_NS::mockAPI(#api, reinterpret_cast<TT>(api))
#endif

class test_xchg_control_msg : public testing::Test {
protected:
    uint8_t *m_buff;
    dlock_connection *m_conn;

    void SetUp()
    {
        int sockfd = 12345;
        m_buff = construct_control_msg(CLIENT_INIT_REQUEST, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
            DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_CLIENT_INIT_REQ_BODY_LEN, 1, 0);
        m_conn = new(std::nothrow) tcp_connection(sockfd);

        ASSERT_NE(m_buff, nullptr);
        ASSERT_NE(m_conn, nullptr);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        free(m_buff);
        delete m_conn;
    }
};

TEST(test_str_to_urma_eid, test_ipv6_to_urma_eid)
{
    int ret;
    dlock_eid_t eid;
    char ip[] = "2031:0000:1F1F:0000:0000:0100:11A0:ADDF";

    ret = str_to_urma_eid(ip, &eid);
    EXPECT_EQ(ret, 0);
}

TEST(test_str_to_urma_eid, test_ipv4_to_urma_eid)
{
    int ret;
    dlock_eid_t eid;
    char ip[] = "192.168.1.60";

    ret = str_to_urma_eid(ip, &eid);
    EXPECT_EQ(ret, 0);
}

TEST(test_str_to_urma_eid, test_ipv4_value_to_urma_eid)
{
    int ret;
    dlock_eid_t eid;
    char ip[] = "0xc0a8013c";

    ret = str_to_urma_eid(ip, &eid);
    EXPECT_EQ(ret, 0);
}

TEST(test_str_to_urma_eid, test_invalid_ip)
{
    int ret;
    dlock_eid_t eid;
    char ip[] = "aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccdddddddddddddddddddddd";

    ret = str_to_urma_eid(ip, &eid);
    EXPECT_EQ(ret, -1);
}

TEST(test_str_to_urma_eid, test_ip_nullptr)
{
    int ret;
    dlock_eid_t eid;

    ret = str_to_urma_eid(nullptr, &eid);
    EXPECT_EQ(ret, -1);
}

TEST(test_str_to_urma_eid, test_eid_nullptr)
{
    int ret;
    char ip[] = "192.168.1.60";

    ret = str_to_urma_eid(ip, nullptr);
    EXPECT_EQ(ret, -1);
}

TEST(test_convert_ip_addr, test_ip_str_nullptr)
{
    struct in_addr ip_addr;

    int ret = convert_ip_addr(nullptr, &ip_addr);
    EXPECT_EQ(ret, -1);
}

TEST(test_convert_ip_addr, test_ip_str_format_error)
{
    struct in_addr ip_addr;
    char *ip_str = strdup("192.168.1");

    int ret = convert_ip_addr(ip_str, &ip_addr);
    EXPECT_EQ(ret, -1);

    free(ip_str);
}

TEST(test_convert_ip_addr, test_invalid_ip)
{
    struct in_addr ip_addr;
    char *ip_str = strdup("256.168.1.60");

    int ret = convert_ip_addr(ip_str, &ip_addr);
    EXPECT_EQ(ret, -1);

    free(ip_str);
}

TEST(test_set_send_recv_timeout, test_set_SO_SNDTIMEO_failed)
{
    MOCKER(setsockopt).stubs().will(returnValue(-1));

    int sockfd = 123456;
    int timeout_second = 5;
    int ret = set_send_recv_timeout(sockfd, timeout_second);
    EXPECT_EQ(ret, -1);

    GlobalMockObject::verify();
}

TEST(test_set_send_recv_timeout, test_set_SO_RCVTIMEO_failed)
{
    MOCKER(setsockopt).stubs().will(returnValue(0)).then(returnValue(-1));

    int sockfd = 123456;
    int timeout_second = 5;
    int ret = set_send_recv_timeout(sockfd, timeout_second);
    EXPECT_EQ(ret, -1);

    GlobalMockObject::verify();
}

TEST(test_set_primary_keepalive, test_set_SO_KEEPALIVE_failed)
{
    MOCKER(setsockopt).stubs().will(returnValue(-1));

    int sockfd = 12345;
    int ret = set_primary_keepalive(sockfd);
    EXPECT_EQ(ret, -1);

    GlobalMockObject::verify();
}

TEST(test_set_primary_keepalive, test_set_TCP_KEEPIDLE_failed)
{
    MOCKER(setsockopt).stubs().will(returnValue(0)).then(returnValue(-1));

    int sockfd = 123456;
    int ret = set_primary_keepalive(sockfd);
    EXPECT_EQ(ret, -1);

    GlobalMockObject::verify();
}

TEST(test_set_primary_keepalive, test_set_TCP_KEEPINTVL_failed)
{
    MOCKER(setsockopt).stubs().will(repeat(0, 2)).then(returnValue(-1));

    int sockfd = 123456;
    int ret = set_primary_keepalive(sockfd);
    EXPECT_EQ(ret, -1);

    GlobalMockObject::verify();
}

TEST(test_set_primary_keepalive, test_set_TCP_KEEPCNT_failed)
{
    MOCKER(setsockopt).stubs().will(repeat(0, 3)).then(returnValue(-1));

    int sockfd = 123456;
    int ret = set_primary_keepalive(sockfd);
    EXPECT_EQ(ret, -1);

    GlobalMockObject::verify();
}

TEST(test_construct_control_msg, test_msg_len_exceeds_max_size)
{
    uint8_t *buff = construct_control_msg(CLIENT_HEARTBEAT_REQUEST, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        (DLOCK_MAX_CTRL_MSG_SIZE + 1), 1, 1);
    EXPECT_EQ(buff, nullptr);
}

TEST(test_construct_control_msg, test_malloc_buff_failed)
{
    MOCKER(malloc).stubs().with(eq(DLOCK_FIXED_CTRL_MSG_HDR_LEN)).will(returnValue((void *)nullptr));

    uint8_t *buff = construct_control_msg(CLIENT_HEARTBEAT_REQUEST, DLOCK_PROTO_VERSION, DLOCK_FIXED_CTRL_MSG_HDR_LEN,
        DLOCK_FIXED_CTRL_MSG_HDR_LEN, 1, 1);
    EXPECT_EQ(buff, nullptr);

    GlobalMockObject::verify();
}

TEST_F(test_xchg_control_msg, test_send_failed)
{
    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(-1));

    m_buff = xchg_control_msg(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    EXPECT_EQ(m_buff, nullptr);
}

TEST_F(test_xchg_control_msg, test_malloc_buff_failed)
{
    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + 1;

    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(0));
    MOCKER(malloc).stubs().with(eq(recv_len)).will(returnValue((void *)nullptr));

    m_buff = xchg_control_msg(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, recv_len);
    EXPECT_EQ(m_buff, nullptr);
}

TEST_F(test_xchg_control_msg, test_recv_failed_with_ret_0)
{
    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(0));
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(0));

    m_buff = xchg_control_msg(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    EXPECT_EQ(m_buff, nullptr);
}

TEST_F(test_xchg_control_msg, test_recv_msg_hdr_len_error)
{
    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(0));
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(1));

    m_buff = xchg_control_msg(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, DLOCK_FIXED_CTRL_MSG_HDR_LEN);
    EXPECT_EQ(m_buff, nullptr);
}

TEST_F(test_xchg_control_msg, test_recv_msg_total_len_error)
{
    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(0));
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(DLOCK_FIXED_CTRL_MSG_HDR_LEN));

    m_buff = xchg_control_msg(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN + 4, DLOCK_FIXED_CTRL_MSG_HDR_LEN + 4);
    EXPECT_EQ(m_buff, nullptr);
}

TEST_F(test_xchg_control_msg, test_xchg_control_msg_by_time_send_failed)
{
    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(-1));

    m_buff = xchg_control_msg_by_time(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, DLOCK_FIXED_CTRL_MSG_HDR_LEN, 1);
    EXPECT_EQ(m_buff, nullptr);
}

TEST_F(test_xchg_control_msg, test_xchg_control_msg_by_time_malloc_failed)
{
    size_t recv_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + 1;

    MOCKER_CPP(&tcp_connection::send, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(0));
    MOCKER(malloc).stubs().with(eq(recv_len)).will(returnValue((void *)nullptr));

    m_buff = xchg_control_msg_by_time(m_conn, m_buff, DLOCK_FIXED_CTRL_MSG_HDR_LEN, recv_len, 1);
    EXPECT_EQ(m_buff, nullptr);
}

TEST(test_flush_recv_buffer, test_invalid_len_and_recv)
{
    int sockfd = 12345;
    dlock_connection *conn = new(std::nothrow) tcp_connection(sockfd);

    ASSERT_NE(conn, nullptr);

    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .expects(exactly(4)).will(repeat(3, 32)).then(returnValue(-1));

    flush_recv_buffer(conn, 0);
    flush_recv_buffer(conn, 2048);

    GlobalMockObject::verify();
    delete conn;
}

TEST(test_check_if_eid_match, test_match)
{
    urma_eid_t eid1;

    (void)memset(&eid1, '1', URMA_EID_SIZE);
    bool ret = check_if_eid_match(eid1, eid1);
    EXPECT_EQ(ret, true);
}

TEST(test_check_if_eid_match, test_not_match)
{
    urma_eid_t eid1;
    urma_eid_t eid2;

    (void)memset(&eid1, '1', URMA_EID_SIZE);
    (void)memcpy(&eid2, &eid1, URMA_EID_SIZE);
    eid2.raw[0] = 2;

    bool ret = check_if_eid_match(eid1, eid2);
    EXPECT_EQ(ret, false);
}
