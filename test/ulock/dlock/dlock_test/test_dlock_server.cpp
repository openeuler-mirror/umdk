/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * File Name     : test_dlock_server.cpp
 * Description   : dlock unit test cases for the functions of dlock_server class
 * History       : create file & add functions
 * 1.Date        : 2024-3-19
 * Author        : huying
 * Modification  : Created file
 */
#include <stdlib.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <malloc.h>

#include <openssl/rand.h>

#include "gtest/gtest.h"
#include "mockcpp/mokc.h"
#include "mockcpp/mockcpp.h"
#include "mockcpp/mockcpp.hpp"

#include "dlock_server.h"
#include "dlock_descriptor.h"
#include "jetty_mgr.h"
#include "jetty_mgr_sepconn.h"
#include "tcp_connection.h"
#include "dlock_connection.h"
#include "test_dlock_comm.h"
#include "utils.h"

#ifndef MOCKER_CPP
#define MOCKER_CPP(api, TT) MOCKCPP_NS::mockAPI(#api, reinterpret_cast<TT>(api))
#endif

class test_dlock_server : public testing::Test {
protected:
    dlock_server *m_server;
    struct server_cfg m_server_cfg;

    void SetUp()
    {
        (void)memset(&m_server_cfg, 0, sizeof(struct server_cfg));
        m_server = new(std::nothrow) dlock_server(1);
        ASSERT_NE(m_server, nullptr);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_server;
    }
};

class test_create_listen_fd : public testing::Test {
protected:
    dlock_server *m_server;
    struct in_addr m_ip_addr;
    char *m_ip_str;

    void SetUp()
    {
        m_server = new(std::nothrow) dlock_server(1);
        m_ip_str = strdup(PRIMARY_ADDRESS);
        ASSERT_NE(m_server, nullptr);
        ASSERT_NE(m_ip_str, nullptr);

        int ret = inet_aton(m_ip_str, &m_ip_addr);
        ASSERT_EQ(ret, 1);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_server;
        free(m_ip_str);
    }
};

class test_init_as_primary : public testing::Test {
protected:
    struct server_cfg m_cfg_s;
    dlock_server *m_server;

    void SetUp()
    {
        prepare_default_primary_server_cfg(m_cfg_s);

        m_server = new(std::nothrow) dlock_server(1);
        ASSERT_NE(m_server, nullptr);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_server;
        destroy_default_primary_server_cfg(m_cfg_s);
    }
};

class test_delete_except_client_entry : public testing::Test {
protected:
    struct server_cfg m_cfg_s;
    dlock_server *m_server;

    void SetUp()
    {
        prepare_default_primary_server_cfg(m_cfg_s);

        m_server = new(std::nothrow) dlock_server(1);
        ASSERT_NE(m_server, nullptr);

        int ret = m_server->init(m_cfg_s);
        ASSERT_EQ(ret, 0);
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        m_server->deinit();

        delete m_server;
        destroy_default_primary_server_cfg(m_cfg_s);
    }

    void prepare_except_client_entry(void);
};

class test_conn_exception_process : public testing::Test {
protected:
    dlock_server *m_server;
    dlock_connection *m_conn;

    void SetUp()
    {
        int sockfd = 12345;

        m_server = new(std::nothrow) dlock_server(1);
        m_conn = new(std::nothrow) tcp_connection(sockfd);

        ASSERT_NE(m_server, nullptr);
        ASSERT_NE(m_conn, nullptr);

        m_server->m_fd2conn_map[sockfd] = m_conn;
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_server;

        // m_conn has been deleted in test case
    }
};

class test_recv_msg : public testing::Test {
protected:
    dlock_server *m_server;
    dlock_connection *m_conn;

    void SetUp()
    {
        int sockfd = 12345;

        m_server = new(std::nothrow) dlock_server(1);
        m_conn = new(std::nothrow) tcp_connection(sockfd);

        ASSERT_NE(m_server, nullptr);
        ASSERT_NE(m_conn, nullptr);

        m_server->m_fd2conn_map[sockfd] = m_conn;
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        // When m_server is deleted, m_conn is also deleted.
        delete m_server;
    }
};

class test_check_control_msg_hdr : public testing::Test {
protected:
    dlock_server *m_server;
    struct dlock_control_hdr m_msg_hdr;

    void SetUp()
    {
        m_server = new(std::nothrow) dlock_server(1);
        ASSERT_NE(m_server, nullptr);

        m_msg_hdr.magic_no = DLOCK_CP_MAGIC_NO;
        m_msg_hdr.version = DLOCK_PROTO_VERSION;
        m_msg_hdr.hdr_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
        m_msg_hdr.total_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN + DLOCK_CLIENT_INIT_REQ_BODY_LEN;
        m_msg_hdr.type = CLIENT_INIT_REQUEST;
        m_msg_hdr.rsvd = 0;
        m_msg_hdr.message_id = 45628;
        m_msg_hdr.value = 0;
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_server;
    }
};

class test_create_object_by_msg : public testing::Test {
protected:
    struct server_cfg m_cfg_s;
    dlock_server *m_server;
    struct object_create_body *m_msg_body;
    int32_t m_client_id;

    void SetUp()
    {
        prepare_default_primary_server_cfg(m_cfg_s);

        m_server = new(std::nothrow) dlock_server(1);
        ASSERT_NE(m_server, nullptr);

        int ret = m_server->init(m_cfg_s);
        ASSERT_EQ(ret, 0);

        unsigned char obj_desc[] = "objx#$sdf";
        uint32_t obj_desc_len = 10;
        uint8_t *buff = (uint8_t *)malloc(sizeof(struct object_create_body) + obj_desc_len);
        ASSERT_NE(buff, nullptr);

        m_msg_body = (struct object_create_body *)buff;
        m_msg_body->obj_id = 1;
        m_msg_body->desc_len = obj_desc_len;
        (void)memcpy_s(m_msg_body->desc, m_msg_body->desc_len, obj_desc, obj_desc_len);

        m_client_id = 1;
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        m_server->deinit();
        delete m_server;
        destroy_default_primary_server_cfg(m_cfg_s);

        free(m_msg_body);
    }
};

class test_create_object_do : public testing::Test {
protected:
    dlock_server *m_server;
    struct dlock_control_hdr m_msg_hdr;
    struct object_create_body *m_msg_body;
    int32_t m_client_id;

    void SetUp()
    {
        m_server = new(std::nothrow) dlock_server(1);
        ASSERT_NE(m_server, nullptr);

        unsigned char obj_desc[] = "objx#$sdf";
        uint32_t obj_desc_len = 10;
        uint8_t *buff = (uint8_t *)malloc(sizeof(struct object_create_body) + obj_desc_len);
        ASSERT_NE(buff, nullptr);
        m_msg_body = (struct object_create_body *)buff;
        m_msg_body->obj_id = 1;
        m_msg_body->desc_len = obj_desc_len;
        (void)memcpy_s(m_msg_body->desc, m_msg_body->desc_len, obj_desc, obj_desc_len);

        m_client_id = 1;

        m_msg_hdr.hdr_len = sizeof(struct dlock_control_hdr);
        m_msg_hdr.total_len = sizeof(struct dlock_control_hdr) + DLOCK_OBJECT_CREATE_BODY_LEN +
            static_cast<uint16_t>(m_msg_body->desc_len);
        m_msg_hdr.client_id = m_client_id;

        client_entry_s *p_client_entry = new(std::nothrow) client_entry_s(m_client_id, nullptr, nullptr);
        ASSERT_NE(p_client_entry, nullptr);
        m_server->m_client_map[m_client_id] = p_client_entry;
        m_server->m_client_num = 1;
    }

    void TearDown()
    {
        GlobalMockObject::verify();

        delete m_server;
        free(m_msg_body);
    }
};

TEST_F(test_dlock_server, test_init_server_1_server_inited)
{
    m_server->m_is_primary = true;
    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_2_lock_memory_init_failed)
{
    auto mocker_memalign = reinterpret_cast<void (*)(size_t, size_t, const char *, int)>(&memalign);
    MOCKER(mocker_memalign).stubs().will(returnValue((void *)nullptr));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_SERVER_NO_RESOURCE));
}

TEST_F(test_dlock_server, test_init_server_3_init_urma_ctx_failed)
{
    MOCKER_CPP(&urma_ctx::init_urma_ctx, dlock_status_t (*)(urma_ctx *))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_4_create_ctx_failed)
{
    MOCKER_CPP(&urma_ctx::create_ctx, dlock_status_t (*)(urma_ctx *))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_6_create_jfce_failed)
{
    MOCKER_CPP(&urma_ctx::create_jfce, dlock_status_t (*)(urma_ctx *))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_7_create_jfc_failed)
{
    MOCKER_CPP(&urma_ctx::create_jfc, dlock_status_t (*)(urma_ctx *, int))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_8_register_seg_failed)
{
    MOCKER_CPP(&urma_ctx::register_seg, dlock_status_t (*)(urma_ctx *, uint32_t))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_10_create_exe_jfc_failed)
{
    MOCKER_CPP(&urma_ctx::new_jfc, urma_jfc_t * (*)(urma_ctx *, int))
        .stubs().will(returnValue((urma_jfc_t *)nullptr));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_11_register_dma_tseg_failed)
{
    MOCKER_CPP(&urma_ctx::register_new_seg, urma_target_seg_t * (*)(urma_ctx *, uint8_t *, uint32_t))
        .stubs().will(returnValue((urma_target_seg_t *)nullptr));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_init_server_12_obj_memory_init_failed)
{
    MOCKER_CPP(&object_memory::init, bool (*)())
        .stubs().will(returnValue(false));

    int ret = m_server->init_server(true, m_server_cfg);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_SERVER_NO_RESOURCE));
}

TEST_F(test_dlock_server, test_primary_control_loop_1_control_events_calloc_failed)
{
    auto mocker_calloc = reinterpret_cast<void (*)(size_t, size_t, const char *, int)>(&calloc);
    MOCKER(mocker_calloc).stubs().will(returnValue((void *)nullptr));

    int ret = m_server->primary_control_loop();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_loop_2_epoll_ctl_failed)
{
    auto mocker_epoll_ctl = reinterpret_cast<int (*)(int, int, int, struct epoll_event *)>(&epoll_ctl);
    MOCKER(mocker_epoll_ctl).stubs().will(returnValue(-1));

    int ret = m_server->primary_control_loop();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_loop_3_epoll_wait_failed)
{
    auto mocker_epoll_ctl = reinterpret_cast<int (*)(int, int, int, struct epoll_event *)>(&epoll_ctl);
    MOCKER(mocker_epoll_ctl).stubs().will(returnValue(0));
    MOCKER(epoll_wait).stubs().will(returnValue(-1));

    int ret = m_server->primary_control_loop();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_loop_4_epoll_create_failed)
{
    auto mocker_epoll_create = reinterpret_cast<int (*)(int, int)>(&epoll_create);
    MOCKER(mocker_epoll_create).stubs().will(returnValue(-1));
    int ret = m_server->primary_control_loop();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_func_1_find_conn_failed)
{
    m_server->m_listen_fd = 10000;
    int ret = m_server->primary_control_func(10001, 10002);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_func_2_accept_failed)
{
    MOCKER(accept).stubs().will(returnValue(-1));

    m_server->m_listen_fd = 10000;
    int ret = m_server->primary_control_func(10001, 10000);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_func_3_sockfd_already_exists)
{
    int new_sockfd = 10002;
    dlock_connection *conn = new(std::nothrow) tcp_connection(new_sockfd);
    ASSERT_NE(conn, nullptr);

    MOCKER(accept).stubs().will(returnValue(new_sockfd));

    m_server->m_fd2conn_map[new_sockfd] = conn;
    m_server->m_listen_fd = 10000;
    int ret = m_server->primary_control_func(10001, 10000);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_primary_control_func_4_epoll_ctl_failed)
{
    int new_sockfd = 10002;

    MOCKER(accept).stubs().will(returnValue(new_sockfd));
    auto mocker_epoll_ctl = reinterpret_cast<int (*)(int, int, int, struct epoll_event *)>(&epoll_ctl);
    MOCKER(mocker_epoll_ctl).stubs().will(returnValue(-1));

    m_server->m_listen_fd = 10000;
    int ret = m_server->primary_control_func(10001, 10000);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_release_object_do_1)
{
    struct dlock_control_hdr m_msg_hdr;
    uint8_t *m_msg_body = nullptr;

    MOCKER_CPP(check_msg_body_len_invalid, bool (*)(struct dlock_control_hdr *, uint16_t))
        .stubs().will(returnValue(true));
    int ret = m_server->release_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_EINVAL));
}

TEST_F(test_dlock_server, test_release_object_do_2)
{
    struct dlock_control_hdr m_msg_hdr;
    uint8_t *m_msg_body = nullptr;

    MOCKER_CPP(check_msg_body_len_invalid, bool (*)(struct dlock_control_hdr *, uint16_t))
        .stubs().will(returnValue(false));
    int ret = m_server->release_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_CLIENT_NOT_INIT));
}

TEST_F(test_dlock_server, test_destroy_object_do_1)
{
    struct dlock_control_hdr m_msg_hdr;
    uint8_t *m_msg_body = nullptr;

    MOCKER_CPP(check_msg_body_len_invalid, bool (*)(struct dlock_control_hdr *, uint16_t))
        .stubs().will(returnValue(true));
    int ret = m_server->destroy_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_EINVAL));
}

TEST_F(test_dlock_server, test_destroy_object_do_2)
{
    struct dlock_control_hdr m_msg_hdr;
    uint8_t *m_msg_body = nullptr;

    MOCKER_CPP(check_msg_body_len_invalid, bool (*)(struct dlock_control_hdr *, uint16_t))
        .stubs().will(returnValue(false));
    int ret = m_server->destroy_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_CLIENT_NOT_INIT));
}

TEST_F(test_dlock_server, test_client_num_count_down)
{
    m_server->m_client_num = 0;
    int ret = m_server->client_num_count_down();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_negotiate_proto_version)
{
    struct client_init_req_body req_body;
    req_body.min_version = 10;
    int ret = m_server->negotiate_proto_version(req_body);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_check_cmd_msg_common_field_1)
{
    struct lock_cmd_msg cmd_msg;
    cmd_msg.magic_no = DLOCK_CP_MAGIC_NO;
    int ret = m_server->check_cmd_msg_common_field(cmd_msg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_check_cmd_msg_common_field_2)
{
    struct lock_cmd_msg cmd_msg;
    cmd_msg.magic_no = DLOCK_DP_MAGIC_NO;
    cmd_msg.version = 10;
    int ret = m_server->check_cmd_msg_common_field(cmd_msg);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_launch_1)
{
    m_server->m_is_primary = false;
    int ret = m_server->launch();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_launch_2)
{
    m_server->m_is_primary = true;

    MOCKER_CPP(pthread_create, int (*)(pthread_t *, const pthread_attr_t *, void * (*)(void *), void *))
        .stubs().will(returnValue(-1));

    int ret = m_server->launch();
    EXPECT_EQ(ret, -1);
}

TEST_F(test_dlock_server, test_get_client_id_max_num_reached)
{
    client_entry_s *p_client_entry;
    for (int i = 0; i < MAX_NUM_CLIENT + 1; i++) {
        p_client_entry = new(std::nothrow) client_entry_s(i, nullptr, nullptr);
        ASSERT_NE(p_client_entry, nullptr);
        m_server->m_client_map[i] = p_client_entry;
        m_server->m_client_num = i + 1;
    }

    int ret = m_server->get_client_id();
    EXPECT_EQ(ret, -static_cast<int>(DLOCK_SERVER_NO_RESOURCE));
}

TEST_F(test_create_listen_fd, test_create_socket_failed)
{
    auto mocker_socket = reinterpret_cast<int (*)(int, int, int)>(&socket);
    MOCKER(mocker_socket).stubs().will(returnValue(-1));

    int listen_fd;
    int ret = m_server->create_listen_fd(m_ip_addr, CONTROL_PORT_CLIENT, listen_fd);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_create_listen_fd, test_setsockopt_failed)
{
    auto mocker_setsockopt = reinterpret_cast<int (*)(int, int, int, const void *, socklen_t)>(&setsockopt);
    MOCKER(mocker_setsockopt).stubs().will(returnValue(-1));

    int listen_fd;
    int ret = m_server->create_listen_fd(m_ip_addr, CONTROL_PORT_CLIENT, listen_fd);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_create_listen_fd, test_bind_failed)
{
    auto mocker_bind = reinterpret_cast<int (*)(int, const struct sockaddr *, socklen_t)>(&bind);
    MOCKER(mocker_bind).stubs().will(returnValue(-1));

    int listen_fd;
    int ret = m_server->create_listen_fd(m_ip_addr, CONTROL_PORT_CLIENT, listen_fd);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_create_listen_fd, test_listen_failed)
{
    auto mocker_listen = reinterpret_cast<int (*)(int, int)>(&listen);
    MOCKER(mocker_listen).stubs().will(returnValue(-1));

    int listen_fd;
    int ret = m_server->create_listen_fd(m_ip_addr, CONTROL_PORT_CLIENT, listen_fd);
    EXPECT_EQ(ret, -1);
}

TEST(test_set_random_seed, test_read_entropy_pool_failed)
{
    dlock_server *p_server = new(std::nothrow) dlock_server(1);
    ASSERT_NE(p_server, nullptr);

    MOCKER_CPP(&dlock_server::read_entropy_pool, dlock_status_t (*)(dlock_server *, int, uint8_t *, int))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = p_server->set_random_seed();
    EXPECT_EQ(ret, DLOCK_FAIL);

    GlobalMockObject::verify();
    delete p_server;
}

TEST_F(test_init_as_primary, test_set_random_seed_failed)
{
    MOCKER_CPP(&dlock_server::set_random_seed, dlock_status_t (*)(dlock_server *))
        .stubs().will(returnValue(DLOCK_FAIL));

    int ret = m_server->init_as_primary(m_cfg_s);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_init_as_primary, test_init_server_failed)
{
    MOCKER_CPP(&dlock_server::init_server, int (*)(dlock_server *, bool, char *, const char *))
        .stubs().will(returnValue(-1));

    int ret = m_server->init_as_primary(m_cfg_s);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_init_as_primary, test_primary_get_addr_and_ports_failed)
{
    MOCKER_CPP(&dlock_server::primary_get_addr_and_ports, int (*)(dlock_server *, const struct server_cfg &,
        struct in_addr &, uint16_t &)).stubs().will(returnValue(-1));

    int ret = m_server->init_as_primary(m_cfg_s);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_init_as_primary, test_create_listen_fd_failed)
{
    MOCKER_CPP(&dlock_server::create_listen_fd, int (*)(dlock_server *, const struct in_addr &, uint16_t, int &))
        .stubs().will(returnValue(-1));

    int ret = m_server->init_as_primary(m_cfg_s);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_init_as_primary, test_server_init)
{
    m_server->m_is_primary = true;
    int ret = m_server->init(m_cfg_s);
    EXPECT_EQ(ret, -1);
}

void test_delete_except_client_entry::prepare_except_client_entry(void)
{
    int client_id = 10001;
    struct timeval tv_start;

    gettimeofday(&tv_start, NULL);

    client_entry_s *p_client_entry = new(std::nothrow) client_entry_s(client_id, nullptr, nullptr);
    ASSERT_NE(p_client_entry, nullptr);
    m_server->m_client_map[client_id] = p_client_entry;
    m_server->m_except_client_set.insert(client_id);
    m_server->m_client_num = 1;

    unsigned char lock_desc[] = "lock#$sdf";
    uint32_t lock_desc_len = 10;
    uint8_t *buff = (uint8_t *)malloc(sizeof(struct get_lock_body) + lock_desc_len);
    ASSERT_NE(buff, nullptr);

    struct get_lock_body *get_msg = (struct get_lock_body *)buff;
    get_msg->lock_id = 462558;
    get_msg->lock_type = DLOCK_ATOMIC;
    get_msg->lease_time = tv_start.tv_sec + 60000;
    get_msg->offset = 0;
    get_msg->desc_len = lock_desc_len;
    (void)memcpy_s(get_msg->desc, get_msg->desc_len, lock_desc, lock_desc_len);

    lock_entry_s *p_lock_entry = m_server->get_lock_by_msg(get_msg);
    ASSERT_NE(p_lock_entry, nullptr);
    p_client_entry->m_lock_map[get_msg->lock_id] = p_lock_entry;
    p_lock_entry->m_lease_time_map[client_id] = get_msg->lease_time;
    free(buff);

    // prepare object entry to test clear object function
    unsigned char obj_desc[] = "object desc 1";
    uint32_t object_desc_len = static_cast<uint32_t>(strlen("object desc 1"));
    buff = (uint8_t *)malloc(sizeof(struct object_create_body) + object_desc_len);
    ASSERT_NE(buff, nullptr);

    struct object_create_body *create_obj_msg = (struct object_create_body *)buff;
    create_obj_msg->obj_id = 1234;
    create_obj_msg->lease_time = 600000;
    create_obj_msg->init_value = 1;
    create_obj_msg->desc_len = object_desc_len;
    (void)memcpy_s(create_obj_msg->desc, create_obj_msg->desc_len, obj_desc, object_desc_len);

    object_entry_s *p_obj_entry = m_server->create_object_by_msg(create_obj_msg, client_id);
    ASSERT_NE(p_obj_entry, nullptr);
    std::chrono::seconds lease_time(create_obj_msg->lease_time);
    p_obj_entry->m_max_lease_tp = std::chrono::steady_clock::now() + lease_time;
    p_obj_entry->m_lease_tp_map[client_id] = p_obj_entry->m_max_lease_tp;
    p_client_entry->m_object_map[client_id] = p_obj_entry;
    p_obj_entry->m_refcnt++;
    m_server->m_curr_object_num++;
    free(buff);
}

TEST_F(test_delete_except_client_entry, test_no_except_client_entry_to_release)
{
    int ret = m_server->delete_except_client_entry();
    EXPECT_EQ(ret, DLOCK_SERVER_NO_RESOURCE);
}

TEST_F(test_delete_except_client_entry, test_delete_except_client_entry_success)
{
    prepare_except_client_entry();

    MOCKER_CPP(&dlock_server::modify_jetty_mgr_to_invalid, int (*)(dlock_server *, jetty_mgr *))
        .stubs().will(returnValue(0));

    int ret = m_server->delete_except_client_entry();
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(m_server->m_client_map.size(), 0u);
    EXPECT_EQ(m_server->m_except_client_set.size(), 0u);
    EXPECT_EQ(m_server->m_client_num, 0);
    EXPECT_EQ(m_server->m_lock_map.size(), 0u);
    EXPECT_EQ(m_server->m_lock_desc_map.size(), 0u);
    EXPECT_EQ(m_server->m_lock_num, 0);
    EXPECT_EQ(m_server->m_object_map.size(), 0u);
    EXPECT_EQ(m_server->m_object_desc_map.size(), 0u);
    EXPECT_EQ(m_server->m_curr_object_num, 0);
}

TEST_F(test_delete_except_client_entry, test_modify_jetty_mgr_state_failed)
{
    prepare_except_client_entry();

    MOCKER_CPP(&dlock_server::modify_jetty_mgr_to_invalid, int (*)(dlock_server *, jetty_mgr *))
        .stubs().will(returnValue(-1));

    int ret = m_server->delete_except_client_entry();
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(m_server->m_client_map.size(), 1u);
    EXPECT_EQ(m_server->m_except_client_set.size(), 1u);
    EXPECT_EQ(m_server->m_client_num, 1);
    EXPECT_EQ(m_server->m_lock_map.size(), 1u);
    EXPECT_EQ(m_server->m_lock_desc_map.size(), 1u);
    EXPECT_EQ(m_server->m_lock_num, 1);
    EXPECT_EQ(m_server->m_object_map.size(), 1u);
    EXPECT_EQ(m_server->m_object_desc_map.size(), 1u);
    EXPECT_EQ(m_server->m_curr_object_num, 1);
}

TEST_F(test_delete_except_client_entry, test_except_client_entry_not_exist)
{
    int client_id = 10001;

    prepare_except_client_entry();
    client_map_t::iterator client_iter = m_server->m_client_map.find(client_id);
    ASSERT_NE(client_iter, m_server->m_client_map.end());

    delete client_iter->second;
    (void)m_server->m_client_map.erase(client_iter);

    MOCKER_CPP(&dlock_server::modify_jetty_mgr_to_invalid, int (*)(dlock_server *, jetty_mgr *))
        .stubs().will(returnValue(0));

    int ret = m_server->delete_except_client_entry();
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(m_server->m_client_map.size(), 0u);
    EXPECT_EQ(m_server->m_except_client_set.size(), 1u);
    EXPECT_EQ(m_server->m_client_num, 1);
    EXPECT_EQ(m_server->m_lock_map.size(), 1u);
    EXPECT_EQ(m_server->m_lock_desc_map.size(), 1u);
    EXPECT_EQ(m_server->m_lock_num, 1);
    EXPECT_EQ(m_server->m_object_map.size(), 1u);
    EXPECT_EQ(m_server->m_object_desc_map.size(), 1u);
    EXPECT_EQ(m_server->m_curr_object_num, 1);
}

TEST_F(test_conn_exception_process, test_conn_peer_replica_server)
{
    m_conn->set_peer_info(DLOCK_CONN_PEER_REPLICA_SERVER, 1);

    m_server->conn_exception_process(m_conn);
    EXPECT_EQ(m_server->m_fd2conn_map.size(), 0u);
}

TEST_F(test_conn_exception_process, test_conn_peer_primary_server)
{
    m_server->m_primary = new(std::nothrow) server_node(m_conn, nullptr, nullptr);
    m_conn->set_peer_info(DLOCK_CONN_PEER_PRIMARY_SERVER, 1);

    m_server->conn_exception_process(m_conn);
    EXPECT_EQ(m_server->m_fd2conn_map.size(), 0u);
}

TEST_F(test_conn_exception_process, test_invalid_conn_peer_type)
{
    m_conn->set_peer_info(DLOCK_CONN_PEER_DEFAULT, 1);

    m_server->conn_exception_process(m_conn);
    EXPECT_EQ(m_server->m_fd2conn_map.size(), 0u);
}

TEST_F(test_recv_msg, test_recv_msg_hdr_1_recv_errno_EAGAIN)
{
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(-1));

    errno = EAGAIN;
    struct dlock_control_hdr msg_hdr;
    int ret = m_server->recv_msg_hdr(m_conn, &msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_recv_msg, test_recv_msg_hdr_2_recv_errno_EINTR)
{
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .expects(exactly(5)).will(returnValue(-1));

    errno = EINTR;
    struct dlock_control_hdr msg_hdr;
    int ret = m_server->recv_msg_hdr(m_conn, &msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_recv_msg, test_recv_msg_hdr_3_recv_len_error)
{
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(sizeof(struct dlock_control_hdr) - 1));

    struct dlock_control_hdr msg_hdr;
    int ret = m_server->recv_msg_hdr(m_conn, &msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_recv_msg, test_recv_msg_ext_hdr_and_body_1_malloc_buff_failed)
{
    auto mocker_malloc = reinterpret_cast<void *(*)(size_t)>(malloc);
    MOCKER(mocker_malloc).stubs().with(eq(DLOCK_CLIENT_INIT_REQ_BODY_LEN)).will(returnValue((void *)nullptr));

    uint8_t *msg_ext_hdr = nullptr;
    uint8_t *msg_body = nullptr;
    int ret = m_server->recv_msg_ext_hdr_and_body(m_conn, 0, DLOCK_CLIENT_INIT_REQ_BODY_LEN, &msg_ext_hdr, &msg_body);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(msg_ext_hdr, nullptr);
    EXPECT_EQ(msg_body, nullptr);
}

TEST_F(test_recv_msg, test_recv_msg_ext_hdr_and_body_2_recv_failed)
{
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(-1));

    uint8_t *msg_ext_hdr = nullptr;
    uint8_t *msg_body = nullptr;
    int ret = m_server->recv_msg_ext_hdr_and_body(m_conn, 0, DLOCK_CLIENT_INIT_REQ_BODY_LEN, &msg_ext_hdr, &msg_body);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(msg_ext_hdr, nullptr);
    EXPECT_EQ(msg_body, nullptr);
}

TEST_F(test_recv_msg, test_recv_msg_ext_hdr_and_body_3_recv_len_error)
{
    MOCKER_CPP(&tcp_connection::recv, ssize_t (*)(tcp_connection *, const void *, size_t, int))
        .stubs().will(returnValue(DLOCK_CLIENT_INIT_REQ_BODY_LEN - 1));

    uint8_t *msg_ext_hdr = nullptr;
    uint8_t *msg_body = nullptr;
    int ret = m_server->recv_msg_ext_hdr_and_body(m_conn, 0, DLOCK_CLIENT_INIT_REQ_BODY_LEN, &msg_ext_hdr, &msg_body);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(msg_ext_hdr, nullptr);
    EXPECT_EQ(msg_body, nullptr);
}

TEST_F(test_check_control_msg_hdr, test_magic_no_error)
{
    m_msg_hdr.magic_no = 0xedf7d74a;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_check_control_msg_hdr, test_version_not_support_1)
{
    m_msg_hdr.version = DLOCK_MIN_PROTO_VERSION - 1;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_check_control_msg_hdr, test_version_not_support_2)
{
    m_msg_hdr.version = DLOCK_PROTO_VERSION + 1;
    m_msg_hdr.total_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    m_msg_hdr.type = CLIENT_HEARTBEAT_REQUEST;
    m_msg_hdr.value = 10001;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_check_control_msg_hdr, test_hdr_len_error_1)
{
    m_msg_hdr.hdr_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN - 1;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_check_control_msg_hdr, test_hdr_len_error_2)
{
    m_msg_hdr.version = DLOCK_PROTO_VERSION;
    m_msg_hdr.total_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN;
    m_msg_hdr.type = CLIENT_HEARTBEAT_REQUEST;
    m_msg_hdr.value = 10001;
    m_msg_hdr.hdr_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN - 1;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_check_control_msg_hdr, test_total_len_error_1)
{
    m_msg_hdr.total_len = DLOCK_FIXED_CTRL_MSG_HDR_LEN - 1;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_check_control_msg_hdr, test_total_len_error_2)
{
    m_msg_hdr.total_len = DLOCK_MAX_CTRL_MSG_SIZE + 1;
    int ret = m_server->check_control_msg_hdr(m_msg_hdr);
    EXPECT_EQ(ret, -1);
}

TEST_F(test_create_object_by_msg, test_descriptor_init_failed)
{
    MOCKER_CPP(&dlock_descriptor::descriptor_init, dlock_status_t (*)(unsigned int, unsigned char *))
        .stubs().will(returnValue(DLOCK_ENOMEM));

    object_entry_s *obj_entry = m_server->create_object_by_msg(m_msg_body, m_client_id);
    EXPECT_EQ(obj_entry, nullptr);
    EXPECT_EQ(m_msg_body->obj_id, -static_cast<int>(DLOCK_SERVER_NO_RESOURCE));
}

TEST_F(test_create_object_by_msg, test_find_available_object_id_failed)
{
    MOCKER_CPP(&dlock_server::find_available_object_id, int (*)(int))
        .stubs().will(returnValue(-1));

    object_entry_s *obj_entry = m_server->create_object_by_msg(m_msg_body, m_client_id);
    EXPECT_EQ(obj_entry, nullptr);
    EXPECT_EQ(m_msg_body->obj_id, -static_cast<int>(DLOCK_SERVER_NO_RESOURCE));
}

TEST_F(test_create_object_by_msg, test_object_memory_alloc_failed)
{
    MOCKER_CPP(&object_memory::alloc_object_memory, uint64_t (*)())
        .stubs().will(returnValue(INVALID_OFFSET));

    object_entry_s *obj_entry = m_server->create_object_by_msg(m_msg_body, m_client_id);
    EXPECT_EQ(obj_entry, nullptr);
    EXPECT_EQ(m_msg_body->obj_id, -static_cast<int>(DLOCK_SERVER_NO_RESOURCE));
}

TEST_F(test_create_object_do, test_msg_body_len_invalid)
{
    m_msg_hdr.total_len = 10;

    int ret = m_server->create_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_EINVAL));
}

TEST_F(test_create_object_do, test_descriptor_init_failed)
{
    MOCKER_CPP(&dlock_descriptor::descriptor_init, dlock_status_t (*)(unsigned int, unsigned char *))
        .stubs().will(returnValue(DLOCK_ENOMEM));

    int ret = m_server->create_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_ENOMEM));
}

TEST_F(test_create_object_do, test_client_id_not_found)
{
    m_msg_hdr.client_id = m_client_id + 1;
    int ret = m_server->create_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, static_cast<int>(DLOCK_CLIENT_NOT_INIT));
}

TEST_F(test_create_object_do, test_create_object_by_msg_failed)
{
    MOCKER_CPP(&dlock_server::create_object_by_msg, object_entry_s * (*)(struct object_create_body *, int32_t))
        .stubs().will(returnValue((object_entry_s *)nullptr));

    m_msg_body->obj_id = -1;
    int ret = m_server->create_object_do(nullptr, &m_msg_hdr, (uint8_t *)m_msg_body);
    EXPECT_EQ(ret, -1);
}