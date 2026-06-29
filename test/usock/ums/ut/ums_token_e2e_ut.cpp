/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * End-to-end coverage for the out-of-band UB token_value exchange.
 *
 * During the UMS CLC handshake (triggered by connect()/accept() on AF_SMC), the
 * kmod submits jetty/seg token_values to the local ums_agent, which proxies them
 * over TLS to the peer agent, which delivers the peer token_values back to its
 * kmod (ums_nl.c TOKEN_DELIVER). A successful full-duplex data round-trip is the
 * integration signal that the token exchange on BOTH ends completed.
 *
 * Prerequisites (same two-host flow as ums_test_ut_server/client via
 * script/ut_cov.sh):
 *   - ums.ko loaded with ub_token_mode=SECURE
 *   - ums_agent running on BOTH hosts with mutually-trusted TLS certs
 *   - LOCAL_IP / REMOTE_IP supplied at build time
 *
 * This file intentionally mirrors the helper layout of ums_test_ut.cpp so it can
 * be wired into the same server/client split if a dedicated role is needed.
 */

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;

#define TOKEN_E2E_PORT      10030
#define TOKEN_E2E_DATA_LEN  1024
#define RECV_BUF_KIB        2048
#define WAIT_READABLE_MAX_RETRIES 3

static int32_t g_listenFd = -1;
static int32_t g_connectFd = -1;
static char g_sendBuff[TOKEN_E2E_DATA_LEN];
static char g_recvBuff[TOKEN_E2E_DATA_LEN];

static int32_t SetNonBlock(int32_t fd)
{
    int32_t flag = fcntl(fd, F_GETFL, 0);
    if (flag < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, (unsigned int)flag | O_NONBLOCK) < 0 ? -1 : 0;
}

static int32_t SetReuse(int32_t fd)
{
    int32_t reuse = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
}

static int32_t CreateServer(void)
{
    g_listenFd = socket(AF_SMC, SOCK_STREAM, 0);
    if (g_listenFd < 0) {
        return -1;
    }
    SetReuse(g_listenFd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    addr.sin_port = htons(TOKEN_E2E_PORT);

    if (bind(g_listenFd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        return -1;
    }
    if (listen(g_listenFd, 5) != 0) {
        return -1;
    }
    return 0;
}

static int32_t CreateClient(void)
{
    g_connectFd = socket(AF_SMC, SOCK_STREAM, 0);
    if (g_connectFd < 0) {
        return -1;
    }
    int32_t sndBuf = 4096;
    setsockopt(g_connectFd, SOL_SOCKET, SO_SNDBUF, &sndBuf, sizeof(sndBuf));
    return SetNonBlock(g_connectFd);
}

static int32_t ClientConnect(void)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(REMOTE_IP);
    addr.sin_port = htons(TOKEN_E2E_PORT);

    int32_t ret = connect(g_connectFd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret != 0 && errno != EINPROGRESS) {
        return -1;
    }
    return 0;
}

static int32_t ServerAccept(void)
{
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    int32_t fd = accept(g_listenFd, (struct sockaddr *)&client, &len);
    return fd;
}

/* Waits for the listen socket to become readable (incoming CLC/TCP connect). */
static int WaitForReadable(int32_t fd, int32_t timeoutMs)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    int32_t ret;
    int32_t retry_cnts = 0;
    do {
        ret = poll(&pfd, 1, timeoutMs);
    } while ((ret == 0) && ((++retry_cnts) < WAIT_READABLE_MAX_RETRIES));
    return ret;
}

class TokenExchangeE2E : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_EQ(CreateServer(), 0);
        ASSERT_EQ(CreateClient(), 0);
        for (int i = 0; i < TOKEN_E2E_DATA_LEN; i++) {
            g_sendBuff[i] = (char)(i & 0x7f);
        }
    }
    void TearDown() override
    {
        if (g_connectFd >= 0) {
            shutdown(g_connectFd, SHUT_RDWR);
            close(g_connectFd);
            g_connectFd = -1;
        }
        if (g_listenFd >= 0) {
            shutdown(g_listenFd, SHUT_RDWR);
            close(g_listenFd);
            g_listenFd = -1;
        }
    }
};

/*
 * Full CLC handshake including the out-of-band token_value exchange on both
 * ends, followed by a data round-trip. Success implies:
 *   - kmod register_clc_session / submit_tokens / wait_token_xchg completed
 *   - both ums_agent peers delivered peer token_values via TOKEN_DELIVER
 *   - ums_rmb_import_seg wired peer_seg_token in SECURE mode
 */
TEST_F(TokenExchangeE2E, ConnectAcceptAndDataExchange)
{
    ASSERT_EQ(ClientConnect(), 0);

    ASSERT_GT(WaitForReadable(g_listenFd, 5000), 0);

    int32_t acceptFd = ServerAccept();
    ASSERT_GE(acceptFd, 0);

    int32_t wr = (int32_t)write(g_connectFd, g_sendBuff, TOKEN_E2E_DATA_LEN);
    ASSERT_EQ(wr, (int32_t)TOKEN_E2E_DATA_LEN);

    usleep(200000);

    int32_t rd = (int32_t)read(acceptFd, g_recvBuff, TOKEN_E2E_DATA_LEN);
    ASSERT_EQ(rd, (int32_t)TOKEN_E2E_DATA_LEN);
    ASSERT_EQ(memcmp(g_sendBuff, g_recvBuff, TOKEN_E2E_DATA_LEN), 0);

    close(acceptFd);
}

/*
 * Reverse-direction round-trip (server -> client) to exercise producer/consumer
 * cursor flow over the token-imported RMB after the exchange.
 */
TEST_F(TokenExchangeE2E, ReverseDirectionDataExchange)
{
    ASSERT_EQ(ClientConnect(), 0);
    ASSERT_GT(WaitForReadable(g_listenFd, 5000), 0);

    int32_t acceptFd = ServerAccept();
    ASSERT_GE(acceptFd, 0);

    int32_t wr = (int32_t)write(acceptFd, g_sendBuff, TOKEN_E2E_DATA_LEN);
    ASSERT_EQ(wr, (int32_t)TOKEN_E2E_DATA_LEN);

    usleep(200000);

    int32_t rd = (int32_t)read(g_connectFd, g_recvBuff, TOKEN_E2E_DATA_LEN);
    ASSERT_EQ(rd, (int32_t)TOKEN_E2E_DATA_LEN);
    ASSERT_EQ(memcmp(g_sendBuff, g_recvBuff, TOKEN_E2E_DATA_LEN), 0);

    close(acceptFd);
}
