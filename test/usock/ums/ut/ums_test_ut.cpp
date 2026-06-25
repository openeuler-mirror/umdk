/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <string>
#include <atomic>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include "gtest/gtest.h"

using namespace std;

int32_t g_port = 10010;

int32_t g_listenFd = 0;

int32_t g_connectFd = 0;

#define DATA_LENGTH 10240

#define INTERFACE_MAX 16

char g_sendBuff[DATA_LENGTH];
char g_recvBuff[DATA_LENGTH];

int32_t SetSocketNonBlock(int32_t fd)
{
    int32_t flag;

    flag = fcntl(fd, F_GETFL, 0);
    if (flag < 0) {
        cout << "fcntl GETFL error" << endl;
        return -1;
    }

    if (fcntl(fd, F_SETFL, (unsigned int)flag | O_NONBLOCK) < 0) {
        cout << "fcntl SETFL error" << endl;
        return -1;
    }

    return 0;
}

int32_t ServerAccept(int32_t sockfd)
{
    int32_t acceptFd;
    uint32_t len;
    struct sockaddr_in client;

    len = sizeof(client);

    acceptFd = accept(sockfd, (struct sockaddr *)&client, &len);
    if (acceptFd < 0) {
        cout << "accept failed errno " << errno << endl;
        return -1;
    } else {
        cout << "accept successfully" << endl;
    }

    return acceptFd;
}

static int32_t SetSocketReuse(int32_t socketFd, int32_t *reuse)
{
    if (setsockopt(socketFd, SOL_SOCKET, SO_REUSEPORT, reuse, sizeof(int32_t)) != 0) {
        return -1;
    }

    return 0;
}

int32_t CreateServer(bool nonBlock)
{
    int32_t ret;
    int32_t reuse = 1;
    struct sockaddr_in servaddr;

    g_listenFd = socket(AF_SMC, SOCK_STREAM, 0);
    if (g_listenFd == -1) {
        cout << "create socket failed" << endl;
        return -1;
    } else {
        cout << "create listen socket successfully " << g_listenFd << endl;
        bzero(&servaddr, sizeof(servaddr));
    }

    if (nonBlock) {
        ret = SetSocketNonBlock(g_listenFd);
        if (ret != 0) {
            cout << "set no block failed" << endl;
        }
    }

    ret = SetSocketReuse(g_listenFd, &reuse);
    if (ret != 0) {
        cout << "set reuse failed" << endl;
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    servaddr.sin_port = htons(g_port);

    int32_t nRcvBuf = 2048;
    int32_t val;
    uint32_t opt_len = sizeof(int);
    setsockopt(g_listenFd, SOL_SOCKET, SO_RCVBUF, (const char*)&nRcvBuf, opt_len);
    getsockopt(g_listenFd, SOL_SOCKET, SO_RCVBUF, &val, &opt_len);
    if (2 * nRcvBuf != val) {
        cout << "fail to set recvbuf to " << val << endl;
        return -1;
    }

    if ((bind(g_listenFd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        cout << "bind failed errno " << errno << endl;
        return -1;
    } else {
        cout << "bind successfully" << endl;
    }

    if ((listen(g_listenFd, 5)) != 0) {
        cout << "listen failed" << endl;
        return -1;
    } else {
        cout << "listen successfully" << endl;
    }

    return 0;
}

int32_t ClientConnect(int32_t sockfd)
{
    int32_t ret;
    struct sockaddr_in servaddr;

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(REMOTE_IP);
    servaddr.sin_port = htons(g_port);

    ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if ((ret != 0) && (errno != EINPROGRESS)) {
        cout << "connect to the server failed errno " << errno << endl;
        return -1;
    } else {
        cout << "connect to the server successfully" << endl;
    }

    return 0;
}

int32_t CreateClient()
{
    int32_t ret;
    g_connectFd = socket(AF_SMC, SOCK_STREAM, 0);
    if (g_connectFd == -1) {
        cout << "create socket failed" << endl;
        return -1;
    } else {
        cout << "create socket successfully " << g_connectFd << endl;
    }

    ret = SetSocketNonBlock(g_connectFd);
    if (ret != 0) {
        return ret;
    }

    int32_t nSndBuf = 4096;
    int32_t val;
    uint32_t opt_len = sizeof(int32_t);
    setsockopt(g_connectFd, SOL_SOCKET, SO_SNDBUF, (const char*)&nSndBuf, opt_len);
    getsockopt(g_connectFd, SOL_SOCKET, SO_SNDBUF, &val, &opt_len);
    if (2 * nSndBuf != val) {
        cout << "fail to set sendbuf to " << val << endl;
        return -1;
    }

    return 0;
}


class SocketInterfaceTest : public ::testing::Test {
protected:
    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    void SetUp() override
    {
        int ret = CreateServer(true);
        EXPECT_TRUE(ret == 0);

        ret = CreateClient();
        EXPECT_TRUE(ret == 0);
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    void TearDown() override
    {
        shutdown(g_connectFd, SHUT_WR);
        close(g_connectFd);

        shutdown(g_listenFd, SHUT_RDWR);
        close(g_listenFd);
    }
};

TEST_F(SocketInterfaceTest, read_and_write_test)
{
    close(g_listenFd);
    int ret = CreateServer(false);
    EXPECT_TRUE(ret == 0);

    int32_t acceptFd;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(100000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, send_and_recv_test)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = send(g_connectFd, g_sendBuff, dataLen, 0);
    cout << "send data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(100000);

    ret = recv(acceptFd, g_recvBuff, dataLen, 0);
    cout << "recv data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, io_multiplex_poll)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 2000;
    struct pollfd pollFds;
    int32_t timeOut = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    pollFds.fd = g_listenFd;
    pollFds.events = POLLIN;
    do {
        ret = poll(&pollFds, 1, timeOut);
        EXPECT_TRUE(ret >= 0);
        cout << "listenfd " << g_listenFd << endl;
        cout << "poll ret " << ret << endl;
    } while (ret == 0);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(100000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, io_multiplex_select)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 2000;
    int32_t nfds;
    fd_set readFds;
    struct timeval tv;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    do {
        nfds = g_listenFd + 1;
        FD_ZERO(&readFds);

        FD_SET(g_listenFd, &readFds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        ret = select(nfds, &readFds, NULL, NULL, &tv);
        EXPECT_TRUE(ret >= 0);
        cout << "listenfd " << g_listenFd << endl;
        cout << "nfds " << nfds <<" select ret " << ret << endl;
    } while (ret == 0);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(100000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, io_multiplex_epoll)
{
    int32_t acceptFd;
    int32_t ret;
    struct epoll_event event;
    int32_t timeOut = 1000;
    size_t dataLen = 2000;

    int32_t epollFd = epoll_create(10);

    (void)memset(&event, 0, sizeof(event));
    event.data.fd = g_listenFd;
    event.events = EPOLLIN;
    ret = epoll_ctl(epollFd, EPOLL_CTL_ADD, g_listenFd, &event);

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    (void)memset(&event, 0, sizeof(event));
    ret = epoll_wait(epollFd, &event, 1, timeOut);
    EXPECT_TRUE(ret > 0);
    EXPECT_TRUE(event.events & EPOLLIN);
    cout << "epoll ret " << ret << " event " << event.events << " fd " << event.data.fd << endl;

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(100000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
    close(epollFd);
}

TEST_F(SocketInterfaceTest, error_handling_connect_failure)
{
    int32_t ret;
    int32_t tempSockFd = socket(AF_SMC, SOCK_STREAM, 0);
    EXPECT_TRUE(tempSockFd >= 0);

    ret = SetSocketNonBlock(tempSockFd);
    EXPECT_TRUE(ret == 0);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("192.0.2.1");
    servaddr.sin_port = htons(9999);

    ret = connect(tempSockFd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    EXPECT_TRUE(ret < 0);
    EXPECT_TRUE(errno == EINPROGRESS || errno == ECONNREFUSED);

    close(tempSockFd);
}

TEST_F(SocketInterfaceTest, boundary_zero_byte_transfer)
{
    int32_t acceptFd;
    int32_t ret;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = write(g_connectFd, g_sendBuff, 0);
    EXPECT_TRUE(ret == 0);

    ret = read(acceptFd, g_recvBuff, 0);
    EXPECT_TRUE(ret == 0);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, boundary_partial_read_write)
{
    int32_t acceptFd;
    int32_t ret;
    size_t totalLen = DATA_LENGTH;
    size_t chunkLen = 2000;
    size_t received = 0;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    for (size_t offset = 0; offset < totalLen; offset += chunkLen) {
        size_t sendLen = (totalLen - offset < chunkLen) ? (totalLen - offset) : chunkLen;
        ret = write(g_connectFd, g_sendBuff + offset, sendLen);
        EXPECT_TRUE(ret == (int32_t)sendLen);
    }

    usleep(200000);

    while (received < totalLen) {
        size_t toRead = (totalLen - received < chunkLen) ? (totalLen - received) : chunkLen;
        ret = read(acceptFd, g_recvBuff + received, toRead);
        EXPECT_TRUE(ret > 0);
        received += (size_t)ret;
    }
    EXPECT_TRUE(received == totalLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, socket_option_tcp_nodelay)
{
    int32_t ret;
    int enable = 1;
    int value = 0;
    socklen_t optLen = sizeof(int);

    ret = setsockopt(g_connectFd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
    EXPECT_TRUE(ret == 0);

    ret = getsockopt(g_connectFd, IPPROTO_TCP, TCP_NODELAY, &value, &optLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(value == enable);
}

TEST_F(SocketInterfaceTest, half_close_test)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = shutdown(g_connectFd, SHUT_WR);
    EXPECT_TRUE(ret == 0);

    ret = read(acceptFd, g_recvBuff, dataLen);
    EXPECT_TRUE(ret == 0);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, getsockname_and_getpeername)
{
    int32_t acceptFd;
    int32_t ret;
    struct sockaddr_in localAddr;
    struct sockaddr_in peerAddr;
    socklen_t addrLen;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(100000);

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    addrLen = sizeof(localAddr);
    ret = getsockname(g_connectFd, (struct sockaddr *)&localAddr, &addrLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(localAddr.sin_family == AF_INET);

    addrLen = sizeof(peerAddr);
    ret = getpeername(g_connectFd, (struct sockaddr *)&peerAddr, &addrLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(peerAddr.sin_port == htons(g_port));

    ret = send(g_connectFd, g_sendBuff, 100, 0);
    EXPECT_TRUE(ret == 100);

    usleep(100000);

    ret = recv(acceptFd, g_recvBuff, 100, MSG_PEEK);
    EXPECT_TRUE(ret == 100);

    ret = recv(acceptFd, g_recvBuff, 100, 0);
    EXPECT_TRUE(ret == 100);

    close(acceptFd);
}