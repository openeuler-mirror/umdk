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
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <linux/netlink.h>

#include "gtest/gtest.h"

using namespace std;

int32_t g_port = 10010;

int32_t g_listenFd = 0;
int32_t g_listenFd_ipv6 = 0;
int32_t g_urgentFd = 0;

#define DATA_LENGTH (2 * 1024 * 1024)

#define INTERFACE_MAX 16
#define MAX_ACCEPT_RETRY_COUNT 100
#define MAX_SPLICE_TIME 3

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

    for (int i = 0; i < MAX_ACCEPT_RETRY_COUNT; i++) {
        acceptFd = accept(sockfd, (struct sockaddr *)&client, &len);
        if (acceptFd >= 0) {
            break;
        }
        usleep(100000);
    }

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

    int32_t time = 1;
    int32_t val;
    uint32_t opt_len = sizeof(int);
    setsockopt(g_listenFd, IPPROTO_TCP, TCP_DEFER_ACCEPT, (char*)&time, sizeof(time));
    getsockopt(g_listenFd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, &opt_len);
    if (time != val) {
        cout << "fail to set DEFER_ACCEPT to " << val << endl;
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

int32_t CreateServer_ipv6(bool nonBlock)
{
    int32_t ret;
    int32_t reuse = 1;
    struct sockaddr_in6 servaddr;

    g_listenFd_ipv6 = socket(AF_SMC, SOCK_STREAM, 1);
    if (g_listenFd_ipv6 == -1) {
        cout << "create socket for ipv6 failed" << endl;
        return -1;
    } else {
        cout << "create listen socket for ipv6 successfully " << g_listenFd_ipv6 << endl;
        bzero(&servaddr, sizeof(servaddr));
    }

    if (nonBlock) {
        ret = SetSocketNonBlock(g_listenFd_ipv6);
        if (ret != 0) {
            cout << "set no block for ipv6 socket failed" << endl;
        }
    }

    ret = SetSocketReuse(g_listenFd_ipv6, &reuse);
    if (ret != 0) {
        cout << "set reuse for ipv6 socket failed" << endl;
    }

    servaddr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, LOCAL_IPV6, &(servaddr.sin6_addr));
    servaddr.sin6_port = htons(g_port);

    int32_t time = 1;
    int32_t val;
    uint32_t opt_len = sizeof(int);
    setsockopt(g_listenFd_ipv6, IPPROTO_TCP, TCP_DEFER_ACCEPT, (char*)&time, sizeof(time));
    getsockopt(g_listenFd_ipv6, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, &opt_len);
    if (time != val) {
        cout << "fail to set DEFER_ACCEPT to " << val << endl;
        return -1;
    }

    if ((bind(g_listenFd_ipv6, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        cout << "ipv6 socket bind failed errno " << errno << endl;
        return -1;
    } else {
        cout << "ipv6 socket bind successfully" << endl;
    }

    if ((listen(g_listenFd_ipv6, 5)) != 0) {
        cout << "listen for ipv6 socket failed" << endl;
        return -1;
    } else {
        cout << "listen for ipv6 socket successfully" << endl;
    }

    return 0;
}

void urg_handler(int sig)
{
    int dataLen = 100;
    recv(g_urgentFd, g_recvBuff, dataLen, MSG_OOB);
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
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    void TearDown() override
    {
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

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);

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

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);

    ret = recv(acceptFd, g_recvBuff, dataLen, 0);
    cout << "recv data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, send_and_recv_test_multi)
{
    int32_t acceptFd[23];
    int32_t ret;
    size_t dataLen = 1000;
    uint32_t len;
    struct sockaddr_in client;

    len = sizeof(client);

    for (int k = 0; k < 23; k++) {
        for (int i = 0; i < MAX_ACCEPT_RETRY_COUNT; i++) {
            acceptFd[k] = accept(g_listenFd, (struct sockaddr *)&client, &len);
            if (acceptFd[k] >= 0) {
                break;
            }
            usleep(100000);
        }
        if (acceptFd[k] < 0) {
            cout << "accept failed errno " << errno << endl;
        } else {
            cout << "accept successfully" << endl;
        }
    }

    usleep(1000000);

    for (int j = 0; j < 23; j++) {
        ret = recv(acceptFd[j], g_recvBuff, dataLen, 0);
        cout << "recv data length expect " << dataLen << " and ret is " << ret << endl;
    }

    for (int m = 0; m < 23; m++) {
        close(acceptFd[m]);
    }  
}

TEST_F(SocketInterfaceTest, io_multiplex_poll)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 1000;
    struct pollfd pollFds;
    int32_t timeOut = 1000;

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

    usleep(1000000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, io_multiplex_select)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 1000;
    int32_t nfds;
    fd_set readFds;
    struct timeval tv;

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

    usleep(1000000);

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
    size_t dataLen = 1000;

    int32_t epollFd = epoll_create(10);

    (void)memset(&event, 0, sizeof(event));
    event.data.fd = g_listenFd;
    event.events = EPOLLIN;
    ret = epoll_ctl(epollFd, EPOLL_CTL_ADD, g_listenFd, &event);

    usleep(1000000);

    (void)memset(&event, 0, sizeof(event));
    ret = epoll_wait(epollFd, &event, 1, timeOut);
    EXPECT_TRUE(ret > 0);
    EXPECT_TRUE(event.events & EPOLLIN);
    cout << "epoll ret " << ret << " event " << event.events << " fd " << event.data.fd << endl;

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
    close(epollFd);

    usleep(1000000);
}

TEST_F(SocketInterfaceTest, send_file)
{
    int32_t acceptFd;
    size_t dataLen = 1000;

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);

    int32_t ret = read(acceptFd, g_recvBuff, dataLen);
    cout << "read data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}

TEST_F(SocketInterfaceTest, send_and_recv_test_ipv6)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 1000;

    ret = CreateServer_ipv6(true);
    EXPECT_TRUE(ret == 0);

    acceptFd = ServerAccept(g_listenFd_ipv6);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);

    ret = recv(acceptFd, g_recvBuff, dataLen, 0);
    cout << "recv data length expect " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
    close(g_listenFd_ipv6);
}

TEST_F(SocketInterfaceTest, write_multi_msg)
{
    int32_t acceptFd;
    struct pollfd pollFds;
    int32_t timeOut = 1000;
    int ret;

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    pollFds.fd = acceptFd;
    pollFds.events = POLLIN;
    do {
        ret = poll(&pollFds, 1, timeOut);
        if (ret == 0) {
            continue;
        }
        ret = recv(acceptFd, g_recvBuff, 1000, 0);
        if (ret == 101 || ret == 0) {
            break;
        }
    } while (true);

    usleep(2000000);
    close(acceptFd);
}

TEST_F(SocketInterfaceTest, ums_splice)
{
    int ret = 0;
    struct pollfd pollFds;
    int32_t timeOut = 1000;
    char sendBuff[DATA_LENGTH];
    struct sockaddr_in remAddr;

    close(g_listenFd);
    CreateServer(true);

    int acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    ret = SetSocketNonBlock(acceptFd);
    EXPECT_TRUE(ret == 0);

    /* create a temp sender */
    int tmpSendFd = socket(AF_SMC, SOCK_STREAM, 0);
    EXPECT_TRUE(tmpSendFd >= 0);

    remAddr.sin_family = AF_INET;
    remAddr.sin_addr.s_addr = inet_addr(REMOTE_IP);
    remAddr.sin_port = htons(1233);

    ret = SetSocketNonBlock(tmpSendFd);
    EXPECT_TRUE(ret == 0);

    sleep(2);

    ret = connect(tmpSendFd, (struct sockaddr *)&remAddr, sizeof(remAddr));
    if ((ret != 0) && (errno != EINPROGRESS) ) {
        printf("tmp sender fail to connect to server\n");
        EXPECT_TRUE(0); 
    }

    sleep(1);
    pollFds.fd = acceptFd;
    pollFds.events = POLLIN;
    do {
        ret = poll(&pollFds, 1, timeOut);
        if (ret == 0) {
            continue;
        }
        ret = recv(acceptFd, g_recvBuff, 1000, 0);

        if (ret == MAX_SPLICE_TIME || ret == 0) {
            break;
        }
        send(tmpSendFd, sendBuff, ++ret, 0);
    } while(true);

    close(acceptFd);
    close(tmpSendFd);
}

TEST_F(SocketInterfaceTest, urgent_data_test)
{
    struct pollfd pollFds;
    int32_t timeOut = 1000;
    size_t dataLen = 1000;
    int endLen = 101;
    int ret;

    close(g_listenFd);
    CreateServer(true);

    g_urgentFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(g_urgentFd >= 0);

    ret = SetSocketNonBlock(g_urgentFd);
    EXPECT_TRUE(ret == 0);

    fcntl(g_urgentFd, F_SETOWN, getpid());
    signal(SIGURG, urg_handler);

    pollFds.fd = g_urgentFd;
    pollFds.events = POLLIN;
    do {
        ret = poll(&pollFds, 1, timeOut);
        if (ret == 0) {
            continue;
        }

        ret = recv(g_urgentFd, g_recvBuff, dataLen, 0);
        if (ret == endLen || ret == 0) {
            break;
        }
    } while (1);

    sleep(2);
    close(g_urgentFd);
}

TEST_F(SocketInterfaceTest, test_closeFd)
{
    int32_t acceptFd;

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);
    close(acceptFd);
}

TEST_F(SocketInterfaceTest, test_ulp_init)
{
    int sockfd;
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        cout << "create socket failed in ulp test" << endl;
    } else {
        cout << "create socket successfully in ulp test " << sockfd << endl;
    }
    ret = setsockopt(sockfd, SOL_TCP, TCP_ULP, "ums", sizeof("ums"));
    if (ret != 0) {
        cout << "setsockopt failed in ulp test " << endl;
    }
    usleep(1000000);
    close(sockfd);
}

TEST_F(SocketInterfaceTest, error_handling_bind_port_in_use)
{
    int32_t ret;
    int32_t reuse = 0;
    int32_t tempSockFd = socket(AF_SMC, SOCK_STREAM, 0);
    EXPECT_TRUE(tempSockFd >= 0);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    servaddr.sin_port = htons(g_port);

    ret = setsockopt(tempSockFd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    EXPECT_TRUE(ret == 0);

    ret = bind(tempSockFd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    EXPECT_TRUE(ret < 0);
    EXPECT_TRUE(errno == EADDRINUSE);

    close(tempSockFd);
}

TEST_F(SocketInterfaceTest, boundary_listen_queue_full)
{
    int32_t ret;
    int32_t tempSockFd = socket(AF_SMC, SOCK_STREAM, 0);
    EXPECT_TRUE(tempSockFd >= 0);

    int32_t reuse = 1;
    ret = setsockopt(tempSockFd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    EXPECT_TRUE(ret == 0);

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    servaddr.sin_port = htons(g_port + 1);

    ret = bind(tempSockFd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    EXPECT_TRUE(ret == 0);

    ret = listen(tempSockFd, 1);
    EXPECT_TRUE(ret == 0);

    const int CLIENT_NUM = 3;
    int32_t clientFds[CLIENT_NUM];
    struct sockaddr_in clientServaddr;
    bzero(&clientServaddr, sizeof(clientServaddr));
    clientServaddr.sin_family = AF_INET;
    clientServaddr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    clientServaddr.sin_port = htons(g_port + 1);

    for (int i = 0; i < CLIENT_NUM; i++) {
        clientFds[i] = socket(AF_SMC, SOCK_STREAM, 0);
        SetSocketNonBlock(clientFds[i]);
        connect(clientFds[i], (struct sockaddr *)&clientServaddr, sizeof(clientServaddr));
    }

    usleep(100000);

    for (int i = 0; i < CLIENT_NUM; i++) {
        if (clientFds[i] >= 0) {
            close(clientFds[i]);
        }
    }

    close(tempSockFd);
}

TEST_F(SocketInterfaceTest, multi_client_connection_test)
{
    const int MAX_CLIENTS = 5;
    int32_t acceptFd[MAX_CLIENTS];
    int32_t clientFd[MAX_CLIENTS];
    int32_t ret;

    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    servaddr.sin_port = htons(g_port);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clientFd[i] = socket(AF_SMC, SOCK_STREAM, 0);
        EXPECT_TRUE(clientFd[i] >= 0);
        SetSocketNonBlock(clientFd[i]);
        ret = connect(clientFd[i], (struct sockaddr *)&servaddr, sizeof(servaddr));
        EXPECT_TRUE(ret == 0 || errno == EINPROGRESS);
    }

    usleep(100000);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        acceptFd[i] = ServerAccept(g_listenFd);
        EXPECT_TRUE(acceptFd[i] >= 0);
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (acceptFd[i] >= 0) {
            close(acceptFd[i]);
        }
        if (clientFd[i] >= 0) {
            close(clientFd[i]);
        }
    }
}

TEST_F(SocketInterfaceTest, socket_option_tcp_keepalive)
{
    int32_t ret;
    int enable = 1;
    int value = 0;
    socklen_t optLen = sizeof(int);

    ret = setsockopt(g_listenFd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
    EXPECT_TRUE(ret == 0);

    ret = getsockopt(g_listenFd, SOL_SOCKET, SO_KEEPALIVE, &value, &optLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(value == enable);

    int keepidle = 30;
    int keepintvl = 5;
    int keepcnt = 3;

    ret = setsockopt(g_listenFd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    EXPECT_TRUE(ret == 0);

    ret = setsockopt(g_listenFd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    EXPECT_TRUE(ret == 0);

    ret = setsockopt(g_listenFd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    EXPECT_TRUE(ret == 0);
}

TEST_F(SocketInterfaceTest, ipv6_boundary_listen_ipv6_address)
{
    int32_t ret;
    int32_t tempSockFd = socket(AF_SMC, SOCK_STREAM, 1);
    EXPECT_TRUE(tempSockFd >= 0);

    int32_t reuse = 1;
    ret = setsockopt(tempSockFd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    EXPECT_TRUE(ret == 0);

    struct sockaddr_in6 servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin6_family = AF_INET6;
    servaddr.sin6_addr = in6addr_any;
    servaddr.sin6_port = htons(g_port + 2);

    ret = bind(tempSockFd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    EXPECT_TRUE(ret == 0);

    ret = listen(tempSockFd, 5);
    EXPECT_TRUE(ret == 0);

    close(tempSockFd);
}

TEST_F(SocketInterfaceTest, server_getsockopt_acceptconn)
{
    int32_t ret;
    int acceptConn = 0;
    socklen_t optLen = sizeof(int);

    ret = getsockopt(g_listenFd, SOL_SOCKET, SO_ACCEPTCONN, &acceptConn, &optLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(acceptConn != 0);
}

TEST_F(SocketInterfaceTest, bidirectional_transfer_test)
{
    int32_t acceptFd;
    int32_t ret;
    size_t dataLen = 512;

    acceptFd = ServerAccept(g_listenFd);
    EXPECT_TRUE(acceptFd >= 0);

    usleep(1000000);

    ret = read(acceptFd, g_recvBuff, dataLen);
    EXPECT_TRUE(ret == (int32_t)dataLen);

    ret = write(acceptFd, g_recvBuff, dataLen);
    EXPECT_TRUE(ret == (int32_t)dataLen);

    close(acceptFd);
}
