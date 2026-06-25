/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <pthread.h>

#include "gtest/gtest.h"

#include "test_netlink.h"

using namespace std;

int32_t g_port = 10010;

int32_t g_connectFd = 0;
int32_t g_connectFd_ipv6 = 0;

#define DATA_LENGTH (2 * 1024 * 1024)

#define INTERFACE_MAX 16
#define MAX_ACCEPT_RETRY_COUNT 100
#define MAX_SPLICE_TIME 3

char g_sendBuff[DATA_LENGTH];

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

    return 0;
}

int32_t ClientConnect_ipv6(int32_t sockfd)
{
    int32_t ret;
    struct sockaddr_in6 servaddr;

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, LOCAL_IPV6, &(servaddr.sin6_addr));
    servaddr.sin6_port = htons(g_port);

    ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if ((ret != 0) && (errno != EINPROGRESS)) {
        cout << "connect to the server for ipv6 failed errno " << errno << endl;
        return -1;
    } else {
        cout << "connect to the server for ipv6 successfully" << endl;
    }

    return 0;
}

int32_t CreateClient_ipv6()
{
    int32_t ret;
    g_connectFd_ipv6 = socket(AF_SMC, SOCK_STREAM, 1);
    if (g_connectFd_ipv6 == -1) {
        cout << "create socket for ipv6 failed" << endl;
        return -1;
    } else {
        cout << "create socket for ipv6 successfully " << g_connectFd_ipv6 << endl;
    }

    ret = SetSocketNonBlock(g_connectFd_ipv6);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

void *cat_ums(void *args)
{
    int32_t ret = system("cat /proc/net/ums");
    if (ret != 0) {
        cout << "exec cmd cat /proc/net/ums error!" << endl;
    }

    ret = system("cat /proc/net/ums6");
    if (ret != 0) {
        cout << "exec cmd cat /proc/net/ums6 error!" << endl;
    }

    return 0;
}

static int test_netlink(pnet_opt *opt)
{
    int ret = 0;
    int id, nlmsg_flags = 0;
    struct nl_sock *sk;
    struct nl_msg *msg;

    sk = nl_socket_alloc();
    if (!sk) {
        perror("create socket error");
        return ret;
    }
    ret = genl_connect(sk);
    if (ret) {
        ret = -1;
        goto free_nl_socket;
    }
    id = genl_ctrl_resolve(sk, SMCR_GENL_FAMILY_NAME);
    if (id < 0) {
        ret = -1;
        if (id == -NLE_OBJ_NOTFOUND) {
            fprintf(stderr, "ums module not loaded\n");
        } else {
            printf("genl ctrl resolve error: %d\n", id);
        }
        goto close_nl;
    }
    nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, cb_handler, NULL);

    msg = nlmsg_alloc();
    if (!msg) {
        printf("nlmsg alloc error\n");
        ret = -1;
        goto close_nl;
    }

    if ((opt->cmd == SMC_PNETID_DEL || opt->cmd == SMC_PNETID_GET) && !opt->pnet_id)
        nlmsg_flags = NLM_F_DUMP;

    if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, id, 0, nlmsg_flags, opt->cmd,
        SMCR_GENL_FAMILY_VERSION)) {
        printf("genlmsg put error\n");
        ret = -1;
        goto free_nlmsg;
    }

    switch (opt->cmd) {
        case SMC_PNETID_ADD:
            if (opt->eth_name)
                ret = nla_put_string(msg, SMC_PNETID_ETHNAME, opt->eth_name);
            if (ret < 0) {
                printf("nla put string error\n");
                ret = -1;
                goto free_nlmsg;
            }

            if (opt->ub_name)
                ret = nla_put_string(msg, SMC_PNETID_IBNAME, opt->ub_name);
            if (ret < 0) {
                printf("nla put string error\n");
                ret = -1;
                goto free_nlmsg;
            }

            if (opt->ub_name)
                ret = nla_put_u8(msg, SMC_PNETID_IBPORT, opt->ub_port);
            if (ret < 0) {
                printf("nla put u8 error\n");
                ret = -1;
                goto free_nlmsg;
            }
        case SMC_PNETID_DEL:
        case SMC_PNETID_GET:
            if (!opt->pnet_id)
                break;
            ret = nla_put_string(msg, SMC_PNETID_NAME, opt->pnet_id);
            if (ret < 0) {
                printf("nla put string error\n");
                ret = -1;
                goto free_nlmsg;
            }
        default:
            printf("Unknown opt cmd.\n");
            break;
    }

    ret = nl_send_auto(sk, msg);
    if (ret < 0) {
        printf("nl send auto error\n");
        ret = -1;
        goto free_nlmsg;
    }

    ret = nl_recvmsgs_default(sk);
    if (opt->cmd == SMC_PNETID_FLUSH && ret != -NLE_OBJ_NOTFOUND)
        ret = 0;
    if (ret < 0) {
        printf("nl recvmsgs error ret: %d\n", ret);
        ret = -1;
        goto free_nlmsg;
    }
    ret = 0;
free_nlmsg:
    nlmsg_free(msg);
close_nl:
    nl_close(sk);
free_nl_socket:
    nl_socket_free(sk);
    return ret;
}

class SocketInterfaceTest : public ::testing::Test {
protected:
    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    void SetUp() override
    {
        int ret = CreateClient();
        EXPECT_TRUE(ret == 0);
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    void TearDown() override
    {
        close(g_connectFd);
    }
};

TEST_F(SocketInterfaceTest, read_and_write_test)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    int32_t set_val = 1;
    int32_t get_val;
    uint32_t opt_len = sizeof(int);
    setsockopt(g_connectFd, IPPROTO_TCP, TCP_NODELAY, (char*)&set_val, sizeof(set_val));
    getsockopt(g_connectFd, IPPROTO_TCP, TCP_NODELAY, &get_val, &opt_len);
    EXPECT_TRUE(set_val == get_val);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    pthread_t tid;
    ret = pthread_create(&tid, NULL, cat_ums, NULL);
    if (ret != 0) {
        cout << "pthread create error: error_code: " << ret << endl;
    }

    usleep(2000000);

    shutdown(g_connectFd, SHUT_WR);
}

TEST_F(SocketInterfaceTest, send_and_recv_test)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ret = send(g_connectFd, g_sendBuff, dataLen, 0);
    cout << "send data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(2000000);
}

TEST_F(SocketInterfaceTest, send_and_recv_test_multi)
{
    int32_t ret;
    size_t dataLen = 1000;
    int32_t connectFd[23];
    struct sockaddr_in servaddr;
 
    bzero(&servaddr, sizeof(servaddr));
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(REMOTE_IP);
    servaddr.sin_port = htons(g_port);
    int32_t nSndBuf = 1024;
    uint32_t opt_len = sizeof(int32_t);
 
    for (int i = 0; i < 23; i++) {
        connectFd[i] = socket(AF_SMC, SOCK_STREAM, 0);
        setsockopt(connectFd[i], SOL_SOCKET, SO_SNDBUF, (const char*)&nSndBuf, opt_len);
        ret = connect(connectFd[i], (struct sockaddr *)&servaddr, sizeof(servaddr));
        if ((ret != 0) && (errno != EINPROGRESS)) {
            cout << "connect to the server failed errno " << errno << endl;
        } else {
            cout << "connect to the server successfully" << endl;
        }
    }
    usleep(1000000);
 
    for (int j = 0; j < 23; j++) {
        for (int k = 0; k < 100; k++) {
            ret = send(connectFd[j], g_sendBuff, dataLen, 0);
            cout << "send data length " << dataLen << " and ret is " << ret << endl;
        }
    }
 
    usleep(2000000);
    for (int m = 0; m < 23; m++) {
        close(connectFd[m]);
    }
}

TEST_F(SocketInterfaceTest, io_multiplex_poll)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(2000000);

    shutdown(g_connectFd, SHUT_RDWR);
}

TEST_F(SocketInterfaceTest, io_multiplex_select)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(2000000);
}

TEST_F(SocketInterfaceTest, io_multiplex_epoll)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(2000000);

    ret = write(g_connectFd, g_sendBuff, dataLen);
    cout << "write data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    usleep(2000000);
}

TEST_F(SocketInterfaceTest, send_file)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    char *filePath = (char *)"./SendFile";
    char cmd[256];

    (void)snprintf(cmd, sizeof(cmd), "dd if=/dev/urandom bs=1k count=1 of=%s", filePath);
    ret = system(cmd);
    if (ret < 0) {
        cout << "create file failed" << endl;
        return;
    }

    int filefd = open(filePath, O_RDONLY, 0);
    if (filefd < 0) {
        cout << "open file failed" << endl;
        return;
    }

    cout << "send file" << dataLen << endl;
    sendfile(g_connectFd, filefd, 0, dataLen);

    usleep(2000000);

    close(filefd);
}

TEST_F(SocketInterfaceTest, send_and_recv_test_ipv6)
{
    int32_t ret;
    size_t dataLen = 1000;

    ret = CreateClient_ipv6();
    EXPECT_TRUE(ret == 0);

    ret = ClientConnect_ipv6(g_connectFd_ipv6);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ret = send(g_connectFd_ipv6, g_sendBuff, dataLen, 0);
    cout << "send data length " << dataLen << " and ret is " << ret << endl;
    EXPECT_TRUE(ret == (int32_t)dataLen);

    pthread_t tid;
    ret = pthread_create(&tid, NULL, cat_ums, NULL);
    if (ret != 0) {
        cout << "pthread create error: error_code: " << ret << endl;
    }

    usleep(2000000);
    close(g_connectFd_ipv6);
}

TEST_F(SocketInterfaceTest, write_multi_msg)
{
    int32_t ret;
    size_t dataLen = 2000;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    for (int i = 0; i < 300; i++) {
        ret = send(g_connectFd, g_sendBuff, dataLen, 0);
        cout << "send data length " << dataLen << " and ret is " << ret << endl;
    }

    sleep(2);
    ret = send(g_connectFd, g_sendBuff, 101, 0);
    cout << "send data length 101 to end the test and ret is " << ret << endl;

    usleep(2000000);

    shutdown(g_connectFd, SHUT_WR);
}

TEST_F(SocketInterfaceTest, ums_splice)
{
    int ret;
    int pipefd[2];
    struct sockaddr_in locAddr;
    struct pollfd pollFds;
    int32_t timeOut = 1000;

    sleep(2);
    close(g_connectFd);
    CreateClient();

    /* config initial sock connect */
    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    /* create a new socket for transfer */
    int tmpRecvFd = socket(AF_SMC, SOCK_STREAM, 0);
    EXPECT_TRUE(tmpRecvFd >= 0);

    ret = SetSocketNonBlock(tmpRecvFd);
    EXPECT_TRUE(ret == 0);

    /* bind and listen */
    locAddr.sin_family = AF_INET;
    locAddr.sin_addr.s_addr = inet_addr(LOCAL_IP);
    locAddr.sin_port = htons(1233);

    ret = bind(tmpRecvFd, (struct sockaddr *)&locAddr, sizeof(locAddr));
    EXPECT_TRUE(ret == 0);

    ret = listen(tmpRecvFd, 5);
    EXPECT_TRUE(ret == 0);
    
    /* accept */
    int32_t tmpAcceptFd;
    uint32_t len;
    struct sockaddr_in client;

    len = sizeof(client);
    for (int i = 0; i < MAX_ACCEPT_RETRY_COUNT; i++) {
        tmpAcceptFd = accept(tmpRecvFd, (struct sockaddr *)&client, &len);
        if (tmpAcceptFd >= 0) {
            break;
        }
        usleep(100000);
    }

    /* create a pipe */
    ret = pipe(pipefd);
    EXPECT_TRUE(ret == 0);

    SetSocketNonBlock(pipefd[0]);
    SetSocketNonBlock(pipefd[1]);

    sleep(2);

    int bs = 1;
    ret = send(g_connectFd, g_sendBuff, bs, 0);

    pollFds.fd = tmpAcceptFd;
    pollFds.events = POLLIN;
    do {
        ret = poll(&pollFds, 1, timeOut);
        if (ret == 0) {
            continue;
        }

        bs = splice(tmpAcceptFd, NULL, pipefd[1], NULL, 100, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if ((bs == MAX_SPLICE_TIME) | (bs == 0)) {
            bs = splice(pipefd[0], NULL, g_connectFd, NULL, bs, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            break;
        }
        bs = splice(pipefd[0], NULL, g_connectFd, NULL, bs, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    } while (1);

    (void)close(pipefd[0]);
    (void)close(pipefd[1]);

    close(tmpAcceptFd);
    close(tmpRecvFd);
}

TEST_F(SocketInterfaceTest, urgent_data_test)
{
    int32_t ret;
    size_t urgentLen = 10;
    size_t endLen = 101;

    close(g_connectFd);
    CreateClient();
    sleep(2);

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    sleep(1);
    ret = send(g_connectFd, g_sendBuff, urgentLen, MSG_OOB);

    sleep(1);
    ret = send(g_connectFd, g_sendBuff, endLen, 0);

    sleep(2);
    shutdown(g_connectFd, SHUT_WR);
}

TEST_F(SocketInterfaceTest, test_closeFd)
{
    int32_t ret;

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    close(g_connectFd);
    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret != 0);
}

TEST_F(SocketInterfaceTest, invalid_ip)
{
    int32_t ret;
    struct sockaddr_in servaddr;

    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("1.2.3.4");
    servaddr.sin_port = htons(g_port);

    ret = connect(g_connectFd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    EXPECT_TRUE(ret != 0);
}

TEST_F(SocketInterfaceTest, test_netlink)
{
    pnet_opt opt = {
        .pnet_id = (char *)"0",
        .eth_name = (char *)"ens1f0np0",
        .ub_name = (char *)"udma_0",
        .ub_port = 1,
        .cmd = SMC_PNETID_ADD,
    };
    (void)test_netlink(&opt);

    opt.cmd = SMC_PNETID_GET;
    (void)test_netlink(&opt);

    opt.cmd = SMC_PNETID_DEL;
    (void)test_netlink(&opt);
}

TEST_F(SocketInterfaceTest, test_client_ioctl)
{
    int32_t ret;
    void *buffer = malloc(10240);
    EXPECT_TRUE(buffer != NULL);

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ioctl(g_connectFd, SIOCINQ, buffer);
    ioctl(g_connectFd, SIOCOUTQ, buffer);
    ioctl(g_connectFd, SIOCOUTQNSD, buffer);
    ioctl(g_connectFd, SIOCATMARK, buffer);

    close(g_connectFd);

    free(buffer);
}

TEST_F(SocketInterfaceTest, test_sockopt)
{
    int32_t set_val = 1;
    int32_t get_val;
    uint32_t opt_len = sizeof(int);

    setsockopt(g_connectFd, SOL_TCP, TCP_CORK, &set_val, sizeof(get_val));
    getsockopt(g_connectFd, SOL_TCP, TCP_CORK, &get_val, &opt_len);
    EXPECT_TRUE(set_val == get_val);

    set_val = 0;
    setsockopt(g_connectFd, SOL_TCP, TCP_CORK, &set_val, sizeof(set_val));
    getsockopt(g_connectFd, SOL_TCP, TCP_CORK, &get_val, &opt_len);
    EXPECT_TRUE(set_val == get_val);

    set_val = 5;
    setsockopt(g_connectFd, SOL_TCP, TCP_FASTOPEN, (char*)&set_val, sizeof(set_val));
    getsockopt(g_connectFd, SOL_TCP, TCP_FASTOPEN, &get_val, &opt_len);
    EXPECT_TRUE(set_val == get_val);
}

TEST_F(SocketInterfaceTest, ipv6_error_handling_invalid_address)
{
    int32_t ret;
    int32_t tempSockFd = socket(AF_SMC, SOCK_STREAM, 1);
    EXPECT_TRUE(tempSockFd >= 0);

    ret = SetSocketNonBlock(tempSockFd);
    EXPECT_TRUE(ret == 0);

    struct sockaddr_in6 servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:db8::1", &(servaddr.sin6_addr));
    servaddr.sin6_port = htons(9999);

    ret = connect(tempSockFd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    EXPECT_TRUE(ret < 0);
    EXPECT_TRUE(errno == EINPROGRESS || errno == ECONNREFUSED || errno == ENETUNREACH);

    close(tempSockFd);
}

TEST_F(SocketInterfaceTest, error_handling_invalid_sockopt)
{
    int32_t ret;
    int32_t invalidOpt = 9999;
    int32_t value = 1;
    socklen_t optLen = sizeof(int);

    ret = setsockopt(g_connectFd, SOL_SOCKET, invalidOpt, &value, sizeof(value));
    EXPECT_TRUE(ret < 0);
    EXPECT_TRUE(errno == EINVAL || errno == ENOPROTOOPT);

    ret = getsockopt(g_connectFd, SOL_SOCKET, invalidOpt, &value, &optLen);
    EXPECT_TRUE(ret < 0);
    EXPECT_TRUE(errno == EINVAL || errno == ENOPROTOOPT);
}

TEST_F(SocketInterfaceTest, timeout_handling_connect_timeout)
{
    int32_t ret;
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    ret = setsockopt(g_connectFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    EXPECT_TRUE(ret == 0);

    ret = setsockopt(g_connectFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    EXPECT_TRUE(ret == 0);
}

TEST_F(SocketInterfaceTest, address_reuse_test)
{
    int32_t ret;
    int32_t reuse = 1;
    int32_t getReuse = 0;
    socklen_t optLen = sizeof(int);

    ret = setsockopt(g_connectFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    EXPECT_TRUE(ret == 0);

    ret = getsockopt(g_connectFd, SOL_SOCKET, SO_REUSEADDR, &getReuse, &optLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(getReuse != 0);
}

TEST_F(SocketInterfaceTest, fcntl_nonblock_flag_test)
{
    int32_t flags;

    flags = fcntl(g_connectFd, F_GETFL, 0);
    EXPECT_TRUE(flags >= 0);
    EXPECT_TRUE((flags & O_NONBLOCK) != 0);
}

TEST_F(SocketInterfaceTest, getpeername_after_connect)
{
    int32_t ret;
    struct sockaddr_in peerAddr;
    socklen_t addrLen = sizeof(peerAddr);

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ret = getpeername(g_connectFd, (struct sockaddr *)&peerAddr, &addrLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(peerAddr.sin_family == AF_INET);
    EXPECT_TRUE(peerAddr.sin_port == htons(g_port));
}

TEST_F(SocketInterfaceTest, so_error_after_nonblock_connect)
{
    int32_t ret;
    int error = 0;
    socklen_t optLen = sizeof(error);

    ret = ClientConnect(g_connectFd);
    EXPECT_TRUE(ret == 0);

    usleep(1000000);

    ret = getsockopt(g_connectFd, SOL_SOCKET, SO_ERROR, &error, &optLen);
    EXPECT_TRUE(ret == 0);
    EXPECT_TRUE(error == 0);
}
