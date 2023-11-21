/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa socket service endpoint header file
 * Author: Ji Lei
 * Create: 2023-06-15
 * Note:
 * History: 2023-06-15 Ji lei Initial version
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <pthread.h>
#include "tpsa_log.h"
#include "tpservice_cfg.h"
#include "vport_table_cfg.h"
#include "sip_table_cfg.h"
#include "dip_table_cfg.h"
#include "live_migrate_table_cfg.h"
#include "global_cfg.h"
#include "tpsa_service.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_TPSA_SOCK           "/var/run/tpsa/tpsa.sock"
#define DEFAULT_TPSA_SOCK_DIR       "/var/run/tpsa/"
#define MAX_CONNECTIONS             64
#define TPSA_MAX_SOCKET_EVENTS      32
#define MS_PER_SEC                  1000
#define DEFAULT_TPSA_SOCK_FILE_PARM 0750

int g_tpsa_server_socket = -1;
static bool g_tpsa_server_running;
static tpsa_process_request g_tpsa_process_request_funcs[COMMAND_TYPE_MAX] = {
    [TPSA_SERVICE_SHOW] = process_tpservice_show,
    [VPORT_TABLE_SHOW] = process_vport_table_show,
    [VPORT_TABLE_ADD] = process_vport_table_add,
    [VPORT_TABLE_DEL] = process_vport_table_del,
    [LIVE_MIGRATE_TABLE_SHOW] = process_live_migrate_table_show,
    [LIVE_MIGRATE_TABLE_ADD] = process_live_migrate_table_add,
    [LIVE_MIGRATE_TABLE_DEL] = process_live_migrate_table_del,
    [SIP_TABLE_SHOW] = process_sip_table_show,
    [SIP_TABLE_ADD] = process_sip_table_add,
    [SIP_TABLE_DEL] = process_sip_table_del,
    [DIP_TABLE_SHOW] = process_dip_table_show,
    [DIP_TABLE_ADD] = process_dip_table_add,
    [DIP_TABLE_DEL] = process_dip_table_del,
    [DIP_TABLE_MODIFY] = process_dip_table_modify,
    [VPORT_TABLE_SHOW_UEID] = process_vport_table_show_ueid,
    [VPORT_TABLE_ADD_UEID] = process_vport_table_add_ueid,
    [VPORT_TABLE_DEL_UEID] = process_vport_table_del_ueid,
    [VPORT_TABLE_SET_UPI] = process_vport_table_set_upi,
    [VPORT_TABLE_SHOW_UPI] = process_vport_table_show_upi,
    [GLOBAL_CFG_SHOW] = process_global_cfg_show,
    [GLOBAL_CFG_SET] = process_global_cfg_set,
};

static int tpsa_server_socket_create()
{
    struct sockaddr_un un;
    int fd;
    int ret;

    /* if socket path not exist create it */
    errno = 0;
    if (access(DEFAULT_TPSA_SOCK_DIR, F_OK)) {
        if (errno != ENOENT) {
            TPSA_LOG_ERR("access %s failed %s\n", DEFAULT_TPSA_SOCK_DIR, ub_strerror(errno));
            return errno;
        }
        if (mkdir(DEFAULT_TPSA_SOCK_DIR, DEFAULT_TPSA_SOCK_FILE_PARM) == -1) {
            TPSA_LOG_ERR("thrift server mkdir sock[%s] failed %s.", DEFAULT_TPSA_SOCK_DIR, ub_strerror(errno));
            return errno;
        }
    }
    /* if socket path has exist unlink it */
    if (!access(DEFAULT_TPSA_SOCK, F_OK)) {
        (void)unlink(DEFAULT_TPSA_SOCK);
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        TPSA_LOG_ERR("socket init failed %s\n", ub_strerror(errno));
        return errno;
    }

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, DEFAULT_TPSA_SOCK);

    ret = bind(fd, (struct sockaddr *)&un, sizeof(un));
    if (ret < 0) {
        TPSA_LOG_ERR("socket bind failed %s\n", ub_strerror(errno));
        (void)close(fd);
        return errno;
    }

    ret = listen(fd, MAX_CONNECTIONS);
    if (ret < 0) {
        TPSA_LOG_ERR("socket listen failed %s\n", ub_strerror(errno));
        (void)close(fd);
        return errno;
    }

    g_tpsa_server_socket = fd;
    return 0;
}

static void tpsa_server_socket_destroy()
{
    if (g_tpsa_server_socket >= 0) {
        (void)close(g_tpsa_server_socket);
        g_tpsa_server_socket = -1;

        if (!access(DEFAULT_TPSA_SOCK_DIR, F_OK)) {
            if (!access(DEFAULT_TPSA_SOCK, F_OK)) {
                (void)unlink(DEFAULT_TPSA_SOCK);
                TPSA_LOG_INFO("tpsa sock file clean\n");
            }
            (void)rmdir(DEFAULT_TPSA_SOCK_DIR);
        }
    }
}

static int tpsa_server_epoll_init()
{
    int epfd;
    struct epoll_event event;

    epfd = epoll_create(1);
    if (epfd == -1) {
        TPSA_LOG_ERR("Failed to create epoll %s\n", ub_strerror(errno));
        return -1;
    }
    event.events  = EPOLLIN;
    event.data.fd = g_tpsa_server_socket;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, g_tpsa_server_socket, &event)) {
        TPSA_LOG_ERR("Failed to add tpsa socket to epoll %s\n", ub_strerror(errno));
        (void)close(epfd);
        return -1;
    }
    return epfd;
}

static int accept_new_conn(void)
{
    struct sockaddr_un addr = {0};
    int connfd;
    socklen_t addrlen;

    addrlen = (socklen_t)sizeof(struct sockaddr_un);
    connfd = accept(g_tpsa_server_socket, (struct sockaddr *)&addr, &addrlen);
    if (connfd < 0) {
        TPSA_LOG_ERR("Failed to accept request on socket %d%s\n", g_tpsa_server_socket,
            ub_strerror(errno));
        return -errno;
    }

    return connfd;
}

static ssize_t read_req(int fd, char *buf)
{
    ssize_t len;

    len = recv(fd, buf, MAX_MSG_LEN, MSG_NOSIGNAL);
    if (len < 0 || len >= MAX_MSG_LEN) {
        TPSA_LOG_ERR("Failed to read request on socket %d%s\n", g_tpsa_server_socket,
            ub_strerror(errno));
        return -1;
    }

    return len;
}

static void send_rsp(int fd, tpsa_response_t *rsp)
{
    if (send(fd, rsp, sizeof(tpsa_response_t) + rsp->rsp_len, MSG_NOSIGNAL) < 0) {
        TPSA_LOG_ERR("Failed send msg to rsp type %d, %s", rsp->cmd_type, ub_strerror(errno));
        return;
    }
}

static void service_main_process_request()
{
    int connfd;
    char buf[MAX_MSG_LEN] = {0};
    ssize_t read_len;
    tpsa_request_t *req = NULL;
    tpsa_response_t *rsp = NULL;
    tpsa_process_request cb;

    connfd = accept_new_conn();
    if (connfd < 0) {
        TPSA_LOG_ERR("Failed to accept request on socket %d%s\n", g_tpsa_server_socket,
            ub_strerror(errno));
        return;
    }

    read_len = read_req(connfd, buf);
    if (read_len <= 0) {
        TPSA_LOG_ERR("no msg read from fd");
        (void)close(connfd);
        return;
    }

    req = (struct tpsa_request *)buf;
    /* rsp alloc inside cb, we need free it */
    if (req->cmd_type < COMMAND_TYPE_MAX) {
        cb = g_tpsa_process_request_funcs[req->cmd_type];
        rsp = cb(req, read_len);
    }

    if (rsp == NULL) {
        (void)close(connfd);
        return;
    }

    send_rsp(connfd, rsp);

    free(rsp);
    (void)close(connfd);
}

void *tpsa_server_run(void *args)
{
    int ret, epfd, n, i;
    struct epoll_event events[TPSA_MAX_SOCKET_EVENTS];

    /* thrift server init */
    TPSA_LOG_INFO("server init start\n");

    ret = tpsa_server_socket_create();
    if (ret) {
        TPSA_LOG_ERR("server socket create failed\n");
        return NULL;
    }

    epfd = tpsa_server_epoll_init();
    if (epfd == -1) {
        TPSA_LOG_ERR("server epoll create failed\n");
        tpsa_server_socket_destroy();
        return NULL;
    }

    (void)pthread_setname_np(pthread_self(), (const char *)"tpsa_service");
    g_tpsa_server_running = true;

    while (g_tpsa_server_running) {
        n = epoll_wait(epfd, events, TPSA_MAX_SOCKET_EVENTS, MS_PER_SEC);
        for (i = 0; i < n; i++) {
            if ((events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
                TPSA_LOG_ERR("Exception event 0x%x fd = %d.\n", events[i].events, events[i].data.fd);
                (void)epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                (void)close(events[i].data.fd);
                continue;
            }
            if (events[i].data.fd == g_tpsa_server_socket && (events[i].events & EPOLLIN)) {
                service_main_process_request();
            }
        }
    }

    (void)close(epfd);
    tpsa_server_socket_destroy();
    TPSA_LOG_INFO("server exited\n");
    return NULL;
}

static pthread_t g_tpsa_service_thread = 0;

int tpsa_socket_service_init(void)
{
    int ret = pthread_create(&g_tpsa_service_thread, NULL, tpsa_server_run, NULL);
    if (ret != 0) {
        TPSA_LOG_ERR("Failed to create tpsa thrift service endpoint thread.\n");
    }
    return ret;
}

void tpsa_socket_service_uninit(void)
{
    g_tpsa_server_running = false;

    if (g_tpsa_service_thread > 0) {
        (void)pthread_join(g_tpsa_service_thread, NULL);
    }
}

#ifdef __cplusplus
}
#endif

