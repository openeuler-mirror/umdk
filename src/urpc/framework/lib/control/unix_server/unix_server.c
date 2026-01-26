/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc unix domain server for inter-process communication
 * Create: 2024-4-22
 */

#include <dirent.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <limits.h>

#include "cp.h"
#include "ip_handshaker.h"
#include "urpc_dbuf_stat.h"
#include "urpc_epoll.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_list.h"
#include "urpc_manage.h"
#include "urpc_socket.h"

#include "unix_server.h"

#define MAX_IPC_CTL_BUF_LEN (1UL << 28)
#define URPC_UNIX_SOCKET_NAME_PREFIX "urpc.sock."

typedef struct unix_server_cmd_node {
    struct urpc_list list;
    urpc_ipc_cmd_t cmd;
} unix_server_cmd_node_t;

static struct {
    int fd;
    struct sockaddr_un addr;
    urpc_epoll_event_t *lev;
} g_urpc_unix_server = {
    .fd = -1,
};

static struct {
    pthread_mutex_t lock;
    struct urpc_list cmds[URPC_IPC_MODULE_MAX];
} g_urpc_unix_server_cmds = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static inline bool is_unix_server_initialized(void)
{
    return g_urpc_unix_server.fd >= 0;
}

static void unix_server_cmds_init(void)
{
    for (int i = 0; i < (int)URPC_IPC_MODULE_MAX; i++) {
        urpc_list_init(&g_urpc_unix_server_cmds.cmds[i]);
    }
}

static void unix_server_cmds_uninit(void)
{
    unix_server_cmd_node_t *node, *next;

    for (int i = 0; i < (int)URPC_IPC_MODULE_MAX; i++) {
        URPC_LIST_FOR_EACH_SAFE(node, next, list, &g_urpc_unix_server_cmds.cmds[i])
        {
            urpc_list_remove(&node->list);
            urpc_dbuf_free(node);
        }
    }
}

static int unix_server_cmd_get(uint16_t module_id, uint16_t cmd_id, urpc_ipc_cmd_t *cmd)
{
    if (module_id >= URPC_IPC_MODULE_MAX) {
        return URPC_FAIL;
    }

    unix_server_cmd_node_t *node;
    (void)pthread_mutex_lock(&g_urpc_unix_server_cmds.lock);
    URPC_LIST_FOR_EACH(node, list, &g_urpc_unix_server_cmds.cmds[module_id])
    {
        if (node->cmd.cmd_id == cmd_id) {
            *cmd = node->cmd;
            (void)pthread_mutex_unlock(&g_urpc_unix_server_cmds.lock);
            return URPC_SUCCESS;
        }
    }

    (void)pthread_mutex_unlock(&g_urpc_unix_server_cmds.lock);
    return URPC_FAIL;
}

static int unix_server_cmd_register(urpc_ipc_cmd_t *cmd)
{
    if (cmd->module_id >= (uint16_t)URPC_IPC_MODULE_MAX) {
        URPC_LIB_LOG_ERR("invalid module id %hu\n", cmd->module_id);
        return URPC_FAIL;
    }

    urpc_ipc_cmd_t target_cmd;
    if (unix_server_cmd_get(cmd->module_id, cmd->cmd_id, &target_cmd) == URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("ipc cmd already registered, module_id %hu, cmd_id %hu\n", cmd->module_id, cmd->cmd_id);
        return URPC_FAIL;
    }

    unix_server_cmd_node_t *node = (unix_server_cmd_node_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX,
        sizeof(unix_server_cmd_node_t));
    if (node == NULL) {
        URPC_LIB_LOG_ERR("malloc ipc cmd node, module_id %hu, cmd_id %hu\n", cmd->module_id, cmd->cmd_id);
        return URPC_FAIL;
    }
    node->cmd = *cmd;

    (void)pthread_mutex_lock(&g_urpc_unix_server_cmds.lock);
    urpc_list_push_back(&g_urpc_unix_server_cmds.cmds[cmd->module_id], &node->list);
    (void)pthread_mutex_unlock(&g_urpc_unix_server_cmds.lock);

    return URPC_SUCCESS;
}

static void unix_server_cmd_unregister(urpc_ipc_cmd_t *cmd)
{
    if (cmd->module_id >= URPC_IPC_MODULE_MAX) {
        return;
    }

    unix_server_cmd_node_t *node, *next;
    (void)pthread_mutex_lock(&g_urpc_unix_server_cmds.lock);
    URPC_LIST_FOR_EACH_SAFE(node, next, list, &g_urpc_unix_server_cmds.cmds[cmd->module_id])
    {
        if (node->cmd.cmd_id == cmd->cmd_id) {
            urpc_list_remove(&node->list);
            (void)pthread_mutex_unlock(&g_urpc_unix_server_cmds.lock);

            urpc_dbuf_free(node);
            return;
        }
    }

    (void)pthread_mutex_unlock(&g_urpc_unix_server_cmds.lock);
}

int unix_server_cmds_register(urpc_ipc_cmd_t *cmd, int num)
{
    int i;

    if (!is_unix_server_initialized()) {
        return URPC_FAIL;
    }

    for (i = 0; i < num; i++) {
        if (unix_server_cmd_register(&cmd[i]) != URPC_SUCCESS) {
            break;
        }
    }

    if (i == num) {
        return URPC_SUCCESS;
    }

    for (int j = 0; j < i; j++) {
        unix_server_cmd_unregister(&cmd[j]);
    }

    return URPC_FAIL;
}

void unix_server_cmds_unregister(urpc_ipc_cmd_t *cmd, int num)
{
    if (!is_unix_server_initialized()) {
        return;
    }

    for (int i = 0; i < num; i++) {
        unix_server_cmd_unregister(&cmd[i]);
    }
}

int unix_ipc_ctl_recv(int fd, urpc_ipc_ctl_head_t *ipc_ctl, char **out_data)
{
    if (urpc_socket_recv(fd, ipc_ctl, sizeof(urpc_ipc_ctl_head_t)) != sizeof(urpc_ipc_ctl_head_t)) {
        return URPC_FAIL;
    }

    if (ipc_ctl->data_size > MAX_IPC_CTL_BUF_LEN) {
        return URPC_FAIL;
    }

    if (ipc_ctl->data_size == 0) {
        return URPC_SUCCESS;
    }

    char *data = urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, ipc_ctl->data_size);
    if (data == NULL) {
        return URPC_FAIL;
    }

    if (urpc_socket_recv(fd, data, ipc_ctl->data_size) != ipc_ctl->data_size) {
        urpc_dbuf_free(data);
        return URPC_FAIL;
    }

    *out_data = data;

    return URPC_SUCCESS;
}

int unix_ipc_ctl_send(int fd, urpc_ipc_ctl_head_t *ipc_ctl, char *in_data)
{
    if (urpc_socket_send(fd, ipc_ctl, sizeof(urpc_ipc_ctl_head_t)) != sizeof(urpc_ipc_ctl_head_t)) {
        return URPC_FAIL;
    }

    if (ipc_ctl->data_size == 0) {
        return URPC_SUCCESS;
    }

    if (urpc_socket_send(fd, in_data, ipc_ctl->data_size) != ipc_ctl->data_size) {
        return URPC_FAIL;
    }

    return URPC_SUCCESS;
}

static inline bool reply_need_free(urpc_ipc_cmd_t *cmd)
{
    return cmd->reply_malloced;
}

static void unix_server_event_process(uint32_t events, struct urpc_epoll_event *e)
{
    if ((events & ((uint32_t)EPOLLERR | EPOLLHUP)) != 0) {
        return;
    }

    int cli_fd = accept(e->fd, NULL, NULL);
    if (cli_fd < 0) {
        return;
    }

    struct timeval tv = {0};
    tv.tv_sec = UNIX_SERVER_RECV_IMTEOUT_S;
    if (setsockopt(cli_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        URPC_LIB_LOG_ERR("set socket timeout opt failed\n");
        goto EXIT;
    }

    urpc_ipc_ctl_head_t req_ctl = {0};
    char *request = NULL;
    if (unix_ipc_ctl_recv(cli_fd, &req_ctl, &request) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("recv ipc request failed, %s\n", strerror(errno));
        goto EXIT;
    }

    urpc_ipc_cmd_t cmd;
    if (unix_server_cmd_get(req_ctl.module_id, req_ctl.cmd_id, &cmd) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("lookup ipc cmd failed, module_id %hu, cmd_id %hu\n", req_ctl.module_id, req_ctl.cmd_id);
        goto FREE_REQUEST;
    }

    char *reply = NULL;
    urpc_ipc_ctl_head_t rsp_ctl = {
        .module_id = req_ctl.module_id, .cmd_id = req_ctl.cmd_id, .error_code = 0, .data_size = 0};
    cmd.func(&req_ctl, request, &rsp_ctl, &reply);

    if (unix_ipc_ctl_send(cli_fd, &rsp_ctl, reply) != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("send ipc reply failed, module_id %hu, cmd_id %hu, %s\n", rsp_ctl.module_id, rsp_ctl.cmd_id,
            strerror(errno));
    }

    if (reply_need_free(&cmd)) {
        urpc_dbuf_free(reply);
    }

FREE_REQUEST:
    urpc_dbuf_free(request);

EXIT:
    (void)close(cli_fd);
}

// unix_domain_file_path must not NULL, and buf len is at least PATH_MAX + 1 to ensure realpath in buf not overflow
int file_path_get(char *buf, size_t len, const char *unix_domain_file_path)
{
    struct stat s = {0};
    size_t file_path_len = strnlen(unix_domain_file_path, PATH_MAX);
    // ensure file path is not empty and with '\0'
    if (file_path_len == 0 || file_path_len == PATH_MAX) {
        return -1;
    }

    if (realpath(unix_domain_file_path, buf) == NULL) {
        return -1;
    }

    if (lstat(buf, &s) != 0) {
        return -1;
    }

    if (!S_ISDIR(s.st_mode)) {
        return -1;
    }

    return 0;
}

static int unix_server_socket_file_clean(const char *dir)
{
    int ret;
    char buf[PATH_MAX + 1];
    DIR *dp = NULL;
    struct dirent *entry = NULL;

    dp = opendir(dir);
    if (dp == NULL) {
        URPC_LIB_LOG_ERR("open dir %s failed, %s\n", dir, strerror(errno));
        return URPC_FAIL;
    }

    // unlink old socket file
    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type != DT_SOCK) {
            continue;
        }
        // find correct socket file name
        if (strstr(entry->d_name, URPC_UNIX_SOCKET_NAME_PREFIX) != entry->d_name) {
            continue;
        }
        ret = snprintf(buf, PATH_MAX + 1, "%s/%s", dir, entry->d_name);
        if (ret < 0) {
            URPC_LIB_LOG_ERR("format unix domain socket file name %s/%s failed, ret %d\n", dir, entry->d_name, ret);
            continue;
        }
        if (unlink(buf) != 0) {
            URPC_LIB_LOG_WARN("clear unix domain socket file %s failed, %s\n", buf, strerror(errno));
        }
    }

    (void)closedir(dp);

    return URPC_SUCCESS;
}

int unix_server_init(const char *unix_domain_file_path)
{
    unix_server_cmds_init();

    int ret;
    g_urpc_unix_server.addr.sun_family = AF_UNIX;
    char buf[PATH_MAX + 1] = {0};
    if (file_path_get(buf, PATH_MAX + 1, unix_domain_file_path) != 0) {
        URPC_LIB_LOG_ERR("check unix domain file path %s failed\n", unix_domain_file_path);
        return URPC_FAIL;
    }

    ret = snprintf(g_urpc_unix_server.addr.sun_path, sizeof(g_urpc_unix_server.addr.sun_path),
        "%s/" URPC_UNIX_SOCKET_NAME_PREFIX "%u", buf, (uint32_t)getpid());
    if (ret < 0) {
        URPC_LIB_LOG_ERR("copy unix domain socket name failed, error %d\n", ret);
        return URPC_FAIL;
    }

    if (unix_server_socket_file_clean(unix_domain_file_path) != URPC_SUCCESS) {
        return URPC_FAIL;
    }

    g_urpc_unix_server.fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_urpc_unix_server.fd < 0) {
        URPC_LIB_LOG_ERR("create unix domain socket failed, %s\n", strerror(errno));
        return URPC_FAIL;
    }

    if (fchmod(g_urpc_unix_server.fd, S_IRUSR | S_IWUSR) == -1) {
        URPC_LIB_LOG_ERR("set unix domain socket permission failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    if (bind(g_urpc_unix_server.fd, (struct sockaddr *)&g_urpc_unix_server.addr, sizeof(struct sockaddr_un)) < 0) {
        URPC_LIB_LOG_ERR("bind unix domain socket failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    if (listen(g_urpc_unix_server.fd, 1) < 0) {
        URPC_LIB_LOG_ERR("listen unix domain socket failed, %s\n", strerror(errno));
        goto CLOSE_FD;
    }

    g_urpc_unix_server.lev =
        (urpc_epoll_event_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_DFX, sizeof(urpc_epoll_event_t));
    if (g_urpc_unix_server.lev == NULL) {
        URPC_LIB_LOG_ERR("malloc epoll event failed\n");
        goto CLOSE_FD;
    }
    g_urpc_unix_server.lev->fd = g_urpc_unix_server.fd;
    g_urpc_unix_server.lev->args = NULL;
    g_urpc_unix_server.lev->func = unix_server_event_process;
    g_urpc_unix_server.lev->events = EPOLLIN;
    g_urpc_unix_server.lev->is_handshaker_ctx = false;
    if (urpc_mange_event_register(URPC_MANAGE_JOB_TYPE_LISTEN, g_urpc_unix_server.lev) != URPC_SUCCESS) {
        goto FREE_EPOLL_EVENT;
    }

    return URPC_SUCCESS;

FREE_EPOLL_EVENT:
    urpc_dbuf_free(g_urpc_unix_server.lev);
    g_urpc_unix_server.lev = NULL;

CLOSE_FD:
    (void)close(g_urpc_unix_server.fd);
    g_urpc_unix_server.fd = -1;

    return URPC_FAIL;
}

void unix_server_uninit(void)
{
    if (!is_unix_server_initialized()) {
        return;
    }

    (void)urpc_mange_event_unregister(URPC_MANAGE_JOB_TYPE_LISTEN, g_urpc_unix_server.lev);
    urpc_dbuf_free(g_urpc_unix_server.lev);
    g_urpc_unix_server.lev = NULL;

    if (shutdown(g_urpc_unix_server.fd, SHUT_RDWR) != 0) {
        URPC_LIB_LOG_ERR("shutdown unix domain server failed, %s\n", strerror(errno));
    }
    (void)close(g_urpc_unix_server.fd);
    g_urpc_unix_server.fd = -1;

    (void)unlink(g_urpc_unix_server.addr.sun_path);

    unix_server_cmds_uninit();
}
