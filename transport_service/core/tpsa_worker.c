/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 * Description: tpsa worker implementation file
 * Author: Chen Wen, Yanfangfang
 * Create: 2023-1-18
 * Note:
 * History: 2023-1-18 port core routines from daemon here
 */

#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/syscall.h>
#include <errno.h>
#include "tpsa_log.h"
#include "tpsa_net.h"
#include "tpsa_worker.h"

#define TPSA_MAX_EPOLL_NUM 2048
#define TPSA_MAX_TCP_CONN 1024
#define TPSA_CM_THREAD_PRIORITY (-20)
#define TPSA_MAX_EPOLL_WAIT 16
#define TPSA_EVENT_MAX_WAIT_MS 10 // 10ms
#define TPSA_SOCK_TIMOUT 10 /* 10s */

static void tpsa_fill_multipath_tp_cfg(tpsa_nl_msg_t *msg)
{
    urma_eid_t src_eid = msg->dst_eid;
    urma_eid_t dst_eid = msg->src_eid;
    tpsa_netaddr_entry_t *src = NULL, *dst = NULL;
    tpsa_nl_create_tp_t *create = (tpsa_nl_create_tp_t *)msg->payload;

    if (tpsa_get_underlay_info(&src_eid, &dst_eid, &src, &dst) != 0) {
        TPSA_LOG_WARN("Failed to look up underlay info");
    } else {
        create->cfg.udp_range = dst->underlay.cfg.udp_range;
        create->cfg.ack_rctp_start = dst->underlay.cfg.ack_rctp_start;
        create->cfg.data_rctp_start = dst->underlay.cfg.data_rctp_start;
        create->cfg.ack_rmtp_start = dst->underlay.cfg.ack_rmtp_start;
        create->cfg.data_rmtp_start = dst->underlay.cfg.data_rmtp_start;
        create->cfg.flag.bs.sr_en = dst->underlay.cfg.flag.bs.sr_en &
            create->cfg.flag.bs.sr_en;
        create->cfg.flag.bs.oor_en = dst->underlay.cfg.flag.bs.oor_en &
            create->cfg.flag.bs.oor_en;
        create->cfg.flag.bs.spray_en = dst->underlay.cfg.flag.bs.spray_en &
            create->cfg.flag.bs.spray_en;
        create->cfg.flag.bs.cc_en = dst->underlay.cfg.flag.bs.cc_en &
            create->cfg.flag.bs.cc_en;
    }
}

static int tpsa_sock_handle_event(tpsa_worker_t *worker, struct epoll_event *ev)
{
    if (!(ev->events & EPOLLIN)) {
        return 0;
    }

    if (ev->data.fd != worker->sock_ctx.listen_fd) {
        tpsa_nl_msg_t msg = { 0 };
        /* Prevent link down up sock small packets from being received multiple times, resulting in exceptions */
        if (tpsa_sock_recv_msg_timeout(ev->data.fd, (char*)&msg, sizeof(tpsa_nl_msg_t),
            TPSA_SOCK_TIMOUT, worker->epollfd) != 0) {
            return -1;
        }
        /* Prevent non-TP connection establishment messages from being forwarded to ubcore */
        if ((msg.msg_type < TPSA_NL_CREATE_TP_REQ && msg.msg_type > TPSA_NL_SET_AGENT_PID)) {
            TPSA_LOG_WARN("An unsupported message type was received.\n");
            return 0;
        }
        /* Local tps and peer tps multipath parameters need to be negotiated */
        if (msg.msg_type == TPSA_NL_CREATE_TP_REQ) {
            tpsa_fill_multipath_tp_cfg(&msg);
        }

        if (tpsa_nl_send_msg(&worker->nl_ctx, &msg) != 0) {
            return -1;
        }
        TPSA_LOG_INFO("[recv_sock_ctx_msg:3]---msg_id: %d, msg_type: %d, transport_type: %d, fd: %d.\n", msg.nlmsg_seq,
            msg.msg_type, msg.transport_type, ev->data.fd);
        return 0;
    }
    if (tpsa_handle_accept_fd(worker->epollfd, &worker->sock_ctx) != 0) {
        return -1;
    }

    return 0;
}

static int tpsa_handle_query_tp_req(tpsa_nl_ctx_t *nl_ctx, tpsa_nl_msg_t *req)
{
    int ret = 0;
    urma_eid_t src_eid = req->src_eid;
    urma_eid_t dst_eid = req->dst_eid;
    tpsa_netaddr_entry_t *src = NULL, *dst = NULL;
    tpsa_nl_msg_t resp;

    resp.payload_len = sizeof(tpsa_nl_query_tp_resp_t);
    resp.hdr.nlmsg_type = resp.msg_type = TPSA_NL_QUERY_TP_RESP;
    resp.hdr.nlmsg_len = tpsa_netlink_msg_len((const tpsa_nl_msg_t *)&resp);
    resp.nlmsg_seq = req->nlmsg_seq;
    resp.transport_type = req->transport_type;
    tpsa_nl_query_tp_resp_t *query_tp_resp = (tpsa_nl_query_tp_resp_t *)resp.payload;

    if (tpsa_get_underlay_info(&src_eid, &dst_eid, &src, &dst) != 0) {
        query_tp_resp->dst_eid = dst_eid;
        query_tp_resp->src_addr.base = src_eid;
        query_tp_resp->dst_addr.base = dst_eid;
        TPSA_LOG_WARN("Failed to look up underlay info");
    } else {
        query_tp_resp->dst_eid =  dst->underlay.eid;
        query_tp_resp->src_addr = src->underlay.netaddr[0];
        query_tp_resp->dst_addr = dst->underlay.netaddr[0];
        query_tp_resp->cfg = dst->underlay.cfg;
    }
    query_tp_resp->tp_exist = false;
    query_tp_resp->tpn = 0;
    query_tp_resp->ret = TPSA_NL_RESP_SUCCESS;

    (void)tpsa_nl_send_msg(nl_ctx, &resp);
    TPSA_LOG_INFO("[Enqueue query tp resp]---msg_id: %d, msg_type: %d, transport_type: %d\n",
        resp.nlmsg_seq, resp.msg_type, resp.transport_type);
    return ret;
}

static int tpsa_handle_nl_msg(tpsa_worker_t *worker, tpsa_nl_msg_t *msg)
{
    return (msg->msg_type == TPSA_NL_QUERY_TP_REQ ? tpsa_handle_query_tp_req(&worker->nl_ctx, msg) :
        tpsa_sock_send_msg(&worker->sock_ctx, msg, sizeof(tpsa_nl_msg_t)));
}

static int tpsa_nl_handle_event(tpsa_worker_t *worker, const struct epoll_event *ev)
{
    if (!(ev->events & EPOLLIN)) {
        return 0;
    }

    tpsa_nl_msg_t msg = { 0 };
    ssize_t recv_len = tpsa_nl_recv_msg(&worker->nl_ctx, &msg, sizeof(tpsa_nl_msg_t), worker->epollfd);
    if (recv_len < 0) {
        TPSA_LOG_ERR("Recv len is zero, event 0x%x fd = %d.\n", ev->events, ev->data.fd);
        return -1;
    }
    TPSA_LOG_INFO("[recv_nl_msg:1]---msg_id: %d, msg_type: %d, transport_type: %d.\n", msg.nlmsg_seq,
        msg.msg_type, msg.transport_type);

    if (tpsa_handle_nl_msg(worker, &msg) != 0) {
        return -1;
    }

    return 0;
}

static void *tpsa_thread_main(void *arg)
{
    tpsa_worker_t *worker = (tpsa_worker_t *)arg;
    if (worker == NULL) {
        TPSA_LOG_ERR("Invalid parameter.\n");
        return NULL;
    }

    (void)pthread_setname_np(pthread_self(), (const char *)"tpsa_server_thread");
    pid_t tid = (pid_t)syscall(SYS_gettid);
    if (setpriority(PRIO_PROCESS, (id_t)tid, TPSA_CM_THREAD_PRIORITY) != 0) {
        TPSA_LOG_ERR("set priority failed: %s.\n", ub_strerror(errno));
        return NULL;
    }

    struct epoll_event events[TPSA_MAX_EPOLL_WAIT];
    while (worker->stop == false) {
        int num_events = epoll_wait(worker->epollfd, events, TPSA_MAX_EPOLL_WAIT, TPSA_EVENT_MAX_WAIT_MS);
        if (num_events == -1) {
            continue;
        }
        for (int i = 0; i < num_events; i++) {
            if ((events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
                TPSA_LOG_ERR("Exception event 0x%x fd = %d.\n", events[i].events, events[i].data.fd);
                (void)epoll_ctl(worker->epollfd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                (void)close(events[i].data.fd);
                continue;
            }
            /* An abnormal event causes err, but the daemon service does not exit */
            if (events[i].data.fd == worker->nl_ctx.fd && tpsa_nl_handle_event(worker, &events[i]) != 0) {
                TPSA_LOG_ERR("Failed to handle nl event.\n");
            }
            if (events[i].data.fd != worker->nl_ctx.fd && tpsa_sock_handle_event(worker, &events[i]) != 0) {
                TPSA_LOG_ERR("Failed to handle sock event\n");
            }
        }
    }
    return NULL;
}

static int tpsa_worker_thread_init(tpsa_worker_t *worker)
{
    int ret;
    pthread_attr_t attr;
    int epollfd;

    epollfd = epoll_create(TPSA_MAX_EPOLL_NUM);
    if (epollfd < 0) {
        TPSA_LOG_ERR("Failed to create epoll fd, nl->epollfd: %d, err: %s.\n",
            epollfd, ub_strerror(errno));
        return -1;
    }

    if (tpsa_add_epoll_event(epollfd, worker->sock_ctx.listen_fd, EPOLLIN) != 0) {
        TPSA_LOG_ERR("Add epoll event failed.\n");
        (void)close(epollfd);
        return -1;
    }

    ret = listen(worker->sock_ctx.listen_fd, TPSA_MAX_TCP_CONN);
    if (ret < 0) {
        TPSA_LOG_ERR("Server socket listen failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
        return -1;
    }

    if (tpsa_add_epoll_event(epollfd, worker->nl_ctx.fd, EPOLLIN) != 0) {
        TPSA_LOG_ERR("Add epoll event failed.\n");
        (void)close(epollfd);
        return -1;
    }

    (void)pthread_attr_init(&attr);
    worker->stop = false;
    worker->epollfd = epollfd;
    ret = pthread_create(&worker->thread, &attr, tpsa_thread_main, worker);
    if (ret < 0) {
        TPSA_LOG_ERR("pthread create failed. ret: %d, err: [%d]%s.\n", ret, errno, ub_strerror(errno));
    }
    (void)pthread_attr_destroy(&attr);
    TPSA_LOG_INFO("thread listen (ep_fd=%d, ADD, nl_fd=%d, sock_listen_fd=%d) succeed.\n",
        epollfd, worker->nl_ctx.fd, worker->sock_ctx.listen_fd);
    return ret;
}

static void tpsa_worker_thread_uninit(tpsa_worker_t *worker)
{
    worker->stop = true;
    (void)pthread_join(worker->thread, NULL);
    if (worker->epollfd >= 0 && close(worker->epollfd) != 0) {
        TPSA_LOG_ERR("Failed to close epoll fd, epollfd: %d, err: %s.\n", worker->epollfd, ub_strerror(errno));
    }
}

tpsa_worker_t *tpsa_worker_init(void)
{
    tpsa_worker_t *worker = calloc(1, sizeof(tpsa_worker_t));
    if (worker == NULL) {
        TPSA_LOG_ERR("Failed to create tpsa worker.\n");
        return NULL;
    }

    if (tpsa_sock_server_init(&worker->sock_ctx) != 0) {
        goto free_work;
    }
    if (tpsa_nl_server_init(&worker->nl_ctx) != 0) {
        goto free_sock_server;
    }
    if (tpsa_worker_thread_init(worker) != 0) {
        goto free_nl_server;
    }
    return worker;

free_nl_server:
    tpsa_nl_server_uninit(&worker->nl_ctx);
free_sock_server:
    tpsa_sock_server_uninit(&worker->sock_ctx);
free_work:
    free(worker);
    return NULL;
}

void tpsa_worker_unint(tpsa_worker_t *worker)
{
    if (worker == NULL) {
        return;
    }
    tpsa_worker_thread_uninit(worker);
    tpsa_nl_server_uninit(&worker->nl_ctx);
    tpsa_sock_server_uninit(&worker->sock_ctx);
    free(worker);
}