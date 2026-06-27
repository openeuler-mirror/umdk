/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <asm/ioctls.h>

#include <linux/ctype.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/rcupdate_wait.h>
#include <linux/sched/signal.h>
#include <linux/socket.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>

#include "ums_dim.h"
#include "ums_pnet.h"
#include "ums_tx.h"
#include "ums_llc.h"
#include "ums_accept.h"
#include "ums_connect.h"
#include "ums_close.h"
#include "ums_ubcore.h"
#include "ums_mod.h"
#include "ums_listen.h"
#include "ums_clc.h"

/* token exchange netlink layer kmod UT (see ums_token_kmod_test.c) */
extern void ums_token_kmod_test_run(void);

#define UMS_TEST_SNDBUF_DEFAULT_SIZE (1 * 1024 * 1024) /* 1MB by default */
#define UMS_TEST_RCVBUF_DEFAULT_SIZE (1 * 1024 * 1024) /* 1MB by default */
#define UMS_TEST_AUTOCORKING_DEFAULT_SIZE ((UMS_TEST_SNDBUF_DEFAULT_SIZE) >> 1)
#define UMS_TEST_CDC_TX_PUSHING 10
#define SOCK_ADDR_SA_FAMILY_LEN_NORMAL 16
#define SOCK_ADDR_SA_FAMILY_LEN_ABNORMAL 1
#define UMS_TEST_KERNEL_CONNECT_FLAGS 2
#define UMS_TEST_TX_WQ_LEN 4
#define UMS_TEST_DEL_LLC_LINK_NUM 100

struct socket *socket;
struct ums_sock *ums;

static void ums_test_close_abort(void)
{
    struct ums_connection *conn = kzalloc(sizeof(*conn), GFP_KERNEL);
    if (!conn)
        return;
    atomic_set(&conn->cdc_tx_pushing, UMS_TEST_CDC_TX_PUSHING);
    atomic_set(&conn->conn_tx_rx_refcnt, 1);
    ums_close_abort(conn);

    if (conn)
        kfree(conn);
}

static int ums_test_create_sock(void)
{
    int rc;
    rc = sock_create(AF_SMC, SOCK_STREAM, 0, &socket);
    if (rc < 0) {
        pr_err("sock create failed in ut.");
        return rc;
    }
    ums = ums_sk(socket->sk);
    if (!ums) {
        pr_err("get ums failed in ut test");
        return -1;
    }

    ums->use_fallback = false; /* assume ub capability first */
    ums->fallback_rsn = 0;
    ums->limit_ums_hs = 0; /* disable limit_ums_hs by default */
    ums->autocorking_size = UMS_TEST_AUTOCORKING_DEFAULT_SIZE;
    ums->ums_buf_type = 0;
    ums->listen_ums = NULL;
    ums->clcsock = NULL;
    init_rwsem(&ums->clcsock_release_lock);

    pr_info("create ums socket success in ut test,sk state is %d", socket->sk->sk_state);
    return 0;
}

/* Test function ums_llc_flow_parallel */
static void ums_test_llc_flow_start(void)
{
    struct ums_link link;
    struct ums_llc_flow flow;
    struct ums_link_group *lgr = kzalloc(sizeof(*lgr), GFP_KERNEL);
    if (!lgr)
        return;
    struct ums_llc_qentry *qentry = kzalloc(sizeof(*qentry), GFP_KERNEL);
    if (!qentry) {
        goto free_lgr;
    }
    u8 id[UMS_LGR_ID_SIZE] = {0};

    qentry->msg.raw.hdr.common.llc_type = UMS_LLC_DELETE_LINK;
    qentry->link = &link;
    link.lgr = lgr;
    lgr->role = UMS_CLNT;
    lgr->delayed_event = NULL;
    flow.type = UMS_LLC_ADD_LINK;
    (void)memcpy(lgr->id, id, UMS_LGR_ID_SIZE);

    /* The first scenario:when the pointer lgr->delayed_event is null */
    ums_llc_flow_start(&flow, qentry);

    /* test other llc type */
    flow.type = UMS_LLC_FLOW_NONE;
    qentry->msg.raw.hdr.common.llc_type = UMS_LLC_ADD_LINK;
    ums_llc_flow_start(&flow, qentry);

    flow.type = UMS_LLC_FLOW_NONE;
    qentry->msg.raw.hdr.common.llc_type = UMS_LLC_TEST_LINK;
    ums_llc_flow_start(&flow, qentry);

    if (qentry)
        kfree(qentry);
free_lgr:
    if (lgr)
        kfree(lgr);
}

static void ums_test_sock_accept(void)
{
    socket->sk->sk_state = (unsigned char)UMS_ACTIVE;
    ums_accept(socket, NULL, 0, 0);
}

/* Test function ums_connect_check_sk_state */
static void ums_test_check_sk_state(void)
{
    struct sockaddr addr;
    addr.sa_family = AF_INET;
    socket->state = SS_UNCONNECTED;

    /* test for ums_connect_check_sk_state */
    socket->sk->sk_state = (unsigned char)UMS_ACTIVE;
    ums_connect(socket, &addr, SOCK_ADDR_SA_FAMILY_LEN_NORMAL, UMS_TEST_KERNEL_CONNECT_FLAGS);

    socket->sk->sk_state = (unsigned char)UMS_LISTEN;
    ums_connect(socket, &addr, SOCK_ADDR_SA_FAMILY_LEN_NORMAL, UMS_TEST_KERNEL_CONNECT_FLAGS);

    socket->sk->sk_state = (unsigned char)UMS_CLOSED;
    ums_connect(socket, &addr, SOCK_ADDR_SA_FAMILY_LEN_NORMAL, UMS_TEST_KERNEL_CONNECT_FLAGS);

    /* when alen is less than sizeof(addr->sa_family) */
    ums_connect(socket, &addr, SOCK_ADDR_SA_FAMILY_LEN_ABNORMAL, UMS_TEST_KERNEL_CONNECT_FLAGS);

    /* when sa_faimly is AF_UNIX */
    addr.sa_family = AF_UNIX;
    ums_connect(socket, &addr, SOCK_ADDR_SA_FAMILY_LEN_NORMAL, UMS_TEST_KERNEL_CONNECT_FLAGS);

    /* Test for ums_connect_check_sk_state */
    socket->state = SS_FREE;
    ums_connect(socket, &addr, SOCK_ADDR_SA_FAMILY_LEN_NORMAL, UMS_TEST_KERNEL_CONNECT_FLAGS);
}

static void ums_test_close_passive_work(struct work_struct *work)
{
    return;
}

void ums_test_tx_work(struct work_struct *work)
{
    return;
}

static void ums_test_close_active(void)
{
    struct workqueue_struct *workqueue_test;
    struct workqueue_struct *tx_wq;
    struct sock *sk = &ums->sk;

    sk->sk_state = UMS_ACTIVE;
    ums->clcsock = NULL;
    ums->listen_ums = NULL;
    init_rwsem(&ums->clcsock_release_lock);
    workqueue_test = alloc_workqueue("workqueue_test", 0, 0);
    tx_wq = alloc_workqueue("ums_tx_wq-%*phN", 0, 0, UMS_TEST_TX_WQ_LEN, 0);
    INIT_WORK(&ums->conn.close_work, ums_test_close_passive_work);
    INIT_DELAYED_WORK(&ums->conn.tx_work, ums_test_tx_work);
    queue_work(workqueue_test, &ums->conn.close_work);
    mod_delayed_work(tx_wq, &ums->conn.tx_work, 0);

    /* test for ums_close_active_abort_on_ums_app_close_wait */
    ums_close_active_abort(ums);
    release_sock(&ums->sk);

    /* test for ums_close_active_abort_on_ums_peer_fin_close_wait */
    sk->sk_state = UMS_PEERCLOSEWAIT1;
    ums_close_active_abort(ums);
    release_sock(&ums->sk);

    /* test for ums_close_active_abort_on_ums_app_fin_close_wait */
    sk->sk_state = UMS_PROCESSABORT;
    ums_close_active_abort(ums);
    release_sock(&ums->sk);

    /* test for default case */
    sk->sk_state = UMS_INIT;
    ums_close_active_abort(ums);

    destroy_workqueue(workqueue_test);
    destroy_workqueue(tx_wq);
}

static void ums_test_close_active_shut(void)
{
    struct ums_connection conn = {0};

    /* test when sk statw is UMS_APPFINCLOSEWAIT */
    ums->sk.sk_state = UMS_APPFINCLOSEWAIT;
    conn.killed = 1;
    atomic_set(&conn.conn_tx_rx_refcnt, 1);
    atomic_set(&conn.bytes_to_rcv, 0);
    conn.local_tx_ctrl.conn_state_flags.peer_conn_abort = 1;
    ums->conn = conn;
    ums_close_active(ums);

    /* test when sk statw is UMS_PROCESSABORT */
    ums->sk.sk_state = UMS_PROCESSABORT;
    atomic_set(&conn.cdc_tx_pushing, UMS_TEST_CDC_TX_PUSHING);
    ums_close_active(ums);

    /* test when sk statw is UMS_PEERABORTWAIT */
    ums->sk.sk_state = UMS_PEERABORTWAIT;
    ums_close_active(ums);
}
static void ums_test_create_jetty(void)
{
    struct ums_link lnk;
    struct ums_ubcore_jfc ums_ub_jfc;
    struct ums_ubcore_device *ums_ub_dev = kzalloc(sizeof(struct ums_ubcore_device), GFP_KERNEL);
    struct ubcore_device ub_dev;

    atomic_set(&ums_ub_jfc.load, 0);
    ums_ub_dev->num_jfc = 1;
    lnk.ums_dev = ums_ub_dev;
    lnk.ums_dev->ub_dev = &ub_dev;
    ums_ub_dev->ums_ub_jfc = &ums_ub_jfc;
    ub_dev.transport_type = UBCORE_TRANSPORT_UB;

    hash_init(ums_ub_dev->jetty2link_htable);
    rwlock_init(&ums_ub_dev->jetty2link_htable_lock);

    ums_ubcore_create_jetty(&lnk);

    hash_del(&lnk.hnode);
    kfree(ums_ub_dev);
}

static void ums_test_close_non_accepted(void)
{
    socket->sk->sk_state = (unsigned char)UMS_INIT;
    ums_close_non_accepted(&ums->sk);
}

static void ums_test_listen_out(void)
{
    struct ums_sock *listen_ums = ums;
    ums->listen_ums = listen_ums;
    ums->sk.sk_state = (unsigned char)UMS_INIT;
    ums_listen_out_connected(ums);
}

static void ums_test_cli_delete_link(void)
{
    struct ums_link_group *lgr = kzalloc(sizeof(*lgr), GFP_KERNEL);
    struct ums_llc_qentry *qentry = kzalloc(sizeof(*qentry), GFP_KERNEL);
    struct ums_llc_msg_del_link del_llc;
    struct ums_link link;

    lgr->llc_flow_lcl.qentry = NULL;
    ums_llc_process_cli_delete_link(lgr);

    del_llc.hd.flags = 0;
    link.state = UMS_LNK_UNUSED;
    lgr->llc_flow_lcl.qentry = qentry;
    qentry->link = &link;
    qentry->msg.delete_link = del_llc;
    mutex_init(&lgr->llc_conf_mutex);
    /* the pointer qentry has been released in function */
    ums_llc_process_cli_delete_link(lgr);

    if (lgr)
        kfree(lgr);
}

static void ums_test_srv_delete_link(void)
{
    struct ums_link_group *lgr = kzalloc(sizeof(*lgr), GFP_KERNEL);
    struct ums_link link;
    struct ums_llc_qentry *qentry = kzalloc(sizeof(*qentry), GFP_KERNEL);
    struct ums_llc_msg_del_link del_llc;

    del_llc.hd.flags = 0;
    del_llc.link_num = UMS_TEST_DEL_LLC_LINK_NUM;
    lgr->llc_flow_lcl.qentry = qentry;
    qentry->link = &link;
    qentry->msg.delete_link = del_llc;
    mutex_init(&lgr->llc_conf_mutex);

    ums_llc_process_srv_delete_link(lgr);

    if (lgr)
        kfree(lgr);
}

static void ums_test_close_passive_abort(void)
{
    ums->sk.sk_state = UMS_INIT;
    ums_close_passive_abort_received(ums);

    ums->sk.sk_state = UMS_APPFINCLOSEWAIT;
    ums_close_passive_abort_received(ums);

    ums->conn.local_tx_ctrl.conn_state_flags.peer_done_writing = 0;
    ums->sk.sk_state = UMS_PEERCLOSEWAIT1;
    ums_close_passive_abort_received(ums);

    ums->sk.sk_state = UMS_PEERCLOSEWAIT2;
    ums_close_passive_abort_received(ums);

    ums->sk.sk_state = UMS_PEERABORTWAIT;
    ums_close_passive_abort_received(ums);

    ums->sk.sk_state = UMS_PROCESSABORT;
    ums_close_passive_abort_received(ums);
}

static int __init ums_test_init(void)
{
    pr_info("ums api test init\n");

    struct ums_sock u_sock;

    ums_tx_init(&u_sock);

    // test ums_dim
    struct ums_dim u_dim = {
        .use_dim = true,
    };

    ums_dim(&u_dim.dim, 0);

    u_dim.dim.measuring_sample.event_ctr = 64;
    u_dim.dim.start_sample.event_ctr = 0;
    ums_dim(&u_dim.dim, 0);

    // test ums_pnet
    u8 pnetid[1] = {0};
    ums_pnet_is_pnetid_set(pnetid);
    (void)ums_test_create_sock();
    ums_test_llc_flow_start();
    ums_test_sock_accept();
    ums_test_check_sk_state();
    ums_test_close_abort();
    ums_test_close_active();
    ums_test_close_active_shut();
    ums_test_create_jetty();
    ums_test_close_non_accepted();
    ums_test_listen_out();
    ums_test_cli_delete_link();
    ums_test_srv_delete_link();
    ums_test_close_passive_abort();
    ums_token_kmod_test_run();
    sock_release(socket);

    return 0;
}

static void __exit ums_test_exit(void)
{
	pr_info("ums api test exit\n");
}

module_init(ums_test_init);
module_exit(ums_test_exit);

MODULE_AUTHOR("huawei");
MODULE_DESCRIPTION("ums api test");
MODULE_LICENSE("GPL");
