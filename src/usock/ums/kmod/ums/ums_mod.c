// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS module implementation
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *                based on prototype from Frank Blaschka
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <asm/ioctls.h>

#include <linux/version.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/rcupdate_wait.h>
#include <linux/sched/signal.h>
#include <linux/socket.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/splice.h>

#include "ums_cdc.h"
#include "ums_clc.h"
#include "ums_close.h"
#include "ums_dfx.h"
#include "ums_llc.h"
#include "ums_log.h"
#include "ums_pnet.h"
#include "ums_rx.h"
#include "ums_tx.h"
#include "ums_ns.h"
#include "ums_common.h"
#include "ums_connect.h"
#include "ums_listen.h"
#include "ums_accept.h"
#include "ums_bind.h"
#include "ums_sockops.h"
#include "ums_release.h"
#include "ums_mod.h"

/* stats */
#if defined(UMS_TRACE)
#define PKT_TX_STATS_ARRAY_SIZE 1026
#define PKT_RX_STATS_ARRAY_SIZE 1026
#define PKT_STATS_SIZE_PER_ELEMENT 1024
#define PKT_MAX_LEN (PKT_STATS_SIZE_PER_ELEMENT * (PKT_TX_STATS_ARRAY_SIZE - 2))
static uint64_t pkt_tx_stats[PKT_TX_STATS_ARRAY_SIZE] = { 0 };
static uint64_t pkt_rx_stats[PKT_RX_STATS_ARRAY_SIZE] = { 0 };
#endif

#define SK_FLAGS_CLC_TO_UMS \
	((1UL << SOCK_URGINLINE) | (1UL << SOCK_KEEPOPEN) | (1UL << SOCK_LINGER) | (1UL << SOCK_DBG))

/* work queues */
struct workqueue_struct *g_ums_tcp_ls_wq = NULL;
struct workqueue_struct *g_ums_hs_wq = NULL;
struct workqueue_struct *g_ums_close_wq = NULL;

unsigned int g_ums_net_id;

static uint32_t ub_token_disable;

module_param(ub_token_disable, uint, 0);
MODULE_PARM_DESC(ub_token_disable, "1:disable ub token, 0:enable ub token, default:0");

static void ums_tcp_listen_work(struct work_struct *work);

static void ums_set_keepalive(struct sock *sk, int val)
{
	struct ums_sock *ums = ums_sk(sk);

	ums->clcsock->sk->sk_prot->keepalive(ums->clcsock->sk, val);
}

static struct ums_hashinfo g_ums_v4_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(g_ums_v4_hashinfo.lock),
};

static struct ums_hashinfo g_ums_v6_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(g_ums_v6_hashinfo.lock),
};

int ums_hash_sk(struct sock *sk)
{
	struct ums_hashinfo *h = (struct ums_hashinfo *)sk->sk_prot->h.smc_hash;
	struct hlist_head *head = &h->ht;

	write_lock_bh(&h->lock);
	sk_add_node(sk, head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&h->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(ums_hash_sk);

void ums_unhash_sk(struct sock *sk)
{
	struct ums_hashinfo *h = (struct ums_hashinfo *)sk->sk_prot->h.smc_hash;

	write_lock_bh(&h->lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&h->lock);
}
EXPORT_SYMBOL_GPL(ums_unhash_sk);

/* This will be called before user really release sock_lock. So do the
 * work which we didn't do because of user hold the sock_lock in the
 * BH context
 */
static void ums_release_cb(struct sock *sk)
{
	struct ums_sock *ums = ums_sk(sk);

	if (ums->conn.tx_in_release_sock) {
		ums_tx_pending(&ums->conn);
		ums->conn.tx_in_release_sock = false;
	}
}

struct proto g_ums_proto = {
	.name = "UMS",
	.owner = THIS_MODULE,
	.keepalive = ums_set_keepalive,
	.hash = ums_hash_sk,
	.unhash = ums_unhash_sk,
	.release_cb = ums_release_cb,
	.obj_size = sizeof(struct ums_sock),
	.h.smc_hash = (void *)&g_ums_v4_hashinfo,
	.slab_flags = SLAB_TYPESAFE_BY_RCU,
};
EXPORT_SYMBOL_GPL(g_ums_proto);

struct proto g_ums_proto6 = {
	.name = "UMS6",
	.owner = THIS_MODULE,
	.keepalive = ums_set_keepalive,
	.hash = ums_hash_sk,
	.unhash = ums_unhash_sk,
	.release_cb = ums_release_cb,
	.obj_size = sizeof(struct ums_sock),
	.h.smc_hash = (void *)&g_ums_v6_hashinfo,
	.slab_flags = SLAB_TYPESAFE_BY_RCU,
};
EXPORT_SYMBOL_GPL(g_ums_proto6);

static void ums_destruct(struct sock *sk)
{
	if (sk->sk_state != (unsigned char)UMS_CLOSED)
		return;
	if (!sock_flag(sk, SOCK_DEAD))
		return;

#ifdef SOCK_REFCNT_DEBUG
	sk_refcnt_debug_dec(sk);
#endif
}

static void ums_free_work(struct work_struct *work)
{
	struct sock *sk;
	struct ums_sock *ums = container_of(work, struct ums_sock, free_work);

	sk = &ums->sk;

	lock_sock(sk);
	if (sk->sk_state == (unsigned char)UMS_CLOSED && !ums->use_fallback)
		ums_conn_free(&ums->conn);
	release_sock(sk);

	sock_put(sk); /* before queue */
}

static struct sock *ums_sock_alloc(struct net *net, struct socket *sock, int protocol)
{
	struct ums_sock *ums;
	struct proto *prot;
	struct sock *sk;
	int i = 0;

	prot = (protocol == (int)UMSPROTO_UMS6) ? &g_ums_proto6 : &g_ums_proto;
	sk = sk_alloc(net, AF_SMC, GFP_KERNEL, prot, 0);
	if (!sk)
		return NULL;

	sock_init_data(sock, sk); /* sets sk_refcnt to 1 */
	sk->sk_state = (unsigned char)UMS_INIT;
	sk->sk_destruct = ums_destruct;
	sk->sk_protocol = (unsigned char)protocol;
	sk->sk_sndbuf = READ_ONCE(g_ums_sysctl_conf.sysctl_sndbuf);
	sk->sk_rcvbuf = READ_ONCE(g_ums_sysctl_conf.sysctl_rcvbuf);

	ums = ums_sk(sk);
	for (i = 0; i < UMS_MAX_TCP_LISTEN_WORKS; i++) {
		ums->tcp_listen_works[i].ums = ums;
		INIT_WORK(&ums->tcp_listen_works[i].work, ums_tcp_listen_work);
	}
	atomic_set(&ums->tcp_listen_work_seq, 0);
	INIT_WORK(&ums->free_work, ums_free_work);
	INIT_WORK(&ums->connect_work, ums_connect_work);
	INIT_DELAYED_WORK(&ums->conn.tx_work, ums_tx_work);
	INIT_DELAYED_WORK(&ums->conn.cdc_tx_work, ums_cdc_tx_work);
	INIT_LIST_HEAD(&ums->accept_q);
	spin_lock_init(&ums->accept_q_lock);
	spin_lock_init(&ums->conn.send_lock);
	sk->sk_prot->hash(sk);
#ifdef SOCK_REFCNT_DEBUG
	sk_refcnt_debug_inc(sk);
#endif
	init_rwsem(&ums->clcsock_release_lock);
	ums_init_saved_callbacks(ums);

	/* default behavior from every net namespace */
	ums->ums_fastopen = 1; /* enable fast open currently */
	return sk;
}

/* clean up for a created but never accepted sock */
void ums_close_non_accepted(struct sock *sk)
{
	struct ums_sock *ums = ums_sk(sk);

	sock_hold(sk); /* sock_put below */
	lock_sock(sk);
	if (sk->sk_lingertime == 0)
		/* wait for peer closing */
		sk->sk_lingertime = UMS_MAX_STREAM_WAIT_TIMEOUT;
	(void)ums_release_inner(ums);
	release_sock(sk);
	sock_put(sk); /* sock_hold above */
	sock_put(sk); /* final sock_put */
}

static void ums_copy_sock_settings_to_ums(struct ums_sock *ums)
{
	ums_copy_sock_settings(&ums->sk, ums->clcsock->sk, (unsigned long)SK_FLAGS_CLC_TO_UMS);
}

static int ums_clcsock_accept(struct ums_sock *lums, struct ums_sock **new_ums)
{
	struct socket *new_clcsock = NULL;
	struct sock *lsk = &lums->sk;
	struct sock *new_sk;
	int rc = -EINVAL;

	down_read(&lums->clcsock_release_lock);
	if (lums->clcsock) {
		if (lums->clcsock->sk->sk_ack_backlog != 0)
			rc = kernel_accept(lums->clcsock, &new_clcsock, SOCK_NONBLOCK);
		else
			rc = -EAGAIN;
	}
	up_read(&lums->clcsock_release_lock);
	if (rc < 0 && rc != -EAGAIN)
		lsk->sk_err = -rc;
	if (rc < 0 || lsk->sk_state == (unsigned char)UMS_CLOSED)
		goto err_out;

	new_sk = ums_sock_alloc(sock_net(lsk), NULL, lsk->sk_protocol);
	if (!new_sk) {
		rc = -ENOMEM;
		lsk->sk_err = ENOMEM;
		goto err_out;
	}
	*new_ums = ums_sk(new_sk);

	if (new_clcsock == NULL) {
		sock_put(new_sk);
		goto err_out;
	}

	/* new clcsock has inherited the ums listen-specific sk_data_ready
	 * function; switch it back to the original sk_data_ready function
	 */
	new_clcsock->sk->sk_data_ready = lums->clcsk_data_ready;

	/* if new clcsock has also inherited the fallback-specific callback
	 * functions, switch them back to the original ones.
	 */
	if (lums->use_fallback) {
		if (lums->clcsk_state_change)
			new_clcsock->sk->sk_state_change = lums->clcsk_state_change;
		if (lums->clcsk_write_space)
			new_clcsock->sk->sk_write_space = lums->clcsk_write_space;
		if (lums->clcsk_error_report)
			new_clcsock->sk->sk_error_report = lums->clcsk_error_report;
	}

	(*new_ums)->clcsock = new_clcsock;

	return 0;
err_out:
	*new_ums = NULL;
	if (new_clcsock)
		sock_release(new_clcsock);
	return rc;
}

static void ums_tcp_listen_work(struct work_struct *work)
{
	struct ums_tcp_listen_work *twork = container_of(work, struct ums_tcp_listen_work, work);
	struct ums_sock *lums = twork->ums;
	struct sock *lsk = &lums->sk;
	struct ums_sock *new_ums;
	bool syn_ums = true;
	int rc = 0;

	while (lsk->sk_state == (unsigned char)UMS_LISTEN) {
		rc = ums_clcsock_accept(lums, &new_ums);
		if (rc != 0) /* clcsock accept queue empty or error */
			goto out;
		if (!new_ums)
			continue;

		new_ums->listen_ums = lums;
		new_ums->use_fallback = lums->use_fallback;
		new_ums->fallback_rsn = lums->fallback_rsn;
		sock_hold(lsk); /* sock_put in ums_listen_work */
		INIT_WORK(&new_ums->ums_listen_work, ums_listen_work);
		ums_copy_sock_settings_to_ums(new_ums);
		new_ums->sk.sk_sndbuf = lums->sk.sk_sndbuf;
		new_ums->sk.sk_rcvbuf = lums->sk.sk_rcvbuf;
		/* check if peer is ums capable */
#if IS_ENABLED(CONFIG_SMC)
		syn_ums = ums_get_syn_smc(new_ums);
#else
		UMS_LOGW_LIMITED("CONFIG_SMC disabled, UMS cannot switch to fallback now!");
#endif

		if (!syn_ums) {
			sock_hold(&new_ums->sk); /* sock_put in passive closing */
			rc = ums_switch_to_fallback(new_ums, UMS_CLC_DECL_PEERNOUMS);
			if (rc != 0)
				ums_listen_out_err(new_ums);
			else
				ums_listen_out_connected(new_ums);
		} else {
			new_ums->ums_negotiated = 1;
			atomic_inc(&lums->queued_ums_hs);
			/* memory barrier */
			smp_mb__after_atomic();
			sock_hold(&new_ums->sk); /* sock_put in passive closing */
			if (!queue_work(g_ums_hs_wq, &new_ums->ums_listen_work))
				sock_put(&new_ums->sk);
		}
	}

out:
	sock_put(&lums->sk); /* sock_hold in ums_clcsock_data_ready() */
}

static int ums_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct ums_sock *ums;
	int r = -ENOTCONN;

	if ((peer != 0) && (sock->sk->sk_state != (unsigned char)UMS_ACTIVE) &&
		(sock->sk->sk_state != (unsigned char)UMS_APPCLOSEWAIT1))
		goto out;

	ums = ums_sk(sock->sk);
	down_read(&ums->clcsock_release_lock);
	if (ums->clcsock && ums->clcsock->ops)
		r = ums->clcsock->ops->getname(ums->clcsock, addr, peer);
	up_read(&ums->clcsock_release_lock);

out:
	return r;
}

static int ums_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	int rc = -EPIPE;

#if defined(UMS_TRACE)
	if (len > PKT_MAX_LEN)
		pkt_tx_stats[PKT_TX_STATS_ARRAY_SIZE - 1]++;
	else
		pkt_tx_stats[len / PKT_STATS_SIZE_PER_ELEMENT]++;
#endif

	ums = ums_sk(sk);
	lock_sock(sk);
	if ((sk->sk_state != (unsigned char)UMS_ACTIVE) &&
		(sk->sk_state != (unsigned char)UMS_APPCLOSEWAIT1) &&
		(sk->sk_state != (unsigned char)UMS_INIT))
		goto out;

	if ((msg->msg_flags & MSG_FASTOPEN) != 0) {
		if ((sk->sk_state == (unsigned char)UMS_INIT) && (ums->connect_nonblock == 0)) {
			rc = ums_switch_to_fallback(ums, (unsigned char)UMS_CLC_DECL_OPTUNSUPP);
			if (rc != 0)
				goto out;
		} else {
			rc = -EINVAL;
			goto out;
		}
	}

	if (ums->use_fallback)
		rc = ums->clcsock->ops->sendmsg(ums->clcsock, msg, len);
	else
		rc = ums_tx_sendmsg(ums, msg, len);

out:
	release_sock(sk);
	return rc;
}

static bool ums_check_sk_err(const struct sock *sk, int *rc)
{
	if ((sk->sk_state == ((unsigned char)UMS_CLOSED)) && ((sk->sk_shutdown & RCV_SHUTDOWN) != 0)) {
		/* socket was connected before, no more data to read */
		*rc = 0;
		return true;
	}
	if (sk->sk_state == (unsigned char)UMS_INIT || sk->sk_state == (unsigned char)UMS_LISTEN ||
		sk->sk_state == (unsigned char)UMS_CLOSED)
		return true;

	if (sk->sk_state == (unsigned char)UMS_PEERFINCLOSEWAIT) {
		*rc = 0;
		return true;
	}

	return false;
}

static int ums_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	int rc = -ENOTCONN;

	ums = ums_sk(sk);
	lock_sock(sk);
	if (ums_check_sk_err(sk, &rc))
		goto out;

	if (ums->use_fallback) {
		rc = ums->clcsock->ops->recvmsg(ums->clcsock, msg, len, flags);
	} else {
		msg->msg_namelen = 0;
		rc = ums_rx_recvmsg(ums, msg, NULL, len, flags);
	}
#if defined(UMS_TRACE)
	if (len > PKT_MAX_LEN)
		pkt_rx_stats[PKT_TX_STATS_ARRAY_SIZE - 1]++;
	else
		pkt_rx_stats[len / PKT_STATS_SIZE_PER_ELEMENT]++;
#endif

out:
	release_sock(sk);
	return rc;
}

static inline __poll_t ums_accept_poll(struct sock *parent)
{
	if (!ums_accept_queue_empty(parent))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

static __poll_t ums_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	__poll_t mask = 0;

	if (!sk)
		return EPOLLNVAL;

	ums = ums_sk(sock->sk);
	if (ums->use_fallback) {
		/* delegate to CLC child sock */
		mask = ums->clcsock->ops->poll(file, ums->clcsock, wait);
		sk->sk_err = ums->clcsock->sk->sk_err;
	} else {
		if (sk->sk_state != (unsigned char)UMS_CLOSED)
			sock_poll_wait(file, sock, wait);
		if (sk->sk_err != 0)
			mask |= EPOLLERR;
		if ((sk->sk_shutdown == SHUTDOWN_MASK) || (sk->sk_state == (unsigned char)UMS_CLOSED))
			mask |= EPOLLHUP;
		if (sk->sk_state == (unsigned char)UMS_LISTEN) {
			/* woken up by sk_data_ready in ums_listen_work() */
			mask |= ums_accept_poll(sk);
		} else if (ums->use_fallback) { /* as result of connect_work() */
			mask |= ums->clcsock->ops->poll(file, ums->clcsock, wait);
			sk->sk_err = ums->clcsock->sk->sk_err;
		} else {
			if (((sk->sk_state != (unsigned char)UMS_INIT) && (atomic_read(&ums->conn.sndbuf_space) != 0)) ||
				((sk->sk_shutdown & SEND_SHUTDOWN) != 0)) {
				mask |= EPOLLOUT | EPOLLWRNORM;
			} else {
				sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			}
			if (atomic_read(&ums->conn.bytes_to_rcv) != 0)
				mask |= EPOLLIN | EPOLLRDNORM;
			if ((sk->sk_shutdown & RCV_SHUTDOWN) != 0)
				mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
			if (sk->sk_state == (unsigned char)UMS_APPCLOSEWAIT1)
				mask |= EPOLLIN;
			if (ums->conn.urg_state == UMS_URG_VALID)
				mask |= EPOLLPRI;
		}
	}

	return mask;
}

static bool ums_check_sk_state(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sock->state == SS_CONNECTING) {
		if (sk->sk_state == (unsigned char)UMS_ACTIVE)
			sock->state = SS_CONNECTED;
		else if (sk->sk_state == (unsigned char)UMS_PEERCLOSEWAIT1 ||
			sk->sk_state == (unsigned char)UMS_PEERCLOSEWAIT2 ||
			sk->sk_state == (unsigned char)UMS_APPCLOSEWAIT1 ||
			sk->sk_state == (unsigned char)UMS_APPCLOSEWAIT2 ||
			sk->sk_state == (unsigned char)UMS_APPFINCLOSEWAIT)
			sock->state = SS_DISCONNECTING;
	}

	if ((sk->sk_state != (unsigned char)UMS_ACTIVE) &&
		(sk->sk_state != (unsigned char)UMS_PEERCLOSEWAIT1) &&
		(sk->sk_state != (unsigned char)UMS_PEERCLOSEWAIT2) &&
		(sk->sk_state != (unsigned char)UMS_APPCLOSEWAIT1) &&
		(sk->sk_state != (unsigned char)UMS_APPCLOSEWAIT2) &&
		(sk->sk_state != (unsigned char)UMS_APPFINCLOSEWAIT))
		return false;

	return true;
}

static int ums_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	bool do_shutdown = true;
	struct ums_sock *ums;
	int rc = -EINVAL;
	int old_state;
	int rc1 = 0;

	ums = ums_sk(sk);

	if ((how < (int)SHUT_RD) || (how > (int)SHUT_RDWR))
		return rc;

	lock_sock(sk);

	rc = -ENOTCONN;
	if (!ums_check_sk_state(sock))
		goto out;

	if (ums->use_fallback) {
		rc = kernel_sock_shutdown(ums->clcsock, how);
		sk->sk_shutdown = ums->clcsock->sk->sk_shutdown;
		if (sk->sk_shutdown == SHUTDOWN_MASK) {
			sk->sk_state = (unsigned char)UMS_CLOSED;
			sk->sk_socket->state = SS_UNCONNECTED;
			sock_put(sk);
		}
		goto out;
	}
	switch (how) {
	case SHUT_RDWR: /* shutdown in both directions */
		old_state = sk->sk_state;
		rc = ums_close_active(ums);
		if (old_state == (unsigned char)UMS_ACTIVE && sk->sk_state == (unsigned char)UMS_PEERCLOSEWAIT1)
			do_shutdown = false;
		break;
	case SHUT_WR:
		rc = ums_close_shutdown_write(ums);
		break;
	case SHUT_RD:
		rc = 0;
		/* nothing more to do because peer is not involved */
		break;
	default:
		UMS_LOGE("Invalid shut down opcode.");
		break;
	}
	if (do_shutdown && ums->clcsock)
		rc1 = kernel_sock_shutdown(ums->clcsock, how);
	/* map sock_shutdown_cmd constants to sk_shutdown value range */
	sk->sk_shutdown |= (u8)(how + 1);

	if (sk->sk_state == (unsigned char)UMS_CLOSED)
		sock->state = SS_UNCONNECTED;
	else
		sock->state = SS_DISCONNECTING;
out:
	release_sock(sk);
	return rc != 0 ? rc : rc1;
}

static int ums_process_ioctl(unsigned int cmd, struct ums_sock *ums, int *answ,
	struct ums_connection *conn)
{
	union ums_host_cursor cons, urg;

	switch (cmd) {
	case SIOCINQ: /* same as FIONREAD */
		if (ums->sk.sk_state == (unsigned char)UMS_LISTEN)
			return -EINVAL;
		if (ums->sk.sk_state == (unsigned char)UMS_INIT || ums->sk.sk_state == (unsigned char)UMS_CLOSED)
			*answ = 0;
		else
			*answ = atomic_read(&ums->conn.bytes_to_rcv);
		break;
	case SIOCOUTQ:
		/* output queue size (not send + not acked) */
		if (ums->sk.sk_state == (unsigned char)UMS_LISTEN)
			return -EINVAL;
		if (ums->sk.sk_state == (unsigned char)UMS_INIT || ums->sk.sk_state == (unsigned char)UMS_CLOSED)
			*answ = 0;
		else
			*answ = ums->conn.sndbuf_desc->len - atomic_read(&ums->conn.sndbuf_space);
		break;
	case SIOCOUTQNSD:
		/* output queue size (not send only) */
		if (ums->sk.sk_state == (unsigned char)UMS_LISTEN)
			return -EINVAL;
		if (ums->sk.sk_state == (unsigned char)UMS_INIT ||
			ums->sk.sk_state == (unsigned char)UMS_CLOSED)
			*answ = 0;
		else
			*answ = ums_tx_prepared_sends(&ums->conn);
		break;
	case SIOCATMARK:
		if (ums->sk.sk_state == (unsigned char)UMS_LISTEN)
			return -EINVAL;
		if (ums->sk.sk_state == (unsigned char)UMS_INIT ||
			ums->sk.sk_state == (unsigned char)UMS_CLOSED) {
			*answ = 0;
		} else {
			ums_curs_copy(&cons, &conn->local_tx_ctrl.cons, conn);
			ums_curs_copy(&urg, &conn->urg_curs, conn);
			*answ = ums_curs_diff((unsigned int)conn->rmb_desc->len, &cons, &urg) == 1;
		}
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static int ums_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct ums_connection *conn;
	struct ums_sock *ums;
	int rc = 0;
	int answ;

	ums = ums_sk(sock->sk);
	conn = &ums->conn;
	lock_sock(&ums->sk);
	if (ums->use_fallback) {
		if (!ums->clcsock) {
			release_sock(&ums->sk);
			return -EBADF;
		}
		answ = ums->clcsock->ops->ioctl(ums->clcsock, cmd, arg);
		release_sock(&ums->sk);
		return answ;
	}
	rc = ums_process_ioctl(cmd, ums, &answ, conn);
	if (rc != 0) {
		release_sock(&ums->sk);
		return rc;
	}
	release_sock(&ums->sk);

	return (int)put_user(answ, (int __user *)arg);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
/* linux kernel remove ->sendpage() and ->sendpage_locked(). sendmsg() with
 * MSG_SPLICE_PAGES should be used instead.
 * UMS does not support sendmsg() with MSG_SPLICE_PAGES now.
 */
static ssize_t ums_sendpage(struct socket *sock, struct page *page, int offset, size_t size,
	int flags)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	int rc = -EPIPE;

	ums = ums_sk(sk);
	lock_sock(sk);
	if (sk->sk_state != (unsigned char)UMS_ACTIVE) {
		release_sock(sk);
		goto out;
	}
	release_sock(sk);
	if (ums->use_fallback) {
		rc = kernel_sendpage(ums->clcsock, page, offset, size, flags);
	} else {
		lock_sock(sk);
		rc = ums_tx_sendpage(ums, page, offset, size, flags);
		release_sock(sk);
	}

out:
	return rc;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) */

static ssize_t ums_splice_read(struct socket *sock, loff_t *ppos, struct pipe_inode_info *pipe,
	size_t len, unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	int rc = -ENOTCONN;

	ums = ums_sk(sk);
	lock_sock(sk);
	if (ums_check_sk_err(sk, &rc))
		goto out;
	release_sock(sk);
	/* above check may not needed for fallback case, refer to tcp */
	if (ums->use_fallback)
		return ums->clcsock->ops->splice_read(ums->clcsock, ppos, pipe, len, flags);
	if (*ppos != 0)
		return -ESPIPE;
	if ((flags & SPLICE_F_NONBLOCK) != 0)
		flags = MSG_DONTWAIT;
	else
		flags = 0;
	return ums_rx_recvmsg(ums, NULL, pipe, len, (int)flags);
out:
	release_sock(sk);
	return rc;
}

/* proto_ops are called by kernel.
 * Kernel has validated parameter of these functions and we don't need double check it.
 */
static const struct proto_ops ums_sock_ops = {
	.family = AF_SMC,
	.owner = THIS_MODULE,
	.release = ums_release,
	.bind = ums_bind,
	.connect = ums_connect,
	.socketpair = sock_no_socketpair,
	.accept = ums_accept,
	.getname = ums_getname,
	.poll = ums_poll,
	.ioctl = ums_ioctl,
	.listen = ums_listen,
	.shutdown = ums_shutdown,
	.setsockopt = ums_setsockopt,
	.getsockopt = ums_getsockopt,
	.sendmsg = ums_sendmsg,
	.recvmsg = ums_recvmsg,
	.mmap = sock_no_mmap,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
/* linux kernel remove ->sendpage() and ->sendpage_locked(). sendmsg() with
 * MSG_SPLICE_PAGES should be used instead.
 * UMS does not support sendmsg() with MSG_SPLICE_PAGES now.
 */
	.sendpage = ums_sendpage,
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) */
	.splice_read = ums_splice_read,
};

static int ums_create_inner(struct net *net, struct socket *sock, int protocol, int kern,
	struct socket *clcsock)
{
	int family = (protocol == UMSPROTO_UMS6) ? PF_INET6 : PF_INET;
	struct ums_sock *ums;
	struct sock *sk;
	int rc;

	if (sock->type != (short)SOCK_STREAM)
		return -ESOCKTNOSUPPORT;
	if (protocol != UMSPROTO_UMS && protocol != UMSPROTO_UMS6)
		return -EPROTONOSUPPORT;

	sock->ops = &ums_sock_ops;
	sock->state = SS_UNCONNECTED;
	sk = ums_sock_alloc(net, sock, protocol);
	if (!sk)
		return -ENOBUFS;

	/* create internal TCP socket for CLC handshake and fallback */
	ums = ums_sk(sk);
	ums->use_fallback = false; /* assume ub capability first */
	ums->fallback_rsn = 0;
	ums->limit_ums_hs = 0; /* disable limit_ums_hs by default */
	ums->autocorking_size = READ_ONCE(g_ums_sysctl_conf.sysctl_autocorking_size);
	ums->ums_buf_type = UMS_PHYS_CONT_BUFS;

	rc = 0;
	if (!clcsock) {
		rc = sock_create_kern(net, family, (int)SOCK_STREAM, (int)IPPROTO_TCP, &ums->clcsock);
		if (rc != 0) {
			sk_common_release(sk);
			return rc;
		}
	} else {
		ums->clcsock = clcsock;
	}

	return rc;
}

static int ums_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	return ums_create_inner(net, sock, protocol, kern, NULL);
}

static const struct net_proto_family UMS_SOCK_FAMILY_OPS = {
	.family = AF_SMC,
	.owner = THIS_MODULE,
	.create = ums_create,
};

static int ums_ulp_init(struct sock *sk)
{
	struct socket *tcp = sk->sk_socket;
	struct net *net = sock_net(sk);
	struct socket *umssock;
	int protocol, ret;

	if (tcp->type != (short)SOCK_STREAM || sk->sk_protocol != IPPROTO_TCP ||
		(sk->sk_family != AF_INET && sk->sk_family != AF_INET6))
		return -ESOCKTNOSUPPORT;
#ifdef KERNEL_VERSION_4
	if (tcp->state != SS_UNCONNECTED || !tcp->file || tcp->wq->fasync_list)
#else
	if (tcp->state != SS_UNCONNECTED || !tcp->file || tcp->wq.fasync_list)
#endif
		return -ENOTCONN;
	if (sk->sk_family == AF_INET)
		protocol = UMSPROTO_UMS;
	else
		protocol = UMSPROTO_UMS6;

	umssock = sock_alloc();
	if (!umssock)
		return -ENFILE;
	umssock->type = (short)SOCK_STREAM;
	__module_get(THIS_MODULE); /* tried in __tcp_ulp_find_autoload */
	ret = ums_create_inner(net, umssock, protocol, 1, tcp);
	if (ret != 0) {
		sock_release(umssock); /* module_put() which ops won't be NULL */
		return ret;
	}
	/* replace tcp socket to ums */
	umssock->file = tcp->file;
	umssock->file->private_data = umssock;
	umssock->file->f_inode = SOCK_INODE(umssock);                /* replace inode when sock_close */
	umssock->file->f_path.dentry->d_inode = SOCK_INODE(umssock); /* dput() in __fput */
	tcp->file = NULL;

	return ret;
}

#ifndef KERNEL_VERSION_4
static void ums_ulp_clone(const struct request_sock *req, struct sock *newsk, const gfp_t priority)
{
	struct inet_connection_sock *icsk = inet_csk(newsk);

	/* don't inherit ulp ops to child when listen */
	icsk->icsk_ulp_ops = NULL;
}
#endif

static struct tcp_ulp_ops g_ums_ulp_ops __read_mostly = {
	.name = "ums",
	.owner = THIS_MODULE,
	.init = ums_ulp_init,
#ifndef KERNEL_VERSION_4
	.clone = ums_ulp_clone,
#endif
};

static __net_init int ums_net_init(struct net *net)
{
	int rc;

	rc = ums_sysctl_net_init(net);
	if (rc != 0)
		return rc;
	return ums_pnet_net_init(net);
}

static void __net_exit ums_net_exit(struct net *net)
{
	ums_sysctl_net_exit(net);
	ums_pnet_net_exit(net);
}

static struct pernet_operations g_ums_pernet_ops = {
	.init = ums_net_init,
	.exit = ums_net_exit,
	.id = &g_ums_net_id,
	.size = sizeof(struct ums_net),
};

static int __net_init ums4_proc_init_net(struct net *net)
{
	static const struct seq_operations UMS4_SEQ_OPS = {
		.show  = ums4_seq_show,
		.start = ums_seq_start,
		.next  = ums_seq_next,
		.stop  = ums_seq_stop,
	};

	/* ums create proc net file */
	if (!proc_create_net_data("ums", 0444, net->proc_net, &UMS4_SEQ_OPS,
		sizeof(struct ums_iter_state), &g_ums_v4_hashinfo))
		return -ENOMEM;

	return 0;
}

static void __net_exit ums4_proc_exit_net(struct net *net)
{
	remove_proc_entry("ums", net->proc_net);
}

static struct pernet_operations g_ums4_net_ops = {
	.init = ums4_proc_init_net,
	.exit = ums4_proc_exit_net,
};

static int __net_init ums6_proc_init_net(struct net *net)
{
	static const struct seq_operations UMS6_SEQ_OPS = {
		.show  = ums6_seq_show,
		.start = ums_seq_start,
		.next  = ums_seq_next,
		.stop  = ums_seq_stop,
	};

	/* ums create proc net file */
	if (!proc_create_net_data("ums6", 0444, net->proc_net, &UMS6_SEQ_OPS,
		sizeof(struct ums_iter_state), &g_ums_v6_hashinfo))
		return -ENOMEM;

	return 0;
}

static void __net_exit ums6_proc_exit_net(struct net *net)
{
	remove_proc_entry("ums6", net->proc_net);
}

static struct pernet_operations g_ums6_net_ops = {
	.init = ums6_proc_init_net,
	.exit = ums6_proc_exit_net,
};

static int __init ums_dfx_init(void)
{
	int rc = 0;

	rc = register_pernet_subsys(&g_ums4_net_ops);
	if (rc != 0) {
		UMS_LOGE("register pernet ums4 net failed.\n");
		goto out;
	}

	rc = register_pernet_subsys(&g_ums6_net_ops);
	if (rc != 0) {
		UMS_LOGE("register pernet ums6 net failed.\n");
		goto unregister_ums4;
	}

	return 0;

unregister_ums4:
	unregister_pernet_subsys(&g_ums4_net_ops);
out:
    return rc;
}

static void ums_dfx_exit(void)
{
	unregister_pernet_subsys(&g_ums6_net_ops);
	unregister_pernet_subsys(&g_ums4_net_ops);
}

static int __init ums_init_work_queue(void)
{
	int rc = -ENOMEM;

	g_ums_tcp_ls_wq = alloc_workqueue("g_ums_tcp_ls_wq", 0, 0);
	if (!g_ums_tcp_ls_wq)
		return rc;
	g_ums_hs_wq = alloc_workqueue("g_ums_hs_wq", 0, 0);
	if (!g_ums_hs_wq)
		goto ums_tcp_ls_wq_out;
	g_ums_close_wq = alloc_workqueue("g_ums_close_wq", 0, 0);
	if (!g_ums_close_wq)
		goto ums_hs_wq_out;

	return 0;

ums_hs_wq_out:
	destroy_workqueue(g_ums_hs_wq);
ums_tcp_ls_wq_out:
	destroy_workqueue(g_ums_tcp_ls_wq);
	return rc;
}

static void ums_destroy_work_queue(void)
{
	destroy_workqueue(g_ums_tcp_ls_wq);
	destroy_workqueue(g_ums_hs_wq);
	destroy_workqueue(g_ums_close_wq);
}

static int __init ums_sock_register(void)
{
	int rc = 0;

	rc = proto_register(&g_ums_proto, 1);
	if (rc != 0) {
		UMS_LOGE("proto registration failed with %d", rc);
		return rc;
	}
	rc = proto_register(&g_ums_proto6, 1);
	if (rc != 0) {
		UMS_LOGE("proto registration(v6) failed with %d", rc);
		goto proto_out;
	}
	rc = sock_register(&UMS_SOCK_FAMILY_OPS);
	if (rc != 0) {
		UMS_LOGE("sock register failed with %d", rc);
		goto proto6_out;
	}

	INIT_HLIST_HEAD(&g_ums_v4_hashinfo.ht);
	INIT_HLIST_HEAD(&g_ums_v6_hashinfo.ht);

	return 0;

proto6_out:
	proto_unregister(&g_ums_proto6);
proto_out:
	proto_unregister(&g_ums_proto);
	return rc;
}

static int __init ums_init_base(void)
{
	int rc = 0;
	rc = register_pernet_subsys(&g_ums_pernet_ops);
	if (rc != 0)
		return rc;
	ums_clc_init();

	rc = ums_pnet_init();
	if (rc != 0)
		goto pernet_subsys_out;

	rc = ums_init_work_queue();
	if (rc != 0)
		goto pnet_out;
	
	rc = ums_core_init();
	if (rc != 0) {
		UMS_LOGE_LIMITED("core initialization failed with %d", rc);
		goto destroy_work_queue;
	}
	rc = ums_llc_init();
	if (rc != 0) {
		UMS_LOGE_LIMITED("llc initialization failed with %d", rc);
		goto core_init_out;
	}
	rc = ums_cdc_init();
	if (rc != 0) {
		UMS_LOGE_LIMITED("cdc initialization failed with %d", rc);
		goto core_init_out;
	}
	rc = ums_sock_register();
	if (rc != 0) {
		goto core_init_out;
	}

	return 0;

core_init_out:
	ums_core_exit();
destroy_work_queue:
	ums_destroy_work_queue();
pnet_out:
	ums_pnet_exit();
pernet_subsys_out:
	unregister_pernet_subsys(&g_ums_pernet_ops);
	return rc;
}

static void ums_destroy_base(void)
{
	sock_unregister(AF_SMC);
	proto_unregister(&g_ums_proto6);
	proto_unregister(&g_ums_proto);
	ums_core_exit();
	ums_destroy_work_queue();
	ums_pnet_exit();
	unregister_pernet_subsys(&g_ums_pernet_ops);
}

static void ums_init_sys_config(void)
{
	if (ub_token_disable == 0) {
		g_ums_sys_tuning_config.ub_token_disable = false;
		UMS_LOGI_LIMITED("ub_token is enable");
	} else {
		g_ums_sys_tuning_config.ub_token_disable = true;
		UMS_LOGI_LIMITED("ub_token is disable");
	}
}

static int __init ums_init(void)
{
	int rc;
#if defined(UMS_TRACE)
	tracing_on();
#endif
	ums_init_sys_config();
	rc = ums_init_base();
	if (rc != 0)
		return rc;
	rc = ums_ubcore_register_client();
	if (rc != 0) {
		UMS_LOGE("ubcore register client fails with %d", rc);
		goto destroy_base;
	}

	rc = tcp_register_ulp(&g_ums_ulp_ops);
	if (rc != 0) {
		UMS_LOGE("tcp register ulp fails with %d", rc);
		goto ubcore_out;
	}

#if IS_ENABLED(CONFIG_SMC)
	static_branch_enable(&tcp_have_smc);
#endif

	rc = ums_dfx_init();
	if (rc != 0) {
		UMS_LOGE("dfx init fails with %d", rc);
		goto ulp_out;
	}

	return 0;

ulp_out:
	tcp_unregister_ulp(&g_ums_ulp_ops);
ubcore_out:
	ums_ubcore_unregister_client();
destroy_base:
	ums_destroy_base();
	return rc;
}

static void __exit ums_exit(void)
{
#if defined(UMS_TRACE)
	tracing_off();
#endif
	ums_dfx_exit();
#if IS_ENABLED(CONFIG_SMC)
	static_branch_disable(&tcp_have_smc);
#endif
	tcp_unregister_ulp(&g_ums_ulp_ops);
	sock_unregister(AF_SMC);
	ums_core_exit();
	ums_ubcore_unregister_client();
	destroy_workqueue(g_ums_close_wq);
	destroy_workqueue(g_ums_tcp_ls_wq);
	destroy_workqueue(g_ums_hs_wq);
	proto_unregister(&g_ums_proto6);
	proto_unregister(&g_ums_proto);
	ums_pnet_exit();
	ums_clc_exit();
	unregister_pernet_subsys(&g_ums_pernet_ops);
	rcu_barrier();
}

module_init(ums_init);
module_exit(ums_exit);

MODULE_AUTHOR("Yao");
MODULE_DESCRIPTION("ums implementation for AF_SMC address family");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(AF_SMC);
MODULE_ALIAS_TCP_ULP("ums");

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_close_non_accepted);
#endif
