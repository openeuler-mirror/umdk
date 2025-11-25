// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS public functions implementation
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *                based on prototype from Frank Blaschka
 *
 * UMS implementation:
 *     Author(s): Sunfang
 */

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/rcupdate_wait.h>
#include <linux/sched/signal.h>
#include <linux/socket.h>
#include <linux/swap.h>
#include <linux/workqueue.h>

#include "ums_core.h"
#include "ums_clc.h"
#include "ums_cdc.h"
#include "ums_log.h"
#include "ums_pnet.h"
#include "ums_common.h"

#define SK_FLAGS_UMS_TO_CLC                                                             \
	((1UL << SOCK_URGINLINE) | (1UL << SOCK_KEEPOPEN) | (1UL << SOCK_LINGER) |          \
		(1UL << SOCK_BROADCAST) | (1UL << SOCK_TIMESTAMP) | (1UL << SOCK_RCVTSTAMP) |   \
		(1UL << SOCK_RCVTSTAMPNS) | (1UL << SOCK_DBG) | (1UL << SOCK_LOCALROUTE) |      \
		(1UL << SOCK_TIMESTAMPING_RX_SOFTWARE) | (1UL << SOCK_RXQ_OVFL) |               \
		(1UL << SOCK_WIFI_STATUS) | (1UL << SOCK_NOFCS) | (1UL << SOCK_FILTER_LOCKED) | \
		(1UL << SOCK_TSTAMP_NEW))

void ums_conn_abort(struct ums_sock *ums, int local_first)
{
	struct ums_connection *conn = &ums->conn;
	struct ums_link_group *lgr = conn->lgr;
	bool lgr_valid = false;

	if (ums_conn_lgr_valid(conn))
		lgr_valid = true;

	ums_conn_free(conn);
	if ((local_first != 0) && lgr_valid)
		ums_lgr_cleanup_early(lgr);
}

void ums_copy_sock_settings(struct sock *dst_sk, struct sock *src_sk, unsigned long mask)
{
	/* options we don't get control via setsockopt for */
	dst_sk->sk_type = src_sk->sk_type;
	dst_sk->sk_sndbuf = src_sk->sk_sndbuf;
	dst_sk->sk_rcvbuf = src_sk->sk_rcvbuf;
	dst_sk->sk_sndtimeo = src_sk->sk_sndtimeo;
	dst_sk->sk_rcvtimeo = src_sk->sk_rcvtimeo;
	dst_sk->sk_mark = src_sk->sk_mark;
	dst_sk->sk_priority = src_sk->sk_priority;
	dst_sk->sk_rcvlowat = src_sk->sk_rcvlowat;
	dst_sk->sk_bound_dev_if = src_sk->sk_bound_dev_if;
	dst_sk->sk_err = src_sk->sk_err;
	dst_sk->sk_flags &= ~mask;
	dst_sk->sk_flags |= src_sk->sk_flags & mask;
	dst_sk->sk_userlocks = src_sk->sk_userlocks;
}

void ums_copy_conn_jetty_info(struct ums_sock *ums)
{
	struct ums_connection *conn = &ums->conn;
	if (conn->lnk && conn->lnk->ub_jetty && conn->lnk->ub_jetty->remote_jetty) {
		conn->jetty_info.l_jetty_id = conn->lnk->ub_jetty->jetty_id;
		conn->jetty_info.r_jetty_id = conn->lnk->ub_jetty->remote_jetty->cfg.id;
		conn->jetty_info.is_ums_conn = true;
	}
}

void ums_copy_sock_settings_to_clc(struct ums_sock *ums)
{
	ums_copy_sock_settings(ums->clcsock->sk, &ums->sk, (unsigned long)SK_FLAGS_UMS_TO_CLC);
}

static int ums_fback_mark_woken(wait_queue_entry_t *wait, unsigned int mode, int sync, void *key)
{
	struct ums_mark_woken *mark = container_of(wait, struct ums_mark_woken, wait_entry);

	mark->woken = true;
	mark->key = key;
	return 0;
}

/* must be called under rcu read lock */
static void ums_fback_wakeup_waitqueue(const struct ums_sock *ums, void *key)
{
	struct socket_wq *wq;
	__poll_t flags;

	wq = rcu_dereference(ums->sk.sk_wq);
	if (!skwq_has_sleeper(wq))
		return;

	/* wake up ums sk->sk_wq */
	if (!key) {
		/* sk_state_change */
		wake_up_interruptible_all(&wq->wait);
		return;
	}
	flags = key_to_poll(key);
	if ((flags & (EPOLLIN | EPOLLOUT)) != 0)
		/* sk_data_ready or sk_write_space */
		wake_up_interruptible_sync_poll(&wq->wait, flags);
	else if ((flags & EPOLLERR) != 0)
		/* sk_error_report */
		wake_up_interruptible_poll(&wq->wait, flags);
}

static void ums_fback_forward_wakeup(struct ums_sock *ums, struct sock *clcsk,
	void (*clcsock_callback)(struct sock *sk))
{
	struct ums_mark_woken mark;
	struct socket_wq *wq;

	mark.woken = false;
	init_waitqueue_func_entry(&mark.wait_entry, ums_fback_mark_woken);
	rcu_read_lock();
	wq = rcu_dereference(clcsk->sk_wq);
	if (!wq) {
		rcu_read_unlock();
		return;
	}
	add_wait_queue(sk_sleep(clcsk), &mark.wait_entry);
	clcsock_callback(clcsk);
	remove_wait_queue(sk_sleep(clcsk), &mark.wait_entry);
	if (mark.woken)
		ums_fback_wakeup_waitqueue(ums, mark.key);
	rcu_read_unlock();
}

static void ums_fback_state_change(struct sock *clcsk)
{
	struct ums_sock *ums;

	read_lock_bh(&clcsk->sk_callback_lock);
	ums = ums_clcsock_user_data(clcsk);
	if (ums)
		ums_fback_forward_wakeup(ums, clcsk, ums->clcsk_state_change);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void ums_fback_data_ready(struct sock *clcsk)
{
	struct ums_sock *ums;

	read_lock_bh(&clcsk->sk_callback_lock);
	ums = ums_clcsock_user_data(clcsk);
	if (ums)
		ums_fback_forward_wakeup(ums, clcsk, ums->clcsk_data_ready);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void ums_fback_write_space(struct sock *clcsk)
{
	struct ums_sock *ums;

	read_lock_bh(&clcsk->sk_callback_lock);
	ums = ums_clcsock_user_data(clcsk);
	if (ums)
		ums_fback_forward_wakeup(ums, clcsk, ums->clcsk_write_space);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void ums_fback_error_report(struct sock *clcsk)
{
	struct ums_sock *ums;

	read_lock_bh(&clcsk->sk_callback_lock);
	ums = ums_clcsock_user_data(clcsk);
	if (ums)
		ums_fback_forward_wakeup(ums, clcsk, ums->clcsk_error_report);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void ums_fback_replace_callbacks(struct ums_sock *ums)
{
	struct sock *clcsk = ums->clcsock->sk;

	write_lock_bh(&clcsk->sk_callback_lock);
	clcsk->sk_user_data = (void *)((uintptr_t)ums | SK_USER_DATA_NOCOPY);

	ums_clcsock_replace_cb(&clcsk->sk_state_change, ums_fback_state_change,
		&ums->clcsk_state_change);
	ums_clcsock_replace_cb(&clcsk->sk_data_ready, ums_fback_data_ready, &ums->clcsk_data_ready);
	ums_clcsock_replace_cb(&clcsk->sk_write_space, ums_fback_write_space, &ums->clcsk_write_space);
	ums_clcsock_replace_cb(&clcsk->sk_error_report, ums_fback_error_report,
		&ums->clcsk_error_report);

	write_unlock_bh(&clcsk->sk_callback_lock);
}

int ums_switch_to_fallback(struct ums_sock *ums, int reason_code)
{
	int rc = 0;

	down_read(&ums->clcsock_release_lock);
	if (!ums->clcsock) {
		rc = -EBADF;
		goto out;
	}

	ums->use_fallback = true;
	ums->fallback_rsn = reason_code;

	UMS_LOGE("switch to fall back with reason code: %x", (u32)reason_code);
	if (ums->sk.sk_socket && ums->sk.sk_socket->file) {
		ums->clcsock->file = ums->sk.sk_socket->file;
		ums->clcsock->file->private_data = ums->clcsock;
#ifdef KERNEL_VERSION_4
		ums->clcsock->wq->fasync_list = ums->sk.sk_socket->wq->fasync_list;
#else
		ums->clcsock->wq.fasync_list = ums->sk.sk_socket->wq.fasync_list;
#endif
		/* restore sk_reuse which is SK_CAN_REUSE */
		ums->clcsock->sk->sk_reuse = ums->sk.sk_reuse;

		/* There might be some wait entries remaining in ums sk->sk_wq and they should be woken up
		 * as clcsock's wait queue is woken up. */
		ums_fback_replace_callbacks(ums);
	}
out:
	up_read(&ums->clcsock_release_lock);
	return rc;
}

void ums_conn_save_peer_info(struct ums_sock *ums, struct ums_clc_msg_accept_confirm *clc)
{
	int bufsize = ums_uncompress_bufsize(clc->r0.rmbe_size);

	ums->conn.peer_rmbe_idx = clc->r0.rmbe_idx;
	ums->conn.local_tx_ctrl.token = ntohl(clc->r0.rmbe_alert_token);
	ums->conn.peer_rmbe_size = bufsize;
	atomic_set(&ums->conn.peer_rmbe_space, ums->conn.peer_rmbe_size);
	ums->conn.tx_off = (u32)(bufsize * (ums->conn.peer_rmbe_idx - 1));
	UMS_LOGI_LIMITED("local conn %u bounded to remote conn %u", ums->conn.conn_id,
		ums->conn.local_tx_ctrl.token);
}

void ums_link_save_peer_info(struct ums_link *link,
	struct ums_clc_msg_accept_confirm *clc, struct ums_init_info *ini)
{
	struct ubcore_device *ub_dev = link->ums_dev->ub_dev;

	link->tjetty_id = ntohl(clc->r0.jetty_id);
	(void)memcpy(link->peer_eid.raw, ini->peer_eid.raw, UMS_EID_SIZE);
	(void)memcpy(link->peer_mac, ini->peer_mac, ETH_ALEN);
	link->peer_psn = ntoh24(clc->r0.psn);
	link->peer_mtu = clc->r0.qp_mtu;
	link->credits_enable = clc->r0.init_credits != 0 ? 1 : 0;
	if (link->credits_enable != 0)
		atomic_set(&link->peer_rq_credits, clc->r0.init_credits);

	(void)memset(&link->ub_tjetty_cfg.id, 0, sizeof(struct ubcore_jetty_id));
	(void)memset(&link->ub_tjetty_cfg, 0, sizeof(struct ubcore_tjetty_cfg));
	link->ub_tjetty_cfg.id.eid = ini->peer_eid;
	link->ub_tjetty_cfg.eid_index = ini->eid_index; /* local eid_index, not the peer eid_index */
	link->ub_tjetty_cfg.id.id = ini->tjetty_id;
	link->ub_tjetty_cfg.trans_mode = UBCORE_TP_RC;

	if ((ub_dev != NULL) && (ub_dev->transport_type == UBCORE_TRANSPORT_UB)) {
		link->ub_tjetty_cfg.flag.bs.order_type = UBCORE_OL; /* low layer ordering */
		link->ub_tjetty_cfg.flag.bs.share_tp = 1;
		link->ub_tjetty_cfg.flag.bs.token_policy = clc->r0.jetty_token_policy;
		link->ub_tjetty_cfg.token_value.token = ntohl(clc->r0.jetty_token_value);
		link->ub_tjetty_cfg.type = UBCORE_JETTY;
		link->ub_tjetty_cfg.tp_type = UBCORE_CTP;
	}
}

/* check if there is a ub device available for this connection. */
/* called for connect and listen */
int ums_find_ub_device(struct ums_sock *ums, struct ums_init_info *ini)
{
	/* PNET table look up: search active ub_device and port
	 * within same PNETID that also contains the ethernet device
	 * used for the internal TCP socket
	 */
	ums_pnet_find_ub_resource(ums->clcsock->sk, ini);
	if (!ini->ub_dev) {
		UMS_LOGE("find ub device failed, vlan is %hu.\n", ini->vlan_id);
		return UMS_CLC_DECL_NOUMSDEV;
	}

	return 0;
}
