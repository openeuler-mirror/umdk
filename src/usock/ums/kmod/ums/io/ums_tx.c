// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS data-plane transport(tx) implementation
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#include <net/sock.h>
#include <net/tcp.h>

#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/workqueue.h>

#include <ub/urma/ubcore_types.h>
#include "ums_cdc.h"
#include "ums_close.h"
#include "ums_log.h"
#include "ums_mod.h"
#include "ums_wr.h"
#include "ums_tx.h"

#define UMS_TX_WORK_DELAY	0
#define UMS_CHUNK_MAX 2
#define UMS_ONE_HALF 2

struct ums_tx_sendmsg_len_status {
	int copylen;
	int send_remaining;
	int send_done;
	bool send_break;
};

struct ums_tx_ub_write_len_status {
	size_t len;
	size_t src_off;
	size_t src_len;
	size_t dst_off;
	size_t dst_len;
	int to_send;
	int rmbe_space;
};

struct ums_tx_ub_write_imm_info {
	size_t len;
	int peer_rmbe_offset;
	int num_sges;
	int skip_flag; /* 1 means we need Two WRITES for a send */
};

/***************************** sndbuf producer *******************************/

/* callback implementation for sk.sk_write_space()
 * to wakeup sndbuf producers that blocked with ums_tx_wait().
 * called under sk_socket lock.
 */
static void ums_tx_write_space(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	struct ums_sock *ums = ums_sk(sk);
	struct socket_wq *wq;

	/* similar to sk_stream_write_space */
	if ((atomic_read(&ums->conn.sndbuf_space) != 0) && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);
		rcu_read_lock();
		wq = rcu_dereference(sk->sk_wq);
		if (skwq_has_sleeper(wq))
			wake_up_interruptible_poll(&wq->wait, EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND);
		if (wq && wq->fasync_list && ((sk->sk_shutdown & SEND_SHUTDOWN) == 0))
			(void)sock_wake_async(wq, SOCK_WAKE_SPACE, POLL_OUT);
		rcu_read_unlock();
	}
}

/* Wakeup sndbuf producers that blocked with ums_tx_wait().
 * Cf. tcp_data_snd_check()=>tcp_check_space()=>tcp_new_space().
 */
void ums_tx_sndbuf_nonfull(struct ums_sock *ums)
{
	if (ums->sk.sk_socket &&
	    test_bit(SOCK_NOSPACE, &ums->sk.sk_socket->flags))
		ums->sk.sk_write_space(&ums->sk);
}

/* blocks sndbuf producer until at least one byte of free space available
 * or urgent Byte was consumed
 */
static int ums_tx_wait(struct ums_sock *ums, long *timeo)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	struct ums_connection *conn = &ums->conn;
	struct sock *sk = &ums->sk;
	int rc = 0;

	/* similar to sk_stream_wait_memory */
	add_wait_queue(sk_sleep(sk), &wait);
	while (1) {
		sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
		if ((sk->sk_err != 0) || ((sk->sk_shutdown & SEND_SHUTDOWN) != 0) || (conn->killed != 0) ||
			(conn->local_tx_ctrl.conn_state_flags.peer_done_writing != 0)) {
			rc = -EPIPE;
			break;
		}
		if (ums_cdc_rxed_any_close(conn)) {
			rc = -ECONNRESET;
			break;
		}
		if (*timeo == 0) {
			/* ensure EPOLLOUT is subsequently generated */
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			rc = -EAGAIN;
			break;
		}
		if (signal_pending(current) != 0) {
			rc = sock_intr_errno(*timeo);
			break;
		}
		sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);
		if ((atomic_read(&conn->sndbuf_space) != 0) && !conn->urg_tx_pend)
			break; /* at least 1 byte of free & no urgent data */
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk_wait_event(sk, timeo, (sk->sk_err != 0) || ((sk->sk_shutdown & SEND_SHUTDOWN) != 0) ||
			ums_cdc_rxed_any_close(conn) || ((atomic_read(&conn->sndbuf_space) != 0) &&
			!conn->urg_tx_pend), &wait);
	}
	remove_wait_queue(sk_sleep(sk), &wait);
	return rc;
}

static bool ums_tx_is_corked(struct ums_sock *ums)
{
	struct tcp_sock *tp = tcp_sk(ums->clcsock->sk);

	return (tp->nonagle & TCP_NAGLE_CORK) != 0 ? true : false;
}

/* If we have pending CDC messages, do not send:
 * Because CQE of this CDC message will happen shortly, it gives
 * a chance to coalesce future sendmsg() payload in to one Write,
 * without need for a timer, and with no latency trade off.
 * Algorithm here:
 *  1. First message should never cork
 *  2. If we have pending Tx CDC messages, wait for the first CDC
 *     message's completion
 *  3. Don't cork to much data in a single Write to prevent burst
 *     traffic, total corked message should not exceed sendbuf/2
 */
static bool ums_should_autocork(struct ums_sock *ums)
{
	struct ums_connection *conn = &ums->conn;
	int corking_size;

	corking_size = min_t(unsigned int, ((u32)conn->sndbuf_desc->len) >> 1, ums->autocorking_size);

	if ((atomic_read(&conn->conn_pend_tx_wr) == 0) || (ums_tx_prepared_sends(conn) > corking_size))
		return false;
	return true;
}

static inline bool ums_is_msg_sendpage_notlast(const struct msghdr *msg)
{
#ifdef MSG_SENDPAGE_NOTLAST
    return ((msg->msg_flags & MSG_SENDPAGE_NOTLAST) != 0);
#else
    return false;
#endif
}

static bool ums_tx_should_cork(struct ums_sock *ums, const struct msghdr *msg)
{
	struct ums_connection *conn = &ums->conn;

	if (ums_should_autocork(ums))
		return true;

	/* for a corked socket defer the writes if
	 * sndbuf_space is still available. The applications
	 * should known how/when to uncork it.
	 */
	if ((((msg->msg_flags & MSG_MORE) != 0) || ums_tx_is_corked(ums) ||
		ums_is_msg_sendpage_notlast(msg)) && (atomic_read(&conn->sndbuf_space) != 0))
		return true;

	return false;
}

static int ums_tx_sendmsg_do(struct ums_sock *ums, struct msghdr *msg,
	union ums_host_cursor *prep, struct ums_tx_sendmsg_len_status *len_status)
{
	size_t chunk_len, chunk_off, chunk_len_sum;
	struct ums_connection *conn = &ums->conn;
	int chunk, writespace;
	char *sndbuf_base;

	/* initialize variables for 1st iteration of subsequent loop */
	/* could be just 1 byte, even after ums_tx_wait above */
	writespace = atomic_read(&conn->sndbuf_space);
	if (writespace <= 0)
		return -1;
	/* not more than what user space asked for */
	len_status->copylen = min_t(int, len_status->send_remaining, writespace);
	/* determine start of sndbuf */
	sndbuf_base = conn->sndbuf_desc->cpu_addr;
	ums_curs_copy(prep, &conn->tx_curs_prep, conn);
	/* determine chunks where to write into sndbuf */
	/* either unwrapped case, or 1st chunk of wrapped case */
	chunk_len = min_t(size_t, (u32)len_status->copylen, ((u32)conn->sndbuf_desc->len) - prep->count);
	chunk_len_sum = chunk_len;
	chunk_off = prep->count;
	for (chunk = 0; chunk < UMS_CHUNK_MAX; chunk++) {
		if (memcpy_from_msg(sndbuf_base + chunk_off, msg, (int)chunk_len) != 0) {
			if (len_status->send_done != 0)
				len_status->send_break = true;
			return -1;
		}
		len_status->send_done += (int)chunk_len;
		len_status->send_remaining -= (int)chunk_len;
		/* either on 1st or 2nd iteration */
		if (chunk_len_sum == (u32)len_status->copylen)
			break;
		/* prepare next (== 2nd) iteration */
		/* remainder */
		chunk_len = ((u32)len_status->copylen) - chunk_len;
		chunk_len_sum += chunk_len;
		chunk_off = 0; /* modulo offset in send ring buffer */
	}

	return 0;
}

static void ums_tx_len_status_init(struct ums_tx_sendmsg_len_status *len_status, size_t len)
{
	len_status->copylen = 0;
	len_status->send_remaining = (int)len;
	len_status->send_done = 0;
	len_status->send_break = false;
}

/* sndbuf producer: main API called by socket layer.
 * called under sock lock.
 */
int ums_tx_sendmsg(struct ums_sock *ums, struct msghdr *msg, size_t len)
{
	struct ums_tx_sendmsg_len_status len_status;
	struct ums_connection *conn = &ums->conn;
	union ums_host_cursor prep;
	struct sock *sk = &ums->sk;
	int rc = 0;
	long timeo;

	if (len > INT_MAX) {
		UMS_LOGE("The length of the data to be sent exceeds the limit");
		return -EMSGSIZE;
	}

	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	ums_tx_len_status_init(&len_status, len);
	/* This should be in poll */
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if ((sk->sk_err != 0) || ((sk->sk_shutdown & SEND_SHUTDOWN) != 0)) {
		rc = -EPIPE;
		goto out_err;
	}

	if (sk->sk_state == (unsigned char)UMS_INIT)
		return -ENOTCONN;

	ums_conn_tx_rx_refcnt_inc(conn);
	if (conn->freed != 0) {
		ums_conn_tx_rx_refcnt_dec(conn);
		return -EPIPE;
	}

	while (msg_data_left(msg) > 0) {
		if (((ums->sk.sk_shutdown & SEND_SHUTDOWN) != 0) ||
			(ums->sk.sk_err == ECONNABORTED) ||
			(conn->killed != 0)) {
			ums_conn_tx_rx_refcnt_dec(conn);
			return -EPIPE;
		}
		if (ums_cdc_rxed_any_close(conn)) {
			ums_conn_tx_rx_refcnt_dec(conn);
			return (int)(len_status.send_done != 0 ? len_status.send_done : -ECONNRESET);
		}
		if ((msg->msg_flags & MSG_OOB) != 0)
			conn->local_tx_ctrl.prod_flags.urg_data_pending = 1;

		if ((atomic_read(&conn->sndbuf_space) == 0) || conn->urg_tx_pend) {
			if ((timeo == 0) && (len_status.send_done != 0)) { /* for non-block socket */
				ums_conn_tx_rx_refcnt_dec(conn);
				return (int)len_status.send_done;
			}
			rc = ums_tx_wait(ums, &timeo);
			if (rc != 0)
				goto out_err_after_ref_inc;
			continue;
		}
		if (ums_tx_sendmsg_do(ums, msg, &prep, &len_status) != 0) {
			if (len_status.send_break) {
				ums_conn_tx_rx_refcnt_dec(conn);
				return (int)len_status.send_done;
			}
			goto out_err_after_ref_inc;
		}
		
		/* update cursors */
		ums_curs_add(conn->sndbuf_desc->len, &prep, (int)len_status.copylen);
		ums_curs_copy(&conn->tx_curs_prep, &prep, conn);
		/* increased in send tasklet ums_cdc_tx_handler() */
		smp_mb__before_atomic();
		/* guarantee 0 <= sndbuf_space <= sndbuf_desc->len */
		atomic_sub((int)len_status.copylen, &conn->sndbuf_space);
		smp_mb__after_atomic();

		/* since we just produced more new data into sndbuf,
		 * trigger sndbuf consumer:write into peer RMBE and CDC
		 */
		if (((msg->msg_flags & MSG_OOB) != 0) && (len_status.send_remaining == 0))
			conn->urg_tx_pend = true;
		/* If we need to cork, do nothing and wait for the next
		 * sendmsg() call or push on tx completion
		 */
		if (!ums_tx_should_cork(ums, msg)) {
			conn->tx_bytes += (u64)len_status.copylen;
			++conn->tx_cnt;
			(void)ums_tx_sndbuf_nonempty(conn);
		} else {
			conn->tx_corked_bytes += (u64)len_status.copylen;
			++conn->tx_corked_cnt;
		}
	} /* while (msg_data_left(msg)) */

	ums_conn_tx_rx_refcnt_dec(conn);
	return (int)len_status.send_done;

out_err_after_ref_inc:
	ums_conn_tx_rx_refcnt_dec(conn);
out_err:
	rc = sk_stream_error(sk, (int)msg->msg_flags, rc);
	if (unlikely(rc == -EAGAIN)) /* make sure we wake any epoll edge trigger waiter */
		sk->sk_write_space(sk);
	return rc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
int ums_tx_sendpage(struct ums_sock *ums, struct page *page, int offset, size_t size, int flags)
{
	struct msghdr msg = { .msg_flags = (u32)flags };
	char *kaddr = kmap(page);
	struct kvec iov;
	int rc;

	iov.iov_base = kaddr + offset;
	iov.iov_len = size;
#ifdef KERNEL_VERSION_4
	iov_iter_kvec(&msg.msg_iter, WRITE | ITER_KVEC, &iov, 1, size);
#else
	iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, size);
#endif
	rc = ums_tx_sendmsg(ums, &msg, size);
	kunmap(page);
	return rc;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0) */

/***************************** sndbuf consumer *******************************/

static inline void ums_imm_add_pending_send(struct ums_connection *conn,
	struct ums_imm_tx_pend *pend)
{
	BUILD_BUG_ON_MSG(
		sizeof(struct ums_imm_tx_pend) > UMS_WR_TX_PEND_PRIV_SIZE,
		"must increase UMS_WR_TX_PEND_PRIV_SIZE to at least sizeof(struct ums_imm_tx_pend)");

	/* set pend states */

	pend->conn = conn;
	pend->cursor = conn->tx_curs_sent;
	pend->p_cursor = conn->local_tx_ctrl.prod;
}

/* sndbuf consumer */
static inline void ums_tx_advance_cursors(struct ums_connection *conn, union ums_host_cursor *prod,
	union ums_host_cursor *sent, size_t len)
{
	ums_curs_add(conn->peer_rmbe_size, prod, (int)len);
	/* increased in recv tasklet ums_cdc_msg_rcv() */
	smp_mb__before_atomic();
	/* data in flight reduces usable snd_wnd */
	atomic_sub((int)len, &conn->peer_rmbe_space);
	/* guarantee 0 <= peer_rmbe_space <= peer_rmbe_size */
	smp_mb__after_atomic();
	ums_curs_add(conn->sndbuf_desc->len, sent, (int)len);
}

static inline void ums_update_tx_pi(struct ums_connection *conn, size_t len)
{
	union ums_host_cursor sent, prod;
	ums_curs_copy(&prod, &conn->local_tx_ctrl.prod, conn);
	ums_curs_copy(&sent, &conn->tx_curs_sent, conn);
	ums_tx_advance_cursors(conn, &prod, &sent, len);
	ums_curs_copy(&conn->local_tx_ctrl.prod, &prod, conn); /* dst: peer RMBE */
	ums_curs_copy(&conn->tx_curs_sent, &sent, conn); /* src: local sndbuf */
}

static inline u32 ums_get_imm(struct ums_connection *conn, int skip_flag)
{
	struct ums_link *link = conn->lnk;
	u8 saved_credits = 0;
	union ums_imm imm;

	/* in DMS, we store conn->token, credit and write_blocked in the IMM */
	imm.write_blocked = conn->local_tx_ctrl.prod_flags.write_blocked;
	imm.skip_flag = ((u32)skip_flag) & 0x1;
	imm.token = conn->local_tx_ctrl.token & UMS_CONN_ID_MASK;
	if (ums_wr_rx_credits_need_announce_frequent(link))
		saved_credits = (u8)ums_wr_rx_get_credits(link);
	imm.credits = saved_credits;

	return imm.data;
}

/* sndbuf consumer: actual data transfer of one target chunk when skipping the dst ring buffer */
static int ums_tx_ub_write(struct ums_connection *conn, int peer_rmbe_offset, int num_sges,
	struct ubcore_jfs_wr *wr)
{
	struct ums_link *link = conn->lnk;
	struct ubcore_jetty *jetty = link->ub_jetty;
	struct ubcore_jfs_wr *bad_wr = NULL;
	int rc;

	/* if peer freed connection */
	if (!conn->tseg || (conn->tseg->seg.ubva.va == 0)) {
		UMS_LOGE("unexpected sends during connection termination flow");
		return -EINVAL;
	}

	wr->user_ctx = (uint64_t)ums_wr_tx_get_next_wr_id(link);
	wr->rw.src.num_sge = (uint32_t)num_sges;
	wr->rw.dst.sge->addr = conn->tseg->seg.ubva.va +
		/* RMBE within RMB */
		conn->tx_off +
		/* offset within RMBE */
		((u32)peer_rmbe_offset);
	wr->rw.dst.sge->tseg = conn->tseg;
	wr->rw.dst.num_sge = 1;
	/* wr_id is set in get_free_slot */
	wr->tjetty = link->ub_tjetty;

	rc = ubcore_post_jetty_send_wr(jetty, wr, &bad_wr);
	if (rc != 0) {
		UMS_LOGE("failed to post jetty send wr, wr id is %llu", wr->user_ctx);
		ums_link_down_cond_sched(link);
	}
	return rc;
}

/* sndbuf consumer: actual data transfer of one target chunk with write */
static int ums_tx_ub_write_imm(struct ums_connection *conn,
	struct ums_tx_ub_write_imm_info *wr_info, struct ubcore_jfs_wr *wr,
	struct ums_imm_tx_pend *pend)
{
	struct ubcore_jetty *jetty = conn->lnk->ub_jetty;
	struct ubcore_jfs_wr *bad_wr = NULL;
	struct ums_link *link = conn->lnk;
	int rc;

	/* if peer freed connection */
	if (!conn->tseg || (conn->tseg->seg.ubva.va == 0)) {
		UMS_LOGE("unexpected sends during connection termination flow");
		return -EINVAL;
	}

	wr->rw.src.num_sge = (uint32_t)wr_info->num_sges;
	wr->rw.dst.sge->addr = conn->tseg->seg.ubva.va +
		/* RMBE within RMB */
		conn->tx_off +
		/* offset within RMBE */
		((u32)wr_info->peer_rmbe_offset);
	wr->rw.dst.sge->tseg = conn->tseg;
	wr->rw.dst.num_sge = 1;
	/* wr_id is set in get_free_slot */
	wr->rw.notify_data = ums_get_imm(conn, wr_info->skip_flag);
	wr->tjetty = link->ub_tjetty;

	ums_update_tx_pi(conn, wr_info->len);
	ums_imm_add_pending_send(conn, pend);
	atomic_inc(&conn->conn_pend_tx_wr);
	smp_mb__after_atomic(); /* Make sure conn_pend_tx_wr added before post */

	rc = ubcore_post_jetty_send_wr(jetty, wr, &bad_wr);
	if (rc != 0) {
		UMS_LOGE("failed to post jetty send wr WRITE_WITH_IMM, wr id is %llu", wr->user_ctx);
		ums_link_down_cond_sched(link);
		if (atomic_dec_and_test(&conn->conn_pend_tx_wr))
			wake_up(&conn->conn_pend_tx_wq);
	}
	return rc;
}

/* UMS helper for construc sge and update states */
static int ums_tx_ub_prepare(struct ums_connection *conn,
	struct ums_tx_ub_write_len_status *len_status, struct ubcore_jfs_wr *wr)
{
	struct ubcore_sge *src_sge = wr->rw.src.sge;
	size_t src_len = len_status->src_len;
	size_t src_off = len_status->src_off;
	struct ums_link *link = conn->lnk;
	size_t src_len_sum = src_len;
	int num_sges = 0;
	int srcchunk;

	for (srcchunk = 0; srcchunk < UMS_CHUNK_MAX; srcchunk++) {
		src_sge[srcchunk].addr = ((uintptr_t)conn->sndbuf_desc->cpu_addr + src_off);
		src_sge[srcchunk].len = (uint32_t)src_len;

		src_sge[srcchunk].tseg = conn->sndbuf_desc->seg[link->link_idx];
		num_sges++;

		src_off += src_len;
		if (src_off >= (u32)conn->sndbuf_desc->len)
			src_off -= (size_t)conn->sndbuf_desc->len;
					/* modulo in send ring */
		/* either on 1st or 2nd iteration */
		if (src_len_sum == len_status->dst_len)
			break;
		/* prepare next (== 2nd) iteration */
		src_len = len_status->dst_len - src_len; /* remainder */
		src_len_sum += src_len;
	}
	return num_sges;
}

/* in urgent case, we need a write + CDC msg combination */
static inline int ums_tx_ub_urgent_write(struct ums_connection *conn,
	struct ums_tx_ub_write_len_status *local_len, struct ubcore_jfs_wr *wr_write_buf)
{
	struct ubcore_sge dst_sge;
	struct ubcore_jfs_wr *wr;
	int num_sges;

	dst_sge.len = (uint32_t)local_len->dst_len;
	wr = wr_write_buf;
	wr->rw.dst.sge = &dst_sge;
	num_sges = ums_tx_ub_prepare(conn, local_len, wr);
	return ums_tx_ub_write(conn, (int)local_len->dst_off, num_sges, wr);
}

/* UMS helper for ums_tx_ub_writes() */
static int ums_tx_ub_writes_inner(struct ums_connection *conn,
	const struct ums_tx_ub_write_len_status *len_status, struct ubcore_jfs_wr *wr_ub_buf,
	struct ums_imm_tx_pend *pend)
{
	struct ums_tx_ub_write_len_status local_len = *len_status;
	struct ums_tx_ub_write_imm_info wr_info;
	size_t remaining_len = local_len.len;
	struct ubcore_sge dst_sge;
	struct ubcore_jfs_wr *wr;
	int rc;

	wr_info.skip_flag = 0;
	/* we need a WIRTE + a WRITE_WITH_IMM in this case */
	if (local_len.dst_len < local_len.len) {
		dst_sge.len = (uint32_t)local_len.dst_len;
		wr = conn->wr_write_buf;
		wr->rw.dst.sge = &dst_sge;
		wr_info.num_sges = ums_tx_ub_prepare(conn, &local_len, wr);
		rc = ums_tx_ub_write(conn, (int)local_len.dst_off, wr_info.num_sges, wr);
		if (rc != 0)
			return rc;
		/* prepare next (== 2nd) iteration */

		remaining_len -= local_len.dst_len;
		local_len.src_off += local_len.dst_len;
		if (local_len.src_off >= (u32)conn->sndbuf_desc->len)
			local_len.src_off -= (size_t)conn->sndbuf_desc->len;
		local_len.src_len = min_t(size_t, remaining_len,
			((u32)conn->sndbuf_desc->len) - local_len.src_off);
		local_len.dst_off = 0;
		local_len.dst_len = remaining_len; /* remainder */
		wr_info.skip_flag = 1;
	}

	if (unlikely(conn->urg_tx_pend)) {
		return ums_tx_ub_urgent_write(conn, &local_len, wr_ub_buf);
	} else {
		dst_sge.len = (uint32_t)local_len.dst_len;
		wr = wr_ub_buf;
		wr->rw.dst.sge = &dst_sge;
		wr_info.num_sges = ums_tx_ub_prepare(conn, &local_len, wr);

		wr_info.peer_rmbe_offset = (int)local_len.dst_off;
		wr_info.len = local_len.len;
		rc = ums_tx_ub_write_imm(conn, &wr_info, wr, pend);
	}
	return rc;
}

/* sndbuf consumer: prepare all necessary (src&dst) chunks of data transmit;
 * usable snd_wnd as max transmit
 */
static int ums_tx_ub_writes(struct ums_connection *conn, struct ubcore_jfs_wr *wr_ub_buf,
	struct ums_imm_tx_pend *pend)
{
	struct ums_tx_ub_write_len_status len_status; /* current chunk values */
	union ums_host_cursor sent, prep, prod, cons;
	struct ums_cdc_producer_flags *pflags;
	int rc;

	/* source: sndbuf */
	ums_curs_copy(&sent, &conn->tx_curs_sent, conn);
	ums_curs_copy(&prep, &conn->tx_curs_prep, conn);
	/* cf. wmem_alloc - (snd_max - snd_una) */
	len_status.to_send = ums_curs_diff((unsigned int)conn->sndbuf_desc->len, &sent, &prep);
	if (len_status.to_send <= 0)
		return 0;

	/* cf. snd_wnd */
	/* destination: RMBE */
	len_status.rmbe_space = atomic_read(&conn->peer_rmbe_space);
	if (len_status.rmbe_space <= 0)
		return 0;

	ums_curs_copy(&prod, &conn->local_tx_ctrl.prod, conn);
	ums_curs_copy(&cons, &conn->local_rx_ctrl.cons, conn);

	/* if usable snd_wnd closes ask peer to advertise once it opens again */
	pflags = &conn->local_tx_ctrl.prod_flags;
	pflags->write_blocked = (len_status.to_send >= len_status.rmbe_space);
	/* cf. usable snd_wnd */
	len_status.len = (size_t)min(len_status.to_send, len_status.rmbe_space);
	/* initialize variables for first iteration of subsequent nested loop */
	len_status.dst_off = prod.count;
	if (prod.wrap == cons.wrap) {
		/* the filled destination area is unwrapped,
		 * hence the available free destination space is wrapped
		 * we need 2 destination chunks of sum len; start with 1st
		 * which is limited by what's available in sndbuf
		 */
		len_status.dst_len = min_t(size_t, ((size_t)conn->peer_rmbe_size - prod.count),
			len_status.len);
	} else {
		/* the filled destination area is wrapped,
		 * hence the available free destination space is unwrapped
		 * we need a single destination chunk of entire len
		 */
		len_status.dst_len = len_status.len;
	}
	/* maximum src_len is determined by dst_len */
	if (sent.count + len_status.dst_len <= (u32)conn->sndbuf_desc->len) {
		/* unwrapped src case:
		 * single chunk of entire dst_len
		 */
		len_status.src_len = len_status.dst_len;
	} else {
		/* wrapped src case:
		 * 2 chunks of sum dst_len; start with 1st:
		 */
		len_status.src_len = ((u32)conn->sndbuf_desc->len) - sent.count;
	}
	len_status.src_off = sent.count;

	rc = ums_tx_ub_writes_inner(conn, &len_status, wr_ub_buf, pend);
	if (rc != 0)
		return rc;

	if (conn->urg_tx_pend && len_status.dst_len == ((u32)len_status.to_send)) {
		pflags->urg_data_present = 1;

		ums_tx_advance_cursors(conn, &prod, &sent, len_status.dst_len);
		ums_curs_copy(&conn->local_tx_ctrl.prod, &prod, conn);
		ums_curs_copy(&conn->tx_curs_sent, &sent, conn);
	}

	return 0;
}

static int ums_tx_handle_get_free_slot_err(struct ums_connection *conn, int err_code)
{
	struct ums_link *link = conn->lnk;
	int rc = err_code;

	UMS_LOGW_LIMITED("cannot get free slot, peer_credit=%d, local_credit=%d",
			atomic_read(&link->peer_rq_credits), atomic_read(&link->local_rq_credits));
	ums_wr_tx_link_put(link);
	if (rc == -EBUSY) {
		struct ums_sock *ums = container_of(conn, struct ums_sock, conn);

		if (ums->sk.sk_err == ECONNABORTED)
			return sock_error(&ums->sk);
		if (conn->killed != 0)
			return -EPIPE;
		rc = 0;
		UMS_LOGW_LIMITED("delay work due to no credit");
		(void)mod_delayed_work(conn->lgr->tx_wq, &conn->tx_work, UMS_TX_WORK_DELAY);
	}

	return rc;
}

static int ums_tx_urgent_sendbuf_noempty(struct ums_connection *conn)
{
	struct ums_cdc_producer_flags *pflags = &conn->local_tx_ctrl.prod_flags;
	struct ums_link *link = conn->lnk;
	struct ubcore_jfs_wr *wr_ub_buf;
	struct ums_cdc_tx_pend *pend;
	struct ums_wr_buf *wr_buf;
	int rc;

	rc = ums_urg_get_free_slot(conn, link, &wr_buf, &wr_ub_buf, &pend);
	if (rc < 0)
		return ums_tx_handle_get_free_slot_err(conn, rc);

	spin_lock_bh(&conn->send_lock);
	if (link != conn->lnk) {
		/* link of connection changed, tx_work will restart */
		(void)ums_wr_tx_put_slot(link, (struct ums_wr_tx_pend_priv *)pend);
		rc = -ENOLINK;
		goto out_unlock;
	}

	if (pflags->urg_data_present == 0) {
		rc = ums_tx_ub_writes(conn, wr_ub_buf, NULL);
		if (rc != 0) {
			(void)ums_wr_tx_put_slot(link, (struct ums_wr_tx_pend_priv *)pend);
			goto out_unlock;
		}
	}

	rc = ums_cdc_msg_send(conn, wr_buf, pend);
	if (rc == 0 && pflags->urg_data_present == 1) {
		pflags->urg_data_pending = 0;
		pflags->urg_data_present = 0;
	}

out_unlock:
	spin_unlock_bh(&conn->send_lock);
	ums_wr_tx_link_put(link);
	return rc;
}

/* Wakeup sndbuf consumers from any context (IRQ or process)
 * since there is more data to transmit; usable snd_wnd as max transmit
 */
static int ums_tx_sndbuf_nonempty_handler(struct ums_connection *conn)
{
	struct ums_link *link = conn->lnk;
	struct ubcore_jfs_wr *wr_ub_buf;
	struct ums_imm_tx_pend *pend;
	int rc;

	if (!link || !ums_wr_tx_link_hold(link))
		return -ENOLINK;

	if (unlikely(conn->urg_tx_pend))
		return ums_tx_urgent_sendbuf_noempty(conn);

	rc = ums_imm_get_free_slot(conn, link, &wr_ub_buf, &pend);
	if (rc < 0)
		return ums_tx_handle_get_free_slot_err(conn, rc);

	spin_lock_bh(&conn->send_lock);
	if (link != conn->lnk) {
		/* link of connection changed, tx_work will restart */
		(void)ums_wr_tx_put_slot(link, (struct ums_wr_tx_pend_priv *)pend);
		rc = -ENOLINK;
		goto out_unlock;
	}
	
	rc = ums_tx_ub_writes(conn, wr_ub_buf, pend);
	if (rc != 0) {
		(void)ums_wr_tx_put_slot(link, (struct ums_wr_tx_pend_priv *)pend);
		goto out_unlock;
	}

out_unlock:
	spin_unlock_bh(&conn->send_lock);
	ums_wr_tx_link_put(link);
	return rc;
}

static int ums_tx_sndbuf_nonempty_inner(struct ums_connection *conn)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);
	int rc = 0;

	/* No data in the send queue */
	if (unlikely(ums_tx_prepared_sends(conn) <= 0))
		goto out;

	/* Peer don't have RMBE space */
	if (unlikely(atomic_read(&conn->peer_rmbe_space) <= 0))
		goto out;

	if ((conn->killed != 0) || (conn->local_rx_ctrl.conn_state_flags.peer_conn_abort != 0)) {
		rc = -EPIPE;    /* connection being aborted */
		goto out;
	}
	rc = ums_tx_sndbuf_nonempty_handler(conn);
	if (rc == 0)
		/* trigger socket release if connection is closing */
		ums_close_wake_tx_prepared(ums);

out:
	return rc;
}

int ums_tx_sndbuf_nonempty(struct ums_connection *conn)
{
	bool again = true;
	int rc;

	/* This make sure only one can send simultaneously to prevent wasting of CPU and CDC slot.
	 * Record whether someone has tried to push while we are pushing. */
	if (atomic_inc_return(&conn->tx_pushing) > 1)
		return 0;

	while (again) {
		atomic_set(&conn->tx_pushing, 1);
		smp_wmb(); /* Make sure tx_pushing is 1 before real send */
		rc = ums_tx_sndbuf_nonempty_inner(conn);

		/* We need to check whether someone else have added some data into the send queue and tried
		 * to push but failed after the atomic_set() when we are pushing.
		 * If so, we need to push again to prevent those data hang in the send queue. */
		if (unlikely(!atomic_dec_and_test(&conn->tx_pushing)))
			continue;
		again = false;
	}

	return rc;
}

/* Wakeup sndbuf consumers from process context
 * since there is more data to transmit. The caller
 * must hold sock lock.
 */
void ums_tx_pending(struct ums_connection *conn)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);

	if (ums->sk.sk_err != 0)
		return;

	ums_conn_tx_rx_refcnt_inc(conn);
	if (conn->freed != 0) {
		ums_conn_tx_rx_refcnt_dec(conn);
		return;
	}

	(void)ums_tx_sndbuf_nonempty(conn);
	ums_conn_tx_rx_refcnt_dec(conn);
}

/* Wakeup sndbuf consumers from process context
 * since there is more data to transmit in locked
 * sock.
 */
void ums_tx_work(struct work_struct *work)
{
	struct ums_connection *conn = container_of(to_delayed_work(work), struct ums_connection,
		tx_work);
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);

	lock_sock(&ums->sk);
	ums_tx_pending(conn);
	release_sock(&ums->sk);
}

void ums_tx_consumer_update(struct ums_connection *conn, bool force)
{
	union ums_host_cursor cfed, cons, prod;
	int sender_free = conn->rmb_desc->len;
	int to_confirm;

	ums_curs_copy(&cons, &conn->local_tx_ctrl.cons, conn);
	ums_curs_copy(&cfed, &conn->rx_curs_confirmed, conn);
	to_confirm = ums_curs_diff((unsigned int)conn->rmb_desc->len, &cfed, &cons);
	if (to_confirm > conn->rmbe_update_limit) {
		ums_curs_copy(&prod, &conn->local_rx_ctrl.prod, conn);
		sender_free = conn->rmb_desc->len -
			ums_curs_diff_large((unsigned int)conn->rmb_desc->len, &cfed, &prod);
	}

	if ((conn->local_rx_ctrl.prod_flags.cons_curs_upd_req != 0) || force ||
		((to_confirm > conn->rmbe_update_limit) &&
		((sender_free <= (conn->rmb_desc->len / UMS_ONE_HALF)) ||
		(conn->local_rx_ctrl.prod_flags.write_blocked != 0)))) {
		if ((conn->killed != 0) || (conn->local_rx_ctrl.conn_state_flags.peer_conn_abort != 0))
			return;
		if ((ums_cdc_get_slot_and_msg_send(conn) < 0) && conn->killed == 0) {
			(void)queue_delayed_work(conn->lgr->tx_wq, &conn->cdc_tx_work,
				UMS_CDC_TX_WORK_DELAY);
			return;
		}
	}
	if ((conn->local_rx_ctrl.prod_flags.write_blocked != 0) &&
		(atomic_read(&conn->bytes_to_rcv) == 0))
		conn->local_rx_ctrl.prod_flags.write_blocked = 0;
}

/***************************** send initialize *******************************/

/* Initialize send properties on connection establishment. NB: not __init! */
void ums_tx_init(struct ums_sock *ums)
{
	ums->sk.sk_write_space = ums_tx_write_space;
}
#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_tx_init);
#endif
