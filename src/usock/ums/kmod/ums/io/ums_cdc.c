// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS Connection Data Control(CDC) implementation
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

#include <linux/spinlock.h>

#include "ums_close.h"
#include "ums_log.h"
#include "ums_mod.h"
#include "ums_rx.h"
#include "ums_tx.h"
#include "ums_wr.h"
#include "ums_cdc.h"

/********************************** send *************************************/

/* handler for send/transmission completion of a CDC msg */
static void ums_cdc_tx_handler(struct ums_wr_tx_pend_priv *pnd_snd, struct ums_link *link,
	enum ubcore_cr_opcode cr_opcode)
{
	struct ums_cdc_tx_pend *cdcpend = (struct ums_cdc_tx_pend *)pnd_snd;
	struct ums_connection *conn = cdcpend->conn;
	struct ums_buf_desc *sndbuf_desc;
	struct ums_sock *ums;
	int diff;

	sndbuf_desc = conn->sndbuf_desc;
	ums = container_of(conn, struct ums_sock, conn);
	sock_hold(&ums->sk); /* Prevent ums->sk from being freed. */
	bh_lock_sock(&ums->sk);
	if (cr_opcode == UBCORE_CR_OPC_SEND)
		conn->tx_cdc_seq_fin = cdcpend->ctrl_seq;
	/* urgent case we need to update cursor after cdc send */
	if (unlikely(conn->urg_tx_pend && sndbuf_desc)) {
		diff = ums_curs_diff((u32)(sndbuf_desc->len), &cdcpend->conn->tx_curs_fin,
			&cdcpend->cursor);
		/* sndbuf_space is decreased in ums_sendmsg */
		smp_mb__before_atomic();
		atomic_add(diff, &conn->sndbuf_space);
		/* guarantee 0 <= sndbuf_space <= sndbuf_desc->len */
		smp_mb__after_atomic();
		ums_curs_copy(&conn->tx_curs_fin, &cdcpend->cursor, conn);
		ums_curs_copy(&conn->local_tx_ctrl_fin, &cdcpend->p_cursor, conn);
	}

	if (atomic_dec_and_test(&conn->conn_pend_tx_wr)) {
		/* If user owns the sock_lock, mark the connection need sending.
		 * User context will later try to send when it release sock_lock
		 * in ums_release_cb()
		 */
		if (sock_owned_by_user(&ums->sk))
			conn->tx_in_release_sock = true;
		else
			ums_tx_pending(conn);

		if (unlikely(wq_has_sleeper(&conn->conn_pend_tx_wq)))
			wake_up(&conn->conn_pend_tx_wq);
	}
	WARN_ON(atomic_read(&conn->conn_pend_tx_wr) < 0);
	bh_unlock_sock(&ums->sk);
	sock_put(&ums->sk); /* for hold in this function */
}

static int ums_get_free_slot(struct ums_get_free_slot_param *param)
{
	int rc;

	rc = ums_wr_tx_get_free_slot(param->link, param->handler, param->wr_buf, param->wr_ub_buf,
		param->pend, false);
	if (rc < 0) {
		UMS_LOGW_LIMITED("get free slot failed, in_sotfrq=%lu, rc=%d, peer_rq=%d, local_rq=%d",
			in_softirq(), rc, atomic_read(&param->link->peer_rq_credits),
			atomic_read(&param->link->local_rq_credits));
		return rc;
	}
	if (param->conn->killed != 0) {
		/* abnormal termination */
		if (rc == 0)
			(void)ums_wr_tx_put_slot(param->link, (struct ums_wr_tx_pend_priv *)(*param->pend));
		rc = -EPIPE;
	}
	return rc;
}

int ums_cdc_get_free_slot(struct ums_connection *conn, struct ums_link *link,
	struct ums_wr_buf **wr_buf, struct ums_cdc_tx_pend **pend)
{
	struct ums_get_free_slot_param param;
	param.conn = conn;
	param.link = link;
	param.wr_buf = wr_buf;
	param.wr_ub_buf = NULL;
	param.pend = (struct ums_wr_tx_pend_priv **)pend;
	param.handler = ums_cdc_tx_handler;
	return ums_get_free_slot(&param);
}

static inline void ums_cdc_add_pending_send(struct ums_connection *conn,
	struct ums_cdc_tx_pend *pend)
{
	BUILD_BUG_ON_MSG(sizeof(struct ums_cdc_msg) > UMS_WR_BUF_SIZE,
		"must increase UMS_WR_BUF_SIZE to at least sizeof(struct ums_cdc_msg)");
	BUILD_BUG_ON_MSG(offsetofend(struct ums_cdc_msg, reserved) > UMS_WR_TX_SIZE,
		"must adapt UMS_WR_TX_SIZE to sizeof(struct ums_cdc_msg); if not all ums_wr upper layer "
		"protocols use the same message size any more, must start to set "
		"link->wr_tx_sges[i].length on each individual ums_wr_tx_send()");
	BUILD_BUG_ON_MSG(sizeof(struct ums_cdc_tx_pend) > UMS_WR_TX_PEND_PRIV_SIZE,
		"must increase UMS_WR_TX_PEND_PRIV_SIZE to at least sizeof(struct ums_cdc_tx_pend)");
	pend->conn = conn;
	pend->ctrl_seq = conn->tx_cdc_seq;
}

int ums_cdc_msg_send(struct ums_connection *conn, struct ums_wr_buf *wr_buf,
	struct ums_cdc_tx_pend *pend)
{
	struct ums_link *link = conn->lnk;
	struct ums_cdc_msg *cdc_msg = (struct ums_cdc_msg *)wr_buf;
	union ums_host_cursor cfed;
	u8 saved_credits = 0;
	int rc;

	if (unlikely(!READ_ONCE(conn->sndbuf_desc)))
		return -EINVAL;

	ums_cdc_add_pending_send(conn, pend);

	conn->tx_cdc_seq++;
	conn->local_tx_ctrl.seqno = conn->tx_cdc_seq;
	ums_host_msg_to_cdc(cdc_msg, conn, &cfed);
	if (ums_wr_rx_credits_need_announce_frequent(link))
		saved_credits = (u8)ums_wr_rx_get_credits(link);
	cdc_msg->credits = saved_credits;

	atomic_inc(&conn->conn_pend_tx_wr);
	smp_mb__after_atomic(); /* Make sure conn_pend_tx_wr added before post */

	rc = ums_wr_tx_send(link, (struct ums_wr_tx_pend_priv *)pend);
	if (likely(rc == 0)) {
		ums_curs_copy(&conn->rx_curs_confirmed, &cfed, conn);
		conn->local_rx_ctrl.prod_flags.cons_curs_upd_req = 0;
	} else {
		conn->tx_cdc_seq--;
		conn->local_tx_ctrl.seqno = conn->tx_cdc_seq;
		ums_wr_rx_put_credits(link, saved_credits);
		if (atomic_dec_and_test(&conn->conn_pend_tx_wr))
			wake_up(&conn->conn_pend_tx_wq);
	}

	return rc;
}

static int ums_cdc_handle_get_free_slot_failed(struct ums_connection *conn, int rc)
{
	struct ums_sock *ums = NULL;

	if (rc == -EBUSY) {
		ums = container_of(conn, struct ums_sock, conn);
		if (ums->sk.sk_err == ECONNABORTED)
			return sock_error(&ums->sk);
		if (conn->killed != 0)
			return -EPIPE;
		(void)mod_delayed_work(conn->lgr->tx_wq, &conn->cdc_tx_work, UMS_CDC_TX_WORK_DELAY);
	}

	return 0;
}

static int ums_cdc_get_slot_and_msg_send_inner(struct ums_connection *conn)
{
	struct ums_cdc_tx_pend *pend;
	struct ums_wr_buf *wr_buf;
	struct ums_link *link;
	bool again = false;
	bool loop = true;
	int rc;

	if (!ums_conn_lgr_valid(conn))
		return -EPIPE;

	while (loop) {
		link = conn->lnk;
		if (!ums_wr_tx_link_hold(link))
			return -ENOLINK;

		rc = ums_cdc_get_free_slot(conn, link, &wr_buf, &pend);
		if (rc < 0) {
			UMS_LOGW_LIMITED("get free slot failed, in_sotfrq=%lu, rc=%d, peer_rq=%d",
				in_softirq(), rc, atomic_read(&link->peer_rq_credits));
			ums_wr_tx_link_put(link);
			return ums_cdc_handle_get_free_slot_failed(conn, rc);
		}

		spin_lock_bh(&conn->send_lock);
		if (link != conn->lnk) {
			/* link of connection changed, try again one time */
			spin_unlock_bh(&conn->send_lock);
			(void)ums_wr_tx_put_slot(link, (struct ums_wr_tx_pend_priv *)pend);
			ums_wr_tx_link_put(link);
			if (again)
				return -ENOLINK;
			again = true;
			continue;
		}
		loop = false;
	}
	rc = ums_cdc_msg_send(conn, wr_buf, pend);
	spin_unlock_bh(&conn->send_lock);
	ums_wr_tx_link_put(link);
	return rc;
}

int ums_cdc_get_slot_and_msg_send(struct ums_connection *conn)
{
	bool again = true;
	int rc;

	ums_conn_tx_rx_refcnt_inc(conn);
	if (conn->freed != 0) {
		ums_conn_tx_rx_refcnt_dec(conn);
		return -EPIPE;
	}

	/* This make sure only one can send simultaneously to prevent wasting
	 * of CPU and CDC slot.
	 * Record whether someone has tried to push while we are pushing.
	 */
	if (atomic_inc_return(&conn->cdc_tx_pushing) > 1) {
		ums_conn_tx_rx_refcnt_dec(conn);
		return 0;
	}

	while (again) {
		atomic_set(&conn->cdc_tx_pushing, 1);
		smp_wmb(); /* Make sure cdc_tx_pushing is 1 before real send */
		rc = ums_cdc_get_slot_and_msg_send_inner(conn);

		/* We need to check whether someone else have added some data into the send queue and tried
		 * to push but failed after the atomic_set() when we are pushing.
		 * If so, we need to push again to prevent those data hang in the send queue. */
		if (unlikely(!atomic_dec_and_test(&conn->cdc_tx_pushing)))
			continue;
		again = false;
	}

	ums_conn_tx_rx_refcnt_dec(conn);
	return rc;
}

/* Wakeup sndbuf consumers from process context
 * since there is more data to transmit. The caller
 * must hold sock lock.
 */
static void ums_tx_cdc_pending(struct ums_connection *conn)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);
	int rc;

	if (ums->sk.sk_err != 0)
		return;

	rc = ums_cdc_get_slot_and_msg_send(conn);
	if ((rc == 0) && (conn->local_rx_ctrl.prod_flags.write_blocked != 0) &&
		(atomic_read(&conn->bytes_to_rcv) == 0))
		conn->local_rx_ctrl.prod_flags.write_blocked = 0;
}

void ums_cdc_tx_work(struct work_struct *work)
{
	struct ums_connection *conn =
		container_of(to_delayed_work(work), struct ums_connection, cdc_tx_work);
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);

	lock_sock(&ums->sk);
	ums_tx_cdc_pending(conn);
	release_sock(&ums->sk);
}

void ums_conn_wait_pend_tx_wr(struct ums_connection *conn)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);
	if (atomic_read(&conn->conn_pend_tx_wr) == 0) {
		return;
	}
	release_sock(&ums->sk);
	wait_event(conn->conn_pend_tx_wq, atomic_read(&conn->conn_pend_tx_wr) == 0);
	lock_sock(&ums->sk);
}

/********************************* receive ***********************************/

static inline bool ums_cdc_before(u16 seq1, u16 seq2)
{
	return (s16)(seq1 - seq2) < 0;
}

static void ums_cdc_handle_urg_data_arrival(struct ums_sock *ums, int *diff_prod)
{
	struct ums_connection *conn = &ums->conn;
	char *urgent_base;

	ums_curs_copy(&conn->urg_curs, &conn->local_rx_ctrl.prod, conn);
	conn->urg_state = UMS_URG_VALID;
	/* inline case we need to skip the urgent byte */
	if (!sock_flag(&ums->sk, SOCK_URGINLINE))
		(*diff_prod)--;
	urgent_base = (char *)conn->rmb_desc->cpu_addr + conn->rx_off;
	if (conn->urg_curs.count != 0)
		conn->urg_rx_byte = *(urgent_base + conn->urg_curs.count - 1);
	else
		conn->urg_rx_byte = *(urgent_base + conn->rmb_desc->len - 1);
	sk_send_sigurg(&ums->sk);
}

static void ums_cdc_msg_recv_check_prod(struct ums_sock *ums, union ums_host_cursor *prod_old)
{
	struct ums_connection *conn = &ums->conn;
	int diff_prod = 0;

	diff_prod =
		ums_curs_diff((u32)(conn->rmb_desc->len), prod_old, &conn->local_rx_ctrl.prod);
	if (likely(diff_prod != 0)) {
		if (likely(conn->local_rx_ctrl.prod_flags.urg_data_present != 0))
			ums_cdc_handle_urg_data_arrival(ums, &diff_prod);
		/* bytes_to_rcv is decreased in ums_recvmsg */
		smp_mb__before_atomic();
		atomic_add(diff_prod, &conn->bytes_to_rcv);
		/* guarantee 0 <= bytes_to_rcv <= rmb_desc->len */
		smp_mb__after_atomic();
		ums->sk.sk_data_ready(&ums->sk);
	} else {
		if (conn->local_rx_ctrl.prod_flags.write_blocked != 0)
			ums->sk.sk_data_ready(&ums->sk);
		if (conn->local_rx_ctrl.prod_flags.urg_data_pending != 0)
			conn->urg_state = UMS_URG_NOTYET;
	}
}

static void ums_cdc_msg_recv_action(struct ums_sock *ums, struct ums_cdc_msg *cdc)
{
	union ums_host_cursor cons_old, prod_old;
	struct ums_connection *conn = &ums->conn;
	int diff_cons;

	ums_curs_copy(&prod_old, &conn->local_rx_ctrl.prod, conn);
	ums_curs_copy(&cons_old, &conn->local_rx_ctrl.cons, conn);
	ums_cdc_msg_to_host(&conn->local_rx_ctrl, cdc, conn);

	diff_cons = ums_curs_diff((u32)conn->peer_rmbe_size, &cons_old,
		&conn->local_rx_ctrl.cons);
	if (diff_cons != 0) {
		/* peer_rmbe_space is decreased during data transfer with write */
		smp_mb__before_atomic();
		atomic_add(diff_cons, &conn->peer_rmbe_space);
		/* guarantee 0 <= peer_rmbe_space <= peer_rmbe_size */
		smp_mb__after_atomic();
	}

	/* only urgent case we need to check prod cursor */
	if (unlikely((conn->local_rx_ctrl.prod_flags.urg_data_present != 0) ||
		(conn->local_rx_ctrl.prod_flags.urg_data_pending != 0)))
		ums_cdc_msg_recv_check_prod(ums, &prod_old);

	/* trigger sndbuf consumer:write into peer RMBE and CDC */
	if (((diff_cons != 0) && (ums_tx_prepared_sends(conn) != 0) &&
			(conn->local_tx_ctrl.prod_flags.write_blocked != 0)) ||
		(conn->local_rx_ctrl.prod_flags.cons_curs_upd_req != 0) ||
		(conn->local_rx_ctrl.prod_flags.urg_data_pending != 0)) {
		if (!sock_owned_by_user(&ums->sk))
			ums_tx_pending(conn);
		else
			conn->tx_in_release_sock = true;
	}

	if ((diff_cons != 0) && conn->urg_tx_pend &&
		(atomic_read(&conn->peer_rmbe_space) == conn->peer_rmbe_size)) {
		/* urg data confirmed by peer, indicate we're ready for more */
		conn->urg_tx_pend = false;
		ums->sk.sk_write_space(&ums->sk);
	}

	if (conn->local_rx_ctrl.conn_state_flags.peer_conn_abort != 0) {
		ums->sk.sk_err = ECONNRESET;
		conn->local_tx_ctrl.conn_state_flags.peer_conn_abort = 1;
	}
	if (ums_cdc_rxed_any_close_or_senddone(conn)) {
		ums->sk.sk_shutdown |= RCV_SHUTDOWN;
		if (ums->clcsock && ums->clcsock->sk)
			ums->clcsock->sk->sk_shutdown |= RCV_SHUTDOWN;
		sock_set_flag(&ums->sk, SOCK_DONE);
		sock_hold(&ums->sk); /* sock_put in close_work */
		if (!queue_work(g_ums_close_wq, &conn->close_work))
			sock_put(&ums->sk);
	}
}

/* called under tasklet context */
static void ums_cdc_msg_recv(struct ums_sock *ums, struct ums_cdc_msg *cdc)
{
	sock_hold(&ums->sk);
	bh_lock_sock(&ums->sk);
	ums_cdc_msg_recv_action(ums, cdc);
	bh_unlock_sock(&ums->sk);
	sock_put(&ums->sk); /* no free sk in softirq-context */
}

/***************************** init, exit, misc ******************************/

static void ums_cdc_rx_handler(struct ums_wc *wc, void *buf)
{
	struct ums_link *link = wc->link;
	struct ubcore_cr *cr = wc->cr;
	struct ums_cdc_msg *cdc = buf;
	struct ums_connection *conn;
	struct ums_link_group *lgr;
	struct ums_sock *ums;

	if (cr->completion_len < offsetof(struct ums_cdc_msg, reserved))
		return; /* short message */
	if (cdc->len != UMS_WR_TX_SIZE)
		return; /* invalid message */

	if (cdc->credits != 0)
		ums_wr_tx_put_credits(link, cdc->credits, true);

	/* lookup connection */
	lgr = ums_get_lgr(link);
	read_lock_bh(&lgr->conns_lock);
	conn = ums_lgr_find_conn(ntohl(cdc->token), lgr);
	read_unlock_bh(&lgr->conns_lock);
	if (!conn)
		return;

	ums_conn_tx_rx_refcnt_inc(conn);
	if (conn->freed != 0) {
		ums_conn_tx_rx_refcnt_dec(conn);
		return;
	}

	ums = container_of(conn, struct ums_sock, conn);
	if (ums_cdc_before(ntohs(cdc->seqno), conn->local_rx_ctrl.seqno)) {
		/* received seqno is old */
		ums_conn_tx_rx_refcnt_dec(conn);
		return;
	}

	ums_cdc_msg_recv(ums, cdc);
	ums_conn_tx_rx_refcnt_dec(conn);
}

/*****************************write_with_imm******************************/
/* handler for send/transmission completion of a IMM msg */
static void ums_imm_tx_handler(struct ums_wr_tx_pend_priv *pnd_snd, struct ums_link *link,
	enum ubcore_cr_opcode cr_opcode)
{
	struct ums_imm_tx_pend *immpend = (struct ums_imm_tx_pend *)pnd_snd;
	struct ums_connection *conn = immpend->conn;
	struct ums_buf_desc *sndbuf_desc;
	struct ums_sock *ums;
	int diff;

	if (!conn)
		return;

	sndbuf_desc = conn->sndbuf_desc;
	ums = container_of(conn, struct ums_sock, conn);
	sock_hold(&ums->sk); /* Prevent ums->sk from being freed. */
	bh_lock_sock(&ums->sk);
	if ((cr_opcode == UBCORE_CR_OPC_SEND) && (sndbuf_desc != NULL)) {
		diff = ums_curs_diff((u32)sndbuf_desc->len, &conn->tx_curs_fin,
			&immpend->cursor);
		/* sndbuf_space is decreased in ums_sendmsg */
		smp_mb__before_atomic();
		atomic_add(diff, &conn->sndbuf_space);
		/* guarantee 0 <= sndbuf_space <= sndbuf_desc->len */
		smp_mb__after_atomic();
		ums_curs_copy(&conn->tx_curs_fin, &immpend->cursor, conn);
		ums_curs_copy(&conn->local_tx_ctrl_fin, &immpend->p_cursor, conn);
	}

	if (atomic_dec_and_test(&conn->conn_pend_tx_wr)) {
		/* If user owns the sock_lock, mark the connection need sending.
		 * User context will later try to send when it release sock_lock
		 * in ums_release_cb()
		 */
		if (sock_owned_by_user(&ums->sk)) {
			conn->tx_in_release_sock = true;
		} else {
			ums_tx_pending(conn);
		}

		if (unlikely(wq_has_sleeper(&conn->conn_pend_tx_wq)))
			wake_up(&conn->conn_pend_tx_wq);
	}
	WARN_ON(atomic_read(&conn->conn_pend_tx_wr) < 0);

	ums_tx_sndbuf_nonfull(ums);
	bh_unlock_sock(&ums->sk);
	sock_put(&ums->sk); /* for hold in this function */
}

int ums_imm_get_free_slot(struct ums_connection *conn, struct ums_link *link,
	struct ubcore_jfs_wr **wr_ub_buf, struct ums_imm_tx_pend **pend)
{
	struct ums_get_free_slot_param param;

	param.conn = conn;
	param.link = link;
	param.wr_buf = NULL;
	param.wr_ub_buf = wr_ub_buf;
	param.pend = (struct ums_wr_tx_pend_priv **)pend;
	param.handler = ums_imm_tx_handler;
	return ums_get_free_slot(&param);
}

static void ums_imm_msg_recv_action(struct ums_sock *ums, u32 length, u32 imm_data)
{
	struct ums_connection *conn = &ums->conn;
	union ums_imm imm;

	u32 len = length;
	imm.data = imm_data;

	/* update write_blocked */
	conn->local_rx_ctrl.prod_flags.write_blocked = imm.write_blocked;

	/* update real data len */
	if (unlikely(imm.skip_flag != 0))
		len += ((u32)conn->rmb_desc->len) - conn->local_rx_ctrl.prod.count;

	/* update prod cursor */
	ums_curs_add(conn->rmb_desc->len, &conn->local_rx_ctrl.prod, (int)len);

	smp_mb__before_atomic();
	atomic_add((int)len, &conn->bytes_to_rcv);
	/* guarantee 0 <= bytes_to_rcv <= rmb_desc->len */
	smp_mb__after_atomic();
	ums->sk.sk_data_ready(&ums->sk);
}

static void ums_imm_rx_handler(struct ums_wc *wc, void *buf)
{
	struct ums_link *link = wc->link;
	struct ubcore_cr *cr = wc->cr;
	struct ums_connection *conn;
	struct ums_link_group *lgr;
	struct ums_sock *ums;
	union ums_imm imm;

	imm.data = (u32)cr->imm_data;

	/* put peer credits */
	ums_wr_tx_put_credits(link, (int)imm.credits, true);

	/* lookup connection */
	lgr = ums_get_lgr(link);
	read_lock_bh(&lgr->conns_lock);
	conn = ums_lgr_find_conn(imm.token, lgr);
	read_unlock_bh(&lgr->conns_lock);
	if (!conn) {
		UMS_LOGE("cannot find a valid conn in link %*phN for imm.token %u, jetty id:%u",
				 UMS_LGR_ID_SIZE, link->link_uid, imm.token, wc->jetty_id);
		return;
	}

	ums_conn_tx_rx_refcnt_inc(conn);
	if (conn->freed != 0) {
		ums_conn_tx_rx_refcnt_dec(conn);
		return;
	}

	ums = container_of(conn, struct ums_sock, conn);
	sock_hold(&ums->sk);
	bh_lock_sock(&ums->sk);
	ums_imm_msg_recv_action(ums, cr->completion_len, imm.data);
	bh_unlock_sock(&ums->sk);
	sock_put(&ums->sk); /* no free sk in softirq-context */
	ums_conn_tx_rx_refcnt_dec(conn);
}

int ums_urg_get_free_slot(struct ums_connection *conn, struct ums_link *link,
	struct ums_wr_buf **wr_buf, struct ubcore_jfs_wr **wr_ub_buf, struct ums_cdc_tx_pend **pend)
{
	struct ums_get_free_slot_param param;
	param.conn = conn;
	param.link = link;
	param.wr_buf = wr_buf;
	param.wr_ub_buf = wr_ub_buf;
	param.pend = (struct ums_wr_tx_pend_priv **)pend;
	param.handler = ums_cdc_tx_handler;
	return ums_get_free_slot(&param);
}

static struct ums_wr_rx_handler g_ums_cdc_rx_handlers[] = {
	{
		.list    = { 0 },
		.handler = ums_cdc_rx_handler,
		.type    = UMS_CDC_MSG_TYPE
	},
	{
		.list    = { 0 },
		.handler = ums_imm_rx_handler,
		.type    = UMS_IMM_MSG_TYPE
	},
	{
		.list    = { 0 },
		.handler = NULL,
		.type    = 0
	}
};

int __init ums_cdc_init(void)
{
	struct ums_wr_rx_handler *handler;
	int rc = 0;

	for (handler = g_ums_cdc_rx_handlers; handler->handler; handler++) {
		INIT_HLIST_NODE(&handler->list);
		rc = ums_wr_rx_register_handler(handler);
		if (rc != 0)
			break;
	}
	return rc;
}
