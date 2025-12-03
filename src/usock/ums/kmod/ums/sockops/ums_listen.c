// SPDX-License-Identifier: GPL-2.0-only
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS listen ops implementation
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *                based on prototype from Frank Blaschka
 *
 * UMS implementation:
 *     Author(s):Sun fang
 */

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/socket.h>

#include "ums_clc.h"
#include "ums_llc.h"
#include "ums_log.h"
#include "ums_close.h"
#include "ums_rx.h"
#include "ums_tx.h"
#include "ums_common.h"
#include "ums_listen.h"

static DEFINE_MUTEX(g_ums_server_lgr_pending); /* serialize link group creation on server */

/* add a just created sock to the accept queue of the listen sock as
 * candidate for a following socket accept call from user space
 */
static void ums_accept_enqueue(struct sock *parent, struct sock *sk)
{
	struct ums_sock *par = ums_sk(parent);

	sock_hold(sk); /* sock_put in ums_accept_unlink () */
	spin_lock(&par->accept_q_lock);
	list_add_tail(&ums_sk(sk)->accept_q, &par->accept_q);
	sk_acceptq_added(parent);
	spin_unlock(&par->accept_q_lock);
}

/* listen worker: finish */
static void ums_listen_out(struct ums_sock *new_ums)
{
	struct ums_sock *lums = new_ums->listen_ums;
	struct sock *newumssk = &new_ums->sk;

	if (new_ums->ums_negotiated != 0)
		atomic_dec(&lums->queued_ums_hs);

	if (lums->sk.sk_state == (unsigned char)UMS_LISTEN) {
		lock_sock_nested(&lums->sk, SINGLE_DEPTH_NESTING);
		ums_accept_enqueue(&lums->sk, newumssk);
		release_sock(&lums->sk);
	} else { /* no longer listening */
		ums_close_non_accepted(newumssk);
	}

	/* Wake up accept */
	lums->sk.sk_data_ready(&lums->sk);
	sock_put(&lums->sk); /* sock_hold in ums_tcp_listen_work */
}

/* listen worker: finish in state connected */
void ums_listen_out_connected(struct ums_sock *new_ums)
{
	struct sock *newumssk = &new_ums->sk;

#ifdef SOCK_REFCNT_DEBUG
	sk_refcnt_debug_inc(newumssk);
#endif
	if (newumssk->sk_state == (unsigned char)UMS_INIT)
		newumssk->sk_state = (unsigned char)UMS_ACTIVE;

	ums_listen_out(new_ums);
}

/* listen worker: finish in error state */
void ums_listen_out_err(struct ums_sock *new_ums)
{
	struct sock *newumssk = &new_ums->sk;

	if (newumssk->sk_state == (unsigned char)UMS_INIT)
		sock_put(&new_ums->sk); /* passive closing */
	newumssk->sk_state = (unsigned char)UMS_CLOSED;

	ums_listen_out(new_ums);
}

/* listen worker: decline and fall back if possible */
static void ums_listen_decline(struct ums_sock *new_ums, int reason_code, int local_first)
{
	/* setup failed, switch back to TCP */
	ums_conn_abort(new_ums, local_first);
	if ((reason_code < 0) || (ums_switch_to_fallback(new_ums, reason_code) != 0)) {
		/* error, no fallback possible */
		ums_listen_out_err(new_ums);
		return;
	}
	if ((reason_code != 0) && (reason_code != UMS_CLC_DECL_PEERDECL && reason_code != UMS_CLC_DECL_TIMEOUT_CL)) {
		if (ums_clc_send_decline(new_ums, (u32)reason_code) < 0) {
			ums_listen_out_err(new_ums);
			return;
		}
	}
	ums_listen_out_connected(new_ums);
}

/* listen worker: check prefixes */
static int ums_listen_prfx_check(struct ums_sock *new_ums, struct ums_clc_msg_proposal *pclc)
{
	struct ums_clc_msg_proposal_prefix *pclc_prfx;
	struct socket *newclcsock = new_ums->clcsock;

	if (pclc->hdr.typev1 == UMS_TYPE_N)
		return 0;
	pclc_prfx = ums_clc_proposal_get_prefix(pclc);
	if (ums_clc_prfx_match(newclcsock, pclc_prfx) != 0)
		return UMS_CLC_DECL_DIFFPREFIX;

	return 0;
}

/* listen worker: initialize connection and buffers */
static int ums_listen_ub_init(struct ums_sock *new_ums, struct ums_init_info *ini)
{
	int rc = 0;

	/* allocate connection / link group */
	rc = ums_conn_create(new_ums, ini);
	if (rc != 0)
		return rc;

	/* create send buffer and rmb */
	if (ums_buf_create(new_ums) != 0)
		return UMS_CLC_DECL_MEM;

	rc = ums_buf_register(new_ums);
	if (rc != 0) {
		ums_snd_recv_bufs_free(new_ums);
		return rc;
	}

	return 0;
}

static inline void ums_rc_check_and_set(struct ums_init_info *ini, int rc)
{
	if (ini->rc == 0)
		ini->rc = (u32)rc;
}

static int ums_find_ub_device_serv(struct ums_sock *new_ums,
	struct ums_clc_msg_proposal *pclc, struct ums_init_info *ini)
{
	int rc;
	if (!ums_indicated(ini->ums_type_v1))
		return UMS_CLC_DECL_NOUMSDEV;

	/* prepare UB check */
	(void)memcpy(ini->peer_systemid, pclc->lcl.id_for_peer, UMS_SYSTEMID_LEN);

	if (pclc->lcl.ubcore_route_enable == UMS_UBCORE_ROUTE_ENABLE) {
		ini->ubcore_route_enable = pclc->lcl.ubcore_route_enable;
		(void)memcpy(ini->dst_v_eid.raw, pclc->lcl.eid.raw, UMS_EID_SIZE);
	} else {
		(void)memcpy(ini->peer_eid.raw, pclc->lcl.eid.raw, UMS_EID_SIZE);
	}

	(void)memcpy(ini->peer_mac, pclc->lcl.mac, ETH_ALEN);
	ini->is_server = true;

	rc = ums_find_ub_device(new_ums, ini);
	if (rc != 0)
		/* no UB device found */
		return UMS_CLC_DECL_NOUMSDEV;
	return ums_listen_ub_init(new_ums, ini);
}

/* determine the local device matching to proposal */
static int ums_listen_find_device(struct ums_sock *new_ums, struct ums_clc_msg_proposal *pclc,
	struct ums_init_info *ini)
{
	int prfx_rc = 0;

	/* check for matching IP prefix and subnet length (V1) */
	prfx_rc = ums_listen_prfx_check(new_ums, pclc);
	if (prfx_rc != 0 && ini->rc == 0)
		ini->rc = (u32)prfx_rc;

	/* get vlan id from IP device */
	if (ums_vlan_by_tcpsk(new_ums->clcsock, ini) != 0)
		return (int)(ini->rc != 0 ? ini->rc : UMS_CLC_DECL_GETVLANERR);

	if (!ums_indicated(pclc->hdr.typev1) && !ums_indicated(pclc->hdr.typev2))
		/* skip UB and decline */
		return (int)(ini->rc != 0 ? ini->rc : UMS_CLC_DECL_NOUMSDEV);

	/* check if V1 is available. V1 only support connect within a subnet. */
	if (prfx_rc == 0) {
		int rc;

		rc = ums_find_ub_device_serv(new_ums, pclc, ini);
		ums_rc_check_and_set(ini, rc);
		return (int)(rc == 0 ? 0 : ini->rc);
	}
	return UMS_CLC_DECL_NOUMSDEV;
}

static int ums_serv_conf_first_link(struct ums_sock *ums)
{
	struct ums_link *link = ums->conn.lnk;
	struct ums_llc_qentry *qentry;
	int rc;

	/* send CONFIRM LINK request to client over the UB fabric */
	rc = ums_llc_send_confirm_link(link, UMS_LLC_REQ);
	if (rc < 0)
		return UMS_CLC_DECL_TIMEOUT_CL;

	/* receive CONFIRM LINK response from client over the UB fabric */
	qentry = ums_llc_wait(link->lgr, link, UMS_LLC_WAIT_TIME, UMS_LLC_CONFIRM_LINK);
	if (!qentry) {
		struct ums_clc_msg_decline dclc;

		rc = ums_clc_wait_msg(ums, &dclc, sizeof(dclc), UMS_CLC_DECLINE, CLC_WAIT_TIME_SHORT);
		return rc == -EAGAIN ? UMS_CLC_DECL_TIMEOUT_CL : rc;
	}
	ums_llc_save_peer_uid(qentry);
	rc = ums_llc_eval_conf_link(qentry, UMS_LLC_RESP);
	ums_llc_flow_qentry_del(&link->lgr->llc_flow_lcl);
	if (rc != 0)
		return UMS_CLC_DECL_RMBE_EC;

	/* confirm_rkey is implicit on 1st contact */
	ums->conn.rmb_desc->confirmed_rkey = true;

	ums_llc_link_active(link);
	ums_lgr_set_type(link->lgr, UMS_LGR_SINGLE);

	return 0;
}

/* listen worker: finish UB setup */
static int ums_listen_ub_finish(struct ums_sock *new_ums, struct ums_clc_msg_accept_confirm *cclc,
	bool local_first, struct ums_init_info *ini)
{
	struct ums_link *link = new_ums->conn.lnk;
	int reason_code = 0;

	if (!link) {
		UMS_LOGE("link is null in listen.");
		return UMS_CLC_DECL_ERR_RDYLNK;
	}
	ini->tjetty_id = ntohl(cclc->r0.jetty_id);

	if ((ini->ubcore_route_enable == UMS_UBCORE_ROUTE_ENABLE) &&
		(!ums_ubcore_check_if_eid_match(&ini->peer_eid, &cclc->r0.lcl.eid))) {
		UMS_LOGE("Expected peer_eid: %pI6c and received peer_eid: %pI6c in clc confirm msg do not match.",
			ini->peer_eid.raw, cclc->r0.lcl.eid.raw);
		return UMS_CLC_DECL_PEEREIDERR;
	}

	if (local_first)
		ums_link_save_peer_info(link, cclc, ini);

	if (ums_rmb_import_seg(&new_ums->conn, cclc) != 0)
		return UMS_CLC_DECL_ERR_RTOK;

	if (local_first) {
		if (ums_ubcore_ready_link(link) != 0)
			return UMS_CLC_DECL_ERR_RDYLNK;
		/* QP confirmation over UB fabric */
		(void)ums_llc_flow_initiate(link->lgr, UMS_LLC_FLOW_ADD_LINK);
		reason_code = ums_serv_conf_first_link(new_ums);
		ums_llc_flow_stop(link->lgr, &link->lgr->llc_flow_lcl);
	}
	return reason_code;
}

/* setup for connection of server */
void ums_listen_work(struct work_struct *work)
{
	struct ums_sock *new_ums = container_of(work, struct ums_sock, ums_listen_work);
	struct ums_clc_msg_accept_confirm *cclc;
	struct ums_clc_msg_proposal_area *buf;
	struct ums_clc_msg_proposal *pclc;
	struct ums_init_info *ini = NULL;
	int rc = 0;

	if (new_ums->listen_ums->sk.sk_state != (unsigned char)UMS_LISTEN) {
		ums_listen_out_err(new_ums);
		return;
	}

	if (new_ums->use_fallback) {
		ums_listen_out_connected(new_ums);
		return;
	}

	/* do inband token exchange -
	 * wait for and receive UMS Proposal CLC message
	 */
	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		rc = UMS_CLC_DECL_MEM;
		goto out_decl;
	}
	pclc = (struct ums_clc_msg_proposal *)buf;
	rc = ums_clc_wait_msg(new_ums, pclc, sizeof(*buf), UMS_CLC_PROPOSAL, CLC_WAIT_TIME);
	if (rc != 0)
		goto out_decl;

	/* IPSec connections opt out of UMS optimizations */
	if (using_ipsec(new_ums)) {
		rc = UMS_CLC_DECL_IPSEC;
		goto out_decl;
	}

	ini = kzalloc(sizeof(*ini), GFP_KERNEL);
	if (!ini) {
		rc = UMS_CLC_DECL_MEM;
		goto out_decl;
	}

	ini->ums_type_v1 = pclc->hdr.typev1;

	ums_lgr_pending_lock(ini, &g_ums_server_lgr_pending);
	ums_close_init(new_ums);
	ums_rx_init(new_ums);
	ums_tx_init(new_ums);

	/* determine UB device used for connection */
	rc = ums_listen_find_device(new_ums, pclc, ini);
	if (rc != 0) {
		UMS_LOGE("listen find device failed, ret: %d", rc);
		goto out_unlock;
	}

	/* send UMS Accept CLC message */
	rc = ums_clc_send_accept(new_ums, ini->first_contact_local, ini->negotiated_eid, ini);
	if (rc != 0) {
		UMS_LOGE("send accept failed, ret: %d", rc);
		goto out_unlock;
	}

	/* receive UMS Confirm CLC message */
	(void)memset(buf, 0, sizeof(struct ums_clc_msg_proposal_area));
	cclc = (struct ums_clc_msg_accept_confirm *)buf;
	rc = ums_clc_wait_msg(new_ums, cclc, sizeof(*buf), UMS_CLC_CONFIRM, CLC_WAIT_TIME);
	if (rc != 0) {
		UMS_LOGE("wait msg failed, ret %d, conn %u", rc, new_ums->conn.conn_id);
		goto out_unlock;
	}

	/* finish worker */
	rc = ums_listen_ub_finish(new_ums, cclc, ini->first_contact_local, ini);
	if (rc != 0)
		goto out_unlock;
	ums_lgr_pending_unlock(ini, &g_ums_server_lgr_pending);

	ums_conn_save_peer_info(new_ums, cclc);
	ums_copy_conn_jetty_info(new_ums);
	ums_listen_out_connected(new_ums);
	goto out_free;

out_unlock:
	ums_lgr_pending_unlock(ini, &g_ums_server_lgr_pending);
out_decl:
	ums_listen_decline(new_ums, rc, ini ? ini->first_contact_local : 0);
out_free:
	kfree(ini);
	kfree(buf);
}

static void ums_clcsock_data_ready(struct sock *listen_clcsock)
{
	struct ums_sock *lums;

	read_lock_bh(&listen_clcsock->sk_callback_lock);
	lums = ums_clcsock_user_data(listen_clcsock);
	if (!lums)
		goto out;
	lums->clcsk_data_ready(listen_clcsock);
	if (lums->sk.sk_state == (unsigned char)UMS_LISTEN) {
		int idx = atomic_fetch_inc(&lums->tcp_listen_work_seq) % UMS_MAX_TCP_LISTEN_WORKS;
		sock_hold(&lums->sk); /* sock_put in ums_tcp_listen_work() */
		if (!queue_work(g_ums_tcp_ls_wq, &lums->tcp_listen_works[idx].work))
			sock_put(&lums->sk);
	}
out:
	read_unlock_bh(&listen_clcsock->sk_callback_lock);
}

static struct sock *ums_tcp_syn_recv_sock(const struct sock *sk, struct sk_buff *skb,
	struct request_sock *req, struct dst_entry *dst, struct request_sock *req_unhash,
	bool *own_req)
{
	struct ums_sock *ums;
	struct sock *child;

	ums = ums_clcsock_user_data(sk);
	if (unlikely(!ums))
		goto drop;

	if (READ_ONCE(sk->sk_ack_backlog) + atomic_read(&ums->queued_ums_hs) > sk->sk_max_ack_backlog)
		goto drop;

	if (sk_acceptq_is_full(&ums->sk))
		goto drop;

	/* passthrough to original syn recv sock fct */
	child = ums->ori_af_ops->syn_recv_sock(sk, skb, req, dst, req_unhash, own_req);
	/* child must not inherit ums or its ops */
	if (child) {
		rcu_assign_sk_user_data(child, NULL);

		/* v4-mapped sockets don't inherit parent ops. Don't restore. */
		if (inet_csk(child)->icsk_af_ops == inet_csk(sk)->icsk_af_ops)
			inet_csk(child)->icsk_af_ops = ums->ori_af_ops;
	}
	return child;

drop:
	dst_release(dst);
	tcp_listendrop(sk);
	return NULL;
}

int ums_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	int rc;

	ums = ums_sk(sk);
	lock_sock(sk);

	rc = -EINVAL;
	if (((sk->sk_state != (unsigned char)UMS_INIT) && (sk->sk_state != (unsigned char)UMS_LISTEN)) ||
		(ums->connect_nonblock != 0) || (sock->state != SS_UNCONNECTED))
		goto out;

	rc = 0;
	if (sk->sk_state == (unsigned char)UMS_LISTEN) {
		sk->sk_max_ack_backlog = (u32)backlog;
		goto out;
	}
	/* some socket options are handled in core, so we could not apply
	 * them to the clc socket -- copy ums socket options to clc socket
	 */
	ums_copy_sock_settings_to_clc(ums);

#if IS_ENABLED(CONFIG_SMC)
	if (!ums->use_fallback)
		ums_set_syn_smc(ums);
#else
	UMS_LOGW_LIMITED("CONFIG_SMC disabled, UMS cannot switch to fallback now!");
#endif

	/* save original sk_data_ready function and establish
	 * ums-specific sk_data_ready function
	 */
	write_lock_bh(&ums->clcsock->sk->sk_callback_lock);
	ums->clcsock->sk->sk_user_data = (void *)((uintptr_t)ums | SK_USER_DATA_NOCOPY);
	ums_clcsock_replace_cb(&ums->clcsock->sk->sk_data_ready, ums_clcsock_data_ready,
		&ums->clcsk_data_ready);
	write_unlock_bh(&ums->clcsock->sk->sk_callback_lock);

	/* save original ops */
	ums->ori_af_ops = inet_csk(ums->clcsock->sk)->icsk_af_ops;

	ums->af_ops = *ums->ori_af_ops;
	ums->af_ops.syn_recv_sock = ums_tcp_syn_recv_sock;

	inet_csk(ums->clcsock->sk)->icsk_af_ops = &ums->af_ops;

	/* para 0 represents the server */
	if (ums->ums_fastopen && (ums_clcsock_enable_fastopen(ums, 1) != 0))
		ums->ums_fastopen = 0; /* rollback when setsockopt failed */

	rc = kernel_listen(ums->clcsock, backlog);
	if (rc != 0) {
		write_lock_bh(&ums->clcsock->sk->sk_callback_lock);
		ums_clcsock_restore_cb(&ums->clcsock->sk->sk_data_ready, &ums->clcsk_data_ready);
		ums->clcsock->sk->sk_user_data = NULL;
		write_unlock_bh(&ums->clcsock->sk->sk_callback_lock);
		goto out;
	}
	sk->sk_max_ack_backlog = (u32)backlog;
	sk->sk_ack_backlog = 0;
	sk->sk_state = (unsigned char)UMS_LISTEN;

out:
	release_sock(sk);
	return rc;
}

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_listen_out_connected);
#endif
