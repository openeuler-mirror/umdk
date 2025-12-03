// SPDX-License-Identifier: GPL-2.0-only
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS connect ops implementation
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *                based on prototype from Frank Blaschka
 *
 * UMS implementation:
 *     Author(s): Sun fang
 */

#include "ums_clc.h"
#include "ums_close.h"
#include "ums_llc.h"
#include "ums_log.h"
#include "ums_pnet.h"
#include "ums_rx.h"
#include "ums_tx.h"
#include "ums_ubcore.h"
#include "ums_common.h"
#include "ums_connect.h"

#define UMS_CLC_MAX_ACCEPT_LEN                                                                 \
	(sizeof(struct ums_clc_msg_accept_confirm_v2) + sizeof(struct ums_clc_first_contact_ext) + \
		sizeof(struct ums_clc_msg_trail))

static DEFINE_MUTEX(g_ums_client_lgr_pending); /* serialize link group creation on client */

/* fall back during connect */
static int ums_connect_fallback(struct ums_sock *ums, int reason_code)
{
	int rc = 0;

	rc = ums_switch_to_fallback(ums, reason_code);
	if (rc != 0) { /* fallback fails */
		if (ums->sk.sk_state == (unsigned char)UMS_INIT)
			sock_put(&ums->sk); /* passive closing */
		return rc;
	}
	ums_copy_sock_settings_to_clc(ums);
	ums->connect_nonblock = 0;
	if (ums->sk.sk_state == (unsigned char)UMS_INIT)
		ums->sk.sk_state = (unsigned char)UMS_ACTIVE;
	return 0;
}

/* decline and fall back during connect */
static int ums_connect_decline_fallback(struct ums_sock *ums, int reason_code)
{
	int rc;

	if (reason_code < 0) { /* error, fallback is not possible */
		if (ums->sk.sk_state == (unsigned char)UMS_INIT)
			sock_put(&ums->sk); /* passive closing */
		return reason_code;
	}
	if (reason_code != UMS_CLC_DECL_PEERDECL && reason_code != UMS_CLC_DECL_TIMEOUT_CL) {
		rc = ums_clc_send_decline(ums, (u32)reason_code);
		if (rc < 0) {
			if (ums->sk.sk_state == (unsigned char)UMS_INIT)
				sock_put(&ums->sk); /* passive closing */
			return rc;
		}
	}
	return ums_connect_fallback(ums, reason_code);
}

static int ums_connect_fallback_check(struct ums_sock *ums, bool *fallback)
{
	if (ums->use_fallback) {
		*fallback = true;
		return ums_connect_fallback(ums, ums->fallback_rsn);
	}

	/* if peer has not signalled UMS-capability, fall back */
#if IS_ENABLED(CONFIG_SMC)
	if (!ums_get_syn_smc(ums)) {
		*fallback = true;
		return ums_connect_fallback(ums, UMS_CLC_DECL_PEERNOUMS);
	}
#endif

	/* IPSec connections opt out of UMS optimizations */
	if (using_ipsec(ums)) {
		*fallback = true;
		return ums_connect_decline_fallback(ums, UMS_CLC_DECL_IPSEC);
	}

	*fallback = false;
	return 0;
}

static int ums_find_proposal_devices(struct ums_sock *ums, struct ums_init_info *ini)
{
	/* check if there is an ub device available */
	int rc = ums_find_ub_device(ums, ini);
	if (rc != 0)
		return rc;

	/* ub is supported for this connection */
	ini->ums_type_v1 = UMS_TYPE_R;

	return 0;
}

static int ums_connect_ini_init(struct ums_sock *ums, struct ums_init_info *ini)
{
	int rc = 0;

	ini->ums_type_v1 = UMS_TYPE_R;

	/* get vlan id from IP device */
	if (ums_vlan_by_tcpsk(ums->clcsock, ini) != 0) {
		ini->ums_type_v1 = UMS_TYPE_N;
		return UMS_CLC_DECL_GETVLANERR;
	}
	rc = ums_find_proposal_devices(ums, ini);
	if (rc != 0)
		UMS_LOGD("find proposal devices failed, %d", rc);

	return rc;
}

static int ums_clnt_conf_first_link(struct ums_sock *ums)
{
	struct ums_link *link = ums->conn.lnk;
	struct ums_llc_qentry *qentry;
	int rc;

	/* receive CONFIRM LINK request from server over UB fabric */
	qentry = ums_llc_wait(link->lgr, NULL, UMS_LLC_CONFIRM_WAIT_TIME, UMS_LLC_CONFIRM_LINK);
	if (!qentry) {
		struct ums_clc_msg_decline dclc;

		rc = ums_clc_wait_msg(ums, &dclc, sizeof(dclc), UMS_CLC_DECLINE, CLC_WAIT_TIME_SHORT);
		/* when rc is negative num, means wait decline msg from server failed */
		UMS_LOGI("wait decline msg from server, rc is %d", rc);
		return rc == -EAGAIN ? UMS_CLC_DECL_TIMEOUT_CL : rc;
	}
	ums_llc_save_peer_uid(qentry);
	rc = ums_llc_eval_conf_link(qentry, UMS_LLC_REQ);
	ums_llc_flow_qentry_del(&link->lgr->llc_flow_lcl);
	if (rc != 0) {
		UMS_LOGE("eval conf link failed, rc is %d", rc);
		return UMS_CLC_DECL_RMBE_EC;
	}

	/* confirm_rkey is implicit on 1st contact */
	ums->conn.rmb_desc->confirmed_rkey = true;

	/* send CONFIRM LINK response over UB fabric */
	UMS_LOGI_LIMITED("client begin to send confirm link");
	rc = ums_llc_send_confirm_link(link, UMS_LLC_RESP);
	if (rc < 0)
		return UMS_CLC_DECL_TIMEOUT_CL;
	UMS_LOGI_LIMITED("client end to send confirm link.\n");
	ums_llc_link_active(link);
	ums_lgr_set_type(link->lgr, UMS_LGR_SINGLE);

	return 0;
}

static void ums_init_ini_info(struct ums_init_info *ini, struct ums_clc_msg_accept_confirm *aclc)
{
	ini->tjetty_id = ntohl(aclc->r0.jetty_id);
	ini->first_contact_peer = aclc->hdr.typev2 & UMS_FIRST_CONTACT_MASK;
	(void)memcpy(ini->peer_systemid, aclc->r0.lcl.id_for_peer, UMS_SYSTEMID_LEN);
	(void)memcpy(ini->peer_eid.raw, aclc->r0.lcl.eid.raw, UMS_EID_SIZE);
	(void)memcpy(ini->peer_mac, aclc->r0.lcl.mac, ETH_ALEN);
}

static int ums_client_create_resources(struct ums_sock *ums,
	struct ums_clc_msg_accept_confirm *aclc, struct ums_init_info *ini, struct ums_link **link)
{
	int reason_code = 0;
	int i;

	ums_init_ini_info(ini, aclc);

	if (ini->ubcore_route_enable == UMS_UBCORE_ROUTE_ENABLE) {
		if (ums_ubcore_find_ub_dev_by_eid(&aclc->r0.peer_eid, ini) != 0) {
			UMS_LOGE("Find ub device by eid failed, eid: %pI6c.", aclc->r0.peer_eid.raw);
			return UMS_CLC_DECL_NOUMSDEV;
		}
		UMS_LOGI_LIMITED("Find ub device succeeded, dev_name: %s, port: %u, eid_index: %d, "
			"eid: %pI6c, peer_eid: %pI6c.", ini->ub_dev->ub_dev->dev_name, ini->ub_port,
			ini->eid_index, ini->eid.raw, ini->peer_eid.raw);
	}

	ums_lgr_pending_lock(ini, &g_ums_client_lgr_pending);
	reason_code = ums_conn_create(ums, ini);
	if (reason_code != 0) {
		ums_lgr_pending_unlock(ini, &g_ums_client_lgr_pending);
		return reason_code;
	}

	ums_conn_save_peer_info(ums, aclc);

	if (ini->first_contact_local != 0) {
		*link = ums->conn.lnk;
	} else {
		/* set link that was assigned by server */
		*link = NULL;
		for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
			struct ums_link *l = &ums->conn.lgr->lnk[i];
			if ((l->tjetty_id == ntohl(aclc->r0.jetty_id)) &&
				(memcmp(l->peer_eid.raw, aclc->r0.lcl.eid.raw, UMS_EID_SIZE) == 0) &&
				(memcmp(l->peer_mac, aclc->r0.lcl.mac, sizeof(l->peer_mac)) == 0)) {
				*link = l;
				break;
			}
		}
		if (!(*link)) {
			reason_code = UMS_CLC_DECL_NOSRVLINK;
			goto connect_abort;
		}
		ums_switch_link_and_count(&ums->conn, *link);
	}

	if (ini->first_contact_local != 0)
		ums_link_save_peer_info(*link, aclc, ini);

	return 0;

connect_abort:
	ums_conn_abort(ums, ini->first_contact_local);
	ums_lgr_pending_unlock(ini, &g_ums_client_lgr_pending);
	ums->connect_nonblock = 0;
	return reason_code;
}

static int ums_client_bind_server(struct ums_sock *ums, struct ums_clc_msg_accept_confirm *aclc,
	const struct ums_init_info *ini, struct ums_link *link)
{
	int reason_code = 0;

	/* create send buffer and rmb */
	if (ums_buf_create(ums) != 0) {
		reason_code = UMS_CLC_DECL_MEM;
		return reason_code;
	}

	reason_code = ums_buf_register(ums);
	if (reason_code != 0)
		return reason_code;

	if (ums_rmb_import_seg(&ums->conn, aclc) != 0) {
		reason_code = UMS_CLC_DECL_ERR_SEG;
		return reason_code;
	}

	ums_close_init(ums);
	ums_rx_init(ums);

	if (ini->first_contact_local != 0) {
		if (ums_ubcore_ready_link(link) != 0) {
			reason_code = UMS_CLC_DECL_ERR_RDYLNK;
			return reason_code;
		}
	} else {
		if (ums_llc_announce_credits(link, UMS_LLC_RESP, true)) {
			reason_code = UMS_CLC_DECL_CREDITSERR;
			return reason_code;
		}
	}

	return 0;
}

/* setup for connection of client */
static int ums_connect_ub(struct ums_sock *ums, struct ums_clc_msg_accept_confirm *aclc,
	struct ums_init_info *ini)
{
	struct ums_link *link = NULL;
	int reason_code = 0;
	u8 *eid = NULL;

	reason_code = ums_client_create_resources(ums, aclc, ini, &link);
	if (reason_code != 0)
		return reason_code;

	if (link == NULL) {
		UMS_LOGE("link is null");
		ums_lgr_pending_unlock(ini, &g_ums_client_lgr_pending);
		return -1;
	}
	reason_code = ums_client_bind_server(ums, aclc, ini, link);
	if (reason_code != 0)
		goto connect_abort;

	reason_code = ums_clc_send_confirm(ums, ini->first_contact_local, eid, ini);
	if (reason_code != 0)
		goto connect_abort;

	ums_tx_init(ums);

	if (ini->first_contact_local != 0) {
		/* QP confirmation over UB fabric */
		(void)ums_llc_flow_initiate(link->lgr, UMS_LLC_FLOW_ADD_LINK);
		reason_code = ums_clnt_conf_first_link(ums);
		ums_llc_flow_stop(link->lgr, &link->lgr->llc_flow_lcl);
		if (reason_code != 0)
			goto connect_abort;
	}
	ums_lgr_pending_unlock(ini, &g_ums_client_lgr_pending);

	ums_copy_sock_settings_to_clc(ums);
	ums->connect_nonblock = 0;
	if (ums->sk.sk_state == (unsigned char)UMS_INIT)
		ums->sk.sk_state = (unsigned char)UMS_ACTIVE;

	return 0;

connect_abort:
	ums_conn_abort(ums, ini->first_contact_local);
	ums_lgr_pending_unlock(ini, &g_ums_client_lgr_pending);
	ums->connect_nonblock = 0;

	return reason_code;
}

/* check if received accept type and version matches a proposed one */
static int ums_connect_check_aclc(struct ums_init_info *ini,
	const struct ums_clc_msg_accept_confirm *aclc)
{
	if ((aclc->hdr.typev1 != UMS_TYPE_R) || (!ums_indicated(ini->ums_type_v1)))
		return UMS_CLC_DECL_MODEUNSUPP;

	return 0;
}

/* CLC handshake during connect */
static int ums_connect_clc(struct ums_sock *ums, struct ums_clc_msg_accept_confirm_v2 *aclc2,
	struct ums_init_info *ini)
{
	int rc = 0;
	/* do inband token exchange */
	rc = ums_clc_send_proposal(ums, ini);
	if (rc != 0) {
		UMS_LOGE("send proposal failed, ret: %d", rc);
		return rc;
	}

	release_sock(&ums->sk);
	/* receive UMS Accept CLC message */
	rc = ums_clc_wait_msg(ums, aclc2, UMS_CLC_MAX_ACCEPT_LEN, UMS_CLC_ACCEPT, CLC_WAIT_TIME);
	lock_sock(&ums->sk);
	return rc;
}

static int ums_connect_process_clc(struct ums_sock *ums,
	struct ums_clc_msg_accept_confirm_v2 *aclc2, struct ums_clc_msg_accept_confirm *aclc,
	u8 *buf, struct ums_init_info *ini)
{
	int rc = 0;

	/* perform CLC handshake */
	rc = ums_connect_clc(ums, aclc2, ini);
	if (rc != 0) {
		/* -EAGAIN on timeout, see tcp_recvmsg() */
		if (rc == -EAGAIN) {
			rc = -ETIMEDOUT;
			ums->sk.sk_err = ETIMEDOUT;
		}
		UMS_LOGE("connect clc failed, ret: %d, conn %u", rc, ums->conn.conn_id);
		return rc;
	}

	/* check if ums modes and versions of CLC proposal and accept match */
	rc = ums_connect_check_aclc(ini, aclc);
	if (rc != 0) {
		UMS_LOGE("connect check aclc failed, ret: %d", rc);
		return rc;
	}

	return 0;
}

/* perform steps before actually connecting */
static int ums_connect_inner(struct ums_sock *ums)
{
	struct ums_clc_msg_accept_confirm_v2 *aclc2;
	struct ums_clc_msg_accept_confirm *aclc;
	struct ums_init_info *ini = NULL;
	u8 *buf = NULL;
	bool fallback;
	int rc = 0;

	rc = ums_connect_fallback_check(ums, &fallback);
	if (fallback)
		return rc;

	ini = kzalloc(sizeof(*ini), GFP_KERNEL);
	if (!ini)
		return ums_connect_decline_fallback(ums, UMS_CLC_DECL_MEM);

	rc = ums_connect_ini_init(ums, ini);
	if (rc != 0)
		goto fallback;

	buf = kzalloc(UMS_CLC_MAX_ACCEPT_LEN, GFP_KERNEL);
	if (!buf) {
		rc = UMS_CLC_DECL_MEM;
		goto fallback;
	}
	aclc2 = (struct ums_clc_msg_accept_confirm_v2 *)buf;
	aclc = (struct ums_clc_msg_accept_confirm *)aclc2;

	rc = ums_connect_process_clc(ums, aclc2, aclc, buf, ini);
	if (rc != 0)
		goto vlan_cleanup;

	/* depending on previous steps, connect using ub */
	if (aclc->hdr.typev1 == UMS_TYPE_R) {
		rc = ums_connect_ub(ums, aclc, ini);
		if (rc != 0) {
			UMS_LOGE("connect ub failed, ret: %x", (u32)rc);
			goto vlan_cleanup;
		}
	}

	ums_copy_conn_jetty_info(ums);

	kfree(buf);
	kfree(ini);
	return 0;

vlan_cleanup:
	kfree(buf);
fallback:
	kfree(ini);
	return ums_connect_decline_fallback(ums, rc);
}

static inline bool ums_if_defer_connect(struct ums_sock *ums)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	return inet_test_bit(DEFER_CONNECT, ums->clcsock->sk);
#else
	return (inet_sk(ums->clcsock->sk)->defer_connect != 0);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0) */
}

void ums_connect_work(struct work_struct *work)
{
	struct ums_sock *ums = container_of(work, struct ums_sock, connect_work);
	long timeo = ums->sk.sk_sndtimeo;
	int rc = 0;

	if (timeo == 0)
		timeo = MAX_SCHEDULE_TIMEOUT;

	if (ums->ums_fastopen && ums_if_defer_connect(ums))
		goto defer_connect;

	lock_sock(ums->clcsock->sk);
	if (ums->clcsock->sk->sk_err != 0) {
		ums->sk.sk_err = ums->clcsock->sk->sk_err;
	} else if (((1 << ums->clcsock->sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) != 0) {
		rc = sk_stream_wait_connect(ums->clcsock->sk, &timeo);
		if ((rc == -EPIPE) &&
			(((1 << ums->clcsock->sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) != 0))
			rc = 0;
	}
	release_sock(ums->clcsock->sk);
defer_connect:
	lock_sock(&ums->sk);
	if ((rc != 0) || (ums->sk.sk_err != 0)) {
		ums->sk.sk_state = UMS_CLOSED;
		if (rc == -EPIPE || rc == -EAGAIN)
			ums->sk.sk_err = EPIPE;
		else if (signal_pending(current) != 0)
			ums->sk.sk_err = -sock_intr_errno(timeo);
		sock_put(&ums->sk); /* passive closing */
		goto out;
	}

	rc = ums_connect_inner(ums);
	if (rc < 0)
		ums->sk.sk_err = -rc;

out:
	if (!sock_flag(&ums->sk, SOCK_DEAD)) {
		if (ums->sk.sk_err != 0) {
			ums->sk.sk_state_change(&ums->sk);
		} else { /* allow polling before and after fallback decision */
			ums->clcsock->sk->sk_write_space(ums->clcsock->sk);
			ums->sk.sk_write_space(&ums->sk);
		}
	}
	release_sock(&ums->sk);
}

static int ums_connect_check_sock_state(struct socket *sock, const struct sock *sk, bool *connected)
{
	int rc = 0;

	*connected = false;

	switch (sock->state) {
	case SS_CONNECTED:
		rc = sk->sk_state == (unsigned char)UMS_ACTIVE ? -EISCONN : -EINVAL;
		break;
	case SS_CONNECTING:
		if (sk->sk_state == (unsigned char)UMS_ACTIVE)
			*connected = true;
		break;
	case SS_UNCONNECTED:
		sock->state = SS_CONNECTING;
		break;
	case SS_FREE:
	case SS_DISCONNECTING:
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int ums_connect_check_sk_state(struct sock *sk, struct socket *sock)
{
	int rc = 0;

	switch (sk->sk_state) {
	case UMS_CLOSED:
		rc = sock_error(sk);
		rc = (rc != 0) ? rc : -ECONNABORTED;
		sock->state = SS_UNCONNECTED;
		break;
	case UMS_ACTIVE:
		rc = -EISCONN;
		break;
	case UMS_INIT:
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int ums_connect_process_clcsock(struct ums_sock *ums)
{
	if (!ums->clcsock || (ums->clcsock && !ums->clcsock->sk))
		return -EBADF;

	ums_copy_sock_settings_to_clc(ums);

#if IS_ENABLED(CONFIG_SMC)
	ums_set_syn_smc(ums);
#else
	UMS_LOGW_LIMITED("CONFIG_SMC disabled, UMS cannot switch to fallback now!");
#endif

	if (ums->connect_nonblock != 0)
		return -EALREADY;

	/* the param 0 represents the server */
	if (ums->ums_fastopen && (ums_clcsock_enable_fastopen(ums, 0) != 0))
		ums->ums_fastopen = 0; /* rollback when setsockopt failed */

	return 0;
}

int ums_connect(struct socket *sock, struct sockaddr *addr, int alen, int flags)
{
	struct sock *sk = sock->sk;
	struct ums_sock *ums;
	int rc = -EINVAL;
	bool connected;

	ums = ums_sk(sk);

	/* separate ums parameter checking to be safe */
	if (alen < (int)sizeof(addr->sa_family))
		goto out_err;
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		goto out_err;

	lock_sock(sk);
	rc = ums_connect_check_sock_state(sock, sk, &connected);
	if (rc != 0)
		goto out;

	if (connected == true)
		goto connected;

	rc = ums_connect_check_sk_state(sk, sock);
	if (rc != 0)
		goto out;

	rc = ums_connect_process_clcsock(ums);
	if (rc != 0)
		goto out;

	rc = kernel_connect(ums->clcsock, addr, alen, flags);
	if ((rc != 0) && (rc != -EINPROGRESS))
		goto out;

	if (ums->use_fallback) {
		sock->state = rc != 0 ? SS_CONNECTING : SS_CONNECTED;
		goto out;
	}
	sock_hold(&ums->sk); /* sock put in passive closing */

	if ((((u32)flags) & O_NONBLOCK) != 0) {
		if (queue_work(g_ums_hs_wq, &ums->connect_work))
			ums->connect_nonblock = 1;
		rc = -EINPROGRESS;
		goto out;
	} else {
		rc = ums_connect_inner(ums);
		if (rc < 0)
			goto out;
	}

connected:
	rc = 0;
	sock->state = SS_CONNECTED;
out:
	release_sock(sk);
out_err:
	return rc;
}

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_connect);
#endif
