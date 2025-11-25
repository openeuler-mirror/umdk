// SPDX-License-Identifier: GPL-2.0
/*
 * UMS(UB Memory based Socket)
 *
 * Description:CLC (connection layer control) handshake over initial TCP socket to
 *     prepare for UB traffic
 *
 * Copyright IBM Corp. 2016, 2018
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#include <net/addrconf.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <linux/ctype.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/sched/signal.h>
#include <linux/utsname.h>

#include "ums_core.h"
#include "ums_log.h"
#include "ums_clc.h"

#define UMS_CLC_ACCEPT_CONFIRM_LEN 108
#define UMS_CLC_RECV_BUF_LEN 200
#define UMS_S6_ADDR32_NUM 3
#define UMS_PROPOSAL_KVEC_NUM 8
#define UMS_CONFIRM_KVEC_NUM 5

/* eye catcher "UMSR" EBCDIC for CLC messages */
static const char UMS_EYECATCHER[UMS_EYECATCHER_LEN] = { '\xe4', '\xd4', '\xe2', '\xd9' };

static u8 g_ums_hostname[UMS_MAX_HOSTNAME_LEN];

/* check arriving CLC proposal */
static bool ums_clc_msg_prop_valid(struct ums_clc_msg_proposal *pclc, size_t recvlen)
{
	struct ums_clc_msg_proposal_prefix *pclc_prfx;
	struct ums_clc_msg_hdr *hdr = &pclc->hdr;

	if (ntohs(pclc->iparea_offset) > recvlen - sizeof(*pclc) - sizeof(*pclc_prfx)) {
		UMS_LOGE("Invalid value of iparea_offset");
		return false;
	}

	pclc_prfx = ums_clc_proposal_get_prefix(pclc);

	if (hdr->typev1 == UMS_TYPE_N)
		return false;
	if (ntohs(hdr->length) > recvlen || ntohs(hdr->length) != sizeof(*pclc) + ntohs(pclc->iparea_offset) +
		sizeof(*pclc_prfx) + pclc_prfx->ipv6_prefixes_cnt * sizeof(struct ums_clc_ipv6_prefix) +
		sizeof(struct ums_clc_msg_trail))
		return false;

	return true;
}

/* check arriving CLC accept or confirm */
static bool ums_clc_msg_acc_conf_valid(struct ums_clc_msg_accept_confirm_v2 *clc_v2, size_t recvlen)
{
	struct ums_clc_msg_hdr *hdr = &clc_v2->hdr;

	if (hdr->typev1 != UMS_TYPE_R)
		return false;

	if ((hdr->typev1 == UMS_TYPE_R &&
		(ntohs(hdr->length) > recvlen || ntohs(hdr->length) != UMS_CLC_ACCEPT_CONFIRM_LEN)))
		return false;

	return true;
}

/* check arriving CLC decline */
static bool ums_clc_msg_decl_valid(struct ums_clc_msg_decline *dclc, size_t recvlen)
{
	struct ums_clc_msg_hdr *hdr = &dclc->hdr;

	if (hdr->typev1 != UMS_TYPE_R)
		return false;

	if (ntohs(hdr->length) > recvlen || ntohs(hdr->length) != sizeof(struct ums_clc_msg_decline))
		return false;

	return true;
}

/* check if received message has a correct header length and contains valid
 * heading and trailing eyecatchers
 */
static bool ums_clc_msg_hdr_valid(struct ums_clc_msg_hdr *clcm, bool check, size_t recvlen)
{
	struct ums_clc_msg_accept_confirm_v2 *clc_v2;
	struct ums_clc_msg_proposal *pclc;
	struct ums_clc_msg_decline *dclc;
	struct ums_clc_msg_trail *trl;
	bool check_trl = check;

	if ((memcmp(clcm->eyecatcher, UMS_EYECATCHER, sizeof(UMS_EYECATCHER)) != 0))
		return false;
	switch (clcm->type) {
	case UMS_CLC_PROPOSAL:
		pclc = (struct ums_clc_msg_proposal *)clcm;
		if (!ums_clc_msg_prop_valid(pclc, recvlen))
			return false;
		trl = (struct ums_clc_msg_trail *)((u8 *)pclc + ntohs(pclc->hdr.length) - sizeof(*trl));
		break;
	case UMS_CLC_DECLINE:
		dclc = (struct ums_clc_msg_decline *)clcm;
		if (!ums_clc_msg_decl_valid(dclc, recvlen))
			return false;
		check_trl = false;
		break;
	case UMS_CLC_ACCEPT:
	case UMS_CLC_CONFIRM:
		clc_v2 = (struct ums_clc_msg_accept_confirm_v2 *)clcm;
		if (!ums_clc_msg_acc_conf_valid(clc_v2, recvlen))
			return false;
		trl = (struct ums_clc_msg_trail *)((u8 *)clc_v2 + ntohs(clc_v2->hdr.length) - sizeof(*trl));
		break;
	default:
		return false;
	}
	if (check_trl && (memcmp(trl->eyecatcher, UMS_EYECATCHER, sizeof(UMS_EYECATCHER)) != 0))
		return false;
	return true;
}

/* find ipv4 addr on device and get the prefix len, fill CLC proposal msg */
static int ums_clc_prfx_set4_rcu(struct dst_entry *dst, __be32 ipv4,
	struct ums_clc_msg_proposal_prefix *prop)
{
	struct in_device *in_dev = __in_dev_get_rcu(dst->dev);
#ifdef KERNEL_VERSION_4
	struct in_ifaddr *in_ifa;
#else
	const struct in_ifaddr *in_ifa;
#endif

	if (!in_dev)
		return -ENODEV;

	in_dev_for_each_ifa_rcu(in_ifa, in_dev) {
		if (!inet_ifa_match(ipv4, in_ifa))
			continue;
		prop->prefix_len = (u8)inet_mask_len(in_ifa->ifa_mask);
		prop->outgoing_subnet = in_ifa->ifa_address & in_ifa->ifa_mask;
		/* prop->ipv6_prefixes_cnt = 0; already done by memset before */
		return 0;
	}
	return -ENOENT;
}

/* fill CLC proposal msg with ipv6 prefixes from device */
static int ums_clc_prfx_set6_rcu(struct dst_entry *dst, struct ums_clc_msg_proposal_prefix *prop,
	struct ums_clc_ipv6_prefix *ipv6_prfx)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev = __in6_dev_get(dst->dev);
	struct inet6_ifaddr *in6_ifa;
	int count = 0;

	if (!in6_dev)
		return -ENODEV;
	/* use a maximum of 8 IPv6 prefixes from device */
	list_for_each_entry(in6_ifa, &in6_dev->addr_list, if_list) {
		if ((((u32)ipv6_addr_type(&in6_ifa->addr)) & IPV6_ADDR_LINKLOCAL) != 0)
			continue;
		ipv6_addr_prefix(&ipv6_prfx[count].prefix, &in6_ifa->addr, (int)in6_ifa->prefix_len);
		ipv6_prfx[count].prefix_len = (u8)in6_ifa->prefix_len;
		count++;
		if (count == UMS_CLC_MAX_V6_PREFIX)
			break;
	}
	prop->ipv6_prefixes_cnt = (u8)count;
	if (count != 0)
		return 0;
#endif
	return -ENOENT;
}

/* retrieve and set prefixes in CLC proposal msg */
static int ums_clc_prfx_set(struct socket *clcsock, struct ums_clc_msg_proposal_prefix *prop,
	struct ums_clc_ipv6_prefix *ipv6_prfx)
{
	struct dst_entry *get_dst = sk_dst_get(clcsock->sk);
	struct sockaddr_storage addr_s;
	struct sockaddr_in6 *addr6;
	struct sockaddr_in *addr4;
	int rc = -ENOENT;

	if (!get_dst) {
		rc = -ENOTCONN;
		goto out;
	}
	if (!get_dst->dev) {
		rc = -ENODEV;
		goto out_release;
	}
	/* get address to which the internal TCP socket is bound */
	if (kernel_getsockname(clcsock, (struct sockaddr *)&addr_s) < 0)
		goto out_release;
	/* analyze IP specific data of net_device belonging to TCP socket */
	addr6 = (struct sockaddr_in6 *)&addr_s;
	rcu_read_lock();
	if (addr_s.ss_family == PF_INET) {
		/* IPv4 */
		addr4 = (struct sockaddr_in *)&addr_s;
		rc = ums_clc_prfx_set4_rcu(get_dst, addr4->sin_addr.s_addr, prop);
	} else if (ipv6_addr_v4mapped(&addr6->sin6_addr)) {
		/* mapped IPv4 address - peer is IPv4 only */
		rc = ums_clc_prfx_set4_rcu(get_dst, addr6->sin6_addr.s6_addr32[UMS_S6_ADDR32_NUM], prop);
	} else {
		/* IPv6 */
		rc = ums_clc_prfx_set6_rcu(get_dst, prop, ipv6_prfx);
	}
	rcu_read_unlock();
out_release:
	dst_release(get_dst);
out:
	return rc;
}

/* match ipv4 addrs of dev against addr in CLC proposal */
static int ums_clc_prfx_match4_rcu(struct net_device *dev, struct ums_clc_msg_proposal_prefix *prop)
{
	struct in_device *in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		return -ENODEV;
	// delete subnet match due to cross subnet condition
	if ((in_dev)->ifa_list != NULL) {
		return 0;
	}
	return -ENOENT;
}

/* match ipv6 addrs of dev against addrs in CLC proposal */
static int ums_clc_prfx_match6_rcu(struct net_device *dev, struct ums_clc_msg_proposal_prefix *prop)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev = __in6_dev_get(dev);
	if (!in6_dev)
		return -ENODEV;
	// delete subnet match due to cross subnet condition and determine that addr_list is not empty
	if (in6_dev->addr_list.next != &in6_dev->addr_list) {
		return 0;
	}
#endif
	return -ENOENT;
}

/* check if proposed prefixes match one of our device prefixes */
int ums_clc_prfx_match(struct socket *clcsock, struct ums_clc_msg_proposal_prefix *prop)
{
	struct dst_entry *get_dst = sk_dst_get(clcsock->sk);
	int rc;

	if (!get_dst) {
		rc = -ENOTCONN;
		goto out;
	}
	if (!get_dst->dev) {
		rc = -ENODEV;
		goto out_release;
	}
	rcu_read_lock();
	if (prop->ipv6_prefixes_cnt == 0)
		rc = ums_clc_prfx_match4_rcu(get_dst->dev, prop);
	else
		rc = ums_clc_prfx_match6_rcu(get_dst->dev, prop);
	rcu_read_unlock();
out_release:
	dst_release(get_dst);
out:
	return rc;
}

static int ums_clc_get_wait_msg_len(struct ums_sock *ums, struct kvec *vec, u8 expected_type,
	int *datalen)
{
	struct ums_clc_msg_hdr *clcm = (struct ums_clc_msg_hdr *)vec->iov_base;
	struct msghdr msg_hdr = { .msg_name = NULL, .msg_namelen = 0 };
	struct sock *clc_sk = ums->clcsock->sk;
	int len, krflags, rc;

	len = rc = 0;
	krflags = MSG_PEEK | MSG_WAITALL;
#ifdef KERNEL_VERSION_4
	iov_iter_kvec(&msg_hdr.msg_iter, READ | ITER_KVEC, vec, 1, sizeof(struct ums_clc_msg_hdr));
#else
	iov_iter_kvec(&msg_hdr.msg_iter, READ, vec, 1, sizeof(struct ums_clc_msg_hdr));
#endif
	len = sock_recvmsg(ums->clcsock, &msg_hdr, krflags);
	if (signal_pending(current) != 0) {
		rc = -EINTR;
		clc_sk->sk_err = EINTR;
		ums->sk.sk_err = EINTR;
		return rc;
	}
	if (clc_sk->sk_err != 0) {
		rc = -clc_sk->sk_err;
		if (clc_sk->sk_err == EAGAIN && expected_type == UMS_CLC_DECLINE)
			clc_sk->sk_err = 0; /* reset for fallback usage */
		else
			ums->sk.sk_err = clc_sk->sk_err;
		UMS_LOGE("sk_err, error code %d", rc);
		return rc;
	}
	if (len == 0) { /* peer has performed orderly shutdown */
		ums->sk.sk_err = ECONNRESET;
		rc = -ECONNRESET;
		return rc;
	}
	if (len < 0) {
		if (len != -EAGAIN || expected_type != UMS_CLC_DECLINE)
			ums->sk.sk_err = -len;
		rc = len;
		UMS_LOGE("len, error len %d", rc);
		return rc;
	}
	*datalen = ntohs(clcm->length);
	if ((len < (int)sizeof(struct ums_clc_msg_hdr)) ||
		((clcm->type != UMS_CLC_DECLINE) && (clcm->type != expected_type))) {
		ums->sk.sk_err = EPROTO;
		rc = -EPROTO;
		return rc;
	}

	return rc;
}

/* Returns:
 * 0 if success and it was not a decline that we received.
 * UMS_CLC_DECL_REPLY if decline received for fallback w/o another decl send.
 * clcsock error, -EINTR, -ECONNRESET, -EPROTO otherwise.
 * Wait for data on the tcp-socket, analyze received data
 */
int ums_clc_wait_msg(struct ums_sock *ums, void *buf, size_t buflen, u8 expected_type,
	unsigned long timeout)
{
	struct msghdr msg_hdr = { .msg_name = NULL, .msg_namelen = 0 };
	struct kvec vec = { .iov_base = buf, .iov_len = buflen };
	long rcvtimeo = ums->clcsock->sk->sk_rcvtimeo;
	struct sock *clc_sk = ums->clcsock->sk;
	struct ums_clc_msg_hdr *clcm = buf;
	int len, datlen, krflags;
	bool check_trl = true;
	size_t recvlen = 0;
	int rc = 0;

	len = datlen = krflags = 0;
	clc_sk->sk_rcvtimeo = (long)timeout;

	/* peek the first few bytes to determine length of data to receive
	 * so we don't consume any subsequent CLC message or payload data
	 * in the TCP byte stream.
	 * Caller must make sure that buflen is no less than
	 * sizeof(struct ums_clc_msg_hdr)
	 */
	rc = ums_clc_get_wait_msg_len(ums, &vec, expected_type, &datlen);
	if (rc != 0) {
		goto out;
	}

	/* receive the complete CLC message */
	(void)memset(&msg_hdr, 0, sizeof(struct msghdr));
	if ((size_t)datlen > buflen) {
		check_trl = false;
		recvlen = buflen;
	} else {
		recvlen = (u32)datlen;
	}
#ifdef KERNEL_VERSION_4
	iov_iter_kvec(&msg_hdr.msg_iter, READ | ITER_KVEC, &vec, 1, recvlen);
#else
	iov_iter_kvec(&msg_hdr.msg_iter, READ, &vec, 1, recvlen);
#endif
	krflags = MSG_WAITALL;
	len = sock_recvmsg(ums->clcsock, &msg_hdr, krflags);
	if (len < (int)recvlen || !ums_clc_msg_hdr_valid(clcm, check_trl, recvlen)) {
		ums->sk.sk_err = EPROTO;
		rc = -EPROTO;
		goto out;
	}
	datlen -= len;
	while (datlen > 0) {
		u8 tmp[UMS_CLC_RECV_BUF_LEN];

		vec.iov_base = tmp;
		vec.iov_len = UMS_CLC_RECV_BUF_LEN;
		/* receive remaining proposal message */
		recvlen = datlen > UMS_CLC_RECV_BUF_LEN ? UMS_CLC_RECV_BUF_LEN : (size_t)datlen;
#ifdef KERNEL_VERSION_4
		iov_iter_kvec(&msg_hdr.msg_iter, READ | ITER_KVEC, &vec, 1, recvlen);
#else
		iov_iter_kvec(&msg_hdr.msg_iter, READ, &vec, 1, recvlen);
#endif
		len = sock_recvmsg(ums->clcsock, &msg_hdr, krflags);
		datlen -= len;
	}

	if (clcm->type == UMS_CLC_DECLINE) {
		struct ums_clc_msg_decline *dclc;

		dclc = (struct ums_clc_msg_decline *)clcm;
		rc = UMS_CLC_DECL_PEERDECL;
		ums->peer_diagnosis = ntohl(dclc->peer_diagnosis);
		if ((expected_type == UMS_CLC_CONFIRM) &&
			((((struct ums_clc_msg_decline *)buf)->hdr.typev2 & UMS_FIRST_CONTACT_MASK) != 0)) {
			/* lgr is null ptr when expected_type is UMS_CLC_PROPOSAL */
			ums->conn.lgr->sync_err = 1;
		}
	}

out:
	clc_sk->sk_rcvtimeo = rcvtimeo;
	return rc;
}

/* send CLC DECLINE message across internal TCP socket */
int ums_clc_send_decline(struct ums_sock *ums, u32 peer_diag_info)
{
	struct ums_clc_msg_decline *dclc_v1;
	struct ums_clc_msg_decline_v2 dclc;
	struct msghdr msg;
	size_t send_len;
	struct kvec vec;
	int len;

	dclc_v1 = (struct ums_clc_msg_decline *)&dclc;
	(void)memset(&dclc, 0, sizeof(struct ums_clc_msg_decline_v2));
	(void)memcpy(dclc.hdr.eyecatcher, UMS_EYECATCHER, UMS_EYECATCHER_LEN);
	dclc.hdr.type = UMS_CLC_DECLINE;
	dclc.os_type = 0;
	dclc.hdr.typev2 = (peer_diag_info == UMS_CLC_DECL_SYNCERR) ? UMS_FIRST_CONTACT_MASK : 0;
	if (ums_ubcore_is_valid_local_systemid())
		(void)memcpy(dclc.id_for_peer, g_local_systemid, UMS_SYSTEMID_LEN);
	dclc.peer_diagnosis = htonl(peer_diag_info);

	(void)memcpy(dclc_v1->trl.eyecatcher, UMS_EYECATCHER, UMS_EYECATCHER_LEN);
	send_len = sizeof(*dclc_v1);

	dclc.hdr.length = htons(send_len);

	(void)memset(&msg, 0, sizeof(struct msghdr));
	vec.iov_base = &dclc;
	vec.iov_len = send_len;
	down_read(&ums->clcsock_release_lock);
	if (!ums->clcsock || !ums->clcsock->sk) {
		up_read(&ums->clcsock_release_lock);
		return -EPROTO;
	}
	len = kernel_sendmsg(ums->clcsock, &msg, &vec, 1, send_len);
	up_read(&ums->clcsock_release_lock);
	if (len < 0 || len < (int)send_len)
		len = -EPROTO;
	return len > 0 ? 0 : len;
}

static int ums_clc_init_proposal(struct ums_sock *ums, struct ums_clc_msg_proposal_area *pclc,
	struct ums_init_info *ini)
{
	struct ums_clc_msg_proposal_prefix *pclc_prfx = &pclc->pclc_prfx;
	struct ums_clc_msg_proposal *pclc_base = &pclc->pclc_base;
	struct ums_clc_msg_umsd *pclc_umsd = &pclc->pclc_umsd;
	size_t plen;
	int rc = 0;

	pclc_base->hdr.typev1 = ini->ums_type_v1;
	plen = sizeof(*pclc_base) + sizeof(*pclc_umsd) + sizeof(pclc->pclc_trl);

	/* retrieve ip prefixes for CLC proposal msg */
	if (ini->ums_type_v1 != UMS_TYPE_N) {
		rc = ums_clc_prfx_set(ums->clcsock, pclc_prfx, pclc->pclc_prfx_ipv6);
		if (rc != 0) {
			return UMS_CLC_DECL_CNFERR;
		} else {
			pclc_base->iparea_offset = htons(sizeof(*pclc_umsd));
			plen += sizeof(*pclc_prfx) + pclc_prfx->ipv6_prefixes_cnt *
				sizeof(pclc->pclc_prfx_ipv6[0]);
		}
	}

	/* build UMS Proposal CLC message */
	(void)memcpy(pclc_base->hdr.eyecatcher, UMS_EYECATCHER, UMS_EYECATCHER_LEN);
	pclc_base->hdr.type = UMS_CLC_PROPOSAL;
	if (ums_indicated(ini->ums_type_v1)) {
		(void)memcpy(pclc_base->lcl.id_for_peer, g_local_systemid, UMS_SYSTEMID_LEN);
		(void)memcpy(pclc_base->lcl.eid.raw, ini->eid.raw, UMS_EID_SIZE);
		pclc_base->lcl.eid_index = ini->eid_index;
		(void)memcpy(pclc_base->lcl.mac, ini->ub_dev->mac[ini->ub_port], ETH_ALEN);
	}

	pclc_umsd->v2_ext_offset = 0;
	pclc_base->hdr.length = htons(plen);
	(void)memcpy(pclc->pclc_trl.eyecatcher, UMS_EYECATCHER, UMS_EYECATCHER_LEN);

	return 0;
}

static int ums_clc_init_proposal_kvec(struct msghdr *msg_hdr, struct kvec *vec,
	struct ums_clc_msg_proposal_area *pclc, const struct ums_init_info *ini)
{
	struct ums_clc_msg_proposal_prefix *pclc_prfx;
	struct ums_clc_msg_proposal *pclc_base;
	int i = 0;

	pclc_base = &pclc->pclc_base;
	pclc_prfx = &pclc->pclc_prfx;
	(void)memset(msg_hdr, 0, sizeof(struct msghdr));
	vec[i].iov_base = pclc_base;
	vec[i++].iov_len = sizeof(*pclc_base);
	vec[i].iov_base = &pclc->pclc_umsd;
	vec[i++].iov_len = sizeof(pclc->pclc_umsd);
	if (ini->ums_type_v1 != UMS_TYPE_N) {
		vec[i].iov_base = pclc_prfx;
		vec[i++].iov_len = sizeof(struct ums_clc_msg_proposal_prefix);
		if (pclc_prfx->ipv6_prefixes_cnt > 0) {
			vec[i].iov_base = pclc->pclc_prfx_ipv6;
			vec[i++].iov_len = pclc_prfx->ipv6_prefixes_cnt * sizeof(pclc->pclc_prfx_ipv6[0]);
		}
	}

	vec[i].iov_base = &pclc->pclc_trl;
	vec[i++].iov_len = sizeof(pclc->pclc_trl);

	return i;
}

/* send CLC PROPOSAL message across internal TCP socket */
int ums_clc_send_proposal(struct ums_sock *ums, struct ums_init_info *ini)
{
	struct ums_clc_msg_proposal_area *pclc;
	struct kvec vec[UMS_PROPOSAL_KVEC_NUM];
	struct msghdr msg_hdr;
	int i, rc, plen, len;
	
	len = i = rc = plen = 0;
	pclc = kzalloc(sizeof(*pclc), GFP_KERNEL);
	if (!pclc)
		return -ENOMEM;

	rc = ums_clc_init_proposal(ums, pclc, ini);
	if (rc != 0) {
		kfree(pclc);
		return rc;
	}

	/* send UMS Proposal CLC message */
	i = ums_clc_init_proposal_kvec(&msg_hdr, vec, pclc, ini);
	/* due to the few bytes needed for clc-handshake this cannot block */

	plen = ntohs(pclc->pclc_base.hdr.length);
	len = kernel_sendmsg(ums->clcsock, &msg_hdr, vec, (u32)i, plen);
	if (len < 0) {
		ums->sk.sk_err = ums->clcsock->sk->sk_err;
		rc = -ums->sk.sk_err;
	} else if (len < plen) {
		rc = -ENETUNREACH;
		ums->sk.sk_err = -rc;
	}

	kfree(pclc);
	return rc;
}

static void ums_clc_confirm_accept_init_basic(struct ums_sock *ums,
	struct ums_clc_msg_accept_confirm *clc)
{
	struct ums_connection *conn = &ums->conn;
	struct ums_link *link = conn->lnk;

	(void)memcpy(clc->hdr.eyecatcher, UMS_EYECATCHER, UMS_EYECATCHER_LEN);
	clc->hdr.typev1 = UMS_TYPE_R;
	clc->hdr.length = htons(UMS_CLC_ACCEPT_CONFIRM_LEN);
	(void)memcpy(clc->r0.lcl.id_for_peer, g_local_systemid, UMS_SYSTEMID_LEN);
	(void)memcpy(clc->r0.lcl.eid.raw, link->eid.raw, UMS_EID_SIZE);
	clc->r0.lcl.eid_index = link->eid_index;
	(void)memcpy(clc->r0.lcl.mac, link->ums_dev->mac[link->port], ETH_ALEN);
	clc->r0.rmbe_idx = 1; /* for now: 1 RMB = 1 RMBE */
	clc->r0.rmbe_alert_token = htonl(conn->conn_id);

	switch (clc->hdr.type) {
	case UMS_CLC_ACCEPT:
		clc->r0.qp_mtu = (u8)link->path_mtu;
		clc->r0.init_credits = (u8)link->wr_rx_cnt;
		break;
	case UMS_CLC_CONFIRM:
		clc->r0.qp_mtu = (u8)min(link->path_mtu, link->peer_mtu);
		clc->r0.init_credits = link->credits_enable != 0 ? (u8)link->wr_rx_cnt : 0;
		break;
	default:
		UMS_LOGE("Wrong msg type when handle msg init.");
		break;
	}
	clc->r0.rmbe_size = (u8)conn->rmbe_size_short;
	/* only support va now */
	clc->r0.rmb_dma_addr = cpu_to_be64((uintptr_t)conn->rmb_desc->cpu_addr);
	hton24(clc->r0.psn, link->psn_initial);
	clc->r0.jetty_id = htonl(link->ub_jetty->jetty_id.id);
	clc->r0.seg_flag = htonl(conn->rmb_desc->seg[link->link_idx]->seg.attr.value);
	if (g_ums_sys_tuning_config.ub_token_disable) {
		clc->r0.jetty_token_policy = UBCORE_TOKEN_NONE;
		clc->r0.jetty_token_value = 0;
		clc->r0.seg_token_value = 0;
	} else {
		clc->r0.jetty_token_policy = UBCORE_TOKEN_PLAIN_TEXT;
		clc->r0.jetty_token_value = htonl(link->jetty_token_value.token);
		clc->r0.seg_token_value = htonl(conn->rmb_desc->seg_token_value.token);
	}
	clc->r0.seg_token_id = htonl(conn->rmb_desc->seg[link->link_idx]->seg.token_id);
}

static inline void ums_clc_confirm_accept_init_trl(struct ums_clc_msg_trail *trl)
{
	(void)memcpy(trl->eyecatcher, UMS_EYECATCHER, UMS_EYECATCHER_LEN);
}

/* build and send CLC CONFIRM / ACCEPT message */
static int ums_clc_send_confirm_accept(struct ums_sock *ums,
	struct ums_clc_msg_accept_confirm_v2 *clc_v2, bool first_contact, u8 *eid,
	struct ums_init_info *ini)
{
	struct ums_clc_msg_accept_confirm *clc;
	struct kvec vec[UMS_CONFIRM_KVEC_NUM];
	struct ums_clc_msg_trail trl;
	struct msghdr msg;
	int i;

	/* send UMS Confirm CLC msg */
	clc = (struct ums_clc_msg_accept_confirm *)clc_v2;
	if (first_contact)
		clc->hdr.typev2 |= UMS_FIRST_CONTACT_MASK;
	ums_clc_confirm_accept_init_basic(ums, clc);

	clc->hdr.length = htons(UMS_CLC_ACCEPT_CONFIRM_LEN);

	ums_clc_confirm_accept_init_trl(&trl);

	(void)memset(&msg, 0, sizeof(struct msghdr));
	i = 0;
	vec[i].iov_base = clc_v2;
	vec[i++].iov_len = UMS_CLC_ACCEPT_CONFIRM_LEN - sizeof(trl);

	vec[i].iov_base = &trl;
	vec[i++].iov_len = sizeof(struct ums_clc_msg_trail);
	return kernel_sendmsg(ums->clcsock, &msg, vec, 1, ntohs(clc->hdr.length));
}

/* send CLC CONFIRM message across internal TCP socket */
int ums_clc_send_confirm(struct ums_sock *ums, bool clnt_first_contact, u8 *eid,
	struct ums_init_info *ini)
{
	struct ums_clc_msg_accept_confirm_v2 cclc_v2;
	int reason_code = 0;
	int len;

	/* send UMS Confirm CLC msg */
	(void)memset(&cclc_v2, 0, sizeof(struct ums_clc_msg_accept_confirm_v2));
	cclc_v2.hdr.type = UMS_CLC_CONFIRM;
	len = ums_clc_send_confirm_accept(ums, &cclc_v2, clnt_first_contact, eid, ini);
	if (len < ntohs(cclc_v2.hdr.length)) {
		if (len >= 0) {
			reason_code = -ENETUNREACH;
			ums->sk.sk_err = -reason_code;
		} else {
			ums->sk.sk_err = ums->clcsock->sk->sk_err;
			reason_code = -ums->sk.sk_err;
		}
	}
	return reason_code;
}

/* send CLC ACCEPT message across internal TCP socket */
int ums_clc_send_accept(struct ums_sock *ums, bool srv_first_contact,
	u8 *negotiated_eid)
{
	struct ums_clc_msg_accept_confirm_v2 aclc_v2;
	int len;

	(void)memset(&aclc_v2, 0, sizeof(struct ums_clc_msg_accept_confirm_v2));
	aclc_v2.hdr.type = UMS_CLC_ACCEPT;
	len = ums_clc_send_confirm_accept(ums, &aclc_v2, srv_first_contact, negotiated_eid,
		NULL);
	if (len < ntohs(aclc_v2.hdr.length))
		len = len >= 0 ? -EPROTO : -ums->clcsock->sk->sk_err;

	return len > 0 ? 0 : len;
}

void __init ums_clc_init(void)
{
	struct new_utsname *u;

	/* ASCII blanks */
	(void)memset(g_ums_hostname, _S, UMS_MAX_HOSTNAME_LEN);
	u = utsname();
	(void)memcpy(g_ums_hostname, u->nodename,
		min_t(size_t, strlen(u->nodename), UMS_MAX_HOSTNAME_LEN));
}

void ums_clc_exit(void) {}