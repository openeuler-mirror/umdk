// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:Link Layer Control (LLC) implementation
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Klaus Wacker <Klaus.Wacker@de.ibm.com>
 *  			  Ursula Braun <ubraun@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s):  YAO Yufeng ZHANG Chuwen
 */

#include <net/tcp.h>

#include "ums_clc.h"
#include "ums_core.h"
#include "ums_log.h"
#include "ums_mod.h"
#include "ums_pnet.h"
#include "ums_llc.h"

#define UMS_LLC_FLAG_NO_RMBE_EYEC	0x03
#define UMS_LLC_FLAG_ADD_LNK_REJ	0x40
#define UMS_LLC_REJ_RSN_NO_ALT_PATH	1
#define UMS_LLC_ADD_LNK_MAX_LINKS	2
#define UMS_LLC_FLAG_DEL_LINK_ALL	0x40
#define UMS_LLC_FLAG_DEL_LINK_ORDERLY	0x20
#define UMS_LLC_DEL_RKEY_MAX	8
#define UMS_LLC_FLAG_RKEY_RETRY	0x10
#define UMS_LLC_FLAG_RKEY_NEG	0x20

static void ums_llc_enqueue(struct ums_link *link, union ums_llc_msg *llc);

struct ums_llc_qentry *ums_llc_flow_qentry_clr(struct ums_llc_flow *flow)
{
	struct ums_llc_qentry *qentry;
	if (unlikely(!flow))
		return NULL;
	qentry = flow->qentry;

	flow->qentry = NULL;
	return qentry;
}

void ums_llc_flow_qentry_del(struct ums_llc_flow *flow)
{
	struct ums_llc_qentry *qentry;

	if (flow->qentry) {
		qentry = flow->qentry;
		flow->qentry = NULL;
		kfree(qentry);
	}
}

static void ums_llc_flow_parallel(struct ums_link_group *lgr, u8 flow_type,
	struct ums_llc_qentry **qentry)
{
	u8 msg_type = (*qentry)->msg.raw.hdr.common.llc_type;

	if ((msg_type == (u8)UMS_LLC_DELETE_LINK) &&
		flow_type != msg_type && !lgr->delayed_event) {
		lgr->delayed_event = *qentry;
		return;
	}
	/* drop parallel or already-in-progress llc requests */
	if (flow_type != msg_type)
		UMS_LOGW_ONCE("UMS lg %*phN dropped parallel LLC msg: msg %d flow %hhu role %d",
			UMS_LGR_ID_SIZE, lgr->id, (*qentry)->msg.raw.hdr.common.type, flow_type, (int)lgr->role);
	kfree(*qentry);
	*qentry = NULL;
}

/* try to start a new llc flow, initiated by an incoming llc msg */
bool ums_llc_flow_start(struct ums_llc_flow *flow, struct ums_llc_qentry *qentry)
{
	struct ums_link_group *lgr = qentry->link->lgr;

	spin_lock_bh(&lgr->llc_flow_lock);
	if (flow->type != UMS_LLC_FLOW_NONE) {
		/* a flow is already active */
		ums_llc_flow_parallel(lgr, (u8)flow->type, &qentry);
		spin_unlock_bh(&lgr->llc_flow_lock);
		return false;
	}
	switch (qentry->msg.raw.hdr.common.llc_type) {
	case UMS_LLC_ADD_LINK:
		flow->type = UMS_LLC_FLOW_ADD_LINK;
		break;
	case UMS_LLC_DELETE_LINK:
		flow->type = UMS_LLC_FLOW_DEL_LINK;
		break;
	case UMS_LLC_CONFIRM_RKEY:
	case UMS_LLC_DELETE_RKEY:
		flow->type = UMS_LLC_FLOW_RKEY;
		break;
	default:
		flow->type = UMS_LLC_FLOW_NONE;
	}
	ums_llc_flow_qentry_set(flow, qentry);
	spin_unlock_bh(&lgr->llc_flow_lock);
	return true;
}

static inline bool ums_llc_flow_initiate_condition(const struct ums_link_group *lgr,
	enum ums_llc_flowtype ftype)
{
	return lgr->llc_flow_lcl.type == UMS_LLC_FLOW_NONE &&
	    (lgr->llc_flow_rmt.type == UMS_LLC_FLOW_NONE ||
	     lgr->llc_flow_rmt.type == ftype);
}

/* start a new local llc flow, wait till current flow finished */
int ums_llc_flow_initiate(struct ums_link_group *lgr, enum ums_llc_flowtype type)
{
	enum ums_llc_flowtype allowed_remote = UMS_LLC_FLOW_NONE;
	const int wait_time_rate = 10;
	int rc;

	/* all flows except confirm_rkey and delete_rkey are exclusive,
	 * confirm/delete rkey flows can run concurrently (local and remote)
	 */
	if (type == UMS_LLC_FLOW_RKEY)
		allowed_remote = UMS_LLC_FLOW_RKEY;

	while (true) {
		if (list_empty(&lgr->list) != 0)
			return -ENODEV;
		spin_lock_bh(&lgr->llc_flow_lock);
		if (ums_llc_flow_initiate_condition(lgr, allowed_remote)) {
			lgr->llc_flow_lcl.type = type;
			spin_unlock_bh(&lgr->llc_flow_lock);
			return 0;
		}
		spin_unlock_bh(&lgr->llc_flow_lock);
		rc = (int)wait_event_timeout(lgr->llc_flow_waiter, ((list_empty(&lgr->list) != 0) ||
			ums_llc_flow_initiate_condition(lgr, allowed_remote)),
			UMS_LLC_WAIT_TIME * wait_time_rate);
		if (rc == 0)
			return -ETIMEDOUT;
	}
}

/* finish the current llc flow */
void ums_llc_flow_stop(struct ums_link_group *lgr, struct ums_llc_flow *flow)
{
	spin_lock_bh(&lgr->llc_flow_lock);
	(void)memset(flow, 0, sizeof(struct ums_llc_flow));
	flow->type = UMS_LLC_FLOW_NONE;
	spin_unlock_bh(&lgr->llc_flow_lock);
	if ((list_empty(&lgr->list) == 0) && (flow == &lgr->llc_flow_lcl) && lgr->delayed_event)
		(void)schedule_work(&lgr->llc_event_work);
	else
		wake_up(&lgr->llc_flow_waiter);
}

struct ums_llc_qentry *ums_llc_wait(struct ums_link_group *lgr, struct ums_link *lnk,
	int time_out, u8 exp_msg)
{
	struct ums_llc_flow *flow = &lgr->llc_flow_lcl;
	u8 rcv_msg;

	wait_event_timeout(lgr->llc_msg_waiter, (flow->qentry || (lnk && !ums_link_usable(lnk)) ||
		(list_empty(&lgr->list) != 0)), time_out);
	if (!flow->qentry || (lnk && !ums_link_usable(lnk)) || (list_empty(&lgr->list) != 0)) {
		UMS_LOGE("list_empty: %d, wait confirm link message from server failed !",
			list_empty(&lgr->list));
		ums_llc_flow_qentry_del(flow);
		goto out;
	}
	rcv_msg = flow->qentry->msg.raw.hdr.common.llc_type;
	if ((exp_msg != 0) && (rcv_msg != exp_msg)) {
		if (rcv_msg == (u8)UMS_LLC_DELETE_LINK) {
			/* flow_start will delay the unexpected msg */
			(void)ums_llc_flow_start(&lgr->llc_flow_lcl, ums_llc_flow_qentry_clr(flow));
			return NULL;
		}
		UMS_LOGW_ONCE(
			"UMS lg %*phN dropped unexpected LLC msg: msg %hhu exp %hhu flow %d role %d flags %x",
			UMS_LGR_ID_SIZE, lgr->id, rcv_msg, exp_msg, (int)flow->type, (int)lgr->role,
			flow->qentry->msg.raw.hdr.flags);
		ums_llc_flow_qentry_del(flow);
	}
out:
	return flow->qentry;
}

/********************************** send *************************************/

/* handler for send/transmission completion of an LLC msg */
static void ums_llc_tx_handler(struct ums_wr_tx_pend_priv *pend, struct ums_link *link,
	enum ubcore_cr_opcode cr_opcode)
{}

/**
 * ums_llc_add_pending_send() - add LLC control message to pending WQE transmits
 * @link: Pointer to UMS link used for sending LLC control message.
 * @wr_buf: Out variable returning pointer to work request payload buffer.
 * @pend: Out variable returning pointer to private pending WR tracking.
 *	  It's the context the transmit complete handler will get.
 * @emergency: If true, can use reserved emergency credits (for LLC announce credits only).
 *
 * Reserves and pre-fills an entry for a pending work request send/tx.
 * Used by mid-level ums_llc_send_msg() to prepare for later actual send/tx.
 * Can sleep due to ums_get_ctrl_buf (if not in softirq context).
 *
 * Return: 0 on success, otherwise an error value.
 */
int ums_llc_add_pending_send(struct ums_link *link, struct ums_wr_buf **wr_buf,
	struct ums_wr_tx_pend_priv **pend, bool emergency)
{
	int rc;

	rc = ums_wr_tx_get_free_slot(link, ums_llc_tx_handler, wr_buf, NULL, pend, emergency);
	if (rc < 0) {
		UMS_LOGW_LIMITED("get free slot failed, in_sotfrq=%ld, rc=%d, "
			"peer_rq=%d, local_rq=%d", in_softirq(), rc, atomic_read(&link->peer_rq_credits),
			atomic_read(&link->local_rq_credits));
		return rc;
	}

	BUILD_BUG_ON_MSG(
		sizeof(union ums_llc_msg) > UMS_WR_BUF_SIZE,
		"must increase UMS_WR_BUF_SIZE to at least sizeof(struct ums_llc_msg)");
	BUILD_BUG_ON_MSG(
		sizeof(union ums_llc_msg) != UMS_WR_TX_SIZE,
		"must adapt UMS_WR_TX_SIZE to sizeof(struct ums_llc_msg); if not all ums_wr upper layer "
		"protocols use the same message size any more, must start to set "
		"link->wr_tx_sges[i].length on each individual ums_wr_tx_send()");
	return 0;
}

void ums_llc_init_msg_hdr(struct ums_llc_hdr *hdr, const struct ums_link_group *lgr, size_t len)
{
	hdr->common.llc_version = 0;
	hdr->length = (u8)len;
}

/* high-level API to send LLC confirm link */
int ums_llc_send_confirm_link(struct ums_link *link, enum ums_llc_reqresp reqresp)
{
	struct ums_llc_msg_confirm_link *confllc;
	struct ums_wr_tx_pend_priv *pend;
	struct ums_wr_buf *wr_buf;
	int rc;

	if (!ums_wr_tx_link_hold(link))
		return -ENOLINK;

	rc = ums_llc_add_pending_send(link, &wr_buf, &pend, false);
	if (rc != 0)
		goto put_out;

	confllc = (struct ums_llc_msg_confirm_link *)wr_buf;
	(void)memset(confllc, 0, sizeof(struct ums_llc_msg_confirm_link));
	confllc->hd.common.llc_type = UMS_LLC_CONFIRM_LINK;
	ums_llc_init_msg_hdr(&confllc->hd, link->lgr, sizeof(*confllc));
	confllc->hd.flags |= UMS_LLC_FLAG_NO_RMBE_EYEC;
	if (reqresp == UMS_LLC_RESP)
		confllc->hd.flags |= UMS_LLC_FLAG_RESP;
	(void)memcpy(confllc->sender_mac, link->ums_dev->mac[link->port], ETH_ALEN);
	(void)memcpy(confllc->sender_eid, link->eid.raw, UMS_EID_SIZE);
	confllc->sender_jetty_id = htonl(link->ub_jetty->jetty_id.id);
	confllc->link_num = link->link_id;
	(void)memcpy(confllc->link_uid, link->link_uid, UMS_LGR_ID_SIZE);
	confllc->max_links = UMS_LLC_ADD_LNK_MAX_LINKS;
	/* send llc message */
	rc = ums_wr_tx_send(link, pend);
put_out:
	ums_wr_tx_link_put(link);
	return rc;
}

/* send LLC delete rkey request */
static int ums_llc_send_delete_rkey(struct ums_link *link, struct ums_buf_desc *rmb_desc)
{
	struct ums_llc_msg_delete_rkey *rkeyllc;
	struct ums_wr_tx_pend_priv *pend;
	struct ums_wr_buf *wr_buf;
	int rc;

	if (!ums_wr_tx_link_hold(link))
		return -ENOLINK;
	rc = ums_llc_add_pending_send(link, &wr_buf, &pend, false);
	if (rc != 0)
		goto put_out;
	rkeyllc = (struct ums_llc_msg_delete_rkey *)wr_buf;
	(void)memset(rkeyllc, 0, sizeof(struct ums_llc_msg_delete_rkey));
	rkeyllc->hd.common.llc_type = UMS_LLC_DELETE_RKEY;
	ums_llc_init_msg_hdr(&rkeyllc->hd, link->lgr, sizeof(*rkeyllc));
	/* wont clear rtokens_used_mask with this msg, it will be cleared within unimport segment process */
	rkeyllc->num_rkeys = 0;
	/* send llc message */
	rc = ums_wr_tx_send(link, pend);
put_out:
	ums_wr_tx_link_put(link);
	return rc;
}

/* send credits announce request or response  */
int ums_llc_announce_credits(struct ums_link *link, enum ums_llc_reqresp reqresp, bool force)
{
	struct ums_llc_msg_announce_credits *announce_credits;
	struct ums_wr_tx_pend_priv *pend;
	struct ums_wr_buf *wr_buf;
	u8 saved_credits = 0;
	int rc;

	if ((link->credits_enable == 0) || (!force && ums_wr_rx_credits_need_announce(link) == 0))
		return 0;

	saved_credits = (u8)ums_wr_rx_get_credits(link);
	if (saved_credits == 0)
		/* maybe synced by cdc msg */
		return 0;

	rc = ums_llc_add_pending_send(link, &wr_buf, &pend, true);
	if (rc != 0) {
		ums_wr_rx_put_credits(link, saved_credits);
		return rc;
	}

	announce_credits = (struct ums_llc_msg_announce_credits *)wr_buf;
	(void)memset(announce_credits, 0, sizeof(struct ums_llc_msg_announce_credits));
	announce_credits->hd.common.type = UMS_LLC_ANNOUNCE_CREDITS;
	announce_credits->hd.length = sizeof(struct ums_llc_msg_announce_credits);
	if (reqresp == UMS_LLC_RESP)
		announce_credits->hd.flags |= UMS_LLC_FLAG_RESP;
	announce_credits->credits = saved_credits;
	/* send llc message */
	rc = ums_wr_tx_send(link, pend);
	if (rc != 0)
		ums_wr_rx_put_credits(link, saved_credits);

	return rc;
}

static int ums_llc_send_message_inner(struct ums_link *link, void *llcbuf, bool wait)
{
	struct ums_wr_tx_pend_priv *pend;
	struct ums_wr_buf *wr_buf;
	int rc;

	if (!ums_wr_tx_link_hold(link))
		return -ENOLINK;
	rc = ums_llc_add_pending_send(link, &wr_buf, &pend, false);
	if (rc != 0)
		goto put_out;
	(void)memcpy(wr_buf, llcbuf, sizeof(union ums_llc_msg));
	if (wait)
		rc = ums_wr_tx_send_wait(link, pend, UMS_LLC_WAIT_TIME);
	else
		rc = ums_wr_tx_send(link, pend);
put_out:
	ums_wr_tx_link_put(link);
	return rc;
}

/* schedule an llc send on link, may wait for buffers */
int ums_llc_send_message(struct ums_link *link, void *llcbuf)
{
	return ums_llc_send_message_inner(link, llcbuf, false);
}

/* schedule an llc send on link, may wait for buffers,
 * and wait for send completion notification.
 * @return 0 on success
 */
static int ums_llc_send_message_wait(struct ums_link *link, void *llcbuf)
{
	return ums_llc_send_message_inner(link, llcbuf, true);
}

/********************************* receive ***********************************/
static int ums_llc_active_link_count(struct ums_link_group *lgr)
{
	int i, link_count = 0;

	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		if (!ums_link_active(&lgr->lnk[i]))
			continue;
		link_count++;
	}
	return link_count;
}

void ums_llc_process_cli_delete_link(struct ums_link_group *lgr)
{
	struct ums_link *lnk_del = NULL, *lnk;
	struct ums_llc_msg_del_link *del_llc;
	struct ums_llc_qentry *qentry;
	int active_links;
	int lnk_idx;

	qentry = ums_llc_flow_qentry_clr(&lgr->llc_flow_lcl);
	if (unlikely(!qentry)) {
		UMS_LOGI("qentry is null");
		return;
	}
	lnk = qentry->link;
	del_llc = &qentry->msg.delete_link;

	if ((del_llc->hd.flags & UMS_LLC_FLAG_DEL_LINK_ALL) != 0) {
		ums_lgr_terminate_sched(lgr);
		goto out;
	}
	mutex_lock(&lgr->llc_conf_mutex);
	/* delete single link */
	for (lnk_idx = 0; lnk_idx < UMS_LINKS_PER_LGR_MAX; lnk_idx++) {
		if (lgr->lnk[lnk_idx].link_id != del_llc->link_num)
			continue;
		lnk_del = &lgr->lnk[lnk_idx];
		break;
	}
	del_llc->hd.flags |= UMS_LLC_FLAG_RESP;
	if (!lnk_del) {
		/* link was not found */
		del_llc->reason = htonl(UMS_LLC_DEL_NOLNK);
		(void)ums_llc_send_message(lnk, &qentry->msg);
		goto out_unlock;
	}

	del_llc->reason = 0;
	(void)ums_llc_send_message(lnk, &qentry->msg); /* response */

	/* clear the delete link */
	ums_link_clear(lnk_del, true);

	active_links = ums_llc_active_link_count(lgr);
	if (active_links == 1) {
		ums_lgr_set_type(lgr, UMS_LGR_SINGLE);
	} else if (active_links == 0) {
		ums_lgr_set_type(lgr, UMS_LGR_NONE);
		ums_lgr_terminate_sched(lgr);
	}
out_unlock:
	mutex_unlock(&lgr->llc_conf_mutex);
out:
	kfree(qentry);
}

void ums_llc_send_link_delete_all(struct ums_link_group *lgr, bool ord, u32 rsn)
{
	struct ums_llc_msg_del_link delllc = {};
	int i;

	delllc.hd.common.llc_type = UMS_LLC_DELETE_LINK;
	ums_llc_init_msg_hdr(&delllc.hd, lgr, sizeof(delllc));
	if (ord)
		delllc.hd.flags |= UMS_LLC_FLAG_DEL_LINK_ORDERLY;
	delllc.hd.flags |= UMS_LLC_FLAG_DEL_LINK_ALL;
	delllc.reason = htonl(rsn);

	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		if (!ums_link_sendable(&lgr->lnk[i]))
			continue;
		if (ums_llc_send_message_wait(&lgr->lnk[i], &delllc) == 0)
			break;
	}
}

void ums_llc_process_srv_delete_link(struct ums_link_group *lgr)
{
	struct ums_llc_msg_del_link *del_llc;
	struct ums_link *lnk, *lnk_del;
	struct ums_llc_qentry *qentry;
	int active_links;
	int i;

	mutex_lock(&lgr->llc_conf_mutex);
	qentry = ums_llc_flow_qentry_clr(&lgr->llc_flow_lcl);
	if (unlikely(!qentry)) {
		mutex_unlock(&lgr->llc_conf_mutex);
		return;
	}
	lnk = qentry->link;
	del_llc = &qentry->msg.delete_link;

	if ((qentry->msg.delete_link.hd.flags & UMS_LLC_FLAG_DEL_LINK_ALL) != 0) {
		/* delete entire lgr */
		ums_llc_send_link_delete_all(lgr, true, ntohl(
					      qentry->msg.delete_link.reason));
		ums_lgr_terminate_sched(lgr);
		goto out;
	}
	/* delete single link */
	lnk_del = NULL;
	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		if (lgr->lnk[i].link_id == del_llc->link_num) {
			lnk_del = &lgr->lnk[i];
			break;
		}
	}
	if (!lnk_del)
		goto out; /* asymmetric link already deleted */

	if (list_empty(&lgr->list) == 0) {
		/* qentry is either a request from peer (send it back to
		 * initiate the DELETE_LINK processing), or a locally
		 * enqueued DELETE_LINK request (forward it)
		 */
		if (ums_llc_send_message(lnk, &qentry->msg) == 0) {
			struct ums_llc_qentry *qentry2;

			qentry2 = ums_llc_wait(lgr, lnk, UMS_LLC_WAIT_TIME,
					       UMS_LLC_DELETE_LINK);
			if (qentry2)
				ums_llc_flow_qentry_del(&lgr->llc_flow_lcl);
		}
	}
	ums_link_clear(lnk_del, true);

	/* if the link is reused,the following code still needs to be executed */
	active_links = ums_llc_active_link_count(lgr);
	if (active_links == 1) {
		ums_lgr_set_type(lgr, UMS_LGR_SINGLE);
	} else if (active_links == 0) {
		ums_lgr_set_type(lgr, UMS_LGR_NONE);
		ums_lgr_terminate_sched(lgr);
	}

out:
	mutex_unlock(&lgr->llc_conf_mutex);
	kfree(qentry);
}

/* process a delete_rkey request from peer, remote flow */
void ums_llc_rmt_delete_rkey(struct ums_link_group *lgr)
{
	struct ums_llc_msg_delete_rkey *llc;
	struct ums_llc_qentry *qentry;
	struct ums_link *link;
	u8 err_mask = 0;
	int i, max;

	qentry = lgr->llc_flow_rmt.qentry;
	llc = &qentry->msg.delete_rkey;
	link = qentry->link;

	max = min_t(u8, llc->num_rkeys, UMS_LLC_DEL_RKEY_MAX);
	for (i = 0; i < max; i++) {
		if (ums_rtoken_delete(link, llc->rkey[i]))
			err_mask |= ((u32)1) << ((UMS_LLC_DEL_RKEY_MAX - 1) - i);
	}
	if (err_mask != 0) {
		llc->hd.flags |= UMS_LLC_FLAG_RKEY_NEG;
		llc->err_mask = err_mask;
	}

	llc->hd.flags |= UMS_LLC_FLAG_RESP;
	(void)ums_llc_send_message(link, &qentry->msg);
	ums_llc_flow_qentry_del(&lgr->llc_flow_rmt);
}

void ums_llc_protocol_violation(struct ums_link_group *lgr, u8 type)
{
	UMS_LOGI_LIMITED("UMS lg %*phN LLC protocol violation: llc_type %d", UMS_LGR_ID_SIZE,
		lgr->id, type);
	ums_llc_set_termination_rsn(lgr, UMS_LLC_DEL_PROT_VIOL);
	ums_lgr_terminate_sched(lgr);
}

/* process llc responses in tasklet context */
static void ums_llc_rx_response(struct ums_link *link, struct ums_llc_qentry *llc_qentry)
{
	enum ums_llc_flowtype flowtype = link->lgr->llc_flow_lcl.type;
	struct ums_llc_flow *flow = &link->lgr->llc_flow_lcl;
	u8 llc_type = llc_qentry->msg.raw.hdr.common.llc_type;

	switch (llc_type) {
	case UMS_LLC_TEST_LINK:
		if (ums_link_active(link))
			complete(&link->llc_testlink_resp);
		break;
	case UMS_LLC_ADD_LINK:
	case UMS_LLC_ADD_LINK_CONT:
	case UMS_LLC_CONFIRM_LINK:
		if (flowtype != UMS_LLC_FLOW_ADD_LINK || flow->qentry)
			break;	/* drop out-of-flow response */
		goto assign;
	case UMS_LLC_DELETE_LINK:
		if (flowtype != UMS_LLC_FLOW_DEL_LINK || flow->qentry)
			break;	/* drop out-of-flow response */
		goto assign;
	case UMS_LLC_CONFIRM_RKEY:
	case UMS_LLC_DELETE_RKEY:
		if (flowtype != UMS_LLC_FLOW_RKEY || flow->qentry)
			break;	/* drop out-of-flow response */
		goto assign;
	case UMS_LLC_CONFIRM_RKEY_CONT:
		/* not used because max links is 3 */
		break;
	case UMS_LLC_ANNOUNCE_CREDITS:
		if (ums_link_active(link))
			ums_wr_tx_put_credits(link, llc_qentry->msg.announce_credits.credits, true);

		break;
	default:
		ums_llc_protocol_violation(link->lgr, llc_qentry->msg.raw.hdr.common.type);
		break;
	}
	kfree(llc_qentry);
	return;
assign:
	ums_llc_flow_qentry_set(&link->lgr->llc_flow_lcl, llc_qentry);
	wake_up(&link->lgr->llc_msg_waiter);
}

static void ums_llc_enqueue(struct ums_link *link, union ums_llc_msg *llc)
{
	struct ums_link_group *lgr = link->lgr;
	struct ums_llc_qentry *llc_qentry;
	unsigned long flags;

	llc_qentry = kmalloc(sizeof(*llc_qentry), GFP_ATOMIC);
	if (!llc_qentry) {
		UMS_LOGE("kalloc llc recv entry failed!");
		return;
	}

	llc_qentry->link = link;
	INIT_LIST_HEAD(&llc_qentry->list);
	(void)memcpy(&llc_qentry->msg, llc, sizeof(union ums_llc_msg));

	/* process responses immediately */
	if ((llc->raw.hdr.flags & UMS_LLC_FLAG_RESP) != 0) {
		ums_llc_rx_response(link, llc_qentry);
		return;
	}

	/* add requests to event queue */
	spin_lock_irqsave(&lgr->llc_event_q_lock, flags);
	list_add_tail(&llc_qentry->list, &lgr->llc_event_q);
	spin_unlock_irqrestore(&lgr->llc_event_q_lock, flags);
	(void)queue_work(system_highpri_wq, &lgr->llc_event_work);
}

/* copy received msg and add it to the event queue */
static void ums_llc_rx_handler(struct ums_wc *wc, void *buf)
{
	struct ums_link *link = wc->link;
	struct ubcore_cr *cr = wc->cr;
	union ums_llc_msg *llc = buf;

	if (cr->completion_len < sizeof(*llc)) {
		UMS_LOGW_LIMITED("find a short message, return!");
		return; /* short message */
	}

	if (llc->raw.hdr.common.llc_version == 0) {
		if (llc->raw.hdr.length != sizeof(*llc)) {
			UMS_LOGW_LIMITED("find an unknown message, return!");
			return; /* invalid message */
		}
	} else {
		if (llc->raw.hdr.length_v2 < sizeof(*llc)) {
			UMS_LOGW_LIMITED("find an unknown v2 message, return!");
			return; /* invalid message */
		}
	}

	ums_llc_enqueue(link, llc);
}

/***************************** worker, utils *********************************/
void ums_llc_link_active(struct ums_link *link)
{
	UMS_LOGI_LIMITED("UMS lg %*phN link added: id %*phN, peerid %*phN, dev %s, port %d",
		UMS_LGR_ID_SIZE, link->lgr->id, UMS_LGR_ID_SIZE, link->link_uid, UMS_LGR_ID_SIZE,
		link->peer_link_uid, link->ums_dev->ub_dev->dev_name, link->port);
	link->state = UMS_LNK_ACTIVE;
	if (link->lgr->llc_testlink_time != 0) {
		link->llc_testlink_time = link->lgr->llc_testlink_time;
		(void)schedule_delayed_work(&link->llc_testlink_wrk,
				      (unsigned long)link->llc_testlink_time);
	}
}

/* unregister an rtoken at the remote peer */
int ums_llc_do_delete_rkey(struct ums_link_group *lgr, struct ums_buf_desc *rmb_desc)
{
	struct ums_llc_qentry *qentry = NULL;
	struct ums_link *send_link;
	int rc = 0;

	send_link = ums_llc_usable_link(lgr);
	if (!send_link)
		return -ENOLINK;

	/* protected by llc_flow control */
	rc = ums_llc_send_delete_rkey(send_link, rmb_desc);
	if (rc != 0)
		goto out;
	/* receive DELETE RKEY response from server over UB fabric */
	qentry = ums_llc_wait(lgr, send_link, UMS_LLC_WAIT_TIME,
			      UMS_LLC_DELETE_RKEY);
	if (!qentry || ((qentry->msg.raw.hdr.flags & UMS_LLC_FLAG_RKEY_NEG) != 0))
		rc = -EFAULT;
out:
	if (qentry)
		ums_llc_flow_qentry_del(&lgr->llc_flow_lcl);
	return rc;
}

void ums_llc_link_set_uid(struct ums_link *link)
{
	__be32 link_uid;

	link_uid = htonl(*((u32 *)link->lgr->id) + link->link_id);
	(void)memcpy(link->link_uid, &link_uid, UMS_LGR_ID_SIZE);
}

/* save peers link user id, used for debug purposes */
void ums_llc_save_peer_uid(struct ums_llc_qentry *qentry)
{
	(void)memcpy(qentry->link->peer_link_uid, qentry->msg.confirm_link.link_uid,
	       UMS_LGR_ID_SIZE);
}

/* evaluate confirm link request or response */
int ums_llc_eval_conf_link(struct ums_llc_qentry *qentry, enum ums_llc_reqresp type)
{
	if (type == UMS_LLC_REQ) {	/* UMS server assigns link_id */
		qentry->link->link_id = qentry->msg.confirm_link.link_num;
		ums_llc_link_set_uid(qentry->link);
	}
	if ((qentry->msg.raw.hdr.flags & UMS_LLC_FLAG_NO_RMBE_EYEC) == 0)
		return -ENOTSUPP;
	return 0;
}

/***************************** init, exit, misc ******************************/

static struct ums_wr_rx_handler g_ums_llc_rx_handlers[] = {
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_CONFIRM_LINK
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_TEST_LINK
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_ADD_LINK
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_ADD_LINK_CONT
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_DELETE_LINK
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_CONFIRM_RKEY
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_CONFIRM_RKEY_CONT
	},
	{
		.handler	= ums_llc_rx_handler,
		.type		= UMS_LLC_DELETE_RKEY
	},
	{
		.handler    = ums_llc_rx_handler,
		.type       = UMS_LLC_ANNOUNCE_CREDITS
	},
	{
		.handler	= NULL,
	}
};

int __init ums_llc_init(void)
{
	struct ums_wr_rx_handler *handler;
	int rc = 0;

	for (handler = g_ums_llc_rx_handlers; handler->handler; handler++) {
		INIT_HLIST_NODE(&handler->list);
		rc = ums_wr_rx_register_handler(handler);
		if (rc != 0)
			break;
	}
	return rc;
}

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_llc_flow_start);
EXPORT_SYMBOL(ums_llc_process_srv_delete_link);
EXPORT_SYMBOL(ums_llc_process_cli_delete_link);
#endif
