// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS link and link group process implementation
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Klaus Wacker <Klaus.Wacker@de.ibm.com>
 *  			  Ursula Braun <ubraun@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s): Sun fang
 */

#include "ums_llc.h"
#include "ums_log.h"
#include "ums_process_link.h"

/* flush the llc event queue */
static void ums_llc_event_flush(struct ums_link_group *lgr)
{
	struct ums_llc_qentry *qentry, *q;

	spin_lock_bh(&lgr->llc_event_q_lock);
	list_for_each_entry_safe(qentry, q, &lgr->llc_event_q, list) {
		list_del_init(&qentry->list);
		kfree(qentry);
	}
	spin_unlock_bh(&lgr->llc_event_q_lock);
}

/* called after lgr was removed from lgr_list */
void ums_llc_lgr_clear(struct ums_link_group *lgr)
{
	ums_llc_event_flush(lgr);
	wake_up_all(&lgr->llc_msg_waiter);
	wake_up_all(&lgr->llc_flow_waiter);
	(void)cancel_work_sync(&lgr->llc_del_link_work);
	(void)cancel_work_sync(&lgr->llc_event_work);
	if (lgr->delayed_event) {
		kfree(lgr->delayed_event);
		lgr->delayed_event = NULL;
	}
}

static void ums_llc_event_handler(struct ums_llc_qentry **qentry)
{
	union ums_llc_msg *llc = &((*qentry)->msg);
	struct ums_link *link = (*qentry)->link;
	struct ums_link_group *lgr = link->lgr;

	if (!ums_link_usable(link))
		goto out;

	switch (llc->raw.hdr.common.llc_type) {
	case UMS_LLC_TEST_LINK:
		llc->test_link.hd.flags |= UMS_LLC_FLAG_RESP;
		(void)ums_llc_send_message(link, llc);
		break;
	case UMS_LLC_ADD_LINK:
		UMS_LOGI("Not support add link.");
		goto out;
	case UMS_LLC_CONFIRM_LINK:
	case UMS_LLC_ADD_LINK_CONT:
		if (lgr->llc_flow_lcl.type != UMS_LLC_FLOW_NONE) {
			/* a flow is waiting for this message */
			ums_llc_flow_qentry_set(&lgr->llc_flow_lcl, *qentry);
			wake_up(&lgr->llc_msg_waiter);
			return;
		}
		break;
	case UMS_LLC_DELETE_LINK:
		if (lgr->llc_flow_lcl.type == UMS_LLC_FLOW_ADD_LINK && !lgr->llc_flow_lcl.qentry) {
			/* DEL LINK REQ during ADD LINK SEQ */
			ums_llc_flow_qentry_set(&lgr->llc_flow_lcl, *qentry);
			wake_up(&lgr->llc_msg_waiter);
		} else if (ums_llc_flow_start(&lgr->llc_flow_lcl, *qentry)) {
			(void)schedule_work(&lgr->llc_del_link_work);
		}
		return;
	case UMS_LLC_CONFIRM_RKEY:
		UMS_LOGI("Not support ums llc confirm rkey");
		goto out;
	case UMS_LLC_CONFIRM_RKEY_CONT:
		/* not used because max links is 3, and 3 rkeys fit into
		 * one CONFIRM_RKEY message
		 */
		goto out;
	case UMS_LLC_DELETE_RKEY:
		/* new request from remote, assign to remote flow */
		if (ums_llc_flow_start(&lgr->llc_flow_rmt, *qentry)) {
			/* process here, does not wait for more llc msgs */
			ums_llc_rmt_delete_rkey(lgr);
			ums_llc_flow_stop(lgr, &lgr->llc_flow_rmt);
		}
		return;
	case UMS_LLC_ANNOUNCE_CREDITS:
		if (ums_link_active(link))
			ums_wr_tx_put_credits(link, llc->announce_credits.credits, true);
		break;
	case UMS_LLC_REQ_ADD_LINK:
		UMS_LOGI("Not support ums llc add link.");
		goto out;
	default:
		ums_llc_protocol_violation(lgr, llc->raw.hdr.common.type);
		break;
	}
out:
	kfree(*qentry);
	*qentry = NULL;
}

/* worker to process llc messages on the event queue */
static void ums_llc_event_work(struct work_struct *work)
{
	struct ums_link_group *lgr = container_of(work, struct ums_link_group, llc_event_work);
	struct ums_llc_qentry *llc_qentry;
	bool again = true;

	if ((lgr->llc_flow_lcl.type == UMS_LLC_FLOW_NONE) && lgr->delayed_event) {
		llc_qentry = lgr->delayed_event;
		lgr->delayed_event = NULL;
		if (ums_link_usable(llc_qentry->link))
			ums_llc_event_handler(&llc_qentry);
		else
			kfree(llc_qentry);
	}

	while (again) {
		spin_lock_bh(&lgr->llc_event_q_lock);
		if (list_empty(&lgr->llc_event_q) == 0) {
			llc_qentry = list_first_entry(&lgr->llc_event_q, struct ums_llc_qentry, list);
			list_del_init(&llc_qentry->list);
			spin_unlock_bh(&lgr->llc_event_q_lock);
			ums_llc_event_handler(&llc_qentry);
			continue;
		}
		again = false;
	}

	spin_unlock_bh(&lgr->llc_event_q_lock);
}

static void ums_llc_delete_link_work(struct work_struct *work)
{
	struct ums_link_group *lgr = container_of(work, struct ums_link_group, llc_del_link_work);

	if (list_empty(&lgr->list) != 0) {
		/* link group is terminating */
		ums_llc_flow_qentry_del(&lgr->llc_flow_lcl);
		goto out;
	}

	if (lgr->role == UMS_CLNT)
		ums_llc_process_cli_delete_link(lgr);
	else
		ums_llc_process_srv_delete_link(lgr);
out:
	ums_llc_flow_stop(lgr, &lgr->llc_flow_lcl);
}

void ums_llc_lgr_init(struct ums_link_group *lgr, struct ums_sock *ums)
{
	struct net *net = sock_net(ums->clcsock->sk);

	INIT_WORK(&lgr->llc_event_work, ums_llc_event_work);
	INIT_WORK(&lgr->llc_del_link_work, ums_llc_delete_link_work);
	spin_lock_init(&lgr->llc_event_q_lock);
	spin_lock_init(&lgr->llc_flow_lock);
	INIT_LIST_HEAD(&lgr->llc_event_q);
	init_waitqueue_head(&lgr->llc_msg_waiter);
	init_waitqueue_head(&lgr->llc_flow_waiter);
	mutex_init(&lgr->llc_conf_mutex);
	lgr->llc_testlink_time = READ_ONCE(net->ipv4.sysctl_tcp_keepalive_time);
}

/* send LLC test link request */
static int ums_llc_send_test_link(struct ums_link *link, u8 user_data[UMS_USER_DATA_LEN])
{
	struct ums_llc_msg_test_link *testllc;
	struct ums_wr_tx_pend_priv *pend;
	struct ums_wr_buf *wr_buf;
	int rc;

	if (!ums_wr_tx_link_hold(link))
		return -ENOLINK;
	rc = ums_llc_add_pending_send(link, &wr_buf, &pend, false);
	if (rc != 0)
		goto put_out;
	testllc = (struct ums_llc_msg_test_link *)wr_buf;
	(void)memset(testllc, 0, sizeof(struct ums_llc_msg_test_link));
	testllc->hd.common.llc_type = UMS_LLC_TEST_LINK;
	ums_llc_init_msg_hdr(&testllc->hd, link->lgr, sizeof(*testllc));
	(void)memcpy(testllc->user_data, user_data, UMS_USER_DATA_LEN);
	/* send llc message */
	rc = ums_wr_tx_send(link, pend);
put_out:
	ums_wr_tx_link_put(link);
	return rc;
}

static void ums_llc_testlink_work(struct work_struct *work)
{
	struct ums_link *link = container_of(to_delayed_work(work), struct ums_link, llc_testlink_wrk);
	unsigned long next_interval;
	int new_keep_alive_time = 0;
	unsigned long expire_time;
	u8 user_data[UMS_USER_DATA_LEN] = { 0 };
	int rc;

	if (!ums_link_active(link))
		return; /* don't reschedule worker */
	expire_time = ((u32)link->llc_testlink_time) + link->wr_rx_tstamp;
	if (time_is_after_jiffies(expire_time)) {
		next_interval = expire_time - jiffies;
		goto out;
	}
	reinit_completion(&link->llc_testlink_resp);
	(void)ums_llc_send_test_link(link, user_data);
	/* receive TEST LINK response over UB fabric */
	rc = (int)wait_for_completion_interruptible_timeout(&link->llc_testlink_resp,
		UMS_LLC_WAIT_TIME);
	if (!ums_link_active(link))
		return; /* link state changed */
	if (rc <= 0) {
		ums_link_down_cond_sched(link);
		return;
	}
	if (link->lgr->net)
		new_keep_alive_time = READ_ONCE(link->lgr->net->ipv4.sysctl_tcp_keepalive_time);
	if ((new_keep_alive_time != link->llc_testlink_time) && (new_keep_alive_time > 0)) {
		link->llc_testlink_time = new_keep_alive_time;
		UMS_LOGW_LIMITED("set new keep alive time:[%d]ms", new_keep_alive_time);
	}
	next_interval = (unsigned long)link->llc_testlink_time;
out:
	(void)schedule_delayed_work(&link->llc_testlink_wrk, next_interval);
}

static void ums_llc_announce_credits_work(struct work_struct *work)
{
	struct ums_link *link = container_of(work, struct ums_link, credits_announce_work);
	int rc, retry = 0, agains = 0;
	const int agains_max = 5;
	bool again = true;

	spin_lock_bh(&link->credit_lock);

	while (again) {
		do
			rc = ums_llc_announce_credits(link, UMS_LLC_RESP, false);
		while ((rc == -EBUSY) && ums_link_sendable(link) && (retry++ < UMS_LLC_ANNOUNCE_CR_MAX_RETRY));

		if ((ums_wr_rx_credits_need_announce(link) != 0) && ums_link_sendable(link) &&
			agains <= agains_max && (rc == 0)) {
			agains++;
			continue;
		}
		again = false;
	}

	clear_bit(UMS_LINKFLAG_ANNOUNCE_PENDING, &link->flags);
	/* credit_lock is used to prevent tasklet seizes CPU before clear_bit */
	spin_unlock_bh(&link->credit_lock);
}

int ums_llc_link_init(struct ums_link *link)
{
	init_completion(&link->llc_testlink_resp);
	spin_lock_init(&link->credit_lock);
	INIT_DELAYED_WORK(&link->llc_testlink_wrk, ums_llc_testlink_work);
	INIT_WORK(&link->credits_announce_work, ums_llc_announce_credits_work);
	return 0;
}

/* called in worker context */
void ums_llc_link_clear(struct ums_link *link, bool log)
{
	if (log)
		UMS_LOGI_LIMITED(
			"UMS lg %*phN link removed: id %*phN, peerid %*phN, ubdev %s, port %d",
			UMS_LGR_ID_SIZE, link->lgr->id, UMS_LGR_ID_SIZE, link->link_uid, UMS_LGR_ID_SIZE,
			link->peer_link_uid, link->ums_dev->ub_dev->dev_name, link->port);
	complete(&link->llc_testlink_resp);
	(void)cancel_delayed_work_sync(&link->llc_testlink_wrk);
	(void)cancel_work_sync(&link->credits_announce_work);
}
