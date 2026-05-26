// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS work request(wr) interface implementation
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Steffen Maier <maier@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/wait.h>

#ifndef KERNEL_VERSION_4
#include "ums_dim.h"
#endif
#include "ums_log.h"
#include "ums_mod.h"
#include "ums_wr.h"

#include <asm/div64.h>

/**
 * Limit the maximum number of CQEs processed during each tasklet scheduling to prevent
 * the tasklet from occupying the CPU for a long time and triggering CPU soft lockup warning.
 */
#define MAX_CQES_PER_TASKLET 65536

#define UMS_WR_RX_HASH_BITS 4
#define UMS_ONE_THIRD 3
#define UMS_ONE_TENTH 10

static DEFINE_HASHTABLE(g_ums_wr_rx_hash, UMS_WR_RX_HASH_BITS);
static DEFINE_SPINLOCK(g_ums_wr_rx_hash_lock);

struct ums_wr_tx_pend { /* control data for a pending send request */
	u64 wr_id;          /* work request id sent */
	ums_wr_tx_handler handler;
	enum ubcore_cr_status wc_status; /* CQE status */
	struct ums_link *link;
	u32 idx;
	struct ums_wr_tx_pend_priv priv;
	u8 compl_requested;
};

/******************************** send queue *********************************/

/*------------------------------- completion --------------------------------*/

/* returns true if at least one tx work request is pending on the given link */
static inline bool ums_wr_is_tx_pend(struct ums_link *link)
{
	return bitmap_empty(link->wr_tx_mask, link->wr_tx_cnt) == 0;
}

/* wait till all pending tx work requests on the given link are completed */
void ums_wr_tx_wait_no_pending_sends(struct ums_link *link)
{
	wait_event_timeout(link->wr_tx_wait, !ums_wr_is_tx_pend(link), UMS_TX_WAIT_TIME);
}

static inline u32 ums_wr_tx_find_pending_index(struct ums_link *link, u64 wr_id)
{
	u32 i;

	for (i = 0; i < link->wr_tx_cnt; i++) {
		if (link->wr_tx_pends[i].wr_id == wr_id)
			return i;
	}
	return link->wr_tx_cnt;
}

static void ums_wr_tx_process_cqe(struct ums_wc *wc)
{
	struct ums_link *link = wc->link;
	struct ums_wr_tx_pend pnd_snd;
	struct ubcore_cr *cr = wc->cr;
	u32 pnd_snd_idx;

	pnd_snd_idx = ums_wr_tx_find_pending_index(link, cr->user_ctx);
	if (pnd_snd_idx == link->wr_tx_cnt) {
			return;
	} else {
		link->wr_tx_pends[pnd_snd_idx].wc_status = cr->status;
		if (link->wr_tx_pends[pnd_snd_idx].compl_requested != 0)
			complete(&link->wr_tx_compl[pnd_snd_idx]);
		(void)memcpy(&pnd_snd, &link->wr_tx_pends[pnd_snd_idx], sizeof(struct ums_wr_tx_pend));
		/* clear the full struct ums_wr_tx_pend including .priv */
		(void)memset(&link->wr_tx_pends[pnd_snd_idx], 0, sizeof(struct ums_wr_tx_pend));
		/* although we only need to memset for non-Write, but it doesnot matter. */
		(void)memset(&link->wr_tx_bufs[pnd_snd_idx], 0, UMS_WR_BUF_SIZE);
		if (!test_and_clear_bit(pnd_snd_idx, link->wr_tx_mask))
			return;
	}

	if (cr->status != UBCORE_CR_SUCCESS) {
		/* terminate link */
		UMS_LOGW("cr status is %d, not success, jetty id:%d, link id:%*phN",
			cr->status, wc->jetty_id, UMS_LGR_ID_SIZE, link->link_uid);
		ums_link_down_cond_sched(link);
	}

	if (pnd_snd.handler)
		pnd_snd.handler(&pnd_snd.priv, link, (enum ubcore_cr_opcode)cr->status);
	if (wq_has_sleeper(&link->wr_tx_wait))
		wake_up(&link->wr_tx_wait);
}

static int ums_wr_tx_get_free_slot_index(struct ums_link *link, u32 *idx, bool emergency)
{
	*idx = link->wr_tx_cnt;
	if (!ums_link_sendable(link))
		return -ENOLINK;

	if (unlikely(emergency)) {
		if (ums_wr_tx_get_credit_emergency(link) == 0)
			return -EBUSY;
	} else {
		if (ums_wr_tx_get_credit(link) == 0)
			return -EBUSY;
	}

	for_each_clear_bit (*idx, link->wr_tx_mask, link->wr_tx_cnt) {
		if (!test_and_set_bit(*idx, link->wr_tx_mask))
			return 0;
	}
	*idx = link->wr_tx_cnt;
	ums_wr_tx_put_credits(link, 1, false);
	return -EBUSY;
}


void ums_wr_tx_put_slot(struct ums_link *link, struct ums_wr_tx_pend_priv *wr_pend_priv)
{
	struct ums_wr_tx_pend *pend;
	u32 idx;

	pend = container_of(wr_pend_priv, struct ums_wr_tx_pend, priv);
	if (pend->idx >= link->wr_tx_cnt) {
		UMS_LOGW_LIMITED("slot index is %u, is invalid", pend->idx);
		return;
	}

	idx = pend->idx;

	/* clear the full struct ums_wr_tx_pend including .priv */
	(void)memset(&link->wr_tx_pends[idx], 0, sizeof(struct ums_wr_tx_pend));
	(void)memset(&link->wr_tx_bufs[idx], 0, UMS_WR_BUF_SIZE);
	(void)test_and_clear_bit(idx, link->wr_tx_mask);
	ums_wr_tx_put_credits(link, 1, true);
}

/**
 * returns buffer for message assembly, and sets info for pending transmit tracking
 * @link:		Pointer to ums_link used to later send the message.
 * @handler:		Send completion handler function pointer.
 * @wr_buf:		Out value returns pointer to message buffer.
 * @wr_ub_buf:		Out value returns pointer to ub work request.
 * @wr_pend_priv:	Out value returns pointer serving as handler context.
 * @emergency:		If true, can use reserved emergency credits (for LLC announce credits only).
 */
int ums_wr_tx_get_free_slot(struct ums_link *link, ums_wr_tx_handler handler,
	struct ums_wr_buf **wr_buf, struct ubcore_jfs_wr **wr_ub_buf,
	struct ums_wr_tx_pend_priv **wr_pend_priv, bool emergency)
{
	struct ums_link_group *lgr = ums_get_lgr(link);
	struct ums_wr_tx_pend *wr_pend;
	u32 idx = link->wr_tx_cnt;
	struct ubcore_jfs_wr *wr_ub;
	u64 wr_id;
	int rc;

	*wr_pend_priv = NULL;
	if (in_softirq() || (lgr->terminating != 0)) {
		rc = ums_wr_tx_get_free_slot_index(link, &idx, emergency);
		if (rc != 0)
			return rc;
	} else {
		rc = (int)wait_event_interruptible_timeout(link->wr_tx_wait, !ums_link_sendable(link) ||
			(lgr->terminating != 0) || (ums_wr_tx_get_free_slot_index(link, &idx, emergency) != -EBUSY),
			UMS_WR_TX_WAIT_FREE_SLOT_TIME);
		if (rc == 0) {
			/* timeout - terminate link */
			UMS_LOGW_LIMITED("timeout to get free slot, peer_credit=%d, local_credit=%d",
				atomic_read(&link->peer_rq_credits), atomic_read(&link->local_rq_credits));
			ums_link_down_cond_sched(link);
			return -EPIPE;
		}
		if (idx == link->wr_tx_cnt)
			return -EPIPE;
	}
	wr_id = (u64)ums_wr_tx_get_next_wr_id(link);
	wr_pend = &link->wr_tx_pends[idx];
	wr_pend->wr_id = wr_id;
	wr_pend->handler = handler;
	wr_pend->link = link;
	wr_pend->idx = idx;
	*wr_pend_priv = &wr_pend->priv;

	/*
	in current version, three cases:
	(1) wr_buf == NULL && wr_ub_buf != NULL, which means write_with_imm;
	(2) wr_buf != NULL && wr_ub_buf == NULL, which means CDC or LLC;
	(3) wr_buf != NULL && wr_ub_buf != NULL, which means CDC(wr_buf) and write(wr_ub_buf),
	we need to fill each one of them
	*/
	if (wr_buf) {
		wr_ub = &link->wr_tx[idx];
		wr_ub->user_ctx = wr_id;
		*wr_buf = &link->wr_tx_bufs[idx];
	}
	
	if (wr_ub_buf) {
		wr_ub = &link->wr_tx_ubcore[idx];
		wr_ub->user_ctx = wr_id;
		*wr_ub_buf = &link->wr_tx_ubcore[idx];

		if (wr_buf)
			wr_ub->opcode = UBCORE_OPC_WRITE;
		else
			wr_ub->opcode = UBCORE_OPC_WRITE_IMM;
	}
	return 0;
}

/* Send prepared WR slot via ubcore_post_jetty_send_wr.
 * @priv: pointer to ums_wr_tx_pend_priv identifying prepared message buffer
 */
int ums_wr_tx_send(struct ums_link *link, struct ums_wr_tx_pend_priv *priv)
{
	struct ums_wr_tx_pend *pend;
	int rc;
	struct ubcore_jfs_wr *bad_wr = NULL;

	pend = container_of(priv, struct ums_wr_tx_pend, priv);
	link->wr_tx[pend->idx].tjetty = link->ub_tjetty;
	rc = ubcore_post_jetty_send_wr(link->ub_jetty, &link->wr_tx[pend->idx], &bad_wr);
	if (rc != 0) {
		(void)ums_wr_tx_put_slot(link, priv);
		ums_link_down_cond_sched(link);
	}
	return rc;
}

/* Send prepared WR slot via ubcore_post_jetty_send_wr and wait for send completion
 * notification.
 * @priv: pointer to ums_wr_tx_pend_priv identifying prepared message buffer
 */
int ums_wr_tx_send_wait(struct ums_link *link, struct ums_wr_tx_pend_priv *priv,
	unsigned long timeout)
{
	struct ums_wr_tx_pend *pend;
	u32 pnd_idx;
	int rc;

	pend = container_of(priv, struct ums_wr_tx_pend, priv);
	pend->compl_requested = 1;
	pnd_idx = pend->idx;
	init_completion(&link->wr_tx_compl[pnd_idx]);

	rc = ums_wr_tx_send(link, priv);
	if (rc != 0)
		return rc;
	/* wait for completion by ums_wr_tx_process_cqe() */
	rc = (int)wait_for_completion_interruptible_timeout(&link->wr_tx_compl[pnd_idx], timeout);
	if (rc <= 0)
		rc = -ENODATA;
	if (rc > 0)
		rc = 0;
	return rc;
}

/****************************** receive queue ********************************/

int ums_wr_rx_register_handler(struct ums_wr_rx_handler *handler)
{
	struct ums_wr_rx_handler *h_iter;
	int rc = 0;

	spin_lock(&g_ums_wr_rx_hash_lock);
	hash_for_each_possible (g_ums_wr_rx_hash, h_iter, list, handler->type) {
		if (h_iter->type == handler->type) {
			rc = -EEXIST;
			goto out_unlock;
		}
	}
	hash_add(g_ums_wr_rx_hash, &handler->list, handler->type);
out_unlock:
	spin_unlock(&g_ums_wr_rx_hash_lock);
	return rc;
}

/* Demultiplex a received work request based on the message type to its handler.
 * Relies on g_ums_wr_rx_hash having been completely filled before any UB WRs,
 * and not being modified any more afterwards so we don't need to lock it.
 */
static void ums_wr_rx_demultiplex(struct ums_wc *wc, u32 wr_rx_idx)
{
	struct ums_wr_rx_handler *handler;
	struct ums_wr_rx_hdr *wr_rx;
	u8 type;
	bool rx_imm = false;
	struct ums_link *link = wc->link;
	struct ubcore_cr *cr = wc->cr;

	if (cr->opcode == UBCORE_CR_OPC_WRITE_WITH_IMM)
		rx_imm = true;
	else if (cr->completion_len < sizeof(*wr_rx))
		return; /* short message */

	wr_rx = (struct ums_wr_rx_hdr *)&link->wr_rx_bufs[wr_rx_idx];
	type = rx_imm ? UMS_IMM_MSG_TYPE : wr_rx->type;
	hash_for_each_possible (g_ums_wr_rx_hash, handler, list, type) {
		if (handler->type == type)
			handler->handler(wc, wr_rx);
	}
}

static inline u32 ums_wr_rx_find_pending_index(struct ums_link *lnk, u64 wr_id)
{
	u32 i;

	for (i = 0; i < lnk->wr_rx_cnt; i++) {
		if (lnk->wr_rx_pends[i].wr_id == wr_id)
			return i;
	}
	return lnk->wr_rx_cnt;
}

/* Post a new receive work request to fill a completed old work request entry.
 *
 * The RQE consumption is out of order.
 * After receiving the rx cr, need to specify the index of link->wr_rx array used for post recv.
 */
static int ums_wr_rx_post(struct ums_link *link, u32 wr_rx_idx)
{
	struct ubcore_jfr_wr *jfr_bad_wr = NULL;
	unsigned long flags;
	u64 wr_id;
	int rc;
	/* A link corresponds to a unique jfc. Before rearm the jfc again, the jfc does not trigger a new tasklet.
	 * Therefore, in this tasklet context, link->wr_rx_id will not be modified by other tasklets.
	 */
	link->wr_rx_id += UMS_WR_ID_NUM;
	wr_id = link->wr_rx_id;

	spin_lock_irqsave(&link->wr_rx_lock, flags);
	if (link->rx_tseg == NULL) {
		spin_unlock_irqrestore(&link->wr_rx_lock, flags);
		return 0;
	}

	link->wr_rx[wr_rx_idx].user_ctx = wr_id;
	link->wr_rx_pends[wr_rx_idx].wr_id = wr_id;

	rc = ubcore_post_jetty_recv_wr(link->ub_jetty, &link->wr_rx[wr_rx_idx], &jfr_bad_wr);
	spin_unlock_irqrestore(&link->wr_rx_lock, flags);
	if (rc != 0) {
		UMS_LOGE("post rqe failed: %d, link id: %*phN, local credit %d, remote credit %d",
			rc, UMS_LGR_ID_SIZE, link->link_uid, atomic_read(&link->local_rq_credits),
			atomic_read(&link->peer_rq_credits));
		return rc;
	}
	ums_wr_rx_put_credits(link, 1);
	return 0;
}

static void ums_wr_rx_process_cqe(struct ums_wc *wc)
{
	struct ums_link *link = wc->link;
	struct ubcore_cr *cr = wc->cr;
	u32 wr_rx_idx;

	wr_rx_idx = ums_wr_rx_find_pending_index(link, cr->user_ctx);
	if (wr_rx_idx == link->wr_rx_cnt) {
		return;
	}

	if (cr->status == UBCORE_CR_SUCCESS) {
		link->wr_rx_tstamp = jiffies;
		ums_wr_rx_demultiplex(wc, wr_rx_idx);
		(void)ums_wr_rx_post(link, wr_rx_idx); /* refill WR RX */
	} else {
		UMS_LOGW("cr status is %d, not success, jetty id:%d, link id:%*phN",
			cr->status, wc->jetty_id, UMS_LGR_ID_SIZE, link->link_uid);
		/* handle status errors */
		if (cr->status == UBCORE_CR_RNR_RETRY_CNT_EXC_ERR || cr->status == UBCORE_CR_FLUSH_ERR)
			ums_link_down_cond_sched(link);
		else
			(void)ums_wr_rx_post(link, wr_rx_idx); /* refill WR RX */
	}

	if ((ums_wr_rx_credits_need_announce(link) != 0) &&
		(test_bit(UMS_LINKFLAG_ANNOUNCE_PENDING, &link->flags) == 0)) {
		set_bit(UMS_LINKFLAG_ANNOUNCE_PENDING, &link->flags);
		(void)schedule_work(&link->credits_announce_work);
	}
}

int ums_wr_rx_post_init(struct ums_link *link)
{
	int rc = 0;
	u32 i;

	for (i = 0; i < link->wr_rx_cnt; i++) {
		rc = ums_wr_rx_post(link, i);
	}
	/* credits have already been announced to peer */
	atomic_set(&link->local_rq_credits, 0);
	return rc;
}

static struct ums_link *ums_get_link_by_jetty_id(struct ums_ubcore_device *ums_ub_dev,
	struct ubcore_jetty_id *jetty_id)
{
	struct ums_link *lnk_iter;

	read_lock(&ums_ub_dev->jetty2link_htable_lock);
	hash_for_each_possible(ums_ub_dev->jetty2link_htable, lnk_iter, hnode, jetty_id->id) {
		if (lnk_iter->ub_jetty->jetty_id.id == jetty_id->id) {
			read_unlock(&ums_ub_dev->jetty2link_htable_lock);
			return lnk_iter;
		}
	}
	read_unlock(&ums_ub_dev->jetty2link_htable_lock);
	return NULL;
}

static void ums_wr_tasklet_fn_inner(struct ums_ubcore_jfc *ums_jfc, u32 rc)
{
	struct ubcore_jetty *jetty;
	struct ums_link *link;
	struct ums_wc wc;
	u32 i;

	for (i = 0; i < rc && i < UMS_WR_MAX_POLL_CQE; i++) {
		jetty = (struct ubcore_jetty *)(ums_jfc->cr_tasklets[i].user_data);
		if (unlikely(IS_ERR_OR_NULL(jetty))) {
			UMS_LOGE("invalid cr user_data: %lu, wc id: %llu",
			    ums_jfc->cr_tasklets[i].user_data, ums_jfc->cr_tasklets[i].user_ctx);
			continue;
		}

		link = ums_get_link_by_jetty_id(ums_jfc->ums_ub_dev, &jetty->jetty_id);
		if (unlikely(IS_ERR_OR_NULL(link))) {
			UMS_LOGE("failed to get link from jetty[eid:%pI6c, id:%u], cr user_data: %lu, "
				"wc id: %llu", &jetty->jetty_id.eid, jetty->jetty_id.id,
				ums_jfc->cr_tasklets[i].user_data, ums_jfc->cr_tasklets[i].user_ctx);
			continue;
		}
		wc.cr = &ums_jfc->cr_tasklets[i];
		wc.link = link;
		wc.jetty_id = jetty->jetty_id.id;

		/* If cr->status is UBCORE_CR_WR_SUSPEND_DONE or UBCORE_CR_WR_FLUSH_ERR_DONE,
		 * it indicates that the cr is a fake CQE generated by the hardware, and cr->user_ctx is invalid.
		 */
		if (unlikely((wc.cr->status == UBCORE_CR_WR_SUSPEND_DONE) ||
			(wc.cr->status == UBCORE_CR_WR_FLUSH_ERR_DONE))) {
			/* terminate link */
			UMS_LOGW("cr status is %d, not success, jetty id:%d, link id:%*phN",
				wc.cr->status, wc.jetty_id, UMS_LGR_ID_SIZE, link->link_uid);
			ums_link_down_cond_sched(link);
			continue;
		}

		if (ums_cr_is_rx(wc.cr)) {
			ums_wr_rx_process_cqe(&wc);
		} else {
			ums_wr_tx_process_cqe(&wc);
		}
	}
}

#ifdef KERNEL_VERSION_4
static void ums_wr_tasklet_fn(unsigned long data)
{
	struct ums_ubcore_jfc *ums_jfc = (struct ums_ubcore_jfc *)data;
#else
static void ums_wr_tasklet_fn(struct tasklet_struct *t)
{
	struct ums_ubcore_jfc *ums_jfc = from_tasklet(ums_jfc, t, tasklet);
#endif
	int completed = 0;
	bool again = true;
	int rc;

	while (again) {
		do {
			rc = ubcore_poll_jfc(ums_jfc->jfc, UMS_WR_MAX_POLL_CQE, ums_jfc->cr_tasklets);
			if (rc <= 0) {
				break;
			}
			ums_wr_tasklet_fn_inner(ums_jfc, (u32)rc);
			completed += rc;
			if (unlikely(completed > MAX_CQES_PER_TASKLET)) {
				break;
			}
		} while (rc > 0);
		if (likely(ubcore_rearm_jfc(ums_jfc->jfc, false) <= 0))
			again = false;
	}

#ifndef KERNEL_VERSION_4
	if (ums_jfc->dim)
		ums_dim(ums_jfc->dim, (unsigned int)completed);
#endif
}

static struct tasklet_struct *ums_get_tasklet_from_jfc(struct ubcore_jfc *jfc)
{
	struct ums_ubcore_device *ubdev;
	struct ums_ubcore_device *n;
	int i;

	list_for_each_entry_safe(ubdev, n, &g_ums_ubcore_devices.list, list) {
		for (i = 0; i < ubdev->num_jfc; i++)
			if (ubdev->ums_ub_jfc[i].jfc == jfc)
				return &ubdev->ums_ub_jfc[i].tasklet;
	}
	UMS_LOGE("failed to find the jfc tasket");

	return NULL;
}

void ums_wr_jfc_handler(struct ubcore_jfc *ub_jfc)
{
	struct tasklet_struct *jfc_tasklet = ums_get_tasklet_from_jfc(ub_jfc);
	if (jfc_tasklet != NULL)
		tasklet_schedule(jfc_tasklet);
}

static void ums_wr_init_sge(struct ums_link *lnk)
{
	bool send_inline = (lnk->ub_jetty->jetty_cfg.max_inline_data > UMS_WR_TX_SIZE);
	u32 i, j;

	for (i = 0; i < lnk->wr_tx_cnt; i++) {
		lnk->wr_tx_sges[i].addr = (uintptr_t)(&lnk->wr_tx_bufs[i]);
		lnk->wr_tx_sges[i].len = UMS_WR_TX_SIZE;
		lnk->wr_tx_sges[i].tseg = lnk->tx_tseg;
		lnk->wr_tx[i].next = NULL;
		lnk->wr_tx[i].send.src.sge = &lnk->wr_tx_sges[i];
		lnk->wr_tx[i].send.src.num_sge = 1;
		lnk->wr_tx[i].opcode = UBCORE_OPC_SEND;
		lnk->wr_tx[i].flag.bs.complete_enable = UBCORE_COMPLETE_ENABLE;
		if (send_inline)
			lnk->wr_tx[i].flag.bs.inline_flag = UBCORE_INLINE_ENABLE;
		/* UMS uses write_wite_imm to replace Write */
		lnk->wr_tx_ubcore[i].opcode = UBCORE_OPC_WRITE_IMM;
		lnk->wr_tx_ubcore[i].flag.bs.complete_enable = UBCORE_COMPLETE_ENABLE;
		lnk->wr_tx_ubcore[i].rw.src.sge = lnk->wr_tx_ub_sges[i].wr_tx_ub_sge;
	}

	for (j = 0; j < UMS_RMBS_PER_LGR_MAX; j++) {
		i = lnk->wr_tx_cnt + j;
		lnk->wr_tx_ubcore[i].opcode = UBCORE_OPC_WRITE;
		lnk->wr_tx_ubcore[i].flag.bs.complete_enable = UBCORE_COMPLETE_DISABLE;
		lnk->wr_tx_ubcore[i].rw.src.sge = lnk->wr_tx_ub_sges[i].wr_tx_ub_sge;
	}
	for (i = 0; i < lnk->wr_rx_cnt; i++) {
		lnk->wr_rx_sges[i].addr = (uintptr_t)(&lnk->wr_rx_bufs[i]);
		lnk->wr_rx_sges[i].len = UMS_WR_TX_SIZE;
		lnk->wr_rx_sges[i].tseg = lnk->rx_tseg;
		lnk->wr_rx[i].next = NULL;
		lnk->wr_rx[i].src.sge = &lnk->wr_rx_sges[i];
		lnk->wr_rx[i].src.num_sge = 1;
	}
}

void ums_wr_free_link(struct ums_link *lnk)
{
	struct ubcore_target_seg *p;
	unsigned long flags;

	if (!lnk->ums_dev)
		return;

	ums_wr_wakeup_tx_wait(lnk);

	ums_wr_tx_wait_no_pending_sends(lnk);
	wait_event(lnk->wr_tx_wait, atomic_read(&lnk->wr_tx_refcnt) == 0);

	spin_lock_irqsave(&lnk->wr_rx_lock, flags);
	if (lnk->rx_tseg) {
		p = lnk->rx_tseg;
		lnk->rx_tseg = NULL;
		spin_unlock_irqrestore(&lnk->wr_rx_lock, flags);
		(void)ubcore_unregister_seg(p);
	} else {
		spin_unlock_irqrestore(&lnk->wr_rx_lock, flags);
	}

	if (lnk->tx_tseg) {
		(void)ubcore_unregister_seg(lnk->tx_tseg);
		lnk->tx_tseg = NULL;
	}
}

void ums_wr_free_link_mem(struct ums_link *lnk)
{
	kfree(lnk->wr_tx_compl);
	lnk->wr_tx_compl = NULL;
	kfree(lnk->wr_tx_pends);
	lnk->wr_tx_pends = NULL;
	bitmap_free(lnk->wr_tx_mask);
	lnk->wr_tx_mask = NULL;
	kfree(lnk->wr_tx_ub_sges);
	lnk->wr_tx_ub_sges = NULL;
	kfree(lnk->wr_tx_sges);
	lnk->wr_tx_sges = NULL;
	kfree(lnk->wr_rx_sges);
	lnk->wr_rx_sges = NULL;
	kfree(lnk->wr_tx_ubcore);
	lnk->wr_tx_ubcore = NULL;
	vfree(lnk->wr_tx_bufs);
	lnk->wr_tx_bufs = NULL;
	vfree(lnk->wr_rx_bufs);
	lnk->wr_rx_bufs = NULL;
	kfree(lnk->wr_rx_pends);
	lnk->wr_rx_pends = NULL;
	kfree(lnk->wr_tx);
	lnk->wr_tx = NULL;
	kfree(lnk->wr_rx);
	lnk->wr_rx = NULL;
}

static int ums_wr_alloc_link_mem_inner(struct ums_link *link)
{
	int sges_per_buf = 1; /* for ums v1 version, sges per buf is 1 */

	link->wr_rx_sges =
		kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_rx_sges[0]) * ((u32)sges_per_buf), GFP_KERNEL);
	if (!link->wr_rx_sges)
		goto wr_tx_sges_no_mem;
	link->wr_tx_mask = bitmap_zalloc(UMS_WR_BUF_CNT, GFP_KERNEL);
	if (!link->wr_tx_mask)
		goto wr_rx_sges_no_mem;
	link->wr_tx_pends = kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_tx_pends[0]), GFP_KERNEL);
	if (!link->wr_tx_pends)
		goto wr_tx_mask_no_mem;
	link->wr_tx_compl = kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_tx_compl[0]), GFP_KERNEL);
	if (!link->wr_tx_compl)
		goto wr_tx_pends_no_mem;
	link->wr_rx_pends = kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_rx_pends[0]), GFP_KERNEL);
	if (!link->wr_rx_pends)
		goto wr_tx_compl_no_mem;

	return 0;
wr_tx_compl_no_mem:
	kfree(link->wr_tx_compl);
wr_tx_pends_no_mem:
	kfree(link->wr_tx_pends);
wr_tx_mask_no_mem:
	kfree(link->wr_tx_mask);
wr_rx_sges_no_mem:
	kfree(link->wr_rx_sges);
wr_tx_sges_no_mem:
	kfree(link->wr_tx_sges);
	return -ENOMEM;
}

int ums_wr_alloc_link_mem(struct ums_link *link)
{
	/* allocate link related memory */
	link->wr_tx_bufs = vzalloc(PAGE_SIZE << get_order(UMS_WR_BUF_CNT * UMS_WR_BUF_SIZE));
	if (!link->wr_tx_bufs)
		goto no_mem;
	link->wr_rx_bufs = vzalloc(PAGE_SIZE << get_order(UMS_WR_BUF_CNT * UMS_WR_BUF_SIZE));
	if (!link->wr_rx_bufs)
		goto wr_tx_bufs_no_mem;
	link->wr_tx = kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_tx[0]), GFP_KERNEL);
	if (!link->wr_tx)
		goto wr_rx_bufs_no_mem;
	link->wr_rx = kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_rx[0]), GFP_KERNEL);
	if (!link->wr_rx)
		goto wr_tx_no_mem;
	link->wr_tx_ubcore = kcalloc(UMS_WR_BUF_CNT + UMS_RMBS_PER_LGR_MAX,
		sizeof(link->wr_tx_ubcore[0]), GFP_KERNEL);
	if (!link->wr_tx_ubcore)
		goto wr_rx_no_mem;
	link->wr_tx_ub_sges = kcalloc(UMS_WR_BUF_CNT + UMS_RMBS_PER_LGR_MAX,
		sizeof(link->wr_tx_ub_sges[0]), GFP_KERNEL);
	if (!link->wr_tx_ub_sges)
		goto wr_tx_ubcore_no_mem;
	link->wr_tx_sges = kcalloc(UMS_WR_BUF_CNT, sizeof(link->wr_tx_sges[0]), GFP_KERNEL);
	if (!link->wr_tx_sges)
		goto wr_tx_ub_sges_no_mem;

	if (ums_wr_alloc_link_mem_inner(link) == 0)
		return 0;

wr_tx_ub_sges_no_mem:
	kfree(link->wr_tx_ub_sges);
wr_tx_ubcore_no_mem:
	kfree(link->wr_tx_ubcore);
wr_rx_no_mem:
	kfree(link->wr_rx);
wr_tx_no_mem:
	kfree(link->wr_tx);
wr_rx_bufs_no_mem:
	vfree(link->wr_rx_bufs);
wr_tx_bufs_no_mem:
	vfree(link->wr_tx_bufs);
no_mem:
	return -ENOMEM;
}

void ums_wr_remove_dev(struct ums_ubcore_device *ums_ub_dev)
{
	int i;

	for (i = 0; i < ums_ub_dev->num_jfc; i++)
		tasklet_kill(&ums_ub_dev->ums_ub_jfc[i].tasklet);
}

void ums_wr_add_dev(struct ums_ubcore_device *ums_ub_dev)
{
	int i;

	for (i = 0; i < ums_ub_dev->num_jfc; i++)
#ifdef KERNEL_VERSION_4
		tasklet_init(&ums_ub_dev->ums_ub_jfc[i].tasklet, ums_wr_tasklet_fn,
			(unsigned long)&ums_ub_dev->ums_ub_jfc[i]);
#else
		tasklet_setup(&ums_ub_dev->ums_ub_jfc[i].tasklet, ums_wr_tasklet_fn);
#endif
}

static void ums_wr_create_link_inner(struct ums_link *lnk)
{
	ums_wr_init_sge(lnk);
	bitmap_zero(lnk->wr_tx_mask, UMS_WR_BUF_CNT);
	init_waitqueue_head(&lnk->wr_tx_wait);
	atomic_set(&lnk->wr_tx_refcnt, 0);
	atomic_set(&lnk->peer_rq_credits, 0);
	atomic_set(&lnk->local_rq_credits, 0);

	lnk->flags = 0;
	lnk->local_cr_watermark_high = max_t(u8, (u8)(lnk->wr_rx_cnt / UMS_ONE_THIRD), 1U);

	/* if credits accumlated less than 10% of wr_rx_cnt(at least 5),
	 * will not be announced by cdc msg.
	 */
	lnk->credits_update_limit = max_t(u8, (u8)(lnk->wr_rx_cnt / UMS_ONE_TENTH), 5U);
}

int ums_wr_create_link(struct ums_link *lnk)
{
	struct ubcore_device *ubdev = lnk->ums_dev->ub_dev;
	union ubcore_reg_seg_flag flag = {
		.bs.token_policy = g_ums_sys_tuning_config.ub_token_mode == UMS_TOKEN_MODE_DISABLE ?
			UBCORE_TOKEN_NONE : UBCORE_TOKEN_PLAIN_TEXT,
		.bs.cacheable = UBCORE_NON_CACHEABLE,
		.bs.access = UCT_UBCORE_MEM_ACCESS_FLAGS,
		.bs.reserved = 0
	};
	struct ubcore_seg_cfg rx_cfg = {
		.va = (uint64_t)lnk->wr_rx_bufs,
		.len = UMS_WR_BUF_SIZE * lnk->wr_rx_cnt,
		.flag = flag,
		.token_id = NULL,
		.token_value.token = 0,
		.iova = 0
	};
	struct ubcore_seg_cfg tx_cfg = {
		.va = (uint64_t)lnk->wr_tx_bufs,
		.len = UMS_WR_BUF_SIZE * lnk->wr_tx_cnt,
		.flag = flag,
		.token_id = NULL,
		.token_value.token = 0,
		.iova = 0
	};
	int rc = 0;
	if (g_ums_sys_tuning_config.ub_token_mode != UMS_TOKEN_MODE_DISABLE) {
		get_random_bytes(&rx_cfg.token_value.token, sizeof(rx_cfg.token_value.token));
		get_random_bytes(&tx_cfg.token_value.token, sizeof(tx_cfg.token_value.token));
	}
	ums_wr_tx_set_wr_id(&lnk->wr_tx_id, 0);
	lnk->wr_rx_id = 1;
	spin_lock_init(&lnk->wr_rx_lock);
	lnk->rx_tseg = ubcore_register_seg(ubdev, &rx_cfg, NULL);
	if (IS_ERR_OR_NULL(lnk->rx_tseg)) {
		UMS_LOGE("failed to regiser link rx seg");
		rc = -EIO;
		goto out;
	}
	lnk->tx_tseg = ubcore_register_seg(ubdev, &tx_cfg, NULL);
	if (IS_ERR_OR_NULL(lnk->tx_tseg)) {
		UMS_LOGE("failed to regiser link tx seg");
		rc = -EIO;
		goto rx_seg;
	}

	ums_wr_create_link_inner(lnk);
	return rc;

rx_seg:
	(void)ubcore_unregister_seg(lnk->rx_tseg);
	lnk->rx_tseg = NULL;
out:
	return rc;
}
