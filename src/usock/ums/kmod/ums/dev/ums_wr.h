/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS work request(wr) interface header file
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

#ifndef UMS_WR_H
#define UMS_WR_H

#include <linux/atomic.h>

#include "ums_core.h"
#include "ums_mod.h"

#include <asm/div64.h>

#define UMS_IMM_MSG_TYPE 0xFF
#define UMS_TX_WAIT_TIME		(2 * HZ)

/* # of ctrl buffers per link, UMS_WR_BUF_CNT should not be less than 2 * UMS_RMBS_PER_LGR_MAX,
 * since every connection at least has two rq/sq credits in average, otherwise may result in waiting
 * for credits in sending process. */
#define UMS_WR_BUF_CNT 255
#define UMS_WR_TX_WAIT_FREE_SLOT_TIME (10 * HZ)
#define UMS_WR_TX_SIZE 44 /* actual size of wr_send data (<=UMS_WR_BUF_SIZE) */
#define UMS_WR_TX_PEND_PRIV_SIZE 32
#define UCT_UBCORE_MEM_ACCESS_FLAGS UBCORE_ACCESS_LOCAL_ONLY
#define UMS_WR_ID_NUM 2

#define UMS_EMERGENCY_CREDITS 2

struct ums_wr_tx_pend_priv {
	u8 priv[UMS_WR_TX_PEND_PRIV_SIZE];
};

struct ums_wc {
	struct ubcore_cr *cr;
	struct ums_link *link;
	u32 jetty_id;
};

typedef void (*ums_wr_tx_handler)(struct ums_wr_tx_pend_priv *, struct ums_link *,
	enum ubcore_cr_opcode);

typedef bool (*ums_wr_tx_filter)(struct ums_wr_tx_pend_priv *, unsigned long);

typedef void (*ums_wr_tx_dismisser)(struct ums_wr_tx_pend_priv *);

struct ums_wr_rx_handler {
	struct hlist_node list; /* hash table collision resolution */
	void (*handler)(struct ums_wc *, void *);
	u8 type;
};

/* Only used by write WRs.
 * All other WRs (CDC/LLC) use ums_wr_tx_send handling WR_ID implicitly
 */
static inline long ums_wr_tx_get_next_wr_id(struct ums_link *link)
{
	return atomic_long_add_return(UMS_WR_ID_NUM, &link->wr_tx_id);
}

static inline void ums_wr_tx_set_wr_id(atomic_long_t *wr_tx_id, long val)
{
	atomic_long_set(wr_tx_id, val);
}

static inline bool ums_wr_tx_link_hold(struct ums_link *link)
{
	if (!ums_link_sendable(link))
		return false;
	atomic_inc(&link->wr_tx_refcnt);
	return true;
}

static inline void ums_wr_tx_link_put(struct ums_link *link)
{
	if (atomic_dec_and_test(&link->wr_tx_refcnt))
		wake_up_all(&link->wr_tx_wait);
}

static inline void ums_wr_wakeup_tx_wait(struct ums_link *lnk)
{
	wake_up_all(&lnk->wr_tx_wait);
}

/* get one tx credit, and peer rq credits dec */
static inline int ums_wr_tx_get_credit(struct ums_link *link)
{
	int new_credits;

	if (link->credits_enable == 0)
		return 1;

	new_credits = atomic_dec_if_positive(&link->peer_rq_credits);
	if (likely(new_credits >= UMS_EMERGENCY_CREDITS))
		return 1;

	if (new_credits < 0)
		return 0;

	atomic_inc(&link->peer_rq_credits);
	return 0;
}

/*
 * get one tx credit for emergency use (LLC announce credits only).
 * can use reserved emergency credits.
 */
static inline int ums_wr_tx_get_credit_emergency(struct ums_link *link)
{
	return (link->credits_enable == 0) || (atomic_dec_if_positive(&link->peer_rq_credits) >= 0);
}

/* put tx credits, when some failures occurred after tx credits got
   or receive announce credits msgs */
static inline void ums_wr_tx_put_credits(struct ums_link *link, int credits, bool wakeup)
{
	if ((link->credits_enable != 0) && (credits != 0)) {
		atomic_add(credits, &link->peer_rq_credits);
		if (wakeup && wq_has_sleeper(&link->wr_tx_wait))
			wake_up_nr(&link->wr_tx_wait, credits);
	}
}

/* get local rq credits and set credits to zero.
   may called when announcing credits */
static inline int ums_wr_rx_get_credits(struct ums_link *link)
{
	return link->credits_enable != 0 ? atomic_fetch_and(0, &link->local_rq_credits) : 0;
}

/* called when post_recv a rqe */
static inline void ums_wr_rx_put_credits(struct ums_link *link, int credits)
{
	if (link->credits_enable != 0 && credits != 0)
		atomic_add(credits, &link->local_rq_credits);
}

/* to check whether local rq credits is higher than watermark. */
static inline bool ums_wr_rx_credits_need_announce(struct ums_link *link)
{
	return (link->credits_enable != 0) && (atomic_read(&link->local_rq_credits) >=
		link->local_cr_watermark_high);
}

static inline bool ums_wr_rx_credits_need_announce_frequent(struct ums_link *link)
{
	/* announce when local rq credits accumulated more than credits_update_limit, or
	 * peer rq credits is empty. As peer credits empty and local credits is less than
	 * credits_update_limit, may results in credits deadlock.
	 */
	return (link->credits_enable != 0) && ((atomic_read(&link->local_rq_credits) >=
		link->credits_update_limit) || (atomic_read(&link->peer_rq_credits) == 0));
}

static inline bool ums_cr_is_rx(struct ubcore_cr *cr)
{
	return (cr->flag.bs.s_r != 0);
}

int ums_wr_create_link(struct ums_link *lnk);
int ums_wr_alloc_link_mem(struct ums_link *link);
void ums_wr_free_link(struct ums_link *lnk);
void ums_wr_free_link_mem(struct ums_link *lnk);
void ums_wr_remove_dev(struct ums_ubcore_device *ums_ub_dev);
void ums_wr_add_dev(struct ums_ubcore_device *ums_ub_dev);
int ums_wr_tx_get_free_slot(struct ums_link *link, ums_wr_tx_handler handler,
	struct ums_wr_buf **wr_buf, struct ubcore_jfs_wr **wr_ub_buf,
	struct ums_wr_tx_pend_priv **wr_pend_priv, bool emergency);
void ums_wr_tx_put_slot(struct ums_link *link, struct ums_wr_tx_pend_priv *wr_pend_priv);
int ums_wr_tx_send(struct ums_link *link, struct ums_wr_tx_pend_priv *priv);
int ums_wr_tx_send_wait(struct ums_link *link, struct ums_wr_tx_pend_priv *priv,
	unsigned long timeout);
void ums_wr_jfc_handler(struct ubcore_jfc *ub_jfc);
void ums_wr_tx_wait_no_pending_sends(struct ums_link *link);
int ums_wr_rx_register_handler(struct ums_wr_rx_handler *handler);
int ums_wr_rx_post_init(struct ums_link *link);

#endif /* UMS_WR_H */
