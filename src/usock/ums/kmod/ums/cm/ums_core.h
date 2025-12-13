/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UMS(UB Memory based Socket)
 *
 * Description:UMS control-plane management(CM) header file
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

#ifndef UMS_CORE_H
#define UMS_CORE_H

#include "ums_log.h"
#include "ums_ubcore.h"

#define GID_SPRINTF_BUFF_SIZE 40
#define UMS_CONN_ID_MASK 0x3FFFFF

struct ums_rtoken_key_info {
	__be32 nw_rkey;
	__be32 nw_rkey_known;
	__be64 nw_vaddr;
};

static inline struct ums_sock *ums_sk(const struct sock *sk)
{
	return (struct ums_sock *)sk;
}

static inline void ums_init_saved_callbacks(struct ums_sock *ums)
{
	ums->clcsk_state_change = NULL;
	ums->clcsk_data_ready = NULL;
	ums->clcsk_write_space = NULL;
	ums->clcsk_error_report = NULL;
}

static inline struct ums_sock *ums_clcsock_user_data(const struct sock *clcsk)
{
	return (struct ums_sock *)((uintptr_t)clcsk->sk_user_data & ~SK_USER_DATA_NOCOPY);
}

/* save target_cb in saved_cb, and replace target_cb with new_cb */
static inline void ums_clcsock_replace_cb(void (**target_cb)(struct sock *),
	void (*new_cb)(struct sock *), void (**saved_cb)(struct sock *))
{
	/* only save once */
	if (!*saved_cb)
		*saved_cb = *target_cb;
	*target_cb = new_cb;
}

/* restore target_cb to saved_cb, and reset saved_cb to NULL */
static inline void ums_clcsock_restore_cb(void (**target_cb)(struct sock *),
	void (**saved_cb)(struct sock *))
{
	if (!*saved_cb)
		return;
	*target_cb = *saved_cb;
	*saved_cb = NULL;
}

#ifdef CONFIG_XFRM
static inline bool using_ipsec(const struct ums_sock *ums)
{
	return (ums->clcsock->sk->sk_policy[0] || ums->clcsock->sk->sk_policy[1]) ? true : false;
}
#else
static inline bool using_ipsec(const struct ums_sock *ums)
{
	return false;
}
#endif

/* Find the connection associated with the given alert token in the link group.
 * To use rbtrees we have to implement our own search core.
 * Requires @conns_lock
 * @token	alert token to search for
 * @lgr		 link group to search in
 * Returns connection associated with token if found, NULL otherwise.
 */
struct ums_connection *ums_lgr_find_conn(u32 token, struct ums_link_group *lgr);

static inline bool ums_conn_lgr_valid(const struct ums_connection *conn)
{
	return conn->lgr && (conn->conn_id != 0);
}

/*
 * Returns true if the specified link is usable.
 *
 * usable means the link is ready to receive UB messages, map memory
 * on the link, etc. This doesn't ensure we are able to send UB messages
 * on this link, if sending UB messages is needed, use ums_link_sendable()
 */
static inline bool ums_link_usable(const struct ums_link *lnk)
{
	if (lnk->state == UMS_LNK_UNUSED || lnk->state == UMS_LNK_INACTIVE)
		return false;
	return true;
}

/*
 * Returns true if the specified link is ready to receive AND send UB
 * messages.
 *
 * For the client side in first contact, the underlying QP may still in
 * RESET or RTR when the link state is ACTIVATING, checks in ums_link_usable()
 * is not strong enough. For those places that need to send any CDC or LLC
 * messages, use ums_link_sendable(), otherwise, use ums_link_usable() instead
 */
static inline bool ums_link_sendable(struct ums_link *lnk)
{
	/* In use, the link is RTS/RTR once the jetty is bounded */
	return ums_link_usable(lnk) && lnk->ub_jetty != NULL && lnk->ub_tjetty != NULL;
}

static inline bool ums_link_active(const struct ums_link *lnk)
{
	return lnk->state == UMS_LNK_ACTIVE;
}

static inline void ums_gid_be16_convert(__u8 *buf, size_t buf_size, u8 *gid_raw)
{
	if (buf_size < GID_SPRINTF_BUFF_SIZE) {
		UMS_LOGE("sprintf failed : buf_size is not enough");
	}
	if (sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			be16_to_cpu(((__be16 *)gid_raw)[0]), be16_to_cpu(((__be16 *)gid_raw)[1]),
			be16_to_cpu(((__be16 *)gid_raw)[2]), be16_to_cpu(((__be16 *)gid_raw)[3]),
			be16_to_cpu(((__be16 *)gid_raw)[4]), be16_to_cpu(((__be16 *)gid_raw)[5]),
			be16_to_cpu(((__be16 *)gid_raw)[6]), be16_to_cpu(((__be16 *)gid_raw)[7])) < 0)
		UMS_LOGE("sprintf failed");
}

static inline struct ums_link_group *ums_get_lgr(struct ums_link *link)
{
	return link->lgr;
}

static inline void ums_lgr_pending_lock(struct ums_init_info *ini, struct mutex *lock)
{
	if (unlikely(ini->mutex))
		UMS_LOGW_ONCE("lgr pending deadlock dected.");

	mutex_lock(lock);
	ini->mutex = lock;
}

static inline void ums_lgr_pending_unlock(struct ums_init_info *ini, struct mutex *lock)
{
	/* already unlock it */
	if (!ini->mutex)
		return;

	ini->mutex = NULL;
	mutex_unlock(lock);
}

/* It must be invoked before checking conn->freed in tx/rx process to
 * ensure that the tx and rx process does not conflict with the corresponding conn free process.
 */
static inline void ums_conn_tx_rx_refcnt_inc(struct ums_connection *conn)
{
	smp_mb__before_atomic();
	atomic_inc(&conn->conn_tx_rx_refcnt);
	smp_mb__after_atomic();
}

/* It must be called in pairs with ums_conn_tx_rx_refcnt_inc() */
static inline void ums_conn_tx_rx_refcnt_dec(struct ums_connection *conn)
{
	smp_mb__before_atomic();

	if (atomic_dec_return(&conn->conn_tx_rx_refcnt) == 0)
		wake_up(&conn->conn_free_wait);

	smp_mb__after_atomic();
}

/* It must be called after conn->freed is set to 1 in ums_conn_free() to
 * ensure that the conn free process does not conflict with the corresponding tx and rx process.
 */
static inline void ums_wait_conn_tx_rx_refcnt(struct ums_connection *conn)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);

	if (atomic_read(&conn->conn_tx_rx_refcnt) == 0) {
		return;
	}

	 /* Other threads holding conn_tx_rx_refcnt may release_lock(sk) during the process and
	  * lock_sock(sk) later. ums_wait_conn_tx_rx_refcnt() is invoked only in ums_conn_free().
	  * In this case, sock must have been locked.
	  *
	  * If release_lock(sk) is not invoked here, Other threads may be stuck at lock_sock(sk)
	  * and cannot release conn_tx_rx_refcnt. As a result, a deadlock occurs.
	  */
	release_sock(&ums->sk);
	wait_event(conn->conn_free_wait, atomic_read(&conn->conn_tx_rx_refcnt) == 0);
	lock_sock(&ums->sk);
}

struct ums_clc_msg_accept_confirm;

void ums_lgr_cleanup_early(struct ums_link_group *lgr);
void ums_lgr_terminate_sched(struct ums_link_group *lgr);
void ums_lgr_hold(struct ums_link_group *lgr);
void ums_lgr_put(struct ums_link_group *lgr);
void ums_port_add(struct ums_ubcore_device *ums_ub_dev, u8 ubport);
void ums_port_err(struct ums_ubcore_device *ums_ub_dev, u8 ubport);
void ums_terminate_all(struct ums_ubcore_device *ums_ub_dev);
int ums_buf_create(struct ums_sock *ums);
int ums_buf_register(struct ums_sock *ums);
void ums_snd_recv_bufs_free(struct ums_sock *ums);
int ums_uncompress_bufsize(u8 compressed);
int ums_rmb_import_seg(struct ums_connection *conn, struct ums_clc_msg_accept_confirm *clc);
void ums_rmb_unimport_seg(struct ums_connection *conn);
int ums_rtoken_delete(struct ums_link *lnk, __be32 nw_rkey);
int ums_vlan_by_tcpsk(struct socket *clcsock, struct ums_init_info *ini);
void ums_conn_free(struct ums_connection *conn);
int ums_conn_create(struct ums_sock *ums, struct ums_init_info *ini);
void ums_lgr_schedule_free_work_fast(struct ums_link_group *lgr);
int ums_core_init(void);
void ums_core_exit(void);
int ums_link_init(struct ums_link_group *lgr, struct ums_link *lnk, u8 link_idx,
	struct ums_init_info *ini);
void ums_link_clear(struct ums_link *lnk, bool log);
void ums_link_hold(struct ums_link *lnk);
void ums_link_put(struct ums_link *lnk);
void ums_switch_link_and_count(struct ums_connection *conn, struct ums_link *to_lnk);
void ums_lgr_set_type(struct ums_link_group *lgr, enum ums_lgr_type new_type);
int ums_link_reg_buf(struct ums_link *link, struct ums_buf_desc *buf_desc, bool is_rmb);
void ums_link_down_cond_sched(struct ums_link *lnk);
#endif /* UMS_CORE_H */
