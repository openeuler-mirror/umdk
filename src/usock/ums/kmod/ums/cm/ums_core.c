// SPDX-License-Identifier: GPL-2.0
/*
 * UMS(UB Memory based Socket)
 *
 * Description:UMS control-plane management(CM)
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

#include <linux/if_vlan.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/socket.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "ums_cdc.h"
#include "ums_clc.h"
#include "ums_close.h"
#include "ums_process_link.h"
#include "ums_llc.h"
#include "ums_mod.h"
#include "ums_wr.h"
#include "ums_core.h"

#define UMS_LGR_NUM_INCR		256
#ifdef UMS_UT_TEST
#define UMS_LGR_FREE_DELAY_SERV		(20 * HZ)
#define UMS_LGR_FREE_DELAY_CLNT		(UMS_LGR_FREE_DELAY_SERV + 1 * HZ)
#else
#define UMS_LGR_FREE_DELAY_SERV		(600 * HZ)
#define UMS_LGR_FREE_DELAY_CLNT		(UMS_LGR_FREE_DELAY_SERV + 10 * HZ)
#endif

#define SENDBUF_ACCESS UBCORE_ACCESS_LOCAL_ONLY
#define RMB_ACCESS (UBCORE_ACCESS_READ | UBCORE_ACCESS_WRITE | UBCORE_ACCESS_ATOMIC)
#define UMS_RMBE_MAX_SIZE 7 /* 0 -> 16KB, 1 -> 32KB, .. 5 -> 512KB .. 7 -> 2MB */
#define UMS_BUF_MIN_SHIFT 14

struct ums_lgr_list g_ums_lgr_list = {	/* established link groups */
	.lock = __SPIN_LOCK_UNLOCKED(g_ums_lgr_list.lock),
	.list = LIST_HEAD_INIT(g_ums_lgr_list.list),
	.num = 0,
};

struct ums_sys_tuning_config g_ums_sys_tuning_config = {
	.ub_token_disable = false,
};

static atomic_t g_lgr_cnt = ATOMIC_INIT(0); /* number of existing link groups */
static DECLARE_WAIT_QUEUE_HEAD(g_lgrs_deleted);

static void ums_buf_free(struct ums_link_group *lgr, bool is_rmb, struct ums_buf_desc *buf_desc);
static void ums_lgr_terminate_inner(struct ums_link_group *lgr, bool soft);
static void ums_link_down_work(struct work_struct *work);
static int ums_modify_jetty_err(struct ums_link *lnk);

/* return head of link group list and its lock for a given link group */
static inline struct list_head *ums_lgr_list_head(struct ums_link_group *lgr,
	spinlock_t **lgr_lock)
{
	*lgr_lock = &g_ums_lgr_list.lock;
	return &g_ums_lgr_list.list;
}

static void ums_ubdev_cnt_inc(struct ums_link *lnk)
{
	atomic_inc(&lnk->ums_dev->lnk_cnt_by_port[lnk->port]);
}

static void ums_ubdev_cnt_dec(struct ums_link *lnk)
{
	atomic_dec(&lnk->ums_dev->lnk_cnt_by_port[lnk->port]);
}

static void ums_lgr_schedule_free_work(struct ums_link_group *lgr)
{
	/* client link group creation always follows the server link group
	 * creation. For client use a somewhat higher removal delay time,
	 * otherwise there is a risk of out-of-sync link groups.
	 */
	if (lgr->freeing == 0)
		(void)mod_delayed_work(system_wq, &lgr->free_work,
			(lgr->role == UMS_CLNT) ? UMS_LGR_FREE_DELAY_CLNT : UMS_LGR_FREE_DELAY_SERV);
}

/* Register connection's alert token in our lookup structure.
 * To use rbtrees we have to implement our own insert core.
 * Requires @conns_lock
 * @ums		connection to register
 * Returns 0 on success, != otherwise.
 */
static void ums_lgr_add_alert_token(struct ums_connection *conn)
{
	struct rb_node **link, *parent = NULL;
	u32 token = conn->conn_id;

	link = &conn->lgr->conns_all.rb_node;
	while (*link) {
		struct ums_connection *cur = rb_entry(*link,
					struct ums_connection, alert_node);
		parent = *link;
		if (cur->conn_id > token)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	rb_link_node(&conn->alert_node, parent, link);
	rb_insert_color(&conn->alert_node, &conn->lgr->conns_all);
}

static void ums_lgr_conn_assign_link_by_conns_num(struct ums_connection *conn, int start_index,
	enum ums_link_state expected)
{
	struct ums_link *lnk;
	int i;

	for (i = start_index; i < UMS_LINKS_PER_LGR_MAX; i++) {
		lnk = &conn->lgr->lnk[i];
		if ((lnk->state == expected) && (lnk->link_is_asym == 0)) {
			conn->lnk = lnk;
			break;
		}
	}
}

/* assign an UMS link to the connection */
static int ums_lgr_conn_assign_link(struct ums_connection *conn, bool first)
{
	enum ums_link_state expected = first ? UMS_LNK_ACTIVATING : UMS_LNK_ACTIVE;
	const unsigned int conns_per_num = 2;
	struct ums_link *lnk;
	int i;

	/* do link balancing */
	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		lnk = &conn->lgr->lnk[i];
		if ((lnk->state != expected) || (lnk->link_is_asym != 0))
			continue;
		if (conn->lgr->role == UMS_CLNT) {
			conn->lnk = lnk; /* temporary, UMS server assigns link */
			break;
		}
		if ((conn->lgr->conns_num % conns_per_num) != 0)
			ums_lgr_conn_assign_link_by_conns_num(conn, i + 1, expected);
		/* server & conns_num % 2 == 0 */
		if (!conn->lnk)
			conn->lnk = lnk;
		break;
	}
	if (!conn->lnk)
		return UMS_CLC_DECL_NOACTLINK;
	atomic_inc(&conn->lnk->conn_cnt);

	return 0;
}

struct ums_connection *ums_lgr_find_conn(u32 token, struct ums_link_group *lgr)
{
	struct ums_connection *res = NULL;
	struct rb_node *node;

	node = lgr->conns_all.rb_node;
	while (node) {
		struct ums_connection *cur = rb_entry(node, struct ums_connection, alert_node);

		if (cur->conn_id > token) {
			node = node->rb_left;
		} else {
			if (cur->conn_id < token) {
				node = node->rb_right;
			} else {
				res = cur;
				break;
			}
		}
	}

	return res;
}

/* Register connection in link group by assigning an alert token
 * registered in a search tree.
 */
static int ums_lgr_register_conn(struct ums_connection *conn, bool first)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);
	static atomic_t nexttoken = ATOMIC_INIT(0);
	int rc;

	rc = ums_lgr_conn_assign_link(conn, first);
	if (rc != 0) {
		conn->lgr = NULL;
		return rc;
	}

	/* find a new conn_id value not yet used by some connection
	 * in this link group
	 */
	sock_hold(&ums->sk); /* sock_put in ums_lgr_unregister_conn() */
	while (conn->conn_id == 0) {
		conn->conn_id = (u32)atomic_inc_return(&nexttoken) & UMS_CONN_ID_MASK;
		if (ums_lgr_find_conn(conn->conn_id, conn->lgr))
			conn->conn_id = 0;
	}
	ums_lgr_add_alert_token(conn);
	conn->lgr->conns_num++;
	UMS_LOGI_LIMITED("register conn %u in lgr %*phN, conn num is %u", conn->conn_id,
		UMS_LGR_ID_SIZE, conn->lgr->id, conn->lgr->conns_num);
	return 0;
}

/* Unregister connection and reset the alert token of the given connection<
 */
static void ums_lgr_unregister_conn_inner(struct ums_connection *conn)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);
	struct ums_link_group *lgr = conn->lgr;

	rb_erase(&conn->alert_node, &lgr->conns_all);
	if (conn->lnk)
		atomic_dec(&conn->lnk->conn_cnt);
	lgr->conns_num--;
	conn->conn_id = 0;
	sock_put(&ums->sk); /* sock_hold in ums_lgr_register_conn() */
}

/* Unregister connection from lgr
 */
static void ums_lgr_unregister_conn(struct ums_connection *conn)
{
	struct ums_link_group *lgr = conn->lgr;

	if (!ums_conn_lgr_valid(conn))
		return;
	write_lock_bh(&lgr->conns_lock);
	if (conn->conn_id != 0)
		ums_lgr_unregister_conn_inner(conn);
	write_unlock_bh(&lgr->conns_lock);
}

void ums_lgr_cleanup_early(struct ums_link_group *lgr)
{
	spinlock_t *lgr_lock;

	if (!lgr)
		return;

	(void)ums_lgr_list_head(lgr, &lgr_lock);
	spin_lock_bh(lgr_lock);
	/* do not use this link group for new connections */
	if (list_empty(&lgr->list) == 0)
		list_del_init(&lgr->list);
	spin_unlock_bh(lgr_lock);
	ums_lgr_terminate_inner(lgr, true);
}

static void ums_lgr_link_deactivate_all(struct ums_link_group *lgr)
{
	int i;

	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		struct ums_link *lnk = &lgr->lnk[i];

		if (ums_link_sendable(lnk))
			lnk->state = UMS_LNK_INACTIVE;
	}
	wake_up_all(&lgr->llc_msg_waiter);
	wake_up_all(&lgr->llc_flow_waiter);
}

static void ums_lgr_free(struct ums_link_group *lgr);

static void ums_lgr_free_work(struct work_struct *work)
{
	int i;
	struct ums_link_group *lgr = container_of(to_delayed_work(work),
						  struct ums_link_group,
						  free_work);
	spinlock_t *lgr_lock;
	bool is_conns_empty;

	(void)ums_lgr_list_head(lgr, &lgr_lock);
	spin_lock_bh(lgr_lock);
	if (lgr->freeing != 0) {
		spin_unlock_bh(lgr_lock);
		return;
	}
	read_lock_bh(&lgr->conns_lock);
	is_conns_empty = RB_EMPTY_ROOT(&lgr->conns_all);
	read_unlock_bh(&lgr->conns_lock);
	if (!is_conns_empty) {
		spin_unlock_bh(lgr_lock);
		return;
	}
	list_del_init(&lgr->list);
	lgr->freeing = 1;
	spin_unlock_bh(lgr_lock);
	(void)cancel_delayed_work(&lgr->free_work);
	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++)
		(void)ums_modify_jetty_err(&lgr->lnk[i]);
	if (lgr->terminating == 0)
		ums_llc_send_link_delete_all(lgr, true, UMS_LLC_DEL_PROG_INIT_TERM);
	ums_lgr_link_deactivate_all(lgr);
	ums_lgr_free(lgr);
}

static void ums_lgr_terminate_work(struct work_struct *work)
{
	struct ums_link_group *lgr = container_of(work, struct ums_link_group, terminate_work);

	ums_lgr_terminate_inner(lgr, true);
}

/* return next unique link id for the lgr */
static u8 ums_next_link_id(struct ums_link_group *lgr)
{
	bool again = true;
	u8 link_id;
	int i;

	while (again) {
		link_id = ++lgr->next_link_id;
		if (link_id == 0)  /* skip zero as link_id */
			link_id = ++lgr->next_link_id;
		for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
			if (ums_link_usable(&lgr->lnk[i]) && lgr->lnk[i].link_id == link_id)
				break;
		}
		if (i < UMS_LINKS_PER_LGR_MAX)
			continue;
		again = false;
	}
	return link_id;
}

static void ums_copy_dev_info_to_link(struct ums_link *link)
{
	struct ums_ubcore_device *ums_dev = link->ums_dev;

	(void)memcpy(link->dev_name, ums_dev->ub_dev->dev_name, UBCORE_MAX_DEV_NAME);
	link->ndev_ifidx = ums_dev->ndev_ifidx[link->port];
}

static void ums_link_fill_basic(struct ums_link_group *lgr, struct ums_link *lnk, u8 link_idx,
	struct ums_init_info *ini)
{
	u8 rndvec[3];

	lnk->ums_dev = ini->ub_dev;
	lnk->port = ini->ub_port;
	lnk->eid_index = ini->eid_index;
	(void)memcpy(lnk->eid.raw, ini->eid.raw, UMS_EID_SIZE);

	(void)get_device(&lnk->ums_dev->ub_dev->dev);
	atomic_inc(&lnk->ums_dev->lnk_cnt);
	refcount_set(&lnk->refcnt, 1); /* link refcnt is set to 1 */
	lnk->clearing = 0;
	lnk->path_mtu = lnk->ums_dev->pattr[lnk->port].active_mtu;
	lnk->link_id = ums_next_link_id(lgr);
	lnk->lgr = lgr;
	ums_lgr_hold(lgr); /* lgr_put in ums_link_clear() */
	lnk->link_idx = link_idx;
	ums_ubdev_cnt_inc(lnk);
	ums_copy_dev_info_to_link(lnk);
	atomic_set(&lnk->conn_cnt, 0);
	atomic_set(&lnk->jetty_mod_cnt, 0);
	ums_llc_link_set_uid(lnk);
	INIT_WORK(&lnk->link_down_wrk, ums_link_down_work);
	get_random_bytes(rndvec, sizeof(rndvec));
	lnk->psn_initial = (u32)(rndvec[0] + (rndvec[1] << 8) + (rndvec[2] << 16));
}

int ums_link_init(struct ums_link_group *lgr, struct ums_link *lnk, u8 link_idx,
	struct ums_init_info *ini)
{
	struct ums_ubcore_device *ums_dev;
	int rc;

	ums_link_fill_basic(lgr, lnk, link_idx, ini);
	if (lnk->ums_dev->initialized == 0) {
		rc = (int)ums_ubcore_setup_per_ubdev(lnk->ums_dev);
		if (rc != 0)
			goto out;
	}

	rc = ums_llc_link_init(lnk);
	if (rc != 0) {
		UMS_LOGE_LIMITED("link init failed, rc=%d", rc);
		goto out;
	}
	rc = ums_wr_alloc_link_mem(lnk);
	if (rc != 0) {
		UMS_LOGE_LIMITED("link mem failed, rc=%d", rc);
		goto clear_llc_lnk;
	}
	rc = ums_ubcore_create_jetty(lnk);
	if (rc != 0) {
		UMS_LOGE_LIMITED("create jetty failed, rc=%d", rc);
		goto free_link_mem;
	}
	rc = ums_wr_create_link(lnk);
	if (rc != 0) {
		UMS_LOGE_LIMITED("create link failed, rc=%d", rc);
		goto destroy_jetty;
	}
	lnk->state = UMS_LNK_ACTIVATING;
	return 0;

destroy_jetty:
	ums_ubcore_destroy_jetty(lnk);
free_link_mem:
	ums_wr_free_link_mem(lnk);
clear_llc_lnk:
	ums_llc_link_clear(lnk, false);
out:
	ums_ubdev_cnt_dec(lnk);
	put_device(&lnk->ums_dev->ub_dev->dev);
	ums_dev = lnk->ums_dev;
	(void)memset(lnk, 0, sizeof(struct ums_link));
	lnk->state = UMS_LNK_UNUSED;
	if (atomic_dec_return(&ums_dev->lnk_cnt) == 0)
		wake_up(&ums_dev->lnks_deleted);
	ums_lgr_put(lgr); /* lgr_hold above */
	return rc;
}

static void ums_lgr_parameter_init(struct ums_link_group *lgr, struct ums_sock *ums,
	struct ums_init_info *ini)
{
	int i;

	lgr->sync_err = 0;
	lgr->terminating = 0;
	lgr->freeing = 0;
	lgr->vlan_id = ini->vlan_id;
	refcount_set(&lgr->refcnt, 1); /* set lgr refcnt to 1 */
	mutex_init(&lgr->sndbufs_lock);
	mutex_init(&lgr->rmbs_lock);
	rwlock_init(&lgr->conns_lock);
	for (i = 0; i < UMS_RMBE_SIZES; i++) {
		INIT_LIST_HEAD(&lgr->sndbufs[i]);
		INIT_LIST_HEAD(&lgr->rmbs[i]);
	}
	lgr->next_link_id = 0;
	spin_lock_bh(&g_ums_lgr_list.lock);
	g_ums_lgr_list.num += UMS_LGR_NUM_INCR;
	(void)memcpy(lgr->id, (u8 *)&g_ums_lgr_list.num, UMS_LGR_ID_SIZE);
	spin_unlock_bh(&g_ums_lgr_list.lock);
	INIT_DELAYED_WORK(&lgr->free_work, ums_lgr_free_work);
	INIT_WORK(&lgr->terminate_work, ums_lgr_terminate_work);
	lgr->conns_all = RB_ROOT;
}

static int ums_lgr_init(struct ums_link_group *lgr, struct ums_sock *ums,
	struct ums_init_info *ini)
{
	int port;
	struct ums_ubcore_device *ubdev;
	u8 link_idx;
	int rc = 0;
	struct ums_link *lnk;

	lgr->role = ums->listen_ums ? UMS_SERV : UMS_CLNT;
	(void)memcpy(lgr->peer_systemid, ini->peer_systemid, UMS_SYSTEMID_LEN);
	
	ubdev = ini->ub_dev;
	port = ini->ub_port;

	mutex_lock(&g_ums_ubcore_devices.mutex);
	if ((list_empty(&ubdev->list) != 0) || test_bit(port, ubdev->ports_going_away)) {
		/* ubdev unavailable */
		rc = UMS_CLC_DECL_NOUMSDEV;
		goto out;
	}
	(void)memcpy(lgr->pnet_id, ubdev->pnetid[port], UMS_MAX_PNETID_LEN);

	ums_llc_lgr_init(lgr, ums);

	link_idx = UMS_SINGLE_LINK;
	lnk = &lgr->lnk[link_idx];

	rc = ums_link_init(lgr, lnk, link_idx, ini);
	if (rc != 0)
		goto out;

	if (lnk->ums_dev->ub_dev->netdev)
		lgr->net = dev_net(lnk->ums_dev->ub_dev->netdev);
	/* UMS only supports VM continous mode */
	lgr->buf_type = UMS_VIRT_CONT_BUFS;
	atomic_inc(&g_lgr_cnt);

	return 0;

out:
	mutex_unlock(&g_ums_ubcore_devices.mutex);
	return rc;
}

/* create a new UMS link group */
static int ums_lgr_create(struct ums_sock *ums, struct ums_init_info *ini)
{
	struct ums_link_group *lgr;
	struct list_head *lgr_list;
	spinlock_t *lgr_lock;
	int rc = 0;

	lgr = kzalloc(sizeof(*lgr), GFP_KERNEL);
	if (!lgr) {
		rc = UMS_CLC_DECL_MEM;
		goto out;
	}
	lgr->tx_wq = alloc_workqueue("ums_tx_wq-%*phN", 0, 0, UMS_LGR_ID_SIZE, lgr->id);
	if (!lgr->tx_wq) {
		rc = -ENOMEM;
		goto free_lgr;
	}

	ums_lgr_parameter_init(lgr, ums, ini);

	rc = ums_lgr_init(lgr, ums, ini);
	if (rc != 0) {
		goto free_wq;
	}
	lgr_list = &g_ums_lgr_list.list;
	lgr_lock = &g_ums_lgr_list.lock;

	ums->conn.lgr = lgr;
	spin_lock_bh(lgr_lock);
	list_add_tail(&lgr->list, lgr_list);
	spin_unlock_bh(lgr_lock);
	mutex_unlock(&g_ums_ubcore_devices.mutex);
	return 0;

free_wq:
	destroy_workqueue(lgr->tx_wq);
free_lgr:
	kfree(lgr);
out:
	if (rc < 0) {
		if (rc == -ENOMEM)
			rc = UMS_CLC_DECL_MEM;
		else
			rc = UMS_CLC_DECL_INTERR;
	}

	return rc;
}

void ums_switch_link_and_count(struct ums_connection *conn,
			       struct ums_link *to_lnk)
{
	atomic_dec(&conn->lnk->conn_cnt);
	/* link_hold in ums_conn_create() */
	ums_link_put(conn->lnk);
	conn->lnk = to_lnk;
	atomic_inc(&conn->lnk->conn_cnt);
	/* link_put in ums_conn_free() */
	ums_link_hold(conn->lnk);
}

static void ums_buf_unuse_inner(struct ums_buf_desc **buf_desc, bool is_rmb,
			   struct ums_link_group *lgr)
{
	struct mutex *lock;  /* lock buffer list */
	int rc;

	if (is_rmb && ((*buf_desc)->confirmed_rkey != 0) && (list_empty(&lgr->list) == 0)) {
		/* unregister rmb with peer */
		rc = ums_llc_flow_initiate(lgr, UMS_LLC_FLOW_RKEY);
		if (rc == 0) {
			/* protect against ums_llc_cli_rkey_exchange() */
			mutex_lock(&lgr->llc_conf_mutex);
			(void)ums_llc_do_delete_rkey(lgr, *buf_desc);
			(*buf_desc)->confirmed_rkey = false;
			mutex_unlock(&lgr->llc_conf_mutex);
			ums_llc_flow_stop(lgr, &lgr->llc_flow_lcl);
		}
	}

	if ((*buf_desc)->reg_err != 0) {
		/* buf registration failed, reuse not possible */
		lock = is_rmb ? &lgr->rmbs_lock :
				&lgr->sndbufs_lock;
		mutex_lock(lock);
		list_del(&(*buf_desc)->list);
		mutex_unlock(lock);

		ums_buf_free(lgr, is_rmb, *buf_desc);
		*buf_desc = NULL;
	} else {
		if (is_rmb)
			/* memzero_explicit provides potential memory barrier semantics */
			memzero_explicit((*buf_desc)->cpu_addr, (size_t)((*buf_desc)->len));
		WRITE_ONCE((*buf_desc)->used, 0);
	}
}

static void ums_buf_unuse(struct ums_connection *conn, struct ums_link_group *lgr)
{
	if (conn->sndbuf_desc) {
		if (conn->sndbuf_desc->is_vm != 0) {
			ums_buf_unuse_inner(&conn->sndbuf_desc, false, lgr);
		} else {
			WRITE_ONCE(conn->sndbuf_desc->used, 0);
		}
	}
	if (conn->rmb_desc)
		ums_buf_unuse_inner(&conn->rmb_desc, true, lgr);
}

/* remove a finished connection from its link group */
void ums_conn_free(struct ums_connection *conn)
{
	struct ums_link_group *lgr;
	if (unlikely(!conn))
		return;
	
	lgr = conn->lgr;
	if (!lgr || (conn->freed != 0))
		/* Connection has never been registered in a
		 * link group, or has already been freed.
		 */
		return;

	conn->freed = 1;
	ums_wait_conn_tx_rx_refcnt(conn);

	UMS_LOGI_LIMITED("free conn %u", conn->conn_id);
	if (!ums_conn_lgr_valid(conn))
		/* Connection has already unregistered from
		 * link group.
		 */
		goto lgr_put;

	ums_conn_wait_pend_tx_wr(conn);

	if (list_empty(&lgr->list) == 0) {
		ums_buf_unuse(conn, lgr); /* allow buffer reuse */
		if (conn->tseg)
			ums_rmb_unimport_seg(conn);
		ums_lgr_unregister_conn(conn);
	}

	if (lgr->conns_num == 0)
		ums_lgr_schedule_free_work(lgr);
lgr_put:
	ums_link_put(conn->lnk); /* link_hold in ums_conn_create() */
	ums_lgr_put(lgr); /* lgr_hold in ums_conn_create() */
}

static void ums_rtoken_clear_link(struct ums_link *lnk)
{
	struct ums_link_group *lgr = lnk->lgr;
	int i;

	for (i = 0; i < UMS_RMBS_PER_LGR_MAX; i++) {
		lgr->rtokens[i][lnk->link_idx].rkey = 0;
		lgr->rtokens[i][lnk->link_idx].dma_addr = 0;
	}
}

static void ums_unregister_seg(struct ums_buf_desc *buf_desc, const struct ums_link *lnk)
{
	if (buf_desc && (buf_desc->is_reg_seg[lnk->link_idx] != 0) &&
		(buf_desc->seg[lnk->link_idx] != NULL)) {
		buf_desc->is_reg_seg[lnk->link_idx] = false;
		(void)ubcore_unregister_seg(buf_desc->seg[lnk->link_idx]);
		buf_desc->seg[lnk->link_idx] = NULL;
	}
	return;
}

/* unregister all buffers of lgr for a deleted link */
static void ums_buf_unregister_lgr(struct ums_link *lnk)
{
	struct ums_link_group *lgr = lnk->lgr;
	struct ums_buf_desc *buf_desc, *bf;
	int i;

	for (i = 0; i < UMS_RMBE_SIZES; i++) {
		mutex_lock(&lgr->rmbs_lock);
		list_for_each_entry_safe(buf_desc, bf, &lgr->rmbs[i], list)
			ums_unregister_seg(buf_desc, lnk);
		mutex_unlock(&lgr->rmbs_lock);
		mutex_lock(&lgr->sndbufs_lock);
		list_for_each_entry_safe(buf_desc, bf, &lgr->sndbufs[i], list)
			ums_unregister_seg(buf_desc, lnk);
		mutex_unlock(&lgr->sndbufs_lock);
	}
}

static void ums_link_clear_inner(struct ums_link *lnk)
{
	struct ums_link_group *lgr = lnk->lgr;
	struct ums_ubcore_device *ums_ub_dev;

	ums_buf_unregister_lgr(lnk);
	ums_ubcore_destroy_jetty(lnk);
	ums_wr_free_link_mem(lnk);
	ums_ubdev_cnt_dec(lnk);
	put_device(&lnk->ums_dev->ub_dev->dev);
	ums_ub_dev = lnk->ums_dev;
	(void)memset(lnk, 0, sizeof(struct ums_link));
	lnk->state = UMS_LNK_UNUSED;
	if (atomic_dec_return(&ums_ub_dev->lnk_cnt) == 0)
		wake_up(&ums_ub_dev->lnks_deleted);
	ums_lgr_put(lgr); /* lgr_hold in ums_link_init() */
}

/* must be called under lgr->llc_conf_mutex lock */
void ums_link_clear(struct ums_link *lnk, bool log)
{
	if (!lnk->lgr || (lnk->clearing != 0) || (lnk->state == UMS_LNK_UNUSED))
		return;
	lnk->clearing = 1;

	ums_llc_link_clear(lnk, log);
	ums_rtoken_clear_link(lnk);
	ums_wr_free_link(lnk);
	ums_link_put(lnk); /* theoretically last link_put */
}

void ums_link_hold(struct ums_link *lnk)
{
	refcount_inc(&lnk->refcnt);
}

void ums_link_put(struct ums_link *lnk)
{
	if (unlikely(!lnk))
		return;
	if (refcount_dec_and_test(&lnk->refcnt))
		ums_link_clear_inner(lnk);
}

static void ums_buf_free(struct ums_link_group *lgr, bool is_rmb, struct ums_buf_desc *buf_desc)
{
	if ((buf_desc->is_vm == 0) && buf_desc->pages)
		__free_pages(buf_desc->pages, buf_desc->order);
	else if ((buf_desc->is_vm != 0) && buf_desc->cpu_addr)
		vfree(buf_desc->cpu_addr);
	kfree(buf_desc);
	buf_desc = NULL;
}

static void ums_lgr_free_bufs_inner(struct ums_link_group *lgr, bool is_rmb)
{
	struct ums_buf_desc *buf_desc, *bf_desc;
	struct list_head *buf_list;
	int i;

	for (i = 0; i < UMS_RMBE_SIZES; i++) {
		if (is_rmb)
			buf_list = &lgr->rmbs[i];
		else
			buf_list = &lgr->sndbufs[i];
		list_for_each_entry_safe(buf_desc, bf_desc, buf_list, list) {
			list_del(&buf_desc->list);
			ums_buf_free(lgr, is_rmb, buf_desc);
		}
	}
}

static void ums_lgr_free_bufs(struct ums_link_group *lgr)
{
	/* free send buffers */
	ums_lgr_free_bufs_inner(lgr, false);
	/* free rmbs */
	ums_lgr_free_bufs_inner(lgr, true);
}

/* won't be freed until no one accesses to lgr anymore */
static void ums_lgr_free_inner(struct ums_link_group *lgr)
{
	ums_lgr_free_bufs(lgr);

	if (atomic_dec_return(&g_lgr_cnt) == 0)
		wake_up(&g_lgrs_deleted);
	kfree(lgr);
}

/* remove a link group */
static void ums_lgr_free(struct ums_link_group *lgr)
{
	int i;

	mutex_lock(&lgr->llc_conf_mutex);
	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		if (lgr->lnk[i].state != UMS_LNK_UNUSED)
			ums_link_clear(&lgr->lnk[i], false);
	}
	mutex_unlock(&lgr->llc_conf_mutex);
	ums_llc_lgr_clear(lgr);

	destroy_workqueue(lgr->tx_wq);

	ums_lgr_put(lgr); /* theoretically last lgr_put */
}

void ums_lgr_hold(struct ums_link_group *lgr)
{
	refcount_inc(&lgr->refcnt);
}

void ums_lgr_put(struct ums_link_group *lgr)
{
	if (refcount_dec_and_test(&lgr->refcnt))
		ums_lgr_free_inner(lgr);
}

static void ums_sk_wake_ups(struct ums_sock *ums)
{
	ums->sk.sk_write_space(&ums->sk);
	ums->sk.sk_data_ready(&ums->sk);
	ums->sk.sk_state_change(&ums->sk);
}

/* kill a connection */
static void ums_conn_kill(struct ums_connection *conn, bool soft)
{
	struct ums_sock *ums = container_of(conn, struct ums_sock, conn);

	(void)ums_close_abort(conn);
	conn->killed = 1;
	ums->sk.sk_err = ECONNABORTED;
	ums_sk_wake_ups(ums);

	ums_conn_wait_pend_tx_wr(conn);

	ums_lgr_unregister_conn(conn);
	ums_close_active_abort(ums);
}

static void ums_lgr_cleanup(struct ums_link_group *lgr)
{
	u32 rsn = lgr->llc_termination_rsn;

	if (rsn == 0)
		rsn = UMS_LLC_DEL_PROG_INIT_TERM;
	ums_llc_send_link_delete_all(lgr, false, rsn);
	ums_lgr_link_deactivate_all(lgr);
}

/* terminate link group
 * @soft: true if link group shutdown can take its time
 *	  false if immediate link group shutdown is required
 */
static void ums_lgr_terminate_inner(struct ums_link_group *lgr, bool soft)
{
	struct ums_connection *conn;
	struct ums_sock *ums;
	struct rb_node *node;

	if (lgr->terminating != 0)
		return;
	/* cancel free_work sync, will terminate when lgr->freeing is set */
	(void)cancel_delayed_work_sync(&lgr->free_work);
	lgr->terminating = 1;

	/* kill link group connections */
	read_lock_bh(&lgr->conns_lock);
	node = rb_first(&lgr->conns_all);
	while (node) {
		read_unlock_bh(&lgr->conns_lock);
		conn = rb_entry(node, struct ums_connection, alert_node);
		ums = container_of(conn, struct ums_sock, conn);
		sock_hold(&ums->sk); /* sock_put below */
		lock_sock(&ums->sk);
		ums_conn_kill(conn, soft);
		release_sock(&ums->sk);
		sock_put(&ums->sk); /* sock_hold above */
		read_lock_bh(&lgr->conns_lock);
		node = rb_first(&lgr->conns_all);
	}
	read_unlock_bh(&lgr->conns_lock);
	ums_lgr_cleanup(lgr);
	ums_lgr_free(lgr);
}

/* unlink link group and schedule termination */
void ums_lgr_terminate_sched(struct ums_link_group *lgr)
{
	spinlock_t *lgr_lock;

	(void)ums_lgr_list_head(lgr, &lgr_lock);
	spin_lock_bh(lgr_lock);
	if ((lgr->terminating != 0) || (lgr->freeing != 0) || (list_empty(&lgr->list) != 0)) {
		spin_unlock_bh(lgr_lock);
		return;
	}
	list_del_init(&lgr->list);
	lgr->freeing = 1;
	spin_unlock_bh(lgr_lock);
	(void)schedule_work(&lgr->terminate_work);
}

/* Called when an UMS device is removed or the ums module is unloaded.
 * If ums_dev is given, all UMS link groups using this device are terminated.
 * If ums_dev is NULL, all UMS link groups are terminated.
 */
void ums_terminate_all(struct ums_ubcore_device *ums_ub_dev)
{
	struct ums_link_group *lgr, *lg;
	LIST_HEAD(lgr_free_list);
	int i;

	spin_lock_bh(&g_ums_lgr_list.lock);
	if (!ums_ub_dev) {
		list_splice_init(&g_ums_lgr_list.list, &lgr_free_list);
		list_for_each_entry(lgr, &lgr_free_list, list)
			lgr->freeing = 1;
	} else {
		list_for_each_entry_safe(lgr, lg, &g_ums_lgr_list.list, list) {
			for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
				if (lgr->lnk[i].ums_dev == ums_ub_dev)
					ums_link_down_cond_sched(&lgr->lnk[i]);
			}
		}
	}
	spin_unlock_bh(&g_ums_lgr_list.lock);

	list_for_each_entry_safe(lgr, lg, &lgr_free_list, list) {
		list_del_init(&lgr->list);
		for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++)
			(void)ums_modify_jetty_err(&lgr->lnk[i]);
		ums_llc_set_termination_rsn(lgr, UMS_LLC_DEL_OP_INIT_TERM);
		ums_lgr_terminate_inner(lgr, false);
	}

	if (ums_ub_dev) {
		if (atomic_read(&ums_ub_dev->lnk_cnt) != 0)
			wait_event(ums_ub_dev->lnks_deleted, atomic_read(&ums_ub_dev->lnk_cnt) == 0);
	} else {
		if (atomic_read(&g_lgr_cnt) != 0)
			wait_event(g_lgrs_deleted, atomic_read(&g_lgr_cnt) == 0);
	}
}

/* set new lgr type and clear all asymmetric link tagging */
void ums_lgr_set_type(struct ums_link_group *lgr, enum ums_lgr_type new_type)
{
	char *lgr_type = "";
	int i;

	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++)
		if (ums_link_usable(&lgr->lnk[i]))
			lgr->lnk[i].link_is_asym = false;
	if (lgr->type == new_type)
		return;
	lgr->type = new_type;

	if (lgr->type == UMS_LGR_SINGLE)
		lgr_type = "SINGLE";
	else
		lgr_type = "NONE";

	UMS_LOGI_LIMITED("UMS lg %*phN state changed: %s, pnetid %.16s", UMS_LGR_ID_SIZE, lgr->id,
		lgr_type, lgr->pnet_id);
}

static inline bool ums_udev_can_access_from_ns(struct ums_ubcore_device *ums_ub_dev,
	struct net *net)
{
	struct net_device *ndev = ums_ub_dev->ub_dev->netdev;

	if (!ndev)
		return false;
	
	return net_eq(dev_net(ndev), net);
}

void ums_port_add(struct ums_ubcore_device *ums_ub_dev, u8 ubport)
{
	struct ums_link_group *lgr, *n;

	spin_lock_bh(&g_ums_lgr_list.lock);
	list_for_each_entry_safe(lgr, n, &g_ums_lgr_list.list, list) {
		if (strncmp(ums_ub_dev->pnetid[ubport], lgr->pnet_id, UMS_MAX_PNETID_LEN) != 0)
			continue;

		if (!ums_udev_can_access_from_ns(ums_ub_dev, lgr->net))
			continue;

		if (lgr->type == UMS_LGR_SINGLE)
			continue;
		UMS_LOGW("Not support multi link.");
	}
	spin_unlock_bh(&g_ums_lgr_list.lock);
}

/* link is down - wakeup tx wait and clear lgr and link,
 * must be called under lgr->llc_conf_mutex lock
 */
static void ums_link_down(struct ums_link *lnk)
{
	struct ums_link_group *lgr = lnk->lgr;

	if (!lgr || (lnk->state == UMS_LNK_UNUSED) || (list_empty(&lgr->list) != 0))
		return;

	/* wake up tx waiters as link is inactive */
	UMS_LOGI("Link down, terminate lgr and lnk %*phN.", UMS_LGR_ID_SIZE,
			 lnk->link_uid);
	ums_wr_wakeup_tx_wait(lnk);

	/* clear the link group and link */
	ums_lgr_terminate_sched(lgr);
	return;
}

/* will get the lgr->llc_conf_mutex lock */
void ums_link_down_cond_sched(struct ums_link *lnk)
{
	if (ums_link_downing(&lnk->state)) {
		ums_link_hold(lnk); /* ums_link_put in link_down_wrk */
		if (!schedule_work(&lnk->link_down_wrk)) {
			ums_link_put(lnk);
		}
	}
}

void ums_port_err(struct ums_ubcore_device *ums_ub_dev, u8 ubport)
{
	struct ums_link_group *lgr, *n;
	int i;

	list_for_each_entry_safe(lgr, n, &g_ums_lgr_list.list, list) {
		if (strncmp(ums_ub_dev->pnetid[ubport], lgr->pnet_id,
				UMS_MAX_PNETID_LEN) != 0)
			continue; /* lgr is not affected */
		if (list_empty(&lgr->list) != 0)
			continue;
		for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
			struct ums_link *lnk = &lgr->lnk[i];

			if (ums_link_usable(lnk) &&
				lnk->ums_dev == ums_ub_dev && lnk->port == ubport)
				ums_link_down_cond_sched(lnk);
		}
	}
}

static int ums_modify_jetty_err(struct ums_link *lnk)
{
	int ret = 0;
	struct ubcore_jetty_attr attr = {0};

	if (!lnk || !lnk->ub_jetty)
		return -1;

	/* Only modify once */
	if (atomic_inc_return(&lnk->jetty_mod_cnt) == 1) {
		attr.mask = (uint32_t)UBCORE_JETTY_STATE;
		attr.state = UBCORE_JETTY_STATE_ERROR;
		ret = ubcore_modify_jetty(lnk->ub_jetty, &attr, NULL);
		if (ret != 0)
			UMS_LOGW_LIMITED("modify jetty[eid:%pI6c, id:%u] failed.",
				&lnk->ub_jetty->jetty_id.eid, lnk->ub_jetty->jetty_id.id);
	}

	return ret;
}

static void ums_link_down_work(struct work_struct *work)
{
	struct ums_link *link = container_of(work, struct ums_link, link_down_wrk);
	struct ums_link_group *lgr = link->lgr;

	(void)ums_modify_jetty_err(link);
	
	if (list_empty(&lgr->list) != 0)
		goto out;
	wake_up_all(&lgr->llc_msg_waiter);
	mutex_lock(&lgr->llc_conf_mutex);
	ums_link_down(link);
	mutex_unlock(&lgr->llc_conf_mutex);

out:
	ums_link_put(link); /* ums_link_hold by schedulers of link_down_work */
}

#ifdef KERNEL_VERSION_4
static int ums_vlan_by_tcpsk_walk(struct net_device *lower_dev, void *priv)
{
	unsigned short *vlan_id = (unsigned short *)priv;
#else
static int ums_vlan_by_tcpsk_walk(struct net_device *lower_dev, struct netdev_nested_priv *priv)
{
	unsigned short *vlan_id = (unsigned short *)priv->data;
#endif

	if (is_vlan_dev(lower_dev)) {
		*vlan_id = vlan_dev_vlan_id(lower_dev);
		return 1;
	}

	return 0;
}

/* Determine vlan of internal TCP socket. */
int ums_vlan_by_tcpsk(struct socket *clcsock, struct ums_init_info *ini)
{
	struct dst_entry *dst = sk_dst_get(clcsock->sk);
	struct netdev_nested_priv priv;
	struct net_device *ndev;

	ini->vlan_id = 0;
	if (!dst)
		return -ENOTCONN;
	if (!dst->dev) {
		dst_release(dst);
		return -ENODEV;
	}
	ndev = dst->dev;
	if (is_vlan_dev(ndev)) {
		ini->vlan_id = vlan_dev_vlan_id(ndev);
		dst_release(dst);
		return 0;
	}
	priv.data = (void *)&ini->vlan_id;
	rtnl_lock();
	(void)netdev_walk_all_lower_dev(ndev, ums_vlan_by_tcpsk_walk, &priv);
	rtnl_unlock();
	dst_release(dst);

	return 0;
}

static bool ums_lgr_match(struct ums_link_group *lgr, struct ums_init_info *ini,
	enum ums_lgr_role role, struct net *net)
{
	struct ums_link *lnk;
	int i;

	if ((memcmp(lgr->peer_systemid, ini->peer_systemid, UMS_SYSTEMID_LEN) != 0) ||
		(lgr->role != role))
		return false;

	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		lnk = &lgr->lnk[i];

		if (!ums_link_active(lnk))
			continue;

		/* use verbs API to check netns, instead of lgr->net */
		if (!ums_udev_can_access_from_ns(lnk->ums_dev, net))
			return false;

		if ((lgr->role == UMS_SERV || lnk->tjetty_id == ini->tjetty_id) &&
			(memcmp(lnk->peer_eid.raw, ini->peer_eid.raw, UMS_EID_SIZE) == 0) &&
			(memcmp(lnk->peer_mac, ini->peer_mac, ETH_ALEN) == 0))
			return true;
	}
	return false;
}

static void ums_rx_tx_counter_init(struct ums_connection *conn)
{
	/* Initialize RX & TX diagnostic inform for each connection.
	 * These counters mean what ums wants net devices "DO" insead of what has been "DONE" */
	conn->rx_cnt = 0;
	conn->tx_cnt = 0;
	conn->tx_corked_cnt = 0;
	conn->rx_bytes = 0;
	conn->tx_bytes = 0;
	conn->tx_corked_bytes = 0;
}

static int ums_new_link_create(struct ums_sock *ums, struct ums_init_info *ini, bool create_lgr)
{
	struct ums_connection *conn = &ums->conn;
	int rc = 0;
	struct ums_link_group *lgr;

	if (ini->first_contact_local != 0) {
		if (!create_lgr)
			return UMS_CLC_DECL_ERR_REQ_LGR;
		/* keep this clcsock for reuse */
		rc = ums_lgr_create(ums, ini);
		if (rc != 0)
			return rc;
		lgr = conn->lgr;
		write_lock_bh(&lgr->conns_lock);
		rc = ums_lgr_register_conn(conn, true);
		write_unlock_bh(&lgr->conns_lock);
		if (rc != 0) {
			ums_lgr_cleanup_early(lgr);
			return rc;
		}
	}
	ums_lgr_hold(conn->lgr); /* lgr_put in ums_conn_free() */
	ums_link_hold(conn->lnk); /* link_put in ums_conn_free() */
	conn->freed = 0;
	conn->local_tx_ctrl.common.type = UMS_CDC_MSG_TYPE;
	conn->local_tx_ctrl.len = UMS_WR_TX_SIZE;
	conn->urg_state = UMS_URG_READ;
	atomic_set(&conn->conn_tx_rx_refcnt, 0);
	init_waitqueue_head(&conn->conn_free_wait);
	init_waitqueue_head(&conn->conn_pend_tx_wq);
	ums_rx_tx_counter_init(conn);
	conn->rx_off = 0;
#ifndef KERNEL_HAS_ATOMIC64
	spin_lock_init(&conn->acurs_lock);
#endif

	return rc;
}

static int ums_conn_create_inner(struct ums_sock *ums, struct ums_init_info *ini, bool create_lgr)
{
	struct ums_connection *conn = &ums->conn;
	struct net *net = sock_net(&ums->sk);
	struct list_head *lgr_list;
	struct ums_link_group *lgr;
	enum ums_lgr_role role;
	spinlock_t *lgr_lock;
	int rc = 0;

	lgr_list = &g_ums_lgr_list.list;
	lgr_lock = &g_ums_lgr_list.lock;
	ini->first_contact_local = 1;
	conn->jetty_info.is_ums_conn = false;
	role = ums->listen_ums ? UMS_SERV : UMS_CLNT;
	if (role == UMS_CLNT && ini->first_contact_peer != 0)
		goto create;
	/* determine if an existing link group can be reused */
	spin_lock_bh(lgr_lock);
	list_for_each_entry(lgr, lgr_list, list) {
		write_lock_bh(&lgr->conns_lock);
		if ((ums_lgr_match(lgr, ini, role, net)) &&
			(lgr->sync_err == 0) && (lgr->vlan_id == ini->vlan_id) &&
			((lgr->conns_num < UMS_RMBS_PER_LGR_MAX) && (lgr->terminating == 0) &&
				(bitmap_full(lgr->rtokens_used_mask, UMS_RMBS_PER_LGR_MAX) == 0))) {
			ini->first_contact_local = 0;
			conn->lgr = lgr;
			rc = ums_lgr_register_conn(conn, false);
			write_unlock_bh(&lgr->conns_lock);
			if (rc != 0) {
				spin_unlock_bh(lgr_lock);
				return rc;
			}
			if (delayed_work_pending(&lgr->free_work))
				(void)cancel_delayed_work(&lgr->free_work);
			break;
		}
		write_unlock_bh(&lgr->conns_lock);
	}
	spin_unlock_bh(lgr_lock);
	if ((role == UMS_CLNT) && (ini->first_contact_peer == 0) && (ini->first_contact_local != 0))
		/* Server reuses a link group, but Client wants to start
		 * a new one
		 * send out_of_sync decline, reason synchr. error
		 */
		return UMS_CLC_DECL_SYNCERR;

create:
	return ums_new_link_create(ums, ini, create_lgr);
}

/* create a new UMS connection (and a new link group if necessary) */
int ums_conn_create(struct ums_sock *ums, struct ums_init_info *ini)
{
	/* try create conn without create lgr first, disallow create lgr */
	int rc = ums_conn_create_inner(ums, ini, false);
	if (rc == 0) {
		/* not rely on new lgr, unlock lgr pending lock in advance. */
		ums_lgr_pending_unlock(ini, ini->mutex);
		return 0;
	} else if (rc != UMS_CLC_DECL_ERR_REQ_LGR) {
		/* that's unexcepted error */
		return rc;
	}

	/* create lgr if needed */
	return ums_conn_create_inner(ums, ini, true);
}

/* convert the RMB size into the compressed notation (minimum 16K, see
 * UMSD/R_DMBE_SIZES.
 * In contrast to plain ilog2, this rounds towards the next power of 2,
 * so the socket application gets at least its desired sndbuf / rcvbuf size.
 */
static u8 ums_compress_bufsize(int size, bool is_rmb)
{
	const unsigned int max_scat = SG_MAX_SINGLE_ALLOC * PAGE_SIZE;
	u8 compressed;
	u32 u_size;

	if (size <= UMS_BUF_MIN_SIZE)
		return 0;
	u_size = ((u32)(size - 1)) >> UMS_BUF_MIN_SHIFT;  /* convert to 16K multiple */
	compressed = min_t(u8, (u8)(ilog2(u_size) + 1), (u8)UMS_RMBE_MAX_SIZE);

	if (is_rmb)
		/* RMBs are backed by & limited to max size of scatterlists */
		compressed = min_t(u8, compressed, (u32)ilog2(max_scat >> UMS_BUF_MIN_SHIFT));

	return compressed;
}

/* convert the RMB size from compressed notation into integer */
int ums_uncompress_bufsize(u8 compressed)
{
	u32 size;

	size = 0x00000001 << (((u32)compressed) + UMS_BUF_MIN_SHIFT);
	return (int)size;
}

/* try to reuse a sndbuf or rmb description slot for a certain
 * buffer size; if not available, return NULL
 */
static struct ums_buf_desc *ums_buf_get_slot(int compressed_bufsize, struct mutex *lock,
	struct list_head *buf_list)
{
	struct ums_buf_desc *buf_slot;

	mutex_lock(lock);
	list_for_each_entry(buf_slot, buf_list, list) {
		/* look for an unused buffer slot */
		if (cmpxchg(&buf_slot->used, 0, 1) == 0) {
			mutex_unlock(lock);
			return buf_slot;
		}
	}
	mutex_unlock(lock);

	return NULL;
}

static inline int ums_rmb_wnd_update_limit(int rmbe_size)
{
	return max_t(int, rmbe_size / 10, SOCK_MIN_SNDBUF >> 1);
}

/* register a new buf on UBcore device, rmb or vzalloced sndbuf
 * must be called under lgr->llc_conf_mutex lock
 */
int ums_link_reg_buf(struct ums_link *link, struct ums_buf_desc *buf_desc, bool is_rmb)
{
	struct ubcore_device *ub_dev = link->ums_dev->ub_dev;
	struct ubcore_target_seg *seg = NULL;
	union ubcore_reg_seg_flag flag = {
		.bs.token_policy = g_ums_sys_tuning_config.ub_token_disable ? UBCORE_TOKEN_NONE : UBCORE_TOKEN_PLAIN_TEXT,
		.bs.cacheable = UBCORE_NON_CACHEABLE,
		.bs.access = is_rmb ? RMB_ACCESS : SENDBUF_ACCESS,
		.bs.reserved = 0
	};
	struct ubcore_seg_cfg cfg;

	(void)memset(&cfg, 0, sizeof(struct ubcore_seg_cfg));

	if (list_empty(&link->lgr->list) != 0)
		return -ENOLINK;

	if (buf_desc->is_reg_seg[link->link_idx] == 0) {
		/* register memory region for new buf */
		cfg.va = (uintptr_t)buf_desc->cpu_addr;
		cfg.len = (uint64_t)buf_desc->len;
		cfg.flag = flag;
		if (!g_ums_sys_tuning_config.ub_token_disable) {
			get_random_bytes(&buf_desc->seg_token_value.token, sizeof(buf_desc->seg_token_value.token));
			cfg.token_value.token = buf_desc->seg_token_value.token;
		}
		seg = ubcore_register_seg(ub_dev, &cfg, NULL);
		if (IS_ERR_OR_NULL(seg)) {
			buf_desc->reg_err = true;
			return -ENOMEM;
		}

		buf_desc->seg[link->link_idx] = seg;
		buf_desc->is_reg_seg[link->link_idx] = true;
	}

	return 0;
}

/* register the new vzalloced sndbuf on all links in clc process */
static int ums_lgr_reg_sndbufs(struct ums_link *link, struct ums_buf_desc *snd_desc)
{
	struct ums_link_group *lgr = link->lgr;
	int i, rc = -ENOLINK;

	if (snd_desc->is_vm == 0)
		return -EINVAL;

	/* protect against parallel ums_link_reg_buf() */
	mutex_lock(&lgr->llc_conf_mutex);
	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		if (!ums_link_usable(&lgr->lnk[i]))
			continue;
		rc = ums_link_reg_buf(&lgr->lnk[i], snd_desc, false);
		if (rc != 0)
			break;
	}
	mutex_unlock(&lgr->llc_conf_mutex);
	return rc;
}

/* register the new rmb on all links in clc process */
static int ums_lgr_reg_rmbs(struct ums_sock *ums, struct ums_buf_desc *rmb_desc)
{
	struct ums_link *link = ums->conn.lnk;
	struct ums_link_group *lgr = link->lgr;
	int i, lnk = 0, rc = -ENOLINK;

	mutex_lock(&lgr->llc_conf_mutex);
	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
		if (!ums_link_usable(&lgr->lnk[i]))
			continue;
		rc = ums_link_reg_buf(&lgr->lnk[i], rmb_desc, true);
		if (rc != 0)
			goto out;
		/* available link count inc */
		lnk++;
	}

	rmb_desc->confirmed_rkey = true;
out:
	mutex_unlock(&lgr->llc_conf_mutex);
	return rc;
}

static struct ums_buf_desc *ums_new_buf_create(const struct ums_link_group *lgr, bool is_rmb,
	int bufsize)
{
	struct ums_buf_desc *buf_desc;

	/* try to alloc a new buffer */
	buf_desc = kzalloc(sizeof(*buf_desc), GFP_KERNEL);
	if (!buf_desc)
		return ERR_PTR(-ENOMEM);

	if (unlikely(lgr->buf_type != UMS_VIRT_CONT_BUFS)) {
		UMS_LOGE("Unsupported lgr type.");
		goto out;
	}

	buf_desc->order = (u32)get_order((unsigned long)bufsize);
	buf_desc->cpu_addr = vzalloc(PAGE_SIZE << buf_desc->order);
	if (!buf_desc->cpu_addr)
		goto out;
	buf_desc->pages = NULL;
	buf_desc->len = bufsize;
	buf_desc->is_vm = true;

	return buf_desc;

out:
	kfree(buf_desc);
	return ERR_PTR(-EAGAIN);
}

static int ums_set_buf_for_conn(struct ums_sock *ums, struct ums_buf_desc *buf_desc,
	int bufsize_compressed, int bufsize, bool is_rmb)
{
	struct ums_connection *conn = &ums->conn;
	const int bufsize_rate = 2;

	if (IS_ERR(buf_desc))
		return (int)PTR_ERR(buf_desc);
	if (is_rmb) {
		conn->rmb_desc = buf_desc;
		conn->rmbe_size_short = bufsize_compressed;
		ums->sk.sk_rcvbuf = bufsize * bufsize_rate;
		atomic_set(&conn->bytes_to_rcv, 0);
		conn->rmbe_update_limit =
			ums_rmb_wnd_update_limit(buf_desc->len);
	} else {
		conn->sndbuf_desc = buf_desc;
		ums->sk.sk_sndbuf = bufsize * bufsize_rate;
		atomic_set(&conn->sndbuf_space, bufsize);
	}

	return 0;
}

static int ums_buf_create_inner(struct ums_sock *ums, bool is_rmb)
{
	struct ums_buf_desc *buf_desc = ERR_PTR(-ENOMEM);
	struct ums_connection *conn = &ums->conn;
	struct ums_link_group *lgr = conn->lgr;
	int bufsize, bufsize_compressed;
	struct list_head *buf_list;
	bool is_dgraded = false;
	struct mutex *lock; /* lock buffer list */
	int sk_buf_size;

	sk_buf_size = (int)(is_rmb ? ((u32)ums->sk.sk_rcvbuf) >> 1 : ((u32)ums->sk.sk_sndbuf) >> 1);
	for (bufsize_compressed = ums_compress_bufsize(sk_buf_size, is_rmb);
	     bufsize_compressed >= 0; bufsize_compressed--) {
		if (is_rmb) {
			lock = &lgr->rmbs_lock;
			buf_list = &lgr->rmbs[bufsize_compressed];
		} else {
			lock = &lgr->sndbufs_lock;
			buf_list = &lgr->sndbufs[bufsize_compressed];
		}
		bufsize = ums_uncompress_bufsize((u8)bufsize_compressed);

		/* check for reusable slot in the link group */
		buf_desc = ums_buf_get_slot(bufsize_compressed, lock, buf_list);
		if (buf_desc) {
			break; /* found reusable slot */
		}
		buf_desc = ums_new_buf_create(lgr, is_rmb, bufsize);
		if (PTR_ERR(buf_desc) == -ENOMEM)
			break;
		if (IS_ERR(buf_desc)) {
			if (!is_dgraded)
				is_dgraded = true;
			continue;
		}
		buf_desc->used = 1;
		mutex_lock(lock);
		list_add(&buf_desc->list, buf_list);
		mutex_unlock(lock);
		break;
	}
	
	return ums_set_buf_for_conn(ums, buf_desc, bufsize_compressed, bufsize, is_rmb);
}

void ums_snd_recv_bufs_free(struct ums_sock *ums)
{
	mutex_lock(&ums->conn.lgr->sndbufs_lock);
	list_del(&ums->conn.sndbuf_desc->list);
	mutex_unlock(&ums->conn.lgr->sndbufs_lock);
	ums_buf_free(ums->conn.lgr, false, ums->conn.sndbuf_desc);
	ums->conn.sndbuf_desc = NULL;

	mutex_lock(&ums->conn.lgr->rmbs_lock);
	list_del(&ums->conn.rmb_desc->list);
	mutex_unlock(&ums->conn.lgr->rmbs_lock);
	ums_buf_free(ums->conn.lgr, false, ums->conn.rmb_desc);
	ums->conn.rmb_desc = NULL;
}
/* create the send and receive buffer for an UMS socket;
 * receive buffers are called RMBs;
 * (even though the UMS protocol allows more than one RMB-element per RMB,
 * the Linux implementation uses just one RMB-element per RMB, i.e. uses an
 * extra RMB for every connection in a link group
 */
int ums_buf_create(struct ums_sock *ums)
{
	int rc;

	/* create send buffer */
	rc = ums_buf_create_inner(ums, false);
	if (rc != 0)
		return rc;
	/* create rmb */
	rc = ums_buf_create_inner(ums, true);
	if (rc != 0) {
		mutex_lock(&ums->conn.lgr->sndbufs_lock);
		list_del(&ums->conn.sndbuf_desc->list);
		mutex_unlock(&ums->conn.lgr->sndbufs_lock);
		ums_buf_free(ums->conn.lgr, false, ums->conn.sndbuf_desc);
		ums->conn.sndbuf_desc = NULL;
	}

	return rc;
}

int ums_buf_register(struct ums_sock *ums)
{
	struct ums_link *link = ums->conn.lnk;
	/* reg sendbufs if they were vzalloced */
	if (ums->conn.sndbuf_desc->is_vm != 0) {
		if (ums_lgr_reg_sndbufs(link, ums->conn.sndbuf_desc) != 0) {
			ums->conn.sndbuf_desc->reg_err = true;
			return UMS_CLC_DECL_ERR_REGBUF;
		}
	}
	if (ums_lgr_reg_rmbs(ums, ums->conn.rmb_desc) != 0) {
		(void)ubcore_unregister_seg(ums->conn.sndbuf_desc->seg[link->link_idx]);
		ums->conn.rmb_desc->reg_err = true;
		ums->conn.sndbuf_desc->seg[link->link_idx] = NULL;
		ums->conn.sndbuf_desc->is_reg_seg[link->link_idx] = false;
		return UMS_CLC_DECL_ERR_REGBUF;
	}
	return 0;
}

static inline int ums_rmb_reserve_rtoken_idx(struct ums_link_group *lgr)
{
	int i;

	for_each_clear_bit(i, lgr->rtokens_used_mask, UMS_RMBS_PER_LGR_MAX) {
		if (!test_and_set_bit(i, lgr->rtokens_used_mask))
			return i;
	}
	return -ENOSPC;
}

/* save rkey and dma_addr received from peer during clc handshake */
int ums_rmb_import_seg(struct ums_connection *conn, struct ums_clc_msg_accept_confirm *clc)
{
	struct ubcore_target_seg_cfg tseg_cfg;
	union ubcore_import_seg_flag flag = {
		.bs.cacheable = UBCORE_NON_CACHEABLE,
		.bs.access = RMB_ACCESS,
		.bs.mapping = UBCORE_SEG_NOMAP,
		.bs.reserved = 0
	};
	struct ums_link *lnk = conn->lnk;

	tseg_cfg.flag = flag;
	tseg_cfg.seg.len = (uint64_t)conn->peer_rmbe_size;
	tseg_cfg.seg.attr.value = ntohl(clc->r0.seg_flag);
	tseg_cfg.seg.token_id = ntohl(clc->r0.seg_token_id);
	tseg_cfg.token_value.token = ntohl(clc->r0.seg_token_value);
	tseg_cfg.seg.ubva.va = be64_to_cpu(clc->r0.rmb_dma_addr);
	(void)memcpy(tseg_cfg.seg.ubva.eid.raw, clc->r0.lcl.eid.raw, UMS_EID_SIZE);
	tseg_cfg.mva = 0;
	conn->tseg = ubcore_import_seg(conn->lnk->ums_dev->ub_dev, &tseg_cfg, NULL);
	if (IS_ERR_OR_NULL(conn->tseg)) {
		UMS_LOGE("failed to import peer tseg");
		return -1;
	}

	/* for the WRITE+WRITE_WITH_IMM case */
	conn->rtoken_idx = ums_rmb_reserve_rtoken_idx(conn->lgr);
	if (conn->rtoken_idx < 0) {
		UMS_LOGE("failed to find a usable index");
		return conn->rtoken_idx;
	}
	conn->wr_write_buf = &lnk->wr_tx_ubcore[((u32)conn->rtoken_idx) + lnk->wr_tx_cnt];
	return 0;
}

void ums_rmb_unimport_seg(struct ums_connection *conn)
{
	struct ums_link_group *lgr = conn->lgr;
	(void)ubcore_unimport_seg(conn->tseg);
	conn->tseg = NULL;
	clear_bit(conn->rtoken_idx, lgr->rtokens_used_mask);
}

/* delete an rtoken from all links */
int ums_rtoken_delete(struct ums_link *lnk, __be32 nw_rkey)
{
	struct ums_link_group *lgr = ums_get_lgr(lnk);
	u32 rkey = ntohl(nw_rkey);
	int i, j;

	for (i = 0; i < UMS_RMBS_PER_LGR_MAX; i++) {
		if (lgr->rtokens[i][lnk->link_idx].rkey == rkey &&
		    test_bit(i, lgr->rtokens_used_mask)) {
			for (j = 0; j < UMS_LINKS_PER_LGR_MAX; j++) {
				lgr->rtokens[i][j].rkey = 0;
				lgr->rtokens[i][j].dma_addr = 0;
			}
			clear_bit(i, lgr->rtokens_used_mask);
			return 0;
		}
	}
	return -ENOENT;
}

static void ums_core_going_away(void)
{
	struct ums_ubcore_device *ums_dev;

	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_for_each_entry(ums_dev, &g_ums_ubcore_devices.list, list) {
		int i;

		for (i = 0; i < UMS_MAX_PORTS; i++)
			set_bit(i, ums_dev->ports_going_away);
	}
	mutex_unlock(&g_ums_ubcore_devices.mutex);
}

/* Clean up all UMS link groups */
static void ums_lgrs_shutdown(void)
{
	ums_core_going_away();

	ums_terminate_all(NULL);
}

static int ums_core_reboot_event(struct notifier_block *this,
	unsigned long event, void *ptr)
{
	ums_lgrs_shutdown();
	ums_ubcore_unregister_client();
	return 0;
}

static struct notifier_block g_ums_reboot_notifier = {
	.notifier_call = ums_core_reboot_event,
};

int __init ums_core_init(void)
{
	return register_reboot_notifier(&g_ums_reboot_notifier);
}

/* Called (from ums_exit) when module is removed */
void ums_core_exit(void)
{
	(void)unregister_reboot_notifier(&g_ums_reboot_notifier);
	ums_lgrs_shutdown();
}

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_conn_create);
#endif
