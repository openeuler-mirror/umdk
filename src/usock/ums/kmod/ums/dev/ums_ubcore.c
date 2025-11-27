// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:implement the invocation of ubcore interface
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#include <linux/inetdevice.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/if_vlan.h>

#include <ub/urma/ubcore_types.h>

#ifndef KERNEL_VERSION_4
#include "ums_dim.h"
#endif
#include "ums_log.h"
#include "ums_mod.h"
#include "ums_pnet.h"
#include "ums_wr.h"
#include "ums_ubcore.h"

#define UMS_MAX_CQE 32766 /* max. # of completion queue elements for UB */

#define UMS_MIN_RNR_TIMER 7 /* rnr retry gap time 2^(UMS_MIN_RNR_TIMER + 1) */
#define UMS_ERR_TIMEOUT 15 /* 4096 * 2 ** timeout usec */
#define UMS_RNR_RETRY 6    /* 7: infinite */
#define UMS_SYSTEM_ID_INEDX 2
#define UMS_DEFAULT_CACHE_LINE_SIZE 128
#define UMS_CQE_ORDER_6 6
#define UMS_CQE_ORDER_7 7
#define UMS_CQE_NUM 2
#define UMS_JFS_DEPTH (UMS_WR_BUF_CNT * 3)
#define UMS_JFC_NUM 1

struct ums_ubcore_devices g_ums_ubcore_devices = {
	/* ums-registered ub devices */
	.mutex = __MUTEX_INITIALIZER(g_ums_ubcore_devices.mutex),
	.list = LIST_HEAD_INIT(g_ums_ubcore_devices.list),
};

u8 g_local_systemid[UMS_SYSTEMID_LEN]; /* unique system identifier */

/* check if eid is still defined on ums_ub_dev */
static bool ums_ubcore_check_link_eid(union ubcore_eid *eid,
	struct ums_ubcore_device *ums_ub_dev)
{
	u32 i;

	for (i = 0; i < ums_ub_dev->ub_dev->eid_table.eid_cnt; i++) {
		if (memcmp(eid->raw, ums_ub_dev->ub_dev->eid_table.eid_entries[i].eid.raw, UMS_EID_SIZE) == 0)
			return true;
	}

	return false;
}

static inline bool ums_ubcore_ipv4_addr_equal_eid(struct in_addr *addr, const union ubcore_eid *eid)
{
	return ((eid->in4.addr == addr->s_addr) &&
		(eid->in4.reserved == 0) &&
		(eid->in4.prefix == htonl(UBCORE_IPV4_MAP_IPV6_PREFIX)));
}

static inline bool ums_ubcore_ipv6_addr_equal_eid(struct in6_addr *addr, union ubcore_eid *eid)
{
	return memcmp(addr->s6_addr, eid->raw, UMS_EID_SIZE) == 0;
}

static inline bool ums_ubcore_sk_rcv_saddr_equal_eid(struct sock *sk, union ubcore_eid *eid)
{
	if (sk->sk_family == AF_INET) {
		return ums_ubcore_ipv4_addr_equal_eid((struct in_addr *)(&sk->sk_rcv_saddr), eid);
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6) {
		return ums_ubcore_ipv6_addr_equal_eid(&sk->sk_v6_rcv_saddr, eid);
	}
#endif

	return false;
}

/* check if the first eid_entry is non-zero */
bool ums_eid_valid(const struct ubcore_device *ub_dev, u32 eid_idx)
{
	u32 i;

	for (i = 0; i < UMS_EID_SIZE; i++) {
		if (ub_dev->eid_table.eid_entries[eid_idx].eid.raw[i] != 0) {
			return true;
		}
	}

	return false;
}

int ums_ubcore_determine_eid(struct ums_ubcore_determine_eid_param *param)
{
	const struct net_device *ndev = param->ums_ub_dev->ub_dev->netdev;
	u32 i;

	if (IS_ERR_OR_NULL(ndev))
		return -ENODEV;

	if (param->vlan_id == 0) {
		if (is_vlan_dev(ndev))
			return -EINVAL;
	}

	if (IS_ERR_OR_NULL(param->eid) || IS_ERR_OR_NULL(param->eid_index))
		return -EINVAL;

	/* Try to locate the EID via IP address. */
	for (i = 0; i < param->ums_ub_dev->ub_dev->eid_table.eid_cnt; i++) {
		if (ums_ubcore_sk_rcv_saddr_equal_eid(param->sk,
		    &param->ums_ub_dev->ub_dev->eid_table.eid_entries[i].eid)) {
			*param->eid_index = i;
			(void)memcpy(param->eid->raw, param->ums_ub_dev->ub_dev->eid_table.eid_entries[i].eid.raw, UMS_EID_SIZE);
			return 0;
		}
	}

	/* On physical or virtual machines, the EID and IP may not have a mapping
	 * relationship and cannot be converted. If the EID cannot be found via the IP address. Traverse the ubcore
	 * device eid table and use the first valid eid with the same net namespace.
	 */
	for (i = 0; i < param->ums_ub_dev->ub_dev->eid_table.eid_cnt; i++) {
		if ((param->net == param->ums_ub_dev->ub_dev->eid_table.eid_entries[i].net) &&
			ums_eid_valid(param->ums_ub_dev->ub_dev, i)) {
			*param->eid_index = i;
			(void)memcpy(param->eid->raw, param->ums_ub_dev->ub_dev->eid_table.eid_entries[i].eid.raw, UMS_EID_SIZE);
			UMS_LOGW_LIMITED("Unable to locate the EID via IP address. Traverse the ubcore "
				"device eid table and use the first valid eid with the same net namespace, "
				"dev_name: %s, eid_index: %d, eid: %pI6c",
				param->ums_ub_dev->ub_dev->dev_name, i, param->eid->raw);
			return 0;
		}
	}

	return -ENODEV;
}

/* Create an identifier unique for this instance of UMS.
 * The MAC-address of the first active registered UB device
 * plus a random 2-byte number is used to create this identifier.
 * This name is delivered to the peer during connection initialization.
 */
static inline void ums_ubcore_define_local_systemid(struct ums_ubcore_device *ums_ub_dev, u8 port)
{
	if (UMS_SYSTEMID_LEN - UMS_SYSTEM_ID_INEDX < ETH_ALEN) {
		UMS_LOGE("memcpy err: mac length of ub dev is out of range");
		return;
	}
	(void)memcpy(&g_local_systemid[UMS_SYSTEM_ID_INEDX], ums_ub_dev->mac[port], ETH_ALEN);
}

bool ums_ubcore_is_valid_local_systemid(void)
{
	return !is_zero_ether_addr(&g_local_systemid[UMS_SYSTEM_ID_INEDX]);
}

static void ums_ubcore_init_local_systemid(void)
{
	get_random_bytes(&g_local_systemid[0], UMS_SYSTEM_ID_INEDX);
}

bool ums_ubcore_port_active(const struct ums_ubcore_device *ums_ub_dev, u8 port)
{
	return ums_ub_dev->pattr[port].state == UBCORE_PORT_ACTIVE;
}

void ums_ubcore_ndev_change(struct net_device *ndev, unsigned long event)
{
	struct ums_ubcore_device *umsubdev;
	struct net_device *lndev;
	u8 port_cnt;
	int i;

	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_for_each_entry (umsubdev, &g_ums_ubcore_devices.list, list) {
		port_cnt = umsubdev->ub_dev->attr.port_cnt;
		for (i = 0; i < min_t(int, port_cnt, UMS_MAX_PORTS); i++) {
			lndev = umsubdev->ub_dev->netdev;
			if (lndev != ndev)
				continue;
			if (event == NETDEV_REGISTER)
				umsubdev->ndev_ifidx[i] = ndev->ifindex;
			if (event == NETDEV_UNREGISTER)
				umsubdev->ndev_ifidx[i] = 0;
		}
	}
	mutex_unlock(&g_ums_ubcore_devices.mutex);
}

/* check all links if the eid is still defined on ums_ub_dev */
static void ums_ubcore_eid_check(struct ums_ubcore_device *ums_ub_dev, u8 port)
{
	struct ums_link_group *lgr;
	int i;

	spin_lock_bh(&g_ums_lgr_list.lock);
	list_for_each_entry (lgr, &g_ums_lgr_list.list, list) {
		if (strncmp(ums_ub_dev->pnetid[port], lgr->pnet_id, UMS_MAX_PNETID_LEN) != 0)
			continue; /* lgr is not affected */
		if (list_empty(&lgr->list) != 0)
			continue;
		for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++) {
			if (lgr->lnk[i].state == UMS_LNK_UNUSED || lgr->lnk[i].ums_dev != ums_ub_dev)
				continue;
			if (!ums_ubcore_check_link_eid(&lgr->lnk[i].eid, ums_ub_dev))
				ums_port_err(ums_ub_dev, port);
		}
	}
	spin_unlock_bh(&g_ums_lgr_list.lock);
}

static void ums_ubcore_remember_port_attr(struct ums_ubcore_device *ums_ub_dev,
	struct ubcore_device_status *status, u8 port)
{
	/* ub device stores some information */
	(void)memset(&ums_ub_dev->pattr[port], 0, sizeof(struct ums_ubcore_port_attr));
	ums_ub_dev->pattr[port].state = status->port_status[port].state;
	ums_ub_dev->pattr[port].active_mtu = status->port_status[port].active_mtu;

	if (!ums_ub_dev->ub_dev->netdev)
		return;
	/* the UMS protocol requires specification of the UB MAC address */
	(void)memcpy(ums_ub_dev->mac[port], ums_ub_dev->ub_dev->netdev->dev_addr, ETH_ALEN);
	if (!ums_ubcore_is_valid_local_systemid() && ums_ubcore_port_active(ums_ub_dev, port))
		/* create unique system identifier */
		ums_ubcore_define_local_systemid(ums_ub_dev, port);
}

/* process context wrapper for might_sleep ums_ubcore_remember_port_attr */
static void ums_ubcore_port_event_work(struct work_struct *work)
{
	struct ums_ubcore_device *ums_ub_dev = container_of(work, struct ums_ubcore_device,
		port_event_work);
	u8 port_idx;
	struct ubcore_device_status status;
	int rc = 0;

	rc = ubcore_query_device_status(ums_ub_dev->ub_dev, &status);
	if (rc != 0)
		return;

	for_each_set_bit (port_idx, &ums_ub_dev->port_event_mask, UMS_MAX_PORTS) {
		(void)ums_ubcore_remember_port_attr(ums_ub_dev, &status, port_idx);
		clear_bit(port_idx, &ums_ub_dev->port_event_mask);
		if (!ums_ubcore_port_active(ums_ub_dev, port_idx)) {
			set_bit(port_idx, ums_ub_dev->ports_going_away);
			ums_port_err(ums_ub_dev, port_idx);
		} else {
			clear_bit(port_idx, ums_ub_dev->ports_going_away);
			ums_port_add(ums_ub_dev, port_idx);
			ums_ubcore_eid_check(ums_ub_dev, port_idx);
		}
	}
}

static int ums_ubcore_import_jetty(struct ums_link *lnk)
{
	lnk->ub_tjetty = ubcore_import_jetty(lnk->ums_dev->ub_dev, &lnk->ub_tjetty_cfg, NULL);
	if (IS_ERR_OR_NULL(lnk->ub_tjetty)) {
		lnk->ub_tjetty = NULL;
		UMS_LOGE("failed to importing jetty");
		return -1;
	}

	return 0;
}

static int ums_ubcore_bind_jetty(struct ums_link *lnk)
{
	int ret = 0;
	ret = ubcore_bind_jetty(lnk->ub_jetty, lnk->ub_tjetty, NULL);
	if (ret != 0) {
		UMS_LOGE("failed to bind local jetty[eid:%pI6c, id:%u] with remote jetty[eid:%pI6c, id:%u]",
			&lnk->ub_jetty->jetty_id.eid, lnk->ub_jetty->jetty_id.id, &lnk->peer_eid, lnk->tjetty_id);
		return ret;
	}
	UMS_LOGI_LIMITED("succeed to bind local jetty[eid:%pI6c, id:%u] with remote "
		"jetty[eid:%pI6c, id:%u]", &lnk->ub_jetty->jetty_id.eid, lnk->ub_jetty->jetty_id.id,
		&lnk->peer_eid, lnk->tjetty_id);

	return ret;
}

int ums_ubcore_ready_link(struct ums_link *lnk)
{
	int rc = 0;

	rc = ums_ubcore_import_jetty(lnk);
	if (rc != 0)
		goto out;

	rc = ums_ubcore_bind_jetty(lnk);
	if (rc != 0)
		goto out;

	rc = ums_wr_rx_post_init(lnk);
	if (rc != 0)
		goto out;
out:
	return rc;
}

/* can be called in IRQ context */
static void ums_ubcore_global_event_handler(struct ubcore_event *ubevent,
	struct ubcore_event_handler *handler)
{
	struct ums_ubcore_device *ums_ub_dev =
		container_of(handler, struct ums_ubcore_device, event_handler);
	bool schedule = false;
	u8 port_idx;

	switch (ubevent->event_type) {
	case UBCORE_EVENT_DEV_FATAL:
		/* terminate all ports on device */
		for (port_idx = 0; port_idx < UMS_MAX_PORTS; port_idx++) {
			set_bit(port_idx, &ums_ub_dev->port_event_mask);
			if (!test_and_set_bit(port_idx, ums_ub_dev->ports_going_away))
				schedule = true;
		}
		break;
	case UBCORE_EVENT_PORT_ACTIVE:
	case UBCORE_EVENT_PORT_DOWN:
	case UBCORE_EVENT_EID_CHANGE:
		port_idx = (u8)ubevent->element.port_id;
		if (port_idx >= UMS_MAX_PORTS)
			break;
		set_bit(port_idx, &ums_ub_dev->port_event_mask);
		break;
	default:
		return;
	}

	if ((ubevent->event_type == UBCORE_EVENT_DEV_FATAL && schedule) ||
		(ubevent->event_type == UBCORE_EVENT_PORT_ACTIVE &&
			test_and_clear_bit(port_idx, ums_ub_dev->ports_going_away)) ||
		(ubevent->event_type == UBCORE_EVENT_PORT_DOWN &&
			!test_and_set_bit(port_idx, ums_ub_dev->ports_going_away)) ||
		ubevent->event_type == UBCORE_EVENT_EID_CHANGE)
		(void)schedule_work(&ums_ub_dev->port_event_work);
}

static struct ums_ubcore_jfc *ums_ubcore_get_least_used_jfc(struct ums_ubcore_device *ums_ub_dev)
{
	struct ums_ubcore_jfc *ums_ub_jfc, *jfc;
	int min, i;

	ums_ub_jfc = ums_ub_dev->ums_ub_jfc;
	jfc = ums_ub_jfc;
	min = atomic_read(&jfc->load);

	for (i = 0; i < ums_ub_dev->num_jfc; i++) {
		if (atomic_read(&ums_ub_jfc[i].load) < min) {
			jfc = &ums_ub_jfc[i];
			min = atomic_read(&jfc->load);
		}
	}
	atomic_inc(&jfc->load);
	return jfc;
}

static void ums_ubcore_put_jfc(struct ums_ubcore_jfc *ums_ub_jfc)
{
	atomic_dec(&ums_ub_jfc->load);
}

/* Unregister connection and reset the alert token of the given connection */
static void ums_remove_jetty2link(struct ums_link *lnk)
{
	write_lock_bh(&lnk->ums_dev->jetty2link_htable_lock);
	hash_del(&lnk->hnode);
	write_unlock_bh(&lnk->ums_dev->jetty2link_htable_lock);
}

void ums_destroy_jetty_and_jfr(struct ums_link *lnk)
{
	struct ubcore_device *ub_dev = lnk->ums_dev->ub_dev;

	if (lnk->ub_jetty && ubcore_delete_jetty(lnk->ub_jetty) != 0)
		UMS_LOGE("delete jetty failed");

	if ((ub_dev->transport_type == UBCORE_TRANSPORT_UB) &&
		lnk->jfr && ubcore_delete_jfr(lnk->jfr) != 0)
		UMS_LOGE("delete jfr failed");
	
	lnk->ub_jetty = NULL;
	lnk->jfr = NULL;
}

void ums_ubcore_destroy_jetty(struct ums_link *lnk)
{
	/* from call hierarchy, lnk can't be null */
	ums_remove_jetty2link(lnk);
	if (lnk->ub_jetty->remote_jetty && ubcore_unbind_jetty(lnk->ub_jetty) != 0)
		UMS_LOGE("unbind jetty failed");
	if (lnk->ub_tjetty && ubcore_unimport_jetty(lnk->ub_tjetty) != 0)
		UMS_LOGE("unimport jetty failed");
	ums_destroy_jetty_and_jfr(lnk);
	ums_ubcore_put_jfc(lnk->ums_ub_jfc);
	lnk->ub_tjetty = NULL;
	lnk->ums_ub_jfc = NULL;
	(void)memset(&lnk->ub_tjetty_cfg, 0, sizeof(struct ubcore_tjetty_cfg));
}

/* Register <jetty_id, link*> in our lookup structure.
 * To use rbtrees we have to implement our own insert core.
 * @ums	link to register
 */
static void ums_add_jetty2link(struct ums_link *lnk)
{
	struct ums_ubcore_device *ums_dev = lnk->ums_dev;
	struct ums_link *lnk_iter;

	write_lock_bh(&ums_dev->jetty2link_htable_lock);
	hash_for_each_possible(ums_dev->jetty2link_htable, lnk_iter, hnode,
		lnk->ub_jetty->jetty_id.id) {
		if (lnk_iter->ub_jetty->jetty_id.id == lnk->ub_jetty->jetty_id.id) {
			write_unlock_bh(&ums_dev->jetty2link_htable_lock);
			UMS_LOGE("failed to add jetty2link, jetty[eid:%pI6c, id:%u] on device %s already "
				"exists, link_uid: %*phN",
				&lnk->ub_jetty->jetty_id.eid, lnk->ub_jetty->jetty_id.id,
				ums_dev->ub_dev->dev_name, UMS_LGR_ID_SIZE, lnk->link_uid);
			return;
		}
	}
	hash_add(ums_dev->jetty2link_htable, &lnk->hnode, lnk->ub_jetty->jetty_id.id);
	write_unlock_bh(&ums_dev->jetty2link_htable_lock);
}

static void ums_ubcore_create_jfr(struct ums_ubcore_jfc *ums_ub_jfc, struct ums_link *lnk)
{
	struct ubcore_jfr_cfg cfg = {0};

	cfg.id = 0;
	cfg.depth = UMS_WR_BUF_CNT;
	cfg.flag.bs.order_type = UBCORE_OL; /* low layer ordering */
	cfg.trans_mode = UBCORE_TP_RC;
	cfg.eid_index = lnk->eid_index;
	cfg.max_sge = 1;
	cfg.min_rnr_timer = UMS_TYPICAL_MIN_RNR_TIMER;
	if (g_ums_sys_tuning_config.ub_token_disable) {
		cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
		cfg.token_value.token = 0;
	} else {
		cfg.flag.bs.token_policy = UBCORE_TOKEN_PLAIN_TEXT;
		get_random_bytes(&lnk->jetty_token_value.token, sizeof(lnk->jetty_token_value.token));
		cfg.token_value.token = lnk->jetty_token_value.token;
	}
	cfg.jfc = ums_ub_jfc->jfc;

	lnk->jfr = ubcore_create_jfr(lnk->ums_dev->ub_dev, &cfg, NULL, NULL);
	if (IS_ERR(lnk->jfr))
		lnk->jfr = NULL;

	return;
}

/* create a queue pair within the protection domain for a link */
int ums_ubcore_create_jetty(struct ums_link *lnk)
{
	struct ums_ubcore_jfc *ums_ub_jfc = ums_ubcore_get_least_used_jfc(lnk->ums_dev);
	struct ubcore_jetty_cfg jetty_cfg = {
		.jfs_depth = UMS_JFS_DEPTH,
		.jfr_depth = UMS_WR_BUF_CNT,
		.send_jfc = ums_ub_jfc->jfc,
		.recv_jfc = ums_ub_jfc->jfc,
		.max_send_sge = UMS_UBCORE_MAX_SEND_SGE,
		.max_recv_sge = 1,
		.rnr_retry = UMS_RNR_RETRY,
		.err_timeout = UMS_ERR_TIMEOUT,
		.min_rnr_timer = UMS_MIN_RNR_TIMER,
		.trans_mode = UBCORE_TP_RC,
		.jetty_context = NULL,
		.max_inline_data = 0, /* to disable inline */
		.eid_index = lnk->eid_index,
		.id = 0, /* let ub driver assign a jetty id */
	};
	struct ubcore_device *ub_dev = lnk->ums_dev->ub_dev;
	int rc = 0;

	if (ub_dev->transport_type == UBCORE_TRANSPORT_UB) {
		ums_ubcore_create_jfr(ums_ub_jfc, lnk);
		if (IS_ERR_OR_NULL(lnk->jfr)) {
			UMS_LOGE("Create jfr failed");
			rc = (int)((lnk->jfr == NULL) ? -EIO : PTR_ERR(lnk->jfr));
			goto put_jfc;
		}
		jetty_cfg.flag.bs.share_jfr = 1;
		jetty_cfg.flag.bs.order_type = UBCORE_OL; /* low layer ordering */
		jetty_cfg.flag.bs.multi_path = 0;
		jetty_cfg.flag.bs.error_suspend = 1;
		jetty_cfg.jfr = lnk->jfr;
	}

	lnk->ub_jetty = ubcore_create_jetty(ub_dev, &jetty_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(lnk->ub_jetty)) {
		rc = (int)((lnk->ub_jetty == NULL) ? -EIO : PTR_ERR(lnk->ub_jetty));
		lnk->ub_jetty = NULL;
		goto destroy_jetty_and_jfr;
	}
	ums_add_jetty2link(lnk);
	UMS_LOGI_LIMITED("create jetty[eid:%pI6c, id:%u] on device %s, bounded to link %*phN,"
		" jfc %u", &lnk->ub_jetty->jetty_id.eid, lnk->ub_jetty->jetty_id.id, ub_dev->dev_name,
		UMS_LGR_ID_SIZE, lnk->link_uid, ums_ub_jfc->jfc->id);

	lnk->ums_ub_jfc = ums_ub_jfc;
	lnk->wr_tx_cnt = min_t(u32, UMS_WR_BUF_CNT, ub_dev->attr.dev_cap.max_jfs_depth);
	lnk->wr_rx_cnt = min_t(u32, UMS_WR_BUF_CNT, ub_dev->attr.dev_cap.max_jfr_depth);
	return 0;
destroy_jetty_and_jfr:
	ums_destroy_jetty_and_jfr(lnk);
put_jfc:
	ums_ubcore_put_jfc(ums_ub_jfc);
	return rc;
}

static void ums_ubcore_cleanup_jfc(struct ums_ubcore_device *ums_ub_dev)
{
	int i;

	for (i = 0; i < ums_ub_dev->num_jfc; i++) {
		if (ums_ub_dev->ums_ub_jfc[i].jfc) {
			/* To confirm: ubcore does not define dim? */
#ifndef KERNEL_VERSION_4
			ums_dim_destroy(&ums_ub_dev->ums_ub_jfc[i]);
#endif
			(void)ubcore_delete_jfc(ums_ub_dev->ums_ub_jfc[i].jfc);
		}
	}

	kfree(ums_ub_dev->ums_ub_jfc);
	ums_ub_dev->ums_ub_jfc = NULL;
}

long ums_ubcore_setup_per_ubdev(struct ums_ubcore_device *ums_ub_dev)
{
	struct ubcore_jfc_cfg jfc_cfg = { .depth = UMS_MAX_CQE };
	struct ums_ubcore_jfc *ums_ub_jfc;
	int jfc_size_order, ums_order;
	size_t num_jfc;
	uint32_t depth;
	long rc;
	u32 i;
	
	if (ums_ub_dev->ub_dev->transport_type == UBCORE_TRANSPORT_UB)
		jfc_cfg.depth = ums_ub_dev->ub_dev->attr.dev_cap.max_jfc_depth;

	mutex_lock(&ums_ub_dev->mutex);
	rc = 0;
	if (ums_ub_dev->initialized != 0)
		goto out;
	/* the calculated number of cq entries fits to mlx5 cq allocation */
	jfc_size_order = cache_line_size() == UMS_DEFAULT_CACHE_LINE_SIZE ?
		UMS_CQE_ORDER_7 : UMS_CQE_ORDER_6;
	ums_order = (MAX_ORDER - jfc_size_order) - 1;
	depth = (uint32_t)(((((u64)0x00000001) << ums_order) * PAGE_SIZE) - UMS_CQE_NUM);
	if (depth < jfc_cfg.depth)
		jfc_cfg.depth = depth;
	num_jfc = UMS_JFC_NUM;
	ums_ub_dev->num_jfc = (int)num_jfc;
	ums_ub_dev->ums_ub_jfc = kcalloc(num_jfc, sizeof(*ums_ub_jfc), GFP_KERNEL);
	if (!ums_ub_dev->ums_ub_jfc) {
		rc = -ENOMEM;
		goto err;
	}
	/* initialize CQs */
	for (i = 0; i < (u32)num_jfc; i++) {
		ums_ub_jfc = &ums_ub_dev->ums_ub_jfc[i];
		ums_ub_jfc->ums_ub_dev = ums_ub_dev;
		atomic_set(&ums_ub_jfc->load, 0);
		/* TO CHECK: How to bind jfc to a core */
		ums_ub_jfc->jfc = ubcore_create_jfc(ums_ub_dev->ub_dev, &jfc_cfg, ums_wr_jfc_handler, NULL,
			NULL);
		if (IS_ERR_OR_NULL(ums_ub_jfc->jfc)) {
			rc = (ums_ub_jfc->jfc == NULL) ? -EIO : PTR_ERR(ums_ub_jfc->jfc);
			ums_ub_jfc->jfc = NULL;
			goto err;
		}
#ifndef KERNEL_VERSION_4
		ums_dim_init(ums_ub_jfc);
#endif
		/* Not enable dim now */
		rc = ubcore_rearm_jfc(ums_ub_jfc->jfc, false);
		if (rc != 0)
			goto err;
	}
	ums_wr_add_dev(ums_ub_dev);
	ums_ub_dev->initialized = 1;
	UMS_LOGI_LIMITED("create %lu jfc, each depth is %u", num_jfc, jfc_cfg.depth);
	goto out;

err:
	ums_ubcore_cleanup_jfc(ums_ub_dev);
out:
	mutex_unlock(&ums_ub_dev->mutex);
	return rc;
}

static void ums_ubcore_cleanup_per_ubcoredev(struct ums_ubcore_device *ums_ub_dev)
{
	mutex_lock(&ums_ub_dev->mutex);
	if (ums_ub_dev->initialized == 0)
		goto out;
	ums_ub_dev->initialized = 0;
	ums_wr_remove_dev(ums_ub_dev);
	ums_ubcore_cleanup_jfc(ums_ub_dev);
out:
	mutex_unlock(&ums_ub_dev->mutex);
}

static struct ubcore_client g_ums_ubcore_client;

/* callback function for ubcore_register_client() */
static int ums_ubcore_add_dev(struct ubcore_device *ub_dev)
{
	struct ums_ubcore_device *ums_ub_dev;
	u8 port_cnt, i;

	if (ub_dev == NULL || ub_dev->transport_type != UBCORE_TRANSPORT_UB)
		return -ENODEV;

	ums_ub_dev = kzalloc(sizeof(*ums_ub_dev), GFP_KERNEL);
	if (!ums_ub_dev)
		return -ENOMEM;

	ums_ub_dev->ub_dev = ub_dev;
	INIT_WORK(&ums_ub_dev->port_event_work, ums_ubcore_port_event_work);
	atomic_set(&ums_ub_dev->lnk_cnt, 0);
	hash_init(ums_ub_dev->jetty2link_htable);
	rwlock_init(&ums_ub_dev->jetty2link_htable_lock);
	init_waitqueue_head(&ums_ub_dev->lnks_deleted);
	mutex_init(&ums_ub_dev->mutex);
	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_add_tail(&ums_ub_dev->list, &g_ums_ubcore_devices.list);
	mutex_unlock(&g_ums_ubcore_devices.mutex);
	ubcore_set_client_ctx_data(ub_dev, &g_ums_ubcore_client, ums_ub_dev);

	ums_ub_dev->event_handler.event_callback = ums_ubcore_global_event_handler;
	INIT_LIST_HEAD(&ums_ub_dev->event_handler.node);
	ubcore_register_event_handler(ub_dev, &ums_ub_dev->event_handler);

	/* trigger reading of the port attributes */
	port_cnt = ums_ub_dev->ub_dev->attr.port_cnt;
	UMS_LOGI_LIMITED("adding ubcore device %s with port count %d",
		ums_ub_dev->ub_dev->dev_name, port_cnt);
	for (i = 0; i < min_t(u8, port_cnt, UMS_MAX_PORTS); i++) {
		set_bit(i, &ums_ub_dev->port_event_mask);
		/* determine pnetids of the port */
		if (ums_pnetid_by_dev_port(ub_dev->dev.parent, (unsigned short)i, ums_ub_dev->pnetid[i]) != 0)
			(void)ums_pnetid_by_table_ub(ums_ub_dev, i + 1);

		if (ums_ub_dev->ub_dev->netdev)
			ums_ub_dev->ndev_ifidx[i] = ums_ub_dev->ub_dev->netdev->ifindex;
		UMS_LOGI_LIMITED("ub device %s port %d has pnetid %.16s%s",
			ums_ub_dev->ub_dev->dev_name, i + 1, ums_ub_dev->pnetid[i],
			ums_ub_dev->pnetid_by_user[i] ? " (user defined)" : "");
	}
	(void)schedule_work(&ums_ub_dev->port_event_work);
	return 0;
}

/* callback function for ubcore_unregister_client() */
static void ums_ubcore_remove_dev(struct ubcore_device *ub_dev, void *client_data)
{
	struct ums_ubcore_device *ums_ub_dev = client_data;

	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_del_init(&ums_ub_dev->list); /* remove from g_ums_ubcore_devices */
	mutex_unlock(&g_ums_ubcore_devices.mutex);
	UMS_LOGI_LIMITED("removing ubcore device %s", ums_ub_dev->ub_dev->dev_name);
	ums_terminate_all(ums_ub_dev);
	ums_ubcore_cleanup_per_ubcoredev(ums_ub_dev);
	ubcore_unregister_event_handler(ub_dev, &ums_ub_dev->event_handler);
	(void)cancel_work_sync(&ums_ub_dev->port_event_work);
	kfree(ums_ub_dev);
}

static struct ubcore_client g_ums_ubcore_client = {
	.list_node = LIST_HEAD_INIT(g_ums_ubcore_client.list_node),
	.client_name = "ums_ubcore",
	.add = ums_ubcore_add_dev,
	.remove = ums_ubcore_remove_dev,
};

int __init ums_ubcore_register_client(void)
{
	int ret;

	ums_ubcore_init_local_systemid();
	ret = ubcore_register_client(&g_ums_ubcore_client);
	if (ret)
		UMS_LOGW_LIMITED("register global ubcore client failed, ret = %d", ret);
	return ret;
}

void ums_ubcore_unregister_client(void)
{
	ubcore_unregister_client(&g_ums_ubcore_client);
}

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_ubcore_create_jetty);
#endif
