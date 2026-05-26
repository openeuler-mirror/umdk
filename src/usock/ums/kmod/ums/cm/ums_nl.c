// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description: UMS Generic Netlink interface for kernel-agent communication
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * UMS implementation:
 *     Author: Hu Ying
 */

#include <linux/hashtable.h>
#include <linux/inet.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/string.h>

#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "ums_log.h"
#include "ums_mod.h"
#include "ums_ubcore.h"
#include "ums_nl.h"

#define UMS_NL_CLC_HASH_BITS 8

struct ums_process_entry {
	u32 portid;
	kuid_t uid;
	kgid_t gid;
	atomic_t available;
};

struct ums_nl_state {
	struct ums_process_entry agent;
	DECLARE_HASHTABLE(clc_ht, UMS_NL_CLC_HASH_BITS);
	spinlock_t clc_lock;
	/*
	 * Serializes agent state modifications (READY/DOWN/notify) to prevent
	 * TOCTOU races between concurrent genl doit callbacks. Generic netlink
	 * does not serialize doit callbacks internally. All usage paths
	 * (doit callbacks and netlink_notify) run in process context,
	 * so mutex is safe.
	 */
	struct mutex agent_mutex;
};

struct ums_nl_clc_entry {
	u32 clc_session_id;
	u8 initiator_id[UMS_SYSTEMID_LEN];
	struct ums_connection *conn;
	struct hlist_node hnode;
};

struct ums_nl_token_params {
	const struct ubcore_token *jetty_token;
	const struct ubcore_token *seg_token;
	bool first_contact;
	u32 clc_session_id;
	const u8 *initiator_id;
	struct ums_ip_addr dst_addr;
};

static struct ums_nl_state g_ums_nl_state = {
	.agent = {
		.portid = 0,
		.uid = INVALID_UID,
		.gid = INVALID_GID,
		.available = ATOMIC_INIT(0),
	},
};

/*
 * Decrement conn->nl_refcnt; wake up ums_conn_free if this is the last
 * reference. Must be called after spin_unlock(&clc_lock) to avoid calling
 * wake_up inside the spinlock critical section.
 *
 * nl_refcnt ownership model (value is always 0 or 1):
 *   nl_refcnt=1 means exactly one holder owns the reference:
 *     - Holder A: the clc_ht hash table entry (entry still in hash table)
 *     - Holder B: a netlink callback (entry already claimed, callback in progress)
 *   ums_nl_claim_conn transfers ownership from A to B without changing the count.
 *   Each holder is responsible for calling ums_conn_nl_put when done.
 */
static __attribute__((unused)) void ums_conn_nl_put(struct ums_connection *conn)
{
	if (refcount_dec_and_test(&conn->nl_refcnt))
		wake_up(&conn->nl_free_wait);
}

static const struct nla_policy g_ums_nl_policy[__UMS_ATTR_MAX] = {
	[UMS_ATTR_ROLE]            = { .type = NLA_U32 },
	[UMS_ATTR_RESULT]          = { .type = NLA_U32 },
	[UMS_ATTR_INITIATOR_ID]    = { .type = NLA_BINARY, .len = UMS_SYSTEMID_LEN },
	[UMS_ATTR_CLC_SESSION_ID]  = { .type = NLA_U32 },
	[UMS_ATTR_DST_IP]          = { .type = NLA_U32 },
	[UMS_ATTR_DST_IP6]         = { .type = NLA_BINARY, .len = sizeof(struct in6_addr) },
	[UMS_ATTR_FIRST_CONTACT]   = { .type = NLA_U8 },
	[UMS_ATTR_JETTY_TOKEN]     = { .type = NLA_U32 },
	[UMS_ATTR_SEG_TOKEN]       = { .type = NLA_U32 },
};

static int ums_nl_verify_sender_uid(kuid_t sender_uid)
{
	unsigned int expected_uid = READ_ONCE(g_ums_sys_tuning_config.ums_agent_uid);
	if (expected_uid != UMS_AGENT_UID_UNSET)
		return uid_eq(sender_uid, make_kuid(&init_user_ns, expected_uid)) ? 0 : -EPERM;

	if (uid_valid(g_ums_nl_state.agent.uid))
		return uid_eq(sender_uid, g_ums_nl_state.agent.uid) ? 0 : -EPERM;

	return 0;
}

static int ums_nl_verify_sender_gid(kgid_t sender_gid)
{
	unsigned int expected_gid = READ_ONCE(g_ums_sys_tuning_config.ums_agent_gid);
	if (expected_gid != UMS_AGENT_GID_UNSET)
		return gid_eq(sender_gid, make_kgid(&init_user_ns, expected_gid)) ? 0 : -EPERM;

	if (gid_valid(g_ums_nl_state.agent.gid))
		return gid_eq(sender_gid, g_ums_nl_state.agent.gid) ? 0 : -EPERM;

	return 0;
}

static __attribute__((unused)) int ums_nl_check_agent_portid(struct genl_info *info)
{
	if (!info || !info->snd_portid)
		return -EINVAL;

	if (!atomic_read(&g_ums_nl_state.agent.available))
		return -ENOTCONN;

	if (info->snd_portid != g_ums_nl_state.agent.portid) {
		UMS_LOGW_LIMITED("portid mismatch: expected=%u, got=%u",
			g_ums_nl_state.agent.portid, info->snd_portid);
		return -EPERM;
	}

	return 0;
}

static int ums_nl_ready(struct sk_buff *skb, struct genl_info *info)
{
	kuid_t sender_uid;
	kgid_t sender_gid;
	u32 role;

	if (!info || !info->attrs)
		return -EINVAL;

	if (!info->attrs[UMS_ATTR_ROLE])
		return -EINVAL;

	role = nla_get_u32(info->attrs[UMS_ATTR_ROLE]);
	if (role != UMS_ROLE_AGENT) {
		UMS_LOGW_LIMITED("unknown role=%u in READY", role);
		return -EINVAL;
	}

	mutex_lock(&g_ums_nl_state.agent_mutex);

	if (atomic_read(&g_ums_nl_state.agent.available)) {
		UMS_LOGW_LIMITED("READY rejected: agent already registered (portid=%u)",
			g_ums_nl_state.agent.portid);
		mutex_unlock(&g_ums_nl_state.agent_mutex);
		return -EBUSY;
	}

	sender_uid = NETLINK_CB(skb).creds.uid;
	sender_gid = NETLINK_CB(skb).creds.gid;

	if (ums_nl_verify_sender_uid(sender_uid) != 0) {
		UMS_LOGW_LIMITED("READY rejected: uid mismatch, sender=%u, expected=%u, learned=%u",
			from_kuid(&init_user_ns, sender_uid),
			READ_ONCE(g_ums_sys_tuning_config.ums_agent_uid),
			from_kuid(&init_user_ns, g_ums_nl_state.agent.uid));
		mutex_unlock(&g_ums_nl_state.agent_mutex);
		return -EPERM;
	}

	if (ums_nl_verify_sender_gid(sender_gid) != 0) {
		UMS_LOGW_LIMITED("READY rejected: gid mismatch, sender=%u, expected=%u, learned=%u",
			from_kgid(&init_user_ns, sender_gid),
			READ_ONCE(g_ums_sys_tuning_config.ums_agent_gid),
			from_kgid(&init_user_ns, g_ums_nl_state.agent.gid));
		mutex_unlock(&g_ums_nl_state.agent_mutex);
		return -EPERM;
	}

	g_ums_nl_state.agent.portid = info->snd_portid;
	g_ums_nl_state.agent.uid = sender_uid;
	g_ums_nl_state.agent.gid = sender_gid;

	if (g_ums_sys_tuning_config.ub_token_mode == UMS_TOKEN_MODE_SECURE) {
		atomic_set(&g_ums_nl_state.agent.available, 1);
		UMS_LOGI_LIMITED("ums_agent ready (portid=%u, uid=%u, gid=%u)",
			info->snd_portid,
			from_kuid(&init_user_ns, sender_uid),
			from_kgid(&init_user_ns, sender_gid));
	} else {
		UMS_LOGI_LIMITED("ums_agent ready but not required (ub_token_mode=%u)",
			g_ums_sys_tuning_config.ub_token_mode);
	}

	mutex_unlock(&g_ums_nl_state.agent_mutex);
	return 0;
}

static int ums_nl_down(struct sk_buff *skb, struct genl_info *info)
{
	u32 role;

	if (!info || !info->attrs)
		return -EINVAL;

	if (!info->attrs[UMS_ATTR_ROLE])
		return -EINVAL;

	role = nla_get_u32(info->attrs[UMS_ATTR_ROLE]);
	if (role != UMS_ROLE_AGENT) {
		UMS_LOGW_LIMITED("unknown role=%u in DOWN", role);
		return -EINVAL;
	}

	mutex_lock(&g_ums_nl_state.agent_mutex);

	if (info->snd_portid != g_ums_nl_state.agent.portid) {
		UMS_LOGW_LIMITED("DOWN rejected: portid mismatch, expected=%u, got=%u",
			g_ums_nl_state.agent.portid, info->snd_portid);
		mutex_unlock(&g_ums_nl_state.agent_mutex);
		return -EPERM;
	}

	atomic_set(&g_ums_nl_state.agent.available, 0);
	g_ums_nl_state.agent.portid = 0;

	if (g_ums_sys_tuning_config.ub_token_mode == UMS_TOKEN_MODE_SECURE)
		UMS_LOGW_LIMITED("ums_agent going down (uid=%u, gid=%u)",
			from_kuid(&init_user_ns, g_ums_nl_state.agent.uid),
			from_kgid(&init_user_ns, g_ums_nl_state.agent.gid));
	else
		UMS_LOGI_LIMITED("ums_agent going down (not required in ub_token_mode=%u)",
			g_ums_sys_tuning_config.ub_token_mode);

	g_ums_nl_state.agent.uid = INVALID_UID;
	g_ums_nl_state.agent.gid = INVALID_GID;

	mutex_unlock(&g_ums_nl_state.agent_mutex);
	return 0;
}

static u32 ums_nl_session_hash(u32 clc_session_id, const u8 *initiator_id)
{
	return hash_min(jhash(initiator_id, UMS_SYSTEMID_LEN, clc_session_id),
		UMS_NL_CLC_HASH_BITS);
}

static __attribute__((unused)) struct ums_nl_clc_entry *ums_nl_find_clc_entry(u32 clc_session_id,
	const u8 *initiator_id)
{
	struct ums_nl_clc_entry *entry;
	u32 hash = ums_nl_session_hash(clc_session_id, initiator_id);

	hash_for_each_possible(g_ums_nl_state.clc_ht, entry, hnode, hash) {
		if (entry->clc_session_id == clc_session_id &&
			memcmp(entry->initiator_id, initiator_id, UMS_SYSTEMID_LEN) == 0)
			return entry;
	}
	return NULL;
}

static const struct genl_ops ums_nl_ops[] = {
	{
		.cmd = UMS_CMD_READY,
		.doit = ums_nl_ready,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UMS_CMD_DOWN,
		.doit = ums_nl_down,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family g_ums_nl_family __ro_after_init = {
	.hdrsize = 0,
	.name = UMS_GENL_NAME,
	.version = UMS_GENL_VERSION,
	.maxattr = UMS_ATTR_MAX,
	.policy = g_ums_nl_policy,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = ums_nl_ops,
	.n_ops = ARRAY_SIZE(ums_nl_ops),
};

bool ums_nl_agent_available(void)
{
	return atomic_read(&g_ums_nl_state.agent.available) != 0;
}

int __init ums_nl_init(void)
{
	int rc;

	hash_init(g_ums_nl_state.clc_ht);
	spin_lock_init(&g_ums_nl_state.clc_lock);
	mutex_init(&g_ums_nl_state.agent_mutex);

	rc = genl_register_family(&g_ums_nl_family);
	if (rc != 0) {
		UMS_LOGE("genl_register_family failed, rc=%d", rc);
		return rc;
	}

	UMS_LOGI("UMS_GENL netlink family registered");
	return 0;
}

void ums_nl_exit(void)
{
	int rc;

	rc = genl_unregister_family(&g_ums_nl_family);
	if (rc != 0)
		UMS_LOGE("genl_unregister_family failed, rc=%d", rc);

	atomic_set(&g_ums_nl_state.agent.available, 0);
	g_ums_nl_state.agent.portid = 0;
	g_ums_nl_state.agent.uid = INVALID_UID;
	g_ums_nl_state.agent.gid = INVALID_GID;
}
