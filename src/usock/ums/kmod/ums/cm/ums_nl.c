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
#define UMS_IPV6_ADDR_LEN    sizeof(struct in6_addr)

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
	struct ums_token_xchg_ctx *token_ctx;
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
 * Decrement token_ctx->nl_refcnt; wake up ums_conn_free if this is the last
 * reference. Must be called after spin_unlock(&clc_lock) to avoid calling
 * wake_up inside the spinlock critical section.
 *
 * nl_refcnt ownership model (value is always 0 or 1):
 *   nl_refcnt=1 means exactly one holder owns the reference:
 *     - Holder A: the clc_ht hash table entry (entry still in hash table)
 *     - Holder B: a netlink callback (entry already claimed, callback in progress)
 *   ums_nl_claim_token_ctx transfers ownership from A to B without changing the count.
 *   Each holder is responsible for calling ums_token_ctx_nl_put when done.
 */
static void ums_token_ctx_nl_put(struct ums_token_xchg_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->nl_refcnt))
		wake_up(&ctx->nl_free_wait);
}

static const struct nla_policy g_ums_nl_policy[__UMS_ATTR_MAX] = {
	[UMS_ATTR_ROLE]            = { .type = NLA_U32 },
	[UMS_ATTR_RESULT]          = { .type = NLA_U32 },
	[UMS_ATTR_INITIATOR_ID]    = { .type = NLA_BINARY, .len = UMS_SYSTEMID_LEN },
	[UMS_ATTR_CLC_SESSION_ID]  = { .type = NLA_U32 },
	[UMS_ATTR_DST_IP]          = { .type = NLA_U32 },
	[UMS_ATTR_DST_IP6]         = { .type = NLA_BINARY, .len = UMS_IPV6_ADDR_LEN },
	[UMS_ATTR_FIRST_CONTACT]   = { .type = NLA_U8 },
	[UMS_ATTR_JETTY_TOKEN]     = { .type = NLA_U32 },
	[UMS_ATTR_SEG_TOKEN]       = { .type = NLA_U32 },
};

static int ums_nl_verify_sender_uid(kuid_t sender_uid)
{
	unsigned int expected_uid = READ_ONCE(g_ums_sys_tuning_config.ums_agent_uid);

	return uid_eq(sender_uid, make_kuid(&init_user_ns, expected_uid)) ? 0 : -EPERM;
}

static int ums_nl_verify_sender_gid(kgid_t sender_gid)
{
	unsigned int expected_gid = READ_ONCE(g_ums_sys_tuning_config.ums_agent_gid);

	return gid_eq(sender_gid, make_kgid(&init_user_ns, expected_gid)) ? 0 : -EPERM;
}

static int ums_nl_check_agent_portid(struct genl_info *info)
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
		UMS_LOGW_LIMITED("READY rejected: uid mismatch, sender=%u, expected=%u",
			from_kuid(&init_user_ns, sender_uid),
			READ_ONCE(g_ums_sys_tuning_config.ums_agent_uid));
		mutex_unlock(&g_ums_nl_state.agent_mutex);
		return -EPERM;
	}

	if (ums_nl_verify_sender_gid(sender_gid) != 0) {
		UMS_LOGW_LIMITED("READY rejected: gid mismatch, sender=%u, expected=%u",
			from_kgid(&init_user_ns, sender_gid),
			READ_ONCE(g_ums_sys_tuning_config.ums_agent_gid));
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

static struct ums_nl_clc_entry *ums_nl_find_clc_entry(u32 clc_session_id,
	const u8 *initiator_id)
{
	struct ums_nl_clc_entry *entry;
	u32 hash = ums_nl_session_hash(clc_session_id, initiator_id);

	hash_for_each_possible(g_ums_nl_state.clc_ht, entry, hnode, hash) {
		if (entry->token_ctx->clc_session_id == clc_session_id &&
			memcmp(entry->token_ctx->initiator_id, initiator_id, UMS_SYSTEMID_LEN) == 0)
			return entry;
	}
	return NULL;
}

/*
 * Atomically remove a clc entry from the hash table and return its token_ctx.
 * This transfers nl_refcnt ownership from holder A (hash table entry) to
 * holder B (the calling netlink callback) without incrementing nl_refcnt.
 * The caller becomes the new owner and must call ums_token_ctx_nl_put when done.
 * Returns NULL if the entry was already removed (e.g., by unregister or a
 * prior claim), which also prevents duplicate callbacks on the same session.
 */
static struct ums_token_xchg_ctx *ums_nl_claim_token_ctx(u32 clc_session_id,
	const u8 *initiator_id)
{
	struct ums_token_xchg_ctx *token_ctx;
	struct ums_nl_clc_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&g_ums_nl_state.clc_lock, flags);
	entry = ums_nl_find_clc_entry(clc_session_id, initiator_id);
	if (entry) {
		token_ctx = entry->token_ctx;
		hash_del(&entry->hnode);
		spin_unlock_irqrestore(&g_ums_nl_state.clc_lock, flags);
		kfree(entry);
		return token_ctx;
	}
	spin_unlock_irqrestore(&g_ums_nl_state.clc_lock, flags);
	return NULL;
}

static int ums_nl_token_submit_fail(struct sk_buff *skb, struct genl_info *info)
{
	struct ums_token_xchg_ctx *token_ctx;
	u32 clc_session_id;
	u8 initiator_id[UMS_SYSTEMID_LEN];
	u32 result;
	int ret;

	if (!info || !info->attrs)
		return -EINVAL;

	ret = ums_nl_check_agent_portid(info);
	if (ret != 0)
		return ret;

	if (!info->attrs[UMS_ATTR_CLC_SESSION_ID] ||
		!info->attrs[UMS_ATTR_INITIATOR_ID] ||
		!info->attrs[UMS_ATTR_RESULT])
		return -EINVAL;

	clc_session_id = nla_get_u32(info->attrs[UMS_ATTR_CLC_SESSION_ID]);
	nla_memcpy(initiator_id, info->attrs[UMS_ATTR_INITIATOR_ID], UMS_SYSTEMID_LEN);
	result = nla_get_u32(info->attrs[UMS_ATTR_RESULT]);

	UMS_LOGE_LIMITED("TOKEN_SUBMIT_FAIL recv, clc_session_id=%u, result=%u",
		clc_session_id, result);

	token_ctx = ums_nl_claim_token_ctx(clc_session_id, initiator_id);
	if (!token_ctx) {
		UMS_LOGW_LIMITED("TOKEN_SUBMIT_FAIL no ctx for clc_session_id=%u",
			clc_session_id);
		return 0;
	}

	if (result == 0) {
		UMS_LOGE_LIMITED("TOKEN_SUBMIT_FAIL with result=0, clc_session_id=%u, treat as protocol error",
			clc_session_id);
		ums_token_xchg_complete(&token_ctx->xchg, -EPROTO);
	} else {
		ums_token_xchg_complete(&token_ctx->xchg, -(int)result);
	}

	ums_token_ctx_nl_put(token_ctx); /* release holder B reference */
	return 0;
}

static int ums_nl_token_deliver(struct sk_buff *skb, struct genl_info *info)
{
	struct ums_token_xchg_ctx *token_ctx;
	u32 clc_session_id;
	u8 initiator_id[UMS_SYSTEMID_LEN];
	u32 result;
	bool first_contact;
	int ret;

	if (!info || !info->attrs)
		return -EINVAL;

	ret = ums_nl_check_agent_portid(info);
	if (ret != 0)
		return ret;

	if (!info->attrs[UMS_ATTR_CLC_SESSION_ID] ||
		!info->attrs[UMS_ATTR_INITIATOR_ID] ||
		!info->attrs[UMS_ATTR_FIRST_CONTACT] ||
		!info->attrs[UMS_ATTR_SEG_TOKEN])
		return -EINVAL;

	clc_session_id = nla_get_u32(info->attrs[UMS_ATTR_CLC_SESSION_ID]);
	nla_memcpy(initiator_id, info->attrs[UMS_ATTR_INITIATOR_ID], UMS_SYSTEMID_LEN);
	result = info->attrs[UMS_ATTR_RESULT] ?
		nla_get_u32(info->attrs[UMS_ATTR_RESULT]) : 0;
	first_contact = nla_get_u8(info->attrs[UMS_ATTR_FIRST_CONTACT]) != 0;

	UMS_LOGD("TOKEN_DELIVER recv, clc_session_id=%u, result=%u, first_contact=%d",
		clc_session_id, result, first_contact);

	token_ctx = ums_nl_claim_token_ctx(clc_session_id, initiator_id);
	if (!token_ctx) {
		UMS_LOGW_LIMITED("TOKEN_DELIVER no ctx for clc_session_id=%u",
			clc_session_id);
		goto zero_out;
	}

	if (result != 0) {
		UMS_LOGE_LIMITED("TOKEN_DELIVER failure, clc_session_id=%u, result=%u",
			clc_session_id, result);
		ums_token_xchg_complete(&token_ctx->xchg, -(int)result);
		goto nl_put;
	}

	if (first_contact && !info->attrs[UMS_ATTR_JETTY_TOKEN]) {
		UMS_LOGE_LIMITED("TOKEN_DELIVER missing JETTY_TOKEN, clc_session_id=%u",
			clc_session_id);
		ums_token_xchg_complete(&token_ctx->xchg, -EBADMSG);
		goto nl_put;
	}

	if (first_contact)
		token_ctx->peer_jetty_token.token =
			nla_get_u32(info->attrs[UMS_ATTR_JETTY_TOKEN]);

	token_ctx->peer_seg_token.token =
		nla_get_u32(info->attrs[UMS_ATTR_SEG_TOKEN]);

	ums_token_xchg_complete(&token_ctx->xchg, 0);

nl_put:
	ums_token_ctx_nl_put(token_ctx); /* release holder B reference */
zero_out:
	if (info->attrs[UMS_ATTR_JETTY_TOKEN])
		memzero_explicit(nla_data(info->attrs[UMS_ATTR_JETTY_TOKEN]),
			sizeof(u32));
	if (info->attrs[UMS_ATTR_SEG_TOKEN])
		memzero_explicit(nla_data(info->attrs[UMS_ATTR_SEG_TOKEN]),
			sizeof(u32));

	return 0;
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
	{
		.cmd = UMS_CMD_TOKEN_SUBMIT_FAIL,
		.doit = ums_nl_token_submit_fail,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UMS_CMD_TOKEN_DELIVER,
		.doit = ums_nl_token_deliver,
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

/*
 * Register a clc session: insert an entry into clc_ht so that netlink
 * callbacks can find the token_ctx. Sets nl_refcnt=1 inside clc_lock, making
 * the hash table entry (holder A) the initial owner of the reference.
 *
 * Must be called early in the connect/listen flow, before the peer side
 * can initiate a token exchange that causes the local agent to deliver
 * tokens. This ensures ums_nl_token_deliver can always find the entry.
 */
int ums_nl_register_clc_session(struct ums_token_xchg_ctx *token_ctx)
{
	struct ums_nl_clc_entry *entry;
	unsigned long flags;
	u32 hash;

	if (g_ums_sys_tuning_config.ub_token_mode != UMS_TOKEN_MODE_SECURE)
		return 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->token_ctx = token_ctx;

	hash = ums_nl_session_hash(token_ctx->clc_session_id, token_ctx->initiator_id);
	spin_lock_irqsave(&g_ums_nl_state.clc_lock, flags);
	if (ums_nl_find_clc_entry(token_ctx->clc_session_id, token_ctx->initiator_id)) {
		spin_unlock_irqrestore(&g_ums_nl_state.clc_lock, flags);
		UMS_LOGE_LIMITED("duplicate clc session, clc_session_id=%u",
			token_ctx->clc_session_id);
		kfree(entry);
		return -EEXIST;
	}
	hash_add(g_ums_nl_state.clc_ht, &entry->hnode, hash);
	/*
	 * Set nl_refcnt=1 inside clc_lock: the hash table entry (holder A)
	 * becomes the initial owner. Safe in spinlock: refcount_set is atomic.
	 */
	refcount_set(&token_ctx->nl_refcnt, 1);
	spin_unlock_irqrestore(&g_ums_nl_state.clc_lock, flags);
	return 0;
}

/*
 * Unregister a clc session: remove the entry from clc_ht.
 * If the entry is found (holder A still owns the reference), remove it and
 * call ums_token_ctx_nl_put to release the reference (nl_refcnt: 1→0).
 * If the entry is not found, it was already claimed by a netlink callback
 * (ownership transferred to holder B); in that case we must NOT call
 * ums_token_ctx_nl_put because holder B is responsible for its own release.
 */
void ums_nl_unregister_clc_session(struct ums_token_xchg_ctx *token_ctx)
{
	struct ums_nl_clc_entry *entry;
	unsigned long flags;

	if (g_ums_sys_tuning_config.ub_token_mode != UMS_TOKEN_MODE_SECURE)
		return;

	spin_lock_irqsave(&g_ums_nl_state.clc_lock, flags);
	entry = ums_nl_find_clc_entry(token_ctx->clc_session_id, token_ctx->initiator_id);
	if (entry) {
		hash_del(&entry->hnode);
		spin_unlock_irqrestore(&g_ums_nl_state.clc_lock, flags);
		kfree(entry);
		ums_token_ctx_nl_put(token_ctx); /* release holder A reference */
		return;
	}
	spin_unlock_irqrestore(&g_ums_nl_state.clc_lock, flags);
	UMS_LOGD("unregister clc session not found, clc_session_id=%u",
		token_ctx->clc_session_id);
}

static int ums_nl_send_token_submit_msg(const struct ums_nl_token_params *params)
{
	struct sk_buff *skb;
	void *msg_head;
	int rc;

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	msg_head = genlmsg_put(skb, 0, 0, &g_ums_nl_family, 0, UMS_CMD_TOKEN_SUBMIT);
	if (!msg_head) {
		nlmsg_free(skb);
		return -ENOMEM;
	}

	rc = nla_put_u32(skb, UMS_ATTR_CLC_SESSION_ID, params->clc_session_id);
	if (rc != 0)
		goto err_out;

	rc = nla_put(skb, UMS_ATTR_INITIATOR_ID, UMS_SYSTEMID_LEN, params->initiator_id);
	if (rc != 0)
		goto err_out;

	rc = nla_put_u8(skb, UMS_ATTR_FIRST_CONTACT, params->first_contact ? 1 : 0);
	if (rc != 0)
		goto err_out;

	rc = nla_put_u32(skb, UMS_ATTR_SEG_TOKEN, params->seg_token->token);
	if (rc != 0)
		goto err_out;

	if (params->dst_addr.family == AF_INET6)
		rc = nla_put(skb, UMS_ATTR_DST_IP6, sizeof(params->dst_addr.ip.in6),
			&params->dst_addr.ip.in6);
	else
		rc = nla_put_u32(skb, UMS_ATTR_DST_IP, params->dst_addr.ip.in4.s_addr);
	if (rc != 0)
		goto err_out;

	if (params->first_contact && params->jetty_token) {
		rc = nla_put_u32(skb, UMS_ATTR_JETTY_TOKEN, params->jetty_token->token);
		if (rc != 0)
			goto err_out;
	}

	genlmsg_end(skb, msg_head);

	rc = genlmsg_unicast(&init_net, skb, g_ums_nl_state.agent.portid);
	if (rc != 0) {
		UMS_LOGE_LIMITED("TOKEN_SUBMIT send failed, clc_session_id=%u, rc=%d",
			params->clc_session_id, rc);
		return rc;
	}

	UMS_LOGD("TOKEN_SUBMIT sent, clc_session_id=%u, first_contact=%u",
		params->clc_session_id, params->first_contact);
	return 0;

err_out:
	nlmsg_free(skb);
	return rc;
}

int ums_nl_submit_tokens(struct ums_token_xchg_ctx *ctx,
	const struct ums_ip_addr *peer_addr, bool first_contact)
{
	struct ums_nl_token_params params = {
		.jetty_token = first_contact ? &ctx->jetty_token : NULL,
		.seg_token = &ctx->seg_token,
		.first_contact = first_contact,
		.clc_session_id = ctx->clc_session_id,
		.initiator_id = ctx->initiator_id,
		.dst_addr = *peer_addr,
	};
	int rc;

	if (g_ums_sys_tuning_config.ub_token_mode != UMS_TOKEN_MODE_SECURE)
		return 0;

	if (!ums_nl_agent_available()) {
		UMS_LOGE_LIMITED("ums_agent not available in SECURE mode, clc_session_id=%u",
			ctx->clc_session_id);
		return -ENOTCONN;
	}

	rc = ums_nl_send_token_submit_msg(&params);
	if (rc != 0)
		return rc;

	return 0;
}

static int ums_nl_netlink_notify(struct notifier_block *nb,
	unsigned long event, void *data)
{
	struct netlink_notify *notify = data;

	(void)nb;

	if (!data)
		return NOTIFY_DONE;

	if (event != NETLINK_URELEASE)
		return NOTIFY_DONE;

	if (notify->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	mutex_lock(&g_ums_nl_state.agent_mutex);

	if (notify->portid != g_ums_nl_state.agent.portid) {
		mutex_unlock(&g_ums_nl_state.agent_mutex);
		return NOTIFY_DONE;
	}

	atomic_set(&g_ums_nl_state.agent.available, 0);
	g_ums_nl_state.agent.portid = 0;

	UMS_LOGW_LIMITED("ums_agent socket closed unexpectedly (portid=%u, uid=%u, gid=%u)",
		notify->portid,
		from_kuid(&init_user_ns, g_ums_nl_state.agent.uid),
		from_kgid(&init_user_ns, g_ums_nl_state.agent.gid));

	g_ums_nl_state.agent.uid = INVALID_UID;
	g_ums_nl_state.agent.gid = INVALID_GID;

	mutex_unlock(&g_ums_nl_state.agent_mutex);
	return NOTIFY_OK;
}

static struct notifier_block g_ums_nl_notifier = {
	.notifier_call = ums_nl_netlink_notify,
};

int __init ums_nl_init(void)
{
	int rc;

	hash_init(g_ums_nl_state.clc_ht);
	spin_lock_init(&g_ums_nl_state.clc_lock);
	mutex_init(&g_ums_nl_state.agent_mutex);

	rc = netlink_register_notifier(&g_ums_nl_notifier);
	if (rc != 0) {
		UMS_LOGE("netlink_register_notifier failed, rc=%d", rc);
		return rc;
	}

	rc = genl_register_family(&g_ums_nl_family);
	if (rc != 0) {
		UMS_LOGE("genl_register_family failed, rc=%d", rc);
		netlink_unregister_notifier(&g_ums_nl_notifier);
		return rc;
	}

	UMS_LOGI("UMS_GENL netlink family registered");
	return 0;
}

void ums_nl_exit(void)
{
	struct ums_token_xchg_ctx *token_ctx;
	struct ums_nl_clc_entry *entry;
	struct hlist_node *tmp;
	int bkt;
	int rc;

	rc = genl_unregister_family(&g_ums_nl_family);
	if (rc != 0)
		UMS_LOGE("genl_unregister_family failed, rc=%d", rc);

	netlink_unregister_notifier(&g_ums_nl_notifier);

	atomic_set(&g_ums_nl_state.agent.available, 0);
	g_ums_nl_state.agent.portid = 0;
	g_ums_nl_state.agent.uid = INVALID_UID;
	g_ums_nl_state.agent.gid = INVALID_GID;

	/*
	 * Defensive cleanup: iterate clc_ht without clc_lock because:
	 * 1) genl_unregister_family() guarantees no new .doit callbacks can
	 *    start, and any in-flight callback has already completed (it
	 *    either claimed and removed its entry via ums_nl_claim_token_ctx, or
	 *    never found one);
	 * 2) ums_core_exit() -> ums_terminate_all() waits for all
	 *    connections to be freed before we reach here, and each
	 *    ums_conn_free() calls ums_nl_unregister_clc_session which
	 *    removes the entry and calls ums_token_ctx_nl_put. Therefore the
	 *    hash table should be empty at this point.
	 * If any entry remains, it indicates a bug. WARN and log to make
	 * the anomaly visible, then clean up as a safety net.
	 */
	hash_for_each_safe(g_ums_nl_state.clc_ht, bkt, tmp, entry, hnode) {
		token_ctx = entry->token_ctx;
		WARN_ON(1);
		UMS_LOGE("residual clc entry during nl_exit, clc_session_id=%u",
			token_ctx->clc_session_id);
		hash_del(&entry->hnode);
		kfree(entry);
		ums_token_ctx_nl_put(token_ctx);
	}
}
