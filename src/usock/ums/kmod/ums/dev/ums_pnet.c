// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS physical net(pnet) related implementation
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s):  Thomas Richter <tmricht@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s):  YAO Yufeng ZHANG Chuwen
 */

#include <net/genetlink.h>
#include <net/netlink.h>
#include <net/netns/generic.h>

#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>

#include <uapi/linux/if.h>
#include <ub/urma/ubcore_types.h>
#include <ub/urma/ubcore_uapi.h>

#include "ums_core.h"
#include "ums_log.h"
#include "ums_pnet.h"

static struct net_device *pnet_find_base_ndev_inner(struct net_device *n_dev);
static struct net_device *pnet_find_base_ndev(struct net_device *n_dev);
static struct genl_family g_ums_pnet_nl_family;

static const struct nla_policy UMS_PNET_POLICY[SMC_PNETID_MAX + 1] = {
	[SMC_PNETID_NAME] = {
		.len = UMS_MAX_PNETID_LEN,
		.type = NLA_NUL_STRING
	},
	[SMC_PNETID_ETHNAME] = {
		.len = IFNAMSIZ - 1,
		.type = NLA_NUL_STRING
	},
	/* for kernel 5.10, ums also uses the macro SMC_PNETID_IBNAME */
	[SMC_PNETID_IBNAME] = {
		.len = UB_DEVICE_NAME_MAX - 1,
		.type = NLA_NUL_STRING
	},
	/* for kernel 5.10, ums also uses the macro SMC_PNETID_IBPORT */
	[SMC_PNETID_IBPORT] = { .type = NLA_U8 }
};

enum ums_pnet_nametype {
	UMS_PNET_ETH = 1,
	UMS_PNET_UB = 2
};

/* pnet entry stored in pnet table */
struct ums_pnetentry {
	struct list_head list;
	char pnet_name[UMS_MAX_PNETID_LEN + 1];
	enum ums_pnet_nametype type;
	union {
		struct {
			char eth_name[IFNAMSIZ + 1];
			struct net_device *ndev;
		};
		struct {
			char ub_name[UB_DEVICE_NAME_MAX + 1];
			u8 ub_port;
		};
	};
};

struct ums_pnet_dump_param {
	struct sk_buff *skb;
	u32 portid;
	u32 seq;
};

/* Check if the pnetid is set */
bool ums_pnet_is_pnetid_set(const u8 *pnetid)
{
	if (pnetid[0] == 0 || pnetid[0] == _S)
		return false;
	return true;
}

/* Check if two given pnetids match */
static bool ums_pnet_match(const u8 *pnet_id1, const u8 *pnet_id2)
{
	int i;

	for (i = 0; i < UMS_MAX_PNETID_LEN; i++) {
		if ((pnet_id1[i] == 0 || pnet_id1[i] == _S) &&
		    (pnet_id2[i] == 0 || pnet_id2[i] == _S))
			break;
		if (pnet_id1[i] != pnet_id2[i])
			return false;
	}
	return true;
}

/* Remove a pnetid from the pnet table.
 */
static int ums_pnet_remove_by_pnetid(struct net *net, char *pnet_name)
{
	struct ums_pnetentry *pnet_elem, *tmp_pe;
	struct ums_pnettable *pnettable;
	struct ums_ubcore_device *ubdev;
	struct ums_net *sn;
	int rc = -ENOENT;
	int ubport;

	/* get pnettable for namespace */
	sn = net_generic(net, g_ums_net_id);
	pnettable = &sn->pnettable;

	/* remove table entry */
	mutex_lock(&pnettable->lock);
	list_for_each_entry_safe(pnet_elem, tmp_pe, &pnettable->pnetlist,
				 list) {
		if (!pnet_name ||
			ums_pnet_match(pnet_elem->pnet_name, pnet_name)) {
			list_del(&pnet_elem->list);
			if (pnet_elem->type == UMS_PNET_ETH && pnet_elem->ndev) {
				dev_put(pnet_elem->ndev);
				UMS_LOGI_LIMITED("net device %s erased user defined pnetid %.16s",
					pnet_elem->eth_name, pnet_elem->pnet_name);
			}
			kfree(pnet_elem);
			rc = 0;
		}
	}
	mutex_unlock(&pnettable->lock);

	/* if this is not the initial namespace, stop here */
	if (net != &init_net)
		return rc;

	/* remove ub devices */
	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_for_each_entry(ubdev, &g_ums_ubcore_devices.list, list) {
		for (ubport = 0; ubport < UMS_MAX_PORTS; ubport++) {
			if (ubdev->pnetid_by_user[ubport] &&
				(!pnet_name || ums_pnet_match(pnet_name, ubdev->pnetid[ubport]))) {
				UMS_LOGI_LIMITED("ubcore device %s ubport %d erased user defined pnetid %.16s",
					ubdev->ub_dev->dev_name, ubport + 1, ubdev->pnetid[ubport]);
				(void)memset(ubdev->pnetid[ubport], 0, UMS_MAX_PNETID_LEN);
				ubdev->pnetid_by_user[ubport] = false;
				rc = 0;
			}
		}
	}
	mutex_unlock(&g_ums_ubcore_devices.mutex);

	return rc;
}

static bool ums_pnet_add_by_ndev_inner(struct net_device *ndev, struct ums_pnetentry *pnetelem,
	int *rc)
{
	bool ret_break = false;

	if ((pnetelem->type == UMS_PNET_ETH) && !pnetelem->ndev &&
		(strncmp(pnetelem->eth_name, ndev->name, IFNAMSIZ) == 0)) {
		dev_hold(ndev);
		pnetelem->ndev = ndev;
		*rc = 0;
		UMS_LOGI_LIMITED("adding net device %s with user defined pnetid %.16s",
			pnetelem->eth_name, pnetelem->pnet_name);
		ret_break = true;
	}
	return ret_break;
}

static bool ums_pnet_remove_by_ndev_inner(struct net_device *ndev, struct ums_pnetentry *pnetelem,
	int *rc)
{
	bool ret_break = false;

	if (pnetelem->type == UMS_PNET_ETH && pnetelem->ndev == ndev) {
		dev_put(pnetelem->ndev);
		pnetelem->ndev = NULL;
		*rc = 0;
		UMS_LOGI_LIMITED("removing net device %s with user defined pnetid %.16s",
			pnetelem->eth_name, pnetelem->pnet_name);
		ret_break = true;
	}
	return ret_break;
}

static int ums_pnet_common_by_ndev(struct net_device *ndev, bool add)
{
	struct ums_pnetentry *pnetelem, *tmp_pe;
	struct ums_pnettable *pnettable;
	struct net *net = dev_net(ndev);
	struct ums_net *sn;
	int rc = -ENOENT;
	bool ret_break;

	/* get pnettable for namespace */
	sn = net_generic(net, g_ums_net_id);
	pnettable = &sn->pnettable;

	mutex_lock(&pnettable->lock);
	list_for_each_entry_safe(pnetelem, tmp_pe, &pnettable->pnetlist, list) {
		if (add)
			ret_break = ums_pnet_add_by_ndev_inner(ndev, pnetelem, &rc);
		else
			ret_break = ums_pnet_remove_by_ndev_inner(ndev, pnetelem, &rc);

		if (ret_break)
			break;
	}
	mutex_unlock(&pnettable->lock);
	return rc;
}

/* Add the reference to a given network device to the pnet table.
 */
static int ums_pnet_add_by_ndev(struct net_device *ndev)
{
	return ums_pnet_common_by_ndev(ndev, true);
}

/* Remove the reference to a given network device from the pnet table.
 */
static int ums_pnet_remove_by_ndev(struct net_device *ndev)
{
	return ums_pnet_common_by_ndev(ndev, false);
}

/* Apply pnetid to ub device when no pnetid is set.
 */
static bool ums_pnet_apply_ub(struct ums_ubcore_device *ubdev, u8 ub_port,
	char *pnet_name)
{
	bool applied = false;

	mutex_lock(&g_ums_ubcore_devices.mutex);
	if (!ums_pnet_is_pnetid_set(ubdev->pnetid[ub_port - 1])) {
		(void)memcpy(ubdev->pnetid[ub_port - 1], pnet_name, UMS_MAX_PNETID_LEN);
		ubdev->pnetid_by_user[ub_port - 1] = true;
		applied = true;
	}
	mutex_unlock(&g_ums_ubcore_devices.mutex);
	return applied;
}

/* The limit for pnet_id is 16 characters.
 * Valid characters should be (single-byte character set) a-z, A-Z, 0-9.
 * Lower case letters are converted to upper case.
 * Interior blanks should not be used.
 */
static bool ums_pnetid_valid(const char *pnet_name, char *pnet_id)
{
	char *bf = skip_spaces(pnet_name);
	size_t bf_len = strlen(bf);
	char *bf_end = bf + bf_len;

	if (bf_len == 0)
		return false;
	while (--bf_end >= bf && isspace(*bf_end))
		;
	if (bf_end - bf >= UMS_MAX_PNETID_LEN)
		return false;
	while (bf <= bf_end) {
		if (!isalnum(*bf))
			return false;
		*pnet_id++ = islower(*bf) ? (char)toupper(*bf) : *bf;
		bf++;
	}
	*pnet_id = '\0';
	return true;
}

/* Find an ub device by a given name. The device might not exist. */
static struct ums_ubcore_device *ums_pnet_find_ub(char *ub_name)
{
	struct ums_ubcore_device *ubdev;

	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_for_each_entry(ubdev, &g_ums_ubcore_devices.list, list) {
		if ((strncmp(ubdev->ub_dev->dev_name, ub_name, sizeof(ubdev->ub_dev->dev_name)) == 0) ||
			(ubdev->ub_dev->dev.parent && (strncmp(dev_name(ubdev->ub_dev->dev.parent), ub_name,
				UB_DEVICE_NAME_MAX - 1) == 0))) {
			goto out;
		}
	}
	ubdev = NULL;
out:
	mutex_unlock(&g_ums_ubcore_devices.mutex);
	return ubdev;
}

static int ums_pnet_add_eth(struct ums_pnettable *pnettable, struct net *net,
	char *eth_name, char *pnet_name)
{
	struct ums_pnetentry *tmp_pe, *new_pe;
	struct net_device *n_dev, *base_ndev;
	u8 ndev_pnetid[UMS_MAX_PNETID_LEN];
	int rc;

	/* check if (base) netdev already has a pnetid. If there is one, we do
	 * not want to add a pnet table entry
	 */
	rc = -EEXIST;
	n_dev = dev_get_by_name(net, eth_name);	/* dev_hold() */
	if (n_dev) {
		base_ndev = pnet_find_base_ndev(n_dev);
		if (ums_pnetid_by_dev_port(base_ndev->dev.parent, base_ndev->dev_port, ndev_pnetid) == 0)
			goto out_put;
	}

	/* add a new netdev entry to the pnet table if there isn't one */
	rc = -ENOMEM;
	new_pe = kzalloc(sizeof(struct ums_pnetentry), GFP_KERNEL);
	if (!new_pe)
		goto out_put;
	new_pe->type = UMS_PNET_ETH;
	(void)memcpy(new_pe->pnet_name, pnet_name, UMS_MAX_PNETID_LEN);
	(void)strncpy(new_pe->eth_name, eth_name, IFNAMSIZ);
	new_pe->ndev = n_dev;

	rc = -EEXIST;
	mutex_lock(&pnettable->lock);
	list_for_each_entry(tmp_pe, &pnettable->pnetlist, list) {
		if ((tmp_pe->type == UMS_PNET_ETH) &&
			(strncmp(tmp_pe->eth_name, eth_name, IFNAMSIZ) == 0)) {
			mutex_unlock(&pnettable->lock);
			kfree(new_pe);
			goto out_put;
		}
	}
	list_add_tail(&new_pe->list, &pnettable->pnetlist);
	mutex_unlock(&pnettable->lock);
	if (n_dev)
		UMS_LOGI_LIMITED("net device %s applied user defined pnetid %.16s",
			new_pe->eth_name, new_pe->pnet_name);
	return 0;

out_put:
	if (n_dev)
		dev_put(n_dev);
	return rc;
}

static int ums_pnet_add_ub(struct ums_pnettable *pnettable, char *ub_name, u8 ub_port,
	char *pnet_name)
{
	struct ums_pnetentry *tmp_pe, *new_pe;
	struct ums_ubcore_device *ubdev;
	bool ubdev_applied = true;
	bool new_ubdev;

	/* try to apply the pnetid to active devices */
	ubdev = ums_pnet_find_ub(ub_name);
	if (ubdev) {
		ubdev_applied = ums_pnet_apply_ub(ubdev, ub_port, pnet_name);
		if (ubdev_applied)
			UMS_LOGI_LIMITED("ubcore device %s ubport %d applied user defined pnetid %.16s",
				ubdev->ub_dev->dev_name, ub_port, ubdev->pnetid[ub_port - 1]);
	}

	/* Apply fails when a device has a hardware-defined pnetid set, do not
	 * add a pnet table entry in that case.
	 */
	if (!ubdev_applied)
		return -EEXIST;

	/* add a new ub entry to the pnet table if there isn't one */
	new_pe = kzalloc(sizeof(*new_pe), GFP_KERNEL);
	if (!new_pe)
		return -ENOMEM;
	new_pe->type = UMS_PNET_UB;
	(void)memcpy(new_pe->pnet_name, pnet_name, UMS_MAX_PNETID_LEN);
	(void)strncpy(new_pe->ub_name, ub_name, UB_DEVICE_NAME_MAX);
	new_pe->ub_port = ub_port;

	new_ubdev = true;
	mutex_lock(&pnettable->lock);
	list_for_each_entry(tmp_pe, &pnettable->pnetlist, list) {
		if ((tmp_pe->type == UMS_PNET_UB) &&
			(strncmp(tmp_pe->ub_name, ub_name, UB_DEVICE_NAME_MAX) == 0)) {
			new_ubdev = false;
			break;
		}
	}
	if (new_ubdev) {
		list_add_tail(&new_pe->list, &pnettable->pnetlist);
		mutex_unlock(&pnettable->lock);
	} else {
		mutex_unlock(&pnettable->lock);
		kfree(new_pe);
	}
	return (new_ubdev) ? 0 : -EEXIST;
}

/* Append a pnetid to the end of the pnet table if not already on this list.
 */
static int ums_pnet_enter(struct net *net, struct nlattr *nla_tb[])
{
	char pnet_name[UMS_MAX_PNETID_LEN + 1];
	struct ums_pnettable *pnettable;
	bool new_netdev = false;
	bool new_ubdev = false;
	struct ums_net *sn;
	u8 ubport = 1;
	char *string;
	int rc;

	/* get pnettable for namespace */
	sn = net_generic(net, g_ums_net_id);
	pnettable = &sn->pnettable;

	rc = -EINVAL;
	if (!nla_tb[SMC_PNETID_NAME])
		goto error;
	string = (char *)nla_data(nla_tb[SMC_PNETID_NAME]);
	if (!ums_pnetid_valid(string, pnet_name))
		goto error;

	if (nla_tb[SMC_PNETID_ETHNAME]) {
		string = (char *)nla_data(nla_tb[SMC_PNETID_ETHNAME]);
		rc = ums_pnet_add_eth(pnettable, net, string, pnet_name);
		if (rc == 0)
			new_netdev = true;
		else if (rc != -EEXIST)
			goto error;
	}

	if (net != &init_net) /* if this is not the initial namespace, stop here */
		return new_netdev ? 0 : -EEXIST;

	rc = -EINVAL;
	if (nla_tb[SMC_PNETID_IBNAME]) {
		string = (char *)nla_data(nla_tb[SMC_PNETID_IBNAME]);
		string = strim(string);
		if (nla_tb[SMC_PNETID_IBPORT]) {
			ubport = nla_get_u8(nla_tb[SMC_PNETID_IBPORT]);
			if (ubport < 1 || ubport > UMS_MAX_PORTS)
				goto error;
		}
		/* for ub transport node, id is start from 1 */
		rc = ums_pnet_add_ub(pnettable, string, ubport, pnet_name);
		if (rc == 0)
			new_ubdev = true;
		else if (rc != -EEXIST)
			goto error;
	}
	return (new_netdev || new_ubdev) ? 0 : -EEXIST;

error:
	return rc;
}

/* Convert an ums_pnetentry to a netlink attribute sequence */
static int ums_pnet_set_nla(struct sk_buff *skb_msg,
	struct ums_pnetentry *pnetelem)
{
	if (nla_put_string(skb_msg, SMC_PNETID_NAME, pnetelem->pnet_name) != 0)
		return -1;
	if (pnetelem->type == UMS_PNET_ETH) {
		if (nla_put_string(skb_msg, SMC_PNETID_ETHNAME,
				   pnetelem->eth_name) != 0)
			return -1;
	} else {
		if (nla_put_string(skb_msg, SMC_PNETID_ETHNAME, "n/a") != 0)
			return -1;
	}
	if (pnetelem->type == UMS_PNET_UB) {
		if ((nla_put_string(skb_msg, SMC_PNETID_IBNAME, pnetelem->ub_name) != 0) ||
			(nla_put_u8(skb_msg, SMC_PNETID_IBPORT, pnetelem->ub_port) != 0))
			return -1;
	} else {
		if ((nla_put_string(skb_msg, SMC_PNETID_IBNAME, "n/a") != 0) ||
			(nla_put_u8(skb_msg, SMC_PNETID_IBPORT, 0xff) != 0))
			return -1;
	}

	return 0;
}

static int ums_pnet_add(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);

	return ums_pnet_enter(net, info->attrs);
}

static int ums_pnet_del(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);

	if (!info->attrs[SMC_PNETID_NAME])
		return -EINVAL;
	return ums_pnet_remove_by_pnetid(net,
		(char *)nla_data(info->attrs[SMC_PNETID_NAME]));
}

static int ums_pnet_dump_start(struct netlink_callback *cb)
{
	cb->args[0] = 0;
	return 0;
}

static int ums_pnet_dumpinfo(struct sk_buff *skb, u32 portid, u32 seq,
	u32 flags, struct ums_pnetentry *pnetelem)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &g_ums_pnet_nl_family,
			(int)flags, SMC_PNETID_GET);
	if (!hdr)
		return -ENOMEM;
	if (ums_pnet_set_nla(skb, pnetelem) < 0) {
		genlmsg_cancel(skb, hdr);
		return -EMSGSIZE;
	}
	genlmsg_end(skb, hdr);
	return 0;
}

static int ums_pnet_dump_inner(struct net *net, struct ums_pnet_dump_param *param,
	u8 *pnetid, int start_idx)
{
	struct ums_pnettable *pnettable;
	struct ums_pnetentry *pnetelem;
	struct ums_net *sn;
	int idx = 0;

	/* get pnettable for namespace */
	sn = net_generic(net, g_ums_net_id);
	pnettable = &sn->pnettable;

	/* dump pnettable entries */
	mutex_lock(&pnettable->lock);
	list_for_each_entry(pnetelem, &pnettable->pnetlist, list) {
		if ((pnetid && !ums_pnet_match(pnetelem->pnet_name, pnetid)) ||
			(idx++ < start_idx) ||
			/* if this is not the initial namespace, dump only netdev */
			(net != &init_net && pnetelem->type != UMS_PNET_ETH))
			continue;
		if (ums_pnet_dumpinfo(param->skb, param->portid, param->seq, NLM_F_MULTI, pnetelem) != 0) {
			--idx;
			break;
		}
	}
	mutex_unlock(&pnettable->lock);
	return idx;
}

static int ums_pnet_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct ums_pnet_dump_param param;
	int idx;

	param.skb = skb;
	param.portid = NETLINK_CB(cb->skb).portid;
	param.seq = cb->nlh->nlmsg_seq;
	idx = ums_pnet_dump_inner(net, &param, NULL, (int)cb->args[0]);

	cb->args[0] = idx;
	return (int)skb->len;
}

/* Retrieve one PNETID entry */
static int ums_pnet_get(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct ums_pnet_dump_param param;
	struct sk_buff *skb_msg;
	void *hdr;

	if (!info->attrs[SMC_PNETID_NAME])
		return -EINVAL;

	skb_msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb_msg)
		return -ENOMEM;

	param.skb = skb_msg;
	param.portid = info->snd_portid;
	param.seq = info->snd_seq;
	(void)ums_pnet_dump_inner(net, &param, nla_data(info->attrs[SMC_PNETID_NAME]), 0);

	/* finish multi part message and send it */
	hdr = nlmsg_put(skb_msg, info->snd_portid, info->snd_seq, NLMSG_DONE, 0,
			NLM_F_MULTI);
	if (!hdr) {
		nlmsg_free(skb_msg);
		return -EMSGSIZE;
	}
	return genlmsg_reply(skb_msg, info);
}

/* Remove and delete all pnetids from pnet table.
 */
static int ums_pnet_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);

	(void)ums_pnet_remove_by_pnetid(net, NULL);
	return 0;
}

/* UMS_PNETID generic netlink operation definition */
static const struct genl_ops UMS_PNET_OPS[] = {
	{
		.cmd = SMC_PNETID_GET,
#ifndef KERNEL_VERSION_4
		.validate = (u8)(GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP),
#endif
		/* can be retrieved by unprivileged users */
		.doit = ums_pnet_get,
		.dumpit = ums_pnet_dump,
		.start = ums_pnet_dump_start
	},
	{
		.cmd = SMC_PNETID_ADD,
#ifndef KERNEL_VERSION_4
		.validate = (u8)(GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP),
#endif
		.flags = GENL_ADMIN_PERM,
		.doit = ums_pnet_add
	},
	{
		.cmd = SMC_PNETID_DEL,
#ifndef KERNEL_VERSION_4
		.validate = (u8)(GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP),
#endif
		.flags = GENL_ADMIN_PERM,
		.doit = ums_pnet_del
	},
	{
		.cmd = SMC_PNETID_FLUSH,
#ifndef KERNEL_VERSION_4
		.validate = (u8)(GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP),
#endif
		.flags = GENL_ADMIN_PERM,
		.doit = ums_pnet_flush
	}
};

/* UMS_PNETID family definition */
static struct genl_family g_ums_pnet_nl_family __ro_after_init = {
	.hdrsize = 0,
	.name = SMCR_GENL_FAMILY_NAME,
	.version = SMCR_GENL_FAMILY_VERSION,
	.maxattr = SMC_PNETID_MAX,
#ifndef KERNEL_VERSION_4
	.policy = UMS_PNET_POLICY,
#endif
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = UMS_PNET_OPS,
	.n_ops =  ARRAY_SIZE(UMS_PNET_OPS),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	.resv_start_op = SMC_PNETID_FLUSH + 1,
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0) */
};

static int ums_pnet_add_pnetid(struct net *net, u8 *pnetid)
{
	struct ums_net *sn = net_generic(net, g_ums_net_id);
	struct ums_pnetids_ndev_entry *pe_entry, *pi_entry;

	pe_entry = kzalloc(sizeof(*pe_entry), GFP_KERNEL);
	if (!pe_entry)
		return -ENOMEM;

	write_lock(&sn->pnetids_ndev.lock);
	list_for_each_entry(pi_entry, &sn->pnetids_ndev.list, list) {
		if (ums_pnet_match(pnetid, pe_entry->pnetid)) {
			refcount_inc(&pi_entry->refcnt);
			kfree(pe_entry);
			goto unlock;
		}
	}
	refcount_set(&pe_entry->refcnt, 1);
	(void)memcpy(pe_entry->pnetid, pnetid, UMS_MAX_PNETID_LEN);
	list_add_tail(&pe_entry->list, &sn->pnetids_ndev.list);

unlock:
	write_unlock(&sn->pnetids_ndev.lock);
	return 0;
}

static void ums_pnet_remove_pnetid(struct net *net, u8 *pnetid)
{
	struct ums_net *sn = net_generic(net, g_ums_net_id);
	struct ums_pnetids_ndev_entry *pe, *pe2;

	write_lock(&sn->pnetids_ndev.lock);
	list_for_each_entry_safe(pe, pe2, &sn->pnetids_ndev.list, list) {
		if (ums_pnet_match(pnetid, pe->pnetid)) {
			if (refcount_dec_and_test(&pe->refcnt)) {
				list_del(&pe->list);
				kfree(pe);
			}
			break;
		}
	}
	write_unlock(&sn->pnetids_ndev.lock);
}

static void ums_pnet_add_base_pnetid(struct net *net, struct net_device *dev, u8 *ndev_pnetid)
{
	struct net_device *base_dev;

	base_dev = pnet_find_base_ndev_inner(dev);
	if (((base_dev->flags & IFF_UP) != 0) &&
		(ums_pnetid_by_dev_port(base_dev->dev.parent, base_dev->dev_port, ndev_pnetid) == 0))
		/* add to PNETIDs list */
		(void)ums_pnet_add_pnetid(net, ndev_pnetid);
}

/* create initial list of netdevice pnetids */
static void ums_pnet_create_pnetids_list(struct net *net)
{
	u8 ndev_pnetid[UMS_MAX_PNETID_LEN];
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(net, dev)
		ums_pnet_add_base_pnetid(net, dev, ndev_pnetid);
	rtnl_unlock();
}

/* clean up list of netdevice pnetids */
static void ums_pnet_destroy_pnetids_list(struct net *net)
{
	struct ums_net *sn = net_generic(net, g_ums_net_id);
	struct ums_pnetids_ndev_entry *pe, *temp_pe;

	write_lock(&sn->pnetids_ndev.lock);
	list_for_each_entry_safe(pe, temp_pe, &sn->pnetids_ndev.list, list) {
		list_del(&pe->list);
		kfree(pe);
	}
	write_unlock(&sn->pnetids_ndev.lock);
}

static int ums_pnet_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *event_ndev = netdev_notifier_info_to_dev(ptr);
	struct net *net = dev_net(event_ndev);
	u8 ndev_pnetid[UMS_MAX_PNETID_LEN];

	switch (event) {
	case NETDEV_REBOOT:
	case NETDEV_UNREGISTER:
		(void)ums_pnet_remove_by_ndev(event_ndev);
		ums_ubcore_ndev_change(event_ndev, event);
		return NOTIFY_OK;
	case NETDEV_REGISTER:
		(void)ums_pnet_add_by_ndev(event_ndev);
		ums_ubcore_ndev_change(event_ndev, event);
		return NOTIFY_OK;
	case NETDEV_UP:
		ums_pnet_add_base_pnetid(net, event_ndev, ndev_pnetid);
		return NOTIFY_OK;
	case NETDEV_DOWN:
		event_ndev = pnet_find_base_ndev_inner(event_ndev);
		if (ums_pnetid_by_dev_port(event_ndev->dev.parent, event_ndev->dev_port, ndev_pnetid) == 0)
			/* remove from PNETIDs list */
			ums_pnet_remove_pnetid(net, ndev_pnetid);
		return NOTIFY_OK;
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block g_ums_netdev_notifier = {
	.notifier_call = ums_pnet_netdev_event
};

/* init network namespace */
int ums_pnet_net_init(struct net *net)
{
	struct ums_net *sn = net_generic(net, g_ums_net_id);
	struct ums_pnettable *pnettable = &sn->pnettable;
	struct ums_pnetids_ndev *pnetids_ndev = &sn->pnetids_ndev;

	INIT_LIST_HEAD(&pnettable->pnetlist);
	mutex_init(&pnettable->lock);
	INIT_LIST_HEAD(&pnetids_ndev->list);
	rwlock_init(&pnetids_ndev->lock);

	ums_pnet_create_pnetids_list(net);

	return 0;
}

int __init ums_pnet_init(void)
{
	int rc;

	rc = genl_register_family(&g_ums_pnet_nl_family);
	if (rc != 0)
		return rc;
	rc = register_netdevice_notifier(&g_ums_netdev_notifier);
	if (rc != 0)
		(void)genl_unregister_family(&g_ums_pnet_nl_family);

	return rc;
}

/* exit network namespace */
void ums_pnet_net_exit(struct net *net)
{
	/* flush pnet table */
	(void)ums_pnet_remove_by_pnetid(net, NULL);
	ums_pnet_destroy_pnetids_list(net);
}

void ums_pnet_exit(void)
{
	(void)unregister_netdevice_notifier(&g_ums_netdev_notifier);
	(void)genl_unregister_family(&g_ums_pnet_nl_family);
}

static struct net_device *pnet_find_base_ndev_inner(struct net_device *n_dev)
{
	int i, nest_lvl;

	ASSERT_RTNL();
	nest_lvl = n_dev->lower_level;

	for (i = 0; i < nest_lvl; i++) {
		struct list_head *lower = &n_dev->adj_list.lower;
		if (list_empty(lower) != 0)
			break;
		lower = lower->next;
		n_dev = netdev_lower_get_next(n_dev, &lower);
	}
	return n_dev;
}

/* Determine one base device for stacked net devices.
 * If the lower device level contains more than one devices
 * (for instance with bonding slaves), just the first device
 * is used to reach a base device.
 */
static struct net_device *pnet_find_base_ndev(struct net_device *n_dev)
{
	rtnl_lock();
	n_dev = pnet_find_base_ndev_inner(n_dev);
	rtnl_unlock();
	return n_dev;
}

static int ums_pnet_find_ndev_pnetid_by_table(struct net_device *ndev, u8 *pnetid)
{
	struct ums_pnettable *pnettable;
	struct net *net = dev_net(ndev);
	struct ums_pnetentry *pnetelem;
	struct ums_net *sn;
	int rc = -ENOENT;

	/* get pnettable for namespace */
	sn = net_generic(net, g_ums_net_id);
	pnettable = &sn->pnettable;

	mutex_lock(&pnettable->lock);
	list_for_each_entry(pnetelem, &pnettable->pnetlist, list) {
		if (pnetelem->type == UMS_PNET_ETH && ndev == pnetelem->ndev) {
			/* get pnetid of netdev device */
			(void)memcpy(pnetid, pnetelem->pnet_name, UMS_MAX_PNETID_LEN);
			rc = 0;
			break;
		}
	}
	mutex_unlock(&pnettable->lock);
	return rc;
}

static int ums_pnet_determine_id(struct ums_ubcore_device *ubdev, struct sock *sk, int i,
    struct ums_init_info *ini, int(*function)(struct ums_ubcore_determine_eid_param*))
{
	struct ums_ubcore_determine_eid_param param;
	param.ums_ub_dev = ubdev;
	param.sk = sk;
	param.port = (u8)i;
	param.vlan_id = ini->vlan_id;
	param.eid = &ini->eid;
	param.eid_index = &ini->eid_index;
	param.net = ini->net;

	if (function(&param) == 0) {
		ini->ub_dev = ubdev;
		ini->ub_port = (u8)i;
		return 0;
	}

	return -ENODEV;
}

/* if handshake network device belongs to a UB device, return its
 * UB device and port
 */
static void ums_pnet_find_ub_dev(struct net_device *netdev, struct sock *sk,
	struct ums_init_info *ini)
{
	struct ums_ubcore_device *ubdev;

	if (ini->is_server && (ini->ubcore_route_enable == UMS_UBCORE_ROUTE_ENABLE)) {
		ums_ubcore_serv_find_ub_dev_non_netdev(ini);
		return;
	}

	mutex_lock(&g_ums_ubcore_devices.mutex);
	list_for_each_entry(ubdev, &g_ums_ubcore_devices.list, list) {
		int i;

		if (ubdev->ub_dev->netdev != netdev)
			continue;
	
		for (i = 0; i < UMS_MAX_PORTS; i++) {
			if (ums_ubcore_port_active(ubdev, (u8)i) &&
					!test_bit(i, ubdev->ports_going_away))
				if (ums_pnet_determine_id(ubdev, sk, i, ini, ums_ubcore_determine_eid) == 0) {
					UMS_LOGI("find ub device success, name:%s", netdev->name);
					break;
				}
		}
	}
	mutex_unlock(&g_ums_ubcore_devices.mutex);

	/*
	 * UMS supports establishing TCP connections based on third-party netdev independent of ubdev.
	 * For UMS client, if ubdev cannot be found via netdev, attempt to locate the virtual ubdev
	 * and src virtual eid.
	 */
	if ((!ini->ub_dev) && (!ini->is_server)) {
		ums_ubcore_clnt_find_src_v_eid_and_ub_dev(ini);
	}
}

/* Determine the corresponding UB device port based on the hardware PNETID.
 * Searching stops at the first matching active UB device port with vlan_id
 * configured.
 * If nothing found, check pnetid table.
 * If nothing found, try to use handshake device
 */
static void ums_pnet_find_ub_by_pnetid(struct net_device *ndev, struct sock *sk,
	struct ums_init_info *ini)
{
	u8 ndev_pnetid[UMS_MAX_PNETID_LEN];

	ndev = pnet_find_base_ndev(ndev);
	if ((ums_pnetid_by_dev_port(ndev->dev.parent, ndev->dev_port, ndev_pnetid) != 0) &&
		(ums_pnet_find_ndev_pnetid_by_table(ndev, ndev_pnetid) != 0))
		ums_pnet_find_ub_dev(ndev, sk, ini);
	else
		UMS_LOGE("No ub device find.");

	return;
}

/* PNET table analysis for a given sock:
 * determine ub_device and port belonging to used internal TCP socket
 * ethernet interface.
 */
void ums_pnet_find_ub_resource(struct sock *sk, struct ums_init_info *ini)
{
	struct dst_entry *dst = sk_dst_get(sk);

	if (!dst)
		goto out;
	if (!dst->dev)
		goto out_rel;

	/**
	 * The network namespace must be the same as the clcsock dev.
	 * It is the network namespace to which the upper-layer application process belongs.
	 */
	ini->net = dev_net(dst->dev);

	ums_pnet_find_ub_by_pnetid(dst->dev, sk, ini);

out_rel:
	dst_release(dst);
out:
	return;
}

/* Lookup and apply a pnet table entry to the given ubcore device.
 */
int ums_pnetid_by_table_ub(struct ums_ubcore_device *ubdev, u8 ub_port)
{
	char *ub_name = ubdev->ub_dev->dev_name;
	struct ums_pnettable *pnettable;
	struct ums_pnetentry *tmp_pe;
	struct ums_net *sn;
	int rc = -ENOENT;

	/* get pnettable for init namespace */
	sn = net_generic(&init_net, g_ums_net_id);
	pnettable = &sn->pnettable;

	mutex_lock(&pnettable->lock);
	list_for_each_entry(tmp_pe, &pnettable->pnetlist, list) {
		if ((tmp_pe->type == UMS_PNET_UB) &&
			(strncmp(tmp_pe->ub_name, ub_name, UB_DEVICE_NAME_MAX) == 0) &&
			(tmp_pe->ub_port == ub_port)) {
			(void)ums_pnet_apply_ub(ubdev, ub_port, tmp_pe->pnet_name);
			rc = 0;
			break;
		}
	}
	mutex_unlock(&pnettable->lock);

	return rc;
}

#ifdef UMS_UT_TEST
EXPORT_SYMBOL(ums_pnet_is_pnetid_set);
#endif
