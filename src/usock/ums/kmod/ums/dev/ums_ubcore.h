// SPDX-License-Identifier: GPL-2.0
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS ubcore interface header file
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#ifndef UMS_UBCORE_H
#define UMS_UBCORE_H

#include <net/ipv6.h>
#include <net/ip.h>

#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/init.h>
#include <linux/types.h>

#include <ub/urma/ubcore_api.h>

#include "ums_adapt.h"
#include "ums_types.h"

#define UMS_MAX_PORTS UBCORE_MAX_PORT_CNT /* Max # of ports */
#define UMS_TYPICAL_MIN_RNR_TIMER 12

#define UMS_JETTY2LINK_HASH_BITS 10 /* 1024 buckets */
#define UMS_JETTY2LINK_HTABLE_SIZE (1 << UMS_JETTY2LINK_HASH_BITS)

#ifndef UBCORE_IPV4_MAP_IPV6_PREFIX
#define UBCORE_IPV4_MAP_IPV6_PREFIX (0x0000ffff)
#endif
/* max. # of compl. queue elements in 1 poll */
#define UMS_WR_MAX_POLL_CQE 64

#define UMS_UBCORE_ROUTE_DISABLE 0
#define UMS_UBCORE_ROUTE_ENABLE 1

struct ums_hashinfo {
	rwlock_t lock;
	struct hlist_head ht;
};

struct ums_ub_port_attr {
	bool is_valid;
	struct net_device *ndev;
};

struct ums_ub_dev_attr {
	bool is_accessed_from_ns;
	struct ums_ub_port_attr port_attr[UMS_MAX_PORTS];
	u32 eid_cnt;
};

struct ums_ubcore_devices { /* list of ums ub devices definition */
	struct list_head list;
	struct mutex mutex; /* protects list of ums ub devices */
};

extern struct ums_ubcore_devices g_ums_ubcore_devices; /* list of ums ubcore devices */
extern struct ums_lgr_list g_ums_lgr_list;             /* list of linkgroups */

struct ums_ubcore_jfc {                   /* ubcore_jfc wrapper for ums */
	struct ums_ubcore_device *ums_ub_dev; /* parent ub device */
	struct ubcore_jfc *jfc;               /* real ub_cq for link */
	struct tasklet_struct tasklet;        /* tasklet for wr */
	atomic_t load;                             /* load of current cq */
	struct ubcore_cr cr_tasklets[UMS_WR_MAX_POLL_CQE];
#ifndef KERNEL_VERSION_4
	struct dim *dim;                      /* dim of jfc */
#endif
};

struct ums_ubcore_port_attr {
	enum ubcore_port_state state;
	enum ubcore_mtu active_mtu;
};

struct ums_ubcore_device { /* ub-device infos for ums */
	struct list_head list;
	struct ubcore_device *ub_dev;
	struct ums_ubcore_port_attr pattr[UMS_MAX_PORTS]; /* ubcore dev. port attrs */
	struct ubcore_event_handler event_handler;        /* global ub_event handler */
	int num_jfc;                                      /* num of snd/rcv jfc */
	struct ums_ubcore_jfc *ums_ub_jfc;                /* send & recv cqs */
	char mac[UMS_MAX_PORTS][ETH_ALEN];
	/* mac address per port */
	u8 pnetid[UMS_MAX_PORTS][UMS_MAX_PNETID_LEN];
	/* pnetid per port */
	bool pnetid_by_user[UMS_MAX_PORTS];
	/* pnetid defined by user? */
	u8 initialized : 1; /* ub dev CQ, evthdl done */
	struct work_struct port_event_work;
	unsigned long port_event_mask;
	DECLARE_BITMAP(ports_going_away, UMS_MAX_PORTS);
	atomic_t lnk_cnt;               /* number of links on ubdev */
	wait_queue_head_t lnks_deleted; /* wait 4 removal of all links */
	struct mutex mutex;             /* protect dev setup+cleanup */
	atomic_t lnk_cnt_by_port[UMS_MAX_PORTS];
	/* number of links per port */
	int ndev_ifidx[UMS_MAX_PORTS]; /* ndev if indexes */

	struct hlist_head jetty2link_htable[UMS_JETTY2LINK_HTABLE_SIZE];
	rwlock_t jetty2link_htable_lock;
};

struct ums_ubcore_determine_eid_param {
	u8 port;
	unsigned short vlan_id;
	union ubcore_eid *eid;
	u32 *eid_index;
	struct ums_ubcore_device *ums_ub_dev;
	struct sock *sk; /* internal tcp sock */
	struct net *net;
};

static inline bool ums_ubcore_check_if_eid_match(const union ubcore_eid *eid1, const union ubcore_eid *eid2)
{
	return (memcmp(eid1->raw, eid2->raw, UMS_EID_SIZE) == 0);
}

int __init ums_ubcore_register_client(void);
void ums_ubcore_unregister_client(void);
void ums_ubcore_destroy_jetty(struct ums_link *lnk);
void ums_destroy_jetty_and_jfr(struct ums_link *lnk);
int ums_ubcore_create_jetty(struct ums_link *lnk);
int ums_ubcore_ready_link(struct ums_link *lnk);
long ums_ubcore_setup_per_ubdev(struct ums_ubcore_device *ums_ub_dev);
int ums_ubcore_determine_eid(struct ums_ubcore_determine_eid_param *param);
int ums_ubcore_find_ub_dev_by_eid(union ubcore_eid *eid, struct ums_init_info *ini);
void ums_ubcore_clnt_find_src_v_eid_and_ub_dev(struct ums_init_info *ini);
void ums_ubcore_serv_find_ub_dev_non_netdev(struct ums_init_info *ini);
bool ums_ubcore_is_valid_local_systemid(void);
bool ums_ubcore_port_active(const struct ums_ubcore_device *ums_ub_dev, u8 port);
void ums_ubcore_ndev_change(struct net_device *ndev, unsigned long event);
bool ums_eid_valid(const struct ubcore_device *ub_dev, u32 eid_idx);
#endif /* UMS_UBCORE_H */
