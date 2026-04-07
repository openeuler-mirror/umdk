/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UB Memory based Socket(UMS)
 *
 * Description:Link Layer Control(LLC) header file
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Klaus Wacker <Klaus.Wacker@de.ibm.com>
 *  			  Ursula Braun <ubraun@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s): YAO Yufeng ZHANG Chuwen
 */

#ifndef UMS_LLC_H
#define UMS_LLC_H

#include "ums_wr.h"

#define UMS_LLC_FLAG_RESP 0x80
#define UMS_LLC_DATA_LEN		40
#define UMS_LLC_RKEYS_PER_CONT_MSG	2
#define UMS_LLC_RKEYS_PER_MSG		3
#define UMS_USER_DATA_LEN 16

#define UMS_LLC_WAIT_FIRST_TIME		(5 * HZ)
#define UMS_LLC_WAIT_TIME		(2 * HZ)

#define UMS_LLC_ANNOUNCE_CR_MAX_RETRY	(1)

/* LLC DELETE LINK Request Reason Codes */
#define UMS_LLC_DEL_LOST_PATH		0x00010000
#define UMS_LLC_DEL_OP_INIT_TERM	0x00020000
#define UMS_LLC_DEL_PROG_INIT_TERM	0x00030000
#define UMS_LLC_DEL_PROT_VIOL		0x00040000
#define UMS_LLC_DEL_NO_ASYM_NEEDED	0x00050000
/* LLC DELETE LINK Response Reason Codes */
#define UMS_LLC_DEL_NOLNK	0x00100000  /* Unknown Link ID (no link) */
#define UMS_LLC_DEL_NOLGR	0x00200000  /* Unknown Link Group */

enum ums_llc_reqresp {
	UMS_LLC_REQ,
	UMS_LLC_RESP
};

struct ums_llc_hdr {
	struct ums_wr_rx_hdr common;
	union {
		struct {
			u8 length; /* 44 */
#if defined(__BIG_ENDIAN_BITFIELD)
			u8 reserved : 4;
			u8 add_link_rej_rsn : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
			u8 add_link_rej_rsn : 4;
			u8 reserved : 4;
#endif
		};
		u16 length_v2; /* 44 - 8192 */
	};
	u8 flags;
} __packed;

struct ums_llc_msg_confirm_link {  /* type 0x01 */
	struct ums_llc_hdr hd;
	u8 sender_mac[ETH_ALEN];
	u8 sender_eid[UMS_EID_SIZE];
	u8 link_num;
	u8 max_links;
	u8 link_uid[UMS_LGR_ID_SIZE];
	__be32 sender_jetty_id;
	u8 reserved[8];
};

struct ums_llc_msg_add_link {  /* type 0x02 */
	struct ums_llc_hdr hd;
	u8 sender_mac[ETH_ALEN];
	u8 reserved2[2];
	u8 sender_gid[UMS_GID_SIZE];
	__be32 sender_jetty_id;
	u8 link_num;
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 reserved3 : 4;
	u8 qp_mtu   : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 qp_mtu   : 4;
	u8 reserved3 : 4;
#endif
	u8 initial_psn[3];
	u8 init_credits;  /* QP rq init credits for rq flowctrl */
	u8 reserved[6];
};

struct ums_llc_msg_add_link_cont_rt {
	__be32 rmb_key;
	__be32 rmb_key_new;
	__be64 rmb_vaddr_new;
};

struct ums_llc_msg_add_link_cont {  /* type 0x03 */
	struct ums_llc_hdr hd;
	u8 link_num;
	u8 num_rkeys;
	u8 reserved2[2];
	struct ums_llc_msg_add_link_cont_rt rt[UMS_LLC_RKEYS_PER_CONT_MSG];
	u8 reserved[4];
} __packed; /* format defined in RFC7609 */

struct ums_llc_msg_del_link { /* type 0x04 */
	struct ums_llc_hdr hd;
	u8 link_num;
	__be32 reason;
	u8 reserved[35];
} __packed; /* format defined in RFC7609 */

struct ums_rmb_rtoken {
	union {
		u8 num_rkeys; /* the num of rtokens */
		u8 link_id; /* link id of the rtoken */
	};
	__be32 rmb_key;
	__be64 rmb_vaddr;
} __packed; /* format defined in RFC7609 */

struct ums_llc_msg_confirm_rkey { /* type 0x06 */
	struct ums_llc_hdr hd;
	struct ums_rmb_rtoken rtoken[UMS_LLC_RKEYS_PER_MSG];
	u8 reserved;
};

struct ums_llc_msg_delete_rkey { /* type 0x09 */
	struct ums_llc_hdr hd;
	u8 num_rkeys;
	u8 err_mask;
	u8 reserved[2];
	__be32 rkey[8];
	u8 reserved2[4];
};

struct ums_llc_msg_test_link { /* type 0x07 */
	struct ums_llc_hdr hd;
	u8 user_data[UMS_USER_DATA_LEN];
	u8 reserved[24];
};

struct ums_llc_msg_announce_credits { /* type 0x0A */
	struct ums_llc_hdr hd;
	u8 credits;
	u8 reserved[39];
};

union ums_llc_msg {
	struct ums_llc_msg_confirm_link confirm_link;
	struct ums_llc_msg_add_link add_link;
	struct ums_llc_msg_add_link_cont add_link_cont;
	struct ums_llc_msg_del_link delete_link;

	struct ums_llc_msg_confirm_rkey confirm_rkey;
	struct ums_llc_msg_delete_rkey delete_rkey;

	struct ums_llc_msg_test_link test_link;
	struct ums_llc_msg_announce_credits announce_credits;
	struct {
		struct ums_llc_hdr hdr;
		u8 data[UMS_LLC_DATA_LEN];
	} raw;
};

struct ums_llc_qentry {
	struct list_head list;
	struct ums_link *link;
	union ums_llc_msg msg;
};

enum ums_llc_msg_type {
	UMS_LLC_CONFIRM_LINK		= 0x01,
	UMS_LLC_ADD_LINK		= 0x02,
	UMS_LLC_ADD_LINK_CONT		= 0x03,
	UMS_LLC_DELETE_LINK		= 0x04,
	UMS_LLC_REQ_ADD_LINK		= 0x05,
	UMS_LLC_CONFIRM_RKEY		= 0x06,
	UMS_LLC_TEST_LINK		= 0x07,
	UMS_LLC_CONFIRM_RKEY_CONT	= 0x08,
	UMS_LLC_DELETE_RKEY		= 0x09,
	UMS_LLC_ANNOUNCE_CREDITS	= 0X0A,
};

static inline bool ums_link_downing(enum ums_link_state *state)
{
	return cmpxchg(state, UMS_LNK_ACTIVE, UMS_LNK_INACTIVE) == UMS_LNK_ACTIVE;
}

/* returns a usable link of the link group, or NULL */
static inline struct ums_link *ums_llc_usable_link(struct ums_link_group *lgr)
{
	int i;

	for (i = 0; i < UMS_LINKS_PER_LGR_MAX; i++)
		if (ums_link_usable(&lgr->lnk[i]))
			return &lgr->lnk[i];
	return NULL;
}

/* set the termination reason code for the link group */
static inline void ums_llc_set_termination_rsn(struct ums_link_group *lgr, u32 rsn)
{
	if (lgr->llc_termination_rsn == 0)
		lgr->llc_termination_rsn = rsn;
}

static inline void ums_llc_flow_qentry_set(struct ums_llc_flow *flow,
	 struct ums_llc_qentry *qentry)
{
	flow->qentry = qentry;
}

/* transmit */
int ums_llc_send_confirm_link(struct ums_link *link, enum ums_llc_reqresp reqresp);
int ums_llc_announce_credits(struct ums_link *link, enum ums_llc_reqresp reqresp, bool force);
void ums_llc_link_active(struct ums_link *link);
int ums_llc_do_delete_rkey(struct ums_link_group *lgr, struct ums_buf_desc *rmb_desc);
int ums_llc_flow_initiate(struct ums_link_group *lgr, enum ums_llc_flowtype type);
void ums_llc_flow_stop(struct ums_link_group *lgr, struct ums_llc_flow *flow);
int ums_llc_eval_conf_link(struct ums_llc_qentry *qentry, enum ums_llc_reqresp type);
void ums_llc_link_set_uid(struct ums_link *link);
void ums_llc_save_peer_uid(struct ums_llc_qentry *qentry);
struct ums_llc_qentry *ums_llc_wait(struct ums_link_group *lgr, struct ums_link *lnk, int time_out,
	u8 exp_msg);
struct ums_llc_qentry *ums_llc_flow_qentry_clr(struct ums_llc_flow *flow);
void ums_llc_flow_qentry_del(struct ums_llc_flow *flow);
void ums_llc_send_link_delete_all(struct ums_link_group *lgr, bool ord, u32 rsn);
int __init ums_llc_init(void);
void ums_llc_rmt_delete_rkey(struct ums_link_group *lgr);
void ums_llc_process_srv_delete_link(struct ums_link_group *lgr);
void ums_llc_process_cli_delete_link(struct ums_link_group *lgr);
int ums_llc_send_message(struct ums_link *link, void *llcbuf);
bool ums_llc_flow_start(struct ums_llc_flow *flow, struct ums_llc_qentry *qentry);
void ums_llc_protocol_violation(struct ums_link_group *lgr, u8 type);
int ums_llc_add_pending_send(struct ums_link *link, struct ums_wr_buf **wr_buf,
	struct ums_wr_tx_pend_priv **pend, bool emergency);
void ums_llc_init_msg_hdr(struct ums_llc_hdr *hdr, const struct ums_link_group *lgr, size_t len);
#endif /* UMS_LLC_H */
