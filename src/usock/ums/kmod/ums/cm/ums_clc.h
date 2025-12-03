/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UMS(UB Memory based Socket)
 *
 * Description:UMS Connection Layer Control(CLC) header file
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

#ifndef UMS_CLC_H
#define UMS_CLC_H

#include "ums_mod.h"
#include "ums_ubcore.h"

#define UMS_CLC_PROPOSAL 0x01
#define UMS_CLC_ACCEPT 0x02
#define UMS_CLC_CONFIRM 0x03
#define UMS_CLC_DECLINE 0x04

#define UMS_TYPE_R 0                       /* UMS-R only */
#define UMS_TYPE_N 2                       /* not UMS-R  */
#define CLC_WAIT_TIME (20 * HZ)            /* max. wait time on clcsock  */
#define CLC_WAIT_TIME_SHORT HZ             /* short wait time on clcsock */
#define UMS_CLC_DECL_MEM 0x01010000        /* insufficient memory resources  */
#define UMS_CLC_DECL_TIMEOUT_CL 0x02010000 /* timeout w4 QP confirm link     */
#define UMS_CLC_DECL_TIMEOUT_AL 0x02020000 /* timeout w4 QP add link	      */
#define UMS_CLC_DECL_CNFERR 0x03000000     /* configuration error            */
#define UMS_CLC_DECL_PEERNOUMS 0x03010000  /* peer did not indicate UMS      */
#define UMS_CLC_DECL_IPSEC 0x03020000      /* IPsec usage		      */
#define UMS_CLC_DECL_NOUMSDEV 0x03030000   /* no UMS device found     */
#define UMS_CLC_DECL_NOSEID 0x03030006     /* peer sent no SEID	      */
#define UMS_CLC_DECL_NOUEID 0x03030008     /* peer sent no UEID	      */
#define UMS_CLC_DECL_ERR_REQ_LGR 0x03030009 /* required create link group */
#define UMS_CLC_DECL_PEEREIDERR 0x0303000b /* peer eid negotiate failed */
#define UMS_CLC_DECL_MODEUNSUPP 0x03040000 /* ums modes do not match (R or D) */
#define UMS_CLC_DECL_RMBE_EC 0x03050000    /* peer has eyecatcher in RMBE    */
#define UMS_CLC_DECL_OPTUNSUPP 0x03060000  /* fastopen sockopt not supported */
#define UMS_CLC_DECL_DIFFPREFIX 0x03070000 /* IP prefix / subnet mismatch    */
#define UMS_CLC_DECL_GETVLANERR 0x03080000 /* err to get vlan id of ip device */
#define UMS_CLC_DECL_NOACTLINK 0x030a0000  /* no active ums link in lgr    */
#define UMS_CLC_DECL_NOSRVLINK 0x030b0000  /* UMS link from srv not found  */
#define UMS_CLC_DECL_VERSMISMAT 0x030c0000 /* UMS version mismatch	      */
#define UMS_CLC_DECL_MAX_DMB 0x030d0000    /* UMS-D DMB limit exceeded       */
#define UMS_CLC_DECL_SYNCERR 0x04000000    /* synchronization error          */
#define UMS_CLC_DECL_PEERDECL 0x05000000   /* peer declined during handshake */
#define UMS_CLC_DECL_INTERR 0x09990000     /* internal error		      */
#define UMS_CLC_DECL_ERR_RTOK 0x09990001   /*	 rtoken handling failed       */
#define UMS_CLC_DECL_ERR_RDYLNK 0x09990002 /*	 ub ready link failed	      */
#define UMS_CLC_DECL_ERR_REGBUF 0x09990003 /*	 reg bufs failed	      */
#define UMS_CLC_DECL_CREDITSERR 0x09990004 /*   announce credits failed      */
#define UMS_CLC_DECL_ERR_SEG 0x09990005    /*	 import seg failed  for UM    */
#define UMS_FIRST_CONTACT_MASK 0b10        /* first contact bit within typev2 */
#define UMS_CLC_MAX_V6_PREFIX 8
#define UMS_CLC_MAX_UEID 8
#define UMS_CLC_OS_ZOS 1
#define UMS_CLC_OS_LINUX 2
#define UMS_CLC_OS_AIX 3
#define UMS_DECL_DIAG_COUNT_V2 4 /* no. of additional peer diagnosis codes */
#define UMS_EYECATCHER_LEN 4
#define UMS_CLC_G_INSTANCE_NUM 4

struct ums_clc_msg_hdr { /* header1 of clc messages */
	u8 eyecatcher[UMS_EYECATCHER_LEN];    /* eye catcher */
	u8 type;             /* proposal / accept / confirm / decline */
	__be16 length;
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 version : 4;
	u8 typev2 : 2;
	u8 typev1 : 2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 typev1 : 2;
	u8 typev2 : 2;
	u8 version : 4;
#endif
} __packed; /* format defined in RFC7609 */

struct ums_clc_msg_trail { /* trailer of clc messages */
	u8 eyecatcher[UMS_EYECATCHER_LEN];
};

struct ums_clc_msg_local {            /* header2 of clc messages */
	u8 id_for_peer[UMS_SYSTEMID_LEN]; /* unique system id */
	union ubcore_eid eid; /* ubcore_eid for peer to import jetty and seg */
	u8 reserved1[4];
	u8 mac[ETH_ALEN];                        /* mac of ub_device port */
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 ubcore_route_enable : 1;
	u8 reserved2 : 7;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved2 : 7;
	u8 ubcore_route_enable : 1;
#endif
	u8 reserved3[3];
};

/* Struct would be 4 byte aligned, but it is used in an array that is sent
 * to peers and must conform to RFC7609, hence we need to use packed here.
 */
struct ums_clc_ipv6_prefix {
	struct in6_addr prefix;
	u8 prefix_len;
} __packed; /* format defined in RFC7609 */

#if defined(__BIG_ENDIAN_BITFIELD)
struct ums_clc_v2_flag {
	u8 release : 4, rsvd : 3, seid : 1;
};
#elif defined(__LITTLE_ENDIAN_BITFIELD)
struct ums_clc_v2_flag {
	u8 seid : 1, rsvd : 3, release : 4;
};
#endif

struct ums_clnt_opts_area_hdr {
	u8 eid_cnt;     /* number of user defined EIDs */
	u8 ism_gid_cnt; /* number of ISMv2 GIDs */
	u8 reserved1;
	struct ums_clc_v2_flag flag;
	u8 reserved2[2];
	__be16 umsd_v2_ext_offset; /* UMS-Dv2 Extension Offset */
};

struct ums_clc_umsd_gid_chid {
	__be64 gid;  /* ISM GID */
	__be16 chid; /* ISMv2 CHID */
} __packed;      /* format defined in
				  * IBM Shared Memory Communications Version 2
				  */

struct ums_clc_msg_proposal_prefix { /* prefix part of clc proposal message */
	__be32 outgoing_subnet;          /* subnet mask */
	u8 prefix_len;                   /* number of significant bits in mask */
	u8 reserved[2];
	u8 ipv6_prefixes_cnt; /* number of IPv6 prefixes in prefix array */
} __aligned(UMS_CLC_G_INSTANCE_NUM);

struct ums_clc_msg_umsd {             /* UMS-D GID information */
	struct ums_clc_umsd_gid_chid ism; /* ISM native GID+CHID of requestor */
	__be16 v2_ext_offset;             /* UMS Version 2 Extension Offset */
	u8 reserved[28];
};

struct ums_clc_umsd_v2_extension {
	u8 system_eid[UMS_MAX_EID_LEN];
	u8 reserved[16];
	struct ums_clc_umsd_gid_chid gidchid[];
};

struct ums_clc_msg_proposal { /* clc proposal message sent by Linux */
	struct ums_clc_msg_hdr hdr;
	struct ums_clc_msg_local lcl;
	__be16 iparea_offset; /* offset to IP address information area */
} __aligned(UMS_CLC_G_INSTANCE_NUM);

struct ums_clc_msg_proposal_area {
	struct ums_clc_msg_proposal pclc_base;
	struct ums_clc_msg_umsd pclc_umsd;
	struct ums_clc_msg_proposal_prefix pclc_prfx;
	struct ums_clc_ipv6_prefix pclc_prfx_ipv6[UMS_CLC_MAX_V6_PREFIX];
	u8 user_eids[UMS_CLC_MAX_UEID][UMS_MAX_EID_LEN];
	struct ums_clc_umsd_v2_extension pclc_umsd_v2_ext;
	struct ums_clc_umsd_gid_chid pclc_gidchids[UMS_MAX_ISM_DEVS];
	struct ums_clc_msg_trail pclc_trl;
};

struct umsr_clc_msg_accept_confirm { /* UMSR accept/confirm */
	struct ums_clc_msg_local lcl;
	u8 rmbe_idx;     /* Index of RMBE in RMB */
	u8 init_credits; /* QP rq init credits for rq flowctrl */

	__be32 jetty_id;         /* jetty.id for peer to import jetty */
	__be32 rmbe_alert_token; /* unique connection id */
	__be32 rmb_rkey;         /* RMB rkey */
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 rmbe_size : 4; /* buf size (compressed) */
	u8 qp_mtu : 4;    /* QP mtu */
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 qp_mtu : 4;
	u8 rmbe_size : 4;
#endif
	u8 psn[3]; /* packet sequence number */

	__be64 rmb_dma_addr; /* RMB virtual address */
	__be32 seg_flag;     /* UMS use this perserved field to store seg.flag for peer to import seg */
	__be32 seg_token_value;  /* token_value for peer to import seg when UB is used */
	__be32 jetty_token_value;  /* token_value for peer to import jetty when UB is used */
	__be32 seg_token_id; /* seg.seg_token_id for peer to import seg */

#if defined(__BIG_ENDIAN_BITFIELD)
	u8 jetty_token_policy : 3; /* token_policy for peer to import jetty when UB is used */
	u8 reserved1 : 5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved1 : 5;
	u8 jetty_token_policy : 3; /* token_policy for peer to import jetty when UB is used */
#endif
	u8 reserved2[3];

	union {
		union ubcore_eid peer_eid; /* CLC Accept */
		u8 reserved3[16]; /* CLC Confirm */
	};
} __packed;

struct umsd_clc_msg_accept_confirm_common { /* UMSD accept/confirm */
	u64 gid;                                /* Sender GID */
	u64 token;                              /* DMB token */
	u8 dmbe_idx;                            /* DMBE index */
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 dmbe_size : 4; /* buf size (compressed) */
	u8 reserved3 : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved3 : 4;
	u8 dmbe_size : 4;
#endif
	u16 reserved4;
	__be32 linkid; /* Link identifier */
} __packed;

struct ums_clc_first_contact_ext {
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 v2_direct : 1, reserved : 7;
	u8 os_type : 4, release : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved : 7, v2_direct : 1;
	u8 release : 4, os_type : 4;
#endif
	u8 reserved2[2];
	u8 hostname[UMS_MAX_HOSTNAME_LEN];
};

struct ums_clc_fce_gid_ext {
	u8 reserved[16];
	u8 gid_cnt;
	u8 reserved2[3];
	u8 gid[][UMS_GID_SIZE];
};

struct ums_clc_msg_accept_confirm { /* clc accept / confirm message */
	struct ums_clc_msg_hdr hdr;
	union {
		struct umsr_clc_msg_accept_confirm r0; /* UMS-R */
		struct {                               /* UMS-D */
			struct umsd_clc_msg_accept_confirm_common d0;
			u32 reserved5[3];
		};
	};
} __packed; /* format defined in RFC7609, 64 bytes */

struct ums_clc_msg_accept_confirm_v2 { /* clc accept / confirm message */
	struct ums_clc_msg_hdr hdr;
	union {
		struct { /* UMS-R */
			struct umsr_clc_msg_accept_confirm r0;
			u8 eid[UMS_MAX_EID_LEN];
			u8 reserved6[8];
		} r1;
		struct { /* UMS-D */
			struct umsd_clc_msg_accept_confirm_common d0;
			__be16 chid;
			u8 eid[UMS_MAX_EID_LEN];
			u8 reserved5[8];
		} d1;
	};
};

struct ums_clc_msg_decline { /* clc decline message */
	struct ums_clc_msg_hdr hdr;
	u8 id_for_peer[UMS_SYSTEMID_LEN]; /* sender peer_id */
	__be32 peer_diagnosis;            /* diagnosis information */
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 os_type : 4;
	u8 reserved : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved : 4;
	u8 os_type : 4;
#endif
	u8 reserved2[3];
	struct ums_clc_msg_trail trl; /* eye catcher "UMSR" EBCDIC */
} __aligned(UMS_CLC_G_INSTANCE_NUM);

struct ums_clc_msg_decline_v2 { /* clc decline message */
	struct ums_clc_msg_hdr hdr;
	u8 id_for_peer[UMS_SYSTEMID_LEN]; /* sender peer_id */
	__be32 peer_diagnosis;            /* diagnosis information */
#if defined(__BIG_ENDIAN_BITFIELD)
	u8 os_type : 4;
	u8 reserved : 4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved : 4;
	u8 os_type : 4;
#endif
	u8 reserved2[3];
	__be32 peer_diagnosis_v2[UMS_DECL_DIAG_COUNT_V2];
	struct ums_clc_msg_trail trl; /* eye catcher "UMSR" EBCDIC */
} __aligned(UMS_CLC_G_INSTANCE_NUM);

/* determine start of the prefix area within the proposal message */
static inline struct ums_clc_msg_proposal_prefix *ums_clc_proposal_get_prefix(
	struct ums_clc_msg_proposal *pclc)
{
	return (struct ums_clc_msg_proposal_prefix *)((u8 *)pclc + sizeof(*pclc) +
		ntohs(pclc->iparea_offset));
}

static inline bool ums_indicated(int ums_type)
{
	return ums_type == UMS_TYPE_R;
}

int ums_clc_prfx_match(struct socket *clcsock, struct ums_clc_msg_proposal_prefix *prop);
int ums_clc_wait_msg(struct ums_sock *ums, void *buf, size_t buflen, u8 expected_type,
	unsigned long timeout);
int ums_clc_send_decline(struct ums_sock *ums, u32 peer_diag_info);
int ums_clc_send_proposal(struct ums_sock *ums, struct ums_init_info *ini);
int ums_clc_send_confirm(struct ums_sock *ums, bool clnt_first_contact,  u8 *eid,
	struct ums_init_info *ini);
int ums_clc_send_accept(struct ums_sock *ums, bool srv_first_contact,
	u8 *negotiated_eid, struct ums_init_info *ini);
void __init ums_clc_init(void);
void ums_clc_exit(void);
#endif /* UMS_CLC_H */
