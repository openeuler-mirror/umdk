/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UB Memory based Socket(UMS)
 *
 * Description:UMS types definition header file
 *
 * Copyright IBM Corp. 2016
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Original SMC-R implementation:
 *     Author(s): Ursula Braun <ubraun@linux.vnet.ibm.com>
 *
 * UMS implementation:
 *     Author(s): LI Yuxing
 */

#ifndef UMS_TYPES_H
#define UMS_TYPES_H

#include <ub/urma/ubcore_types.h>
#include <linux/atomic.h>
#include <linux/pci.h>

/* max. # of RMBs per link group. Correspondingly, UMS_WR_BUF_CNT should not be less than 2 *
 * UMS_RMBS_PER_LGR_MAX, since every connection at least has two rq/sq credits in average, otherwise
 * may result in waiting for credits in sending process. */
#define UMS_RMBS_PER_LGR_MAX 32

#define UMS_WR_BUF_SIZE 48      /* size of work request buffer */
#define UMS_MAX_HOSTNAME_LEN 32
#define UMS_MAX_EID_LEN 32

#define UMS_UBCORE_MAX_SEND_SGE 2
#define UMS_GID_SIZE UBCORE_EID_SIZE
#define UMS_EID_SIZE UBCORE_EID_SIZE
#define UMS_SYSTEMID_LEN 8
#define UMS_MAX_PNETID_LEN 16

#define UMS_LGR_ID_SIZE 4
#define UMS_LINKFLAG_ANNOUNCE_PENDING 0
#define UMS_MAX_ISM_DEVS 8 /* max # of proposed non-native ISM devices */
#define UMS_MOD_G_INSTANCE_NUM 8

/* For now we just allow one parallel link per link group. The UMS protocol allows more (up to 8).
 */
#define UMS_LINKS_PER_LGR_MAX 1
#define UMS_SINGLE_LINK 0

#define UMS_BUF_MIN_SIZE 16384 /* minimum size of an RMB */
#define UMS_RMBE_SIZES 16      /* number of distinct RMBE sizes */
/* theoretically, the RFC states that largest size would be 512K, i.e. compressed 5 and thus 6 sizes
 * (0..5), despite struct ums_clc_msg_accept_confirm.rmbe_size being a 4 bit value (0..15) */

#define GID_LIST_SIZE 2
#define UMS_MAX_TCP_LISTEN_WORKS 2

#define UMSPROTO_UMS 0  /* UMS protocol, IPv4 */
#define UMSPROTO_UMS6 1 /* UMS protocol, IPv6 */

struct ums_lgr_list { /* list of link group definition */
	struct list_head list;
	spinlock_t lock; /* protects list of link groups */
	u32 num;         /* unique link group number */
};

enum ums_lgr_role { /* possible roles of a link group */
	UMS_CLNT,       /* client */
	UMS_SERV        /* server */
};

enum ums_link_state {   /* possible states of a link */
	UMS_LNK_UNUSED,     /* link is unused */
	UMS_LNK_INACTIVE,   /* link is inactive */
	UMS_LNK_ACTIVATING, /* link is being activated */
	UMS_LNK_ACTIVE     /* link is active */
};

struct ums_wr_buf {
	u8 raw[UMS_WR_BUF_SIZE];
};

struct ums_ub_sge { /* sges for writes */
	struct ubcore_sge wr_tx_ub_sge[UMS_UBCORE_MAX_SEND_SGE];
};

struct ums_wr_rx_pend { /* control data for a pending recv work request */
	u64 wr_id;
};

struct ums_link {
	struct rb_node jetty_node;
	spinlock_t credit_lock;                 /* to solve credit deadlock */
	struct ums_ubcore_device *ums_dev;      /* ubcore-device */
	struct ums_ubcore_jfc *ums_ub_jfc;      /* jfc for recv & send */
	struct ubcore_jetty *ub_jetty;          /* UB RC jetty */
	struct ubcore_jfr *jfr;                 /* just used in RS mode */
	struct ubcore_tjetty *ub_tjetty;        /* UB RC tjetty */
	u32 tjetty_id;                          /* jetty id of peer */
	struct ubcore_tjetty_cfg ub_tjetty_cfg; /* UB RC tjetty */
	struct ubcore_udata udata;              /* ub udata */
	u8 port;                                /* device port id */
	struct ums_wr_buf *wr_tx_bufs;          /* WR send payload buffers */
	struct ubcore_jfs_wr *wr_tx;            /* WR send meta data */
	struct ubcore_sge *wr_tx_sges;          /* WR send gather meta data */
	struct ums_ub_sge *wr_tx_ub_sges;       /* WRITE gather meta data */
	struct ubcore_jfs_wr *wr_tx_ubcore;     /* WR WRITE */
	struct ums_wr_tx_pend *wr_tx_pends;     /* WR send waiting for CQE */
	struct completion *wr_tx_compl;         /* WR send CQE completion */
	/* above four vectors have wr_tx_cnt elements and use the same index */
	atomic_long_t wr_tx_id;               /* seq # of last sent WR */
	unsigned long *wr_tx_mask;            /* bit mask of used indexes */
	u32 wr_tx_cnt;                        /* number of WR send buffers */
	struct ubcore_target_seg *tx_tseg;
	wait_queue_head_t wr_tx_wait; /* wait for free WR send buf */
	atomic_t wr_tx_refcnt;        /* tx refs to link */

	struct ums_wr_buf *wr_rx_bufs; /* WR recv payload buffers */
	struct ubcore_jfr_wr *wr_rx;   /* WR recv meta data */
	struct ubcore_sge *wr_rx_sges; /* WR recv scatter meta data */
	struct ums_wr_rx_pend *wr_rx_pends; /* WR recv waiting for CQE */
	/* above three vectors have wr_rx_cnt elements and use the same index */
	spinlock_t wr_rx_lock;
	struct ubcore_target_seg *rx_tseg;
	u64 wr_rx_id;               /* seq # of last recv WR */
	u32 wr_rx_cnt;              /* number of WR recv buffers */
	unsigned long wr_rx_tstamp; /* jiffies when last buf rx */

	atomic_t peer_rq_credits;                 /* credits for peer rq flowctrl */
	atomic_t local_rq_credits;                /* credits for local rq flowctrl */
	u8 credits_enable;                        /* credits enable flag, set when negotiation */
	u8 local_cr_watermark_high;               /* local rq credits watermark */
	u8 credits_update_limit;                  /* credits update limit for cdc msg */
	struct work_struct credits_announce_work; /* work for credits announcement */
	unsigned long flags;                      /* link flags, UMS_LINKFLAG_ANNOUNCE_PENDING .etc */

	union ubcore_eid eid;
	u32 eid_index;
	enum ubcore_mtu path_mtu;           /* used mtu */
	enum ubcore_mtu peer_mtu;           /* mtu size of peer */
	u32 psn_initial;                    /* QP tx initial packet seqno */
	u32 peer_psn;                       /* QP rx initial packet seqno */
	u8 peer_mac[ETH_ALEN];              /* = gid[8:10||13:15] */
	union ubcore_eid peer_eid;          /* eid of peer */
	u8 link_id;                         /* unique # within link group */
	u8 peer_link_uid[UMS_LGR_ID_SIZE];  /* peer uid */
	u8 link_uid[UMS_LGR_ID_SIZE];       /* unique lnk id */
	u8 link_idx;                        /* index in lgr link array */
	u8 link_is_asym;                    /* is link asymmetric? */
	u8 clearing : 1;                    /* link is being cleared */
	refcount_t refcnt;                  /* link reference count */
	struct ums_link_group *lgr;         /* parent link group */
	struct work_struct link_down_wrk;   /* wrk to bring link down */
	char dev_name[UBCORE_MAX_DEV_NAME]; /* u device name */
	int ndev_ifidx;                     /* network device ifindex */

	enum ums_link_state state;            /* state of link */
	struct delayed_work llc_testlink_wrk; /* testlink worker */
	struct completion llc_testlink_resp;  /* wait for rx of testlink */
	int llc_testlink_time;                /* testlink interval */
	atomic_t conn_cnt;                    /* connections on this link */
	atomic_t jetty_mod_cnt;               /* jetty modified count */
	struct ubcore_token jetty_token_value; /* token_value for jetty */

	struct hlist_node hnode; /* for ums_dev->jetty2link_htable */
};

/* tx/rx buffer list element for sndbufs list and rmbs list of a lgr */
struct ums_buf_desc {
	struct list_head list;
	void *cpu_addr; /* virtual address of buffer */
	struct page *pages;
	int len;  /* length of buffer */
	u32 used; /* currently used / unused */
	union {
		struct {       /* UMS */
			u32 order; /* allocation order */
			u8 is_vm;
			/* virtually contiguous */
			struct ubcore_target_seg *seg[UMS_LINKS_PER_LGR_MAX];
			u8 is_reg_seg[UMS_LINKS_PER_LGR_MAX];
			u8 confirmed_rkey; /* confirm_rkey done */
			u8 reg_err;        /* buffer registration err */
		};
		struct { /* UMS-D */
			unsigned short sba_idx;
			/* SBA index number */
			u64 token;
			/* DMB token number */
			dma_addr_t dma_addr;
			/* DMA address */
		};
	};
	struct ubcore_token seg_token_value; /* token value for segment */
};

struct ums_rtoken { /* address/key of remote RMB */
	u64 dma_addr;
	u32 rkey;
};

enum ums_lgr_type {           /* redundancy state of lgr */
	UMS_LGR_NONE,             /* no active links, lgr to be deleted */
	UMS_LGR_SINGLE,           /* 1 active RNIC on each peer */
};

enum ums_buf_type { /* types of UMS sndbufs and RMBs */
	UMS_PHYS_CONT_BUFS = 0,
	UMS_VIRT_CONT_BUFS = 1,
	UMS_MIXED_BUFS = 2
};

enum ums_llc_flowtype {
	UMS_LLC_FLOW_NONE = 0,
	UMS_LLC_FLOW_ADD_LINK = 2,
	UMS_LLC_FLOW_DEL_LINK = 4,
	UMS_LLC_FLOW_REQ_ADD_LINK = 5,
	UMS_LLC_FLOW_RKEY = 6
};

struct ums_llc_qentry;

struct ums_llc_flow {
	enum ums_llc_flowtype type;
	struct ums_llc_qentry *qentry;
};

struct ums_link_group {
	struct list_head list;
	struct rb_root conns_all; /* connection tree */
	rwlock_t conns_lock;      /* protects conns_all */
	unsigned int conns_num;   /* current # of connections, 2^24 maximum */
	unsigned short vlan_id;   /* vlan id of link group */

	struct list_head sndbufs[UMS_RMBE_SIZES]; /* tx buffers */
	struct mutex sndbufs_lock;                /* protects tx buffers */
	struct list_head rmbs[UMS_RMBE_SIZES];    /* rx buffers */
	struct mutex rmbs_lock;                   /* protects rx buffers */

	u8 id[UMS_LGR_ID_SIZE];            /* unique lgr id */
	struct delayed_work free_work;     /* delayed freeing of an lgr */
	struct work_struct terminate_work; /* abnormal lgr termination */
	struct workqueue_struct *tx_wq;    /* wq for conn. tx workers */
	u8 sync_err : 1;                   /* lgr no longer fits to peer */
	u8 terminating : 1;                /* lgr is terminating */
	u8 freeing : 1;                    /* lgr is being freed */

	refcount_t refcnt; /* lgr reference count */
	u8 negotiated_eid[UMS_MAX_EID_LEN];
	u8 peer_os; /* peer operating system */
	u8 peer_ums_release;
	u8 peer_hostname[UMS_MAX_HOSTNAME_LEN];
	union {
		struct { /* UMS-R */
			enum ums_lgr_role role;
			/* client or server */
			struct ums_link lnk[UMS_LINKS_PER_LGR_MAX];
			/* WR v2 send payload buffer */
			char peer_systemid[UMS_SYSTEMID_LEN];
			/* unique system_id of peer */
			struct ums_rtoken rtokens[UMS_RMBS_PER_LGR_MAX][UMS_LINKS_PER_LGR_MAX];
			/* remote addr/key pairs */
			DECLARE_BITMAP(rtokens_used_mask, UMS_RMBS_PER_LGR_MAX);
			/* used rtoken elements */
			u8 next_link_id;
			enum ums_lgr_type type;
			enum ums_buf_type buf_type;
			/* redundancy state */
			u8 pnet_id[UMS_MAX_PNETID_LEN + 1];
			/* pnet id of this lgr */
			struct list_head llc_event_q;
			/* queue for llc events */
			spinlock_t llc_event_q_lock;
			/* protects llc_event_q */
			struct mutex llc_conf_mutex;
			/* protects lgr reconfig. */
			struct work_struct llc_del_link_work;
			struct work_struct llc_event_work;
			/* llc event worker */
			wait_queue_head_t llc_flow_waiter;
			/* w4 next llc event */
			wait_queue_head_t llc_msg_waiter;
			/* w4 next llc msg */
			struct ums_llc_flow llc_flow_lcl;
			/* llc local control field */
			struct ums_llc_flow llc_flow_rmt;
			/* llc remote control field */
			struct ums_llc_qentry *delayed_event;
			/* arrived when flow active */
			spinlock_t llc_flow_lock;
			/* protects llc flow */
			int llc_testlink_time;
			/* link keep alive time */
			u32 llc_termination_rsn;
			/* rsn code for termination */
			u8 nexthop_mac[ETH_ALEN];
			u8 uses_gateway;
			__be32 saddr;
			/* net namespace */
			struct net *net;
		};
		struct { /* UMS-D */
			u64 peer_gid;
			/* Peer GID (remote) */
			struct smcd_dev *umsd;
			/* ISM device for VLAN reg. */
			u8 peer_shutdown : 1;
			/* peer triggered shutdownn */
		};
	};
};

struct ums_clc_msg_local;

struct ums_gidlist {
	u8 len;
	u8 list[GID_LIST_SIZE][UMS_GID_SIZE];
};

struct ums_init_info {
	u8 ums_type_v1;
	u8 first_contact_peer;
	u8 first_contact_local;
	unsigned short vlan_id;
	u32 rc;
	u8 negotiated_eid[UMS_MAX_EID_LEN];
	union ubcore_eid peer_eid;
	u8 peer_mac[ETH_ALEN];
	u8 peer_systemid[UMS_SYSTEMID_LEN];
	union ubcore_eid eid;
	u32 eid_index;
	u8 ub_port;
	u32 tjetty_id;
	struct ums_ubcore_device *ub_dev;
	struct net *net;
	/* mutex holding for conn create */
	struct mutex *mutex;

	bool is_server;
	/*
	 * If topo_eid_enable is true, then the src eid and dst eid
	 * required for establishing the link is obtained by the source virtual
	 * eid and destination virtual eid.
	 */
	u8 topo_eid_enable;
	union ubcore_eid src_v_eid; /* Source virtual eid, refer to the source bonding eid. */
	union ubcore_eid dst_v_eid; /* Destination virtual eid, refer to the destination bonding eid. */
};

enum ums_state { /* possible states of an UMS socket */
	UMS_ACTIVE = 1,
	UMS_INIT = 2,
	UMS_CLOSED = 7,
	UMS_LISTEN = 10,
	/* normal close */
	UMS_PEERCLOSEWAIT1 = 20,
	UMS_PEERCLOSEWAIT2 = 21,
	UMS_APPCLOSEWAIT1 = 22,
	UMS_APPCLOSEWAIT2 = 23,
	UMS_APPFINCLOSEWAIT = 24,
	UMS_PEERFINCLOSEWAIT = 25,
	/* abnormal close */
	UMS_PEERABORTWAIT = 26,
	UMS_PROCESSABORT = 27
};

struct ums_wr_rx_hdr { /* common prefix part of LLC and CDC to demultiplex */
	union {
		u8 type;
#if defined(__BIG_ENDIAN_BITFIELD)
		struct {
			u8 llc_version : 4;
			u8 llc_type : 4;
		};
#elif defined(__LITTLE_ENDIAN_BITFIELD)
		struct {
			u8 llc_type : 4;
			u8 llc_version : 4;
		};
#endif
	};
} __aligned(1);

struct ums_cdc_conn_state_flags {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved : 5;
	u8 peer_conn_abort : 1;
	u8 peer_conn_closed : 1;
	u8 peer_done_writing : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 peer_done_writing : 1;
	u8 peer_conn_closed : 1;
	u8 peer_conn_abort : 1;
	u8 reserved : 5;
#endif
};

struct ums_cdc_producer_flags {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 reserved : 4;
	u8 urg_data_present : 1;
	u8 urg_data_pending : 1;
	u8 cons_curs_upd_req : 1;
	u8 write_blocked : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 write_blocked : 1;
	u8 cons_curs_upd_req : 1;
	u8 urg_data_pending : 1;
	u8 urg_data_present : 1;
	u8 reserved : 4;
#endif
};

/* in host byte order */
union ums_host_cursor { /* UMS cursor - an offset in an RMBE */
	struct {
		u16 reserved;
		u16 wrap;  /* window wrap sequence number */
		u32 count; /* cursor (= offset) part */
	};
#ifdef ATOMIC64_INIT
	atomic64_t acurs;
#else
	u64 acurs;
#endif
} __aligned(UMS_MOD_G_INSTANCE_NUM);

/* in host byte order, except for flag bitfields in network byte order */
struct ums_host_cdc_msg {                             /* Connection Data Control message */
	struct ums_wr_rx_hdr common;                      /* .type = 0xFE */
	u8 len;                                           /* length = 44 */
	u16 seqno;                                        /* connection seq # */
	u32 token;                                        /* alert_token */
	union ums_host_cursor prod;                       /* producer cursor */
	union ums_host_cursor cons;                       /* consumer cursor, piggy backed "ack" */
	struct ums_cdc_producer_flags prod_flags;         /* conn. tx/rx status */
	struct ums_cdc_conn_state_flags conn_state_flags; /* peer conn. status */
	u8 reserved[18];
} __aligned(UMS_MOD_G_INSTANCE_NUM);

enum ums_urg_state {
	UMS_URG_VALID = 1,  /* data present */
	UMS_URG_NOTYET = 2, /* data pending */
	UMS_URG_READ = 3    /* data was already read */
};

struct ums_conn_jetty_info {
	bool is_ums_conn;
	struct ubcore_jetty_id l_jetty_id;
	struct ubcore_jetty_id r_jetty_id;
};

struct ums_mark_woken {
	bool woken;
	void *key;
	wait_queue_entry_t wait_entry;
};

struct ums_connection {
	struct rb_node alert_node;
	struct ums_link_group *lgr;       /* link group of connection */
	struct ums_link *lnk;             /* assigned UMS link */
	u32 conn_id;            /* unique conn. id */
	u8 peer_rmbe_idx;                 /* from tcp handshake */
	int peer_rmbe_size;               /* size of peer rx buffer */
	atomic_t peer_rmbe_space;         /* remaining free bytes in peer rmbe */
	int rtoken_idx;                   /* idx to peer RMB rkey/addr */
	struct ubcore_target_seg *tseg;   /* seg for remote rmbe */
	struct ums_buf_desc *sndbuf_desc; /* send buffer descriptor */
	struct ums_buf_desc *rmb_desc;    /* RMBE descriptor */
	int rmbe_size_short;              /* compressed notation */
	int rmbe_update_limit;
	/* lower limit for consumer
	 * cursor update
	 */
	struct ums_host_cdc_msg local_tx_ctrl; /* host byte order staging buffer for CDC msg send
											* .prod cf. TCP snd_nxt
											* .cons cf. TCP sends ack
											*/
	union ums_host_cursor local_tx_ctrl_fin;
	/* prod crsr - confirmed by peer */
	union ums_host_cursor tx_curs_prep; /* tx - prepared data
										 * snd_max..wmem_alloc
										 */
	union ums_host_cursor tx_curs_sent; /* tx - sent data
										 * snd_nxt ?
										 */
	union ums_host_cursor tx_curs_fin;  /* tx - confirmed by peer
										 * snd-wnd-begin ?
										 */

	atomic_t sndbuf_space;             /* remaining space in sndbuf */
	u16 tx_cdc_seq;                    /* sequence # for CDC send */
	u16 tx_cdc_seq_fin;                /* sequence # - tx completed */
	spinlock_t send_lock;              /* protect wr_sends */
	atomic_t conn_pend_tx_wr;          /* number of pending tx CDC or IMM wqe
										* - inc when post wqe,
										* - dec on polled tx cqe
										*/
	wait_queue_head_t conn_pend_tx_wq; /* wakeup on no conn_pend_tx_wr */

	atomic_t tx_pushing;         /* nr_threads trying imm_tx push */
	struct delayed_work tx_work; /* retry of ums write_with_imm */

	atomic_t cdc_tx_pushing;         /* nr_threads trying cdc_tx push */
	struct delayed_work cdc_tx_work; /* retry of ums cdc send */

	u32 tx_off; /* base offset in peer rmb */

	struct ums_host_cdc_msg local_rx_ctrl;   /* filled during event_handl.
											  * .prod cf. TCP rcv_nxt
											  * .cons cf. TCP snd_una
											  */
	union ums_host_cursor rx_curs_confirmed; /* confirmed to peer
											  * source of snd_una ?
											  */
	union ums_host_cursor urg_curs; /* points at urgent byte */
	enum ums_urg_state urg_state;
	bool urg_tx_pend;        /* urgent data staged */
	bool urg_rx_skip_pend;   /* indicate urgent oob data read, but previous regular
							  * data still pending
							  */
	char urg_rx_byte;        /* urgent byte */
	bool tx_in_release_sock; /* flush pending tx data in
							  * sock release_cb()
							  */
	atomic_t bytes_to_rcv;   /* arrived data, not yet received */
	atomic_t splice_pending; /* number of spliced bytes
							  * pending processing
							  */
#ifndef ATOMIC64_INIT
	spinlock_t acurs_lock; /* protect cursors */
#endif
	struct work_struct close_work;   /* peer sent some closing */
	struct tasklet_struct rx_tsklet; /* Receiver tasklet for UMS-D */
	u8 rx_off;                       /* receive offset:
									  * 0 for UMS-R, 32 for UMS-D
									  */
	u64 rx_cnt;                      /* rx counter */
	u64 tx_cnt;                      /* tx counter */
	u64 tx_corked_cnt;               /* tx counter with MSG_MORE flag or corked */
	u64 rx_bytes;                    /* rx size */
	u64 tx_bytes;                    /* tx size */
	u64 tx_corked_bytes;             /* tx size with MSG_MORE flag or corked */
	u64 peer_token;                  /* UMS-D token of peer */
	u8 killed : 1;                   /* abnormal termination */
	u8 freed : 1;                    /* normal termiation */
	u8 out_of_sync : 1;              /* out of sync with peer */

	struct ubcore_jfs_wr *wr_write_buf; /* for write when the tx ring buf reverse */

	/* If the tx and rx process accesses the conn after the conn is freed, the system
	 * may crash because the released resources are accessed.
	 * Use conn_tx_rx_refcnt and freed flags to avoid concurrent access conflicts of conn.
	 */
	atomic_t conn_tx_rx_refcnt;
	wait_queue_head_t conn_free_wait; /* wakeup when conn_tx_rx_refcnt == 0 */

	struct ums_conn_jetty_info jetty_info;
};

struct ums_tcp_listen_work {
	struct ums_sock *ums;
	struct work_struct work;
};

struct ums_sock { /* ums sock container */
	struct sock sk;
	struct socket *clcsock; /* internal tcp socket */
	/* original stat_change function */
	void (*clcsk_state_change)(struct sock *sk);
	/* original data_ready function */
	void (*clcsk_data_ready)(struct sock *sk);
	/* original write_space function */
	void (*clcsk_write_space)(struct sock *sk);
	/* original error_report function */
	void (*clcsk_error_report)(struct sock *sk);
	struct ums_connection conn;      /* ums connection */
	struct ums_sock *listen_ums;     /* listen parent */
	struct work_struct connect_work; /* handle non-blocking connect */
	struct ums_tcp_listen_work tcp_listen_works[UMS_MAX_TCP_LISTEN_WORKS];
	/* handle tcp socket accepts */
	atomic_t tcp_listen_work_seq;       /* used to select tcp_listen_works */
	struct work_struct ums_listen_work; /* prepare new accept socket */
	struct work_struct free_work;       /* free ums conn */
	struct list_head accept_q;          /* sockets to be accepted */
	spinlock_t accept_q_lock;           /* protects accept_q */
	bool limit_ums_hs;                  /* put constraint on handshake */
	unsigned int autocorking_size;
	unsigned int ums_buf_type;
	/* enable UMS handshake proposal via tcp fastopen */
	bool ums_fastopen;
	bool use_fallback;      /* fallback to tcp */
	int fallback_rsn;       /* fallback reason */
	u32 peer_diagnosis;     /* decline reason from peer */
	atomic_t queued_ums_hs; /* queued ums handshakes */
	/* original af ops */
	struct inet_connection_sock_af_ops af_ops;
	const struct inet_connection_sock_af_ops *ori_af_ops;
	/* sockopt TCP_DEFER_ACCEPT value */
	int sockopt_defer_accept;
	/* shutdown wr or close started, waiting for unsent data to be sent */
	u8 wait_close_tx_prepared : 1;
	/* whether the ums_sock was successfully negotiated via TCP options. */
	u8 ums_negotiated : 1;
	/* non-blocking connect in flight */
	u8 connect_nonblock : 1;
	/* protects clcsock of a listen socket */
	struct rw_semaphore clcsock_release_lock;
};

struct ums_sys_tuning_config {
	bool ub_token_disable;
};

#endif /* UMS_TYPES_H */
