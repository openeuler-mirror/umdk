/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __UDMA_U_CTL_H__
#define __UDMA_U_CTL_H__

#include <stdbool.h>
#include "urma_types.h"

#define REDUCE_OPCODE_MIN 8
#define REDUCE_OPCODE_MAX 11
#define REDUCE_DATA_TYPE_MAX 9
#define PARTITION_ALIGNMENT 0xfff
#define UDMA_USER_CTL_QUERY_TP_SPORT 9

struct udma_u_que_cfg_ex {
	uint32_t buff_size;
	void *buff;
};

union udma_jfr_flag {
	struct {
		uint32_t idxq_cstm  : 1;
		uint32_t rq_cstm    : 1;
		uint32_t swdb_cstm    : 1;
		uint32_t swdb_ctl_cstm :1;
		uint32_t reserved       : 28;
	} bs;
	uint32_t value;
};

struct udma_u_jfr_cstm_cfg {
	union udma_jfr_flag flag;
	struct udma_u_que_cfg_ex idx_que;
	struct udma_u_que_cfg_ex rq;
	uint32_t *sw_db;
};

struct udma_u_jfr_cfg_ex {
	urma_jfr_cfg_t base_cfg;
	struct udma_u_jfr_cstm_cfg cstm_cfg;
};

union udma_jfs_flag {
	struct {
		uint32_t sq_cstm : 1;
		uint32_t db_cstm : 1;
		uint32_t db_ctl_cstm : 1;
		uint32_t reserved : 29;
	} bs;
	uint32_t value;
};

struct udma_u_jfs_cstm_cfg {
	union udma_jfs_flag flag;
	struct udma_u_que_cfg_ex sq;
	uint32_t tgid;
};

enum udma_u_jetty_type {
	UDMA_U_CACHE_LOCK_DWQE_JETTY_TYPE,
	UDMA_U_CCU_JETTY_TYPE,
	UDMA_U_NORMAL_JETTY_TYPE,
};

struct udma_u_jfs_cfg_ex {
	uint32_t id;
	urma_jfs_cfg_t base_cfg;
	struct udma_u_jfs_cstm_cfg cstm_cfg;
	enum udma_u_jetty_type jetty_type;
	bool pi_type;
	uint32_t sqebb_num;
};

struct udma_u_jetty_cfg_ex {
	urma_jetty_cfg_t base_cfg;
	struct udma_u_jfr_cstm_cfg jfr_cstm; /* control noshare jfr of jetty */
	struct udma_u_jfs_cstm_cfg jfs_cstm; /* control jfs of jetty */
	enum udma_u_jetty_type jetty_type;
	bool pi_type;
	uint32_t sqebb_num;
};

enum udma_u_jfc_type {
	UDMA_U_NORMAL_JFC_TYPE,
	UDMA_U_STARS_JFC_TYPE,
	UDMA_U_CCU_JFC_TYPE,
};

struct udma_u_jfc_cfg_ex {
	urma_jfc_cfg_t base_cfg;
	enum udma_u_jfc_type jfc_mode;
};

struct udma_u_jfs_wr_ex {
	urma_jfs_wr_t wr;
	bool reduce_en;
	uint8_t reduce_opcode;
	uint8_t reduce_data_type;
};

struct udma_u_wr_ex {
	bool is_jetty;
	bool db_en;
	union {
		urma_jfs_t *jfs;
		urma_jetty_t *jetty;
	};
	struct udma_u_jfs_wr_ex *wr;
	struct udma_u_jfs_wr_ex **bad_wr;
};

struct udma_u_post_info {
	uint64_t *dwqe_addr;
	void volatile *db_addr;
	uint64_t *ctrl;
	uint32_t pi;
};

struct udma_u_update_ci {
	uint16_t ci; /* entry_idx parsed from the CQE, only 16 bits. */
	bool is_jetty;
	urma_jfs_t *jfs;
	urma_jetty_t *jetty;
};

struct udma_u_jetty_info {
	urma_jetty_t *jetty;
	void *dwqe_addr;
	void *db_addr;
};

struct udma_u_jfs_info {
	urma_jfs_t *jfs;
	void *dwqe_addr;
	void *db_addr;
};

struct udma_u_tp_sport_in {
	uint32_t tpn;
};

struct udma_u_tp_sport_out {
	uint32_t data_udp_srcport;
	uint32_t ack_udp_srcport;
};

enum udma_u_user_ctl_opcode {
	UDMA_U_USER_CTL_CREATE_JFR_EX,
	UDMA_U_USER_CTL_DELETE_JFR_EX,
	UDMA_U_USER_CTL_CREATE_JFS_EX,
	UDMA_U_USER_CTL_DELETE_JFS_EX,
	UDMA_U_USER_CTL_CREATE_JFC_EX,
	UDMA_U_USER_CTL_DELETE_JFC_EX,
	UDMA_U_USER_CTL_CREATE_JETTY_EX,
	UDMA_U_USER_CTL_DELETE_JETTY_EX,
	UDMA_U_USER_CTL_POST_WR,
	UDMA_U_USER_CTL_UPDATE_CI,
	UDMA_U_USER_CTL_QUERY_UE_INFO,
	UDMA_U_USER_CTL_QUERY_TP_SPORT,
	UDMA_U_USER_CTL_QUERY_CQE_AUX_INFO,
	UDMA_U_USER_CTL_QUERY_AE_AUX_INFO,
	UDMA_U_USER_CTL_MAX,
};

struct udma_u_ue_info {
	uint32_t ue_id;
	uint32_t chip_id;
	uint32_t die_id;
};

struct udma_u_cqe_info_in {
	enum urma_cr_status status;
	uint8_t s_r;
	uint16_t rsv_bitmap;
	uint32_t rsvd[8];
};

enum udma_u_cqe_aux_info_type {
	TPP2TQEM_WR_CNT,
	DEVICE_RAS_STATUS_2,
	RXDMA_WR_PAYL_AXI_ERR,
	RXDMA_HEAD_SPLIT_ERR_FLAG0,
	RXDMA_HEAD_SPLIT_ERR_FLAG1,
	RXDMA_HEAD_SPLIT_ERR_FLAG2,
	RXDMA_HEAD_SPLIT_ERR_FLAG3,
	TP_RCP_INNER_ALM_FOR_CQE,
	TWP_AE_DFX_FOR_CQE,
	PA_OUT_PKT_ERR_CNT,
	TP_DAM_AXI_ALARM,
	TP_DAM_VFT_BT_ALARM,
	TP_EUM_AXI_ALARM,
	TP_EUM_VFT_BT_ALARM,
	TP_TPMM_AXI_ALARM,
	TP_TPMM_VFT_BT_ALARM,
	TP_TPGCM_AXI_ALARM,
	TP_TPGCM_VFT_BT_ALARM,
	TWP_ALM,
	TP_RWP_INNER_ALM_FOR_CQE,
	TWP_DFX21,
	LQC_TA_RNR_TANACK_CNT,
	FVT,
	RQMT0,
	RQMT1,
	RQMT2,
	RQMT3,
	RQMT4,
	RQMT5,
	RQMT6,
	RQMT7,
	RQMT8,
	RQMT9,
	RQMT10,
	RQMT11,
	RQMT12,
	RQMT13,
	RQMT14,
	RQMT15,
	PROC_ERROR_ALM,
	LQC_TA_TIMEOUT_TAACK_CNT,
	TP_RRP_ERR_FLG_0_FOR_CQE,
	MAX_CQE_AUX_INFO_TYPE_NUM
};

struct udma_u_cqe_aux_info_out {
	enum udma_u_cqe_aux_info_type *aux_info_type;
	uint32_t *aux_info_value;
	uint32_t aux_info_num;
	uint32_t rsv_bitmap;
	uint32_t rsvd[8];
};

struct udma_u_ae_info_in {
	uint32_t event_type;
	uint32_t rsv_bitmap;
	uint32_t rsvd[8];
};

enum udma_u_ae_aux_info_type {
	TP_RRP_FLUSH_TIMER_PKT_CNT,
	TPP_DFX5,
	TWP_AE_DFX_FOR_AE,
	TP_RRP_ERR_FLG_0_FOR_AE,
	TP_RRP_ERR_FLG_1,
	TP_RWP_INNER_ALM_FOR_AE,
	TP_RCP_INNER_ALM_FOR_AE,
	LQC_TA_TQEP_WQE_ERR,
	LQC_TA_CQM_CQE_INNER_ALARM,
	MAX_AE_AUX_INFO_TYPE_NUM
};

struct udma_u_ae_aux_info_out {
	enum udma_u_ae_aux_info_type *aux_info_type;
	uint32_t *aux_info_value;
	uint32_t aux_info_num;
};

struct udma_u_fe_info {
	uint32_t rsv_bitmap;
	uint32_t rsvd[7];
};

#endif /* __UDMA_U_CTL_H__ */
