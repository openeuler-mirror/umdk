/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * exec 层专用：WQE/CQE 位域镜像（sqe_ctl/jfc_cqe）与 IPC 客户端声明。
 * 数据层（关联表/表 extern/函数声明）见 urma_sim_res.h（res 层提供）。
 */
#ifndef URMA_SIM_EXEC_H
#define URMA_SIM_EXEC_H

#include "urma_sim_res.h"

/* === 跨进程 IPC：unix socket（路径含 eid），对端线程代执行内存操作 === */

/* 在 create_context 拿到本进程 eid 后调：起后台 socket 线程，listen 路径含 eid。
 * 幂等（已起则 no-op）。eid 为 16 字节。 */
void urma_sim_ipc_start(const uint8_t *eid /* 16 bytes */);

/* 判断 rmt_eid 是不是本进程。是→走单进程 memcpy 路径；否→走跨进程 IPC。
 * eid 为 16 字节。返回 1=本进程，0=对端。 */
int urma_sim_ipc_is_local(const uint8_t *rmt_eid /* 16 bytes */);

/* IPC 客户端返回：0 成功；-1 链路/协议失败（ACK_TIMEOUT 类）；
 * -2 = 远端长度错误（须造 REM_RSP_LENGTH_ERR CQE，勿折叠成链路失败） */
#define URMA_SIM_IPC_RC_LEN_ERR (-2)

/* 跨进程读：向对端请求读 tid 对应 seg，rmt_addr 为远端地址（对端按段内偏移
 * off=rmt_addr-seg.va 定位），数据写 local_buf。0 成功，<0 失败。 */
int urma_sim_ipc_read(const uint8_t *rmt_eid, uint32_t tid, uint64_t rmt_addr,
                      void *local_buf, uint32_t len);

/* 跨进程写：local_buf → 对端 tid seg（rmt_addr 按段内偏移定位）。0/-<0。 */
int urma_sim_ipc_write(const uint8_t *rmt_eid, uint32_t tid, uint64_t rmt_addr,
                       const void *local_buf, uint32_t len);

/* === 跨进程 SEND：发 {jetty_id,data,len}，对端投进其 JFR recv 槽+造 recv CQE === */
int urma_sim_ipc_send(const uint8_t *rmt_eid, uint32_t jetty_id,
                      const void *data, uint32_t len, uint32_t src_jfc_id,
                      uint8_t cqe_opcode, uint64_t imm_data,
                      uint32_t src_jetty_id, uint32_t src_tpn,
                      const uint8_t *src_eid);

/* FG-05: 跨进程 WRITE_WITH_IMM 的 imm 通知投递（对端产 imm recv CQE，不写 recv 槽）。
 * 返回 0 成功，<0 失败。 */
int urma_sim_ipc_write_imm(const uint8_t *rmt_eid, uint32_t jetty_id,
                           uint8_t cqe_opcode, uint64_t imm_data,
                           uint32_t src_jetty_id, uint32_t src_tpn,
                           const uint8_t *src_eid);

/* FG-01: 跨进程 CAS/FAA（对端执行原子读改写，原值回 local_buf） */
int urma_sim_ipc_atomic(const uint8_t *rmt_eid, uint32_t tid, uint64_t rmt_addr,
                        uint8_t opcode, uint32_t len, const uint8_t *data,
                        uint8_t *local_buf);



/* WQE/CQE 位域结构镜像（独立于 udma 头，避免 include 链断） */
struct urma_sim_sqe_ctl {
    uint32_t sqe_bb_idx : 16;       /* off 0 */
    uint32_t flag : 7;
    uint32_t udf_flag : 1;
    uint32_t rsv0 : 3;
    uint32_t nf : 1;
    uint32_t token_en : 1;
    uint32_t rmt_jetty_type : 2;
    uint32_t owner : 1;             /* off 3 */
    uint32_t target_hint : 8;       /* off 4 */
    uint32_t opcode : 8;            /* off 5 */
    uint32_t rsv1 : 6;
    uint32_t inline_msg_len : 10;   /* off 7 */
    uint32_t tp_id : 24;            /* off 8 */
    uint32_t sge_num : 8;           /* off 11 */
    uint32_t rmt_jetty_or_seg_id : 20;  /* off 12 */
    uint32_t write_len : 10;
    uint32_t rsv2 : 2;              /* off 15 */
    uint8_t rmt_eid[URMA_SIM_EID_SIZE];  /* off 16-32 */
    uint32_t rmt_token_value;       /* off 32 */
    uint32_t udf_type : 8;          /* off 36 */
    uint32_t reduce_data_type : 4;
    uint32_t reduce_opcode : 4;
    uint32_t rsv3 : 16;             /* off 39 */
    uint32_t rmt_addr_l_or_token_id;     /* off 40 */
    uint32_t rmt_addr_h_or_token_value;  /* off 44 */
};  /* sizeof = 48 */
_Static_assert(sizeof(struct urma_sim_sqe_ctl) == 48, "sqe_ctl size mismatch");
/* opcode/rmt_jetty 等是位域，C 标准/GCC 不允许对位域取 offsetof（取地址非法），
 * 故无法用 _Static_assert 校位域偏移。布局靠 sizeof + 非位域成员锚点校验：
 * rmt_addr_l_or_token_id 是 sqe_ctl 内最后一个普通 uint32 成员（非位域），@40。 */
_Static_assert(offsetof(struct urma_sim_sqe_ctl, rmt_addr_l_or_token_id) == 40, "rmt_addr_l off");

struct urma_sim_jfc_cqe {
    uint32_t s_r : 1;          /* off 0 */
    uint32_t is_jetty : 1;
    uint32_t owner : 1;       /* bit2 — get_next_cqe 用 owner^valid_owner==0 判有效 */
    uint32_t inline_en : 1;
    uint32_t opcode : 3;
    uint32_t fd : 1;
    uint32_t rsv : 8;
    uint32_t substatus : 8;
    uint32_t status : 8;       /* off 3 — UDMA_CQE_SUCCESS=0 */
    uint32_t entry_idx : 16;   /* off 4 */
    uint32_t local_num_l : 16; /* off 6 */
    uint32_t local_num_h : 4;  /* off 8 */
    uint32_t rmt_idx : 20;
    uint32_t rsv1 : 8;         /* off 11 */
    uint32_t tpn : 24;         /* off 12 */
    uint32_t rsv2 : 8;         /* off 15 */
    uint32_t byte_cnt;         /* off 16 */
    uint32_t user_data_l;      /* off 20 */
    uint32_t user_data_h;      /* off 24 */
    uint32_t rmt_eid[4];       /* off 28 */
    uint32_t data_l;           /* off 44 */
    uint32_t data_h;           /* off 48 */
    uint32_t inline_data[3];   /* off 52 */
};  /* sizeof = 64 */
_Static_assert(sizeof(struct urma_sim_jfc_cqe) == 64, "jfc_cqe size mismatch");
/* 位域不取 offsetof，锚点用非位域成员（同 res 层旧校验） */
_Static_assert(offsetof(struct urma_sim_jfc_cqe, user_data_l) == 20, "user_data_l off");
_Static_assert(offsetof(struct urma_sim_jfc_cqe, user_data_h) == 24, "user_data_h off");
#endif /* URMA_SIM_EXEC_H */
