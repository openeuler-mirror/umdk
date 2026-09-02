/* SPDX-License-Identifier: MIT */
/* Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * URMA 仿真数据面：CQE 生成 + WQE 解析 + 硬件轮询线程。
 * （从 urma_sim_res.c 拆出，保持各源文件 < 1000 行便于评审） */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#include "udma_abi.h"  /* UDMA_JFC_DB_VALID_OWNER_M 等 */
#include "urma_sim_res.h"
#include "urma_sim_exec.h"


static void cqe_set_user_data(struct urma_sim_jfc_cqe *cqe, uint64_t queue_addr)
{
    cqe->user_data_l = (uint32_t)(queue_addr & 0xffffffff);
    cqe->user_data_h = (uint32_t)((queue_addr >> 32) & 0xffffffff);
}

/* 造一个 send CQE（s_r=0）：按 cq_ci 槽位 + owner，填 user_data=queue/entry_idx/byte_cnt/
 * local_id（local_num_h<<16|local_num_l）/is_jetty/remote 字段。 */
/* CQ 槽几何（与真 udma 一致）：实际容量 max(depth,64) 向上 2 幂（provider 消费者
 * 至少按 64 槽轮询，只按请求 depth 回绕会覆盖/永久不可见）。send/recv 共用。 */
static struct urma_sim_jfc_cqe *cq_produce_slot(urma_sim_cq_assoc_t *cq_a,
                                                uint32_t *valid_owner_out)
{
    uint32_t depth = cq_a->depth > 0 ? cq_a->depth : 64;
    uint32_t eff = (depth < 64) ? 64 : depth;
    uint32_t bbcnt = 1;
    while (bbcnt < eff) {
        bbcnt <<= 1;
    }
    uint32_t cq_shift = 0;
    while ((1U << cq_shift) < bbcnt) {
        cq_shift++;
    }
    uint32_t ci = cq_a->cq_ci;
    *valid_owner_out = (ci >> cq_shift) & UDMA_JFC_DB_VALID_OWNER_M;
    return (struct urma_sim_jfc_cqe *)(uintptr_t)(cq_a->cq_addr +
                                                 (uint64_t)(ci & (bbcnt - 1)) * URMA_SIM_CQE_SIZE);
}

static struct urma_sim_jfc_cqe *produce_cqe(urma_sim_cq_assoc_t *cq_a, uint64_t queue_addr,
                                             uint32_t jetty_id, uint32_t entry_idx, uint32_t byte_cnt,
                                             uint8_t cqe_opcode, uint8_t err_status, uint8_t err_substatus,
                                             int is_jetty, uint32_t rmt_idx, uint32_t tpn,
                                             const uint8_t *rmt_eid)
{
    if (cq_a == NULL || cq_a->cq_addr == 0) {
        return NULL;
    }
    (void)pthread_mutex_lock(&g_cq_lock);
    uint32_t valid_owner = 0;
    struct urma_sim_jfc_cqe *cqe = cq_produce_slot(cq_a, &valid_owner);
    struct urma_sim_jfc_cqe local_cqe;
    memset(&local_cqe, 0, sizeof(local_cqe));
    /* 在栈上初始化全量字段，最后带 owner 原子发布——防消费端在环形回绕时读到 owner=0 的半初始化 CQE */
    local_cqe.is_jetty = is_jetty;     /* send CQE：jetty 内嵌 sq=1 / 独立 jfs=0（节 3，
                                   * parse_cqe_for_send 按它还原 jetty 或 jfs 对象） */
    local_cqe.opcode = cqe_opcode & 0x7;   /* hw_cqe_opcode：SEND=0/SEND_WITH_IMM=1/...，send 侧 CQE 用 */
    local_cqe.entry_idx = entry_idx & 0xffff;
    local_cqe.byte_cnt = byte_cnt;
    local_cqe.local_num_l = (uint16_t)(jetty_id & 0xffff);   /* cr->local_id 低 16 位 */
    local_cqe.local_num_h = (jetty_id >> 16) & 0xf;          /* cr->local_id 高 4 位 */
    /* 节 12: remote 字段——cr.remote_id/tpn/rmt_eid 从 CQE 还原，
     * 此前不填 → 对端信息恒 0，cr.remote_id/cr.tpn 无法校验 */
    local_cqe.rmt_idx = rmt_idx & 0xfffff;
    local_cqe.tpn = tpn;
    if (rmt_eid != NULL) {
        memcpy(local_cqe.rmt_eid, rmt_eid, URMA_SIM_EID_SIZE);
    }
    cqe_set_user_data(&local_cqe, queue_addr);   /* parse_cqe_for_send 用来找回 queue */
    /* 异常注入（URMA_SIM_INJECT_STATUS）：err_status 由调用方传入，优先于注入 */
    uint8_t status = (err_status != 0) ? err_status : g_inject_cqe_status;
    if (status != 0) {
        local_cqe.status = status;
        /* (status, substatus) 二元组（节 17 ④）：LOCAL_OP_ERR(2)/REMOTE_OP_ERR(3)
         * 必须带 substatus，否则 get_cr_status 判 is_valid=false → JFC_POLL_ERR */
        local_cqe.substatus = err_substatus;
        SIM_DBG("inject: CQE status=%u substatus=%u (entry_idx=%u)\n",
                local_cqe.status, local_cqe.substatus, entry_idx);
    }
    local_cqe.owner = valid_owner ^ 1;
    cq_a->cq_ci++;
    __sync_synchronize();
    memcpy(cqe, &local_cqe, sizeof(local_cqe));
    (void)pthread_mutex_unlock(&g_cq_lock);
    return cqe;
}

/* 造 recv CQE（s_r=1）：查表依据 is_jetty，local_id=jetty_id，user_data=jfr 指针 */
struct urma_sim_jfc_cqe *produce_recv_cqe(urma_sim_cq_assoc_t *cq_a, uint64_t jfr_addr,
                                                  uint32_t jetty_id, uint32_t rqe_idx, uint32_t byte_cnt,
                                                  uint8_t cqe_opcode, uint64_t imm_data, int is_jetty,
                                                  uint8_t err_status, uint8_t err_substatus,
                                                  uint32_t rmt_idx, uint32_t tpn,
                                                  const uint8_t *rmt_eid)
{
    if (cq_a == NULL || cq_a->cq_addr == 0) {
        return NULL;
    }
    (void)pthread_mutex_lock(&g_cq_lock);
    uint32_t valid_owner = 0;
    struct urma_sim_jfc_cqe *cqe = cq_produce_slot(cq_a, &valid_owner);
    struct urma_sim_jfc_cqe local_cqe;
    memset(&local_cqe, 0, sizeof(local_cqe));
    local_cqe.s_r = 1;                 /* CQE_FOR_RECEIVE=1 */
    local_cqe.is_jetty = is_jetty;     /* recv CQE：对端 JFR 属 jetty(共享)=1 / 独立 jfr=0（节 3，
                                   * parse_cqe_for_recv 按它查 jetty_table 或 jfr_table） */
    local_cqe.opcode = cqe_opcode & 0x7;   /* HW_CQE_OPC_SEND=0/SEND_WITH_IMM=1/SEND_WITH_INV=2/WRITE_WITH_IMM=3 */
    local_cqe.entry_idx = rqe_idx & 0xffff;
    local_cqe.byte_cnt = byte_cnt;
    /* IMM 变体：imm_data 填 data_l/h（urma parse_cqe_for_recv: imm = (data_h<<32)|data_l）。
     * SEND_WITH_INVALID 的 token 也走 data_l（cqe->data_l & inv_mask）。 */
    local_cqe.data_l = (uint32_t)(imm_data & 0xffffffff);
    local_cqe.data_h = (uint32_t)((imm_data >> 32) & 0xffffffff);
    /* local_num = jetty_id：低 16 位 local_num_l，高 4 位 local_num_h（jetty_id 20 位够） */
    local_cqe.local_num_l = (uint16_t)(jetty_id & 0xffff);
    local_cqe.local_num_h = (jetty_id >> 16) & 0xf;
    /* 发送端身份：真 udma 从 recv CQE 恢复 remote_id/tpn（udma_u_jfc.c:755） */
    local_cqe.rmt_idx = rmt_idx & 0xfffff;
    local_cqe.tpn = tpn;
    if (rmt_eid != NULL) {
        /* provider 在 poll_jfc 解析 CQE 时会调用 udma_u_swap_endian128 还原为网络序，
         * 故此处写入 CQE 时统一转换为 128 位硬件小端序 */
        for (int i = 0; i < URMA_SIM_EID_SIZE; i++) {
            ((uint8_t *)local_cqe.rmt_eid)[i] = rmt_eid[URMA_SIM_EID_SIZE - 1 - i];
        }
    }
    /* 节 17 ④: 错误 recv CQE（如对端长度错误 LOCAL_OP_ERR + LOCAL_LENGTH_ERR） */
    if (err_status != 0) {
        local_cqe.status = err_status;
        local_cqe.substatus = err_substatus;
    }
    cqe_set_user_data(&local_cqe, jfr_addr);   /* cr->user_data=&jfr->base */
    local_cqe.owner = valid_owner ^ 1;
    cq_a->cq_ci++;
    __sync_synchronize();
    memcpy(cqe, &local_cqe, sizeof(local_cqe));
    (void)pthread_mutex_unlock(&g_cq_lock);
    return cqe;
}

/* 处理一条 WQE：按 opcode 执行 READ/WRITE/原子/SEND + 造 CQE。
 * 单进程 rmt_addr 即远端真实地址可直接 memcpy；跨进程走 IPC。 */
/* 环形回绕读取：WQE 各字段可能跨队尾（provider 逐字段 wrap 写）——
 * 先按环形平坦复制到栈缓冲，process_wqe 全部用副本。 */
#define URMA_SIM_WQE_MAX_COPY 512   /* 覆盖：ctl_len(≤80) + 8*SGE(128) + inline/原子数据 */

static void wrap_copy(uint8_t *dst, const uint8_t *qbuf, size_t qsz,
                      uint64_t abs_off, size_t n)
{
    while (n > 0) {
        size_t at = (size_t)(abs_off % qsz);
        size_t chunk = qsz - at;
        if (chunk > n) {
            chunk = n;
        }
        memcpy(dst, qbuf + at, chunk);
        dst += chunk;
        abs_off += chunk;
        n -= chunk;
    }
}

static void process_wqe(urma_sim_queue_assoc_t *qa, uint8_t *wqe_buf, uint32_t wqe_idx)
{
    uint8_t wqe_copy[URMA_SIM_WQE_MAX_COPY];
    uint32_t wqe_cnt = (qa->wqe_cnt > 0) ? qa->wqe_cnt : 1;
    size_t qsz = (size_t)wqe_cnt * URMA_SIM_WQEBB;
    uint64_t wqe_abs = (uint64_t)((uint8_t *)wqe_buf - (uint8_t *)(uintptr_t)qa->buf_addr);
    if (wqe_abs >= qsz) {
        wqe_abs %= qsz;   /* 防御：偏移越界时折回 */
    }
    wrap_copy(wqe_copy, (const uint8_t *)(uintptr_t)qa->buf_addr, qsz, wqe_abs,
              sizeof(wqe_copy));
    struct urma_sim_sqe_ctl *wqe = (struct urma_sim_sqe_ctl *)wqe_copy;
    uint8_t opcode = (uint8_t)wqe->opcode;
    /* 远端地址 = (rmt_addr_h << 32) | rmt_addr_l（udma_fill_read/write_sqe 写入）。
     * 单进程下就是对端 va；跨进程下无意义（对端进程指针），改用 rmt_tid + rmt_eid 经 IPC。 */
    uint64_t rmt_addr = ((uint64_t)wqe->rmt_addr_h_or_token_value << 32) |
                        (uint64_t)wqe->rmt_addr_l_or_token_id;
    uint32_t tid = wqe->rmt_jetty_or_seg_id & 0xfffff;
    uint32_t rmt_jetty_id = wqe->rmt_jetty_or_seg_id & 0xfffff;  /* SEND 用：对端 jetty id */
    const uint8_t *rmt_eid = wqe->rmt_eid;   /* 对端 EID（小端硬件序，WQE 存储） */
    uint8_t rmt_eid_net[URMA_SIM_EID_SIZE];  /* 反转为网络序，供资源绑定表匹配 */
    for (int i = 0; i < URMA_SIM_EID_SIZE; i++) {
        rmt_eid_net[i] = rmt_eid[URMA_SIM_EID_SIZE - 1 - i];
    }
    int is_local = urma_sim_ipc_is_local(rmt_eid);   /* 本进程→memcpy；对端→IPC */
    /* ctl_len 随 opcode 变：IMM=64、NOTIFY=80、其余 48；SGE/inline 数据在头之后 */
    uint32_t ctl_len = 48;
    if (opcode == 4) {
        ctl_len = 64;
    } else if (opcode == 5) {
        ctl_len = 80;
    } else if (opcode == 0x19) {
        ctl_len = 56;   /* SQE_WRITE_ATOMICADD_CTL_LEN：inline payload 从 56 起 */
    }
    /* 数据源：inline（flag&0x40）→ 头部后连续区（inline_msg_len）；否则 SGE 列表 */
    uint32_t sge_num = wqe->sge_num;
    const struct urma_sim_wqe_sge *sges =
        (const struct urma_sim_wqe_sge *)((uint8_t *)wqe + ctl_len);
    uint64_t local_va = 0;
    uint32_t local_len = 0;
    if ((wqe->flag & 0x40 /* UDMAWQE_INLINE_EN */) && sge_num == 0) {
        local_va = (uint64_t)(uintptr_t)((uint8_t *)wqe + ctl_len);
        local_len = (uint32_t)wqe->inline_msg_len;
    } else if (sge_num > 0) {
        local_va = sges[0].va;
        local_len = sges[0].length;
    }

    uint32_t done_len = 0;
    uint8_t err_status = 0;   /* 语义错误（RNR 等）→ 错误 CQE，见节 10 */
    uint8_t err_substatus = 0; /* 与 status 组成 (status, substatus) 二元组（节 17 ④） */
    uint32_t imm_jetty_id = rmt_jetty_id; /* FG-04: WRITE_WITH_IMM 的对端 jetty id（默认回退） */
    /* CQE opcode：SEND/IMM/INV/WRITE_IMM 有专门值（parse_cqe 据此恢复
 * cr.opcode + imm/inv）；READ/WRITE/原子走 SEND(0) */
    uint8_t cqe_opcode = 0;   /* HW_CQE_OPC_SEND=0 */
    uint64_t imm_data = 0;    /* IMM 变体的 immediate 数据（填 CQE data_l/h） */
    int has_imm = 0;
    switch (opcode) {
        case 0:  /* SEND（不带 rmt_addr，投递对端 JFR recv 槽；rmt_jetty_or_seg_id=对端 jetty） */
        case 1:  /* SEND_WITH_IMM */
        case 2: { /* SEND_WITH_INVALID */
            /* IMM/INV 复用偏移 40-47 放 imm/token（SQE_SEND_IMM_FIELD），即 rmt_addr 字段 */
            if (opcode == 1) { cqe_opcode = 1; has_imm = 1; imm_data = rmt_addr; }
            if (opcode == 2) { cqe_opcode = 2; imm_data = rmt_addr; }  /* token 走 data_l */
            /* 多 SGE（节 2）：数据分散在 sges[0..sge_num-1]，拼装成连续消息再投递。
             * inline（sge_num=0）时数据在 local_va（队列内副本），直接投递。
             * 零 SGE/零长 SEND 合法（udma_u_jfs.c:518）：同样投递 + 产 byte_cnt=0
             * recv CQE（否则接收方收不到零长完成、recv 槽不消费）。 */
            {
                char *msg = NULL;
                const void *src = NULL;
                uint32_t msg_len = local_len;
                int payload_ok = 1;
                if (sge_num > 1) {
                    /* 按总长分配（u64 累加截断 UINT32_MAX）：32 位累加回绕致越界 */
                    uint64_t send_total64 = 0;
                    for (uint32_t i = 0; i < sge_num; i++) {
                        send_total64 += sges[i].length;
                    }
                    uint32_t send_total = (send_total64 > UINT32_MAX) ?
                                          UINT32_MAX : (uint32_t)send_total64;
                    msg = (char *)malloc(send_total > 0 ? send_total : 1);
                    if (msg == NULL) {
                        payload_ok = 0;
                        err_status = 5;   /* 聚合分配失败：造错误 CQE（防发送端假成功） */
                    } else {
                        char *p = msg;
                        size_t wrote = 0;
                        for (uint32_t i = 0; i < sge_num && wrote < (size_t)send_total; i++) {
                            if (sges[i].length > 0) {
                                if (sges[i].va == 0) {
                                    /* 非法地址但长度非零：访问错误，拒绝发送未初始化内存 */
                                    payload_ok = 0;
                                    err_status = 2;   /* UDMA_CQE_LOCAL_OP_ERR */
                                    err_substatus = 0;
                                    break;
                                }
                                size_t n = sges[i].length;
                                if (n > (size_t)send_total - wrote) {
                                    n = (size_t)send_total - wrote;
                                }
                                memcpy(p, (void *)(uintptr_t)sges[i].va, n);
                                p += n;
                                wrote += n;
                            }
                        }
                        src = msg;
                        msg_len = send_total;
                    }
                } else {
                    src = (void *)(uintptr_t)local_va;   /* 零 SGE 时可能为 NULL */
                }
                if (payload_ok && (src != NULL || msg_len == 0)) {
                    if (is_local) {
                        urma_sim_queue_assoc_t *jfr_qa =
                            urma_sim_jfr_find_by_jetty(rmt_eid_net, rmt_jetty_id);
                        if (jfr_qa != NULL) {
                            if (urma_sim_jfr_deliver_send(jfr_qa, rmt_jetty_id, src, msg_len,
                                                          cqe_opcode, imm_data,
                                                          (uint32_t)qa->id,
                                                          (uint32_t)wqe->tp_id,
                                                          urma_sim_eid_is_valid(qa->eid) ? (const uint8_t *)qa->eid
                                                                                         : NULL) == 0) {
                                done_len = msg_len;
                            } else {
                                /* 无 recv 槽（RNR）：错误 CQE（节 10），不再假绿 */
                                err_status = 4;  /* UDMA_CQE_TRANSACTION_RETRY_COUNTER_ERR */
                            }
                        } else {
                            SIM_DBG("poll: SEND no JFR for jetty=%u\n", rmt_jetty_id);
                            err_status = 4;  /* 对端 JFR 不存在同样视为 RNR */
                        }
                    } else {
                        if (urma_sim_ipc_send(rmt_eid, rmt_jetty_id, src, msg_len, qa->jfc_id,
                                              cqe_opcode, imm_data,
                                              (uint32_t)qa->id,
                                              (uint32_t)wqe->tp_id,
                                              urma_sim_eid_is_valid(qa->eid) ? (const uint8_t *)qa->eid
                                                                             : NULL) == 0) {
                            done_len = msg_len;
                        } else {
                            SIM_DBG("poll: ipc_send fail jetty=%u\n", rmt_jetty_id);
                            err_status = 4;
                        }
                    }
                }
                free(msg);
            }
            break;
        }
        case 6: { /* UDMA_OPCODE_READ=6（从远端 src 读到本端 dst） */
            /* 多 SGE（节 2）：dst 各段依次承接 rmt+off 的数据 */
            uint32_t off = 0;
            if (is_local) {
                for (uint32_t i = 0; i < sge_num; i++) {
                    void *dst = (void *)(uintptr_t)sges[i].va;
                    if (dst != NULL && sges[i].length > 0) {
                        void *src = (void *)(uintptr_t)(rmt_addr + off);
                        if (src != NULL) {
                            memcpy(dst, src, sges[i].length);
                            done_len += sges[i].length;
                        }
                    }
                    off += sges[i].length;
                }
            } else {
                /* 跨进程：多 SGE 合并读回并分发（只读首段会让其余缓冲保持旧数据） */
                if (sge_num > 1) {
                    uint64_t rtd = 0;
                    for (uint32_t i = 0; i < sge_num; i++) rtd += sges[i].length;
                    uint32_t rtotal = (rtd > UINT32_MAX) ? UINT32_MAX : (uint32_t)rtd;
                    char *rbuf = (char *)malloc(rtotal > 0 ? rtotal : 1);
                    if (rbuf != NULL) {
                        int rc_r = urma_sim_ipc_read(rmt_eid, tid, rmt_addr, rbuf, rtotal);
                        if (rc_r == 0) {
                            uint32_t off = 0;
                            for (uint32_t i = 0; i < sge_num; i++) {
                                uint32_t n = sges[i].length;
                                if (n > (uint32_t)rtotal - off) {
                                    n = (uint32_t)rtotal - off;   /* 截断保护 */
                                }
                                if (sges[i].va != 0 && n > 0) {
                                    memcpy((void *)(uintptr_t)sges[i].va, rbuf + off, n);
                                }
                                off += sges[i].length;
                            }
                            done_len = rtotal;
                        } else if (rc_r == URMA_SIM_IPC_RC_LEN_ERR) {
                            SIM_DBG("poll: ipc_read len err tid=%u\n", tid);
                            err_status = 2;
                            err_substatus = 3;
                        } else {
                            SIM_DBG("poll: ipc_read fail tid=%u (link down?)\n", tid);
                            err_status = 5;
                        }
                        free(rbuf);
                    } else {
                        err_status = 5;
                    }
                } else if (local_len > 0) {
                    int rc_r = urma_sim_ipc_read(rmt_eid, tid, rmt_addr,
                                          (void *)(uintptr_t)local_va, local_len);
                    if (rc_r == 0) {
                        done_len = local_len;
                    } else if (rc_r == URMA_SIM_IPC_RC_LEN_ERR) {
                        SIM_DBG("poll: ipc_read len err tid=%u\n", tid);
                        err_status = 2;
                        err_substatus = 3;
                    } else {
                        SIM_DBG("poll: ipc_read fail tid=%u (link down?)\n", tid);
                        err_status = 5;
                    }
                }
            }
            break;
        }
        case 3:  /* WRITE（本端 src → 远端 dst） */
        case 4:  /* WRITE_WITH_IMM（imm@48，对端产 imm recv CQE） */
        case 5: { /* WRITE_WITH_NOTIFY（notify_addr@56/data@64；数据落地后才发布） */
            /* imm/notify 在 WQE 头扩展区；notify 先记录，数据搬运后发布 */
            uint64_t notify_addr = 0;
            uint64_t notify_data = 0;
            if (opcode == 4) {
                has_imm = 1;
                imm_data = *(const uint64_t *)((const uint8_t *)wqe + 48);  /* SQE_WRITE_IMM_FIELD */
                cqe_opcode = 3;  /* HW_CQE_OPC_WRITE_WITH_IMM */
                /* FG-04: WRITE_IMM 对端 jetty id 在 WRITE_IMM_TOKEN_FIELD(56)
                 * 的 token_id（rmt_jetty_or_seg_id 是 seg tid 不能用于查 JFR） */
                imm_jetty_id = 0;
                memcpy(&imm_jetty_id, (const uint8_t *)wqe + 56, sizeof(uint32_t));
            } else if (opcode == 5) {
                /* WRITE_NOTIFY：notify_data 写 notify_addr（门铃）；跨进程不能解引用对端 va
                 * （SIGSEGV）——仅 is_local 写门铃，跨进程走显式错误路径 */
                notify_addr = *(const uint64_t *)((const uint8_t *)wqe + 56); /* SQE_NOTIFY_ADDR_FIELD */
                notify_data = *(const uint64_t *)((const uint8_t *)wqe + 64); /* SQE_NOTIFY_DATA_FIELD */
                /* 注意：notify 写入须在 payload 落地之后（provider 把数据写与
                 * 通知编码为同一复合 WQE），此处只记录，发布点在数据搬运后。 */
            }
            /* 多 SGE 依次搬出；inline（无 SGE 列表，数据在 ctl 头后连续区）显式搬 */
            if (is_local) {
                uint32_t off = 0;
                if (local_len > 0 && sge_num == 0) {
                    void *dst = (void *)(uintptr_t)rmt_addr;
                    if (dst != NULL) {
                        memcpy(dst, (void *)(uintptr_t)local_va, local_len);
                        done_len = local_len;
                    }
                } else {
                    for (uint32_t i = 0; i < sge_num; i++) {
                        void *src = (void *)(uintptr_t)sges[i].va;
                        if (src != NULL && sges[i].length > 0) {
                            void *dst = (void *)(uintptr_t)(rmt_addr + off);
                            if (dst != NULL) {
                                memcpy(dst, src, sges[i].length);
                                done_len += sges[i].length;
                            }
                        }
                        off += sges[i].length;
                    }
                }
                /* WRITE_WITH_IMM：单进程额外产 imm recv CQE（数据已写 seg，不占 recv 槽）；
                 * NOTIFY 不产（门铃即通知）。对端 jetty id 取自 WRITE_IMM_TOKEN_FIELD(56)。 */
                if (has_imm && opcode == 4) {
                    urma_sim_queue_assoc_t *jfr_qa =
                        urma_sim_jfr_find_by_jetty(rmt_eid_net, imm_jetty_id);
                    if (jfr_qa != NULL) {
                        if (urma_sim_jfr_deliver_imm(jfr_qa, imm_jetty_id, cqe_opcode,
                                                     imm_data, (uint32_t)qa->id,
                                                     (uint32_t)wqe->tp_id,
                                                     urma_sim_eid_is_valid(qa->eid) ? (const uint8_t *)qa->eid
                                                                                    : NULL) != 0) {
                            /* 无 recv 槽：imm 通知投递失败 → RNR 错误 CQE（节 10） */
                            err_status = 4;
                        }
                    } else {
                        SIM_DBG("poll: WRITE_IMM no JFR for jetty=%u\n", imm_jetty_id);
                        err_status = 4;
                    }
                }
                /* WRITE_NOTIFY：payload 已落地，此刻才发布（data 可见后再通知） */
                if (opcode == 5 && notify_addr != 0) {
                    *(volatile uint64_t *)(uintptr_t)notify_addr = notify_data;
                }
            } else {
                /* 跨进程写：多 SGE 拼连续载荷一并写 */
                int wrc = -1;
                uint64_t wtd = 0;
                if (sge_num > 1) {
                    for (uint32_t i = 0; i < sge_num; i++) wtd += sges[i].length;
                }
                uint32_t wtotal = (wtd > UINT32_MAX) ? UINT32_MAX : (uint32_t)wtd;
                if (sge_num > 1) {
                    char *wbuf = (char *)malloc(wtotal > 0 ? wtotal : 1);
                    if (wbuf != NULL) {
                        char *wp = wbuf;
                        size_t wrote = 0;
                        for (uint32_t i = 0; i < sge_num && wrote < (size_t)wtotal; i++) {
                            size_t n = sges[i].length;
                            if (n > (size_t)wtotal - wrote) {
                                n = (size_t)wtotal - wrote;
                            }
                            if (sges[i].va != 0 && n > 0) {
                                memcpy(wp, (void *)(uintptr_t)sges[i].va, n);
                                wp += n;
                                wrote += n;
                            } else {
                                wp += sges[i].length;
                            }
                        }
                        wrc = urma_sim_ipc_write(rmt_eid, tid, rmt_addr, wbuf, wtotal);
                        free(wbuf);
                    }
                } else if (local_len > 0) {
                    wrc = urma_sim_ipc_write(rmt_eid, tid, rmt_addr,
                                             (void *)(uintptr_t)local_va, local_len);
                }
                if (wrc == 0) {
                    done_len = (sge_num > 1) ? wtotal : local_len;
                } else if (wrc == URMA_SIM_IPC_RC_LEN_ERR) {
                    SIM_DBG("poll: ipc_write len err tid=%u\n", tid);
                    err_status = 2;   /* UDMA_CQE_LOCAL_OP_ERR */
                    err_substatus = 3; /* UDMA_CQE_REM_RSP_LENGTH_ERR */
                } else {
                    SIM_DBG("poll: ipc_write fail tid=%u\n", tid);
                    err_status = 5;
                }
                /* 跨进程 WRITE_IMM：仅 payload 成功（wrc==0）才发 imm 通知（防双端矛盾） */
                if (has_imm && opcode == 4 && wrc == 0) {
                    if (urma_sim_ipc_write_imm(rmt_eid, imm_jetty_id, cqe_opcode,
                                               imm_data, (uint32_t)qa->id,
                                               (uint32_t)wqe->tp_id,
                                               urma_sim_eid_is_valid(qa->eid) ? (const uint8_t *)qa->eid
                                                                              : NULL) != 0) {
                        err_status = 4;   /* 通知投递失败 → RNR 类错误 */
                    }
                }
                /* 跨进程 WRITE_WITH_NOTIFY（FG-05b）：notify_addr 是对端进程 va，
                 * 未实现前显式错误（不再假成功）。 */
                if (opcode == 5) {
                    SIM_DBG("poll: WRITE_NOTIFY cross-proc notify TODO jetty=%u\n",
                            rmt_jetty_id);
                    err_status = 5;
                }
            }
            break;
        }
        case 7:   /* CAS（远端值==cmp 则换 swap，原值回本端） */
        case 0xb: { /* FAA（远端值+=operand，原值回本端） */
            /* 原子长度=首 SGE length（4/8/16）；WQE：首 SGE va=本端原值槽，
             * wqe+64 起 swap/operand、wqe+64+len 起 cmp（CAS）。 */
            uint32_t atom_len = local_len;   /* 首 SGE length = 原子长度 */
            if (atom_len == 0 || atom_len > 16) {
                done_len = 0;
                break;
            }
            /* 本端 buf（存读到的原值）：首 SGE 的 va = local_va */
            void *local_buf = (void *)(uintptr_t)local_va;
            /* 原子数据在 wqe+64（SQE_ATOMIC_DATA_FIELD） */
            const uint8_t *atom_data = (const uint8_t *)wqe + 64;
            if (is_local) {
                /* 单进程原子：必须用真原子原语（对端轮询/IPC/应用线程可并发改同一
                 * 目标，memcpy+memcmp+store 序列会被插入丢增量/错覆盖） */
                void *rmt = (void *)(uintptr_t)rmt_addr;
                if (rmt == NULL) { done_len = 0; break; }
                if (opcode == 7) {  /* CAS：若远端值==cmp 则换 swap */
                    const uint8_t *swap = atom_data;
                    const uint8_t *cmp = atom_data + atom_len;
                    if (atom_len == 4) {
                        /* CAS 语义：*rmt == cmp → 换 swap。expected 必须用 WR 的
                         * cmp（先读远端值当 expected 会让并发写安全的交换被漏：
                         * 读值≠cmp、随后他人改成 cmp 时不再写 swap——破坏线性化） */
                        uint32_t expected, desired;
                        memcpy(&expected, cmp, 4);
                        memcpy(&desired, swap, 4);
                        __atomic_compare_exchange_n((uint32_t *)rmt, &expected,
                                                    desired, 0, __ATOMIC_SEQ_CST,
                                                    __ATOMIC_RELAXED);
                        memcpy(local_buf, &expected, 4);   /* 原值（失败时已被更新） */
                    } else if (atom_len == 8) {
                        uint64_t expected, desired;
                        memcpy(&expected, cmp, 8);
                        memcpy(&desired, swap, 8);
                        __atomic_compare_exchange_n((uint64_t *)rmt, &expected,
                                                    desired, 0, __ATOMIC_SEQ_CST,
                                                    __ATOMIC_RELAXED);
                        memcpy(local_buf, &expected, 8);
                    } else if (atom_len == 16) {
                        __uint128_t expected, desired;
                        memcpy(&expected, cmp, 16);
                        memcpy(&desired, swap, 16);
                        __atomic_compare_exchange_n((__uint128_t *)rmt, &expected,
                                                    desired, 0, __ATOMIC_SEQ_CST,
                                                    __ATOMIC_RELAXED);
                        memcpy(local_buf, &expected, 16);
                    }
                } else {  /* FAA：远端值 += operand（fetch-add 原子原语） */
                    if (atom_len == 4) {
                        uint32_t op;
                        memcpy(&op, atom_data, 4);
                        uint32_t old = __atomic_fetch_add((uint32_t *)rmt, op,
                                                          __ATOMIC_SEQ_CST);
                        memcpy(local_buf, &old, 4);
                    } else if (atom_len == 8) {
                        uint64_t op;
                        memcpy(&op, atom_data, 8);
                        uint64_t old = __atomic_fetch_add((uint64_t *)rmt, op,
                                                          __ATOMIC_SEQ_CST);
                        memcpy(local_buf, &old, 8);
                    }
                    /* 16 字节 FAA 不支持（check_atomic_len 只 CAS 允许 16） */
                }
                done_len = atom_len;
            } else {
                /* 跨进程：需 IPC OP_ATOMIC（读远端值+条件写+回原值）。TODO。
                 * 现造成功 CQE 但不真做原子（数据未动）。 */
                /* FG-01: 跨进程原子经 IPC 在对端进程执行读-改-写，原值回本端 buf。
                 * 失败 → 错误 CQE（不再 TODO 假成功）。 */
                int rc_a = urma_sim_ipc_atomic(rmt_eid, tid, rmt_addr, opcode, atom_len,
                                         atom_data, (uint8_t *)(uintptr_t)local_va);
                if (rc_a == 0) {
                    done_len = atom_len;
                } else if (rc_a == URMA_SIM_IPC_RC_LEN_ERR) {
                    /* 远端长度错误：REM_RSP_LENGTH_ERR（非链路失败） */
                    SIM_DBG("poll: atomic len err opcode=%u tid=%u\n", opcode, tid);
                    err_status = 2;   /* UDMA_CQE_LOCAL_OP_ERR */
                    err_substatus = 3; /* UDMA_CQE_REM_RSP_LENGTH_ERR */
                } else {
                    SIM_DBG("poll: atomic cross-proc fail opcode=%u tid=%u\n", opcode, tid);
                    err_status = 5;
                }
            }
            break;
        }
        case 0x19: { /* WRITE_WITH_ATOMICSTORE_ADD：payload 写 + 原子加复合。
             * 字段：写目标@24、原子目标@40、加数@48（非 payload）、本地 payload
             * 地址@56、长度=(sge_num&0xff)|(write_len<<8)，inline 在 ctl 后 */
            uint64_t waddr = *(const uint64_t *)((const uint8_t *)wqe + 24);
            uint64_t aaddr = *(const uint64_t *)((const uint8_t *)wqe + 40);
            uint64_t aval  = *(const uint64_t *)((const uint8_t *)wqe + 48);
            uint32_t wlen = 0;
            const uint8_t *psrc = NULL;
            if ((wqe->flag & 0x40 /* INLINE_EN */) && sge_num == 0) {
                psrc = (const uint8_t *)(uintptr_t)local_va;   /* inline 数据 */
                wlen = (uint32_t)wqe->inline_msg_len;
            } else {
                wlen = ((uint32_t)wqe->sge_num & 0xff) | ((uint32_t)wqe->write_len << 8);
                psrc = (const uint8_t *)(uintptr_t)(*(const uint64_t *)((const uint8_t *)wqe + 56));
            }
            if (is_local) {
                if (waddr != 0 && psrc != NULL && wlen > 0) {
                    memcpy((void *)(uintptr_t)waddr, psrc, wlen);
                }
                if (aaddr != 0) {
                    uint32_t o4; uint64_t o8;
                    memcpy(&o4, &aval, 4);
                    memcpy(&o8, &aval, 8);
                    if (wlen == 4) {
                        (void)__atomic_fetch_add((uint32_t *)(uintptr_t)aaddr, o4,
                                                 __ATOMIC_SEQ_CST);
                    } else {
                        (void)__atomic_fetch_add((uint64_t *)(uintptr_t)aaddr, o8,
                                                 __ATOMIC_SEQ_CST);
                    }
                }
                done_len = wlen;
            } else {
                /* 跨进程复合原子：未实现 → 显式错误（不再假成功吞掉） */
                SIM_DBG("poll: ATOMICSTORE_ADD cross-proc TODO\n");
                err_status = 5;
            }
            break;
        }
        case 0x11: { /* UDMA_OPCODE_NOP=0x11：no-op，不搬数据只占位产 CQE */
            done_len = 0;
            break;
        }
        default:
            /* 未知 opcode：显式错误 CQE（不再按成功吞掉——未实现的 opcode
             * 应用应收到失败而非静默假绿） */
            SIM_DBG("poll: unknown opcode=%u\n", opcode);
            err_status = 5;
            break;
    }
    SIM_DBG("poll: WQE idx=%u opcode=%u tid=%u local_va=%lx len=%u rmt=%lx %s cqe_op=%u imm=%u/%lx\n",
            wqe_idx, opcode, tid, (unsigned long)local_va, local_len, (unsigned long)rmt_addr,
            is_local ? "local" : "ipc", cqe_opcode, has_imm, (unsigned long)imm_data);

    /* 造 CQE 写到关联的 CQ。entry_idx=wqe_idx（pi），让真 udma 更新 queue->ci */
    /* complete_enable（⑥）：bit5=0x20 时抑制 send CQE（cq moderation，perftest
     * cq_mod=100 默认置位规律）。不影响数据搬运与队列推进（ci/wrid 照常）。 */
    if (wqe->flag & 0x20 /* complete_enable */) {
        urma_sim_cq_assoc_t *cq_a = urma_sim_cq_assoc_find(qa->jfc_id);
        if (cq_a != NULL) {
            produce_cqe(cq_a, qa->jetty_addr, qa->id, wqe_idx, done_len, cqe_opcode, err_status,
                        err_substatus, qa->is_jetty,
                        wqe->rmt_jetty_or_seg_id & 0xfffff,   /* 对端 jetty/jfr id */
                        (uint32_t)wqe->tp_id,                 /* 对端 tpn */
                        wqe->rmt_eid);                        /* 对端 eid */
        } else {
            SIM_DBG("poll: no CQ for jfc_id=%u, CQE dropped\n", qa->jfc_id);
        }
    }
}

/* 复刻真 udma get_wqebb_cnt：WQE 占几个 64B WQEBB（inline=(ctl+len-1)/64+1，
 * NOP/ATOMICSTORE_ADD=1，其余=(ctl+(sge_num-1)*16)/64+1，CAS/FAA sge_num=2） */
static uint32_t sim_get_wqebb_cnt(const struct urma_sim_sqe_ctl *wqe)
{
    uint8_t opcode = (uint8_t)wqe->opcode;
    uint32_t ctl_len = 48;  /* SQE_NORMAL_CTL_LEN */
    if (opcode == 4) {       /* UDMA_OPCODE_WRITE_WITH_IMM */
        ctl_len = 64;        /* SQE_WRITE_IMM_CTL_LEN */
    } else if (opcode == 5) { /* UDMA_OPCODE_WRITE_WITH_NOTIFY */
        ctl_len = 80;        /* SQE_WRITE_NOTIFY_CTL_LEN */
    }
    if ((opcode == 0 || opcode == 1 || opcode == 2 || opcode == 3 ||
         opcode == 4 || opcode == 5) && (wqe->flag & 0x40 /* UDMAWQE_INLINE_EN */)) {
        /* inline：数据在 ctl_len 起，长度 = inline_msg_len */
        return (ctl_len + (uint32_t)wqe->inline_msg_len - 1) / 64 + 1;
    }
    if (opcode == 0x11) {    /* UDMA_OPCODE_NOP */
        return 1;            /* NOP_WQEBB_CNT */
    }
    if (opcode == 0x19) {    /* UDMA_OPCODE_WRITE_WITH_ATOMICSTORE_ADD */
        return 1;            /* WRITE_WITH_ATOMICSTORE_ADD_WQEBB_CNT */
    }
    uint32_t sge_num = wqe->sge_num;
    if (opcode == 7 || opcode == 0xb) {  /* UDMA_OPCODE_CAS / UDMA_OPCODE_FAA */
        sge_num = 2;         /* UDMA_ATOMIC_SGE_NUM(1) + 1 */
    }
    if (sge_num == 0) {
        sge_num = 1;
    }
    return (ctl_len + (sge_num - 1) * 16) / 64 + 1;
}

/* 处理 pi_seen..pi-1 的 WQE：环形索引（pi&mask，WQEBB=64），步进按 sim_get_wqebb_cnt
 * （多块 WQE 按 1 步进会让后续 WQE 错位解析）。 */
static void process_queue(urma_sim_queue_assoc_t *qa)
{
    if (qa->db_addr == 0 || qa->buf_addr == 0) {
        return;
    }
    volatile uint32_t *pi_ptr = (volatile uint32_t *)(uintptr_t)(qa->db_addr + URMA_SIM_DOORBELL_OFFSET);
    uint32_t pi = *pi_ptr;
    if (pi == qa->pi_seen) {
        return;  /* 无变化 */
    }
    /* 处理 pi_seen..pi-1 的 WQE：环形索引（WQEBB=64），步进按 sim_get_wqebb_cnt */
    uint32_t mask = (qa->wqe_cnt > 0) ? (qa->wqe_cnt - 1) : 0;
    size_t qsz = ((size_t)qa->wqe_cnt > 0 ? (size_t)qa->wqe_cnt : 1) * URMA_SIM_WQEBB;
    while (qa->pi_seen != pi) {
        uint32_t idx = qa->pi_seen & mask;
        uint8_t *wqe = (uint8_t *)(uintptr_t)(qa->buf_addr + (uint64_t)idx * URMA_SIM_WQEBB);
        process_wqe(qa, wqe, idx);
        /* pi_seen 步进按该 WQE 的 wqebb_cnt（inline/IMM/NOTIFY/≥2 SGE/CAS/FAA 占多块）。
         * ctl 头也可能跨队尾，先环形复制 80B 再算步进（与 process_wqe 的 wrap 一致）。 */
        uint8_t hdr_copy[80];
        wrap_copy(hdr_copy, (const uint8_t *)(uintptr_t)qa->buf_addr, qsz,
                  (uint64_t)idx * URMA_SIM_WQEBB, sizeof(hdr_copy));
        uint32_t step = sim_get_wqebb_cnt((struct urma_sim_sqe_ctl *)hdr_copy);
        qa->pi_seen += step;
    }
}

static atomic_int g_hw_thread_run = 0;
static pthread_t g_hw_thread;
/* ⑦B: 轮询间隔（us）可配置——URMA_SIM_POLL_US 环境变量（默认 100）。
 * 时延测试可调小（真实硬件中断驱动是微秒级），性能测试可调大。 */
static uint32_t g_sim_poll_us = 100;

static void *urma_sim_hw_thread(void *arg)
{
    (void)arg;
    while (atomic_load(&g_hw_thread_run)) {
        for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
            if (!g_sim_queue_assoc[i].in_use || g_sim_queue_assoc[i].db_addr == 0) {
                continue;
            }
            if (g_sim_queue_assoc[i].q_type == 1) {
                /* JFR recv 队列：扫 sw_db(pi) 变化，吸新 post 的 recv 进 pending 队列（供 SEND 取用） */
                jfr_refill_pending(&g_sim_queue_assoc[i]);
            } else {
                /* sq 发送队列：扫 doorbell pi 变化，解 WQE 执行 READ/WRITE/SEND */
                process_queue(&g_sim_queue_assoc[i]);
            }
        }
        usleep(g_sim_poll_us);
    }
    return NULL;
}

void urma_sim_hw_start(void)
{
    if (atomic_exchange(&g_hw_thread_run, 1) != 0) {
        return; /* 已启动 */
    }
    const char *poll_us = getenv("URMA_SIM_POLL_US");
    if (poll_us != NULL && poll_us[0] != '\0') {
        long v = strtol(poll_us, NULL, 0);
        if (v > 0 && v <= 1000000) {
            g_sim_poll_us = (uint32_t)v;
        }
    }
    pthread_create(&g_hw_thread, NULL, urma_sim_hw_thread, NULL);
}
