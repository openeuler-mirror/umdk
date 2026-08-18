/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * 方式 1 核心实现：拦 mmap → 假 doorbell/queue/cq 内存 → 轮询线程解析 WQE + memcpy + 造 CQE。
 *
 * 真 udma provider 代码原样跑，sim 只在它 mmap(dev_fd, offset) 时给假地址。
 * 真 udma 把 WQE 写进假 queue、把 pi 写进假 doorbell；sim 轮询线程发现 pi 变化，
 * 解析 WQE（udma_jfs_sqe_ctl 位域）执行 READ/WRITE memcpy，再往假 cq 写 CQE
 * （udma_u_jfc_cqe 位域，对齐 parse_cqe_for_send）。
 */

#include "urma_sim_res.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdatomic.h>

#include "urma_cmd.h"      /* urma_cmd_udrv_priv_t */
#include "udma_abi.h"      /* udma_create_jetty_ucmd（create 时 udata 传的 cmd，含 jetty_addr/buf_addr/db_addr） */

/* WQEBB/CQE_SIZE（cq_assoc_register 用 CQE_SIZE 推 depth，早于位域段） */
#define URMA_SIM_WQEBB 64
#define URMA_SIM_CQE_SIZE 64

/* udma_wqe_sge：length + token_id + va = 16 字节 */

/* === 假内存映射表 === */
urma_sim_mmap_region_t g_sim_mmap_regions[URMA_SIM_MMAP_MAX] = {0};

/* munmap 拦截命中后释放槽位：匿名映射由拦截层 real_munmap 真释放， */
void urma_sim_mmap_free(void *addr)
{
    if (addr == NULL) {
        return;
    }
    for (int i = 0; i < URMA_SIM_MMAP_MAX; i++) {
        if (g_sim_mmap_regions[i].in_use &&
            g_sim_mmap_regions[i].addr == addr) {
            g_sim_mmap_regions[i].in_use = 0;
            return;
        }
    }
}

int urma_sim_mmap_decode_offset(off_t offset, int page_size, uint32_t *cmd, uint32_t *idx)
{
    if (page_size <= 0) {
        return -1;
    }
    unsigned long v = (unsigned long)(offset / page_size);
    *cmd = (uint32_t)(v & 0xf);
    *idx = (uint32_t)((v >> 4) & 0xfffffff);
    return 0;
}

/* 找空闲 region 槽 */
static urma_sim_mmap_region_t *find_free_region(void)
{
    for (int i = 0; i < URMA_SIM_MMAP_MAX; i++) {
        if (!g_sim_mmap_regions[i].in_use) {
            return &g_sim_mmap_regions[i];
        }
    }
    return NULL;
}

void *urma_sim_mmap_alloc(int dev_fd, size_t size, uint32_t cmd, uint32_t idx)
{
    (void)dev_fd;
    urma_sim_mmap_region_t *r = find_free_region();
    if (r == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    /* 用系统调用直接 mmap，避开 LD_PRELOAD 符号解析（本库拦截 mmap， */
    void *p = (void *)syscall(SYS_mmap, NULL, size,
                              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    r->addr = p;
    r->size = size;
    r->cmd = cmd;
    r->idx = idx;
    r->in_use = 1;
    return p;
}

urma_sim_mmap_region_t *urma_sim_mmap_find(void *addr)
{
    if (addr == NULL) {
        return NULL;
    }
    for (int i = 0; i < URMA_SIM_MMAP_MAX; i++) {
        if (g_sim_mmap_regions[i].in_use) {
            char *base = (char *)g_sim_mmap_regions[i].addr;
            char *end = base + g_sim_mmap_regions[i].size;
            if ((char *)addr >= base && (char *)addr < end) {
                return &g_sim_mmap_regions[i];
            }
        }
    }
    return NULL;
}

int urma_sim_fd_is_cdev(int fd)
{
    urma_sim_fd_t *e = urma_sim_fd_get(fd);
    return e != NULL && e->type == URMA_SIM_FD_CDEV;
}

/* === queue 关联表 === */
urma_sim_queue_assoc_t g_sim_queue_assoc[URMA_SIM_QUEUE_MAX] = {0};

/* jetty→jfr 共享绑定表（节 3）：类型/宏/表声明前移到文件靠前（release_by_handle
 * 释放 queue assoc 时要同步清绑定，防止 ID 复用后被路由到旧 JFR）。 */
typedef struct {
    uint8_t eid[16];   /* 设备维度：Jetty/JFR 标识 = (eid, uasid, id)（urma_types.h:450） */
    uint32_t jetty_id;
    uint32_t jfr_id;
    int in_use;
} urma_sim_jfr_bind_t;

#define URMA_SIM_JFR_BIND_MAX 512
static urma_sim_jfr_bind_t g_sim_jfr_bind[URMA_SIM_JFR_BIND_MAX] = {0};

/* 并发保护（节 7）：hw 线程（jfr_refill_pending/process_queue）与 IPC 线程
 */
pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_cq_lock = PTHREAD_MUTEX_INITIALIZER;

/* === 异常注入（错误 CQE 测试用）===
 */
uint8_t g_inject_cqe_status = 0;

int urma_sim_queue_assoc_register(uint64_t udata_data)
{
    if (udata_data == 0) {
        return -1;
    }
    urma_cmd_udrv_priv_t *udata = (urma_cmd_udrv_priv_t *)(uintptr_t)udata_data;
    if (udata->in_addr == 0 || udata->in_len < sizeof(struct udma_create_jetty_ucmd)) {
        return -1;
    }
    const struct udma_create_jetty_ucmd *cmd = (const struct udma_create_jetty_ucmd *)(uintptr_t)udata->in_addr;
    for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
        if (!g_sim_queue_assoc[i].in_use) {
            g_sim_queue_assoc[i].id = 0;
            g_sim_queue_assoc[i].is_jetty = 0;
            g_sim_queue_assoc[i].eid_valid = 0;
            g_sim_queue_assoc[i].jetty_addr = cmd->jetty_addr;
            g_sim_queue_assoc[i].buf_addr = cmd->buf_addr;
            g_sim_queue_assoc[i].db_addr = 0;
            g_sim_queue_assoc[i].pi_seen = 0;
            g_sim_queue_assoc[i].in_use = 1;
            /* 区分 sq/rq：CREATE_JFR 的 ucmd 带 idx_addr（索引队列），idx_addr!=0 → rq。
             * CREATE_JETTY/JFS 的 idx_addr=0（sq 不用索引队列）。rq 记 JFR 字段供 SEND 用。 */
            if (cmd->idx_addr != 0) {
                g_sim_queue_assoc[i].q_type = 1;   /* rq（JFR 接收队列） */
                g_sim_queue_assoc[i].max_sge = cmd->buf_len; /* 借 buf_len 暂存？否：buf_len 是 rq.qbuf_size。
 */
                g_sim_queue_assoc[i].max_sge = 0;  /* 待 urma_sim_jfr_set_recv_geom 补 */
                g_sim_queue_assoc[i].wqe_shift = 0;
                g_sim_queue_assoc[i].wqe_cnt = 0;
                g_sim_queue_assoc[i].idx_addr = cmd->idx_addr;
                g_sim_queue_assoc[i].idx_len = cmd->idx_len;
                g_sim_queue_assoc[i].rq_pi_seen = 0;
                g_sim_queue_assoc[i].pending_head = 0;
                g_sim_queue_assoc[i].pending_tail = 0;
                /* JFR 的 db（sw_db）在 ucmd.db_addr；sq 的 db 经 mmap JETTY_DSQE 才填。
                 * JFR 的 db 是 kernel buffer（sw_db 指针），不经 mmap，故在此直接记。 */
                g_sim_queue_assoc[i].db_addr = cmd->db_addr;
                SIM_DBG("queue_assoc[%d]: JFR-RQ jetty=%lx buf=%lx sw_db=%lx idx=%lx\n",
                        i, (unsigned long)cmd->jetty_addr, (unsigned long)cmd->buf_addr,
                        (unsigned long)cmd->db_addr, (unsigned long)cmd->idx_addr);
            } else {
                g_sim_queue_assoc[i].q_type = 0;   /* sq */
                /* sq 的 baseblk_cnt（WQE 槽数，环形 mask 用）从 buf_len 推：
 */
                uint32_t bb = cmd->buf_len / URMA_SIM_WQEBB;   /* depth 近似 */
                uint32_t bbcnt = 1;
                while (bbcnt < bb) {
                    bbcnt <<= 1;
                }
                g_sim_queue_assoc[i].wqe_cnt = bbcnt;
                SIM_DBG("queue_assoc[%d]: jetty=%lx buf=%lx bbcnt=%u\n",
                        i, (unsigned long)cmd->jetty_addr, (unsigned long)cmd->buf_addr, bbcnt);
            }
            return i;
        }
    }
    return -1;
}

void urma_sim_queue_assoc_set_id(int slot, uint32_t id)
{
    if (slot >= 0 && slot < URMA_SIM_QUEUE_MAX && g_sim_queue_assoc[slot].in_use) {
        g_sim_queue_assoc[slot].id = id;
        SIM_DBG("queue_assoc[%d].id=%u\n", slot, id);
    }
}

void urma_sim_queue_assoc_set_handle(int slot, uint64_t handle)
{
    if (slot >= 0 && slot < URMA_SIM_QUEUE_MAX && g_sim_queue_assoc[slot].in_use) {
        g_sim_queue_assoc[slot].handle = handle;
    }
}

/* 节 14: DELETE_* 清理 stale assoc（指针复用错配根因）——按 handle 释放槽。 */
void urma_sim_queue_assoc_release_by_handle(uint64_t handle)
{
    if (handle == 0) {
        return;
    }
    for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
        if (g_sim_queue_assoc[i].in_use && g_sim_queue_assoc[i].handle == handle) {
            /* 释放时同步清 jetty→jfr 绑定（节 3）：释放 Jetty 后其 ID 被
 */
            if (g_sim_queue_assoc[i].is_jetty) {
                for (int b = 0; b < URMA_SIM_JFR_BIND_MAX; b++) {
                    if (g_sim_jfr_bind[b].in_use &&
                        g_sim_jfr_bind[b].jetty_id == g_sim_queue_assoc[i].id &&
                        memcmp(g_sim_jfr_bind[b].eid, g_sim_queue_assoc[i].eid, 16) == 0) {
                        g_sim_jfr_bind[b].in_use = 0;
                    }
                }
            } else if (g_sim_queue_assoc[i].q_type == 1) {
                for (int b = 0; b < URMA_SIM_JFR_BIND_MAX; b++) {
                    if (g_sim_jfr_bind[b].in_use &&
                        g_sim_jfr_bind[b].jfr_id == g_sim_queue_assoc[i].id &&
                        memcmp(g_sim_jfr_bind[b].eid, g_sim_queue_assoc[i].eid, 16) == 0) {
                        g_sim_jfr_bind[b].in_use = 0;
                    }
                }
            }
            g_sim_queue_assoc[i].in_use = 0;
            SIM_DBG("queue_assoc[%d] released (handle=%lu)\n", i, (unsigned long)handle);
        }
    }
}

void urma_sim_queue_assoc_set_is_jetty(int slot, int is_jetty)
{
    if (slot >= 0 && slot < URMA_SIM_QUEUE_MAX && g_sim_queue_assoc[slot].in_use) {
        g_sim_queue_assoc[slot].is_jetty = is_jetty;
    }
}

void urma_sim_queue_assoc_set_eid(int slot, const uint8_t *eid)
{
    if (slot >= 0 && slot < URMA_SIM_QUEUE_MAX && g_sim_queue_assoc[slot].in_use &&
        eid != NULL) {
        memcpy(g_sim_queue_assoc[slot].eid, eid, 16);
        /* IPv4-mapped EID 首字节必为 0，不能用 eid[0] 判有效 */
        static const uint8_t z[16] = {0};
        g_sim_queue_assoc[slot].eid_valid = (memcmp(eid, z, 16) != 0);
    }
}

urma_sim_queue_assoc_t *urma_sim_queue_assoc_set_db_by_idx(uint32_t idx, uint64_t db_addr)
{
    /* 只限 SQ（q_type==0）：JFR 的 rq 与 Jetty/JFS 的 sq 是独立资源表，数值 ID
 */
    for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
        if (g_sim_queue_assoc[i].in_use && g_sim_queue_assoc[i].q_type == 0 &&
            g_sim_queue_assoc[i].id == idx) {
            g_sim_queue_assoc[i].db_addr = db_addr;
            SIM_DBG("queue_assoc[%d].db=%lx (idx=%u)\n", i, (unsigned long)db_addr, idx);
            return &g_sim_queue_assoc[i];
        }
    }
    return NULL;
}

urma_sim_queue_assoc_t *urma_sim_queue_assoc_find_by_jetty(uint64_t jetty_addr)
{
    if (jetty_addr == 0) {
        return NULL;
    }
    for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
        if (g_sim_queue_assoc[i].in_use && g_sim_queue_assoc[i].jetty_addr == jetty_addr) {
            return &g_sim_queue_assoc[i];
        }
    }
    return NULL;
}

void urma_sim_queue_assoc_set_jfc(int slot, uint32_t jfc_id)
{
    if (slot >= 0 && slot < URMA_SIM_QUEUE_MAX && g_sim_queue_assoc[slot].in_use) {
        g_sim_queue_assoc[slot].jfc_id = jfc_id;
    }
}

/* === CQ 关联表 === */
urma_sim_cq_assoc_t g_sim_cq_assoc[URMA_SIM_CQ_MAX] = {0};

int urma_sim_cq_assoc_register(uint64_t udata_data)
{
    if (udata_data == 0) {
        return -1;
    }
    urma_cmd_udrv_priv_t *udata = (urma_cmd_udrv_priv_t *)(uintptr_t)udata_data;
    if (udata->in_addr == 0 || udata->in_len < sizeof(struct udma_create_jfc_ucmd)) {
        return -1;
    }
    /* jfc_ucmd 和 jetty_ucmd 首字段都是 buf_addr（偏移 0），直接读首字段。
     * buf_len 在偏移 8（udma_create_jfc_ucmd.buf_len），用于推算 CQ 深度→cq_shift。 */
    uint64_t cq_addr = *(const uint64_t *)(uintptr_t)udata->in_addr;
    uint32_t buf_len = 0;
    memcpy(&buf_len, (const void *)(uintptr_t)(udata->in_addr + 8), sizeof(buf_len));
    /* depth = buf_len / cqe_size(64) */
    uint32_t depth = buf_len / URMA_SIM_CQE_SIZE;
    for (int i = 0; i < URMA_SIM_CQ_MAX; i++) {
        if (!g_sim_cq_assoc[i].in_use) {
            g_sim_cq_assoc[i].jfc_id = 0;
            g_sim_cq_assoc[i].cq_addr = cq_addr;  /* CQ 内存地址 */
            g_sim_cq_assoc[i].depth = depth;        /* CQ 深度（造 CQE 算 cq_shift） */
            g_sim_cq_assoc[i].cq_ci = 0;
            g_sim_cq_assoc[i].in_use = 1;
            SIM_DBG("cq_assoc[%d]: cq_addr=%lx depth=%u\n",
                    i, (unsigned long)cq_addr, depth);
            return i;
        }
    }
    return -1;
}

void urma_sim_cq_assoc_set_id(int slot, uint32_t jfc_id)
{
    if (slot >= 0 && slot < URMA_SIM_CQ_MAX && g_sim_cq_assoc[slot].in_use) {
        g_sim_cq_assoc[slot].jfc_id = jfc_id;
        SIM_DBG("cq_assoc[%d].jfc_id=%u\n", slot, jfc_id);
    }
}

void urma_sim_cq_assoc_set_handle(int slot, uint64_t handle)
{
    if (slot >= 0 && slot < URMA_SIM_CQ_MAX && g_sim_cq_assoc[slot].in_use) {
        g_sim_cq_assoc[slot].handle = handle;
    }
}

/* ACTIVE_JFC：jfc 在 active 时重新分配 CQ 内存（udma_u_active_jfc →
 */
void urma_sim_cq_assoc_update_addr(uint64_t handle, uint64_t new_addr, uint32_t new_depth)
{
    if (handle == 0 || new_addr == 0) {
        return;
    }
    for (int i = 0; i < URMA_SIM_CQ_MAX; i++) {
        if (g_sim_cq_assoc[i].in_use && g_sim_cq_assoc[i].handle == handle) {
            SIM_DBG("cq_assoc[%d] addr update: %lx -> %lx (handle=%lu)\n", i,
                    (unsigned long)g_sim_cq_assoc[i].cq_addr,
                    (unsigned long)new_addr, (unsigned long)handle);
            g_sim_cq_assoc[i].cq_addr = new_addr;
            if (new_depth > 0) {
                g_sim_cq_assoc[i].depth = new_depth;   /* active 可改 depth：掩码随新 CQ */
            }
            g_sim_cq_assoc[i].cq_ci = 0;   /* 产索引随新缓冲重置（见下注释） */
            /* 真 udma active 时创建空 CQ 且消费索引 ci=0（udma_u_jfc.c:85,221）—— */
        }
    }
}

/* 节 14: DELETE_JFC 清理 stale CQ 关联 */
void urma_sim_cq_assoc_release_by_handle(uint64_t handle)
{
    if (handle == 0) {
        return;
    }
    for (int i = 0; i < URMA_SIM_CQ_MAX; i++) {
        if (g_sim_cq_assoc[i].in_use && g_sim_cq_assoc[i].handle == handle) {
            g_sim_cq_assoc[i].in_use = 0;
            SIM_DBG("cq_assoc[%d] released (handle=%lu)\n", i, (unsigned long)handle);
        }
    }
}

urma_sim_cq_assoc_t *urma_sim_cq_assoc_find(uint32_t jfc_id)
{
    if (jfc_id == 0) {
        return NULL;
    }
    for (int i = 0; i < URMA_SIM_CQ_MAX; i++) {
        if (g_sim_cq_assoc[i].in_use && g_sim_cq_assoc[i].jfc_id == jfc_id) {
            return &g_sim_cq_assoc[i];
        }
    }
    return NULL;
}

/* === tid→seg 内存映射表 ===
 */
urma_sim_tid_seg_t g_sim_tid_seg[URMA_SIM_TID_MAX] = {0};

void urma_sim_tid_seg_register(uint32_t tid, uint64_t va, uint64_t len)
{
    if (tid == 0) {
        return;
    }
    /* URMA 允许一个 token id 注册多个 segment（urma_api.h:793）——同一 tid 下 */
    for (int i = 0; i < URMA_SIM_TID_MAX; i++) {
        if (g_sim_tid_seg[i].in_use && g_sim_tid_seg[i].tid == tid &&
            g_sim_tid_seg[i].va == va) {
            g_sim_tid_seg[i].len = len;   /* 幂等更新 */
            return;
        }
    }
    for (int i = 0; i < URMA_SIM_TID_MAX; i++) {
        if (!g_sim_tid_seg[i].in_use) {
            g_sim_tid_seg[i].tid = tid;
            g_sim_tid_seg[i].va = va;
            g_sim_tid_seg[i].len = len;
            g_sim_tid_seg[i].in_use = 1;
            return;
        }
    }
}

void urma_sim_tid_seg_unregister(uint32_t tid, uint64_t va)
{
    for (int i = 0; i < URMA_SIM_TID_MAX; i++) {
        if (g_sim_tid_seg[i].in_use && g_sim_tid_seg[i].tid == tid &&
            g_sim_tid_seg[i].va == va) {
            g_sim_tid_seg[i].in_use = 0;
            return;
        }
    }
}

urma_sim_tid_seg_t *urma_sim_tid_seg_find(uint32_t tid)
{
    if (tid == 0) {
        return NULL;
    }
    for (int i = 0; i < URMA_SIM_TID_MAX; i++) {
        if (g_sim_tid_seg[i].in_use && g_sim_tid_seg[i].tid == tid) {
            return &g_sim_tid_seg[i];
        }
    }
    return NULL;
}

/* 按 (tid, addr) 找段：addr 必须落在该段 [va, va+len) 内（多 segment token
 * 时各段 va 不同——IPC 用请求的远端地址定位对应段，不能只按 tid 找首条）。 */
urma_sim_tid_seg_t *urma_sim_tid_seg_find_addr(uint32_t tid, uint64_t addr)
{
    if (tid == 0) {
        return NULL;
    }
    for (int i = 0; i < URMA_SIM_TID_MAX; i++) {
        if (g_sim_tid_seg[i].in_use && g_sim_tid_seg[i].tid == tid &&
            addr >= g_sim_tid_seg[i].va &&
            addr < g_sim_tid_seg[i].va + g_sim_tid_seg[i].len) {
            return &g_sim_tid_seg[i];
        }
    }
    return NULL;
}

/* === JFR 按 jetty_id 寻址（SEND 投递到对端 recv 队列） ===
 */

void urma_sim_jfr_bind_jetty(const uint8_t *eid, uint32_t jetty_id, uint32_t jfr_id)
{
    if (eid == NULL) {
        return;
    }
    if (jfr_id == 0) {
        /* 无共享 JFR：清除该 (eid,jetty) 的历史绑定（删除/ID 复用不残留） */
        for (int i = 0; i < URMA_SIM_JFR_BIND_MAX; i++) {
            if (g_sim_jfr_bind[i].in_use && g_sim_jfr_bind[i].jetty_id == jetty_id &&
                memcmp(g_sim_jfr_bind[i].eid, eid, 16) == 0) {
                g_sim_jfr_bind[i].in_use = 0;
                SIM_DBG("jfr_bind: clear jetty_id=%u\n", jetty_id);
            }
        }
        return;
    }
    for (int i = 0; i < URMA_SIM_JFR_BIND_MAX; i++) {
        if (g_sim_jfr_bind[i].in_use && g_sim_jfr_bind[i].jetty_id == jetty_id &&
            memcmp(g_sim_jfr_bind[i].eid, eid, 16) == 0) {
            g_sim_jfr_bind[i].jfr_id = jfr_id;  /* 更新 */
            return;
        }
    }
    for (int i = 0; i < URMA_SIM_JFR_BIND_MAX; i++) {
        if (!g_sim_jfr_bind[i].in_use) {
            memcpy(g_sim_jfr_bind[i].eid, eid, 16);
            g_sim_jfr_bind[i].jetty_id = jetty_id;
            g_sim_jfr_bind[i].jfr_id = jfr_id;
            g_sim_jfr_bind[i].in_use = 1;
            SIM_DBG("jfr_bind: jetty_id=%u → jfr_id=%u\n", jetty_id, jfr_id);
            return;
        }
    }
}

/* 绑定命中 → recv 完成按 jetty（is_jetty=1/local_id=jetty_id）；否则独立 JFR */
static int jfr_bind_hits(const uint8_t *eid, uint32_t jetty_id, uint32_t jfr_id)
{
    for (int i = 0; i < URMA_SIM_JFR_BIND_MAX; i++) {
        if (g_sim_jfr_bind[i].in_use && g_sim_jfr_bind[i].jetty_id == jetty_id &&
            g_sim_jfr_bind[i].jfr_id == jfr_id &&
            (eid == NULL || memcmp(g_sim_jfr_bind[i].eid, eid, 16) == 0)) {
            return 1;
        }
    }
    return 0;
}

urma_sim_queue_assoc_t *urma_sim_jfr_find_by_jetty(const uint8_t *eid, uint32_t jetty_id)
{
    uint32_t jfr_id = 0;
    int has_eid = urma_sim_eid_is_valid(eid);
    for (int i = 0; i < URMA_SIM_JFR_BIND_MAX; i++) {
        if (g_sim_jfr_bind[i].in_use && g_sim_jfr_bind[i].jetty_id == jetty_id &&
            (!has_eid || memcmp(g_sim_jfr_bind[i].eid, eid, 16) == 0)) {
            jfr_id = g_sim_jfr_bind[i].jfr_id;
            break;
        }
    }
    if (jfr_id == 0) {
        /* 独立 jfs/jfr 方式（节 3）：SEND 的 rmt_jetty_or_seg_id 是 jfr_id（非 jetty_id），
         * 无 jetty→jfr 绑定。按 jfr_id 直查 rq assoc（q_type=1, .id==jfr_id）兜底。 */
        jfr_id = jetty_id;
    }
    /* 按 (eid, jfr_id) 查 JFR 的 rq assoc（多设备允许同资源 ID；
     * 只按 id 会命中另一设备同 ID 的队列 → 数据投递到错误设备） */
    for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
        if (g_sim_queue_assoc[i].in_use && g_sim_queue_assoc[i].q_type == 1 &&
            g_sim_queue_assoc[i].id == jfr_id &&
            (!has_eid || (g_sim_queue_assoc[i].eid_valid &&
             memcmp(g_sim_queue_assoc[i].eid, eid, 16) == 0))) {
            return &g_sim_queue_assoc[i];
        }
    }
    return NULL;
}

/* ilog2（向上 2 幂后再取 log2），同真 udma UDMA_U_ILOG32(roundup_pow2(x)) */
static uint32_t sim_ilog2_pow2(uint32_t x)
{
    if (x == 0) {
        return 0;
    }
    uint32_t p = 1;
    uint32_t shift = 0;
    while (p < x) {
        p <<= 1;
        shift++;
    }
    return shift;
}

void urma_sim_jfr_set_recv_geom(int slot, uint32_t max_sge, uint32_t depth)
{
    if (slot < 0 || slot >= URMA_SIM_QUEUE_MAX || !g_sim_queue_assoc[slot].in_use) {
        return;
    }
    urma_sim_queue_assoc_t *qa = &g_sim_queue_assoc[slot];
    /* max_sge 向上 2 幂（真 udma roundup_pow_of_two(cfg->max_sge)）；若 0 给默认 1 */
    uint32_t sge_pow = 1;
    while (sge_pow < max_sge && sge_pow < (1u << 20)) {
        sge_pow <<= 1;
    }
    qa->max_sge = sge_pow;
    /* wqe_shift = ilog2(UDMA_SGE_SIZE(16) * sge_pow)（udma_u_jfr.c:47） */
    qa->wqe_shift = sim_ilog2_pow2(16 * sge_pow);
    /* wqe_cnt = 索引环槽数：provider 强制最小 UDMA_U_MIN_JFR_DEPTH(64)，否则
 */
    uint32_t cnt = 1;
    while (cnt < depth && cnt < (1u << 24)) {
        cnt <<= 1;
    }
    if (cnt < 64) {
        cnt = 64;   /* UDMA_U_MIN_JFR_DEPTH；64 本身是 2 的幂 */
    }
    qa->wqe_cnt = cnt;
    SIM_DBG("jfr_geom[%d]: max_sge=%u(%u) wqe_shift=%u wqe_cnt=%u\n",
            slot, max_sge, sge_pow, qa->wqe_shift, qa->wqe_cnt);
}

/* 从 pending 取一个 recv 槽（rqe_idx/va 输出）；无槽 -1 */
static int jfr_pop_pending(urma_sim_queue_assoc_t *qa, uint32_t *out_rqe, uint64_t *out_va)
{
    if (qa == NULL || qa->pending_head == qa->pending_tail) {
        return -1;  /* 空 */
    }
    uint32_t pos = qa->pending_head & 0xff;
    if (out_rqe != NULL) {
        *out_rqe = qa->pending_rqe[pos];
    }
    if (out_va != NULL) {
        *out_va = qa->pending_va[pos];
    }
    qa->pending_head++;
    return 0;
}

/* rq 轮询：扫 JFR 的 sw_db（db_addr）pi 变化，把新 post 的 recv WQE 登记进 pending 队列。
 * 由主轮询线程对 q_type=1 的 assoc 周期调用。 */
void jfr_refill_pending(urma_sim_queue_assoc_t *qa)
{
    if (qa->db_addr == 0 || qa->buf_addr == 0 || qa->idx_addr == 0 || qa->wqe_shift == 0) {
        return;
    }
    (void)pthread_mutex_lock(&g_pending_lock);
    volatile uint32_t *sw_db = (volatile uint32_t *)(uintptr_t)qa->db_addr;
    /* ⑱: sw_db 是 16 位寄存器（真实写 pi & GENMASK(15,0)，udma_u_jfr.c:498）——
     * 按掩码比较，recv 累计超 65536 回绕后仍能追上（此前完整计数比较会失配）。 */
    uint32_t pi = *sw_db & 0xffff;   /* UDMA_JFR_DB_PROD_IDX_M = GENMASK(15,0) */
    if (pi == (qa->rq_pi_seen & 0xffff)) {
        (void)pthread_mutex_unlock(&g_pending_lock);
        return;
    }
    uint32_t mask = qa->wqe_cnt > 0 ? (qa->wqe_cnt - 1) : 0;
    /* 处理 rq_pi_seen..pi-1 的每个新 recv。索引队列每项 4B（wqe_idx），按 head=pi&(wqe_cnt-1) 排。 */
    while ((qa->rq_pi_seen & 0xffff) != pi) {
        uint32_t head = qa->rq_pi_seen & mask;
        uint32_t wqe_idx = *((volatile uint32_t *)(uintptr_t)(qa->idx_addr + (uint64_t)head * 4));
        /* recv WQE = buf_addr + (wqe_idx << wqe_shift)，首 sge {length,token_id,va} */
        uint8_t *wqe = (uint8_t *)(uintptr_t)(qa->buf_addr + ((uint64_t)wqe_idx << qa->wqe_shift));
        struct urma_sim_wqe_sge *sge = (struct urma_sim_wqe_sge *)wqe;
        uint32_t cnt = qa->pending_tail - qa->pending_head;  /* 环形容量 256 */
        if (cnt < 256) {
            uint32_t pos = qa->pending_tail & 0xff;
            qa->pending_rqe[pos] = wqe_idx;
            qa->pending_va[pos] = sge->va;
            qa->pending_tail++;
            qa->rq_pi_seen++;
            SIM_DBG("jfr_refill: pi=%u wqe_idx=%u va=%lx (pending=%u)\n",
                    qa->rq_pi_seen, wqe_idx, (unsigned long)sge->va, cnt + 1);
        } else {
            /* ⑰: pending 满时不推进 rq_pi_seen——保留槽等下轮再入队（不丢 recv）。 */
            SIM_DBG("jfr_refill: pending full (cnt=%u), hold pi\n", cnt);
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_pending_lock);
}

/* 把 data 的 [0, len) 字节按 RQE 的 SGE 依次散布（每个 SGE 填满后再进下一个）。 */
static void scatter_into_rqe(const struct urma_sim_wqe_sge *sges, uint32_t sge_cnt,
                             const void *data, uint32_t len, uint64_t limit)
{
    size_t off = 0;
    uint64_t remain = limit;
    for (uint32_t i = 0; i < sge_cnt && off < len; i++) {
        uint32_t n = sges[i].length;
        if (n == 0) {
            break;
        }
        if ((uint64_t)n > remain) {
            n = (uint32_t)remain;
        }
        if (n > len - off) {
            n = len - off;
        }
        memcpy((void *)(uintptr_t)sges[i].va, (const char *)data + off, n);
        off += n;
        remain -= n;
    }
}

/* SEND 到达本端 JFR：取 recv 槽、写数据、造 recv CQE（先 refill_pending 吸新 post）；
 * 0 成功，-1 无槽（RNR） */
int urma_sim_jfr_deliver_send(urma_sim_queue_assoc_t *jfr_qa, uint32_t jetty_id,
                              const void *data, uint32_t len,
                              uint8_t cqe_opcode, uint64_t imm_data,
                              uint32_t src_jetty_id, uint32_t src_tpn,
                              const uint8_t *src_eid)
{
    if (jfr_qa == NULL) {
        return -1;
    }
    jfr_refill_pending(jfr_qa);   /* 吸新 post 的 recv（主轮询可能还没扫到） */
    uint32_t rqe_idx = 0;
    uint64_t recv_va = 0;
    (void)pthread_mutex_lock(&g_pending_lock);
    int pop_rc = jfr_pop_pending(jfr_qa, &rqe_idx, &recv_va);
    (void)pthread_mutex_unlock(&g_pending_lock);
    if (pop_rc != 0) {
        SIM_DBG("jfr_deliver: no recv slot (RNR) jetty=%u\n", jetty_id);
        return -1;  /* 对端还没 post recv → RNR */
    }
    /* 接收容量 = RQE 内全部非空 SGE 长度之和：provider 把一个 recv WR 的所有
 */
    uint64_t cap = 0;
    const struct urma_sim_wqe_sge *sges = NULL;
    uint32_t sge_cnt = 0;
    if (jfr_qa->wqe_shift > 0) {
        sges = (const struct urma_sim_wqe_sge *)(uintptr_t)(jfr_qa->buf_addr +
                                                            ((uint64_t)rqe_idx << jfr_qa->wqe_shift));
        sge_cnt = jfr_qa->max_sge;
        for (uint32_t i = 0; i < sge_cnt; i++) {
            cap += sges[i].length;
        }
    }
    if (len > cap) {
        /* FG-08: 真实语义（udma_u_jfc.c:575-588）——能搬多少搬多少 + 对端产
 */
        SIM_DBG("jfr_deliver: SEND len=%u > recv cap=%llu (LOCAL_LENGTH_ERR)\n", len, (unsigned long long)cap);
        if (sges != NULL) {
            scatter_into_rqe(sges, sge_cnt, data, len, cap);
        }
        urma_sim_cq_assoc_t *cq_err = urma_sim_cq_assoc_find(jfr_qa->jfc_id);
        if (cq_err != NULL) {
            int jetty_cr = jfr_bind_hits(jfr_qa->eid, jetty_id, jfr_qa->id);
            uint32_t local_id = jetty_cr ? jetty_id : jfr_qa->id;
            produce_recv_cqe(cq_err, jfr_qa->jetty_addr, local_id, rqe_idx, 0, cqe_opcode,
                             imm_data, jetty_cr,
                             2 /* UDMA_CQE_LOCAL_OP_ERR */, 1 /* UDMA_CQE_LOCAL_LENGTH_ERR */,
                             src_jetty_id, src_tpn, src_eid);
        }
        return -1;
    }
    if (len > 0 && sges != NULL) {
        scatter_into_rqe(sges, sge_cnt, data, len, len);
    }
    /* 造 recv CQE 写进 JFR 关联的 CQ（jfc_id）。真 udma poll 读到 s_r=1 CQE，
     * 用 local_id(=jetty_id) 查 jfr_table 拿 jfr，用 entry_idx(=rqe_idx) 从 wrid[] 还原 user_ctx。 */
    urma_sim_cq_assoc_t *cq_a = urma_sim_cq_assoc_find(jfr_qa->jfc_id);
    if (cq_a != NULL) {
        /* recv CQE 的 local_id：is_jetty=1 时 provider 按 jetty_table（key=jetty_id） */
        int jetty_cr = jfr_bind_hits(jfr_qa->eid, jetty_id, jfr_qa->id);
        uint32_t local_id = jetty_cr ? jetty_id : jfr_qa->id;
        produce_recv_cqe(cq_a, jfr_qa->jetty_addr, local_id, rqe_idx, len, cqe_opcode, imm_data,
                         jetty_cr, 0, 0, src_jetty_id, src_tpn, src_eid);
        SIM_DBG("jfr_deliver: recv CQE jetty=%u rqe=%u len=%u op=%u imm=%lx\n",
                jetty_id, rqe_idx, len, cqe_opcode, (unsigned long)imm_data);
    } else {
        SIM_DBG("jfr_deliver: no CQ for jfc_id=%u\n", jfr_qa->jfc_id);
        return -1;
    }
    return 0;
}

/* WRITE_IMM 通知：只产 imm recv CQE（不搬数据、不进 recv 槽）；0/-1 */
int urma_sim_jfr_deliver_imm(urma_sim_queue_assoc_t *jfr_qa, uint32_t jetty_id,
                             uint8_t cqe_opcode, uint64_t imm_data,
                             uint32_t src_jetty_id, uint32_t src_tpn,
                             const uint8_t *src_eid)
{
    if (jfr_qa == NULL) {
        return -1;
    }
    jfr_refill_pending(jfr_qa);
    uint32_t rqe_idx = 0;
    uint64_t recv_va = 0;
    (void)pthread_mutex_lock(&g_pending_lock);
    int pop_rc = jfr_pop_pending(jfr_qa, &rqe_idx, &recv_va);
    (void)pthread_mutex_unlock(&g_pending_lock);
    if (pop_rc != 0) {
        SIM_DBG("jfr_deliver_imm: no recv slot (RNR) jetty=%u\n", jetty_id);
        return -1;
    }
    (void)recv_va;   /* WRITE_WITH_IMM 数据写 seg，不进 recv 槽 */
    urma_sim_cq_assoc_t *cq_a = urma_sim_cq_assoc_find(jfr_qa->jfc_id);
    if (cq_a != NULL) {
        int jetty_cr = jfr_bind_hits(jfr_qa->eid, jetty_id, jfr_qa->id);
        uint32_t local_id = jetty_cr ? jetty_id : jfr_qa->id;
        produce_recv_cqe(cq_a, jfr_qa->jetty_addr, local_id, rqe_idx, 0, cqe_opcode, imm_data,
                         jetty_cr, 0, 0, src_jetty_id, src_tpn, src_eid);
        SIM_DBG("jfr_deliver_imm: recv CQE jetty=%u rqe=%u op=%u imm=%lx\n",
                jetty_id, rqe_idx, cqe_opcode, (unsigned long)imm_data);
    } else {
        SIM_DBG("jfr_deliver_imm: no CQ for jfc_id=%u\n", jfr_qa->jfc_id);
        return -1;
    }
    return 0;
}

/* === 轮询线程：检测 doorbell pi 变化 → 读 WQE → memcpy → 造 CQE ===
 */

#define URMA_SIM_DOORBELL_OFFSET 0x80


/* owner/entry_idx 是位域，不能取 offsetof；布局靠非位域锚点 user_data_l@20、user_data_h@24 校验 */
/* CQE_FOR_SEND=0, status UDMA_CQE_SUCCESS=0, is_jetty=0；owner 直接用位域赋值 */

/* 把 64 位 queue ptr 拆 low/high 写进 CQE 的 user_data_l/h。
 * 真 udma 用 (user_data_h<<32)|user_data_l 还原 queue 指针。 */
