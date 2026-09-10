/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * 跨进程 IPC（方式1 扩展）：双进程实时数据传递。
 *
 * 单进程仿真靠 memcpy（同地址空间，test_hw_post 自引用已验证）。但跨进程时
 * A 进程解引用 B 进程的 buf 指针 = SIGSEGV。故用 unix socket 实时传数据：
 *   - 每进程 sim 在 create_context 拿到本进程 eid 后，起后台线程 listen
 *     unix socket，路径含 eid 低 64 位（/tmp/urma_sim_ipc_<hex>）。
 *   - A 解 WQE 拿 rmt_eid=B 的 eid（test 链路天然带的，import_jetty/post 填），
 *     推算 B 的 socket 路径 → 连 B → 发读/写请求。
 *   - B 后台线程收到请求：tid → 查本进程 g_sim_tid_seg 表 → B 的 buf 指针
 *     → 读/写 B 的 buf（同进程，指针有效）→ 回 A。
 *   - tid 只在本进程查本进程指针；eid 定位对端进程。零共享存储，纯 IPC。
 *
 * 协议（极简定长头 + 变长数据）：
 *   请求:  magic(4)=0x53494d55  op(4)=1/2  tid(4)  len(4)  [WRITE 后跟 len 字节]
 *   响应:  magic(4)            status(4)  len(4)        [READ 后跟 len 字节]
 */

#include "urma_sim_res.h"
#include "urma_sim_exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define URMA_SIM_IPC_MAGIC 0x53494d55u   /* "SIMU" */
#define URMA_SIM_IPC_OP_READ  1
#define URMA_SIM_IPC_OP_WRITE 2
#define URMA_SIM_IPC_OP_SEND  3   /* 投递到对端 JFR recv 队列：tid 字段复用为 jetty_id */
#define URMA_SIM_IPC_OP_WRITE_IMM 4  /* FG-05: 跨进程 WRITE_WITH_IMM 的 imm 通知投递 */
#define URMA_SIM_IPC_OP_ATOMIC  5    /* FG-01: 跨进程 CAS/FAA 原子读-改-写 */
/* 响应 resp[1] 状态码：0=成功、1=远端长度错误（URMA_CR_REM_RESP_LEN_ERR 语义）、
 * 0xffffffff=通用失败。长度错误不再静默截短——客户端据此返回失败。 */
#define URMA_SIM_IPC_RESP_LEN_ERR 1
#define URMA_SIM_IPC_SOCK_DIR "/tmp"

/* 本进程 eid 表（节 15：多设备 IPC——同进程多个 ctx/设备各有独立 eid）。
 * eid 16B 与 WQE 里 rmt_eid 同格式（swap 后的 le_eid，比较/寻址一致）。
 * 每 eid 一个监听 socket/线程；is_local 匹配任一 eid 即走本地 memcpy。 */
#define URMA_SIM_MAX_EIDS 8
static uint8_t g_local_eids[URMA_SIM_MAX_EIDS][16] = {{0}};
static int g_local_eid_cnt = 0;
static pthread_t g_ipc_threads[URMA_SIM_MAX_EIDS];
static int g_ipc_thread_cnt = 0;
static pthread_mutex_t g_ipc_init_lock = PTHREAD_MUTEX_INITIALIZER;

/* 链路故障注入：按 eid 前 8 字节 hex 设置 down。
 * 环境变量 URMA_SIM_LINK_DOWN=hex 下指定 eid 的链路 down（IPC 请求返错）。
 * URMA_SIM_LINK_UP=hex 恢复。 */
static uint8_t g_link_down_eid[16] = {0};
static int g_link_down_active = 0;

static void link_fault_init(void)
{
    const char *down = getenv("URMA_SIM_LINK_DOWN");
    if (down != NULL && strlen(down) >= 16) {
        int consumed = 0;
        /* 逐字节十六进制转换：须校验 sscanf 成功且全串匹配——含非十六进制
         * 字符时不写入 v，未初始化读取是 UB（随机 EID 被判 link down）。 */
        int ok = 1;
        for (int i = 0; i < 8 && ok; i++) {
            unsigned int v = 0;   /* 失败时不读未初始化值 */
            if (sscanf(down + i * 2, "%02x%n", &v, &consumed) != 1 || consumed != 2) {
                ok = 0;
                break;   /* 本次循环不再用 v */
            }
            g_link_down_eid[i] = (uint8_t)v;
        }
        if (!ok) {
            g_link_down_active = 0;
            fprintf(stderr,
                    "WARN: URMA_SIM_LINK_DOWN invalid hex string \"%.16s\", link fault injection disabled\n",
                    down);
            return;
        }
        g_link_down_active = 1;
        SIM_DBG("ipc: link DOWN for eid %02x%02x%02x%02x%02x%02x%02x%02x\n",
                g_link_down_eid[0],g_link_down_eid[1],g_link_down_eid[2],g_link_down_eid[3],
                g_link_down_eid[4],g_link_down_eid[5],g_link_down_eid[6],g_link_down_eid[7]);
    }
    const char *up = getenv("URMA_SIM_LINK_UP");
    if (up != NULL && g_link_down_active) {
        g_link_down_active = 0;
        SIM_DBG("ipc: link UP (fault cleared)\n");
    }
}

/* 检查 rmt_eid 是否处于故障 down 状态 */
static int link_is_down(const uint8_t *rmt_eid)
{
    if (!g_link_down_active) return 0;
    return memcmp(rmt_eid, g_link_down_eid, 8) == 0;
}

/* 16 字节反转（与 udma_u_swap_endian128 一致）。 */
static void swap_eid128(const uint8_t *src, uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = src[15 - i];
    }
}

/* eid 转 hex 路径。注意 WQE 里 rmt_eid 是 le_eid（swap 反转版），故此处的 eid
 * 入参也是 swap 后的格式。用前 8 字节（swap 后含 IPv4 段，有区分度；
 * 末 8 字节 swap 后是原前 8 字节=全 0 前缀，会撞，故不用末 8）。 */
static int eid_to_sockpath(const uint8_t *eid, char *path, size_t sz)
{
    /* ⑦N: socket 目录可配置（URMA_SIM_IPC_DIR）——DT 多 case 并行/多实例
     * 隔离（脚本传了独立目录但此前硬编码 /tmp，同 eid 实例会互相 unlink 污染）。 */
    const char *dir = getenv("URMA_SIM_IPC_DIR");
    if (dir == NULL || dir[0] == '\0') {
        dir = URMA_SIM_IPC_SOCK_DIR;
    }
    const uint8_t *p = eid;   /* 完整 16 字节：EID 唯一性由整个 raw（urma_eid_t）决定，
                             * 只用前 8 字节会让 subnet 不同而 interface_id 相同的
                             * EID 撞同一 socket 路径（后启动者 unlink 抢占）。 */
    int n = snprintf(path, sz, "%s/urma_sim_ipc_", dir);
    for (int i = 0; i < 16 && n >= 0 && n < (int)sz; i++) {
        int r = snprintf(path + n, sz - n, "%02x", p[i]);
        if (r < 0) {
            path[0] = '\0';
            return -1;
        }
        n += r;
    }
    if (n < 0 || n >= (int)sz) {
        /* 长目录（>49B）下 32 hex 放不下：截断会让不同 EID 撞同一路径，
         * 不能静默使用截断名——直接失败由调用方处理。 */
        path[0] = '\0';
        return -1;
    }
    return 0;
}

/* 判断指定 eid 是否属于本进程的虚拟设备。
 * 严格白名单匹配：仅当 rmt_eid 与本进程已成功登记的 EID 匹配时才返回 1；
 * 未注册或启动失败时不假定为本地，避免跨进程操作把对端虚拟地址当作本地地址解引用导致 SIGSEGV。 */
int urma_sim_ipc_is_local(const uint8_t *rmt_eid)
{
    if (rmt_eid == NULL) {
        return 1;   /* NULL 视为本进程 */
    }
    (void)pthread_mutex_lock(&g_ipc_init_lock);
    int local = 0;
    /* 节 15: 严格匹配任一已注册 local eid（多设备同进程） */
    for (int i = 0; i < g_local_eid_cnt; i++) {
        if (memcmp(rmt_eid, g_local_eids[i], 16) == 0) {
            local = 1;
            break;
        }
    }
    (void)pthread_mutex_unlock(&g_ipc_init_lock);
    return local;
}

/* 全读/全写（处理 partial read/write）。返回 0 成功 -1 失败。 */
static int recv_all(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, (char *)buf + got, n - got, 0);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        got += r;
    }
    return 0;
}
static int send_all(int fd, const void *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = send(fd, (const char *)buf + sent, n - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return -1;
        }
        sent += r;
    }
    return 0;
}

/* 后台线程：处理一个连接。读请求 → 查本进程 tid 表 → 读/写 buf → 回响应。 */
/* 监听线程参数：socket fd + 本设备 eid（接收侧按 eid 隔离绑定/投递） */
typedef struct {
    int lfd;
    uint8_t eid[16];
} ipc_thread_arg_t;

static void handle_conn(int cfd, const uint8_t *local_eid)
{
    /* ⑦E: 连接超时（5s）——对端半开连接/崩溃时 recv/send 不再永久阻塞，
     * 超时关闭连接并继续服务后续请求（此前单线程串行 + 无超时，
     * 一个坏连接卡死整个 IPC 服务）。 */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    /* 协议头：基础 4 个 u32(magic/op/tid/len)。SEND 在 magic 校验后还要收 cqe_opcode+imm（3 个 u32）。 */
    uint32_t hdr[4];   /* magic, op, tid, len */
    if (recv_all(cfd, hdr, sizeof(hdr)) != 0) {
        goto done;
    }
    uint32_t magic = hdr[0], op = hdr[1], tid = hdr[2], len = hdr[3];
    if (magic != URMA_SIM_IPC_MAGIC || len > (16u << 20)) {   /* 上限 16MB 防恶意/异常 */
        goto done;
    }
    /* SEND：tid 字段复用为对端 jetty_id。先收数据，再投递到本进程 JFR recv 队列。 */
    if (op == URMA_SIM_IPC_OP_SEND) {
        /* SEND 协议头扩展（hdr 后 9 个 u32）：cqe_op、imm_l、imm_h、src_tpn、
         * src_jetty_id、src_eid[4]——src_eid 从第 5 项起，不再覆盖 src_jetty 槽 */
        uint32_t ext[9];
        if (recv_all(cfd, ext, sizeof(ext)) != 0) {
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        uint8_t cqe_opcode = (uint8_t)ext[0];
        uint64_t imm_data = ((uint64_t)ext[2] << 32) | (uint64_t)ext[1];
        uint32_t src_tpn = ext[3];
        uint32_t src_jetty = ext[4];
        uint8_t src_eid[16];
        memcpy(src_eid, &ext[5], sizeof(src_eid));
        char *data = (char *)malloc(len > 0 ? len : 1);
        if (data == NULL) {
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        if (len > 0 && recv_all(cfd, data, len) != 0) {
            free(data);
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        /* tid = 对端 jetty_id → 查本进程 JFR rq → 投递 + 造 recv CQE（带 imm/opcode） */
        urma_sim_queue_assoc_t *jfr_qa =
                urma_sim_jfr_find_by_jetty(local_eid, tid);   /* 接收设备 eid 维度 */
        int rc = -1;
        if (jfr_qa != NULL) {
            rc = urma_sim_jfr_deliver_send(jfr_qa, tid, data, len, cqe_opcode, imm_data,
                                          src_jetty, src_tpn, src_eid);
        }
        free(data);
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (rc == 0) ? 0u : (uint32_t)-1, 0};
        send_all(cfd, resp, sizeof(resp));
        goto done;
    }
    /* FG-05: WRITE_WITH_IMM 的 imm 通知——与 OP_SEND 同扩展头
     * （cqe_opcode + imm_l + imm_h），但数据已写 seg，不投 recv 槽，
     * 只产 imm recv CQE（deliver_imm）。 */
    if (op == URMA_SIM_IPC_OP_WRITE_IMM) {
        /* 与 OP_SEND 同扩展头（9 个 u32；src_eid 从第 5 项起） */
        uint32_t ext[9];
        if (recv_all(cfd, ext, sizeof(ext)) != 0) {
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        uint8_t cqe_opcode = (uint8_t)ext[0];
        uint64_t imm_data = ((uint64_t)ext[2] << 32) | (uint64_t)ext[1];
        uint32_t src_tpn = ext[3];
        uint32_t src_jetty = ext[4];
        uint8_t src_eid[16];
        memcpy(src_eid, &ext[5], sizeof(src_eid));
        urma_sim_queue_assoc_t *jfr_qa =
                urma_sim_jfr_find_by_jetty(local_eid, tid);   /* tid=对端 jetty_id */
        int rc = -1;
        if (jfr_qa != NULL) {
            rc = urma_sim_jfr_deliver_imm(jfr_qa, tid, cqe_opcode, imm_data,
                                          src_jetty, src_tpn, src_eid);
        }
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (rc == 0) ? 0u : (uint32_t)-1, 0};
        send_all(cfd, resp, sizeof(resp));
        goto done;
    }
    /* FG-01: 跨进程 CAS/FAA——按 tid 定位 seg，读原值、执行原子写、原值回传。 */
    if (op == URMA_SIM_IPC_OP_ATOMIC) {
        urma_sim_tid_seg_t *ts = urma_sim_tid_seg_find(tid);
        if (ts == NULL || ts->va == 0) {
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        /* hdr 扩展 5 个 u32：opcode、len、len2（CAS 时 cmp 长度，与 len 相同）、
         * rmt_addr_l、rmt_addr_h（原子目标在请求方 WQE 的远端 va） */
        uint32_t ext[5];
        if (recv_all(cfd, ext, sizeof(ext)) != 0) {
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        uint8_t aop = (uint8_t)ext[0];
        uint32_t alen = ext[1];
        uint32_t alen2 = ext[2];
        uint64_t a_rmt = ((uint64_t)ext[4] << 32) | (uint64_t)ext[3];
        /* 多 segment token：按请求远端地址定位对应段（只按 tid 会命中首条） */
        ts = urma_sim_tid_seg_find_addr(tid, a_rmt);
        if (ts == NULL) {
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_RESP_LEN_ERR, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        if (alen == 0 || alen > 16 || alen2 > 16) {
            /* alen2 未约束会引发超大 malloc（alen+alen2 回绕/耗尽内存）——拒绝 */
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        if (aop == 7 && alen2 != alen) {
            /* CAS：cmp 长度必须等于 swap 长度（客户端按 2*len 布局传） */
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        char *data = (char *)malloc(alen + alen2);
        if (data == NULL) goto done;
        if (recv_all(cfd, data, alen + alen2) != 0) {
            free(data);
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        /* 原子目标 = 段基址 + 请求方 WQE 远端地址偏差（段内偏移），非总 seg 起点 */
        uint64_t a_off = a_rmt - (uint64_t)ts->va;
        if (a_off > ts->len || (uint64_t)alen > ts->len - a_off) {
            /* 原子长度/偏移超出目标段：远端长度错误，不部分执行 */
            free(data);
            uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_RESP_LEN_ERR, 0};
            send_all(cfd, resp, sizeof(resp));
            goto done;
        }
        void *rmt = (void *)(uintptr_t)(ts->va + a_off);
        uint8_t *orig = (uint8_t *)malloc(alen > 0 ? alen : 1);
        if (orig == NULL) { free(data); goto done; }

        /* 执行原子：与本地 WQE 路径统一使用 GCC 原生 __atomic_* 指令，
         * 保证本地执行与跨进程 IPC 并发访问同一内存段时的严格线性化一致性 */
        if (aop == 7) {  /* CAS: data[0..alen)=swap, data[alen..)=cmp */
            if (alen == 4) {
                uint32_t cmp_val, swap_val;
                memcpy(&swap_val, data, 4);
                memcpy(&cmp_val, data + 4, 4);
                uint32_t expected = cmp_val;
                __atomic_compare_exchange_n((uint32_t *)rmt, &expected,
                                            swap_val, 0, __ATOMIC_SEQ_CST,
                                            __ATOMIC_RELAXED);
                memcpy(orig, &expected, 4);
            } else if (alen == 8) {
                uint64_t cmp_val, swap_val;
                memcpy(&swap_val, data, 8);
                memcpy(&cmp_val, data + 8, 8);
                uint64_t expected = cmp_val;
                __atomic_compare_exchange_n((uint64_t *)rmt, &expected,
                                            swap_val, 0, __ATOMIC_SEQ_CST,
                                            __ATOMIC_RELAXED);
                memcpy(orig, &expected, 8);
            }
#if defined(__SIZEOF_INT128__)
            else if (alen == 16) {
                typedef unsigned __int128 urma_u128_t;
                urma_u128_t cmp_val, swap_val;
                memcpy(&swap_val, data, 16);
                memcpy(&cmp_val, data + 16, 16);
                urma_u128_t expected = cmp_val;
                __atomic_compare_exchange_n((urma_u128_t *)rmt, &expected,
                                            swap_val, 0, __ATOMIC_SEQ_CST,
                                            __ATOMIC_RELAXED);
                memcpy(orig, &expected, 16);
            }
#endif
            else {
                memcpy(orig, rmt, alen);
            }
        } else {         /* FAA: data[0..alen)=operand */
            if (alen == 4) {
                uint32_t op_val;
                memcpy(&op_val, data, 4);
                uint32_t old_val = __atomic_fetch_add((uint32_t *)rmt, op_val, __ATOMIC_SEQ_CST);
                memcpy(orig, &old_val, 4);
            } else if (alen == 8) {
                uint64_t op_val;
                memcpy(&op_val, data, 8);
                uint64_t old_val = __atomic_fetch_add((uint64_t *)rmt, op_val, __ATOMIC_SEQ_CST);
                memcpy(orig, &old_val, 8);
            } else {
                memcpy(orig, rmt, alen);
            }
        }
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, 0, alen};
        if (send_all(cfd, resp, sizeof(resp)) != 0) { free(data); free(orig); goto done; }
        if (send_all(cfd, orig, alen) != 0) { free(data); free(orig); goto done; }
        free(data);
        free(orig);
        goto done;
    }
    /* 查本进程 tid → buf */
    urma_sim_tid_seg_t *ts = urma_sim_tid_seg_find(tid);
    if (ts == NULL || ts->va == 0) {
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
        send_all(cfd, resp, sizeof(resp));
        goto done;
    }
    /* READ/WRITE：协议头再扩展 2 个 u32 = rmt_addr_l/h（请求方 WQE 的远端 va，
     * provider 写在 rmt_addr_l_or_token_id/rmt_addr_h_or_token_value）。按
     * 段内偏移 off = rmt_addr - seg.va 定位实际操作位置；off+len 越段 → 长度错误
     * （此前总是操作 seg 起始，破坏错误数据仍上报成功）。 */
    uint32_t ext_rmt[2];
    if (recv_all(cfd, ext_rmt, sizeof(ext_rmt)) != 0) {
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, (uint32_t)-1, 0};
        send_all(cfd, resp, sizeof(resp));
        goto done;
    }
    uint64_t rmt_addr = ((uint64_t)ext_rmt[1] << 32) | (uint64_t)ext_rmt[0];
    /* 多 segment token：按请求远端地址定位对应段（只按 tid 会命中首条） */
    ts = urma_sim_tid_seg_find_addr(tid, rmt_addr);
    if (ts == NULL) {
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_RESP_LEN_ERR, 0};
        send_all(cfd, resp, sizeof(resp));
        goto done;
    }
    uint64_t off = rmt_addr - (uint64_t)ts->va;
    if (off > ts->len || (uint64_t)len > ts->len - off) {
        /* 远端长度错误（URMA_CR_REM_RESP_LEN_ERR），不截短后成功。
         * WRITE 的负载在错误响应之后才被客户端发出：必须先吸走 len 字节
         * （丢弃），否则大负载时客户端发送中途 EPIPE，看不到长度错误响应
         * （长度错误语义随负载大小变化）。 */
        if (op == URMA_SIM_IPC_OP_WRITE && len > 0) {
            char discard_buf[4096];
            uint32_t remaining = len;
            while (remaining > 0) {
                uint32_t chunk = remaining < (uint32_t)sizeof(discard_buf) ?
                                 remaining : (uint32_t)sizeof(discard_buf);
                if (recv_all(cfd, discard_buf, chunk) != 0) {
                    break;
                }
                remaining -= chunk;
            }
        }
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_RESP_LEN_ERR, 0};
        send_all(cfd, resp, sizeof(resp));
        goto done;
    }
    void *rmt = (void *)(uintptr_t)(ts->va + off);
    uint32_t act_len = len;
    if (op == URMA_SIM_IPC_OP_READ) {
        /* B 读自己的 buf → 发给 A */
        char *stackbuf = NULL;
        char *buf = (char *)(uintptr_t)rmt;   /* 段内偏移后的实际读位置 */
        (void)stackbuf;
        (void)stackbuf;
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, 0, act_len};
        if (send_all(cfd, resp, sizeof(resp)) != 0) goto done;
        if (send_all(cfd, buf, act_len) != 0) goto done;
    } else if (op == URMA_SIM_IPC_OP_WRITE) {
        /* A 发来的数据 → 写进 B 的 buf（段内偏移位置） */
        char *buf = (char *)(uintptr_t)rmt;
        char *tmp = (char *)malloc(act_len);
        if (tmp == NULL) goto done;
        if (recv_all(cfd, tmp, act_len) != 0) { free(tmp); goto done; }
        memcpy(buf, tmp, act_len);   /* B 同进程,va 有效 */
        free(tmp);
        uint32_t resp[3] = {URMA_SIM_IPC_MAGIC, 0, act_len};
        send_all(cfd, resp, sizeof(resp));
    }
done:
    close(cfd);
}

static void *urma_sim_ipc_thread(void *arg)
{
    ipc_thread_arg_t *ta = (ipc_thread_arg_t *)arg;
    int lfd = ta->lfd;
    while (1) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle_conn(cfd, ta->eid);
    }
    free(ta);   /* 线程退出：释放参数对象（异常退出也不遗留） */
    return NULL;
}

void urma_sim_ipc_start(const uint8_t *eid)
{
    if (eid == NULL) {
        return;
    }
    (void)pthread_mutex_lock(&g_ipc_init_lock);
    /* 存 swap 版（与 WQE 里 rmt_eid 同格式），已注册的 eid 幂等返回 */
    uint8_t sw[16];
    swap_eid128(eid, sw);
    for (int i = 0; i < g_local_eid_cnt; i++) {
        if (memcmp(g_local_eids[i], sw, 16) == 0) {
            (void)pthread_mutex_unlock(&g_ipc_init_lock);
            return;   /* 该 eid 已起 */
        }
    }
    if (g_local_eid_cnt >= URMA_SIM_MAX_EIDS) {
        fprintf(stderr, "DBG ipc: eid table full (%d)\n", g_local_eid_cnt);
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    link_fault_init();  /* 初始化链路故障注入（读环境变量，幂等） */
    char path[96];
    if (eid_to_sockpath(sw, path, sizeof(path)) != 0) {
        fprintf(stderr, "FATAL: ipc socket path too long for eid, skip\n");
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    unlink(path);   /* 清理上次残留 */

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) {
        SIM_DBG("ipc: socket fail %s\n", strerror(errno));
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* sun_path 108 字节，path 最大约 40 字节，不会截断 */
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        SIM_DBG("ipc: bind %s fail %s\n", path, strerror(errno));
        close(lfd);
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    if (listen(lfd, 16) != 0) {
        SIM_DBG("ipc: listen fail %s\n", strerror(errno));
        close(lfd);
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    /* 注册 eid 后起监听线程（节 15：每 eid 独立 socket/线程）。
     * pthread_create 失败：关闭 lfd、清 socket 路径、不登记 eid（该 eid
     * 可重试）；绝不能"声称已启动"——否则 socket 无人 accept，跨进程
     * 请求阻塞/超时且 eids 无法重试，泄漏 fd 与路径。 */
    ipc_thread_arg_t *ta = (ipc_thread_arg_t *)calloc(1, sizeof(*ta));
    if (ta == NULL) {
        fprintf(stderr, "FATAL: ipc thread arg alloc fail\n");
        close(lfd);
        unlink(path);
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    ta->lfd = lfd;
    /* 线程给 JFR 查询用的 eid 须与资源登记同键序（urma_str_to_eid 的 raw）；
     * g_local_eids 存的是 swap 版——这里换回 raw。 */
    swap_eid128(sw, ta->eid);
    if (pthread_create(&g_ipc_threads[g_ipc_thread_cnt], NULL, urma_sim_ipc_thread,
                       ta) != 0) {
        fprintf(stderr, "FATAL: ipc listen thread create fail: %s\n", strerror(errno));
        close(lfd);
        unlink(path);
        free(ta);   /* 创建失败：参数对象须释放（可反复重试而不泄漏） */
        (void)pthread_mutex_unlock(&g_ipc_init_lock);
        return;
    }
    SIM_DBG("ipc: listen %s (lfd=%d)\n", path, lfd);
    pthread_detach(g_ipc_threads[g_ipc_thread_cnt]);
    memcpy(g_local_eids[g_local_eid_cnt], sw, 16);
    g_local_eid_cnt++;
    g_ipc_thread_cnt++;
    (void)pthread_mutex_unlock(&g_ipc_init_lock);
}

/* 客户端：连 rmt_eid 对应进程的 socket。返回 fd，<0 失败。 */
static int ipc_connect(const uint8_t *rmt_eid)
{
    char path[96];
    if (eid_to_sockpath(rmt_eid, path, sizeof(path)) != 0) {
        return -1;   /* 路径不可表示：判定为连接失败 */
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    /* 重试连接（对端可能还没起） */
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            return fd;
        }
        if (errno != ENOENT && errno != ECONNREFUSED) {
            break;
        }
        usleep(10000);   /* 10ms × 50 = 0.5s */
    }
    SIM_DBG("ipc: connect %s fail %s\n", path, strerror(errno));
    close(fd);
    return -1;
}

int urma_sim_ipc_read(const uint8_t *rmt_eid, uint32_t tid, uint64_t rmt_addr,
                      void *local_buf, uint32_t len)
{
    if (link_is_down(rmt_eid)) return -1;
    int fd = ipc_connect(rmt_eid);
    if (fd < 0) return -1;
    uint32_t hdr[6] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_OP_READ, tid, len,
                        (uint32_t)(rmt_addr & 0xffffffff),
                        (uint32_t)((rmt_addr >> 32) & 0xffffffff)};
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { close(fd); return -1; }
    uint32_t resp[3];
    if (recv_all(fd, resp, sizeof(resp)) != 0) { close(fd); return -1; }
    if (resp[0] != URMA_SIM_IPC_MAGIC) { close(fd); return -1; }
    if (resp[1] == URMA_SIM_IPC_RESP_LEN_ERR) {
        close(fd);
        return URMA_SIM_IPC_RC_LEN_ERR;   /* 远端长度错误：与链路失败区分 */
    }
    if (resp[1] != 0) { close(fd); return -1; }
    /* 远端必须按请求长度完整返回（超段已由服务端报长度错误，不再部分成功） */
    if (resp[2] != len) { close(fd); return -1; }
    if (recv_all(fd, local_buf, len) != 0) { close(fd); return -1; }
    close(fd);
    return 0;
}

int urma_sim_ipc_write(const uint8_t *rmt_eid, uint32_t tid, uint64_t rmt_addr,
                       const void *local_buf, uint32_t len)
{
    if (link_is_down(rmt_eid)) return -1;
    int fd = ipc_connect(rmt_eid);
    if (fd < 0) return -1;
    uint32_t hdr[6] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_OP_WRITE, tid, len,
                        (uint32_t)(rmt_addr & 0xffffffff),
                        (uint32_t)((rmt_addr >> 32) & 0xffffffff)};
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { close(fd); return -1; }
    if (send_all(fd, local_buf, len) != 0) { close(fd); return -1; }
    uint32_t resp[3];
    if (recv_all(fd, resp, sizeof(resp)) != 0) { close(fd); return -1; }
    if (resp[0] != URMA_SIM_IPC_MAGIC) { close(fd); return -1; }
    if (resp[1] == URMA_SIM_IPC_RESP_LEN_ERR) {
        close(fd);
        return URMA_SIM_IPC_RC_LEN_ERR;   /* 远端长度错误：与链路失败区分 */
    }
    if (resp[1] != 0) { close(fd); return -1; }
    /* 服务端成功即完整写入（超段已拒绝）；再校验长度一致 */
    if (resp[2] != len) { close(fd); return -1; }
    close(fd);
    return 0;
}

/* FG-05: 跨进程 WRITE_WITH_IMM 的 imm 通知投递。
 * 发 {op=WRITE_IMM, jetty_id, 0} + {cqe_opcode, imm_l, imm_h}；对端 deliver_imm
 * 产 imm recv CQE（不写 recv 槽）。 */
int urma_sim_ipc_write_imm(const uint8_t *rmt_eid, uint32_t jetty_id,
                           uint8_t cqe_opcode, uint64_t imm_data,
                           uint32_t src_jetty_id, uint32_t src_tpn,
                           const uint8_t *src_eid)
{
    if (link_is_down(rmt_eid)) return -1;
    int fd = ipc_connect(rmt_eid);
    if (fd < 0) return -1;
    /* 协议：magic/op/jetty_id/0 + cqe_op/imm_l/imm_h/src_tpn/src_jetty/src_eid[4] = 13 u32 */
    uint32_t hdr[13] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_OP_WRITE_IMM, jetty_id, 0,
                        (uint32_t)cqe_opcode,
                        (uint32_t)(imm_data & 0xffffffff),
                        (uint32_t)((imm_data >> 32) & 0xffffffff),
                        src_tpn, src_jetty_id};   /* eid 从 hdr[9] 起，不覆盖 src_jetty */
    static const uint8_t zero_eid[16] = {0};
    memcpy(&hdr[9], src_eid != NULL ? src_eid : zero_eid, 16);
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { close(fd); return -1; }
    uint32_t resp[3];
    if (recv_all(fd, resp, sizeof(resp)) != 0) { close(fd); return -1; }
    if (resp[0] != URMA_SIM_IPC_MAGIC || resp[1] != 0) { close(fd); return -1; }
    close(fd);
    return 0;
}

/* FG-01: 跨进程 CAS/FAA——对端按 tid 定位 seg，执行读-改-写，原值回 local_buf。
 * data 指向 WQE 原子数据区（CAS: swap+cmp=2*len；FAA: operand=len）。 */
int urma_sim_ipc_atomic(const uint8_t *rmt_eid, uint32_t tid, uint64_t rmt_addr,
                        uint8_t opcode, uint32_t len, const uint8_t *data,
                        uint8_t *local_buf)
{
    if (link_is_down(rmt_eid)) return -1;
    if (len == 0 || len > 16 || local_buf == NULL) return -1;
    int fd = ipc_connect(rmt_eid);
    if (fd < 0) return -1;
    uint32_t alen2 = (opcode == 7) ? len : 0;   /* CAS 才有 cmp（len 字节） */
    uint32_t hdr[9] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_OP_ATOMIC, tid, len,
                        (uint32_t)opcode, len, alen2,
                        (uint32_t)(rmt_addr & 0xffffffff),
                        (uint32_t)((rmt_addr >> 32) & 0xffffffff)};
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { close(fd); return -1; }
    if (send_all(fd, data, len + alen2) != 0) { close(fd); return -1; }
    uint32_t resp[3];
    if (recv_all(fd, resp, sizeof(resp)) != 0) { close(fd); return -1; }
    if (resp[0] != URMA_SIM_IPC_MAGIC) { close(fd); return -1; }
    if (resp[1] == URMA_SIM_IPC_RESP_LEN_ERR) {
        close(fd);
        return URMA_SIM_IPC_RC_LEN_ERR;   /* 远端长度错误：与链路失败区分 */
    }
    if (resp[1] != 0) { close(fd); return -1; }
    /* 原子原值必须完整（alen 字节）；超段/异常已在服务端拒绝 */
    if (resp[2] != len) { close(fd); return -1; }
    if (recv_all(fd, local_buf, len) != 0) { close(fd); return -1; }
    close(fd);
    return 0;
}

/* 跨进程 SEND：连 rmt_eid 对端进程 socket，发 {op=SEND, jetty_id, len, data}，
 * 对端查自己 JFR recv 槽 → memcpy 进 recv buf → 造 recv CQE → 回 status。
 * tid 参数这里语义是 jetty_id（对端 JFR 的 jetty id，WQE 里 rmt_jetty_or_seg_id）。
 * cqe_opcode/imm_data：IMM 变体（SEND_WITH_IMM/INV）的对端 recv CQE opcode + imm/token 数据。 */
int urma_sim_ipc_send(const uint8_t *rmt_eid, uint32_t jetty_id,
                      const void *data, uint32_t len, uint32_t src_jfc_id,
                      uint8_t cqe_opcode, uint64_t imm_data,
                      uint32_t src_jetty_id, uint32_t src_tpn,
                      const uint8_t *src_eid)
{
    (void)src_jfc_id;   /* 保留接口，当前不用（send CQE 由发起方自己的 process_wqe 造） */
    if (link_is_down(rmt_eid)) return -1;
    int fd = ipc_connect(rmt_eid);
    if (fd < 0) return -1;
    /* 协议：magic/op/jetty_id/len + cqe_op/imm_l/imm_h/src_tpn/src_jetty/src_eid[4] = 13 u32 */
    uint32_t hdr[13] = {URMA_SIM_IPC_MAGIC, URMA_SIM_IPC_OP_SEND, jetty_id, len,
                        (uint32_t)cqe_opcode,
                        (uint32_t)(imm_data & 0xffffffff),
                        (uint32_t)((imm_data >> 32) & 0xffffffff),
                        src_tpn, src_jetty_id};   /* eid 从 hdr[9] 起，不覆盖 src_jetty */
    static const uint8_t zero_eid[16] = {0};
    memcpy(&hdr[9], src_eid != NULL ? src_eid : zero_eid, 16);
    if (send_all(fd, hdr, sizeof(hdr)) != 0) { close(fd); return -1; }
    if (len > 0 && send_all(fd, data, len) != 0) { close(fd); return -1; }
    uint32_t resp[3];
    if (recv_all(fd, resp, sizeof(resp)) != 0) { close(fd); return -1; }
    if (resp[0] != URMA_SIM_IPC_MAGIC || resp[1] != 0) { close(fd); return -1; }
    close(fd);
    return 0;
}
