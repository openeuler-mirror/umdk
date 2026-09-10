/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * 拦截 ummu(libummu.so)4 个函数，伪造返回，让真 udma provider 的
 * alloc_tid/register_seg/unregister_seg/free_tid 走通（无 ummu 内核模块）。
 *
 * ummu 符号无版本号（T ummu_grant，非 @VERSION），LD_PRELOAD 直接定义同名
 * 全局符号即可拦截。真 udma 调用点：
 *  - ummu_allocate_tid : udma_u_tid.c:40 (alloc_token_id)
 *  - ummu_free_tid     : udma_u_tid.c:62/81 (free_token_id), udma_u_jfc.c:609 (poll)
 *  - ummu_grant        : udma_u_segment.c:84 (register_seg)
 *  - ummu_ungrant      : udma_u_segment.c:126 (unregister_seg)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#include <ummu_api.h>

#include "urma_sim_res.h"

/* 仿真假 TID 生成（ummu_allocate_tid 的出参）：自增分配保证多次 token 分配
 * 相互独立（固定 0x1234 会让不同 token 注册的段共享同一远端访问键，tid→段
 * 关联冲突：远端读写错地址、注销破坏他 token 映射）。原子递增，无锁并发安全。 */
static uint32_t g_next_tid = 1;

int ummu_allocate_tid(struct ummu_tid_attr *tid_attr, uint32_t *tid)
{
    (void)tid_attr;
    if (tid != NULL) {
        *tid = __sync_fetch_and_add(&g_next_tid, 1);
    }
    return 0;
}

int ummu_grant(uint32_t tid, void *data, size_t data_size,
               enum ummu_mapt_perm perm, struct ummu_seg_attr *seg_attr)
{
    (void)perm;
    (void)seg_attr;
    /* tid→va 映射：真 udma register_seg 调 ummu_grant(tid, va, len, ...) 把
     * tid→va 写进硬件。sim 记录此映射，轮询解到 WQE 远端 tid 时查 va 做 memcpy。 */
    urma_sim_tid_seg_register(tid, (uint64_t)(uintptr_t)data, (uint64_t)data_size);
    return 0;
}

int ummu_ungrant(uint32_t tid, void *data, size_t size)
{
    (void)size;
    urma_sim_tid_seg_unregister(tid, (uint64_t)(uintptr_t)data);
    return 0;
}

int ummu_ungrant_by_token(uint32_t tid, void *data, size_t size, uint32_t token_val)
{
    (void)size;
    (void)token_val;
    urma_sim_tid_seg_unregister(tid, (uint64_t)(uintptr_t)data);
    return 0;
}

int ummu_free_tid(uint32_t tid)
{
    (void)tid;
    return 0;
}
