/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider slide window implementation
 * Author: Ma Chuan
 * Create: 2025-03-05
 * Note:
 * History: 2025-03-05
 */
#include <stdint.h>
#include "ub_bitmap.h"
#include "urma_log.h"
#include "bondp_slide_window.h"

static bool is_seq_in_loop_range(uint32_t head, uint32_t len, uint32_t max_size, uint32_t seq)
{
    uint32_t tail = (head + len) % max_size;
    if (tail < head) {
        // when overflow, tail is less than head
        return (seq >= head) || (seq < tail);
    } else {
        return (seq >= head) && (seq < tail);
    }
}

int bdp_slide_wnd_init(bdp_slide_wnd_t *wnd, uint32_t total_size, uint32_t window_size, uint32_t head)
{
    if (wnd == NULL) {
        URMA_LOG_ERR("Invalid param wnd\n");
        return -1;
    }
    if (total_size <= window_size) {
        URMA_LOG_ERR("Invalid param: total_size <= window_size\n");
        return -1;
    }
    wnd->bits = ub_bitmap_alloc(total_size);
    if (wnd->bits == NULL) {
        URMA_LOG_ERR("Failed to init bitmap");
        return -1;
    }
    wnd->total_size = total_size;
    wnd->window_size = window_size;
    wnd->head = head % total_size;
    return 0;
}

void bdp_slide_wnd_uninit(bdp_slide_wnd_t *wnd)
{
    if (wnd == NULL) {
        URMA_LOG_ERR("Invalid param wnd\n");
        return;
    }
    ub_bitmap_free(wnd->bits);
}

bool bdp_slide_wnd_seq_in_window(bdp_slide_wnd_t *wnd, uint32_t seq)
{
    if (wnd == NULL) {
        URMA_LOG_ERR("Invalid param wnd\n");
        return false;
    }
    if (seq >= wnd->total_size) {
        URMA_LOG_ERR("Seq larger than total size of bitmap\n");
        return false;
    }
    return is_seq_in_loop_range(wnd->head, wnd->window_size, wnd->total_size, seq);
}

bool bdp_slide_wnd_has(bdp_slide_wnd_t *wnd, uint32_t seq)
{
    if (wnd == NULL) {
        URMA_LOG_ERR("Invalid param wnd\n");
        return false;
    }
    if (seq >= wnd->total_size) {
        URMA_LOG_ERR("Seq larger than total size of bitmap\n");
        return false;
    }
    return is_seq_in_loop_range(wnd->head, wnd->window_size, wnd->total_size, seq) &&
        ub_bitmap_is_set(wnd->bits, seq);
}

int bdp_slide_wnd_add(bdp_slide_wnd_t *wnd, uint32_t seq)
{
    if (wnd == NULL) {
        URMA_LOG_ERR("Invalid param wnd\n");
        return -1;
    }
    if (!bdp_slide_wnd_seq_in_window(wnd, seq)) {
        return BDP_SLIDE_WND_OUT_OF_WND;
    }
    if (ub_bitmap_is_set(wnd->bits, seq)) {
        return BDP_SLIDE_WND_DUPLICATE;
    }
    ub_bitmap_set1(wnd->bits, seq);
    while (ub_bitmap_is_set(wnd->bits, wnd->head)) {
        ub_bitmap_set0(wnd->bits, (wnd->head + wnd->window_size) % wnd->total_size);
        wnd->head++;
        wnd->head %= wnd->total_size;
    }
    return 0;
}
