/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bonding provider slide window header
 * Author: Ma Chuan
 * Create: 2025-03-05
 * Note:
 * History: 2025-03-05
 */
#ifndef BDP_SLIDE_WINDOW_H
#define BDP_SLIDE_WINDOW_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BDP_SLIDE_WND_OUT_OF_WND (-2)
#define BDP_SLIDE_WND_DUPLICATE  (-3)
/** A simple slide window.
 * Valid seq: [head, head + window_size) or [0, head + window_size % total_size) || [head, total_size).
 * Head is in [0, total_size).
 * window size must be less than total size.
 * Total size should cover all possiable sequence number, e.x. UINT32_MAX.
*/
typedef struct bdp_slide_window {
    unsigned long *bits;
    uint32_t total_size;
    uint32_t window_size;
    uint32_t head;
} bdp_slide_wnd_t;

int bdp_slide_wnd_init(bdp_slide_wnd_t *wnd, uint32_t total_size, uint32_t window_size, uint32_t head);
void bdp_slide_wnd_uninit(bdp_slide_wnd_t *wnd);

bool bdp_slide_wnd_seq_in_window(bdp_slide_wnd_t *wnd, uint32_t seq);
/** Add a sequence number to the window.
 * Automaticlly slide window if the sequence number of `head` is 1.
 * @return 0: success
 * @return -1: failure
 * @return BDP_SLIDE_WND_OUT_OF_WND: The sequence number is out of window.
 * @return BDP_SLIDE_WND_DUPLICATE: The sequence number is duplicate.
*/
int bdp_slide_wnd_add(bdp_slide_wnd_t *wnd, uint32_t seq);
/** Check if the sequence number is in the window and mark it as 1. */
bool bdp_slide_wnd_has(bdp_slide_wnd_t *wnd, uint32_t seq);

#ifdef __cplusplus
}
#endif

#endif // BDP_SLIDE_WINDOW_H
