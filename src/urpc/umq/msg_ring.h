/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc msg_ring base share memory.
 * Create: 2025-5-22
 */

#ifndef MSG_RING_H
#define MSG_RING_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MSG_RING_NAME 31

typedef struct shm_ring_hdr {
    volatile uint32_t pi;
    volatile uint32_t ci;
    volatile uint32_t cq_event_flag;  // 0: 无事件, 1: 有事件
    volatile uint32_t pending_events; // 事件计数器
} shm_ring_hdr_t;

typedef struct msg_ring {
    char msg_ring_name[MAX_MSG_RING_NAME + 1];
    int shm_fd;
    uint32_t shm_size;
    bool owner;

    void *shm_tx_ring;
    shm_ring_hdr_t *shm_tx_ring_hdr;
    uint32_t tx_max_buf_size;
    uint32_t tx_depth;

    void *shm_rx_ring;
    shm_ring_hdr_t *shm_rx_ring_hdr;
    uint32_t rx_max_buf_size;
    uint32_t rx_depth;
} msg_ring_t;

typedef struct msg_ring_option {
    bool owner;
    uint32_t tx_max_buf_size;
    uint32_t tx_depth;
    uint32_t rx_max_buf_size;
    uint32_t rx_depth;
    void *addr;
} msg_ring_option_t;

msg_ring_t *msg_ring_create(char *msg_ring_name, uint32_t msg_ring_name_len, msg_ring_option_t *opt);

void msg_ring_destroy(msg_ring_t *msg_ring_h);

int msg_ring_post_tx(msg_ring_t *msg_ring_h, char *tx_buf, uint32_t tx_buf_size);

int msg_ring_post_tx_batch(msg_ring_t *msg_ring_h, char **tx_buf, uint32_t *tx_buf_size, uint32_t tx_buf_cnt);

int msg_ring_poll_tx(msg_ring_t *msg_ring_h, char *tx_buf, uint32_t tx_max_buf_size, uint32_t *avail_buf_size);

int msg_ring_poll_tx_batch(msg_ring_t *msg_ring_h, char **tx_buf, uint32_t tx_max_buf_size,
    uint32_t *avail_buf_size, uint32_t max_cnt);

int msg_ring_post_rx(msg_ring_t *msg_ring_h, char *rx_buf, uint32_t rx_buf_size);

int msg_ring_poll_rx(msg_ring_t *msg_ring_h, char *rx_buf, uint32_t rx_max_buf_size, uint32_t *avail_buf_size);

int msg_ring_poll_rx_batch(msg_ring_t *msg_ring_h, char **rx_buf, uint32_t rx_max_buf_size,
    uint32_t *avail_buf_size, uint32_t max_cnt);

#ifdef __cplusplus
}
#endif

#endif