/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: urpc msg ring base share memory.
 * Create: 2025-5-22
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include "umq_vlog.h"
#include "msg_ring.h"

#define SHM_MODE (0660)
#define NUM_RING_HEADERS  (2)

typedef struct shm_ring_buf_hdr {
    volatile uint32_t avail_buf_size;
} shm_ring_buf_hdr_t;

#if defined(__x86_64__)
#define MB() asm volatile("mfence" ::: "memory")
#define RMB() asm volatile("lfence" ::: "memory")
#define WMB() asm volatile("sfence" ::: "memory")
#elif defined(__aarch64__)
#define DSB(opt) asm volatile("DSB " #opt : : : "memory")
#define MB() DSB(sy)
#define RMB() DSB(ld)
#define WMB() DSB(st)
#endif

msg_ring_t *msg_ring_create(char *msg_ring_name, uint32_t msg_ring_name_len, msg_ring_option_t *opt)
{
    int ret;
    void *ptr;
    uint32_t shm_size;
    if (msg_ring_name_len > MAX_MSG_RING_NAME) {
        return NULL;
    }

    msg_ring_t *msg_ring_h = (msg_ring_t *)calloc(1, sizeof(msg_ring_t));
    if (msg_ring_h == NULL) {
        UMQ_VLOG_ERR("msg ring calloc failed\n");
        return NULL;
    }
    msg_ring_h->shm_fd = -1;
    int shm_fd = -1;

    (void)memcpy(msg_ring_h->msg_ring_name, msg_ring_name, msg_ring_name_len);

    if (opt->addr == NULL) {
        shm_size = opt->tx_depth * opt->tx_max_buf_size +
                   opt->rx_depth * opt->rx_max_buf_size + NUM_RING_HEADERS * (uint32_t)sizeof(shm_ring_hdr_t);

        if (opt->owner) {
            shm_fd = shm_open(msg_ring_name, O_CREAT | O_RDWR | O_EXCL, SHM_MODE);
            if (shm_fd == -1) {
                UMQ_VLOG_ERR("shm open failed, errno: %d\n", errno);
                goto ERR_SHM_OPEN;
            }

            // set share memory size
            ret = ftruncate(shm_fd, shm_size);
            if (ret != 0) {
                UMQ_VLOG_ERR("ftruncate failed, errno: %d\n", errno);
                goto ERR_SHM_SIZE;
            }
        } else {
            shm_fd = shm_open(msg_ring_name, O_RDWR, SHM_MODE);
            if (shm_fd == -1) {
                UMQ_VLOG_ERR("shm open failed, errno: %d\n", errno);
                goto ERR_SHM_OPEN;
            }
        }
        msg_ring_h->shm_fd = shm_fd;
        msg_ring_h->shm_size = shm_size;
        msg_ring_h->owner = opt->owner;

        ptr = mmap(0, shm_size, PROT_WRITE | PROT_READ, MAP_SHARED, shm_fd, 0);
        if (ptr == MAP_FAILED) {
            UMQ_VLOG_ERR("mmap failed, errno: %d\n", errno);
            goto ERR_SHM_MMAP;
        }
    } else {
        ptr = opt->addr;
    }

    /* msg_ring share memory layout
     * tx ring | rx ring | tx ring header | rx ring header
     */
    msg_ring_h->shm_tx_ring = ptr;
    msg_ring_h->shm_rx_ring = msg_ring_h->shm_tx_ring + opt->tx_depth * opt->tx_max_buf_size;
    msg_ring_h->shm_tx_ring_hdr =
        (shm_ring_hdr_t *)(msg_ring_h->shm_rx_ring + opt->rx_depth * opt->rx_max_buf_size);
    msg_ring_h->shm_rx_ring_hdr = (shm_ring_hdr_t *)(msg_ring_h->shm_tx_ring_hdr + sizeof(shm_ring_hdr_t));
    if (opt->owner) {
        msg_ring_h->shm_tx_ring_hdr->ci = 0;
        msg_ring_h->shm_tx_ring_hdr->pi = 0;
        atomic_init(&msg_ring_h->shm_tx_ring_hdr->cq_event_flag, 0);
        atomic_init(&msg_ring_h->shm_tx_ring_hdr->pending_events, 0);

        msg_ring_h->shm_rx_ring_hdr->ci = 0;
        msg_ring_h->shm_rx_ring_hdr->pi = 0;
        atomic_init(&msg_ring_h->shm_rx_ring_hdr->cq_event_flag, 0);
        atomic_init(&msg_ring_h->shm_rx_ring_hdr->pending_events, 0);
    }

    msg_ring_h->tx_max_buf_size = opt->tx_max_buf_size;
    msg_ring_h->tx_depth = opt->tx_depth;
    msg_ring_h->rx_max_buf_size = opt->rx_max_buf_size;
    msg_ring_h->rx_depth = opt->rx_depth;
    return msg_ring_h;

ERR_SHM_MMAP:
ERR_SHM_SIZE:
    if (shm_fd != -1) {
        close(shm_fd);
    }
    if (opt->owner) {
        shm_unlink(msg_ring_name);
    }
ERR_SHM_OPEN:

    free(msg_ring_h);
    return NULL;
}

void msg_ring_destroy(msg_ring_t *msg_ring_h)
{
    if (msg_ring_h->shm_fd != -1) {
        munmap(msg_ring_h->shm_tx_ring, msg_ring_h->shm_size);
        msg_ring_h->shm_tx_ring = NULL;
        close(msg_ring_h->shm_fd);
        msg_ring_h->shm_fd = -1;
        if (msg_ring_h->owner) {
            shm_unlink(msg_ring_h->msg_ring_name);
        }
    }
    free(msg_ring_h);
}

int msg_ring_post_tx(msg_ring_t *msg_ring_h, char *tx_buf, uint32_t tx_buf_size)
{
    uint32_t payload_size = msg_ring_h->tx_max_buf_size - (uint32_t)sizeof(shm_ring_buf_hdr_t);
    if (tx_buf_size > payload_size) {
        UMQ_LIMIT_VLOG_ERR("post tx failed, payload_size %u is less than tx_buf_size %u\n",
                           payload_size, tx_buf_size);
        return -1;
    }

    shm_ring_hdr_t *tx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_tx_ring_hdr;
    if ((tx_ring_hdr->pi + 1) % msg_ring_h->tx_depth == tx_ring_hdr->ci) {
        UMQ_LIMIT_VLOG_ERR("post tx failed, the queue is full\n");
        return -EAGAIN;
    }

    MB();
    shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_tx_ring +
        tx_ring_hdr->pi * msg_ring_h->tx_max_buf_size);
    char *ring_buf_p = (char *)(ring_buf_hdr + 1);
    (void)memcpy(ring_buf_p, tx_buf, tx_buf_size);
    ring_buf_hdr->avail_buf_size = tx_buf_size;

    // Ensure that we post tx_buf before we update pi
    WMB();
    tx_ring_hdr->pi = (tx_ring_hdr->pi + 1) % msg_ring_h->tx_depth;

    return 0;
}

int msg_ring_post_tx_batch(msg_ring_t *msg_ring_h, char **tx_buf, uint32_t *tx_buf_size, uint32_t tx_buf_cnt)
{
    // rest empty count
    shm_ring_hdr_t *tx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_tx_ring_hdr;
    uint32_t left_cnt = (tx_ring_hdr->ci + msg_ring_h->tx_depth - tx_ring_hdr->pi - 1) % msg_ring_h->tx_depth;
    if (left_cnt < tx_buf_cnt) {
        UMQ_LIMIT_VLOG_ERR("post tx batch failed, rest tx_depth %u is less than tx_cnt %u\n",
                           left_cnt, tx_buf_cnt);
        return -1;
    }

    MB();
    for (uint32_t i = 0; i < tx_buf_cnt; ++i) {
        shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_tx_ring +
            ((tx_ring_hdr->pi + i) % msg_ring_h->tx_depth) * msg_ring_h->tx_max_buf_size);
        char *ring_buf_p = (char *)(ring_buf_hdr + 1);
        (void)memcpy(ring_buf_p, tx_buf[i], tx_buf_size[i]);
        ring_buf_hdr->avail_buf_size = tx_buf_size[i];
    }

    // Ensure that we post tx_buf before we update pi
    WMB();
    tx_ring_hdr->pi = (tx_ring_hdr->pi + tx_buf_cnt) % msg_ring_h->tx_depth;

    return 0;
}

int msg_ring_poll_tx(msg_ring_t *msg_ring_h, char *tx_buf, uint32_t tx_max_buf_size, uint32_t *avail_buf_size)
{
    shm_ring_hdr_t *tx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_tx_ring_hdr;
    if (tx_ring_hdr->pi == tx_ring_hdr->ci) {
        return -1;
    }

    RMB();
    shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_tx_ring +
        tx_ring_hdr->ci * msg_ring_h->tx_max_buf_size);
    char *ring_buf_p = (char *)(ring_buf_hdr + 1);
    if (tx_max_buf_size < ring_buf_hdr->avail_buf_size) {
        UMQ_LIMIT_VLOG_ERR("tx_max_buf_size %u is less than avail_buf_size %u\n", tx_max_buf_size,
                           ring_buf_hdr->avail_buf_size);
        return -1;
    }
    (void)memcpy(tx_buf, ring_buf_p, ring_buf_hdr->avail_buf_size);
    *avail_buf_size = ring_buf_hdr->avail_buf_size;

    // Ensure that we poll tx_buf before we update ci
    MB();
    tx_ring_hdr->ci = (tx_ring_hdr->ci + 1) % msg_ring_h->tx_depth;

    return 0;
}

int msg_ring_poll_tx_batch(msg_ring_t *msg_ring_h, char **tx_buf, uint32_t tx_max_buf_size,
    uint32_t *avail_buf_size, uint32_t max_cnt)
{
    shm_ring_hdr_t *tx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_tx_ring_hdr;
    if (tx_ring_hdr->pi == tx_ring_hdr->ci) {
        return 0;
    }

    uint32_t i = 0;
    uint32_t left_cnt = (tx_ring_hdr->pi + msg_ring_h->tx_depth - tx_ring_hdr->ci) % msg_ring_h->tx_depth;
    uint32_t max_cnt_ = left_cnt < max_cnt ? left_cnt : max_cnt;
    char *tx_buf_;
    RMB();
    for (; i < max_cnt_; ++i) {
        shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_tx_ring +
            ((tx_ring_hdr->ci + i) % msg_ring_h->tx_depth) * msg_ring_h->tx_max_buf_size);
        char *ring_buf_p = (char *)(ring_buf_hdr + 1);
        tx_buf_ = tx_buf[i];
        if (tx_max_buf_size < ring_buf_hdr->avail_buf_size) {
            UMQ_LIMIT_VLOG_ERR("tx_max_buf_size %u is less than avail_buf_size %u\n", tx_max_buf_size,
                               ring_buf_hdr->avail_buf_size);
            return -1;
        }
        (void)memcpy(tx_buf_, ring_buf_p, ring_buf_hdr->avail_buf_size);
        avail_buf_size[i] = ring_buf_hdr->avail_buf_size;
    }

    // Ensure that we poll tx_buf before we update ci
    MB();
    tx_ring_hdr->ci = (tx_ring_hdr->ci + i) % msg_ring_h->tx_depth;

    return i;
}

int msg_ring_post_rx(msg_ring_t *msg_ring_h, char *rx_buf, uint32_t rx_buf_size)
{
    uint32_t payload_size = msg_ring_h->rx_max_buf_size - (uint32_t)sizeof(shm_ring_buf_hdr_t);
    if (rx_buf_size > payload_size) {
        UMQ_LIMIT_VLOG_ERR("post rx failed, payload_size %u is less than rx_buf_size %u\n",
                           payload_size, rx_buf_size);
        return -1;
    }

    shm_ring_hdr_t *rx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_rx_ring_hdr;
    if ((rx_ring_hdr->pi + 1) % msg_ring_h->rx_depth == rx_ring_hdr->ci) {
        UMQ_LIMIT_VLOG_ERR("post rx failed, the queue is full\n");
        return -EAGAIN;
    }

    MB();
    shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_rx_ring +
        rx_ring_hdr->pi * msg_ring_h->rx_max_buf_size);
    char *ring_buf_p = (char *)(ring_buf_hdr + 1);
    (void)memcpy(ring_buf_p, rx_buf, rx_buf_size);
    ring_buf_hdr->avail_buf_size = rx_buf_size;

    // Ensure that we poll rx_buf before we update pi
    WMB();
    rx_ring_hdr->pi = (rx_ring_hdr->pi + 1) % msg_ring_h->rx_depth;

    return 0;
}

int msg_ring_poll_rx(msg_ring_t *msg_ring_h, char *rx_buf, uint32_t rx_max_buf_size, uint32_t *avail_buf_size)
{
    shm_ring_hdr_t *rx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_rx_ring_hdr;
    if (rx_ring_hdr->pi == rx_ring_hdr->ci) {
        return -1;
    }

    RMB();
    shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_rx_ring +
        rx_ring_hdr->ci * msg_ring_h->rx_max_buf_size);
    char *ring_buf_p =  (char *)(ring_buf_hdr + 1);
    if (rx_max_buf_size < ring_buf_hdr->avail_buf_size) {
        UMQ_LIMIT_VLOG_ERR("rx_max_buf_size %u is less than avail_buf_size %u\n", rx_max_buf_size,
                           ring_buf_hdr->avail_buf_size);
        return -1;
    }
    (void)memcpy(rx_buf, ring_buf_p, ring_buf_hdr->avail_buf_size);
    *avail_buf_size = ring_buf_hdr->avail_buf_size;

    // Ensure that we poll rx_buf before we update ci
    MB();
    rx_ring_hdr->ci = (rx_ring_hdr->ci + 1) % msg_ring_h->rx_depth;

    return 0;
}

int msg_ring_poll_rx_batch(msg_ring_t *msg_ring_h, char **rx_buf, uint32_t rx_max_buf_size,
    uint32_t *avail_buf_size, uint32_t max_cnt)
{
    shm_ring_hdr_t *rx_ring_hdr = (shm_ring_hdr_t *)msg_ring_h->shm_rx_ring_hdr;
    if (rx_ring_hdr->pi == rx_ring_hdr->ci) {
        return 0;
    }

    uint32_t i = 0;
    uint32_t left_cnt = (rx_ring_hdr->pi + msg_ring_h->rx_depth - rx_ring_hdr->ci) % msg_ring_h->rx_depth;
    uint32_t max_cnt_ = left_cnt < max_cnt ? left_cnt : max_cnt;
    char *rx_buf_ = rx_buf[0];
    RMB();

    for (; i < max_cnt_; ++i) {
        shm_ring_buf_hdr_t *ring_buf_hdr = (shm_ring_buf_hdr_t *)(msg_ring_h->shm_rx_ring +
            ((rx_ring_hdr->ci + i) % msg_ring_h->rx_depth) * msg_ring_h->rx_max_buf_size);
        char *ring_buf_p = (char *)(ring_buf_hdr + 1);
        if (rx_max_buf_size < ring_buf_hdr->avail_buf_size) {
            UMQ_LIMIT_VLOG_ERR("rx_max_buf_size %u is less than avail_buf_size %u\n", rx_max_buf_size,
                               ring_buf_hdr->avail_buf_size);
            return -1;
        }
        rx_buf_ = rx_buf[i];
        (void)memcpy(rx_buf_, ring_buf_p, ring_buf_hdr->avail_buf_size);
        avail_buf_size[i] = ring_buf_hdr->avail_buf_size;
    }

    // Ensure that we poll rx_buf before we update ci
    MB();
    rx_ring_hdr->ci = (rx_ring_hdr->ci + i) % msg_ring_h->rx_depth;

    return i;
}