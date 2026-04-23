/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider support netlink.
 */
#ifndef BONDP_NETLINK_H
#define BONDP_NETLINK_H

#define SEND_SWITCHBACK_REQ 0

typedef struct bondp_switchback_req {
    struct {
        uint32_t vjetty_id;
        uint32_t local_idx;
        uint32_t target_idx;
        uint8_t ctrl_type;
        uint8_t req_seq;
        uint16_t reserved;
        uint32_t payload;
    } in;
} bondp_switchback_req_t;

typedef struct bondp_switchback_msg {
    struct {
        uint32_t recv_local_id;
        uint8_t ctrl_type;
        uint8_t req_seq;
        uint16_t reserved;
        uint32_t payload;
    } in;
} bondp_switchback_msg_t;

int bondp_nl_init(void);
void bondp_nl_uninit(void);
int bondp_nl_get_fd(void);
int bondp_nl_send_switchback_req(const bondp_switchback_req_t *req);
int bondp_nl_recv_switchback_msg(bondp_switchback_msg_t *msg);
int bondp_fallback_ctrl_send_default(bondp_context_t *bdp_ctx, uint32_t vjetty_id,
    int local_idx, int target_idx, uint8_t ctrl_type, uint8_t req_seq, uint32_t payload);
#endif // BONDP_NETLINK_H
