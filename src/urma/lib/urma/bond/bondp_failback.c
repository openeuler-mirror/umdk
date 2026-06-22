/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Bond provider failback netlink helpers.
 */

#include <errno.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <stdint.h>
#include <string.h>

#include "bondp_netlink.h"
#include "bondp_types.h"
#include "ubagg_ioctl.h"
#include "urma_log.h"
#include "urma_provider.h"
#include "urma_types.h"

#include "bondp_failback.h"

typedef struct bondp_fb_task {
    uint32_t request_id;
    uint32_t peer_node_id;
    urma_eid_t src_eid;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
    uint32_t new_pjetty_id;
} bondp_fb_task_t;

typedef struct bondp_fb_result {
    uint32_t request_id;
    uint32_t peer_node_id;
    urma_eid_t src_eid;
    uint32_t vjetty_id;
    uint32_t pjetty_idx;
    uint32_t new_pjetty_id;
    int32_t result;
} bondp_fb_result_t;

static __attribute__((unused)) int bondp_fb_user_ctl_start(
    bondp_context_t *bdp_ctx,
    const bondp_fb_task_t *task)
{
    if (bdp_ctx == NULL || task == NULL) {
        return -EINVAL;
    }

    urma_user_ctl_in_t in = {
        .opcode = FAILBACK_START,
        .addr = (uint64_t)(uintptr_t)task,
        .len = sizeof(*task),
    };
    urma_user_ctl_out_t out = {0};
    urma_udrv_t udrv = {0};

    return urma_cmd_user_ctl(&bdp_ctx->v_ctx, &in, &out, &udrv);
}

static __attribute__((unused)) int bondp_fb_user_ctl_result(
    bondp_context_t *bdp_ctx,
    const bondp_fb_result_t *fb_result)
{
    if (bdp_ctx == NULL || fb_result == NULL) {
        return -EINVAL;
    }

    urma_user_ctl_in_t in = {
        .opcode = FAILBACK_RESULT,
        .addr = (uint64_t)(uintptr_t)fb_result,
        .len = sizeof(*fb_result),
    };
    urma_user_ctl_out_t out = {0};
    urma_udrv_t udrv = {0};

    return urma_cmd_user_ctl(&bdp_ctx->v_ctx, &in, &out, &udrv);
}

static void bondp_fb_handle_notify(const bondp_fb_task_t *task)
{
    (void)task;
}

static void bondp_fb_handle_done(const bondp_fb_result_t *result)
{
    (void)result;
}

void bondp_fb_handle_notify_nl_msg(struct nlattr *attrs[])
{
    if (attrs[BONDP_NL_ATTR_PAYLOAD] == NULL) {
        URMA_LOG_WARN("Missing failback notify netlink payload.\n");
        return;
    }

    void *payload = nla_data(attrs[BONDP_NL_ATTR_PAYLOAD]);
    int payload_len = nla_len(attrs[BONDP_NL_ATTR_PAYLOAD]);
    if (payload == NULL || payload_len != (int)sizeof(bondp_fb_task_t)) {
        URMA_LOG_WARN("Invalid failback notify payload len=%d\n", payload_len);
        return;
    }

    bondp_fb_task_t task = {0};
    (void)memcpy(&task, payload, sizeof(task));
    bondp_fb_handle_notify(&task);
}

void bondp_fb_handle_done_nl_msg(struct nlattr *attrs[])
{
    if (attrs[BONDP_NL_ATTR_PAYLOAD] == NULL) {
        URMA_LOG_WARN("Missing failback done netlink payload.\n");
        return;
    }

    void *payload = nla_data(attrs[BONDP_NL_ATTR_PAYLOAD]);
    int payload_len = nla_len(attrs[BONDP_NL_ATTR_PAYLOAD]);
    if (payload == NULL || payload_len != (int)sizeof(bondp_fb_result_t)) {
        URMA_LOG_WARN("Invalid failback done payload len=%d\n", payload_len);
        return;
    }

    bondp_fb_result_t result = {0};
    (void)memcpy(&result, payload, sizeof(result));
    bondp_fb_handle_done(&result);
}
