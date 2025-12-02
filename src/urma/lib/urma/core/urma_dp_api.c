/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: liburma data path API
 * Author: Ouyang Changchun, Qian Guoxin
 * Create: 2021-08-11
 * Note:
 * History: 2021-08-11
 */

#include <stddef.h>

#include "urma_api.h"
#include "urma_log.h"
#include "urma_opcode.h"
#include "urma_private.h"
#include "urma_provider.h"

static inline urma_ops_t *get_ops_by_urma_jfc(urma_jfc_t *jfc)
{
    if (jfc == NULL || jfc->urma_ctx == NULL) {
        return NULL;
    }
    return jfc->urma_ctx->ops;
}

static inline urma_ops_t *get_ops_by_urma_jfs(urma_jfs_t *jfs)
{
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->jfs_cfg.jfc == NULL) {
        return NULL;
    }
    return jfs->urma_ctx->ops;
}

static inline urma_ops_t *get_ops_by_urma_jfr(urma_jfr_t *jfr)
{
    if (jfr == NULL || jfr->urma_ctx == NULL || jfr->jfr_cfg.jfc == NULL) {
        return NULL;
    }
    return jfr->urma_ctx->ops;
}

static inline urma_ops_t *get_ops_by_urma_jfce(urma_jfce_t *jfce)
{
    if (jfce == NULL || jfce->urma_ctx == NULL) {
        return NULL;
    }
    return jfce->urma_ctx->ops;
}

static inline urma_ops_t *get_ops_by_urma_jetty(urma_jetty_t *jetty)
{
    if (jetty == NULL || jetty->urma_ctx == NULL || jetty->urma_ctx->dev == NULL) {
        return NULL;
    }

    return jetty->urma_ctx->ops;
}

static inline urma_status_t checkout_valid_tjfr(urma_target_jetty_t *tjfr)
{
    if (tjfr == NULL || tjfr->urma_ctx == NULL || tjfr->urma_ctx->dev == NULL) {
        return URMA_EINVAL;
    }
    return URMA_SUCCESS;
}

static inline int check_valid_sgl(urma_sg_t sg)
{
    for (uint32_t i = 0; i < sg.num_sge; i++) {
        if (sg.sge == NULL || sg.sge[i].addr == 0) {
            URMA_LOG_ERR("sge is a null pointer.\n");
            return -1;
        }
    }
    return 0;
}

static int check_valid_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr)
{
    if (jfr == NULL || wr == NULL) {
        URMA_LOG_ERR("There are invalid parameters.\n");
        return -1;
    }

    if (check_valid_sgl(wr->src) != 0) {
        return -1;
    }
    return 0;
}

urma_status_t urma_write(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,         //
                         urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg, //
                         uint64_t dst, uint64_t src, uint32_t len,                 //
                         urma_jfs_wr_flag_t flag, uint64_t user_ctx)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jfs(jfs);
    /* src_tseg could be NULL as src data could be inline data */
    if (dp_ops == NULL || dp_ops->post_jfs_wr == NULL || target_jfr == NULL || dst_tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_sge_t src_sge = {.addr = src, .len = len, .tseg = (urma_target_seg_t *)src_tseg};
    urma_sge_t dst_sge = {.addr = dst, .len = len, .tseg = (urma_target_seg_t *)dst_tseg};
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr;
    wr.opcode = URMA_OPC_WRITE;
    wr.flag = flag;
    wr.user_ctx = user_ctx;
    wr.rw.src.num_sge = 1;
    wr.rw.src.sge = &src_sge;
    wr.rw.dst.num_sge = 1;
    wr.rw.dst.sge = &dst_sge;
    wr.tjetty = (urma_target_jetty_t *)target_jfr;
    wr.next = NULL;
    return dp_ops->post_jfs_wr(jfs, &wr, &bad_wr);
}

urma_status_t urma_read(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,         //
                        urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg, //
                        uint64_t dst, uint64_t src, uint32_t len,                 //
                        urma_jfs_wr_flag_t flag, uint64_t user_ctx)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jfs(jfs);
    if (dp_ops == NULL || dp_ops->post_jfs_wr == NULL || target_jfr == NULL || dst_tseg == NULL || src_tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_sge_t src_sge = {.addr = src, .len = len, .tseg = (urma_target_seg_t *)src_tseg};
    urma_sge_t dst_sge = {.addr = dst, .len = len, .tseg = (urma_target_seg_t *)dst_tseg};
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr;
    wr.opcode = URMA_OPC_READ;
    wr.flag = flag;
    wr.user_ctx = user_ctx;
    wr.rw.src.num_sge = 1;
    wr.rw.src.sge = &src_sge;
    wr.rw.dst.num_sge = 1;
    wr.rw.dst.sge = &dst_sge;
    wr.tjetty = (urma_target_jetty_t *)target_jfr;
    wr.next = NULL;
    return dp_ops->post_jfs_wr(jfs, &wr, &bad_wr);
}

urma_status_t urma_send(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,        //
                        urma_target_seg_t *src_tseg, uint64_t src, uint32_t len, //
                        urma_jfs_wr_flag_t flag, uint64_t user_ctx)
{
    /* check parameter */
    if (checkout_valid_tjfr(target_jfr) != URMA_SUCCESS) {
        URMA_LOG_ERR("null pointer exists in tjfr.\n");
        return URMA_EINVAL;
    }
    urma_ops_t *dp_ops = get_ops_by_urma_jfs(jfs);
    if (dp_ops == NULL || dp_ops->post_jfs_wr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (flag.bs.inline_flag == URMA_INLINE_DISABLE && src_tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_sge_t src_sge = {.addr = src, .len = len, .tseg = (urma_target_seg_t *)src_tseg};
    urma_jfs_wr_t wr;
    urma_jfs_wr_t *bad_wr;
    wr.opcode = URMA_OPC_SEND;
    wr.flag = flag;
    wr.user_ctx = user_ctx;
    wr.send.src.num_sge = 1;
    wr.send.src.sge = &src_sge;
    wr.tjetty = (urma_target_jetty_t *)target_jfr;
    wr.send.tseg = NULL;
    wr.next = NULL;
    return dp_ops->post_jfs_wr(jfs, &wr, &bad_wr);
}

urma_status_t urma_recv(urma_jfr_t *jfr, urma_target_seg_t *recv_tseg, //
                        uint64_t buf, uint32_t len, uint64_t user_ctx)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jfr(jfr);

    if (dp_ops == NULL || dp_ops->post_jfr_wr == NULL || recv_tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_sge_t src_sge = {.addr = buf, .len = len, .tseg = recv_tseg};

    urma_jfr_wr_t wr;
    urma_jfr_wr_t *bad_wr;
    wr.user_ctx = user_ctx;
    wr.src.sge = &src_sge;
    wr.src.num_sge = 1;
    wr.next = NULL;
    if (check_valid_jfr_wr(jfr, &wr) != 0) {
        URMA_LOG_ERR("There are invalid parameters.\n");
        return URMA_FAIL;
    }
    return dp_ops->post_jfr_wr(jfr, &wr, &bad_wr);
}

int urma_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
    urma_ops_t *dp_ops = get_ops_by_urma_jfc(jfc);
    if (dp_ops == NULL || dp_ops->poll_jfc == NULL || cr == NULL || cr_cnt < 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    return dp_ops->poll_jfc(jfc, cr_cnt, cr);
}

urma_status_t urma_rearm_jfc(urma_jfc_t *jfc, bool solicited_only)
{
    urma_ops_t *dp_ops = get_ops_by_urma_jfc(jfc);
    if (dp_ops == NULL || dp_ops->rearm_jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return dp_ops->rearm_jfc(jfc, solicited_only);
}

int urma_wait_jfc(urma_jfce_t *jfce, uint32_t jfc_cnt, int time_out, urma_jfc_t *jfc[])
{
    urma_ops_t *dp_ops = get_ops_by_urma_jfce(jfce);
    if (dp_ops == NULL || dp_ops->wait_jfc == NULL || jfc_cnt == 0 || jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    return dp_ops->wait_jfc(jfce, jfc_cnt, time_out, jfc);
}

void urma_ack_jfc(urma_jfc_t *jfc[], uint32_t nevents[], uint32_t jfc_cnt)
{
    if (jfc == NULL || nevents == NULL || jfc_cnt == 0) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return;
    }
    urma_ops_t *dp_ops = get_ops_by_urma_jfc(jfc[0]);
    if (dp_ops == NULL || dp_ops->ack_jfc == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return;
    }
    dp_ops->ack_jfc(jfc, nevents, jfc_cnt);
}

urma_status_t urma_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jfs(jfs);
    if (dp_ops == NULL || dp_ops->post_jfs_wr == NULL || wr == NULL || bad_wr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    return dp_ops->post_jfs_wr(jfs, wr, bad_wr);
}

urma_status_t urma_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jfr(jfr);
    if (dp_ops == NULL || dp_ops->post_jfr_wr == NULL || wr == NULL || bad_wr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }
    return dp_ops->post_jfr_wr(jfr, wr, bad_wr);
}

urma_status_t urma_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jetty(jetty);
    if (dp_ops == NULL || dp_ops->post_jetty_send_wr == NULL || wr == NULL || bad_wr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return dp_ops->post_jetty_send_wr(jetty, wr, bad_wr);
}

urma_status_t urma_post_jetty_recv_wr(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    /* check parameter */
    urma_ops_t *dp_ops = get_ops_by_urma_jetty(jetty);
    if (dp_ops == NULL || dp_ops->post_jetty_recv_wr == NULL || wr == NULL || bad_wr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    return dp_ops->post_jetty_recv_wr(jetty, wr, bad_wr);
}
