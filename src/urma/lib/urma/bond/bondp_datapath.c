/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond datapth ops implementation file
 * Author: Ma Chuan
 * Create: 2025-02-19
 * Note:
 * History: 2025-02-19   Create File
 */

#include <threads.h>

#include "bondp_connection.h"
#include "bondp_context_table.h"
#include "bondp_datapath_convert.h"
#include "bondp_datapath_schedule.h"
#include "bondp_health_check.h"
#include "bondp_types.h"
#include "ub_get_clock.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"
#include "urma_provider.h"

#include "bondp_datapath.h"

#define URMA_BONDP_BATCH_POST_MAX_NUM 280

static urma_jetty_id_t *get_comp_urma_jetty_id(bondp_comp_t *bdp_comp)
{
    switch (bdp_comp->comp_type) {
        case BONDP_COMP_JFS:
            return &bdp_comp->v_jfs.jfs_id;
        case BONDP_COMP_JETTY:
            return &bdp_comp->v_jetty.jetty_id;
        case BONDP_COMP_JFR:
            return &bdp_comp->v_jfr.jfr_id;
        default:
            URMA_LOG_ERR("Failed to get_comp_urma_jetty, Invalid type=%d\n", bdp_comp->comp_type);
            return NULL;
    }
}

static wr_buf_t *get_recv_wr_buf(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return NULL;
    }
    if (bdp_comp->comp_type == BONDP_COMP_JETTY) {
        urma_jfr_t *jfr = bdp_comp->v_jetty.jetty_cfg.shared.jfr;
        if (jfr == NULL) {
            URMA_LOG_ERR("JETTY shared jfr is NULL\n");
            return NULL;
        }
        bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
        return &bdp_jfr->recv_wr_buf;
    } else if (bdp_comp->comp_type == BONDP_COMP_JFR) {
        return &bdp_comp->recv_wr_buf;
    }
    return NULL;
}

static pthread_spinlock_t *get_recv_wr_lock(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return NULL;
    }
    if (bdp_comp->comp_type == BONDP_COMP_JETTY) {
        urma_jfr_t *jfr = bdp_comp->v_jetty.jetty_cfg.shared.jfr;
        if (jfr == NULL) {
            URMA_LOG_ERR("JETTY shared jfr is NULL\n");
            return NULL;
        }
        bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
        return &bdp_jfr->recv_wr_lock;
    } else if (bdp_comp->comp_type == BONDP_COMP_JFR) {
        return &bdp_comp->recv_wr_lock;
    }
    return NULL;
}

static urma_status_t comp_post_send(bondp_comp_t *comp, int send_idx, urma_jfs_wr_t *send_wr, urma_jfs_wr_t **bad_wr,
    int wr_count)
{
    urma_status_t ret;
    if (comp->comp_type == BONDP_COMP_JETTY) {
        ret = urma_post_jetty_send_wr(comp->p_jetty[send_idx], send_wr, bad_wr);
    } else if (comp->comp_type == BONDP_COMP_JFS) {
        ret = urma_post_jfs_wr(comp->p_jfs[send_idx], send_wr, bad_wr);
    } else {
        URMA_LOG_ERR("Invalid post jfs wr type=%d\n", comp->comp_type);
        ret = URMA_EINVAL;
    }
    if (ret == URMA_SUCCESS) {
        atomic_fetch_add(&comp->sqe_cnt[send_idx], wr_count);
    }
    return ret;
}

static urma_status_t comp_post_recv(bondp_comp_t *comp, int recv_idx, urma_jfr_wr_t *recv_wr, urma_jfr_wr_t **bad_wr)
{
    urma_status_t ret;
    if (comp->comp_type == BONDP_COMP_JETTY) {
        ret = urma_post_jetty_recv_wr(comp->p_jetty[recv_idx], recv_wr, bad_wr);
    } else if (comp->comp_type == BONDP_COMP_JFR) {
        ret = urma_post_jfr_wr(comp->p_jfr[recv_idx], recv_wr, bad_wr);
    } else {
        URMA_LOG_ERR("Invalid post jfr wr type=%d\n", comp->comp_type);
        ret = URMA_EINVAL;
    }
    if (ret == URMA_SUCCESS) {
        comp->rqe_cnt[recv_idx] += 1;
    }
    return ret;
}

static urma_status_t post_send_check_jfs_wr_valid(const bondp_context_t *bdp_ctx, const urma_jfs_wr_t *wr)
{
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            /* No need to handle cases where num_sge == 0 or sge == NULL;
               UDMA will take care of it, as SEND_WITH_IMM may allow NULL to be passed.
            */
            if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->send.src.num_sge) {
                URMA_LOG_WARN("The number of sge %u the destination segment is greater than the maximum supported=%u"
                              "by the device.\n",
                              wr->send.src.num_sge,
                              bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
            }
            break;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            /* It must be verified; otherwise, udma will cause a segmentation fault. */
            if (wr->rw.src.num_sge == 0 || wr->rw.dst.num_sge == 0 ||
                wr->rw.src.sge == NULL || wr->rw.dst.sge == NULL) {
                URMA_LOG_ERR("when set write_wr, either of src/dst num_sge/sge has been set zero or NULL.\n");
                return URMA_EINVAL;
            }
            /* The limitation of rsge is the number of *remote sge* that can be accessed,
               whether for write or read operations. */
            if (wr->opcode == URMA_OPC_READ) {
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge < wr->rw.src.num_sge) {
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.src.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge);
                }
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.dst.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
                }
            } else {
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->rw.src.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.src.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
                }
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.dst.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge);
                }
            }
            break;
        case URMA_OPC_CAS:
            /* It must be verified; otherwise, udma will cause a segmentation fault. */
            if (wr->cas.src == NULL || wr->cas.dst == NULL) {
                URMA_LOG_ERR("when set cas_wr, either src or dst is NULL.\n");
                return URMA_EINVAL;
            }
            break;
        case URMA_OPC_FADD:
            /* It must be verified; otherwise, udma will cause a segmentation fault. */
            if (wr->faa.src == NULL || wr->faa.dst == NULL) {
                URMA_LOG_ERR("when set faa_wr, either src or dst is NULL.\n");
                return URMA_EINVAL;
            }
            break;
        default:
            break;
    }
    return URMA_SUCCESS;
}

static urma_status_t post_send_check_valid(bondp_comp_t *bdp_send_comp, bondp_target_jetty_t *bdp_tjetty,
                                           const urma_jfs_wr_t *wr)
{
    if (bdp_send_comp->comp_type != BONDP_COMP_JFS && bdp_send_comp->comp_type != BONDP_COMP_JETTY) {
        URMA_LOG_ERR("Try to call post_send api by invalid comp_type=%d\n", bdp_send_comp->comp_type);
        return URMA_EINVAL;
    }
    urma_status_t ret = post_send_check_jfs_wr_valid(bdp_send_comp->bondp_ctx, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    if (wr->flag.bs.has_drv_ext) {
        bondp_jfs_wr_t *bwr = CONTAINER_OF_FIELD(wr, bondp_jfs_wr_t, base);
        /* currently only check src_chip_id */
        if (bwr->src_chip_id < BONDP_CHIP_ID_MIN || bwr->src_chip_id > BONDP_CHIP_ID_MAX) {
            URMA_LOG_ERR("Invalid src_chip_id=%u.\n", bwr->src_chip_id);
            return URMA_EINVAL;
        }
    }
    return URMA_SUCCESS;
}

static urma_status_t post_send_check_wr_list_valid(bondp_comp_t *bdp_send_comp, const urma_jfs_wr_t *wr,
                                                   urma_jfs_wr_t **bad_wr)
{
    bondp_target_jetty_t *bdp_tjetty = NULL;
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *cur = (urma_jfs_wr_t *)wr;

    while (cur != NULL) {
        /* No need to check NULL for tjetty of each wr */
        bdp_tjetty = CONTAINER_OF_FIELD(cur->tjetty, bondp_target_jetty_t, v_tjetty);
        ret = post_send_check_valid(bdp_send_comp, bdp_tjetty, cur);
        if (ret != URMA_SUCCESS) {
            *bad_wr = cur;
            return ret;
        }
        cur = cur->next;
    }

    return URMA_SUCCESS;
}

static urma_status_t bondp_post_send_wr_no_store(bondp_comp_t *bdp_comp,
                                                 const urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    // Pre-allocated space to improve datapath performance
    static thread_local urma_jfs_wr_t prealloc_wr_list[BONDP_MAX_WR_LIST_NUM];
    static thread_local urma_sge_t prealloc_src_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];
    static thread_local urma_sge_t prealloc_dst_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];

    urma_status_t ret = URMA_SUCCESS;

    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("WR->tjetty is NULL\n");
        return URMA_EINVAL;
    }

    int send_idx = -1, target_idx = -1;
    if (!wr->flag.bs.has_drv_ext) {
        ret = schedule_send(wr->tjetty, bdp_comp, &send_idx, &target_idx, NULL);
    } else {
        bondp_jfs_wr_t *bwr = CONTAINER_OF_FIELD(wr, bondp_jfs_wr_t, base);
        bondp_chip_id_info_t info = {.src_chip_id = bwr->src_chip_id, .dst_chip_id = bwr->dst_chip_id};
        ret = schedule_send(wr->tjetty, bdp_comp, &send_idx, &target_idx, &info);
    }
    if (ret != 0) {
        return URMA_FAIL;
    }

    int index = 0;
    urma_jfs_wr_t *vwr = (urma_jfs_wr_t *)wr;
    while (vwr != NULL) {
        urma_jfs_wr_t *pwr = &prealloc_wr_list[index];
        ret = copy_jfs_wr(vwr, pwr, prealloc_src_sge[index], prealloc_dst_sge[index]);
        if (ret != 0) {
            return ret;
        }
        ret = convert_jfs_vwr_to_pwr(pwr, send_idx, target_idx, bdp_comp);
        if (ret != 0) {
            return ret;
        }
        if (vwr->next != NULL) {
            pwr->next = &prealloc_wr_list[index + 1];
        }

        vwr = vwr->next;
        index++;
        if (index >= BONDP_MAX_WR_LIST_NUM - 1) {
            URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_MAX_WR_LIST_NUM - 1);
            return URMA_EINVAL;
        }
    }

    ret = comp_post_send(bdp_comp, send_idx, prealloc_wr_list, bad_wr, 1);
    return ret;
}

/**
 * This function assumes all WRs in the list share the same tjetty and scheduling result.
 * It processes each WR under a single lock acquisition, allocates entries, copies and
 * converts the WRs, then submits them as a batch to comp_post_send.
 */
static urma_status_t bondp_post_send_wr_list_and_store(bondp_comp_t *bdp_comp,
    urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    if (bdp_comp->comp_type != BONDP_COMP_JFS && bdp_comp->comp_type != BONDP_COMP_JETTY) {
        URMA_LOG_ERR("Try to call post_send api by invalid comp_type=%d\n", bdp_comp->comp_type);
        return URMA_EINVAL;
    }
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *cur = wr;
    int wr_count = 0;
    int send_idx = 0;
    int target_idx = 0;
    bondp_target_jetty_t *bdp_tjetty = NULL;
    bondp_chip_id_info_t chip_info = {0};
    int processed = 0;
    int success_node = 0;
    jfs_wr_entry_t *wr_entries[URMA_BONDP_BATCH_POST_MAX_NUM];

    bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("WR->tjetty is NULL\n");
        return URMA_EINVAL;
    }

    if (!cur->flag.bs.has_drv_ext) {
        ret = schedule_send(cur->tjetty, bdp_comp, &send_idx, &target_idx, NULL);
    } else {
        bondp_jfs_wr_t *bwr = CONTAINER_OF_FIELD(cur, bondp_jfs_wr_t, base);
        chip_info.src_chip_id = bwr->src_chip_id;
        chip_info.dst_chip_id = bwr->dst_chip_id;
        ret = schedule_send(cur->tjetty, bdp_comp, &send_idx, &target_idx, &chip_info);
    }
    if (ret != 0) {
        return URMA_FAIL;
    }

    (void)pthread_spin_lock(&bdp_comp->send_wr_lock);
    while (cur != NULL && wr_count < URMA_BONDP_BATCH_POST_MAX_NUM) {
        wr_entries[wr_count] = jfs_wr_buf_alloc(&bdp_comp->send_wr_buf);
        if (wr_entries[wr_count] == NULL) {
            (void)pthread_spin_unlock(&bdp_comp->send_wr_lock);
            ret = URMA_FAIL;
            goto RELEASEBUF;
        }
        wr_entries[wr_count]->user_ctx = cur->user_ctx;
        wr_entries[wr_count]->target_vjetty = bdp_tjetty;
        wr_entries[wr_count]->send_idx = send_idx;
        wr_entries[wr_count]->target_idx = target_idx;
        wr_entries[wr_count]->bdp_comp = bdp_comp;
        wr_count++;
        cur = cur->next;
    }
    (void)pthread_spin_unlock(&bdp_comp->send_wr_lock);

    if (cur != NULL) {
        URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", URMA_BONDP_BATCH_POST_MAX_NUM);
        ret = URMA_EINVAL;
        goto RELEASEBUF;
    }

    cur = wr;
    for (int i = 0; i < wr_count; i++, cur = cur->next) {
        jfs_wr_entry_t *wr_entry = wr_entries[i];
        urma_jfs_wr_t *pwr = &wr_entry->wr;

        ret = copy_jfs_wr(cur, pwr, NULL, NULL);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to copy jfs wr\n");
            free_jfs_wr(pwr);
            goto CLEANUP;
        }

        add_vwr_use_cnt(pwr);
        ret = convert_jfs_vwr_to_pwr(pwr, wr_entry->send_idx, wr_entry->target_idx, bdp_comp);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to convert jfs wr\n");
            convert_jfs_pwr_to_vwr_resend(pwr, &wr_entry->target_vjetty->v_tjetty);
            release_vwr_use_cnt(pwr);
            free_jfs_wr(pwr);
            goto CLEANUP;
        }
        pwr->user_ctx = wr_entry->wr_id;

        if (i > 0) {
            wr_entries[i - 1]->wr.next = pwr;
        }
        pwr->next = NULL;
        processed++;
    }

    ret = comp_post_send(bdp_comp, send_idx, &wr_entries[0]->wr, bad_wr, wr_count);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post send wr batch, ret: %d.\n", ret);
        goto ROLLBACK;
    }
    return URMA_SUCCESS;

ROLLBACK:
    cur = &wr_entries[0]->wr;
    while (cur != NULL && bad_wr != NULL && cur != *bad_wr) {
        success_node++;
        cur = cur->next;
    }
    atomic_fetch_add(&bdp_comp->sqe_cnt[send_idx], success_node); // submit success node
CLEANUP:
    for (int j = success_node; j < processed; j++) {
        convert_jfs_pwr_to_vwr_resend(&wr_entries[j]->wr, &wr_entries[j]->target_vjetty->v_tjetty);
        release_vwr_use_cnt(&wr_entries[j]->wr);
        free_jfs_wr(&wr_entries[j]->wr);
    }
RELEASEBUF:
    (void)pthread_spin_lock(&bdp_comp->send_wr_lock);
    for (int j = success_node; j < wr_count; j++) {
        jfs_wr_buf_release(wr_entries[j]);
    }
    (void)pthread_spin_unlock(&bdp_comp->send_wr_lock);
    return ret;
}

urma_status_t bondp_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_status_t ret = URMA_SUCCESS;

    PERF_PROFILING_START(BOND_JETTY_POST_SEND);
    ret = post_send_check_wr_list_valid(bdp_jetty, wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_JETTY_POST_SEND);
        return ret;
    }

    if (is_single_dev_mode(bdp_jetty->bondp_ctx)) {
        ret = bondp_post_send_wr_no_store(bdp_jetty, wr, bad_wr);
    } else {
        (void)pthread_spin_lock(&bdp_jetty->send_lock);
        ret = bondp_post_send_wr_list_and_store(bdp_jetty, wr, bad_wr);
        (void)pthread_spin_unlock(&bdp_jetty->send_lock);
    }
    PERF_PROFILING_END(BOND_JETTY_POST_SEND);

    return ret;
}

urma_status_t bondp_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);
    urma_status_t ret = URMA_SUCCESS;

    PERF_PROFILING_START(BOND_JFS_POST_SEND);
    ret = post_send_check_wr_list_valid(bdp_jfs, wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_JFS_POST_SEND);
        return ret;
    }
    if (is_single_dev_mode(bdp_jfs->bondp_ctx)) {
        ret = bondp_post_send_wr_no_store(bdp_jfs, wr, bad_wr);
    } else {
        (void)pthread_spin_lock(&bdp_jfs->send_lock);
        ret = bondp_post_send_wr_list_and_store(bdp_jfs, wr, bad_wr);
        (void)pthread_spin_unlock(&bdp_jfs->send_lock);
    }
    PERF_PROFILING_END(BOND_JFS_POST_SEND);

    return ret;
}

urma_status_t urma_write_affinity(urma_jfs_t *jfs, urma_target_jetty_t *target_jfr,         //
                                  urma_target_seg_t *dst_tseg, urma_target_seg_t *src_tseg, //
                                  uint64_t dst, uint64_t src, uint32_t len,                 //
                                  urma_jfs_wr_flag_t flag, uint64_t user_ctx,               //
                                  uint32_t src_chip_id, uint32_t dst_chip_id)
{
    /* check parameter */
    if (jfs == NULL || jfs->urma_ctx == NULL || jfs->jfs_cfg.jfc == NULL) {
        return URMA_EINVAL;
    }
    urma_ops_t *dp_ops = jfs->urma_ctx->ops;
    /* src_tseg could be NULL as src data could be inline data */
    if (dp_ops == NULL || dp_ops->post_jfs_wr == NULL || target_jfr == NULL || dst_tseg == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_sge_t src_sge = {.addr = src, .len = len, .tseg = (urma_target_seg_t *)src_tseg};
    urma_sge_t dst_sge = {.addr = dst, .len = len, .tseg = (urma_target_seg_t *)dst_tseg};
    bondp_jfs_wr_t wr;
    urma_jfs_wr_t *base = &wr.base;
    urma_jfs_wr_t *bad_wr;
    base->opcode = URMA_OPC_WRITE;
    base->flag = flag;
    base->flag.bs.has_drv_ext = 1;
    base->user_ctx = user_ctx;
    base->rw.src.num_sge = 1;
    base->rw.src.sge = &src_sge;
    base->rw.dst.num_sge = 1;
    base->rw.dst.sge = &dst_sge;
    base->tjetty = (urma_target_jetty_t *)target_jfr;
    base->next = NULL;
    wr.src_chip_id = src_chip_id;
    wr.dst_chip_id = dst_chip_id;
    return dp_ops->post_jfs_wr(jfs, base, &bad_wr);
}

static urma_status_t bondp_post_recv_wr_no_store(bondp_comp_t *bdp_comp,
                                                 const urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    // Pre-allocated space to improve datapath performance
    static thread_local urma_jfr_wr_t prealloc_wr_list[BONDP_MAX_WR_LIST_NUM];
    static thread_local urma_sge_t prealloc_src_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];

    urma_status_t ret = 0;

    int recv_idx = -1;
    ret = schedule_recv(bdp_comp, &recv_idx);
    if (ret != 0) {
        return URMA_FAIL;
    }

    int index = 0;
    urma_jfr_wr_t *vwr = (urma_jfr_wr_t *)wr;
    while (vwr != NULL) {
        urma_jfr_wr_t *pwr = &prealloc_wr_list[index];
        ret = copy_jfr_wr(vwr, pwr, prealloc_src_sge[index]);
        if (ret != 0) {
            return ret;
        }
        ret = convert_jfr_vwr_to_pwr(pwr, recv_idx);
        if (ret != 0) {
            return ret;
        }
        if (vwr->next != NULL) {
            pwr->next = &prealloc_wr_list[index + 1];
        }

        vwr = vwr->next;
        index++;
        if (index >= BONDP_MAX_WR_LIST_NUM - 1) {
            URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_MAX_WR_LIST_NUM - 1);
            return URMA_EINVAL;
        }
    }

    ret = comp_post_recv(bdp_comp, recv_idx, prealloc_wr_list, bad_wr);
    return ret;
}

static urma_status_t bondp_post_recv_wr_and_store(bondp_comp_t *bdp_comp, urma_jfr_wr_t *wr,
                                                  urma_jfr_wr_t **bad_wr)
{
    urma_status_t ret;

    int recv_idx = 0;
    ret = schedule_recv(bdp_comp, &recv_idx);
    if (ret != 0) {
        return URMA_FAIL;
    }

    wr_buf_t *recv_wr_buf = get_recv_wr_buf(bdp_comp);
    pthread_spinlock_t *recv_wr_lock = get_recv_wr_lock(bdp_comp);
    if (recv_wr_buf == NULL || recv_wr_lock == NULL) {
        URMA_LOG_ERR("Failed to get recv_wr_buf or recv_wr_lock, comp_type:%d\n", bdp_comp->comp_type);
        return URMA_EINVAL;
    }

    (void)pthread_spin_lock(recv_wr_lock);
    jfr_wr_entry_t *wr_entry = jfr_wr_buf_alloc(recv_wr_buf);
    (void)pthread_spin_unlock(recv_wr_lock);
    if (wr_entry == NULL) {
        URMA_LOG_ERR("Failed to allocate jfr wr entry\n");
        return URMA_EAGAIN;
    }
    wr_entry->user_ctx = wr->user_ctx;
    wr_entry->bdp_comp = bdp_comp;
    wr_entry->recv_idx = recv_idx;

    urma_jfr_wr_t *pwr = &wr_entry->wr;
    ret = copy_jfr_wr(wr, pwr, NULL);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to copy jfr wr\n");
        goto FREE_PWR;
    }

    ret = convert_jfr_vwr_to_pwr(pwr, recv_idx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to convert jfr wr\n");
        goto FREE_PWR;
    }

    pwr->user_ctx = wr_entry->wr_id;
    ret = comp_post_recv(bdp_comp, recv_idx, pwr, bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post recv wr\n");
        goto FREE_PWR;
    }

    return URMA_SUCCESS;

FREE_PWR:
    free_jfr_wr(pwr);
    (void)pthread_spin_lock(recv_wr_lock);
    jfr_wr_buf_release(wr_entry);
    (void)pthread_spin_unlock(recv_wr_lock);
    return ret;
}

static urma_status_t post_recv_check_jfr_wr_valid(const bondp_context_t *bdp_ctx, const urma_jfr_wr_t *wr)
{
    /* No need to handle cases where num_sge == 0 or sge == NULL; Certain hardware supports this usage. */
    if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfr_sge < wr->src.num_sge) {
        URMA_LOG_WARN("The number of sge %u the src segment is greater than the maximum supported=%u"
                      " by the device.\n",
                      wr->src.num_sge,
                      bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfr_sge);
    }
    return URMA_SUCCESS;
}

static urma_status_t post_recv_check_wr_list_valid(bondp_comp_t *bdp_recv_comp, const urma_jfr_wr_t *wr,
                                                   urma_jfr_wr_t **bad_wr)
{
    if (bdp_recv_comp->comp_type != BONDP_COMP_JETTY && bdp_recv_comp->comp_type != BONDP_COMP_JFR) {
        URMA_LOG_ERR("Invalid bdp_recv_comp type=%d\n", bdp_recv_comp->comp_type);
        *bad_wr = (urma_jfr_wr_t *)wr;
        return URMA_EINVAL;
    }
    urma_status_t ret = URMA_SUCCESS;
    urma_jfr_wr_t *cur = (urma_jfr_wr_t *)wr;
    while (cur != NULL) {
        ret = post_recv_check_jfr_wr_valid(bdp_recv_comp->bondp_ctx, cur);
        if (ret != URMA_SUCCESS) {
            *bad_wr = cur;
            return ret;
        }
        cur = cur->next;
    }

    return URMA_SUCCESS;
}

urma_status_t bondp_post_jetty_recv_wr(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_status_t ret = URMA_SUCCESS;

    PERF_PROFILING_START(BOND_JETTY_POST_RECV);
    ret = post_recv_check_wr_list_valid(bdp_jetty, wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_JETTY_POST_RECV);
        return ret;
    }

    if (is_single_dev_mode(bdp_jetty->bondp_ctx)) {
        ret = bondp_post_recv_wr_no_store(bdp_jetty, wr, bad_wr);
    } else {
        urma_jfr_wr_t *cur = wr;

        while (cur != NULL) {
            ret = bondp_post_recv_wr_and_store(bdp_jetty, cur, bad_wr);
            if (ret != URMA_SUCCESS) {
                PERF_PROFILING_END(BOND_JETTY_POST_RECV);
                return ret;
            }
            cur = cur->next;
        }
    }
    PERF_PROFILING_END(BOND_JETTY_POST_RECV);

    return ret;
}

urma_status_t bondp_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
    urma_status_t ret = URMA_SUCCESS;

    PERF_PROFILING_START(BOND_POST_JFR_RECV);
    ret = post_recv_check_wr_list_valid(bdp_jfr, wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_POST_JFR_RECV);
        return ret;
    }

    if (is_single_dev_mode(bdp_jfr->bondp_ctx)) {
        ret = bondp_post_recv_wr_no_store(bdp_jfr, wr, bad_wr);
    } else {
        urma_jfr_wr_t *cur = wr;

        while (cur != NULL) {
            ret = bondp_post_recv_wr_and_store(bdp_jfr, cur, bad_wr);
            if (ret != URMA_SUCCESS) {
                PERF_PROFILING_END(BOND_POST_JFR_RECV);
                return ret;
            }
            cur = cur->next;
        }
    }
    PERF_PROFILING_END(BOND_POST_JFR_RECV);

    return ret;
}

typedef enum cr_convert_ret {
    // CR conversion failed and the caller should abort the polling flow.
    CONVERT_FAIL = -1,
    // CR is converted successfully and should be returned to the caller, regardless of cr's own status.
    CONVERT_SUCCESS = 0,
    // CR is consumed internally and should not be returned to the caller.
    CONVERT_SKIP = 1,
} cr_convert_ret_t;

static int resend_jfs_wr(bondp_comp_t *bdp_comp, jfs_wr_entry_t *wr_entry, int send_idx, int target_idx)
{
    wr_entry->send_idx = send_idx;
    wr_entry->target_idx = target_idx;
    urma_jfs_wr_t *wr = &wr_entry->wr;
    urma_target_jetty_t *vtjetty = &wr_entry->target_vjetty->v_tjetty;
    convert_jfs_pwr_to_vwr_resend(wr, vtjetty);
    convert_jfs_vwr_to_pwr_for_resend(wr, send_idx, target_idx);

    urma_jfs_wr_t *bad_wr = NULL;
    int ret = comp_post_send(wr_entry->bdp_comp, send_idx, wr, &bad_wr, 1);

    if (ret != URMA_SUCCESS) {
        convert_jfs_pwr_to_vwr_resend(wr, vtjetty);
        release_vwr_use_cnt(wr);
        free_jfs_wr(wr);
        (void)pthread_spin_lock(&bdp_comp->send_wr_lock);
        jfs_wr_buf_release(wr_entry);
        (void)pthread_spin_unlock(&bdp_comp->send_wr_lock);
    }

    return ret;
}

static bondp_comp_t *get_comp_by_cr(bondp_context_t *bdp_ctx, int dev_idx, urma_cr_t *cr)
{
    urma_jetty_id_t pjetty_id = {
        .eid = bdp_ctx->p_ctxs[dev_idx]->eid,
        .id = cr->local_id,
    };

    bdp_p_vjetty_type_t p_vjetty_type;
    if (cr->flag.bs.jetty != 0) {
        p_vjetty_type = JETTY;
    } else if (cr->flag.bs.s_r == 0) {
        p_vjetty_type = JFS;
    } else {
        p_vjetty_type = JFR;
    }

    pthread_rwlock_rdlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_comp_t *comp = bdp_p_vjetty_id_table_lookup_comp_without_lock(
        &bdp_ctx->p_vjetty_id_table, pjetty_id, p_vjetty_type);
    if (comp == NULL) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to get comp, local_id=%d\n", pjetty_id.id);
        return NULL;
    }
    atomic_fetch_add(&comp->use_cnt.atomic_cnt, 1);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return comp;
}

static inline void put_comp(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return;
    }
    atomic_fetch_sub(&bdp_comp->use_cnt.atomic_cnt, 1);
}

static cr_convert_ret_t handle_fake_cr_with_store(bondp_context_t *bdp_ctx, int idx, urma_cr_t *cr)
{
    bondp_comp_t *comp = get_comp_by_cr(bdp_ctx, idx, cr);
    if (comp == NULL) {
        URMA_LOG_ERR("Skip fake cr because vjetty is not found, idx=%d, local_id=%u\n",
                     idx, cr->local_id);
        return CONVERT_SKIP;
    }

    uint8_t target_state_bit = 0;
    if (cr->status == URMA_CR_WR_SUSPEND_DONE) {
        target_state_bit = PJETTY_SUSPEND_DONE;
    } else if (cr->status == URMA_CR_WR_FLUSH_ERR_DONE) {
        target_state_bit = PJETTY_FLUSH_ERROR_DONE;
    } else {
        URMA_LOG_ERR("Invalid cr error status=%d\n", cr->status);
        put_comp(comp);
        return CONVERT_FAIL;
    }
    comp->pjettys_error_done[idx] |= target_state_bit;
    bool all_reported = true;
    // pjetty_idx
    for (int idx = 0; idx < URMA_UBAGG_DEV_MAX_NUM; idx++) {
        if (comp->members[idx] == NULL) {
            continue;
        }
        if ((comp->pjettys_error_done[idx] & target_state_bit) == 0) {
            all_reported = false;
            break;
        }
    }
    if (all_reported && comp->modify_to_error) {
        cr->local_id = get_comp_urma_jetty_id(comp)->id;
        /* Caller should copy this CR to output array. */
        put_comp(comp);
        return CONVERT_SUCCESS;
    }
    put_comp(comp);
    return CONVERT_SKIP;
}

static cr_convert_ret_t handle_send_cr_with_store(bondp_context_t *bdp_ctx, int idx, urma_cr_t *cr)
{
    const uint64_t wr_id = cr->user_ctx;
    bondp_comp_t *bdp_comp = get_comp_by_cr(bdp_ctx, idx, cr);
    if (bdp_comp == NULL) {
        URMA_LOG_ERR("Failed to find jetty when handle send cr, cr.local_id=%u.\n", cr->local_id);
        return CONVERT_SKIP;
    }

    jfs_wr_entry_t *wr_entry = jfs_wr_buf_get(&bdp_comp->send_wr_buf, wr_id);
    if (wr_entry == NULL) {
        /*
         * For backup path retransmission: the CR for the retransmitted WR may complete
         * before the error-reporting CR from the original path, causing premature WR
         * entry release and NULL retrieval. The current fix is to skip these CRs,
         * but this is risky because subsequent WRs may reuse the same memory,
         * resulting in WR/CR mismatch.
         */
        put_comp(bdp_comp);
        return CONVERT_SKIP;
    }

    uint32_t send_idx = wr_entry->send_idx;
    uint32_t target_idx = wr_entry->target_idx;

    if (bdp_comp->valid[idx] == false || idx != send_idx) {
        put_comp(bdp_comp);
        return CONVERT_SKIP;
    }

    if (is_failover_cr(cr) && !bdp_comp->modify_to_error) {
        (void)pthread_spin_lock(&bdp_comp->send_lock);
        bdp_comp->valid[send_idx] = false;

        int new_send_idx = -1, new_target_idx = -1;
        if (schedule_send(&wr_entry->target_vjetty->v_tjetty, bdp_comp,
                          &new_send_idx, &new_target_idx, NULL) != 0) {
            /*
             * When all ports are invalid and no port is available to resend the wr,
             * this error CQE is returned directly to the upper layer.
             */
            URMA_LOG_ERR("Failed to find valid port for retransmission.\n");
            (void)pthread_spin_unlock(&bdp_comp->send_lock);
            goto CONVERT_CR;
        }

        URMA_LOG_DEBUG("Resend from %d to %d\n", send_idx, new_send_idx);
        urma_ubagg_switch_inc();

        for (int i = 0; i < bdp_comp->send_wr_buf.max_wr_num; i++) {
            const uint64_t resend_wr_id = (wr_entry->wr_id + i - 1) % bdp_comp->send_wr_buf.max_wr_num + 1;
            jfs_wr_entry_t *resend_wr_entry = jfs_wr_buf_get(&bdp_comp->send_wr_buf, resend_wr_id);
            if (resend_wr_entry == NULL ||
                resend_wr_entry->entry_type != WR_BUF_ENTRY_JFS ||
                resend_wr_entry->bdp_comp != bdp_comp ||
                resend_wr_entry->send_idx != send_idx ||
                resend_wr_entry->target_idx != target_idx) {
                continue;
            }
            atomic_fetch_sub(&bdp_comp->sqe_cnt[send_idx], 1);
            if (resend_jfs_wr(bdp_comp, resend_wr_entry, new_send_idx, new_target_idx) != 0) {
                URMA_LOG_ERR("Failed to resend jfs wr, wr_id=%lu\n", resend_wr_id);
            }
        }
        bondp_health_notify_datapath_link_fail(bdp_comp->bondp_ctx, wr_entry->target_vjetty,
                                               (int)send_idx, (int)target_idx);
        /* Update active link after failover is finished. */
        bondp_health_update_active_idx(bdp_comp->bondp_ctx, wr_entry->target_vjetty, new_send_idx);

        bool is_primary_failover = (bdp_comp->active_count > 0 &&
                                    send_idx == (uint32_t)bdp_comp->active_indices[0] &&
                                    new_send_idx != (int)bdp_comp->active_indices[0]);
        if (is_primary_failover) {
            bondp_health_event_info_t event_info = {
                .local_idx = -1,
                .target_idx = -1,
                .user_ctx = 0,
                .cr_status = 0,
                .new_active_idx = -1,
                .bdp_jetty = NULL,
                .bdp_tjetty = wr_entry->target_vjetty,
            };
            bondp_notify_health_event(bdp_comp->bondp_ctx, BONDP_HEALTH_EVENT_FALLBACK_TASK_KICK, &event_info);
        }
        (void)pthread_spin_unlock(&bdp_comp->send_lock);
        put_comp(bdp_comp);
        return CONVERT_SKIP;
    }

CONVERT_CR:
    atomic_fetch_sub(&bdp_comp->sqe_cnt[send_idx], 1);

    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_comp->bondp_ctx, &msn);
    cr->local_id = get_comp_urma_jetty_id(bdp_comp)->id;
    cr->user_ctx = wr_entry->user_ctx;

    convert_jfs_pwr_to_vwr_resend(&wr_entry->wr, &wr_entry->target_vjetty->v_tjetty);
    release_vwr_use_cnt(&wr_entry->wr);
    free_jfs_wr(&wr_entry->wr);
    (void)pthread_spin_lock(&bdp_comp->send_wr_lock);
    jfs_wr_buf_release(wr_entry);
    (void)pthread_spin_unlock(&bdp_comp->send_wr_lock);
    put_comp(bdp_comp);
    return CONVERT_SUCCESS;
}

static cr_convert_ret_t handle_recv_cr_with_store(bondp_context_t *bdp_ctx, int idx, urma_cr_t *cr)
{
    bondp_comp_t *recv_comp = get_comp_by_cr(bdp_ctx, idx, cr);
    if (recv_comp == NULL) {
        URMA_LOG_ERR("Failed to find local jetty, idx=%u, id=%u\n", idx, cr->local_id);
        return CONVERT_SKIP;
    }

    const uint64_t wr_id = cr->user_ctx;
    wr_buf_t *recv_wr_buf = get_recv_wr_buf(recv_comp);
    pthread_spinlock_t *recv_wr_lock = get_recv_wr_lock(recv_comp);
    if (recv_wr_buf == NULL || recv_wr_lock == NULL) {
        URMA_LOG_ERR("Failed to get recv_wr_buf or recv_wr_lock, comp_type:%d\n", recv_comp->comp_type);
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }

    jfr_wr_entry_t *wr_entry = jfr_wr_buf_get(recv_wr_buf, wr_id);
    if (wr_entry == NULL) {
        // wr_entry could not be NULL
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }

    bondp_comp_t *post_comp = wr_entry->bdp_comp;
    uint32_t recv_idx = wr_entry->recv_idx;
    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_ctx, &msn);
    cr->local_id = recv_comp->v_jetty.jetty_id.id;
    cr->user_ctx = wr_entry->user_ctx;

    post_comp->rqe_cnt[recv_idx] -= 1;

    bool msn_enable = bdp_ctx->msn_enable;
    if (!msn_enable) {
        goto CONVERT_SUCCESS_OUT;
    }

    /* Do de-duplicating */
    int ret = 0;
    urma_jetty_id_t target_jetty_id = cr->remote_id;
    bondp_conn_t *v_conn = NULL;
    ret = bondp_conn_table_get_or_create(&recv_comp->v_conn_table, &target_jetty_id, &v_conn);
    if (ret != 0) {
        free_jfr_wr(&wr_entry->wr);
        (void)pthread_spin_lock(recv_wr_lock);
        jfr_wr_buf_release(wr_entry);
        (void)pthread_spin_unlock(recv_wr_lock);
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }
    if (!bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn) || bdp_slide_wnd_has(&v_conn->recv_wnd, msn)) {
        URMA_LOG_DEBUG("Rearm recv WR due to: outside of window=%d or duplicate %d\n",
                       !bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn),
                       bdp_slide_wnd_has(&v_conn->recv_wnd, msn));
        urma_jfr_wr_t *bad_wr = NULL;
        ret = comp_post_recv(post_comp, recv_idx, &wr_entry->wr, &bad_wr);
        put_comp(recv_comp);
        return CONVERT_SKIP;
    }

    (void)bdp_slide_wnd_add(&v_conn->recv_wnd, msn);

CONVERT_SUCCESS_OUT:
    free_jfr_wr(&wr_entry->wr);
    (void)pthread_spin_lock(recv_wr_lock);
    jfr_wr_buf_release(wr_entry);
    (void)pthread_spin_unlock(recv_wr_lock);
    put_comp(recv_comp);
    return CONVERT_SUCCESS;
}

/**
 * @param dev_idx: The index of pjfc used when polling jfc.
 * In fact, what we need is the index of pjetty relative to vjetty, but we cannot obtain it when calling this function.
 * Considering that the binding relationship between pjfc and pjetty keeps their indices consistent,
 * we use the index of pjfc as the index for pjetty.
 */
static cr_convert_ret_t bondp_handle_cr_no_store(bondp_context_t *bdp_ctx, int idx, urma_cr_t *cr)
{
    bondp_comp_t *comp = get_comp_by_cr(bdp_ctx, idx, cr);
    if (comp == NULL) {
        return CONVERT_SKIP;
    }

    // Special handling is applied to the CRs constructed by the hardware of SUSPEND_DONE and FLUSH_ERROR_DONE.
    if (is_fake_cr(cr)) {
        cr->local_id = comp->v_jetty.jetty_id.id;
        put_comp(comp);
        return CONVERT_SUCCESS;
    }

    if (is_recv_cr(cr)) {
        comp->rqe_cnt[idx] -= 1;
    } else {
        atomic_fetch_sub(&comp->sqe_cnt[idx], 1);
    }

    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_ctx, &msn);
    cr->local_id = comp->v_jetty.jetty_id.id;

    /* Caller should copy this CR to output array. */
    put_comp(comp);
    return CONVERT_SUCCESS;
}

static cr_convert_ret_t bondp_handle_cr_with_store(bondp_context_t *bdp_ctx, int idx, urma_cr_t *cr)
{
    if (is_ctrl_cr(cr)) {
        (void)bondp_try_handle_health_check_cr(bdp_ctx, idx, cr);
        return CONVERT_SKIP;
    } else if (is_fake_cr(cr)) {
        return handle_fake_cr_with_store(bdp_ctx, idx, cr);
    } else if (is_recv_cr(cr)) {
        return handle_recv_cr_with_store(bdp_ctx, idx, cr);
    } else {
        return handle_send_cr_with_store(bdp_ctx, idx, cr);
    }
}

int bondp_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
    static thread_local urma_cr_t pcr_buf[URMA_UBAGG_MAX_CR_CNT_PER_DEV];

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jfc->urma_ctx, bondp_context_t, v_ctx);
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);

    int cr_cnt_remaining = cr_cnt;

    PERF_PROFILING_START(BOND_POLL_JFC);

    /* Start polling from the next device index to avoid starvation. */
    int start_idx = bdp_jfc->lasted_polled_jfc_idx + 1;

    for (int i = 0; i < bdp_jfc->dev_num && cr_cnt_remaining > 0; i++) {
        int idx = ((start_idx + i) % bdp_jfc->dev_num);

        if (bdp_jfc->p_jfc[idx] == NULL) {
            continue;
        }

        int pcr_cnt_max = cr_cnt_remaining > URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              ? URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              : cr_cnt_remaining;
        int pcr_cnt = urma_poll_jfc(bdp_jfc->p_jfc[idx], pcr_cnt_max, pcr_buf);

        if (pcr_cnt < 0) {
            PERF_PROFILING_END(BOND_POLL_JFC);
            return pcr_cnt;
        }
        if (pcr_cnt == 0) {
            continue;
        }

        for (int cr_id = 0; cr_id < pcr_cnt; cr_id++) {
            urma_cr_t *pcr = &pcr_buf[cr_id];
            cr_convert_ret_t conv_ret;

            if (is_single_dev_mode(bdp_ctx)) {
                conv_ret = bondp_handle_cr_no_store(bdp_ctx, idx, pcr);
            } else {
                conv_ret = bondp_handle_cr_with_store(bdp_ctx, idx, pcr);
            }
            if (conv_ret == CONVERT_FAIL) {
                return -1;
            }
            if (conv_ret == CONVERT_SUCCESS) {
                cr[cr_cnt - cr_cnt_remaining] = *pcr;
                cr_cnt_remaining--;
            }
        }

        bdp_jfc->lasted_polled_jfc_idx = idx;
    }

    PERF_PROFILING_END(BOND_POLL_JFC);
    return cr_cnt - cr_cnt_remaining;
}

int bondp_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr)
{
    static thread_local urma_cr_t pcr_buf[URMA_UBAGG_MAX_CR_CNT_PER_DEV];

    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jetty->urma_ctx, bondp_context_t, v_ctx);
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);

    int cr_cnt_remaining = cr_cnt;

    for (int i = 0; i < URMA_UBAGG_DEV_MAX_NUM && cr_cnt_remaining > 0; i++) {
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }

        int pcr_cnt_max = cr_cnt_remaining > URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              ? URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              : cr_cnt_remaining;
        int pcr_cnt = urma_flush_jetty(bdp_jetty->p_jetty[i], pcr_cnt_max, pcr_buf);
        if (pcr_cnt < 0) {
            URMA_LOG_ERR("Failed to flush pjetty[%d], pcr_cnt=%d\n", i, pcr_cnt);
            return pcr_cnt;
        }
        if (pcr_cnt == 0) {
            continue;
        }

        for (int cr_id = 0; cr_id < pcr_cnt; cr_id++) {
            urma_cr_t *pcr = &pcr_buf[cr_id];
            cr_convert_ret_t conv_ret;

            if (is_single_dev_mode(bdp_ctx)) {
                conv_ret = bondp_handle_cr_no_store(bdp_ctx, i, pcr);
            } else {
                conv_ret = bondp_handle_cr_with_store(bdp_ctx, i, pcr);
            }
            if (conv_ret == CONVERT_FAIL) {
                return -1;
            }
            if (conv_ret == CONVERT_SUCCESS) {
                cr[cr_cnt - cr_cnt_remaining] = *pcr;
                cr_cnt_remaining--;
            }
        }
    }

    return cr_cnt - cr_cnt_remaining;
}
