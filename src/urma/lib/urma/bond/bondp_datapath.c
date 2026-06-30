/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond datapth ops implementation file
 * Author: Ma Chuan
 * Create: 2025-02-19
 * Note:
 * History: 2025-02-19   Create File
 */

#include <errno.h>
#include <threads.h>

#include "bondp_connection.h"
#include "bondp_context_table.h"
#include "bondp_datapath_convert.h"
#include "bondp_datapath_schedule.h"
#include "bondp_failback.h"
#include "bondp_health_check.h"
#include "bondp_types.h"
#include "ub_get_clock.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"
#include "urma_provider.h"

#include "bondp_datapath.h"

#define BONDP_POST_SEND_MAX_RETRY     3
/* Max consecutive fast returns before forcing a full scan */
#define BONDP_FAST_RETURN_THRESHOLD   64

static int resend_jfs_wr(bondp_comp_t *bdp_comp, jfs_wr_entry_t *wr_entry, int send_idx, int target_idx);

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

static bondp_comp_t *get_recv_count_comp(bondp_comp_t *recv_comp)
{
    if (recv_comp == NULL) {
        return NULL;
    }
    if (recv_comp->comp_type == BONDP_COMP_JETTY && recv_comp->v_jetty.jetty_cfg.shared.jfr != NULL) {
        return CONTAINER_OF_FIELD(recv_comp->v_jetty.jetty_cfg.shared.jfr, bondp_comp_t, v_jfr);
    }
    return recv_comp;
}

static urma_status_t comp_post_send(bondp_comp_t *comp, int send_idx, int target_idx,
                                    urma_jfs_wr_t *send_wr, urma_jfs_wr_t **bad_wr, int wr_count)
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
        atomic_fetch_add(&comp->sqe_cnt[send_idx][target_idx], wr_count);
    }
    return ret;
}

static urma_status_t comp_post_recv(bondp_comp_t *comp, int recv_idx, urma_jfr_wr_t *recv_wr, urma_jfr_wr_t **bad_wr,
                                    int wr_count)
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
    uint32_t *rqe_cnt = get_recv_count_comp(comp)->rqe_cnt;
    if (ret == URMA_SUCCESS) {
        rqe_cnt[recv_idx] += wr_count;
    }
    return ret;
}

static urma_status_t post_send_check_jfs_wr_valid(const urma_jfs_wr_t *wr,
                                                  uint32_t max_jfs_sge, uint32_t max_jfs_rsge)
{
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            /* No need to handle cases where num_sge == 0 or sge == NULL;
               UDMA will take care of it, as SEND_WITH_IMM may allow NULL to be passed.
            */
            if (max_jfs_sge < wr->send.src.num_sge) {
                URMA_LOG_WARN("The number of sge %u the destination segment is greater than the maximum supported=%u"
                              "by the device.\n",
                              wr->send.src.num_sge,
                              max_jfs_sge);
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
                if (max_jfs_rsge < wr->rw.src.num_sge) {
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.src.num_sge,
                                  max_jfs_rsge);
                }
                if (max_jfs_sge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.dst.num_sge,
                                  max_jfs_sge);
                }
            } else {
                if (max_jfs_sge < wr->rw.src.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.src.num_sge,
                                  max_jfs_sge);
                }
                if (max_jfs_rsge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported=%u"
                                  " by the device.\n",
                                  wr->rw.dst.num_sge,
                                  max_jfs_rsge);
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

static urma_status_t post_send_check_valid(bondp_comp_t *bdp_send_comp,
                                           const urma_jfs_wr_t *wr, uint32_t max_jfs_sge,
                                           uint32_t max_jfs_rsge)
{
    urma_status_t ret = post_send_check_jfs_wr_valid(wr, max_jfs_sge, max_jfs_rsge);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    if (wr->flag.bs.has_drv_ext) {
        bondp_jfs_wr_t *bwr = CONTAINER_OF_FIELD(wr, bondp_jfs_wr_t, base);
        if (bwr->src_chip_id < BONDP_CHIP_ID_MIN || bwr->src_chip_id > BONDP_CHIP_ID_MAX
            || bwr->dst_chip_id < BONDP_CHIP_ID_MIN || bwr->dst_chip_id > BONDP_CHIP_ID_MAX) {
            URMA_LOG_ERR("Invalid src_chip_id=%u or dst_chip_id=%u.\n", bwr->src_chip_id, bwr->dst_chip_id);
            return URMA_EINVAL;
        }
    }
    return URMA_SUCCESS;
}

static urma_status_t post_send_check_wr_list_valid(bondp_comp_t *bdp_send_comp, const urma_jfs_wr_t *wr,
                                                   urma_jfs_wr_t **bad_wr, int *wr_total)
{
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *cur = (urma_jfs_wr_t *)wr;
    int count = 0;

    if (bdp_send_comp->comp_type != BONDP_COMP_JFS && bdp_send_comp->comp_type != BONDP_COMP_JETTY) {
        URMA_LOG_ERR("Try to call post_send api by invalid comp_type=%d\n", bdp_send_comp->comp_type);
        return URMA_EINVAL;
    }

    const urma_device_cap_t *dev_cap = &bdp_send_comp->bondp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap;
    uint32_t max_jfs_sge = dev_cap->max_jfs_sge;
    uint32_t max_jfs_rsge = dev_cap->max_jfs_rsge;

    while (cur != NULL) {
        ret = post_send_check_valid(bdp_send_comp, cur, max_jfs_sge, max_jfs_rsge);
        if (ret != URMA_SUCCESS) {
            *bad_wr = cur;
            return ret;
        }
        cur = cur->next;
        count++;
    }

    *wr_total = count;
    return URMA_SUCCESS;
}

static urma_status_t schedule_send_wr(const urma_jfs_wr_t *wr, bondp_comp_t *bdp_comp,
                                      int *send_idx, int *target_idx)
{
    if (!wr->flag.bs.has_drv_ext) {
        return schedule_send(wr->tjetty, bdp_comp, send_idx, target_idx, NULL);
    }
    bondp_jfs_wr_t *bwr = CONTAINER_OF_FIELD(wr, bondp_jfs_wr_t, base);
    bondp_chip_id_info_t info = {.src_chip_id = bwr->src_chip_id, .dst_chip_id = bwr->dst_chip_id};
    return schedule_send(wr->tjetty, bdp_comp, send_idx, target_idx, &info);
}

static void try_failback(bondp_comp_t *bdp_comp)
{
    if (!g_bondp_global_ctx->enable_failback) {
        return;
    }

    pthread_spin_lock(&bdp_comp->send_lock);

    uint32_t rebuilt_cnt = 0;
    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        if (!atomic_exchange(&bdp_comp->rebuild_done[i], false)) {
            continue;
        }
        rebuilt_cnt++;
        atomic_store(&bdp_comp->valid[i], true);
    }

    if (rebuilt_cnt == 0) {
        pthread_spin_unlock(&bdp_comp->send_lock);
        return;
    }

    URMA_LOG_INFO("Failback triggered on post, vjetty_id=%u rebuilt_cnt=%u\n",
                  bdp_comp->v_jetty.jetty_id.id, rebuilt_cnt);

    for (uint32_t i = 0; i < bdp_comp->send_wr_buf.max_wr_num; ++i) {
        const uint64_t resend_wr_id = (uint64_t)i + 1;
        jfs_wr_entry_t *resend_wr_entry = jfs_wr_buf_get(&bdp_comp->send_wr_buf, resend_wr_id);
        if (resend_wr_entry == NULL ||
            resend_wr_entry->entry_type != WR_BUF_ENTRY_JFS ||
            resend_wr_entry->bdp_comp != bdp_comp) {
            continue;
        }

        uint32_t old_send_idx = resend_wr_entry->send_idx;
        uint32_t old_target_idx = resend_wr_entry->target_idx;
        int new_send_idx = -1;
        int new_target_idx = -1;
        if (schedule_send(&resend_wr_entry->target_vjetty->v_tjetty, bdp_comp,
                          &new_send_idx, &new_target_idx, NULL) != 0) {
            URMA_LOG_DEBUG("Skip failback resend on post, no valid route for wr_id=%lu vjetty_id=%u\n",
                           resend_wr_id, resend_wr_entry->target_vjetty->v_tjetty.id.id);
            continue;
        }

        if (old_send_idx == (uint32_t)new_send_idx && old_target_idx == (uint32_t)new_target_idx) {
            continue;
        }

        atomic_fetch_sub(&bdp_comp->sqe_cnt[old_send_idx][old_target_idx], 1);
        if (resend_jfs_wr(bdp_comp, resend_wr_entry, new_send_idx, new_target_idx) != 0) {
            URMA_LOG_ERR("Failed failback resend on post, wr_id=%lu new_send_idx=%d new_target_idx=%d\n",
                         resend_wr_id, new_send_idx, new_target_idx);
            continue;
        }
    }
    pthread_spin_unlock(&bdp_comp->send_lock);
}

static urma_status_t bondp_post_send_wr_no_store(bondp_comp_t *bdp_comp,
                                                 const urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr,
                                                 int wr_total)
{
    static thread_local urma_jfs_wr_t prealloc_wr_list[BONDP_MAX_WR_LIST_NUM];
    static thread_local urma_sge_t prealloc_src_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];
    static thread_local urma_sge_t prealloc_dst_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];

    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("WR->tjetty is NULL\n");
        return URMA_EINVAL;
    }
    uint32_t base_msn = 0;
    if (bdp_tjetty->is_msn_enabled) {
        base_msn = atomic_fetch_add(&bdp_comp->msn, wr_total) % BONDP_MAX_BITMAP_SIZE;
    }
    for (int retry = 0; retry < BONDP_POST_SEND_MAX_RETRY; retry++) {
        urma_status_t ret = URMA_SUCCESS;
        int send_idx = -1;
        int target_idx = -1;
        ret = schedule_send_wr(wr, bdp_comp, &send_idx, &target_idx);
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
            uint32_t wr_msn = (base_msn + index) % BONDP_MAX_BITMAP_SIZE;
            bool msn_enable = bdp_tjetty->is_msn_enabled;
            ret = encode_jfs_wr_msn(pwr, bdp_comp, wr_msn, msn_enable);
            if (ret != 0) {
                return ret;
            }
            map_jfs_vwr_to_path(pwr, send_idx, target_idx);
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
        if (!atomic_load(&bdp_comp->valid[send_idx])) {
            continue;
        }
        ret = comp_post_send(bdp_comp, send_idx, target_idx, prealloc_wr_list, bad_wr, wr_total);
        return ret;
    }
    URMA_LOG_WARN("Post send failed after %d retries due to path invalidation\n", BONDP_POST_SEND_MAX_RETRY);
    return URMA_FAIL;
}

/**
 * This function assumes all WRs in the list share the same tjetty and scheduling result.
 * It processes each WR under a single lock acquisition, allocates entries, copies and
 * converts the WRs, then submits them as a batch to comp_post_send.
 */
static urma_status_t bondp_post_send_wr_list_and_store(bondp_comp_t *bdp_comp,
    urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr, int wr_total)
{
    if (bdp_comp->comp_type != BONDP_COMP_JFS && bdp_comp->comp_type != BONDP_COMP_JETTY) {
        URMA_LOG_ERR("Try to call post_send api by invalid comp_type=%d\n", bdp_comp->comp_type);
        return URMA_EINVAL;
    }
    bondp_target_jetty_t *bdp_tjetty = NULL;
    bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("WR->tjetty is NULL\n");
        return URMA_EINVAL;
    }
    try_failback(bdp_comp);
    if (wr_total > BONDP_BATCH_POST_MAX_NUM) {
        URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_BATCH_POST_MAX_NUM);
        return URMA_EINVAL;
    }
    uint32_t base_msn = 0;
    if (bdp_tjetty->is_msn_enabled) {
        base_msn = atomic_fetch_add(&bdp_comp->msn, wr_total) % BONDP_MAX_BITMAP_SIZE;
    }
    for (int retry = 0; retry < BONDP_POST_SEND_MAX_RETRY; retry++) {
        urma_status_t ret = URMA_SUCCESS;
        int wr_count = 0;
        int send_idx = -1;
        int target_idx = -1;
        jfs_wr_entry_t *wr_entries[BONDP_BATCH_POST_MAX_NUM];
        ret = schedule_send_wr(wr, bdp_comp, &send_idx, &target_idx);
        if (ret != 0) {
            return URMA_FAIL;
        }
        uint32_t allocated = jfs_wr_buf_alloc_batch(&bdp_comp->send_wr_buf, wr_entries, wr_total);
        if (allocated != (uint32_t)wr_total) {
            jfs_wr_buf_release_batch(&bdp_comp->send_wr_buf, wr_entries, allocated);
            if (!atomic_load(&bdp_comp->valid[send_idx])) {
                continue; /* Path invalidated, retry */
            }
            return URMA_EAGAIN;
        }
        /* Copy + encode MSN + map path + link.
         * NOTE: send_idx/target_idx/entry_type are NOT set here —
         * they are set inside send_lock below */
        urma_jfs_wr_t *cur = wr;
        for (int i = 0; i < wr_total; i++) {
            jfs_wr_entry_t *wr_entry = wr_entries[i];
            wr_entry->user_ctx = cur->user_ctx;
            wr_entry->target_vjetty = bdp_tjetty;
            wr_entry->bdp_comp = bdp_comp;

            urma_jfs_wr_t *pwr = &wr_entry->wr;
            ret = copy_jfs_wr(cur, pwr, wr_entry->src_sge, wr_entry->dst_sge);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to copy jfs wr at index %d\n", i);
                goto CLEANUP;
            }
            add_vwr_use_cnt(pwr);
            uint32_t wr_msn = (base_msn + i) % BONDP_MAX_BITMAP_SIZE;
            bool msn_enable = bdp_tjetty->is_msn_enabled;
            ret = encode_jfs_wr_msn(pwr, bdp_comp, wr_msn, msn_enable);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to encode jfs wr msn at index %d\n", i);
                convert_jfs_pwr_to_vwr_resend(pwr, &wr_entry->target_vjetty->v_tjetty);
                release_vwr_use_cnt(pwr);
                goto CLEANUP;
            }

            map_jfs_vwr_to_path(pwr, send_idx, target_idx);
            pwr->user_ctx = wr_entry->wr_id;
            /* Link WRs into a chain */
            if (i > 0) {
                wr_entries[i - 1]->wr.next = pwr;
            }
            pwr->next = NULL;
            wr_count++;
            cur = cur->next;
        }
        int success_node = 0;
        /*
         * Critical section: commit entry_type + send_idx/target_idx, check
         * valid, submit. send_lock ensures mutual exclusion with failover CR
         * handling in handle_send_cr_with_store.
         */
        pthread_spin_lock(&bdp_comp->send_lock);
        for (int i = 0; i < wr_total; i++) {
            wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)wr_entries[i];
            hdr->entry_type = WR_BUF_ENTRY_JFS;
            wr_entries[i]->send_idx = send_idx;
            wr_entries[i]->target_idx = target_idx;
        }
        if (!atomic_load(&bdp_comp->valid[send_idx])) {
            for (int i = 0; i < wr_total; i++) {
                wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)wr_entries[i];
                hdr->entry_type = 0;
                wr_entries[i]->send_idx = 0;
                wr_entries[i]->target_idx = 0;
            }
            pthread_spin_unlock(&bdp_comp->send_lock);
            for (int j = 0; j < wr_count; j++) {
                convert_jfs_pwr_to_vwr_resend(&wr_entries[j]->wr, &wr_entries[j]->target_vjetty->v_tjetty);
                release_vwr_use_cnt(&wr_entries[j]->wr);
            }
            jfs_wr_buf_release_batch(&bdp_comp->send_wr_buf, wr_entries, allocated);
            continue;
        }
        ret = comp_post_send(bdp_comp, send_idx, target_idx, &wr_entries[0]->wr, bad_wr, wr_count);
        if (ret != URMA_SUCCESS) {
            urma_jfs_wr_t *pcur = &wr_entries[0]->wr;
            while (pcur != NULL && bad_wr != NULL && pcur != *bad_wr) {
                success_node++;
                pcur = pcur->next;
            }
            atomic_fetch_add(&bdp_comp->sqe_cnt[send_idx][target_idx], success_node);
            for (int j = success_node; j < wr_total; j++) {
                wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)wr_entries[j];
                hdr->entry_type = 0;
                wr_entries[j]->send_idx = 0;
                wr_entries[j]->target_idx = 0;
            }
        }
        pthread_spin_unlock(&bdp_comp->send_lock);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to post send wr batch, ret: %d.\n", ret);
            goto ROLLBACK;
        }
        return URMA_SUCCESS;
ROLLBACK:
        for (int j = success_node; j < wr_count; j++) {
            convert_jfs_pwr_to_vwr_resend(&wr_entries[j]->wr, &wr_entries[j]->target_vjetty->v_tjetty);
            release_vwr_use_cnt(&wr_entries[j]->wr);
        }
        jfs_wr_buf_release_batch(&bdp_comp->send_wr_buf, &wr_entries[success_node],
            allocated - success_node);
        return ret;
CLEANUP:
        for (int j = 0; j < wr_count; j++) {
            convert_jfs_pwr_to_vwr_resend(&wr_entries[j]->wr, &wr_entries[j]->target_vjetty->v_tjetty);
            release_vwr_use_cnt(&wr_entries[j]->wr);
        }
        jfs_wr_buf_release_batch(&bdp_comp->send_wr_buf, wr_entries, allocated);
        if (ret != URMA_FAIL || atomic_load(&bdp_comp->valid[send_idx])) {
            return ret;
        }
    }
    URMA_LOG_WARN("Post send failed after %d retries due to path invalidation\n", BONDP_POST_SEND_MAX_RETRY);
    return URMA_FAIL;
}

urma_status_t bondp_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_status_t ret = URMA_SUCCESS;
    int wr_total = 0;

    PERF_PROFILING_START(BOND_JETTY_POST_SEND);
    ret = post_send_check_wr_list_valid(bdp_jetty, wr, bad_wr, &wr_total);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_JETTY_POST_SEND);
        return ret;
    }

    if (is_single_dev_mode(bdp_jetty->bondp_ctx)) {
        ret = bondp_post_send_wr_no_store(bdp_jetty, wr, bad_wr, wr_total);
    } else {
        ret = bondp_post_send_wr_list_and_store(bdp_jetty, wr, bad_wr, wr_total);
    }
    PERF_PROFILING_END(BOND_JETTY_POST_SEND);

    return ret;
}

urma_status_t bondp_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);
    urma_status_t ret = URMA_SUCCESS;
    int wr_total = 0;

    PERF_PROFILING_START(BOND_JFS_POST_SEND);
    ret = post_send_check_wr_list_valid(bdp_jfs, wr, bad_wr, &wr_total);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_JFS_POST_SEND);
        return ret;
    }

    if (is_single_dev_mode(bdp_jfs->bondp_ctx)) {
        ret = bondp_post_send_wr_no_store(bdp_jfs, wr, bad_wr, wr_total);
    } else {
        ret = bondp_post_send_wr_list_and_store(bdp_jfs, wr, bad_wr, wr_total);
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

    ret = comp_post_recv(bdp_comp, recv_idx, prealloc_wr_list, bad_wr, 1);
    return ret;
}

static urma_status_t bondp_post_recv_wr_list_without_backup(bondp_comp_t *bdp_comp, urma_jfr_wr_t *wr,
                                                            urma_jfr_wr_t **bad_wr)
{
    static thread_local urma_jfr_wr_t prealloc_wr_list[BONDP_MAX_WR_LIST_NUM];
    static thread_local urma_sge_t prealloc_src_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];

    if (bdp_comp == NULL) {
        URMA_LOG_ERR("Invalid bdp_comp: NULL in recv post without backup.\n");
        return URMA_EINVAL;
    }
    urma_jfr_wr_t *cur = wr;
    urma_status_t ret = URMA_SUCCESS;
    uint32_t recv_wr_cnt[URMA_UBAGG_DEV_MAX_NUM] = {0};
    int wr_count = 0;

    while (cur != NULL && wr_count < BONDP_BATCH_POST_MAX_NUM) {
        wr_count++;
        cur = cur->next;
    }
    if (cur != NULL) {
        URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_BATCH_POST_MAX_NUM);
        return URMA_EINVAL;
    }

    ret = schedule_recv_n(bdp_comp, (uint32_t)wr_count, recv_wr_cnt);
    if (ret != 0) {
        return URMA_FAIL;
    }

    int index = 0;
    cur = wr;
    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        uint32_t recv_idx_u = bdp_comp->active_indices[i];
        if (recv_idx_u >= URMA_UBAGG_DEV_MAX_NUM) {
            URMA_LOG_ERR("Invalid recv_idx=%u when post recv wr.\n", recv_idx_u);
            return URMA_EINVAL;
        }
        int recv_idx = (int)recv_idx_u;
        uint32_t recv_cnt = recv_wr_cnt[recv_idx_u];

        if (recv_cnt == 0) {
            continue;
        }

        urma_jfr_wr_t *post_wr_head = &prealloc_wr_list[index];
        urma_jfr_wr_t *post_wr_tail = NULL;
        for (uint32_t j = 0; j < recv_cnt; j++) {
            if (cur == NULL) {
                URMA_LOG_ERR("Unexpected WR list end, recv_idx=%d, recv_cnt=%u, cur_j=%u\n",
                             recv_idx, recv_cnt, j);
                return URMA_EINVAL;
            }
            urma_jfr_wr_t *pwr = &prealloc_wr_list[index];
            ret = copy_jfr_wr(cur, pwr, prealloc_src_sge[index]);
            if (ret != 0) {
                return ret;
            }
            ret = convert_jfr_vwr_to_pwr(pwr, recv_idx);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to convert recv wr without backup, recv_idx=%d, ret=%d\n", recv_idx, ret);
                return ret;
            }
            if (post_wr_tail != NULL) {
                post_wr_tail->next = pwr;
            }
            post_wr_tail = pwr;
            cur = cur->next;
            index++;
        }

        if (post_wr_tail == NULL) {
            URMA_LOG_ERR("Invalid empty recv wr segment, recv_idx=%d, recv_cnt=%u\n", recv_idx, recv_cnt);
            return URMA_EINVAL;
        }
        post_wr_tail->next = NULL;
        ret = comp_post_recv(bdp_comp, recv_idx, post_wr_head, bad_wr, (int)recv_cnt);
        if (ret != URMA_SUCCESS) {
            URMA_LOG_ERR("Failed to post recv wr without backup, recv_idx=%d, recv_cnt=%u, ret:%d\n",
                         recv_idx, recv_cnt, ret);
            int posted_node = 0;
            urma_jfr_wr_t *posted_wr = post_wr_head;
            while (posted_wr != NULL && bad_wr != NULL && posted_wr != *bad_wr) {
                posted_node++;
                posted_wr = posted_wr->next;
            }
            bdp_comp->rqe_cnt[recv_idx_u] += (uint32_t)posted_node;
            return ret;
        }
    }
    return URMA_SUCCESS;
}

/**
* Batch post recv WRs: allocate all entries in one lock, copy+convert,
* link into a single WR chain, then submit with one comp_post_recv.
*/
static urma_status_t bondp_post_recv_wr_list_and_store(bondp_comp_t *bdp_comp, urma_jfr_wr_t *wr,
                                                       urma_jfr_wr_t **bad_wr)
{
    urma_jfr_wr_t *cur = wr;
    urma_status_t ret = URMA_SUCCESS;
    jfr_wr_entry_t *wr_entries[BONDP_BATCH_POST_MAX_NUM];
    uint32_t recv_wr_cnt[URMA_UBAGG_DEV_MAX_NUM] = {0};
    int wr_count = 0;
    int process_node = 0;
    int success_node = 0;

    wr_buf_t *recv_wr_buf = get_recv_wr_buf(bdp_comp);
    if (recv_wr_buf == NULL) {
        URMA_LOG_ERR("Failed to get recv_wr_buf, comp_type:%d\n", bdp_comp->comp_type);
        return URMA_EINVAL;
    }
    while (cur != NULL && wr_count < BONDP_BATCH_POST_MAX_NUM) {
        wr_count++;
        cur = cur->next;
    }
    if (cur != NULL) {
        URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_BATCH_POST_MAX_NUM);
        return URMA_EINVAL;
    }
    uint32_t allocated = jfr_wr_buf_alloc_batch(recv_wr_buf, wr_entries, (uint32_t)wr_count);
    if (allocated != (uint32_t)wr_count) {
        URMA_LOG_ERR("Bondp WR buffer is not enough, reqeusted %u, available %u.\n",
            wr_count, allocated);
        jfr_wr_buf_release_batch(recv_wr_buf, wr_entries, allocated);
        return URMA_ENOMEM;
    }
    ret = schedule_recv_n(bdp_comp, (uint32_t)wr_count, recv_wr_cnt);
    if (ret != 0) {
        URMA_LOG_ERR("Bondp schedule recv failed, ret = %d.\n", ret);
        ret = URMA_FAIL;
        goto CLEANUP;
    }
    cur = wr;
    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        int recv_idx = (int)bdp_comp->active_indices[i];
        uint32_t recv_cnt = recv_wr_cnt[recv_idx];
        for (uint32_t j = 0; j < recv_cnt; j++, cur = cur->next) {
            jfr_wr_entry_t *wr_entry = wr_entries[process_node];
            urma_jfr_wr_t *pwr = &wr_entry->wr;
            wr_entry->recv_idx = (uint32_t)recv_idx;
            wr_entry->user_ctx = cur->user_ctx;
            wr_entry->bdp_comp = bdp_comp;
            ret = copy_jfr_wr(cur, pwr, wr_entry->src_sge);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to copy jfr wr at index %u\n", process_node);
                goto CLEANUP;
            }
            ret = convert_jfr_vwr_to_pwr(pwr, recv_idx);
            if (ret != 0) {
                URMA_LOG_ERR("Failed to convert jfr wr at index %u\n", process_node);
                goto CLEANUP;
            }
            pwr->user_ctx = wr_entry->wr_id;
            if (j > 0) {
                wr_entries[process_node - 1]->wr.next = pwr;
            }
            pwr->next = NULL;
            process_node++;
        }
    }
    for (uint32_t i = 0; i < bdp_comp->active_count; i++) {
        int recv_idx = (int)bdp_comp->active_indices[i];
        uint32_t recv_cnt = recv_wr_cnt[recv_idx];
        if (recv_cnt == 0) {
            continue;
        }
        for (int k = success_node; k < success_node + (int)recv_cnt; k++) {
            wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)wr_entries[k];
            hdr->entry_type = WR_BUF_ENTRY_JFR;
        }
        ret = comp_post_recv(bdp_comp, recv_idx, &wr_entries[success_node]->wr, bad_wr, (int)recv_cnt);
        if (ret == URMA_SUCCESS) {
            success_node += (int)recv_cnt;
            continue;
        }
        URMA_LOG_ERR("Failed to post recv wr, ret:%d\n", ret);
        int posted_node = 0;
        urma_jfr_wr_t *posted_wr = &wr_entries[success_node]->wr;
        while (posted_wr != NULL && bad_wr != NULL && posted_wr != *bad_wr) {
            posted_node++;
            posted_wr = posted_wr->next;
        }
        bdp_comp->rqe_cnt[recv_idx] += (uint32_t)posted_node;
        for (int k = success_node + posted_node; k < success_node + (int)recv_cnt; k++) {
            wr_buf_entry_hdr_t *hdr = (wr_buf_entry_hdr_t *)wr_entries[k];
            hdr->entry_type = 0;
        }
        success_node += posted_node;
        goto CLEANUP;
    }
    return URMA_SUCCESS;
CLEANUP:
    jfr_wr_buf_release_batch(recv_wr_buf, &wr_entries[success_node], allocated - success_node);
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
        ret = (bdp_jetty->bondp_ctx->msn_enable) ? bondp_post_recv_wr_list_and_store(bdp_jetty, wr, bad_wr)
                                               : bondp_post_recv_wr_list_without_backup(bdp_jetty, wr, bad_wr);
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
        ret = (bdp_jfr->bondp_ctx->msn_enable) ? bondp_post_recv_wr_list_and_store(bdp_jfr, wr, bad_wr)
                                             : bondp_post_recv_wr_list_without_backup(bdp_jfr, wr, bad_wr);
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
    wr->next = NULL;
    int ret = comp_post_send(wr_entry->bdp_comp, send_idx, target_idx, wr, &bad_wr, 1);
    if (ret != URMA_SUCCESS) {
        convert_jfs_pwr_to_vwr_resend(wr, vtjetty);
        release_vwr_use_cnt(wr);
        jfs_wr_buf_release(&bdp_comp->send_wr_buf, wr_entry);
    }

    return ret;
}

/*
 * Thread-local 16-slot cache for get_comp_by_cr.
 */
#define TL_COMP_CACHE_SLOTS 16

static bondp_comp_t *get_comp_by_cr(bondp_context_t *bdp_ctx, int dev_idx, urma_cr_t *cr)
{
    static thread_local bondp_context_t *tl_ctx;
    static thread_local uint32_t tl_gen;
    static thread_local int tl_fill_pos;
    static thread_local int tl_evict_pos;
    static thread_local struct {
        int           dev_idx;
        uint32_t      local_id;
        uint8_t       type;
        bondp_comp_t *comp;
    } tl_slots[TL_COMP_CACHE_SLOTS];

    bdp_p_vjetty_type_t p_vjetty_type;
    if (cr->flag.bs.jetty != 0) {
        p_vjetty_type = JETTY;
    } else if (cr->flag.bs.s_r == 0) {
        p_vjetty_type = JFS;
    } else {
        p_vjetty_type = JFR;
    }
    /* Invalidate whole cache only if ctx or gen changed */
    bool cache_valid = true;
    uint32_t cur_gen = atomic_load(&bdp_ctx->p_vjetty_id_table.gen);
    if (tl_ctx != bdp_ctx || tl_gen != cur_gen) {
        for (int i = 0; i < TL_COMP_CACHE_SLOTS; i++) {
            tl_slots[i].comp = NULL;
        }
        tl_ctx       = bdp_ctx;
        tl_gen       = cur_gen;
        tl_fill_pos  = 0;
        tl_evict_pos = 0;
        cache_valid  = false;
    }

    /* Fast path */
    if (cache_valid) {
        for (int i = 0; i < TL_COMP_CACHE_SLOTS; i++) {
            if (tl_slots[i].comp == NULL) {
                break;
            }
            if (tl_slots[i].dev_idx == dev_idx &&
                tl_slots[i].local_id == cr->local_id &&
                tl_slots[i].type == (uint8_t)p_vjetty_type) {
                bondp_comp_t *comp = tl_slots[i].comp;
                atomic_fetch_add(&comp->use_cnt.atomic_cnt, 1);
                if (atomic_load(&bdp_ctx->p_vjetty_id_table.gen) != tl_gen) {
                    atomic_fetch_sub(&comp->use_cnt.atomic_cnt, 1);
                    for (int j = 0; j < TL_COMP_CACHE_SLOTS; j++) {
                        tl_slots[j].comp = NULL;
                    }
                    tl_fill_pos  = 0;
                    tl_evict_pos = 0;
                    break;
                }
                return comp;
            }
        }
    }
    /* Slow path: cache miss → rwlock + hash-table lookup. */
    urma_jetty_id_t pjetty_id = {
        .eid = bdp_ctx->p_ctxs[dev_idx]->eid,
        .id = cr->local_id,
    };
    pthread_rwlock_rdlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_comp_t *comp = bdp_p_vjetty_id_table_lookup_comp_without_lock(
        &bdp_ctx->p_vjetty_id_table, pjetty_id, p_vjetty_type);
    if (comp == NULL) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to get comp, local_id=%d\n", pjetty_id.id);
        return NULL;
    }
    atomic_fetch_add(&comp->use_cnt.atomic_cnt, 1);
    cur_gen = atomic_load(&bdp_ctx->p_vjetty_id_table.gen);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);

    tl_gen = cur_gen;
    int slot;
    if (tl_fill_pos < TL_COMP_CACHE_SLOTS) {
        slot = tl_fill_pos++;
    } else {
        slot = tl_evict_pos;
        tl_evict_pos = (tl_evict_pos + 1) & (TL_COMP_CACHE_SLOTS - 1);
    }
    tl_slots[slot].dev_idx  = dev_idx;
    tl_slots[slot].local_id = cr->local_id;
    tl_slots[slot].type     = (uint8_t)p_vjetty_type;
    tl_slots[slot].comp     = comp;

    return comp;
}

static inline void put_comp(bondp_comp_t *bdp_comp)
{
    if (bdp_comp == NULL) {
        return;
    }
    atomic_fetch_sub(&bdp_comp->use_cnt.atomic_cnt, 1);
}

static cr_convert_ret_t handle_recv_cr_without_backup(bondp_context_t *bdp_ctx, int idx, urma_cr_t *cr)
{
    bondp_comp_t *recv_comp = get_comp_by_cr(bdp_ctx, idx, cr);
    if (recv_comp == NULL) {
        URMA_LOG_ERR("Failed to find local jetty, idx=%u, id=%u\n", idx, cr->local_id);
        return CONVERT_SKIP;
    }
    bondp_comp_t *count_comp = get_recv_count_comp(recv_comp);
    if (count_comp == NULL) {
        URMA_LOG_ERR("Failed to get count comp in recv cr without backup, idx=%d, local_id=%u\n", idx, cr->local_id);
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }
    if (idx < 0 || idx >= URMA_UBAGG_DEV_MAX_NUM) {
        URMA_LOG_ERR("Invalid idx=%d in recv cr without backup.\n", idx);
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }
    if (count_comp->rqe_cnt[idx] == 0) {
        URMA_LOG_WARN("recv cr without backup rqe_cnt underflow risk, idx=%d, local_id=%u\n", idx, cr->local_id);
    } else {
        count_comp->rqe_cnt[idx] -= 1;
    }
    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_ctx, &msn);
    urma_jetty_id_t *comp_id = get_comp_urma_jetty_id(recv_comp);
    if (comp_id == NULL) {
        URMA_LOG_ERR("Failed to get comp local_id in recv cr without backup.\n");
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }
    cr->local_id = comp_id->id;
    put_comp(recv_comp);
    return CONVERT_SUCCESS;
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

    if (atomic_load(&bdp_comp->valid[idx]) == false || idx != send_idx) {
        put_comp(bdp_comp);
        return CONVERT_SKIP;
    }

    if (is_failover_cr(cr) && !bdp_comp->modify_to_error) {
        (void)pthread_spin_lock(&bdp_comp->send_lock);
        atomic_store(&bdp_comp->valid[send_idx], false);
        /* choose the failover route(0 or 1) through send_idx */
        int new_send_idx = send_idx;
        int new_target_idx = -1;
        if (!g_bondp_global_ctx->enable_failover ||
            schedule_send(&wr_entry->target_vjetty->v_tjetty, bdp_comp,
                          &new_send_idx, &new_target_idx, NULL) != 0) {
            /*
             * When all ports are invalid and no port is available to resend the wr,
             * this error CQE is returned directly to the upper layer.
             */
            URMA_LOG_ERR("Failed to find valid port for retransmission.\n");
            (void)pthread_spin_unlock(&bdp_comp->send_lock);
            goto CONVERT_CR;
        }

        URMA_LOG_INFO("Resend from [%u, %u] to [%d, %d]\n", send_idx, target_idx,
                      new_send_idx, new_target_idx);
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
            atomic_fetch_sub(&bdp_comp->sqe_cnt[send_idx][target_idx], 1);
            if (resend_jfs_wr(bdp_comp, resend_wr_entry, new_send_idx, new_target_idx) != 0) {
                URMA_LOG_ERR("Failed to resend jfs wr, wr_id=%lu\n", resend_wr_id);
            }
        }
        bondp_health_notify_datapath_link_fail(bdp_comp->bondp_ctx, wr_entry->target_vjetty,
                                               (int)send_idx, (int)target_idx);
        /* Update active link after failover is finished. */
        bondp_health_update_active_idx(bdp_comp->bondp_ctx, wr_entry->target_vjetty, new_send_idx);

        int ret = bondp_fb_add_task(bdp_comp->bondp_ctx, bdp_comp->v_jetty.jetty_id.id, send_idx);
        if (ret != 0 && ret != -EEXIST) {
            URMA_LOG_WARN("Failed to add failback task, vjetty_id=%u pjetty_idx=%u ret=%d\n",
                          wr_entry->target_vjetty->v_tjetty.id.id, send_idx, ret);
        }
        (void)pthread_spin_unlock(&bdp_comp->send_lock);
        put_comp(bdp_comp);
        return CONVERT_SKIP;
    }

CONVERT_CR:
    atomic_fetch_sub(&bdp_comp->sqe_cnt[send_idx][target_idx], 1);

    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_comp->bondp_ctx, &msn);
    cr->local_id = get_comp_urma_jetty_id(bdp_comp)->id;
    cr->user_ctx = wr_entry->user_ctx;

    convert_jfs_pwr_to_vwr_resend(&wr_entry->wr, &wr_entry->target_vjetty->v_tjetty);
    release_vwr_use_cnt(&wr_entry->wr);
    jfs_wr_buf_release(&bdp_comp->send_wr_buf, wr_entry);
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
    if (recv_wr_buf == NULL) {
        URMA_LOG_ERR("Failed to get recv_wr_buf, comp_type:%d\n", recv_comp->comp_type);
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
    bondp_comp_t *jfr = get_recv_count_comp(post_comp);
    uint32_t recv_idx = wr_entry->recv_idx;
    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_ctx, &msn);
    cr->local_id = recv_comp->v_jetty.jetty_id.id;
    cr->user_ctx = wr_entry->user_ctx;

    if (jfr->rqe_cnt[recv_idx] == 0) {
        URMA_LOG_WARN("recv cr with store rqe_cnt underflow risk, idx=%u, local_id=%u\n",
                      recv_idx, cr->local_id);
    } else {
        jfr->rqe_cnt[recv_idx] -= 1;
    }

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
        jfr_wr_buf_release(recv_wr_buf, wr_entry);
        put_comp(recv_comp);
        return CONVERT_FAIL;
    }
    if (!bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn) || bdp_slide_wnd_has(&v_conn->recv_wnd, msn)) {
        URMA_LOG_DEBUG("Rearm recv WR due to: outside of window=%d or duplicate %d\n",
                       !bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn),
                       bdp_slide_wnd_has(&v_conn->recv_wnd, msn));
        urma_jfr_wr_t *bad_wr = NULL;
        ret = comp_post_recv(post_comp, recv_idx, &wr_entry->wr, &bad_wr, 1);
        put_comp(recv_comp);
        return CONVERT_SKIP;
    }

    (void)bdp_slide_wnd_add(&v_conn->recv_wnd, msn);

CONVERT_SUCCESS_OUT:
    jfr_wr_buf_release(recv_wr_buf, wr_entry);
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
        atomic_fetch_sub(&comp->sqe_cnt[idx][0], 1);
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
        return (bdp_ctx->msn_enable) ? handle_recv_cr_with_store(bdp_ctx, idx, cr)
                                   : handle_recv_cr_without_backup(bdp_ctx, idx, cr);
    } else {
        return handle_send_cr_with_store(bdp_ctx, idx, cr);
    }
}

int bondp_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr)
{
    PERF_PROFILING_START(BOND_POLL_JFC);
    static thread_local urma_cr_t pcr_buf[URMA_UBAGG_MAX_CR_CNT_PER_DEV];
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jfc->urma_ctx, bondp_context_t, v_ctx);
    bondp_jfc_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_jfc_t, v_jfc);
    int cr_cnt_remaining = cr_cnt;
    bool single_dev = is_single_dev_mode(bdp_ctx);
    uint32_t enabled_count = bdp_jfc->enabled_count;

    int hot_idx = bdp_jfc->lasted_polled_jfc_idx;
    bool need_full_scan = false;
    bool hot_polled = false;
    /* Hot path is active-backup only */
    if (bdp_ctx->bonding_mode != BONDP_BONDING_MODE_BALANCE &&
        hot_idx >= 0 && bdp_jfc->p_jfc[hot_idx] != NULL) {
        int pcr_cnt_max = cr_cnt_remaining > URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              ? URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              : cr_cnt_remaining;
        int pcr_cnt = urma_poll_jfc(bdp_jfc->p_jfc[hot_idx], pcr_cnt_max, pcr_buf);
        if (pcr_cnt < 0) {
            PERF_PROFILING_END(BOND_POLL_JFC);
            return pcr_cnt;
        }
        if (pcr_cnt > 0) {
            hot_polled = true;
            bdp_jfc->polled_mask |= (1U << (uint32_t)hot_idx);
            for (int cr_id = 0; cr_id < pcr_cnt; cr_id++) {
                urma_cr_t *pcr = &pcr_buf[cr_id];
                if (!need_full_scan && (is_failover_cr(pcr) || is_fake_cr(pcr))) {
                    need_full_scan = true;
                }
                cr_convert_ret_t conv_ret = single_dev
                    ? bondp_handle_cr_no_store(bdp_ctx, hot_idx, pcr)
                    : bondp_handle_cr_with_store(bdp_ctx, hot_idx, pcr);
                if (conv_ret == CONVERT_FAIL) {
                    PERF_PROFILING_END(BOND_POLL_JFC);
                    return -1;
                }
                if (conv_ret == CONVERT_SUCCESS) {
                    cr[cr_cnt - cr_cnt_remaining] = *pcr;
                    cr_cnt_remaining--;
                }
            }
            if (!need_full_scan &&
                cr_cnt_remaining < cr_cnt &&
                bdp_jfc->fast_return_count < BONDP_FAST_RETURN_THRESHOLD) {
                bdp_jfc->fast_return_count++;
                bdp_jfc->lasted_polled_jfc_idx = hot_idx;
                PERF_PROFILING_END(BOND_POLL_JFC);
                return cr_cnt - cr_cnt_remaining;
            }
        }
    }
    /* Full scan: hot_idx returned 0 or balance mode needs all paths. */
    bdp_jfc->fast_return_count = 0;
    uint32_t start_n = 0;
    for (uint32_t n = 0; n < enabled_count; n++) {
        if ((int)bdp_jfc->enabled_indices[n] == hot_idx) {
            start_n = (n + 1) % enabled_count;
            break;
        }
    }
    for (uint32_t i = 0; i < enabled_count && cr_cnt_remaining > 0; i++) {
        uint32_t n = (start_n + i) % enabled_count;
        int idx = (int)bdp_jfc->enabled_indices[n];
        if (hot_polled && idx == hot_idx) {
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
        bdp_jfc->polled_mask |= (1U << (uint32_t)idx);
        for (int cr_id = 0; cr_id < pcr_cnt; cr_id++) {
            urma_cr_t *pcr = &pcr_buf[cr_id];
            cr_convert_ret_t conv_ret;
            if (single_dev) {
                conv_ret = bondp_handle_cr_no_store(bdp_ctx, idx, pcr);
            } else {
                conv_ret = bondp_handle_cr_with_store(bdp_ctx, idx, pcr);
            }
            if (conv_ret == CONVERT_FAIL) {
                PERF_PROFILING_END(BOND_POLL_JFC);
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
        URMA_LOG_DEBUG("flush pjetty[%d], pcr_cnt=%d\n", i, pcr_cnt);
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
