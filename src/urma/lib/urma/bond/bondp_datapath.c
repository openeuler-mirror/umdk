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
#include "bondp_jetty_ctx.h"
#include "bondp_types.h"
#include "urma_api.h"
#include "urma_log.h"
#include "urma_private.h"

#include "bondp_datapath.h"
#include "ub_get_clock.h"
#include "urma_perf.h"

#define PJETTY_ID_ENCODE_OFFSET (32)
#define VJETTY_ID_ENCODE_OFFSET (48)
#define WRITE_IMM_USER_BITS     (32)
#define IMM_OPCODE_SHIFT        (56)
#define IMM_OPCODE_MASK         (0x3)
#define WRITE_IMM_IS_SO_SHIFT   (63)
#define CALLBACK_SUCCESS        (0)
#define CALLBACK_SKIP           (1)
#define CALLBACK_FAIL           (-1)
#define RECV_WR_ID_MAX          (1U << 31)

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
            URMA_LOG_ERR("Failed to get_comp_urma_jetty, Invalid type: %d\n", bdp_comp->comp_type);
            return NULL;
    }
}

static urma_status_t comp_post_send(bondp_comp_t *comp, int send_idx, urma_jfs_wr_t *send_wr, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret;
    if (comp->comp_type == BONDP_COMP_JETTY) {
        ret = urma_post_jetty_send_wr(comp->p_jetty[send_idx], send_wr, bad_wr);
    } else if (comp->comp_type == BONDP_COMP_JFS) {
        ret = urma_post_jfs_wr(comp->p_jfs[send_idx], send_wr, bad_wr);
    } else {
        URMA_LOG_ERR("Invalid post jfs wr type: %d\n", comp->comp_type);
        ret = URMA_EINVAL;
    }
    if (ret == URMA_SUCCESS) {
        comp->rqe_cnt[send_idx] += 1;
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
        URMA_LOG_ERR("Invalid post jfr wr type: %d\n", comp->comp_type);
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
                URMA_LOG_WARN("The number of sge %u the destination segment is greater than the maximum supported: %u"
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
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported: %u"
                                  " by the device.\n",
                                  wr->rw.src.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge);
                }
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported: %u"
                                  " by the device.\n",
                                  wr->rw.dst.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
                }
            } else {
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->rw.src.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported: %u"
                                  " by the device.\n",
                                  wr->rw.src.num_sge,
                                  bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
                }
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported: %u"
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
        URMA_LOG_ERR("Try to call post_send api by invalid comp_type: %d\n", bdp_send_comp->comp_type);
        return URMA_EINVAL;
    }
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid bdp_target_jetty");
        return URMA_EINVAL;
    }
    if (is_multipath_comp(bdp_send_comp) != bdp_tjetty->is_multipath) {
        URMA_LOG_ERR("Data cannot be transferred between jettys in different multipath mode\n");
        return URMA_EINVAL;
    }
    urma_status_t ret = post_send_check_jfs_wr_valid(bdp_send_comp->bondp_ctx, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    return URMA_SUCCESS;
}

static urma_status_t post_send_check_wr_list_valid(bondp_comp_t *bdp_send_comp, const urma_jfs_wr_t *wr,
    urma_jfs_wr_t **bad_wr)
{
    bondp_target_jetty_t *bdp_tjetty = NULL;
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *cur = wr;

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

/**
 * When sending data, attempt to retrieve the v_conn corresponding to the target tjetty from bjetty_ctx;
 * if it does not exist, try to create one, then init it with `init_v_conn_on_send` if needed.
 * @return: NULL if lookup failed and creation failed
 */
static bdp_v_conn_t *get_v_conn_on_send(bjetty_ctx_t *bjetty_ctx, bondp_target_jetty_t *bdp_tjetty)
{
    urma_jetty_id_t *comp_jetty_id = get_comp_urma_jetty_id(bjetty_ctx->bdp_comp);
    if (comp_jetty_id == NULL) {
        return NULL;
    }
    urma_jetty_id_t *vtjetty_id = &bdp_tjetty->v_tjetty.id;
    bdp_v_conn_t *v_conn = bdp_v_conn_table_lookup(&bjetty_ctx->v_conn_table, vtjetty_id);
    if (!v_conn) {
        int ret = bdp_v_conn_table_add_on_send(&bjetty_ctx->v_conn_table, vtjetty_id,
                                               bdp_tjetty, bdp_tjetty->target_dev_num, &v_conn, bjetty_ctx->bond_ctx->v_ctx.aggr_mode);
        if (ret != 0) {
            URMA_LOG_ERR("Failed to create v_conn for vjetty, ret: %d, "
                         "[" URMA_JETTY_ID_FMT " -> " URMA_JETTY_ID_FMT "]\n",
                         ret, URMA_JETTY_ID_ARGS(comp_jetty_id), URMA_JETTY_ID_ARGS(vtjetty_id));
            return NULL;
        }
    }
    /* v_conn is not null */
    /* If this v_conn is created by handle_recv, then we need to initialize it */
    if (v_conn->target_vjetty == NULL) {
        init_v_conn_on_send(v_conn, bdp_tjetty, bdp_tjetty->target_dev_num);
    }
    return v_conn;
}

static urma_status_t bondp_post_send_wr_no_store(bjetty_ctx_t *bjetty_ctx,
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

    bdp_v_conn_t *v_conn = get_v_conn_on_send(bjetty_ctx, bdp_tjetty);
    if (v_conn == NULL) {
        return URMA_FAIL;
    }

    int send_idx = -1, target_idx = -1;
    ret = schedule_send(wr, bjetty_ctx->bdp_comp, &send_idx, &target_idx);
    if (ret != 0) {
        return URMA_FAIL;
    }

    int index = 0;
    urma_jfs_wr_t *vwr = (urma_jfs_wr_t *)wr;
    while (vwr != NULL) {
        urma_jfs_wr_t *pwr = &prealloc_wr_list[index];
        ret = copy_jfs_wr(vwr, pwr, prealloc_src_sge[index], prealloc_dst_sge[index]);
        if (ret != 0) {
            return URMA_FAIL;
        }
        ret = convert_jfs_vwr_to_pwr(pwr, send_idx, target_idx, bjetty_ctx, v_conn);
        if (ret != 0) {
            return URMA_FAIL;
        }
        if (pwr->next != NULL) {
            pwr->next = &prealloc_wr_list[index + 1];
        }

        vwr = vwr->next;
        index++;
        if (index >= BONDP_MAX_WR_LIST_NUM - 1) {
            URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_MAX_WR_LIST_NUM - 1);
            return URMA_EINVAL;
        }
    }

    ret = comp_post_send(bjetty_ctx->bdp_comp, send_idx, prealloc_wr_list, bad_wr);
    return ret;
}

static urma_status_t bondp_post_send_wr_and_store(bjetty_ctx_t *bjetty_ctx, bondp_jfc_t *vjfc,
                                                  urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret = URMA_SUCCESS;

    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("WR->tjetty is NULL\n");
        return URMA_EINVAL;
    }

    bdp_v_conn_t *v_conn = get_v_conn_on_send(bjetty_ctx, bdp_tjetty);
    if (v_conn == NULL) {
        return URMA_FAIL;
    }

    int send_idx = 0, target_idx = 0;
    ret = schedule_send(wr, bjetty_ctx->bdp_comp, &send_idx, &target_idx);
    if (ret != 0) {
        return URMA_FAIL;
    }

    jfs_wr_entry_t *wr_entry = jfs_wr_buf_alloc(&vjfc->wr_buf);
    if (wr_entry == NULL) {
        URMA_LOG_ERR("Failed to allocate jfs wr entry\n");
        return URMA_EAGAIN;
    }
    wr_entry->user_ctx = wr->user_ctx;
    wr_entry->bjetty_ctx = bjetty_ctx;
    wr_entry->v_conn = v_conn;
    wr_entry->send_idx = send_idx;
    wr_entry->target_idx = target_idx;

    urma_jfs_wr_t *pwr = &wr_entry->wr;
    ret = copy_jfs_wr(wr, pwr, NULL, NULL);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to copy jfs wr\n");
        goto FREE_PWR;
    }

    ret = convert_jfs_vwr_to_pwr(pwr, send_idx, target_idx, bjetty_ctx, v_conn);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to convert jfs wr\n");
        goto FREE_PWR;
    }

    pwr->user_ctx = wr_entry->wr_id;
    ret = comp_post_send(bjetty_ctx->bdp_comp, send_idx, pwr, bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post send wr\n");
        goto FREE_PWR;
    }

    return URMA_SUCCESS;

FREE_PWR:
    free_jfs_wr(pwr);
    jfs_wr_buf_release(wr_entry);
    return ret;
}

static urma_status_t bondp_post_send_wr_list_store(bjetty_ctx_t *bjetty_ctx, bondp_jfc_t *vjfc,
    urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *cur = wr;

    while (cur != NULL) {
        ret = bondp_post_send_wr_and_store(bjetty_ctx, vjfc, cur, bad_wr);
        if (ret != URMA_SUCCESS) {
            return ret;
        }
        cur = cur->next;
    }
    
    return URMA_SUCCESS;
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

    bjetty_ctx_t *bjetty_ctx = &bdp_jetty->bjetty_ctx;
    if (is_single_dev_mode(jetty->urma_ctx)) {
        ret = bondp_post_send_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        ret = bondp_post_send_wr_list_store(bjetty_ctx, bdp_jetty->send_jfc, wr, bad_wr);
    }
    PERF_PROFILING_END(BOND_JETTY_POST_SEND);

    return ret;
}

urma_status_t bondp_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);
    bjetty_ctx_t *bjetty_ctx = &bdp_jfs->bjetty_ctx;
    urma_status_t ret = URMA_SUCCESS;

    PERF_PROFILING_START(BOND_JFS_POST_SEND);
    ret = post_send_check_wr_list_valid(bdp_jfs, wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        PERF_PROFILING_END(BOND_JFS_POST_SEND);
        return ret;
    }
    if (is_single_dev_mode(jfs->urma_ctx)) {
        ret = bondp_post_send_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        ret = bondp_post_send_wr_list_store(bjetty_ctx, bdp_jfs->send_jfc, wr, bad_wr);
    }
    PERF_PROFILING_END(BOND_JFS_POST_SEND);

    return ret;
}

static urma_status_t bondp_post_recv_wr_no_store(bjetty_ctx_t *bjetty_ctx,
                                                 const urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    // Pre-allocated space to improve datapath performance
    static thread_local urma_jfr_wr_t prealloc_wr_list[BONDP_MAX_WR_LIST_NUM];
    static thread_local urma_sge_t prealloc_src_sge[BONDP_MAX_WR_LIST_NUM][BONDP_MAX_SGE_NUM];

    urma_status_t ret = 0;

    int recv_idx = -1;
    ret = schedule_recv(bjetty_ctx->bdp_comp, &recv_idx);
    if (ret != 0) {
        return URMA_FAIL;
    }

    int index = 0;
    urma_jfr_wr_t *vwr = (urma_jfr_wr_t *)wr;
    while (vwr != NULL) {
        urma_jfr_wr_t *pwr = &prealloc_wr_list[index];
        ret = copy_jfr_wr(vwr, pwr, prealloc_src_sge[index]);
        if (ret != 0) {
            return URMA_FAIL;
        }
        ret = convert_jfr_vwr_to_pwr(pwr, recv_idx);
        if (ret != 0) {
            return URMA_FAIL;
        }
        if (pwr->next != NULL) {
            pwr->next = &prealloc_wr_list[index + 1];
        }

        vwr = vwr->next;
        index++;
        if (index >= BONDP_MAX_WR_LIST_NUM - 1) {
            URMA_LOG_ERR("Bondp supports at most %d wr_list.\n", BONDP_MAX_WR_LIST_NUM - 1);
            return URMA_EINVAL;
        }
    }

    ret = comp_post_recv(bjetty_ctx->bdp_comp, recv_idx, prealloc_wr_list, bad_wr);
    return ret;
}

static urma_status_t bondp_post_recv_wr_and_store(bjetty_ctx_t *bjetty_ctx, bondp_jfc_t *vjfc,
                                                  urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    int recv_idx = 0;
    urma_status_t ret;

    ret = schedule_recv(bjetty_ctx->bdp_comp, &recv_idx);
    if (ret != 0) {
        return URMA_FAIL;
    }

    jfr_wr_entry_t *wr_entry = jfr_wr_buf_alloc(&vjfc->wr_buf);
    if (wr_entry == NULL) {
        URMA_LOG_ERR("Failed to allocate jfr wr entry\n");
        return URMA_EAGAIN;
    }
    wr_entry->user_ctx = wr->user_ctx;
    wr_entry->bjetty_ctx = bjetty_ctx;
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
    ret = comp_post_recv(bjetty_ctx->bdp_comp, recv_idx, pwr, bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post recv wr\n");
        goto FREE_PWR;
    }

    return URMA_SUCCESS;

FREE_PWR:
    free_jfr_wr(pwr);
    jfr_wr_buf_release(wr_entry);
    return ret;
}

static urma_status_t bondp_post_recv_wr_list_store(bjetty_ctx_t *bjetty_ctx, bondp_jfc_t *vjfc,
    urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    urma_status_t ret = URMA_SUCCESS;
    urma_jfr_wr_t *cur = wr;

    while (cur != NULL) {
        ret = bondp_post_recv_wr_and_store(bjetty_ctx, vjfc, cur, bad_wr);
        if (ret != URMA_SUCCESS) {
            return ret;
        }
        cur = cur->next;
    }

    return URMA_SUCCESS;
}

static urma_status_t post_recv_check_jfr_wr_valid(const bondp_context_t *bdp_ctx, const urma_jfr_wr_t *wr)
{
    /* No need to handle cases where num_sge == 0 or sge == NULL; Certain hardware supports this usage. */
    if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfr_sge < wr->src.num_sge) {
        URMA_LOG_WARN("The number of sge %u the src segment is greater than the maximum supported: %u"
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
        URMA_LOG_ERR("Invalid bdp_recv_comp type: %d\n", bdp_recv_comp->comp_type);
        *bad_wr = wr;
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

    /* non-null bjetty_ctx value because post_recv_check_wr_list_valid performed validation. */
    bjetty_ctx_t *bjetty_ctx = &bdp_jetty->bjetty_ctx;
    if (is_single_dev_mode(jetty->urma_ctx)) {
        ret = bondp_post_recv_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        ret = bondp_post_recv_wr_list_store(bjetty_ctx, bdp_jetty->recv_jfc, wr, bad_wr);
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

    /* non-null bjetty_ctx value because post_recv_check_wr_list_valid performed validation. */
    bjetty_ctx_t *bjetty_ctx = &bdp_jfr->bjetty_ctx;
    // workaround, at this point, jfr only support multipath
    bdp_jfr->is_multipath = true;
    if (is_single_dev_mode(jfr->urma_ctx)) {
        ret = bondp_post_recv_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        ret = bondp_post_recv_wr_list_store(bjetty_ctx, bdp_jfr->recv_jfc, wr, bad_wr);
    }
    PERF_PROFILING_END(BOND_POST_JFR_RECV);

    return ret;
}

typedef enum cr_convert_ret {
    CONVERT_FAIL = -1,
    CONVERT_SUCCESS = 0,
    CONVERT_SKIP = 1,
} cr_convert_ret_t;

static inline bool is_recv_cr(const urma_cr_t *cr)
{
    return cr->flag.bs.s_r == 1;
}

static int resend_jfs_wr(jfs_wr_entry_t *wr_entry, int send_idx, int target_idx)
{
    int ret;

    wr_entry->send_idx = send_idx;
    wr_entry->target_idx = target_idx;
    urma_jfs_wr_t *wr = &wr_entry->wr;
    urma_target_jetty_t *vtjetty = (urma_target_jetty_t *)(wr_entry->v_conn->target_vjetty);
    ret = convert_jfs_pwr_to_another_path(wr, vtjetty, send_idx, target_idx);
    if (ret != 0) {
        URMA_LOG_ERR("Failed to set_jfs_wr_ptseg_ptjetty\n");
        return -1;
    }

    urma_jfs_wr_t *bad_wr = NULL;
    ret = comp_post_send(wr_entry->bjetty_ctx->bdp_comp, send_idx, wr, &bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to set_jfs_wr_ptseg_ptjetty\n");
        return -1;
    }

    return 0;
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
        URMA_LOG_ERR("Failed to get comp, local_id: %d\n", pjetty_id.id);
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

/**
 * When the cr status is URMA_CR_WR_SUSPEND_DONE or URMA_CR_WR_FLUSH_ERR_DONE,
 * it indicates that the CR is a fake one constructed by hardware.
 * At this time, the `urma_ctx` field in CR is invalid and most likely 0.
 */
static inline bool is_fake_cr(const urma_cr_t *cr)
{
    return cr->status == URMA_CR_WR_SUSPEND_DONE || cr->status == URMA_CR_WR_FLUSH_ERR_DONE;
}

static cr_convert_ret_t handle_fake_cr_with_store(bondp_context_t *bdp_ctx, bondp_jfc_t *bdp_jfc, int idx, urma_cr_t *cr)
{
    bondp_comp_t *comp = get_comp_by_cr(bdp_ctx, idx, cr);
    if (comp == NULL) {
        return CONVERT_FAIL;
    }

    uint8_t target_state_bit = 0;
    if (cr->status == URMA_CR_WR_SUSPEND_DONE) {
        target_state_bit = PJETTY_SUSPEND_DONE;
    } else if (cr->status == URMA_CR_WR_FLUSH_ERR_DONE) {
        target_state_bit = PJETTY_FLUSH_ERROR_DONE;
    } else {
        URMA_LOG_ERR("Invalid cr error status: %d\n", cr->status);
        put_comp(comp);
        return CONVERT_FAIL;
    }
    comp->bjetty_ctx.pjettys_error_done[idx] |= target_state_bit;
    bool all_reported = true;
    // pjetty_idx
    for (int idx = 0; idx < URMA_UBAGG_DEV_MAX_NUM; idx++) {
        if (comp->members[idx] == NULL) {
            continue;
        }
        if ((comp->bjetty_ctx.pjettys_error_done[idx] & target_state_bit) == 0) {
            all_reported = false;
            break;
        }
    }
    if (all_reported) {
        cr->local_id = get_comp_urma_jetty_id(comp)->id;
        /* Caller should copy this CR to output array. */
        put_comp(comp);
        return CONVERT_SUCCESS;
    }
    put_comp(comp);
    return CONVERT_SKIP;
}

static cr_convert_ret_t handle_send_cr_with_store(bondp_jfc_t *bdp_jfc, urma_cr_t *cr)
{
    const uint64_t wr_id = cr->user_ctx;
    jfs_wr_entry_t *wr_entry = jfs_wr_buf_get(&bdp_jfc->wr_buf, wr_id);
    if (wr_entry == NULL) {
        // wr_entry could not be NULL
        return CONVERT_FAIL;
    }

    bjetty_ctx_t *bjetty_ctx = wr_entry->bjetty_ctx;
    uint32_t send_idx = wr_entry->send_idx;
    bjetty_ctx->bdp_comp->valid[send_idx] = false;
    bjetty_ctx->bdp_comp->sqe_cnt[send_idx] -= 1;

    if (cr->status != 0) {
        if (bjetty_ctx->bdp_comp->valid[send_idx] == true) {
            bjetty_ctx->bdp_comp->valid[send_idx] = false;

            int new_send_idx = -1, new_target_idx = -1;
            if (schedule_send(&wr_entry->wr, bjetty_ctx->bdp_comp, &new_send_idx, &new_target_idx) != 0) {
                URMA_LOG_ERR("Failed to schedule send for migration\n");
                return CONVERT_FAIL;
            }

            URMA_LOG_DEBUG("Resend from %d to %d\n", send_idx, new_send_idx);

            for (int i = 0; i < bdp_jfc->wr_buf.max_wr_num; i++) {
                const int wr_id = __idx_to_wr_id((bdp_jfc->wr_buf.latest_used + 1 + i) % PRIMARY_EID_NUM);
                jfs_wr_entry_t *resend_wr_entry = jfs_wr_buf_get(&bdp_jfc->wr_buf, wr_id);
                if (resend_wr_entry->send_idx != wr_entry->send_idx ||
                    resend_wr_entry->target_idx != wr_entry->target_idx) {
                    continue;
                }
                if (resend_jfs_wr(resend_wr_entry, new_send_idx, new_target_idx) != 0) {
                    URMA_LOG_ERR("Failed to resend jfs wr, wr_id: %d\n", wr_id);
                }
            }
        }
        return CONVERT_SKIP;
    }

    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bjetty_ctx->bond_ctx, &msn);
    cr->local_id = get_comp_urma_jetty_id(wr_entry->bjetty_ctx->bdp_comp)->id;
    cr->user_ctx = wr_entry->user_ctx;

    free_jfs_wr(&wr_entry->wr);
    jfs_wr_buf_release(wr_entry);
    return CONVERT_SUCCESS;
}

static cr_convert_ret_t handle_recv_cr_with_store(bondp_jfc_t *bdp_jfc, urma_cr_t *cr)
{
    const uint64_t wr_id = cr->user_ctx;
    jfr_wr_entry_t *wr_entry = jfr_wr_buf_get(&bdp_jfc->wr_buf, wr_id);
    if (wr_entry == NULL) {
        // wr_entry could not be NULL
        return CONVERT_FAIL;
    }

    bjetty_ctx_t *bjetty_ctx = wr_entry->bjetty_ctx;
    uint32_t recv_idx = wr_entry->recv_idx;
    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bjetty_ctx->bond_ctx, &msn);
    cr->local_id = get_comp_urma_jetty_id(wr_entry->bjetty_ctx->bdp_comp)->id;
    cr->user_ctx = wr_entry->user_ctx;

    bjetty_ctx->bdp_comp->rqe_cnt[recv_idx] -= 1;

    /* Do de-duplicating */
    int ret = 0;
    urma_jetty_id_t target_jetty_id = cr->remote_id;
    bdp_v_conn_t *v_conn = bdp_v_conn_table_lookup(&bjetty_ctx->v_conn_table, &target_jetty_id);
    if (!v_conn) {
        ret = bdp_v_conn_table_add_on_recv(&bjetty_ctx->v_conn_table, &target_jetty_id, &v_conn,
                                           bjetty_ctx->bond_ctx->v_ctx.aggr_mode);
        if (ret != 0) {
            free_jfr_wr(&wr_entry->wr);
            jfr_wr_buf_release(wr_entry);
            return CONVERT_FAIL;
        }
    }
    if (!bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn) || bdp_slide_wnd_has(&v_conn->recv_wnd, msn)) {
        URMA_LOG_DEBUG("Rearm recv WR due to: outside of window: %d or duplicate %d\n",
                       !bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn),
                       bdp_slide_wnd_has(&v_conn->recv_wnd, msn));
        urma_jfr_wr_t *bad_wr = NULL;
        ret = comp_post_recv(bjetty_ctx->bdp_comp, recv_idx, &wr_entry->wr, &bad_wr);
        return CONVERT_SKIP;
    }

    (void)bdp_slide_wnd_add(&v_conn->recv_wnd, msn);

    free_jfr_wr(&wr_entry->wr);
    jfr_wr_buf_release(wr_entry);
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
        return CONVERT_FAIL;
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
        comp->sqe_cnt[idx] -= 1;
    }

    uint32_t msn = 0;
    convert_pcr_to_vcr(cr, bdp_ctx, &msn);
    cr->local_id = comp->v_jetty.jetty_id.id;

    /* Caller should copy this CR to output array. */
    put_comp(comp);
    return CONVERT_SUCCESS;
}

static cr_convert_ret_t bondp_handle_cr_with_store(bondp_context_t *bdp_ctx, bondp_jfc_t *bdp_jfc, int idx, urma_cr_t *cr)
{
    /* Handle CR with status URMA_CR_WR_SUSPEND_DONE or URMA_CR_WR_FLUSH_ERR_DONE */
    if (is_fake_cr(cr)) {
        return handle_fake_cr_with_store(bdp_ctx, bdp_jfc, idx, cr);
    } else if (is_recv_cr(cr)) {
        return handle_recv_cr_with_store(bdp_jfc, cr);
    } else {
        return handle_send_cr_with_store(bdp_jfc, cr);
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

            if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
                conv_ret = bondp_handle_cr_no_store(bdp_ctx, idx, pcr);
            } else {
                conv_ret = bondp_handle_cr_with_store(bdp_ctx, bdp_jfc, idx, pcr);
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
        if (bdp_jetty->p_jetty[i] == NULL ||
            bdp_jetty->valid[i] == false) {
            continue;
        }

        int pcr_cnt_max = cr_cnt_remaining > URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              ? URMA_UBAGG_MAX_CR_CNT_PER_DEV
                              : cr_cnt_remaining;
        int pcr_cnt = urma_flush_jetty(bdp_jetty->p_jetty[i], pcr_cnt_max, pcr_buf);

        if (pcr_cnt < 0) {
            URMA_LOG_ERR("Failed to flush pjetty[%d]: %d\n", i, pcr_cnt);
            return pcr_cnt;
        }
        if (pcr_cnt == 0) {
            continue;
        }

        for (int cr_id = 0; cr_id < pcr_cnt; cr_id++) {
            urma_cr_t *pcr = &pcr_buf[cr_id];
            cr_convert_ret_t conv_ret;

            if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
                conv_ret = bondp_handle_cr_no_store(bdp_ctx, i, pcr);
            } else {
                conv_ret = bondp_handle_cr_with_store(bdp_ctx, bdp_jetty->send_jfc, i, pcr);
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
