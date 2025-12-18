/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: Bond datapth ops implementation file
 * Author: Ma Chuan
 * Create: 2025-02-19
 * Note:
 * History: 2025-02-19   Create File
 */
#include "bondp_datapath.h"
#include "urma_log.h"
#include "urma_api.h"
#include "bondp_types.h"
#include "urma_private.h"
#include "wr_buffer.h"
#include "wr_utils.h"
#include "bondp_jetty_ctx.h"
#include "bondp_connection.h"
#include "bondp_context_table.h"

#define PJETTY_ID_ENCODE_OFFSET (32)
#define VJETTY_ID_ENCODE_OFFSET (48)
#define WRITE_IMM_USER_BITS (32)
#define WRITE_IMM_IS_SO_SHIFT (63)
#define CALLBACK_SUCCESS (0)
#define CALLBACK_SKIP (1)
#define CALLBACK_FAIL (-1)
#define RECV_WR_ID_MAX (1U << 31)

typedef enum bondp_cr_handler_ret {
    CR_HANDLER_ERR_AND_COPY     = -1,
    CR_HANDLER_SUCCESS_AND_COPY = 0,
    CR_HANDLER_SUCCESS_AND_SKIP = 1,
    CR_HANDLER_ERR_AND_SKIP     = 2,
} bondp_cr_handler_ret_t;

/** Pass arguments to JFR WR buffer migration function */
struct rearm_args {
    bjetty_ctx_t *bjetty_ctx;
    int migrate_idx;
    urma_jfr_wr_t **bad_wr;
    int skip_count;
    int ret;
};

/** Pass arguments to JFS WR buffer migration function */
struct resend_args {
    bjetty_ctx_t *bjetty_ctx;
    uint32_t migrate_idx;
    urma_jfs_wr_t **bad_wr;
    int skip_count;
    int ret;
};

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

static urma_status_t comp_post_send(bjetty_ctx_t *bjetty_ctx, int send_idx,
    urma_jfs_wr_t *send_wr, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret;
    if (bjetty_ctx->bdp_comp->comp_type == BONDP_COMP_JETTY) {
        ret = urma_post_jetty_send_wr(bjetty_ctx->pjettys[send_idx], send_wr, bad_wr);
    } else if (bjetty_ctx->bdp_comp->comp_type == BONDP_COMP_JFS) {
        ret = urma_post_jfs_wr((urma_jfs_t *)bjetty_ctx->pjettys[send_idx], send_wr, bad_wr);
    } else {
        URMA_LOG_ERR("Invalid post jfs wr type: %d\n", bjetty_ctx->bdp_comp->comp_type);
        ret = URMA_EINVAL;
    }
    return ret;
}

static urma_status_t comp_post_recv(bjetty_ctx_t *bjetty_ctx, int recv_idx,
    urma_jfr_wr_t *recv_wr, urma_jfr_wr_t **bad_wr)
{
    urma_status_t ret;
    if (bjetty_ctx->bdp_comp->comp_type == BONDP_COMP_JETTY) {
        ret = urma_post_jetty_recv_wr(bjetty_ctx->pjettys[recv_idx], recv_wr, bad_wr);
    } else if (bjetty_ctx->bdp_comp->comp_type == BONDP_COMP_JFR) {
        ret = urma_post_jfr_wr((urma_jfr_t *)bjetty_ctx->pjettys[recv_idx], recv_wr, bad_wr);
    } else {
        URMA_LOG_ERR("Invalid post jfr wr type: %d\n", bjetty_ctx->bdp_comp->comp_type);
        ret = URMA_EINVAL;
    }
    return ret;
}

/** Ignore idx_start, iterate the array from idx_start + 1.
 * This function returns idx_start if no other dev is valid.
 * This function returns -1 when all devs are invalid.
 */
static int find_next_valid_jetty_idx(bool *pjettys_valid, int dev_num, int idx_start)
{
    int ret = -1;
    for (int i = 0; i < dev_num; ++i) {
        if (pjettys_valid[(idx_start + i + 1) % dev_num]) {
            ret = (idx_start + i + 1) % dev_num;
            break;
        }
    }
    return ret;
}

static bool is_all_pjetty_fail(bjetty_ctx_t *bjetty_ctx)
{
    for (int i = 0; i < bjetty_ctx->dev_num; ++i) {
        if (bjetty_ctx->pjettys_valid[i]) {
            return false;
        }
    }
    return true;
}

/** Use user_ctx to store information of certain WR in post_jetty APIs.
 *  We need these params to find corresponding vjetty and wr_buf in bondp_poll_jfc
 */
static inline void encode_wr_user_ctx(uint64_t *user_ctx, uint32_t wr_id, uint16_t vjetty_id, uint16_t pjetty_id)
{
    *user_ctx = wr_id;
    *user_ctx |= (uint64_t)pjetty_id << PJETTY_ID_ENCODE_OFFSET;
    *user_ctx |= (uint64_t)vjetty_id << VJETTY_ID_ENCODE_OFFSET;
}

static inline void decode_wr_user_ctx(uint64_t user_ctx, uint32_t *wr_id, uint16_t *vjetty_id, uint16_t *pjetty_id)
{
    *wr_id = user_ctx & 0xffffffff;
    *pjetty_id = (user_ctx >> PJETTY_ID_ENCODE_OFFSET) & 0xffff;
    *vjetty_id = user_ctx >> VJETTY_ID_ENCODE_OFFSET;
}

static int get_send_idx_with_least_load(bjetty_ctx_t *bjetty_ctx)
{
    int least_load_idx = -1;
    uint32_t least_load = UINT32_MAX;
    uint32_t count = 0;
    uint32_t send_idx = 0;
    for (int i = 0; i < bjetty_ctx->dev_num; ++i) {
        send_idx = (i + bjetty_ctx->send_idx + 1) % bjetty_ctx->dev_num;
        if (bjetty_ctx->pjettys_valid[send_idx] == false) {
            continue;
        }
        count = wr_buf_count(bjetty_ctx->jfs_bufs[send_idx]);
        if (count < least_load) {
            least_load = count;
            least_load_idx = send_idx;
        }
    }
    return least_load_idx;
}

/** Select send pjetty idx in bjetty_ctx and target pjetty idx in bdp_target_jetty.
 * @return: 0 success.
 * @return: -1 when all local pjettys are invalid or all target pjettys are invalid.
 */
static int schedule_send_target_idx_default(bjetty_ctx_t *bjetty_ctx, bdp_v_conn_t *v_conn,
    int local_dev_num, int target_dev_num,
    urma_opcode_t opcode, urma_transport_mode_t trans_mode, int *send_idx, int *target_idx)
{
    bjetty_ctx->send_idx = get_send_idx_with_least_load(bjetty_ctx);
    if (bjetty_ctx->send_idx < 0) {
        URMA_LOG_DEBUG("Failed to find valid send jetty idx.\n");
        return -1;
    }
    *send_idx = bjetty_ctx->send_idx;
    switch (opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
            v_conn->rqe_idx = find_next_valid_jetty_idx(v_conn->target_valid, target_dev_num, v_conn->rqe_idx);
            if (v_conn->rqe_idx < 0) {
                URMA_LOG_DEBUG("Failed to find valid target jetty idx for rqe_idx.\n");
                return -1;
            }
            *target_idx = v_conn->rqe_idx;
            break;
        default:
            v_conn->non_rqe_idx = find_next_valid_jetty_idx(v_conn->target_valid,
                target_dev_num, v_conn->non_rqe_idx);
            if (v_conn->non_rqe_idx < 0) {
                URMA_LOG_DEBUG("Failed to find valid target jetty idx for non_rqe_idx.\n");
                return -1;
            }
            *target_idx = v_conn->non_rqe_idx;
            break;
    }
    if (trans_mode == URMA_TM_RC) {
        *send_idx = *target_idx;
    }
    return 0;
}
/**
 * In matrix server, multipath mode has two different planes.
 * Each plane has one device which can connect to any other device identified by primary eid.
 * Choose target with RR and RQE requirement, then set send_idx = target_idx.
 * @param v_conn: can be NULL in single-die mode.
 */
static int schedule_next_route_in_matrix_server_multipath(const urma_jfs_wr_t *wr, bondp_target_jetty_t *bdp_tjetty,
    bdp_v_conn_t *v_conn,
    int *send_idx, int *target_idx)
{
    if (is_single_dev_mode(bdp_tjetty->v_tjetty.urma_ctx)) {
        *send_idx = 0;
        *target_idx = 0;
        return 0;
    }
    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
            v_conn->rqe_idx = find_next_valid_jetty_idx(v_conn->target_valid,
                bdp_tjetty->target_dev_num, v_conn->rqe_idx);
            if (v_conn->rqe_idx < 0) {
                URMA_LOG_DEBUG("Failed to find valid target jetty idx for rqe_idx.\n");
                return -1;
            }
            *target_idx = v_conn->rqe_idx;
            break;
        default:
            v_conn->non_rqe_idx = find_next_valid_jetty_idx(v_conn->target_valid,
                bdp_tjetty->target_dev_num, v_conn->non_rqe_idx);
            if (v_conn->non_rqe_idx < 0) {
                URMA_LOG_DEBUG("Failed to find valid target jetty idx for non_rqe_idx.\n");
                return -1;
            }
            *target_idx = v_conn->non_rqe_idx;
            break;
    }
    *send_idx = *target_idx;
    return 0;
}

static int schedule_next_route_in_matrix_server_singlepath(bjetty_ctx_t *bjetty_ctx, bondp_target_jetty_t *bdp_tjetty,
    int *send_idx, int *target_idx)
{
    if (bjetty_ctx->direct_local_port == -1 || bjetty_ctx->direct_target_port == -1) {
        URMA_LOG_ERR("Invalid single path port. Single path mode only support RC and need to call bind_jetty\n");
        return -1;
    }
    *send_idx = bjetty_ctx->direct_local_port;
    *target_idx = bjetty_ctx->direct_target_port;
    return 0;
}

/**
 * @param v_conn: can be NULL in singledie mode
 * @param send_idx: output
 * @param target_idx: output
 */
static int schedule_send(const urma_jfs_wr_t *wr, bjetty_ctx_t *bjetty_ctx, bdp_v_conn_t *v_conn,
    int *send_idx, int *target_idx)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("Invalid wr->tjetty: NULL\n");
        return URMA_EINVAL;
    }
    if (!is_in_matrix_server(bjetty_ctx->bond_ctx)) {
        return schedule_send_target_idx_default(bjetty_ctx, v_conn, bjetty_ctx->dev_num,
            bdp_tjetty->target_dev_num, wr->opcode, bdp_tjetty->v_tjetty.trans_mode, send_idx, target_idx);
    }
    if (is_multipath_comp(bjetty_ctx->bdp_comp)) {
        return schedule_next_route_in_matrix_server_multipath(wr, bdp_tjetty, v_conn, send_idx, target_idx);
    }
    return schedule_next_route_in_matrix_server_singlepath(bjetty_ctx, bdp_tjetty, send_idx, target_idx);
}

static inline bool wr_buf_try_add(wr_buf_t *buf, uint32_t id)
{
    return !wr_buf_contain(buf, id);
}

static inline uint64_t get_hdr_addr(uint32_t id, uint64_t start_addr)
{
    return (((uint64_t)id * sizeof(bjetty_hdr_t)) & (URMA_UBAGG_HDR_BUF_SIZE - 1)) + start_addr;
}

static inline void set_hdr_sge(urma_sge_t *sge, uint32_t id, uint64_t start_addr, urma_target_seg_t *tseg)
{
    sge->addr = get_hdr_addr(id, start_addr);
    sge->len = sizeof(bjetty_hdr_t);
    sge->tseg = tseg;
}
/**
 * Local register seg only need param local_idx
 * Imported seg need both idxs
 */
static inline urma_target_seg_t *get_p_tseg(urma_target_seg_t *tseg, int local_idx, int remote_idx)
{
    /* Use token_id to distinguish local register seg and imported seg
       This is useful for write ops */
    if (tseg->token_id != NULL) {
        return CONTAINER_OF_FIELD(tseg, bondp_comp_t, v_tseg)->p_tseg[local_idx];
    } else {
        return CONTAINER_OF_FIELD(tseg, bondp_import_tseg_t, v_tseg)->p_tseg[local_idx][remote_idx];
    }
}

static inline urma_target_jetty_t *get_p_tjetty(urma_target_jetty_t *tjetty, int send_idx, int target_idx)
{
    return CONTAINER_OF_FIELD(tjetty, bondp_target_jetty_t, v_tjetty)->p_tjetty[send_idx][target_idx];
}

/** Reconstruct a new WR according to the user input.
 * Do the following steps:
 * 1. Deepcopy the input WR.
 * 2. Add a new sge at wr.src.sge[0], and set its addr to the next valid hdr addr if the opcode is SEND_*.
 * Considering the WR split operation in the future (Fit for CTP/UTP), the return value is a list of WR, connected by
 * WR->next.
 * The content at the addr of the first sge of SEND is empty and need to be filled.
 * @return A list of WRs as the result of the split of input WR connected by WR->next.
 * Currently, it returns the modified WR of the input, and consider it as a single element. (It may have next != NULL)
 */
static urma_jfs_wr_t *get_new_jfs_wr(const urma_jfs_wr_t *wr,
    void *hdr_send_buf, urma_target_seg_t *hdr_send_tseg,
    uint32_t send_wr_id, int send_idx, int recv_idx, int *output_len)
{
    urma_jfs_wr_t *new_wrs = NULL;
    urma_jfs_wr_t *copied_send_wr = NULL;
    int wr_len = 1;

    switch (wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            copied_send_wr = deepcopy_jfs_wr_and_add_hdr_sge(wr);
            if (copied_send_wr == NULL) {
                goto EXIT;
            }
            /* set hdr sge */
            set_hdr_sge(&copied_send_wr->send.src.sge[0], send_wr_id,
                (uint64_t)hdr_send_buf, hdr_send_tseg);
            /* We need cqe to do deduplication, so we have to set this flag */
            copied_send_wr->flag.bs.complete_enable = 1;
            new_wrs = copied_send_wr;
            *output_len = wr_len;
            break;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
        case URMA_OPC_CAS:
        case URMA_OPC_FADD:
            copied_send_wr = deepcopy_jfs_wr(wr);
            if (copied_send_wr == NULL) {
                goto EXIT;
            }
            /* We need cqe to do deduplication, so we have to set this flag */
            copied_send_wr->flag.bs.complete_enable = 1;
            new_wrs = copied_send_wr;
            *output_len = wr_len;
            break;
        default:
            URMA_LOG_ERR("unsupport opcode %d\n", wr->opcode);
            new_wrs = NULL;
            *output_len = 0;
            break;
    }
EXIT:
    return new_wrs;
}

static inline uint64_t encode_and_replace_jfs_user_ctx(urma_jfs_wr_t *wr, uint32_t send_wr_id,
    uint16_t bjetty_id, uint16_t pjetty_id)
{
    uint64_t user_ctx = wr->user_ctx;
    encode_wr_user_ctx(&wr->user_ctx, send_wr_id, bjetty_id, pjetty_id);
    return user_ctx;
}

static inline void fill_send_hdr(urma_sge_t *sge, uint32_t msn, bool is_so)
{
    ((bjetty_hdr_t *)(sge->addr))->msn = msn;
    ((bjetty_hdr_t *)(sge->addr))->is_so = is_so;
}

static inline void encode_imm_data(uint64_t *imm_data, uint32_t msn, bool is_so)
{
    *imm_data |= (uint64_t)msn << WRITE_IMM_USER_BITS; /* msn takes up to 24 bits */
    *imm_data |= (uint64_t)is_so << WRITE_IMM_IS_SO_SHIFT;
}

/** Change vseg and vtjetty to pseg and ptjetty in opcode URMA_OPC_SEND_*.
 * We store the original vtseg and vtjetty in send_wr in wr_buf and set pseg and ptjetty in tmp_wr.
 * This is useful when we need to migrate a WR to another dev.
 */
static urma_status_t set_send_wr_ptseg_ptjetty(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty,
    int send_idx, int target_idx)
{
    if (vtjetty == NULL) {
        URMA_LOG_ERR("tjetty in WR is NULL\n");
        return URMA_EINVAL;
    }
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(vtjetty, bondp_target_jetty_t, v_tjetty);
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid vtjetty, the structure may be self-consturcted.\n");
        return URMA_EINVAL;
    }
    for (int i = 0; i < send_wr->send.src.num_sge; ++i) {
        urma_target_seg_t *vtseg = (urma_target_seg_t *)send_wr->send.src.sge[i].tseg;
        if (vtseg == NULL) {
            if (send_wr->flag.bs.inline_flag) {
                continue;
            }
            URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
            return URMA_EINVAL;
        }
        if ((void *)vtseg->user_ctx == NULL) {
            URMA_LOG_ERR("Failed to set ptseg, vtseg->user_ctx is NULL."
                "The input parameter may be a self-constructed structure.\n");
            return URMA_EINVAL;
        }
        vtseg = (urma_target_seg_t *)vtseg->user_ctx;
        send_wr->send.src.sge[i].tseg = get_p_tseg(vtseg, send_idx, target_idx);
    }
    send_wr->tjetty = get_p_tjetty(vtjetty, send_idx, target_idx);
    return URMA_SUCCESS;
}

/** Change vseg and vtjetty to pseg and ptjetty in opcode URMA_OPC_WRITE
 * We store the original vseg and vtjetty in send_wr in wr_buf and set pseg and ptjetty in tmp_wr.
 * This is useful when we need to migrate a WR to another dev.
 */
static urma_status_t set_write_wr_ptseg_ptjetty(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty,
    int send_idx, int target_idx)
{
    if (vtjetty == NULL) {
        URMA_LOG_ERR("tjetty in WR is NULL\n");
        return URMA_EINVAL;
    }
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(vtjetty, bondp_target_jetty_t, v_tjetty);
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid vtjetty, the structure may be self-consturcted.\n");
        return URMA_EINVAL;
    }
    urma_target_seg_t *vtseg = NULL;
    for (int i = 0; i < send_wr->rw.src.num_sge; ++i) {
        vtseg = (urma_target_seg_t *)send_wr->rw.src.sge[i].tseg;
        if (vtseg == NULL) {
            if (send_wr->flag.bs.inline_flag) {
                continue;
            }
            URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
            return URMA_EINVAL;
        }
        if ((void *)vtseg->user_ctx == NULL) {
            URMA_LOG_ERR("vtseg->user_ctx is NULL."
                "The input parameter may be a self-constructed structure."
                "Using the Adaptation Solution.\n");
            vtseg = bondp_find_vtseg_by_va(send_wr->rw.src.sge[i].tseg->seg.token_id);
            if (vtseg == NULL) {
                URMA_LOG_ERR("bondp_find_vtseg_by_va fail.");
                return URMA_FAIL;
            }
            if ((void *)vtseg->user_ctx == NULL) {
                URMA_LOG_ERR("bondp_find_vtseg_by_va found error vtseg, vtseg->user_ctx is NULL\n");
                return URMA_FAIL;
            }
        }
        vtseg = (urma_target_seg_t *)vtseg->user_ctx;
        send_wr->rw.src.sge[i].tseg = get_p_tseg(vtseg, send_idx, target_idx);
    }
    for (int i = 0; i < send_wr->rw.dst.num_sge; ++i) {
        vtseg = (urma_target_seg_t *)send_wr->rw.dst.sge[i].tseg;
        if (vtseg == NULL) {
            if (send_wr->flag.bs.inline_flag) {
                continue;
            }
            URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
            return URMA_EINVAL;
        }
        if ((void *)vtseg->user_ctx == NULL) {
            URMA_LOG_ERR("vtseg->user_ctx is NULL."
                "The input parameter may be a self-constructed structure."
                "Using the Adaptation Solution.\n");
            vtseg = bondp_find_vtseg_by_va(send_wr->rw.dst.sge[i].tseg->seg.token_id);
            if (vtseg == NULL) {
                URMA_LOG_ERR("bondp_find_vtseg_by_va fail.");
                return URMA_FAIL;
            }
            if ((void *)vtseg->user_ctx == NULL) {
                URMA_LOG_ERR("bondp_find_vtseg_by_va found error vtseg, vtseg->user_ctx is NULL\n");
                return URMA_FAIL;
            }
        }
        vtseg = (urma_target_seg_t *)vtseg->user_ctx;
        send_wr->rw.dst.sge[i].tseg = get_p_tseg(vtseg, send_idx, target_idx);
    }
    send_wr->tjetty = get_p_tjetty(vtjetty, send_idx, target_idx);
    return URMA_SUCCESS;
}

/** Change vseg and vtjetty to pseg and ptjetty in opcode URMA_OPC_CAS
 * We store the original vseg and vtjetty in send_wr in wr_buf and set pseg and ptjetty in tmp_wr.
 * This is useful when we need to migrate a WR to another dev.
 */
static urma_status_t set_cas_wr_ptseg_pjetty(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty,
    int send_idx, int target_idx)
{
    if (vtjetty == NULL) {
        URMA_LOG_ERR("tjetty in WR is NULL\n");
        return URMA_EINVAL;
    }
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(vtjetty, bondp_target_jetty_t, v_tjetty);
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid vtjetty, the structure may be self-consturcted.\n");
        return URMA_EINVAL;
    }
    if (send_wr->cas.src == NULL || send_wr->cas.dst == NULL) {
        URMA_LOG_ERR("when set cas_wr, one of src or dst is NULL.\n");
        return URMA_EINVAL;
    }
    urma_target_seg_t *vtseg = NULL;
    vtseg = (urma_target_seg_t *)send_wr->cas.src->tseg;
    if (vtseg == NULL) {
        URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
        return URMA_EINVAL;
    }
    if ((void *)vtseg->user_ctx == NULL) {
        URMA_LOG_ERR("vtseg->user_ctx is NULL."
            "The input parameter may be a self-constructed structure.\n");
        return URMA_EINVAL;
    }
    vtseg = (urma_target_seg_t *)vtseg->user_ctx;
    send_wr->cas.src->tseg = get_p_tseg(vtseg, send_idx, target_idx);
    vtseg = (urma_target_seg_t *)send_wr->cas.dst->tseg;
    if (vtseg == NULL) {
        URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
        return URMA_EINVAL;
    }
    if ((void *)vtseg->user_ctx == NULL) {
        URMA_LOG_ERR("vtseg->user_ctx is NULL."
            "The input parameter may be a self-constructed structure.\n");
        return URMA_EINVAL;
    }
    send_wr->cas.dst->tseg = get_p_tseg(vtseg, send_idx, target_idx);

    send_wr->tjetty = get_p_tjetty(vtjetty, send_idx, target_idx);
    return URMA_SUCCESS;
}

/** Change vseg and vtjetty to pseg and ptjetty in opcode URMA_OPC_FADD
 * We store the original vseg and vtjetty in send_wr in wr_buf and set pseg and ptjetty in tmp_wr.
 * This is useful when we need to migrate a WR to another dev.
 */
static urma_status_t set_fadd_wr_ptseg_pjetty(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty,
    int send_idx, int target_idx)
{
    if (vtjetty == NULL) {
        URMA_LOG_ERR("tjetty in WR is NULL\n");
        return URMA_EINVAL;
    }
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(vtjetty, bondp_target_jetty_t, v_tjetty);
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid vtjetty, the structure may be self-consturcted.\n");
        return URMA_EINVAL;
    }
    if (send_wr->faa.src == NULL || send_wr->faa.dst == NULL) {
        URMA_LOG_ERR("when set faa_wr, one of src or dst is NULL.\n");
        return URMA_EINVAL;
    }
    urma_target_seg_t *vtseg = NULL;
    vtseg = (urma_target_seg_t *)send_wr->faa.src->tseg;
    if (vtseg == NULL) {
        URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
        return URMA_EINVAL;
    }
    if ((void *)vtseg->user_ctx == NULL) {
        URMA_LOG_ERR("vtseg->user_ctx is NULL."
            "The input parameter may be a self-constructed structure.\n");
        return URMA_EINVAL;
    }
    vtseg = (urma_target_seg_t *)vtseg->user_ctx;
    send_wr->faa.src->tseg = get_p_tseg(vtseg, send_idx, target_idx);

    vtseg = (urma_target_seg_t *)send_wr->faa.dst->tseg;
    if (vtseg == NULL) {
        URMA_LOG_ERR("Failed to set ptseg, vtseg is NULL\n");
        return URMA_EINVAL;
    }
    if ((void *)vtseg->user_ctx == NULL) {
        URMA_LOG_ERR("vtseg->user_ctx is NULL."
            "The input parameter may be a self-constructed structure.\n");
        return URMA_EINVAL;
    }
    vtseg = (urma_target_seg_t *)send_wr->faa.dst->tseg->user_ctx;
    send_wr->faa.dst->tseg = get_p_tseg(vtseg, send_idx, target_idx);
    send_wr->tjetty = get_p_tjetty(vtjetty, send_idx, target_idx);
    return URMA_SUCCESS;
}

static urma_status_t set_jfs_wr_ptseg_ptjetty(urma_jfs_wr_t *send_wr, urma_target_jetty_t *vtjetty,
    int send_idx, int target_idx)
{
    urma_status_t ret = URMA_SUCCESS;
    switch (send_wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            return set_send_wr_ptseg_ptjetty(send_wr, vtjetty, send_idx, target_idx);
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            return set_write_wr_ptseg_ptjetty(send_wr, vtjetty, send_idx, target_idx);
        case URMA_OPC_CAS:
            return set_cas_wr_ptseg_pjetty(send_wr, vtjetty, send_idx, target_idx);
        case URMA_OPC_FADD:
            return set_fadd_wr_ptseg_pjetty(send_wr, vtjetty, send_idx, target_idx);
        default:
            URMA_LOG_ERR("Unsupported send opcode\n");
            return URMA_EINVAL;
    }
    return ret;
}

static urma_status_t encode_jfs_wr_reliable_info(urma_jfs_wr_t *send_wr, wr_buf_extra_value_t *value)
{
    switch (send_wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            fill_send_hdr(send_wr->send.src.sge,
                value->msn,
                value->flag.bs.place_order == URMA_STRONG_ORDER);
            break;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            if (send_wr->opcode == URMA_OPC_WRITE_IMM) {
                /* We need to use the imm data field to carry msn to the target.
                   So we have to limit user's data to WRITE_IMM_USER_BITS bits. */
                encode_imm_data(&send_wr->rw.notify_data, value->msn, value->flag.bs.place_order == URMA_STRONG_ORDER);
            }
            break;
        default:
            URMA_LOG_ERR("Unsupported send opcode\n");
            return URMA_EINVAL;
    }
    return URMA_SUCCESS;
}
/**
 * 1. Change tseg in sges from v_tseg to p_tseg
 * 2. Change tjetty in send_wr from v_tjetty to p_tjetty
 * 3. Fill in header sge for send opcode
 * 4. Encode imm_data for write_with_imm opcode
 * @param send_wr: A copy of original jfs wr. An extra sge should be appended at the header of sges for send ops.
 * @param value: Extra value to send the current WR, including send/target idx and msn, etc.
 */
static urma_status_t update_send_wr_before_post(urma_jfs_wr_t *send_wr, wr_buf_extra_value_t *value)
{
    urma_status_t ret = URMA_SUCCESS;
    ret = set_jfs_wr_ptseg_ptjetty(send_wr, value->vtjetty, value->send_idx, value->target_idx);
    if (ret) {
        URMA_LOG_ERR("Failed to set_jfs_wr_ptseg_ptjetty\n");
        return ret;
    }
    ret = encode_jfs_wr_reliable_info(send_wr, value);
    if (ret) {
        URMA_LOG_ERR("Failed to encode_jfs_wr_reliable_info\n");
        return ret;
    }
    return ret;
}
/**
 * Post send jfs wr and store it in bjetty_ctx->jfs_bufs
 * @param send_wr: A copy of original jfs wr. An extra sge should be appended at the header of sges for send ops.
 * @param value: Extra value to send the current WR, including send/target idx and msn, etc.
 */
static urma_status_t send_and_store_jfs_wr(bjetty_ctx_t *bjetty_ctx, uint32_t v_jetty_id, urma_jfs_wr_t *send_wr,
    uint32_t send_wr_id, wr_buf_extra_value_t *value, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret = URMA_SUCCESS;

    ret = update_send_wr_before_post(send_wr, value);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    /* We need user_ctx to find corresponding wr_buf entry in poll function,
       so we need to encode user_ctx with key information and store the original one */
    (void)encode_and_replace_jfs_user_ctx(send_wr, send_wr_id,
        (uint16_t)v_jetty_id, (uint16_t)value->send_idx);
    /* post send wr */
    ret = comp_post_send(bjetty_ctx, value->send_idx, send_wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post send in send_and_store_jfs_wr, ret %d", ret);
        return ret;
    }
    /* store to jfs_wr_buf */
    /* This operation may fail due to extremely high speed of sending
       which consumes all send_wr_id space of 2^24 */
    (void)jfs_wr_buf_add_wr(bjetty_ctx->jfs_bufs[value->send_idx], send_wr_id, send_wr, value);
    return URMA_SUCCESS;
}

static inline void increase_id_after_send(uint32_t *send_wr_id, uint32_t *msn, urma_opcode_t opcode)
{
    (*send_wr_id)++;
    (*send_wr_id) &= (BONDP_MAX_BITMAP_SIZE - 1);
    if (opcode != URMA_OPC_WRITE && opcode != URMA_OPC_READ) {
        (*msn)++;
        (*msn) &= (BONDP_MAX_BITMAP_SIZE - 1);
    }
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
                    "by the device.\n", wr->send.src.num_sge,
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
                        " by the device.\n", wr->rw.src.num_sge,
                        bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge);
                }
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported: %u"
                        " by the device.\n", wr->rw.dst.num_sge,
                        bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
                }
            } else {
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge < wr->rw.src.num_sge) {
                    URMA_LOG_WARN("The number of local sge %u is greater than the maximum supported: %u"
                        " by the device.\n", wr->rw.src.num_sge,
                        bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_sge);
                }
                if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfs_rsge < wr->rw.dst.num_sge) {
                    URMA_LOG_WARN("The number of remote sge %u is greater than the maximum supported: %u"
                        " by the device.\n", wr->rw.dst.num_sge,
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
    if (!is_valid_bondp_comp(bdp_send_comp)) {
        URMA_LOG_ERR("Invalid bdp_send_comp");
        return URMA_EINVAL;
    }
    if (bdp_send_comp->comp_type != BONDP_COMP_JFS && bdp_send_comp->comp_type != BONDP_COMP_JETTY) {
        URMA_LOG_ERR("Try to call post_send api by invalid comp_type: %d\n", bdp_send_comp->comp_type);
        return URMA_EINVAL;
    }
    if (!is_valid_bdp_tjetty(bdp_tjetty)) {
        URMA_LOG_ERR("Invalid bdp_target_jetty");
        return URMA_EINVAL;
    }
    if (is_in_matrix_server(bdp_send_comp->bondp_ctx) != bdp_tjetty->is_in_matrix_server) {
        URMA_LOG_ERR("Data cannot be transferred between jettys in different matrix server mode\n");
        return URMA_EINVAL;
    }
    if (is_in_matrix_server(bdp_send_comp->bondp_ctx)) {
        if (is_multipath_comp(bdp_send_comp) != bdp_tjetty->is_multipath) {
            URMA_LOG_ERR("Data cannot be transferred between jettys in different multipath mode\n");
            return URMA_EINVAL;
        }
    }
    bjetty_ctx_t *bjetty_ctx = bdp_send_comp->comp_ctx;
    if (bjetty_ctx == NULL) {
        URMA_LOG_ERR("No bjetty_ctx\n");
        return URMA_EINVAL;
    }
    if (is_all_pjetty_fail(bjetty_ctx)) {
        URMA_LOG_ERR("All bonding devs are invalid");
        return URMA_FAIL;
    }
    urma_status_t ret = post_send_check_jfs_wr_valid(bdp_send_comp->bondp_ctx, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
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
        URMA_LOG_ERR("Invalid comp_jetty_id\n");
        return NULL;
    }
    urma_jetty_id_t *vtjetty_id = &bdp_tjetty->v_tjetty.id;
    bdp_v_conn_t *v_conn = bdp_v_conn_table_lookup(&bjetty_ctx->v_conn_table, vtjetty_id);
    if (!v_conn) {
        int ret = bdp_v_conn_table_add_on_send(&bjetty_ctx->v_conn_table, vtjetty_id,
            bdp_tjetty, bdp_tjetty->target_dev_num, &v_conn);
        if (ret) {
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
/**
 * Do not cache WR, nor perform reliability processing;
 * simply replicate the WR information,
 * replace it with ptjetty and ptseg content,
 * and then send it.
 */
static urma_status_t bondp_post_send_wr_no_store(bjetty_ctx_t *bjetty_ctx,
    const urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret = URMA_SUCCESS;
    int local_port = -1;
    int target_port = -1;
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    if (bdp_tjetty == NULL) {
        URMA_LOG_ERR("WR->tjetty is NULL\n");
        return URMA_EINVAL;
    }
    bdp_v_conn_t *v_conn = get_v_conn_on_send(bjetty_ctx, bdp_tjetty);
    if (v_conn == NULL) {
        URMA_LOG_ERR("Failed to get v_conn\n");
        return URMA_FAIL;
    }
    ret = schedule_send(wr, bjetty_ctx, v_conn, &local_port, &target_port);
    if (ret) {
        URMA_LOG_ERR("Failed to get local/target port");
        return URMA_FAIL;
    }
    urma_jfs_wr_t *copied_jfs_wr = deepcopy_jfs_wr(wr);
    if (copied_jfs_wr == NULL) {
        URMA_LOG_ERR("Failed to get copied_jfs_wr\n");
        return URMA_FAIL;
    }
    urma_jfs_wr_t *cur_wr = copied_jfs_wr;
    while (cur_wr != NULL) {
        ret = set_jfs_wr_ptseg_ptjetty(cur_wr, cur_wr->tjetty, local_port, target_port);
        if (ret) {
            URMA_LOG_ERR("Failed to emplace jfs pjetty ptseg\n");
            goto DEL_AND_RET;
        }
        cur_wr = cur_wr->next;
    }
    ret = comp_post_send(bjetty_ctx, local_port, copied_jfs_wr, bad_wr);
DEL_AND_RET:
    (void)delete_copied_jfs_wr(copied_jfs_wr);
    return ret;
}
/**
 * Enable WR caching during data transmission,
 * support failover functionality, and enable SO to handle in-order processing.
 * Compared to `bondp_post_send_wr_no_store`, it provides all designed features supported by the aggregation device.
 */
static urma_status_t bondp_post_send_wr_and_store(bjetty_ctx_t *bjetty_ctx,
    const urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    bdp_v_conn_t *v_conn = get_v_conn_on_send(bjetty_ctx, bdp_tjetty);
    if (v_conn == NULL) {
        URMA_LOG_ERR("Failed to get v_conn\n");
        return URMA_FAIL;
    }
    /* Schedule sending jetty */
    int send_idx = 0;
    int target_idx = 0;
    urma_status_t ret = schedule_send(wr, bjetty_ctx, v_conn, &send_idx, &target_idx);
    if (ret) {
        URMA_LOG_ERR("Failed to get send target idx\n");
        return URMA_FAIL;
    }
    /* We maintain the following statement:
       wr_buf contains a certain WR <=> urma post api succeeds to send data
       Therefore, if wr_buf can't cache the WR data, then we can't call post api to send */
    if (!wr_buf_try_add(bjetty_ctx->jfs_bufs[send_idx], bjetty_ctx->send_wr_id)) {
        /* get_comp_urma_jetty_id will return a non-null value,
           because the previous post_send_check_valid has performed validation. */
        urma_jetty_id_t *comp_jetty_id = get_comp_urma_jetty_id(bjetty_ctx->bdp_comp);
        URMA_LOG_INFO("No space left in wr_buf[%d], jetty_id: " URMA_JETTY_ID_FMT "\n", send_idx,
            URMA_JETTY_ID_ARGS(comp_jetty_id));
        return URMA_EAGAIN;
    }
    /* get new wr */
    /*
    ! Currently, we assume param `next` is not NULL
    This function will deepcopy WR and add a sge at pos 0 to store user-space header
    The hdr sge is empty after allocation, it needs to be filled afterwards
    ! Only valid when we don't do WR split
    */
    int new_wrs_len = 0;
    urma_jfs_wr_t *send_wr = get_new_jfs_wr(wr, bjetty_ctx->hdr_send_buf, bjetty_ctx->hdr_send_tseg,
        bjetty_ctx->send_wr_id, send_idx, target_idx, &new_wrs_len);
    if (send_wr == NULL) {
        URMA_LOG_ERR("Failed to get jfs wr");
        return URMA_FAIL;
    }
    /* Store essential information to wr_buf when the WR is posted for the first time */
    wr_buf_extra_value_t value = {
        .user_ctx = wr->user_ctx,
        .flag = wr->flag,
        .v_conn = v_conn,
        .vtjetty = wr->tjetty,
        .send_idx = send_idx,
        .target_idx = target_idx,
        .trans_mode = bdp_tjetty->v_tjetty.trans_mode
    };
    /* Only set msn for ops which need RQE */
    if (wr->opcode != URMA_OPC_WRITE && wr->opcode != URMA_OPC_READ) {
        value.msn = v_conn->msn;
    } else {
        value.msn = -1; /* valid msn < 2^24, so -1 indicates invalid */
    }
    /* Handle Strong Order */
    /* Sender needs to delay sending SO WRs until all previous WRs are acked
       So we use send_wr_id to mark the order */
    if (send_wr->flag.bs.place_order == URMA_STRONG_ORDER && v_conn->send_wnd.head != bjetty_ctx->send_wr_id) {
        /* If we can't send SO WR now, we need to cache it until the previous WR is acked */
        so_queue_data_t so_data = {
            .send_wr = send_wr,
            .send_wr_id = bjetty_ctx->send_wr_id,
            .ex_value = value
        };
        if (bdp_v_conn_push_send_so(v_conn, &so_data)) {
            URMA_LOG_ERR("Failed to push so wr to so queue");
            ret = URMA_FAIL;
            goto FREE_SEND_WR;
        }
        increase_id_after_send(&bjetty_ctx->send_wr_id, &v_conn->msn, wr->opcode);
        ret = URMA_SUCCESS;
        goto EXIT;
    }
    /* get_comp_urma_jetty_id will return a non-null value,
       because the previous post_send_check_valid has performed validation. */
    ret = send_and_store_jfs_wr(bjetty_ctx, get_comp_urma_jetty_id(bjetty_ctx->bdp_comp)->id,
        send_wr, bjetty_ctx->send_wr_id, &value, bad_wr);
    if (ret != URMA_SUCCESS) {
        goto FREE_SEND_WR;
    }
    increase_id_after_send(&bjetty_ctx->send_wr_id, &v_conn->msn, wr->opcode);
    ret = URMA_SUCCESS;
    /* The WRs copied from user input are already moved into the wr_buf
       wr_buf takes the ownership of them and release them when destruct
       But the array of WRs need to be released */
    goto EXIT;
FREE_SEND_WR:
    delete_copied_jfs_wr(send_wr);
EXIT:
    return ret;
}

urma_status_t bondp_post_jetty_send_wr(urma_jetty_t *jetty, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    urma_status_t ret = post_send_check_valid(bdp_jetty, bdp_tjetty, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    bjetty_ctx_t *bjetty_ctx = bdp_jetty->comp_ctx;
    if (is_single_dev_mode(jetty->urma_ctx)) {
        return bondp_post_send_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        return bondp_post_send_wr_and_store(bjetty_ctx, wr, bad_wr);
    }
}

/** Select recv pjetty in post_jetty_recv_wr */
static urma_status_t schedule_recv_idx_default(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    bjetty_ctx->post_recv_idx = find_next_valid_jetty_idx(bjetty_ctx->pjettys_valid, bjetty_ctx->dev_num,
                                                          bjetty_ctx->post_recv_idx);
    if (bjetty_ctx->post_recv_idx < 0) {
        /* all pjetty fail */
        URMA_LOG_INFO("All pjetty fail in schedule_recv_idx_default.");
        return URMA_FAIL;
    }
    *recv_idx = bjetty_ctx->post_recv_idx;
    return URMA_SUCCESS;
}

/** Reconstruct a new WR according to the user input.
 * Do the following steps:
 * 1. Deepcopy the input WR.
 * 2. Add a new sge at wr.src.sge[0], and set its addr to the next valid hdr addr.
 * Considering the Wr split operation in the future (Fit for CTP/UTP), the return value is a list of WR, connected by
 * WR->next.
 * The content at the addr of the first sge is empty and need to be filled.
 * @return A list of WRs as the result of the split of input WR connected by WR->next.
 * Currently, it returns the modified WR of the input, and consider it as a single element. (It may have next != NULL)
*/
static urma_jfr_wr_t *get_new_jfr_wr(const urma_jfr_wr_t *wr, bjetty_ctx_t *bjetty_ctx, int recv_idx, int *output_len)
{
    urma_jfr_wr_t *copied_jfr_wr = NULL;
    int wr_len = 1;

    copied_jfr_wr = deepcopy_jfr_wr_and_add_hdr_sge(wr);
    if (copied_jfr_wr == NULL) {
        return NULL;
    }
    *output_len = wr_len;
    /* set hdr sge */
    set_hdr_sge(&copied_jfr_wr->src.sge[0], bjetty_ctx->recv_wr_id,
        (uint64_t)bjetty_ctx->hdr_recv_buf, get_p_tseg(bjetty_ctx->hdr_recv_tseg, recv_idx, 0));
    /* set user sge */
    for (int i = 0; i < wr->src.num_sge; ++i) {
        copied_jfr_wr->src.sge[1 + i].tseg = get_p_tseg(wr->src.sge[i].tseg, recv_idx, 0);
    }
    return copied_jfr_wr;
}

/**
 * Consider of message split, we need to know the certain WR of each splitted WRs.
 * We may need to encode this information in the encode function.
 * Currently we only use user_ctx to distinguish different WR.
*/
static uint64_t encode_and_replace_jfr_user_ctx(urma_jfr_wr_t *wr, uint32_t recv_wr_id,
    uint16_t bjetty_id, uint16_t pjetty_id)
{
    uint64_t user_ctx = wr->user_ctx;
    encode_wr_user_ctx(&wr->user_ctx, recv_wr_id, bjetty_id, pjetty_id);
    return user_ctx;
}

static void update_bjetty_ctx_after_post_recv(bjetty_ctx_t *bjetty_ctx)
{
    bjetty_ctx->recv_wr_id++;
    bjetty_ctx->recv_wr_id &= (RECV_WR_ID_MAX - 1);
}

static urma_status_t copy_store_and_post_jfr_wr(uint32_t v_jetty_id, bjetty_ctx_t *bjetty_ctx, int recv_idx,
    urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    /*
    We maintain the following statement:
    wr_buf contains a certain WR <=> urma post api succeeds to send data
    Therefore, if wr_buf can't cache the WR data, then we can't call post api to send
    */
    if (!wr_buf_try_add(bjetty_ctx->jfr_bufs[recv_idx], bjetty_ctx->recv_wr_id)) {
        return URMA_EAGAIN;
    }
    int new_wrs_len = 0;
    urma_jfr_wr_t *recv_wr = get_new_jfr_wr(wr, bjetty_ctx, recv_idx, &new_wrs_len);
    if (recv_wr == NULL) {
        return URMA_FAIL;
    }
    uint64_t original_user_ctx = encode_and_replace_jfr_user_ctx(recv_wr, bjetty_ctx->recv_wr_id,
        (uint16_t)v_jetty_id, (uint16_t)recv_idx);
    /* post recv */
    urma_status_t ret = 0;
    ret = comp_post_recv(bjetty_ctx, recv_idx, recv_wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post jetty recv %d\n", ret);
        goto FREE_COPIED_JFR_WR;
    }
    /* store to jfr_wr_buf */
    /* This operation won't fail because we check before */
    wr_buf_extra_value_t value = {
        .user_ctx = original_user_ctx
    };
    (void)jfr_wr_buf_add_wr(bjetty_ctx->jfr_bufs[recv_idx], bjetty_ctx->recv_wr_id, recv_wr, &value);
    update_bjetty_ctx_after_post_recv(bjetty_ctx);
    ret = URMA_SUCCESS;
    goto EXIT;
FREE_COPIED_JFR_WR:
    delete_copied_jfr_wr(recv_wr);
EXIT:
    return ret;
}

static urma_status_t set_jfr_wr_ptjetty_ptseg_without_hdr(urma_jfr_wr_t *recv_wr, int local_idx, int target_idx)
{
    /* set user sge */
    for (int i = 0; i < recv_wr->src.num_sge; ++i) {
        if (recv_wr->src.sge[i].tseg == NULL) {
            URMA_LOG_ERR("Recv sge[%d] has NULL tseg\n", i);
            return URMA_EINVAL;
        }
        if ((void *)recv_wr->src.sge[i].tseg->user_ctx == NULL) {
            URMA_LOG_ERR("Recv sge[%d] has invalid tseg, user_ctx is NULL. It may be self-constructed\n", i);
            return URMA_EINVAL;
        }
        recv_wr->src.sge[i].tseg = get_p_tseg(recv_wr->src.sge[i].tseg, local_idx, target_idx);
    }
    return URMA_SUCCESS;
}

static urma_status_t schedule_next_recv_port_matrix_multipath(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    if (is_single_dev_mode(&bjetty_ctx->bond_ctx->v_ctx)) {
        *recv_idx = 0;
        return URMA_SUCCESS;
    }
    return schedule_recv_idx_default(bjetty_ctx, recv_idx);
}

static urma_status_t schedule_next_recv_port_matrix_singlepath(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    if (bjetty_ctx->direct_local_port == -1 || bjetty_ctx->direct_target_port == -1) {
        URMA_LOG_ERR("Invalid single path port in recv."
            "It is likely because `urma_post_jetty_recv` was called before `urma_bind_jetty`.\n");
        return URMA_EINVAL;
    }
    *recv_idx= bjetty_ctx->direct_local_port;
    return URMA_SUCCESS;
}

static urma_status_t schedule_recv(bjetty_ctx_t *bjetty_ctx, int *recv_idx)
{
    if (!is_in_matrix_server(bjetty_ctx->bdp_comp->bondp_ctx)) {
        return schedule_recv_idx_default(bjetty_ctx, recv_idx);
    }
    /* JFR is set to multipath mode at default */
    /* Only JETTY can be single_path mode in schedule_recv */
    if (is_multipath_comp(bjetty_ctx->bdp_comp)) {
        return schedule_next_recv_port_matrix_multipath(bjetty_ctx, recv_idx);
    }
    return schedule_next_recv_port_matrix_singlepath(bjetty_ctx, recv_idx);
}
/**
 * Do not cache WR, nor perform reliability processing;
 * simply replicate the WR information,
 * replace it with ptjetty and ptseg content,
 * and then post recv.
 */
static urma_status_t bondp_post_recv_wr_no_store(bjetty_ctx_t *bjetty_ctx,
    const urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    int recv_idx = -1;
    urma_status_t ret = 0;
    ret = schedule_recv(bjetty_ctx, &recv_idx);
    if (ret) {
        URMA_LOG_ERR("Failed to schedule recv: %d\n", ret);
        return URMA_FAIL;
    }
    urma_jfr_wr_t *copied_jfr_wr = deepcopy_jfr_wr(wr);
    if (copied_jfr_wr == NULL) {
        URMA_LOG_ERR("Failed to get copied_jfr_wr\n");
        return URMA_FAIL;
    }
    urma_jfr_wr_t *cur_wr = copied_jfr_wr;
    while (cur_wr != NULL) {
        ret = set_jfr_wr_ptjetty_ptseg_without_hdr(cur_wr, recv_idx, 0);
        if (ret) {
            URMA_LOG_ERR("Failed to emplace jfr pjetty ptseg\n");
            goto DELETE_JFR_WR;
        }
        cur_wr = cur_wr->next;
    }
    ret = comp_post_recv(bjetty_ctx, recv_idx, copied_jfr_wr, bad_wr);
DELETE_JFR_WR:
    (void)delete_copied_jfr_wr(copied_jfr_wr);
    return ret;
}
/**
 * During the post_recv process,
 * cache the WR to allow for data deduplication operations when duplicate WRs are received subsequently.
 * Check bjetty_ctx is valid before calling this function.
*/
static urma_status_t bondp_post_recv_wr_and_store(bjetty_ctx_t *bjetty_ctx, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    bondp_comp_t *bdp_comp = bjetty_ctx->bdp_comp;
    int recv_idx = 0;
    /* Schedule receiving jetty */
    int ret = schedule_recv(bjetty_ctx, &recv_idx);
    if (ret) {
        URMA_LOG_ERR("Failed to schedule recv: %d\n", ret);
        return URMA_FAIL;
    }
    /* get_comp_urma_jetty_id will return a non-null value,
       because the previous post_recv_check_valid has performed validation. */
    return copy_store_and_post_jfr_wr(get_comp_urma_jetty_id(bdp_comp)->id, bjetty_ctx, recv_idx, wr, bad_wr);
}

static urma_status_t post_recv_check_jfr_wr_valid(bondp_context_t *bdp_ctx, const urma_jfr_wr_t *wr)
{
    /* No need to handle cases where num_sge == 0 or sge == NULL; Certain hardware supports this usage. */
    if (bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfr_sge < wr->src.num_sge) {
        URMA_LOG_WARN("The number of sge %u the src segment is greater than the maximum supported: %u"
            " by the device.\n", wr->src.num_sge,
            bdp_ctx->v_ctx.dev->sysfs_dev->dev_attr.dev_cap.max_jfr_sge);
    }
    return URMA_SUCCESS;
}

static urma_status_t post_recv_check_valid(bondp_comp_t *bdp_recv_comp, const urma_jfr_wr_t *wr)
{
    if (!is_valid_bondp_comp(bdp_recv_comp)) {
        URMA_LOG_ERR("Invalid bdp_comp\n");
        return URMA_EINVAL;
    }
    bjetty_ctx_t *bjetty_ctx = bdp_recv_comp->comp_ctx;
    if (bjetty_ctx == NULL) {
        URMA_LOG_ERR("bjetty_ctx is NULL\n");
        return URMA_EINVAL;
    }
    if (bdp_recv_comp->comp_type != BONDP_COMP_JETTY && bdp_recv_comp->comp_type != BONDP_COMP_JFR) {
        URMA_LOG_ERR("Invalid bdp_recv_comp type: %d\n", bdp_recv_comp->comp_type);
        return URMA_EINVAL;
    }
    urma_status_t ret = post_recv_check_jfr_wr_valid(bdp_recv_comp->bondp_ctx, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    return URMA_SUCCESS;
}

urma_status_t bondp_post_jetty_recv_wr(urma_jetty_t *jetty, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_status_t ret = URMA_SUCCESS;
    ret = post_recv_check_valid(bdp_jetty, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    /* non-null bjetty_ctx value because post_recv_check_valid performed validation. */
    bjetty_ctx_t *bjetty_ctx = bdp_jetty->comp_ctx;
    if (is_single_dev_mode(jetty->urma_ctx)) {
        return bondp_post_recv_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        return bondp_post_recv_wr_and_store(bjetty_ctx, wr, bad_wr);
    }
}

static inline bool is_device_error(urma_cr_status_t status)
{
    return status >= URMA_CR_ACK_TIMEOUT_ERR;
}

static inline bool is_target_device_error(urma_cr_status_t status)
{
    return false;
}

static inline bool is_local_device_error(bjetty_ctx_t *bjetty_ctx, int send_idx)
{
    return !bjetty_ctx->pjettys_valid[send_idx];
}

static inline bool is_recv_cr(urma_cr_t *cr)
{
    return cr->flag.bs.s_r == 1;
}

/** Callback function to migrate JFS WR buffer from a device in error to target device
 * The callback function is called on every wr_buf_node_t in the wr_buf
 * @return 0: Success
 * @return <0: Error
 * @return >0: Skip when the target WR buffer is full
 */
static int resend_wr_in_error_device_buf(wr_buf_node_t *node, void *args)
{
    struct resend_args *ra = (struct resend_args *)args;
    bjetty_ctx_t *bjetty_ctx = ra->bjetty_ctx;
    uint32_t migrate_idx = ra->migrate_idx;
    urma_jfs_wr_t **bad_wr = ra->bad_wr;
    int ret = CALLBACK_SUCCESS;

    if (!wr_buf_try_add(bjetty_ctx->jfs_bufs[migrate_idx], node->key)) {
        /* skip if we can't add the WR */
        ra->skip_count++;
        URMA_LOG_DEBUG("Skip in resend_wr_in_error_device_buf\n");
        return CALLBACK_SKIP;
    }
    node->value.send_idx = migrate_idx;
    node->value.target_idx = migrate_idx;
    /* get_comp_urma_jetty_id(bjetty_ctx->bdp_comp) always returns non-null value. */
    /* Because resend funciton access stored bjetty_ctx pointer which has been validated in post_send_check_valid */
    ret = send_and_store_jfs_wr(bjetty_ctx, get_comp_urma_jetty_id(bjetty_ctx->bdp_comp)->id,
        node->jfs_wr, node->key, &node->value, bad_wr);
    ra->ret = -ret;
    return -ret;
}

/** Migrate the WRs in a failed jetty to another valid jetty
 * Any error occurs in the migration process will interrupt the whole procedure, until the next call
 * Repeat interruptions may cause the migration never succeed to be resent
 * @return 0: Data migration succeed, all the WRs are resend and stored in another jetty's wr_buf
 * @return <0: Error occurs in data migration, error code is the opposite of urma_status_t in urma_post_jetty_send_wr
 * @return >0: Data migration partially succeed. Return value is the number of WRs which are not migrated
 */
int resend_error_device(bjetty_ctx_t *bjetty_ctx, uint32_t err_idx, uint32_t migrate_idx, urma_jfs_wr_t **bad_wr)
{
    if (wr_buf_count(bjetty_ctx->jfs_bufs[err_idx]) == 0) {
        return 0;
    }
    struct resend_args args = {
        .bjetty_ctx = bjetty_ctx,
        .migrate_idx = migrate_idx,
        .bad_wr = bad_wr,
        .skip_count = 0,
        .ret = 0,
    };
    wr_buf_traverse_and_remove(bjetty_ctx->jfs_bufs[err_idx], resend_wr_in_error_device_buf, &args);
    return args.ret;
}

static urma_status_t send_so_from_snd_queue(bjetty_ctx_t *bjetty_ctx, bdp_v_conn_t *v_conn)
{
    so_queue_data_t *so_data = NULL;
    so_queue_data_t tmp_data;
    bdp_slide_wnd_t *snd_wnd = &v_conn->send_wnd;
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *bad_wr = NULL;

    while (!bdp_queue_is_empty(&v_conn->send_strong_order_queue)) {
        if (v_conn->target_vjetty == NULL) {
            URMA_LOG_ERR("v_conn has NULL target_vjetty in sending SO\n");
            return URMA_FAIL;
        }
        (void)bdp_queue_front(&v_conn->send_strong_order_queue, (void **)&so_data);
        if (snd_wnd->head == so_data->send_wr_id) {
            /* do send SO */
            /* get_comp_urma_jetty_id(bjetty_ctx->bdp_comp) always returns non-null value. */
            /* Because stored bjetty_ctx pointer which has been validated in post_send_check_valid */
            ret = send_and_store_jfs_wr(bjetty_ctx, get_comp_urma_jetty_id(bjetty_ctx->bdp_comp)->id, so_data->send_wr,
                so_data->send_wr_id, &so_data->ex_value, &bad_wr);
            if (ret != URMA_SUCCESS) {
                URMA_LOG_WARN("Failed to send SO, ret = %d\n", ret);
                return ret;
            }
            (void)bdp_v_conn_pop_send_so(v_conn, &tmp_data);
        } else {
            return URMA_SUCCESS;
        }
    }
    return URMA_SUCCESS;
}

static urma_status_t resend_wr_from_node(bjetty_ctx_t *bjetty_ctx, wr_buf_node_t *node,
    int send_idx, int target_idx, urma_jfs_wr_t **bad_wr)
{
    urma_status_t ret = URMA_SUCCESS;
    urma_jfs_wr_t *send_wr = node->jfs_wr;
    wr_buf_extra_value_t *value = &node->value;

    switch (send_wr->opcode) {
        case URMA_OPC_SEND:
        case URMA_OPC_SEND_IMM:
        case URMA_OPC_SEND_INVALIDATE:
            ret = set_send_wr_ptseg_ptjetty(send_wr, value->vtjetty, send_idx, target_idx);
            break;
        case URMA_OPC_WRITE:
        case URMA_OPC_WRITE_IMM:
        case URMA_OPC_WRITE_NOTIFY:
        case URMA_OPC_READ:
            ret = set_write_wr_ptseg_ptjetty(send_wr, value->vtjetty, send_idx, target_idx);
            break;
        case URMA_OPC_CAS:
            ret = set_cas_wr_ptseg_pjetty(send_wr, value->vtjetty, send_idx, target_idx);
            break;
        case URMA_OPC_FADD:
            ret = set_fadd_wr_ptseg_pjetty(send_wr, value->vtjetty, send_idx, target_idx);
            break;
        default:
            URMA_LOG_ERR("Unsupported send opcode\n");
            return URMA_FAIL;
    }
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to set ptseg_ptjetty\n");
        return ret;
    }
    value->send_idx = send_idx;
    value->target_idx = target_idx;
    /* post send wr */
    ret = comp_post_send(bjetty_ctx, send_idx, send_wr, bad_wr);
    if (ret != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to post send in resend_wr_from_node, ret %d", ret);
        return ret;
    }
    /* We already have the node stored in jfs wr, so we don't need to store it again */
    return URMA_SUCCESS;
}

static int handle_target_fail(bjetty_ctx_t *bjetty_ctx, uint32_t origin_send_idx, uint32_t send_wr_id)
{
    urma_jfs_wr_t *bad_wr = NULL;
    wr_buf_node_t *node;
    int send_idx = 0;
    int target_idx = 0;
    bdp_v_conn_t *v_conn = NULL;
    int ret = 0;
    node = jfs_wr_buf_get_node(bjetty_ctx->jfs_bufs[origin_send_idx], send_wr_id);
    if (!node) {
        /* Some error may cause receives a CR but we don't have the cache */
        /* Such as we receive a duplicate data CR, which has been ACKed before */
        URMA_LOG_DEBUG("Duplicate send CR, wr_id %u in handle_target_fail.\n", send_wr_id);
        return CR_HANDLER_ERR_AND_COPY;
    }
    v_conn = (bdp_v_conn_t *)node->value.v_conn;
    v_conn->target_valid[node->value.target_idx] = false;
    /* change target */
    ret = schedule_send_target_idx_default(bjetty_ctx, v_conn, bjetty_ctx->dev_num, v_conn->target_dev_num,
        node->jfs_wr->opcode, node->value.trans_mode, &send_idx, &target_idx);
    /* resend self to other dev */
    ret = resend_wr_from_node(bjetty_ctx, node, send_idx, target_idx, &bad_wr);
    if (ret != URMA_SUCCESS) {
        return CR_HANDLER_ERR_AND_COPY;
    } else {
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
}
/**
 * Determine whether an opcode in a CR is of the send type, which will be used in recovering cr->completion_len.
 */
static inline bool is_cr_type_send(urma_cr_t *cr)
{
    /* All opcodes other than this are related to opcode SEND. */
    return cr->opcode != URMA_CR_OPC_WRITE_WITH_IMM;
}
/**
 * Remove header len from completion_len if this CR using header for failover handling
 */
static inline void recover_cr_completion_len(urma_cr_t *cr)
{
    /* recover completion len */
    if (is_cr_type_send(cr)) {
        /* If cr->completion_len is 0, we should not perform the conversion. */
        if (cr->completion_len >= sizeof(bjetty_hdr_t)) {
            cr->completion_len -= sizeof(bjetty_hdr_t);
        }
    }
}
/**
 * Perform the recovery operation for certain fields in the CR uniformly within the handle_send/handle_recv functions.
 * Subsequent updates may enhance the recovery capabilities for other fields in CR.
 */
static void restore_user_cr(urma_cr_t *cr, uint64_t original_user_ctx)
{
    /* Restore the replaced value */
    cr->user_ctx = original_user_ctx;
    /* recover completion len */
    recover_cr_completion_len(cr);
}

/**
 * @return 0: Success, Do copy CR
 * @return 1: Success, Do Not copy CR
 * @return <0: Error,  Do copy CR
 * @return >1: Error, and Do Not copy CR
 */
static bondp_cr_handler_ret_t handle_send(bjetty_ctx_t *bjetty_ctx, urma_cr_t *cr,
    uint32_t send_idx, uint32_t send_wr_id)
{
    urma_jfs_wr_t *bad_wr = NULL;
    wr_buf_node_t *node;
    int migrate_idx = 0;
    bdp_v_conn_t *v_conn = NULL;
    int ret = 0;
    uint64_t original_user_ctx;
    if (bjetty_ctx->bdp_comp->comp_type != BONDP_COMP_JETTY && bjetty_ctx->bdp_comp->comp_type != BONDP_COMP_JFS) {
        URMA_LOG_ERR("Invalid bdp_comp type: %d\n", bjetty_ctx->bdp_comp->comp_type);
        return CR_HANDLER_ERR_AND_COPY;
    }
    /* Device fail */
    if (is_all_pjetty_fail(bjetty_ctx)) {
        URMA_LOG_DEBUG("All pjetty fail in handle_send\n");
        return CR_HANDLER_ERR_AND_COPY;
    }
    if (is_target_device_error(cr->status)) {
        /* target error and change target */
        return handle_target_fail(bjetty_ctx, send_idx, send_wr_id);
    }
    /* Do migration */
    if (is_local_device_error(bjetty_ctx, send_idx)) {
        /*
        Do migration when the current jetty fail and at least one jetty is valid.
        Migrate all WRs from the current jetty to the next valid jetty
        ! Migration may fail, but considering it transparent to user, so we return 1 to ignore CR
        */
        if (is_in_matrix_server(bjetty_ctx->bond_ctx)) {
            migrate_idx = (send_idx + 1) % PRIMARY_EID_NUM;
            if (!bjetty_ctx->pjettys_valid[migrate_idx]) {
                migrate_idx = -1;
            }
        } else {
            migrate_idx = find_next_valid_jetty_idx(bjetty_ctx->pjettys_valid, bjetty_ctx->dev_num, send_idx);
        }
        ret = resend_error_device(bjetty_ctx, send_idx, migrate_idx, &bad_wr);
        URMA_LOG_DEBUG("Migrate send from %d to %d, ret %d\n", send_idx, migrate_idx, ret);
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
    /*
    Do normal process
    Check if the data is in the buffer
    If not, user should not have sent this data
    Return and don't copy CR
    */
    node = jfs_wr_buf_get_node(bjetty_ctx->jfs_bufs[send_idx], send_wr_id);
    if (!node) {
        /* Some error may cause receives a CR but we don't have the cache */
        /* Such as we receive a duplicate data CR, which has been ACKed before */
        URMA_LOG_DEBUG("Duplicate send CR, wr_id %u\n", send_wr_id);
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
    /* Handle v_conn slide window */
    v_conn = (bdp_v_conn_t *)node->value.v_conn;
    if (cr->status != URMA_CR_SUCCESS) {
        original_user_ctx = node->value.user_ctx;
        /* Won't fail because we check before */
        (void)jfs_wr_buf_remove_wr(bjetty_ctx->jfs_bufs[send_idx], send_wr_id);
        restore_user_cr(cr, original_user_ctx);
        return CR_HANDLER_SUCCESS_AND_COPY;
    }
    /* Sender use send_wr_id to indicate the order of send, node->key is send_wr_id */
    (void)bdp_slide_wnd_add(&v_conn->send_wnd, send_wr_id);
    /* Send SO from queue */
    if (send_so_from_snd_queue(bjetty_ctx, v_conn) != URMA_SUCCESS) {
        URMA_LOG_ERR("Failed to send stored SO of send_wr_id %u\n", send_wr_id);
        /* We can still poll for NO, so don't return error */
    }
    /* If this jfs wr doesn't ask for cqe, we simply remove it from buffer */
    if (!node->value.flag.bs.complete_enable) {
        (void)jfs_wr_buf_remove_wr(bjetty_ctx->jfs_bufs[send_idx], send_wr_id);
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
    original_user_ctx = node->value.user_ctx;
    /* Won't fail because we check before */
    (void)jfs_wr_buf_remove_wr(bjetty_ctx->jfs_bufs[send_idx], send_wr_id);
    restore_user_cr(cr, original_user_ctx);
    return CR_HANDLER_SUCCESS_AND_COPY;
}

/** Callback function to migrate JFR WR buffer from a device in error to target device
 * The callback function is called on every wr_buf_node_t in the wr_buf
 * @return 0: Success
 * @return <0: Error
 * @return >0: Skip when the target WR buffer is full
 */
static int rearm_wr_in_error_device_buf(wr_buf_node_t *node, void *args)
{
    struct rearm_args *ra = (struct rearm_args *)args;
    bjetty_ctx_t *bjetty_ctx = ra->bjetty_ctx;
    int migrate_idx = ra->migrate_idx;
    urma_jfr_wr_t **bad_wr = ra->bad_wr;
    int ret = 0;

    if (!wr_buf_try_add(bjetty_ctx->jfr_bufs[migrate_idx], node->key)) {
        /* skip if we can't add the WR */
        ra->skip_count++;
        URMA_LOG_DEBUG("Skip in rearm_wr_in_error_device_buf\n");
        return CALLBACK_SKIP;
    }
    ret = comp_post_recv(bjetty_ctx, migrate_idx, node->wr, bad_wr);
    if (ret) {
        /*
        When we fail to post recv, the following post_recv operation will probably fail
        Therefore we just directly exit the process
        !If the WR always fail to post recv, we may need to construct CR by ourselves
        Use negative value because urma_status_t could be 1
        which conflicts with our error code
        */
        ra->ret = -ret;
        URMA_LOG_DEBUG("Failed to rearm wr in migration\n");
        return -ret;
    }
    /* This won't fail because of wr_buf_try_add */
    (void)jfr_wr_buf_add_wr(bjetty_ctx->jfr_bufs[migrate_idx], node->key, node->wr, &node->value);
    return CALLBACK_SUCCESS;
}

/** Rearm all WRs in a failed jetty to a valid one
 * Any error occurs in the migration process will interrupt the whole procedure, until the next call
 * Repeat interruptions may cause the migration never succeed to be resent
 * @return 0: Rearm succeed, all the WRs are rearmed and stored in another jetty's wr_buf
 * @return <0: Error occurs, error code is the opposite of urma_status_t in urma_post_jetty_recv_wr
 * @return >0: Rearm partially succeed. Return value is the number of WRs which are not rearmed.
 */
int rearm_error_device(bjetty_ctx_t *bjetty_ctx, int err_idx, int migrate_idx, urma_jfr_wr_t **bad_wr)
{
    if (wr_buf_count(bjetty_ctx->jfr_bufs[err_idx]) == 0) {
        return 0;
    }
    struct rearm_args args = {
        .bjetty_ctx = bjetty_ctx,
        .migrate_idx = migrate_idx,
        .bad_wr = bad_wr,
        .skip_count = 0,
        .ret = 0,
    };
    wr_buf_traverse_and_remove(bjetty_ctx->jfr_bufs[err_idx], rearm_wr_in_error_device_buf, &args);
    return args.ret;
}

uint32_t parse_hdr(uint64_t start_addr, uint32_t ctx, bjetty_hdr_t *hdr)
{
    uintptr_t hdr_addr = get_hdr_addr(ctx, start_addr);
    *hdr = *((bjetty_hdr_t *)hdr_addr);
    return ((bjetty_hdr_t *)hdr_addr)->msn;
}

uint32_t parse_imm_data(uint64_t imm_data, bjetty_hdr_t *hdr)
{
    hdr->is_so = (imm_data >> WRITE_IMM_IS_SO_SHIFT) & 1;
    hdr->msn = (imm_data >> WRITE_IMM_USER_BITS) & (BONDP_MAX_BITMAP_SIZE - 1);
    return hdr->msn;
}

urma_status_t rearm_single_wr(bjetty_ctx_t *bjetty_ctx, int recv_idx, uint32_t id, urma_jfr_wr_t **bad_wr)
{
    urma_jfr_wr_t *wr = jfr_wr_buf_get_wr(bjetty_ctx->jfr_bufs[recv_idx], id);
    if (wr == NULL) {
        return URMA_FAIL;
    }
    return comp_post_recv(bjetty_ctx, recv_idx, wr, bad_wr);
}

static inline bdp_r_p2v_jetty_id_type_t get_remote_id_type_by_cr(urma_cr_t *cr)
{
    return cr->flag.bs.jetty ? REMOTE_JETTY : REMOTE_JFR;
}

/**
 * @return 0: Success, Do copy CR
 * @return 1: Success, Do Not copy CR
 * @return <0: Error,  Do copy CR
 * @return >1: Error, and Do Not copy CR
 */
static bondp_cr_handler_ret_t handle_recv(bjetty_ctx_t *bjetty_ctx, urma_cr_t *cr, int recv_idx, uint32_t recv_wr_id,
    bdp_v_conn_t **v_conn_out)
{
    urma_jfr_wr_t *bad_wr = NULL;
    int ret = 0;
    uint64_t original_user_ctx = 0;
    uint32_t msn = 0;
    int migrate_idx = 0;
    bdp_v_conn_t *v_conn = NULL;
    bjetty_hdr_t hdr = {0};

    if (bjetty_ctx->bdp_comp->comp_type != BONDP_COMP_JETTY && bjetty_ctx->bdp_comp->comp_type != BONDP_COMP_JFR) {
        URMA_LOG_ERR("Invalid bdp_comp type: %d\n", bjetty_ctx->bdp_comp->comp_type);
        return CR_HANDLER_ERR_AND_COPY;
    }
    /* Device fail */
    if (is_all_pjetty_fail(bjetty_ctx)) {
        URMA_LOG_DEBUG("All pjetty fail in handle_recv");
        return CR_HANDLER_ERR_AND_COPY;
    }
    /* Do migration */
    if (!bjetty_ctx->pjettys_valid[recv_idx]) {
        /*
        Do migration when the current jetty fail and at least one jetty is valid.
        Migrate all WRs from the current jetty to the next valid jetty
        ! Migration may fail, but considering it transparent to user, so we return 1 to ignore CR
        */
        migrate_idx = find_next_valid_jetty_idx(bjetty_ctx->pjettys_valid, bjetty_ctx->dev_num, recv_idx);
        ret = rearm_error_device(bjetty_ctx, recv_idx, migrate_idx, &bad_wr);
        URMA_LOG_DEBUG("Migrate recv from %d to %d, ret: %d\n", recv_idx, migrate_idx, ret);
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
    ret = jfr_wr_buf_get_user_ctx(bjetty_ctx->jfr_bufs[recv_idx], recv_wr_id, &original_user_ctx);
    if (ret) {
        /*
        This packet has been ACKed
        Return directly
        */
        URMA_LOG_DEBUG("Failed to get user_ctx in jfr_wr_buf of recv_wr_id %u, skip\n", recv_wr_id);
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }

    urma_jetty_id_t target_jetty_id = {0};
    ret = bdp_r_p2v_jetty_id_table_lookup(
        &bjetty_ctx->bond_ctx->remote_p2v_jetty_id_table,
        &cr->remote_id, get_remote_id_type_by_cr(cr), &target_jetty_id
    );
    if (ret != 0) {
        URMA_LOG_ERR("Failed to get target jetty id " EID_FMT " %u %u.\n",
            EID_ARGS(cr->remote_id.eid), cr->remote_id.id, cr->remote_id.uasid);
        (void)jfr_wr_buf_remove_wr(bjetty_ctx->jfr_bufs[recv_idx], recv_wr_id);
        restore_user_cr(cr, original_user_ctx);
        return CR_HANDLER_ERR_AND_COPY;
    }
    /* Do de-duplicating */
    if (cr->opcode == URMA_CR_OPC_WRITE_WITH_IMM) {
        msn = parse_imm_data(cr->imm_data, &hdr);
        cr->imm_data &= ((uint64_t)1 << WRITE_IMM_USER_BITS) - 1;
    } else {
        msn = parse_hdr((uint64_t)bjetty_ctx->hdr_recv_buf, recv_wr_id, &hdr);
    }
    v_conn = bdp_v_conn_table_lookup(&bjetty_ctx->v_conn_table, &target_jetty_id);
    if (!v_conn) {
        if (bdp_v_conn_table_add_on_recv(&bjetty_ctx->v_conn_table, &target_jetty_id, &v_conn)) {
            /* get_comp_urma_jetty_id will return a non-null value,
               because we check bjetty_ctx->bdp_comp type at the entrance of this function. */
            urma_jetty_id_t *jfr_jetty_id = get_comp_urma_jetty_id(bjetty_ctx->bdp_comp);
            URMA_LOG_ERR("Failed to create vconn for ( "EID_FMT" %d, "EID_FMT" %d)",
                EID_ARGS(jfr_jetty_id->eid), jfr_jetty_id->id,
                EID_ARGS(target_jetty_id.eid), target_jetty_id.id
            );
            (void)jfr_wr_buf_remove_wr(bjetty_ctx->jfr_bufs[recv_idx], recv_wr_id);
            restore_user_cr(cr, original_user_ctx);
            return CR_HANDLER_ERR_AND_COPY;
        }
    }
    if (!bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn) || bdp_slide_wnd_has(&v_conn->recv_wnd, msn)) {
        ret = rearm_single_wr(bjetty_ctx, recv_idx, recv_wr_id, &bad_wr);
        URMA_LOG_DEBUG("Rearm recv WR due to: outside of window: %d or duplicate %d\n",
            !bdp_slide_wnd_seq_in_window(&v_conn->recv_wnd, msn),
            bdp_slide_wnd_has(&v_conn->recv_wnd, msn));
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
    if (hdr.is_so && v_conn->recv_wnd.head != msn) {
        /* cache so cr */
        so_cr_queue_data_t cr_data = {
            .msn = msn,
            .cr = *cr,
        };
        cr_data.cr.user_ctx = original_user_ctx;
        bdp_v_conn_push_recv_so_cr(v_conn, &cr_data);
        (void)jfr_wr_buf_remove_wr(bjetty_ctx->jfr_bufs[recv_idx], recv_wr_id);
        *v_conn_out = v_conn;
        URMA_LOG_DEBUG("Store jfr SO CR with recv_wr_id %u, msn %u\n", recv_wr_id, msn);
        return CR_HANDLER_SUCCESS_AND_SKIP;
    }
    (void)bdp_slide_wnd_add(&v_conn->recv_wnd, msn);
    /*
    We assure this entry exists by using jfs_wr_buf_get_user_ctx
    So it won't fail
    */
    (void)jfr_wr_buf_remove_wr(bjetty_ctx->jfr_bufs[recv_idx], recv_wr_id);
    restore_user_cr(cr, original_user_ctx);
    *v_conn_out = v_conn;
    return CR_HANDLER_SUCCESS_AND_COPY;
}
/**
 * After handle_recv, continuously check the SO queue and report all SOs that can be reported.
 * @param cr_output: The cr array used for output, i.e., the `cr` parameter of `bondp_poll_jfc`.
 * @param so_cnt_limit: The maximum length of the array queue for SO.
 * Please note that SO and bondp_poll_pjfc share the cr_output array,
 * so this value should not exceed the `cr_cnt` parameter of `bondp_poll_jfc`.
 * @param total_cnt_limit: The maximum length of `cr_output`, is generally input by the user.
 * @param total_cnt(in/out): The length of the current cr queue, which will increase if an SO is dequeued.
 */
static void handle_recv_so(bdp_v_conn_t *v_conn, urma_cr_t *cr_output, int so_cnt_limit, int total_cnt_limit,
    int *total_cnt)
{
    if (v_conn == NULL) {
        return;
    }
    so_cr_queue_data_t *cr_data;
    int so_cnt = 0;
    while (!bdp_queue_is_empty(&v_conn->recv_strong_order_cr_queue) &&
        so_cnt < so_cnt_limit &&
        *total_cnt < total_cnt_limit) {
        (void)bdp_queue_front(&v_conn->recv_strong_order_cr_queue, (void **)&cr_data);
        if (v_conn->recv_wnd.head != cr_data->msn) {
            break;
        }
        (void)bdp_slide_wnd_add(&v_conn->recv_wnd, cr_data->msn);
        so_cnt++;
        cr_output[(*total_cnt)++] = cr_data->cr;
    }
}

static inline bdp_p_vjetty_type_t get_p_vjetty_type_by_cr(urma_cr_t *cr)
{
    if (cr->flag.bs.jetty) {
        return JETTY;
    }
    if (cr->flag.bs.s_r == 0) {
        return JFS;
    }
    return JFR;
}
/**
 * Utilize certain fields in CR to get the corresponding bjetty_ctx, thereby executing failover and recovery functions.
 * It may be necessary to modify the implementation of this function in the future.
 * When calling this function, it must be ensured that the user_ctx in this CR is valid.
 * That is to say, this interface cannot be called during URMA_CR_WR_SUSPEND_DONE and URMA_CR_WR_FLUSH_ERR_DONE.
 * When obtaining the `bjetty_ctx`, this function will increment the reference count of its corresponding `bondp_comp`.
 * The caller needs to decrement the reference count when bjetty_ctx is about to go out of scope.
 * @return Return bjetty_ctx on success, return NULL on failure.
 */
static bjetty_ctx_t *get_bjetty_ctx_by_cr(bondp_context_t *bdp_ctx, int dev_idx, urma_cr_t *cr)
{
    urma_jetty_id_t pjetty_id = {
        .eid = bdp_ctx->p_ctxs[dev_idx]->eid,
        .id = cr->local_id,
    };
    pthread_rwlock_rdlock(&bdp_ctx->p_vjetty_id_table.lock);
    bondp_comp_t *comp = bdp_p_vjetty_id_table_lookup_comp_without_lock(&bdp_ctx->p_vjetty_id_table, pjetty_id,
                                                                        get_p_vjetty_type_by_cr(cr));
    if (comp == NULL) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Failed to get comp, local_id: %d\n", pjetty_id.id);
        return NULL;
    }
    if (comp->comp_ctx == NULL) {
        pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
        URMA_LOG_ERR("Null bjetty_ctx in bdp_comp\n");
        return NULL;
    }
    atomic_fetch_add(&comp->use_cnt.atomic_cnt, 1);
    pthread_rwlock_unlock(&bdp_ctx->p_vjetty_id_table.lock);
    return (bjetty_ctx_t *)comp->comp_ctx;
}
/**
 * After calling the `get_bjetty_xxx` function, it is necessary to call this function to decrement the reference count.
 * The encapsulation of this function is primarily aimed at making the src/urma easier to understand.
 */
static inline void put_bjetty_ctx(bjetty_ctx_t *bjetty_ctx)
{
    if (bjetty_ctx == NULL) {
        return;
    }
    atomic_fetch_sub(&bjetty_ctx->bdp_comp->use_cnt.atomic_cnt, 1);
}
/**
 * When the cr status is URMA_CR_WR_SUSPEND_DONE or URMA_CR_WR_FLUSH_ERR_DONE,
 * it indicates that the CR is a fake one constructed by hardware.
 * At this time, the `urma_ctx` field in CR is invalid and most likely 0.
 */
static inline bool is_cr_user_ctx_valid(urma_cr_t *cr)
{
    return !(cr->status == URMA_CR_WR_SUSPEND_DONE || cr->status == URMA_CR_WR_FLUSH_ERR_DONE);
}
/**
 * Based on the cr read from the device with the index dev_id,
 * determine whether the device is experiencing an issue at this time.
 * When calling this function, it must be ensured that the user_ctx in this CR is valid.
 * That is to say, this interface cannot be called during URMA_CR_WR_SUSPEND_DONE and URMA_CR_WR_FLUSH_ERR_DONE.
 */
static urma_status_t update_device_valid_state(bondp_context_t *bdp_ctx, int dev_id, int cqe_cnt, urma_cr_t *cr_buf)
{
    if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
        return URMA_SUCCESS;
    }
    for (int cr_id = 0; cr_id < cqe_cnt; ++cr_id) {
        if (!is_cr_user_ctx_valid(&cr_buf[cr_id])) {
            continue;
        }
        bjetty_ctx_t *bjetty_ctx = get_bjetty_ctx_by_cr(bdp_ctx, dev_id, &cr_buf[cr_id]);
        if (bjetty_ctx == NULL) {
            URMA_LOG_ERR("Failed to get bjetty_ctx\n");
            return URMA_FAIL;
        }
        if (bjetty_ctx->pjettys_valid[dev_id] && is_device_error(cr_buf[cr_id].status)) {
            bjetty_ctx->pjettys_valid[dev_id] = false;
            put_bjetty_ctx(bjetty_ctx);
            /* If a problem arises, then the equipment must already have an issue,
               and there is no need to continue with subsequent CR checks. */
            return URMA_SUCCESS;
        }
        put_bjetty_ctx(bjetty_ctx);
    }
    return URMA_SUCCESS;
}
/**
 * Poll pjfc in sequence until cr_cnt is exhausted or all pjfc have no CRs available for acquisition.
 * The traversal order will start from the `last_poll_idx` stored in `bdp_jfc->comp_ctx`,
 * which is the index of the last poll that resulted in a non-zero value (otherwise, it remains unchanged).
 * Each iteration starts from the next idx of the last obtainable CR from pjfc to prevent pjfc from starving.
 * @return: The total number of all CQEs obtained from all pjfcs,
 * where negative values represent errors and 0 indicates no CQEs were obtained.
 */
static int bondp_poll_pjfc(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jfc, int cr_cnt,
    int cqe_cnt[], urma_cr_t (*bdp_cr_buf)[URMA_UBAGG_MAX_CR_CNT_PER_DEV])
{
    int total_cqe_cnt = 0;
    int remaining_poll = cr_cnt;
    uintptr_t last_poll_idx = (uintptr_t)bdp_jfc->comp_ctx;
    /* Starting from the next idx of the last obtainable CR from pjfc, prevent pjfc from starving. */
    for (int i = 1; i <= bdp_jfc->dev_num; ++i) {
        int dev_id = (last_poll_idx + i) % bdp_jfc->dev_num;
        if (remaining_poll <= 0) {
            break;
        }
        if (bdp_jfc->p_jfc[dev_id] == NULL) {
            continue;
        }
        int current_cr_cnt = remaining_poll > URMA_UBAGG_MAX_CR_CNT_PER_DEV ?
            URMA_UBAGG_MAX_CR_CNT_PER_DEV : remaining_poll;
        cqe_cnt[dev_id] = urma_poll_jfc(bdp_jfc->p_jfc[dev_id], current_cr_cnt, bdp_cr_buf[dev_id]);
        if (cqe_cnt[dev_id] < 0) {
            URMA_LOG_ERR("Failed to poll pjfc[%d]: %d\n", dev_id, cqe_cnt[dev_id]);
            return cqe_cnt[dev_id];
        }
        if (cqe_cnt[dev_id] == 0) {
            continue;
        }
        total_cqe_cnt += cqe_cnt[dev_id];
        remaining_poll -= cqe_cnt[dev_id];
        bdp_jfc->comp_ctx = (void *)(uintptr_t)dev_id;
        urma_status_t ret = update_device_valid_state(bdp_ctx, dev_id, cqe_cnt[dev_id], bdp_cr_buf[dev_id]);
        if (ret) {
            URMA_LOG_ERR("Failed to update deivce valid state: %d\n", ret);
            return -ret;
        }
    }
    return total_cqe_cnt;
}
/**
 * Convert the local_id field of a CR from pjetty.id to vjetty.id if possible.
 * @return: If conversion is possible, perform the conversion and return 0; otherwise, do not replace and return -1.
 */
static int restore_cr_local_id(bondp_context_t *bdp_ctx,  int dev_idx, urma_cr_t *cr)
{
    uint32_t vjetty_id;
    urma_jetty_id_t pjetty_id = {
        .eid = bdp_ctx->p_ctxs[dev_idx]->eid,
        .id = cr->local_id,
    };
    int ret = bdp_p_vjetty_id_table_lookup(&bdp_ctx->p_vjetty_id_table, pjetty_id, get_p_vjetty_type_by_cr(cr),
        &vjetty_id);
    if (ret) {
        URMA_LOG_ERR("Failed to get vjetty.id of local_id: %u, ret: %d\n", pjetty_id.id, ret);
        return -1;
    }
    cr->local_id = vjetty_id;
    return 0;
}
/**
 * Convert the remote_id field of a CR from pjetty_id to vjetty_id if possible.
 * @return: If conversion is possible, perform the conversion and return 0; otherwise, do not replace and return -1.
 */
static int restore_cr_remote_id(bondp_context_t *bdp_ctx, urma_cr_t *cr)
{
    urma_jetty_id_t jetty_id = {0};
    int ret = bdp_r_p2v_jetty_id_table_lookup(&bdp_ctx->remote_p2v_jetty_id_table,
        &cr->remote_id, get_remote_id_type_by_cr(cr), &jetty_id);
    if (ret != 0) {
        return -1;
    }
    cr->remote_id = jetty_id;
    return 0;
}
/**
 * In scenarios where the remote_id cannot be restored,
 * the topo_map can be used to restore only the remote_id.eid field,
 * while other fields cannot be restored and will be set to 0.
 */
static void restore_cr_remote_id_fallback(bondp_context_t *bdp_ctx, urma_cr_t *cr)
{
    urma_eid_t eid_output = {0};
    int ret = get_bonding_eid_by_target_eid(bdp_ctx->topo_map, &cr->remote_id.eid, &eid_output);
    if (ret != 0) {
        // Set EID to all zero in error case
        cr->remote_id.eid.in6.interface_id = 0;
        cr->remote_id.eid.in6.subnet_prefix = 0;
    } else {
        cr->remote_id.eid = eid_output;
    }
    cr->remote_id.uasid = 0;
    cr->remote_id.id = 0;
}

/**
 * @param dev_idx: The index of pjfc used when polling jfc.
 * In fact, what we need is the index of pjetty relative to vjetty, but we cannot obtain it when calling this function.
 * Considering that the binding relationship between pjfc and pjetty keeps their indices consistent,
 * we use the index of pjfc as the index for pjetty.
 */
static int bondp_handle_cr_no_store(bondp_context_t *bdp_ctx, int dev_idx, urma_cr_t *cr, urma_cr_t *cr_output_array,
                                    int *total_cnt)
{
    // Special handling is applied to the CRs constructed by the hardware of SUSPEND_DONE and FLUSH_ERROR_DONE.
    if (!is_cr_user_ctx_valid(cr)) {
        // find out the bjetty_ctx
        bjetty_ctx_t *bjetty_ctx = get_bjetty_ctx_by_cr(bdp_ctx, dev_idx, cr);
        if (bjetty_ctx == NULL) {
            return -1;
        }
        uint8_t target_state_bit = 0;
        if (cr->status == URMA_CR_WR_SUSPEND_DONE) {
            target_state_bit = PJETTY_SUSPEND_DONE;
        } else if (cr->status == URMA_CR_WR_FLUSH_ERR_DONE) {
            target_state_bit = PJETTY_FLUSH_ERROR_DONE;
        } else {
            URMA_LOG_ERR("Invalid cr error status: %d\n", cr->status);
            put_bjetty_ctx(bjetty_ctx);
            return -1;
        }
        bjetty_ctx->pjettys_error_done[dev_idx] |= target_state_bit;
        bool all_reported = true;
        // pjetty_idx
        for (int idx = 0; idx < URMA_UBAGG_DEV_MAX_NUM; idx++) {
            if (bjetty_ctx->pjettys[idx] == NULL) {
                continue;
            }
            if ((bjetty_ctx->pjettys_error_done[idx] & target_state_bit) == 0) {
                all_reported = false;
                break;
            }
        }
        if (all_reported) {
            // restore local_id, method #2 through bjetty_ctx
            cr->local_id = get_comp_urma_jetty_id(bjetty_ctx->bdp_comp)->id;
            // restore remote_id
            if (restore_cr_remote_id(bdp_ctx, cr)) {
                restore_cr_remote_id_fallback(bdp_ctx, cr);
            }
            // report
            cr_output_array[(*total_cnt)++] = *cr;
        }
        put_bjetty_ctx(bjetty_ctx);
        return 0;
    }
    if (restore_cr_local_id(bdp_ctx, dev_idx, cr)) {
        cr->local_id = 0; /* Replace with invalid value under exceptional circumstances */
    }
    /* Perform remote_id restoration on both the sending and receiving ends.
    Although the remote_id field on the sending end cannot be guaranteed to be correct,
    according to the description of urma_cr_t.
    However, it has been found in actual testing that this field is generally valid, hence this approach is taken.
    */
    if (restore_cr_remote_id(bdp_ctx, cr)) {
        restore_cr_remote_id_fallback(bdp_ctx, cr);
    }
    /* When calling bondp_poll_pjfc,
       it can be ensured that the total number of processed CRs is less than the `cr_cnt` parameter passed by the user.
       Therefore, unless the user passes an array of incorrect size, there will be no array out-of-bounds issue. */
    cr_output_array[(*total_cnt)++] = *cr;
    return 0;
}

static inline bool is_cr_handler_ret_skip(bondp_cr_handler_ret_t ret)
{
    return ret == CR_HANDLER_SUCCESS_AND_SKIP || ret == CR_HANDLER_ERR_AND_SKIP;
}

static int bondp_handle_cr_with_store(bondp_context_t *bdp_ctx, int dev_idx, int total_cqe_cnt, int cr_cnt_limit,
                                      urma_cr_t *cr, urma_cr_t *cr_output_array, int *total_cnt)
{
    /* Handle CR with status URMA_CR_WR_SUSPEND_DONE or URMA_CR_WR_FLUSH_ERR_DONE */
    if (!is_cr_user_ctx_valid(cr)) {
        /* For these CRs where the user_ctx does not exist, simply restore the necessary values and then skip them. */
        if (restore_cr_local_id(bdp_ctx, dev_idx, cr)) {
            cr->local_id = 0; /* Replace with invalid value under exceptional circumstances */
        }
        /*
        Always attempt to restore the remote_id field, as it has been found to be correct in many cases during testing.
        Even if it is incorrect, we can invalidate it using the fallback function.
        */
        if (restore_cr_remote_id(bdp_ctx, cr)) {
            restore_cr_remote_id_fallback(bdp_ctx, cr);
        }
        /* recover completion len */
        recover_cr_completion_len(cr);
        cr_output_array[(*total_cnt)++] = *cr;
        return 0;
    }
    bjetty_ctx_t *bjetty_ctx = get_bjetty_ctx_by_cr(bdp_ctx, dev_idx, cr);
    if (bjetty_ctx == NULL) {
        return -1;
    }
    uint32_t wr_id = 0;
    uint16_t _bjetty_id = 0;
    uint16_t pjetty_id = 0;
    decode_wr_user_ctx(cr->user_ctx, &wr_id, &_bjetty_id, &pjetty_id);
    bondp_cr_handler_ret_t ret;
    if (is_recv_cr(cr)) {
        /* handle recv */
        bdp_v_conn_t *v_conn = NULL;
        ret = handle_recv(bjetty_ctx, cr, pjetty_id, wr_id, &v_conn);
        /* Since recv_so is cached in the queue, although it can ensure that total_cqe_cnt <= cr_cnt_limit,
            this function will increase additional array space requirements.
            The current implementation method results in a situation where,
            when cr_cnt is not sufficiently large and the user still has an SO in the cache,
            the user cannot retrieve the cached SO data when no messages are received from a certain Jetty.
            This issue requires re-implementing the logic of handle_recv_so to resolve. */
        handle_recv_so(v_conn, cr, cr_cnt_limit - total_cqe_cnt, cr_cnt_limit, total_cnt);
    } else {
        /* handle send */
        ret = handle_send(bjetty_ctx, cr, pjetty_id, wr_id);
    }
    if (!is_cr_handler_ret_skip(ret)) {
        /* restore cr local id with bjetty_ctx */
        /* non-null return value because bjetty_ctx->bdp_comp type is checked in `get_bjetty_ctx_by_cr` */
        cr->local_id = get_comp_urma_jetty_id(bjetty_ctx->bdp_comp)->id;
        /*
        Perform remote_id restoration on both the sending and receiving ends.
        Although the remote_id field on the sending end cannot be guaranteed to be correct,
        according to the description of urma_cr_t.
        However, it has been found in actual testing that this field is generally valid, hence this approach is taken.
        */
        if (restore_cr_remote_id(bdp_ctx, cr)) {
            restore_cr_remote_id_fallback(bdp_ctx, cr);
        }
        /* When calling bondp_poll_pjfc,
        it can be ensured that the total number of processed CRs is less than the `cr_cnt` parameter passed by the user.
        Therefore, unless the user passes an array of incorrect size, there will be no array out-of-bounds issue. */
        cr_output_array[(*total_cnt)++] = *cr;
    }
    put_bjetty_ctx(bjetty_ctx);
    return ret == CR_HANDLER_ERR_AND_COPY || ret == CR_HANDLER_ERR_AND_SKIP ? -1 : 0;
}

int bondp_poll_jfc(urma_jfc_t *jfc, int cr_cnt, urma_cr_t *cr_output_array)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jfc->urma_ctx, bondp_context_t, v_ctx);
    bondp_comp_t *bdp_jfc = CONTAINER_OF_FIELD(jfc, bondp_comp_t, v_jfc);
    urma_cr_t bdp_cr_buf[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_MAX_CR_CNT_PER_DEV] = {0};
    int cqe_cnt[URMA_UBAGG_DEV_MAX_NUM] = {0};

    if (!is_valid_bondp_comp(bdp_jfc)) {
        return -EINVAL;
    }

    /* Get all CR from pjfc and check device status */
    int total_cqe_cnt = bondp_poll_pjfc(bdp_ctx, bdp_jfc, cr_cnt, cqe_cnt, bdp_cr_buf);
    if (total_cqe_cnt <= 0) {
        return total_cqe_cnt;
    }
    /* Handle each CR */
    int total_cnt = 0;
    for (int dev_id = 0; dev_id< bdp_jfc->dev_num; ++dev_id) {
        if (bdp_jfc->p_jfc[dev_id] == NULL) {
            continue;
        }
        for (int cr_id = 0; cr_id < cqe_cnt[dev_id]; ++cr_id) {
            int ret = 0;
            if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
                ret = bondp_handle_cr_no_store(bdp_ctx, dev_id, &bdp_cr_buf[dev_id][cr_id],
                    cr_output_array, &total_cnt);
            } else {
                ret = bondp_handle_cr_with_store(bdp_ctx, dev_id, total_cqe_cnt, cr_cnt,
                    &bdp_cr_buf[dev_id][cr_id], cr_output_array, &total_cnt);
            }
            if (ret < 0) {
                return ret;
            }
        }
    }
    return total_cnt;
}

uint32_t bondp_get_jfs_msn(urma_jfs_wr_t *wr, uint32_t *msn)
{
    /* Only set msn for ops which need RQE */
    if (wr->opcode != URMA_OPC_WRITE && wr->opcode != URMA_OPC_READ) {
        return *msn;
    }
    return -1; /* valid msn < 2^24, so -1 indicates invalid */
}

urma_status_t bondp_post_jfs_wr(urma_jfs_t *jfs, urma_jfs_wr_t *wr, urma_jfs_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jfs = CONTAINER_OF_FIELD(jfs, bondp_comp_t, v_jfs);
    bondp_target_jetty_t *bdp_tjetty = CONTAINER_OF_FIELD(wr->tjetty, bondp_target_jetty_t, v_tjetty);
    bjetty_ctx_t *bjetty_ctx = bdp_jfs->comp_ctx;
    urma_status_t ret = URMA_SUCCESS;

    ret = post_send_check_valid(bdp_jfs, bdp_tjetty, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    if (is_single_dev_mode(jfs->urma_ctx)) {
        return bondp_post_send_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        return bondp_post_send_wr_and_store(bjetty_ctx, wr, bad_wr);
    }
}

urma_status_t bondp_post_jfr_wr(urma_jfr_t *jfr, urma_jfr_wr_t *wr, urma_jfr_wr_t **bad_wr)
{
    bondp_comp_t *bdp_jfr = CONTAINER_OF_FIELD(jfr, bondp_comp_t, v_jfr);
    urma_status_t ret = URMA_SUCCESS;
    ret = post_recv_check_valid(bdp_jfr, wr);
    if (ret != URMA_SUCCESS) {
        return ret;
    }
    /* non-null bjetty_ctx value because post_recv_check_valid performed validation. */
    bjetty_ctx_t *bjetty_ctx = bdp_jfr->comp_ctx;
    // workaround, at this point, jfr only support multipath
    bdp_jfr->is_multipath = true;
    if (is_single_dev_mode(jfr->urma_ctx)) {
        return bondp_post_recv_wr_no_store(bjetty_ctx, wr, bad_wr);
    } else {
        return bondp_post_recv_wr_and_store(bjetty_ctx, wr, bad_wr);
    }
}

static int bondp_flush_pjetty(bondp_context_t *bdp_ctx, bondp_comp_t *bdp_jetty, int cr_cnt,
    int flush_cnt[], urma_cr_t (*bdp_cr_buf)[URMA_UBAGG_MAX_CR_CNT_PER_DEV])
{
    int total_flush_cnt = 0;
    int remaining_flush = cr_cnt;

    for (int i = 0; i <= bdp_jetty->dev_num; ++i) {
        if (remaining_flush <= 0) {
            break;
        }
        if (bdp_jetty->p_jetty[i] == NULL) {
            continue;
        }
        int current_cr_cnt = remaining_flush > URMA_UBAGG_MAX_CR_CNT_PER_DEV ?
            URMA_UBAGG_MAX_CR_CNT_PER_DEV : remaining_flush;
        flush_cnt[i] = urma_flush_jetty(bdp_jetty->p_jetty[i], current_cr_cnt, bdp_cr_buf[i]);
        if (flush_cnt[i] < 0) {
            URMA_LOG_ERR("Failed to flush pjetty[%d]: %d\n", i, flush_cnt[i]);
            return flush_cnt[i];
        }
        if (flush_cnt[i] == 0) {
            continue;
        }
        total_flush_cnt += flush_cnt[i];
        remaining_flush -= flush_cnt[i];
    }
    return total_flush_cnt;
}

int bondp_flush_jetty(urma_jetty_t *jetty, int cr_cnt, urma_cr_t *cr_output_array)
{
    bondp_context_t *bdp_ctx = CONTAINER_OF_FIELD(jetty->urma_ctx, bondp_context_t, v_ctx);
    bondp_comp_t *bdp_jetty = CONTAINER_OF_FIELD(jetty, bondp_comp_t, v_jetty);
    urma_cr_t bdp_cr_buf[URMA_UBAGG_DEV_MAX_NUM][URMA_UBAGG_MAX_CR_CNT_PER_DEV] = {0};
    int flush_cnt[URMA_UBAGG_DEV_MAX_NUM] = {0};

    if (!is_valid_bondp_comp(bdp_jetty)) {
        return -EINVAL;
    }

    /* Get all CR from pjetty and check device status */
    int total_flush_cnt = bondp_flush_pjetty(bdp_ctx, bdp_jetty, cr_cnt, flush_cnt, bdp_cr_buf);
    if (total_flush_cnt <= 0) {
        return total_flush_cnt;
    }
    /* Handle each CR */
    int total_cnt = 0;
    for (int dev_id = 0; dev_id < bdp_jetty->dev_num; ++dev_id) {
         if (bdp_jetty->p_jetty[dev_id] == NULL) {
             continue;
         }
         for (int cr_id = 0; cr_id < flush_cnt[dev_id]; ++cr_id) {
             int ret = 0;
             if (is_single_dev_mode(&bdp_ctx->v_ctx)) {
                 ret = bondp_handle_cr_no_store(bdp_ctx, dev_id, &bdp_cr_buf[dev_id][cr_id],
                     cr_output_array, &total_cnt);
             } else {
                 ret = bondp_handle_cr_with_store(bdp_ctx, dev_id, total_flush_cnt, cr_cnt,
                     &bdp_cr_buf[dev_id][cr_id], cr_output_array, &total_cnt);
             }
             if (ret < 0) {
                 return total_cnt;
             }
         }
     }
    return total_cnt;
}
