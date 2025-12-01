/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 * Description: urma cmd tlv parse source file
 * Author: Wang Hang
 * Create: 2024-08-26
 * Note:
 * History: 2024-08-26 create file
 */

#include "ub_util.h"
#include "urma_log.h"

#include "urma_cmd_tlv.h"

static inline void fill_attr(urma_cmd_attr_t *attr, uint16_t type, uint16_t field_size, uint16_t el_num,
                             uint16_t el_size, uintptr_t data)
{
    *attr = (urma_cmd_attr_t){
        .type = type,
        .flag = 0,
        .field_size = field_size,
        .attr_data.bs = {.el_num = el_num, .el_size = el_size},
        .data = data,
    };
}

/**
 * Fill attr with a field, which is a value or an array taken as a whole.
 * @param v Full path of field, e.g. `arg->out.attr.dev_cap.feature`
 */
#define ATTR(attr, type, v) fill_attr(attr, type, sizeof(v), 1, 0, (uintptr_t)(&(v)))

/**
 * Fill attr with a field, which belongs to an array of structs.
 * @param v1 Full path of struct array, e.g. `arg->out.attr.port_attr`
 * @param v2 Path relative to struct in array, e.g. `active_speed`
 */
#define ATTR_ARRAY(attr, type, v1, v2)                                                                                 \
    fill_attr(attr, type, sizeof((v1)->v2), ARRAY_SIZE(v1), sizeof((v1)[0]), (uintptr_t)(&((v1)->v2)))

static int urma_tlv_ioctl(int ioctl_fd, urma_cmd_t cmd, urma_cmd_attr_t *args, uint32_t args_len)
{
    urma_cmd_hdr_t hdr = {
        .command = (uint32_t)cmd,
        .args_len = args_len,
        .args_addr = (uint64_t)args,
    };
    int ret = ioctl(ioctl_fd, URMA_CMD, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("ioctl failed, ret:%d, errno:%d, cmd:%u.\n", ret, errno, hdr.command);
    }
    return ret;
}

int urma_ioctl_create_ctx(int ioctl_fd, urma_cmd_create_ctx_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_CTX_IN_NUM + CREATE_CTX_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_CTX_IN_EID, arg->in.eid);
    ATTR(a++, CREATE_CTX_IN_EID_INDEX, arg->in.eid_index);
    ATTR(a++, CREATE_CTX_IN_UDATA, arg->udata);
    ATTR(a++, CREATE_CTX_OUT_ASYNC_FD, arg->out.async_fd);
    ATTR(a++, CREATE_CTX_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_CTX, attrs, sizeof(attrs));
}

int urma_ioctl_alloc_token_id(int ioctl_fd, urma_cmd_alloc_token_id_t *arg)
{
    urma_cmd_attr_t attrs[ALLOC_TOKEN_ID_IN_NUM + ALLOC_TOKEN_ID_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, ALLOC_TOKEN_ID_IN_UDATA, arg->udata);
    ATTR(a++, ALLOC_TOKEN_ID_IN_FLAG, arg->in.flag);
    ATTR(a++, ALLOC_TOKEN_ID_OUT_TOKEN_ID, arg->out.token_id);
    ATTR(a++, ALLOC_TOKEN_ID_OUT_HANDLE, arg->out.handle);
    ATTR(a++, ALLOC_TOKEN_ID_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_ALLOC_TOKEN_ID, attrs, sizeof(attrs));
}

int urma_ioctl_free_token_id(int ioctl_fd, urma_cmd_free_token_id_t *arg)
{
    urma_cmd_attr_t attrs[FREE_TOKEN_ID_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, FREE_TOKEN_ID_IN_HANDLE, arg->in.handle);
    ATTR(a++, FREE_TOKEN_ID_IN_TOKEN_ID, arg->in.token_id);
    ATTR(a++, FREE_TOKEN_ID_IN_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_FREE_TOKEN_ID, attrs, sizeof(attrs));
}

int urma_ioctl_register_seg(int ioctl_fd, urma_cmd_register_seg_t *arg)
{
    urma_cmd_attr_t attrs[REGISTER_SEG_IN_NUM + REGISTER_SEG_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, REGISTER_SEG_IN_VA, arg->in.va);
    ATTR(a++, REGISTER_SEG_IN_LEN, arg->in.len);
    ATTR(a++, REGISTER_SEG_IN_TOKEN_ID, arg->in.token_id);
    ATTR(a++, REGISTER_SEG_IN_TOKEN_ID_HANDLE, arg->in.token_id_handle);
    ATTR(a++, REGISTER_SEG_IN_TOKEN, arg->in.token);
    ATTR(a++, REGISTER_SEG_IN_FLAG, arg->in.flag);
    ATTR(a++, REGISTER_SEG_IN_UDATA, arg->udata);
    ATTR(a++, REGISTER_SEG_OUT_TOKEN_ID, arg->out.token_id);
    ATTR(a++, REGISTER_SEG_OUT_HANDLE, arg->out.handle);
    ATTR(a++, REGISTER_SEG_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_REGISTER_SEG, attrs, sizeof(attrs));
}

int urma_ioctl_unregister_seg(int ioctl_fd, urma_cmd_unregister_seg_t *arg)
{
    urma_cmd_attr_t attrs[UNREGISTER_SEG_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNREGISTER_SEG_IN_HANDLE, arg->in.handle);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_UNREGISTER_SEG, attrs, sizeof(attrs));
}

int urma_ioctl_import_seg(int ioctl_fd, urma_cmd_import_seg_t *arg)
{
    urma_cmd_attr_t attrs[IMPORT_SEG_IN_NUM + IMPORT_SEG_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, IMPORT_SEG_IN_EID, arg->in.eid);
    ATTR(a++, IMPORT_SEG_IN_VA, arg->in.va);
    ATTR(a++, IMPORT_SEG_IN_LEN, arg->in.len);
    ATTR(a++, IMPORT_SEG_IN_FLAG, arg->in.flag);
    ATTR(a++, IMPORT_SEG_IN_TOKEN, arg->in.token);
    ATTR(a++, IMPORT_SEG_IN_TOKEN_ID, arg->in.token_id);
    ATTR(a++, IMPORT_SEG_IN_MVA, arg->in.mva);
    ATTR(a++, IMPORT_SEG_IN_UDATA, arg->udata);
    ATTR(a++, IMPORT_SEG_OUT_HANDLE, arg->out.handle);
    ATTR(a++, IMPORT_SEG_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_IMPORT_SEG, attrs, sizeof(attrs));
}

int urma_ioctl_unimport_seg(int ioctl_fd, urma_cmd_unimport_seg_t *arg)
{
    urma_cmd_attr_t attrs[UNIMPORT_SEG_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNIMPORT_SEG_IN_HANDLE, arg->in.handle);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_UNIMPORT_SEG, attrs, sizeof(attrs));
}

int urma_ioctl_create_jfs(int ioctl_fd, urma_cmd_create_jfs_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_JFS_IN_NUM + CREATE_JFS_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_JFS_IN_DEPTH, arg->in.depth);
    ATTR(a++, CREATE_JFS_IN_FLAG, arg->in.flag);
    ATTR(a++, CREATE_JFS_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, CREATE_JFS_IN_PRIORITY, arg->in.priority);
    ATTR(a++, CREATE_JFS_IN_MAX_SGE, arg->in.max_sge);
    ATTR(a++, CREATE_JFS_IN_MAX_RSGE, arg->in.max_rsge);
    ATTR(a++, CREATE_JFS_IN_MAX_INLINE_DATA, arg->in.max_inline_data);
    ATTR(a++, CREATE_JFS_IN_RETRY_CNT, arg->in.retry_cnt);
    ATTR(a++, CREATE_JFS_IN_RNR_RETRY, arg->in.rnr_retry);
    ATTR(a++, CREATE_JFS_IN_ERR_TIMEOUT, arg->in.err_timeout);
    ATTR(a++, CREATE_JFS_IN_JFC_ID, arg->in.jfc_id);
    ATTR(a++, CREATE_JFS_IN_JFC_HANDLE, arg->in.jfc_handle);
    ATTR(a++, CREATE_JFS_IN_URMA_JFS, arg->in.urma_jfs);
    ATTR(a++, CREATE_JFS_IN_UDATA, arg->udata);
    ATTR(a++, CREATE_JFS_OUT_ID, arg->out.id);
    ATTR(a++, CREATE_JFS_OUT_DEPTH, arg->out.depth);
    ATTR(a++, CREATE_JFS_OUT_MAX_SGE, arg->out.max_sge);
    ATTR(a++, CREATE_JFS_OUT_MAX_RSGE, arg->out.max_rsge);
    ATTR(a++, CREATE_JFS_OUT_MAX_INLINE_DATA, arg->out.max_inline_data);
    ATTR(a++, CREATE_JFS_OUT_HANDLE, arg->out.handle);
    ATTR(a++, CREATE_JFS_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_JFS, attrs, sizeof(attrs));
}

int urma_ioctl_modify_jfs(int ioctl_fd, urma_cmd_modify_jfs_t *arg)
{
    urma_cmd_attr_t attrs[MODIFY_JFS_IN_NUM + MODIFY_JFS_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, MODIFY_JFS_IN_HANDLE, arg->in.handle);
    ATTR(a++, MODIFY_JFS_IN_MASK, arg->in.mask);
    ATTR(a++, MODIFY_JFS_IN_STATE, arg->in.state);
    ATTR(a++, MODIFY_JFS_IN_UDATA, arg->udata);
    ATTR(a++, MODIFY_JFS_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_MODIFY_JFS, attrs, sizeof(attrs));
}

int urma_ioctl_query_jfs(int ioctl_fd, urma_cmd_query_jfs_t *arg)
{
    urma_cmd_attr_t attrs[QUERY_JFS_IN_NUM + QUERY_JFS_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, QUERY_JFS_IN_HANDLE, arg->in.handle);
    ATTR(a++, QUERY_JFS_OUT_DEPTH, arg->out.depth);
    ATTR(a++, QUERY_JFS_OUT_FLAG, arg->out.flag);
    ATTR(a++, QUERY_JFS_OUT_TRANS_MODE, arg->out.trans_mode);
    ATTR(a++, QUERY_JFS_OUT_PRIORITY, arg->out.priority);
    ATTR(a++, QUERY_JFS_OUT_MAX_SGE, arg->out.max_sge);
    ATTR(a++, QUERY_JFS_OUT_MAX_RSGE, arg->out.max_rsge);
    ATTR(a++, QUERY_JFS_OUT_MAX_INLINE_DATA, arg->out.max_inline_data);
    ATTR(a++, QUERY_JFS_OUT_RETRY_CNT, arg->out.retry_cnt);
    ATTR(a++, QUERY_JFS_OUT_RNR_RETRY, arg->out.rnr_retry);
    ATTR(a++, QUERY_JFS_OUT_ERR_TIMEOUT, arg->out.err_timeout);
    ATTR(a++, QUERY_JFS_OUT_STATE, arg->out.state);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_QUERY_JFS, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jfs(int ioctl_fd, urma_cmd_delete_jfs_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JFS_IN_NUM + DELETE_JFS_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JFS_IN_HANDLE, arg->in.handle);
    ATTR(a++, DELETE_JFS_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JFS, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jfs_batch(int ioctl_fd, urma_cmd_delete_jfs_batch_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JFS_BATCH_IN_NUM + DELETE_JFS_BATCH_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JFS_BATCH_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
    ATTR(a++, DELETE_JFS_BATCH_OUT_BAD_JFS_INDEX, arg->out.bad_jfs_index);
    ATTR(a++, DELETE_JFS_BATCH_IN_JFS_COUNT, arg->in.jfs_num);
    ATTR(a++, DELETE_JFS_BATCH_IN_JFS_PTR, arg->in.jfs_ptr);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JFS_BATCH, attrs, sizeof(attrs));
}

int urma_ioctl_create_jfr(int ioctl_fd, urma_cmd_create_jfr_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_JFR_IN_NUM + CREATE_JFR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_JFR_IN_DEPTH, arg->in.depth);
    ATTR(a++, CREATE_JFR_IN_FLAG, arg->in.flag);
    ATTR(a++, CREATE_JFR_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, CREATE_JFR_IN_MAX_SGE, arg->in.max_sge);
    ATTR(a++, CREATE_JFR_IN_MIN_RNR_TIMER, arg->in.min_rnr_timer);
    ATTR(a++, CREATE_JFR_IN_JFC_ID, arg->in.jfc_id);
    ATTR(a++, CREATE_JFR_IN_JFC_HANDLE, arg->in.jfc_handle);
    ATTR(a++, CREATE_JFR_IN_TOKEN, arg->in.token);
    ATTR(a++, CREATE_JFR_IN_ID, arg->in.id);
    ATTR(a++, CREATE_JFR_IN_URMA_JFR, arg->in.urma_jfr);
    ATTR(a++, CREATE_JFR_IN_UDATA, arg->udata);
    ATTR(a++, CREATE_JFR_OUT_ID, arg->out.id);
    ATTR(a++, CREATE_JFR_OUT_DEPTH, arg->out.depth);
    ATTR(a++, CREATE_JFR_OUT_MAX_SGE, arg->out.max_sge);
    ATTR(a++, CREATE_JFR_OUT_HANDLE, arg->out.handle);
    ATTR(a++, CREATE_JFR_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_JFR, attrs, sizeof(attrs));
}

int urma_ioctl_modify_jfr(int ioctl_fd, urma_cmd_modify_jfr_t *arg)
{
    urma_cmd_attr_t attrs[MODIFY_JFR_IN_NUM + MODIFY_JFR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, MODIFY_JFR_IN_HANDLE, arg->in.handle);
    ATTR(a++, MODIFY_JFR_IN_MASK, arg->in.mask);
    ATTR(a++, MODIFY_JFR_IN_RX_THRESHOLD, arg->in.rx_threshold);
    ATTR(a++, MODIFY_JFR_IN_STATE, arg->in.state);
    ATTR(a++, MODIFY_JFR_IN_UDATA, arg->udata);
    ATTR(a++, MODIFY_JFR_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_MODIFY_JFR, attrs, sizeof(attrs));
}

int urma_ioctl_query_jfr(int ioctl_fd, urma_cmd_query_jfr_t *arg)
{
    urma_cmd_attr_t attrs[QUERY_JFR_IN_NUM + QUERY_JFR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, QUERY_JFR_IN_HANDLE, arg->in.handle);
    ATTR(a++, QUERY_JFR_OUT_DEPTH, arg->out.depth);
    ATTR(a++, QUERY_JFR_OUT_FLAG, arg->out.flag);
    ATTR(a++, QUERY_JFR_OUT_TRANS_MODE, arg->out.trans_mode);
    ATTR(a++, QUERY_JFR_OUT_MAX_SGE, arg->out.max_sge);
    ATTR(a++, QUERY_JFR_OUT_MIN_RNR_TIMER, arg->out.min_rnr_timer);
    ATTR(a++, QUERY_JFR_OUT_TOKEN, arg->out.token);
    ATTR(a++, QUERY_JFR_OUT_ID, arg->out.id);
    ATTR(a++, QUERY_JFR_OUT_RX_THRESHOLD, arg->out.rx_threshold);
    ATTR(a++, QUERY_JFR_OUT_STATE, arg->out.state);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_QUERY_JFR, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jfr(int ioctl_fd, urma_cmd_delete_jfr_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JFR_IN_NUM + DELETE_JFR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JFR_IN_HANDLE, arg->in.handle);
    ATTR(a++, DELETE_JFR_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JFR, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jfr_batch(int ioctl_fd, urma_cmd_delete_jfr_batch_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JFR_BATCH_IN_NUM + DELETE_JFR_BATCH_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JFR_BATCH_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
    ATTR(a++, DELETE_JFR_BATCH_OUT_BAD_JFR_INDEX, arg->out.bad_jfr_index);
    ATTR(a++, DELETE_JFR_BATCH_IN_JFR_COUNT, arg->in.jfr_num);
    ATTR(a++, DELETE_JFR_BATCH_IN_JFR_PTR, arg->in.jfr_ptr);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JFR_BATCH, attrs, sizeof(attrs));
}

int urma_ioctl_create_jfc(int ioctl_fd, urma_cmd_create_jfc_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_JFC_IN_NUM + CREATE_JFC_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_JFC_IN_DEPTH, arg->in.depth);
    ATTR(a++, CREATE_JFC_IN_FLAG, arg->in.flag);
    ATTR(a++, CREATE_JFC_IN_JFCE_FD, arg->in.jfce_fd);
    ATTR(a++, CREATE_JFC_IN_URMA_JFC, arg->in.urma_jfc);
    ATTR(a++, CREATE_JFC_IN_CEQN, arg->in.ceqn);
    ATTR(a++, CREATE_JFC_IN_UDATA, arg->udata);
    ATTR(a++, CREATE_JFC_OUT_ID, arg->out.id);
    ATTR(a++, CREATE_JFC_OUT_DEPTH, arg->out.depth);
    ATTR(a++, CREATE_JFC_OUT_HANDLE, arg->out.handle);
    ATTR(a++, CREATE_JFC_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_JFC, attrs, sizeof(attrs));
}

int urma_ioctl_modify_jfc(int ioctl_fd, urma_cmd_modify_jfc_t *arg)
{
    urma_cmd_attr_t attrs[MODIFY_JFC_IN_NUM + MODIFY_JFC_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, MODIFY_JFC_IN_HANDLE, arg->in.handle);
    ATTR(a++, MODIFY_JFC_IN_MASK, arg->in.mask);
    ATTR(a++, MODIFY_JFC_IN_MODERATE_COUNT, arg->in.moderate_count);
    ATTR(a++, MODIFY_JFC_IN_MODERATE_PERIOD, arg->in.moderate_period);
    ATTR(a++, MODIFY_JFC_IN_UDATA, arg->udata);
    ATTR(a++, MODIFY_JFC_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_MODIFY_JFC, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jfc(int ioctl_fd, urma_cmd_delete_jfc_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JFC_IN_NUM + DELETE_JFC_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JFC_IN_HANDLE, arg->in.handle);
    ATTR(a++, DELETE_JFC_OUT_COMP_EVENTS_REPORTED, arg->out.comp_events_reported);
    ATTR(a++, DELETE_JFC_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JFC, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jfc_batch(int ioctl_fd, urma_cmd_delete_jfc_batch_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JFC_BATCH_IN_NUM + DELETE_JFC_BATCH_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JFC_BATCH_OUT_COMP_EVENTS_REPORTED, arg->out.comp_events_reported);
    ATTR(a++, DELETE_JFC_BATCH_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
    ATTR(a++, DELETE_JFC_BATCH_OUT_BAD_JFC_INDEX, arg->out.bad_jfc_index);
    ATTR(a++, DELETE_JFC_BATCH_IN_JFC_COUNT, arg->in.jfc_num);
    ATTR(a++, DELETE_JFC_BATCH_IN_JFC_PTR, arg->in.jfc_ptr);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JFC_BATCH, attrs, sizeof(attrs));
}

int urma_ioctl_create_jfce(int ioctl_fd, urma_cmd_create_jfce_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_JFCE_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_JFCE_OUT_FD, arg->out.fd);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_JFCE, attrs, sizeof(attrs));
}

int urma_ioctl_import_jfr(int ioctl_fd, urma_cmd_import_jfr_t *arg)
{
    urma_cmd_attr_t attrs[IMPORT_JFR_IN_NUM + IMPORT_JFR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, IMPORT_JFR_IN_EID, arg->in.eid);
    ATTR(a++, IMPORT_JFR_IN_ID, arg->in.id);
    ATTR(a++, IMPORT_JFR_IN_FLAG, arg->in.flag);
    ATTR(a++, IMPORT_JFR_IN_TOKEN, arg->in.token);
    ATTR(a++, IMPORT_JFR_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, IMPORT_JFR_IN_TP_TYPE, arg->in.tp_type);
    ATTR(a++, IMPORT_JFR_IN_UDATA, arg->udata);
    ATTR(a++, IMPORT_JFR_OUT_TPN, arg->out.tpn);
    ATTR(a++, IMPORT_JFR_OUT_HANDLE, arg->out.handle);
    ATTR(a++, IMPORT_JFR_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_IMPORT_JFR, attrs, sizeof(attrs));
}

int urma_ioctl_import_jfr_ex(int ioctl_fd, urma_cmd_import_jfr_ex_t *arg)
{
    urma_cmd_attr_t attrs[IMPORT_JFR_EX_IN_NUM + IMPORT_JFR_EX_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, IMPORT_JFR_EX_IN_EID, arg->in.eid);
    ATTR(a++, IMPORT_JFR_EX_IN_ID, arg->in.id);
    ATTR(a++, IMPORT_JFR_EX_IN_FLAG, arg->in.flag);
    ATTR(a++, IMPORT_JFR_EX_IN_TOKEN, arg->in.token);
    ATTR(a++, IMPORT_JFR_EX_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, IMPORT_JFR_EX_IN_TP_TYPE, arg->in.tp_type);
    ATTR(a++, IMPORT_JFR_EX_IN_TP_HANDLE, arg->in.tp_handle);
    ATTR(a++, IMPORT_JFR_EX_IN_PEER_TP_HANDLE, arg->in.peer_tp_handle);
    ATTR(a++, IMPORT_JFR_EX_IN_TAG, arg->in.tag);
    ATTR(a++, IMPORT_JFR_EX_IN_TX_PSN, arg->in.tx_psn);
    ATTR(a++, IMPORT_JFR_EX_IN_RX_PSN, arg->in.rx_psn);
    ATTR(a++, IMPORT_JFR_EX_IN_UDATA, arg->udata);
    ATTR(a++, IMPORT_JFR_EX_OUT_TPN, arg->out.tpn);
    ATTR(a++, IMPORT_JFR_EX_OUT_HANDLE, arg->out.handle);
    ATTR(a++, IMPORT_JFR_EX_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_IMPORT_JFR_EX, attrs, sizeof(attrs));
}

int urma_ioctl_unimport_jfr(int ioctl_fd, urma_cmd_unimport_jfr_t *arg)
{
    urma_cmd_attr_t attrs[UNIMPORT_JFR_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNIMPORT_JFR_IN_HANDLE, arg->in.handle);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_UNIMPORT_JFR, attrs, sizeof(attrs));
}

int urma_ioctl_create_jetty(int ioctl_fd, urma_cmd_create_jetty_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_JETTY_IN_NUM + CREATE_JETTY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_JETTY_IN_ID, arg->in.id);
    ATTR(a++, CREATE_JETTY_IN_JETTY_FLAG, arg->in.jetty_flag);
    ATTR(a++, CREATE_JETTY_IN_JFS_DEPTH, arg->in.jfs_depth);
    ATTR(a++, CREATE_JETTY_IN_JFS_FLAG, arg->in.jfs_flag);
    ATTR(a++, CREATE_JETTY_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, CREATE_JETTY_IN_PRIORITY, arg->in.priority);
    ATTR(a++, CREATE_JETTY_IN_MAX_SEND_SGE, arg->in.max_send_sge);
    ATTR(a++, CREATE_JETTY_IN_MAX_SEND_RSGE, arg->in.max_send_rsge);
    ATTR(a++, CREATE_JETTY_IN_MAX_INLINE_DATA, arg->in.max_inline_data);
    ATTR(a++, CREATE_JETTY_IN_RNR_RETRY, arg->in.rnr_retry);
    ATTR(a++, CREATE_JETTY_IN_ERR_TIMEOUT, arg->in.err_timeout);
    ATTR(a++, CREATE_JETTY_IN_SEND_JFC_ID, arg->in.send_jfc_id);
    ATTR(a++, CREATE_JETTY_IN_SEND_JFC_HANDLE, arg->in.send_jfc_handle);
    ATTR(a++, CREATE_JETTY_IN_JFR_DEPTH, arg->in.jfr_depth);
    ATTR(a++, CREATE_JETTY_IN_JFR_FLAG, arg->in.jfr_flag);
    ATTR(a++, CREATE_JETTY_IN_MAX_RECV_SGE, arg->in.max_recv_sge);
    ATTR(a++, CREATE_JETTY_IN_MIN_RNR_TIMER, arg->in.min_rnr_timer);
    ATTR(a++, CREATE_JETTY_IN_RECV_JFC_ID, arg->in.recv_jfc_id);
    ATTR(a++, CREATE_JETTY_IN_RECV_JFC_HANDLE, arg->in.recv_jfc_handle);
    ATTR(a++, CREATE_JETTY_IN_TOKEN, arg->in.token);
    ATTR(a++, CREATE_JETTY_IN_JFR_ID, arg->in.jfr_id);
    ATTR(a++, CREATE_JETTY_IN_JFR_HANDLE, arg->in.jfr_handle);
    ATTR(a++, CREATE_JETTY_IN_JETTY_GRP_HANDLE, arg->in.jetty_grp_handle);
    ATTR(a++, CREATE_JETTY_IN_IS_JETTY_GRP, arg->in.is_jetty_grp);
    ATTR(a++, CREATE_JETTY_IN_URMA_JETTY, arg->in.urma_jetty);
    ATTR(a++, CREATE_JETTY_IN_UDATA, arg->udata);
    ATTR(a++, CREATE_JETTY_OUT_ID, arg->out.id);
    ATTR(a++, CREATE_JETTY_OUT_HANDLE, arg->out.handle);
    ATTR(a++, CREATE_JETTY_OUT_JFS_DEPTH, arg->out.jfs_depth);
    ATTR(a++, CREATE_JETTY_OUT_JFR_DEPTH, arg->out.jfr_depth);
    ATTR(a++, CREATE_JETTY_OUT_MAX_SEND_SGE, arg->out.max_send_sge);
    ATTR(a++, CREATE_JETTY_OUT_MAX_SEND_RSGE, arg->out.max_send_rsge);
    ATTR(a++, CREATE_JETTY_OUT_MAX_RECV_SGE, arg->out.max_recv_sge);
    ATTR(a++, CREATE_JETTY_OUT_MAX_INLINE_DATA, arg->out.max_inline_data);
    ATTR(a++, CREATE_JETTY_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_JETTY, attrs, sizeof(attrs));
}

int urma_ioctl_modify_jetty(int ioctl_fd, urma_cmd_modify_jetty_t *arg)
{
    urma_cmd_attr_t attrs[MODIFY_JETTY_IN_NUM + MODIFY_JETTY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, MODIFY_JETTY_IN_HANDLE, arg->in.handle);
    ATTR(a++, MODIFY_JETTY_IN_MASK, arg->in.mask);
    ATTR(a++, MODIFY_JETTY_IN_RX_THRESHOLD, arg->in.rx_threshold);
    ATTR(a++, MODIFY_JETTY_IN_STATE, arg->in.state);
    ATTR(a++, MODIFY_JETTY_IN_UDATA, arg->udata);
    ATTR(a++, MODIFY_JETTY_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_MODIFY_JETTY, attrs, sizeof(attrs));
}

int urma_ioctl_query_jetty(int ioctl_fd, urma_cmd_query_jetty_t *arg)
{
    urma_cmd_attr_t attrs[QUERY_JETTY_IN_NUM + QUERY_JETTY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, QUERY_JETTY_IN_HANDLE, arg->in.handle);
    ATTR(a++, QUERY_JETTY_OUT_ID, arg->out.id);
    ATTR(a++, QUERY_JETTY_OUT_JETTY_FLAG, arg->out.jetty_flag);
    ATTR(a++, QUERY_JETTY_OUT_JFS_DEPTH, arg->out.jfs_depth);
    ATTR(a++, QUERY_JETTY_OUT_JFR_DEPTH, arg->out.jfr_depth);
    ATTR(a++, QUERY_JETTY_OUT_JFS_FLAG, arg->out.jfs_flag);
    ATTR(a++, QUERY_JETTY_OUT_JFR_FLAG, arg->out.jfr_flag);
    ATTR(a++, QUERY_JETTY_OUT_TRANS_MODE, arg->out.trans_mode);
    ATTR(a++, QUERY_JETTY_OUT_MAX_SEND_SGE, arg->out.max_send_sge);
    ATTR(a++, QUERY_JETTY_OUT_MAX_SEND_RSGE, arg->out.max_send_rsge);
    ATTR(a++, QUERY_JETTY_OUT_MAX_RECV_SGE, arg->out.max_recv_sge);
    ATTR(a++, QUERY_JETTY_OUT_MAX_INLINE_DATA, arg->out.max_inline_data);
    ATTR(a++, QUERY_JETTY_OUT_PRIORITY, arg->out.priority);
    ATTR(a++, QUERY_JETTY_OUT_RETRY_CNT, arg->out.retry_cnt);
    ATTR(a++, QUERY_JETTY_OUT_RNR_RETRY, arg->out.rnr_retry);
    ATTR(a++, QUERY_JETTY_OUT_ERR_TIMEOUT, arg->out.err_timeout);
    ATTR(a++, QUERY_JETTY_OUT_MIN_RNR_TIMER, arg->out.min_rnr_timer);
    ATTR(a++, QUERY_JETTY_OUT_JFR_ID, arg->out.jfr_id);
    ATTR(a++, QUERY_JETTY_OUT_TOKEN, arg->out.token);
    ATTR(a++, QUERY_JETTY_OUT_RX_THRESHOLD, arg->out.rx_threshold);
    ATTR(a++, QUERY_JETTY_OUT_STATE, arg->out.state);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_QUERY_JETTY, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jetty(int ioctl_fd, urma_cmd_delete_jetty_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JETTY_IN_NUM + DELETE_JETTY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JETTY_IN_HANDLE, arg->in.handle);
    ATTR(a++, DELETE_JETTY_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JETTY, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jetty_batch(int ioctl_fd, urma_cmd_delete_jetty_batch_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JETTY_BATCH_IN_NUM + DELETE_JETTY_BATCH_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JETTY_BATCH_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);
    ATTR(a++, DELETE_JETTY_BATCH_OUT_BAD_JETTY_INDEX, arg->out.bad_jetty_index);
    ATTR(a++, DELETE_JETTY_BATCH_IN_JETTY_COUNT, arg->in.jetty_num);
    ATTR(a++, DELETE_JETTY_BATCH_IN_JETTY_PTR, arg->in.jetty_ptr);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DELETE_JETTY_BATCH, attrs, sizeof(attrs));
}

int urma_ioctl_import_jetty(int ioctl_fd, urma_cmd_import_jetty_t *arg)
{
    urma_cmd_attr_t attrs[IMPORT_JETTY_IN_NUM + IMPORT_JETTY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, IMPORT_JETTY_IN_EID, arg->in.eid);
    ATTR(a++, IMPORT_JETTY_IN_ID, arg->in.id);
    ATTR(a++, IMPORT_JETTY_IN_FLAG, arg->in.flag);
    ATTR(a++, IMPORT_JETTY_IN_TOKEN, arg->in.token);
    ATTR(a++, IMPORT_JETTY_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, IMPORT_JETTY_IN_POLICY, arg->in.policy);
    ATTR(a++, IMPORT_JETTY_IN_TYPE, arg->in.type);
    ATTR(a++, IMPORT_JETTY_IN_TP_TYPE, arg->in.tp_type);
    ATTR(a++, IMPORT_JETTY_IN_UDATA, arg->udata);
    ATTR(a++, IMPORT_JETTY_OUT_TPN, arg->out.tpn);
    ATTR(a++, IMPORT_JETTY_OUT_HANDLE, arg->out.handle);
    ATTR(a++, IMPORT_JETTY_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_IMPORT_JETTY, attrs, sizeof(attrs));
}

int urma_ioctl_import_jetty_ex(int ioctl_fd, urma_cmd_import_jetty_ex_t *arg)
{
    urma_cmd_attr_t attrs[IMPORT_JETTY_EX_IN_NUM + IMPORT_JETTY_EX_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, IMPORT_JETTY_EX_IN_EID, arg->in.eid);
    ATTR(a++, IMPORT_JETTY_EX_IN_ID, arg->in.id);
    ATTR(a++, IMPORT_JETTY_EX_IN_FLAG, arg->in.flag);
    ATTR(a++, IMPORT_JETTY_EX_IN_TOKEN, arg->in.token);
    ATTR(a++, IMPORT_JETTY_EX_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, IMPORT_JETTY_EX_IN_POLICY, arg->in.policy);
    ATTR(a++, IMPORT_JETTY_EX_IN_TYPE, arg->in.type);
    ATTR(a++, IMPORT_JETTY_EX_IN_TP_TYPE, arg->in.tp_type);
    ATTR(a++, IMPORT_JETTY_EX_IN_TP_HANDLE, arg->in.tp_handle);
    ATTR(a++, IMPORT_JETTY_EX_IN_PEER_TP_HANDLE, arg->in.peer_tp_handle);
    ATTR(a++, IMPORT_JETTY_EX_IN_TAG, arg->in.tag);
    ATTR(a++, IMPORT_JETTY_EX_IN_TX_PSN, arg->in.tx_psn);
    ATTR(a++, IMPORT_JETTY_EX_IN_RX_PSN, arg->in.rx_psn);
    ATTR(a++, IMPORT_JETTY_EX_IN_UDATA, arg->udata);
    ATTR(a++, IMPORT_JETTY_EX_OUT_TPN, arg->out.tpn);
    ATTR(a++, IMPORT_JETTY_EX_OUT_HANDLE, arg->out.handle);
    ATTR(a++, IMPORT_JETTY_EX_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_IMPORT_JETTY_EX, attrs, sizeof(attrs));
}

int urma_ioctl_unimport_jetty(int ioctl_fd, urma_cmd_unimport_jetty_t *arg)
{
    urma_cmd_attr_t attrs[UNIMPORT_JETTY_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNIMPORT_JETTY_IN_HANDLE, arg->in.handle);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_UNIMPORT_JETTY, attrs, sizeof(attrs));
}

static int urma_ioctl_advise_jetty_inner(int ioctl_fd, urma_cmd_t cmd, urma_cmd_advise_jetty_t *arg)
{
    urma_cmd_attr_t attrs[ADVISE_JETTY_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, ADVISE_JETTY_IN_JETTY_HANDLE, arg->in.jetty_handle);
    ATTR(a++, ADVISE_JETTY_IN_TJETTY_HANDLE, arg->in.tjetty_handle);
    ATTR(a++, ADVISE_JETTY_IN_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, cmd, attrs, sizeof(attrs));
}

static int urma_ioctl_unadvise_jetty_inner(int ioctl_fd, urma_cmd_t cmd, urma_cmd_unadvise_jetty_t *arg)
{
    urma_cmd_attr_t attrs[UNADVISE_JETTY_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNADVISE_JETTY_IN_JETTY_HANDLE, arg->in.jetty_handle);
    ATTR(a++, UNADVISE_JETTY_IN_TJETTY_HANDLE, arg->in.tjetty_handle);

    return urma_tlv_ioctl(ioctl_fd, cmd, attrs, sizeof(attrs));
}

inline int urma_ioctl_advise_jfr(int ioctl_fd, urma_cmd_advise_jetty_t *arg)
{
    return urma_ioctl_advise_jetty_inner(ioctl_fd, URMA_CMD_ADVISE_JFR, arg);
}

inline int urma_ioctl_unadvise_jfr(int ioctl_fd, urma_cmd_unadvise_jetty_t *arg)
{
    return urma_ioctl_unadvise_jetty_inner(ioctl_fd, URMA_CMD_UNADVISE_JFR, arg);
}

inline int urma_ioctl_advise_jetty(int ioctl_fd, urma_cmd_advise_jetty_t *arg)
{
    return urma_ioctl_advise_jetty_inner(ioctl_fd, URMA_CMD_ADVISE_JETTY, arg);
}

inline int urma_ioctl_unadvise_jetty(int ioctl_fd, urma_cmd_unadvise_jetty_t *arg)
{
    return urma_ioctl_unadvise_jetty_inner(ioctl_fd, URMA_CMD_UNADVISE_JETTY, arg);
}

int urma_ioctl_bind_jetty(int ioctl_fd, urma_cmd_bind_jetty_t *arg)
{
    urma_cmd_attr_t attrs[BIND_JETTY_IN_NUM + BIND_JETTY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, BIND_JETTY_IN_JETTY_HANDLE, arg->in.jetty_handle);
    ATTR(a++, BIND_JETTY_IN_TJETTY_HANDLE, arg->in.tjetty_handle);
    ATTR(a++, BIND_JETTY_IN_UDATA, arg->udata);
    ATTR(a++, BIND_JETTY_OUT_TPN, arg->out.tpn);
    ATTR(a++, BIND_JETTY_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_BIND_JETTY, attrs, sizeof(attrs));
}

int urma_ioctl_bind_jetty_ex(int ioctl_fd, urma_cmd_bind_jetty_ex_t *arg)
{
    urma_cmd_attr_t attrs[BIND_JETTY_EX_IN_NUM + BIND_JETTY_EX_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, BIND_JETTY_EX_IN_JETTY_HANDLE, arg->in.jetty_handle);
    ATTR(a++, BIND_JETTY_EX_IN_TJETTY_HANDLE, arg->in.tjetty_handle);
    ATTR(a++, BIND_JETTY_EX_IN_TP_HANDLE, arg->in.tp_handle);
    ATTR(a++, BIND_JETTY_EX_IN_PEER_TP_HANDLE, arg->in.peer_tp_handle);
    ATTR(a++, BIND_JETTY_EX_IN_TAG, arg->in.tag);
    ATTR(a++, BIND_JETTY_EX_IN_TX_PSN, arg->in.tx_psn);
    ATTR(a++, BIND_JETTY_EX_IN_RX_PSN, arg->in.rx_psn);
    ATTR(a++, BIND_JETTY_EX_IN_UDATA, arg->udata);
    ATTR(a++, BIND_JETTY_EX_OUT_TPN, arg->out.tpn);
    ATTR(a++, BIND_JETTY_EX_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_BIND_JETTY_EX, attrs, sizeof(attrs));
}

int urma_ioctl_unbind_jetty(int ioctl_fd, urma_cmd_unadvise_jetty_t *arg)
{
    return urma_ioctl_unadvise_jetty_inner(ioctl_fd, URMA_CMD_UNBIND_JETTY, arg);
}

int urma_ioctl_create_jetty_grp(int ioctl_fd, urma_cmd_create_jetty_grp_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_JETTY_GRP_IN_NUM + CREATE_JETTY_GRP_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_JETTY_GRP_IN_NAME, arg->in.name);
    ATTR(a++, CREATE_JETTY_GRP_IN_TOKEN, arg->in.token);
    ATTR(a++, CREATE_JETTY_GRP_IN_ID, arg->in.id);
    ATTR(a++, CREATE_JETTY_GRP_IN_POLICY, arg->in.policy);
    ATTR(a++, CREATE_JETTY_GRP_IN_FLAG, arg->in.flag);
    ATTR(a++, CREATE_JETTY_GRP_IN_URMA_JETTY_GRP, arg->in.urma_jetty_grp);
    ATTR(a++, CREATE_JETTY_GRP_IN_UDATA, arg->udata);
    ATTR(a++, CREATE_JETTY_GRP_OUT_ID, arg->out.id);
    ATTR(a++, CREATE_JETTY_GRP_OUT_HANDLE, arg->out.handle);
    ATTR(a++, CREATE_JETTY_GRP_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_JETTY_GRP, attrs, sizeof(attrs));
}

int urma_ioctl_delete_jetty_grp(int ioctl_fd, urma_cmd_delete_jetty_grp_t *arg)
{
    urma_cmd_attr_t attrs[DELETE_JETTY_GRP_IN_NUM + DELETE_JETTY_GRP_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, DELETE_JETTY_GRP_IN_HANDLE, arg->in.handle);
    ATTR(a++, DELETE_JETTY_GRP_OUT_ASYNC_EVENTS_REPORTED, arg->out.async_events_reported);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_DESTROY_JETTY_GRP, attrs, sizeof(attrs));
}

int urma_ioctl_user_ctl(int ioctl_fd, urma_cmd_user_ctl_t *arg)
{
    urma_cmd_attr_t attrs[USER_CTL_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, USER_CTL_IN_IN_ADDR, arg->in.addr);
    ATTR(a++, USER_CTL_IN_IN_LEN, arg->in.len);
    ATTR(a++, USER_CTL_IN_OPCODE, arg->in.opcode);
    ATTR(a++, USER_CTL_IN_OUT_ADDR, arg->out.addr);
    ATTR(a++, USER_CTL_IN_OUT_LEN, arg->out.len);
    ATTR(a++, USER_CTL_IN_UDATA, arg->udrv);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_USER_CTL, attrs, sizeof(attrs));
}

int urma_ioctl_get_eid_list(int ioctl_fd, urma_cmd_get_eid_list_t *arg)
{
    urma_cmd_attr_t attrs[GET_EID_LIST_IN_NUM + GET_EID_LIST_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, GET_EID_LIST_IN_MAX_EID_CNT, arg->in.max_eid_cnt);
    ATTR(a++, GET_EID_LIST_OUT_EID_CNT, arg->out.eid_cnt);
    ATTR(a++, GET_EID_LIST_OUT_EID_LIST, arg->out.eid_list);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_GET_EID_LIST, attrs, sizeof(attrs));
}

int urma_ioctl_get_netaddr_list(int ioctl_fd, urma_cmd_get_net_addr_list_t *arg)
{
    urma_cmd_attr_t attrs[GET_NET_ADDR_LIST_IN_NUM + GET_NET_ADDR_LIST_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;
    uint64_t netaddr_size = (uint64_t)sizeof(urma_cmd_net_addr_info_t);

    ATTR(a++, GET_NET_ADDR_LIST_IN_MAX_NETADDR_CNT, arg->in.max_netaddr_cnt);
    ATTR(a++, GET_NET_ADDR_LIST_OUT_NETADDR_CNT, arg->out.netaddr_cnt);
    fill_attr(a++, GET_NET_ADDR_LIST_OUT_NETADDR_LIST, netaddr_size, arg->out.len / netaddr_size, netaddr_size,
              arg->out.addr);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_GET_NETADDR_LIST, attrs, sizeof(attrs));
}

int urma_ioctl_modify_tp(int ioctl_fd, urma_cmd_modify_tp_t *arg)
{
    urma_cmd_attr_t attrs[MODIFY_TP_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, MODIFY_TP_IN_TPN, arg->in.tpn);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_FLAG, arg->in.tp_cfg.flag);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_TRANS_MODE, arg->in.tp_cfg.trans_mode);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_RETRY_NUM, arg->in.tp_cfg.retry_num);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_RETRY_FACTOR, arg->in.tp_cfg.retry_factor);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_ACK_TIMEOUT, arg->in.tp_cfg.ack_timeout);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_DSCP, arg->in.tp_cfg.dscp);
    ATTR(a++, MODIFY_TP_IN_TP_CFG_OOR_CNT, arg->in.tp_cfg.oor_cnt);
    ATTR(a++, MODIFY_TP_IN_ATTR_FLAG, arg->in.attr.flag);
    ATTR(a++, MODIFY_TP_IN_ATTR_PEER_TPN, arg->in.attr.peer_tpn);
    ATTR(a++, MODIFY_TP_IN_ATTR_STATE, arg->in.attr.state);
    ATTR(a++, MODIFY_TP_IN_ATTR_TX_PSN, arg->in.attr.tx_psn);
    ATTR(a++, MODIFY_TP_IN_ATTR_RX_PSN, arg->in.attr.rx_psn);
    ATTR(a++, MODIFY_TP_IN_ATTR_MTU, arg->in.attr.mtu);
    ATTR(a++, MODIFY_TP_IN_ATTR_CC_PATTERN_IDX, arg->in.attr.cc_pattern_idx);
    ATTR(a++, MODIFY_TP_IN_ATTR_OOS_CNT, arg->in.attr.oos_cnt);
    ATTR(a++, MODIFY_TP_IN_ATTR_LOCAL_NET_ADDR_IDX, arg->in.attr.local_net_addr_idx);
    ATTR(a++, MODIFY_TP_IN_ATTR_PEER_NET_ADDR, arg->in.attr.peer_net_addr);
    ATTR(a++, MODIFY_TP_IN_ATTR_DATA_UDP_START, arg->in.attr.data_udp_start);
    ATTR(a++, MODIFY_TP_IN_ATTR_ACK_UDP_START, arg->in.attr.ack_udp_start);
    ATTR(a++, MODIFY_TP_IN_ATTR_UDP_RANGE, arg->in.attr.udp_range);
    ATTR(a++, MODIFY_TP_IN_ATTR_HOP_LIMIT, arg->in.attr.hop_limit);
    ATTR(a++, MODIFY_TP_IN_ATTR_FLOW_LABEL, arg->in.attr.flow_label);
    ATTR(a++, MODIFY_TP_IN_ATTR_PORT_ID, arg->in.attr.port_id);
    ATTR(a++, MODIFY_TP_IN_ATTR_MN, arg->in.attr.mn);
    ATTR(a++, MODIFY_TP_IN_ATTR_PEER_TRANS_TYPE, arg->in.attr.peer_trans_type);
    ATTR(a++, MODIFY_TP_IN_MASK, arg->in.mask);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_MODIFY_TP, attrs, sizeof(attrs));
}

int urma_ioctl_query_dev_attr(int ioctl_fd, urma_cmd_query_device_attr_t *arg)
{
    urma_cmd_attr_t attrs[QUERY_DEVICE_IN_NUM + QUERY_DEVICE_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, QUERY_DEVICE_IN_DEV_NAME, arg->in.dev_name);

    ATTR(a++, QUERY_DEVICE_OUT_GUID, arg->out.attr.guid);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_FEATURE, arg->out.attr.dev_cap.feature);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC, arg->out.attr.dev_cap.max_jfc);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS, arg->out.attr.dev_cap.max_jfs);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR, arg->out.attr.dev_cap.max_jfr);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY, arg->out.attr.dev_cap.max_jetty);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_GRP, arg->out.attr.dev_cap.max_jetty_grp);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_IN_JETTY_GRP, arg->out.attr.dev_cap.max_jetty_in_jetty_grp);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC_DEPTH, arg->out.attr.dev_cap.max_jfc_depth);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_DEPTH, arg->out.attr.dev_cap.max_jfs_depth);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_DEPTH, arg->out.attr.dev_cap.max_jfr_depth);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_INLINE_LEN, arg->out.attr.dev_cap.max_jfs_inline_len);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_SGE, arg->out.attr.dev_cap.max_jfs_sge);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_RSGE, arg->out.attr.dev_cap.max_jfs_rsge);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_SGE, arg->out.attr.dev_cap.max_jfr_sge);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_MSG_SIZE, arg->out.attr.dev_cap.max_msg_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_READ_SIZE, arg->out.attr.dev_cap.max_read_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_WRITE_SIZE, arg->out.attr.dev_cap.max_write_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_CAS_SIZE, arg->out.attr.dev_cap.max_cas_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_SWAP_SIZE, arg->out.attr.dev_cap.max_swap_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_ADD_SIZE, arg->out.attr.dev_cap.max_fetch_and_add_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_SUB_SIZE, arg->out.attr.dev_cap.max_fetch_and_sub_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_AND_SIZE, arg->out.attr.dev_cap.max_fetch_and_and_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_OR_SIZE, arg->out.attr.dev_cap.max_fetch_and_or_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_XOR_SIZE, arg->out.attr.dev_cap.max_fetch_and_xor_size);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_ATOMIC_FEAT, arg->out.attr.dev_cap.atomic_feat);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_TRANS_MODE, arg->out.attr.dev_cap.trans_mode);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_SUB_TRANS_MODE_CAP, arg->out.attr.dev_cap.sub_trans_mode_cap);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_CONGESTION_CTRL_ALG, arg->out.attr.dev_cap.congestion_ctrl_alg);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_CEQ_CNT, arg->out.attr.dev_cap.ceq_cnt);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_TP_IN_TPG, arg->out.attr.dev_cap.max_tp_in_tpg);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_EID_CNT, arg->out.attr.dev_cap.max_eid_cnt);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_PAGE_SIZE_CAP, arg->out.attr.dev_cap.page_size_cap);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_OOR_CNT, arg->out.attr.dev_cap.max_oor_cnt);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MN, arg->out.attr.dev_cap.mn);
    ATTR(a++, QUERY_DEVICE_OUT_DEV_CAP_MAX_NETADDR_CN, arg->out.attr.dev_cap.max_netaddr_cnt);
    ATTR(a++, QUERY_DEVICE_OUT_PORT_CNT, arg->out.attr.port_cnt);
    ATTR(a++, QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MIN, arg->out.attr.reserved_jetty_id_min);
    ATTR(a++, QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MAX, arg->out.attr.reserved_jetty_id_max);

    ATTR_ARRAY(a++, QUERY_DEVICE_OUT_PORT_ATTR_MAX_MTU, arg->out.attr.port_attr, max_mtu);
    ATTR_ARRAY(a++, QUERY_DEVICE_OUT_PORT_ATTR_STATE, arg->out.attr.port_attr, state);
    ATTR_ARRAY(a++, QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_WIDTH, arg->out.attr.port_attr, active_width);
    ATTR_ARRAY(a++, QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_SPEED, arg->out.attr.port_attr, active_speed);
    ATTR_ARRAY(a++, QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_MTU, arg->out.attr.port_attr, active_mtu);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_QUERY_DEV_ATTR, attrs, sizeof(attrs));
}

int urma_ioctl_wait_jfc(int ioctl_fd, urma_cmd_jfce_wait_t *arg)
{
    urma_cmd_attr_t attrs[JFCE_WAIT_IN_NUM + JFCE_WAIT_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, JFCE_WAIT_IN_MAX_EVENT_CNT, arg->in.max_event_cnt);
    ATTR(a++, JFCE_WAIT_IN_TIME_OUT, arg->in.time_out);
    ATTR(a++, JFCE_WAIT_OUT_EVENT_CNT, arg->out.event_cnt);
    ATTR(a++, JFCE_WAIT_OUT_EVENT_DATA, arg->out.event_data);

    urma_cmd_hdr_t hdr = {
        .command = (uint32_t)URMA_EVENT_CMD_WAIT_JFCE,
        .args_len = sizeof(attrs),
        .args_addr = (uint64_t)(uintptr_t)attrs,
    };
    int ret = ioctl(ioctl_fd, URMA_CMD_WAIT_JFC, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("wait jfc ioctl failed, ret:%d, errno:%d.\n", ret, errno);
    }
    return ret;
}

int urma_ioctl_get_async_event(int ioctl_fd, urma_cmd_async_event_t *arg)
{
    urma_cmd_attr_t attrs[GET_ASYNC_EVENT_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, GET_ASYNC_EVENT_OUT_EVENT_TYPE, arg->event_type);
    ATTR(a++, GET_ASYNC_EVENT_OUT_EVENT_DATA, arg->event_data);

    urma_cmd_hdr_t hdr = {
        .command = (uint32_t)URMA_EVENT_CMD_GET_ASYNC_EVENT,
        .args_len = sizeof(attrs),
        .args_addr = (uint64_t)(uintptr_t)attrs,
    };
    int ret = ioctl(ioctl_fd, URMA_CMD_GET_ASYNC_EVENT, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("get async event ioctl failed, ret:%d, errno:%d.\n", ret, errno);
    }
    return ret;
}

int urma_ioctl_import_jetty_async(int ioctl_fd, urma_cmd_import_jetty_async_t *arg)
{
    urma_cmd_attr_t attrs[IMPORT_JETTY_ASYNC_IN_NUM + IMPORT_JETTY_ASYNC_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, IMPORT_JETTY_ASYNC_IN_EID, arg->in.eid);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_ID, arg->in.id);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_FLAG, arg->in.flag);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_TOKEN, arg->in.token);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_POLICY, arg->in.policy);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_TYPE, arg->in.type);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_URMA_TJETTY, arg->in.urma_tjetty);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_USER_CTX, arg->in.user_ctx);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_FD, arg->in.fd);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_TIMEOUT, arg->in.timeout);
    ATTR(a++, IMPORT_JETTY_ASYNC_IN_UDATA, arg->udata);
    ATTR(a++, IMPORT_JETTY_ASYNC_OUT_TPN, arg->out.tpn);
    ATTR(a++, IMPORT_JETTY_ASYNC_OUT_HANDLE, arg->out.handle);
    ATTR(a++, IMPORT_JETTY_ASYNC_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_IMPORT_JETTY_ASYNC, attrs, sizeof(attrs));
}

int urma_ioctl_unimport_jetty_async(int ioctl_fd, urma_cmd_unimport_jetty_async_t *arg)
{
    urma_cmd_attr_t attrs[UNIMPORT_JETTY_ASYNC_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNIMPORT_JETTY_ASYNC_IN_HANDLE, arg->in.handle);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_UNIMPORT_JETTY_ASYNC, attrs, sizeof(attrs));
}

int urma_ioctl_bind_jetty_async(int ioctl_fd, urma_cmd_bind_jetty_async_t *arg)
{
    urma_cmd_attr_t attrs[BIND_JETTY_ASYNC_IN_NUM + BIND_JETTY_ASYNC_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, BIND_JETTY_ASYNC_IN_JETTY_HANDLE, arg->in.jetty_handle);
    ATTR(a++, BIND_JETTY_ASYNC_IN_TJETTY_HANDLE, arg->in.tjetty_handle);
    ATTR(a++, BIND_JETTY_ASYNC_IN_URMA_TJETTY, arg->in.urma_tjetty);
    ATTR(a++, BIND_JETTY_ASYNC_IN_URMA_JETTY, arg->in.urma_jetty);
    ATTR(a++, BIND_JETTY_ASYNC_IN_FD, arg->in.fd);
    ATTR(a++, BIND_JETTY_ASYNC_IN_USER_CTX, arg->in.user_ctx);
    ATTR(a++, BIND_JETTY_ASYNC_IN_TIMEOUT, arg->in.timeout);
    ATTR(a++, BIND_JETTY_ASYNC_IN_UDATA, arg->udata);
    ATTR(a++, BIND_JETTY_ASYNC_OUT_TPN, arg->out.tpn);
    ATTR(a++, BIND_JETTY_ASYNC_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_BIND_JETTY_ASYNC, attrs, sizeof(attrs));
}

int urma_ioctl_unbind_jetty_async(int ioctl_fd, urma_cmd_unbind_jetty_async_t *arg)
{
    urma_cmd_attr_t attrs[UNBIND_JETTY_ASYNC_IN_NUM] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, UNBIND_JETTY_ASYNC_IN_JETTY_HANDLE, arg->in.jetty_handle);
    ATTR(a++, UNBIND_JETTY_ASYNC_IN_TJETTY_HANDLE, arg->in.tjetty_handle);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_UNBIND_JETTY_ASYNC, attrs, sizeof(attrs));
}

int urma_ioctl_create_notifier(int ioctl_fd, urma_cmd_create_notifier_t *arg)
{
    urma_cmd_attr_t attrs[CREATE_NOTIFIER_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, CREATE_NOTIFIER_OUT_FD, arg->out.fd);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_CREATE_NOTIFIER, attrs, sizeof(attrs));
}

int urma_ioctl_wait_notify(int ioctl_fd, urma_cmd_wait_notify_t *arg)
{
    urma_cmd_attr_t attrs[WAIT_NOTIFY_IN_NUM + WAIT_NOTIFY_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, WAIT_NOTIFY_IN_CNT, arg->in.cnt);
    ATTR(a++, WAIT_NOTIFY_IN_TIMEOUT, arg->in.timeout);
    ATTR(a++, WAIT_NOTIFY_OUT_CNT, arg->out.cnt);
    ATTR(a++, WAIT_NOTIFY_OUT_NOTIFY, arg->out.notify);

    urma_cmd_hdr_t hdr = {
        .command = (uint32_t)URMA_EVENT_CMD_WAIT_NOTIFY,
        .args_len = sizeof(attrs),
        .args_addr = (uint64_t)(uintptr_t)attrs,
    };
    int ret = ioctl(ioctl_fd, URMA_CMD_WAIT_NOTIFY, &hdr);
    if (ret != 0) {
        URMA_LOG_ERR("wait notify ioctl failed, ret:%d, errno:%d.\n", ret, errno);
    }
    return ret;
}

int urma_ioctl_get_tp_list(int ioctl_fd, urma_cmd_get_tp_list_t *arg)
{
    urma_cmd_attr_t attrs[GET_TP_LIST_IN_NUM + GET_TP_LIST_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, GET_TP_LIST_IN_FLAG, arg->in.flag);
    ATTR(a++, GET_TP_LIST_IN_TRANS_MODE, arg->in.trans_mode);
    ATTR(a++, GET_TP_LIST_IN_LOCAL_EID, arg->in.local_eid);
    ATTR(a++, GET_TP_LIST_IN_PEER_EID, arg->in.peer_eid);
    ATTR(a++, GET_TP_LIST_IN_TP_CNT, arg->in.tp_cnt);
    ATTR(a++, GET_TP_LIST_IN_UDATA, arg->udata);
    ATTR(a++, GET_TP_LIST_OUT_TP_CNT, arg->out.tp_cnt);
    ATTR(a++, GET_TP_LIST_OUT_TP_HANDLE, arg->out.tp_handle);
    ATTR(a++, GET_TP_LIST_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_GET_TP_LIST, attrs, sizeof(attrs));
}

int urma_ioctl_set_tp_attr(int ioctl_fd, urma_cmd_set_tp_attr_t *arg)
{
    urma_cmd_attr_t attrs[SET_TP_ATTR_IN_NUM + SET_TP_ATTR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, SET_TP_ATTR_IN_TP_HANDLE, arg->in.tp_handle);
    ATTR(a++, SET_TP_ATTR_IN_TP_ATTR_CNT, arg->in.tp_attr_cnt);
    ATTR(a++, SET_TP_ATTR_IN_TP_ATTR_BITMAP, arg->in.tp_attr_bitmap);
    ATTR(a++, SET_TP_ATTR_IN_TP_ATTR, arg->in.tp_attr);
    ATTR(a++, SET_TP_ATTR_IN_UDATA, arg->udata);
    ATTR(a++, SET_TP_ATTR_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_SET_TP_ATTR, attrs, sizeof(attrs));
}

int urma_ioctl_get_tp_attr(int ioctl_fd, urma_cmd_get_tp_attr_t *arg)
{
    urma_cmd_attr_t attrs[GET_TP_ATTR_IN_NUM + GET_TP_ATTR_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, GET_TP_ATTR_IN_TP_HANDLE, arg->in.tp_handle);
    ATTR(a++, GET_TP_ATTR_IN_UDATA, arg->udata);
    ATTR(a++, GET_TP_ATTR_OUT_TP_ATTR_CNT, arg->out.tp_attr_cnt);
    ATTR(a++, GET_TP_ATTR_OUT_TP_ATTR_BITMAP, arg->out.tp_attr_bitmap);
    ATTR(a++, GET_TP_ATTR_OUT_TP_ATTR, arg->out.tp_attr);
    ATTR(a++, GET_TP_ATTR_OUT_UDATA, arg->udata);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_GET_TP_ATTR, attrs, sizeof(attrs));
}

int urma_ioctl_exchange_tp_info(int ioctl_fd, urma_cmd_exchange_tp_info_t *arg)
{
    urma_cmd_attr_t attrs[EXCHANGE_TP_INFO_IN_NUM + EXCHANGE_TP_INFO_OUT_NUM - URMA_CMD_OUT_TYPE_INIT] = {0};
    urma_cmd_attr_t *a = attrs;

    ATTR(a++, EXCHANGE_TP_INFO_IN_FLAG, arg->in.get_tp_cfg.flag);
    ATTR(a++, EXCHANGE_TP_INFO_IN_TRANS_MODE, arg->in.get_tp_cfg.trans_mode);
    ATTR(a++, EXCHANGE_TP_INFO_IN_LOCAL_EID, arg->in.get_tp_cfg.local_eid);
    ATTR(a++, EXCHANGE_TP_INFO_IN_PEER_EID, arg->in.get_tp_cfg.peer_eid);
    ATTR(a++, EXCHANGE_TP_INFO_IN_TP_HANDLE, arg->in.tp_handle);
    ATTR(a++, EXCHANGE_TP_INFO_IN_TX_PSN, arg->in.tx_psn);
    ATTR(a++, EXCHANGE_TP_INFO_OUT_PEER_TP_HANDLE, arg->out.peer_tp_handle);
    ATTR(a++, EXCHANGE_TP_INFO_OUT_RX_PSN, arg->out.rx_psn);

    return urma_tlv_ioctl(ioctl_fd, URMA_CMD_EXCHANGE_TP_INFO, attrs, sizeof(attrs));
}
