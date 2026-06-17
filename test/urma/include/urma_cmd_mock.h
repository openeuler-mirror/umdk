/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: Shared URMA command mock data for unit tests.
 */

#ifndef TEST_URMA_INCLUDE_URMA_CMD_MOCK_H
#define TEST_URMA_INCLUDE_URMA_CMD_MOCK_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "urma_cmd_tlv.h"

namespace urma_test {

static constexpr int MOCK_IOCTL_FD = 17;
static constexpr uint32_t MOCK_EID_INDEX = 3;
static constexpr uint32_t MOCK_TOKEN_ID = 0x1234;
static constexpr uint32_t MOCK_TOKEN = 0x5678;
static constexpr uint32_t MOCK_JFS_ID = 0x90;
static constexpr uint32_t MOCK_JFC_ID = 0x91;
static constexpr uint64_t MOCK_HANDLE = 0x123456789abcdef0ULL;
static constexpr uint64_t MOCK_TOKEN_HANDLE = 0x223456789abcdef0ULL;
static constexpr uint64_t MOCK_SEG_VA = 0x100000ULL;
static constexpr uint64_t MOCK_SEG_LEN = 0x2000ULL;
static constexpr uint64_t MOCK_SEG_MVA = 0x300000ULL;
static constexpr uint64_t MOCK_JFC_HANDLE = 0x323456789abcdef0ULL;
static constexpr uint64_t MOCK_JFS_PTR = 0x423456789abcdef0ULL;
static constexpr uint64_t MOCK_UDATA_IN = 0x523456789abcdef0ULL;
static constexpr uint64_t MOCK_UDATA_OUT = 0x623456789abcdef0ULL;

struct ExpectedAttr {
    uint8_t type;
    uint16_t fieldSize;
    uint32_t elNum;
    uint32_t elSize;
    /* Store the source field address as an integer so tests compare pointer identity, not pointed values. */
    uintptr_t data;
};

inline void FillMockEid(uint8_t eid[URMA_CMD_EID_SIZE])
{
    for (size_t i = 0; i < URMA_CMD_EID_SIZE; i++) {
        eid[i] = static_cast<uint8_t>(0xa0U + i);
    }
}

inline urma_cmd_udrv_priv_t MakeUdata()
{
    return {
        .in_addr = MOCK_UDATA_IN,
        .in_len = 64,
        .out_addr = MOCK_UDATA_OUT,
        .out_len = 128,
    };
}

inline urma_cmd_create_ctx_t MakeCreateCtxCmd()
{
    urma_cmd_create_ctx_t arg = {};
    FillMockEid(arg.in.eid);
    arg.in.eid_index = MOCK_EID_INDEX;
    arg.out.async_fd = -1;
    arg.udata = MakeUdata();
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedCreateCtxAttrs(urma_cmd_create_ctx_t *arg)
{
    return {
        { CREATE_CTX_IN_EID, sizeof(arg->in.eid), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.eid) },
        { CREATE_CTX_IN_EID_INDEX, sizeof(arg->in.eid_index), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.eid_index) },
        { CREATE_CTX_IN_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
        { CREATE_CTX_OUT_ASYNC_FD, sizeof(arg->out.async_fd), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.async_fd) },
        { CREATE_CTX_OUT_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
    };
}

inline urma_cmd_alloc_token_id_t MakeAllocTokenIdCmd()
{
    urma_cmd_alloc_token_id_t arg = {};
    arg.in.flag.bs.multi_seg = 1;
    arg.out.token_id = MOCK_TOKEN_ID;
    arg.out.handle = MOCK_TOKEN_HANDLE;
    arg.udata = MakeUdata();
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedAllocTokenIdAttrs(urma_cmd_alloc_token_id_t *arg)
{
    return {
        { ALLOC_TOKEN_ID_IN_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
        { ALLOC_TOKEN_ID_IN_FLAG, sizeof(arg->in.flag), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.flag) },
        { ALLOC_TOKEN_ID_OUT_TOKEN_ID, sizeof(arg->out.token_id), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.token_id) },
        { ALLOC_TOKEN_ID_OUT_HANDLE, sizeof(arg->out.handle), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.handle) },
        { ALLOC_TOKEN_ID_OUT_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
    };
}

inline urma_cmd_free_token_id_t MakeFreeTokenIdCmd()
{
    urma_cmd_free_token_id_t arg = {};
    arg.in.handle = MOCK_TOKEN_HANDLE;
    arg.in.token_id = MOCK_TOKEN_ID;
    arg.udata = MakeUdata();
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedFreeTokenIdAttrs(urma_cmd_free_token_id_t *arg)
{
    return {
        { FREE_TOKEN_ID_IN_HANDLE, sizeof(arg->in.handle), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.handle) },
        { FREE_TOKEN_ID_IN_TOKEN_ID, sizeof(arg->in.token_id), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.token_id) },
        { FREE_TOKEN_ID_IN_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
    };
}

inline urma_cmd_register_seg_t MakeRegisterSegCmd()
{
    urma_cmd_register_seg_t arg = {};
    arg.in.va = MOCK_SEG_VA;
    arg.in.len = MOCK_SEG_LEN;
    arg.in.token_id = MOCK_TOKEN_ID;
    arg.in.token_id_handle = MOCK_TOKEN_HANDLE;
    arg.in.token = MOCK_TOKEN;
    arg.in.flag = 1;
    arg.out.token_id = MOCK_TOKEN_ID + 1;
    arg.out.handle = MOCK_HANDLE;
    arg.udata = MakeUdata();
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedRegisterSegAttrs(urma_cmd_register_seg_t *arg)
{
    return {
        { REGISTER_SEG_IN_VA, sizeof(arg->in.va), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.va) },
        { REGISTER_SEG_IN_LEN, sizeof(arg->in.len), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.len) },
        { REGISTER_SEG_IN_TOKEN_ID, sizeof(arg->in.token_id), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.token_id) },
        { REGISTER_SEG_IN_TOKEN_ID_HANDLE, sizeof(arg->in.token_id_handle), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.token_id_handle) },
        { REGISTER_SEG_IN_TOKEN, sizeof(arg->in.token), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.token) },
        { REGISTER_SEG_IN_FLAG, sizeof(arg->in.flag), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.flag) },
        { REGISTER_SEG_IN_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
        { REGISTER_SEG_OUT_TOKEN_ID, sizeof(arg->out.token_id), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.token_id) },
        { REGISTER_SEG_OUT_HANDLE, sizeof(arg->out.handle), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.handle) },
        { REGISTER_SEG_OUT_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
    };
}

inline urma_cmd_unregister_seg_t MakeUnregisterSegCmd()
{
    urma_cmd_unregister_seg_t arg = {};
    arg.in.handle = MOCK_HANDLE;
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedUnregisterSegAttrs(urma_cmd_unregister_seg_t *arg)
{
    return {
        { UNREGISTER_SEG_IN_HANDLE, sizeof(arg->in.handle), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.handle) },
    };
}

inline urma_cmd_import_seg_t MakeImportSegCmd()
{
    urma_cmd_import_seg_t arg = {};
    FillMockEid(arg.in.eid);
    arg.in.va = MOCK_SEG_VA;
    arg.in.len = MOCK_SEG_LEN;
    arg.in.flag = 2;
    arg.in.token = MOCK_TOKEN;
    arg.in.token_id = MOCK_TOKEN_ID;
    arg.in.mva = MOCK_SEG_MVA;
    arg.out.handle = MOCK_HANDLE;
    arg.udata = MakeUdata();
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedImportSegAttrs(urma_cmd_import_seg_t *arg)
{
    return {
        { IMPORT_SEG_IN_EID, sizeof(arg->in.eid), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.eid) },
        { IMPORT_SEG_IN_VA, sizeof(arg->in.va), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.va) },
        { IMPORT_SEG_IN_LEN, sizeof(arg->in.len), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.len) },
        { IMPORT_SEG_IN_FLAG, sizeof(arg->in.flag), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.flag) },
        { IMPORT_SEG_IN_TOKEN, sizeof(arg->in.token), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.token) },
        { IMPORT_SEG_IN_TOKEN_ID, sizeof(arg->in.token_id), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.token_id) },
        { IMPORT_SEG_IN_MVA, sizeof(arg->in.mva), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.mva) },
        { IMPORT_SEG_IN_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
        { IMPORT_SEG_OUT_HANDLE, sizeof(arg->out.handle), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.handle) },
        { IMPORT_SEG_OUT_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
    };
}

inline urma_cmd_create_jfs_t MakeCreateJfsCmd()
{
    urma_cmd_create_jfs_t arg = {};
    arg.in.depth = 128;
    arg.in.flag = 0x7;
    arg.in.trans_mode = URMA_TM_RC;
    arg.in.priority = 5;
    arg.in.max_sge = 3;
    arg.in.max_rsge = 2;
    arg.in.max_inline_data = 64;
    arg.in.retry_cnt = 1;
    arg.in.rnr_retry = 7;
    arg.in.err_timeout = 12;
    arg.in.jfc_id = MOCK_JFC_ID;
    arg.in.jfc_handle = MOCK_JFC_HANDLE;
    arg.in.urma_jfs = MOCK_JFS_PTR;
    arg.out.id = MOCK_JFS_ID;
    arg.out.depth = arg.in.depth;
    arg.out.max_sge = arg.in.max_sge;
    arg.out.max_rsge = arg.in.max_rsge;
    arg.out.max_inline_data = arg.in.max_inline_data;
    arg.out.handle = MOCK_HANDLE;
    arg.udata = MakeUdata();
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedCreateJfsAttrs(urma_cmd_create_jfs_t *arg)
{
    return {
        { CREATE_JFS_IN_DEPTH, sizeof(arg->in.depth), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.depth) },
        { CREATE_JFS_IN_FLAG, sizeof(arg->in.flag), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.flag) },
        { CREATE_JFS_IN_TRANS_MODE, sizeof(arg->in.trans_mode), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.trans_mode) },
        { CREATE_JFS_IN_PRIORITY, sizeof(arg->in.priority), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.priority) },
        { CREATE_JFS_IN_MAX_SGE, sizeof(arg->in.max_sge), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.max_sge) },
        { CREATE_JFS_IN_MAX_RSGE, sizeof(arg->in.max_rsge), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.max_rsge) },
        { CREATE_JFS_IN_MAX_INLINE_DATA, sizeof(arg->in.max_inline_data), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.max_inline_data) },
        { CREATE_JFS_IN_RETRY_CNT, sizeof(arg->in.retry_cnt), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.retry_cnt) },
        { CREATE_JFS_IN_RNR_RETRY, sizeof(arg->in.rnr_retry), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.rnr_retry) },
        { CREATE_JFS_IN_ERR_TIMEOUT, sizeof(arg->in.err_timeout), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.err_timeout) },
        { CREATE_JFS_IN_JFC_ID, sizeof(arg->in.jfc_id), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.jfc_id) },
        { CREATE_JFS_IN_JFC_HANDLE, sizeof(arg->in.jfc_handle), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.jfc_handle) },
        { CREATE_JFS_IN_URMA_JFS, sizeof(arg->in.urma_jfs), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.urma_jfs) },
        { CREATE_JFS_IN_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
        { CREATE_JFS_OUT_ID, sizeof(arg->out.id), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.id) },
        { CREATE_JFS_OUT_DEPTH, sizeof(arg->out.depth), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.depth) },
        { CREATE_JFS_OUT_MAX_SGE, sizeof(arg->out.max_sge), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.max_sge) },
        { CREATE_JFS_OUT_MAX_RSGE, sizeof(arg->out.max_rsge), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.max_rsge) },
        { CREATE_JFS_OUT_MAX_INLINE_DATA, sizeof(arg->out.max_inline_data), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.max_inline_data) },
        { CREATE_JFS_OUT_HANDLE, sizeof(arg->out.handle), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.handle) },
        { CREATE_JFS_OUT_UDATA, sizeof(arg->udata), 1, 0, reinterpret_cast<uintptr_t>(&arg->udata) },
    };
}

inline urma_cmd_query_jfs_t MakeQueryJfsCmd()
{
    urma_cmd_query_jfs_t arg = {};
    arg.in.handle = MOCK_HANDLE;
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedQueryJfsAttrs(urma_cmd_query_jfs_t *arg)
{
    return {
        { QUERY_JFS_IN_HANDLE, sizeof(arg->in.handle), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.handle) },
        { QUERY_JFS_OUT_DEPTH, sizeof(arg->out.depth), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.depth) },
        { QUERY_JFS_OUT_FLAG, sizeof(arg->out.flag), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.flag) },
        { QUERY_JFS_OUT_TRANS_MODE, sizeof(arg->out.trans_mode), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.trans_mode) },
        { QUERY_JFS_OUT_PRIORITY, sizeof(arg->out.priority), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.priority) },
        { QUERY_JFS_OUT_MAX_SGE, sizeof(arg->out.max_sge), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.max_sge) },
        { QUERY_JFS_OUT_MAX_RSGE, sizeof(arg->out.max_rsge), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.max_rsge) },
        { QUERY_JFS_OUT_MAX_INLINE_DATA, sizeof(arg->out.max_inline_data), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.max_inline_data) },
        { QUERY_JFS_OUT_RETRY_CNT, sizeof(arg->out.retry_cnt), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.retry_cnt) },
        { QUERY_JFS_OUT_RNR_RETRY, sizeof(arg->out.rnr_retry), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.rnr_retry) },
        { QUERY_JFS_OUT_ERR_TIMEOUT, sizeof(arg->out.err_timeout), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.err_timeout) },
        { QUERY_JFS_OUT_STATE, sizeof(arg->out.state), 1, 0, reinterpret_cast<uintptr_t>(&arg->out.state) },
    };
}

inline urma_cmd_delete_jfs_t MakeDeleteJfsCmd()
{
    urma_cmd_delete_jfs_t arg = {};
    arg.in.handle = MOCK_HANDLE;
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedDeleteJfsAttrs(urma_cmd_delete_jfs_t *arg)
{
    return {
        { DELETE_JFS_IN_HANDLE, sizeof(arg->in.handle), 1, 0, reinterpret_cast<uintptr_t>(&arg->in.handle) },
        { DELETE_JFS_OUT_ASYNC_EVENTS_REPORTED, sizeof(arg->out.async_events_reported), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.async_events_reported) },
    };
}

inline urma_cmd_delete_jfs_batch_t MakeDeleteJfsBatchCmd(urma_jfs_t **jfsArr, uint32_t jfsNum)
{
    urma_cmd_delete_jfs_batch_t arg = {};
    arg.in.jfs_num = jfsNum;
    arg.in.jfs_ptr = reinterpret_cast<uint64_t>(jfsArr);
    arg.out.bad_jfs_index = 1;
    return arg;
}

inline std::vector<ExpectedAttr> ExpectedDeleteJfsBatchAttrs(urma_cmd_delete_jfs_batch_t *arg)
{
    return {
        { DELETE_JFS_BATCH_OUT_ASYNC_EVENTS_REPORTED, sizeof(arg->out.async_events_reported), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.async_events_reported) },
        { DELETE_JFS_BATCH_OUT_BAD_JFS_INDEX, sizeof(arg->out.bad_jfs_index), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->out.bad_jfs_index) },
        { DELETE_JFS_BATCH_IN_JFS_COUNT, sizeof(arg->in.jfs_num), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.jfs_num) },
        { DELETE_JFS_BATCH_IN_JFS_PTR, sizeof(arg->in.jfs_ptr), 1, 0,
          reinterpret_cast<uintptr_t>(&arg->in.jfs_ptr) },
    };
}

inline void ExpectAttrsEqual(const urma_cmd_attr_t *attrs, const std::vector<ExpectedAttr> &expected)
{
    ASSERT_NE(nullptr, attrs);
    for (size_t i = 0; i < expected.size(); i++) {
        EXPECT_EQ(expected[i].type, attrs[i].type) << "attr index " << i;
        EXPECT_EQ(0, attrs[i].flag) << "attr index " << i;
        EXPECT_EQ(expected[i].fieldSize, attrs[i].field_size) << "attr index " << i;
        EXPECT_EQ(expected[i].elNum, attrs[i].attr_data.bs.el_num) << "attr index " << i;
        EXPECT_EQ(expected[i].elSize, attrs[i].attr_data.bs.el_size) << "attr index " << i;
        EXPECT_EQ(expected[i].data, attrs[i].data) << "attr index " << i;
    }
}

} // namespace urma_test

#endif // TEST_URMA_INCLUDE_URMA_CMD_MOCK_H
