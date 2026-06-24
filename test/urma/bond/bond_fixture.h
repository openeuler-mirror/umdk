/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding unit test helpers.
 */

#ifndef TEST_URMA_BOND_BOND_FIXTURE_H
#define TEST_URMA_BOND_BOND_FIXTURE_H

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <atomic>
#include <cerrno>
#include <dlfcn.h>
#include <vector>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <netlink/handlers.h>
#include <netlink/errno.h>
#include <netlink/msg.h>

#include <gtest/gtest.h>

#include "bondp_api.h"
#include "bondp_connection.h"
#include "bondp_context_table.h"
#include "bondp_datapath.h"
#include "bondp_datapath_convert.h"
#include "bondp_datapath_schedule.h"
#include "bondp_hash_table.h"
#include "bondp_health_check.h"
#include "bondp_failback.h"
#include "bondp_link_recovery.h"
#include "bondp_netlink.h"
#include "bondp_provider_ops.h"
#include "bondp_segment.h"
#include "bondp_slide_window.h"
#include "bondp_timewheel.h"
#include "bondp_types.h"
#include "bondp_worker.h"
#include "bondp_wr_buf.h"
#include "ubagg_ioctl.h"
#include "urma_cmd_tlv.h"
#include "urma_provider.h"
#include "urma_private.h"
#include "urma_hw_mock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"


namespace urma_test_bond {

extern bool g_mockEpollCreateFail;
extern bool g_mockEpollCreate1Fail;
extern bool g_mockEpollCtlFail;
extern bool g_mockEventfdFail;
extern bool g_mockPthreadCreateFail;
extern urma_device_t *g_mockNamedDevice;
extern urma_ops_t *g_mockCreateContextOps;
extern int g_mockCreateContextCount;
extern bool g_mockCreateContextFail;
extern bool g_mockCreateContextBadFd;
extern bool g_mockDeleteContextFail;
extern bool g_mockUserCtlFail;
extern bool g_mockNetlink;
extern bool g_mockNetlinkAllocFail;
extern bool g_mockNetlinkConnectFail;
extern bool g_mockNetlinkResolveFail;
extern struct nl_sock *g_mockNetlinkSock;
extern int g_mockNetlinkFd;
extern int g_mockNetlinkRecvReturn;
extern int g_mockNetlinkRecvCount;
extern size_t g_mockCallocFailNmemb;

void ResetMockNetlinkCallback();
int InvokeMockNetlinkMsg(bondp_nl_cmd_t cmd, const void *payload, size_t payloadLen);

struct BondProviderMockGuard {
    bondp_global_context_t *savedGlobalCtx;
    urma_device_t *savedNamedDevice;
    urma_ops_t *savedCreateContextOps;
    int savedCreateContextCount;
    bool savedEpollCreateFail;
    bool savedEpollCreate1Fail;
    bool savedEpollCtlFail;
    bool savedEventfdFail;
    bool savedPthreadCreateFail;
    bool savedCreateContextFail;
    bool savedCreateContextBadFd;
    bool savedDeleteContextFail;
    bool savedUserCtlFail;
    bool savedNetlink;
    bool savedNetlinkAllocFail;
    bool savedNetlinkConnectFail;
    bool savedNetlinkResolveFail;
    int savedNetlinkFd;
    int savedNetlinkRecvReturn;
    int savedNetlinkRecvCount;
    size_t savedCallocFailNmemb;

    BondProviderMockGuard(bondp_global_context_t *globalCtx, urma_device_t *namedDevice, urma_ops_t *createContextOps)
        : savedGlobalCtx(g_bondp_global_ctx),
          savedNamedDevice(g_mockNamedDevice),
          savedCreateContextOps(g_mockCreateContextOps),
          savedCreateContextCount(g_mockCreateContextCount),
          savedEpollCreateFail(g_mockEpollCreateFail),
          savedEpollCreate1Fail(g_mockEpollCreate1Fail),
          savedEpollCtlFail(g_mockEpollCtlFail),
          savedEventfdFail(g_mockEventfdFail),
          savedPthreadCreateFail(g_mockPthreadCreateFail),
          savedCreateContextFail(g_mockCreateContextFail),
          savedCreateContextBadFd(g_mockCreateContextBadFd),
          savedDeleteContextFail(g_mockDeleteContextFail),
          savedUserCtlFail(g_mockUserCtlFail),
          savedNetlink(g_mockNetlink),
          savedNetlinkAllocFail(g_mockNetlinkAllocFail),
          savedNetlinkConnectFail(g_mockNetlinkConnectFail),
          savedNetlinkResolveFail(g_mockNetlinkResolveFail),
          savedNetlinkFd(g_mockNetlinkFd),
          savedNetlinkRecvReturn(g_mockNetlinkRecvReturn),
          savedNetlinkRecvCount(g_mockNetlinkRecvCount),
          savedCallocFailNmemb(g_mockCallocFailNmemb)
    {
        g_bondp_global_ctx = globalCtx;
        g_mockNamedDevice = namedDevice;
        g_mockCreateContextOps = createContextOps;
        g_mockCreateContextCount = 0;
        g_mockEpollCreateFail = false;
        g_mockEpollCreate1Fail = false;
        g_mockEpollCtlFail = false;
        g_mockEventfdFail = false;
        g_mockPthreadCreateFail = false;
        g_mockCreateContextFail = false;
        g_mockCreateContextBadFd = false;
        g_mockDeleteContextFail = false;
        g_mockUserCtlFail = false;
        g_mockNetlink = false;
        g_mockNetlinkAllocFail = false;
        g_mockNetlinkConnectFail = false;
        g_mockNetlinkResolveFail = false;
        g_mockNetlinkFd = -1;
        g_mockNetlinkRecvReturn = 0;
        g_mockNetlinkRecvCount = 0;
        g_mockCallocFailNmemb = 0;
        ResetMockNetlinkCallback();
    }

    ~BondProviderMockGuard()
    {
        g_bondp_global_ctx = savedGlobalCtx;
        g_mockNamedDevice = savedNamedDevice;
        g_mockCreateContextOps = savedCreateContextOps;
        g_mockCreateContextCount = savedCreateContextCount;
        g_mockEpollCreateFail = savedEpollCreateFail;
        g_mockEpollCreate1Fail = savedEpollCreate1Fail;
        g_mockEpollCtlFail = savedEpollCtlFail;
        g_mockEventfdFail = savedEventfdFail;
        g_mockPthreadCreateFail = savedPthreadCreateFail;
        g_mockCreateContextFail = savedCreateContextFail;
        g_mockCreateContextBadFd = savedCreateContextBadFd;
        g_mockDeleteContextFail = savedDeleteContextFail;
        g_mockUserCtlFail = savedUserCtlFail;
        g_mockNetlink = savedNetlink;
        g_mockNetlinkAllocFail = savedNetlinkAllocFail;
        g_mockNetlinkConnectFail = savedNetlinkConnectFail;
        g_mockNetlinkResolveFail = savedNetlinkResolveFail;
        g_mockNetlinkFd = savedNetlinkFd;
        g_mockNetlinkRecvReturn = savedNetlinkRecvReturn;
        g_mockNetlinkRecvCount = savedNetlinkRecvCount;
        g_mockCallocFailNmemb = savedCallocFailNmemb;
        ResetMockNetlinkCallback();
    }
};

struct BondTopoMapCleanup {
    bondp_global_context_t *globalCtx;

    explicit BondTopoMapCleanup(bondp_global_context_t *ctx) : globalCtx(ctx)
    {
    }

    ~BondTopoMapCleanup()
    {
        auto *sentinel = reinterpret_cast<topo_map_t *>(0x1);

        if (globalCtx != nullptr && globalCtx->topo_map != nullptr && globalCtx->topo_map != sentinel) {
            delete_topo_map(globalCtx->topo_map);
            globalCtx->topo_map = nullptr;
        }
    }
};

inline uint64_t ReadAttrValue(const urma_cmd_attr_t &attr)
{
    uint64_t value = 0;

    if (attr.data == 0 || attr.field_size == 0 || attr.field_size > sizeof(value)) {
        return 0;
    }
    std::memcpy(&value, reinterpret_cast<void *>(attr.data), attr.field_size);
    return value;
}

inline void WriteAttrValue(const urma_cmd_attr_t &attr, uint64_t value)
{
    if (attr.data == 0 || attr.field_size == 0 || attr.field_size > sizeof(value)) {
        return;
    }
    std::memcpy(reinterpret_cast<void *>(attr.data), &value, attr.field_size);
}

inline void FillMockBondIdInfo(uint64_t outAddr, uint32_t outLen)
{
    if (outAddr == 0 || outLen < sizeof(urma_bond_id_info_out_t)) {
        return;
    }

    auto *out = reinterpret_cast<urma_bond_id_info_out_t *>(outAddr);
    out->enabled_count = 1;
    out->enabled_indices[0] = 0;
    out->slave_id[0].id = urma_test::GetHwMockState().ioctlId + 1;
    out->slave_id[0].eid.in6.subnet_prefix = 0x11110000ULL;
    out->slave_id[0].eid.in6.interface_id = 0x22220000ULL;
    out->connected[0][0] = true;
}

inline void FillMockSegInfo(uint64_t outAddr, uint32_t outLen)
{
    size_t minLen = sizeof(urma_bond_seg_info_out_t) +
                    sizeof(bool) * URMA_UBAGG_DEV_MAX_NUM * URMA_UBAGG_DEV_MAX_NUM;

    if (outAddr == 0 || outLen < minLen) {
        return;
    }

    auto *out = reinterpret_cast<urma_bond_seg_info_out_t *>(outAddr);
    out->slaves[0].ubva.va = 0xabc000ULL;
    out->slaves[0].ubva.eid.in6.subnet_prefix = 0x33330000ULL;
    out->slaves[0].ubva.eid.in6.interface_id = 0x44440000ULL;
    out->slaves[0].len = 4096;
    out->slaves[0].token_id = 0x55;

    auto *connected = reinterpret_cast<bool *>(reinterpret_cast<char *>(out) + sizeof(*out));
    connected[0] = true;
}

inline void FillMockPhysicalDeviceInfo(uint64_t outAddr, uint32_t outLen)
{
    if (outAddr == 0 || outLen < sizeof(bondp_userctl_physical_device_out_t)) {
        return;
    }

    auto *out = reinterpret_cast<bondp_userctl_physical_device_out_t *>(outAddr);
    out->physical_dev_num = 1;
    std::snprintf(out->physical_devs[0].dev_name, sizeof(out->physical_devs[0].dev_name), "mock_phy0");
    out->physical_devs[0].primary_eid_idx = UINT32_MAX;
    for (uint32_t i = 0; i < PORT_NUM; i++) {
        out->physical_devs[0].port_eid_idx[i] = UINT32_MAX;
    }
    out->physical_devs[0].port_eid_idx[0] = 0;
}

inline void FillMockTopoInfo(uint64_t outAddr, uint32_t outLen)
{
    if (outAddr == 0 || outLen < sizeof(ubagg_topo_info_out)) {
        return;
    }

    auto *out = reinterpret_cast<ubagg_topo_info_out *>(outAddr);
    out->node_num = 1;
    out->topo_info[0].is_current = true;
    auto *aggEid = reinterpret_cast<urma_eid_t *>(out->topo_info[0].agg_devs[0].agg_eid);
    aggEid->in6.subnet_prefix = 0x51510000ULL;
    aggEid->in6.interface_id = 0x61610000ULL;
}

inline void FillUserCtlOutput(urma_cmd_attr_t *attrs, uint32_t attrCount)
{
    uint32_t opcode = 0;
    uint64_t outAddr = 0;
    uint32_t outLen = 0;

    for (uint32_t i = 0; i < attrCount; i++) {
        if (attrs[i].type == USER_CTL_IN_OPCODE) {
            opcode = static_cast<uint32_t>(ReadAttrValue(attrs[i]));
        } else if (attrs[i].type == USER_CTL_IN_OUT_ADDR) {
            outAddr = ReadAttrValue(attrs[i]);
        } else if (attrs[i].type == USER_CTL_IN_OUT_LEN) {
            outLen = static_cast<uint32_t>(ReadAttrValue(attrs[i]));
        }
    }

    if (opcode == GET_SLAVE_DEVICE) {
        FillMockPhysicalDeviceInfo(outAddr, outLen);
    } else if (opcode == GET_TOPO_INFO) {
        FillMockTopoInfo(outAddr, outLen);
    } else if (opcode == GET_RJETTY) {
        FillMockBondIdInfo(outAddr, outLen);
    } else if (opcode == GET_SEG_CTX) {
        FillMockSegInfo(outAddr, outLen);
    }
}

inline void FillCreateOutput(uint32_t command, urma_cmd_attr_t *attrs, uint32_t attrCount)
{
    for (uint32_t i = 0; i < attrCount; i++) {
        uint8_t type = attrs[i].type;

        if ((command == URMA_CMD_CREATE_JFC && type == CREATE_JFC_OUT_ID) ||
            (command == URMA_CMD_CREATE_JFS && type == CREATE_JFS_OUT_ID) ||
            (command == URMA_CMD_CREATE_JFR && type == CREATE_JFR_OUT_ID) ||
            (command == URMA_CMD_CREATE_JETTY && type == CREATE_JETTY_OUT_ID) ||
            (command == URMA_CMD_REGISTER_SEG && type == REGISTER_SEG_OUT_TOKEN_ID)) {
            WriteAttrValue(attrs[i], urma_test::GetHwMockState().ioctlId);
        } else if ((command == URMA_CMD_CREATE_JFC && type == CREATE_JFC_OUT_HANDLE) ||
            (command == URMA_CMD_CREATE_JFS && type == CREATE_JFS_OUT_HANDLE) ||
            (command == URMA_CMD_CREATE_JFR && type == CREATE_JFR_OUT_HANDLE) ||
            (command == URMA_CMD_CREATE_JETTY && type == CREATE_JETTY_OUT_HANDLE) ||
            (command == URMA_CMD_REGISTER_SEG && type == REGISTER_SEG_OUT_HANDLE) ||
            (command == URMA_CMD_IMPORT_JETTY && type == IMPORT_JETTY_OUT_HANDLE) ||
            (command == URMA_CMD_IMPORT_JFR && type == IMPORT_JFR_OUT_HANDLE)) {
            WriteAttrValue(attrs[i], urma_test::GetHwMockState().ioctlHandle);
        } else if ((command == URMA_CMD_IMPORT_JETTY && type == IMPORT_JETTY_OUT_UDATA) ||
            (command == URMA_CMD_IMPORT_JFR && type == IMPORT_JFR_OUT_UDATA)) {
            auto *udata = reinterpret_cast<urma_cmd_udrv_priv_t *>(attrs[i].data);
            if (udata != nullptr) {
                FillMockBondIdInfo(udata->out_addr, udata->out_len);
            }
        } else if (command == URMA_CMD_CREATE_CTX && type == CREATE_CTX_OUT_ASYNC_FD) {
            int asyncFd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

            WriteAttrValue(attrs[i], static_cast<uint64_t>(asyncFd));
        } else if ((command == URMA_CMD_DELETE_JFC || command == URMA_CMD_DELETE_JFS ||
            command == URMA_CMD_DELETE_JFR || command == URMA_CMD_DELETE_JETTY) &&
            type >= URMA_CMD_OUT_TYPE_INIT) {
            WriteAttrValue(attrs[i], 0);
        } else if (type >= URMA_CMD_OUT_TYPE_INIT) {
            WriteAttrValue(attrs[i], 1);
        }
    }
}

static const uint32_t BOND_TEST_RECV_BATCH_POST_MAX_NUM = 280;
static constexpr uint8_t BOND_TEST_FALLBACK_CTRL_REQ = 1;
static constexpr uint8_t BOND_TEST_FALLBACK_CTRL_RESP = 2;

struct BondPathFixture {
    bondp_context_t ctx = {};
    urma_device_t dev = {};
    urma_sysfs_dev_t sysfsDev = {};
    urma_context_t phyCtx = {};
    urma_ops_t phyOps = {};
    urma_jfc_t phyJfc = {};
    bondp_comp_t comp = {};
    bondp_target_jetty_t target = {};
    urma_jfs_t phyJfs[2] = {};
    urma_jfr_t phyJfr[2] = {};
    urma_jetty_t phyJetty[2] = {};
    urma_target_jetty_t phyTarget[2][2] = {};
    bondp_tseg_t localSeg = {};
    bondp_import_tseg_t remoteSeg = {};
    urma_target_seg_t localPhy[2] = {};
    urma_target_seg_t remotePhy[2][2] = {};
    urma_sge_t srcSge[1] = {};
    urma_sge_t dstSge[1] = {};
    bondp_global_context_t globalCtx = {};
    bondp_global_context_t *savedGlobalCtx = nullptr;

    BondPathFixture()
    {
        urma_test::ResetHwMockState();
        /* Build a two-path virtual topology without creating real URMA devices. */
        savedGlobalCtx = g_bondp_global_ctx;
        g_bondp_global_ctx = &globalCtx;
        globalCtx.enable_failover = true;
        std::snprintf(dev.name, sizeof(dev.name), "bond_path_ut");
        sysfsDev.dev_attr.dev_cap.max_jfc_depth = 8;
        sysfsDev.dev_attr.dev_cap.max_jfs_depth = 8;
        sysfsDev.dev_attr.dev_cap.max_jfr_depth = 8;
        sysfsDev.dev_attr.dev_cap.max_jfs_inline_len = 64;
        sysfsDev.dev_attr.dev_cap.max_jfs_sge = 8;
        sysfsDev.dev_attr.dev_cap.max_jfs_rsge = 8;
        sysfsDev.dev_attr.dev_cap.max_jfr_sge = 8;
        dev.sysfs_dev = &sysfsDev;
        ctx.v_ctx.dev = &dev;
        ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
        ctx.bonding_level = BONDP_BONDING_LEVEL_IODIE;
        ctx.msn_enable = true;
        phyCtx.dev = &dev;
        phyCtx.ops = &phyOps;
        phyJfc.urma_ctx = &phyCtx;
        comp.bondp_ctx = &ctx;
        comp.comp_type = BONDP_COMP_JETTY;
        comp.v_jfs.jfs_cfg.trans_mode = URMA_TM_RC;
        comp.v_jfs.jfs_cfg.flag.bs.order_type = URMA_OL;
        comp.v_jfr.jfr_cfg.trans_mode = URMA_TM_RC;
        comp.v_jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
        comp.v_jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
        comp.v_jetty.jetty_cfg.jfs_cfg.flag.bs.order_type = URMA_OL;
        comp.v_jetty.jetty_id.id = 0x22;
        comp.v_jfs.jfs_id.id = 0x23;
        comp.v_jfr.jfr_id.id = 0x24;
        comp.active_count = 2;
        comp.active_indices[0] = 0;
        comp.active_indices[1] = 1;
        comp.valid[0] = true;
        comp.valid[1] = true;
        phyJfs[0].urma_ctx = &phyCtx;
        phyJfs[1].urma_ctx = &phyCtx;
        phyJfs[0].jfs_cfg.jfc = &phyJfc;
        phyJfs[1].jfs_cfg.jfc = &phyJfc;
        phyJfs[0].jfs_cfg.trans_mode = URMA_TM_RC;
        phyJfs[1].jfs_cfg.trans_mode = URMA_TM_RC;
        phyJfs[0].jfs_cfg.flag.bs.order_type = URMA_OL;
        phyJfs[1].jfs_cfg.flag.bs.order_type = URMA_OL;
        phyJfr[0].urma_ctx = &phyCtx;
        phyJfr[1].urma_ctx = &phyCtx;
        phyJfr[0].jfr_cfg.jfc = &phyJfc;
        phyJfr[1].jfr_cfg.jfc = &phyJfc;
        phyJfr[0].jfr_cfg.trans_mode = URMA_TM_RC;
        phyJfr[1].jfr_cfg.trans_mode = URMA_TM_RC;
        phyJfr[0].jfr_cfg.flag.bs.order_type = URMA_OL;
        phyJfr[1].jfr_cfg.flag.bs.order_type = URMA_OL;
        phyJetty[0].urma_ctx = &phyCtx;
        phyJetty[1].urma_ctx = &phyCtx;
        phyJetty[0].jetty_id.id = 0x25;
        phyJetty[1].jetty_id.id = 0x26;
        comp.p_jfs[0] = &phyJfs[0];
        comp.p_jfs[1] = &phyJfs[1];
        comp.p_jfr[0] = &phyJfr[0];
        comp.p_jfr[1] = &phyJfr[1];
        comp.p_jetty[0] = &phyJetty[0];
        comp.p_jetty[1] = &phyJetty[1];

        target.active_count = 2;
        target.active_indices[0] = 0;
        target.active_indices[1] = 1;
        target.valid[0] = true;
        target.valid[1] = true;
        target.p_tjetty[0][0] = &phyTarget[0][0];
        target.p_tjetty[1][1] = &phyTarget[1][1];
        comp.p_jetty[0]->remote_jetty = &phyTarget[0][0];
        comp.p_jetty[1]->remote_jetty = &phyTarget[1][1];

        localSeg.v_tseg.token_id = reinterpret_cast<urma_token_id_t *>(this);
        localSeg.p_tseg[0] = &localPhy[0];
        localSeg.p_tseg[1] = &localPhy[1];
        localPhy[0].handle = reinterpret_cast<uint64_t>(&localSeg.v_tseg);
        localPhy[1].handle = reinterpret_cast<uint64_t>(&localSeg.v_tseg);

        remoteSeg.p_tseg[0][0] = &remotePhy[0][0];
        remoteSeg.p_tseg[1][1] = &remotePhy[1][1];
        remotePhy[0][0].handle = reinterpret_cast<uint64_t>(&remoteSeg.v_tseg);
        remotePhy[1][1].handle = reinterpret_cast<uint64_t>(&remoteSeg.v_tseg);

        srcSge[0].tseg = &localSeg.v_tseg;
        dstSge[0].tseg = &remoteSeg.v_tseg;
    }

    ~BondPathFixture()
    {
        g_bondp_global_ctx = savedGlobalCtx;
    }

    urma_jfs_wr_t MakeSendWr(urma_opcode_t opcode)
    {
        urma_jfs_wr_t wr = {};
        wr.opcode = opcode;
        wr.tjetty = &target.v_tjetty;
        wr.send.src.sge = srcSge;
        wr.send.src.num_sge = 1;
        wr.send.imm_data = 0x123456789ULL;
        return wr;
    }

    urma_jfs_wr_t MakeRwWr(urma_opcode_t opcode)
    {
        urma_jfs_wr_t wr = {};
        wr.opcode = opcode;
        wr.tjetty = &target.v_tjetty;
        wr.rw.src.sge = srcSge;
        wr.rw.src.num_sge = 1;
        wr.rw.dst.sge = dstSge;
        wr.rw.dst.num_sge = 1;
        wr.rw.notify_data = 0xabcdefULL;
        return wr;
    }
};

inline void SetRefCount(urma_ref_t *ref, unsigned long value)
{
    ref->atomic_cnt.store(value);
}

static urma_jfc_t *MockCreatePhysicalJfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg);
static urma_status_t MockModifyPhysicalJfc(urma_jfc_t *jfc, urma_jfc_attr_t *attr);
static urma_status_t MockDeletePhysicalJfc(urma_jfc_t *jfc);
static urma_jfs_t *MockCreatePhysicalJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg);
static urma_status_t MockModifyPhysicalJfs(urma_jfs_t *jfs, urma_jfs_attr_t *attr);
static urma_status_t MockDeletePhysicalJfs(urma_jfs_t *jfs);
static urma_jfr_t *MockCreatePhysicalJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg);
static urma_status_t MockModifyPhysicalJfr(urma_jfr_t *jfr, urma_jfr_attr_t *attr);
static urma_status_t MockQueryPhysicalJfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr);
static urma_status_t MockDeletePhysicalJfr(urma_jfr_t *jfr);
static urma_jetty_t *MockCreatePhysicalJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg);
static urma_status_t MockModifyPhysicalJetty(urma_jetty_t *jetty, urma_jetty_attr_t *attr);
static urma_status_t MockDeletePhysicalJetty(urma_jetty_t *jetty);
static urma_target_seg_t *MockRegisterPhysicalSeg(urma_context_t *ctx, urma_seg_cfg_t *cfg);
static urma_status_t MockUnregisterPhysicalSeg(urma_target_seg_t *seg);
static urma_target_seg_t *MockImportPhysicalSeg(urma_context_t *ctx, urma_seg_t *seg, urma_token_t *token,
                                                uint64_t addr, urma_import_seg_flag_t flag);
static urma_status_t MockUnimportPhysicalSeg(urma_target_seg_t *seg);
static urma_target_jetty_t *MockImportPhysicalJetty(urma_context_t *ctx, urma_rjetty_t *rjetty,
                                                    urma_token_t *token);
static urma_target_jetty_t *MockImportPhysicalJfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *token);
static urma_status_t MockUnimportPhysicalJetty(urma_target_jetty_t *target);

struct BondPublicApiFixture {
    bondp_context_t ctx = {};
    bondp_context_t otherBondCtx = {};
    urma_context_t phyCtx = {};
    urma_ops_t phyOps = {};
    urma_device_t dev = {};
    urma_device_t phyDev = {};
    urma_sysfs_dev_t sysfsDev = {};
    bondp_jfc_t jfc = {};
    bondp_jfce_t jfce = {};
    urma_jfce_t phyJfce[2] = {};
    urma_jfc_t phyJfc = {};
    urma_jfs_t phyJfs = {};
    urma_jfr_t phyJfr = {};
    urma_jetty_t phyJetty[2] = {};
    bondp_comp_t jfs = {};
    bondp_comp_t jfr = {};
    bondp_comp_t jetty = {};
    bondp_target_jetty_t targetJetty = {};
    bondp_target_jetty_t targetJfr = {};

    BondPublicApiFixture()
    {
        urma_test::ResetHwMockState();
        /* Public API smoke tests exercise stable outer branches; provider/device paths stay mocked by zero members. */
        std::snprintf(dev.name, sizeof(dev.name), "bond_ut");
        std::snprintf(phyDev.name, sizeof(phyDev.name), "bond_phy_ut");
        sysfsDev.dev_attr.dev_cap.max_jfc_depth = 8;
        sysfsDev.dev_attr.dev_cap.max_jfs_depth = 8;
        sysfsDev.dev_attr.dev_cap.max_jfr_depth = 8;
        sysfsDev.dev_attr.dev_cap.max_jfs_inline_len = 64;
        sysfsDev.dev_attr.dev_cap.max_jfs_sge = 8;
        sysfsDev.dev_attr.dev_cap.max_jfs_rsge = 8;
        sysfsDev.dev_attr.dev_cap.max_jfr_sge = 8;
        dev.sysfs_dev = &sysfsDev;
        otherBondCtx.v_ctx.dev = &dev;
        ctx.dev_num = 0;
        ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
        ctx.bonding_level = BONDP_BONDING_LEVEL_IODIE;
        ctx.v_ctx.dev = &dev;
        ctx.v_ctx.dev_fd = -1;
        ctx.v_ctx.async_fd = -1;
        phyDev.sysfs_dev = &sysfsDev;
        phyCtx.dev = &phyDev;
        phyCtx.ops = &phyOps;
        phyCtx.eid_index = 0;
        phyCtx.ref.atomic_cnt.store(1);
        pthread_rwlock_init(&ctx.p_vjetty_id_table.lock, nullptr);

        jfce.bondp_ctx = &ctx;
        jfce.v_jfce.fd = -1;
        SetRefCount(&jfce.use_cnt, 1);

        jfc.dev_num = 0;
        jfc.v_jfc.urma_ctx = &ctx.v_ctx;
        jfc.v_jfc.jfc_cfg.jfce = &jfce.v_jfce;
        SetRefCount(&jfc.use_cnt, 1);

        InitComp(&jfs, BONDP_COMP_JFS);
        jfs.v_jfs.jfs_cfg.jfc = &jfc.v_jfc;

        InitComp(&jfr, BONDP_COMP_JFR);
        jfr.v_jfr.jfr_cfg.jfc = &jfc.v_jfc;

        InitComp(&jetty, BONDP_COMP_JETTY);
        jetty.v_jetty.urma_ctx = &ctx.v_ctx;
        jetty.v_jetty.jetty_cfg.shared.jfr = &jfr.v_jfr;

        targetJetty.v_tjetty.urma_ctx = &ctx.v_ctx;
        targetJetty.v_tjetty.type = URMA_JETTY;
        SetRefCount(&targetJetty.use_cnt, 2);

        targetJfr.v_tjetty.urma_ctx = &ctx.v_ctx;
        targetJfr.v_tjetty.type = URMA_JFR;
        SetRefCount(&targetJfr.use_cnt, 2);
    }

    ~BondPublicApiFixture()
    {
        pthread_rwlock_destroy(&ctx.p_vjetty_id_table.lock);
    }

    void InitComp(bondp_comp_t *comp, bondp_comp_type_t type)
    {
        comp->bondp_ctx = &ctx;
        comp->comp_type = type;
        SetRefCount(&comp->use_cnt, 1);
    }

    void InitActiveComp(bondp_comp_t *comp, uint32_t firstIndex)
    {
        comp->enabled_count = 1;
        comp->active_count = 1;
        comp->enabled_indices[0] = firstIndex;
        comp->active_indices[0] = firstIndex;
    }

    void InitJfceFdList()
    {
        jfce.dev_num = 2;
        phyJfce[0].fd = 10;
        phyJfce[1].fd = 11;
        jfce.p_jfce[0] = &phyJfce[0];
        jfce.p_jfce[1] = &phyJfce[1];
    }

    void InitSinglePhysicalMember()
    {
        ctx.dev_num = 1;
        ctx.p_ctxs[0] = &phyCtx;
        jfc.dev_num = 1;
        phyOps.create_jfc = MockCreatePhysicalJfc;
        phyOps.modify_jfc = MockModifyPhysicalJfc;
        phyOps.delete_jfc = MockDeletePhysicalJfc;
        phyOps.create_jfs = MockCreatePhysicalJfs;
        phyOps.modify_jfs = MockModifyPhysicalJfs;
        phyOps.delete_jfs = MockDeletePhysicalJfs;
        phyOps.create_jfr = MockCreatePhysicalJfr;
        phyOps.modify_jfr = MockModifyPhysicalJfr;
        phyOps.query_jfr = MockQueryPhysicalJfr;
        phyOps.delete_jfr = MockDeletePhysicalJfr;
        phyOps.create_jetty = MockCreatePhysicalJetty;
        phyOps.modify_jetty = MockModifyPhysicalJetty;
        phyOps.delete_jetty = MockDeletePhysicalJetty;
        phyOps.alloc_token_id = bondp_alloc_token_id;
        phyOps.free_token_id = bondp_free_token_id;
        phyOps.register_seg = MockRegisterPhysicalSeg;
        phyOps.unregister_seg = MockUnregisterPhysicalSeg;
        phyOps.import_seg = MockImportPhysicalSeg;
        phyOps.unimport_seg = MockUnimportPhysicalSeg;
        phyOps.import_jetty = MockImportPhysicalJetty;
        phyOps.import_jfr = MockImportPhysicalJfr;
        phyOps.unimport_jetty = MockUnimportPhysicalJetty;
        phyOps.unimport_jfr = MockUnimportPhysicalJetty;
        phyJfce[0].urma_ctx = &phyCtx;
        phyJfc.urma_ctx = &phyCtx;
        phyJfc.jfc_id.id = 0x404;
        phyJfs.urma_ctx = &phyCtx;
        phyJfs.jfs_id.id = 0x408;
        phyJfs.jfs_cfg.jfc = &phyJfc;
        phyJfs.jfs_cfg.trans_mode = URMA_TM_RC;
        phyJfs.jfs_cfg.flag.bs.order_type = URMA_OL;
        phyJfr.urma_ctx = &phyCtx;
        phyJfr.jfr_id.id = 0x405;
        phyJfr.jfr_cfg.jfc = &phyJfc;
        phyJfr.jfr_cfg.trans_mode = URMA_TM_RC;
        phyJfr.jfr_cfg.flag.bs.order_type = URMA_OL;
        phyJetty[0].urma_ctx = &phyCtx;
        phyJetty[1].urma_ctx = &phyCtx;
        phyJetty[0].jetty_id.id = 0x406;
        phyJetty[1].jetty_id.id = 0x407;
        jfc.p_jfc[0] = &phyJfc;
        jfs.p_jfs[0] = &phyJfs;
        jfr.p_jfr[0] = &phyJfr;
        jetty.p_jetty[0] = &phyJetty[0];
    }
};

inline urma_user_ctl_in_t MakeUserCtl(uint32_t opcode, void *addr, uint32_t len)
{
    urma_user_ctl_in_t in = {};

    in.opcode = opcode;
    in.addr = reinterpret_cast<uint64_t>(addr);
    in.len = len;
    return in;
}

inline urma_user_ctl_out_t MakeUserCtlOut(void *addr, uint32_t len)
{
    urma_user_ctl_out_t out = {};

    out.addr = reinterpret_cast<uint64_t>(addr);
    out.len = len;
    return out;
}

inline int CallBondUserCtl(urma_context_t *ctx, uint32_t opcode, void *addr, uint32_t len,
                           urma_user_ctl_out_t *out)
{
    urma_user_ctl_in_t in = MakeUserCtl(opcode, addr, len);

    return bondp_user_ctl(ctx, &in, out);
}

static urma_jfce_t *MockCreatePhysicalJfce(urma_context_t *ctx);
static urma_status_t MockDeletePhysicalJfce(urma_jfce_t *jfce);

inline urma_jfce_t *MockCreatePhysicalJfce(urma_context_t *ctx)
{
    urma_jfce_t *jfce = static_cast<urma_jfce_t *>(std::calloc(1, sizeof(*jfce)));
    if (jfce == nullptr) {
        return nullptr;
    }
    jfce->urma_ctx = ctx;
    jfce->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (jfce->fd < 0) {
        std::free(jfce);
        return nullptr;
    }
    return jfce;
}

inline urma_jfce_t *MockCreatePhysicalJfceNull(urma_context_t *)
{
    return nullptr;
}

inline urma_jfce_t *MockCreatePhysicalJfceBadFd(urma_context_t *ctx)
{
    auto *jfce = static_cast<urma_jfce_t *>(std::calloc(1, sizeof(urma_jfce_t)));

    if (jfce == nullptr) {
        return nullptr;
    }
    jfce->urma_ctx = ctx;
    jfce->fd = -1;
    return jfce;
}

inline urma_status_t MockDeletePhysicalJfce(urma_jfce_t *jfce)
{
    if (jfce == nullptr) {
        return URMA_EINVAL;
    }
    if (jfce->fd >= 0) {
        (void)close(jfce->fd);
    }
    std::free(jfce);
    return urma_test::GetHwMockState().status;
}

inline urma_jfc_t *MockCreatePhysicalJfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
{
    urma_jfc_t *jfc = static_cast<urma_jfc_t *>(std::calloc(1, sizeof(urma_jfc_t)));
    if (jfc == nullptr) {
        return nullptr;
    }
    jfc->urma_ctx = ctx;
    jfc->jfc_cfg = *cfg;
    jfc->jfc_id.id = 0x101;
    return jfc;
}

inline urma_status_t MockModifyPhysicalJfc(urma_jfc_t *, urma_jfc_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeletePhysicalJfc(urma_jfc_t *jfc)
{
    std::free(jfc);
    return urma_test::GetHwMockState().status;
}

inline urma_jfs_t *MockCreatePhysicalJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
    urma_jfs_t *jfs = static_cast<urma_jfs_t *>(std::calloc(1, sizeof(urma_jfs_t)));
    if (jfs == nullptr) {
        return nullptr;
    }
    jfs->urma_ctx = ctx;
    jfs->jfs_cfg = *cfg;
    jfs->jfs_id.id = 0x202;
    return jfs;
}

inline urma_status_t MockModifyPhysicalJfs(urma_jfs_t *, urma_jfs_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeletePhysicalJfs(urma_jfs_t *jfs)
{
    std::free(jfs);
    return urma_test::GetHwMockState().status;
}

inline urma_jfr_t *MockCreatePhysicalJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
{
    urma_jfr_t *jfr = static_cast<urma_jfr_t *>(std::calloc(1, sizeof(urma_jfr_t)));
    if (jfr == nullptr) {
        return nullptr;
    }
    jfr->urma_ctx = ctx;
    jfr->jfr_cfg = *cfg;
    jfr->jfr_id.id = 0x303;
    return jfr;
}

inline urma_status_t MockModifyPhysicalJfr(urma_jfr_t *, urma_jfr_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockQueryPhysicalJfr(urma_jfr_t *jfr, urma_jfr_cfg_t *cfg, urma_jfr_attr_t *attr)
{
    if (urma_test::GetHwMockState().jfrQueryStatus != URMA_SUCCESS) {
        return urma_test::GetHwMockState().jfrQueryStatus;
    }

    *cfg = jfr->jfr_cfg;
    attr->mask = JFR_STATE | JFR_RX_THRESHOLD;
    attr->state = URMA_JFR_STATE_READY;
    attr->rx_threshold = static_cast<uint32_t>(urma_test::GetHwMockState().intReturn);
    return URMA_SUCCESS;
}

inline urma_status_t MockDeletePhysicalJfr(urma_jfr_t *jfr)
{
    std::free(jfr);
    return urma_test::GetHwMockState().status;
}

inline urma_jetty_t *MockCreatePhysicalJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg)
{
    urma_jetty_t *jetty = static_cast<urma_jetty_t *>(std::calloc(1, sizeof(urma_jetty_t)));
    if (jetty == nullptr) {
        return nullptr;
    }
    jetty->urma_ctx = ctx;
    jetty->jetty_cfg = *cfg;
    jetty->jetty_id.id = 0x505;
    return jetty;
}

inline urma_status_t MockModifyPhysicalJetty(urma_jetty_t *, urma_jetty_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeletePhysicalJetty(urma_jetty_t *jetty)
{
    std::free(jetty);
    return urma_test::GetHwMockState().status;
}

inline void FreeCreatedBondCompForTest(bondp_comp_t *comp)
{
    if (comp == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        std::free(comp->members[i]);
        comp->members[i] = nullptr;
    }
    if (comp->v_conn_table.hmap.bucket != nullptr) {
        bondp_hash_table_destroy(&comp->v_conn_table);
    }
    wr_buf_uninit(&comp->send_wr_buf);
    wr_buf_uninit(&comp->recv_wr_buf);
    if (comp->comp_type == BONDP_COMP_JFS || comp->comp_type == BONDP_COMP_JETTY) {
        (void)pthread_spin_destroy(&comp->send_lock);
    }
    std::free(comp);
}

inline void FreeCreatedBondJfcForTest(bondp_jfc_t *jfc)
{
    if (jfc == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < URMA_UBAGG_DEV_MAX_NUM; ++i) {
        std::free(jfc->p_jfc[i]);
        jfc->p_jfc[i] = nullptr;
    }
    std::free(jfc);
}

inline urma_target_seg_t *MockRegisterPhysicalSeg(urma_context_t *ctx, urma_seg_cfg_t *cfg)
{
    urma_target_seg_t *seg = static_cast<urma_target_seg_t *>(std::calloc(1, sizeof(urma_target_seg_t)));
    if (seg == nullptr) {
        return nullptr;
    }

    seg->urma_ctx = ctx;
    seg->token_id = cfg->token_id;
    seg->seg.ubva.va = cfg->va;
    seg->seg.len = cfg->len;
    seg->seg.token_id = 0x5151;
    seg->handle = reinterpret_cast<uint64_t>(seg);
    return seg;
}

inline urma_status_t MockUnregisterPhysicalSeg(urma_target_seg_t *seg)
{
    std::free(seg);
    return urma_test::GetHwMockState().status;
}

inline urma_target_seg_t *MockImportPhysicalSeg(urma_context_t *ctx, urma_seg_t *seg, urma_token_t *,
                                                uint64_t addr, urma_import_seg_flag_t)
{
    urma_test::GetHwMockState().importSegCount++;
    if (urma_test::GetHwMockState().status != URMA_SUCCESS) {
        return nullptr;
    }

    urma_target_seg_t *target = static_cast<urma_target_seg_t *>(std::calloc(1, sizeof(urma_target_seg_t)));
    if (target == nullptr) {
        return nullptr;
    }

    target->urma_ctx = ctx;
    target->seg = *seg;
    target->mva = addr;
    target->handle = reinterpret_cast<uint64_t>(target);
    return target;
}

inline urma_status_t MockUnimportPhysicalSeg(urma_target_seg_t *seg)
{
    std::free(seg);
    return urma_test::GetHwMockState().status;
}

inline urma_target_jetty_t *MockImportPhysicalJetty(urma_context_t *ctx, urma_rjetty_t *rjetty,
                                                    urma_token_t *)
{
    urma_test::GetHwMockState().importJettyCount++;
    if (urma_test::GetHwMockState().status != URMA_SUCCESS) {
        return nullptr;
    }

    urma_target_jetty_t *target = static_cast<urma_target_jetty_t *>(std::calloc(1, sizeof(urma_target_jetty_t)));
    if (target == nullptr) {
        return nullptr;
    }

    target->urma_ctx = ctx;
    target->id = rjetty->jetty_id;
    target->trans_mode = rjetty->trans_mode;
    target->type = rjetty->type;
    target->handle = reinterpret_cast<uint64_t>(target);
    return target;
}

inline urma_target_jetty_t *MockImportPhysicalJfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *)
{
    urma_test::GetHwMockState().importJfrCount++;
    if (urma_test::GetHwMockState().status != URMA_SUCCESS) {
        return nullptr;
    }

    urma_target_jetty_t *target = static_cast<urma_target_jetty_t *>(std::calloc(1, sizeof(urma_target_jetty_t)));
    if (target == nullptr) {
        return nullptr;
    }

    target->urma_ctx = ctx;
    target->id = rjfr->jfr_id;
    target->trans_mode = rjfr->trans_mode;
    target->type = URMA_JFR;
    target->handle = reinterpret_cast<uint64_t>(target);
    return target;
}

inline urma_status_t MockUnimportPhysicalJetty(urma_target_jetty_t *target)
{
    std::free(target);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostJfsWr(urma_jfs_t *, urma_jfs_wr_t *wr, urma_jfs_wr_t **badWr)
{
    EXPECT_EQ(URMA_OPC_WRITE, wr->opcode);
    EXPECT_TRUE(wr->flag.bs.has_drv_ext);
    EXPECT_NE(nullptr, wr->rw.src.sge);
    EXPECT_NE(nullptr, wr->rw.dst.sge);
    EXPECT_NE(nullptr, badWr);
    return URMA_SUCCESS;
}

inline urma_status_t MockPostAnyJfsWr(urma_jfs_t *, urma_jfs_wr_t *wr, urma_jfs_wr_t **badWr)
{
    urma_test::GetHwMockState().postJfsCount++;
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = static_cast<urma_jfs_wr_t *>(urma_test::GetHwMockState().badSendWr);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostSecondJfsWrFails(urma_jfs_t *, urma_jfs_wr_t *wr, urma_jfs_wr_t **badWr)
{
    urma_test::GetHwMockState().postJfsCount++;
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = (wr->next == nullptr) ? wr : wr->next;
    return URMA_EAGAIN;
}

inline urma_status_t MockPostAnyJfrWr(urma_jfr_t *, urma_jfr_wr_t *wr, urma_jfr_wr_t **badWr)
{
    urma_test::GetHwMockState().postJfrCount++;
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = static_cast<urma_jfr_wr_t *>(urma_test::GetHwMockState().badRecvWr);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostFirstJfrWrFails(urma_jfr_t *, urma_jfr_wr_t *wr, urma_jfr_wr_t **badWr)
{
    urma_test::GetHwMockState().postJfrCount++;
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = wr;
    return URMA_EAGAIN;
}

inline urma_status_t MockPostJettySendWr(urma_jetty_t *, urma_jfs_wr_t *wr, urma_jfs_wr_t **badWr)
{
    urma_test::GetHwMockState().postJfsCount++;
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = static_cast<urma_jfs_wr_t *>(urma_test::GetHwMockState().badSendWr);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostJettyRecvWr(urma_jetty_t *, urma_jfr_wr_t *wr, urma_jfr_wr_t **badWr)
{
    urma_test::GetHwMockState().postJfrCount++;
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = static_cast<urma_jfr_wr_t *>(urma_test::GetHwMockState().badRecvWr);
    return urma_test::GetHwMockState().status;
}

static urma_cr_t g_mockDatapathCr = {};
static int g_mockDatapathCrCount = 0;

inline int MockPollOneCr(urma_jfc_t *, int crCnt, urma_cr_t *cr)
{
    if (g_mockDatapathCrCount <= 0 || crCnt <= 0) {
        return 0;
    }
    cr[0] = g_mockDatapathCr;
    g_mockDatapathCrCount--;
    return 1;
}

inline int MockFlushOneCr(urma_jetty_t *, int crCnt, urma_cr_t *cr)
{
    return MockPollOneCr(nullptr, crCnt, cr);
}

static urma_jfc_t *g_mockWaitJfc = nullptr;
static urma_async_event_t g_mockAsyncEvent = {};
static int g_mockAckAsyncCount = 0;

inline urma_status_t MockRearmPhysicalJfc(urma_jfc_t *, bool)
{
    return urma_test::GetHwMockState().status;
}

inline int MockWaitOnePhysicalJfc(urma_jfce_t *, uint32_t, int, urma_jfc_t *jfc[])
{
    jfc[0] = g_mockWaitJfc;
    return urma_test::GetHwMockState().intReturn;
}

inline void MockAckPhysicalJfc(urma_jfc_t *[], uint32_t [], uint32_t)
{
}

static urma_status_t MockGetAsyncEvent(urma_context_t *ctx, urma_async_event_t *event)
{
    *event = g_mockAsyncEvent;
    event->urma_ctx = ctx;
    return urma_test::GetHwMockState().status;
}

inline void MockAckAsyncEvent(urma_async_event_t *)
{
    g_mockAckAsyncCount++;
    urma_test::GetHwMockState().ackAsyncCount++;
}

struct HashTableNode {
    hmap_node_t hmapNode;
    uint32_t key;
    uint32_t payload;
};

inline bool HashTableNodeMatches(hmap_node_t *node, void *key)
{
    HashTableNode *entry = CONTAINER_OF_FIELD(node, HashTableNode, hmapNode);
    uint32_t *expectedKey = static_cast<uint32_t *>(key);

    return entry->key == *expectedKey;
}

inline void FreeHashTableNode(hmap_node_t *node)
{
    HashTableNode *entry = CONTAINER_OF_FIELD(node, HashTableNode, hmapNode);

    std::free(entry);
}

inline uint32_t HashTableNodeHash(void *key)
{
    return *static_cast<uint32_t *>(key);
}

inline void TimewheelCountCallback(void *arg)
{
    uint32_t *count = static_cast<uint32_t *>(arg);

    (*count)++;
}

inline urma_jetty_id_t MakeJettyId(uint32_t id)
{
    urma_jetty_id_t jettyId = {};

    jettyId.id = id;
    jettyId.uasid = id + 1;
    jettyId.eid.in6.subnet_prefix = 0x10000000ULL + id;
    jettyId.eid.in6.interface_id = 0x20000000ULL + id;
    return jettyId;
}

inline urma_eid_t MakeEid(uint32_t id)
{
    urma_eid_t eid = {};

    eid.in6.subnet_prefix = 0x30000000ULL + id;
    eid.in6.interface_id = 0x40000000ULL + id;
    return eid;
}

inline uint64_t MakeHealthUserCtx(uint32_t vjettyId, uint32_t localIdx, uint32_t targetIdx)
{
    constexpr uint64_t healthMagic = 0xFF12000000000000ULL;
    constexpr uint32_t healthIdxMask = 0xFFFF;
    constexpr uint32_t vjettyIdShift = 32;
    constexpr uint32_t localIdxShift = 16;

    return healthMagic | ((static_cast<uint64_t>(vjettyId & healthIdxMask)) << vjettyIdShift) |
        ((static_cast<uint64_t>(localIdx & healthIdxMask)) << localIdxShift) |
        static_cast<uint64_t>(targetIdx & healthIdxMask);
}

inline bondp_health_task_t *FindFirstHealthTask(bondp_heath_check_ctx_t *health)
{
    bondp_health_task_t *task = nullptr;

    HMAP_FOR_EACH(task, hmap_node, &health->task_table.hmap) {
        return task;
    }
    return nullptr;
}

inline void CopyEidToTopo(char dst[EID_LEN], const urma_eid_t &eid)
{
    static_assert(sizeof(urma_eid_t) == EID_LEN, "topo EID storage must match urma_eid_t");
    std::memcpy(dst, &eid, EID_LEN);
}

struct BondWorkerGuard {
    ~BondWorkerGuard()
    {
        bondp_worker_destroy();
    }
};

struct WorkerCounter {
    std::atomic<int> count = 0;
    int fd = -1;
};

struct EnvGuard {
    const char *name;
    bool hadValue;
    std::string oldValue;

    EnvGuard(const char *envName, const char *value) : name(envName), hadValue(false)
    {
        const char *existing = std::getenv(name);
        if (existing != nullptr) {
            hadValue = true;
            oldValue = existing;
        }
        if (value == nullptr) {
            unsetenv(name);
        } else {
            setenv(name, value, 1);
        }
    }

    ~EnvGuard()
    {
        if (hadValue) {
            setenv(name, oldValue.c_str(), 1);
        } else {
            unsetenv(name);
        }
    }
};

inline void CountWorkerTask(void *arg)
{
    WorkerCounter *counter = static_cast<WorkerCounter *>(arg);

    counter->count.fetch_add(1);
}

inline void CountReadableFd(void *arg)
{
    WorkerCounter *counter = static_cast<WorkerCounter *>(arg);
    eventfd_t value = 0;

    if (counter->fd >= 0) {
        (void)eventfd_read(counter->fd, &value);
    }
    counter->count.fetch_add(1);
}

inline bool WaitForWorkerCount(WorkerCounter *counter, int expected)
{
    for (uint32_t i = 0; i < 100; i++) {
        if (counter->count.load() >= expected) {
            return true;
        }
        usleep(5000);
    }
    return false;
}

} // namespace urma_test_bond
#pragma GCC diagnostic pop

#endif // TEST_URMA_BOND_BOND_FIXTURE_H
