/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding unit tests.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <cerrno>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "bondp_api.h"
#include "bondp_connection.h"
#include "bondp_context_table.h"
#include "bondp_datapath.h"
#include "bondp_datapath_convert.h"
#include "bondp_datapath_schedule.h"
#include "bondp_hash_table.h"
#include "bondp_health_check.h"
#include "bondp_link_recovery.h"
#include "bondp_netlink.h"
#include "bondp_provider_ops.h"
#include "bondp_segment.h"
#include "bondp_slide_window.h"
#include "bondp_timewheel.h"
#include "bondp_types.h"
#include "bondp_worker.h"
#include "bondp_wr_buf.h"
#include "urma_provider.h"
#include "urma_private.h"

TEST(UrmaBondTest, SlideWindowRejectsInvalidInit)
{
    bdp_slide_wnd_t wnd = {};

    EXPECT_EQ(-1, bdp_slide_wnd_init(nullptr, 8, 4, 0));
    EXPECT_EQ(-1, bdp_slide_wnd_init(&wnd, 4, 4, 0));
}

TEST(UrmaBondTest, SlideWindowAddsAndSlidesHead)
{
    bdp_slide_wnd_t wnd = {};

    ASSERT_EQ(0, bdp_slide_wnd_init(&wnd, 8, 4, 6));
    EXPECT_TRUE(bdp_slide_wnd_seq_in_window(&wnd, 6));
    EXPECT_TRUE(bdp_slide_wnd_seq_in_window(&wnd, 1));
    EXPECT_FALSE(bdp_slide_wnd_seq_in_window(&wnd, 2));

    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 6));
    EXPECT_EQ(7U, wnd.head);
    EXPECT_EQ(BDP_SLIDE_WND_OUT_OF_WND, bdp_slide_wnd_add(&wnd, 6));
    EXPECT_EQ(BDP_SLIDE_WND_OUT_OF_WND, bdp_slide_wnd_add(&wnd, 3));

    bdp_slide_wnd_uninit(&wnd);
}

TEST(UrmaBondTest, WrBufferAllocGetRelease)
{
    wr_buf_t buf = {};
    jfs_wr_entry_t *jfsEntry = nullptr;
    jfr_wr_entry_t *jfrEntry = nullptr;

    EXPECT_EQ(-EINVAL, wr_buf_init(nullptr, 2));
    EXPECT_EQ(-EINVAL, wr_buf_init(&buf, 0));

    ASSERT_EQ(0, wr_buf_init(&buf, 2));
    jfsEntry = jfs_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, jfsEntry);
    EXPECT_EQ(1U, jfsEntry->wr_id);
    EXPECT_EQ(WR_BUF_ENTRY_JFS, jfsEntry->entry_type);
    EXPECT_TRUE(jfsEntry == jfs_wr_buf_get(&buf, jfsEntry->wr_id));

    jfrEntry = jfr_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, jfrEntry);
    EXPECT_EQ(2U, jfrEntry->wr_id);
    EXPECT_EQ(WR_BUF_ENTRY_JFR, jfrEntry->entry_type);
    EXPECT_TRUE(jfrEntry == jfr_wr_buf_get(&buf, jfrEntry->wr_id));

    EXPECT_EQ(nullptr, jfs_wr_buf_alloc(&buf));
    jfs_wr_buf_release(&buf, jfsEntry);
    EXPECT_EQ(nullptr, jfs_wr_buf_get(&buf, 1));
    EXPECT_NE(nullptr, jfs_wr_buf_alloc(&buf));

    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, WrBufferReleaseJfrAndReuse)
{
    wr_buf_t buf = {};
    jfr_wr_entry_t *entry = nullptr;

    ASSERT_EQ(0, wr_buf_init(&buf, 1));
    entry = jfr_wr_buf_alloc(&buf);
    ASSERT_NE(nullptr, entry);
    uint64_t wrId = entry->wr_id;
    EXPECT_EQ(nullptr, jfr_wr_buf_alloc(&buf));
    jfr_wr_buf_release(&buf, entry);
    EXPECT_EQ(nullptr, jfr_wr_buf_get(&buf, wrId));
    EXPECT_NE(nullptr, jfr_wr_buf_alloc(&buf));
    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, WrBufferBatchAllocReleaseJfs)
{
    wr_buf_t buf = {};
    jfs_wr_entry_t *entries[3] = {};

    ASSERT_EQ(0, wr_buf_init(&buf, 2));
    EXPECT_EQ(0U, jfs_wr_buf_alloc_batch(&buf, entries, 0));
    EXPECT_EQ(2U, jfs_wr_buf_alloc_batch(&buf, entries, 3));
    ASSERT_NE(nullptr, entries[0]);
    ASSERT_NE(nullptr, entries[1]);
    EXPECT_EQ(1U, entries[0]->wr_id);
    EXPECT_EQ(2U, entries[1]->wr_id);
    EXPECT_EQ(0U, jfs_wr_buf_alloc_batch(&buf, entries, 1));

    jfs_wr_buf_release_batch(&buf, entries, 2);
    EXPECT_NE(nullptr, jfs_wr_buf_alloc(&buf));
    wr_buf_uninit(&buf);
}

TEST(UrmaBondTest, SlideWindowHasDuplicateAndWrapAround)
{
    bdp_slide_wnd_t wnd = {};

    ASSERT_EQ(0, bdp_slide_wnd_init(&wnd, 8, 4, 6));
    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 7));
    EXPECT_TRUE(bdp_slide_wnd_has(&wnd, 7));
    EXPECT_EQ(BDP_SLIDE_WND_DUPLICATE, bdp_slide_wnd_add(&wnd, 7));
    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 6));
    EXPECT_EQ(8U, bdp_slide_wnd_has(&wnd, 0) ? 8U : wnd.total_size);
    EXPECT_EQ(0, bdp_slide_wnd_add(&wnd, 0));
    bdp_slide_wnd_uninit(&wnd);
}

namespace {

static const uint32_t BOND_TEST_RECV_BATCH_POST_MAX_NUM = 280;

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
    urma_target_jetty_t phyTarget[2][2] = {};
    bondp_tseg_t localSeg = {};
    bondp_import_tseg_t remoteSeg = {};
    urma_target_seg_t localPhy[2] = {};
    urma_target_seg_t remotePhy[2][2] = {};
    urma_sge_t srcSge[1] = {};
    urma_sge_t dstSge[1] = {};

    BondPathFixture()
    {
        /* Build a two-path virtual topology without creating real URMA devices. */
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
        comp.v_jfr.jfr_cfg.trans_mode = URMA_TM_RC;
        comp.v_jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
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
        phyJfr[0].urma_ctx = &phyCtx;
        phyJfr[1].urma_ctx = &phyCtx;
        phyJfr[0].jfr_cfg.jfc = &phyJfc;
        phyJfr[1].jfr_cfg.jfc = &phyJfc;
        comp.p_jfs[0] = &phyJfs[0];
        comp.p_jfs[1] = &phyJfs[1];
        comp.p_jfr[0] = &phyJfr[0];
        comp.p_jfr[1] = &phyJfr[1];
        comp.p_jetty[0] = &comp.v_jetty;
        comp.p_jetty[1] = &comp.v_jetty;

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

static void SetRefCount(urma_ref_t *ref, unsigned long value)
{
    ref->atomic_cnt.store(value);
}

static urma_jfc_t *MockCreatePhysicalJfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg);
static urma_status_t MockDeletePhysicalJfc(urma_jfc_t *jfc);
static urma_jfs_t *MockCreatePhysicalJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg);
static urma_status_t MockDeletePhysicalJfs(urma_jfs_t *jfs);
static urma_jfr_t *MockCreatePhysicalJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg);
static urma_status_t MockDeletePhysicalJfr(urma_jfr_t *jfr);
static urma_jetty_t *MockCreatePhysicalJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg);
static urma_status_t MockDeletePhysicalJetty(urma_jetty_t *jetty);
static urma_target_seg_t *MockRegisterPhysicalSeg(urma_context_t *ctx, urma_seg_cfg_t *cfg);
static urma_status_t MockUnregisterPhysicalSeg(urma_target_seg_t *seg);

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
    urma_jfr_t phyJfr = {};
    bondp_comp_t jfs = {};
    bondp_comp_t jfr = {};
    bondp_comp_t jetty = {};
    bondp_target_jetty_t targetJetty = {};
    bondp_target_jetty_t targetJfr = {};

    BondPublicApiFixture()
    {
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
        phyOps.create_jfc = MockCreatePhysicalJfc;
        phyOps.delete_jfc = MockDeletePhysicalJfc;
        phyOps.create_jfs = MockCreatePhysicalJfs;
        phyOps.delete_jfs = MockDeletePhysicalJfs;
        phyOps.create_jfr = MockCreatePhysicalJfr;
        phyOps.delete_jfr = MockDeletePhysicalJfr;
        phyOps.create_jetty = MockCreatePhysicalJetty;
        phyOps.delete_jetty = MockDeletePhysicalJetty;
        phyOps.register_seg = MockRegisterPhysicalSeg;
        phyOps.unregister_seg = MockUnregisterPhysicalSeg;
        phyJfce[0].urma_ctx = &phyCtx;
        phyJfc.urma_ctx = &phyCtx;
        phyJfc.jfc_id.id = 0x404;
        phyJfr.urma_ctx = &phyCtx;
        phyJfr.jfr_id.id = 0x405;
        phyJfr.jfr_cfg.jfc = &phyJfc;
        jfc.p_jfc[0] = &phyJfc;
        jfr.p_jfr[0] = &phyJfr;
    }
};

static urma_user_ctl_in_t MakeUserCtl(uint32_t opcode, void *addr, uint32_t len)
{
    urma_user_ctl_in_t in = {};

    in.opcode = opcode;
    in.addr = reinterpret_cast<uint64_t>(addr);
    in.len = len;
    return in;
}

static urma_user_ctl_out_t MakeUserCtlOut(void *addr, uint32_t len)
{
    urma_user_ctl_out_t out = {};

    out.addr = reinterpret_cast<uint64_t>(addr);
    out.len = len;
    return out;
}

static int CallBondUserCtl(urma_context_t *ctx, uint32_t opcode, void *addr, uint32_t len,
                           urma_user_ctl_out_t *out)
{
    urma_user_ctl_in_t in = MakeUserCtl(opcode, addr, len);

    return bondp_user_ctl(ctx, &in, out);
}

static urma_jfc_t *MockCreatePhysicalJfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg)
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

static urma_status_t MockDeletePhysicalJfc(urma_jfc_t *jfc)
{
    std::free(jfc);
    return URMA_SUCCESS;
}

static urma_jfs_t *MockCreatePhysicalJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
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

static urma_status_t MockDeletePhysicalJfs(urma_jfs_t *jfs)
{
    std::free(jfs);
    return URMA_SUCCESS;
}

static urma_jfr_t *MockCreatePhysicalJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
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

static urma_status_t MockDeletePhysicalJfr(urma_jfr_t *jfr)
{
    std::free(jfr);
    return URMA_SUCCESS;
}

static urma_jetty_t *MockCreatePhysicalJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg)
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

static urma_status_t MockDeletePhysicalJetty(urma_jetty_t *jetty)
{
    std::free(jetty);
    return URMA_SUCCESS;
}

static urma_target_seg_t *MockRegisterPhysicalSeg(urma_context_t *ctx, urma_seg_cfg_t *cfg)
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

static urma_status_t MockUnregisterPhysicalSeg(urma_target_seg_t *seg)
{
    std::free(seg);
    return URMA_SUCCESS;
}

static urma_status_t MockPostJfsWr(urma_jfs_t *, urma_jfs_wr_t *wr, urma_jfs_wr_t **badWr)
{
    EXPECT_EQ(URMA_OPC_WRITE, wr->opcode);
    EXPECT_TRUE(wr->flag.bs.has_drv_ext);
    EXPECT_NE(nullptr, wr->rw.src.sge);
    EXPECT_NE(nullptr, wr->rw.dst.sge);
    EXPECT_NE(nullptr, badWr);
    return URMA_SUCCESS;
}

static urma_status_t MockPostAnyJfsWr(urma_jfs_t *, urma_jfs_wr_t *wr, urma_jfs_wr_t **badWr)
{
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = nullptr;
    return URMA_SUCCESS;
}

static urma_status_t MockPostAnyJfrWr(urma_jfr_t *, urma_jfr_wr_t *wr, urma_jfr_wr_t **badWr)
{
    EXPECT_NE(nullptr, wr);
    EXPECT_NE(nullptr, badWr);
    *badWr = nullptr;
    return URMA_SUCCESS;
}

static urma_cr_t g_mockDatapathCr = {};
static int g_mockDatapathCrCount = 0;

static int MockPollOneCr(urma_jfc_t *, int crCnt, urma_cr_t *cr)
{
    if (g_mockDatapathCrCount <= 0 || crCnt <= 0) {
        return 0;
    }
    cr[0] = g_mockDatapathCr;
    g_mockDatapathCrCount--;
    return 1;
}

static int MockFlushOneCr(urma_jetty_t *, int crCnt, urma_cr_t *cr)
{
    return MockPollOneCr(nullptr, crCnt, cr);
}

static urma_jfc_t *g_mockWaitJfc = nullptr;
static urma_async_event_t g_mockAsyncEvent = {};
static int g_mockAckAsyncCount = 0;

static urma_status_t MockRearmPhysicalJfc(urma_jfc_t *, bool)
{
    return URMA_SUCCESS;
}

static int MockWaitOnePhysicalJfc(urma_jfce_t *, uint32_t, int, urma_jfc_t *jfc[])
{
    jfc[0] = g_mockWaitJfc;
    return 1;
}

static void MockAckPhysicalJfc(urma_jfc_t *[], uint32_t [], uint32_t)
{
}

static urma_status_t MockGetAsyncEvent(urma_context_t *ctx, urma_async_event_t *event)
{
    *event = g_mockAsyncEvent;
    event->urma_ctx = ctx;
    return URMA_SUCCESS;
}

static void MockAckAsyncEvent(urma_async_event_t *)
{
    g_mockAckAsyncCount++;
}

struct HashTableNode {
    hmap_node_t hmapNode;
    uint32_t key;
    uint32_t payload;
};

static bool HashTableNodeMatches(hmap_node_t *node, void *key)
{
    HashTableNode *entry = CONTAINER_OF_FIELD(node, HashTableNode, hmapNode);
    uint32_t *expectedKey = static_cast<uint32_t *>(key);

    return entry->key == *expectedKey;
}

static void FreeHashTableNode(hmap_node_t *node)
{
    HashTableNode *entry = CONTAINER_OF_FIELD(node, HashTableNode, hmapNode);

    std::free(entry);
}

static uint32_t HashTableNodeHash(void *key)
{
    return *static_cast<uint32_t *>(key);
}

static void TimewheelCountCallback(void *arg)
{
    uint32_t *count = static_cast<uint32_t *>(arg);

    (*count)++;
}

static urma_jetty_id_t MakeJettyId(uint32_t id)
{
    urma_jetty_id_t jettyId = {};

    jettyId.id = id;
    jettyId.uasid = id + 1;
    jettyId.eid.in6.subnet_prefix = 0x10000000ULL + id;
    jettyId.eid.in6.interface_id = 0x20000000ULL + id;
    return jettyId;
}

static urma_eid_t MakeEid(uint32_t id)
{
    urma_eid_t eid = {};

    eid.in6.subnet_prefix = 0x30000000ULL + id;
    eid.in6.interface_id = 0x40000000ULL + id;
    return eid;
}

static void CopyEidToTopo(char dst[EID_LEN], const urma_eid_t &eid)
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

static void CountWorkerTask(void *arg)
{
    WorkerCounter *counter = static_cast<WorkerCounter *>(arg);

    counter->count.fetch_add(1);
}

static void CountReadableFd(void *arg)
{
    WorkerCounter *counter = static_cast<WorkerCounter *>(arg);
    eventfd_t value = 0;

    if (counter->fd >= 0) {
        (void)eventfd_read(counter->fd, &value);
    }
    counter->count.fetch_add(1);
}

static bool WaitForWorkerCount(WorkerCounter *counter, int expected)
{
    for (uint32_t i = 0; i < 100; i++) {
        if (counter->count.load() >= expected) {
            return true;
        }
        usleep(5000);
    }
    return false;
}

} // namespace

TEST(UrmaBondTest, TimewheelSchedulesCancelsAndAdvancesDeterministically)
{
    tw_cfg_t cfg = { .tick_ms = 10, .slot_num = 2 };
    uint32_t fired = 0;
    tw_task_id_t firstTask = 0;
    tw_task_id_t cancelTask = 0;
    tw_task_id_t roundTask = 0;

    EXPECT_EQ(nullptr, tw_create(nullptr));
    EXPECT_EQ(0U, tw_get_tick_ms(nullptr));
    EXPECT_EQ(-EINVAL, tw_schedule(nullptr, 0, TimewheelCountCallback, &fired, &firstTask));
    EXPECT_EQ(-EINVAL, tw_cancel(nullptr, firstTask));
    tw_advance(nullptr, 1);

    tw_t *tw = tw_create(&cfg);
    ASSERT_NE(nullptr, tw);
    EXPECT_EQ(10U, tw_get_tick_ms(tw));
    EXPECT_EQ(-EINVAL, tw_schedule(tw, 0, nullptr, &fired, &firstTask));
    EXPECT_EQ(-EINVAL, tw_schedule(tw, 0, TimewheelCountCallback, &fired, nullptr));
    EXPECT_EQ(-EINVAL, tw_cancel(tw, 0));
    EXPECT_EQ(-ENOENT, tw_cancel(tw, 0xdead));
    tw_advance(tw, 0);

    ASSERT_EQ(0, tw_schedule(tw, 0, TimewheelCountCallback, &fired, &firstTask));
    EXPECT_NE(0U, firstTask);
    tw_advance(tw, 1);
    EXPECT_EQ(1U, fired);
    EXPECT_EQ(-ENOENT, tw_cancel(tw, firstTask));

    ASSERT_EQ(0, tw_schedule(tw, 10, TimewheelCountCallback, &fired, &cancelTask));
    EXPECT_EQ(0, tw_cancel(tw, cancelTask));
    tw_advance(tw, 1);
    EXPECT_EQ(1U, fired);

    ASSERT_EQ(0, tw_schedule(tw, 30, TimewheelCountCallback, &fired, &roundTask));
    tw_advance(tw, 2);
    EXPECT_EQ(1U, fired);
    tw_advance(tw, 1);
    EXPECT_EQ(2U, fired);
    tw_destroy(tw);
    tw_destroy(nullptr);
}

TEST(UrmaBondTest, HashTableCreateLookupRemoveAndDestroy)
{
    bondp_hash_table_t tbl = {};
    uint32_t key = 7;
    uint32_t missingKey = 8;
    auto *node = static_cast<HashTableNode *>(std::calloc(1, sizeof(HashTableNode)));
    ASSERT_NE(nullptr, node);
    node->key = key;
    node->payload = 0xabc;

    ASSERT_EQ(0, bondp_hash_table_create(&tbl, 4, HashTableNodeMatches, FreeHashTableNode, HashTableNodeHash));
    bondp_hash_table_add_with_hash(&tbl, &node->hmapNode, HashTableNodeHash(&key));
    EXPECT_EQ(&node->hmapNode, bondp_hash_table_lookup(&tbl, &key, HashTableNodeHash(&key)));
    EXPECT_EQ(&node->hmapNode, bondp_hash_table_lookup_without_lock(&tbl, &key, HashTableNodeHash(&key)));
    EXPECT_EQ(nullptr, bondp_hash_table_lookup(&tbl, &missingKey, HashTableNodeHash(&missingKey)));
    bondp_hash_table_remove(&tbl, &node->hmapNode);
    EXPECT_EQ(nullptr, bondp_hash_table_lookup_without_lock(&tbl, &key, HashTableNodeHash(&key)));
    FreeHashTableNode(&node->hmapNode);

    node = static_cast<HashTableNode *>(std::calloc(1, sizeof(HashTableNode)));
    ASSERT_NE(nullptr, node);
    node->key = key;
    bondp_hash_table_add_with_hash_without_lock(&tbl, &node->hmapNode, HashTableNodeHash(&key));
    bondp_hash_table_destroy(&tbl);

    bondp_hash_table_t firstMatchTbl = {};
    HashTableNode first = { .key = 1, .payload = 1 };
    ASSERT_EQ(0, bondp_hash_table_create(&firstMatchTbl, 4, nullptr, nullptr, HashTableNodeHash));
    bondp_hash_table_add_with_hash_without_lock(&firstMatchTbl, &first.hmapNode, 0x55);
    EXPECT_EQ(&first.hmapNode, bondp_hash_table_lookup(&firstMatchTbl, &missingKey, 0x55));
    EXPECT_EQ(&first.hmapNode, bondp_hash_table_lookup_without_lock(&firstMatchTbl, &missingKey, 0x55));
    bondp_hash_table_destroy(&firstMatchTbl);
}

TEST(UrmaBondTest, ContextTablesMapJettyIdsAndRemoteTokenIds)
{
    bondp_hash_table_t pJettyTable = {};
    bondp_hash_table_t tokenTable = {};
    bondp_comp_t comp = {};
    urma_jetty_id_t pJettyId = MakeJettyId(0x21);
    bondp_v2p_token_id_t tokenItem = {};
    bondp_v2p_token_id_t lookedUpToken = {};
    urma_eid_t remoteEid = MakeEid(0x31);

    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&pJettyTable, 4));
    EXPECT_EQ(BONDP_HASH_MAP_INVALID_PARAM_ERROR,
        bdp_p_vjetty_id_table_add_without_lock(&pJettyTable, pJettyId, JETTY, 0x11, nullptr));
    EXPECT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(&pJettyTable, pJettyId, JETTY, 0x11, &comp));
    EXPECT_EQ(&comp, bdp_p_vjetty_id_table_lookup_comp_without_lock(&pJettyTable, pJettyId, JETTY));
    EXPECT_EQ(nullptr, bdp_p_vjetty_id_table_lookup_comp_without_lock(&pJettyTable, pJettyId, JFS));
    EXPECT_EQ(BONDP_HASH_MAP_COLLIDE_ERROR,
        bdp_p_vjetty_id_table_add_without_lock(&pJettyTable, pJettyId, JETTY, 0x12, &comp));
    EXPECT_EQ(BONDP_HASH_MAP_NOT_FOUND_ERROR, bdp_p_vjetty_id_table_del_without_lock(&pJettyTable, pJettyId, JFS));
    EXPECT_EQ(0, bdp_p_vjetty_id_table_del_without_lock(&pJettyTable, pJettyId, JETTY));
    EXPECT_EQ(nullptr, bdp_p_vjetty_id_table_lookup_comp_without_lock(&pJettyTable, pJettyId, JETTY));
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&pJettyTable));

    ASSERT_EQ(0, bdp_r_v2p_token_id_table_create(&tokenTable, 4));
    EXPECT_EQ(BONDP_HASH_MAP_NOT_FOUND_ERROR,
        bdp_r_v2p_token_id_tabl_lookup(&tokenTable, 0x44, remoteEid, &lookedUpToken));
    tokenItem.key.v_token_id = 0x44;
    tokenItem.key.v_remote_eid = remoteEid;
    tokenItem.v_handle = 0x55667788ULL;
    tokenItem.index = 3;
    tokenItem.connected[0][1] = true;
    tokenItem.peer_p_seg[1].len = 0x99;
    EXPECT_EQ(tokenItem.key.v_token_id, tokenTable.hash_f(&tokenItem.key));
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_add_lockless(&tokenTable, &tokenItem));
    EXPECT_EQ(0, bdp_r_v2p_token_id_tabl_lookup(&tokenTable, 0x44, remoteEid, &lookedUpToken));
    EXPECT_EQ(tokenItem.v_handle, lookedUpToken.v_handle);
    EXPECT_EQ(tokenItem.index, lookedUpToken.index);
    EXPECT_TRUE(lookedUpToken.connected[0][1]);
    EXPECT_EQ(0x99U, lookedUpToken.peer_p_seg[1].len);
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_add_lockless(&tokenTable, &tokenItem));
    EXPECT_EQ(-1, bdp_r_v2p_token_id_del_idx_lockless(&tokenTable, 9));
    EXPECT_EQ(0, bdp_r_v2p_token_id_del_idx_lockless(&tokenTable, tokenItem.index));
    EXPECT_EQ(BONDP_HASH_MAP_NOT_FOUND_ERROR,
        bdp_r_v2p_token_id_tabl_lookup(&tokenTable, 0x44, remoteEid, &lookedUpToken));
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_destroy(&tokenTable));
}

TEST(UrmaBondTest, ConnectionTableGetOrCreateReusesExistingConnection)
{
    bondp_hash_table_t tbl = {};
    urma_jetty_id_t firstId = MakeJettyId(0x41);
    urma_jetty_id_t secondId = MakeJettyId(0x42);
    bondp_conn_t *firstConn = nullptr;
    bondp_conn_t *sameConn = nullptr;
    bondp_conn_t *secondConn = nullptr;

    ASSERT_EQ(0, bondp_conn_table_create(&tbl, 4));
    EXPECT_EQ(0, bondp_conn_table_get_or_create(&tbl, &firstId, &firstConn));
    ASSERT_NE(nullptr, firstConn);
    EXPECT_EQ(0, bondp_conn_table_get_or_create(&tbl, &firstId, &sameConn));
    EXPECT_EQ(firstConn, sameConn);
    EXPECT_EQ(0, bondp_conn_table_get_or_create(&tbl, &secondId, &secondConn));
    ASSERT_NE(nullptr, secondConn);
    EXPECT_NE(firstConn, secondConn);
    EXPECT_TRUE(bdp_slide_wnd_seq_in_window(&firstConn->recv_wnd, 0));
    bondp_hash_table_destroy(&tbl);
}

TEST(UrmaBondTest, TopoInfoMapsPhysicalAndAggregateEids)
{
    bondp_topo_node_t topo = {};
    urma_eid_t aggEid = MakeEid(0x51);
    urma_eid_t primaryEid = MakeEid(0x52);
    urma_eid_t portEid = MakeEid(0x53);
    urma_eid_t missingEid = MakeEid(0x54);
    urma_eid_t output = {};

    EXPECT_EQ(nullptr, create_topo_map(nullptr, 1));
    EXPECT_EQ(nullptr, create_topo_map(&topo, 0));
    EXPECT_EQ(nullptr, create_topo_map(&topo, MAX_NODE_NUM + 1));
    EXPECT_EQ(nullptr, create_topo_map(&topo, 1));
    delete_topo_map(nullptr);

    topo.is_current = true;
    CopyEidToTopo(topo.agg_devs[0].agg_eid, aggEid);
    CopyEidToTopo(topo.agg_devs[0].ues[0].primary_eid, primaryEid);
    CopyEidToTopo(topo.agg_devs[0].ues[0].port_eid[0], portEid);

    topo_map_t *map = create_topo_map(&topo, 1);
    ASSERT_NE(nullptr, map);
    EXPECT_EQ(1U, map->node_num);

    ASSERT_EQ(0, get_bonding_eid_by_target_eid(map, &aggEid, &output));
    EXPECT_EQ(0, std::memcmp(&aggEid, &output, sizeof(output)));
    ASSERT_EQ(0, get_bonding_eid_by_target_eid(map, &primaryEid, &output));
    EXPECT_EQ(0, std::memcmp(&aggEid, &output, sizeof(output)));
    ASSERT_EQ(0, get_bonding_eid_by_target_eid(map, &portEid, &output));
    EXPECT_EQ(0, std::memcmp(&aggEid, &output, sizeof(output)));
    EXPECT_EQ(-1, get_bonding_eid_by_target_eid(map, &missingEid, &output));
    EXPECT_EQ(-1, get_bonding_eid_by_target_eid(nullptr, &portEid, &output));
    EXPECT_EQ(-1, get_bonding_eid_by_target_eid(map, nullptr, &output));

    delete_topo_map(map);
}

TEST(UrmaBondTest, WorkerPublicApisScheduleCancelAndHandleFdEvents)
{
    BondWorkerGuard guard;
    WorkerCounter taskCounter = {};
    WorkerCounter fdCounter = {};
    bondp_worker_task_id_t taskId = 0;
    bondp_worker_task_id_t cancelId = 0;

    bondp_worker_destroy();
    EXPECT_EQ(-ENODEV, bondp_worker_schedule(0, CountWorkerTask, &taskCounter, &taskId));
    EXPECT_EQ(-ENODEV, bondp_worker_cancel(1));
    EXPECT_EQ(-EINVAL, bondp_worker_add_fd(-1, CountReadableFd, &fdCounter));
    EXPECT_EQ(-EINVAL, bondp_worker_add_fd(0, nullptr, &fdCounter));
    EXPECT_EQ(-ENODEV, bondp_worker_del_fd(0));
    EXPECT_EQ(-EINVAL, bondp_worker_del_fd(-1));

    ASSERT_EQ(0, bondp_worker_create());
    EXPECT_EQ(-EEXIST, bondp_worker_create());
    EXPECT_EQ(-EINVAL, bondp_worker_schedule(0, nullptr, &taskCounter, &taskId));
    EXPECT_EQ(-EINVAL, bondp_worker_schedule(0, CountWorkerTask, &taskCounter, nullptr));
    EXPECT_EQ(-ENOENT, bondp_worker_cancel(0xdead));

    ASSERT_EQ(0, bondp_worker_schedule(0, CountWorkerTask, &taskCounter, &taskId));
    EXPECT_TRUE(WaitForWorkerCount(&taskCounter, 1));
    EXPECT_EQ(-ENOENT, bondp_worker_cancel(taskId));

    ASSERT_EQ(0, bondp_worker_schedule(1000, CountWorkerTask, &taskCounter, &cancelId));
    EXPECT_EQ(0, bondp_worker_cancel(cancelId));
    usleep(20000);
    EXPECT_EQ(1, taskCounter.count.load());

    fdCounter.fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(fdCounter.fd, 0);
    ASSERT_EQ(0, bondp_worker_add_fd(fdCounter.fd, CountReadableFd, &fdCounter));
    EXPECT_EQ(-EEXIST, bondp_worker_add_fd(fdCounter.fd, CountReadableFd, &fdCounter));
    ASSERT_EQ(0, eventfd_write(fdCounter.fd, 1));
    EXPECT_TRUE(WaitForWorkerCount(&fdCounter, 1));
    EXPECT_EQ(0, bondp_worker_del_fd(fdCounter.fd));
    EXPECT_EQ(-ENOENT, bondp_worker_del_fd(fdCounter.fd));
    EXPECT_EQ(0, close(fdCounter.fd));
    fdCounter.fd = -1;

    bondp_worker_destroy();
    bondp_worker_destroy();
}

TEST(UrmaBondTest, DatapathCopyAndFreeWorkRequests)
{
    BondPathFixture fixture;
    urma_jfs_wr_t src = fixture.MakeRwWr(URMA_OPC_WRITE);
    urma_jfs_wr_t dst = {};
    urma_sge_t preallocSrc[1] = {};
    urma_sge_t preallocDst[1] = {};
    urma_jfr_wr_t recvSrc = {};
    urma_jfr_wr_t recvDst = {};
    urma_sge_t atomicSrc = {};
    urma_sge_t atomicDst = {};
    urma_jfs_wr_t atomicWr = {};

    EXPECT_EQ(URMA_SUCCESS, copy_jfs_wr(&src, &dst, preallocSrc, preallocDst));
    EXPECT_EQ(preallocSrc, dst.rw.src.sge);
    EXPECT_EQ(preallocDst, dst.rw.dst.sge);

    src.opcode = URMA_OPC_SEND;
    src.send.src.sge = fixture.srcSge;
    src.send.src.num_sge = 1;
    EXPECT_EQ(URMA_SUCCESS, copy_jfs_wr(&src, &dst, preallocSrc, nullptr));
    EXPECT_EQ(preallocSrc, dst.send.src.sge);
    src.opcode = URMA_OPC_NOP;
    EXPECT_EQ(URMA_EINVAL, copy_jfs_wr(&src, &dst, nullptr, nullptr));

    atomicSrc.tseg = fixture.srcSge[0].tseg;
    atomicDst.tseg = fixture.dstSge[0].tseg;
    atomicWr.opcode = URMA_OPC_CAS;
    atomicWr.cas.src = &atomicSrc;
    atomicWr.cas.dst = &atomicDst;
    EXPECT_EQ(URMA_SUCCESS, copy_jfs_wr(&atomicWr, &dst, preallocSrc, preallocDst));
    EXPECT_EQ(preallocSrc, dst.cas.src);
    EXPECT_EQ(preallocDst, dst.cas.dst);

    recvSrc.src.sge = fixture.srcSge;
    recvSrc.src.num_sge = 1;
    EXPECT_EQ(URMA_SUCCESS, copy_jfr_wr(&recvSrc, &recvDst, preallocSrc));
    EXPECT_EQ(preallocSrc, recvDst.src.sge);
    dst = {};
    dst.opcode = URMA_OPC_SEND;
    dst.send.src.sge = static_cast<urma_sge_t *>(std::calloc(1, sizeof(urma_sge_t)));
    ASSERT_NE(nullptr, dst.send.src.sge);
    free_jfs_wr(&dst);
    EXPECT_EQ(nullptr, dst.send.src.sge);

    recvDst.src.sge = static_cast<urma_sge_t *>(std::calloc(1, sizeof(urma_sge_t)));
    ASSERT_NE(nullptr, recvDst.src.sge);
    free_jfr_wr(&recvDst);
    EXPECT_EQ(nullptr, recvDst.src.sge);
}

TEST(UrmaBondTest, DatapathConvertMapsAndRestoresWorkRequests)
{
    BondPathFixture fixture;
    urma_jfs_wr_t sendWr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t writeWr = fixture.MakeRwWr(URMA_OPC_WRITE_IMM);
    urma_sge_t casSrc = {};
    urma_sge_t casDst = {};
    urma_sge_t faddSrc = {};
    urma_sge_t faddDst = {};
    urma_jfs_wr_t casWr = {};
    urma_jfs_wr_t faddWr = {};
    urma_jfr_wr_t recvWr = {};
    urma_cr_t cr = {};
    uint32_t msn = 0;

    casSrc.tseg = &fixture.localSeg.v_tseg;
    casDst.tseg = &fixture.remoteSeg.v_tseg;
    faddSrc.tseg = &fixture.localSeg.v_tseg;
    faddDst.tseg = &fixture.remoteSeg.v_tseg;

    EXPECT_EQ(URMA_SUCCESS, convert_jfs_vwr_to_pwr(&sendWr, 0, 0, &fixture.comp, true));
    EXPECT_EQ(URMA_OPC_SEND_IMM, sendWr.opcode);
    EXPECT_EQ(&fixture.phyTarget[0][0], sendWr.tjetty);
    convert_jfs_pwr_to_vwr_resend(&sendWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.target.v_tjetty, sendWr.tjetty);

    EXPECT_EQ(URMA_SUCCESS, convert_jfs_vwr_to_pwr(&writeWr, 1, 1, &fixture.comp, true));
    EXPECT_EQ(&fixture.phyTarget[1][1], writeWr.tjetty);
    convert_jfs_pwr_to_vwr_resend(&writeWr, &fixture.target.v_tjetty);
    convert_jfs_vwr_to_pwr_for_resend(&writeWr, 0, 0);

    casWr.opcode = URMA_OPC_CAS;
    casWr.tjetty = &fixture.target.v_tjetty;
    casWr.cas.src = &casSrc;
    casWr.cas.dst = &casDst;
    EXPECT_EQ(URMA_SUCCESS, convert_jfs_vwr_to_pwr(&casWr, 0, 0, &fixture.comp, true));
    convert_jfs_pwr_to_vwr_resend(&casWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, casWr.cas.src->tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, casWr.cas.dst->tseg);

    faddWr.opcode = URMA_OPC_FADD;
    faddWr.tjetty = &fixture.target.v_tjetty;
    faddWr.faa.src = &faddSrc;
    faddWr.faa.dst = &faddDst;
    EXPECT_EQ(URMA_SUCCESS, convert_jfs_vwr_to_pwr(&faddWr, 0, 0, &fixture.comp, true));
    convert_jfs_pwr_to_vwr_resend(&faddWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, faddWr.faa.src->tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, faddWr.faa.dst->tseg);

    sendWr.opcode = URMA_OPC_NOP;
    sendWr.tjetty = nullptr;
    EXPECT_EQ(URMA_EINVAL, convert_jfs_vwr_to_pwr(&sendWr, 0, 0, &fixture.comp, true));
    convert_jfs_pwr_to_vwr_resend(&sendWr, &fixture.target.v_tjetty);
    convert_jfs_vwr_to_pwr_for_resend(&sendWr, 0, 0);
    add_vwr_use_cnt(&sendWr);
    release_vwr_use_cnt(&sendWr);

    recvWr.src.sge = fixture.srcSge;
    recvWr.src.num_sge = 1;
    EXPECT_EQ(URMA_SUCCESS, convert_jfr_vwr_to_pwr(&recvWr, 0));

    cr.flag.bs.s_r = 0;
    cr.imm_data = 0x123456789ULL;
    convert_pcr_to_vcr(&cr, &fixture.ctx, &msn);
}

TEST(UrmaBondTest, DatapathPublicPostSendPropagatesSingleDeviceNoStoreFailure)
{
    BondPathFixture fixture;
    urma_jfs_wr_t wr = fixture.MakeRwWr(URMA_OPC_WRITE);
    urma_jfs_wr_t *badWr = nullptr;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.active_count = 1;
    fixture.target.active_count = 1;
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;

    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.comp.v_jfs, &wr, &badWr));
    EXPECT_EQ(nullptr, badWr);
    EXPECT_EQ(0U, fixture.comp.sqe_cnt[0][0].load());
}

TEST(UrmaBondTest, DatapathPublicPostRecvPropagatesSingleDeviceNoStoreFailure)
{
    BondPathFixture fixture;
    urma_sge_t recvSge[1] = {};
    urma_jfr_wr_t wr = {};
    urma_jfr_wr_t *badWr = nullptr;

    recvSge[0].tseg = &fixture.localSeg.v_tseg;
    wr.src.sge = recvSge;
    wr.src.num_sge = 1;
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.comp.active_count = 1;
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;
    fixture.phyOps.post_jfr_wr = MockPostAnyJfrWr;

    EXPECT_EQ(URMA_EINVAL, bondp_post_jfr_wr(&fixture.comp.v_jfr, &wr, &badWr));
    EXPECT_EQ(nullptr, badWr);
    EXPECT_EQ(0U, fixture.comp.rqe_cnt[0]);
}

TEST(UrmaBondTest, DatapathPublicPostRecvWithoutBackupSplitsAcrossActivePaths)
{
    BondPathFixture fixture;
    urma_sge_t firstSge[1] = {};
    urma_sge_t secondSge[1] = {};
    urma_jfr_wr_t firstWr = {};
    urma_jfr_wr_t secondWr = {};
    urma_jfr_wr_t *badWr = nullptr;

    firstSge[0].tseg = &fixture.localSeg.v_tseg;
    secondSge[0].tseg = &fixture.localSeg.v_tseg;
    firstWr.src.sge = firstSge;
    firstWr.src.num_sge = 1;
    firstWr.next = &secondWr;
    secondWr.src.sge = secondSge;
    secondWr.src.num_sge = 1;
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = false;
    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;
    fixture.phyOps.post_jfr_wr = MockPostAnyJfrWr;
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.recv_wr_buf, 2));

    EXPECT_EQ(URMA_EINVAL, bondp_post_jfr_wr(&fixture.comp.v_jfr, &firstWr, &badWr));
    EXPECT_EQ(nullptr, badWr);
    EXPECT_EQ(1U, fixture.comp.rqe_cnt[0] + fixture.comp.rqe_cnt[1]);
    wr_buf_uninit(&fixture.comp.recv_wr_buf);
}

TEST(UrmaBondTest, DatapathPollJfcConvertsSingleDeviceSendCr)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJfsId = MakeJettyId(0x88);

    physicalJfsId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJfsId.eid;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.v_jetty.jetty_id.id = 0x220;
    fixture.comp.sqe_cnt[0][0].store(1);
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJfsId, JFS, fixture.comp.v_jfs.jfs_id.id, &fixture.comp));

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;

    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_SUCCESS;
    g_mockDatapathCr.local_id = physicalJfsId.id;
    g_mockDatapathCr.flag.bs.s_r = 0;
    g_mockDatapathCr.flag.bs.jetty = 0;

    EXPECT_EQ(1, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(fixture.comp.v_jetty.jetty_id.id, outCr.local_id);
    EXPECT_EQ(0U, fixture.comp.sqe_cnt[0][0].load());
    EXPECT_EQ(0, vJfc.lasted_polled_jfc_idx);

    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathFlushJettyConvertsFakeCrAndPropagatesProviderError)
{
    BondPathFixture fixture;
    urma_jetty_t physicalJetty = {};
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJettyId = MakeJettyId(0x99);

    physicalJettyId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJettyId.eid;
    fixture.phyOps.flush_jetty = MockFlushOneCr;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jetty.jetty_id.id = 0x330;
    physicalJetty.urma_ctx = &fixture.phyCtx;
    physicalJetty.jetty_id = physicalJettyId;
    physicalJetty.jetty_cfg.jfs_cfg.depth = 1;
    fixture.comp.p_jetty[0] = &physicalJetty;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJettyId, JETTY, fixture.comp.v_jetty.jetty_id.id, &fixture.comp));

    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_WR_SUSPEND_DONE;
    g_mockDatapathCr.local_id = physicalJettyId.id;
    g_mockDatapathCr.flag.bs.jetty = 1;

    EXPECT_EQ(1, bondp_flush_jetty(&fixture.comp.v_jetty, 1, &outCr));
    EXPECT_EQ(fixture.comp.v_jetty.jetty_id.id, outCr.local_id);

    fixture.phyOps.flush_jetty = [](urma_jetty_t *, int, urma_cr_t *) -> int { return -EIO; };
    EXPECT_EQ(-EIO, bondp_flush_jetty(&fixture.comp.v_jetty, 1, &outCr));

    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathScheduleCoversModesAndErrors)
{
    BondPathFixture fixture;
    int sendIdx = -1;
    int targetIdx = -1;
    int recvIdx = -1;
    bondp_chip_id_info_t chipInfo = { BONDP_CHIP_ID_MIN, BONDP_CHIP_ID_MIN };

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));
    EXPECT_EQ(0, schedule_recv(&fixture.comp, &recvIdx));

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));
    EXPECT_EQ(0, schedule_recv(&fixture.comp, &recvIdx));

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.comp.sqe_cnt[0][0].store(2);
    fixture.comp.sqe_cnt[1][1].store(1);
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, &chipInfo));
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));

    fixture.comp.active_count = 0;
    EXPECT_EQ(-1, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));
    EXPECT_EQ(-1, schedule_recv(&fixture.comp, &recvIdx));

    fixture.comp.active_count = 1;
    fixture.target.active_count = 0;
    EXPECT_EQ(-1, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));

    fixture.target.active_count = 1;
    fixture.ctx.bonding_mode = static_cast<bondp_bonding_mode_t>(0xff);
    EXPECT_EQ(-1, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));
    EXPECT_EQ(-1, schedule_recv(&fixture.comp, &recvIdx));
}

TEST(UrmaBondTest, PublicApiDeletePathsRejectObjectsStillInUse)
{
    BondPublicApiFixture fixture;

    EXPECT_EQ(URMA_EAGAIN, bondp_delete_jfce(&fixture.jfce.v_jfce));
    EXPECT_EQ(URMA_EAGAIN, bondp_delete_jfc(&fixture.jfc.v_jfc));
    EXPECT_EQ(URMA_EAGAIN, bondp_delete_jfs(&fixture.jfs.v_jfs));
    EXPECT_EQ(URMA_EAGAIN, bondp_delete_jfr(&fixture.jfr.v_jfr));
    EXPECT_EQ(URMA_EAGAIN, bondp_delete_jetty(&fixture.jetty.v_jetty));
}

TEST(UrmaBondTest, PublicApiModifyAndQueryHandleEmptyMemberSets)
{
    BondPublicApiFixture fixture;
    urma_jfc_attr_t jfcAttr = {};
    urma_jfs_attr_t jfsAttr = {};
    urma_jfr_attr_t jfrAttr = {};
    urma_jfr_cfg_t queriedCfg = {};
    urma_jetty_attr_t jettyAttr = {};

    jfsAttr.mask = JFS_STATE;
    jfsAttr.state = URMA_JETTY_STATE_ERROR;
    jettyAttr.mask = JETTY_STATE;
    jettyAttr.state = URMA_JETTY_STATE_ERROR;

    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfc(&fixture.jfc.v_jfc, &jfcAttr));
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfs(&fixture.jfs.v_jfs, &jfsAttr));
    EXPECT_TRUE(fixture.jfs.modify_to_error);
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfr(&fixture.jfr.v_jfr, &jfrAttr));
    EXPECT_EQ(URMA_SUCCESS, bondp_query_jfr(&fixture.jfr.v_jfr, &queriedCfg, &jfrAttr));
    EXPECT_EQ(JFR_STATE, jfrAttr.mask);
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jetty(&fixture.jetty.v_jetty, &jettyAttr));
    EXPECT_TRUE(fixture.jetty.modify_to_error);
}

TEST(UrmaBondTest, PublicApiRejectsInvalidCreateAndControlInputs)
{
    BondPublicApiFixture fixture;
    bondp_jfc_cfg_t jfcCfg = {};
    bondp_jfs_cfg_t jfsCfg = {};
    bondp_jfr_cfg_t jfrCfg = {};
    bondp_port_id_t portId = {};
    urma_jetty_cfg_t jettyCfg = {};
    urma_jfc_t *jfcList[1] = {};
    uint32_t nevents[1] = {1};
    urma_async_event_t asyncEvent = {};
    urma_user_ctl_in_t ctl = {};
    urma_user_ctl_out_t ctlOut = {};

    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg));
    urma_jfce_t *jfce = bondp_create_jfce(&fixture.ctx.v_ctx);
    ASSERT_NE(nullptr, jfce);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_jfce(jfce));

    jfcCfg.base.flag.bs.has_drv_ext = 1;
    EXPECT_EQ(nullptr, bondp_create_jfc(&fixture.ctx.v_ctx, &jfcCfg.base));
    jfsCfg.base.flag.bs.has_drv_ext = 1;
    EXPECT_EQ(nullptr, bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg.base));
    jfrCfg.base.flag.bs.has_drv_ext = 1;
    EXPECT_EQ(nullptr, bondp_create_jfr(&fixture.ctx.v_ctx, &jfrCfg.base));

    jfcCfg.port_ids = &portId;
    jfcCfg.port_count = URMA_UBAGG_DEV_MAX_NUM + 1;
    EXPECT_EQ(nullptr, bondp_create_jfc(&fixture.ctx.v_ctx, &jfcCfg.base));
    jfsCfg.port_ids = &portId;
    jfsCfg.port_count = URMA_UBAGG_DEV_MAX_NUM + 1;
    EXPECT_EQ(nullptr, bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg.base));
    jfrCfg.port_ids = &portId;
    jfrCfg.port_count = URMA_UBAGG_DEV_MAX_NUM + 1;
    EXPECT_EQ(nullptr, bondp_create_jfr(&fixture.ctx.v_ctx, &jfrCfg.base));

    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, nullptr, &ctlOut));
    ctl.opcode = UINT32_MAX;
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &ctl, &ctlOut));
    EXPECT_EQ(URMA_EINVAL, bondp_get_async_event(nullptr, &asyncEvent));
    EXPECT_EQ(URMA_EINVAL, bondp_get_async_event(&fixture.ctx.v_ctx, nullptr));

    bondp_jfc_t noJfceJfc = {};
    EXPECT_EQ(URMA_EINVAL, bondp_rearm_jfc(&noJfceJfc.v_jfc, false));
    EXPECT_EQ(-1, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 0, jfcList));
    bondp_ack_jfc(jfcList, nevents, 1);
    asyncEvent.priv = nullptr;
    bondp_ack_async_event(&asyncEvent);
}

TEST(UrmaBondTest, PublicCreateApisRejectInvalidPortIdsBeforeProviderAccess)
{
    BondPublicApiFixture fixture;
    bondp_jfc_cfg_t jfcCfg = {};
    bondp_jfs_cfg_t jfsCfg = {};
    bondp_jfr_cfg_t jfrCfg = {};
    bondp_jetty_cfg_t jettyCfg = {};
    bondp_port_id_t portId = {};

    jfcCfg.base.flag.bs.has_drv_ext = 1;
    jfcCfg.base.jfce = &fixture.jfce.v_jfce;
    jfcCfg.port_ids = &portId;
    jfcCfg.port_count = 1;
    portId.chip_id = 0;
    portId.die_id = 1;
    portId.port_idx = UINT8_MAX;
    EXPECT_EQ(nullptr, bondp_create_jfc(&fixture.ctx.v_ctx, &jfcCfg.base));

    jfsCfg.base.flag.bs.has_drv_ext = 1;
    jfsCfg.base.jfc = &fixture.jfc.v_jfc;
    jfsCfg.port_ids = &portId;
    jfsCfg.port_count = 1;
    portId.chip_id = 1;
    portId.die_id = 2;
    portId.port_idx = UINT8_MAX;
    EXPECT_EQ(nullptr, bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg.base));

    jfrCfg.base.flag.bs.has_drv_ext = 1;
    jfrCfg.base.jfc = &fixture.jfc.v_jfc;
    jfrCfg.port_ids = &portId;
    jfrCfg.port_count = 1;
    portId.chip_id = 1;
    portId.die_id = 1;
    portId.port_idx = PORT_NUM + 1;
    EXPECT_EQ(nullptr, bondp_create_jfr(&fixture.ctx.v_ctx, &jfrCfg.base));

    jettyCfg.base.flag.bs.has_drv_ext = 1;
    jettyCfg.base.flag.bs.share_jfr = URMA_SHARE_JFR;
    jettyCfg.base.shared.jfr = &fixture.jfr.v_jfr;
    jettyCfg.port_ids = &portId;
    jettyCfg.port_count = 1;
    portId.chip_id = 1;
    portId.die_id = 1;
    portId.port_idx = 0;
    fixture.ctx.dev_num = 1;
    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg.base));

    portId.port_idx = UINT8_MAX;
    fixture.ctx.dev_num = 2;
    EXPECT_EQ(nullptr, bondp_create_jfc(&fixture.ctx.v_ctx, &jfcCfg.base));
}

TEST(UrmaBondTest, PublicJfcEventApisDispatchToPhysicalMembers)
{
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    uint32_t nevents[1] = {1};
    int epollFd = -1;
    int eventFd = -1;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.jfc.dev_num = 1;
    fixture.jfce.dev_num = 1;
    fixture.phyOps.rearm_jfc = MockRearmPhysicalJfc;
    EXPECT_EQ(URMA_SUCCESS, bondp_rearm_jfc(&fixture.jfc.v_jfc, true));

    epollFd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(epollFd, 0);
    eventFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(eventFd, 0);
    fixture.jfce.v_jfce.fd = epollFd;
    fixture.phyJfce[0].fd = eventFd;
    fixture.phyJfce[0].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[0] = &fixture.phyJfce[0];
    fixture.phyJfc.jfc_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfc.v_jfc);
    fixture.phyOps.wait_jfc = MockWaitOnePhysicalJfc;
    fixture.phyOps.ack_jfc = MockAckPhysicalJfc;
    g_mockWaitJfc = &fixture.phyJfc;
    ev.events = EPOLLIN;
    ev.data.fd = eventFd;
    ASSERT_EQ(0, epoll_ctl(epollFd, EPOLL_CTL_ADD, eventFd, &ev));
    ASSERT_EQ(0, eventfd_write(eventFd, 1));

    EXPECT_EQ(1, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 0, readyJfc));
    EXPECT_EQ(&fixture.jfc.v_jfc, readyJfc[0]);
    bondp_ack_jfc(readyJfc, nevents, 1);

    EXPECT_EQ(0, close(eventFd));
    EXPECT_EQ(0, close(epollFd));
}

TEST(UrmaBondTest, PublicAsyncEventMapsPhysicalJfsAndAckReleasesPrivateEvent)
{
    BondPublicApiFixture fixture;
    urma_jfc_t physicalJfc = {};
    urma_jfs_t physicalJfs = {};
    urma_jfr_t physicalJfr = {};
    urma_jetty_t physicalJetty = {};
    urma_async_event_t event = {};
    int epollFd = -1;
    int eventFd = -1;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    epollFd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(epollFd, 0);
    eventFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(eventFd, 0);
    fixture.ctx.v_ctx.async_fd = epollFd;
    physicalJfc.urma_ctx = &fixture.phyCtx;
    physicalJfc.jfc_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfc.v_jfc);
    physicalJfs.urma_ctx = &fixture.phyCtx;
    physicalJfs.jfs_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfs.v_jfs);
    physicalJfr.urma_ctx = &fixture.phyCtx;
    physicalJfr.jfr_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfr.v_jfr);
    physicalJetty.urma_ctx = &fixture.phyCtx;
    physicalJetty.jetty_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jetty.v_jetty);
    fixture.phyOps.get_async_event = MockGetAsyncEvent;
    fixture.phyOps.ack_async_event = MockAckAsyncEvent;
    g_mockAckAsyncCount = 0;
    ev.events = EPOLLIN;
    ev.data.ptr = &fixture.phyCtx;
    ASSERT_EQ(0, epoll_ctl(epollFd, EPOLL_CTL_ADD, eventFd, &ev));
    ASSERT_EQ(0, eventfd_write(eventFd, 1));

    g_mockAsyncEvent = {};
    g_mockAsyncEvent.event_type = URMA_EVENT_JFC_ERR;
    g_mockAsyncEvent.element.jfc = &physicalJfc;
    EXPECT_EQ(URMA_SUCCESS, bondp_get_async_event(&fixture.ctx.v_ctx, &event));
    EXPECT_EQ(&fixture.jfc.v_jfc, event.element.jfc);
    bondp_ack_async_event(&event);

    g_mockAsyncEvent = {};
    g_mockAsyncEvent.event_type = URMA_EVENT_JFR_LIMIT;
    g_mockAsyncEvent.element.jfr = &physicalJfr;
    EXPECT_EQ(URMA_SUCCESS, bondp_get_async_event(&fixture.ctx.v_ctx, &event));
    EXPECT_EQ(&fixture.jfr.v_jfr, event.element.jfr);
    bondp_ack_async_event(&event);

    g_mockAsyncEvent = {};
    g_mockAsyncEvent.event_type = URMA_EVENT_JETTY_ERR;
    g_mockAsyncEvent.element.jetty = &physicalJetty;
    EXPECT_EQ(URMA_SUCCESS, bondp_get_async_event(&fixture.ctx.v_ctx, &event));
    EXPECT_EQ(&fixture.jetty.v_jetty, event.element.jetty);
    bondp_ack_async_event(&event);

    g_mockAsyncEvent = {};
    g_mockAsyncEvent.event_type = URMA_EVENT_EID_CHANGE;
    EXPECT_EQ(URMA_SUCCESS, bondp_get_async_event(&fixture.ctx.v_ctx, &event));
    EXPECT_EQ(0U, event.element.eid_idx);
    bondp_ack_async_event(&event);

    g_mockAsyncEvent = {};
    g_mockAsyncEvent.event_type = URMA_EVENT_JFR_ERR;
    g_mockAsyncEvent.element.jfr = &physicalJfr;
    physicalJfr.jfr_cfg.user_ctx = 0;
    EXPECT_EQ(URMA_EINVAL, bondp_get_async_event(&fixture.ctx.v_ctx, &event));
    physicalJfr.jfr_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfr.v_jfr);

    g_mockAsyncEvent = {};
    g_mockAsyncEvent.event_type = URMA_EVENT_JFS_ERR;
    g_mockAsyncEvent.element.jfs = &physicalJfs;
    EXPECT_EQ(URMA_SUCCESS, bondp_get_async_event(&fixture.ctx.v_ctx, &event));
    EXPECT_EQ(&fixture.ctx.v_ctx, event.urma_ctx);
    EXPECT_EQ(URMA_EVENT_JFS_ERR, event.event_type);
    EXPECT_EQ(&fixture.jfs.v_jfs, event.element.jfs);
    ASSERT_NE(nullptr, event.priv);
    bondp_ack_async_event(&event);
    EXPECT_EQ(nullptr, event.priv);
    EXPECT_EQ(5, g_mockAckAsyncCount);

    EXPECT_EQ(0, close(eventFd));
    EXPECT_EQ(0, close(epollFd));
}

TEST(UrmaBondTest, NetlinkPublicApisHandleInvalidAndUninitializedState)
{
    bondp_switchback_req_t req = {};
    bondp_switchback_msg_t msg = {};
    bondp_context_t ctx = {};

    bondp_nl_uninit();
    EXPECT_EQ(-1, bondp_nl_get_fd());
    EXPECT_EQ(-EINVAL, bondp_nl_send_switchback_req(nullptr));
    EXPECT_EQ(-ENOTCONN, bondp_nl_send_switchback_req(&req));
    EXPECT_EQ(-EINVAL, bondp_nl_recv_switchback_msg(nullptr));
    EXPECT_EQ(-ENOTCONN, bondp_nl_recv_switchback_msg(&msg));

    EXPECT_EQ(-EINVAL, bondp_fallback_ctrl_send_default(nullptr, 1, 0, 0, 1, 2, 3));
    EXPECT_EQ(-EINVAL, bondp_fallback_ctrl_send_default(&ctx, 1, -1, 0, 1, 2, 3));
    EXPECT_EQ(-EINVAL, bondp_fallback_ctrl_send_default(&ctx, 1, 0, -1, 1, 2, 3));
    EXPECT_EQ(-ENOTCONN, bondp_fallback_ctrl_send_default(&ctx, 1, 0, 0, 1, 2, 3));
}

TEST(UrmaBondTest, LinkRecoveryRebuildsLocalPjettyWithMockProvider)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfsJfc = {};
    bondp_comp_t vJfr = {};
    bondp_health_task_t task = {};
    urma_jetty_id_t oldId = MakeJettyId(0x610);
    urma_jetty_t *oldJetty = nullptr;

    EXPECT_EQ(-1, bondp_rebuild_local_pjetty(nullptr, 0));
    task.bondp_jetty = nullptr;
    EXPECT_EQ(-1, bondp_rebuild_local_pjetty(&task, 0));

    oldId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    oldJetty = static_cast<urma_jetty_t *>(std::calloc(1, sizeof(*oldJetty)));
    ASSERT_NE(nullptr, oldJetty);
    oldJetty->urma_ctx = &fixture.phyCtx;
    oldJetty->jetty_id = oldId;
    oldJetty->jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    oldJetty->urma_jetty_opt.is_actived = true;

    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyOps.create_jetty = MockCreatePhysicalJetty;
    fixture.phyOps.delete_jetty = MockDeletePhysicalJetty;
    fixture.phyCtx.ref.atomic_cnt.store(2);
    vJfsJfc.p_jfc[0] = &fixture.phyJfc;
    vJfr.comp_type = BONDP_COMP_JFR;
    vJfr.p_jfr[0] = &fixture.phyJfr[0];
    fixture.phyJfr[0].jfr_cfg.jfc = &fixture.phyJfc;
    fixture.phyJfr[0].jfr_cfg.depth = 4;
    fixture.phyJfr[0].jfr_cfg.max_sge = 1;
    fixture.phyJfr[0].jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.comp.bondp_ctx = &fixture.ctx;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jetty.jetty_id.id = 0x620;
    fixture.comp.v_jetty.jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.jfc = &vJfsJfc.v_jfc;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.depth = 4;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.max_sge = 1;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.max_rsge = 1;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.comp.v_jetty.jetty_cfg.shared.jfr = &vJfr.v_jfr;
    fixture.comp.p_jetty[0] = oldJetty;
    fixture.comp.valid[0] = true;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, oldId, JETTY, fixture.comp.v_jetty.jetty_id.id, &fixture.comp));
    task.bondp_jetty = &fixture.comp;
    task.sub_tasks[0][1].valid = true;
    task.sub_tasks[0][1].local_idx = 0;
    task.sub_tasks[0][1].target_idx = 1;
    task.sub_tasks[0][1].probe_pending = true;
    atomic_store(&task.sub_tasks[0][1].link_ok, false);

    EXPECT_EQ(-1, bondp_rebuild_local_pjetty(&task, -1));
    EXPECT_EQ(-1, bondp_rebuild_local_pjetty(&task, URMA_UBAGG_DEV_MAX_NUM));
    EXPECT_EQ(0, bondp_rebuild_local_pjetty(&task, 0));
    ASSERT_NE(nullptr, fixture.comp.p_jetty[0]);
    EXPECT_NE(oldJetty, fixture.comp.p_jetty[0]);
    EXPECT_FALSE(fixture.comp.valid[0]);
    EXPECT_TRUE(task.sub_tasks[0][1].valid);
    EXPECT_FALSE(task.sub_tasks[0][1].probe_pending);
    EXPECT_FALSE(atomic_load(&task.sub_tasks[0][1].link_ok));
    EXPECT_EQ(nullptr, bdp_p_vjetty_id_table_lookup_comp_without_lock(&fixture.ctx.p_vjetty_id_table, oldId, JETTY));
    EXPECT_EQ(&fixture.comp, bdp_p_vjetty_id_table_lookup_comp_without_lock(
        &fixture.ctx.p_vjetty_id_table, fixture.comp.p_jetty[0]->jetty_id, JETTY));

    std::free(fixture.comp.p_jetty[0]);
    fixture.comp.p_jetty[0] = nullptr;
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, PublicCreateApisCleanupPhysicalMembersWhenVirtualCreateFails)
{
    BondPublicApiFixture fixture;
    urma_jfc_cfg_t jfcCfg = {};
    urma_jfs_cfg_t jfsCfg = {};
    urma_jfr_cfg_t jfrCfg = {};
    urma_jetty_cfg_t jettyCfg = {};
    bondp_global_context_t fakeGlobal = {};

    fixture.InitSinglePhysicalMember();
    fixture.InitJfceFdList();
    jfcCfg.jfce = &fixture.jfce.v_jfce;
    EXPECT_EQ(nullptr, bondp_create_jfc(&fixture.ctx.v_ctx, &jfcCfg));

    jfsCfg.jfc = &fixture.jfc.v_jfc;
    jfsCfg.depth = 4;
    jfsCfg.max_sge = 1;
    jfsCfg.max_rsge = 1;
    jfsCfg.trans_mode = URMA_TM_RC;
    EXPECT_EQ(nullptr, bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg));

    jfrCfg.jfc = &fixture.jfc.v_jfc;
    jfrCfg.depth = 4;
    jfrCfg.max_sge = 1;
    jfrCfg.trans_mode = URMA_TM_RC;
    EXPECT_EQ(nullptr, bondp_create_jfr(&fixture.ctx.v_ctx, &jfrCfg));

    fixture.jfr.v_jfr.jfr_cfg.jfc = &fixture.jfc.v_jfc;
    fixture.jfr.v_jfr.jfr_cfg.depth = 4;
    fixture.jfr.v_jfr.jfr_cfg.max_sge = 1;
    fixture.jfr.v_jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.phyJfr.jfr_cfg.depth = 4;
    fixture.phyJfr.jfr_cfg.max_sge = 1;
    fixture.phyJfr.jfr_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    jettyCfg.jfs_cfg.jfc = &fixture.jfc.v_jfc;
    jettyCfg.jfs_cfg.depth = 4;
    jettyCfg.jfs_cfg.max_sge = 1;
    jettyCfg.jfs_cfg.max_rsge = 1;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.shared.jfr = &fixture.jfr.v_jfr;
    jettyCfg.shared.jfc = &fixture.jfc.v_jfc;
    g_bondp_global_ctx = &fakeGlobal;
    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg));
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, PublicUserCtlUpdatesStableContextFlags)
{
    BondPublicApiFixture fixture;
    urma_user_ctl_out_t unusedOut = {};
    bondp_set_bonding_mode_in_t modeIn = {};
    urma_context_aggr_mode_t legacyMode = URMA_AGGR_MODE_BALANCE;

    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    fixture.ctx.seg_cache_enable = false;
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_ENABLE_SEG_CACHE, nullptr, 0, &unusedOut));
    EXPECT_TRUE(fixture.ctx.seg_cache_enable);

    fixture.ctx.msn_enable = true;
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_DISABLE_MSN, nullptr, 0, &unusedOut));
    EXPECT_FALSE(fixture.ctx.msn_enable);

    fixture.ctx.v_ctx.ref.atomic_cnt.store(2);
    fixture.ctx.seg_cache_enable = false;
    EXPECT_EQ(URMA_EAGAIN,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_ENABLE_SEG_CACHE, nullptr, 0, &unusedOut));
    EXPECT_FALSE(fixture.ctx.seg_cache_enable);

    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    EXPECT_EQ(-EINVAL, CallBondUserCtl(nullptr, BONDP_USER_CTL_ENABLE_SEG_CACHE, nullptr, 0, &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, nullptr,
        sizeof(legacyMode), &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, &legacyMode,
        sizeof(legacyMode) - 1, &unusedOut));
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, &legacyMode,
        sizeof(legacyMode), &unusedOut));

    modeIn.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    modeIn.bonding_level = BONDP_BONDING_LEVEL_IODIE;
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE, nullptr,
        sizeof(modeIn), &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE, &modeIn,
        sizeof(modeIn) - 1, &unusedOut));
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE, &modeIn, sizeof(modeIn),
        &unusedOut));
}

TEST(UrmaBondTest, PublicUserCtlQueriesPortsAndJfceFds)
{
    BondPublicApiFixture fixture;
    bondp_query_port_in_t queryIn = {};
    bondp_query_port_out_t queryOut = {};
    bondp_get_jfce_fd_list_in_t fdIn = {};
    bondp_get_jfce_fd_list_out_t fdOut = {};
    urma_user_ctl_in_t in = {};
    urma_user_ctl_out_t out = {};

    fixture.InitActiveComp(&fixture.jfr, 3);
    queryIn.jfr = &fixture.jfr.v_jfr;
    in = MakeUserCtl(BONDP_USER_CTL_QUERY_PORT, &queryIn, sizeof(queryIn));
    out = MakeUserCtlOut(&queryOut, sizeof(queryOut));
    EXPECT_EQ(0, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    EXPECT_EQ(1U, queryOut.enabled_count);
    EXPECT_EQ(3U, queryOut.enabled_indices[0]);
    EXPECT_EQ(1U, queryOut.active_count);
    EXPECT_EQ(3U, queryOut.active_indices[0]);

    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_QUERY_PORT, nullptr, sizeof(queryIn), &out));
    out = MakeUserCtlOut(nullptr, sizeof(queryOut));
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    out = MakeUserCtlOut(&queryOut, sizeof(queryOut));
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_QUERY_PORT, &queryIn, sizeof(queryIn) - 1, &out));
    queryIn.jfr = nullptr;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_QUERY_PORT, &queryIn, sizeof(queryIn), &out));
    fixture.jfr.bondp_ctx = &fixture.otherBondCtx;
    queryIn.jfr = &fixture.jfr.v_jfr;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_QUERY_PORT, &queryIn, sizeof(queryIn), &out));
    fixture.jfr.bondp_ctx = &fixture.ctx;

    fixture.InitJfceFdList();
    fdIn.jfce = &fixture.jfce.v_jfce;
    in = MakeUserCtl(BONDP_USER_CTL_GET_JFCE_FD_LIST, &fdIn, sizeof(fdIn));
    out = MakeUserCtlOut(&fdOut, sizeof(fdOut));
    EXPECT_EQ(0, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    EXPECT_EQ(2U, fdOut.count);
    EXPECT_EQ(10, fdOut.fd_list[0]);
    EXPECT_EQ(11, fdOut.fd_list[1]);

    fdIn.jfce = nullptr;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_GET_JFCE_FD_LIST, &fdIn, sizeof(fdIn), &out));
    fixture.jfce.bondp_ctx = &fixture.otherBondCtx;
    fdIn.jfce = &fixture.jfce.v_jfce;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_GET_JFCE_FD_LIST, &fdIn, sizeof(fdIn), &out));
}

TEST(UrmaBondTest, PublicApiModifyDoesNotMarkErrorForNonErrorState)
{
    BondPublicApiFixture fixture;
    urma_jfs_attr_t jfsAttr = {};
    urma_jetty_attr_t jettyAttr = {};

    jfsAttr.mask = JFS_STATE;
    jfsAttr.state = URMA_JETTY_STATE_READY;
    jettyAttr.mask = JETTY_RX_THRESHOLD;
    jettyAttr.state = URMA_JETTY_STATE_ERROR;

    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfs(&fixture.jfs.v_jfs, &jfsAttr));
    EXPECT_FALSE(fixture.jfs.modify_to_error);
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jetty(&fixture.jetty.v_jetty, &jettyAttr));
    EXPECT_FALSE(fixture.jetty.modify_to_error);
}

TEST(UrmaBondTest, PublicDatapathApisRejectInvalidWorkRequests)
{
    BondPublicApiFixture fixture;
    urma_jfs_wr_t sendWr = {};
    urma_jfs_wr_t *badSend = nullptr;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;
    urma_cr_t cr = {};

    fixture.jfs.comp_type = BONDP_COMP_JFR;
    fixture.jetty.comp_type = BONDP_COMP_JFR;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &sendWr, &badSend));
    EXPECT_EQ(&sendWr, badSend);
    badSend = nullptr;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jetty_send_wr(&fixture.jetty.v_jetty, &sendWr, &badSend));
    EXPECT_EQ(&sendWr, badSend);

    fixture.jfr.comp_type = BONDP_COMP_JFS;
    fixture.jetty.comp_type = BONDP_COMP_JFS;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfr_wr(&fixture.jfr.v_jfr, &recvWr, &badRecv));
    EXPECT_EQ(&recvWr, badRecv);
    badRecv = nullptr;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jetty_recv_wr(&fixture.jetty.v_jetty, &recvWr, &badRecv));
    EXPECT_EQ(&recvWr, badRecv);

    EXPECT_EQ(0, bondp_poll_jfc(&fixture.jfc.v_jfc, 1, &cr));
    EXPECT_EQ(0, bondp_flush_jetty(&fixture.jetty.v_jetty, 1, &cr));
}

TEST(UrmaBondTest, PublicDatapathApisValidateSendWorkRequestFields)
{
    BondPublicApiFixture fixture;
    urma_jfs_wr_t *badSend = nullptr;
    urma_jfs_wr_t writeWr = {};
    urma_jfs_wr_t casWr = {};
    urma_jfs_wr_t faddWr = {};
    bondp_jfs_wr_t affinityWr = {};
    urma_sge_t srcSge = {};
    urma_sge_t dstSge = {};

    writeWr.opcode = URMA_OPC_WRITE;
    writeWr.tjetty = &fixture.targetJetty.v_tjetty;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &writeWr, &badSend));
    EXPECT_EQ(&writeWr, badSend);

    badSend = nullptr;
    casWr.opcode = URMA_OPC_CAS;
    casWr.tjetty = &fixture.targetJetty.v_tjetty;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &casWr, &badSend));
    EXPECT_EQ(&casWr, badSend);

    badSend = nullptr;
    faddWr.opcode = URMA_OPC_FADD;
    faddWr.tjetty = &fixture.targetJetty.v_tjetty;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &faddWr, &badSend));
    EXPECT_EQ(&faddWr, badSend);

    srcSge.tseg = reinterpret_cast<urma_target_seg_t *>(&fixture);
    dstSge.tseg = reinterpret_cast<urma_target_seg_t *>(&fixture.targetJetty);
    affinityWr.base.opcode = URMA_OPC_WRITE;
    affinityWr.base.flag.bs.has_drv_ext = 1;
    affinityWr.base.tjetty = &fixture.targetJetty.v_tjetty;
    affinityWr.base.rw.src.sge = &srcSge;
    affinityWr.base.rw.src.num_sge = 1;
    affinityWr.base.rw.dst.sge = &dstSge;
    affinityWr.base.rw.dst.num_sge = 1;
    affinityWr.src_chip_id = BONDP_CHIP_ID_MAX + 1;
    affinityWr.dst_chip_id = BONDP_CHIP_ID_MIN;
    badSend = nullptr;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &affinityWr.base, &badSend));
    EXPECT_EQ(&affinityWr.base, badSend);
}

TEST(UrmaBondTest, PublicDatapathApisRejectRecvStateBeforeProviderAccess)
{
    BondPublicApiFixture fixture;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;
    jfr_wr_entry_t *heldEntry = nullptr;

    fixture.jetty.v_jetty.jetty_cfg.shared.jfr = nullptr;
    fixture.jetty.comp_type = BONDP_COMP_JETTY;
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    EXPECT_EQ(URMA_EINVAL, bondp_post_jetty_recv_wr(&fixture.jetty.v_jetty, &recvWr, &badRecv));

    ASSERT_EQ(0, wr_buf_init(&fixture.jfr.recv_wr_buf, 1));
    heldEntry = jfr_wr_buf_alloc(&fixture.jfr.recv_wr_buf);
    ASSERT_NE(nullptr, heldEntry);
    fixture.jfr.active_count = 1;
    fixture.jfr.active_indices[0] = 0;
    EXPECT_EQ(URMA_ENOMEM, bondp_post_jfr_wr(&fixture.jfr.v_jfr, &recvWr, &badRecv));
    jfr_wr_buf_release(&fixture.jfr.recv_wr_buf, heldEntry);
    wr_buf_uninit(&fixture.jfr.recv_wr_buf);
}

TEST(UrmaBondTest, PublicDatapathRecvWithoutBackupRejectsStableScheduleFailures)
{
    BondPublicApiFixture fixture;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;

    fixture.ctx.msn_enable = false;
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.jfr.active_count = 0;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfr_wr(&fixture.jfr.v_jfr, &recvWr, &badRecv));

    fixture.jfr.active_count = 1;
    fixture.jfr.active_indices[0] = 0;
    fixture.ctx.bonding_mode = static_cast<bondp_bonding_mode_t>(0xff);
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfr_wr(&fixture.jfr.v_jfr, &recvWr, &badRecv));
}

TEST(UrmaBondTest, PublicDatapathRecvWithoutBackupRejectsOversizedWrList)
{
    BondPublicApiFixture fixture;
    urma_jfr_wr_t recvWr[BOND_TEST_RECV_BATCH_POST_MAX_NUM + 1] = {};
    urma_jfr_wr_t *badRecv = nullptr;

    for (uint32_t i = 0; i < BOND_TEST_RECV_BATCH_POST_MAX_NUM; i++) {
        recvWr[i].next = &recvWr[i + 1];
    }
    fixture.ctx.msn_enable = false;
    fixture.InitActiveComp(&fixture.jfr, 0);
    ASSERT_EQ(0, wr_buf_init(&fixture.jfr.recv_wr_buf, 1));
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfr_wr(&fixture.jfr.v_jfr, &recvWr[0], &badRecv));
    wr_buf_uninit(&fixture.jfr.recv_wr_buf);
}

TEST(UrmaBondTest, PublicDatapathSendWrListReturnsFirstBadWr)
{
    BondPublicApiFixture fixture;
    urma_jfs_wr_t firstWr = {};
    urma_jfs_wr_t secondWr = {};
    urma_jfs_wr_t *badSend = nullptr;

    firstWr.opcode = URMA_OPC_SEND;
    firstWr.tjetty = &fixture.targetJetty.v_tjetty;
    firstWr.next = &secondWr;
    secondWr.opcode = URMA_OPC_WRITE;
    secondWr.tjetty = &fixture.targetJetty.v_tjetty;

    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &firstWr, &badSend));
    EXPECT_EQ(&secondWr, badSend);
}

TEST(UrmaBondTest, PublicTargetJettyRefHelpersAndAffinityWrapper)
{
    BondPublicApiFixture fixture;
    urma_ops_t ops = {};
    urma_jfs_t jfs = {};
    urma_jfc_t jfc = {};
    urma_context_t ctx = {};
    urma_target_seg_t dst = {};
    urma_target_seg_t src = {};

    bondp_tjetty_get(&fixture.targetJetty.v_tjetty);
    EXPECT_EQ(3UL, fixture.targetJetty.use_cnt.atomic_cnt.load());
    bondp_tjetty_put(&fixture.targetJetty.v_tjetty);
    EXPECT_EQ(2UL, fixture.targetJetty.use_cnt.atomic_cnt.load());

    bondp_tjetty_get(&fixture.targetJfr.v_tjetty);
    EXPECT_EQ(3UL, fixture.targetJfr.use_cnt.atomic_cnt.load());
    bondp_tjetty_put(&fixture.targetJfr.v_tjetty);
    EXPECT_EQ(2UL, fixture.targetJfr.use_cnt.atomic_cnt.load());

    EXPECT_EQ(URMA_EINVAL, urma_write_affinity(nullptr, &fixture.targetJfr.v_tjetty, &dst, &src,
                                               0, 0, 4, {}, 0, 0, 0));
    jfs.urma_ctx = &ctx;
    jfs.jfs_cfg.jfc = &jfc;
    EXPECT_EQ(URMA_EINVAL, urma_write_affinity(&jfs, &fixture.targetJfr.v_tjetty, &dst, &src,
                                               0, 0, 4, {}, 0, 0, 0));
    ops.post_jfs_wr = MockPostJfsWr;
    ctx.ops = &ops;
    EXPECT_EQ(URMA_EINVAL, urma_write_affinity(&jfs, nullptr, &dst, &src, 0, 0, 4, {}, 0, 0, 0));
    EXPECT_EQ(URMA_EINVAL, urma_write_affinity(&jfs, &fixture.targetJfr.v_tjetty, nullptr, &src,
                                               0, 0, 4, {}, 0, 0, 0));
    EXPECT_EQ(URMA_SUCCESS, urma_write_affinity(&jfs, &fixture.targetJfr.v_tjetty, &dst, &src,
                                                0x1000, 0x2000, 4, {}, 0x55, 1, 2));
}

TEST(UrmaBondTest, PublicJettyBindAndUnimportApisCoverSafeStateTransitions)
{
    BondPublicApiFixture fixture;

    EXPECT_EQ(URMA_FAIL, bondp_bind_jetty(&fixture.jetty.v_jetty, &fixture.targetJetty.v_tjetty));
    fixture.jetty.v_jetty.remote_jetty = &fixture.targetJetty.v_tjetty;
    EXPECT_EQ(URMA_EINVAL, bondp_bind_jetty(&fixture.jetty.v_jetty, &fixture.targetJetty.v_tjetty));

    EXPECT_EQ(URMA_SUCCESS, bondp_unbind_jetty(&fixture.jetty.v_jetty));
    EXPECT_EQ(nullptr, fixture.jetty.v_jetty.remote_jetty);
    EXPECT_EQ(1UL, fixture.targetJetty.use_cnt.atomic_cnt.load());

    SetRefCount(&fixture.targetJetty.use_cnt, 2);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jetty(&fixture.targetJetty.v_tjetty));
    EXPECT_EQ(1UL, fixture.targetJetty.use_cnt.atomic_cnt.load());

    SetRefCount(&fixture.targetJfr.use_cnt, 2);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jfr(&fixture.targetJfr.v_tjetty));
    EXPECT_EQ(1UL, fixture.targetJfr.use_cnt.atomic_cnt.load());
}

TEST(UrmaBondTest, PublicImportApisPropagateCommandFailureWithoutDevices)
{
    BondPublicApiFixture fixture;
    urma_rjetty_t rjetty = {};
    urma_rjfr_t rjfr = {};
    urma_token_t token = {};

    /* dev_fd=-1 keeps the ioctl path deterministic and avoids touching /dev or sysfs. */
    fixture.ctx.v_ctx.dev_fd = -1;
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, &rjetty, &token));
    EXPECT_EQ(nullptr, bondp_import_jfr(&fixture.ctx.v_ctx, &rjfr, &token));
}

TEST(UrmaBondTest, PublicSegmentApisCoverTokenAndRefcountPaths)
{
    BondPublicApiFixture fixture;
    urma_token_id_t token = {};
    urma_seg_cfg_t segCfg = {};
    bondp_tseg_t localSeg = {};
    bondp_import_tseg_t remoteSeg = {};

    urma_token_id_t *allocated = bondp_alloc_token_id(&fixture.ctx.v_ctx);
    ASSERT_NE(nullptr, allocated);
    EXPECT_EQ(&fixture.ctx.v_ctx, allocated->urma_ctx);
    EXPECT_EQ(URMA_SUCCESS, bondp_free_token_id(allocated));
    EXPECT_EQ(URMA_SUCCESS, bondp_free_token_id(nullptr));

    segCfg.token_id = nullptr;
    EXPECT_EQ(nullptr, bondp_register_seg(&fixture.ctx.v_ctx, &segCfg));
    segCfg.token_id = &token;
    segCfg.flag.bs.token_id_valid = URMA_TOKEN_ID_INVALID;
    EXPECT_EQ(nullptr, bondp_register_seg(&fixture.ctx.v_ctx, &segCfg));
    segCfg.flag.bs.token_id_valid = 1;
    fixture.ctx.v_ctx.dev_fd = -1;
    EXPECT_EQ(nullptr, bondp_register_seg(&fixture.ctx.v_ctx, &segCfg));

    urma_seg_t remoteSegInfo = {};
    urma_token_t importToken = {};
    EXPECT_EQ(nullptr, bondp_import_seg(&fixture.ctx.v_ctx, &remoteSegInfo, &importToken, 0x1000, {}));

    localSeg.v_tseg.token_id = &token;
    SetRefCount(&localSeg.use_cnt, 2);
    bondp_tseg_get(&localSeg.v_tseg);
    EXPECT_EQ(3UL, localSeg.use_cnt.atomic_cnt.load());
    EXPECT_EQ(URMA_SUCCESS, bondp_unregister_seg(&localSeg.v_tseg));
    EXPECT_EQ(2UL, localSeg.use_cnt.atomic_cnt.load());
    bondp_tseg_put(&localSeg.v_tseg);
    EXPECT_EQ(1UL, localSeg.use_cnt.atomic_cnt.load());

    remoteSeg.v_tseg.token_id = nullptr;
    SetRefCount(&remoteSeg.use_cnt, 2);
    bondp_tseg_get(&remoteSeg.v_tseg);
    EXPECT_EQ(3UL, remoteSeg.use_cnt.atomic_cnt.load());
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_seg(&remoteSeg.v_tseg));
    EXPECT_EQ(2UL, remoteSeg.use_cnt.atomic_cnt.load());
    bondp_tseg_put(&remoteSeg.v_tseg);
    EXPECT_EQ(1UL, remoteSeg.use_cnt.atomic_cnt.load());
}

TEST(UrmaBondTest, PublicSegmentRegisterCleansPhysicalSegWhenVirtualRegisterFails)
{
    BondPublicApiFixture fixture;
    urma_token_id_t token = {};
    urma_seg_cfg_t segCfg = {};

    /*
     * Physical member registration is mocked in memory. The virtual segment still
     * stops at dev_fd=-1, so this covers rollback without opening a real device.
     */
    fixture.InitSinglePhysicalMember();
    fixture.ctx.v_ctx.dev_fd = -1;
    token.urma_ctx = &fixture.ctx.v_ctx;
    segCfg.token_id = &token;
    segCfg.flag.bs.token_id_valid = URMA_TOKEN_ID_VALID;
    segCfg.va = 0x100000;
    segCfg.len = 4096;

    EXPECT_EQ(nullptr, bondp_register_seg(&fixture.ctx.v_ctx, &segCfg));
}

TEST(UrmaBondTest, PublicSegmentApisReleaseLastReferencesThroughStableFailures)
{
    BondPublicApiFixture fixture;
    urma_token_id_t token = {};
    auto *localSeg = static_cast<bondp_tseg_t *>(std::calloc(1, sizeof(bondp_tseg_t)));
    auto *remoteSeg = static_cast<bondp_import_tseg_t *>(std::calloc(1, sizeof(bondp_import_tseg_t)));
    auto *fullRemoteSeg = static_cast<bondp_import_tseg_t *>(std::calloc(1, sizeof(bondp_import_tseg_t)));
    urma_target_seg_t phySeg = {};

    ASSERT_NE(nullptr, localSeg);
    ASSERT_NE(nullptr, remoteSeg);
    ASSERT_NE(nullptr, fullRemoteSeg);
    fixture.ctx.v_ctx.dev_fd = -1;
    localSeg->v_tseg.token_id = &token;
    localSeg->v_tseg.urma_ctx = &fixture.ctx.v_ctx;
    localSeg->v_tseg.handle = reinterpret_cast<uint64_t>(&localSeg->v_tseg);
    localSeg->v_orig_handle = 0x1010;
    SetRefCount(&localSeg->use_cnt, 1);
    EXPECT_EQ(URMA_SUCCESS, bondp_unregister_seg(&localSeg->v_tseg));

    remoteSeg->v_tseg.token_id = nullptr;
    remoteSeg->v_tseg.urma_ctx = &fixture.ctx.v_ctx;
    remoteSeg->v_tseg.handle = reinterpret_cast<uint64_t>(&remoteSeg->v_tseg);
    remoteSeg->is_reused = true;
    SetRefCount(&remoteSeg->use_cnt, 1);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_seg(&remoteSeg->v_tseg));

    fullRemoteSeg->v_tseg.token_id = nullptr;
    fullRemoteSeg->v_tseg.urma_ctx = &fixture.ctx.v_ctx;
    fullRemoteSeg->v_tseg.handle = reinterpret_cast<uint64_t>(&fullRemoteSeg->v_tseg);
    fullRemoteSeg->v_orig_handle = 0x2020;
    fullRemoteSeg->is_reused = false;
    phySeg.urma_ctx = &fixture.ctx.v_ctx;
    phySeg.handle = 0x3030;
    fullRemoteSeg->p_tseg[0][0] = &phySeg;
    fullRemoteSeg->p_orig_handle[0][0] = 0x4040;
    SetRefCount(&fullRemoteSeg->use_cnt, 1);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_seg(&fullRemoteSeg->v_tseg));
}

TEST(UrmaBondTest, PublicProviderOpsRejectInvalidOrUninitializedState)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_device_t dev = {};

    std::snprintf(dev.name, sizeof(dev.name), "bond_ut");
    fixture.ctx.v_ctx.dev = &dev;
    fixture.ctx.v_ctx.ref.atomic_cnt.store(0);

    EXPECT_EQ(nullptr, bondp_create_context(&dev, 0, -1));
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(-EINVAL, bondp_set_bonding_mode(nullptr, BONDP_BONDING_MODE_BALANCE,
                                              BONDP_BONDING_LEVEL_IODIE));
    EXPECT_EQ(-EINVAL, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_MAX,
                                              BONDP_BONDING_LEVEL_IODIE));
    EXPECT_EQ(-EINVAL, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_BALANCE,
                                              BONDP_BONDING_LEVEL_MAX));

    fixture.ctx.v_ctx.ref.atomic_cnt.store(2);
    EXPECT_EQ(URMA_EAGAIN, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_BALANCE,
                                                  BONDP_BONDING_LEVEL_IODIE));

    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.bonding_level = BONDP_BONDING_LEVEL_IODIE;
    EXPECT_EQ(0, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_BALANCE,
                                        BONDP_BONDING_LEVEL_IODIE));

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.bonding_level = BONDP_BONDING_LEVEL_IODIE;
    fixture.ctx.v_ctx.dev_fd = -1;
    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    EXPECT_EQ(-1, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_STANDALONE,
                                         BONDP_BONDING_LEVEL_IODIE));

    g_bondp_global_ctx = &fakeGlobal;
    EXPECT_EQ(URMA_FAIL, bondp_init(nullptr));
    EXPECT_EQ(nullptr, bondp_create_context(&dev, 0, -1));
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, PublicProviderDeleteContextPropagatesVirtualDeleteFailure)
{
    auto *ctx = static_cast<bondp_context_t *>(std::calloc(1, sizeof(bondp_context_t)));
    ASSERT_NE(nullptr, ctx);
    bondp_global_context_t fakeGlobal = {};
    urma_device_t dev = {};

    std::snprintf(dev.name, sizeof(dev.name), "bond_delete_ut");
    ctx->v_ctx.dev = &dev;
    ctx->v_ctx.dev_fd = -1;
    ctx->v_ctx.async_fd = -1;
    ctx->real_async_fd = -1;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&ctx->p_vjetty_id_table, 4));
    ASSERT_EQ(0, bdp_r_v2p_token_id_table_create(&ctx->remote_v2p_token_id_table, 4));

    g_bondp_global_ctx = &fakeGlobal;
    fakeGlobal.health_thread_ctx.enable_health_check = false;
    EXPECT_EQ(URMA_FAIL, bondp_delete_context(&ctx->v_ctx));
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, PublicProviderUninitReleasesHeapGlobalContext)
{
    auto *global = static_cast<bondp_global_context_t *>(std::calloc(1, sizeof(bondp_global_context_t)));
    ASSERT_NE(nullptr, global);

    /*
     * bondp_uninit owns and frees the global context. Keep this fixture heap-backed
     * and health-check disabled so the test covers cleanup without starting threads.
     */
    bondp_health_check_global_ctx_init(global);
    global->health_thread_ctx.enable_health_check = false;
    g_bondp_global_ctx = global;

    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
}

TEST(UrmaBondTest, HealthCheckPublicApisHonorDisabledContract)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_bond_seg_info_out_t segOut = {};
    urma_bond_id_info_out_t idOut = {};
    urma_rjetty_t rjetty = {};
    urma_cr_t cr = {};
    bool enabled = true;

    /*
     * Health check normal operation owns eventfd, epoll, netlink and provider resources.
     * The public contract is still stable when disabled, so keep this UT at that outer boundary.
     */
    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    EXPECT_FALSE(bondp_health_check_enabled());

    bondp_health_check_ctx_init(&fixture.ctx);
    EXPECT_EQ(4096U, fixture.ctx.bondp_heath_check_ctx.check_buf_len);
    EXPECT_EQ(-1, fixture.ctx.bondp_heath_check_ctx.health_check_fd);

    EXPECT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    EXPECT_EQ(0, bondp_register_health_check_seg_for_jetty(&fixture.ctx, &fixture.jetty));
    EXPECT_EQ(0, bondp_fill_vjetty_health_info(&fixture.ctx, &fixture.jetty, &segOut, &enabled));
    EXPECT_FALSE(enabled);

    idOut.is_health_check_enable = true;
    EXPECT_EQ(0, bondp_import_health_check_tseg(&fixture.ctx, &fixture.targetJetty, &idOut, &rjetty));
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_health_check_tseg(&fixture.targetJetty));
    EXPECT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));

    bondp_health_update_active_idx(&fixture.ctx, &fixture.targetJetty, 0);
    bondp_health_kick_fallback_task(&fixture.ctx, &fixture.targetJetty);
    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, 0, 1, 0, 0);
    bondp_health_notify_datapath_link_fail(&fixture.ctx, &fixture.targetJetty, 0, 0);
    bondp_notify_health_event(&fixture.ctx, BONDP_HEALTH_EVENT_ACTIVE_IDX_UPDATE, nullptr);
    EXPECT_FALSE(bondp_try_handle_health_check_cr(&fixture.ctx, 0, &cr));

    bondp_unregister_health_check_task(&fixture.ctx, &fixture.targetJetty);
    bondp_unregister_health_check_seg_for_jetty(&fixture.jetty);
    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckContextCreateAndDestroyUseLocalEventFds)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};

    /*
     * This covers enabled context lifecycle without starting the health thread or touching
     * provider resources. The epoll fd is local to the test and closed by global uninit.
     */
    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    EXPECT_GE(fixture.ctx.bondp_heath_check_ctx.health_check_fd, 0);
    bondp_destroy_health_check_ctx(&fixture.ctx);
    EXPECT_EQ(-1, fixture.ctx.bondp_heath_check_ctx.health_check_fd);

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}
