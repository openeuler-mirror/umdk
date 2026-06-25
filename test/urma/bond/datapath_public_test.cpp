/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding public datapath unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

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

TEST(UrmaBondTest, DatapathPublicPostRecvWithoutBackupRejectsOversizedList)
{
    BondPathFixture fixture;
    urma_sge_t recvSge[1] = {};
    std::vector<urma_jfr_wr_t> wrs(BONDP_BATCH_POST_MAX_NUM + 1);
    urma_jfr_wr_t *badWr = nullptr;

    recvSge[0].tseg = &fixture.localSeg.v_tseg;
    for (size_t i = 0; i < wrs.size(); i++) {
        wrs[i].src.sge = recvSge;
        wrs[i].src.num_sge = 1;
        wrs[i].next = (i + 1 < wrs.size()) ? &wrs[i + 1] : nullptr;
    }
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = false;
    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.phyOps.post_jfr_wr = MockPostAnyJfrWr;

    EXPECT_EQ(URMA_EINVAL, bondp_post_jfr_wr(&fixture.comp.v_jfr, &wrs[0], &badWr));
    EXPECT_EQ(nullptr, badWr);
    EXPECT_EQ(0, urma_test::GetHwMockState().postJfrCount);
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

TEST(UrmaBondTest, DatapathPollJfcConvertsRecvCrWithoutBackup)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJfrId = MakeJettyId(0x8d);

    physicalJfrId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = false;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJfrId.eid;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.comp.v_jfr.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jfr.jfr_id.id = 0x8e;
    fixture.comp.p_jfr[0] = &fixture.phyJfr[0];
    fixture.comp.rqe_cnt[0] = 1;
    fixture.phyJfr[0].jfr_id = physicalJfrId;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJfrId, JFR, fixture.comp.v_jfr.jfr_id.id, &fixture.comp));

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;

    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_SUCCESS;
    g_mockDatapathCr.local_id = physicalJfrId.id;
    g_mockDatapathCr.flag.bs.s_r = 1;
    g_mockDatapathCr.opcode = URMA_CR_OPC_SEND_WITH_IMM;

    EXPECT_EQ(1, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(fixture.comp.v_jfr.jfr_id.id, outCr.local_id);
    EXPECT_EQ(0U, fixture.comp.rqe_cnt[0]);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathPollRecvCrWithStoreUsesBufferedWr)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    jfr_wr_entry_t *entry = nullptr;
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJfrId = MakeJettyId(0x91);

    physicalJfrId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.recv_wr_buf, 2));
    ASSERT_EQ(0, bondp_conn_table_create(&fixture.comp.v_conn_table, 4));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJfrId.eid;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.valid[0] = true;
    fixture.comp.v_jfr.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jfr.jfr_id.id = 0x92;
    fixture.comp.p_jfr[0] = &fixture.phyJfr[0];
    fixture.phyJfr[0].jfr_id = physicalJfrId;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJfrId, JFR, fixture.comp.v_jfr.jfr_id.id, &fixture.comp));
    entry = jfr_wr_buf_alloc(&fixture.comp.recv_wr_buf);
    ASSERT_NE(nullptr, entry);
    entry->bdp_comp = &fixture.comp;
    entry->recv_idx = 0;
    entry->user_ctx = 0xcafe;
    fixture.comp.rqe_cnt[0] = 1;

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;

    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_SUCCESS;
    g_mockDatapathCr.local_id = physicalJfrId.id;
    g_mockDatapathCr.user_ctx = entry->wr_id;
    g_mockDatapathCr.flag.bs.s_r = 1;
    g_mockDatapathCr.opcode = URMA_CR_OPC_SEND_WITH_IMM;
    g_mockDatapathCr.remote_id = MakeJettyId(0x93);

    EXPECT_EQ(1, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(fixture.comp.v_jfr.jfr_id.id, outCr.local_id);
    EXPECT_EQ(0xcafeU, outCr.user_ctx);
    EXPECT_EQ(0U, fixture.comp.rqe_cnt[0]);

    bondp_hash_table_destroy(&fixture.comp.v_conn_table);
    wr_buf_uninit(&fixture.comp.recv_wr_buf);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathPollJfcConvertsFakeCrWithStore)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJettyId = MakeJettyId(0x8f);

    physicalJettyId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJettyId.eid;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.modify_to_error = true;
    fixture.comp.v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jetty.jetty_id.id = 0x90;
    fixture.comp.p_jetty[0] = &fixture.phyJetty[0];
    fixture.comp.p_jetty[1] = nullptr;
    fixture.phyJetty[0].jetty_id = physicalJettyId;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJettyId, JETTY, fixture.comp.v_jetty.jetty_id.id, &fixture.comp));

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;

    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_WR_FLUSH_ERR_DONE;
    g_mockDatapathCr.local_id = physicalJettyId.id;
    g_mockDatapathCr.flag.bs.jetty = 1;

    EXPECT_EQ(1, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(fixture.comp.v_jetty.jetty_id.id, outCr.local_id);
    EXPECT_NE(0U, fixture.comp.pjettys_error_done[0]);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathPostSendStoreAndPollCompletionRoundTrip)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    urma_jfs_wr_t wr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t *badWr = nullptr;
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJfsId = MakeJettyId(0x8a);
    urma_status_t postRet;
    urma_jfs_wr_t copiedWr = {};
    urma_sge_t copiedSrc[1] = {};
    urma_sge_t copiedDst[1] = {};
    int scheduledSendIdx = -1;
    int scheduledTargetIdx = -1;

    physicalJfsId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJfsId.eid;
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.valid[0] = true;
    fixture.comp.v_jfs.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jfs.jfs_id.id = 0x8b;
    fixture.comp.p_jfs[0] = &fixture.phyJfs[0];
    fixture.target.active_count = 1;
    fixture.target.active_indices[0] = 0;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.valid[0] = true;
    fixture.target.is_msn_enabled = true;
    fixture.target.v_tjetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.target.v_tjetty.id.id = 0x8c;
    fixture.target.v_tjetty.type = URMA_JETTY;
    SetRefCount(&fixture.target.use_cnt, 2);
    SetRefCount(&fixture.localSeg.use_cnt, 2);
    SetRefCount(&fixture.remoteSeg.use_cnt, 2);
    fixture.target.p_tjetty[0][0] = &fixture.phyTarget[0][0];
    fixture.phyJfs[0].jfs_id = physicalJfsId;
    fixture.phyJfs[0].jfs_cfg.jfc = &fixture.phyJfc;
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.send_wr_buf, 4));
    ASSERT_EQ(0, pthread_spin_init(&fixture.comp.send_lock, PTHREAD_PROCESS_PRIVATE));
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJfsId, JFS, fixture.comp.v_jfs.jfs_id.id, &fixture.comp));

    wr.user_ctx = 0xbeef;
    EXPECT_EQ(0, schedule_send(wr.tjetty, &fixture.comp, &scheduledSendIdx, &scheduledTargetIdx, nullptr));
    EXPECT_EQ(0, scheduledSendIdx);
    EXPECT_EQ(0, scheduledTargetIdx);
    EXPECT_EQ(URMA_SUCCESS, copy_jfs_wr(&wr, &copiedWr, copiedSrc, copiedDst));
    EXPECT_EQ(URMA_SUCCESS, encode_jfs_wr_msn(&copiedWr, &fixture.comp, 0, fixture.target.is_msn_enabled));
    ASSERT_EQ(URMA_SUCCESS, urma_post_jfs_wr(fixture.comp.p_jfs[0], &wr, &badWr));
    urma_test::GetHwMockState().postJfsCount = 0;
    badWr = nullptr;

    postRet = bondp_post_jfs_wr(&fixture.comp.v_jfs, &wr, &badWr);
    if (postRet != URMA_SUCCESS) {
        EXPECT_EQ(0, urma_test::GetHwMockState().postJfsCount);
        pthread_spin_destroy(&fixture.comp.send_lock);
        wr_buf_uninit(&fixture.comp.send_wr_buf);
        EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
        ASSERT_EQ(URMA_SUCCESS, postRet);
    }
    EXPECT_EQ(nullptr, badWr);
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfsCount);
    EXPECT_EQ(1U, fixture.comp.sqe_cnt[0][0].load());

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;
    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_SUCCESS;
    g_mockDatapathCr.local_id = physicalJfsId.id;
    g_mockDatapathCr.user_ctx = 1;

    EXPECT_EQ(1, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(fixture.comp.v_jfs.jfs_id.id, outCr.local_id);
    EXPECT_EQ(0xbeefU, outCr.user_ctx);
    EXPECT_EQ(0U, fixture.comp.sqe_cnt[0][0].load());

    pthread_spin_destroy(&fixture.comp.send_lock);
    wr_buf_uninit(&fixture.comp.send_wr_buf);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathPostSendStoreHandlesFullBufferAndInvalidPathRetry)
{
    BondPathFixture fixture;
    urma_jfs_wr_t wr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t invalidWr = fixture.MakeRwWr(URMA_OPC_WRITE);
    urma_jfs_wr_t *badWr = nullptr;
    jfs_wr_entry_t *heldEntry = nullptr;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.valid[0] = true;
    fixture.comp.v_jfs.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.p_jfs[0] = &fixture.phyJfs[0];
    fixture.target.active_count = 1;
    fixture.target.active_indices[0] = 0;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.valid[0] = true;
    fixture.target.is_msn_enabled = true;
    fixture.target.v_tjetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.target.v_tjetty.type = URMA_JETTY;
    fixture.target.p_tjetty[0][0] = &fixture.phyTarget[0][0];
    SetRefCount(&fixture.target.use_cnt, 2);
    SetRefCount(&fixture.localSeg.use_cnt, 2);
    SetRefCount(&fixture.remoteSeg.use_cnt, 2);
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.send_wr_buf, 1));
    ASSERT_EQ(0, pthread_spin_init(&fixture.comp.send_lock, PTHREAD_PROCESS_PRIVATE));

    heldEntry = jfs_wr_buf_alloc(&fixture.comp.send_wr_buf);
    ASSERT_NE(nullptr, heldEntry);
    EXPECT_EQ(URMA_EAGAIN, bondp_post_jfs_wr(&fixture.comp.v_jfs, &wr, &badWr));
    jfs_wr_buf_release(&fixture.comp.send_wr_buf, heldEntry);

    heldEntry = jfs_wr_buf_alloc(&fixture.comp.send_wr_buf);
    ASSERT_NE(nullptr, heldEntry);
    fixture.comp.valid[0] = false;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.comp.v_jfs, &wr, &badWr));
    jfs_wr_buf_release(&fixture.comp.send_wr_buf, heldEntry);

    fixture.comp.valid[0] = false;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.comp.v_jfs, &wr, &badWr));

    fixture.comp.valid[0] = true;
    invalidWr.rw.src.num_sge = BONDP_MAX_SGE_NUM + 1;
    EXPECT_EQ(URMA_ENOMEM, bondp_post_jfs_wr(&fixture.comp.v_jfs, &invalidWr, &badWr));

    pthread_spin_destroy(&fixture.comp.send_lock);
    wr_buf_uninit(&fixture.comp.send_wr_buf);
}

TEST(UrmaBondTest, DatapathPostSendStoreRollsBackAfterPartialProviderFailure)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    urma_jfs_wr_t firstWr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t secondWr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t *badWr = nullptr;
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJfsId = MakeJettyId(0x9a);

    physicalJfsId.uasid = 0;
    firstWr.user_ctx = 0x101;
    secondWr.user_ctx = 0x202;
    firstWr.next = &secondWr;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.send_wr_buf, 4));
    ASSERT_EQ(0, pthread_spin_init(&fixture.comp.send_lock, PTHREAD_PROCESS_PRIVATE));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJfsId.eid;
    fixture.phyOps.post_jfs_wr = MockPostSecondJfsWrFails;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.valid[0] = true;
    fixture.comp.v_jfs.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jfs.jfs_id.id = 0x9b;
    fixture.comp.p_jfs[0] = &fixture.phyJfs[0];
    fixture.target.active_count = 1;
    fixture.target.active_indices[0] = 0;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.valid[0] = true;
    fixture.target.is_msn_enabled = true;
    fixture.target.v_tjetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.target.v_tjetty.id.id = 0x9c;
    fixture.target.v_tjetty.type = URMA_JETTY;
    fixture.target.p_tjetty[0][0] = &fixture.phyTarget[0][0];
    fixture.phyJfs[0].jfs_id = physicalJfsId;
    fixture.phyJfs[0].jfs_cfg.jfc = &fixture.phyJfc;
    SetRefCount(&fixture.target.use_cnt, 3);
    SetRefCount(&fixture.localSeg.use_cnt, 3);
    SetRefCount(&fixture.remoteSeg.use_cnt, 3);
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJfsId, JFS, fixture.comp.v_jfs.jfs_id.id, &fixture.comp));

    EXPECT_EQ(URMA_EAGAIN, bondp_post_jfs_wr(&fixture.comp.v_jfs, &firstWr, &badWr));
    EXPECT_NE(nullptr, badWr);
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfsCount);
    EXPECT_EQ(1U, fixture.comp.sqe_cnt[0][0].load());

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;
    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_SUCCESS;
    g_mockDatapathCr.local_id = physicalJfsId.id;
    g_mockDatapathCr.user_ctx = 1;

    EXPECT_EQ(1, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(firstWr.user_ctx, outCr.user_ctx);
    EXPECT_EQ(0U, fixture.comp.sqe_cnt[0][0].load());

    pthread_spin_destroy(&fixture.comp.send_lock);
    wr_buf_uninit(&fixture.comp.send_wr_buf);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, DatapathPostRecvStoreSubmitsAndCleansProviderFailure)
{
    BondPathFixture fixture;
    urma_sge_t recvSge[2] = {};
    urma_jfr_wr_t firstWr = {};
    urma_jfr_wr_t secondWr = {};
    urma_jfr_wr_t *badWr = nullptr;

    recvSge[0].tseg = &fixture.localSeg.v_tseg;
    recvSge[1].tseg = &fixture.localSeg.v_tseg;
    firstWr.src.sge = &recvSge[0];
    firstWr.src.num_sge = 1;
    firstWr.user_ctx = 0x1010;
    firstWr.next = &secondWr;
    secondWr.src.sge = &recvSge[1];
    secondWr.src.num_sge = 1;
    secondWr.user_ctx = 0x2020;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.v_jfr.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.p_jfr[0] = &fixture.phyJfr[0];
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;
    fixture.phyOps.post_jfr_wr = MockPostAnyJfrWr;
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.recv_wr_buf, 4));

    EXPECT_EQ(URMA_SUCCESS, bondp_post_jfr_wr(&fixture.comp.v_jfr, &firstWr, &badWr));
    EXPECT_EQ(nullptr, badWr);
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfrCount);
    EXPECT_EQ(2U, fixture.comp.rqe_cnt[0]);

    urma_test::ResetHwMockState();
    badWr = nullptr;
    fixture.comp.rqe_cnt[0] = 0;
    fixture.phyOps.post_jfr_wr = MockPostFirstJfrWrFails;
    EXPECT_EQ(URMA_EAGAIN, bondp_post_jfr_wr(&fixture.comp.v_jfr, &firstWr, &badWr));
    EXPECT_NE(nullptr, badWr);
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfrCount);
    EXPECT_EQ(0U, fixture.comp.rqe_cnt[0]);

    wr_buf_uninit(&fixture.comp.recv_wr_buf);
}

TEST(UrmaBondTest, DatapathFailoverCrResendsBufferedJfsWrToBackupPath)
{
    BondPathFixture fixture;
    bondp_jfc_t vJfc = {};
    urma_jfs_wr_t wr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t *badWr = nullptr;
    urma_cr_t outCr = {};
    urma_jetty_id_t physicalJfsId = MakeJettyId(0x94);

    physicalJfsId.uasid = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.send_wr_buf, 4));
    ASSERT_EQ(0, pthread_spin_init(&fixture.comp.send_lock, PTHREAD_PROCESS_PRIVATE));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyCtx.eid = physicalJfsId.eid;
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.active_count = 2;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.active_indices[1] = 1;
    fixture.comp.valid[0] = true;
    fixture.comp.valid[1] = true;
    fixture.comp.v_jfs.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jfs.jfs_id.id = 0x95;
    fixture.comp.p_jfs[0] = &fixture.phyJfs[0];
    fixture.comp.p_jfs[1] = &fixture.phyJfs[1];
    fixture.target.active_count = 2;
    fixture.target.active_indices[0] = 0;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.active_indices[1] = 1;
    fixture.target.local_active_indices[1] = 1;
    fixture.target.valid[0] = true;
    fixture.target.valid[1] = true;
    fixture.target.is_msn_enabled = true;
    fixture.target.v_tjetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.target.v_tjetty.id.id = 0x96;
    fixture.target.v_tjetty.type = URMA_JETTY;
    SetRefCount(&fixture.target.use_cnt, 2);
    SetRefCount(&fixture.localSeg.use_cnt, 2);
    SetRefCount(&fixture.remoteSeg.use_cnt, 2);
    fixture.target.p_tjetty[0][0] = &fixture.phyTarget[0][0];
    fixture.target.p_tjetty[1][1] = &fixture.phyTarget[1][1];
    fixture.phyJfs[0].jfs_id = physicalJfsId;
    fixture.phyJfs[0].jfs_cfg.jfc = &fixture.phyJfc;
    fixture.phyJfs[1].jfs_cfg.jfc = &fixture.phyJfc;
    fixture.comp.sqe_cnt[1][1].store(1);
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, physicalJfsId, JFS, fixture.comp.v_jfs.jfs_id.id, &fixture.comp));

    wr.user_ctx = 0xbeef;
    ASSERT_EQ(URMA_SUCCESS, bondp_post_jfs_wr(&fixture.comp.v_jfs, &wr, &badWr));
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfsCount);
    EXPECT_EQ(1U, fixture.comp.sqe_cnt[0][0].load());

    vJfc.v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    vJfc.dev_num = 1;
    vJfc.lasted_polled_jfc_idx = -1;
    vJfc.p_jfc[0] = &fixture.phyJfc;
    g_mockDatapathCr = {};
    g_mockDatapathCrCount = 1;
    g_mockDatapathCr.status = URMA_CR_ACK_TIMEOUT_ERR;
    g_mockDatapathCr.local_id = physicalJfsId.id;
    g_mockDatapathCr.user_ctx = 1;

    EXPECT_EQ(0, bondp_poll_jfc(&vJfc.v_jfc, 1, &outCr));
    EXPECT_EQ(2, urma_test::GetHwMockState().postJfsCount);
    EXPECT_EQ(0U, fixture.comp.sqe_cnt[0][0].load());
    EXPECT_EQ(2U, fixture.comp.sqe_cnt[1][1].load());

    pthread_spin_destroy(&fixture.comp.send_lock);
    wr_buf_uninit(&fixture.comp.send_wr_buf);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
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
    urma_jfs_wr_t readWr = {};
    urma_jfs_wr_t sendWr = {};
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

    writeWr.rw.src.sge = &srcSge;
    writeWr.rw.src.num_sge = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_sge + 1;
    writeWr.rw.dst.sge = &dstSge;
    writeWr.rw.dst.num_sge = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_rsge + 1;
    badSend = nullptr;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &writeWr, &badSend));

    readWr.opcode = URMA_OPC_READ;
    readWr.tjetty = &fixture.targetJetty.v_tjetty;
    readWr.rw.src.sge = &srcSge;
    readWr.rw.src.num_sge = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_rsge + 1;
    readWr.rw.dst.sge = &dstSge;
    readWr.rw.dst.num_sge = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_sge + 1;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &readWr, &badSend));

    sendWr.opcode = URMA_OPC_SEND;
    sendWr.tjetty = &fixture.targetJetty.v_tjetty;
    sendWr.send.src.sge = &srcSge;
    sendWr.send.src.num_sge = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_sge + 1;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &sendWr, &badSend));

    casWr.cas.src = &srcSge;
    casWr.cas.dst = &dstSge;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &casWr, &badSend));
    faddWr.faa.src = &srcSge;
    faddWr.faa.dst = &dstSge;
    EXPECT_EQ(URMA_FAIL, bondp_post_jfs_wr(&fixture.jfs.v_jfs, &faddWr, &badSend));
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

TEST(UrmaBondTest, DatapathJettyStandaloneDispatchesProviderPostCallbacks)
{
    BondPathFixture fixture;
    urma_jfs_wr_t sendWr = fixture.MakeSendWr(URMA_OPC_SEND);
    urma_jfs_wr_t *badSend = nullptr;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_STANDALONE;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.v_jetty.jetty_cfg.shared.jfr = &fixture.comp.v_jfr;
    fixture.phyOps.post_jetty_send_wr = MockPostJettySendWr;
    fixture.phyOps.post_jetty_recv_wr = MockPostJettyRecvWr;

    recvWr.src.sge = fixture.srcSge;
    recvWr.src.num_sge = 1;
    EXPECT_EQ(URMA_SUCCESS, bondp_post_jetty_send_wr(&fixture.comp.v_jetty, &sendWr, &badSend));
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfsCount);
    fixture.comp.v_jetty.remote_jetty = nullptr;
    EXPECT_EQ(URMA_SUCCESS, bondp_post_jetty_recv_wr(&fixture.comp.v_jetty, &recvWr, &badRecv));
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfrCount);
    EXPECT_EQ(1U, fixture.comp.rqe_cnt[0]);

    urma_test::SetHwMockBadWr(&sendWr, &recvWr);
    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(URMA_FAIL, bondp_post_jetty_send_wr(&fixture.comp.v_jetty, &sendWr, &badSend));
    EXPECT_NE(nullptr, badSend);
    EXPECT_EQ(URMA_FAIL, bondp_post_jetty_recv_wr(&fixture.comp.v_jetty, &recvWr, &badRecv));
    EXPECT_NE(nullptr, badRecv);
}

TEST(UrmaBondTest, DatapathJettyRecvStoreUsesSharedJfrBuffer)
{
    BondPathFixture fixture;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.msn_enable = true;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.v_jetty.jetty_cfg.shared.jfr = &fixture.comp.v_jfr;
    fixture.phyOps.post_jetty_recv_wr = MockPostJettyRecvWr;
    ASSERT_EQ(0, wr_buf_init(&fixture.comp.recv_wr_buf, 2));

    recvWr.src.sge = fixture.srcSge;
    recvWr.src.num_sge = 1;
    EXPECT_EQ(URMA_SUCCESS, bondp_post_jetty_recv_wr(&fixture.comp.v_jetty, &recvWr, &badRecv));
    EXPECT_EQ(1, urma_test::GetHwMockState().postJfrCount);
    EXPECT_EQ(1U, fixture.comp.rqe_cnt[0]);

    wr_buf_uninit(&fixture.comp.recv_wr_buf);
}

TEST(UrmaBondTest, DatapathSendStoreRejectsOversizedList)
{
    BondPathFixture fixture;
    urma_jfs_wr_t oversizedWr[BONDP_BATCH_POST_MAX_NUM + 1] = {};
    urma_jfs_wr_t *badSend = nullptr;

    fixture.comp.comp_type = BONDP_COMP_JFS;
    fixture.comp.active_count = 1;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.valid[0] = true;
    fixture.comp.v_jfs.urma_ctx = &fixture.ctx.v_ctx;
    fixture.target.active_count = 1;
    fixture.target.active_indices[0] = 0;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.valid[0] = true;
    fixture.target.is_msn_enabled = true;
    fixture.target.v_tjetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.target.v_tjetty.type = URMA_JETTY;
    SetRefCount(&fixture.target.use_cnt, 2);
    SetRefCount(&fixture.localSeg.use_cnt, 2);
    SetRefCount(&fixture.remoteSeg.use_cnt, 2);

    for (uint32_t i = 0; i < BONDP_BATCH_POST_MAX_NUM; i++) {
        oversizedWr[i] = fixture.MakeSendWr(URMA_OPC_SEND);
        oversizedWr[i].next = &oversizedWr[i + 1];
    }
    oversizedWr[BONDP_BATCH_POST_MAX_NUM] = fixture.MakeSendWr(URMA_OPC_SEND);
    EXPECT_EQ(URMA_EINVAL, bondp_post_jfs_wr(&fixture.comp.v_jfs, &oversizedWr[0], &badSend));
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
