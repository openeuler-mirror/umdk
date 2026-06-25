/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding segment, provider and health unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

namespace {
struct MockFailbackTaskPayload {
    uint32_t requestId;
    uint32_t peerNodeId;
    urma_eid_t srcEid;
    uint32_t vjettyId;
    uint32_t pjettyIdx;
    uint32_t newPjettyId;
};

struct MockFailbackResultPayload {
    uint32_t requestId;
    uint32_t peerNodeId;
    urma_eid_t srcEid;
    uint32_t vjettyId;
    uint32_t pjettyIdx;
    uint32_t newPjettyId;
    int32_t result;
};
} // namespace

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
    fixture.phyJfr[0].jfr_cfg.flag.bs.order_type = URMA_OL;
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
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.flag.bs.order_type = URMA_OL;
    vJfr.v_jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
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

TEST(UrmaBondTest, HealthFallbackKickArmsTaskAndStopsAtStableRebuildFailure)
{
    BondPathFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    bondp_jfc_t vJfsJfc = {};
    bondp_comp_t vJfr = {};
    urma_target_jetty_t phyTarget[2] = {};
    urma_target_seg_t checkSeg[2] = {};
    urma_jetty_id_t oldId = MakeJettyId(0x660);
    urma_jetty_t *oldJetty = nullptr;
    urma_target_jetty_t *oldTarget = nullptr;
    uint32_t oldPrimaryId = oldId.id;

    oldId.uasid = 0;
    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);
    fakeGlobal.health_thread_ctx.cfg.backup_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_max_backoff = 1;

    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));

    oldJetty = static_cast<urma_jetty_t *>(std::calloc(1, sizeof(*oldJetty)));
    ASSERT_NE(nullptr, oldJetty);
    oldJetty->urma_ctx = &fixture.phyCtx;
    oldJetty->jetty_id = oldId;
    oldJetty->jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    oldJetty->remote_jetty = nullptr;
    oldJetty->urma_jetty_opt.is_actived = true;
    oldTarget = static_cast<urma_target_jetty_t *>(std::calloc(1, sizeof(*oldTarget)));
    ASSERT_NE(nullptr, oldTarget);
    oldTarget->urma_ctx = &fixture.phyCtx;
    oldTarget->id.id = 0x661;
    oldTarget->trans_mode = URMA_TM_RC;
    oldTarget->type = URMA_JETTY;
    phyTarget[0].id.id = 0x661;
    phyTarget[1].id.id = 0x662;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyOps.create_jetty = MockCreatePhysicalJetty;
    fixture.phyOps.delete_jetty = MockDeletePhysicalJetty;
    fixture.phyOps.import_jetty = MockImportPhysicalJetty;
    fixture.phyOps.unimport_jetty = MockUnimportPhysicalJetty;
    fixture.phyCtx.ref.atomic_cnt.store(2);
    vJfsJfc.p_jfc[0] = &fixture.phyJfc;
    vJfr.comp_type = BONDP_COMP_JFR;
    vJfr.p_jfr[0] = &fixture.phyJfr[0];
    fixture.phyJfr[0].jfr_cfg.jfc = &fixture.phyJfc;
    fixture.phyJfr[0].jfr_cfg.depth = 4;
    fixture.phyJfr[0].jfr_cfg.max_sge = 1;
    fixture.phyJfr[0].jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.phyJfr[0].jfr_cfg.flag.bs.order_type = URMA_OL;

    fixture.comp.bondp_ctx = &fixture.ctx;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jetty.jetty_id.id = 0x663;
    fixture.comp.v_jetty.jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.jfc = &vJfsJfc.v_jfc;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.depth = 4;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.max_sge = 1;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.max_rsge = 1;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.flag.bs.order_type = URMA_OL;
    vJfr.v_jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
    fixture.comp.v_jetty.jetty_cfg.shared.jfr = &vJfr.v_jfr;
    fixture.comp.p_jetty[0] = oldJetty;
    fixture.comp.p_jetty[1] = &fixture.phyJetty[1];
    fixture.comp.valid[0] = true;
    fixture.comp.valid[1] = true;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, oldId, JETTY, fixture.comp.v_jetty.jetty_id.id, &fixture.comp));

    fixture.target.v_tjetty.id.id = 0x664;
    fixture.target.v_tjetty.trans_mode = URMA_TM_UM;
    fixture.target.active_count = 2;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.active_indices[0] = 1;
    fixture.target.local_active_indices[1] = 1;
    fixture.target.active_indices[1] = 1;
    fixture.target.p_tjetty[0][1] = oldTarget;
    fixture.target.p_tjetty[1][1] = &phyTarget[1];
    fixture.target.p_check_tseg[0][1] = &checkSeg[0];
    fixture.target.p_check_tseg[1][1] = &checkSeg[1];

    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.target, &fixture.comp));
    bondp_health_update_active_idx(&fixture.ctx, &fixture.target, 1);
    bondp_health_kick_fallback_task(&fixture.ctx, &fixture.target);

    bondp_health_task_t *task = FindFirstHealthTask(&fixture.ctx.bondp_heath_check_ctx);
    ASSERT_NE(nullptr, task);
    EXPECT_TRUE(task->fallback_task.pending);
    EXPECT_TRUE(task->fallback_task.local_rebuilt);
    EXPECT_FALSE(task->fallback_task.req_sent);
    EXPECT_EQ(1U, task->fallback_task.primary_target_idx);
    EXPECT_NE(oldJetty, fixture.comp.p_jetty[0]);

    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, 0xdead, 0xff, task->fallback_task.req_seq, oldPrimaryId);
    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, 0xdead, BOND_TEST_FALLBACK_CTRL_REQ,
        task->fallback_task.req_seq, oldPrimaryId);
    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, fixture.comp.p_jetty[1]->jetty_id.id,
        BOND_TEST_FALLBACK_CTRL_REQ, task->fallback_task.req_seq, fixture.comp.p_jetty[0]->jetty_id.id);
    EXPECT_TRUE(task->fallback_task.local_rebuilt);
    EXPECT_FALSE(task->fallback_task.req_sent);

    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, fixture.comp.p_jetty[1]->jetty_id.id,
        BOND_TEST_FALLBACK_CTRL_REQ, task->fallback_task.req_seq, oldPrimaryId);
    EXPECT_TRUE(task->fallback_task.local_rebuilt);
    EXPECT_FALSE(task->fallback_task.req_sent);
    EXPECT_NE(oldJetty, fixture.comp.p_jetty[0]);

    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, fixture.comp.p_jetty[1]->jetty_id.id,
        BOND_TEST_FALLBACK_CTRL_RESP, static_cast<uint8_t>(task->fallback_task.req_seq + 1), 0x668);
    EXPECT_FALSE(task->fallback_task.resp_received);

    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, fixture.comp.p_jetty[1]->jetty_id.id,
        BOND_TEST_FALLBACK_CTRL_RESP, task->fallback_task.req_seq, 0x667);
    EXPECT_TRUE(task->fallback_task.relink_done);
    EXPECT_FALSE(task->fallback_task.pending);
    EXPECT_FALSE(task->fallback_task.resp_received);
    EXPECT_EQ(UINT32_MAX, task->fallback_task.remote_primary_pjetty_id);
    EXPECT_NE(nullptr, fixture.target.p_tjetty[0][1]);
    EXPECT_NE(oldTarget, fixture.target.p_tjetty[0][1]);
    EXPECT_FALSE(fixture.comp.valid[0]);
    EXPECT_TRUE(task->sub_tasks[0][1].valid);
    EXPECT_TRUE(atomic_load(&task->sub_tasks[0][1].link_ok));

    bondp_unregister_health_check_task(&fixture.ctx, &fixture.target);
    std::free(oldTarget);
    fixture.target.p_tjetty[0][1] = nullptr;
    std::free(fixture.comp.p_jetty[0]);
    fixture.comp.p_jetty[0] = nullptr;
    bondp_destroy_health_check_ctx(&fixture.ctx);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthFallbackRequestSelectsBackupLocalIndex)
{
    BondPathFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    bondp_jfc_t vJfsJfc = {};
    bondp_comp_t vJfr = {};
    urma_target_jetty_t phyTarget[2] = {};
    urma_target_seg_t checkSeg[2] = {};
    urma_jetty_id_t oldId = MakeJettyId(0x670);
    urma_jetty_t *oldJetty = nullptr;
    urma_target_jetty_t oldTarget = {};

    oldId.uasid = 0;
    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 8));
    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));

    oldJetty = static_cast<urma_jetty_t *>(std::calloc(1, sizeof(*oldJetty)));
    ASSERT_NE(nullptr, oldJetty);
    oldJetty->urma_ctx = &fixture.phyCtx;
    oldJetty->jetty_id = oldId;
    oldJetty->jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    oldJetty->urma_jetty_opt.is_actived = true;
    oldTarget.urma_ctx = &fixture.phyCtx;
    oldTarget.id.id = 0x671;
    oldTarget.trans_mode = URMA_TM_RC;
    oldTarget.type = URMA_JETTY;
    phyTarget[0].id.id = 0x671;
    phyTarget[1].id.id = 0x672;

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyOps.create_jetty = MockCreatePhysicalJetty;
    fixture.phyOps.delete_jetty = MockDeletePhysicalJetty;
    fixture.phyOps.import_jetty = MockImportPhysicalJetty;
    fixture.phyOps.unimport_jetty = MockUnimportPhysicalJetty;
    vJfsJfc.p_jfc[0] = &fixture.phyJfc;
    vJfr.comp_type = BONDP_COMP_JFR;
    vJfr.p_jfr[0] = &fixture.phyJfr[0];
    fixture.phyJfr[0].jfr_cfg.jfc = &fixture.phyJfc;
    fixture.phyJfr[0].jfr_cfg.depth = 4;
    fixture.phyJfr[0].jfr_cfg.max_sge = 1;
    fixture.phyJfr[0].jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.phyJfr[0].jfr_cfg.flag.bs.order_type = URMA_OL;

    fixture.comp.bondp_ctx = &fixture.ctx;
    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.comp.v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    fixture.comp.v_jetty.jetty_id.id = 0x673;
    fixture.comp.v_jetty.jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.jfc = &vJfsJfc.v_jfc;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.depth = 4;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.max_sge = 1;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.max_rsge = 1;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.comp.v_jetty.jetty_cfg.jfs_cfg.flag.bs.order_type = URMA_OL;
    vJfr.v_jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
    fixture.comp.v_jetty.jetty_cfg.shared.jfr = &vJfr.v_jfr;
    fixture.comp.p_jetty[0] = oldJetty;
    fixture.comp.p_jetty[1] = &fixture.phyJetty[1];
    fixture.comp.valid[0] = true;
    fixture.comp.valid[1] = true;
    fixture.comp.active_count = 2;
    fixture.comp.active_indices[0] = 0;
    fixture.comp.active_indices[1] = 1;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_add_without_lock(
        &fixture.ctx.p_vjetty_id_table, oldId, JETTY, fixture.comp.v_jetty.jetty_id.id, &fixture.comp));

    fixture.target.v_tjetty.id.id = 0x674;
    fixture.target.v_tjetty.trans_mode = URMA_TM_UM;
    fixture.target.active_count = 2;
    fixture.target.local_active_indices[0] = 0;
    fixture.target.active_indices[0] = 1;
    fixture.target.local_active_indices[1] = 1;
    fixture.target.active_indices[1] = 1;
    fixture.target.p_tjetty[0][1] = &oldTarget;
    fixture.target.p_tjetty[1][1] = &phyTarget[1];
    fixture.target.p_check_tseg[0][1] = &checkSeg[0];
    fixture.target.p_check_tseg[1][1] = &checkSeg[1];

    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.target, &fixture.comp));
    bondp_health_task_t *task = FindFirstHealthTask(&fixture.ctx.bondp_heath_check_ctx);
    ASSERT_NE(nullptr, task);
    EXPECT_EQ(0, task->active_local_idx);

    bondp_health_notify_fallback_ctrl_rx(&fixture.ctx, oldId.id, BOND_TEST_FALLBACK_CTRL_REQ, 1, 0xdeadbeef);
    EXPECT_EQ(1, task->active_local_idx);

    bondp_unregister_health_check_task(&fixture.ctx, &fixture.target);
    if (fixture.comp.p_jetty[0] != oldJetty) {
        std::free(fixture.comp.p_jetty[0]);
        fixture.comp.p_jetty[0] = nullptr;
    }
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
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

TEST(UrmaBondTest, PublicSegmentRegisterAndUnregisterUseMockIoctlSuccessPath)
{
    BondPublicApiFixture fixture;
    urma_token_id_t token = {};
    urma_seg_cfg_t segCfg = {};
    urma_target_seg_t *target = nullptr;

    fixture.InitSinglePhysicalMember();
    fixture.ctx.v_ctx.dev_fd = 7;
    token.urma_ctx = &fixture.ctx.v_ctx;
    segCfg.token_id = &token;
    segCfg.flag.bs.token_id_valid = URMA_TOKEN_ID_VALID;
    segCfg.va = 0x120000;
    segCfg.len = 4096;
    urma_test::SetHwMockIoctl(true, 0xc10, 0xc100);

    target = bondp_register_seg(&fixture.ctx.v_ctx, &segCfg);
    EXPECT_GT(urma_test::GetHwMockState().ioctlCount, 0);
    if (target != nullptr) {
        EXPECT_EQ(0xc10U, target->seg.token_id);
        EXPECT_EQ(&fixture.ctx.v_ctx, target->urma_ctx);
        EXPECT_EQ(URMA_SUCCESS, bondp_unregister_seg(target));
    }
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

TEST(UrmaBondTest, PublicImportSegmentUsesPhysicalProviderMocks)
{
    BondPublicApiFixture fixture;
    urma_token_t token = {};
    urma_import_seg_flag_t flag = {};
    urma_target_seg_t *target = nullptr;
    auto *remote = static_cast<urma_seg_t *>(std::calloc(1, sizeof(urma_seg_t) + sizeof(urma_bond_seg_ext_t)));
    ASSERT_NE(nullptr, remote);
    auto *ext = reinterpret_cast<urma_bond_seg_ext_t *>(remote->ext.buf);

    fixture.InitSinglePhysicalMember();
    fixture.ctx.seg_cache_enable = true;
    ASSERT_EQ(0, bdp_r_v2p_token_id_table_create(&fixture.ctx.remote_v2p_token_id_table, 4));
    remote->ubva.eid = MakeEid(0x801);
    remote->ubva.va = 0x100000;
    remote->len = 4096;
    remote->token_id = 0x71;
    remote->ext.flag.bs.enable = 1;
    remote->ext.length = sizeof(*ext) - 1;
    EXPECT_EQ(nullptr, bondp_import_seg(&fixture.ctx.v_ctx, remote, &token, 0x300000, flag));
    remote->ext.length = sizeof(*ext);
    ext->peer_p_seg[0].ubva.eid = MakeEid(0x802);
    ext->peer_p_seg[0].ubva.va = 0x200000;
    ext->peer_p_seg[0].len = 4096;
    ext->peer_p_seg[0].token_id = 0x72;
    ext->connected[0][0] = true;

    target = bondp_import_seg(&fixture.ctx.v_ctx, remote, &token, 0x300000, flag);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(&fixture.ctx.v_ctx, target->urma_ctx);
    EXPECT_EQ(0x300000U, target->mva);
    bondp_tseg_get(target);
    bondp_tseg_put(target);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_seg(target));

    target = bondp_import_seg(&fixture.ctx.v_ctx, remote, &token, 0x300000, flag);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_seg(target));

    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(nullptr, bondp_import_seg(&fixture.ctx.v_ctx, remote, &token, 0x300000, flag));
    EXPECT_EQ(0, bdp_r_v2p_token_id_table_destroy(&fixture.ctx.remote_v2p_token_id_table));
    std::free(remote);
}

TEST(UrmaBondTest, PublicImportJettyUsesExtAndPhysicalProviderMocks)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_token_t token = {};
    urma_target_jetty_t *target = nullptr;
    auto *remote = static_cast<urma_rjetty_t *>(std::calloc(1, sizeof(urma_rjetty_t) + sizeof(urma_bond_jetty_ext_t)));
    ASSERT_NE(nullptr, remote);
    auto *ext = reinterpret_cast<urma_bond_jetty_ext_t *>(remote->ext.buf);

    fixture.InitSinglePhysicalMember();
    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = false;

    remote->jetty_id = MakeJettyId(0x811);
    remote->trans_mode = URMA_TM_RC;
    remote->type = URMA_JETTY;
    remote->ext.flag.bs.enable = 1;
    remote->ext.length = sizeof(*ext);
    ext->slave_id[0] = MakeJettyId(0x812);
    ext->enable_indices[0] = 0;
    ext->enable_count = 1;
    ext->connected[0][0] = true;

    target = bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token);
    EXPECT_EQ(1, urma_test::GetHwMockState().importJettyCount);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(remote->jetty_id.id, target->id.id);
    bondp_tjetty_get(target);
    bondp_tjetty_put(target);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jetty(target));

    remote->ext.length = sizeof(*ext) - 1;
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token));
    remote->ext.length = sizeof(*ext);

    ext->enable_count = 0;
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token));
    ext->enable_count = 1;

    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token));

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
    std::free(remote);
}

TEST(UrmaBondTest, PublicImportJettyUsesMockIoctlAndPhysicalProvider)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_rjetty_t rjetty = {};
    urma_token_t token = {};
    urma_target_jetty_t *target = nullptr;

    fixture.InitSinglePhysicalMember();
    fixture.ctx.v_ctx.dev_fd = 7;
    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = false;
    urma_test::SetHwMockIoctl(true, 0xa30, 0xa300);
    rjetty.jetty_id = MakeJettyId(0xa31);
    rjetty.trans_mode = URMA_TM_RC;
    rjetty.type = URMA_JETTY;

    target = bondp_import_jetty(&fixture.ctx.v_ctx, &rjetty, &token);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(1, urma_test::GetHwMockState().importJettyCount);
    EXPECT_EQ(URMA_JETTY, target->type);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jetty(target));

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, PublicImportJfrUsesMockIoctlAndPhysicalProvider)
{
    BondPublicApiFixture fixture;
    urma_rjfr_t rjfr = {};
    urma_token_t token = {};
    urma_target_jetty_t *target = nullptr;

    fixture.InitSinglePhysicalMember();
    fixture.ctx.v_ctx.dev_fd = 7;
    urma_test::SetHwMockIoctl(true, 0xa20, 0xa200);
    rjfr.jfr_id = MakeJettyId(0xa21);
    rjfr.trans_mode = URMA_TM_RC;

    target = bondp_import_jfr(&fixture.ctx.v_ctx, &rjfr, &token);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(1, urma_test::GetHwMockState().importJfrCount);
    EXPECT_EQ(URMA_JFR, target->type);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jfr(target));

    urma_test::ResetHwMockState();
    fixture.ctx.v_ctx.dev_fd = 7;
    urma_test::SetHwMockIoctl(true, 0xa22, 0xa220);
    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(nullptr, bondp_import_jfr(&fixture.ctx.v_ctx, &rjfr, &token));
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

    fixture.ctx.v_ctx.dev_fd = 7;
    urma_test::SetHwMockIoctl(true, 0xe40, 0xe400);
    EXPECT_EQ(0, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_ACTIVE_BACKUP,
                                        BONDP_BONDING_LEVEL_PORT));
    EXPECT_EQ(BONDP_BONDING_MODE_ACTIVE_BACKUP, fixture.ctx.bonding_mode);
    EXPECT_EQ(BONDP_BONDING_LEVEL_PORT, fixture.ctx.bonding_level);

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.ctx.bonding_level = BONDP_BONDING_LEVEL_IODIE;
    fixture.ctx.v_ctx.dev_fd = -1;
    auto *oldPhyCtx = static_cast<urma_context_t *>(std::calloc(1, sizeof(urma_context_t)));
    ASSERT_NE(nullptr, oldPhyCtx);
    oldPhyCtx->async_fd = -1;
    fixture.ctx.p_ctxs[0] = oldPhyCtx;
    g_mockDeleteContextFail = true;
    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    EXPECT_EQ(URMA_FAIL, bondp_set_bonding_mode(&fixture.ctx.v_ctx, BONDP_BONDING_MODE_STANDALONE,
                                                BONDP_BONDING_LEVEL_IODIE));
    EXPECT_EQ(nullptr, fixture.ctx.p_ctxs[0]);
    g_mockDeleteContextFail = false;

    g_bondp_global_ctx = &fakeGlobal;
    EXPECT_EQ(URMA_FAIL, bondp_init(nullptr));
    EXPECT_EQ(nullptr, bondp_create_context(&dev, 0, -1));
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, PublicProviderCreateContextUsesCachedTopoAndMockPhysicalContext)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_context_t *createdCtx = nullptr;

    fixture.ctx.v_ctx.dev_fd = 7;
    fakeGlobal.topo_map = reinterpret_cast<topo_map_t *>(0x1);
    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup(&fakeGlobal);
    urma_test::SetHwMockIoctl(true, 0xd10, 0xd100);

    createdCtx = bondp_create_context(&fixture.dev, 0, 7);
    ASSERT_NE(nullptr, createdCtx);
    EXPECT_GT(urma_test::GetHwMockState().ioctlCount, 0);
    EXPECT_EQ(1, g_mockCreateContextCount);
    EXPECT_FALSE(fakeGlobal.skip_load_topo);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_context(createdCtx));
}

TEST(UrmaBondTest, PublicProviderCreateContextLoadsTopoFromMockUserCtl)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_context_t *createdCtx = nullptr;

    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup(&fakeGlobal);
    urma_test::SetHwMockIoctl(true, 0xd20, 0xd200);

    createdCtx = bondp_create_context(&fixture.dev, 0, 7);
    ASSERT_NE(nullptr, createdCtx);
    ASSERT_NE(nullptr, fakeGlobal.topo_map);
    EXPECT_EQ(fakeGlobal.topo_map, CONTAINER_OF_FIELD(createdCtx, bondp_context_t, v_ctx)->topo_map);
    EXPECT_FALSE(fakeGlobal.skip_load_topo);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_context(createdCtx));
    delete_topo_map(fakeGlobal.topo_map);
    fakeGlobal.topo_map = nullptr;
}

TEST(UrmaBondTest, PublicProviderCreateContextCleansVirtualContextOnStableFailures)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup(&fakeGlobal);

    urma_test::SetHwMockIoctl(true, 0xd30, 0xd300);
    g_mockEpollCreateFail = true;
    EXPECT_EQ(nullptr, bondp_create_context(&fixture.dev, 0, 7));
    g_mockEpollCreateFail = false;

    urma_test::SetHwMockIoctl(true, 0xd31, 0xd310);
    g_mockUserCtlFail = true;
    EXPECT_EQ(nullptr, bondp_create_context(&fixture.dev, 0, 7));
    EXPECT_TRUE(fakeGlobal.skip_load_topo);
    g_mockUserCtlFail = false;
    fakeGlobal.skip_load_topo = false;
}

TEST(UrmaBondTest, PublicProviderCreateContextPropagatesPhysicalContextFailures)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup(&fakeGlobal);

    urma_test::SetHwMockIoctl(true, 0xd40, 0xd400);
    fakeGlobal.topo_map = reinterpret_cast<topo_map_t *>(0x1);

    g_mockCreateContextFail = true;
    EXPECT_EQ(nullptr, bondp_create_context(&fixture.dev, 0, 7));
    EXPECT_EQ(0, g_mockCreateContextCount);

    g_mockCreateContextFail = false;
    g_mockCreateContextBadFd = true;
    EXPECT_EQ(nullptr, bondp_create_context(&fixture.dev, 0, 7));
    EXPECT_EQ(1, g_mockCreateContextCount);
}

TEST(UrmaBondTest, PublicProviderDeleteContextPropagatesPhysicalDeleteFailure)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_context_t *createdCtx = nullptr;

    fakeGlobal.topo_map = reinterpret_cast<topo_map_t *>(0x1);
    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup(&fakeGlobal);
    urma_test::SetHwMockIoctl(true, 0xd50, 0xd500);

    createdCtx = bondp_create_context(&fixture.dev, 0, 7);
    ASSERT_NE(nullptr, createdCtx);
    g_mockDeleteContextFail = true;
    EXPECT_EQ(URMA_FAIL, bondp_delete_context(createdCtx));
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

TEST(UrmaBondTest, PublicProviderInitReadsEnvAndCleansUp)
{
    EnvGuard failover("BOND_ENABLE_FAILOVER", "false");
    EnvGuard failback("BOND_ENABLE_FAILBACK", "bad-bool");
    EnvGuard backupStart("BOND_HEALTH_CHECK_BACKUP_START", "99");
    EnvGuard backupInterval("BOND_HEALTH_CHECK_BACKUP_INTERVAL", "3600001");
    EnvGuard activeStart("BOND_HEALTH_CHECK_ACTIVE_START", "200");
    EnvGuard activeInterval("BOND_HEALTH_CHECK_ACTIVE_INTERVAL", "bad-int");
    EnvGuard activeBackoff("BOND_HEALTH_CHECK_ACTIVE_MAX_BACKOFF", "0");

    g_bondp_global_ctx = nullptr;
    g_mockNetlink = true;
    g_mockNetlinkConnectFail = true;
    EXPECT_EQ(URMA_SUCCESS, bondp_init(nullptr));
    EXPECT_NE(nullptr, g_bondp_global_ctx);
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
    bondp_nl_sock_uninit();
    g_mockNetlinkConnectFail = false;
    g_mockNetlink = false;
}

TEST(UrmaBondTest, PublicProviderInitAcceptsValidEnvValues)
{
    EnvGuard failover("BOND_ENABLE_FAILOVER", "true");
    EnvGuard failback("BOND_ENABLE_FAILBACK", "false");
    EnvGuard backupStart("BOND_HEALTH_CHECK_BACKUP_START", "100");
    EnvGuard backupInterval("BOND_HEALTH_CHECK_BACKUP_INTERVAL", "1000");
    EnvGuard activeStart("BOND_HEALTH_CHECK_ACTIVE_START", "100");
    EnvGuard activeInterval("BOND_HEALTH_CHECK_ACTIVE_INTERVAL", "60000");
    EnvGuard activeBackoff("BOND_HEALTH_CHECK_ACTIVE_MAX_BACKOFF", "100");

    g_bondp_global_ctx = nullptr;
    g_mockNetlink = true;
    g_mockNetlinkConnectFail = true;
    EXPECT_EQ(URMA_SUCCESS, bondp_init(nullptr));
    EXPECT_NE(nullptr, g_bondp_global_ctx);
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
    bondp_nl_sock_uninit();
    g_mockNetlinkConnectFail = false;
    g_mockNetlink = false;
}

TEST(UrmaBondTest, NetlinkInitUsesMockSocketAndCoversFailureBranches)
{
    g_mockNetlink = true;
    g_mockNetlinkAllocFail = true;
    EXPECT_EQ(-ENOMEM, bondp_nl_sock_init());

    g_mockNetlinkAllocFail = false;
    g_mockNetlinkConnectFail = true;
    EXPECT_EQ(-EIO, bondp_nl_sock_init());

    g_mockNetlinkConnectFail = false;
    g_mockNetlinkResolveFail = true;
    EXPECT_EQ(-ENOENT, bondp_nl_sock_init());

    g_mockNetlinkResolveFail = false;
    EXPECT_EQ(0, bondp_nl_sock_init());
    EXPECT_EQ(0, bondp_nl_sock_init());
    bondp_nl_sock_uninit();
    bondp_nl_sock_uninit();
    g_mockNetlink = false;
}

TEST(UrmaBondTest, NetlinkWorkerAndCallbackDispatchUseMockSocket)
{
    int evtFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(evtFd, 0);

    MockFailbackTaskPayload task = {};
    MockFailbackResultPayload result = {};
    task.requestId = 1;
    task.srcEid = MakeEid(0x910);
    task.vjettyId = 0x911;
    task.pjettyIdx = 0;
    task.newPjettyId = 0x912;
    result.requestId = task.requestId;
    result.srcEid = task.srcEid;
    result.vjettyId = task.vjettyId;
    result.pjettyIdx = task.pjettyIdx;
    result.newPjettyId = task.newPjettyId;
    result.result = 0;

    g_mockNetlink = true;
    EXPECT_EQ(-ENODEV, bondp_nl_worker_init());
    g_mockNetlinkFd = -1;
    EXPECT_EQ(0, bondp_nl_sock_init());
    EXPECT_EQ(-EINVAL, bondp_nl_worker_init());

    g_mockNetlinkFd = evtFd;
    g_mockNetlinkRecvReturn = -NLE_AGAIN;
    ASSERT_EQ(0, bondp_worker_create());
    EXPECT_EQ(0, bondp_nl_worker_init());
    EXPECT_EQ(0, bondp_nl_worker_init());
    ASSERT_EQ(0, eventfd_write(evtFd, 1));
    for (int i = 0; i < 50 && g_mockNetlinkRecvCount == 0; i++) {
        usleep(1000);
    }
    EXPECT_GT(g_mockNetlinkRecvCount, 0);
    bondp_nl_worker_uninit();
    bondp_nl_worker_uninit();
    bondp_worker_destroy();

    EXPECT_EQ(NL_OK, InvokeMockNetlinkMsg(BONDP_NL_CMD_FAILBACK_NOTIFY, &task, sizeof(task)));
    EXPECT_EQ(NL_OK, InvokeMockNetlinkMsg(BONDP_NL_CMD_FAILBACK_NOTIFY, &task, sizeof(task) - 1));
    EXPECT_EQ(NL_OK, InvokeMockNetlinkMsg(BONDP_NL_CMD_FAILBACK_DONE, &result, sizeof(result)));
    EXPECT_EQ(NL_OK, InvokeMockNetlinkMsg(BONDP_NL_CMD_FAILBACK_DONE, nullptr, 0));
    EXPECT_EQ(NL_OK, InvokeMockNetlinkMsg(static_cast<bondp_nl_cmd_t>(0xff), nullptr, 0));

    bondp_nl_sock_uninit();
    g_mockNetlink = false;
    g_mockNetlinkFd = -1;
    g_mockNetlinkRecvReturn = 0;
    g_mockNetlinkRecvCount = 0;
    ResetMockNetlinkCallback();
    EXPECT_EQ(0, close(evtFd));
}

TEST(UrmaBondTest, FailbackTaskTableCoversScheduleFailureDuplicateAndLookup)
{
    BondPathFixture fixture;

    EXPECT_EQ(-EINVAL, bondp_fb_add_task(nullptr, 0x920, 0));
    EXPECT_EQ(-EINVAL, bondp_fb_add_task(&fixture.ctx, 0x920, 0));
    ASSERT_EQ(0, bondp_fb_init(&fixture.ctx));

    /* No worker is present here; the task is inserted then removed through the stable failure path. */
    bondp_worker_destroy();
    EXPECT_EQ(-ENODEV, bondp_fb_add_task(&fixture.ctx, 0x920, 0));

    ASSERT_EQ(0, bondp_worker_create());
    EXPECT_EQ(0, bondp_fb_add_task(&fixture.ctx, 0x921, 1));
    EXPECT_EQ(-EEXIST, bondp_fb_add_task(&fixture.ctx, 0x921, 1));
    usleep(20000);
    bondp_worker_destroy();
    bondp_fb_uninit(&fixture.ctx);
    bondp_fb_uninit(&fixture.ctx);
}

TEST(UrmaBondTest, PublicProviderInitSucceedsWithMockNetlinkAndDisabledHealth)
{
    EnvGuard failover("BOND_ENABLE_FAILOVER", "false");

    g_mockNetlink = true;
    g_bondp_global_ctx = nullptr;
    EXPECT_EQ(URMA_SUCCESS, bondp_init(nullptr));
    EXPECT_NE(nullptr, g_bondp_global_ctx);
    EXPECT_EQ(URMA_FAIL, bondp_init(nullptr));
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
    g_mockNetlink = false;
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
    EXPECT_EQ(0, bondp_start_health_check_thread());
    bondp_stop_health_check_thread();

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

TEST(UrmaBondTest, HealthCheckImportTsegUsesMockProviderRoutes)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    bondp_rjetty_t rjetty = {};
    urma_bond_id_info_out_t idOut = {};
    urma_target_jetty_t physicalTarget = {};

    fixture.InitSinglePhysicalMember();
    fixture.jetty.v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    rjetty.base.flag.bs.has_drv_ext = 1;
    rjetty.jetty = &fixture.jetty.v_jetty;
    physicalTarget.urma_ctx = &fixture.phyCtx;
    fixture.targetJetty.active_count = 1;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.p_tjetty[0][0] = &physicalTarget;

    idOut.is_health_check_enable = true;
    idOut.health_check_seg.slaves[0].ubva.va = 0x1234000;
    idOut.health_check_seg.slaves[0].ubva.eid = MakeEid(0x771);
    idOut.health_check_seg.slaves[0].len = 4096;
    idOut.health_check_seg.slaves[0].token_id = 0x7788;

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;

    EXPECT_EQ(0, bondp_import_health_check_tseg(&fixture.ctx, &fixture.targetJetty, &idOut, &rjetty.base));
    ASSERT_NE(nullptr, fixture.targetJetty.p_check_tseg[0][0]);
    EXPECT_EQ(1, urma_test::GetHwMockState().importSegCount);
    EXPECT_EQ(idOut.health_check_seg.slaves[0].token_id, fixture.targetJetty.p_check_tseg[0][0]->seg.token_id);

    EXPECT_EQ(0, bondp_import_health_check_tseg(&fixture.ctx, &fixture.targetJetty, &idOut, &rjetty.base));
    EXPECT_EQ(1, urma_test::GetHwMockState().importSegCount);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_health_check_tseg(&fixture.targetJetty));
    EXPECT_EQ(nullptr, fixture.targetJetty.p_check_tseg[0][0]);

    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(-1, bondp_import_health_check_tseg(&fixture.ctx, &fixture.targetJetty, &idOut, &rjetty.base));
    EXPECT_EQ(2, urma_test::GetHwMockState().importSegCount);
    EXPECT_EQ(nullptr, fixture.targetJetty.p_check_tseg[0][0]);

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckLocalSegRegisterFillAndUnregisterUseProviderMocks)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_bond_seg_info_out_t segOut = {};
    bool enabled = false;

    fixture.InitSinglePhysicalMember();
    fixture.phyDev.type = URMA_TRANSPORT_IP;
    fixture.ctx.dev_num = 2;
    fixture.ctx.p_ctxs[1] = nullptr;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = nullptr;

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    ASSERT_EQ(0, bondp_register_health_check_seg_for_jetty(&fixture.ctx, &fixture.jetty));
    ASSERT_NE(nullptr, fixture.jetty.check_tseg[0]);
    EXPECT_EQ(nullptr, fixture.jetty.check_tseg[1]);
    EXPECT_EQ(0, bondp_fill_vjetty_health_info(&fixture.ctx, &fixture.jetty, &segOut, &enabled));
    EXPECT_TRUE(enabled);
    EXPECT_EQ(fixture.jetty.check_tseg[0]->seg.len, segOut.slaves[0].len);
    EXPECT_EQ(fixture.jetty.check_tseg[0]->seg.token_id, segOut.slaves[0].token_id);

    EXPECT_EQ(0, bondp_register_health_check_seg_for_jetty(&fixture.ctx, &fixture.jetty));
    bondp_unregister_health_check_seg_for_jetty(&fixture.jetty);
    EXPECT_EQ(nullptr, fixture.jetty.check_tseg[0]);

    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckLocalSegRegisterFailureCleansPartialState)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};

    fixture.InitSinglePhysicalMember();
    fixture.phyDev.type = URMA_TRANSPORT_IP;
    fixture.ctx.dev_num = 2;
    fixture.ctx.p_ctxs[1] = &fixture.phyCtx;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = &fixture.phyJetty[1];

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    fixture.phyOps.register_seg = [](urma_context_t *ctx, urma_seg_cfg_t *cfg) -> urma_target_seg_t * {
        if (urma_test::GetHwMockState().importSegCount++ == 0) {
            return MockRegisterPhysicalSeg(ctx, cfg);
        }
        return nullptr;
    };
    EXPECT_EQ(-1, bondp_register_health_check_seg_for_jetty(&fixture.ctx, &fixture.jetty));
    EXPECT_EQ(nullptr, fixture.jetty.check_tseg[0]);
    EXPECT_EQ(nullptr, fixture.jetty.check_tseg[1]);

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

TEST(UrmaBondTest, HealthCheckContextCreateCleansUpEventfdFailure)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    g_mockEventfdFail = true;
    EXPECT_EQ(-1, bondp_create_health_check_ctx(&fixture.ctx));
    g_mockEventfdFail = false;
    EXPECT_LT(fixture.ctx.bondp_heath_check_ctx.health_check_fd, 0);

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckContextCreateCleansUpEpollCtlFailure)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    g_mockEpollCtlFail = true;
    EXPECT_EQ(-1, bondp_create_health_check_ctx(&fixture.ctx));
    g_mockEpollCtlFail = false;
    EXPECT_EQ(-1, fixture.ctx.bondp_heath_check_ctx.health_check_fd);

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckDestroyFreesRegisteredTasks)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_target_jetty_t phyTarget = {};
    urma_target_seg_t checkSeg = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    fixture.jetty.bondp_ctx = &fixture.ctx;
    fixture.jetty.v_jetty.jetty_id.id = 0x921;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.targetJetty.v_tjetty.id.id = 0x922;
    fixture.targetJetty.v_tjetty.trans_mode = URMA_TM_UM;
    fixture.targetJetty.active_count = 1;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget;
    fixture.targetJetty.p_check_tseg[0][0] = &checkSeg;

    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));
    bondp_destroy_health_check_ctx(&fixture.ctx);
    EXPECT_EQ(-1, fixture.ctx.bondp_heath_check_ctx.health_check_fd);

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckThreadStartsAndStopsWithoutContexts)
{
    bondp_global_context_t fakeGlobal = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;

    ASSERT_EQ(0, bondp_start_health_check_thread());
    bondp_stop_health_check_thread();
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckThreadConsumesQueuedLocalEvent)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_target_jetty_t phyTarget[1] = {};
    urma_target_seg_t checkSeg[1] = {};
    bondp_health_event_info_t info = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.cfg.backup_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.backup_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_max_backoff = 1;

    ASSERT_EQ(0, bondp_start_health_check_thread());
    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.jetty.bondp_ctx = &fixture.ctx;
    fixture.jetty.v_jetty.jetty_id.id = 0x911;
    fixture.jetty.active_count = 1;
    fixture.jetty.active_indices[0] = 0;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.targetJetty.v_tjetty.id.id = 0x912;
    fixture.targetJetty.v_tjetty.trans_mode = URMA_TM_UM;
    fixture.targetJetty.active_count = 1;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget[0];
    fixture.targetJetty.p_check_tseg[0][0] = &checkSeg[0];
    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));

    info.bdp_tjetty = &fixture.targetJetty;
    info.new_active_idx = 0;
    bondp_notify_health_event(&fixture.ctx, BONDP_HEALTH_EVENT_ACTIVE_IDX_UPDATE, &info);
    usleep(150000);

    bondp_stop_health_check_thread();
    bondp_unregister_health_check_task(&fixture.ctx, &fixture.targetJetty);
    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckThreadSendsBackupProbeThroughMockProvider)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_target_jetty_t phyTarget[2] = {};
    urma_target_seg_t checkSeg[2] = {};
    urma_target_seg_t localCheckSeg[2] = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.cfg.backup_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.backup_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_max_backoff = 1;

    fixture.phyOps.post_jetty_send_wr = MockPostJettySendWr;
    fixture.phyJetty[0].urma_ctx = &fixture.phyCtx;
    fixture.phyJetty[1].urma_ctx = &fixture.phyCtx;
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    fixture.jetty.bondp_ctx = &fixture.ctx;
    fixture.jetty.v_jetty.jetty_id.id = 0x931;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = &fixture.phyJetty[1];
    fixture.jetty.check_tseg[0] = &localCheckSeg[0];
    fixture.jetty.check_tseg[1] = &localCheckSeg[1];
    fixture.jetty.valid[0] = true;
    fixture.jetty.valid[1] = true;
    fixture.targetJetty.v_tjetty.id.id = 0x932;
    fixture.targetJetty.v_tjetty.trans_mode = URMA_TM_UM;
    fixture.targetJetty.active_count = 2;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.local_active_indices[1] = 1;
    fixture.targetJetty.active_indices[1] = 1;
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget[0];
    fixture.targetJetty.p_tjetty[1][1] = &phyTarget[1];
    fixture.targetJetty.p_check_tseg[0][0] = &checkSeg[0];
    fixture.targetJetty.p_check_tseg[1][1] = &checkSeg[1];
    checkSeg[0].seg.ubva.va = 0x1000;
    checkSeg[1].seg.ubva.va = 0x2000;

    ASSERT_EQ(0, bondp_start_health_check_thread());
    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));
    bondp_health_task_t *task = FindFirstHealthTask(&fixture.ctx.bondp_heath_check_ctx);
    ASSERT_NE(nullptr, task);
    atomic_store(&fixture.jetty.valid[task->primary_local_idx], false);
    task->next_probe_ts_us = 0;

    usleep(150000);
    bondp_stop_health_check_thread();
    EXPECT_GT(urma_test::GetHwMockState().postJfsCount, 0);

    bondp_unregister_health_check_task(&fixture.ctx, &fixture.targetJetty);
    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckEnabledTaskLifecycleUsesLocalObjects)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_target_jetty_t phyTarget[2] = {};
    urma_target_seg_t checkSeg[2] = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.cfg.backup_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.backup_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_interval_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.active_max_backoff = 1;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    fixture.jetty.bondp_ctx = &fixture.ctx;
    fixture.jetty.v_jetty.jetty_id.id = 0x901;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = &fixture.phyJetty[1];
    fixture.targetJetty.v_tjetty.id.id = 0x902;
    fixture.targetJetty.active_count = 2;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.local_active_indices[1] = 1;
    fixture.targetJetty.active_indices[1] = 1;
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget[0];
    fixture.targetJetty.p_tjetty[1][1] = &phyTarget[1];
    fixture.targetJetty.p_check_tseg[0][0] = &checkSeg[0];
    fixture.targetJetty.p_check_tseg[1][1] = &checkSeg[1];

    EXPECT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));
    bondp_health_update_active_idx(&fixture.ctx, &fixture.targetJetty, 0);
    bondp_health_event_info_t info = {};
    info.bdp_tjetty = &fixture.targetJetty;
    info.new_active_idx = 0;
    bondp_notify_health_event(&fixture.ctx, BONDP_HEALTH_EVENT_ACTIVE_IDX_UPDATE, &info);
    bondp_notify_health_event(&fixture.ctx, BONDP_HEALTH_EVENT_MAX, &info);
    bondp_unregister_health_check_task(&fixture.ctx, &fixture.targetJetty);
    bondp_destroy_health_check_ctx(&fixture.ctx);

    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckCrHandlerConsumesMatchingMockCompletion)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_target_jetty_t phyTarget[2] = {};
    urma_target_seg_t checkSeg[2] = {};
    urma_cr_t cr = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.health_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(fakeGlobal.health_thread_ctx.health_epoll_fd, 0);

    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_ACTIVE_BACKUP;
    fixture.jetty.bondp_ctx = &fixture.ctx;
    fixture.jetty.v_jetty.jetty_id.id = 0x941;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = &fixture.phyJetty[1];
    fixture.targetJetty.v_tjetty.id.id = 0x942;
    fixture.targetJetty.active_count = 2;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.local_active_indices[1] = 1;
    fixture.targetJetty.active_indices[1] = 1;
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget[0];
    fixture.targetJetty.p_tjetty[1][1] = &phyTarget[1];
    fixture.targetJetty.p_check_tseg[0][0] = &checkSeg[0];
    fixture.targetJetty.p_check_tseg[1][1] = &checkSeg[1];

    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));
    bondp_health_task_t *task = FindFirstHealthTask(&fixture.ctx.bondp_heath_check_ctx);
    ASSERT_NE(nullptr, task);
    task->sub_tasks[1][1].user_ctx = MakeHealthUserCtx(fixture.jetty.v_jetty.jetty_id.id, 1, 1);
    task->sub_tasks[1][1].probe_pending = true;

    cr.user_ctx = task->sub_tasks[1][1].user_ctx;
    cr.status = URMA_CR_SUCCESS;
    EXPECT_TRUE(bondp_try_handle_health_check_cr(&fixture.ctx, 1, &cr));
    EXPECT_FALSE(task->sub_tasks[1][1].probe_pending);
    EXPECT_TRUE(fixture.jetty.valid[1]);

    cr.user_ctx = MakeHealthUserCtx(fixture.jetty.v_jetty.jetty_id.id, 0, 1);
    EXPECT_FALSE(bondp_try_handle_health_check_cr(&fixture.ctx, 1, &cr));
    cr.user_ctx = 0;
    EXPECT_FALSE(bondp_try_handle_health_check_cr(&fixture.ctx, 1, &cr));

    bondp_unregister_health_check_task(&fixture.ctx, &fixture.targetJetty);
    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}

TEST(UrmaBondTest, HealthCheckThreadProcessesQueuedLinkFailureEvents)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_target_jetty_t phyTarget[2] = {};
    urma_target_seg_t checkSeg[2] = {};
    bondp_health_event_info_t timeoutInfo = {};

    g_bondp_global_ctx = &fakeGlobal;
    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = true;
    fakeGlobal.health_thread_ctx.cfg.active_start_ms = 1;
    fakeGlobal.health_thread_ctx.cfg.backup_start_ms = 1000;
    fakeGlobal.health_thread_ctx.cfg.backup_interval_ms = 1000;
    fakeGlobal.health_thread_ctx.cfg.active_interval_ms = 1000;
    fakeGlobal.health_thread_ctx.cfg.active_max_backoff = 1;

    ASSERT_EQ(0, bondp_start_health_check_thread());
    bondp_health_check_ctx_init(&fixture.ctx);
    ASSERT_EQ(0, bondp_create_health_check_ctx(&fixture.ctx));
    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.jetty.bondp_ctx = &fixture.ctx;
    fixture.jetty.v_jetty.jetty_id.id = 0x951;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = &fixture.phyJetty[1];
    fixture.targetJetty.v_tjetty.id.id = 0x952;
    fixture.targetJetty.v_tjetty.trans_mode = URMA_TM_UM;
    fixture.targetJetty.active_count = 2;
    fixture.targetJetty.local_active_indices[0] = 0;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.local_active_indices[1] = 1;
    fixture.targetJetty.active_indices[1] = 1;
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget[0];
    fixture.targetJetty.p_tjetty[1][1] = &phyTarget[1];
    fixture.targetJetty.p_check_tseg[0][0] = &checkSeg[0];
    fixture.targetJetty.p_check_tseg[1][1] = &checkSeg[1];

    ASSERT_EQ(0, bondp_register_health_check_task(&fixture.ctx, &fixture.targetJetty, &fixture.jetty));
    bondp_health_task_t *task = FindFirstHealthTask(&fixture.ctx.bondp_heath_check_ctx);
    ASSERT_NE(nullptr, task);
    task->sub_tasks[1][1].user_ctx = MakeHealthUserCtx(fixture.jetty.v_jetty.jetty_id.id, 1, 1);
    fixture.jetty.p_jetty[0] = nullptr;
    fixture.jetty.p_jetty[1] = nullptr;

    bondp_health_notify_datapath_link_fail(&fixture.ctx, &fixture.targetJetty, 0, 0);
    timeoutInfo.local_idx = 1;
    timeoutInfo.target_idx = 1;
    timeoutInfo.user_ctx = task->sub_tasks[1][1].user_ctx;
    timeoutInfo.cr_status = URMA_CR_LOC_LEN_ERR;
    timeoutInfo.new_active_idx = -1;
    timeoutInfo.bdp_tjetty = &fixture.targetJetty;
    bondp_notify_health_event(&fixture.ctx, BONDP_HEALTH_EVENT_TA_TIMEOUT, &timeoutInfo);
    usleep(150000);

    EXPECT_TRUE(task->sub_tasks[0][0].need_check);
    EXPECT_FALSE(atomic_load(&task->sub_tasks[0][0].link_ok));
    EXPECT_FALSE(atomic_load(&task->sub_tasks[1][1].link_ok));

    bondp_stop_health_check_thread();
    bondp_unregister_health_check_task(&fixture.ctx, &fixture.targetJetty);
    bondp_destroy_health_check_ctx(&fixture.ctx);
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    g_bondp_global_ctx = nullptr;
}
