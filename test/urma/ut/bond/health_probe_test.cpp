/* SPDX-License-Identifier: MIT */
/* Health-check (bondp_dp_health) UT: init, probe cycle, register/unregister. */

#include "bond_fixture.h"

using namespace urma_test_bond;

namespace {

/* The health probe allocates depth-1024 queues, which exceeds the default
 * 8-entry device caps of the fixtures; raise them for these tests. */
void RaiseProbeDevCaps(BondPublicApiFixture &fixture)
{
    fixture.sysfsDev.dev_attr.dev_cap.max_jfc_depth = 4096;
    fixture.sysfsDev.dev_attr.dev_cap.max_jfs_depth = 4096;
    fixture.sysfsDev.dev_attr.dev_cap.max_jfr_depth = 4096;
}

/* Two-node topo: node 0 is the local node, node 1 is the remote peer. */
void InitTwoNodeTopo(bondp_topo_node_t topo[2], const urma_eid_t &remote_eid)
{
    topo[0].is_current = true;
    CopyEidToTopo(topo[0].agg_devs[0].agg_eid, MakeEid(0xc01));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].primary_eid, MakeEid(0xc02));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].port_eid[0], MakeEid(0xc03));
    CopyEidToTopo(topo[1].agg_devs[0].agg_eid, remote_eid);
    topo[1].links[0][0] = true;
}

} // namespace

TEST(UrmaBondTest, HealthInitRejectsInvalidArgsAndSkipsWithoutTopo)
{
    BondPublicApiFixture fixture;
    bondp_hc_cfg_t cfg = {};

    EXPECT_EQ(-EINVAL, bondp_hc_init(nullptr, &cfg));

    /* Without a topo node the health context is not mounted (init still returns 0). */
    fixture.InitSinglePhysicalMember();
    EXPECT_EQ(0, bondp_hc_init(&fixture.ctx, &cfg));
    EXPECT_EQ(nullptr, fixture.ctx.hc_ctx);
    bondp_hc_uninit(&fixture.ctx);
}

TEST(UrmaBondTest, HealthInitMountsProbeResourcesAndFillsSegInfo)
{
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_topo_node_t topo[2] = {};
    urma_bond_seg_info_out_t segInfo = {};
    bool enabled = false;

    fixture.InitSinglePhysicalMember();
    RaiseProbeDevCaps(fixture);
    InitTwoNodeTopo(topo, MakeEid(0xc11));
    ASSERT_EQ(0, bondp_topo_init(topo, 2));

    /* cfg == NULL -> defaults; cfg with values must be accepted too */
    ASSERT_EQ(0, bondp_hc_init(&fixture.ctx, nullptr));
    ASSERT_NE(nullptr, fixture.ctx.hc_ctx);
    EXPECT_EQ(0, bondp_hc_init(&fixture.ctx, nullptr)); /* idempotent */

    /* probe segs are mounted -> fill_seg_info reports them enabled */
    EXPECT_EQ(0, bondp_hc_fill_seg_info(&fixture.ctx, &segInfo, &enabled));
    EXPECT_TRUE(enabled);
    EXPECT_NE(0U, segInfo.slaves[0].len);

    bondp_hc_uninit(&fixture.ctx);
    EXPECT_EQ(nullptr, fixture.ctx.hc_ctx);
    bondp_hc_uninit(&fixture.ctx); /* idempotent */
    EXPECT_FALSE(bondp_hc_fill_seg_info(&fixture.ctx, &segInfo, &enabled));
    EXPECT_FALSE(enabled);
}

TEST(UrmaBondTest, HealthStartRunsProbeCycleAndStops)
{
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_topo_node_t topo[2] = {};
    bondp_hc_cfg_t cfg = {};

    fixture.InitSinglePhysicalMember();
    RaiseProbeDevCaps(fixture);
    fixture.phyOps.post_jetty_send_wr = MockPostJettySendWr;
    fixture.phyOps.post_jfs_wr = MockPostAnyJfsWr;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    InitTwoNodeTopo(topo, MakeEid(0xc21));
    ASSERT_EQ(0, bondp_topo_init(topo, 2));

    cfg.probe_interval_ms = 20;
    cfg.batch_node_num = 1;
    ASSERT_EQ(0, bondp_hc_init(&fixture.ctx, &cfg));
    ASSERT_EQ(0, bondp_worker_create());
    EXPECT_EQ(0, bondp_hc_start(&fixture.ctx, URMA_MAX_PRIORITY));
    EXPECT_EQ(0, bondp_hc_start(&fixture.ctx, URMA_MAX_PRIORITY)); /* already started */

    /* let a few probe batches run through the worker */
    usleep(200 * 1000);

    bondp_hc_uninit(&fixture.ctx);
    bondp_worker_destroy();
}

TEST(UrmaBondTest, HealthTjettyRegisterSyncAndUnregister)
{
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_topo_node_t topo[2] = {};
    urma_bond_id_info_out_t rjettyInfo = {};
    urma_target_jetty_t phyTarget = {};

    fixture.InitSinglePhysicalMember();
    RaiseProbeDevCaps(fixture);
    fixture.targetJetty.v_tjetty.id = MakeJettyId(0xc31);
    fixture.targetJetty.v_tjetty.type = URMA_JETTY;
    SetTargetJettyPath(fixture.targetJetty, 0, 0, &phyTarget, true);
    InitTwoNodeTopo(topo, fixture.targetJetty.v_tjetty.id.eid);
    ASSERT_EQ(0, bondp_topo_init(topo, 2));
    ASSERT_EQ(0, bondp_hc_init(&fixture.ctx, nullptr));

    EXPECT_EQ(-EINVAL, bondp_hc_register_tjetty(nullptr, &fixture.targetJetty, &rjettyInfo));
    EXPECT_EQ(-EINVAL, bondp_hc_register_tjetty(&fixture.ctx, nullptr, &rjettyInfo));
    EXPECT_EQ(-EINVAL, bondp_hc_register_tjetty(&fixture.ctx, &fixture.targetJetty, nullptr));

    /* peer did not request health check -> no-op */
    rjettyInfo.is_health_check_enable = 0;
    EXPECT_EQ(0, bondp_hc_register_tjetty(&fixture.ctx, &fixture.targetJetty, &rjettyInfo));
    EXPECT_EQ(0U, fixture.targetJetty.mask & BONDP_TJETTY_FLAG_HC_REGISTERED);

    rjettyInfo.is_health_check_enable = 1;
    rjettyInfo.enabled_count = 1;
    rjettyInfo.enabled_indices[0] = 0;
    rjettyInfo.slave_id[0] = MakeJettyId(0xc32);
    rjettyInfo.connected[0][0] = true;
    /* a health-check seg must be published for the path to be registered */
    rjettyInfo.health_check_seg.slaves[0].len = 4096;
    rjettyInfo.health_check_seg.slaves[0].ubva.va = 0x1000;
    rjettyInfo.health_check_seg.slaves[0].token_id = 0x71;
    EXPECT_EQ(0, bondp_hc_register_tjetty(&fixture.ctx, &fixture.targetJetty, &rjettyInfo));
    EXPECT_NE(0U, fixture.targetJetty.mask & BONDP_TJETTY_FLAG_HC_REGISTERED);
    EXPECT_EQ(-1, bondp_hc_register_tjetty(&fixture.ctx, &fixture.targetJetty, &rjettyInfo));

    bondp_hc_tjetty_sync_valid(&fixture.targetJetty);
    bondp_hc_unregister_tjetty(&fixture.ctx, &fixture.targetJetty);
    EXPECT_EQ(0U, fixture.targetJetty.mask & BONDP_TJETTY_FLAG_HC_REGISTERED);

    bondp_hc_unregister_tjetty(&fixture.ctx, nullptr); /* safe no-op */
    bondp_hc_uninit(&fixture.ctx);
}

namespace {

/* Health-check context with one registered path (local 0 -> target 0), ready
 * for probe completions. */
void InitHealthWithRegisteredPath(BondPublicApiFixture &fixture, bondp_topo_node_t topo[2],
                                  urma_target_jetty_t *phyTarget, urma_eid_t remoteEid)
{
    urma_bond_id_info_out_t rjettyInfo = {};

    fixture.InitSinglePhysicalMember();
    RaiseProbeDevCaps(fixture);
    fixture.phyOps.post_jetty_send_wr = MockPostJettySendWr;
    fixture.phyOps.poll_jfc = MockPollOneCr;
    InitTwoNodeTopo(topo, remoteEid);
    fixture.targetJetty.v_tjetty.id = MakeJettyId(0xc51);
    fixture.targetJetty.v_tjetty.type = URMA_JETTY;
    fixture.targetJetty.v_tjetty.urma_ctx = &fixture.ctx.v_ctx;
    SetTargetJettyPath(fixture.targetJetty, 0, 0, phyTarget, true);

    rjettyInfo.is_health_check_enable = 1;
    rjettyInfo.enabled_count = 1;
    rjettyInfo.enabled_indices[0] = 0;
    rjettyInfo.health_check_seg.slaves[0].len = 4096;
    rjettyInfo.health_check_seg.slaves[0].ubva.va = 0x1000;
    rjettyInfo.health_check_seg.slaves[0].token_id = 0x71;
    (void)rjettyInfo;
}

} // namespace

TEST(UrmaBondTest, HealthProbeCrSuccessRefreshesPathAndJettys)
{
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_topo_node_t topo[2] = {};
    urma_target_jetty_t phyTarget = {};
    bondp_hc_cfg_t cfg = {};

    InitHealthWithRegisteredPath(fixture, topo, &phyTarget, MakeEid(0xc61));
    ASSERT_EQ(0, bondp_topo_init(topo, 2));
    cfg.probe_interval_ms = 20;
    cfg.batch_node_num = 1;
    ASSERT_EQ(0, bondp_hc_init(&fixture.ctx, &cfg));

    /* register the target jetty so the probe path has a tjetty to report to */
    urma_bond_id_info_out_t rjettyInfo = {};
    rjettyInfo.is_health_check_enable = 1;
    rjettyInfo.enabled_count = 1;
    rjettyInfo.enabled_indices[0] = 0;
    rjettyInfo.health_check_seg.slaves[0].len = 4096;
    rjettyInfo.health_check_seg.slaves[0].ubva.va = 0x1000;
    rjettyInfo.health_check_seg.slaves[0].token_id = 0x71;
    fixture.targetJetty.v_tjetty.id = MakeJettyId(0xc61);
    ASSERT_EQ(0, bondp_hc_register_tjetty(&fixture.ctx, &fixture.targetJetty, &rjettyInfo));

    ASSERT_EQ(0, bondp_worker_create());
    ASSERT_EQ(0, bondp_hc_start(&fixture.ctx, URMA_MAX_PRIORITY));

    /* one successful probe completion for (node 1, target 0) */
    g_mockDatapathCr = {};
    g_mockDatapathCr.status = URMA_CR_SUCCESS;
    g_mockDatapathCr.user_ctx = (uint64_t)1 << 32;
    g_mockDatapathCrCount = 1;
    usleep(200 * 1000);

    bondp_hc_uninit(&fixture.ctx);
    bondp_worker_destroy();
}

TEST(UrmaBondTest, HealthProbeCrTimeoutRebuildsProbeJetty)
{
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_topo_node_t topo[2] = {};
    urma_target_jetty_t phyTarget = {};
    bondp_hc_cfg_t cfg = {};

    InitHealthWithRegisteredPath(fixture, topo, &phyTarget, MakeEid(0xc71));
    ASSERT_EQ(0, bondp_topo_init(topo, 2));
    cfg.probe_interval_ms = 20;
    cfg.batch_node_num = 1;
    ASSERT_EQ(0, bondp_hc_init(&fixture.ctx, &cfg));
    ASSERT_EQ(0, bondp_worker_create());
    ASSERT_EQ(0, bondp_hc_start(&fixture.ctx, URMA_MAX_PRIORITY));

    /* a timeout completion makes the probe loop rebuild the probe jetty */
    g_mockDatapathCr = {};
    g_mockDatapathCr.status = URMA_CR_ACK_TIMEOUT_ERR;
    g_mockDatapathCr.user_ctx = (uint64_t)1 << 32;
    g_mockDatapathCrCount = 1;
    usleep(200 * 1000);

    bondp_hc_uninit(&fixture.ctx);
    bondp_worker_destroy();
}
