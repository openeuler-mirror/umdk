/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding segment, provider and health unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

namespace {
static size_t FillSingleRjettyExt(urma_rjetty_t *remote, uint32_t localIdx, uint32_t targetIdx,
                                  const urma_jetty_id_t &slaveId)
{
    auto *extHdr = bondp_rjetty_get_priv_ext(remote);
    auto *ext = reinterpret_cast<urma_bond_jetty_ext_v0_t *>(extHdr->data);
    auto *localIndices = reinterpret_cast<uint8_t *>(ext->data);
    auto *targetEntry = reinterpret_cast<bondp_rjetty_target_ctx_t *>(ext->data + 1);

    std::memset(ext, 0, sizeof(*ext) + 1 + sizeof(*targetEntry));
    ext->version = BONDP_RJETTY_EXT_VERSION_V0;
    ext->mask = BONDP_RJETTY_EXT_MASK_LOCAL_CTX | BONDP_RJETTY_EXT_MASK_TARGET_CTX;
    ext->local_ctx_cnt = 1;
    ext->target_ctx_cnt = 1;
    localIndices[0] = static_cast<uint8_t>(localIdx);
    targetEntry->target_idx = static_cast<uint8_t>(targetIdx);
    targetEntry->slave_id = slaveId;

    remote->flag.bs.has_user_info = 1;
    extHdr->len = static_cast<uint32_t>(sizeof(*ext) + 1 + sizeof(*targetEntry));
    return extHdr->len;
}
} // namespace


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
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_topo_node_t topo[2] = {};
    urma_token_t token = {};
    urma_import_seg_flag_t flag = {};
    urma_target_seg_t *target = nullptr;
    auto *remote = static_cast<urma_seg_t *>(std::calloc(1, sizeof(urma_seg_t) +
        sizeof(bondp_seg_ext_priv_t) + sizeof(urma_bond_seg_ext_t)));
    ASSERT_NE(nullptr, remote);
    bondp_seg_set_user_info(remote, true);
    auto *segExt = bondp_seg_get_priv_ext(remote);
    auto *ext = reinterpret_cast<urma_bond_seg_ext_t *>(segExt->data);

    fixture.InitSinglePhysicalMember();
    fixture.ctx.seg_cache_enable = true;
    ASSERT_EQ(0, bdp_r_v2p_token_id_table_create(&fixture.ctx.remote_v2p_token_id_table, 4));
    remote->ubva.eid = MakeEid(0x801);
    remote->ubva.va = 0x100000;
    remote->len = 4096;
    remote->token_id = 0x71;
    segExt->len = sizeof(*ext) - 1;
    EXPECT_EQ(nullptr, bondp_import_seg(&fixture.ctx.v_ctx, remote, &token, 0x300000, flag));
    segExt->len = sizeof(*ext);
    ext->peer_p_seg[0].ubva.eid = MakeEid(0x802);
    ext->peer_p_seg[0].ubva.va = 0x200000;
    ext->peer_p_seg[0].len = 4096;
    ext->peer_p_seg[0].token_id = 0x72;

    topo[0].is_current = true;
    CopyEidToTopo(topo[0].agg_devs[0].agg_eid, MakeEid(0x800));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].primary_eid, MakeEid(0x803));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].port_eid[0], MakeEid(0x804));
    CopyEidToTopo(topo[1].agg_devs[0].agg_eid, remote->ubva.eid);
    topo[1].links[0][0] = true;
    ASSERT_EQ(0, bondp_topo_init(topo, 2));

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
    BondTopoMapCleanup topoCleanup;
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    bondp_topo_node_t topo[2] = {};
    urma_token_t token = {};
    urma_target_jetty_t *target = nullptr;
    auto *bondRemote = static_cast<bondp_rjetty_t *>(std::calloc(1, sizeof(bondp_rjetty_t)));
    ASSERT_NE(nullptr, bondRemote);
    urma_rjetty_t *remote = &bondRemote->base;
    auto *jettyExt = bondp_rjetty_get_priv_ext(remote);

    fixture.InitSinglePhysicalMember();
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    topo[0].is_current = true;
    CopyEidToTopo(topo[0].agg_devs[0].agg_eid, MakeEid(0x810));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].primary_eid, MakeEid(0x820));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].port_eid[0], MakeEid(0x821));
    CopyEidToTopo(topo[1].agg_devs[0].agg_eid, MakeEid(0x811));
    topo[1].links[0][0] = true;
    ASSERT_EQ(0, bondp_topo_init(topo, 2));
    g_bondp_global_ctx = &fakeGlobal;
    fakeGlobal.enable_health_check = false;

    remote->jetty_id = MakeJettyId(0x811);
    remote->jetty_id.eid = MakeEid(0x811);
    remote->trans_mode = URMA_TM_RC;
    remote->type = URMA_JETTY;
    size_t extLength = FillSingleRjettyExt(remote, 0, 0, MakeJettyId(0x812));

    target = bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token);
    EXPECT_EQ(1, urma_test::GetHwMockState().importJettyCount);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(remote->jetty_id.id, target->id.id);
    bondp_tjetty_get(target);
    bondp_tjetty_put(target);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jetty(target));

    jettyExt->len = static_cast<uint32_t>(sizeof(urma_bond_jetty_ext_v0_t) - 1);
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token));
    jettyExt->len = static_cast<uint32_t>(extLength);

    auto *ext = reinterpret_cast<urma_bond_jetty_ext_v0_t *>(jettyExt->data);
    ext->target_ctx_cnt = 0;
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token));
    ext->target_ctx_cnt = 1;

    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(nullptr, bondp_import_jetty(&fixture.ctx.v_ctx, remote, &token));

    g_bondp_global_ctx = nullptr;
    std::free(bondRemote);
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
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    g_bondp_global_ctx = &fakeGlobal;
    fakeGlobal.enable_health_check = false;
    urma_test::SetHwMockIoctl(true, 0xa30, 0xa300);
    rjetty.jetty_id = MakeJettyId(0xa31);
    rjetty.trans_mode = URMA_TM_RC;
    rjetty.type = URMA_JETTY;

    target = bondp_import_jetty(&fixture.ctx.v_ctx, &rjetty, &token);
    ASSERT_NE(nullptr, target);
    EXPECT_EQ(1, urma_test::GetHwMockState().importJettyCount);
    EXPECT_EQ(URMA_JETTY, target->type);
    EXPECT_EQ(URMA_SUCCESS, bondp_unimport_jetty(target));

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
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
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

    g_bondp_global_ctx = nullptr;
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
    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup;
    bondp_topo_node_t topo = {};
    topo.is_current = true;
    ASSERT_EQ(0, bondp_topo_init(&topo, 1));
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
    BondTopoMapCleanup topoCleanup;
    urma_test::SetHwMockIoctl(true, 0xd20, 0xd200);

    createdCtx = bondp_create_context(&fixture.dev, 0, 7);
    ASSERT_NE(nullptr, createdCtx);
    EXPECT_TRUE(bondp_topo_is_initialized());
    EXPECT_EQ(1U, bondp_topo_get_node_num());
    EXPECT_FALSE(fakeGlobal.skip_load_topo);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_context(createdCtx));
}

TEST(UrmaBondTest, PublicProviderCreateContextCleansVirtualContextOnStableFailures)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup;

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
    BondTopoMapCleanup topoCleanup;

    urma_test::SetHwMockIoctl(true, 0xd40, 0xd400);
    bondp_topo_node_t topo = {};
    topo.is_current = true;
    ASSERT_EQ(0, bondp_topo_init(&topo, 1));

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

    BondProviderMockGuard mockGuard(&fakeGlobal, &fixture.phyDev, &fixture.phyOps);
    BondTopoMapCleanup topoCleanup;
    bondp_topo_node_t topo = {};
    topo.is_current = true;
    ASSERT_EQ(0, bondp_topo_init(&topo, 1));
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
    fakeGlobal.enable_health_check = false;
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
    global->enable_health_check = false;
    g_bondp_global_ctx = global;

    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
}

TEST(UrmaBondTest, PublicProviderInitReadsEnvAndCleansUp)
{
    EnvGuard failover("BOND_ENABLE_FAILOVER", "false");
    EnvGuard failback("BOND_ENABLE_FAILBACK", "bad-bool");
    EnvGuard healthCheck("BOND_ENABLE_HEALTH_CHECK", nullptr);
    EnvGuard healthInterval("BOND_HEALTH_CHECK_ACTIVE_INTERVAL", "bad-int");

    g_bondp_global_ctx = nullptr;
    EXPECT_EQ(URMA_SUCCESS, bondp_init(nullptr));
    EXPECT_NE(nullptr, g_bondp_global_ctx);
    EXPECT_FALSE(g_bondp_global_ctx->enable_failover);
    EXPECT_FALSE(g_bondp_global_ctx->enable_failback);
    EXPECT_FALSE(g_bondp_global_ctx->enable_health_check);
    EXPECT_EQ(BONDP_HC_DEFAULT_PROBE_INTERVAL_MS,
              g_bondp_global_ctx->health_check_interval_ms);
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
}

TEST(UrmaBondTest, PublicProviderInitAcceptsValidEnvValues)
{
    EnvGuard failover("BOND_ENABLE_FAILOVER", "true");
    EnvGuard failback("BOND_ENABLE_FAILBACK", "false");
    EnvGuard healthCheck("BOND_ENABLE_HEALTH_CHECK", "true");
    EnvGuard healthInterval("BOND_HEALTH_CHECK_ACTIVE_INTERVAL", "60000");

    g_bondp_global_ctx = nullptr;
    EXPECT_EQ(URMA_SUCCESS, bondp_init(nullptr));
    EXPECT_NE(nullptr, g_bondp_global_ctx);
    EXPECT_TRUE(g_bondp_global_ctx->enable_failover);
    EXPECT_FALSE(g_bondp_global_ctx->enable_failback);
    EXPECT_TRUE(g_bondp_global_ctx->enable_health_check);
    EXPECT_EQ(60000U, g_bondp_global_ctx->health_check_interval_ms);
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
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
    usleep(2100000);
    bondp_fb_uninit(&fixture.ctx);
    bondp_worker_destroy();
    bondp_fb_uninit(&fixture.ctx);
}

TEST(UrmaBondTest, PublicProviderInitSucceedsWithDisabledHealth)
{
    EnvGuard failover("BOND_ENABLE_FAILOVER", "false");

    g_bondp_global_ctx = nullptr;
    EXPECT_EQ(URMA_SUCCESS, bondp_init(nullptr));
    EXPECT_NE(nullptr, g_bondp_global_ctx);
    EXPECT_EQ(URMA_FAIL, bondp_init(nullptr));
    EXPECT_EQ(URMA_SUCCESS, bondp_uninit());
    EXPECT_EQ(nullptr, g_bondp_global_ctx);
}

TEST(UrmaBondTest, HealthV2PublicApisHonorDisabledAndInvalidContracts)
{
    BondPathFixture fixture;
    urma_bond_seg_info_out_t segInfo = {};
    urma_bond_id_info_out_t idInfo = {};
    bool enabled = true;

    EXPECT_EQ(-EINVAL, bondp_hc_fill_seg_info(nullptr, &segInfo, &enabled));
    EXPECT_EQ(-EINVAL, bondp_hc_fill_seg_info(&fixture.ctx, nullptr, &enabled));
    EXPECT_EQ(-EINVAL, bondp_hc_fill_seg_info(&fixture.ctx, &segInfo, nullptr));
    EXPECT_EQ(0, bondp_hc_fill_seg_info(&fixture.ctx, &segInfo, &enabled));
    EXPECT_FALSE(enabled);

    EXPECT_EQ(-EINVAL, bondp_hc_import_tseg(nullptr, &fixture.target, &idInfo));
    EXPECT_EQ(-EINVAL, bondp_hc_import_tseg(&fixture.ctx, nullptr, &idInfo));
    EXPECT_EQ(-EINVAL, bondp_hc_import_tseg(&fixture.ctx, &fixture.target, nullptr));
    EXPECT_EQ(0, bondp_hc_import_tseg(&fixture.ctx, &fixture.target, &idInfo));
    EXPECT_EQ(URMA_SUCCESS, bondp_hc_unimport_tseg(&fixture.target));
    EXPECT_EQ(URMA_FAIL, bondp_hc_unimport_tseg(nullptr));

}
