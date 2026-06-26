/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding public API unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

static urma_jfce_t *g_emptyEventJfce = nullptr;
static urma_jfc_t *g_readyEventJfc = nullptr;
static urma_jfc_t *g_rearmedPhysicalJfc[URMA_UBAGG_DEV_MAX_NUM] = {};
static int g_readyEventFd = -1;
static int g_waitJfcCallCount = 0;
static int g_rearmPhysicalJfcCount = 0;

class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) : fd_(fd)
    {
    }

    ~ScopedFd()
    {
        Reset();
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    int Get() const
    {
        return fd_;
    }

    void Reset(int fd = -1)
    {
        if (fd_ >= 0) {
            (void)close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_;
};

class MockWaitJfcStateGuard {
public:
    ~MockWaitJfcStateGuard()
    {
        g_emptyEventJfce = nullptr;
        g_readyEventJfc = nullptr;
        g_readyEventFd = -1;
        g_waitJfcCallCount = 0;
        std::memset(g_rearmedPhysicalJfc, 0, sizeof(g_rearmedPhysicalJfc));
        g_rearmPhysicalJfcCount = 0;
    }
};

static int MockWaitEmptyThenReadyPhysicalJfc(urma_jfce_t *jfce, uint32_t, int, urma_jfc_t *jfc[])
{
    eventfd_t value = 0;
    g_waitJfcCallCount++;
    (void)eventfd_read(jfce->fd, &value);
    if (jfce == g_emptyEventJfce) {
        if (g_readyEventFd >= 0) {
            (void)eventfd_write(g_readyEventFd, 1);
        }
        return 0;
    }
    jfc[0] = g_readyEventJfc;
    return 1;
}

static int MockWaitPersistentEmptyThenReadyPhysicalJfc(urma_jfce_t *jfce, uint32_t, int, urma_jfc_t *jfc[])
{
    eventfd_t value = 0;
    g_waitJfcCallCount++;
    if (jfce == g_emptyEventJfce) {
        if (g_readyEventFd >= 0) {
            (void)eventfd_write(g_readyEventFd, 1);
        }
        return 0;
    }
    (void)eventfd_read(jfce->fd, &value);
    jfc[0] = g_readyEventJfc;
    return 1;
}

static int MockWaitReadablePhysicalJfcWithoutCompletion(urma_jfce_t *, uint32_t, int, urma_jfc_t *[])
{
    g_waitJfcCallCount++;
    return 0;
}

static urma_status_t MockRecordRearmPhysicalJfc(urma_jfc_t *jfc, bool)
{
    if (g_rearmPhysicalJfcCount < static_cast<int>(URMA_UBAGG_DEV_MAX_NUM)) {
        g_rearmedPhysicalJfc[g_rearmPhysicalJfcCount++] = jfc;
    }
    return urma_test::GetHwMockState().status;
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

TEST(UrmaBondTest, PublicDeleteApisReachVirtualDeleteFailurePaths)
{
    BondPublicApiFixture fixture;

    auto *jfc = static_cast<bondp_jfc_t *>(std::calloc(1, sizeof(bondp_jfc_t)));
    ASSERT_NE(nullptr, jfc);
    jfc->v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    jfc->v_jfc.jfc_id.id = 0x701;
    SetRefCount(&jfc->use_cnt, 0);
    EXPECT_EQ(URMA_FAIL, bondp_delete_jfc(&jfc->v_jfc));

    auto *parentJfc = static_cast<bondp_jfc_t *>(std::calloc(1, sizeof(bondp_jfc_t)));
    ASSERT_NE(nullptr, parentJfc);
    parentJfc->v_jfc.urma_ctx = &fixture.ctx.v_ctx;
    SetRefCount(&parentJfc->use_cnt, 1);

    auto *jfs = static_cast<bondp_comp_t *>(std::calloc(1, sizeof(bondp_comp_t)));
    ASSERT_NE(nullptr, jfs);
    jfs->bondp_ctx = &fixture.ctx;
    jfs->comp_type = BONDP_COMP_JFS;
    jfs->v_jfs.urma_ctx = &fixture.ctx.v_ctx;
    jfs->v_jfs.jfs_cfg.jfc = &parentJfc->v_jfc;
    jfs->v_jfs.jfs_id.id = 0x702;
    SetRefCount(&jfs->use_cnt, 0);
    ASSERT_EQ(0, pthread_spin_init(&jfs->send_lock, PTHREAD_PROCESS_PRIVATE));
    EXPECT_EQ(URMA_FAIL, bondp_delete_jfs(&jfs->v_jfs));

    auto *jfr = static_cast<bondp_comp_t *>(std::calloc(1, sizeof(bondp_comp_t)));
    ASSERT_NE(nullptr, jfr);
    jfr->bondp_ctx = &fixture.ctx;
    jfr->comp_type = BONDP_COMP_JFR;
    jfr->v_jfr.urma_ctx = &fixture.ctx.v_ctx;
    jfr->v_jfr.jfr_cfg.jfc = &parentJfc->v_jfc;
    jfr->v_jfr.jfr_id.id = 0x703;
    SetRefCount(&jfr->use_cnt, 0);
    EXPECT_EQ(URMA_FAIL, bondp_delete_jfr(&jfr->v_jfr));

    auto *parentJfr = static_cast<bondp_comp_t *>(std::calloc(1, sizeof(bondp_comp_t)));
    ASSERT_NE(nullptr, parentJfr);
    parentJfr->v_jfr.urma_ctx = &fixture.ctx.v_ctx;
    SetRefCount(&parentJfr->use_cnt, 1);

    auto *jetty = static_cast<bondp_comp_t *>(std::calloc(1, sizeof(bondp_comp_t)));
    ASSERT_NE(nullptr, jetty);
    jetty->bondp_ctx = &fixture.ctx;
    jetty->comp_type = BONDP_COMP_JETTY;
    jetty->v_jetty.urma_ctx = &fixture.ctx.v_ctx;
    jetty->v_jetty.jetty_cfg.shared.jfr = &parentJfr->v_jfr;
    jetty->v_jetty.jetty_cfg.shared.jfc = &parentJfc->v_jfc;
    jetty->v_jetty.jetty_id.id = 0x704;
    SetRefCount(&jetty->use_cnt, 0);
    ASSERT_EQ(0, pthread_spin_init(&jetty->send_lock, PTHREAD_PROCESS_PRIVATE));
    EXPECT_EQ(URMA_FAIL, bondp_delete_jetty(&jetty->v_jetty));

    std::free(parentJfr);
    std::free(parentJfc);
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

TEST(UrmaBondTest, PublicApiModifyAndQueryPropagatePhysicalMemberResults)
{
    BondPublicApiFixture fixture;
    urma_jfc_attr_t jfcAttr = {};
    urma_jfs_attr_t jfsAttr = {};
    urma_jfr_attr_t jfrAttr = {};
    urma_jfr_cfg_t queriedCfg = {};
    urma_jetty_attr_t jettyAttr = {};

    fixture.InitSinglePhysicalMember();
    jfsAttr.mask = JFS_STATE;
    jfsAttr.state = URMA_JETTY_STATE_ERROR;
    jettyAttr.mask = JETTY_STATE;
    jettyAttr.state = URMA_JETTY_STATE_ERROR;

    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, bondp_modify_jfc(&fixture.jfc.v_jfc, &jfcAttr));
    EXPECT_EQ(URMA_EAGAIN, bondp_modify_jfs(&fixture.jfs.v_jfs, &jfsAttr));
    EXPECT_TRUE(fixture.jfs.modify_to_error);
    EXPECT_EQ(URMA_EAGAIN, bondp_modify_jfr(&fixture.jfr.v_jfr, &jfrAttr));
    EXPECT_EQ(URMA_EAGAIN, bondp_modify_jetty(&fixture.jetty.v_jetty, &jettyAttr));
    EXPECT_TRUE(fixture.jetty.modify_to_error);

    urma_test::SetHwMockStatus(URMA_SUCCESS);
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfc(&fixture.jfc.v_jfc, &jfcAttr));
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfs(&fixture.jfs.v_jfs, &jfsAttr));
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jfr(&fixture.jfr.v_jfr, &jfrAttr));
    EXPECT_EQ(URMA_SUCCESS, bondp_modify_jetty(&fixture.jetty.v_jetty, &jettyAttr));

    urma_test::GetHwMockState().jfrQueryStatus = URMA_FAIL;
    EXPECT_EQ(URMA_FAIL, bondp_query_jfr(&fixture.jfr.v_jfr, &queriedCfg, &jfrAttr));

    urma_test::GetHwMockState().jfrQueryStatus = URMA_SUCCESS;
    urma_test::SetHwMockIntReturn(3);
    EXPECT_EQ(URMA_SUCCESS, bondp_query_jfr(&fixture.jfr.v_jfr, &queriedCfg, &jfrAttr));
    EXPECT_EQ(JFR_STATE | JFR_RX_THRESHOLD, jfrAttr.mask);
    EXPECT_EQ(URMA_JFR_STATE_READY, jfrAttr.state);
    EXPECT_EQ(3U, jfrAttr.rx_threshold);
}

TEST(UrmaBondTest, PublicApiRejectsInvalidCreateAndControlInputs)
{
    BondPublicApiFixture fixture;
    bondp_jfc_cfg_t jfcCfg = {};
    bondp_jfs_cfg_t jfsCfg = {};
    bondp_jfr_cfg_t jfrCfg = {};
    bondp_port_id_t portId = {};
    urma_jetty_cfg_t jettyCfg = {};
    bondp_jetty_cfg_t jettyExtCfg = {};
    urma_jfc_t *jfcList[1] = {};
    uint32_t nevents[1] = {1};
    urma_async_event_t asyncEvent = {};
    urma_user_ctl_in_t ctl = {};
    urma_user_ctl_out_t ctlOut = {};

    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg));
    jettyCfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    jettyCfg.shared.jfr = &fixture.jfr.v_jfr;
    jettyCfg.id = BONDP_MAX_WELL_KNOWN_JETTY_ID;
    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg));
    jettyCfg.id = 0;
    jettyExtCfg.base = jettyCfg;
    jettyExtCfg.base.flag.bs.has_drv_ext = 1;
    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyExtCfg.base));
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
    ctl.opcode = BONDP_USER_CTL_OPCODE_GET_RJETTY;
    ctl.addr = 0;
    ctl.len = 0;
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &ctl, &ctlOut));
    ctl.opcode = BONDP_USER_CTL_OPCODE_GET_SEG_CTX;
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

TEST(UrmaBondTest, PublicJfceCreateAndDeleteUseMockPhysicalMember)
{
    BondPublicApiFixture fixture;
    urma_jfce_t *jfce = nullptr;

    fixture.InitSinglePhysicalMember();
    fixture.ctx.dev_num = 1;
    fixture.ctx.p_ctxs[0] = nullptr;
    fixture.phyOps.create_jfce = MockCreatePhysicalJfce;
    fixture.phyOps.delete_jfce = MockDeletePhysicalJfce;
    jfce = bondp_create_jfce(&fixture.ctx.v_ctx);
    ASSERT_NE(nullptr, jfce);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_jfce(jfce));

    fixture.InitSinglePhysicalMember();
    fixture.ctx.dev_num = 1;
    fixture.ctx.p_ctxs[0] = &fixture.phyCtx;
    fixture.phyOps.create_jfce = MockCreatePhysicalJfce;
    fixture.phyOps.delete_jfce = MockDeletePhysicalJfce;

    jfce = bondp_create_jfce(&fixture.ctx.v_ctx);
    ASSERT_NE(nullptr, jfce);
    auto *bdpJfce = CONTAINER_OF_FIELD(jfce, bondp_jfce_t, v_jfce);
    EXPECT_GE(jfce->fd, 0);
    ASSERT_NE(nullptr, bdpJfce->p_jfce[0]);
    EXPECT_GE(bdpJfce->p_jfce[0]->fd, 0);
    ASSERT_EQ(0, close(bdpJfce->p_jfce[0]->fd));
    bdpJfce->p_jfce[0]->fd = -1;
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_jfce(jfce));
}

TEST(UrmaBondTest, PublicJfceCreateAndDeletePropagatePhysicalFailures)
{
    BondPublicApiFixture fixture;
    urma_jfce_t *jfce = nullptr;

    fixture.InitSinglePhysicalMember();
    fixture.phyOps.create_jfce = MockCreatePhysicalJfceNull;
    fixture.phyOps.delete_jfce = MockDeletePhysicalJfce;
    EXPECT_EQ(nullptr, bondp_create_jfce(&fixture.ctx.v_ctx));

    fixture.phyOps.create_jfce = MockCreatePhysicalJfceBadFd;
    EXPECT_EQ(nullptr, bondp_create_jfce(&fixture.ctx.v_ctx));

    fixture.phyOps.create_jfce = MockCreatePhysicalJfce;
    jfce = bondp_create_jfce(&fixture.ctx.v_ctx);
    ASSERT_NE(nullptr, jfce);
    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(URMA_FAIL, bondp_delete_jfce(jfce));
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
    fixture.jfc.enabled_count = 1;
    fixture.jfc.enabled_indices[0] = 0;
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

TEST(UrmaBondTest, PublicWaitJfcContinuesAfterEmptyPhysicalEvent)
{
    MockWaitJfcStateGuard stateGuard;
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    urma_jfc_t readyPhysicalJfc = {};
    ScopedFd epollFd;
    ScopedFd staleEventFd;
    ScopedFd readyEventFd;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.ctx.dev_num = 2;
    fixture.jfc.dev_num = 2;
    fixture.jfce.dev_num = 2;
    fixture.phyOps.wait_jfc = MockWaitEmptyThenReadyPhysicalJfc;
    fixture.phyOps.ack_jfc = MockAckPhysicalJfc;

    epollFd.Reset(epoll_create1(EPOLL_CLOEXEC));
    ASSERT_GE(epollFd.Get(), 0);
    staleEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(staleEventFd.Get(), 0);
    readyEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(readyEventFd.Get(), 0);

    fixture.jfce.v_jfce.fd = epollFd.Get();
    fixture.phyJfce[0].fd = staleEventFd.Get();
    fixture.phyJfce[0].urma_ctx = &fixture.phyCtx;
    fixture.phyJfce[1].fd = readyEventFd.Get();
    fixture.phyJfce[1].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[0] = &fixture.phyJfce[0];
    fixture.jfce.p_jfce[1] = &fixture.phyJfce[1];
    readyPhysicalJfc.jfc_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfc.v_jfc);
    g_emptyEventJfce = &fixture.phyJfce[0];
    g_readyEventJfc = &readyPhysicalJfc;
    g_readyEventFd = readyEventFd.Get();
    g_waitJfcCallCount = 0;

    ev.events = EPOLLIN;
    ev.data.fd = staleEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, staleEventFd.Get(), &ev));
    ev.data.fd = readyEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, readyEventFd.Get(), &ev));
    ASSERT_EQ(0, eventfd_write(staleEventFd.Get(), 1));

    EXPECT_EQ(1, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 100, readyJfc));
    EXPECT_EQ(&fixture.jfc.v_jfc, readyJfc[0]);
    EXPECT_GT(g_waitJfcCallCount, 1);
}

TEST(UrmaBondTest, PublicWaitJfcScansBackupWhenStalePrimaryRemainsReadable)
{
    MockWaitJfcStateGuard stateGuard;
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    urma_jfc_t readyPhysicalJfc = {};
    ScopedFd epollFd;
    ScopedFd staleEventFd;
    ScopedFd readyEventFd;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.ctx.dev_num = 2;
    fixture.jfc.dev_num = 2;
    fixture.jfce.dev_num = 2;
    fixture.phyOps.wait_jfc = MockWaitPersistentEmptyThenReadyPhysicalJfc;
    fixture.phyOps.ack_jfc = MockAckPhysicalJfc;

    epollFd.Reset(epoll_create1(EPOLL_CLOEXEC));
    ASSERT_GE(epollFd.Get(), 0);
    staleEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(staleEventFd.Get(), 0);
    readyEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(readyEventFd.Get(), 0);

    fixture.jfce.v_jfce.fd = epollFd.Get();
    fixture.phyJfce[0].fd = staleEventFd.Get();
    fixture.phyJfce[0].urma_ctx = &fixture.phyCtx;
    fixture.phyJfce[1].fd = readyEventFd.Get();
    fixture.phyJfce[1].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[0] = &fixture.phyJfce[0];
    fixture.jfce.p_jfce[1] = &fixture.phyJfce[1];
    readyPhysicalJfc.jfc_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfc.v_jfc);
    g_emptyEventJfce = &fixture.phyJfce[0];
    g_readyEventJfc = &readyPhysicalJfc;
    g_readyEventFd = readyEventFd.Get();
    g_waitJfcCallCount = 0;

    ev.events = EPOLLIN;
    ev.data.fd = staleEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, staleEventFd.Get(), &ev));
    ev.data.fd = readyEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, readyEventFd.Get(), &ev));
    ASSERT_EQ(0, eventfd_write(staleEventFd.Get(), 1));

    EXPECT_EQ(1, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 100, readyJfc));
    EXPECT_EQ(&fixture.jfc.v_jfc, readyJfc[0]);
    EXPECT_GT(g_waitJfcCallCount, 1);
}

TEST(UrmaBondTest, PublicWaitJfcContinuesAfterEmptyPhysicalEventWithInfiniteTimeout)
{
    MockWaitJfcStateGuard stateGuard;
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    urma_jfc_t readyPhysicalJfc = {};
    ScopedFd epollFd;
    ScopedFd staleEventFd;
    ScopedFd readyEventFd;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.ctx.dev_num = 2;
    fixture.jfc.dev_num = 2;
    fixture.jfce.dev_num = 2;
    fixture.phyOps.wait_jfc = MockWaitPersistentEmptyThenReadyPhysicalJfc;
    fixture.phyOps.ack_jfc = MockAckPhysicalJfc;

    epollFd.Reset(epoll_create1(EPOLL_CLOEXEC));
    ASSERT_GE(epollFd.Get(), 0);
    staleEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(staleEventFd.Get(), 0);
    readyEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(readyEventFd.Get(), 0);

    fixture.jfce.v_jfce.fd = epollFd.Get();
    fixture.phyJfce[0].fd = staleEventFd.Get();
    fixture.phyJfce[0].urma_ctx = &fixture.phyCtx;
    fixture.phyJfce[1].fd = readyEventFd.Get();
    fixture.phyJfce[1].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[0] = &fixture.phyJfce[0];
    fixture.jfce.p_jfce[1] = &fixture.phyJfce[1];
    readyPhysicalJfc.jfc_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfc.v_jfc);
    g_emptyEventJfce = &fixture.phyJfce[0];
    g_readyEventJfc = &readyPhysicalJfc;
    g_readyEventFd = readyEventFd.Get();
    g_waitJfcCallCount = 0;

    ev.events = EPOLLIN;
    ev.data.fd = staleEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, staleEventFd.Get(), &ev));
    ev.data.fd = readyEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, readyEventFd.Get(), &ev));
    ASSERT_EQ(0, eventfd_write(staleEventFd.Get(), 1));

    EXPECT_EQ(1, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, -1, readyJfc));
    EXPECT_EQ(&fixture.jfc.v_jfc, readyJfc[0]);
    EXPECT_GT(g_waitJfcCallCount, 1);
}

TEST(UrmaBondTest, PublicWaitJfcRetriesReadablePhysicalEventUntilTimeout)
{
    MockWaitJfcStateGuard stateGuard;
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    ScopedFd epollFd;
    ScopedFd eventFd;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.jfc.dev_num = 1;
    fixture.jfce.dev_num = 1;
    fixture.phyOps.wait_jfc = MockWaitReadablePhysicalJfcWithoutCompletion;

    epollFd.Reset(epoll_create1(EPOLL_CLOEXEC));
    ASSERT_GE(epollFd.Get(), 0);
    eventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(eventFd.Get(), 0);

    fixture.jfce.v_jfce.fd = epollFd.Get();
    fixture.phyJfce[0].fd = eventFd.Get();
    fixture.phyJfce[0].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[0] = &fixture.phyJfce[0];
    g_waitJfcCallCount = 0;

    ev.events = EPOLLIN;
    ev.data.fd = eventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, eventFd.Get(), &ev));
    ASSERT_EQ(0, eventfd_write(eventFd.Get(), 1));

    EXPECT_EQ(0, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 10, readyJfc));
    EXPECT_EQ(nullptr, readyJfc[0]);
    EXPECT_GT(g_waitJfcCallCount, 1);
}

TEST(UrmaBondTest, PublicWaitJfcMarksEventSourceForNextRearm)
{
    MockWaitJfcStateGuard stateGuard;
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    urma_jfc_t backupPhysicalJfc = {};
    ScopedFd epollFd;
    ScopedFd backupEventFd;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.ctx.dev_num = 2;
    fixture.jfc.dev_num = 2;
    fixture.jfc.enabled_count = 2;
    fixture.jfc.enabled_indices[0] = 0;
    fixture.jfc.enabled_indices[1] = 1;
    fixture.jfc.p_jfc[1] = &backupPhysicalJfc;
    fixture.jfc.polled_mask = 1U;
    fixture.jfce.dev_num = 2;
    fixture.phyOps.wait_jfc = MockWaitEmptyThenReadyPhysicalJfc;
    fixture.phyOps.ack_jfc = MockAckPhysicalJfc;
    fixture.phyOps.rearm_jfc = MockRecordRearmPhysicalJfc;

    epollFd.Reset(epoll_create1(EPOLL_CLOEXEC));
    ASSERT_GE(epollFd.Get(), 0);
    backupEventFd.Reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    ASSERT_GE(backupEventFd.Get(), 0);

    fixture.jfce.v_jfce.fd = epollFd.Get();
    fixture.phyJfce[1].fd = backupEventFd.Get();
    fixture.phyJfce[1].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[1] = &fixture.phyJfce[1];
    backupPhysicalJfc.urma_ctx = &fixture.phyCtx;
    backupPhysicalJfc.jfc_cfg.user_ctx = reinterpret_cast<uint64_t>(&fixture.jfc.v_jfc);
    g_emptyEventJfce = nullptr;
    g_readyEventJfc = &backupPhysicalJfc;
    g_waitJfcCallCount = 0;

    ev.events = EPOLLIN;
    ev.data.fd = backupEventFd.Get();
    ASSERT_EQ(0, epoll_ctl(epollFd.Get(), EPOLL_CTL_ADD, backupEventFd.Get(), &ev));
    ASSERT_EQ(0, eventfd_write(backupEventFd.Get(), 1));

    EXPECT_EQ(1, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 100, readyJfc));
    EXPECT_EQ(&fixture.jfc.v_jfc, readyJfc[0]);

    EXPECT_EQ(URMA_SUCCESS, bondp_rearm_jfc(&fixture.jfc.v_jfc, false));
    ASSERT_EQ(2, g_rearmPhysicalJfcCount);
    EXPECT_EQ(&fixture.phyJfc, g_rearmedPhysicalJfc[0]);
    EXPECT_EQ(&backupPhysicalJfc, g_rearmedPhysicalJfc[1]);
}

TEST(UrmaBondTest, PublicEventApisCoverProviderFailureContracts)
{
    BondPublicApiFixture fixture;
    urma_jfc_t *readyJfc[1] = {};
    urma_async_event_t event = {};
    int epollFd = -1;
    int eventFd = -1;
    epoll_event ev = {};

    fixture.InitSinglePhysicalMember();
    fixture.jfc.dev_num = 1;
    fixture.jfce.dev_num = 1;
    fixture.phyOps.rearm_jfc = MockRearmPhysicalJfc;
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_FAIL, bondp_rearm_jfc(&fixture.jfc.v_jfc, true));

    epollFd = epoll_create1(EPOLL_CLOEXEC);
    ASSERT_GE(epollFd, 0);
    eventFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    ASSERT_GE(eventFd, 0);
    fixture.jfce.v_jfce.fd = epollFd;
    fixture.phyJfce[0].fd = eventFd;
    fixture.phyJfce[0].urma_ctx = &fixture.phyCtx;
    fixture.jfce.p_jfce[0] = &fixture.phyJfce[0];
    fixture.phyOps.wait_jfc = MockWaitOnePhysicalJfc;
    g_mockWaitJfc = &fixture.phyJfc;
    ev.events = EPOLLIN;
    ev.data.fd = eventFd;
    ASSERT_EQ(0, epoll_ctl(epollFd, EPOLL_CTL_ADD, eventFd, &ev));
    ASSERT_EQ(0, eventfd_write(eventFd, 1));

    urma_test::SetHwMockIntReturn(-EIO);
    EXPECT_EQ(0, bondp_wait_jfc(&fixture.jfce.v_jfce, 1, 0, readyJfc));

    fixture.ctx.v_ctx.async_fd = epollFd;
    fixture.phyOps.get_async_event = MockGetAsyncEvent;
    ev.data.ptr = &fixture.phyCtx;
    ASSERT_EQ(0, epoll_ctl(epollFd, EPOLL_CTL_MOD, eventFd, &ev));
    ASSERT_EQ(0, eventfd_write(eventFd, 1));
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, bondp_get_async_event(&fixture.ctx.v_ctx, &event));

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
    jfsCfg.flag.bs.order_type = URMA_OL;
    EXPECT_EQ(nullptr, bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg));

    jfrCfg.jfc = &fixture.jfc.v_jfc;
    jfrCfg.depth = 4;
    jfrCfg.max_sge = 1;
    jfrCfg.trans_mode = URMA_TM_RC;
    jfrCfg.flag.bs.order_type = URMA_OL;
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

TEST(UrmaBondTest, PublicCreateJfcCoversVirtualCreateWithMockIoctl)
{
    BondPublicApiFixture fixture;
    urma_jfc_cfg_t jfcCfg = {};

    fixture.InitSinglePhysicalMember();
    fixture.ctx.v_ctx.dev_fd = 7;
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    jfcCfg.depth = 4;
    urma_test::SetHwMockIoctl(true, 0xb08, 0xb080);

    urma_jfc_t *createdJfc = bondp_create_jfc(&fixture.ctx.v_ctx, &jfcCfg);
    ASSERT_NE(nullptr, createdJfc);
    EXPECT_EQ(0xb08U, createdJfc->jfc_id.id);
    FreeCreatedBondJfcForTest(CONTAINER_OF_FIELD(createdJfc, bondp_jfc_t, v_jfc));
}

TEST(UrmaBondTest, PublicCreateAndDeleteApisUseMockPhysicalMembers)
{
    BondPublicApiFixture fixture;
    urma_jfs_cfg_t jfsCfg = {};
    urma_jfr_cfg_t jfrCfg = {};

    fixture.InitSinglePhysicalMember();
    fixture.InitActiveComp(&fixture.jfr, 0);
    fixture.ctx.v_ctx.dev_fd = 7;
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 16));

    jfsCfg.jfc = &fixture.jfc.v_jfc;
    jfsCfg.depth = 4;
    jfsCfg.max_sge = 1;
    jfsCfg.max_rsge = 1;
    jfsCfg.trans_mode = URMA_TM_RC;
    urma_test::SetHwMockIoctl(true, 0xb10, 0xb100);
    urma_jfs_t *createdJfs = bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg);
    ASSERT_NE(nullptr, createdJfs);
    createdJfs->async_events_acked = 0;
    SetRefCount(&CONTAINER_OF_FIELD(createdJfs, bondp_comp_t, v_jfs)->use_cnt, 0);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_jfs(createdJfs));

    jfrCfg.jfc = &fixture.jfc.v_jfc;
    jfrCfg.depth = 4;
    jfrCfg.max_sge = 1;
    jfrCfg.trans_mode = URMA_TM_RC;
    urma_test::SetHwMockIoctl(true, 0xb20, 0xb200);
    urma_jfr_t *createdJfr = bondp_create_jfr(&fixture.ctx.v_ctx, &jfrCfg);
    ASSERT_NE(nullptr, createdJfr);
    createdJfr->async_events_acked = 0;
    SetRefCount(&CONTAINER_OF_FIELD(createdJfr, bondp_comp_t, v_jfr)->use_cnt, 0);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_jfr(createdJfr));

    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, PublicCreateAndDeleteJettyCoverVirtualPhysicalIdMapping)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_jetty_cfg_t jettyCfg = {};

    fixture.InitSinglePhysicalMember();
    fixture.InitActiveComp(&fixture.jfr, 0);
    fixture.ctx.v_ctx.dev_fd = 7;
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 16));

    fixture.jfr.v_jfr.jfr_cfg.jfc = &fixture.jfc.v_jfc;
    fixture.jfr.v_jfr.jfr_cfg.depth = 4;
    fixture.jfr.v_jfr.jfr_cfg.max_sge = 1;
    fixture.jfr.v_jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.jfr.v_jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
    fixture.phyJfr.jfr_cfg = fixture.jfr.v_jfr.jfr_cfg;

    jettyCfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    jettyCfg.jfs_cfg.jfc = &fixture.jfc.v_jfc;
    jettyCfg.jfs_cfg.depth = 4;
    jettyCfg.jfs_cfg.max_sge = 1;
    jettyCfg.jfs_cfg.max_rsge = 1;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_OL;
    jettyCfg.shared.jfr = &fixture.jfr.v_jfr;
    jettyCfg.shared.jfc = &fixture.jfc.v_jfc;

    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = false;
    g_bondp_global_ctx = &fakeGlobal;
    urma_test::SetHwMockIoctl(true, 0xb50, 0xb500);
    urma_jetty_t *createdJetty = bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg);
    ASSERT_NE(nullptr, createdJetty);
    EXPECT_EQ(0xb50U, createdJetty->jetty_id.id);
    createdJetty->async_events_acked = 0;
    SetRefCount(&CONTAINER_OF_FIELD(createdJetty, bondp_comp_t, v_jetty)->use_cnt, 0);
    EXPECT_EQ(URMA_SUCCESS, bondp_delete_jetty(createdJetty));

    g_bondp_global_ctx = nullptr;
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, PublicCreateApisCleanupIdMappingAfterLateWrBufferFailures)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    urma_jfs_cfg_t jfsCfg = {};
    urma_jfr_cfg_t jfrCfg = {};
    urma_jetty_cfg_t jettyCfg = {};

    fixture.InitSinglePhysicalMember();
    fixture.InitActiveComp(&fixture.jfr, 0);
    fixture.ctx.v_ctx.dev_fd = 7;
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 16));

    /*
     * The calloc mock is scoped to nmemb=4, which is the wr_buf entry count here.
     * Earlier object allocations use nmemb=1 and stay on the normal mocked path.
     */
    jfsCfg.jfc = &fixture.jfc.v_jfc;
    jfsCfg.depth = 4;
    jfsCfg.max_sge = 1;
    jfsCfg.max_rsge = 1;
    jfsCfg.trans_mode = URMA_TM_RC;
    urma_test::SetHwMockIoctl(true, 0xb60, 0xb600);
    g_mockCallocFailNmemb = 4;
    EXPECT_EQ(nullptr, bondp_create_jfs(&fixture.ctx.v_ctx, &jfsCfg));
    g_mockCallocFailNmemb = 0;

    jfrCfg.jfc = &fixture.jfc.v_jfc;
    jfrCfg.depth = 4;
    jfrCfg.max_sge = 1;
    jfrCfg.trans_mode = URMA_TM_RC;
    urma_test::SetHwMockIoctl(true, 0xb61, 0xb610);
    g_mockCallocFailNmemb = 4;
    EXPECT_EQ(nullptr, bondp_create_jfr(&fixture.ctx.v_ctx, &jfrCfg));
    g_mockCallocFailNmemb = 0;

    fixture.jfr.v_jfr.jfr_cfg.jfc = &fixture.jfc.v_jfc;
    fixture.jfr.v_jfr.jfr_cfg.depth = 4;
    fixture.jfr.v_jfr.jfr_cfg.max_sge = 1;
    fixture.jfr.v_jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.jfr.v_jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
    fixture.phyJfr.jfr_cfg = fixture.jfr.v_jfr.jfr_cfg;
    jettyCfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    jettyCfg.jfs_cfg.jfc = &fixture.jfc.v_jfc;
    jettyCfg.jfs_cfg.depth = 1;
    jettyCfg.jfs_cfg.max_sge = 1;
    jettyCfg.jfs_cfg.max_rsge = 1;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_OL;
    jettyCfg.shared.jfr = &fixture.jfr.v_jfr;
    jettyCfg.shared.jfc = &fixture.jfc.v_jfc;

    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = false;
    g_bondp_global_ctx = &fakeGlobal;
    urma_test::SetHwMockIoctl(true, 0xb62, 0xb620);
    g_mockCallocFailNmemb = 4;
    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg));
    g_mockCallocFailNmemb = 0;
    g_bondp_global_ctx = nullptr;
    bondp_health_check_global_ctx_uninit(&fakeGlobal);

    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
}

TEST(UrmaBondTest, PublicCreateJettyHonorsExplicitPortIds)
{
    BondPublicApiFixture fixture;
    bondp_global_context_t fakeGlobal = {};
    bondp_jetty_cfg_t jettyCfg = {};
    urma_jfs_cfg_t jfsCfg = {};
    urma_jfr_cfg_t jfrCfg = {};
    bondp_port_id_t portId = {};

    fixture.InitSinglePhysicalMember();
    fixture.InitActiveComp(&fixture.jfr, 0);
    fixture.ctx.v_ctx.dev_fd = 7;
    ASSERT_EQ(0, bdp_p_vjetty_id_table_create(&fixture.ctx.p_vjetty_id_table, 16));

    jfsCfg.jfc = &fixture.jfc.v_jfc;
    jfsCfg.depth = 4;
    jfsCfg.max_sge = 1;
    jfsCfg.max_rsge = 1;
    jfsCfg.trans_mode = URMA_TM_RC;
    jfrCfg.jfc = &fixture.jfc.v_jfc;
    jfrCfg.depth = 4;
    jfrCfg.max_sge = 1;
    jfrCfg.trans_mode = URMA_TM_RC;
    fixture.jfr.v_jfr.jfr_cfg = jfrCfg;
    fixture.phyJfr.jfr_cfg = jfrCfg;
    portId.chip_id = 1;
    portId.port_idx = UINT8_MAX;

    jettyCfg.base.flag.bs.share_jfr = URMA_SHARE_JFR;
    jettyCfg.base.flag.bs.has_drv_ext = 1;
    jettyCfg.base.jfs_cfg = jfsCfg;
    jettyCfg.base.shared.jfr = &fixture.jfr.v_jfr;
    jettyCfg.base.shared.jfc = &fixture.jfc.v_jfc;
    jettyCfg.port_ids = &portId;
    jettyCfg.port_count = 1;

    bondp_health_check_global_ctx_init(&fakeGlobal);
    fakeGlobal.health_thread_ctx.enable_health_check = false;
    g_bondp_global_ctx = &fakeGlobal;
    urma_test::SetHwMockIoctl(true, 0xb40, 0xb400);
    EXPECT_EQ(nullptr, bondp_create_jetty(&fixture.ctx.v_ctx, &jettyCfg.base));
    g_bondp_global_ctx = nullptr;
    bondp_health_check_global_ctx_uninit(&fakeGlobal);
    EXPECT_EQ(0, bdp_p_vjetty_id_table_destroy(&fixture.ctx.p_vjetty_id_table));
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
    fixture.ctx.msn_enable = true;
    EXPECT_EQ(URMA_EAGAIN,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_DISABLE_MSN, nullptr, 0, &unusedOut));
    EXPECT_TRUE(fixture.ctx.msn_enable);

    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    EXPECT_EQ(-EINVAL, CallBondUserCtl(nullptr, BONDP_USER_CTL_ENABLE_SEG_CACHE, nullptr, 0, &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, nullptr,
        sizeof(legacyMode), &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, &legacyMode,
        sizeof(legacyMode) - 1, &unusedOut));
    legacyMode = static_cast<urma_context_aggr_mode_t>(URMA_AGGR_MODE_BALANCE + 1);
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, &legacyMode,
        sizeof(legacyMode), &unusedOut));
    legacyMode = URMA_AGGR_MODE_BALANCE;
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE_LEGACY, &legacyMode,
        sizeof(legacyMode), &unusedOut));

    modeIn.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    modeIn.bonding_level = BONDP_BONDING_LEVEL_IODIE;
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE, nullptr,
        sizeof(modeIn), &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE, &modeIn,
        sizeof(modeIn) - 1, &unusedOut));
    modeIn.bonding_mode = BONDP_BONDING_MODE_MAX;
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_MODE, &modeIn,
        sizeof(modeIn), &unusedOut));
    modeIn.bonding_mode = BONDP_BONDING_MODE_BALANCE;
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
    out = MakeUserCtlOut(&queryOut, sizeof(queryOut) - 1);
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

    out = MakeUserCtlOut(nullptr, sizeof(fdOut));
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    out = MakeUserCtlOut(&fdOut, sizeof(fdOut) - 1);
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    out = MakeUserCtlOut(&fdOut, sizeof(fdOut));
    fdIn.jfce = nullptr;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_GET_JFCE_FD_LIST, &fdIn, sizeof(fdIn), &out));
    fixture.jfce.bondp_ctx = &fixture.otherBondCtx;
    fdIn.jfce = &fixture.jfce.v_jfce;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_GET_JFCE_FD_LIST, &fdIn, sizeof(fdIn), &out));
}

TEST(UrmaBondTest, PublicUserCtlGetRjettyAndSegCtxUseMockIoctl)
{
    BondPublicApiFixture fixture;
    bondp_import_tseg_t inputTseg = {};
    urma_target_seg_t physicalSeg = {};
    urma_rjetty_t *rjetty = nullptr;
    urma_seg_t *seg = nullptr;
    urma_user_ctl_out_t out = {};

    fixture.ctx.v_ctx.dev_fd = 7;
    fixture.ctx.enabled_count = 1;
    fixture.ctx.enabled_indices[0] = 0;
    fixture.InitSinglePhysicalMember();
    fixture.InitActiveComp(&fixture.jetty, 0);
    fixture.jetty.v_jetty.jetty_id = MakeJettyId(0xa01);
    fixture.jetty.v_jetty.jetty_id.eid = MakeEid(0xa02);

    bondp_topo_node_t topo[2] = {};
    topo[0].is_current = true;
    CopyEidToTopo(topo[0].agg_devs[0].agg_eid, MakeEid(0xa03));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].primary_eid, MakeEid(0xa04));
    CopyEidToTopo(topo[0].agg_devs[0].ues[0].port_eid[0], MakeEid(0xa05));
    CopyEidToTopo(topo[1].agg_devs[0].agg_eid, fixture.jetty.v_jetty.jetty_id.eid);
    topo[1].links[0][0] = true;
    fixture.ctx.topo_map = create_topo_map(topo, 2);
    ASSERT_NE(nullptr, fixture.ctx.topo_map);

    out = MakeUserCtlOut(&rjetty, sizeof(rjetty));
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_GET_RJETTY,
                                 &fixture.jetty.v_jetty, sizeof(fixture.jetty.v_jetty), &out));
    ASSERT_NE(nullptr, rjetty);
    EXPECT_TRUE(rjetty->flag.bs.has_user_info != 0);
    auto *jettyPrivExt = bondp_rjetty_get_priv_ext(rjetty);
    EXPECT_EQ(sizeof(urma_bond_jetty_ext_v0_t) + 1 + sizeof(bondp_rjetty_target_ctx_t),
        jettyPrivExt->len);
    auto *jettyExt = reinterpret_cast<urma_bond_jetty_ext_v0_t *>(jettyPrivExt->data);
    EXPECT_EQ(BONDP_RJETTY_EXT_VERSION_V0, jettyExt->version);
    EXPECT_EQ(1U, jettyExt->local_ctx_cnt);
    EXPECT_EQ(1U, jettyExt->target_ctx_cnt);
    EXPECT_NE(0U, jettyExt->mask & BONDP_RJETTY_EXT_MASK_CONNECTED_BITMAP);
    EXPECT_NE(0U, jettyExt->connected_bitmap[0] & 0x1U);
    auto *targetEntry = reinterpret_cast<bondp_rjetty_target_ctx_t *>(jettyExt->data + 1);
    EXPECT_EQ(0U, targetEntry->target_idx);
    std::free(rjetty);

    inputTseg.v_tseg.urma_ctx = &fixture.ctx.v_ctx;
    physicalSeg.seg.token_id = 0x55;
    inputTseg.p_tseg[0][0] = &physicalSeg;
    out = MakeUserCtlOut(&seg, sizeof(seg));
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_GET_SEG_CTX,
                                 &inputTseg.v_tseg, sizeof(inputTseg.v_tseg), &out));
    ASSERT_NE(nullptr, seg);
    EXPECT_TRUE(bondp_seg_has_user_info(seg));
    auto *segPrivExt = bondp_seg_get_priv_ext(seg);
    EXPECT_EQ(sizeof(urma_bond_seg_ext_t), segPrivExt->len);
    auto *segExt = reinterpret_cast<urma_bond_seg_ext_t *>(segPrivExt->data);
    EXPECT_EQ(0x55U, segExt->peer_p_seg[0].token_id);
    EXPECT_TRUE(segExt->connected[0][0]);
    std::free(seg);
    delete_topo_map(fixture.ctx.topo_map);
    fixture.ctx.topo_map = nullptr;
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

TEST(UrmaBondTest, PublicJettyBindUsesPhysicalTargetsAndRollsBackFailures)
{
    BondPublicApiFixture fixture;
    urma_target_jetty_t phyTarget[2] = {};

    fixture.InitActiveComp(&fixture.jetty, 0);
    fixture.targetJetty.active_count = 2;
    fixture.targetJetty.active_indices[0] = 0;
    fixture.targetJetty.active_indices[1] = 1;
    fixture.jetty.active_count = 2;
    fixture.jetty.active_indices[0] = 0;
    fixture.jetty.active_indices[1] = 1;
    fixture.jetty.p_jetty[0] = &fixture.phyJetty[0];
    fixture.jetty.p_jetty[1] = &fixture.phyJetty[1];
    fixture.targetJetty.p_tjetty[0][0] = &phyTarget[0];
    fixture.targetJetty.p_tjetty[1][1] = &phyTarget[1];

    EXPECT_EQ(URMA_SUCCESS, bondp_bind_jetty(&fixture.jetty.v_jetty, &fixture.targetJetty.v_tjetty));
    EXPECT_EQ(&fixture.targetJetty.v_tjetty, fixture.jetty.v_jetty.remote_jetty);
    EXPECT_EQ(2, urma_test::GetHwMockState().bindJettyCount);
    EXPECT_EQ(3UL, fixture.targetJetty.use_cnt.atomic_cnt.load());

    EXPECT_EQ(URMA_SUCCESS, bondp_unbind_jetty(&fixture.jetty.v_jetty));
    EXPECT_EQ(nullptr, fixture.jetty.v_jetty.remote_jetty);
    EXPECT_EQ(2UL, fixture.targetJetty.use_cnt.atomic_cnt.load());

    urma_test::ResetHwMockState();
    urma_test::SetHwMockBindJettyFailAt(2);
    EXPECT_EQ(URMA_FAIL, bondp_bind_jetty(&fixture.jetty.v_jetty, &fixture.targetJetty.v_tjetty));
    EXPECT_EQ(nullptr, fixture.phyJetty[0].remote_jetty);
    EXPECT_EQ(1, urma_test::GetHwMockState().unbindJettyCount);
}
