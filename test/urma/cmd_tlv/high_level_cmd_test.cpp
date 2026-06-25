/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA high-level command wrapper unit tests.
 */

#include "cmd_tlv_fixture.h"

using namespace urma_cmd_tlv_test;

TEST(UrmaCmdTlvTest, HighLevelJettyCommandWrappersPropagateIoctlResults)
{
    urma_context_t ctx = {};
    urma_jetty_t firstJetty = {};
    urma_jetty_t secondJetty = {};
    urma_jetty_t *jettyArr[] = { &firstJetty, &secondJetty };
    urma_jetty_t *badJetty = nullptr;
    urma_jetty_grp_t jettyGrp = {};

    InitCmdContext(&ctx);
    firstJetty.urma_ctx = &ctx;
    firstJetty.handle = 0x1001;
    secondJetty.urma_ctx = &ctx;
    secondJetty.handle = 0x1002;

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_delete_jetty_batch(jettyArr, 2, &badJetty));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_DELETE_JETTY_BATCH);
    EXPECT_EQ(nullptr, badJetty);

    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);
    EXPECT_EQ(-1, urma_cmd_delete_jetty_batch(jettyArr, 2, &badJetty));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_DELETE_JETTY_BATCH);
    EXPECT_EQ(&firstJetty, badJetty);

    ASSERT_EQ(0, pthread_mutex_init(&jettyGrp.event_mutex, nullptr));
    ASSERT_EQ(0, pthread_cond_init(&jettyGrp.event_cond, nullptr));
    jettyGrp.urma_ctx = &ctx;
    jettyGrp.handle = 0x2001;

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_delete_jetty_grp(&jettyGrp));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_DESTROY_JETTY_GRP);

    pthread_cond_destroy(&jettyGrp.event_cond);
    pthread_mutex_destroy(&jettyGrp.event_mutex);
}

TEST(UrmaCmdTlvTest, HighLevelMiscCommandWrappersEmitExpectedHeaders)
{
    urma_context_t ctx = {};
    urma_net_addr_info_t addrInfo[2] = {};
    uint32_t addrCnt = 0;
    urma_tp_cfg_t tpCfg = {};
    urma_tp_attr_t tpAttr = {};
    urma_tp_attr_mask_t tpMask = {};
    struct urma_sysfs_dev sysfsDev = {};
    urma_net_addr_t netAddr = {};
    urma_eid_t eid = {};
    uint8_t mac[URMA_MAC_BYTES] = {};

    InitCmdContext(&ctx);
    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_get_net_addr_list(&ctx, 2, addrInfo, &addrCnt));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_NETADDR_LIST);
    EXPECT_EQ(0U, addrCnt);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_modify_tp(&ctx, 0x33, &tpCfg, &tpAttr, tpMask));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_MODIFY_TP);

    std::strncpy(sysfsDev.dev_name, "mock_ub", sizeof(sysfsDev.dev_name) - 1);
    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_query_device_attr(urma_test::MOCK_IOCTL_FD, &sysfsDev));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_QUERY_DEV_ATTR);

    netAddr.sin_family = AF_INET;
    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_get_eid_by_ip(&ctx, &netAddr, &eid));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_EID_BY_IP);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_get_ip_by_eid(&ctx, &eid, &netAddr));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_IP_BY_EID);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_get_smac(&ctx, mac));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_SMAC);

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_get_dmac(&ctx, &netAddr, mac));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_DMAC);
}

TEST(UrmaCmdTlvTest, HighLevelMiscCommandWrappersPropagateIoctlFailure)
{
    urma_context_t ctx = {};
    urma_tp_cfg_t tpCfg = {};
    urma_tp_attr_t tpAttr = {};
    urma_tp_attr_mask_t tpMask = {};
    urma_net_addr_t netAddr = {};
    urma_eid_t eid = {};
    uint8_t mac[URMA_MAC_BYTES] = {};

    InitCmdContext(&ctx);
    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);
    EXPECT_EQ(-1, urma_cmd_modify_tp(&ctx, 0x33, &tpCfg, &tpAttr, tpMask));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_MODIFY_TP);

    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);
    EXPECT_EQ(-1, urma_cmd_get_eid_by_ip(&ctx, &netAddr, &eid));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_EID_BY_IP);

    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);
    EXPECT_EQ(-1, urma_cmd_get_ip_by_eid(&ctx, &eid, &netAddr));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_IP_BY_EID);

    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);
    EXPECT_EQ(-1, urma_cmd_get_smac(&ctx, mac));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_SMAC);

    ResetIoctlCapture();
    SetIoctlFailure(-1, EINVAL);
    EXPECT_EQ(-1, urma_cmd_get_dmac(&ctx, &netAddr, mac));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_GET_DMAC);
}

TEST(UrmaCmdTlvTest, HighLevelJfcLifecycleHelpersAreReached)
{
    urma_context_t ctx = {};
    urma_jfc_cfg_t cfg = {};
    urma_jfc_t allocatedJfc = {};
    urma_jfc_t activeJfc = {};
    urma_jfc_t ackJfc = {};
    urma_jfc_t *ackList[] = { &ackJfc };
    uint32_t nevents[] = { 3 };

    InitCmdContext(&ctx);
    cfg.depth = 4;

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_alloc_jfc(&ctx, &cfg, &allocatedJfc, nullptr));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_ALLOC_JFC);
    EXPECT_EQ(&ctx, allocatedJfc.urma_ctx);
    pthread_cond_destroy(&allocatedJfc.event_cond);
    pthread_mutex_destroy(&allocatedJfc.event_mutex);

    activeJfc.urma_ctx = &ctx;
    activeJfc.handle = 0x3030;
    activeJfc.jfc_cfg = cfg;
    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_active_jfc(&activeJfc, nullptr));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_ACTIVE_JFC);
    EXPECT_EQ(&ctx, activeJfc.urma_ctx);
    pthread_cond_destroy(&activeJfc.event_cond);
    pthread_mutex_destroy(&activeJfc.event_mutex);

    ASSERT_EQ(0, pthread_mutex_init(&ackJfc.event_mutex, nullptr));
    ASSERT_EQ(0, pthread_cond_init(&ackJfc.event_cond, nullptr));
    urma_cmd_ack_jfc(ackList, nevents, 1);
    EXPECT_EQ(3U, ackJfc.comp_events_acked);
    pthread_cond_destroy(&ackJfc.event_cond);
    pthread_mutex_destroy(&ackJfc.event_mutex);
}

TEST(UrmaCmdTlvTest, HighLevelDeleteContextDestroysInitializedMutex)
{
    urma_context_t ctx = {};

    InitCmdContext(&ctx);
    ctx.async_fd = -1;
    ASSERT_EQ(0, pthread_mutex_init(&ctx.mutex, nullptr));
    EXPECT_EQ(0, urma_cmd_delete_context(&ctx));
}

TEST(UrmaCmdTlvTest, HighLevelCreateContextInitializesContextWithoutSysfs)
{
    urma_context_t ctx = {};
    urma_device_t dev = {};
    urma_ops_t ops = {};
    urma_context_cfg_t cfg = {};

    cfg.dev = &dev;
    cfg.ops = &ops;
    cfg.dev_fd = urma_test::MOCK_IOCTL_FD;
    cfg.eid_index = 2;
    cfg.uasid = 0x77;

    ResetIoctlCapture();
    EXPECT_EQ(0, urma_cmd_create_context(&ctx, &cfg, nullptr));
    ExpectCapturedHeader(static_cast<unsigned long>(URMA_CMD), URMA_CMD_CREATE_CTX);
    EXPECT_EQ(&dev, ctx.dev);
    EXPECT_EQ(&ops, ctx.ops);
    EXPECT_EQ(2U, ctx.eid_index);
    EXPECT_EQ(0x77U, ctx.uasid);

    ctx.async_fd = -1;
    EXPECT_EQ(0, urma_cmd_delete_context(&ctx));
}
