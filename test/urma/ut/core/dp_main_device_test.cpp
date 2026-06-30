/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core datapath, main and device unit tests.
 */

#include "core_fixture.h"

using namespace urma_test_core;

TEST(UrmaCoreTest, DpApiWrappersValidateInputsAndDispatchOps)
{
    CoreApiFixture fixture;
    urma_jfs_wr_flag_t flag = {};
    urma_target_seg_t srcSeg = {};
    urma_target_seg_t dstSeg = {};
    urma_cr_t cr = {};
    urma_jfs_wr_t sendWr = {};
    urma_jfs_wr_t *badSend = nullptr;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;
    urma_jfc_t *jfcList[1] = { &fixture.jfc };
    uint32_t nevents[1] = { 1 };

    EXPECT_EQ(URMA_EINVAL, urma_write(nullptr, &fixture.tjfr, &dstSeg, &srcSeg, 1, 2, 4, flag, 0));
    EXPECT_EQ(URMA_EINVAL, urma_write(&fixture.jfs, nullptr, &dstSeg, &srcSeg, 1, 2, 4, flag, 0));
    fixture.ops.post_jfs_wr = MockPostJfsWr;
    EXPECT_EQ(URMA_SUCCESS, urma_write(&fixture.jfs, &fixture.tjfr, &dstSeg, nullptr, 1, 0, 4, flag, 0));
    EXPECT_EQ(URMA_EINVAL, urma_read(&fixture.jfs, &fixture.tjfr, &dstSeg, nullptr, 1, 2, 4, flag, 0));
    EXPECT_EQ(URMA_SUCCESS, urma_read(&fixture.jfs, &fixture.tjfr, &dstSeg, &srcSeg, 1, 2, 4, flag, 0));
    EXPECT_EQ(URMA_EINVAL, urma_send(&fixture.jfs, nullptr, &srcSeg, 2, 4, flag, 0));
    EXPECT_EQ(URMA_EINVAL, urma_send(&fixture.jfs, &fixture.tjfr, nullptr, 2, 4, flag, 0));
    EXPECT_EQ(URMA_SUCCESS, urma_send(&fixture.jfs, &fixture.tjfr, &srcSeg, 2, 4, flag, 0));

    EXPECT_EQ(URMA_EINVAL, urma_recv(nullptr, &srcSeg, 1, 4, 0));
    EXPECT_EQ(URMA_EINVAL, urma_recv(&fixture.jfr, nullptr, 1, 4, 0));
    fixture.ops.post_jfr_wr = MockPostJfrWr;
    EXPECT_EQ(URMA_FAIL, urma_recv(&fixture.jfr, &srcSeg, 0, 4, 0));
    EXPECT_EQ(URMA_SUCCESS, urma_recv(&fixture.jfr, &srcSeg, 1, 4, 0));

    EXPECT_EQ(-1, urma_poll_jfc(nullptr, 1, &cr));
    EXPECT_EQ(-1, urma_poll_jfc(&fixture.jfc, -1, &cr));
    EXPECT_EQ(-1, urma_poll_jfc(&fixture.jfc, 1, nullptr));
    fixture.ops.poll_jfc = MockPollJfc;
    EXPECT_EQ(1, urma_poll_jfc(&fixture.jfc, 1, &cr));

    EXPECT_EQ(URMA_EINVAL, urma_rearm_jfc(nullptr, false));
    fixture.ops.rearm_jfc = MockRearmJfc;
    EXPECT_EQ(URMA_SUCCESS, urma_rearm_jfc(&fixture.jfc, false));

    EXPECT_EQ(-1, urma_wait_jfc(nullptr, 1, 0, jfcList));
    EXPECT_EQ(-1, urma_wait_jfc(&fixture.jfce, 0, 0, jfcList));
    EXPECT_EQ(-1, urma_wait_jfc(&fixture.jfce, 1, 0, nullptr));
    fixture.ops.wait_jfc = MockWaitJfc;
    EXPECT_EQ(1, urma_wait_jfc(&fixture.jfce, 1, 0, jfcList));
    urma_ack_jfc(nullptr, nevents, 1);
    urma_ack_jfc(jfcList, nullptr, 1);
    fixture.ops.ack_jfc = MockAckJfc;
    urma_ack_jfc(jfcList, nevents, 1);

    EXPECT_EQ(URMA_EINVAL, urma_post_jfs_wr(nullptr, &sendWr, &badSend));
    EXPECT_EQ(URMA_EINVAL, urma_post_jfs_wr(&fixture.jfs, nullptr, &badSend));
    EXPECT_EQ(URMA_EINVAL, urma_post_jfs_wr(&fixture.jfs, &sendWr, nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_post_jfs_wr(&fixture.jfs, &sendWr, &badSend));

    EXPECT_EQ(URMA_EINVAL, urma_post_jfr_wr(nullptr, &recvWr, &badRecv));
    EXPECT_EQ(URMA_EINVAL, urma_post_jfr_wr(&fixture.jfr, nullptr, &badRecv));
    EXPECT_EQ(URMA_EINVAL, urma_post_jfr_wr(&fixture.jfr, &recvWr, nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_post_jfr_wr(&fixture.jfr, &recvWr, &badRecv));

    fixture.ops.post_jetty_send_wr = MockPostJettySendWr;
    fixture.ops.post_jetty_recv_wr = MockPostJettyRecvWr;
    EXPECT_EQ(URMA_EINVAL, urma_post_jetty_send_wr(nullptr, &sendWr, &badSend));
    EXPECT_EQ(URMA_SUCCESS, urma_post_jetty_send_wr(&fixture.jetty, &sendWr, &badSend));
    EXPECT_EQ(URMA_EINVAL, urma_post_jetty_recv_wr(&fixture.jetty, nullptr, &badRecv));
    EXPECT_EQ(URMA_SUCCESS, urma_post_jetty_recv_wr(&fixture.jetty, &recvWr, &badRecv));
}

TEST(UrmaCoreTest, FormatConvertAndDpErrorBranchesCoverStableContracts)
{
    CoreApiFixture fixture;
    urma_eid_t eid = {};
    urma_jfs_wr_flag_t flag = {};
    urma_target_seg_t srcSeg = {};
    urma_sge_t invalidSge = {};
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;
    urma_jfc_t *jfcList[1] = { &fixture.jfc };
    uint32_t nevents[1] = { 1 };

    EXPECT_EQ(-EINVAL, urma_str_to_eid(nullptr, &eid));
    EXPECT_EQ(-EINVAL, urma_str_to_eid("1", &eid));
    EXPECT_EQ(-EINVAL, urma_str_to_eid("not-an-eid", &eid));
    EXPECT_EQ(0, urma_str_to_eid("192.168.10.1", &eid));
    EXPECT_EQ(0, urma_str_to_eid("2001:db8::1", &eid));
    EXPECT_EQ(0, urma_str_to_eid("0x12345", &eid));

    EXPECT_EQ(URMA_EINVAL, urma_send(&fixture.jfs, &fixture.tjfr, &srcSeg, 2, 4, flag, 0));

    fixture.ops.post_jfr_wr = MockPostJfrWr;
    recvWr.src.num_sge = 1;
    recvWr.src.sge = &invalidSge;
    EXPECT_EQ(URMA_EINVAL, urma_post_jfr_wr(&fixture.jfr, &recvWr, &badRecv));

    urma_ack_jfc(jfcList, nevents, 1);
}

TEST(UrmaCoreTest, DpApiProviderReturnValuesPropagateForWrAndCompletion)
{
    CoreApiFixture fixture;
    urma_jfs_wr_t sendWr = {};
    urma_jfs_wr_t *badSend = nullptr;
    urma_jfr_wr_t recvWr = {};
    urma_jfr_wr_t *badRecv = nullptr;
    urma_cr_t cr = {};
    urma_jfc_t *jfcList[1] = { &fixture.jfc };

    fixture.InstallMockOps();
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    urma_test::SetHwMockBadWr(&sendWr, &recvWr);

    EXPECT_EQ(URMA_EAGAIN, urma_post_jfs_wr(&fixture.jfs, &sendWr, &badSend));
    EXPECT_EQ(&sendWr, badSend);
    EXPECT_EQ(URMA_EAGAIN, urma_post_jfr_wr(&fixture.jfr, &recvWr, &badRecv));
    EXPECT_EQ(&recvWr, badRecv);
    badSend = nullptr;
    badRecv = nullptr;
    EXPECT_EQ(URMA_EAGAIN, urma_post_jetty_send_wr(&fixture.jetty, &sendWr, &badSend));
    EXPECT_EQ(&sendWr, badSend);
    EXPECT_EQ(URMA_EAGAIN, urma_post_jetty_recv_wr(&fixture.jetty, &recvWr, &badRecv));
    EXPECT_EQ(&recvWr, badRecv);

    urma_test::SetHwMockIntReturn(-EIO);
    EXPECT_EQ(-EIO, urma_poll_jfc(&fixture.jfc, 1, &cr));
    EXPECT_EQ(-EIO, urma_wait_jfc(&fixture.jfce, 1, 0, jfcList));
    EXPECT_EQ(URMA_EAGAIN, urma_rearm_jfc(&fixture.jfc, false));
}

TEST(UrmaCoreTest, CoreAsyncEventAndUserCtlPropagateProviderResults)
{
    CoreApiFixture fixture;
    urma_async_event_t event = {};
    urma_user_ctl_in_t ctlIn = {};
    urma_user_ctl_out_t ctlOut = {};

    fixture.InstallMockOps();
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, urma_get_async_event(&fixture.ctx, &event));

    urma_test::SetHwMockStatus(URMA_SUCCESS);
    event.urma_ctx = &fixture.ctx;
    EXPECT_EQ(0, urma_test::GetHwMockState().ackAsyncCount);
    urma_ack_async_event(&event);
    EXPECT_EQ(1, urma_test::GetHwMockState().ackAsyncCount);

    urma_test::GetHwMockState().userCtlReturn = URMA_ENOPERM;
    EXPECT_EQ(URMA_ENOPERM, urma_user_ctl(&fixture.ctx, &ctlIn, &ctlOut));
}

TEST(UrmaCoreTest, MainApisValidateProviderContextAndDeviceContracts)
{
    CoreApiFixture fixture;
    urma_provider_ops_t provider = {};
    urma_provider_ops_t badProvider = {};
    urma_context_aggr_mode_t aggrMode = URMA_AGGR_MODE_ACTIVE_BACKUP;
    uint32_t uasid = 0;
    int deviceNum = 7;
    urma_device_t **deviceList = nullptr;
    char longName[URMA_MAX_NAME + 1] = {};
    char bondingName[URMA_MAX_NAME] = "bonding_dev0";
    char normalName[URMA_MAX_NAME] = "core_ut";
    urma_device_t noSysfsDev = fixture.dev;
    urma_device_t noEidDev = fixture.dev;
    urma_sysfs_dev_t noEidSysfs = fixture.sysfsDev;

    EXPECT_EQ(URMA_SUCCESS, urma_uninit());
    urma_status_t initRet = urma_init(nullptr);
    EXPECT_TRUE(initRet == URMA_SUCCESS || initRet == URMA_FAIL || initRet == URMA_EEXIST);
    if (initRet == URMA_SUCCESS) {
        deviceList = urma_get_device_list(&deviceNum);
        EXPECT_TRUE(deviceList == nullptr || deviceNum >= 0);
        urma_free_device_list(deviceList);
        EXPECT_EQ(URMA_SUCCESS, urma_uninit());
    }
    EXPECT_EQ(nullptr, urma_get_device_list(nullptr));
    deviceList = static_cast<urma_device_t **>(calloc(1, sizeof(*deviceList)));
    ASSERT_NE(nullptr, deviceList);
    urma_free_device_list(deviceList);
    urma_free_device_list(nullptr);
    EXPECT_EQ(nullptr, urma_get_eid_list(nullptr, &uasid));
    EXPECT_EQ(nullptr, urma_get_eid_list(&fixture.dev, nullptr));
    EXPECT_EQ(nullptr, urma_get_eid_list(&fixture.dev, &uasid));
    noSysfsDev.sysfs_dev = nullptr;
    EXPECT_EQ(nullptr, urma_get_eid_list(&noSysfsDev, &uasid));
    noEidSysfs.dev_attr.dev_cap.max_eid_cnt = 0;
    noEidDev.sysfs_dev = &noEidSysfs;
    EXPECT_EQ(nullptr, urma_get_eid_list(&noEidDev, &uasid));
    urma_free_eid_list(nullptr);
    EXPECT_EQ(URMA_EINVAL, urma_query_device(nullptr, &fixture.sysfsDev.dev_attr));
    EXPECT_EQ(URMA_EINVAL, urma_query_device(&fixture.dev, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_query_device(&noSysfsDev, &fixture.sysfsDev.dev_attr));
    EXPECT_EQ(nullptr, urma_get_device_by_name(nullptr));
    (void)memset(longName, 'a', sizeof(longName));
    EXPECT_EQ(nullptr, urma_get_device_by_name(longName));
    EXPECT_EQ(nullptr, urma_get_device_by_eid({}, URMA_TRANSPORT_MAX));
    EXPECT_EQ(-1, urma_open_cdev(const_cast<char *>("/tmp/urma_core_ut_missing_cdev")));
    EXPECT_EQ(nullptr, urma_create_context(nullptr, 0));
    EXPECT_EQ(URMA_EINVAL, urma_delete_context(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_set_context_opt(nullptr, URMA_OPT_AGGR_MODE, &aggrMode, sizeof(aggrMode)));
    EXPECT_EQ(URMA_EINVAL, urma_get_uasid(nullptr));
    EXPECT_EQ(-1, urma_register_sysfs_dev(nullptr));
    EXPECT_EQ(-1, urma_register_sysfs_dev(&fixture.sysfsDev));
    EXPECT_TRUE(urma_is_bonding_dev(bondingName));
    EXPECT_FALSE(urma_is_bonding_dev(normalName));

    EXPECT_EQ(-1, urma_register_provider_ops(nullptr));
    EXPECT_EQ(-1, urma_register_provider_ops(&badProvider));
    provider.name = "core_ut_provider";
    provider.get_uasid = MockProviderGetUasid;
    EXPECT_EQ(0, urma_register_provider_ops(&provider));
    EXPECT_EQ(URMA_SUCCESS, urma_get_uasid(&uasid));
    EXPECT_EQ(0x5a5aU, uasid);
    EXPECT_EQ(0, urma_unregister_provider_ops(&provider));

    fixture.dev.ops = &provider;
    provider.name = "core_ut_provider";
    EXPECT_EQ(nullptr, urma_create_context(&fixture.dev, 0));
    fixture.sysfsDev.flag = URMA_SYSFS_DEV_FLAG_DRIVER_CREATED;
    provider.create_context = MockProviderCreateContext;
    urma_context_t *ctx = urma_create_context(&fixture.dev, 3);
    ASSERT_NE(nullptr, ctx);
    EXPECT_EQ(3U, ctx->eid_index);
    EXPECT_EQ(URMA_AGGR_MODE_STANDALONE, ctx->aggr_mode);
    ctx->ref.atomic_cnt.store(2);
    provider.delete_context = MockProviderDeleteContext;
    EXPECT_EQ(URMA_EAGAIN, urma_delete_context(ctx));
    ctx->ref.atomic_cnt.store(1);
    EXPECT_EQ(URMA_SUCCESS, urma_delete_context(ctx));
    provider.delete_context = MockProviderDeleteContextBusy;
    EXPECT_EQ(URMA_FAIL, urma_delete_context(ctx));

    provider.name = "not_ub_agg";
    EXPECT_EQ(URMA_EINVAL, urma_set_context_opt(&fixture.ctx, URMA_OPT_AGGR_MODE, &aggrMode, sizeof(aggrMode)));
    provider.name = "ub_agg";
    fixture.dev.ops = &provider;
    EXPECT_EQ(URMA_EINVAL, urma_set_context_opt(&fixture.ctx, URMA_OPT_AGGR_MODE, nullptr, sizeof(aggrMode)));
    EXPECT_EQ(URMA_EINVAL, urma_set_context_opt(&fixture.ctx, URMA_OPT_AGGR_MODE, &aggrMode, sizeof(uint8_t)));
    fixture.ops.user_ctl = MockUserCtl;
    EXPECT_EQ(URMA_ENOPERM, urma_set_context_opt(&fixture.ctx, URMA_OPT_AGGR_MODE, &aggrMode, sizeof(aggrMode)));
    urma_test::GetHwMockState().userCtlReturn = URMA_SUCCESS;
    EXPECT_EQ(URMA_SUCCESS, urma_set_context_opt(&fixture.ctx, URMA_OPT_AGGR_MODE, &aggrMode, sizeof(aggrMode)));
    EXPECT_EQ(URMA_EINVAL, urma_set_context_opt(&fixture.ctx, static_cast<urma_opt_name_t>(UINT32_MAX),
                                                &aggrMode, sizeof(aggrMode)));
}

TEST(UrmaCoreTest, MainCreateContextReadsEidAndOpensLocalCdev)
{
    TempSysfsTree sysfs;
    CoreApiFixture fixture;
    urma_provider_ops_t provider = {};
    urma_eid_t expectedEid = {};

    ASSERT_TRUE(sysfs.Init());
    ASSERT_TRUE(sysfs.Mkdir("eids"));
    ASSERT_TRUE(sysfs.WriteFile("eids/eid0", "192.168.30.1\n"));
    ASSERT_TRUE(sysfs.WriteFile("mock_cdev", "not a real device\n"));
    ASSERT_EQ(0, urma_str_to_eid("192.168.30.1", &expectedEid));

    provider.create_context = MockProviderCreateContext;
    provider.delete_context = MockProviderDeleteContext;
    fixture.dev.ops = &provider;
    fixture.sysfsDev.flag = 0;
    fixture.sysfsDev.dev_attr.dev_cap.max_eid_cnt = 1;
    std::snprintf(fixture.sysfsDev.sysfs_path, sizeof(fixture.sysfsDev.sysfs_path), "%s", sysfs.root.c_str());
    std::snprintf(fixture.dev.path, sizeof(fixture.dev.path), "%s/mock_cdev", sysfs.root.c_str());

    urma_context_t *ctx = urma_create_context(&fixture.dev, 0);
    ASSERT_NE(nullptr, ctx);
    EXPECT_EQ(0U, ctx->eid_index);
    EXPECT_EQ(URMA_AGGR_MODE_STANDALONE, ctx->aggr_mode);
    EXPECT_EQ(0, memcmp(&ctx->eid, &expectedEid, sizeof(expectedEid)));
    EXPECT_GE(ctx->dev_fd, 0);
    EXPECT_EQ(URMA_SUCCESS, urma_delete_context(ctx));

    provider.create_context = MockProviderCreateContextNull;
    ctx = urma_create_context(&fixture.dev, 0);
    EXPECT_EQ(nullptr, ctx);
}

TEST(UrmaCoreTest, MainProviderLoaderUsesLocalDlopenMocks)
{
    TempSysfsTree providerRoot;
    urma_provider_ops_t provider = {};
    auto *sysfsDev = static_cast<urma_sysfs_dev_t *>(std::calloc(1, sizeof(urma_sysfs_dev_t)));
    auto *dev = static_cast<urma_device_t *>(std::calloc(1, sizeof(urma_device_t)));
    urma_eid_t eid = {};
    int deviceNum = 0;
    urma_device_t **deviceList = nullptr;
    char foundName[URMA_MAX_NAME] = "core_global_dev";
    char missingName[URMA_MAX_NAME] = "missing_global_dev";

    ASSERT_TRUE(providerRoot.Init());
    ASSERT_TRUE(providerRoot.Mkdir("urma"));
    ASSERT_TRUE(providerRoot.Mkdir("eids"));
    ASSERT_TRUE(providerRoot.WriteFile("liburma.so", "core loader anchor\n"));
    ASSERT_TRUE(providerRoot.WriteFile("urma/liburma_mock.so", "mock provider\n"));
    ASSERT_TRUE(providerRoot.WriteFile("eids/eid0", "192.168.20.1\n"));
    ASSERT_EQ(0, chmod((providerRoot.root + "/urma/liburma_mock.so").c_str(), 0700));
    ASSERT_NE(nullptr, sysfsDev);
    ASSERT_NE(nullptr, dev);
    ASSERT_EQ(0, urma_str_to_eid("192.168.20.1", &eid));

    CoreProviderRedirectGuard redirect(providerRoot.root + "/liburma.so");
    EXPECT_EQ(URMA_SUCCESS, urma_uninit());
    EXPECT_EQ(URMA_SUCCESS, urma_init(nullptr));
    EXPECT_EQ(1, g_coreDlopenCount);

    provider.name = "core_driver";
    EXPECT_EQ(0, urma_register_provider_ops(&provider));
    std::snprintf(sysfsDev->dev_name, sizeof(sysfsDev->dev_name), "core_global_dev");
    std::snprintf(sysfsDev->driver_name, sizeof(sysfsDev->driver_name), "core_driver");
    std::snprintf(sysfsDev->sysfs_path, sizeof(sysfsDev->sysfs_path), "%s", providerRoot.root.c_str());
    sysfsDev->flag = URMA_SYSFS_DEV_FLAG_DRIVER_CREATED;
    sysfsDev->dev_attr.dev_cap.max_eid_cnt = 1;
    sysfsDev->urma_device = dev;
    std::snprintf(dev->name, sizeof(dev->name), "core_global_dev");
    dev->sysfs_dev = sysfsDev;
    dev->type = URMA_TRANSPORT_UB;
    EXPECT_EQ(0, urma_register_sysfs_dev(sysfsDev));
    EXPECT_EQ(-1, urma_register_sysfs_dev(sysfsDev));
    deviceList = urma_get_device_list(&deviceNum);
    ASSERT_NE(nullptr, deviceList);
    EXPECT_EQ(1, deviceNum);
    EXPECT_EQ(dev, deviceList[0]);
    urma_free_device_list(deviceList);
    EXPECT_EQ(dev, urma_get_device_by_name(foundName));
    EXPECT_EQ(nullptr, urma_get_device_by_name(missingName));
    EXPECT_EQ(dev, urma_get_device_by_eid(eid, URMA_TRANSPORT_UB));
    EXPECT_EQ(nullptr, urma_get_device_by_eid(eid, URMA_TRANSPORT_MAX));
    EXPECT_EQ(0, urma_unregister_provider_ops(&provider));

    EXPECT_EQ(URMA_SUCCESS, urma_uninit());
    EXPECT_EQ(1, g_coreDlcloseCount);
}

TEST(UrmaCoreTest, DeviceSysfsApisParseTemporaryFilesAndFallbackEids)
{
    TempSysfsTree sysfs;
    urma_sysfs_dev_t sysfsDev = {};
    urma_device_t dev = {};
    urma_device_attr_t attr = {};
    urma_eid_t eid = {};
    urma_eid_info_t eidInfo[2] = {};
    char readBuf[32] = {};
    uint32_t eidCnt = 0;

    ASSERT_TRUE(sysfs.Init());
    ASSERT_TRUE(sysfs.Mkdir("port0"));
    ASSERT_TRUE(sysfs.Mkdir("eids"));
    ASSERT_TRUE(sysfs.WriteFile("value", "abc\n"));
    ASSERT_TRUE(sysfs.WriteFile("no_newline", "xyz"));
    ASSERT_TRUE(sysfs.WriteFile("full", "1234"));
    ASSERT_TRUE(sysfs.WriteFile("empty", ""));
    ASSERT_TRUE(sysfs.WriteFile("cdev", "x\n"));
    ASSERT_TRUE(sysfs.WriteFile("port0/max_mtu", "4\n"));
    ASSERT_TRUE(sysfs.WriteFile("port0/state", "1\n"));
    ASSERT_TRUE(sysfs.WriteFile("port0/active_width", "2\n"));
    ASSERT_TRUE(sysfs.WriteFile("port0/active_speed", "3\n"));
    ASSERT_TRUE(sysfs.WriteFile("port0/active_mtu", "5\n"));
    ASSERT_TRUE(sysfs.WriteFile("eids/eid0", "192.168.1.1\n"));
    ASSERT_TRUE(sysfs.WriteFile("eids/eid1", "bad-eid\n"));

    EXPECT_EQ(3, urma_read_sysfs_file(sysfs.root.c_str(), "value", readBuf, sizeof(readBuf)));
    EXPECT_STREQ("abc", readBuf);
    EXPECT_EQ(3, urma_read_sysfs_file(sysfs.root.c_str(), "no_newline", readBuf, sizeof(readBuf)));
    EXPECT_STREQ("xyz", readBuf);
    EXPECT_EQ(-1, urma_read_sysfs_file(sysfs.root.c_str(), "missing", readBuf, sizeof(readBuf)));
    EXPECT_EQ(-1, urma_read_sysfs_file(sysfs.root.c_str(), "full", readBuf, 4));
    EXPECT_EQ(-1, urma_read_sysfs_file(sysfs.root.c_str(), "empty", readBuf, sizeof(readBuf)));
    std::string cdevPath = sysfs.root + "/cdev";
    int openedFd = urma_open_cdev(const_cast<char *>(cdevPath.c_str()));
    ASSERT_GE(openedFd, 0);
    EXPECT_EQ(0, close(openedFd));

    std::snprintf(sysfsDev.dev_name, sizeof(sysfsDev.dev_name), "core_sysfs_dev");
    std::snprintf(sysfsDev.sysfs_path, sizeof(sysfsDev.sysfs_path), "%s", sysfs.root.c_str());
    sysfsDev.dev_attr.port_cnt = 1;
    sysfsDev.dev_attr.dev_cap.max_eid_cnt = 2;
    urma_update_port_attr(&sysfsDev);
    EXPECT_EQ(4U, static_cast<uint32_t>(sysfsDev.dev_attr.port_attr[0].max_mtu));
    EXPECT_EQ(1U, static_cast<uint32_t>(sysfsDev.dev_attr.port_attr[0].state));
    EXPECT_EQ(2U, static_cast<uint32_t>(sysfsDev.dev_attr.port_attr[0].active_width));
    EXPECT_EQ(3U, static_cast<uint32_t>(sysfsDev.dev_attr.port_attr[0].active_speed));
    EXPECT_EQ(5U, static_cast<uint32_t>(sysfsDev.dev_attr.port_attr[0].active_mtu));

    EXPECT_EQ(0, urma_read_eid_with_index(&sysfsDev, 0, &eid));
    EXPECT_EQ(-1, urma_read_eid_with_index(&sysfsDev, 1, &eid));
    dev.sysfs_dev = &sysfsDev;
    std::snprintf(dev.path, sizeof(dev.path), "/tmp/urma_core_ut_missing_cdev");
    EXPECT_EQ(1U, urma_read_eid_list(&dev, eidInfo, ARRAY_SIZE(eidInfo)));
    EXPECT_EQ(0U, eidInfo[0].eid_index);
    urma_eid_info_t *list = urma_get_eid_list(&dev, &eidCnt);
    ASSERT_NE(nullptr, list);
    EXPECT_EQ(1U, eidCnt);
    urma_free_eid_list(list);

    EXPECT_EQ(0, urma_query_eid(&dev, 0, &eid));
    EXPECT_EQ(-1, urma_query_device_attr(&sysfsDev));
    EXPECT_EQ(URMA_FAIL, urma_query_device(&dev, &attr));
}

TEST(UrmaCoreTest, DeviceMergeSkipsDuplicateAndRemovesStaleMemoryDevices)
{
    struct ub_list devList;
    struct ub_list candidateList;
    struct ub_list devNameList;
    urma_sysfs_dev_t *existing = nullptr;
    urma_sysfs_dev_t *duplicate = nullptr;
    urma_sysfs_dev_t *stale = nullptr;

    ub_list_init(&devList);
    ub_list_init(&candidateList);
    ub_list_init(&devNameList);
    existing = AllocMemorySysfsDevice("merge_dev", URMA_SYSFS_DEV_FLAG_DRIVER_CREATED);
    duplicate = AllocMemorySysfsDevice("merge_dev", 0);
    ASSERT_NE(nullptr, existing);
    ASSERT_NE(nullptr, duplicate);
    ub_list_insert_after(&devList, &existing->node);
    ub_list_insert_after(&candidateList, &duplicate->node);
    EXPECT_EQ(1U, urma_merge_sysfs_devices(&devList, &candidateList, &devNameList));
    EXPECT_EQ(1U, ub_list_size(&devList));
    EXPECT_EQ(0U, ub_list_size(&candidateList));
    CleanupSysfsDeviceList(&devList);

    ub_list_init(&devList);
    ub_list_init(&candidateList);
    ub_list_init(&devNameList);
    stale = AllocMemorySysfsDevice("stale_dev", 0);
    ASSERT_NE(nullptr, stale);
    ub_list_insert_after(&devList, &stale->node);
    EXPECT_EQ(0U, urma_merge_sysfs_devices(&devList, &candidateList, &devNameList));
    EXPECT_EQ(0U, ub_list_size(&devList));
}

TEST(UrmaCoreTest, DeviceDiscoveryParsesRedirectedSysfsTree)
{
    TempSysfsTree sysfs;
    struct dirent ignored = {};
    struct dirent dent = {};
    urma_provider_ops_t provider = {};
    urma_driver_t driver = {};
    struct ub_list driverList;
    struct ub_list devList;

    ASSERT_TRUE(sysfs.Init());
    PopulateReadableSysfsDevice(&sysfs, "dev0");
    PopulateReadableSysfsDevice(&sysfs, "bonding_dev0");
    ASSERT_TRUE(sysfs.WriteFile("bonding_dev0/ubdev", "bonding_dev0\n"));
    ASSERT_TRUE(sysfs.WriteFile("bonding_dev0/reserved_jetty_id", "invalid-range\n"));
    ASSERT_TRUE(sysfs.WriteFile("plain_file", "not a directory\n"));
    CoreSysfsRedirectGuard redirect(sysfs.root);

    std::snprintf(ignored.d_name, sizeof(ignored.d_name), ".");
    EXPECT_EQ(nullptr, urma_read_sysfs_device(&ignored));
    std::snprintf(ignored.d_name, sizeof(ignored.d_name), "ubcore");
    EXPECT_EQ(nullptr, urma_read_sysfs_device(&ignored));
    std::snprintf(ignored.d_name, sizeof(ignored.d_name), "missing_dev");
    EXPECT_EQ(nullptr, urma_read_sysfs_device(&ignored));
    std::snprintf(ignored.d_name, sizeof(ignored.d_name), "plain_file");
    EXPECT_EQ(nullptr, urma_read_sysfs_device(&ignored));

    std::snprintf(dent.d_name, sizeof(dent.d_name), "dev0");
    urma_sysfs_dev_t *readDev = urma_read_sysfs_device(&dent);
    ASSERT_NE(nullptr, readDev);
    EXPECT_STREQ("core_sysfs_dev", readDev->dev_name);
    EXPECT_STREQ("core_driver", readDev->driver_name);
    EXPECT_EQ(URMA_TRANSPORT_UB, readDev->transport_type);
    EXPECT_EQ(1U, readDev->dev_attr.port_cnt);
    EXPECT_EQ(2U, readDev->dev_attr.dev_cap.max_jfc);
    EXPECT_EQ(4096ULL, readDev->dev_attr.dev_cap.max_msg_size);
    EXPECT_EQ(17U, readDev->dev_attr.reserved_jetty_id_min);
    EXPECT_EQ(19U, readDev->dev_attr.reserved_jetty_id_max);
    std::free(readDev);

    std::snprintf(dent.d_name, sizeof(dent.d_name), "bonding_dev0");
    readDev = urma_read_sysfs_device(&dent);
    ASSERT_NE(nullptr, readDev);
    EXPECT_STREQ("bonding_dev0", readDev->dev_name);
    EXPECT_EQ(0U, readDev->vendor_id);
    EXPECT_EQ(0U, readDev->device_id);
    EXPECT_EQ(UINT32_MAX, readDev->dev_attr.reserved_jetty_id_min);
    EXPECT_EQ(UINT32_MAX, readDev->dev_attr.reserved_jetty_id_max);
    std::free(readDev);

    ub_list_init(&driverList);
    ub_list_init(&devList);
    provider.name = "core_driver";
    driver.ops = &provider;
    ub_list_insert_after(&driverList, &driver.node);
    EXPECT_EQ(2U, urma_discover_devices(&devList, &driverList));
    EXPECT_EQ(2U, ub_list_size(&devList));
    CleanupSysfsDeviceList(&devList);
    ub_list_remove(&driver.node);
}

TEST(UrmaCoreTest, DeviceDiscoverySkipsExistingAndUnmatchedDevices)
{
    TempSysfsTree sysfs;
    urma_provider_ops_t provider = {};
    urma_provider_ops_t mismatchProvider = {};
    urma_driver_t driver = {};
    urma_driver_t mismatchDriver = {};
    urma_sysfs_dev_t *existing = nullptr;
    struct ub_list driverList;
    struct ub_list devList;
    struct ub_list candidateList;
    struct ub_list devNameList;

    ASSERT_TRUE(sysfs.Init());
    PopulateReadableSysfsDevice(&sysfs, "dev0");
    CoreSysfsRedirectGuard redirect(sysfs.root);

    ub_list_init(&driverList);
    ub_list_init(&devList);
    provider.name = "core_driver";
    driver.ops = &provider;
    ub_list_insert_after(&driverList, &driver.node);
    existing = AllocMemorySysfsDevice("core_sysfs_dev", 0);
    ASSERT_NE(nullptr, existing);
    ub_list_insert_after(&devList, &existing->node);
    EXPECT_EQ(1U, urma_discover_devices(&devList, &driverList));
    EXPECT_EQ(1U, ub_list_size(&devList));
    CleanupSysfsDeviceList(&devList);
    ub_list_remove(&driver.node);

    ub_list_init(&driverList);
    ub_list_init(&candidateList);
    ub_list_init(&devNameList);
    mismatchProvider.name = "other_driver";
    mismatchDriver.ops = &mismatchProvider;
    ub_list_insert_after(&driverList, &mismatchDriver.node);
    urma_scan_sysfs_devices(&candidateList, &devNameList, &driverList);
    EXPECT_EQ(0U, ub_list_size(&candidateList));
    EXPECT_EQ(1U, ub_list_size(&devNameList));
    CleanupSysfsDeviceList(&candidateList);
    CleanupSysfsDevNameList(&devNameList);
    ub_list_remove(&mismatchDriver.node);
}

TEST(UrmaCoreTest, DeviceListAndDriverHelpersUseMemoryObjects)
{
    urma_provider_ops_t provider = {};
    urma_match_entry_t matchTable[2] = {};
    urma_driver_t driver = {};
    struct ub_list driverList;
    struct ub_list devList;
    struct ub_list candidateList;
    struct ub_list devNameList;

    ub_list_init(&driverList);
    ub_list_init(&devList);
    ub_list_init(&candidateList);
    ub_list_init(&devNameList);
    provider.name = "core_driver";
    driver.ops = &provider;
    ub_list_insert_after(&driverList, &driver.node);

    urma_sysfs_dev_t sysfsDev = {};
    std::snprintf(sysfsDev.dev_name, sizeof(sysfsDev.dev_name), "core_list_dev");
    std::snprintf(sysfsDev.driver_name, sizeof(sysfsDev.driver_name), "core_driver");
    EXPECT_TRUE(urma_match_driver(&sysfsDev, &driverList));
    EXPECT_EQ(&driver, sysfsDev.driver);

    urma_sysfs_dev_t noMatchDev = {};
    std::snprintf(noMatchDev.driver_name, sizeof(noMatchDev.driver_name), "missing_driver");
    EXPECT_FALSE(urma_match_driver(&noMatchDev, &driverList));

    matchTable[0].vendor_id = 0x19e5;
    matchTable[0].device_id = 0x1001;
    provider.match_table = matchTable;
    noMatchDev.vendor_id = 0x19e5;
    noMatchDev.device_id = 0x1001;
    EXPECT_TRUE(urma_match_driver(&noMatchDev, &driverList));
    provider.match_table = nullptr;

    urma_sysfs_dev_t *listedSysfsDev = static_cast<urma_sysfs_dev_t *>(calloc(1, sizeof(*listedSysfsDev)));
    ASSERT_NE(nullptr, listedSysfsDev);
    urma_device_t *listedDev = static_cast<urma_device_t *>(calloc(1, sizeof(*listedDev)));
    ASSERT_NE(nullptr, listedDev);
    std::snprintf(listedSysfsDev->dev_name, sizeof(listedSysfsDev->dev_name), "core_list_dev");
    listedSysfsDev->urma_device = listedDev;
    ub_list_insert_after(&devList, &listedSysfsDev->node);
    EXPECT_EQ(listedDev, urma_find_dev_by_name(&devList, "core_list_dev"));
    EXPECT_EQ(nullptr, urma_find_dev_by_name(&devList, "absent"));
    urma_free_devices(&devList);

    urma_sysfs_dev_t *candidate = static_cast<urma_sysfs_dev_t *>(calloc(1, sizeof(*candidate)));
    ASSERT_NE(nullptr, candidate);
    candidate->flag = URMA_SYSFS_DEV_FLAG_DRIVER_CREATED;
    candidate->urma_device = static_cast<urma_device_t *>(calloc(1, sizeof(urma_device_t)));
    ASSERT_NE(nullptr, candidate->urma_device);
    std::snprintf(candidate->dev_name, sizeof(candidate->dev_name), "driver_created_dev");
    ub_list_insert_after(&candidateList, &candidate->node);
    EXPECT_EQ(1U, urma_merge_sysfs_devices(&devList, &candidateList, &devNameList));
    EXPECT_EQ(candidate->urma_device, urma_find_dev_by_name(&devList, "driver_created_dev"));
    urma_free_devices(&devList);

    urma_sysfs_dev_t *unloaded = static_cast<urma_sysfs_dev_t *>(calloc(1, sizeof(*unloaded)));
    ASSERT_NE(nullptr, unloaded);
    unloaded->urma_device = static_cast<urma_device_t *>(calloc(1, sizeof(urma_device_t)));
    ASSERT_NE(nullptr, unloaded->urma_device);
    std::snprintf(unloaded->dev_name, sizeof(unloaded->dev_name), "unloaded_dev");
    ub_list_insert_after(&devList, &unloaded->node);
    EXPECT_EQ(0U, urma_merge_sysfs_devices(&devList, &candidateList, &devNameList));
    EXPECT_EQ(nullptr, urma_find_dev_by_name(&devList, "unloaded_dev"));

    urma_sysfs_dev_t *loaded = static_cast<urma_sysfs_dev_t *>(calloc(1, sizeof(*loaded)));
    ASSERT_NE(nullptr, loaded);
    loaded->urma_device = static_cast<urma_device_t *>(calloc(1, sizeof(urma_device_t)));
    ASSERT_NE(nullptr, loaded->urma_device);
    std::snprintf(loaded->dev_name, sizeof(loaded->dev_name), "loaded_dev");
    ub_list_insert_after(&devList, &loaded->node);
    auto *loadedName = static_cast<urma_sysfs_dev_name_t *>(calloc(1, sizeof(urma_sysfs_dev_name_t)));
    ASSERT_NE(nullptr, loadedName);
    std::snprintf(loadedName->dev_name, sizeof(loadedName->dev_name), "loaded_dev");
    ub_list_insert_after(&devNameList, &loadedName->node);
    EXPECT_EQ(1U, urma_merge_sysfs_devices(&devList, &candidateList, &devNameList));
    EXPECT_NE(nullptr, urma_find_dev_by_name(&devList, "loaded_dev"));
    urma_free_devices(&devList);

    ub_list_remove(&driver.node);
}
