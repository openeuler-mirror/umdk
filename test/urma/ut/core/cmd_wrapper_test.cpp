/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core command wrapper unit tests.
 */

#include "core_fixture.h"

using namespace urma_test_core;

TEST(UrmaCoreTest, CmdTokenAndSegmentWrappersPropagateIoctlFailure)
{
    CmdIoctlFailureFixture fixture;
    urma_token_id_t outToken = {};
    urma_token_id_flag_t tokenFlag = {};
    urma_target_seg_t outSeg = {};
    urma_seg_cfg_t segCfg = {};

    ASSERT_TRUE(fixture.Init());
    SetCoreIoctlResult(-1, ENOTTY);
    tokenFlag.bs.multi_seg = 1;
    segCfg.va = 0x1000;
    segCfg.len = 0x2000;
    segCfg.token_id = &fixture.token;
    segCfg.token_value.token = 0x3333;

    EXPECT_EQ(-1, urma_cmd_alloc_token_id(&fixture.ctx, &outToken, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_alloc_token_id_ex(&fixture.ctx, &outToken, tokenFlag, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_free_token_id(&fixture.token));
    EXPECT_EQ(-1, urma_cmd_register_seg(&fixture.ctx, &outSeg, &segCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unregister_seg(&fixture.tseg));
    EXPECT_EQ(-1, urma_cmd_import_seg(&fixture.ctx, &outSeg, &fixture.importSegCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unimport_seg(&fixture.tseg));
}

TEST(UrmaCoreTest, CmdJfcJfsJfrWrappersPropagateIoctlFailure)
{
    CmdIoctlFailureFixture fixture;
    urma_jfc_attr_t jfcAttr = {};
    urma_jfs_attr_t jfsAttr = {};
    urma_jfr_attr_t jfrAttr = {};
    urma_jfs_cfg_t jfsCfgOut = {};
    urma_jfr_cfg_t jfrCfgOut = {};
    uint32_t optValue = 4;
    urma_jfc_t *jfcArr[1] = { nullptr };
    urma_jfs_t *jfsArr[1] = { nullptr };
    urma_jfr_t *jfrArr[1] = { nullptr };
    urma_jfc_t *badJfc = nullptr;
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;

    ASSERT_TRUE(fixture.Init());
    SetCoreIoctlResult(-1, ENOTTY);
    jfcArr[0] = &fixture.jfc;
    jfsArr[0] = &fixture.jfs;
    jfrArr[0] = &fixture.jfr;

    EXPECT_EQ(-1, urma_cmd_create_jfc(&fixture.ctx, &fixture.jfc, &fixture.jfc.jfc_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfc(&fixture.jfc, &jfcAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_delete_jfc(&fixture.jfc));
    EXPECT_EQ(-1, urma_cmd_delete_jfc_batch(jfcArr, 1, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);
    EXPECT_EQ(-1, urma_cmd_alloc_jfc(&fixture.ctx, &fixture.jfc.jfc_cfg, &fixture.jfc, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_get_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_active_jfc(&fixture.jfc, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_deactive_jfc(&fixture.jfc, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_free_jfc(&fixture.jfc, &fixture.udata));

    EXPECT_EQ(-1, urma_cmd_create_jfs(&fixture.ctx, &fixture.jfs, &fixture.jfs.jfs_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfs(&fixture.jfs, &jfsAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jfs(&fixture.jfs, &jfsCfgOut, &jfsAttr));
    EXPECT_EQ(-1, urma_cmd_delete_jfs(&fixture.jfs));
    EXPECT_EQ(-1, urma_cmd_delete_jfs_batch(jfsArr, 1, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);
    EXPECT_EQ(-1, urma_cmd_alloc_jfs(&fixture.ctx, &fixture.jfs.jfs_cfg, &fixture.jfs, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_get_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_active_jfs(&fixture.jfs, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_deactive_jfs(&fixture.jfs, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_free_jfs(&fixture.jfs, &fixture.udata));

    EXPECT_EQ(-1, urma_cmd_create_jfr(&fixture.ctx, &fixture.jfr, &fixture.jfr.jfr_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfr(&fixture.jfr, &jfrAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jfr(&fixture.jfr, &jfrCfgOut, &jfrAttr));
    EXPECT_EQ(-1, urma_cmd_delete_jfr(&fixture.jfr));
    EXPECT_EQ(-1, urma_cmd_delete_jfr_batch(jfrArr, 1, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);
    EXPECT_EQ(-1, urma_cmd_alloc_jfr(&fixture.ctx, &fixture.jfr.jfr_cfg, &fixture.jfr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_get_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_active_jfr(&fixture.jfr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_deactive_jfr(&fixture.jfr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_free_jfr(&fixture.jfr, &fixture.udata));
}

TEST(UrmaCoreTest, CmdJettyNotifierAndControlWrappersPropagateIoctlFailure)
{
    CmdIoctlFailureFixture fixture;
    urma_jetty_cfg_t jettyCfg = {};
    urma_jetty_attr_t jettyAttr = {};
    urma_jetty_grp_t jettyGrp = {};
    urma_jetty_grp_cfg_t jettyGrpCfg = {};
    urma_notify_t notify = {};
    urma_user_ctl_in_t ctlIn = {};
    urma_user_ctl_out_t ctlOut = {};
    urma_udrv_t udrv = {};
    urma_get_tp_cfg_t getTpCfg = {};
    urma_tp_info_t tpInfo = {};
    uint32_t tpCnt = 1;
    uint8_t tpAttrCnt = 1;
    uint32_t tpAttrBitmap = 1;
    urma_tp_attr_value_t tpAttr = {};
    uint64_t peerTpHandle = 0;
    uint32_t rxPsn = 0;
    uint32_t optValue = 4;
    urma_jetty_t *jettyArr[1] = { nullptr };
    urma_jetty_t *badJetty = nullptr;

    ASSERT_TRUE(fixture.Init());
    SetCoreIoctlResult(-1, ENOTTY);
    jettyCfg = fixture.jetty.jetty_cfg;
    std::snprintf(jettyGrpCfg.name, sizeof(jettyGrpCfg.name), "cmd_grp");
    jettyArr[0] = &fixture.jetty;

    EXPECT_EQ(-1, urma_cmd_create_jfce(&fixture.ctx));
    EXPECT_EQ(-1, urma_cmd_create_jetty(&fixture.ctx, &fixture.jetty, &jettyCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jetty(&fixture.jetty, &jettyAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jetty(&fixture.jetty, &jettyCfg, &jettyAttr));
    EXPECT_EQ(-1, urma_cmd_delete_jetty(&fixture.jetty));
    EXPECT_EQ(-1, urma_cmd_delete_jetty_batch(jettyArr, 1, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
    EXPECT_EQ(-1, urma_cmd_alloc_jetty(&fixture.ctx, &jettyCfg, &fixture.jetty, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &optValue, sizeof(optValue),
        &fixture.udata));
    fixture.jetty.jetty_cfg.shared.jfc = nullptr;
    EXPECT_EQ(-1, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JETTY_BIND_RX_JFC, &optValue,
        sizeof(uint64_t), &fixture.udata));
    fixture.jetty.jetty_cfg.shared.jfc = &fixture.jfc;
    fixture.jetty.jetty_cfg.shared.jfr = nullptr;
    EXPECT_EQ(-1, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JETTY_BIND_JFR, &optValue,
        sizeof(uint64_t), &fixture.udata));
    fixture.jetty.jetty_cfg.shared.jfr = &fixture.jfr;
    fixture.jetty.jetty_cfg.jetty_grp = nullptr;
    EXPECT_EQ(-1, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JETTY_BIND_JTG, &optValue,
        sizeof(uint64_t), &fixture.udata));
    fixture.jetty.jetty_cfg.jfs_cfg.jfc = nullptr;
    EXPECT_EQ(-1, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JFS_BIND_JFC, &optValue,
        sizeof(uint64_t), &fixture.udata));
    fixture.jetty.jetty_cfg.jfs_cfg.jfc = &fixture.jfc;
    EXPECT_EQ(-1, urma_cmd_get_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &optValue, sizeof(optValue),
        &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_active_jetty(&fixture.jetty, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_deactive_jetty(&fixture.jetty, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_free_jetty(&fixture.jetty, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jetty_grp(&fixture.ctx, &jettyGrp, &jettyGrpCfg, &fixture.udata));

    EXPECT_EQ(-1, urma_cmd_import_jfr(&fixture.ctx, &fixture.tjfr, &fixture.tjfrCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_import_jfr_ex(&fixture.ctx, &fixture.tjfr, &fixture.tjfrCfg, &fixture.importJfrExCfg,
        &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unimport_jfr(&fixture.tjfr));
    EXPECT_EQ(-1, urma_cmd_advise_jfr(&fixture.jfs, &fixture.tjfr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unadvise_jfr(&fixture.jfs, &fixture.tjfr));
    EXPECT_EQ(-1, urma_cmd_import_jetty(&fixture.ctx, &fixture.tjfr, &fixture.tjettyCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_import_jetty_ex(&fixture.ctx, &fixture.tjfr, &fixture.tjettyCfg,
        &fixture.importJettyExCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unimport_jetty(&fixture.tjfr));
    EXPECT_EQ(-1, urma_cmd_advise_jetty(&fixture.jetty, &fixture.tjfr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unadvise_jetty(&fixture.jetty, &fixture.tjfr));
    EXPECT_EQ(-1, urma_cmd_bind_jetty(&fixture.jetty, &fixture.tjfr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_bind_jetty_ex(&fixture.jetty, &fixture.tjfr, &fixture.bindJettyExCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unbind_jetty(&fixture.jetty));

    EXPECT_EQ(-1, urma_cmd_create_notifier(&fixture.ctx));
    EXPECT_EQ(-1, urma_cmd_wait_notify(&fixture.notifier, 1, &notify, 0));
    EXPECT_EQ(-1, urma_cmd_import_jetty_async(&fixture.notifier, &fixture.tjfr, &fixture.tjettyCfg, 0, 0,
        &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unimport_jetty_async(&fixture.tjfr));
    EXPECT_EQ(-1, urma_cmd_bind_jetty_async(&fixture.notifier, &fixture.jetty, &fixture.tjfr, 0, 0, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_unbind_jetty_async(&fixture.jetty));

    EXPECT_EQ(-1, urma_cmd_user_ctl(&fixture.ctx, &ctlIn, &ctlOut, &udrv));
    EXPECT_EQ(-1, urma_cmd_get_tp_list(&fixture.ctx, &getTpCfg, &tpCnt, &tpInfo, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_tp_attr(&fixture.ctx, 1, tpAttrCnt, tpAttrBitmap, &tpAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_get_tp_attr(&fixture.ctx, 1, &tpAttrCnt, &tpAttrBitmap, &tpAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_exchange_tp_info(&fixture.ctx, &getTpCfg, 1, 2, &peerTpHandle, &rxPsn));
}

TEST(UrmaCoreTest, CmdWrappersRejectInvalidParametersBeforeIoctl)
{
    CmdIoctlFailureFixture fixture;
    urma_context_cfg_t ctxCfg = {};
    urma_context_t badCtx = {};
    urma_jfs_t otherJfs = {};
    urma_jfr_t otherJfr = {};
    urma_jfc_t otherJfc = {};
    urma_jetty_t otherJetty = {};
    urma_jfc_t *jfcArr[2] = {};
    urma_jfs_t *jfsArr[2] = {};
    urma_jfr_t *jfrArr[2] = {};
    urma_jetty_t *jettyArr[2] = {};
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;
    urma_jfc_t *badJfc = nullptr;
    urma_jetty_t *badJetty = nullptr;
    urma_jfs_cfg_t jfsCfg = {};
    urma_jfr_cfg_t jfrCfg = {};
    urma_jfs_attr_t jfsAttr = {};
    urma_jfr_attr_t jfrAttr = {};
    urma_jetty_attr_t jettyAttr = {};
    urma_jetty_cfg_t jettyCfg = {};
    uint32_t optValue = 4;

    ASSERT_TRUE(fixture.Init());

    EXPECT_EQ(-1, urma_cmd_create_context(nullptr, &ctxCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_context(&fixture.ctx, nullptr, &fixture.udata));
    ctxCfg.dev_fd = -1;
    ctxCfg.dev = &fixture.dev;
    ctxCfg.ops = &fixture.ops;
    EXPECT_EQ(-1, urma_cmd_create_context(&fixture.ctx, &ctxCfg, &fixture.udata));
    badCtx.dev_fd = -1;
    EXPECT_EQ(-1, urma_cmd_delete_context(nullptr));
    EXPECT_EQ(-1, urma_cmd_delete_context(&badCtx));
    urma_token_id_flag_t tokenFlag = {};
    tokenFlag.bs.multi_seg = 1;
    EXPECT_EQ(-1, urma_cmd_alloc_token_id_ex(nullptr, &fixture.token, tokenFlag, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_alloc_token_id_ex(&badCtx, &fixture.token, tokenFlag, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_alloc_token_id_ex(&fixture.ctx, nullptr, tokenFlag, &fixture.udata));
    urma_token_id_t invalidToken = {};
    EXPECT_EQ(-1, urma_cmd_free_token_id(nullptr));
    EXPECT_EQ(-1, urma_cmd_free_token_id(&invalidToken));
    invalidToken.urma_ctx = &badCtx;
    EXPECT_EQ(-1, urma_cmd_free_token_id(&invalidToken));
    urma_target_seg_t invalidTseg = {};
    EXPECT_EQ(-1, urma_cmd_unregister_seg(nullptr));
    EXPECT_EQ(-1, urma_cmd_unregister_seg(&invalidTseg));
    invalidTseg.urma_ctx = &badCtx;
    EXPECT_EQ(-1, urma_cmd_unregister_seg(&invalidTseg));
    EXPECT_EQ(-1, urma_cmd_unimport_seg(nullptr));
    invalidTseg.urma_ctx = nullptr;
    EXPECT_EQ(-1, urma_cmd_unimport_seg(&invalidTseg));
    invalidTseg.urma_ctx = &badCtx;
    EXPECT_EQ(-1, urma_cmd_unimport_seg(&invalidTseg));

    EXPECT_EQ(-1, urma_cmd_create_jfs(nullptr, &fixture.jfs, &fixture.jfs.jfs_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jfs(&fixture.ctx, nullptr, &fixture.jfs.jfs_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jfs(&fixture.ctx, &fixture.jfs, nullptr, &fixture.udata));
    jfsCfg = fixture.jfs.jfs_cfg;
    jfsCfg.jfc = nullptr;
    EXPECT_EQ(-1, urma_cmd_create_jfs(&fixture.ctx, &fixture.jfs, &jfsCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfs(nullptr, &jfsAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfs(&fixture.jfs, nullptr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jfs(nullptr, &jfsCfg, &jfsAttr));
    EXPECT_EQ(-1, urma_cmd_query_jfs(&fixture.jfs, nullptr, &jfsAttr));
    EXPECT_EQ(-1, urma_cmd_query_jfs(&fixture.jfs, &jfsCfg, nullptr));
    EXPECT_EQ(-1, urma_cmd_delete_jfs(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(nullptr, 1, &badJfs));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(jfsArr, 0, &badJfs));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(jfsArr, 1, nullptr));
    jfsArr[0] = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(jfsArr, 1, &badJfs));
    EXPECT_EQ(nullptr, badJfs);
    jfsArr[0] = &fixture.jfs;
    jfsArr[1] = &otherJfs;
    badCtx.dev = fixture.ctx.dev;
    badCtx.ops = fixture.ctx.ops;
    badCtx.dev_fd = fixture.ctx.dev_fd + 1;
    otherJfs = fixture.jfs;
    otherJfs.urma_ctx = &badCtx;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);
    EXPECT_EQ(-1, urma_cmd_alloc_jfs(nullptr, &fixture.jfs.jfs_cfg, &fixture.jfs, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_alloc_jfs(&fixture.ctx, nullptr, &fixture.jfs, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_alloc_jfs(&fixture.ctx, &fixture.jfs.jfs_cfg, nullptr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jfs_opt(nullptr, URMA_JFS_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jfs_opt(&fixture.jfs, 0, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, nullptr, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_get_jfs_opt(nullptr, URMA_JFS_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_get_jfs_opt(&fixture.jfs, 0, &optValue, sizeof(optValue), &fixture.udata));

    EXPECT_EQ(-1, urma_cmd_create_jfr(nullptr, &fixture.jfr, &fixture.jfr.jfr_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jfr(&fixture.ctx, nullptr, &fixture.jfr.jfr_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jfr(&fixture.ctx, &fixture.jfr, nullptr, &fixture.udata));
    jfrCfg = fixture.jfr.jfr_cfg;
    jfrCfg.jfc = nullptr;
    EXPECT_EQ(-1, urma_cmd_create_jfr(&fixture.ctx, &fixture.jfr, &jfrCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfr(nullptr, &jfrAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfr(&fixture.jfr, nullptr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jfr(nullptr, &jfrCfg, &jfrAttr));
    EXPECT_EQ(-1, urma_cmd_query_jfr(&fixture.jfr, nullptr, &jfrAttr));
    EXPECT_EQ(-1, urma_cmd_query_jfr(&fixture.jfr, &jfrCfg, nullptr));
    EXPECT_EQ(-1, urma_cmd_delete_jfr(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(nullptr, 1, &badJfr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(jfrArr, 0, &badJfr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(jfrArr, 1, nullptr));
    jfrArr[0] = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(jfrArr, 1, &badJfr));
    EXPECT_EQ(nullptr, badJfr);
    jfrArr[0] = &fixture.jfr;
    jfrArr[1] = &otherJfr;
    otherJfr = fixture.jfr;
    otherJfr.urma_ctx = &badCtx;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);

    EXPECT_EQ(-1, urma_cmd_create_jfc(nullptr, &fixture.jfc, &fixture.jfc.jfc_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jfc(&fixture.ctx, nullptr, &fixture.jfc.jfc_cfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_create_jfc(&fixture.ctx, &fixture.jfc, nullptr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jfc(nullptr, nullptr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_delete_jfc(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(nullptr, 1, &badJfc));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(jfcArr, 0, &badJfc));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(jfcArr, 1, nullptr));
    jfcArr[0] = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(jfcArr, 1, &badJfc));
    EXPECT_EQ(nullptr, badJfc);
    jfcArr[0] = &fixture.jfc;
    jfcArr[1] = &otherJfc;
    otherJfc = fixture.jfc;
    otherJfc.urma_ctx = &badCtx;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);
    EXPECT_EQ(-1, urma_cmd_modify_jetty(nullptr, &jettyAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jetty(nullptr, &jettyCfg, &jettyAttr));
    EXPECT_EQ(-1, urma_cmd_delete_jetty(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jetty_batch(nullptr, 1, &badJetty));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jetty_batch(jettyArr, 0, &badJetty));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jetty_batch(jettyArr, 1, nullptr));
    jettyArr[0] = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jetty_batch(jettyArr, 1, &badJetty));
    EXPECT_EQ(nullptr, badJetty);
    jettyArr[0] = &fixture.jetty;
    jettyArr[1] = &otherJetty;
    otherJetty = fixture.jetty;
    otherJetty.urma_ctx = &badCtx;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
    badCtx.dev_fd = -1;
    otherJetty.urma_ctx = &badCtx;
    jettyArr[0] = &otherJetty;
    badJetty = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jetty_batch(jettyArr, 1, &badJetty));
    EXPECT_EQ(&otherJetty, badJetty);
}

TEST(UrmaCoreTest, CmdWrappersFillObjectsWhenIoctlSucceeds)
{
    CoreApiFixture fixture;
    urma_cmd_udrv_priv_t udata = {};
    urma_token_id_t token = {};
    urma_token_id_t tokenEx = {};
    urma_target_seg_t tseg = {};
    urma_target_seg_t tsegNoToken = {};
    urma_target_seg_t importedNoToken = {};
    urma_seg_cfg_t segCfg = {};
    urma_seg_cfg_t segCfgNoToken = {};
    urma_import_tseg_cfg_t importSegCfg = {};
    urma_import_tseg_cfg_t importSegCfgNoToken = {};
    urma_jfc_t jfc = {};
    urma_jfs_t jfs = {};
    urma_jfr_t jfr = {};
    urma_jetty_t jetty = {};
    urma_jetty_t privateJetty = {};
    urma_jetty_cfg_t jettyCfgNoRxJfc = fixture.jetty.jetty_cfg;
    urma_jetty_cfg_t privateJettyCfg = fixture.jetty.jetty_cfg;
    urma_jfr_cfg_t privateJfrCfg = fixture.jfr.jfr_cfg;
    urma_target_jetty_t tjfr = {};
    urma_target_jetty_t tjetty = {};
    urma_notifier_t notifier = {};
    urma_tjfr_cfg_t tjfrCfg = {};
    urma_tjetty_cfg_t tjettyCfg = {};
    urma_import_jfr_ex_cfg_t importJfrExCfg = {};
    urma_import_jetty_ex_cfg_t importJettyExCfg = {};
    urma_bind_jetty_ex_cfg_t bindJettyExCfg = {};
    urma_jetty_grp_t jettyGrp = {};
    urma_jetty_grp_t privateJettyGrp = {};
    urma_jetty_grp_cfg_t jettyGrpCfg = {};
    urma_token_t importToken = {};
    urma_eid_info_t eidList[1] = {};
    uint32_t eidCnt = 1;
    urma_jfc_t *jfcEvents[1] = {};
    uint32_t nevents[1] = { 1 };
    urma_async_event_t asyncEvent = {};

    fixture.ctx.dev_fd = 17;
    fixture.ctx.async_fd = 18;
    importToken.token = 0xaaa;
    segCfg.va = 0x1000;
    segCfg.len = 0x2000;
    segCfg.token_id = &fixture.token;
    segCfg.token_value = importToken;
    importSegCfg.ubva = fixture.tseg.seg.ubva;
    importSegCfg.len = 0x2000;
    importSegCfg.token_id = fixture.token.token_id;
    importSegCfg.token = &importToken;
    importSegCfg.mva = 0x3000;
    tjfrCfg.jfr_id = fixture.tjfr.id;
    tjfrCfg.trans_mode = URMA_TM_RM;
    tjfrCfg.tp_type = URMA_RTP;
    tjfrCfg.token = &importToken;
    tjettyCfg.jetty_id = fixture.tjfr.id;
    tjettyCfg.trans_mode = URMA_TM_RC;
    tjettyCfg.tp_type = URMA_RTP;
    tjettyCfg.type = URMA_JETTY;
    tjettyCfg.token = &importToken;
    notifier.urma_ctx = &fixture.ctx;
    notifier.fd = 19;
    jettyCfgNoRxJfc.shared.jfc = nullptr;
    privateJettyCfg.flag.bs.share_jfr = URMA_NO_SHARE_JFR;
    privateJettyCfg.jfr_cfg = &privateJfrCfg;
    privateJettyCfg.jetty_grp = &privateJettyGrp;
    privateJettyGrp.handle = 0x7801;
    std::snprintf(jettyGrpCfg.name, sizeof(jettyGrpCfg.name), "cmd_success_grp");

    SetCoreIoctlResult(0, 0);
    EXPECT_EQ(0, urma_cmd_alloc_token_id(&fixture.ctx, &token, &udata));
    urma_token_id_flag_t tokenFlag = {};
    tokenFlag.bs.multi_seg = 1;
    EXPECT_EQ(0, urma_cmd_alloc_token_id_ex(&fixture.ctx, &tokenEx, tokenFlag, &udata));
    EXPECT_EQ(tokenFlag.value, tokenEx.flag.value);
    EXPECT_EQ(0, urma_cmd_register_seg(&fixture.ctx, &tseg, &segCfg, &udata));
    segCfgNoToken = segCfg;
    segCfgNoToken.token_id = nullptr;
    segCfgNoToken.flag.bs.token_id_valid = URMA_TOKEN_ID_INVALID;
    EXPECT_EQ(0, urma_cmd_register_seg(&fixture.ctx, &tsegNoToken, &segCfgNoToken, &udata));
    EXPECT_EQ(nullptr, tsegNoToken.token_id);
    EXPECT_EQ(0, urma_cmd_import_seg(&fixture.ctx, &tseg, &importSegCfg, &udata));
    importSegCfgNoToken = importSegCfg;
    importSegCfgNoToken.token = nullptr;
    EXPECT_EQ(0, urma_cmd_import_seg(&fixture.ctx, &importedNoToken, &importSegCfgNoToken, &udata));

    EXPECT_EQ(0, urma_cmd_create_jfc(&fixture.ctx, &jfc, &fixture.jfc.jfc_cfg, &udata));
    EXPECT_EQ(0, urma_cmd_create_jfs(&fixture.ctx, &jfs, &fixture.jfs.jfs_cfg, &udata));
    EXPECT_EQ(0, urma_cmd_alloc_jfs(&fixture.ctx, &fixture.jfs.jfs_cfg, &jfs, &udata));
    EXPECT_EQ(0, urma_cmd_active_jfs(&jfs, &udata));
    EXPECT_TRUE(jfs.urma_jfs_opt.is_actived);
    EXPECT_EQ(0, urma_cmd_deactive_jfs(&jfs, &udata));
    EXPECT_FALSE(jfs.urma_jfs_opt.is_actived);
    EXPECT_EQ(0, urma_cmd_create_jfr(&fixture.ctx, &jfr, &fixture.jfr.jfr_cfg, &udata));
    EXPECT_EQ(0, urma_cmd_alloc_jfr(&fixture.ctx, &fixture.jfr.jfr_cfg, &jfr, &udata));
    EXPECT_EQ(0, urma_cmd_active_jfr(&jfr, &udata));
    EXPECT_TRUE(jfr.urma_jfr_opt.is_actived);
    EXPECT_EQ(0, urma_cmd_deactive_jfr(&jfr, &udata));
    EXPECT_FALSE(jfr.urma_jfr_opt.is_actived);

    EXPECT_EQ(0, urma_cmd_create_jetty(&fixture.ctx, &jetty, &jettyCfgNoRxJfc, &udata));
    EXPECT_EQ(&fixture.jfc, jetty.jetty_cfg.shared.jfc);
    jetty.jetty_cfg.shared.jfc = nullptr;
    EXPECT_EQ(0, urma_cmd_alloc_jetty(&fixture.ctx, &jettyCfgNoRxJfc, &jetty, &udata));
    EXPECT_EQ(&fixture.jfc, jetty.jetty_cfg.shared.jfc);
    EXPECT_EQ(0, urma_cmd_active_jetty(&jetty, &udata));
    EXPECT_EQ(0, urma_cmd_deactive_jetty(&jetty, &udata));
    EXPECT_EQ(0, urma_cmd_create_jetty(&fixture.ctx, &privateJetty, &privateJettyCfg, &udata));
    EXPECT_EQ(URMA_NO_SHARE_JFR, privateJetty.jetty_cfg.flag.bs.share_jfr);
    EXPECT_EQ(0, urma_cmd_active_jetty(&privateJetty, &udata));
    EXPECT_EQ(0, urma_cmd_deactive_jetty(&privateJetty, &udata));
    urma_uninit_jetty_cfg(&privateJetty.jetty_cfg);
    EXPECT_EQ(0, urma_cmd_import_jfr(&fixture.ctx, &tjfr, &tjfrCfg, &udata));
    EXPECT_EQ(0, urma_cmd_import_jfr_ex(&fixture.ctx, &tjfr, &tjfrCfg, &importJfrExCfg, &udata));
    EXPECT_EQ(0, urma_cmd_import_jetty(&fixture.ctx, &tjetty, &tjettyCfg, &udata));
    EXPECT_EQ(0, urma_cmd_import_jetty_ex(&fixture.ctx, &tjetty, &tjettyCfg, &importJettyExCfg, &udata));
    EXPECT_EQ(0, urma_cmd_bind_jetty(&jetty, &tjetty, &udata));
    EXPECT_EQ(&tjetty, jetty.remote_jetty);
    EXPECT_EQ(0, urma_cmd_bind_jetty_ex(&jetty, &tjetty, &bindJettyExCfg, &udata));
    EXPECT_EQ(0, urma_cmd_unbind_jetty(&jetty));
    EXPECT_EQ(0, urma_cmd_create_jetty_grp(&fixture.ctx, &jettyGrp, &jettyGrpCfg, &udata));
    EXPECT_EQ(0, urma_cmd_import_jetty_async(&notifier, &tjetty, &tjettyCfg, 0x123, 0, &udata));
    EXPECT_EQ(0, urma_cmd_bind_jetty_async(&notifier, &jetty, &tjetty, 0x456, 0, &udata));
    EXPECT_EQ(0, urma_cmd_unbind_jetty_async(&jetty));

    EXPECT_EQ(0, urma_cmd_get_eid_list(17, 1, eidList, &eidCnt));
    EXPECT_EQ(0, eidCnt);
    EXPECT_EQ(0, urma_cmd_wait_jfc(17, 1, 0, jfcEvents));
    urma_cmd_ack_jfc(&jfcEvents[0], nevents, 1);
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &asyncEvent));
    asyncEvent.event_type = URMA_EVENT_JFC_ERR;
    asyncEvent.element.jfc = &jfc;
    urma_cmd_ack_async_event(&asyncEvent);
}

TEST(UrmaCoreTest, CmdWrappersSucceedForUpdateDeleteAndControlPaths)
{
    CmdIoctlFailureFixture fixture;
    urma_jfc_attr_t jfcAttr = {};
    urma_jfs_attr_t jfsAttr = {};
    urma_jfr_attr_t jfrAttr = {};
    urma_jetty_attr_t jettyAttr = {};
    urma_jfs_cfg_t jfsCfgOut = {};
    urma_jfr_cfg_t jfrCfgOut = {};
    urma_jetty_cfg_t jettyCfgOut = {};
    urma_jfc_t *jfcArr[1] = { nullptr };
    urma_jfs_t *jfsArr[1] = { nullptr };
    urma_jfr_t *jfrArr[1] = { nullptr };
    urma_jetty_t *jettyArr[1] = { nullptr };
    urma_jfc_t *badJfc = nullptr;
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;
    urma_jetty_t *badJetty = nullptr;
    urma_notify_t notify = {};
    urma_user_ctl_in_t ctlIn = {};
    urma_user_ctl_out_t ctlOut = {};
    urma_udrv_t udrv = {};
    urma_get_tp_cfg_t getTpCfg = {};
    urma_tp_info_t tpInfo = {};
    urma_tp_attr_value_t tpAttr = {};
    urma_jetty_grp_t jettyGrp = {};
    uint32_t tpCnt = 1;
    uint8_t tpAttrCnt = 1;
    uint32_t tpAttrBitmap = 1;
    uint64_t peerTpHandle = 0;
    uint32_t rxPsn = 0;
    uint32_t optValue = 4;

    ASSERT_TRUE(fixture.Init());
    SetCoreIoctlResult(0, 0);
    jfcArr[0] = &fixture.jfc;
    jfsArr[0] = &fixture.jfs;
    jfrArr[0] = &fixture.jfr;
    jettyArr[0] = &fixture.jetty;

    EXPECT_EQ(0, urma_cmd_free_token_id(&fixture.token));
    EXPECT_EQ(0, urma_cmd_unregister_seg(&fixture.tseg));
    EXPECT_EQ(0, urma_cmd_unimport_seg(&fixture.tseg));

    EXPECT_EQ(0, urma_cmd_modify_jfc(&fixture.jfc, &jfcAttr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_delete_jfc(&fixture.jfc));
    EXPECT_EQ(0, urma_cmd_delete_jfc_batch(jfcArr, 1, &badJfc));
    EXPECT_EQ(nullptr, badJfc);
    EXPECT_EQ(0, urma_cmd_alloc_jfc(&fixture.ctx, &fixture.jfc.jfc_cfg, &fixture.jfc, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_get_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_active_jfc(&fixture.jfc, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_deactive_jfc(&fixture.jfc, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_free_jfc(&fixture.jfc, &fixture.udata));

    EXPECT_EQ(0, urma_cmd_modify_jfs(&fixture.jfs, &jfsAttr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_query_jfs(&fixture.jfs, &jfsCfgOut, &jfsAttr));
    EXPECT_EQ(0, urma_cmd_delete_jfs(&fixture.jfs));
    EXPECT_EQ(0, urma_cmd_delete_jfs_batch(jfsArr, 1, &badJfs));
    EXPECT_EQ(nullptr, badJfs);
    EXPECT_EQ(0, urma_cmd_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_get_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_free_jfs(&fixture.jfs, &fixture.udata));

    EXPECT_EQ(0, urma_cmd_modify_jfr(&fixture.jfr, &jfrAttr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_query_jfr(&fixture.jfr, &jfrCfgOut, &jfrAttr));
    EXPECT_EQ(0, urma_cmd_delete_jfr(&fixture.jfr));
    EXPECT_EQ(0, urma_cmd_delete_jfr_batch(jfrArr, 1, &badJfr));
    EXPECT_EQ(nullptr, badJfr);
    EXPECT_EQ(0, urma_cmd_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_get_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &optValue, sizeof(optValue), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_free_jfr(&fixture.jfr, &fixture.udata));

    EXPECT_EQ(0, urma_cmd_modify_jetty(&fixture.jetty, &jettyAttr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_query_jetty(&fixture.jetty, &jettyCfgOut, &jettyAttr));
    EXPECT_EQ(URMA_SHARE_JFR, jettyCfgOut.flag.bs.share_jfr);
    EXPECT_EQ(0, urma_cmd_delete_jetty(&fixture.jetty));
    EXPECT_EQ(0, urma_cmd_delete_jetty_batch(jettyArr, 1, &badJetty));
    EXPECT_EQ(nullptr, badJetty);
    EXPECT_EQ(0, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &optValue, sizeof(optValue),
        &fixture.udata));
    fixture.jfc.handle = 0x7101;
    fixture.jfr.handle = 0x7102;
    jettyGrp.handle = 0x7103;
    fixture.jetty.jetty_cfg.shared.jfc = &fixture.jfc;
    fixture.jetty.jetty_cfg.shared.jfr = &fixture.jfr;
    fixture.jetty.jetty_cfg.jetty_grp = &jettyGrp;
    fixture.jetty.jetty_cfg.jfs_cfg.jfc = &fixture.jfc;
    EXPECT_EQ(0, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JETTY_BIND_RX_JFC, &optValue,
        sizeof(uint64_t), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JETTY_BIND_JFR, &optValue,
        sizeof(uint64_t), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JETTY_BIND_JTG, &optValue,
        sizeof(uint64_t), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JFS_BIND_JFC, &optValue,
        sizeof(uint64_t), &fixture.udata));
    EXPECT_EQ(0, urma_cmd_get_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &optValue, sizeof(optValue),
        &fixture.udata));
    EXPECT_EQ(0, urma_cmd_free_jetty(&fixture.jetty, &fixture.udata));

    EXPECT_EQ(0, urma_cmd_unimport_jfr(&fixture.tjfr));
    EXPECT_EQ(0, urma_cmd_advise_jfr(&fixture.jfs, &fixture.tjfr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_unadvise_jfr(&fixture.jfs, &fixture.tjfr));
    EXPECT_EQ(0, urma_cmd_unimport_jetty(&fixture.tjfr));
    EXPECT_EQ(0, urma_cmd_advise_jetty(&fixture.jetty, &fixture.tjfr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_unadvise_jetty(&fixture.jetty, &fixture.tjfr));
    EXPECT_EQ(1, urma_cmd_wait_notify(&fixture.notifier, 1, &notify, 0));
    EXPECT_EQ(0, urma_cmd_unimport_jetty_async(&fixture.tjfr));

    EXPECT_EQ(0, urma_cmd_user_ctl(&fixture.ctx, &ctlIn, &ctlOut, &udrv));
    EXPECT_EQ(0, urma_cmd_get_tp_list(&fixture.ctx, &getTpCfg, &tpCnt, &tpInfo, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_set_tp_attr(&fixture.ctx, 1, tpAttrCnt, tpAttrBitmap, &tpAttr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_get_tp_attr(&fixture.ctx, 1, &tpAttrCnt, &tpAttrBitmap, &tpAttr, &fixture.udata));
    EXPECT_EQ(0, urma_cmd_exchange_tp_info(&fixture.ctx, &getTpCfg, 1, 2, &peerTpHandle, &rxPsn));
}

TEST(UrmaCoreTest, CmdDestroyAndBatchFailureOutputsUseMockHardwareValues)
{
    CmdIoctlFailureFixture fixture;
    urma_jfc_t extraJfc = {};
    urma_jfs_t extraJfs = {};
    urma_jfr_t extraJfr = {};
    urma_jetty_t extraJetty = {};
    urma_jfc_t *jfcArr[2] = {};
    urma_jfs_t *jfsArr[2] = {};
    urma_jfr_t *jfrArr[2] = {};
    urma_jetty_t *jettyArr[2] = {};
    urma_jfc_t *badJfc = nullptr;
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;
    urma_jetty_t *badJetty = nullptr;

    ASSERT_TRUE(fixture.Init());
    extraJfc = fixture.jfc;
    extraJfc.handle = fixture.jfc.handle + 1;
    extraJfs = fixture.jfs;
    extraJfs.handle = fixture.jfs.handle + 1;
    extraJfr = fixture.jfr;
    extraJfr.handle = fixture.jfr.handle + 1;
    extraJetty = fixture.jetty;
    extraJetty.handle = fixture.jetty.handle + 1;
    jfcArr[0] = &fixture.jfc;
    jfcArr[1] = &extraJfc;
    jfsArr[0] = &fixture.jfs;
    jfsArr[1] = &extraJfs;
    jfrArr[0] = &fixture.jfr;
    jfrArr[1] = &extraJfr;
    jettyArr[0] = &fixture.jetty;
    jettyArr[1] = &extraJetty;

    SetCoreIoctlResult(EIO, 0);
    EXPECT_EQ(0, urma_cmd_free_token_id(&fixture.token));
    EXPECT_EQ(0, urma_cmd_unregister_seg(&fixture.tseg));
    EXPECT_EQ(0, urma_cmd_unimport_seg(&fixture.tseg));
    EXPECT_EQ(0, urma_cmd_delete_jfc(&fixture.jfc));
    EXPECT_EQ(0, urma_cmd_delete_jfs(&fixture.jfs));
    EXPECT_EQ(0, urma_cmd_delete_jfr(&fixture.jfr));
    EXPECT_EQ(EIO, urma_cmd_delete_jetty(&fixture.jetty));

    SetCoreIoctlResult(-1, EINVAL);
    g_coreBatchBadIndex = 1;
    EXPECT_EQ(-1, urma_cmd_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&extraJfc, badJfc);
    EXPECT_EQ(-1, urma_cmd_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&extraJfs, badJfs);
    EXPECT_EQ(-1, urma_cmd_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&extraJfr, badJfr);
    EXPECT_EQ(-1, urma_cmd_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&extraJetty, badJetty);

    g_coreBatchBadIndex = 9;
    badJfc = nullptr;
    badJfs = nullptr;
    badJfr = nullptr;
    badJetty = nullptr;
    EXPECT_EQ(-1, urma_cmd_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);
    EXPECT_EQ(-1, urma_cmd_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);
    EXPECT_EQ(-1, urma_cmd_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);
    EXPECT_EQ(-1, urma_cmd_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
}

TEST(UrmaCoreTest, CmdDeleteRejectsMixedDevicesAndReportsNonBlockingPendingEvents)
{
    CmdIoctlFailureFixture fixture;
    urma_context_t otherCtx = {};
    urma_jfc_t extraJfc = {};
    urma_jfs_t extraJfs = {};
    urma_jfr_t extraJfr = {};
    urma_jfc_t invalidJfc = {};
    urma_jfs_t invalidJfs = {};
    urma_jfr_t invalidJfr = {};
    urma_jfc_t *jfcArr[2] = {};
    urma_jfs_t *jfsArr[2] = {};
    urma_jfr_t *jfrArr[2] = {};
    urma_jfc_t *badJfc = nullptr;
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;

    ASSERT_TRUE(fixture.Init());
    otherCtx.dev = fixture.ctx.dev;
    otherCtx.ops = fixture.ctx.ops;
    otherCtx.eid = fixture.ctx.eid;
    otherCtx.uasid = fixture.ctx.uasid;
    otherCtx.eid_index = fixture.ctx.eid_index;
    otherCtx.dev_fd = fixture.pipeFd[1];
    extraJfc = fixture.jfc;
    extraJfc.urma_ctx = &otherCtx;
    extraJfs = fixture.jfs;
    extraJfs.urma_ctx = &otherCtx;
    extraJfr = fixture.jfr;
    extraJfr.urma_ctx = &otherCtx;

    jfcArr[0] = &fixture.jfc;
    jfcArr[1] = &extraJfc;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);

    jfsArr[0] = &fixture.jfs;
    jfsArr[1] = &extraJfs;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);

    jfrArr[0] = &fixture.jfr;
    jfrArr[1] = &extraJfr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);

    invalidJfc = fixture.jfc;
    invalidJfs = fixture.jfs;
    invalidJfr = fixture.jfr;
    invalidJfc.urma_ctx = &otherCtx;
    invalidJfs.urma_ctx = &otherCtx;
    invalidJfr.urma_ctx = &otherCtx;
    otherCtx.dev_fd = -1;
    jfcArr[0] = &invalidJfc;
    jfsArr[0] = &invalidJfs;
    jfrArr[0] = &invalidJfr;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfc_batch(jfcArr, 1, &badJfc));
    EXPECT_EQ(&invalidJfc, badJfc);
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfs_batch(jfsArr, 1, &badJfs));
    EXPECT_EQ(&invalidJfs, badJfs);
    EXPECT_EQ(URMA_EINVAL, urma_cmd_delete_jfr_batch(jfrArr, 1, &badJfr));
    EXPECT_EQ(&invalidJfr, badJfr);

    SetCoreIoctlResult(0, 0);
    fixture.jfc.jfc_cfg.flag.bs.non_blocking = 1;
    fixture.jfc.async_events_acked = 1;
    EXPECT_EQ(URMA_EAGAIN, urma_cmd_delete_jfc(&fixture.jfc));

    fixture.jfs.jfs_cfg.flag.bs.non_blocking = 1;
    fixture.jfs.async_events_acked = 1;
    EXPECT_EQ(URMA_EAGAIN, urma_cmd_delete_jfs(&fixture.jfs));
}

TEST(UrmaCoreTest, CmdQueryJettyCoversSharedAndPrivateReceiveConfigs)
{
    CmdIoctlFailureFixture fixture;
    urma_jetty_cfg_t outCfg = {};
    urma_jfr_cfg_t privateJfrCfg = {};
    urma_jetty_attr_t attr = {};

    ASSERT_TRUE(fixture.Init());
    SetCoreIoctlResult(0, 0);

    g_coreQueryJettyFlag = URMA_SHARE_JFR;
    EXPECT_EQ(0, urma_cmd_query_jetty(&fixture.jetty, &outCfg, &attr));
    EXPECT_EQ(URMA_SHARE_JFR, outCfg.flag.bs.share_jfr);
    EXPECT_EQ(fixture.jetty.jetty_cfg.shared.jfr, outCfg.shared.jfr);
    EXPECT_EQ(fixture.jetty.jetty_cfg.shared.jfc, outCfg.shared.jfc);
    EXPECT_EQ(1U, attr.rx_threshold);

    g_coreQueryJettyFlag = URMA_NO_SHARE_JFR;
    outCfg = {};
    EXPECT_EQ(-1, urma_cmd_query_jetty(&fixture.jetty, &outCfg, &attr));

    fixture.jetty.jetty_cfg.flag.bs.share_jfr = URMA_NO_SHARE_JFR;
    fixture.jetty.jetty_cfg.jfr_cfg = &fixture.jfr.jfr_cfg;
    outCfg = {};
    outCfg.jfr_cfg = &privateJfrCfg;
    EXPECT_EQ(0, urma_cmd_query_jetty(&fixture.jetty, &outCfg, &attr));
    EXPECT_EQ(URMA_NO_SHARE_JFR, outCfg.flag.bs.share_jfr);
    EXPECT_EQ(1U, outCfg.jfr_cfg->depth);
    EXPECT_EQ(0x779U, outCfg.jfr_cfg->id);
    EXPECT_EQ(0x77aU, outCfg.jfr_cfg->token_value.token);
    EXPECT_EQ(fixture.jfr.jfr_cfg.jfc, outCfg.jfr_cfg->jfc);
}

TEST(UrmaCoreTest, CmdNetworkLookupWrappersValidateAndCopyIoctlOutputs)
{
    CoreApiFixture fixture;
    urma_net_addr_t netAddr = {};
    urma_eid_t eid = {};
    uint8_t smac[URMA_MAC_BYTES] = {};
    uint8_t dmac[URMA_MAC_BYTES] = {};

    fixture.ctx.dev_fd = 17;
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_eid_by_ip(nullptr, &netAddr, &eid));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_eid_by_ip(&fixture.ctx, nullptr, &eid));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_eid_by_ip(&fixture.ctx, &netAddr, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_ip_by_eid(nullptr, &eid, &netAddr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_ip_by_eid(&fixture.ctx, nullptr, &netAddr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_ip_by_eid(&fixture.ctx, &eid, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_smac(nullptr, smac));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_smac(&fixture.ctx, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_dmac(nullptr, &netAddr, dmac));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_dmac(&fixture.ctx, nullptr, dmac));
    EXPECT_EQ(URMA_EINVAL, urma_cmd_get_dmac(&fixture.ctx, &netAddr, nullptr));

    SetCoreIoctlResult(-1, ENOTTY);
    EXPECT_EQ(-1, urma_cmd_get_eid_by_ip(&fixture.ctx, &netAddr, &eid));
    EXPECT_EQ(-1, urma_cmd_get_ip_by_eid(&fixture.ctx, &eid, &netAddr));
    EXPECT_EQ(-1, urma_cmd_get_smac(&fixture.ctx, smac));
    EXPECT_EQ(-1, urma_cmd_get_dmac(&fixture.ctx, &netAddr, dmac));

    SetCoreIoctlResult(0, 0);
    EXPECT_EQ(0, urma_cmd_get_eid_by_ip(&fixture.ctx, &netAddr, &eid));
    EXPECT_NE(0U, eid.raw[0]);
    EXPECT_EQ(0, urma_cmd_get_ip_by_eid(&fixture.ctx, &eid, &netAddr));
    EXPECT_EQ(0, urma_cmd_get_smac(&fixture.ctx, smac));
    EXPECT_EQ(0x30U, smac[0]);
    EXPECT_EQ(0, urma_cmd_get_dmac(&fixture.ctx, &netAddr, dmac));
    EXPECT_EQ(0x40U, dmac[0]);
}

TEST(UrmaCoreTest, CmdAsyncEventsMapAndAckAllStableObjectTypes)
{
    CmdIoctlFailureFixture fixture;
    urma_async_event_t event = {};
    urma_jetty_grp_t jettyGrp = {};

    ASSERT_TRUE(fixture.Init());
    ASSERT_EQ(0, pthread_mutex_init(&jettyGrp.event_mutex, nullptr));
    ASSERT_EQ(0, pthread_cond_init(&jettyGrp.event_cond, nullptr));
    SetCoreIoctlResult(0, 0);

    event.event_type = URMA_EVENT_JFC_ERR;
    event.element.jfc = &fixture.jfc;
    urma_cmd_ack_async_event(&event);
    EXPECT_EQ(1U, fixture.jfc.async_events_acked);

    event.event_type = URMA_EVENT_JFS_ERR;
    event.element.jfs = &fixture.jfs;
    urma_cmd_ack_async_event(&event);
    EXPECT_EQ(1U, fixture.jfs.async_events_acked);

    event.event_type = URMA_EVENT_JFR_LIMIT;
    event.element.jfr = &fixture.jfr;
    urma_cmd_ack_async_event(&event);
    EXPECT_EQ(1U, fixture.jfr.async_events_acked);

    event.event_type = URMA_EVENT_JETTY_LIMIT;
    event.element.jetty = &fixture.jetty;
    urma_cmd_ack_async_event(&event);
    EXPECT_EQ(1U, fixture.jetty.async_events_acked);

    event.event_type = URMA_EVENT_JETTY_GRP_ERR;
    event.element.jetty_grp = &jettyGrp;
    urma_cmd_ack_async_event(&event);
    EXPECT_EQ(1U, jettyGrp.async_events_acked);

    g_coreAsyncEventType = URMA_EVENT_JFC_ERR;
    g_coreAsyncEventData = reinterpret_cast<uint64_t>(&fixture.jfc);
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(&fixture.jfc, event.element.jfc);

    g_coreAsyncEventType = URMA_EVENT_JFS_ERR;
    g_coreAsyncEventData = reinterpret_cast<uint64_t>(&fixture.jfs);
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(&fixture.jfs, event.element.jfs);

    g_coreAsyncEventType = URMA_EVENT_JFR_ERR;
    g_coreAsyncEventData = reinterpret_cast<uint64_t>(&fixture.jfr);
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(&fixture.jfr, event.element.jfr);

    g_coreAsyncEventType = URMA_EVENT_JETTY_ERR;
    g_coreAsyncEventData = reinterpret_cast<uint64_t>(&fixture.jetty);
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(&fixture.jetty, event.element.jetty);

    g_coreAsyncEventType = URMA_EVENT_JETTY_GRP_ERR;
    g_coreAsyncEventData = reinterpret_cast<uint64_t>(&jettyGrp);
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(&jettyGrp, event.element.jetty_grp);

    g_coreAsyncEventType = URMA_EVENT_PORT_DOWN;
    g_coreAsyncEventData = 3;
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(3U, event.element.port_id);

    g_coreAsyncEventType = URMA_EVENT_DEV_FATAL;
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));

    g_coreAsyncEventType = URMA_EVENT_EID_CHANGE;
    g_coreAsyncEventData = 5;
    EXPECT_EQ(URMA_SUCCESS, urma_cmd_get_async_event(&fixture.ctx, &event));
    EXPECT_EQ(5U, event.element.eid_idx);

    g_coreAsyncEventType = UINT32_MAX;
    EXPECT_EQ(URMA_FAIL, urma_cmd_get_async_event(&fixture.ctx, &event));

    (void)pthread_cond_destroy(&jettyGrp.event_cond);
    (void)pthread_mutex_destroy(&jettyGrp.event_mutex);
}
