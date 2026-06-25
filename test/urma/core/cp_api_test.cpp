/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core control-plane API unit tests.
 */

#include "core_fixture.h"

using namespace urma_test_core;

TEST(UrmaCoreTest, CpApiJfcValidatesInputsAndDispatchesOps)
{
    CoreApiFixture fixture;
    urma_jfc_cfg_t cfg = {};
    urma_jfc_attr_t attr = {};
    urma_jfc_t *badJfc = nullptr;

    cfg.depth = 4;
    cfg.jfce = &fixture.jfce;
    EXPECT_EQ(nullptr, urma_create_jfc(nullptr, &cfg));
    EXPECT_EQ(nullptr, urma_create_jfc(&fixture.ctx, nullptr));
    EXPECT_EQ(nullptr, urma_create_jfc(&fixture.ctx, &cfg));

    fixture.ops.create_jfc = MockCreateJfc;
    cfg.depth = 0;
    EXPECT_EQ(nullptr, urma_create_jfc(&fixture.ctx, &cfg));
    cfg.depth = 4;
    urma_jfc_t *created = urma_create_jfc(&fixture.ctx, &cfg);
    ASSERT_NE(nullptr, created);
    EXPECT_TRUE(created->urma_jfc_opt.is_actived);
    EXPECT_EQ(2UL, fixture.ctx.ref.atomic_cnt.load());
    EXPECT_EQ(1UL, fixture.jfce.ref.atomic_cnt.load());

    EXPECT_EQ(URMA_EINVAL, urma_modify_jfc(nullptr, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jfc(&fixture.jfc, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jfc(&fixture.jfc, &attr));
    fixture.ops.modify_jfc = MockModifyJfc;
    EXPECT_EQ(URMA_SUCCESS, urma_modify_jfc(&fixture.jfc, &attr));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc(nullptr));
    fixture.jfc.urma_jfc_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc(&fixture.jfc));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc(&fixture.jfc));
    fixture.ops.delete_jfc = MockDeleteJfc;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfc(&fixture.jfc));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc_batch(nullptr, 1, &badJfc));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc_batch(&created, 0, &badJfc));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc_batch(&created, 1, nullptr));
    fixture.ops.delete_jfc_batch = MockDeleteJfcBatch;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfc_batch(&created, 1, &badJfc));
    EXPECT_EQ(nullptr, badJfc);
}

TEST(UrmaCoreTest, CpApiJfsValidatesStateAndPropagatesOps)
{
    CoreApiFixture fixture;
    urma_jfs_cfg_t cfg = {};
    urma_jfs_attr_t attr = {};
    urma_jfs_t *jfsArr[2] = { &fixture.jfs, nullptr };
    urma_jfs_t *badJfs = nullptr;
    urma_cr_t cr = {};

    EXPECT_EQ(nullptr, urma_create_jfs(nullptr, &cfg));
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, nullptr));
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &cfg));
    cfg.jfc = &fixture.jfc;
    cfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &cfg));

    EXPECT_EQ(URMA_EINVAL, urma_modify_jfs(nullptr, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jfs(&fixture.jfs, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jfs(&fixture.jfs, &attr));
    fixture.ops.modify_jfs = MockModifyJfs;
    EXPECT_EQ(URMA_ENOPERM, urma_modify_jfs(&fixture.jfs, &attr));

    EXPECT_EQ(URMA_EINVAL, urma_query_jfs(nullptr, &cfg, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jfs(&fixture.jfs, nullptr, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jfs(&fixture.jfs, &cfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jfs(&fixture.jfs, &cfg, &attr));
    fixture.ops.query_jfs = MockQueryJfs;
    EXPECT_EQ(URMA_SUCCESS, urma_query_jfs(&fixture.jfs, &cfg, &attr));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jfs(nullptr));
    fixture.jfs.urma_jfs_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfs(&fixture.jfs));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jfs_batch(nullptr, 1, &badJfs));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);
    jfsArr[1] = &fixture.jfs;
    fixture.ops.delete_jfs_batch = MockDeleteJfsBatch;
    EXPECT_EQ(URMA_FAIL, urma_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);
    fixture.ctx.ref.atomic_cnt.store(3);
    fixture.ops.delete_jfs_batch = MockDeleteJfsBatchSuccess;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(nullptr, badJfs);
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());

    fixture.jfs.jfs_cfg.depth = 1;
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), urma_flush_jfs(nullptr, 1, &cr));
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), urma_flush_jfs(&fixture.jfs, 0, &cr));
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), urma_flush_jfs(&fixture.jfs, 1, nullptr));
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), urma_flush_jfs(&fixture.jfs, 2, &cr));
    fixture.ops.flush_jfs = MockFlushJfs;
    EXPECT_EQ(1, urma_flush_jfs(&fixture.jfs, 1, &cr));
}

TEST(UrmaCoreTest, CpApiJfrValidatesInputsAndPropagatesOps)
{
    CoreApiFixture fixture;
    urma_jfr_cfg_t cfg = {};
    urma_jfr_attr_t attr = {};
    urma_jfr_t *jfrArr[2] = { &fixture.jfr, nullptr };
    urma_jfr_t *badJfr = nullptr;

    EXPECT_EQ(nullptr, urma_create_jfr(nullptr, &cfg));
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, nullptr));
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &cfg));
    cfg.jfc = &fixture.jfc;
    cfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &cfg));

    EXPECT_EQ(URMA_EINVAL, urma_modify_jfr(nullptr, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jfr(&fixture.jfr, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jfr(&fixture.jfr, &attr));
    fixture.ops.modify_jfr = MockModifyJfr;
    EXPECT_EQ(URMA_SUCCESS, urma_modify_jfr(&fixture.jfr, &attr));

    EXPECT_EQ(URMA_EINVAL, urma_query_jfr(nullptr, &cfg, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jfr(&fixture.jfr, nullptr, &attr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jfr(&fixture.jfr, &cfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jfr(&fixture.jfr, &cfg, &attr));
    fixture.ops.query_jfr = MockQueryJfr;
    EXPECT_EQ(URMA_EAGAIN, urma_query_jfr(&fixture.jfr, &cfg, &attr));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jfr(nullptr));
    fixture.jfr.urma_jfr_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfr(&fixture.jfr));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jfr_batch(nullptr, 1, &badJfr));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);
    jfrArr[1] = &fixture.jfr;
    fixture.ops.delete_jfr_batch = MockDeleteJfrBatchStatus;
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, urma_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);
    fixture.ctx.ref.atomic_cnt.store(3);
    fixture.ops.delete_jfr_batch = MockDeleteJfrBatchSuccess;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(nullptr, badJfr);
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());
}

TEST(UrmaCoreTest, CpApiJfsJfrCreateAndActiveCoverStableBoundaryBranches)
{
    CoreApiFixture fixture;
    urma_jfs_cfg_t jfsCfg = fixture.jfs.jfs_cfg;
    urma_jfr_cfg_t jfrCfg = fixture.jfr.jfr_cfg;

    fixture.ops.create_jfs = MockCreateJfs;
    jfsCfg.flag.bs.order_type = URMA_OT;
    jfsCfg.trans_mode = URMA_TM_RM;
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &jfsCfg));
    jfsCfg.trans_mode = URMA_TM_RC;
    jfsCfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_depth + 1;
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &jfsCfg));
    jfsCfg.depth = 4;
    jfsCfg.max_inline_data = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_inline_len + 1;
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &jfsCfg));
    jfsCfg.max_inline_data = 0;
    fixture.ops.create_jfs = MockCreateJfsNull;
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &jfsCfg));
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());
    fixture.ops.create_jfs = MockCreateJfs;
    urma_jfs_t *createdJfs = urma_create_jfs(&fixture.ctx, &jfsCfg);
    ASSERT_NE(nullptr, createdJfs);
    EXPECT_TRUE(createdJfs->urma_jfs_opt.is_actived);
    EXPECT_EQ(2UL, fixture.ctx.ref.atomic_cnt.load());

    fixture.jfs.urma_jfs_opt.is_actived = false;
    fixture.jfc.urma_jfc_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfs(&fixture.jfs));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.jfs.jfs_cfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(URMA_EINVAL, urma_active_jfs(&fixture.jfs));
    fixture.jfs.jfs_cfg.trans_mode = URMA_TM_RM;
    fixture.jfs.jfs_cfg.flag.bs.order_type = URMA_OT;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfs(&fixture.jfs));
    fixture.jfs.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.jfs.jfs_cfg.flag.bs.order_type = URMA_NO;
    fixture.jfs.jfs_cfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_depth + 1;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfs(&fixture.jfs));
    fixture.jfs.jfs_cfg.depth = 4;
    fixture.ops.active_jfs = MockJfsStatus;
    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(URMA_FAIL, urma_active_jfs(&fixture.jfs));
    urma_test::SetHwMockStatus(URMA_SUCCESS);
    EXPECT_EQ(URMA_SUCCESS, urma_active_jfs(&fixture.jfs));

    fixture.ops.create_jfr = MockCreateJfr;
    jfrCfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &jfrCfg));
    jfrCfg.trans_mode = URMA_TM_RC;
    jfrCfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfr_depth + 1;
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &jfrCfg));
    jfrCfg.depth = 4;
    jfrCfg.max_sge = fixture.sysfsDev.dev_attr.dev_cap.max_jfr_sge + 1;
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &jfrCfg));
    jfrCfg.max_sge = 1;
    fixture.ops.create_jfr = MockCreateJfrNull;
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &jfrCfg));
    fixture.ops.create_jfr = MockCreateJfr;
    urma_jfr_t *createdJfr = urma_create_jfr(&fixture.ctx, &jfrCfg);
    ASSERT_NE(nullptr, createdJfr);
    EXPECT_TRUE(createdJfr->urma_jfr_opt.is_actived);

    fixture.jfr.urma_jfr_opt.is_actived = false;
    fixture.jfr.jfr_cfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(URMA_EINVAL, urma_active_jfr(&fixture.jfr));
    fixture.jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.jfr.jfr_cfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfr_depth + 1;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfr(&fixture.jfr));
    fixture.jfr.jfr_cfg.depth = 4;
    fixture.jfc.urma_jfc_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfr(&fixture.jfr));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.ops.active_jfr = MockJfrStatus;
    urma_test::SetHwMockStatus(URMA_FAIL);
    EXPECT_EQ(URMA_FAIL, urma_active_jfr(&fixture.jfr));
    urma_test::SetHwMockStatus(URMA_SUCCESS);
    EXPECT_EQ(URMA_SUCCESS, urma_active_jfr(&fixture.jfr));
}

TEST(UrmaCoreTest, CpApiInactiveJfcJfsJfrApisValidateAndDispatch)
{
    CoreApiFixture fixture;
    uint32_t depth = 4;
    urma_jfc_cfg_t jfcCfg = fixture.jfc.jfc_cfg;
    urma_jfc_t *createdJfc = nullptr;
    urma_jfs_cfg_t jfsCfg = fixture.jfs.jfs_cfg;
    urma_jfs_t *createdJfs = nullptr;
    urma_jfr_cfg_t jfrCfg = fixture.jfr.jfr_cfg;
    urma_jfr_t *createdJfr = nullptr;

    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfc(nullptr, &jfcCfg, &createdJfc));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfc(&fixture.ctx, nullptr, &createdJfc));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfc(&fixture.ctx, &jfcCfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfc(&fixture.ctx, &jfcCfg, &createdJfc));
    fixture.ops.alloc_jfc = MockAllocJfc;
    EXPECT_EQ(URMA_SUCCESS, urma_alloc_jfc(&fixture.ctx, &jfcCfg, &createdJfc));
    ASSERT_NE(nullptr, createdJfc);

    EXPECT_EQ(URMA_EINVAL, urma_set_jfc_opt(nullptr, URMA_JFC_DEPTH, &depth, sizeof(depth)));
    fixture.jfc.urma_jfc_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, nullptr, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, 0));
    fixture.ops.set_jfc_opt = MockJfcOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_get_jfc_opt(&fixture.jfc, 0, &depth, sizeof(depth)));
    fixture.ops.get_jfc_opt = MockJfcOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_get_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, sizeof(depth)));

    EXPECT_EQ(URMA_EINVAL, urma_active_jfc(nullptr));
    fixture.ops.active_jfc = MockJfcStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_active_jfc(&fixture.jfc));
    EXPECT_TRUE(fixture.jfc.urma_jfc_opt.is_actived);
    fixture.ops.deactive_jfc = MockJfcStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_deactive_jfc(&fixture.jfc));
    fixture.ops.free_jfc = MockJfcStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_free_jfc(&fixture.jfc));

    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfs(nullptr, &jfsCfg, &createdJfs));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfs(&fixture.ctx, nullptr, &createdJfs));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfs(&fixture.ctx, &jfsCfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfs(&fixture.ctx, &jfsCfg, &createdJfs));
    fixture.ops.alloc_jfs = MockAllocJfs;
    EXPECT_EQ(URMA_SUCCESS, urma_alloc_jfs(&fixture.ctx, &jfsCfg, &createdJfs));
    ASSERT_NE(nullptr, createdJfs);

    fixture.jfs.urma_jfs_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, nullptr, sizeof(depth)));
    fixture.ops.set_jfs_opt = MockJfsOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_get_jfs_opt(&fixture.jfs, 0, &depth, sizeof(depth)));
    fixture.ops.get_jfs_opt = MockJfsOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_get_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.ops.active_jfs = MockJfsStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_active_jfs(&fixture.jfs));
    fixture.ops.deactive_jfs = MockJfsStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_deactive_jfs(&fixture.jfs));
    fixture.ops.free_jfs = MockJfsStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_free_jfs(&fixture.jfs));

    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfr(nullptr, &jfrCfg, &createdJfr));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfr(&fixture.ctx, nullptr, &createdJfr));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfr(&fixture.ctx, &jfrCfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jfr(&fixture.ctx, &jfrCfg, &createdJfr));
    fixture.ops.alloc_jfr = MockAllocJfr;
    EXPECT_EQ(URMA_SUCCESS, urma_alloc_jfr(&fixture.ctx, &jfrCfg, &createdJfr));
    ASSERT_NE(nullptr, createdJfr);

    fixture.jfr.urma_jfr_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, nullptr, sizeof(depth)));
    fixture.ops.set_jfr_opt = MockJfrOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &depth, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_get_jfr_opt(&fixture.jfr, 0, &depth, sizeof(depth)));
    fixture.ops.get_jfr_opt = MockJfrOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_get_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &depth, sizeof(depth)));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.ops.active_jfr = MockJfrStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_active_jfr(&fixture.jfr));
    fixture.ops.deactive_jfr = MockJfrStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_deactive_jfr(&fixture.jfr));
    fixture.ops.free_jfr = MockJfrStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_free_jfr(&fixture.jfr));
}

TEST(UrmaCoreTest, CpApiSegmentAndTokenApisValidateAndDispatch)
{
    CoreApiFixture fixture;
    urma_token_id_flag_t tokenFlag = {};
    urma_seg_cfg_t segCfg = {};
    urma_token_t tokenValue = {};
    urma_import_seg_flag_t importFlag = {};

    EXPECT_EQ(nullptr, urma_alloc_token_id(nullptr));
    EXPECT_EQ(nullptr, urma_alloc_token_id(&fixture.ctx));
    fixture.ops.alloc_token_id = MockAllocTokenId;
    urma_token_id_t *token = urma_alloc_token_id(&fixture.ctx);
    ASSERT_NE(nullptr, token);
    EXPECT_EQ(2UL, fixture.ctx.ref.atomic_cnt.load());

    tokenFlag.bs.multi_seg = 1;
    fixture.ops.alloc_token_id_ex = MockAllocTokenIdEx;
    EXPECT_EQ(nullptr, urma_alloc_token_id_ex(&fixture.ctx, tokenFlag));
    fixture.sysfsDev.dev_attr.dev_cap.feature.bs.muti_seg_per_token_id = 1;
    EXPECT_NE(nullptr, urma_alloc_token_id_ex(&fixture.ctx, tokenFlag));

    EXPECT_EQ(URMA_EINVAL, urma_free_token_id(nullptr));
    fixture.token.ref.atomic_cnt.store(1);
    EXPECT_EQ(URMA_EINVAL, urma_free_token_id(&fixture.token));
    fixture.token.ref.atomic_cnt.store(0);
    EXPECT_EQ(URMA_EINVAL, urma_free_token_id(&fixture.token));
    fixture.ops.free_token_id = MockFreeTokenId;
    EXPECT_EQ(URMA_SUCCESS, urma_free_token_id(&fixture.token));

    EXPECT_EQ(nullptr, urma_import_seg(nullptr, &fixture.seg, &tokenValue, 0, importFlag));
    fixture.seg.attr.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    EXPECT_EQ(nullptr, urma_import_seg(&fixture.ctx, &fixture.seg, nullptr, 0, importFlag));
    fixture.seg.attr.bs.token_policy = URMA_TOKEN_NONE;
    EXPECT_EQ(nullptr, urma_import_seg(&fixture.ctx, &fixture.seg, nullptr, 0, importFlag));
    fixture.ops.import_seg = MockImportSeg;
    EXPECT_NE(nullptr, urma_import_seg(&fixture.ctx, &fixture.seg, nullptr, 0, importFlag));

    EXPECT_EQ(URMA_EINVAL, urma_unimport_seg(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_seg(&fixture.tseg));
    fixture.ops.unimport_seg = MockUnimportSeg;
    EXPECT_EQ(URMA_SUCCESS, urma_unimport_seg(&fixture.tseg));

    EXPECT_EQ(nullptr, urma_register_seg(nullptr, &segCfg));
    EXPECT_EQ(nullptr, urma_register_seg(&fixture.ctx, nullptr));
    EXPECT_EQ(nullptr, urma_register_seg(&fixture.ctx, &segCfg));
    segCfg.va = 0x1000;
    EXPECT_EQ(nullptr, urma_register_seg(&fixture.ctx, &segCfg));
    fixture.ops.register_seg = MockRegisterSeg;
    EXPECT_NE(nullptr, urma_register_seg(&fixture.ctx, &segCfg));

    EXPECT_EQ(URMA_EINVAL, urma_unregister_seg(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_unregister_seg(&fixture.tseg));
    fixture.ops.unregister_seg = MockUnregisterSeg;
    EXPECT_EQ(URMA_SUCCESS, urma_unregister_seg(&fixture.tseg));
}

TEST(UrmaCoreTest, CpApiMiscControlApisValidateAndDispatch)
{
    CoreApiFixture fixture;
    urma_async_event_t event = {};
    urma_user_ctl_in_t ctlIn = {};
    urma_user_ctl_out_t ctlOut = {};
    urma_tp_cfg_t tpCfg = {};
    urma_tp_attr_t tpAttr = {};
    urma_tp_attr_mask_t tpMask = {};
    urma_get_tp_cfg_t getTpCfg = {};
    urma_tp_info_t tpInfo = {};
    urma_tp_attr_value_t tpAttrValue = {};
    uint32_t tpCnt = 1;
    uint8_t tpAttrCnt = 1;
    uint32_t tpAttrBitmap = 0;
    urma_net_addr_t netAddr = {};
    urma_eid_t eid = {};
    uint8_t mac[6] = {};

    EXPECT_EQ(URMA_EINVAL, urma_get_async_event(nullptr, &event));
    EXPECT_EQ(URMA_EINVAL, urma_get_async_event(&fixture.ctx, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_get_async_event(&fixture.ctx, &event));
    fixture.ops.get_async_event = MockGetAsyncEvent;
    EXPECT_EQ(URMA_SUCCESS, urma_get_async_event(&fixture.ctx, &event));
    urma_ack_async_event(nullptr);
    event.urma_ctx = &fixture.ctx;
    urma_ack_async_event(&event);
    fixture.ops.ack_async_event = MockAckAsyncEvent;
    urma_ack_async_event(&event);

    EXPECT_EQ(URMA_EINVAL, urma_user_ctl(nullptr, &ctlIn, &ctlOut));
    EXPECT_EQ(URMA_EINVAL, urma_user_ctl(&fixture.ctx, nullptr, &ctlOut));
    EXPECT_EQ(URMA_EINVAL, urma_user_ctl(&fixture.ctx, &ctlIn, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_user_ctl(&fixture.ctx, &ctlIn, &ctlOut));
    fixture.ops.user_ctl = MockUserCtl;
    EXPECT_EQ(URMA_ENOPERM, urma_user_ctl(&fixture.ctx, &ctlIn, &ctlOut));

    EXPECT_EQ(URMA_EINVAL, urma_modify_tp(nullptr, 1, &tpCfg, &tpAttr, tpMask));
    EXPECT_EQ(URMA_EINVAL, urma_modify_tp(&fixture.ctx, 1, nullptr, &tpAttr, tpMask));
    EXPECT_EQ(URMA_EINVAL, urma_modify_tp(&fixture.ctx, 1, &tpCfg, nullptr, tpMask));
    EXPECT_EQ(URMA_EINVAL, urma_modify_tp(&fixture.ctx, 1, &tpCfg, &tpAttr, tpMask));
    fixture.ops.modify_tp = MockModifyTp;
    EXPECT_EQ(URMA_SUCCESS, urma_modify_tp(&fixture.ctx, 1, &tpCfg, &tpAttr, tpMask));

    EXPECT_EQ(URMA_EINVAL, urma_get_tp_list(nullptr, &getTpCfg, &tpCnt, &tpInfo));
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_list(&fixture.ctx, nullptr, &tpCnt, &tpInfo));
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_list(&fixture.ctx, &getTpCfg, nullptr, &tpInfo));
    tpCnt = 0;
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_list(&fixture.ctx, &getTpCfg, &tpCnt, &tpInfo));
    tpCnt = 1;
    getTpCfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_list(&fixture.ctx, &getTpCfg, &tpCnt, &tpInfo));
    getTpCfg.trans_mode = URMA_TM_RC;
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_list(&fixture.ctx, &getTpCfg, &tpCnt, &tpInfo));
    fixture.ops.get_tp_list = MockGetTpList;
    EXPECT_EQ(URMA_SUCCESS, urma_get_tp_list(&fixture.ctx, &getTpCfg, &tpCnt, &tpInfo));

    EXPECT_EQ(URMA_EINVAL, urma_set_tp_attr(nullptr, 1, 1, 0, &tpAttrValue));
    EXPECT_EQ(URMA_EINVAL, urma_set_tp_attr(&fixture.ctx, 1, 1, 0, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_set_tp_attr(&fixture.ctx, 1, 1, 0, &tpAttrValue));
    fixture.ops.set_tp_attr = MockSetTpAttr;
    EXPECT_EQ(URMA_SUCCESS, urma_set_tp_attr(&fixture.ctx, 1, 1, 1U << 16, &tpAttrValue));

    EXPECT_EQ(URMA_EINVAL, urma_get_tp_attr(nullptr, 1, &tpAttrCnt, &tpAttrBitmap, &tpAttrValue));
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_attr(&fixture.ctx, 1, nullptr, &tpAttrBitmap, &tpAttrValue));
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_attr(&fixture.ctx, 1, &tpAttrCnt, nullptr, &tpAttrValue));
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_attr(&fixture.ctx, 1, &tpAttrCnt, &tpAttrBitmap, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_get_tp_attr(&fixture.ctx, 1, &tpAttrCnt, &tpAttrBitmap, &tpAttrValue));
    fixture.ops.get_tp_attr = MockGetTpAttr;
    EXPECT_EQ(URMA_SUCCESS, urma_get_tp_attr(&fixture.ctx, 1, &tpAttrCnt, &tpAttrBitmap, &tpAttrValue));

    EXPECT_EQ(URMA_EINVAL, urma_get_eid_by_ip(nullptr, &netAddr, &eid));
    EXPECT_EQ(URMA_EINVAL, urma_get_ip_by_eid(&fixture.ctx, nullptr, &netAddr));
    EXPECT_EQ(URMA_EINVAL, urma_get_smac(&fixture.ctx, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_get_dmac(&fixture.ctx, &netAddr, nullptr));
    fixture.ops.get_eid_by_ip = MockGetEidByIp;
    fixture.ops.get_ip_by_eid = MockGetIpByEid;
    fixture.ops.get_smac = MockGetSmac;
    fixture.ops.get_dmac = MockGetDmac;
    EXPECT_EQ(URMA_SUCCESS, urma_get_eid_by_ip(&fixture.ctx, &netAddr, &eid));
    EXPECT_EQ(URMA_SUCCESS, urma_get_ip_by_eid(&fixture.ctx, &eid, &netAddr));
    EXPECT_EQ(URMA_SUCCESS, urma_get_smac(&fixture.ctx, mac));
    EXPECT_EQ(URMA_SUCCESS, urma_get_dmac(&fixture.ctx, &netAddr, mac));
}

TEST(UrmaCoreTest, CpApiJettyAndJfceApisValidateAndDispatch)
{
    CoreApiFixture fixture;
    urma_jetty_cfg_t jettyCfg = fixture.jetty.jetty_cfg;
    urma_jetty_attr_t jettyAttr = {};
    urma_jetty_t *jettyArr[2] = { &fixture.jetty, nullptr };
    urma_jetty_t *badJetty = nullptr;
    urma_jetty_t *createdJetty = nullptr;
    urma_cr_t cr = {};
    uint32_t depth = 4;
    urma_jetty_grp_t jettyGrp = {};

    jettyCfg.flag.bs.share_jfr = URMA_SHARE_JFR;
    EXPECT_EQ(nullptr, urma_create_jfce(nullptr));
    EXPECT_EQ(nullptr, urma_create_jfce(&fixture.ctx));
    fixture.ops.create_jfce = MockCreateJfce;
    urma_jfce_t *createdJfce = urma_create_jfce(&fixture.ctx);
    ASSERT_NE(nullptr, createdJfce);
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfce(nullptr));
    createdJfce->ref.atomic_cnt.store(2);
    EXPECT_EQ(URMA_FAIL, urma_delete_jfce(createdJfce));
    createdJfce->ref.atomic_cnt.store(1);
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfce(createdJfce));
    fixture.ops.delete_jfce = MockDeleteJfce;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfce(createdJfce));

    EXPECT_EQ(nullptr, urma_create_jetty(nullptr, &jettyCfg));
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, nullptr));
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));
    fixture.ops.create_jetty = MockCreateJetty;
    urma_jetty_t *created = urma_create_jetty(&fixture.ctx, &jettyCfg);
    ASSERT_NE(nullptr, created);
    EXPECT_TRUE(created->urma_jetty_opt.is_actived);

    EXPECT_EQ(URMA_EINVAL, urma_modify_jetty(nullptr, &jettyAttr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jetty(&fixture.jetty, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_modify_jetty(&fixture.jetty, &jettyAttr));
    fixture.ops.modify_jetty = MockModifyJetty;
    EXPECT_EQ(URMA_SUCCESS, urma_modify_jetty(&fixture.jetty, &jettyAttr));

    EXPECT_EQ(URMA_EINVAL, urma_query_jetty(nullptr, &jettyCfg, &jettyAttr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jetty(&fixture.jetty, nullptr, &jettyAttr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jetty(&fixture.jetty, &jettyCfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_query_jetty(&fixture.jetty, &jettyCfg, &jettyAttr));
    fixture.ops.query_jetty = MockQueryJetty;
    EXPECT_EQ(URMA_SUCCESS, urma_query_jetty(&fixture.jetty, &jettyCfg, &jettyAttr));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty(nullptr));
    fixture.jetty.urma_jetty_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty(&fixture.jetty));
    fixture.jetty.urma_jetty_opt.is_actived = true;
    fixture.jetty.remote_jetty = &fixture.tjfr;
    EXPECT_EQ(URMA_ENOPERM, urma_delete_jetty(&fixture.jetty));
    fixture.jetty.remote_jetty = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty(&fixture.jetty));
    fixture.ops.delete_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jetty(&fixture.jetty));

    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty_batch(nullptr, 1, &badJetty));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty_batch(jettyArr, 0, &badJetty));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty_batch(jettyArr, 1, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
    jettyArr[1] = &fixture.jetty;
    fixture.jetty.remote_jetty = &fixture.tjfr;
    EXPECT_EQ(URMA_ENOPERM, urma_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
    fixture.jetty.remote_jetty = nullptr;
    fixture.ops.delete_jetty_batch = MockDeleteJettyBatchStatus;
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, urma_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
    urma_test::SetHwMockStatus(URMA_SUCCESS);
    fixture.ops.delete_jetty_batch = MockDeleteJettyBatch;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jetty_batch(jettyArr, 2, &badJetty));

    ASSERT_EQ(0, pthread_mutex_init(&jettyGrp.list_mutex, nullptr));
    jettyGrp.urma_ctx = &fixture.ctx;
    jettyGrp.jetty_list = static_cast<urma_jetty_t **>(calloc(4, sizeof(urma_jetty_t *)));
    ASSERT_NE(nullptr, jettyGrp.jetty_list);
    jettyCfg.jetty_grp = &jettyGrp;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RM;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_OI;
    jettyCfg.shared.jfr->jfr_cfg.trans_mode = URMA_TM_RM;
    jettyCfg.shared.jfr->jfr_cfg.flag.bs.order_type = URMA_OI;
    fixture.ops.create_jetty = MockCreateJetty;
    urma_jetty_t *groupedJetty = urma_create_jetty(&fixture.ctx, &jettyCfg);
    if (groupedJetty == nullptr) {
        free(jettyGrp.jetty_list);
        (void)pthread_mutex_destroy(&jettyGrp.list_mutex);
        FAIL() << "failed to create grouped jetty";
    }
    EXPECT_EQ(1U, jettyGrp.jetty_cnt);
    fixture.ops.delete_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jetty(groupedJetty));
    EXPECT_EQ(0U, jettyGrp.jetty_cnt);
    for (uint32_t i = 0; i < fixture.sysfsDev.dev_attr.dev_cap.max_jetty_in_jetty_grp; ++i) {
        jettyGrp.jetty_list[i] = &fixture.jetty;
    }
    jettyGrp.jetty_cnt = fixture.sysfsDev.dev_attr.dev_cap.max_jetty_in_jetty_grp;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));
    free(jettyGrp.jetty_list);
    jettyCfg.jetty_grp = nullptr;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_OL;
    fixture.jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    fixture.jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
    (void)pthread_mutex_destroy(&jettyGrp.list_mutex);

    fixture.jetty.jetty_cfg.jfs_cfg.depth = 1;
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), urma_flush_jetty(nullptr, 1, &cr));
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), urma_flush_jetty(&fixture.jetty, 2, &cr));
    fixture.ops.flush_jetty = MockFlushJetty;
    EXPECT_EQ(1, urma_flush_jetty(&fixture.jetty, 1, &cr));

    EXPECT_EQ(URMA_EINVAL, urma_alloc_jetty(nullptr, &jettyCfg, &createdJetty));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jetty(&fixture.ctx, nullptr, &createdJetty));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jetty(&fixture.ctx, &jettyCfg, nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_alloc_jetty(&fixture.ctx, &jettyCfg, &createdJetty));
    fixture.ops.alloc_jetty = MockAllocJetty;
    EXPECT_EQ(URMA_SUCCESS, urma_alloc_jetty(&fixture.ctx, &jettyCfg, &createdJetty));
    ASSERT_NE(nullptr, createdJetty);

    fixture.jetty.urma_jetty_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jetty_opt(nullptr, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, nullptr, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, 0));
    fixture.jetty.urma_jetty_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    fixture.jetty.urma_jetty_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(uint8_t)));
    EXPECT_EQ(URMA_EINVAL, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    fixture.ops.set_jetty_opt = MockJettyOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_get_jetty_opt(&fixture.jetty, 0, &depth, sizeof(depth)));
    fixture.ops.get_jetty_opt = MockJettyOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_get_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));

    fixture.jetty.urma_jetty_opt.is_actived = false;
    fixture.jetty.jetty_cfg.shared.jfc = &fixture.jfc;
    fixture.jetty.jetty_cfg.jfs_cfg.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(URMA_EINVAL, urma_active_jetty(&fixture.jetty));
    fixture.jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.jetty.jetty_cfg.jfs_cfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_depth + 1;
    EXPECT_EQ(URMA_EINVAL, urma_active_jetty(&fixture.jetty));
    fixture.jetty.jetty_cfg.jfs_cfg.depth = 4;
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.jfr.urma_jfr_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_active_jetty(&fixture.jetty));
    fixture.jfr.urma_jfr_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_active_jetty(&fixture.jetty));
    fixture.ops.active_jetty = MockJettyStatus;
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, urma_active_jetty(&fixture.jetty));
    urma_test::SetHwMockStatus(URMA_SUCCESS);
    EXPECT_EQ(URMA_SUCCESS, urma_active_jetty(&fixture.jetty));
    fixture.ops.deactive_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_deactive_jetty(&fixture.jetty));
    fixture.ops.free_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_free_jetty(&fixture.jetty));
}

TEST(UrmaCoreTest, CpApiCreateJettyRejectsInvalidConfigVariants)
{
    CoreApiFixture fixture;
    urma_jetty_cfg_t jettyCfg = fixture.jetty.jetty_cfg;
    urma_jfr_cfg_t privateJfrCfg = fixture.jfr.jfr_cfg;
    urma_jetty_grp_t jettyGrp = {};

    fixture.ops.create_jetty = MockCreateJetty;

    jettyCfg.jfs_cfg.jfc = nullptr;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    jettyCfg = fixture.jetty.jetty_cfg;
    jettyCfg.shared.jfr = nullptr;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    jettyCfg = fixture.jetty.jetty_cfg;
    jettyCfg.jfs_cfg.trans_mode = static_cast<urma_transport_mode_t>(0);
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    jettyCfg = fixture.jetty.jetty_cfg;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RM;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_NO;
    fixture.jfr.jfr_cfg.trans_mode = URMA_TM_RM;
    fixture.jfr.jfr_cfg.flag.bs.order_type = URMA_NO;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    jettyCfg = fixture.jetty.jetty_cfg;
    fixture.jfr.jfr_cfg.trans_mode = URMA_TM_RM;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    fixture.dev.type = URMA_TRANSPORT_IB;
    jettyCfg = fixture.jetty.jetty_cfg;
    jettyCfg.flag.bs.share_jfr = URMA_NO_SHARE_JFR;
    jettyCfg.jfr_cfg = nullptr;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    jettyCfg.jfr_cfg = &privateJfrCfg;
    privateJfrCfg.trans_mode = URMA_TM_RM;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    fixture.dev.type = URMA_TRANSPORT_UB;
    jettyCfg = fixture.jetty.jetty_cfg;
    fixture.jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.jetty_grp = &jettyGrp;
    jettyGrp.cfg.flag.bs.token_policy = URMA_TOKEN_NONE;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));

    jettyCfg = fixture.jetty.jetty_cfg;
    fixture.sysfsDev.dev_attr.dev_cap.max_jfs_depth = 1;
    jettyCfg.jfs_cfg.depth = 2;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));
}

TEST(UrmaCoreTest, CpApiTargetJettyAndNotifierApisValidateAndDispatch)
{
    CoreApiFixture fixture;
    urma_rjfr_t rjfr = {};
    urma_rjetty_t rjetty = {};
    urma_token_t tokenValue = {};
    urma_import_jetty_ex_cfg_t importCfg = {};
    urma_bind_jetty_ex_cfg_t bindCfg = {};
    urma_notify_t notify = {};
    int callbackArg = 0;

    rjfr.trans_mode = URMA_TM_RM;
    rjfr.tp_type = URMA_RTP;
    rjetty.trans_mode = URMA_TM_RC;
    rjetty.tp_type = URMA_RTP;
    fixture.tjfr.trans_mode = URMA_TM_RM;

    EXPECT_EQ(nullptr, urma_import_jfr(nullptr, &rjfr, &tokenValue));
    EXPECT_EQ(nullptr, urma_import_jfr(&fixture.ctx, nullptr, &tokenValue));
    EXPECT_EQ(nullptr, urma_import_jfr(&fixture.ctx, &rjfr, &tokenValue));
    rjfr.flag.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;
    EXPECT_EQ(nullptr, urma_import_jfr(&fixture.ctx, &rjfr, nullptr));
    rjfr.flag.bs.token_policy = URMA_TOKEN_NONE;
    fixture.ops.import_jfr_ex = MockImportJfrEx;
    rjfr.flag.bs.share_tp = 1;
    EXPECT_EQ(nullptr, urma_import_jfr(&fixture.ctx, &rjfr, &tokenValue));
    rjfr.flag.bs.share_tp = 0;
    EXPECT_NE(nullptr, urma_import_jfr(&fixture.ctx, &rjfr, &tokenValue));
    fixture.ops.import_jfr_ex = nullptr;
    fixture.ops.import_jfr = MockImportJfr;
    EXPECT_NE(nullptr, urma_import_jfr(&fixture.ctx, &rjfr, &tokenValue));
    EXPECT_EQ(nullptr, urma_import_jfr_ex(&fixture.ctx, &rjfr, nullptr, &importCfg));
    fixture.ops.import_jfr_ex = MockImportJfrEx;
    EXPECT_NE(nullptr, urma_import_jfr_ex(&fixture.ctx, &rjfr, &tokenValue, &importCfg));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_jfr(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_jfr(&fixture.tjfr));
    fixture.ops.unimport_jfr = MockTargetJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_unimport_jfr(&fixture.tjfr));

    fixture.jfs.jfs_cfg.trans_mode = URMA_TM_RM;
    EXPECT_EQ(URMA_EINVAL, urma_advise_jfr(nullptr, &fixture.tjfr));
    EXPECT_EQ(URMA_SUCCESS, urma_advise_jfr(&fixture.jfs, &fixture.tjfr));
    fixture.dev.type = URMA_TRANSPORT_MAX;
    EXPECT_EQ(URMA_EINVAL, urma_advise_jfr(&fixture.jfs, &fixture.tjfr));
    fixture.ops.advise_jfr = MockAdviseJfr;
    EXPECT_EQ(URMA_SUCCESS, urma_advise_jfr(&fixture.jfs, &fixture.tjfr));
    EXPECT_EQ(URMA_EINVAL, urma_advise_jfr_async(&fixture.jfs, &fixture.tjfr, nullptr, &callbackArg));
    fixture.ops.advise_jfr_async = MockAdviseJfrAsync;
    EXPECT_EQ(URMA_SUCCESS, urma_advise_jfr_async(&fixture.jfs, &fixture.tjfr, MockAdviseCallback, &callbackArg));
    EXPECT_EQ(URMA_EINVAL, urma_unadvise_jfr(nullptr, &fixture.tjfr));
    fixture.ops.unadvise_jfr = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_unadvise_jfr(&fixture.jfs, &fixture.tjfr));
    fixture.ops.unadvise_jfr = MockAdviseJfr;
    EXPECT_EQ(URMA_SUCCESS, urma_unadvise_jfr(&fixture.jfs, &fixture.tjfr));

    EXPECT_EQ(nullptr, urma_import_jetty(nullptr, &rjetty, &tokenValue));
    EXPECT_EQ(nullptr, urma_import_jetty(&fixture.ctx, nullptr, &tokenValue));
    EXPECT_EQ(nullptr, urma_import_jetty(&fixture.ctx, &rjetty, &tokenValue));
    rjetty.trans_mode = static_cast<urma_transport_mode_t>(0xff);
    EXPECT_EQ(nullptr, urma_import_jetty(&fixture.ctx, &rjetty, &tokenValue));
    rjetty.trans_mode = URMA_TM_RC;
    fixture.ops.import_jetty_ex = MockImportJettyEx;
    rjetty.flag.bs.share_tp = 1;
    EXPECT_EQ(nullptr, urma_import_jetty(&fixture.ctx, &rjetty, &tokenValue));
    rjetty.flag.bs.share_tp = 0;
    EXPECT_NE(nullptr, urma_import_jetty(&fixture.ctx, &rjetty, &tokenValue));
    fixture.ops.import_jetty_ex = nullptr;
    fixture.ops.import_jetty = MockImportJetty;
    EXPECT_NE(nullptr, urma_import_jetty(&fixture.ctx, &rjetty, &tokenValue));
    EXPECT_EQ(nullptr, urma_import_jetty_ex(&fixture.ctx, &rjetty, nullptr, &importCfg));
    fixture.ops.import_jetty_ex = MockImportJettyEx;
    EXPECT_NE(nullptr, urma_import_jetty_ex(&fixture.ctx, &rjetty, &tokenValue, &importCfg));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_jetty(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_jetty(&fixture.tjfr));
    fixture.ops.unimport_jetty = MockTargetJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_unimport_jetty(&fixture.tjfr));

    fixture.jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.tjfr.trans_mode = URMA_TM_RC;
    EXPECT_EQ(URMA_EINVAL, urma_bind_jetty(nullptr, &fixture.tjfr));
    fixture.ops.bind_jetty = MockBindJetty;
    EXPECT_EQ(URMA_SUCCESS, urma_bind_jetty(&fixture.jetty, &fixture.tjfr));
    fixture.ops.bind_jetty = nullptr;
    fixture.ops.bind_jetty_ex = MockBindJettyEx;
    EXPECT_EQ(URMA_SUCCESS, urma_bind_jetty(&fixture.jetty, &fixture.tjfr));
    EXPECT_EQ(URMA_EINVAL, urma_bind_jetty_ex(&fixture.jetty, &fixture.tjfr, nullptr));
    fixture.ops.bind_jetty_ex = MockBindJettyEx;
    EXPECT_EQ(URMA_SUCCESS, urma_bind_jetty_ex(&fixture.jetty, &fixture.tjfr, &bindCfg));
    EXPECT_EQ(URMA_EINVAL, urma_unbind_jetty(&fixture.jetty));
    fixture.jetty.remote_jetty = &fixture.tjfr;
    EXPECT_EQ(URMA_EINVAL, urma_unbind_jetty(&fixture.jetty));
    fixture.ops.unbind_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_unbind_jetty(&fixture.jetty));

    fixture.jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RM;
    fixture.tjfr.trans_mode = URMA_TM_RM;
    fixture.dev.type = URMA_TRANSPORT_UB;
    EXPECT_EQ(URMA_EINVAL, urma_advise_jetty(nullptr, &fixture.tjfr));
    EXPECT_EQ(URMA_SUCCESS, urma_advise_jetty(&fixture.jetty, &fixture.tjfr));
    fixture.dev.type = URMA_TRANSPORT_MAX;
    EXPECT_EQ(URMA_EINVAL, urma_advise_jetty(&fixture.jetty, &fixture.tjfr));
    fixture.ops.advise_jetty = MockAdviseJetty;
    EXPECT_EQ(URMA_SUCCESS, urma_advise_jetty(&fixture.jetty, &fixture.tjfr));
    EXPECT_EQ(URMA_EINVAL, urma_unadvise_jetty(nullptr, &fixture.tjfr));
    fixture.ops.unadvise_jetty = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_unadvise_jetty(&fixture.jetty, &fixture.tjfr));
    fixture.ops.unadvise_jetty = MockAdviseJetty;
    EXPECT_EQ(URMA_SUCCESS, urma_unadvise_jetty(&fixture.jetty, &fixture.tjfr));

    EXPECT_EQ(nullptr, urma_create_notifier(nullptr));
    EXPECT_EQ(nullptr, urma_create_notifier(&fixture.ctx));
    fixture.ops.create_notifier = MockCreateNotifier;
    urma_notifier_t *notifier = urma_create_notifier(&fixture.ctx);
    ASSERT_NE(nullptr, notifier);
    EXPECT_EQ(-1, urma_wait_notify(nullptr, 1, &notify, 0));
    EXPECT_EQ(0, urma_wait_notify(notifier, 0, &notify, 0));
    EXPECT_EQ(-URMA_EINVAL, urma_wait_notify(notifier, 1, &notify, 0));
    fixture.ops.wait_notify = MockWaitNotify;
    fixture.ops.ack_notify = MockAckNotify;
    EXPECT_EQ(1, urma_wait_notify(notifier, 1, &notify, 0));
    EXPECT_EQ(URMA_EINVAL, urma_ack_notify(nullptr, 1, &notify));
    EXPECT_EQ(URMA_SUCCESS, urma_ack_notify(&fixture.ctx, 1, &notify));
    fixture.ops.ack_notify = nullptr;
    EXPECT_EQ(-static_cast<int>(URMA_EINVAL), static_cast<int>(urma_ack_notify(&fixture.ctx, 1, &notify)));
    fixture.ops.ack_notify = MockAckNotify;

    EXPECT_EQ(nullptr, urma_import_jetty_async(nullptr, &rjetty, &tokenValue, 0, 0));
    EXPECT_EQ(nullptr, urma_import_jetty_async(notifier, &rjetty, &tokenValue, 0, 0));
    fixture.ops.import_jetty_async = MockImportJettyAsyncNull;
    fixture.ctx.ref.atomic_cnt.store(1);
    EXPECT_EQ(nullptr, urma_import_jetty_async(notifier, &rjetty, &tokenValue, 0, 0));
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());
    fixture.ops.import_jetty_async = MockImportJettyAsync;
    EXPECT_NE(nullptr, urma_import_jetty_async(notifier, &rjetty, &tokenValue, 0, 0));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_jetty_async(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_unimport_jetty_async(&fixture.tjfr));
    fixture.ops.unimport_jetty_async = MockTargetJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_unimport_jetty_async(&fixture.tjfr));

    fixture.jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
    fixture.tjfr.trans_mode = URMA_TM_RC;
    EXPECT_EQ(URMA_EINVAL, urma_bind_jetty_async(nullptr, &fixture.jetty, &fixture.tjfr, 0, 0));
    EXPECT_EQ(URMA_EINVAL, urma_bind_jetty_async(notifier, &fixture.jetty, &fixture.tjfr, 0, 0));
    fixture.ops.bind_jetty_async = MockBindJettyAsync;
    EXPECT_EQ(URMA_SUCCESS, urma_bind_jetty_async(notifier, &fixture.jetty, &fixture.tjfr, 0, 0));
    EXPECT_EQ(URMA_EINVAL, urma_unbind_jetty_async(&fixture.jetty));
    fixture.jetty.remote_jetty = &fixture.tjfr;
    EXPECT_EQ(URMA_EINVAL, urma_unbind_jetty_async(&fixture.jetty));
    fixture.ops.unbind_jetty_async = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_unbind_jetty_async(&fixture.jetty));

    EXPECT_EQ(URMA_EINVAL, urma_delete_notifier(nullptr));
    fixture.ops.delete_notifier = MockDeleteNotifier;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_notifier(notifier));
}

TEST(UrmaCoreTest, CpApiJettyGroupAndUtilityApisValidateAndDispatch)
{
    CoreApiFixture fixture;
    urma_jetty_cfg_t copiedCfg = {};
    urma_jetty_cfg_t sourceCfg = fixture.jetty.jetty_cfg;
    urma_jfr_cfg_t localJfrCfg = fixture.jfr.jfr_cfg;
    urma_jetty_grp_cfg_t grpCfg = {};
    uint32_t cnt = 0;

    sourceCfg.flag.bs.share_jfr = URMA_NO_SHARE_JFR;
    sourceCfg.jfr_cfg = &localJfrCfg;
    EXPECT_EQ(0, urma_init_jetty_cfg(&copiedCfg, &sourceCfg));
    ASSERT_NE(nullptr, copiedCfg.jfr_cfg);
    urma_uninit_jetty_cfg(&copiedCfg);
    EXPECT_EQ(nullptr, copiedCfg.jfr_cfg);

    EXPECT_EQ(nullptr, urma_create_jetty_grp(nullptr, &grpCfg));
    EXPECT_EQ(nullptr, urma_create_jetty_grp(&fixture.ctx, &grpCfg));
    fixture.ops.create_jetty_grp = MockCreateJettyGrp;
    fixture.ops.delete_jetty_grp = MockDeleteJettyGrp;
    std::snprintf(grpCfg.name, sizeof(grpCfg.name), "core_grp");
    urma_jetty_grp_t *grp = urma_create_jetty_grp(&fixture.ctx, &grpCfg);
    ASSERT_NE(nullptr, grp);
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty_grp(nullptr));
    grp->jetty_cnt = 1;
    EXPECT_EQ(URMA_ENOPERM, urma_delete_jetty_grp(grp));
    grp->jetty_cnt = 0;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jetty_grp(grp));

    EXPECT_EQ(-URMA_EINVAL, urma_get_tpn(nullptr));
    EXPECT_EQ(-URMA_EINVAL, urma_get_tpn(&fixture.jetty));
    fixture.ops.get_tpn = MockGetTpn;
    EXPECT_EQ(7, urma_get_tpn(&fixture.jetty));

    EXPECT_EQ(nullptr, urma_get_net_addr_list(nullptr, &cnt));
    EXPECT_EQ(nullptr, urma_get_net_addr_list(&fixture.ctx, nullptr));
    fixture.sysfsDev.dev_attr.dev_cap.max_netaddr_cnt = 0;
    EXPECT_EQ(nullptr, urma_get_net_addr_list(&fixture.ctx, &cnt));
    fixture.sysfsDev.dev_attr.dev_cap.max_netaddr_cnt = 2;
    fixture.ctx.dev_fd = 17;
    SetCoreIoctlResult(-1, ENOTTY);
    EXPECT_EQ(nullptr, urma_get_net_addr_list(&fixture.ctx, &cnt));
    SetCoreIoctlResult(0, 0);
    urma_net_addr_info_t *netAddrList = urma_get_net_addr_list(&fixture.ctx, &cnt);
    ASSERT_NE(nullptr, netAddrList);
    EXPECT_EQ(2U, cnt);
    EXPECT_EQ(7U, netAddrList[0].index);
    EXPECT_EQ(AF_INET, netAddrList[0].netaddr.sin_family);
    EXPECT_EQ(0x01020304U, netAddrList[0].netaddr.in4.s_addr);
    EXPECT_EQ(100U, netAddrList[0].netaddr.vlan);
    EXPECT_EQ(0xaaU, netAddrList[0].netaddr.mac[0]);
    EXPECT_EQ(24U, netAddrList[0].netaddr.prefix_len);
    EXPECT_EQ(8U, netAddrList[1].index);
    EXPECT_EQ(AF_INET6, netAddrList[1].netaddr.sin_family);
    EXPECT_EQ(200U, netAddrList[1].netaddr.vlan);
    EXPECT_EQ(0xbbU, netAddrList[1].netaddr.mac[0]);
    EXPECT_EQ(64U, netAddrList[1].netaddr.prefix_len);
    urma_free_net_addr_list(netAddrList);
    urma_free_net_addr_list(nullptr);
    urma_net_addr_info_t *list = static_cast<urma_net_addr_info_t *>(calloc(1, sizeof(*list)));
    ASSERT_NE(nullptr, list);
    urma_free_net_addr_list(list);
}

TEST(UrmaCoreTest, CpApiProviderReturnValuesPropagateForJfcJfsJfrJetty)
{
    CoreApiFixture fixture;
    urma_jfc_attr_t jfcAttr = {};
    urma_jfs_attr_t jfsAttr = {};
    urma_jfr_attr_t jfrAttr = {};
    urma_jetty_attr_t jettyAttr = {};
    urma_jfs_cfg_t jfsCfg = {};
    urma_jfr_cfg_t jfrCfg = {};
    urma_jetty_cfg_t jettyCfg = {};

    fixture.InstallMockOps();
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    urma_test::GetHwMockState().jfsModifyStatus = URMA_EAGAIN;
    urma_test::GetHwMockState().jfrQueryStatus = URMA_EAGAIN;

    EXPECT_EQ(URMA_EAGAIN, urma_modify_jfc(&fixture.jfc, &jfcAttr));
    EXPECT_EQ(URMA_EAGAIN, urma_delete_jfc(&fixture.jfc));
    EXPECT_EQ(URMA_EAGAIN, urma_modify_jfs(&fixture.jfs, &jfsAttr));
    EXPECT_EQ(URMA_EAGAIN, urma_query_jfs(&fixture.jfs, &jfsCfg, &jfsAttr));
    EXPECT_EQ(URMA_EAGAIN, urma_modify_jfr(&fixture.jfr, &jfrAttr));
    EXPECT_EQ(URMA_EAGAIN, urma_query_jfr(&fixture.jfr, &jfrCfg, &jfrAttr));
    EXPECT_EQ(URMA_EAGAIN, urma_modify_jetty(&fixture.jetty, &jettyAttr));
    EXPECT_EQ(URMA_EAGAIN, urma_query_jetty(&fixture.jetty, &jettyCfg, &jettyAttr));
}

TEST(UrmaCoreTest, CpApiProviderNullAndStateFailuresCoverStableBranches)
{
    CoreApiFixture fixture;
    urma_jfc_cfg_t jfcCfg = fixture.jfc.jfc_cfg;
    urma_jfs_cfg_t jfsCfg = fixture.jfs.jfs_cfg;
    urma_jfr_cfg_t jfrCfg = fixture.jfr.jfr_cfg;
    urma_jetty_cfg_t jettyCfg = fixture.jetty.jetty_cfg;
    urma_jfc_t *createdJfc = nullptr;
    uint32_t depth = 4;

    fixture.ops.create_jfc = MockCreateJfcNull;
    EXPECT_EQ(nullptr, urma_create_jfc(&fixture.ctx, &jfcCfg));
    fixture.ops.alloc_jfc = MockAllocJfcNull;
    EXPECT_EQ(URMA_ENOMEM, urma_alloc_jfc(&fixture.ctx, &jfcCfg, &createdJfc));

    fixture.jfc.urma_jfc_opt.is_actived = false;
    fixture.ops.free_jfc = MockJfcStatus;
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, urma_free_jfc(&fixture.jfc));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.ops.delete_jfc = MockDeleteJfc;
    EXPECT_EQ(URMA_EAGAIN, urma_delete_jfc(&fixture.jfc));
    fixture.ops.active_jfc = MockJfcStatus;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfc(&fixture.jfc));
    fixture.jfc.urma_jfc_opt.is_actived = false;
    EXPECT_EQ(URMA_EAGAIN, urma_active_jfc(&fixture.jfc));
    fixture.ops.deactive_jfc = MockJfcStatus;
    EXPECT_EQ(URMA_EINVAL, urma_deactive_jfc(&fixture.jfc));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    EXPECT_EQ(URMA_EAGAIN, urma_deactive_jfc(&fixture.jfc));

    fixture.ops.create_jfs = MockCreateJfsNull;
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &jfsCfg));
    jfsCfg.flag.bs.order_type = URMA_OT;
    jfsCfg.trans_mode = URMA_TM_RM;
    EXPECT_EQ(nullptr, urma_create_jfs(&fixture.ctx, &jfsCfg));
    fixture.jfs.urma_jfs_opt.is_actived = false;
    fixture.ops.free_jfs = MockJfsStatus;
    EXPECT_EQ(URMA_EAGAIN, urma_free_jfs(&fixture.jfs));
    fixture.jfs.jfs_cfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfs_depth + 1;
    fixture.ops.active_jfs = MockJfsStatus;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfs(&fixture.jfs));
    fixture.jfs.jfs_cfg.depth = 4;
    fixture.jfs.urma_jfs_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfs(&fixture.jfs));
    fixture.jfs.urma_jfs_opt.is_actived = false;
    EXPECT_EQ(URMA_EAGAIN, urma_active_jfs(&fixture.jfs));
    fixture.jfs.urma_jfs_opt.is_actived = true;
    fixture.ops.deactive_jfs = MockJfsStatus;
    EXPECT_EQ(URMA_EAGAIN, urma_deactive_jfs(&fixture.jfs));

    fixture.ops.create_jfr = MockCreateJfrNull;
    EXPECT_EQ(nullptr, urma_create_jfr(&fixture.ctx, &jfrCfg));
    fixture.jfr.urma_jfr_opt.is_actived = false;
    fixture.ops.free_jfr = MockJfrStatus;
    EXPECT_EQ(URMA_EAGAIN, urma_free_jfr(&fixture.jfr));
    fixture.jfr.jfr_cfg.depth = fixture.sysfsDev.dev_attr.dev_cap.max_jfr_depth + 1;
    fixture.ops.active_jfr = MockJfrStatus;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfr(&fixture.jfr));
    fixture.jfr.jfr_cfg.depth = 4;
    fixture.jfr.urma_jfr_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_active_jfr(&fixture.jfr));
    fixture.jfr.urma_jfr_opt.is_actived = false;
    EXPECT_EQ(URMA_EAGAIN, urma_active_jfr(&fixture.jfr));
    fixture.jfr.urma_jfr_opt.is_actived = true;
    fixture.ops.deactive_jfr = MockJfrStatus;
    EXPECT_EQ(URMA_EAGAIN, urma_deactive_jfr(&fixture.jfr));

    fixture.ops.create_jetty = MockCreateJettyNull;
    EXPECT_EQ(nullptr, urma_create_jetty(&fixture.ctx, &jettyCfg));
    fixture.jetty.urma_jetty_opt.is_actived = false;
    fixture.ops.set_jetty_opt = MockJettyOpt;
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    EXPECT_EQ(URMA_EAGAIN, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));
}

TEST(UrmaCoreTest, CpApiBatchDeleteReportsConfiguredBadObjects)
{
    CoreApiFixture fixture;
    urma_jfc_t *jfcArr[2] = { &fixture.jfc, &fixture.jfc };
    urma_jfc_t *badJfc = nullptr;

    fixture.InstallMockOps();
    urma_test::SetHwMockStatus(URMA_EAGAIN);
    urma_test::SetHwMockBadObject(&fixture.jfc);

    EXPECT_EQ(URMA_EAGAIN, urma_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);
}

TEST(UrmaCoreTest, CpApiProviderFailuresCoverDeleteBatchAndOptBranches)
{
    CoreApiFixture fixture;
    urma_jfc_t brokenJfc = fixture.jfc;
    urma_jfs_t brokenJfs = fixture.jfs;
    urma_jfr_t brokenJfr = fixture.jfr;
    urma_jfc_t *jfcArr[2] = { &fixture.jfc, &brokenJfc };
    urma_jfs_t *jfsArr[2] = { &fixture.jfs, &brokenJfs };
    urma_jfr_t *jfrArr[2] = { &fixture.jfr, &brokenJfr };
    urma_jfc_t *badJfc = nullptr;
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;
    uint32_t depth = 4;

    fixture.InstallMockOps();
    brokenJfc.urma_ctx = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);

    brokenJfs.urma_ctx = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);

    brokenJfr.urma_ctx = nullptr;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);

    urma_test::SetHwMockStatus(URMA_EAGAIN);
    fixture.jfs.urma_jfs_opt.is_actived = true;
    fixture.jfs.jfs_id.id = 0x55;
    EXPECT_EQ(URMA_EAGAIN, urma_delete_jfs(&fixture.jfs));
    fixture.jfr.urma_jfr_opt.is_actived = true;
    fixture.jfr.jfr_id.id = 0x66;
    EXPECT_EQ(URMA_EAGAIN, urma_delete_jfr(&fixture.jfr));

    fixture.jfc.urma_jfc_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, sizeof(depth)));
    fixture.jfc.urma_jfc_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, sizeof(uint64_t)));
    fixture.ops.set_jfc_opt = MockJfcOpt;
    EXPECT_EQ(URMA_EAGAIN, urma_set_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, sizeof(depth)));
    fixture.ops.get_jfc_opt = MockJfcOpt;
    EXPECT_EQ(URMA_EAGAIN, urma_get_jfc_opt(&fixture.jfc, URMA_JFC_DEPTH, &depth, sizeof(depth)));

    fixture.jfs.urma_jfs_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    fixture.jfs.urma_jfs_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &depth, sizeof(uint64_t)));
    fixture.ops.set_jfs_opt = MockJfsOpt;
    EXPECT_EQ(URMA_EAGAIN, urma_set_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    fixture.ops.get_jfs_opt = MockJfsOpt;
    EXPECT_EQ(URMA_EAGAIN, urma_get_jfs_opt(&fixture.jfs, URMA_JFS_DEPTH, &depth, sizeof(depth)));

    fixture.jfr.urma_jfr_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &depth, sizeof(depth)));
    fixture.jfr.urma_jfr_opt.is_actived = false;
    EXPECT_EQ(URMA_EINVAL, urma_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &depth, sizeof(uint64_t)));
    fixture.ops.set_jfr_opt = MockJfrOpt;
    EXPECT_EQ(URMA_EAGAIN, urma_set_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &depth, sizeof(depth)));
    fixture.ops.get_jfr_opt = MockJfrOpt;
    EXPECT_EQ(URMA_EAGAIN, urma_get_jfr_opt(&fixture.jfr, URMA_JFR_DEPTH, &depth, sizeof(depth)));
}

TEST(UrmaCoreTest, CpApiAdditionalNullAndStateBranchesUseExistingMocks)
{
    CoreApiFixture fixture;
    urma_jfc_t *jfcArr[2] = { &fixture.jfc, nullptr };
    urma_jfs_t *jfsArr[2] = { &fixture.jfs, nullptr };
    urma_jfr_t *jfrArr[2] = { &fixture.jfr, nullptr };
    urma_jfc_t *badJfc = nullptr;
    urma_jfs_t *badJfs = nullptr;
    urma_jfr_t *badJfr = nullptr;

    EXPECT_EQ(URMA_EINVAL, urma_free_jfc(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_free_jfs(nullptr));
    EXPECT_EQ(URMA_EINVAL, urma_free_jfr(nullptr));

    fixture.InstallMockOps();
    fixture.jfc.urma_jfc_opt.is_actived = false;
    fixture.jfc.jfc_cfg.jfce = nullptr;
    fixture.ctx.ref.atomic_cnt.store(2);
    fixture.ops.free_jfc = MockJfcStatus;
    urma_test::SetHwMockStatus(URMA_SUCCESS);
    EXPECT_EQ(URMA_SUCCESS, urma_free_jfc(&fixture.jfc));
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());

    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.jfc.jfc_cfg.jfce = &fixture.jfce;
    fixture.ctx.ref.atomic_cnt.store(2);
    fixture.jfce.ref.atomic_cnt.store(1);
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfc(&fixture.jfc));
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());
    EXPECT_EQ(0UL, fixture.jfce.ref.atomic_cnt.load());

    fixture.jfc.urma_jfc_opt.is_actived = true;
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfc_batch(jfcArr, 2, &badJfc));
    EXPECT_EQ(&fixture.jfc, badJfc);
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfs_batch(jfsArr, 2, &badJfs));
    EXPECT_EQ(&fixture.jfs, badJfs);
    EXPECT_EQ(URMA_EINVAL, urma_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(&fixture.jfr, badJfr);
}

TEST(UrmaCoreTest, CpApiRemoteJettyAndSegContextHelpersUseLocalAndProviderPaths)
{
    CoreApiFixture fixture;
    urma_rjetty_t *rjetty = nullptr;
    urma_seg_t *seg = nullptr;
    uint32_t length = 0;
    uint32_t size = 0;

    EXPECT_EQ(URMA_EINVAL, urma_get_rjetty(nullptr, &rjetty, &length));
    EXPECT_EQ(URMA_EINVAL, urma_get_rjetty(&fixture.jetty, nullptr, &length));
    EXPECT_EQ(URMA_EINVAL, urma_get_rjetty(&fixture.jetty, &rjetty, nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_get_rjetty(&fixture.jetty, &rjetty, &length));
    ASSERT_NE(nullptr, rjetty);
    EXPECT_EQ(fixture.jetty.jetty_id.id, rjetty->jetty_id.id);
    EXPECT_EQ(sizeof(urma_rjetty_t), length);
    urma_put_rjetty(rjetty);
    urma_put_rjetty(nullptr);

    EXPECT_EQ(URMA_EINVAL, urma_get_seg_ctx(nullptr, &seg, &size));
    EXPECT_EQ(URMA_EINVAL, urma_get_seg_ctx(&fixture.tseg, nullptr, &size));
    EXPECT_EQ(URMA_EINVAL, urma_get_seg_ctx(&fixture.tseg, &seg, nullptr));
    fixture.tseg.seg.ubva.va = 0x1234000;
    fixture.tseg.seg.len = 0x2000;
    EXPECT_EQ(URMA_SUCCESS, urma_get_seg_ctx(&fixture.tseg, &seg, &size));
    ASSERT_NE(nullptr, seg);
    EXPECT_EQ(fixture.tseg.seg.ubva.va, seg->ubva.va);
    EXPECT_EQ(fixture.tseg.seg.len, seg->len);
    EXPECT_EQ(sizeof(urma_seg_t), size);
    urma_put_seg_ctx(seg);
    urma_put_seg_ctx(nullptr);

    std::snprintf(fixture.dev.name, sizeof(fixture.dev.name), "bonding_dev_core_ut");
    EXPECT_EQ(URMA_EINVAL, urma_get_rjetty(&fixture.jetty, &rjetty, &length));
    EXPECT_EQ(URMA_EINVAL, urma_get_seg_ctx(&fixture.tseg, &seg, &size));
    fixture.ops.user_ctl = MockUserCtl;
    urma_test::GetHwMockState().userCtlReturn = URMA_ENOPERM;
    EXPECT_EQ(URMA_FAIL, urma_get_rjetty(&fixture.jetty, &rjetty, &length));
    EXPECT_EQ(URMA_FAIL, urma_get_seg_ctx(&fixture.tseg, &seg, &size));
    urma_test::GetHwMockState().userCtlReturn = 0;
    rjetty = nullptr;
    seg = nullptr;
    EXPECT_EQ(URMA_SUCCESS, urma_get_rjetty(&fixture.jetty, &rjetty, &length));
    ASSERT_NE(nullptr, rjetty);
    urma_put_rjetty(rjetty);
    EXPECT_EQ(URMA_SUCCESS, urma_get_seg_ctx(&fixture.tseg, &seg, &size));
    ASSERT_NE(nullptr, seg);
    urma_put_seg_ctx(seg);
}
