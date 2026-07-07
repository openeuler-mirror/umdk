/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA bonding datapath convert and schedule unit tests.
 */

#include "bond_fixture.h"

using namespace urma_test_bond;

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

TEST(UrmaBondTest, DatapathCopyAndFreeAllocatedAndInvalidWorkRequests)
{
    BondPathFixture fixture;
    urma_jfs_wr_t src = fixture.MakeRwWr(URMA_OPC_READ);
    urma_jfs_wr_t dst = {};
    urma_jfs_wr_t invalid = fixture.MakeRwWr(URMA_OPC_WRITE);
    urma_jfs_wr_t atomicWr = {};
    urma_jfr_wr_t recvSrc = {};
    urma_jfr_wr_t recvDst = {};
    urma_sge_t preallocSrc[BONDP_MAX_SGE_NUM] = {};
    urma_sge_t preallocDst[BONDP_MAX_SGE_NUM] = {};
    urma_sge_t atomicSrc = {};
    urma_sge_t atomicDst = {};

    ASSERT_EQ(URMA_SUCCESS, copy_jfs_wr(&src, &dst, nullptr, nullptr));
    ASSERT_NE(nullptr, dst.rw.src.sge);
    ASSERT_NE(nullptr, dst.rw.dst.sge);
    EXPECT_NE(fixture.srcSge, dst.rw.src.sge);
    EXPECT_NE(fixture.dstSge, dst.rw.dst.sge);
    free_jfs_wr(&dst);
    EXPECT_EQ(nullptr, dst.rw.src.sge);
    EXPECT_EQ(nullptr, dst.rw.dst.sge);

    invalid.rw.src.num_sge = BONDP_MAX_SGE_NUM + 1;
    EXPECT_EQ(URMA_ENOMEM, copy_jfs_wr(&invalid, &dst, preallocSrc, preallocDst));

    invalid = fixture.MakeSendWr(URMA_OPC_SEND_INVALIDATE);
    invalid.send.src.num_sge = BONDP_MAX_SGE_NUM + 1;
    EXPECT_EQ(URMA_ENOMEM, copy_jfs_wr(&invalid, &dst, preallocSrc, preallocDst));

    atomicSrc.tseg = &fixture.localSeg.v_tseg;
    atomicDst.tseg = &fixture.remoteSeg.v_tseg;
    atomicWr.opcode = URMA_OPC_FADD;
    atomicWr.faa.src = &atomicSrc;
    atomicWr.faa.dst = &atomicDst;
    ASSERT_EQ(URMA_SUCCESS, copy_jfs_wr(&atomicWr, &dst, nullptr, nullptr));
    ASSERT_NE(nullptr, dst.faa.src);
    ASSERT_NE(nullptr, dst.faa.dst);
    EXPECT_NE(&atomicSrc, dst.faa.src);
    EXPECT_NE(&atomicDst, dst.faa.dst);
    free_jfs_wr(&dst);
    EXPECT_EQ(nullptr, dst.faa.src);
    EXPECT_EQ(nullptr, dst.faa.dst);

    atomicWr = {};
    atomicWr.opcode = URMA_OPC_CAS;
    ASSERT_EQ(URMA_SUCCESS, copy_jfs_wr(&atomicWr, &dst, preallocSrc, preallocDst));
    EXPECT_EQ(nullptr, dst.cas.src);
    EXPECT_EQ(nullptr, dst.cas.dst);

    recvSrc.src.sge = fixture.srcSge;
    recvSrc.src.num_sge = BONDP_MAX_SGE_NUM + 1;
    EXPECT_EQ(URMA_ENOMEM, copy_jfr_wr(&recvSrc, &recvDst, preallocSrc));
}

TEST(UrmaBondTest, DatapathBindUnbindAndUseCountsCoverRwAndAtomicPaths)
{
    BondPathFixture fixture;
    urma_jfs_wr_t rw = fixture.MakeRwWr(URMA_OPC_WRITE_NOTIFY);
    urma_jfs_wr_t casWr = {};
    urma_jfs_wr_t faddWr = {};
    urma_sge_t casSrc = {};
    urma_sge_t casDst = {};
    urma_sge_t faddSrc = {};
    urma_sge_t faddDst = {};

    casSrc.tseg = &fixture.localSeg.v_tseg;
    casDst.tseg = &fixture.remoteSeg.v_tseg;
    faddSrc.tseg = &fixture.localSeg.v_tseg;
    faddDst.tseg = &fixture.remoteSeg.v_tseg;
    casWr.opcode = URMA_OPC_CAS;
    casWr.cas.src = &casSrc;
    casWr.cas.dst = &casDst;
    casWr.tjetty = &fixture.target.v_tjetty;
    faddWr.opcode = URMA_OPC_FADD;
    faddWr.faa.src = &faddSrc;
    faddWr.faa.dst = &faddDst;
    faddWr.tjetty = &fixture.target.v_tjetty;

    convert_jfs_vwr_to_pwr(&casWr, 0, 0);
    EXPECT_EQ(&fixture.localPhy[0], casWr.cas.src->tseg);
    EXPECT_EQ(&fixture.remotePhy[0][0], casWr.cas.dst->tseg);
    convert_jfs_pwr_to_vwr(&casWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, casWr.cas.src->tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, casWr.cas.dst->tseg);

    convert_jfs_vwr_to_pwr(&faddWr, 1, 1);
    EXPECT_EQ(&fixture.localPhy[1], faddWr.faa.src->tseg);
    EXPECT_EQ(&fixture.remotePhy[1][1], faddWr.faa.dst->tseg);
    convert_jfs_pwr_to_vwr(&faddWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, faddWr.faa.src->tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, faddWr.faa.dst->tseg);

    SetRefCount(&fixture.target.use_cnt, 1);
    SetRefCount(&fixture.localSeg.use_cnt, 1);
    SetRefCount(&fixture.remoteSeg.use_cnt, 1);
    get_jfs_vwr_refs(&rw);
    put_jfs_vwr_refs(&rw);
    get_jfs_vwr_refs(&casWr);
    put_jfs_vwr_refs(&casWr);
    get_jfs_vwr_refs(&faddWr);
    put_jfs_vwr_refs(&faddWr);
    EXPECT_EQ(1UL, fixture.target.use_cnt.atomic_cnt.load());
    EXPECT_EQ(1UL, fixture.localSeg.use_cnt.atomic_cnt.load());
    EXPECT_EQ(1UL, fixture.remoteSeg.use_cnt.atomic_cnt.load());
}

TEST(UrmaBondTest, DatapathEncodeBindAndUnbindWorkRequests)
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

    encode_jfs_wr_msn(&sendWr, &fixture.comp, 0, true);
    convert_jfs_vwr_to_pwr(&sendWr, 0, 0);
    EXPECT_EQ(URMA_OPC_SEND_IMM, sendWr.opcode);
    EXPECT_EQ(&fixture.phyTarget[0][0], sendWr.tjetty);
    convert_jfs_pwr_to_vwr(&sendWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.target.v_tjetty, sendWr.tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, sendWr.send.src.sge[0].tseg);

    encode_jfs_wr_msn(&writeWr, &fixture.comp, 1, true);
    convert_jfs_vwr_to_pwr(&writeWr, 1, 1);
    EXPECT_EQ(&fixture.phyTarget[1][1], writeWr.tjetty);
    EXPECT_EQ(&fixture.localPhy[1], writeWr.rw.src.sge[0].tseg);
    EXPECT_EQ(&fixture.remotePhy[1][1], writeWr.rw.dst.sge[0].tseg);
    convert_jfs_pwr_to_vwr(&writeWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.target.v_tjetty, writeWr.tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, writeWr.rw.src.sge[0].tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, writeWr.rw.dst.sge[0].tseg);
    convert_jfs_vwr_to_pwr(&writeWr, 0, 0);
    EXPECT_EQ(&fixture.phyTarget[0][0], writeWr.tjetty);
    convert_jfs_pwr_to_vwr(&writeWr, &fixture.target.v_tjetty);

    casWr.opcode = URMA_OPC_CAS;
    casWr.tjetty = &fixture.target.v_tjetty;
    casWr.cas.src = &casSrc;
    casWr.cas.dst = &casDst;
    encode_jfs_wr_msn(&casWr, &fixture.comp, 2, true);
    convert_jfs_vwr_to_pwr(&casWr, 0, 0);
    EXPECT_EQ(&fixture.localPhy[0], casWr.cas.src->tseg);
    EXPECT_EQ(&fixture.remotePhy[0][0], casWr.cas.dst->tseg);
    convert_jfs_pwr_to_vwr(&casWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, casWr.cas.src->tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, casWr.cas.dst->tseg);

    faddWr.opcode = URMA_OPC_FADD;
    faddWr.tjetty = &fixture.target.v_tjetty;
    faddWr.faa.src = &faddSrc;
    faddWr.faa.dst = &faddDst;
    encode_jfs_wr_msn(&faddWr, &fixture.comp, 3, true);
    convert_jfs_vwr_to_pwr(&faddWr, 0, 0);
    EXPECT_EQ(&fixture.localPhy[0], faddWr.faa.src->tseg);
    EXPECT_EQ(&fixture.remotePhy[0][0], faddWr.faa.dst->tseg);
    convert_jfs_pwr_to_vwr(&faddWr, &fixture.target.v_tjetty);
    EXPECT_EQ(&fixture.localSeg.v_tseg, faddWr.faa.src->tseg);
    EXPECT_EQ(&fixture.remoteSeg.v_tseg, faddWr.faa.dst->tseg);

    sendWr.opcode = URMA_OPC_NOP;
    sendWr.tjetty = nullptr;
    encode_jfs_wr_msn(&sendWr, &fixture.comp, 4, true);
    convert_jfs_vwr_to_pwr(&sendWr, 0, 0);
    convert_jfs_pwr_to_vwr(&sendWr, &fixture.target.v_tjetty);
    get_jfs_vwr_refs(&sendWr);
    put_jfs_vwr_refs(&sendWr);

    recvWr.src.sge = fixture.srcSge;
    recvWr.src.num_sge = 1;
    convert_jfr_vwr_to_pwr(&recvWr, 0);
    EXPECT_EQ(&fixture.localPhy[0], recvWr.src.sge[0].tseg);

    cr.flag.bs.s_r = 0;
    cr.imm_data = 0x123456789ULL;
    convert_pcr_to_vcr(&cr, &fixture.ctx, &msn);
}

TEST(UrmaBondTest, DatapathScheduleCoversModesAndErrors)
{
    BondPathFixture fixture;
    int sendIdx = -1;
    int targetIdx = -1;
    int recvIdx = -1;
    bondp_chip_id_info_t chipInfo = { BONDP_CHIP_ID_MIN, BONDP_CHIP_ID_MIN };

    fixture.comp.v_jetty.remote_jetty = &fixture.target.v_tjetty;
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

TEST(UrmaBondTest, DatapathScheduleCoversAffinityAndBatchReceiveBoundaries)
{
    BondPathFixture fixture;
    bondp_comp_t sharedJfr = {};
    int sendIdx = -1;
    int targetIdx = -1;
    uint32_t recvCnt[URMA_UBAGG_DEV_MAX_NUM] = {};
    bondp_chip_id_info_t chipInfo = { BONDP_CHIP_ID_MIN, BONDP_CHIP_ID_MIN };

    fixture.ctx.bonding_mode = BONDP_BONDING_MODE_BALANCE;
    fixture.comp.sqe_cnt[0][0].store(1);
    fixture.comp.sqe_cnt[1][1].store(1);
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));
    EXPECT_TRUE((sendIdx == 0 && targetIdx == 0) || (sendIdx == 1 && targetIdx == 1));

    fixture.comp.comp_type = BONDP_COMP_JFR;
    fixture.comp.v_jfr.jfr_cfg.trans_mode = URMA_TM_RC;
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));

    fixture.comp.comp_type = static_cast<bondp_comp_type_t>(0xff);
    EXPECT_EQ(0, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, nullptr));

    fixture.comp.comp_type = BONDP_COMP_JETTY;
    fixture.ctx.bonding_level = BONDP_BONDING_LEVEL_PORT;
    EXPECT_EQ(URMA_FAIL, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, &chipInfo));

    fixture.ctx.bonding_level = static_cast<bondp_bonding_level_t>(0xff);
    EXPECT_EQ(URMA_EINVAL, schedule_send(&fixture.target.v_tjetty, &fixture.comp, &sendIdx, &targetIdx, &chipInfo));

    EXPECT_EQ(URMA_EINVAL, schedule_recv_n(&fixture.comp, 1, nullptr));
    EXPECT_EQ(0, schedule_recv_n(&fixture.comp, 0, recvCnt));

    sharedJfr.rqe_cnt[0] = 4;
    sharedJfr.rqe_cnt[1] = 1;
    fixture.comp.v_jetty.jetty_cfg.shared.jfr = &sharedJfr.v_jfr;
    ASSERT_EQ(0, schedule_recv_n(&fixture.comp, 3, recvCnt));
    EXPECT_EQ(0U, recvCnt[0]);
    EXPECT_EQ(3U, recvCnt[1]);

    fixture.comp.active_count = 0;
    EXPECT_EQ(-1, schedule_recv_n(&fixture.comp, 1, recvCnt));
}
