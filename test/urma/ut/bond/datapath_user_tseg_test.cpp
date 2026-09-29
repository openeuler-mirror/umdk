/* SPDX-License-Identifier: MIT */
/* Import-free (user_tseg) remote SGE conversion paths of bondp_datapath_convert. */

#include "bond_fixture.h"

using namespace urma_test_bond;

namespace {

/* Build a real bonding user_tseg buffer through the public user_ctl, the same
 * way an application obtains it before posting an import-free WR. */
urma_user_tseg_t *MakeBondUserTseg(BondPublicApiFixture &fixture, bondp_tseg_t &localTseg,
                                   urma_token_id_t &token, urma_target_seg_t &phySeg)
{
    urma_user_tseg_t *userTseg = nullptr;
    urma_user_ctl_out_t out = {};

    localTseg.v_tseg.urma_ctx = &fixture.ctx.v_ctx;
    localTseg.v_tseg.token_id = &token;
    phySeg.seg.token_id = 0x71;
    localTseg.p_tseg[0] = &phySeg;

    out = MakeUserCtlOut(&userTseg, sizeof(userTseg));
    if (CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_GET_USER_TSEG, &localTseg.v_tseg,
                        sizeof(localTseg.v_tseg), &out) != 0) {
        return nullptr;
    }
    return userTseg;
}

} // namespace

TEST(UrmaBondTest, DatapathConvertMapsAndRestoresImportFreeUserTseg)
{
    BondPublicApiFixture fixture;
    bondp_tseg_t localTseg = {};
    urma_token_id_t token = {};
    urma_target_seg_t phySeg = {};
    urma_user_tseg_t *userTseg = MakeBondUserTseg(fixture, localTseg, token, phySeg);
    ASSERT_NE(nullptr, userTseg);
    ASSERT_NE(0U, userTseg->attr.bs.has_user_info);

    urma_sge_t srcSge = {};
    urma_sge_t dstSge = {};
    srcSge.tseg = &localTseg.v_tseg;
    srcSge.len = 64;
    srcSge.addr = 0x1000;
    /* import-free remote SGE: no tseg, only a user_tseg extension */
    dstSge.tseg = nullptr;
    dstSge.user_tseg = userTseg;
    dstSge.len = 64;
    dstSge.addr = 0x2000;

    urma_sg_t srcSg = {.sge = &srcSge, .num_sge = 1};
    urma_sg_t dstSg = {.sge = &dstSge, .num_sge = 1};
    urma_jfs_wr_t wr = {};
    wr.opcode = URMA_OPC_WRITE;
    wr.rw.src = srcSg;
    wr.rw.dst = dstSg;

    EXPECT_EQ(1U, jfs_wr_count_remote_user_tseg(&wr));

    urma_user_tseg_t scratch[2] = {};
    urma_user_tseg_t *saved[2] = {};
    convert_jfs_vwr_to_pwr(&wr, 0, 0, scratch, saved);

    /* the SGE now points at the bare per-path copy: peer token id, no extension */
    EXPECT_EQ(&scratch[0], wr.rw.dst.sge[0].user_tseg);
    EXPECT_EQ(0U, wr.rw.dst.sge[0].user_tseg->attr.bs.has_user_info);
    EXPECT_EQ(0x71U, wr.rw.dst.sge[0].user_tseg->token_id);
    EXPECT_EQ(userTseg, saved[0]);

    convert_jfs_pwr_to_vwr(&wr, &fixture.targetJetty.v_tjetty, saved);
    EXPECT_EQ(userTseg, wr.rw.dst.sge[0].user_tseg);

    std::free(userTseg);
}

TEST(UrmaBondTest, DatapathConvertHandlesMissingImportFreeScratchSlots)
{
    BondPublicApiFixture fixture;
    bondp_tseg_t localTseg = {};
    urma_token_id_t token = {};
    urma_target_seg_t phySeg = {};
    urma_user_tseg_t *userTseg = MakeBondUserTseg(fixture, localTseg, token, phySeg);
    ASSERT_NE(nullptr, userTseg);

    urma_sge_t dstSge = {};
    dstSge.user_tseg = userTseg;
    dstSge.len = 64;
    urma_sg_t dstSg = {.sge = &dstSge, .num_sge = 1};
    urma_sge_t srcSge = {};
    srcSge.tseg = &localTseg.v_tseg;
    srcSge.len = 64;
    urma_sg_t srcSg = {.sge = &srcSge, .num_sge = 1};
    urma_jfs_wr_t wr = {};
    wr.opcode = URMA_OPC_WRITE;
    wr.rw.src = srcSg;
    wr.rw.dst = dstSg;

    /* no scratch slots: the conversion must keep the virtual pointer (no crash) */
    convert_jfs_vwr_to_pwr(&wr, 0, 0, nullptr, nullptr);
    EXPECT_EQ(userTseg, wr.rw.dst.sge[0].user_tseg);

    /* restore without saved pointers drops the stale pointer instead of keeping it */
    convert_jfs_pwr_to_vwr(&wr, &fixture.targetJetty.v_tjetty, nullptr);
    EXPECT_EQ(nullptr, wr.rw.dst.sge[0].user_tseg);

    std::free(userTseg);
}
