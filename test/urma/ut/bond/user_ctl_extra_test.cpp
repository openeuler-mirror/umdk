/* SPDX-License-Identifier: MIT */
/* Extra bondp user_ctl opcode coverage: SET_BONDING_PORT / SET_CTX_CFG /
 * QUERY_PORT_STATUS / GET_USER_TSEG / FILL_USER_TSEG. */

#include "bond_fixture.h"

using namespace urma_test_bond;

TEST(UrmaBondTest, UserCtlSetBondingPortValidatesAndStores)
{
    BondPublicApiFixture fixture;
    bondp_set_bonding_port_in_t portIn = {};
    bondp_port_id_t ids[2] = {};
    urma_user_ctl_out_t unusedOut = {};

    fixture.InitSinglePhysicalMember();

    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, nullptr, 0, &unusedOut));

    portIn.port_ids = nullptr;
    portIn.port_count = 1;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn, sizeof(portIn) - 1,
                        &unusedOut));
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn, sizeof(portIn),
                        &unusedOut));

    portIn.port_ids = ids;
    portIn.port_count = 0;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn, sizeof(portIn),
                        &unusedOut));
    portIn.port_count = URMA_UBAGG_DEV_MAX_NUM + 1;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn, sizeof(portIn),
                        &unusedOut));

    /* port_idx below URMA_ACTIVE_PORT_MIN is not a valid port EID */
    portIn.port_count = 1;
    ids[0].bs.chip_id = 1;
    ids[0].bs.die_id = 1;
    ids[0].bs.port_idx = 1;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn, sizeof(portIn),
                        &unusedOut));

    /* primary EID of chip 1 -> active index 0 (p_ctxs[0] is alive) */
    ids[0].bs.port_idx = UINT8_MAX;
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn,
                                 sizeof(portIn), &unusedOut));
    EXPECT_TRUE(fixture.ctx.port_cfg_enable);
    EXPECT_EQ(1U, fixture.ctx.port_cfg.enabled_count);
    EXPECT_EQ(0U, fixture.ctx.port_cfg.enabled_indices[0]);
    EXPECT_EQ(1U, fixture.ctx.port_cfg.chip_id_count);

    /* duplicate port ids are rejected */
    ids[1] = ids[0];
    portIn.port_count = 2;
    EXPECT_EQ(-EINVAL,
        CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn, sizeof(portIn),
                        &unusedOut));

    /* port EID: chip 1 / port 4 maps to active index get_matrix_port_p_idx(0, 4) = 6 */
    fixture.ctx.dev_num = URMA_UBAGG_DEV_MAX_NUM;
    fixture.ctx.p_ctxs[6] = &fixture.phyCtx;
    ids[0].bs.port_idx = URMA_ACTIVE_PORT_MIN;
    portIn.port_count = 1;
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_BONDING_PORT, &portIn,
                                 sizeof(portIn), &unusedOut));
    EXPECT_EQ(1U, fixture.ctx.port_cfg.enabled_count);
    EXPECT_EQ(6U, fixture.ctx.port_cfg.enabled_indices[0]);
    fixture.ctx.p_ctxs[6] = nullptr;
}

TEST(UrmaBondTest, UserCtlSetCtxCfgValidatesAndApplies)
{
    BondPublicApiFixture fixture;
    bondp_set_ctx_cfg_in_t cfg = {};
    urma_user_ctl_out_t unusedOut = {};

    /* start from a fully valid configuration */
    fixture.ctx.health_check_interval_ms = 1000;
    fixture.ctx.health_check_batch_node_num = 1;
    fixture.ctx.rnr_retry_max = 1;

    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, nullptr,
                                       sizeof(cfg), &unusedOut));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg,
                                       sizeof(cfg) - 1, &unusedOut));
    cfg.mask = 0;
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg,
                                       sizeof(cfg), &unusedOut));
    cfg.mask = ~BONDP_CTX_CFG_MASK_ALL; /* unknown bits */
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg,
                                       sizeof(cfg), &unusedOut));

    /* context still referenced -> EAGAIN */
    fixture.ctx.v_ctx.ref.atomic_cnt.store(2);
    cfg.mask = BONDP_CTX_CFG_ENABLE_FAILOVER;
    cfg.enable_failover = true;
    EXPECT_EQ(URMA_EAGAIN, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg,
                                           sizeof(cfg), &unusedOut));

    fixture.ctx.v_ctx.ref.atomic_cnt.store(1);
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg, sizeof(cfg),
                                 &unusedOut));
    EXPECT_TRUE(fixture.ctx.enable_failover);

    /* numeric fields are applied under the mask, out-of-range values rejected */
    cfg.mask = BONDP_CTX_CFG_HEALTH_CHECK_INTERVAL | BONDP_CTX_CFG_HEALTH_CHECK_BATCH_NUM |
               BONDP_CTX_CFG_RNR_MAX | BONDP_CTX_CFG_RNR_JITTER_RATIO;
    cfg.health_check_interval_ms = 500;
    cfg.health_check_batch_node_num = 4;
    cfg.rnr_retry_max = 8;
    cfg.rnr_retry_jitter_ratio = 10;
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg, sizeof(cfg),
                                 &unusedOut));
    EXPECT_EQ(500U, fixture.ctx.health_check_interval_ms);
    EXPECT_EQ(4U, fixture.ctx.health_check_batch_node_num);
    EXPECT_EQ(8U, fixture.ctx.rnr_retry_max);
    EXPECT_EQ(10U, fixture.ctx.rnr_retry_jitter_ratio);

    cfg.health_check_interval_ms = 1; /* below the minimum */
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_SET_CTX_CFG, &cfg,
                                       sizeof(cfg), &unusedOut));
}

TEST(UrmaBondTest, UserCtlQueryPortStatusFillsEnabledPorts)
{
    BondPublicApiFixture fixture;
    bondp_query_port_status_out_t statusOut = {};
    urma_user_ctl_in_t in = MakeUserCtl(BONDP_USER_CTL_QUERY_PORT_STATUS, nullptr, 0);
    urma_user_ctl_out_t out = MakeUserCtlOut(&statusOut, sizeof(statusOut));

    /* parameter validation */
    out = MakeUserCtlOut(&statusOut, sizeof(statusOut) - 1);
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    out = MakeUserCtlOut(nullptr, sizeof(statusOut));
    EXPECT_EQ(-EINVAL, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));

    /* from the context enabled indices, with a bad port marked */
    out = MakeUserCtlOut(&statusOut, sizeof(statusOut));
    fixture.ctx.enabled_count = 2;
    fixture.ctx.enabled_indices[0] = 0;
    fixture.ctx.enabled_indices[1] = 6;
    fixture.ctx.port_status_bad[0] = true;
    EXPECT_EQ(0, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    EXPECT_EQ(2U, statusOut.port_count);
    EXPECT_EQ(BONDP_PORT_STATUS_BAD, statusOut.port_status[0].status);
    /* active index 0 -> primary EID of chip 1 (port_idx = UINT8_MAX) */
    EXPECT_EQ(1U, statusOut.port_status[0].chip_id);
    EXPECT_EQ(UINT8_MAX, statusOut.port_status[0].port_idx);
    EXPECT_EQ(BONDP_PORT_STATUS_GOOD, statusOut.port_status[1].status);

    /* the port config takes precedence once configured */
    fixture.ctx.port_cfg_enable = true;
    fixture.ctx.port_cfg.enabled_count = 1;
    fixture.ctx.port_cfg.enabled_indices[0] = 0;
    fixture.ctx.port_status_bad[0] = false;
    statusOut = {};
    EXPECT_EQ(0, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    EXPECT_EQ(1U, statusOut.port_count);
    EXPECT_EQ(BONDP_PORT_STATUS_GOOD, statusOut.port_status[0].status);

    /* an out-of-range enabled index is skipped */
    fixture.ctx.port_cfg.enabled_indices[0] = URMA_UBAGG_DEV_MAX_NUM + 1;
    statusOut = {};
    EXPECT_EQ(0, bondp_user_ctl(&fixture.ctx.v_ctx, &in, &out));
    EXPECT_EQ(0U, statusOut.port_count);
}

TEST(UrmaBondTest, UserCtlGetAndFillUserTseg)
{
    BondPublicApiFixture fixture;
    bondp_tseg_t tseg = {};
    urma_token_id_t token = {};
    urma_target_seg_t phySeg = {};
    urma_user_tseg_t *userTseg = nullptr;
    urma_user_ctl_out_t out = {};

    tseg.v_tseg.urma_ctx = &fixture.ctx.v_ctx;
    tseg.v_tseg.token_id = &token;
    phySeg.seg.token_id = 0x71;
    tseg.p_tseg[0] = &phySeg;

    /* imported segs (no token id) do not expose per-slave token ids */
    tseg.v_tseg.token_id = nullptr;
    out = MakeUserCtlOut(&userTseg, sizeof(userTseg));
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_GET_USER_TSEG,
                                       &tseg.v_tseg, sizeof(tseg.v_tseg), &out));

    tseg.v_tseg.token_id = &token;
    out = MakeUserCtlOut(&userTseg, sizeof(userTseg) - 1);
    EXPECT_EQ(-EINVAL, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_GET_USER_TSEG,
                                       &tseg.v_tseg, sizeof(tseg.v_tseg), &out));

    userTseg = nullptr;
    out = MakeUserCtlOut(&userTseg, sizeof(userTseg));
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_GET_USER_TSEG,
                                 &tseg.v_tseg, sizeof(tseg.v_tseg), &out));
    ASSERT_NE(nullptr, userTseg);
    EXPECT_NE(0U, userTseg->attr.bs.has_user_info);
    std::free(userTseg);

    /* fill variant: size probe then in-place copy */
    std::vector<uint8_t> buf(64);
    urma_user_ctl_out_t fillOut = MakeUserCtlOut(buf.data(), 0);
    EXPECT_EQ(-ENOSPC, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_FILL_USER_TSEG,
                                       &tseg.v_tseg, sizeof(tseg.v_tseg), &fillOut));
    uint32_t need = fillOut.len;
    EXPECT_GT(need, 0U);

    buf.resize(need);
    fillOut = MakeUserCtlOut(buf.data(), need);
    EXPECT_EQ(0, CallBondUserCtl(&fixture.ctx.v_ctx, BONDP_USER_CTL_OPCODE_FILL_USER_TSEG,
                                 &tseg.v_tseg, sizeof(tseg.v_tseg), &fillOut));
    EXPECT_EQ(need, fillOut.len);
    auto *filled = reinterpret_cast<urma_user_tseg_t *>(buf.data());
    EXPECT_NE(0U, filled->attr.bs.has_user_info);
}
