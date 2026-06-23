/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core unit tests.
 */

#include <cstdio>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "urma_api.h"
#include "urma_device.h"
#include "urma_log.h"
#include "urma_perf.h"
#include "urma_provider.h"
#include "urma_private.h"

typedef struct urma_test_cfg {
    uint32_t depth;
    uint64_t userCtx;
} urma_test_cfg_t;

typedef struct urma_test_opt {
    uint32_t id;
    uint64_t addr;
} urma_test_opt_t;

static const uint64_t URMA_TEST_DEPTH_OPT = 1;
static const uint64_t URMA_TEST_ID_OPT = 2;
static const uint64_t URMA_TEST_JFS_OPT = 3;
static const uint64_t URMA_TEST_ID_MASK = 0x10;
static const uint64_t URMA_TEST_JFS_MASK = 0x20;

static const opt_map_t TEST_OPT_TABLE[] = {
    { URMA_TEST_DEPTH_OPT, URMA_CFG_MASK, TARGET_CFG, offsetof(urma_test_cfg_t, depth), sizeof(uint32_t) },
    { URMA_TEST_ID_OPT, URMA_TEST_ID_MASK, TARGET_OPT, offsetof(urma_test_opt_t, id), sizeof(uint32_t) },
    { URMA_TEST_JFS_OPT, URMA_TEST_JFS_MASK, TARGET_JFS_CFG, offsetof(urma_test_cfg_t, userCtx),
      sizeof(uint64_t) },
};

namespace {

static int g_logCallbackCount = 0;
static int g_locLogCallbackCount = 0;
static int g_lastLogLevel = -1;
static int g_coreIoctlReturn = -1;
static int g_coreIoctlErrno = ENOTTY;

static void SetCoreIoctlResult(int returnValue, int errorNo)
{
    g_coreIoctlReturn = returnValue;
    g_coreIoctlErrno = errorNo;
}

static void MockLogCallback(int level, char *message)
{
    g_logCallbackCount++;
    g_lastLogLevel = level;
    EXPECT_NE(nullptr, message);
}

static void MockLocLogCallback(int level, const char *file, const char *function, int line, char *message)
{
    g_locLogCallbackCount++;
    g_lastLogLevel = level;
    EXPECT_NE(nullptr, file);
    EXPECT_NE(nullptr, function);
    EXPECT_GT(line, 0);
    EXPECT_NE(nullptr, message);
}

struct CoreApiFixture {
    urma_device_t dev = {};
    urma_sysfs_dev_t sysfsDev = {};
    urma_ops_t ops = {};
    urma_context_t ctx = {};
    urma_jfce_t jfce = {};
    urma_jfc_t jfc = {};
    urma_jfs_t jfs = {};
    urma_jfr_t jfr = {};
    urma_jetty_t jetty = {};
    urma_token_id_t token = {};
    urma_target_seg_t tseg = {};
    urma_seg_t seg = {};
    urma_target_jetty_t tjfr = {};

    CoreApiFixture()
    {
        std::snprintf(dev.name, sizeof(dev.name), "core_ut");
        dev.type = URMA_TRANSPORT_UB;
        sysfsDev.dev_attr.dev_cap.max_jfc_depth = 16;
        sysfsDev.dev_attr.dev_cap.max_jfs_depth = 16;
        sysfsDev.dev_attr.dev_cap.max_jfr_depth = 16;
        sysfsDev.dev_attr.dev_cap.max_jfs_inline_len = 64;
        sysfsDev.dev_attr.dev_cap.max_jfs_sge = 4;
        sysfsDev.dev_attr.dev_cap.max_jfs_rsge = 4;
        sysfsDev.dev_attr.dev_cap.max_jfr_sge = 4;
        sysfsDev.dev_attr.dev_cap.max_jetty_in_jetty_grp = 4;
        dev.sysfs_dev = &sysfsDev;
        ctx.dev = &dev;
        ctx.ops = &ops;
        ctx.ref.atomic_cnt.store(1);
        jfce.urma_ctx = &ctx;
        jfce.ref.atomic_cnt.store(0);

        jfc.urma_ctx = &ctx;
        jfc.jfc_cfg.depth = 4;
        jfc.jfc_cfg.jfce = &jfce;
        jfc.urma_jfc_opt.is_actived = true;

        jfs.urma_ctx = &ctx;
        jfs.jfs_cfg.depth = 4;
        jfs.jfs_cfg.jfc = &jfc;
        jfs.jfs_cfg.trans_mode = URMA_TM_RC;
        jfs.jfs_cfg.max_sge = 1;
        jfs.jfs_cfg.max_rsge = 1;
        jfs.urma_jfs_opt.is_actived = true;

        jfr.urma_ctx = &ctx;
        jfr.jfr_cfg.depth = 4;
        jfr.jfr_cfg.jfc = &jfc;
        jfr.jfr_cfg.trans_mode = URMA_TM_RC;
        jfr.jfr_cfg.flag.bs.order_type = URMA_OL;
        jfr.jfr_cfg.max_sge = 1;
        jfr.urma_jfr_opt.is_actived = true;

        jetty.urma_ctx = &ctx;
        jetty.jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR;
        jetty.jetty_cfg.shared.jfr = &jfr;
        jetty.jetty_cfg.shared.jfc = &jfc;
        jetty.jetty_cfg.jfs_cfg.jfc = &jfc;
        jetty.jetty_cfg.jfs_cfg.depth = 4;
        jetty.jetty_cfg.jfs_cfg.max_sge = 1;
        jetty.jetty_cfg.jfs_cfg.max_rsge = 1;
        jetty.jetty_cfg.jfs_cfg.trans_mode = URMA_TM_RC;
        jetty.urma_jetty_opt.is_actived = true;

        token.urma_ctx = &ctx;
        token.ref.atomic_cnt.store(0);
        tseg.urma_ctx = &ctx;
        tseg.token_id = &token;
        tjfr.urma_ctx = &ctx;
        tjfr.trans_mode = URMA_TM_RM;
        seg.attr.bs.token_policy = URMA_TOKEN_NONE;
    }
};

struct CmdIoctlFailureFixture : CoreApiFixture {
    int pipeFd[2] = { -1, -1 };
    bool eventInit = false;
    urma_cmd_udrv_priv_t udata = {};
    urma_import_tseg_cfg_t importSegCfg = {};
    urma_tjfr_cfg_t tjfrCfg = {};
    urma_tjetty_cfg_t tjettyCfg = {};
    urma_import_jfr_ex_cfg_t importJfrExCfg = {};
    urma_import_jetty_ex_cfg_t importJettyExCfg = {};
    urma_bind_jetty_ex_cfg_t bindJettyExCfg = {};
    urma_notifier_t notifier = {};
    urma_token_t importToken = {};

    ~CmdIoctlFailureFixture()
    {
        if (eventInit) {
            DestroyEventObjects();
        }
        if (pipeFd[0] >= 0) {
            close(pipeFd[0]);
        }
        if (pipeFd[1] >= 0) {
            close(pipeFd[1]);
        }
    }

    bool Init()
    {
        if (pipe(pipeFd) != 0) {
            return false;
        }
        ctx.dev_fd = pipeFd[0];
        ctx.async_fd = pipeFd[0];
        jfce.fd = pipeFd[0];
        notifier.urma_ctx = &ctx;
        notifier.fd = pipeFd[0];
        InitEventObjects();
        InitCommandObjects();
        return true;
    }

private:
    void InitEventObjects()
    {
        ASSERT_EQ(0, pthread_mutex_init(&jfc.event_mutex, nullptr));
        ASSERT_EQ(0, pthread_cond_init(&jfc.event_cond, nullptr));
        ASSERT_EQ(0, pthread_mutex_init(&jfs.event_mutex, nullptr));
        ASSERT_EQ(0, pthread_cond_init(&jfs.event_cond, nullptr));
        ASSERT_EQ(0, pthread_mutex_init(&jfr.event_mutex, nullptr));
        ASSERT_EQ(0, pthread_cond_init(&jfr.event_cond, nullptr));
        ASSERT_EQ(0, pthread_mutex_init(&jetty.event_mutex, nullptr));
        ASSERT_EQ(0, pthread_cond_init(&jetty.event_cond, nullptr));
        eventInit = true;
    }

    void DestroyEventObjects()
    {
        (void)pthread_cond_destroy(&jetty.event_cond);
        (void)pthread_mutex_destroy(&jetty.event_mutex);
        (void)pthread_cond_destroy(&jfr.event_cond);
        (void)pthread_mutex_destroy(&jfr.event_mutex);
        (void)pthread_cond_destroy(&jfs.event_cond);
        (void)pthread_mutex_destroy(&jfs.event_mutex);
        (void)pthread_cond_destroy(&jfc.event_cond);
        (void)pthread_mutex_destroy(&jfc.event_mutex);
    }

    void InitCommandObjects()
    {
        token.urma_ctx = &ctx;
        token.token_id = 0x101;
        token.handle = 0x202;
        tseg.urma_ctx = &ctx;
        tseg.handle = 0x303;
        jfc.handle = 0x404;
        jfc.jfc_id.id = 0x405;
        jfs.handle = 0x505;
        jfs.jfs_id.id = 0x506;
        jfr.handle = 0x606;
        jfr.jfr_id.id = 0x607;
        jetty.handle = 0x707;
        jetty.jetty_id.id = 0x708;
        tjfr.urma_ctx = &ctx;
        tjfr.handle = 0x808;
        tjfr.id.id = 0x809;
        tjfr.trans_mode = URMA_TM_RC;
        tjfr.tp_type = URMA_RTP;
        jetty.remote_jetty = &tjfr;
        importToken.token = 0x909;
        InitImportCfgs();
    }

    void InitImportCfgs()
    {
        importSegCfg.ubva = tseg.seg.ubva;
        importSegCfg.len = 0x1000;
        importSegCfg.token_id = token.token_id;
        importSegCfg.token = &importToken;
        importSegCfg.mva = 0x2000;
        tjfrCfg.jfr_id = tjfr.id;
        tjfrCfg.trans_mode = URMA_TM_RM;
        tjfrCfg.tp_type = URMA_RTP;
        tjfrCfg.token = &importToken;
        tjettyCfg.jetty_id = tjfr.id;
        tjettyCfg.trans_mode = URMA_TM_RC;
        tjettyCfg.tp_type = URMA_RTP;
        tjettyCfg.type = URMA_JETTY;
        tjettyCfg.token = &importToken;
    }
};

struct TempSysfsTree {
    char rootTemplate[64] = "/tmp/urma_core_ut_XXXXXX";
    std::string root;
    std::vector<std::string> files;
    std::vector<std::string> dirs;

    bool Init()
    {
        char *created = mkdtemp(rootTemplate);
        if (created == nullptr) {
            return false;
        }
        root = created;
        return true;
    }

    bool Mkdir(const char *relativePath)
    {
        std::string path = root + "/" + relativePath;
        if (mkdir(path.c_str(), 0700) != 0) {
            return false;
        }
        dirs.push_back(path);
        return true;
    }

    bool WriteFile(const char *relativePath, const char *content)
    {
        std::string path = root + "/" + relativePath;
        FILE *fp = fopen(path.c_str(), "w");
        if (fp == nullptr) {
            return false;
        }
        bool ok = fputs(content, fp) >= 0;
        ok = fclose(fp) == 0 && ok;
        if (ok) {
            files.push_back(path);
        }
        return ok;
    }

    ~TempSysfsTree()
    {
        for (auto it = files.rbegin(); it != files.rend(); ++it) {
            (void)unlink(it->c_str());
        }
        for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
            (void)rmdir(it->c_str());
        }
        if (!root.empty()) {
            (void)rmdir(root.c_str());
        }
    }
};

static urma_jfc_t *MockCreateJfc(urma_context_t *, urma_jfc_cfg_t *cfg)
{
    static urma_jfc_t jfc = {};

    jfc = {};
    jfc.jfc_cfg = *cfg;
    jfc.urma_ctx = cfg->jfce->urma_ctx;
    return &jfc;
}

static urma_status_t MockStatusSuccess()
{
    return URMA_SUCCESS;
}

static urma_status_t MockModifyJfc(urma_jfc_t *, urma_jfc_attr_t *)
{
    return MockStatusSuccess();
}

static urma_status_t MockDeleteJfc(urma_jfc_t *)
{
    return MockStatusSuccess();
}

static urma_status_t MockDeleteJfcBatch(urma_jfc_t **, int, urma_jfc_t **badJfc)
{
    *badJfc = nullptr;
    return URMA_SUCCESS;
}

static urma_status_t MockAllocJfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg, urma_jfc_t **jfc)
{
    static urma_jfc_t mockJfc = {};

    mockJfc.urma_ctx = ctx;
    mockJfc.jfc_cfg = *cfg;
    mockJfc.urma_jfc_opt.is_actived = false;
    *jfc = &mockJfc;
    return URMA_SUCCESS;
}

static urma_status_t MockJfcStatus(urma_jfc_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockJfcOpt(urma_jfc_t *, uint64_t, void *, uint32_t)
{
    return URMA_SUCCESS;
}

static urma_status_t MockModifyJfs(urma_jfs_t *, urma_jfs_attr_t *)
{
    return URMA_ENOPERM;
}

static urma_status_t MockQueryJfs(urma_jfs_t *, urma_jfs_cfg_t *, urma_jfs_attr_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockDeleteJfsBatch(urma_jfs_t **jfsArr, int, urma_jfs_t **badJfs)
{
    *badJfs = jfsArr[1];
    return URMA_FAIL;
}

static urma_status_t MockDeleteJfsBatchSuccess(urma_jfs_t **, int, urma_jfs_t **badJfs)
{
    *badJfs = nullptr;
    return URMA_SUCCESS;
}

static urma_status_t MockModifyJfr(urma_jfr_t *, urma_jfr_attr_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockQueryJfr(urma_jfr_t *, urma_jfr_cfg_t *, urma_jfr_attr_t *)
{
    return URMA_EAGAIN;
}

static urma_status_t MockDeleteJfrBatchSuccess(urma_jfr_t **, int, urma_jfr_t **badJfr)
{
    *badJfr = nullptr;
    return URMA_SUCCESS;
}

static int MockFlushJfs(urma_jfs_t *, int, urma_cr_t *)
{
    return 1;
}

static urma_status_t MockAllocJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg, urma_jfs_t **jfs)
{
    static urma_jfs_t mockJfs = {};

    mockJfs.urma_ctx = ctx;
    mockJfs.jfs_cfg = *cfg;
    mockJfs.urma_jfs_opt.is_actived = false;
    *jfs = &mockJfs;
    return URMA_SUCCESS;
}

static urma_status_t MockJfsStatus(urma_jfs_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockJfsOpt(urma_jfs_t *, uint64_t, void *, uint32_t)
{
    return URMA_SUCCESS;
}

static urma_status_t MockAllocJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg, urma_jfr_t **jfr)
{
    static urma_jfr_t mockJfr = {};

    mockJfr.urma_ctx = ctx;
    mockJfr.jfr_cfg = *cfg;
    mockJfr.urma_jfr_opt.is_actived = false;
    *jfr = &mockJfr;
    return URMA_SUCCESS;
}

static urma_status_t MockJfrStatus(urma_jfr_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockJfrOpt(urma_jfr_t *, uint64_t, void *, uint32_t)
{
    return URMA_SUCCESS;
}

static urma_token_id_t *MockAllocTokenId(urma_context_t *ctx)
{
    static urma_token_id_t token = {};

    token.urma_ctx = ctx;
    token.ref.atomic_cnt.store(0);
    token.token_id = 0xabc;
    return &token;
}

static urma_token_id_t *MockAllocTokenIdEx(urma_context_t *ctx, urma_token_id_flag_t)
{
    return MockAllocTokenId(ctx);
}

static urma_status_t MockFreeTokenId(urma_token_id_t *)
{
    return URMA_SUCCESS;
}

static urma_target_seg_t *MockImportSeg(urma_context_t *ctx, urma_seg_t *, urma_token_t *, uint64_t,
                                        urma_import_seg_flag_t)
{
    static urma_target_seg_t tseg = {};

    tseg = {};
    tseg.urma_ctx = ctx;
    return &tseg;
}

static urma_status_t MockUnimportSeg(urma_target_seg_t *)
{
    return URMA_SUCCESS;
}

static urma_target_seg_t *MockRegisterSeg(urma_context_t *ctx, urma_seg_cfg_t *cfg)
{
    static urma_target_seg_t tseg = {};

    tseg = {};
    tseg.urma_ctx = ctx;
    tseg.token_id = cfg->token_id;
    return &tseg;
}

static urma_status_t MockUnregisterSeg(urma_target_seg_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockGetAsyncEvent(urma_context_t *, urma_async_event_t *)
{
    return URMA_SUCCESS;
}

static void MockAckAsyncEvent(urma_async_event_t *)
{
}

static int MockUserCtl(urma_context_t *, urma_user_ctl_in_t *, urma_user_ctl_out_t *)
{
    return URMA_ENOPERM;
}

static int MockModifyTp(urma_context_t *, uint32_t, urma_tp_cfg_t *, urma_tp_attr_t *, urma_tp_attr_mask_t)
{
    return URMA_SUCCESS;
}

static urma_status_t MockGetTpList(urma_context_t *, urma_get_tp_cfg_t *, uint32_t *tpCnt, urma_tp_info_t *)
{
    *tpCnt = 1;
    return URMA_SUCCESS;
}

static urma_status_t MockSetTpAttr(const urma_context_t *, const uint64_t, const uint8_t,
                                   const uint32_t, const urma_tp_attr_value_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockGetTpAttr(const urma_context_t *, const uint64_t, uint8_t *tpAttrCnt,
                                   uint32_t *tpAttrBitmap, urma_tp_attr_value_t *)
{
    *tpAttrCnt = 1;
    *tpAttrBitmap = 0;
    return URMA_SUCCESS;
}

static urma_status_t MockNetLookup()
{
    return URMA_SUCCESS;
}

static urma_status_t MockGetEidByIp(const urma_context_t *, const urma_net_addr_t *, urma_eid_t *)
{
    return MockNetLookup();
}

static urma_status_t MockGetIpByEid(const urma_context_t *, const urma_eid_t *, urma_net_addr_t *)
{
    return MockNetLookup();
}

static urma_status_t MockGetSmac(const urma_context_t *, uint8_t *)
{
    return MockNetLookup();
}

static urma_status_t MockGetDmac(const urma_context_t *, const urma_net_addr_t *, uint8_t *)
{
    return MockNetLookup();
}

static urma_jfce_t *MockCreateJfce(urma_context_t *ctx)
{
    static urma_jfce_t jfce = {};

    jfce.urma_ctx = ctx;
    jfce.ref.atomic_cnt.store(0);
    return &jfce;
}

static urma_status_t MockDeleteJfce(urma_jfce_t *)
{
    return URMA_SUCCESS;
}

static urma_jetty_t *MockCreateJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg)
{
    static urma_jetty_t jetty = {};

    jetty.urma_ctx = ctx;
    jetty.jetty_cfg = *cfg;
    jetty.urma_jetty_opt.is_actived = false;
    return &jetty;
}

static urma_status_t MockJettyStatus(urma_jetty_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockModifyJetty(urma_jetty_t *, urma_jetty_attr_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockQueryJetty(urma_jetty_t *, urma_jetty_cfg_t *, urma_jetty_attr_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockDeleteJettyBatch(urma_jetty_t **, int, urma_jetty_t **badJetty)
{
    *badJetty = nullptr;
    return URMA_SUCCESS;
}

static int MockFlushJetty(urma_jetty_t *, int, urma_cr_t *)
{
    return 1;
}

static urma_status_t MockAllocJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg, urma_jetty_t **jetty)
{
    static urma_jetty_t mockJetty = {};

    mockJetty.urma_ctx = ctx;
    mockJetty.jetty_cfg = *cfg;
    mockJetty.urma_jetty_opt.is_actived = false;
    *jetty = &mockJetty;
    return URMA_SUCCESS;
}

static urma_status_t MockJettyOpt(urma_jetty_t *, uint64_t, void *, uint32_t)
{
    return URMA_SUCCESS;
}

static urma_target_jetty_t *MockImportJfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *)
{
    static urma_target_jetty_t tjfr = {};

    tjfr.urma_ctx = ctx;
    tjfr.trans_mode = rjfr->trans_mode;
    tjfr.tp_type = rjfr->tp_type;
    return &tjfr;
}

static urma_target_jetty_t *MockImportJfrEx(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *,
                                            urma_active_tp_cfg_t *)
{
    return MockImportJfr(ctx, rjfr, nullptr);
}

static urma_target_jetty_t *MockImportJetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *)
{
    static urma_target_jetty_t tjetty = {};

    tjetty.urma_ctx = ctx;
    tjetty.trans_mode = rjetty->trans_mode;
    tjetty.flag = rjetty->flag;
    tjetty.tp_type = rjetty->tp_type;
    return &tjetty;
}

static urma_target_jetty_t *MockImportJettyEx(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *,
                                              urma_active_tp_cfg_t *)
{
    return MockImportJetty(ctx, rjetty, nullptr);
}

static urma_status_t MockTargetJettyStatus(urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockAdviseJfr(urma_jfs_t *, urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockAdviseJfrAsync(urma_jfs_t *, urma_target_jetty_t *, urma_advise_async_cb_func, void *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockAdviseJetty(urma_jetty_t *, urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockBindJetty(urma_jetty_t *, urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockBindJettyEx(urma_jetty_t *, urma_target_jetty_t *, urma_active_tp_cfg_t *)
{
    return URMA_SUCCESS;
}

static int MockGetTpn(urma_jetty_t *)
{
    return 7;
}

static urma_jetty_grp_t *MockCreateJettyGrp(urma_context_t *ctx, urma_jetty_grp_cfg_t *cfg)
{
    static urma_jetty_grp_t jettyGrp = {};

    jettyGrp.urma_ctx = ctx;
    jettyGrp.cfg = *cfg;
    return &jettyGrp;
}

static urma_status_t MockDeleteJettyGrp(urma_jetty_grp_t *)
{
    return URMA_SUCCESS;
}

static urma_notifier_t *MockCreateNotifier(urma_context_t *ctx)
{
    static urma_notifier_t notifier = {};

    notifier.urma_ctx = ctx;
    return &notifier;
}

static urma_status_t MockDeleteNotifier(urma_notifier_t *)
{
    return URMA_SUCCESS;
}

static int MockWaitNotify(urma_notifier_t *, uint32_t cnt, urma_notify_t *notify, int)
{
    if (cnt > 0) {
        notify[0].status = URMA_SUCCESS;
    }
    return static_cast<int>(cnt);
}

static void MockAckNotify(uint32_t, urma_notify_t *)
{
}

static void MockAdviseCallback(urma_status_t, void *)
{
}

static urma_target_jetty_t *MockImportJettyAsync(urma_notifier_t *notifier, const urma_rjetty_t *rjetty,
                                                 const urma_token_t *, uint64_t, int)
{
    static urma_target_jetty_t tjetty = {};

    tjetty.urma_ctx = notifier->urma_ctx;
    tjetty.trans_mode = rjetty->trans_mode;
    return &tjetty;
}

static urma_status_t MockBindJettyAsync(urma_notifier_t *, urma_jetty_t *, urma_target_jetty_t *, uint64_t, int)
{
    return URMA_SUCCESS;
}

static urma_status_t MockPostJfsWr(urma_jfs_t *, urma_jfs_wr_t *, urma_jfs_wr_t **badWr)
{
    *badWr = nullptr;
    return URMA_SUCCESS;
}

static urma_status_t MockPostJfrWr(urma_jfr_t *, urma_jfr_wr_t *, urma_jfr_wr_t **badWr)
{
    *badWr = nullptr;
    return URMA_SUCCESS;
}

static urma_status_t MockPostJettySendWr(urma_jetty_t *, urma_jfs_wr_t *, urma_jfs_wr_t **badWr)
{
    *badWr = nullptr;
    return URMA_SUCCESS;
}

static urma_status_t MockPostJettyRecvWr(urma_jetty_t *, urma_jfr_wr_t *, urma_jfr_wr_t **badWr)
{
    *badWr = nullptr;
    return URMA_SUCCESS;
}

static int MockPollJfc(urma_jfc_t *, int, urma_cr_t *)
{
    return 1;
}

static urma_status_t MockRearmJfc(urma_jfc_t *, bool)
{
    return URMA_SUCCESS;
}

static int MockWaitJfc(urma_jfce_t *, uint32_t, int, urma_jfc_t *[])
{
    return 1;
}

static void MockAckJfc(urma_jfc_t *[], uint32_t [], uint32_t)
{
}

static urma_status_t MockProviderGetUasid(uint32_t *uasid)
{
    *uasid = 0x5a5a;
    return URMA_SUCCESS;
}

static urma_context_t *MockProviderCreateContext(urma_device_t *dev, uint32_t, int devFd)
{
    static urma_context_t ctx = {};

    ctx.dev = dev;
    ctx.dev_fd = devFd;
    return &ctx;
}

static urma_status_t MockProviderDeleteContext(urma_context_t *)
{
    return URMA_SUCCESS;
}

static urma_status_t MockProviderDeleteContextBusy(urma_context_t *)
{
    return URMA_FAIL;
}

} // namespace

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...)
{
    va_list args;

    va_start(args, request);
    (void)va_arg(args, void *);
    va_end(args);

    (void)fd;
    (void)request;
    errno = g_coreIoctlErrno;
    return g_coreIoctlReturn;
}

TEST(UrmaCoreTest, CheckOptValidUpdatesOnlyOptionMask)
{
    uint64_t mask = 0;

    EXPECT_EQ(URMA_SUCCESS, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_DEPTH_OPT, sizeof(uint32_t)));
    EXPECT_EQ(0U, mask);

    EXPECT_EQ(URMA_SUCCESS, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_ID_OPT, sizeof(uint32_t)));
    EXPECT_EQ(URMA_TEST_ID_MASK, mask);
}

TEST(UrmaCoreTest, CheckOptValidRejectsWrongLengthAndIgnoresUnknownOpt)
{
    uint64_t mask = 0;

    EXPECT_EQ(URMA_EINVAL, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_ID_OPT, sizeof(uint64_t)));
    EXPECT_EQ(0U, mask);

    /* Unknown options are ignored by the public helper, but must not set target bits. */
    EXPECT_EQ(URMA_SUCCESS, urma_check_opt_valid(&mask, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), 0xff, sizeof(uint32_t)));
    EXPECT_EQ(0U, mask);
}

TEST(UrmaCoreTest, SetOptionsCommonWritesTargetStruct)
{
    urma_test_cfg_t cfg = {};
    urma_test_opt_t opt = {};
    urma_test_cfg_t jfsCfg = {};
    uint32_t depth = 128;
    uint32_t id = 7;
    uint64_t userCtx = 0x12345678;

    EXPECT_EQ(URMA_SUCCESS, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_DEPTH_OPT, &depth, sizeof(depth), &cfg, &opt, &jfsCfg));
    EXPECT_EQ(depth, cfg.depth);

    EXPECT_EQ(URMA_SUCCESS, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_ID_OPT, &id, sizeof(id), &cfg, &opt, &jfsCfg));
    EXPECT_EQ(id, opt.id);

    EXPECT_EQ(URMA_SUCCESS, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), URMA_TEST_JFS_OPT, &userCtx, sizeof(userCtx), &cfg, &opt, &jfsCfg));
    EXPECT_EQ(userCtx, jfsCfg.userCtx);

    EXPECT_EQ(URMA_EINVAL, urma_set_options_common(nullptr, TEST_OPT_TABLE,
        ARRAY_SIZE(TEST_OPT_TABLE), 0xff, &id, sizeof(id), &cfg, &opt, &jfsCfg));
}

TEST(UrmaCoreTest, UbaggSwitchCounter)
{
    urma_ubagg_switch_init();
    EXPECT_EQ(0U, urma_ubagg_switch_get());
    urma_ubagg_switch_inc();
    urma_ubagg_switch_inc();
    EXPECT_EQ(2U, urma_ubagg_switch_get());
}

TEST(UrmaCoreTest, LogApisHandleCallbacksLevelsTagsAndEnv)
{
    const char *oldLevelEnv = getenv("URMA_LOG_LEVEL");
    const char *oldSeparatorEnv = getenv("URMA_LOG_SEPARATOR");
    std::string oldLevel = oldLevelEnv == nullptr ? "" : oldLevelEnv;
    std::string oldSeparator = oldSeparatorEnv == nullptr ? "" : oldSeparatorEnv;

    g_logCallbackCount = 0;
    g_locLogCallbackCount = 0;
    EXPECT_EQ(URMA_EINVAL, urma_register_log_func(nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_register_log_func(MockLogCallback));
    urma_log("CoreLogTest", 1, URMA_VLOG_LEVEL_INFO, "plain %d", 1);
    EXPECT_EQ(1, g_logCallbackCount);
    EXPECT_EQ(static_cast<int>(URMA_VLOG_LEVEL_INFO), g_lastLogLevel);

    EXPECT_EQ(URMA_EINVAL, urma_register_loc_log_func(nullptr));
    EXPECT_EQ(URMA_SUCCESS, urma_register_loc_log_func(MockLocLogCallback));
    int locLogCountAfterRegister = g_locLogCallbackCount;
    urma_log_loc("core_test.cpp", "LogApis", 2, URMA_VLOG_LEVEL_ERR, "loc");
    EXPECT_GT(g_locLogCallbackCount, locLogCountAfterRegister);
    EXPECT_EQ(static_cast<int>(URMA_VLOG_LEVEL_ERR), g_lastLogLevel);

    urma_log_set_level(URMA_VLOG_LEVEL_WARNING);
    EXPECT_EQ(URMA_VLOG_LEVEL_WARNING, urma_log_get_level());
    EXPECT_TRUE(urma_log_drop(URMA_VLOG_LEVEL_DEBUG));
    EXPECT_FALSE(urma_log_drop(URMA_VLOG_LEVEL_ERR));
    urma_log_set_level(URMA_VLOG_LEVEL_MAX);
    EXPECT_EQ(URMA_VLOG_LEVEL_WARNING, urma_log_get_level());

    urma_log_set_thread_tag("core-ut");
    EXPECT_STREQ("core-ut", urma_log_get_thread_tag());
    urma_log_set_thread_tag(nullptr);
    EXPECT_STREQ("core-ut", urma_log_get_thread_tag());

    EXPECT_STREQ("fatal", urma_get_level_print(URMA_VLOG_LEVEL_CRIT));
    EXPECT_STREQ("error", urma_get_level_print(URMA_VLOG_LEVEL_ERR));
    EXPECT_STREQ("warning", urma_get_level_print(URMA_VLOG_LEVEL_WARNING));
    EXPECT_STREQ("info", urma_get_level_print(URMA_VLOG_LEVEL_INFO));
    EXPECT_STREQ("debug", urma_get_level_print(URMA_VLOG_LEVEL_DEBUG));
    EXPECT_STREQ("Unknown", urma_get_level_print(URMA_VLOG_LEVEL_MAX));
    EXPECT_EQ(URMA_VLOG_LEVEL_CRIT, urma_log_get_level_from_string("fatal"));
    EXPECT_EQ(URMA_VLOG_LEVEL_ERR, urma_log_get_level_from_string("ERROR"));
    EXPECT_EQ(URMA_VLOG_LEVEL_WARNING, urma_log_get_level_from_string("warning"));
    EXPECT_EQ(URMA_VLOG_LEVEL_INFO, urma_log_get_level_from_string("info"));
    EXPECT_EQ(URMA_VLOG_LEVEL_DEBUG, urma_log_get_level_from_string("debug"));
    EXPECT_EQ(URMA_VLOG_LEVEL_MAX, urma_log_get_level_from_string(nullptr));
    EXPECT_EQ(URMA_VLOG_LEVEL_MAX, urma_log_get_level_from_string("invalid"));

    setenv("URMA_LOG_LEVEL", "debug", 1);
    urma_getenv_log_level();
    EXPECT_EQ(URMA_VLOG_LEVEL_DEBUG, urma_log_get_level());
    setenv("URMA_LOG_LEVEL", "invalid", 1);
    urma_getenv_log_level();
    EXPECT_EQ(URMA_VLOG_LEVEL_DEBUG, urma_log_get_level());
    setenv("URMA_LOG_SEPARATOR", ":", 1);
    urma_getenv_log_separator();
    setenv("URMA_LOG_SEPARATOR", "bad@", 1);
    urma_getenv_log_separator();

    urma_log_rl_state_t rl = {};
    EXPECT_TRUE(urma_log_rl_check(&rl, "core_test.cpp", "LogApis", 3));
    for (uint32_t i = 0; i < URMA_LOG_RL_LIMIT + 1; i++) {
        (void)urma_log_rl_check(&rl, "core_test.cpp", "LogApis", 3);
    }

    EXPECT_EQ(URMA_SUCCESS, urma_unregister_log_func());
    if (oldLevelEnv == nullptr) {
        unsetenv("URMA_LOG_LEVEL");
    } else {
        setenv("URMA_LOG_LEVEL", oldLevel.c_str(), 1);
    }
    if (oldSeparatorEnv == nullptr) {
        unsetenv("URMA_LOG_SEPARATOR");
    } else {
        setenv("URMA_LOG_SEPARATOR", oldSeparator.c_str(), 1);
    }
}

TEST(UrmaCoreTest, PerfApisRecordAndFormatStats)
{
    char perfBuf[8192] = {};
    uint32_t len = sizeof(perfBuf);
    uint64_t start = 0;
    uint64_t end = 0;

    EXPECT_FALSE(urma_perf_is_enabled());
    EXPECT_EQ(URMA_ENOPERM, urma_step_perf(UB_JFS_POST_SEND, 100));
    EXPECT_EQ(URMA_SUCCESS, urma_start_perf());
    EXPECT_TRUE(urma_perf_is_enabled());

    start = urma_get_perf_timestamp();
    end = urma_get_perf_timestamp();
    EXPECT_GE(end, start);
    EXPECT_EQ(URMA_EINVAL, urma_step_perf(URMA_PERF_RECORD_TYPE_MAX, 1));
    EXPECT_EQ(URMA_EINVAL, urma_step_perf(UB_JFS_POST_SEND, 0));
    EXPECT_EQ(URMA_SUCCESS, urma_step_perf(UB_JFS_POST_SEND, 1));
    EXPECT_EQ(URMA_SUCCESS, urma_step_perf(UB_JFS_POST_SEND, 1024));
    EXPECT_EQ(URMA_EINVAL, urma_get_perf_info(nullptr, &len));
    EXPECT_EQ(URMA_EINVAL, urma_get_perf_info(perfBuf, nullptr));
    len = 1;
    EXPECT_EQ(URMA_EINVAL, urma_get_perf_info(perfBuf, &len));
    len = sizeof(perfBuf);
    EXPECT_EQ(URMA_SUCCESS, urma_get_perf_info(perfBuf, &len));
    EXPECT_NE(nullptr, strstr(perfBuf, "UB_JFS_POST_SEND"));
    EXPECT_GT(len, 0U);

    EXPECT_EQ(URMA_SUCCESS, urma_stop_perf());
    EXPECT_FALSE(urma_perf_is_enabled());
}

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

    ASSERT_TRUE(fixture.Init());
    SetCoreIoctlResult(-1, ENOTTY);
    jettyCfg = fixture.jetty.jetty_cfg;
    std::snprintf(jettyGrpCfg.name, sizeof(jettyGrpCfg.name), "cmd_grp");

    EXPECT_EQ(-1, urma_cmd_create_jfce(&fixture.ctx));
    EXPECT_EQ(-1, urma_cmd_create_jetty(&fixture.ctx, &fixture.jetty, &jettyCfg, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_modify_jetty(&fixture.jetty, &jettyAttr, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_query_jetty(&fixture.jetty, &jettyCfg, &jettyAttr));
    EXPECT_EQ(-1, urma_cmd_delete_jetty(&fixture.jetty));
    EXPECT_EQ(-1, urma_cmd_alloc_jetty(&fixture.ctx, &jettyCfg, &fixture.jetty, &fixture.udata));
    EXPECT_EQ(-1, urma_cmd_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &optValue, sizeof(optValue),
        &fixture.udata));
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

TEST(UrmaCoreTest, CmdWrappersFillObjectsWhenIoctlSucceeds)
{
    CoreApiFixture fixture;
    urma_cmd_udrv_priv_t udata = {};
    urma_token_id_t token = {};
    urma_target_seg_t tseg = {};
    urma_seg_cfg_t segCfg = {};
    urma_import_tseg_cfg_t importSegCfg = {};
    urma_jfc_t jfc = {};
    urma_jfs_t jfs = {};
    urma_jfr_t jfr = {};
    urma_jetty_t jetty = {};
    urma_jetty_cfg_t jettyCfgNoRxJfc = fixture.jetty.jetty_cfg;
    urma_target_jetty_t tjfr = {};
    urma_target_jetty_t tjetty = {};
    urma_notifier_t notifier = {};
    urma_tjfr_cfg_t tjfrCfg = {};
    urma_tjetty_cfg_t tjettyCfg = {};
    urma_import_jfr_ex_cfg_t importJfrExCfg = {};
    urma_import_jetty_ex_cfg_t importJettyExCfg = {};
    urma_bind_jetty_ex_cfg_t bindJettyExCfg = {};
    urma_jetty_grp_t jettyGrp = {};
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
    std::snprintf(jettyGrpCfg.name, sizeof(jettyGrpCfg.name), "cmd_success_grp");

    SetCoreIoctlResult(0, 0);
    EXPECT_EQ(0, urma_cmd_alloc_token_id(&fixture.ctx, &token, &udata));
    EXPECT_EQ(0, urma_cmd_register_seg(&fixture.ctx, &tseg, &segCfg, &udata));
    EXPECT_EQ(0, urma_cmd_import_seg(&fixture.ctx, &tseg, &importSegCfg, &udata));

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
    fixture.ctx.ref.atomic_cnt.store(3);
    fixture.ops.delete_jfr_batch = MockDeleteJfrBatchSuccess;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jfr_batch(jfrArr, 2, &badJfr));
    EXPECT_EQ(nullptr, badJfr);
    EXPECT_EQ(1UL, fixture.ctx.ref.atomic_cnt.load());
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
    EXPECT_EQ(URMA_EINVAL, urma_delete_jetty_batch(jettyArr, 2, &badJetty));
    EXPECT_EQ(&fixture.jetty, badJetty);
    jettyArr[1] = &fixture.jetty;
    fixture.ops.delete_jetty_batch = MockDeleteJettyBatch;
    EXPECT_EQ(URMA_SUCCESS, urma_delete_jetty_batch(jettyArr, 2, &badJetty));

    ASSERT_EQ(0, pthread_mutex_init(&jettyGrp.list_mutex, nullptr));
    jettyGrp.urma_ctx = &fixture.ctx;
    jettyGrp.jetty_list = static_cast<urma_jetty_t **>(calloc(4, sizeof(urma_jetty_t *)));
    ASSERT_NE(nullptr, jettyGrp.jetty_list);
    jettyCfg.jetty_grp = &jettyGrp;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RM;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_DEF_ORDER;
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
    free(jettyGrp.jetty_list);
    jettyCfg.jetty_grp = nullptr;
    jettyCfg.jfs_cfg.trans_mode = URMA_TM_RC;
    jettyCfg.jfs_cfg.flag.bs.order_type = URMA_DEF_ORDER;
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
    fixture.ops.set_jetty_opt = MockJettyOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_set_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    EXPECT_EQ(URMA_EINVAL, urma_get_jetty_opt(&fixture.jetty, 0, &depth, sizeof(depth)));
    fixture.ops.get_jetty_opt = MockJettyOpt;
    EXPECT_EQ(URMA_SUCCESS, urma_get_jetty_opt(&fixture.jetty, URMA_JFS_DEPTH, &depth, sizeof(depth)));
    fixture.jfc.urma_jfc_opt.is_actived = true;
    fixture.jfr.urma_jfr_opt.is_actived = true;
    fixture.ops.active_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_active_jetty(&fixture.jetty));
    fixture.ops.deactive_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_deactive_jetty(&fixture.jetty));
    fixture.ops.free_jetty = MockJettyStatus;
    EXPECT_EQ(URMA_SUCCESS, urma_free_jetty(&fixture.jetty));
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

    EXPECT_EQ(nullptr, urma_import_jetty_async(nullptr, &rjetty, &tokenValue, 0, 0));
    EXPECT_EQ(nullptr, urma_import_jetty_async(notifier, &rjetty, &tokenValue, 0, 0));
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
    urma_free_net_addr_list(nullptr);
    urma_net_addr_info_t *list = static_cast<urma_net_addr_info_t *>(calloc(1, sizeof(*list)));
    ASSERT_NE(nullptr, list);
    urma_free_net_addr_list(list);
}

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
    urma_free_eid_list(nullptr);
    EXPECT_EQ(URMA_EINVAL, urma_query_device(nullptr, &fixture.sysfsDev.dev_attr));
    EXPECT_EQ(URMA_EINVAL, urma_query_device(&fixture.dev, nullptr));
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
    ASSERT_TRUE(sysfs.WriteFile("full", "1234"));
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
    EXPECT_EQ(-1, urma_read_sysfs_file(sysfs.root.c_str(), "missing", readBuf, sizeof(readBuf)));
    EXPECT_EQ(-1, urma_read_sysfs_file(sysfs.root.c_str(), "full", readBuf, 4));
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
