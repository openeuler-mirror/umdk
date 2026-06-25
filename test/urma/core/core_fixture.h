/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 * Description: URMA core unit test helpers.
 */

#ifndef TEST_URMA_CORE_CORE_FIXTURE_H
#define TEST_URMA_CORE_CORE_FIXTURE_H

#include <cstdio>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "urma_api.h"
#include "urma_cmd_tlv.h"
#include "urma_device.h"
#include "urma_log.h"
#include "urma_perf.h"
#include "urma_provider.h"
#include "urma_private.h"
#include "urma_hw_mock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"

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
static const uint32_t CORE_USER_CTL_GET_RJETTY = 9;
static const uint32_t CORE_USER_CTL_GET_SEG_CTX = 10;

static const opt_map_t TEST_OPT_TABLE[] = {
    { URMA_TEST_DEPTH_OPT, URMA_CFG_MASK, TARGET_CFG, offsetof(urma_test_cfg_t, depth), sizeof(uint32_t) },
    { URMA_TEST_ID_OPT, URMA_TEST_ID_MASK, TARGET_OPT, offsetof(urma_test_opt_t, id), sizeof(uint32_t) },
    { URMA_TEST_JFS_OPT, URMA_TEST_JFS_MASK, TARGET_JFS_CFG, offsetof(urma_test_cfg_t, userCtx),
      sizeof(uint64_t) },
};

namespace urma_test_core {

extern int g_logCallbackCount;
extern int g_locLogCallbackCount;
extern int g_lastLogLevel;
extern int g_coreIoctlReturn;
extern int g_coreIoctlErrno;
extern uint32_t g_coreAsyncEventType;
extern uint64_t g_coreAsyncEventData;
extern uint32_t g_coreQueryJettyFlag;
extern uint32_t g_coreBatchBadIndex;
extern std::string g_coreSysfsRedirectRoot;
extern std::string g_coreProviderDliPath;
extern int g_coreDlopenCount;
extern int g_coreDlcloseCount;
static const char CORE_SYSFS_PREFIX[] = "/sys/class/ubcore";

inline void SetCoreIoctlResult(int returnValue, int errorNo)
{
    g_coreIoctlReturn = returnValue;
    g_coreIoctlErrno = errorNo;
}

inline std::string MapCoreSysfsPath(const char *path)
{
    if (path == nullptr || g_coreSysfsRedirectRoot.empty()) {
        return path == nullptr ? std::string() : std::string(path);
    }

    const size_t prefixLen = sizeof(CORE_SYSFS_PREFIX) - 1;
    if (strncmp(path, CORE_SYSFS_PREFIX, prefixLen) != 0) {
        return std::string(path);
    }
    return g_coreSysfsRedirectRoot + (path + prefixLen);
}

inline void MockLogCallback(int level, char *message)
{
    g_logCallbackCount++;
    g_lastLogLevel = level;
    EXPECT_NE(nullptr, message);
}

inline void MockLocLogCallback(int level, const char *file, const char *function, int line, char *message)
{
    g_locLogCallbackCount++;
    g_lastLogLevel = level;
    EXPECT_NE(nullptr, file);
    EXPECT_NE(nullptr, function);
    EXPECT_GT(line, 0);
    EXPECT_NE(nullptr, message);
}

inline void *CorePerfWorker(void *)
{
    (void)urma_get_perf_timestamp();
    EXPECT_EQ(URMA_SUCCESS, urma_step_perf(UB_JFS_POST_SEND, 1));
    return nullptr;
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
        urma_test::ResetHwMockState();
        g_coreQueryJettyFlag = URMA_SHARE_JFR;
        g_coreBatchBadIndex = 0;
        g_coreAsyncEventType = URMA_EVENT_PORT_ACTIVE;
        g_coreAsyncEventData = 0x7;
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

    void InstallMockOps();
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

struct SysfsFileSpec {
    const char *path;
    const char *value;
};

inline void PopulateReadableSysfsDevice(TempSysfsTree *sysfs, const char *devName)
{
    static const SysfsFileSpec files[] = {
        { "ubdev", "core_sysfs_dev\n" },
        { "driver_name", "core_driver\n" },
        { "transport_type", "0\n" },
        { "guid", "192.168.10.1\n" },
        { "feature", "1\n" },
        { "max_jfc", "2\n" },
        { "max_jfs", "3\n" },
        { "max_jfr", "4\n" },
        { "max_jetty", "5\n" },
        { "max_jetty_grp", "6\n" },
        { "max_jetty_in_jetty_grp", "7\n" },
        { "max_jfc_depth", "8\n" },
        { "max_jfs_depth", "9\n" },
        { "max_jfr_depth", "10\n" },
        { "max_jfs_inline_size", "11\n" },
        { "max_jfs_sge", "12\n" },
        { "max_jfs_rsge", "13\n" },
        { "max_jfr_sge", "14\n" },
        { "max_msg_size", "4096\n" },
        { "trans_mode", "3\n" },
        { "port_count", "1\n" },
        { "max_eid_cnt", "2\n" },
        { "page_size_cap", "65536\n" },
        { "reserved_jetty_id", "17-19\n" },
        { "device/vendor", "21\n" },
        { "device/device", "22\n" },
        { "port0/max_mtu", "4\n" },
        { "port0/state", "1\n" },
        { "port0/active_width", "2\n" },
        { "port0/active_speed", "3\n" },
        { "port0/active_mtu", "5\n" },
    };
    std::string prefix = std::string(devName) + "/";

    ASSERT_TRUE(sysfs->Mkdir(devName));
    ASSERT_TRUE(sysfs->Mkdir((prefix + "device").c_str()));
    ASSERT_TRUE(sysfs->Mkdir((prefix + "port0").c_str()));
    for (const auto &file : files) {
        ASSERT_TRUE(sysfs->WriteFile((prefix + file.path).c_str(), file.value));
    }
}

inline void CleanupSysfsDeviceList(struct ub_list *devList)
{
    urma_sysfs_dev_t *sysfsDev = nullptr;
    urma_sysfs_dev_t *next = nullptr;

    UB_LIST_FOR_EACH_SAFE (sysfsDev, next, node, devList) {
        ub_list_remove(&sysfsDev->node);
        std::free(sysfsDev->urma_device);
        std::free(sysfsDev);
    }
}

inline void CleanupSysfsDevNameList(struct ub_list *devNameList)
{
    urma_sysfs_dev_name_t *sysfsDevName = nullptr;
    urma_sysfs_dev_name_t *next = nullptr;

    UB_LIST_FOR_EACH_SAFE (sysfsDevName, next, node, devNameList) {
        ub_list_remove(&sysfsDevName->node);
        std::free(sysfsDevName);
    }
}

inline urma_sysfs_dev_t *AllocMemorySysfsDevice(const char *devName, uint32_t flags)
{
    auto *sysfsDev = static_cast<urma_sysfs_dev_t *>(std::calloc(1, sizeof(urma_sysfs_dev_t)));
    auto *dev = static_cast<urma_device_t *>(std::calloc(1, sizeof(urma_device_t)));
    if (sysfsDev == nullptr || dev == nullptr) {
        std::free(dev);
        std::free(sysfsDev);
        return nullptr;
    }

    std::snprintf(sysfsDev->dev_name, sizeof(sysfsDev->dev_name), "%s", devName);
    std::snprintf(dev->name, sizeof(dev->name), "%s", devName);
    sysfsDev->flag = flags;
    sysfsDev->urma_device = dev;
    dev->sysfs_dev = sysfsDev;
    return sysfsDev;
}

struct CoreSysfsRedirectGuard {
    explicit CoreSysfsRedirectGuard(const std::string &root)
    {
        g_coreSysfsRedirectRoot = root;
    }

    ~CoreSysfsRedirectGuard()
    {
        g_coreSysfsRedirectRoot.clear();
    }
};

struct CoreProviderRedirectGuard {
    explicit CoreProviderRedirectGuard(const std::string &dliPath)
    {
        g_coreProviderDliPath = dliPath;
        g_coreDlopenCount = 0;
        g_coreDlcloseCount = 0;
    }

    ~CoreProviderRedirectGuard()
    {
        g_coreProviderDliPath.clear();
    }
};

inline urma_jfc_t *MockCreateJfc(urma_context_t *, urma_jfc_cfg_t *cfg)
{
    static urma_jfc_t jfc = {};

    jfc = {};
    jfc.jfc_cfg = *cfg;
    jfc.urma_ctx = cfg->jfce->urma_ctx;
    return &jfc;
}

inline urma_jfc_t *MockCreateJfcNull(urma_context_t *, urma_jfc_cfg_t *)
{
    return nullptr;
}

inline urma_status_t MockModifyJfc(urma_jfc_t *, urma_jfc_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeleteJfc(urma_jfc_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeleteJfcBatch(urma_jfc_t **jfcArr, int, urma_jfc_t **badJfc)
{
    *badJfc = static_cast<urma_jfc_t *>(urma_test::GetHwMockState().badObject);
    if (*badJfc == nullptr && urma_test::GetHwMockState().status != URMA_SUCCESS) {
        *badJfc = jfcArr[0];
    }
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockAllocJfc(urma_context_t *ctx, urma_jfc_cfg_t *cfg, urma_jfc_t **jfc)
{
    static urma_jfc_t mockJfc = {};

    mockJfc.urma_ctx = ctx;
    mockJfc.jfc_cfg = *cfg;
    mockJfc.urma_jfc_opt.is_actived = false;
    *jfc = &mockJfc;
    return URMA_SUCCESS;
}

inline urma_status_t MockAllocJfcNull(urma_context_t *, urma_jfc_cfg_t *, urma_jfc_t **jfc)
{
    *jfc = nullptr;
    return URMA_SUCCESS;
}

inline urma_status_t MockJfcStatus(urma_jfc_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockJfcOpt(urma_jfc_t *, uint64_t, void *, uint32_t)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockModifyJfs(urma_jfs_t *, urma_jfs_attr_t *)
{
    return urma_test::GetHwMockState().jfsModifyStatus;
}

inline urma_status_t MockQueryJfs(urma_jfs_t *, urma_jfs_cfg_t *, urma_jfs_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeleteJfs(urma_jfs_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeleteJfsBatch(urma_jfs_t **jfsArr, int, urma_jfs_t **badJfs)
{
    *badJfs = jfsArr[1];
    return URMA_FAIL;
}

inline urma_status_t MockDeleteJfsBatchSuccess(urma_jfs_t **, int, urma_jfs_t **badJfs)
{
    *badJfs = nullptr;
    return URMA_SUCCESS;
}

inline urma_status_t MockModifyJfr(urma_jfr_t *, urma_jfr_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockQueryJfr(urma_jfr_t *, urma_jfr_cfg_t *, urma_jfr_attr_t *)
{
    return urma_test::GetHwMockState().jfrQueryStatus;
}

inline urma_status_t MockDeleteJfr(urma_jfr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeleteJfrBatchSuccess(urma_jfr_t **, int, urma_jfr_t **badJfr)
{
    *badJfr = nullptr;
    return URMA_SUCCESS;
}

inline urma_status_t MockDeleteJfrBatchStatus(urma_jfr_t **jfrArr, int, urma_jfr_t **badJfr)
{
    *badJfr = jfrArr[0];
    return urma_test::GetHwMockState().status;
}

inline int MockFlushJfs(urma_jfs_t *, int, urma_cr_t *)
{
    return urma_test::GetHwMockState().intReturn;
}

inline urma_status_t MockAllocJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg, urma_jfs_t **jfs)
{
    static urma_jfs_t mockJfs = {};

    mockJfs.urma_ctx = ctx;
    mockJfs.jfs_cfg = *cfg;
    mockJfs.urma_jfs_opt.is_actived = false;
    *jfs = &mockJfs;
    return URMA_SUCCESS;
}

inline urma_jfs_t *MockCreateJfs(urma_context_t *ctx, urma_jfs_cfg_t *cfg)
{
    static urma_jfs_t mockJfs = {};

    mockJfs = {};
    mockJfs.urma_ctx = ctx;
    mockJfs.jfs_cfg = *cfg;
    return &mockJfs;
}

inline urma_jfs_t *MockCreateJfsNull(urma_context_t *, urma_jfs_cfg_t *)
{
    return nullptr;
}

inline urma_status_t MockJfsStatus(urma_jfs_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockJfsOpt(urma_jfs_t *, uint64_t, void *, uint32_t)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockAllocJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg, urma_jfr_t **jfr)
{
    static urma_jfr_t mockJfr = {};

    mockJfr.urma_ctx = ctx;
    mockJfr.jfr_cfg = *cfg;
    mockJfr.urma_jfr_opt.is_actived = false;
    *jfr = &mockJfr;
    return URMA_SUCCESS;
}

inline urma_jfr_t *MockCreateJfr(urma_context_t *ctx, urma_jfr_cfg_t *cfg)
{
    static urma_jfr_t mockJfr = {};

    mockJfr = {};
    mockJfr.urma_ctx = ctx;
    mockJfr.jfr_cfg = *cfg;
    return &mockJfr;
}

inline urma_jfr_t *MockCreateJfrNull(urma_context_t *, urma_jfr_cfg_t *)
{
    return nullptr;
}

inline urma_status_t MockJfrStatus(urma_jfr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockJfrOpt(urma_jfr_t *, uint64_t, void *, uint32_t)
{
    return urma_test::GetHwMockState().status;
}

inline urma_token_id_t *MockAllocTokenId(urma_context_t *ctx)
{
    static urma_token_id_t token = {};

    token.urma_ctx = ctx;
    token.ref.atomic_cnt.store(0);
    token.token_id = 0xabc;
    return &token;
}

inline urma_token_id_t *MockAllocTokenIdEx(urma_context_t *ctx, urma_token_id_flag_t)
{
    return MockAllocTokenId(ctx);
}

inline urma_status_t MockFreeTokenId(urma_token_id_t *)
{
    return URMA_SUCCESS;
}

inline urma_target_seg_t *MockImportSeg(urma_context_t *ctx, urma_seg_t *, urma_token_t *, uint64_t,
                                        urma_import_seg_flag_t)
{
    static urma_target_seg_t tseg = {};

    tseg = {};
    tseg.urma_ctx = ctx;
    return &tseg;
}

inline urma_status_t MockUnimportSeg(urma_target_seg_t *)
{
    return URMA_SUCCESS;
}

inline urma_target_seg_t *MockRegisterSeg(urma_context_t *ctx, urma_seg_cfg_t *cfg)
{
    static urma_target_seg_t tseg = {};

    tseg = {};
    tseg.urma_ctx = ctx;
    tseg.token_id = cfg->token_id;
    return &tseg;
}

inline urma_status_t MockUnregisterSeg(urma_target_seg_t *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockGetAsyncEvent(urma_context_t *, urma_async_event_t *)
{
    return urma_test::GetHwMockState().status;
}

inline void MockAckAsyncEvent(urma_async_event_t *)
{
    urma_test::GetHwMockState().ackAsyncCount++;
}

inline int MockUserCtl(urma_context_t *, urma_user_ctl_in_t *in, urma_user_ctl_out_t *out)
{
    int ret = urma_test::GetHwMockState().userCtlReturn;
    if (ret != 0 || in == nullptr || out == nullptr) {
        return ret;
    }

    if (in->opcode == CORE_USER_CTL_GET_RJETTY) {
        auto **rjetty = reinterpret_cast<urma_rjetty_t **>(out->addr);
        *rjetty = static_cast<urma_rjetty_t *>(std::calloc(1, sizeof(urma_rjetty_t)));
    } else if (in->opcode == CORE_USER_CTL_GET_SEG_CTX) {
        auto **seg = reinterpret_cast<urma_seg_t **>(out->addr);
        *seg = static_cast<urma_seg_t *>(std::calloc(1, sizeof(urma_seg_t)));
    }
    return ret;
}

inline int MockModifyTp(urma_context_t *, uint32_t, urma_tp_cfg_t *, urma_tp_attr_t *, urma_tp_attr_mask_t)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockGetTpList(urma_context_t *, urma_get_tp_cfg_t *, uint32_t *tpCnt, urma_tp_info_t *)
{
    *tpCnt = 1;
    return URMA_SUCCESS;
}

inline urma_status_t MockSetTpAttr(const urma_context_t *, const uint64_t, const uint8_t,
                                   const uint32_t, const urma_tp_attr_value_t *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockGetTpAttr(const urma_context_t *, const uint64_t, uint8_t *tpAttrCnt,
                                   uint32_t *tpAttrBitmap, urma_tp_attr_value_t *)
{
    *tpAttrCnt = 1;
    *tpAttrBitmap = 0;
    return URMA_SUCCESS;
}

inline urma_status_t MockNetLookup()
{
    return URMA_SUCCESS;
}

inline urma_status_t MockGetEidByIp(const urma_context_t *, const urma_net_addr_t *, urma_eid_t *)
{
    return MockNetLookup();
}

inline urma_status_t MockGetIpByEid(const urma_context_t *, const urma_eid_t *, urma_net_addr_t *)
{
    return MockNetLookup();
}

inline urma_status_t MockGetSmac(const urma_context_t *, uint8_t *)
{
    return MockNetLookup();
}

inline urma_status_t MockGetDmac(const urma_context_t *, const urma_net_addr_t *, uint8_t *)
{
    return MockNetLookup();
}

inline urma_jfce_t *MockCreateJfce(urma_context_t *ctx)
{
    static urma_jfce_t jfce = {};

    jfce.urma_ctx = ctx;
    jfce.ref.atomic_cnt.store(0);
    return &jfce;
}

inline urma_status_t MockDeleteJfce(urma_jfce_t *)
{
    return URMA_SUCCESS;
}

inline urma_jetty_t *MockCreateJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg)
{
    static urma_jetty_t jetty = {};

    jetty.urma_ctx = ctx;
    jetty.jetty_cfg = *cfg;
    jetty.urma_jetty_opt.is_actived = false;
    return &jetty;
}

inline urma_jetty_t *MockCreateJettyNull(urma_context_t *, urma_jetty_cfg_t *)
{
    return nullptr;
}

inline urma_status_t MockJettyStatus(urma_jetty_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockModifyJetty(urma_jetty_t *, urma_jetty_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockQueryJetty(urma_jetty_t *, urma_jetty_cfg_t *, urma_jetty_attr_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockDeleteJettyBatch(urma_jetty_t **, int, urma_jetty_t **badJetty)
{
    *badJetty = nullptr;
    return URMA_SUCCESS;
}

inline urma_status_t MockDeleteJettyBatchStatus(urma_jetty_t **jettyArr, int, urma_jetty_t **badJetty)
{
    *badJetty = jettyArr[0];
    return urma_test::GetHwMockState().status;
}

inline int MockFlushJetty(urma_jetty_t *, int, urma_cr_t *)
{
    return urma_test::GetHwMockState().intReturn;
}

inline urma_status_t MockAllocJetty(urma_context_t *ctx, urma_jetty_cfg_t *cfg, urma_jetty_t **jetty)
{
    static urma_jetty_t mockJetty = {};

    mockJetty.urma_ctx = ctx;
    mockJetty.jetty_cfg = *cfg;
    mockJetty.urma_jetty_opt.is_actived = false;
    *jetty = &mockJetty;
    return URMA_SUCCESS;
}

inline urma_status_t MockJettyOpt(urma_jetty_t *, uint64_t, void *, uint32_t)
{
    return urma_test::GetHwMockState().status;
}

inline urma_target_jetty_t *MockImportJfr(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *)
{
    static urma_target_jetty_t tjfr = {};

    tjfr.urma_ctx = ctx;
    tjfr.trans_mode = rjfr->trans_mode;
    tjfr.tp_type = rjfr->tp_type;
    return &tjfr;
}

inline urma_target_jetty_t *MockImportJfrEx(urma_context_t *ctx, urma_rjfr_t *rjfr, urma_token_t *,
                                            urma_active_tp_cfg_t *)
{
    return MockImportJfr(ctx, rjfr, nullptr);
}

inline urma_target_jetty_t *MockImportJetty(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *)
{
    static urma_target_jetty_t tjetty = {};

    tjetty.urma_ctx = ctx;
    tjetty.trans_mode = rjetty->trans_mode;
    tjetty.flag = rjetty->flag;
    tjetty.tp_type = rjetty->tp_type;
    return &tjetty;
}

inline urma_target_jetty_t *MockImportJettyEx(urma_context_t *ctx, urma_rjetty_t *rjetty, urma_token_t *,
                                              urma_active_tp_cfg_t *)
{
    return MockImportJetty(ctx, rjetty, nullptr);
}

inline urma_status_t MockTargetJettyStatus(urma_target_jetty_t *)
{
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockAdviseJfr(urma_jfs_t *, urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockAdviseJfrAsync(urma_jfs_t *, urma_target_jetty_t *, urma_advise_async_cb_func, void *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockAdviseJetty(urma_jetty_t *, urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockBindJetty(urma_jetty_t *, urma_target_jetty_t *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockBindJettyEx(urma_jetty_t *, urma_target_jetty_t *, urma_active_tp_cfg_t *)
{
    return URMA_SUCCESS;
}

inline int MockGetTpn(urma_jetty_t *)
{
    return 7;
}

inline urma_jetty_grp_t *MockCreateJettyGrp(urma_context_t *ctx, urma_jetty_grp_cfg_t *cfg)
{
    static urma_jetty_grp_t jettyGrp = {};

    jettyGrp.urma_ctx = ctx;
    jettyGrp.cfg = *cfg;
    return &jettyGrp;
}

inline urma_status_t MockDeleteJettyGrp(urma_jetty_grp_t *)
{
    return URMA_SUCCESS;
}

inline urma_notifier_t *MockCreateNotifier(urma_context_t *ctx)
{
    static urma_notifier_t notifier = {};

    notifier.urma_ctx = ctx;
    return &notifier;
}

inline urma_status_t MockDeleteNotifier(urma_notifier_t *)
{
    return URMA_SUCCESS;
}

inline int MockWaitNotify(urma_notifier_t *, uint32_t cnt, urma_notify_t *notify, int)
{
    if (cnt > 0) {
        notify[0].status = URMA_SUCCESS;
    }
    return static_cast<int>(cnt);
}

inline void MockAckNotify(uint32_t, urma_notify_t *)
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

inline urma_target_jetty_t *MockImportJettyAsyncNull(urma_notifier_t *, const urma_rjetty_t *,
                                                     const urma_token_t *, uint64_t, int)
{
    return nullptr;
}

inline urma_status_t MockBindJettyAsync(urma_notifier_t *, urma_jetty_t *, urma_target_jetty_t *, uint64_t, int)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockPostJfsWr(urma_jfs_t *, urma_jfs_wr_t *, urma_jfs_wr_t **badWr)
{
    *badWr = static_cast<urma_jfs_wr_t *>(urma_test::GetHwMockState().badSendWr);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostJfrWr(urma_jfr_t *, urma_jfr_wr_t *, urma_jfr_wr_t **badWr)
{
    *badWr = static_cast<urma_jfr_wr_t *>(urma_test::GetHwMockState().badRecvWr);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostJettySendWr(urma_jetty_t *, urma_jfs_wr_t *, urma_jfs_wr_t **badWr)
{
    *badWr = static_cast<urma_jfs_wr_t *>(urma_test::GetHwMockState().badSendWr);
    return urma_test::GetHwMockState().status;
}

inline urma_status_t MockPostJettyRecvWr(urma_jetty_t *, urma_jfr_wr_t *, urma_jfr_wr_t **badWr)
{
    *badWr = static_cast<urma_jfr_wr_t *>(urma_test::GetHwMockState().badRecvWr);
    return urma_test::GetHwMockState().status;
}

inline int MockPollJfc(urma_jfc_t *, int, urma_cr_t *)
{
    return urma_test::GetHwMockState().intReturn;
}

inline urma_status_t MockRearmJfc(urma_jfc_t *, bool)
{
    return urma_test::GetHwMockState().status;
}

inline int MockWaitJfc(urma_jfce_t *, uint32_t, int, urma_jfc_t *[])
{
    return urma_test::GetHwMockState().intReturn;
}

inline void MockAckJfc(urma_jfc_t *[], uint32_t [], uint32_t)
{
}

static urma_status_t MockProviderGetUasid(uint32_t *uasid)
{
    *uasid = 0x5a5a;
    return URMA_SUCCESS;
}

inline urma_context_t *MockProviderCreateContext(urma_device_t *dev, uint32_t, int devFd)
{
    static urma_context_t ctx = {};

    ctx.dev = dev;
    ctx.dev_fd = devFd;
    return &ctx;
}

inline urma_context_t *MockProviderCreateContextNull(urma_device_t *, uint32_t, int)
{
    return nullptr;
}

inline urma_status_t MockProviderDeleteContext(urma_context_t *)
{
    return URMA_SUCCESS;
}

inline urma_status_t MockProviderDeleteContextBusy(urma_context_t *)
{
    return URMA_FAIL;
}

inline void CoreApiFixture::InstallMockOps()
{
    ops.modify_jfc = MockModifyJfc;
    ops.delete_jfc = MockDeleteJfc;
    ops.delete_jfc_batch = MockDeleteJfcBatch;
    ops.modify_jfs = MockModifyJfs;
    ops.query_jfs = MockQueryJfs;
    ops.delete_jfs = MockDeleteJfs;
    ops.delete_jfs_batch = MockDeleteJfsBatch;
    ops.modify_jfr = MockModifyJfr;
    ops.query_jfr = MockQueryJfr;
    ops.delete_jfr = MockDeleteJfr;
    ops.delete_jfr_batch = MockDeleteJfrBatchSuccess;
    ops.modify_jetty = MockModifyJetty;
    ops.query_jetty = MockQueryJetty;
    ops.delete_jetty = MockJettyStatus;
    ops.delete_jetty_batch = MockDeleteJettyBatch;
    ops.get_async_event = MockGetAsyncEvent;
    ops.ack_async_event = MockAckAsyncEvent;
    ops.user_ctl = MockUserCtl;
    ops.post_jfs_wr = MockPostJfsWr;
    ops.post_jfr_wr = MockPostJfrWr;
    ops.post_jetty_send_wr = MockPostJettySendWr;
    ops.post_jetty_recv_wr = MockPostJettyRecvWr;
    ops.poll_jfc = MockPollJfc;
    ops.rearm_jfc = MockRearmJfc;
    ops.wait_jfc = MockWaitJfc;
    ops.ack_jfc = MockAckJfc;
}

inline void ReadCoreAttrU32(const urma_cmd_attr_t &attr, uint32_t *value)
{
    if (attr.data == 0 || value == nullptr) {
        return;
    }
    *value = *reinterpret_cast<uint32_t *>(static_cast<uintptr_t>(attr.data));
}

inline void ReadCoreAttrU64(const urma_cmd_attr_t &attr, uint64_t *value)
{
    if (attr.data == 0 || value == nullptr) {
        return;
    }
    *value = *reinterpret_cast<uint64_t *>(static_cast<uintptr_t>(attr.data));
}

inline void WriteCoreAttrValue(const urma_cmd_attr_t &attr, uint64_t value)
{
    if (attr.data == 0) {
        return;
    }
    void *dst = reinterpret_cast<void *>(static_cast<uintptr_t>(attr.data));
    switch (attr.field_size) {
        case sizeof(uint8_t):
            *static_cast<uint8_t *>(dst) = static_cast<uint8_t>(value);
            break;
        case sizeof(uint32_t):
            *static_cast<uint32_t *>(dst) = static_cast<uint32_t>(value);
            break;
        case sizeof(uint64_t):
            *static_cast<uint64_t *>(dst) = value;
            break;
        default:
            break;
    }
}

inline void WriteCoreAttrPattern(const urma_cmd_attr_t &attr, uint8_t seed)
{
    if (attr.data == 0 || attr.field_size == 0) {
        return;
    }
    auto *dst = reinterpret_cast<uint8_t *>(static_cast<uintptr_t>(attr.data));
    for (uint16_t i = 0; i < attr.field_size; ++i) {
        dst[i] = static_cast<uint8_t>(seed + i);
    }
}

inline void FillCoreOptOutput(urma_cmd_attr_t *attrs, size_t attrNum, uint8_t inBufType, uint8_t inLenType,
    uint8_t outBufType, uint8_t outLenType)
{
    uint64_t inBuf = 0;
    uint32_t inLen = 0;

    for (size_t i = 0; i < attrNum; ++i) {
        if (attrs[i].type == inBufType) {
            ReadCoreAttrU64(attrs[i], &inBuf);
        } else if (attrs[i].type == inLenType) {
            ReadCoreAttrU32(attrs[i], &inLen);
        }
    }
    for (size_t i = 0; i < attrNum; ++i) {
        if (attrs[i].type == outBufType) {
            WriteCoreAttrValue(attrs[i], inBuf);
        } else if (attrs[i].type == outLenType) {
            WriteCoreAttrValue(attrs[i], inLen);
        }
    }
}

inline void FillCoreQueryJettyOutput(urma_cmd_attr_t *attrs, size_t attrNum)
{
    for (size_t i = 0; i < attrNum; ++i) {
        switch (attrs[i].type) {
            case QUERY_JETTY_OUT_ID:
                WriteCoreAttrValue(attrs[i], 0x778);
                break;
            case QUERY_JETTY_OUT_JETTY_FLAG:
                WriteCoreAttrValue(attrs[i], g_coreQueryJettyFlag);
                break;
            case QUERY_JETTY_OUT_JFS_DEPTH:
            case QUERY_JETTY_OUT_JFR_DEPTH:
            case QUERY_JETTY_OUT_MAX_SEND_SGE:
            case QUERY_JETTY_OUT_MAX_SEND_RSGE:
            case QUERY_JETTY_OUT_MAX_RECV_SGE:
            case QUERY_JETTY_OUT_MAX_INLINE_DATA:
            case QUERY_JETTY_OUT_PRIORITY:
            case QUERY_JETTY_OUT_RETRY_CNT:
            case QUERY_JETTY_OUT_RNR_RETRY:
            case QUERY_JETTY_OUT_ERR_TIMEOUT:
            case QUERY_JETTY_OUT_MIN_RNR_TIMER:
            case QUERY_JETTY_OUT_RX_THRESHOLD:
            case QUERY_JETTY_OUT_STATE:
                WriteCoreAttrValue(attrs[i], 1);
                break;
            case QUERY_JETTY_OUT_TRANS_MODE:
                WriteCoreAttrValue(attrs[i], URMA_TM_RC);
                break;
            case QUERY_JETTY_OUT_JFR_ID:
                WriteCoreAttrValue(attrs[i], 0x779);
                break;
            case QUERY_JETTY_OUT_TOKEN:
                WriteCoreAttrValue(attrs[i], 0x77a);
                break;
            default:
                break;
        }
    }
}

inline void FillCoreBatchDeleteOutput(urma_cmd_hdr_t *hdr, urma_cmd_attr_t *attrs, size_t attrNum)
{
    for (size_t i = 0; i < attrNum; ++i) {
        switch (hdr->command) {
            case URMA_CMD_DELETE_JFC_BATCH:
                if (attrs[i].type == DELETE_JFC_BATCH_OUT_BAD_JFC_INDEX) {
                    WriteCoreAttrValue(attrs[i], g_coreBatchBadIndex);
                } else if (attrs[i].type == DELETE_JFC_BATCH_OUT_COMP_EVENTS_REPORTED ||
                    attrs[i].type == DELETE_JFC_BATCH_OUT_ASYNC_EVENTS_REPORTED) {
                    WriteCoreAttrValue(attrs[i], 0);
                }
                break;
            case URMA_CMD_DELETE_JFS_BATCH:
                if (attrs[i].type == DELETE_JFS_BATCH_OUT_BAD_JFS_INDEX) {
                    WriteCoreAttrValue(attrs[i], g_coreBatchBadIndex);
                } else if (attrs[i].type == DELETE_JFS_BATCH_OUT_ASYNC_EVENTS_REPORTED) {
                    WriteCoreAttrValue(attrs[i], 0);
                }
                break;
            case URMA_CMD_DELETE_JFR_BATCH:
                if (attrs[i].type == DELETE_JFR_BATCH_OUT_BAD_JFR_INDEX) {
                    WriteCoreAttrValue(attrs[i], g_coreBatchBadIndex);
                } else if (attrs[i].type == DELETE_JFR_BATCH_OUT_ASYNC_EVENTS_REPORTED) {
                    WriteCoreAttrValue(attrs[i], 0);
                }
                break;
            case URMA_CMD_DELETE_JETTY_BATCH:
                if (attrs[i].type == DELETE_JETTY_BATCH_OUT_BAD_JETTY_INDEX) {
                    WriteCoreAttrValue(attrs[i], g_coreBatchBadIndex);
                } else if (attrs[i].type == DELETE_JETTY_BATCH_OUT_ASYNC_EVENTS_REPORTED) {
                    WriteCoreAttrValue(attrs[i], 0);
                }
                break;
            default:
                break;
        }
    }
}

inline void FillCoreWaitNotifyOutput(urma_cmd_attr_t *attrs, size_t attrNum)
{
    static urma_target_jetty_t targetJetty = {};

    for (size_t i = 0; i < attrNum; ++i) {
        if (attrs[i].type == WAIT_NOTIFY_OUT_CNT) {
            WriteCoreAttrValue(attrs[i], 1);
        } else if (attrs[i].type == WAIT_NOTIFY_OUT_NOTIFY && attrs[i].data != 0) {
            auto *notify = reinterpret_cast<urma_cmd_notify_t *>(static_cast<uintptr_t>(attrs[i].data));
            notify[0].type = URMA_IMPORT_JETTY_NOTIFY;
            notify[0].status = URMA_SUCCESS;
            notify[0].user_ctx = 0x77b;
            notify[0].urma_jetty = reinterpret_cast<uint64_t>(&targetJetty);
            notify[0].vtpn = 0x77c;
        }
    }
}

inline void FillCoreAsyncEventOutput(urma_cmd_attr_t *attrs, size_t attrNum)
{
    for (size_t i = 0; i < attrNum; ++i) {
        if (attrs[i].type == GET_ASYNC_EVENT_OUT_EVENT_TYPE) {
            WriteCoreAttrValue(attrs[i], g_coreAsyncEventType);
        } else if (attrs[i].type == GET_ASYNC_EVENT_OUT_EVENT_DATA) {
            WriteCoreAttrValue(attrs[i], g_coreAsyncEventData);
        }
    }
}

inline void FillCoreNetworkLookupOutput(urma_cmd_hdr_t *hdr, urma_cmd_attr_t *attrs, size_t attrNum)
{
    for (size_t i = 0; i < attrNum; ++i) {
        switch (hdr->command) {
            case URMA_CMD_GET_EID_BY_IP:
                if (attrs[i].type == GET_EID_BY_IP_INFO_OUT_EID) {
                    WriteCoreAttrPattern(attrs[i], 0x10);
                }
                break;
            case URMA_CMD_GET_IP_BY_EID:
                if (attrs[i].type == GET_IP_BY_EID_INFO_OUT_NET_ADDR) {
                    WriteCoreAttrPattern(attrs[i], 0x20);
                }
                break;
            case URMA_CMD_GET_SMAC:
                if (attrs[i].type == GET_SMAC_OUT_MAC) {
                    WriteCoreAttrPattern(attrs[i], 0x30);
                }
                break;
            case URMA_CMD_GET_DMAC:
                if (attrs[i].type == GET_DMAC_OUT_MAC) {
                    WriteCoreAttrPattern(attrs[i], 0x40);
                }
                break;
            default:
                break;
        }
    }
}

inline void FillCoreNetAddrListOutput(urma_cmd_attr_t *attrs, size_t attrNum)
{
    uint32_t maxNetaddrCnt = 0;
    urma_cmd_net_addr_info_t *addrInfo = nullptr;

    for (size_t i = 0; i < attrNum; ++i) {
        if (attrs[i].type == GET_NET_ADDR_LIST_IN_MAX_NETADDR_CNT) {
            ReadCoreAttrU32(attrs[i], &maxNetaddrCnt);
        } else if (attrs[i].type == GET_NET_ADDR_LIST_OUT_NETADDR_LIST && attrs[i].data != 0) {
            addrInfo = reinterpret_cast<urma_cmd_net_addr_info_t *>(static_cast<uintptr_t>(attrs[i].data));
        }
    }

    for (size_t i = 0; i < attrNum; ++i) {
        if (attrs[i].type == GET_NET_ADDR_LIST_OUT_NETADDR_CNT) {
            WriteCoreAttrValue(attrs[i], maxNetaddrCnt);
        }
    }
    if (addrInfo == nullptr || maxNetaddrCnt == 0) {
        return;
    }

    addrInfo[0].index = 7;
    addrInfo[0].netaddr.type = URMA_CMD_NET_ADDR_TYPE_IPV4;
    addrInfo[0].netaddr.net_addr.in4.addr = 0x01020304;
    addrInfo[0].netaddr.vlan = 100;
    addrInfo[0].netaddr.mac[0] = 0xaa;
    addrInfo[0].netaddr.prefix_len = 24;
    if (maxNetaddrCnt < 2) {
        return;
    }

    addrInfo[1].index = 8;
    addrInfo[1].netaddr.type = URMA_CMD_NET_ADDR_TYPE_IPV6;
    addrInfo[1].netaddr.net_addr.in6.subnet_prefix = 0x1122334455667788ULL;
    addrInfo[1].netaddr.net_addr.in6.interface_id = 0x8877665544332211ULL;
    addrInfo[1].netaddr.vlan = 200;
    addrInfo[1].netaddr.mac[0] = 0xbb;
    addrInfo[1].netaddr.prefix_len = 64;
}

inline void FillCoreIoctlOutput(urma_cmd_hdr_t *hdr)
{
    if (hdr == nullptr || hdr->args_addr == 0 || hdr->args_len == 0) {
        return;
    }

    auto *attrs = reinterpret_cast<urma_cmd_attr_t *>(static_cast<uintptr_t>(hdr->args_addr));
    size_t attrNum = hdr->args_len / sizeof(urma_cmd_attr_t);

    switch (hdr->command) {
        case URMA_CMD_GET_JFC_OPT:
            FillCoreOptOutput(attrs, attrNum, GET_JFC_OPT_IN_BUF, GET_JFC_OPT_IN_LEN,
                GET_JFC_OPT_OUT_BUF, GET_JFC_OPT_OUT_LEN);
            break;
        case URMA_CMD_GET_JFS_OPT:
            FillCoreOptOutput(attrs, attrNum, GET_JFS_OPT_IN_BUF, GET_JFS_OPT_IN_LEN,
                GET_JFS_OPT_OUT_BUF, GET_JFS_OPT_OUT_LEN);
            break;
        case URMA_CMD_GET_JFR_OPT:
            FillCoreOptOutput(attrs, attrNum, GET_JFR_OPT_IN_BUF, GET_JFR_OPT_IN_LEN,
                GET_JFR_OPT_OUT_BUF, GET_JFR_OPT_OUT_LEN);
            break;
        case URMA_CMD_GET_JETTY_OPT:
            FillCoreOptOutput(attrs, attrNum, GET_JETTY_OPT_IN_BUF, GET_JETTY_OPT_IN_LEN,
                GET_JETTY_OPT_OUT_BUF, GET_JETTY_OPT_OUT_LEN);
            break;
        case URMA_CMD_QUERY_JETTY:
            FillCoreQueryJettyOutput(attrs, attrNum);
            break;
        case URMA_CMD_DELETE_JFC_BATCH:
        case URMA_CMD_DELETE_JFS_BATCH:
        case URMA_CMD_DELETE_JFR_BATCH:
        case URMA_CMD_DELETE_JETTY_BATCH:
            FillCoreBatchDeleteOutput(hdr, attrs, attrNum);
            break;
        case URMA_EVENT_CMD_GET_ASYNC_EVENT:
            FillCoreAsyncEventOutput(attrs, attrNum);
            break;
        case URMA_EVENT_CMD_WAIT_NOTIFY:
            FillCoreWaitNotifyOutput(attrs, attrNum);
            break;
        case URMA_CMD_GET_EID_BY_IP:
        case URMA_CMD_GET_IP_BY_EID:
        case URMA_CMD_GET_SMAC:
        case URMA_CMD_GET_DMAC:
            FillCoreNetworkLookupOutput(hdr, attrs, attrNum);
            break;
        case URMA_CMD_GET_NETADDR_LIST:
            FillCoreNetAddrListOutput(attrs, attrNum);
            break;
        default:
            break;
    }
}

} // namespace

#pragma GCC diagnostic pop

#endif // TEST_URMA_CORE_CORE_FIXTURE_H
