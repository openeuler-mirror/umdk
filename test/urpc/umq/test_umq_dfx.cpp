#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <cstring>

#include "umq_api.h"
#include "umq_errno.h"
#include "perf.h"
#include "dfx.h"
#include "umq_vlog.h"
#include "urpc_util.h"

// Test DFX functionality
class DfxTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
        umq_perf_uninit();
    }
};

TEST_F(DfxTest, DfxInitSuccessWithPerf) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;

    int result = umq_dfx_init(&cfg);
    EXPECT_EQ(result, UMQ_SUCCESS);
}

TEST_F(DfxTest, DfxInitWithoutPerfFeature) {
    umq_init_cfg_t cfg = {};
    cfg.feature = 0;

    int result = umq_dfx_init(&cfg);
    EXPECT_EQ(result, UMQ_SUCCESS);
}

TEST_F(DfxTest, DfxUninit) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;

    int init_result = umq_dfx_init(&cfg);
    EXPECT_EQ(init_result, UMQ_SUCCESS);

    // This should not crash
    umq_dfx_uninit();
    SUCCEED();
}

TEST_F(DfxTest, DfxCmdProcessNullParams) {
    // Test with null cmd
    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(nullptr, &result);

    // Test with null result
    umq_dfx_cmd_t cmd = {};
    umq_dfx_cmd_process(&cmd, nullptr);

    // Test with both null
    umq_dfx_cmd_process(nullptr, nullptr);

    SUCCEED();  // If no crash, test passes
}

TEST_F(DfxTest, DfxCmdProcessPerfModuleStart) {
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    // Initialize the fixed-size array
    memset(cmd.perf_in_param.thresh_array, 0, sizeof(cmd.perf_in_param.thresh_array));
    cmd.perf_in_param.thresh_num = 0;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // After calling start with empty array, it should fail
    EXPECT_NE(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_START);
}

TEST_F(DfxTest, DfxCmdProcessPerfModuleStop) {
    // First start perf
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    uint64_t thresh_array[8];
    for (int i = 0; i < 2; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    umq_perf_start(thresh_array, 2);

    // Then test stop command
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_STOP;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_STOP);
}

TEST_F(DfxTest, DfxCmdProcessPerfModuleClear) {
    // First start then stop perf to allow clearing
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    uint64_t thresh_array[8];
    for (int i = 0; i < 2; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    umq_perf_start(thresh_array, 2);
    umq_perf_stop();

    // Now test clear command
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_CLEAR;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_CLEAR);
}

TEST_F(DfxTest, DfxCmdProcessPerfModuleGetResult) {
    // First start then stop perf to get results
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    uint64_t thresh_array[8];
    for (int i = 0; i < 2; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    umq_perf_start(thresh_array, 2);
    umq_perf_stop();

    // Now test get result command
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_GET_RESULT;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, 0);  // umq_perf_info_get returns 0 on success
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_GET_RESULT);
}

TEST_F(DfxTest, DfxCmdProcessPerfModuleInvalidCmd) {
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_MAX;  // Invalid command

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_FAIL);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_MAX);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
}

TEST_F(DfxTest, DfxCmdProcessUnknownModule) {
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = static_cast<umq_dfx_module_id_t>(999);  // Unknown module

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_FAIL);
}

TEST_F(DfxTest, DfxCmdProcessStatsModule) {
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_STATS;  // Stats module (should go to default case)

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_FAIL);
}

TEST_F(DfxTest, MultipleInitAndUninitCycle) {
    // Test multiple init/uninit cycles
    for (int i = 0; i < 3; ++i) {
        umq_init_cfg_t cfg = {};
        cfg.feature = UMQ_FEATURE_ENABLE_PERF;

        int init_result = umq_dfx_init(&cfg);
        EXPECT_EQ(init_result, UMQ_SUCCESS);

        umq_dfx_uninit();
    }

    SUCCEED();
}

// Integration test: full workflow
TEST_F(DfxTest, FullWorkflow) {
    // Initialize
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;

    int init_result = umq_dfx_init(&cfg);
    EXPECT_EQ(init_result, UMQ_SUCCESS);

    // Configure perf with thresholds
    uint64_t thresh_array[8];
    for (int i = 0; i < 4; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }

    umq_dfx_cmd_t start_cmd = {};
    start_cmd.module_id = UMQ_DFX_MODULE_PERF;
    start_cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    // Copy array instead of direct assignment
    for (int i = 0; i < 4; ++i) {
        start_cmd.perf_in_param.thresh_array[i] = thresh_array[i];
    }
    start_cmd.perf_in_param.thresh_num = 4;

    umq_dfx_result_t start_result = {};
    umq_dfx_cmd_process(&start_cmd, &start_result);
    EXPECT_EQ(start_result.err_code, UMQ_SUCCESS);

    // Stop perf
    umq_dfx_cmd_t stop_cmd = {};
    stop_cmd.module_id = UMQ_DFX_MODULE_PERF;
    stop_cmd.perf_cmd_id = UMQ_PERF_CMD_STOP;

    umq_dfx_result_t stop_result = {};
    umq_dfx_cmd_process(&stop_cmd, &stop_result);
    EXPECT_EQ(stop_result.err_code, UMQ_SUCCESS);

    // Get results
    umq_dfx_cmd_t get_cmd = {};
    get_cmd.module_id = UMQ_DFX_MODULE_PERF;
    get_cmd.perf_cmd_id = UMQ_PERF_CMD_GET_RESULT;

    umq_dfx_result_t get_result = {};
    umq_dfx_cmd_process(&get_cmd, &get_result);
    EXPECT_EQ(get_result.err_code, 0);

    // Clear perf data
    umq_dfx_cmd_t clear_cmd = {};
    clear_cmd.module_id = UMQ_DFX_MODULE_PERF;
    clear_cmd.perf_cmd_id = UMQ_PERF_CMD_CLEAR;

    umq_dfx_result_t clear_result = {};
    umq_dfx_cmd_process(&clear_cmd, &clear_result);
    EXPECT_EQ(clear_result.err_code, UMQ_SUCCESS);

    // Uninitialize
    umq_dfx_uninit();
}

// Additional tests for umq_dfx_init to improve coverage
TEST_F(DfxTest, DfxInitWithMultipleFeatures) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF | 0x10; // Perf + another feature

    int result = umq_dfx_init(&cfg);
    EXPECT_EQ(result, UMQ_SUCCESS);
}

TEST_F(DfxTest, DfxInitWithZeroFeature) {
    umq_init_cfg_t cfg = {};
    cfg.feature = 0; // No features enabled

    int result = umq_dfx_init(&cfg);
    EXPECT_EQ(result, UMQ_SUCCESS);
}

TEST_F(DfxTest, DfxInitPerfInitFailure) {
    // This test might not work well due to static linking
    // We'll focus on code paths that can be tested more easily
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;

    // Initialize once to set up the global context
    int init_result = umq_perf_init();
    EXPECT_EQ(init_result, UMQ_SUCCESS);

    int result = umq_dfx_init(&cfg);
    EXPECT_NE(result, UMQ_SUCCESS);
}

// More detailed tests for umq_dfx_cmd_process
TEST_F(DfxTest, DfxCmdProcessPerfStartWithValidThresholds) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    // Prepare thresholds
    uint64_t thresh_array[8];
    for (int i = 0; i < 4; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }

    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    for (int i = 0; i < 4; ++i) {
        cmd.perf_in_param.thresh_array[i] = thresh_array[i];
    }
    cmd.perf_in_param.thresh_num = 4;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // Should succeed with valid thresholds
    EXPECT_EQ(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_START);
}

TEST_F(DfxTest, DfxCmdProcessPerfStopWhenNotRunning) {
    // Try to stop when perf hasn't been started
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_STOP;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // Should fail when trying to stop non-running perf
    EXPECT_NE(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_STOP);
}

TEST_F(DfxTest, DfxCmdProcessPerfClearWhenNotRunning) {
    // Initialize but don't start perf
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_CLEAR;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // Should succeed when clearing without running perf
    EXPECT_EQ(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_CLEAR);
}

TEST_F(DfxTest, DfxCmdProcessPerfGetResultWhenPerfRunning) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    // Start perf
    uint64_t thresh_array[8];
    for (int i = 0; i < 2; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    umq_perf_start(thresh_array, 2);

    // Try to get results while perf is running
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_GET_RESULT;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // Should fail when getting results while perf is running
    EXPECT_NE(result.err_code, 0);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_GET_RESULT);
}

// Test different perf command IDs in detail
TEST_F(DfxTest, DfxCmdProcessPerfCmdMax) {
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_MAX;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_FAIL);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_MAX);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
}

TEST_F(DfxTest, DfxCmdProcessPerfCmdDefaultCase) {
    // Use a value that falls into default case
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = static_cast<umq_perf_cmd_id_t>(999);

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    EXPECT_EQ(result.err_code, UMQ_FAIL);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_MAX);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
}

TEST_F(DfxTest, DfxUninitAfterInit) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    int init_result = umq_dfx_init(&cfg);
    EXPECT_EQ(init_result, UMQ_SUCCESS);

    // This should properly clean up
    umq_dfx_uninit();
    SUCCEED();
}

// Test boundary conditions for threshold arrays
TEST_F(DfxTest, DfxCmdProcessPerfStartWithEmptyThresholds) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    // Leave thresh_array empty and thresh_num as 0

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // Should succeed even with no thresholds
    EXPECT_EQ(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_START);
}

TEST_F(DfxTest, DfxCmdProcessPerfStartWithMaxThresholds) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    umq_dfx_init(&cfg);

    uint64_t thresh_array[8];
    for (int i = 0; i < 8; ++i) {
        thresh_array[i] = (i + 1) * 50;
    }

    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    for (int i = 0; i < 8; ++i) {
        cmd.perf_in_param.thresh_array[i] = thresh_array[i];
    }
    cmd.perf_in_param.thresh_num = 8;

    umq_dfx_result_t result = {};
    umq_dfx_cmd_process(&cmd, &result);

    // Should handle max thresholds
    EXPECT_EQ(result.err_code, UMQ_SUCCESS);
    EXPECT_EQ(result.module_id, UMQ_DFX_MODULE_PERF);
    EXPECT_EQ(result.perf_cmd_id, UMQ_PERF_CMD_START);
}

// Test umq_dfx_cmd_process with various combinations
TEST_F(DfxTest, DfxCmdProcessAllPerfCommandsSequence) {
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    int init_result = umq_dfx_init(&cfg);
    EXPECT_EQ(init_result, UMQ_SUCCESS);

    // Test START
    uint64_t thresh_array[8];
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }

    umq_dfx_cmd_t start_cmd = {};
    start_cmd.module_id = UMQ_DFX_MODULE_PERF;
    start_cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    for (int i = 0; i < 3; ++i) {
        start_cmd.perf_in_param.thresh_array[i] = thresh_array[i];
    }
    start_cmd.perf_in_param.thresh_num = 3;

    umq_dfx_result_t start_result = {};
    umq_dfx_cmd_process(&start_cmd, &start_result);
    EXPECT_EQ(start_result.err_code, UMQ_SUCCESS);

    // Test STOP
    umq_dfx_cmd_t stop_cmd = {};
    stop_cmd.module_id = UMQ_DFX_MODULE_PERF;
    stop_cmd.perf_cmd_id = UMQ_PERF_CMD_STOP;

    umq_dfx_result_t stop_result = {};
    umq_dfx_cmd_process(&stop_cmd, &stop_result);
    EXPECT_EQ(stop_result.err_code, UMQ_SUCCESS);

    // Test CLEAR
    umq_dfx_cmd_t clear_cmd = {};
    clear_cmd.module_id = UMQ_DFX_MODULE_PERF;
    clear_cmd.perf_cmd_id = UMQ_PERF_CMD_CLEAR;

    umq_dfx_result_t clear_result = {};
    umq_dfx_cmd_process(&clear_cmd, &clear_result);
    EXPECT_EQ(clear_result.err_code, UMQ_SUCCESS);

    // Test GET RESULT
    umq_dfx_cmd_t get_result_cmd = {};
    get_result_cmd.module_id = UMQ_DFX_MODULE_PERF;
    get_result_cmd.perf_cmd_id = UMQ_PERF_CMD_GET_RESULT;

    umq_dfx_result_t get_result = {};
    umq_dfx_cmd_process(&get_result_cmd, &get_result);
    EXPECT_EQ(get_result.err_code, 0);
}

// Test different module IDs
TEST_F(DfxTest, DfxCmdProcessAllModuleTypes) {
    // Test PERF module
    umq_dfx_cmd_t perf_cmd = {};
    perf_cmd.module_id = UMQ_DFX_MODULE_PERF;
    perf_cmd.perf_cmd_id = UMQ_PERF_CMD_START;

    umq_dfx_result_t perf_result = {};
    umq_dfx_cmd_process(&perf_cmd, &perf_result);

    // Test STATS module (should fail)
    umq_dfx_cmd_t stats_cmd = {};
    stats_cmd.module_id = UMQ_DFX_MODULE_STATS;
    // perf_cmd_id doesn't matter for STATS module

    umq_dfx_result_t stats_result = {};
    umq_dfx_cmd_process(&stats_cmd, &stats_result);
    EXPECT_EQ(stats_result.err_code, UMQ_FAIL);
    
    // Test unknown module
    umq_dfx_cmd_t unknown_cmd = {};
    unknown_cmd.module_id = static_cast<umq_dfx_module_id_t>(999);
    // perf_cmd_id doesn't matter for unknown module

    umq_dfx_result_t unknown_result = {};
    umq_dfx_cmd_process(&unknown_cmd, &unknown_result);
    EXPECT_EQ(unknown_result.err_code, UMQ_FAIL);
}

// Memory allocation and error path tests
TEST_F(DfxTest, DfxInitAfterPerfContextExists) {
    // Initialize perf manually first
    int perf_init_result = umq_perf_init();
    EXPECT_EQ(perf_init_result, UMQ_SUCCESS);

    // Now try DFX init - this should work fine since it checks for perf feature
    umq_init_cfg_t cfg = {};
    cfg.feature = UMQ_FEATURE_ENABLE_PERF;
    int dfx_init_result = umq_dfx_init(&cfg);
    // The behavior depends on whether umq_dfx_init calls umq_perf_init again
    EXPECT_NE(dfx_init_result, UMQ_SUCCESS);
}

// Null pointer tests with more details
TEST_F(DfxTest, DfxCmdProcessVariousNullCombinations) {
    umq_dfx_cmd_t cmd = {};
    cmd.module_id = UMQ_DFX_MODULE_PERF;
    cmd.perf_cmd_id = UMQ_PERF_CMD_START;
    umq_dfx_result_t result = {};

    // Test with valid cmd but null result
    umq_dfx_cmd_process(&cmd, nullptr);

    // Test with null cmd but valid result
    umq_dfx_cmd_process(nullptr, &result);

    // Test with both null
    umq_dfx_cmd_process(nullptr, nullptr);

    SUCCEED();
}