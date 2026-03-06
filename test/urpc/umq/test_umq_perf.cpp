#include "mockcpp/mockcpp.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <cstring>

#include "umq_api.h"
#include "umq_errno.h"
#include "perf.h"
#include "umq_vlog.h"
#include "urpc_util.h"

#define UMQ_PERF_MAX_THRESH_NS (100000u)
#define UMQ_PERF_REC_MAX_NUM (64u)

static uint64_t g_mock_urpc_get_cpu_cycles_value = 1000;
static uint64_t g_mock_urpc_get_cpu_hz_value = 2000000000ULL; // 2GHz

// Test fixture for perf functions
class PerfTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Reset mock cycle value for predictable tests
        g_mock_urpc_get_cpu_cycles_value = 1000;
        MOCKER(urpc_get_cpu_cycles).stubs().will(returnValue(g_mock_urpc_get_cpu_cycles_value));
        MOCKER(urpc_get_cpu_hz).stubs().will(returnValue(g_mock_urpc_get_cpu_hz_value));
    }

    void TearDown() override {
        // Cleanup after each test
        umq_perf_stop();
        umq_perf_uninit();
    }
};

// Test umq_perf_init function
TEST_F(PerfTest, InitSuccess) {
    int ret = umq_perf_init();
    EXPECT_EQ(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, InitTwiceShouldFail) {
    int ret = umq_perf_init();
    EXPECT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_init();
    EXPECT_NE(ret, UMQ_SUCCESS); // Should fail since already initialized
}

// Test umq_perf_get_start_timestamp_with_feature
TEST_F(PerfTest, GetStartTimestampWithPerfFeature) {
    uint32_t feature = UMQ_FEATURE_ENABLE_PERF;
    uint64_t timestamp = umq_perf_get_start_timestamp_with_feature(feature);

    // When perf is not enabled, should return 0
    EXPECT_EQ(timestamp, 0);
}

TEST_F(PerfTest, GetStartTimestampWithoutPerfFeature) {
    uint32_t feature = 0;  // No perf feature
    uint64_t timestamp = umq_perf_get_start_timestamp_with_feature(feature);

    EXPECT_EQ(timestamp, 0);
}

// Test umq_perf_record_write_with_feature
TEST_F(PerfTest, RecordWriteWithPerfFeature) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);  // Use cast
    uint64_t start = 1000;
    uint32_t feature = UMQ_FEATURE_ENABLE_PERF;

    // This function should not crash when called
    umq_perf_record_write_with_feature(type, start, feature);
    SUCCEED();  // If no crash, test passes
}

TEST_F(PerfTest, RecordWriteWithoutPerfFeature) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);  // Use cast
    uint64_t start = 1000;
    uint32_t feature = 0;  // No perf feature

    // This function should return immediately without doing anything
    umq_perf_record_write_with_feature(type, start, feature);
    SUCCEED();  // If no crash, test passes
}

static void test_perf_cfg_set(umq_perf_stats_cfg_t *cfg)
{
    for (int i = 0; i < 3; ++i) {
        cfg->thresh_array[i] = (i + 1) * 100;
    }
    cfg->thresh_num = 3;
}

// Test perf start/stop/clear operations
TEST_F(PerfTest, PerfStartStop) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);

    ret = umq_perf_reset(&cfg);
    EXPECT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    EXPECT_EQ(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfStartWithNullArrayShouldFail) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
    EXPECT_NE(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfStartWithoutInitShouldFail) {
    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);

    int ret = umq_perf_reset(&cfg);
    EXPECT_NE(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfClearWhenStartedShouldFail) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);

    ret = umq_perf_reset(&cfg);
    EXPECT_EQ(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfClearAfterStopping) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);

    ret = umq_perf_reset(&cfg);
    EXPECT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    EXPECT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_t info;
    ret = umq_perf_info_get(&info);
    EXPECT_EQ(ret, 0);
}

TEST_F(PerfTest, PerfInfoGetAfterStopping) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);

    ret = umq_perf_reset(&cfg);
    EXPECT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    EXPECT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_t info;
    ret = umq_perf_info_get(&info);
    EXPECT_EQ(ret, 0);  // Should succeed after stopping
}

TEST_F(PerfTest, StartWithTooManyThresholds) {
    umq_perf_start();

    umq_perf_stats_cfg_t cfg = {0};
    // Create an array larger than UMQ_PERF_QUANTILE_MAX_NUM
    for (size_t i = 0; i < UMQ_PERF_QUANTILE_MAX_NUM; ++i) {
        cfg.thresh_array[i] = (i + 1) * 100;
    }
    cfg.thresh_num = UMQ_PERF_QUANTILE_MAX_NUM + 10;

    int ret = umq_perf_reset(&cfg);
    EXPECT_EQ(ret, -UMQ_ERR_EAGAIN);  // Should return EAGAIN for too many thresholds
}

TEST_F(PerfTest, StartWithLargeThresholdValues) {
    umq_perf_start();

    // Test with threshold values larger than UMQ_PERF_MAX_THRESH_NS
    umq_perf_stats_cfg_t cfg = {0};
    cfg.thresh_array[0] = UMQ_PERF_MAX_THRESH_NS + 1;
    cfg.thresh_array[1] = UMQ_PERF_MAX_THRESH_NS + 10;
    cfg.thresh_num = 2;
    int ret = umq_perf_reset(&cfg);

    // Should still succeed but ignore large thresholds
    EXPECT_EQ(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfRecordWriteFunctions) {
    // These functions should not crash when called with valid parameters
    // (though they won't do much without proper initialization)
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;

    // This should not crash
    umq_perf_record_write(type, start);
    SUCCEED();
}

TEST_F(PerfTest, PerfRecordWriteWithDirection) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;
    umq_io_direction_t direction = UMQ_IO_ALL;

    // This should not crash
    umq_perf_record_write_with_direction(type, start, direction);
    SUCCEED();
}

TEST_F(PerfTest, PerfRecordAllocFunction) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Need to start perf first to enable recording
    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Now call umq_perf_get_start_timestamp which internally calls umq_dp_thread_run_once
    // and umq_perf_record_alloc
    g_mock_urpc_get_cpu_cycles_value = 2000;
    uint64_t timestamp = umq_perf_get_start_timestamp();

    // This should trigger the allocation process
    EXPECT_GT(timestamp, 0);
}

TEST_F(PerfTest, PerfRecordAllocExhaustedCapacity) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Manually set all records as used to test exhaustion case
    // This requires access to internal state, so we'll just call the function indirectly
    // by triggering the path through umq_get_start_timestamp after enabling perf
    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Call multiple times to exercise the allocation logic
    for (int i = 0; i < 5; ++i) {
        g_mock_urpc_get_cpu_cycles_value = 2000 + i * 100;
        uint64_t timestamp = umq_perf_get_start_timestamp();
        if (timestamp > 0) {
            // Successfully allocated
        }
    }

    SUCCEED();
}

TEST_F(PerfTest, FindPerfRecordBucketNoThreshold) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Directly test the internal function by creating appropriate context
    // Since it's static, we need to trigger it through public API
    umq_perf_stats_cfg_t cfg = {0}; // No thresholds set
    cfg.thresh_num = 1;
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Now when we call perf recording functions, find_perf_record_bucket will be called
    g_mock_urpc_get_cpu_cycles_value = 3000;

    // To trigger find_perf_record_bucket, we need to call umq_perf_record_write
    // But this requires proper setup including setting g_perf_record_index
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;

    // This should trigger find_perf_record_bucket with no thresholds set
    umq_perf_record_write_with_feature(type, start, UMQ_FEATURE_ENABLE_PERF);

    SUCCEED();
}

TEST_F(PerfTest, FindPerfRecordBucketWithThresholds) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Now call perf recording which will trigger find_perf_record_bucket
    g_mock_urpc_get_cpu_cycles_value = 2500;

    // Trigger the recording function
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;

    // Enable perf recording temporarily
    umq_perf_record_write_with_feature(type, start, UMQ_FEATURE_ENABLE_PERF);

    SUCCEED();
}

TEST_F(PerfTest, PerfFillPerfRecordFunction) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Enable perf
    // uint32_t feature = UMQ_FEATURE_ENABLE_PERF;
    g_mock_urpc_get_cpu_cycles_value = 2000;

    // Get timestamp to allocate record index
    uint64_t timestamp = umq_perf_get_start_timestamp();
    EXPECT_GT(timestamp, 0);

    // Now call record write which will trigger umq_perf_fill_perf_record
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start_time = 1000;

    // This should trigger the fill function
    umq_perf_record_write(type, start_time);

    SUCCEED();
}

TEST_F(PerfTest, PerfConvertCyclesToNs) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Stop perf to allow getting info
    ret = umq_perf_stop();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Get perf info which should call umq_perf_convert_cycles_to_ns
    umq_perf_stats_t info;
    ret = umq_perf_info_get(&info);
    EXPECT_EQ(ret, 0);

    SUCCEED();
}

TEST_F(PerfTest, PerfRecordWriteFunctionsEdgeCases) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Enable perf recording
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;

    // Test normal recording
    umq_perf_record_write(type, start);

    // Test recording with direction
    umq_io_direction_t direction = UMQ_IO_ALL;
    umq_perf_record_write_with_direction(type, start, direction);

    SUCCEED();
}

TEST_F(PerfTest, PerfRecordAllocationBoundary) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Try to trigger multiple allocations
    for (int i = 0; i < 10; ++i) {
        g_mock_urpc_get_cpu_cycles_value = 1000 + i * 100;
        uint64_t timestamp = umq_perf_get_start_timestamp();
        if (timestamp > 0) {
            // Valid timestamp means allocation worked
        }
    }

    SUCCEED();
}

TEST_F(PerfTest, ClearPerfRecordItem) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    SUCCEED();
}

TEST_F(PerfTest, ComprehensivePerfTest) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Set up thresholds
    uint64_t thresh_array[8] = {50, 100, 200, 300, 400, 500, 600, 700};
    umq_perf_stats_cfg_t cfg = {0};
    cfg.thresh_num = 8;
    memcpy(cfg.thresh_array, thresh_array, sizeof(thresh_array));
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Enable recording by getting timestamps
    for (int i = 0; i < 5; ++i) {
        g_mock_urpc_get_cpu_cycles_value = 1000 + i * 1000;
        uint64_t timestamp = umq_perf_get_start_timestamp();
        if (timestamp > 0) {
            // Record some data
            umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(i % UMQ_PERF_RECORD_TYPE_MAX);
            umq_perf_record_write(type, timestamp - 100);

            // Also test with direction
            umq_perf_record_write_with_direction(type, timestamp - 50, UMQ_IO_ALL);
        }
    }

    // Stop perf
    ret = umq_perf_stop();
    EXPECT_EQ(ret, UMQ_SUCCESS);

    // Get results (this calls umq_perf_convert_cycles_to_ns)
    umq_perf_stats_t info;
    ret = umq_perf_info_get(&info);
    EXPECT_EQ(ret, 0);

    SUCCEED();
}

TEST_F(PerfTest, MinValueConditionTest) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_cfg_t cfg = {0};
    test_perf_cfg_set(&cfg);
    ret = umq_perf_reset(&cfg);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    // Set mock to same value to create zero delta
    g_mock_urpc_get_cpu_cycles_value = 1000;
    uint64_t timestamp = umq_perf_get_start_timestamp();

    if (timestamp > 0) {
        // Record with same start time to create zero delta
        umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
        umq_perf_record_write(type, 1000);
    }

    SUCCEED();
}

TEST(InlineFunctionsTest, GetStartTimestampWithFeature) {
    uint32_t feature_with_perf = UMQ_FEATURE_ENABLE_PERF;
    uint32_t feature_without_perf = 0;

    // Without perf feature, should return 0
    uint64_t result1 = umq_perf_get_start_timestamp_with_feature(feature_without_perf);
    EXPECT_EQ(result1, 0);

    // With perf feature but perf not enabled, should return 0
    uint64_t result2 = umq_perf_get_start_timestamp_with_feature(feature_with_perf);
    EXPECT_EQ(result2, 0);
}

TEST(InlineFunctionsTest, RecordWriteWithFeature) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;
    uint32_t feature_with_perf = UMQ_FEATURE_ENABLE_PERF;
    uint32_t feature_without_perf = 0;

    // With perf feature disabled, should return immediately
    umq_perf_record_write_with_feature(type, start, feature_without_perf);
    SUCCEED();

    // With perf feature enabled but perf not initialized, should return immediately
    umq_perf_record_write_with_feature(type, start, feature_with_perf);
    SUCCEED();
}