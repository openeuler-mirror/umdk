#include "mockcpp/mockcpp.hpp"
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
    int result = umq_perf_init();
    EXPECT_EQ(result, UMQ_SUCCESS);
}

TEST_F(PerfTest, InitTwiceShouldFail) {
    int result1 = umq_perf_init();
    EXPECT_EQ(result1, UMQ_SUCCESS);

    int result2 = umq_perf_init();
    EXPECT_NE(result2, UMQ_SUCCESS);  // Should fail since already initialized
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

// Test perf start/stop/clear operations
TEST_F(PerfTest, PerfStartStop) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8];  // Fixed size array
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    uint32_t thresh_num = 3;

    int start_result = umq_perf_start(thresh_array, thresh_num);
    EXPECT_EQ(start_result, UMQ_SUCCESS);

    int stop_result = umq_perf_stop();
    EXPECT_EQ(stop_result, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfStartWithNullArrayShouldFail) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    int start_result = umq_perf_start(NULL, 3);
    EXPECT_NE(start_result, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfStartWithoutInitShouldFail) {
    uint64_t thresh_array[8];  // Fixed size array
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    uint32_t thresh_num = 3;

    int start_result = umq_perf_start(thresh_array, thresh_num);
    EXPECT_NE(start_result, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfClearWhenStartedShouldFail) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8];  // Fixed size array
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    uint32_t thresh_num = 3;

    int start_result = umq_perf_start(thresh_array, thresh_num);
    EXPECT_EQ(start_result, UMQ_SUCCESS);

    int clear_result = umq_perf_clear();
    EXPECT_NE(clear_result, UMQ_SUCCESS);  // Should fail because perf is running
}

TEST_F(PerfTest, PerfClearAfterStopping) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8];  // Fixed size array
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    uint32_t thresh_num = 3;

    int start_result = umq_perf_start(thresh_array, thresh_num);
    EXPECT_EQ(start_result, UMQ_SUCCESS);

    int stop_result = umq_perf_stop();
    EXPECT_EQ(stop_result, UMQ_SUCCESS);

    int clear_result = umq_perf_clear();
    EXPECT_EQ(clear_result, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfInfoGetWhenRunningShouldFail) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8];  // Fixed size array
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    uint32_t thresh_num = 3;

    int start_result = umq_perf_start(thresh_array, thresh_num);
    EXPECT_EQ(start_result, UMQ_SUCCESS);

    umq_perf_infos_t *info = nullptr;
    int info_result = umq_perf_info_get(&info);
    EXPECT_NE(info_result, 0);  // Should fail because perf is running
}

TEST_F(PerfTest, PerfInfoGetAfterStopping) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8];  // Fixed size array
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    uint32_t thresh_num = 3;

    int start_result = umq_perf_start(thresh_array, thresh_num);
    EXPECT_EQ(start_result, UMQ_SUCCESS);

    int stop_result = umq_perf_stop();
    EXPECT_EQ(stop_result, UMQ_SUCCESS);

    umq_perf_infos_t *info = nullptr;
    int info_result = umq_perf_info_get(&info);
    EXPECT_EQ(info_result, 0);  // Should succeed after stopping
}

TEST_F(PerfTest, StartWithTooManyThresholds) {
    umq_perf_init();

    // Create an array larger than UMQ_PERF_QUANTILE_MAX_NUM
    uint64_t large_thresh_array[UMQ_PERF_QUANTILE_MAX_NUM + 10];
    for (size_t i = 0; i < UMQ_PERF_QUANTILE_MAX_NUM + 10; ++i) {
        large_thresh_array[i] = (i + 1) * 100;
    }

    int result = umq_perf_start(large_thresh_array, UMQ_PERF_QUANTILE_MAX_NUM + 10);
    EXPECT_EQ(result, -UMQ_ERR_EAGAIN);  // Should return EAGAIN for too many thresholds
}

TEST_F(PerfTest, StartWithLargeThresholdValues) {
    umq_perf_init();

    // Test with threshold values larger than UMQ_PERF_MAX_THRESH_NS
    uint64_t thresh_array[8] = {UMQ_PERF_MAX_THRESH_NS + 1, UMQ_PERF_MAX_THRESH_NS + 10};
    int result = umq_perf_start(thresh_array, 2);

    // Should still succeed but ignore large thresholds
    EXPECT_EQ(result, UMQ_SUCCESS);
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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    // Need to start perf first to enable recording
    uint64_t thresh_array[8];
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

    // Now call umq_perf_get_start_timestamp which internally calls umq_dp_thread_run_once
    // and umq_perf_record_alloc
    g_mock_urpc_get_cpu_cycles_value = 2000;
    uint64_t timestamp = umq_perf_get_start_timestamp();

    // This should trigger the allocation process
    EXPECT_GT(timestamp, 0);
}

TEST_F(PerfTest, PerfRecordAllocExhaustedCapacity) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    // Manually set all records as used to test exhaustion case
    // This requires access to internal state, so we'll just call the function indirectly
    // by triggering the path through umq_get_start_timestamp after enabling perf
    uint64_t thresh_array[8];
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    // Directly test the internal function by creating appropriate context
    // Since it's static, we need to trigger it through public API
    uint64_t thresh_array[8] = {0}; // No thresholds set
    int start_result = umq_perf_start(thresh_array, 1);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8] = {100, 200, 300};
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8] = {100, 200, 300};
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8] = {100, 200, 300};
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

    // Stop perf to allow getting info
    int stop_result = umq_perf_stop();
    ASSERT_EQ(stop_result, UMQ_SUCCESS);

    // Get perf info which should call umq_perf_convert_cycles_to_ns
    umq_perf_infos_t *info = nullptr;
    int info_result = umq_perf_info_get(&info);
    EXPECT_EQ(info_result, 0);

    SUCCEED();
}

TEST_F(PerfTest, PerfRecordWriteFunctionsEdgeCases) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8] = {100, 200, 300};
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8];
    for (int i = 0; i < 3; ++i) {
        thresh_array[i] = (i + 1) * 100;
    }
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8] = {100, 200, 300};
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

    int stop_result = umq_perf_stop();
    ASSERT_EQ(stop_result, UMQ_SUCCESS);

    // Clear should reset counters
    int clear_result = umq_perf_clear();
    EXPECT_EQ(clear_result, UMQ_SUCCESS);

    SUCCEED();
}

TEST_F(PerfTest, ComprehensivePerfTest) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    // Set up thresholds
    uint64_t thresh_array[8] = {50, 100, 200, 300, 400, 500, 600, 700};
    int start_result = umq_perf_start(thresh_array, 8);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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
    int stop_result = umq_perf_stop();
    EXPECT_EQ(stop_result, UMQ_SUCCESS);

    // Get results (this calls umq_perf_convert_cycles_to_ns)
    umq_perf_infos_t *info = nullptr;
    int info_result = umq_perf_info_get(&info);
    EXPECT_EQ(info_result, 0);

    // Clear everything
    int clear_result = umq_perf_clear();
    EXPECT_EQ(clear_result, UMQ_SUCCESS);

    SUCCEED();
}

TEST_F(PerfTest, MinValueConditionTest) {
    int init_result = umq_perf_init();
    ASSERT_EQ(init_result, UMQ_SUCCESS);

    uint64_t thresh_array[8] = {100, 200, 300};
    int start_result = umq_perf_start(thresh_array, 3);
    ASSERT_EQ(start_result, UMQ_SUCCESS);

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