#include "mockcpp/mockcpp.hpp"
#include <gtest/gtest.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <vector>

#include "umq_api.h"
#include "umq_errno.h"
#include "perf.h"
#include "umq_vlog.h"
#include "urpc_util.h"

static uint64_t g_mock_urpc_get_cpu_hz_value = 2000000000ULL; // 2GHz

// Test fixture for perf functions
class PerfTest : public ::testing::Test {
protected:
    void SetUp() override {
        // urpc_get_cpu_cycles is a static inline and is NOT mocked: tests rely on
        // the real rdtsc (thread-safe) and inject controlled deltas via start = ts - D.
        // urpc_get_cpu_hz is a real symbol, mocked so ns conversion is deterministic.
        MOCKER(urpc_get_cpu_hz).stubs().will(returnValue(g_mock_urpc_get_cpu_hz_value));
    }

    void TearDown() override {
        // Cleanup after each test
        umq_perf_stop();
        umq_perf_uninit();
        GlobalMockObject::verify();
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
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;
    uint32_t feature = UMQ_FEATURE_ENABLE_PERF;

    umq_perf_record_write_with_feature(type, start, feature);
    SUCCEED();
}

TEST_F(PerfTest, RecordWriteWithoutPerfFeature) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;
    uint32_t feature = 0;  // No perf feature

    umq_perf_record_write_with_feature(type, start, feature);
    SUCCEED();
}

// Test perf start/stop/clear operations
TEST_F(PerfTest, PerfStartStop) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
    EXPECT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    EXPECT_EQ(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfResetWithoutInitShouldFail) {
    int ret = umq_perf_reset(NULL);
    EXPECT_NE(ret, UMQ_SUCCESS);
}

TEST_F(PerfTest, PerfClearAfterStopping) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
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

    ret = umq_perf_reset(NULL);
    EXPECT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_t info;
    ret = umq_perf_info_get(&info);
    EXPECT_EQ(ret, 0);  // Should succeed after stopping
}

TEST_F(PerfTest, PerfRecordWriteFunctions) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;

    umq_perf_record_write(type, start);
    SUCCEED();
}

TEST_F(PerfTest, PerfRecordWriteWithDirection) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;
    umq_io_direction_t direction = UMQ_IO_ALL;

    umq_perf_record_write_with_direction(type, start, direction);
    SUCCEED();
}

TEST_F(PerfTest, PerfRecordAllocFunction) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    uint64_t timestamp = umq_perf_get_start_timestamp();
    EXPECT_GT(timestamp, 0);
}

TEST_F(PerfTest, PerfRecordAllocationBoundary) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    for (int i = 0; i < 10; ++i) {
        uint64_t timestamp = umq_perf_get_start_timestamp();
        if (timestamp > 0) {
            // Successfully allocated
        }
    }
    SUCCEED();
}

TEST_F(PerfTest, PerfFillPerfRecordFunction) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    uint64_t timestamp = umq_perf_get_start_timestamp();
    EXPECT_GT(timestamp, 0);

    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    umq_perf_record_write(type, timestamp - 100);
    SUCCEED();
}

TEST_F(PerfTest, PerfConvertCyclesToNs) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_reset(NULL);
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ret = umq_perf_stop();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    umq_perf_stats_t info;
    ret = umq_perf_info_get(&info);
    EXPECT_EQ(ret, 0);
}

// record a spread of deltas and verify 4 quantiles are ordered and non-zero
TEST_F(PerfTest, QuantileOutputOrdered) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ASSERT_EQ(umq_perf_reset(NULL), UMQ_SUCCESS);

    // real rdtsc is used; inject increasing deltas via start = ts - delta
    uint64_t ts = umq_perf_get_start_timestamp();
    ASSERT_GT(ts, 0);

    umq_perf_record_type_t type = UMQ_PERF_RECORD_ENQUEUE;
    const int N = 500;
    for (int i = 0; i < N; i++) {
        umq_perf_record_write(type, ts - (uint64_t)(i + 1));
    }
    ASSERT_EQ(umq_perf_stop(), UMQ_SUCCESS);

    umq_perf_stats_t info;
    ASSERT_EQ(umq_perf_info_get(&info), 0);
    EXPECT_EQ(info.type_record[type].sample_num, (uint64_t)N);

    uint64_t p50 = info.type_record[type].quantile_val[0];
    uint64_t p90 = info.type_record[type].quantile_val[1];
    uint64_t p99 = info.type_record[type].quantile_val[2];
    uint64_t p9999 = info.type_record[type].quantile_val[3];
    EXPECT_GT(p50, 0u);
    EXPECT_LE(p50, p90);
    EXPECT_LE(p90, p99);
    EXPECT_LE(p99, p9999);
    EXPECT_LE(p9999, info.type_record[type].maxinum);
}

// min/max/average are reported alongside quantiles
TEST_F(PerfTest, MinMaxAverageReported) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ASSERT_EQ(umq_perf_reset(NULL), UMQ_SUCCESS);

    uint64_t ts = umq_perf_get_start_timestamp();
    ASSERT_GT(ts, 0);

    umq_perf_record_type_t type = UMQ_PERF_RECORD_POST_TX;
    umq_perf_record_write(type, ts - 100);   // small delta
    umq_perf_record_write(type, ts - 800);   // larger delta (both < 1000)
    ASSERT_EQ(umq_perf_stop(), UMQ_SUCCESS);

    umq_perf_stats_t info;
    ASSERT_EQ(umq_perf_info_get(&info), 0);
    EXPECT_EQ(info.type_record[type].sample_num, 2u);
    EXPECT_GT(info.type_record[type].mininum, 0u);
    EXPECT_GT(info.type_record[type].maxinum, info.type_record[type].mininum);
    EXPECT_GT(info.type_record[type].average, 0u);
}

// thread safety: multiple threads record into per-thread records, aggregated before thread exit
TEST_F(PerfTest, MultiThreadRecordAggregate) {
    int ret = umq_perf_start();
    ASSERT_EQ(ret, UMQ_SUCCESS);

    ASSERT_EQ(umq_perf_reset(NULL), UMQ_SUCCESS);

    const int T = 4;
    const int N = 500;
    std::atomic<int> done(0);
    std::mutex mtx;
    std::condition_variable cv;
    bool release = false;

    std::vector<std::thread> threads;
    for (int t = 0; t < T; t++) {
        threads.emplace_back([&]() {
            uint64_t ts = umq_perf_get_start_timestamp();
            if (ts != 0) {
                for (int i = 0; i < N; i++) {
                    umq_perf_record_write(UMQ_PERF_RECORD_ENQUEUE, ts - (uint64_t)(i + 1));
                }
            }
            done.fetch_add(1);
            cv.notify_one();
            // keep this thread alive so its per-thread record is not freed before aggregation
            std::unique_lock<std::mutex> lk(mtx);
            cv.wait(lk, [&] { return release; });
        });
    }

    {
        std::unique_lock<std::mutex> lk(mtx);
        cv.wait(lk, [&] { return done.load() == T; });
    }
    ASSERT_EQ(umq_perf_stop(), UMQ_SUCCESS);

    umq_perf_stats_t info;
    ASSERT_EQ(umq_perf_info_get(&info), 0);
    EXPECT_EQ(info.type_record[UMQ_PERF_RECORD_ENQUEUE].sample_num, (uint64_t)T * N);

    {
        std::unique_lock<std::mutex> lk(mtx);
        release = true;
    }
    cv.notify_all();
    for (auto &th : threads) {
        th.join();
    }
}

TEST(InlineFunctionsTest, GetStartTimestampWithFeature) {
    uint32_t feature_with_perf = UMQ_FEATURE_ENABLE_PERF;
    uint32_t feature_without_perf = 0;

    uint64_t result1 = umq_perf_get_start_timestamp_with_feature(feature_without_perf);
    EXPECT_EQ(result1, 0);

    uint64_t result2 = umq_perf_get_start_timestamp_with_feature(feature_with_perf);
    EXPECT_EQ(result2, 0);
}

TEST(InlineFunctionsTest, RecordWriteWithFeature) {
    umq_perf_record_type_t type = static_cast<umq_perf_record_type_t>(1);
    uint64_t start = 1000;
    uint32_t feature_with_perf = UMQ_FEATURE_ENABLE_PERF;
    uint32_t feature_without_perf = 0;

    umq_perf_record_write_with_feature(type, start, feature_without_perf);
    SUCCEED();

    umq_perf_record_write_with_feature(type, start, feature_with_perf);
    SUCCEED();
}
