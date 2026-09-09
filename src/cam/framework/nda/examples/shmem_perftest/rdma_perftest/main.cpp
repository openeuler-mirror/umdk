/**
 * Copyright (c) 2026 Huawei Technologies Co., Ltd.
 * This program is free software, you can redistribute it and/or modify it under the terms and conditions of
 * CANN Open Software License Agreement Version 2.0 (the "License").
 * Please refer to the License for details. You may not use this file except in compliance with the License.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
 * See LICENSE in the root of the software repository for the full text of the License.
 */

#include <algorithm>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <getopt.h>
#include "utils.h"
#include "perftest_common_types.h"
#include "mte_perftest_common.h"

constexpr int UB_ALIGN_SIZE = 64;

#define CHECK_ACL_GOTO(call, ret_var, label)                        \
    do {                                                            \
        auto _ret = (call);                                         \
        if (_ret != 0) {                                            \
            std::cerr << #call << " failed: " << _ret << std::endl; \
            ret_var = _ret;                                         \
            goto label;                                             \
        }                                                           \
    } while (0)

#define CHECK_SHMEM_GOTO(call, ret_var, label)                      \
    do {                                                            \
        auto _ret = (call);                                         \
        if (_ret != 0) {                                            \
            std::cerr << #call << " failed: " << _ret << std::endl; \
            ret_var = _ret;                                         \
            goto label;                                             \
        }                                                           \
    } while (0)

#define CHECK_ACL_CLEANUP(call, ret_var)                            \
    do {                                                            \
        auto _ret = (call);                                         \
        if (_ret != 0) {                                            \
            std::cerr << #call << " failed: " << _ret << std::endl; \
            if (ret_var == 0) {                                     \
                ret_var = _ret;                                     \
            }                                                       \
        }                                                           \
    } while (0)

#define CHECK_SHMEM_CLEANUP(call, ret_var)                          \
    do {                                                            \
        auto _ret = (call);                                         \
        if (_ret != 0) {                                            \
            std::cerr << #call << " failed: " << _ret << std::endl; \
            if (ret_var == 0) {                                     \
                ret_var = _ret;                                     \
            }                                                       \
        }                                                           \
    } while (0)

int g_npus = 8;
const char* ipport;
static const char* fuc_data_type;
static const char* fuc_test_type;
int f_npu = 0;
aclshmemx_uniqueid_t default_flag_uid;

extern "C" void launch_rdma_perf_kernel(
    uint32_t block_dim, void* stream, uint64_t fftsAddr, uint8_t* dst_gva, uint8_t* src_gva, int elements,
    int test_mode, int data_type, int ub_size_b, int loop_count, int metric, int batch, int sync_id,
    uint8_t* timing_out_gva);

static perftest::rdma_mode_t get_rdma_mode(const char* test_type_str)
{
    if (strcmp(test_type_str, "put") == 0)
        return perftest::TEST_MODE_RDMA_PUT;
    if (strcmp(test_type_str, "bi_put") == 0)
        return perftest::TEST_MODE_RDMA_BI_PUT;
    if (strcmp(test_type_str, "get") == 0)
        return perftest::TEST_MODE_RDMA_GET;
    if (strcmp(test_type_str, "bi_get") == 0)
        return perftest::TEST_MODE_RDMA_BI_GET;
    return perftest::TEST_MODE_RDMA_INVALID;
}

static bool is_valid_data_type(const char* data_type_str)
{
    if (strcmp(data_type_str, "float") == 0)
        return true;
    if (strcmp(data_type_str, "int8") == 0)
        return true;
    if (strcmp(data_type_str, "int16") == 0)
        return true;
    if (strcmp(data_type_str, "int32") == 0)
        return true;
    if (strcmp(data_type_str, "int64") == 0)
        return true;
    if (strcmp(data_type_str, "uint8") == 0)
        return true;
    if (strcmp(data_type_str, "uint16") == 0)
        return true;
    if (strcmp(data_type_str, "uint32") == 0)
        return true;
    if (strcmp(data_type_str, "uint64") == 0)
        return true;
    if (strcmp(data_type_str, "char") == 0)
        return true;
    return false;
}

static perftest::perf_metric_t get_perf_metric(const char* metric_str)
{
    if (strcmp(metric_str, "lat") == 0)
        return perftest::PERF_METRIC_LAT;
    if (strcmp(metric_str, "bw") == 0)
        return perftest::PERF_METRIC_BW;
    return perftest::PERF_METRIC_INVALID;
}

template <typename T>
int test_rdma_perf_test_impl(
    int pe_id, int n_pes, uint64_t local_mem_size, int min_exponent, int max_exponent, int loop_count,
    perftest::rdma_mode_t test_mode, perftest::perf_data_type_t data_type_enum, int ub_size_b,
    perftest::perf_metric_t metric, int batch, int sync_id, std::vector<std::vector<std::string>>& csv_data)
{
    static const char* kFunc = "test_rdma_perf_test_impl";
    constexpr uint32_t block_dim = 1;
    int32_t device_id = (pe_id % g_npus + f_npu);
    aclshmemx_init_attr_t attributes;
    aclrtStream stream = nullptr;
    void* dst_ptr = nullptr;
    void* src_ptr = nullptr;
    void* timing_out_ptr = nullptr;
    bool acl_initialized = false;
    bool device_set = false;
    bool stream_created = false;
    bool shmem_initialized = false;
    int ret = 0;
    uint64_t fftsAddr = 0;

    CHECK_ACL_GOTO(aclInit(nullptr), ret, cleanup);
    acl_initialized = true;

    CHECK_ACL_GOTO(aclrtSetDevice(device_id), ret, cleanup);
    device_set = true;

    CHECK_ACL_GOTO(aclrtCreateStream(&stream), ret, cleanup);
    stream_created = true;

    fftsAddr = util_get_ffts_config();

    test_set_attr(pe_id, n_pes, local_mem_size, ipport, default_flag_uid, &attributes);
    attributes.option_attr.data_op_engine_type = ACLSHMEM_DATA_OP_ROCE;
    CHECK_SHMEM_GOTO(aclshmemx_init_attr(ACLSHMEMX_INIT_WITH_DEFAULT, &attributes), ret, cleanup);
    shmem_initialized = true;

    for (int exponent = min_exponent; exponent <= max_exponent; exponent++) {
        size_t datasize = static_cast<size_t>(1) << exponent;
        std::cout << "pe: " << pe_id << " size: " << datasize << std::endl;

        dst_ptr = aclshmem_malloc(datasize);
        src_ptr = aclshmem_malloc(datasize);
        if (dst_ptr == nullptr) {
            std::cerr << "[ERROR] [" << kFunc << "] aclshmem_malloc failed for dst_ptr, size=" << datasize << std::endl;
            ret = -1;
            goto cleanup;
        }
        if (src_ptr == nullptr) {
            std::cerr << "[ERROR] [" << kFunc << "] aclshmem_malloc failed for src_ptr, size=" << datasize << std::endl;
            ret = -1;
            goto cleanup;
        }

        timing_out_ptr = aclshmem_malloc(sizeof(int64_t) * 2);
        if (timing_out_ptr == nullptr) {
            std::cerr << "[ERROR] [" << kFunc << "] aclshmem_malloc failed for timing_out_ptr" << std::endl;
            ret = -1;
            goto cleanup;
        }
        {
            std::vector<int64_t> zero(2, 0);
            CHECK_ACL_GOTO(
                aclrtMemcpy(
                    timing_out_ptr, sizeof(int64_t) * 2, zero.data(), sizeof(int64_t) * 2, ACL_MEMCPY_HOST_TO_DEVICE),
                ret, cleanup);
        }

        int trans_size = datasize / sizeof(T);

        std::vector<T> src_input(trans_size, 0);
        std::vector<T> dst_input(trans_size, 0);
        for (int i = 0; i < trans_size; i++) {
            src_input[i] = (T)(pe_id + 10);
            dst_input[i] = (T)(pe_id + 100);
        }
        CHECK_ACL_GOTO(
            aclrtMemcpy(src_ptr, datasize, src_input.data(), datasize, ACL_MEMCPY_HOST_TO_DEVICE), ret, cleanup);
        CHECK_ACL_GOTO(
            aclrtMemcpy(dst_ptr, datasize, dst_input.data(), datasize, ACL_MEMCPY_HOST_TO_DEVICE), ret, cleanup);
        aclshmem_barrier_all(); // Ensure initialization is complete.
        launch_rdma_perf_kernel(
            block_dim, stream, fftsAddr, (uint8_t*)dst_ptr, (uint8_t*)src_ptr, trans_size, static_cast<int>(test_mode),
            static_cast<int>(data_type_enum), ub_size_b, loop_count, static_cast<int>(metric), batch, sync_id,
            (uint8_t*)timing_out_ptr);
        CHECK_ACL_GOTO(aclrtSynchronizeStream(stream), ret, cleanup);
        aclshmem_barrier_all(); // Ensure that operator execution on all PEs has completed.
        bool is_put_get_mode =
            (test_mode == perftest::TEST_MODE_RDMA_PUT || test_mode == perftest::TEST_MODE_RDMA_BI_PUT ||
             test_mode == perftest::TEST_MODE_RDMA_GET || test_mode == perftest::TEST_MODE_RDMA_BI_GET);
        if (is_put_get_mode) {
            // Read back timing output: [0]=PE0_time(forward), [1]=PE1_time(reverse)
            // After cross-PE exchange in kernel, both PEs have both values.
            std::vector<int64_t> timing_host(2, 0);
            CHECK_ACL_GOTO(
                aclrtMemcpy(
                    timing_host.data(), sizeof(int64_t) * 2, timing_out_ptr, sizeof(int64_t) * 2,
                    ACL_MEMCPY_DEVICE_TO_HOST),
                ret, cleanup);

            bool is_bidir =
                (test_mode == perftest::TEST_MODE_RDMA_BI_PUT || test_mode == perftest::TEST_MODE_RDMA_BI_GET);

            // CSV: compute BW from timing_out
            const char* soc_name = aclrtGetSocName();
            int64_t cycle2us = 50;
            if (soc_name != nullptr && std::string(soc_name).find("Ascend950") != std::string::npos) {
                cycle2us = 1000;
            }
            double per_iter_us0 = (loop_count > 0) ? static_cast<double>(timing_host[0]) / cycle2us / loop_count : 0.0;
            double per_iter_us1 = (loop_count > 0) ? static_cast<double>(timing_host[1]) / cycle2us / loop_count : 0.0;

            double bw_gb = 0.0, bw_gib = 0.0, per_iter_us = 0.0;
            if (is_bidir) {
                if (metric == perftest::PERF_METRIC_LAT) {
                    per_iter_us = (per_iter_us0 + per_iter_us1) / 2;
                    std::cout << "[LAT] PE" << pe_id << " forward(PE0→PE1)=" << per_iter_us0 << " us"
                              << " reverse(PE1→PE0)=" << per_iter_us1 << " us"
                              << " avg=" << per_iter_us << " us" << std::endl;
                } else {
                    double bps0 = (per_iter_us0 > 0) ? datasize / per_iter_us0 * 1000000.0 : 0.0;
                    double bps1 = (per_iter_us1 > 0) ? datasize / per_iter_us1 * 1000000.0 : 0.0;
                    double bw_gb_0 = bps0 / 1000.0 / 1000.0 / 1000.0;
                    double bw_gb_1 = bps1 / 1000.0 / 1000.0 / 1000.0;
                    bw_gb = bw_gb_0 + bw_gb_1;
                    double bw_gib_0 = bps0 / 1024.0 / 1024.0 / 1024.0;
                    double bw_gib_1 = bps1 / 1024.0 / 1024.0 / 1024.0;
                    bw_gib = bw_gib_0 + bw_gib_1;
                    std::cout << "[BW] PE" << pe_id << " forward(PE0→PE1)=" << bw_gb_0 << " GB/s"
                              << " reverse(PE1→PE0)=" << bw_gb_1 << " GB/s"
                              << " total=" << bw_gb << " GB/s" << std::endl;
                    per_iter_us = per_iter_us0 + per_iter_us1;
                }
            } else {
                if (metric == perftest::PERF_METRIC_LAT) {
                    per_iter_us = (pe_id == 0) ? per_iter_us0 : per_iter_us1;
                    std::cout << "[LAT] PE" << pe_id << ": " << per_iter_us << " us" << std::endl;
                } else {
                    per_iter_us = (pe_id == 0) ? per_iter_us0 : per_iter_us1;
                    double bps = (per_iter_us > 0) ? datasize / per_iter_us * 1000000.0 : 0.0;
                    bw_gb = bps / 1000.0 / 1000.0 / 1000.0;
                    bw_gib = bps / 1024.0 / 1024.0 / 1024.0;
                    std::cout << "[BW] PE" << pe_id << ": " << bw_gb << " GB/s" << std::endl;
                }
            }

            std::vector<std::string> row = {
                uint64_to_string(datasize),           int_to_string(g_npus),   "1",
                double_to_string(ub_size_b / 1024.0), double_to_string(bw_gb), double_to_string(bw_gib),
                double_to_string(per_iter_us),
            };
            csv_data.push_back(row);
        }

        bool verify_success = true;
        auto compare_values = [&](T* p1, T* p2, size_t count, const char* l1, const char* l2) -> bool {
            for (size_t i = 0; i < count; i++) {
                if (p1[i] != p2[i]) {
                    std::cout << "  [ERROR] Mismatch at index " << i << ": " << l1 << "=" << (double)p1[i] << ", " << l2
                              << "=" << (double)p2[i] << std::endl;
                    return false;
                }
            }
            return true;
        };

        std::vector<T> dst_host(trans_size, 0);
        std::vector<T> src_host(trans_size, 0);
        CHECK_ACL_GOTO(
            aclrtMemcpy(dst_host.data(), datasize, dst_ptr, datasize, ACL_MEMCPY_DEVICE_TO_HOST), ret, cleanup);
        CHECK_ACL_GOTO(
            aclrtMemcpy(src_host.data(), datasize, src_ptr, datasize, ACL_MEMCPY_DEVICE_TO_HOST), ret, cleanup);

        int peer_pe = (pe_id + 1) % n_pes;
        if (test_mode == perftest::TEST_MODE_RDMA_PUT) {
            std::cout << "\n[Verification] put: checking..." << std::endl;
            if (pe_id != 0) {
                T expected_val = static_cast<T>(10);
                if (!compare_values(dst_host.data(), &expected_val, 1, "dst[0]", "peer_src[0]")) {
                    verify_success = false;
                }
            }
        } else if (test_mode == perftest::TEST_MODE_RDMA_GET) {
            std::cout << "\n[Verification] get: checking..." << std::endl;
            if (pe_id == 0) {
                T expected_val = static_cast<T>(peer_pe + 10);
                if (!compare_values(dst_host.data(), &expected_val, 1, "dst[0]", "peer_src[0]")) {
                    verify_success = false;
                }
            }
        } else if (test_mode == perftest::TEST_MODE_RDMA_BI_PUT) {
            std::cout << "\n[Verification] bi_put: checking..." << std::endl;
            T expected_val = static_cast<T>(peer_pe + 10);
            if (!compare_values(dst_host.data(), &expected_val, 1, "dst[0]", "peer_src[0]")) {
                verify_success = false;
            }
        } else if (test_mode == perftest::TEST_MODE_RDMA_BI_GET) {
            std::cout << "\n[Verification] bi_get: checking..." << std::endl;
            T expected_val = static_cast<T>(peer_pe + 10);
            if (!compare_values(dst_host.data(), &expected_val, 1, "dst[0]", "peer_src[0]")) {
                verify_success = false;
            }
        }

        if (verify_success) {
            std::cout << "[Verification] SUCCESS" << std::endl;
        } else {
            std::cout << "[Verification] FAILED" << std::endl;
        }

        aclshmem_free(dst_ptr);
        dst_ptr = nullptr;
        aclshmem_free(src_ptr);
        src_ptr = nullptr;
        aclshmem_free(timing_out_ptr);
        timing_out_ptr = nullptr;
        CHECK_ACL_GOTO(aclrtSynchronizeStream(stream), ret, cleanup);
    }

cleanup:
    if (dst_ptr != nullptr) {
        aclshmem_free(dst_ptr);
        dst_ptr = nullptr;
    }
    if (src_ptr != nullptr) {
        aclshmem_free(src_ptr);
        src_ptr = nullptr;
    }
    if (timing_out_ptr != nullptr) {
        aclshmem_free(timing_out_ptr);
        timing_out_ptr = nullptr;
    }
    if (shmem_initialized) {
        CHECK_SHMEM_CLEANUP(aclshmem_finalize(), ret);
    }
    if (stream_created) {
        CHECK_ACL_CLEANUP(aclrtDestroyStream(stream), ret);
    }
    if (device_set) {
        CHECK_ACL_CLEANUP(aclrtResetDevice(device_id), ret);
    }
    if (acl_initialized) {
        CHECK_ACL_CLEANUP(aclFinalize(), ret);
    }
    return ret;
}

int main(int argc, char* argv[])
{
    int n_pes = 2;
    int pe_id = 0;
    ipport = "tcp://127.0.0.1:8768";
    g_npus = 2;
    f_npu = 4;
    const char* test_type = "put";
    fuc_data_type = "float";
    int input_block_size = 1;
    int min_exponent = 3;
    int max_exponent = 17;
    int loop_count = 1000;
    int ub_size_b = 128;
    const char* metric_str = "bw";
    int batch = 0;
    int sync_id = 0;
    int qp_num = 1;

    static struct option long_options[] = {
        {"pes", required_argument, 0, 0},
        {"pe-id", required_argument, 0, 0},
        {"ipport", required_argument, 0, 0},
        {"gnpus", required_argument, 0, 0},
        {"fnpu", required_argument, 0, 0},
        {"test-type", required_argument, 0, 't'},
        {"datatype", required_argument, 0, 'd'},
        {"block-size", required_argument, 0, 'b'},
        {"block-range", required_argument, 0, 0},
        {"exponent", required_argument, 0, 'e'},
        {"exponent-range", required_argument, 0, 0},
        {"loop-count", required_argument, 0, 0},
        {"ub-size", required_argument, 0, 0},
        {"metric", required_argument, 0, 0},
        {"batch", required_argument, 0, 0},
        {"sync-id", required_argument, 0, 0},
        {"qp", required_argument, 0, 'q'},
        {0, 0, 0, 0}};

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "t:d:b:e:q:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't':
                test_type = optarg;
                break;
            case 'd':
                fuc_data_type = optarg;
                break;
            case 'b':
                input_block_size = std::atoi(optarg);
                break;
            case 'e':
                min_exponent = max_exponent = std::atoi(optarg);
                break;
            case 'q':
                qp_num = std::atoi(optarg);
                break;
            case 0:
                if (strcmp(long_options[option_index].name, "pes") == 0)
                    n_pes = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "pe-id") == 0)
                    pe_id = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "ipport") == 0)
                    ipport = optarg;
                else if (strcmp(long_options[option_index].name, "gnpus") == 0)
                    g_npus = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "fnpu") == 0)
                    f_npu = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "block-range") == 0) {
                    input_block_size = std::atoi(optarg);
                    if (optind < argc) {
                        optind++;
                    }
                } else if (strcmp(long_options[option_index].name, "exponent-range") == 0) {
                    min_exponent = std::atoi(optarg);
                    if (optind < argc) {
                        max_exponent = std::atoi(argv[optind]);
                        optind++;
                    }
                } else if (strcmp(long_options[option_index].name, "loop-count") == 0)
                    loop_count = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "ub-size") == 0)
                    ub_size_b = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "metric") == 0)
                    metric_str = optarg;
                else if (strcmp(long_options[option_index].name, "batch") == 0)
                    batch = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "sync-id") == 0)
                    sync_id = std::atoi(optarg);
                else if (strcmp(long_options[option_index].name, "qp") == 0)
                    qp_num = std::atoi(optarg);
                break;
            default:
                std::cerr << "Unknown argument" << std::endl;
                return 1;
        }
    }

    if (n_pes <= 0) {
        std::cerr << "Error: --pes must be greater than 0 (got " << n_pes << ")" << std::endl;
        return 1;
    }
    if (g_npus <= 0) {
        std::cerr << "Error: --gnpus must be greater than 0 (got " << g_npus << ")" << std::endl;
        return 1;
    }
    if (pe_id < 0 || pe_id >= n_pes) {
        std::cerr << "Error: --pe-id must be in range [0, " << n_pes << ") (got " << pe_id << ")" << std::endl;
        return 1;
    }
    if (f_npu < 0) {
        std::cerr << "Error: --fnpu must be greater than or equal to 0 (got " << f_npu << ")" << std::endl;
        return 1;
    }

    if (input_block_size != 1) {
        std::cerr << "WARN: RDMA perftest forces block_size=1 (got " << input_block_size << ")" << std::endl;
    }

    perftest::perf_metric_t metric = get_perf_metric(metric_str);
    if (metric == perftest::PERF_METRIC_INVALID) {
        std::cerr << "Error: --metric must be 'bw' or 'lat' (got '" << metric_str << "')" << std::endl;
        return 1;
    }

    if (strcmp(test_type, "put_signal") == 0) {
        std::cerr << "Error: test type 'put_signal' is not supported by rdma_perftest "
                     "(aclshmemx_roce_put_signal_nbi API unavailable)"
                  << std::endl;
        return 1;
    }

    if (batch < 0) {
        std::cerr << "Error: --batch must be >= 0 (got " << batch << ")" << std::endl;
        return 1;
    }
    if (loop_count < 1) {
        std::cerr << "Error: --loop-count must be >= 1 (got " << loop_count << ")" << std::endl;
        return 1;
    }
    if (batch == 0 || batch > loop_count) {
        batch = loop_count;
    }
    if (qp_num != 1) {
        std::cerr << "Error: --qp must be 1 (single QP only, got " << qp_num << ")" << std::endl;
        return 1;
    }
    if (sync_id < 0) {
        std::cerr << "Error: --sync-id must be >= 0 (got " << sync_id << ")" << std::endl;
        return 1;
    }

    if (!is_valid_data_type(fuc_data_type)) {
        std::cerr << "Error: --datatype must be one of: float, int8, int16, int32, int64, uint8, uint16, uint32, "
                     "uint64, char (got '"
                  << fuc_data_type << "')" << std::endl;
        return 1;
    }

    ub_size_b = ((ub_size_b + UB_ALIGN_SIZE - 1) / UB_ALIGN_SIZE) * UB_ALIGN_SIZE;

    std::cout << "[INFO] rdma_perftest start, pe=" << pe_id << ", t=" << test_type << ", d=" << fuc_data_type
              << ", exp=" << min_exponent << "-" << max_exponent << ", loop=" << loop_count << ", ub=" << ub_size_b
              << "B, metric=" << metric_str << ", batch=" << batch << ", sync_id=" << sync_id << ", qp=" << qp_num
              << std::endl;

    fuc_test_type = test_type;
    perftest::rdma_mode_t test_mode = get_rdma_mode(test_type);
    if (test_mode == perftest::TEST_MODE_RDMA_INVALID) {
        std::cerr << "Error: -t/--test-type must be one of: put, bi_put, get, bi_get (got '" << test_type << "')"
                  << std::endl;
        return 1;
    }
    perftest::perf_data_type_t data_type_enum = get_data_type(fuc_data_type);

    // The exponent upper bound is 62: below, max_datasize = (1ULL << max_exponent) is then multiplied by 2.
    // If exponent >= 63, (1ULL << 63) * 2 would overflow uint64_t itself.
    const int MAX_ALLOWED_EXPONENT = 62;
    if (min_exponent < 0 || max_exponent < min_exponent || max_exponent > MAX_ALLOWED_EXPONENT) {
        std::cerr << "Error: exponent range invalid, must be [0, " << MAX_ALLOWED_EXPONENT << "] and min<=max (got "
                  << min_exponent << "-" << max_exponent << ")" << std::endl;
        return 1;
    }

    uint64_t max_datasize = (1ULL << max_exponent);
    uint64_t local_mem_size = 1024UL * 1024UL * 1024;
    const uint64_t ONE_GB = 1024UL * 1024UL * 1024;
    const uint64_t MAX_GB = 40;
    if (max_datasize * 2 > local_mem_size) {
        uint64_t gb_needed = (max_datasize * 2 + ONE_GB - 1) / ONE_GB;
        if (gb_needed > MAX_GB) {
            std::cerr << "Error: required mem exceeds 40GB" << std::endl;
            return 1;
        }
        local_mem_size = gb_needed * ONE_GB;
    }

    std::vector<std::vector<std::string>> csv_data = {
        {"DataSize/B", "Npus", "Blocks", "UBsize/KB", "Bandwidth/GB/s", "Bandwidth/GiB/s", "CoreMaxTime/us"}};

    int status = 0;
#define RDMA_TEST_IMPL_OP(type)                                                                                     \
    status = test_rdma_perf_test_impl<type>(                                                                        \
        pe_id, n_pes, local_mem_size, min_exponent, max_exponent, loop_count, test_mode, data_type_enum, ub_size_b, \
        metric, batch, sync_id, csv_data)
    DISPATCH_BY_TYPE(fuc_data_type, RDMA_TEST_IMPL_OP);
#undef RDMA_TEST_IMPL_OP

    if (status != 0) {
        std::cerr << "[FAILED] rdma_perftest failed in pe " << pe_id << std::endl;
        return status;
    }
    if (pe_id == 0) {
        std::string csv_filename = "output/rdma_" + std::string(metric_str) + "_" + std::string(fuc_test_type) + "_" +
                                   std::string(fuc_data_type) + "_0.csv";
        write_csv(csv_filename, csv_data);
    }

    std::cout << "[SUCCESS] rdma_perftest done in pe " << pe_id << std::endl;
    return 0;
}
