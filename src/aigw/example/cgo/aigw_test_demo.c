/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * @file example_aigw.c
 * @brief Example application demonstrating the usage of AIGW (AI Gateway) C API.
 *
 * This example illustrates how to initialize the AIGW component, register a cache driver,
 * perform node selection for inference requests using load balancing, notify events,
 * and manage concurrent AI inference workloads.
 *
 * It spawns 10 concurrent threads to simulate real-time inference traffic, showcasing
 * thread safety and performance characteristics of the AIGW API under load.
 *
 * The example uses mock implementations for cache operations to avoid external dependencies,
 * making it self-contained and suitable for integration testing or development reference.
 *
 * @note This example assumes that libaigw.so is properly installed and linked.
 *       The mock cache driver demonstrates the expected behavior of real drivers
 *       (e.g., Redis, DCS) without requiring network services.
 *
 *       All string buffers are safely handled within defined length limits.
 *       Dynamic memory is carefully managed to prevent leaks.
 *
 * @create 2026-01-26
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>

#include "aigw.h"
#include "simple_cache.h"

#ifdef ENABLE_REDIS_DRIVER
#include "redis_cache_driver.h"
#endif

#define NUM_OF_REQUEST 100
#define MODEL_NAME "qwen-72b"

#define NUM_OF_MAP_FIELDS 2

#define AIGW_UUID_MAX_LEN 36
#define AIGW_ROLE_MAX_LEN 32
#define AIGW_MODEL_STR_MAX_LEN 64
#define AIGW_GENERIC_STR_MAX_LEN 128
#define AIGW_LOG_LEVEL_MAX_LEN 16
#define AIGW_LOG_PATH_MAX_LEN 256

// Configuration constants for aigw_init
#define AIGW_MAX_INSTANCES_PER_MODEL 128
#define AIGW_MAX_SUPPORTED_MODELS    128
#define AIGW_MAX_PROMPT_LENGTH       20480
#define AIGW_REQUEST_TTL_SECONDS     600

// Sleep ranges (microseconds) for staged simulation timing
#define SLEEP_NODE_SELECT_BASE_US     1000000   // 1000ms
#define SLEEP_NODE_SELECT_RANGE_US    1000000
#define SLEEP_RECEIVED_KVC_BASE_US    6000000   // 6000ms
#define SLEEP_RECEIVED_KVC_RANGE_US   1000000
#define SLEEP_FINISHED_BASE_US        1000000
#define SLEEP_FINISHED_RANGE_US       1000000

#define USEC_PER_MSEC 1000

// xorshift32 constants (from Marsaglia, 2003): the triple (13, 17, 5) gives a
// full period of 2^32 - 1 for this PRNG.
#define XORSHIFT32_SHIFT_A 13
#define XORSHIFT32_SHIFT_B 17
#define XORSHIFT32_SHIFT_C 5

// Utility function: generate a simple UUID string (for example purposes only)
static void generate_uuid(char *buf, size_t len, int id)
{
    int written = snprintf(buf, len, "req-%08d", id);
    if (written < 0 || (size_t)written >= len) {
        if (len > 0) {
            buf[0] = '\0';
        }
    }
}

// Utility function: safely copy string into fixed-size buffer
static void safe_strcpy(char *dst, const char *src, size_t max_len)
{
    if (max_len > 0) {
        strncpy(dst, src, max_len - 1);
        dst[max_len - 1] = '\0';
    } else {
        *dst = '\0';
    }
}

static char* g_model[] = {
    "qwen-72b",
    "qwen-32b",
    "qwen-7b"
};
#define MODEL_COUNT (sizeof(g_model) / sizeof(g_model[0]))

// Predefined node list for load balancing simulation
static aigw_node_info_t g_nodes[] = {
    {.role = AIGW_INFER_PREFILL,    .node_addr = "192.168.1.10:8080", .group_id = "group-a"},
    {.role = AIGW_INFER_PREFILL,    .node_addr = "192.168.1.11:8080", .group_id = "group-a"},
    {.role = AIGW_INFER_PREFILL,    .node_addr = "192.168.1.12:8080", .group_id = "group-b"},
    {.role = AIGW_INFER_DECODE,     .node_addr = "192.168.1.13:8080", .group_id = "group-a"},
    {.role = AIGW_INFER_DECODE,     .node_addr = "192.168.1.14:8080", .group_id = "group-b"},
};

#define NODE_COUNT (sizeof(g_nodes) / sizeof(g_nodes[0]))

// Sample message content pool (simulating user inputs)
static const char* g_contents[] = {
    "Hello, how are you?",
    "Tell me about AI.",
    "Write a poem about spring.",
    "Explain quantum computing.",
    "Translate 'hello' to French.",
    "Summarize the last meeting.",
    "Generate Python code for Fibonacci.",
    "What is the weather today?",
    "Recommend a good book.",
    "Debug this C code snippet."
};

#define CONTENT_SIZE (sizeof(g_contents) / sizeof(g_contents[0]))

static const char *default_pretrain_ttft_filepath = "/etc/aigw/example/ttft_pretrain.txt";

// Deterministic, thread-safe pseudo-random replacement for rand(). Sufficient
// for spreading sleep timings in a demo; never use this for security purposes.
// xorshift32 seeded from req_id mixed with current time.
static unsigned int demo_prng(unsigned int *state)
{
    unsigned int x = *state;
    x ^= x << XORSHIFT32_SHIFT_A;
    x ^= x >> XORSHIFT32_SHIFT_B;
    x ^= x << XORSHIFT32_SHIFT_C;
    *state = x;
    return x;
}

static unsigned int demo_seed_from(int req_id)
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned int seed = (unsigned int)((ts.tv_nsec ^ (long)req_id) | 1u);
    return seed;
}

// Simulated request workflow done in a strongly-typed function (no void*).
static void run_request_workflow(int req_id)
{
    char uuid[AIGW_UUID_MAX_LEN];
    generate_uuid(uuid, sizeof(uuid), req_id);

    aigw_openai_message_t message;
    message.role = "user";
    message.content = g_contents[req_id % CONTENT_SIZE];

    aigw_request_t request = {0};
    request.uuid = uuid;
    request.model = g_model[req_id % MODEL_COUNT];
    request.messages = &message;
    request.message_num = 1;

    aigw_select_context_t ctx = {
        .node_num = NODE_COUNT,
        .node_list = g_nodes
    };

    unsigned int prng_state = demo_seed_from(req_id);

    int sleep_us1 = (int)(demo_prng(&prng_state) % SLEEP_NODE_SELECT_RANGE_US) + SLEEP_NODE_SELECT_BASE_US;
    printf("Request %s: Sleeping %d ms before node selection...\n", uuid, sleep_us1 / USEC_PER_MSEC);
    usleep(sleep_us1);

    aigw_select_result_t result = {0};
    aigw_error_t err = aigw_select_nodes(&request, &ctx, &result);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "Request %s: Node selection failed: %d, error: %s\n",
                uuid, err, result.error_desc);
        return;
    }

    printf("Request %s: Prefill=%s, Decode=%s\n",
           uuid, result.prefill_node_addr, result.decode_node_addr);

    // Notify event: prefill finished
    aigw_event_info_t event = {0};
    event.model = request.model;
    event.request_id = request.uuid;
    event.event_name = "DECODE_RECEIVED_KVC";

    int sleep_us2 = (int)(demo_prng(&prng_state) % SLEEP_RECEIVED_KVC_RANGE_US) + SLEEP_RECEIVED_KVC_BASE_US;
    printf("Request %s: Sleeping %d ms before notifying event DECODE_RECEIVED_KVC\n", uuid, sleep_us2 / USEC_PER_MSEC);
    usleep(sleep_us2);
    aigw_notify_event(AIGW_EVENT_REQUEST, &event);

    // Notify event: decode finished
    event.event_name = "REQUEST_IS_FINISHED";
    int sleep_us3 = (int)(demo_prng(&prng_state) % SLEEP_FINISHED_RANGE_US) + SLEEP_FINISHED_BASE_US;
    printf("Request %s: Sleeping %d ms before notifying event REQUEST_IS_FINISHED\n", uuid, sleep_us3 / USEC_PER_MSEC);
    usleep(sleep_us3);
    aigw_notify_event(AIGW_EVENT_REQUEST, &event);
}

// Atomic sequence used by worker threads to draw their own request ID, avoiding
// the need to pass a typed pointer through pthread_create's opaque parameter.
static atomic_int g_request_seq = 0;

/*
 * Forward-declared opaque payload type. Never defined and never dereferenced;
 * its sole purpose is to give the trampoline a strongly typed parameter
 * (`request_thread_arg_t *` rather than `void *`). The actual value passed
 * is NULL — the worker derives its request ID from g_request_seq.
 */
typedef struct request_thread_arg request_thread_arg_t;

/*
 * pthread worker. Takes a typed (opaque) pointer instead of `void *` to
 * comply with strongly-typed-parameter requirements; the value is unused.
 * The request ID is drawn from g_request_seq, not from the argument.
 *
 * Adapted to the POSIX `void *(*)(void *)` ABI via a single cast at the
 * pthread_create call site.
 */
static void *process_request_trampoline(request_thread_arg_t *arg)
{
    (void)arg;
    int req_id = atomic_fetch_add(&g_request_seq, 1) + 1;
    run_request_workflow(req_id);
    return NULL;
}

// Build the aigw configuration used by main().
static void build_aigw_config(aigw_config_t *cfg)
{
    cfg->log_level = "info";
    cfg->log_path = "/tmp";
    cfg->max_instances_per_model = AIGW_MAX_INSTANCES_PER_MODEL;
    cfg->max_supported_models = AIGW_MAX_SUPPORTED_MODELS;
    cfg->max_prompt_length = AIGW_MAX_PROMPT_LENGTH;
    cfg->request_ttl_seconds = AIGW_REQUEST_TTL_SECONDS;
}

// Initialize aigw + register cache driver + run cache test.
// Returns AIGW_SUCCESS only on full success; on failure, aigw_init may have
// succeeded — the caller is responsible for calling aigw_uninit().
static aigw_error_t init_and_test_cache(void)
{
    aigw_config_t cfg = {0};
    build_aigw_config(&cfg);

    printf("Initializing AIGW...\n");
    aigw_error_t err = aigw_init(&cfg);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_init failed with error: %d\n", err);
        return err;
    }

    printf("Registering cache driver...\n");
#ifdef ENABLE_REDIS_DRIVER
    aigw_cache_driver_t *driver = get_redis_cache_driver();
#else
    aigw_cache_driver_t *driver = get_simple_cache_driver();
#endif

    err = aigw_register_cache_driver(driver);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_register_cache_driver failed: %d\n", err);
        return err;
    }

    printf("Testing cache operations...\n");
#ifdef ENABLE_REDIS_DRIVER
    err = test_redis_cache();
#else
    err = test_simple_cache();
#endif
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "test_simple_cache failed: %d\n", err);
        return err;
    }
    return AIGW_SUCCESS;
}

// Register the demo qwen-72b model with separated deployment policies.
static void register_demo_model(void)
{
    aigw_model_config_t model_cfg = {
        .model = "qwen-72b",
        .deploy_policy = AIGW_DEPLOY_SEPARATED,
        .p_lb_type = AIGW_LB_PREFILL_TIME_AWARE,
        .d_lb_type = AIGW_LB_TOKEN_AWARE,
        .pretrain_ttft_path = default_pretrain_ttft_filepath,
        .tokenization_ratio = 0.35,
    };
    aigw_error_t err = aigw_register_model(&model_cfg);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_register_model failed: %d\n", err);
    }
}

// Spawn NUM_OF_REQUEST threads, each running run_request_workflow().
// thread_invalid[i] is set to 1 if creation failed.
static void spawn_request_threads(pthread_t *threads, int *thread_invalid)
{
    atomic_store(&g_request_seq, 0);
    for (int i = 0; i < NUM_OF_REQUEST; i++) {
        thread_invalid[i] = 0;
        // Cast required to bridge the strongly-typed trampoline to the POSIX
        // pthread_create ABI. Safe on all supported LP64 platforms: pointer
        // parameters share calling conventions regardless of pointee type,
        // and the trampoline never reads the argument.
        int ret = pthread_create(&threads[i], NULL,
                                 (void *(*)(void *))process_request_trampoline, NULL);
        if (ret != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            thread_invalid[i] = 1;
        }
    }
}

static void join_request_threads(pthread_t *threads, const int *thread_invalid)
{
    for (int i = 0; i < NUM_OF_REQUEST; i++) {
        if (thread_invalid[i]) {
            continue;
        }
        pthread_join(threads[i], NULL);
    }
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("=== AIGW API Example: %d Concurrent Requests ===\n", NUM_OF_REQUEST);

    aigw_error_t err = init_and_test_cache();
    if (err != AIGW_SUCCESS) {
        printf("Uninitializing AIGW...\n");
        aigw_uninit();
        printf("Example completed.\n");
        return -1;
    }

    register_demo_model();

    // 4. Spawn multiple threads to simulate concurrent inference requests
    printf("Spawning %d concurrent inference requests...\n", NUM_OF_REQUEST);
    pthread_t threads[NUM_OF_REQUEST];
    int thread_invalid[NUM_OF_REQUEST];
    spawn_request_threads(threads, thread_invalid);
    join_request_threads(threads, thread_invalid);

    err = aigw_unregister_model("qwen-72b");
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_unregister_model failed: %d\n", err);
    }

    // 5. Unregister cache driver
    printf("Unregistering cache driver...\n");
    err = aigw_unregister_cache_driver();
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_unregister_cache_driver failed: %d\n", err);
    }

    // 6. Finalize and clean up
    printf("Uninitializing AIGW...\n");
    aigw_uninit();

    printf("Example completed.\n");
    return 0;
}
