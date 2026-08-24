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

#include "aigw.h"
#include "simple_cache.h"

#ifdef ENABLE_REDIS_DRIVER
#include "redis_cache_driver.h"
#endif

#define NUM_OF_REQUEST 100
#define MODEL_NAME "qwen-72b"

#define NUM_OF_MAP_FIELDS 2

// Demo configuration limits
#define DEMO_MAX_INSTANCES_PER_MODEL 128
#define DEMO_MAX_SUPPORTED_MODELS   128
#define DEMO_MAX_PROMPT_LENGTH       20480
#define DEMO_REQUEST_TTL_SECONDS     600

#define AIGW_UUID_MAX_LEN 36
#define AIGW_ROLE_MAX_LEN 32
#define AIGW_MODEL_STR_MAX_LEN 64
#define AIGW_GENERIC_STR_MAX_LEN 128
#define AIGW_LOG_LEVEL_MAX_LEN 16
#define AIGW_LOG_PATH_MAX_LEN 256

// Typed thread request argument (avoids void* parameter; G.FUD.03)
typedef struct {
    int req_id;
} request_arg_t;

// Utility function: generate a simple UUID string (for example purposes only)
static void generate_uuid(char *buf, size_t len, int id)
{
    int n = snprintf(buf, len, "req-%08d", id);  // G.FUU.01: check snprintf return
    if (n < 0 || (size_t)n >= len) {
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

// Thread function: process one inference request
static void* process_request(void *arg)
{
    request_arg_t *req = (request_arg_t *)arg;
    int req_id = req->req_id;
    free(req); // Free dynamically allocated argument

    char uuid[AIGW_UUID_MAX_LEN];
    generate_uuid(uuid, sizeof(uuid), req_id);

    // Construct message
    aigw_openai_message_t message;
    message.role = "user";
    message.content = g_contents[req_id % CONTENT_SIZE];

    aigw_request_t request = {0};
    request.uuid = uuid;
    request.model = g_model[req_id % MODEL_COUNT];
    request.messages = &message;
    request.message_num = 1;

    // Selection context with load balancing strategies
    aigw_select_context_t ctx = {
        .node_num = NODE_COUNT,
        .node_list = g_nodes
    };

    // G.OTH.03: use random() instead of rand() for non-security sleep jitter
    int sleep_us1 = (random() % 1000 + 1000) * 1000;  // 1000ms ~ 2000ms => 1s ~ 2s
    printf("Request %s: Sleeping %d ms before node selection...\n", uuid, sleep_us1 / 1000);
    usleep(sleep_us1);

    aigw_select_result_t result = {0};
    aigw_error_t err = aigw_select_nodes(&request, &ctx, &result);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "Request %s: Node selection failed: %d, error: %s\n",
                uuid, err, result.error_desc);
        return NULL;
    }

    printf("Request %s: Prefill=%s, Decode=%s\n",
           uuid, result.prefill_node_addr, result.decode_node_addr);

    // Notify event: prefill finished
    aigw_event_info_t event = {0};
    event.model = request.model;
    event.request_id = request.uuid;
    event.event_name = "DECODE_RECEIVED_KVC";

    // G.OTH.03: use random() instead of rand() for non-security sleep jitter
    int sleep_us2 = (random() % 1000 + 6000) * 1000;  // 1000ms ~ 2000ms => 1s ~ 2s
    printf("Request %s: Sleeping %d ms before notifying event DECODE_RECEIVED_KVC\n", uuid, sleep_us2 / 1000);
    usleep(sleep_us2);
    aigw_notify_event(AIGW_EVENT_REQUEST, &event);

    // Notify event: decode finished
    event.event_name = "REQUEST_IS_FINISHED";
    // G.OTH.03: use random() instead of rand() for non-security sleep jitter
    int sleep_us3 = (random() % 1000 + 1000) * 1000;  // 1000ms ~ 2000ms => 1s ~ 2s
    printf("Request %s: Sleeping %d ms before notifying event REQUEST_IS_FINISHED\n", uuid, sleep_us3 / 1000);
    usleep(sleep_us3);
    aigw_notify_event(AIGW_EVENT_REQUEST, &event);

    return NULL;
}

// Helper: initialize component configuration (extracted from main; G.FUD.05)
static aigw_error_t init_aigw_component(void)
{
    // 1. Initialize component configuration
    aigw_config_t cfg = {0};
    cfg.log_level = "info";
    cfg.log_path = "/tmp";
    cfg.max_instances_per_model = DEMO_MAX_INSTANCES_PER_MODEL;
    cfg.max_supported_models = DEMO_MAX_SUPPORTED_MODELS;
    cfg.max_prompt_length = DEMO_MAX_PROMPT_LENGTH;
    cfg.request_ttl_seconds = DEMO_REQUEST_TTL_SECONDS;

    printf("Initializing AIGW...\n");
    aigw_error_t err = aigw_init(&cfg);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_init failed with error: %d\n", err);
    }
    return err;
}

// Helper: register cache driver and test cache operations (extracted from main; G.FUD.05)
static aigw_error_t register_and_test_cache_driver(void)
{
    // 2. Register cache driver
    printf("Registering cache driver...\n");
#ifdef ENABLE_REDIS_DRIVER
    aigw_cache_driver_t *driver = get_redis_cache_driver();
#else
    aigw_cache_driver_t *driver = get_simple_cache_driver();
#endif
    aigw_error_t err = aigw_register_cache_driver(driver);
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_register_cache_driver failed: %d\n", err);
        return err;
    }

    // 3. Test cache operations
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

// Helper: register the demo model (extracted from main; G.FUD.05)
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

// Helper: spawn concurrent inference request threads (extracted from main; G.FUD.05)
static void run_concurrent_requests(void)
{
    // 4. Spawn multiple threads to simulate concurrent inference requests (real-time requirement)
    printf("Spawning %d concurrent inference requests...\n", NUM_OF_REQUEST);
    pthread_t threads[NUM_OF_REQUEST];
    for (int i = 0; i < NUM_OF_REQUEST; i++) {
        // G.FUU.01: check malloc return
        request_arg_t *req = malloc(sizeof(request_arg_t));
        if (req == NULL) {
            fprintf(stderr, "Failed to allocate request argument %d\n", i);
            threads[i] = -1;
            continue;
        }
        req->req_id = i + 1;
        int ret = pthread_create(&threads[i], NULL, process_request, req);
        if (ret != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            free(req);
            threads[i] = -1;
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < NUM_OF_REQUEST; i++) {
        if (threads[i] == -1) {
            continue;
        }
        pthread_join(threads[i], NULL);
    }
}

// Helper: unregister the demo model (extracted from main; G.FUD.05)
static void unregister_demo_model(void)
{
    aigw_error_t err = aigw_unregister_model("qwen-72b");
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_unregister_model failed: %d\n", err);
    }
}

// Helper: unregister cache driver (extracted from main; G.FUD.05)
static void unregister_cache_driver_safe(void)
{
    // 5. Unregister cache driver
    printf("Unregistering cache driver...\n");
    aigw_error_t err = aigw_unregister_cache_driver();
    if (err != AIGW_SUCCESS) {
        fprintf(stderr, "aigw_unregister_cache_driver failed: %d\n", err);
    }
}

int main(int argc, char *argv[])
{
    printf("=== AIGW API Example: %d Concurrent Requests ===\n", NUM_OF_REQUEST);

    aigw_error_t err = init_aigw_component();
    if (err != AIGW_SUCCESS) {
        return -1;
    }

    err = register_and_test_cache_driver();
    if (err != AIGW_SUCCESS) {
        // G.CTL.05: no goto; clean up directly and finalize
        printf("Uninitializing AIGW...\n");
        aigw_uninit();
        printf("Example completed.\n");
        return -1;
    }

    register_demo_model();
    run_concurrent_requests();
    unregister_demo_model();
    unregister_cache_driver_safe();

    // 6. Finalize and clean up
    printf("Uninitializing AIGW...\n");
    aigw_uninit();

    printf("Example completed.\n");
    return 0;
}
