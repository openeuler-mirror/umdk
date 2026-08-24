/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>

#include "redis_cache_driver.h"

// Thread-local Redis context (thread-safe for single-thread-per-connection)
// Note: For multi-threaded use, ensure one thread uses one connection.
static __thread redisContext *tls_redis_context = NULL;

// Helper: Free redisReply object
static void free_redis_reply(void *reply) {
    if (reply) {
        freeReplyObject(reply);
    }
}

// Get or create thread-local Redis connection
static redisContext *get_redis_context(void) {
    if (tls_redis_context == NULL) {
        tls_redis_context = redisConnect("127.0.0.1", 6379);
        if (tls_redis_context == NULL) {
            printf("Failed to allocate Redis context\n");
            return NULL;
        }
        if (tls_redis_context->err) {
            printf("Redis connection error: %s\n", tls_redis_context->errstr);
            redisFree(tls_redis_context);
            tls_redis_context = NULL;
            return NULL;
        }
    }
    return tls_redis_context;
}

// Release thread-local Redis connection (optional, called on thread exit)
void destroy_redis_context(void) {
    if (tls_redis_context) {
        redisFree(tls_redis_context);
        tls_redis_context = NULL;
    }
}

// Retrieve all fields from a Redis hash
aigw_error_t redis_hash_get_all(const char *key, key_value_array_t *out_fields) {
    if (!key || !out_fields) {
        return AIGW_ERR_INVALID_PARAM;
    }

    redisContext *ctx = get_redis_context();
    if (!ctx) {
        return AIGW_ERR_INTERNAL;
    }

    // Execute HGETALL command
    redisReply *reply = (redisReply*)redisCommand(ctx, "HGETALL %s", key);
    if (!reply) {
        return AIGW_ERR_INTERNAL;
    }
    if (reply->type == REDIS_REPLY_NIL) {
        free_redis_reply(reply);
        out_fields->pairs = NULL;
        out_fields->count = 0;
        return AIGW_ERR_NOT_FOUND;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        free_redis_reply(reply);
        return AIGW_ERR_INTERNAL;
    }

    // Each field has a value, so number of pairs = elements / 2
    int num_pairs = reply->elements / 2;
    if (num_pairs == 0) {
        free_redis_reply(reply);
        out_fields->pairs = NULL;
        out_fields->count = 0;
        return AIGW_SUCCESS;
    }

    // Allocate memory for key-value pairs
    key_value_pair_t *pairs = (key_value_pair_t*)calloc(num_pairs, sizeof(key_value_pair_t));
    if (!pairs) {
        free_redis_reply(reply);
        return AIGW_ERR_NO_MEMORY;
    }

    int idx = 0;
    for (size_t i = 0; i < reply->elements - 1; i += 2) {
        redisReply *field = reply->element[i];
        redisReply *value = reply->element[i + 1];

        if (field->type != REDIS_REPLY_STRING || value->type != REDIS_REPLY_STRING) {
            continue; // Skip non-string entries
        }

        strncpy(pairs[idx].key, field->str, AIGW_CACHE_KEY_MAX_LEN - 1);
        strncpy(pairs[idx].value, value->str, AIGW_CACHE_VALUE_MAX_LEN - 1);
        pairs[idx].key[AIGW_CACHE_KEY_MAX_LEN - 1] = '\0';
        pairs[idx].value[AIGW_CACHE_VALUE_MAX_LEN - 1] = '\0';
        idx++;
    }

    free_redis_reply(reply);

    out_fields->pairs = pairs;
    out_fields->count = idx;
    return AIGW_SUCCESS;
}

// Set multiple fields in a Redis hash
aigw_error_t redis_hash_set_fields(const char *key, const key_value_array_t *fields) {
    if (!key || !fields || !fields->pairs || fields->count <= 0) {
        return AIGW_ERR_INVALID_PARAM;
    }

    redisContext *ctx = get_redis_context();
    if (!ctx) {
        return AIGW_ERR_INTERNAL;
    }

    // Step 1: Build command: HSET key field1 value1 field2 value2 ...
    int argc = 2 + fields->count * 2;
    const char **argv = (const char**)calloc(argc, sizeof(char*));
    size_t *argvlen = (size_t*)malloc(argc * sizeof(size_t));

    if (!argv || !argvlen) {
        free(argv);
        free(argvlen);
        return AIGW_ERR_NO_MEMORY;
    }

    argv[0] = "HSET";
    argvlen[0] = 4;
    argv[1] = key;
    argvlen[1] = strlen(key);

    for (int i = 0; i < fields->count; i++) {
        int idx = 2 + i * 2;
        argv[idx] = fields->pairs[i].key;
        argvlen[idx] = strlen(fields->pairs[i].key);
        argv[idx + 1] = fields->pairs[i].value;
        argvlen[idx + 1] = strlen(fields->pairs[i].value);
    }

    redisReply *reply = redisCommandArgv(ctx, argc, argv, argvlen);
    free(argv);
    free(argvlen);

    if (!reply || reply->type == REDIS_REPLY_ERROR) {
        free_redis_reply(reply);
        return AIGW_ERR_INTERNAL;
    }

    free_redis_reply(reply);

    if (fields->ttl <= 0) {
        return AIGW_SUCCESS;
    }

    // Step 2: Set TTL if needed
    const char *expire_argv[3];
    size_t expire_argvlen[3];

    expire_argv[0] = "EXPIRE";
    expire_argvlen[0] = 6;
    expire_argv[1] = key;
    expire_argvlen[1] = strlen(key);

    char ttl_str[12]; // Supports up to 2^32 (~4e9 seconds)
    int len = snprintf(ttl_str, sizeof(ttl_str), "%d", fields->ttl);
    if (len < 0 || len >= (int)sizeof(ttl_str)) {
        return AIGW_ERR_INTERNAL; // Should not happen
    }
    expire_argv[2] = ttl_str;
    expire_argvlen[2] = len;

    redisReply *expire_reply = redisCommandArgv(ctx, 3, expire_argv, expire_argvlen);
    if (!expire_reply || expire_reply->type == REDIS_REPLY_ERROR) {
        free_redis_reply(expire_reply);
        printf("Failed to set ttl\n");
    }
    free_redis_reply(expire_reply);

    return AIGW_SUCCESS;
}

// Delete multiple fields from a Redis hash
aigw_error_t redis_hash_delete_fields(const char *key, char **field_keys, uint32_t field_count) {
    if (!key || !field_keys || field_count <= 0) {
        return AIGW_ERR_INVALID_PARAM;
    }

    redisContext *ctx = get_redis_context();
    if (!ctx) {
        return AIGW_ERR_INTERNAL;
    }

    // Validate all field keys are non-NULL
    for (uint32_t i = 0; i < field_count; i++) {
        if (!field_keys[i]) {
            return AIGW_ERR_INVALID_PARAM;
        }
    }

    // Build command: HDEL key field1 field2 ...
    int argc = 2 + field_count;  // "HDEL", key, fields...
    const char **argv = (const char**)calloc(argc, sizeof(char*));
    size_t *argvlen = (size_t*)malloc(argc * sizeof(size_t));

    if (!argv || !argvlen) {
        free(argv);
        free(argvlen);
        return AIGW_ERR_NO_MEMORY;
    }

    argv[0] = "HDEL";
    argvlen[0] = 4;
    argv[1] = key;
    argvlen[1] = strlen(key);

    for (int i = 0; i < field_count; i++) {
        argv[2 + i] = field_keys[i];
        argvlen[2 + i] = strlen(field_keys[i]);
    }

    redisReply *reply = redisCommandArgv(ctx, argc, argv, argvlen);
    free(argv);
    free(argvlen);

    if (!reply) {
        return AIGW_ERR_INTERNAL;
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        free_redis_reply(reply);
        return AIGW_ERR_INTERNAL;
    }

    free_redis_reply(reply);
    return AIGW_SUCCESS;
}

/**
 * @brief Batch retrieve all fields from multiple Redis hashes using Pipeline.
 *
 * Uses hiredis Pipeline to send multiple HGETALL commands in a single network round-trip.
 *
 * @param[in]  keys         Array of hash keys. Must be non-NULL and null-terminated.
 * @param[in]  key_count   Number of keys in the array.
 * @param[out] out_arrays   Pointer to receive allocated array of key_value_array_t.
 *                          Caller must free each pairs[i] and then free the array.
 * @param[out] array_count  Number of successfully retrieved results.
 * @return AIGW_SUCCESS on success, or error code.
 */
aigw_error_t redis_hash_get_all_batch(const char **keys, uint32_t key_count,
                                      key_value_array_t *out_arrays) {
    // Parameter validation
    if (!keys || key_count == 0 || !out_arrays) {
        return AIGW_ERR_INVALID_PARAM;
    }

    // Verify that all keys are not empty
    for (uint32_t i = 0; i < key_count; i++) {
        if (!keys[i]) {
            return AIGW_ERR_INVALID_PARAM;
        }
    }

    // Get Redis connection
    redisContext *ctx = get_redis_context();
    if (!ctx) {
        return AIGW_ERR_INTERNAL;
    }

    // Send all HGETALL commands in batches using Pipeline
    for (uint32_t i = 0; i < key_count; i++) {
        redisAppendCommand(ctx, "HGETALL %s", keys[i]);
    }

    // Get and parse responses one by one
    for (uint32_t i = 0; i < key_count; i++) {
        redisReply *reply = NULL;
        int ret = redisGetReply(ctx, (void**)&reply);

        if (ret != REDIS_OK || !reply) {
            // Clean allocated memory
            for (uint32_t j = 0; j < key_count; j++) {
                if (out_arrays[j].pairs) {
                    free(out_arrays[j].pairs);
                }
            }
            return AIGW_ERR_INTERNAL;
        }

        // Parse the response (reuse the parsing logic of redis_hash_get_all)
        if (reply->type == REDIS_REPLY_NIL) {
            // key does not exist
            out_arrays[i].pairs = NULL;
            out_arrays[i].count = 0;
        } else if (reply->type == REDIS_REPLY_ARRAY) {
            int num_pairs = reply->elements / 2;
            if (num_pairs > 0) {
                key_value_pair_t *pairs = (key_value_pair_t*)calloc(num_pairs, sizeof(key_value_pair_t));
                if (!pairs) {
                    freeReplyObject(reply);
                    // Clean allocated memory
                    for (uint32_t j = 0; j < key_count; j++) {
                        if (out_arrays[j].pairs) {
                            free(out_arrays[j].pairs);
                        }
                    }
                    return AIGW_ERR_NO_MEMORY;
                }

                int idx = 0;
                for (size_t j = 0; j < reply->elements - 1; j += 2) {
                    redisReply *field = reply->element[j];
                    redisReply *value = reply->element[j + 1];

                    if (field->type == REDIS_REPLY_STRING && value->type == REDIS_REPLY_STRING) {
                        strncpy(pairs[idx].key, field->str, AIGW_CACHE_KEY_MAX_LEN - 1);
                        strncpy(pairs[idx].value, value->str, AIGW_CACHE_VALUE_MAX_LEN - 1);
                        pairs[idx].key[AIGW_CACHE_KEY_MAX_LEN - 1] = '\0';
                        pairs[idx].value[AIGW_CACHE_VALUE_MAX_LEN - 1] = '\0';
                        idx++;
                    }
                }

                out_arrays[i].pairs = pairs;
                out_arrays[i].count = idx;
            } else {
                out_arrays[i].pairs = NULL;
                out_arrays[i].count = 0;
            }
        } else {
            freeReplyObject(reply);
            // Clean allocated memory
            for (uint32_t j = 0; j < key_count; j++) {
                if (out_arrays[j].pairs) {
                    free(out_arrays[j].pairs);
                }
            }

            return AIGW_ERR_INTERNAL;
        }

        freeReplyObject(reply);
    }

    return AIGW_SUCCESS;
}

// Get the Redis cache driver instance (thread-safe due to static init)
aigw_cache_driver_t *get_redis_cache_driver(void) {
    static aigw_cache_driver_t driver = {
        .driver_name = "redis_cache",
        .ops = {
            .hash_get_all = redis_hash_get_all,
            .hash_get_all_batch = redis_hash_get_all_batch,
            .hash_set_fields = redis_hash_set_fields,
            .hash_delete_fields = redis_hash_delete_fields
        }
    };
    return &driver;
}

// Test function to verify Redis cache operations
aigw_error_t test_redis_cache(void) {
    aigw_cache_driver_t *driver = get_redis_cache_driver();
    if (!driver) {
        printf("Failed to get Redis driver\n");
        return AIGW_ERR_INTERNAL;
    }

    const char *model_key = "model:llama3";
    const char *req_id_1 = "req_001";
    const char *req_id_2 = "req_002";
    const char *payload1 = "{\"input\":\"Hello\",\"tokens\":512}";
    const char *payload2 = "{\"input\":\"World\",\"tokens\":256}";

    // === Test: Write data ===
    key_value_array_t fields;
    fields.count = 2;
    fields.pairs = (key_value_pair_t*)calloc(2, sizeof(key_value_pair_t));
    if (!fields.pairs) {
        return AIGW_ERR_NO_MEMORY;
    }

    strncpy(fields.pairs[0].key, req_id_1, AIGW_CACHE_KEY_MAX_LEN - 1);
    strncpy(fields.pairs[0].value, payload1, AIGW_CACHE_VALUE_MAX_LEN - 1);
    fields.pairs[0].key[AIGW_CACHE_KEY_MAX_LEN - 1] = '\0';
    fields.pairs[0].value[AIGW_CACHE_VALUE_MAX_LEN - 1] = '\0';

    strncpy(fields.pairs[1].key, req_id_2, AIGW_CACHE_KEY_MAX_LEN - 1);
    strncpy(fields.pairs[1].value, payload2, AIGW_CACHE_VALUE_MAX_LEN - 1);
    fields.pairs[1].key[AIGW_CACHE_KEY_MAX_LEN - 1] = '\0';
    fields.pairs[1].value[AIGW_CACHE_VALUE_MAX_LEN - 1] = '\0';

    aigw_error_t ret = driver->ops.hash_set_fields((char*)model_key, &fields);
    if (ret != AIGW_SUCCESS) {
        printf("hash_set_fields failed: %d\n", ret);
        free(fields.pairs);
        return ret;
    }
    printf("hash_set_fields succeeded\n");

    // === Test: Read data ===
    key_value_array_t out_fields = {0};
    ret = driver->ops.hash_get_all((char*)model_key, &out_fields);
    if (ret != AIGW_SUCCESS) {
        printf("hash_get_all failed: %d\n", ret);
        free(fields.pairs);
        return ret;
    }

    printf("Retrieved %d fields:\n", out_fields.count);
    for (int i = 0; i < out_fields.count; i++) {
        printf("  %s = %s\n", out_fields.pairs[i].key, out_fields.pairs[i].value);
    }

    // Free output pairs
    if (out_fields.pairs) {
        free(out_fields.pairs);
    }

    // === Test: Delete field ===
    char *fields_to_del[] = {(char*)req_id_1};
    ret = driver->ops.hash_delete_fields((char*)model_key, fields_to_del, 1);
    if (ret != AIGW_SUCCESS) {
        printf("hash_delete_fields failed: %d\n", ret);
        free(fields.pairs);
        return ret;
    }
    printf("Deleted field: %s\n", req_id_1);

    // Verify remaining data
    ret = driver->ops.hash_get_all((char*)model_key, &out_fields);
    if (ret == AIGW_SUCCESS) {
        printf("After delete, remaining fields (%d):\n", out_fields.count);
        for (int i = 0; i < out_fields.count; i++) {
            printf("  %s = %s\n", out_fields.pairs[i].key, out_fields.pairs[i].value);
        }
        free(out_fields.pairs);
    } else if (ret == AIGW_ERR_NOT_FOUND) {
        printf("No fields left in hash.\n");
    } else {
        printf("hash_get_all after delete failed: %d\n", ret);
    }

    // Cleanup
    free(fields.pairs);
    return AIGW_SUCCESS;
}
