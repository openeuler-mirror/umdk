/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * @file simple_cache.c
 * @brief simulate redis-like cache.
 *
 * @create 2026-01-26
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "simple_cache.h"

#ifdef DEBUG_CACHE
#define CACHE_DEBUG(fmt, ...) printf("[CACHE DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define CACHE_DEBUG(fmt, ...)
#endif

// Define constants
#define MAX_MODEL_NAME_LEN 64
#define MAX_REQ_ID_LEN     AIGW_CACHE_KEY_MAX_LEN
#define MAX_JSON_STR_LEN   AIGW_CACHE_VALUE_MAX_LEN
#define HASH_MAP_SIZE      1024  // Size of the hash table (simulated large array)

// djb2 hash algorithm constants
#define DJB2_INIT_HASH     5381
#define DJB2_SHIFT_BITS    5

// Entry states for linear probing
#define STATE_EMPTY    0
#define STATE_OCCUPIED 1
#define STATE_DELETED  2

#define TEST_KV_COUNT 2

// Structure to store key-value pair for inner map (request ID -> JSON string)
typedef struct {
    char req_id[MAX_REQ_ID_LEN];
    char json_value[MAX_JSON_STR_LEN];
    int state;  // STATE_EMPTY, STATE_OCCUPIED, STATE_DELETED
} InnerEntry;

// Structure for outer map entry: model name -> array of inner entries
typedef struct {
    char model_name[MAX_MODEL_NAME_LEN];
    InnerEntry inner_map[HASH_MAP_SIZE];  // Simulated "map" for request load info
    int in_use;  // Flag to indicate if this model entry is used
    pthread_rwlock_t lock;  // Read-write lock for concurrent access to this model
} OuterEntry;

// Global hash map (array) to simulate outer map: modelName -> inner map
static OuterEntry global_hash_map[HASH_MAP_SIZE];

// Mutex to protect access to the global array (for model insertion/removal)
static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

// Hash function for strings (djb2 algorithm)
static unsigned int hash_string(const char* str)
{
    unsigned int hash = DJB2_INIT_HASH;
    int c;
    while ((c = *str++)) {
        hash = ((hash << DJB2_SHIFT_BITS) + hash) + c; // hash * 33 + c
    }
    return hash % HASH_MAP_SIZE;
}

// Initialize a freshly-claimed outer entry for the given model name.
static void init_outer_entry(OuterEntry *entry, const char *model_name)
{
    strncpy(entry->model_name, model_name, MAX_MODEL_NAME_LEN - 1);
    entry->model_name[MAX_MODEL_NAME_LEN - 1] = '\0';
    memset(entry->inner_map, 0, sizeof(entry->inner_map)); // state=0
    entry->in_use = 1;
    pthread_rwlock_init(&entry->lock, NULL);
}

/**
 * Find or create an outer entry for the given model name.
 * Returns a pointer to the OuterEntry, or NULL if failed (e.g., table full).
 */
OuterEntry* get_or_create_outer_entry(const char* model_name)
{
    if (!model_name) {
        return NULL;
    }

    unsigned int start_index = hash_string(model_name);
    unsigned int index = start_index;
    OuterEntry* first_free = NULL;
    int full_scan_done = 0;

    pthread_mutex_lock(&global_mutex);
    CACHE_DEBUG("Trying to get or create model: %s", model_name);

    do {
        OuterEntry* entry = &global_hash_map[index];

        if (!entry->in_use) {
            if (!first_free) {
                first_free = entry;
            }
        } else if (strcmp(entry->model_name, model_name) == 0) {
            CACHE_DEBUG("Found existing model: %s", model_name);
            pthread_mutex_unlock(&global_mutex);
            return entry;
        }

        index = (index + 1) % HASH_MAP_SIZE;
        if (index == start_index) {
            full_scan_done = 1;
        }
    } while (!full_scan_done);

    if (first_free) {
        init_outer_entry(first_free, model_name);
        CACHE_DEBUG("Created new model entry: %s", model_name);
        pthread_mutex_unlock(&global_mutex);
        return first_free;
    }

    CACHE_DEBUG("Hash table full, cannot create model: %s", model_name);
    pthread_mutex_unlock(&global_mutex);
    return NULL;
}

/**
 * Get the outer entry for a model name (without creating it).
 * Returns pointer to OuterEntry or NULL if not found.
 */
OuterEntry* get_outer_entry(const char* model_name)
{
    if (!model_name) {
        return NULL;
    }

    unsigned int start = hash_string(model_name);
    unsigned int i = start;
    do {
        OuterEntry* entry = &global_hash_map[i];
        if (!entry->in_use) {
            CACHE_DEBUG("Model not found: %s (empty slot at %u)", model_name, i);
            return NULL;
        }
        if (strcmp(entry->model_name, model_name) == 0) {
            CACHE_DEBUG("Found model: %s at index %u", model_name, i);
            return entry;
        }
        i = (i + 1) % HASH_MAP_SIZE;
    } while (i != start);
    CACHE_DEBUG("Model not found: %s (full scan)", model_name);
    return NULL;
}

// Count occupied slots in an outer entry's inner map.
static int count_occupied(const OuterEntry *outer)
{
    int count = 0;
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        if (outer->inner_map[i].state == STATE_OCCUPIED) {
            count++;
        }
    }
    return count;
}

// Copy occupied entries from outer->inner_map into the pairs array.
static void copy_occupied_entries(const OuterEntry *outer, key_value_pair_t *pairs)
{
    int idx = 0;
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        const InnerEntry* entry = &outer->inner_map[i];
        if (entry->state != STATE_OCCUPIED) {
            continue;
        }
        key_value_pair_t *kv = &pairs[idx++];
        strncpy(kv->key, entry->req_id, AIGW_CACHE_KEY_MAX_LEN - 1);
        kv->key[AIGW_CACHE_KEY_MAX_LEN - 1] = '\0';
        strncpy(kv->value, entry->json_value, AIGW_CACHE_VALUE_MAX_LEN - 1);
        kv->value[AIGW_CACHE_VALUE_MAX_LEN - 1] = '\0';
    }
}

/**
 * Mock function: Retrieves all fields and values from a hash stored at the given key.
 */
static aigw_error_t simple_cache_hash_get_all(const char *model_name, key_value_array_t *out_array)
{
    if (model_name == NULL || out_array == NULL) {
        CACHE_DEBUG("Invalid parameter: model_name=%p, out_array=%p", model_name, out_array);
        return AIGW_ERR_INVALID_PARAM;
    }

    OuterEntry* outer = get_outer_entry(model_name);
    if (!outer) {
        out_array->pairs = NULL;
        out_array->count = 0;
        CACHE_DEBUG("Model not found: %s", model_name);
        return AIGW_ERR_NOT_FOUND;
    }

    pthread_rwlock_rdlock(&outer->lock);
    CACHE_DEBUG("Reading hash for model: %s", model_name);

    int count = count_occupied(outer);
    if (count == 0) {
        out_array->pairs = NULL;
        out_array->count = 0;
        pthread_rwlock_unlock(&outer->lock);
        CACHE_DEBUG("Hash is empty for model: %s", model_name);
        return AIGW_SUCCESS;
    }
    if (count < 0 || count > HASH_MAP_SIZE) {
        // Defensive bound: count_occupied scans HASH_MAP_SIZE slots, so count
        // must lie in [0, HASH_MAP_SIZE]. Anything else is corrupt state.
        pthread_rwlock_unlock(&outer->lock);
        out_array->pairs = NULL;
        out_array->count = 0;
        CACHE_DEBUG("Invalid occupied count %d for model: %s", count, model_name);
        return AIGW_ERR_INTERNAL;
    }

    out_array->pairs = (key_value_pair_t*)malloc((size_t)count * sizeof(key_value_pair_t));
    if (!out_array->pairs) {
        pthread_rwlock_unlock(&outer->lock);
        out_array->count = 0;
        CACHE_DEBUG("Memory allocation failed for %d pairs", count);
        return AIGW_ERR_NO_MEMORY;
    }

    copy_occupied_entries(outer, out_array->pairs);
    out_array->count = count;
    pthread_rwlock_unlock(&outer->lock);
    CACHE_DEBUG("Retrieved %d entries for model: %s", count, model_name);
    return AIGW_SUCCESS;
}

// Try to insert one (req_id, json_value) into outer->inner_map. On success returns
// the slot index via *out_index and AIGW_SUCCESS; AIGW_ERR_NO_SPACE if no slot.
static aigw_error_t insert_one_field(OuterEntry *outer, const char *req_id,
                                     const char *json_value, int *out_index)
{
    unsigned int start_index = hash_string(req_id);
    unsigned int index = start_index;

    do {
        InnerEntry* entry = &outer->inner_map[index];
        if (entry->state == STATE_EMPTY || entry->state == STATE_DELETED ||
            strcmp(entry->req_id, req_id) == 0) {
            strncpy(entry->req_id, req_id, MAX_REQ_ID_LEN - 1);
            entry->req_id[MAX_REQ_ID_LEN - 1] = '\0';
            strncpy(entry->json_value, json_value, MAX_JSON_STR_LEN - 1);
            entry->json_value[MAX_JSON_STR_LEN - 1] = '\0';
            entry->state = STATE_OCCUPIED;
            *out_index = (int)index;
            return AIGW_SUCCESS;
        }
        index = (index + 1) % HASH_MAP_SIZE;
    } while (index != start_index);

    return AIGW_ERR_NO_SPACE;
}

// Roll back inner_map mutations recorded in touched_indices[0..touched_count-1].
static void rollback_inserts(OuterEntry *outer, const int *touched_indices, int touched_count)
{
    for (int i = 0; i < touched_count; i++) {
        outer->inner_map[touched_indices[i]].state = STATE_DELETED;
    }
}

/**
 * Mock function: Set multiple fields in the hash (set request load info for a model).
 */
static aigw_error_t simple_cache_hash_set_fields(const char *model_name, const key_value_array_t *fields)
{
    if (model_name == NULL || fields == NULL) {
        CACHE_DEBUG("Invalid parameter: model_name=%p, fields=%p", model_name, fields);
        return AIGW_ERR_INVALID_PARAM;
    }

    if (fields->count > HASH_MAP_SIZE) {
        CACHE_DEBUG("Field count %d exceeds hash size", fields->count);
        return AIGW_ERR_INVALID_PARAM;
    }

    OuterEntry* outer = get_or_create_outer_entry(model_name);
    if (outer == NULL) {
        CACHE_DEBUG("No space to create model: %s", model_name);
        return AIGW_ERR_NO_SPACE;
    }

    int *touched_indices = malloc(fields->count * sizeof(int));
    if (!touched_indices) {
        return AIGW_ERR_NO_MEMORY;
    }
    int touched_count = 0;
    int rollback_required = 0;

    pthread_rwlock_wrlock(&outer->lock);
    CACHE_DEBUG("Setting %d fields for model: %s", fields->count, model_name);

    for (int f = 0; f < fields->count; f++) {
        const char *req_id = fields->pairs[f].key;
        const char *json_value = fields->pairs[f].value;

        if (req_id == NULL || json_value == NULL) {
            rollback_required = 1;
            break;
        }

        int slot_index = -1;
        if (insert_one_field(outer, req_id, json_value, &slot_index) != AIGW_SUCCESS) {
            rollback_required = 1;
            break;
        }
        touched_indices[touched_count++] = slot_index;
    }

    if (rollback_required) {
        rollback_inserts(outer, touched_indices, touched_count);
        pthread_rwlock_unlock(&outer->lock);
        free(touched_indices);
        CACHE_DEBUG("Set failed, rolled back");
        return AIGW_ERR_NO_SPACE;
    }

    pthread_rwlock_unlock(&outer->lock);
    free(touched_indices);
    CACHE_DEBUG("Set success for %d fields", fields->count);
    return AIGW_SUCCESS;
}

// Locate the inner_map slot that holds req_id. Returns AIGW_SUCCESS on hit (with
// slot index in *out_index), AIGW_ERR_NOT_FOUND on miss.
static aigw_error_t locate_field(const OuterEntry *outer, const char *req_id, int *out_index)
{
    unsigned int start_index = hash_string(req_id);
    unsigned int index = start_index;

    do {
        const InnerEntry* entry = &outer->inner_map[index];
        if (entry->state == STATE_EMPTY) {
            // Stop probing: insertion would have used this slot.
            return AIGW_ERR_NOT_FOUND;
        }
        if (entry->state == STATE_OCCUPIED && strcmp(entry->req_id, req_id) == 0) {
            *out_index = (int)index;
            return AIGW_SUCCESS;
        }
        index = (index + 1) % HASH_MAP_SIZE;
    } while (index != start_index);

    return AIGW_ERR_NOT_FOUND;
}

/**
 * Mock function: Deletes multiple fields from a hash atomically.
 */
static aigw_error_t simple_cache_hash_delete_fields(const char *model_name, char **field_keys, uint32_t field_count)
{
    if (model_name == NULL || field_keys == NULL || field_count == 0) {
        CACHE_DEBUG("Invalid parameter: model_name=%p, field_keys=%p, count=%d", model_name, field_keys, field_count);
        return AIGW_ERR_INVALID_PARAM;
    }

    if (field_count > HASH_MAP_SIZE) {
        CACHE_DEBUG("Field count %d exceeds hash size", field_count);
        return AIGW_ERR_INVALID_PARAM;
    }

    OuterEntry* outer = get_outer_entry(model_name);
    if (outer == NULL) {
        CACHE_DEBUG("Model not found: %s", model_name);
        return AIGW_ERR_NOT_FOUND;
    }

    int *indices_to_delete = malloc(field_count * sizeof(int));
    if (!indices_to_delete) {
        return AIGW_ERR_NO_MEMORY;
    }
    int found_count = 0;

    pthread_rwlock_wrlock(&outer->lock);
    CACHE_DEBUG("Deleting %d fields from model: %s", field_count, model_name);

    aigw_error_t scan_err = AIGW_SUCCESS;
    for (uint32_t i = 0; i < field_count; i++) {
        const char *req_id = field_keys[i];
        if (req_id == NULL) {
            scan_err = AIGW_ERR_INVALID_PARAM;
            break;
        }
        int slot_index = -1;
        aigw_error_t err = locate_field(outer, req_id, &slot_index);
        if (err != AIGW_SUCCESS) {
            CACHE_DEBUG("Delete failed: key not found: %s", req_id);
            scan_err = err;
            break;
        }
        indices_to_delete[found_count++] = slot_index;
    }

    if (scan_err != AIGW_SUCCESS) {
        pthread_rwlock_unlock(&outer->lock);
        free(indices_to_delete);
        return scan_err;
    }

    for (int i = 0; i < found_count; i++) {
        outer->inner_map[indices_to_delete[i]].state = STATE_DELETED;
    }

    pthread_rwlock_unlock(&outer->lock);
    free(indices_to_delete);
    CACHE_DEBUG("Deleted %d fields", found_count);
    return AIGW_SUCCESS;
}

// Free already-populated entries in out_arrays[0..n-1] on batch failure.
static void free_partial_out_arrays(key_value_array_t *out_arrays, uint32_t n)
{
    for (uint32_t j = 0; j < n; j++) {
        if (out_arrays[j].pairs) {
            free(out_arrays[j].pairs);
            out_arrays[j].pairs = NULL;
            out_arrays[j].count = 0;
        }
    }
}

/**
 * Mock function: Batch retrieves all fields and values from multiple hashes.
 */
static aigw_error_t simple_cache_hash_get_all_batch(const char **keys, uint32_t key_count,
                                                    key_value_array_t *out_arrays)
{
    // Parameter validation
    if (!keys || key_count == 0 || !out_arrays) {
        CACHE_DEBUG("Invalid parameter: keys=%p, key_count=%u, out_arrays=%p",
                   keys, key_count, out_arrays);
        return AIGW_ERR_INVALID_PARAM;
    }

    // Verify that all keys are not empty
    for (uint32_t i = 0; i < key_count; i++) {
        if (!keys[i]) {
            CACHE_DEBUG("Key at index %u is NULL", i);
            return AIGW_ERR_INVALID_PARAM;
        }
    }

    // Traverse each key and call simple_cache_hash_get_all to get the results
    for (uint32_t i = 0; i < key_count; i++) {
        aigw_error_t err = simple_cache_hash_get_all(keys[i], &out_arrays[i]);
        if (err != AIGW_SUCCESS && err != AIGW_ERR_NOT_FOUND) {
            free_partial_out_arrays(out_arrays, i);
            CACHE_DEBUG("Failed to get hash for key %s: %d", keys[i], err);
            return err;
        }
    }

    CACHE_DEBUG("Retrieved %u hashes", key_count);
    return AIGW_SUCCESS;
}

/**
 * Optional: Cleanup function to destroy locks (call at program exit)
 */
static void simple_cache_cleanup(void)
{
    pthread_mutex_lock(&global_mutex);
    for (int i = 0; i < HASH_MAP_SIZE; i++) {
        if (global_hash_map[i].in_use) {
            pthread_rwlock_destroy(&global_hash_map[i].lock);
            global_hash_map[i].in_use = 0;
        }
    }
    pthread_mutex_unlock(&global_mutex);
    pthread_mutex_destroy(&global_mutex);
    CACHE_DEBUG("Cleanup completed");
}

static aigw_cache_driver_t simple_redis_cache = {
    .driver_name = "simple_redis_cache",
    .ops = {
        .hash_get_all = simple_cache_hash_get_all,
        .hash_set_fields = simple_cache_hash_set_fields,
        .hash_delete_fields = simple_cache_hash_delete_fields,
        .hash_get_all_batch = simple_cache_hash_get_all_batch,
    },
};

aigw_cache_driver_t *get_simple_cache_driver(void)
{
    return &simple_redis_cache;
}

// Populate the two test key/value pairs used by test_simple_cache().
static void fill_test_kv_pairs(key_value_pair_t *kv_pairs)
{
    strncpy(kv_pairs[0].key, "req1", sizeof(kv_pairs[0].key) - 1);
    strncpy(kv_pairs[0].value,
        "{\"timeStamp\": 123, \"promptLength\": 10, \"predictPrefillTime\": 50, "
        "\"prefill_instanceId\": \"prefill1\", \"decode_instanceId\": \"decode1\", \"beginInferTime\": 130}",
        sizeof(kv_pairs[0].value) - 1);

    strncpy(kv_pairs[1].key, "req2", sizeof(kv_pairs[1].key) - 1);
    strncpy(kv_pairs[1].value,
        "{\"timeStamp\": 125, \"promptLength\": 15, \"predictPrefillTime\": 60, "
        "\"prefill_instanceId\": \"prefill2\", \"decode_instanceId\": \"decode2\", \"beginInferTime\": 135}",
        sizeof(kv_pairs[1].value) - 1);
}

static void print_kv_array(const char *prefix, const key_value_array_t *arr)
{
    printf("%s, got %d entries:\n", prefix, arr->count);
    for (int i = 0; i < arr->count; i++) {
        printf("Key: %s, Value: %s\n", arr->pairs[i].key, arr->pairs[i].value);
    }
}

// Test function
aigw_error_t test_simple_cache(void)
{
    key_value_pair_t kv_pairs[TEST_KV_COUNT] = {0};
    fill_test_kv_pairs(kv_pairs);

    key_value_array_t fields = {
        .pairs = kv_pairs,
        .count = TEST_KV_COUNT
    };

    aigw_error_t err = simple_cache_hash_set_fields("gpt-3", &fields);
    if (err != AIGW_SUCCESS) {
        printf("Set failed: %d\n", err);
        return err;
    }

    key_value_array_t result = {0};
    err = simple_cache_hash_get_all("gpt-3", &result);
    if (err != AIGW_SUCCESS && err != AIGW_ERR_NOT_FOUND) {
        printf("Get all failed: %d\n", err);
        return err;
    }
    print_kv_array("After set", &result);

    char *del_keys[] = { "req1" };
    err = simple_cache_hash_delete_fields("gpt-3", del_keys, 1);
    if (err != AIGW_SUCCESS) {
        printf("Delete failed: %d\n", err);
        free(result.pairs);
        return err;
    }

    key_value_array_t result2 = {0};
    err = simple_cache_hash_get_all("gpt-3", &result2);
    print_kv_array("After delete", &result2);

    if (result.pairs) {
        free(result.pairs);
    }
    if (result2.pairs) {
        free(result2.pairs);
    }

    if (result2.count == 1) {
        printf("Test simple_cache successfully\n");
        return AIGW_SUCCESS;
    }
    return AIGW_ERR_INTERNAL;
}

/* this function will be automatically called before main */
void __attribute__((constructor)) simple_cache_before_main(void)
{
    memset(global_hash_map, 0, sizeof(global_hash_map));
    CACHE_DEBUG("Global hash map initialized");
}

/* this function will be automatically called after main */
void __attribute__((destructor)) simple_cache_after_main(void)
{
    simple_cache_cleanup();
}
