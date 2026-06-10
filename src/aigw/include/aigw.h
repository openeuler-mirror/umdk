/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * @file aigw.h
 * @brief AI Gateway (AIGW) C API for inference routing, load balancing, and cache integration.
 *
 * This header defines a pluggable, thread-safe interface for:
 * - Request routing with load balancing
 * - Node selection based on role and capacity
 * - Event notification (monitoring/tracing)
 * - Distributed cache backend abstraction (e.g., Redis)
 *
 * Note: For compatibility with Go CGO, input pointer parameters are not marked 'const',
 *       even though they are treated as read-only within the implementation.
 *
 * @create 2026-01-19
 */

#ifndef AIGW_H
#define AIGW_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ========================================================================================
// Configuration and String Length Limits
// ========================================================================================

/**
 * @def AIGW_ERR_DESC_MAX_LEN
 * @brief Maximum length of error description string.
 */
#define AIGW_ERR_DESC_MAX_LEN         256

/**
 * @def AIGW_ADDR_MAX_LEN
 * @brief Maximum length of node address string (e.g., "192.168.1.1:8080").
 */
#define AIGW_ADDR_MAX_LEN             256

/**
 * @def AIGW_CACHE_KEY_MAX_LEN
 * @brief Maximum length (in bytes) of a cache key string, including null terminator.
 */
#define AIGW_CACHE_KEY_MAX_LEN        128

/**
 * @def AIGW_CACHE_VALUE_MAX_LEN
 * @brief Maximum length (in bytes) of a cache value string, including null terminator.
 */
#define AIGW_CACHE_VALUE_MAX_LEN      1024

// ========================================================================================
// Error Codes
// ========================================================================================

/**
 * @enum aigw_error_t
 * @brief Standard error codes returned by AIGW APIs.
 */
typedef enum {
    AIGW_SUCCESS            =  0,  ///< Operation succeeded.
    AIGW_ERR_INVALID_PARAM  = -1,  ///< Invalid input parameter (e.g., NULL pointer, out of range).
    AIGW_ERR_TIMEOUT        = -2,  ///< Operation timed out.
    AIGW_ERR_NOT_FOUND      = -3,  ///< Requested resource not found.
    AIGW_ERR_NO_MEMORY      = -4,  ///< Memory allocation failed.
    AIGW_ERR_INTERNAL       = -5,  ///< Internal error in AIGW component.
    AIGW_ERR_NO_SPACE       = -6,  ///< No space to hold data.
    AIGW_ERR_COMP_NOT_INIT  = -7,  ///< Component is not initialized.
    AIGW_ERR_INVALID_STATE  = -8,  ///< Invalid state in AIGW component.
} aigw_error_t;

// ========================================================================================
// Component Configuration
// ========================================================================================

/**
 * @struct aigw_config_t
 * @brief Configuration for initializing the AIGW component.
 */
typedef struct {
    const char *log_level; /**< Log level ("trace", "debug", "info", "warn", "warning", "error", "fatal", "panic"). */
    const char *log_path;  /**< Log output file path. */

    int32_t max_instances_per_model;    /**< Maximum number of inference instances allowed per model (> 0). */
    int32_t max_supported_models;       /**< Maximum number of models the system supports (> 0). */

    int32_t max_prompt_length;          /**< Maximum allowed length of input prompt in characters (> 0). */
    int32_t request_ttl_seconds;        /**< Time-to-live for each request in seconds (> 0). */
} aigw_config_t;

/**
 * @brief Initialize the AIGW component with the given configuration.
 *
 * This function must be called before any other AIGW API.
 * It is not thread-safe and should be called once during startup.
 *
 * @param[in] cfg Pointer to a valid aigw_config_t structure. Must not be NULL.
 *                The configuration is copied internally; the caller retains ownership.
 *                The memory must remain valid during the call.
 * @return AIGW_SUCCESS on success, or appropriate error code.
 *
 * @note If initialization fails, subsequent API calls may have undefined behavior.
 */
aigw_error_t aigw_init(aigw_config_t *cfg);

/**
 * @brief Uninitialize and release resources held by the AIGW component.
 *
 * This function should be called during shutdown.
 * It is not thread-safe and should be called once.
 *
 * @note No API should be called after uninitialization.
 */
void aigw_uninit(void);

// ========================================================================================
// Message and Request Structures
// ========================================================================================

/**
 * @struct aigw_openai_message_t
 * @brief Represents a single message in an OpenAI-style chat request.
 *
 * Example roles: "user", "assistant", "system".
 * The `content` pointer must remain valid during API calls that use this struct.
 */
typedef struct {
    const char *role;           /**< Role of sender (e.g., "user", "assistant"); read-only */
    const char *content;        /**< Message content; caller manages lifetime */
} aigw_openai_message_t;

/**
 * @struct aigw_request_t
 * @brief Represents an AI inference request.
 */
typedef struct {
    const char *uuid;                    /**< Unique request ID (UUID string) */
    const char *model;                   /**< Target model name */
    const aigw_openai_message_t *messages; /**< Array of conversation messages */
    uint32_t message_num;                /**< Number of messages */
} aigw_request_t;

// ========================================================================================
// Load Balancing and Node Selection
// ========================================================================================

/**
 * @enum aigw_infer_role_type_t
 * @brief Role of an inference node in processing a request.
 */
typedef enum {
    AIGW_INFER_MIXED   = 0,  ///< Node handles both prefill and decode.
    AIGW_INFER_PREFILL,      ///< Node specializes in prefill phase.
    AIGW_INFER_DECODE,       ///< Node specializes in decode phase.
} aigw_infer_role_type_t;

/**
 * @struct aigw_node_info_t
 * @brief Information about an inference node.
 */
typedef struct {
    aigw_infer_role_type_t role;     /**< Node's inference role (prefill/decode/mixed) */
    const char *node_addr;           /**< Node address (e.g., "ip:port"); read-only */
    const char *group_id;            /**< Group ID for routing and scaling; read-only */
} aigw_node_info_t;

/**
 * @struct aigw_select_context_t
 * @brief Context for node selection, including load balancing strategy and node list.
 */
typedef struct {
    uint32_t node_num;                   /**< Number of nodes in node_list */
    const aigw_node_info_t *node_list;   /**< Array of candidate nodes */
} aigw_select_context_t;

/**
 * @struct aigw_select_result_t
 * @brief Result of node selection for a request.
 */
typedef struct {
    char prefill_node_addr[AIGW_ADDR_MAX_LEN]; /**< Output: selected prefill node address; empty if none */
    char decode_node_addr[AIGW_ADDR_MAX_LEN];  /**< Output: selected decode node address; empty if none */
    char error_desc[AIGW_ERR_DESC_MAX_LEN];    /**< Output: error description if failed */
} aigw_select_result_t;

/**
 * @brief Select appropriate nodes for processing the given request.
 *
 * This function selects prefill and decode nodes based on the request and context.
 *
 * @param[in]  req        Pointer to the inference request. Must not be NULL.
 *                        The request data is read-only and will not be modified.
 *                        Must remain valid during the call.
 * @param[in]  ctx        Pointer to the selection context containing candidate nodes. Must not be NULL.
 *                        The context data is read-only and will not be modified.
 *                        Must remain valid during the call.
 * @param[out] out_result Pointer to a pre-allocated result structure.
 *                        Will be filled with selected node addresses or error details.
 *                        Must not be NULL.
 * @return AIGW_SUCCESS if node selection succeeded,
 *         AIGW_ERR_INVALID_PARAM if input is invalid,
 *         AIGW_ERR_NOT_FOUND if no suitable node found,
 *         or another error code.
 *
 * @note All input parameters are logically 'const' (read-only).
 *       'const' is omitted in function signature to maintain compatibility with Go CGO.
 *       The caller owns all input and output memory.
 */
aigw_error_t aigw_select_nodes(aigw_request_t *req, aigw_select_context_t *ctx,
                               aigw_select_result_t *out_result);

// ========================================================================================
// Event Notification
// ========================================================================================

/**
 * @enum aigw_event_type_t
 * @brief Types of events that can be notified.
 */
typedef enum {
    AIGW_EVENT_REQUEST = 0,  ///< Request-level event.
} aigw_event_type_t;

/**
 * @struct aigw_event_info_t
 * @brief Represents an event related to a request.
 */
typedef struct {
    const char *model;        /**< Model associated with the event; read-only */
    const char *request_id;   /**< Request UUID; read-only */
    const char *event_name;   /**< Event name (e.g., "KVC_GENERATED"); read-only */
} aigw_event_info_t;

/**
 * @brief Notify the system of a specific event.
 *
 * Used for logging, monitoring, metrics collection, or triggering side effects.
 *
 * @param[in] event_type Type of event.
 * @param[in] event      Pointer to event data structure. Must not be NULL.
 *                       The content is read-only and will not be modified.
 *                       Must remain valid during the call.
 * @return AIGW_SUCCESS if notification was accepted, or error code.
 *
 * @note This function is thread-safe.
 */
aigw_error_t aigw_notify_event(aigw_event_type_t event_type, aigw_event_info_t *event);

// ========================================================================================
// Cache Interface
// ========================================================================================

/**
 * @struct key_value_pair_t
 * @brief Represents a single key-value pair with string buffers.
 */
typedef struct {
    char key[AIGW_CACHE_KEY_MAX_LEN];     ///< Null-terminated key string.
    char value[AIGW_CACHE_VALUE_MAX_LEN]; ///< Null-terminated value string.
} key_value_pair_t;

/**
 * @struct key_value_array_t
 * @brief Dynamic array of key-value pairs.
 *
 * @note
 * - ttl is ignored on update operations — only the initial creation sets the expiration.
 * - The driver allocates memory for `pairs` using malloc (or equivalent).
 *   The caller **must** call `free(pairs)` and then `free(array)` if allocated.
 */
typedef struct {
    key_value_pair_t *pairs; ///< Dynamically allocated array of key-value pairs.
    int count;               ///< Number of valid entries in 'pairs'.

    int32_t ttl; ///< Time-to-live (TTL) for the Redis key in seconds (0 = no expiry).
                 ///< Only applied when the key is first created; ignored during updates.
                 ///< Immutable once set. Used only in set operations.
} key_value_array_t;

/**
 * @struct aigw_cache_driver_ops_t
 * @brief Function pointer interface for cache backend operations.
 *
 * Defines a pluggable driver interface for interacting with distributed cache systems
 * (e.g., Redis, DCS). Supports hash-based operations commonly used in metric caching
 * and coordination scenarios.
 *
 * Example usage:
 * - hash_get_all: Retrieve model status or node metrics
 * - hash_set_fields: Update node load or request counters
 * - hash_delete_fields: Clean up stale request entries
 */
typedef struct {
    /**
     * @brief Retrieves all fields and values from a hash stored at the given key.
     *
     * If the key does not exist, `out_array->pairs` will be NULL and `out_array->count = 0`.
     *
     * @note The driver allocates memory for `out_array->pairs` using malloc (or equivalent).
     *       The caller **must** call `free(out_array->pairs)` to release it.
     *
     * @param[in]  key        The hash key. Must be non-NULL and null-terminated.
     * @param[out] out_array  Pointer to a pre-allocated key_value_array_t to receive the result.
     *                        On success, this will point to an allocated array of pairs.
     * @return AIGW_SUCCESS if the operation was accepted (even if key doesn't exist),
     *         or an appropriate error code on communication/backend failure.
     */
    aigw_error_t (*hash_get_all)(const char *key, key_value_array_t *out_array);

    /**
     * @brief Retrieves all fields and values from multiple hashes atomically.
     *
     * Performs batch retrieval of hash data for multiple keys in a single operation.
     * This is more efficient than calling hash_get_all multiple times for each key.
     *
     * @param[in]  keys         Array of hash keys to retrieve. Must be non-NULL with valid strings.
     * @param[in]  key_count    Number of keys in the keys array. Must be > 0.
     * @param[out] out_arrays   Pre-allocated array of key_value_array_t (size: key_count).
     *                          The caller allocates this array before calling this function.
     *                          Each element will be filled with the result for corresponding key.
     * @return AIGW_SUCCESS if the operation was accepted,
     *         or an appropriate error code on communication/backend failure.
     *
     * @note The driver allocates memory for each `out_arrays[i].pairs` using malloc.
     *       The caller **must** call `free(out_arrays[i].pairs)` for each valid array.
     *       If a key does not exist, the corresponding array will have `count = 0` and `pairs = NULL`.
     */
    aigw_error_t (*hash_get_all_batch)(const char **keys, uint32_t key_count, key_value_array_t *out_arrays);

    /**
     * @brief Sets multiple fields in a hash atomically.
     *
     * Sets the specified fields to their corresponding values in the hash stored at `key`.
     * The operation is atomic: either all field updates succeed, or none do.
     * Creates the hash if it does not exist.
     *
     * @param[in] key     The hash key. Must be non-NULL and null-terminated.
     * @param[in] fields  Array of key_value_pair_t containing field names and values to set.
     *                    Must have `fields->count > 0` and valid strings.
     * @return AIGW_SUCCESS on full success; otherwise, an error code indicating failure.
     *         On error, no fields are modified (atomic guarantee).
     */
    aigw_error_t (*hash_set_fields)(const char *key, const key_value_array_t *fields);

    /**
     * @brief Deletes multiple fields from a hash atomically.
     *
     * Removes the specified fields from the hash stored at `key`.
     * The operation is atomic: either all deletions succeed, or none do.
     * Non-existent fields are treated as success.
     *
     * @param[in] key         The hash key. Must be non-NULL and null-terminated.
     * @param[in] field_keys  Array of C-strings (field names) to delete. Each must be null-terminated.
     * @param[in] field_count Number of field names in field_keys.
     * @return AIGW_SUCCESS if all deletions were processed successfully,
     *         or an error code if the atomic operation failed (e.g., network error).
     *         On error, no fields are deleted.
     */
    aigw_error_t (*hash_delete_fields)(const char *key, char **field_keys, uint32_t field_count);
} aigw_cache_driver_ops_t;

/**
 * @struct aigw_cache_driver_t
 * @brief Driver interface for cache backend.
 */
typedef struct {
    const char *driver_name;           /**< Name of the driver (e.g., "redis", "dcs"); read-only */
    aigw_cache_driver_ops_t ops;       /**< Function pointers for backend operations */
} aigw_cache_driver_t;

/**
 * @brief Register a cache driver.
 *
 * Installs a backend driver for cache operations (e.g., Redis, DCS). Only one driver
 * can be registered at a time.
 *
 * @param[in] driver Pointer to a valid aigw_cache_driver_t structure. Must not be NULL.
 *                   The structure is copied internally; the caller retains ownership.
 *                   The content will not be modified during the call.
 * @return AIGW_SUCCESS on success, or error code.
 */
aigw_error_t aigw_register_cache_driver(aigw_cache_driver_t *driver);

/**
 * @brief Unregister the currently registered cache driver.
 *
 * Releases resources associated with the current driver. If no driver is registered,
 * this function returns error.
 *
 * @return AIGW_SUCCESS on success, or error code.
 */
aigw_error_t aigw_unregister_cache_driver(void);

// ========================================================================================
// Model management
// ========================================================================================

/**
 * @enum aigw_lb_type_t
 * @brief Supported load balancing strategies for node selection.
 */
typedef enum {
    AIGW_LB_NONE = 0,
    AIGW_LB_TOKEN_AWARE,             ///< Select node based on available capacity, such as GPU memory.
    AIGW_LB_PREFILL_TIME_AWARE,      ///< Select node with the least processing time for faster response.
} aigw_lb_type_t;

typedef enum {
    AIGW_DEPLOY_SEPARATED = 0,
} aigw_deploy_policy_t;

/**
 * @struct aigw_model_config_t
 * @brief Configuration structure for model registration.
 */
typedef struct {
    const char *model;                                  /**< Target model name */
    aigw_deploy_policy_t deploy_policy;                 /**< Deployment policy for inference instance */
    aigw_lb_type_t p_lb_type;                           /**< Load balancing algorithm type for prefill */
    aigw_lb_type_t d_lb_type;                           /**< Load balancing algorithm type for decode */
    const char *pretrain_ttft_path;                     /**< Pretrain ttft path used by AIGW_LB_PREFILL_TIME_AWARE */

    uint32_t cache_refresh_interval_ms; /**< Cache refresh interval in milliseconds, use default interval if set to 0 */
    double tokenization_ratio;     /**< Ratio of characters to tokens (e.g., 0.5 means 2 chars per token on average). */
} aigw_model_config_t;

/**
 * @brief Register a model configuration.
 *
 * Registers a new model with the AIGW system. The configuration is copied internally;
 * the caller retains ownership of the original structure and can free it after return.
 *
 * @param[in] cfg Pointer to a valid aigw_model_config_t structure. Must not be NULL.
 *                The content of the structure will be read but not modified.
 *                The memory must remain valid during the call.
 *
 * @return AIGW_SUCCESS on success, or appropriate error code.
 *
 * @note This parameter is logically 'const' (read-only), but declared without 'const'
 *       qualifier to ensure compatibility with Go CGO bindings.
 */
aigw_error_t aigw_register_model(aigw_model_config_t *cfg);

/**
 * @brief Unregister a model by name.
 *
 * Removes a previously registered model from the system. If the model is in use,
 * unregistration may fail or be delayed depending on implementation.
 *
 * @param[in] model_name Null-terminated string identifying the model to unregister.
 *                       Must not be NULL. The string content will not be modified.
 *                       The memory must remain valid during the call.
 *
 * @return AIGW_SUCCESS if model was successfully unregistered,
 *         AIGW_ERR_NOT_FOUND if model not registered,
 *         or another error code on failure.
 *
 * @note The 'const' qualifier is omitted for CGO compatibility.
 *       The function treats this string as read-only.
 */
aigw_error_t aigw_unregister_model(char *model_name);

#ifdef __cplusplus
}
#endif

#endif // AIGW_H
