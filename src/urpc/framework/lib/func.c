/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: urpc func
 */
#include <stdatomic.h>
#include "cp.h"
#include "urpc_hmap.h"
#include "urpc_id_generator.h"
#include "urpc_framework_types.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "urpc_framework_api.h"
#include "urpc_dbuf_stat.h"
#include "urpc_hash.h"
#include "func.h"

/*
The urpc function id consists of the device class, subclass, p, and method:
Device Class (12-bit): indicates the functional device class.
Sub Class (12-bit): indicates the sub-type of the functional device.
P[rivate] (1-bit)
0: Method is a fixed public method.
1: Method is a customized method that can be deployed.
Method (23-bit): indicates the uRPC invoking function.

Reserved public Method (P[23] Method[22:0]):
    0000 0000 0000 0000 0000 0000: Querying the Public method Supported by a Device
Reserved customized Method(P[23] Method[22:0]):
    1000 0000 0000 0000 0000 0000: Querying the Customized method Supported by a Device
    1000 0000 0000 0000 0000 0001: Deploying a New Customized method
    1000 0000 0000 0000 0000 0010: Deleting a Deployed Customized method
    1000 0000 0000 0000 0000 0011: Queries a specified Customized method
*/
typedef struct urpc_func_id {
    uint64_t method : 23;
    uint64_t p : 1;
    uint64_t sub_class : 12;
    uint64_t device_class : 12;
} urpc_func_id_t;

#define METHOD_NUM (1 << 23)
#define URPC_FUNC_TABLE_SIZE (1 << 17)
#define METHOD_MIN 4
#define METHOD_PRIVATE 1
#define METHOD_MASK 0x7fffff
#define PRIVATE_MASK 0x800000

typedef struct urpc_func_base_entry {
    struct urpc_hmap_node name_node;
    urpc_handler_info_t info;
    uint64_t func_id;
} urpc_func_base_entry_t;

typedef struct urpc_func_entry {
    struct urpc_hmap_node id_node;
    struct urpc_hmap_node name_node;
    urpc_handler_info_t info;
    uint64_t func_id;
} urpc_func_entry_t;

typedef struct name_id {
    char name[FUNCTION_NAME_LEN];
    uint64_t id;
} name_id_t;

typedef struct urpc_func_info {
    uint8_t version;
    int32_t err_code;
    uint32_t count;
    name_id_t name_map[0];
} urpc_func_info_t;

static struct urpc_hmap g_urpc_func_id_table;
static struct urpc_hmap g_urpc_func_name_table;
static pthread_rwlock_t  g_urpc_func_table_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static urpc_id_generator_t g_urpc_func_id_gen;
static uint64_t g_urpc_func_id_fixed_prefix;
static bool g_urpc_function_initialized;

static inline bool is_private_method(uint64_t func_id)
{
    return func_id & PRIVATE_MASK;
}

static inline bool is_valid_device_class(uint16_t device_class)
{
    urpc_func_id_t *func_id_prefix = (urpc_func_id_t *)(uintptr_t)&g_urpc_func_id_fixed_prefix;
    return device_class == func_id_prefix->device_class;
}

static inline bool is_valid_sub_class(uint16_t sub_class)
{
    urpc_func_id_t *func_id_prefix = (urpc_func_id_t *)(uintptr_t)&g_urpc_func_id_fixed_prefix;
    return sub_class == func_id_prefix->sub_class;
}

static inline bool is_valid_class(uint64_t func_id)
{
    urpc_func_id_t *func_id_prefix = (urpc_func_id_t *)(uintptr_t)&func_id;
    uint16_t device_class = func_id_prefix->device_class;
    uint16_t sub_class = func_id_prefix->sub_class;
    return is_valid_device_class(device_class) && is_valid_sub_class(sub_class);
}

static inline urpc_func_base_entry_t *urpc_client_func_entry_get_by_name(struct urpc_hmap *hmap, const char *name)
{
    uint32_t hash = urpc_hash_string(name, 0);
    urpc_func_base_entry_t *base_entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(base_entry, name_node, hash, hmap) {
        if (strcmp(base_entry->info.name, name) == 0) {
            return base_entry;
        }
    }

    return NULL;
}

// method_id is func id without prefix
static inline urpc_func_entry_t *urpc_server_func_entry_get_by_id(struct urpc_hmap *hmap, uint32_t method_id)
{
    urpc_func_entry_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, id_node, method_id, hmap) {
        if ((entry->func_id & METHOD_MASK) == method_id) {
            return entry;
        }
    }

    return NULL;
}

static inline urpc_func_entry_t *urpc_server_func_entry_get_by_name(struct urpc_hmap *hmap, const char *name)
{
    uint32_t hash = urpc_hash_string(name, 0);
    urpc_func_entry_t *entry = NULL;
    URPC_HMAP_FOR_EACH_WITH_HASH(entry, name_node, hash, hmap) {
        if (strcmp(entry->info.name, name) == 0) {
            return entry;
        }
    }

    return NULL;
}

int urpc_func_exec(uint64_t func_id, urpc_sge_t *args, uint32_t args_sge_num, urpc_sge_t **rsps,
    uint32_t *rsps_sge_num)
{
    uint32_t method_id = func_id & METHOD_MASK;
    if (args == NULL || rsps == NULL || rsps_sge_num == NULL) {
        URPC_LIB_LOG_DEBUG("parameter invalid\n");
        return -URPC_ERR_EINVAL;
    }
    if (!is_private_method(func_id) || !is_valid_class(func_id)) {
        URPC_LIB_LOG_DEBUG("function id [%lu] invalid\n", func_id);
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_rwlock_rdlock(&g_urpc_func_table_rwlock);
    if (!g_urpc_function_initialized) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
         URPC_LIB_LOG_DEBUG("the function module needs to be initialized\n");
        return -1;
    }
    urpc_func_entry_t *entry = urpc_server_func_entry_get_by_id(&g_urpc_func_id_table, method_id);
    if (entry == NULL || entry->info.type != URPC_HANDLER_SYNC || entry->info.sync_handler == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_DEBUG("lookup function[%lu] failed\n", func_id);
        return -1;
    }
    entry->info.sync_handler(args, args_sge_num, entry->info.ctx, rsps, rsps_sge_num);
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    return 0;
}

int urpc_func_async_exec(uint64_t func_id, urpc_sge_t *args, uint32_t args_sge_num, void* req_ctx, uint64_t qh)
{
    uint32_t method_id = func_id & METHOD_MASK;
    if (args == NULL || req_ctx == NULL) {
        URPC_LIB_LOG_DEBUG("parameter invalid\n");
        return -URPC_ERR_EINVAL;
    }
    if (!is_private_method(func_id) || !is_valid_class(func_id)) {
        URPC_LIB_LOG_DEBUG("function id [%lu] invalid\n", func_id);
        return -URPC_ERR_EINVAL;
    }

    (void)pthread_rwlock_rdlock(&g_urpc_func_table_rwlock);
    if (!g_urpc_function_initialized) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
         URPC_LIB_LOG_DEBUG("the function module needs to be initialized\n");
        return -1;
    }
    urpc_func_entry_t *entry = urpc_server_func_entry_get_by_id(&g_urpc_func_id_table, method_id);
    if (entry == NULL || entry->info.type != URPC_HANDLER_ASYNC || entry->info.async_handler == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_DEBUG("lookup function[%lu] failed\n", func_id);
        return -1;
    }
    entry->info.async_handler(args, args_sge_num, entry->info.ctx, req_ctx, qh);
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    return 0;
}

int urpc_func_register(urpc_handler_info_t *info, uint64_t *func_id)
{
    if (info == NULL || func_id == NULL || info->sync_handler == NULL || strnlen(info->name, FUNCTION_NAME_LEN) == 0 ||
        strnlen(info->name, FUNCTION_NAME_LEN) == FUNCTION_NAME_LEN) {
        URPC_LIB_LOG_ERR("parameter invalid\n");
        return -URPC_ERR_EINVAL;
    }
    int ret = urpc_func_init(urpc_device_class_get(), urpc_sub_class_get());
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("func init failed, ret:%d\n", ret);
        return URPC_FAIL;
    }

    *func_id = urpc_func_id_get(URPC_INVALID_ID_U32, info->name);
    if (*func_id != URPC_INVALID_FUNC_ID) {
        URPC_LIB_LOG_INFO("func [%s] is already registered in id[%lu]\n", info->name, *func_id);
        return URPC_SUCCESS;
    }

    uint32_t method_id;
    ret = urpc_id_generator_alloc(&g_urpc_func_id_gen, METHOD_MIN, &method_id);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("get id generator failed\n");
        return ret;
    }
    *func_id = g_urpc_func_id_fixed_prefix | method_id;

    urpc_func_entry_t *entry =
        (urpc_func_entry_t *)urpc_dbuf_calloc(URPC_DBUF_TYPE_FUNC, 1, sizeof(urpc_func_entry_t));
    if (entry == NULL) {
        URPC_LIB_LOG_ERR("malloc function base_entry failed\n");
        urpc_id_generator_free(&g_urpc_func_id_gen, method_id);
        return -URPC_ERR_ENOMEM;
    }

    (void)pthread_rwlock_wrlock(&g_urpc_func_table_rwlock);
    urpc_hmap_insert(&g_urpc_func_id_table, &entry->id_node, method_id);
    urpc_hmap_insert(&g_urpc_func_name_table, &entry->name_node, urpc_hash_string(info->name, 0));
    entry->info = *info;
    entry->func_id = *func_id;
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);

    URPC_LIB_LOG_INFO("register function[%lu] successful\n", *func_id);
    return URPC_SUCCESS;
}

int urpc_func_unregister(uint64_t func_id)
{
    if (!is_valid_class(func_id) || !is_private_method(func_id)) {
        URPC_LIB_LOG_ERR("function id invalid\n");
        return -URPC_ERR_EINVAL;
    }

    uint32_t method_id = func_id & METHOD_MASK;
    (void)pthread_rwlock_wrlock(&g_urpc_func_table_rwlock);
    if (!g_urpc_function_initialized) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_ERR("the function module needs to be initialized\n");
        return URPC_FAIL;
    }

    urpc_func_entry_t *entry = urpc_server_func_entry_get_by_id(&g_urpc_func_id_table, method_id);
    if (entry == NULL) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_ERR("function doesn't exist in hash table\n");
        return URPC_FAIL;
    }

    urpc_id_generator_free(&g_urpc_func_id_gen, method_id);
    urpc_hmap_remove(&g_urpc_func_id_table, &entry->id_node);
    urpc_hmap_remove(&g_urpc_func_name_table, &entry->name_node);
    urpc_dbuf_free(entry);
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    URPC_LIB_LOG_INFO("unregister function[%lu] successful\n", func_id);

    return URPC_SUCCESS;
}

uint64_t urpc_func_id_get(uint32_t urpc_chid, const char *name)
{
    uint64_t func_id = URPC_INVALID_FUNC_ID;
    if (name == NULL) {
        URPC_LIB_LOG_ERR("function name is null\n");
        return func_id;
    }

    // for client
    if (urpc_chid != URPC_INVALID_ID_U32) {
        urpc_channel_info_t *channel = channel_get(urpc_chid);
        if (channel == NULL) {
            URPC_LIB_LOG_ERR("channel not found\n");
            return func_id;
        }

        (void)pthread_rwlock_rdlock(&channel->rw_lock);
        urpc_func_base_entry_t *base_entry = urpc_client_func_entry_get_by_name(&channel->func_tbl, name);
        if (base_entry != NULL) {
            func_id = base_entry->func_id;
        }
        (void)pthread_rwlock_unlock(&channel->rw_lock);

        return func_id;
    }

    // for server
    (void)pthread_rwlock_rdlock(&g_urpc_func_table_rwlock);
    if (!g_urpc_function_initialized) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_ERR("the function module needs to be initialized\n");
        return func_id;
    }

    urpc_func_entry_t *entry = urpc_server_func_entry_get_by_name(&g_urpc_func_name_table, name);
    if (entry != NULL) {
        func_id = entry->func_id;
    }
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    return func_id;
}

int urpc_func_init(uint16_t device_class, uint16_t sub_class)
{
    (void)pthread_rwlock_wrlock(&g_urpc_func_table_rwlock);
    if (g_urpc_function_initialized) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        return 0;
    }
    int ret = urpc_id_generator_init(&g_urpc_func_id_gen, URPC_ID_GENERATOR_TYPE_BITMAP, METHOD_NUM);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("id generator init failed, ret:%d\n", ret);
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        return ret;
    }

    ret = urpc_hmap_init(&g_urpc_func_id_table, URPC_FUNC_TABLE_SIZE);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("hmap init failed, ret:%d\n", ret);
        goto UNINIT_ID_GENERATOR;
    }

    ret = urpc_hmap_init(&g_urpc_func_name_table, URPC_FUNC_TABLE_SIZE);
    if (ret != 0) {
        URPC_LIB_LOG_ERR("hmap init failed, ret:%d\n", ret);
        goto UNINIT_FUNC;
    }

    urpc_func_id_t *func_id = (urpc_func_id_t *)(uintptr_t)&g_urpc_func_id_fixed_prefix;
    func_id->device_class = device_class;
    func_id->sub_class = sub_class;
    func_id->p = METHOD_PRIVATE;
    g_urpc_function_initialized = true;
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    return URPC_SUCCESS;

UNINIT_FUNC:
    urpc_hmap_uninit(&g_urpc_func_id_table);

UNINIT_ID_GENERATOR:
    urpc_id_generator_uninit(&g_urpc_func_id_gen);
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    return ret;
}

void urpc_func_uninit(void)
{
    (void)pthread_rwlock_wrlock(&g_urpc_func_table_rwlock);
    if (!g_urpc_function_initialized) {
        (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_INFO("urpc already uninit function\n");
        return;
    }

    urpc_id_generator_uninit(&g_urpc_func_id_gen);
    urpc_func_entry_t *cur = NULL;
    urpc_func_entry_t *next = NULL;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, id_node, &g_urpc_func_id_table) {
        urpc_hmap_remove(&g_urpc_func_id_table, &cur->id_node);
        urpc_hmap_remove(&g_urpc_func_name_table, &cur->name_node);
        urpc_dbuf_free(cur);
    }
    urpc_hmap_uninit(&g_urpc_func_id_table);
    urpc_hmap_uninit(&g_urpc_func_name_table);
    g_urpc_function_initialized = false;
    (void)pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
}

// used for server to construct send func info
int urpc_func_info_get(void **addr, uint32_t *len)
{
    int ret = URPC_FAIL;
    pthread_rwlock_rdlock(&g_urpc_func_table_rwlock);
    uint32_t func_count = urpc_hmap_count(&g_urpc_func_id_table);
    uint32_t info_size = (uint32_t)(sizeof(urpc_func_info_t) + sizeof(name_id_t) * func_count);
    urpc_func_info_t *info = urpc_dbuf_calloc(URPC_DBUF_TYPE_FUNC, 1, info_size);
    if (info == NULL) {
        pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
        URPC_LIB_LOG_ERR("malloc func info memory failed\n");
        return -URPC_ERR_ENOMEM;
    }

    info->version = 0;
    if (func_count == 0) {
        info->err_code = -URPC_ERR_FUNC_NULL;
        URPC_LIB_LOG_INFO("server register no function\n");
        ret = URPC_SUCCESS;
        goto EXIT;
    }

    uint32_t index = 0;
    urpc_func_entry_t *entry = NULL;
    URPC_HMAP_FOR_EACH(entry, id_node, &g_urpc_func_id_table) {
        info->name_map[index].id = entry->func_id;
        strcpy(info->name_map[index].name, entry->info.name);
        index++;
    }
    pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    info->err_code = 0;
    info->count = index;
    *len = info_size;
    *addr = info;

    return URPC_SUCCESS;

EXIT:
    pthread_rwlock_unlock(&g_urpc_func_table_rwlock);
    info->count = 0;
    *len = (uint32_t)sizeof(urpc_func_info_t);
    *addr = info;
    return ret;
}

// used for client to recv func info
int urpc_func_info_set(struct urpc_hmap *table, uint64_t addr, uint32_t len)
{
    if (len < sizeof(urpc_func_info_t)) {
        URPC_LIB_LOG_ERR("invalid func info len:%u\n", len);
        return URPC_FAIL;
    }

    urpc_func_info_t *info = (urpc_func_info_t *)(uintptr_t)addr;
    uint64_t info_size = (uint64_t)(sizeof(urpc_func_info_t) + sizeof(name_id_t) * info->count);
    if (info_size > UINT32_MAX || info_size != len) {
        URPC_LIB_LOG_ERR("invalid func info len:%lu\n", info_size);
        return URPC_FAIL;
    }

    if (info->version != 0) {
        URPC_LIB_LOG_ERR("unsupported func info version\n");
        return URPC_FAIL;
    }

    if (info->err_code != 0) {
        if (info->err_code == -URPC_ERR_FUNC_NULL) {
            urpc_func_tbl_release(table);
            return URPC_SUCCESS;
        }
        URPC_LIB_LOG_ERR("recv func info error code:%d\n", info->err_code);
        return URPC_FAIL;
    }

    struct urpc_hmap func_tbl;
    int ret = urpc_hmap_init(&func_tbl, info->count);
    if (ret != URPC_SUCCESS) {
        URPC_LIB_LOG_ERR("hmap init failed, ret:%d\n", ret);
        return URPC_FAIL;
    }

    for (uint32_t i = 0; i < info->count; i++) {
        if (strnlen(info->name_map[i].name, FUNCTION_NAME_LEN) == 0 ||
            strnlen(info->name_map[i].name, FUNCTION_NAME_LEN) == FUNCTION_NAME_LEN) {
            URPC_LIB_LOG_ERR("recv invalid function table\n");
            ret = URPC_FAIL;
            break;
        }

        urpc_func_base_entry_t *base_entry = urpc_dbuf_calloc(URPC_DBUF_TYPE_FUNC, 1, sizeof(urpc_func_base_entry_t));
        if (base_entry == NULL) {
            URPC_LIB_LOG_ERR("malloc function base_entry failed\n");
            ret = URPC_FAIL;
            break;
        }
        strcpy(base_entry->info.name, info->name_map[i].name);
        if (urpc_client_func_entry_get_by_name(&func_tbl, info->name_map[i].name) != NULL) {
            urpc_dbuf_free(base_entry);
            URPC_LIB_LOG_ERR("function already exists in hash table\n");
            ret = URPC_FAIL;
            break;
        }

        urpc_hmap_insert(&func_tbl, &base_entry->name_node, urpc_hash_string(info->name_map[i].name, 0));
        base_entry->func_id = info->name_map[i].id;
    }

    if (ret != URPC_SUCCESS) {
        urpc_func_tbl_release(&func_tbl);
        return URPC_FAIL;
    }

    urpc_func_tbl_release(table);
    *table = func_tbl;
    return URPC_SUCCESS;
}

void urpc_func_tbl_release(struct urpc_hmap *func_table)
{
    if ((func_table == NULL) || (func_table->bucket == NULL)) {
        return;
    }

    urpc_func_base_entry_t *cur = NULL;
    urpc_func_base_entry_t *next = NULL;
    URPC_HMAP_FOR_EACH_SAFE(cur, next, name_node, func_table) {
        urpc_hmap_remove(func_table, &cur->name_node);
        urpc_dbuf_free(cur);
    }
    urpc_hmap_uninit(func_table);
}
