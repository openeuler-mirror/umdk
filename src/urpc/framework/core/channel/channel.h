/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define inner channel struct
 */
#ifndef CHANNEL_H
#define CHANNEL_H

#include <pthread.h>

#include "crypto.h"
#include "queue.h"
#include "urpc_hmap.h"
#include "urpc_socket.h"
#include "urpc_timer.h"
#include "urpc_framework_types.h"
#include "urpc_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_MAX_CHANNELS                       300000
#define URPC_DEFAULT_CHANNEL_REQ_ENTRY          1024
/* Maximum tx sq depth is 2047 in URPC_TRANS_MODE_UB */
#define URPC_MAX_CHANNEL_REQ_ENTRY              ((2047 + 1) * MAX_QUEUE_SIZE)
#define URPC_MAX_CHANNEL_PER_CLIENT             16
#define URPC_MAX_CLIENTS                        300000
#define URPC_SERVER_MAX_CHANNELS                (URPC_MAX_CHANNEL_PER_CLIENT * URPC_MAX_CLIENTS)
#define URPC_MAX_CLIENT_CHANNELS_PER_CLIENT     256

#define URPC_BASE_ID_OFFSETS                    4

#define URPC_ATTR_MANAGE                        1

typedef enum urpc_channel_status {
    /* channel is idle */
    URPC_CHANNEL_IDLE = 0,
    /* channel is ready for work */
    URPC_CHANNEL_READY,
    /* channel has seen a failure but expects to recover */
    URPC_CHANNEL_FAILURE,
    /* channel has seen a failure that it cannot recover from */
    URPC_CHANNEL_SHUTDOWN,
} urpc_channel_status_e;

typedef struct urpc_channel_id_allocator {
    uint32_t *available_ids;
    uint32_t num_available;
    uint32_t next_id;
    pthread_mutex_t lock;
} urpc_channel_id_allocator_t;

typedef struct server_node {
    urpc_endpoints_t endpoints;
    uint32_t urpc_qh_count;
    uint32_t server_chid;
    uint64_t *urpc_qh;
    urpc_channel_capability_t cap;
    urpc_list_t node;
    urpc_cipher_t *cipher_opt;
    urpc_instance_key_t instance_key; // remote key info
    uint32_t index;
} server_node_t;

typedef void (*urpc_req_cb_t)(urpc_sge_t *rsps, uint32_t rsps_sge_num, int err, void *arg, void *ctx);

typedef struct req_entry {
    /* The callback can be executed only once. Tell the timeout thread whether the callback can be invoked normally. */
    pthread_mutex_t lock;
    urpc_timer_t *timer;
    void *ctx;
    urpc_sge_t *args;
    uint32_t args_num;
    uint32_t req_id;
    uint32_t remote_chid;
    uint32_t local_chid;
    uint32_t server_node_idx;
    uint64_t send_qh;
    uint8_t valid;
    urpc_req_cb_t cb;                      // callback func for request when receiving response
    void *cb_arg;                          // callback arg
} req_entry_t;

typedef enum channel_stats_type {
    CHANNEL_REQ_ENTRY_TOTAL_NUM = 0,
    CHANNEL_REQ_ENTRY_FREE_NUM,
    CHANNEL_LAST_ALLOC_REQ_ID,
    CHANNEL_LAST_FREE_REQ_ID,
    CHANNEL_TASK_TOTAL_NUM,
    CHANNEL_TASK_RUNNING_NUM,
    CHANNEL_TASK_SUCCEEDED_NUM,
    CHANNEL_TASK_FAILED_NUM,
    CHANNEL_STATS_TYPE_MAX
} channel_stats_type_t;

typedef struct all_channel_query_info {
    uint32_t total_num;
} all_channel_query_info_t;

typedef struct channel_server_info {
    urpc_host_info_t info;
    urpc_instance_key_t key;
} channel_server_info_t;

typedef struct channel_query_info {
    volatile uint64_t       req_entry_stats[CHANNEL_STATS_TYPE_MAX];
    volatile uint64_t       timer_stats[TIMER_STATS_TYPE_MAX];
    uint32_t                server_cnt;
    channel_server_info_t   server[0];
} channel_query_info_t;

typedef struct urpc_channel_info {
    uint32_t                id;
    uint32_t                req_id;
    urpc_list_t             tcp_node; // single channel node under tcp transport obj
    urpc_list_t             task_ready_list;
    /* Details of the queue for the connected server */
    urpc_list_t             server_nodes_list;
    /* Details of local queues related to the channel */
    struct queue_nodes_head l_queue_nodes_head;
    /* Details of remote queues related to the channel */
    struct queue_nodes_head r_queue_nodes_head;
    /* current local queue for round-robin */
    queue_node_t            *cur_rr_local_queue;
    /* current remote queue for round-robin */
    queue_node_t            *cur_rr_remote_queue;
    /* current poll queue */
    queue_node_t            *cur_poll_queue;
    /* req entry table */
    req_entry_t             *req_entry_table;
    /* within the read lock protection range, the data plane that protect resource contention on channels */
    pthread_spinlock_t      lock;
    /* control plane uses write locks, and the data plane uses read locks */
    pthread_rwlock_t        rw_lock;
    /* number of local queues related to the channel */
    uint32_t                l_qnum;
    /* number of remote queues related to the channel */
    uint32_t                r_qnum;
    urpc_channel_status_e   status;
    uint32_t                attr;
    uint32_t                manage_chid;
    uint32_t                server_node_index;
    provider_t              *provider;      // currently, each channel only support one provider
    /* size of req entry related to the channel, can only be a power of 2 */
    uint32_t                req_entry_size;
    struct urpc_hmap        func_tbl;
    uint32_t                mem_info_num;
    urpc_list_t             mem_info_list;
    pthread_rwlock_t        mem_info_lock;
    bool                    handshaking;
    volatile uint64_t       stats[CHANNEL_STATS_TYPE_MAX];
} urpc_channel_info_t;

typedef struct urpc_server_channel_info {
    urpc_list_t             node;           // for tcp keealive loss clean resource
    uint64_t                keepalive_attr;
    uint32_t                id;
    uint32_t                mapped_id;
    /* enable URPC_FEATURE_MULTIPLEX, for n client channels to 1 server channel */
    uint32_t                client_chid[URPC_MAX_CLIENT_CHANNELS_PER_CLIENT];
    uint32_t                client_chid_num;
    uint32_t                manage_chid;
    uint32_t                manage_mapped_id;
    /* Details of remote queues related to the channel */
    struct queue_nodes_head r_queue_nodes_head;
    pthread_rwlock_t        rw_lock;
    urpc_channel_status_e   status;
    uint32_t                attr;
    urpc_instance_key_t     key;
    urpc_cipher_t           *cipher_opt;
    urpc_list_t             mem_key_list;
} urpc_server_channel_info_t;

typedef struct urpc_server_connect_table {
    struct urpc_hmap    hmap;
    pthread_spinlock_t  lock;
    bool                lock_inited;
} urpc_server_connect_table_t;

typedef struct urpc_server_connect_entry {
    struct urpc_hmap_node       node;
    urpc_instance_key_t         key;
    uint32_t                    base_id;
    urpc_channel_id_allocator_t count_id;
    uint64_t                    user_ctx;
} urpc_server_connect_entry_t;

typedef struct channel_mem_info {
    urpc_list_t node;
    xchg_mem_info_t xchg_mem_info;
    uint64_t mem_h;
} channel_mem_info_t;

typedef struct mem_entry_key_node {
    struct urpc_list node;
    mem_hmap_key_t mem_key;
} mem_entry_key_node_t;

typedef struct urpc_detach_info {
    urpc_instance_key_t key;
    uint32_t server_chid;
} urpc_detach_info_t;

void urpc_server_info_convert(urpc_host_info_t *src, urpc_host_info_inner_t *dst);

int channel_id_allocator_init(urpc_channel_id_allocator_t *id_allocator, uint32_t max_num);
void channel_id_allocator_uninit(urpc_channel_id_allocator_t *id_allocator);
uint32_t channel_id_allocator_get(urpc_channel_id_allocator_t *id_allocator, uint32_t max_id);
void channel_id_allocator_release(urpc_channel_id_allocator_t *id_allocator, uint32_t max_id, uint32_t urpc_chid);

/* Client Channel */
int urpc_client_channel_id_allocator_init(void);
void urpc_client_channel_id_allocator_uninit(void);

urpc_channel_info_t *channel_alloc(void);
urpc_channel_info_t *channel_get(uint32_t urpc_chid);
int channel_free(uint32_t urpc_chid);
void req_entry_table_init(urpc_channel_info_t *channel);

int channel_add_remote_queue(
    urpc_channel_info_t *channel, queue_t *queue, batch_queue_import_ctx_t *ctx, int timeout);
int channel_post_add_remote_queue(urpc_channel_info_t *channel, queue_t *queue, void *ctx);

int channel_remove_local_queue(urpc_channel_info_t *channel, queue_t *queue);
int channel_remove_remote_queue(urpc_channel_info_t *channel, queue_t *queue);
int channel_remove_remote_queue_async(urpc_channel_info_t *channel, queue_t *queue);
void server_channel_remove_remote_queue(urpc_server_channel_info_t *channel, queue_node_t *cur_node);
int channel_get_local_queue_info(uint64_t qh, queue_info_t *queue_info);
int channel_get_local_queues(urpc_channel_info_t *channel, uint32_t queue_size, uint64_t *qh);
bool is_remote_queue_in_queue_info(queue_t *queue, void *chmsg_input);
int server_channel_put_remote_queue_async(uint32_t server_chid, void *chmsg_input, batch_queue_import_ctx_t *ctx);
int server_channel_post_put_remote_queue(uint32_t server_chid, batch_queue_import_ctx_t *ctx);
bool channel_put_remote_queue_infos(urpc_channel_info_t *channel, uint32_t remote_chid,
                                    urpc_endpoints_t *endpoints, void *chmsg_input);
int channel_flush_remote_queue_info(
    urpc_channel_info_t *channel, urpc_endpoints_t *endpoints, server_node_t *server_node, void *chmsg_input);
int channel_update_remote_queue_info(urpc_channel_info_t *channel, urpc_endpoints_t *endpoints,
    server_node_t *server_node, void *chmsg_input, bool is_all_queue);
void channel_flush_server_node(server_node_t *server_node, void *chmsg_input, urpc_endpoints_t *endpoints);
void channel_update_server_node(server_node_t *server_node, void *chmsg_input, urpc_endpoints_t *endpoints);
uint32_t channel_remove_server(urpc_channel_info_t *channel, urpc_host_info_t *server);
server_node_t *channel_get_server_node(urpc_channel_info_t *channel, urpc_host_info_t *server);
server_node_t *channel_get_server_node_by_index(urpc_channel_info_t *channel, uint64_t index);
server_node_t *channel_get_server_node_by_chid(urpc_channel_info_t *channel, uint32_t server_chid);
uint32_t channel_get_server_chid(urpc_channel_info_t *channel, urpc_host_info_t *server);
int channel_get_queue_trans_info(uint32_t urpc_chid, char **output, uint32_t *output_size);

void channel_queue_query(urpc_channel_info_t *channel, urpc_channel_qinfos_t *info);
int channel_get_req_id(urpc_channel_info_t *channel, uint32_t *id);

req_entry_t *req_entry_get(urpc_channel_info_t *channel, void *ctx);
req_entry_t *req_entry_query(uint32_t urpc_chid, uint32_t req_id, bool need_lock);
void req_entry_put(req_entry_t *req_entry);

queue_t *channel_get_next_local_queue(urpc_channel_info_t *channel);
queue_t *channel_get_next_remote_queue(urpc_channel_info_t *channel);
queue_t *channel_get_cur_poll_queue(urpc_channel_info_t *channel);
queue_t *channel_get_local_queue_by_handle(urpc_channel_info_t *channel, uint64_t urpc_qh);
queue_t *channel_get_remote_queue_by_handle(urpc_channel_info_t *channel, uint64_t urpc_qh);
queue_t *channel_get_remote_queue_by_flag(urpc_channel_info_t *channel, urpc_queue_flag_t *flag);
queue_t *channel_get_remote_queue_by_qid(urpc_channel_info_t *channel, uint32_t qid);

uint32_t channel_num_get(void);
int channel_info_get(uint32_t urpc_chid, char **output, uint32_t *output_size);

/* Server Channel */
int urpc_server_channel_id_allocator_init(void);
void urpc_server_channel_id_allocator_uninit(void);
uint32_t urpc_server_channel_id_all_get(
    urpc_instance_key_t *key, uint32_t *server_chids, uint32_t server_chids_max_num);

urpc_server_channel_info_t *server_channel_alloc(urpc_instance_key_t *key, uint64_t user_ctx);
urpc_server_channel_info_t *server_channel_get(uint32_t urpc_chid);
urpc_server_channel_info_t *server_channel_get_with_rw_lock(uint32_t urpc_chid, bool is_write);
int server_channel_free(uint32_t urpc_chid, bool lock_free);

queue_t *server_channel_search_remote_queue(uint32_t server_chid, queue_t *l_queue, queue_t *q_src);
queue_t *server_channel_search_remote_queue_by_flag(uint32_t server_chid, urpc_queue_flag_t *flag);
void server_channel_unlock(uint32_t server_chid);
int server_channel_get_queue_trans_info(uint32_t urpc_chid, char **output, uint32_t *output_size);

int server_channel_cipher_init(urpc_server_channel_info_t *channel, crypto_key_t *crypto_key);
uint32_t server_channel_id_map_lookup(uint32_t mapped_id);

void server_channel_connect_hmap_lock(void);
void server_channel_connect_hmap_unlock(void);

int server_channel_import_rollback(uint32_t urpc_chid, queue_info_t *queue_info);

int server_channel_add_client_chid(urpc_server_channel_info_t *server_channel, uint32_t client_chid);
void server_channel_rm_client_chid(urpc_server_channel_info_t *server_channel, uint32_t client_chid);

static inline bool is_req_entry_timeout(const req_entry_t *entry)
{
    return ((entry->valid != URPC_FALSE) && is_urpc_timer_running(entry->timer));
}

int server_channel_add_mem(urpc_server_channel_info_t *server_channel, xchg_mem_info_t *xchg_mem);
int server_channel_put_mem_info(uint32_t server_chid, xchg_mem_info_t **mem_info, uint32_t mem_info_num);

#ifdef __cplusplus
}
#endif
#endif
