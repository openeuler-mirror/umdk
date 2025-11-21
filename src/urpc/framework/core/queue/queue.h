/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: define queue abstract and struct
 */

#ifndef QUEUE_H
#define QUEUE_H

#include <errno.h>
#include <stdbool.h>
#include "urma_types.h"
#include "urpc_epoll.h"
#include "urpc_list.h"
#include "urpc_slab.h"
#include "urpc_hmap.h"
#include "urpc_slist.h"
#include "urpc_framework_types.h"
#include "queue_resource_ref.h"
#include "urpc_dbuf_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

#define URPC_POST_RECV_WR_NUM (32)
#define QUEUE_MSG_SRC_QUEUE_INFO_SIZE (40)

/* Queue flags, Configured in the `flag` of create_local_queue()/create_remote_flag or `queue_flag` of queue_info_t. */
#define URPC_QUEUE_FLAG_QUICK_REPLY 0x2
#define URPC_QUEUE_FLAG_KEEPALIVE 0x10

#define QUEUE_STATS_TYPE_SGE_OFFSET 1
#define QUEUE_STATS_TYPE_BYTES_OFFSET 2
#define QUEUE_STATS_TYPE_DMA_SGE_OFFSET 3
#define QUEUE_STATS_TYPE_DMA_BYTES_OFFSET 4

#define QUEUE_ID_INVALID 0
#define QUEUE_ID_UPPER_LIMIT 0xffff
#define QUEUE_ID_MAX (QUEUE_ID_UPPER_LIMIT + 1)

#define QALLOCA_NORMAL_SIZE_FLAG  1
#define QALLOCA_LARGE_SIZE_FLAG   (1 << 1)

#define URPC_PLOG_PRIORITY 4

#define DEFAULT_READ_CACHE_LIST_DEPTH 5120
#define DEFAULT_READ_CACHE_LIST_TIMEOUT_S 12

#define IO_MODE_MAX 4
#define URPC_DEFAULT_ALIGN (8)
#define URPC_QUEUE_IMPORT_TIMEOUT 30000

typedef struct provider_ops provider_ops_t;
typedef struct provider provider_t;
typedef struct read_cache read_cache_t;

typedef struct urpc_queue_flag {
    uint8_t is_remote : 1;
    uint8_t rsvd : 3;
    uint8_t is_keepalive : 1;
} urpc_queue_flag_t;

typedef enum queue_event {
    TX_SEND,
    RX_RECV,
    QUEUE_ERR,
    CTX_ERR,
} queue_event_t;

typedef enum queue_authn_mode {
    QUEUE_AUTHN_BY_QUEUE,
    QUEUE_AUTHN_BY_QUEUE_INFO
} queue_authn_mode_t;

// queue ctx types in data plane process
typedef enum queue_ctx_type {
    QUEUE_CTX_TYPE_TX = 0,
    QUEUE_CTX_TYPE_REQ,
    QUEUE_CTX_TYPE_QSRC,

    QUEUE_CTX_TYPE_MAX,
} queue_ctx_type_t;

// indicate queue ctx is used in tx or rx
typedef enum queue_ctx_direction {
    QUEUE_CTX_RX,
    QUEUE_CTX_TX,
} queue_ctx_direction_t;

typedef struct queue_ctx_info {
    queue_ctx_type_t type;
    queue_ctx_direction_t direction;
    size_t size;
} queue_ctx_info_t;

struct queue_ops;
typedef struct queue_ops queue_ops_t;

typedef struct rq_ctx {
    q_res_ref_t ctx_ref;
    volatile uint32_t ready_cnt; // ready queue number for order queue
    volatile uint32_t rx_wr_cnt;
    eslab_t rx_user_ctx_slab;
    uint8_t lock_free;
    pthread_spinlock_t lock;
} rq_ctx_t;

typedef struct ce_ctx {
    q_res_ref_t ctx_ref;
} ce_ctx_t;

typedef struct cq_ctx {
    q_res_ref_t ctx_ref;
    atomic_uint expect_cq_depth; // total depth of shared qhs, must ensure n * (rx_depth, or (tx_depth + 1)) <= cq_depth
} cq_ctx_t;

typedef struct queue_transport_ctx {
    urpc_list_t queue_list;
    pthread_mutex_t queue_list_mutex;
    urpc_list_t provider_list;
} queue_transport_ctx_t;

typedef struct mem_handle {
    uint32_t num;
    uint64_t handle[0];
} mem_handle_t;

typedef struct tseg_handle {
    uint32_t num;
    uint64_t handle[0];
} tseg_handle_t;

typedef struct mem_hmap_key {
    uint32_t server_chid;
    uint32_t token_id;
    uint32_t token_value;
} __attribute__((packed)) mem_hmap_key_t;

typedef struct mem_entry {
    struct urpc_hmap_node node;
    tseg_handle_t *tseg_h;
    uint32_t timestamp;
    mem_hmap_key_t mem_key;
} mem_entry_t;

typedef struct mem_hmap {
    struct urpc_hmap hmap;
    pthread_rwlock_t lock;
    uint32_t ref_cnt;
} mem_hmap_t;

typedef struct read_cache_list {
    pthread_spinlock_t lock;
    urpc_list_t read_cache_list;
    uint32_t normal_node_num;
    uint32_t err_node_num;
    uint32_t timeout;
    uint32_t init;
} read_cache_list_t;

typedef struct plog_read_cache_ret_msg {
    urpc_poll_msg_t *msg;
    uint32_t msg_cnt;
} plog_read_cache_ret_msg_t;

struct read_cache {
    urpc_list_t node;
    int32_t err_code;
    uint32_t timestamp;
    int (*process_callback)(read_cache_t *args, uint32_t urpc_chid, plog_read_cache_ret_msg_t *ret_msg);
    void (*exception_callback)(read_cache_t *args, uint32_t urpc_chid, int32_t err_code,
                               plog_read_cache_ret_msg_t *ret_msg);
};

/* both local and remote */
typedef struct queue {
    provider_t *provider;
    queue_ops_t *ops;
    union {
        urpc_queue_flag_t flag;  // only flag now, add both need pro here.
        uint8_t flag_val;
    };
    urpc_queue_status_t status;
    int32_t err_code;
    volatile uint32_t ref_cnt;
} queue_t;

URPC_SLIST_HEAD(queue_nodes_head, queue_node);

/* only local */
typedef struct queue_local_t {
    queue_t queue;                  // placed at the beginning of the definition to facilitate conversion of types
    eslab_t slab[QUEUE_CTX_TYPE_MAX];
    volatile uint64_t stats[STATS_TYPE_MAX];
    volatile uint64_t error_stats[ERR_STATS_TYPE_MAX];
    rq_ctx_t *rq_ctx;
    cq_ctx_t *tx_cq_ctx; // tx_cq
    cq_ctx_t *cq_ctx; // rx_cq
    ce_ctx_t *ce_ctx; // jfce计数信息
    urpc_list_t node;
    uint16_t qid;
    uint16_t notify : 1;
    uint16_t tx_flush_done : 1; // recv tx flush done
    uint16_t rx_flush_done : 1; // recv rx flush done or no need recv rx flush done
    uint16_t is_damage : 1;     // queue not available, destroy queue no verification rx/tx wr cnt
    uint16_t is_binded : 1;       // queue is bind
    uint16_t rsvd : 12;
    atomic_uint err_msg_num;
    volatile uint16_t tx_wr_cnt;
    urpc_qcfg_get_t cfg;
    uint32_t timestamp;
    read_cache_list_t rcache_list;
    int thread_index;
    uint32_t err_timestamp;
    urma_jetty_id_t remote_jetty_id;
} queue_local_t;

/* only remote */
struct server_node;
typedef struct urpc_qcfg_remote_get {
    struct server_node *server_node;    // server node the queue belongs to
    uint64_t custom_flag;               // user can define some flag for queue
    urpc_queue_type_t type;             // type of queue
    uint32_t rx_buf_size;               // size of the receive buffer
    uint32_t rx_depth;                  // depth of the receive buffer ring
    uint32_t remote_chid;
    uint8_t trans_mode;                 // transmission mode of the queue
} urpc_qcfg_remote_get_t;

typedef struct queue_remote {
    queue_t queue;                  // placed at the beginning of the definition to facilitate conversion of types
    urpc_qcfg_remote_get_t cfg;
    uint32_t timestamp;
    uint32_t bind_local_qid;
    uint16_t qid;
} queue_remote_t;

typedef struct queue_node {
    uint64_t urpc_qh;
    URPC_SLIST_ENTRY(queue_node) node;
    uint32_t ref_cnt;
} queue_node_t;

typedef struct src_queue_info {
    uint8_t info[QUEUE_MSG_SRC_QUEUE_INFO_SIZE];
} src_q_info_t;

typedef struct queue_msg {
    queue_event_t ev;
    int status;  // cr.status (plays the role of err_code when ev = QUEUE_ERR)
    uint32_t len; // cr.completion_len;
    void *data;
    src_q_info_t src_q_info;
} queue_msg_t;

typedef struct queue_msgs {
    queue_msg_t *msg;
    int msg_num;
} queue_msgs_t;

typedef struct queue_wr {
    urpc_sge_t *sge;
    urpc_sge_t *dst_sge;  // use in read scene
    uint32_t sge_num;
    uint32_t dst_sge_num;  // use in read scene
    queue_t *r_queue;
    uint64_t total_size;
    void *ctx;
    struct queue_wr *next;
    uint32_t server_chid;
    uint32_t token_id;
    uint32_t token_value;
} queue_wr_t;

/* Control plane exchange information.
 * 1. Pay attention to the alignment when adding new field
 * 2. If packed is used, the receiver cannot access the address of the structure field.  */
typedef struct queue_info {
    uint64_t custom_flag;
    uint32_t rx_buf_size;
    uint32_t timestamp;
    urpc_queue_type_t type;
    urpc_queue_trans_mode_t trans_mode;
    uint16_t qid;
    uint8_t priority;
    uint8_t queue_flag;
    /* Depends on `trans_mode` */
    union {
        struct {
            urma_jetty_id_t jetty_id;
            urma_target_type_t type;
            urma_token_t token;
            uint8_t order_type;
        } mode_jetty;
    };
} __attribute__((aligned(URPC_DEFAULT_ALIGN))) queue_info_t;

/* to create quick reply queue */
typedef struct quick_reply_queue_info {
    src_q_info_t *src_q_info;
    uint16_t qid;
} qr_queue_info_t;

typedef struct urpc_channel_capability {
    uint32_t is_support_quik_reply : 1;  // server only
    uint32_t rsvd : 31;
} urpc_channel_capability_t;

// use eid + pid to identify different client/server instance
typedef struct urpc_instance_key {
    urpc_eid_t eid;
    uint32_t pid;
} urpc_instance_key_t;

/* If packed is used, the receiver cannot access the address of the structure field. */
typedef struct urpc_chinfo {
    urpc_instance_key_t key;
    urpc_channel_capability_t cap;
    uint32_t attr;
    uint32_t chid;  // local chid for send and remote chid for recv
    uint32_t server_chid;
} __attribute__((aligned(URPC_DEFAULT_ALIGN))) urpc_chinfo_t;

typedef struct queue_create_option {
    urpc_qcfg_create_t *cfg;
    urpc_queue_type_t type;
    uint32_t qid;
} queue_create_option_t;

typedef struct xchg_mem_info {
    uint64_t seg_len;
    uint32_t seg_token_id;
    urma_import_seg_flag_t seg_flag;
    urma_token_t token;
    urma_ubva_t ubva;
} __attribute__((packed)) xchg_mem_info_t;

typedef struct queue_trans_resource_spec {
    uint32_t uasid;
    uint32_t id;
    uint32_t tpn;
} queue_trans_resource_spec_t;

typedef struct queue_trans_info {
    urpc_eid_t eid;
    urpc_queue_flag_t flag;
    uint64_t custom_flag;
    uint16_t qid;
    uint32_t trans_spec_cnt;
    queue_trans_resource_spec_t trans_spec[0];
} queue_trans_info_t;

typedef enum queue_query_trans_type {
    QUEUE_QUERY_TRANS_INFO_SIZE,
    QUEUE_QUERY_TRANS_INFO_DATA,
} queue_query_trans_type_t;

typedef enum flush_type {
    TX,
    RX,
    ALL
} flush_type_t;

// Use these values temporarily, waiting for udma to define
#define USER_CTL_REGISTER_PA_MEM       0x1c
#define USER_CTL_UNREGISTER_PA_MEM     0x1d
#define USER_CTL_MAPPING_JETTY_FE_IDX  0x1e

typedef struct mem_seg_register_param {
    uint64_t addr;
    uint64_t len;
    mem_seg_token_t *token;
    bool     va;
    uint32_t fe_idx;
} mem_seg_register_param_t;

typedef enum queue_import_status {
    QUEUE_IMPORT_INIT = 0,
    QUEUE_IMPORT_RUNNING,
    QUEUE_IMPORT_SUCCESS,
    QUEUE_IMPORT_FAIL
} queue_import_status_t;

typedef struct queue_import_async_info {
    urpc_list_t node;
    uint64_t queue_handle;
    uint64_t notifier_handle;
    provider_t *provider;
    uint64_t t_jetty_handle;
    queue_import_status_t status;
    void *task;
} queue_import_async_info_t;

typedef struct queue_import_ctx {
    urpc_list_t node;
    urpc_list_t list;
    uint64_t notifier_handle;
    int fd;
    int total; // indicates the number of pre-delivered import send.
    int running_count;  // indicates the number of delivered import send sucessfully.
    int result;
    provider_t *provider;
    urpc_epoll_event_t *event;
    bool is_add;
} queue_import_ctx_t;

typedef struct batch_queue_import_ctx {
    urpc_list_t list;
    urpc_list_t import_list;
    void *task;
    int total;
    int running_count;
    int result;
    bool is_inited;
    bool is_user_inited;
} batch_queue_import_ctx_t;

typedef void (*flush_callback_t)(queue_t *queue, void *data, int status_code, flush_type_t type);
typedef void (*import_callback_t)(void *ctx, int status);
typedef void (*delete_queue_callback_t)(queue_t *queue);

typedef struct queue_ops {
    struct urpc_list node;
    urpc_queue_trans_mode_t mode;
    // control api
    queue_t *(*create_local_queue)(queue_create_option_t *option, uint16_t flag);
    int (*delete_local_queue)(queue_t *l_queue, delete_queue_callback_t delete_queue_cb);
    int (*query_local_queue)(queue_t *l_queue, void *ptr);
    uint32_t (*query_trans_info)(queue_t *queue, queue_query_trans_type_t type, void *ptr);
    queue_t *(*create_remote_queue)(void *ptr, uint32_t remote_chid, uint16_t flag);
    void (*delete_remote_queue)(queue_t *r_queue);
    int (*import_remote_queue)(queue_t *r_queue, provider_t *provider);
    int (*unimport_remote_queue)(queue_t *r_queue);
    int (*import_remote_queue_async)(
        queue_t *r_queue, provider_t *provider, queue_import_async_info_t *async_info, int timeout);
    int (*unimport_remote_queue_async)(queue_t *r_queue);
    int (*bind_queue)(queue_t *l_queue, queue_t *r_queue);
    int (*unbind_queue)(queue_t *l_queue);
    bool (*is_same_queue)(queue_t *queue, void *info, queue_authn_mode_t mode);
    int (*update_queue_status)(queue_t *r_queue, queue_import_async_info_t *async_info);
    int (*modify_queue)(queue_t *l_queue, urpc_queue_status_t status);
    // datapath api
    int (*send)(queue_t *l_queue, queue_wr_t *wr);
    int (*read)(queue_t *l_queue, queue_wr_t *wr);
    int (*poll)(queue_t *l_queue, queue_msgs_t *msgs, urpc_poll_direction_t poll_direction);
    int (*post)(queue_t *l_queue, queue_wr_t *wr);
    int (*wait)(queue_t *l_queue, int timeout);
    int (*mem_seg_token_get)(uint64_t mem_h, mem_seg_token_t *token);
    int (*get_interrupt_fd)(queue_t *l_queue);
    int (*mapping_queue_fe_idx)(queue_t *queue, uint32_t fe_idx);
} queue_ops_t;

typedef union provider_flag {
    struct {
        uint32_t multi_eid : 1;
        uint32_t rsvd : 31;
    } bs;
    uint32_t value;
} provider_flag_t;

typedef struct provider_init_opt {
    urpc_trans_info_t *cfg;
    provider_flag_t flag;
    uint32_t start_idx;             // start idx for providers
} provider_init_opt_t;

typedef enum provider_ops_mode {
    PROVIDER_MODE_JETTY
} provider_ops_mode_t;

typedef struct provider {
    struct urpc_list node;
    provider_ops_t *ops;
    uint32_t idx;
    urpc_trans_mode_t trans_mode;
} provider_t;

typedef struct urpc_notify {
    int status;
    uint64_t user_ctx;
} urpc_notify_t;

struct provider_ops {
    struct urpc_list node;
    provider_ops_mode_t mode;
    uint32_t (*init)(provider_init_opt_t *opt);
    void (*uninit)(provider_t *provider);
    uint64_t (*register_mem)(provider_t *provider, mem_seg_register_param_t *parm);
    int (*unregister_mem)(provider_t *provider, uint64_t mem_h, bool va);
    void (*get_eid)(provider_t *provider, urpc_eid_t *eid);
    urpc_trans_mode_t (*get_trans_mode)(provider_t *provider);
    uint64_t (*create_notifier)(queue_import_ctx_t *ctx);
    int (*destroy_notifier)(uint64_t handle);
    int (*get_async_event_notification)(uint64_t handle, uint32_t cnt, urpc_notify_t *result, int timeout);
    int (*register_importer)(provider_t *provider, import_callback_t func);
    void (*unregister_importer)(provider_t *provider);
    int (*import_mem)(provider_t *provider, xchg_mem_info_t *mem_info, uint32_t server_chid);
    int (*unimport_mem)(provider_t *provider, mem_hmap_key_t *mem_key);
};

void queue_register_ops(queue_ops_t *queue_ops);
queue_ops_t *queue_get_ops(urpc_queue_trans_mode_t mode);

queue_transport_ctx_t *get_queue_transport_ctx(void);
void queue_list_push(queue_local_t *local_q);
void queue_list_pop(queue_local_t *local_q);
int queue_id_allocator_init(void);
void queue_id_allocator_uninit(void);
int queue_id_allocator_alloc(uint32_t *qid);
void queue_id_allocator_free(uint32_t qid);
bool queue_id_is_invaild(uint32_t qid);

int provider_init(uint8_t cfg_num, urpc_trans_info_t *cfg, provider_flag_t flag);
void provider_uninit(void);
void provider_list_push(provider_t *provider);
void provider_list_pop(provider_t *provider);
uint32_t provider_get_list_size(void);  // For UT, currently
provider_t *get_provider(urpc_eid_t *eid);
urpc_queue_trans_mode_t urpc_queue_default_trans_mode_get(void);
urpc_list_t *get_provider_list(void);
void provider_register_ops(provider_ops_t *provider_ops);
provider_ops_t *provider_get_ops(provider_ops_mode_t mode);

/* Interfaces used on queues across different trans-mode */
int get_local_queues(uint32_t queue_max, uint64_t *qh, uint32_t *queue_num);
uint64_t get_one_local_queue_by_qid(uint64_t qid);
int get_queue_trans_info(char **output, uint32_t *output_size);
int advise_local_queues(queue_t *r_queue);
void unadvise_local_queues(queue_t *r_queue);
void query_queues_stats(uint64_t *stats, int stats_len, uint64_t *error_stats, int error_stats_len);
int query_queues_stats_by_id(uint16_t qid, uint64_t *stats, int stats_len, uint64_t *error_stats, int error_stats_len);
int queue_info_get(uint16_t qid, char **output, uint32_t *output_size);

int queue_slab_init(queue_local_t *local_q);
void queue_slab_uninit(queue_local_t *local_q);

void queue_ctx_infos_set(queue_ctx_info_t *info, int num);
void queue_ctx_infos_get(queue_ctx_info_t *info, int num);
size_t queue_ctx_size_get(queue_ctx_type_t type);

void queue_stats_enable(void);
void queue_stats_disable(void);
bool is_queue_stats_enable(void);

void queue_read_cache_list_init(read_cache_list_t *rcache_list, uint32_t timeout);
void queue_read_cache_list_uninit(read_cache_list_t *rcache_list);
int queue_read_cache_list_push_back(read_cache_list_t *rcache_list, read_cache_t *read_cache);
void queue_read_cache_list_push_front(read_cache_list_t *rcache_list, read_cache_t *read_cache);
read_cache_t *queue_read_cache_list_pop_front(read_cache_list_t *rcache_list);
static inline bool queue_read_cache_list_need_process(read_cache_list_t *rcache_list)
{
    return (rcache_list->normal_node_num != 0) || (rcache_list->err_node_num != 0);
}

/* For Ut test */
static inline uint32_t queue_read_cache_list_size(read_cache_list_t *rcache_list)
{
    pthread_spin_lock(&rcache_list->lock);
    uint32_t list_size = rcache_list->normal_node_num + rcache_list->err_node_num;
    pthread_spin_unlock(&rcache_list->lock);
    return list_size;
}

typedef struct queue_ctx_head {
    queue_local_t *l_queue;
#if defined URPC_ASAN || defined URPC_CODE_COVERAGE
    void *eslab_ctx;
#endif
    uint32_t is_eslab : 1;
    uint32_t in_use : 1;
    uint32_t rsvd : 30;
    char buf[0];
} __attribute__((packed)) queue_ctx_head_t;

static ALWAYS_INLINE queue_ctx_head_t *queue_ctx_malloc(queue_local_t *local_q, queue_ctx_type_t type)
{
    queue_ctx_head_t *ctx_head = (queue_ctx_head_t *)urpc_dbuf_malloc(URPC_DBUF_TYPE_QUEUE,
        queue_ctx_size_get(type) + sizeof(queue_ctx_head_t));
    if (URPC_UNLIKELY(ctx_head == NULL)) {
        return NULL;
    }

    ctx_head->l_queue = local_q;
    ctx_head->is_eslab = URPC_FALSE;
    ctx_head->in_use = URPC_TRUE;
    return ctx_head;
}

/* caller guarantee ctx pointer is not NULL */
static ALWAYS_INLINE int queue_ctx_validate(queue_t *l_queue, queue_ctx_type_t type, void *ctx)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    // check whether context is allocted by 'malloc'. if so, not validate this context and return success directly
    if (!eslab_validate_addr(&local_q->slab[type], ctx)) {
        return URPC_SUCCESS;
    }

    queue_ctx_head_t *ctx_head = CONTAINER_OF_FIELD(ctx, queue_ctx_head_t, buf);
    if (URPC_UNLIKELY(ctx_head->in_use == URPC_FALSE)) {
        return -URPC_ERR_EPERM;
    }

    return URPC_SUCCESS;
}

#if !defined URPC_ASAN && !defined URPC_CODE_COVERAGE
static ALWAYS_INLINE void *queue_ctx_get(queue_t *l_queue, queue_ctx_type_t type)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    if (URPC_UNLIKELY(local_q->slab[type].addr == NULL)) {
        return NULL;
    }

    queue_ctx_head_t *ctx_head;
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ctx_head = (queue_ctx_head_t *)eslab_get_buf_lockless(&local_q->slab[type]);
    } else {
        ctx_head = (queue_ctx_head_t *)eslab_get_buf(&local_q->slab[type]);
    }

    if (URPC_UNLIKELY(ctx_head == NULL)) {
        if (URPC_UNLIKELY(errno != URPC_ERR_ENOMEM)) {
            return NULL;
        }

        ctx_head = queue_ctx_malloc(local_q, type);
        return ctx_head == NULL ? NULL : (void *)ctx_head->buf;
    }

    ctx_head->l_queue = local_q;
    ctx_head->is_eslab = URPC_TRUE;
    ctx_head->in_use = URPC_TRUE;
    return (void *)ctx_head->buf;
}

static ALWAYS_INLINE void queue_ctx_put(queue_ctx_type_t type, void *ctx)
{
    if (URPC_UNLIKELY(ctx == NULL)) {
        return;
    }

    queue_ctx_head_t *ctx_head = CONTAINER_OF_FIELD(ctx, queue_ctx_head_t, buf);
    if (URPC_UNLIKELY(ctx_head->in_use == URPC_FALSE)) {
        return;
    }
    ctx_head->in_use = URPC_FALSE;

    if (URPC_UNLIKELY(ctx_head->is_eslab == URPC_FALSE)) {
        urpc_dbuf_free(ctx_head);
        return;
    }

    if (URPC_LIKELY(ctx_head->l_queue->cfg.lock_free != 0)) {
        eslab_put_buf_lockless(&ctx_head->l_queue->slab[type], (void *)ctx_head);
        return;
    }

    eslab_put_buf(&ctx_head->l_queue->slab[type], (void *)ctx_head);
}
#else
void *queue_ctx_get(queue_t *l_queue, queue_ctx_type_t type);
void queue_ctx_put(queue_ctx_type_t type, void *ctx);
#endif

typedef struct rx_user_ctx_head {
    rq_ctx_t *rq_ctx;
    char buf[0];
} __attribute__((packed)) rx_user_ctx_head_t;

int rx_user_ctx_init(eslab_t *rx_user_ctx_slab, uint32_t rx_depth);
void rx_user_ctx_uninit(eslab_t *rx_user_ctx_slab);

static ALWAYS_INLINE void *rx_user_ctx_get(queue_t *l_queue)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    if (URPC_UNLIKELY(local_q->rq_ctx->rx_user_ctx_slab.addr == NULL)) {
        return NULL;
    }

    rq_ctx_t *rq_ctx = local_q->rq_ctx;
    rx_user_ctx_head_t *ctx_head;
    if (URPC_LIKELY(rq_ctx->lock_free != 0)) {
        ctx_head = (rx_user_ctx_head_t *)eslab_get_buf_lockless(&rq_ctx->rx_user_ctx_slab);
    } else {
        ctx_head = (rx_user_ctx_head_t *)eslab_get_buf(&rq_ctx->rx_user_ctx_slab);
    }

    if (URPC_UNLIKELY(ctx_head == NULL)) {
        return NULL;
    }

    ctx_head->rq_ctx = rq_ctx;
    return (void *)ctx_head->buf;
}

static ALWAYS_INLINE void rx_user_ctx_put(void *ctx)
{
    if (URPC_UNLIKELY(ctx == NULL)) {
        return;
    }

    rx_user_ctx_head_t *ctx_head = CONTAINER_OF_FIELD(ctx, rx_user_ctx_head_t, buf);
    if (URPC_LIKELY(ctx_head->rq_ctx->lock_free != 0)) {
        eslab_put_buf_lockless(&ctx_head->rq_ctx->rx_user_ctx_slab, (void *)ctx_head);
        return;
    }

    eslab_put_buf(&ctx_head->rq_ctx->rx_user_ctx_slab, (void *)ctx_head);
}

static ALWAYS_INLINE void *rx_user_ctx_flush(queue_t *l_queue)
{
    queue_local_t *local_q = CONTAINER_OF_FIELD(l_queue, queue_local_t, queue);
    rq_ctx_t *rq_ctx = local_q->rq_ctx;

    /**
     * Draining the JFR requires that all queues sharing this JFR are set to the error state
     * meaning the ready_cnt count must be zero
     */
    if (URPC_UNLIKELY(rq_ctx->rx_user_ctx_slab.addr == NULL || rq_ctx->ready_cnt > 0)) {
        return NULL;
    }

    rx_user_ctx_head_t *ctx_head;
    if (URPC_LIKELY(rq_ctx->lock_free != 0)) {
        ctx_head = (rx_user_ctx_head_t *)eslab_get_first_used_object_lockless(&rq_ctx->rx_user_ctx_slab);
    } else {
        ctx_head = (rx_user_ctx_head_t *)eslab_get_first_used_object(&rq_ctx->rx_user_ctx_slab);
    }

    if (URPC_UNLIKELY(ctx_head == NULL)) {
        return NULL;
    }

    ctx_head->rq_ctx = rq_ctx;
    return (void *)ctx_head->buf;
}

typedef struct sges_stats {
    uint32_t normal_len; // not include dma sge len
    uint32_t dma_len;
    uint32_t record_cnt;
    uint32_t normal_cnt; // not include dma sge cnt
    uint32_t dma_cnt;
} sges_stats_t;

void queue_common_error_stats_record(urpc_error_stats_type_t type);

// only local queue support record/get stats
static ALWAYS_INLINE void queue_sge_stats_record(
    queue_t *queue, urpc_stats_type_t type, uint32_t sge_num, uint32_t completion_len)
{
    if (!is_queue_stats_enable()) {
        return;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);

    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ++local_q->stats[type];
        local_q->stats[type + QUEUE_STATS_TYPE_SGE_OFFSET] += sge_num;
        local_q->stats[type + QUEUE_STATS_TYPE_BYTES_OFFSET] += completion_len;
        return;
    }

    (void)__sync_add_and_fetch(&local_q->stats[type], 1);
    if (URPC_LIKELY(sge_num > 0)) {
        (void)__sync_add_and_fetch(&local_q->stats[type + QUEUE_STATS_TYPE_SGE_OFFSET],
            sge_num);
        (void)__sync_add_and_fetch(&local_q->stats[type + QUEUE_STATS_TYPE_BYTES_OFFSET],
            completion_len);
    }
}

static ALWAYS_INLINE void queue_dma_sge_stats_record(queue_t *queue, urpc_stats_type_t type, sges_stats_t *sge_stats)
{
    if (!is_queue_stats_enable()) {
        return;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        local_q->stats[type] += sge_stats->record_cnt;
        local_q->stats[type + QUEUE_STATS_TYPE_SGE_OFFSET] += sge_stats->normal_cnt;
        local_q->stats[type + QUEUE_STATS_TYPE_BYTES_OFFSET] += sge_stats->normal_len;
        local_q->stats[type + QUEUE_STATS_TYPE_DMA_SGE_OFFSET] += sge_stats->dma_cnt;
        local_q->stats[type + QUEUE_STATS_TYPE_DMA_BYTES_OFFSET] += sge_stats->dma_len;
        return;
    }

    (void)__sync_add_and_fetch(&local_q->stats[type], sge_stats->record_cnt);
    (void)__sync_add_and_fetch(&local_q->stats[type + QUEUE_STATS_TYPE_SGE_OFFSET], sge_stats->normal_cnt);
    (void)__sync_add_and_fetch(&local_q->stats[type + QUEUE_STATS_TYPE_BYTES_OFFSET], sge_stats->normal_len);
    if (URPC_UNLIKELY(sge_stats->dma_cnt > 0)) {
        (void)__sync_add_and_fetch(&local_q->stats[type + QUEUE_STATS_TYPE_DMA_SGE_OFFSET], sge_stats->dma_cnt);
        (void)__sync_add_and_fetch(&local_q->stats[type + QUEUE_STATS_TYPE_DMA_BYTES_OFFSET], sge_stats->dma_len);
    }
}

static ALWAYS_INLINE bool is_manager_queue(urpc_queue_flag_t flag)
{
    return (flag.is_keepalive == URPC_TRUE);
}

static ALWAYS_INLINE void queue_error_stats_record(queue_t *queue, urpc_error_stats_type_t type)
{
    if (!is_queue_stats_enable()) {
        return;
    }

    if (URPC_UNLIKELY(queue == NULL)) {
        queue_common_error_stats_record(type);
        return;
    }

    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ++local_q->error_stats[type];
        return;
    }
    (void)__sync_add_and_fetch(&local_q->error_stats[type], 1);
}

void queue_stats_get(queue_t *queue, uint64_t *stats, int stats_len);
void queue_error_stats_get(queue_t *queue, uint64_t *stats, int stats_len);

static ALWAYS_INLINE bool queue_use_default_allocator(urpc_queue_flag_t flag)
{
    return (flag.is_keepalive != 0);
}

static ALWAYS_INLINE bool is_queue_need_advise(queue_t *l_queue, queue_t *r_queue)
{
    return (l_queue->flag.is_keepalive == r_queue->flag.is_keepalive);
}

static ALWAYS_INLINE bool is_queue_flag_same(urpc_queue_flag_t flag1, urpc_queue_flag_t flag2)
{
    return (flag1.is_remote == flag2.is_remote) && (flag1.is_keepalive == flag2.is_keepalive);
}

static ALWAYS_INLINE void queue_stats_record(queue_t *queue, urpc_stats_type_t type)
{
    if (!is_queue_stats_enable()) {
        return;
    }
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ++local_q->stats[type];
        return;
    }
    (void)__sync_add_and_fetch(&local_q->stats[type], 1);
}


static ALWAYS_INLINE void queue_io_sended_stats_record(uint16_t call_mode, queue_t *queue)
{
    if (!is_queue_stats_enable()) {
        return;
    }

    urpc_stats_type_t table[IO_MODE_MAX] = {
        STATS_TYPE_NORMAL_WITHOUT_ACK_REQ_SENDED,
        STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ_SENDED,
        STATS_TYPE_NORMAL_WITH_ACK_REQ_SENDED,
        STATS_TYPE_EARLY_RSP_WITH_ACK_REQ_SENDED
    };
    uint16_t mode = call_mode & (FUNC_CALL_MODE_EARLY_RSP | FUNC_CALL_MODE_ACK);
    if (mode >= IO_MODE_MAX) {
        return;
    }

    urpc_stats_type_t type = table[mode];
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ++local_q->stats[type];
        return;
    }

    (void)__sync_add_and_fetch(&local_q->stats[type], 1);
}

static ALWAYS_INLINE void queue_io_req_error_stats_record(uint16_t call_mode, queue_t *queue) {
    if (!is_queue_stats_enable()) {
        return;
    }

    urpc_error_stats_type_t table[IO_MODE_MAX] = {
        ERR_STATS_TYPE_NORMAL_WITHOUT_ACK_REQ,
        ERR_STATS_TYPE_EARLY_RSP_WITHOUT_ACK_REQ,
        ERR_STATS_TYPE_NORMAL_WITH_ACK_REQ,
        ERR_STATS_TYPE_EARLY_RSP_WITH_ACK_REQ
    };
    urpc_error_stats_type_t type = ERR_STATS_TYPE_MAX;

    uint16_t mode = call_mode & (FUNC_CALL_MODE_EARLY_RSP | FUNC_CALL_MODE_ACK);
    if (mode >= IO_MODE_MAX) {
        return;
    }

    type = table[mode];
    queue_local_t *local_q = CONTAINER_OF_FIELD(queue, queue_local_t, queue);
    if (URPC_LIKELY(local_q->cfg.lock_free != 0)) {
        ++local_q->error_stats[type];
        return;
    }
    (void)__sync_add_and_fetch(&local_q->error_stats[type], 1);
}

void queue_common_error_stats_get(uint64_t *stats, int stats_len);

const char *queue_stats_name_get(int type);

const char *queue_error_stats_name_get(int type);

void flush_callback(queue_t *queue, void *data, int status_code, flush_type_t type);

int urpc_instance_key_fill(urpc_instance_key_t *key);
uint32_t urpc_instance_key_hash(urpc_instance_key_t *key);
bool urpc_instance_key_cmp(urpc_instance_key_t *key1, urpc_instance_key_t *key2);

uint32_t urpc_get_local_qh(uint64_t **qh_list);

#ifdef __cplusplus
}
#endif

#endif
