/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Token proxy module implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-12
 * Note:
 * History: 2026-05-12  Create File
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "ums_agent_log.h"
#include "ums_agent_utils.h"
#include "ums_agent_list.h"
#include "ums_agent_nl.h"
#include "ums_agent_tls_conn.h"
#include "ums_agent_token_proxy.h"

#define UMS_AGENT_MSG_MAGIC                          0x554D5341
#define UMS_AGENT_VERSION                            1
#define UMS_AGENT_MAX_MSG_LEN                        4096
#define UMS_AGENT_TOKEN_ENTRY_PENDING_TIMEOUT_SEC    10
#define UMS_AGENT_RECV_BUF_SIZE                      (UMS_AGENT_MAX_MSG_LEN * 2)
#define UMS_AGENT_SEND_BUF_SIZE                      (UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN)
#define UMS_AGENT_MAX_RECV_ITERATIONS                16

enum ums_agent_cipher_id {
    UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384 = 1,
};

enum ums_agent_msg_type {
    UMS_AGENT_MSG_TOKEN_TRANSFER = 1,
};

struct ums_agent_msg_hdr {
    uint32_t magic;

    /*
     * DFX tracing only, not validated;
     * TCP guarantees ordering, TLS AEAD guarantees integrity
     */
    uint32_t seqno;

    uint16_t payload_len;
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  cipher_id;
    uint8_t  reserved[3];
} __attribute__((packed));

struct ums_agent_token_transfer {
    uint32_t clc_id;
    uint8_t  id_for_peer[UMS_SYSTEMID_LEN];
    uint32_t jetty_token_value;
    uint32_t seg_token_value;
    union {
        uint8_t value;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        struct {
            uint8_t first_contact : 1;
            uint8_t reserved     : 7;
        } bs;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        struct {
            uint8_t reserved     : 7;
            uint8_t first_contact : 1;
        } bs;
#endif
    } flags;
    uint8_t  reserved[3];
} __attribute__((packed));

#define UMS_AGENT_MSG_HDR_LEN          sizeof(struct ums_agent_msg_hdr)
#define UMS_AGENT_TOKEN_TRANSFER_LEN   sizeof(struct ums_agent_token_transfer)

struct ums_agent_pending_entry {
    struct ums_token_entry entry;
    struct timespec submit_time;
    struct ums_agent_list_node node;
};

struct ums_agent_conn_ctx {
    uint32_t tx_seqno;
    uint8_t recv_buf[UMS_AGENT_RECV_BUF_SIZE];
    uint32_t recv_len;
    uint8_t send_buf[UMS_AGENT_SEND_BUF_SIZE];
    uint32_t send_len;
    uint32_t send_offset;
};

struct ums_agent_token_proxy {
    bool initialized;
    uint16_t listen_port;
    struct ums_agent_list_node pending_list;
    GHashTable *conn_ctx_ht;
};

static struct ums_agent_token_proxy g_ums_agent_tp = {0};

static void ums_agent_tp_notify_token_deliver(uint32_t clc_id,
    uint32_t peer_jetty_token, uint32_t peer_seg_token,
    uint8_t first_contact)
{
    int ret = ums_agent_nl_send_token_deliver(clc_id,
        peer_jetty_token, peer_seg_token, first_contact);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("TOKEN_DELIVER send failed, clc_id=%u, "
            "kernel will timeout", clc_id);
    }
}

static void ums_agent_tp_notify_token_submit_fail(uint32_t clc_id, int result)
{
    int ret = ums_agent_nl_send_token_submit_fail(clc_id, result);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("TOKEN_SUBMIT_FAIL send failed, clc_id=%u, "
            "kernel will timeout", clc_id);
    }
}

static struct ums_agent_pending_entry *ums_agent_pending_entry_create(
    const struct ums_token_entry *entry)
{
    struct ums_agent_pending_entry *p = calloc(1, sizeof(*p));
    if (!p) {
        UMS_AGENT_LOG_ERR("failed to allocate pending entry");
        return NULL;
    }
    p->entry = *entry;
    ums_agent_get_monotonic_time(&p->submit_time);
    ums_agent_list_init(&p->node);
    return p;
}

static void ums_agent_pending_entry_destroy(struct ums_agent_pending_entry *p)
{
    ums_agent_secure_zero(&p->entry.jetty_token_value, sizeof(p->entry.jetty_token_value));
    ums_agent_secure_zero(&p->entry.seg_token_value, sizeof(p->entry.seg_token_value));
    free(p);
}

static void ums_agent_pending_entry_enqueue(struct ums_agent_pending_entry *p)
{
    ums_agent_list_add_tail(&p->node, &g_ums_agent_tp.pending_list);
}

static void ums_agent_pending_entry_dequeue(struct ums_agent_pending_entry *target)
{
    ums_agent_list_remove(&target->node);
}

static bool ums_agent_pending_entry_match(const struct ums_agent_pending_entry *p,
    const struct ums_agent_ip_addr *addr)
{
    return ums_agent_ip_addr_equal(&p->entry.dst_addr, addr);
}

static bool ums_agent_tp_has_pending_for_peer(const struct ums_agent_ip_addr *addr)
{
    struct ums_agent_list_node *pos;
    ums_agent_list_for_each(pos, &g_ums_agent_tp.pending_list) {
        struct ums_agent_pending_entry *p =
            ums_agent_list_entry(pos, struct ums_agent_pending_entry, node);
        if (ums_agent_pending_entry_match(p, addr)) {
            return true;
        }
    }
    return false;
}

static void ums_agent_conn_ctx_destroy(void *data)
{
    struct ums_agent_conn_ctx *ctx = data;
    if (!ctx) {
        return;
    }
    ums_agent_secure_zero(ctx->recv_buf, ctx->recv_len);
    ums_agent_secure_zero(ctx->send_buf, ctx->send_len);
    free(ctx);
}

static struct ums_agent_conn_ctx *ums_agent_conn_ctx_get(struct ums_agent_tls_conn *conn)
{
    struct ums_agent_conn_ctx *ctx =
        g_hash_table_lookup(g_ums_agent_tp.conn_ctx_ht, conn);
    if (ctx) {
        return ctx;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        UMS_AGENT_LOG_ERR("failed to allocate conn context");
        return NULL;
    }
    g_hash_table_insert(g_ums_agent_tp.conn_ctx_ht, conn, ctx);
    return ctx;
}

static void ums_agent_conn_ctx_remove(struct ums_agent_tls_conn *conn)
{
    g_hash_table_remove(g_ums_agent_tp.conn_ctx_ht, conn);
}

static struct ums_agent_conn_ctx *ums_agent_conn_ctx_find(struct ums_agent_tls_conn *conn)
{
    return g_hash_table_lookup(g_ums_agent_tp.conn_ctx_ht, conn);
}

static void ums_agent_tp_serialize_msg_hdr(struct ums_agent_conn_ctx *ctx,
    struct ums_agent_msg_hdr *hdr)
{
    hdr->magic = htonl(UMS_AGENT_MSG_MAGIC);
    hdr->seqno = htonl(ctx->tx_seqno);
    hdr->payload_len = htons(UMS_AGENT_TOKEN_TRANSFER_LEN);
    hdr->version = UMS_AGENT_VERSION;
    hdr->msg_type = UMS_AGENT_MSG_TOKEN_TRANSFER;
    hdr->cipher_id = UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384;
    memset(hdr->reserved, 0, sizeof(hdr->reserved));
}

static void ums_agent_tp_serialize_token_transfer(const struct ums_token_entry *entry,
    struct ums_agent_token_transfer *payload)
{
    payload->clc_id = htonl(entry->clc_id);
    memcpy(payload->id_for_peer, entry->id_for_peer, UMS_SYSTEMID_LEN);
    payload->jetty_token_value = htonl(entry->jetty_token_value);
    payload->seg_token_value = htonl(entry->seg_token_value);
    payload->flags.value = 0;
    payload->flags.bs.first_contact = entry->first_contact;
    memset(payload->reserved, 0, sizeof(payload->reserved));
}

static void ums_agent_tp_deserialize_msg_hdr(const struct ums_agent_msg_hdr *raw,
    struct ums_agent_msg_hdr *out)
{
    out->magic = ntohl(raw->magic);
    out->seqno = ntohl(raw->seqno);
    out->payload_len = ntohs(raw->payload_len);
    out->version = raw->version;
    out->msg_type = raw->msg_type;
    out->cipher_id = raw->cipher_id;
    memcpy(out->reserved, raw->reserved, sizeof(out->reserved));
}

static void ums_agent_tp_deserialize_token_transfer(const struct ums_agent_token_transfer *raw,
    struct ums_agent_token_transfer *out)
{
    out->clc_id = ntohl(raw->clc_id);
    memcpy(out->id_for_peer, raw->id_for_peer, UMS_SYSTEMID_LEN);
    out->jetty_token_value = ntohl(raw->jetty_token_value);
    out->seg_token_value = ntohl(raw->seg_token_value);
    out->flags.value = raw->flags.value;
    memcpy(out->reserved, raw->reserved, sizeof(out->reserved));
}

static bool ums_agent_tp_conn_has_pending_send(struct ums_agent_conn_ctx *ctx)
{
    return ctx && ctx->send_len > ctx->send_offset;
}

static int ums_agent_tp_flush_send_buf(struct ums_agent_tls_conn *conn,
    struct ums_agent_conn_ctx *ctx)
{
    while (ctx->send_offset < ctx->send_len) {
        int ret = ums_agent_tls_conn_send(conn,
            ctx->send_buf + ctx->send_offset,
            ctx->send_len - ctx->send_offset);
        if (ret == 0) {
            char ip_str[INET6_ADDRSTRLEN] = {0};
            ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
            UMS_AGENT_LOG_ERR("TLS send returned 0 bytes, peer=%s:%u",
                ip_str, conn->peer_port);
            return -EIO;
        }
        if (ret < 0) {
            if (ret == -EAGAIN) {
                return -EAGAIN;
            }
            char ip_str[INET6_ADDRSTRLEN] = {0};
            ums_agent_ip_addr_to_str(&conn->peer_addr, ip_str, sizeof(ip_str));
            UMS_AGENT_LOG_ERR("TLS send failed, peer=%s:%u",
                ip_str, conn->peer_port);
            return -EIO;
        }

        ctx->send_offset += (uint32_t)ret;
    }

    ums_agent_secure_zero(ctx->send_buf, ctx->send_len);
    ctx->send_len = 0;
    ctx->send_offset = 0;
    ctx->tx_seqno++;
    return 0;
}

static int ums_agent_tp_send_entry(struct ums_agent_tls_conn *conn,
    const struct ums_token_entry *entry)
{
    struct ums_agent_conn_ctx *ctx = ums_agent_conn_ctx_get(conn);
    if (!ctx) {
        UMS_AGENT_LOG_ERR("failed to get conn context for send");
        return -ENOMEM;
    }

    if (ums_agent_tp_conn_has_pending_send(ctx)) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&entry->dst_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_WARN("send buffer busy, dropping entry, clc_id=%u, peer=%s:%u",
            entry->clc_id, ip_str, conn->peer_port);
        return -EBUSY;
    }

    struct ums_agent_msg_hdr hdr;
    struct ums_agent_token_transfer payload;

    ums_agent_tp_serialize_msg_hdr(ctx, &hdr);
    ums_agent_tp_serialize_token_transfer(entry, &payload);

    memcpy(ctx->send_buf, &hdr, UMS_AGENT_MSG_HDR_LEN);
    memcpy(ctx->send_buf + UMS_AGENT_MSG_HDR_LEN, &payload, UMS_AGENT_TOKEN_TRANSFER_LEN);
    ctx->send_len = UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN;
    ctx->send_offset = 0;

    ums_agent_secure_zero(&payload, sizeof(payload));

    int ret = ums_agent_tp_flush_send_buf(conn, ctx);
    if (ret == -EAGAIN) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(&entry->dst_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_DEBUG("TLS send pending (EAGAIN), clc_id=%u, peer=%s:%u",
            entry->clc_id, ip_str, conn->peer_port);
        return 0;
    }
    if (ret < 0) {
        return ret;
    }

    UMS_AGENT_LOG_DEBUG("TOKEN_TRANSFER sent, clc_id=%u, first_contact=%u",
        entry->clc_id, entry->first_contact);
    return 0;
}

static int ums_agent_tp_validate_msg_hdr(const struct ums_agent_msg_hdr *hdr,
    const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port)
{
    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));

    if (hdr->magic != UMS_AGENT_MSG_MAGIC) {
        UMS_AGENT_LOG_WARN("invalid magic=0x%08x from %s:%u, expected=0x%08x",
            hdr->magic, ip_str, peer_port, UMS_AGENT_MSG_MAGIC);
        return -EBADMSG;
    }

    if (hdr->version != UMS_AGENT_VERSION) {
        UMS_AGENT_LOG_WARN("unsupported version=%u from %s:%u",
            hdr->version, ip_str, peer_port);
        return -EBADMSG;
    }

    if (hdr->msg_type != UMS_AGENT_MSG_TOKEN_TRANSFER) {
        UMS_AGENT_LOG_WARN("invalid msg_type=%u from %s:%u",
            hdr->msg_type, ip_str, peer_port);
        return -EBADMSG;
    }

    if (hdr->payload_len > UMS_AGENT_MAX_MSG_LEN - UMS_AGENT_MSG_HDR_LEN) {
        UMS_AGENT_LOG_WARN("payload_len=%u exceeds max from %s:%u",
            hdr->payload_len, ip_str, peer_port);
        return -EBADMSG;
    }

    return 0;
}

static int ums_agent_tp_validate_token_transfer(const struct ums_agent_msg_hdr *hdr,
    const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port)
{
    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));

    if (hdr->payload_len != UMS_AGENT_TOKEN_TRANSFER_LEN) {
        UMS_AGENT_LOG_WARN("payload_len=%u mismatch, expected=%zu, from %s:%u",
            hdr->payload_len, UMS_AGENT_TOKEN_TRANSFER_LEN,
            ip_str, peer_port);
        return -EBADMSG;
    }

    if (hdr->cipher_id != UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384) {
        UMS_AGENT_LOG_WARN("cipher_id=%u mismatch from %s:%u",
            hdr->cipher_id, ip_str, peer_port);
        return -EBADMSG;
    }

    return 0;
}

static void ums_agent_tp_process_pending_for_conn(struct ums_agent_tls_conn *conn,
    const struct ums_agent_ip_addr *addr, int status)
{
    struct ums_agent_list_node *pos;
    struct ums_agent_list_node *n;
    ums_agent_list_for_each_safe(pos, n, &g_ums_agent_tp.pending_list) {
        struct ums_agent_pending_entry *cur =
            ums_agent_list_entry(pos, struct ums_agent_pending_entry, node);

        if (!ums_agent_pending_entry_match(cur, addr)) {
            continue;
        }

        ums_agent_pending_entry_dequeue(cur);

        if (status != 0) {
            UMS_AGENT_LOG_ERR("pending entry failed, clc_id=%u, result=%d",
                cur->entry.clc_id, status);
            ums_agent_tp_notify_token_submit_fail(cur->entry.clc_id, ECONNREFUSED);
            ums_agent_pending_entry_destroy(cur);
        } else {
            int ret = ums_agent_tp_send_entry(conn, &cur->entry);
            if (ret != 0) {
                ums_agent_tp_notify_token_submit_fail(cur->entry.clc_id, -ret);
            }
            ums_agent_pending_entry_destroy(cur);
        }
    }
}

static void ums_agent_tp_on_connect_complete(
    struct ums_agent_tls_conn *conn, int status, void *user_data)
{
    (void)user_data;

    if (!conn) {
        return;
    }

    const struct ums_agent_ip_addr *addr =
        ums_agent_tls_conn_get_peer_addr(conn);
    if (!addr) {
        return;
    }

    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(addr, ip_str, sizeof(ip_str));

    if (status != 0) {
        UMS_AGENT_LOG_ERR("TLS connect failed, peer=%s:%u",
            ip_str, conn->peer_port);
    } else {
        UMS_AGENT_LOG_DEBUG("TLS connect succeeded, peer=%s:%u",
            ip_str, conn->peer_port);
    }

    ums_agent_tp_process_pending_for_conn(conn, addr, status);
}

static int ums_agent_tp_process_one_msg(struct ums_agent_tls_conn *conn,
    const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port,
    const uint8_t *data, uint32_t len)
{
    if (len < UMS_AGENT_MSG_HDR_LEN) {
        return 0;
    }

    struct ums_agent_msg_hdr raw_hdr;
    memcpy(&raw_hdr, data, UMS_AGENT_MSG_HDR_LEN);

    struct ums_agent_msg_hdr hdr;
    ums_agent_tp_deserialize_msg_hdr(&raw_hdr, &hdr);

    int ret = ums_agent_tp_validate_msg_hdr(&hdr, peer_addr, peer_port);
    if (ret != 0) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_WARN("header validation failed, dropping connection %s:%u",
            ip_str, peer_port);
        return -EBADMSG;
    }

    uint16_t total_len = UMS_AGENT_MSG_HDR_LEN + hdr.payload_len;
    if (len < total_len) {
        return 0;
    }

    if (hdr.msg_type == UMS_AGENT_MSG_TOKEN_TRANSFER) {
        ret = ums_agent_tp_validate_token_transfer(&hdr, peer_addr, peer_port);
        if (ret != 0) {
            return -EBADMSG;
        }

        struct ums_agent_token_transfer raw_payload;
        memcpy(&raw_payload, data + UMS_AGENT_MSG_HDR_LEN,
            UMS_AGENT_TOKEN_TRANSFER_LEN);

        struct ums_agent_token_transfer msg;
        ums_agent_tp_deserialize_token_transfer(&raw_payload, &msg);

        char ip_str[INET6_ADDRSTRLEN] = {0};
        ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));
        UMS_AGENT_LOG_DEBUG("TOKEN_TRANSFER received, clc_id=%u, "
            "first_contact=%u, seqno=%u from %s:%u",
            msg.clc_id, msg.flags.bs.first_contact, hdr.seqno,
            ip_str, peer_port);

        ums_agent_tp_notify_token_deliver(msg.clc_id,
            msg.jetty_token_value, msg.seg_token_value,
            msg.flags.bs.first_contact);

        ums_agent_secure_zero(&msg.jetty_token_value, sizeof(msg.jetty_token_value));
        ums_agent_secure_zero(&msg.seg_token_value, sizeof(msg.seg_token_value));
        ums_agent_secure_zero(&raw_payload, sizeof(raw_payload));
    }

    return (int)total_len;
}

static int ums_agent_tp_process_recv_buf(struct ums_agent_tls_conn *conn,
    struct ums_agent_conn_ctx *ctx,
    const struct ums_agent_ip_addr *peer_addr, uint16_t peer_port)
{
    uint32_t consumed = 0;
    while (consumed < ctx->recv_len) {
        int msg_len = ums_agent_tp_process_one_msg(
            conn, peer_addr, peer_port,
            ctx->recv_buf + consumed, ctx->recv_len - consumed);
        if (msg_len == 0) {
            break;
        }
        if (msg_len < 0) {
            ums_agent_tls_conn_shutdown(conn);
            return msg_len;
        }
        consumed += (uint32_t)msg_len;
    }

    if (consumed > 0 && consumed < ctx->recv_len) {
        memmove(ctx->recv_buf, ctx->recv_buf + consumed,
            ctx->recv_len - consumed);
    }
    ctx->recv_len -= consumed;
    return 0;
}

static void ums_agent_tp_on_data_available(struct ums_agent_tls_conn *conn,
    void *user_data)
{
    (void)user_data;

    if (!conn) {
        return;
    }

    const struct ums_agent_ip_addr *peer_addr =
        ums_agent_tls_conn_get_peer_addr(conn);
    uint16_t peer_port = ums_agent_tls_conn_get_peer_port(conn);
    if (!peer_addr) {
        return;
    }

    struct ums_agent_conn_ctx *ctx = ums_agent_conn_ctx_get(conn);
    if (!ctx) {
        UMS_AGENT_LOG_ERR("failed to get conn context");
        ums_agent_tls_conn_shutdown(conn);
        return;
    }

    uint32_t iterations = 0;
    while (iterations < UMS_AGENT_MAX_RECV_ITERATIONS) {
        uint32_t avail = UMS_AGENT_RECV_BUF_SIZE - ctx->recv_len;
        if (avail == 0) {
            char ip_str[INET6_ADDRSTRLEN] = {0};
            ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));
            UMS_AGENT_LOG_WARN("recv buffer full, closing connection %s:%u",
                ip_str, peer_port);
            ums_agent_tls_conn_shutdown(conn);
            return;
        }

        int recv_len = ums_agent_tls_conn_recv(conn,
            ctx->recv_buf + ctx->recv_len, avail);
        if (recv_len < 0) {
            if (recv_len == -EAGAIN) {
                return;
            }
            char ip_str[INET6_ADDRSTRLEN] = {0};
            ums_agent_ip_addr_to_str(peer_addr, ip_str, sizeof(ip_str));
            UMS_AGENT_LOG_ERR("recv failed from %s:%u", ip_str, peer_port);
            ums_agent_tls_conn_shutdown(conn);
            return;
        }

        if (recv_len == 0) {
            ums_agent_tls_conn_shutdown(conn);
            return;
        }

        ctx->recv_len += (uint32_t)recv_len;

        int ret = ums_agent_tp_process_recv_buf(conn, ctx, peer_addr, peer_port);
        if (ret < 0) {
            return;
        }

        iterations++;
    }
}

static void ums_agent_tp_on_writable(struct ums_agent_tls_conn *conn,
    void *user_data)
{
    (void)user_data;

    if (!conn) {
        return;
    }

    struct ums_agent_conn_ctx *ctx = ums_agent_conn_ctx_find(conn);
    if (!ctx) {
        return;
    }

    if (!ums_agent_tp_conn_has_pending_send(ctx)) {
        return;
    }

    int ret = ums_agent_tp_flush_send_buf(conn, ctx);
    if (ret == -EAGAIN) {
        return;
    }
    if (ret < 0) {
        ums_agent_tls_conn_shutdown(conn);
        return;
    }

    UMS_AGENT_LOG_DEBUG("pending send completed, peer fd=%d", conn->fd);
}

static void ums_agent_tp_on_conn_close(
    struct ums_agent_tls_conn *conn, void *user_data)
{
    (void)user_data;

    if (!conn) {
        return;
    }

    ums_agent_conn_ctx_remove(conn);
}

static int ums_agent_tp_on_token_submit(struct ums_token_entry *entry)
{
    if (!g_ums_agent_tp.initialized) {
        UMS_AGENT_LOG_WARN("token proxy not initialized, rejecting submit");
        return -EINVAL;
    }

    if (!entry) {
        UMS_AGENT_LOG_ERR("entry is NULL");
        return -EINVAL;
    }

    int ret;
    struct ums_agent_tls_conn *conn = ums_agent_tls_conn_pool_get(
        &entry->dst_addr);
    if (conn) {
        ret = ums_agent_tp_send_entry(conn, entry);
        ums_agent_tls_conn_pool_put(conn);
        return ret;
    }

    bool need_connect = !ums_agent_tp_has_pending_for_peer(
        &entry->dst_addr);

    struct ums_agent_pending_entry *p =
        ums_agent_pending_entry_create(entry);
    if (!p) {
        return -ENOMEM;
    }
    ums_agent_pending_entry_enqueue(p);

    char ip_str[INET6_ADDRSTRLEN] = {0};
    ums_agent_ip_addr_to_str(&entry->dst_addr, ip_str, sizeof(ip_str));

    if (!need_connect) {
        UMS_AGENT_LOG_DEBUG("TOKEN_SUBMIT queued, clc_id=%u, peer=%s:%u "
            "(connection pending)", entry->clc_id, ip_str,
            g_ums_agent_tp.listen_port);
        return 0;
    }

    ret = ums_agent_tls_conn_connect(&entry->dst_addr, g_ums_agent_tp.listen_port);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("TLS connect failed for %s:%u", ip_str,
            g_ums_agent_tp.listen_port);
        ums_agent_pending_entry_dequeue(p);
        ums_agent_pending_entry_destroy(p);
        return -ECONNREFUSED;
    }

    UMS_AGENT_LOG_DEBUG("TOKEN_SUBMIT queued, clc_id=%u, peer=%s:%u",
        entry->clc_id, ip_str, g_ums_agent_tp.listen_port);
    return 0;
}

static void ums_agent_tp_check_pending_timeout(void)
{
    struct timespec now;
    ums_agent_get_monotonic_time(&now);

    struct ums_agent_list_node *pos;
    struct ums_agent_list_node *n;
    ums_agent_list_for_each_safe(pos, n, &g_ums_agent_tp.pending_list) {
        struct ums_agent_pending_entry *cur =
            ums_agent_list_entry(pos, struct ums_agent_pending_entry, node);

        int64_t elapsed = ums_agent_timespec_diff_sec(&cur->submit_time, &now);
        if (elapsed >= UMS_AGENT_TOKEN_ENTRY_PENDING_TIMEOUT_SEC) {
            UMS_AGENT_LOG_WARN("pending entry timed out, clc_id=%u, "
                "elapsed=%lds", cur->entry.clc_id, (long)elapsed);
            ums_agent_pending_entry_dequeue(cur);
            ums_agent_tp_notify_token_submit_fail(cur->entry.clc_id, ETIMEDOUT);
            ums_agent_pending_entry_destroy(cur);
        }
    }
}

static const struct ums_agent_tls_conn_ops g_ums_agent_tp_conn_ops = {
    .on_connect_complete = ums_agent_tp_on_connect_complete,
    .on_data_available = ums_agent_tp_on_data_available,
    .on_writable = ums_agent_tp_on_writable,
    .on_close = ums_agent_tp_on_conn_close,
    .user_data = NULL,
};

int ums_agent_tp_init(uint16_t listen_port)
{
    if (g_ums_agent_tp.initialized) {
        UMS_AGENT_LOG_WARN("token proxy already initialized");
        return 0;
    }

    memset(&g_ums_agent_tp, 0, sizeof(g_ums_agent_tp));
    ums_agent_list_init(&g_ums_agent_tp.pending_list);
    g_ums_agent_tp.listen_port = listen_port;

    g_ums_agent_tp.conn_ctx_ht = g_hash_table_new_full(
        g_direct_hash, g_direct_equal, NULL,
        ums_agent_conn_ctx_destroy);
    if (!g_ums_agent_tp.conn_ctx_ht) {
        UMS_AGENT_LOG_ERR("failed to create conn_ctx hash table");
        return -1;
    }

    ums_agent_tls_conn_register_ops(&g_ums_agent_tp_conn_ops);
    ums_agent_nl_set_token_submit_cb(ums_agent_tp_on_token_submit);
    g_ums_agent_tp.initialized = true;
    return 0;
}

void ums_agent_tp_deinit(void)
{
    if (!g_ums_agent_tp.initialized) {
        UMS_AGENT_LOG_WARN("token proxy not initialized");
        return;
    }

    ums_agent_nl_set_token_submit_cb(NULL);
    ums_agent_tls_conn_unregister_ops();

    if (g_ums_agent_tp.conn_ctx_ht) {
        g_hash_table_destroy(g_ums_agent_tp.conn_ctx_ht);
        g_ums_agent_tp.conn_ctx_ht = NULL;
    }

    struct ums_agent_list_node *pos;
    struct ums_agent_list_node *n;
    ums_agent_list_for_each_safe(pos, n, &g_ums_agent_tp.pending_list) {
        struct ums_agent_pending_entry *cur =
            ums_agent_list_entry(pos, struct ums_agent_pending_entry, node);
        ums_agent_pending_entry_dequeue(cur);
        ums_agent_tp_notify_token_submit_fail(cur->entry.clc_id, ESHUTDOWN);
        ums_agent_pending_entry_destroy(cur);
    }
    ums_agent_list_init(&g_ums_agent_tp.pending_list);

    g_ums_agent_tp.initialized = false;
}

void ums_agent_tp_timer_tick(void)
{
    if (!g_ums_agent_tp.initialized) {
        UMS_AGENT_LOG_WARN("token proxy not initialized");
        return;
    }

    ums_agent_tp_check_pending_timeout();
}
