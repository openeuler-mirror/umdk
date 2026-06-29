/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Unit tests for the UMS agent token proxy (token value exchange
 * between sender and receiver over TLS).
 *
 * Coverage: serialization/byte-order, header & payload validation, message
 * framing, pending-list lifecycle, send-path (full/EAGAIN/0/error), on_token_submit
 * dispatch, connect-complete, writable/close callbacks, pending-timeout and
 * init/deinit.
 *
 * The production TU (ums_agent_token_proxy.c) is #included so the
 * static functions are reachable. Its external dependencies (ums_agent_nl_*,
 * ums_agent_tls_conn_*, time/ip utils, logging) are replaced by controllable
 * mock stubs defined below. No real network or TLS is involved.
 */

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <openssl/ssl.h>

#include "ums_agent_token_proxy.c" /* NOLINT: white-box include of production TU */

/* ---------------------------------------------------------------------------
 * Mock state
 * ------------------------------------------------------------------------- */

struct mock_nl_deliver {
    bool called;
    int calls;
    uint32_t clc_session_id;
    uint8_t initiator_id[UMS_SYSTEMID_LEN];
    uint32_t peer_jetty_token;
    uint32_t peer_seg_token;
    uint8_t first_contact;
    int ret;
};

struct mock_nl_submit_fail {
    bool called;
    int calls;
    uint32_t clc_session_id;
    uint8_t initiator_id[UMS_SYSTEMID_LEN];
    int result;
    int ret;
};

struct mock_tls_send {
    bool called;
    int ret;
    uint32_t total_sent;
    uint8_t sink[UMS_AGENT_MAX_MSG_LEN * 2];
};

struct mock_tls_recv {
    const uint8_t *data;
    uint32_t len;
    uint32_t off;
    bool eof;
};

static struct {
    struct timespec now;

    struct mock_nl_deliver deliver;
    struct mock_nl_submit_fail submit_fail;
    ums_agent_nl_token_submit_cb submit_cb;

    struct mock_tls_send send;
    struct mock_tls_recv recv;

    int connect_ret;
    int connect_calls;

    int shutdown_calls;

    bool pool_get_hit;
    struct ums_agent_tls_conn fake_conn;
} g_mock;

static void mock_reset(void)
{
    memset(&g_mock, 0, sizeof(g_mock));
    g_mock.send.ret = -1;
}

/* ---------------------------------------------------------------------------
 * Mock: netlink dependency of token_proxy.c
 * ------------------------------------------------------------------------- */

int ums_agent_nl_send_token_deliver(uint32_t clc_session_id,
    const uint8_t *initiator_id, uint32_t peer_jetty_token,
    uint32_t peer_seg_token, uint8_t first_contact)
{
    g_mock.deliver.called = true;
    g_mock.deliver.calls++;
    g_mock.deliver.clc_session_id = clc_session_id;
    memcpy(g_mock.deliver.initiator_id, initiator_id, UMS_SYSTEMID_LEN);
    g_mock.deliver.peer_jetty_token = peer_jetty_token;
    g_mock.deliver.peer_seg_token = peer_seg_token;
    g_mock.deliver.first_contact = first_contact;
    return g_mock.deliver.ret;
}

int ums_agent_nl_send_token_submit_fail(uint32_t clc_session_id,
    const uint8_t *initiator_id, int result)
{
    g_mock.submit_fail.called = true;
    g_mock.submit_fail.calls++;
    g_mock.submit_fail.clc_session_id = clc_session_id;
    memcpy(g_mock.submit_fail.initiator_id, initiator_id, UMS_SYSTEMID_LEN);
    g_mock.submit_fail.result = result;
    return g_mock.submit_fail.ret;
}

void ums_agent_nl_set_token_submit_cb(ums_agent_nl_token_submit_cb cb)
{
    g_mock.submit_cb = cb;
}

/* ---------------------------------------------------------------------------
 * Mock: tls_conn dependency of token_proxy.c
 * ------------------------------------------------------------------------- */

void ums_agent_tls_conn_register_ops(const struct ums_agent_tls_conn_ops *ops) {}
void ums_agent_tls_conn_unregister_ops(void) {}

struct ums_agent_tls_conn *ums_agent_tls_conn_pool_get(
    const struct ums_agent_ip_addr *peer_addr)
{
    return g_mock.pool_get_hit ? &g_mock.fake_conn : NULL;
}

void ums_agent_tls_conn_pool_put(struct ums_agent_tls_conn *conn) {}

int ums_agent_tls_conn_connect(const struct ums_agent_ip_addr *peer_addr,
    uint16_t peer_port)
{
    g_mock.connect_calls++;
    return g_mock.connect_ret;
}

void ums_agent_tls_conn_shutdown(struct ums_agent_tls_conn *conn)
{
    g_mock.shutdown_calls++;
}

int ums_agent_tls_conn_send(struct ums_agent_tls_conn *conn,
    const void *data, uint32_t len)
{
    g_mock.send.called = true;
    if (g_mock.send.ret > 0) {
        uint32_t copy = (uint32_t)g_mock.send.ret;
        if (copy > len) {
            copy = len;
        }
        if (copy > sizeof(g_mock.send.sink) - g_mock.send.total_sent) {
            copy = sizeof(g_mock.send.sink) - g_mock.send.total_sent;
        }
        memcpy(g_mock.send.sink + g_mock.send.total_sent, data, copy);
        g_mock.send.total_sent += copy;
    }
    return g_mock.send.ret;
}

int ums_agent_tls_conn_recv(struct ums_agent_tls_conn *conn,
    void *buf, uint32_t buf_len)
{
    (void)conn;
    if (g_mock.recv.off >= g_mock.recv.len) {
        return g_mock.recv.eof ? 0 : -EAGAIN;
    }
    uint32_t avail = g_mock.recv.len - g_mock.recv.off;
    uint32_t n = (buf_len < avail) ? buf_len : avail;
    memcpy(buf, g_mock.recv.data + g_mock.recv.off, n);
    g_mock.recv.off += n;
    return (int)n;
}

const struct ums_agent_ip_addr *ums_agent_tls_conn_get_peer_addr(
    const struct ums_agent_tls_conn *conn)
{
    return &conn->peer_addr;
}

uint16_t ums_agent_tls_conn_get_peer_port(const struct ums_agent_tls_conn *conn)
{
    return conn->peer_port;
}

/* ---------------------------------------------------------------------------
 * Mock: time / ip utils used by token_proxy.c
 * ------------------------------------------------------------------------- */

void ums_agent_get_monotonic_time(struct timespec *ts)
{
    *ts = g_mock.now;
}

int64_t ums_agent_timespec_diff_sec(const struct timespec *start,
    const struct timespec *end)
{
    return (int64_t)(end->tv_sec - start->tv_sec);
}

bool ums_agent_ip_addr_equal(const struct ums_agent_ip_addr *a,
    const struct ums_agent_ip_addr *b)
{
    if (a->family != b->family) {
        return false;
    }
    if (a->family == AF_INET) {
        return a->ip.in4.s_addr == b->ip.in4.s_addr;
    }
    return memcmp(&a->ip.in6, &b->ip.in6, sizeof(a->ip.in6)) == 0;
}

struct ums_agent_ip_str ums_agent_ip_addr_fmt(const struct ums_agent_ip_addr *addr)
{
    struct ums_agent_ip_str s = {"<mock>"};
    return s;
}

void ums_agent_log_output(enum ums_agent_log_level level, const char *func,
    int line, const char *fmt, ...) {}

static struct ums_token_entry make_entry(uint32_t session, uint32_t jetty,
    uint32_t seg, uint8_t first_contact)
{
    struct ums_token_entry e;
    memset(&e, 0, sizeof(e));
    e.clc_session_id = session;
    e.jetty_token_value = jetty;
    e.seg_token_value = seg;
    e.first_contact = first_contact;
    e.dst_addr.family = AF_INET;
    e.dst_addr.ip.in4.s_addr = htonl(0x0a000001); /* 10.0.0.1 */
    for (int i = 0; i < UMS_SYSTEMID_LEN; i++) {
        e.initiator_id[i] = (uint8_t)(session + i);
    }
    return e;
}

static void drain_pending_list(void)
{
    struct ums_agent_list_node *pos;
    struct ums_agent_list_node *n;
    ums_agent_list_for_each_safe(pos, n, &g_ums_agent_tp.pending_list) {
        struct ums_agent_pending_entry *p =
            ums_agent_list_entry(pos, struct ums_agent_pending_entry, node);
        ums_agent_pending_entry_dequeue(p);
        ums_agent_pending_entry_destroy(p);
    }
}

static struct ums_agent_ip_addr make_addr_v4(uint32_t host_order_ip)
{
    struct ums_agent_ip_addr a = {};
    a.family = AF_INET;
    a.ip.in4.s_addr = htonl(host_order_ip);
    return a;
}

/*
 * prime_conn - make the mock connection look like an established, in-pool
 * connection to `host_order_ip`, and pre-create its conn_ctx (so the
 * on_token_submit "reuse idle conn" path is taken instead of falling through
 * to pending_entry_handler). Returns the primed ctx.
 */
static struct ums_agent_conn_ctx *prime_conn(struct ums_agent_tls_conn *conn,
    uint32_t host_order_ip)
{
    conn->peer_addr = make_addr_v4(host_order_ip);
    conn->peer_port = 0;
    g_mock.pool_get_hit = true;
    return ums_agent_conn_ctx_get(conn);
}

/* enqueue a pending entry whose dst_addr matches the primed conn. */
static struct ums_agent_pending_entry *enqueue_for_peer(uint32_t session,
    uint32_t host_order_ip)
{
    struct ums_token_entry e = make_entry(session, 0, 0, 0);
    e.dst_addr = make_addr_v4(host_order_ip);
    struct ums_agent_pending_entry *p = ums_agent_pending_entry_create(&e);
    ums_agent_pending_entry_enqueue(p);
    return p;
}

class TokenProxyTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        mock_reset();
        ASSERT_EQ(ums_agent_tp_init(0), 0);
    }
    void TearDown() override
    {
        ums_agent_tp_deinit();
        drain_pending_list();
    }
};

/* ---------------------------------------------------------------------------
 * Serialization round-trip (byte order is htonl/ntohl)
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, SerializeDeserializeHdrRoundTrip)
{
    struct ums_agent_conn_ctx ctx = {};
    ctx.tx_seqno = 0x11223344;

    struct ums_agent_msg_hdr hdr;
    ums_agent_tp_serialize_msg_hdr(&ctx, &hdr);

    EXPECT_EQ(hdr.magic, htonl(UMS_AGENT_MSG_MAGIC));
    EXPECT_EQ(hdr.seqno, htonl(0x11223344));
    EXPECT_EQ(hdr.payload_len, htons(UMS_AGENT_TOKEN_TRANSFER_LEN));
    EXPECT_EQ(hdr.version, (uint8_t)UMS_AGENT_VERSION);
    EXPECT_EQ(hdr.msg_type, (uint8_t)UMS_AGENT_MSG_TOKEN_TRANSFER);
    EXPECT_EQ(hdr.cipher_id, (uint8_t)UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384);

    struct ums_agent_msg_hdr out;
    ums_agent_tp_deserialize_msg_hdr(&hdr, &out);
    EXPECT_EQ(out.seqno, (uint32_t)0x11223344);
    EXPECT_EQ(out.payload_len, (uint16_t)UMS_AGENT_TOKEN_TRANSFER_LEN);
}

TEST_F(TokenProxyTest, SerializeTokenTransferRoundTrip)
{
    struct ums_token_entry e =
        make_entry(0xAABBCCDD, 0x12345678, 0xCAFEBABE, 1);

    struct ums_agent_token_transfer raw;
    ums_agent_tp_serialize_token_transfer(&e, &raw);

    /* wire values must be network byte order */
    EXPECT_EQ(raw.clc_session_id, htonl(0xAABBCCDD));
    EXPECT_EQ(raw.jetty_token_value, htonl(0x12345678));
    EXPECT_EQ(raw.seg_token_value, htonl(0xCAFEBABE));
    EXPECT_EQ(raw.flags.bs.first_contact, 1);

    struct ums_agent_token_transfer out;
    ums_agent_tp_deserialize_token_transfer(&raw, &out);
    EXPECT_EQ(out.clc_session_id, (uint32_t)0xAABBCCDD);
    EXPECT_EQ(out.jetty_token_value, (uint32_t)0x12345678);
    EXPECT_EQ(out.seg_token_value, (uint32_t)0xCAFEBABE);
    EXPECT_EQ(out.flags.bs.first_contact, 1);
}

/* ---------------------------------------------------------------------------
 * Header / payload validation
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, ValidateHdrRejectsBadMagic)
{
    struct ums_agent_ip_addr addr = {};
    struct ums_agent_msg_hdr hdr = {};
    hdr.magic = UMS_AGENT_MSG_MAGIC + 1;
    hdr.version = UMS_AGENT_VERSION;
    hdr.msg_type = UMS_AGENT_MSG_TOKEN_TRANSFER;
    hdr.payload_len = UMS_AGENT_TOKEN_TRANSFER_LEN;
    EXPECT_LT(ums_agent_tp_validate_msg_hdr(&hdr, &addr, 0), 0);
}

TEST_F(TokenProxyTest, ValidateHdrRejectsBadVersionAndMsgType)
{
    struct ums_agent_ip_addr addr = {};
    struct ums_agent_msg_hdr hdr = {};
    hdr.magic = UMS_AGENT_MSG_MAGIC;
    hdr.version = UMS_AGENT_VERSION + 1;
    hdr.msg_type = UMS_AGENT_MSG_TOKEN_TRANSFER;
    hdr.payload_len = UMS_AGENT_TOKEN_TRANSFER_LEN;
    EXPECT_LT(ums_agent_tp_validate_msg_hdr(&hdr, &addr, 0), 0);

    hdr.version = UMS_AGENT_VERSION;
    hdr.msg_type = (uint8_t)~UMS_AGENT_MSG_TOKEN_TRANSFER;
    EXPECT_LT(ums_agent_tp_validate_msg_hdr(&hdr, &addr, 0), 0);
}

TEST_F(TokenProxyTest, ValidateHdrRejectsOversizedPayload)
{
    struct ums_agent_ip_addr addr = {};
    struct ums_agent_msg_hdr hdr = {};
    hdr.magic = UMS_AGENT_MSG_MAGIC;
    hdr.version = UMS_AGENT_VERSION;
    hdr.msg_type = UMS_AGENT_MSG_TOKEN_TRANSFER;
    hdr.payload_len = (uint16_t)(UMS_AGENT_MAX_MSG_LEN); /* exceeds max */
    EXPECT_LT(ums_agent_tp_validate_msg_hdr(&hdr, &addr, 0), 0);
}

TEST_F(TokenProxyTest, ValidateTokenTransferRejectsMismatchedLenAndCipher)
{
    struct ums_agent_ip_addr addr = {};
    struct ums_agent_msg_hdr hdr = {};
    hdr.magic = UMS_AGENT_MSG_MAGIC;
    hdr.msg_type = UMS_AGENT_MSG_TOKEN_TRANSFER;

    hdr.payload_len = UMS_AGENT_TOKEN_TRANSFER_LEN - 1;
    hdr.cipher_id = UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384;
    EXPECT_LT(ums_agent_tp_validate_token_transfer(&hdr, &addr, 0), 0);

    hdr.payload_len = UMS_AGENT_TOKEN_TRANSFER_LEN;
    hdr.cipher_id = UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384 + 1;
    EXPECT_LT(ums_agent_tp_validate_token_transfer(&hdr, &addr, 0), 0);

    hdr.cipher_id = UMS_AGENT_CIPHER_TLS_AES_256_GCM_SHA384;
    EXPECT_EQ(ums_agent_tp_validate_token_transfer(&hdr, &addr, 0), 0);
}

/* ---------------------------------------------------------------------------
 * Message framing
 * ------------------------------------------------------------------------- */

static void build_wire_msg(uint8_t *buf, const struct ums_token_entry *e)
{
    struct ums_agent_conn_ctx ctx = {};
    struct ums_agent_msg_hdr hdr;
    struct ums_agent_token_transfer payload;
    ums_agent_tp_serialize_msg_hdr(&ctx, &hdr);
    ums_agent_tp_serialize_token_transfer(e, &payload);
    memcpy(buf, &hdr, UMS_AGENT_MSG_HDR_LEN);
    memcpy(buf + UMS_AGENT_MSG_HDR_LEN, &payload, UMS_AGENT_TOKEN_TRANSFER_LEN);
}

TEST_F(TokenProxyTest, ProcessOneMsg_PartialHeaderWaits)
{
    struct ums_agent_ip_addr addr = {};
    uint8_t buf[UMS_AGENT_MSG_HDR_LEN - 1];
    int ret = ums_agent_tp_process_one_msg(&addr, 0, buf, sizeof(buf));
    EXPECT_EQ(ret, 0); /* need more data */
}

TEST_F(TokenProxyTest, ProcessOneMsg_PartialPayloadWaits)
{
    struct ums_agent_ip_addr addr = {};
    uint8_t full[UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN];
    struct ums_token_entry e = make_entry(7, 0, 0x55, 0);
    build_wire_msg(full, &e);

    int ret = ums_agent_tp_process_one_msg(&addr, 0, full,
        UMS_AGENT_MSG_HDR_LEN + 1);
    EXPECT_EQ(ret, 0);
}

TEST_F(TokenProxyTest, ProcessOneMsg_CompleteDeliversAndReturnsTotalLen)
{
    struct ums_agent_ip_addr addr = {};
    uint8_t full[UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN];
    struct ums_token_entry e = make_entry(42, 0x1111, 0x2222, 1);
    build_wire_msg(full, &e);

    int ret = ums_agent_tp_process_one_msg(&addr, 0, full, sizeof(full));
    EXPECT_EQ(ret, (int)sizeof(full));
    EXPECT_TRUE(g_mock.deliver.called);
    EXPECT_EQ(g_mock.deliver.clc_session_id, (uint32_t)42);
    EXPECT_EQ(g_mock.deliver.peer_seg_token, (uint32_t)0x2222);
    EXPECT_EQ(g_mock.deliver.peer_jetty_token, (uint32_t)0x1111);
    EXPECT_EQ(g_mock.deliver.first_contact, (uint8_t)1);
}

TEST_F(TokenProxyTest, ProcessOneMsg_TwoMessagesBackToBack)
{
    struct ums_agent_ip_addr addr = {};
    uint8_t buf[2 * (UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN)];
    struct ums_token_entry e1 = make_entry(1, 0, 0xA1, 0);
    struct ums_token_entry e2 = make_entry(2, 0, 0xA2, 0);
    build_wire_msg(buf, &e1);
    build_wire_msg(buf + UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN, &e2);

    int off = 0;
    int r1 = ums_agent_tp_process_one_msg(&addr, 0, buf + off, sizeof(buf) - off);
    ASSERT_GT(r1, 0);
    off += r1;
    int r2 = ums_agent_tp_process_one_msg(&addr, 0, buf + off, sizeof(buf) - off);
    EXPECT_GT(r2, 0);
    EXPECT_EQ(off + r2, (int)sizeof(buf));
}

TEST_F(TokenProxyTest, ProcessOneMsg_BadMagicReturnsError)
{
    struct ums_agent_ip_addr addr = {};
    uint8_t full[UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN];
    struct ums_token_entry e = make_entry(1, 0, 1, 0);
    build_wire_msg(full, &e);
    /* corrupt magic */
    full[0] ^= 0xFF;
    int ret = ums_agent_tp_process_one_msg(&addr, 0, full, sizeof(full));
    EXPECT_EQ(ret, -EBADMSG);
}

/* ---------------------------------------------------------------------------
 * Pending list lifecycle
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, PendingListEnqueueDequeueMaintainsCount)
{
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
    struct ums_agent_pending_entry *p1 =
        ums_agent_pending_entry_create(&make_entry(1, 0, 0, 0));
    struct ums_agent_pending_entry *p2 =
        ums_agent_pending_entry_create(&make_entry(2, 0, 0, 0));
    ASSERT_TRUE(p1 && p2);
    ums_agent_pending_entry_enqueue(p1);
    ums_agent_pending_entry_enqueue(p2);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)2);
    ums_agent_pending_entry_dequeue(p1);
    ums_agent_pending_entry_destroy(p1);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)1);
    ums_agent_pending_entry_dequeue(p2);
    ums_agent_pending_entry_destroy(p2);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
}

/*
 * Pending-list cap (UMS_AGNET_MAX_PENDING_ENTRY_NUM = 1000).
 *
 * The cap is the very first check in ums_agent_pending_entry_handler, ahead of
 * any entry creation / connect, so pre-filling the list directly (O(1) tail
 * enqueue per entry, no connect / send side-effects) and then driving
 * ums_agent_tp_on_token_submit isolates the >= boundary precisely. All entries
 * share the 10.0.0.1 dst_addr produced by make_entry() so that on the
 * "accepted" case has_pending_for_peer() is true and need_connect stays false
 * (no connect call to stage).
 */
static void fill_pending_list(uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        struct ums_token_entry e = make_entry(i, 0, 0, 0);
        struct ums_agent_pending_entry *p = ums_agent_pending_entry_create(&e);
        ASSERT_NE(p, nullptr);
        ums_agent_pending_entry_enqueue(p);
    }
}

/* At the cap: ums_agent_tp_on_token_submit -> pending_entry_handler returns
 * -EAGAIN before creating an entry or issuing a connect. */
TEST_F(TokenProxyTest, PendingListRejectsAtMaxLimit)
{
    fill_pending_list(UMS_AGNET_MAX_PENDING_ENTRY_NUM);
    ASSERT_EQ(ums_agent_pending_entry_num_get(),
        (uint32_t)UMS_AGNET_MAX_PENDING_ENTRY_NUM);

    g_mock.pool_get_hit = false; /* no pooled conn -> pending_entry_handler */
    g_mock.connect_ret = 0;

    struct ums_token_entry e = make_entry(1001, 0xC0, 0xDE, 1);
    int ret = ums_agent_tp_on_token_submit(&e);

    EXPECT_EQ(ret, -EAGAIN);
    EXPECT_EQ(ums_agent_pending_entry_num_get(),
        (uint32_t)UMS_AGNET_MAX_PENDING_ENTRY_NUM); /* unchanged */
    EXPECT_EQ(g_mock.connect_calls, 0);              /* rejected before connect */
    EXPECT_FALSE(g_mock.submit_fail.called);
}

/* One short of the cap: submit is still accepted. Because a pending entry for
 * this peer already exists, need_connect is false and the entry is enqueued
 * without a connect, bringing the list to exactly the cap. */
TEST_F(TokenProxyTest, PendingListAcceptsBelowMaxLimitBoundary)
{
    fill_pending_list(UMS_AGNET_MAX_PENDING_ENTRY_NUM - 1);
    ASSERT_EQ(ums_agent_pending_entry_num_get(),
        (uint32_t)(UMS_AGNET_MAX_PENDING_ENTRY_NUM - 1));

    g_mock.pool_get_hit = false;
    g_mock.connect_ret = 0;

    struct ums_token_entry e = make_entry(999, 0xC0, 0xDE, 1);
    int ret = ums_agent_tp_on_token_submit(&e);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(ums_agent_pending_entry_num_get(),
        (uint32_t)UMS_AGNET_MAX_PENDING_ENTRY_NUM); /* now at the cap */
    EXPECT_EQ(g_mock.connect_calls, 0);              /* need_connect was false */
    EXPECT_FALSE(g_mock.submit_fail.called);
}

/* ---------------------------------------------------------------------------
 * Pending entry timeout -> TOKEN_SUBMIT_FAIL(ETIMEDOUT)
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, PendingTimeoutFailsWithEtimedout)
{
    struct ums_agent_pending_entry *p =
        ums_agent_pending_entry_create(&make_entry(99, 0, 0, 0));
    ASSERT_TRUE(p);
    ums_agent_pending_entry_enqueue(p);

    /* advance monotonic clock past the pending timeout window */
    g_mock.now.tv_sec = UMS_AGENT_TOKEN_ENTRY_PENDING_TIMEOUT_SEC + 1;
    ums_agent_tp_timer_tick();

    EXPECT_TRUE(g_mock.submit_fail.called);
    EXPECT_EQ(g_mock.submit_fail.clc_session_id, (uint32_t)99);
    EXPECT_EQ(g_mock.submit_fail.result, ETIMEDOUT);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
}

TEST_F(TokenProxyTest, PendingNotExpiredRemains)
{
    struct ums_agent_pending_entry *p =
        ums_agent_pending_entry_create(&make_entry(5, 0, 0, 0));
    ASSERT_TRUE(p);
    ums_agent_pending_entry_enqueue(p);

    g_mock.now.tv_sec = UMS_AGENT_TOKEN_ENTRY_PENDING_TIMEOUT_SEC - 1;
    ums_agent_tp_timer_tick();

    EXPECT_FALSE(g_mock.submit_fail.called);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)1);
}

/* ---------------------------------------------------------------------------
 * on_token_submit dispatch
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, OnTokenSubmitRejectsWhenNotInitialized)
{
    ums_agent_tp_deinit();
    struct ums_token_entry e = make_entry(1, 0, 0, 0);
    EXPECT_EQ(ums_agent_tp_on_token_submit(&e), -EINVAL);
}

TEST_F(TokenProxyTest, OnTokenSubmitRejectsNullEntry)
{
    EXPECT_EQ(ums_agent_tp_on_token_submit(NULL), -EINVAL);
}

TEST_F(TokenProxyTest, OnTokenSubmitQueuedTriggersConnect)
{
    g_mock.connect_ret = 0; /* connect initiated */
    struct ums_token_entry e = make_entry(10, 0xAAAA, 0xBBBB, 1);

    int ret = ums_agent_tp_on_token_submit(&e);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(g_mock.connect_calls, 1);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)1);
}

TEST_F(TokenProxyTest, OnTokenSubmitConnectFailRejects)
{
    g_mock.connect_ret = -1;
    struct ums_token_entry e = make_entry(11, 0, 0, 1);

    int ret = ums_agent_tp_on_token_submit(&e);
    EXPECT_EQ(ret, -ECONNREFUSED);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
}

/*
 * on_token_submit reuse path: an idle pooled conn whose conn_ctx already exists
 * is sent to immediately (no pending queue, no connect).
 */
TEST_F(TokenProxyTest, OnTokenSubmitReusesIdleConn)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);
    g_mock.send.ret = (int)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN);

    struct ums_token_entry e = make_entry(12, 0xC0, 0xDE, 1);
    int ret = ums_agent_tp_on_token_submit(&e);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(g_mock.send.called);
    EXPECT_EQ(g_mock.send.total_sent,
        (uint32_t)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN));
    EXPECT_EQ(g_mock.connect_calls, 0);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
}

/*
 * on_token_submit reuse path when TLS send returns EAGAIN: send_entry returns 1,
 * on_token_submit stages an in_flight_entry on the conn_ctx (and does NOT
 * enqueue on the pending list). The caller sees 0; completion is driven later
 * by on_writable.
 */
TEST_F(TokenProxyTest, OnTokenSubmitSendEagainMarksInFlight)
{
    struct ums_agent_conn_ctx *ctx = prime_conn(&g_mock.fake_conn, 0x0a000001);
    g_mock.send.ret = -EAGAIN;

    struct ums_token_entry e = make_entry(13, 0x11, 0x22, 1);
    int ret = ums_agent_tp_on_token_submit(&e);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(g_mock.send.called);
    ASSERT_NE(ctx->in_flight_entry, nullptr);
    EXPECT_EQ(ctx->send_len, (uint32_t)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN));
    EXPECT_EQ(ctx->send_offset, (uint32_t)0); /* nothing flushed yet */
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
    EXPECT_FALSE(g_mock.submit_fail.called);
}

/* same path, TLS send returns 0 (peer closed) -> -EIO propagated. */
TEST_F(TokenProxyTest, OnTokenSubmitSendZeroReturnsEio)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);
    g_mock.send.ret = 0;

    struct ums_token_entry e = make_entry(14, 0, 0, 1);
    int ret = ums_agent_tp_on_token_submit(&e);
    EXPECT_EQ(ret, -EIO);
}

/* ---------------------------------------------------------------------------
 * on_connect_complete callback (g_ums_agent_tp_conn_ops.on_connect_complete)
 *
 * Drives ums_agent_tp_process_pending_for_conn: on success it flushes queued
 * entries for the peer over the now-established TLS conn; on failure it fails
 * every queued entry for that peer with ECONNREFUSED.
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, OnConnectCompleteSuccessFlushesPending)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);
    enqueue_for_peer(20, 0x0a000001);
    g_mock.send.ret = (int)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN);

    g_ums_agent_tp_conn_ops.on_connect_complete(&g_mock.fake_conn, 0, NULL);

    EXPECT_TRUE(g_mock.send.called);
    EXPECT_FALSE(g_mock.submit_fail.called);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
}

TEST_F(TokenProxyTest, OnConnectCompleteFailureFailsPending)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);
    enqueue_for_peer(21, 0x0a000001);
    enqueue_for_peer(22, 0x0a000001);

    g_ums_agent_tp_conn_ops.on_connect_complete(&g_mock.fake_conn, -1, NULL);

    EXPECT_TRUE(g_mock.submit_fail.called);
    EXPECT_EQ(g_mock.submit_fail.calls, 2);
    EXPECT_EQ(g_mock.submit_fail.result, ECONNREFUSED);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
}

TEST_F(TokenProxyTest, OnConnectCompleteSendEagainMarksInFlight)
{
    struct ums_agent_conn_ctx *ctx = prime_conn(&g_mock.fake_conn, 0x0a000001);
    enqueue_for_peer(23, 0x0a000001);
    g_mock.send.ret = -EAGAIN;

    g_ums_agent_tp_conn_ops.on_connect_complete(&g_mock.fake_conn, 0, NULL);

    /* entry dequeued from pending and staged as in-flight for later flush */
    ASSERT_NE(ctx->in_flight_entry, nullptr);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
    EXPECT_FALSE(g_mock.submit_fail.called);
}

/* ---------------------------------------------------------------------------
 * on_writable callback (g_ums_agent_tp_conn_ops.on_writable)
 *
 * Flushes a pending (partially-sent) buffer; on success destroys the
 * in_flight_entry and drains the next pending entry; on EAGAIN it must keep
 * the in_flight entry and retry later; on a hard send error it shuts the conn.
 * ------------------------------------------------------------------------- */

class WritableBase {
protected:
    struct ums_agent_conn_ctx *ctx;
    struct ums_token_entry entry = make_entry(30, 0x70, 0x80, 1);

    void prime(void)
    {
        ctx = prime_conn(&g_mock.fake_conn, 0x0a000001);
        /* stage a partially-flushed send (TLS returns EAGAIN) */
        g_mock.send.ret = -EAGAIN;
        ASSERT_EQ(ums_agent_tp_send_entry(&g_mock.fake_conn, &entry), 1);
        ASSERT_EQ(ctx->send_len,
            (uint32_t)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN));
        ASSERT_EQ(ctx->send_offset, (uint32_t)0);
        /* the producer (on_token_submit / connect_complete) would stage this */
        ctx->in_flight_entry = ums_agent_pending_entry_create(&entry);
    }
};

TEST_F(TokenProxyTest, OnWritableSuccessFlushesAndDestroysInFlight)
{
    WritableBase w;
    w.prime();
    g_mock.send.ret = (int)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN);

    g_ums_agent_tp_conn_ops.on_writable(&g_mock.fake_conn, NULL);

    EXPECT_EQ(g_mock.shutdown_calls, 0);
    EXPECT_EQ(w.ctx->in_flight_entry, nullptr);
    EXPECT_EQ(w.ctx->send_len, (uint32_t)0);
    EXPECT_EQ(w.ctx->send_offset, (uint32_t)0);
}

TEST_F(TokenProxyTest, OnWritableEagainKeepsInFlightAndRetriesLater)
{
    WritableBase w;
    w.prime();
    g_mock.send.ret = -EAGAIN;

    g_ums_agent_tp_conn_ops.on_writable(&g_mock.fake_conn, NULL);

    EXPECT_EQ(g_mock.shutdown_calls, 0);
    ASSERT_NE(w.ctx->in_flight_entry, nullptr);
    EXPECT_EQ(w.ctx->send_len,
        (uint32_t)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN));

    /* a subsequent writable after the peer becomes ready must succeed */
    g_mock.send.ret = (int)(UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN);
    g_ums_agent_tp_conn_ops.on_writable(&g_mock.fake_conn, NULL);
    EXPECT_EQ(w.ctx->in_flight_entry, nullptr);
    EXPECT_EQ(w.ctx->send_len, (uint32_t)0);
}

TEST_F(TokenProxyTest, OnWritableSendErrorShutsDownConnection)
{
    WritableBase w;
    w.prime();
    g_mock.send.ret = -EIO;

    g_ums_agent_tp_conn_ops.on_writable(&g_mock.fake_conn, NULL);

    EXPECT_GE(g_mock.shutdown_calls, 1);
    /* in_flight left for conn_ctx_destroy to clean up during deinit */
    ASSERT_NE(w.ctx->in_flight_entry, nullptr);
}

/* ---------------------------------------------------------------------------
 * on_data_available callback (g_ums_agent_tp_conn_ops.on_data_available)
 *
 * Receives a framed TOKEN_TRANSFER from the peer agent and forwards the peer
 * token_values to the kmod via TOKEN_DELIVER. Recv returning 0 (peer closed)
 * shuts the connection down.
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, OnDataAvailableDeliversPeerTokenValues)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);

    static uint8_t wire[UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN];
    struct ums_token_entry e = make_entry(40, 0xAAA1, 0xBBB2, 1);
    build_wire_msg(wire, &e);
    g_mock.recv.data = wire;
    g_mock.recv.len = sizeof(wire);
    g_mock.recv.off = 0;
    g_mock.recv.eof = false;

    g_ums_agent_tp_conn_ops.on_data_available(&g_mock.fake_conn, NULL);

    EXPECT_TRUE(g_mock.deliver.called);
    EXPECT_EQ(g_mock.deliver.clc_session_id, (uint32_t)40);
    EXPECT_EQ(g_mock.deliver.peer_jetty_token, (uint32_t)0xAAA1);
    EXPECT_EQ(g_mock.deliver.peer_seg_token, (uint32_t)0xBBB2);
    EXPECT_EQ(g_mock.deliver.first_contact, (uint8_t)1);
    EXPECT_EQ(g_mock.shutdown_calls, 0);
}

TEST_F(TokenProxyTest, OnDataAvailableRecvEofShutsDown)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);
    g_mock.recv.data = NULL;
    g_mock.recv.len = 0;
    g_mock.recv.off = 0;
    g_mock.recv.eof = true;

    g_ums_agent_tp_conn_ops.on_data_available(&g_mock.fake_conn, NULL);

    EXPECT_GE(g_mock.shutdown_calls, 1);
    EXPECT_FALSE(g_mock.deliver.called);
}

TEST_F(TokenProxyTest, OnDataAvailableBadMagicShutsDown)
{
    prime_conn(&g_mock.fake_conn, 0x0a000001);
    static uint8_t wire[UMS_AGENT_MSG_HDR_LEN + UMS_AGENT_TOKEN_TRANSFER_LEN];
    struct ums_token_entry e = make_entry(41, 0, 1, 0);
    build_wire_msg(wire, &e);
    wire[0] ^= 0xFF; /* corrupt magic */
    g_mock.recv.data = wire;
    g_mock.recv.len = sizeof(wire);
    g_mock.recv.off = 0;
    g_mock.recv.eof = false;

    g_ums_agent_tp_conn_ops.on_data_available(&g_mock.fake_conn, NULL);

    EXPECT_GE(g_mock.shutdown_calls, 1);
    EXPECT_FALSE(g_mock.deliver.called);
}

/* ---------------------------------------------------------------------------
 * on_close callback (g_ums_agent_tp_conn_ops.on_close)
 *
 * A conn teardown must fail any in_flight entry (ECONNRESET) and every queued
 * pending entry for that peer (ECONNRESET), then drop the conn_ctx.
 * ------------------------------------------------------------------------- */

TEST_F(TokenProxyTest, OnCloseFailsInFlightAndPending)
{
    struct ums_agent_conn_ctx *ctx = prime_conn(&g_mock.fake_conn, 0x0a000001);
    struct ums_token_entry inflight_e = make_entry(50, 0, 0, 0);
    ctx->in_flight_entry = ums_agent_pending_entry_create(&inflight_e);
    enqueue_for_peer(51, 0x0a000001);

    g_ums_agent_tp_conn_ops.on_close(&g_mock.fake_conn, NULL);

    EXPECT_EQ(g_mock.submit_fail.calls, 2);
    EXPECT_EQ(g_mock.submit_fail.result, ECONNRESET);
    EXPECT_EQ(ctx->in_flight_entry, nullptr);
    EXPECT_EQ(ums_agent_pending_entry_num_get(), (uint32_t)0);
    /* conn_ctx must be gone so a later writable/data event is a no-op */
    EXPECT_EQ(ums_agent_conn_ctx_find(&g_mock.fake_conn), nullptr);
}

/*
 * RecvBufferFull_ClosesConnection (NOT REACHABLE under current framing):
 * the "recv buffer full after processing" shutdown branch in
 * ums_agent_tp_on_data_available needs recv_len == UMS_AGENT_RECV_BUF_SIZE
 * (8192) with process_recv_buf consuming 0 bytes. Consuming 0 requires an
 * incomplete message whose total_len exceeds the buffer, but
 * validate_msg_hdr caps payload_len at UMS_AGENT_MAX_MSG_LEN - MSG_HDR_LEN
 * (4084), so a frame completes at <= 4096 bytes -- well under 8192 -- and gets
 * consumed before the buffer can fill. The branch is defensive only; left
 * documented rather than artificially forced (would need raising MAX_MSG_LEN
 * above RECV_BUF_SIZE/2 solely for the test).
 */


/* ---------------------------------------------------------------------------
 * init / deinit
 * ------------------------------------------------------------------------- */

TEST(TokenProxyInitTest, DoubleInitIsNoop)
{
    mock_reset();
    ASSERT_EQ(ums_agent_tp_init(0), 0);
    EXPECT_EQ(ums_agent_tp_init(0), 0);
    ums_agent_tp_deinit();
    drain_pending_list();
}

TEST(TokenProxyInitTest, TimerTickBeforeInitIsNoop)
{
    mock_reset();
    ums_agent_tp_timer_tick(); /* must not crash */
}

