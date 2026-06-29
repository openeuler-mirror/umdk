/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * White-box unit tests for the UMS agent netlink layer (token exchange path).
 *
 * Coverage: TOKEN_SUBMIT attribute validation (ums_agent_nl_validate_token_submit)
 * and TOKEN_SUBMIT processing/parsing (ums_agent_nl_process_token_submit),
 * including IPv4/IPv6 dst handling, optional JETTY_TOKEN, callback dispatch and
 * the "no handler" rejection path. Secure-zero of token fields is asserted.
 *
 * the production TU (ums_agent_nl.c) is #included so the static
 * validate/process helpers are reachable. libnl3 symbols (nla_*, NLA_HDRLEN)
 * resolve via the linked nl-3/nl-genl-3 libraries. The epoll dependency and
 * logging are stubbed out. No real netlink socket is opened.
 */

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <netlink/attr.h>
#include <netlink/netlink.h>

#include "ums_agent_nl.c" /* NOLINT: white-box include of production TU */

/* ---------------------------------------------------------------------------
 * Stubs for epoll / logging dependencies of ums_agent_nl.c
 * ------------------------------------------------------------------------- */

int ums_agent_epoll_add_fd(int fd, uint32_t events) { return 0; }
int ums_agent_epoll_del_fd(int fd) { return 0; }

void ums_agent_log_output(enum ums_agent_log_level level, const char *func,
    int line, const char *fmt, ...) {}

/* ---------------------------------------------------------------------------
 * Helpers: build fake nlattr entries
 *
 * nla_len(attr) == attr->nla_len - NLA_HDRLEN, nla_data(attr) == (char*)attr +
 * NLA_HDRLEN. We mimic libnl layout so nla_get_* / nla_memcpy / nla_len behave
 * identically on hand-built attributes.
 * ------------------------------------------------------------------------- */

static struct nlattr *mk_attr(void *buf, int type, const void *data, int datalen)
{
    struct nlattr *a = (struct nlattr *)buf;
    a->nla_type = (uint16_t)type;
    a->nla_len = (uint16_t)(NLA_HDRLEN + datalen);
    memcpy((char *)buf + NLA_HDRLEN, data, datalen);
    return a;
}

static struct nlattr *mk_u32(void *buf, int type, uint32_t v)
{
    return mk_attr(buf, type, &v, sizeof(v));
}

static struct nlattr *mk_u8(void *buf, int type, uint8_t v)
{
    return mk_attr(buf, type, &v, sizeof(v));
}

/* Per-test attribute arena: one buffer per known attribute slot. */
struct NlAttrArena {
    char buf[UMS_ATTR_MAX + 1][32];
    struct nlattr *attrs[UMS_ATTR_MAX + 1];

    void reset() { memset(attrs, 0, sizeof(attrs)); }

    void put_u32(int type, uint32_t v)
    {
        attrs[type] = mk_u32(buf[type], type, v);
    }
    void put_u8(int type, uint8_t v)
    {
        attrs[type] = mk_u8(buf[type], type, v);
    }
    void put_bin(int type, const void *data, int len)
    {
        attrs[type] = mk_attr(buf[type], type, data, len);
    }
    struct nlattr **raw() { return attrs; }
};

class NlTest : public ::testing::Test {
protected:
    NlAttrArena a;
    void SetUp() override { a.reset(); }
};

/* ---------------------------------------------------------------------------
 * ums_agent_nl_validate_token_submit
 * ------------------------------------------------------------------------- */

TEST_F(NlTest, ValidateAcceptsMinimalIPv4WithoutJetty)
{
    uint8_t initiator[UMS_SYSTEMID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 0x100);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 0x200);
    a.put_u32(UMS_ATTR_DST_IP, 0x0a000001u);
    EXPECT_EQ(ums_agent_nl_validate_token_submit(a.raw()), 0);
}

TEST_F(NlTest, ValidateRejectsMissingEachRequiredAttr)
{
    uint8_t initiator[UMS_SYSTEMID_LEN] = {0};
    /* full valid baseline */
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    a.put_u32(UMS_ATTR_DST_IP, 1);
    ASSERT_EQ(ums_agent_nl_validate_token_submit(a.raw()), 0);

    struct NlAttrArena b;
    /* missing CLC_SESSION_ID */
    b.reset();
    b.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    b.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    b.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    b.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_LT(ums_agent_nl_validate_token_submit(b.raw()), 0);

    /* missing INITIATOR_ID */
    b.reset();
    b.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    b.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    b.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    b.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_LT(ums_agent_nl_validate_token_submit(b.raw()), 0);

    /* missing FIRST_CONTACT */
    b.reset();
    b.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    b.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    b.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    b.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_LT(ums_agent_nl_validate_token_submit(b.raw()), 0);

    /* missing SEG_TOKEN */
    b.reset();
    b.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    b.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    b.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    b.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_LT(ums_agent_nl_validate_token_submit(b.raw()), 0);

    /* missing both DST_IP and DST_IP6 */
    b.reset();
    b.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    b.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    b.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    b.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    EXPECT_LT(ums_agent_nl_validate_token_submit(b.raw()), 0);
}

TEST_F(NlTest, ValidateRejectsWrongInitiatorIdLength)
{
    uint8_t initiator[UMS_SYSTEMID_LEN - 1] = {0};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, sizeof(initiator));
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    a.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_LT(ums_agent_nl_validate_token_submit(a.raw()), 0);
}

TEST_F(NlTest, ValidateRejectsWrongDstIp6Length)
{
    uint8_t initiator[UMS_SYSTEMID_LEN] = {0};
    uint8_t short_v6[8] = {0};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    a.put_bin(UMS_ATTR_DST_IP6, short_v6, sizeof(short_v6));
    EXPECT_LT(ums_agent_nl_validate_token_submit(a.raw()), 0);
}

TEST_F(NlTest, ValidateFirstContactRequiresJettyToken)
{
    uint8_t initiator[UMS_SYSTEMID_LEN] = {0};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 1);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    a.put_u32(UMS_ATTR_DST_IP, 1);
    /* no JETTY_TOKEN -> reject */
    EXPECT_LT(ums_agent_nl_validate_token_submit(a.raw()), 0);

    /* add JETTY_TOKEN -> accept */
    a.put_u32(UMS_ATTR_JETTY_TOKEN, 0x9999);
    EXPECT_EQ(ums_agent_nl_validate_token_submit(a.raw()), 0);
}

/* ---------------------------------------------------------------------------
 * ums_agent_nl_process_token_submit
 *
 * The process helper does NOT check g_ums_agent_nl.initialized; it only reads
 * token_submit_cb. We set the static global directly.
 * ------------------------------------------------------------------------- */

static struct {
    bool called;
    struct ums_token_entry entry;
    int ret;
} g_cb;

static int capture_cb(struct ums_token_entry *entry)
{
    g_cb.called = true;
    g_cb.entry = *entry;
    return g_cb.ret;
}

class NlProcessTest : public ::testing::Test {
protected:
    NlAttrArena a;
    void SetUp() override
    {
        memset(&g_cb, 0, sizeof(g_cb));
        g_cb.ret = 0;
        a.reset();
        g_ums_agent_nl.token_submit_cb = capture_cb;
    }
    void TearDown() override
    {
        g_ums_agent_nl.token_submit_cb = NULL;
    }
};

TEST_F(NlProcessTest, ParsesIPv4AndDispatchesCallback)
{
    uint8_t initiator[UMS_SYSTEMID_LEN] = {9, 8, 7, 6, 5, 4, 3, 2};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 0xCAFE);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 0x11223344);
    a.put_u32(UMS_ATTR_DST_IP, htonl(0xC0A80101)); /* 192.168.1.1 */

    ASSERT_EQ(ums_agent_nl_process_token_submit(a.raw()), 0);
    ASSERT_TRUE(g_cb.called);
    EXPECT_EQ(g_cb.entry.clc_session_id, (uint32_t)0xCAFE);
    EXPECT_EQ(g_cb.entry.seg_token_value, (uint32_t)0x11223344);
    EXPECT_EQ(g_cb.entry.first_contact, (uint8_t)0);
    EXPECT_EQ(g_cb.entry.dst_addr.family, AF_INET);
    EXPECT_EQ(g_cb.entry.dst_addr.ip.in4.s_addr, htonl(0xC0A80101));
    EXPECT_EQ(memcmp(g_cb.entry.initiator_id, initiator, UMS_SYSTEMID_LEN), 0);
}

TEST_F(NlProcessTest, ParsesIPv6AndOptionalJettyToken)
{
    uint8_t initiator[UMS_SYSTEMID_LEN] = {1};
    uint8_t v6[16] = {0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 7);
    a.put_bin(UMS_ATTR_INITIATOR_ID, initiator, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 1);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 0x1);
    a.put_u32(UMS_ATTR_JETTY_TOKEN, 0x2);
    a.put_bin(UMS_ATTR_DST_IP6, v6, sizeof(v6));

    ASSERT_EQ(ums_agent_nl_process_token_submit(a.raw()), 0);
    ASSERT_TRUE(g_cb.called);
    EXPECT_EQ(g_cb.entry.dst_addr.family, AF_INET6);
    EXPECT_EQ(memcmp(&g_cb.entry.dst_addr.ip.in6, v6, sizeof(v6)), 0);
    EXPECT_EQ(g_cb.entry.jetty_token_value, (uint32_t)0x2);
}

TEST_F(NlProcessTest, NoHandlerReturnsEnotsup)
{
    g_ums_agent_nl.token_submit_cb = NULL;
    uint8_t zero[UMS_SYSTEMID_LEN] = {0};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    a.put_bin(UMS_ATTR_INITIATOR_ID, zero, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    a.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_EQ(ums_agent_nl_process_token_submit(a.raw()), -ENOTSUP);
}

TEST_F(NlProcessTest, CallbackFailurePropagated)
{
    g_cb.ret = -EBUSY;
    uint8_t zero[UMS_SYSTEMID_LEN] = {0};
    a.put_u32(UMS_ATTR_CLC_SESSION_ID, 1);
    a.put_bin(UMS_ATTR_INITIATOR_ID, zero, UMS_SYSTEMID_LEN);
    a.put_u8(UMS_ATTR_FIRST_CONTACT, 0);
    a.put_u32(UMS_ATTR_SEG_TOKEN, 1);
    a.put_u32(UMS_ATTR_DST_IP, 1);
    EXPECT_EQ(ums_agent_nl_process_token_submit(a.raw()), -EBUSY);
}

/* ---------------------------------------------------------------------------
 * ums_agent_nl_send_token_deliver / ums_agent_nl_send_token_submit_fail
 *
 * Both build a genl nl_msg and hand it to nl_send_auto(). We intercept
 * nl_send_auto (extern "C" to match libnl's declaration linkage so the
 * production's call resolves here instead of into libnl-3) and capture the
 * built message -- cmd, version, family id and the parsed nla attributes --
 * before the kernel would see it. No real netlink socket is opened: the
 * production only passes g_ums_agent_nl.ums_sock to nl_send_auto and the mock
 * ignores it, so ums_sock may stay NULL.
 *
 * The static-inline ums_agent_nl_secure_zero_msg() is also reachable via the
 * white-box #include and is exercised directly on a real nl_msg built with
 * libnl, confirming the payload region is cleansed.
 * ------------------------------------------------------------------------- */

struct NlSendCapture {
    bool called;
    int calls;
    int ret;                 /* value the mock returns (0 ok, <0 error) */
    uint8_t cmd;
    uint8_t version;
    int family_id;           /* nlmsghdr.nlmsg_type, set by genlmsg_put */
    bool has_clc_session_id;
    uint32_t clc_session_id;
    bool has_initiator_id;
    uint8_t initiator_id[UMS_SYSTEMID_LEN];
    bool has_first_contact;
    uint8_t first_contact;
    bool has_seg_token;
    uint32_t seg_token;
    bool has_jetty_token;
    uint32_t jetty_token;
    bool has_result;
    uint32_t result;
};

static NlSendCapture g_send;

extern "C" int nl_send_auto(struct nl_sock *sock, struct nl_msg *msg)
{
    (void)sock;
    g_send.called = true;
    g_send.calls++;

    struct nlmsghdr *nh = nlmsg_hdr(msg);
    struct genlmsghdr *gh = genlmsg_hdr(nh);
    g_send.cmd = gh->cmd;
    g_send.version = gh->version;
    g_send.family_id = (int)nh->nlmsg_type;

    struct nlattr *attrs[UMS_ATTR_MAX + 1];
    memset(attrs, 0, sizeof(attrs));
    if (nla_parse(attrs, UMS_ATTR_MAX, genlmsg_attrdata(gh, 0),
        genlmsg_attrlen(gh, 0), NULL) == 0) {
        if (attrs[UMS_ATTR_CLC_SESSION_ID]) {
            g_send.has_clc_session_id = true;
            g_send.clc_session_id = nla_get_u32(attrs[UMS_ATTR_CLC_SESSION_ID]);
        }
        if (attrs[UMS_ATTR_INITIATOR_ID]) {
            g_send.has_initiator_id = true;
            memcpy(g_send.initiator_id, nla_data(attrs[UMS_ATTR_INITIATOR_ID]),
                UMS_SYSTEMID_LEN);
        }
        if (attrs[UMS_ATTR_FIRST_CONTACT]) {
            g_send.has_first_contact = true;
            g_send.first_contact = nla_get_u8(attrs[UMS_ATTR_FIRST_CONTACT]);
        }
        if (attrs[UMS_ATTR_SEG_TOKEN]) {
            g_send.has_seg_token = true;
            g_send.seg_token = nla_get_u32(attrs[UMS_ATTR_SEG_TOKEN]);
        }
        if (attrs[UMS_ATTR_JETTY_TOKEN]) {
            g_send.has_jetty_token = true;
            g_send.jetty_token = nla_get_u32(attrs[UMS_ATTR_JETTY_TOKEN]);
        }
        if (attrs[UMS_ATTR_RESULT]) {
            g_send.has_result = true;
            g_send.result = nla_get_u32(attrs[UMS_ATTR_RESULT]);
        }
    }

    return g_send.ret;
}

class NlSendTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        memset(&g_send, 0, sizeof(g_send));
        g_send.ret = 0; /* default: send succeeds */
        g_ums_agent_nl.ums_available = true;
        g_ums_agent_nl.ums_family_id = 0x1234;
        g_ums_agent_nl.ums_sock = NULL; /* mock ignores it */
    }
    void TearDown() override
    {
        g_ums_agent_nl.ums_available = false;
        g_ums_agent_nl.ums_family_id = 0;
        g_ums_agent_nl.ums_sock = NULL;
    }
};

static const uint8_t g_nl_init_id[UMS_SYSTEMID_LEN] = {0xA1, 0xB2, 0xC3, 0xD4,
    0xE5, 0xF6, 0x07, 0x18};

/* first_contact=0: JETTY_TOKEN MUST be absent (peer has no jetty token to
 * import); SEG_TOKEN is always present. This is the attr-presence contract the
 * kmod token_deliver doit relies on. */
TEST_F(NlSendTest, SendTokenDeliverFirstContactZeroOmitsJettyAttr)
{
    int ret = ums_agent_nl_send_token_deliver(0xCAFEBABE, g_nl_init_id,
        0xAAAA1111 /* jetty, must be dropped */, 0xBBBB2222, /* first_contact */ 0);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(g_send.called);
    EXPECT_EQ(g_send.cmd, (uint8_t)UMS_CMD_TOKEN_DELIVER);
    EXPECT_EQ(g_send.version, (uint8_t)UMS_GENL_VERSION);
    EXPECT_EQ(g_send.family_id, 0x1234);
    EXPECT_TRUE(g_send.has_clc_session_id);
    EXPECT_EQ(g_send.clc_session_id, (uint32_t)0xCAFEBABE);
    EXPECT_TRUE(g_send.has_initiator_id);
    EXPECT_EQ(memcmp(g_send.initiator_id, g_nl_init_id, UMS_SYSTEMID_LEN), 0);
    EXPECT_TRUE(g_send.has_first_contact);
    EXPECT_EQ(g_send.first_contact, (uint8_t)0);
    EXPECT_TRUE(g_send.has_seg_token);
    EXPECT_EQ(g_send.seg_token, (uint32_t)0xBBBB2222);
    EXPECT_FALSE(g_send.has_jetty_token); /* the key assertion */
}

/* first_contact=1: JETTY_TOKEN MUST be present with the peer's jetty value. */
TEST_F(NlSendTest, SendTokenDeliverFirstContactOneIncludesJettyAttr)
{
    int ret = ums_agent_nl_send_token_deliver(0x11223344, g_nl_init_id,
        0x12345678, 0x9ABCDEF0, 1);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(g_send.first_contact, (uint8_t)1);
    EXPECT_TRUE(g_send.has_jetty_token);
    EXPECT_EQ(g_send.jetty_token, (uint32_t)0x12345678);
    EXPECT_TRUE(g_send.has_seg_token);
    EXPECT_EQ(g_send.seg_token, (uint32_t)0x9ABCDEF0);
}

TEST_F(NlSendTest, SendTokenDeliverUmsUnavailableReturnsErrorWithoutSend)
{
    g_ums_agent_nl.ums_available = false;
    int ret = ums_agent_nl_send_token_deliver(1, g_nl_init_id, 1, 1, 1);
    EXPECT_LT(ret, 0);
    EXPECT_FALSE(g_send.called);
}

/* Any negative from nl_send_auto is mapped by the production to -1 and still
 * runs the secure_zero + free path (asserted separately below). */
TEST_F(NlSendTest, SendTokenDeliverSendErrorPropagated)
{
    g_send.ret = -NLE_AGAIN; /* NLE_AGAIN is used by the production itself */
    int ret = ums_agent_nl_send_token_deliver(2, g_nl_init_id, 2, 2, 0);
    EXPECT_LT(ret, 0);
    EXPECT_TRUE(g_send.called);
}

TEST_F(NlSendTest, SendTokenSubmitFailBuildsExpectedPayload)
{
    int result = -ECONNREFUSED;
    int ret = ums_agent_nl_send_token_submit_fail(0xDEADBEEF, g_nl_init_id, result);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(g_send.called);
    EXPECT_EQ(g_send.cmd, (uint8_t)UMS_CMD_TOKEN_SUBMIT_FAIL);
    EXPECT_EQ(g_send.version, (uint8_t)UMS_GENL_VERSION);
    EXPECT_TRUE(g_send.has_clc_session_id);
    EXPECT_EQ(g_send.clc_session_id, (uint32_t)0xDEADBEEF);
    EXPECT_TRUE(g_send.has_initiator_id);
    EXPECT_EQ(memcmp(g_send.initiator_id, g_nl_init_id, UMS_SYSTEMID_LEN), 0);
    EXPECT_TRUE(g_send.has_result);
    EXPECT_EQ(g_send.result, (uint32_t)result);
    EXPECT_FALSE(g_send.has_seg_token);
    EXPECT_FALSE(g_send.has_jetty_token);
    EXPECT_FALSE(g_send.has_first_contact);
}

TEST_F(NlSendTest, SendTokenSubmitFailUmsUnavailableReturnsError)
{
    g_ums_agent_nl.ums_available = false;
    int ret = ums_agent_nl_send_token_submit_fail(1, g_nl_init_id, -EAGAIN);
    EXPECT_LT(ret, 0);
    EXPECT_FALSE(g_send.called);
}

/*
 * ums_agent_nl_secure_zero_msg is static inline in the production TU; build a
 * real nl_msg with a non-zero genl payload (genlmsghdr + nla attrs) and confirm
 * the helper cleanses exactly the [NLMSG_DATA, nlmsg_len) region that the send
 * paths rely on after nl_send_auto (success or error).
 */
TEST_F(NlSendTest, SecureZeroMsgZeroesGenlPayload)
{
    struct nl_msg *msg = nlmsg_alloc();
    ASSERT_NE(msg, nullptr);

    void *gh = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, 0x1234, 0, 0,
        UMS_CMD_TOKEN_DELIVER, UMS_GENL_VERSION);
    ASSERT_NE(gh, nullptr);
    ASSERT_EQ(nla_put_u32(msg, UMS_ATTR_SEG_TOKEN, 0xDEADBEEF), 0);
    ASSERT_EQ(nla_put_u32(msg, UMS_ATTR_CLC_SESSION_ID, 0xCAFEBABE), 0);

    struct nlmsghdr *nh = nlmsg_hdr(msg);
    uint32_t payload_len = nh->nlmsg_len - NLMSG_HDRLEN;
    ASSERT_GT(payload_len, (uint32_t)0);

    uint8_t *payload = (uint8_t *)NLMSG_DATA(nh);
    bool any_nonzero = false;
    for (uint32_t i = 0; i < payload_len; i++) {
        if (payload[i] != 0) {
            any_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(any_nonzero) << "payload should be non-zero before cleanse";

    ums_agent_nl_secure_zero_msg(msg);

    for (uint32_t i = 0; i < payload_len; i++) {
        EXPECT_EQ(payload[i], (uint8_t)0) << "residual at offset " << i;
    }

    nlmsg_free(msg);
}
