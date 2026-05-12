/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: TLS CTX module implementation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-05-09
 * Note:
 * History: 2026-05-09  Create File
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <keyutils.h>
#include <openssl/ssl.h>

#include "ums_agent_log.h"
#include "ums_agent_utils.h"
#include "ums_agent_tls_ctx.h"

#define UMS_AGENT_TLS_KEY_TYPE               "user"
#define UMS_AGENT_TLS_PRKEY_PWD_BUF_SIZE      256
#define UMS_AGENT_TLS_VERIFY_DEPTH            2
#define UMS_AGENT_TLS_CERT_WARN_DAYS          7
#define UMS_AGENT_TLS_CERT_CHECK_INTERVAL_SEC 86400

struct ums_agent_tls_ctx {
    SSL_CTX *server_ssl_ctx;
    SSL_CTX *client_ssl_ctx;
    struct timespec last_cert_check_time;
    bool initialized;
};

static struct ums_agent_tls_ctx g_ums_agent_tls_ctx;

static int ums_agent_keyring_get_password(const char *desc, char *pwd_buf, size_t pwd_buf_len)
{
    key_serial_t key = request_key(UMS_AGENT_TLS_KEY_TYPE, desc, NULL,
        KEY_SPEC_USER_KEYRING);
    if (key < 0) {
        UMS_AGENT_LOG_ERR("request_key '%s' from @u keyring failed: %s (errno=%d)",
            desc, strerror(errno), errno);
        return -1;
    }

    long ret = keyctl_read(key, pwd_buf, pwd_buf_len - 1);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("keyctl_read for key desc '%s' failed: %s (errno=%d)",
            desc, strerror(errno), errno);
        ums_agent_secure_zero(pwd_buf, pwd_buf_len);
        return -1;
    }

    if (ret > (long)(pwd_buf_len - 1)) {
        ums_agent_secure_zero(pwd_buf, pwd_buf_len);
        UMS_AGENT_LOG_ERR("private key password (key desc '%s') too long (>= %zu chars)",
            desc, pwd_buf_len - 1);
        return -1;
    }

    pwd_buf[ret] = '\0';
    return 0;
}

static int ums_agent_tls_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    (void)rwflag;

    const char *desc = (const char *)userdata;
    if (!desc || !buf || size <= 0) {
        return 0;
    }

    char pwd_buf[UMS_AGENT_TLS_PRKEY_PWD_BUF_SIZE];
    if (ums_agent_keyring_get_password(desc, pwd_buf, sizeof(pwd_buf)) != 0) {
        return 0;
    }

    size_t len = strlen(pwd_buf);
    if (len >= (size_t)size) {
        UMS_AGENT_LOG_ERR("password for '%s' too long for OpenSSL buffer "
            "(%zu >= %d)", desc, len, size);
        ums_agent_secure_zero(pwd_buf, sizeof(pwd_buf));
        return 0;
    }

    (void)memcpy(buf, pwd_buf, len);
    buf[len] = '\0';

    ums_agent_secure_zero(pwd_buf, sizeof(pwd_buf));
    return (int)len;
}

static int ums_agent_check_cert_not_before(X509 *cert, const char *name,
    const char *cert_path)
{
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    if (!not_before) {
        UMS_AGENT_LOG_ERR("failed to get notBefore from %s '%s'", name, cert_path);
        return -1;
    }

    int days = 0;
    int secs = 0;
    if (ASN1_TIME_diff(&days, &secs, not_before, NULL) == 0) {
        UMS_AGENT_LOG_ERR("failed to compare notBefore time for %s '%s'", name, cert_path);
        return -1;
    }

    if (days < 0 || (days == 0 && secs < 0)) {
        UMS_AGENT_LOG_ERR("%s '%s' is not yet valid", name, cert_path);
        return -1;
    }

    return 0;
}

static int ums_agent_check_cert_not_after(X509 *cert, const char *name,
    const char *cert_path)
{
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (!not_after) {
        UMS_AGENT_LOG_ERR("failed to get notAfter from %s '%s'", name, cert_path);
        return -1;
    }

    int days = 0;
    int secs = 0;
    if (ASN1_TIME_diff(&days, &secs, NULL, not_after) == 0) {
        UMS_AGENT_LOG_ERR("failed to compare time for %s '%s'", name, cert_path);
        return -1;
    }

    if (days < 0 || (days == 0 && secs <= 0)) {
        UMS_AGENT_LOG_ERR("%s '%s' has expired", name, cert_path);
        return -1;
    }

    if ((uint32_t)days < UMS_AGENT_TLS_CERT_WARN_DAYS) {
        UMS_AGENT_LOG_WARN("%s '%s' will expire in %d days %d seconds", name, cert_path, days, secs);
    }

    return 0;
}

static int ums_agent_tls_check_x509_cert_expiry(const char *cert_path, const char *name)
{
    if (cert_path[0] == '\0') {
        return 0;
    }

    X509 *cert = NULL;
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        UMS_AGENT_LOG_ERR("failed to open %s '%s': %s (errno=%d)",
            name, cert_path, strerror(errno), errno);
        return -1;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    (void)fclose(fp);

    if (!cert) {
        UMS_AGENT_LOG_ERR("failed to parse %s '%s'", name, cert_path);
        return -1;
    }

    if (ums_agent_check_cert_not_before(cert, name, cert_path) != 0) {
        X509_free(cert);
        return -1;
    }

    if (ums_agent_check_cert_not_after(cert, name, cert_path) != 0) {
        X509_free(cert);
        return -1;
    }

    X509_free(cert);
    return 0;
}

static int ums_agent_load_crl_to_store(X509_STORE *store, const char *crl_path)
{
    if (!crl_path || crl_path[0] == '\0') {
        return 0;
    }

    FILE *fp = fopen(crl_path, "r");
    if (!fp) {
        UMS_AGENT_LOG_ERR("failed to open CRL '%s': %s (errno=%d)",
            crl_path, strerror(errno), errno);
        return -1;
    }

    X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
    (void)fclose(fp);

    if (!crl) {
        UMS_AGENT_LOG_ERR("failed to parse CRL '%s'", crl_path);
        return -1;
    }

    int ret = X509_STORE_add_crl(store, crl);
    X509_CRL_free(crl);

    if (ret != 1) {
        UMS_AGENT_LOG_ERR("X509_STORE_add_crl '%s' failed", crl_path);
        return -1;
    }

    return 0;
}

static int ums_agent_setup_security_hardening(SSL_CTX *ctx, bool is_server)
{
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if (SSL_CTX_set_max_early_data(ctx, 0) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_set_max_early_data failed");
        return -1;
    }

    X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
    if (!param) {
        UMS_AGENT_LOG_ERR("SSL_CTX_get0_param failed");
        return -1;
    }
    X509_VERIFY_PARAM_set_depth(param, UMS_AGENT_TLS_VERIFY_DEPTH);

    if (is_server) {
        if (SSL_CTX_set_num_tickets(ctx, 0) != 1) {
            UMS_AGENT_LOG_ERR("SSL_CTX_set_num_tickets failed");
            return -1;
        }
    }

    return 0;
}

static int ums_agent_setup_crl_verification(SSL_CTX *ctx, const char *crl_path)
{
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    if (!store) {
        UMS_AGENT_LOG_ERR("SSL_CTX_get_cert_store failed");
        return -1;
    }

    if (ums_agent_load_crl_to_store(store, crl_path) != 0) {
        return -1;
    }

    X509_VERIFY_PARAM *param = X509_STORE_get0_param(store);
    if (!param) {
        UMS_AGENT_LOG_ERR("X509_STORE_get0_param failed");
        return -1;
    }

    if (X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK) != 1) {
        UMS_AGENT_LOG_ERR("X509_VERIFY_PARAM_set_flags failed");
        return -1;
    }

    return 0;
}

static int ums_agent_setup_ssl_ctx(SSL_CTX *ctx,
    const struct ums_agent_x509_config *x509,
    const char *cipher_suite, bool is_server)
{
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_set_min_proto_version failed");
        return -1;
    }
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_set_max_proto_version failed");
        return -1;
    }

    if (SSL_CTX_set_ciphersuites(ctx, cipher_suite) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_set_ciphersuites '%s' failed", cipher_suite);
        return -1;
    }

    if (SSL_CTX_load_verify_locations(ctx, x509->truststore, NULL) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_load_verify_locations '%s' failed", x509->truststore);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, x509->certificate, SSL_FILETYPE_PEM) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_use_certificate_file '%s' failed", x509->certificate);
        return -1;
    }

    SSL_CTX_set_default_passwd_cb(ctx, ums_agent_tls_password_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)x509->prkey_pwd_desc);

    if (SSL_CTX_use_PrivateKey_file(ctx, x509->private_key, SSL_FILETYPE_PEM) != 1) {
        UMS_AGENT_LOG_ERR("SSL_CTX_use_PrivateKey_file '%s' failed", x509->private_key);
        return -1;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        UMS_AGENT_LOG_ERR("certificate and private key do not match");
        return -1;
    }

    if (x509->crl[0] != '\0') {
        if (ums_agent_setup_crl_verification(ctx, x509->crl) != 0) {
            return -1;
        }
    }

    SSL_CTX_set_verify(ctx,
        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if (ums_agent_setup_security_hardening(ctx, is_server) != 0) {
        return -1;
    }

    return 0;
}

static SSL_CTX *ums_agent_tls_create_ssl_ctx(const struct ums_agent_x509_config *x509,
    const char *cipher_suite, bool is_server)
{
    const SSL_METHOD *method = is_server ? TLS_server_method() : TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        UMS_AGENT_LOG_ERR("SSL_CTX_new for %s failed", is_server ? "server" : "client");
        return NULL;
    }

    if (ums_agent_setup_ssl_ctx(ctx, x509, cipher_suite, is_server) != 0) {
        UMS_AGENT_LOG_ERR("failed to setup %s SSL_CTX", is_server ? "server" : "client");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

static void ums_agent_tls_free_ssl_ctx(SSL_CTX *ctx)
{
    if (!ctx) {
        return;
    }

    SSL_CTX_free(ctx);
}

void ums_agent_secure_zero(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}

int ums_agent_tls_check_certs_expiry(const char *server_cert_path,
    const char *client_cert_path, bool force)
{
    if (!force) {
        struct timespec now;
        ums_agent_get_monotonic_time(&now);

        int64_t elapsed = ums_agent_timespec_diff_sec(
            &g_ums_agent_tls_ctx.last_cert_check_time, &now);
        if (elapsed < UMS_AGENT_TLS_CERT_CHECK_INTERVAL_SEC) {
            return 0;
        }

        g_ums_agent_tls_ctx.last_cert_check_time = now;
    }

    int ret = 0;
    if (ums_agent_tls_check_x509_cert_expiry(server_cert_path, "server_cert") != 0) {
        ret = -1;
    }
    if (ums_agent_tls_check_x509_cert_expiry(client_cert_path, "client_cert") != 0) {
        ret = -1;
    }
    return ret;
}

int ums_agent_tls_ctx_init(const struct ums_agent_config *config)
{
    if (g_ums_agent_tls_ctx.initialized) {
        UMS_AGENT_LOG_WARN("tls ctx already initialized");
        return 0;
    }

    (void)memset(&g_ums_agent_tls_ctx, 0, sizeof(g_ums_agent_tls_ctx));

    if (OPENSSL_init_ssl(0, NULL) != 1) {
        UMS_AGENT_LOG_ERR("OPENSSL_init_ssl failed");
        return -1;
    }

    g_ums_agent_tls_ctx.server_ssl_ctx = ums_agent_tls_create_ssl_ctx(
        &config->server, config->cipher_suite, true);
    if (!g_ums_agent_tls_ctx.server_ssl_ctx) {
        return -1;
    }

    g_ums_agent_tls_ctx.client_ssl_ctx = ums_agent_tls_create_ssl_ctx(
        &config->client, config->cipher_suite, false);
    if (!g_ums_agent_tls_ctx.client_ssl_ctx) {
        ums_agent_tls_free_ssl_ctx(g_ums_agent_tls_ctx.server_ssl_ctx);
        g_ums_agent_tls_ctx.server_ssl_ctx = NULL;
        return -1;
    }

    g_ums_agent_tls_ctx.initialized = true;
    return 0;
}

void ums_agent_tls_ctx_deinit(void)
{
    if (!g_ums_agent_tls_ctx.initialized) {
        return;
    }

    ums_agent_tls_free_ssl_ctx(g_ums_agent_tls_ctx.server_ssl_ctx);
    g_ums_agent_tls_ctx.server_ssl_ctx = NULL;
    ums_agent_tls_free_ssl_ctx(g_ums_agent_tls_ctx.client_ssl_ctx);
    g_ums_agent_tls_ctx.client_ssl_ctx = NULL;
    g_ums_agent_tls_ctx.initialized = false;
}

SSL_CTX *ums_agent_tls_get_server_ssl_ctx(void)
{
    if (!g_ums_agent_tls_ctx.initialized) {
        UMS_AGENT_LOG_ERR("tls ctx not initialized");
        return NULL;
    }
    return g_ums_agent_tls_ctx.server_ssl_ctx;
}

SSL_CTX *ums_agent_tls_get_client_ssl_ctx(void)
{
    if (!g_ums_agent_tls_ctx.initialized) {
        UMS_AGENT_LOG_ERR("tls ctx not initialized");
        return NULL;
    }
    return g_ums_agent_tls_ctx.client_ssl_ctx;
}

