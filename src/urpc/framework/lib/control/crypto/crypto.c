/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: realize crypto module
 * Create: 2024-07-09
 */

#include <fcntl.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <string.h>

#include "cp.h"
#include "keepalive.h"
#include "state.h"
#include "urpc_framework_api.h"
#include "urpc_framework_errno.h"
#include "urpc_lib_log.h"
#include "protocol.h"

#include "crypto.h"

static char g_urpc_cipher_list[URPC_MAX_CIPHER_LIST_LENGTH] = {0};
static char g_urpc_cipher_suites[URPC_MAX_CIPHER_LIST_LENGTH] = {0};

static struct {
    volatile urpc_ssl_config_t ssl_cfg;
    pthread_mutex_t lock;
    bool seed_inited;
} g_urpc_crypto_ctx = {
    .ssl_cfg = {.psk.cipher_list = g_urpc_cipher_list, .psk.cipher_suites = g_urpc_cipher_suites},
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .seed_inited = false,
};

static int is_ssl_cfg_valid(urpc_ssl_config_t *cfg)
{
    if (cfg == NULL) {
        URPC_LIB_LOG_ERR("ssl config is null\n");
        return -URPC_ERR_EINVAL;
    }

    if ((cfg->ssl_flag & URPC_SSL_FLAG_ENABLE) == 0) {
        URPC_LIB_LOG_INFO("ssl is disabled\n");
        return URPC_SUCCESS;
    }

    if ((cfg->ssl_flag & URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE) != 0 &&
        (cfg->ssl_flag & URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE) == 0) {
        URPC_LIB_LOG_ERR("only support to set URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE alone or "
                         "(URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE | URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE) together\n");
        return -URPC_ERR_EINVAL;
    }

    // Currently, only TLS-PSK could be used for cp crypto module.
    if (cfg->ssl_mode != SSL_MODE_PSK) {
        URPC_LIB_LOG_ERR("unsupported ssl mode %d\n", cfg->ssl_mode);
        return -URPC_ERR_EINVAL;
    }

    if (cfg->max_tls_version > URPC_TLS_VERSION_1_3 || cfg->min_tls_version < URPC_TLS_VERSION_1_2 ||
        cfg->min_tls_version > cfg->max_tls_version) {
        URPC_LIB_LOG_ERR("tls version is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    // cipher_list must be set for TLS1.2 and cipher_suites must be set for TLS1.3
    if (cfg->min_tls_version == URPC_TLS_VERSION_1_2 && (cfg->psk.cipher_list == NULL ||
        strnlen(cfg->psk.cipher_list, URPC_MAX_CIPHER_LIST_LENGTH) == URPC_MAX_CIPHER_LIST_LENGTH)) {
        URPC_LIB_LOG_ERR("cipher_list is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    if (cfg->max_tls_version == URPC_TLS_VERSION_1_3 && (cfg->psk.cipher_suites == NULL ||
        strnlen(cfg->psk.cipher_suites, URPC_MAX_CIPHER_LIST_LENGTH) == URPC_MAX_CIPHER_LIST_LENGTH)) {
        URPC_LIB_LOG_ERR("cipher_suites is invalid\n");
        return -URPC_ERR_EINVAL;
    }

    urpc_role_t role = urpc_role_get();
    if (role != URPC_ROLE_SERVER && cfg->psk.client_cb_func == NULL) {
        URPC_LIB_LOG_ERR("client_cb_func should not be null for client\n");
        return -URPC_ERR_EINVAL;
    } else if (role != URPC_ROLE_CLIENT && cfg->psk.server_cb_func == NULL) {
        URPC_LIB_LOG_ERR("server_cb_func should not be null for server\n");
        return -URPC_ERR_EINVAL;
    }

    return URPC_SUCCESS;
}

static int ssl_cfg_copy(urpc_ssl_config_t *dst_cfg, urpc_ssl_config_t *src_cfg)
{
    dst_cfg->ssl_flag = src_cfg->ssl_flag;
    if ((dst_cfg->ssl_flag & URPC_SSL_FLAG_ENABLE) == 0) {
        return URPC_SUCCESS;
    }
    dst_cfg->ssl_mode = src_cfg->ssl_mode;
    dst_cfg->min_tls_version = src_cfg->min_tls_version;
    dst_cfg->max_tls_version = src_cfg->max_tls_version;

    if (src_cfg->psk.cipher_list != NULL) {
        strncpy(dst_cfg->psk.cipher_list, src_cfg->psk.cipher_list, URPC_MAX_CIPHER_LIST_LENGTH - 1);
        dst_cfg->psk.cipher_list[URPC_MAX_CIPHER_LIST_LENGTH - 1] = '\0';
    } else {
        memset(dst_cfg->psk.cipher_list, 0, URPC_MAX_CIPHER_LIST_LENGTH);
    }

    if (src_cfg->psk.cipher_suites != NULL) {
        strncpy(dst_cfg->psk.cipher_suites, src_cfg->psk.cipher_suites, URPC_MAX_CIPHER_LIST_LENGTH - 1);
        dst_cfg->psk.cipher_suites[URPC_MAX_CIPHER_LIST_LENGTH - 1] = '\0';
    } else {
        memset(dst_cfg->psk.cipher_suites, 0, URPC_MAX_CIPHER_LIST_LENGTH);
    }

    dst_cfg->psk.client_cb_func = src_cfg->psk.client_cb_func;
    dst_cfg->psk.server_cb_func = src_cfg->psk.server_cb_func;
    return URPC_SUCCESS;
}

int urpc_ssl_config_set(urpc_ssl_config_t *cfg)
{
    if (urpc_state_get() == URPC_STATE_UNINIT) {
        URPC_LIB_LOG_ERR("urpc should be initialized first\n");
        return -URPC_ERR_EPERM;
    }

    int ret = is_ssl_cfg_valid(cfg);
    if (ret != URPC_SUCCESS) {
        return ret;
    }

    // Copy the SSL config. Avoid the concurrency of reading and writing of g_ssl_cfg.
    (void)pthread_mutex_lock(&g_urpc_crypto_ctx.lock);
    if ((cfg->ssl_flag & URPC_SSL_FLAG_ENABLE) != 0 && !g_urpc_crypto_ctx.seed_inited) {
        ret = urpc_rand_seed_init();
        g_urpc_crypto_ctx.seed_inited = (ret == URPC_SUCCESS);
    }
    if (ret == URPC_SUCCESS) {
        ret = ssl_cfg_copy((urpc_ssl_config_t *)&g_urpc_crypto_ctx.ssl_cfg, cfg);
    }
    (void)pthread_mutex_unlock(&g_urpc_crypto_ctx.lock);
    if (ret == URPC_SUCCESS) {
        URPC_LIB_LOG_INFO("ssl config set success ssl mode = %u, tls_version[%u, %u]\n",
            cfg->ssl_mode, cfg->min_tls_version, cfg->max_tls_version);
    }
    return ret;
}

static void ssl_init(void)
{
    // According to the api documents of SSL, it's safe not to check the return value of below 3 functions.
    // Always return "1". SSL_library_init() is not reentrant, execute it after lock();
    (void)SSL_library_init();
    // Return no values.
    OpenSSL_add_all_algorithms();
    // Return no values.
    SSL_load_error_strings();
}

static inline int crypto_tls_version_get(urpc_tls_version_t version)
{
    return version == URPC_TLS_VERSION_1_2 ? TLS1_2_VERSION : TLS1_3_VERSION;
}

static SSL_CTX *ssl_ctx_create(urpc_ssl_config_t *cfg, bool is_server)
{
    SSL_CTX *ssl_ctx;
    if (is_server) {
        ssl_ctx = SSL_CTX_new(TLS_server_method());
    } else {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
    }
    if (ssl_ctx == NULL) {
        URPC_LIB_LOG_ERR("SSL_CTX_new() failed\n");
        return NULL;
    }

    (void)SSL_CTX_set_min_proto_version(ssl_ctx, crypto_tls_version_get(cfg->min_tls_version));
    (void)SSL_CTX_set_max_proto_version(ssl_ctx, crypto_tls_version_get(cfg->max_tls_version));

    if (strlen(cfg->psk.cipher_list) != 0 && SSL_CTX_set_cipher_list(ssl_ctx, cfg->psk.cipher_list) <= 0) {
        URPC_LIB_LOG_ERR("SSL_CTX_set_cipher_list() failed. cipher_list = %s\n", cfg->psk.cipher_list);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (strlen(cfg->psk.cipher_suites) != 0 && SSL_CTX_set_ciphersuites(ssl_ctx, cfg->psk.cipher_suites) <= 0) {
        URPC_LIB_LOG_ERR("SSL_CTX_set_ciphersuites() failed. cipher_suites = %s\n", cfg->psk.cipher_suites);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    return ssl_ctx;
}

SSL *crypto_ssl_init(int sockfd, bool is_server)
{
    int ret = 0;
    char cipher_list[URPC_MAX_CIPHER_LIST_LENGTH] = {0};
    char cipher_suites[URPC_MAX_CIPHER_LIST_LENGTH] = {0};
    urpc_ssl_config_t cfg = {0};
    cfg.psk.cipher_list = cipher_list;
    cfg.psk.cipher_suites = cipher_suites;

    (void)pthread_mutex_lock(&g_urpc_crypto_ctx.lock);
    // Initialize the SSL library. Do not need rollback.
    ssl_init();
    ret = ssl_cfg_copy(&cfg, (urpc_ssl_config_t *)&g_urpc_crypto_ctx.ssl_cfg);
    (void)pthread_mutex_unlock(&g_urpc_crypto_ctx.lock);
    if (ret != URPC_SUCCESS) {
        goto ERR_EXIT;
    }

    SSL_CTX *ssl_ctx = ssl_ctx_create(&cfg, is_server);
    if (ssl_ctx == NULL) {
        goto ERR_EXIT;
    }

    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        URPC_LIB_LOG_ERR("SSL_new() failed\n");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    ret = SSL_set_fd(ssl, sockfd);
    if (ret <= 0) {
        URPC_LIB_LOG_ERR("SSL_set_fd() failed\n");
        goto UNINIT_SSL;
    }

    // Register the callback functions and establish the TLS-PSK connection.
    if (is_server) {
        SSL_set_psk_server_callback(ssl, (SSL_psk_server_cb_func)cfg.psk.server_cb_func);
    } else {
        SSL_set_psk_client_callback(ssl, (SSL_psk_client_cb_func)cfg.psk.client_cb_func);
    }
    return ssl;
UNINIT_SSL:
    crypto_ssl_uninit(ssl);
ERR_EXIT:
    return NULL;
}

void crypto_ssl_uninit(SSL *ssl)
{
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
}

int crypto_ssl_connect(SSL *ssl, int *err)
{
    int ret = SSL_connect(ssl);
    if (ret > 0) {
        // handshake completed successfully
        return URPC_SUCCESS;
    }
    *err = SSL_get_error(ssl, ret);
    if (*err == SSL_ERROR_WANT_READ || *err == SSL_ERROR_WANT_WRITE) {
        return URPC_RUNNING;
    }
    URPC_LIB_LOG_ERR("connect failed with errno %d\n", *err);
    return URPC_FAIL;
}

int crypto_ssl_accept(SSL *ssl, int *err)
{
    int ret = SSL_accept(ssl);
    if (ret > 0) {
        // handshake completed successfully
        return URPC_SUCCESS;
    }
    *err = SSL_get_error(ssl, ret);
    if (*err == SSL_ERROR_WANT_READ || *err == SSL_ERROR_WANT_WRITE) {
        return URPC_RUNNING;
    }
    URPC_LIB_LOG_ERR("ssl accept failed with errno %d\n", *err);
    return URPC_FAIL;
}

size_t crypto_ssl_send(SSL *ssl, void *buf, size_t size)
{
    /* blocking send */
    char *cur = (char *)buf;
    ssize_t sent = 0;
    size_t total = size;
    while (total > 0) {
        sent = SSL_write(ssl, cur, total);
        int ret = SSL_get_error(ssl, sent);
        if (ret == SSL_ERROR_NONE) {
            total -= sent;
            cur += sent;
        } else if (ret == SSL_ERROR_WANT_WRITE) {
            continue;
        } else {
            URPC_LIB_LOG_ERR("SSL_write() failed! err: %s, ret: %d, SSL_get_error: %d\n", strerror(errno), sent, ret);
            break;
        }
    }

    // Return the size of successfully sent data.
    return size - total;
}

size_t crypto_ssl_recv(SSL *ssl, void *buf, size_t size)
{
    /* blocking recv */
    char *cur = (char *)buf;
    ssize_t received = 0;
    size_t total = size;
    while (total > 0) {
        received = SSL_read(ssl, cur, total);
        int ret = SSL_get_error(ssl, received);
        if (ret == SSL_ERROR_NONE) {
            total -= received;
            cur += received;
        } else if (ret == SSL_ERROR_WANT_READ) {
            continue;
        } else {
            URPC_LIB_LOG_ERR(
                "SSL_read() failed! err: %s, ret: %d, SSL_get_error: %d\n", strerror(errno), received, ret);
            break;
        }
    }

    // Return the size of successfully received data.
    return size - total;
}

bool crypto_is_ssl_enabled_lock_free(void)
{
    return (g_urpc_crypto_ctx.ssl_cfg.ssl_flag & URPC_SSL_FLAG_ENABLE) != 0;
}

bool crypto_is_ssl_enabled(void)
{
    (void)pthread_mutex_lock(&g_urpc_crypto_ctx.lock);
    bool ret = crypto_is_ssl_enabled_lock_free();
    (void)pthread_mutex_unlock(&g_urpc_crypto_ctx.lock);
    return ret;
}

// whether ssl encryption is enabled for data plane.
bool crypto_is_dp_ssl_enabled(void)
{
    (void)pthread_mutex_lock(&g_urpc_crypto_ctx.lock);
    bool ret = (g_urpc_crypto_ctx.ssl_cfg.ssl_flag & URPC_SSL_FLAG_ENABLE) != 0 &&
        (g_urpc_crypto_ctx.ssl_cfg.ssl_flag & URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE) == 0;
    (void)pthread_mutex_unlock(&g_urpc_crypto_ctx.lock);
    return ret;
}

// whether ssl encryption is enabled for data plane. concurrency correctness is not guaranteed.
bool crypto_is_dp_ssl_enabled_lock_free(void)
{
    uint32_t ssl_flag = g_urpc_crypto_ctx.ssl_cfg.ssl_flag;
    return (ssl_flag & URPC_SSL_FLAG_ENABLE) != 0 && (ssl_flag & URPC_SSL_FLAG_URPC_ENCRYPT_DISABLE) == 0;
}

// whether user payload (user header & user data) need encryption. concurrency correctness is not guaranteed.
// Note that, user payload encryption should only be enabled when urpc_is_dp_ssl_enabled() return true.
static bool crypto_is_user_payload_encryption_enabled_lock_free(void)
{
    return (g_urpc_crypto_ctx.ssl_cfg.ssl_flag & URPC_SSL_FLAG_SGE_ENCRYPT_DISABLE) == 0;
}

uint32_t crypto_security_field_size_get(void)
{
    return crypto_is_dp_ssl_enabled_lock_free() ? URPC_AES_CHECK_LEN : 0;
}

int crypto_ssl_gen_crypto_key(crypto_key_t *crypto_key)
{
    return RAND_priv_bytes(crypto_key->key, URPC_CRYPTO_KEY_BYTES) == 1 ? URPC_SUCCESS : URPC_FAIL;
}

uint32_t crypto_gen_rand_channel_id(uint32_t id)
{
    // if ssl is not enabled, just use id
    if (!crypto_is_ssl_enabled_lock_free()) {
        return id;
    }

    uint32_t rand_id = id;
    // channel id use 24bit
    if (RAND_priv_bytes((uint8_t *)&rand_id, sizeof(uint32_t) - 1) != 1) {
        URPC_LIB_LOG_WARN("generate rand channel id failed, use base id directly\n");
        return id;
    }

    return rand_id;
}

int crypto_cipher_init(urpc_cipher_t *cipher_opt, crypto_key_t *crypto_key)
{
    // for client, one server_node should only be attached once; for server, new channel is created when it's attached.
    if (cipher_opt->cipher != NULL) {
        URPC_LIB_LOG_INFO("crypto cipher has been initialized\n");
        return URPC_SUCCESS;
    }

    cipher_opt->cipher = EVP_aes_256_gcm();
    if (cipher_opt->cipher == NULL) {
        URPC_LIB_LOG_ERR("create crypto cipher failed\n");
        return URPC_FAIL;
    }
    memcpy(&cipher_opt->crypto_key, crypto_key, sizeof(crypto_key_t));
    atomic_init(&cipher_opt->counter, 0);
    URPC_LIB_LOG_DEBUG("cipher initialized successfully\n");

    return URPC_SUCCESS;
}

void crypto_cipher_uninit(urpc_cipher_t *cipher_opt)
{
    if (cipher_opt == NULL) {
        return;
    }
    cipher_opt->cipher = NULL;
    memset(&cipher_opt->crypto_key, 0, sizeof(crypto_key_t));
    cipher_opt->chid = URPC_INVALID_ID_U32;
    atomic_init(&cipher_opt->counter, 0);
    URPC_LIB_LOG_DEBUG("cipher uninitialized successfully\n");
}

EVP_CIPHER_CTX *crypto_encrypt_ctx_init(urpc_cipher_t *cipher_opt,
    unsigned char *iv, size_t iv_len __attribute__((unused)))
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        URPC_LIB_LOG_ERR("cannot create EVP_CIPHER_CTX\n");
        return NULL;
    }
    uint32_t *chid = (uint32_t *)iv;
    *chid = cipher_opt->chid;
    unsigned long long *counter = (unsigned long long *)(iv + sizeof(cipher_opt->chid));
    *counter = atomic_fetch_add(&cipher_opt->counter, 1);
    if (EVP_EncryptInit_ex(ctx, cipher_opt->cipher, NULL, cipher_opt->crypto_key.key, iv) == 0) {
        URPC_LIB_LOG_ERR("Cipher Encrypt Init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

int crypto_encrypt_user_data(
    EVP_CIPHER_CTX *ctx, urpc_sge_t *sge, uint32_t sge_num, uint32_t hdr_index, uint32_t first_sge_offset)
{
    int encrypt_out = 0;
    uint32_t offset = first_sge_offset;
    bool user_payload_encryption_enabled = crypto_is_user_payload_encryption_enabled_lock_free();
    for (uint32_t i = hdr_index; i < sge_num; ++i) {
        if (URPC_UNLIKELY(sge[i].flag & SGE_FLAG_DATA_ZONE)) {
            continue;
        }
        if (EVP_EncryptUpdate(ctx,
            user_payload_encryption_enabled ? (unsigned char *)((uintptr_t)sge[i].addr + offset) : NULL,
            &encrypt_out, (unsigned char *)((uintptr_t)sge[i].addr + offset), sge[i].length - offset) != 1) {
            URPC_LIB_LOG_ERR("cipher encrypt add user data sge[%u] for encryption failed\n", i);
            return URPC_FAIL;
        }
        offset = 0;
    }

    return URPC_SUCCESS;
}

int crypto_decrypt_user_data(
    EVP_CIPHER_CTX *ctx, urpc_sge_t *sge, uint32_t sge_num, uint32_t hdr_index, uint32_t first_sge_offset)
{
    int decrypt_out = 0;
    uint32_t offset = first_sge_offset;
    bool user_payload_encryption_enabled = crypto_is_user_payload_encryption_enabled_lock_free();
    for (uint32_t i = hdr_index; i < sge_num; ++i) {
        if (EVP_DecryptUpdate(ctx,
            user_payload_encryption_enabled ? (unsigned char *)((uintptr_t)sge[i].addr + offset) : NULL,
            &decrypt_out, (unsigned char *)((uintptr_t)sge[i].addr + offset), sge[i].length - offset) != 1) {
            URPC_LIB_LOG_ERR("decrypt user data sge[%u] failed\n", i);
            return URPC_FAIL;
        }
        offset = 0;
    }

    return URPC_SUCCESS;
}

int crypto_encrypt_keepalive_req(urpc_cipher_t *cipher_opt, urpc_sge_t *sge, uint32_t sge_num)
{
    if (URPC_UNLIKELY(sge_num != 1 || sge[0].length < URPC_KEEPALIVE_HDR_SIZE)) {
        URPC_LIB_LIMIT_LOG_ERR("keepalive sge invalid\n");
        return URPC_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (URPC_UNLIKELY(ctx == NULL)) {
        URPC_LIB_LIMIT_LOG_ERR("cannot create EVP_CIPHER_CTX\n");
        return URPC_FAIL;
    }

    // generate iv & init encrypt ctx
    unsigned char iv[URPC_AES_IV_LEN];
    uint32_t *chid = (uint32_t *)iv;
    *chid = cipher_opt->chid;
    unsigned long long *counter = (unsigned long long *)(iv + sizeof(cipher_opt->chid));
    *counter = atomic_fetch_add(&cipher_opt->counter, 1);
    if (EVP_EncryptInit_ex(ctx, cipher_opt->cipher, NULL, cipher_opt->crypto_key.key, iv) == 0) {
        URPC_LIB_LIMIT_LOG_ERR("cipher encrypt init failed\n");
        goto ERR_EXIT;
    }

    // base header: integrity
    int encrypt_out = 0;
    urpc_req_head_t *base = (urpc_req_head_t *)(uintptr_t)sge[0].addr;
    if (EVP_EncryptUpdate(ctx, NULL, &encrypt_out, (unsigned char *)base,
                          URPC_KEEPALIVE_HDR_SIZE - URPC_AES_CHECK_LEN) != 1) {
        URPC_LIB_LIMIT_LOG_ERR("cipher encrypt add keepalive header for integrity check failed\n");
        goto ERR_EXIT;
    }

    // if has user input msg
    unsigned char *need_encrypt_ext = (unsigned char *)((uintptr_t)(void *)base + URPC_KEEPALIVE_HDR_SIZE);
    if (sge[0].length > URPC_KEEPALIVE_HDR_SIZE &&
        EVP_EncryptUpdate(ctx, need_encrypt_ext, &encrypt_out, need_encrypt_ext,
                          sge[0].length - URPC_KEEPALIVE_HDR_SIZE) != 1) {
        URPC_LIB_LIMIT_LOG_ERR("cipher encrypt add keepalive message for encryption failed\n");
        goto ERR_EXIT;
    }

    if (EVP_EncryptFinal_ex(ctx, NULL, &encrypt_out) != 1) {
        URPC_LIB_LIMIT_LOG_ERR("Cipher Encrypt Final failed\n");
        goto ERR_EXIT;
    }

    // generate tag
    unsigned char tag[URPC_AES_TAG_LEN];
    if ((EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, URPC_AES_TAG_LEN, tag)) != 1) {
        URPC_LIB_LIMIT_LOG_ERR("cipher encrypt generate tag data failed\n");
        goto ERR_EXIT;
    }

    urpc_security_exthdr_t *sec_hdr = (urpc_security_exthdr_t *)(uintptr_t)(need_encrypt_ext - URPC_AES_CHECK_LEN);
    memcpy(sec_hdr->iv, iv, URPC_AES_IV_LEN);
    memcpy(sec_hdr->tag, tag, URPC_AES_TAG_LEN);
    URPC_LIB_LIMIT_LOG_DEBUG("cipher encrypt keepalive successfully\n");

    EVP_CIPHER_CTX_free(ctx);
    return URPC_SUCCESS;

ERR_EXIT:
    EVP_CIPHER_CTX_free(ctx);
    return URPC_FAIL;
}

int crypto_decrypt_keepalive_req(urpc_cipher_t *cipher_opt, urpc_sge_t *sge, uint32_t sge_num)
{
    if (URPC_UNLIKELY(sge_num != 1 || sge[0].length < URPC_KEEPALIVE_HDR_SIZE)) {
        URPC_LIB_LIMIT_LOG_ERR("keepalive sge invalid\n");
        return URPC_FAIL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        URPC_LIB_LIMIT_LOG_ERR("cannot create EVP_CIPHER_CTX_new\n");
        return URPC_FAIL;
    }

    unsigned char iv[URPC_AES_IV_LEN];
    unsigned char tag[URPC_AES_TAG_LEN];
    urpc_req_head_t *base = (urpc_req_head_t *)(uintptr_t)sge[0].addr;
    unsigned char *need_encrypt_ext = (unsigned char *)((uintptr_t)(void *)base + URPC_KEEPALIVE_HDR_SIZE);
    urpc_security_exthdr_t *sec_hdr = (urpc_security_exthdr_t *)(uintptr_t)(need_encrypt_ext - URPC_AES_CHECK_LEN);
    // read iv & tag from security header
    memcpy(iv, sec_hdr->iv, URPC_AES_IV_LEN);
    memcpy(tag, sec_hdr->tag, URPC_AES_TAG_LEN);

    if (cipher_opt != NULL) {
        if (EVP_DecryptInit_ex(ctx, cipher_opt->cipher, NULL, cipher_opt->crypto_key.key, iv) == 0) {
            URPC_LIB_LIMIT_LOG_ERR("cipher decrypt init failed\n");
            goto ERR_EXIT;
        }
    } else {
        urpc_keepalive_head_t *keepalive_hdr =
            (urpc_keepalive_head_t *)((uintptr_t)(sge[0].addr + sizeof(urpc_req_head_t)));
        uint32_t server_chid = server_channel_id_map_lookup(urpc_keepalive_parse_server_channel(keepalive_hdr));
        urpc_server_channel_info_t *channel = server_channel_get_with_rw_lock(server_chid, false);
        if (channel == NULL) {
            URPC_LIB_LIMIT_LOG_ERR("get server channel failed\n");
            goto ERR_EXIT;
        }
        if (channel->cipher_opt == NULL) {
            (void)pthread_rwlock_unlock(&channel->rw_lock);
            URPC_LIB_LIMIT_LOG_ERR("server channel cipher_opt is null\n");
            goto ERR_EXIT;
        }
        if (EVP_DecryptInit_ex(ctx, channel->cipher_opt->cipher, NULL, channel->cipher_opt->crypto_key.key, iv) == 0) {
            (void)pthread_rwlock_unlock(&channel->rw_lock);
            URPC_LIB_LIMIT_LOG_ERR("cipher decrypt init failed\n");
            goto ERR_EXIT;
        }
        (void)pthread_rwlock_unlock(&channel->rw_lock);
    }

    // base header: integrity
    int decrypt_out = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &decrypt_out, (unsigned char *)base,
                          URPC_KEEPALIVE_HDR_SIZE - URPC_AES_CHECK_LEN) != 1) {
        URPC_LIB_LOG_ERR("decrypt basic keepalive header failed\n");
        goto ERR_EXIT;
    }

    // if has user input msg
    if (sge[0].length > URPC_KEEPALIVE_HDR_SIZE &&
        EVP_DecryptUpdate(ctx, need_encrypt_ext, &decrypt_out, need_encrypt_ext,
                          sge[0].length - URPC_KEEPALIVE_HDR_SIZE) != 1) {
        URPC_LIB_LOG_ERR("decrypt keepalive message failed\n");
        goto ERR_EXIT;
    }

    // valid tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, URPC_AES_TAG_LEN, tag) != 1) {
        URPC_LIB_LOG_ERR("cipher decrypt check tag data failed\n");
        goto ERR_EXIT;
    }

    if (EVP_DecryptFinal_ex(ctx, NULL, &decrypt_out) != 1) {
        URPC_LIB_LOG_ERR("cipher EVP_DecryptFinal_ex failed\n");
        goto ERR_EXIT;
    }

    URPC_LIB_LIMIT_LOG_DEBUG("cipher decrypt keepalive successfully\n");
    EVP_CIPHER_CTX_free(ctx);
    return URPC_SUCCESS;

ERR_EXIT:
    EVP_CIPHER_CTX_free(ctx);
    return URPC_FAIL;
}

int crypto_server_cipher_ctx_init(EVP_CIPHER_CTX *ctx, uint32_t server_channel, unsigned char *iv, size_t iv_len)
{
    uint32_t server_chid = server_channel_id_map_lookup(server_channel);
    urpc_server_channel_info_t *channel = server_channel_get_with_rw_lock(server_chid, false);
    if (channel == NULL) {
        URPC_LIB_LOG_ERR("get server channel failed\n");
        return URPC_FAIL;
    }
    if (channel->cipher_opt == NULL) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        URPC_LIB_LOG_ERR("server channel cipher_opt is null\n");
        return URPC_FAIL;
    }
    if (EVP_DecryptInit_ex(ctx, channel->cipher_opt->cipher, NULL, channel->cipher_opt->crypto_key.key, iv) == 0) {
        (void)pthread_rwlock_unlock(&channel->rw_lock);
        URPC_LIB_LOG_ERR("cipher decrypt init failed\n");
        return URPC_FAIL;
    }
    (void)pthread_rwlock_unlock(&channel->rw_lock);
    return URPC_SUCCESS;
}

// if ssl not enabled, just use timestamp to ensure time-varying
uint32_t crypto_gen_rand_token(void)
{
    if (!crypto_is_ssl_enabled_lock_free()) {
        return get_timestamp();
    }

    uint32_t rand_token;
    if (RAND_priv_bytes((uint8_t *)&rand_token, sizeof(uint32_t)) != 1) {
        URPC_LIB_LOG_WARN("generate rand token failed, use timestamp directly\n");
        return get_timestamp();
    }

    return rand_token;
}