/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
 * Description: UVS security implememtation
 * Author: Zhao Yusu
 * Create: 2024-02-28
 * Note:
 * History: 2024-02-28 Zhao Yusu         Introduce UVS socket security
 */

#include "tpsa_log.h"
#include "uvs_security.h"

#define SSL_SUCCESS         1
#define SSL_FAIL            0

static int uvs_verify_cert_wrapper(X509_STORE_CTX *ctx, void *arg)
{
    if (ctx == NULL || arg == NULL) {
        TPSA_LOG_ERR("Invalid argument.\n");
        return SSL_FAIL;
    }

    uvs_ssl_cfg_t *cfg = (uvs_ssl_cfg_t *)arg;
    if (cfg->verify_cert(ctx, cfg->crl_path) != 0) {
        TPSA_LOG_ERR("Fail to verify remote's certificate.\n");
        return SSL_FAIL;
    }

    return SSL_SUCCESS;
}

static int check_local(SSL_CTX *ctx, uvs_ssl_cfg_t *cfg)
{
    if (SSL_CTX_use_certificate_file(ctx, cfg->cert_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to load certificate file (path=%s).\n", cfg->cert_path);
        return -1;
    }

    char *pwd = NULL;
    int pwd_len;
    cfg->generate_pwd(&pwd, &pwd_len);
    if (pwd == NULL) {
        TPSA_LOG_ERR("Fail to generate password for private key file.\n");
        return -1;
    }

    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)pwd);

    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->prkey_path, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to load private key file (path=%s).\n", cfg->prkey_path);
        cfg->erase_pwd(pwd, pwd_len);
        return -1;
    }

    if (SSL_CTX_check_private_key(ctx) != SSL_SUCCESS) {
        TPSA_LOG_ERR("Certificate and private key do not match.\n");
        cfg->erase_pwd(pwd, pwd_len);
        return -1;
    }

    cfg->erase_pwd(pwd, pwd_len);
    return 0;
}

SSL *uvs_create_secure_socket(int sockfd, uvs_ssl_cfg_t *cfg, bool server)
{
    SSL *ssl;
    int rc;

    if (cfg == NULL) {
        TPSA_LOG_ERR("Invalid argument.\n");
        return NULL;
    }

    SSL_CTX *ctx = server ? SSL_CTX_new(TLS_server_method()) : SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        TPSA_LOG_ERR("Fail to create SSL context.\n");
        return NULL;
    }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to set protocol version for SSL context.\n");
        goto ERR_FREE_CTX;
    }

    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to set ciphersuite (TLS_AES_256_GCM_SHA384).\n");
        goto ERR_FREE_CTX;
    }

    if (server) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    if (cfg->verify_cert != NULL) {
        SSL_CTX_set_cert_verify_callback(ctx, uvs_verify_cert_wrapper, cfg);
    }

    if (SSL_CTX_load_verify_locations(ctx, cfg->ca_path, NULL) != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to load CA file (path=%s).\n", cfg->ca_path);
        goto ERR_FREE_CTX;
    }

    if (check_local(ctx, cfg) != 0) {
        goto ERR_FREE_CTX;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        TPSA_LOG_ERR("Fail to create SSL object.\n");
        goto ERR_FREE_CTX;
    }

    if (SSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to set fd for SSL object.\n");
        goto ERR_FREE_SSL;
    }

    rc = server ? SSL_accept(ssl) : SSL_connect(ssl);
    if (rc != SSL_SUCCESS) {
        TPSA_LOG_ERR("Fail to establish TLS connection.\n");
        goto ERR_FREE_SSL;
    }

    SSL_CTX_free(ctx);
    return ssl;

ERR_FREE_SSL:
    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
ERR_FREE_CTX:
    SSL_CTX_free(ctx);
    return NULL;
}

void uvs_destroy_secure_socket(SSL *ssl)
{
    if (ssl == NULL) {
        return;
    }

    (void)SSL_shutdown(ssl);
    SSL_free(ssl);
}

int uvs_ssl_init(uvs_ssl_cfg_t *cfg)
{
    if (cfg == NULL || cfg->ca_path == NULL || cfg->cert_path == NULL || cfg->prkey_path == NULL ||
        cfg->generate_pwd == NULL || cfg->erase_pwd == NULL) {
        TPSA_LOG_ERR("Invalid argument.\n");
        return -1;
    }

    (void)SSL_library_init();
    (void)OpenSSL_add_all_algorithms();
    (void)SSL_load_error_strings();
    return 0;
}