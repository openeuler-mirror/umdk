/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Configuration loading and validation for the UMS agent
 * Author: Hu Ying
 * Create: 2026-04-20
 * Note:
 * History: 2026-04-20  Create File
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <glib.h>

#include "ums_agent_utils.h"
#include "ums_agent_config.h"

#define UMS_AGENT_MAX_CONNS_MIN     1
#define UMS_AGENT_MAX_CONNS_MAX     65535
#define UMS_AGENT_MAX_CONNS_DEFAULT 1024

#define UMS_AGENT_MIN_LISTEN_PORT     1024
#define UMS_AGENT_MAX_LISTEN_PORT     65535
#define UMS_AGENT_DEFAULT_LISTEN_PORT 61080
#define UMS_AGENT_DEFAULT_CIPHER_SUITE "TLS_AES_256_GCM_SHA384"

#define UMS_AGENT_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static const char *g_ums_agent_supported_cipher_suites[] = {
    "TLS_AES_256_GCM_SHA384"
};

static const char *g_ums_agent_log_level_names[] = {
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
};

static enum ums_agent_log_level ums_agent_str_to_log_level(const char *str)
{
    for (int i = 0; i < UMS_AGENT_LOG_LEVEL_MAX; i++) {
        if (strcasecmp(str, g_ums_agent_log_level_names[i]) == 0) {
            return (enum ums_agent_log_level)i;
        }
    }
    return UMS_AGENT_LOG_LEVEL_MAX;
}

static void ums_agent_set_defaults(struct ums_agent_config *config)
{
    config->log_level = UMS_AGENT_LOG_LEVEL_INFO;
    config->listen_port = UMS_AGENT_DEFAULT_LISTEN_PORT;
    config->max_conns = UMS_AGENT_MAX_CONNS_DEFAULT;
    (void)snprintf(config->cipher_suite, sizeof(config->cipher_suite), "%s", UMS_AGENT_DEFAULT_CIPHER_SUITE);

    memset(&config->client, 0, sizeof(config->client));
    memset(&config->server, 0, sizeof(config->server));
}

static bool ums_agent_is_valid_port(int port)
{
    return (port >= UMS_AGENT_MIN_LISTEN_PORT) && (port <= UMS_AGENT_MAX_LISTEN_PORT);
}

static bool ums_agent_is_valid_cipher_suite(const char *cipher_suite)
{
    for (size_t i = 0; i < UMS_AGENT_ARRAY_SIZE(g_ums_agent_supported_cipher_suites); i++) {
        if (strcmp(cipher_suite, g_ums_agent_supported_cipher_suites[i]) == 0) {
            return true;
        }
    }

    return false;
}

int ums_agent_resolve_path(const char *path, const char *config_name, char *resolved_path)
{
    if (!path || !config_name || !resolved_path) {
        UMS_AGENT_LOG_ERR("invalid parameter: path=%p, config_name=%p, resolved_path=%p",
            path, config_name, resolved_path);
        return -1;
    }

    size_t path_len = strnlen(path, PATH_MAX);
    if (path_len == 0) {
        UMS_AGENT_LOG_ERR("%s is empty", config_name);
        return -1;
    }
    if (path_len >= PATH_MAX) {
        UMS_AGENT_LOG_ERR("%s exceeds maximum path length (%u characters, including null terminator)",
            config_name, PATH_MAX);
        return -1;
    }

    if (realpath(path, resolved_path) == NULL) {
        UMS_AGENT_LOG_ERR("failed to resolve %s: %s (errno=%d)", config_name, strerror(errno), errno);
        return -1;
    }

    return 0;
}

static int ums_agent_validate_and_resolve_path(const char *path,
    const char *config_name, char *resolved_path)
{
    if (ums_agent_resolve_path(path, config_name, resolved_path) != 0) {
        return -1;
    }

    if (access(resolved_path, R_OK) != 0) {
        UMS_AGENT_LOG_ERR("%s is not readable: %s (errno=%d)", config_name, strerror(errno), errno);
        return -1;
    }

    return 0;
}

static int ums_agent_load_x509_truststore(GKeyFile *kf, const char *group,
    struct ums_agent_x509_config *x509)
{
    gchar *value = g_key_file_get_string(kf, group, "x509.truststore", NULL);
    if (!value) {
        UMS_AGENT_LOG_ERR("%s.x509.truststore must be configured", group);
        return -1;
    }

    char resolved_path[PATH_MAX];
    if (ums_agent_validate_and_resolve_path(value, "x509.truststore",
        resolved_path) != 0) {
        g_free(value);
        return -1;
    }

    (void)snprintf(x509->truststore, sizeof(x509->truststore), "%s", resolved_path);
    g_free(value);
    return 0;
}

static int ums_agent_load_x509_crl(GKeyFile *kf, const char *group,
    struct ums_agent_x509_config *x509)
{
    gchar *value = g_key_file_get_string(kf, group, "x509.crl", NULL);
    if (!value) {
        return 0;
    }

    if (value[0] == '\0') {
        g_free(value);
        return 0;
    }

    char resolved_path[PATH_MAX];
    if (ums_agent_validate_and_resolve_path(value, "x509.crl", resolved_path) != 0) {
        g_free(value);
        return -1;
    }
    (void)snprintf(x509->crl, sizeof(x509->crl), "%s", resolved_path);
    g_free(value);
    return 0;
}

static int ums_agent_load_x509_certificate(GKeyFile *kf, const char *group,
    struct ums_agent_x509_config *x509)
{
    gchar *value = g_key_file_get_string(kf, group, "x509.certificate", NULL);
    if (!value) {
        UMS_AGENT_LOG_ERR("%s.x509.certificate must be configured", group);
        return -1;
    }

    char resolved_path[PATH_MAX];
    if (ums_agent_validate_and_resolve_path(value, "x509.certificate", resolved_path) != 0) {
        g_free(value);
        return -1;
    }
    (void)snprintf(x509->certificate, sizeof(x509->certificate), "%s", resolved_path);
    g_free(value);
    return 0;
}

static int ums_agent_load_x509_private_key(GKeyFile *kf, const char *group,
    struct ums_agent_x509_config *x509)
{
    gchar *value = g_key_file_get_string(kf, group, "x509.private_key", NULL);
    if (!value) {
        UMS_AGENT_LOG_ERR("%s.x509.private_key must be configured", group);
        return -1;
    }

    char resolved_path[PATH_MAX];
    if (ums_agent_validate_and_resolve_path(value, "x509.private_key", resolved_path) != 0) {
        g_free(value);
        return -1;
    }
    (void)snprintf(x509->private_key, sizeof(x509->private_key), "%s", resolved_path);
    g_free(value);
    return 0;
}

static int ums_agent_load_x509_prkey_pwd_desc(GKeyFile *kf, const char *group,
    struct ums_agent_x509_config *x509)
{
    gchar *value = g_key_file_get_string(kf, group, "x509.prkey_pwd_desc", NULL);
    if (!value) {
        UMS_AGENT_LOG_ERR("%s.x509.prkey_pwd_desc must be configured", group);
        return -1;
    }

    size_t len = strnlen(value, UMS_AGENT_MAX_PWD_DESC_LEN);
    if (len == 0) {
        UMS_AGENT_LOG_ERR("x509.prkey_pwd_desc is empty");
        g_free(value);
        return -1;
    }
    if (len >= UMS_AGENT_MAX_PWD_DESC_LEN) {
        UMS_AGENT_LOG_ERR("x509.prkey_pwd_desc exceeds maximum length (%u characters, "
            "including null terminator)", UMS_AGENT_MAX_PWD_DESC_LEN);
        g_free(value);
        return -1;
    }

    (void)snprintf(x509->prkey_pwd_desc, sizeof(x509->prkey_pwd_desc), "%s", value);
    g_free(value);
    return 0;
}

static int ums_agent_load_x509_config(GKeyFile *kf, const char *group,
    struct ums_agent_x509_config *x509)
{
    if (ums_agent_load_x509_truststore(kf, group, x509) != 0) {
        return -1;
    }

    if (ums_agent_load_x509_crl(kf, group, x509) != 0) {
        return -1;
    }

    if (ums_agent_load_x509_certificate(kf, group, x509) != 0) {
        return -1;
    }

    if (ums_agent_load_x509_private_key(kf, group, x509) != 0) {
        return -1;
    }

    if (ums_agent_load_x509_prkey_pwd_desc(kf, group, x509) != 0) {
        return -1;
    }

    return 0;
}

static int ums_agent_load_network_listen_port(GKeyFile *kf, struct ums_agent_config *cfg)
{
    if (!g_key_file_has_key(kf, "network", "listen_port", NULL)) {
        return 0;
    }

    GError *error = NULL;
    int port = g_key_file_get_integer(kf, "network", "listen_port", &error);
    if (error) {
        UMS_AGENT_LOG_ERR("invalid listen_port: %s", error->message);
        g_error_free(error);
        return -1;
    }
    if (!ums_agent_is_valid_port(port)) {
        UMS_AGENT_LOG_ERR("listen_port %d out of range [%d-%d]",
            port, UMS_AGENT_MIN_LISTEN_PORT, UMS_AGENT_MAX_LISTEN_PORT);
        return -1;
    }

    cfg->listen_port = port;
    return 0;
}

static int ums_agent_load_network_listen_addr(GKeyFile *kf, struct ums_agent_config *cfg)
{
    gchar *value = g_key_file_get_string(kf, "network", "listen_addr", NULL);
    if (!value) {
        UMS_AGENT_LOG_ERR("network.listen_addr must be configured");
        return -1;
    }

    if (value[0] == '\0') {
        UMS_AGENT_LOG_ERR("network.listen_addr must be configured (empty value is not allowed)");
        g_free(value);
        return -1;
    }

    if (ums_agent_ip_addr_from_str(&cfg->listen_addr, value) != 0) {
        UMS_AGENT_LOG_ERR("invalid listen_addr, expected IPv4 or IPv6 address");
        g_free(value);
        return -1;
    }

    g_free(value);
    return 0;
}

static int ums_agent_load_network_max_conns(GKeyFile *kf, struct ums_agent_config *cfg)
{
    if (!g_key_file_has_key(kf, "network", "max_conns", NULL)) {
        return 0;
    }

    GError *error = NULL;
    int max_conns = g_key_file_get_integer(kf, "network", "max_conns", &error);
    if (error) {
        UMS_AGENT_LOG_ERR("invalid max_conns: %s", error->message);
        g_error_free(error);
        return -1;
    }
    if (max_conns < UMS_AGENT_MAX_CONNS_MIN || max_conns > UMS_AGENT_MAX_CONNS_MAX) {
        UMS_AGENT_LOG_ERR("max_conns %d out of range [%d-%d]",
            max_conns, UMS_AGENT_MAX_CONNS_MIN, UMS_AGENT_MAX_CONNS_MAX);
        return -1;
    }

    cfg->max_conns = max_conns;
    return 0;
}

static int ums_agent_load_network_config(GKeyFile *kf, struct ums_agent_config *cfg)
{
    if (ums_agent_load_network_listen_port(kf, cfg) != 0) {
        return -1;
    }

    if (ums_agent_load_network_listen_addr(kf, cfg) != 0) {
        return -1;
    }

    if (ums_agent_load_network_max_conns(kf, cfg) != 0) {
        return -1;
    }

    return 0;
}

static int ums_agent_load_tls_config(GKeyFile *kf, struct ums_agent_config *cfg)
{
    gchar *value = g_key_file_get_string(kf, "tls", "cipher_suite", NULL);
    if (!value) {
        return 0;
    }

    if (!ums_agent_is_valid_cipher_suite(value)) {
        UMS_AGENT_LOG_ERR("unsupported cipher_suite: %s", value);
        g_free(value);
        return -1;
    }

    (void)snprintf(cfg->cipher_suite, sizeof(cfg->cipher_suite), "%s", value);
    g_free(value);
    return 0;
}

static int ums_agent_load_logging_config(GKeyFile *kf, struct ums_agent_config *cfg)
{
    gchar *value = g_key_file_get_string(kf, "logging", "log_level", NULL);
    if (!value) {
        return 0;
    }

    enum ums_agent_log_level level = ums_agent_str_to_log_level(value);
    if (level == UMS_AGENT_LOG_LEVEL_MAX) {
        UMS_AGENT_LOG_ERR("invalid log_level: %s", value);
        g_free(value);
        return -1;
    }

    cfg->log_level = level;
    g_free(value);
    return 0;
}

int ums_agent_config_init(const char *path, struct ums_agent_config **config)
{
    GKeyFile *kf = NULL;
    GError *error = NULL;
    struct ums_agent_config *cfg = NULL;
    int ret = -1;

    kf = g_key_file_new();
    if (!kf) {
        UMS_AGENT_LOG_ERR("failed to create key file");
        goto out;
    }

    if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &error)) {
        UMS_AGENT_LOG_ERR("failed to load %s: %s", path, error->message);
        g_error_free(error);
        goto out;
    }

    cfg = calloc(1, sizeof(*cfg));
    if (!cfg) {
        UMS_AGENT_LOG_ERR("failed to allocate config memory");
        goto out;
    }

    ums_agent_set_defaults(cfg);

    if (g_key_file_has_group(kf, "logging")) {
        if (ums_agent_load_logging_config(kf, cfg) != 0) {
            goto out;
        }
    }

    if (!g_key_file_has_group(kf, "authenticate.client")) {
        UMS_AGENT_LOG_ERR("config missing required section [authenticate.client]");
        goto out;
    }
    if (ums_agent_load_x509_config(kf, "authenticate.client", &cfg->client) != 0) {
        goto out;
    }

    if (!g_key_file_has_group(kf, "authenticate.server")) {
        UMS_AGENT_LOG_ERR("config missing required section [authenticate.server]");
        goto out;
    }
    if (ums_agent_load_x509_config(kf, "authenticate.server", &cfg->server) != 0) {
        goto out;
    }

    if (!g_key_file_has_group(kf, "network")) {
        UMS_AGENT_LOG_ERR("config missing required section [network]");
        goto out;
    }
    if (ums_agent_load_network_config(kf, cfg) != 0) {
        goto out;
    }

    if (g_key_file_has_group(kf, "tls")) {
        if (ums_agent_load_tls_config(kf, cfg) != 0) {
            goto out;
        }
    }

    *config = cfg;
    cfg = NULL;
    ret = 0;

out:
    if (kf) {
        g_key_file_free(kf);
    }
    free(cfg);
    return ret;
}

void ums_agent_config_deinit(struct ums_agent_config *config)
{
    if (!config) {
        return;
    }
    free(config);
}
