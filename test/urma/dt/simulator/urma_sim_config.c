/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * 加载 urma_sim_config.json 初始化 g_urma_sim。
 * 用极简手写解析器，只支持本模块的固定 schema：
 *   {"devices":[{"name":"..","sysfs":{"k":"v",..},"ioctl":[{"command":N,"entries":[{"key":"..","value":".."}]}]}]}
 * 不引入第三方 JSON 库依赖。
 */

#include "urma_sim_intercept.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* 内置默认配置：无 config.json 时使用。一个 udma_sim0 设备，属性齐全。 */
static const char *g_default_config =
"{\n"
"  \"devices\": [\n"
"    {\n"
"      \"name\": \"udma_sim0\",\n"
"      \"sysfs\": {\n"
"        \"ubdev\": \"udma_sim0\",\n"
"        \"driver_name\": \"udma\",\n"
"        \"transport_type\": \"0\",\n"
"        \"guid\": \"192.168.10.1\",\n"
"        \"feature\": \"1\",\n"
"        \"max_jfc\": \"64\",\n"
"        \"max_jfs\": \"1024\",\n"
"        \"max_jfr\": \"1024\",\n"
"        \"max_jetty\": \"4096\",\n"
"        \"max_jetty_grp\": \"64\",\n"
"        \"max_jetty_in_jetty_grp\": \"32\",\n"
"        \"max_jfc_depth\": \"16384\",\n"
"        \"max_jfs_depth\": \"16384\",\n"
"        \"max_jfr_depth\": \"16384\",\n"
"        \"max_jfs_inline_size\": \"64\",\n"
"        \"max_jfs_sge\": \"8\",\n"
"        \"max_jfs_rsge\": \"8\",\n"
"        \"max_jfr_sge\": \"8\",\n"
"        \"max_msg_size\": \"1073741824\",\n"
"        \"max_read_size\": \"1048576\",\n"
"        \"max_write_size\": \"1048576\",\n"
"        \"max_cas_size\": \"8\",\n"
"        \"max_swap_size\": \"8\",\n"
"        \"max_fetch_and_add_size\": \"8\",\n"
"        \"max_fetch_and_sub_size\": \"8\",\n"
"        \"max_fetch_and_and_size\": \"8\",\n"
"        \"max_fetch_and_or_size\": \"8\",\n"
"        \"max_fetch_and_xor_size\": \"8\",\n"
"        \"atomic_feat\": \"15\",\n"
"        \"trans_mode\": \"3\",\n"
"        \"congestion_ctrl_alg\": \"0\",\n"
"        \"ceq_cnt\": \"16\",\n"
"        \"max_tp_in_tpg\": \"256\",\n"
"        \"port_count\": \"1\",\n"
"        \"max_eid_cnt\": \"4\",\n"
"        \"page_size_cap\": \"65536\",\n"
"        \"max_oor_cnt\": \"32\",\n"
"        \"mn\": \"1\",\n"
"        \"max_netaddr_cnt\": \"8\",\n"
"        \"reserved_jetty_id\": \"17-19\",\n"
"        \"device/vendor\": \"21\",\n"
"        \"device/device\": \"22\",\n"
"        \"port0/max_mtu\": \"4\",\n"
"        \"port0/state\": \"1\",\n"
"        \"port0/active_width\": \"2\",\n"
"        \"port0/active_speed\": \"3\",\n"
"        \"port0/active_mtu\": \"5\",\n"
"        \"eids/eid0\": \"192.168.10.1\"\n"
"      }\n"
"    }\n"
"  ]\n"
"}\n";

urma_sim_state_t g_urma_sim = {0};
urma_sim_fd_t g_urma_sim_fds[URMA_SIM_FD_MAX] = {0};

/* ===== 极简 JSON 解析器（仅支持本 schema） ===== */

typedef struct {
    const char *p;
    const char *end;
} json_parser_t;

static void skip_ws(json_parser_t *ps)
{
    while (ps->p < ps->end && isspace((unsigned char)*ps->p)) {
        ps->p++;
    }
}

/* 期望当前字符是 c，跳过它和后续空白 */
static int expect_char(json_parser_t *ps, char c)
{
    skip_ws(ps);
    if (ps->p >= ps->end || *ps->p != c) {
        return -1;
    }
    ps->p++;
    return 0;
}

/* 读一个双引号字符串到 out（去转义只处理 \" 和 \\）。返回 0 成功。 */
static int parse_string(json_parser_t *ps, char *out, size_t out_sz)
{
    if (expect_char(ps, '"') != 0) {
        return -1;
    }
    size_t i = 0;
    while (ps->p < ps->end && *ps->p != '"') {
        char c = *ps->p++;
        if (c == '\\' && ps->p < ps->end) {
            char next = *ps->p++;
            if (next == '"') { c = '"'; }
            else if (next == '\\') { c = '\\'; }
            else if (next == '/') { c = '/'; }
            else if (next == 'n') { c = '\n'; }
            else { c = next; }
        }
        if (i + 1 < out_sz) {
            out[i++] = c;
        }
    }
    if (ps->p >= ps->end || *ps->p != '"') {
        return -1;
    }
    ps->p++;
    out[i] = '\0';
    return 0;
}

/* 读一个无符号整数（command/数值）。返回 0 成功。 */
static int parse_uint(json_parser_t *ps, uint32_t *out)
{
    skip_ws(ps);
    uint32_t v = 0;
    int got = 0;
    while (ps->p < ps->end && isdigit((unsigned char)*ps->p)) {
        unsigned int digit = (unsigned int)(*ps->p - '0');
        if (v > (UINT32_MAX - digit) / 10U) {
            return -1;   /* 累加溢出（如 4294967336 回绕成 40）→ 拒绝 */
        }
        v = v * 10U + digit;
        ps->p++;
        got = 1;
    }
    if (!got) {
        return -1;
    }
    *out = v;
    return 0;
}

/* 解析单个 sysfs 键值对："key":"value" 填入 kv 数组 */
static int parse_sysfs_kv(json_parser_t *ps, urma_sim_kv_t *kvs, int *cnt, int cap)
{
    char key[64];
    char val[128];
    if (parse_string(ps, key, sizeof(key)) != 0) {
        return -1;
    }
    if (expect_char(ps, ':') != 0) {
        return -1;
    }
    if (parse_string(ps, val, sizeof(val)) != 0) {
        return -1;
    }
    if (*cnt < cap) {
        snprintf(kvs[*cnt].key, sizeof(kvs[*cnt].key), "%s", key);
        snprintf(kvs[*cnt].value, sizeof(kvs[*cnt].value), "%s", val);
        (*cnt)++;
    }
    return 0;
}

/* 解析一个键值对数组 [{"key":"..","value":".."}]* 填入 kvs 数组。用于 match 和 out。
 * 每个 entry 是一个 JSON 对象，含 "key" 和 "value" 两个字段。 */
static int parse_kv_array(json_parser_t *ps, urma_sim_kv_t *kvs, int *cnt, int cap)
{
    if (expect_char(ps, '[') != 0) {
        return -1;
    }
    skip_ws(ps);
    while (ps->p < ps->end && *ps->p != ']') {
        if (expect_char(ps, '{') != 0) {
            return -1;
        }
        char key[64] = {0};
        char val[128] = {0};
        skip_ws(ps);
        while (ps->p < ps->end && *ps->p != '}') {
            char field[16];
            if (parse_string(ps, field, sizeof(field)) != 0) {
                return -1;
            }
            if (expect_char(ps, ':') != 0) {
                return -1;
            }
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == '"') {
                if (strcmp(field, "key") == 0) {
                    if (parse_string(ps, key, sizeof(key)) != 0) {
                        return -1;
                    }
                } else if (strcmp(field, "value") == 0) {
                    if (parse_string(ps, val, sizeof(val)) != 0) {
                        return -1;
                    }
                } else {
                    return -1;
                }
            } else {
                uint32_t num;
                if (parse_uint(ps, &num) != 0) {
                    return -1;
                }
                if (strcmp(field, "value") == 0) {
                    snprintf(val, sizeof(val), "%u", num);
                } else if (strcmp(field, "key") == 0) {
                    snprintf(key, sizeof(key), "%u", num);
                } else {
                    return -1;
                }
            }
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == ',') {
                ps->p++;
                skip_ws(ps);
            }
        }
        if (expect_char(ps, '}') != 0) {
            return -1;
        }
        if (*cnt < cap && key[0] != '\0') {
            snprintf(kvs[*cnt].key, sizeof(kvs[*cnt].key), "%s", key);
            snprintf(kvs[*cnt].value, sizeof(kvs[*cnt].value), "%s", val);
            (*cnt)++;
        }
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == ',') {
            ps->p++;
            skip_ws(ps);
        }
    }
    if (expect_char(ps, ']') != 0) {
        return -1;
    }
    return 0;
}

/* 解析一条表单规则 {"command":N,"match":[...],"out":[...]} */
static int parse_ioctl_rule(json_parser_t *ps, urma_sim_ioctl_rule_t *rule)
{
    if (expect_char(ps, '{') != 0) {
        return -1;
    }
    rule->match_cnt = 0;
    rule->out_cnt = 0;
    skip_ws(ps);
    while (ps->p < ps->end && *ps->p != '}') {
        char field[32];
        if (parse_string(ps, field, sizeof(field)) != 0) {
            return -1;
        }
        if (expect_char(ps, ':') != 0) {
            return -1;
        }
        if (strcmp(field, "command") == 0) {
            if (parse_uint(ps, &rule->command) != 0) {
                return -1;
            }
        } else if (strcmp(field, "match") == 0) {
            if (parse_kv_array(ps, rule->match, &rule->match_cnt,
                               (int)(sizeof(rule->match) / sizeof(rule->match[0]))) != 0) {
                return -1;
            }
        } else if (strcmp(field, "out") == 0) {
            if (parse_kv_array(ps, rule->out, &rule->out_cnt,
                               (int)(sizeof(rule->out) / sizeof(rule->out[0]))) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == ',') {
            ps->p++;
            skip_ws(ps);
        }
    }
    if (expect_char(ps, '}') != 0) {
        return -1;
    }
    return 0;
}

/* 解析一个设备对象 {"name":"..","sysfs":{..},"ioctl":[...]} */
static int parse_device(json_parser_t *ps, urma_sim_dev_t *dev)
{
    if (expect_char(ps, '{') != 0) {
        return -1;
    }
    dev->sysfs_cnt = 0;
    dev->ioctl_rule_cnt = 0;
    skip_ws(ps);
    while (ps->p < ps->end && *ps->p != '}') {
        char field[32];
        if (parse_string(ps, field, sizeof(field)) != 0) {
            return -1;
        }
        if (expect_char(ps, ':') != 0) {
            return -1;
        }
        if (strcmp(field, "name") == 0) {
            if (parse_string(ps, dev->name, sizeof(dev->name)) != 0) {
                return -1;
            }
        } else if (strcmp(field, "sysfs") == 0) {
            if (expect_char(ps, '{') != 0) {
                return -1;
            }
            skip_ws(ps);
            while (ps->p < ps->end && *ps->p != '}') {
                if (parse_sysfs_kv(ps, dev->sysfs, &dev->sysfs_cnt,
                                   (int)(sizeof(dev->sysfs) / sizeof(dev->sysfs[0]))) != 0) {
                    return -1;
                }
                skip_ws(ps);
                if (ps->p < ps->end && *ps->p == ',') {
                    ps->p++;
                    skip_ws(ps);
                }
            }
            if (expect_char(ps, '}') != 0) {
                return -1;
            }
        } else if (strcmp(field, "ioctl") == 0) {
            if (expect_char(ps, '[') != 0) {
                return -1;
            }
            skip_ws(ps);
            while (ps->p < ps->end && *ps->p != ']') {
                if (dev->ioctl_rule_cnt >= (int)(sizeof(dev->ioctl_rules) / sizeof(dev->ioctl_rules[0]))) {
                    return -1;
                }
                if (parse_ioctl_rule(ps, &dev->ioctl_rules[dev->ioctl_rule_cnt]) != 0) {
                    return -1;
                }
                dev->ioctl_rule_cnt++;
                skip_ws(ps);
                if (ps->p < ps->end && *ps->p == ',') {
                    ps->p++;
                    skip_ws(ps);
                }
            }
            if (expect_char(ps, ']') != 0) {
                return -1;
            }
        } else {
            return -1;
        }
        skip_ws(ps);
        if (ps->p < ps->end && *ps->p == ',') {
            ps->p++;
            skip_ws(ps);
        }
    }
    if (expect_char(ps, '}') != 0) {
        return -1;
    }
    return 0;
}

static int parse_config(const char *text)
{
    const int base_cnt = g_urma_sim.dev_cnt;
    json_parser_t ps = { .p = text, .end = text + strlen(text) };
    int rc = 0;

    if (expect_char(&ps, '{') != 0) {
        rc = -1;
        goto out;
    }
    skip_ws(&ps);
    while (ps.p < ps.end && *ps.p != '}') {
        char field[32];
        if (parse_string(&ps, field, sizeof(field)) != 0) {
            rc = -1;
            goto out;
        }
        if (expect_char(&ps, ':') != 0) {
            rc = -1;
            goto out;
        }
        if (strcmp(field, "devices") != 0) {
            rc = -1;
            goto out;
        }
        if (expect_char(&ps, '[') != 0) {
            rc = -1;
            goto out;
        }
        skip_ws(&ps);
        while (ps.p < ps.end && *ps.p != ']') {
            if (g_urma_sim.dev_cnt >= (int)(sizeof(g_urma_sim.devices) / sizeof(g_urma_sim.devices[0]))) {
                rc = -1;
                goto out;
            }
            if (parse_device(&ps, &g_urma_sim.devices[g_urma_sim.dev_cnt]) != 0) {
                rc = -1;
                goto out;
            }
            g_urma_sim.dev_cnt++;
            skip_ws(&ps);
            if (ps.p < ps.end && *ps.p == ',') {
                ps.p++;
                skip_ws(&ps);
            }
        }
        if (expect_char(&ps, ']') != 0) {
            rc = -1;
            goto out;
        }
        skip_ws(&ps);
        if (ps.p < ps.end && *ps.p == ',') {
            ps.p++;
            skip_ws(&ps);
        }
    }
    /* 根对象结束：必须消费右花括号，且其后仅剩空白，否则视为截断/尾随垃圾 */
    if (expect_char(&ps, '}') != 0) {
        rc = -1;
        goto out;
    }
    skip_ws(&ps);
    if (ps.p != ps.end) {
        rc = -1;
        goto out;
    }
out:
    if (rc != 0) {
        g_urma_sim.dev_cnt = base_cnt;   /* 回滚本次已解析的设备，避免污染回退配置 */
    }
    return rc;
}

/* 从环境变量 URMA_SIM_CONFIG 指定的文件加载，否则用内置默认配置 */
void urma_sim_init(void)
{
    if (g_urma_sim.initialized) {
        return;
    }
    g_urma_sim.initialized = 1;

    const char *cfg_path = getenv("URMA_SIM_CONFIG");
    int loaded = 0;
    if (cfg_path != NULL && cfg_path[0] != '\0') {
        FILE *fp = fopen(cfg_path, "r");
        if (fp != NULL) {
            char buf[65536];
            size_t n = 0;
            int read_err = 0;
            for (;;) {
                size_t r = fread(buf + n, 1, sizeof(buf) - 1 - n, fp);
                n += r;
                if (n < sizeof(buf) - 1) {
                    if (ferror(fp)) {
                        read_err = 1;   /* 读错误：不确定完整内容 */
                    }
                    break;              /* 读不满 → 正常 EOF 或出错 */
                }
                /* 缓冲区读满（65535）：最后一次 fread 可能恰好停在 EOF 前，feof()
                 * 未必置位。再探测 1 字节区分"恰好 65535（完整可解析）"与
                 * "还有更多（配置超长，拒绝）"。 */
                int c = fgetc(fp);
                if (c != EOF) {
                    read_err = 1;       /* 还有内容：配置超长，不完整 */
                } else if (ferror(fp)) {
                    read_err = 1;       /* 读错误 */
                }
                break;
            }
            fclose(fp);
            buf[n] = '\0';
            if (!read_err && parse_config(buf) == 0) {
                loaded = 1;
            }
        }
    }
    if (!loaded) {
        /* ⑦C: 配置加载/解析失败不再静默——明确告警（此前静默回退默认配置，
         * 写错配置无感知）。 */
        if (cfg_path != NULL && cfg_path[0] != '\0') {
            fprintf(stderr, "WARN: URMA_SIM_CONFIG=%s load/parse failed, "
                    "fallback to builtin default config\n", cfg_path);
        }
        /* 未加载到任何完整配置：确保从干净状态回退（parse_config 虽在失败时
         * 回滚自身 dev_cnt，这里显式复位，杜绝残留设备污染内置配置解析）。 */
        g_urma_sim.dev_cnt = 0;
        if (parse_config(g_default_config) != 0) {
            fprintf(stderr, "FATAL: builtin default config parse failed\n");
            g_urma_sim.dev_cnt = 0;
        }
    }
}
