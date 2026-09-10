/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * 虚拟设备 ioctl 命令分发。处理 urma_admin 经 URMA_CMD 发来的查询命令。
 *
 * 协议（urma_cmd.h / urma_cmd_tlv.h）：
 *   ioctl(fd, URMA_CMD, &hdr)  其中 hdr 是 urma_cmd_hdr_t*
 *     hdr->command  = 命令号（如 URMA_CMD_QUERY_DEV_ATTR）
 *     hdr->args_addr = urma_cmd_attr_t 数组首地址
 *     hdr->args_len  = 数组总字节数 = attrNum * sizeof(urma_cmd_attr_t)
 *   每个 attr: { type, flag, field_size, attr_data, data }
 *     data 是指向实际值缓冲的指针；仿真按 type 命中后往 *(uintptr_t)data 写值。
 *   attr->type 的语义由各命令的 urma_cmd_<cmd>_type_t 枚举定义，且 OUT 字段从
 *   URMA_CMD_OUT_TYPE_INIT(0x80) 起编号。回填只关心 OUT 类型的 attr。
 */

#include "urma_sim_intercept.h"
#include "urma_sim_res.h"
#include "urma_sim_exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/eventfd.h>

#include "udma_abi.h"   /* udma_create_ctx_resp（create_context 返回，sim 填 cqe_size=64 等） */
#include "urma_types.h" /* urma_eid_t（urma_str_to_eid 出参，CREATE_CTX 自动起 IPC 用） */

/* 按 attr->field_size 往 attr->data 指向的地址写数值。抄 core_fixture.h WriteCoreAttrValue。 */
static void write_attr_value(const urma_cmd_attr_t *attr, uint64_t value)
{
    if (attr->data == 0) {
        return;
    }
    void *dst = (void *)(uintptr_t)attr->data;
    switch (attr->field_size) {
        case 1:
            *(uint8_t *)dst = (uint8_t)value;
            break;
        case 2:
            *(uint16_t *)dst = (uint16_t)value;
            break;
        case 4:
            *(uint32_t *)dst = (uint32_t)value;
            break;
        case 8:
            *(uint64_t *)dst = value;
            break;
        default:
            break;
    }
}

/* 把字符串值转 uint64（十进制）。非数字返回 0。 */
static uint64_t str_to_u64(const char *s)
{
    if (s == NULL) {
        return 0;
    }
    while (*s == ' ' || *s == '\t' || *s == '\n') {
        s++;
    }
    uint64_t v = 0;
    int got = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10U + (uint64_t)(*s - '0');
        s++;
        got = 1;
    }
    return got ? v : 0;
}


/* 在设备的 ioctl 输出表里找指定 command 的条目 */
/* 读 attrs 里某 type 的 IN 值（按 field_size 读）。未找到返回 -1。 */
static int read_in_attr(urma_cmd_attr_t *attrs, size_t attr_num, uint8_t type, uint64_t *out)
{
    for (size_t i = 0; i < attr_num; i++) {
        if (attrs[i].type == type && attrs[i].data != 0) {
            const void *src = (const void *)(uintptr_t)attrs[i].data;
            switch (attrs[i].field_size) {
                case 1: *out = *(const uint8_t *)src; break;
                case 2: *out = *(const uint16_t *)src; break;
                case 4: *out = *(const uint32_t *)src; break;
                case 8: *out = *(const uint64_t *)src; break;
                default: return -1;
            }
            return 0;
        }
    }
    return -1;
}

/* 表单匹配：一条规则的 match 全部满足（IN attr 值 == 期望值）才命中。
 * match 为空 → 无条件命中。返回 1 命中, 0 不命中。 */
static int rule_match(const urma_sim_ioctl_rule_t *rule, urma_cmd_attr_t *attrs, size_t attr_num)
{
    for (int i = 0; i < rule->match_cnt; i++) {
        uint32_t type = (uint32_t)str_to_u64(rule->match[i].key);
        uint64_t expected = str_to_u64(rule->match[i].value);
        uint64_t actual = 0;
        if (read_in_attr(attrs, attr_num, (uint8_t)type, &actual) != 0 || actual != expected) {
            return 0;
        }
    }
    return 1;
}

/* 在设备的表单规则里找第一条匹配的规则（command 相同 + match 命中）。 */
static const urma_sim_ioctl_rule_t *find_ioctl_rule(const urma_sim_dev_t *dev, uint32_t command,
                                                   urma_cmd_attr_t *attrs, size_t attr_num)
{
    for (int i = 0; i < dev->ioctl_rule_cnt; i++) {
        if (dev->ioctl_rules[i].command == command &&
            rule_match(&dev->ioctl_rules[i], attrs, attr_num)) {
            return &dev->ioctl_rules[i];
        }
    }
    return NULL;
}

/* 按规则的 out 回填 attrs：遍历 attrs，对 OUT 类型（>=0x80）的 attr，
 * 若其 type 出现在规则 out 里则写对应值。 */
static void apply_rule_out(const urma_sim_ioctl_rule_t *rule, urma_cmd_attr_t *attrs, size_t attr_num)
{
    for (size_t i = 0; i < attr_num; i++) {
        if (attrs[i].type < URMA_CMD_OUT_TYPE_INIT) {
            continue;
        }
        char type_key[16];
        snprintf(type_key, sizeof(type_key), "%u", attrs[i].type);
        for (int j = 0; j < rule->out_cnt; j++) {
            if (strcmp(rule->out[j].key, type_key) == 0) {
                write_attr_value(&attrs[i], str_to_u64(rule->out[j].value));
                break;
            }
        }
    }
}

/* attr type 对应的 sysfs 文件名映射表。
 * QUERY_DEV_ATTR 的 OUT attr type 与 sysfs 文件有对应关系（urma 库两边都解析）。
 * 仿真优先用 ioctl 输出表回填；没有表项则按 type→sysfs 名 fallback 用 sysfs 值。 */
typedef struct {
    uint32_t attr_type;          /* urma_cmd_query_device_attr_type_t 枚举值（绝对值） */
    const char *sysfs_file;       /* 对应 sysfs 文件名 */
    uint8_t field_size;           /* 该字段宽度（字节） */
} query_dev_attr_map_t;

/* QUERY_DEV_ATTR 的 OUT attr type 枚举从 0x80 起。下面列的是相对偏移（枚举里出现的顺序），
 * 绝对 type = URMA_CMD_OUT_TYPE_INIT + 偏移。我们直接用枚举符号，避免硬编码偏移。 */
static const query_dev_attr_map_t g_query_dev_attr_map[] = {
    /* ⑦M: 补 GUID/FEATURE（此前缺映射 → 查询恒 0，urma_device.c:349 ioctl
     * 成功不走 sysfs fallback）。GUID 是 16 字节 urma_guid_t（非标量！），
     * 回填走 urma_str_to_eid 解析，见 handle_query_dev_attr 特判。 */
    { QUERY_DEVICE_OUT_GUID,                     "guid",                  sizeof(urma_guid_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_FEATURE,          "feature",               sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC,                  "max_jfc",                  sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS,                  "max_jfs",                  sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR,                  "max_jfr",                  sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY,                "max_jetty",                sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_GRP,            "max_jetty_grp",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JETTY_IN_JETTY_GRP,  "max_jetty_in_jetty_grp",   sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFC_DEPTH,            "max_jfc_depth",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_DEPTH,            "max_jfs_depth",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_DEPTH,            "max_jfr_depth",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_INLINE_LEN,       "max_jfs_inline_size",      sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_SGE,               "max_jfs_sge",              sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFS_RSGE,              "max_jfs_rsge",             sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_JFR_SGE,               "max_jfr_sge",              sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_MSG_SIZE,             "max_msg_size",             sizeof(uint64_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_READ_SIZE,            "max_read_size",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_WRITE_SIZE,           "max_write_size",           sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_CAS_SIZE,             "max_cas_size",             sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_SWAP_SIZE,           "max_swap_size",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_ADD_SIZE,   "max_fetch_and_add_size",   sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_SUB_SIZE,   "max_fetch_and_sub_size",   sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_AND_SIZE,   "max_fetch_and_and_size",   sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_OR_SIZE,   "max_fetch_and_or_size",    sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_FETCH_AND_XOR_SIZE,   "max_fetch_and_xor_size",   sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_ATOMIC_FEAT,              "atomic_feat",              sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_TRANS_MODE,              "trans_mode",               sizeof(uint16_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_CONGESTION_CTRL_ALG,     "congestion_ctrl_alg",      sizeof(uint16_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_CEQ_CNT,                 "ceq_cnt",                  sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_TP_IN_TPG,           "max_tp_in_tpg",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_EID_CNT,             "max_eid_cnt",              sizeof(uint16_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_PAGE_SIZE_CAP,           "page_size_cap",            sizeof(uint64_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_OOR_CNT,            "max_oor_cnt",              sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MN,                     "mn",                       sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_DEV_CAP_MAX_NETADDR_CN,         "max_netaddr_cnt",          sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_PORT_CNT,                       "port_count",               sizeof(uint8_t) },
    { QUERY_DEVICE_OUT_PORT_ATTR_MAX_MTU,              "port0/max_mtu",            sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_PORT_ATTR_STATE,                "port0/state",              sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_WIDTH,         "port0/active_width",       sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_SPEED,         "port0/active_speed",       sizeof(uint32_t) },
    { QUERY_DEVICE_OUT_PORT_ATTR_ACTIVE_MTU,           "port0/active_mtu",         sizeof(uint32_t) },
};

/* 从 QUERY_DEV_ATTR 的 IN attrs 里读 dev_name（QUERY_DEVICE_IN_DEV_NAME），
 * 找到对应的 sim 设备。找不到返回第一台（兼容旧行为）。 */
static const urma_sim_dev_t *select_dev_by_query_in(urma_cmd_attr_t *attrs, size_t attr_num)
{
    if (g_urma_sim.dev_cnt == 0) {
        return NULL;
    }
    /* ⑦L: 找不到设备返回 NULL（上层报错），不再回退 devices[0]——
     * 配置 typo/错误 dev_name 会被伪装成成功查询到第一台设备。 */
    for (size_t i = 0; i < attr_num; i++) {
        if (attrs[i].type == QUERY_DEVICE_IN_DEV_NAME && attrs[i].data != 0) {
            const char *name = (const char *)(uintptr_t)attrs[i].data;
            return urma_sim_find_dev(name);   /* 找不到返回 NULL */
        }
    }
    return NULL;
}

/* 处理 QUERY_DEV_ATTR：先用表单规则回填，未覆盖的 OUT attr 按 type→sysfs 映射 fallback。 */
static int handle_query_dev_attr(urma_cmd_attr_t *attrs, size_t attr_num, const urma_sim_dev_t *dev)
{
    /* 先用表单规则：找到匹配规则就按其 out 回填 */
    const urma_sim_ioctl_rule_t *rule = find_ioctl_rule(dev, URMA_CMD_QUERY_DEV_ATTR, attrs, attr_num);
    if (rule != NULL) {
        apply_rule_out(rule, attrs, attr_num);
    }
    /* fallback：对仍未填的 OUT attr，按 type→sysfs 文件名映射用 sysfs 值回填 */
    for (size_t i = 0; i < attr_num; i++) {
        urma_cmd_attr_t *attr = &attrs[i];
        if (attr->type < URMA_CMD_OUT_TYPE_INIT) {
            continue;
        }
        /* 规则已填的不再覆盖：检查该 type 是否在 rule.out 里 */
        if (rule != NULL) {
            char type_key[16];
            snprintf(type_key, sizeof(type_key), "%u", attr->type);
            bool in_rule = false;
            for (int j = 0; j < rule->out_cnt; j++) {
                if (strcmp(rule->out[j].key, type_key) == 0) {
                    in_rule = true;
                    break;
                }
            }
            if (in_rule) {
                continue;
            }
        }
        /* PRIORITY_INFO 是结构体数组（urma_sl_info[16]：SL+tp_type 各 4B），write_attr_value 只处理
         * 1/2/4/8B 标量填不了。perftest read_lat 用 RM，get_jetty_priority_by_tp_type 扫
         * priority_info[].tp_type 找 rtp(bs.rtp=1→value=1)，找不到则 priority=255 →
         * udma_u_create_jetty 判 priority>=UDMA_MAX_PRIORITY(15) 失败。故 sim 按 sysfs
         * priority/priorityN/sl + tp_type 填 priority_info[0..15]。 */
        /* ⑦M: reserved_jetty_id 范围（config "reserved_jetty_id": "17-19"）——
         * 解析 "min-max" 填 RESERVED_JETTY_ID_MIN/MAX（此前无映射 → 恒 0） */
        if ((attr->type == QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MIN ||
             attr->type == QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MAX) && attr->data != 0) {
            char rjv[64] = {0};
            if (urma_sim_read_sysfs(dev, "reserved_jetty_id", rjv, sizeof(rjv)) > 0) {
                uint32_t rj_min = 0, rj_max = 0;
                if (sscanf(rjv, "%u-%u", &rj_min, &rj_max) == 2) {
                    write_attr_value(attr,
                        (attr->type == QUERY_DEVICE_OUT_RESERVED_JETTY_ID_MIN) ? rj_min : rj_max);
                }
            }
            continue;
        }
        if (attr->type == QUERY_DEVICE_OUT_DEV_CAP_PRIORITY_INFO && attr->data != 0) {
            uint8_t *base = (uint8_t *)(uintptr_t)attr->data;
            for (int i = 0; i < 16; i++) {
                char sl_path[64];
                char tp_path[64];
                char sl_val[16] = {0};
                char tp_val[16] = {0};
                snprintf(sl_path, sizeof(sl_path), "priority/priority%d/sl", i);
                snprintf(tp_path, sizeof(tp_path), "priority/priority%d/tp_type", i);
                uint32_t sl = 0, tp = 0;
                if (urma_sim_read_sysfs(dev, sl_path, sl_val, sizeof(sl_val)) > 0) {
                    sl = (uint32_t)str_to_u64(sl_val);
                }
                if (urma_sim_read_sysfs(dev, tp_path, tp_val, sizeof(tp_val)) > 0) {
                    tp = (uint32_t)str_to_u64(tp_val);
                }
                uint32_t *p = (uint32_t *)(base + (uint64_t)i * 8);
                p[0] = sl;      /* SL */
                p[1] = tp;      /* tp_type.value */
            }
            continue;
        }
        for (size_t m = 0; m < sizeof(g_query_dev_attr_map) / sizeof(g_query_dev_attr_map[0]); m++) {
            if (g_query_dev_attr_map[m].attr_type == attr->type) {
                char sysfs_value_buf[128] = {0};
                ssize_t r = urma_sim_read_sysfs(dev, g_query_dev_attr_map[m].sysfs_file,
                                                sysfs_value_buf, sizeof(sysfs_value_buf));
                if (r > 0) {
                    if (g_query_dev_attr_map[m].attr_type == QUERY_DEVICE_OUT_GUID &&
                        attr->data != 0 &&
                        attr->field_size >= (uint8_t)sizeof(urma_guid_t)) {
                        /* GUID 是 16 字节结构（urma_guid_t），sysfs 值为
                         * IPv4/IPv6/EID 字符串——按真库规范用 urma_str_to_eid
                         * 解析写入（urma_device.c:290），标量 write 路径
                         * （1/2/4/8B）无法处理 16B，此前 GUID 恒为全 0。 */
                        urma_eid_t g = {0};
                        /* read_sysfs 给配置值追加 '\n'，urma_str_to_eid 的
                         * inet_pton 遇尾随空白解析失败——先剥尾部空白
                         * （同 CREATE_CTX 路径），再解析。 */
                        ssize_t sl = r;
                        while (sl > 0 && (sysfs_value_buf[sl - 1] == '\n' ||
                                          sysfs_value_buf[sl - 1] == '\r' ||
                                          sysfs_value_buf[sl - 1] == ' ' ||
                                          sysfs_value_buf[sl - 1] == '\t')) {
                            sysfs_value_buf[--sl] = '\0';
                        }
                        if (urma_str_to_eid(sysfs_value_buf, &g) == 0) {
                            memcpy((void *)(uintptr_t)attr->data, g.raw, sizeof(g.raw));
                        }
                    } else {
                        write_attr_value(attr, str_to_u64(sysfs_value_buf));
                    }
                }
                break;
            }
        }
    }
    return 0;
}

/* 按 attr type 找 attr 返回其 data 指针，找不到 NULL。 */
static uint64_t find_attr_data(urma_cmd_attr_t *attrs, size_t attr_num, uint8_t type)
{
    for (size_t i = 0; i < attr_num; i++) {
        if (attrs[i].type == type) {
            return attrs[i].data;
        }
    }
    return 0;
}

/* 处理 CREATE_CTX：回填 async_fd + 往 udata.out_addr 写 resp。
 * resp 关键字段（udma_u_init_context 读）：
 *   cqe_size=64（CQE 条目大小=sizeof(udma_u_jfc_cqe)=64B，否则 align_power2(0)=0
 *     会让 CQ baseblk_shift=0、CQE 排布错位）
 *   dtu_enable/sq_reserved/hugepage_enable/lock_buffer_en/ccu_* 全 0
 *     （绕开 dtu/reserved_sq/hugepage/lock_buffer/ccu 分支，无硬件不支持）
 *   atomic_add_en=0、st64b_en=0、dwqe_enable=0（简化：关闭这些可选特性）
 * 另：自动起本进程 IPC（urma_sim_ipc_start），用本设备 eids/eid0 的二进制 eid。
 * 之前 IPC 只在自写 test 调 urma_sim_ipc_start 才起，intergration_test 不调 → g_local_eid=0
 * → is_local 恒真 → 跨进程 WRITE/READ 解引用对端 va SIGSEGV。改在 CREATE_CTX 自动起。 */
static int handle_create_ctx(urma_cmd_attr_t *attrs, size_t attr_num, const urma_sim_dev_t *dev)
{
    /* OUT_ASYNC_FD(type=128)：async_fd 是异步事件通道（⑲）。
     * 回填一个真 eventfd（EFD_NONBLOCK），让 urma_get_async_event 的 ioctl
     * 能被 sim 拦截到（见 urma_sim.c ioctl），无事件返回 EAGAIN；
     * 此前回填 0（stdin）→ 真 ioctl(stdin) ENOTTY → 假失败。 */
    uint64_t async_data = find_attr_data(attrs, attr_num, CREATE_CTX_OUT_ASYNC_FD);
    if (async_data != 0) {
        int efd = (int)eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (efd < 0) {
            /* eventfd 失败（EMFILE/ENFILE 等）：不再回填 0/假成功——调用方会把
             * 0 当有效 fd，事件 ioctl 打错对象、销毁时关闭进程标准输入。 */
            (void)fprintf(stderr, "WARN: CREATE_CTX eventfd fail: %s\n", strerror(errno));
            return -errno;   /* 透传原始错误（ENFILE/ENOMEM 等），不固定编 EMFILE */
        }
        urma_cmd_attr_t tmp;
        tmp.data = async_data;
        tmp.field_size = sizeof(int);
        write_attr_value(&tmp, (uint32_t)efd);
        urma_sim_async_fd_register(efd);
    }
    /* OUT_UDATA(type=129)：data 指向 urma_cmd_udrv_priv_t，其 out_addr/out_len 指向 resp。
     * 往 resp 写字段：先全 0（关所有可选特性），再设 cqe_size=64。 */
    uint64_t udata_data = find_attr_data(attrs, attr_num, CREATE_CTX_OUT_UDATA);
    if (udata_data != 0) {
        urma_cmd_udrv_priv_t *udata = (urma_cmd_udrv_priv_t *)(uintptr_t)udata_data;
        if (udata->out_addr != 0 && udata->out_len >= sizeof(struct udma_create_ctx_resp)) {
            struct udma_create_ctx_resp *resp =
                (struct udma_create_ctx_resp *)(uintptr_t)udata->out_addr;
            memset(resp, 0, sizeof(*resp));
            resp->cqe_size = 64;   /* sizeof(udma_u_jfc_cqe)=64，CQE 条目大小 */
        }
    }
    /* 自动起本进程 IPC：读本设备 eids/eid0 → urma_str_to_eid 转二进制 → urma_sim_ipc_start。
     * 每个 ctx 用自己设备的 eid 起 IPC（udma_sim0/1 eid 不同 → socket 路径不撞）。
     * ipc_start 幂等（g_ipc_started 已置则 no-op）。 */
    if (dev != NULL) {
        char eid_str[64] = {0};
        ssize_t r = urma_sim_read_sysfs(dev, "eids/eid0", eid_str, sizeof(eid_str));
        if (r > 0) {
            /* sysfs 值常带尾部换行，urma_str_to_eid 不吃 → 去尾空白 */
            while (r > 0 && (eid_str[r - 1] == '\n' || eid_str[r - 1] == '\r' ||
                              eid_str[r - 1] == ' ' || eid_str[r - 1] == '\t')) {
                eid_str[--r] = '\0';
            }
            urma_eid_t eid;   /* union：raw[16] / in4 / in6 */
            memset(&eid, 0, sizeof(eid));
            int (*str2eid)(const char *, urma_eid_t *) = (int (*)(const char *, urma_eid_t *))
                dlsym(RTLD_DEFAULT, "urma_str_to_eid");
            if (str2eid != NULL && str2eid(eid_str, &eid) == 0) {
                urma_sim_ipc_start(eid.raw);
            }
        }
    }
    return 0;
}

/* 假 id/handle 递增计数器（每次建链命令 +1，避免不同对象 handle 撞）。 */
static uint32_t g_sim_next_handle = 0x1000;

/* 把某 OUT attr 回填成递增假值（id 和 handle 各递增一次）。 */
/* 回填某 OUT attr 为指定值（caller 给定值）。 */
static void fill_out_attr_value(urma_cmd_attr_t *attrs, size_t attr_num, uint8_t type, uint32_t value)
{
    for (size_t i = 0; i < attr_num; i++) {
        if (attrs[i].type == type && attrs[i].data != 0) {
            urma_cmd_attr_t tmp;
            tmp.data = attrs[i].data;
            /* 按 OUT attr 的实际 field_size 写（max_sge/max_rsge 等是 uint8，
             * 硬编码 4 字节会写进相邻字段，见 ⑦G） */
            tmp.field_size = attrs[i].field_size;
            write_attr_value(&tmp, value);
            return;
        }
    }
}

static void fill_out_attr(urma_cmd_attr_t *attrs, size_t attr_num, uint8_t type)
{
    fill_out_attr_value(attrs, attr_num, type, ++g_sim_next_handle);
}

/* 处理建链命令：回填 OUT_ID(128) + 对应 OUT_HANDLE 为递增假值。
 * 真 udma 拿到假 id/handle 存进对象，后续用它做关联和 mmap（sim 拦 mmap 给假内存）。
 * OUT_ID 对所有命令都是 128；OUT_HANDLE 各命令不同（见 urma_cmd_tlv.h 枚举）。 */
static int handle_link_cmd(uint32_t command, urma_cmd_attr_t *attrs, size_t attr_num,
                              const uint8_t *dev_eid)
{
    uint8_t out_id = 128;          /* 所有建链命令的 OUT_ID 都是 128 */
    uint8_t out_handle = 0;        /* 各命令的 OUT_HANDLE type */
    uint8_t in_udata = 0;          /* 各命令的 IN_UDATA type */
    switch (command) {
        case URMA_CMD_CREATE_JFC:     out_handle = CREATE_JFC_OUT_HANDLE;     in_udata = CREATE_JFC_IN_UDATA;     break;
        case URMA_CMD_CREATE_JFS:     out_handle = CREATE_JFS_OUT_HANDLE;     in_udata = CREATE_JFS_IN_UDATA;     break;
        case URMA_CMD_CREATE_JFR:     out_handle = CREATE_JFR_OUT_HANDLE;     in_udata = CREATE_JFR_IN_UDATA;     break;
        case URMA_CMD_CREATE_JETTY:   out_handle = CREATE_JETTY_OUT_HANDLE;   in_udata = CREATE_JETTY_IN_UDATA;   break;
        case URMA_CMD_IMPORT_JETTY:       out_handle = IMPORT_JETTY_OUT_HANDLE;       break;
        case URMA_CMD_IMPORT_JETTY_EX:    out_handle = IMPORT_JETTY_EX_OUT_HANDLE;    break;
        case URMA_CMD_IMPORT_JFR:         out_handle = IMPORT_JFR_OUT_HANDLE;         break;
        case URMA_CMD_IMPORT_JFR_EX:      out_handle = IMPORT_JFR_EX_OUT_HANDLE;      break;
        case URMA_CMD_ALLOC_TOKEN_ID: out_handle = ALLOC_TOKEN_ID_OUT_HANDLE; break;
        default:
            /* 无 OUT_HANDLE 的命令只回填 OUT_ID（如 BIND_JETTY 通常无输出 handle）。 */
            fill_out_attr(attrs, attr_num, out_id);
            return 0;
    }
    /* 从 IN_UDATA 读 udata cmd（udma_create_jetty_ucmd）。
     * - CREATE_JFC：buf_addr=CQ 地址，注册到 CQ 关联表，回填的 id=jfc_id
     * - CREATE_JFS/JFR/JETTY：jetty_addr/buf_addr=queue，注册到 queue 关联表，
     *   并从 IN_JFC_ID 拿 jfc_id 关联到 CQ（造 CQE 找 CQ 用） */
    uint32_t id = ++g_sim_next_handle;
    /* 用户指定 id（节 16 B 类/⑤）：CREATE_JETTY / CREATE_JFR 的 IN_ID（cfg->id）
     * 非 0 时以用户值为准（assoc.id 与 OUT_ID 一致 → doorbell mmap 的 db.id 匹配正常；
     * 真实内核同样用 in.id 创建并以 out.id 返回实际 id）；0/ANY 时用自增模拟分配。 */
    if (command == URMA_CMD_CREATE_JETTY) {
        uint64_t in_id = 0;
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_ID, &in_id) == 0 && in_id != 0) {
            id = (uint32_t)in_id;
        }
    }
    if (command == URMA_CMD_CREATE_JFR) {
        uint64_t in_id = 0;
        if (read_in_attr(attrs, attr_num, CREATE_JFR_IN_ID, &in_id) == 0 && in_id != 0) {
            id = (uint32_t)in_id;
        }
    }
    int cq_slot = -1;
    int slot = -1;
    if (command == URMA_CMD_CREATE_JFC && in_udata != 0) {
        uint64_t udata_data = find_attr_data(attrs, attr_num, in_udata);
        if (udata_data != 0) {
            cq_slot = urma_sim_cq_assoc_register(udata_data);
            if (cq_slot >= 0) {
                urma_sim_cq_assoc_set_id(cq_slot, id);
            }
        }
    } else if (in_udata != 0) {
        uint64_t udata_data = find_attr_data(attrs, attr_num, in_udata);
        if (udata_data != 0) {
            slot = urma_sim_queue_assoc_register(udata_data);
        }
        if (slot >= 0) {
            urma_sim_queue_assoc_set_id(slot, id);
            urma_sim_queue_assoc_set_eid(slot, dev_eid);
            /* 标记 sq 类型（节 3）：CREATE_JETTY=jetty 内嵌 sq（is_jetty=1）；
             * CREATE_JFS=独立 jfs（is_jetty=0）——send CQE 的 is_jetty 位按它填，
             * 独立 jfs 的 CQE 标 1 会让真 udma 用 jetty container_of 还原野指针。 */
            if (command == URMA_CMD_CREATE_JETTY) {
                urma_sim_queue_assoc_set_is_jetty(slot, 1);
            } else if (command == URMA_CMD_CREATE_JFS) {
                urma_sim_queue_assoc_set_is_jetty(slot, 0);
            }
            /* CREATE_JFS 从 IN_JFC_ID 拿 jfc_id，关联 queue → CQ */
            if (command == URMA_CMD_CREATE_JFS) {
                uint64_t jfc_id_data = find_attr_data(attrs, attr_num, CREATE_JFS_IN_JFC_ID);
                if (jfc_id_data != 0) {
                    uint32_t jfc_id = *(uint32_t *)(uintptr_t)jfc_id_data;
                    urma_sim_queue_assoc_set_jfc(slot, jfc_id);
                }
            }
            /* CREATE_JETTY 从 IN_SEND_JFC_ID 拿 jfs 的 jfc_id，关联 jetty 的 sq → CQ
             * （send CQE 找 CQ 用）。否则 send CQE 因 jfc_id=0 丢。 */
            if (command == URMA_CMD_CREATE_JETTY) {
                uint64_t jfc_id_data = find_attr_data(attrs, attr_num, CREATE_JETTY_IN_SEND_JFC_ID);
                if (jfc_id_data != 0) {
                    uint32_t jfc_id = *(uint32_t *)(uintptr_t)jfc_id_data;
                    urma_sim_queue_assoc_set_jfc(slot, jfc_id);
                }
            }
            /* CREATE_JFR 从 IN_JFC_ID 拿 jfc_id（JFR 的 CQ），关联 JFR rq → CQ（recv CQE 找 CQ 用）。
             * 之前只给 JFS 设了 jfc_id，JFR 没设 → produce_recv_cqe 找不到 CQ。 */
            if (command == URMA_CMD_CREATE_JFR) {
                uint64_t jfc_id_data = find_attr_data(attrs, attr_num, CREATE_JFR_IN_JFC_ID);
                if (jfc_id_data != 0) {
                    uint32_t jfc_id = *(uint32_t *)(uintptr_t)jfc_id_data;
                    urma_sim_queue_assoc_set_jfc(slot, jfc_id);
                }
                /* 补全 JFR recv WQE 几何（max_sge/depth → wqe_shift/wqe_cnt），ucmd 不带 max_sge。
                 * depth=uint32 field_size=4；max_sge=uint8 field_size=1，必须按 field_size 读
                 * （直接 *(uint32*) 读 4 字节会带相邻字段垃圾）。用 read_in_attr 正确按 field_size 读。 */
                uint64_t depth_v = 0, sge_v = 0;
                (void)read_in_attr(attrs, attr_num, CREATE_JFR_IN_DEPTH, &depth_v);
                (void)read_in_attr(attrs, attr_num, CREATE_JFR_IN_MAX_SGE, &sge_v);
                uint32_t depth = (depth_v != 0) ? (uint32_t)depth_v : 64;
                uint32_t max_sge = (sge_v != 0) ? (uint32_t)sge_v : 1;
                urma_sim_jfr_set_recv_geom(slot, max_sge, depth);
            }
        }
    }
    fill_out_attr_value(attrs, attr_num, out_id, id);
    /* ALLOC_TOKEN_ID：除通用 OUT_HANDLE 外，再回填 OUT_TOKEN_ID。
     * 此前把 out_handle 设成 TOKEN_ID 且提前 return，导致 OUT_HANDLE 恒 0，
     * 用户态 token 的 handle 无法指向 token uobject（REGISTER_SEG/FREE_TOKEN_ID
     * 用错对象句柄）。现在走统一 handle 回填，token_id 另填。 */
    if (command == URMA_CMD_ALLOC_TOKEN_ID) {
        /* OUT_TOKEN_ID = 本次 ummu_allocate_tid 分配的 tid<<8：真 udma 的
         * udma_exec_alloc_tid_cmd(ctx, token_id, ...) 把 token_id（=tid<<8）
         * 放进 IN_UDATA 传入（udma_u_tid.c:53 + udma_u_set_udata）。sim 从
         * IN_UDATA 回显，保证与 grant 登记的 tid 一致——此前固定回填
         * 0x1234<<8，多 token 分配不独立，tid→段关联冲突。 */
        uint64_t tok = 0;
        uint64_t udata_data = find_attr_data(attrs, attr_num, ALLOC_TOKEN_ID_IN_UDATA);
        if (udata_data != 0) {
            const urma_cmd_udrv_priv_t *ud =
                (const urma_cmd_udrv_priv_t *)(uintptr_t)udata_data;
            if (ud->in_addr != 0 && ud->in_len >= (uint64_t)sizeof(uint32_t)) {
                tok = *(const uint32_t *)(uintptr_t)ud->in_addr;
            }
        }
        if (tok == 0) {
            /* IN_UDATA 缺失/长度不匹配/值非法：拒绝该请求。此前用占位值
             * 0x1<<8 蒙混成功——恰好等于首个正常 token，注册段/远端访问/
             * 注销会命中另一个 token 的映射（且真实 UMMU TID 并不一致）。 */
            (void)fprintf(stderr, "WARN: ALLOC_TOKEN_ID IN_UDATA token missing, reject\n");
            return -EINVAL;   /* 错误码经返回值编码，拦截层据此设 errno（透传） */
        }
        fill_out_attr_value(attrs, attr_num, ALLOC_TOKEN_ID_OUT_TOKEN_ID, (uint32_t)tok);
    }
    if (command == URMA_CMD_CREATE_JFR) {
        /* fill_jfr 用 out.depth/max_sge 覆盖 jfr->jfr_cfg.depth/max_sge（urma_cmd.c urma_fill_jfr）。
         * sim 不回填则 out.depth=0 → jfr->jfr_cfg.depth=0 → urma_create_jetty 的 dev_cap 检查
         * 判 "jfr_depth==0 out of range" 失败（urma_sample 用 share_jfr 模式必经此路）。
         * 真 kernel 返回实际分配的深度（向上 2 幂）；sim 原样回填 IN depth/max_sge 即可。
         * 注意按 field_size 读（⑦G）：max_sge=uint8，*(uint32*) 读会带 min_rnr_timer+填充。 */
        uint64_t depth_v = 0, sge_v = 0;
        if (read_in_attr(attrs, attr_num, CREATE_JFR_IN_DEPTH, &depth_v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFR_OUT_DEPTH, (uint32_t)depth_v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JFR_IN_MAX_SGE, &sge_v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFR_OUT_MAX_SGE, (uint32_t)sge_v);
        }
    }
    if (command == URMA_CMD_CREATE_JFS) {
        /* fill_jfs 用 out.depth/max_sge/max_rsge/max_inline_data 覆盖 jfs 对象配置（③）：
         * 不回填 → 对象配置被覆盖成 0 → udma_u_active_jfs 用 depth=0 重建 sq 出 0 深度队列。
         * 真 kernel 返回实际分配值；sim 原样回填 IN。 */
        uint64_t v = 0;
        if (read_in_attr(attrs, attr_num, CREATE_JFS_IN_DEPTH, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFS_OUT_DEPTH, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JFS_IN_MAX_SGE, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFS_OUT_MAX_SGE, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JFS_IN_MAX_RSGE, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFS_OUT_MAX_RSGE, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JFS_IN_MAX_INLINE_DATA, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFS_OUT_MAX_INLINE_DATA, (uint32_t)v);
        }
    }
    if (command == URMA_CMD_CREATE_JFC) {
        /* fill_jfc 用 out.depth 覆盖 jfc->jfc_cfg.depth（③）：不回填 → depth=0。
         * 注意 cq_assoc 的 depth 已从 udata buf_len 推（CQ 轮询/满检查用），
         * 此处回填保证对象配置与分配一致。 */
        uint64_t v = 0;
        if (read_in_attr(attrs, attr_num, CREATE_JFC_IN_DEPTH, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JFC_OUT_DEPTH, (uint32_t)v);
        }
    }
    if (command == URMA_CMD_CREATE_JETTY) {
        /* fill_jetty 用 out.jfs_depth/jfr_depth/max_send_sge/max_send_rsge/max_recv_sge/
         * max_inline_data 覆盖 jetty 配置（③）：不回填 → 全部覆盖成 0。原样回填 IN。 */
        uint64_t v = 0;
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_JFS_DEPTH, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JETTY_OUT_JFS_DEPTH, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_JFR_DEPTH, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JETTY_OUT_JFR_DEPTH, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_MAX_SEND_SGE, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JETTY_OUT_MAX_SEND_SGE, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_MAX_SEND_RSGE, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JETTY_OUT_MAX_SEND_RSGE, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_MAX_RECV_SGE, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JETTY_OUT_MAX_RECV_SGE, (uint32_t)v);
        }
        if (read_in_attr(attrs, attr_num, CREATE_JETTY_IN_MAX_INLINE_DATA, &v) == 0) {
            fill_out_attr_value(attrs, attr_num, CREATE_JETTY_OUT_MAX_INLINE_DATA, (uint32_t)v);
        }
    }
    if (command == URMA_CMD_CREATE_JETTY) {
        /* CREATE_JETTY 的 IN attrs 带 CREATE_JETTY_IN_JFR_ID（共享的 JFR id）。
         * 建 jetty_id(=OUT_ID=id)→jfr_id 映射，SEND 时按 jetty_id 查 JFR rq。
         * 真 udma jetty 与共享 JFR 同 ctx 成对建，IN_JFR_ID=0 表纯 jfs 无 jfr。 */
        uint64_t in_jfr_id = find_attr_data(attrs, attr_num, CREATE_JETTY_IN_JFR_ID);
        uint32_t jfr_id = 0;
        if (in_jfr_id != 0) {
            jfr_id = *(uint32_t *)(uintptr_t)in_jfr_id;
        }
        urma_sim_jfr_bind_jetty(dev_eid, id, jfr_id);   /* 绑定含设备维度 */
    }
    if (command == URMA_CMD_IMPORT_JFR || command == URMA_CMD_IMPORT_JFR_EX) {
        /* fill_tjfr 读 arg->out.tpn（urma_cmd.c:1473）→ tjetty->tp.tpn（节 12 根因）：
         * 不回填则 tpn=0 → WQE tp_id=0 → CQE tpn=0。回填递增假 tpn（非 0）。 */
        fill_out_attr_value(attrs, attr_num,
                            (command == URMA_CMD_IMPORT_JFR) ?
                                IMPORT_JFR_OUT_TPN : IMPORT_JFR_EX_OUT_TPN,
                            ++g_sim_next_handle);
    }
    /* import 存在性校验（⑤/节 3）：目标 eid 是本进程（is_local）时校验目标
     * 对象已建——import 不存在的 id 应报错（负向用例可测）；跨进程（对端在
     * 另一 sim 实例，本进程查不到）跳过校验。 */
    if (command == URMA_CMD_IMPORT_JETTY || command == URMA_CMD_IMPORT_JETTY_EX ||
        command == URMA_CMD_IMPORT_JFR || command == URMA_CMD_IMPORT_JFR_EX) {
        uint64_t id_v = 0;
        uint8_t in_eid = (command == URMA_CMD_IMPORT_JFR) ? IMPORT_JFR_IN_EID :
                         (command == URMA_CMD_IMPORT_JFR_EX) ? IMPORT_JFR_EX_IN_EID :
                         (command == URMA_CMD_IMPORT_JETTY) ? IMPORT_JETTY_IN_EID :
                                                              IMPORT_JETTY_EX_IN_EID;
        uint8_t in_id = (command == URMA_CMD_IMPORT_JFR) ? IMPORT_JFR_IN_ID :
                        (command == URMA_CMD_IMPORT_JFR_EX) ? IMPORT_JFR_EX_IN_ID :
                        (command == URMA_CMD_IMPORT_JETTY) ? IMPORT_JETTY_IN_ID :
                                                             IMPORT_JETTY_EX_IN_ID;
        /* EID 是 16 字节数组，read_in_attr 只支持标量（1/2/4/8）必然失败；
         * 直接用 attr.data 指向用户 eid 缓冲的原始地址交给 is_local 判定。 */
        const void *eid_ptr = NULL;
        for (size_t i = 0; i < attr_num; i++) {
            if (attrs[i].type == in_eid && attrs[i].data != 0) {
                eid_ptr = (const void *)(uintptr_t)attrs[i].data;
                break;
            }
        }
        if (eid_ptr != NULL &&
            read_in_attr(attrs, attr_num, in_id, &id_v) == 0 &&
            urma_sim_ipc_is_local((const uint8_t *)eid_ptr) && id_v != 0) {
            int found = 0;
            uint32_t want = (uint32_t)id_v;
            if (command == URMA_CMD_IMPORT_JFR || command == URMA_CMD_IMPORT_JFR_EX) {
                /* 独立 jfr：查 rq assoc（q_type=1, .id==want） */
                for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
                    if (g_sim_queue_assoc[i].in_use && g_sim_queue_assoc[i].q_type == 1 &&
                        g_sim_queue_assoc[i].id == want) {
                        found = 1;
                        break;
                    }
                }
            } else {
                /* jetty：查 jetty sq（is_jetty=1, .id==want） */
                for (int i = 0; i < URMA_SIM_QUEUE_MAX; i++) {
                    if (g_sim_queue_assoc[i].in_use && g_sim_queue_assoc[i].is_jetty &&
                        g_sim_queue_assoc[i].id == want) {
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) {
                fprintf(stderr, "DBG import: target id=%u not found (EINVAL)\n", want);
                return -EINVAL;   /* 错误码经返回值编码，拦截层据此设 errno（透传） */
            }
        }
    }
    /* 记录 handle 到关联表（节 14：DELETE_* 按 handle 清 stale assoc） */
    uint64_t handle_val = ++g_sim_next_handle;
    fill_out_attr_value(attrs, attr_num, out_handle, (uint32_t)handle_val);
    if (cq_slot >= 0) {
        urma_sim_cq_assoc_set_handle(cq_slot, handle_val);
    }
    if (slot >= 0) {
        urma_sim_queue_assoc_set_handle(slot, handle_val);
    }
    return 0;
}

/* 节 14: DELETE_* 清理 stale assoc（delete flush 的 sim 侧：清表防指针复用错配）。
 * 按 IN_HANDLE 释放对应 queue/cq 关联；回填 OUT_ASYNC_EVENTS_REPORTED=0。 */
static int handle_delete_cmd(uint32_t command, urma_cmd_attr_t *attrs, size_t attr_num)
{
    uint8_t in_handle = 0;
    uint8_t out_events = 0;
    switch (command) {
        case URMA_CMD_DELETE_JFS:     in_handle = DELETE_JFS_IN_HANDLE;     out_events = DELETE_JFS_OUT_ASYNC_EVENTS_REPORTED;     break;
        case URMA_CMD_DELETE_JFR:     in_handle = DELETE_JFR_IN_HANDLE;     out_events = DELETE_JFR_OUT_ASYNC_EVENTS_REPORTED;     break;
        case URMA_CMD_DELETE_JETTY:   in_handle = DELETE_JETTY_IN_HANDLE;   out_events = DELETE_JETTY_OUT_ASYNC_EVENTS_REPORTED;   break;
        case URMA_CMD_DELETE_JFC:     in_handle = DELETE_JFC_IN_HANDLE;     out_events = DELETE_JFC_OUT_ASYNC_EVENTS_REPORTED;     break;
        default:
            return 0;
    }
    uint64_t hv = 0;
    if (read_in_attr(attrs, attr_num, in_handle, &hv) == 0 && hv != 0) {
        if (command == URMA_CMD_DELETE_JFC) {
            urma_sim_cq_assoc_release_by_handle(hv);
        } else {
            urma_sim_queue_assoc_release_by_handle(hv);
        }
    }
    fill_out_attr_value(attrs, attr_num, out_events, 0);
    return 0;
}

int urma_sim_handle_ioctl(int fd, uint32_t command, uint32_t args_len, uint64_t args_addr)
{
    SIM_DBG("ioctl: cmd=%u args_len=%u\n", command, args_len);
    if (args_addr == 0 || args_len == 0) {
        return -1;
    }
    urma_cmd_attr_t *attrs = (urma_cmd_attr_t *)(uintptr_t)args_addr;
    size_t attr_num = args_len / sizeof(urma_cmd_attr_t);
    if (attr_num == 0 || attr_num > 256) {
        return -1;
    }

    /* 选设备：
     * - QUERY_DEV_ATTR 用 IN_DEV_NAME 选（urma_admin show dev 各发一次，带设备名）
     * - 其他命令用 fd 选（cdev 假 fd 登记了 dev_idx） */
    const urma_sim_dev_t *dev = NULL;
    if (command == URMA_CMD_QUERY_DEV_ATTR) {
        dev = select_dev_by_query_in(attrs, attr_num);
    } else {
        urma_sim_fd_t *fe = urma_sim_fd_get(fd);
        if (fe != NULL && fe->type == URMA_SIM_FD_CDEV) {
            dev = &g_urma_sim.devices[fe->dev_idx];
        }
    }
    /* ⑦L/G28: 设备/fd 查不到不再回退 devices[0]——返回失败（真实 EBADF/ENOTTY）。
     * 此前已 close 的假 fd/非假 fd/typo 设备名都会被伪装成成功。 */
    if (dev == NULL) {
        return -EBADF;   /* 错误码经返回值编码，拦截层据此设 errno（透传） */
    }
    if (g_urma_sim.dev_cnt == 0) {
        return -1;
    }

    /* 通用表单分发：先查设备该 command 的规则，命中则按 out 回填。 */
    const urma_sim_ioctl_rule_t *rule = find_ioctl_rule(dev, command, attrs, attr_num);
    if (rule != NULL) {
        apply_rule_out(rule, attrs, attr_num);
    }

    /* 命令特定处理：CREATE_CTX 回填 async_fd + resp（cqe_size=64 等）。 */
    if (command == URMA_CMD_CREATE_CTX) {
        return handle_create_ctx(attrs, attr_num, dev);
    }
    /* 建链命令：回填假 id/handle，让真 udma 继续（后续 mmap queue/doorbell 由 sim 拦截）。 */
    if (command == URMA_CMD_CREATE_JFC || command == URMA_CMD_CREATE_JFS ||
        command == URMA_CMD_CREATE_JFR || command == URMA_CMD_CREATE_JETTY ||
        command == URMA_CMD_IMPORT_JETTY || command == URMA_CMD_IMPORT_JETTY_EX ||
        command == URMA_CMD_IMPORT_JFR || command == URMA_CMD_IMPORT_JFR_EX ||
        command == URMA_CMD_BIND_JETTY || command == URMA_CMD_ALLOC_TOKEN_ID) {
        /* 本设备 eid（发送端身份）：从设备 sysfs eids/eid0 解析 16 字节 */
        uint8_t dev_eid[16] = {0};
        {
            char eid_str[64] = {0};
            ssize_t er = urma_sim_read_sysfs(dev, "eids/eid0", eid_str, sizeof(eid_str));
            if (er > 0) {
                ssize_t el = er;
                while (el > 0 && (eid_str[el - 1] == '\n' || eid_str[el - 1] == '\r' ||
                                  eid_str[el - 1] == ' ' || eid_str[el - 1] == '\t')) {
                    eid_str[--el] = '\0';
                }
                {   /* dev_eid 是 1 字节对齐数组，不能直接收 urma_eid_t*（in4
                     * 成员 64 位写会未对齐访问 UB）——用对齐后的局部 eid 再拷贝 */
                    urma_eid_t de;
                    if (urma_str_to_eid(eid_str, &de) != 0) {
                        memset(dev_eid, 0, sizeof(dev_eid));
                    } else {
                        memcpy(dev_eid, de.raw, sizeof(dev_eid));
                    }
                }
            }
        }
        return handle_link_cmd(command, attrs, attr_num, dev_eid);
    }
    /* REGISTER_SEG：回填 OUT_TOKEN_ID = IN_TOKEN_ID（保持 tid 一致：tid = token_id>>8 = ummu tid）。
     * 真 udma register_seg 调 ummu_grant(ummu_tid) 登记 tid→va；tseg->seg.token_id 来自
     * ioctl 的 out.token_id（fill_registered_tseg 设）。若 sim 不回填，out.token_id=0 →
     * tseg->seg.token_id=0 → 对端 import 后 WQE rmt_tid=0，IPC 查不到对端 seg。 */
    if (command == URMA_CMD_REGISTER_SEG) {
        uint64_t in_tok = find_attr_data(attrs, attr_num, REGISTER_SEG_IN_TOKEN_ID);
        uint32_t tok = 0;
        if (in_tok != 0) {
            tok = *(uint32_t *)(uintptr_t)in_tok;   /* IN token_id（=ummu_tid<<8） */
        }
        fill_out_attr_value(attrs, attr_num, REGISTER_SEG_OUT_TOKEN_ID, tok);
        fill_out_attr(attrs, attr_num, REGISTER_SEG_OUT_HANDLE);
        return 0;
    }
    /* CREATE_JFCE：真 udma 用返回的 fd 作 eventfd（wait_jfc 阻塞读它）。
     * 无硬件容器里创建一个真 eventfd 给它，让 wait/select 不崩（事件不触发，poll 主动取 CQE）。 */
    if (command == URMA_CMD_CREATE_JFCE) {
        /* CREATE_JFCE_OUT_FD = 128（= URMA_CMD_OUT_TYPE_INIT） */
        int efd = (int)eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (efd < 0) {
            /* 同 CREATE_CTX：失败即命令失败（EMFILE/ENFILE），不回填 0 假成功 */
            (void)fprintf(stderr, "WARN: CREATE_JFCE eventfd fail: %s\n", strerror(errno));
            return -errno;   /* 透传原始错误（ENFILE/ENOMEM 等），不固定编 EMFILE */
        }
        fill_out_attr_value(attrs, attr_num, CREATE_JFCE_OUT_FD, (uint32_t)efd);
        return 0;
    }
    if (command == URMA_CMD_QUERY_DEV_ATTR) {
        return handle_query_dev_attr(attrs, attr_num, dev);
    }
    /* GET_EID_LIST：让真 urma 走 sysfs fallback（读 eids/eidN）。sim 不直接回填 ioctl 输出，
     * 返回 -1 让 urma_read_eid_list 失败 → fallback read_eid_list_sysyf 读 /sys/.../eids/eid%u，
     * 该路径经 sim 的 open/read 拦截能拿到 config 里 eids/eid0、eids/eid1 的 IP 串并转成 eid。
     * 若回填 0（成功但 eid_cnt=0），urma_get_eid_list 会判空返回 NULL（urma_sample get_eid_index 失败）。
     */
    if (command == URMA_CMD_GET_EID_LIST) {
        return -1;
    }
    /* 节 14: DELETE_* 清理 stale assoc（按 handle 释放，防指针复用错配） */
    if (command == URMA_CMD_DELETE_JFS || command == URMA_CMD_DELETE_JFR ||
        command == URMA_CMD_DELETE_JETTY || command == URMA_CMD_DELETE_JFC) {
        return handle_delete_cmd(command, attrs, attr_num);
    }
    /* ACTIVE_JFC：jfc 在 active 时重新分配 CQ 内存——按 handle 同步
     * cq_assoc.cq_addr（否则 CQE 写旧地址、provider poll 读新地址错位）。 */
    if (command == URMA_CMD_ACTIVE_JFC) {
        uint64_t hv = 0;
        if (read_in_attr(attrs, attr_num, ACTIVE_JFC_IN_HANDLE, &hv) == 0 && hv != 0) {
            uint64_t udata_data = find_attr_data(attrs, attr_num, ACTIVE_JFC_IN_UDATA);
            if (udata_data != 0) {
                const urma_cmd_udrv_priv_t *udata =
                    (const urma_cmd_udrv_priv_t *)(uintptr_t)udata_data;
                if (udata->in_addr != 0) {
                    /* udma_create_jfc_ucmd 首字段 = buf_addr（新 CQ 内存） */
                    uint64_t new_addr = *(const uint64_t *)(uintptr_t)udata->in_addr;
                    /* ucmd 第二字段 = buf_len（新 CQ 尺寸），depth=buf_len/64；
                     * 仅换地址会保留旧深度 → 缩容越界/扩容早回绕。 */
                    uint32_t new_buf_len = 0;
                    if (udata->in_len >= (uint64_t)sizeof(uint64_t) + sizeof(uint32_t)) {
                        memcpy(&new_buf_len, (const void *)(uintptr_t)(udata->in_addr + 8),
                               sizeof(new_buf_len));
                    }
                    uint32_t new_depth = (new_buf_len > 0) ? new_buf_len / URMA_SIM_CQE_SIZE : 0;
                    urma_sim_cq_assoc_update_addr(hv, new_addr, new_depth);
                }
            }
            /* 回填 OUT_ID/OUT_DEPTH/OUT_HANDLE：真 udma 成功后用户态用这些输出
             * 重建 JFC（fill_active_jfc 覆盖 id/handle/depth）——缺回填会让
             * JFC 的 ID/handle/depth 变 0：后续 JFS/Jetty 带错 JFC ID、
             * DELETE 无法按原 handle 清关联。 */
            for (int i = 0; i < URMA_SIM_CQ_MAX; i++) {
                if (g_sim_cq_assoc[i].in_use && g_sim_cq_assoc[i].handle == hv) {
                    fill_out_attr_value(attrs, attr_num, ACTIVE_JFC_OUT_ID,
                                        g_sim_cq_assoc[i].jfc_id);
                    fill_out_attr_value(attrs, attr_num, ACTIVE_JFC_OUT_DEPTH,
                                        g_sim_cq_assoc[i].depth);
                    break;
                }
            }
            fill_out_attr_value(attrs, attr_num, ACTIVE_JFC_OUT_HANDLE,
                                (uint32_t)hv);
        }
        return 0;
    }
    return 0;
}
