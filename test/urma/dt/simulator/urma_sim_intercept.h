/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * URMA 设备仿真 - 内部接口。
 *
 * liburma_sim.so 通过 LD_PRELOAD 拦截 opendir/readdir/stat/realpath/open/read/ioctl
 * 这 6 类 libc 调用，在用户态虚拟出 /sys/class/ubcore/<dev> 设备树和 /dev/uburma/<dev>
 * 字符设备，让无硬件环境下的 urma_admin 能枚举/查询虚拟设备。
 *
 * 假数据来源：urma_sim_config.json，由 urma_sim_config.c 加载进内存。
 */

#ifndef URMA_SIM_H
#define URMA_SIM_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#include "urma_cmd.h"
#include "urma_cmd_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* sim 设备单条 sysfs 属性键值对 */
typedef struct urma_sim_kv {
    char key[64];
    char value[128];
} urma_sim_kv_t;

/* 表单模拟：一条 ioctl 输入→输出规则。
 * - command：命令号（urma_cmd 枚举值）
 * - match：输入匹配条件，每项 {type, value}。type 是 IN attr 的 type（<0x80），
 *   value 是期望的十进制数值。仿真读 attrs 里对应 type 的值与之比较。
 *   match 为空 → 该命令无条件命中（适用于 query 类，输入只是 handle/name）。
 * - out：命中后回填的 OUT attr，每项 {type, value}。type 是 OUT attr 的 type（>=0x80），
 *   value 是十进制数值，按 attr->field_size 写入 *(uintptr_t)attr->data。
 * 一个 command 可有多条规则，按 match 顺序匹配第一条命中的。 */
typedef struct urma_sim_ioctl_rule {
    uint32_t command;
    urma_sim_kv_t match[16];    /* key = 十进制 IN attr type, value = 十进制期望值 */
    int match_cnt;
    urma_sim_kv_t out[64];      /* key = 十进制 OUT attr type, value = 十进制回填值 */
    int out_cnt;
} urma_sim_ioctl_rule_t;

/* 一个虚拟设备 */
typedef struct urma_sim_dev {
    char name[64];                         /* 设备名，如 "udma_sim0" */
    urma_sim_kv_t sysfs[128];              /* sysfs 文件→值（含 driver_name="udma" 等） */
    int sysfs_cnt;
    urma_sim_ioctl_rule_t ioctl_rules[32]; /* 表单：各命令的输入→输出规则 */
    int ioctl_rule_cnt;
} urma_sim_dev_t;

/* 仿真全局状态 */
typedef struct urma_sim_state {
    urma_sim_dev_t devices[16];
    int dev_cnt;
    int initialized;
} urma_sim_state_t;

extern urma_sim_state_t g_urma_sim;

/* constructor: 启动时加载 config 初始化 g_urma_sim */
void urma_sim_init(void);

/* === 拦截层辅助：判断路径是否属于 sim 域 === */
/* /sys/class/ubcore 或 /dev/uburma 前缀 */
int urma_sim_is_sysfs_path(const char *path);
int urma_sim_is_cdev_path(const char *path);

/* 在 sim 设备表里按设备名查 */
const urma_sim_dev_t *urma_sim_find_dev(const char *dev_name);

/* 从一个完整路径 /sys/class/ubcore/<dev>/<file> 解析出 dev 名和 file 名 */
int urma_sim_split_sysfs_path(const char *path, char *dev_name, size_t dev_sz,
                              char *file_name, size_t file_sz);

/* sysfs 文件读：按 dev+file 查值，写入 buf，返回长度；未命中返回 -1 */
ssize_t urma_sim_read_sysfs(const urma_sim_dev_t *dev, const char *file,
                            char *buf, size_t size);

/* === fd 表（open 返回的假 fd 映射回 sim 上下文） === */
typedef enum {
    URMA_SIM_FD_NONE = 0,
    URMA_SIM_FD_SYSFS,        /* 读 sysfs 属性文件 */
    URMA_SIM_FD_CDEV,         /* /dev/uburma/<dev> 字符设备 */
} urma_sim_fd_type_t;

typedef struct urma_sim_fd {
    urma_sim_fd_type_t type;
    int dev_idx;              /* g_urma_sim.devices 下标 */
    char file[64];            /* sysfs 文件名（type=SYSFS 时） */
    size_t read_off;          /* 已读偏移（sysfs 值按字符串读，read 一次给完） */
    int in_use;
} urma_sim_fd_t;

#define URMA_SIM_FD_MAX 256
extern urma_sim_fd_t g_urma_sim_fds[URMA_SIM_FD_MAX];

/* 分配一个假 fd（>= 100000，避开真 fd 空间），登记类型+dev_idx+file；失败返回 -1 */
int urma_sim_fd_alloc(urma_sim_fd_type_t type, int dev_idx, const char *file);

/* 由假 fd 查 fd 表项；非假 fd 返回 NULL */
urma_sim_fd_t *urma_sim_fd_get(int fd);

/* 释放假 fd */
void urma_sim_fd_free(int fd);

/* === 异步事件 fd 登记 ===
 * CREATE_CTX 回填的 async_fd 是真 eventfd（内核分配的小 fd），无法走假 fd 表
 * （100000+ 限制）。需要独立登记，供 GET_ASYNC_EVENT 拦截判定（否则该命令
 * 透明放行到 eventfd 上 ioctl → ENOTTY）。 */
void urma_sim_async_fd_register(int fd);
int urma_sim_async_fd_is_registered(int fd);

/* opendir 不需要伪 DIR：constructor 在 /tmp 下造临时目录含设备名子目录，
 * opendir("/sys/class/ubcore") 劫持成真 opendir 该临时目录，readdir 走 libc 原样吐设备名。 */

/* === ioctl 命令分发 === */
/* 处理一次 URMA_CMD ioctl：解析 hdr，按 command + 表单规则回填输出 attr。
 * fd 用于查 cdev 假 fd 对应的设备（非 QUERY_DEV_ATTR 类命令靠 fd 选设备）。
 * 返回 0 成功，-1 不认。 */
int urma_sim_handle_ioctl(int fd, uint32_t command, uint32_t args_len, uint64_t args_addr);

#ifdef __cplusplus
}
#endif

#endif /* URMA_SIM_H */
