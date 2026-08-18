/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * LD_PRELOAD 拦截层。拦截 6 类 libc 调用，把 /sys/class/ubcore 和 /dev/uburma
 * 在用户态接管。
 *
 * 策略：
 *  - opendir("/sys/class/ubcore") → 真 opendir 一个临时目录（含设备名条目），
 *    readdir 能正常吐设备名。临时目录在 constructor 里按 config 造好。
 *  - stat("/sys/class/ubcore/<dev>") → 返回 S_ISDIR。
 *  - realpath("/sys/class/ubcore/..." 或 "/dev/uburma/...") → 返回原路径。
 *  - open("/sys/class/ubcore/<dev>/<file>") → 返回假 fd，read 时返回 config 值。
 *  - open("/dev/uburma/<dev>") → 返回假 fd（cdev），供后续 ioctl。
 *  - read(假fd,...) → 按 fd 表项查 sysfs 值。
 *  - ioctl(假fd, URMA_CMD, &hdr) → 转 urma_sim_handle_ioctl。
 *
 * 非 sim 域的调用 → dlsym(RTLD_NEXT, ...) 转真实现。
 */

#include "urma_sim_intercept.h"
#include "urma_sim_res.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <time.h>

/* 真 libc 函数指针（懒加载） */
static DIR *(*real_opendir)(const char *) = NULL;
static int (*real_stat)(const char *, struct stat *) = NULL;
static char *(*real_realpath)(const char *, char *) = NULL;
static int (*real_open)(const char *, int, ...) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static int (*real_ioctl)(int, unsigned long, ...) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_access)(const char *, int) = NULL;
static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
static int (*real_munmap)(void *, size_t) = NULL;

#define URMA_SYSFS_PREFIX "/sys/class/ubcore"
#define URMA_DEV_PREFIX   "/dev/uburma"
#define URMA_SIM_PREFIX_LEN 17  /* "/sys/class/ubcore" 长度 */

/* 临时目录：构造函数里在 /tmp 下造好，含每个设备名作为子目录条目。 */
static char g_sim_dir_root[256] = {0};

/* 仿真就绪标志：ctor 里临时目录建成并填好设备子目录才置 1。
 * 若目录创建失败（/tmp 不可写/占用耗尽），拦截器不得再对仿真路径工作：
 * 一律返回 ENOENT，避免"宿主设备枚举 + 模拟器 I/O 拦截"的混合态（可能误操作
 * 宿主真实 URMA 设备，或产生不稳定结果）。 */
static int g_sim_ready = 0;

static void load_real_funcs(void)
{
    real_opendir = (DIR *(*)(const char *))dlsym(RTLD_NEXT, "opendir");
    real_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "stat");
    real_realpath = (char *(*)(const char *, char *))dlsym(RTLD_NEXT, "realpath");
    real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    real_read = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    real_ioctl = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    real_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
    real_access = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
    real_mmap = (void *(*)(void *, size_t, int, int, int, off_t))dlsym(RTLD_NEXT, "mmap");
    real_munmap = (int (*)(void *, size_t))dlsym(RTLD_NEXT, "munmap");
}

static void init_real_funcs(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;

    pthread_once(&once, load_real_funcs);
}

/* === 路径判断 === */
int urma_sim_is_sysfs_path(const char *path)
{
    return path != NULL && strncmp(path, URMA_SYSFS_PREFIX, URMA_SIM_PREFIX_LEN) == 0 &&
           (path[URMA_SIM_PREFIX_LEN] == '\0' || path[URMA_SIM_PREFIX_LEN] == '/');
}

int urma_sim_is_cdev_path(const char *path)
{
    size_t plen = strlen(URMA_DEV_PREFIX);
    return path != NULL && strncmp(path, URMA_DEV_PREFIX, plen) == 0 &&
           (path[plen] == '\0' || path[plen] == '/');
}

const urma_sim_dev_t *urma_sim_find_dev(const char *dev_name)
{
    if (dev_name == NULL) {
        return NULL;
    }
    for (int i = 0; i < g_urma_sim.dev_cnt; i++) {
        if (strcmp(g_urma_sim.devices[i].name, dev_name) == 0) {
            return &g_urma_sim.devices[i];
        }
    }
    return NULL;
}

/* 从 /sys/class/ubcore/<dev> 或 /sys/class/ubcore/<dev>/<file> 解析 dev 和 file。
 * 无 file 时 file_name 输出空串。返回 0 命中设备，-1 不命中。 */
int urma_sim_split_sysfs_path(const char *path, char *dev_name, size_t dev_sz,
                             char *file_name, size_t file_sz)
{
    if (!urma_sim_is_sysfs_path(path)) {
        return -1;
    }
    const char *rest = path + URMA_SIM_PREFIX_LEN;
    if (*rest == '/') {
        rest++;
    }
    /* 取 dev 名（到下一个 / 或末尾） */
    size_t i = 0;
    while (rest[i] != '\0' && rest[i] != '/' && i + 1 < dev_sz) {
        dev_name[i] = rest[i];
        i++;
    }
    dev_name[i] = '\0';

    file_name[0] = '\0';
    if (rest[i] == '/') {
        const char *file = rest + i + 1;
        strncpy(file_name, file, file_sz - 1);
        file_name[file_sz - 1] = '\0';
    }
    /* 忽略尾部斜杠产生的空 dev */
    if (dev_name[0] == '\0') {
        return -1;
    }
    return 0;
}

/* 按 dev+file 查 sysfs 值。返回写入 buf 的字节数（不含末尾 0），未命中 -1。 */
ssize_t urma_sim_read_sysfs(const urma_sim_dev_t *dev, const char *file, char *buf, size_t size)
{
    if (dev == NULL || file == NULL || buf == NULL || size == 0) {
        return -1;
    }
    for (int i = 0; i < dev->sysfs_cnt; i++) {
        if (strcmp(dev->sysfs[i].key, file) == 0) {
            size_t len = strlen(dev->sysfs[i].value);
            if (len + 2 > size) {  /* 需要末尾 \n 和 \0；不足时截断并至少留 1 字节给 \0 */
                len = size - 1;
            }
            if (len > 0) {
                memcpy(buf, dev->sysfs[i].value, len);
                /* sysfs 文件惯例以换行结尾，urma 库 ub_str_to_* 兼容尾部 \n */
                if (len + 1 < size && buf[len - 1] != '\n') {
                    buf[len] = '\n';
                    len++;
                }
            }
            buf[len] = '\0';
            return (ssize_t)len;
        }
    }
    return -1;
}

/* === fd 表 === */
int urma_sim_fd_alloc(urma_sim_fd_type_t type, int dev_idx, const char *file)
{
    for (int i = 0; i < URMA_SIM_FD_MAX; i++) {
        if (!g_urma_sim_fds[i].in_use) {
            int fd = 100000 + i;
            g_urma_sim_fds[i].in_use = 1;
            g_urma_sim_fds[i].type = type;
            g_urma_sim_fds[i].dev_idx = dev_idx;
            g_urma_sim_fds[i].read_off = 0;
            g_urma_sim_fds[i].file[0] = '\0';
            if (file != NULL) {
                strncpy(g_urma_sim_fds[i].file, file, sizeof(g_urma_sim_fds[i].file) - 1);
            }
            return fd;
        }
    }
    return -1;
}

urma_sim_fd_t *urma_sim_fd_get(int fd)
{
    if (fd < 100000 || fd >= 100000 + URMA_SIM_FD_MAX) {
        return NULL;
    }
    urma_sim_fd_t *e = &g_urma_sim_fds[fd - 100000];
    return e->in_use ? e : NULL;
}

void urma_sim_fd_free(int fd)
{
    urma_sim_fd_t *e = urma_sim_fd_get(fd);
    if (e != NULL) {
        e->in_use = 0;
    }
}

/* === 异步事件 fd 登记（GET_ASYNC_EVENT 拦截判定） ===
 * async_fd 是 CREATE_CTX 回填的真 eventfd（内核分配的小 fd），查不到假 fd 表
 * （urma_sim_fd_get 只认 100000+）；必须独立登记，否则 GET_ASYNC_EVENT 会被
 * 透传到 eventfd 上 ioctl → ENOTTY，urma_get_async_event() 恒失败。 */
static int g_async_event_fds[URMA_SIM_FD_MAX];
static int g_async_event_cnt = 0;

void urma_sim_async_fd_register(int fd)
{
    if (fd < 0) {
        return;
    }
    for (int i = 0; i < g_async_event_cnt; i++) {
        if (g_async_event_fds[i] == fd) {
            return;
        }
    }
    if (g_async_event_cnt < URMA_SIM_FD_MAX) {
        g_async_event_fds[g_async_event_cnt++] = fd;
    }
}

int urma_sim_async_fd_is_registered(int fd)
{
    for (int i = 0; i < g_async_event_cnt; i++) {
        if (g_async_event_fds[i] == fd) {
            return 1;
        }
    }
    return 0;
}

/* urma 日志回调：全级别打到 stderr（URMA_SIM_STDERR_LOG=1 时注册）。
 * 容器里 urma 默认走 syslog 看不见，调试 urma_sample 等不注册 log 的程序时用。 */
void urma_sim_stderr_log(int level, char *message)
{
    (void)level;
    (void)fputs(message, stderr);
}

/* ⑦A: DBG 日志门控——URMA_SIM_DEBUG=1 才输出（懒加载环境变量）。 */
static int g_sim_debug = -1;
int urma_sim_debug_enabled(void)
{
    if (g_sim_debug < 0) {
        const char *dbg = getenv("URMA_SIM_DEBUG");
        g_sim_debug = (dbg != NULL && dbg[0] != '\0' && dbg[0] != '0') ? 1 : 0;
    }
    return g_sim_debug;
}

/* === 构造函数：初始化 + 造临时枚举目录 === */
__attribute__((constructor))
static void urma_sim_ctor(void)
{
    urma_sim_init();
    /* 可选：把 liburma 日志引到 stderr（urma 默认走 syslog，容器里看不到）。
     * 设 URMA_SIM_STDERR_LOG=1 开启。test 程序若自己注册了 log func 会覆盖此设置，
     * 故不影响 test_hw_post/test_ipc_2proc（它们 my_log 只打 ERROR）。 */
    if (getenv("URMA_SIM_STDERR_LOG") != NULL) {
        void urma_register_log_func(void (*func)(int level, char *message));
        urma_register_log_func(urma_sim_stderr_log);
    }
    /* 异常注入：URMA_SIM_INJECT_STATUS=十进制 src_status（1=LOCAL_OP_ERR/4=RNR_RETRY/5=ACK_TIMEOUT）
     * produce_cqe 命中造 error CQE，验真 udma 错误转换链。默认 0=不注入。 */
    const char *inj = getenv("URMA_SIM_INJECT_STATUS");
    if (inj != NULL && inj[0] != '\0') {
        long v = strtol(inj, NULL, 0);
        if (v > 0 && v < 7) {   /* UDMA_SRC_STATUS_NUM=7 */
            g_inject_cqe_status = (uint8_t)v;
        }
    }
    /* 在 /tmp 下造一个临时目录，每个设备名建一个子目录。
     * urma_discover_devices 的 opendir("/sys/class/ubcore") 我们劫持成 opendir 这个临时目录，
     * readdir 就能正常吐设备名。 */
    /* URMA_SIM_HW=1：启动模拟硬件轮询线程（真 udma provider 接管设备，
     * sim 只拦 ioctl/mmap/ummu + 产 CQE）。未设则报错退出——legacy
     * sim 自身 provider 已废弃（方式 3），不再注册。 */
    const char *hw = getenv("URMA_SIM_HW");
    if (hw != NULL && hw[0] == '1') {
        urma_sim_hw_start();
    } else {
        fprintf(stderr, "WARN: URMA_SIM_HW is not set to 1; DT 需要真 udma provider + "
                        "sim 硬件模拟（方式 1），请设置 URMA_SIM_HW=1\n");
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    g_sim_dir_root[0] = '\0';
    for (int attempt = 0; attempt < 16; attempt++) {
        /* 唯一性来源：PID + 墙钟秒 + 纳秒（na ns × PID 不可预测，非进程内从 0 计
         * 的 clock()）；EEXIST 仅当极端巧合才可能，attempt 作为最后的兜底后缀。 */
        snprintf(g_sim_dir_root, sizeof(g_sim_dir_root), "/tmp/urma_sim_%d_%ld_%ld_%d",
                 (int)getpid(), (long)ts.tv_sec,
                 (long)(ts.tv_nsec ^ (long)getpid()), attempt);
        if (mkdir(g_sim_dir_root, 0700) == 0) {
            break;
        }
        g_sim_dir_root[0] = '\0';
        if (errno != EEXIST) {
            (void)fprintf(stderr, "FATAL: cannot create tmp dir under /tmp: %s\n", strerror(errno));
            break;
        }
    }
    if (g_sim_dir_root[0] == '\0') {
        /* 16 次尝试仍未建成：明确告警，绝不静默回退到真实 /sys /dev 调用方
         * 无法区分，可能误操作宿主真实 URMA 设备。 */
        (void)fprintf(stderr, "FATAL: cannot create unique tmp dir for sim devices under /tmp\n");
        return;
    }
    int subdir_ok = 1;
    for (int i = 0; i < g_urma_sim.dev_cnt; i++) {
        char p[512];
        snprintf(p, sizeof(p), "%s/%s", g_sim_dir_root, g_urma_sim.devices[i].name);
        if (mkdir(p, 0700) != 0) {
            subdir_ok = 0;
            (void)fprintf(stderr, "FATAL: cannot create sim device dir %s: %s\n",
                          p, strerror(errno));
            break;
        }
    }
    if (!subdir_ok) {
        /* 设备枚举目录不完整（ENOSPC/EDQUOT/权限等）：不得发布就绪。保持
         * g_sim_ready=0，拦截器对仿真路径一律拒绝，避免"枚举只见部分设备、
         * 而 stat/open 仍按配置识别全部设备"的内部不一致。 */
        (void)fprintf(stderr, "FATAL: sim device enumeration incomplete, simulator disabled\n");
        return;
    }
    g_sim_ready = 1;
}
__attribute__((destructor))
static void urma_sim_dtor(void)
{
    if (g_sim_dir_root[0] != '\0') {
        for (int i = 0; i < g_urma_sim.dev_cnt; i++) {
            char p[512];
            snprintf(p, sizeof(p), "%s/%s", g_sim_dir_root, g_urma_sim.devices[i].name);
            rmdir(p);
        }
        rmdir(g_sim_dir_root);
    }
}

/* ====== 拦截实现 ====== */

DIR *opendir(const char *name)
{
    init_real_funcs();
    /* /sys/class/ubcore(枚举设备) 和 /dev/uburma(check_dev_name 校验设备名)
     * 都重定向到 constructor 造的临时目录，该目录含每个设备名作为子条目。 */
    if (g_sim_ready && g_sim_dir_root[0] != '\0' &&
        (strcmp(name, URMA_SYSFS_PREFIX) == 0 || strcmp(name, URMA_DEV_PREFIX) == 0)) {
        return real_opendir(g_sim_dir_root);
    }
    /* 仿真未就绪（目录创建失败）：禁止回落到宿主的 /sys、/dev 枚举，直接拒绝。 */
    if (!g_sim_ready &&
        (strcmp(name, URMA_SYSFS_PREFIX) == 0 || strcmp(name, URMA_DEV_PREFIX) == 0)) {
        errno = ENOENT;
        return NULL;
    }
    /* build 路径下的 provider 目录（urma_open_drivers 用 dladdr 推算 liburma 路径，
     * build_noasan 的 liburma 没有 /urma/ 子目录）。重定向到装版 provider 目录，
     * 让 urma_init 能 dlopen 真 udma provider（与 sim 同名，sim 先注册赢）。 */
    size_t name_len = strlen(name);
    if (strstr(name, "build") != NULL && name_len >= strlen("/urma") &&
        strcmp(name + name_len - strlen("/urma"), "/urma") == 0) {
        return real_opendir("/usr/lib64/urma");
    }
    return real_opendir(name);
}

int stat(const char *path, struct stat *buf)
{
    init_real_funcs();
    if (urma_sim_is_sysfs_path(path)) {
        if (!g_sim_ready) {
            errno = ENOENT;   /* 仿真未就绪：不访问宿主设备树 */
            return -1;
        }
        char dev_name[64];
        char file_name[64];
        if (urma_sim_split_sysfs_path(path, dev_name, sizeof(dev_name), file_name, sizeof(file_name)) == 0) {
            if (urma_sim_find_dev(dev_name) != NULL) {
                memset(buf, 0, sizeof(*buf));
                if (file_name[0] == '\0') {
                    buf->st_mode = S_IFDIR | 0755;
                } else {
                    buf->st_mode = S_IFREG | 0644;
                    buf->st_size = 64;
                }
                buf->st_mtime = 1000000;  /* 固定时间，urma 用 st_mtim 做 time_created 比较 */
                return 0;
            }
        }
        /* 设备不存在 → ENOENT */
        errno = ENOENT;
        return -1;
    }
    return real_stat(path, buf);
}

/* build 路径下的 provider .so（urma_open_drivers 用 dladdr 推算 liburma 路径，build_noasan
 * 的 liburma 没有 urma 子目录）。把 build 路径下 urma 目录里的 .so 重定向到
 * /usr/lib64/urma/<file>。命中返回 malloc 的重定向路径（caller free），否则 NULL。 */
static char *urma_sim_provider_redirect(const char *path)
{
    if (path == NULL) {
        return NULL;
    }
    const char *sim_provider = strstr(path, "/urma/liburma_sim.so");
    if (sim_provider != NULL && strcmp(sim_provider, "/urma/liburma_sim.so") == 0) {
        char *out = malloc(strlen(path) + 1);
        if (out == NULL) {
            return NULL;
        }
        strcpy(out, path);
        return out;
    }
    if (strstr(path, "build") == NULL) {
        return NULL;
    }
    /* 路径必须含 /urma/ 段，且以 .so 结尾。取最后一个 /urma/ 后的 basename。 */
    const char *last = NULL;
    const char *p = path;
    while ((p = strstr(p, "/urma/")) != NULL) {
        last = p;
        p += strlen("/urma/");
    }
    if (last == NULL) {
        return NULL;
    }
    const char *basename = last + strlen("/urma/");
    size_t blen = strlen(basename);
    /* 接受 .so / .so.0 / .so.0.0.3 等版本后缀：basename 必须含 ".so" 子串 */
    if (blen < 3 || strstr(basename, ".so") == NULL) {
        return NULL;
    }
    char *out = malloc(strlen("/usr/lib64/urma/") + blen + 1);
    if (out == NULL) {
        return NULL;
    }
    snprintf(out, strlen("/usr/lib64/urma/") + blen + 1, "/usr/lib64/urma/%s", basename);
    return out;
}

int access(const char *path, int mode)
{
    init_real_funcs();
    char *redir = urma_sim_provider_redirect(path);
    if (redir != NULL) {
        int r = real_access(redir, mode);
        free(redir);
        return r;
    }
    return real_access(path, mode);
}

/* mmap 拦截：真 udma provider 对 dev_fd（sim 假 fd）做 mmap，offset 编码了 cmd+idx。
 * 反解 offset → 按 cmd 类型分配假内存（doorbell/queue/cq），返回给真 udma 使用。 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    init_real_funcs();
    if (urma_sim_fd_is_cdev(fd)) {
        uint32_t cmd = 0;
        uint32_t idx = 0;
        /* page_size 用 4096（UDMA_HW_PAGE_SIZE），真 udma 也是这个 */
        if (urma_sim_mmap_decode_offset(offset, 4096, &cmd, &idx) == 0) {
            void *p = urma_sim_mmap_alloc(fd, length, cmd, idx);
            if (p != NULL) {
                /* doorbell mmap（JETTY_DSQE）：idx=db.id，关联回 create 时登记的 queue，
                 * 填 db_addr。后续轮询用此关联从 doorbell 找到 queue（buf_addr/jetty_addr）。 */
                if (cmd == URMA_SIM_MMAP_JETTY_DSQE) {
                    urma_sim_queue_assoc_set_db_by_idx(idx, (uint64_t)(uintptr_t)p);
                }
                return p;
            }
            errno = ENOMEM;
            return MAP_FAILED;
        }
        errno = EINVAL;
        return MAP_FAILED;
    }
    return real_mmap(addr, length, prot, flags, fd, offset);
}

/* munmap：对 sim 假内存（urma_sim_mmap_find 命中）no-op 返回 0（不真释放，进程退出回收）；
 * 非假内存走真 munmap。 */
int munmap(void *addr, size_t length)
{
    init_real_funcs();
    urma_sim_mmap_region_t *reg = urma_sim_mmap_find(addr);
    if (reg != NULL) {
        /* 命中 sim 假内存：仅支持整区释放。部分/子区间 munmap 无法用单槽
         * 跟踪（剩余部分脱离跟踪 or 已解除区间仍被识别为模拟映射，模拟线程
         * 可能访问已解除内存）——显式拒绝而非产生不一致。 */
        if ((uintptr_t)addr != (uintptr_t)reg->addr || length != reg->size) {
            errno = EINVAL;
            return -1;
        }
        /* 先真释放匿名映射，成功后才清槽位（失败保留槽位并透传 errno） */
        if (real_munmap(addr, length) != 0) {
            return -1;
        }
        urma_sim_mmap_free(addr);
        return 0;
    }
    return real_munmap(addr, length);
}

char *realpath(const char *path, char *resolved)
{
    init_real_funcs();
    /* provider .so 重定向（urma_open_provider 用 realpath 标准化路径） */
    char *redir = urma_sim_provider_redirect(path);
    if (redir != NULL) {
        char *out = resolved;
        if (out == NULL) {
            out = redir;
        } else {
            strcpy(out, redir);
            free(redir);
        }
        return out;
    }
    if (urma_sim_is_sysfs_path(path) || urma_sim_is_cdev_path(path)) {
        if (!g_sim_ready) {
            errno = ENOENT;   /* 仿真未就绪：不访问宿主设备树 */
            return NULL;
        }
        /* 直接返回原路径。resolved 为 NULL 时需 malloc。 */
        char *out = resolved;
        if (out == NULL) {
            out = (char *)malloc(strlen(path) + 1);
            if (out == NULL) {
                return NULL;
            }
        }
        strcpy(out, path);
        return out;
    }
    /* resolved==NULL 时模拟 glibc 语义（caller free）：部分环境
     * （如 glibc 2.35 受限环境）对 realpath(path, NULL) 直接返回
     * EINVAL——拦截器自己 malloc 后调真实现，行为与 POSIX 一致。 */
    if (resolved == NULL) {
        char *tmp = (char *)malloc(PATH_MAX);
        if (tmp == NULL) {
            return NULL;
        }
        if (real_realpath(path, tmp) == NULL) {
            free(tmp);
            return NULL;
        }
        return tmp;
    }
    return real_realpath(path, resolved);
}

/* open 的 sim 实现：sysfs 文件 + /dev/uburma/<dev> → 假 fd；其余透传。 */
static int urma_sim_open_impl(const char *path, int flags, mode_t mode)
{
    init_real_funcs();

    if (urma_sim_is_sysfs_path(path)) {
        if (!g_sim_ready) {
            errno = ENOENT;   /* 仿真未就绪：不访问宿主设备树 */
            return -1;
        }
        char dev_name[64];
        char file_name[64];
        if (urma_sim_split_sysfs_path(path, dev_name, sizeof(dev_name), file_name, sizeof(file_name)) == 0 &&
            file_name[0] != '\0') {
            const urma_sim_dev_t *dev = urma_sim_find_dev(dev_name);
            if (dev == NULL) {
                errno = ENOENT;
                return -1;
            }
            /* 找设备下标 */
            int idx = -1;
            for (int i = 0; i < g_urma_sim.dev_cnt; i++) {
                if (strcmp(g_urma_sim.devices[i].name, dev_name) == 0) {
                    idx = i;
                    break;
                }
            }
            int fd = urma_sim_fd_alloc(URMA_SIM_FD_SYSFS, idx, file_name);
            if (fd < 0) {
                errno = EMFILE;
                return -1;
            }
            return fd;
        }
    }

    if (urma_sim_is_cdev_path(path)) {
        if (!g_sim_ready) {
            errno = ENOENT;   /* 仿真未就绪：不访问宿主设备树 */
            return -1;
        }
        /* /dev/uburma/<dev> → cdev 假 fd */
        const char *dev_name = path + strlen(URMA_DEV_PREFIX);
        if (*dev_name == '/') {
            dev_name++;
        }
        int idx = -1;
        for (int i = 0; i < g_urma_sim.dev_cnt; i++) {
            if (strcmp(g_urma_sim.devices[i].name, dev_name) == 0) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            errno = ENOENT;
            return -1;
        }
        int fd = urma_sim_fd_alloc(URMA_SIM_FD_CDEV, idx, NULL);
        if (fd < 0) {
            errno = EMFILE;
            return -1;
        }
        return fd;
    }

    return real_open(path, flags, mode);
}

int open(const char *path, int flags, ...)
{
    init_real_funcs();
    mode_t mode = 0;
#ifdef __O_TMPFILE
    if ((flags & O_CREAT) != 0 || (flags & __O_TMPFILE) == __O_TMPFILE) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    return urma_sim_open_impl(path, flags, mode);
}

/* __open_2 是 glibc _FORTIFY_SOURCE 的安全变体：open 不带 O_CREAT 时编译器把
 * open(path, flags) 重写成 __open_2(path, flags)（运行时校验 path 非 NULL）。
 * urma_admin 用 __open_2@GLIBC_2.17，必须单独拦截，否则拦不住。 */
int __open_2(const char *path, int flags)
{
    init_real_funcs();
    return urma_sim_open_impl(path, flags, 0);
}

ssize_t read(int fd, void *buf, size_t count)
{
    init_real_funcs();
    urma_sim_fd_t *e = urma_sim_fd_get(fd);
    if (e != NULL && e->type == URMA_SIM_FD_SYSFS) {
        const urma_sim_dev_t *dev = &g_urma_sim.devices[e->dev_idx];
        char val[128];
        ssize_t len = urma_sim_read_sysfs(dev, e->file, val, sizeof(val));
        if (len < 0) {
            errno = ENOENT;
            return -1;
        }
        if (e->read_off >= (size_t)len) {
            return 0;  /* EOF */
        }
        size_t remain = (size_t)len - e->read_off;
        size_t n = count < remain ? count : remain;
        memcpy(buf, val + e->read_off, n);
        e->read_off += n;
        return (ssize_t)n;
    }
    return real_read(fd, buf, count);
}

int close(int fd)
{
    init_real_funcs();
    urma_sim_fd_t *e = urma_sim_fd_get(fd);
    if (e != NULL) {
        urma_sim_fd_free(fd);
        return 0;
    }
    return real_close(fd);
}

int ioctl(int fd, unsigned long request, ...)
{
    init_real_funcs();
    va_list ap;
    va_start(ap, request);
    void *argp = va_arg(ap, void *);
    va_end(ap);

    urma_sim_fd_t *e = urma_sim_fd_get(fd);
    if (e != NULL && e->type == URMA_SIM_FD_CDEV && request == URMA_CMD && argp != NULL) {
        urma_cmd_hdr_t *hdr = (urma_cmd_hdr_t *)argp;
        int ret = urma_sim_handle_ioctl(fd, hdr->command, hdr->args_len, hdr->args_addr);
        /* 透传返回值：urma_sim_handle_ioctl 返回 -1 表示 sim 不直接回填（如 GET_EID_LIST），
         * 让真 urma 走 sysfs fallback（urma_read_eid_list 失败 → 读 eids/eidN）。
         * 错误码：命令层用 -errno 编码具体错误（ret < -1），在此透传为 errno
         * （EINVAL/EBADF…不能被统一覆盖成 EIO，否则调用方把命令构造错误误报
         * 为设备 I/O 故障）；仅 ret == -1（无具体错误码）才回退 EIO。 */
        if (ret != 0) {
            errno = (ret < -1) ? -ret : EIO;
            return -1;
        }
        return 0;
    }
    /* GET_ASYNC_EVENT（⑲）：async_fd 是 CREATE_CTX 回填的真 eventfd（非假
     * fd 表 100000+ 段），必须用独立登记表判定。sim 拦截：无事件回填 0 并返回
     * EAGAIN（真实"无事件"语义，应用轮询循环依赖）；有事件（错误注入）时
     * 回填 EVENT_TYPE/EVENT_DATA 返回 0。 */
    if (urma_sim_async_fd_is_registered(fd) && request == URMA_CMD_GET_ASYNC_EVENT && argp != NULL) {
        urma_cmd_hdr_t *hdr = (urma_cmd_hdr_t *)argp;
        if (hdr->args_addr != 0 && hdr->args_len != 0) {
            /* attrs 数组：GET_ASYNC_EVENT_OUT_EVENT_TYPE / OUT_EVENT_DATA 全 0（无事件） */
            size_t attr_num = hdr->args_len / sizeof(urma_cmd_attr_t);
            urma_cmd_attr_t *attrs = (urma_cmd_attr_t *)(uintptr_t)hdr->args_addr;
            for (size_t i = 0; i < attr_num; i++) {
                if (attrs[i].data != 0) {
                    memset((void *)(uintptr_t)attrs[i].data, 0, attrs[i].field_size);
                }
            }
        }
        errno = EAGAIN;
        return -1;
    }
    /* 非 sim 域 ioctl：需要把 argp 透传。libc ioctl 是变参，这里只能转单参形式。 */
    return real_ioctl(fd, request, argp);
}
