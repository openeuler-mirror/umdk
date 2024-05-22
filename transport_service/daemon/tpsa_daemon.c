/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tpsa daemon main file
 * Author: Chen Wen
 * Create: 2022-08-24
 * Note:
 * History: 2022-08-24: Create file
 */

#define _GNU_SOURCE
#include <errno.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <execinfo.h>

#include "ub_util.h"
#include "ub_list.h"
#include "ub_shash.h"
#include "uvs_api.h"
#include "tpsa_log.h"
#include "tpsa_config.h"
#include "tpsa_net.h"
#include "tpsa_service.h"
#include "tpsa_daemon.h"

#define DEFAULT_UMASK    0027
#define DUMP_STACK_DEPTH 64

static tpsa_daemon_ctx_t g_tpsa_daemon_ctx;
static const char * const g_pidfile = "/var/run/tpsa.pid";
static FILE *g_file = NULL;
static int g_dev_null_fd = -1;

static void tpsa_sig_cb_func(int signal)
{
    g_tpsa_daemon_ctx.keeper_runnig = false;
}

static void tpsa_register_signal(void)
{
    struct sigaction psa;
    psa.sa_flags = 0;
    psa.sa_handler = tpsa_sig_cb_func;
    (void)sigaction(SIGTSTP, &psa, NULL); /* need SIGTSTP to kill */

    // Ignore SIGPIPE
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        TPSA_LOG_WARN("register SIGPIPE callback failed");
    }
}

static int lock_file(FILE *file)
{
    struct flock flk;
    int error;

    if (file == NULL) {
        return -1;
    }

    flk.l_type = F_WRLCK;
    flk.l_whence = SEEK_SET;
    flk.l_start = 0;
    flk.l_len = 0;
    flk.l_pid = 0;

LOCK_AGAIN:
    error = fcntl(fileno(file), F_SETLK, &flk);
    if (error == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            return error;
        } else if (errno == EINTR) {
            goto LOCK_AGAIN;
        }
    }

    return 0;
}

static void running_singleton(void)
{
    pid_t pid;
    int error;

    /* print a syslog before open g_pidfile avoid file closed by syslog */
    TPSA_LOG_INFO("running_singleton\n");

    /* Step 1: open pidfile */
    g_file = fopen(g_pidfile, "a+");
    if (g_file == NULL) {
        TPSA_LOG_ERR("open uvs pid file failed\n");
        exit(EXIT_FAILURE);
    }

    /* Step 2: lock pidfile */
    error = lock_file(g_file);
    if (error) {
        TPSA_LOG_ERR("lock uvs pid file failed\n");
        goto ERR;
    }

    /* Step 3: clear pidfile and wirte pid to it */
    if (ftruncate(fileno(g_file), 0) == -1) {
        TPSA_LOG_ERR("clear uvs pid file failed\n");
        goto ERR;
    }

    pid = getpid();
    error = fprintf(g_file, "%ld\n", (long)pid);
    if (error < 0) {
        TPSA_LOG_ERR("write uvs pid file failed\n");
        goto ERR;
    }

    if (fflush(g_file) == EOF) {
        TPSA_LOG_ERR("flush uvs pid file failed\n");
        goto ERR;
    }

    return;
ERR:
    if (g_file) {
        (void)fclose(g_file);
        g_file = NULL;
    }
    exit(EXIT_FAILURE);
}

static int standard_stream_fds_close(void)
{
    g_dev_null_fd = open("/dev/null", O_RDWR);
    int ret;

    if (g_dev_null_fd < 0) {
        ret = errno;
        TPSA_LOG_ERR("standard stream fdsclose error: %s", ub_strerror(errno));
        return ret;
    }

    (void)dup2(g_dev_null_fd, STDIN_FILENO);
    (void)dup2(g_dev_null_fd, STDOUT_FILENO);
    (void)dup2(g_dev_null_fd, STDERR_FILENO);

    if (g_dev_null_fd > STDERR_FILENO) {
        (void)close(g_dev_null_fd);
        g_dev_null_fd = -1;
    }
    return 0;
}

static void daemonize(void)
{
    pid_t pid;
    int ret;

    pid = fork();
    if (pid == -1) {
        TPSA_LOG_ERR("fork daemon process failed");
    }

    if (pid > 0) {
        exit(0);    /* Fork success, exit the parent process */
    }

    /* Runnig int the child daemon process */
    ret = setsid();          /* create new session */
    if (ret == -1) {
        TPSA_LOG_ERR("failed to create child process");
        exit(0);
    }

    ret = chdir("/");      /* change work dir */
    if (ret == -1) {
        TPSA_LOG_ERR("failed to change dir to /");
        exit(0);
    }

    (void)umask(DEFAULT_UMASK);     /* reset file mask */
    ret = standard_stream_fds_close();
    if (ret != 0) {
        exit(0);
    }

    running_singleton();
    return;
}

static void pid_file_clean(void)
{
    if (!access(g_pidfile, F_OK)) {
        (void)unlink(g_pidfile);
        TPSA_LOG_INFO("pid file clean\n");
    }
}

static void close_gfile_gfd(void)
{
    if (g_file) {
        (void)fclose(g_file);
        g_file = NULL;
    }

    if (g_dev_null_fd >= 0) {
        (void)close(g_dev_null_fd);
        g_dev_null_fd = -1;
    }

    pid_file_clean();
}

static void crash_dump_stack(int signo)
{
    void *buffer[DUMP_STACK_DEPTH] = {0};
    int depth;
    char **strings = NULL;
    int i = 0;

    /* reset signal deal func to default */
    (void)signal(SIGSEGV, SIG_DFL);
    (void)signal(SIGABRT, SIG_DFL);
    (void)signal(SIGBUS, SIG_DFL);
    depth = backtrace(buffer, DUMP_STACK_DEPTH);
    strings = backtrace_symbols(buffer, depth);
    if (strings == NULL) {
        TPSA_LOG_ERR("backtrace_symbols err.");
        goto out;
    }

    TPSA_LOG_ERR("dump %d stack:", depth);
    for (i = 0; i < depth; i++)  {
        TPSA_LOG_ERR("%s\n", strings[i]);
    }
    free(strings);

out:
    /* del signal handler, and send signal */
    (void)signal(signo, SIG_DFL);
    (void)raise(signo);
}

static void register_crash_signal(void)
{
    void* dummy = NULL;
    int depth;

    /* call backtrace() and backtrace_symbols_fd() to make sure libgcc is loaded beforehand.
    ** then avoid to call malloc
    */
    depth = backtrace(&dummy, 1);
    backtrace_symbols_fd(&dummy, depth, STDOUT_FILENO);

    if (signal(SIGSEGV, crash_dump_stack) == SIG_ERR) {
        TPSA_LOG_WARN("register SIGSEGV callback failed");
    }
    if (signal(SIGABRT, crash_dump_stack) == SIG_ERR) {
        TPSA_LOG_WARN("register SIGABRT callback failed");
    }
    if (signal(SIGBUS, crash_dump_stack) == SIG_ERR) {
        TPSA_LOG_WARN("register SIGBUS callback failed");
    }
}

int main(int argc, char *argv[])
{
    daemonize();

    register_crash_signal();

    tpsa_config_t uvs_cfg = {0};
    if (tpsa_parse_config_file(&uvs_cfg) != 0) {
        return -1;
    }

    uvs_init_attr_t attr = {true, uvs_cfg.tpsa_worker_cpu_core};
    uvs_socket_init_attr_t socket_attr = {
        .type = uvs_cfg.tpsa_ip_type,
        .server_ip = uvs_cfg.tpsa_server_ip,
        .server_port = uvs_cfg.tpsa_server_port
    };
    if (uvs_so_init(&attr) != 0) {
        return -1;
    }
    if (uvs_socket_init(&socket_attr) != 0) {
        uvs_so_uninit();
        return -1;
    }
    g_tpsa_daemon_ctx.worker = uvs_get_worker();

    if (tpsa_socket_service_init() != 0) {
        uvs_socket_uninit();
        uvs_so_uninit();
        return -1;
    }
    /* In order to receive the process stop signal */
    tpsa_register_signal();

    g_tpsa_daemon_ctx.keeper_runnig = true;
    while (g_tpsa_daemon_ctx.keeper_runnig) {
        (void)sleep(1);
    }

    TPSA_LOG_INFO("tpsa daemon start to exit!\n");

    tpsa_socket_service_uninit();
    uvs_socket_uninit();
    uvs_so_uninit();
    TPSA_LOG_INFO("uvs daemon exited!\n");

    close_gfile_gfd();
    return 0;
}

tpsa_daemon_ctx_t *get_tpsa_daemon_ctx(void)
{
    return &g_tpsa_daemon_ctx;
}

