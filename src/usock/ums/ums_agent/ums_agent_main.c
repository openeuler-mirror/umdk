/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Description: Main entry of the UMS agent daemon
 * Author: Hu Ying
 * Create: 2026-04-20
 * Note:
 * History: 2026-04-20  Create File
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <glib.h>
#include <systemd/sd-daemon.h>

#include "ums_agent_config.h"
#include "ums_agent_log.h"

#define UMS_AGENT_VERSION             "0.1.0"
#define UMS_AGENT_CONFIG_PATH_PREFIX  "/etc/ums_agent/"
#define UMS_AGENT_DEFAULT_CONFIG_PATH "/etc/ums_agent/ums_agent.conf"
#define UMS_AGENT_EPOLL_MAX_EVENTS    32

struct ums_agent_ctx {
    int epoll_fd;
    int nl_fd;
    int tls_listen_fd;
    int timer_fd;
    int signal_fd;
    atomic_bool running;
    struct ums_agent_config *config;
};

static struct ums_agent_ctx g_ums_agent_ctx = {
    .epoll_fd = -1,
    .nl_fd = -1,
    .tls_listen_fd = -1,
    .timer_fd = -1,
    .signal_fd = -1,
    .running = ATOMIC_VAR_INIT(false),
    .config = NULL,
};

static void ums_agent_print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n"
           "Options:\n"
           "  -c, --config <path>   Configuration file path (must be under %s default: %s)\n"
           "  -v, --version         Show version\n"
           "  -h, --help            Show this help\n",
           prog, UMS_AGENT_CONFIG_PATH_PREFIX, UMS_AGENT_DEFAULT_CONFIG_PATH);
}

static void ums_agent_print_version(void)
{
    printf("ums_agent version %s\n", UMS_AGENT_VERSION);
}

static int ums_agent_validate_and_resolve_config_path(const char *path, char *resolved_path)
{
    if (!path) {
        fprintf(stderr, "ums_agent: config path is NULL\n");
        return -1;
    }

    if (ums_agent_resolve_path(path, "config path", resolved_path) != 0) {
        fprintf(stderr, "ums_agent: failed to resolve config path\n");
        return -1;
    }

    if (!g_str_has_prefix(resolved_path, UMS_AGENT_CONFIG_PATH_PREFIX)) {
        fprintf(stderr, "ums_agent: invalid config path: %s (must be under %s)\n",
            resolved_path, UMS_AGENT_CONFIG_PATH_PREFIX);
        return -1;
    }

    return 0;
}

static int ums_agent_parse_args(int argc, char *argv[], char *config_path)
{
    static struct option long_opts[] = {
        {"config",  required_argument, NULL, 'c'},
        {"version", no_argument,       NULL, 'v'},
        {"help",    no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:vh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c':
                if (ums_agent_validate_and_resolve_config_path(optarg, config_path) != 0) {
                    return -1;
                }
                break;
            case 'v':
                ums_agent_print_version();
                return 1;
            case 'h':
                ums_agent_print_usage(argv[0]);
                return 1;
            default:
                ums_agent_print_usage(argv[0]);
                return -1;
        }
    }
    return 0;
}

static int ums_agent_epoll_init(void)
{
    g_ums_agent_ctx.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (g_ums_agent_ctx.epoll_fd < 0) {
        UMS_AGENT_LOG_ERR("epoll_create1 failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }
    return 0;
}

static void ums_agent_epoll_deinit(void)
{
    if (g_ums_agent_ctx.epoll_fd >= 0) {
        close(g_ums_agent_ctx.epoll_fd);
        g_ums_agent_ctx.epoll_fd = -1;
    }
}

static int ums_agent_register_fd_to_epoll(int fd, uint32_t events)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(g_ums_agent_ctx.epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        UMS_AGENT_LOG_ERR("epoll_ctl ADD fd=%d failed: %s (errno=%d)", fd, strerror(errno), errno);
        return -1;
    }
    return 0;
}

static int ums_agent_setup_signal_fd(void)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        UMS_AGENT_LOG_ERR("sigprocmask failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0) {
        UMS_AGENT_LOG_ERR("signalfd failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    if (ums_agent_register_fd_to_epoll(sfd, EPOLLIN) < 0) {
        close(sfd);
        return -1;
    }

    g_ums_agent_ctx.signal_fd = sfd;
    return 0;
}

static void ums_agent_teardown_signal_fd(void)
{
    if (g_ums_agent_ctx.signal_fd >= 0) {
        close(g_ums_agent_ctx.signal_fd);
        g_ums_agent_ctx.signal_fd = -1;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

static int ums_agent_setup_timer_fd(void)
{
    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (tfd < 0) {
        UMS_AGENT_LOG_ERR("timerfd_create failed: %s (errno=%d)", strerror(errno), errno);
        return -1;
    }

    if (ums_agent_register_fd_to_epoll(tfd, EPOLLIN) < 0) {
        close(tfd);
        return -1;
    }

    g_ums_agent_ctx.timer_fd = tfd;
    return 0;
}

static void ums_agent_request_stop(void)
{
    atomic_store(&g_ums_agent_ctx.running, false);
}

static void ums_agent_handle_signal_event(int sfd)
{
    struct signalfd_siginfo si;
    ssize_t n = read(sfd, &si, sizeof(si));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return;
        }
        UMS_AGENT_LOG_ERR("read signalfd failed: %s (errno=%d)", strerror(errno), errno);
        return;
    }
    if (n != sizeof(si)) {
        UMS_AGENT_LOG_ERR("read signalfd: unexpected size %zd, expected %zu", n, sizeof(si));
        return;
    }

    if (si.ssi_signo != SIGTERM && si.ssi_signo != SIGINT) {
        UMS_AGENT_LOG_WARN("received unexpected signal %d, ignoring", si.ssi_signo);
        return;
    }

    UMS_AGENT_LOG_INFO("received signal %d (%s), stopping",
        si.ssi_signo,
        si.ssi_signo == SIGTERM ? "SIGTERM" : "SIGINT");

    ums_agent_request_stop();
}

static void ums_agent_handle_timer_event(int tfd)
{
    uint64_t expirations;
    ssize_t n = read(tfd, &expirations, sizeof(expirations));
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return;
        }
        UMS_AGENT_LOG_ERR("read timerfd failed: %s (errno=%d)", strerror(errno), errno);
        return;
    }
    if (n != sizeof(expirations)) {
        UMS_AGENT_LOG_WARN("read timerfd: unexpected size %zd, expected %zu", n, sizeof(expirations));
        return;
    }
    // handle timer event (use expirations to process missed ticks if needed)
}

static void ums_agent_dispatch_event(struct epoll_event *ev)
{
    int fd = ev->data.fd;

    if (fd == g_ums_agent_ctx.signal_fd && (ev->events & EPOLLIN)) {
        ums_agent_handle_signal_event(fd);
    } else if (fd == g_ums_agent_ctx.tls_listen_fd && (ev->events & EPOLLIN)) {
        // handle tls listen event
    } else if (fd == g_ums_agent_ctx.nl_fd && (ev->events & EPOLLIN)) {
        // handle netlink event
    } else if (fd == g_ums_agent_ctx.timer_fd && (ev->events & EPOLLIN)) {
        ums_agent_handle_timer_event(fd);
    } else {
        UMS_AGENT_LOG_WARN("unhandled epoll event: fd=%d, events=0x%x", fd, ev->events);
    }
}

static int ums_agent_epoll_loop(void)
{
    struct epoll_event events[UMS_AGENT_EPOLL_MAX_EVENTS];

    UMS_AGENT_LOG_INFO("entering main event loop");

    while (atomic_load(&g_ums_agent_ctx.running)) {
        int nfds = epoll_wait(g_ums_agent_ctx.epoll_fd, events, UMS_AGENT_EPOLL_MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            UMS_AGENT_LOG_ERR("epoll_wait failed: %s (errno=%d)", strerror(errno), errno);
            return -1;
        }

        for (int i = 0; i < nfds; i++) {
            ums_agent_dispatch_event(&events[i]);
        }
    }

    UMS_AGENT_LOG_INFO("exiting main event loop");
    return 0;
}

static void ums_agent_fatal_signal_handler(int sig)
{
    static const char msg[] = "ums_agent: fatal signal received, aborting\n";
    ssize_t ret = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ret;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, sig);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    (void)raise(sig);
    _exit(128 + sig); /* 128 + signal number per Unix convention for signal exit codes */
}

static void ums_agent_signal_init(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = ums_agent_fatal_signal_handler;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSEGV);
    sigaddset(&sa.sa_mask, SIGABRT);
    sigaddset(&sa.sa_mask, SIGBUS);
    sigaddset(&sa.sa_mask, SIGFPE);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}

static int ums_agent_notify_systemd(const char *state)
{
    int ret = sd_notify(0, state);
    if (ret < 0) {
        UMS_AGENT_LOG_WARN("sd_notify(\"%s\") failed: %s", state, strerror(-ret));
        return ret;
    }
    UMS_AGENT_LOG_DEBUG("sd_notify(\"%s\") sent, ret=%d", state, ret);
    return 0;
}

static void ums_agent_shutdown(void)
{
    UMS_AGENT_LOG_INFO("ums_agent shutting down");

    ums_agent_notify_systemd("STOPPING=1");

    if (g_ums_agent_ctx.tls_listen_fd >= 0) {
        close(g_ums_agent_ctx.tls_listen_fd);
        g_ums_agent_ctx.tls_listen_fd = -1;
    }

    if (g_ums_agent_ctx.nl_fd >= 0) {
        // sending DOWN notification to kernel
        close(g_ums_agent_ctx.nl_fd);
        g_ums_agent_ctx.nl_fd = -1;
    }

    if (g_ums_agent_ctx.timer_fd >= 0) {
        close(g_ums_agent_ctx.timer_fd);
        g_ums_agent_ctx.timer_fd = -1;
    }

    ums_agent_teardown_signal_fd();
    ums_agent_epoll_deinit();
    ums_agent_config_deinit(g_ums_agent_ctx.config);
    g_ums_agent_ctx.config = NULL;

    UMS_AGENT_LOG_INFO("ums_agent shut down successfully");
    ums_agent_log_deinit();
}

int main(int argc, char *argv[])
{
    char config_path[PATH_MAX];
    int ret;

    (void)snprintf(config_path, sizeof(config_path), "%s", UMS_AGENT_DEFAULT_CONFIG_PATH);
    ret = ums_agent_parse_args(argc, argv, config_path);
    if (ret > 0) {
        return EXIT_SUCCESS;
    } else if (ret < 0) {
        return EXIT_FAILURE;
    }

    ums_agent_log_init(UMS_AGENT_LOG_LEVEL_INFO);

    ums_agent_signal_init();

    ret = ums_agent_config_init(config_path, &g_ums_agent_ctx.config);
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("config init failed, config_path=%s", config_path);
        ums_agent_log_deinit();
        return EXIT_FAILURE;
    }

    ums_agent_log_set_level(g_ums_agent_ctx.config->log_level);

    UMS_AGENT_LOG_INFO("ums_agent starting, config=%s", config_path);

    ret = ums_agent_epoll_init();
    if (ret < 0) {
        UMS_AGENT_LOG_ERR("epoll init failed");
        goto err_log;
    }

    if (ums_agent_setup_signal_fd() < 0) {
        UMS_AGENT_LOG_ERR("signal fd setup failed");
        goto err_epoll;
    }

    if (ums_agent_setup_timer_fd() < 0) {
        UMS_AGENT_LOG_ERR("timer fd setup failed");
        goto err_signal;
    }

    atomic_store(&g_ums_agent_ctx.running, true);

    UMS_AGENT_LOG_INFO("ums_agent initialized successfully");

    ums_agent_notify_systemd("READY=1");

    ret = ums_agent_epoll_loop();

    ums_agent_shutdown();

    return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

err_signal:
    if (g_ums_agent_ctx.signal_fd >= 0) {
        close(g_ums_agent_ctx.signal_fd);
        g_ums_agent_ctx.signal_fd = -1;
    }
err_epoll:
    ums_agent_epoll_deinit();
err_log:
    ums_agent_log_deinit();
    ums_agent_config_deinit(g_ums_agent_ctx.config);
    g_ums_agent_ctx.config = NULL;
    return EXIT_FAILURE;
}
