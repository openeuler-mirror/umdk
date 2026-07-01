/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Description: liburma public API fuzz entry generated from urma_api.h
 */

#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "urma_api.h"

typedef int (*fuzz_entry_t)(void);

typedef struct fuzz_case {
    const char *name;
    fuzz_entry_t entry;
} fuzz_case_t;

#ifndef URMA_LIBFUZZER
static int WaitFuzzChild(pid_t pid, const char *case_name)
{
    int status = 0;

    /* LCOV_EXCL_START */
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {
        fprintf(stderr, "%s terminated by signal %d\n", case_name, WTERMSIG(status));
        return 1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "%s exited with status %d\n", case_name, status);
        return 1;
    }
    /* LCOV_EXCL_STOP */

    return 0;
}

static int RunFuzzCase(const fuzz_case_t *test_case)
{
    pid_t pid = fork();

    /* LCOV_EXCL_START */
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    /* LCOV_EXCL_STOP */

    if (pid == 0) {
        (void)alarm(2);
        (void)test_case->entry();
        exit(0);
    }

    return WaitFuzzChild(pid, test_case->name);
}
#endif

static int Fuzz_urma_init(void)
{
    (void)urma_init(NULL);
    return 0;
}

static int Fuzz_urma_uninit(void)
{
    (void)urma_uninit();
    return 0;
}

static int Fuzz_urma_get_device_list(void)
{
    (void)urma_get_device_list(NULL);
    return 0;
}

static int Fuzz_urma_free_device_list(void)
{
    (void)urma_free_device_list(NULL);
    return 0;
}

static int Fuzz_urma_get_eid_list(void)
{
    (void)urma_get_eid_list(NULL, NULL);
    return 0;
}

static int Fuzz_urma_free_eid_list(void)
{
    (void)urma_free_eid_list(NULL);
    return 0;
}

static int Fuzz_urma_get_device_by_name(void)
{
    (void)urma_get_device_by_name(NULL);
    return 0;
}

static int Fuzz_urma_get_device_by_eid(void)
{
    urma_eid_t arg0_eid = {0};
    urma_transport_type_t arg1_type = {0};

    (void)urma_get_device_by_eid(arg0_eid, arg1_type);
    return 0;
}

static int Fuzz_urma_query_device(void)
{
    (void)urma_query_device(NULL, NULL);
    return 0;
}

static int Fuzz_urma_create_context(void)
{
    (void)urma_create_context(NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_delete_context(void)
{
    (void)urma_delete_context(NULL);
    return 0;
}

static int Fuzz_urma_set_context_opt(void)
{
    urma_opt_name_t arg1_opt_name = {0};

    (void)urma_set_context_opt(NULL, arg1_opt_name, NULL, (size_t)0);
    return 0;
}

static int Fuzz_urma_create_jfc(void)
{
    (void)urma_create_jfc(NULL, NULL);
    return 0;
}

static int Fuzz_urma_modify_jfc(void)
{
    (void)urma_modify_jfc(NULL, NULL);
    return 0;
}

static int Fuzz_urma_delete_jfc(void)
{
    (void)urma_delete_jfc(NULL);
    return 0;
}

static int Fuzz_urma_alloc_jfc(void)
{
    (void)urma_alloc_jfc(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_set_jfc_opt(void)
{
    (void)urma_set_jfc_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_active_jfc(void)
{
    (void)urma_active_jfc(NULL);
    return 0;
}

static int Fuzz_urma_get_jfc_opt(void)
{
    (void)urma_get_jfc_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_deactive_jfc(void)
{
    (void)urma_deactive_jfc(NULL);
    return 0;
}

static int Fuzz_urma_free_jfc(void)
{
    (void)urma_free_jfc(NULL);
    return 0;
}

static int Fuzz_urma_delete_jfc_batch(void)
{
    (void)urma_delete_jfc_batch(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_create_jfs(void)
{
    (void)urma_create_jfs(NULL, NULL);
    return 0;
}

static int Fuzz_urma_modify_jfs(void)
{
    (void)urma_modify_jfs(NULL, NULL);
    return 0;
}

static int Fuzz_urma_query_jfs(void)
{
    (void)urma_query_jfs(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_delete_jfs(void)
{
    (void)urma_delete_jfs(NULL);
    return 0;
}

static int Fuzz_urma_delete_jfs_batch(void)
{
    (void)urma_delete_jfs_batch(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_flush_jfs(void)
{
    (void)urma_flush_jfs(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_alloc_jfs(void)
{
    (void)urma_alloc_jfs(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_set_jfs_opt(void)
{
    (void)urma_set_jfs_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_active_jfs(void)
{
    (void)urma_active_jfs(NULL);
    return 0;
}

static int Fuzz_urma_get_jfs_opt(void)
{
    (void)urma_get_jfs_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_deactive_jfs(void)
{
    (void)urma_deactive_jfs(NULL);
    return 0;
}

static int Fuzz_urma_free_jfs(void)
{
    (void)urma_free_jfs(NULL);
    return 0;
}

static int Fuzz_urma_create_jfr(void)
{
    (void)urma_create_jfr(NULL, NULL);
    return 0;
}

static int Fuzz_urma_modify_jfr(void)
{
    (void)urma_modify_jfr(NULL, NULL);
    return 0;
}

static int Fuzz_urma_query_jfr(void)
{
    (void)urma_query_jfr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_delete_jfr(void)
{
    (void)urma_delete_jfr(NULL);
    return 0;
}

static int Fuzz_urma_delete_jfr_batch(void)
{
    (void)urma_delete_jfr_batch(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_import_jfr(void)
{
    (void)urma_import_jfr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_import_jfr_ex(void)
{
    (void)urma_import_jfr_ex(NULL, NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_unimport_jfr(void)
{
    (void)urma_unimport_jfr(NULL);
    return 0;
}

static int Fuzz_urma_advise_jfr(void)
{
    (void)urma_advise_jfr(NULL, NULL);
    return 0;
}

static int Fuzz_urma_advise_jfr_async(void)
{
    urma_advise_async_cb_func arg2_cb_fun = {0};

    (void)urma_advise_jfr_async(NULL, NULL, arg2_cb_fun, NULL);
    return 0;
}

static int Fuzz_urma_unadvise_jfr(void)
{
    (void)urma_unadvise_jfr(NULL, NULL);
    return 0;
}

static int Fuzz_urma_alloc_jfr(void)
{
    (void)urma_alloc_jfr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_set_jfr_opt(void)
{
    (void)urma_set_jfr_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_active_jfr(void)
{
    (void)urma_active_jfr(NULL);
    return 0;
}

static int Fuzz_urma_get_jfr_opt(void)
{
    (void)urma_get_jfr_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_deactive_jfr(void)
{
    (void)urma_deactive_jfr(NULL);
    return 0;
}

static int Fuzz_urma_free_jfr(void)
{
    (void)urma_free_jfr(NULL);
    return 0;
}

static int Fuzz_urma_create_jetty(void)
{
    (void)urma_create_jetty(NULL, NULL);
    return 0;
}

static int Fuzz_urma_modify_jetty(void)
{
    (void)urma_modify_jetty(NULL, NULL);
    return 0;
}

static int Fuzz_urma_query_jetty(void)
{
    (void)urma_query_jetty(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_delete_jetty(void)
{
    (void)urma_delete_jetty(NULL);
    return 0;
}

static int Fuzz_urma_delete_jetty_batch(void)
{
    (void)urma_delete_jetty_batch(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_import_jetty(void)
{
    (void)urma_import_jetty(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_import_jetty_ex(void)
{
    (void)urma_import_jetty_ex(NULL, NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_unimport_jetty(void)
{
    (void)urma_unimport_jetty(NULL);
    return 0;
}

static int Fuzz_urma_advise_jetty(void)
{
    (void)urma_advise_jetty(NULL, NULL);
    return 0;
}

static int Fuzz_urma_unadvise_jetty(void)
{
    (void)urma_unadvise_jetty(NULL, NULL);
    return 0;
}

static int Fuzz_urma_bind_jetty(void)
{
    (void)urma_bind_jetty(NULL, NULL);
    return 0;
}

static int Fuzz_urma_bind_jetty_ex(void)
{
    (void)urma_bind_jetty_ex(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_unbind_jetty(void)
{
    (void)urma_unbind_jetty(NULL);
    return 0;
}

static int Fuzz_urma_flush_jetty(void)
{
    (void)urma_flush_jetty(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_get_rjetty(void)
{
    (void)urma_get_rjetty(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_put_rjetty(void)
{
    (void)urma_put_rjetty(NULL);
    return 0;
}

static int Fuzz_urma_import_jetty_async(void)
{
    (void)urma_import_jetty_async(NULL, NULL, NULL, (uint64_t)0, (int)0);
    return 0;
}

static int Fuzz_urma_unimport_jetty_async(void)
{
    (void)urma_unimport_jetty_async(NULL);
    return 0;
}

static int Fuzz_urma_bind_jetty_async(void)
{
    (void)urma_bind_jetty_async(NULL, NULL, NULL, (uint64_t)0, (int)0);
    return 0;
}

static int Fuzz_urma_unbind_jetty_async(void)
{
    (void)urma_unbind_jetty_async(NULL);
    return 0;
}

static int Fuzz_urma_create_notifier(void)
{
    (void)urma_create_notifier(NULL);
    return 0;
}

static int Fuzz_urma_delete_notifier(void)
{
    (void)urma_delete_notifier(NULL);
    return 0;
}

static int Fuzz_urma_alloc_jetty(void)
{
    (void)urma_alloc_jetty(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_set_jetty_opt(void)
{
    (void)urma_set_jetty_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_active_jetty(void)
{
    (void)urma_active_jetty(NULL);
    return 0;
}

static int Fuzz_urma_get_jetty_opt(void)
{
    (void)urma_get_jetty_opt(NULL, (uint64_t)0, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_deactive_jetty(void)
{
    (void)urma_deactive_jetty(NULL);
    return 0;
}

static int Fuzz_urma_free_jetty(void)
{
    (void)urma_free_jetty(NULL);
    return 0;
}

static int Fuzz_urma_wait_notify(void)
{
    (void)urma_wait_notify(NULL, (uint32_t)0, NULL, (int)0);
    return 0;
}

static int Fuzz_urma_ack_notify(void)
{
    (void)urma_ack_notify(NULL, (uint32_t)0, NULL);
    return 0;
}

static int Fuzz_urma_create_jetty_grp(void)
{
    (void)urma_create_jetty_grp(NULL, NULL);
    return 0;
}

static int Fuzz_urma_delete_jetty_grp(void)
{
    (void)urma_delete_jetty_grp(NULL);
    return 0;
}

static int Fuzz_urma_create_jfce(void)
{
    (void)urma_create_jfce(NULL);
    return 0;
}

static int Fuzz_urma_delete_jfce(void)
{
    (void)urma_delete_jfce(NULL);
    return 0;
}

static int Fuzz_urma_get_async_event(void)
{
    (void)urma_get_async_event(NULL, NULL);
    return 0;
}

static int Fuzz_urma_ack_async_event(void)
{
    (void)urma_ack_async_event(NULL);
    return 0;
}

static int Fuzz_urma_alloc_token_id(void)
{
    (void)urma_alloc_token_id(NULL);
    return 0;
}

static int Fuzz_urma_alloc_token_id_ex(void)
{
    urma_token_id_flag_t arg1_flag = {0};

    (void)urma_alloc_token_id_ex(NULL, arg1_flag);
    return 0;
}

static int Fuzz_urma_free_token_id(void)
{
    (void)urma_free_token_id(NULL);
    return 0;
}

static int Fuzz_urma_register_seg(void)
{
    (void)urma_register_seg(NULL, NULL);
    return 0;
}

static int Fuzz_urma_unregister_seg(void)
{
    (void)urma_unregister_seg(NULL);
    return 0;
}

static int Fuzz_urma_import_seg(void)
{
    urma_import_seg_flag_t arg4_flag = {0};

    (void)urma_import_seg(NULL, NULL, NULL, (uint64_t)0, arg4_flag);
    return 0;
}

static int Fuzz_urma_unimport_seg(void)
{
    (void)urma_unimport_seg(NULL);
    return 0;
}

static int Fuzz_urma_get_seg_ctx(void)
{
    (void)urma_get_seg_ctx(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_put_seg_ctx(void)
{
    (void)urma_put_seg_ctx(NULL);
    return 0;
}

static int Fuzz_urma_post_jfs_wr(void)
{
    (void)urma_post_jfs_wr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_post_jfr_wr(void)
{
    (void)urma_post_jfr_wr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_post_jetty_send_wr(void)
{
    (void)urma_post_jetty_send_wr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_post_jetty_recv_wr(void)
{
    (void)urma_post_jetty_recv_wr(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_write(void)
{
    urma_jfs_wr_flag_t arg7_flag = {0};

    (void)urma_write(NULL, NULL, NULL, NULL, (uint64_t)0, (uint64_t)0, (uint32_t)0, arg7_flag, (uint64_t)0);
    return 0;
}

static int Fuzz_urma_read(void)
{
    urma_jfs_wr_flag_t arg7_flag = {0};

    (void)urma_read(NULL, NULL, NULL, NULL, (uint64_t)0, (uint64_t)0, (uint32_t)0, arg7_flag, (uint64_t)0);
    return 0;
}

static int Fuzz_urma_send(void)
{
    urma_jfs_wr_flag_t arg5_flag = {0};

    (void)urma_send(NULL, NULL, NULL, (uint64_t)0, (uint32_t)0, arg5_flag, (uint64_t)0);
    return 0;
}

static int Fuzz_urma_recv(void)
{
    (void)urma_recv(NULL, NULL, (uint64_t)0, (uint32_t)0, (uint64_t)0);
    return 0;
}

static int Fuzz_urma_poll_jfc(void)
{
    (void)urma_poll_jfc(NULL, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_rearm_jfc(void)
{
    (void)urma_rearm_jfc(NULL, false);
    return 0;
}

static int Fuzz_urma_wait_jfc(void)
{
    (void)urma_wait_jfc(NULL, (uint32_t)0, (int)0, NULL);
    return 0;
}

static int Fuzz_urma_ack_jfc(void)
{
    (void)urma_ack_jfc(NULL, NULL, (uint32_t)0);
    return 0;
}

static int Fuzz_urma_get_uasid(void)
{
    (void)urma_get_uasid(NULL);
    return 0;
}

static int Fuzz_urma_user_ctl(void)
{
    (void)urma_user_ctl(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_register_log_func(void)
{
    urma_log_cb_t arg0_func = {0};

    (void)urma_register_log_func(arg0_func);
    return 0;
}

static int Fuzz_urma_register_loc_log_func(void)
{
    urma_loc_log_cb arg0_func = {0};

    (void)urma_register_loc_log_func(arg0_func);
    return 0;
}

static int Fuzz_urma_unregister_log_func(void)
{
    (void)urma_unregister_log_func();
    return 0;
}

static int Fuzz_urma_log_get_level(void)
{
    (void)urma_log_get_level();
    return 0;
}

static int Fuzz_urma_log_set_level(void)
{
    urma_vlog_level_t arg0_level = {0};

    (void)urma_log_set_level(arg0_level);
    return 0;
}

static int Fuzz_urma_log_get_thread_tag(void)
{
    (void)urma_log_get_thread_tag();
    return 0;
}

static int Fuzz_urma_log_set_thread_tag(void)
{
    (void)urma_log_set_thread_tag(NULL);
    return 0;
}

static int Fuzz_urma_get_tpn(void)
{
    (void)urma_get_tpn(NULL);
    return 0;
}

static int Fuzz_urma_get_net_addr_list(void)
{
    (void)urma_get_net_addr_list(NULL, NULL);
    return 0;
}

static int Fuzz_urma_free_net_addr_list(void)
{
    (void)urma_free_net_addr_list(NULL);
    return 0;
}

static int Fuzz_urma_modify_tp(void)
{
    urma_tp_attr_mask_t arg4_mask = {0};

    (void)urma_modify_tp(NULL, (uint32_t)0, NULL, NULL, arg4_mask);
    return 0;
}

static int Fuzz_urma_get_tp_list(void)
{
    (void)urma_get_tp_list(NULL, NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_set_tp_attr(void)
{
    (void)urma_set_tp_attr(NULL, (const uint64_t)0, (const uint8_t)0, (const uint32_t)0, NULL);
    return 0;
}

static int Fuzz_urma_get_tp_attr(void)
{
    (void)urma_get_tp_attr(NULL, (const uint64_t)0, NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_get_eid_by_ip(void)
{
    (void)urma_get_eid_by_ip(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_get_ip_by_eid(void)
{
    (void)urma_get_ip_by_eid(NULL, NULL, NULL);
    return 0;
}

static int Fuzz_urma_get_smac(void)
{
    (void)urma_get_smac(NULL, NULL);
    return 0;
}

static int Fuzz_urma_get_dmac(void)
{
    (void)urma_get_dmac(NULL, NULL, NULL);
    return 0;
}

const fuzz_case_t g_urma_fuzz_cases[] = {
    {"urma_init", Fuzz_urma_init},
    {"urma_uninit", Fuzz_urma_uninit},
    {"urma_get_device_list", Fuzz_urma_get_device_list},
    {"urma_free_device_list", Fuzz_urma_free_device_list},
    {"urma_get_eid_list", Fuzz_urma_get_eid_list},
    {"urma_free_eid_list", Fuzz_urma_free_eid_list},
    {"urma_get_device_by_name", Fuzz_urma_get_device_by_name},
    {"urma_get_device_by_eid", Fuzz_urma_get_device_by_eid},
    {"urma_query_device", Fuzz_urma_query_device},
    {"urma_create_context", Fuzz_urma_create_context},
    {"urma_delete_context", Fuzz_urma_delete_context},
    {"urma_set_context_opt", Fuzz_urma_set_context_opt},
    {"urma_create_jfc", Fuzz_urma_create_jfc},
    {"urma_modify_jfc", Fuzz_urma_modify_jfc},
    {"urma_delete_jfc", Fuzz_urma_delete_jfc},
    {"urma_alloc_jfc", Fuzz_urma_alloc_jfc},
    {"urma_set_jfc_opt", Fuzz_urma_set_jfc_opt},
    {"urma_active_jfc", Fuzz_urma_active_jfc},
    {"urma_get_jfc_opt", Fuzz_urma_get_jfc_opt},
    {"urma_deactive_jfc", Fuzz_urma_deactive_jfc},
    {"urma_free_jfc", Fuzz_urma_free_jfc},
    {"urma_delete_jfc_batch", Fuzz_urma_delete_jfc_batch},
    {"urma_create_jfs", Fuzz_urma_create_jfs},
    {"urma_modify_jfs", Fuzz_urma_modify_jfs},
    {"urma_query_jfs", Fuzz_urma_query_jfs},
    {"urma_delete_jfs", Fuzz_urma_delete_jfs},
    {"urma_delete_jfs_batch", Fuzz_urma_delete_jfs_batch},
    {"urma_flush_jfs", Fuzz_urma_flush_jfs},
    {"urma_alloc_jfs", Fuzz_urma_alloc_jfs},
    {"urma_set_jfs_opt", Fuzz_urma_set_jfs_opt},
    {"urma_active_jfs", Fuzz_urma_active_jfs},
    {"urma_get_jfs_opt", Fuzz_urma_get_jfs_opt},
    {"urma_deactive_jfs", Fuzz_urma_deactive_jfs},
    {"urma_free_jfs", Fuzz_urma_free_jfs},
    {"urma_create_jfr", Fuzz_urma_create_jfr},
    {"urma_modify_jfr", Fuzz_urma_modify_jfr},
    {"urma_query_jfr", Fuzz_urma_query_jfr},
    {"urma_delete_jfr", Fuzz_urma_delete_jfr},
    {"urma_delete_jfr_batch", Fuzz_urma_delete_jfr_batch},
    {"urma_import_jfr", Fuzz_urma_import_jfr},
    {"urma_import_jfr_ex", Fuzz_urma_import_jfr_ex},
    {"urma_unimport_jfr", Fuzz_urma_unimport_jfr},
    {"urma_advise_jfr", Fuzz_urma_advise_jfr},
    {"urma_advise_jfr_async", Fuzz_urma_advise_jfr_async},
    {"urma_unadvise_jfr", Fuzz_urma_unadvise_jfr},
    {"urma_alloc_jfr", Fuzz_urma_alloc_jfr},
    {"urma_set_jfr_opt", Fuzz_urma_set_jfr_opt},
    {"urma_active_jfr", Fuzz_urma_active_jfr},
    {"urma_get_jfr_opt", Fuzz_urma_get_jfr_opt},
    {"urma_deactive_jfr", Fuzz_urma_deactive_jfr},
    {"urma_free_jfr", Fuzz_urma_free_jfr},
    {"urma_create_jetty", Fuzz_urma_create_jetty},
    {"urma_modify_jetty", Fuzz_urma_modify_jetty},
    {"urma_query_jetty", Fuzz_urma_query_jetty},
    {"urma_delete_jetty", Fuzz_urma_delete_jetty},
    {"urma_delete_jetty_batch", Fuzz_urma_delete_jetty_batch},
    {"urma_import_jetty", Fuzz_urma_import_jetty},
    {"urma_import_jetty_ex", Fuzz_urma_import_jetty_ex},
    {"urma_unimport_jetty", Fuzz_urma_unimport_jetty},
    {"urma_advise_jetty", Fuzz_urma_advise_jetty},
    {"urma_unadvise_jetty", Fuzz_urma_unadvise_jetty},
    {"urma_bind_jetty", Fuzz_urma_bind_jetty},
    {"urma_bind_jetty_ex", Fuzz_urma_bind_jetty_ex},
    {"urma_unbind_jetty", Fuzz_urma_unbind_jetty},
    {"urma_flush_jetty", Fuzz_urma_flush_jetty},
    {"urma_get_rjetty", Fuzz_urma_get_rjetty},
    {"urma_put_rjetty", Fuzz_urma_put_rjetty},
    {"urma_import_jetty_async", Fuzz_urma_import_jetty_async},
    {"urma_unimport_jetty_async", Fuzz_urma_unimport_jetty_async},
    {"urma_bind_jetty_async", Fuzz_urma_bind_jetty_async},
    {"urma_unbind_jetty_async", Fuzz_urma_unbind_jetty_async},
    {"urma_create_notifier", Fuzz_urma_create_notifier},
    {"urma_delete_notifier", Fuzz_urma_delete_notifier},
    {"urma_alloc_jetty", Fuzz_urma_alloc_jetty},
    {"urma_set_jetty_opt", Fuzz_urma_set_jetty_opt},
    {"urma_active_jetty", Fuzz_urma_active_jetty},
    {"urma_get_jetty_opt", Fuzz_urma_get_jetty_opt},
    {"urma_deactive_jetty", Fuzz_urma_deactive_jetty},
    {"urma_free_jetty", Fuzz_urma_free_jetty},
    {"urma_wait_notify", Fuzz_urma_wait_notify},
    {"urma_ack_notify", Fuzz_urma_ack_notify},
    {"urma_create_jetty_grp", Fuzz_urma_create_jetty_grp},
    {"urma_delete_jetty_grp", Fuzz_urma_delete_jetty_grp},
    {"urma_create_jfce", Fuzz_urma_create_jfce},
    {"urma_delete_jfce", Fuzz_urma_delete_jfce},
    {"urma_get_async_event", Fuzz_urma_get_async_event},
    {"urma_ack_async_event", Fuzz_urma_ack_async_event},
    {"urma_alloc_token_id", Fuzz_urma_alloc_token_id},
    {"urma_alloc_token_id_ex", Fuzz_urma_alloc_token_id_ex},
    {"urma_free_token_id", Fuzz_urma_free_token_id},
    {"urma_register_seg", Fuzz_urma_register_seg},
    {"urma_unregister_seg", Fuzz_urma_unregister_seg},
    {"urma_import_seg", Fuzz_urma_import_seg},
    {"urma_unimport_seg", Fuzz_urma_unimport_seg},
    {"urma_get_seg_ctx", Fuzz_urma_get_seg_ctx},
    {"urma_put_seg_ctx", Fuzz_urma_put_seg_ctx},
    {"urma_post_jfs_wr", Fuzz_urma_post_jfs_wr},
    {"urma_post_jfr_wr", Fuzz_urma_post_jfr_wr},
    {"urma_post_jetty_send_wr", Fuzz_urma_post_jetty_send_wr},
    {"urma_post_jetty_recv_wr", Fuzz_urma_post_jetty_recv_wr},
    {"urma_write", Fuzz_urma_write},
    {"urma_read", Fuzz_urma_read},
    {"urma_send", Fuzz_urma_send},
    {"urma_recv", Fuzz_urma_recv},
    {"urma_poll_jfc", Fuzz_urma_poll_jfc},
    {"urma_rearm_jfc", Fuzz_urma_rearm_jfc},
    {"urma_wait_jfc", Fuzz_urma_wait_jfc},
    {"urma_ack_jfc", Fuzz_urma_ack_jfc},
    {"urma_get_uasid", Fuzz_urma_get_uasid},
    {"urma_user_ctl", Fuzz_urma_user_ctl},
    {"urma_register_log_func", Fuzz_urma_register_log_func},
    {"urma_register_loc_log_func", Fuzz_urma_register_loc_log_func},
    {"urma_unregister_log_func", Fuzz_urma_unregister_log_func},
    {"urma_log_get_level", Fuzz_urma_log_get_level},
    {"urma_log_set_level", Fuzz_urma_log_set_level},
    {"urma_log_get_thread_tag", Fuzz_urma_log_get_thread_tag},
    {"urma_log_set_thread_tag", Fuzz_urma_log_set_thread_tag},
    {"urma_get_tpn", Fuzz_urma_get_tpn},
    {"urma_get_net_addr_list", Fuzz_urma_get_net_addr_list},
    {"urma_free_net_addr_list", Fuzz_urma_free_net_addr_list},
    {"urma_modify_tp", Fuzz_urma_modify_tp},
    {"urma_get_tp_list", Fuzz_urma_get_tp_list},
    {"urma_set_tp_attr", Fuzz_urma_set_tp_attr},
    {"urma_get_tp_attr", Fuzz_urma_get_tp_attr},
    {"urma_get_eid_by_ip", Fuzz_urma_get_eid_by_ip},
    {"urma_get_ip_by_eid", Fuzz_urma_get_ip_by_eid},
    {"urma_get_smac", Fuzz_urma_get_smac},
    {"urma_get_dmac", Fuzz_urma_get_dmac},
};

size_t GetUrmaFuzzCaseCount(void)
{
    return sizeof(g_urma_fuzz_cases) / sizeof(g_urma_fuzz_cases[0]);
}

#ifdef URMA_LIBFUZZER
static size_t SelectUrmaFuzzCase(const uint8_t *data, size_t size)
{
    size_t i;
    size_t value = 0;
    bool has_digit = false;

    for (i = 0; i < size; ++i) {
        if (data[i] >= '0' && data[i] <= '9') {
            has_digit = true;
            value = (value * 10) + (size_t)(data[i] - '0');
        } else if (!has_digit) {
            value = (value * 131) + data[i];
        }
    }

    return value % GetUrmaFuzzCaseCount();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t index;

    if (size == 0) {
        return 0;
    }

    index = SelectUrmaFuzzCase(data, size);
    (void)g_urma_fuzz_cases[index].entry();
    return 0;
}
#else
int main(void)
{
    size_t i;

    for (i = 0; i < GetUrmaFuzzCaseCount(); ++i) {
        if (RunFuzzCase(&g_urma_fuzz_cases[i]) != 0) {
            return 1; /* LCOV_EXCL_LINE */
        }
    }

    return 0;
}
#endif
