/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 * Description: liburma main file
 * Author: Yan Fangfang, Qian Guoxin
 * Create: 2021-07-13
 * Note:
 * History: 2021-07-13
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>

#include "urma_device.h"
#include "urma_log.h"
#include "urma_private.h"
#include "urma_provider.h"
#include "urma_types.h"

#if defined(__ANDROID__) || defined(__OHOS__)
#define LIBURMA_DIR "/system/lib64/urma"
#else
#define LIBURMA_DIR "/usr/lib64/urma"
#endif
#define URMA_MAX_LIB_PATH 256

static struct ub_list g_driver_list = UB_LIST_INITIALIZER(&g_driver_list);
static struct ub_list g_so_list = UB_LIST_INITIALIZER(&g_so_list);
static struct ub_list g_dev_list = UB_LIST_INITIALIZER(&g_dev_list);
static uint32_t g_uasid;
static pthread_spinlock_t g_dev_list_lock;
static atomic_uint g_init_flag;

typedef struct urma_so {
    char path[URMA_MAX_LIB_PATH];
    void *dl;            /* Handle returned by dlopen so */
    struct ub_list node; /* Add to so list */
} urma_so_t;

static void urma_close_provider(void *handler, const char *file)
{
    int ret;

    if (handler != NULL) {
        ret = dlclose(handler);
        if (ret == 0) {
            URMA_LOG_INFO("%s is closed.\n", file);
        } else {
            URMA_LOG_ERR("%s close failed, err: %s.\n", file, dlerror());
        }
    }
}

#if !defined(__OHOS__) && !defined(__OH__) && !defined(__ANDROID__)
static int urma_open_provider(const char file[URMA_MAX_LIB_PATH])
{
    int ret;
    char *canonicalized_path = NULL;

    ret = access(file, F_OK | R_OK | X_OK); // Determine permission: exist & read & execute
    if (ret != 0) {
        URMA_LOG_ERR("%s doesn't exist or doesn't have permission.\n", file);
        return -1;
    }

    /* Resolve symbols only as the code that references them is executed.
       If the symbol is never referenced, then it is never resolved. */
    canonicalized_path = realpath(file, NULL);
    if (canonicalized_path == NULL) {
        URMA_LOG_ERR("realpath failed.\n");
        return -1;
    }

    urma_so_t *so = calloc(1, sizeof(urma_so_t));
    if (so == NULL) {
        free(canonicalized_path);
        return -ENOMEM;
    }
    (void)strncpy(so->path, file, URMA_MAX_LIB_PATH);
    so->dl = dlopen(canonicalized_path, RTLD_NOW);
    if (so->dl == NULL) {
        URMA_LOG_ERR("%s open failed, err: %s.\n", canonicalized_path, dlerror());
        free(so);
        free(canonicalized_path);
        return -1;
    }

    URMA_LOG_INFO("%s open succeed.\n", canonicalized_path);
    free(canonicalized_path);
    ub_list_push_back(&g_so_list, &so->node);
    return 0;
}
#endif

int urma_register_provider_ops(urma_provider_ops_t *provider_ops)
{
    if (provider_ops == NULL || provider_ops->name == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }
    urma_driver_t *driver = calloc(1, sizeof(urma_driver_t));
    if (driver == NULL) {
        return -ENOMEM;
    }
    driver->ops = provider_ops;
    ub_list_push_back(&g_driver_list, &driver->node);
    URMA_LOG_INFO("%s ops register succeed.\n", provider_ops->name);
    return 0;
}

int urma_unregister_provider_ops(urma_provider_ops_t *provider_ops)
{
    if (provider_ops == NULL || provider_ops->name == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    urma_driver_t *driver, *next;
    UB_LIST_FOR_EACH_SAFE (driver, next, node, &g_driver_list) {
        if (driver->ops == provider_ops) {
            ub_list_remove(&driver->node);
            free(driver);
            break;
        }
    }
    URMA_LOG_INFO("%s ops unregister succeed.\n", provider_ops->name);
    return 0;
}

#if !defined(__OHOS__) && !defined(__OH__) && !defined(__ANDROID__)
static bool urma_validate_driver(struct dirent *dent)
{
    size_t len = strnlen(dent->d_name, NAME_MAX + 1);
    if (len > NAME_MAX) {
        URMA_LOG_ERR("Invalid driver name length.\n");
        return false;
    }

    const char *driver_prefix = "liburma";
    if (dent->d_type == DT_LNK || dent->d_type == DT_REG) {
        if (len < strlen(".so") || strncmp(dent->d_name, driver_prefix, strlen(driver_prefix)) != 0) {
            URMA_LOG_INFO("dent_name: %s is not valid\n", dent->d_name);
            return false;
        }
        return true;
    }
    return false;
}

static int urma_open_drivers(void)
{
    Dl_info info;
    int ret = dladdr((void *)&urma_open_drivers, &info);
    if (ret == 0) {
        URMA_LOG_ERR("Failed to get dl addr: %s\n", dlerror());
        return -1;
    }
    if (info.dli_fname != NULL) {
        URMA_LOG_INFO("dl_addr: %s\n", info.dli_fname);
    }

    char dl_dir[URMA_MAX_LIB_PATH] = {0};
    if (snprintf(dl_dir, URMA_MAX_LIB_PATH, "%s", info.dli_fname) <= 0) {
        URMA_LOG_ERR("Failed to prepare dli_fname.\n");
        return -1;
    }
    char *last_char = strrchr(dl_dir, '/');
    if (last_char == NULL) {
        URMA_LOG_ERR("strrchr %s failed, errno: %d\n", dl_dir, errno);
        return -1;
    }
    *last_char = 0;
    strcat(dl_dir, "/urma");
    DIR *dir = opendir(dl_dir);
    if (dir == NULL) {
        URMA_LOG_ERR("Failed to open liburma dir %s\n", dl_dir);
        return -1;
    }

    int n_loaded_drivers = 0;
    struct dirent *dent;
    char path[URMA_MAX_LIB_PATH] = {0};

    while ((dent = readdir(dir)) != NULL) {
        if (urma_validate_driver(dent) == false) {
            continue;
        }
        if (snprintf(path, URMA_MAX_LIB_PATH - 1, "%s/%s", dl_dir, dent->d_name) <= 0) {
            URMA_LOG_ERR("snprintf_s %s failed\n", dent->d_name);
            continue;
        }
        if (urma_open_provider(path) != 0) {
            URMA_LOG_ERR("Failed to open provider %s\n", path);
            continue;
        }
        n_loaded_drivers++;
    }
    (void)closedir(dir);
    return n_loaded_drivers;
}
#endif

urma_status_t urma_init(urma_init_attr_t *conf)
{
    urma_getenv_log_level();

    /* g_init_flag is initialized as 0 */
    if (atomic_load(&g_init_flag) > 0) {
        URMA_LOG_ERR("urma_init has been called before.\n");
        return URMA_EEXIST;
    }
#if !defined(__OHOS__) && !defined(__OH__) && !defined(__ANDROID__)
    /* TODONEXT: call ubcore to allocate uasid */
    if (urma_open_drivers() <= 0) {
        URMA_LOG_ERR("None of the providers registered.\n");
        /* we can continue on android platform */
#if !defined(__ANDROID__) && !defined(SO_LINKED)
        return URMA_FAIL;
#endif
    }
#endif

    (void)pthread_spin_init(&g_dev_list_lock, PTHREAD_PROCESS_PRIVATE);
    urma_driver_t *driver, *next;
    UB_LIST_FOR_EACH_SAFE (driver, next, node, &g_driver_list) {
        if (driver->ops->init == NULL || driver->ops->init(conf) != URMA_SUCCESS) {
            URMA_LOG_WARN("Provider init failed %s", driver->ops->name);
            ub_list_remove(&driver->node);
            free(driver);
        }
    }
    (void)pthread_spin_lock(&g_dev_list_lock);
#if !defined(__OHOS__) && !defined(__OH__) && !defined(__ANDROID__)
    (void)urma_discover_devices(&g_dev_list, &g_driver_list);
#endif
    (void)pthread_spin_unlock(&g_dev_list_lock);

    atomic_fetch_add(&g_init_flag, 1);
    return URMA_SUCCESS;
}

urma_status_t urma_uninit(void)
{
    urma_status_t ret = URMA_SUCCESS;
    if (atomic_load(&g_init_flag) == 0) {
        URMA_LOG_WARN("urma has not been initialized.\n");
        return ret;
    }

    urma_driver_t *driver;
    UB_LIST_FOR_EACH (driver, node, &g_driver_list) {
        if (driver->ops->uninit == NULL || driver->ops->uninit() != URMA_SUCCESS) {
            URMA_LOG_WARN("Provider uninit failed %s\n", driver->ops->name);
            ret = URMA_FAIL;
        }
    }
    (void)pthread_spin_lock(&g_dev_list_lock);
    urma_free_devices(&g_dev_list);
    (void)pthread_spin_unlock(&g_dev_list_lock);
    (void)pthread_spin_destroy(&g_dev_list_lock);
    /* unload urma so */
    urma_so_t *so, *next;
    UB_LIST_FOR_EACH_SAFE (so, next, node, &g_so_list) {
        urma_close_provider(so->dl, so->path);
        ub_list_remove(&so->node);
        free(so);
    }

    atomic_fetch_sub(&g_init_flag, 1);
    return ret;
}

static urma_device_t **get_urma_device_list(int *num_devices)
{
    urma_device_t **device_list;
    device_list = calloc(1, (uint64_t)(*num_devices) * sizeof(urma_device_t *));
    if (device_list == NULL) {
        errno = ENOMEM;
        goto out;
    }

    int tmp_num = 0;
    urma_sysfs_dev_t *sysfs_dev;
    UB_LIST_FOR_EACH (sysfs_dev, node, &g_dev_list) {
        device_list[tmp_num] = sysfs_dev->urma_device;
        tmp_num++;
    }
    if (tmp_num == 0 || tmp_num != *num_devices) {
        errno = ENOEXEC;
        goto free_device_list;
    }
    return device_list;

free_device_list:
    free(device_list);
out:
    *num_devices = 0;
    return NULL;
}

urma_device_t **urma_get_device_list(int *num_devices)
{
    if (num_devices == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    (void)pthread_spin_lock(&g_dev_list_lock);
#if !defined(__OHOS__) && !defined(__OH__) && !defined(__ANDROID__)
    (void)urma_discover_devices(&g_dev_list, &g_driver_list);
#endif
    *num_devices = (int)ub_list_size(&g_dev_list);
    if (*num_devices == 0) {
        (void)pthread_spin_unlock(&g_dev_list_lock);
        errno = ENODEV;
        return NULL;
    }

    urma_device_t **device_list = get_urma_device_list(num_devices);
    (void)pthread_spin_unlock(&g_dev_list_lock);
    return device_list;
}

void urma_free_device_list(urma_device_t **device_list)
{
    if (device_list == NULL) {
        return;
    }
    free(device_list);
    device_list = NULL;
    return;
}

urma_eid_info_t *urma_get_eid_list(urma_device_t *dev, uint32_t *cnt)
{
    if (dev == NULL || dev->sysfs_dev == NULL || cnt == NULL) {
        URMA_LOG_WARN("invalid parameter with null_ptr.\n");
        errno = EINVAL;
        return NULL;
    }

    uint32_t max_eid_cnt = dev->sysfs_dev->dev_attr.dev_cap.max_eid_cnt;
    if (max_eid_cnt == 0) {
        URMA_LOG_ERR("max eid cnt %u is err", max_eid_cnt);
        errno = EINVAL;
        return NULL;
    }

    urma_eid_info_t *eid_list;

    eid_list = calloc(1, max_eid_cnt * sizeof(urma_eid_info_t));
    if (eid_list == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    *cnt = urma_read_eid_list(dev, eid_list, max_eid_cnt);
    if (*cnt == 0) {
        free(eid_list);
        errno = EIO;
        return NULL;
    }

    return eid_list;
}

void urma_free_eid_list(urma_eid_info_t *eid_list)
{
    if (eid_list != NULL) {
        free(eid_list);
    }
}

urma_status_t urma_query_device(urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    if (dev == NULL || dev->sysfs_dev == NULL || dev_attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return URMA_EINVAL;
    }

    urma_update_port_attr(dev->sysfs_dev);
    (void)memcpy(dev_attr, &dev->sysfs_dev->dev_attr, sizeof(urma_device_attr_t));

    return URMA_SUCCESS;
}

urma_device_t *urma_get_device_by_name(char *dev_name)
{
    if (dev_name == NULL || strnlen(dev_name, URMA_MAX_NAME) >= URMA_MAX_NAME) {
        URMA_LOG_ERR("Invalid parameter.\n");
        errno = EINVAL;
        return NULL;
    }

    int device_num = 0;
    urma_device_t **device_list = urma_get_device_list(&device_num);
    if (device_list == NULL || device_num == 0) {
        URMA_LOG_ERR("urma get device list failed, device_num: %d.\n", device_num);
        return NULL;
    }

    urma_device_t *urma_dev = NULL;
    for (int i = 0; i < device_num; i++) {
        if (strcmp(device_list[i]->name, dev_name) == 0) {
            urma_dev = device_list[i];
            break;
        }
    }
    for (int i = 0; urma_dev == NULL && i < device_num; i++) {
        URMA_LOG_ERR("device list name:%s does not match dev_name: %s.\n", device_list[i]->name, dev_name);
        if (i == device_num - 1) {
            errno = ENODEV;
        }
    }
    urma_free_device_list(device_list);
    return urma_dev;
}

urma_device_t *urma_get_device_by_eid(urma_eid_t eid, urma_transport_type_t type)
{
    int device_num = 0;
    urma_eid_info_t *eid_list;
    uint32_t cnt = 0;

    urma_device_t **device_list = urma_get_device_list(&device_num);
    if (device_list == NULL || device_num == 0) {
        URMA_LOG_ERR("urma get device list failed!\n");
        return NULL;
    }

    urma_device_t *urma_dev = NULL;
    for (int i = 0; i < device_num; i++) {
        if (device_list[i]->type != type) {
            continue;
        }
        eid_list = urma_get_eid_list(device_list[i], &cnt);
        for (uint32_t j = 0; eid_list != NULL && j < cnt; j++) {
            if (memcmp(&eid_list[j].eid, &eid, sizeof(urma_eid_t)) == 0) {
                urma_dev = device_list[i];
                urma_free_eid_list(eid_list);
                urma_free_device_list(device_list);
                return urma_dev;
            }
        }
        urma_free_eid_list(eid_list);
    }
    urma_free_device_list(device_list);
    errno = ENODEV;
    return urma_dev;
}

int urma_open_cdev(char *path)
{
    char *file_path = NULL;
    int fd;

    file_path = realpath(path, NULL);
    if (file_path == NULL) {
        URMA_LOG_ERR("file_path:%s is not standardize.\n", path);
        return -1;
    }
    fd = open(file_path, O_RDWR);
    free(file_path);
    return fd;
}

int urma_query_eid(urma_device_t *dev, uint32_t eid_index, urma_eid_t *eid)
{
    return urma_read_eid_with_index(dev->sysfs_dev, eid_index, eid);
}

urma_context_t *urma_create_context(urma_device_t *dev, uint32_t eid_index)
{
    if (dev == NULL || dev->ops == NULL || dev->ops->create_context == NULL) {
        URMA_LOG_ERR("Failed to find device by eid.\n");
        errno = EINVAL;
        return NULL;
    }

    urma_eid_t eid;
    (void)memset(&eid, 0, sizeof(urma_eid_t));
    int dev_fd = -1;
    if ((dev->sysfs_dev->flag & URMA_SYSFS_DEV_FLAG_DRIVER_CREATED) == 0) {
        // The sysfs_dev was not created by driver. Then query its eid.
        if (urma_query_eid(dev, eid_index, &eid) != 0) {
            URMA_LOG_ERR("Failed to query eid.\n");
            errno = EIO;
            return NULL;
        }
        dev_fd = urma_open_cdev(dev->path);
        if (dev_fd < 0) {
            URMA_LOG_ERR("Failed to open urma cdev with path %s\n", dev->path);
            errno = EIO;
            return NULL;
        }
    }

    urma_context_t *ctx = dev->ops->create_context(dev, eid_index, dev_fd);
    if (ctx == NULL) {
        URMA_LOG_ERR("Failed to create urma context.\n");
        if (dev_fd >= 0) {
            (void)close(dev_fd);
        }
        return NULL;
    }
    /* Save dev_fd in the context, in case that driver did not do this */
    ctx->dev_fd = dev_fd;
    ctx->eid_index = eid_index;
    ctx->eid = eid;
    atomic_init(&ctx->ref.atomic_cnt, 1);
    ctx->aggr_mode = URMA_AGGR_MODE_STANDALONE;

    return ctx;
}

urma_status_t urma_delete_context(urma_context_t *ctx)
{
    URMA_LOG_INFO("urma delete context start.\n");
    if (ctx == NULL || ctx->dev == NULL || ctx->dev->ops == NULL || ctx->dev->ops->delete_context == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    uint64_t atomic_cnt = (uint64_t)atomic_load(&ctx->ref.atomic_cnt);
    if (atomic_cnt > 1) {
        URMA_LOG_WARN("already in use, atomic_cnt: %lu.\n", atomic_cnt);
        return URMA_EAGAIN;
    }

    int dev_fd = ctx->dev_fd;
    urma_status_t ret = ctx->dev->ops->delete_context(ctx);
    if (ret == URMA_SUCCESS && dev_fd >= 0) {
        (void)close(dev_fd);
    } else {
        URMA_LOG_WARN("Delete context error, fd: %d not closed, ret: %d.\n", dev_fd, ret);
    }

    URMA_LOG_INFO("urma delete context end.\n");
    return ret;
}

urma_status_t urma_set_context_opt(urma_context_t *ctx, urma_opt_name_t opt_name, const void *opt_value, size_t opt_len)
{
    if (ctx == NULL || ctx->dev == NULL || ctx->dev->ops == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    switch (opt_name) {
        case URMA_OPT_AGGR_MODE:
            if (opt_len != sizeof(urma_context_aggr_mode_t)) {
                URMA_LOG_ERR("Invalid option value len.\n");
                return URMA_EINVAL;
            }
            if (strcmp(ctx->dev->ops->name, "ub_agg") != 0) {
                URMA_LOG_ERR("Cannot set aggregated mode for non-aggregated device.\n");
                return URMA_EINVAL;
            }
            const uint32_t URMA_USER_CTL_BOND_SET_AGGR_MODE = 5;
            urma_user_ctl_in_t in = {
                .opcode = URMA_USER_CTL_BOND_SET_AGGR_MODE,
                .addr = (uint64_t)opt_value,
                .len = opt_len,
            };
            urma_user_ctl_out_t out = {0};
            return urma_user_ctl(ctx, &in, &out);
        default:
            URMA_LOG_ERR("Invalid option name.\n");
            return URMA_EINVAL;
    }
}

/* Temporarily use uasid allocated by provider */
urma_status_t urma_get_uasid(uint32_t *uasid)
{
    if (uasid == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_driver_t *driver;
    UB_LIST_FOR_EACH (driver, node, &g_driver_list) {
        if (driver->ops->get_uasid == NULL) {
            continue;
        }
        if (driver->ops->get_uasid(&g_uasid) == URMA_SUCCESS) {
            *uasid = g_uasid;
            return URMA_SUCCESS;
        }
    }
    return URMA_FAIL;
}

int urma_register_sysfs_dev(struct urma_sysfs_dev *dev)
{
    if (dev == NULL) {
        URMA_LOG_DEBUG("Register device failed. Invalid input.\n");
        return -1;
    }
    (void)pthread_spin_lock(&g_dev_list_lock);
    if (urma_find_dev_by_name(&g_dev_list, dev->dev_name) != NULL) {
        (void)pthread_spin_unlock(&g_dev_list_lock);
        URMA_LOG_DEBUG("Register device failed. %s device already existed.\n", dev->dev_name);
        return -1;
    }
    if (!urma_match_driver(dev, &g_driver_list)) {
        (void)pthread_spin_unlock(&g_dev_list_lock);
        URMA_LOG_ERR("Register device failed. Failed to match driver for device %s.\n", dev->dev_name);
        return -1;
    }
    dev->urma_device->ops = dev->driver->ops;
    ub_list_insert_after(&g_dev_list, &dev->node);
    (void)pthread_spin_unlock(&g_dev_list_lock);
    URMA_LOG_DEBUG("Success register the %s device.\n", dev->dev_name);
    return 0;
}

static __attribute__((constructor)) void liburma_init(void)
{
#if !defined(__OHOS__) && !defined(__OH__) && !defined(__ANDROID__)
    urma_discover_sysfs_path();
#endif
    syslog(LOG_INFO, "LogTag_URMA|%s[%d]|Start to init liburma.\n", __func__, __LINE__);
    return;
}

static __attribute__((destructor)) void liburma_uninit(void)
{
    syslog(LOG_INFO, "LogTag_URMA|%s[%d]|Finish to uninit liburma.\n", __func__, __LINE__);
    return;
}
