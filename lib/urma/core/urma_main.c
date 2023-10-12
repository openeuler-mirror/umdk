/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: liburma main file
 * Author: Yan Fangfang, Qian Guoxin
 * Create: 2021-07-13
 * Note:
 * History: 2021-07-13
 */

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>

#include "urma_ex_api.h"
#include "urma_log.h"
#include "urma_types.h"
#include "urma_provider.h"
#include "urma_private.h"
#include "urma_provider.h"
#include "urma_device.h"

#define LIBURMA_DIR "/usr/lib64/urma"
#define URMA_DRIVER_NAME_PREFIX "liburma"
#define URMA_MAX_LIB_PATH 256

static struct ub_list g_driver_list = UB_LIST_INITIALIZER(&g_driver_list);
static struct ub_list g_so_list = UB_LIST_INITIALIZER(&g_so_list);
static struct ub_list g_dev_list = UB_LIST_INITIALIZER(&g_dev_list);
static uint32_t g_uasid;
static pthread_spinlock_t g_dev_list_lock;
static atomic_uint g_init_flag;

typedef struct urma_so {
    char path[URMA_MAX_LIB_PATH];
    void *dl; /* Handle returned by dlopen so */
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

static int urma_open_provider(const char *file)
{
    int ret;
    char *canonicalized_path = NULL;

    ret = access(file, F_OK | R_OK | X_OK);  // Determine permission: exist & read & execute
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
        URMA_LOG_ERR("calloc failed");
        return -1;
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

int urma_register_provider_ops(urma_provider_ops_t *provider_ops)
{
    if (provider_ops == NULL || provider_ops->name == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }
    urma_driver_t *driver = calloc(1, sizeof(urma_driver_t));
    if (driver == NULL) {
        return -1;
    }
    driver->ops = provider_ops;
    ub_list_push_back(&g_driver_list, &driver->node);
    URMA_LOG_INFO("%s ops register succeed.\n", provider_ops->name);
    return 0;
}

int urma_unregister_provider_ops(const urma_provider_ops_t *provider_ops)
{
    if (provider_ops == NULL || provider_ops->name == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return -1;
    }

    urma_driver_t *driver, *next;
    UB_LIST_FOR_EACH_SAFE(driver, next, node, &g_driver_list) {
        if (driver->ops == provider_ops) {
            ub_list_remove(&driver->node);
            free(driver);
            break;
        }
    }
    URMA_LOG_INFO("%s ops unregister succeed.\n", provider_ops->name);
    return 0;
}

static bool urma_validate_driver(struct dirent *dent)
{
    size_t len = strlen(dent->d_name);

    if (dent->d_type == DT_LNK || dent->d_type == DT_REG) {
        if (len < strlen(".so") || strncmp(dent->d_name + len - strlen(".so"), ".so", strlen(".so")) != 0 ||
            strncmp(dent->d_name, URMA_DRIVER_NAME_PREFIX, strlen(URMA_DRIVER_NAME_PREFIX)) != 0) {
            URMA_LOG_INFO("dent_name: %s is not valid\n", dent->d_name);
            return false;
        }
        return true;
    }
    return false;
}

static int urma_open_drivers(void)
{
    DIR *dir = opendir(LIBURMA_DIR);
    if (dir == NULL) {
        URMA_LOG_ERR("Failed to open liburma dir %s", LIBURMA_DIR);
        return -1;
    }

    int n_loaded_drivers = 0;
    struct dirent *dent;
    char path[URMA_MAX_LIB_PATH] = {0};

    while ((dent = readdir(dir)) != NULL) {
        if (urma_validate_driver(dent) == false) {
            continue;
        }
        if (snprintf(path, URMA_MAX_LIB_PATH - 1, "%s/%s", LIBURMA_DIR, dent->d_name) == -1) {
            URMA_LOG_ERR("snprintf %s failed", dent->d_name);
            continue;
        }
        if (urma_open_provider(path) != 0) {
            URMA_LOG_ERR("Failed to open provider %s\n", path);
        }
        n_loaded_drivers++;
    }
    (void)closedir(dir);
    return n_loaded_drivers;
}

urma_status_t urma_init(const urma_init_attr_t *conf)
{
    /* g_init_flag is initialized as 0 */
    if (atomic_load(&g_init_flag) > 0) {
        URMA_LOG_ERR("urma_init has been called before.\n");
        return URMA_FAIL;
    }
    /* TODONEXT: call ubcore to allocate uasid */
    if (urma_open_drivers() <= 0) {
        URMA_LOG_ERR("None of the providers registered.\n");
        return URMA_FAIL;
    }

    urma_driver_t *driver, *next;
    UB_LIST_FOR_EACH_SAFE(driver, next, node, &g_driver_list) {
        if (driver->ops->init == NULL || driver->ops->init(conf) != URMA_SUCCESS) {
            URMA_LOG_WARN("Provider init failed %s", driver->ops->name);
            ub_list_remove(&driver->node);
            free(driver);
        }
    }
    (void)pthread_spin_init(&g_dev_list_lock, PTHREAD_PROCESS_PRIVATE);
    (void)pthread_spin_lock(&g_dev_list_lock);
    (void)urma_discover_devices(&g_dev_list, &g_driver_list);
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
    UB_LIST_FOR_EACH(driver, node, &g_driver_list) {
        if (driver->ops->uninit == NULL || driver->ops->uninit() != URMA_SUCCESS) {
            URMA_LOG_WARN("Provider uninit failed %s", driver->ops->name);
            ret = URMA_FAIL;
        }
    }
    (void)pthread_spin_lock(&g_dev_list_lock);
    urma_free_devices(&g_dev_list);
    (void)pthread_spin_unlock(&g_dev_list_lock);
    (void)pthread_spin_destroy(&g_dev_list_lock);
    /* unload urma so */
    urma_so_t *so, *next;
    UB_LIST_FOR_EACH_SAFE(so, next, node, &g_so_list) {
        urma_close_provider(so->dl, so->path);
        ub_list_remove(&so->node);
        free(so);
    }

    atomic_fetch_sub(&g_init_flag, 1);
    return ret;
}

urma_status_t urma_ib_set_transport_mode(urma_context_t *ctx, urma_ib_tm_t mode)
{
    if ((ctx == NULL) || (ctx->ops == NULL)) {
        URMA_LOG_ERR("parameter invalid in urma_ib_set_transport_mode.\n");
        return URMA_EINVAL;
    }

    if (strcmp(ctx->dev->ops->name, "provider_ib") != 0) {
        URMA_LOG_WARN("Only provider_ib can configure ib_tm.\n");
        return URMA_SUCCESS;
    }

    urma_set_tm_ctx_t input_ctx;
    input_ctx.ctx = ctx;
    input_ctx.tm_mode = mode;
    urma_user_ctl_in_t in = {
        .addr = (uint64_t)&input_ctx,
        .len = sizeof(input_ctx),
        .opcode = URMA_USER_CTL_SET_CTX_TM
    };
    if (ctx->ops->user_ctl == NULL) {
        URMA_LOG_ERR("Invalid parameter with user_ctl null_ptr.\n");
        return URMA_FAIL;
    }
    int ret = ctx->ops->user_ctl(ctx, &in, NULL);
    if ((urma_status_t)ret != URMA_SUCCESS && (urma_status_t)ret != URMA_ENOPERM) {
        URMA_LOG_ERR("Failed to excecute user_ctl, ret: %d.\n", ret);
        return URMA_FAIL;
    }
    return (urma_status_t)ret;
}

static urma_device_t **get_urma_device_list(int *num_devices)
{
    urma_device_t **device_list;
    device_list = calloc(1, (uint64_t)(*num_devices) * sizeof(urma_device_t *));
    if (device_list == NULL) {
        URMA_LOG_ERR("Failed to allocate memory.\n");
        goto out;
    }

    int tmp_num = 0;
    urma_sysfs_dev_t *sysfs_dev;
    UB_LIST_FOR_EACH(sysfs_dev, node, &g_dev_list) {
        device_list[tmp_num] = sysfs_dev->urma_device;
        tmp_num++;
    }
    if (tmp_num == 0 || tmp_num != *num_devices) {
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
        return NULL;
    }

    (void)pthread_spin_lock(&g_dev_list_lock);
    *num_devices = (int)urma_discover_devices(&g_dev_list, &g_driver_list);
    if (*num_devices == 0) {
        (void)pthread_spin_unlock(&g_dev_list_lock);
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

urma_status_t urma_query_device(const urma_device_t *dev, urma_device_attr_t *dev_attr)
{
    if (dev == NULL || dev->sysfs_dev == NULL || dev_attr == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_update_port_attr(dev->sysfs_dev);
    (void)memcpy(dev_attr, &dev->sysfs_dev->dev_attr, sizeof(urma_device_attr_t));

    return URMA_SUCCESS;
}

urma_device_t *urma_get_device_by_name(const char *dev_name)
{
    if (dev_name == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
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
    }
    urma_free_device_list(device_list);
    return urma_dev;
}

urma_device_t *urma_get_device_by_eid(urma_eid_t eid, urma_transport_type_t type)
{
    int device_num = 0;
    urma_device_t **device_list = urma_get_device_list(&device_num);
    if (device_list == NULL || device_num == 0) {
        URMA_LOG_ERR("urma get device list failed!\n");
        return NULL;
    }

    urma_device_t *urma_dev = NULL;
    for (int i = 0; i < device_num; i++) {
        if (memcmp(&device_list[i]->eid, &eid, sizeof(urma_eid_t)) == 0 && device_list[i]->type == type) {
            urma_dev = device_list[i];
            break;
        }
    }
    urma_free_device_list(device_list);
    return urma_dev;
}

static int urma_open_cdev(const char *path)
{
    char *file_path = NULL;
    int fd = -1;

    file_path = realpath(path, NULL);
    if (file_path == NULL) {
        URMA_LOG_ERR("file_path:%s is not standardize.\n", path);
        return -1;
    }
    fd = open(file_path, O_RDWR);
    free(file_path);
    return fd;
}

urma_context_t *urma_create_context(urma_device_t *dev)
{
    if (dev == NULL || dev->ops == NULL || dev->ops->create_context == NULL) {
        URMA_LOG_ERR("Failed to find device by eid.\n");
        return NULL;
    }

    int dev_fd = urma_open_cdev(dev->path);
    if (dev_fd < 0 && dev->type != URMA_TRANSPORT_IP) {
        URMA_LOG_ERR("Failed to open urma cdev with path %s\n", dev->path);
        return NULL;
    }

    urma_context_t *ctx = dev->ops->create_context(dev, dev_fd, g_uasid);
    if (ctx == NULL) {
        URMA_LOG_ERR("Failed to create urma context.\n");
        if (dev_fd >= 0) {
            (void)close(dev_fd);
        }
        return NULL;
    }
    /* Save dev_fd in the context, in case that driver did not do this */
    ctx->dev_fd = dev_fd;
    atomic_init(&ctx->ref->atomic_cnt, 1);

    return ctx;
}

urma_status_t urma_delete_context(urma_context_t *ctx)
{
    if (ctx == NULL || ctx->dev == NULL || ctx->dev->ops == NULL ||
        ctx->dev->ops->delete_context == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    if (atomic_load(&ctx->ref->atomic_cnt) > 1) {
        URMA_LOG_ERR("already in use.\n");
        return URMA_EINVAL;
    }

    int dev_fd = ctx->dev_fd;
    urma_status_t ret = ctx->dev->ops->delete_context(ctx);
    if (ret == URMA_SUCCESS && dev_fd >= 0) {
        (void)close(dev_fd);
    }

    return ret;
}

/* Temporarily use uasid allocated by IB provider */
urma_status_t urma_get_uasid(uint32_t *uasid)
{
    if (uasid == NULL) {
        URMA_LOG_ERR("Invalid parameter.\n");
        return URMA_EINVAL;
    }

    urma_driver_t *driver;
    UB_LIST_FOR_EACH(driver, node, &g_driver_list) {
        if (driver->ops->get_uasid == NULL) {
            continue;
        }
        if (driver->ops->get_uasid(&g_uasid) == URMA_SUCCESS) {
            break;
        }
    }
    *uasid = g_uasid;
    return URMA_SUCCESS;
}

static __attribute__((constructor)) void liburma_init(void)
{
    return;
}

static __attribute__((destructor)) void liburma_uninit(void)
{
    return;
}
