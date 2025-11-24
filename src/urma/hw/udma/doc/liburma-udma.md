# UDMA Userspace Driver (u-udma)

## Introduction

**UDMA** (UnifiedBus Direct Memory Access) is a hardware I/O device that provides direct memory access capabilities.

This document describes the functionalities along with code implementation of the UDMA userspace driver **u-udma** (`liburma-udma.so`). Please refer to [README.md](../README.md) for the UDMA userspace driver context, dependencies, installation, and supported hardware.

Application developers are not expected to use the UDMA driver directly; rather, they integrate its functionalities via the URMA programming API. As the UDMA userspace driver (`liburma-udma.so`) is packaged with URMA, installation of URMA alone grants access to UDMA's communication features.

## Functionality

### How UDMA Implements URMA Extensions

**u-udma** implements userspace extensions of the URMA programming API, which exposes the UnifiedBus remote memory access programming model to application developers. Understanding how u-udma extends URMA is crucial for comprehending the module's functionality and code structure.

URMA defines URMA device management functions and URMA communication functions through the `urma_provider_ops` and `urma_ops` interfaces, respectively. As an URMA provider, u-udma implements the `urma_provider_ops` and `urma_ops` interfaces in the file [udma_u_ops.c](../udma_u_ops.c).

Below is the code snippet for u-udma's implementation of the `urma_provider_ops` interface, which implements the u-udma module initialization and context management:

```c
urma_provider_ops_t g_udma_provider_ops = {
    .name = "udma",
    .attr = {
        .version = 1,
        .transport_type = URMA_TRANSPORT_UB,
    },
    .match_table = NULL,
    .init = udma_u_init,
    .uninit = udma_u_uninit,
    .query_device = udma_u_query_device,
    .create_context = udma_u_create_context,
    .delete_context = udma_u_delete_context,
};
```

Below is the code snippet for u-udma's implementation of the `urma_ops` interface, which includes all UDMA communication functionalities (`UDMA_OPS`):

```c
static urma_ops_t g_udma_ops = {
    .name = "UDMA_OPS",
    .create_jfc = udma_u_create_jfc,
    .modify_jfc = udma_u_modify_jfc,
    .delete_jfc = udma_u_delete_jfc,
    .create_jfs = udma_u_create_jfs,
    //...
};
```

Finally, u-udma registers the provider by calling the URMA API `urma_register_provider_ops` in the file [udma_u_main.c](../udma_u_main.c).

```c
//register UDMA provider to URMA
static __attribute__((constructor)) void urma_provider_ub_init(void)
{
    int ret;

    ret = urma_register_provider_ops(&g_udma_provider_ops);
    if (ret)
        UDMA_LOG_ERR("Provider UB register ops failed(%d).\n", ret);
    return;
}
```

At runtime, when an application calls the URMA function create_context to create an `urma_context`, URMA subsequently invokes u-udma's `udma_u_create_context` function. Within this function, u-udma's `g_udma_ops` is assigned to the `urma_context`.

### Module Functionalities

The functions provided by **u-udma** are split into two parts: the **Control Plane** and the **Data Plane**.

  * **Control Plane**: Provides UnifiedBus communication context and channel management functions, including UnifiedBus communication context, Jetty, Segment management, and event reporting, etc.
  * **Data Plane**: Provides data transmission and reception functions of UnifiedBus.

The functions within `UDMA_OPS` (defined in [udma_u_ops.c](../udma_u_ops.c)) serve as the entry points for both the Control Plane and the Data Plane. Reviewing their implementation provides a comprehensive understanding of the u-udma module's capabilities.

#### Control Plane

The detailed functions of the Control Plane are as follows.

**Jetty Resource Management**, including management of JFS, JFR, JFC, and Jetty resources. The corresponding `UDMA_OPS` functions are:

  * `udma_u_create_jetty`
  * `udma_u_create_jetty_grp`
  * `udma_u_create_jfs`
  * `udma_u_create_jfc`
  * `etc.`

**Transport Channel (TP) Management**, including TP creation and query. The corresponding `UDMA_OPS` function is:

  * `udma_u_ctrlq_get_tp_list`

**Memory Management for UDMA Communication**, including local memory registration and remote memory import. The corresponding `UDMA_OPS` functions are:

  * `udma_u_register_seg`
  * `udma_u_unregister_seg`
  * `udma_u_import_seg`
  * `udma_u_unimport_seg`

**Token ID (TID) Management**, including creation and release. The corresponding `UDMA_OPS` functions are:

  * `udma_u_alloc_tid`
  * `udma_u_free_tid`
  * `etc.`

#### Data Plane

The Data Plane provides functions for data transmission, reception, and completion events for both send and receive operations. The detailed functions are as follows.

**Data Send and Receive**, supporting transmission and reception using Jetty, JFR, or JFS. The corresponding `UDMA_OPS` functions are:

  * `udma_u_post_jetty_send_wr`
  * `udma_u_post_jetty_recv_wr`
  * `udma_u_post_jfs_wr`
  * `udma_u_post_jfr_wr`

**Receive and Send Completion Events**. The corresponding `UDMA_OPS` functions are:

  * `udma_u_poll_jfc`
  * `udma_u_wait_jfc`
  * `udma_u_ack_jfc`
  * `udma_u_rearm_jfc`
  * `udma_u_create_jfce`

## Support

If there is any issue or question, please email the specific information related
to the issue or question to [dev@openeuler.org](mailto:dev@openeuler.org) or vendor's support channel.
