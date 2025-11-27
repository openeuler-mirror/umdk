# UDMA Device Driver (Userspace)

## Introduction

This folder containers source files of UDMA driver userspace module (`u-udma`), this document describes the context and capabilities of the UDMA driver userspace module.

### What is UDMA

**UDMA** (UnifiedBus Direct Memory Access), is a hardware I/O device that provides direct memory access capabilities. 

The UDMA driver integrates with the UnifiedBus protocol by implementing the **URMA programming API**, which exposes the UnifiedBus remote memory access programming model to application developers.

**Unified Bus** is an interconnect protocol for SuperPoD,  It unifies IO, memory access, and communication between various processing units under a single interconnect technology framework. The UnifiedBus specifications are open source and available on the official website: `UB Specification Documents <https://www.unifiedbus.com/>`_.

**URMA(Unified Remote Memory Access)** is a component within the UnifiedBus protocol stack, designed to abstract and facilitate communication between different hardware and software entities.

### UDMA Device Driver

UDMA driver composed of `u-duma(liburma-duma)` and `k-udma(udma.ko)`, both of them implements URMA extention(provding UnifiedBus direct memory capability) and depends on UMMU (for memory address translation).

```html
               ┌─────────────────────────────────┐                         
               │               App               │                         
               │                                 │                         
               └────────────────┬────────────────┘                         
                                │                                          
               ┌────────────────▼────────────────┐                         
               │                                 │                         
               │               urma              │                         
               └────────────────┬────────────────┘                         
                                │                                          
               ┌────────────────▼────────────────┐         ┌──────────────┐
               │                                 │         │              │
               │              u-udma             ┼─────────►    libummu   │
 user sapce    └──────┬──────────────────┬───────┘         └──────────────┘
                      │                  │control path                     
──────────────────────┼──────────────────┼─────────────────────────────────────                     
                      │          ┌───────▼───────┐                         
 kernel space         │          │      urma     │                         
                      │          └───────┬───────┘                         
                      │          ┌───────▼───────┐         ┌─────────────┐ 
             data path│          │      k-udma   ┼─────────►   ummu      │ 
                      │          └───────┬───────┘         └─────────────┘ 
                      │          ┌───────▼───────┐                         
                      │          │      ubase    │                         
                      │          └───────┬───────┘                         
               ┌──────▼──────────────────▼───────┐                         
               │             udma hw             │                         
               └─────────────────────────────────┘
```

#### u-udma

**u-udma** implements userspace extensions of the URMA programming API, which exposes the UnifiedBus remote memory access programming model to application developers. The userspace **u-udma** module enables userspace applications to **directly access device memory** (the `data path` in the diagram), achieving a **Kernel Bypass** effect.

The functions provided by **u-udma** are split into two parts: the **Control Plane** and the **Data Plane**.

* **Control Plane**: Provides UnifiedBus communication context and channel management functions, including UnifiedBus communication context, Jetty, Segment management, and event reporting etc.. Control plane functions rely on **k-udma**; operations that must be performed in kernelspace are accomplished via **ioctl** calls to **k-udma**.
* **Data Plane**: Provides data transmission and reception functions of UnifiedBus.

#### k-udma

**k-udma** implements kernelspace extension of the URMA programming API. The scope of functions provided by **k-udma** includes UnifiedBus communication context, Jetty, Segment management, Transport Protocol (TP) connection establishment, and event reporting etc..


### Supported Hardware

The UDMA driver supports the following hardware devices:

| Vendor ID | Device ID |
|-----------|-----------|
| 0xCC08    | 0xA001    |
| 0xCC08    | 0xA002    |
| 0xCC08    | 0xD802    |
| 0xCC08    | 0xD803    |
| 0xCC08    | 0xD80B    |
| 0xCC08    | 0xD80C    |

You can view device information by executing the **`lsub`** command on the Host system. An example output is shown below:

```shell

    UB network controller <0002>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<a001>
    UB network controller <0082>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<d802>
    UB network controller <0002>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<d80b>

```

The **`Vendor ID`** and **`Device ID`** are located at the end of each output line, in the format **`<VendorID>:<DeviceID>`**, e.g., **`<cc08>:<a001>`**.

Note: The **`lsub`** command is provided by **`ubutils`**; ensure it is installed before execution.

### Using UDMA

#### Installation

You can install the **u-udma** driver module in two ways: from source code or via an RPM package.
**u-udma** is currently compiled and packaged with UMDK. Refer to the [UMDK Installation Document](/doc/en/urma/URMA QuickStart Guide.en.md) for installation instructions.

Upon successful installation, the **u-udma** module installs two files on the operating system:

```bash
/usr/include/ub/umdk/urma/udma/udma_u_ctl.h
/usr/lib64/urma/liburma-udma.so
```

* [udma\_u\_ctl.h](../../../src/urma/hw/udma/include/udma_u_ctl.h): Contains hardware-specific configuration parameters. Applications should only use this file if they are aware of specific hardware differences and require customized configuration. These interfaces are currently unstable and subject to change in future versions, their use is not recommended.
* liburma-udma.so: The dynamic linking library containing the **u-udma** module's functionality.

#### Usage

Once installed, developers should write applications using the **URMA API**. The **URMA internal implementation** will invoke the UDMA driver to enable the UDMA device and perform memory access operations. **Application developers are not required to explicitly call the UDMA driver.**

You can learn how to use the URMA API by reading the [URMA API Specification](../../../doc/en/urma/URMA API Guide.en.md). We also provide a [sample program based on URMA programming](../../../src/urma/examples) for reference.
