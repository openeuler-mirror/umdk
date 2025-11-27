# UDMA设备驱动（用户态）

## 简介

本文件夹包含 UDMA 驱动用户空间模块 (`u-udma`) 的源代码文件，本文档描述了 UDMA 驱动用户空间模块的上下文和功能。

### 什么是 UDMA

**UDMA** (UnifiedBus 直接内存访问) 是一种提供直接内存访问能力的硬件 I/O 设备。

UDMA 驱动通过实现 **URMA 编程 API** 集成到 UnifiedBus 协议中，该 API 向应用程序开发人员暴露了 UnifiedBus 远程内存访问编程模型。

**Unified Bus** ，中文名称为“灵衢”，是面向面向超节点的互联协议，它将各种处理单元之间的 I/O、内存访问和通信统一在一个互连技术框架下。UnifiedBus规范已开源，可在官方网站上获取：[UB 规范文档](https://www.unifiedbus.com/)。

**URMA (Unified Remote Memory Access)** 是 UnifiedBus 协议栈中的一个组件，旨在抽象和促进不同硬件和软件实体之间的通信。

### UDMA设备驱动

UDMA设备驱动由用户态`u-udma(liburma-udma.so)`和内核态`k-udma(udma.ko)`两个模块组成，这两个模块分别对接到URMA用户态和内核态协议栈扩展接口，实现基于UB设备间的UDMA通信功能，他们都依赖UMMU提供的内存地址转换功能。

```html
               ┌─────────────────────────────────┐                         
               │               App               │                         
               │                                 │                         
               └────────────────┬────────────────┘                         
                                │                                          
               ┌────────────────▼────────────────┐                         
               │                                 │                         
               │               liburma           │                         
               └────────────────┬────────────────┘                         
                                │                                          
               ┌────────────────▼────────────────┐         ┌──────────────┐
               │                                 │         │              │
               │              u-udma             ┼─────────►    libummu   │
 user sapce    └──────┬──────────────────┬───────┘         └──────────────┘
                      │                  │control path                     
──────────────────────┼──────────────────┼─────────────────────────────────────                     
                      │          ┌───────▼───────┐                         
 kernel space         │          │      urma     │                         
                      │          └───────┬───────┘                         
                      │          ┌───────▼───────┐         ┌─────────────┐ 
             data path│          │      k-udma   ┼─────────►   ummu      │ 
                      │          └───────┬───────┘         └─────────────┘ 
                      │          ┌───────▼───────┐                         
                      │          │      ubase    │                         
                      │          └───────┬───────┘                         
               ┌──────▼──────────────────▼───────┐                         
               │             udma hw             │                         
               └─────────────────────────────────┘                         
```

#### u-udma
**u-udma** 实现URMA协议栈用户态扩展接口，提供UnifiedBus通信功能。通过用户态u-udma驱动，使能用户态应用程序直接访问设备内存能力（图中的```data path```），达到Kernel Bypass的效果。

u-udma提供的功能分为控制面与数据面两部分：

- 控制面：提供UnifiedBus通信上下文与通道管理功能，包括进程上下文管理，Segment管理，Jetty管理，事件上报，数据面通道管理等。
- 数据面：提供UnifiedBus通信数据收发功能，包括Read/Write、Send/Recv等。

#### k-udma
**k-udma** 实现URMA协议栈内核态扩展接口，提供的功能包括UDMA设备管理，Segment管理，Jetty管理，传输通道管理，事件管理，数据面通道管理等。

### 支持的硬件

UDMA 驱动支持的硬件设备如下：

| Vendor ID | Device ID |
|-----------|-----------|
| 0xCC08    | 0xA001    |
| 0xCC08    | 0xA002    |
| 0xCC08    | 0xD802    |
| 0xCC08    | 0xD803    |
| 0xCC08    | 0xD80B    |
| 0xCC08    | 0xD80C    |

通过在Host主机上执行 ```lsub``` 命令可以查看设备信息，下面输出样例：

```shell

    UB network controller <0002>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<a001>
    UB network controller <0082>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<d802>
    UB network controller <0002>: Huawei Technologies Co., Ltd. URMA management ub entity <cc08>:<d80b>

```

```Vendor ID``` 与 ```Device ID``` 在输出行的尾端，格式为  ```<VendorID>:<DeviceID>```，如 ```<cc08>:<a001>```

注： ```lsub``` 命令来自 ```ubutils```，执行之前确保已经安装.


### 使用 UDMA

#### 安装

您可以通过两种方式安装u-udma驱动模块：源码、RPM包。
u-udma当前与URMA在同一个项目编译与打包，安装方式参考[URMA安装文档](../../../doc/ch/urma/URMA QuickStart Guide.ch.md)

u-udma模块安装完成后，会在操作系统上安装2个文件：

```bash
/usr/include/ub/umdk/urma/udma/udma_u_ctl.h
/usr/lib64/urma/liburma-udma.so
```

- [udma_u_ctl.h](../../../src/urma/hw/udma/include/udma_u_ctl.h): 硬件相关的配置参数，这部分配置不包含在URMA标准API中，应用需要显示引用此头文件。
- liburma-udma.so: 承载u-udma模块功能的动态链接库。

#### 使用

安装完成之后，开发者可以使用URMA的API，编写应用程序，URMA内部实现会调用UDMA驱动使能UDMA设备、实现内存互访操作，应用开发者无需显示调用UDMA驱动。

您可以通过阅读 [URMA接口规范](../../../doc/ch/urma/URMA API Guide.ch.md)了解如何使用URMA API，同时我们还提供了一个[基于URMA编程的的样例程序](../../../src/urma/examples)供参考。

