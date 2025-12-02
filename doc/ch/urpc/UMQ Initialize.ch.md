# UMQ Initialize

## 功能简介
统一消息队列（UMQ）初始化接口，负责加载UMQ框架、配置运行参数并创建初始数据传输环境。在使用任何UMQ功能之前，必须首先正确初始化UMQ环境。

## 概述
- 加载umq framework的so
- 基于模式创建并初始化设备
- 注册内存并初始化small内存池
- 初始化dfx

## 调用时机
- 应用程序启动时，首先要初始化umq
- 只需要调用一次

## 可配参数说明
- buf mode: 选择使用UMQ Buffer的模式，支持UMQ_BUF_SPLIT和UMQ_BUF_COMBINE两种类型
- feature: 设置umq特性
- | 特性类型                        | 描述             |
  | ------------------------------- | ---------------- |
  | UMQ_FEATURE_API_BASE            | 使用umq的基础API |
  | UMQ_FEATURE_API_PRO             | 使用umq的增强API |
  | UMQ_FEATURE_ENABLE_TOKEN_POLICY | 开启token策略    |
  | UMQ_FEATURE_ENABLE_STATS        | 开启报文统计     |
  | UMQ_FEATURE_ENABLE_PERF         | 开启时延统计     |
  | UMQ_FEATURE_ENABLE_FLOW_CONTROL | 开启流控         |
- headroom_size: 配置用户数据头的大小，[0, 512]字节
- io_lock_free: I/O线程安全时可设为true以提升性能
- trans_info_num: 数据面传输设备信息的数量，最多支持128个
- flow_control: 配置流控参数
- block_cfg: 配置小型内存池block的大小，支持8K, 16K, 32K, 64K 4种类型。
- cna：使用方导入内存的UB控制器的CNA地址，仅UMQ_TRANS_MODE_UBMM和UMQ_TRANS_MODE_UBMM_PLUS模式有效
- ubmm_eid: 用方导入内存的UB控制器的EID，仅UMQ_TRANS_MODE_UBMM和UMQ_TRANS_MODE_UBMM_PLUS模式有效
- trans_info：数据面传输设备信息，用于初始化对应得设备

## 设备初始化
按照传输设备信息，初始化设备。

### UB设备初始化
对于UB设备umq支持同时使用多个EID创建多个设备，每个设备对应一个EID。UMQ支持用户通过umq_init一次性初始化所有设备，也支持初始化之后动态添加设备。初始设备时，用户可通过指定eid或者dev_name + eid_idx的方式初始化。通过trans_info_num确定实际有效的trans info的数量。

**一次性初始化**

执行步骤：

    1. 初始化前，在umq_init_cfg中准备所有需要初始化的EID的trans info数组，并正确填写trans_info_num
    2. 调用umq_init接口传入umq_init_cfg
    3. umq会将每个有效的 trans info 创建并初始化一个对应的UB设备

一次性初始化UB设备示例：

```
    umq_init_cfg_t init_cfg = {
        .feature = UMQ_FEATURE_API_PRO,
        .trans_info_num = 2,
    };
    init_cfg->trans_info[0].trans_mode = UMQ_TRANS_MODE_UB;
    sprintf(init_cfg->trans_info[0].dev_info.dev.dev_name, "%s", "udma2");
    init_cfg.trans_info[0].dev_info.dev.eid_idx = 7;
	init_cfg->trans_info[1].trans_mode = UMQ_TRANS_MODE_UB;
    sprintf(init_cfg->trans_info[1].dev_info.dev.dev_name, "%s", "udma5");
    init_cfg.trans_info[1].dev_info.dev.eid_idx = 7;
    umq_init(&init_cfg);
```

**动态初始化**

执行步骤：

    1. 准备新EID的trans info
    2. 调用umq_dev_add接口，传入该trans info
    3. umq会校验此EID是否已存在，然后为其创建新的UB设备, 将之前已经注册的所有内存池，都注册到这个新设备上

动态初始化UB设备示例：

```
    umq_trans_info_t trans_info;
    trans_info.trans_mode = UMQ_TRANS_MODE_UB;
    sprintf(trans_info.dev_info.dev.dev_name, "%s", "udma5");
    trans_info.dev_info.dev.eid_idx = 7;
    umq_dev_add(&trans_info);
```

## dfx 初始化
目前 dfx 支持时延统计（perf）模块。

### perf初始化
perf 是时延打点模块。初始化时仅申请内存并初始化锁，配置feature中UMQ_FEATURE_ENABLE_PERF参数即可生效，其余初始化在数据面首次调用打点函数时完成。
