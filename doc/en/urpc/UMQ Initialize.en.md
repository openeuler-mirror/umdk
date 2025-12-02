# UMQ Initialize

## Function Introduction
The Unified Message Queue (UMQ) initialization interface is responsible for loading the UMQ framework, configuring runtime parameters, and creating the initial data transmission environment. The UMQ environment must be correctly initialized before using any UMQ functionality.

## Overview
- Load the UMQ framework shared object (so)
- Create and initialize devices based on the mode
- Register memory and initialize the small memory pool
- Initialize dfx

## Timing of Invocation
- UMQ must be initialized first when the application starts
- It only needs to be called once

## Configurable Parameter Description
- buf mode: Selects the mode for using UMQ Buffer, supports two types: 'UMQ_BUF_SPLIT' and 'UMQ_BUF_COMBINE'
- feature: Sets UMQ features
- | Feature Type                        | Description                                      |
  | ----------------------------------- | ------------------------------------------------ |
  | UMQ_FEATURE_API_BASE                | Use basic UMQ APIs                           |
  | UMQ_FEATURE_API_PRO                 | Use enhanced UMQ APIs                        |
  | UMQ_FEATURE_ENABLE_TOKEN_POLICY     | Enables the token policy                         |
  | UMQ_FEATURE_ENABLE_STATS            | Enables packet statistics                        |
  | UMQ_FEATURE_ENABLE_PERF             | Enables latency statistics                       |
  | UMQ_FEATURE_ENABLE_FLOW_CONTROL     | Enables flow control                             |
- headroom_size: Configures the size of the user data header, [0, 512] bytes
- io_lock_free: Can be set to true when I/O threads are safe to improve performance
- trans_info_num: The number of data plane transmission device information entries, supports up to 128
- flow_control: Configures flow control parameters
- block_cfg: Configures the size of blocks in the small memory pool, supports four types: 8K, 16K, 32K, 64K
- cna: The CNA address of the UB controller for memory imported by the user, only valid for UMQ_TRANS_MODE_UBMM and UMQ_TRANS_MODE_UBMM_PLUS modes
- ubmm_eid: The EID of the UB controller for memory imported by the user, only valid for UMQ_TRANS_MODE_UBMM and UMQ_TRANS_MODE_UBMM_PLUS modes
- trans_info: Data plane transmission device information, used to initialize the corresponding device

## Device Initialization
Devices are initialized according to the transmission device information.

### UB Device Initialization
For UB devices, UMQ supports creating multiple devices using multiple EIDs simultaneously, with each device corresponding to one EID. UMQ allows users to initialize all devices at once via `umq_init` or to dynamically add devices after initialization. When initializing devices, users can specify either an `eid` or a `dev_name` + `eid_idx` combination. The `trans_info_num` determines the actual number of valid `trans_info` entries.

**One-time Initialization**

Execution Steps:

    1. Before initialization, prepare an array of `trans_info` for all EIDs that need to be initialized in `umq_init_cfg`, and correctly fill in `trans_info_num`
    2. Call the `umq_init` interface and pass in `umq_init_cfg`
    3. UMQ will create and initialize a corresponding UB device for each valid `trans_info`

One-time initialization UB device example:

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

**Dynamic Initialization**

Execution Steps:

    1. Prepare the `trans_info` for the new EID
    2. Call the `umq_dev_add` interface and pass in this `trans_info`
    3. UMQ will verify if this EID already exists, then create a new UB device for it, and register all previously registered memory pools onto this new device

Dynamic initialization UB device example:

```
    umq_trans_info_t trans_info;
    trans_info.trans_mode = UMQ_TRANS_MODE_UB;
    sprintf(trans_info.dev_info.dev.dev_name, "%s", "udma5");
    trans_info.dev_info.dev.eid_idx = 7;
    umq_dev_add(&trans_info);
```

## DFX Initialization
Currently, dfx supports the latency statistics (perf) module.

### Perf Initialization
Perf is a latency measurement module. During initialization, it only allocates memory and initializes locks. It becomes effective when the `UMQ_FEATURE_ENABLE_PERF` parameter in the feature is configured. The remaining initialization is completed upon the first call to the measurement function on the data plane.
