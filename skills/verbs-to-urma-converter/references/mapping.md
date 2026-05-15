# URMA API 映射参考

> URMA API 版本: 25.12.0
> **重要**: 本文档涵盖最新的 URMA API。请始终根据源仓库验证 https://atomgit.com/openeuler/umdk

## URMA 源仓库

| 资源 | URL | 说明 |
|----------|-----|-------------|
| **主仓库** | https://atomgit.com/openeuler/umdk | 官方 URMA/UMDK 源码 |
| URMA 头文件 | `lib/urma/include/` | 核心 API 头文件 |
| URMA API | `include/urma_api.h` | 公共 API 定义 |
| URMA 类型 | `include/urma_types.h` | 类型定义 |
| URMA 示例 | `tools/urma_perftest/` | 性能测试示例 |

### 头文件位置

| 头文件 | 内容 |
|--------|---------|
| `urma_api.h` | 函数签名、资源生命周期 |
| `urma_types.h` | 结构体、枚举、宏 |
| `urma_opcode.h` | 常量：URMA_ACCESS_*, URMA_TOKEN_*, URMA_OPC_* |

```bash
find /usr -name "urma_api.h" -o -name "urma_opcode.h" 2>/dev/null
# 常见位置：/usr/include/ub/umdk/urma/
```

---

## 无 URMA 等价物（直接删除）

以下 Verbs API 在 URMA 中没有对应项，迁移时**直接删除**而非替换：

| Verbs API | 删除原因 | 删除时的注意事项 |
|-----------|---------|----------------|
| `ibv_alloc_pd()` | PD 在 URMA 中隐式存在，由 context 管理 | 删除调用及其返回的 `ibv_pd*` 变量；原通过 PD 获取的 context 改为直接使用 `urma_context_t*` |
| `ibv_dealloc_pd()` | 同上 | 在清理流程中删除此调用 |
| `ibv_query_gid()` | EID 在 `urma_create_context()` 时已确定 | 改用 `urma_get_eid_list()` 获取 EID |
| `ibv_query_pkey()` | URMA 中无分区键概念 | 直接删除相关逻辑 |
| `port_attr->lid` | URMA 已移除 LID，仅使用 EID | 所有引用 LID 的代码（地址交换、路由判断）改用 EID |
| `ibv_modify_qp(IBV_QPS_INIT)` | URMA 中 Jetty 创建即处于 INIT 状态 | 删除此 modify_qp 调用，相关端口/GID 初始化逻辑无需迁移 |
| `ibv_modify_qp(IBV_QPS_RESET)` | URMA 中 delete+create 代替 reset | 删除此调用，如需重置则先 delete 再 create |

**⚠️ 不要试图为这些 API 寻找"等价物"**——它们代表的语义在 URMA 中不存在或由其他机制隐式处理。遇到表中未列出的无映射 API 时，查阅 `urma_api.h` 确认后再决定是删除还是替换。

---

## API 函数映射

### 初始化/反初始化

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| *(隐式)* | `urma_init()` | 初始化 URMA 库 - 必须在任何 URMA API 之前调用 |
| *(隐式)* | `urma_uninit()` | 反初始化 URMA 库 - 退出时调用一次 |

### 初始化与设备

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_get_device_list()` | `urma_get_device_list(&num_devices)` | **num_devices 指针为必需参数，不能为 NULL** |
| `ibv_free_device_list()` | `urma_free_device_list()` | 释放设备列表 |
| `ibv_open_device()` | `urma_create_context()` | 获取设备上下文 |
| `ibv_close_device()` | `urma_delete_context()` | 关闭设备上下文 |
| `ibv_query_device()` | `urma_query_device()` | 查询设备能力 |
| `ibv_query_port()` | *(在 urma_query_device() 中)* | 端口信息包含在设备属性中 |
| `ibv_get_device_name(dev)` | `dev->name` | 直接成员访问，不是函数 |

### 端口查询

URMA 没有独立的端口查询函数。使用 `urma_query_device()`：

```c
// 获取包含端口信息的设备属性
urma_device_attr_t dev_attr = {0};
status = urma_query_device(ctx->context->dev, &dev_attr);
if (status != URMA_SUCCESS) {
    fprintf(stderr, "无法获取设备信息\n");
    return 1;
}
// 端口 1 属性：
urma_port_attr_t port_attr = dev_attr.port_attr[0];
```

### 内存注册

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_alloc_pd()` | *(隐式)* | URMA 中无显式 PD |
| `ibv_dealloc_pd()` | *(隐式)* | 由上下文销毁处理 |
| `ibv_reg_mr()` | `urma_register_seg()` | 注册内存段 |
| `ibv_dereg_mr()` | `urma_unregister_seg()` | 注销内存段 |
| `ibv_reg_dm_mr()` | *(直接使用 DM)* | 设备内存支持 |
| `ibv_advise_mr()` | *(参见 URMA 标志)* | ODP/预取通过标志实现 |

### 完成队列

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_create_cq()` | `urma_create_jfc()` | 创建完成队列 |
| `ibv_destroy_cq()` | `urma_delete_jfc()` | 销毁完成队列 |
| `ibv_poll_cq()` | `urma_poll_jfc()` | 轮询完成事件，每次最多 16 条 |
| `ibv_req_notify_cq()` | `urma_rearm_jfc()` | 请求通知 |

#### JFC 限制与建议

**轮询限制**：RDMA 设备每次调用最多轮询 **16 条完成记录**。

**深度建议**：
```
JFC 深度 >= 关联 Jetty 队列深度之和 / CR 生成间隔 + 关联 Jetty 数量
```

**关键约束**：JFC 深度必须 >= JFR 深度 + JFS 深度，否则完成事件可能丢失。

### 事件通道（完成通道）

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_create_comp_channel()` | `urma_create_jfce()` | 创建事件通道 |
| `ibv_destroy_comp_channel()` | `urma_delete_jfce()` | 销毁事件通道 |
| `ibv_get_cq_event()` | `urma_wait_jfc()` | 等待完成事件（阻塞） |
| `ibv_ack_cq_events()` | `urma_ack_jfc()` | `urma_wait_jfc()` 之后**必须调用** |

**事件模式完整序列：**
```c
// 1. 创建 JFCE（事件通道）
urma_jfce_t *jfce = urma_create_jfce(ctx);

// 2. 创建绑定 JFCE 的 JFC
urma_jfc_cfg_t jfc_cfg = {
    .depth = 128,
    .jfce = jfce,  // 绑定事件通道
    .user_ctx = 0
};
urma_jfc_t *jfc = urma_create_jfc(ctx, &jfc_cfg);

// 3. 初始装填（第一次等待之前）
urma_rearm_jfc(jfc, false);

// 4. 等待事件（阻塞）
urma_jfc_t *ev_jfc = NULL;
int cnt = urma_wait_jfc(jfce, 1, timeout_ms, &ev_jfc);

// 5. 重新装填以接收下一个事件（可在轮询/确认之前或之后）
urma_rearm_jfc(jfc, false);

// 6. 轮询完成事件
urma_cr_t cr;
urma_poll_jfc(jfc, 1, &cr);

// 7. 确认 - 必须调用！
uint32_t ack_cnt = 1;
urma_ack_jfc(&ev_jfc, &ack_cnt, 1);
```

**⚠️ 关键**：每次 `urma_wait_jfc()` 之后必须调用 `urma_ack_jfc()`。遗漏会导致资源泄漏。

**注意**：`rearm` 和 `ack` 的顺序可以灵活，但 `ack` 必须在 `wait` 之后调用。

### 异步事件处理

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_get_async_event()` | `urma_get_async_event()` | 获取异步事件 |
| `ibv_ack_async_event()` | `urma_ack_async_event()` | 确认异步事件 |

### 队列对 / Jetty（生命周期）

| Verbs 操作 | URMA 操作 | 说明 |
|-----------|----------|-------|
| `ibv_create_qp()` | `urma_create_jfr()` → `urma_create_jetty()` | **所有模式 (RC/RM/UM)**：先创建 JFR，再创建 Jetty 并设置 `jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR` 和 `jetty_cfg.shared.jfr = jfr` |
| `ibv_modify_qp(RTR)` | `urma_import_jetty()` | **所有模式**都需要 import |
| `ibv_modify_qp(RTS)` | `urma_bind_jetty()` | **仅 RC 模式** |
| `ibv_destroy_qp()` | **RC**：`urma_unbind_jetty()` → `urma_unimport_jetty()` → `urma_delete_jetty()` → `urma_delete_jfr()` | 必须按顺序调用 |
| | **RM/UM**：`urma_unimport_jetty()` → `urma_delete_jetty()` → `urma_delete_jfr()` | 必须按顺序调用 |
| `ibv_query_qp()` | `urma_query_jetty()` | 查询 QP 状态 |

---

### 连接建立决策树

Verbs 的 `ibv_modify_qp()` 在 URMA 中的对应操作取决于传输模式。以下决策树帮助快速确定正确流程：

```
ibv_modify_qp(RTR) 出现时 → 判断 trans_mode:
  ├─ RC (IBV_QPT_RC / URMA_TM_RC)
  │    → urma_import_jetty()  // 导入远端 Jetty
  │    → urma_bind_jetty()    // 建立可靠连接（仅 RC 需要）
  │
  ├─ RM (URMA_TM_RM)
  │    → urma_import_jetty()  // 导入远端 Jetty（无 bind）
  │
  └─ UM (IBV_QPT_UD / URMA_TM_UM)
       → urma_import_jetty()  // 导入远端 Jetty（无 bind）

ibv_modify_qp(RTS) 出现时 → 判断 trans_mode:
  ├─ RC → 已由 bind_jetty() 完成，无需额外操作
  ├─ RM → 不适用（无连接状态转换）
  └─ UM → 不适用

ibv_modify_qp(INIT) 出现时 → 直接删除（Jetty 创建即处于 INIT 状态）
ibv_modify_qp(RESET) 出现时 → 替换为 delete + create（如需重置）
```

**地址交换格式决策**：
```
Verbs 交换内容:  lid + gid + qpn + psn
                ↓
URMA 交换内容:  eid + jpn
                ↓
具体打包:       rjetty.jetty_id.eid  (16字节 EID)
                rjetty.jetty_id.uasid (UASID)
                rjetty.jetty_id.id    (JPN)
                rjetty.tp_type        (URMA_RTP 或 URMA_UTP)
                rjetty.trans_mode     (URMA_TM_RC/RM/UM)
```

**清理顺序决策**：
```
程序退出 → 判断使用的传输模式:
  ├─ RC 模式:  unbind_jetty → unimport_jetty → delete_jetty → delete_jfr → delete_jfc → uninit
  ├─ RM 模式:  unimport_jetty → delete_jetty → delete_jfr → delete_jfc → uninit
  └─ UM 模式:  unimport_jetty → delete_jetty → delete_jfr → delete_jfc → uninit
                                                                          ↑
                                                                最后调用 urma_uninit()！
```

---

### 共享接收队列 (SRQ)

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_srq` | `urma_jfr_t` | 共享接收队列 |
| `ibv_create_srq()` | `urma_create_jfr()` | 创建 SRQ |
| `ibv_destroy_srq()` | `urma_delete_jfr()` | 销毁 SRQ |
| `ibv_post_srq_recv()` | `urma_post_jfr_wr()` | 向 SRQ 投递接收请求 |
| `ibv_modify_srq()` | `urma_modify_jfr()` | 修改 JFR 属性 |
| `ibv_query_srq()` | `urma_query_jfr()` | 查询 JFR 属性 |
| 使用共享 SRQ 的 QP | `jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR` + `jetty_cfg.shared.jfr = srq` | 多个 Jetty 共享同一个 JFR |


**注意**：使用 `URMA_TOKEN_PLAIN_TEXT`（或更高安全级别）时，JFR 也需要有效的 token，该 token 必须与远端交换。

### 工作请求

| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_post_send()` | `urma_post_jfs_wr()` | 投递发送请求 (JFS) |
| `ibv_post_send()` | `urma_post_jetty_send_wr()` | 投递发送请求 (Jetty) |
| `ibv_post_recv()` | `urma_post_jfr_wr()` | 投递接收请求 (JFR) |
| `ibv_post_recv()` | `urma_post_jetty_recv_wr()` | 投递接收请求 (Jetty) |

### 高层操作

| Verbs | URMA 高层 API | 说明 |
|-------|---------------------|-------|
| 手动 send/recv | `urma_send()` | 简化发送 |
| 手动 send/recv | `urma_recv()` | 简化接收 |
| RDMA Write | `urma_write()` | 直接 RDMA 写 |
| RDMA Read | `urma_read()` | 直接 RDMA 读 |
| Atomic | `urma_cas()`, `urma_faa()` | 比较并交换、取值加 |

---

## 枚举映射

### MTU

| Verbs | URMA |
|-------|------|
| `IBV_MTU_256` | `URMA_MTU_256` |
| `IBV_MTU_512` | `URMA_MTU_512` |
| `IBV_MTU_1024` | `URMA_MTU_1024` |
| `IBV_MTU_2048` | `URMA_MTU_2048` |
| `IBV_MTU_4096` | `URMA_MTU_4096` |
| - | `URMA_MTU_8192` |

### 访问标志

#### 注册标志 (urma_reg_seg_flag_t)

| Verbs | URMA | 值 | 说明 |
|-------|------|-------|-------------|
| `IBV_ACCESS_LOCAL_WRITE` | `URMA_ACCESS_LOCAL_ONLY` | 0x1 | 仅本地访问（与其他标志互斥） |
| `IBV_ACCESS_REMOTE_READ` | `URMA_ACCESS_READ` | 0x2 | 读取权限 |
| `IBV_ACCESS_REMOTE_WRITE` | `URMA_ACCESS_WRITE` | 0x4 | 写入权限（需要 READ） |
| `IBV_ACCESS_REMOTE_ATOMIC` | `URMA_ACCESS_ATOMIC` | 0x8 | 原子操作（需要 READ+WRITE） |
| `IBV_ACCESS_ON_DEMAND` | *(不支持)* | - | ODP 处理方式不同 |
| `IBV_ACCESS_ZERO_BASED` | *(URMA 中不需要)* | - | |

**依赖关系**：WRITE 依赖 READ，ATOMIC 依赖 READ+WRITE。

### QP 状态

| Verbs | URMA | 说明 |
|-------|------|-------|
| `IBV_QPS_RESET` | *(在创建时)* | 初始状态 |
| `IBV_QPS_INIT` | *(在创建时)* | 已初始化 |
| `IBV_QPS_RTR` | `urma_import_jetty()` | 准备接收 |
| `IBV_QPS_RTS` | `urma_bind_jetty()` | 准备发送 |
| `IBV_QPS_ERR` | *(错误状态)* | 错误 |

### QP 类型

| Verbs | URMA | 说明 |
|-------|------|-------|
| `IBV_QPT_RC` | `URMA_TM_RC` | 可靠连接 |
| `IBV_QPT_UD` | `URMA_TM_UM` | 不可靠消息 |
| - | `URMA_TM_RM` | 可靠消息（无连接） |

**关键：所有传输模式都需要显式创建 JFR 和 import_jetty**

| Verbs | URMA | 资源创建差异 |
|-------|------|------------------------------|
| QP 内部包含发送/接收队列 | **Jetty 默认不创建 JFR**，必须显式创建并共享 |

**必需步骤（所有模式）：**
```
1. urma_create_jfr()     // 创建接收队列 (JFR)
2. urma_create_jetty()   // 创建发送队列 (JFS)
   └── 设置 jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR
   └── 设置 jetty_cfg.shared.jfr = 步骤 1 创建的 JFR
3. urma_import_jetty()   // 导入远端 Jetty（所有模式 - 必需！）
   └── 设置 wr.tjetty = imported_target_jetty  // 必须在发送 WR 中设置
```

**RC 模式额外步骤：**
```
4. urma_bind_jetty()      // 绑定连接（仅 RC）
```

**RM 模式：**
```
4. urma_import_jetty()    // （advise 已废弃）
```

**UM 模式：**
```
4. urma_import_jetty()    // （无 bind）
```

### 工作请求操作码

| Verbs | URMA | 说明 |
|-------|------|-------|
| `IBV_WR_SEND` | `URMA_OPC_SEND` | |
| `IBV_WR_SEND_WITH_IMM` | `URMA_OPC_SEND_IMM` | 即时数据在 `send.imm_data` |
| `IBV_WR_RDMA_WRITE` | `URMA_OPC_WRITE` | |
| `IBV_WR_RDMA_WRITE_WITH_IMM` | `URMA_OPC_WRITE_IMM` | 即时数据在 `rw.notify_data`（不是 `imm_data`！） |
| `IBV_WR_RDMA_READ` | `URMA_OPC_READ` | |
| `IBV_WR_ATOMIC_CMP_AND_SWP` | `URMA_OPC_CAS` | |
| `IBV_WR_ATOMIC_FETCH_AND_ADD` | `URMA_OPC_FADD` | 注意：FAA → FADD |

**重要**：即时数据操作的字段区别：
- `URMA_OPC_SEND_IMM`：使用 `wr.send.imm_data`
- `URMA_OPC_WRITE_IMM`：使用 `wr.rw.notify_data`（不同字段！）

### 完成状态值

| Verbs | URMA | 说明 |
|-------|------|-------|
| `IBV_WC_SUCCESS` | `URMA_CR_SUCCESS` | 成功 |
| `IBV_WC_LOC_LEN_ERR` | `URMA_CR_LOC_LEN_ERR` | 本地数据过长 |
| `IBV_WC_LOC_QP_OP_ERR` | `URMA_CR_LOC_OPERATION_ERR` | 本地操作错误 |
| `IBV_WC_LOC_ACCESS_ERR` | `URMA_CR_LOC_ACCESS_ERR` | 本地访问错误 |
| `IBV_WC_REM_RESP_ERR` | `URMA_CR_REM_RESP_LEN_ERR` | 远端响应长度错误 |
| `IBV_WC_REM_OP_ERR` | `URMA_CR_REM_OPERATION_ERR` | 远端操作错误 |
| `IBV_WC_RNR_RETRY_CNT_EXC` | `URMA_CR_RNR_RETRY_CNT_EXC_ERR` | RNR 重试超限 |
| `IBV_WC_WR_FLUSH_ERR` | `URMA_CR_WR_FLUSH_ERR` | WR 被刷新 |

### 错误码

| URMA 错误 | 值 | 说明 |
|------------|-------|-------------|
| `URMA_SUCCESS` | 0 | 成功 |
| `URMA_EAGAIN` | -11 | 资源暂时不可用 |
| `URMA_ENOMEM` | -12 | 内存分配失败 |
| `URMA_ENOPERM` | -1 | 操作不允许 |
| `URMA_ETIMEOUT` | -110 | 操作超时 |
| `URMA_EINVAL` | -22 | 无效参数 |
| `URMA_EEXIST` | -17 | 已存在 |
| `URMA_EINPROGRESS` | -115 | 操作进行中 |
| `URMA_FAIL` | 0x1000 | 通用失败 |

**返回值检查**：URMA 函数的返回值语义不统一，需按类别判断：

| 类别 | 成功条件 | 示例函数 |
|------|---------|---------|
| 资源管理类 | 返回 0 表示成功，非 0 表示错误 | `urma_init`, `urma_register_seg`, `urma_create_jfc`, `urma_create_jetty`, `urma_import_jetty`, `urma_bind_jetty` |
| 轮询/等待类 | 返回 >0 表示成功（返回计数），0 或负数表示失败/无数据 | `urma_poll_jfc`, `urma_wait_jfc` |
| 指针返回类 | 返回非 NULL 表示成功，NULL 表示失败 | `urma_create_context`, `urma_create_jfce` |

**⚠️ 常见错误**：将 `urma_poll_jfc()` 或 `urma_wait_jfc()` 的返回值用 `!= 0` 检查成功——这会错误地将错误码也视为成功。正确做法是 `> 0` 表示有完成事件。

### 传输类型 (TP Type)

| TP 类型 | URMA 值 | 说明 |
|---------|------------|-------------|
| 可靠传输 | `URMA_RTP` | 默认可靠传输协议 |
| 连接传输 | `URMA_CTP` | 面向连接的传输 |
| 不可靠传输 | `URMA_UTP` | 不可靠传输，最高性能 |

**注意**：TP 类型决定连接行为。

### 完成记录操作码

| Verbs | URMA | 说明 |
|-------|------|-------------|
| `IBV_WC_SEND` | `URMA_CR_OPC_SEND` | 发送操作完成 |
| `IBV_WC_RDMA_WRITE` | `URMA_CR_OPC_WRITE` | RDMA 写完成 |
| `IBV_WC_RDMA_READ` | `URMA_CR_OPC_READ` | RDMA 读完成 |
| `IBV_WC_RECV` | `URMA_CR_OPC_RECV` | 接收完成 |
| `IBV_WC_RECV_RDMA_WITH_IMM` | `URMA_CR_OPC_WRITE_WITH_IMM` | 带即时数据的写 |

**注意**：`URMA_CR_OPC_WRITE_WITH_IMM` 常用于带即时数据通知的 RDMA 操作。

### Token 策略

| 策略 | 值 | Token 要求 | 安全级别 | 使用场景 |
|--------|-------|-------------------|----------------|----------|
| `URMA_TOKEN_NONE` | 0 | 可以为 0 | 无认证 | 开发/测试 |
| `URMA_TOKEN_PLAIN_TEXT` | 1 | 必须非零 | 明文 token | 生产环境（推荐） |
| `URMA_TOKEN_SIGNED` | 2 | 必须非零 | 签名认证 | 高安全 |
| `URMA_TOKEN_ALL_ENCRYPTED` | 3 | 必须非零 | 全加密 | 最高安全 |

### 传输模式

| 模式 | 值 | 说明 | 使用场景 |
|------|-------|-------------|----------|
| `URMA_TM_RM` | 0x1 | 可靠消息 | 双向、无连接 |
| `URMA_TM_RC` | 0x2 | 可靠连接 | 单向、面向连接 |
| `URMA_TM_UM` | 0x4 | 不可靠消息 | 高性能，可能丢包 |

---

## 数据结构映射

**迁移时必须使用指定初始化语法，绝不能先定义再赋值：**
  ```c
  // ❌ 错误 - 未初始化的局部变量，字段值未定义
  urma_seg_cfg_t seg_cfg;
  seg_cfg.va = (uint64_t)buf;
  // ✅ 正确 - 使用指定初始化，未指定的字段自动置零
  urma_seg_cfg_t seg_cfg = {
      .va = (uint64_t)buf,
      .len = size
  };
  ```
  原因：URMA 结构体字段众多，遗漏字段会导致未定义行为。

### 核心对象

| Verbs 类型 | URMA 类型 | 说明 |
|------------|-----------|-------|
| `ibv_context` | `urma_context_t` | 设备上下文句柄 |
| `ibv_pd` | *(隐式)* | PD 在 URMA 中隐式管理 |
| `ibv_mr` | `urma_target_seg_t` | 通过 `urma_register_seg()` 获取的内存区域 |
| `ibv_cq` | `urma_jfc_t` | 完成队列 |
| `ibv_comp_channel` | `urma_jfce_t` | 完成事件通道 |
| `ibv_qp` | `urma_jetty_t` | 队列对（发送/接收组合） |
| `ibv_qp` | `urma_jfs_t` + `urma_jfr_t` | 队列对（发送/接收分离） |
| `ibv_srq` | `urma_jfr_t` | 共享接收队列 - 可被多个 Jetty 共享 |
| `ibv_device` | `urma_device_t` | 网络设备 |
| `ibv_port_attr` | `urma_port_attr_t` | 端口属性 |
| `ibv_sge` | `urma_sge_t` | 散聚条目 |
| `ibv_send_wr` | `urma_jfs_wr_t` | 发送工作请求 |
| `ibv_recv_wr` | `urma_jfr_wr_t` | 接收工作请求 |

### 地址类型

| Verbs | URMA | 格式 |
|-------|------|--------|
| `lid` | *(已移除)* | URMA 使用 EID 代替 LID |
| `union ibv_gid` | `urma_eid_t` | 16 字节端点 ID |
| `qpn` | `jpn` | Jetty 对编号 |
| `psn` | *(已移除)* | PSN 由 URMA 内核内部管理 |

### 地址交换格式

| Verbs 格式 | URMA 格式 | 示例 |
|--------------|-------------|---------|
| `lid:qpn:psn:gid` | `jpn:eid` | Verbs: `0001:010203:abcdef:...` |
| | | URMA: `010203:0000000000000000000000000000000000000000000000000000000000000000` |

**注意**：
- URMA 完全移除了 LID - 仅使用 EID（16 字节）
- URMA 移除了 PSN - 由内核内部管理，无需用户空间交换

---

## 结构体字段映射

> **重要**：本节将 Verbs 结构体字段映射到 URMA 结构体字段。
> 若此处未找到映射，请阅读系统 URMA 头文件进行验证。

### 完成记录 (ibv_wc → urma_cr_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `wc.qp_num` | `cr.local_id` | **不是** `cr.jetty_id.id` |
| `wc.wr_id` | `cr.user_ctx` | 用户上下文 |
| `wc.status` | `cr.status` | 完成状态 |
| `wc.opcode` | `cr.opcode` | 操作码 |
| `wc.byte_len` | `cr.completion_len` | 传输字节数 |
| `wc.imm_data` | `cr.imm_data` | 即时数据 |

#### 完成记录 (urma_cr_t) 详细字段

| URMA 字段 | 说明 |
|------------|-------------|
| `cr.local_id` | 本地 Jetty/JFS/JFR ID |
| `cr.remote_id` | 远端 Jetty ID（仅接收 CR 有效） |
| `cr.user_ctx` | 用户上下文 (wr_id) |
| `cr.completion_len` | 传输字节数 |
| `cr.imm_data` | 即时数据（send/write with imm） |
| `cr.opcode` | 操作码（仅接收 CR 有效） |
| `cr.tpn` | TP 或 TPG 编号 |

### 队列对 (ibv_qp → urma_jetty_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `qp->qp_num` | `jetty->jetty_id.id` | **不是** `jetty->id` |
| `qp->state` | `jetty->jetty_cfg` | 通过 jetty 配置获取 |
| `qp->qp_type` | `jetty->jetty_cfg.jfs_cfg.trans_mode` | 传输模式 |

### 端口属性 (ibv_port_attr → urma_port_attr_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `port_attr->lid` | *(已移除)* | URMA 中**不存在**，使用 EID |
| `port_attr->gid` | `eid_info->eid` | 通过 `urma_get_eid_list()` 获取 |
| `port_attr->mtu` | `port_attr->active_mtu` | 活跃 MTU |

### 设备属性 (ibv_device_attr → urma_device_attr_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `dev_attr->phys_port_cnt` | `dev_attr->port_cnt` | 端口数 |
| `dev_attr->gid_tbl_len` | `dev_attr->dev_cap.max_eid_cnt` | 最大 EID 数 |

### 远端 Jetty (urma_rjetty_t)

| 必需字段 | 说明 |
|---------------|-------|
| `rjetty.jetty_id` | 远端 jetty ID（EID, uasid, id） |
| `rjetty.trans_mode` | 传输模式 (URMA_TM_RC/RM/UM) |
| `rjetty.policy` | 策略 (URMA_JETTY_GRP_POLICY_RR) |
| `rjetty.type` | 类型 (URMA_JETTY) |
| `rjetty.flag` | 导入标志 |
| `rjetty.tp_type` | **关键**：必须设置 (URMA_RTP) |

### 散聚条目 (ibv_sge → urma_sge_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `sge.addr` | `sge.addr` | 缓冲区地址 |
| `sge.length` | `sge.len` | **不是** `length` |
| `sge.lkey` | `sge.tseg` | **不是**整数，使用 `urma_target_seg_t*`，来自 `urma_register_seg()` 或 `urma_import_seg()` |

**重要**：RDMA 读/写/原子操作中，远端内存段的 `tseg` 必须通过 `urma_import_seg()` 获取，而非 `urma_register_seg()`。详见 pitfalls.md §23。

### 发送工作请求 (ibv_send_wr → urma_jfs_wr_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `wr.wr_id` | `wr.user_ctx` | 工作请求 ID |
| `wr.opcode` | `wr.opcode` | 操作码 |
| `wr.send_flags` | `wr.flag.value` 或 `wr.flag.bs.*` | 使用位域设置各标志 |
| `wr.sg_list` | `wr.send.src.sge` | **不是** `wr.sge` - 嵌套在联合 `send.src` 中 |
| `wr.num_sge` | `wr.send.src.num_sge` | **不是** `wr.num_sge` - 嵌套在 `urma_sg_t` 中 |
| `wr.next` | `wr.next` | 链表 |

**发送标志：**

| Verbs 标志 | URMA 位域 | 说明 |
|------------|---------------|-------|
| `IBV_SEND_SIGNALED` | `flag.bs.complete_enable = 1` | 生成完成事件 |
| `IBV_SEND_INLINE` | `flag.bs.inline_flag = 1` | 内联数据 |
| `IBV_SEND_FENCE` | `flag.bs.fence = 1` | 栅栏 |
| `IBV_SEND_SOLICITED` | `flag.bs.solicited_enable = 1` | 请求事件 |

### 接收工作请求 (ibv_recv_wr → urma_jfr_wr_t)

| Verbs 字段 | URMA 字段 | 说明 |
|-------------|-------------|-------|
| `wr.wr_id` | `wr.user_ctx` | 工作请求 ID |
| `wr.sg_list` | `wr.src.sge` | **不是** `wr.sge` - 嵌套在 `src` 中 |
| `wr.num_sge` | `wr.src.num_sge` | **不是** `wr.num_sge` - 嵌套在 `urma_sg_t` 中 |
| `wr.next` | `wr.next` | 链表 |

### urma_reg_seg_flag_t 位域布局

```c
typedef union urma_reg_seg_flag {
    struct {
        uint32_t token_policy   : 3;  // 位 0-2
        uint32_t cacheable      : 1;  // 位 3
        uint32_t dsva           : 1;  // 位 4
        uint32_t access         : 6;  // 位 5-10
        uint32_t non_pin        : 1;  // 位 11
        uint32_t user_iova      : 1;  // 位 12
        uint32_t token_id_valid : 1;  // 位 13
        uint32_t reserved       : 18; // 位 14-31
    } bs;
    uint32_t value;
} urma_reg_seg_flag_t;
```

### 常见字段映射错误

| 错误用法 | 正确用法 | 错误原因 |
|---------------|---------------|--------------|
| `cr.jetty_id.id` | `cr.remote_id.id` | `urma_cr_t` 没有 `jetty_id` 成员 |
| `jetty->id` | `jetty->jetty_id.id` | `urma_jetty_t` 没有 `id` 成员 |
| `port_attr->lid` | 使用 EID | URMA 已移除 LID |
| `rjetty`（缺少 tp_type） | `rjetty.tp_type = URMA_RTP` | 必须设置 tp_type |
| `sge.length` | `sge.len` | 字段名为 `len`，不是 `length` |
| `sge.lkey` | `sge.tseg` | 使用指针类型，不是整数键 |
| `wr.sg_list` | `wr.send.src.sge` / `wr.src.sge` | 嵌套在联合/结构体中 |
| `wr.num_sge` | `wr.send.src.num_sge` / `wr.src.num_sge` | 嵌套在 `urma_sg_t` 中 |
| `seg_cfg.addr` | `seg_cfg.va` | 字段名为 `va`，不是 `addr` |
| `flag = URMA_ACCESS_LOCAL_ONLY` | `flag.bs.access = URMA_ACCESS_LOCAL_ONLY` | 通过位域访问 |
| `.value = URMA_ACCESS_LOCAL_ONLY` | `.bs.token_policy = URMA_TOKEN_NONE, .bs.access = ...` | `.value` 会设置所有位 |

### URMA 特有参数（Verbs 中无对应项）

以下参数在 URMA 中存在但 Verbs 中没有对应项，必须根据设备能力正确设置。

| URMA 参数 | 设备能力字段 | 典型值 | 说明 |
|----------------|-------------------|---------------|-------|
| `jfs_cfg.max_rsge` | `dev_cap.max_jfs_rsge` | 通常为 1 | 最大远端 SGE 数（Verbs 无对应项） |
| `jfs_cfg.max_sge` | `dev_cap.max_jfs_sge` | 13+ | 发送最大本地 SGE |
| `jfr_cfg.max_sge` | `dev_cap.max_jfr_sge` | 4+ | 接收最大本地 SGE |
| `jfs_cfg.depth` | `dev_cap.max_jfs_depth` | 8192 | JFS 队列深度 |
| `jfr_cfg.depth` | `dev_cap.max_jfr_depth` | 32768 | JFR 队列深度 |
| `jfs_cfg.max_inline_data` | `dev_cap.max_jfs_inline_len` | 208 | 最大内联数据 |
| `jfc_cfg.depth` | `dev_cap.max_jfc_depth` | 65536 | JFC 深度 |

**⚠️ 关键：使用用户自定义常量需与设备能力值进行比较，使用其中较小的值**

```c
// ✅ 正确 - 使用设备能力
urma_jfs_cfg_t jfs_cfg = {
    .max_sge = min(13, (uint8_t)ctx->dev_attr.dev_cap.max_jfs_sge),
    .max_rsge = ming(12, (uint8_t)ctx->dev_attr.dev_cap.max_jfs_rsge),  // 不是 max_sge！
};

// ❌ 错误 - 使用任意值
urma_jfs_cfg_t jfs_cfg = {
    .max_sge = 13,
    .max_rsge = 13,  // 错误！设备可能仅支持 1
};
```

---

## 添加新映射

在迁移过程中发现新 API 映射时：

1. 确定分类（数据结构、API 函数、枚举等）
2. 在相应表格中添加条目
3. 包含：Verbs API、URMA API 和简要说明

格式：
```markdown
| Verbs API | URMA API | 说明 |
|-----------|----------|-------|
| `ibv_xxx()` | `urma_xxx()` | 说明 |
```
