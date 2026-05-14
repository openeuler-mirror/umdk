# URMA 代码模式与最佳实践

> URMA API 版本: 25.12.0

## 系统头文件位置

| 安装方式 | 包含路径 |
|-------------|--------------|
| 系统安装 | `#include <ub/umdk/urma/urma_api.h>` |
| 自定义安装 | 检查 `find /usr -name "urma_api.h"` |

---

## 1. 初始化流程

### 黄金法则
**每个进程必须调用一次 `urma_init()`，退出时必须调用一次 `urma_uninit()`。**

### 正确模式

```c
// 程序启动时（例如 main() 开头）
urma_init_attr_t init_attr = {
    .token = 0,
    .uasid = 0
};
if (urma_init(&init_attr) != URMA_SUCCESS) {
    fprintf(stderr, "URMA 初始化失败\n");
    return 1;
}

// ... 你的 URMA 操作 ...

// 程序退出时（例如 main() 末尾）
urma_uninit();
```

### 资源创建顺序（所有模式：RC/RM/UM）

```
urma_init()           ← 必须最先调用！（在任何 URMA API 之前）
    ↓
urma_get_device_list() / urma_get_device_by_name()
    ↓
urma_create_context(device, eid_index)
    ↓
urma_create_jfce(context)        [可选 - 用于事件驱动模式]
    ↓
urma_create_jfc(context, &jfc_cfg)
    ↓
urma_register_seg(context, &seg_cfg)
    ↓
urma_create_jfr(context, &jfr_cfg)  [必需 - 共享 JFR]
    ↓
urma_create_jetty(context, &jetty_cfg)  [传入共享 JFR + 设置 share_jfr]
    ↓
urma_import_jetty(context, &rjetty)    [所有模式都需要]
    ↓
urma_bind_jetty(jetty, tjetty)          [仅 RC 模式]
```

### 关键差异：GID 索引 vs EID 索引的指定时机

Verbs 和 URMA 在指定 GID/EID 索引的时机上有重大差异：

| 特性 | Verbs (RDMA) | URMA |
|---------|--------------|------|
| 指定索引的时机 | `ibv_modify_qp()` 中作为 `sgid_index` 参数 | `urma_create_context()` 中作为 `eid_index` 参数 |
| 何时设置 | QP 创建后，连接前 (modify_qp) | 设备打开时（上下文创建） |
| 如何获取本地 GID | 通过 `ibv_query_gid(ctx, port, gid_idx, &gid)` | 直接通过 `ctx->eid` |
| 范围 | 每个 QP 可使用不同的 gid_index | 整个上下文共享同一个 EID |

**Verbs 代码模式**：
```c
// 1. 创建 QP（此处未指定 gid）
struct ibv_qp_init_attr init_attr = { .qp_type = IBV_QPT_RC, ... };
struct ibv_qp *qp = ibv_create_qp(pd, &init_attr);

// 2. 修改 QP 到 INIT 状态
struct ibv_qp_attr attr = { .qp_state = IBV_QPS_INIT, ... };
ibv_modify_qp(qp, &attr, IBV_QP_STATE);

// 3. 修改 QP 到 RTR 状态 - 此处指定 gid_index
attr.ah_attr.grh.sgid_index = gid_idx;  // 此处指定
attr.ah_attr.grh.dgid = remote_gid;
ibv_modify_qp(qp, &attr, IBV_QP_AV);

// 4. 获取本地 gid（随时可查询）
ibv_query_gid(context, port, gid_idx, &local_gid);
```

**URMA 代码模式**：
```c
// 1. 创建上下文时必须指定 eid_index（本地 EID 在此处确定）
urma_context_t *ctx = urma_create_context(device, eid_idx);  // 此处指定

// 2. 获取本地 EID（直接从上下文获取）
urma_eid_t local_eid = ctx->eid;

// 3. 连接时只需提供 remote_eid
urma_rjetty_t rjetty = {
    .jetty_id = {
        .eid = remote_eid,  // 远端 EID
        .id = remote_jpn
    },
    .tp_type = URMA_RTP
};
urma_target_jetty_t *tjetty = urma_import_jetty(ctx, &rjetty, NULL);
urma_bind_jetty(jetty, tjetty);
```

**迁移注意事项**：
- **必须尽早确定 eid_idx**：在 URMA 中，创建上下文之前就必须决定使用哪个 EID 索引
- **整个上下文共享一个 EID**：与 Verbs 不同，URMA 中所有 Jetty 共享同一个 EID
- **不能动态更改**：URMA 不支持像 Verbs 那样通过 modify_qp 动态更改 gid_index

> 完整的资源创建代码示例见 §4 "组合 Jetty 创建"。

---

## 2. 内存注册

### URMA 版本

```c
// PD 是隐式的 - 无需分配

// 注册内存段
urma_seg_cfg_t seg_cfg = {
    .va = (uint64_t)buf,
    .len = size,
    .token_id = NULL,
    .token_value.token = 0xABCDEF,  // 安全 token（必须非零！）
    .flag.bs.token_policy = URMA_TOKEN_NONE,
    .flag.bs.cacheable = URMA_NON_CACHEABLE,
    .flag.bs.access = URMA_ACCESS_LOCAL_ONLY,  // 必须设置！
    .flag.bs.token_id_valid = 0,
    .flag.bs.reserved = 0,
    .user_ctx = 0,
    .iova = 0
};
urma_target_seg_t *tseg = urma_register_seg(ctx, &seg_cfg);

// 注销
urma_unregister_seg(tseg);
```

**要点**：
- PD 是隐式的，无需 `ibv_alloc_pd()`
- `sge.tseg` 是指向 `urma_target_seg_t` 的指针，不是整数键
- 当 `token_policy` 要求时，token 必须非零

### ⚠️ 关键：访问标志必须设置

`.bs.access` 字段**必须**显式设置，否则运行时错误：
```
urma_check_seg_cfg[2769]|Local only access is not allowed to config with other accesse
```

**访问标志语义：**
- `URMA_ACCESS_LOCAL_ONLY`：仅本地访问，不允许远端访问
- 不使用 `LOCAL_ONLY` 时：本地默认拥有完全访问权限，远端访问由 READ/WRITE/ATOMIC 控制

**根据操作类型选择：**
- `send/recv`（双端）：使用 `URMA_ACCESS_LOCAL_ONLY`
- `RDMA 读/写`（单端）：使用 `URMA_ACCESS_READ | URMA_ACCESS_WRITE`（不要使用 LOCAL_ONLY）
- `原子操作`：在上述基础上添加 `URMA_ACCESS_ATOMIC`

### ⚠️ 关键：访问标志互斥

**`URMA_ACCESS_LOCAL_ONLY` 不能与其他访问标志组合：**
```c
// ❌ 错误 - 会导致运行时错误
.flag.bs.access = URMA_ACCESS_LOCAL_ONLY | URMA_ACCESS_READ;

// ✅ 正确 - 选择一种类别
.flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE;  // 用于 RDMA
.flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC;  // 用于 RDMA + 原子
.flag.bs.access = URMA_ACCESS_LOCAL_ONLY;  // 仅用于 send/recv
```

**从 Verbs 迁移：**
| Verbs 标志 | URMA 标志 |
|-------------|------------|
| 仅 `IBV_ACCESS_LOCAL_WRITE` | `URMA_ACCESS_LOCAL_ONLY` |
| `IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE` | `URMA_ACCESS_READ | URMA_ACCESS_WRITE` |
| `... | IBV_ACCESS_REMOTE_ATOMIC` | `... | URMA_ACCESS_ATOMIC` |

### urma_reg_seg_flag_t 位域布局

```c
// 错误 - .value 会设置所有位，包括 token_policy
urma_reg_seg_flag_t flag = { .value = URMA_ACCESS_LOCAL_ONLY };
// 结果：token_policy=1 (URMA_TOKEN_PLAIN_TEXT)，而不是 0 (URMA_TOKEN_NONE)！

// 正确 - .bs.xxx 设置单个字段
urma_reg_seg_flag_t flag = {
    .bs.token_policy = URMA_TOKEN_NONE,
    .bs.cacheable = URMA_NON_CACHEABLE,
    .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE,
    .bs.token_id_valid = 0,
    .bs.reserved = 0
};
```

### 常见配置

```c
// 仅本地访问（开发环境）
urma_reg_seg_flag_t flag = {
    .bs.token_policy = URMA_TOKEN_NONE,
    .bs.cacheable = URMA_NON_CACHEABLE,
    .bs.access = URMA_ACCESS_LOCAL_ONLY,
    .bs.token_id_valid = 0,
    .bs.reserved = 0
};

// 完全远端访问（生产环境）
urma_reg_seg_flag_t flag = {
    .bs.token_policy = URMA_TOKEN_PLAIN_TEXT,
    .bs.cacheable = URMA_NON_CACHEABLE,
    .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
    .bs.token_id_valid = 0,
    .bs.reserved = 0
};
```

---

## 3. 完成队列

### 轮询模式

```c
// 创建完成队列（轮询模式 - 无 JFCE）
urma_jfc_cfg_t jfc_cfg = {
    .depth = depth,
    .flag.value = 0,
    .jfce = NULL,  // NULL = 轮询模式
    .user_ctx = 0
};
urma_jfc_t *jfc = urma_create_jfc(ctx, &jfc_cfg);

// 轮询完成事件
urma_cr_t cr[16];
int ne = urma_poll_jfc(jfc, 16, cr);

// 清理
urma_delete_jfc(jfc);
```

**要点**：
- 每次 `urma_poll_jfc()` 调用最多 16 条完成记录
- JFC 深度必须 >= JFR 深度 + JFS 深度

### 事件驱动模式

```c
// 创建 JFCE
urma_jfce_t *jfce = urma_create_jfce(ctx);

// 创建绑定 JFCE 的 JFC
urma_jfc_cfg_t jfc_cfg = {
    .depth = 128,
    .jfce = jfce,
    .user_ctx = 0
};
urma_jfc_t *jfc = urma_create_jfc(ctx, &jfc_cfg);

urma_rearm_jfc(jfc, false);  // 初始装填

urma_jfc_t *ev_jfc = NULL;
int cnt = urma_wait_jfc(jfce, 1, timeout_ms, &ev_jfc);

urma_rearm_jfc(jfc, false);  // 重新装填

urma_cr_t cr;
urma_poll_jfc(jfc, 1, &cr);

// 参数：(jfc_数组, 事件数_数组, jfc_数组_数量)
// - jfc_数组：要确认的 JFC 指针数组
// - 事件数_数组：每个 JFC 要确认的事件数数组
// - jfc_数组_数量：数组中 JFC 指针的数量（不是事件数！）
uint32_t ack_cnt = 1;  // 要确认的事件数
urma_ack_jfc(&ev_jfc, &ack_cnt, 1);  // 必须：1 = 数组中有 1 个 JFC
```

**事件模式序列**：
```
wait -> rearm -> poll -> ack
```

**关键**：每次 `urma_wait_jfc()` 之后必须调用 `urma_ack_jfc()`。

### 模式对比

| 特性 | 轮询模式 | 事件模式 |
|---------|--------------|------------|
| 延迟 | 极低 (μs) | 低 (10-100μs) |
| CPU 使用率 | 高 | 低 |
| 需要 JFCE | 否 | 是 |
| 调用序列 | `poll → 使用` | `wait → rearm → poll → ack` |
| 适用场景 | 高频、低延迟 | 多路复用、节能 |

### JFCE 中断驱动线程模式

```c
typedef struct {
    urma_context_t *ctx;
    urma_jfce_t *jfce;
    urma_jfc_t *jfc;
    int running;
} event_handler_t;

int event_handler_init(event_handler_t *eh, urma_context_t *ctx) {
    eh->ctx = ctx;
    eh->running = 1;

    eh->jfce = urma_create_jfce(ctx);
    if (!eh->jfce) return -1;

    urma_jfc_cfg_t jfc_cfg = {
        .depth = 128,
        .jfce = eh->jfce,
        .user_ctx = 0
    };
    eh->jfc = urma_create_jfc(ctx, &jfc_cfg);
    if (!eh->jfc) {
        urma_delete_jfce(eh->jfce);
        return -1;
    }

    urma_rearm_jfc(eh->jfc, false);
    return 0;
}

void *event_handler_thread(void *arg) {
    event_handler_t *eh = (event_handler_t *)arg;

    while (eh->running) {
        urma_jfc_t *ev_jfc = NULL;
        int cnt = urma_wait_jfc(eh->jfce, 1, 1000, &ev_jfc);
        if (cnt <= 0) continue;
        if (ev_jfc != eh->jfc) continue;

        urma_cr_t cr;
        while (urma_poll_jfc(eh->jfc, 1, &cr) > 0) {
            if (cr.status == URMA_CR_SUCCESS) {
                // 处理成功
            }
        }

        uint32_t ack_cnt = 1;
        urma_ack_jfc(&ev_jfc, &ack_cnt, 1);
        urma_rearm_jfc(eh->jfc, false);
    }

    return NULL;
}

void event_handler_cleanup(event_handler_t *eh) {
    eh->running = 0;
    urma_delete_jfc(eh->jfc);
    urma_delete_jfce(eh->jfce);
}
```

---

## 4. Jetty 连接流程

### 按传输模式

URMA 根据传输模式使用不同的连接 API。API 映射参见 mapping.md。

#### RC 模式（可靠连接）- 单 Jetty

RC 模式使用 `urma_import_jetty()` + `urma_bind_jetty()`：

```c
// 步骤 1：导入远端 Jetty
urma_rjetty_t rjetty = {
    .jetty_id = { .eid = remote_eid, .uasid = 0, .id = remote_jpn },
    .trans_mode = URMA_TM_RC,
    .policy = URMA_JETTY_GRP_POLICY_RR,
    .type = URMA_JETTY,
    .tp_type = URMA_RTP,  // 关键：必须设置！
    .flag = { .bs.order_type = URMA_DEF_ORDER, .bs.share_tp = 0 }
};
urma_token_t token = { .token = 0xACFE };
urma_target_jetty_t *tjetty = urma_import_jetty(ctx, &rjetty, &token);

// 步骤 2：绑定本地 Jetty 到远端（仅 RC！）
urma_bind_jetty(jetty, tjetty);
```

**要点**：
- 仅 RC 模式使用 `urma_bind_jetty()`。这在 urma_api.h 中有文档："Only supported by jetty under URMA_TM_RC"
- 必须保存 `tjetty` 指针用于清理（见 §8）

#### RM 模式（可靠消息）- 共享 JFR

RM 模式使用 `urma_import_jetty()`（advise 已废弃）：

```c
// 步骤 1：导入远端 Jetty
urma_rjetty_t rjetty = {
    .jetty_id = { .eid = remote_eid, .uasid = 0, .id = remote_jpn },
    .trans_mode = URMA_TM_RM,
    .policy = URMA_JETTY_GRP_POLICY_RR,
    .type = URMA_JETTY,
    .tp_type = URMA_RTP,
    .flag = {
        .bs.order_type = URMA_DEF_ORDER,
        .bs.share_tp = 0
    }
};
urma_token_t token = { .token = 0xACFE };
urma_target_jetty_t *tjetty = urma_import_jetty(ctx, &rjetty, &token);
```

**要点**：
- RM 模式仅使用 import_jetty（无 advise）
- 必须设置 tp_type = URMA_RTP
- 必须保存 tjetty 指针用于清理（见 §8）

#### UM 模式（不可靠消息）- 共享 JFR

UM 模式使用 `urma_import_jetty()`（无 bind）：

```c
// 步骤 1：导入远端 Jetty
urma_rjetty_t rjetty = {
    .jetty_id = { .eid = remote_eid, .uasid = 0, .id = remote_jpn },
    .trans_mode = URMA_TM_UM,
    .policy = URMA_JETTY_GRP_POLICY_RR,
    .type = URMA_JETTY,
    .tp_type = URMA_UTP,  // UM 模式使用 UTP！
    .flag.bs.order_type = URMA_DEF_ORDER,
    .flag.bs.share_tp = 0
};
urma_token_t token = { .token = 0 };
urma_target_jetty_t *tjetty = urma_import_jetty(ctx, &rjetty, &token);

// 步骤 2：在发送 WR 中设置 tjetty
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_SEND,
    .flag.bs.complete_enable = 1,
    .tjetty = tjetty,  // 关键 - 必须设置！
    .send.src.sge = &sge,
    .send.src.num_sge = 1
};
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

**要点**：
- UM 模式需要 import_jetty（与之前的文档不同）
- UM 模式使用 tp_type = URMA_UTP
- 发送前必须设置 wr.tjetty
- 无需 bind/advise，但仍需 import
- 更简单但可靠性较低（可能丢包）

### 连接总结

> **重要**：所有模式 (RC/RM/UM) 都使用共享 JFR。创建流程：先创建 JFR，创建 Jetty 时传入并设置 share_jfr。

| 模式 | 传输方式 | 连接 API | 清理顺序 |
|------|-----------|-----------------|---------------|
| RC | URMA_TM_RC | `urma_import_jetty()` + `urma_bind_jetty()` | unbind → unimport → delete jetty → delete jfr |
| RM | URMA_TM_RM | `urma_import_jetty()`（advise 已废弃） | unimport → delete jetty → delete jfr |
| UM | URMA_TM_UM | `urma_import_jetty()`（无 bind） | unimport → delete jetty → delete jfr |

注意：所有模式都需要 import_jetty，只有 RC 模式需要 bind_jetty。

完整清理代码示例见 §8。

### 组合 Jetty 创建

```c
// 1. 先创建 JFR（所有模式共享 JFR）
urma_jfr_cfg_t jfr_cfg = {
    .depth = 256,
    .trans_mode = URMA_TM_RC,  // 必须与 Jetty 的 trans_mode 匹配
    .max_sge = 1,
    .jfc = jfc,
    .token_value = token,
    .flag = {
        .bs.token_policy = URMA_TOKEN_NONE,
        .bs.tag_matching = URMA_NO_TAG_MATCHING,
        .bs.order_type = URMA_DEF_ORDER
    }
};
urma_jfr_t *jfr = urma_create_jfr(ctx, &jfr_cfg);

// 2. 创建带共享 JFR 的 Jetty
urma_jetty_cfg_t jetty_cfg = {
    .id = 0,  // 自动分配

    // 关键：必须设置 share_jfr 标志
    .flag = {
        .bs.share_jfr = URMA_SHARE_JFR
    },

    // 发送端 (JFS)
    .jfs_cfg = {
        .depth = 16,
        .trans_mode = URMA_TM_RC,  // 必须与 JFR 的 trans_mode 匹配
        .priority = 0,
        .max_sge = 1,
        .rnr_retry = URMA_TYPICAL_RNR_RETRY,
        .err_timeout = URMA_TYPICAL_ERR_TIMEOUT,
        .jfc = jfc,
        .flag = {
            .bs.order_type = URMA_DEF_ORDER  // 必须与 JFR 匹配
        },
        .user_ctx = 0
    },

    // 接收端（共享 JFR）
    .shared = {
        .jfr = jfr,  // 传入共享 JFR
        .jfc = jfc
    },

    .user_ctx = 0
};

urma_jetty_t *jetty = urma_create_jetty(ctx, &jetty_cfg);
```

**要点**：JFS 中的 `order_type`（jfs_cfg.flag.bs.order_type）必须与 JFR 和 rjetty 显式匹配，否则会导致运行时错误。

---

## 5. Send/Recv 操作

### Send 操作

```c
// 准备本地缓冲区
urma_sge_t sge = {
    .addr = (uint64_t)buf,
    .len = size,
    .tseg = local_tseg
};
urma_sg_t src_sg = { .sge = &sge, .num_sge = 1 };

urma_send_wr_t send_wr = {
    .src = src_sg,
    .target_hint = 0,
    .imm_data = 0,
    .tseg = NULL
};

urma_jfs_wr_t wr = {0};
wr.opcode = URMA_OPC_SEND;
wr.flag.bs.complete_enable = 1;
wr.flag.bs.solicited_enable = 1;
wr.user_ctx = wr_id;
wr.tjetty = t_jetty;
wr.send = send_wr;

urma_jfs_wr_t *bad_wr = NULL;
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### 带即时数据的 Send

```c
urma_send_wr_t send_wr = {
    .src = src_sg,
    .imm_data = IMM_DATA  // 即时数据在 send.imm_data
};

urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_SEND_IMM,
    .flag.bs.complete_enable = 1,
    .tjetty = t_jetty,
    .user_ctx = wr_id,
    .send = send_wr
};
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### Recv 操作

```c
// 准备接收缓冲区
urma_sge_t sge = {
    .addr = (uint64_t)buf,
    .len = size,
    .tseg = local_tseg
};
urma_sg_t src_sg = { .sge = &sge, .num_sge = 1 };

urma_jfr_wr_t wr = {0};
wr.src = src_sg;
wr.user_ctx = wr_id;
wr.next = NULL;

urma_jfr_wr_t *bad_wr = NULL;
urma_post_jetty_recv_wr(jetty, &wr, &bad_wr);
```

**要点**：
- 设置字段前始终用 `{0}` 初始化工作请求
- `wr.send.src.sge` 嵌套在 `urma_send_wr_t.src` 中
- 接收的 `wr.src.sge` 嵌套在 `urma_jfr_wr_t.src` 中
- `SEND_IMM` 使用 `send.imm_data`（与 `WRITE_IMM` 使用 `rw.notify_data` 不同）

---

## 6. RDMA 读/写操作

### RDMA 操作的 src/dst 语义

**重要**：URMA 对 READ 和 WRITE 操作使用不同的 src/dst 语义：

| 操作 | src | dst | 数据流向 |
|-----------|-----|-----|-----------|
| WRITE | **本地**地址 | **远端**地址 | 本地 → 远端 |
| WRITE_IMM | **本地**地址 | **远端**地址 | 本地 → 远端 |
| READ | **远端**地址 | **本地**地址 | 远端 → 本地 |

**结构定义**：
```c
typedef struct urma_rw_wr {
    urma_sg_t src;  // write 时为本地 va，read 时为远端 va
    urma_sg_t dst;  // write 时为远端 va，read 时为本地 va
    uint8_t target_hint;
    uint64_t notify_data;  // 用于 WRITE_IMM
} urma_rw_wr_t;
```

### 导入远端段（RDMA 操作必需）

执行 RDMA 读/写/原子操作前，必须导入远端内存段：

```c
// 在连接阶段导入远端段
urma_import_seg_flag_t seg_flag = {
    .bs.cacheable = URMA_NON_CACHEABLE,
    .bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC,
    .bs.mapping = URMA_SEG_NOMAP,
    .bs.reserved = 0
};

urma_target_seg_t *import_tseg = urma_import_seg(
    ctx->urma_ctx,
    &remote_seg,      // 来自地址交换
    &token,           // 匹配的 token
    0,
    seg_flag
);
if (import_tseg == NULL) {
    fprintf(stderr, "导入段失败\n");
    return -1;
}
```

### Write 操作

```c
// 准备本地和远端 sge
urma_sge_t local_sge = {
    .addr = (uint64_t)local_buf,
    .len = MSG_SIZE,
    .tseg = local_tseg
};
urma_sge_t remote_sge = {
    .addr = remote_va,
    .len = MSG_SIZE,
    .tseg = import_tseg  // 必须使用导入的段！
};

urma_sg_t src_sg = { .sge = &local_sge, .num_sge = 1 };
urma_sg_t dst_sg = { .sge = &remote_sge, .num_sge = 1 };

// WRITE：src=本地，dst=远端
urma_rw_wr_t rw = { .src = src_sg, .dst = dst_sg };
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_WRITE,
    .flag.bs.complete_enable = 1,
    .tjetty = t_jetty,
    .user_ctx = wr_id,
    .rw = rw
};
urma_jfs_wr_t *bad_wr = NULL;
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### 带即时数据的 Write

```c
// 准备本地和远端 sge（与 WRITE 相同）
urma_sge_t local_sge = {
    .addr = (uint64_t)local_buf,
    .len = MSG_SIZE,
    .tseg = local_tseg
};
urma_sge_t remote_sge = {
    .addr = remote_va,
    .len = MSG_SIZE,
    .tseg = import_tseg
};

urma_sg_t src_sg = { .sge = &local_sge, .num_sge = 1 };
urma_sg_t dst_sg = { .sge = &remote_sge, .num_sge = 1 };

// WRITE_IMM 使用 rw.notify_data（不是 imm_data！）
urma_rw_wr_t rw = {
    .src = src_sg,
    .dst = dst_sg,
    .notify_data = IMM_DATA
};
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_WRITE_IMM,
    .flag.bs.complete_enable = 1,
    .tjetty = t_jetty,
    .user_ctx = wr_id,
    .rw = rw
};
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### Read 操作

```c
// 准备本地和远端 sge
urma_sge_t local_sge = {
    .addr = (uint64_t)local_buf,
    .len = MSG_SIZE,
    .tseg = local_tseg
};
urma_sge_t remote_sge = {
    .addr = remote_va,
    .len = MSG_SIZE,
    .tseg = import_tseg
};

// READ：src=远端，dst=本地（与 WRITE 相反）
urma_sg_t src_sg = { .sge = &remote_sge, .num_sge = 1 };  // READ 的远端
urma_sg_t dst_sg = { .sge = &local_sge, .num_sge = 1 };   // READ 的本地

urma_rw_wr_t rw = { .src = src_sg, .dst = dst_sg };
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_READ,
    .flag.bs.complete_enable = 1,
    .tjetty = t_jetty,
    .user_ctx = wr_id,
    .rw = rw
};
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### 完整 RDMA 操作生命周期

```c
// 1. 交换阶段：交换远端段信息
typedef struct {
    urma_seg_t seg;           // 远端段信息
    urma_jetty_id_t jetty_id; // 远端 Jetty ID
} exchange_info_t;

// 2. 连接阶段：导入远端段
urma_target_seg_t *import_seg[test_ctx->num_seg];
for (int i = 0; i < test_ctx->num_seg; i++) {
    import_seg[i] = urma_import_seg(ctx, &remote[i].seg, &token, 0, seg_flag);
}

// 3. 操作阶段：使用 import_seg 进行 RDMA
urma_sge_t remote_sge = {
    .addr = remote_va,
    .len = length,
    .tseg = import_seg[id]  // 使用导入的段
};

// 4. 清理阶段：注销前先取消导入
for (int i = 0; i < test_ctx->num_seg; i++) {
    urma_unimport_seg(import_seg[i]);
}
urma_unregister_seg(local_tseg);
```

> **迁移提示**：URMA 提供高层封装（`urma_write`/`urma_read`/`urma_send`/`urma_recv`），但迁移时应优先使用低层 API（`urma_post_jetty_send_wr` 等），以便精确控制 WR 字段。

### 即时数据字段对比

| 操作 | 字段 | 位置 |
|-----------|-------|----------|
| `URMA_OPC_SEND_IMM` | `imm_data` | `wr.send.imm_data` |
| `URMA_OPC_WRITE_IMM` | `notify_data` | `wr.rw.notify_data` |

**注意**：SEND_IMM 和 WRITE_IMM 使用不同的字段存储即时数据。

---

## 7. 地址交换

### URMA 版本

```c
// EID 转线格式字符串
char eid_str[URMA_EID_STR_LEN + 1];
eid_to_wire_gid(&my_dest.eid, eid_str);

// 发送：jpn:eid（无 PSN）
snprintf(msg, sizeof(msg), "%06x:%s", my_dest.jpn, eid_str);

// 接收
sscanf(msg, "%hx:%s", &rem_dest->jpn, eid_str);
wire_gid_to_eid(eid_str, &rem_dest->eid);
```

**要点**：
- URMA 无 LID - 仅使用 EID（16 字节）
- URMA 无 PSN - 由内核管理，无需用户空间交换
- 格式：`jpn:eid`

---

## 8. 清理顺序

### 按传输模式清理

清理顺序取决于连接建立时使用的传输模式。

#### RC 模式（Jetty + import + bind）

RC 模式使用 `urma_import_jetty()` + `urma_bind_jetty()` 建立连接：

```c
// 1. 解绑（仅 RC 模式需要）
urma_unbind_jetty(local_jetty);

// 2. 取消导入（释放远端 Jetty 引用）
urma_unimport_jetty(target_jetty);

// 3. 删除本地 Jetty
urma_delete_jetty(local_jetty);

// 4. 删除共享 JFR（在所有 Jetty 销毁后）
urma_delete_jfr(shared_jfr);
```

**重要**：必须在连接阶段保存 `tjetty` 指针，以便在清理时使用：
```c
// 连接期间 (pp_connect_ctx)：
ctx->tjetty[i] = urma_import_jetty(ctx->context, &rjetty, &token);
urma_bind_jetty(ctx->jetty[i], ctx->tjetty[i]);

// 清理期间：
urma_unbind_jetty(ctx->jetty[i]);
urma_unimport_jetty(ctx->tjetty[i]);
urma_delete_jetty(ctx->jetty[i]);
```

#### RM 模式（Jetty + import）

RM 模式使用 `urma_import_jetty()` 建立连接（advise 已废弃）：

```c
// 1. 取消导入（释放远端 Jetty 引用）
urma_unimport_jetty(target_jetty);

// 2. 删除本地 Jetty
urma_delete_jetty(local_jetty);

// 3. 删除共享 JFR（在所有 Jetty 销毁后）
urma_delete_jfr(shared_jfr);
```

#### UM 模式（Jetty + import）

UM 模式使用 `urma_import_jetty()` 建立连接（无 bind）：

```c
// 1. 取消导入（释放远端 Jetty 引用）
urma_unimport_jetty(target_jetty);

// 2. 删除本地 Jetty
urma_delete_jetty(local_jetty);

// 3. 删除共享 JFR（在所有 Jetty 销毁后）
urma_delete_jfr(shared_jfr);
```

### 完整清理序列

> **重要**：所有模式 (RC/RM/UM) 都使用共享 JFR。清理顺序：先删除所有 Jetty，再删除共享 JFR。

```c
// 1. 修改 Jetty 为错误状态（推荐）
urma_jetty_attr_t attr = { .mask = JETTY_STATE, .state = URMA_JETTY_STATE_ERROR };
urma_modify_jetty(jetty, &attr);

// 2. (RC 模式) 解绑 - 必须在取消导入之前调用
urma_unbind_jetty(jetty);

// 3. 取消导入远端 Jetty - 释放远端 Jetty 引用
urma_unimport_jetty(tjetty);

// 4. 取消导入远端段 - 必须在注销本地段之前
//    （针对 RDMA 读/写操作中导入的远端段）
urma_unimport_seg(import_tseg);

// 5. 删除本地 Jetty
urma_delete_jetty(jetty);

// 6. 删除共享 JFR（在所有 Jetty 销毁后）
urma_delete_jfr(shared_jfr);

// 7. 删除 JFC
urma_delete_jfc(jfc);

// 8. 注销本地内存段
urma_unregister_seg(tseg);

// 9. 删除事件通道
if (jfce) urma_delete_jfce(jfce);

// 10. 删除上下文
urma_delete_context(ctx);

// 11. 释放设备列表
urma_free_device_list(dev_list);

// 12. 反初始化 URMA
urma_uninit();
```

**要点**：顺序必须为：
1. 解绑 (RC) - **必须最先**
2. 取消导入 Jetty - **必须在解绑之后**
3. 取消导入段 - **必须在注销本地段之前**
4. 删除 Jetty/JFR - **必须在所有取消导入之后**
5. 删除 JFC - **在 Jetty/JFR 删除之后**
6. 注销段 - **在使用它的所有资源删除之后**
7. 删除上下文/反初始化 - **最后**

在 delete 之前跳过 unbind/unimport 会导致资源泄漏。

---

## 9. 内联 Send 优化

```c
int post_send_inline(urma_jetty_t *jetty, urma_target_jetty_t *tjetty,
                     urma_target_seg_t *local_tseg,
                     uint8_t *buf, uint32_t len, uint64_t wr_id) {
    urma_sge_t sge = {0};
    urma_jfs_wr_t wr = {0};
    urma_jfs_wr_t *bad_wr = NULL;

    sge.addr = (uint64_t)buf;
    sge.len = len;

    wr.opcode = URMA_OPC_SEND;
    wr.flag.value = 0;
    wr.flag.bs.complete_enable = 1;
    wr.tjetty = tjetty;
    wr.user_ctx = wr_id;
    wr.send.src.sge = &sge;
    wr.send.src.num_sge = 1;

    // 检查消息是否适合内联缓冲区
    if (len <= jetty->jetty_cfg->jfs_cfg.max_inline_data) {
        wr.flag.bs.inline_flag = 1;  // 启用内联模式
        // 内联时 tseg 可以为 NULL
    } else {
        sge.tseg = local_tseg;  // 使用已注册内存
    }

    return urma_post_jetty_send_wr(jfs, &wr, &bad_wr);
}
```

**使用场景**：
| 消息大小 | 建议 |
|--------------|----------------|
| < 64 字节 | 始终使用内联 |
| 64-256 字节 | 如果 max_inline_data 支持则使用内联 |
| > 256 字节 | 使用已注册内存 |

---

## 10. 链式 WR 批量发送

```c
#define BATCH_SIZE 32

typedef struct {
    urma_jfs_t *jfs;
    urma_jfc_t *jfc;
    urma_target_seg_t *local_tseg;
} batch_sender_t;

int batch_send(batch_sender_t *sender, uint8_t **bufs, uint32_t *lens, int count) {
    urma_jfs_wr_t wrs[BATCH_SIZE];
    urma_jfs_wr_t *bad_wr;
    int sent = 0;

    for (int i = 0; i < count && i < BATCH_SIZE; i++) {
        memset(&wrs[i], 0, sizeof(wrs[i]));

        wrs[i].opcode = URMA_OPC_SEND;
        wrs[i].flag.bs.complete_enable = 1;
        wrs[i].user_ctx = (uint64_t)i;

        // 小消息使用内联
        if (lens[i] <= sender->jfs->jfs_cfg.max_inline_data) {
            wrs[i].flag.bs.inline_flag = 1;
        }

        wrs[i].send.src.sge = &(urma_sge_t){
            .addr = (uint64_t)bufs[i],
            .len = lens[i],
            .tseg = sender->local_tseg
        };
        wrs[i].send.src.num_sge = 1;

        // 链接 WR
        if (i > 0) {
            wrs[i-1].next = &wrs[i];
        }
    }

    // 投递批量
    if (urma_post_jetty_send_wr(sender->jfs, &wrs[0], &bad_wr) != URMA_SUCCESS) {
        return -1;
    }

    return count;
}
```

---

## 11. RM vs RC 模式设置

### RM 模式（独立 JFS + JFR）

```c
// 创建独立的 JFS 用于发送
urma_jfs_cfg_t jfs_cfg = {
    .depth = 16,
    .trans_mode = URMA_TM_RM,
    .priority = 0,
    .max_sge = 1,
    .jfc = jfc
};
urma_jfs_t *jfs = urma_create_jfs(ctx, &jfs_cfg);

// 创建独立的 JFR 用于接收
urma_jfr_cfg_t jfr_cfg = {
    .depth = 16,
    .trans_mode = URMA_TM_RM,
    .jfc = jfc
};
urma_jfr_t *jfr = urma_create_jfr(ctx, &jfr_cfg);

// 导入远端 JFR（无需 bind）
urma_rjfr_t rjfr = {
    .jfr_id = remote_jfr_id,
    .trans_mode = URMA_TM_RM,
    .flag.value = 0,
    .tp_type = URMA_RTP
};
urma_target_jfr_t *tjfr = urma_import_jfr(ctx, &rjfr, &token);
```

### RC 模式（单 Jetty）

```c
urma_jetty_cfg_t jetty_cfg = {
    .id = 0,
    .jfs_cfg = { .depth = 16, .trans_mode = URMA_TM_RC, .jfc = jfc },
    .shared.jfc = jfc
};
urma_jetty_t *jetty = urma_create_jetty(ctx, &jetty_cfg);

// RC 模式需要 import + bind
urma_rjetty_t rjetty = {
    .jetty_id = remote_jetty_id,
    .trans_mode = URMA_TM_RC,
    .policy = URMA_JETTY_GRP_POLICY_RR,
    .type = URMA_JETTY,
    .flag.value = 0,
    .tp_type = URMA_RTP
};
urma_target_jetty_t *tjetty = urma_import_jetty(ctx, &rjetty, &token);
urma_bind_jetty(jetty, tjetty);  // RC 模式需要 bind
```

### 选择指南

| 场景 | 推荐模式 |
|----------|------------------|
| 双向通信 | 独立模式 (RM) |
| 简单请求-响应 | 统一模式 (RC) |
| 需要多路径支持 | 独立模式 (RM) |
| 更低资源占用 | 统一模式 (RC) |

---

## 12. Token 管理

### Token 生命周期

```
注册：  local_seg = urma_register_seg(ctx, &seg_cfg)  // token = 0x1234
     ↓
交换：  通过 TCP/Socket 将 token 发送到远端
     ↓
导入：  remote_seg = urma_import_seg(ctx, &seg, &token, ...)  // 必须匹配！
     ↓
访问：  RDMA 读/写操作
```

### Token 生成

```c
#include <openssl/rand.h>

urma_token_t generate_token(void) {
    urma_token_t token;
    int ret = RAND_priv_bytes((unsigned char *)&token.token, sizeof(token.token));
    if (ret != 1) {
        token.token = 0xABCDEF;  // 回退到固定 token
    }
    return token;
}
```

### Token 交换

```c
// 发送本地 token
write(sockfd, &local_token.token, sizeof(local_token.token));

// 接收远端 token
urma_token_t remote_token;
read(sockfd, &remote_token.token, sizeof(remote_token.token));

// 使用远端 token 进行导入
urma_target_seg_t *dst_tseg = urma_import_seg(ctx, &seg, &remote_token, 0, flag);
```

### Token 匹配规则

| 本地策略 | 远端策略 | 是否需要 Token |
|--------------|---------------|----------------|
| `URMA_TOKEN_NONE` | `URMA_TOKEN_NONE` | 否 |
| `URMA_TOKEN_PLAIN_TEXT` | `URMA_TOKEN_PLAIN_TEXT` | 是（必须匹配） |
| `URMA_TOKEN_NONE` | `URMA_TOKEN_PLAIN_TEXT` | 是（远端要求） |

---

## 13. 端口状态检查

```c
int check_urma_device_state(char *dev_name) {
    urma_device_t *urma_dev = urma_get_device_by_name(dev_name);
    if (urma_dev == NULL) {
        fprintf(stderr, "未找到设备 %s\n", dev_name);
        return -1;
    }

    urma_device_attr_t dev_attr;
    if (urma_query_device(urma_dev, &dev_attr) != URMA_SUCCESS) {
        fprintf(stderr, "查询设备 %s 失败\n", dev_name);
        return -1;
    }

    for (uint32_t port_idx = 0; port_idx < dev_attr.port_cnt; port_idx++) {
        if (dev_attr.port_attr[port_idx].state == URMA_PORT_ACTIVE) {
            return port_idx + 1;  // 返回从 1 开始的端口号
        }
    }

    fprintf(stderr, "设备 %s 上未找到活跃端口\n", dev_name);
    return -1;
}
```

---

## 14. EID 索引处理

```c
uint32_t get_urma_eid_index(urma_device_t *urma_dev, urma_eid_t *eid) {
    uint32_t eid_cnt;
    urma_eid_info_t *eid_list = urma_get_eid_list(urma_dev, &eid_cnt);
    if (eid_list == NULL) {
        return UINT32_MAX;
    }

    // 如果 eid 为 NULL，返回第一个可用索引
    for (uint32_t i = 0; i < eid_cnt; i++) {
        if (eid == NULL || memcmp(eid->raw, eid_list[i].eid.raw, 16) == 0) {
            uint32_t index = eid_list[i].eid_index;
            urma_free_eid_list(eid_list);
            return index;
        }
    }

    urma_free_eid_list(eid_list);
    return UINT32_MAX;
}
```

### 使用示例

```c
urma_device_t *dev = urma_get_device_by_name("ubcore0");
uint32_t eid_index = get_urma_eid_index(dev, NULL);  // 获取第一个 EID
urma_context_t *ctx = urma_create_context(dev, eid_index);
```

---

## 15. 大页支持

```c
#include <ub/ub_hugepage.h>

#define HUGE_PAGE_2MB 2
#define HUGE_PAGE_1GB 1024

urma_target_seg_t *register_with_hugepage(urma_context_t *ctx,
                                           size_t len, int hugepage_size) {
    // 分配大页内存
    void *buf = ub_hugemalloc(len, hugepage_size, NULL);
    if (!buf) return NULL;
    memset(buf, 0, len);

    // 使用 URMA 注册
    urma_seg_cfg_t seg_cfg = {
        .va = (uint64_t)buf,
        .len = len,
        .token_id = NULL,
        .token_value.token = 0,
        .flag.bs.token_policy = URMA_TOKEN_NONE,
        .flag.bs.cacheable = URMA_NON_CACHEABLE,
        .flag.bs.access = URMA_ACCESS_LOCAL_ONLY,
        .flag.bs.token_id_valid = 0,
        .flag.bs.reserved = 0,
        .user_ctx = 0,
        .iova = 0
    };

    urma_target_seg_t *tseg = urma_register_seg(ctx, &seg_cfg);
    if (!tseg) {
        ub_hugefree(buf, len);
        return NULL;
    }

    return tseg;
}

void unregister_with_hugepage(urma_target_seg_t *tseg, void *buf, size_t len) {
    urma_unregister_seg(tseg);
    ub_hugefree(buf, len);
}
```

**要点**：
- 使用 `ub_hugemalloc()` 分配
- 使用 `ub_hugefree()` 释放（不是 `free()`）
- 分配后使用 `urma_register_seg()` 注册

---

## 16. JFC 深度约束

### 关键约束

```
JFC 深度必须 >= JFR 深度 + JFS 深度
```

### 深度建议

```
JFC 深度 >= 关联 Jetty 队列深度之和 / CR 生成间隔 + 关联 Jetty 数量
```

### 示例

```c
// 已知：JFR 深度 = 64，JFS 深度 = 16
urma_jfc_cfg_t jfc_cfg = {
    .depth = 64 + 16,  // 必须 >= JFR + JFS 深度
    .jfce = NULL,
    .user_ctx = 0
};
urma_jfc_t *jfc = urma_create_jfc(ctx, &jfc_cfg);
```

---

## 17. 缓冲区布局最佳实践

### 推荐布局

```
缓冲区布局（用于 RDMA 操作）：
[0, MSG_SIZE-1]              : 本地发送缓冲区 / RDMA 源
[MSG_SIZE, 2*MSG_SIZE-1]     : 本地接收缓冲区
[2*MSG_SIZE, MEM_SIZE-1]     : 接收池（用于预投递接收）
```

### 示例

```c
#define MSG_SIZE 4096
#define MEM_SIZE 0x100000  // 1MB
#define RECV_POOL_START (2 * MSG_SIZE)

void *buf = memalign(PAGE_SIZE, MEM_SIZE);

// 从偏移 0 发送
urma_sge_t send_sge = {
    .addr = (uint64_t)buf,
    .len = MSG_SIZE,
    .tseg = local_tseg
};

// 从接收池预投递接收
for (int i = 0; i < BATCH_SIZE; i++) {
    uint64_t offset = RECV_POOL_START + i * MSG_SIZE;
    urma_sge_t recv_sge = {
        .addr = (uint64_t)buf + offset,
        .len = MSG_SIZE,
        .tseg = local_tseg
    };
    // ... 使用 recv_sge 投递接收 ...
}
```

---

## 18. 错误处理迁移

### Verbs 错误处理模式

Verbs 的错误处理基于两种约定：
- 返回指针的函数（`ibv_open_device`, `ibv_create_cq` 等）：NULL 表示失败，`errno` 设置原因
- 返回整数的函数（`ibv_poll_cq`, `ibv_post_send` 等）：0 或负数表示失败

```c
// Verbs 指针返回 - 检查 NULL
struct ibv_cq *cq = ibv_create_cq(ctx, 128, NULL, NULL, 0);
if (!cq) {
    perror("ibv_create_cq");
    exit(1);
}

// Verbs 整数返回 - 检查负值
int ne = ibv_poll_cq(cq, 1, &wc);
if (ne < 0) {
    fprintf(stderr, "poll CQ failed\n");
}
```

### URMA 错误处理模式

URMA 的返回值语义不统一，必须按类别区分（详见 mapping.md 错误码章节）：

```c
// 1. 资源管理类 - 返回 0 表示成功
int status = urma_init(&init_attr);
if (status != URMA_SUCCESS) {   // URMA_SUCCESS == 0
    fprintf(stderr, "urma_init failed: %d\n", status);
    return 1;
}

status = urma_register_seg(ctx, &seg_cfg, &local_seg);
if (status != URMA_SUCCESS) {
    fprintf(stderr, "urma_register_seg failed: %d\n", status);
    return 1;
}

status = urma_create_jfc(ctx, &jfc_cfg, &jfc);
if (status != URMA_SUCCESS) {
    fprintf(stderr, "urma_create_jfc failed: %d\n", status);
    return 1;
}

// 2. 轮询/等待类 - 返回 >0 表示成功（返回计数）
int cnt = urma_poll_jfc(jfc, 16, crs);
if (cnt > 0) {
    // 成功，cnt 为完成记录数
    for (int i = 0; i < cnt; i++) {
        process_cr(&crs[i]);
    }
} else if (cnt == 0) {
    // 无完成事件（非错误）
} else {
    // cnt < 0 表示错误
    fprintf(stderr, "urma_poll_jfc failed: %d\n", cnt);
}

urma_jfc_t *ev_jfc = NULL;
cnt = urma_wait_jfc(jfce, 1, timeout_ms, &ev_jfc);
if (cnt > 0) {
    // 成功，收到事件
    urma_ack_jfc(&ev_jfc, &(uint32_t){1}, 1);  // 必须调用！
} else if (cnt == 0) {
    // 超时，无事件
} else {
    // 错误
    fprintf(stderr, "urma_wait_jfc failed: %d\n", cnt);
}

// 3. 指针返回类 - 返回非 NULL 表示成功
urma_context_t *ctx = urma_create_context(dev);
if (!ctx) {
    fprintf(stderr, "urma_create_context failed\n");
    return 1;
}

urma_jfce_t *jfce = urma_create_jfce(ctx);
if (!jfce) {
    fprintf(stderr, "urma_create_jfce failed\n");
    goto cleanup_context;
}
```

### 关键差异

- **Verbs 使用 `errno` / `perror()`** → **URMA 使用返回值直接判断**：URMA 函数不设置 `errno`，错误信息通过返回值获取
- **`ibv_poll_cq()` 返回 0 表示无事件** → **`urma_poll_jfc()` 也返回 0 表示无事件**，但必须区分"0=无事件"和"<0=错误"，不能统一用 `<= 0` 处理
- **Verbs 的 `ibv_wc.status` 检查** → **URMA 的 `cr.status` 检查**：语义相同，但枚举名不同（见 mapping.md 完成状态映射）
- **常见迁移错误**：将 `urma_poll_jfc()` 返回值用 `if (cnt)` 或 `if (cnt != 0)` 判断——这会把错误码也当作成功处理。正确写法是 `if (cnt > 0)`

---

## 19. 设备类型处理

UB 设备与其他设备在内存管理上有所不同：

```c
// 根据设备类型选择内存释放方式
if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
    munmap(ctx->va, MEM_SIZE);  // UB 设备使用 munmap
} else {
    free(ctx->va);              // 其他设备使用 free
}
```

---
## 添加新示例

创建新的迁移模式时：

1. 确定模式分类
2. 同时提供 Verbs 和 URMA 版本
3. 在注释中包含关键差异
4. 引用 `mapping.md` 获取 API 名称

格式：
```markdown
## 分类名称

### URMA 版本
```c
// URMA 代码
```

### 关键差异
- 要点 1
- 要点 2
```
