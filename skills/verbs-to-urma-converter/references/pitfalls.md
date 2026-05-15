# 常见陷阱与解决方案

> URMA API 版本: 25.12.0
> **重要**：遇到新问题时，请添加到此处以帮助后续迁移。

---

## 1. Token 管理

### 问题
URMA 内存注册和远端访问需要安全 token。token 使用错误会导致失败。

### 症状
```
段注册失败
导入远端段失败
访问拒绝错误
```

### 错误
```c
// 缺少 token
urma_seg_cfg_t seg_cfg = { .token_value.token = 0, /* ... */ };

// token 策略不匹配
seg_cfg.token_value.token = 0;
seg_cfg.flag.bs.token_policy = URMA_TOKEN_PLAIN_TEXT;  // 冲突！
```

### 正确
```c
// 使用安全策略的非零 token
urma_seg_cfg_t seg_cfg = {
    .token_value.token = 0xABCDEF,  // 必须非零！
    .flag.bs.token_policy = URMA_TOKEN_PLAIN_TEXT,
    // ...
};

// 或者 token=0 时使用 URMA_TOKEN_NONE
seg_cfg.token_value.token = 0;
seg_cfg.flag.bs.token_policy = URMA_TOKEN_NONE;

// 或者分配 token ID
urma_token_id_t *token_id = urma_alloc_token_id(ctx);
seg_cfg.token_id = token_id;
// 记得释放：urma_free_token_id(token_id);
```

### Token 策略要求

| 策略 | Token 值要求 |
|--------|------------------------|
| `URMA_TOKEN_NONE` | 可以为 0 |
| `URMA_TOKEN_PLAIN_TEXT` | 必须非零 |
| `URMA_TOKEN_SIGNED` | 必须非零 |
| `URMA_TOKEN_ALL_ENCRYPTED` | 必须非零 |

### Token 交换
```c
// 通过 TCP/Socket 交换
write(sockfd, &local_token.token, sizeof(local_token.token));
read(sockfd, &remote_token.token, sizeof(remote_token.token));
// 双方必须使用相同的 token
```

### 相关
- `urma_register_seg()` - 当 `token_policy != URMA_TOKEN_NONE` 时需要非零 token
- `urma_import_seg()` - 需要 token 与注册段匹配
- `urma_import_jetty()` - 如果 JFR 有 token，jetty 也需要 token

### Token 不匹配

本地和远端使用不同的 token 会导致导入失败。常见原因：未交换 token、token 策略不匹配。

```c
// 正确：通过 TCP/Socket 交换 token
// 本地端发送 token
write(sockfd, &local_token.token, sizeof(local_token.token));

// 远端接收 token
read(sockfd, &remote_token.token, sizeof(remote_token.token));

// 双方使用相同的 token
urma_import_seg(ctx, &seg, &remote_token, 0, flag);
```

---

## 2. 清理顺序

### 问题
错误的清理顺序导致资源泄漏或崩溃。

### 错误
```c
urma_delete_jfc(jfc);      // JFC 在 Jetty 之前删除！
urma_delete_jetty(jetty);  // 崩溃！
```

### 正确
```c
urma_modify_jetty(jetty, &(urma_jetty_attr_t){ .mask = JETTY_STATE, .state = URMA_JETTY_STATE_ERROR });
urma_unbind_jetty(jetty);
urma_unimport_jetty(tjetty);
urma_delete_jetty(jetty);
urma_delete_jfr(jfr);
urma_delete_jfc(jfc);
urma_unregister_seg(tseg);
if (jfce) urma_delete_jfce(jfce);
urma_delete_context(ctx);
urma_uninit();
```

---

## 3. JFC 深度不足

### 问题
JFC 深度 < JFR 深度 + JFS 深度导致完成事件丢失和潜在数据丢失。

### 症状
```
完成事件丢失
程序挂起等待完成
数据不完整
```

### 错误
```c
// JFR 深度 = 64，JFS 深度 = 16
// 需要 JFC 深度 = 64 + 16 = 80
urma_jfc_cfg_t jfc_cfg = { .depth = 32 };  // 太小！
```

### 正确
```c
urma_jfc_cfg_t jfc_cfg = {
    .depth = jfr_depth + jfs_depth,  // 最小值：深度之和
    .jfce = NULL,
    .user_ctx = 0
};

// 推荐：2 倍安全裕量
urma_jfc_cfg_t jfc_cfg = {
    .depth = (jfr_depth + jfs_depth) * 2,
    .jfce = NULL,
    .user_ctx = 0
};
```

### 深度计算公式

```
最小 JFC 深度 = JFR 深度 + JFS 深度
推荐 JFC 深度 = (JFR 深度 + JFS 深度) * 2
```

### 计算示例

| 组件 | 深度 |
|-----------|-------|
| JFR（接收队列） | 64 |
| JFS（发送队列） | 16 |
| **最小 JFC** | 80 |
| **推荐 JFC** | 160 |

### 相关
- `urma_create_jfc()` - JFC 创建
- `urma_create_jfr()` - JFR 创建
- `urma_create_jetty()` - Jetty 创建（包含 JFS）

---

## 4. 轮询限制超限

### 问题
每次调用轮询超过 16 条完成记录会导致错误。

### 症状
```
轮询返回错误
程序异常
```

### 错误
```c
urma_cr_t cr[32];
urma_poll_jfc(jfc, 32, cr);  // 错误！
```

### 正确
```c
urma_cr_t cr[16];
urma_poll_jfc(jfc, 16, cr);  // 每次最多 16 条
```

### 限制
RDMA 设备每次调用最多轮询 **16 条完成记录**。

### 相关
- `urma_poll_jfc()` - JFC 轮询

---

## 5. 遗漏 urma_ack_jfc()

### 问题
`urma_wait_jfc()` 之后忘记调用 `urma_ack_jfc()` 会导致**资源泄漏和系统不稳定**。

### 症状
```
事件通道耗尽
系统不稳定
无法再接收事件
```

### 错误
```c
urma_wait_jfc(jfce, 1, timeout, &ev_jfc);
urma_poll_jfc(jfc, 1, &cr);
// 缺少 urma_ack_jfc()！
```

### 正确
```c
urma_wait_jfc(jfce, 1, timeout, &ev_jfc);
urma_rearm_jfc(jfc, false);
urma_poll_jfc(jfc, 1, &cr);
uint32_t ack_cnt = 1;
urma_ack_jfc(&ev_jfc, &ack_cnt, 1);  // 必须
```

### 事件模式序列

**必须的序列**：`wait → rearm → poll → ack`

遗漏任何步骤会导致：
- 遗漏 `rearm`：不再触发后续事件
- 遗漏 `ack`：资源泄漏，系统可能挂起
- 错误的 `ev_jfc`：未定义行为

完整事件模式代码示例见 `patterns.md §3`。

### 验证规则
- `urma_wait_jfc()` - 等待事件
- `urma_ack_jfc()` - 确认事件（必须）
- `urma_rearm_jfc()` - 重新装填以接收下一个事件

---

## 6. EID vs GID 格式

### 问题
Verbs 使用 8 字节 GID。URMA 使用 16 字节 EID。直接转换会失败。

### 错误
```c
memcpy(eid->raw, gid->raw, 8);  // 只复制了 8 字节！
```

### 正确
```c
// 使用转换函数
wire_gid_to_gid(wgid_str, &eid);
gid_to_wire_gid(&eid, wgid_str);
```

---

## 7. 内联 Send 未检查大小

### 问题
设置 `inline_flag` 但未验证消息大小是否适合设备的内联缓冲区。

### 症状
```
数据损坏
发送操作失败
消息被静默截断
```

### 错误
```c
wr.flag.bs.inline_flag = 1;  // 总是内联！
```

### 正确
```c
if (len <= jfs->jfs_cfg.max_inline_data) {
    wr.flag.bs.inline_flag = 1;
    // 内联时 tseg 可以为 NULL
} else {
    wr.flag.bs.inline_flag = 0;
    sge.tseg = local_tseg;
}
```

### 大小指南
| 消息大小 | 是否内联？ | 需要的 max_inline_data |
|--------------|---------|--------------------------|
| < 64 字节 | 是 | 任意 |
| 64-256 字节 | 可能 | 检查设备能力 |
| > 256 字节 | 否 | 不适用 |

### 相关
- `urma_jfs_cfg_t.max_inline_data` - 设备内联限制
- `urma_jfs_wr_flag_t.bs.inline_flag` - 内联启用标志

---

## 8. 远端 Jetty 未绑定

### 问题
在 Jetty 绑定之前尝试发送。

### 错误
```c
// 创建后立即发送，未 import/bind
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);  // 可能失败！
```

### 正确
```c
// 发送前始终检查 remote_jetty 是否已设置
if (jetty->remote_jetty == NULL) {
    // 尚未连接 - 等待或处理错误
}
```

---

## 9. 地址交换格式

### 问题
在 URMA 代码中使用 Verbs 地址交换格式（包含 LID）。

### 错误
```c
sprintf(msg, "%04x:%06x:%06x:%s", lid, qpn, psn, gid);  // 包含 LID！
sprintf(msg, "%06x:%06x:%s", jpn, psn, eid_str);  // 包含 PSN！
```

### 正确
```c
sprintf(msg, "%06x:%s", jpn, eid_str);  // 仅 jpn:eid，无 LID，无 PSN！
```

### 相关
- 完整地址交换代码见 `patterns.md §7`
- EID 宏（EID_FMT, EID_ARGS）见 `mapping.md`

---

## 10. 缺少 share_jfr 标志

### 问题
创建带共享 JFR 的 Jetty 时遗漏了标志。

### 症状
```
无法创建带共享 SRQ 的 Jetty
```

### 错误
```c
urma_jetty_cfg_t jetty_cfg = {0};
jetty_cfg.shared.jfr = srq;  // 缺少标志！
```

### 正确
```c
urma_jetty_cfg_t jetty_cfg = {0};
jetty_cfg.flag.bs.share_jfr = 1;  // 关键！
jetty_cfg.shared.jfr = srq;
```

### 重要说明
- `jetty_cfg.flag.bs.share_jfr` 必须设置为 1
- 所有 Jetty 共享同一个 `urma_jfr_t` 指针
- 向共享 JFR 投递接收请求，而不是向各个 Jetty

### 相关 API
- `urma_create_jfr()` - 创建 SRQ 等价物
- `urma_delete_jfr()` - 销毁 SRQ
- `urma_post_jfr_wr()` - 向共享队列投递

---

## 11. 大页内存错误释放

### 问题
对 `ub_hugemalloc()` 分配的内存使用 `free()` 会导致损坏。

### 症状
```
段错误
内存损坏
双重释放错误
```

### 错误
```c
void *buf = ub_hugemalloc(size, hugepage_size, NULL);
free(buf);  // 崩溃！
```

### 正确
```c
ub_hugefree(buf, size);
```

### 模式
```c
typedef struct {
    void *buf;
    size_t len;
    int is_hugepage;
} buffer_t;

void safe_free(buffer_t *b) {
    if (b->is_hugepage) {
        ub_hugefree(b->buf, b->len);
    } else {
        free(b->buf);
    }
    free(b);
}
```

### 相关
- `ub_hugemalloc()` - 分配大页内存
- `ub_hugefree()` - 释放大页内存

---

## 12. UB 设备内存错误释放

### 问题
对 UB 传输设备的内存使用 `free()` 会导致错误。

### 症状
```
内存泄漏
双重释放损坏
段错误
```

### 错误
```c
free(ctx->va);  // 对 UB 设备可能是错误的
```

### 正确
```c
if (ctx->urma_ctx->dev->type == URMA_TRANSPORT_UB) {
    munmap(ctx->va, MEM_SIZE);  // UB 设备使用 munmap
} else {
    free(ctx->va);              // 其他设备使用 free
}
```

### 设备类型
| 设备类型 | 分配 | 释放 |
|-------------|------------|--------------|
| UB | `mmap()` | `munmap()` |
| 其他 | `malloc()/memalign()` | `free()` |

### 相关
- `urma_context_t.dev->type` - 设备类型字段
- `URMA_TRANSPORT_UB` - UB 传输类型

---

## 13. 远端 Jetty 缺少 tp_type

### 问题
未在 `urma_rjetty_t` 中设置 `tp_type`。

### 错误
```c
urma_rjetty_t rjetty = {
    .jetty_id = remote_id,
    .trans_mode = URMA_TM_RC,
    // tp_type 缺失！
};
```

### 正确
```c
urma_rjetty_t rjetty = {
    .jetty_id = remote_id,
    .trans_mode = URMA_TM_RC,
    .tp_type = URMA_RTP,  // 关键！
    // ...
};
```

---

## 14. urma_init() 未在 URMA API 之前调用

### 问题
在 `urma_init()` 之前调用 `urma_get_device_list()` 等 URMA API。

### 错误
```c
// urma_get_device_list 在 urma_init 之前调用！
urma_device_t **dev_list = urma_get_device_list(&num_devices);
urma_init(&init_attr);  // 太迟了！
```

### 正确
```c
// urma_init 必须最先调用
urma_init(&init_attr);
urma_device_t **dev_list = urma_get_device_list(&num_devices);
```

**关键**：`urma_init()` 必须在任何 URMA API 之前调用，包括 `urma_get_device_list()`。

---

## 15. 多次调用 urma_init()

### 问题
多次调用 `urma_init()`。

### 错误
```c
void create_resources() {
    urma_init(&init_attr);  // 被多次调用！
}
```

### 正确
```c
// 程序启动时调用一次
urma_init(&init_attr);
// ... 所有操作 ...
// 程序退出时调用一次
urma_uninit();
```

---

## 16. 内存对齐

### 问题
未对齐的内存导致性能问题或失败。

### 解决方案
```c
// 使用对齐内存分配
#include <stdlib.h>

// 页对齐
long page_size = sysconf(_SC_PAGESIZE);
void *buf = memalign(page_size, size);

// 或缓存行对齐以获得最佳性能
void *buf;
posix_memalign(&buf, 64, size);  // 64 字节缓存行
```

---

## 17. 事件通道使用

### 问题
轮询模式和事件模式混用。

### 解决方案
```c
// 轮询模式 - 无事件通道
urma_jfc_cfg_t jfc_cfg = {
    .jfce = NULL,  // 无事件
    // ...
};

// 事件驱动模式
urma_jfce_t *jfce = urma_create_jfce(ctx);
urma_jfc_cfg_t jfc_cfg = {
    .jfce = jfce,  // 使用事件
    // ...
};
```

---

## 18. 工作请求标志

### 问题
遗漏标志导致操作不完成或不生成完成记录。

### 解决方案
```c
// 请求完成通知
wr.flag.bs.complete_enable = 1;

// 请求远端事件
wr.flag.bs.solicited_enable = 1;

// 栅栏（用于读/原子操作）
wr.flag.bs.fence = 1;

// 内联数据（无 sge 复制）
wr.flag.bs.inline_flag = 1;
```

---

## 19. EID 索引处理

### 问题
创建上下文时使用错误的 EID 索引。

### 解决方案
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

---

## 20. Jetty 创建缺少 JFR

### 问题
`jfr_cfg` 已废弃，所有传输模式 (RC/RM/UM) 必须先显式创建 JFR 然后共享。

### 症状
```
无法创建 Jetty
无效配置
```

### 错误
```c
// 错误 1：使用废弃的 jfr_cfg
urma_jetty_cfg_t jetty_cfg = {
    .jfr_cfg = &jfr_cfg,  // 已废弃！
    .jfs_cfg = { ... }
};

// 错误 2：shared 未设置
urma_jetty_cfg_t jetty_cfg = {
    .jfs_cfg = { ... }
    // 缺少 shared 字段！
};
```

### 正确
```c
// 1. 先创建 JFR（所有模式必需）
urma_jfr_cfg_t jfr_cfg = {
    .depth = 64,
    .trans_mode = URMA_TM_UM,  // 必须与 Jetty 的 trans_mode 匹配
    .jfc = jfc,
    .flag.bs.token_policy = URMA_TOKEN_NONE,
    .flag.bs.order_type = URMA_DEF_ORDER
};
urma_jfr_t *jfr = urma_create_jfr(ctx, &jfr_cfg);

// 2. 创建 Jetty 并共享 JFR
urma_jetty_cfg_t jetty_cfg = {
    .flag.bs.share_jfr = URMA_SHARE_JFR,  // 必须设置！
    .jfs_cfg = {
        .depth = 1,
        .trans_mode = URMA_TM_UM,  // 必须与 JFR 的 trans_mode 匹配
        .jfc = jfc,
        .flag.bs.order_type = URMA_DEF_ORDER
    },
    .shared = {
        .jfr = jfr,   // 指向创建的 JFR
        .jfc = jfc    // 可选：替换 jfc
    }
};
urma_jetty_t *jetty = urma_create_jetty(ctx, &jetty_cfg);
```

### 必需检查清单（所有模式）
- [ ] 调用 urma_create_jfr() 创建接收队列
- [ ] 设置 jetty_cfg.flag.bs.share_jfr = URMA_SHARE_JFR
- [ ] 设置 jetty_cfg.shared.jfr = 上面创建的 JFR
- [ ] JFR.trans_mode == Jetty.jfs_cfg.trans_mode
- [ ] JFR.flag.bs.order_type == Jetty.jfs_cfg.flag.bs.order_type
- [ ] 调用 urma_import_jetty() 获取远端 Jetty（所有模式！）
- [ ] 发送前设置 wr.tjetty = 导入的目标 Jetty

### 相关 API
- `urma_create_jfr()` - 创建接收队列
- `urma_create_jetty()` - 创建带共享 JFR 的发送队列
- `URMA_SHARE_JFR` - 启用 JFR 共享的标志
- `urma_delete_jfr()` - 销毁 JFR
- `urma_import_jetty()` - 导入远端 Jetty（所有模式必需！）
- `urma_unimport_jetty()` - 释放导入的 Jetty

---

## 21. 发送工作请求中缺少 tjetty

### 问题
所有传输模式 (RC/RM/UM) 的发送工作请求必须设置 tjetty 字段为导入的远端 Jetty。

### 症状
```
发送操作失败
操作超时
无数据发送
```

### 错误
```c
// 缺少 tjetty - 发送将失败
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_SEND,
    .flag.bs.complete_enable = 1,
    // .tjetty 未设置！
    .send = { .src = { .sge = &sge, .num_sge = 1 } }
};
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### 正确
```c
// 1. 导入远端 Jetty（所有模式必需！）
urma_rjetty_t rjetty = {
    .jetty_id = { .eid = remote_eid, .uasid = 0, .id = remote_jpn },
    .trans_mode = URMA_TM_UM,
    .type = URMA_JETTY,
    .tp_type = URMA_UTP,  // UM 模式使用 UTP
    .flag.bs.order_type = URMA_DEF_ORDER
};
urma_target_jetty_t *tjetty = urma_import_jetty(ctx, &rjetty, &token);

// 2. 在发送 WR 中设置 tjetty
urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_SEND,
    .flag.bs.complete_enable = 1,
    .tjetty = tjetty,  // 关键 - 必须设置！
    .send = { .src = { .sge = &sge, .num_sge = 1 } }
};
urma_post_jetty_send_wr(jetty, &wr, &bad_wr);
```

### 按传输模式的 tp_type
| 模式 | tp_type | 说明 |
|------|---------|-------------|
| RC | `URMA_RTP` | 可靠传输协议 |
| RM | `URMA_RTP` | 可靠传输协议 |
| UM | `URMA_UTP` | 不可靠传输协议 |

> **检查要点**：地址交换后调用 import_jetty()、存储 tjetty 指针、每次发送前设置 wr.tjetty、按模式设置 tp_type、清理时 unimport_jetty()。

### 相关 API
- `urma_import_jetty()` - 导入远端 Jetty
- `urma_unimport_jetty()` - 释放导入的 Jetty
- `urma_post_jetty_send_wr()` - 设置 tjetty 后发送

---

## 22. RDMA 操作缺少 urma_import_seg()

### 问题
RDMA 读/写/原子操作中，远端内存段的 `tseg` 字段必须通过 `urma_import_seg()` 获取。设置 `tseg = NULL` 会导致运行时失败。

### 症状
```
RDMA 读/写操作失败
RDMA 操作时段错误
无效参数错误
```

### 错误
```c
// ❌ tseg 设为 NULL - 运行时将失败！
urma_sge_t dst_sge = {
    .addr = remote_va,
    .len = length,
    .tseg = NULL  // 错误！
};

urma_jfs_wr_t wr = {
    .opcode = URMA_OPC_WRITE,
    .rw = { .dst = { .sge = &dst_sge, .num_sge = 1 }, ... }
};
```

### 正确
```c
// 步骤 1：在连接阶段导入远端段
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

// 步骤 2：在 RDMA 操作中使用导入的 tseg
urma_sge_t dst_sge = {
    .addr = remote_va,
    .len = length,
    .tseg = import_tseg  // 正确！
};
```

### 与 Verbs 的区别

| Verbs | URMA |
|-------|------|
| `sge.lkey` 是本地整数键 | `sge.tseg` 是指向 `urma_target_seg_t` 的指针 |
| 直接使用 `rkey` 进行远端访问 | 必须先调用 `urma_import_seg()` 获取 `tseg` |

### 完整生命周期

```
1. 交换阶段：    交换远端段信息 (seg.ubva.va, seg.len 等)
2. 连接阶段：    urma_import_seg() 导入远端内存段
3. 操作阶段：    使用 import_tseg 进行 RDMA 读/写/原子操作
4. 清理阶段：    urma_unimport_seg() 释放引用
```

### 清理顺序

必须在注销本地段之前取消导入远端段：

```c
// 正确的清理顺序
urma_unimport_seg(import_tseg);     // 首先：取消导入远端段
urma_unregister_seg(local_tseg);    // 然后：注销本地段
```

> **检查要点**：连接阶段 import_seg()、存储 import_tseg、RDMA 操作使用 import_tseg（WRITE 设 dst_sge.tseg，READ 设 src_sge.tseg）、清理时 unimport_seg 在 unregister_seg 之前。

### 相关 API
- `urma_import_seg()` - 导入远端内存段
- `urma_unimport_seg()` - 释放导入的段
- `urma_post_jetty_send_wr()` - 使用正确 tseg 投递 RDMA 读/写

---

## 23. 段交换不完整

### 问题
交换 RDMA 操作的段信息时，复制单个字段而非整个 `urma_seg_t` 结构体会导致遗漏 `token_id` 等字段，而 `urma_import_seg()` 需要这些字段。

### 症状
```
urma_import_seg() 失败
无效 token_id 错误
RDMA 读/写操作失败
```

### 错误
```c
// ❌ 不完整 - 仅复制了部分字段
remote->seg.ubva.eid = ctx->eid;
remote->seg.ubva.uasid = ctx->uasid;
remote->seg.ubva.va = local_tseg->seg.ubva.va;
remote->seg.len = local_tseg->seg.len;
remote->seg.attr.value = flag.value;
// 遗漏：token_id 和其他字段！
```

### 正确
```c
// ✅ 正确 - 复制整个结构体
remote->seg = local_tseg->seg;
```

### urma_seg_t 中的必需字段

| 字段 | 用途 | 导入时是否必需 |
|-------|---------|---------------------|
| `ubva.eid` | 端点 ID | 是 |
| `ubva.uasid` | 用户地址空间 ID | 是 |
| `ubva.va` | 虚拟地址 | 是 |
| `len` | 段长度 | 是 |
| `attr` | 段属性 | 是 |
| `token_id` | Token ID | 是（如果 token_id_valid） |

### 完整交换示例

```c
// 本地端：注册段
urma_target_seg_t *local_tseg = urma_register_seg(ctx, &seg_cfg);

// 打包用于交换（完整结构体复制）
exchange_msg.seg = local_tseg->seg;

// 远端：接收并导入
urma_target_seg_t *import_tseg = urma_import_seg(ctx, &exchange_msg.seg, &token, 0, flag);
```

### 相关
- `urma_register_seg()` - 返回包含所有字段的 `urma_seg_t`
- `urma_import_seg()` - 需要完整的 `urma_seg_t`
- `urma_seg_cfg_t.token_id` - 当 `attr.bs.token_id_valid = 1` 时必需

---

## 24. WRITE_IMM 的 imm_data 字段错误

### 问题
`URMA_OPC_WRITE_IMM` 和 `URMA_OPC_SEND_IMM` 的即时数据存储在不同字段中。使用错误字段会导致即时数据被忽略或损坏。

### 症状
```
远端未收到即时数据
即时数据为垃圾值
WRITE_WITH_IMM 完成事件缺少 imm_data
```

### 错误
```c
// ❌ 错误：WRITE_IMM 使用了错误的字段
if (opcode == URMA_OPC_WRITE_IMM || opcode == URMA_OPC_SEND_IMM) {
    wr.send.imm_data = IMM_DATA;  // WRITE_IMM 时错误！
}
```

### 正确
```c
// ✅ 正确：不同操作码使用不同字段
if (opcode == URMA_OPC_SEND_IMM) {
    wr.send.imm_data = IMM_DATA;      // SEND_IMM：使用 send.imm_data
} else if (opcode == URMA_OPC_WRITE_IMM) {
    wr.rw.notify_data = IMM_DATA;     // WRITE_IMM：使用 rw.notify_data
}
```

### 按操作码的字段映射

| 操作码 | 结构体 | 字段 | 说明 |
|--------|-----------|-------|-------------|
| `URMA_OPC_SEND` | `urma_send_wr_t` | - | 无即时数据 |
| `URMA_OPC_SEND_IMM` | `urma_send_wr_t` | `imm_data` | 即时数据 |
| `URMA_OPC_WRITE` | `urma_rw_wr_t` | - | 无即时数据 |
| `URMA_OPC_WRITE_IMM` | `urma_rw_wr_t` | `notify_data` | 即时数据（不是 imm_data！） |

### 结构定义

```c
// 用于 SEND 操作
typedef struct urma_send_wr {
    urma_sg_t src;
    uint8_t target_hint;
    uint64_t imm_data;       // SEND_IMM 使用此字段
    urma_target_seg_t *tseg;
} urma_send_wr_t;

// 用于 RDMA 写/读操作
typedef struct urma_rw_wr {
    urma_sg_t src;
    urma_sg_t dst;
    uint8_t target_hint;
    uint64_t notify_data;    // WRITE_IMM 使用此字段（不是 imm_data！）
} urma_rw_wr_t;
```

### 接收端

接收方在两种情况下都通过完成记录的 `cr.imm_data` 获取即时数据：

```c
urma_cr_t cr;
urma_poll_jfc(jfc, 1, &cr);

if (cr.opcode == URMA_CR_OPC_WRITE_WITH_IMM) {
    printf("收到 imm_data: %lu\n", cr.imm_data);  // 来自 notify_data
} else if (cr.flag.bs.s_r == 1 && cr.opcode == URMA_CR_OPC_SEND) {
    // 带即时数据的 SEND
    printf("收到 imm_data: %lu\n", cr.imm_data);  // 来自 imm_data
}
```

### 相关
- `urma_send_wr_t.imm_data` - 用于 SEND_IMM
- `urma_rw_wr_t.notify_data` - 用于 WRITE_IMM
- `urma_cr_t.imm_data` - 完成记录中收到的即时数据

---

## 25. 访问标志组合错误

### 问题
`URMA_ACCESS_LOCAL_ONLY` 与远端访问标志互斥。组合使用会导致运行时错误。

### 症状
```
Local only access is not allowed to config with other accesses
段注册失败
RDMA 操作出现访问错误
```

### 错误
```c
// ❌ LOCAL_ONLY 与远端访问标志冲突
.flag.bs.access = URMA_ACCESS_LOCAL_ONLY | URMA_ACCESS_READ | URMA_ACCESS_WRITE;

// ❌ 使用 CAS/FADD 操作时缺少 ATOMIC
.flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE;
// 但代码使用了 URMA_OPC_CAS 或 URMA_OPC_FADD
```

### 正确
```c
// ✅ 仅 RDMA 读/写
.flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE;

// ✅ RDMA + 原子操作
.flag.bs.access = URMA_ACCESS_READ | URMA_ACCESS_WRITE | URMA_ACCESS_ATOMIC;

// ✅ 仅 send/recv（无 RDMA）
.flag.bs.access = URMA_ACCESS_LOCAL_ONLY;
```

### 访问标志语义

| 标志 | 含义 | 兼容标志 |
|------|---------|-----------------|
| `URMA_ACCESS_LOCAL_ONLY` | 仅本地访问 | 无（互斥） |
| `URMA_ACCESS_READ` | 远端读 | WRITE, ATOMIC |
| `URMA_ACCESS_WRITE` | 远端写 | READ, ATOMIC |
| `URMA_ACCESS_ATOMIC` | 远端原子操作 | READ, WRITE |

### 必需检查清单
- [ ] 如果设置了 `LOCAL_ONLY`，不应设置其他访问标志
- [ ] 如果代码使用了 `URMA_OPC_CAS` 或 `URMA_OPC_FADD`，必须包含 `URMA_ACCESS_ATOMIC`
- [ ] 迁移时与原始 Verbs 代码的访问标志进行对比

### 相关
- `urma_register_seg()` - 带访问标志的段注册
- `urma_import_seg()` - 远端段导入
- `URMA_OPC_CAS`, `URMA_OPC_FADD` - 原子操作

---

## 26. 参数超出设备能力

### 问题
URMA 有设备特定的限制，必须检查。参数超出设备能力会导致运行时错误。

### 症状
```
jetty cfg out of range, jfs_depth:8192, max_jfs_depth: 8192, ...
jfs_rsge:13, max_jfs_rsge: 1, ...
```

### 错误
```c
// ❌ max_rsge 设为 max_send_sge，但设备仅支持 1 个远端 sge
.max_sge = 13,
.max_rsge = 13,  // 错误！设备 max_jfs_rsge = 1

// ❌ 设置前未检查设备能力
.depth = user_value,  // 可能超出 max_jfs_depth
```

### 正确
```c
// ✅ 使用设备能力限制
urma_jfs_cfg_t jfs_cfg = {
    .depth = ctx->dev_attr.dev_cap.max_jfs_depth,
    .max_sge = (uint8_t)ctx->dev_attr.dev_cap.max_jfs_sge,
    .max_rsge = (uint8_t)ctx->dev_attr.dev_cap.max_jfs_rsge,  // 使用 max_jfs_rsge！
    .max_inline_data = ctx->dev_attr.dev_cap.max_jfs_inline_len,
};

urma_jfr_cfg_t jfr_cfg = {
    .depth = ctx->dev_attr.dev_cap.max_jfr_depth,
    .max_sge = (uint8_t)ctx->dev_attr.dev_cap.max_jfr_sge,
};
```

### URMA 特有的设备能力（Verbs 中无对应项）

| URMA 字段 | 设备能力 | 说明 |
|------------|------------|-------------|
| `max_rsge` | `max_jfs_rsge` | 最大远端 SGE 数（Verbs 无对应项） |
| `max_sge` (JFS) | `max_jfs_sge` | 发送最大本地 SGE 数 |
| `max_sge` (JFR) | `max_jfr_sge` | 接收最大本地 SGE 数 |
| `depth` (JFS) | `max_jfs_depth` | JFS 队列深度 |
| `depth` (JFR) | `max_jfr_depth` | JFR 队列深度 |
| `max_inline_data` | `max_jfs_inline_len` | 最大内联数据长度 |

### 必需检查清单
- [ ] 所有 `depth`、`max_sge`、`max_rsge`、`max_inline_data` 值必须 ≤ 设备能力
- [ ] `max_rsge` 是 URMA 特有的，使用 `dev_cap.max_jfs_rsge`（通常 = 1）
- [ ] 与 `urma_device_cap_t` 字段对比，而非用户自定义常量
- [ ] 阅读原始 URMA 示例了解正确的参数来源

### 相关
- `urma_query_device()` - 查询设备能力
- `urma_device_cap_t` - 设备能力结构体
- `urma_create_jetty()`, `urma_create_jfr()`, `urma_create_jfc()` - 资源创建

---

## 27. 返回计数的函数的返回值检查错误

### 问题
某些 URMA 函数返回计数（成功为正数）而非成功返回 0。检查 `ret != 0` 或 `ret == 0` 会导致逻辑错误。

### 受影响函数

| 函数 | 返回值 | 含义 |
|----------|-------------|---------|
| `urma_poll_jfc()` | `> 0` | 成功，完成记录数 |
| `urma_poll_jfc()` | `0` | 无可用完成记录 |
| `urma_poll_jfc()` | `< 0` | 错误 |
| `urma_wait_jfc()` | `> 0` | 成功，事件数 |
| `urma_wait_jfc()` | `0` | 超时（如果指定了超时） |
| `urma_wait_jfc()` | `< 0` | 错误 |

### 症状
```
成功被当作失败处理
测试意外退出
事件循环提前终止
```

### 错误
```c
// ❌ 错误：ret=1（成功）触发了错误处理
ret = urma_wait_jfc(jfce, 1, timeout, &ev_jfc);
if (ret != 0) {
    // 此代码块在成功时执行！
    return -1;
}

// ❌ 错误：ret=5（5 条完成记录）触发了错误处理
ret = urma_poll_jfc(jfc, 16, cr);
if (ret != 0) {
    // 此代码块在成功时执行！
    return -1;
}
```

### 正确
```c
// ✅ 正确：检查 <= 0（失败/超时）
int cnt = urma_wait_jfc(jfce, 1, timeout, &ev_jfc);
if (cnt <= 0) {
    // 处理超时或错误
    continue;
}

// ✅ 正确：使用 > 0 的 while 循环
int ne;
while ((ne = urma_poll_jfc(jfc, 16, cr)) > 0) {
    // 处理 ne 条完成记录
    for (int i = 0; i < ne; i++) {
        // 处理 cr[i]
    }
}

// ✅ 正确：仅 < 0 为错误（0 = 无完成记录也是正常的）
ret = urma_poll_jfc(jfc, 1, &cr);
if (ret < 0) {
    // 错误处理
} else if (ret > 0) {
    // 处理完成记录
}
```

### 与 Verbs 对比

| Verbs 函数 | 返回值语义 | URMA 等价 | URMA 返回值语义 |
|----------------|-----------------|-----------------|----------------------|
| `ibv_poll_cq()` | 返回计数（> 0 成功） | `urma_poll_jfc()` | 相同：返回计数 |
| `ibv_get_cq_event()` | 0 为成功 | `urma_wait_jfc()` | 返回计数（> 0 成功） |

**关键差异**：Verbs 的 `ibv_get_cq_event()` 成功返回 0，而 URMA 的 `urma_wait_jfc()` 返回事件计数。

### 必需检查清单
- [ ] 所有 `urma_poll_jfc()` 调用使用 `> 0` 或 `<= 0` 检查返回值，不是 `== 0` 或 `!= 0`
- [ ] 所有 `urma_wait_jfc()` 调用使用 `> 0` 或 `<= 0` 检查返回值，不是 `== 0` 或 `!= 0`
- [ ] 验证返回值 > 0 时走的是成功路径

### 相关
- `urma_poll_jfc()` - 轮询完成事件
- `urma_wait_jfc()` - 等待事件
- `urma_ack_jfc()` - wait 之后必须调用

---

## 添加新陷阱

遇到新问题时：

1. 确定分类
2. 描述症状
3. 提供解决方案
4. 如适用，包含代码示例

格式：
```markdown
## 分类名称

### 问题
问题描述。

### 症状
观察到的错误消息或行为。

### 解决方案
修复方法。

### 代码示例
```c
// 正确方式
```

### 相关 API
- `api_name()`
```
