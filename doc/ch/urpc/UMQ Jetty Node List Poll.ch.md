# UMQ Jetty Node List Poll 轮询优化设计

| 项 | 内容 |
|---|---|
| 模块 | `src/urpc/umq/umq_ub/`（jetty pool / transport pool / poll 数据面） |
| 状态 | 设计评审中 |
| 日期 | 2026-09-06 |

## 1. 背景与问题

main+share_transport UMQ 的 TX poll 轮询路径 `umq_ub_poll_tx_round_robin`（`umq_pro_ub.c`）负责在多个 transport pool jetty node 之间做 round-robin CQE 收割。当前实现以 `jetty_node_list->bitmap` 为遍历索引：循环内反复调用 `urpc_bitmap_find_next_bit` 寻找下一个有效槽位。

```c
// 现状 (umq_pro_ub.c:2291-2328)，在 jetty_node_list->lock 临界区内
for (uint32_t scanned = 0; scanned < jetty_node_list->list_len && ...; scanned++) {
    current_idx = (uint32_t)urpc_bitmap_find_next_bit(jetty_node_list->bitmap,
        jetty_node_list->list_len, current_idx);       // 每次迭代一次位图扫描
    if (current_idx >= jetty_node_list->list_len) { /* wrap ... */ }
    jetty_pool_node_t *node = jetty_node_list->node_list[current_idx];
    ...
}
```

### 1.1 性能问题

`urpc_bitmap_find_next_bit`（`urpc_bitmap.c`）从 `offset` 所在 word 起逐 word 扫描，单次调用最坏扫描 `list_len / 64` 个 word。当前 `list_len` = `JETTY_POOL_MAX_NODES` = 65536，即：

- **单次调用最坏 1024 个 word（8KB）读**。活跃 node 数为 k、槽位稀疏分布时，一轮 poll 触发 k 次 `find_next_bit`，平均每次扫 `1024/k` 个 word。k=1 且槽位靠后时，正扫 + wrap 回扫合计约 2048 个 word 读 —— 而实际只需要访问 1 个 node。
- **缓存不友好**：bitmap 8KB 超出 L1 cache（aarch64 典型 64KB L1D 中占 1/8），稀疏 set bit 导致大量冷 cache line 读。
- **迭代上界错位**：`scanned < list_len` 的上界是槽位容量（65536），不是活跃 node 数。数据面的遍历成本应与"有效 node 数"成正比，而不是与"槽位容量"成正比。

### 1.2 结构问题

- round-robin 游标 `next_poll_idx` 定义在**bitmap 槽位空间** `[0, list_len)`，wrap 判断、删除后的游标连续性都要在稀疏空间里推理，逻辑复杂且脆弱。
- `bitmap` 同时承担两个职责：**idx 分配/占用状态**（控制面）与**有效节点枚举**（数据面遍历）。后者是数据面热路径，被前者"槽位必须稀疏稳定"的约束连带拖慢。

## 2. 设计目标

1. poll 数据面遍历复杂度从 `O(active_cnt × list_len/64)` 降为 **`O(active_cnt)`**（active_cnt 为当前有效 node 数）。
2. `tp_handle_idx` 对外语义**完全不变**——它是上层（ubsocket）持有的稳定句柄，且写进 `buf_ref_id`、`option->tp_handle_idx`，槽位号不可因删除而改变含义。
3. 控制面（create/destroy）允许 O(active_cnt) 的写操作（低频），数据面只读、零额外扫描。
4. 不改变现有锁结构（poll 与 create/destroy 仍以 `jetty_node_list->lock` 串行），不引入新的并发语义。

## 3. 总体思路

把"有效槽位的枚举"从 bitmap 位图中剥离，改用一块**创建时追加、销毁时前移压缩的 idx 紧凑数组**：

- **控制面写**：create 成功后把新分配的槽位号 append 到 `valid_idx[]` 尾部；destroy 时把该槽位号从数组中摘除（其后元素 `memmove` 前移一位，`valid_cnt` 减一）。
- **数据面只读**：poll 在锁临界区内只读遍历 `valid_idx[0 .. valid_cnt)`，直接索引 `node_list[]`，不再触碰 bitmap。
- **bitmap 职责收缩**：仅保留 idx 分配（`urpc_bitmap_find_next_zero_bit` + `set1`/`set0`）与 O(1) 存在性校验（`urpc_bitmap_is_set`，供 post/wait/get_fd 等路径校验外部传入的 `tp_handle_idx`）。数据面遍历职责移除。

```
                控制面（低频，持锁写）                 数据面（高频，持锁只读）
              ┌──────────────────────────┐         ┌────────────────────────────┐
   create ───▶│ find_next_zero_bit 分配槽 │         │ for i in [cursor, cnt):    │
              │ bitmap set1              │         │   node = node_list[        │
              │ valid_idx[cnt++] = slot  │         │            valid_idx[i]]   │
   destroy ──▶│ bitmap set0              │   ────▶ │   poll_tx_single(node)     │
              │ memmove 摘除 valid_idx[pos]│        │ （无 bitmap 扫描）          │
              │ valid_cnt--               │         │                            │
              └──────────────────────────┘         └────────────────────────────┘
```

## 4. 数据结构变更

### 4.1 `umq_ub_jetty_node_list_t`（`umq_ub_jetty_pool.h`）

```c
typedef struct umq_ub_jetty_node_list {
    jetty_pool_node_t **node_list;
    uint32_t list_len;
    urpc_bitmap_t bitmap;
    uint16_t *valid_idx;                // NEW: 有效槽位号紧凑数组（按创建顺序，无空洞）
    uint32_t valid_cnt;                 // NEW: valid_idx 当前条目数
    volatile uint32_t ref_cnt;
    volatile uint32_t next_poll_idx;    // 语义变更: 游标迁移到 valid_idx 空间 [0, valid_cnt)
    util_external_mutex_lock *lock;     // 仍然串行化 bitmap + node_list + valid_idx 的变更
} umq_ub_jetty_node_list_t;
```

要点：

- `valid_idx` 元素类型为 `uint16_t`：槽位号上界受 `JETTY_POOL_MAX_NODES` = 65536 约束，合法取值 `[0, 65535]`，`uint16_t` 完全容纳。容量 = `list_len`（与 `node_list` 同参数一次性 `calloc`，65536 × 2B = **128KB** 常驻；`node_list` 本身 512KB，相对可接受。动态扩缩容方案见 §9 备选）。
- `valid_idx` 中**只登记 create 成功的槽位**，因此 `node_list[valid_idx[i]]` 保证非 NULL——现有 poll 循环里的 `if (node == NULL) continue` 分支可删除。
- `next_poll_idx` 的语义从"bitmap 槽位空间"迁移为"valid_idx 数组下标空间"。全代码库仅 `umq_ub_poll_tx_round_robin` 两处读写它（且都在锁内），语义迁移封闭在本模块内。
- `valid_idx`/`valid_cnt` 的所有读写均发生在 `jetty_node_list->lock` 临界区内，无需 atomic。`next_poll_idx` 沿用现有 `__atomic_load_n/store_n`（ACQUIRE/RELEASE）访问习惯——锁内属于冗余但无害，保持 diff 最小。

### 4.2 `jetty_pool_node_t`（`umq_ub_private.h`）

```c
typedef struct jetty_pool_node {
    ...
    uint32_t node_list_pos;    // NEW: 本 node 槽位号在 valid_idx[] 中的下标；槽位被占用时有意义
    ...
} jetty_pool_node_t;
```

用于 destroy 时 O(1) 定位待摘除条目，避免线性查找。安全性：

- node 由 `umq_ub_jetty_pool_get_free_node()` 分配时整体 `memset` 清零，池化复用不会残留旧值；
- 仅在槽位占用期间（create 成功 → destroy 前）有效，与 `node_list[idx]` 指向关系同生命周期。

## 5. 控制面变更（`umq_ub_impl.c`）

### 5.1 create：`umq_ub_transport_pool_resource_create_impl`

在持锁临界区内，idx 分配逻辑不变，登记动作从"仅 bitmap set1"扩展为"bitmap set1 + append valid_idx"：

```c
(void)util_mutex_lock(jetty_node_list->lock);
unsigned long offset = urpc_bitmap_find_next_zero_bit(jetty_node_list->bitmap, jetty_node_list->list_len, 0);
if (offset >= jetty_node_list->list_len) { /* 满了，原样返回 */ }
ret = umq_ub_create_jetty_node(queue, dev_ctx, option, &jetty_node_list->node_list[offset]);
if (ret != UMQ_SUCCESS) { /* 原样返回，不动 valid_idx */ }

jetty_node_list->node_list[offset]->node_list_pos = jetty_node_list->valid_cnt;  // NEW
jetty_node_list->valid_idx[jetty_node_list->valid_cnt] = (uint16_t)offset;      // NEW
jetty_node_list->valid_cnt++;                                                   // NEW
urpc_bitmap_set1(jetty_node_list->bitmap, offset);
(void)util_mutex_unlock(jetty_node_list->lock);
return (uint32_t)offset;
```

次序保证：**资源创建成功才登记**——`umq_ub_create_jetty_node` 失败路径不触碰 `valid_idx`，与现有"失败不 set1"次序一致。

### 5.2 destroy：`umq_ub_transport_pool_resource_destroy_impl`

持锁临界区内，在现有 `bitmap set0` 的基础上增加数组压缩与游标修正：

```c
(void)util_mutex_lock(jetty_node_list->lock);
if (!urpc_bitmap_is_set(jetty_node_list->bitmap, tp_handle_idx)) { /* 原样返回 */ }

int ret = umq_ub_destroy_jetty_node(queue, jetty_node_list->node_list[tp_handle_idx]);
if (ret != UMQ_SUCCESS) { /* 原样返回，不动 valid_idx */ }

jetty_pool_node_t *node = jetty_node_list->node_list[tp_handle_idx];
uint32_t pos = node->node_list_pos;
/* 防御式校验: pos 失配（理论不可达）时降级为线性查找，避免 memmove 越界/错删 */
if (pos >= jetty_node_list->valid_cnt || jetty_node_list->valid_idx[pos] != tp_handle_idx) {
    for (pos = 0; pos < jetty_node_list->valid_cnt; pos++) {
        if (jetty_node_list->valid_idx[pos] == tp_handle_idx) {
            break;
        }
    }
}

/* 摘除: pos 之后的条目前移一位 */
memmove(&jetty_node_list->valid_idx[pos], &jetty_node_list->valid_idx[pos + 1],
    (jetty_node_list->valid_cnt - pos - 1) * sizeof(uint16_t));
jetty_node_list->valid_cnt--;

/* 游标修正: 见下表 */
if (pos < jetty_node_list->next_poll_idx) {
    jetty_node_list->next_poll_idx--;
}

urpc_bitmap_set0(jetty_node_list->bitmap, tp_handle_idx);
(void)util_mutex_unlock(jetty_node_list->lock);
```

**注意：destroy 不清空 `node_list[tp_handle_idx]`**（与现状一致）。现有代码中 `umq_ub_poll_tx_single` 等路径存在"无锁 `urpc_bitmap_is_set` 检查后读 `node_list[idx]`"的窗口（`umq_pro_ub.c:2168`），若 destroy 新增置 NULL，会把该窗口的后果从"读到已回收 node"恶化为"NULL 解引用"，因此保持既有行为不变。`valid_idx` 的不变式（create 成功才登记）依然保证 compact 遍历路径读到的槽位非 NULL。

### 5.3 游标修正规则

`next_poll_idx` 语义为"下一次 poll 的起始下标"（valid_idx 空间）。poll 与 destroy 同锁串行，修正规则在 destroy 临界区内推理即可，无竞争：

| 被删条目位置 pos | next_poll_idx 修正 | 理由 |
|---|---|---|
| `pos < next_poll_idx` | `next_poll_idx--` | 游标左侧少了一个条目，原游标指向的条目左移一位；不减一会导致下轮 poll 跳过该条目（饿死一轮） |
| `pos == next_poll_idx` | 不变 | 被删的正是"下一个要 poll 的"条目；其后条目左移补位，游标不动即正确衔接 |
| `pos > next_poll_idx` | 不变 | 游标指向的条目未移动 |

`next_poll_idx` 在删除后可能等于 `valid_cnt`（如删的是最后一个条目），由 poll 入口的 clamp（见 §6）归零处理。

**create（append）不需要游标修正**：新条目落在尾部，不影响 `[0, valid_cnt)` 内已有下标与游标的对应关系；下轮 poll 从游标出发必然会扫到它。

## 6. 数据面变更：`umq_ub_poll_tx_round_robin`（`umq_pro_ub.c`）

遍历骨架与现有代码**同构**——把"bitmap 中找下一个 set bit"替换为"compact 数组取下一个条目"，diff 最小化：

```c
umq_ub_jetty_node_list_t *jetty_node_list = umq_ub_queue_jetty_node_list_get(queue);
if (jetty_node_list == NULL || jetty_node_list->valid_cnt == 0) {       // 替代原 bitmap == NULL 判断
    return 0;
}

int32_t qbuf_cnt = 0;
util_mutex_lock(jetty_node_list->lock);
uint32_t cnt = jetty_node_list->valid_cnt;                              // 锁内快照，循环中恒定
uint32_t start_idx = __atomic_load_n(&jetty_node_list->next_poll_idx, __ATOMIC_ACQUIRE);
if (start_idx >= cnt) {
    start_idx = 0;
}
uint32_t current_pos = start_idx;
bool wrapped = false;
for (uint32_t scanned = 0; scanned < cnt && (uint32_t)qbuf_cnt < buf_count; scanned++) {
    uint32_t tp_idx = jetty_node_list->valid_idx[current_pos];          // O(1) 数组读，无位图扫描；uint16_t 读后提升为 uint32_t
    jetty_pool_node_t *node = jetty_node_list->node_list[tp_idx];       // 保证非 NULL，可删原判空分支

    if (__atomic_load_n(&node->tx_outstanding, __ATOMIC_ACQUIRE) != 0) {
        uint32_t remaining = buf_count - (uint32_t)qbuf_cnt;
        option->tp_handle_idx = tp_idx;                                  // 对外仍是槽位号，语义不变
        uint32_t poll_batch = remaining > UMQ_BATCH_SIZE ? UMQ_BATCH_SIZE : remaining;
        int result = umq_ub_poll_tx_single(queue, &buf[qbuf_cnt], poll_batch, option);
        if (result > 0) {
            qbuf_cnt += result;
        }
    }

    current_pos++;
    if (current_pos >= cnt) {                                            // 替代原 find_next_bit >= list_len 判断
        if (wrapped) {
            break;
        }
        wrapped = true;
        current_pos = 0;
    }
    if (wrapped && current_pos >= start_idx) {
        break;
    }
}
if (current_pos >= cnt) {
    current_pos = 0;
}
__atomic_store_n(&jetty_node_list->next_poll_idx, current_pos, __ATOMIC_RELEASE);
util_mutex_unlock(jetty_node_list->lock);
```

语义对比：

| 维度 | 现状 | 新方案 |
|---|---|---|
| 单步定位成本 | `urpc_bitmap_find_next_bit`，最坏 1024 word 读 | 一次 `valid_idx[i]` 数组读 |
| 单轮 poll 总成本 | `O(active_cnt × list_len/64)` | `O(active_cnt)` |
| 循环上界 | `list_len`（槽位容量 65536） | `valid_cnt`（活跃 node 数） |
| node 判空 | 需要（bitmap set 但 node 为 NULL 的防御） | 不需要（登记次序保证非 NULL） |
| RR 公平性 | 槽位空间游标，删除扰动下可能跳过节点 | compact 空间游标 + destroy 修正规则，严格逐位轮转 |
| 缓存行为 | bitmap 8KB 冷扫描 | `valid_idx` 头部 1 条 cache line 装 32 个条目（uint16_t） |

其他数据面路径（`umq_ub_post_tx`、`umq_ub_wait_tx_interrupt`、`umq_ub_get_fd_list`、`umq_ub_poll_fc_tx` 等）通过 `urpc_bitmap_is_set + node_list[tp_handle_idx]` 校验并访问**单个**指定槽位，O(1) 且与遍历无关，**保持不变**。

## 7. 初始化/去初始化变更（`umq_ub_jetty_pool.c`）

- `umq_ub_jetty_node_list_init`：增加 `valid_idx = calloc(node_cnt, sizeof(uint16_t))`，失败走既有 goto 错误回收链（free bitmap / node_list / lock 的次序补入 free valid_idx）。
- `umq_ub_jetty_node_list_uninit`：增加 `free(valid_idx)`、置 NULL；`valid_cnt` 清零（随 `memset(&g_jetty_pool, 0, ...)` 自然完成）。
- `g_jetty_pool` 为静态结构体，`umq_ub_jetty_pool_uninit` 末尾整体 memset 清零，新字段无需额外处理。

## 8. 并发与正确性论证

1. **poll 与 create/destroy 互斥**：三者都在 `jetty_node_list->lock` 临界区内访问 `valid_idx`/`valid_cnt`/`next_poll_idx`/`node_list` 槽位，既有互斥锁直接覆盖新数据结构，无新增竞争窗口。
2. **memmove 期间 poll 可见性**：destroy 持锁完成 `memmove + valid_cnt-- + 游标修正 + bitmap set0 + node_list[idx] = NULL` 后才释放锁；下一轮 poll 拿锁后看到的是压缩完成的 consistent 快照。poll 在锁内先对 `valid_cnt` 取局部快照 `cnt`，循环期间不会因 destroy 并发修改而越界（同锁串行，不存在循环中途变更）。
3. **退出路径**：`umq_ub_poll_tx_round_robin` 入口的 `g_ubsocket_exiting` 守卫（防 release 路径 `umq_ub_jetty_node_free` 与 poll 的 heap-use-after-free 竞争）原样保留，不受本变更影响。
4. **错误注入防御**：`node_list_pos` 失配时 destroy 降级线性查找（§5.2），保证任何单字段损坏不至引发 `memmove` 越界写。
5. **`umq_ub_destroy_jetty_node` 失败路径**：不动 `valid_idx`/bitmap/`node_list`，与现状"失败不 set0"一致，槽位仍可再次尝试 destroy。

## 9. 备选方案与取舍

| 方案 | 描述 | 取舍 |
|---|---|---|
| **A. 线性查找 pos（不加 `node_list_pos` 字段）** | destroy 时在 `valid_idx` 中线性查找槽位号 | 查找 O(valid_cnt) 最坏 128KB 扫描；destroy 本身销毁 urma 资源为毫秒级，线性查找非瓶颈。省一个字段但把 O(1) 变 O(N)。**不选**：`node_list_pos` 仅 4 字节 + 两行赋值，成本远低于收益 |
| **B. valid_idx 动态扩缩容** | 初始小数组、满时翻倍 | 常驻内存从 128KB 降到活跃规模，但引入 realloc 失败处理与容量上限判断；create 高频时（弹性伸缩）realloc 抖动。**不选**：与 `node_list` 512KB 相比 128KB 固定分配已足够小，简单可靠优先 |
| **C. 双缓冲/RCU 去 poll 锁** | compact 数组天然适配 RCU（控制面写新数组、数据面无锁读旧数组） | 虽可消除"poll 持锁调用 `urma_poll_jfc`（长临界区）"的既有问题，但引入全新的内存回收机制，**复杂度过高，明确不采用**。本次保持既有锁结构不变 |
| **D. 完全删除 bitmap** | idx 分配也改用空闲栈 | post/wait 等路径的 `urpc_bitmap_is_set` O(1) 存在性校验依赖 bitmap，需另行设计校验机制（如代际 tag）。**不选**：bitmap 保留"idx 分配 + 存在性校验"两职责，仅卸下遍历职责，符合设计原则 |

## 10. 实施步骤

| 步骤 | 文件 | 内容 |
|---|---|---|
| 1 | `umq_ub_jetty_pool.h` | `umq_ub_jetty_node_list_t` 增加 `valid_idx`/`valid_cnt` 字段 |
| 2 | `umq_ub_private.h` | `jetty_pool_node_t` 增加 `node_list_pos` 字段 |
| 3 | `umq_ub_jetty_pool.c` | init/uninit 分配与释放 `valid_idx`（含错误回收链） |
| 4 | `umq_ub_impl.c` | create 追加登记；destroy 压缩数组 + 游标修正 |
| 5 | `umq_pro_ub.c` | `umq_ub_poll_tx_round_robin` 遍历重写（compact 数组步进） |
| 6 | UT | 新增/更新用例（见 §11） |

全部变更位于 `libumq` 内部（private 头），无对外 API/ABI 影响；`umq_ub_jetty_node_list_t` 结构体变化随 libumq 整体重编，ubsocket 侧通过 `umq_ub_queue_jetty_node_list_get()` 拿到的指针访问字段，同库重编后自然一致。

## 11. 测试与验收

### 11.1 功能用例（gtest + mockcpp，遵循单用例 ≤1s 约束）

| 用例 | 验证点 |
|---|---|
| create 后 valid_idx 登记正确 | `valid_cnt` 递增、`valid_idx[cnt-1] == 返回的 tp_handle_idx`、`node_list_pos` 正确 |
| destroy 中间条目 | `memmove` 后数组无空洞、`valid_cnt` 递减、bitmap 对应位清零、`node_list[idx] == NULL` |
| destroy 后 create 复用槽位 | bitmap 回收的槽位号可被再次分配，且 append 到 valid_idx 尾部 |
| 游标修正三位置 | pos < / == / > `next_poll_idx` 三种删除位置下，下轮 poll 起点符合 §5.3 规则表 |
| RR 公平性 | k 个 node 交替 `tx_outstanding`，连续多轮 poll 后每个 node 被 poll 次数差 ≤ 1 |
| 空/满边界 | 全部 destroy 后 poll 返回 0；create 满 `list_len` 个后拒绝再分配 |
| 退出守卫 | `g_ubsocket_exiting = true` 时 poll 直接返回 0（回归既有行为） |

### 11.2 性能验收

- 微基准：`active_cnt` ∈ {1, 8, 64} × 槽位分布 {稠密低位, 均匀分散, 最高位}，对比优化前后单轮 `umq_ub_poll_tx_round_robin` 的纯遍历开销（去掉 `poll_tx_single` 的 mock 计时）。预期稀疏 + 少 node 场景提升 1~2 个数量级。
- 实际业务基准：aarch64（Kunpeng 920）上跑 UBSocket 吞吐/时延基线，确认无回退、share-JFR 多 node 场景 p99 有改善。

### 11.3 回归

- `HCOM_BUILD_TYPE=debug HCOM_BUILD_TESTS=on ./build.sh` + `./build/generate_gtest_report.sh`
- `USE_URMA_STUB=on UMQ_BUILD=on UBSOCKET_UT=on bash build/build_umq_and_ubsocket.sh` + `ctest --test-dir src/ubsocket/build --output-on-failure`
- ASan/TSan 跑 transport pool 动态增删 + 并发 poll 场景，确认无新报告

## 12. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 游标修正规则错误导致某 node 被跳过/重复一轮 | §5.3 规则表 + §11.1 专项三位置用例；影响面仅为单轮调度公平性，不丢数据 |
| `node_list_pos` 与 `valid_idx` 失配（理论不可达） | destroy 侧防御式校验 + 线性查找降级，永不越界 |
| `valid_idx` 128KB 常驻内存 | 与 `node_list` 512KB 同量级；如未来需要可平滑演进到 §9.B 动态扩缩 |
| 漏改某处 `next_poll_idx` 语义使用点 | 已全库 grep 确认仅 `umq_ub_poll_tx_round_robin` 两处读写；review 时以 grep 结果为核对清单 |
