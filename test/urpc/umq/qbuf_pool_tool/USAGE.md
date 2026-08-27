# qbuf_pool_tool 测试使用

## 1. 概述

`qbuf_pool_tool` 是 umq 多级 size_class qbuf pool 的文件驱动测试工具。一个 `.txt` 脚本 = 一个用例，主线程读脚本分发命令到工作线程执行。聚焦验证多级池核心特性：多级 sc 路由、TLS 字节预算、fetch/return 生命周期、多线程 TLS 隔离、泄漏检测。

## 2. 构建与运行

独立 cmake 项目，不依赖顶层 hcom cmake、不需要 `BUILD_TESTS=ON`、不需要装 gtest/mockcpp。从仓库根：

```bash
cmake -S test/hcom/unit_test/umq/qbuf_pool_tool -B build_qbuf_tool
cmake --build build_qbuf_tool -j
./build_qbuf_tool/qbuf_pool_tool <script.txt>
```

跑批：
```bash
for f in test/hcom/unit_test/umq/qbuf_pool_tool/cases/*.txt; do
    echo "=== $(basename $f) ==="
    ./build_qbuf_tool/qbuf_pool_tool "$f"
done
```

退出码：0=全部命令成功，非0=有命令失败。

## 3. 命令集

每行一命令,`#` 开头注释(含 inline `#`),空行忽略。

### 3.1 单行命令

| 命令 | 形式 | 执行者 | 说明 |
|---|---|---|---|
| `init` | `init count=2 blockSizes=4K,64K mode=split scaleCap=on totalSz=200M tlsBudget=0 poolMaxSz=0 expSlotSz=0 weights=2,1 escape=on expThreshold=0 tlsExpandBudget=0 threads=1` | 主线程 | key=value 顺序无关,缺省用默认;`threads=N` 启动 N 工作线程。**下限:threads≥1**(无上限,但 threads>8 时 spinlock 自旋烧 CPU,见 case_13)。`blockSizes=` 必填(无 `mult` 几何级数回退),`weights=` 缺省时生产代码兜底 `{1,1}` 等权 |
| `thread_K alloc` | `thread_K alloc <size> [num=1] [headroom=0]` | worker K | 分配,size 支持 `4K`/`64K`/`1M` 后缀;输出每个 buf 的 sc/ptr/buf_size。**上限:num≤1000** |
| `thread_K free` | `thread_K free <orig_idx>` 或 `thread_K free all` | worker K | `orig_idx` 是 buf 的**稳定索引**(alloc 时分配,单调递增,erase 不前移);`free all` 清该线程全部并重置 orig_idx 计数器 |
| `info` | `info` | 主线程 | 全量状态(开发调试用,~50 行) |
| `status` | `status` | 主线程 | 精简状态(测试用,3 段一个框) |
| `quit` | `quit` | 主线程 | 提前退出(触发 Cleanup:泄漏检查 + join workers) |

**init 参数对照表(对应 cfg 字段)**:

| 参数 | cfg 字段 | 默认值 | 语义 |
|---|---|---|---|
| `totalSz` | `total_size` | 200M | 初始预分配池大小 |
| `poolMaxSz` | `umq_buf_pool_max_size` | 2GB(=0 时) | **总内存 ceiling** = 初始池 + 全部 expansion 槽。硬上限 6GB(`scaleCap=on` 时 `poolMaxSz>6G` 会被 umq_qbuf_pool_init 拒绝) |
| `expSlotSz` | `expansion_size` | 32MB(=0 时) | **per-slot 目标内存**(每次 expansion 想"加"多少)。经量化(÷blk_size→÷sub_slot_blk_count→×2MB)后变成实际 `slot.total_buf_size`,与 `expSlotSz` 不严格相等 |
| `tlsBudget` | `tls_pool_mem_budget` | 96MB(=0 时) | 全局 TLS bytes cap |
| `blockSizes` | `explicit_block_sizes[]` | 未设置→mult 几何级数回退 | **显式 per-SC block_size 数组**(commit 600d24a 后替代 `size_class_step_multiplier`)。格式:`blockSizes=4K,64K` 或 `4K,32K,128K`,逗号分隔,token 数必须等于 `count`。生产路径见 `umq_backend.cpp:67-69` memcpy `UmqSetting::UMQ_EXPLICIT_BLOCK_SIZES = {4096, 65536}`。**未设置时**工具用 `mult` 计算几何级数 `base * mult^i`(默认 `mult=16 base=4K` → `{4K, 64K}` 巧合与生产一致),但只能表达几何级数——非几何分布(如 `{4K, 32K, 128K}`)必须用 `blockSizes=`。token 支持 K/M/G 后缀(`ParseSize`) |
| `weights` | `per_sc_weights[]` | 未设置→全 0→生产兜底 {1,1} | **per-SC 分配权重数组**(commit 600d24a 后替代 `lazy_init_block_size_threshold`)。格式:`weights=2,1` 或 `1,1,0`,逗号分隔,token 数必须等于 `count`。**特殊值 0 = lazy SC**(init 时不预分配,首次 alloc 触发 expansion,替代旧的 `lazyThreshold` 阈值机制,改为 per-SC 粒度控制)。生产路径见 `umq_backend.cpp:70-72` memcpy `UmqSetting::UMQ_PER_SC_WEIGHTS = {2, 1}`(4K 拿 2x 份额避免 expansion)。**未设置时** `cfg.per_sc_weights[]` 全 0,生产代码 `umq_qbuf_pool.c:1595-1597` 检测全 0 → 回退默认 `{1, 1}` 等权 |
| `escape` | `disable_malloc_escape`(取反) | on(=启用 escape) | **malloc escape 开关**。`escape=off` 时 `cfg.disable_malloc_escape=true`,escape 路径关闭:`umq_qbuf_escape_alloc` 立即返回 EINVAL(`umq_qbuf_pool.c:2034`)、`umq_normal_qbuf_alloc` 跳过内部 escape 分支(`:2143`/`:2182`)。用于测试 pool 耗尽时返回 ENOMEM 而非 fallback 到 malloc escape 的场景 |
| `expThreshold` | `expansion_threshold` | 0(→生产默认 30) | **expansion 触发水位百分比**。控制 `trigger_expand_block_num = expansion_block_count * threshold / 100`。0 时生产代码取 `QBUF_POOL_DEFAULT_EXPANSION_THRESHOLD`(=30%)。范围 **[1, 100]**,越界 init 返回 EINVAL(`umq_qbuf_pool.c:1225-1228`)。高值(如 90)= expansion 更早触发;低值(如 5)= 滞后触发 |
| `tlsExpandBudget` | `tls_expand_mem_budget` | 0(→生产默认 7/8 tlsBudget) | **per-thread TLS bytes cap**。0 时生产代码取 `umq_qbuf_pool_expand_max(tls_pool_mem_budget)` = 7/8 的 `tlsBudget`(`umq_qbuf_pool.c:1214-1216`)。控制 TLS fetch 截断:`local_total_bytes + delta > tlsExpandBudget` 时截断 delta(`:1666-1669`)。与 `tlsBudget`(全局所有线程总 cap)独立语义 |
| `count`/`mode`/`scaleCap`/`threads` | (对应字段) | 见示例 | `count` 是 SC 数量(1..UMQ_SIZE_CLASS_MAX,默认 2);**`mult` 和 `base` 参数已移除**——`base` 从 `blockSizes[0]` 自动推导(经 `BlkSizeToEnum` 反向映射) |

**`blockSizes=` 历史**(commit 600d24a 后):
- 旧字段 `size_class_step_multiplier`(单一整数,几何级数 `base * mult^i`)已从 `qbuf_pool_cfg_t` 移除,改为显式数组 `explicit_block_sizes[]`
- 工具原 `mult` 参数(几何级数回退)和 `base` 参数(显式枚举)已**彻底移除**——`base` 现从 `blockSizes[0]` 自动推导(经 `utils.cpp` 的 `BlkSizeToEnum()` 反向映射,4096→`BLOCK_SIZE_4K` 等),避免冗余参数
- `blockSizes=` 现为**必填**参数(无回退);token 支持 K/M/G 后缀(`ParseSize`),如 `4K,64K` 或 `4096,65536`

**`weights=` 与旧 `lazyThreshold` 的关系**(commit 600d24a 后):
- 旧字段 `lazy_init_block_size_threshold`(单一阈值,blk_size ≥ 阈值的 SC 走 lazy)已被移除,改为 per-SC 数组 `per_sc_weights[]`
- `weights[i]=0` 即该 SC lazy(语义与旧 `lazyThreshold` 等价,但粒度从"阈值"改为"per-SC")
- 旧用例 `case_16~20` 已从 `lazyThreshold=1M` 迁移到 `weights=1,1,0`(3 SCs,sc2 即 1M lazy)

**`poolMaxSz` 与 `expSlotSz` 的关键区别**(易混):
- `poolMaxSz` 是**总上限**,经派生 `expansion_mem_size_max = poolMaxSz - 初始池大小` 后,用 CAS 限制 `exp_total_mem_pool_size`(当前已用 expansion 内存)。**这才是真正"限制总内存"的配置**。
- `expSlotSz` 是**per-slot 目标**,经派生链推算 per-slot 实际分配大小,init 时不与 `poolMaxSz` 做比较。设 `expSlotSz > poolMaxSz` 会让 init 静默通过、运行时 expansion 必败(每次 slot 申请都超 cap)。
- 验证 expansion 行为时:**先调 `poolMaxSz` 设小**(如 `poolMaxSz=64M`)让 expansion 触发后能很快撞到上限;再用 `expSlotSz` 控制 per-slot 粒度。

### 3.2 并行块:`parallel` / `join`

```
parallel
  thread_0 alloc 4096 100
  thread_1 alloc 4096 100
  thread_2 alloc 4096 100
join
```

**语义**:`parallel` 和 `join` 之间的所有 `thread_K` 命令异步派发(主线程不阻塞等待每个 worker),`join` 时统一收割。多个 worker 真正并发执行——验证生产代码的 spinlock(`block_pool[sc].global_mutex`)、原子计数器(`g_total_local_cap_with_data_bytes`)、CAS(`is_async_expanding`)等并发原语。

**硬规则**:
1. 块内只能放 `thread_K alloc/free` 命令,禁止 `init/info/status/quit/repeat/parallel`
2. 同一 worker 在同一 `parallel` 块内不能既 alloc 又 free(避免 `w.alloced` 主线程 drain 与 worker free 的 race)。需要 alloc+free 时用两个独立 parallel 块
3. 同一 worker 不能在同一 parallel 块内出现两次(用单条 `alloc num=N` 代替)
4. `parallel` 不能嵌套 `parallel`
5. `info`/`status` 必须在 `join` 之后调用(此时所有 worker 已停,DFX 拿到稳定快照)

### 3.3 重复块:`repeat N` / `end`

```
repeat 1000
  parallel
    thread_0 alloc 4096 10
    thread_0 free all
  join
end
```

**语义**:`repeat N` 和 `end` 之间的内容串行执行 N 次。**上限:N≤10000**。每次迭代可以是单行 `thread_K` 命令(串行)或一个嵌套的 `parallel/join` 块。

**硬规则**:
1. 块内禁止 `info/status/init/quit`(检查守恒在 repeat 之后做)
2. 块内禁止嵌套 `repeat` 或 `stress_repeat`
3. 块内最多一个 `parallel` 子块
4. 单次 race 概率低,用 `repeat` 放大竞态窗口
5. 块内允许 `snapshot N` 指令(见 §3.5)

### 3.4 长稳重复块:`stress_repeat` / `end`(无限循环)

```
stress_repeat
  parallel
    thread_0 alloc 4096 10
    thread_1 alloc 4096 10
  join
  parallel
    thread_0 free all
    thread_1 free all
  join
  snapshot 1000
end
```

**语义**:`stress_repeat` 和 `end` 之间的内容**无限循环执行**,直到:
1. **SIGINT/SIGTERM**(Ctrl-C 或 `kill -INT <pid>`):优雅退出 — 当前 iter 完成后 break,打印 `[stress] interrupted by signal at iter N` + 最终 summary,parser 继续下一行(可后续 `status`/`quit`)。退出码 0
2. **ExecuteBlockLines 返回非 0**(alloc/free 失败):立即 abort,退出码 1
3. **第二次 Ctrl-C**:`OnStopSignal` 重装默认 handler 并 raise,进程立即死(用于 cleanup 卡死场景)

**与 `repeat` 的关键区别**(memory-bounded 设计):
1. **不记录 action 历史**:`g_actions` 在 stress 模式下不 push 任何条目,无限循环后 `g_actions` 大小恒等于 stress_repeat 之前的条目数(通常只有 1 条 `init`)。`DrainWorkerResult` 在 `g_stress_mode==true` 时跳过所有 `g_actions` 写入
2. **不打印 per-buf 详情**:`DrainWorkerResult` 在 stress 模式下跳过 `printf("[tN] buf[i]...")`,避免无限迭代 × 1000 buf 输出洪水
3. **每轮末尾清空 `Worker::alloc_ops` 并重置 `next_orig_idx`**:当某 worker 的 `alloced.empty()`(用户保证 alloc/free 配对)时,`DoStressRepeatBlock` 静默 `alloc_ops.clear()` + `next_orig_idx = 0`。这覆盖 `free <idx>` 模式(不像 `free all` 自动重置)——让 `free 0`/`free 1` 等稳定索引在无限循环下每轮都能正确匹配(否则 `next_orig_idx` 持续增长,第二轮起 `free 0` 找不到 orig_idx=0 的 buf)。**用户必须保证每轮 alloc 和 free 配对**,否则 `alloced` 非空时 `alloc_ops` 和 `next_orig_idx` 都不会重置(保护 `FREE_IDX` cross-ref),内存会随泄漏线性增长,最终触发 `WORKER_ALLOCED_CAP=65536` 上限终止 stress
4. **StressCounters 汇总**:`g_stress` 全局计数器(total_allocs / total_frees / total_bufs_alloced / total_bufs_freed / errors)在 `DrainWorkerResult` + `DoFree` serial 路径 bump,主线程单线程无需 atomic。`status` 在 `g_stress_mode==true` 或 `g_stress.iters_done>0` 时在顶部追加 `stress running` / `stress interrupted` / `stress done` 段
5. **无限循环 ≠ 无界内存**:工具自身内存恒定(g_actions 不增长、alloc_ops 每轮清空、counters 1 个 struct、snapshot 直输 stdout 不存)。可放心跑天级别长稳

**硬规则**(同 `repeat`):
1. 块内禁止 `info/status/init/quit`
2. 块内禁止嵌套 `repeat` 或 `stress_repeat`
3. 块内允许 `parallel/join` 子块和 `snapshot N` 指令
4. **用户保证每轮 alloc/free 配对**(工具不强制守恒检查,但泄漏时内存会增长,无限循环下必然 OOM)
5. **不能在 batch 跑批中混用** — stress_repeat 无限循环,自动化脚本会卡住。手动 Ctrl-C 控制

**Ctrl-C 退出后查询**:
```bash
# Terminal 1: 启动 stress_repeat
./build_qbuf_tool/qbuf_pool_tool cases/case_21_stress_repeat.txt

# (跑一段时间后按 Ctrl-C)
# 输出:
# [stress] interrupted by signal at iter 12345 (waiting for current iter to complete, then exiting gracefully)
# [stress interrupted] iters=12345 uptime=0h 1m 2s allocs=98760 frees=98760 ...
# ====================[ status ]====================
# stress interrupted:
#   iters: 12345
#   ...
```

### 3.5 snapshot 指令(可选,用于 `repeat` 和 `stress_repeat` 块内)

```
stress_repeat 1000000
  parallel
    thread_0 alloc 4096 10
  join
  parallel
    thread_0 free all
  join
  snapshot 1000
end
```

**语义**:每 N 轮迭代打印一行进度摘要到 stdout,**不存入任何 vector**——内存恒定,与迭代数无关。

输出格式(stress 模式):
```
[stress] iter=1000/1000000 uptime=0h 12m 34s allocs=8000 frees=8000 errors=0 alloced_held=0
```

`repeat`(非 stress)模式下输出 `[snapshot]` 前缀,字段相同。

**实现**:`DoRepeatBlock` / `DoStressRepeatBlock` 预扫描块内的 `snapshot N` 指令提取 interval,在循环中 `(i+1) % interval == 0` 时打印。`ExecuteBlockLines` 把 `snapshot` 当 no-op 跳过。

### 3.6 actions 序号语义

`g_actions` 序号按**派发顺序**记录(不按完成顺序)。并行块内的命令在派发时预占 `g_actions` 槽位,`SyncAll` 收割时回填字符串。这保证序号稳定可复现——同样的脚本多次跑出来的序号一致,便于 debug。


## 4. 用例说明（cases/）

### 4.1 串行用例(原 case_01~07)

| 用例 | 场景 | 验证点 |
|---|---|---|
| `case_01_basic_init_alloc_free.txt` | init + info 全量 + 跨 sc alloc + free all | info 多级字段 + 路由函数 + TLS 字节预算 |
| `case_02_status.txt` | status 基本流程（init→alloc→free all→status） | actions / held allocs / pool state 演变 |
| `case_03_leak.txt` | alloc 不 free | alloced > 0 + 退出 NOTE per thread |
| `case_04_interleaved_alloc_free.txt` | 单线程穿插 alloc/free，每步 status | TLS 复用 + 全程守恒 + idx 语义 |
| `case_05_multi_thread.txt` | 多线程基础（threads=2） | per-thread TLS 隔离（t0/t1 不同 tid/fetch） |
| `case_06_complex_multi_thread.txt` | 复杂多线程（threads=3，混合 sc，穿插 free，泄漏） | per-thread TLS + held allocs per-worker + per-thread 泄漏 |
| `case_07_tls_fetch_return.txt` | TLS fetch/return 生命周期（单线程） | fetch_from_global → free 还 TLS → self_shrink return_to_global |

### 4.2 并行用例(新增 case_08~13)

| 用例 | 场景 | 验证点 | 涉及原语 |
|---|---|---|---|
| `case_08_concurrent_alloc_race.txt` | 8 worker 同时 alloc 同 sc(C1) | fetch_from_global spinlock race + 守恒 | `block_pool[sc].global_mutex` |
| `case_09_concurrent_free_race.txt` | 8 worker TLS 装满后同时 free all(C2) | return_to_global/TLS-update race + 守恒 | 同上 |
| `case_10_mixed_alloc_free_race.txt` | repeat 500,每 iter alloc 块 + free 块(C3+C8) | alloc/free churn 守恒 + self_shrink 反复触发 | spinlock + atomic |
| `case_11_cross_sc_parallel.txt` | 不同 worker 不同 sc 并发(C7) | per-sc 锁粒度隔离 + 多级 sc 路由 | 不同 spinlock |
| `case_12_stress_repeat.txt` | repeat 10000 长跑(C8) | 长程守恒 + 计数器累积 + 自旋压力 | 综合所有原语 |
| `case_13_threads_beyond_8.txt` | threads=16(突破旧 8 上限) | init 不报错 + 16 worker 全部拿 buf + 守恒 + per-thread TLS 16 行不同 tid | 综合所有原语 |

**注意**:并行用例 threads=8 时 CPU 占用高(spinklock 自旋烧 CPU),单次 case_12 跑 1~3 秒。threads>8(如 case_13=16)自旋压力更大,机器核数不足时实际并发度受限,但 init 不再拒绝、守恒仍成立。

### 4.3 字段映射用例(新增 case_14~16)

修复 `expSz → cfg.expansion_size` 误用后新增的 3 个用例,验证 `poolMaxSz`/`expSlotSz` 两个字段映射的正确性。

| 用例 | 场景 | 验证点 | 退出码 |
|---|---|---|---|
| `case_14_poolMaxSz_field_mapping.txt` | `poolMaxSz=6G`(走硬上限边界)正向 | 字段被正确解析、传给 `cfg.umq_buf_pool_max_size`、被 `umq_qbuf_pool_init` 接受;`info` 段2 `expansion_mem_size_max` 字段显示对应值 | 0 |
| `case_15_expSlotSz_field_mapping.txt` | `expSlotSz=64M` 正向 | 字段被正确解析、传给 `cfg.expansion_size`、被接受;`info` 段2 `expansion_size` 字段显示对应值 | 0 |
| `case_16_field_mapping_rejected.txt` | 旧名 `expSz=` + `poolMaxSz=7G` 越界 | (1) 旧名 `expSz` 被工具 parsing 拒绝(防回归) (2) `poolMaxSz>6G` 被生产代码 `umq_qbuf_pool.c:1356` 拒绝(证明映射走的是 `umq_buf_pool_max_size` 路径而非 `expansion_size`) | 1(预期失败) |

**case_16 注意**:两个 init 都预期失败,退出码=1 是正确行为。用例的"通过"语义是"两个 init 都按预期被拒绝",不是"所有命令成功"。batch 跑(`for f in cases/*.txt; do ... done`)会看到 case_16 退出码非0,属预期。

### 4.4 长稳用例(新增 case_21~23)

**注意**:case_21~23 用 `stress_repeat`(无限循环),**不能在 batch `for f in cases/*.txt; do ...` 中跑** — 会卡住。手动启动 + Ctrl-C 控制。

| 用例 | 场景 | 验证点 |
|------|------|--------|
| `case_21_stress_repeat.txt` | 8 worker 无限 `stress_repeat` + `snapshot 100` | g_actions 不增长(只 17 条 bootstrap);Ctrl-C 后 stress summary 段显示 allocs=frees/errors=0;状态=interrupted |
| `case_22_stress_infinite.txt` | 8 worker 无限 `stress_repeat` + `snapshot 10000` | 长稳压力:RSS 恒定 ~204MB(=200MB pool + 4MB 工具);配合外部 `ps -o rss= -p <pid>` 监控 |
| `case_23_stress_free_idx.txt` | 2 worker 无限 `stress_repeat` 用 `free <idx>` 而非 `free all` | 验证 `alloc_ops` 和 `next_orig_idx` 在 iter 边界被静默清空/重置(否则 `free <idx>` 模式下 `next_orig_idx` 持续增长,第二轮起 `free 0` 找不到匹配 buf,无限循环下立即失败) |

**手动验证流程**:
```bash
# Terminal 1: 启动 stress
./build_qbuf_tool/qbuf_pool_tool cases/case_22_stress_infinite.txt &
PID=$!

# Terminal 2: 监控 RSS(应保持 ~204MB 恒定)
while kill -0 $PID 2>/dev/null; do
    ps -o rss= -p $PID | awk '{print strftime("%H:%M:%S"), $1"KB"}'
    sleep 60
done

# Terminal 1(回到 1): Ctrl-C 优雅停止
# 期望输出:
#   [stress] interrupted by signal at iter N (waiting for current iter to complete, then exiting gracefully)
#   [stress interrupted] iters=N uptime=... allocs=... frees=... errors=0 ...
#   ====================[ status ]====================
#   stress interrupted:
#     iters: N
#     ...
```

### 4.5 burst/sustained 用例(新增 case_14_burst / case_15_sustained)

> **编号说明**:这两个用例与 §4.3 的 `case_14_poolMaxSz_field_mapping` / `case_15_expSlotSz_field_mapping` 共用编号(case_14、case_15)。batch 跑批时同号用例都会执行,语义上易混淆——建议未来重编号(见 §10 已知问题)。

验证 high-water mark cap 修复:TLS cap 不随 burst 膨胀、expansion pool 在 free 后能收缩。

| 用例 | 场景 | 验证点 | 退出码 |
|---|---|---|---|
| `case_14_burst_alloc_free_shrink.txt` | 10000 sc1 buf burst(10 批×1000,共 655360000 字节)+ free all + 5 次 status + 最终 info | 修复前 TLS sc1 buf=62K(inflated)、`expansion_count=15`(不收缩);修复后 <10K、`expansion_count<=2`(大部分收缩)。**注意**:工具限制单次 alloc num≤1000,故 10000 拆 10 批 | 0 |
| `case_15_sustained_burst_stability.txt` | `repeat 1000` 轮 burst alloc 1000 sc1 + free all + 最终 status/info | 修复前 expansion memory 单调增长(每轮 burst 留 residual);修复后稳定(cap 不膨胀、slot 收缩) | 0 |

### 4.6 lazy init 用例(case_16~20)

> **编号说明**:`case_16_lazy_init_3sc` 与 §4.3 的 `case_16_field_mapping_rejected` 共用编号 case_16;`case_17_lazy_init_multi_expand` 与 §4.7 的 `case_17_without_data` 共用编号 case_17。batch 跑批时同号用例都会执行——建议未来重编号(见 §10 已知问题)。

验证 `weights=` 参数中 weight=0 的 lazy SC 行为:weight=0 的 SC 在 init 时不预分配,首次 alloc 触发 expansion。

> **历史**:这 5 个用例原使用 `lazyThreshold=1M`(基于 `lazy_init_block_size_threshold` 阈值字段),commit `600d24a` 移除该字段改为 per-SC `per_sc_weights[]` 数组后,用例迁移到 `weights=1,1,0`(sc2 即 1M SC weight=0 = lazy)。同时把 `mult=16 base=4K` 改为更显式的 `blockSizes=4K,64K,1M`,并修复 case_17/19 中误用的 `expSz=` 旧名(应 `expSlotSz=`)。

| 用例 | 场景 | 验证点 |
|---|---|---|
| `case_16_lazy_init_3sc.txt` | 3-SC `blockSizes=4K,64K,1M` `weights=1,1,0`,基础 alloc/free | 1M SC init 时为空(`info` 段3 `glbl_free=0`);首次 alloc 1M 触发 expansion;3 个 SC alloc + free all 正常 |
| `case_17_lazy_init_multi_expand.txt` | lazy 1M 多轮 expansion,`expSlotSz=2M`(2 块/轮),4 个 1M alloc | 触发 2 轮 expansion(每轮 2 块);`info` 段3 `exp_count`/`exp_total_blk` 反映多轮累积 |
| `case_18_lazy_init_combine.txt` | lazy 1M + COMBINE 模式(`mode=combine`) | lazy init 与 COMBINE 模式叠加正确:buf_size = block_size(无 header 分离);1M SC 同样走 lazy 路径 |
| `case_19_lazy_init_concurrent.txt` | 8 worker 并发跨 SC alloc(t0-3 alloc 4K、t4-5 alloc 64K、t6-7 alloc 1M),`expSlotSz=4M` | per-sc expansion 隔离:1M SC 的 expansion 不被 4K/64K 并发 alloc 干扰;`status` 守恒 + per-thread TLS 隔离 |
| `case_20_lazy_init_headroom.txt` | lazy 1M + `headroom=512`(`thread_0 alloc 524288 1 512`) | lazy init 与 headroom 叠加:alloc 时携带 headroom 元数据,buf_size 反映 block_size + headroom |

### 4.7 without_data 路径用例(新增 case_17_without_data)

> **编号说明**:与 §4.6 的 `case_17_lazy_init_multi_expand` 共用编号 case_17。batch 跑批时两者都会执行——建议未来重编号(见 §10 已知问题)。

验证 `request_size=0` 的 without_data mempool 路径:独立 buf pool,只借 `umq_buf_t` header(描述符)不带 data region。

| 用例 | 场景 | 验证点 |
|---|---|---|
| `case_17_without_data.txt` | `scaleCap=off`,threads=2;4 阶段:info → 单线程 alloc 0 5 + status → free all + status → 多线程并发 alloc 0 10 + free all | (1) `DoAlloc` 接受 size=0(此前拒绝为 invalid) (2) `umq_normal_qbuf_alloc(0,...)` 路由到 without_data 路径(`umq_qbuf_pool.c:1942`) (3) buf 输出 `sc=- ... [nodata]`(无 SC 概念) (4) DFX 段6 Per-Thread TLS Pool Stats (WithoutData) 计数增长:`CurBuf`/`AccFetchCnt`/`AccAllocCnt`/`AccFreeCnt` (5) free all 还 TLS 非 global(同 FAQ Q1) (6) `status` alloced 列**不**计 without_data buf(单独 `without_data: N bufs` 行) (7) held allocs 显示 `alloc 0 -> nodata, N/M bufs held` (8) 多线程 per-thread TLS WithoutData 隔离 |

**关键配置**:`scaleCap=off`(`disable_scale_cap=true`)让 `init_split_mode_layout` 预分配 without_data pool(`umq_qbuf_pool.c:1283-1299`,`head_without_data_count = total_blk_num * UMQ_EMPTY_HEADER_COEFFICIENT`),使 alloc 0 N 直接命中 global without_data pool 无需 expansion。

### 4.8 新增 init 参数用例(case_24~27)

补齐 `qbuf_pool_cfg_t` 中此前工具未暴露的字段:`disable_malloc_escape`、`expansion_threshold`、`tls_expand_mem_budget`、`explicit_block_sizes[]`、`per_sc_weights[]`。

| 用例 | 场景 | 验证点 | 退出码 |
|---|---|---|---|
| `case_24_escape_disabled.txt` | `escape=off` + 小 pool(4M),alloc 100(范围内)+ alloc 700(超 pool) | (1) init 段2 `disable_malloc_escape=1` (2) 范围内 alloc 成功 (3) 超 pool alloc **失败**(ret≠0),无 escape fallback (4) 段9 `escape_buf_cnt=0`(无 escape buf 创建)。对比默认 `escape=on`:同场景会静默创建 escape buf | 0 |
| `case_25_expansion_threshold.txt` | `expThreshold=90`(激进早 expansion) + alloc 100 | (1) init 段2 `expansion_threshold=90` (2) expansion 在 90% 水位触发(比默认 30% 更早)。注:`expThreshold=0` 不报错,生产代码取默认 30(`:1223-1224`);`expThreshold=200` 越界 init 返回 EINVAL(`:1225-1228`) | 0 |
| `case_26_tls_expand_budget.txt` | `tlsBudget=96M` + `tlsExpandBudget=1M` + 2 线程各 alloc 100 | (1) init 段2 `tls_expand_qbuf_pool_depth=1048576` (2) 段5 每线程 `CurCap ≤ 256`（1M/4K=256，对比默认 84M/4K=21504） (3) 段7 每线程 `sc0 tls_cap_cnt ≤ 256`。证明 per-thread cap 独立于全局 `tlsBudget` | 0 |
| `case_27_blockSizes_weights_field_mapping.txt` | `blockSizes=4K,64K` `weights=2,1` 正向(对齐生产默认) | (1) init 段2 `explicit_block_sizes=[4096,65536]` (2) 段3 `sc0 initial_blocks` 约为 `sc1` 的 32x(`2x weight × 64K/4K`)(3) 跨 SC alloc/free 正常。**对齐生产**:`UmqSetting::UMQ_EXPLICIT_BLOCK_SIZES={4096,65536}` `UMQ_PER_SC_WEIGHTS={2,1}` 经 `umq_backend.cpp:67-72` memcpy 路径,工具与生产走相同代码路径 | 0 |

**字段对照**:

| init 参数 | cfg 字段 | 默认值(=0 时) | 生产消费点 |
|---|---|---|---|
| `escape` | `disable_malloc_escape`(取反) | false(escape 启用) | `umq_qbuf_pool.c:2034/2143/2182/2481` |
| `expThreshold` | `expansion_threshold` | 30(`QBUF_POOL_DEFAULT_EXPANSION_THRESHOLD`) | `umq_qbuf_pool.c:1111/1229/1311/1330/1393/1412` |
| `tlsExpandBudget` | `tls_expand_mem_budget` | 7/8 × `tlsBudget`(`umq_qbuf_pool_expand_max`) | `umq_qbuf_pool.c:1214-1216/1666-1669` |
| `blockSizes` | `explicit_block_sizes[]` | 未设→`mult` 几何级数回退(`base * mult^i`) | `umq_backend.cpp:67-69`(memcpy `UmqSetting::UMQ_EXPLICIT_BLOCK_SIZES`) |
| `weights` | `per_sc_weights[]` | 未设→全 0→生产兜底 `{1,1}` | `umq_backend.cpp:70-72`(memcpy `UmqSetting::UMQ_PER_SC_WEIGHTS`),`umq_qbuf_pool.c:1586-1599`(默认回退) |


## 5. status 输出示例（case_06 actions 段后）

```
====================[ status ]====================
actions (8):
  [1] init threads=3 count=2 mode=split scaleCap=on totalSz=209715200 poolMaxSz=0 expSlotSz=0 blockSizes=4096,65536 weights=default(1,1) escape=on expThreshold=0 tlsExpandBudget=0
  [2] [t0] alloc 4096 -> sc=0, 1 buf
  [3] [t0] alloc 32768 -> sc=1, 1 buf
  [4] [t1] alloc 65536 -> sc=1, 1 buf
  [5] [t1] alloc 70000 -> sc=1, 2 bufs
  [6] [t1] free 1 -> 1 buf
  [7] [t2] alloc 70000 -> sc=1, 2 bufs
  [8] [t2] free 0 -> 1 buf
held allocs:
  [t0][2] alloc 4096 -> sc=0, 1/1 buf held (free 0)
  [t0][3] alloc 32768 -> sc=1, 1/1 buf held (free 1)
  [t1][4] alloc 65536 -> sc=1, 1/1 buf held (free 2)
  [t1][5] alloc 70000 -> sc=1, 1/2 bufs held (free 3-4)
  [t2][7] alloc 70000 -> sc=1, 1/2 bufs held (free 5-6)
pool state (per-sc global/alloced/exp + per-thread tls):
  sc | blk_size | global | alloced | exp
  0  | 4096     | 2816   | 1        | 0
  1  | 65536    | 2816   | 5        | 0
  per-thread TLS:
    t0 (tid=1265)
      sc0: buf=63   cap=64
      sc1: buf=8    cap=64
    t1 (tid=1266)
      sc0: buf=0    cap=0
      sc1: buf=16   cap=64
    t2 (tid=1267)
      sc0: buf=0    cap=0
      sc1: buf=8    cap=64
  Pool OS Mem Claimed: 209715200 bytes (initial=209715200 + expansion=0 + escape=0)
==================================================
```

### 三段分工

1. **actions** — 完整动作历史（含 `[tK]` 前缀，alloc/free 都记录）
2. **held allocs** — 当前持有（去掉 alloc 又 free 的，`[tK][actions_idx]` 格式，显示 `remaining/total` 如 `1/2 bufs held`，括号内 `(free N)` 或 `(free N-M)` 提示该 op 的稳定 orig_idx 范围）
3. **pool state** — per-sc `global/alloced/exp`（全局总和）+ `per-thread TLS` 子表（每 thread 一块含 kernel tid，sc 分行 `buf/cap`）+ `Pool OS Mem Claimed` 行（initial + expansion + escape 三部分总和）

### 守恒一眼可见

每 sc `global + tls + alloced` 恒定。如 sc0：`global 2816 + tls 63 + alloced 1 = 2880`（init 总块数）；sc1：`global 2816 + tls(t0 8 + t1 16 + t2 8) 32 + alloced 5 = 2853` ≈ 2880（alloc 70000 占用 2 个 64K buf，故 tls 略多于 fetch）。

> **注**：`tid` 是 kernel TID（`syscall(SYS_gettid)`，小数字），与生产代码 `g_thread_cache.stats.tid` 一致；非 `pthread_self()` 地址（旧文档示例如 `129814476351168` 是 pthread_t 地址，已废弃）。`cap` 是 TLS per-SC 容量上限（count，非 bytes），`buf` 是当前 TLS 缓存的 buf 数。

## 6. info 输出（全量，~9 段）

`info` 调用 `umq_qbuf_pool_stats_to_str` 输出 DFX 字符串，按 init 验证流程排序（summary → config → per-sc → 派生指标）：

| 段 | 标题 | 关键列 | 说明 |
|----|------|--------|------|
| 1 | Global Pool Config | Type/Mode/TotalSize/TotalBlk/BlkSize/Headroom/DataSize/BufSize/UmqBufSize/FreeBlk/FreeSize/NoBufFreeBlk/NoBufFreeSize | 池总览（raw 数值），含 without_data pool 的 NoBuf 列 |
| 2 | Pool Config [Normal] | size_class_count/blk_size[]/per_sc_block_count/disable_scale_cap/disable_malloc_escape/expansion_size/expansion_threshold/batch_count/expansion_mem_size_max/exp_total_mem_pool_size/tls_qbuf_pool_depth/tls_expand_qbuf_pool_depth/exp_slot_used_count | 配置参数（init key=value 直接对照）；`blk_size[]` 是 `explicit_block_sizes[]` 的 DFX 别名；**`per_sc_weights[]` 不在 DFX 输出中**（生产代码内部使用，仅在 init 时影响 `per_sc_block_count` 分配） |
| 3 | Per-SizeClass State | sc/blk_size/glbl_free/hdr_free/exp_slots/exp_total_blk/exp_total_exp/exp_total_shrink/glbl_total/cap/exp_free/trig_expand | per-sc 状态；`glbl_free` 是 global 可用 buf 数（with_data）；`hdr_free` 是 without_data pool 可用数（sc0 列）；`exp_slots`/`exp_free` 是 expansion 槽位与可用块；`trig_expand` 是触发 expansion 的水位阈值 |
| 4 | Expansion Pool | Type/ExpandCnt/TotalBlk/FreeBlk/MemSize/AccExpCnt/SyncExpCnt/AsyncExpCnt/AccShrinkCnt + `partial_slot_count: WithData=N WithoutData=N` | WithData + WithoutData 两行 + partial_slot_count 单行（部分填充槽统计） |
| 5 | Per-Thread TLS Pool Stats (WithData) | Type/TID/CurCap/CurBuf/AccFetchCnt/AccFetchBuf/AccReturnCnt/AccReturnBuf/AccAllocCnt/AccFreeCnt | `total` 行 + 每 thread 一行；`AccAlloc`→`AccAllocCnt`、`AccFree`→`AccFreeCnt`（Cnt 后缀统一） |
| 6 | Per-Thread TLS Pool Stats (WithoutData) | 同上列名 | 借用 header 场景，多数情况下全 0 |
| 7 | Per-Thread Per-SC TLS (WithData) | sc/tls_buf_cnt/tls_cap_cnt | per-thread per-sc 细分（`local_qbuf_pool_num==0` 时整段跳过）；`tls_buf_cnt` 是当前 TLS 缓存 buf 数，`tls_cap_cnt` 是 per-SC 容量上限（count，非 bytes） |
| 8 | Derived Metrics | Pool/TotalSize/TotalCnt/FreeSize/FreeCnt/Utilization/TlsLocality/AllocMinusFree + 每行 `Normal-scN` 子行 | 派生指标：`utilization=(total-free)/total%`、`tls_locality=tls/(tls+global)%`、`alloc_minus_free=AccAlloc-AccFree`（leak 探针，应=0 或=tls cur_buf 总和）；size 列同时显示 raw + K/M/G 单位；per-SC 子行独立显示各 SC 利用率 |
| 9 | Escape | escape_buf_cnt | 加 `== [ Escape ] ==` 三段式框架，与其他段一致 |

## 7. 测试场景对照表

| 测试目的 | 用例 / 命令 | 关键观察点 |
|---|---|---|
| 多级 sc 路由正确 | case_01 / `alloc 4096`+`alloc 65536` | alloc 输出 `sc=0` / `sc=1`；info 段 3 Per-SizeClass `blk_size=4096/65536` 反推 |
| 多级结构初始化 | case_01 `info` 段 2+3 | 段 2 `size_class_count=2`、`blk_size[0]=4096`/`blk_size[1]=65536`；段 3 `blk_size=4096`(sc0) / `65536`(sc1)、`glbl_free`/`hdr_free` 分行 |
| TLS 字节预算机制 | case_01 `info` 段 5+7 alloc 前后 | 段 5 `CurCap`（=TLS 总 buf 容量）累加（不随 alloc 递减）；段 7 per-sc `tls_cap_cnt` 是 per-SC 容量上限 |
| TLS fetch 批量预取 | case_07 阶段1 `info` 段 5 | `AccFetchBuf=320`（5 批×64），`AccAllocCnt=300` |
| free 还 TLS 非 global | case_07 阶段2 `info` 段 5 | free all 后 `CurBuf` 升到 fetch 量（320），`FreeBlk` 不变（actual==cap） |
| self_shrink 归还 global | case_07 阶段3 `info` 段 5+段 8 | alloc 1 触发 shrink，`CurBuf` 降、`FreeBlk` 升；段 8 `TlsLocality` 同步下降 |
| 多线程 TLS 隔离 | case_05/06 `status` 或 `info` 段 5 | 段 5 不同 `TID`（kernel TID 小数字）的行各自 `AccFetchBuf`/`CurBuf` 独立 |
| per-thread 泄漏检测 | case_03/06 | `info` 段 8 `AllocMinusFree > 0`（运行中可见）；退出 `NOTE: thread K has N bufs unfreed` |
| 守恒一眼可见 | case_04 `info` 段 3+5+8 | 每 sc：段 3 `glbl_free` + 段 5 `CurBuf` + alloced（=AccAlloc-AccFree） 恒等于 init 总块数；段 8 `Utilization` 与之对齐 |
| held allocs 过滤 | case_04 status | alloc+free 对隐藏，只显示仍持有的（`remaining/total`） |

## 8. 常见问题

### Q1: free all 后 TLS buf 没下降、global 没升，为什么不归还？
`umq_qbuf_free` 把 buf 还到 **TLS 缓存**（with_data 池），不是直接 global。`return_to_global` 只在 `actual_bytes > cap_bytes`（`umq_qbuf_pool.c:1750`）触发，`cap_bytes = bytes_with_data[sc]`（fetch 时累加）。free all 后 `actual = fetch×block = bytes_with_data = cap`，相等不超，不归还。归还 global 在 `self_shrink`（alloc 路径，`remaining/4 >= 64`）。见 case_07 阶段3。
### Q2: `alloc 4096 num=300` 报 "size/num invalid"？

alloc 的 num 是**位置参数**（args[2] 直接 strtoul），不是 key=value。`num=300` 被解析成 0。用 `alloc 4096 300`（位置参数）。init 才用 key=value。

**alloc 上限**（三层）：
1. **单次 alloc**: `num ≤ 1000`（`DoAlloc` 检查，防止单次过大）
2. **per-worker 累计**: `alloced.size() ≤ WORKER_ALLOCED_CAP=65536`（防止 `alloced` vector 无界增长 + O(n) 扫描退化）。超限时 `DoAlloc` 返回错误，提示 "Free some bufs first or use `free all` to reset"
3. **池子耗尽**: `umq_normal_qbuf_alloc` 返回 ENOMEM（自然上限，通常最先触发）

per-worker 上限是安全网——池子通常只有 ~5760 bufs（200M totalSz），8 worker 平均每个 ~720 bufs，远低于 65536。只有当用户忘记 `free all` 而持续 alloc 时才会撞上限。

### Q3: 多线程时 actions 序号和 held allocs 序号怎么对应？
held allocs 的 `[tK][N]` 中 `N` 是 `actions_idx+1`，对应 actions 段的序号（含 alloc+free 对，alloc 操作的序号）。alloc 又 free 的 `remaining=0` 时从 held allocs 隐藏，但 actions 段保留全历史。
### Q4: `thread_K free <orig_idx>` 的 orig_idx 是全局还是 per-thread？

**per-thread**。`thread_K free <orig_idx>` 只 free worker K 自己的 `alloced` 中 `orig_idx` 匹配的 buf，不支持跨线程 free。

**orig_idx 语义**（稳定索引，不会因 erase 前移）：
- 每个 buf 在 drain 时分配一个单调递增的 `orig_idx`（从 0 开始）
- `free N` 通过扫描 `alloced` 查找 `orig_idx == N` 的 buf，erase 该 buf 后**其他 buf 的 orig_idx 不变**
- `free all` 清空 `alloced` 并重置 `next_orig_idx = 0`，下次 alloc 从 0 重新开始
- `held allocs` 段每行末尾的 `(free N)` 或 `(free N-M)` 提示该 op 的 orig_idx 范围，用户直接照抄即可

**与旧版本（erase 前移）的区别**：旧版 `free 0; free 1; free 2; free 3; free 4` 因 erase 前移只释放 3 个 buf（b0/b2/b4），剩 2 个泄漏；新版稳定索引下 5 个全部正确释放。

### Q5: 退出码怎么看？
0=全部命令成功，非0=有命令失败（ERROR 打到 stderr）。脚本结束自动 Cleanup（泄漏检查 + join workers + uninit）。

### Q6: 为什么 `info` 的 TLS 段要遍历 `g_tls_register_head`？
`g_thread_cache` 是 `__thread`，主线程访问只看主线程 TLS（空，主线程不分发业务）。要看所有 worker TLS，必须遍历全局链表 `g_tls_register_head`（加锁 `g_tls_stats_lock`）。

### Q7: 并行块内的 buf[i] 输出是按 worker 顺序打印的，看起来像串行？是并行的吗？

**是并行的——worker 执行并发，但 drain（打印）由主线程串行做**。

设计如此：主线程在 `SyncAll()` 中按 `g_workers` 顺序（worker idx 升序）`pthread_cond_wait(done)` + drain `task.alloc_list`，保证 `g_actions` 序号稳定（按派发顺序，非完成顺序）。所以 buf[i] 输出顺序是 t0 全部、t1 全部、…、t7 全部——这**只反映 drain 顺序，不反映执行顺序**。

要验证 worker 真并发执行，开 verbose 模式：

```bash
QBUF_TOOL_VERBOSE=1 ./build_qbuf_tool/qbuf_pool_tool case_08_concurrent_alloc_race.txt 2>&1 1>/dev/null
```

输出示例（关键证据）：
```
[parallel] dispatched 8 commands in 158μs, entering barrier (workers now running concurrently)
[sync] t0 drained: worker ran [95925..95933]μs (dur=8μs), main waited 0μs for done
[sync] t1 drained: worker ran [95936..95959]μs (dur=23μs), main waited 0μs for done
[sync] t2 drained: worker ran [95946..95964]μs (dur=18μs), main waited 1μs for done
...
[sync] barrier complete: total=346μs, parallel_exec_window=152μs,
       per-worker wait: min=0μs max=1μs avg=0μs
```

**判断标准**：
1. **per-worker wait ≈ 0**（max=1μs）：主线程到达 SyncAll 时 8 个 worker 都已完成 → 必然并发（串行的话每个 wait ≈ worker 执行时间）
2. **worker 区间重叠**：t1=[95936..95959] 与 t2=[95946..95964] 在 [95946..95959] 重叠 13μs 同时跑
3. **parallel_exec_window < Σ(worker dur)**：152μs < 8+23+18+4+3+9+7+5=77μs 的 8 倍 — 并发节省了 ~6 倍时间

Verbose 模式默认关闭，stress 用例(case_10/12)若开 verbose 会产生大量 timing 行，建议只在调试 race 时启用。


### Q8: `repeat` 和 `stress_repeat` 怎么选?

| 维度 | `repeat N` | `stress_repeat` |
|------|-----------|-------------------|
| 上限 | N≤10000 | **无限循环** |
| 退出条件 | 跑完 N 次 | Ctrl-C(SIGINT/SIGTERM)或 alloc/free 失败 |
| g_actions | 每轮 push,线性增长 | 不 push,恒定 |
| per-buf printf | 每轮打印 | 跳过 |
| Worker::alloc_ops | 不主动清(由 `free all` 清) | 每轮末尾静默清+重置 `next_orig_idx`(当 `alloced.empty()`) |
| 适用场景 | 调试竞态、放大 race window | 天级别长稳、内存压力验证 |
| 出错时调试 | g_actions 完整历史可回溯 | 只有 iter 号 + 失败行(stress 模式不记历史) |
| batch 自动化 | ✅ 可在 `for f in cases/*.txt; do ...` 中跑 | ❌ 无限循环,不能进 batch(会卡住) |

**建议**:
- 短测试(N≤10000)、需要 action 历史、自动化 batch → `repeat`
- 长稳(手动控制时长)、验证内存恒定 → `stress_repeat` + `snapshot N`,Ctrl-C 控制
- 调试 race 时先用 `repeat` 跑小 N 看 action 历史,确认逻辑无误后再切 `stress_repeat` 长跑

### Q9: `stress_repeat` 跑到一半 OOM 了怎么办?

`stress_repeat` 设计上保证工具自身内存恒定(g_actions 不增长、alloc_ops 每轮清空、counters 1 个 struct)。如果 RSS 仍增长,排查:

1. **用户泄漏**:`status` 的 `stress progress` 段看 `alloced_held`——若非 0 且持续增长,说明每轮 alloc/free 未配对。修复脚本。
2. **pool expansion**: `status` 的 `Pool OS Mem Claimed` 行看 `initial + expansion + escape`——若 expansion 持续增长,说明生产代码 expansion 没回收(可能 pool 配置问题,检查 `poolMaxSz` cap)。pool 自身受 `poolMaxSz` CAS 约束,理论上限确定。
3. **glibc malloc arena**:多线程场景 glibc 会为每个线程分配 malloc arena(默认 8×CPU 核数)。用 `MALLOC_ARENA_MAX=2 ./build_qbuf_tool/qbuf_pool_tool ...` 限制 arena 数,可显著降 RSS。
4. **buf printf 拖留**:stress 模式下 per-buf printf 已跳过;若仍看到大量 stdout 输出,检查是否误用了 `repeat` 而非 `stress_repeat`。


## 9. 文件清单

```
test/hcom/unit_test/umq/qbuf_pool_tool/
├── CMakeLists.txt          # 独立 cmake 项目
├── qbuf_pool_tool.h        # struct + 全局 extern + 函数声明
├── stubs.cpp               # extern C stubs(不 include .c)
├── utils.cpp               # 纯解析器
├── core.cpp                # tool state + 命令分发;不再 #include umq_qbuf_pool.c
│                           #  (由 CMakeLists.txt 编入 tool target);所有 umq pool
│                           #  状态访问走公共 DFX API (umq_stats_qbuf_pool_get +
│                           #  umq_qbuf_pool_stats_to_str) 和公共 umq_qbuf_pool.h
│                           #  函数(init/uninit/normal_qbuf_alloc/qbuf_free/...)
│                           #  + DispatchAsync/SyncAll/DrainWorkerResult/
│                           #    DoParallelBlock/DoRepeatBlock/DoStressRepeatBlock/
│                           #    ExecuteBlockLines
├── main.cpp                # 脚本读 + 命令分发 + parallel/repeat/stress_repeat 块解析状态机
└── cases/                  # 30 个用例(含 4 组重号,见 §10)
    ├── case_01_basic_init_alloc_free.txt
    ├── case_02_status.txt
    ├── case_03_leak.txt
    ├── case_04_interleaved_alloc_free.txt
    ├── case_05_multi_thread.txt
    ├── case_06_complex_multi_thread.txt
    ├── case_07_tls_fetch_return.txt
    ├── case_08_concurrent_alloc_race.txt   # 并行
    ├── case_09_concurrent_free_race.txt    # 并行
    ├── case_10_mixed_alloc_free_race.txt   # 并行+repeat
    ├── case_11_cross_sc_parallel.txt       # 并行
    ├── case_12_stress_repeat.txt           # 并行+repeat
    ├── case_13_threads_beyond_8.txt         # 并行(突破旧 8 上限)
    ├── case_14_poolMaxSz_field_mapping.txt  # 字段映射正向 (poolMaxSz) — §4.3
    ├── case_14_burst_alloc_free_shrink.txt  # burst + shrink — §4.5
    ├── case_15_expSlotSz_field_mapping.txt  # 字段映射正向 (expSlotSz) — §4.3
    ├── case_15_sustained_burst_stability.txt # sustained burst 稳定性 — §4.5
    ├── case_16_field_mapping_rejected.txt   # 字段映射负向 (旧名+越界) — §4.3
    ├── case_16_lazy_init_3sc.txt            # lazy 1M 基础 — §4.6
    ├── case_17_lazy_init_multi_expand.txt   # lazy 多轮 expansion — §4.6
    ├── case_17_without_data.txt             # without_data 路径 — §4.7
    ├── case_18_lazy_init_combine.txt         # lazy + COMBINE — §4.6
    ├── case_19_lazy_init_concurrent.txt      # lazy + 并发 — §4.6
    ├── case_20_lazy_init_headroom.txt        # lazy + headroom — §4.6
    ├── case_21_stress_repeat.txt            # 长稳 stress_repeat 基础(无限循环)
    ├── case_22_stress_infinite.txt          # 长稳无限循环 + RSS 监控示例
    ├── case_23_stress_free_idx.txt          # 长稳 free <idx> 模式 (alloc_ops 清空验证)
    ├── case_24_escape_disabled.txt          # escape=off + pool 耗尽验证 — §4.8
    ├── case_25_expansion_threshold.txt       # expThreshold 水位控制 — §4.8
    ├── case_26_tls_expand_budget.txt          # tlsExpandBudget per-thread cap — §4.8
    └── case_27_blockSizes_weights_field_mapping.txt  # blockSizes=/weights= 字段映射 — §4.8
```

## 10. 已知问题

### 10.1 用例编号冲突(4 组重号)

cases/ 目录存在 4 组共用编号的文件:

| 编号 | 文件 A | 文件 B |
|---|---|---|
| case_14 | `case_14_poolMaxSz_field_mapping.txt`(§4.3,退出码 0) | `case_14_burst_alloc_free_shrink.txt`(§4.5,退出码 0) |
| case_15 | `case_15_expSlotSz_field_mapping.txt`(§4.3,退出码 0) | `case_15_sustained_burst_stability.txt`(§4.5,退出码 0) |
| case_16 | `case_16_field_mapping_rejected.txt`(§4.3,**退出码 1**) | `case_16_lazy_init_3sc.txt`(§4.6,退出码 0) |
| case_17 | `case_17_lazy_init_multi_expand.txt`(§4.6,退出码 0) | `case_17_without_data.txt`(§4.7,退出码 0) |

**影响**:
1. `for f in cases/*.txt; do ./build_qbuf_tool/qbuf_pool_tool "$f"; done` 跑批时同号用例都会执行——case_16 一个退出 0 一个退出 1,自动化结果难以按编号归因
2. `cases/` 目录按字母序排列时,`case_16_field_mapping_rejected.txt` 排在 `case_16_lazy_init_3sc.txt` 之前;两者都跑时日志混杂

**建议修复**:lazy init 系列(case_16~20 共 5 个)+ burst 系列(case_14_burst、case_15_sustained 共 2 个)+ without_data(case_17_without_data 1 个)重编号为 case_27~34,避免与字段映射用例冲突(case_24~26 已被新增的 init 参数用例占用,见 §4.8)。重编号后同步更新本文件 §4.5~§4.7 与 §9 文件清单。

### 10.2 测试声称不支持的字段 — 实际情况

测试曾声称工具不支持 5 个 init 选项,实际核查(`qbuf_pool_cfg_t` 定义见 `umq_qbuf_pool_base.h:85-113`):

| 字段 | 测试声称 | 实际 | 说明 |
|---|---|---|---|
| `umq_buf_pool_max_size` | 不支持 | **已支持** | init 参数 `poolMaxSz`,见 §3.1。case_14_poolMaxSz/case_16_field_mapping 已验证 |
| `disable_malloc_escape` | 不支持 | 已补齐(§4.8) | init 参数 `escape`,case_24 验证 |
| `expansion_threshold` | 不支持 | 已补齐(§4.8) | init 参数 `expThreshold`,case_25 验证 |
| `tls_expand_mem_budget` | 不支持 | 已补齐(§4.8) | init 参数 `tlsExpandBudget`,case_26 验证 |
| `explicit_block_sizes` | (commit 600d24a 新增字段) | 已补齐(§4.8) | init 参数 `blockSizes`,case_27 验证。此前工具用 `mult` 几何级数近似,凑巧与生产 `{4K, 64K}` 一致但无法表达非几何分布 |
| `per_sc_weights` | (commit 600d24a 新增字段) | 已补齐(§4.8) | init 参数 `weights`,case_27 验证。此前工具 `cfg.per_sc_weights[]` 全 0→生产代码兜底 `{1,1}`,与生产 `{2,1}` 不一致 |
| `lazy_init_block_size_threshold` | (旧字段,已移除) | **已删除** | commit `600d24a` 移除该字段,改为 per-SC `per_sc_weights[i]==0` 表达 lazy。工具 `lazyThreshold` 参数同步移除,旧用例迁移到 `weights=1,1,0`(见 §4.6) |
| `size_class_step_multiplier` | (旧字段,已移除) | **已删除** | commit `600d24a` 移除该字段,改为显式数组 `explicit_block_sizes[]`。工具原 `mult` 参数(几何级数回退)和 `base` 参数(显式枚举)已彻底移除——`base` 现从 `blockSizes[0]` 自动推导,`blockSizes=` 必填 |
| `batch_mem_size` | 不支持 | **字段不存在** | `qbuf_pool_cfg_t` 中无此字段;全仓 grep 返回 0 匹配。疑为拼写错误或幻觉字段名,需向测试团队核实来源 |

### 10.3 build_qbuf_tool/ 构建产物目录

`qbuf_pool_tool/build_qbuf_tool/` 包含 `CMakeCache.txt`/`Makefile`/`qbuf_pool_tool` 二进制等构建产物。构建产物不应进 git 跟踪——需确认 `.gitignore` 是否已忽略;若已 commit,应 `git rm -r --cached qbuf_pool_tool/build_qbuf_tool` 清理并加入 `.gitignore`。
