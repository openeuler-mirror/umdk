# Memory copy and alignment

status: **accepted**

普通 **Vector GM ↔ UB** 搬运：先问 **这条路径能不能用 `DataCopy`，还是必须 `DataCopyPad`**，以及 **`blockLen` 的单位是 DataBlock 还是字节**。不要先抄 Softmax 样例，也不要把 `GetValue`/`SetValue` 写成非法。

本文不是 stride 百科，不是 Cube `nd2nz` / L1 / L0 搬运教程。950 上的 `MatMulImpl` / LoadData2D / A2 GMM 高阶 API **不走这篇**。搬完何时能给 Vector 用，见 [pipeline-events-and-ordering](../synchronization/pipeline-events-and-ordering.md)。

证据种类：`official-document` | `source-code` | `recommendation` | `unknown`。  
本文件 **没有** `benchmark`。

---

## 先问什么

```text
1. 有效长度（effective）和 32B 对齐长度（aligned）各是多少？
2. 这次搬运能不能证明：长度 32B 对齐，且 UB 起始地址 32B 对齐？
   已证明满足 DataCopy contract → DataCopy 可用
   明确存在非对齐             → DataCopyPad
   尚无法证明对齐             → 优先 DataCopyPad（recommendation）
                                 或回到 tiling 把对齐条件证明出来
3. 你填的 blockLen 是 DataBlock 还是字节？（DataCopy ≠ DataCopyPad）
4. Compute / 回写用的是有效长，还是把 pad / aligned footprint 当 logical 数据了？
5. 每个 DMA edge：source base / dest base 对齐、transfer granularity、
   **logical payload** 与 **physical landing footprint** 各是多少？
   不得只按有效字节设计 UB dest（4B gather ≠ compact dest+4*k）
```

不要先问“能不能 GetValue 一把梭”。那是调试手段，不是生产数据路径（`recommendation`）。

---

## Rule

```text
DataCopy
  要求搬运长度 32B 对齐，且 UB 起始地址 32B 对齐
  DataCopy(dst, src, count)（Level-2，按元素 count）：
    count * sizeof(T) 必须满足文档的 DataBlock 粒度；
    非整块部分不会被完整搬运。floor ≠ tail handling，
    不能靠它处理非对齐 tail。
  DataCopyParams：
    blockLen 本身以 DataBlock(32B) 为单位，
    不存在“把字节数填进去再自动帮你取整”。

DataCopyPad
  给非对齐 GM↔UB
  DataCopyExtParams.blockLen 单位 = 字节
  UB 侧起始地址仍要 32B 对齐；GM 侧按元素对齐即可

GetValue / SetValue
  合法标量接口（PIPE_S）
  ≠ 生产批量搬运
```

`ONE_BLK_SIZE = 32`（`official-document` / 头文件）。  
32B 对齐元素数 = `32 / sizeof(T)`：fp16=16，fp32=8，int8=32。这是算术，不是第二套硬件规格。

---

## 选哪条 API

| 判定 | API | 证据 |
| --- | --- | --- |
| 已证明长度与 UB 起址都 32B 对齐 | `DataCopy` 可用 | `official-document`（CANN 8.5.0 非对齐实践） |
| 明确存在非对齐 | `DataCopyPad` | 同上；Pad 就是为这个场景存在的 |
| 设计阶段尚无法证明对齐 | 优先 `DataCopyPad`，或回 tiling 证明对齐 | `recommendation` |

CopyIn 非对齐、CopyOut 却用 `DataCopy`，是常见错配。两边各自按上面判定，不要“进用 Pad、出用 Copy”。

没有 `DataCopyPad` 的旧型号才走 UnPad / GatherMask / 带冗余搬出那套手工方案。**950 普通 Vector 先用 Pad，不要先抄那套百科。**

---

## `blockLen` 单位不要混

同一份 `DataCopyParams` 结构，在两条 API 里 **单位不同**。混了会少搬、多搬或错位，而且常常不报编译错。

| API | 结构 | `blockCount` | `blockLen` 单位 | `blockLen` 范围 |
| --- | --- | --- | --- | --- |
| `DataCopy` | `DataCopyParams` | `uint16_t`，∈ [1, 4095] | **DataBlock = 32B** | ∈ [1, 65535] |
| `DataCopyPad` | `DataCopyExtParams` | 同上 | **字节** | ∈ [1, 2097151] |
| `DataCopyPad` | `DataCopyParams` | 同上 | **字节**（Pad 路径） | 不超过 `uint16_t` |

`DataCopy` 的 Level-2 `count` 是 **元素个数**。文档要求 `count * sizeof(T)` 满足 32B 粒度；非整块不会被完整搬走。这是这条 overload 的截断行为，**不是** tail 处理机制。`DataCopyParams` 路径没有“填字节再 floor”。

`DataCopyPad` 的 stride / gap：UB（VECIN/VECOUT）侧单位是 DataBlock，GM 侧是字节。记住这一句就够；不要在这里展开 stride 图。

`C2` / `C2PIPE2GM` 上 DataCopy 还有 64B/128B 特例。普通 Vector GM↔UB **不要用**。

---

## Ext 参数

`DataCopyPad` 同时吃 `DataCopyParams` 和 `DataCopyExtParams`（头文件 overload，`official-document`）。

Ext 的 `blockLen` 是 `uint32_t`，范围更大；`DataCopyPadExtParams<T>` 的 `paddingValue` 是 `T`。  
**优先 Ext** 是 `recommendation`（少溢出、类型更安全），不是“非 Ext 非法”，也 **没有** 本文件可引用的性能对比。

---

## effective vs aligned（回传到 tiling）

和 [tiling-from-shape](../engineering/tiling-from-shape.md) 同一条合同：

**对齐改变的是搬运/存储合同，不是 logical shape。**  
`alignment changes storage footprint, not logical tensor extent.`

| 用途 | 用哪套长度 |
| --- | --- |
| `DataCopyPad` 的 `blockLen`、Compute / Reduce 的 count | **effective**（真实元素或字节） |
| UB 行偏移、`InitBuffer` 尺寸、下一行起址 | **aligned**（补到 32B） |

方向不要混：

```text
GM → UB（CopyIn）
  effective payload 进入 UB
  为 local layout / alignment 产生的 padding
  不属于 logical tensor

UB → GM（CopyOut）
  GM 只应写回 logical effective payload
  不要因为 UB buffer 是 aligned footprint
  就把 aligned length 当成输出有效长度
```

```text
logical payload length
  ≠
local storage footprint

logical payload
  ≠
legal DMA landing layout
```

每次 DMA 的 **destination UB base** 仍要满足该 API 的对齐（DataCopy / DataCopyPad：32B）。
有效 4B 不能落到 compact `dst + 4*k`（k≥1 时 dest 非 32B 对齐）。
UB map 必须同时写：logical payload、landing layout、physical reserved bytes。
这是本 Card 已有 dest 对齐合同的应用，不是第二条搬运规格。落地检查走 Physical Realizability Gate。

### Invocation ≠ selection

选对 API **不等于** 这一次调用已经合法。性能关键或非自然对齐的搬运，在冻结 API 名之后仍须证明 **exact invocation**：

```text
A selected API is not implementation-ready until the exact invocation
has proven:
- overload/signature
- unit (bytes vs elements; uint16 vs uint32)
- source extent
- destination extent / footprint
- padding/alignment
- stride
- completion semantics
- resource-specific limits of this path
```

`DataCopyPadParams{}` / 默认构造不是证据。4B source 声称 32B slot 时，必须写出 occupancy 与下一 slot 是否重叠。合同细节读 target-version 头文件 / 实现，不要在本 Card 展开公式。
Gate 走 [API Invocation Contract](../../../skills/cam/operator/cam-operator-development/references/performance-by-construction.md)。

elewise 有时可以让 CopyIn 的冗余一起算（官方实践允许），那是明确选择，不是默认。不要把这条默许套到 CopyOut 的 GM 有效长度上。

对齐膨胀会加大 UB footprint → proposal 过不了就 **revise tile**，不要在 kernel 里“差不多对齐”。

容量数字仍读 [950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md) 的运行时接口，不要把 248 KiB 写进 copy 参数。

---

## GetValue / SetValue

`GlobalTensor` / `LocalTensor` 上都有，合法，走 `PIPE_S`（`source-code`）。

| 当作 | 不当作 |
| --- | --- |
| 调试单点、组一个很小的 scalar / 索引 | 生产路径上的 GM↔UB 批量搬运 |
|  | “禁止使用 / 非法 API” |

循环 `SetValue`/`GetValue` 搬整块是 **差的生产搬运**（`recommendation`），不是合法性问题。替代是 `DataCopy` / `DataCopyPad`。

---

## What NOT To Generalize

| 不要当成 fact | 为什么 |
| --- | --- |
| “DataCopy 要对齐 512B” | 某份 skill 索引；官方 Vector `DataCopy` 写的是 **32B** |
| `GetValue`/`SetValue` 禁止使用 | 合法；只是不要当生产搬运 |
| Ext 与非 Ext“同一条 MTE、性能无差” | cannbot 声称；本文无 `benchmark` |
| `blockCount` 可写到 `uint16_t` 满幅 65535 | 官方 Pad/Copy 文档都是 **[1, 4095]** |
| 把 `DataCopy` 的 `blockLen` 填成字节 | 那是 Pad 的单位 |
| Compact / LoopMode / 950 专用 pad 模式 | 新文档有，本树 8.5.0 头文件未在本文核对，标 `unknown` |
| Cube `nd2nz`、CO1、Enhanced、A2 `MatMulImpl` | 别的 API / Case |
| Softmax 逐行模板、stride 全图、UnPad 百科 | 超出本 Card |
| Level-2 `count` 的 floor 能安全处理 tail | floor ≠ tail handling；非整块不会被完整搬走 |

---

## Sources

| Field | Value |
| --- | --- |
| 官方实践 | CANN 8.5.0 [非对齐场景](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/opdevg/Ascendcopdevg/atlas_ascendc_10_0034.html) |
| 官方 API | CANN 8.5.0 [DataCopyPad (ISASI)](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/API/ascendcopapi/atlasascendc_api_07_0265.html) |
| 官方 API | CANN 8.5.0 [DataCopy](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850alpha001/API/ascendcopapi/atlasascendc_api_07_0103.html)（`blockLen` = DataBlock；Level-2 `count` 非整块不完整搬运） |
| 头文件 | `ascendc/basic_api/interface/kernel_struct_data_copy.h` · `kernel_operator_data_copy_intf.h` · `kernel_tensor.h`（CANN 8.5.0 / `cam_wangyibo_dev_85`） |
| 发现来源（非真源） | cannbot `ops/ascendc-api-best-practices/references/api-datacopy.md` @ `c4c425641d11127945d22e5a752fcad77646be97` |
| Related | [tiling-from-shape](../engineering/tiling-from-shape.md)、[950 hierarchy](../hardware/ascend950/core-and-memory-hierarchy.md) |
| Last written | 2026-08-25 |
| status | accepted |
