# Mask, repeat, and kernel limits

status: **accepted**

普通 **Vector** kernel：先问 **你调用的是哪条 overload**，再填 `repeatTime` / `count` / `mask`。不要把行数直接塞进 `uint8_t repeatTime`，也不要把 `std::sqrt` 写进 `__aicore__` 函数。

本文是短约束 Card，不是算术 API 说明书，也不是 mask 百科。Copy / pipeline / TQue 已有专文。

证据种类：`official-document` | `source-code` | `recommendation`。  
本文件 **没有** `benchmark`。

---

## 先问什么

```text
1. 这条 API 是 Level-0（mask + repeatTime）还是 Level-2（count）？
2. repeatTime 的类型是不是 uint8_t？这次要迭代几次？
3. Compare 的 count * sizeof(T) 是否 256B 对齐？
4. 这条约束有没有回传到 tile，或 kernel 内的 outer loop？
```

不要先问“repeat 填 256 会不会自动拆批”。

---

## Rule

```text
先看 overload，再填数

same number / same unit
  ≠
same API contract

Level-0（mask + repeatTime）
  repeatTime / mask 的合法范围由具体 overload 决定
  表示类型常为 uint8_t；本文引用的官方约束要求 repeatTime ≤ 255
  256 传进 uint8_t 是 C++ 截断，不是 tail 处理 / 自动拆批
  不要把“一拍 256B”推广到所有 Vector API / 所有 dtype

Level-2（count）
  按元素个数；不要套 255
  Compare 的 count：元素所占空间须 256B 对齐

Kernel
  计算走 Ascend C API 与 TPipe buffer
  不要 new / malloc / std::vector
  不要把 Host 的 std:: 数学抄进 __aicore__
```

超限就 **revise**：减小 tile，或在 kernel 内增加外层循环，把一次超限工作拆成多次合法 API 调用。和 [tiling-from-shape](../../engineering/tiling-from-shape.md) 同一条回传。

---

## `repeatTime` ≤ 255 只挂在对应 overload

官方高维切分说明：Vector 用 `repeatTime` 配迭代次数，**由于硬件限制不能超过 255**（`official-document`）。  
本机 CANN 8.5.0 头文件里，`Add`/`Sub` 等 Level-0 的 `repeatTime` 是 `uint8_t`（`source-code`）。

| 合同 | 不要读成 |
| --- | --- |
| 这条 overload 的 `repeatTime` ≤ 255 | 所有 Vector API 都有 255；下界一定是 0 |
| Level-2 `Add(dst, src0, src1, count)` 按元素 | 把 `count=256` 当成 repeat 溢出 |
| 超了就改 tile，或在 kernel 内加 outer loop | `repeatTime` 会自动 floor / 拆批 |

`uint32_t rows = 256` 传进 `uint8_t repeatTime`：按 C++ 转成 `0`。这是类型截断，**不是** DataCopy Level-2 那种文档写明的向下取整，更不是 tail 机制。

`repeatTime=0` 有没有有效执行语义，以该 overload 文档为准。`uint8_t` 能表示 0，只是语言层事实。

`mask` 的元素容量随具体 API 和 datatype 查文档；不要仅凭 `256/sizeof(T)` 为任意 API 推 mask。Level-0 的 mask/repeat **不是** Level-2 的 `count`。不要在这里展开 bit 模式。

Example（只对本文引用的典型 Vector 高维切分模型，如官方用 `Add` 说明的那条）：一个 `repeat` 对应 256B 的 Vector 数据处理粒度；连续模式 mask 上限约 `256/sizeof(T)`。不要把这条当所有 Level-0 通例。

---

## Compare：256B 是这条 API 的存储合同

Level-2 `Compare(..., uint32_t count)`：官方要求 `count` 个元素所占空间 **256 字节对齐**（`official-document`）。整 tensor 重载时，src 也要 256B 对齐。

这是 Compare 自己的合同，不是普通 `Add` 的 32B，也不是“DataCopy 要对齐 512B”。

对齐的是 **Compare 看到的 footprint**。logical 有效长度仍按 [memory-copy-and-alignment](../../memory/memory-copy-and-alignment.md)：GM 只写回 effective payload。padding 策略（填极值再比）是实现选择，本文不写菜谱。

---

## Kernel 侧不要把 Host C++ 当核上运行时

| 不要在 `__aicore__` 里做 | 用什么 |
| --- | --- |
| `new` / `malloc` / `std::vector` | `TPipe::InitBuffer` + `TQue`/`TBuf` |
| `std::sqrt` / `std::exp` / `<cmath>` 批量数学 | `AscendC::Sqrt` / `Exp` 等 |
| Host tiling 文件 `#include "kernel_operator.h"` | 那份头给核函数 |

Host 侧 `std::min`、`aclrtMalloc` 仍然合法。禁的是 **核上** 把 Host 运行时/堆/STL 数学当计算路径。

---

## What NOT To Generalize

| 不要当成 fact | 为什么 |
| --- | --- |
| 所有 Vector API `repeatTime`≤255 | 只看带该参数的 overload |
| 所有 Level-0 都是一拍 256B | 只是被引用的高维切分模型；查具体 API |
| 256 会“自动拆成两拍” | 类型截断或超硬件上限，不是拆批器 |
| `repeatTime` 合法下界一定是 0 | 未在本文对每条 overload 核实 |
| Compare 256B = 普通搬运 32B | 不同 API 的存储合同 |
| 本文是 Add/Sub/Exp 说明书 | 不写每个算术 API |
| GatherMask / A2 高阶 API | 不在本 Card |

---

## Sources

| Field | Value |
| --- | --- |
| 官方 | CANN 8.5.0 [矢量高维切分 / repeatTime](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850/opdevg/Ascendcopdevg/atlas_ascendc_10_0022.html)（引用模型：`repeatTime`≤255；该模型下一拍 256B） |
| 官方 | CANN 8.5.0 [Compare](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/850alpha001/API/ascendcopapi/atlasascendc_api_07_0066.html)（`calCount` 所占空间 256B 对齐） |
| 头文件 | `kernel_operator_vec_binary_intf.h`、`kernel_operator_vec_cmpsel_intf.h`（CANN 8.5.0 / `cam_wangyibo_dev_85`） |
| 发现来源（非真源） | cannbot `api-repeat-limits.md` / `api-restrictions.md` @ `c4c425641d11127945d22e5a752fcad77646be97` |
| Related | [tiling-from-shape](../../engineering/tiling-from-shape.md)、[memory-copy-and-alignment](../../memory/memory-copy-and-alignment.md) |
| Last written | 2026-08-22 |
| status | accepted |
