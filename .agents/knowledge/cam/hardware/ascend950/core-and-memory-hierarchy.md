# Ascend 950 核与片上层级

status: **accepted**

Agent 写 **Ascend 950 / Weaver `ascend950`** 算子时，先问 **当前设备的 `NpuArch` 和 `GetCoreMemSize`**，再定 tile 预算。不要把某张 Case、某份 cannbot 表、或某一份 ini 的核数抄进 kernel。

本文的「层级」主要指算子设计需要预算的 **memory resources 及其平台容量**，不试图给出 DAV_3510 全部合法数据搬运通路图。没画的箭头不表示不存在。

本文只冻结 **能在本机 CANN 8.5.0 对上的命名与片上容量**。不是代际百科，不是带宽/算力广告，也不是 Cube Case 的 L1 公式。

证据种类：`official-document` | `source-code` | `recommendation` | `unknown`。  
本文件 **没有** `benchmark`。

---

## 先问什么

```text
1. 当前平台的 NpuArch 是什么？（GetCurNpuArch，不要猜产品名）
2. 当前设备的 UB / L1 / L0* 各是多少？（GetCoreMemSize）
3. 核数用 GetCoreNumAic / GetCoreNumAiv，还是抄了 28/32？
4. 这个数字来自 ini 典型值、Case ArchTag，还是运行时接口？
```

不要先问“950 的 UB 是不是 248KB”。那是第 2 问对上之后的核对，不是第 1 问。

---

## 同物异名（先对齐词，再读数字）

这些名字指同一代际的不同文件，**不要合成一个 token**。

| 出现位置 | 写法 | 证据 |
| --- | --- | --- |
| Weaver / Cases | `ascend950`、产品口语 “Ascend 950” | `source-code` |
| CATLASS | `Arch::Ascend950`；部分工程 `CATLASS_ARCH=3510` | `source-code` |
| `platform_ascendc.h` `SocVersion` | **`ASCEND910_95`**，注释 `__DAV_C310__`。**没有 `ASCEND950` 枚举** | `official-document` |
| `soc_spec.h` `NpuArch` | **`DAV_3510 = 3510`** | `official-document` |
| `platform_config/*.ini` | 文件名 **`Ascend910_95xx.ini`**（不是 `Ascend950*.ini`）；字段 **`NpuArch=3510`** | `official-document` |
| 算子仓目录 | **`arch35/`**。本轮检查的 3510-targeted 实现用这个目录名。是 **repo convention**，不是 CANN `NpuArch` / `SocVersion` API；头文件也 **没有** `arch35` 枚举 | `source-code`（ops / vllm-ascend / Weaver Cases） |

`__DAV_C310__` 是 device 编译宏；Host 侧对应注释挂在 `SocVersion::ASCEND910_95` 上。**不要从 C310 的数字字面推出 3510。**  
`GetCurNpuArch()` 失败返回 `NpuArch::DAV_RESV`。

对照样本（只用来防抄错代，不是 950 规格）：本树 `Ascend910B1.ini` 为 `NpuArch=2201`（`DAV_2201`），UB 192 KiB、L0C 128 KiB。不要把 A2 的 UB/L0C 写进 950 kernel。

---

## 运行时读什么

Host tiling 用 `platform_ascendc::PlatformAscendC`（`official-document`）：

```text
GetCurNpuArch()     → NpuArch（DAV_3510 / DAV_2201 / …）
GetSocVersion()     → SocVersion（ASCEND910_95 / ASCEND910B / …）
GetCoreMemSize(t)   → 该 CoreMemType 的字节数
GetCoreNumAic()     → Cube / AICore 个数
GetCoreNumAiv()     → VectorCore 个数
```

`CoreMemType`：`L0_A` `L0_B` `L0_C` `L1` `L2` `UB` `HBM` `FB` `BT`。  
`FB` 的硬件含义本文标 `unknown`，不要当第三套 UB 用。  
另有 `GetCoreMemBw`：接口存在，**本文不引用任何 TB/s 数字**。

Case / ArchTag 里的 `UB_SIZE`、`L1_SIZE`（如 `Arch::Ascend950::UB_SIZE`）是 **编译期架构常量 / 该实现采用的资源假设**，不是当前设备的 live runtime value。它只证明这份实现按某个 ArchTag 的静态假设设计/编译，**推不出** launch 时读过实际板卡容量。Host tiling 要适配实际平台时，优先 `PlatformAscendC` 查询。命名检查也不等于容量全集，见 [CanImplement](../../engineering/canimplement-is-not-all-constraints.md)。

---

## 片上容量（NpuArch=3510，本树 22/22 一致）

本机 CANN **8.5.0**、`aarch64-linux/data/platform_config` 中 **22** 份 `NpuArch=3510` ini，下列字段 **全部相同**（`official-document`）。CATLASS `Arch::Ascend950` 与之一致（`source-code`），仍建议 Host 走 `GetCoreMemSize`。

| 层级 | ini 字段 | 字节 | 习惯读法 |
| --- | --- | --- | --- |
| L1 | `l1_size` | 524288 | 512 KiB |
| UB | `ub_size` | 253952 | 248 KiB（248×1024） |
| L0A | `l0_a_size` | 65536 | 64 KiB |
| L0B | `l0_b_size` | 65536 | 64 KiB |
| L0C | `l0_c_size` | 262144 | 256 KiB |
| BT | `bt_size` | 4096 | 4 KiB |

同批 ini 还一致：`core_type_list=CubeCore,VectorCore`，`cube_core_cnt : vector_core_cnt = 1 : 2`，`sparsity=0`，`cube_m/k/n_size=16`。  
1:2 是 **这些 3510 ini 的事实**，不是“所有 SKU 永远 28+56”。核数仍读 `GetCoreNumAic` / `GetCoreNumAiv`。

ini 必要但不充分：这 22 份对上了片上 buffer，不证明每份都是量产板，也不证明通路删改。

---

## 随 SKU 变的量（禁止写成“950 标称”）

同一 `NpuArch=3510` 下，本树 ini 已经拆开：

| 量 | 本树观察到的范围 | 怎么用 |
| --- | --- | --- |
| Cube / Vector 核 | cube ∈ {8, 28, 32, 36}，vec 恒为 2× | `GetCoreNumAic` / `GetCoreNumAiv` |
| L2 | 16 / 96 / 112 / 128 MiB | `GetCoreMemSize(L2)` |
| HBM（`memory_size`） | 16–144 GiB | `GetCoreMemSize(HBM)` |

`Ascend910_950z.ini`：8 cube / 16 vec / 16 MiB L2 / 16 GiB。这是本树中一个明显较小的配置样本，足以反证「950 固定 28 cube / 56 vec」。不要推断其产品定位。

---

## 和算子设计怎么接

```text
普通 Vector tiling     → 片上预算看 UB（GM ↔ UB）
Cube / GEMM Cases      → 再看 L1 / L0A / L0B / L0C
核间怎么切             → 用运行时核数，不要写死 28 或 32
```

- Vector 第一次设计读 [tiling-from-shape](../../engineering/tiling-from-shape.md)。容量回传用 **本文的运行时接口 + 上表典型值核对**，不要把 248 KiB 写进 `TilingData`。
- L1/L0 是 **Cube-oriented** 层级：GEMM Case 会用到。不要把这句话升级成“Vector 硬件上碰不到 L1”的定律。
- 68 一类 reduce 的 **192 KiB computeLength** 是那次 tile 提案，**不是** UB 容量。3510 的 UB 典型值是 248 KiB；2201 才是 192 KiB。
- 73 的 L1 不等式是那份 kernel 的 `CanImplement`，不要并进本文。

---

## What NOT To Generalize

| 不要当成 fact | 为什么 |
| --- | --- |
| “L1→GM / GM→L0 已删除” | cannbot 声称；本树 ini/头文件 **未证实**。标 `unknown`，本轮不 promote |
| 1.4 / 1.6 TB/s、54T 双发、Kirin 全代表 | 广告或他仓表，无本机一手 |
| SIMT 128KB register / SSBuffer 容量 | 经验值，未对 ini |
| `SocVersion::ASCEND950` | CANN 8.5.0 **没有这个枚举** |
| 把 `arch35` 写成 CANN API | 只是算子仓目录约定 |
| 把 28 cube / 56 vec 写成“950” | 只是若干 SKU；950z 是 8/16 |
| 把 Case `UB_SIZE` / `L1_SIZE` 当 live 平台 | 静态 ArchTag 常量 / implementation assumption；应用 `GetCoreMemSize` |
| 把 Get/SetValue、repeat 上限写进本文 | 留给 API Card |

---

## Sources

| Field | Value |
| --- | --- |
| 核对环境 | Docker `cam_wangyibo_dev_85`；CANN **8.5.0** `/usr/local/Ascend/cann-8.5.0` |
| ini | `aarch64-linux/data/platform_config/Ascend910_95{0z,72,74,75,76,77,78,79,7b,7c,7d,81,82,84,87,88,89,8a,8b,91,92,99}.ini`（22 份 `NpuArch=3510`） |
| 对照 ini | `Ascend910B1.ini`（`NpuArch=2201`） |
| 头文件 | `aarch64-linux/include/tiling/platform/platform_ascendc.h`（`CoreMemType` / `SocVersion` / `GetCoreMemSize` / `GetCurNpuArch`） |
| 头文件 | `aarch64-linux/include/platform/soc_spec.h`（`NpuArch::DAV_3510 = 3510`） |
| CATLASS ArchTag 常量 | `urma_moonep/3rdparty/catlass/include/catlass/arch/arch.hpp`（`Arch::Ascend950`） |
| 发现来源（非真源） | cannbot `ops/npu-arch` @ `c4c425641d11127945d22e5a752fcad77646be97` |
| Related | [tiling-from-shape](../../engineering/tiling-from-shape.md)、[CanImplement](../../engineering/canimplement-is-not-all-constraints.md) |
| Last written | 2026-08-22 |
| status | accepted |
