# CanImplement 不是全部约束

Agent 看到函数名叫 `CanImplement`、Host 也调了、失败还打了一句人话，容易当成「当前 policy 的全部合法性已经编码」。没有。

本文是索引，不是第二份 73 教程。live 数字读 [73](../../../cases/cam/operators/compute/gemm/ascend950-matmul-full-loadA/case.md)，恒 `true` 的链读 [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md)。

证据种类：`source-code` | `design-doc`。本文件 **没有** `benchmark`。

---

## Rule

```text
函数叫 CanImplement
  ≠ 做了检查
做了检查
  ≠ 编码了你以为存在的全部约束
Host 失败文案
  ≠ 谓词
```

先打开实现和调用点，再相信名字或 cout。

---

## Worked examples（本批 live Case）

| Case | `CanImplement` 做什么 | Host | 不要读成 |
| --- | --- | --- | --- |
| 43 / 53 | `return true`（`source-code`） | 43 调了但不看返回值 | “CATLASS 都没有守卫” |
| 73 | `A_bytes + B_pingpong <= L1_SIZE` | 看返回值；失败打印 “MatA tile cannot be full loaded to L1.” | “有检查 = A 能 full-load、half-L1 已验” |

73 的文案说的是 full-K A load 意图。谓词没有 README 一半 L1，也没有 `L1A_TILE_SIZE = L1/2`。命名常量、设计文档、总和不等式、物理拷贝是四件东西。

43 写过「别的 kernel 有真实检查」。73 就是真实检查的样本：**真实 ≠ 完整**。不要把「非恒 true」升级成「L1 规划已闭合」。

---

## 先问什么

```text
1. 这个 Kernel 的 CanImplement 公式是什么？（打开函数体）
2. Host 看不看返回值？失败时打印的那句话和公式是不是同一件事？
3. Block 的命名 buffer / static_assert / README 句子，有没有出现在公式里？
```

不要先问“这个算子有没有 CanImplement”。

---

## Related Cases

| 角色 | Case |
| --- | --- |
| 恒 true | [43](../../../cases/cam/operators/compute/gemm/ascend950-basic-matmul/case.md)、[53](../../../cases/cam/operators/compute/gemm/ascend950-fp8-mx-matmul/case.md) |
| 真实但部分 | [73](../../../cases/cam/operators/compute/gemm/ascend950-matmul-full-loadA/case.md) |

不要并进 66/68 的切 K 索引。不要把 `sparse_matmul_tla.hpp` 写成「完整守卫」——本批没有 close-read。

---

## Sources

| Field | Value |
| --- | --- |
| repository | cann/catlass |
| remote | `https://gitcode.com/cann/catlass.git` |
| commit | `a8b4fffbd9cabc021dfd47253e907a1cde59de25` |
| 43 | `include/catlass/gemm/kernel/basic_matmul_tla.hpp` |
| 53 | `include/catlass/gemm/kernel/mx_matmul_tla.hpp` |
| 73 | `include/catlass/gemm/kernel/matmul_full_loadA_tla.hpp` · `examples/73_ascend950_matmul_full_loadA/matmul_full_loadA_tla.cpp` |
| Last verified | 2026-08-21 |
