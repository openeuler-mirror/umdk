<!--
SPDX-License-Identifier: MIT
Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
Description: Routed async CAM operator test guide.
-->

# Routed async CAM operator tests

These scripts test UMDK's four compact routed-only asynchronous communication
operators in `torch.ops.umdk_cam_op_lib`:

| Phase | Operator |
| --- | --- |
| Dispatch send | `moe_dispatch_send_async` |
| Dispatch receive | `moe_dispatch_recv_async` |
| Combine send | `moe_combine_send_async` |
| Combine receive | `moe_combine_recv_async` |

| File | Purpose |
| --- | --- |
| `async_cam_precision.py` | Independent CPU dispatch and FP16/BF16 combine golden |
| `async_cam_performance.py` | Per-operator and complete-round measurements |
| `async_cam_common.py` | Protocol planning, HCCL setup, and four-stage execution |
| `test_async_cam_*.py` | Offline planner, timing and optional CPU tensor regressions |

The local contract is defined in
[`pybind.cpp`](../../src/cam/comm_operator/pybind/pybind.cpp) and the four
`cam_moe_distribute_*` directories under
[`ascend_kernels`](../../src/cam/comm_operator/ascend_kernels).
The scripts load the locally built `umdk_cam_op_lib` package. They require no
model weights or shared-expert transfers.

## Python-only validation

From the repository root, no torch or Ascend installation is needed for:

```bash
python test/cam/async_cam_precision.py --help
python test/cam/async_cam_precision.py --dry-run
python test/cam/async_cam_performance.py --dry-run
python -m unittest discover -s test/cam -p "test_async_cam_*.py"
```

Dry runs validate topology, positive per-rank lengths, receive capacity,
integer-address limits, buffer requirements, and planned expert chunks.
They execute no native operators. Normal execution requires torchrun and fails
if the runtime, device, or one of the four registered operators is missing.

`test_async_cam_golden` runs tensor regression tests when CPU PyTorch is
installed and otherwise reports skips. It needs no torch-npu or NPU. It checks
FP16/BF16 output rounding, FP32 accumulation order, quantization budgets and
strict bit comparisons; the other two test modules need only standard Python.

## Native setup

Use Ascend 910C (`ascend910_93`) with the matching PyTorch, torch-npu and
CANN/HCCL stack. Build the four operators from this repository:

```bash
./build/cam/build.sh -c ascend910_93 -a \
  "cam_moe_distribute_dispatch_send;cam_moe_distribute_dispatch_recv;cam_moe_distribute_combine_send;cam_moe_distribute_combine_recv"
```

Install the generated CAM `.run` package, source its
`opp/vendors/CAM/bin/set_env.bash`, and install the matching
`output/cam/comm_operator/dist/umdk_cam_op_lib_*.whl`, following the
[CAM build and installation guide](../../src/cam/README.md).
The native run lazily imports `umdk_cam_op_lib` to register the operators.

Launch one process per NPU, with Attention ranks first and MoE ranks second.
All ranks must receive identical script arguments. The default topology is
2 Attention + 2 MoE, Attention TP=2, four experts per MoE, top-k=2, and unequal
Attention lengths `7,5`. `--lengths 32` broadcasts one length to every Attention
rank. Multi-node launches use the usual torchrun rendezvous arguments;
`LOCAL_RANK` selects the local device and `RANK` is the global HCCL rank.

The harness creates a Gloo world for control traffic and a separate full-rank
HCCL group for payloads. It passes the actual HCCL communicator name to every
operator. `comm_id=0` and FP16 `comm_args` are reserved ABI placeholders.
No ordinary HCCL collective is issued on the payload group's windows.

`--window-mb` sets both `HCCL_BUFFSIZE` and `LCCL_BUFFER_SIZE`, as well as the
HCCL group's `hccl_buffer_size`, before native initialization. `--capacity`
sets `BATCH_SIZE_FACTOR=capacity/262144`; it must be a power of two and fit
every TP-aggregated single expert. Multiple experts may require multiple
receive chunks. The preflight rejects configurations outside the harness's
conservative bounds for the current kernels; these bounds are not a claim
that all accepted configurations have been qualified on hardware.

## Precision

```bash
timeout --kill-after=30s 600s torchrun --standalone --nproc_per_node=4 \
  test/cam/async_cam_precision.py --dtype fp16 --dynamic-quant 0

# Multiple chunks, quantized BF16, and repeated use of the same HCCL windows.
timeout --kill-after=30s 600s torchrun --standalone --nproc_per_node=4 \
  test/cam/async_cam_precision.py --dtype bf16 --dynamic-quant 1 --capacity 4

# Empty experts and an entirely empty MoE participant still send completion.
timeout --kill-after=30s 600s torchrun --standalone --nproc_per_node=4 \
  test/cam/async_cam_precision.py --routing sparse --capacity 16

# Two independent Attention groups: receive order may vary by readiness.
timeout --kill-after=30s 600s torchrun --standalone --nproc_per_node=6 \
  test/cam/async_cam_precision.py --attn-ranks 4 --moe-ranks 2 --tp-size 2 \
  --lengths 7,5,3,1 --capacity 4
```

Run both dtypes with quantization 0 and 1, and both balanced/sparse routing.
The default input has distinct token/rank/layer values, distinct top-k IDs,
nonuniform FP32 weights, and a deterministic expert-dependent affine transform.

### CPU golden

The comparison baseline is a CPU golden built from the raw inputs, not from
anything the device returns. Every participating rank's `x`, `expert_ids` and
`expert_weights` are generated once on the CPU, and the golden is derived from
that same tensor that is handed to the operator, so no unrounded FP32 input can
enter the reference. Floating-point payloads, synthetic expert outputs, and the
final combine golden use the selected FP16/BF16 dtype. Device metadata is a
*compared object* and never an input to the reference: routing is rebuilt
independently from the raw `expert_ids`,
otherwise a wrong metadata field would be folded silently into the answer.

The checks answer different questions and are reported under separate labels:

| Layer | What the golden provides | Contract |
| --- | --- | --- |
| Routing and movement | Destination rank, expert and token for every logical route | Exact |
| Quantized dispatch | INT8 values and FP32 scales | Bit-identical under the versioned quantization contract |
| Weighted combine | FP32 multiply/accumulate in top-k slot order, then FP16/BF16 rounding | Compare against a golden with the same dtype as the device output |
| Quantization error | Quantized and unquantized CPU goldens in the selected FP16/BF16 dtype | Separate run-derived absolute budget |

Dispatch is validated per receive chunk: unquantized payloads, quantized INT8
values, and the FP32 dequantization scales must all be bit-identical to the
golden. Quantization is lossy; a payload or a scale that the source only copies
is not, so no tolerance is granted there. The quantization error itself is
reported separately, under its own budget — see the combine note below.

### Quantization contract

The dynamic-quantization contract is versioned in
`async_cam_common._quantize_contract()`, which is the single place allowed to
encode it. It mirrors `QuantProcess()` in
`src/cam/comm_operator/ascend_kernels/cam_moe_distribute_dispatch_send/op_kernel`: per-row FP32
`amax`, multiplier `127/amax`, FP32 product rounding followed by
round-half-to-even, and the reciprocal
`1.0f/(127.0f/amax)` stored as the dequantization scale. The stored value is the
reciprocal of an already-rounded quotient, so it is *not* bit-identical to
`amax/127` in FP32 for most rows; the golden reproduces the kernel's form because
the scales are compared against the device. If the kernel's rounding, range, or
reciprocal convention changes, that function has to change with it and the
contract version must be bumped. A tolerance must never be widened to absorb a
contract change. The same scalar arithmetic is restated in plain Python (`f32`,
`quant_dynamic_scale`, `quant_stored_scale`, `quantize_row`) so CPU tests can pin
it without a tensor library.

Combine uses one CPU golden in the selected FP16/BF16 dtype. The CPU follows the
native arithmetic: multiply and accumulate in FP32 in top-k slot order, then
round once to the output dtype. FP32 is an intermediate arithmetic dtype; the
acceptance baseline is the rounded FP16/BF16 result.

With quantization enabled, a separate CPU golden applies the same expert
transform and weighted combination to the unquantized inputs. Both goldens have
the selected FP16/BF16 dtype. Their difference is checked against an explicit,
run-derived absolute error budget with `rtol=0`, independently of the device
comparison. Quantization error is reported separately from the combine tolerance.

Final combine uses `atol=rtol=0.001` for FP16 and `atol=rtol=0.008` for BF16,
with nonfinite mismatches rejected. Mismatch reports include the number of
bitwise-differing elements, `max_abs_error`, `relative_l2`, the count outside
tolerance, and the first differing index. FP64 is used only to calculate error
diagnostics, never as the golden acceptance dtype. Zero-tolerance checks compare
bit patterns, including the sign of zero.

Only valid payload/scale rows are inspected; unused capacity is uninitialized.
The receive anchor is FP16/BF16 and is separate from INT8 send placeholders.
Inputs deliberately have nonzero row maxima for dynamic quantization; zero-row
quantization, duplicate expert IDs, invalid device metadata injection, graph
execution, and concurrent layers require separate hardware qualification.

## Performance

```bash
timeout --kill-after=30s 600s torchrun --standalone --nproc_per_node=4 \
  test/cam/async_cam_performance.py --measure-mode both \
  --warmup 2 --iterations 10 --output .cache/async-cam-performance.json

timeout --kill-after=30s 600s torchrun --standalone --nproc_per_node=4 \
  test/cam/async_cam_performance.py --measure-mode cycle \
  --warmup 5 --iterations 50 --dtype bf16 --dynamic-quant 1 \
  --output .cache/async-cam-cycle.json
```

An untimed precision round must pass before warmup. Warmup samples are excluded
from measured summaries. `both` runs separate `send` and `recv` schedules:

- `send`: receivers announce readiness before senders launch. Sender staggering
  and a receive guard are configured by `--sender-stagger-ms` and
  `--receiver-guard-ms`. Summaries include dispatch-send and combine-send.
- `recv`: senders announce readiness before native launch, then receivers wait
  `--receiver-delay-ms`. Only receive operators are synchronously timed;
  unmeasured sends are not synchronized before receivers can post.
- `cycle`: all four operators are measured without artificial delays. This is
  a serialized harness round with a synthetic expert transform.

Readiness describes a host about to launch, not a confirmed running kernel.
Delays apply only to the first call of each phase so later chunks drain freely.
Use a separate device-profiler run to establish whether peer waits or sender
overlap remain; this harness does not claim pure transfer or kernel latency.

| Metric | Boundary |
| --- | --- |
| `host_ms` | Native call through NPU synchronization, including launch and waits |
| `event_ms` | NPU stream events around the native call, including device waits |
| `lifecycle_ms` | Whole round including CPU metadata, transforms, control and delays |

CPU oracle work is excluded from measured rounds. Per-op intervals exclude the
expert transform and deliberate scheduling delay. Each dispatch-receive and
combine-send chunk is one sample; unequal chunk counts must not be treated as
equal request counts. JSON includes raw samples, per-rank mean/median/p95/min/max,
and the per-iteration maximum across ranks for complete-round latency. The p95
uses the nearest-rank definition. There is no inferred bandwidth or model
throughput claim.

Successful JSON reports are written after normal process-group teardown.

## Hardware evidence still required

The local Python checks do not establish Ascend correctness, CANN compilation,
HCCL connectivity, or performance. Record the exact UMDK source revision, command,
device placement, CANN/HCCL/driver versions, PyTorch/torch-npu versions, window
sizes, and JSON/log artifacts when running on hardware. Compare performance
only with identical workload, topology, warmup, iterations, and measurement mode.

`--timeout-seconds` bounds control operations and arms a per-round watchdog.
Some native kernels poll device flags without a process-group timeout; a stuck
round terminates its worker rather than trying to synchronize it during cleanup.
The external Linux `timeout` in the examples also bounds startup and teardown.
Device cleanup after failure still requires validation on the target stack.
