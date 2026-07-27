# GatherSelectionKvCacheCustom

`GatherSelectionKvCacheCustom` is an isolated experimental variant of
`GatherSelectionKvCache`. It keeps the stateful topK/reuse analysis at token
granularity and distributes only full-KV data copies across all available AIV
cores.

The production operator and its tiling/kernel files are not modified.

This is a separate operator instead of another branch in the existing kernel.
The custom op still needs one host tiling entry and one device-kernel entrypoint
because those are required by the AscendC registration/build chain. Its tiling
key is fixed to `1`; it does not introduce another runtime strategy matrix into
the production operator.

## Three phases

1. Token leaders load topK/status metadata, filter and sort topK IDs, detect
   same-token selected-cache hits, assign insertion positions, and write a copy
   plan to user workspace. Rare selected-cache compaction moves remain serialized
   on the token leader so an in-place move cannot overwrite another move's source.
2. After a cross-core barrier, all AIV cores consume the flattened
   `[token, valid_topk]` plan. Same-token hits and completed compaction moves are
   skipped; remaining entries are copied from full KV to their preassigned
   selected-cache positions.
3. After a second cross-core barrier, token leaders reload and commit block
   status plus `selection_kv_actual_seq`.

Workspace contains one `valid_topk` value per token and three int32 arrays per
plan item: `topk_id`, `insert_idx`, and `action`. The tiling also reserves the
platform-reported AscendC system workspace and the kernel accesses its plan
through `GetUserWorkspace`.

## Intentional first-version restrictions

- `33 <= TOPK <= 2048`
- `selection_topk_block_size == 1`
- `H == 1`
- `S == 1`
- TND input `[B, 1, TOPK]` or BSND input `[B, 1, 1, TOPK]`

`S == 1` is a correctness boundary, not just a performance shortcut. With
multiple query positions, selected-cache reuse may read data belonging to a
different seq position while another core rewrites it. Supporting that case
requires an additional dependency/snapshot design.

## Torch API

After building and installing the CAM run package + `umdk_cam_op_lib` wheel:

```python
import umdk_cam_op_lib  # noqa: F401

torch.ops.umdk_cam_op_lib.gather_selection_kv_cache_custom(
    selection_k_rope,
    selection_kv_cache,
    selection_kv_block_table,
    selection_kv_block_status,
    selection_topk_indices,
    full_k_rope,
    full_kv_cache,
    full_kv_block_table,
    full_kv_actual_seq,
    full_q_actual_seq,
    selection_topk_block_size=1,
)
```

This experimental API is intended for the explicit eager/stream pipeline only.

## Build

Register the operator directory name in `operator_registry.json`, then build as
usual (optionally restrict the op set):

```bash
./build/cam/build.sh -c ascend910_93 -a gather_selection_kv_cache_custom
```

## Validation

```bash
python3 src/cam/examples/test_gather_selection_kv_cache_custom.py
python3 src/cam/examples/benchmark_gather_selection_kv_cache_custom.py
```
