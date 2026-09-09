# GatherSelectionSparseFlashAttention

A3-only MIX AIC/AIV operator ported from cann-recipes `gather_KV_custom`.
It fuses selected-KV cache service into the arch22 KvQuantSparseFlashAttention MLA pipeline.

Contract (initial):

- SoC: `ascend910_93`
- Query: FP16/BF16 TND, D=576
- Packed INT8 PA KV, D=656
- KV head = 1, sparse/selection block size = 1, `attention_mode=2`

Python:

```python
import umdk_cam_op_lib  # noqa: F401

attention_out, selection_actual_seq = torch.ops.umdk_cam_op_lib.gather_selection_sparse_flash_attention(
    query,
    selection_kv_cache,
    selection_kv_block_table,
    selection_kv_block_status,
    selection_topk_indices,
    full_kv_cache,
    full_kv_block_table,
    actual_seq_lengths_query,
    full_kv_actual_seq,
    scale_value=scale,
)
```

Build (CAM):

```bash
./build/cam/build.sh -c ascend910_93 -a gather_selection_sparse_flash_attention
```

NPU functional + precision (A3, after install):

```bash
# miss fan-out / status commit / second-pass hit, and attention vs gather+KQSFA
python3 src/cam/examples/test_gather_selection_sparse_flash_attention.py
# optional: GSFA_DEVICE=0 GSFA_MISS_RATES=0,0.5,1
```

Host-only selection golden (no NPU, does not exercise the installed op):

```bash
python3 src/cam/examples/test_gather_selection_sparse_flash_attention_cpu.py
```
