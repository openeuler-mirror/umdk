# SPDX-License-Identifier: MIT
"""Traffic conservation and comparison-contract tests; no NPU required."""

import copy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


TEST_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(TEST_ROOT))
from deepep_benchmark_metrics import aggregate_report, compare_reports, gbps, summarize, traffic_plan


def test_dedup_dispatch_and_expanded_combine_have_different_counts():
    # Two slots on the same F share one forward token, but return two payloads.
    plan = traffic_plan([[[0, 1, 2], [2, 3, -1]]], 2, 4, 128, 3)
    assert plan['unique_tokens_a_f'] == [[1, 2]]
    assert plan['routes_a_f'] == [[2, 3]]
    assert plan['expert_counts'] == [[1, 1], [2, 1]]
    assert sum(plan['ep_combine_payload_bytes_per_f']) == 3 * 256
    assert sum(plan['afd_combine_payload_bytes_per_f']) == 5 * 256
    assert plan['afd_dispatch_data_bytes_per_a'] == [3 * (256 + 64) + 4 * 5 + 8 * 4]


def test_bf16_k6_counts_transferred_metadata_not_storage_padding():
    plan = traffic_plan([[[0, 1, 2, 3, 4, 5]]], 2, 256, 7168, 6)
    assert plan['payload_bytes_per_row'] == 14336
    assert plan['afd_metadata_bytes'] == 96
    assert plan['afd_record_transfer_bytes'] == 14432
    assert plan['afd_record_storage_stride'] == 14848
    assert plan['afd_dispatch_record_bytes_per_a'] == [14432]
    assert sum(plan['afd_combine_payload_bytes_per_f']) == 6 * 14336
    assert plan['padded_rows_per_f'] == [6 * 128, 0]
    # All storage padding is excluded from both traffic numerators.
    assert plan['afd_record_storage_stride'] not in plan['afd_dispatch_record_bytes_per_a']


def test_masks_and_empty_ranks_do_not_inflate_payload():
    plan = traffic_plan([[[0, 1], [2, 3]], [[-1, -1]]], 2, 4, 128, 2,
                        masks=[[False, True], [True]])
    assert plan['unique_tokens_a_f'] == [[0, 1], [0, 0]]
    assert plan['routes_a_f'] == [[0, 2], [0, 0]]
    assert plan['routes_per_f'] == [0, 2]
    assert plan['afd_dispatch_data_bytes_per_a'][1] == 8 * 4  # Count/prefix tables still sent.


def test_official_backend_preserves_masked_routes_and_zero_weights():
    torch = pytest.importorskip('torch')
    from deepep_benchmark_runtime import OfficialBackend

    args = SimpleNamespace(num_tokens=3, hidden=128, num_topk=2, timeout_seconds=10)
    rt = SimpleNamespace(
        args=args, rank=0, is_source=True, device=torch.device('cpu'), torch=torch,
        routes=[[[0, -1], [-1, -1], [17, 255]]], plan={'ep_expert_id_offset': 256},
        source_x=lambda _rank: torch.zeros((3, 128), dtype=torch.bfloat16),
        dist=SimpleNamespace(distributed_c10d=SimpleNamespace(_get_default_group=lambda: None)),
        deep_ep=SimpleNamespace(EPBuffer=lambda *_args, **_kwargs: object()),
    )
    backend = OfficialBackend(rt)
    assert backend.idx.tolist() == [[256, -1], [-1, -1], [273, 511]]
    assert backend.weights.dtype == torch.float32
    assert backend.weights.tolist() == [[1.0, 0.0], [0.0, 0.0], [1.0, 1.0]]


def test_combine_golden_excludes_masked_slots():
    torch = pytest.importorskip('torch')
    from deepep_benchmark_runtime import Runtime

    # Values 1 and 2 for slots 0 and 1 make either masked contribution observable.
    rt = SimpleNamespace(
        args=SimpleNamespace(num_tokens=4, hidden=1, num_topk=2), rank=0, is_source=True,
        device=torch.device('cpu'), torch=torch, iteration=0, expected_outputs={},
        routes=[[[0, -1], [-1, 0], [-1, -1], [0, 1]]],
        fixture=lambda _tokens, slots: (slots + 1).to(torch.bfloat16).unsqueeze(1),
    )
    output = torch.tensor([[1], [2], [0], [3]], dtype=torch.bfloat16)
    Runtime.validate_combine(rt, output)
    with pytest.raises(RuntimeError, match='combined result differs'):
        Runtime.validate_combine(rt, torch.full_like(output, 3))


@pytest.mark.parametrize('routes', [[[[0, 0]]], [[[0, 4]]], [[[0, -2]]], [[[0]]]])
def test_invalid_route_contract_is_rejected(routes):
    with pytest.raises(ValueError):
        traffic_plan(routes, 2, 4, 128, 2)


@pytest.mark.parametrize('world', [4, 8])
def test_requested_4096_topk6_shape_conserves_routes(world):
    a = f = world // 2
    routes = [[[((token * 7 + source * 17 + k) % 256) for k in range(6)]
               for token in range(4096)] for source in range(a)]
    plan = traffic_plan(routes, f, 256, 7168, 6)
    assert sum(plan['routes_per_f']) == a * 4096 * 6
    assert sum(map(sum, plan['unique_tokens_a_f'])) <= a * 4096 * min(f, 6)
    assert plan['q'] >= a * 4096
    assert plan['q'] >= max(plan['routes_per_f'])
    assert plan['q_alloc'] >= max(plan['padded_rows_per_f'])
    assert plan['ep_physical_expert_slots'] == 512
    assert plan['ep_expert_id_offset'] == 256
    # Every mapped expert is on a physical F rank, with the same local expert ID.
    for expert in range(256):
        physical = expert + plan['ep_expert_id_offset']
        assert physical // plan['local_experts'] == a + expert // plan['local_experts']
        assert physical % plan['local_experts'] == expert % plan['local_experts']


def test_decimal_bandwidth_and_zero_interval_rejection():
    assert gbps(1_000_000_000, 1000) == 1
    for milliseconds in [0, -1, float('nan'), float('inf')]:
        with pytest.raises(ValueError):
            gbps(1, milliseconds)


def test_aggregate_uses_aligned_per_iteration_maxima_and_no_duplex_factor():
    plan = traffic_plan([[[0, 1]], [[2, 3]]], 2, 4, 128, 2)
    samples = [
        [{'iteration': 5, 'dispatch_send_ms': 1, 'combine_recv_ms': 7,
          'dispatch_harness_ms': 12, 'combine_harness_ms': 14}],
        [{'iteration': 5, 'dispatch_send_ms': 3, 'combine_recv_ms': 6,
          'dispatch_harness_ms': 13, 'combine_harness_ms': 12}],
        [{'iteration': 5, 'dispatch_recv_ms': 2, 'combine_send_ms': 4,
          'dispatch_harness_ms': 11, 'combine_harness_ms': 13}],
        [{'iteration': 5, 'dispatch_recv_ms': 4, 'combine_send_ms': 2,
          'dispatch_harness_ms': 12, 'combine_harness_ms': 14}],
    ]
    result = aggregate_report('cam', plan, samples)['per_iteration']
    assert result['dispatch_device_envelope_ms'] == [7]
    assert result['combine_device_envelope_ms'] == [7]
    assert result['dispatch_accounted_gbps'] == [sum(plan['afd_dispatch_data_bytes_per_a']) / 3e6]
    assert result['combine_accounted_gbps'] == [sum(plan['afd_combine_payload_bytes_per_f']) / 4e6]
    samples[2][0]['iteration'] = 6
    with pytest.raises(ValueError, match='identities'):
        aggregate_report('cam', plan, samples)


def test_percentiles_are_nearest_rank():
    assert summarize(range(1, 101))['p95'] == 95


def reports():
    summary = {'statistics': {name: {'median': value} for name, value in [
        ('dispatch_device_envelope_ms', 2), ('combine_device_envelope_ms', 4),
        ('dispatch_harness_ms', 8), ('combine_harness_ms', 16)]}}
    base = {'backend': 'official', 'status': 'PASS',
            'provenance': {'verified': True, 'test_sha256': 'same', 'test_modules_sha256': {'metrics': 'same'}},
            'metric_version': 'test', 'workload': {'route_sha256': 'same', 'tokens_per_source': [4096, 4096]},
            'protocol': {'num_ai_cores': 32, 'cache_mode': 'cold'},
            'environment': {'torch': '2.10', 'torch_npu': '2.10', 'device_names': ['A5'] * 4,
                            'CANN': {'content': '9.2.0'}},
            'summary': summary}
    candidate = copy.deepcopy(base)
    candidate['backend'] = 'cam'
    candidate['rank_results'] = [
        {'rank': rank, 'backend_identity': {'cam_opp': {'status': 'observed', 'sha256': '1' * 64}}}
        for rank in range(4)
    ]
    return base, candidate


def test_comparison_never_reports_a_bandwidth_speedup():
    base, candidate = reports()
    result = compare_reports(base, candidate)
    assert result['bandwidth_ratio'] is None
    assert result['cam_opp_sha256'] == '1' * 64 and not result['cam_opp_pinned']
    assert result['latency_comparison']['dispatch_device_envelope_ms']['ratio_official_over_cam'] == 1


@pytest.mark.parametrize('field,value', [('workload', {}), ('protocol', {}), ('metric_version', 'different')])
def test_comparison_rejects_mismatched_work_or_measurement(field, value):
    base, candidate = reports()
    candidate[field] = value
    with pytest.raises(ValueError, match='incomparable'):
        compare_reports(base, candidate)


def test_comparison_rejects_unverified_or_correctness_only_result():
    base, candidate = reports()
    candidate['provenance']['verified'] = False
    with pytest.raises(ValueError, match='provenance'):
        compare_reports(base, candidate)
    candidate['provenance']['verified'] = True
    candidate['summary'] = None
    with pytest.raises(ValueError, match='samples'):
        compare_reports(base, candidate)


@pytest.mark.parametrize('identity', [None, {'status': 'observed', 'sha256': '2' * 64},
                                      {'status': 'unresolved'}])
def test_comparison_rejects_inconsistent_cam_opp(identity):
    base, candidate = reports()
    candidate['rank_results'][1]['backend_identity']['cam_opp'] = identity
    with pytest.raises(ValueError, match='CAM OPP identity'):
        compare_reports(base, candidate)


def test_comparison_rejects_different_cann_or_harness():
    base, candidate = reports()
    candidate['environment']['CANN']['content'] = '9.1.0'
    with pytest.raises(ValueError, match='CANN'):
        compare_reports(base, candidate)
    candidate['environment']['CANN']['content'] = '9.2.0'
    candidate['provenance']['test_sha256'] = 'changed'
    with pytest.raises(ValueError, match='script revisions'):
        compare_reports(base, candidate)


def test_dry_run_requires_neither_torch_nor_npu():
    run = subprocess.run([sys.executable, str(TEST_ROOT / 'benchmark_deepep_afd.py'), '--dry-run',
                          '--num-processes', '8'], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    data = json.loads(run.stdout)
    assert data['roles'] == '4A4F' and data['tokens_per_A'] == 4096
    assert data['runtime'] == 'NOT TESTED'


def test_fixture_matches_official_sine_sample_then_integer_quantization():
    torch = pytest.importorskip('torch')
    from deepep_benchmark_runtime import route_fixture
    import math
    ids = torch.tensor([0, 5, 4096, 8191], dtype=torch.int64)
    slots = torch.tensor([0, 1, 3, 5], dtype=torch.int64)
    token_seeds = ids.unsqueeze(1) * 6 + torch.arange(6).unsqueeze(0)
    values = torch.sin((((token_seeds * 131071 % (4 * 4096 * 6)).float() + 1) /
                        (4 * 4096 * 6)).unsqueeze(-1) * torch.arange(1, 129, dtype=torch.float32) + math.sin(0.0))
    expected = torch.round(values.to(torch.bfloat16).float() * 8).to(torch.bfloat16)
    actual = route_fixture(torch, ids, slots, 128, 6, 4096, 4, 0)
    assert torch.equal(actual, expected[torch.arange(4), slots])


def test_integer_fixture_eliminates_local_reduction_rounding_difference():
    torch = pytest.importorskip('torch')
    from deepep_benchmark_runtime import route_fixture
    ids = torch.arange(32, dtype=torch.int64)
    routes = [route_fixture(torch, ids, torch.full_like(ids, k), 128, 6, 4096, 4, 0) for k in range(6)]
    direct = sum((x.float() for x in routes), torch.zeros((32, 128))).to(torch.bfloat16)
    groups = [sum((routes[k].float() for k in indices), torch.zeros((32, 128))).to(torch.bfloat16)
              for indices in ((0, 2, 5), (1, 3, 4))]
    staged = (groups[0].float() + groups[1].float()).to(torch.bfloat16)
    assert torch.equal(direct, staged)
