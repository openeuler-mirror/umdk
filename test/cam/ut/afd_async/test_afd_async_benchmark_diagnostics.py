# SPDX-License-Identifier: MIT
"""Regression checks for issue #6 source selection and ABI diagnostics."""

import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

TEST_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(TEST_ROOT))
import benchmark_afd_async as benchmark
from afd_async_benchmark_diagnostics import (
    CAM_OPS, CONTEXT, DiagnosticTrace, cam_opp_manifest, decode_context, observe_controls,
    require_registered_storage, tensor_storage,
)


def make_opp(root):
    tbe = root / 'op_impl/ai_core/tbe'
    files = [root / 'op_api/lib/libcust_opapi.so', tbe / 'op_tiling/liboptiling.so',
             tbe / 'kernel/config/ascend950/binary_info_config.json']
    for op in CAM_OPS:
        directory = tbe / 'kernel/ascend950' / op
        files.extend((directory / 'kernel.o', directory / 'kernel.json',
                      tbe / 'kernel/config/ascend950' / (op + '.json')))
    for path in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(path.name.encode())
    return root


def test_opp_fingerprint_detects_an_updated_or_missing_kernel(tmp_path):
    root = make_opp(tmp_path / 'CAM')
    second = make_opp(tmp_path / 'another-install')
    first = cam_opp_manifest(root)
    assert first['sha256'] == cam_opp_manifest(second)['sha256']
    kernel = root / 'op_impl/ai_core/tbe/kernel/ascend950/afd_async_combine_send/kernel.o'
    assert kernel.relative_to(root).as_posix() in first['files_sha256']
    kernel.write_bytes(b'new kernel')
    assert cam_opp_manifest(root)['sha256'] != first['sha256']
    kernel.unlink()
    with pytest.raises(ValueError, match='missing Ascend950 kernel'):
        cam_opp_manifest(root)


def test_device_rejects_an_unexpected_opp_before_measurement(monkeypatch):
    import afd_async_benchmark_runtime as runtime

    observed = 'a' * 64
    monkeypatch.setattr(runtime, 'loaded_cam_opp', lambda: {'status': 'observed', 'sha256': observed})

    def gather(target, value, group):
        target[:] = [value, value]

    backend = runtime.CamBackend.__new__(runtime.CamBackend)
    backend.args = SimpleNamespace(expected_cam_opp_sha256='b' * 64, num_processes=2, skip_perf_test=False)
    backend.rt = SimpleNamespace(phase=lambda *_args, **_kw: None, cpu_group=None,
                                 dist=SimpleNamespace(all_gather_object=gather))
    with pytest.raises(RuntimeError, match='differs from expected'):
        backend.record_loaded_opp()
    backend.args.expected_cam_opp_sha256 = observed
    backend.record_loaded_opp()
    assert backend.opp_identity['sha256'] == backend.opp_identity['expected_sha256']


@pytest.mark.skipif(sys.platform != 'linux', reason='uses Linux loaded-library mappings')
def test_opp_identity_uses_the_mapped_aclnn_library(tmp_path):
    cc = shutil.which('cc')
    if not cc:
        pytest.skip('host C compiler required')
    root = make_opp(tmp_path / 'loaded OPP')
    lib = root / 'op_api/lib/libcust_opapi.so'
    code = '\n'.join(f'void {name}{suffix}(void) {{}}' for name in CAM_OPS.values()
                     for suffix in ('', 'GetWorkspaceSize'))
    subprocess.run([cc, '-shared', '-fPIC', '-Wl,-soname,libcust_opapi.so', '-x', 'c', '-', '-o', str(lib)],
                   input=code, text=True, check=True)
    script = """import ctypes, json, sys
from afd_async_benchmark_diagnostics import loaded_cam_opp
lib = ctypes.CDLL(sys.argv[1])
print(json.dumps(loaded_cam_opp()))
"""
    env = dict(os.environ, PYTHONPATH=str(TEST_ROOT), ASCEND_CUSTOM_OPP_PATH=str(root))
    args = [sys.executable, '-c', script, str(lib)]
    observed = json.loads(subprocess.check_output(args, env=env, text=True))
    assert observed['mapped_op_api'] == str(lib)
    assert observed['sha256'] == cam_opp_manifest(root)['sha256']
    other = make_opp(tmp_path / 'stale')
    env['ASCEND_CUSTOM_OPP_PATH'] = os.pathsep.join((str(other), str(root)))
    run = subprocess.run(args, env=env, capture_output=True, text=True)
    assert run.returncode and 'another configured OPP' in run.stderr


def context_fixture(sources=2, peers=2, source=0):
    lanes_at = 256
    peers_at = lanes_at + sources * 32
    addresses_at = peers_at + peers * 32
    layers_at = addresses_at + sources * peers * 64
    directory_at = layers_at + 32
    return_lanes_at = directory_at + 32 + sources * 32
    size = return_lanes_at + sources * 32
    control_size = sources * (peers * 64 if source is not None else 128)
    raw = bytearray(size)
    integers = [2, peers, sources, sources, 8, 2, 14336, 0, 8, 4096, 4096, 128,
                1, 0xffffffff if source is None else source, 1, 0, 0 if peers == 1 else 8, 0]
    CONTEXT.pack_into(raw, 0, *integers, lanes_at, peers_at, addresses_at, layers_at,
                      size, 1 << 24, control_size, directory_at)
    struct.pack_into('<3Q2I', raw, directory_at, directory_at + 32, return_lanes_at, 14336, 1, 0)
    for lane in range(sources):
        struct.pack_into('<8I', raw, lanes_at + lane * 32, lane, 0, 0, lane, 0, 4096, 0, 0)
        struct.pack_into('<4Q', raw, return_lanes_at + lane * 32, 0, lane * peers * 64 + 32,
                         lane * 128 + 96, 0)
        for f in range(peers):
            struct.pack_into('<8Q', raw, addresses_at + (lane * peers + f) * 64,
                             0, 0, 0, 0, lane * 128, lane * 128 + 64, (lane * peers + f) * 64, 0)
    return raw, bytearray(control_size)


@pytest.mark.parametrize('peers', [1, 2, 4])
def test_control_decoder_follows_owner_offsets_and_preserves_non_bit_value(peers):
    raw, controls = context_fixture(sources=peers, peers=peers, source=0)
    layout = decode_context(raw)
    struct.pack_into('<I', controls, 32, 3)
    values = observe_controls(layout, controls, 0)
    assert len(values) == peers
    assert values[0]['done']['offset'] == 32
    assert values[0]['done']['value'] == 3  # Never turn 3 into a valid bit via &1.
    assert values[-1]['consumed']['offset'] == (peers - 1) * 64


def test_f_control_decoder_reads_credit_in_its_own_plane():
    raw, controls = context_fixture(sources=4, peers=4, source=None)
    struct.pack_into('<I', controls, 3 * 128 + 96, 1)
    values = observe_controls(decode_context(raw), controls)
    assert [v['credit']['offset'] for v in values] == [96, 224, 352, 480]
    assert values[3]['credit']['value'] == 1


def test_context_and_control_bounds_fail_before_access():
    raw, controls = context_fixture()
    with pytest.raises(ValueError, match='header'):
        decode_context(raw[:128])
    struct.pack_into('<Q', raw, 128, len(raw) + 32)
    with pytest.raises(ValueError, match='bounds'):
        decode_context(raw)
    raw, controls = context_fixture()
    layout = decode_context(raw)
    with pytest.raises(ValueError, match='control tensor'):
        observe_controls(layout, controls[:-1], 0)
    layout['returns'][0] = (0, len(controls), 96, 0)
    with pytest.raises(ValueError, match='outside tensor'):
        observe_controls(layout, controls, 0)


class TensorStub:
    shape = (32768, 7168)
    dtype = 'torch.bfloat16'
    device = 'npu:1'
    pointer = 4096

    def data_ptr(self):
        return self.pointer

    def storage_offset(self):
        return 0

    def stride(self):
        return (7168, 1)


def test_registered_source_guard_rejects_address_rebinding():
    tensor = TensorStub()
    before = tensor_storage(tensor)
    require_registered_storage(tensor, before, 'combine_x')
    tensor.pointer = 8192
    with pytest.raises(RuntimeError, match='changed after HcommMemReg'):
        require_registered_storage(tensor, before, 'combine_x')


def test_phase_trace_persists_first_failure_without_device_reads(tmp_path):
    trace = DiagnosticTrace(tmp_path, 1)
    trace.record('combine_send.wait', 0)
    trace.record('round.failed', 0, error_type='RuntimeError', error='507035')
    records = [json.loads(line) for line in trace.path.read_text(encoding='utf-8').splitlines()]
    assert records[-1]['previous_phase'] == 'combine_send.wait'
    assert records[-1]['iteration'] == 0


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def init_repository(path):
    path.mkdir(parents=True)
    git(path, 'init', '-q')
    (path / 'tracked.txt').write_text('baseline\n', encoding='utf-8')
    git(path, 'add', 'tracked.txt')
    git(path, '-c', 'user.name=Benchmark test', '-c', 'user.email=benchmark@example.invalid',
        'commit', '-qm', 'fixture')
    return git(path, 'rev-parse', 'HEAD')


def test_explicit_cam_root_and_reference_support_a_copied_driver(tmp_path, monkeypatch):
    owner, cam = tmp_path / 'owner', tmp_path / 'cam'
    owner_commit = init_repository(owner)
    cam_commit = init_repository(cam)
    jit_commit = init_repository(owner / 'third-party/deep_jit')
    monkeypatch.setattr(benchmark, 'OWNER_COMMIT', owner_commit)
    monkeypatch.setattr(benchmark, 'DEEPJIT_COMMIT', jit_commit)
    args = SimpleNamespace(deepep_root=owner, backend='cam', cam_root=cam, cam_reference=cam_commit,
                           allow_unverified_source=False)
    result = benchmark.verify_source(args)
    assert result['verified'] and result['cam_commit'] == cam_commit
    assert result['cam_production_tree_equivalent_to'] == cam_commit
    assert result['deepjit_commit'] == jit_commit
    production = cam / 'src/cam/kernel.cpp'
    production.parent.mkdir(parents=True)
    production.write_text('changed\n', encoding='utf-8')
    git(cam, 'add', 'src/cam/kernel.cpp')
    git(cam, '-c', 'user.name=Benchmark test', '-c', 'user.email=benchmark@example.invalid',
        'commit', '-qm', 'different implementation')
    with pytest.raises(RuntimeError, match='differs from declared reference'):
        benchmark.verify_source(args)
    args.cam_reference = git(cam, 'rev-parse', 'HEAD')
    assert benchmark.verify_source(args)['verified']
    args.cam_reference = 'HEAD'
    assert benchmark.verify_source(args)['cam_production_tree_equivalent_to'] == git(cam, 'rev-parse', 'HEAD')
    untracked = production.with_name('extra.h')
    untracked.write_text('// an untracked production include\n', encoding='utf-8')
    with pytest.raises(RuntimeError, match='uncommitted changes'):
        benchmark.verify_source(args)
    untracked.unlink()
    monkeypatch.setattr(benchmark, 'OWNER_COMMIT', '0' * 40)
    args.allow_unverified_source = True
    result = benchmark.verify_source(args)
    assert not result['verified'] and result['verification_problems']
    assert result['deepep_commit'] == owner_commit  # Keep actual identity, never claim the requested one.


@pytest.mark.parametrize('option', ['--allow-unverified-source', '--diagnostics-dir'])
def test_diagnostic_modes_cannot_silently_generate_performance_results(option):
    arguments = ['--dry-run', option]
    if option == '--diagnostics-dir':
        arguments.append('diagnostics')
    with pytest.raises(SystemExit):
        benchmark.parse_args(arguments)
    args = benchmark.parse_args(arguments + ['--skip-perf-test'])
    assert args.skip_perf_test


def test_correctness_rounds_default_covers_both_reuse_transitions():
    assert benchmark.parse_args(['--dry-run']).correctness_rounds == 4
    with pytest.raises(SystemExit):
        benchmark.parse_args(['--dry-run', '--correctness-rounds', '1'])
