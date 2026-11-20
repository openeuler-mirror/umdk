# SPDX-License-Identifier: MIT
"""Compare official DeepEP-Ascend EP and current CAM AFD with matched A/F work.

Requested cases (run each backend in its own correctly built environment):
  python3 test/cam/benchmark_afd_async.py --backend official \
    --deepep-root /work/DeepEP-official --num-processes 4 --num-ai-cores 32 \
    --num-tokens 4096 --hidden 7168 --num-topk 6 --num-experts 256 \
    --dispatch-dtype bf16 --test-first-only --output results/ep-2a2f.json
  python3 test/cam/benchmark_afd_async.py --backend cam \
    --deepep-root /work/DeepEP-afd-owner --num-processes 4 --num-ai-cores 32 \
    --num-tokens 4096 --hidden 7168 --num-topk 6 --num-experts 256 \
    --dispatch-dtype bf16 --test-first-only --output results/cam-2a2f.json
Change --num-processes to 8 for 4A4F; every A still has exactly 4096 tokens.
Start CAM correctness on Ascend950 with --num-ai-cores 1 --num-tokens 64
--num-topk 2 --num-experts 8 --cache-mode warm --skip-perf-test.
Issue #6 reports CAM combine_send error 507035 for K=6/E=256. The target
commands above describe the workload; CAM performance requires a passing
correctness run for the actual loaded OPP and shape.
  python3 test/cam/benchmark_afd_async.py --compare results/ep-2a2f.json results/cam-2a2f.json
  python3 test/cam/benchmark_afd_async.py --dry-run --num-processes 8

Reference: deepseek-ai/DeepEP-Ascend@4dfccac4, tests/ep/test_ep.py,
deep_ep/utils/{refs,testing}.py. That script uses T-rank tokens and measures
profiled communication/epilogue kernels with relocated barriers. This script
uses exactly T tokens per A and complete NPU-event intervals. Its GB/s must
not be compared directly with the original script's isolated URMA GB/s.

Matched topology: ranks [0,A) own input; ranks [A,A+F) own E active experts.
Official EP stays unmodified. Its rank-partitioned expert space contains
E*(A+F)/F slots (512 for E=256 and A=F); the A half is unused, and each logical
expert ID is shifted by A*(E/F). F participants have one fully masked dummy
token. The logical workload remains A*T input tokens and E active experts.
BF16 / alignment=128 / no bias matches the first BF16 official test case.
Weights are one because EP returns weights separately while AFD multiplies
payloads by them. The official sin-based per-route fixture is rounded to
bounded integers, so both reduction orders have the same exact BF16 golden.
Input and expert-output signs alternate every round to expose stale payloads.

BANDWIDTH CONTRACT (decimal GB/s, BF16):
  P = 2*H; U[a,f] = number of tokens with any valid route to f;
  R[a,f] = number of valid expert routes to f (padding/masked routes excluded).
  M = align32(align32(8*K) + 4*K + 8).
  EP original logical dispatch numerator at F: sum_a U[a,f]*(P+12*K).
  EP combine numerator at F: sum_a U[a,f]*P (local reduction before sending).
  The EP combine numerator preserves the official payload-only formula; any
  returned routing weights are not part of that numerator.
  AFD DS record bytes at A: sum_f U[a,f]*(P+M).
  AFD DS auxiliary bytes at A: 4*sum_f R[a,f] + 8*E (refs/counts/prefixes).
  AFD CS payload bytes at F: sum_a R[a,f]*P (one return per expert route).
  GB/s = bytes / (event_ms*1e6), with no factor of two.
For H=7168,K=6, P=14336 and M=96: a DS record transfers 14432 bytes,
although its storage stride is 14848 bytes. Neither stride, Q, Q_alloc nor
padded expert rows is a payload numerator. Headers, CQEs and control traffic
are excluded; this is accounted data throughput, not physical link capacity.
DR and CR move/reduce data already in local GM: no URMA GB/s is assigned to them.

MEASUREMENT CONTRACT:
  Dispatch: A DS completes, then F scheduler/DR. Device envelope=max_A DS +
  max_F DR; host phase includes control/barriers. This is a staged comparison.
  Combine: F CS and A CR run concurrently. Device envelope=max(CS,CR), which
  includes receiver waits. FFN fixture and ComputeReady are outside timing.
  CAM aggregate data GB/s uses sum of sender bytes / max sender event duration.
  EP aggregate accounting uses sum of logical bytes / max complete-op duration.
  These numerators/boundaries differ; GB/s ratios are deliberately not speedups.
  Route checks precede warmup; unprofiled repeated rounds precede measurement.
  Optional profiling is a separate pass after those checks, excluded from stats.

Prerequisites: build/install all four CAM ops from the printed UMDK revision;
CAM additionally needs companion AFDBuffer owner@25b5153e (control plane only).
--deepep-root must be the matching clean, built source tree, with deep_ep._C
available there. Use --fingerprint-cam-opp on the packaged vendor directory and
--expected-cam-opp-sha256 on the device to check the installed CAM binary set.
No NPU result is implied by --dry-run or the CPU accounting unit tests.

Failure diagnosis (no profiler/performance sampling):
  --skip-perf-test --diagnostics-dir output/issue6
CAM defaults to the clean implementation at HEAD. For an A/B with the same
driver, set --cam-root /work/umdk/base and --cam-reference <full-commit>
for each installed build. A copied driver need not live inside that tree.
Tarball imports without verifiable Git identity may use --allow-unverified-source
ONLY together with --skip-perf-test; reports remain verified=false. The pinned
official and owner trees both require DeepJIT@65f513952b8771408a19202f65e36398522db6db.
"""

import argparse
from datetime import timedelta
import importlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading

from afd_async_benchmark_diagnostics import cam_opp_manifest, file_hash
from afd_async_benchmark_metrics import (
    DEEPJIT_COMMIT, METRIC_VERSION, OFFICIAL_COMMIT, OWNER_COMMIT,
    aggregate_report, compare_reports, traffic_plan,
)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--backend', choices=('official', 'cam'), default='cam')
    parser.add_argument('--deepep-root', type=Path)
    parser.add_argument('--cam-root', type=Path, help='CAM source checkout, independent of this script location')
    parser.add_argument('--cam-reference', default='HEAD', help='Expected CAM source revision under test')
    parser.add_argument('--fingerprint-cam-opp', type=Path, metavar='VENDOR_DIR',
                        help='Print the offline fingerprint of a built CAM OPP vendor directory')
    parser.add_argument('--expected-cam-opp-sha256', help='Require this independently recorded CAM OPP fingerprint')
    parser.add_argument('--allow-unverified-source', action='store_true', help='Diagnostic-only archive/import fallback; never marks provenance verified')
    parser.add_argument('--diagnostics-dir', type=Path, help='Per-rank phase/ABI evidence for correctness-only diagnosis')
    parser.add_argument('--num-processes', type=int, default=4)
    parser.add_argument('--num-ai-cores', type=int, default=32)
    parser.add_argument('--num-tokens', type=int, default=4096, help='Exact tokens on each Attention rank')
    parser.add_argument('--hidden', type=int, default=7168)
    parser.add_argument('--num-topk', type=int, default=6)
    parser.add_argument('--num-experts', type=int, default=256, help='Active experts on the FFN ranks')
    parser.add_argument('--dispatch-dtype', choices=('bf16',), default='bf16')
    parser.add_argument('--test-first-only', action='store_true', help='Compatibility flag: this test implements the first BF16/no-bias case')
    parser.add_argument('--expert-alignment', type=int, default=128)
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--warmup', type=int, default=10)
    parser.add_argument('--iterations', type=int, default=50)
    parser.add_argument('--stability-iterations', type=int, default=100)
    parser.add_argument('--correctness-rounds', type=int, default=4, help='Checked transactions before warmup')
    parser.add_argument('--skip-perf-test', action='store_true', help='Run checked transactions only')
    parser.add_argument('--profile-dir', type=Path, help='Optional separate post-validation profiler pass')
    parser.add_argument('--profile-iterations', type=int, default=3)
    parser.add_argument('--cache-mode', choices=('cold', 'warm'), default='cold')
    parser.add_argument('--timeout-seconds', type=int, default=300)
    parser.add_argument('--memory-budget-gib', type=int, default=8)
    parser.add_argument('--transport-reserve-mib', type=int, default=512)
    parser.add_argument('--max-padded-rows', type=int, default=65536)
    parser.add_argument('--master-port', type=int, default=0)
    parser.add_argument('--output', type=Path, default=Path('output/afd_async_benchmark.json'))
    parser.add_argument('--dry-run', action='store_true', help='Print formulas, topology and references without importing torch')
    parser.add_argument('--compare', nargs=2, type=Path, metavar=('OFFICIAL_JSON', 'CAM_JSON'))
    args = parser.parse_args(argv)
    if args.fingerprint_cam_opp and (args.compare or args.dry_run or args.expected_cam_opp_sha256):
        parser.error('--fingerprint-cam-opp takes one packaged vendor directory as a standalone operation')
    if args.fingerprint_cam_opp or args.compare:
        return args
    if args.expected_cam_opp_sha256:
        if args.backend != 'cam' or not re.fullmatch('[0-9a-fA-F]{64}', args.expected_cam_opp_sha256):
            parser.error('--expected-cam-opp-sha256 requires the CAM backend and a 64-digit hexadecimal digest')
        args.expected_cam_opp_sha256 = args.expected_cam_opp_sha256.lower()
    if args.num_processes not in (2, 4, 8):
        parser.error('--num-processes must be 2 (smoke), 4 (2A2F), or 8 (4A4F)')
    if not 1 <= args.num_tokens <= 32768 or not 1 <= args.num_ai_cores <= 64:
        parser.error('tokens must be 1..32768 and AI cores 1..64')
    if not 128 <= args.hidden <= 8192 or args.hidden % 128:
        parser.error('BF16 hidden must be a multiple of 128 in [128,8192]')
    if not 1 <= args.num_topk <= min(args.num_experts, 32):
        parser.error('top-k must be 1..min(experts,32)')
    if not 1 <= args.num_experts <= 512 or args.num_experts % (args.num_processes // 2):
        parser.error('active experts must be <=512 and divisible by F rank count')
    if args.expert_alignment <= 0 or args.expert_alignment & (args.expert_alignment - 1):
        parser.error('expert alignment must be a power of two')
    if args.correctness_rounds < 2:
        parser.error('at least two correctness rounds are required to check slot reuse')
    if min(args.iterations, args.profile_iterations, args.timeout_seconds, args.memory_budget_gib,
           args.transport_reserve_mib, args.max_padded_rows) <= 0 or min(args.warmup, args.stability_iterations) < 0:
        parser.error('invalid iteration, timeout or resource budget')
    if args.profile_dir and args.stability_iterations < 100:
        parser.error('profiling requires at least 100 unprofiled stability iterations')
    if (args.allow_unverified_source or args.diagnostics_dir) and (not args.skip_perf_test or args.profile_dir):
        parser.error('unverified-source and diagnostic runs require --skip-perf-test and no profiler')
    if not 0 <= args.master_port <= 65535:
        parser.error('master port must be 0..65535')
    if not args.dry_run and not args.deepep_root:
        parser.error('--deepep-root is required for an attributable baseline/owner build')
    return args


def git_output(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f'cannot establish Git identity for {root}: {result.stderr.strip()}')
    return result.stdout.strip()


def verify_source(args):
    args.deepep_root = args.deepep_root.resolve()
    expected = OFFICIAL_COMMIT if args.backend == 'official' else OWNER_COMMIT
    problems = []
    actual, cam, reference, deepjit = None, None, None, None
    try:
        actual = git_output(args.deepep_root, 'rev-parse', 'HEAD')
        if actual != expected:
            problems.append(f'DeepEP expected {expected}, found {actual}')
        if git_output(args.deepep_root, 'status', '--porcelain', '--untracked-files=no', '--', 'deep_ep', 'csrc'):
            problems.append('DeepEP implementation has tracked local changes')
    except RuntimeError as exc:
        problems.append(str(exc))
    jit_root = args.deepep_root / 'third-party/deep_jit'
    try:
        if Path(git_output(jit_root, 'rev-parse', '--show-toplevel')).resolve() != jit_root.resolve():
            raise RuntimeError('DeepJIT submodule is not an initialized repository')
        deepjit = git_output(jit_root, 'rev-parse', 'HEAD')
        if deepjit != DEEPJIT_COMMIT:
            problems.append(f'DeepJIT expected {DEEPJIT_COMMIT}, found {deepjit}')
        if git_output(jit_root, 'status', '--porcelain', '--untracked-files=no'):
            problems.append('DeepJIT has tracked local changes')
    except RuntimeError as exc:
        problems.append(str(exc))
    repo = (args.cam_root or Path(__file__).resolve().parents[2]).resolve()
    if args.backend == 'cam':
        try:
            if Path(git_output(repo, 'rev-parse', '--show-toplevel')).resolve() != repo:
                raise RuntimeError('--cam-root must be the UMDK Git checkout root')
            cam = git_output(repo, 'rev-parse', 'HEAD')
            reference = git_output(repo, 'rev-parse', '--verify', f'{args.cam_reference}^{{commit}}')
            if git_output(repo, 'diff', '--name-only', reference, cam, '--', 'src/cam', 'build/cam'):
                problems.append(f'CAM implementation differs from declared reference {reference}')
            if git_output(repo, 'status', '--porcelain', '--untracked-files=normal', '--', 'src/cam', 'build/cam'):
                problems.append('CAM production source/build files have uncommitted changes')
        except RuntimeError as exc:
            problems.append(str(exc))
    if problems and not args.allow_unverified_source:
        raise RuntimeError('Source verification failed:\n' + '\n'.join(problems))
    return {'verified': not problems, 'verification_problems': problems,
            'deepep_commit': actual, 'deepep_expected_commit': expected,
            'deepjit_commit': deepjit, 'deepjit_expected_commit': DEEPJIT_COMMIT,
            'cam_commit': cam, 'cam_root': str(repo) if args.backend == 'cam' else None,
            'cam_requested_reference': args.cam_reference if args.backend == 'cam' else None,
            'cam_production_tree_equivalent_to': reference if not problems and args.backend == 'cam' else None,
            'test_sha256': file_hash(__file__),
            'test_modules_sha256': {name: file_hash(Path(__file__).with_name(name)) for name in
                                   ('afd_async_benchmark_metrics.py', 'afd_async_benchmark_runtime.py',
                                    'afd_async_benchmark_diagnostics.py')}}


def make_routes(torch, args):
    # Same random-score/top-k construction as the official test's balanced case,
    # on CPU with an explicit per-source seed so separate backend runs agree.
    routes = []
    for source in range(args.num_processes // 2):
        generator = torch.Generator(device='cpu').manual_seed(args.seed + source)
        scores = torch.rand((args.num_tokens, args.num_experts), generator=generator,
                            dtype=torch.float32, device='cpu')
        routes.append(torch.topk(scores, args.num_topk, dim=-1, sorted=False).indices.tolist())
    return routes


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    temporary.replace(path)


def cann_identity():
    try:
        from torch_npu.npu.utils import get_cann_version
        version = get_cann_version()
        if version:
            return {'source': 'torch_npu.npu.utils.get_cann_version', 'content': str(version)}
    except (ImportError, AttributeError, RuntimeError):
        pass
    candidates = []
    for variable in ('ASCEND_HOME_PATH', 'ASCEND_TOOLKIT_HOME', 'ASCEND_CANN_PACKAGE_PATH'):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]))
    candidates.append(Path('/usr/local/Ascend/ascend-toolkit/latest'))
    for root in candidates:
        for relative in ('version.cfg', 'version.info', 'aarch64-linux/ascend_toolkit_install.info'):
            path = root / relative
            if path.is_file():
                content = path.read_text(encoding='utf-8')
                version = re.search(r'(?im)^\s*(?:cann_)?version\s*[:=]\s*(.+?)\s*$', content)
                if version:
                    return {'source': str(path.resolve()), 'content': version.group(1)}
    return {'source': None, 'content': None}


def worker(rank, args, provenance):
    sys.path.insert(0, str(args.deepep_root))
    import torch
    import torch_npu
    import torch.distributed as dist
    import deep_ep
    from deep_ep.utils.envs import init_seed
    from afd_async_benchmark_runtime import Runtime, OfficialBackend, CamBackend

    if not Path(deep_ep.__file__).resolve().is_relative_to(args.deepep_root):
        raise RuntimeError('imported DeepEP package is outside the declared source tree')
    torch.npu.set_device(rank)
    dist.init_process_group('hccl', init_method='env://', rank=rank, world_size=args.num_processes,
                            timeout=timedelta(seconds=args.timeout_seconds))
    cpu_group = dist.new_group(backend='gloo', timeout=timedelta(seconds=args.timeout_seconds))
    init_seed(args.seed)
    routes = make_routes(torch, args)
    plan = traffic_plan(routes, args.num_processes // 2, args.num_experts, args.hidden,
                        args.num_topk, args.expert_alignment)
    if plan['q_alloc'] > args.max_padded_rows:
        raise RuntimeError(f"one-slice Q_alloc={plan['q_alloc']} exceeds --max-padded-rows; increase the declared limit")
    rt = Runtime(torch, dist, deep_ep, cpu_group, rank, args, routes, plan)
    rt.phase('libraries.loaded', provenance=provenance, deepep_extension=str(deep_ep._C.__file__),
             deepep_extension_sha256=file_hash(deep_ep._C.__file__))
    hashes = [None] * args.num_processes
    dist.all_gather_object(hashes, plan['route_sha256'], group=cpu_group)
    if len(set(hashes)) != 1:
        raise RuntimeError('ranks did not construct identical routing inputs')
    if rank == 0:
        print('BENCH_CONTRACT ' + json.dumps({'backend': args.backend, 'source': provenance,
              'shape': [args.num_tokens, args.hidden, args.num_topk, args.num_experts],
              'roles': [plan['num_sources'], plan['num_ffn_ranks']], 'q': plan['q'],
              'q_alloc': plan['q_alloc'], 'routes_per_f': plan['routes_per_f'],
              'unique_tokens_per_f': plan['unique_tokens_per_f']}), flush=True)
    try:
        backend = OfficialBackend(rt) if args.backend == 'official' else CamBackend(rt)
    except BaseException as exc:
        rt.phase('initialization.failed', error_type=type(exc).__name__, error=str(exc))
        raise
    samples = []
    next_iteration = 0

    def run_once(check=False):
        nonlocal next_iteration
        iteration = next_iteration
        def timed_out():
            phase = rt.trace.last_phase
            rt.phase('watchdog.timeout', last_observed_phase=phase)
            print(f'BENCH_TIMEOUT rank={rank} iteration={iteration} phase={phase}', file=sys.stderr, flush=True)
            os._exit(124)
        watchdog = threading.Timer(args.timeout_seconds, timed_out)
        watchdog.daemon = True
        watchdog.start()
        try:
            result = backend.round(iteration, check)
            next_iteration += 1
            return result
        except BaseException as exc:
            # Do not query device tensors after a device fault; preserve the
            # last host checkpoint before destructors or peer failures obscure it.
            rt.phase('round.failed', error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            watchdog.cancel()

    # Repeated checked transactions exercise both values of the reuse bits.
    for _ in range(args.correctness_rounds):
        run_once(check=True)
    if rank == 0:
        print(f'CORRECTNESS_PASS rounds={args.correctness_rounds}', flush=True)
    if not args.skip_perf_test:
        for _ in range(args.warmup):
            run_once()
        for _ in range(args.stability_iterations):
            run_once(check=True)
        if rank == 0:
            label = 'STABILITY_PASS' if args.stability_iterations else 'STABILITY_NOT_RUN'
            print(f'{label} rounds={args.stability_iterations} profiler=OFF', flush=True)
        for _ in range(args.iterations):
            samples.append(run_once())
    if args.profile_dir and not args.skip_perf_test:
        directory = args.profile_dir.resolve() / f'rank{rank}'
        directory.mkdir(parents=True, exist_ok=False)
        with torch_npu.profiler.profile(
            activities=[torch_npu.profiler.ProfilerActivity.CPU, torch_npu.profiler.ProfilerActivity.NPU],
            record_shapes=False, profile_memory=False, with_stack=False,
            on_trace_ready=torch_npu.profiler.tensorboard_trace_handler(str(directory))) as profiler:
            for _ in range(args.profile_iterations):
                run_once()
                profiler.step()
    rt.sync()
    rank_result = {'rank': rank, 'samples': samples, 'device_name': torch.npu.get_device_name(rank),
                   'deepep_extension': str(deep_ep._C.__file__),
                   'deepep_extension_sha256': file_hash(deep_ep._C.__file__),
                   'backend_identity': backend.identity(), 'cam_config': getattr(backend, 'cfg', None)}
    gathered = [None] * args.num_processes
    dist.all_gather_object(gathered, rank_result, group=cpu_group)
    backend.close()
    rt.sync()
    dist.destroy_process_group(cpu_group)
    dist.destroy_process_group()
    if rank == 0:
        workload = {k: plan[k] for k in ('num_sources', 'num_ffn_ranks', 'tokens_per_source', 'num_experts',
                    'hidden', 'topk', 'expert_alignment', 'route_sha256')}
        workload.update(fixture='official-sine-rounded-integer-v1', seed=args.seed, weights='unit', bias=None,
                        iteration_sign_flip=True)
        protocol = {'num_ai_cores': args.num_ai_cores, 'warmup': args.warmup, 'iterations': args.iterations,
                    'stability_iterations': args.stability_iterations, 'cache_mode': args.cache_mode,
                    'correctness_rounds': args.correctness_rounds,
                    'timing': 'NPU event/current stream/complete operation', 'schedule': 'single-slice-staged-dispatch'}
        report = {'status': 'PASS', 'backend': args.backend, 'metric_version': METRIC_VERSION,
                  'provenance': provenance, 'workload': workload, 'protocol': protocol, 'traffic': plan,
                  'environment': {'torch': torch.__version__, 'torch_npu': torch_npu.__version__,
                    'device_names': [r['device_name'] for r in gathered],
                    'hostname': socket.gethostname(), 'CANN': cann_identity(),
                    'ASCEND_RT_VISIBLE_DEVICES': os.environ.get('ASCEND_RT_VISIBLE_DEVICES'),
                    'ASCEND_HOME_PATH': os.environ.get('ASCEND_HOME_PATH'),
                    'ASCEND_CUSTOM_OPP_PATH': os.environ.get('ASCEND_CUSTOM_OPP_PATH')},
                  'rank_results': gathered, 'correctness_rounds': args.correctness_rounds,
                  'summary': aggregate_report(args.backend, plan, [r['samples'] for r in gathered]) if samples else None,
                  'limit': 'No production E2E, maximum-overlap, or physical-link-bandwidth claim.'}
        write_report(args.output, report)
        print('RUN_PASS ' + str(args.output), flush=True)
        if report['summary']:
            print(json.dumps(report['summary']['statistics'], indent=2), flush=True)


def main(argv=None):
    args = parse_args(argv)
    if args.fingerprint_cam_opp:
        print(json.dumps(cam_opp_manifest(args.fingerprint_cam_opp), indent=2))
        return
    if args.compare:
        reports = [json.loads(p.read_text(encoding='utf-8')) for p in args.compare]
        result = compare_reports(*reports)
        print(json.dumps(result, indent=2))
        return
    if args.dry_run:
        a = args.num_processes // 2
        print(json.dumps({'official_commit': OFFICIAL_COMMIT, 'owner_commit': OWNER_COMMIT,
              'cam_reference': args.cam_reference, 'roles': f'{a}A{a}F', 'tokens_per_A': args.num_tokens,
              'active_experts': args.num_experts, 'official_physical_expert_slots': 2 * args.num_experts,
              'hidden': args.hidden, 'topk': args.num_topk, 'aiv_count': args.num_ai_cores,
              'timing': 'events including waits; separate optional profiler pass',
              'bandwidth_formula': 'DS: U*(2H+align32(align32(8K)+4K+8))+4R+8E per A; CS: R*2H per F',
              'bandwidth_units': 'bytes/(event_ms*1e6) decimal GB/s', 'runtime': 'NOT TESTED'}, indent=2))
        return
    if args.output.exists():
        raise FileExistsError(f'use a new output path: {args.output}')
    if 'RANK' in os.environ or 'WORLD_SIZE' in os.environ:
        raise RuntimeError('launch with python3, not torchrun; --num-processes spawns the workers')
    provenance = verify_source(args)
    os.environ.setdefault('MASTER_ADDR', '127.0.0.1')
    if args.master_port:
        os.environ['MASTER_PORT'] = str(args.master_port)
    elif 'MASTER_PORT' not in os.environ:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            os.environ['MASTER_PORT'] = str(listener.getsockname()[1])
    torch = importlib.import_module('torch')
    torch.multiprocessing.spawn(worker, args=(args, provenance), nprocs=args.num_processes, join=True)


if __name__ == '__main__':
    main()
