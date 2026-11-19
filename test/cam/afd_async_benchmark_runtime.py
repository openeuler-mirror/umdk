# SPDX-License-Identifier: MIT
"""Device adapters for benchmark_afd_async.py; no production kernel changes.

EP call shapes follow official test_ep.py@4dfccac4. AFDBuffer construction and
CAM argument order follow companion run_pipeline_cam.py@25b5153e. Source and
binary identities are recorded by the launcher, rather than inferred from names.
"""

import math
from pathlib import Path
import struct
import time

from afd_async_benchmark_metrics import align_up, gbps
from afd_async_benchmark_diagnostics import (
    DiagnosticTrace, decode_context, file_hash, loaded_cam_opp, observe_controls,
    require_registered_storage, tensor_storage,
)


ACTIVE = struct.Struct('<10I3Q')
WORDS = struct.Struct('<8I')
TX_MAGIC = 0x41465431
TX_IDLE, TX_SELECTED, TX_SLICE, TX_COMPLETE = 0, 1, 2, 3


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def snapshot(tensor):
    return bytes(tensor.detach().cpu().tolist())


def route_fixture(torch, global_token, topk_slot, hidden, topk, max_tokens, world, seed):
    """Official generate_pre_combine_data formula, evaluated only at needed slots.

    Round the official BF16 sine values to integers in [-8,8]. For K<=32 all
    partial/final integer sums are exactly representable in BF16, removing the
    native EP local-reduction vs AFD final-reduction rounding difference.
    """
    token_seed = global_token * topk + topk_slot
    max_seed = world * max_tokens * topk
    phase = ((token_seed * 131071 % max_seed).float() + 1) / max_seed
    columns = torch.arange(1, hidden + 1, dtype=torch.float32, device=global_token.device)
    raw = torch.sin(phase[:, None] * columns[None, :] + math.sin(float(seed))).to(torch.bfloat16)
    return torch.round(raw.float() * 8).to(torch.bfloat16)


class Runtime:
    def __init__(self, torch, dist, deep_ep, cpu_group, rank, args, routes, plan):
        self.torch, self.dist, self.deep_ep = torch, dist, deep_ep
        self.cpu_group, self.rank, self.args = cpu_group, rank, args
        self.routes, self.plan = routes, plan
        self.sources = plan['num_sources']
        self.is_source = rank < self.sources
        self.device = torch.device(f'npu:{rank}')
        self.x_cache = {}
        self.iteration = 0
        self.trace = DiagnosticTrace(getattr(args, 'diagnostics_dir', None), rank)
        self.expected_outputs = {}
        self.scrub = (torch.empty(1 << 26, dtype=torch.int32, device=self.device)
                      if args.cache_mode == 'cold' else None)
        # Build the independent expected route roster before any device output.
        self.expected = {}
        if not self.is_source:
            f = rank - self.sources
            for a, tokens in enumerate(routes):
                for t, selected in enumerate(tokens):
                    for k, expert in enumerate(selected):
                        if expert >= 0 and expert // plan['local_experts'] == f:
                            self.expected[(a, t, k)] = expert % plan['local_experts']

    def phase(self, name, **details):
        self.trace.record(name, self.iteration, **details)

    def sync(self, name='barrier'):
        self.phase(name + '.device_sync')
        self.torch.npu.synchronize()
        self.phase(name + '.gloo_wait')
        self.dist.barrier(group=self.cpu_group)
        self.phase(name + '.complete')

    def timed(self, fn):
        name = fn.__name__
        if self.scrub is not None:
            self.phase(name + '.cache_flush')
            self.scrub.zero_()
            self.torch.npu.synchronize()
        start = self.torch.npu.Event(enable_timing=True)
        end = self.torch.npu.Event(enable_timing=True)
        self.phase(name + '.launch')
        start.record()
        result = fn()
        end.record()
        self.phase(name + '.wait')
        end.synchronize()
        milliseconds = float(start.elapsed_time(end))
        require(math.isfinite(milliseconds) and milliseconds > 0, 'invalid NPU event duration')
        self.phase(name + '.complete', event_ms=milliseconds)
        return milliseconds, result

    def source_x(self, source):
        key = (source, self.iteration & 1)
        if (source, 0) not in self.x_cache:
            generator = self.torch.Generator(device='cpu').manual_seed(self.args.seed + 10000 + source)
            self.x_cache[(source, 0)] = self.torch.randn(
                (self.args.num_tokens, self.args.hidden), dtype=self.torch.bfloat16,
                generator=generator, device='cpu')
        if key not in self.x_cache:
            self.x_cache[key] = -self.x_cache[(source, 0)]
        return self.x_cache[key]

    def fixture(self, token_ids, slots):
        a = self.args
        value = route_fixture(self.torch, token_ids, slots, a.hidden, a.num_topk,
                              a.num_tokens, a.num_processes, a.seed)
        return -value if self.iteration & 1 else value

    def fill_combine(self, output, dst_rows, token_ids, slots):
        output.zero_()
        for begin in range(0, dst_rows.numel(), 256):
            end = begin + 256
            output.index_copy_(0, dst_rows[begin:end].long(), self.fixture(token_ids[begin:end], slots[begin:end]))

    def validate_dispatch(self, output, weights, entries, padded_rows):
        """Check route identity/coverage, expert contiguity, payload and padding."""
        actual = {}
        for row, source, token, slot in entries:
            key = (source, token, slot)
            require(key in self.expected, f'unexpected received route {key}')
            require(key not in actual, f'duplicate received route {key}')
            require(0 <= row < padded_rows, f'receive row outside active output: {row}')
            actual[key] = row
        require(set(actual) == set(self.expected), 'missing or extra dispatch routes')
        require(len(set(actual.values())) == len(actual), 'two routes alias an expanded row')
        if self.is_source:
            require(not entries and padded_rows == 0, 'Attention rank received an expert payload')
            return
        f = self.rank - self.sources
        require(len(entries) == self.plan['routes_per_f'][f], 'effective route count mismatch')
        cursor = 0
        for expert, count in enumerate(self.plan['expert_counts'][f]):
            rows = sorted(actual[key] for key, value in self.expected.items() if value == expert)
            require(rows == list(range(cursor, cursor + count)), f'expert {expert} rows are not contiguous')
            padded_end = cursor + align_up(count, self.args.expert_alignment)
            if padded_end > cursor + count:
                bits = output[cursor + count:padded_end].view(self.torch.uint8)
                require(int(self.torch.count_nonzero(bits).item()) == 0, 'nonzero dispatch padding')
            cursor = padded_end
        require(cursor == padded_rows, 'padded row total mismatch')
        # Compare to original CPU inputs, never to reconstructed data returned by DR.
        entries = sorted(entries)
        for begin in range(0, len(entries), 128):
            chunk = entries[begin:begin + 128]
            rows = self.torch.tensor([x[0] for x in chunk], dtype=self.torch.int64, device=self.device)
            expected = self.torch.stack([self.source_x(a)[t] for _, a, t, _ in chunk])
            received = output.index_select(0, rows).cpu()
            require(self.torch.equal(received.view(self.torch.uint8), expected.view(self.torch.uint8)),
                    'dispatch payload differs from original input')
            if weights is not None:
                require(bool(self.torch.all(weights.index_select(0, rows) == 1).item()), 'dispatch weights changed')

    def validate_combine(self, output):
        if not self.is_source:
            require(int(self.torch.count_nonzero(output).item()) == 0, 'dummy F input returned nonzero output')
            return
        parity = self.iteration & 1
        if parity not in self.expected_outputs:
            expected = self.torch.empty_like(output)
            routes = self.torch.tensor(self.routes[self.rank], dtype=self.torch.int64, device=self.device)
            for begin in range(0, self.args.num_tokens, 256):
                end = min(begin + 256, self.args.num_tokens)
                token_ids = self.rank * self.args.num_tokens + self.torch.arange(begin, end, device=self.device)
                acc = self.torch.zeros((end - begin, self.args.hidden), dtype=self.torch.float32, device=self.device)
                for k in range(self.args.num_topk):
                    values = self.fixture(token_ids, self.torch.full_like(token_ids, k)).float()
                    acc.add_(values.masked_fill(routes[begin:end, k, None] < 0, 0))
                expected[begin:end] = acc.to(self.torch.bfloat16)
            self.expected_outputs[parity] = expected
        require(self.torch.equal(output, self.expected_outputs[parity]),
                'combined result differs from independent exact golden')


class OfficialBackend:
    def __init__(self, rt):
        self.rt, self.torch, self.args = rt, rt.torch, rt.args
        a, t = self.args, self.torch
        self.buffer = rt.deep_ep.EPBuffer(
            rt.dist.distributed_c10d._get_default_group(), num_max_tokens_per_rank=a.num_tokens,
            hidden=a.hidden, num_topk=a.num_topk, allow_hybrid_mode=False,
            allow_multiple_reduction=True, num_cpu_timeout_secs=a.timeout_seconds,
            num_gpu_timeout_secs=a.timeout_seconds, explicitly_destroy=True)
        if rt.is_source:
            self.x = rt.source_x(rt.rank).to(rt.device)
            raw_idx = t.tensor(rt.routes[rt.rank], dtype=t.int64, device=rt.device)
            valid = raw_idx >= 0
            self.idx = t.where(valid, raw_idx + rt.plan['ep_expert_id_offset'], raw_idx)
            self.weights = valid.to(t.float32)
        else:
            self.x = t.zeros((1, a.hidden), dtype=t.bfloat16, device=rt.device)
            self.idx = t.full((1, a.num_topk), -1, dtype=t.int64, device=rt.device)
            self.weights = t.zeros((1, a.num_topk), dtype=t.float32, device=rt.device)

    def dispatch(self):
        x, indices, weights, handle, event = self.buffer.dispatch(
            x=self.x, topk_idx=self.idx, topk_weights=self.weights,
            num_sms=self.args.num_ai_cores, num_max_tokens_per_rank=self.args.num_tokens,
            num_experts=self.rt.plan['ep_physical_expert_slots'], expert_alignment=self.args.expert_alignment,
            async_with_compute_stream=True, do_handle_copy=False, do_cpu_sync=True,
            do_expand=True, do_zero_padding=True, defer_epilogue=False)
        event.current_stream_wait(release_handle=True)
        return x, indices, weights, handle

    def round(self, iteration, check):
        rt, t = self.rt, self.torch
        rt.iteration = iteration
        if rt.is_source:
            self.x.copy_(rt.source_x(rt.rank).to(rt.device))
        rt.sync()
        begin = time.perf_counter()
        dispatch_ms, (recv_x, _, recv_weights, handle) = rt.timed(self.dispatch)
        rt.sync()
        dispatch_host = (time.perf_counter() - begin) * 1000
        count = int(handle.psum_num_recv_tokens_per_rank[-1].item())
        expected_unique = 0 if rt.is_source else rt.plan['unique_tokens_per_f'][rt.rank - rt.sources]
        require(count == expected_unique, 'official unique-token count differs from input routes')
        metadata = handle.recv_src_metadata[:count]
        dst, token_ids, slots = [], [], []
        for k in range(self.args.num_topk):
            valid = metadata[:, k] >= 0
            dst.append(metadata[valid, k].long())
            token_ids.append(metadata[valid, -2].long())
            slots.append(t.full_like(token_ids[-1], k))
        dst, token_ids, slots = t.cat(dst), t.cat(token_ids), t.cat(slots)
        padded = 0 if rt.is_source else rt.plan['padded_rows_per_f'][rt.rank - rt.sources]
        require(recv_x.size(0) == padded, 'official expanded capacity differs from expected aligned rows')
        if check:
            entries = [(row, source_token // self.args.num_tokens, source_token % self.args.num_tokens, slot)
                       for row, source_token, slot in zip(dst.cpu().tolist(), token_ids.cpu().tolist(), slots.cpu().tolist())]
            rt.validate_dispatch(recv_x, recv_weights, entries, padded)
        combine_x = t.empty_like(recv_x)
        rt.fill_combine(combine_x, dst, token_ids, slots)
        rt.sync()
        begin = time.perf_counter()

        def combine():
            output, weights, event = self.buffer.combine(
                x=combine_x, handle=handle, topk_weights=recv_weights, bias=None,
                num_sms=self.args.num_ai_cores, async_with_compute_stream=True, defer_epilogue=False)
            event.current_stream_wait(release_handle=True)
            return output, weights

        combine_ms, (output, weights) = rt.timed(combine)
        rt.sync()
        combine_host = (time.perf_counter() - begin) * 1000
        if check:
            rt.validate_combine(output)
            require(t.equal(weights, self.weights), 'official combine did not return the original weights')
        f = rt.rank - rt.sources
        return {'iteration': iteration, 'dispatch_ms': dispatch_ms, 'combine_ms': combine_ms,
                'dispatch_harness_ms': dispatch_host, 'combine_harness_ms': combine_host,
                'dispatch_accounted_gbps': 0 if rt.is_source else gbps(rt.plan['ep_dispatch_logical_bytes_per_f'][f], dispatch_ms),
                'combine_accounted_gbps': 0 if rt.is_source else gbps(rt.plan['ep_combine_payload_bytes_per_f'][f], combine_ms)}

    def identity(self):
        return {'api': 'unmodified deep_ep.EPBuffer', 'physical_expert_slots': self.rt.plan['ep_physical_expert_slots'],
                'active_experts': self.args.num_experts, 'F_dummy_tokens': 1, 'F_dummy_routes': -1}

    def close(self):
        self.buffer.destroy()


class CamBackend:
    def __init__(self, rt):
        import umdk_cam_op_lib
        from deep_ep.utils.envs import get_hccl_group_name
        self.cam_module = umdk_cam_op_lib
        self.opp_identity = None
        self.rt, self.torch, self.args = rt, rt.torch, rt.args
        self.ops = rt.torch.ops.umdk_cam_op_lib
        a, t, p = self.args, self.torch, rt.plan
        self.group_name = get_hccl_group_name(rt.dist.distributed_c10d._get_default_group(), rt.rank)
        sources = list(range(rt.sources))
        receivers = list(range(rt.sources, a.num_processes))
        lanes = [[source, 0, 0, source, 0, a.num_tokens] for source in sources]
        self.owner = rt.deep_ep.AFDBuffer(
            rt.rank, self.group_name, sources, receivers, lanes, [0], a.hidden, 0,
            a.num_topk, a.num_experts, a.num_tokens, False, a.num_ai_cores,
            a.timeout_seconds, a.timeout_seconds, a.memory_budget_gib << 30, a.transport_reserve_mib << 20)
        if rt.is_source:
            self.owner.prepare_combine_recv(round_step=False, fair_round_robin=False)
            self.x = rt.source_x(rt.rank).to(rt.device)
            self.idx = t.tensor(rt.routes[rt.rank], dtype=t.int64, device=rt.device)
            self.weights = (self.idx >= 0).to(t.float32)
            self.mask = t.ones(a.num_tokens, dtype=t.bool, device=rt.device)
            self.output = t.empty_like(self.x)
            self.task = t.empty(64, dtype=t.uint8, device=rt.device)
            self.send_status = self.owner.send_status.view(t.int32)
            self.recv_status = self.owner.recv_status.view(t.int32)
            self.sf = t.zeros(1, dtype=t.int16, device=rt.device)
            self.progress = t.empty(0, dtype=t.uint8, device=rt.device)
        else:
            self.owner.prepare_recv(p['q'], p['q_alloc'], a.expert_alignment,
                                    ffn_transaction=True, backend_max_rows=a.max_padded_rows)
            self.owner.prepare_ffn(False)
        self.cfg = {k: int(v) for k, v in self.owner.camConfig().items()}
        self.cfg['num_hidden'] = self.cfg['num_hidden_bytes'] // 2
        require(self.cfg['num_vec_cores'] == a.num_ai_cores, 'owner and CAM AIV counts differ')
        if not rt.is_source:
            require(self.cfg['recv_q_alloc'] == p['q_alloc'], 'owner receive capacity differs from plan')
            self.recv_sf = t.empty((p['q_alloc'], self.cfg['num_sf_packs']), dtype=t.int16, device=rt.device)
        self.context_bytes = snapshot(self.owner.context)
        self.control_layout = decode_context(self.context_bytes)
        self.registered_storage = {name: tensor_storage(getattr(self.owner, name))
                                   for name in ('payload', 'control_buffer')}
        if not rt.is_source:
            self.registered_storage['combine_x'] = tensor_storage(self.owner.combine_x)
        rt.phase('cam.prepared', cfg=self.cfg, registered_storage=self.registered_storage,
                 channel_stride=self.control_layout['channel_stride'], loaded_extension=self.identity())
        self.control_observation('controls.initial')
        # Shared JIT cache compilation is serialized and outside all measurements.
        for rank in range(a.num_processes):
            if rt.rank == rank and not rt.is_source:
                self.owner.compileFFNSchedulerOnly()
                self.owner.compileFFNPollOnly(False)
                self.owner.compileComputeReadyOnly()
            rt.sync()

    def dispatch_send(self):
        o, c = self.owner, self.cfg
        self.ops.afd_async_dispatch_send(
            self.x, self.sf, self.idx, self.weights, self.mask, self.task, o.context,
            o.control_buffer, o.round_ledger, o.workspace, o.jetty_ptrs, self.send_status, self.group_name,
            c['num_ranks'], c['num_experts'], c['num_topk'], c['num_tokens_per_tile'],
            0, 0, c['num_sf_packs'], c['timeout_cycles'], 8, c['num_vec_cores'])

    def dispatch_recv(self):
        o, c = self.owner, self.cfg
        self.ops.afd_async_dispatch_recv(
            o.payload, o.context, o.active, o.execution_state, o.recv_workspace, o.control_buffer,
            o.recv_x, self.recv_sf, o.recv_src_metadata, self.group_name,
            c['num_ranks'], c['num_experts'], c['num_topk'], c['num_source_lanes'], c['num_layers'],
            c['recv_q'], c['recv_q_alloc'], c['recv_alignment'], c['recv_tile'], c['recv_rank'], 0, 0,
            c['payload_bytes'], c['control_bytes'], c['context_bytes'], c['num_hidden'],
            c['num_sf_packs'], c['num_vec_cores'])

    def combine_send(self):
        o, c = self.owner, self.cfg
        self.ops.afd_async_combine_send(
            o.combine_x, o.recv_src_metadata, o.context, o.active, o.control_buffer,
            o.execution_state, o.combine_send_workspace, o.jetty_ptrs, o.completion, self.group_name,
            c['num_src_ranks'], c['num_ranks'], c['num_experts'], c['num_topk'], c['num_source_lanes'],
            c['num_layers'], c['recv_q_alloc'], c['combine_tile'], c['recv_rank'], c['timeout_cycles'],
            c['completion_bytes'], c['num_vec_cores'])

    def combine_recv(self):
        o, c = self.owner, self.cfg
        self.ops.afd_async_combine_recv(
            o.payload, self.task, o.context, o.control_buffer, o.round_ledger, o.combine_recv_workspace,
            self.mask, self.output, self.idx, self.weights, self.recv_status, self.progress, self.group_name,
            c['num_experts'], c['num_ranks'], c['num_topk'], c['round_step'], 0, c['num_hidden'],
            c['num_token_capacity'], 8, c['return_progress_bytes'], c['timeout_cycles'], c['num_vec_cores'])

    def scheduler(self):
        o = self.owner
        o.ffnScheduler(o.context, o.control_buffer, o.scheduler_workspace, o.active, o.execution_state,
                       o.completion, o.psum_num_recv_tokens_per_expert, o.num_unaligned_recv_tokens_per_expert)

    def state(self):
        raw = snapshot(self.owner.active)
        offset = 64 + 64 * self.rt.sources + 32 * self.rt.sources * self.rt.plan['local_experts']
        active = ACTIVE.unpack_from(raw)
        require(active[9] == TX_MAGIC, 'AFD transaction trailer missing')
        return active, WORDS.unpack_from(raw, offset)

    def select(self):
        deadline = time.monotonic() + self.args.timeout_seconds
        self.rt.phase('scheduler.select')
        while time.monotonic() < deadline:
            self.owner.ffnPoll()
            self.scheduler()
            _, state = self.state()
            if state[0] == TX_SELECTED:
                self.rt.phase('scheduler.selected', transaction=list(state))
                return
            require(state[0] == TX_IDLE, f'FFN selection failed: {state}')
        raise TimeoutError('FFN scheduler did not select the published round')

    def check_registered_storage(self):
        for name, expected in self.registered_storage.items():
            require_registered_storage(getattr(self.owner, name), expected, name)

    def control_observation(self, phase, force=False):
        if not force and self.rt.trace.path is None:
            return None
        self.check_registered_storage()
        source = self.control_layout['src_rank_idx'] if self.rt.is_source else None
        observations = observe_controls(self.control_layout, snapshot(self.owner.control_buffer), source)
        self.rt.phase(phase, controls=observations)
        return observations

    def check_controls(self, iteration):
        observations = self.control_observation('controls.check', force=True)
        for observed in observations:
            names = ('consumed', 'done') if self.rt.is_source else ('credit',)
            for name in names:
                expected = (self.published_ledger[1 if name == 'consumed' else 2] if self.rt.is_source
                            else self.expected_credit[observed['lane']])
                block = observed[name]
                require(block['value'] == expected,
                        f'{name.title()} bit mismatch: got={block["value"]} want={expected} '
                        f'iteration={iteration} rank={self.rt.rank} lane={observed["lane"]} '
                        f'peer={observed.get("peer")} offset={block["offset"]} words={block["words"]}')
        if self.rt.is_source:
            ledger = snapshot(self.owner.round_ledger)
            require(all(struct.unpack_from('<I', ledger, bank * 64)[0] == 0 for bank in range(2)),
                    'round ledger was not released')

    def round(self, iteration, check):
        rt, t, p = self.rt, self.torch, self.rt.plan
        rt.iteration = iteration
        sample = {'iteration': iteration}
        if rt.is_source:
            self.x.copy_(rt.source_x(rt.rank).to(rt.device))
            packed = struct.pack('<16I', 2, rt.rank, 0, iteration, 0, self.args.num_tokens, 1, *([0] * 9))
            self.task.copy_(t.tensor(list(packed), dtype=t.uint8, device=rt.device))
        rt.sync('round_start')
        begin = time.perf_counter()
        if rt.is_source:
            sample['dispatch_send_ms'], _ = rt.timed(self.dispatch_send)
            require(self.send_status.cpu().tolist()[:2] == [2, 0], 'CAM dispatch_send failed')
            self.published_ledger = WORDS.unpack_from(snapshot(self.owner.round_ledger))
            require(self.published_ledger[0] == 1 and self.published_ledger[1] <= 1 and
                    self.published_ledger[2] <= 1, 'DS did not publish a valid single-round ledger')
            rt.phase('dispatch.published', ledger=list(self.published_ledger))
        # All data have been posted before DR; receive wait is not mislabelled
        # as transfer bandwidth, and a cohort cannot depend on Python polling order.
        rt.sync('dispatch_send_to_recv')
        if not rt.is_source:
            self.select()
            sample['dispatch_recv_ms'], _ = rt.timed(self.dispatch_recv)
            active, state = self.state()
            require(state[0] == TX_SLICE and state[3] == p['local_experts'],
                    f'expected one complete expert slice: {state}')
            f = rt.rank - rt.sources
            require(active[7] == p['routes_per_f'][f] and active[8] == p['padded_rows_per_f'][f],
                    'DR valid/padded counts differ from original input routes')
            require(WORDS.unpack_from(snapshot(self.owner.execution_state))[0] == 2, 'DR not INPUT_READY')
            rt.phase('dispatch_recv.validated', active=list(active), transaction=list(state))
            raw = snapshot(self.owner.active)
            member_offset = 64 + 64 * rt.sources + 32 * rt.sources * p['local_experts'] + 32 + 32 * rt.sources
            self.expected_credit = {}
            for member_idx in range(state[5]):
                member = WORDS.unpack_from(raw, member_offset + 32 * member_idx)
                require(member[0] < rt.sources and member[2] <= 1, 'invalid frozen return member')
                self.expected_credit[member[0]] = member[2] ^ 1
            require(set(self.expected_credit) == set(range(rt.sources)), 'single cohort is missing source members')
        rt.sync('dispatch_complete')
        sample['dispatch_harness_ms'] = (time.perf_counter() - begin) * 1000
        if self.opp_identity is None:
            self.record_loaded_opp()
        if not rt.is_source:
            padded = p['padded_rows_per_f'][rt.rank - rt.sources]
            metadata = self.owner.recv_src_metadata[:padded]
            valid = metadata[:, 0] >= 0
            rows = t.nonzero(valid, as_tuple=True)[0]
            md = metadata[valid]
            token_ids = md[:, 0].long() * self.args.num_tokens + md[:, 1].long()
            slots = md[:, 2].long()
            if check:
                require(bool(t.all(md[:, 3] == 0).item()), 'unexpected Active entry for one cohort')
                entries = [(row, a, token, k) for row, (a, token, k, _) in zip(rows.cpu().tolist(), md.cpu().tolist())]
                rt.validate_dispatch(self.owner.recv_x, None, entries, padded)
            self.check_registered_storage()
            rt.phase('fixture.before', combine_storage=tensor_storage(self.owner.combine_x))
            rt.fill_combine(self.owner.combine_x, rows, token_ids, slots)
            self.check_registered_storage()
            rt.phase('fixture.after', combine_storage=tensor_storage(self.owner.combine_x))
            self.owner.computeReady()
        rt.sync('fixture_ready')
        self.control_observation('controls.before_combine')
        begin = time.perf_counter()
        if rt.is_source:
            sample['combine_recv_ms'], _ = rt.timed(self.combine_recv)
        else:
            sample['combine_send_ms'], _ = rt.timed(self.combine_send)
        rt.sync('combine_complete')
        sample['combine_harness_ms'] = (time.perf_counter() - begin) * 1000
        self.control_observation('controls.after_combine_before_golden')
        if rt.is_source:
            require(self.recv_status.cpu().tolist()[:2] == [2, 0], 'CAM combine_recv failed')
            if check:
                rt.phase('golden.before')
                rt.validate_combine(self.output)
                rt.phase('golden.after')
                self.control_observation('controls.after_golden')
            sample['dispatch_accounted_gbps'] = gbps(p['afd_dispatch_data_bytes_per_a'][rt.rank], sample['dispatch_send_ms'])
        else:
            _, state = self.state()
            require(state[0] == TX_COMPLETE and state[7] == 1, f'CS did not commit one complete slice: {state}')
            require(WORDS.unpack_from(snapshot(self.owner.execution_state))[0] == 4, 'CS not COMMITTED')
            sample['combine_accounted_gbps'] = gbps(p['afd_combine_payload_bytes_per_f'][rt.rank - rt.sources], sample['combine_send_ms'])
        if check:
            self.check_controls(iteration)
        if not rt.is_source:
            rt.phase('scheduler.retire')
            self.scheduler()
            require(self.state()[1][0] == TX_IDLE, 'scheduler did not retire the completed transaction')
        rt.sync('round_complete')
        return sample

    def record_loaded_opp(self):
        # DS or DR has executed on every rank. Hash outside both timed phases,
        # before the first CS launch so a failing CS can still be attributed.
        try:
            self.opp_identity = loaded_cam_opp()
        except (AttributeError, OSError, ValueError) as exc:
            self.opp_identity = {'status': 'unresolved', 'reason': str(exc)}
        expected = self.args.expected_cam_opp_sha256
        self.opp_identity['expected_sha256'] = expected
        self.rt.phase('cam.opp.loaded', cam_opp=self.opp_identity)
        digests = [None] * self.args.num_processes
        self.rt.dist.all_gather_object(digests, self.opp_identity.get('sha256'), group=self.rt.cpu_group)
        if expected or not self.args.skip_perf_test:
            require(None not in digests and len(set(digests)) == 1, f'unresolved or mixed CAM OPP builds: {digests}')
        if expected:
            require(all(d == expected for d in digests), f'loaded CAM OPP differs from expected {expected}: {digests}')

    def identity(self):
        path = Path(self.cam_module.__file__).resolve()
        return {'api': 'torch.ops.umdk_cam_op_lib.afd_async_*_*',
                'cam_extension': str(path), 'cam_extension_sha256': file_hash(path),
                'cam_opp': self.opp_identity,
                'control_plane': 'companion AFDBuffer; no JIT replacement of the four communication ops'}

    def close(self):
        self.owner.destroy()
