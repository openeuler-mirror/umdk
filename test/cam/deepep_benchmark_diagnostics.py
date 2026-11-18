# SPDX-License-Identifier: MIT
"""Host-only diagnostics for AFD ABI 2; never changes device protocol state."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import time


CONTEXT = struct.Struct('<18I8Q')
LANE = struct.Struct('<8I')
ADDRESS = struct.Struct('<8Q')
RETURN_DIRECTORY = struct.Struct('<3Q2I')
RETURN_LANE = struct.Struct('<4Q')

CAM_OPS = {
    'cam_deepep_dispatch_send': 'aclnnCamDeepepDispatchSend',
    'cam_deepep_dispatch_recv': 'aclnnCamDeepepDispatchRecv',
    'cam_deepep_combine_send': 'aclnnCamDeepepCombineSend',
    'cam_deepep_combine_recv': 'aclnnCamDeepepCombineRecv',
}


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for data in iter(lambda: stream.read(1 << 20), b''):
            digest.update(data)
    return digest.hexdigest()


def cam_opp_manifest(vendor_root):
    """Fingerprint the operator API, tiling and four installed Ascend950 kernel sets."""
    root = Path(vendor_root).resolve(strict=True)
    tbe = root / 'op_impl/ai_core/tbe'
    kernel = tbe / 'kernel'
    artifacts = [root / 'op_api/lib/libcust_opapi.so', kernel / 'config/ascend950/binary_info_config.json']
    tiling = list((tbe / 'op_tiling').rglob('*.so'))
    if not tiling:
        raise ValueError(f'missing tiling library under {tbe}')
    artifacts.extend(tiling)
    for op in sorted(CAM_OPS):
        directory = kernel / 'ascend950' / op
        objects = sorted(directory.glob('*.o'))
        if not objects:
            raise ValueError(f'missing Ascend950 kernel objects in {directory}')
        for obj in objects:
            artifacts.extend((obj, obj.with_suffix('.json')))
        artifacts.append(kernel / 'config/ascend950' / (op + '.json'))
    hashes = {path.relative_to(root).as_posix(): file_hash(path) for path in artifacts}
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {'vendor_root': str(root), 'files_sha256': hashes, 'sha256': hashlib.sha256(encoded).hexdigest()}


def loaded_cam_opp():
    """Resolve the ACLNN symbols from the already-loaded custom API, then fingerprint its package."""
    # The CAM pybind loader looks up these symbols in libcust_opapi.so first.
    # RTLD_NOLOAD prevents this observation from loading a different library.
    lib = ctypes.CDLL('libcust_opapi.so', mode=os.RTLD_LAZY | os.RTLD_NOLOAD)
    maps = []
    for line in Path('/proc/self/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and 'x' in fields[1] and fields[5].startswith('/'):
            start, end = (int(v, 16) for v in fields[0].split('-'))
            major, minor = (int(v, 16) for v in fields[3].split(':'))
            maps.append((start, end, Path(fields[5]), os.makedev(major, minor), int(fields[4])))
    mapped = set()
    for op in CAM_OPS.values():
        for symbol in (op, op + 'GetWorkspaceSize'):
            address = ctypes.cast(getattr(lib, symbol), ctypes.c_void_p).value
            owner = next((item[2:] for item in maps if item[0] <= address < item[1]), None)
            if owner is None:
                raise ValueError(f'cannot identify the mapped owner of {symbol}')
            mapped.add(owner)
    if len(mapped) != 1:
        raise ValueError('the DeepEP ACLNN symbols resolve to different mapped libraries')
    path, dev, inode = mapped.pop()
    if path.parent.name != 'lib' or path.parent.parent.name != 'op_api':
        raise ValueError(f'mapped library is outside a CAM OPP op_api/lib directory: {path}')
    root = path.parents[2].resolve(strict=True)
    api = root / 'op_api/lib/libcust_opapi.so'
    other_roots = [Path(p).resolve() for p in os.environ.get('ASCEND_CUSTOM_OPP_PATH', '').split(os.pathsep) if p]
    for other in other_roots:
        if other != root and any((other / 'op_impl/ai_core/tbe/kernel/ascend950' / op).is_dir() for op in CAM_OPS):
            raise ValueError(f'another configured OPP also supplies DeepEP kernels: {other}')
    manifest = cam_opp_manifest(root)
    stat = api.stat()
    if (stat.st_dev, stat.st_ino) != (dev, inode) or not path.samefile(api):
        raise ValueError(f'installed op_api differs from the mapped file: {path}')
    return {**manifest, 'mapped_op_api': str(path), 'status': 'observed'}


def decode_context(raw):
    if len(raw) < 256:
        raise ValueError('AFD context does not cover the ABI 2 header')
    values = CONTEXT.unpack_from(raw)
    if values[0] != 2 or values[1] <= 0 or values[2] <= 0 or values[3] <= 0:
        raise ValueError('invalid AFD ABI or rank/lane counts')
    context_bytes = values[22]
    if not 256 <= context_bytes <= len(raw):
        raise ValueError('AFD context_bytes exceeds its tensor')

    def read(record, offset):
        if offset < 0 or offset % 32 or offset + record.size > context_bytes:
            raise ValueError(f'AFD context record outside bounds: offset={offset}, bytes={record.size}')
        return record.unpack_from(raw, offset)

    directory = read(RETURN_DIRECTORY, values[25])
    if directory[3] != 1:
        raise ValueError('unsupported AFD return-directory version')
    lanes = [read(LANE, values[18] + i * 32) for i in range(values[3])]
    for lane in lanes:
        if lane[0] >= values[2]:
            raise ValueError('lane source index outside the source domain')
    return {
        'abi_version': values[0], 'num_ranks': values[1], 'num_src_ranks': values[2],
        'num_source_lanes': values[3], 'src_rank_idx': values[13], 'channel_stride': values[16],
        'context_bytes': context_bytes, 'control_bytes': values[24],
        'return_stride': directory[2], 'lanes': lanes,
        'addresses': [read(ADDRESS, values[20] + i * 64) for i in range(values[3] * values[1])],
        'returns': [read(RETURN_LANE, directory[1] + i * 32) for i in range(values[3])],
    }


def observe_controls(layout, raw, source_index=None):
    """Report exact offsets and words, without masking invalid values to 0/1."""
    if len(raw) != layout['control_bytes']:
        raise ValueError('control tensor does not match context.control_bytes')

    def block(offset):
        if offset < 0 or offset % 32 or offset + 32 > len(raw):
            raise ValueError(f'control block outside tensor: offset={offset}, bytes={len(raw)}')
        return {'offset': offset, 'value': struct.unpack_from('<I', raw, offset)[0],
                'words': list(struct.unpack_from('<8I', raw, offset))}

    result = []
    if source_index is not None:
        if source_index != layout['src_rank_idx']:
            raise ValueError('requested source does not match the context source index')
        for lane, description in enumerate(layout['lanes']):
            if description[0] != source_index:
                continue
            for peer in range(layout['num_ranks']):
                address = layout['addresses'][lane * layout['num_ranks'] + peer]
                result.append({'lane': lane, 'peer': peer,
                               'consumed': block(address[6]),
                               'done': block(layout['returns'][lane][1] + peer * 64)})
        if not result:
            raise ValueError('source has no lane in the context')
    else:
        for lane, returned in enumerate(layout['returns']):
            result.append({'lane': lane, 'credit': block(returned[2])})
    return result


def tensor_storage(tensor):
    return {'data_ptr': int(tensor.data_ptr()), 'storage_offset': int(tensor.storage_offset()),
            'shape': list(tensor.shape), 'stride': list(tensor.stride()),
            'dtype': str(tensor.dtype), 'device': str(tensor.device)}


def require_registered_storage(tensor, expected, name):
    actual = tensor_storage(tensor)
    if actual != expected:
        raise RuntimeError(f'{name} changed after HcommMemReg: expected={expected}, actual={actual}')
    return actual


class DiagnosticTrace:
    def __init__(self, directory, rank):
        self.rank = rank
        self.last_phase = 'initialization'
        self.path = None
        if directory is not None:
            root = Path(directory)
            root.mkdir(parents=True, exist_ok=True)
            self.path = root / f'rank{rank}-pid{os.getpid()}-{time.time_ns()}.jsonl'

    def record(self, phase, iteration, **details):
        previous = self.last_phase
        self.last_phase = phase
        if self.path is None:
            return
        event = {'rank': self.rank, 'pid': os.getpid(), 'iteration': iteration,
                 'phase': phase, 'previous_phase': previous, 'monotonic_ns': time.monotonic_ns(), **details}
        line = json.dumps(event, ensure_ascii=False)
        with self.path.open('a', encoding='utf-8') as stream:
            stream.write(line + '\n')
        print('BENCH_PHASE ' + line, flush=True)
