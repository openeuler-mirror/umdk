# SPDX-License-Identifier: MIT
"""CPU-only workload accounting for the official EP / CAM AFD comparison.

U[a,f] counts source tokens with at least one valid expert on F (deduplicated).
R[a,f] counts valid (source, token, top-k slot) routes, without deduplication.
Neither tensor capacity Q nor padded expert rows belongs in these wire counts.
"""

import hashlib
import json
import math
import statistics


OFFICIAL_COMMIT = "4dfccac4fc345519427e1019557301c9e59e9c76"
OWNER_COMMIT = "25b5153eb2549107c13c8d462e325ac28cea8dea"
DEEPJIT_COMMIT = "65f513952b8771408a19202f65e36398522db6db"
METRIC_VERSION = "ep-afd-matched-roles-v1"


def align_up(value, alignment):
    if value < 0 or alignment <= 0:
        raise ValueError("nonnegative size and positive alignment required")
    return (value + alignment - 1) // alignment * alignment


def gbps(num_bytes, milliseconds):
    """Decimal GB/s: bytes / (milliseconds * 1e6); never multiply by two."""
    if num_bytes < 0 or not math.isfinite(milliseconds) or milliseconds <= 0:
        raise ValueError("invalid traffic count or measurement interval")
    return num_bytes / (milliseconds * 1e6)


def traffic_plan(routes, num_ffn_ranks, num_experts, hidden, topk, alignment=128, masks=None):
    """Build counts from original CPU input routes, independently of device output.

    routes[a][t][k] is a logical expert ID in [0,E), or -1 for a masked route.
    Duplicate expert IDs within one token are rejected, as required by AFD.
    The official EP role mapping uses E*(A+F)/F physical expert slots: the A
    slots are unused, and logical IDs are shifted by A*(E/F) onto the F ranks.
    """
    if not routes or num_ffn_ranks <= 0 or num_experts <= 0 or num_experts % num_ffn_ranks:
        raise ValueError("nonempty sources and evenly partitioned experts required")
    if hidden <= 0 or not 1 <= topk <= min(32, num_experts):
        raise ValueError("invalid hidden or top-k")
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("expert alignment must be a power of two")
    sources = len(routes)
    local_experts = num_experts // num_ffn_ranks
    unique = [[0] * num_ffn_ranks for _ in routes]
    expanded = [[0] * num_ffn_ranks for _ in routes]
    expert_counts = [[0] * local_experts for _ in range(num_ffn_ranks)]
    if masks is not None and len(masks) != sources:
        raise ValueError("mask source count mismatch")
    for a, tokens in enumerate(routes):
        if masks is not None and len(masks[a]) != len(tokens):
            raise ValueError("mask token count mismatch")
        for t, selected in enumerate(tokens):
            if len(selected) != topk:
                raise ValueError("top-k row width mismatch")
            if any(not isinstance(e, int) or e < -1 or e >= num_experts for e in selected):
                raise ValueError("expert ID outside the contract")
            valid = [e for e in selected if e >= 0]
            if len(valid) != len(set(valid)):
                raise ValueError("duplicate expert in one token")
            if masks is not None and not masks[a][t]:
                continue
            peers = set()
            for e in valid:
                f, local = divmod(e, local_experts)
                peers.add(f)
                expanded[a][f] += 1
                expert_counts[f][local] += 1
            for f in peers:
                unique[a][f] += 1
    unique_per_f = [sum(row[f] for row in unique) for f in range(num_ffn_ranks)]
    routes_per_f = [sum(row[f] for row in expanded) for f in range(num_ffn_ranks)]
    padded = [sum(align_up(n, alignment) for n in counts) for counts in expert_counts]
    payload = 2 * hidden  # BF16 dispatch and BF16 combine.
    logical_record = payload + 8 * topk + 4 * topk
    metadata = align_up(align_up(8 * topk, 32) + 4 * topk + 8, 32)
    transfer_record = payload + metadata
    # DS sends refs per route, then two int32 count/prefix tables per F peer.
    table_bytes_per_a = [4 * sum(row) + 8 * num_experts for row in expanded]
    records_per_a = [sum(row) * transfer_record for row in unique]
    route_hash = hashlib.sha256(json.dumps(
        {"routes": routes, "masks": masks}, separators=(",", ":")).encode()).hexdigest()
    return {
        "num_sources": sources, "num_ffn_ranks": num_ffn_ranks,
        "tokens_per_source": [len(tokens) for tokens in routes],
        "num_experts": num_experts, "local_experts": local_experts,
        "hidden": hidden, "topk": topk, "expert_alignment": alignment,
        "route_sha256": route_hash, "unique_tokens_a_f": unique, "routes_a_f": expanded,
        "unique_tokens_per_f": unique_per_f, "routes_per_f": routes_per_f,
        "expert_counts": expert_counts, "padded_rows_per_f": padded,
        "payload_bytes_per_row": payload, "afd_metadata_bytes": metadata,
        "afd_record_transfer_bytes": transfer_record,
        "afd_record_storage_stride": align_up(payload + metadata, 512),
        "afd_dispatch_record_bytes_per_a": records_per_a,
        "afd_dispatch_table_bytes_per_a": table_bytes_per_a,
        "afd_dispatch_data_bytes_per_a": [r + t for r, t in zip(records_per_a, table_bytes_per_a)],
        "afd_combine_payload_bytes_per_f": [n * payload for n in routes_per_f],
        # Match tests/ep/test_ep.py's logical received-record accounting.
        "ep_dispatch_logical_bytes_per_f": [n * logical_record for n in unique_per_f],
        "ep_combine_payload_bytes_per_f": [n * payload for n in unique_per_f],
        "ep_physical_expert_slots": (sources + num_ffn_ranks) * local_experts,
        "ep_expert_id_offset": sources * local_experts,
        # One slice, including padding. The owner also requires the conservative
        # largest whole-expert bound (sum of source lane capacities).
        "q": max(1, sum(map(len, routes)), max(routes_per_f)),
        "q_alloc": max(align_up(max(1, sum(map(len, routes)), max(routes_per_f)), alignment),
                       max(padded)),
    }


def summarize(values):
    if not values or any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("finite, nonnegative samples required")
    ordered = sorted(values)
    return {"n": len(values), "mean": statistics.mean(values), "median": statistics.median(values),
            "p95": ordered[math.ceil(.95 * len(ordered)) - 1], "min": ordered[0], "max": ordered[-1]}


def aggregate_report(backend, plan, rank_samples):
    """Aggregate aligned iterations, never sum per-rank GB/s or unrelated medians."""
    sources = plan["num_sources"]
    world = sources + plan["num_ffn_ranks"]
    if len(rank_samples) != world or not rank_samples[0]:
        raise ValueError("one nonempty sample list per rank required")
    count = len(rank_samples[0])
    if any(len(s) != count for s in rank_samples):
        raise ValueError("rank iteration counts differ")
    series = {key: [] for key in ("dispatch_device_envelope_ms", "combine_device_envelope_ms",
                                  "dispatch_harness_ms", "combine_harness_ms",
                                  "dispatch_accounted_gbps", "combine_accounted_gbps")}
    for iteration in range(count):
        row = [samples[iteration] for samples in rank_samples]
        if any(r["iteration"] != row[0]["iteration"] for r in row):
            raise ValueError("rank iteration identities differ")
        if backend == "cam":
            ds = max(r["dispatch_send_ms"] for r in row[:sources])
            dr = max(r["dispatch_recv_ms"] for r in row[sources:])
            cs = max(r["combine_send_ms"] for r in row[sources:])
            cr = max(r["combine_recv_ms"] for r in row[:sources])
            dispatch, combine = ds + dr, max(cs, cr)
            dispatch_bytes = sum(plan["afd_dispatch_data_bytes_per_a"])
            combine_bytes = sum(plan["afd_combine_payload_bytes_per_f"])
            dispatch_denominator, combine_denominator = ds, cs
        elif backend == "official":
            dispatch = max(r["dispatch_ms"] for r in row)
            combine = max(r["combine_ms"] for r in row)
            dispatch_bytes = sum(plan["ep_dispatch_logical_bytes_per_f"])
            combine_bytes = sum(plan["ep_combine_payload_bytes_per_f"])
            dispatch_denominator, combine_denominator = dispatch, combine
        else:
            raise ValueError("unknown backend")
        series["dispatch_device_envelope_ms"].append(dispatch)
        series["combine_device_envelope_ms"].append(combine)
        series["dispatch_harness_ms"].append(max(r["dispatch_harness_ms"] for r in row))
        series["combine_harness_ms"].append(max(r["combine_harness_ms"] for r in row))
        series["dispatch_accounted_gbps"].append(gbps(dispatch_bytes, dispatch_denominator))
        series["combine_accounted_gbps"].append(gbps(combine_bytes, combine_denominator))
    return {"per_iteration": series, "statistics": {key: summarize(v) for key, v in series.items()},
            "device_envelope": ("dispatch=max_A(DS)+max_F(DR) with a barrier between phases; "
                                "combine=max(max_F(CS),max_A(CR))" if backend == "cam" else
                                "maximum complete EP dispatch or combine event across ranks"),
            "bandwidth_boundary": (
                "CAM: sum of sender data bytes / maximum sender event interval; no DR/CR network rate"
                if backend == "cam" else
                "EP: sum of logical received/sent record bytes / maximum complete-operation event interval"),
            "warning": "Different traffic accounting and timing boundaries; GB/s ratios are not speedups."}


def compare_reports(baseline, candidate):
    if baseline.get("backend") != "official" or candidate.get("backend") != "cam":
        raise ValueError("compare requires an official baseline and a CAM candidate")
    for report in (baseline, candidate):
        if report.get("status") != "PASS" or not report.get("provenance", {}).get("verified"):
            raise ValueError("successful reports with verified source provenance required")
        if not report.get("summary"):
            raise ValueError("performance samples are required; correctness-only reports cannot be compared")
    for key in ("metric_version", "workload", "protocol"):
        if baseline.get(key) != candidate.get(key):
            raise ValueError(f"incomparable {key}")
    for key in ("test_sha256", "test_modules_sha256"):
        if not baseline["provenance"].get(key) or baseline["provenance"].get(key) != candidate["provenance"].get(key):
            raise ValueError("incomparable benchmark script revisions")
    for key in ("torch", "torch_npu", "device_names"):
        if baseline["environment"].get(key) != candidate["environment"].get(key):
            raise ValueError(f"incomparable environment: {key}")
    for key in ("hostname", "ASCEND_RT_VISIBLE_DEVICES"):
        if baseline["environment"].get(key) != candidate["environment"].get(key):
            raise ValueError(f"incomparable placement: {key}")
    base_cann = baseline["environment"].get("CANN", {}).get("content")
    candidate_cann = candidate["environment"].get("CANN", {}).get("content")
    if not base_cann or base_cann != candidate_cann:
        raise ValueError("matching recorded CANN versions are required for automatic comparison")
    ranks = candidate.get("rank_results", [])
    observations = [(r.get("backend_identity", {}).get("cam_opp") or {}) for r in ranks]
    digests = {o.get("sha256") for o in observations}
    if (not ranks or len(ranks) != len(candidate["environment"]["device_names"]) or
            {r.get("rank") for r in ranks} != set(range(len(ranks))) or len(digests) != 1 or
            any(o.get("status") != "observed" or not o.get("sha256") or
                o.get("expected_sha256") not in (None, o["sha256"]) for o in observations)):
        raise ValueError("a consistent observed CAM OPP identity is required on every rank")
    result = {}
    for key in ("dispatch_device_envelope_ms", "combine_device_envelope_ms",
                "dispatch_harness_ms", "combine_harness_ms"):
        a = baseline["summary"]["statistics"][key]["median"]
        b = candidate["summary"]["statistics"][key]["median"]
        if a <= 0 or b <= 0:
            raise ValueError("positive timing medians required")
        result[key] = {"official_median_ms": a, "cam_median_ms": b, "ratio_official_over_cam": a / b}
    return {"latency_comparison": result,
            "cam_opp_sha256": observations[0]["sha256"],
            "cam_opp_pinned": all(o.get("expected_sha256") for o in observations),
            "scope": "Matched synthetic workload; staged harness/device envelopes, not production overlap or E2E.",
            "bandwidth_ratio": None}
