#!/usr/bin/env python3
"""TTFT benchmark: aigw prefix-tree routing benefit vs direct vLLM paths.

Scenarios:
  A: through aigw (prefix cache routing active, prefix table primed to worker1)
  B: direct to worker2 with INDEPENDENT prompts (deterministic miss -> full prefill)
  C: direct to worker1 with shared prefix (deterministic hit -> tail prefill only)
  D: through aigw with prefix routing disabled (leastConn fallback, cold table)

Dataset per tier: shared prefix P_L (~90% of tier length) + 20 random tails
(2-4 blocks = 256-512 tokens). Prompt token counts calibrated via vLLM
/tokenize endpoint.

Worker1 is warmed with P_L directly (KV events feed aigw's table regardless of
request source), so aigw deterministically maps the prefix to worker1.

Output: CSV rows (append mode) for post-hoc analysis.
"""

import argparse
import csv
import json
import random
import sys
import time
import urllib.request

MODEL = "Qwen2.5-7B"
W1 = "http://169.254.30.2:8081"
W2 = "http://169.254.30.3:8082"
AIGW = "http://127.0.0.1:8701/aigw/v1/openai/chat/completions"
HITS_METRIC = "vllm:prefix_cache_hits_total"

SENTENCE = ("The quick brown fox jumps over the lazy dog and chases "
            "the playful squirrel through the autumn forest.")
WORDS = (
    "algorithm architecture cache tensor memory latency throughput scheduler "
    "request batch token prompt attention head layer gradient optimizer epoch "
    "inference deployment server cluster node replica shard partition hash "
    "prefix suffix block page frame allocator pool queue buffer stream socket "
    "connection endpoint route traffic load balance policy strategy metric "
    "observe monitor trace profile sample distribution percentile median mean "
    "variance noise signal model weight parameter gradient quantization "
    "compression distillation fine tune alignment safety guardrail tokenizer "
    "vocabulary embedding projection normalization residual activation gelu "
    "relu softmax mask causal rotary position scale factor epsilon momentum "
    "decay clip clipnorm regularization dropout batch norm layer norm "
    "convolution pooling stride padding kernel filter channel depth width "
    "height spatial temporal dynamic static compile optimize fusion kernel "
    "custom operator schedule pipeline parallel data tensor sequence context "
    "window sliding chunked prefill decode stage engine worker driver device "
    "host memory bandwidth flops throughput latency tail head block eviction "
    "replacement lru lfu clock policy hit ratio miss ratio warm cold startup "
    "shutdown graceful crash recovery checkpoint snapshot durable persistent "
    "log replay recover fallback retry timeout deadline cancel propagate "
    "exception error code message protocol handshake auth token refresh "
    "expire rotate secret key hmac signature verify encrypt decrypt cipher"
).split()


def get_hits(port, host="127.0.0.1"):
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/metrics", timeout=10) as resp:
            for line in resp:
                line = line.decode().strip()
                if line.startswith(HITS_METRIC + "{") and line.split()[0].endswith("}"):
                    return float(line.split()[1])
    except Exception:
        pass
    return -1.0


def tokenize_count(url, prompt):
    body = json.dumps({"model": MODEL, "prompt": prompt, "add_special_tokens": False}).encode()
    req = urllib.request.Request(url + "/tokenize", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["count"]


def measure_template_overhead(url):
    probe = "measure"
    n_content = tokenize_count(url, probe)
    body = json.dumps({"model": MODEL,
                       "messages": [{"role": "user", "content": probe}],
                       "max_tokens": 1}).encode()
    req = urllib.request.Request(url + "/v1/chat/completions", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        used = json.loads(resp.read())["usage"]["prompt_tokens"]
    return used - n_content


def calibrate_prefix(tok_url, tier_tokens, overhead):
    """Binary search number of repeated sentences so content+overhead == tier."""
    lo, hi = 1, 4096
    best_n, best_diff = 1, 10 ** 9
    while lo <= hi:
        mid = (lo + hi) // 2
        content = " ".join([SENTENCE] * mid)
        n = tokenize_count(tok_url, content)
        diff = abs(n + overhead - tier_tokens)
        if diff < best_diff:
            best_n, best_diff = mid, diff
        if n + overhead < tier_tokens:
            lo = mid + 1
        else:
            hi = mid - 1
    return best_n


def calibrate_tail(tok_url, target_tokens):
    """Random word tail calibrated to target_tokens (words~tokens 1:1, few iters)."""
    n_words = max(16, target_tokens // 2)
    tail = ""
    n = 0
    for _ in range(6):
        tail = " ".join(random.choices(WORDS, k=n_words))
        n = tokenize_count(tok_url, tail)
        diff = n - target_tokens
        if abs(diff) <= 8:
            return tail, n
        n_words = max(16, n_words - diff // 2)
    return tail, n


def calibrate_independent(tok_url, tier_tokens, overhead):
    """Independent prompt (random words) calibrated to tier total tokens."""
    tgt = tier_tokens - overhead
    tail, n = calibrate_tail(tok_url, tgt)
    return tail, n


def sse_ttft(url, body, timeout=180):
    """Return (ttft_s, ok) - time to first content-bearing SSE chunk."""
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw in resp:
                line = raw.decode().strip()
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    ev = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                for ch in ev.get("choices") or []:
                    content = (ch.get("delta") or {}).get("content")
                    if content:
                        return (time.perf_counter() - start) * 1000.0, True
    except Exception as e:
        print(f"    [warn] request failed: {e}", file=sys.stderr)
        return -1.0, False
    return -1.0, False


def chat_body(prompt):
    return {"model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 8,
            "stream": True}


def run_scenario(csvw, tier, scenario, prompts, url, n):
    """Run n requests against url. Returns (done, hits_w1_delta, hits_w2_delta)."""
    rng = random.Random(seed + hash((tier, scenario)) % 2 ** 32)
    order = list(range(len(prompts)))
    rng.shuffle(order)

    h1_0 = get_hits(8081)
    h2_0 = get_hits(8082)
    done = 0
    for idx in order:
        prompt, tail_tokens = prompts[idx]
        ttft, ok = sse_ttft(url, chat_body(prompt))
        if not ok:
            continue
        csvw.writerow([time.strftime("%Y-%m-%dT%H:%M:%S"), tier, scenario, done,
                       tail_tokens, round(ttft, 2), 1])
        done += 1
        if done >= n:
            break
    h1_1 = get_hits(8081)
    h2_1 = get_hits(8082)
    return done, h1_1 - h1_0, h2_1 - h2_0


def main():
    global seed
    ap = argparse.ArgumentParser()
    ap.add_argument("--tiers", default="512,2048,4096")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--scenarios", default="A,B,C")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="/tmp/ttft_results.csv")
    ap.add_argument("--warm", action="store_true",
                    help="warm worker1 with P_L directly before measurements")
    args = ap.parse_args()
    seed = args.seed

    tiers = [int(t) for t in args.tiers.split(",")]
    scenarios = args.scenarios.split(",")
    urls = {"A": AIGW, "B": W2 + "/v1/chat/completions",
            "C": W1 + "/v1/chat/completions", "D": AIGW}
    tok_url = W1

    overhead = measure_template_overhead(W1)
    print(f"[setup] template overhead={overhead} tokens", flush=True)

    with open(args.out, "a", newline="") as f:
        csvw = csv.writer(f)
        if f.tell() == 0:
            csvw.writerow(["ts", "tier", "scenario", "req_idx", "tail_tokens",
                           "ttft_ms", "ok"])
        for tier in tiers:
            n_pref = calibrate_prefix(tok_url, tier, overhead)
            prefix = " ".join([SENTENCE] * n_pref)
            pref_tokens = tokenize_count(tok_url, prefix) + overhead
            print(f"[tier {tier}] prefix: {n_pref} sentences (={pref_tokens} tokens)", flush=True)

            tails = []
            for _ in range(args.n):
                tgt = random.Random(seed + tier + _).randint(256, 512)
                tail, tn = calibrate_tail(tok_url, tgt)
                tails.append((tail, tn))

            if args.warm:
                warm_prompt = prefix + " " + tails[0][0]
                ttft, ok = sse_ttft(W1 + "/v1/chat/completions", chat_body(warm_prompt))
                print(f"  [warm] worker1 direct ttft={ttft:.1f}ms ok={ok}", flush=True)
                time.sleep(3)

            for sc in scenarios:
                if sc == "B":
                    prompts = [calibrate_independent(tok_url, tier, overhead)
                               for _ in range(args.n)]
                    print(f"  [B] tier={tier} independent prompts "
                          f"(deterministic miss), n={args.n} ...", flush=True)
                else:
                    prompts = [(prefix + " " + t, tn) for t, tn in tails]
                    print(f"  [{sc}] tier={tier} shared-prefix prompts, n={args.n} ...",
                          flush=True)
                done, dh1, dh2 = run_scenario(csvw, tier, sc, prompts, urls[sc], args.n)
                print(f"  [{sc}] tier={tier} done={done} "
                      f"hits_w1_delta={dh1:.0f} hits_w2_delta={dh2:.0f}", flush=True)
    print("[done]")


if __name__ == "__main__":
    main()
