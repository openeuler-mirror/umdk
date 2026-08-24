# aigw 前缀缓存 ↔ vLLM 联调打通 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 aigw 前缀感知路由链路(renderclient + prefixcache + kvevents + prefix_cache_lb)接到环境里两个 vLLM 实例(8081/8080),端到端验证前缀命中与 KV 复用。

**Architecture:** vLLM 0.18 自带 `/v1/chat/completions/render`(返回 token_ids)与 `kv_events.py`(ZMQ PUB :5557、msgpack、BlockStored/Removed/Cleared)。aigw 仅需 1 行代码改动让 render client 打 `/render` 端点 + 两侧 block_size 对齐到 128 + 配置启用 prefix cache LB 与 KV 订阅 + 运行时注册 worker。消息线兼容性已在调研阶段用样本编码实测通过。

**Tech Stack:** Go 1.24(aigw)、vllm-ascend v0.18.0(vLLM)、ZMQ + msgpack、Python(ZMQ 抓包脚本)、Docker。

> **EXECUTION DEVIATION (Task 2, 2026-08-04):** 原计划模型 `Qwen3.5-9B` 是混合 Mamba+attention 架构,vLLM 0.18 的 `kv_events` 在混合模型上启动即崩(`Hybrid KV cache manager is disabled but failed to convert the KV cache specs to one unified type`)。已改为纯 attention 模型 **`Qwen2.5-7B-Instruct`**(下载到 `/root/.cache/modelscope/hub/models/Qwen/Qwen2.5-7B-Instruct`)。下文 Task 3/4/5 里的 model 名均应读作 `Qwen2.5-7B-Instruct`。`--block-size 128` 在纯 attention 上验证可用。详见 `.superpowers/sdd/.../task-2-report.md`。

## Global Constraints

- vLLM 镜像必须用 image ID `bab0bb869c9c` 启动(registry DNS 不通,tag 名会触发 pull 失败)。
- 两 vLLM 容器必须 `--privileged` 启动(否则 Ascend 驱动报 `drvRet=87`)。
- 两 vLLM 容器必须**串行重启**以保 HBM 分配平衡(单 NPU 共享)。
- **block_size 两侧统一 128**:vLLM `--block-size 128` + aigw `AIGW_PREFIX_CACHE_BLOCK_SIZE=128` + `globalSchedulers[].blockSize=128`。不一致则 aigw 自算 hash 粒度对不上,永远 0 命中。
- `globalSchedulers[].model` 必须等于 vLLM `--served-model-name`(均 `Qwen2.5-7B-Instruct`,见上方 DEVIATION)。
- aigw ZMQ 订阅端口硬编码 `:5557`(`internal/kvevents/manager.go:192-198`);vLLM 必须在容器内绑 `tcp://*:5557`。aigw 以 host 进程运行,通过各 vLLM 容器的**内网 IP**(172.17.0.x)直连 `:5557`(host 可达 docker bridge 容器 IP);每容器在自己的 network namespace 内绑 5557,互不冲突,故**无需** `-p 5557` 宿主映射。worker 注册时 `instanceIp` 必须填该容器的内网 IP(非 127.0.0.1),这样 aigw 的 ZMQ 订阅端点 `tcp://<IP>:5557` 与 proxy 转发的 `http://<IP>:<port>` 都可达。
- model 权重与 torch_compile_cache 都 bind mount `/root/.cache`(宿主 `/root/.cache`),两实例共享,这是串行重启的原因之一。

## File Structure

| 文件 | 责任 | 任务 |
|---|---|---|
| `internal/renderclient/adapter.go` | vLLM render 端点路径与响应解析;改 `getChatPath()` 指向 `/v1/chat/completions/render` | Task 1 |
| `internal/renderclient/adapter_test.go`(新建) | 锁定 render 路径 + 验证 parseResponse 能解析 vLLM 真实 render 响应 | Task 1 |
| `/tmp/zmq_capture.py`(临时) | 抓 vLLM ZMQ 事件,确认线格式与 aigw 解码器一致 | Task 3 |
| `configs/aigw-prefix-cache.example.json`(新建运行时配置模板) | aigw 启动配置模板:block_size=128、prefixCache LB、renderClient baseURL、model 名;复制为 `aigw-prefix-cache.json` 并填入本机路径/IP 后使用 | Task 4 |
| `/mnt/workspace/vllm-setup.md`(已存在) | vLLM 容器重建模板;Task 2 复用并加 `--block-size 128` + `--kv-events-config` + `-p 5557` | Task 2 |

---

## Task 1: render client 指向 /render 端点 + 兼容性单测

**Files:**
- Modify: `internal/renderclient/adapter.go:89-91`
- Create: `internal/renderclient/adapter_test.go`

**Interfaces:**
- Consumes: 无(纯 stdlib)
- Produces: `(*vllmAdapter).getChatPath()` 返回 `/v1/chat/completions/render`;`parseResponse` 已能解析 vLLM render 响应(json tag `token_ids` 对齐,见 `types.go:28`)。后续 Task 4 的 renderClient 经此路径拿 token_ids。

- [ ] **Step 1: 写失败测试(新建 `internal/renderclient/adapter_test.go`)**

```go
package renderclient

import "testing"

// TestVllmAdapter_GetChatPathPointsToRenderEndpoint 锁定 render client 必须打
// vLLM 的 /render 端点。stock vLLM 的 /v1/chat/completions 做真实生成、不返回
// token_ids;只有 /v1/chat/completions/render 返回 {"token_ids":[...]}。
func TestVllmAdapter_GetChatPathPointsToRenderEndpoint(t *testing.T) {
	a := newVLLMAdapter("Qwen2.5-7B-Instruct")
	const want = "/v1/chat/completions/render"
	if got := a.getChatPath(); got != want {
		t.Fatalf("getChatPath() = %q, want %q", got, want)
	}
}

// TestVllmAdapter_ParseRenderResponse_ExtractsTokenIDs 用 vLLM 0.18
// /v1/chat/completions/render 的真实响应体(curl 录得)验证 RenderResponse 的
// json tag 与 vLLM 线格式对齐——能正确抽出 token_ids。
func TestVllmAdapter_ParseRenderResponse_ExtractsTokenIDs(t *testing.T) {
	body := []byte(`{"request_id":"chatcmpl-x","token_ids":[248045,846,198,14556,248046,198,248045,74455,198,248068,198],"features":null,"model":"Qwen2.5-7B-Instruct","stream":false}`)
	a := newVLLMAdapter("Qwen2.5-7B-Instruct")
	resp, err := a.parseResponse(body)
	if err != nil {
		t.Fatalf("parseResponse failed: %v", err)
	}
	want := []int64{248045, 846, 198, 14556, 248046, 198, 248045, 74455, 198, 248068, 198}
	if len(resp.TokenIDs) != len(want) {
		t.Fatalf("TokenIDs len = %d, want %d (got %v)", len(resp.TokenIDs), len(want), resp.TokenIDs)
	}
	for i := range want {
		if resp.TokenIDs[i] != want[i] {
			t.Fatalf("TokenIDs[%d] = %d, want %d", i, resp.TokenIDs[i], want[i])
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败(路径项 fail,parseResponse 项 pass)**

Run: `go test ./internal/renderclient/ -run TestVllmAdapter -v`
Expected: `TestVllmAdapter_GetChatPathPointsToRenderEndpoint` FAIL(`got "/v1/chat/completions"`);`TestVllmAdapter_ParseRenderResponse_ExtractsTokenIDs` PASS(证明 json tag 已对齐)。

> 若 Go 未安装,先执行 Task 1 的前置 Step 0(见下)。

- [ ] **Step 2a(前置,仅当 host 无 go):安装 Go 1.24**

```bash
# 确认缺失
which go || true
# 装 Go 1.24 到 /usr/local/go(不污染系统,只解压)
curl -sSLO /tmp/go.tgz https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf /tmp/go.tgz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin
go version   # 期望: go version go1.24.0 linux/amd64
```

- [ ] **Step 3: 改 `internal/renderclient/adapter.go:89-91`**

```go
func (a *vllmAdapter) getChatPath() string {
	return "/v1/chat/completions/render"
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/renderclient/ -run TestVllmAdapter -v`
Expected: 两个测试 PASS。

- [ ] **Step 5: 提交**

```bash
cd /mnt/workspace/aigw/aigw
git add internal/renderclient/adapter.go internal/renderclient/adapter_test.go
git -c user.email="aigw-dev@local" -c user.name="aigw-dev" commit -m "fix(renderclient): point chat path at vLLM /render endpoint for token_ids

stock vLLM's /v1/chat/completions performs generation and returns no
token_ids; only /v1/chat/completions/render returns {token_ids:[...]}.
Add unit test pinning the path and a characterization test proving
parseResponse parses a recorded vLLM render body."
```

---

## Task 2: vLLM 两容器串行重启(block_size=128 + KV 事件 + 5557 端口)

**Files:** 无仓库文件;操作 Docker。复用 `/mnt/workspace/vllm-setup.md` 的 docker run 模板,加 3 项新参数。

**Interfaces:**
- Consumes: 镜像 `bab0bb869c9c`、宿主 `/root/.cache`、Ascend 设备文件
- Produces: 两个 vLLM 实例,`/v1/chat/completions/render` 可用、`:5557` ZMQ 在监听、`/metrics` 的 `block_size=128`。后续 Task 3/4/5 依赖。

> 关键:先停容器 1、起新配置容器 1(此时容器 2 仍占 ~24GB HBM,新容器 1 按 0.5 预算算仍 ~24GB,平衡);再停容器 2、起新配置容器 2。

- [ ] **Step 1: 停并删旧容器 1**

```bash
sudo docker stop vllm-ascend-env && sudo docker rm vllm-ascend-env
```

- [ ] **Step 2: 用新配置起容器 1(端口 8081 + 5557)**

```bash
sudo docker run -d --name vllm-ascend-env --privileged \
  -p 8081:8081 \
  --device /dev/davinci7:/dev/davinci7 \
  --device /dev/davinci_manager:/dev/davinci_manager \
  --device /dev/devmm_svm:/dev/devmm_svm \
  --device /dev/hisi_hdc:/dev/hisi_hdc \
  -v /etc/ascend_install.info:/etc/ascend_install.info \
  -v /root/.cache:/root/.cache \
  -v /usr/local/dcmi:/usr/local/dcmi \
  -v /usr/local/bin/npu-smi:/usr/local/bin/npu-smi \
  -v /usr/local/Ascend/driver/lib64:/usr/local/Ascend/driver/lib64 \
  -v /usr/local/Ascend/driver/version.info:/usr/local/Ascend/driver/version.info \
  --entrypoint /bin/bash \
  bab0bb869c9c \
  -c "vllm serve /root/.cache/modelscope/hub/models/Qwen/Qwen3.5-9B --dtype auto --port 8081 --tensor-parallel-size 1 --max-model-len 32768 --max-num-seqs 4 --max-num-batched-tokens 65536 --served-model-name Qwen3.5-9B --trust-remote-code --gpu-memory-utilization 0.5 --enable-prefix-caching --block-size 128 --kv-events-config '{\"enable_kv_cache_events\": true, \"publisher\": \"zmq\", \"endpoint\": \"tcp://*:5557\", \"topic\": \"\"}'"
```

> 引号说明:外层 `"..."` 是 host bash 给 `bash -c` 的单参数,内层 JSON 的双引号写 `\"`、外裹 `'...'`;container 内 bash 解析后 vLLM 收到合法 JSON。

- [ ] **Step 3: 等 30~80s 首次图编译,验证容器 1**

```bash
# render 仍可用 + 返回 token_ids
curl -s -X POST http://localhost:8081/v1/chat/completions/render \
  -H "Content-Type: application/json" \
  -d '{"model":"Qwen2.5-7B-Instruct","messages":[{"role":"user","content":"hi"}],"max_tokens":1}' | head -c 200
# 5557 在监听
sudo docker exec vllm-ascend-env ss -tlnp | grep 5557
# block_size=128
curl -s http://localhost:8081/metrics | grep -E 'cache_config_info' | grep -oE 'block_size="[0-9]+"'
```
Expected:render 返回含 `token_ids`;`ss` 见 `:5557 LISTEN`;metrics `block_size="128"`。
> 若 `--block-size 128` 被 vllm-ascend 拒绝(启动失败或强制回 1024):看 `docker logs vllm-ascend-env`;如确实不支持,保留 1024 并把 Task 4 配置里 `AIGW_PREFIX_CACHE_BLOCK_SIZE`/`globalSchedulers[].blockSize` 也改回 1024,matchThreshold 维持低值(10)。

- [ ] **Step 4: 停并删旧容器 2,用新配置起容器 2(端口 8080 + 5557→5558 避免宿主冲突)**

```bash
sudo docker stop vllm-ascend-env-2 && sudo docker rm vllm-ascend-env-2
sudo docker run -d --name vllm-ascend-env-2 --privileged \
  -p 8080:8080 \
  --device /dev/davinci7:/dev/davinci7 \
  --device /dev/davinci_manager:/dev/davinci_manager \
  --device /dev/devmm_svm:/dev/devmm_svm \
  --device /dev/hisi_hdc:/dev/hisi_hdc \
  -v /etc/ascend_install.info:/etc/ascend_install.info \
  -v /root/.cache:/root/.cache \
  -v /usr/local/dcmi:/usr/local/dcmi \
  -v /usr/local/bin/npu-smi:/usr/local/bin/npu-smi \
  -v /usr/local/Ascend/driver/lib64:/usr/local/Ascend/driver/lib64 \
  -v /usr/local/Ascend/driver/version.info:/usr/local/Ascend/driver/version.info \
  --entrypoint /bin/bash \
  bab0bb869c9c \
  -c "vllm serve /root/.cache/modelscope/hub/models/Qwen/Qwen3.5-9B --dtype auto --port 8080 --tensor-parallel-size 1 --max-model-len 32768 --max-num-seqs 4 --max-num-batched-tokens 65536 --served-model-name Qwen3.5-9B --trust-remote-code --gpu-memory-utilization 0.5 --enable-prefix-caching --block-size 128 --kv-events-config '{\"enable_kv_cache_events\": true, \"publisher\": \"zmq\", \"endpoint\": \"tcp://*:5557\", \"topic\": \"\"}'"
```

> 容器 2 同样在容器内绑 `:5557`(独立 network namespace,不与容器 1 冲突),aigw 通过容器 2 的内网 IP 访问。**无需** `-p 5557` 宿主映射。Task 4 用 `docker inspect` 取两容器内网 IP 注册 worker。

- [ ] **Step 5: 验证容器 2 + HBM 平衡**

```bash
curl -s -X POST http://localhost:8080/v1/chat/completions/render -H "Content-Type: application/json" -d '{"model":"Qwen2.5-7B-Instruct","messages":[{"role":"user","content":"hi"}],"max_tokens":1}' | head -c 200
sudo docker exec vllm-ascend-env-2 ss -tlnp | grep 5557
sudo npu-smi info | grep -E '910B3|65536'   # HBM 应 ~45GB used,~20GB 余
```
Expected:render 返回 token_ids;容器内 5557 LISTEN;HBM 与重启前量级一致。

---

## Task 3: ZMQ 事件抓包 smoke test(线格式去风险)

**Files:**
- Create: `/tmp/zmq_capture.py`(临时,不入仓)

**Interfaces:**
- Consumes: Task 2 的 vLLM `:5557` PUB
- Produces: 确认 vLLM 发的事件 multipart 帧布局 + msgpack 字段顺序与 `internal/kvevents/client.go:216`(decodeBatch)+ `client.go:266`(decodeBlockStored)一致。这是 aigw 订阅前的前置去风险。

- [ ] **Step 1: 写抓包脚本**

`/tmp/zmq_capture.py`:
```python
import time, zmq, msgspec
ctx = zmq.Context()
sock = ctx.socket(zmq.SUB)
sock.connect("tcp://127.0.0.1:5557")   # 容器 1
sock.setsockopt(zmq.SUBSCRIBE, b"")
print("waiting for KV events on 5557 ...")
deadline = time.time() + 90
while time.time() < deadline:
    try:
        parts = sock.recv_multipart(timeout=5000)
    except zmq.Again:
        continue
    print(f"=== frames={len(parts)}")
    for i, p in enumerate(parts):
        print(f"  [{i}] len={len(p)} head={p[:48]!r}")
    last = parts[-1]
    try:
        obj = msgspec.msgpack.decode(last)
        print("  decoded:", obj)
        if isinstance(obj, list) and len(obj) >= 2 and isinstance(obj[1], list):
            ev = obj[1][0] if obj[1] else None
            if isinstance(ev, list) and ev:
                print("  event[0] tag:", ev[0], " fields:", ev[1:])
    except Exception as e:
        print("  decode err:", e)
print("done")
```

- [ ] **Step 2: 在 vllm 容器 1 内跑脚本,同时另开终端发请求触发事件**

```bash
# 终端 A:容器 1 内抓包
sudo docker exec -i vllm-ascend-env bash -c 'cat > /tmp/zc.py && python3 /tmp/zc.py' < /tmp/zmq_capture.py
# 终端 B:触发一次生成,产生 BlockStored 事件
curl -s -X POST http://localhost:8081/v1/chat/completions -H "Content-Type: application/json" -d '{"model":"Qwen2.5-7B-Instruct","messages":[{"role":"user","content":"hello world this is a prefix cache test"}],"max_tokens":8}'
```

- [ ] **Step 3: 核对线格式**

Expected:终端 A 打印 `frames=3`(`[topic, seq(8B), msgpack_batch]`),decoded 形如 `[<ts>, [['BlockStored', [hashes...], parent, [token_ids...], 128, lora_id, ...]]]`。
- 确认 tag 是字符串 `"BlockStored"`(与 `client.go:244` switch 一致)
- 确认 raw[1:] 的 raw[3]=block_size=128(与 `client.go:293` 一致)
- 确认 raw[1:] 长度 ≥5(`client.go:267` 守卫)
- 若 frames 数 ≠ 3 或字段顺序不符:记录差异,回到调研——可能需在 aigw 解码器加适配(不入本计划,作为发现项上报)。

---

## Task 4: aigw 运行时配置 + 构建 + 启动 + 注册 worker

**Files:**
- Create: `configs/aigw-prefix-cache.example.json`(运行时配置模板,基于 `configs/aigw.json` 裁剪;含占位路径/IP,复制为 `aigw-prefix-cache.json` 后按本机环境填写)

**Interfaces:**
- Consumes: Task 1 的 render client 改动、Task 2 的 vLLM 实例(8081/8080 + 两内网 IP 的 5557)、Task 3 已验证的线格式
- Produces: 一个运行中的 aigw 进程,日志可见 render tokenize + ZMQ 订阅 + decodeBlockStored。Task 5 依赖。

- [ ] **Step 1: 取两 vLLM 容器内网 IP**

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vllm-ascend-env
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vllm-ascend-env-2
# 记为 IP1=172.17.0.X, IP2=172.17.0.Y
```

- [ ] **Step 2: 写运行时配置 `configs/aigw-prefix-cache.example.json`(模板)**

基于 `configs/aigw.json`,只保留一个 model 的实例模式 scheduler,关键字段:

```json
{
  "global": {
    "listenPort": "8701",
    "logPath": "/var/log/aigw/aigw.log"
  },
  "globalSchedulers": [
    {
      "model": "Qwen2.5-7B-Instruct",
      "mode": "",
      "blockSize": 128,
      "loadBalancer": { "mixed": "prefixCache" },
      "renderClient": {
        "endpointTemplate": "http://{ip}:8000",
        "baseURL": "http://127.0.0.1:8081",
        "timeout": 5000,
        "maxRetries": 3,
        "connPoolSize": 100
      },
      "prefixCache": {
        "enabled": true,
        "blockSize": 128,
        "matchThreshold": 10
      }
    }
  ]
}
```

> zk/discovery 段:本机单实例 aigw,可把 discovery 关掉或用文件发现(参考 `test/e2e/test_config_prefix_cache.json`)。若 aigw 启动强校验 zk,先用 fake zk(参考 e2e mock 的 8000 端口)或注释掉 zk 配置项试启动,看日志报什么再补。

- [ ] **Step 3: 设环境变量**

```bash
export AIGW_PREFIX_CACHE_ENABLED=true
export AIGW_KV_EVENTS_ENABLED=true
export AIGW_PREFIX_CACHE_BLOCK_SIZE=128
export AIGW_PREFIX_CACHE_MATCH_THRESHOLD=10
export AIGW_KV_EVENTS_ENDPOINT_TEMPLATE='tcp://{ip}:5557'
# 若选 Task 2 Step 4 的 (a) 方案,IP 用容器内网 IP,端口恒 5557,模板默认即可
```

- [ ] **Step 4: 构建 aigw 二进制**

```bash
cd /mnt/workspace/aigw/aigw
# 前置:若无 rust/cargo,装最小工具链(build_rust.sh 需要,产出 tokenizers FFI)
which cargo || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
# 全量构建(含 rust FFI + cgo lib + UT)
./build.sh
# 期望产出二进制
ls -la output/aigw 2>&1
```
> 若 `./build.sh` 因 LightGBM/opensrc 依赖失败,先单独验 go build 能否过(需要 cgo rust lib 就位):`go build -o output/aigw ./cmd/aigw`。失败信息记录,可能需补 cmake/gcc 依赖(已确认 cmake/gcc 在)。

- [ ] **Step 5: 启动 aigw**

```bash
mkdir -p /var/log/aigw
./output/aigw --config=configs/aigw-prefix-cache.json 2>&1 | tee /var/log/aigw/startup.log
# 先把 configs/aigw-prefix-cache.example.json 复制成 aigw-prefix-cache.json,
# 按本机环境填入 tokenizer configPath 和 renderClient.baseURL。
# 期望日志:监听 8701;prefixCache LB 初始化;renderClient baseURL=...
```

- [ ] **Step 6: 注册两个 vLLM worker**

```bash
# worker 1 (HTTP 8081, ZMQ 内网 IP1:5557) — instanceIp 用容器 1 内网 IP
curl -s -X POST http://localhost:8701/aigw/v1/register-instance -H "Content-Type: application/json" \
  -d "{\"name\":\"vllm-1\",\"model\":\"Qwen2.5-7B-Instruct\",\"instanceIp\":\"$IP1\",\"port\":\"8081\",\"role\":\"mixed\"}"
# worker 2 (HTTP 8080, ZMQ 内网 IP2:5557) — instanceIp 用容器 2 内网 IP
curl -s -X POST http://localhost:8701/aigw/v1/register-instance -H "Content-Type: application/json" \
  -d "{\"name\":\"vllm-2\",\"model\":\"Qwen2.5-7B-Instruct\",\"instanceIp\":\"$IP2\",\"port\":\"8080\",\"role\":\"mixed\"}"
```
> `instanceIp`+`port` 是 vLLM HTTP 端口(供 proxy 转发到 `http://$IPx:<port>`);ZMQ 订阅端点由 aigw 据 `instanceIp` 拼 `tcp://<IP>:5557`(`manager.go:192-198`)。**因硬编码 :5557,两 worker 必须用不同内网 IP**(IP1≠IP2,见 Step 1),各自容器内绑 5557 互不冲突。proxy 转发与 ZMQ 订阅都经同一内网 IP,一致。

- [ ] **Step 7: 验证 aigw 通路**

```bash
# aigw 日志应见:ZMQ 订阅起 + 收到事件
grep -E 'ZMQ subscriber|decodeBlockStored|Starting ZMQ|render.*tokenization' /var/log/aigw/startup.log | tail
# 触发一次请求让 aigw tokenize
curl -s -X POST http://localhost:8701/v1/openai/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen2.5-7B-Instruct","messages":[{"role":"user","content":"hello"}],"max_tokens":4}' | head -c 300
```
Expected:日志见 `[render] chat tokenization: tokens=N` 与 `[kvevents] Starting ZMQ subscriber tcp://<IP>:5557`;收事件后见 `decodeBlockStored: blockSize=128`。

---

## Task 5: 端到端前缀命中验证

**Files:** 无;操作 curl + metrics。

**Interfaces:**
- Consumes: Task 4 运行中的 aigw + 两 vLLM worker + 已收的 KV 事件
- Produces: 证明前缀命中(`prefix_cache_hits_total` 增长 + 同 worker + 二次延迟降)与 fallback 行为。

- [ ] **Step 1: 直连 vLLM 预热一个长前缀**

```bash
PROMPT='请用中文详细解释前缀缓存(prefix caching)在 vLLM 中的工作原理,包括 block_size、hash 链、KV 复用、命中率影响因素。'
# 直连 worker 1 预热(让它的 KV cache 存这个前缀)
curl -s -X POST http://localhost:8081/v1/chat/completions -H "Content-Type: application/json" \
  -d "{\"model\":\"Qwen2.5-7B-Instruct\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}],\"max_tokens\":4}" -o /dev/null -w '%{http_code}\n'
# 记录预热后命中数
H0=$(curl -s http://localhost:8081/metrics | grep -E 'prefix_cache_hits_total' | grep -oE '[0-9]+$')
echo "hits_before=$H0"
```

- [ ] **Step 2: 经 aigw 发同前缀请求,应路由到 worker 1 并命中**

```bash
time curl -s -X POST http://localhost:8701/v1/openai/chat/completions -H "Content-Type: application/json" \
  -d "{\"model\":\"Qwen2.5-7B-Instruct\",\"messages\":[{\"role\":\"user\",\"content\":\"$PROMPT\"}],\"max_tokens\":4}" -o /tmp/r1.json -w 'http=%{http_code} t=%{time_total}\n'
cat /tmp/r1.json | head -c 200
# 查 aigw 日志选了哪个 worker + 命中百分比
grep -E 'matchPercent|PrefillUrl|selected instance' /var/log/aigw/startup.log | tail
```
Expected:经 aigw 请求路由到 vllm-1;aigw 日志见 matchPercent 高(接近 100,前缀整段相同);响应延迟显著低于冷启动。

- [ ] **Step 3: 验证 vLLM 侧命中数增长**

```bash
H1=$(curl -s http://localhost:8081/metrics | grep -E 'prefix_cache_hits_total' | grep -oE '[0-9]+$')
echo "hits_before=$H0 hits_after=$H1"
```
Expected:`H1 > H0`(vLLM 自身的 prefix cache 也命中,aigw 选对了 worker 让复用发生)。

- [ ] **Step 4: aigw 自身表统计**

```bash
grep -E 'TotalContexts|TotalPrefixes|TotalMappings' /var/log/aigw/startup.log | tail
```
Expected:非 0(证明 ZMQ 事件已喂进 sync table)。

- [ ] **Step 5: fallback 路径(完全不同前缀)**

```bash
time curl -s -X POST http://localhost:8701/v1/openai/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"Qwen2.5-7B-Instruct","messages":[{"role":"user","content":"zzqx unrelated random words token xyz 999"}],"max_tokens":4}' -o /dev/null -w 'http=%{http_code} t=%{time_total}\n'
```
Expected:`http=200`;aigw 日志见 matchPercent 低 → 走 leastConn fallback,无报错。

- [ ] **Step 6: 记录结果(可选提交一个验证日志)**

```bash
# 把验证输出存档(不入仓,只留证据)
cp /var/log/aigw/startup.log /tmp/aigw-e2e-$(date +%s).log
echo "e2e verification done"
```

---

## Self-Review

**Spec coverage:**
- §4a vLLM 启动参数(block_size 128 + kv-events-config + 5557)→ Task 2 ✓
- §4b adapter.go getChatPath 改动 → Task 1 ✓
- §4c 配置(env vars + aigw.json: blockSize/matchThreshold/model/loadBalancer/renderClient.baseURL/endpoint template)→ Task 4 Step 2/3 ✓
- §4d worker 注册 → Task 4 Step 6 ✓
- §6 验证(6 层)→ Task 2 Step 3(render+5557+metrics)、Task 3(ZMQ 抓包)、Task 4 Step 7(aigw tokenize+订阅)、Task 5 Step 1-4(端到端命中)、Task 5 Step 5(fallback)✓
- §7 回滚 → 各 Task 注明反向操作(stop/rm 容器、还原代码、改回 LB)✓
- §8 风险 1(vllm-ascend 是否接受 128)→ Task 2 Step 3 注明降级路径 ✓
- §8 风险 3(ExternalBlockHash 类型)→ Task 3 抓包核对 ✓

**Placeholder scan:** 无 TBD/TODO;"若 zk 强校验"等条件分支给了具体动作,非占位。

**Type consistency:** `getChatPath()` / `parseResponse` / `newVLLMAdapter` / `RenderResponse.TokenIDs` 在 Task 1 测试与实现一致;`RegisterInstanceIn` 字段(`name/model/instanceIp/port/role`)与 Task 4 Step 6 curl body 一致(`internal/base/aigw_type.go:37-46`)。

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-04-aigw-prefix-cache-vllm-integration.md`. Two execution options:

1. **Subagent-Driven (recommended)** - 每个 Task 派新 subagent 执行,任务间我 review,迭代快。
2. **Inline Execution** - 本会话内顺序执行,带 checkpoint review。

Which approach?
