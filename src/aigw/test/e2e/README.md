# AIGW E2E 测试目录

本目录包含 AIGW 端到端测试的完整工具集:

## 文件说明

- `benchmark_e2e.sh` - 综合 benchmark 脚本，自动启动 mock 服务和 AIGW，运行测试，最后清理进程
- `verify_e2e.sh` - 验证脚本，单独测试 mock 服务和 AIGW 的基本功能
- `mock_e2e_server.py` - Mock 服务，模拟 Kubernetes API 和后端 DP Worker
- `test_e2e_client.py` - 测试客户端，测试 AIGW 的调度和转发功能
- `test_config.json` - AIGW 测试配置文件

## 快速开始

### 运行 Benchmark

```bash
cd test/e2e
./benchmark_e2e.sh
```

## 测试说明

### Benchmark 测试项
| 测试项 | 说明 |
|--------|------|
| Mock K8s 启动 | 自动启动 mock Kubernetes API 服务和 Worker 后端 |
| Mock Worker 启动 | 自动启动 mock DP Worker 服务 ( 端流式响应支持 |
| AIGW 启动 | 自动启动 AIGW 并使用测试配置 |
| 测试客户端 | 测试 AIGW 的调度建议获取、请求转发，流式响应处理 |
| 验证脚本 | 验证 mock 服务和 AIGW 的基本功能 |
| 清理进程 | 测试完成后自动清理启动的进程 |

### 预期结果
- 所有验证项通过 ( 13 通过 / 0 失败
- 测试客户端分项结果: 4 通过 / 2 失败
  - health: 通过 ( 健康检查成功
  - suggestion: 通过 ( 获取调度建议成功
  - forward_stream: 通过 ( 流式转发成功
  - forward_non_stream: 失败 ( 非流式转发失败
  - hash_affinity: 通过 ( 一致性 Hash 亲和性测试通过
  - dp_rank: 失败 ( DP Rank header 注入测试失败)

## 已解决问题
1. **tokenizer 配置**: 修正了 configPath 指向正确的 tokenizer 文件路径
2. **UUID 字段**: 在测试客户端请求中添加 uuid 字段, 修正长度为 0 的问题
3. **consistentHash LB**: 在 `gs_manager_opts.go` 中添加 `consistentHash` case 支持

## 待解决问题
1. **非流式转发**: 非流式请求返回 500 错误,需检查 AIGW 和 Worker 日志
2. **DP Rank 注入**: DP Rank header 测试返回空列表,需检查 AIGW 转发逻辑
