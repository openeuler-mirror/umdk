# AIGW - AI推理网关

<div align="center">

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-Proprietary-red)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)

**高性能 · 智能调度 · 企业级**

</div>

---

## 简介

AIGW (AI Gateway) 是一个企业级的大语言模型推理网关，专为大规模LLM推理场景设计。它提供智能调度、负载均衡、缓存管理等核心能力，为AI推理服务提供高性能、高可用的支撑。

### 核心价值

- **极致性能**：通过智能调度和缓存优化，显著降低推理延迟
- **灵活部署**：支持独立服务和共享库两种部署模式，适应不同场景
- **高可用性**：多实例部署、自动故障转移，保障服务稳定运行
- **易于集成**：提供C API和RESTful接口，轻松集成到现有系统

---

## 功能特性

### 🚀 核心能力

| 功能 | 描述 |
|------|------|
| **智能调度** | 支持Token、时间感知、容量等多种负载均衡策略 |
| **智能路由** | 区分prefill和decode阶段，实现上下文感知的请求分发 |
| **缓存管理** | Redis和本地缓存双重缓存机制，有效降低重复请求开销 |
| **延迟预测** | 基于LightGBM和EMA算法的机器学习预测，优化调度决策 |
| **服务发现** | 集成ZooKeeper实现实例注册与发现 |
| **监控告警** | 内置统计、日志和告警系统，实时掌握服务状态 |
| **多模型支持** | 支持同时管理多个大语言模型，灵活切换 |
| **分词器集成** | 集成HuggingFace Tokenizers实现高效文本分词 |

### 🛡️ 安全与可靠性

- **安全通信**：支持HMAC、AES-GCM、TLS等多种安全机制
- **健康检查**：自动检测实例健康状态，及时剔除故障节点
- **限流保护**：支持请求限流，防止服务过载

---

## 技术架构

### 技术栈

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │
│  │  RESTful API │  │   C API      │  │  监控面板 │ │
│  └──────────────┘  └──────────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      网关层 (Go)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │ 调度器   │ │ 负载均衡 │ │ 缓存中心 │ │ 监控   │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘ │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      基础设施层                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │ ZooKeeper │ │  Redis   │ │ LightGBM │ │ 日志   │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 多语言支持

| 语言 | 用途 |
|------|------|
| **Go** | 核心业务逻辑、HTTP服务、调度算法 |
| **Rust** | 高性能分词器（通过FFI集成） |
| **C/C++** | CGO共享库、缓存驱动接口 |
| **Python** | LightGBM模型训练、HuggingFace Tokenizers |

---

## 项目结构

```
AIGW/
├── cmd/                        # 命令行入口
│   └── aigw/
│       └── main.go           # 主程序入口
├── internal/                   # 内部包
│   ├── core/                 # 核心管理器
│   ├── gs/                   # 全局调度器
│   ├── cachecenter/          # 缓存中心
│   ├── server/               # HTTP服务器
│   ├── zk/                   # ZooKeeper集成
│   ├── tokenizers/           # 分词器
│   ├── vectorizer/           # 特征向量化
│   ├── alarmmonitor/          # 告警监控
│   ├── modelmonitor/         # 模型监控
│   └── stats/               # 统计模块
├── pkg/                        # 公共包
│   ├── lightgbm/             # LightGBM集成
│   ├── latencyprediction/    # 延迟预测
│   ├── log/                  # 日志模块
│   ├── crypto/               # 加密模块
│   ├── sock/                 # Socket通信
│   └── utils/                # 工具函数
├── src/                        # CGO源码
│   └── libaigw.go          # C API实现
├── include/                    # C API头文件
│   └── aigw.h             # C API接口定义
├── example/                    # 示例代码
│   ├── cgo/                 # C语言示例
│   └── CMakeLists.txt       # 示例构建配置
├── configs/                    # 配置文件
│   └── aigw.json           # 主配置文件
├── build/                      # 构建脚本
├── open_source/                # 第三方依赖
└── output/                     # 构建输出
```

---

## 快速开始

### 环境要求

| 组件 | 版本要求 | 说明 |
|------|----------|------|
| Go | 1.21+ | 核心开发语言 |
| Rust | 1.70+ | 分词器编译 |
| CMake | 3.10+ | 构建工具 |
| GCC/Clang | - | C/C++编译器 |
| Python | 3.8+ | LightGBM模型训练（可选） |
| ZooKeeper | 3.5+ | 服务发现（必需） |
| Redis | 5.0+ | 缓存服务（可选） |

### 构建项目

```bash
# 基础构建
./build.sh

# 带单元测试构建
./build.sh --ut

# 调试模式构建
./build.sh --debug

# 清理构建产物
./build.sh --clean
```

### 构建选项

| 选项 | 说明 |
|------|------|
| `--coverage` | 启用代码覆盖率 |
| `--debug` | 启用调试编译 |
| `--fuzz` | 启用模糊测试 |
| `--ut` | 启用单元测试 |
| `--at` | 启用集成测试 |
| `--rpm` | 构建RPM包 |
| `--version` | 指定版本号 |
| `--release` | 指定发布号 |
| `--notest` | 移除所有测试文件 |
| `--tsan` | 启用线程安全检查 |
| `--clean` | 清理构建产物 |

### 运行服务

```bash
# 作为独立服务运行
./output/aigw --config=/etc/aigw/conf/aigw.json
```

---

## 配置说明

配置文件采用JSON格式，主要包含以下部分：

### 全局配置

```json
{
  "global": {
    "host": "",                    // 监听地址
    "port": "",                    // 监听端口
    "logPath": "/var/log/aigw",  // 日志路径
    "logLevel": "info",           // 日志级别: debug/info/warn/error
    "reqTimeout": 600             // 请求超时时间（秒）
  }
}
```

### ZooKeeper配置

```json
{
  "zookeeper": {
    "address": "",                          // ZooKeeper地址
    "inferenceInstancePath": "/mep/aigw/instances",
    "scheduleServicePath": "/mep/aigw/global_schedulers",
    "enableTls": false,                   // 是否启用TLS
    "tlsCaFile": "",                      // CA证书路径
    "tlsCrtFile": "",                    // 客户端证书路径
    "tlsKeyFile": ""                      // 客户端私钥路径
  }
}
```

### 全局调度器配置

```json
{
  "globalSchedulers": [
    {
      "model": "DeepSeek-R1-Distill-Qwen-7B",
      "blockSize": 128,
      "deployPolicy": "separated",         // 部署策略: mixed/separated
      "maxTimeToFirstToken": 200,        // 首token最大延迟（ms）
      "maxTimeBetweenTokens": 50,         // token间最大延迟（ms）
      "tokenizeModelName": "DeepSeek-R1",
      "loadBalancer": {
        "prefill": "prefillTimeAware",   // prefill负载均衡策略
        "decode": "token",               // decode负载均衡策略
        "batchSize": 32,
        "reservedBlockNumber": 50
      }
    }
  ]
}
```

### 负载均衡策略

| 策略 | 适用场景 | 说明 |
|------|----------|------|
| `roundRobin` | 通用场景 | 轮询分配请求 |
| `leastConn` | 长连接场景 | 选择连接数最少的节点 |
| `capacity` | 资源敏感场景 | 基于节点容量分配 |
| `token` | Token敏感场景 | 基于Token数量分配 |
| `prefillTimeAware` | Prefill阶段 | 预填充时间感知调度 |
| `decode` | Decode阶段 | 解码阶段专用策略 |

---

## C API 使用指南

### 初始化

```c
#include "aigw.h"

// 配置AIGW
aigw_config_t cfg = {
    .log_level = "info",
    .log_path = "/tmp",
    .max_instances_per_model = 128,
    .max_supported_models = 128,
    .max_prompt_length = 20480,
    .request_ttl_seconds = 600
};

// 初始化
aigw_error_t err = aigw_init(&cfg);
if (err != AIGW_SUCCESS) {
    // 处理错误
}
```

### 注册模型

```c
aigw_model_config_t model_cfg = {
    .model = "qwen-72b",
    .deploy_policy = AIGW_DEPLOY_SEPARATED,
    .p_lb_type = AIGW_LB_PREFILL_TIME_AWARE,
    .d_lb_type = AIGW_LB_TOKEN_AWARE,
    .pretrain_ttft_path = "/path/to/ttft_model.txt",
    .tokenization_ratio = 0.35
};

err = aigw_register_model(&model_cfg);
```

### 节点选择

```c
// 定义候选节点
aigw_node_info_t nodes[] = {
    {.role = AIGW_INFER_PREFILL, .node_addr = "192.168.1.10:8080"},
    {.role = AIGW_INFER_DECODE, .node_addr = "192.168.1.11:8080"}
};

// 构建请求
aigw_openai_message_t msg = {.role = "user", .content = "Hello"};
aigw_request_t req = {
    .uuid = "req-001",
    .model = "qwen-72b",
    .messages = &msg,
    .message_num = 1
};

// 选择节点
aigw_select_context_t ctx = {
    .node_num = 2,
    .node_list = nodes
};

aigw_select_result_t result = {0};
err = aigw_select_nodes(&req, &ctx, &result);

if (err == AIGW_SUCCESS) {
    printf("Prefill: %s, Decode: %s\n",
           result.prefill_node_addr, result.decode_node_addr);
}
```

### 事件通知

```c
aigw_event_info_t event = {
    .model = "qwen-72b",
    .request_id = "req-001",
    .event_name = "REQUEST_IS_FINISHED"
};

err = aigw_notify_event(AIGW_EVENT_REQUEST, &event);
```

### 清理资源

```c
aigw_unregister_model("qwen-72b");
aigw_uninit();
```

---

## 部署模式

### 独立服务模式

作为HTTP服务器运行，提供RESTful API接口：

```bash
./aigw --config=/etc/aigw/conf/aigw.json
```

**适用场景**：
- 需要独立部署推理网关服务
- 多个应用共享推理网关
- 需要远程访问推理服务

### 共享库模式

通过C API嵌入其他应用：

```c
#include "aigw.h"

// 在应用中初始化并使用AIGW
aigw_init(&cfg);
// ... 使用AIGW功能
aigw_uninit();
```

**适用场景**：
- 需要将推理网关集成到现有应用
- 对性能有极致要求
- 需要更紧密的集成

---

## 示例代码

完整示例代码位于 `example/cgo/` 目录，演示了：

- AIGW初始化和配置
- 缓存驱动注册
- 模型注册和管理
- 并发请求处理
- 节点选择和负载均衡
- 事件通知

### 构建示例

```bash
cd example
mkdir build && cd build
cmake ..
make
./aigw_test_demo
```

---

## 性能特性

| 指标 | 说明 |
|------|------|
| **高并发** | 支持数千并发推理请求 |
| **低延迟** | 智能调度优化首token延迟 |
| **高可用** | 多实例部署，自动故障转移 |
| **可扩展** | 水平扩展支持，动态实例注册 |

---

## 常见问题

### Q: AIGW支持哪些大语言模型？

A: AIGW支持所有兼容OpenAI API格式的大语言模型，包括但不限于：
- DeepSeek系列
- Qwen系列
- LLaMA系列
- ChatGLM系列

### Q: 如何配置多个模型？

A: 在配置文件的 `globalSchedulers` 数组中添加多个模型配置即可。

### Q: 缓存是必须的吗？

A: 不是必须的。Redis缓存是可选的，不配置时系统仍可正常运行，只是无法享受缓存带来的性能提升。

### Q: 如何监控AIGW的运行状态？

A: AIGW提供内置的监控接口，可以通过HTTP API查询服务状态、实例信息、请求统计等数据。

---

## 开源依赖

本项目集成了以下开源组件：

| 组件 | 许可证 | 用途 |
|------|--------|------|
| [LightGBM](https://github.com/microsoft/LightGBM) | MIT | 梯度提升决策树框架 |
| [Eigen](https://eigen.tuxfamily.org/) | MPL2.0 | C++模板库，用于线性代数运算 |
| [compute](https://github.com/kth-competitive-programming/kactl) | MIT | 计算几何库 |
| [fast_double_parser](https://github.com/lemire/fast_double_parser) | BSD-3 | 快速浮点数解析 |
| [fmt](https://github.com/fmtlib/fmt) | MIT | C++格式化库 |

---

## 许可证

Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.

---

## 贡献

欢迎提交Issue和Pull Request来帮助改进项目。在提交代码前，请确保：

1. 代码通过所有单元测试
2. 代码符合项目编码规范
3. 添加必要的注释和文档

---

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交Issue：[GitHub Issues](https://github.com/your-repo/aigw/issues)
- 发送邮件：[your-email@example.com]

---

<div align="center">

**Made with ❤️ by AIGW Team**

</div>
