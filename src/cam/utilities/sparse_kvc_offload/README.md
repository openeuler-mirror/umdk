# Sparse KVCache Offload (DeepSeek-V3.2-Exp)

## 概述

本目录是 UMDK **CAM**（Communication Acceleration for Matrix）下的 **稀疏 KVCache Offload** 特性，面向 DeepSeek-V3.2-Exp 的 DSA（DeepSeek Sparse Attention）结构，把占比较高的 MLA Full KVCache 从设备内存卸载到 Host 内存，从而在长序列场景下释放设备内存压力、提升可支持的 batch size。

该能力从 [cann-recipes-infer](https://gitcode.com/cann/cann-recipes-infer) 迁移而来，并整理为一套可在 UMDK 仓内**端到端运行**的自包含栈（模型 + runner + 配置 + 必要的框架子集），运行在华为 Atlas A3 集群上。

- KVCache Offload 的方案设计（Prefill 单层 KVCache + 多流 D2H、Decode 阶段 `GatherSelectionKvCache` 按 TopK 从 Host 侧聚合）可参考上游文档 [NPU DeepSeek-V3.2-Exp 推理优化实践](https://gitcode.com/cann/cann-recipes-infer/blob/master/docs/models/deepseek-v3.2-exp/deepseek_v3.2_exp_inference_guide.md) 的 “KVCache Offload” 章节。
- CAM 组件整体介绍与算子构建见 [CAM README](../../README.md)。

> 本特性依赖 CAM 自定义算子库 `umdk_cam_op_lib`（其中需提供 `gather_selection_kv_cache` 等算子）。代码中通过 `import umdk_cam_op_lib` 注册算子，运行前请确保该 whl 已构建并安装（见下文“构建并安装 CAM 算子库”）。

---

## 硬件与环境要求

产品型号：Atlas A3 系列

操作系统：Linux ARM

镜像版本：cann8.5_pt2.6.0_dsv3.2_aarch_image:v0.7

驱动版本：Ascend HDK 25.2.0

> 通过 `npu-smi info` 检查 Ascend NPU 固件和驱动是否正确安装。如果未安装或版本不是 25.2.0，请先下载[固件和驱动包](https://www.hiascend.com/hardware/firmware-drivers/community?product=7&model=33&cann=All&driver=Ascend+HDK+25.2.0)，然后根据[指导](https://hiascend.com/document/redirect/CannCommunityInstSoftware)自行安装。

---

## 快速启动

### 下载源码

在各个节点上克隆 UMDK 源码，本特性位于 `src/cam/utilities/sparse_kvc_offload`。

```shell
mkdir -p /home/code; cd /home/code/
git clone https://gitcode.com/openeuler/umdk.git
cd umdk/src/cam/utilities/sparse_kvc_offload
```

### 下载数据集

从[链接](https://huggingface.co/datasets/xinrongzhang2022/InfiniteBench/blob/main/longbook_qa_eng.jsonl)中下载长序列输入数据集 longbook_qa_eng，并上传到各个节点上新建的路径 `dataset/InfiniteBench` 下。

```shell
mkdir -p dataset/InfiniteBench
```

### 下载权重

下载 [DeepSeek-V3.2-Exp 原始 fp8 权重](https://huggingface.co/deepseek-ai/DeepSeek-V3.2-Exp)，并上传到 Atlas A3 各节点某个固定的路径下，比如 `/data/models/DeepSeek-V3.2-Exp-fp8`。

### 获取 docker 镜像

从 [ARM 镜像地址](https://cann-ai.obs.cn-north-4.myhuaweicloud.com/cann-quantization/DeepSeek-V3.2-Exp/cann8.5_pt2.6.0_dsv3.2_aarch_image_v0.7.tar) 下载 docker 镜像，上传到 A3 服务器每个节点，并导入镜像 `docker load -i cann8.5_pt2.6.0_dsv3.2_aarch_image_v0.7.tar`。

### 拉起 docker 容器

在各个节点上通过如下脚本拉起容器，默认容器名为 `umdk_sparse_kvc_offload`。注意：需要将权重路径和源码路径挂载到容器里。

```shell
docker run -u root -itd --name umdk_sparse_kvc_offload --ulimit nproc=65535:65535 --ipc=host \
    --device=/dev/davinci0     --device=/dev/davinci1 \
    --device=/dev/davinci2     --device=/dev/davinci3 \
    --device=/dev/davinci4     --device=/dev/davinci5 \
    --device=/dev/davinci6     --device=/dev/davinci7 \
    --device=/dev/davinci8     --device=/dev/davinci9 \
    --device=/dev/davinci10    --device=/dev/davinci11 \
    --device=/dev/davinci12    --device=/dev/davinci13 \
    --device=/dev/davinci14    --device=/dev/davinci15 \
    --device=/dev/davinci_manager --device=/dev/devmm_svm \
    --device=/dev/hisi_hdc \
    -v /home/:/home \
    -v /data:/data \
    -v /etc/localtime:/etc/localtime \
    -v /usr/local/Ascend/driver:/usr/local/Ascend/driver \
    -v /etc/ascend_install.info:/etc/ascend_install.info -v /var/log/npu/:/usr/slog \
    -v /usr/local/bin/npu-smi:/usr/local/bin/npu-smi -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v /usr/local/dcmi:/usr/local/dcmi -v /usr/local/sbin:/usr/local/sbin \
    -v /etc/hccn.conf:/etc/hccn.conf -v /root/.pip:/root/.pip -v /etc/hosts:/etc/hosts \
    -v /usr/bin/hostname:/usr/bin/hostname \
    --net=host \
    --shm-size=128g \
    --privileged \
    cann8.5_pt2.6.0_dsv3.2_aarch_image:v0.7 /bin/bash
```

在各个节点上通过如下命令进入容器：

```shell
docker attach umdk_sparse_kvc_offload
cd /home/code/umdk/src/cam/utilities/sparse_kvc_offload
```

### 构建并安装 CAM 算子库

本特性通过 `import umdk_cam_op_lib` 注册所需自定义算子（如 `gather_selection_kv_cache`）。请先按 [CAM README](../../README.md) 构建并安装算子库：

```shell
# 在 UMDK 仓根目录构建 CAM 算子（whl + run 包），SOC 以实际环境为准
./build/cam/build.sh -c ascend910_93

# 安装 run 包与算子环境变量
./output/cam/comm_operator/run/CAM_<soc>_<os>_<arch>.run --install-path=/usr/local/Ascend/ascend-toolkit/latest/opp
source /usr/local/Ascend/ascend-toolkit/latest/opp/vendors/CAM/bin/set_env.bash

# 安装 python 侧算子库
pip install --force-reinstall ./output/cam/comm_operator/dist/umdk_cam_op_lib_XXX.whl
```

### 转换权重

在各个节点上使用 `utils/weight_convert.sh` 完成 FP8 到 Bfloat16/Int8 权重转换。

> 入参介绍：`input_fp8_hf_path`：原始 fp8 权重路径；`output_hf_path`：转换后输出的权重路径；`quant_mode`：量化模式

如果权重转换的运行环境为 NPU，需要先执行：

```shell
cann_path=/usr/local/Ascend/ascend-toolkit/latest  # cann 包安装路径
source ${cann_path}/bin/setenv.bash
```

权重转换拉起示例：

```shell
# 转换为 Bfloat16 权重
bash utils/weight_convert.sh --input_fp8_hf_path /data/models/DeepSeek-V3.2-Exp-FP8 --output_hf_path /data/models/DeepSeek-V3.2-Exp-Bfloat16 --quant_mode bfloat16

# 转换为 W8A8C16 权重
bash utils/weight_convert.sh --input_fp8_hf_path /data/models/DeepSeek-V3.2-Exp-FP8 --output_hf_path /data/models/DeepSeek-V3.2-Exp-W8A8C16 --quant_mode w8a8c16

# 转换为 W8A8C8 权重
bash utils/weight_convert.sh --input_fp8_hf_path /data/models/DeepSeek-V3.2-Exp-FP8 --output_hf_path /data/models/DeepSeek-V3.2-Exp-W8A8C8 --quant_mode w8a8c8

# 转换为 W4A8C8 权重
bash utils/weight_convert.sh --input_fp8_hf_path /data/models/DeepSeek-V3.2-Exp-FP8 --output_hf_path /data/models/DeepSeek-V3.2-Exp-W4A8C8 --quant_mode w4a8c8
```

### 修改配置

- 在各个节点上修改 `set_env.sh` 中的 IPs。

  ```shell
  export IPs=('xxx.xxx.xxx.xxx' 'xxx.xxx.xxx.xxx') # 所有节点的 IP，确保第 1 个 IP 是 master，多个节点的 ip 通过空格分开
  ```

- 在各个节点上修改 `config/` 路径下需要执行的 yaml 文件中的 `model_path`。关于 YAML 文件中的更多配置说明可参见 [YAML 参数描述](./config/README.md)。

  ```
  # BF16
  model_path: "/data/models/DeepSeek-V3.2-Exp-Bfloat16"
  # W8A8C16
  model_path: "/data/models/DeepSeek-V3.2-Exp-W8A8C16"
  # W8A8C8
  model_path: "/data/models/DeepSeek-V3.2-Exp-W8A8C8"
  ```

- 若要开启 KVCache Offload，请选择带 `offload` 的配置（如 `config/deepseek_v3.2_exp_rank_128_128ep_w8a8c8_offload_benchmark.yaml`），或在 yaml 中将 `model_config.enable_offload` 置为 `True`。

- 在各个节点上修改 `infer.sh` 中的 `YAML_FILE_NAME`，指定为上一步需要执行的 yaml 文件名。

  ```
  # W8A8C8 + KVCache Offload
  export YAML_FILE_NAME=deepseek_v3.2_exp_rank_128_128ep_w8a8c8_offload_benchmark.yaml

  # W8A8C8 prefill / decode（未开启 offload）
  export YAML_FILE_NAME=deepseek_v3.2_exp_rank_64_64ep_w8a8c8_prefill_benchmark.yaml
  export YAML_FILE_NAME=deepseek_v3.2_exp_rank_128_128ep_w8a8c8_decode_benchmark.yaml
  ```

  > **Note**: 可在对应 yaml 文件中修改 `world_size` 配置以适配不同卡数。

### 拉起多卡推理

在各个节点上同步执行如下命令即可拉起多卡推理任务。

```shell
bash infer.sh
```

---

## 附录

### FAQ

- **自定义算子导入失败**：如果报错日志中出现类似 `'_OpNamespace' object has no attribute 'gather_selection_kv_cache'` 或 `import umdk_cam_op_lib` 失败等关键字，说明 CAM 算子库未正确构建/安装，请参考 [CAM README](../../README.md) 重新构建并安装 `umdk_cam_op_lib`。
- **HCCL_BUFFSIZE 不足问题**：如果报错日志中出现关键字 "HCCL_BUFFSIZE is too SMALL, ..., NEEDED_HCCL_BUFFSIZE..., HCCL_BUFFSIZE=200MB, ..."，可通过配置环境变量 `export HCCL_BUFFSIZE=实际需要的大小` 解决，所有 Rank 上的该环境变量需保持一致。HCCL_BUFFSIZE 参数介绍可参考[昇腾资料](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/83RC1alpha003/maintenref/envvar/envref_07_0080.html)中的详细描述。
