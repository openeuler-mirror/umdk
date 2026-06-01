# CAM

 **CAM**  is short for  **C**ommunication  **A**cceleration for  **M**atrix on Ascend NPU. CAM provides EP (Expert Parallelism) communication kernels, high performance KVCache transfer for PD disaggregation and KVC pooling, AFD communication kernels, RL weights transfer and so on. CAM is easily to be run in single kernel mode or integrated into vllm or SGLang framework. 

# Roadmap

- [x]  **EP Communication: Dispatch & Combine** 
  - [x] Support A2
  - [x] Support A3
  - [ ] Support low latency mode
  - [x] Support high throughput mode
  - [ ] Support BF16/FP16 input
  - [x] Support SHMEM
- [x]  **FusedDeepMoE: Dispatch + GEMM + Combine** 
  - [ ] Support A2
  - [x] Support A3
  - [x] Support low latency mode
  - [ ] Support high throughput mode
  - [ ] Support BF16/FP16 input
  - [x] Support W8A8 for GEMM
  - [ ] Support W4A8 for GEMM
- [ ]  **KVCache Transfer** 
- [ ]  **RL Weights Transfer** 
- [ ]  **AFD Communication**
 
# Performance
(To be done)

# Directory Structures
```text
UMDK/
|--- build/
|    |--- cam/                      # build script for cam project
|    |    |--- comm_operator/       # build script for cam communication operator
|--- doc/
|    |--- ch/  
|    |    |--- cam/                 # cam doc in Chinese
|    |--- en/  
|    |    |--- cam/                 # cam doc in English
|--- src/
|    |--- cam/  
|    |    |--- comm_operator/       # code of communication operator
|    |    |    |--- ascend_kernels/ # code of ascend kernels
|    |    |    |--- pybind/         # code of python interface bindings
|    |    |--- examples/            # examples for different kernels
|    |    |--- third_party/         # third party dependencies (git submodules)
|    |    |    |--- catlass/        # catlass (git submodule, pinned commit)
|--- test/
|    |--- cam/                      # UT test code of cam
```

# Quick Start
## 1. Basic Environment Requirements
|Requirements|Type|Version|Description|
|---|---|---|---|
|Ascend Chip|Required|A2/A3|You can run CAM now only in an Ascend A2 or A3 SuperPod.|
|CANN|Required|8.3/8.5/9.0|Before using CAM, you need to install CANN 8.3, 8.5 or 9.0 to offer basic toolkit functions. Please refer to “[Huawei Ascend-CANN](https://www.hiascend.com/cann)” and install CANN first.|
|Torch|Required|2.8.0|To compile Pybind whl packet in CAM, you need to install Torch first.|
|Torch-Npu|Required|2.8.0 post1~post4|Torch-Npu version depends on CANN version. See `docker/cam/Dockerfile` for the matched wheel of each CANN preset.|
|gtest|Required|1.16.0|gtest is used for UT.|
|OpenMPI|Required|5.0.7|MPI interfaces are used for multi-thread tests.|
|Ascend-SHMEM|Optional|1.3.0|If you want to compile and run SHMEM kernels, you need to install Ascend-SHMEM first. Please refer to "[Huawei Ascend-SHMEM](https://gitcode.com/cann/shmem)".

For quickly start, we support a docker compose file sample in "umdk/docker/cam" folder. In ubuntu system with aarch64 architecture, you can build the image first:
```bash
cd umdk
docker build --build-arg BUILD_ARG=a3_9.0_open -t cam-dev:a3_9.0_open -f docker/cam/Dockerfile .
```
Supported `BUILD_ARG` values: `a3_8.3_open`, `a3_8.5_open`, `a3_9.0_open`. The `BUILD_ARG` must match `IMAGE_NAME` in `.env`.

Then change `COMPOSE_PROJECT_NAME`, `IMAGE_NAME` and `CONTAINER_NAME` in `docker/cam/.env` if needed, and run:
```bash
cd docker/cam
docker compose up -d
```
to create a runnable docker container quickly. Other system configurations may need to modify some commands to fit.

## 2. Compile and Install
### · Compile
CAM offers a basic ".run" packet for kernels and a ".whl" packet for python interface. You can easily compile these two packets with the command below:
```bash
# enter UMDK folder
cd UMDK/
# initialize git submodules (catlass, etc.)
git submodule update --init --recursive
# build
./build/cam/build.sh
```
To enable debug mode, use the following command instead:
```bash
./build/cam/build.sh -d
```
If we get final output like `Build packet successful!`, then we can find the two packets in:
```bash
# whl packet, XXX depends on the compile environment.
output/cam/comm_operator/dist/umdk_cam_op_lib_XXX.whl
# run packet, XXX depends on the compile environment.
output/cam/comm_operator/run/cam_ascend910XXX.run
```
### · Install
To install these two packets, you may follow the commands below:
```bash
# Step 1: install run packet. The recommended install path is the opp folder in your environment.
./output/cam/comm_operator/run/cam_ascend910XXX.run --install-path=/usr/local/Ascend/ascend-toolkit/latest/opp
# Step 2: enable environment variables. The path is provided from the output that you install run packet. 
source /usr/local/Ascend/ascend-toolkit/lateset/opp/vendors/CAM/bin/set_env.bash
# Step 3: install whl packet.
pip install --force-reinstall ./output/cam/comm_operator/dist/umdk_cam_op_lib_XXX.whl
```