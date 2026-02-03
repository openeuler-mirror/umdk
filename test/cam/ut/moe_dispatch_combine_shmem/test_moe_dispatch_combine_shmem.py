#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: UT for dispatch/combine shmem op
# Create: 2026-01-14
# Note:
# History: 2026-01-14 create file
#

import pytest
import torch
import torch_npu
import numpy as np
import torch.distributed as dist
import torchair
from torchair.configs.compiler_config import CompilerConfig
from collections import defaultdict
import os
import math
import random
import socket
# cam torch安装包
import umdk_cam_op_lib
import shmem as shm
shm.set_conf_store_tls(False, "") # 关闭tls认证

from ..util import tool
# 必要夹具 导入即生效
from ..util.marker import Author
from ..util.marker import MPTest
from ..util.marker import A3Test
from ..util.marker import SKIP_ENV_RANKSIZE_UNEQUAL

class Module(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(self, expandX, expertIds, scales, shmPtr, world_size, rank, totalExpertNum, sharedExpertRankNum, sharedExpertNum, expertScales):
        output = torch.ops.umdk_cam_op_lib.moe_dispatch_shmem(
            x=expandX,
            expert_ids=expertIds,
            scales=None,
            x_active_mask=None,
            ep_world_size=world_size,
            ep_rank_id=rank,
            moe_expert_num=(totalExpertNum - sharedExpertNum),
            tp_world_size=1,
            tp_rank_id=0,
            expert_shard_type=0,
            shared_expert_num=1,
            shared_expert_rank_num=sharedExpertRankNum,
            quant_mode=0,
            global_bs=0,
            expert_token_nums_type=0,
            ext_info=shmPtr
        )

        expandXOut, dynamicScalesOut, expandIdxOut, expertTokenNumsOut, epSendCountOut, tpSendCountOut = output[0:6]
        # 构造暂时不支持的参数
        x_active_mask = None
        activation_scale = None
        weight_scale = None
        group_list = None
        expand_scales = None
        moe_expert_num = totalExpertNum - sharedExpertRankNum
        tp_world_size = 1
        tp_rank_id = 0
        expert_shard_type = 0
        global_bs = 0
        out_dtype = 0
        comm_quant_mode = 0
        group_list_type = 0
        shared_expert_num = 1
        
        output1 = torch.ops.umdk_cam_op_lib.moe_combine_shmem(
            expand_x=expandXOut,
            expert_ids=expertIds,
            expand_idx=expandIdxOut,
            ep_send_counts=epSendCountOut,
            expert_scales=expertScales,
            tp_send_counts=tpSendCountOut,
            x_active_mask=x_active_mask,
            activation_scale=activation_scale,
            weight_scale=weight_scale,
            group_list=group_list,
            expand_scales=expand_scales,
            ep_world_size=world_size,
            ep_rank_id=rank,
            moe_expert_num=moe_expert_num,
            tp_world_size=tp_world_size,
            tp_rank_id=tp_rank_id,
            expert_shard_type=expert_shard_type,
            shared_expert_num=shared_expert_num,
            shared_expert_rank_num=sharedExpertRankNum,
            global_bs=global_bs,
            comm_quant_mode=comm_quant_mode,
            ext_info=shmPtr,
            out_dtype=out_dtype,
            group_list_type=group_list_type)
        return output1

def gen_x(rank, batchSize, hidden_size):
    arr = [rank * batchSize + i + 1 for i in range(batchSize) for j in range(hidden_size)]
    return arr

def gen_expert_ids(rank, batchSize, topk, worldSize, sharedExpertNum):
    arr = [0] * (batchSize * topk)
    for i in range(batchSize):
        for j in range(topk):
            arr[i * topk + j] = (rank + i + j) % (worldSize - sharedExpertNum)
    return arr

def gen_scales(batchSize, topk):
    arr = [0.0] * (batchSize * topk)

    for i in range(batchSize):
        sum_val = 0.0
        for j in range(topk):
            distribution = random.uniform(1, 10)
            arr[i * topk + j] = distribution
            sum_val += arr[i * topk + j]
        for j in range(topk):
            arr[i * topk + j] /= sum_val
    return arr

def gen_dispatch_input(rank, batchSize, topk, hiddenSize, worldSize, sharedExpertNum):
    expandX_list = gen_x(rank, batchSize, hiddenSize)
    expert_id_list = gen_expert_ids(rank, batchSize, topk, worldSize, sharedExpertNum)
    expandX = np.array(expandX_list, dtype=float)
    expandX = expandX.reshape(-1, hiddenSize)
    expertIds = np.array(expert_id_list, dtype=np.int32)
    expertIds = expertIds.reshape(batchSize, topk)
    return expandX, expertIds

CASE_16RANK = {
    "totalExpertNum": 16,
    "sharedExpertNum": 2,
    "topk": 8,
    "batchSize": 32,
    "hiddenSize": 7168,
}
CASE_4RANK = {
    "totalExpertNum": 4,
    "sharedExpertNum": 1,
    "topk": 1,
    "batchSize": 32,
    "hiddenSize": 7168,
}
CASE_8RANK = {
    "totalExpertNum": 8,
    "sharedExpertNum": 1,
    "topk": 4,
    "batchSize": 32,
    "hiddenSize": 7168,
}
is_encode_utf8=True

@MPTest # 用例类型，此处代表多进程测试例
@A3Test
@SKIP_ENV_RANKSIZE_UNEQUAL(16) # RankSize不为期望的16时，跳过此用例
@pytest.mark.parametrize("mode", ['Eager'])
def test_base_test(mode):
    # 图模式无法获得算子覆盖率故提前退出
    if mode == "GE" and tool.is_run_for_cov():
        return
    # 通过工具方法获得rank和ranksize
    rank = tool.get_rank()
    worldSize = tool.get_world_size()

    case = CASE_16RANK
    totalExpertNum = case["totalExpertNum"]
    sharedExpertNum = case["sharedExpertNum"]
    sharedExpertRankNum = case["sharedExpertNum"]
    topk = case["topk"]
    hiddenSize = case["hiddenSize"]
    batchSize = case["batchSize"]
    quant = False
    dataType = torch.float16

    # expandX
    expandXData = np.array(gen_x(rank, batchSize, hiddenSize))
    expandXData = expandXData.reshape(batchSize, hiddenSize)
    expandXTensor = torch.tensor(expandXData, dtype=dataType, device='npu')

    # expertIds
    expertIdsData = np.array(gen_expert_ids(rank, batchSize, topk, worldSize, sharedExpertNum))
    expertIdsData = expertIdsData.reshape(batchSize, topk)
    expertIdsTensor = torch.tensor(expertIdsData, dtype=torch.int32, device='npu')

    # scales当前未使用
    scalesTensor = None

    scalesData = np.array(gen_scales(batchSize, topk))
    scalesData = scalesData.reshape(batchSize, topk)
    expertScalesTensor = torch.tensor(scalesData, dtype=torch.float, device='npu')

    if mode == "Eager":
        mod = Module().npu()
    elif mode == "GE":
        torch_npu.npu.set_compile_mode(jit_compile=True)
        config = CompilerConfig()
        npu_backend = torchair.get_npu_backend(compiler_config=config)
        mod = torch.compile(Module().npu(), backend=npu_backend)

    ep_ranks_list = list(np.arange(0, worldSize))

    # shmem init
    ipPort = "tcp://127.0.0.1:8666"
    localMemSize = 1024 ** 3
    init_attrs = shm.InitAttr()
    init_attrs.my_rank = rank
    init_attrs.n_ranks = worldSize
    init_attrs.local_mem_size = 1024 ** 3
    base_port = 8766 # 基础端口
    init_attrs.ip_port = ipPort

    shm_ret = 0
    shm_ret = shm.shmem_init(init_attrs)
    if shm_ret != 0:
        raise ValueError('[ERROR] shmem_init failed')
    shmem_ptr = shm.shmem_malloc(localMemSize)
    out = mod(
        expandX=expandXTensor,
        expertIds=expertIdsTensor,
        scales=scalesTensor,
        shmPtr=shmem_ptr,
        world_size=worldSize,
        rank=rank,
        totalExpertNum=totalExpertNum,
        sharedExpertNum=sharedExpertNum,
        expertScales=expertScalesTensor,
        sharedExpertRankNum=sharedExpertRankNum
    )

    torch.npu.synchronize()

    shm_ret = shm.shmem_free(shmem_ptr)
    shm_ret = shm.shmem_finialize()

    out_cpu = out.cpu()
    if sharedExpertRankNum > 0:
        expect_out = 2 * expandXData
    else:
        expect_out = expandXData
    tool.allclose_nparray(expect_out.astype(float), out_cpu.to(torch.float).numpy(), 5e-3)