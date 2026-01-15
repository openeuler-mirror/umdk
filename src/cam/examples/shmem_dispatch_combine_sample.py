#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Example for shmem dispatch/combine operator.
# Create: 2026-01-14
# Note:
# History: 2026-01-14 create shmem dispatch/combine example file
#

import torch
import torch_npu
import numpy as np
import torch.distributed as dist
import torch.multiprocessing as mp
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

def _count_unequal_element(data_expect, data_check, rtol, atol, msg=""):
    assert data_expect.shape == data_check.shape
    total_count = len(data_expect.flatten())
    error = np.abs(data_expect - data_check)
    greater = np.greater(error, atol + np.abs(data_check) * rtol)
    loss_count = np.count_nonzero(greater)
    assert (
        loss_count / total_count
    ) < rtol, "\nmsg{0}_data_expect_std:{1}\ndata_check_error:{2}\nloss:{3}".format(
        msg, data_expect[greater], data_check[greater], error[greater]
    )

def allclose_nparray(data_expect, data_check, rtol=1e-4, atol=1e-4, equal_nan=True, msg=""):
    if np.any(np.isnan(data_expect)):
        assert np.allclose(data_expect, data_check, rtol, atol, equal_nan=equal_nan)
    elif not np.allclose(data_expect, data_check, rtol, atol, equal_nan=equal_nan):
        _count_unequal_element(data_expect, data_check, rtol, atol, msg)
    else:
        assert True

class Module(torch.nn.Module):
    def __init__(self):
        super().__init__()

    def forward(self, expandX, expertIds, scales, shmPtr, world_size, rank, totalExpertNum, sharedExpertRankNum, sharedExpertNum, expertScales):
        output = torch.ops.umdk_cam_op_lib.moe_dispatch_shmem(
            expandX,
            expertIds,
            None,
            None,
            world_size,
            rank,
            (totalExpertNum - sharedExpertNum),
            1,
            0,
            0,
            1,
            sharedExpertNum,
            0,
            0,
            0,
            shmPtr
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
            expandXOut,
            expertIds,
            expandIdxOut,
            epSendCountOut,
            expertScales,
            tpSendCountOut,
            x_active_mask,
            activation_scale,
            weight_scale,
            group_list,
            expand_scales,
            world_size,
            rank,
            moe_expert_num,
            tp_world_size,
            tp_rank_id,
            expert_shard_type,
            shared_expert_num,
            sharedExpertRankNum,
            global_bs,
            comm_quant_mode,
            shmPtr,
            out_dtype,
            group_list_type)
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

def test_base_test(local_rank_id, ep_world_size):
    rank = local_rank_id
    worldSize = ep_world_size

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

    mod = Module().npu()

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
    allclose_nparray(expect_out.astype(float), out_cpu.to(torch.float).numpy(), 5e-3)

if __name__ == "__main__":
    local_rank = int(os.environ["LOCAL_RANK"])
    world_size = int(os.environ["WORLD_SIZE"])
    # shmem init must comes after torch.npu.set_device(or any other aclInit device action)
    torch.npu.set_device(local_rank)
    dist.init_process_group(backend="hccl", rank=local_rank)
    test_base_test(local_rank, world_size)