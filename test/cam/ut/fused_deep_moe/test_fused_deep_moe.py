#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Description: UT for fused_deep_moe op
# Create: 2026-1-13
# Note:
# History: 2026-1-13 create UT test file
#

import pytest
import torch
import torch_npu
import numpy as np
import torch.distributed as dist
import torchair
from torchair.configs.compiler_config import CompilerConfig
from collections import defaultdict
import gc
import os
import sys
import math
import socket
#cam torch扩展包
import umdk_cam_op_lib

from ..util import tool
# 必要夹具 导入即生效
from ..util.marker import Author
from ..util.marker import MPTest
from ..util.marker import A3Test
from ..util.marker import SKIP_ENV_RANKSIZE_UNEQUAL

torch_npu.npu.config.allow_internal_format = True


class CustomOps(torch.nn.Module):
    def __init__(self,
                 gmm1_weight,
                 gmm1_weight_scale,
                 gmm2_weight,
                 gmm2_weight_scale,
                 ep_hcomm_info,
                 batch_size,
                 token_hidden_size,
                 moe_intermediate_size,
                 ep_world_size,
                 moe_expert_num,
                 global_rank_id,
                 shared_expert_rank_num=0,
                 dynamic_eplb=False):
        super().__init__()
        self.ep_hcomm_info = ep_hcomm_info
        self.batch_size = batch_size
        self.token_hidden_size = token_hidden_size
        self.moe_intermediate_size = moe_intermediate_size
        self.ep_world_size = ep_world_size
        self.moe_expert_num = moe_expert_num
        self.global_rank_id = global_rank_id
        self.shared_expert_rank_num = shared_expert_rank_num
        is_shared_expert = global_rank_id < shared_expert_rank_num
        moe_expert_num_per_rank = moe_expert_num // (ep_world_size - shared_expert_rank_num)
        self.local_expert_num = 1 if is_shared_expert else moe_expert_num_per_rank
        self.ep_recv_count_size = self.local_expert_num * ep_world_size
        self.dynamic_eplb = dynamic_eplb
        self.gmm1_weight = torch.empty([
            self.local_expert_num, self.token_hidden_size,
            self.moe_intermediate_size * 2
        ])
        self.gmm1_weight_scale = torch.empty(
            [self.local_expert_num, self.moe_intermediate_size * 2])
        self.gmm2_weight = torch.empty([
            self.local_expert_num, self.moe_intermediate_size,
            self.token_hidden_size
        ])
        self.gmm2_weight_scale = torch.empty(
            [self.local_expert_num, self.token_hidden_size])
        self._process_weights_after_loading(gmm1_weight, gmm1_weight_scale,
                                            gmm2_weight, gmm2_weight_scale)
    
    def _process_weights_after_loading(self, gmm1_weight, gmm1_weight_scale,
                                       gmm2_weight, gmm2_weight_scale):
        gmm1_weight = torch_npu.npu_format_cast(gmm1_weight,
                                                torch_npu.Format.FRACTAL_NZ)
        gmm2_weight = torch_npu.npu_format_cast(gmm2_weight,
                                                torch_npu.Format.FRACTAL_NZ)
        self.gmm1_weight = torch.nn.Parameter(gmm1_weight, requires_grad=False)
        self.gmm1_weight_scale = torch.nn.Parameter(gmm1_weight_scale,
                                                    requires_grad=False)
        self.gmm2_weight = torch.nn.Parameter(gmm2_weight, requires_grad=False)
        self.gmm2_weight_scale = torch.nn.Parameter(gmm2_weight_scale,
                                                    requires_grad=False)

        self.gmm1_weight_scale_fp32 = torch.nn.Parameter(
            gmm1_weight_scale.float(), requires_grad=False)
        self.gmm2_weight_scale_fp32 = torch.nn.Parameter(
            gmm2_weight_scale.float(), requires_grad=False)
    
    def _apply_ops(self, x, expert_ids, smooth_scales, expert_scales, x_active_mask):
        raise NotImplementedError("To be implemented in subclass")

    def forward(self, x, expert_ids, smooth_scales, expert_scales, x_active_mask):
        return self._apply_ops(x, expert_ids, smooth_scales, expert_scales, x_active_mask)

class SmallOps(CustomOps):
    def __init__(self,
                 gmm1_weight,
                 gmm1_weight_scale,
                 gmm2_weight,
                 gmm2_weight_scale,
                 ep_hcomm_info,
                 batch_size,
                 token_hidden_size,
                 moe_intermediate_size,
                 ep_world_size,
                 moe_expert_num,
                 global_rank_id,
                 shared_expert_rank_num,
                 dynamic_eplb=False):
        super().__init__(gmm1_weight, gmm1_weight_scale, gmm2_weight,
                         gmm2_weight_scale, ep_hcomm_info, batch_size,
                         token_hidden_size, moe_intermediate_size,
                         ep_world_size, moe_expert_num, global_rank_id,
                         shared_expert_rank_num, dynamic_eplb)
        self.tp_hcomm_info = ""
       
    def _apply_ops(self, x, expert_ids, smooth_scales, expert_scales, x_active_mask):
        outputs = torch_npu.npu_moe_distribute_dispatch_v2(
            x=x,
            expert_ids=expert_ids,
            expert_scales=expert_scales,
            x_active_mask=x_active_mask,
            group_ep=self.ep_hcomm_info,
            ep_world_size=self.ep_world_size,
            ep_rank_id=self.global_rank_id,
            moe_expert_num=self.moe_expert_num,
            group_tp=self.tp_hcomm_info,
            tp_world_size=1,
            tp_rank_id=0,
            expert_shard_type=0,
            shared_expert_num=1,
            shared_expert_rank_num=self.shared_expert_rank_num,
            quant_mode=2,
            global_bs=self.batch_size * self.ep_world_size,
            expert_token_nums_type=1,  # 0代表前缀和，1代表各自数量
        )
        expand_x, dynamic_scales, assist_info_for_combine, expert_token_nums, ep_send_counts, tp_send_counts, expand_scales = outputs
        output_dtype = x.dtype

        y1_int32 = torch_npu.npu_grouped_matmul(
            x=[expand_x],
            weight=[self.gmm1_weight],
            split_item=3,
            group_list_type=1,  # 默认为0，代表前缀和形式
            group_type=0,  # 0代表m轴分组
            group_list=expert_token_nums,
            output_dtype=torch.int32)[0]
        y1, y1_scale = torch_npu.npu_dequant_swiglu_quant(
            x=y1_int32,
            weight_scale=self.gmm1_weight_scale.to(torch.float32),
            activation_scale=dynamic_scales,
            bias=None,
            quant_scale=None,
            quant_offset=None,
            group_index=expert_token_nums,
            activate_left=True,
            quant_mode=1,
        )
        y2 = torch_npu.npu_grouped_matmul(x=[y1],
                                          weight=[self.gmm2_weight],
                                          scale=[self.gmm2_weight_scale],
                                          per_token_scale=[y1_scale],
                                          split_item=2,
                                          group_list_type=1,
                                          group_type=0,
                                          group_list=expert_token_nums,
                                          output_dtype=output_dtype)[0]
        combine_output = torch_npu.npu_moe_distribute_combine_v2(
            expand_x=y2,
            expert_ids=expert_ids,
            assist_info_for_combine=assist_info_for_combine,
            ep_send_counts=ep_send_counts,
            expert_scales=expert_scales,
            x_active_mask=x_active_mask,
            group_ep=self.ep_hcomm_info,
            ep_world_size=self.ep_world_size,
            ep_rank_id=self.global_rank_id,
            moe_expert_num=self.moe_expert_num,
            tp_send_counts=tp_send_counts,
            expand_scales=expand_scales,
            group_tp=self.tp_hcomm_info,
            tp_world_size=1,
            tp_rank_id=0,
            expert_shard_type=0,
            shared_expert_num=1,
            shared_expert_rank_num=self.shared_expert_rank_num,
            global_bs=self.batch_size * self.ep_world_size)
        return (combine_output, expert_token_nums)

class FusionOp(CustomOps):
    def __init__(self,
                 gmm1_weight,
                 gmm1_weight_scale,
                 gmm2_weight,
                 gmm2_weight_scale,
                 ep_hcomm_info,
                 batch_size,
                 token_hidden_size,
                 moe_intermediate_size,
                 ep_world_size,
                 moe_expert_num,
                 global_rank_id,
                 shared_expert_rank_num=0,
                 dynamic_eplb=False):
        super().__init__(gmm1_weight, gmm1_weight_scale, gmm2_weight,
                         gmm2_weight_scale, ep_hcomm_info, batch_size,
                         token_hidden_size, moe_intermediate_size,
                         ep_world_size, moe_expert_num, global_rank_id,
                         shared_expert_rank_num, dynamic_eplb)

    def _apply_ops(self, x, expert_ids, smooth_scales, expert_scales, x_active_mask):
        output, expert_token_nums = torch.ops.umdk_cam_op_lib.fused_deep_moe(
            x=x,
            expert_ids=expert_ids,
            gmm1_weight=self.gmm1_weight,
            gmm1_weight_scale=self.gmm1_weight_scale_fp32,
            gmm2_weight=self.gmm2_weight,
            gmm2_weight_scale=self.gmm2_weight_scale_fp32,
            expert_scales=expert_scales,
            expert_smooth_scales=smooth_scales,
            x_active_mask=x_active_mask,
            group_ep=self.ep_hcomm_info,
            ep_rank_size=self.ep_world_size,
            ep_rank_id=self.global_rank_id,
            moe_expert_num=self.moe_expert_num,
            shared_expert_num=1,
            shared_expert_rank_num=self.shared_expert_rank_num,
            quant_mode=0,
            global_bs=self.batch_size * self.ep_world_size)
        return (output, expert_token_nums)

    def _process_weights_after_loading(self, gmm1_weight, gmm1_weight_scale,
                                       gmm2_weight, gmm2_weight_scale):
        gmm1_weight = torch_npu.npu_format_cast(gmm1_weight,
                                                torch_npu.Format.FRACTAL_NZ)
        gmm2_weight = torch_npu.npu_format_cast(gmm2_weight,
                                                torch_npu.Format.FRACTAL_NZ)
        gmm1_weight_scale = gmm1_weight_scale.float()
        gmm2_weight_scale = gmm2_weight_scale.float()

        if self.dynamic_eplb:
            self.gmm1_weight = [
                weight.clone() for weight in gmm1_weight.unbind(dim=0)
            ]
            self.gmm1_weight_scale_fp32 = [
                weight.clone() for weight in gmm1_weight_scale.unbind(dim=0)
            ]
            self.gmm2_weight = [
                weight.clone() for weight in gmm2_weight.unbind(dim=0)
            ]
            self.gmm2_weight_scale_fp32 = [
                weight.clone() for weight in gmm2_weight_scale.unbind(dim=0)
            ]
        else:
            self.gmm1_weight = [gmm1_weight.clone()]
            self.gmm1_weight_scale_fp32 = [gmm1_weight_scale.clone()]
            self.gmm2_weight = [gmm2_weight.clone()]
            self.gmm2_weight_scale_fp32 = [gmm2_weight_scale.clone()]

def generate_datas(batch_size,
                   token_hidden_size,
                   moe_intermediate_size,
                   ep_world_size,
                   moe_expert_num,
                   global_rank_id,
                   shared_expert_rank_num=0,
                   top_k=8,
                   test_bfloat16=True,
                   enable_dynamic_bs=False,
                   with_mc2_mask=False):
    is_shared_expert = global_rank_id < shared_expert_rank_num
    moe_expert_num_per_rank = moe_expert_num // (ep_world_size - shared_expert_rank_num)
    actual_bs = int(
        torch.randint(2 if with_mc2_mask else 1, batch_size, [1]).item(
        ) if enable_dynamic_bs else batch_size)
    local_expert_num = 1 if is_shared_expert else moe_expert_num_per_rank
    gmm1_input_dim = token_hidden_size
    gmm1_output_dim = moe_intermediate_size * 2
    gmm2_input_dim = moe_intermediate_size
    gmm2_output_dim = token_hidden_size
    x = torch.rand([actual_bs, token_hidden_size]) * 10 - 5
    expert_ids = torch.arange(
        global_rank_id * batch_size * top_k,
        global_rank_id * batch_size * top_k + actual_bs * top_k).to(
            torch.int32).view(actual_bs, top_k)
    expert_ids = expert_ids % moe_expert_num
    if is_shared_expert:
        gmm1_weight = torch.ones([
            local_expert_num, gmm1_input_dim, gmm1_output_dim
        ]).to(torch.int8) * 4
        gmm2_weight = torch.ones([
            local_expert_num, gmm2_input_dim, gmm2_output_dim
        ]).to(torch.int8) * 4
        gmm1_weight[:, :, ::2] = gmm1_weight[:, :, ::2] * -1
        gmm2_weight[:, :, ::2] = gmm2_weight[:, :, ::2] * -1
        gmm1_weight_scale = torch.ones([local_expert_num, gmm1_output_dim
                                        ]) * 0.0015
        gmm2_weight_scale = torch.ones([local_expert_num, gmm2_output_dim
                                        ]) * 0.0015
    else:
        gmm1_weight = torch.randint(
            -16, 16,
            [local_expert_num, gmm1_input_dim, gmm1_output_dim]).to(torch.int8)
        gmm2_weight = torch.randint(
            -16, 16,
            [local_expert_num, gmm2_input_dim, gmm2_output_dim]).to(torch.int8)
        gmm1_weight_scale = torch.rand([local_expert_num, gmm1_output_dim
                                        ]) * 0.003 + 0.0015
        gmm2_weight_scale = torch.rand([local_expert_num, gmm2_output_dim
                                        ]) * 0.003 + 0.0015
    expert_scales = torch.rand(actual_bs, top_k)
    if test_bfloat16:
        x = x.bfloat16()
        gmm1_weight_scale = gmm1_weight_scale.bfloat16()
        gmm2_weight_scale = gmm2_weight_scale.bfloat16()
    else:
        x = x.half()
    smooth_sales = None
    x_active_mask = None
    valid_token_num = actual_bs
    if with_mc2_mask:
        valid_token_num = int(torch.randint(1, actual_bs, [1]).item())
        x_active_mask = torch.cat(
            (torch.ones(valid_token_num),
             torch.zeros(actual_bs - valid_token_num))).bool()
    return (x, expert_ids, smooth_sales, expert_scales, x_active_mask), \
            (gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale), \
            actual_bs, valid_token_num

CASE_4RANK = {
    "totalExpertNum": 16,
    "sharedExpertNum": 0,
    "topk": 8,
    "batchSize": 16,
    "hiddenSize": 7168,
    "intermediateHiddenSize": 2048,
    "dynamicEPLB": False,
    "with_mc2_mask": False,
}

CASE_8RANK = {
    "totalExpertNum": 16,
    "sharedExpertNum": 0,
    "topk": 8,
    "batchSize": 32,
    "hiddenSize": 7168,
    "intermediateHiddenSize": 2048,
    "dynamicEPLB": True,
    "with_mc2_mask": False,
}

@MPTest # 用例类型，此处代表多进程测试例
@A3Test
@SKIP_ENV_RANKSIZE_UNEQUAL(4) # RankSize不为期望的4时跳过此用例
@pytest.mark.parametrize("mode", [("GE"), ('Eager')])
def test_base_test(mode):
    # 图模式无法获得算子覆盖率故提前退出
    if mode == "GE" and tool.is_run_for_cov():
        return
    # 通过工具方法获取rank和ranksize
    rank = tool.get_rank()
    worldSize = tool.get_world_size()
    case = CASE_4RANK
    totalExpertNum = case["totalExpertNum"]
    sharedExpertNum = case["sharedExpertNum"]
    topk = case["topk"]
    hiddenSize = case["hiddenSize"]
    intermediateHiddenSize = case["intermediateHiddenSize"]
    batchSize = case["batchSize"]
    dynamicEPLB = case["dynamicEPLB"]
    with_mc2_mask = case["with_mc2_mask"]
    test_bfloat16 = True

    # 构造通信域
    ep_ranks_list = list(np.arange(0, worldSize))
    ep_group = dist.new_group(backend="hccl", ranks=ep_ranks_list)
    ep_group_small = dist.new_group(backend="hccl", ranks=ep_ranks_list)

    ep_hcomm_info_fused = ep_group._get_backend(
        torch.device("npu")).get_hccl_comm_name(rank)
    ep_hcomm_info_small = ep_group_small._get_backend(
        torch.device("npu")).get_hccl_comm_name(rank)
    torch_npu.npu.synchronize()
    
    # 构造输入数据
    dynamicBS = False
    parameter = (batchSize, hiddenSize, intermediateHiddenSize,
                 worldSize, totalExpertNum, rank, sharedExpertNum)
    input_datas, weight_datas, actual_bs, valid_token_num = generate_datas(
        *parameter, topk, test_bfloat16, dynamicBS, with_mc2_mask)
    input_datas = [
        data.npu() if data is not None else None for data in input_datas
    ]
    weight_datas = [
        data.npu() if data is not None else None for data in weight_datas
    ]

    small_ops = SmallOps(*weight_datas, ep_hcomm_info_small,
                         *parameter, dynamicEPLB).npu()
    fused_ops = FusionOp(*weight_datas, ep_hcomm_info_fused,
                         *parameter, dynamicEPLB).npu()
    small_op_token_output, small_op_count_output = small_ops(*input_datas)
    fused_op_token_output, fused_op_count_output = fused_ops(*input_datas)
    torch_npu.npu.synchronize()

    torch.testing.assert_close(small_op_token_output.cpu(),
                               fused_op_token_output.cpu(),
                               atol=2.0,
                               rtol=0.02)
    print("token output accuracy is achieved!")
    torch.testing.assert_close(small_op_count_output.cpu(),
                               fused_op_count_output.cpu())
    print("count output accuracy is achieved!")
