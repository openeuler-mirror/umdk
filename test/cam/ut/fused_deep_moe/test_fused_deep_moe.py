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

def convert_tensor_into_parameter(tensor, trans_nz=False):
    if tensor is None:
        return None
    if trans_nz:
        tensor = torch_npu.npu_format_cast(tensor, torch_npu.Format.FRACTAL_NZ)
    return torch.nn.Parameter(tensor, requires_grad=False)

class CustomOps(torch.nn.Module):

    def __init__(self,
                 ep_hcomm_info,
                 meta_info,
                 weight_datas,
                 share_weight_datas):
        super().__init__()
        self.ep_hcomm_info = ep_hcomm_info
        batch_size, ep_world_size, moe_expert_num, global_rank_id, dynamic_eplb = meta_info
        self.ep_world_size = ep_world_size
        self.moe_expert_num = moe_expert_num
        self.global_rank_id = global_rank_id
        self.dynamic_eplb = dynamic_eplb
        self.global_batch_size = batch_size * ep_world_size
        self.with_share = None
        self.with_smooth = None
        self._checkout_datas(weight_datas, share_weight_datas)
        self._process_share_weights_after_loading(share_weight_datas)
        self._process_weights_after_loading(weight_datas)

    def _checkout_datas(self, weight_datas, share_weight_datas):
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales = weight_datas
        share_mm1_weight, share_mm1_weight_scale, share_mm2_weight, share_mm2_weight_scale, share_smooth_scales = share_weight_datas
        if share_mm1_weight is not None:
            assert share_mm1_weight_scale is not None, "share expert need share_mm1_weight_scale"
            assert share_mm2_weight is not None, "share expert need share_mm2_weight"
            assert share_mm2_weight_scale is not None, "share expert need share_mm2_weight_scale"
            if smooth_scales is not None:
                assert share_smooth_scales is not None, "share expert need share_smooth_scales"
                self.with_smooth = True
            else:
                self.with_smooth = False
            self.with_share = True
        else:
            self.with_share = False

    def _process_share_weights_after_loading(self, share_weight_datas):
        share_gmm1_weight, share_gmm1_weight_scale, share_gmm2_weight, share_gmm2_weight_scale, share_smooth_scales = share_weight_datas
        self.share_gmm1_weight = convert_tensor_into_parameter(share_gmm1_weight, trans_nz=True)
        self.share_gmm1_weight_scale = convert_tensor_into_parameter(share_gmm1_weight_scale)
        self.share_gmm2_weight = convert_tensor_into_parameter(share_gmm2_weight, trans_nz=True)
        self.share_gmm2_weight_scale = convert_tensor_into_parameter(share_gmm2_weight_scale)
        self.share_smooth_scales = convert_tensor_into_parameter(share_smooth_scales)

    def _process_weights_after_loading(self, weight_datas):
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales = weight_datas
        self.gmm1_weight = convert_tensor_into_parameter(gmm1_weight, trans_nz=True)
        self.gmm1_weight_scale = convert_tensor_into_parameter(gmm1_weight_scale)
        self.gmm2_weight = convert_tensor_into_parameter(gmm2_weight, trans_nz=True)
        self.gmm2_weight_scale = convert_tensor_into_parameter(gmm2_weight_scale)
        self.smooth_scales = convert_tensor_into_parameter(smooth_scales)

    def _apply_ops(self, x, expert_ids, expert_scales, x_active_mask):
        raise NotImplementedError("To be implemented in subclass")

    def forward(self, x, expert_ids, expert_scales, x_active_mask):
        return self._apply_ops(x, expert_ids, expert_scales, x_active_mask)


class SmallOps(CustomOps):

    def __init__(self,
                 ep_hcomm_info,
                 meta_info,
                 weight_datas,
                 share_weight_datas):
        super().__init__(ep_hcomm_info, meta_info, weight_datas, share_weight_datas)
        self.shared_expert_rank_num = 0
        self.tp_hcomm_info = ""

    def share_compute(self, x):
        x1_int8, x1_scale = torch_npu.npu_dynamic_quant(x, smooth_scales=self.share_smooth_scales)
        gmm1_result = torch_npu.npu_quant_matmul(x1_int8, self.share_gmm1_weight, self.share_gmm1_weight_scale, pertoken_scale=None, output_dtype=torch.int32)
        x2_int8, x2_scale = torch_npu.npu_dequant_swiglu_quant(
            x=gmm1_result,
            weight_scale=self.share_gmm1_weight_scale,
            activation_scale=x1_scale,
            bias=None,
            quant_scale=None,
            quant_offset=None,
            group_index=None,
            activate_left=True,
            quant_mode=1,
        )
        gmm2_result = torch_npu.npu_quant_matmul(x2_int8, self.share_gmm2_weight, self.share_gmm2_weight_scale, pertoken_scale=x2_scale, output_dtype=x.dtype)
        return gmm2_result

    def _apply_ops(self, x, expert_ids, expert_scales, x_active_mask):
        if self.with_share:
            share_output = self.share_compute(x)
        else:
            share_output = None
        outputs = torch_npu.npu_moe_distribute_dispatch_v2(
            x=x,
            expert_ids=expert_ids,
            expert_scales=expert_scales,
            scales=self.smooth_scales,
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
            global_bs=self.global_batch_size,
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
            weight_scale=self.gmm1_weight_scale,
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
            global_bs=self.global_batch_size)
        return (combine_output, share_output, expert_token_nums)


class FusionOp(CustomOps):

    def __init__(self,
                 ep_hcomm_info,
                 meta_info,
                 weight_datas,
                 share_weight_datas):
        super().__init__(ep_hcomm_info, meta_info, weight_datas, share_weight_datas)

    def _apply_ops(self, x, expert_ids, expert_scales, x_active_mask):
        output, share_output, expert_token_nums = torch.ops.umdk_cam_op_lib.fused_deep_moe(
            x=x,
            expert_ids=expert_ids,
            gmm1_weight=self.gmm1_weight,
            gmm1_weight_scale=self.gmm1_weight_scale,
            gmm2_weight=self.gmm2_weight,
            gmm2_weight_scale=self.gmm2_weight_scale,
            expert_scales=expert_scales,
            share_gmm1_weight=self.share_gmm1_weight,
            share_gmm1_weight_scale=self.share_gmm1_weight_scale,
            share_gmm2_weight=self.share_gmm2_weight,
            share_gmm2_weight_scale=self.share_gmm2_weight_scale,
            expert_smooth_scales=self.smooth_scales,
            share_smooth_scales=self.share_smooth_scales_fp32,
            x_active_mask=x_active_mask,
            group_ep=self.ep_hcomm_info,
            ep_rank_size=self.ep_world_size,
            ep_rank_id=self.global_rank_id,
            moe_expert_num=self.moe_expert_num,
            quant_mode=0,
            global_bs=self.global_batch_size)
        return (output, share_output, expert_token_nums)

    def _process_share_weights_after_loading(self, share_weight_datas):
        super()._process_share_weights_after_loading(share_weight_datas)
        _, _, _, _, share_smooth_scales = share_weight_datas
        if self.with_share and self.with_smooth:
            self.share_smooth_scales_fp32 = convert_tensor_into_parameter(share_smooth_scales.float())
        else:
            self.share_smooth_scales_fp32 = None

    def _process_weights_after_loading(self, weight_datas):
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales = weight_datas
        gmm1_weight = convert_tensor_into_parameter(gmm1_weight, trans_nz=True)
        gmm1_weight_scale = convert_tensor_into_parameter(gmm1_weight_scale)
        gmm2_weight = convert_tensor_into_parameter(gmm2_weight, trans_nz=True)
        gmm2_weight_scale = convert_tensor_into_parameter(gmm2_weight_scale)
        if self.dynamic_eplb:
            self.gmm1_weight = [
                weight.clone() for weight in gmm1_weight.unbind(dim=0)
            ]
            self.gmm1_weight_scale = [
                weight.clone() for weight in gmm1_weight_scale.unbind(dim=0)
            ]
            self.gmm2_weight = [
                weight.clone() for weight in gmm2_weight.unbind(dim=0)
            ]
            self.gmm2_weight_scale = [
                weight.clone() for weight in gmm2_weight_scale.unbind(dim=0)
            ]
        else:
            self.gmm1_weight = [gmm1_weight.clone()]
            self.gmm1_weight_scale = [gmm1_weight_scale.clone()]
            self.gmm2_weight = [gmm2_weight.clone()]
            self.gmm2_weight_scale = [gmm2_weight_scale.clone()]
        self.smooth_scales = convert_tensor_into_parameter(smooth_scales)

def generate_datas(batch_size,
                   token_hidden_size,
                   moe_intermediate_size,
                   ep_world_size,
                   moe_expert_num,
                   global_rank_id,
                   top_k=8,
                   enable_dynamic_bs=False,
                   with_mc2_mask=False,
                   with_share=False,
                   with_smooth=False,
                   share_expert_intermediate_size=None):
    moe_expert_num_per_rank = moe_expert_num // ep_world_size
    actual_bs = int(
        np.random.randint(2 if with_mc2_mask else 1, batch_size)
        if enable_dynamic_bs else batch_size)
    local_expert_num = moe_expert_num_per_rank
    gmm1_input_dim = token_hidden_size
    gmm1_output_dim = moe_intermediate_size * 2
    gmm2_input_dim = moe_intermediate_size
    gmm2_output_dim = token_hidden_size
    x = np.random.rand(actual_bs, token_hidden_size).astype(np.float32) * 10 - 5
    expert_ids = np.arange(
        global_rank_id * batch_size * top_k,
        global_rank_id * batch_size * top_k + actual_bs * top_k,
        dtype=np.int32).reshape(actual_bs, top_k)
    expert_ids = expert_ids % moe_expert_num
    gmm1_weight = np.random.randint(
        -16, 16,
        [local_expert_num, gmm1_input_dim, gmm1_output_dim]).astype(np.int8)
    gmm2_weight = np.random.randint(
        -16, 16,
        [local_expert_num, gmm2_input_dim, gmm2_output_dim]).astype(np.int8)
    gmm1_weight_scale = (np.random.rand(local_expert_num, gmm1_output_dim
                                        ).astype(np.float32) * 0.003 + 0.0015)
    gmm2_weight_scale = (np.random.rand(local_expert_num, gmm2_output_dim
                                        ).astype(np.float32) * 0.003 + 0.0015)
    expert_scales = np.random.rand(actual_bs, top_k).astype(np.float32)
    # Generate shared expert weights
    share_mm1_weight = None
    share_mm1_weight_scale = None
    share_mm2_weight = None
    share_mm2_weight_scale = None
    if with_share:
        # Use share_expert_intermediate_size for shared expert gmm1HLen
        share_gmm2_input_dim = share_expert_intermediate_size if share_expert_intermediate_size is not None else moe_intermediate_size
        share_gmm1_output_dim = share_gmm2_input_dim * 2
        share_mm1_weight = np.ones([gmm1_input_dim, share_gmm1_output_dim]).astype(np.int8) * 4
        share_mm2_weight = np.ones([share_gmm2_input_dim, gmm2_output_dim]).astype(np.int8) * 4
        share_mm1_weight_scale = np.ones([share_gmm1_output_dim]) * 0.0015
        share_mm2_weight_scale = np.ones([gmm2_output_dim]) * 0.0015
        share_mm1_weight[:, ::2] = share_mm1_weight[:, ::2] * -1
        share_mm2_weight[:, ::2] = share_mm2_weight[:, ::2] * -1
    smooth_scales = None
    share_smooth_scales = None
    if with_smooth:
        smooth_scales = torch.rand([moe_expert_num, token_hidden_size])
        share_smooth_scales = torch.rand([token_hidden_size]).to(x.dtype)
    x_active_mask = None
    valid_token_num = actual_bs
    if with_mc2_mask:
        valid_token_num = int(np.random.randint(1, actual_bs))
        x_active_mask = np.concatenate(
            [np.ones(valid_token_num),
             np.zeros(actual_bs - valid_token_num)]).astype(bool)
    return (x, expert_ids, expert_scales, x_active_mask), \
            (gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales), \
            (share_mm1_weight, share_mm1_weight_scale, share_mm2_weight, share_mm2_weight_scale, share_smooth_scales), \
            actual_bs, valid_token_num

CASE_4RANK = {
    "totalExpertNum": 16,
    "topk": 8,
    "batchSize": 16,
    "hiddenSize": 7168,
    "intermediateHiddenSize": 2048,
    "dynamicEPLB": False,
    "with_mc2_mask": False,
}

CASE_8RANK = {
    "totalExpertNum": 16,
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
    with_share = False
    with_smooth = False
    share_expert_intermediate_size = 0
    parameter = (batchSize, hiddenSize, intermediateHiddenSize,
                 worldSize, totalExpertNum, rank, topk, dynamicBS, with_mc2_mask,
                 with_share, with_smooth, share_expert_intermediate_size)
    input_datas, weight_datas, share_weight_datas, actual_bs, valid_token_num = generate_datas(*parameter)

    x_dtype = torch.bfloat16 if test_bfloat16 else torch.float16
    scale_dtype = torch.bfloat16 if test_bfloat16 else torch.float32
    x_np, expert_ids_np, expert_scales_np, x_active_mask_np = input_datas
    input_datas = [
        torch.from_numpy(x_np).to(dtype=x_dtype).npu(),
        torch.from_numpy(expert_ids_np).npu(),
        torch.from_numpy(expert_scales_np).npu(),
        torch.from_numpy(x_active_mask_np).npu() if x_active_mask_np is not None else None,
    ]
    meta_info = (batchSize, worldSize, totalExpertNum, rank, dynamicEPLB)
    gmm1_w, gmm1_ws, gmm2_w, gmm2_ws, smooth_scales = weight_datas
    weight_datas = [
        torch.from_numpy(gmm1_w).npu(),
        torch.from_numpy(gmm1_ws).float().npu(),
        torch.from_numpy(gmm2_w).npu(),
        torch.from_numpy(gmm2_ws).to(dtype=scale_dtype).npu(),
        None if smooth_scales is None else torch.from_numpy(smooth_scales).float().npu()
    ]
    share_mm1_w, share_mm1_ws, share_mm2_w, share_mm2_ws, share_smooth_scales = share_weight_datas
    share_weight_datas = [
        None if share_mm1_w is None else torch.from_numpy(share_mm1_w).npu(),
        None if share_mm1_ws is None else torch.from_numpy(share_mm1_ws).float().npu(),
        None if share_mm2_w is None else torch.from_numpy(share_mm2_w).npu(),
        None if share_mm2_ws is None else torch.from_numpy(share_mm2_ws).to(dtype=scale_dtype).npu(),
        None if share_smooth_scales is None else torch.from_numpy(share_smooth_scales).to(x_dtype).npu()
    ]

    small_ops = SmallOps(ep_hcomm_info_small, meta_info, weight_datas, share_weight_datas).npu()
    fused_ops = FusionOp(ep_hcomm_info_fused, meta_info, weight_datas, share_weight_datas).npu()
    small_op_token_output, small_op_share_output, small_op_count_output = small_ops(*input_datas)
    fused_op_token_output, fused_op_share_output, fused_op_count_output = fused_ops(*input_datas)
    torch_npu.npu.synchronize()

    small_token_np = small_op_token_output[:valid_token_num].cpu().float().numpy()
    fused_token_np = fused_op_token_output[:valid_token_num].cpu().float().numpy()
    tool.allclose_nparray(small_token_np, fused_token_np, rtol=0.02, atol=2.0)
    print("token output accuracy is achieved!")
    if with_share:
        small_share_token_np = small_op_share_output.cpu().float().numpy()
        fused_share_token_np = fused_op_share_output.cpu().float().numpy()
        tool.allclose_nparray(small_share_token_np, fused_share_token_np, rtol=0.02, atol=2.0)
        print("token share output accuracy is achieved!")
    small_count_np = small_op_count_output.cpu().numpy()
    fused_count_np = fused_op_count_output.cpu().numpy()
    np.testing.assert_array_equal(small_count_np, fused_count_np)
    print("count output accuracy is achieved!")
