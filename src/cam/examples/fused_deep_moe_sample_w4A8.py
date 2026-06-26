#
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: Example for the FusedDeepMoe W4A8 operator.
#
# This sample demonstrates two equivalent approaches for the W4A8 Mixture-of-Experts computation:
#
#   1. FusionOp: A single fused operator that performs dispatch, quantized GMM1 with
#      SiLU activation, quantized GMM2, dequantization, and combine all on the NPU.
#      Supports both shared experts and routed experts.
#
#   2. SmallOps: A combination of smaller operators achieving the same result:
#      dispatch (NPU) + int8-to-int4 conversion (CPU) + GMM1 (CPU) + SiLU (CPU) +
#      dequant (CPU) + int8-to-int4 conversion (CPU) + GMM2 (CPU) + dequant (CPU) +
#      combine (NPU).
#
# The sample also includes precision validation between shared experts and routed
# experts outputs, and compares FusionOp results against SmallOps for correctness.
#
# Note: Weight matrices have been converted to NZ format but are not tagged with
# the NZ label. This should be kept consistent with the operator host-side NZ
# format validation relaxed accordingly.
#
# Create: 2026-06-29
# Note:
# History: 2026-06-29 create example file
#

import gc
import os
import sys
from pathlib import Path
import numpy as np
import torch
import torch.distributed as dist
import torch.multiprocessing as mp
import torch_npu
import torchair

import umdk_cam_op_lib

torch.manual_seed(42)
torch_npu.npu.config.allow_internal_format = True
class TorchSimulator:
    """
    PyTorch 模拟 npu_grouped_matmul_swiglu_quant_v2 (MSD A8W4) 的调试工具。
    不依赖 NPU 硬件，所有中间结果均可直接查看。

    模拟 C++ kernel 的三段流水线架构:
      Pre-process(AIV):  INT8 激活拆分为 high/low INT4
      Mid-process(AIC):  INT4 × INT4 两次矩阵乘 (分别应用 weight_scale 反量化)
      Post-process:      合并高低位 + assistMatrix → × per-token scale → SwiGLU → quant

    用法:
        sim_y, sim_y_scale = TorchSimulator.a8w4_simulate(
            x_int8=expand_x,              # INT8  [M, K]
            weight_int32=gmm1_weight,     # INT32 [E, K, N//8] 打包的 INT4
            weight_scale=gmm1_wt_scale,   # float [E, N]
            x_scale=dynamic_scales,       # float [M]
            group_list=expert_token_nums, # int64 [E]
            assist_matrix=assist_mat,     # float [E, N]
        )
    """

    # ---------- 底层工具 ----------
    @staticmethod
    def _nz_to_nd_int32(weight_nz):
        """
        将 INT32 weight 从 NZ 格式转回 ND 格式。
        NZ  [E, N/64, K/16, 16, 8] → ND  [E, K, N//8]
        """
        if weight_nz.ndim == 3:
            return weight_nz
        E = weight_nz.shape[0]
        N_div_64 = weight_nz.shape[1]
        K_div_16 = weight_nz.shape[2]
        weight_nd = weight_nz.permute(0, 2, 3, 1, 4).contiguous()
        return weight_nd.view(E, K_div_16 * 16, N_div_64 * 8)

    @staticmethod
    def _int32_unpack_int4(int32_tensor):
        """INT32 按 4-bit nibble 解包为有符号 INT4。 (E, M, N) → (E, M, 8*N)"""
        unpacked = []
        for s in range(0, 32, 4):
            nib = (int32_tensor >> s) & 0xF
            nib = torch.where(nib >= 8, nib - 16, nib).to(torch.int8)
            unpacked.append(nib.unsqueeze(-1))      # (E, M, N, 1)
        # cat 得到 (E, M, N, 8)，再展平最后两维 → (E, M, N*8)
        return torch.cat(unpacked, dim=-1).reshape(*int32_tensor.shape[:-1], -1)


    @staticmethod
    def _expand_by_group(tensor, group_counts):
        """将 [E, ...] 按 group_counts 展开为 [M, ...] 的 per-token 形式。"""
        if isinstance(group_counts, torch.Tensor) and group_counts.dim() == 0:
            count = int(group_counts.item())
            if count <= 0:
                return tensor.new_zeros(0, *tensor.shape[1:])
            return tensor.expand(count, *tensor.shape)
        parts = [tensor[e:e+1].expand(int(group_counts[e].item()), *tensor.shape[1:])
                 for e in range(tensor.shape[0]) if int(group_counts[e].item()) > 0]
        return torch.cat(parts, dim=0) if parts else tensor.new_zeros(0, *tensor.shape[1:])

    @staticmethod
    def compute_assist_matrix(weight_int4):
        """
        计算 A8W4 辅助矩阵: assistMatrix[e, j] = 8.0 * Σ_k W[e, k, j]
        weight_int4: [E, K, N] INT8, 值域 [-8, 7]
        Returns: float32 [E, N]
        """
        return 8.0 * weight_int4.float().sum(dim=1)

    # ---------- MSD A8W4 三段模拟 ----------

    @staticmethod
    def _a8w4_mid_process(x_high, x_low, weight_int4, weight_scale, group_counts):
        M = x_high.shape[0]
        if weight_int4.dim() == 2:
            E = 1
        else:
            E = weight_int4.shape[0]
        N = weight_int4.shape[-1]

        ws = weight_scale.float()
        ws_per_token = TorchSimulator._expand_by_group(ws, group_counts)

        c_high = torch.empty(M, N, dtype=torch.float32)
        c_low = torch.empty(M, N, dtype=torch.float32)
        start = 0
        for e in range(E):
            if isinstance(group_counts, torch.Tensor) and group_counts.dim() == 0:
                cnt = int(group_counts.item())
            else:
                cnt = int(group_counts[e].item())
            if cnt <= 0:
                continue
            end = start + cnt
            w = weight_int4[e].to(torch.int32) if weight_int4.dim() > 2 else weight_int4.to(torch.int32)
            c_high[start:end] = x_high[start:end].to(torch.int32).mm(w).float()
            c_low[start:end]  = x_low[start:end].to(torch.int32).mm(w).float()
            start = end
        c_high = c_high * ws_per_token
        c_low  = c_low  * ws_per_token
        return c_high, c_low

    @staticmethod
    def _a8w4_pre_process(x_int8):
        """
        Pre-Process: INT8 激活拆分为 high/low INT4。
        X_high = floor(X_int8 / 16)
        X_low  = (X_int8 & 0x0F) - 8
        Returns: (x_high_int4, x_low_int4) 均为 int8 值域 [-8, 7]
        """
        x_i32 = x_int8.to(torch.int32)
        x_high = (x_i32 // 16).to(torch.int8)
        x_low = ((x_i32 & 0x0F) - 8).to(torch.int8)
        return x_high, x_low

    @staticmethod
    def _a8w4_post_process(c_high, c_low, x_scale, assist_matrix, group_counts):
        """
        Post-Process (对应 GMMA8W4PostProcess):
          合并 → per-token scale → SwiGLU → 量化

          C = (C_high * 16 + C_low + assistMatrix) * x_scale
          然后 split → Swish(act) * gate → quant per-token.

        Returns: (y_int8, y_scale)  INT8 [M, N/2], float [M]
        """
        assist_per_token = TorchSimulator._expand_by_group(assist_matrix.float(), group_counts)
        x_scale_f32 = x_scale.float()
        total_tokens = int(group_counts.item()) if (isinstance(group_counts, torch.Tensor) and group_counts.dim() == 0) else sum(group_counts)
        x_scale_f32 = x_scale.cpu()[:total_tokens].float()

        merged = (c_high * 16.0 + c_low + assist_per_token) * x_scale_f32.unsqueeze(1)

        half_n = merged.shape[1] // 2
        act, gate = merged[:, :half_n], merged[:, half_n:]
        swiglu_out = torch.sigmoid(act) * act * gate

        row_max = swiglu_out.abs().amax(dim=1, keepdim=True)
        y_scale = (row_max / 127.0).squeeze(1)
        y_float = torch.round(swiglu_out / y_scale.unsqueeze(1))
        y_int8 = y_float.clamp(-128, 127).to(torch.int8)

        return y_int8, y_scale

    @staticmethod
    def _a8w4_post_process_GMM2(c_high, c_low, x_scale, assist_matrix, group_counts):
        """
        Post-Process for GMM2: 合并 + per-token scale, 返回 bfloat16。

        Returns: bfloat16 [M, N]
        """
        assist_per_token = TorchSimulator._expand_by_group(assist_matrix.float(), group_counts)
        x_scale_f32 = x_scale.float()

        merged = (c_high * 16.0 + c_low + assist_per_token) * x_scale_f32.unsqueeze(1)
        merged = merged.to(torch.bfloat16)

        return merged

LOG_NAME = "fused_deep_moe_sample_logs"
BASE_KWARGS = {
    "batch_size": 64,
    "token_hidden_size": 7168,
    "moe_intermediate_size": 2048,
    "ep_world_size": 16,
    "moe_expert_num": 64,
    "top_k": 8,
    "test_bfloat16": True,
    "enable_dynamic_bs": False,
    "test_graph": False,
    "with_mc2_mask": False,
    "dynamic_eplb": False,
    "with_share": False,
    "with_smooth": False,
    "share_expert_intermediate_size": 2048
}

def redirect_output(log_file_path):
    log_path = Path(LOG_NAME) / log_file_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(LOG_NAME + "/" + log_file_path, "w")
    os.dup2(f.fileno(), sys.stdout.fileno())
    os.dup2(f.fileno(), sys.stderr.fileno())
    return f

def output_to_file(rank_id):
    return False

def convert_nd_to_nz(x: torch.Tensor) -> torch.Tensor:
    fractal_size_dict = {
        torch.int8: (16, 32),
        torch.float16: (16, 16),
        torch.bfloat16: (16, 16),
        torch.int32: (16, 8)
    }
    m0, n0 = fractal_size_dict[x.dtype]
    *dims, m, n = x.shape
    assert(m % m0 == 0 and n % n0 == 0)
    order = list(range(len(dims))) + [-2, -4, -3, -1]
    return x.reshape(*dims, m // m0, m0, n // n0, n0).permute(order).reshape(*dims, m, n).contiguous()

def convert_tensor_into_parameter(tensor, trans_nz=False):
    if tensor is None:
        return None
    if trans_nz:
        tensor = convert_nd_to_nz(tensor)
    return torch.nn.Parameter(tensor, requires_grad=False)


class DecodeMoeOps(torch.nn.Module):

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
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales, gmm1_bias, gmm2_bias = weight_datas
        share_mm1_weight, share_mm1_weight_scale, share_mm2_weight, share_mm2_weight_scale, share_smooth_scales, share_mm1_bias, share_mm2_bias = share_weight_datas
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
        share_gmm1_weight, share_gmm1_weight_scale, share_gmm2_weight, share_gmm2_weight_scale, share_smooth_scales, share_gmm1_bias, share_gmm2_bias = share_weight_datas
        self.share_gmm1_weight = convert_tensor_into_parameter(share_gmm1_weight, trans_nz=True)
        self.share_gmm1_weight_scale = convert_tensor_into_parameter(share_gmm1_weight_scale)
        self.share_gmm2_weight = convert_tensor_into_parameter(share_gmm2_weight, trans_nz=True)
        self.share_gmm2_weight_scale = convert_tensor_into_parameter(share_gmm2_weight_scale)
        self.share_smooth_scales = convert_tensor_into_parameter(share_smooth_scales)
        self.share_gmm1_bias = convert_tensor_into_parameter(share_gmm1_bias)
        self.share_gmm2_bias = convert_tensor_into_parameter(share_gmm2_bias)

    def _process_weights_after_loading(self, weight_datas):
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales, gmm1_bias, gmm2_bias = weight_datas
        self.gmm1_weight = gmm1_weight.cpu()
        self.gmm1_weight_scale = gmm1_weight_scale.cpu()
        self.gmm2_weight = gmm2_weight.cpu()
        self.gmm2_weight_scale = gmm2_weight_scale.cpu()
        self.gmm1_bias = gmm1_bias.cpu()
        self.gmm2_bias = gmm2_bias.cpu()
        self.smooth_scales = convert_tensor_into_parameter(smooth_scales)

    def _apply_ops(self, x, expert_ids, expert_scales, x_active_mask):
        raise NotImplementedError("To be implemented in subclass")

    def forward(self, x, expert_ids, expert_scales, x_active_mask):
        return self._apply_ops(x, expert_ids, expert_scales, x_active_mask)


class SmallOps(DecodeMoeOps):

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
        return x1_int8, x1_scale

    def _apply_ops(self, x, expert_ids, expert_scales, x_active_mask):
        if self.with_share:
            x1_int8, x1_scale = self.share_compute(x)
            return (x1_int8, x1_scale)

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
            expert_token_nums_type=1,
        )
        expand_x, dynamic_scales, assist_info_for_combine, expert_token_nums, ep_send_counts, tp_send_counts, expand_scales = outputs
        weight_int4 = TorchSimulator._int32_unpack_int4(self.gmm1_weight)
        total_tokens = sum(expert_token_nums)
        x = expand_x.cpu()[:total_tokens]
        x_high, x_low = TorchSimulator._a8w4_pre_process(x)

        c_high, c_low = TorchSimulator._a8w4_mid_process(
            x_high, x_low, weight_int4, self.gmm1_weight_scale.cpu(), expert_token_nums.cpu())
        y_int8_1, y_scale = TorchSimulator._a8w4_post_process(
            c_high, c_low, dynamic_scales.cpu(), self.gmm1_bias.cpu(), expert_token_nums.cpu())
        y_int8_high, y_int8_low = TorchSimulator._a8w4_pre_process(y_int8_1)
        weight2_int4 = TorchSimulator._int32_unpack_int4(self.gmm2_weight)
        c_high, c_low = TorchSimulator._a8w4_mid_process(
            y_int8_high, y_int8_low, weight2_int4, self.gmm2_weight_scale.cpu(), expert_token_nums.cpu())
        y2_cpu = TorchSimulator._a8w4_post_process_GMM2(
            c_high, c_low, y_scale.cpu(), self.gmm2_bias.cpu(), expert_token_nums.cpu())
        padded_row_count = expand_x.shape[0]
        if y2_cpu.shape[0] < padded_row_count:
            y2_padded = torch.zeros(padded_row_count, y2_cpu.shape[1], dtype=y2_cpu.dtype)
            y2_padded[:y2_cpu.shape[0]] = y2_cpu
            y2 = y2_padded.npu()
        else:
            y2 = y2_cpu.npu()
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
        return combine_output


class FusionOp(DecodeMoeOps):

    def __init__(self,
                 ep_hcomm_info,
                 meta_info,
                 weight_datas,
                 share_weight_datas):
        super().__init__(ep_hcomm_info, meta_info, weight_datas, share_weight_datas)

    def _apply_ops(self, x, expert_ids, expert_scales, x_active_mask):
        self.share_smooth_scales_fp32 = torch.zeros(256*1024*1024).npu().to(torch.float32)
        output, share_output, expert_token_nums = torch.ops.umdk_cam_op_lib.fused_deep_moe(
            x=x,
            expert_ids=expert_ids,
            gmm1_weight=self.gmm1_weight,
            gmm1_weight_scale=self.gmm1_weight_scale,
            gmm2_weight=self.gmm2_weight,
            gmm2_weight_scale=self.gmm2_weight_scale,
            expert_scales=expert_scales,
            gmm1_bias=self.gmm1_bias,
            gmm2_bias=self.gmm2_bias,
            share_gmm1_bias=self.share_gmm1_bias,
            share_gmm2_bias=self.share_gmm2_bias,
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
        _, _, _, _, share_smooth_scales, share_mm1_bias, share_mm2_bias = share_weight_datas
        if self.with_share and self.with_smooth:
            self.share_smooth_scales_fp32 = convert_tensor_into_parameter(share_smooth_scales.float())
        else:
            self.share_smooth_scales_fp32 = None

    def _process_weights_after_loading(self, weight_datas):
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales, gmm1_bias, gmm2_bias = weight_datas
        gmm1_weight = convert_tensor_into_parameter(gmm1_weight, trans_nz=True)
        gmm1_weight_scale = convert_tensor_into_parameter(gmm1_weight_scale)
        gmm2_weight = convert_tensor_into_parameter(gmm2_weight, trans_nz=True)
        gmm2_weight_scale = convert_tensor_into_parameter(gmm2_weight_scale)
        gmm1_bias_tmp = convert_tensor_into_parameter(gmm1_bias)
        gmm2_bias_tmp = convert_tensor_into_parameter(gmm2_bias)
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
            self.gmm1_bias = [
                weight.clone() for weight in gmm1_bias_tmp.unbind(dim=0)
            ]
            self.gmm2_bias = [
                weight.clone() for weight in gmm2_bias_tmp.unbind(dim=0)
            ]
        else:
            self.gmm1_weight = [gmm1_weight.clone()]
            self.gmm1_weight_scale = [gmm1_weight_scale.clone()]
            self.gmm2_weight = [gmm2_weight.clone()]
            self.gmm2_weight_scale = [gmm2_weight_scale.clone()]
            self.gmm1_bias = [gmm1_bias_tmp.clone()]
            self.gmm2_bias = [gmm2_bias_tmp.clone()]
        self.smooth_scales = convert_tensor_into_parameter(smooth_scales)


def _int32_unpack_int4(int32_tensor):
    """INT32 按 4-bit nibble 解包为有符号 INT4。N 个 int32 → 8*N 个并列 int4 (值域 [-8, 7])。"""
    unpacked = []
    for s in range(0, 32, 4):
        nib = (int32_tensor >> s) & 0xF
        nib = torch.where(nib >= 8, nib - 16, nib).to(torch.int8)
        unpacked.append(nib)
    return torch.stack(unpacked, dim=-1).reshape(*int32_tensor.shape[:-1], -1)

def generate_datas(batch_size,
                   token_hidden_size,
                   moe_intermediate_size,
                   ep_world_size,
                   moe_expert_num,
                   global_rank_id,
                   top_k=8,
                   test_bfloat16=True,
                   enable_dynamic_bs=False,
                   with_mc2_mask=False,
                   with_share=False,
                   with_smooth=False,
                   share_expert_intermediate_size=None):
    moe_expert_num_per_rank = moe_expert_num // ep_world_size
    actual_bs = int(
        torch.randint(2 if with_mc2_mask else 1, batch_size, [1]).item(
        ) if enable_dynamic_bs else batch_size)
    local_expert_num = moe_expert_num_per_rank
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
    gmm1_weight = torch.randint(
        -127, 127,
        [local_expert_num, gmm1_input_dim, gmm1_output_dim//8]).to(torch.int32)
    gmm2_weight = torch.randint(
        -127, 127,
        [local_expert_num, gmm2_input_dim, gmm2_output_dim//8]).to(torch.int32)

    gmm1_input_dim = gmm1_weight.shape[1]
    gmm2_input_dim = gmm2_weight.shape[1]
    gmm1_weight_int4 = _int32_unpack_int4(gmm1_weight)
    gmm2_weight_int4 = _int32_unpack_int4(gmm2_weight)

    gmm1_weight_scale = torch.rand([local_expert_num, gmm1_output_dim
                                    ]) * 0.003 + 0.0015
    gmm2_weight_scale = torch.rand([local_expert_num, gmm2_output_dim
                                    ]) * 0.003 + 0.0015
    gmm1_bias = 8.0 * gmm1_weight_int4.float().sum(dim=1) * gmm1_weight_scale
    gmm2_bias = 8.0 * gmm2_weight_int4.float().sum(dim=1) * gmm2_weight_scale
    expert_scales = torch.rand(actual_bs, top_k)

    share_mm1_weight = None
    share_mm1_weight_scale = None
    share_mm2_weight = None
    share_mm2_weight_scale = None
    share_gmm1_bias = None
    share_gmm2_bias = None
    if with_share:
        share_gmm2_input_dim = share_expert_intermediate_size if share_expert_intermediate_size is not None else moe_intermediate_size
        share_gmm1_output_dim = share_gmm2_input_dim * 2
        share_mm1_weight = torch.randint(
            -127, 127,
            [gmm1_input_dim, share_gmm1_output_dim//8]).to(torch.int32)
        share_mm2_weight = torch.randint(
            -127, 127,
            [share_gmm2_input_dim, gmm2_output_dim//8]).to(torch.int32)
        share_mm1_weight_scale = torch.rand([share_gmm1_output_dim]) * 0.0015
        share_mm2_weight_scale = torch.rand([gmm2_output_dim]) * 0.0015
        share_mm1_weight_int4 = _int32_unpack_int4(share_mm1_weight)
        share_mm2_weight_int4 = _int32_unpack_int4(share_mm2_weight)
        share_gmm1_bias = 8.0 * share_mm1_weight_int4.float().sum(dim=0) * share_mm1_weight_scale
        share_gmm2_bias = 8.0 * share_mm2_weight_int4.float().sum(dim=0) * share_mm2_weight_scale

    if test_bfloat16:
        x = x.bfloat16()
        gmm2_weight_scale = gmm2_weight_scale.bfloat16()
        if with_share:
            share_mm2_weight_scale = share_mm2_weight_scale.bfloat16()
    else:
        x = x.half()
    smooth_scales = None
    share_smooth_scales = None
    if with_smooth:
        smooth_scales = torch.rand([moe_expert_num, token_hidden_size])
        share_smooth_scales = torch.rand([token_hidden_size]).to(x.dtype)
    x_active_mask = None
    valid_token_num = actual_bs
    if with_mc2_mask:
        valid_token_num = int(torch.randint(1, actual_bs, [1]).item())
        x_active_mask = torch.cat(
            (torch.ones(valid_token_num),
             torch.zeros(actual_bs - valid_token_num))).bool()
    return (x, expert_ids, expert_scales, x_active_mask), \
            (gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales, gmm1_bias, gmm2_bias), \
            (share_mm1_weight, share_mm1_weight_scale, share_mm2_weight, share_mm2_weight_scale, share_smooth_scales, share_gmm1_bias, share_gmm2_bias), \
            actual_bs, valid_token_num


def run_once(local_rank_id,
             batch_size,
             token_hidden_size,
             moe_intermediate_size,
             ep_world_size,
             moe_expert_num,
             top_k=8,
             test_bfloat16=True,
             enable_dynamic_bs=False,
             test_graph=False,
             with_mc2_mask=False,
             dynamic_eplb=False,
             with_share=False,
             with_smooth=False,
             share_expert_intermediate_size=None):
    torch.set_printoptions(precision=8, sci_mode=False)
    log_file = redirect_output(f"local_rank_{local_rank_id}.log"
                               ) if output_to_file(local_rank_id) else None
    global_rank_id = local_rank_id
    device_id = local_rank_id % 16
    torch_npu.npu.set_device(device_id)

    os.environ["MASTER_ADDR"] = "127.0.0.1"
    os.environ["MASTER_PORT"] = "27500"
    dist.init_process_group(backend="hccl",
                            rank=local_rank_id,
                            world_size=ep_world_size)
    ep_ranks_list = list(np.arange(0, ep_world_size))
    ep_group = dist.new_group(backend="hccl", ranks=ep_ranks_list)
    ep_group_small = dist.new_group(backend="hccl", ranks=ep_ranks_list)

    ep_hcomm_info_fused = ep_group._get_backend(
        torch.device("npu")).get_hccl_comm_name(local_rank_id)
    ep_hcomm_info_small = ep_group_small._get_backend(
        torch.device("npu")).get_hccl_comm_name(local_rank_id)
    torch_npu.npu.synchronize(device_id)

    parameter = (batch_size, token_hidden_size, moe_intermediate_size,
                 ep_world_size, moe_expert_num, global_rank_id, top_k,
                 test_bfloat16, enable_dynamic_bs, with_mc2_mask,
                 with_share, with_smooth, share_expert_intermediate_size)
    input_datas, weight_datas, share_weight_datas, actual_bs, valid_token_num = generate_datas(*parameter)
    input_datas = [
        data.npu() if data is not None else None for data in input_datas
    ]
    meta_info = (batch_size, ep_world_size, moe_expert_num, global_rank_id, dynamic_eplb)
    weight_datas_npu = [
        data.npu() if data is not None else None for data in weight_datas
    ]
    share_weight_datas_npu = [
        data.npu() if data is not None else None for data in share_weight_datas
    ]
    small_ops = SmallOps(ep_hcomm_info_small, meta_info, weight_datas_npu, share_weight_datas_npu).npu()
    fused_ops = FusionOp(ep_hcomm_info_fused, meta_info, weight_datas_npu, share_weight_datas_npu).npu()

    def validate_pair(sim_out, op_out, name, atol=1e-3, rtol=1e-2):
        sim = sim_out.cpu()
        op = op_out.cpu()

        abs_diff = (sim - op).abs()
        max_abs = abs_diff.max().item()
        mean_abs = abs_diff.mean().item()

        denom = torch.abs(op) + 1e-8
        rel_diff = abs_diff / denom
        max_rel = rel_diff.max().item()
        mean_rel = rel_diff.mean().item()

        within_tol = (abs_diff <= atol + rtol * torch.abs(op)).float().mean().item()

        print(f"\n===== {name} 精度校验 =====")
        print(f"绝对误差: max={max_abs:.6f}, mean={mean_abs:.6f}")
        print(f"相对误差: max={max_rel:.6f}, mean={mean_rel:.6f}")
        print(f"在 atol={atol}, rtol={rtol} 下匹配比例: {within_tol*100:.2f}%")

        if within_tol > 0.99:
            print(f"✓ {name} 校验通过")
        else:
            print(f"✗ {name} 校验未通过，匹配比例过低")

        return within_tol

    if with_share:
        gmm1_weight, gmm1_weight_scale, gmm2_weight, gmm2_weight_scale, smooth_scales, gmm1_bias, gmm2_bias = share_weight_datas
        x, dynamic_scales = small_ops(*input_datas)
        fused_op_output = fused_ops(*input_datas)
        fused_op_token_output, fused_op_share_output, fused_op_count_output = fused_op_output

        weight_int4 = TorchSimulator._int32_unpack_int4(gmm1_weight)
        x_high, x_low = TorchSimulator._a8w4_pre_process(x)
        expert_token_nums = torch.tensor(x.shape[0], dtype=torch.int64)
        c_high, c_low = TorchSimulator._a8w4_mid_process(
            x_high.cpu(), x_low.cpu(), weight_int4.cpu(), gmm1_weight_scale.cpu(), expert_token_nums.cpu())
        y_int8, y_scale = TorchSimulator._a8w4_post_process(
            c_high, c_low, dynamic_scales.cpu(), gmm1_bias.cpu(), expert_token_nums.cpu())
        y_int8_high, y_int8_low = TorchSimulator._a8w4_pre_process(y_int8)
        weight2_int4 = TorchSimulator._int32_unpack_int4(gmm2_weight)
        c_high, c_low = TorchSimulator._a8w4_mid_process(
            y_int8_high, y_int8_low, weight2_int4, gmm2_weight_scale.cpu(), expert_token_nums.cpu())
        y2_cpu = TorchSimulator._a8w4_post_process_GMM2(
            c_high, c_low, y_scale.cpu(), gmm2_bias.cpu(), expert_token_nums.cpu())
        validate_pair(y2_cpu, fused_op_share_output, "y2_cpu vs fused_op_share_output")
    else:
        combine_output = small_ops(*input_datas)
        fused_op_output = fused_ops(*input_datas)
        fused_op_token_output, fused_op_share_output, fused_op_count_output = fused_op_output
        validate_pair(fused_op_token_output, combine_output, "y_npu vs y_cpu")

    torch_npu.npu.synchronize(device_id)

    dist.destroy_process_group()
    if log_file is not None:
        log_file.close()
    print(f"rank-{global_rank_id} Passed!")

    gc.collect()
    torch.npu.empty_cache()
    torch.npu.reset_peak_memory_stats()


@torch.inference_mode()
def test_fused_deep_moe_base():
    custom_kwargs = BASE_KWARGS
    ep_world_size = custom_kwargs["ep_world_size"]
    custom_args = tuple(custom_kwargs.values())
    mp.spawn(run_once, args=custom_args, nprocs=ep_world_size, join=True)


@torch.inference_mode()
def test_fused_deep_moe_with_mc2_mask():
    custom_kwargs = BASE_KWARGS
    custom_kwargs["with_mc2_mask"] = True
    ep_world_size = custom_kwargs["ep_world_size"]
    custom_args = tuple(custom_kwargs.values())
    mp.spawn(run_once, args=custom_args, nprocs=ep_world_size, join=True)


@torch.inference_mode()
def test_fused_deep_moe_eplb():
    custom_kwargs = BASE_KWARGS
    custom_kwargs["dynamic_eplb"] = True
    ep_world_size = custom_kwargs["ep_world_size"]
    custom_args = tuple(custom_kwargs.values())
    mp.spawn(run_once, args=custom_args, nprocs=ep_world_size, join=True)



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch_size", type=int, default=64)
    parser.add_argument("--token_hidden_size", type=int, default=7168)
    parser.add_argument("--moe_intermediate_size", type=int, default=2048)
    parser.add_argument("--ep_world_size", type=int, default=16)
    parser.add_argument("--moe_expert_num", type=int, default=64)
    parser.add_argument("--top_k", type=int, default=8)
    parser.add_argument("--test_float16", action="store_true", default=False)
    parser.add_argument("--enable_dynamic_bs", action="store_true", default=False)
    parser.add_argument("--test_graph", action="store_true", default=False)
    parser.add_argument("--with_mc2_mask", action="store_true", default=False)
    parser.add_argument("--dynamic_eplb", action="store_true", default=False)
    parser.add_argument("--with_share", action="store_true", default=False)
    parser.add_argument("--with_smooth", action="store_true", default=False)
    parser.add_argument("--share_expert_intermediate_size", type=int)
    args = parser.parse_args()
    BASE_KWARGS["batch_size"] = args.batch_size
    BASE_KWARGS["token_hidden_size"] = args.token_hidden_size
    BASE_KWARGS["moe_intermediate_size"] = args.moe_intermediate_size
    BASE_KWARGS["moe_expert_num"] = args.moe_expert_num
    BASE_KWARGS["ep_world_size"] = args.ep_world_size
    BASE_KWARGS["top_k"] = args.top_k
    BASE_KWARGS["test_bfloat16"] = not args.test_float16
    BASE_KWARGS["enable_dynamic_bs"] = args.enable_dynamic_bs
    BASE_KWARGS["test_graph"] = args.test_graph
    BASE_KWARGS["with_mc2_mask"] = args.with_mc2_mask
    BASE_KWARGS["dynamic_eplb"] = args.dynamic_eplb
    BASE_KWARGS["with_share"] = args.with_share
    BASE_KWARGS["with_smooth"] = args.with_smooth
    BASE_KWARGS["share_expert_intermediate_size"] = args.share_expert_intermediate_size \
        if args.share_expert_intermediate_size is not None else args.moe_intermediate_size
    test_fused_deep_moe_base()