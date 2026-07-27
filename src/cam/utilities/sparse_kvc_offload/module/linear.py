# coding=utf-8
# Adapted from
# https://github.com/vllm-project/vllm/blob/v0.9.0/vllm/model_executor/layers/linear.py
# Copyright (c) 2025-2026 Huawei Technologies Co., Ltd.
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
from abc import ABC, abstractmethod
import math
from typing import Optional, Union, List, Sequence, Tuple

import torch
import torch.nn as nn
from torch.nn import Parameter
import torch_npu
from transformers.activations import ACT2FN
from transformers.utils import logging

from module.quantization import QuantizeMethodBase, QuantizationConfig
from .utils import (divide, set_weight_attrs)
logger = logging.get_logger(__name__)


def split_tensor_along_last_dim(
    tensor: torch.Tensor,
    num_partitions: int,
    contiguous_split_chunks: bool = False,
) -> Sequence[torch.Tensor]:
    """ Split a tensor along its last dimension.

        Arguments:
            tensor: input tensor.
            num_partitions: number of partitions to split the tensor
            contiguous_split_chunks: If True, make each chunk contiguous
                                     in memory.

        Returns:
            A list of Tensors
    """
    # Get the size and dimension.
    last_dim = tensor.dim() - 1
    last_dim_size = divide(tensor.size()[last_dim], num_partitions)
    # Split.
    tensor_list = torch.split(tensor, last_dim_size, dim=last_dim)
    # NOTE: torch.split does not create contiguous tensors by default.
    if contiguous_split_chunks:
        return tuple(chunk.contiguous() for chunk in tensor_list)

    return tensor_list


class LinearMethodBase(QuantizeMethodBase):
    """Base class for different (maybe quantized) linear methods."""

    @abstractmethod
    def create_weights(self, layer: torch.nn.Module,
                       input_size_per_partition: int,
                       output_partition_sizes: list[int], input_size: int,
                       output_size: int, params_dtype: torch.dtype,
                       **extra_weight_attrs):
        """Create weights for a linear layer.
           The weights will be set as attributes of the layer.

        Args:
            layer: The layer that is using the LinearMethodBase factory.
            input_size_per_partition: Size of the weight input dim on rank X.
            output_partition_sizes: Sizes of the output dim of each logical
                weight on rank X. E.g., output_partition_sizes for MergedColumnParallelLinear
                is a list contains the width of Wq, Wk, Wv on rank X.
            input_size: Size of the input dim of the weight across all ranks.
            output_size: Size of the output dim of the weight across all ranks.
            params_dtype: Datatype of the parameters.
        """
        raise NotImplementedError

    @abstractmethod
    def apply(self,
              layer: torch.nn.Module,
              x: torch.Tensor,
              bias: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Apply the weights in layer to the input tensor.
        Expects create_weights to have been called before on the layer.
        """
        raise NotImplementedError


class UnquantizedLinearMethod(LinearMethodBase):
    """Linear method without quantization."""

    def create_weights(self, layer: torch.nn.Module,
                       input_size_per_partition: int,
                       output_partition_sizes: list[int], input_size: int,
                       output_size: int, params_dtype: torch.dtype,
                       **extra_weight_attrs):
        weight = Parameter(torch.empty(sum(output_partition_sizes),
                                       input_size_per_partition,
                                       dtype=params_dtype),
                           requires_grad=False)
        set_weight_attrs(weight, {"input_dim": 1, "output_dim": 0})
        layer.register_parameter("weight", weight)
        set_weight_attrs(weight, extra_weight_attrs)

    def apply(self,
              layer: torch.nn.Module,
              x: torch.Tensor,
              bias: Optional[torch.Tensor] = None,
              **kargs) -> torch.Tensor:
        origin_shape = x.size()
        x = x.reshape(-1, origin_shape[-1])
        out = torch.matmul(x, layer.weight.data)
        if bias is not None:
            out = out + bias
        out = out.view(*origin_shape[:-1], out.shape[-1])
        return out

    def process_weights_after_loading(self, layer, is_transpose=True, is_nz=True, **kwargs):
        weight = layer.weight
        if is_transpose:
            weight.data = weight.data.transpose(-2, -1)
        if is_nz and layer.weight.dtype != torch.float32:
            weight.data = torch_npu.npu_format_cast(weight.data.contiguous(), 29)  # 29: format nz
        layer.weight = Parameter(weight, requires_grad=False)


class LinearBase(torch.nn.Module):
    """Base linear layer.

    Args:
        input_size: input dimension of the linear layer.
        output_size: output dimension of the linear layer.
        bias: If true, add bias.
        skip_bias_add: If true, skip adding bias but instead return it.
        params_dtype: Data type for the parameters.
        quant_config: Quantization configure.
        return_bias: If true, return bias together with outputs in forward pass.
    """

    def __init__(
        self,
        input_size: int,
        output_size: int,
        skip_bias_add: bool = False,
        params_dtype: Optional[torch.dtype] = None,
        quant_config: Optional = None,
        prefix: str = "",
        *,
        return_bias: Optional[bool] = False,
    ):
        super().__init__()

        # Keep input parameters
        self.input_size = input_size
        self.output_size = output_size
        self.skip_bias_add = skip_bias_add
        if params_dtype is None:
            params_dtype = torch.get_default_dtype()
        self.params_dtype = params_dtype
        if quant_config is None:
            self.quant_method: Optional[
                QuantizeMethodBase] = UnquantizedLinearMethod()
        else:
            self.quant_method = quant_config.get_quant_method(self,
                                                              prefix=prefix)
        self.return_bias = return_bias

    def forward(
        self, input_: torch.Tensor
    ) -> Union[torch.Tensor, tuple[torch.Tensor, Optional[Parameter]]]:
        raise NotImplementedError


class ColumnParallelLinear(LinearBase):
    """Linear layer with column parallelism.

    The linear layer is defined as Y = XA + b. A is parallelized along
    its second dimension as A = [A_1, ..., A_p].

    Args:
        input_size: first dimension of matrix A.
        output_size: second dimension of matrix A.
        bias: If true, add bias.
        tp_size: The size of the tensor parallel communication domain
                 where the current device is located.
        tp_rank: The rank index of current device in the located tensor parallel
                 communication domain.
        skip_bias_add: This was added to enable performance optimizations where
                       bias can be fused with other element-wise operations. we
                       skip adding bias but instead return it.
        params_dtype: Data type for the parameters.
        quant_config: Quantization configure.
        output_sizes: list of output sizes packed into one output, like for QKV
                       the list would be size 3.
        prefix: The name of the layer in the state dict, including all parents
                        (e.g. model.layers.0.q_b_proj)
        return_bias: If true, return bias together with outputs in forward pass.
    """

    def __init__(
        self,
        input_size: int,
        output_size: int,
        bias: bool = False,
        tp_size: int = 1,
        tp_rank: int = 0,
        skip_bias_add: bool = False,
        params_dtype: Optional[torch.dtype] = None,
        quant_config: Optional = None,
        output_sizes: Optional[list[int]] = None,
        prefix: str = "",
        *,
        return_bias: Optional[bool] = False,
    ):
        # Divide the weight matrix along the last dimension.
        self.tp_size = tp_size
        self.tp_rank = tp_rank
        self.input_size_per_partition = input_size
        self.output_size_per_partition = divide(output_size, self.tp_size)
        self.output_partition_sizes = [self.output_size_per_partition]
        # If QKV or MergedColumn, use output size of each partition.
        if hasattr(self, "output_sizes"):
            self.output_partition_sizes = [
                divide(output_size, self.tp_size)
                for output_size in self.output_sizes
            ]

        super().__init__(input_size,
                         output_size,
                         skip_bias_add,
                         params_dtype,
                         quant_config,
                         prefix,
                         return_bias=return_bias,
                         )

        if output_sizes is None:
            output_sizes = [output_size]

        if self.quant_method is None:
            raise RuntimeError("quant method cannnot be none")
        self.quant_method.create_weights(
            layer=self,
            input_size_per_partition=self.input_size_per_partition,
            output_partition_sizes=self.output_partition_sizes,
            input_size=self.input_size,
            output_size=self.output_size,
            params_dtype=self.params_dtype,
            weight_loader=self.weight_loader)
        if bias:
            self.bias = Parameter(
                torch.empty(self.output_size_per_partition,
                            dtype=params_dtype))
            set_weight_attrs(self.bias, {
                "output_dim": 0,
                "weight_loader": self.weight_loader,
            })
        else:
            self.register_parameter("bias", None)

    def weight_loader(self, param: Parameter, loaded_weight: torch.Tensor):
        output_dim = getattr(param, "output_dim", None)

        is_sharded_weight = getattr(param, "is_sharded_weight", False)
        use_bitsandbytes_4bit = getattr(param, "use_bitsandbytes_4bit", False)
        # bitsandbytes loads the weights of the specific portion
        # no need to narrow
        is_sharded_weight = is_sharded_weight or use_bitsandbytes_4bit

        param_data = param.data
        if output_dim is not None and not is_sharded_weight:
            shard_size = param_data.shape[output_dim]
            start_idx = self.tp_rank * shard_size
            loaded_weight = loaded_weight.narrow(output_dim, start_idx,
                                                 shard_size)

        # Special case for loading scales off disk, which often do not
        # have a shape.
        if len(loaded_weight.shape) == 0:
            loaded_weight = loaded_weight.reshape(1)

        if param_data.shape != loaded_weight.shape:
            raise RuntimeError(
                f"Tried to load weights of shape {loaded_weight.shape}"
                f"to a parameter of shape {param_data.shape}")
        param_data.copy_(loaded_weight)

    def forward(
        self, input_, dynamic_scale=None, out_dtype=torch.bfloat16
    ) -> Union[torch.Tensor, tuple[torch.Tensor, Optional[Parameter]]]:
        bias = self.bias if not self.skip_bias_add else None

        # Matrix multiply.
        if self.quant_method is None:
            raise RuntimeError("quant method cannnot be none")
        output = self.quant_method.apply(self,
                                         x=input_,
                                         bias=bias,
                                         dynamic_scale=dynamic_scale,
                                         out_dtype=out_dtype)
        output_bias = self.bias if self.skip_bias_add else None
        if not self.return_bias:
            return output
        return output, output_bias

    def extra_repr(self) -> str:
        s = f"in_features={self.input_size}"
        s += f", output_features={self.output_size_per_partition}"
        s += f", bias={self.bias is not None}"
        s += f", tp_size={self.tp_size}"
        return s


class VocabParallelEmbedding(nn.Embedding):
    """Embedding parallelized in the vocabulary dimension.

    Adapted from torch.nn.Embedding, note that we pad the vocabulary size to
    make sure it is divisible by the number of model parallel NPUs.

    Args:
        vocab_size: Vocabulary size.
        hidden_size: Second dimension of matrix A.
        padding_idx: The index of the padding token.
        params_dtype: Data type for the parameters.
        tp_size: The size of the tensor parallel communication domain
                 where the current device is located.
        tp_rank: The rank index of current device in the located tensor parallel
                 communication domain.
    """
    def __init__(
        self,
        vocab_size,
        hidden_size,
        padding_idx,
        params_dtype,
        tp_size=1,
        tp_rank=0,
    ):
        self.tp_size = tp_size
        self.tp_rank = tp_rank
        self.input_size = vocab_size
        self.input_size_per_partition = divide(vocab_size, self.tp_size)
        shard_start_idx = self.tp_rank * self.input_size_per_partition
        shard_end_idx = shard_start_idx + self.input_size_per_partition
        local_padding_idx = None
        if padding_idx is not None and shard_start_idx <= padding_idx < shard_end_idx:
            local_padding_idx = padding_idx - shard_start_idx

        super().__init__(self.input_size_per_partition,
                         hidden_size,
                         local_padding_idx,
                         dtype=params_dtype)
        self.output_size_per_partition = hidden_size
        self.output_size = hidden_size
        self.output_partition_sizes = [hidden_size]
        self.params_dtype = params_dtype
        self.weight.requires_grad_(False)
        set_weight_attrs(self.weight, {"input_dim": 0, "output_dim": 1})
        set_weight_attrs(self.weight, {"weight_loader": self.weight_loader})

    def weight_loader(self, param: Parameter, loaded_weight: torch.Tensor):
        input_dim = getattr(param, "input_dim", None)
        use_bitsandbytes_4bit = getattr(param, "use_bitsandbytes_4bit", False)

        param_data = param.data
        # bitsandbytes loads the weights of the specific portion
        # no need to narrow here
        if input_dim is not None and not use_bitsandbytes_4bit:
            shard_size = param_data.shape[input_dim]
            start_idx = self.tp_rank * shard_size
            loaded_weight = loaded_weight.narrow(input_dim, start_idx,
                                                 shard_size)

        # Special case for loading scales off disk, which often do not
        # have a shape.
        if len(loaded_weight.shape) == 0:
            loaded_weight = loaded_weight.reshape(1)

        if param_data.shape != loaded_weight.shape:
            raise RuntimeError("param_data.shape != loaded_weight.shape")
        param_data.copy_(loaded_weight)


class ReplicatedLinear(LinearBase):
    """Replicated linear layer.

    Args:
        input_size: input dimension of the linear layer.
        output_size: output dimension of the linear layer.
        bias: If true, add bias.
        skip_bias_add: If true, skip adding bias but instead return it.
        params_dtype: Data type for the parameters.
        quant_config: Quantization configure.
        prefix: The name of the layer in the state dict, including all parents
                        (e.g. model.layers.0.gate)
        return_bias: If true, return bias together with outputs in forward pass.
    """

    def __init__(
        self,
        input_size: int,
        output_size: int,
        bias: bool = False,
        skip_bias_add: bool = False,
        params_dtype: Optional[torch.dtype] = None,
        quant_config: Optional = None,
        prefix: str = "",
        *,
        return_bias: bool = False,
    ):
        super().__init__(input_size,
                         output_size,
                         skip_bias_add,
                         params_dtype,
                         quant_config,
                         prefix=prefix,
                         return_bias=return_bias,
                         )

        # All the linear layer supports quant method.
        if self.quant_method is None:
            raise RuntimeError("quant method cannnot be none")
        self.quant_method.create_weights(self,
                                         self.input_size, [self.output_size],
                                         self.input_size,
                                         self.output_size,
                                         self.params_dtype,
                                         weight_loader=self.weight_loader)

        if bias:
            self.bias = Parameter(
                torch.empty(self.output_size, dtype=self.params_dtype))
            set_weight_attrs(self.bias, {
                "output_dim": 0,
                "weight_loader": self.weight_loader,
            })
        else:
            self.register_parameter("bias", None)

    def weight_loader(self, param: Parameter, loaded_weight: torch.Tensor):
        if len(loaded_weight.shape) == 0:
            loaded_weight = loaded_weight.reshape(1)

        if param.size() != loaded_weight.size():
            raise RuntimeError(
                f"Tried to load weights of size {loaded_weight.size()}"
                f"to a parameter of size {param.size()}")
        param.data.copy_(loaded_weight)

    def forward(
        self, input_: torch.Tensor, dynamic_scale=None, out_dtype=torch.bfloat16
    ) -> Union[torch.Tensor, tuple[torch.Tensor, Optional[Parameter]]]:
        bias = self.bias if not self.skip_bias_add else None
        if self.quant_method is None:
            raise RuntimeError("quant method cannnot be none")
        output = self.quant_method.apply(self,
                                         x=input_,
                                         bias=bias,
                                         dynamic_scale=dynamic_scale,
                                         out_dtype=out_dtype)
        output_bias = self.bias if self.skip_bias_add else None
        if not self.return_bias:
            return output
        return output, output_bias

    def extra_repr(self) -> str:
        s = f"in_features={self.input_size}"
        s += f", output_features={self.output_size}"
        s += f", bias={self.bias is not None}"
        return s


class MergedColumnParallelLinear(LinearBase):
    """Linear layer with column parallelism.

    The linear layer is defined as Y = XA + b. A is parallelized along
    its second dimension as A = [A_1, ..., A_p]. A is concatenated by two
    weight matrices along second dimension.

    Args:
        input_size: first dimension of matrix A.
        output_sizes: list of output sizes packed into one output, like for QKV
                      the list would be size 3.
        bias: If true, add bias.
        skip_bias_add: This was added to enable performance optimizations where
                       bias can be fused with other element-wise operations. we
                       skip adding bias but instead return it.
        tp_size: The size of the tensor parallel communication domain
                 where the current device is located.
        tp_rank: The rank index of current device in the located tensor parallel
                 communication domain.
        params_dtype: Data type for the parameters.
        quant_config: Quantization configure.
        prefix: The name of the layer in the state dict, including all parents
                        (e.g. model.layers.0.mlp.merge_up_gate_proj)
        return_bias: If true, return bias together with outputs in forward pass.
    """
    def __init__(self,
                 input_size: int,
                 output_sizes: List[int],
                 bias: bool = False,
                 skip_bias_add: bool = False,
                 tp_size: int = 1,
                 tp_rank: int = 0,
                 params_dtype: Optional[torch.dtype] = None,
                 quant_config: Optional = None,
                 prefix: str = "",
                 return_bias: bool = False,
                 ):
        self.output_sizes = output_sizes
        self.tp_size = tp_size
        if not all(output_size % tp_size == 0 for output_size in output_sizes):
            raise RuntimeError("All output_sizes must be divisible by tp_size")
        self.tp_rank = tp_rank
        self.quant_config = quant_config
        output_size = sum(output_sizes)
        super().__init__(input_size,
                         output_size,
                         skip_bias_add,
                         params_dtype,
                         quant_config,
                         prefix,
                         return_bias=return_bias,
                         )
        if self.quant_method is None:
            raise RuntimeError("self.quant_method must not be None")
        # Divide the weight matrix along the last dimension.
        self.output_size_per_partition = divide(self.output_size, tp_size)
        self.output_partition_sizes = [self.output_size_per_partition]
        # If QKV or MergedColumn, use output size of each partition.
        if hasattr(self, "output_sizes"):
            self.output_partition_sizes = [
                divide(output_size, self.tp_size)
                for output_size in self.output_sizes
            ]
        output_sizes = [output_size]

        self.quant_method.create_weights(
            layer=self,
            input_size_per_partition=self.input_size,
            output_partition_sizes=self.output_partition_sizes,
            input_size=self.input_size,
            output_size=self.output_size,
            params_dtype=self.params_dtype,
            weight_loader=self.weight_loader)
        if bias:
            self.bias = Parameter(
                torch.empty(self.output_size_per_partition,
                            dtype=params_dtype))
            set_weight_attrs(self.bias, {
                "output_dim": 0,
                "weight_loader": self.weight_loader,
            })
        else:
            self.register_parameter("bias", None)
        self.throw_dequant = True

    def forward(self, input_, dynamic_scale=None, out_dtype=torch.bfloat16):
        bias = self.bias if not self.skip_bias_add else None

        # Matrix multiply.
        if self.quant_method is None:
            raise RuntimeError("self.quant_method must not be None")
        output = self.quant_method.apply(self,
                                         x=input_,
                                         bias=bias,
                                         dynamic_scale=dynamic_scale,
                                         out_dtype=out_dtype)
        output_bias = self.bias if self.skip_bias_add else None
        if not self.return_bias:
            return output
        return output, output_bias

    def weight_loader(self,
                      param: Parameter,
                      loaded_weight: torch.Tensor,
                      loaded_shard_id: Optional[int] = None):

        param_data = param.data
        output_dim = getattr(param, "output_dim", None)
        is_per_block_scale = getattr(param, "is_per_block_scale", False)
        # Special case for per-tensor scale to load scalar into fused array.
        needs_scalar_to_array = getattr(param, "needs_scalar_to_array", False)

        if loaded_shard_id is None:
            # Loaded weight is already fused on disk (qkv/mlp).
            if output_dim is None:
                if param_data.shape != loaded_weight.shape:
                    raise RuntimeError("param_data.shape != loaded_weight.shape")
                param_data.copy_(loaded_weight)
                return
            current_shard_offset = 0
            shard_offsets: List[Tuple[int, int, int]] = []
            for i, output_size in enumerate(self.output_sizes):
                shard_offsets.append((i, current_shard_offset, output_size))
                current_shard_offset += output_size
            packed_dim = getattr(param, "packed_dim", None)
            for shard_id, shard_offset, shard_size in shard_offsets:
                # Special case for Quantization.
                # If quantized, we need to adjust the offset and size to account
                # for the packing.
                if packed_dim == output_dim:
                    shard_size = shard_size // param.pack_factor
                    shard_offset = shard_offset // param.pack_factor

                loaded_weight_shard = loaded_weight.narrow(
                    output_dim, shard_offset, shard_size)
                self.weight_loader(param, loaded_weight_shard, shard_id)
            return

        if loaded_shard_id >= len(self.output_sizes):
            raise RuntimeError("loaded_shard_id must be less than the length of self.output_sizes")
        if output_dim is not None:
            if is_per_block_scale:
                block_size = self.quant_config.weight_block_size[0]
                shard_offset = math.ceil(sum(self.output_sizes[:loaded_shard_id]) / block_size) // self.tp_size
                shard_size = math.ceil(self.output_sizes[loaded_shard_id] / block_size) // self.tp_size
            else:
                shard_offset = sum(self.output_sizes[:loaded_shard_id]) // self.tp_size
                shard_size = self.output_sizes[loaded_shard_id] // self.tp_size
            # Special case for quantization.
            # If quantized, we need to adjust the offset and size to account
            # for the packing.
            packed_dim = getattr(param, "packed_dim", None)
            if packed_dim == output_dim:
                shard_size = shard_size // param.pack_factor
                shard_offset = shard_offset // param.pack_factor

            use_bitsandbytes_4bit = getattr(param, "use_bitsandbytes_4bit",
                                            False)
            if use_bitsandbytes_4bit:
                shard_size = loaded_weight.shape[output_dim]
                shard_offset = loaded_weight.shape[output_dim] * \
                    loaded_shard_id

            param_data = param_data.narrow(output_dim, shard_offset,
                                           shard_size)
            start_idx = self.tp_rank * shard_size
            # bitsandbytes loads the weights of the specific portion
            # no need to narrow here
            if not use_bitsandbytes_4bit:
                loaded_weight = loaded_weight.narrow(output_dim, start_idx,
                                                     shard_size)

        else:
            ignore_warning = getattr(param, "ignore_warning", False)
            if not ignore_warning:
                logger.warning(
                    "Loading a weight without `output_dim` attribute in "
                    "MergedColumnParallelLinear, assume the weight is "
                    "the same for all partitions.")

        if param_data.shape != loaded_weight.shape:
            raise RuntimeError("param_data.shape != loaded_weight.shape")
        param_data.copy_(loaded_weight)


class RowParallelLinear(LinearBase):
    """Linear layer with row parallelism.

    The linear layer is defined as Y = XA + b. A is parallelized along
    its first dimension and X along its second dimension as:
               -   -
              | A_1 |
              | .   |
          A = | .   |        X = [X_1, ..., X_p]
              | .   |
              | A_p |
               -   -
    Arguments:
        input_size: first dimension of matrix A.
        output_size: second dimension of matrix A.
        bias: If true, add bias. Note that bias is not parallelized.
        tp_size: The size of the tensor parallel communication domain
                 where the current device is located.
        tp_rank: The rank index of current device in the located tensor parallel
                 communication domain.
        input_is_parallel: If true, we assume that the input is already
                           split across the Npus and we do not split
                           again.
        skip_bias_add: This was added to enable performance optimization where
                       bias can be fused with other element-wise operations.
                       We skip adding bias but instead return it.
        params_dtype: Data type for the parameters.
        quant_config: Quantization configure.
        prefix: The name of the layer in the state dict, including all parents
                        (e.g. model.layers.0.o_proj)
        return_bias: If true, return bias together with outputs in forward pass.
    """
    def __init__(self,
                 input_size: int,
                 output_size: int,
                 bias: bool = False,
                 tp_size: int = 1,
                 tp_rank: int = 0,
                 input_is_parallel: bool = True,
                 skip_bias_add: bool = False,
                 params_dtype: Optional[torch.dtype] = None,
                 quant_config: Optional = None,
                 prefix: str = "",
                 return_bias: bool = False):
        super().__init__(input_size,
                         output_size,
                         skip_bias_add,
                         params_dtype,
                         quant_config,
                         prefix,
                         )

        if self.quant_method is None:
            raise RuntimeError("self.quant_method must not be None")

        self.input_is_parallel = input_is_parallel

        self.tp_size = tp_size
        self.tp_rank = tp_rank
        # Divide the weight matrix along the last dimension.
        self.input_size_per_partition = divide(input_size, self.tp_size)
        self.output_size_per_partition = output_size
        self.output_partition_sizes = [output_size]

        self.quant_method.create_weights(
            layer=self,
            input_size_per_partition=self.input_size_per_partition,
            output_partition_sizes=self.output_partition_sizes,
            input_size=self.input_size,
            output_size=self.output_size,
            params_dtype=self.params_dtype,
            weight_loader=self.weight_loader)

        if bias:
            self.bias = Parameter(
                torch.empty(self.output_size, dtype=params_dtype))
            set_weight_attrs(self.bias, {
                "output_dim": 0,
                "weight_loader": self.weight_loader,
            })
        else:
            self.register_parameter("bias", None)

    def weight_loader(self, param: Parameter, loaded_weight: torch.Tensor):
        input_dim = getattr(param, "input_dim", None)
        use_bitsandbytes_4bit = getattr(param, "use_bitsandbytes_4bit", False)

        param_data = param.data
        # bitsandbytes loads the weights of the specific portion
        # no need to narrow here
        if input_dim is not None and not use_bitsandbytes_4bit:
            shard_size = param_data.shape[input_dim]
            start_idx = self.tp_rank * shard_size
            loaded_weight = loaded_weight.narrow(input_dim, start_idx,
                                                 shard_size)

        # Special case for loading scales off disk, which often do not
        # have a shape.
        if len(loaded_weight.shape) == 0:
            loaded_weight = loaded_weight.reshape(1)

        if param_data.shape != loaded_weight.shape:
            raise RuntimeError("param_data.shape != loaded_weight.shape")
        param_data.copy_(loaded_weight)

    def forward(self, input_, dynamic_scale=None, out_dtype=torch.bfloat16):
        if self.input_is_parallel:
            input_parallel = input_
        else:
            splitted_input = split_tensor_along_last_dim(
                input_, num_partitions=self.tp_size)
            input_parallel = splitted_input[self.tp_rank].contiguous()

        # Matrix multiply.
        if self.quant_method is None:
            raise RuntimeError("self.quant_method is None")
        # Only fuse bias add into matmul for rank 0 (this ensures that
        # bias will not get added more than once in TP>1 case)
        bias_ = None if (self.tp_rank > 0 or self.skip_bias_add) else self.bias
        output = self.quant_method.apply(self,
                                         x=input_parallel,
                                         bias=bias_,
                                         dynamic_scale=dynamic_scale,
                                         out_dtype=out_dtype)

        output_bias = self.bias if self.skip_bias_add else None
        if not self.return_bias:
            return output
        return output, output_bias

    def extra_repr(self) -> str:
        s = f"input_features={self.input_size_per_partition}"
        s += f", output_features={self.output_size}"
        s += f", bias={self.bias is not None}"
        s += f", tp_size={self.tp_size}"
        return s


class NpuLinear(nn.Module):
    def __init__(self, in_feature, out_feature, bias: bool = False, dtype: torch.dtype = torch.bfloat16):
        super().__init__()
        self.weight = nn.Parameter(torch.empty((out_feature, in_feature), dtype=dtype), requires_grad=False)
        self.bias = None
        if bias is not None and bias:
            self.bias = nn.Parameter(torch.empty((out_feature,), dtype=dtype, required_grad=False))

    def forward(self, x):
        origin_shape = x.size()
        x = x.view(-1, origin_shape[-1])
        out = torch.matmul(x, self.weight.data)
        if self.bias is not None:
            out = out + self.bias
        out = out.view(*origin_shape[:-1], -1)
        return out


class DynamicW8A8Linear(nn.Module):
    def __init__(self, in_feature, out_feature, bias=False, offset=False, dtype=torch.bfloat16):
        super().__init__()
        self.in_feature, self.out_feature = in_feature, out_feature
        self.weight = Parameter(torch.ones((out_feature, in_feature), dtype=torch.int8), requires_grad=False)
        if bias:
            self.bias = Parameter(torch.ones((out_feature,), dtype=dtype))
        else:
            self.bias = None
        self.smooth_scales = Parameter(torch.ones(self.in_feature, dtype=dtype), requires_grad=False)
        self.weight_scale = Parameter(torch.ones(self.out_feature, dtype=dtype), requires_grad=False)
        if offset:
            self.offset = Parameter(torch.ones(self.out_feature, dtype=dtype), requires_grad=False)
        else:
            self.offset = None


    def forward(self, x, dynamic_scale=None, out_dtype=torch.bfloat16):
        if dynamic_scale is not None:
            x_scale = dynamic_scale
        else:
            x, x_scale = torch_npu.npu_dynamic_quant(x, smooth_scales=self.smooth_scales)
        out_shape = x.size()[:-1] + (self.out_feature, )
        x = x.view(-1, x.size(-1))
        x_scale = x_scale.view(-1)
        x = torch_npu.npu_quant_matmul(x, self.weight,
                                    self.weight_scale.view(-1),
                                    pertoken_scale=None if out_dtype == torch.int32 else x_scale,
                                    bias=self.bias,
                                    output_dtype=out_dtype)
        x = x.view(out_shape)
        if out_dtype == torch.int32:
            return x, x_scale
        else:
            return x


class DynamicW8A8MoeFFN(nn.Module):
    def __init__(self, hidden_size, intermediate_size, expert_num, dtype=torch.bfloat16):
        super().__init__()
        self.dtype = dtype
        self.hidden_size = hidden_size
        self.intermediate_size = intermediate_size

        self.group_w1_w3 = Parameter(
            torch.empty((expert_num, self.intermediate_size * 2, self.hidden_size),
                dtype=torch.int8), requires_grad=False)
        self.group_w2 = Parameter(
            torch.empty((expert_num, self.hidden_size, self.intermediate_size),
                dtype=torch.int8), requires_grad=False)

        _, self.out_feature_1, self.in_feature_1 = self.group_w1_w3.size()
        _, self.out_feature_2, self.in_feature_2 = self.group_w2.size()

        self.smooth_scale_1 = Parameter(torch.ones((expert_num, self.in_feature_1), dtype=dtype), requires_grad=False)
        self.group_w1_w3_scale = Parameter(
            torch.ones(size=(expert_num, self.out_feature_1), dtype=dtype), requires_grad=False)
        self.smooth_scale_2 = Parameter(torch.ones((expert_num, self.in_feature_2), dtype=dtype), requires_grad=False)
        self.group_w2_scale = Parameter(
            torch.ones(size=(expert_num, self.out_feature_2), dtype=dtype), requires_grad=False)


    def forward(self, x, expert_tokens, group_list_type=0, pertoken_scale=None):
        hidden_size = x.size(-1)

        if pertoken_scale is None:
            x, pertoken_scale = torch_npu.npu_dynamic_quant(x)

        if pertoken_scale.dim() > 1:
            pertoken_scale = pertoken_scale.reshape(-1)
            x = x.view(-1, hidden_size)

        mm1_mm3 = torch_npu.npu_grouped_matmul([x], [self.group_w1_w3],
                                                group_list=expert_tokens, split_item=3,
                                                output_dtype=torch.int32, group_type=0,
                                                group_list_type=group_list_type,
                                                tuning_config=[0]
                                                )[0]

        intermediate_h, pertoken_scale = torch_npu.npu_dequant_swiglu_quant(
            mm1_mm3, weight_scale=self.group_w1_w3_scale,
            quant_scale=self.smooth_scale_2,
            group_index=expert_tokens,
            activate_left=True,
            quant_mode=1,
            activation_scale=pertoken_scale
            )

        out_hidden = torch_npu.npu_grouped_matmul(
            [intermediate_h], [self.group_w2], bias=None,
            scale=[self.group_w2_scale], per_token_scale=[pertoken_scale],
            group_list=expert_tokens, split_item=3,
            output_dtype=self.dtype, group_type=0,
            group_list_type=group_list_type,
            tuning_config=[0]
        )[0]

        return out_hidden


class QKVParallelLinear(ColumnParallelLinear):
    """Linear layers for the attention's QKV transformation.

    Linear layers for the linear transformation of the query, key, and value
    vectors in the attention layer. The weight matrix is concatenated along
    the output dimension. The layer is parallelized along the head dimension.
    When the number of key/value heads is smaller than the number of query
    heads (e.g., multi-query/grouped-query attention), the key/value head may
    be replicated while the query heads are partitioned.

    Args:
        hidden_size: input hidden state size of the transformer.
        head_size: size of each attention head.
        total_num_heads: total number of attention query heads.
        total_num_kv_heads: total number of attention key/value heads. If
                            None, assume total_num_kv_heads = total_num_heads.
        bias: If true, add bias.
        skip_bias_add: This was added to enable performance optimizations where
                       bias can be fused with other element-wise operations. we
                       skip adding bias but instead return it.
        tp_size: The size of the tensor parallel communication domain
                 where the current device is located.
        tp_rank: The rank index of current device in the located tensor parallel
                 communication domain.
        params_dtype: Data type for the parameters.
        quant_config: Quantization configure.
        prefix: The name of the layer in the state dict, including all parents
                        (e.g. model.layers.0.qkv_proj)
        return_bias: If true, return bias together with outputs in forward pass.
    """

    def __init__(
        self,
        hidden_size: int,
        head_size: int,
        total_num_heads: int,
        total_num_kv_heads: Optional[int] = None,
        bias: bool = True,
        skip_bias_add: bool = False,
        tp_size: int = 1,
        tp_rank: int = 0,
        params_dtype: Optional[torch.dtype] = None,
        quant_config: Optional[QuantizationConfig] = None,
        prefix: str = "",
        *,
        return_bias: bool = True):
        self.hidden_size = hidden_size
        self.head_size = head_size
        self.total_num_heads = total_num_heads
        if total_num_kv_heads is None:
            total_num_kv_heads = total_num_heads
        self.total_num_kv_heads = total_num_kv_heads
        # Divide the weight matrix along the last dimension.
        self.tp_size = tp_size
        self.tp_rank = tp_rank
        self.num_heads = divide(self.total_num_heads, tp_size)
        if tp_size >= self.total_num_kv_heads:
            self.num_kv_heads = 1
            self.num_kv_head_replicas = divide(tp_size,
                                               self.total_num_kv_heads)
        else:
            self.num_kv_heads = divide(self.total_num_kv_heads, tp_size)
            self.num_kv_head_replicas = 1
        input_size = self.hidden_size
        output_size = (self.num_heads +
                       2 * self.num_kv_heads) * tp_size * self.head_size
        self.output_sizes = [
            self.num_heads * self.head_size * tp_size,  # q_proj
            self.num_kv_heads * self.head_size * tp_size,  # k_proj
            self.num_kv_heads * self.head_size * tp_size,  # v_proj
        ]

        super().__init__(input_size=input_size,
                         output_size=output_size,
                         bias=bias,
                         tp_size=tp_size,
                         tp_rank=tp_rank,
                         skip_bias_add=skip_bias_add,
                         params_dtype=params_dtype,
                         quant_config=quant_config,
                         prefix=prefix,
                         return_bias=return_bias,
                         )

    def weight_loader(self,
                      param: Parameter,
                      loaded_weight: torch.Tensor,
                      loaded_shard_id: Optional[str] = None):

        param_data = param.data
        output_dim = getattr(param, "output_dim", None)

        # Special case for per-tensor scales in fused case.
        needs_scalar_to_array = getattr(param, "needs_scalar_to_array", False)

        if loaded_shard_id is None:
            # Loaded weight is already fused on disk (qkv).
            # (e.g., Phi-3's qkv_proj).
            if output_dim is None:
                assert param_data.shape == loaded_weight.shape
                param_data.copy_(loaded_weight)
                return
            shard_offsets = [
                # (shard_id, shard_offset, shard_size)
                ("q", 0, self.total_num_heads * self.head_size),
                ("k", self.total_num_heads * self.head_size,
                 self.total_num_kv_heads * self.head_size),
                ("v", (self.total_num_heads + self.total_num_kv_heads) *
                 self.head_size, self.total_num_kv_heads * self.head_size),
            ]

            packed_dim = getattr(param, "packed_dim", None)
            for shard_id, shard_offset, shard_size in shard_offsets:
                # Special case for Quantized Weights.
                # If quantized, we need to adjust the offset and size to account
                # for the packing.
                if packed_dim == output_dim:
                    shard_size = shard_size // param.pack_factor
                    shard_offset = shard_offset // param.pack_factor

                loaded_weight_shard = loaded_weight.narrow(
                    output_dim, shard_offset, shard_size)
                self.weight_loader(param, loaded_weight_shard, shard_id)
            return

        assert loaded_shard_id in ["q", "k", "v"]

        # If output dim is defined, use the default loading process.
        if output_dim is not None:
            if loaded_shard_id == "q":
                shard_offset = 0
                shard_size = self.num_heads * self.head_size
            elif loaded_shard_id == "k":
                shard_offset = self.num_heads * self.head_size
                shard_size = self.num_kv_heads * self.head_size
            elif loaded_shard_id == "v":
                shard_offset = (self.num_heads +
                                self.num_kv_heads) * self.head_size
                shard_size = self.num_kv_heads * self.head_size
            packed_dim = getattr(param, "packed_dim", None)
            if packed_dim == output_dim:
                shard_size = shard_size // param.pack_factor
                shard_offset = shard_offset // param.pack_factor

            is_sharded_weight = getattr(param, "is_sharded_weight", False)
            # no need to narrow
            is_sharded_weight = is_sharded_weight

            param_data = param_data.narrow(output_dim, shard_offset,
                                           shard_size)
            if loaded_shard_id == "q":
                shard_id = self.tp_rank
            else:
                shard_id = self.tp_rank // self.num_kv_head_replicas
            start_idx = shard_id * shard_size

            if not is_sharded_weight:
                loaded_weight = loaded_weight.narrow(output_dim, start_idx,
                                                     shard_size)

        else:
            ignore_warning = getattr(param, "ignore_warning", False)
            if not ignore_warning:
                logger.warning(
                    "Loading a weight without `output_dim` attribute in "
                    "QKVParallelLinear, assume the weight is the same "
                    "for all partitions.")

        assert param_data.shape == loaded_weight.shape
        param_data.copy_(loaded_weight)
