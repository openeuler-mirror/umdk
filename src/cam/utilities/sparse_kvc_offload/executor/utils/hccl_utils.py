# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import logging
import math
import os
from typing import Optional

import torch
import torch_npu
import torch.distributed as dist
from torch.distributed.distributed_c10d import _world

logger = logging.getLogger(__name__)

from executor.utils import align_up

WIN_ADDR_ALIGN = 512
MB_SIZE = 1024 * 1024
SCALE_EXPAND_IDX_BUFFER = 44
UB_ALIGN = 32
FULL_MESH_DATA_ALIGN = 480


def get_default_group():
    return _world._default_pg


def get_group_name(comm_group, global_rank):
    return None if comm_group is None\
        else comm_group._get_backend(torch.device("npu")).get_hccl_comm_name(global_rank)


def get_global_routed_expert_num(config) -> Optional[int]:
    """Normalize the config field used as the global routed expert count for MoE EP buffer sizing."""
    if hasattr(config, "n_routed_experts"):
        return config.n_routed_experts
    if hasattr(config, "num_experts"):
        return config.num_experts
    return None


created_group = {}


def init_comm_group_by_ranks(
    ranks,
    global_rank,
    group_name="unknown",
    hccl_buffer_size=None,
    group_type=None,
    platform_version="A3",
    return_name=False,
):
    """Pure low-level HCCL group builder.

    Given an explicit ranks list and HCCL parameters, build one HCCL
    ProcessGroup and optionally return its HCCL comm name.  All business-side
    decisions (None/default_pg shortcuts, signature-based reuse, string
    whitelist) live in ``CommManager`` — this helper only answers "how to
    create", not "whether to create / reuse".

    Pre-conditions (enforced by the caller, typically ``CommManager``):
    - ``len(ranks) >= 2``.  Single-rank subgroups should be resolved to
      ``None`` before reaching this helper.
    - ``ranks`` is the full subgroup ranks list, identical across all world
      ranks (torch collective contract for ``dist.new_group``).

    Args:
        ranks: All global ranks forming this subgroup.
        global_rank: Caller's global rank, only used for HCCL comm name.
        group_name: Logical group name, used only for logging.
        hccl_buffer_size: HCCL buffer size in MB.  ``None`` falls back to the
            ``HCCL_BUFFSIZE`` env var (default 200).
        group_type: ``hccl_op_expansion_mode``.  ``None`` means unspecified;
            values >= 1 map to specific expansion modes (1 hostcpu_ts,
            2 aicpu_ts, 3 aiv, 4 aiv_only, 5 ccu_ms, 6 ccu_sch, 7 aicpu_ub).
        platform_version: "A3" or "950".  On 950, ``HCCL_BUFFSIZE`` env is
            rewritten to match the per-group buffer size.
        return_name: If True, return ``(group, hccl_comm_name)``.

    Returns:
        The ``dist.ProcessGroup`` for the current rank's view of this
        subgroup, or ``(group, name)`` when ``return_name`` is True.
    """
    if hccl_buffer_size is None:
        hccl_buffer_size = int(os.environ.get("HCCL_BUFFSIZE", 200))

    options = torch_npu._C._distributed_c10d.ProcessGroupHCCL.Options()
    options.hccl_config = {"hccl_buffer_size": hccl_buffer_size}
    if group_type is not None:
        options.hccl_config["hccl_op_expansion_mode"] = group_type
    if platform_version == "950":
        os.environ["HCCL_BUFFSIZE"] = str(hccl_buffer_size)

    logger.info(
        f"init_comm_group_by_ranks: group={group_name} action=new_group ranks={list(ranks)} "
        f"buffer_size={hccl_buffer_size}MB group_type={group_type} "
        f"platform_version={platform_version}"
    )
    group = dist.new_group(list(ranks), pg_options=options)
    if return_name and global_rank in ranks:
        return group, get_group_name(group, global_rank)
    if return_name:
        return group, None
    return group


def init_comm_group(
    global_rank,
    group_num,
    world_size,
    group_stride=1,
    group_name="default",
    hccl_buffer_size=None,
    return_name=False,
    group_type=None, # 1：hostcpu_ts 2 aicpu_ts 3:aiv 4:aiv_only 5:ccu_ms 6:ccu_sch 7 aicpu_ub 0 default
    platform_version="A3",
):
    # Respect HCCL_BUFFSIZE env var when caller doesn't pass an explicit size.
    # ProcessGroupHCCL options.hccl_config does NOT read the env var, so
    # without this fallback an `export HCCL_BUFFSIZE=...` from launch scripts
    # has no effect on moe_ep groups created via comm_manager.
    if hccl_buffer_size is None:
        hccl_buffer_size = int(os.environ.get("HCCL_BUFFSIZE", 200))
    group_size = world_size // group_num
    default_pg = get_default_group()

    cur_group_set = None
    for group_id in range(group_num):
        if group_stride == 1:
            start_rank_id = group_id * group_size
            init_rank_id = global_rank // group_size * group_size
        else:
            start_rank_id = group_id
            init_rank_id = global_rank % group_num

        cur_group_list = [start_rank_id + i * group_stride for i in range(group_size)]
        if default_pg is not None and group_type is None:
            # fullmesh v2, communication for Expert Parallelism shall be exclusively occupied
            if group_num == world_size and "moe_ep_group" not in group_name:
                cur_group = None
            elif group_num == 1 and "moe_ep_group" not in group_name:
                cur_group = default_pg
            else:
                logging.info(f"group:{group_name} create default type comm group")
                options = torch_npu._C._distributed_c10d.ProcessGroupHCCL.Options()
                options.hccl_config = {"hccl_buffer_size": hccl_buffer_size}
                if platform_version == "950":
                    os.environ["HCCL_BUFFSIZE"] = str(hccl_buffer_size)
                cur_group = dist.new_group(cur_group_list, pg_options=options)
        elif group_type is not None:
            global created_group
            if group_type == 0:
                logging.info(f"group:{group_name} create default type comm group")
                cur_group = default_pg
            else:
                if group_name not in created_group.keys():
                    logging.info(f"group:{group_name} create type {group_type} comm group")
                    options = torch_npu._C._distributed_c10d.ProcessGroupHCCL.Options()
                    options.hccl_config = {"hccl_op_expansion_mode": group_type}
                    options.hccl_config = {"hccl_buffer_size": hccl_buffer_size}
                    if platform_version == "950":
                        os.environ["HCCL_BUFFSIZE"] = str(hccl_buffer_size)
                    cur_group = dist.new_group(cur_group_list, pg_options=options)
                    created_group[group_name] = cur_group
                else:
                    logging.info(f"group:{group_name} has already been created")
                    cur_group = created_group.get(group_name, None)
                    assert cur_group is not None
        else:
            cur_group = None

        if start_rank_id == init_rank_id:
            cur_group_set = cur_group
            logger.info(f"group_name is {group_name}, group_list: {cur_group_list}")
    logger.info(f"{group_name} hccl comm init rank_id: {global_rank}")
    if not return_name:
        return cur_group_set
    else:
        logger.info(f"{group_name} hccl comm init in else branch rank_id: {global_rank}")
        comm_name = get_group_name(cur_group_set, global_rank)
        logger.info(f"{group_name} rank_{global_rank} hccl comm init in else branch comm_name: {comm_name}")
        return cur_group_set, comm_name


def calc_moe_hccl_buffer_size(
        runner_settings,
        config,
        is_full_mesh_v2=False):
    """
    calc hccl buffer size (MB) for MoE Dispatch and Combine ops.
    runner_settings accepts either legacy runner_settings dict or refactored InferenceConfig.
    formula:
      not full_mesh_v2:
        (localMoeExpertNum * maxBs * ep_worldsize * align512(ceil480(align32(2*h)+44)) +
         (top_k + shardExpertNum) * maxBs * align512(2*h)) * 2 / 1024 / 1024
      full_mesh_v2:
        (localMoeExpertNum * maxBs * ep_worldsize * align512(align32(2*h)+44) +
         (top_k + shardExpertNum) * maxBs * align512(2*h)) * 2 / 1024 / 1024
    """
    default_hccl_buffsize = 200 # MB
    # Temporary compatibility layer for the framework refactor:
    # legacy ModelRunner passes a runner_settings dict, while the refactored
    # framework passes InferenceConfig directly.  Keep the parsing split here
    # so the MC2 buffer formula below remains shared by both paths.
    if isinstance(runner_settings, dict):
        # Legacy ModelRunner path: parse values from runner_settings.
        data_config = runner_settings.get("data_config", {})
        model_config = runner_settings.get("model_config", {})
        parallel_config = runner_settings.get("parallel_config", {})
        world_size = runner_settings.get("world_size", 16)
        batch_size = data_config.get("batch_size", 16)
        next_n = model_config.get("next_n", 0)
        moe_ep_size = parallel_config.get("moe_ep_size", 1)
        platform_version = model_config.get("platform_version", "A3")
    else:
        # Refactored executor path: parse values from InferenceConfig.
        world_size = runner_settings.parallel_config.world_size
        batch_size = runner_settings.scheduler_config.batch_size
        next_n = runner_settings.model_config.next_n
        moe_ep_size = runner_settings.parallel_config.moe_ep_size
        platform_version = runner_settings.model_config.platform_version
    spec_len = next_n + 1

    total_experts = get_global_routed_expert_num(config)
    if total_experts is None:
        raise AttributeError(
            f"{type(config).__name__} does not provide n_routed_experts or num_experts"
        )
    experts_per_rank = total_experts // moe_ep_size
    hidden_size = config.hidden_size
    top_k = config.num_experts_per_tok
    shared_expert_rank_num = 0 # route and share on same card = 0

    bs_per_rank = batch_size // world_size * spec_len
    if not is_full_mesh_v2:
        token_need_size_dispatch = align_up(align_up(2 * hidden_size, UB_ALIGN) +
                                 SCALE_EXPAND_IDX_BUFFER, WIN_ADDR_ALIGN)
    else:
        token_need_size_dispatch = math.ceil(2 * hidden_size / FULL_MESH_DATA_ALIGN) * WIN_ADDR_ALIGN
    dispatch_size = experts_per_rank * bs_per_rank * world_size * token_need_size_dispatch
    combine_size = (top_k + shared_expert_rank_num) * bs_per_rank * \
                    align_up(2 * hidden_size, WIN_ADDR_ALIGN)
    moe_buffer_size = (dispatch_size + combine_size) * 2 / MB_SIZE  # MB
    moe_buffer_size = math.ceil(moe_buffer_size) + 11  # add win size

    # use default value if moe_buffer_size is small than default_hccl_buffersize
    if moe_buffer_size <= default_hccl_buffsize:
        hccl_buffer_size = default_hccl_buffsize
    else:
        hccl_buffer_size = moe_buffer_size

    logger.info(f"batch_size:{batch_size} world_size:{world_size} moe_ep_size:{moe_ep_size}")
    logger.info(f"experts_per_rank:{experts_per_rank} hidden_size:{hidden_size} spec_len:{spec_len}")
    logger.info(f"dispatch_size:{dispatch_size} combine_size:{combine_size}")
    logger.info(f"hccl_buffer_size:{hccl_buffer_size} (MB) moe_buffer_size:{moe_buffer_size} (MB)")

    return hccl_buffer_size
