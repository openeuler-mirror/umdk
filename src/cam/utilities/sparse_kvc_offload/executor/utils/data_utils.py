# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

import json
import os
import logging
import math
from datasets import load_dataset  # requires version == 3.6.0

logger = logging.getLogger(__name__)


def load_infinitebench_dataset(data_path):
    prompts = []
    datasets = ["longbook_qa_eng.jsonl"]
    data = load_dataset(data_path, data_files=datasets, split="train", trust_remote_code=True)
    for d in data:
        prompts.append(d['context'])
    return prompts


def load_longbench_dataset(data_path):
    prompts = []
    datasets = ["narrativeqa", "qasper", "multifieldqa_en", "multifieldqa_zh", "hotpotqa", "2wikimqa", "musique", \
                "dureader", "gov_report", "qmsum", "multi_news", "vcsum", "trec", "triviaqa", "samsum", "lsht", \
                "passage_count", "passage_retrieval_en", "passage_retrieval_zh", "lcc", "repobench-p"]
    datasets_e = ["qasper", "multifieldqa_en", "hotpotqa", "2wikimqa", "gov_report", "multi_news", "trec", \
                  "triviaqa", "samsum", "passage_count", "passage_retrieval_en", "lcc", "repobench-p"]
    datasets_e = [item + "_e" for item in datasets_e]

    for dataset in datasets + datasets_e:
        data = load_dataset(data_path, dataset, split='test', trust_remote_code=True)
        for d in data:
            prompts.append(d['context'])
    return prompts


def generate_default_prompt(dataset_dir):
    json_path = os.path.join(dataset_dir, "default_prompt.json")
    json_path = os.path.abspath(json_path)
    try:
        with open(json_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            text = data["text"]
    except FileNotFoundError as e:
        raise FileNotFoundError(f"prompt error: prompt file({json_path}) not find.") from e
    except json.JSONDecodeError as e:
        logger.error(f"prompt error: the json format of prompt file({json_path}) is incorrect.")
        raise e
    except Exception as e:
        raise e
    if isinstance(text, list):
        preset_prompts = text
    else:
        preset_prompts = [text]
    return preset_prompts


def get_prompts_for_cur_rank(preset_prompts, global_bs, batch_size_per_rank, global_dp_rank):
    preset_prompts = preset_prompts * (global_bs // len(preset_prompts) + 1)
    preset_prompts = preset_prompts[global_dp_rank * batch_size_per_rank: (global_dp_rank + 1) * batch_size_per_rank]
    query_id_list = list(range(global_dp_rank * batch_size_per_rank, (global_dp_rank + 1) * batch_size_per_rank))
    logger.info(f"prompt batch size: {len(preset_prompts)}/{global_bs}, {query_id_list=}")
    return (preset_prompts, query_id_list)


def generate_prompt(runner_settings):
    batch_size = runner_settings.get("data_config").get("batch_size", 1)
    attn_tp_size = runner_settings.get("parallel_config").get("attn_tp_size", 1)
    cp_size = runner_settings.get("parallel_config").get("cp_size", 1)
    global_rank = int(os.getenv("RANK_ID", 0))
    bs_per_cp_group = runner_settings.get("data_config").get("bs_per_cp_group", 1)
    dataset = runner_settings.get("data_config").get("dataset", "default")
    kvp_size = runner_settings.get("parallel_config").get("kvp_size", 1)
    world_size = int(os.getenv("WORLD_SIZE", "1"))
    global_dp_rank = global_rank // max(cp_size, kvp_size) // attn_tp_size
    if cp_size > 1:
        batch_size_per_rank = bs_per_cp_group
    else:
        batch_size_per_rank = runner_settings.get("data_config").get("batch_size_per_rank", 1)

    cur_dir = os.path.dirname(__file__)
    dataset_path = os.path.join(cur_dir, "../../dataset")
    if dataset == "default":
        preset_prompts = generate_default_prompt(dataset_path)
    elif dataset == "LongBench":
        dataset_path = os.path.abspath(os.path.join(dataset_path, f"{dataset}"))
        if os.path.isdir(dataset_path): # use local LongBench dataset first
            dataset = dataset_path
        else:
            dataset = "THUDM/LongBench"
        preset_prompts = load_longbench_dataset(dataset)
    elif dataset == "InfiniteBench":
        dataset_path = os.path.abspath(os.path.join(dataset_path, f"{dataset}"))
        if os.path.isdir(dataset_path): # use local InfiniteBench dataset first
            dataset = dataset_path
        preset_prompts = load_infinitebench_dataset(dataset)
    else:
        raise Exception(f"your dataset {dataset} is not supported, dataset supported: LongBench, InfiniteBench")
    return get_prompts_for_cur_rank(preset_prompts, batch_size, batch_size_per_rank, global_dp_rank)


def tokenizer_in_loop(tokenizer, prompts, input_max_len=32, section_size=1024):
    total_num = len(prompts)
    if section_size <= 0:
        raise ValueError(f"section_size must be positive, but got {section_size}.")
    section_num = math.ceil(total_num / section_size)
    input_ids_list = []
    for i in range(section_num):
        start_index = i * section_size
        end_index = (i + 1) * section_size
        each_prompts = prompts[start_index: end_index]
        prompts_input_ids = tokenizer(each_prompts, truncation=True, max_length=input_max_len,
                                      return_attention_mask=False).input_ids
        input_ids_list.extend(prompts_input_ids)
        logger.info(f"{len(input_ids_list)} of {total_num} prompts have been tokenized...")
    return input_ids_list


def build_dataset_input(tokenizer, prompts, input_max_len, max_new_tokens=32, is_chat=False):
    # Provide system prompt for the text; the default is aritcle continuation, which can be modified as needed.
    prefix = "Please read a part of the book below, and then give me the summary.\n[start of the book]\n"
    suffix = "\n[end of the book]\n\n" + \
            "Now you have read it. Please summarize it for me. " + \
            f"First, tell me the title and the author, and then tell the story in {max_new_tokens} words.\n\n "
    if is_chat:
        system_prompt_chat = [{"role": "user", "content": prefix + suffix}]
        system_prompt_len = len(tokenizer.apply_chat_template(
                                system_prompt_chat,
                                add_generation_prompt=True,
                                return_dict=False,
                                tokenize=True
                            ))
    else:
        system_prompt_len = len(tokenizer(prefix + suffix).input_ids)
    if system_prompt_len > input_max_len:
        logger.info("The parameter 'input_max_len' should be greater than the length of system prompt. " + \
         "Please modify the input_max_len in the YAML file or modify system prompt in executor/utils/data_utils.py.")

    # use tokenizer loop to avoid host oom when query num is large
    input_ids_list = tokenizer_in_loop(tokenizer, prompts, input_max_len)

    out_prompts = []
    for prompt_input_ids in input_ids_list:
        prompt = prefix + \
            tokenizer.decode(prompt_input_ids[:input_max_len - system_prompt_len], skip_special_tokens=True) + \
            suffix
        out_prompts.append(prompt)
    return out_prompts
