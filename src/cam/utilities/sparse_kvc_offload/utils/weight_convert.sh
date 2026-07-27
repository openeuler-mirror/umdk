# coding=utf-8
# Copyright (c) 2025 Huawei Technologies Co., Ltd.
# This program is free software, you can redistribute it and/or modify it under the terms and conditions of
# CANN Open Software License Agreement Version 2.0 (the "License").
# Please refer to the License for details. You may not use this file except in compliance with the License.
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY, OR FITNESS FOR A PARTICULAR PURPOSE.
# See LICENSE in the root of the software repository for the full text of the License.

#!/bin/bash
INPUT_FP8_HF_PATH=""
OUTPUT_HF_PATH=""
QUANT_MODE=""


while [[ $# -gt 0 ]]; do
    case $1 in
        --input_fp8_hf_path)
            INPUT_FP8_HF_PATH="$2"
            shift 2
            ;;
        --output_hf_path)
            OUTPUT_HF_PATH="$2"
            shift 2
            ;;
        --quant_mode)
            QUANT_MODE="$2"
            shift 2
            ;;
        *)
            echo "Unknown Parameters: $1"
            echo "Usage: $0 --input_fp8_hf_path <input_path> --output_hf_path <output_path> --quant_mode <mode>"
            echo "Supported Quant Mode: bfloat16, w8a8c16, w8a8c8, w4a8c8"
            exit 1
            ;;
    esac
done


if [[ -z "$INPUT_FP8_HF_PATH" ]] || [[ -z "$OUTPUT_HF_PATH" ]] || [[ -z "$QUANT_MODE" ]]; then
    echo "Usage: $0 --input_fp8_hf_path <input_path> --output_hf_path <output_path> --quant_mode <mode>"
    echo "Supported Quant Mode: bfloat16, w8a8c16, w8a8c8, w4a8c8"
    exit 1
fi


case "${QUANT_MODE,,}" in
    bfloat16)
        echo "Convert to bfloat16 weights..."
        python utils/convert_model.py \
            --input_fp8_hf_path "$INPUT_FP8_HF_PATH" \
            --output_hf_path "$OUTPUT_HF_PATH"
        ;;
    w8a8c16)
        echo "Convert to w8a8c16 weights..."
        python utils/convert_model.py \
            --input_fp8_hf_path "$INPUT_FP8_HF_PATH" \
            --output_hf_path "$OUTPUT_HF_PATH" \
            --quant_type "w8a8c16"
        ;;
    w8a8c8)
        export QUANT_URL=https://cann-ai.obs.cn-north-4.myhuaweicloud.com/cann-quantization/DeepSeek-V3.2-Exp/w8a8c8.zip
        mkdir -p ./quantization

        # Download the quantization zip file
        if ! wget --no-check-certificate -P ./quantization "$QUANT_URL"; then
            echo "Error: Failed to download quantization parameters from $QUANT_URL"
            exit 1
        fi

        # Unzip the file
        echo "Extracting quantization parameters..."
        if ! unzip -o "./quantization/w8a8c8.zip" -d ./quantization; then
            echo "Error: Failed to extract ./quantization/w8a8c8.zip"
            exit 1
        fi

        echo "Convert to w8a8c8 weights..."
        python utils/convert_model.py \
            --input_fp8_hf_path "$INPUT_FP8_HF_PATH" \
            --output_hf_path "$OUTPUT_HF_PATH" \
            --quant_type "w8a8c8" \
            --clip \
            --quant_param_path "./quantization/w8a8c8"
        ;;
    w4a8c8)
        export QUANT_URL=https://cann-ai.obs.cn-north-4.myhuaweicloud.com/cann-quantization/DeepSeek-V3.2-Exp/w4a8c8.zip
        mkdir -p ./quantization

        # Download the quantization zip file
        if ! wget --no-check-certificate -P ./quantization "$QUANT_URL"; then
            echo "Error: Failed to download quantization parameters from $QUANT_URL"
            exit 1
        fi

        # Unzip the file
        echo "Extracting quantization parameters..."
        if ! unzip -o "./quantization/w4a8c8.zip" -d ./quantization; then
            echo "Error: Failed to extract ./quantization/w4a8c8.zip"
            exit 1
        fi

        echo "Convert to w4a8c8 weights..."
        python utils/convert_model.py \
            --input_fp8_hf_path "$INPUT_FP8_HF_PATH" \
            --output_hf_path "$OUTPUT_HF_PATH" \
            --quant_type "w4a8c8" \
            --clip \
            --quant_param_path "./quantization/w4a8c8"
        ;;
    *)
        echo "Error: Unsupport Quant_mode: $QUANT_MODE"
        echo "Supported Mode: bfloat16, w8a8c16, w8a8c8, w4a8c8"
        exit 1
        ;;
esac

echo "Output path: $OUTPUT_HF_PATH"