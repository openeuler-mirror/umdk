#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
# Description: snc building script
# Create: 2026-05-29
# Note:
# History: 2025-05-29 create snc building script

# SNC 项目构建脚本
# 用于构建 Java 库项目并生成 JAR 包

# 项目根目录
BASE_DIR=$(cd "$(dirname "$0")/../.." && pwd)
SNC_DIR="$BASE_DIR/src/snc"
BUILD_DIR="$BASE_DIR/build/snc"

# 检查 Maven 版本
check_maven() {
    local version
    version=$(mvn -v | head -n 1 | awk '{print $3}')
    
    if [[ -z "$version" ]]; then
        echo "Error: Maven 未安装或未配置环境变量"
        exit 1
    fi

    echo "Mavne 版本: $version"
}

# 检查 JDK 版本
check_jdk() {
    local version
    version=$(java -version 2>&1 | awk -F'"' '/version/ {print $2}')
    
    if [[ -z "$version" ]]; then
        echo "Error: JDK 未安装或未配置环境变量"
        exit 1
    fi

    echo "JDK 版本: $version"
}

# 执行构建
build() {
    echo "开始构建 SNC 项目..."
    
    cd "$SNC_DIR" || {
        echo "Error: 无法进入目录: $SNC_DIR"
        exit 1
    }
    
    # 执行 Maven 打包
    if [[ "$SKIP_TEST" == "true" ]]; then
        echo "跳过测试，执行打包..."
        mvn clean package -DskipTests
    else
        echo "执行完整构建（包含测试）..."
        mvn clean package
    fi
    
    if [[ $? -eq 0 ]]; then
        echo "构建成功！"
        
        # 复制产物到 build 目录
        mkdir -p "$BUILD_DIR/output"
        cp "$SNC_DIR/target/snc-*.jar" "$BUILD_DIR/output/" 2>/dev/null || true
        
        echo "构建产物已复制到: $BUILD_DIR/output/"
        ls -la "$BUILD_DIR/output/"
    else
        echo "Error: 构建失败！"
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    echo "SNC 项目构建脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help      显示此帮助信息"
    echo "  -s, --skip-test 跳过测试构建"
    echo "  -c, --clean     仅清理构建产物"
    echo ""
    echo "示例:"
    echo "  $0                  # 完整构建（包含测试）"
    echo "  $0 -s               # 跳过测试构建"
    echo "  $0 -c               # 清理构建产物"
}

# 清理构建
clean() {
    echo "清理构建产物..."
    
    cd "$SNC_DIR" || {
        echo "Error: 无法进入目录: $SNC_DIR"
        exit 1
    }
    
    mvn clean
    
    if [[ -d "$BUILD_DIR/output" ]]; then
        rm -rf "$BUILD_DIR/output"
    fi
    
    echo "清理完成"
}

# 主函数
main() {
    # 默认不跳过测试
    SKIP_TEST="false"
    
    # 解析命令行参数
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -s|--skip-test)
                SKIP_TEST="true"
                ;;
            -c|--clean)
                clean
                exit 0
                ;;
            *)
                echo "Error: 未知选项: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
    
    # 检查依赖
    echo "检查构建环境..."
    check_maven
    check_jdk
    
    # 执行构建
    build
}

# 执行主函数
main "$@"
