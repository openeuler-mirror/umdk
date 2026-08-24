#!/bin/bash
#
# AIGW E2E Benchmark Script
# 自动启动 mock 服务和 AIGW，运行测试，最后清理进程
#

set -e

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
K8S_PORT=18080
WORKER_BASE_PORT=19000
AIGW_PORT=8888
NUM_WORKERS=4
DP_SIZE=2
NAMESPACE="vllm"
MODEL="test-model"
AIGW_CONFIG="$SCRIPT_DIR/test_config.json"

# 进程跟踪
MOCK_PID=""
AIGW_PID=""

# 颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 清理函数
cleanup() {
    log_info "清理进程..."

    # 关闭 Mock 服务器
    if [ -n "$MOCK_PID" ] && kill -0 "$MOCK_PID" 2>/dev/null; then
        log_info "关闭 Mock 服务器 (PID: $MOCK_PID)"
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi

    # 关闭 AIGW
    if [ -n "$AIGW_PID" ] && kill -0 "$AIGW_PID" 2>/dev/null; then
        log_info "关闭 AIGW (PID: $AIGW_PID)"
        kill "$AIGW_PID" 2>/dev/null || true
        wait "$AIGW_PID" 2>/dev/null || true
    fi

    # 清理可能的残留端口
    for port in $K8S_PORT $WORKER_BASE_PORT $((WORKER_BASE_PORT+1)) $((WORKER_BASE_PORT+2)) $((WORKER_BASE_PORT+3)) $AIGW_PORT; do
        local pids=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | sort -u)
        if [ -n "$pids" ]; then
            for pid in $pids; do
                if [ "$pid" != "$$" ]; then
                    log_warning "清理残留进程 PID $pid (端口 $port)"
                    kill "$pid" 2>/dev/null || true
                fi
            done
        fi
    done

    log_success "清理完成"
}

# 设置退出时清理
trap cleanup EXIT

# 检查端口是否可用
check_port_available() {
    local port=$1
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        return 1
    fi
    return 0
}

# 等待端口就绪
wait_port() {
    local port=$1
    local timeout=${2:-30}
    local desc=${3:-"服务"}

    log_info "等待 $desc 就绪 (端口 $port)..."
    for i in $(seq 1 $timeout); do
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            log_success "$desc 已就绪 (端口 $port)"
            return 0
        fi
        sleep 1
    done
    log_error "$desc 未就绪 (端口 $port) 超时"
    return 1
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."

    # Python3
    if ! command -v python3 &>/dev/null; then
        log_error "python3 未安装"
        exit 1
    fi

    # curl
    if ! command -v curl &>/dev/null; then
        log_error "curl 未安装"
        exit 1
    fi

    # AIGW 二进制
    if [ ! -f "$ROOT_DIR/output/aigw/aigw" ]; then
        log_error "AIGW 可执行文件不存在: $ROOT_DIR/output/aigw/aigw"
        log_info "请先运行 build.sh 编译 AIGW"
        exit 1
    fi

    # 测试配置
    if [ ! -f "$AIGW_CONFIG" ]; then
        log_error "测试配置文件不存在: $AIGW_CONFIG"
        exit 1
    fi

    # Mock 服务器脚本
    if [ ! -f "$SCRIPT_DIR/mock_e2e_server.py" ]; then
        log_error "Mock 服务器脚本不存在: $SCRIPT_DIR/mock_e2e_server.py"
        exit 1
    fi

    # 测试客户端脚本
    if [ ! -f "$SCRIPT_DIR/test_e2e_client.py" ]; then
        log_error "测试客户端脚本不存在: $SCRIPT_DIR/test_e2e_client.py"
        exit 1
    fi

    log_success "依赖检查通过"
}

# 启动 Mock 服务器
start_mock_server() {
    log_info "启动 Mock 服务器..."

    # 检查端口是否可用
    for port in $K8S_PORT $WORKER_BASE_PORT $((WORKER_BASE_PORT+1)) $((WORKER_BASE_PORT+2)) $((WORKER_BASE_PORT+3)); do
        if ! check_port_available $port; then
            log_error "端口 $port 已被占用"
            return 1
        fi
    done

    # 启动 Mock 服务器
    python3 "$SCRIPT_DIR/mock_e2e_server.py" \
        --k8s-port $K8S_PORT \
        --worker-base-port $WORKER_BASE_PORT \
        --num-workers $NUM_WORKERS \
        --dp-size $DP_SIZE \
        --namespace $NAMESPACE \
        --model $MODEL \
        > /tmp/mock_server.log 2>&1 &

    MOCK_PID=$!
    log_info "Mock 服务器已启动 (PID: $MOCK_PID)"

    # 等待 K8s API 就绪
    wait_port $K8S_PORT 30 "K8s Mock API" || return 1

    # 等待 Worker 就绪
    for i in $(seq 0 $((NUM_WORKERS-1))); do
        wait_port $((WORKER_BASE_PORT+i)) 10 "Worker $i" || return 1
    done

    log_success "Mock 服务器启动完成"
    return 0
}

# 启动 AIGW
start_aigw() {
    log_info "启动 AIGW..."

    # 检查端口是否可用
    if ! check_port_available $AIGW_PORT; then
        log_error "端口 $AIGW_PORT 已被占用"
        return 1
    fi

    # 启动 AIGW (使用 --config=path 参数指定配置文件)
    cd "$ROOT_DIR/output/aigw"
    ./aigw --config="$AIGW_CONFIG" > /tmp/aigw.log 2>&1 &
    AIGW_PID=$!
    cd "$SCRIPT_DIR"

    log_info "AIGW 已启动 (PID: $AIGW_PID)"

    # 等待 AIGW 就绪
    wait_port $AIGW_PORT 30 "AIGW" || return 1

    # 检查健康状态
    sleep 2
    if curl -s "http://127.0.0.1:${AIGW_PORT}/aigw/v1/health" | grep -q "ok\|healthy\|UP"; then
        log_success "AIGW 健康检查通过"
    else
        log_warning "AIGW 健康检查未返回预期响应，但服务已启动"
    fi

    log_success "AIGW 启动完成"
    return 0
}

# 运行测试客户端
run_test_client() {
    log_info "运行测试客户端..."
    echo ""
    echo "=============================================="
    echo "E2E 测试客户端"
    echo "=============================================="
    echo ""

    python3 "$SCRIPT_DIR/test_e2e_client.py" \
        --aigw-host 127.0.0.1 \
        --aigw-port $AIGW_PORT \
        --model $MODEL

    local result=$?
    echo ""
    if [ $result -eq 0 ]; then
        log_success "测试客户端完成"
    else
        log_error "测试客户端失败 (退出码: $result)"
    fi
    return $result
}

# 运行验证脚本
run_verify_script() {
    log_info "运行验证脚本..."
    echo ""
    echo "=============================================="
    echo "E2E 验证脚本"
    echo "=============================================="
    echo ""

    bash "$SCRIPT_DIR/verify_e2e.sh"

    local result=$?
    echo ""
    if [ $result -eq 0 ]; then
        log_success "验证脚本完成"
    else
        log_error "验证脚本失败 (退出码: $result)"
    fi
    return $result
}

# 显示日志摘要
show_log_summary() {
    log_info "日志摘要"
    echo ""

    if [ -f /tmp/mock_server.log ]; then
        echo "--- Mock Server 日志 (最后 20 行) ---"
        tail -20 /tmp/mock_server.log
        echo ""
    fi

    if [ -f /tmp/aigw.log ]; then
        echo "--- AIGW 日志 (最后 20 行) ---"
        tail -20 /tmp/aigw.log
        echo ""
    fi
}

# 主函数
main() {
    echo "=============================================="
    echo "AIGW E2E Benchmark"
    echo "=============================================="
    echo ""
    echo "配置:"
    echo "  K8s Port:        $K8S_PORT"
    echo "  Worker Base:     $WORKER_BASE_PORT"
    echo "  Num Workers:     $NUM_WORKERS"
    echo "  DP Size:         $DP_SIZE"
    echo "  AIGW Port:       $AIGW_PORT"
    echo "  Model:           $MODEL"
    echo "  Namespace:       $NAMESPACE"
    echo ""

    # 检查依赖
    check_dependencies

    # 启动 Mock 服务器
    start_mock_server || {
        log_error "Mock 服务器启动失败"
        show_log_summary
        exit 1
    }

    echo ""

    # 启动 AIGW
    start_aigw || {
        log_error "AIGW 启动失败"
        show_log_summary
        exit 1
    }

    echo ""

    # 运行测试
    local test_result=0

    # 运行测试客户端
    if ! run_test_client; then
        test_result=1
    fi

    echo ""

    # 运行验证脚本
    if ! run_verify_script; then
        test_result=1
    fi

    echo ""

    # 显示日志摘要
    show_log_summary

    # 结果
    echo "=============================================="
    echo "Benchmark 结果"
    echo "=============================================="
    if [ $test_result -eq 0 ]; then
        log_success "所有测试通过!"
    else
        log_error "存在测试失败"
    fi
    echo ""

    return $test_result
}

# 运行
main "$@"
