# qbuf_pool_tool: standalone file-driven test driver for umq multi-level
# size_class qbuf pool. Independent CMake project — does NOT require the top-
# level hcom cmake config, BUILD_TESTS=ON, or gtest/mockcpp. Build from repo
# root with:
#   cmake -S test/urpc/umq/qbuf_pool_tool -B build_qbuf_tool
#   cmake --build build_qbuf_tool -j
cmake_minimum_required(VERSION 3.14)
# Enable both C and CXX: the tool's .cpp TUs (stubs/utils/core/main) call into
# umq_qbuf_pool.c / umq_qbuf_pool_base.c / umq_dfx_api_str.c which are C sources
# compiled with the C compiler (umq_qbuf_pool.c uses GNU extensions via
# urpc_util.h, expects C linkage).
project(qbuf_pool_tool C CXX)

# Resolve repo root: this dir is test/urpc/umq/qbuf_pool_tool (5 levels up)
get_filename_component(UMDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)

# Sources:
# - stubs.cpp: extern C stubs (umq_qbuf_alloc / huge_qbuf_pool_info_get / tiny_qbuf_pool_info_get)
# - utils.cpp: pure parsers
# - core.cpp: tool state + dispatcher (worker threads, alloc/free/info/status)
# - main.cpp: script reader + command dispatcher
# - umq_dfx_api_str.c: DFX to_str (string-conversion) — pulled in so the tool
#   can call umq_qbuf_pool_stats_to_str() without dragging in umq_inner.h /
#   perf.h from umq_dfx_api.c (which holds the *_get() funcs that depend on the
#   transport-layer chain). The tool provides its own umq_stats_qbuf_pool_get
#   wrapper in stubs.cpp (forwards to umq_qbuf_pool_info_get directly).
# - umq_qbuf_pool.c + umq_qbuf_pool_base.c: umq pool impl (init/alloc/free/
#   info_get + multi-level size_class state). Compiled into the tool target
#   (replaces the previous #include "umq_qbuf_pool.c" approach in core.cpp so
#   the tool no longer reaches into production static state).
add_executable(qbuf_pool_tool
    stubs.cpp
    utils.cpp
    core.cpp
    main.cpp
    ${UMDK_ROOT}/src/urpc/umq/umq_dfx_api_str.c
    ${UMDK_ROOT}/src/urpc/umq/qbuf/umq_qbuf_pool.c
    ${UMDK_ROOT}/src/urpc/umq/qbuf/umq_qbuf_pool_base.c
    ${UMDK_ROOT}/src/urpc/umq/qbuf/umq_rx_qbuf_pool.c
    ${UMDK_ROOT}/src/urpc/umq/qbuf/umq_tiny_qbuf_pool.c
    ${UMDK_ROOT}/src/urpc/util/urpc_thread_closure.cpp
    ${UMDK_ROOT}/src/urpc/util/urpc_id_generator.c
    ${UMDK_ROOT}/src/urpc/util/urpc_bitmap.c
    ${UMDK_ROOT}/src/urpc/util/urpc_dbuf_stat.c
    ${UMDK_ROOT}/src/urpc/util/util_lock.c)
target_include_directories(qbuf_pool_tool PRIVATE
    ${UMDK_ROOT}/src/urpc/umq/qbuf
    ${UMDK_ROOT}/src/urpc/umq
    ${UMDK_ROOT}/src/urpc/include/umq
    ${UMDK_ROOT}/src/urpc/include
    ${UMDK_ROOT}/src/urpc/include/umq/transport_layer
    ${UMDK_ROOT}/src/urpc/include/umq/umq_ub
    ${UMDK_ROOT}/src/urpc/include/framework
    ${UMDK_ROOT}/src/urpc/util)
# gnu++11 (not strict c++11): umq_qbuf_pool.c pulls in urpc_util.h which uses
# the GNU 'typeof' extension; strict c++11 rejects it on some toolchains.
# .c files use gnu11 (C), .cpp files use gnu++11 (C++). The C source TUs
# (umq_qbuf_pool.c / umq_qbuf_pool_base.c / umq_dfx_api_str.c) carry GNU
# extensions too.
target_compile_options(qbuf_pool_tool PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=gnu++11>
    $<$<COMPILE_LANGUAGE:C>:-std=gnu11>
    -D_GNU_SOURCE
    -DUMQ_QBUF_DEBUG
    -g)
target_link_libraries(qbuf_pool_tool rt pthread dl)

# Stub for util_log_ctx_get (needed by urpc_dbuf_stat.c)
target_sources(qbuf_pool_tool PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/util_log_stub.c)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/util_log_stub.c
    "#include <stddef.h>\nvoid *util_log_ctx_get(void) { return NULL; }\n")
