# SPDX-License-Identifier: MIT
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

add_executable(urma_api_fuzz
    urma_api_fuzz.c
)
target_link_libraries(urma_api_fuzz PRIVATE urma_test_common ${URMA_SO} ${URMA_COMMON_SO}
    nl-genl-3 nl-3 dl rt pthread)

add_executable(uvs_api_fuzz
    uvs_api_fuzz.c
)
target_link_libraries(uvs_api_fuzz PRIVATE urma_test_common ${URMA_TPSA_SO} ${URMA_COMMON_SO}
    nl-genl-3 nl-3 dl rt pthread)

add_custom_target(urma_fuzz
    DEPENDS urma_api_fuzz uvs_api_fuzz
)

add_test(NAME urma_api_fuzz COMMAND urma_api_fuzz)
set_tests_properties(urma_api_fuzz PROPERTIES LABELS "phase_fuzz;phase_fuzz_urma")

add_test(NAME uvs_api_fuzz COMMAND uvs_api_fuzz)
set_tests_properties(uvs_api_fuzz PROPERTIES LABELS "phase_fuzz;phase_fuzz_uvs")

find_program(CLANG_BIN clang)
if(CLANG_BIN)
    set(URMA_LIBFUZZER_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/libfuzzer)
    file(MAKE_DIRECTORY ${URMA_LIBFUZZER_OUTPUT_DIR})
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -print-file-name=libasan.so
        OUTPUT_VARIABLE URMA_GCC_LIBASAN
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(EXISTS "${URMA_GCC_LIBASAN}")
        set(URMA_LIBFUZZER_ENV "LD_PRELOAD=${URMA_GCC_LIBASAN}")
    else()
        set(URMA_LIBFUZZER_ENV "")
    endif()

    add_custom_command(
        OUTPUT ${URMA_LIBFUZZER_OUTPUT_DIR}/urma_api_libfuzzer
        COMMAND ${CLANG_BIN}
            -DURMA_LIBFUZZER
            -I${CMAKE_CURRENT_LIST_DIR}/../include
            -I${URMA_COMMON_INCLUDE_DIR}
            -I${URMA_CORE_DIR}
            -I${URMA_CORE_INCLUDE_DIR}
            -I${URMA_BOND_DIR}
            -I${URMA_BOND_UTILS_DIR}
            -I${URMA_BOND_DIR}/include
            -I${URMA_UVS_CORE_DIR}
            -I${URMA_UVS_INCLUDE_DIR}
            -Wall -Werror -O1 -g -fsanitize=fuzzer
            ${CMAKE_CURRENT_LIST_DIR}/urma_api_fuzz.c
            -L${URMA_BUILD_DIR}/urma/lib/urma/core
            -L${URMA_BUILD_DIR}/urma/common
            -lurma -lurma_common -lnl-genl-3 -lnl-3 -ldl -lrt -lpthread
            -Wl,-rpath,${URMA_BUILD_DIR}/urma/lib/urma/core
            -Wl,-rpath,${URMA_BUILD_DIR}/urma/common
            -o ${URMA_LIBFUZZER_OUTPUT_DIR}/urma_api_libfuzzer
        DEPENDS urma_api_fuzz
        VERBATIM
    )

    add_custom_command(
        OUTPUT ${URMA_LIBFUZZER_OUTPUT_DIR}/uvs_api_libfuzzer
        COMMAND ${CLANG_BIN}
            -DURMA_LIBFUZZER
            -I${CMAKE_CURRENT_LIST_DIR}/../include
            -I${URMA_COMMON_INCLUDE_DIR}
            -I${URMA_CORE_DIR}
            -I${URMA_CORE_INCLUDE_DIR}
            -I${URMA_BOND_DIR}
            -I${URMA_BOND_UTILS_DIR}
            -I${URMA_BOND_DIR}/include
            -I${URMA_UVS_CORE_DIR}
            -I${URMA_UVS_INCLUDE_DIR}
            -Wall -Werror -O1 -g -fsanitize=fuzzer
            ${CMAKE_CURRENT_LIST_DIR}/uvs_api_fuzz.c
            -L${URMA_BUILD_DIR}/urma/lib/uvs/core
            -L${URMA_BUILD_DIR}/urma/common
            -ltpsa -lurma_common -lnl-genl-3 -lnl-3 -ldl -lrt -lpthread
            -Wl,-rpath,${URMA_BUILD_DIR}/urma/lib/uvs/core
            -Wl,-rpath,${URMA_BUILD_DIR}/urma/common
            -o ${URMA_LIBFUZZER_OUTPUT_DIR}/uvs_api_libfuzzer
        DEPENDS uvs_api_fuzz
        VERBATIM
    )

    add_custom_target(urma_libfuzzer ALL
        DEPENDS
            ${URMA_LIBFUZZER_OUTPUT_DIR}/urma_api_libfuzzer
            ${URMA_LIBFUZZER_OUTPUT_DIR}/uvs_api_libfuzzer
    )
    add_dependencies(urma_fuzz urma_libfuzzer)

    add_test(NAME urma_api_libfuzzer_smoke
        COMMAND ${URMA_LIBFUZZER_OUTPUT_DIR}/urma_api_libfuzzer -runs=128 -max_len=8)
    set_tests_properties(urma_api_libfuzzer_smoke PROPERTIES
        LABELS "phase_fuzz;phase_libfuzzer"
        ENVIRONMENT "${URMA_LIBFUZZER_ENV}"
    )

    add_test(NAME uvs_api_libfuzzer_smoke
        COMMAND ${URMA_LIBFUZZER_OUTPUT_DIR}/uvs_api_libfuzzer -runs=64 -max_len=8)
    set_tests_properties(uvs_api_libfuzzer_smoke PROPERTIES
        LABELS "phase_fuzz;phase_libfuzzer"
        ENVIRONMENT "${URMA_LIBFUZZER_ENV}"
    )
endif()
