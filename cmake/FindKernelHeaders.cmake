if(KERNEL_PATH)
    message(STATUS "Specified KERNEL_PATH: ${KERNEL_PATH}")
    set(KERNELHEADERS_DIR "${KERNEL_PATH}")
else()
    message(STATUS "Not specified KERNEL_PATH ")
    # Find the kernel release
    execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Find the headers
    find_path(KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /lib/modules/${KERNEL_RELEASE}/build
    )
endif()

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")

if (KERNELHEADERS_DIR)
    set(KERNELHEADERS_INCLUDE_DIRS
        ${KERNELHEADERS_DIR}/include
        ${KERNELHEADERS_DIR}/arch/arm64/include
        CACHE PATH "Kernel headers include dirs"
        )
    set(KERNELHEADERS_FOUND 1 CACHE STRING "Set to 1 if kernel headers were found")
else ()
    set(KERNELHEADERS_FOUND 0 CACHE STRING "Set to 0 if kernel headers were not found")
endif ()

mark_as_advanced(KERNELHEADERS_FOUND)