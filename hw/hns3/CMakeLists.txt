aux_source_directory(${CMAKE_CURRENT_LIST_DIR} PROVIDER_UB_DIR_SRCS)

add_library(HNS3_UDMA_SO SHARED ${PROVIDER_UB_DIR_SRCS})

target_include_directories(HNS3_UDMA_SO PRIVATE ${UBus_SOURCE_DIR}/lib/urma/include)
target_include_directories(HNS3_UDMA_SO PRIVATE ${UBus_SOURCE_DIR}/include/common)

target_link_libraries(HNS3_UDMA_SO PRIVATE urma)
target_link_libraries(HNS3_UDMA_SO PRIVATE urma_common)

set(HNS3_UDMA_NAME urma-hns3)
set_target_properties(HNS3_UDMA_SO PROPERTIES OUTPUT_NAME ${HNS3_UDMA_NAME})

set(CMAKE_C_FLAGS "-Wall -Wextra -Wfloat-equal -fno-common -std=gnu99 \
-D_FORTIFY_SOURCE=2 -O3 -fstack-protector-all -s -ftrapv -Wl,-z,relro,-z,now \
-march=armv8.3-a+crc+crypto+fp+sve")
set(CMAKE_LD_FLAGS "-s")

install(TARGETS HNS3_UDMA_SO LIBRARY DESTINATION /usr/lib64/urma OPTIONAL)
